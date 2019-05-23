//===--- FixItHintUtils.cpp - clang-tidy-----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "FixItHintUtils.h"
#include "LexerUtils.h"
#include "clang/AST/ASTContext.h"

namespace clang {
namespace tidy {
namespace utils {
namespace fixit {

FixItHint changeVarDeclToReference(const VarDecl &Var, ASTContext &Context) {
  SourceLocation AmpLocation = Var.getLocation();
  auto Token = utils::lexer::getPreviousToken(
      AmpLocation, Context.getSourceManager(), Context.getLangOpts());
  if (!Token.is(tok::unknown))
    AmpLocation = Lexer::getLocForEndOfToken(Token.getLocation(), 0,
                                             Context.getSourceManager(),
                                             Context.getLangOpts());
  return FixItHint::CreateInsertion(AmpLocation, "&");
}

static bool isValueType(const Type *T) {
  return !(isa<PointerType>(T) || isa<ReferenceType>(T) || isa<ArrayType>(T) ||
           isa<MemberPointerType>(T));
}
static bool isValueType(QualType QT) { return isValueType(QT.getTypePtr()); }
static bool isArrayType(QualType QT) { return isa<ArrayType>(QT.getTypePtr()); }
static bool isReferenceType(QualType QT) {
  return isa<ReferenceType>(QT.getTypePtr());
}
static bool isPointerType(const Type *T) { return isa<PointerType>(T); }
static bool isPointerType(QualType QT) {
  return isPointerType(QT.getTypePtr());
}
static bool isMemberOrFunctionPointer(QualType QT) {
  return (isPointerType(QT) && QT->isFunctionPointerType()) ||
         isa<MemberPointerType>(QT.getTypePtr());
}
static bool locDangerous(SourceLocation S) {
  return S.isInvalid() || S.isMacroID();
}

static Optional<SourceLocation>
skipLParensBackwards(SourceLocation Start, const ASTContext &Context) {
  Token T;
  auto PreviousTokenLParen = [&]() {
    T = lexer::getPreviousToken(Start, Context.getSourceManager(),
                                Context.getLangOpts());
    return T.is(tok::l_paren);
  };
  while (PreviousTokenLParen()) {
    if (locDangerous(Start))
      return None;
    Start = lexer::findPreviousTokenStart(Start, Context.getSourceManager(),
                                          Context.getLangOpts());
  }
  if (locDangerous(Start))
    return None;
  return Start;
}

static Optional<FixItHint> fixIfNotDangerous(SourceLocation Loc,
                                             StringRef Text) {
  if (locDangerous(Loc))
    return None;
  return FixItHint::CreateInsertion(Loc, Text);
}

static Optional<FixItHint> changeValue(const VarDecl &Var, ConstTarget CT,
                                       ConstPolicy CP,
                                       const ASTContext &Context) {
  switch (CP) {
  case ConstPolicy::Left:
    return fixIfNotDangerous(Var.getTypeSpecStartLoc(), "const ");
  case ConstPolicy::Right:
    Optional<SourceLocation> IgnoredParens =
        skipLParensBackwards(Var.getLocation(), Context);

    if (IgnoredParens)
      return fixIfNotDangerous(*IgnoredParens, "const ");
    return None;
  }
}

static Optional<FixItHint> changePointerItself(const VarDecl &Var,
                                               const ASTContext &Context) {
  if (locDangerous(Var.getLocation()))
    return None;

  Optional<SourceLocation> IgnoredParens =
      skipLParensBackwards(Var.getLocation(), Context);
  if (IgnoredParens)
    return fixIfNotDangerous(*IgnoredParens, "const ");
  return None;
}

static Optional<FixItHint> changePointer(const VarDecl &Var,
                                         const Type *Pointee, ConstTarget CT,
                                         ConstPolicy CP,
                                         const ASTContext &Context) {
  // The pointer itself shall be marked as `const`. This is always right
  // of the '*' or in front of the identifier.
  if (CT == ConstTarget::Value)
    return changePointerItself(Var, Context);

  // Mark the pointee `const` that is a normal value (`int* p = nullptr;`).
  if (CT == ConstTarget::Pointee && isValueType(Pointee)) {
    // Adding the `const` on the left side is just the beginning of the type
    // specification. (`const int* p = nullptr;`)
    if (CP == ConstPolicy::Left)
      return fixIfNotDangerous(Var.getTypeSpecStartLoc(), "const ");

    // Adding the `const` on the right side of the value type requires finding
    // the `*` token and placing the `const` left of it.
    // (`int const* p = nullptr;`)
    if (CP == ConstPolicy::Right) {
      SourceLocation BeforeStar = lexer::findPreviousTokenKind(
          Var.getLocation(), Context.getSourceManager(), Context.getLangOpts(),
          tok::star);
      if (locDangerous(BeforeStar))
        return None;

      Optional<SourceLocation> IgnoredParens =
          skipLParensBackwards(BeforeStar, Context);

      if (IgnoredParens)
        return fixIfNotDangerous(*IgnoredParens, " const");
      return None;
    }
  }

  if (CT == ConstTarget::Pointee && isPointerType(Pointee)) {
    // Adding the `const` to the pointee if the pointee is a pointer
    // is the same as 'CP == Right && isValueType(Pointee)'.
    // The `const` must be left of the last `*` token.
    // (`int * const* p = nullptr;`)
    SourceLocation BeforeStar = lexer::findPreviousTokenKind(
        Var.getLocation(), Context.getSourceManager(), Context.getLangOpts(),
        tok::star);
    return fixIfNotDangerous(BeforeStar, " const");
  }

  llvm_unreachable("All paths should have been handled");
}

static Optional<FixItHint> changeReferencee(const VarDecl &Var,
                                            QualType Pointee, ConstTarget CT,
                                            ConstPolicy CP,
                                            const ASTContext &Context) {
  if (CP == ConstPolicy::Left && isValueType(Pointee))
    return fixIfNotDangerous(Var.getTypeSpecStartLoc(), "const ");

  SourceLocation BeforeRef = lexer::findPreviousAnyTokenKind(
      Var.getLocation(), Context.getSourceManager(), Context.getLangOpts(),
      tok::amp, tok::ampamp);
  Optional<SourceLocation> IgnoredParens =
      skipLParensBackwards(BeforeRef, Context);
  if (IgnoredParens)
    return fixIfNotDangerous(*IgnoredParens, " const");

  return None;
}

Optional<FixItHint> changeVarDeclToConst(const VarDecl &Var, ConstTarget CT,
                                         ConstPolicy CP,
                                         const ASTContext *Context) {
  assert((CP == ConstPolicy::Left || CP == ConstPolicy::Right) &&
         "Unexpected Insertion Policy");
  assert((CT == ConstTarget::Pointee || CT == ConstTarget::Value) &&
         "Unexpected Target");

  QualType ParenStrippedType = Var.getType().IgnoreParens();
  if (isValueType(ParenStrippedType))
    return changeValue(Var, CT, CP, *Context);

  if (isReferenceType(ParenStrippedType))
    return changeReferencee(Var, Var.getType()->getPointeeType(), CT, CP,
                            *Context);

  if (isMemberOrFunctionPointer(ParenStrippedType))
    return changePointerItself(Var, *Context);

  if (isPointerType(ParenStrippedType))
    return changePointer(Var, ParenStrippedType->getPointeeType().getTypePtr(),
                         CT, CP, *Context);

  if (isArrayType(ParenStrippedType)) {
    const Type *AT = ParenStrippedType->getBaseElementTypeUnsafe();
    assert(AT && "Did not retrieve array element type for an array.");

    if (isValueType(AT))
      return changeValue(Var, CT, CP, *Context);

    if (isPointerType(AT))
      return changePointer(Var, AT->getPointeeType().getTypePtr(), CT, CP,
                           *Context);
  }

  return None;
}
} // namespace fixit
} // namespace utils
} // namespace tidy
} // namespace clang
