//===--- ConstCorrectnessCheck.cpp - clang-tidy -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ConstCorrectnessCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace cppcoreguidelines {

namespace {
// FIXME: This matcher exists in some other code-review as well.
// It should probably move to ASTMatchers.
AST_MATCHER(VarDecl, isLocal) { return Node.isLocalVarDecl(); }
} // namespace

void ConstCorrectnessCheck::storeOptions(ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "AnalyzeValues", AnalyzeValues);
  Options.store(Opts, "AnalyzeReferences", AnalyzeReferences);
  Options.store(Opts, "WarnPointersAsValues", WarnPointersAsValues);
}

void ConstCorrectnessCheck::registerMatchers(MatchFinder *Finder) {
  const auto ConstType = hasType(isConstQualified());
  const auto ConstReference = hasType(references(isConstQualified()));
  const auto TemplateType = anyOf(hasType(templateTypeParmType()),
                                  hasType(substTemplateTypeParmType()));

  // Match local variables which could be 'const' if not modified later.
  // Example: `int i = 10` would match `int i`.
  const auto LocalValDecl = varDecl(
      allOf(isLocal(), hasInitializer(anything()),
            unless(anyOf(ConstType, ConstReference, TemplateType,
                         hasType(cxxRecordDecl(isLambda())), isImplicit()))));

  // Match the function scope for which the analysis of all local variables
  // shall be run.
  const auto FunctionScope =
      functionDecl(allOf(hasBody(compoundStmt().bind("scope")),
                         findAll(LocalValDecl.bind("new-local-value"))));
  Finder->addMatcher(FunctionScope, this);
}

void ConstCorrectnessCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *LocalScope = Result.Nodes.getNodeAs<CompoundStmt>("scope");
  assert(LocalScope && "Did not match scope for local variable");
  registerScope(LocalScope, Result.Context);

  const auto *Variable = Result.Nodes.getNodeAs<VarDecl>("new-local-value");
  assert(Variable && "Did not match local variable definition");

  // Each variable can only in one category: Value, Pointer, Reference.
  // Analysis can be controlled for every category.
  if (!AnalyzeReferences && Variable->getType()->isReferenceType())
    return;

  if (!WarnPointersAsValues && Variable->getType()->isPointerType())
    return;

  if (!AnalyzeValues && !(Variable->getType()->isReferenceType() ||
                          Variable->getType()->isPointerType()))
    return;

  if (ScopesCache[LocalScope]->isMutated(Variable))
    return;

  // TODO Implement automatic code transformation to add the 'const'.
  diag(Variable->getBeginLoc(),
       "variable %0 of type %1 can be declared 'const'")
      << Variable << Variable->getType();
}

void ConstCorrectnessCheck::registerScope(const CompoundStmt *LocalScope,
                                          ASTContext *Context) {
  if (ScopesCache.find(LocalScope) == ScopesCache.end())
    ScopesCache.insert(std::make_pair(
        LocalScope,
        std::make_unique<ExprMutationAnalyzer>(*LocalScope, *Context)));
}

} // namespace cppcoreguidelines
} // namespace tidy
} // namespace clang
