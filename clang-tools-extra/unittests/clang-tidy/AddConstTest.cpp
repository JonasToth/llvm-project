#include "../clang-tidy/utils/FixItHintUtils.h"
#include "ClangTidyTest.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Tooling/Tooling.h"
#include "gtest/gtest.h"

namespace clang {
namespace tidy {

namespace {
using namespace clang::ast_matchers;
using namespace utils::fixit;

template <ConstTarget CT = ConstTarget::Pointee,
          ConstPolicy CP = ConstPolicy::Left>
class ConstTransform : public ClangTidyCheck {
public:
  ConstTransform(StringRef CheckName, ClangTidyContext *Context)
      : ClangTidyCheck(CheckName, Context) {}

  void registerMatchers(MatchFinder *Finder) override {
    Finder->addMatcher(varDecl(hasName("target")).bind("var"), this);
  }

  void check(const MatchFinder::MatchResult &Result) override {
    const auto *D = Result.Nodes.getNodeAs<VarDecl>("var");
    using utils::fixit::changeVarDeclToConst;
    Optional<FixItHint> Fix = changeVarDeclToConst(*D, CT, CP, Result.Context);
    auto Diag = diag(D->getBeginLoc(), "doing const transformation");
    if (Fix)
      Diag << *Fix;
  }
};
} // namespace

namespace test {
using PointeeLTransform =
    ConstTransform<ConstTarget::Pointee, ConstPolicy::Left>;
using PointeeRTransform =
    ConstTransform<ConstTarget::Pointee, ConstPolicy::Right>;

using ValueLTransform = ConstTransform<ConstTarget::Value, ConstPolicy::Left>;
using ValueRTransform = ConstTransform<ConstTarget::Value, ConstPolicy::Right>;

// ----------------------------------------------------------------------------
// Test Value-like types. Everything with indirection is done later.
// ----------------------------------------------------------------------------

// TODO: Template-code

TEST(Values, Builtin) {
  StringRef Snippet = "int target = 0;";

  EXPECT_EQ("const int target = 0;", runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("const int target = 0;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int const target = 0;", runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int const target = 0;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Values, TypedefBuiltin) {
  StringRef T = "typedef int MyInt;";
  StringRef S = "MyInt target = 0;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const MyInt target = 0;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const MyInt target = 0;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("MyInt const target = 0;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("MyInt const target = 0;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, TypedefBuiltinPointer) {
  StringRef T = "typedef int* MyInt;";
  StringRef S = "MyInt target = nullptr;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const MyInt target = nullptr;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const MyInt target = nullptr;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("MyInt const target = nullptr;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("MyInt const target = nullptr;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, AutoValue) {
  StringRef T = "int f() { return 42; }\n";
  StringRef S = "auto target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, AutoPointer) {
  StringRef T = "int* f() { return nullptr; }\n";
  StringRef S = "auto target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, AutoReference) {
  StringRef T = "static int global = 42; int& f() { return global; }\n";
  StringRef S = "auto target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const auto target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, DeclTypeValue) {
  StringRef T = "int f() { return 42; }\n";
  StringRef S = "decltype(f()) target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, DeclTypePointer) {
  // The pointer itself will be changed to 'const'. There is no
  // way to make the pointee 'const' with this syntax.
  StringRef T = "int* f() { return nullptr; }\n";
  StringRef S = "decltype(f()) target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, DeclTypeReference) {
  // Same as pointer, but the reference itself will be marked 'const'.
  // This has no effect and will result in a warning afterwards. The
  // transformation itself is still correct.
  StringRef T = "static int global = 42; int& f() { return global; }\n";
  StringRef S = "decltype(f()) target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const decltype(f()) target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("decltype(f()) const target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Values, Parens) {
  StringRef Snippet = "int ((target)) = 0;";

  EXPECT_EQ("const int ((target)) = 0;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("const int ((target)) = 0;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int const ((target)) = 0;",
            runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int const ((target)) = 0;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}

// ----------------------------------------------------------------------------
// Test builtin-arrays
// ----------------------------------------------------------------------------

TEST(Arrays, Builtin) {
  StringRef Snippet = "int target[][1] = {{1}, {2}, {3}};";

  EXPECT_EQ("const int target[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("const int target[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<ValueLTransform>(Snippet));

  EXPECT_EQ("int const target[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<PointeeRTransform>(Snippet));
  EXPECT_EQ("int const target[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<ValueRTransform>(Snippet));
}
TEST(Arrays, BuiltinParens) {
  StringRef Snippet = "int ((target))[][1] = {{1}, {2}, {3}};";

  EXPECT_EQ("const int ((target))[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("const int ((target))[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<ValueLTransform>(Snippet));

  EXPECT_EQ("int const ((target))[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<PointeeRTransform>(Snippet));
  EXPECT_EQ("int const ((target))[][1] = {{1}, {2}, {3}};",
            runCheckOnCode<ValueRTransform>(Snippet));
}
TEST(Arrays, Pointers) {
  StringRef Snippet = "int x; int* target[] = {&x, &x, &x};";

  EXPECT_EQ("int x; const int* target[] = {&x, &x, &x};",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int x; int const* target[] = {&x, &x, &x};",
            runCheckOnCode<PointeeRTransform>(Snippet));

  EXPECT_EQ("int x; int* const target[] = {&x, &x, &x};",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int x; int* const target[] = {&x, &x, &x};",
            runCheckOnCode<ValueRTransform>(Snippet));
}
TEST(Arrays, PointerPointers) {
  StringRef Snippet = "int* x = nullptr; int** target[] = {&x, &x, &x};";

  EXPECT_EQ("int* x = nullptr; int* const* target[] = {&x, &x, &x};",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int* x = nullptr; int** const target[] = {&x, &x, &x};",
            runCheckOnCode<ValueLTransform>(Snippet));

  EXPECT_EQ("int* x = nullptr; int* const* target[] = {&x, &x, &x};",
            runCheckOnCode<PointeeRTransform>(Snippet));
  EXPECT_EQ("int* x = nullptr; int** const target[] = {&x, &x, &x};",
            runCheckOnCode<ValueRTransform>(Snippet));
}
TEST(Arrays, PointersParens) {
  StringRef Snippet = "int x; int* (target)[] = {&x, &x, &x};";

  EXPECT_EQ("int x; const int* (target)[] = {&x, &x, &x};",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int x; int const* (target)[] = {&x, &x, &x};",
            runCheckOnCode<PointeeRTransform>(Snippet));

  EXPECT_EQ("int x; int* const (target)[] = {&x, &x, &x};",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int x; int* const (target)[] = {&x, &x, &x};",
            runCheckOnCode<ValueRTransform>(Snippet));
}

// ----------------------------------------------------------------------------
// Test reference types. This does not include pointers and arrays.
// ----------------------------------------------------------------------------

TEST(Reference, LValueBuiltin) {
  StringRef Snippet = "int x = 42; int& target = x;";

  EXPECT_EQ("int x = 42; const int& target = x;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int x = 42; const int& target = x;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int x = 42; int const& target = x;",
            runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int x = 42; int const& target = x;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Reference, RValueBuiltin) {
  StringRef Snippet = "int&& target = 42;";
  EXPECT_EQ("const int&& target = 42;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("const int&& target = 42;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int const&& target = 42;",
            runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int const&& target = 42;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Reference, LValueToPointer) {
  StringRef Snippet = "int* p; int *& target = p;";
  EXPECT_EQ("int* p; int * const& target = p;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int* p; int * const& target = p;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int* p; int * const& target = p;",
            runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int* p; int * const& target = p;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Reference, LValueParens) {
  StringRef Snippet = "int x = 42; int ((& target)) = x;";

  EXPECT_EQ("int x = 42; const int ((& target)) = x;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int x = 42; const int ((& target)) = x;",
            runCheckOnCode<PointeeLTransform>(Snippet));

  EXPECT_EQ("int x = 42; int  const((& target)) = x;",
            runCheckOnCode<ValueRTransform>(Snippet));
  EXPECT_EQ("int x = 42; int  const((& target)) = x;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Reference, ToArray) {
  StringRef ArraySnippet = "int a[4] = {1, 2, 3, 4};";
  StringRef Snippet = "int (&target)[4] = a;";
  auto Cat = [&ArraySnippet](StringRef S) { return (ArraySnippet + S).str(); };

  EXPECT_EQ(Cat("const int (&target)[4] = a;"),
            runCheckOnCode<ValueLTransform>(Cat(Snippet)));
  EXPECT_EQ(Cat("const int (&target)[4] = a;"),
            runCheckOnCode<PointeeLTransform>(Cat(Snippet)));

  EXPECT_EQ(Cat("int  const(&target)[4] = a;"),
            runCheckOnCode<ValueRTransform>(Cat(Snippet)));
  EXPECT_EQ(Cat("int  const(&target)[4] = a;"),
            runCheckOnCode<PointeeRTransform>(Cat(Snippet)));
}
TEST(Reference, Auto) {
  StringRef T = "static int global = 42; int& f() { return global; }\n";
  StringRef S = "auto& target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const auto& target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const& target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("const auto& target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const& target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}

// ----------------------------------------------------------------------------
// Test pointers types.
// ----------------------------------------------------------------------------

TEST(Pointers, SingleBuiltin) {
  StringRef Snippet = "int* target = nullptr;";

  EXPECT_EQ("int* const target = nullptr;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int* const target = nullptr;",
            runCheckOnCode<ValueRTransform>(Snippet));

  EXPECT_EQ("const int* target = nullptr;",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int const* target = nullptr;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Pointers, MultiBuiltin) {
  StringRef Snippet = "int** target = nullptr;";

  EXPECT_EQ("int** const target = nullptr;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int** const target = nullptr;",
            runCheckOnCode<ValueRTransform>(Snippet));

  EXPECT_EQ("int* const* target = nullptr;",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int* const* target = nullptr;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Pointers, ToArray) {
  StringRef ArraySnippet = "int a[4] = {1, 2, 3, 4};";
  StringRef Snippet = "int (*target)[4] = &a;";
  auto Cat = [&ArraySnippet](StringRef S) { return (ArraySnippet + S).str(); };

  EXPECT_EQ(Cat("int (*const target)[4] = &a;"),
            runCheckOnCode<ValueLTransform>(Cat(Snippet)));
  EXPECT_EQ(Cat("const int (*target)[4] = &a;"),
            runCheckOnCode<PointeeLTransform>(Cat(Snippet)));

  EXPECT_EQ(Cat("int (*const target)[4] = &a;"),
            runCheckOnCode<ValueRTransform>(Cat(Snippet)));
  EXPECT_EQ(Cat("int  const(*target)[4] = &a;"),
            runCheckOnCode<PointeeRTransform>(Cat(Snippet)));
}
TEST(Pointers, Parens) {
  StringRef Snippet = "int ((**target)) = nullptr;";

  EXPECT_EQ("int ((**const target)) = nullptr;",
            runCheckOnCode<ValueLTransform>(Snippet));
  EXPECT_EQ("int ((**const target)) = nullptr;",
            runCheckOnCode<ValueRTransform>(Snippet));

  EXPECT_EQ("int ((* const*target)) = nullptr;",
            runCheckOnCode<PointeeLTransform>(Snippet));
  EXPECT_EQ("int ((* const*target)) = nullptr;",
            runCheckOnCode<PointeeRTransform>(Snippet));
}
TEST(Pointers, Auto) {
  StringRef T = "int* f() { return nullptr; }\n";
  StringRef S = "auto* target = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("auto* const target = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto* const target = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("const auto* target = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto const* target = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Pointers, AutoParens) {
  StringRef T = "int* f() { return nullptr; }\n";
  StringRef S = "auto (((* target))) = f();";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("auto (((* const target))) = f();"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto (((* const target))) = f();"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("const auto (((* target))) = f();"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("auto  const(((* target))) = f();"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Pointers, FunctionPointer) {
  StringRef S = "int (*target)(float, int, double) = nullptr;";

  EXPECT_EQ("int (*const target)(float, int, double) = nullptr;",
            runCheckOnCode<ValueLTransform>(S));
  EXPECT_EQ("int (*const target)(float, int, double) = nullptr;",
            runCheckOnCode<ValueRTransform>(S));

  EXPECT_EQ("int (*const target)(float, int, double) = nullptr;",
            runCheckOnCode<PointeeLTransform>(S));
  EXPECT_EQ("int (*const target)(float, int, double) = nullptr;",
            runCheckOnCode<PointeeRTransform>(S));

  S = "int (((*target)))(float, int, double) = nullptr;";
  EXPECT_EQ("int (((*const target)))(float, int, double) = nullptr;",
            runCheckOnCode<PointeeRTransform>(S));
}
TEST(Pointers, MemberFunctionPointer) {
  StringRef T = "struct A { int f() { return 1; } };";
  StringRef S = "int (A::*target)() = &A::f;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("int (A::*const target)() = &A::f;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("int (A::*const target)() = &A::f;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("int (A::*const target)() = &A::f;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("int (A::*const target)() = &A::f;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "int (A::*((target)))() = &A::f;";
  EXPECT_EQ(Cat("int (A::*const ((target)))() = &A::f;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
}
TEST(Pointers, MemberDataPointer) {
  StringRef T = "struct A { int member = 0; };";
  StringRef S = "int A::*target = &A::member;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("int A::*const target = &A::member;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("int A::*const target = &A::member;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("int A::*const target = &A::member;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("int A::*const target = &A::member;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "int A::*((target)) = &A::member;";
  EXPECT_EQ(Cat("int A::*const ((target)) = &A::member;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}

// ----------------------------------------------------------------------------
// Test TagTypes (struct, class, unions, enums)
// ----------------------------------------------------------------------------

TEST(TagTypes, Struct) {
  StringRef T = "struct Foo { int data; int method(); };\n";
  StringRef S = "struct Foo target{0};";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const struct Foo target{0};"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const struct Foo target{0};"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("struct Foo const target{0};"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("struct Foo const target{0};"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo target{0};";
  EXPECT_EQ(Cat("const Foo target{0};"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo target{0};"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const target{0};"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const target{0};"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo (target){0};";
  EXPECT_EQ(Cat("const Foo (target){0};"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo (target){0};"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const (target){0};"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const (target){0};"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(TagTypes, Class) {
  StringRef T = "class Foo { int data; int method(); };\n";
  StringRef S = "class Foo target;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const class Foo target;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const class Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("class Foo const target;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("class Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo target;";
  EXPECT_EQ(Cat("const Foo target;"), runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const target;"), runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo (target);";
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(TagTypes, Enum) {
  StringRef T = "enum Foo { N_ONE, N_TWO, N_THREE };\n";
  StringRef S = "enum Foo target;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const enum Foo target;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const enum Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("enum Foo const target;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("enum Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo target;";
  EXPECT_EQ(Cat("const Foo target;"), runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const target;"), runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo (target);";
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(TagTypes, Union) {
  StringRef T = "union Foo { int yay; float nej; };\n";
  StringRef S = "union Foo target;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("const union Foo target;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const union Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("union Foo const target;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("union Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo target;";
  EXPECT_EQ(Cat("const Foo target;"), runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo target;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const target;"), runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const target;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));

  S = "Foo (target);";
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("const Foo (target);"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
  EXPECT_EQ(Cat("Foo const (target);"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}

// ----------------------------------------------------------------------------
// Test Macro expansions.
// ----------------------------------------------------------------------------

TEST(Macro, AllInMacro) {
  StringRef T = "#define DEFINE_VARIABLE int target = 42\n";
  StringRef S = "DEFINE_VARIABLE;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("DEFINE_VARIABLE;"), runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("DEFINE_VARIABLE;"), runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("DEFINE_VARIABLE;"), runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("DEFINE_VARIABLE;"), runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Macro, MacroParameter) {
  StringRef T = "#define DEFINE_VARIABLE(X) int X = 42\n";
  StringRef S = "DEFINE_VARIABLE(target);";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("DEFINE_VARIABLE(target);"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("DEFINE_VARIABLE(target);"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("DEFINE_VARIABLE(target);"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("DEFINE_VARIABLE(target);"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Macro, MacroTypeValue) {
  StringRef T = "#define BAD_TYPEDEF int\n";
  StringRef S = "BAD_TYPEDEF target = 42;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("BAD_TYPEDEF target = 42;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("BAD_TYPEDEF target = 42;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));

  EXPECT_EQ(Cat("BAD_TYPEDEF const target = 42;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
  EXPECT_EQ(Cat("BAD_TYPEDEF const target = 42;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));
}
TEST(Macro, MacroTypePointer) {
  StringRef T = "#define BAD_TYPEDEF int *\n";
  StringRef S = "BAD_TYPEDEF target = nullptr;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("BAD_TYPEDEF const target = nullptr;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("BAD_TYPEDEF const target = nullptr;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  // FIXME: Failing even all parts seem to bail-out in for isMacroID()
  EXPECT_NE(Cat("BAD_TYPEDEF target = nullptr;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
  EXPECT_EQ(Cat("BAD_TYPEDEF target = nullptr;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
}
TEST(Macro, MacroTypeReference) {
  StringRef T = "static int g = 42;\n#define BAD_TYPEDEF int&\n";
  StringRef S = "BAD_TYPEDEF target = g;";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("BAD_TYPEDEF target = g;"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  // FIXME: Failing even all parts seem to bail-out in for isMacroID()
  EXPECT_NE(Cat("BAD_TYPEDEF target = g;"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("BAD_TYPEDEF target = g;"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  // FIXME: Failing even all parts seem to bail-out in for isMacroID()
  EXPECT_NE(Cat("BAD_TYPEDEF target = g;"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}

// ----------------------------------------------------------------------------
// Test template code.
// ----------------------------------------------------------------------------

TEST(Template, FunctionValue) {
  StringRef T = "template <typename T> void f(T v) \n";
  StringRef S = "{ T target = v; }";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Template, FunctionPointer) {
  StringRef T = "template <typename T> void f(T* v) \n";
  StringRef S = "{ T* target = v; }";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("{ T* const target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T* const target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T* target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const* target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Template, FunctionReference) {
  StringRef T = "template <typename T> void f(T& v) \n";
  StringRef S = "{ T& target = v; }";
  auto Cat = [&T](StringRef S) { return (T + S).str(); };

  EXPECT_EQ(Cat("{ const T& target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const& target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T& target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const& target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Template, MultiInstantiationsFunction) {
  StringRef T = "template <typename T> void f(T v) \n";
  StringRef S = "{ T target = v; }";
  StringRef InstantStart = "void calls() {\n";
  StringRef InstValue = "f<int>(42);\n";
  StringRef InstConstValue = "f<const int>(42);\n";
  StringRef InstPointer = "f<int*>(nullptr);\n";
  StringRef InstPointerConst = "f<int* const>(nullptr);\n";
  StringRef InstConstPointer = "f<const int*>(nullptr);\n";
  StringRef InstConstPointerConst = "f<const int* const>(nullptr);\n";
  StringRef InstRef = "int i = 42;\nf<int&>(i);\n";
  StringRef InstConstRef = "f<const int&>(i);\n";
  StringRef InstantEnd = "}";
  auto Cat = [&](StringRef Target) {
    return (T + Target + InstantStart + InstValue + InstConstValue +
            InstPointer + InstPointerConst + InstConstPointer +
            InstConstPointerConst + InstRef + InstConstRef + InstantEnd)
        .str();
  };

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}

TEST(Template, StructValue) {
  StringRef T = "template <typename T> struct S { void f(T& v) \n";
  StringRef S = "{ T target = v; }";
  StringRef End = "\n};";
  auto Cat = [&T, &End](StringRef S) { return (T + S + End).str(); };

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Template, StructPointer) {
  StringRef T = "template <typename T> struct S { void f(T* v) \n";
  StringRef S = "{ T* target = v; }";
  StringRef End = "\n};";
  auto Cat = [&T, &End](StringRef S) { return (T + S + End).str(); };

  EXPECT_EQ(Cat("{ T* const target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T* const target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T* target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const* target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
TEST(Template, StructReference) {
  StringRef T = "template <typename T> struct S { void f(T& v) \n";
  StringRef S = "{ T& target = v; }";
  StringRef End = "\n};";
  auto Cat = [&T, &End](StringRef S) { return (T + S + End).str(); };

  EXPECT_EQ(Cat("{ const T& target = v; }"),
            runCheckOnCode<ValueLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const& target = v; }"),
            runCheckOnCode<ValueRTransform>(Cat(S)));

  EXPECT_EQ(Cat("{ const T& target = v; }"),
            runCheckOnCode<PointeeLTransform>(Cat(S)));
  EXPECT_EQ(Cat("{ T const& target = v; }"),
            runCheckOnCode<PointeeRTransform>(Cat(S)));
}
} // namespace test
} // namespace tidy
} // namespace clang
