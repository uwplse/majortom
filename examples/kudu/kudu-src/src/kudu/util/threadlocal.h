// Copyright 2014 Cloudera, Inc.
// Confidential Cloudera Information: Covered by NDA.
#ifndef KUDU_UTIL_THREADLOCAL_H_
#define KUDU_UTIL_THREADLOCAL_H_

// Block-scoped static thread local implementation.
//
// Usage is similar to a C++11 thread_local. The BLOCK_STATIC_THREAD_LOCAL macro
// defines a thread-local pointer to the specified type, which is lazily
// instantiated by any thread entering the block for the first time. The
// constructor for the type T is invoked at macro execution time, as expected,
// and its destructor is invoked when the corresponding thread's Runnable
// returns, or when the thread exits.
//
// Inspired by Poco <http://pocoproject.org/docs/Poco.ThreadLocal.html>,
// Andrew Tomazos <http://stackoverflow.com/questions/12049684/>, and
// the C++11 thread_local API.
//
// Example usage:
//
// // Invokes a 3-arg constructor on SomeClass:
// BLOCK_STATIC_THREAD_LOCAL(SomeClass, instance, arg1, arg2, arg3);
// instance->DoSomething();
//
#define BLOCK_STATIC_THREAD_LOCAL(T, t, ...)                                    \
static __thread T* t;                                                           \
do {                                                                            \
  static __thread ::kudu::threadlocal::internal::PerThreadDestructorList dtor;  \
                                                                                \
  if (PREDICT_FALSE(t == NULL)) {                                               \
    t = new T(__VA_ARGS__);                                                     \
    dtor.destructor = ::kudu::threadlocal::internal::Destroy<T>;                \
    dtor.arg = t;                                                               \
    ::kudu::threadlocal::internal::AddDestructor(&dtor);                        \
  }                                                                             \
} while (false)

// Class-scoped static thread local implementation.
//
// Very similar in implementation to the above block-scoped version, but
// requires a bit more syntax and vigilance to use properly.
//
// DECLARE_STATIC_THREAD_LOCAL(Type, instance_var_) must be placed in the
// class header, as usual for variable declarations.
//
// Because these variables are static, they must also be defined in the impl
// file with DEFINE_STATIC_THREAD_LOCAL(Type, Classname, instance_var_),
// which is very much like defining any static member, i.e. int Foo::member_.
//
// Finally, each thread must initialize the instance before using it by calling
// INIT_STATIC_THREAD_LOCAL(Type, instance_var_, ...). This is a cheap
// call, and may be invoked at the top of any method which may reference a
// thread-local variable.
//
// Due to all of these requirements, you should probably declare TLS members
// as private.
//
// Example usage:
//
// // foo.h
// #include "kudu/utils/file.h"
// class Foo {
//  public:
//   void DoSomething(std::string s);
//  private:
//   DECLARE_STATIC_THREAD_LOCAL(utils::File, file_);
// };
//
// // foo.cc
// #include "kudu/foo.h"
// DEFINE_STATIC_THREAD_LOCAL(utils::File, Foo, file_);
// void Foo::WriteToFile(std::string s) {
//   // Call constructor if necessary.
//   INIT_STATIC_THREAD_LOCAL(utils::File, file_, "/tmp/file_location.txt");
//   file_->Write(s);
// }

// Goes in the class declaration (usually in a header file).
// dtor must be destructed _after_ t, so it gets defined first.
// Uses a mangled variable name for dtor since it must also be a member of the
// class.
#define DECLARE_STATIC_THREAD_LOCAL(T, t)                                                     \
static __thread ::kudu::threadlocal::internal::PerThreadDestructorList kudu_tls_##t##dtor_;   \
static __thread T* t

// You must also define the instance in the .cc file.
#define DEFINE_STATIC_THREAD_LOCAL(T, Class, t)                                               \
__thread ::kudu::threadlocal::internal::PerThreadDestructorList Class::kudu_tls_##t##dtor_;   \
__thread T* Class::t

// Must be invoked at least once by each thread that will access t.
#define INIT_STATIC_THREAD_LOCAL(T, t, ...)                                       \
do {                                                                              \
  if (PREDICT_FALSE(t == NULL)) {                                                 \
    t = new T(__VA_ARGS__);                                                       \
    kudu_tls_##t##dtor_.destructor = ::kudu::threadlocal::internal::Destroy<T>;   \
    kudu_tls_##t##dtor_.arg = t;                                                  \
    ::kudu::threadlocal::internal::AddDestructor(&kudu_tls_##t##dtor_);           \
  }                                                                               \
} while (false)

// Internal implementation below.

namespace kudu {
namespace threadlocal {
namespace internal {

// List of destructors for all thread locals instantiated on a given thread.
struct PerThreadDestructorList {
  void (*destructor)(void*);
  void* arg;
  PerThreadDestructorList* next;
};

// Add a destructor to the list.
void AddDestructor(PerThreadDestructorList* p);

// Destroy the passed object of type T.
template<class T>
static void Destroy(void* t) {
  // With tcmalloc, this should be pretty cheap (same thread as new).
  delete reinterpret_cast<T*>(t);
}

} // namespace internal
} // namespace threadlocal
} // namespace kudu

#endif // KUDU_UTIL_THREADLOCAL_H_
