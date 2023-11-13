#ifndef DEFINES_H
#define DEFINES_H
#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
#define __PRETTY_FUNCTION__ __FUNCSIG__
#endif
enum class PGStatus
{
    Fail,
    Success,
    Conflict,
    NotFound,
    Unauthorized,
    UnprocessableEntity
};
#endif // DEFINES_H
