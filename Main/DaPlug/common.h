#ifndef COMMUN_H_INCLUDED
#define COMMUN_H_INCLUDED

#ifdef _WIN32

    #define DAPLUG_EXPORTS //Should be defined only when building a dll

    #ifdef DAPLUG_EXPORTS
        #define DAPLUGAPI __declspec(dllexport)
    #else
        #define DAPLUGAPI __declspec(dllimport)
    #endif // DAPLUG_EXPORTS

    #define DAPLUGCALL __cdecl

#else

    #define DAPLUGAPI
    #define DAPLUGCALL

#endif // _WIN32

#endif // COMMUN_H_INCLUDED
