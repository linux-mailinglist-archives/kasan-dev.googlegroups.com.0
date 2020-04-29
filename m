Return-Path: <kasan-dev+bncBDM3P4G7YIARBPMSU72QKGQEAJ7ZFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B49131BE653
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Apr 2020 20:36:46 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id r10sf2449818otk.16
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Apr 2020 11:36:46 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PkSL8hEoRutXRWroD5iQR2Ez4Jx7mrQ+k/JOzq1oP3w=;
        b=TimjcYcv3aT8/6mgmEuwbCV4SxaIl2gVHjFgsu5olUGIiNpbtVR8GcDeW7+iEtMGsP
         1ZhnzY/32Q7Ns45/GQslc1+dbu+7mdjeCiiPWt8vzVvUAzeqHuRA5eVy56hsbvoMmT17
         s6bIpx+0NtCf66VLST3/2q+yprKQlg3O9QmodgkXcUO0CkmGhf4IgeA5obrMseYjMOXp
         nXDHXFyt7TUmoM1sjzOI3m+6PpJyW3X7POah/G/yFR2j8g5HpuUUiSwPhJfXUVUpZ0Wy
         Szgjwj4+0i7ORjc2mtCeRJb3T8w0aE65IXqyybVGEr7aQ/sirAgOAkkLHmdlnUvp3J7A
         EJ7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PkSL8hEoRutXRWroD5iQR2Ez4Jx7mrQ+k/JOzq1oP3w=;
        b=BMiX0p9a8x2XIj6fvbn6kYp94rbQmoCdZG24t6V44/FbqM3GB4oy8EyAbqCzZ+AbVo
         rcoa1GAz6WQuKmxHk0ZUm1WC3a5F4NrAI09MsmP+TQ61We9xtxRsW1BiQT8xMf3myPSZ
         0J4N2wcHjnY0nFVD0TobibqS6/scPJwp2HlAL8y28OiMb6BoJJmSkrYi4BZCPRbdYmEx
         yqK06cevtfTxLyINldrJgvZt21OJF7Sal7zT8IgR43LR3szNOvK1DR2LptaTbGMFvEBP
         XzbsbT4Z1KqlpUeQNmHsQepi2yqWDfiYfwcIx5pJGOUbUK9qgpnuR5UniPLRpBLw51Na
         n+zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PkSL8hEoRutXRWroD5iQR2Ez4Jx7mrQ+k/JOzq1oP3w=;
        b=sPCy341cNMU4Rr7zF/H6aC07+1IZopzGyUV/Icxj2vH75htBMtjjDD7KUr2/FGGD0J
         CX61Fi01kfnB/bh70jTt6KWofhpSd8JrfQ7nF3+ZmFYw5cq1sciu2rK7MWqjkAA1pkFp
         tnK4sBQ63CK7FwwtWZKjQZmWyA6rRXMyb+VLAQnkzS5H9aRzdeEF+8ALeTez7+4gMkKz
         NNGalyPThGbkPzB2cbBOvb/SXTQaW7fg9x8Td9+pmZgTuNAJ0q1eNuN3Q4Tpr1Kvn4zC
         6SXBVaPsZXNhqrlmyP3MvVC4qq1R87lJiOmv9ZD67T+tin3HeHXxTRxgf7ImAyqKoREf
         EU0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaKXqycs0WRXi2Z1NTAs8lm8Wz/vNQXRlU3IFPur7azk28ao2jD
	F5E64fPzuSdZ2v265w77ujg=
X-Google-Smtp-Source: APiQypL86ClOLUQaBbUghezlLgCF9JSWXT53SLmb3aehqA6yBq32G/YB4SjnQdavyARQB5PUTd2y0Q==
X-Received: by 2002:a9d:12e2:: with SMTP id g89mr14139071otg.289.1588185405458;
        Wed, 29 Apr 2020 11:36:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2c91:: with SMTP id o139ls1848178ooo.11.gmail; Wed, 29
 Apr 2020 11:36:45 -0700 (PDT)
X-Received: by 2002:a4a:d247:: with SMTP id e7mr28740549oos.55.1588185404810;
        Wed, 29 Apr 2020 11:36:44 -0700 (PDT)
Date: Wed, 29 Apr 2020 11:36:43 -0700 (PDT)
From: samclaughlin2323@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f4179150-78b4-438e-bd13-ff12a41c9d26@googlegroups.com>
In-Reply-To: <20200424145521.8203-3-dja@axtens.net>
References: <20200424145521.8203-1-dja@axtens.net>
 <20200424145521.8203-3-dja@axtens.net>
Subject: Re: [PATCH v4 2/2] string.h: fix incompatibility between
 FORTIFY_SOURCE and KASAN
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3050_2069079169.1588185404095"
X-Original-Sender: samclaughlin2323@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_3050_2069079169.1588185404095
Content-Type: multipart/alternative; 
	boundary="----=_Part_3051_1438230620.1588185404096"

------=_Part_3051_1438230620.1588185404096
Content-Type: text/plain; charset="UTF-8"

fdshgfdsfdsfvdhsgfdsrepwwrp[wewreew
rjewhrjwerjehgrggjrwegrgewgrew

hghrwegfgrwegreggrwegrwerew rwe rwgyrtre[rw[rewrewprewrewtyytrwyter


On Friday, April 24, 2020 at 7:55:37 AM UTC-7, Daniel Axtens wrote:
>
> The memcmp KASAN self-test fails on a kernel with both KASAN and 
> FORTIFY_SOURCE. 
>
> When FORTIFY_SOURCE is on, a number of functions are replaced with 
> fortified versions, which attempt to check the sizes of the operands. 
> However, these functions often directly invoke __builtin_foo() once they 
> have performed the fortify check. Using __builtins may bypass KASAN 
> checks if the compiler decides to inline it's own implementation as 
> sequence of instructions, rather than emit a function call that goes out 
> to a KASAN-instrumented implementation. 
>
> Why is only memcmp affected? 
> ============================ 
>
> Of the string and string-like functions that kasan_test tests, only memcmp 
> is replaced by an inline sequence of instructions in my testing on x86 
> with 
> gcc version 9.2.1 20191008 (Ubuntu 9.2.1-9ubuntu2). 
>
> I believe this is due to compiler heuristics. For example, if I annotate 
> kmalloc calls with the alloc_size annotation (and disable some fortify 
> compile-time checking!), the compiler will replace every memset except the 
> one in kmalloc_uaf_memset with inline instructions. (I have some WIP 
> patches to add this annotation.) 
>
> Does this affect other functions in string.h? 
> ============================================= 
>
> Yes. Anything that uses __builtin_* rather than __real_* could be 
> affected. This looks like: 
>
>  - strncpy 
>  - strcat 
>  - strlen 
>  - strlcpy maybe, under some circumstances? 
>  - strncat under some circumstances 
>  - memset 
>  - memcpy 
>  - memmove 
>  - memcmp (as noted) 
>  - memchr 
>  - strcpy 
>
> Whether a function call is emitted always depends on the compiler. Most 
> bugs should get caught by FORTIFY_SOURCE, but the missed memcmp test shows 
> that this is not always the case. 
>
> Isn't FORTIFY_SOURCE disabled with KASAN? 
> ========================================- 
>
> The string headers on all arches supporting KASAN disable fortify with 
> kasan, but only when address sanitisation is _also_ disabled. For example 
> from x86: 
>
>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__) 
>  /* 
>   * For files that are not instrumented (e.g. mm/slub.c) we 
>   * should use not instrumented version of mem* functions. 
>   */ 
>  #define memcpy(dst, src, len) __memcpy(dst, src, len) 
>  #define memmove(dst, src, len) __memmove(dst, src, len) 
>  #define memset(s, c, n) __memset(s, c, n) 
>
>  #ifndef __NO_FORTIFY 
>  #define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */ 
>  #endif 
>
>  #endif 
>
> This comes from commit 6974f0c4555e ("include/linux/string.h: add the 
> option of fortified string.h functions"), and doesn't work when KASAN is 
> enabled and the file is supposed to be sanitised - as with test_kasan.c 
>
> I'm pretty sure this is not wrong, but not as expansive it should be: 
>
>  * we shouldn't use __builtin_memcpy etc in files where we don't have 
>    instrumentation - it could devolve into a function call to memcpy, 
>    which will be instrumented. Rather, we should use __memcpy which 
>    by convention is not instrumented. 
>
>  * we also shouldn't be using __builtin_memcpy when we have a KASAN 
>    instrumented file, because it could be replaced with inline asm 
>    that will not be instrumented. 
>
> What is correct behaviour? 
> ========================== 
>
> Firstly, there is some overlap between fortification and KASAN: both 
> provide some level of _runtime_ checking. Only fortify provides 
> compile-time checking. 
>
> KASAN and fortify can pick up different things at runtime: 
>
>  - Some fortify functions, notably the string functions, could easily be 
>    modified to consider sub-object sizes (e.g. members within a struct), 
>    and I have some WIP patches to do this. KASAN cannot detect these 
>    because it cannot insert poision between members of a struct. 
>
>  - KASAN can detect many over-reads/over-writes when the sizes of both 
>    operands are unknown, which fortify cannot. 
>
> So there are a couple of options: 
>
>  1) Flip the test: disable fortify in santised files and enable it in 
>     unsanitised files. This at least stops us missing KASAN checking, but 
>     we lose the fortify checking. 
>
>  2) Make the fortify code always call out to real versions. Do this only 
>     for KASAN, for fear of losing the inlining opportunities we get from 
>     __builtin_*. 
>
> (We can't use kasan_check_{read,write}: because the fortify functions are 
> _extern inline_, you can't include _static_ inline functions without a 
> compiler warning. kasan_check_{read,write} are static inline so we can't 
> use them even when they would otherwise be suitable.) 
>
> Take approach 2 and call out to real versions when KASAN is enabled. 
>
> Use __underlying_foo to distinguish from __real_foo: __real_foo always 
> refers to the kernel's implementation of foo, __underlying_foo could be 
> either the kernel implementation or the __builtin_foo implementation. 
>
> Cc: Daniel Micay <danie...@gmail.com <javascript:>> 
> Cc: Andrey Ryabinin <arya...@virtuozzo.com <javascript:>> 
> Cc: Alexander Potapenko <gli...@google.com <javascript:>> 
> Cc: Dmitry Vyukov <dvy...@google.com <javascript:>> 
> Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified 
> string.h functions") 
> Reviewed-by: Dmitry Vyukov <dvy...@google.com <javascript:>> 
> Tested-by: David Gow <davi...@google.com <javascript:>> 
> Signed-off-by: Daniel Axtens <d...@axtens.net <javascript:>> 
> --- 
>  include/linux/string.h | 60 +++++++++++++++++++++++++++++++++--------- 
>  1 file changed, 48 insertions(+), 12 deletions(-) 
>
> diff --git a/include/linux/string.h b/include/linux/string.h 
> index 6dfbb2efa815..9b7a0632e87a 100644 
> --- a/include/linux/string.h 
> +++ b/include/linux/string.h 
> @@ -272,6 +272,31 @@ void __read_overflow3(void) 
> __compiletime_error("detected read beyond size of ob 
>  void __write_overflow(void) __compiletime_error("detected write beyond 
> size of object passed as 1st parameter"); 
>   
>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && 
> defined(CONFIG_FORTIFY_SOURCE) 
> + 
> +#ifdef CONFIG_KASAN 
> +extern void *__underlying_memchr(const void *p, int c, __kernel_size_t 
> size) __RENAME(memchr); 
> +extern int __underlying_memcmp(const void *p, const void *q, 
> __kernel_size_t size) __RENAME(memcmp); 
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t 
> size) __RENAME(memcpy); 
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t 
> size) __RENAME(memmove); 
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) 
> __RENAME(memset); 
> +extern char *__underlying_strcat(char *p, const char *q) 
> __RENAME(strcat); 
> +extern char *__underlying_strcpy(char *p, const char *q) 
> __RENAME(strcpy); 
> +extern __kernel_size_t __underlying_strlen(const char *p) 
> __RENAME(strlen); 
> +extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t 
> count) __RENAME(strncat); 
> +extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t 
> size) __RENAME(strncpy); 
> +#else 
> +#define __underlying_memchr        __builtin_memchr 
> +#define __underlying_memcmp        __builtin_memcmp 
> +#define __underlying_memcpy        __builtin_memcpy 
> +#define __underlying_memmove        __builtin_memmove 
> +#define __underlying_memset        __builtin_memset 
> +#define __underlying_strcat        __builtin_strcat 
> +#define __underlying_strcpy        __builtin_strcpy 
> +#define __underlying_strlen        __builtin_strlen 
> +#define __underlying_strncat        __builtin_strncat 
> +#define __underlying_strncpy        __builtin_strncpy 
> +#endif 
> + 
>  __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t 
> size) 
>  { 
>          size_t p_size = __builtin_object_size(p, 0); 
> @@ -279,14 +304,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char 
> *q, __kernel_size_t size) 
>                  __write_overflow(); 
>          if (p_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_strncpy(p, q, size); 
> +        return __underlying_strncpy(p, q, size); 
>  } 
>   
>  __FORTIFY_INLINE char *strcat(char *p, const char *q) 
>  { 
>          size_t p_size = __builtin_object_size(p, 0); 
>          if (p_size == (size_t)-1) 
> -                return __builtin_strcat(p, q); 
> +                return __underlying_strcat(p, q); 
>          if (strlcat(p, q, p_size) >= p_size) 
>                  fortify_panic(__func__); 
>          return p; 
> @@ -300,7 +325,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p) 
>          /* Work around gcc excess stack consumption issue */ 
>          if (p_size == (size_t)-1 || 
>              (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == 
> '\0')) 
> -                return __builtin_strlen(p); 
> +                return __underlying_strlen(p); 
>          ret = strnlen(p, p_size); 
>          if (p_size <= ret) 
>                  fortify_panic(__func__); 
> @@ -333,7 +358,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char 
> *q, size_t size) 
>                          __write_overflow(); 
>                  if (len >= p_size) 
>                          fortify_panic(__func__); 
> -                __builtin_memcpy(p, q, len); 
> +                __underlying_memcpy(p, q, len); 
>                  p[len] = '\0'; 
>          } 
>          return ret; 
> @@ -346,12 +371,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char 
> *q, __kernel_size_t count) 
>          size_t p_size = __builtin_object_size(p, 0); 
>          size_t q_size = __builtin_object_size(q, 0); 
>          if (p_size == (size_t)-1 && q_size == (size_t)-1) 
> -                return __builtin_strncat(p, q, count); 
> +                return __underlying_strncat(p, q, count); 
>          p_len = strlen(p); 
>          copy_len = strnlen(q, count); 
>          if (p_size < p_len + copy_len + 1) 
>                  fortify_panic(__func__); 
> -        __builtin_memcpy(p + p_len, q, copy_len); 
> +        __underlying_memcpy(p + p_len, q, copy_len); 
>          p[p_len + copy_len] = '\0'; 
>          return p; 
>  } 
> @@ -363,7 +388,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, 
> __kernel_size_t size) 
>                  __write_overflow(); 
>          if (p_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_memset(p, c, size); 
> +        return __underlying_memset(p, c, size); 
>  } 
>   
>  __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t 
> size) 
> @@ -378,7 +403,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, 
> __kernel_size_t size) 
>          } 
>          if (p_size < size || q_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_memcpy(p, q, size); 
> +        return __underlying_memcpy(p, q, size); 
>  } 
>   
>  __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t 
> size) 
> @@ -393,7 +418,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, 
> __kernel_size_t size) 
>          } 
>          if (p_size < size || q_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_memmove(p, q, size); 
> +        return __underlying_memmove(p, q, size); 
>  } 
>   
>  extern void *__real_memscan(void *, int, __kernel_size_t) 
> __RENAME(memscan); 
> @@ -419,7 +444,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void 
> *q, __kernel_size_t size) 
>          } 
>          if (p_size < size || q_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_memcmp(p, q, size); 
> +        return __underlying_memcmp(p, q, size); 
>  } 
>   
>  __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size) 
> @@ -429,7 +454,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, 
> __kernel_size_t size) 
>                  __read_overflow(); 
>          if (p_size < size) 
>                  fortify_panic(__func__); 
> -        return __builtin_memchr(p, c, size); 
> +        return __underlying_memchr(p, c, size); 
>  } 
>   
>  void *__real_memchr_inv(const void *s, int c, size_t n) 
> __RENAME(memchr_inv); 
> @@ -460,11 +485,22 @@ __FORTIFY_INLINE char *strcpy(char *p, const char 
> *q) 
>          size_t p_size = __builtin_object_size(p, 0); 
>          size_t q_size = __builtin_object_size(q, 0); 
>          if (p_size == (size_t)-1 && q_size == (size_t)-1) 
> -                return __builtin_strcpy(p, q); 
> +                return __underlying_strcpy(p, q); 
>          memcpy(p, q, strlen(q) + 1); 
>          return p; 
>  } 
>   
> +/* Don't use these outside the FORITFY_SOURCE implementation */ 
> +#undef __underlying_memchr 
> +#undef __underlying_memcmp 
> +#undef __underlying_memcpy 
> +#undef __underlying_memmove 
> +#undef __underlying_memset 
> +#undef __underlying_strcat 
> +#undef __underlying_strcpy 
> +#undef __underlying_strlen 
> +#undef __underlying_strncat 
> +#undef __underlying_strncpy 
>  #endif 
>   
>  /** 
> -- 
> 2.20.1 
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4179150-78b4-438e-bd13-ff12a41c9d26%40googlegroups.com.

------=_Part_3051_1438230620.1588185404096
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

fdshgfdsfdsfvdhsgfdsrepwwrp[wewreew<div>rjewhrjwerjehgrggjrwegrgewgrew</div=
><div><br></div><div>hghrwegfgrwegreggrwegrwerew rwe rwgyrtre[rw[rewrewprew=
rewtyytrwyter</div><div><br><br>On Friday, April 24, 2020 at 7:55:37 AM UTC=
-7, Daniel Axtens wrote:<blockquote class=3D"gmail_quote" style=3D"margin: =
0;margin-left: 0.8ex;border-left: 1px #ccc solid;padding-left: 1ex;">The me=
mcmp KASAN self-test fails on a kernel with both KASAN and
<br>FORTIFY_SOURCE.
<br>
<br>When FORTIFY_SOURCE is on, a number of functions are replaced with
<br>fortified versions, which attempt to check the sizes of the operands.
<br>However, these functions often directly invoke __builtin_foo() once the=
y
<br>have performed the fortify check. Using __builtins may bypass KASAN
<br>checks if the compiler decides to inline it&#39;s own implementation as
<br>sequence of instructions, rather than emit a function call that goes ou=
t
<br>to a KASAN-instrumented implementation.
<br>
<br>Why is only memcmp affected?
<br>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D
<br>
<br>Of the string and string-like functions that kasan_test tests, only mem=
cmp
<br>is replaced by an inline sequence of instructions in my testing on x86 =
with
<br>gcc version 9.2.1 20191008 (Ubuntu 9.2.1-9ubuntu2).
<br>
<br>I believe this is due to compiler heuristics. For example, if I annotat=
e
<br>kmalloc calls with the alloc_size annotation (and disable some fortify
<br>compile-time checking!), the compiler will replace every memset except =
the
<br>one in kmalloc_uaf_memset with inline instructions. (I have some WIP
<br>patches to add this annotation.)
<br>
<br>Does this affect other functions in string.h?
<br>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D<wbr>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
<br>
<br>Yes. Anything that uses __builtin_* rather than __real_* could be
<br>affected. This looks like:
<br>
<br>=C2=A0- strncpy
<br>=C2=A0- strcat
<br>=C2=A0- strlen
<br>=C2=A0- strlcpy maybe, under some circumstances?
<br>=C2=A0- strncat under some circumstances
<br>=C2=A0- memset
<br>=C2=A0- memcpy
<br>=C2=A0- memmove
<br>=C2=A0- memcmp (as noted)
<br>=C2=A0- memchr
<br>=C2=A0- strcpy
<br>
<br>Whether a function call is emitted always depends on the compiler. Most
<br>bugs should get caught by FORTIFY_SOURCE, but the missed memcmp test sh=
ows
<br>that this is not always the case.
<br>
<br>Isn&#39;t FORTIFY_SOURCE disabled with KASAN?
<br>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D<wbr>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D-
<br>
<br>The string headers on all arches supporting KASAN disable fortify with
<br>kasan, but only when address sanitisation is _also_ disabled. For examp=
le
<br>from x86:
<br>
<br>=C2=A0#if defined(CONFIG_KASAN) &amp;&amp; !defined(__SANITIZE_ADDRESS_=
_)
<br>=C2=A0/*
<br>=C2=A0 * For files that are not instrumented (e.g. mm/slub.c) we
<br>=C2=A0 * should use not instrumented version of mem* functions.
<br>=C2=A0 */
<br>=C2=A0#define memcpy(dst, src, len) __memcpy(dst, src, len)
<br>=C2=A0#define memmove(dst, src, len) __memmove(dst, src, len)
<br>=C2=A0#define memset(s, c, n) __memset(s, c, n)
<br>
<br>=C2=A0#ifndef __NO_FORTIFY
<br>=C2=A0#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc=
. */
<br>=C2=A0#endif
<br>
<br>=C2=A0#endif
<br>
<br>This comes from commit 6974f0c4555e (&quot;include/linux/string.h: add =
the
<br>option of fortified string.h functions&quot;), and doesn&#39;t work whe=
n KASAN is
<br>enabled and the file is supposed to be sanitised - as with test_kasan.c
<br>
<br>I&#39;m pretty sure this is not wrong, but not as expansive it should b=
e:
<br>
<br>=C2=A0* we shouldn&#39;t use __builtin_memcpy etc in files where we don=
&#39;t have
<br>=C2=A0 =C2=A0instrumentation - it could devolve into a function call to=
 memcpy,
<br>=C2=A0 =C2=A0which will be instrumented. Rather, we should use __memcpy=
 which
<br>=C2=A0 =C2=A0by convention is not instrumented.
<br>
<br>=C2=A0* we also shouldn&#39;t be using __builtin_memcpy when we have a =
KASAN
<br>=C2=A0 =C2=A0instrumented file, because it could be replaced with inlin=
e asm
<br>=C2=A0 =C2=A0that will not be instrumented.
<br>
<br>What is correct behaviour?
<br>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
<br>
<br>Firstly, there is some overlap between fortification and KASAN: both
<br>provide some level of _runtime_ checking. Only fortify provides
<br>compile-time checking.
<br>
<br>KASAN and fortify can pick up different things at runtime:
<br>
<br>=C2=A0- Some fortify functions, notably the string functions, could eas=
ily be
<br>=C2=A0 =C2=A0modified to consider sub-object sizes (e.g. members within=
 a struct),
<br>=C2=A0 =C2=A0and I have some WIP patches to do this. KASAN cannot detec=
t these
<br>=C2=A0 =C2=A0because it cannot insert poision between members of a stru=
ct.
<br>
<br>=C2=A0- KASAN can detect many over-reads/over-writes when the sizes of =
both
<br>=C2=A0 =C2=A0operands are unknown, which fortify cannot.
<br>
<br>So there are a couple of options:
<br>
<br>=C2=A01) Flip the test: disable fortify in santised files and enable it=
 in
<br>=C2=A0 =C2=A0 unsanitised files. This at least stops us missing KASAN c=
hecking, but
<br>=C2=A0 =C2=A0 we lose the fortify checking.
<br>
<br>=C2=A02) Make the fortify code always call out to real versions. Do thi=
s only
<br>=C2=A0 =C2=A0 for KASAN, for fear of losing the inlining opportunities =
we get from
<br>=C2=A0 =C2=A0 __builtin_*.
<br>
<br>(We can&#39;t use kasan_check_{read,write}: because the fortify functio=
ns are
<br>_extern inline_, you can&#39;t include _static_ inline functions withou=
t a
<br>compiler warning. kasan_check_{read,write} are static inline so we can&=
#39;t
<br>use them even when they would otherwise be suitable.)
<br>
<br>Take approach 2 and call out to real versions when KASAN is enabled.
<br>
<br>Use __underlying_foo to distinguish from __real_foo: __real_foo always
<br>refers to the kernel&#39;s implementation of foo, __underlying_foo coul=
d be
<br>either the kernel implementation or the __builtin_foo implementation.
<br>
<br>Cc: Daniel Micay &lt;<a href=3D"javascript:" target=3D"_blank" gdf-obfu=
scated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"this.href=3D=
&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;javascript:=
&#39;;return true;">danie...@gmail.com</a>&gt;
<br>Cc: Andrey Ryabinin &lt;<a href=3D"javascript:" target=3D"_blank" gdf-o=
bfuscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"this.href=
=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;javascri=
pt:&#39;;return true;">arya...@virtuozzo.com</a>&gt;
<br>Cc: Alexander Potapenko &lt;<a href=3D"javascript:" target=3D"_blank" g=
df-obfuscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"this.=
href=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;java=
script:&#39;;return true;">gli...@google.com</a>&gt;
<br>Cc: Dmitry Vyukov &lt;<a href=3D"javascript:" target=3D"_blank" gdf-obf=
uscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"this.href=
=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;javascri=
pt:&#39;;return true;">dvy...@google.com</a>&gt;
<br>Fixes: 6974f0c4555e (&quot;include/linux/string.h: add the option of fo=
rtified string.h functions&quot;)
<br>Reviewed-by: Dmitry Vyukov &lt;<a href=3D"javascript:" target=3D"_blank=
" gdf-obfuscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"th=
is.href=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;j=
avascript:&#39;;return true;">dvy...@google.com</a>&gt;
<br>Tested-by: David Gow &lt;<a href=3D"javascript:" target=3D"_blank" gdf-=
obfuscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"this.hre=
f=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39;javascr=
ipt:&#39;;return true;">davi...@google.com</a>&gt;
<br>Signed-off-by: Daniel Axtens &lt;<a href=3D"javascript:" target=3D"_bla=
nk" gdf-obfuscated-mailto=3D"tKzjlpIqAwAJ" rel=3D"nofollow" onmousedown=3D"=
this.href=3D&#39;javascript:&#39;;return true;" onclick=3D"this.href=3D&#39=
;javascript:&#39;;return true;">d...@axtens.net</a>&gt;
<br>---
<br>=C2=A0include/linux/string.h | 60 ++++++++++++++++++++++++++++++<wbr>++=
+---------
<br>=C2=A01 file changed, 48 insertions(+), 12 deletions(-)
<br>
<br>diff --git a/include/linux/string.h b/include/linux/string.h
<br>index 6dfbb2efa815..9b7a0632e87a 100644
<br>--- a/include/linux/string.h
<br>+++ b/include/linux/string.h
<br>@@ -272,6 +272,31 @@ void __read_overflow3(void) __compiletime_error(&q=
uot;detected read beyond size of ob
<br>=C2=A0void __write_overflow(void) __compiletime_error(&quot;detected wr=
ite beyond size of object passed as 1st parameter&quot;);
<br>=C2=A0
<br>=C2=A0#if !defined(__NO_FORTIFY) &amp;&amp; defined(__OPTIMIZE__) &amp;=
&amp; defined(CONFIG_FORTIFY_SOURCE)
<br>+
<br>+#ifdef CONFIG_KASAN
<br>+extern void *__underlying_memchr(const void *p, int c, __kernel_size_t=
 size) __RENAME(memchr);
<br>+extern int __underlying_memcmp(const void *p, const void *q, __kernel_=
size_t size) __RENAME(memcmp);
<br>+extern void *__underlying_memcpy(void *p, const void *q, __kernel_size=
_t size) __RENAME(memcpy);
<br>+extern void *__underlying_memmove(void *p, const void *q, __kernel_siz=
e_t size) __RENAME(memmove);
<br>+extern void *__underlying_memset(void *p, int c, __kernel_size_t size)=
 __RENAME(memset);
<br>+extern char *__underlying_strcat(char *p, const char *q) __RENAME(strc=
at);
<br>+extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strc=
py);
<br>+extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(str=
len);
<br>+extern char *__underlying_strncat(char *p, const char *q, __kernel_siz=
e_t count) __RENAME(strncat);
<br>+extern char *__underlying_strncpy(char *p, const char *q, __kernel_siz=
e_t size) __RENAME(strncpy);
<br>+#else
<br>+#define __underlying_memchr=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_memchr
<br>+#define __underlying_memcmp=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_memcmp
<br>+#define __underlying_memcpy=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_memcpy
<br>+#define __underlying_memmove=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_memmove
<br>+#define __underlying_memset=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_memset
<br>+#define __underlying_strcat=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_strcat
<br>+#define __underlying_strcpy=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_strcpy
<br>+#define __underlying_strlen=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_strlen
<br>+#define __underlying_strncat=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_strncat
<br>+#define __underlying_strncpy=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>builtin_strncpy
<br>+#endif
<br>+
<br>=C2=A0__FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_s=
ize_t size)
<br>=C2=A0{
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t p_size =3D=
 __builtin_object_size(p, 0);
<br>@@ -279,14 +304,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const cha=
r *q, __kernel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__write_<wbr>overflow();
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_strnc=
py(p, q, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_st=
rncpy(p, q, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0__FORTIFY_INLINE char *strcat(char *p, const char *q)
<br>=C2=A0{
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t p_size =3D=
 __builtin_object_size(p, 0);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size =3D=3D=
 (size_t)-1)
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_strcat(p, q);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_strcat(p, q);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (strlcat(p, q,=
 p_size) &gt;=3D p_size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return p;
<br>@@ -300,7 +325,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char =
*p)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Work around gc=
c excess stack consumption issue */
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size =3D=3D=
 (size_t)-1 ||
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0 =C2=A0(__=
builtin_constant_p(p[p_<wbr>size - 1]) &amp;&amp; p[p_size - 1] =3D=3D &#39=
;\0&#39;))
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_strlen(p);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_strlen(p);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ret =3D strnlen(p=
, p_size);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt;=
=3D ret)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>@@ -333,7 +358,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char=
 *q, size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0__<wbr>write_overflow();
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (len &gt;=3D p_size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0<wbr>fortify_panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0__builtin_<wbr>memcpy(p, q, len);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0__underlying_<wbr>memcpy(p, q, len);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0p[len] =3D &#39;\0&#39;;
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
<br>@@ -346,12 +371,12 @@ __FORTIFY_INLINE char *strncat(char *p, const cha=
r *q, __kernel_size_t count)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t p_size =3D=
 __builtin_object_size(p, 0);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t q_size =3D=
 __builtin_object_size(q, 0);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size =3D=3D=
 (size_t)-1 &amp;&amp; q_size =3D=3D (size_t)-1)
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_strncat(p, q, count);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_strncat(p, q, count);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0p_len =3D strlen(=
p);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0copy_len =3D strn=
len(q, count);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; p=
_len + copy_len + 1)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__builtin_memcpy(p + p=
_len, q, copy_len);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__underlying_memcpy(p =
+ p_len, q, copy_len);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0p[p_len + copy_le=
n] =3D &#39;\0&#39;;
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return p;
<br>=C2=A0}
<br>@@ -363,7 +388,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __ker=
nel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__write_<wbr>overflow();
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_memse=
t(p, c, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_me=
mset(p, c, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0__FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_si=
ze_t size)
<br>@@ -378,7 +403,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *=
q, __kernel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize || q_size &lt; size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_memcp=
y(p, q, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_me=
mcpy(p, q, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0__FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_s=
ize_t size)
<br>@@ -393,7 +418,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void =
*q, __kernel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize || q_size &lt; size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_memmo=
ve(p, q, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_me=
mmove(p, q, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0extern void *__real_memscan(void *, int, __kernel_size_t) __RENAM=
E(memscan);
<br>@@ -419,7 +444,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const vo=
id *q, __kernel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize || q_size &lt; size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_memcm=
p(p, q, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_me=
mcmp(p, q, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0__FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size=
_t size)
<br>@@ -429,7 +454,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c,=
 __kernel_size_t size)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__read_<wbr>overflow();
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size &lt; s=
ize)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fortify_<wbr>panic(__func__);
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_memch=
r(p, c, size);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_me=
mchr(p, c, size);
<br>=C2=A0}
<br>=C2=A0
<br>=C2=A0void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(=
memchr_inv);
<br>@@ -460,11 +485,22 @@ __FORTIFY_INLINE char *strcpy(char *p, const char=
 *q)
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t p_size =3D=
 __builtin_object_size(p, 0);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0size_t q_size =3D=
 __builtin_object_size(q, 0);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (p_size =3D=3D=
 (size_t)-1 &amp;&amp; q_size =3D=3D (size_t)-1)
<br>-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __builtin_strcpy(p, q);
<br>+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0return __underlying_strcpy(p, q);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0memcpy(p, q, strl=
en(q) + 1);
<br>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return p;
<br>=C2=A0}
<br>=C2=A0
<br>+/* Don&#39;t use these outside the FORITFY_SOURCE implementation */
<br>+#undef __underlying_memchr
<br>+#undef __underlying_memcmp
<br>+#undef __underlying_memcpy
<br>+#undef __underlying_memmove
<br>+#undef __underlying_memset
<br>+#undef __underlying_strcat
<br>+#undef __underlying_strcpy
<br>+#undef __underlying_strlen
<br>+#undef __underlying_strncat
<br>+#undef __underlying_strncpy
<br>=C2=A0#endif
<br>=C2=A0
<br>=C2=A0/**
<br>--=20
<br>2.20.1
<br>
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f4179150-78b4-438e-bd13-ff12a41c9d26%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/f4179150-78b4-438e-bd13-ff12a41c9d26%40googlegroups.com</a>.<br =
/>

------=_Part_3051_1438230620.1588185404096--

------=_Part_3050_2069079169.1588185404095--
