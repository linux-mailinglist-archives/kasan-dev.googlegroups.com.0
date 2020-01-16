Return-Path: <kasan-dev+bncBCMIZB7QWENRBPVVQDYQKGQEKLNA3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 60B9213D5BB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:11:43 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id e22sf7533570oig.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579162302; cv=pass;
        d=google.com; s=arc-20160816;
        b=z3kd9ySYCOuYi/i2u1bL3iUbT3p2kN17vzezXILvSVTz4gpkRjcwFAu+l7whPptu0y
         Hdem4tWe4RIdQcuAbgDvcgg/+XfbLSmML97ymXlTlBvxlk5jziUxCFxHMcWTjUttOERB
         9KzUn32eEqRAhttGN1DD6nf6n8YmH0mknF5bLgcTLhQGmk11a1LSThXSr8YMcgHr9Eov
         e4ZR1kegOY9Uk47IODfAx/fEo3D0oYOCwYyQhfbxPKhz9TLwAJ4aZCZeoRd0KZIS16fn
         vwQQFlI42kS5h3gheGEfs5mh0XVdhNsiGKse/73cRSUUl+9PIotAtR0n1UcMTvU8WAua
         ewug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=POPJlqIMl1ukx3q/worfNJ7Nvl1qUj1H3LCqbXlymC4=;
        b=YbJIVaGz8XMd16qIyXY7whhdjjUz8YLdjvIs4Hb/XmsaDJEVjYKNjiEtGyCWDoZuS5
         ySuwtnR3BjZDLX5d7zvLUKZ6dUMBW9v5EO3s5HotLTELyFjBdy8BqEqT44LYDEFqbFvJ
         wEhuJjpnj93kQJV+/w/wU2+JuZULrlJ1QxldfYU3mOz2NHfE6DmLR7ygL6OhQkwhAz3x
         UVxZNpHia20k5tqMwikgI72v+fo+MQGevbbAvZBoCoiMEFNFRbNZxbSau83WKZ4sORNu
         iyWRznjOIS2F3w9CJGSgvpJHC8mxynPPNY0f4fbUHCW/s0TEfOOA7uz7vRKW5CZ1Evxq
         ++uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WlNJ9Xb/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POPJlqIMl1ukx3q/worfNJ7Nvl1qUj1H3LCqbXlymC4=;
        b=JQK8muIsdLsP9WvZ4cylKhdXfhzg8AAytpIgWcKYyWhd16uDpdPe3CKTlLZknCfzLI
         df34flWjl/bpGR6OVz4KE6ZCVw0HrewG3K/TvmsppmlAOBGxp0k5NMVj6SGd0m4hXCTS
         fRD3kOQvRoQBHAaGHsECnubP4HiKrwltoNnZt9qLnOosf7FX097NYoKnorVAI1x80Pkl
         eHXDt8cqo5FC3JRcQa+6tV5oKwnMKXXPPUOmUlBJJnSQI8VPYc6TuJ29Ju/ZkW6latzp
         f8sjPyg9hf+S/wl+nHy4VogDnbOx+QDwpI74ilLYvaJphFTFgbEitZJg68pZIXQXEx0B
         9Sig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POPJlqIMl1ukx3q/worfNJ7Nvl1qUj1H3LCqbXlymC4=;
        b=n1Q+NBYFgIXUnQg2TYFb6T4hL7+2FbzzFaQS/zv48SCprfiFRuUmJrzXd+NsTT9WGM
         bTeWH74S34Glgig9WNYeb+eJobcsIk9wSZmgAleeMkhIoHTI/LqydIo0bclPB+8C50Hp
         G+quuO3q6p6CIfEJOqnAlPYbLaNYS976vzkjqvuF8EtsGjWFt0G2IOZyqvLpX+UmPVpP
         iYcyEpCg3hBtmLwYTGQYOHdAalC7m4x1VJEvxnCaG77aMvr9rAu1rHLvxvHYPusA+RQK
         JdiOKYSoUsxfmM/hpID4yFjhgu5QoBviwnHSb37e9CjDBqO9eAWPniYMcSY70SlMX1ye
         HV7g==
X-Gm-Message-State: APjAAAX6lgz/bo71JXd9laggRYFPjpMmOMxs/RVcPkFNgnnT5bRahA/B
	Fd5HxShKQrctnn8WOm9DA1E=
X-Google-Smtp-Source: APXvYqzasapxghXWsZNj5rxTP9ZpUhLcglUFY6J6R5xORaf99U/vwopuDCBeIPHrdnfu8APZT8ut1A==
X-Received: by 2002:a9d:74c7:: with SMTP id a7mr1102586otl.7.1579162302106;
        Thu, 16 Jan 2020 00:11:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60d0:: with SMTP id b16ls3864460otk.0.gmail; Thu, 16 Jan
 2020 00:11:41 -0800 (PST)
X-Received: by 2002:a9d:7616:: with SMTP id k22mr1069713otl.364.1579162301703;
        Thu, 16 Jan 2020 00:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579162301; cv=none;
        d=google.com; s=arc-20160816;
        b=dmYmhAUFCpErNHBLZBaMkXxTsnESoHiaVU1vDk/K+pLJBLiP/h/r4bBpEKKM48TF2z
         /DfDX9WKzMoQTgJHDPmX1Tuw1x5+fZk/jYVOCLMKmCpyxpEwkeEzpo9+1I/SDgWAYSs1
         7SZZEC0VIdba67VD2ZJlwj+MBrc5ayaB6peolGoIoph5yw3leK7okcQjEm6M5tfCG8ru
         KGz9wfDSv+uhKK3T8LExQJ1F93T1mPACgQnvwNnKrR07ZH0r7eMVGGFeMPW4lnNBWP/j
         wQ1iVY/s97y1WzZv82Dy9Xt0Gku+/cAmchKASmmQZJcyvoWlp5FF/Hp1/XdXa74XC/tg
         qytw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9cA48MMBOQHJK5hX776mf3AO5GIfMTcVwVO3yILYkD4=;
        b=iIlseQNzjB+lWTo51YVVP18sk6c1bVhXV7bn1k1n4DlW1nJkiExEkzNxDEz6nkIWma
         E1ka7tzCyRTbRntID6ScoP/jVt/KS+oWTu/LfUYZaD+JxR5BC6T7n7rPSaG74MP504+C
         /X+71WilIB0Csg+3Nes4BuXAabXwD7ClD87h0+5HOKX3PzUz9G6ctNK6vQJ97Y1Zm/3m
         AKPn8l9V8XdRkuAfPH5KTLS+U8ombr0UEXlvxdEgv5ROgWU7pgfDAXAdDJwdpHT6wl3p
         e2zFCyrg7hhasvGYwp1qT6o1lj+2VuL4OHmOsmIpQnyA8iuBIAtk9VjX43865D02xCr3
         86gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WlNJ9Xb/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id p5si968443oip.3.2020.01.16.00.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:11:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id z76so18336991qka.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:11:41 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr32222475qki.250.1579162300813;
 Thu, 16 Jan 2020 00:11:40 -0800 (PST)
MIME-Version: 1.0
References: <20200116062625.32692-1-dja@axtens.net> <20200116062625.32692-3-dja@axtens.net>
In-Reply-To: <20200116062625.32692-3-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:11:28 +0100
Message-ID: <CACT4Y+ZmzN5z4kZsV_6zBX0SKyLzNKmNNa3Bixnr4SXLaWSbhw@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] string.h: fix incompatibility between
 FORTIFY_SOURCE and KASAN
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	"the arch/x86 maintainers" <x86@kernel.org>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	Daniel Micay <danielmicay@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="WlNJ9Xb/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jan 16, 2020 at 7:26 AM Daniel Axtens <dja@axtens.net> wrote:
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
> is replaced by an inline sequence of instructions in my testing on x86 with
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
> This is sometimes enough to make the memcmp test succeed with
> FORTIFY_SOURCE enabled. It is at least enough to get the function call
> into the module. One more fix is needed to make it reliable: see the next
> patch.
>
> Cc: Daniel Micay <danielmicay@gmail.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified string.h functions")
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>
> v2: add #undefs, do not drop arch code: Dmitry pointed out that we _do_ want
>     to disable fortify in non-sanitised files because of how __builtin_memcpy
>     might end up as a call to regular memcpy rather than __memcpy.
>
> Dmitry, this might cause a few new syzkaller splats - I first picked it up
> building from a syskaller config. Or it might not, it just depends what gets
> replaced with an inline sequence of instructions.

If you mean new true bugs, I don't think it's changing anything on top
of the hundreds of known existing open bugs:
https://syzkaller.appspot.com/upstream#open
If anything, I would say it's good to surface more true bugs.


> checkpatch complains about some over-long lines, happy to change the format
> if anyone has better ideas for how to lay it out.
> ---
>  include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
>  1 file changed, 48 insertions(+), 12 deletions(-)
>
> diff --git a/include/linux/string.h b/include/linux/string.h
> index 3b8e8b12dd37..18d3f7a4b2b9 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -317,6 +317,31 @@ void __read_overflow3(void) __compiletime_error("detected read beyond size of ob
>  void __write_overflow(void) __compiletime_error("detected write beyond size of object passed as 1st parameter");
>
>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
> +
> +#ifdef CONFIG_KASAN
> +extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
> +extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
> +extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
> +extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
> +extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
> +extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
> +extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
> +#else
> +#define __underlying_memchr    __builtin_memchr
> +#define __underlying_memcmp    __builtin_memcmp
> +#define __underlying_memcpy    __builtin_memcpy
> +#define __underlying_memmove   __builtin_memmove
> +#define __underlying_memset    __builtin_memset
> +#define __underlying_strcat    __builtin_strcat
> +#define __underlying_strcpy    __builtin_strcpy
> +#define __underlying_strlen    __builtin_strlen
> +#define __underlying_strncat   __builtin_strncat
> +#define __underlying_strncpy   __builtin_strncpy
> +#endif
> +
>  __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
>  {
>         size_t p_size = __builtin_object_size(p, 0);
> @@ -324,14 +349,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
>                 __write_overflow();
>         if (p_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_strncpy(p, q, size);
> +       return __underlying_strncpy(p, q, size);
>  }
>
>  __FORTIFY_INLINE char *strcat(char *p, const char *q)
>  {
>         size_t p_size = __builtin_object_size(p, 0);
>         if (p_size == (size_t)-1)
> -               return __builtin_strcat(p, q);
> +               return __underlying_strcat(p, q);
>         if (strlcat(p, q, p_size) >= p_size)
>                 fortify_panic(__func__);
>         return p;
> @@ -345,7 +370,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p)
>         /* Work around gcc excess stack consumption issue */
>         if (p_size == (size_t)-1 ||
>             (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == '\0'))
> -               return __builtin_strlen(p);
> +               return __underlying_strlen(p);
>         ret = strnlen(p, p_size);
>         if (p_size <= ret)
>                 fortify_panic(__func__);
> @@ -378,7 +403,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char *q, size_t size)
>                         __write_overflow();
>                 if (len >= p_size)
>                         fortify_panic(__func__);
> -               __builtin_memcpy(p, q, len);
> +               __underlying_memcpy(p, q, len);
>                 p[len] = '\0';
>         }
>         return ret;
> @@ -391,12 +416,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char *q, __kernel_size_t count)
>         size_t p_size = __builtin_object_size(p, 0);
>         size_t q_size = __builtin_object_size(q, 0);
>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
> -               return __builtin_strncat(p, q, count);
> +               return __underlying_strncat(p, q, count);
>         p_len = strlen(p);
>         copy_len = strnlen(q, count);
>         if (p_size < p_len + copy_len + 1)
>                 fortify_panic(__func__);
> -       __builtin_memcpy(p + p_len, q, copy_len);
> +       __underlying_memcpy(p + p_len, q, copy_len);
>         p[p_len + copy_len] = '\0';
>         return p;
>  }
> @@ -408,7 +433,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __kernel_size_t size)
>                 __write_overflow();
>         if (p_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_memset(p, c, size);
> +       return __underlying_memset(p, c, size);
>  }
>
>  __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
> @@ -423,7 +448,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
>         }
>         if (p_size < size || q_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_memcpy(p, q, size);
> +       return __underlying_memcpy(p, q, size);
>  }
>
>  __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
> @@ -438,7 +463,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
>         }
>         if (p_size < size || q_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_memmove(p, q, size);
> +       return __underlying_memmove(p, q, size);
>  }
>
>  extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
> @@ -464,7 +489,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void *q, __kernel_size_t size)
>         }
>         if (p_size < size || q_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_memcmp(p, q, size);
> +       return __underlying_memcmp(p, q, size);
>  }
>
>  __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
> @@ -474,7 +499,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
>                 __read_overflow();
>         if (p_size < size)
>                 fortify_panic(__func__);
> -       return __builtin_memchr(p, c, size);
> +       return __underlying_memchr(p, c, size);
>  }
>
>  void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(memchr_inv);
> @@ -505,11 +530,22 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
>         size_t p_size = __builtin_object_size(p, 0);
>         size_t q_size = __builtin_object_size(q, 0);
>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
> -               return __builtin_strcpy(p, q);
> +               return __underlying_strcpy(p, q);
>         memcpy(p, q, strlen(q) + 1);
>         return p;
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZmzN5z4kZsV_6zBX0SKyLzNKmNNa3Bixnr4SXLaWSbhw%40mail.gmail.com.
