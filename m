Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMG377YAKGQE6V47JKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 836DB13D353
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 05:59:29 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id l25sf12873963qtu.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 20:59:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579150768; cv=pass;
        d=google.com; s=arc-20160816;
        b=kSx9MvPS3+jINgk7OBbPw2+uKoMUwjaamYZQJWgFpzUNPE2N27va0nO+cFW94JriAu
         qBptQ6a7+/tZdzRP4AS1Vwakx4nj3KA9PNuy55KkJuYeJmW0chtmLri5r9u6AgA7GQa1
         WHb+k5TkDPAUOmD5N9CNqI4LaJl+NsbSsjlG2k5IoD/qdjHJlRZNO/+RNJoybz5Z0ply
         BMhsm+fZ5OFI8+3Pvj/bR0iaVC+LjbmwQmi4VoAQHJTnTpqBL/fnaFVV72ShG+14ttXs
         wgx6s1IjCzQevRqEwufP88KWQZElGbqr5rlGCeqTCiOph/nCvD7XJVqMXiXk8RjFwp2a
         MTkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=eFFeWvojgvlUQSWe29QbMUWmC2K3SR19t2dlLAS3Q9A=;
        b=FYs96tdgN6UGssEgadwBVBng9jImNPSp1AJ23k+In6xKB2/HndFEzHlmf/JzKW/wj4
         Cb9jYcGk5dbv/E96qV7X5Sj3x2lcUn5Ona3fGrmdhVJoiFCk2hklOg5u0TlZAg7J/S3J
         iQfKPtFrkax4APt6FXm8XNjdYDxb09DPYlv32x8YkgW17P6aKVbOOhqyxhPBbXoNQ9YP
         Nen/PLaNygZLWmyrDycPfkU1VpJcvnWNcAMwxerYg59QH0CfRsIBCZclJpzSW4u3wVGf
         rAdQYUZu5ZzHIDUy3NB1zwMoaialvycxkKUNpAWUJHQuP59yTxM/H1mWGFACIKjmiExb
         Vdqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EqouT2wd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFFeWvojgvlUQSWe29QbMUWmC2K3SR19t2dlLAS3Q9A=;
        b=Qn1Zgnso83Zt1QnpPPnXlmynbXYKhVt4nN0dIBExs+3KrOyrCIkyc1zuWNB3eCr+vU
         5gzwVMtqTOjWYCQO/EcpQVeBcWlaDxqkITU0rk/9Z5Av1nJAHCLURud3IWe121lWkglN
         LrLqAhH/gVv4H9du2Pd8fgYRDDB/WPi51Ado/UO9RKy9nc9KscqjfRgHtqJ1xXUa5A66
         9IDJdXo1GWeSkELQ95Ixtw1v0OfxAXsRWDCy7SFg5E110+T0w/dEyf8ndJiBzix+XdH1
         5lttkEgDbsrckDYk1HfONo7dSb+v9MaggxJ+CD8BXZl2CPqEVmd2Hs+ErOczvK5D3gnC
         A2iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFFeWvojgvlUQSWe29QbMUWmC2K3SR19t2dlLAS3Q9A=;
        b=kqdPZxCGILUe9RPhhMxU7VzAc7tiX9sf+baC1cjwdkeNXmeHpjnqax/GDuAF2YENnT
         cusy5s+G+RvOcthST1OpVUhv2KZ6/X7O+kDPS1k2B7lVeVvr/EBMbXY3jtuOn/98LbBw
         c5hRply7KgO8iViK3EZ2/haP5KhViEd3/5vzNQDG8PNTUUC0IKBlAHrRS7Cw/JduPpPt
         j+xXxvSnWk77uHOqMzIUeIm+6AMm03W5ABHoPJjCSmZF4wphkDnnKrCJ+R20cisYeIIq
         vvHPwMRB+KM/MZeJpy9oZb7ziT3qUb299uiBXyDoDB99N0FZy7S3h5iorvY00UZd8A5C
         rCjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWqkwQcHc0bkyZRWILtZHnZA9kxSu3l7IrddjQo7hl91PRqZMQa
	C6KrWXe4h1fkklxK4cxC8LE=
X-Google-Smtp-Source: APXvYqzFIye/XNjA8wHeGdO5rsTIjkKZspoDKk1ZjvgdrThYucrfns5HJjPoVgiikg/cnR2BFFXnSg==
X-Received: by 2002:ac8:514c:: with SMTP id h12mr671992qtn.332.1579150768394;
        Wed, 15 Jan 2020 20:59:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:7d7:: with SMTP id 23ls5034848qkb.13.gmail; Wed, 15
 Jan 2020 20:59:28 -0800 (PST)
X-Received: by 2002:a05:620a:1324:: with SMTP id p4mr31672955qkj.497.1579150767949;
        Wed, 15 Jan 2020 20:59:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579150767; cv=none;
        d=google.com; s=arc-20160816;
        b=hgkBfi29pnL9rtOAETp0qoNY8Yt1M62Kq4MeRR+4RpZoMgTgf+TO4N9/kzDFW3jeNX
         VSYe9gHyHE09OLD4PD6ZauZYEu7PCuiEFBIB7c6bKuu9V+ANwXmuW1Jy/iQV7gNOFHwo
         RkooyfMm037CTszfsb9qrpqamw71DbMs56jSmwI8zm5NVINxni4TY18CSN2WJMRnFkKf
         8FT66ouRZMxRuyMyQF/TOSzOKYw1/D2EFukRMI6m6xaT2vPSDeRPVjT40em1Pk8Fsd8z
         Z0OWmjD03mQBE66+wA8djPatDhu8x2sbg/+JiBkC5d7ktXYiTCJLAMhmSR5AtTrWAzCz
         tM/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=z53UVTG1ULBtuQ1LxJSMm2czmwa20G9F5OXvojD1fg4=;
        b=IusVTRMDsApngk5IJR4apjlPnYLJ3lifnmKK88ITpLXaLIqfog1Gx59/B1FEyY3TFt
         ZtuYHzY5MtMEm3JGXx3OEnZlwpO0t9NmJh+OVQJ+amlc2hvLr6l5jfZJJtsoLwvW1ncw
         ozz3HNIlhNwGYjbGYj7jYEWOSX6CskYvuQpCHp+Kc8gA0PE+W4lSOyg+5e1jnFUZy6dQ
         n9CB4OUeT5vrJ8R8PJKJrAJHLWjrRGb44Rg1OwCuGKNJVWOqfafGLtClYfTYuiuHIlbX
         oCbMfBePbMS4IN6h/0QLHUQaAi4Tpw+DHqE7DGHshJkV6PkZvUcNrphO/85pZ3G9u71q
         aTVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EqouT2wd;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id g23si969837qki.4.2020.01.15.20.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 20:59:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id p27so7798380pli.10
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 20:59:27 -0800 (PST)
X-Received: by 2002:a17:90a:238b:: with SMTP id g11mr4528703pje.128.1579150766876;
        Wed, 15 Jan 2020 20:59:26 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id i9sm24055664pfk.24.2020.01.15.20.59.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 20:59:26 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, the arch/x86 maintainers <x86@kernel.org>, Daniel Micay <danielmicay@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH 2/2] string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
In-Reply-To: <CACT4Y+bxh1OmV64Z-EZrYk-otW9q_fxiHnvrE_VMYj-=YAk2Bg@mail.gmail.com>
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-3-dja@axtens.net> <CACT4Y+bxh1OmV64Z-EZrYk-otW9q_fxiHnvrE_VMYj-=YAk2Bg@mail.gmail.com>
Date: Thu, 16 Jan 2020 15:59:22 +1100
Message-ID: <8736cgkndh.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=EqouT2wd;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Dmitry Vyukov <dvyukov@google.com> writes:

> On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
>>
>> The memcmp KASAN self-test fails on a kernel with both KASAN and
>> FORTIFY_SOURCE.
>>
>> When FORTIFY_SOURCE is on, a number of functions are replaced with
>> fortified versions, which attempt to check the sizes of the operands.
>> However, these functions often directly invoke __builtin_foo() once they
>> have performed the fortify check. Using __builtins may bypass KASAN
>> checks if the compiler decides to inline it's own implementation as
>> sequence of instructions, rather than emit a function call that goes out
>> to a KASAN-instrumented implementation.
>>
>> Why is only memcmp affected?
>> ============================
>>
>> Of the string and string-like functions that kasan_test tests, only memcmp
>> is replaced by an inline sequence of instructions in my testing on x86 with
>> gcc version 9.2.1 20191008 (Ubuntu 9.2.1-9ubuntu2).
>>
>> I believe this is due to compiler heuristics. For example, if I annotate
>> kmalloc calls with the alloc_size annotation (and disable some fortify
>> compile-time checking!), the compiler will replace every memset except the
>> one in kmalloc_uaf_memset with inline instructions. (I have some WIP
>> patches to add this annotation.)
>>
>> Does this affect other functions in string.h?
>> =============================================
>>
>> Yes. Anything that uses __builtin_* rather than __real_* could be
>> affected. This looks like:
>>
>>  - strncpy
>>  - strcat
>>  - strlen
>>  - strlcpy maybe, under some circumstances?
>>  - strncat under some circumstances
>>  - memset
>>  - memcpy
>>  - memmove
>>  - memcmp (as noted)
>>  - memchr
>>  - strcpy
>>
>> Whether a function call is emitted always depends on the compiler. Most
>> bugs should get caught by FORTIFY_SOURCE, but the missed memcmp test shows
>> that this is not always the case.
>>
>> Isn't FORTIFY_SOURCE disabled with KASAN?
>> ========================================-
>>
>> The string headers on all arches supporting KASAN disable fortify with
>> kasan, but only when address sanitisation is _also_ disabled. For example
>> from x86:
>>
>>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
>>  /*
>>   * For files that are not instrumented (e.g. mm/slub.c) we
>>   * should use not instrumented version of mem* functions.
>>   */
>>  #define memcpy(dst, src, len) __memcpy(dst, src, len)
>>  #define memmove(dst, src, len) __memmove(dst, src, len)
>>  #define memset(s, c, n) __memset(s, c, n)
>>
>>  #ifndef __NO_FORTIFY
>>  #define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
>>  #endif
>>
>>  #endif
>>
>> This comes from commit 6974f0c4555e ("include/linux/string.h: add the
>> option of fortified string.h functions"), and doesn't work when KASAN is
>> enabled and the file is supposed to be sanitised - as with test_kasan.c
>
> Hi Daniel,
>
> Thanks for addressing this. And special kudos for description detail level! :)
>
> Phew, this layering of checking tools is a bit messy...
>
>> I'm pretty sure this is backwards: we shouldn't be using __builtin_memcpy
>> when we have a KASAN instrumented file, but we can use __builtin_* - and in
>> many cases all fortification - in files where we don't have
>> instrumentation.
>
> I think if we use __builtin_* in a non-instrumented file, the compiler
> can emit a call to normal mem* function which will be intercepted by
> kasan and we will get instrumentation in a file which should not be
> instrumented. Moreover this behavior will depend on optimization level
> and compiler internals.
> But as far as I see this does not affect any of the following and the
> code change.
>

mmm OK - you are right, when I consider this and your other point...

>>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
>> +
>> +#ifdef CONFIG_KASAN
>> +extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
>
>
> arch headers do:
>
> #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> #define memcpy(dst, src, len) __memcpy(dst, src, len)
> ...
>
> to disable instrumentation. Does this still work with this change?
> Previously they disabled fortify. What happens now? Will define of
> memcpy to __memcpy also affect __RENAME(memcpy), so that
> __underlying_memcpy will be an alias to __memcpy?

This is a good question. It's a really intricate set of interactions!!

Between these two things, I think I'm going to just drop the removal of
architecture changes, which means that fortify will continue to be
disabled for files that disable KASAN sanitisation. It's just too
complicated to reason through and satisfy myself that we're not going to
get weird bugs, and the payoff is really small.

>> +extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
>
> All of these macros are leaking from the header file. Tomorrow we will
> discover __underlying_memcpy uses somewhere in the wild, which will
> not making understanding what actually happens simpler :)
> Perhaps undef all of them at the bottom?

I can't stop the function definitions from leaking, but I can stop the
defines from leaking, which means we will catch any uses outside this
block in a FORITY_SOURCE && !KASAN build. I've fixed this for v2.

Regards,
Daniel

>> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
>> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
>> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
>> +extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
>> +extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
>> +extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
>> +extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
>> +extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
>> +#else
>> +#define __underlying_memchr    __builtin_memchr
>> +#define __underlying_memcmp    __builtin_memcmp
>> +#define __underlying_memcpy    __builtin_memcpy
>> +#define __underlying_memmove   __builtin_memmove
>> +#define __underlying_memset    __builtin_memset
>> +#define __underlying_strcat    __builtin_strcat
>> +#define __underlying_strcpy    __builtin_strcpy
>> +#define __underlying_strlen    __builtin_strlen
>> +#define __underlying_strncat   __builtin_strncat
>> +#define __underlying_strncpy   __builtin_strncpy
>> +#endif
>> +
>>  __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
>>  {
>>         size_t p_size = __builtin_object_size(p, 0);
>> @@ -324,14 +349,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
>>                 __write_overflow();
>>         if (p_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_strncpy(p, q, size);
>> +       return __underlying_strncpy(p, q, size);
>>  }
>>
>>  __FORTIFY_INLINE char *strcat(char *p, const char *q)
>>  {
>>         size_t p_size = __builtin_object_size(p, 0);
>>         if (p_size == (size_t)-1)
>> -               return __builtin_strcat(p, q);
>> +               return __underlying_strcat(p, q);
>>         if (strlcat(p, q, p_size) >= p_size)
>>                 fortify_panic(__func__);
>>         return p;
>> @@ -345,7 +370,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p)
>>         /* Work around gcc excess stack consumption issue */
>>         if (p_size == (size_t)-1 ||
>>             (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == '\0'))
>> -               return __builtin_strlen(p);
>> +               return __underlying_strlen(p);
>>         ret = strnlen(p, p_size);
>>         if (p_size <= ret)
>>                 fortify_panic(__func__);
>> @@ -378,7 +403,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char *q, size_t size)
>>                         __write_overflow();
>>                 if (len >= p_size)
>>                         fortify_panic(__func__);
>> -               __builtin_memcpy(p, q, len);
>> +               __underlying_memcpy(p, q, len);
>>                 p[len] = '\0';
>>         }
>>         return ret;
>> @@ -391,12 +416,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char *q, __kernel_size_t count)
>>         size_t p_size = __builtin_object_size(p, 0);
>>         size_t q_size = __builtin_object_size(q, 0);
>>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
>> -               return __builtin_strncat(p, q, count);
>> +               return __underlying_strncat(p, q, count);
>>         p_len = strlen(p);
>>         copy_len = strnlen(q, count);
>>         if (p_size < p_len + copy_len + 1)
>>                 fortify_panic(__func__);
>> -       __builtin_memcpy(p + p_len, q, copy_len);
>> +       __underlying_memcpy(p + p_len, q, copy_len);
>>         p[p_len + copy_len] = '\0';
>>         return p;
>>  }
>> @@ -408,7 +433,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __kernel_size_t size)
>>                 __write_overflow();
>>         if (p_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_memset(p, c, size);
>> +       return __underlying_memset(p, c, size);
>>  }
>>
>>  __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
>> @@ -423,7 +448,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
>>         }
>>         if (p_size < size || q_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_memcpy(p, q, size);
>> +       return __underlying_memcpy(p, q, size);
>>  }
>>
>>  __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
>> @@ -438,7 +463,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
>>         }
>>         if (p_size < size || q_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_memmove(p, q, size);
>> +       return __underlying_memmove(p, q, size);
>>  }
>>
>>  extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
>> @@ -464,7 +489,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void *q, __kernel_size_t size)
>>         }
>>         if (p_size < size || q_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_memcmp(p, q, size);
>> +       return __underlying_memcmp(p, q, size);
>>  }
>>
>>  __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
>> @@ -474,7 +499,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
>>                 __read_overflow();
>>         if (p_size < size)
>>                 fortify_panic(__func__);
>> -       return __builtin_memchr(p, c, size);
>> +       return __underlying_memchr(p, c, size);
>>  }
>>
>>  void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(memchr_inv);
>> @@ -505,7 +530,7 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
>>         size_t p_size = __builtin_object_size(p, 0);
>>         size_t q_size = __builtin_object_size(q, 0);
>>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
>> -               return __builtin_strcpy(p, q);
>> +               return __underlying_strcpy(p, q);
>>         memcpy(p, q, strlen(q) + 1);
>>         return p;
>>  }
>> --
>> 2.20.1
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8736cgkndh.fsf%40dja-thinkpad.axtens.net.
