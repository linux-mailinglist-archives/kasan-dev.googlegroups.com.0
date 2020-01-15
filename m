Return-Path: <kasan-dev+bncBCMIZB7QWENRBQGQ7TYAKGQEJV5USVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id ACE9B13C6B9
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 15:57:05 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id r2sf3712932pls.18
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 06:57:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579100224; cv=pass;
        d=google.com; s=arc-20160816;
        b=bw0Ejowe/gyN1y9e8IcAYKjFQvywRHHREKgMncLSZpTzBQQh+3QgbYNy4kEGXvNVD0
         maonINYV4d0WR5zhDYYoT/+qgI09EzJIHpEvtKyyB8tXYagdBCeymW5t4iTwyq1CNvA6
         1WrdO/mBBraF0dKn1tBFrzADUgXERso0c26ri28+a1GhhwWejGGaRgT4H5eV4wfbYTG6
         M2iaFipgYCTDfg0It75NRXXHEZ3V+iEubApfVdoqDbpm/4YRk0HH0DKLAHVnqEXzpdiN
         JzG7/fTjYaSyuf5MriSLX4j67KVxH67VlBGi4tofcDj2Kt4jaiqeNWdX0zrsAyX1WEu6
         MSGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QPzbVym8JIQfI2fE9x7/nuVOvSbqlZH2hMgholv0KqI=;
        b=i5XkUxYJOh0AAYPXhvispmSL/TJP/IL+Kqav/yvXRP/qfRg0wg208xUW2MDNGT3chI
         gXdRnz343UzXGvDs3jz21yrOaUA5RgfL/qWfPwRluzhMi7sIXKnw0ef57DfKx7HqjZqt
         Y+bpWC+wW5k0jk9682QQciMnuxEu8EDFYYmDGKvqyPiqdHC1EhQyClKcWQ95DfQzdz3s
         woaaqXm7gPBAbtSupMTMLGf7s/tlU+/sQoUxFGtdUFm58Hz/T3VHOi/Z3wXaL2G4dYhj
         +QCJVhBBiT2r++L1nZCm1e0rOkArucXTJOOf0HCx/DaJcqvRwyMJ5+u0CPlSKfJnXaGN
         dLfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MZYzePp+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QPzbVym8JIQfI2fE9x7/nuVOvSbqlZH2hMgholv0KqI=;
        b=kQw52JvsoTEJOyzrmKs3eb9fLEpcdZU0zoEYTtAWsH+Uv+ck9SgKt3ARg+clhrMAw9
         W5KiPneCrFQPeo3Un7iJDVM6IxW3u7KcCtr3C+pUy8mdlQqFfFZlgWkcFFFOqvmmSqlW
         JyJ34NlSfaPGkkw6MVJFksU70s1Gqxbo3mHXyBYiwwTeOh9lFo1SB0D8KF9K5/mFvJXR
         Wr20YfpG+8nPOhK0dc5O5G2Q3vuqiMJfqJORfmIM3fOr0i6vwDgPrXBcsBLsWFBnzKqB
         gVxijwizwhw/PLk8qkvD92Au6fi6Z1L6DnRqBZMVNr/zL6e6OfQB+za2Qg9vLwaA8VaE
         bxMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QPzbVym8JIQfI2fE9x7/nuVOvSbqlZH2hMgholv0KqI=;
        b=rkoXUr+ycRP4+ITfz59VwPB0BLBG2TnHgk28iOPGmurcJSUBG4EHZBkbEdtlHED4kc
         uXeeUzwjRNF1t+kat+VWzkTLsr8X1PXiTZ6RtSsZpxKzYAe8sgxeAkXxAJpVyBUyXl8/
         bhZVBoDDw1M548wQStU+1ueZC4709t4x3ZTnNISLSW4zsVr6M7dAVpx7uiUUTE5WxC5E
         QICsxld77eU0QiOfEVtUPqmZRH1zMTGygmqPlC/h2+Ey9gtIgdB6nUllqJjN8jdbyQRg
         lE/bGqJKluvaQVRsND8dy89BHEvFg6lwNxe5Tz6PoFHcvP7nYR43eJo2Ci5nRWJFs2HE
         WLZA==
X-Gm-Message-State: APjAAAU9IhpRSEo8ICqND1WAoP/S6SZkeRVQXDyi0xfm9jnTnSLoYAbj
	MTBxx1iRwp8pIq5YX7VA5iY=
X-Google-Smtp-Source: APXvYqxtAFdbfu139yRQLsHsDaC2HxRxg8cvBlvk3O3jDmrlIvMVvUdkWvBd3wdDC8lO1Lk6qpa+Ug==
X-Received: by 2002:a65:42c2:: with SMTP id l2mr32666552pgp.172.1579100224284;
        Wed, 15 Jan 2020 06:57:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:81ca:: with SMTP id c10ls3037445pfn.8.gmail; Wed, 15 Jan
 2020 06:57:03 -0800 (PST)
X-Received: by 2002:a63:9d07:: with SMTP id i7mr35121430pgd.344.1579100223751;
        Wed, 15 Jan 2020 06:57:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579100223; cv=none;
        d=google.com; s=arc-20160816;
        b=ZmiohBNJ4D+THMtVufrVobb0qGXVvi8kl3GO+7WM6SY8NtC16yeYHqm6NdxZnu2d9m
         m+uYBzDSxDPYzAHEb7mgcMJHn4Ghtj+cib8asPIK1u1CVoGtv50xnOz4Q+90/kYK9RRt
         23D0TSe4VbF9RC0TZ7lBK+mlWsB8CLexO+6bz33jgb+FA/ePFm5DzsNXNCGEtYdBAb47
         RySOYqjQTpQfwyfeu6bIbG3GLxts2rYSLMKBO8fbnOcsNBNePaMFmqOrrZz72lbDK6Pf
         jgMDMXyZYf8UsWSXu86lYH8e5DXJXmeeBjS+9Ik7VflGF3d3PwpQPTYE1uSmIwvS/DUm
         or4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nCNJXe7yG41T3Zx4qiLeK6GwZVm1UZIhPymZyFVUSUg=;
        b=wH8rvzXtP/eqhNkrkT/esWBFcQpmfhD2mPLFQe5Idmt62/qzSW9WgYuj0nXTOguaHT
         tiII6b3dvxw3y10/Ow6Vk8s0ZEDPyEdBXmJ/OnVmY/o/C8m/Su7Ai7Yu/XxVaHE3EXhA
         tIIMm1FeWYLWnm0FrE4RUzZitqmrJJBXw47fN0AIbPcDsxwaYwWXMA/z/ci9F1mrC4AX
         oIK2HqyNtsN066KTKnbBg/XTQ3UbEfugLRRkWwZ7qTnN3l5iqyhNIRZZcHAOYA58pSl7
         HjdYxRxiRwdNkSTrekdxAbYXGIoHi7E/iWmrO0OGqf6uFXAb3bCa4vfGJa3Q2S4Sikxw
         Ujmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MZYzePp+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id h19si897685pfn.1.2020.01.15.06.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 06:57:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w47so15979336qtk.4
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 06:57:03 -0800 (PST)
X-Received: by 2002:ac8:24c1:: with SMTP id t1mr3865061qtt.257.1579100222741;
 Wed, 15 Jan 2020 06:57:02 -0800 (PST)
MIME-Version: 1.0
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-3-dja@axtens.net>
In-Reply-To: <20200115063710.15796-3-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 15:56:51 +0100
Message-ID: <CACT4Y+bxh1OmV64Z-EZrYk-otW9q_fxiHnvrE_VMYj-=YAk2Bg@mail.gmail.com>
Subject: Re: [PATCH 2/2] string.h: fix incompatibility between FORTIFY_SOURCE
 and KASAN
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	"the arch/x86 maintainers" <x86@kernel.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MZYzePp+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
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

Hi Daniel,

Thanks for addressing this. And special kudos for description detail level! :)

Phew, this layering of checking tools is a bit messy...

> I'm pretty sure this is backwards: we shouldn't be using __builtin_memcpy
> when we have a KASAN instrumented file, but we can use __builtin_* - and in
> many cases all fortification - in files where we don't have
> instrumentation.

I think if we use __builtin_* in a non-instrumented file, the compiler
can emit a call to normal mem* function which will be intercepted by
kasan and we will get instrumentation in a file which should not be
instrumented. Moreover this behavior will depend on optimization level
and compiler internals.
But as far as I see this does not affect any of the following and the
code change.



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

I support option 2.
For KASAN build we don't care about inlining/performance that much,
getting it to work reliably and with reasonable complexity is more
important.
And it's better to leave prod build as it is now (proving that any
change is harmless is impossible).



> Use __underlying_foo to distinguish from __real_foo: __real_foo always
> refers to the kernel's implementation of foo, __underlying_foo could be
> either the kernel implementation or the __builtin_foo implementation.
>
> Remove all the attempted disablement code in arch string headers.
>
> This makes all the tests succeed with FORTIFY_SOURCE enabled.
>
> Cc: Daniel Micay <danielmicay@gmail.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Fixes: 6974f0c4555e ("include/linux/string.h: add the option of fortified string.h functions")
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> ---
>
> Dmitry, this might cause a few new syzkaller splats - I first picked it up
> building from a syskaller config. Or it might not, it just depends what gets
> replaced with an inline sequence of instructions.
>
> checkpatch complains about some over-long lines, happy to change the format
> if anyone has better ideas for how to lay it out.
> ---
>  arch/arm64/include/asm/string.h   |  4 ---
>  arch/powerpc/include/asm/string.h |  4 ---
>  arch/s390/include/asm/string.h    |  4 ---
>  arch/x86/include/asm/string_64.h  |  4 ---
>  arch/xtensa/include/asm/string.h  |  3 --
>  include/linux/string.h            | 49 +++++++++++++++++++++++--------
>  6 files changed, 37 insertions(+), 31 deletions(-)
>
> diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
> index b31e8e87a0db..eafb2c4771fc 100644
> --- a/arch/arm64/include/asm/string.h
> +++ b/arch/arm64/include/asm/string.h
> @@ -59,10 +59,6 @@ void memcpy_flushcache(void *dst, const void *src, size_t cnt);
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
>
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
> -
>  #endif
>
>  #endif
> diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/asm/string.h
> index b72692702f35..952c5934596b 100644
> --- a/arch/powerpc/include/asm/string.h
> +++ b/arch/powerpc/include/asm/string.h
> @@ -43,10 +43,6 @@ void *__memmove(void *to, const void *from, __kernel_size_t n);
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
>
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
> -
>  #endif
>
>  #ifdef CONFIG_PPC64
> diff --git a/arch/s390/include/asm/string.h b/arch/s390/include/asm/string.h
> index 4c0690fc5167..e0b66d8c89a1 100644
> --- a/arch/s390/include/asm/string.h
> +++ b/arch/s390/include/asm/string.h
> @@ -75,10 +75,6 @@ extern void *__memmove(void *dest, const void *src, size_t n);
>
>  #define __no_sanitize_prefix_strfunc(x) __##x
>
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
> -
>  #else
>  #define __no_sanitize_prefix_strfunc(x) x
>  #endif /* defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__) */
> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
> index 75314c3dbe47..ec63d11e1f04 100644
> --- a/arch/x86/include/asm/string_64.h
> +++ b/arch/x86/include/asm/string_64.h
> @@ -76,10 +76,6 @@ int strcmp(const char *cs, const char *ct);
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
>
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
> -
>  #endif
>
>  #define __HAVE_ARCH_MEMCPY_MCSAFE 1
> diff --git a/arch/xtensa/include/asm/string.h b/arch/xtensa/include/asm/string.h
> index 89b51a0c752f..8cf04c5a33fb 100644
> --- a/arch/xtensa/include/asm/string.h
> +++ b/arch/xtensa/include/asm/string.h
> @@ -132,9 +132,6 @@ extern void *__memmove(void *__dest, __const__ void *__src, size_t __n);
>  #define memmove(dst, src, len) __memmove(dst, src, len)
>  #define memset(s, c, n) __memset(s, c, n)
>
> -#ifndef __NO_FORTIFY
> -#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> -#endif
>  #endif
>
>  #endif /* _XTENSA_STRING_H */
> diff --git a/include/linux/string.h b/include/linux/string.h
> index 3b8e8b12dd37..4364c106355e 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -317,6 +317,31 @@ void __read_overflow3(void) __compiletime_error("detected read beyond size of ob
>  void __write_overflow(void) __compiletime_error("detected write beyond size of object passed as 1st parameter");
>
>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
> +
> +#ifdef CONFIG_KASAN
> +extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);


arch headers do:

#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
#define memcpy(dst, src, len) __memcpy(dst, src, len)
...

to disable instrumentation. Does this still work with this change?
Previously they disabled fortify. What happens now? Will define of
memcpy to __memcpy also affect __RENAME(memcpy), so that
__underlying_memcpy will be an alias to __memcpy?



> +extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);

All of these macros are leaking from the header file. Tomorrow we will
discover __underlying_memcpy uses somewhere in the wild, which will
not making understanding what actually happens simpler :)
Perhaps undef all of them at the bottom?



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
> @@ -505,7 +530,7 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
>         size_t p_size = __builtin_object_size(p, 0);
>         size_t q_size = __builtin_object_size(q, 0);
>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
> -               return __builtin_strcpy(p, q);
> +               return __underlying_strcpy(p, q);
>         memcpy(p, q, strlen(q) + 1);
>         return p;
>  }
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbxh1OmV64Z-EZrYk-otW9q_fxiHnvrE_VMYj-%3DYAk2Bg%40mail.gmail.com.
