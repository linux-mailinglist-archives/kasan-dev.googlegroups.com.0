Return-Path: <kasan-dev+bncBCMIZB7QWENRB3PR77YAKGQEITUDDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E7C3F13D3DF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 06:47:26 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id 199sf21599205ywe.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 21:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579153646; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQXaaAFdMrdtDXhkJwQcj+8hyH1sNcf8eqvvQxSCWZSZUvwCvPAtoV+U5WVX6rwJtr
         7HTXgfrEAFq/bh5+AMxIcUrb9MQh6LD50HfYAPYt8uMTRtG2IPw0CPZ9Zx0qtYtc+cg5
         pPCVDr5t+0QQPnQjoTUIT+XkZUAPOYYbVn+E7Jw0A3Zo8gCNY4cfIgCxlJ8AmN58G+Nm
         lNMxqvGT/SxZ2WOKft69IZei5jfLU02vm6Y7fWNDMpvNIgoRCWZJdrmljx5s36HqkiSM
         FEC/jGIKS56UF3TMrXzQCN0EL1o1cmE2Fc8HoiA6keNOrOfqUrJpedEvSq6dG6H9Trmd
         Jkxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/a2JxSGEep3JVjVbmPqK9yCk/qbnWqrILezP7nFcWk8=;
        b=mQCghF31biepsxodeJ6JSWqDlEMmiPWfGZsBHKtfyam77zexa/doUh9xeSnuPc8F6Y
         /1SnJbzPBIl9aPT0HiuldVY8FX2PMMuxQljf/m1Sxx0Qn6C80P9FlxkOJtSz6PQKv46F
         v3prUcYMk4Hr/mCkiK0ouZde+CgDjPn7C4Qg1u7qgJ+2DjLXNR7scCM1hX7FV3iu666s
         LM7T7tiFmEQcBr9bpXAcjBuj2tlgEcpQ9X/NBqv74+4bmY2knlKXq3XfW/AsJdfKQjps
         pgVZ3/B8QNh/5+zq4JVYEqClPbEsqa/iOd8ADmVgIpfTcyQnWzJDIaKy7d4htqrj99Ea
         Njpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v1YrVzVa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/a2JxSGEep3JVjVbmPqK9yCk/qbnWqrILezP7nFcWk8=;
        b=Cq89z/v2h1JaqtW3bI6JI+KwoH9YRL/DHoKGMfpnPwo+O2Ha0aXLczRNmWuehx+kk1
         UW3I9sCZalieBZV1JuoJxwMMjXXNiVKkANIeeuL7doNRDtLcXCe7XJWtgo8bR30dRdMu
         k/kES3Kw2OgUzAqgUBbCtWoscWvEi5lNxZjPOBLIw0FpoiZnjveLuiVLPRcl74LF/1aO
         AMjQxGheNKZ9Idz920JWv7wXk748Cn3B9R9Bfdh1EZAxviXUzU8t8Kscddc/AUOrjxmN
         RPRCB3oFUebLOGI/D3HYg/hzYyLEfk6SULMGggvXDkg37/6X5JXsZEPKbejj1tduVEiI
         b2ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/a2JxSGEep3JVjVbmPqK9yCk/qbnWqrILezP7nFcWk8=;
        b=il8lMxJKuzsnh7DDSegJoCZezZIUnSxUfh1vS8olv61WrxSVRm0fc+h4+Q4w5r4F6F
         xP8DfpwgOXMcKJwEj8SY6tdaCaw33BXh9a2/XLaUULm5Lq76igtfdNyNxHoXPk4gOhrC
         ZTloK7cTO9TDQR8X2Xl5r/it+UI/KwQ2uvHrXezzsJPSc5Rqa06cHnvJMCuoYaOJeBlx
         a1qd73lojwh/5Jawdzf6dGGiKPGADIrZq8TgRKoIaab0e3Ya78/76wNwmghIf58Oj+yY
         5Tkf1oyC2r0eRzEis4MwtOb3D/LHcgfEXRGXWNvhGKPDeP5gR+rIgvGxcvL65z03JxRi
         MIdg==
X-Gm-Message-State: APjAAAV8vn00VUZMnxVivw5RH/MZM9CejoCICvCWFiM+61VPlJa031dM
	etifIaQGzlUmhWOGjoQ3D9c=
X-Google-Smtp-Source: APXvYqzzicQ9heA8kNz/Ef1BFNUbyPmoq9dlLs29tmpQS6UZ/FynGSW1DIUOre1UxNQem2FyxyI+Aw==
X-Received: by 2002:a25:2d1b:: with SMTP id t27mr11044815ybt.299.1579153645872;
        Wed, 15 Jan 2020 21:47:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8083:: with SMTP id q125ls3394732ywf.10.gmail; Wed, 15
 Jan 2020 21:47:25 -0800 (PST)
X-Received: by 2002:a81:5206:: with SMTP id g6mr25857528ywb.216.1579153645482;
        Wed, 15 Jan 2020 21:47:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579153645; cv=none;
        d=google.com; s=arc-20160816;
        b=w2j0KHFugW6jTzNPbVaIfaFVsLXeG4Q/xcmNNE5mztRuAPX4t7AdrX3BjVVdYpnpUD
         3E/8cfEwhU+NSi6qvzKzoE9ExVr0DBWhq9HvPySi0NQM24kFh3RRdv1EcPTkGy2o1lIk
         HB8PDyv+fOd0pErqHZQ5Xuc0Xoednmjb/GoK5lQP66lKkH+ui9yVa71p/zFbsh+dWpjD
         dyvG16DmnLeF8j3g2GiyAH07XsXIILl9sbxBVTejiLZd35AM8ZYdKjnGihNPX2dPLXLJ
         7KYp5JLASMpv6ck6o2jpDaGRm/iyJPLMX4wcHhYcFcRF71PoaVWlSQXT6i5ZLhWM9Svz
         JuKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wF6ZZgDVBcb52vVymB/toV0bmt4NnNtZaybtThqWt40=;
        b=IyaIaQU2SmLOnRtF2OT4aEdxb4hOVESWol1faZmaigd32aHCHBzniKYDqgv6Rc3MUh
         mQ8TAjCWo5XcPCCExxOf0WDY6+Lf8DjebWixuVhbctmQueNAFKCEThl5NE4BKUzovNpC
         UVr9hwN4Q7qbO1k8U0vf2mauoJDrP/yB1VFSvXEKr+PLWUm/XpkI1GMWZv+J8Ozm2RQs
         zGlzimVeCFCjE5PAV8QBbXDn+R12tvMBBFcPKHWiQZ10frz/9Y4tWZ6E52Fmlh2aUuAE
         m3WZE0wt7zEuS0g71PyM5mxhJkxLzbQXkP4HQ++qy5+BzINPZ5EyzgEiCAvPsQphDy6c
         Om5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v1YrVzVa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id f8si841367ybg.2.2020.01.15.21.47.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 21:47:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id y8so8554599qvk.6
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 21:47:25 -0800 (PST)
X-Received: by 2002:a0c:c351:: with SMTP id j17mr1025368qvi.80.1579153644733;
 Wed, 15 Jan 2020 21:47:24 -0800 (PST)
MIME-Version: 1.0
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-3-dja@axtens.net>
 <CACT4Y+bxh1OmV64Z-EZrYk-otW9q_fxiHnvrE_VMYj-=YAk2Bg@mail.gmail.com> <8736cgkndh.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <8736cgkndh.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 06:47:13 +0100
Message-ID: <CACT4Y+Z7Fs1tzaECX_oT5VX05vPAehnfsR-m6P2uVtDACm7w8w@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=v1YrVzVa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Thu, Jan 16, 2020 at 5:59 AM Daniel Axtens <dja@axtens.net> wrote:
>
> Dmitry Vyukov <dvyukov@google.com> writes:
>
> > On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
> >>
> >> The memcmp KASAN self-test fails on a kernel with both KASAN and
> >> FORTIFY_SOURCE.
> >>
> >> When FORTIFY_SOURCE is on, a number of functions are replaced with
> >> fortified versions, which attempt to check the sizes of the operands.
> >> However, these functions often directly invoke __builtin_foo() once they
> >> have performed the fortify check. Using __builtins may bypass KASAN
> >> checks if the compiler decides to inline it's own implementation as
> >> sequence of instructions, rather than emit a function call that goes out
> >> to a KASAN-instrumented implementation.
> >>
> >> Why is only memcmp affected?
> >> ============================
> >>
> >> Of the string and string-like functions that kasan_test tests, only memcmp
> >> is replaced by an inline sequence of instructions in my testing on x86 with
> >> gcc version 9.2.1 20191008 (Ubuntu 9.2.1-9ubuntu2).
> >>
> >> I believe this is due to compiler heuristics. For example, if I annotate
> >> kmalloc calls with the alloc_size annotation (and disable some fortify
> >> compile-time checking!), the compiler will replace every memset except the
> >> one in kmalloc_uaf_memset with inline instructions. (I have some WIP
> >> patches to add this annotation.)
> >>
> >> Does this affect other functions in string.h?
> >> =============================================
> >>
> >> Yes. Anything that uses __builtin_* rather than __real_* could be
> >> affected. This looks like:
> >>
> >>  - strncpy
> >>  - strcat
> >>  - strlen
> >>  - strlcpy maybe, under some circumstances?
> >>  - strncat under some circumstances
> >>  - memset
> >>  - memcpy
> >>  - memmove
> >>  - memcmp (as noted)
> >>  - memchr
> >>  - strcpy
> >>
> >> Whether a function call is emitted always depends on the compiler. Most
> >> bugs should get caught by FORTIFY_SOURCE, but the missed memcmp test shows
> >> that this is not always the case.
> >>
> >> Isn't FORTIFY_SOURCE disabled with KASAN?
> >> ========================================-
> >>
> >> The string headers on all arches supporting KASAN disable fortify with
> >> kasan, but only when address sanitisation is _also_ disabled. For example
> >> from x86:
> >>
> >>  #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> >>  /*
> >>   * For files that are not instrumented (e.g. mm/slub.c) we
> >>   * should use not instrumented version of mem* functions.
> >>   */
> >>  #define memcpy(dst, src, len) __memcpy(dst, src, len)
> >>  #define memmove(dst, src, len) __memmove(dst, src, len)
> >>  #define memset(s, c, n) __memset(s, c, n)
> >>
> >>  #ifndef __NO_FORTIFY
> >>  #define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> >>  #endif
> >>
> >>  #endif
> >>
> >> This comes from commit 6974f0c4555e ("include/linux/string.h: add the
> >> option of fortified string.h functions"), and doesn't work when KASAN is
> >> enabled and the file is supposed to be sanitised - as with test_kasan.c
> >
> > Hi Daniel,
> >
> > Thanks for addressing this. And special kudos for description detail level! :)
> >
> > Phew, this layering of checking tools is a bit messy...
> >
> >> I'm pretty sure this is backwards: we shouldn't be using __builtin_memcpy
> >> when we have a KASAN instrumented file, but we can use __builtin_* - and in
> >> many cases all fortification - in files where we don't have
> >> instrumentation.
> >
> > I think if we use __builtin_* in a non-instrumented file, the compiler
> > can emit a call to normal mem* function which will be intercepted by
> > kasan and we will get instrumentation in a file which should not be
> > instrumented. Moreover this behavior will depend on optimization level
> > and compiler internals.
> > But as far as I see this does not affect any of the following and the
> > code change.
> >
>
> mmm OK - you are right, when I consider this and your other point...
>
> >>  #if !defined(__NO_FORTIFY) && defined(__OPTIMIZE__) && defined(CONFIG_FORTIFY_SOURCE)
> >> +
> >> +#ifdef CONFIG_KASAN
> >> +extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
> >
> >
> > arch headers do:
> >
> > #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> > #define memcpy(dst, src, len) __memcpy(dst, src, len)
> > ...
> >
> > to disable instrumentation. Does this still work with this change?
> > Previously they disabled fortify. What happens now? Will define of
> > memcpy to __memcpy also affect __RENAME(memcpy), so that
> > __underlying_memcpy will be an alias to __memcpy?
>
> This is a good question. It's a really intricate set of interactions!!
>
> Between these two things, I think I'm going to just drop the removal of
> architecture changes, which means that fortify will continue to be
> disabled for files that disable KASAN sanitisation. It's just too
> complicated to reason through and satisfy myself that we're not going to
> get weird bugs, and the payoff is really small.

Sounds good to me. We don't need to solve all of the world 's problems
at once :)

> >> +extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
> >
> > All of these macros are leaking from the header file. Tomorrow we will
> > discover __underlying_memcpy uses somewhere in the wild, which will
> > not making understanding what actually happens simpler :)
> > Perhaps undef all of them at the bottom?
>
> I can't stop the function definitions from leaking, but I can stop the
> defines from leaking, which means we will catch any uses outside this
> block in a FORITY_SOURCE && !KASAN build. I've fixed this for v2.

I think it's good enough and a good practice to undef local macros.

> Regards,
> Daniel
>
> >> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
> >> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
> >> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
> >> +extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
> >> +extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
> >> +extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
> >> +extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
> >> +extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
> >> +#else
> >> +#define __underlying_memchr    __builtin_memchr
> >> +#define __underlying_memcmp    __builtin_memcmp
> >> +#define __underlying_memcpy    __builtin_memcpy
> >> +#define __underlying_memmove   __builtin_memmove
> >> +#define __underlying_memset    __builtin_memset
> >> +#define __underlying_strcat    __builtin_strcat
> >> +#define __underlying_strcpy    __builtin_strcpy
> >> +#define __underlying_strlen    __builtin_strlen
> >> +#define __underlying_strncat   __builtin_strncat
> >> +#define __underlying_strncpy   __builtin_strncpy
> >> +#endif
> >> +
> >>  __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
> >>  {
> >>         size_t p_size = __builtin_object_size(p, 0);
> >> @@ -324,14 +349,14 @@ __FORTIFY_INLINE char *strncpy(char *p, const char *q, __kernel_size_t size)
> >>                 __write_overflow();
> >>         if (p_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_strncpy(p, q, size);
> >> +       return __underlying_strncpy(p, q, size);
> >>  }
> >>
> >>  __FORTIFY_INLINE char *strcat(char *p, const char *q)
> >>  {
> >>         size_t p_size = __builtin_object_size(p, 0);
> >>         if (p_size == (size_t)-1)
> >> -               return __builtin_strcat(p, q);
> >> +               return __underlying_strcat(p, q);
> >>         if (strlcat(p, q, p_size) >= p_size)
> >>                 fortify_panic(__func__);
> >>         return p;
> >> @@ -345,7 +370,7 @@ __FORTIFY_INLINE __kernel_size_t strlen(const char *p)
> >>         /* Work around gcc excess stack consumption issue */
> >>         if (p_size == (size_t)-1 ||
> >>             (__builtin_constant_p(p[p_size - 1]) && p[p_size - 1] == '\0'))
> >> -               return __builtin_strlen(p);
> >> +               return __underlying_strlen(p);
> >>         ret = strnlen(p, p_size);
> >>         if (p_size <= ret)
> >>                 fortify_panic(__func__);
> >> @@ -378,7 +403,7 @@ __FORTIFY_INLINE size_t strlcpy(char *p, const char *q, size_t size)
> >>                         __write_overflow();
> >>                 if (len >= p_size)
> >>                         fortify_panic(__func__);
> >> -               __builtin_memcpy(p, q, len);
> >> +               __underlying_memcpy(p, q, len);
> >>                 p[len] = '\0';
> >>         }
> >>         return ret;
> >> @@ -391,12 +416,12 @@ __FORTIFY_INLINE char *strncat(char *p, const char *q, __kernel_size_t count)
> >>         size_t p_size = __builtin_object_size(p, 0);
> >>         size_t q_size = __builtin_object_size(q, 0);
> >>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
> >> -               return __builtin_strncat(p, q, count);
> >> +               return __underlying_strncat(p, q, count);
> >>         p_len = strlen(p);
> >>         copy_len = strnlen(q, count);
> >>         if (p_size < p_len + copy_len + 1)
> >>                 fortify_panic(__func__);
> >> -       __builtin_memcpy(p + p_len, q, copy_len);
> >> +       __underlying_memcpy(p + p_len, q, copy_len);
> >>         p[p_len + copy_len] = '\0';
> >>         return p;
> >>  }
> >> @@ -408,7 +433,7 @@ __FORTIFY_INLINE void *memset(void *p, int c, __kernel_size_t size)
> >>                 __write_overflow();
> >>         if (p_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_memset(p, c, size);
> >> +       return __underlying_memset(p, c, size);
> >>  }
> >>
> >>  __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
> >> @@ -423,7 +448,7 @@ __FORTIFY_INLINE void *memcpy(void *p, const void *q, __kernel_size_t size)
> >>         }
> >>         if (p_size < size || q_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_memcpy(p, q, size);
> >> +       return __underlying_memcpy(p, q, size);
> >>  }
> >>
> >>  __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
> >> @@ -438,7 +463,7 @@ __FORTIFY_INLINE void *memmove(void *p, const void *q, __kernel_size_t size)
> >>         }
> >>         if (p_size < size || q_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_memmove(p, q, size);
> >> +       return __underlying_memmove(p, q, size);
> >>  }
> >>
> >>  extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
> >> @@ -464,7 +489,7 @@ __FORTIFY_INLINE int memcmp(const void *p, const void *q, __kernel_size_t size)
> >>         }
> >>         if (p_size < size || q_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_memcmp(p, q, size);
> >> +       return __underlying_memcmp(p, q, size);
> >>  }
> >>
> >>  __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
> >> @@ -474,7 +499,7 @@ __FORTIFY_INLINE void *memchr(const void *p, int c, __kernel_size_t size)
> >>                 __read_overflow();
> >>         if (p_size < size)
> >>                 fortify_panic(__func__);
> >> -       return __builtin_memchr(p, c, size);
> >> +       return __underlying_memchr(p, c, size);
> >>  }
> >>
> >>  void *__real_memchr_inv(const void *s, int c, size_t n) __RENAME(memchr_inv);
> >> @@ -505,7 +530,7 @@ __FORTIFY_INLINE char *strcpy(char *p, const char *q)
> >>         size_t p_size = __builtin_object_size(p, 0);
> >>         size_t q_size = __builtin_object_size(q, 0);
> >>         if (p_size == (size_t)-1 && q_size == (size_t)-1)
> >> -               return __builtin_strcpy(p, q);
> >> +               return __underlying_strcpy(p, q);
> >>         memcpy(p, q, strlen(q) + 1);
> >>         return p;
> >>  }
> >> --
> >> 2.20.1
> >>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8736cgkndh.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ7Fs1tzaECX_oT5VX05vPAehnfsR-m6P2uVtDACm7w8w%40mail.gmail.com.
