Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH5HSHCQMGQE2VEN7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id CC71AB2BF0F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 12:36:17 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-71d605c1c11sf64813807b3.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 03:36:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755599776; cv=pass;
        d=google.com; s=arc-20240605;
        b=atDi1vO9PCKNG3P7/ouo6Fl+L1jGHwcNgKk62xl0Nh5PkHM8VejT/hlGkqVu8UaTjU
         Hud6rOsXPkuRf2q5fVHrSuK3MBVT8oS12DakpgcXZE1CPdoNPvRHEDo+1+K09Y7PAIbP
         qDHnY2eR1E8fQt9Dl0ht+qBruYpCz3RT2n6T+2Wsw01yNkCtJAgb7D20GwziqEGpE4qw
         99X0VEgYmwwb2XztxRfUHY9B2rI2mLioj6jqFPWuq4RxN2wwd1KTsKvxmbSTNBo0a8Gm
         OEetIGwVaVMXmUPrcV5GpyGkBmvXcSFteaon0DPLKMLUceRkvEWRu8SRYIiOTaM7oDat
         q6tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DJIcm8rBuxRdSJLpRl0yY01nbJA1BwfihEiIoh7mNdQ=;
        fh=9DbEaLH10MhGJNfaUORSC68Bz/YCmdtVG4jqlu/+C4s=;
        b=VPfC6FHSjeiuucTGzhQY/pSvlRbKiaB/kRXBUzcd8rKP+muL6SsCKoSQZ5KM4z3jQM
         +EK94e922w2jTVc3sMNZz/NlfWkzpuCM8P+hYPwN0piLmre0jHokwieBkUx3x7ztqOOm
         BvdNDhsJNo3/lZgBxAgo4aeQ5hC0wozb3LXus0OBZ91F1Uj284nazrMm5N/Q65lsfmNs
         SOyaL29oqLL3xevKnyLjLxbz6JKV4SJznUeLbb7Y3LHmMHEGEqDOWCyyblhzHwn8cxcd
         G/LlPvdWV45JhVRE6PtoD77KI3l86B/1dp8rir+tcCcFb7Tzm4OFY1rggD2dzMrujTaJ
         YA2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="XUc/gzi6";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755599776; x=1756204576; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DJIcm8rBuxRdSJLpRl0yY01nbJA1BwfihEiIoh7mNdQ=;
        b=W0ik+a+HvfW17HS+9xihjg92icEKX1U8hR3P0HDDqmYVvWBrbMjQ7t2sPCKTMODhPG
         klsqDnIsNRwcI6rmBst4oaee0neLhAFYbX7ELLkAo3ieot5+fcEiOZ56Na9++SAgb7cb
         LCBrqsNbY6qqXiByXTn98Ozqsdj+kJ+uSHImVxgxOryWDklxvl4ZxunBXgmICj/FPPtU
         cm4Q/+VPoFurtsEGB4fnE3MglRRSTEPqZ0MjK3HUxWdbDEKS+nTvXY6FZR7/1nmMjpAN
         F2wgSdjXCuCOCmHghjF9A+jtvDBPLMPYMfxf8xf/8TY/5EO0GwlXb+gYf2g1+SbkKupC
         Hw8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755599776; x=1756204576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DJIcm8rBuxRdSJLpRl0yY01nbJA1BwfihEiIoh7mNdQ=;
        b=PBe+ekMR9DVSSPI603YDxCqg9KHQywKgQQlyXuNY7FAyXfBRl0CAgCtCRM3vq+3E0T
         /t3PC/PcGaJj2t/yfBS2nk89ovgm1XJVUja1jbyxfdWKue03+J4oBLCNVONJRGIVdxHD
         DrbLNwaBJ2JY7P9vLio9rD+kl6gdak+Xi0PJjYuHkjn8VkHQ81f3/87LWcOc5B3Vx6Fw
         uE2HdHeOmPDgT8+DiSFKHYy1WgFwh+eDg3PjNphUN+N7H0J5xQeUyfsKHfGdHTOZTSmS
         2mvmVeQ2m74SBrEWxEUEyQmNnwzQ9SzF1Bns9EAY/jXqcxkCtgys92Cl5tThBcW+4wtp
         IVkg==
X-Forwarded-Encrypted: i=2; AJvYcCVLuDQLd0iRc0aw/8dG2H1aW3jH4epaZoTXsf7fA5DqYuQDfI0F9kUosK0XE/18QhVVXQ8J6g==@lfdr.de
X-Gm-Message-State: AOJu0YxJcZ/t61ju0hj962I5yZOVOzuJCpHQdCw0g28kCZ6ZdGix5bbr
	GCEcbqfdLMJPPwOaeGbX9ni24vGt5m06FiYLp4IKo3Yiwo7ZzXBRnxl7
X-Google-Smtp-Source: AGHT+IFmc5UwUSTUarhcYTvPaFWvIImHdU/MdvcWTkW4+9GaecT7HooEeYZyLwT/XLAGxtWdmEXbPg==
X-Received: by 2002:a05:6902:124f:b0:e93:3a7c:10da with SMTP id 3f1490d57ef6-e94e6218e23mr2243159276.37.1755599775970;
        Tue, 19 Aug 2025 03:36:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdTMdkSHakP88+i9G2rT1Tu0ww1iY+oqx7XWp71fgIogw==
Received: by 2002:a05:6902:26c8:b0:e90:4b0e:c3c9 with SMTP id
 3f1490d57ef6-e931cc4d79bls5432902276.2.-pod-prod-06-us; Tue, 19 Aug 2025
 03:36:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3RddSq0/+q9n1fhMPgnXNqRrDg0APoevfIzoBqix7I7EJB5UDIlFV1flpnx0GmmiYBgEUjO/GGac=@googlegroups.com
X-Received: by 2002:a05:6902:1002:b0:e90:11bb:397c with SMTP id 3f1490d57ef6-e94e60632c9mr2358577276.10.1755599775012;
        Tue, 19 Aug 2025 03:36:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755599775; cv=none;
        d=google.com; s=arc-20240605;
        b=i0tsF51GvjT+SfpL19nHwPmMcnuHC72Uh0kG5/IKNW5LjAoW+Wafha5bi0F/+vqy9P
         4XXmlmJsM2iALiOtV/cRgmlMsl19+oaWOggfil7SrQBzFLR3z3+jUhhu7TA7Q0udRJwl
         wkvAivYV33uj97b6goE8DMMZDcSc2jgI2g5J2BXTqXxljYRz9iv4Avb8Hf0LHJstecRp
         FvrzTRkMI01kJizD4kneN/oZA3EZQLg5kXhAfwlrth53HSQ/7Vb7FvtmfXQsxxZHwkWz
         OnRn9BH1dl4wtEjplGUfVMYEsWE8iUQ/RaOE+iP5zJuWWhxhDkKfnlroe6Lgr/ZYQebd
         FUdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2fN+Cw2GD8q7ciDJSfP7W+cnq2F/R7FubEkGbK5iPps=;
        fh=Ph7BWLurm1IgNKSRBLfXsUN6hZsYEcCTiB3fpATNxHM=;
        b=EWocQg92Ms1Y0wAZ2wGHx58IVNLkBTXB5UyDLhrXV82LF4HUdAbqvvf8uYHcFj8Zhy
         0cBPGrb8D+YnWqU4fyTrvH/1/dzChWg5gZ1RFdsaBLD38+f/GZvtigz/edAQdJU/zSEm
         hvGP52aL/4HMvugyF9BPlASyepfxpYhD+BUVzo7AP891pw/4Ves0l+f8QNuvpxkfj0dR
         gE1u4oU1danXf5CzAOWSd2yYMS9RAHfAsiuXahp2HJolFxjB7aS/FzlT7wb38j5hRZSe
         B6Py76xuERApoCqX8icw6B9pzRvhCp+2ExdjDmo7msRU4zv2u/tKS3ssl78TWMqB41xk
         T+PA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="XUc/gzi6";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9339e1d539si443873276.4.2025.08.19.03.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Aug 2025 03:36:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-71d6051aeafso42365697b3.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Aug 2025 03:36:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIBQCrgQe8gmLv2Q5vP+J/ngW+v+d2zOtMKp1McuUuox8v3uKrlbIe1gGfwCXlnYCW+xnuXn5Qazo=@googlegroups.com
X-Gm-Gg: ASbGncuY+MUv83iTWJCHMzY3M8uja87F9fiJEX+JQ7xOll5DoWwATaQ9PIEJQ1JxV84
	sXbdxze8vPEHVcZAuvyP/DkkuETmYnF6hFK4IbpF4cyVrjEyd5hXyr1y2dcBUpiwk2AAOLdfQgA
	q8VxmaJCQ+cHGIUVHYXlDcSV28A6S8lo7L3+9+593kWyigw5mIV/TfDFh4gBDN8Oa0JnO2DckSx
	s0T7ZTTFKJoMRSgYjTzVGJHwevSxHKViuTZiW4vYbhYQmjrNJmb34rq
X-Received: by 2002:a05:690c:6c02:b0:71e:325e:5468 with SMTP id
 00721157ae682-71f9d494f58mr24000397b3.5.1755599774272; Tue, 19 Aug 2025
 03:36:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org> <20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0@kernel.org>
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Aug 2025 12:35:37 +0200
X-Gm-Features: Ac12FXy_pMfFpBqlyslz5YoDfRSNwKDNUf2Ii-KoSTGsRrmWmRwz_9vxZQpt2K4
Message-ID: <CANpmjNN243_NoHOEdHvs0zDTzX5w4hjWoeo9TnQbwgfPzOWJAA@mail.gmail.com>
Subject: Re: [PATCH 09/10] objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Kees Cook <kees@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, patches@lists.linux.dev, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="XUc/gzi6";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 18 Aug 2025 at 20:58, Nathan Chancellor <nathan@kernel.org> wrote:
>
> Now that the minimum supported version of LLVM for building the kernel
> has been bumped to 15.0.0, __no_kcsan will always ensure that the thread
> sanitizer functions are not generated, so remove the check for tsan
> functions in is_profiling_func() and the always true depends and
> unnecessary select lines in KCSAN_WEAK_MEMORY.
>
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Acked-by: Marco Elver <elver@google.com>

Good riddance.

> ---
> Cc: Josh Poimboeuf <jpoimboe@kernel.org>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> ---
>  lib/Kconfig.kcsan     |  6 ------
>  tools/objtool/check.c | 10 ----------
>  2 files changed, 16 deletions(-)
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 609ddfc73de5..4ce4b0c0109c 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -185,12 +185,6 @@ config KCSAN_WEAK_MEMORY
>         bool "Enable weak memory modeling to detect missing memory barriers"
>         default y
>         depends on KCSAN_STRICT
> -       # We can either let objtool nop __tsan_func_{entry,exit}() and builtin
> -       # atomics instrumentation in .noinstr.text, or use a compiler that can
> -       # implement __no_kcsan to really remove all instrumentation.
> -       depends on !ARCH_WANTS_NO_INSTR || HAVE_NOINSTR_HACK || \
> -                  CC_IS_GCC || CLANG_VERSION >= 140000
> -       select OBJTOOL if HAVE_NOINSTR_HACK
>         help
>           Enable support for modeling a subset of weak memory, which allows
>           detecting a subset of data races due to missing memory barriers.
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index d14f20ef1db1..efa4c060ff4e 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -2453,16 +2453,6 @@ static bool is_profiling_func(const char *name)
>         if (!strncmp(name, "__sanitizer_cov_", 16))
>                 return true;
>
> -       /*
> -        * Some compilers currently do not remove __tsan_func_entry/exit nor
> -        * __tsan_atomic_signal_fence (used for barrier instrumentation) with
> -        * the __no_sanitize_thread attribute, remove them. Once the kernel's
> -        * minimum Clang version is 14.0, this can be removed.
> -        */
> -       if (!strncmp(name, "__tsan_func_", 12) ||
> -           !strcmp(name, "__tsan_atomic_signal_fence"))
> -               return true;
> -
>         return false;
>  }
>
>
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN243_NoHOEdHvs0zDTzX5w4hjWoeo9TnQbwgfPzOWJAA%40mail.gmail.com.
