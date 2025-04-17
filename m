Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75TQXAAMGQE6R66EHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B167A92BE7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 21:44:01 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-73917303082sf787149b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 12:44:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744919039; cv=pass;
        d=google.com; s=arc-20240605;
        b=i1c4Q1jIcCTikV+PKF52D2h9+bFkYTFwWJznKZTcmE3UN/H+noK4YqLgLjspm3w/ex
         LD7eKPhCWGAAD4oflpG3+qrIqYrGGwaVmPD/puDVp66oUPc5xZHi6ZYktjKMZqJ26Tz0
         Aov4MqZak/sjnQ10fiK1yQen2KkANajym33RPR2qNpzNxwlQQ/bkveNC8UeOy8I2Y5BY
         F4E+19GMoDV+/txkR7D+EcVaLcDbdJtU31imvoeDeQVa9bMYl01C8FNL9XkhDG01+XVJ
         kJ+scJxu8g3jZmQc91qN91B50zrUYB580Lv6V9WWnMIB3Cu3XQ86X65drQR1maisfq8C
         NSXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xd3bVAUBSS5zh3eTy9gWVJ5mrw7VISk3TwtxzO0hzio=;
        fh=cQhqjsj+ciSJAHKhKFr6qZlLRrHLVkLMyNk3V50kHqQ=;
        b=Q9qsLCguhBMXs/IpieglQ39TvpVNS+Wd0/+0+fDKtnVoSSuLJilf/J2uyb0mbI2wMu
         4MXmsoUADVG06z7klkvUpC1hslYgaf3L8LjmPhilxaOzZTtL7UtFP3eyzhNZx6iyZqJ4
         6V2yl1DwG3Q7I4guK7d2phJceR15Mxgg7aF2HLcieBDHrMUIHP/t9Tp6mwcNn6J1qyAm
         xMwQXMn3SnTAr7RqXln81JkrHtU+PkTttONJWD+YWg/S/eRmZJKZfcwkBfnZ3VZ2bNq8
         3+ZtCQzxDwlkTc+z0NKPkFEsz/qINeAygizE4LdGl5Z9/QbHnKuYNMTpZUCzCarZ2L//
         e44g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q5MVLLDF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744919039; x=1745523839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xd3bVAUBSS5zh3eTy9gWVJ5mrw7VISk3TwtxzO0hzio=;
        b=hcDxFfwsvqJ0Fv37/hpmJdE6dyzhWBgK647POt/2qshULzs87IAu1gZVPCLacjiXjV
         trFHFmzJ9txN/OeQONIBCKqMW7FAxbom+6geaNQDUdIbmAKr1chD2a/vcS/OazJ1cUJD
         lfZOe0jGOti2OcCLrgQIhtQ29XKHLc+a3lF3v6PgBAlHznIjaZvEaTlZ0dUyXR8DIaC5
         UfGK8Zgx87rcowFQLNpaPTXF1ODqJ0ZoIh7aSwLyxx5+vzLkzDkiyHcLjq2oUL+cGf5H
         u18UpZH4RmBmV1uFGKWFBI7VqHRZuFWv4GhmQGHUGX3QdliBe8FLBCZxl314BNM3cerk
         jIiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744919039; x=1745523839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xd3bVAUBSS5zh3eTy9gWVJ5mrw7VISk3TwtxzO0hzio=;
        b=QF6rEpIZxs1mbnTmOAlAl0RCDg7CoP3Vw7lWLyyJQkbc12LIuEB9mPs3GzVWU2YyWm
         U0NVlBsrMsQBdaycQcNY7+d/WXQkRLmAJfFV1f2styvtLoVONtNWyYJDLninTt5Hcexo
         pyH+dS+o1TQ9GQUBbc8LhLkjXsxScEFDgj3BH6h7Ks1TvL5rqY53n1kGyoTlbuqzCfmH
         OunmWWk+rkqwZ6KO6U5ke3scbRs0NLrWbo2HnrDV/kEMvasg9vsyHiJ+jzYC7LPGNnWK
         S+h+bmPJ6v5JXbDINKGHv2CbnfR8k9Y+wUta1noTFQADeslsopr863OWY8XOT2pQIkhy
         jwJA==
X-Forwarded-Encrypted: i=2; AJvYcCUB7GQh1MXG5EzpCAJwZd+VjWavjItuf0CgcnUwBoj6v03bQuQJLzRKsbzyj3soxpXKyM2bFw==@lfdr.de
X-Gm-Message-State: AOJu0YyphH7AxQqn7ZsNMxdoJ6ti4xaFTBXzVU0CrBy6lrevaKvlOln5
	qiPRgIogWb+dNQm8TLntrADJl2w2H726lZDtlh9n2nEyPpazCLZ0
X-Google-Smtp-Source: AGHT+IEkB/l3BMYPxOW0BsHhkEOp0D1a76PUpAu80UYJK+L+gTdTO0prbhnWdJNYWNwFHOwAE+768Q==
X-Received: by 2002:a05:6a00:114d:b0:736:3c2f:acdd with SMTP id d2e1a72fcca58-73dc14c80b5mr146033b3a.14.1744919039340;
        Thu, 17 Apr 2025 12:43:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKsrlZFLepsO3E5hzGJsGicxtjUo84PONw5DHu6Bxu8eQ==
Received: by 2002:a05:6a00:390f:b0:728:e1d1:39dd with SMTP id
 d2e1a72fcca58-73c32a0d9c5ls1511446b3a.1.-pod-prod-05-us; Thu, 17 Apr 2025
 12:43:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKmdAcVcJoSTmiW4TlBOs0ejNYyP7MwjQMbKsDANbfyJlg+tuLRycpEvGIgotmXsoG0YuKFsbVt2U=@googlegroups.com
X-Received: by 2002:a05:6a00:130e:b0:736:b402:533a with SMTP id d2e1a72fcca58-73dc14453bcmr155963b3a.1.1744919037845;
        Thu, 17 Apr 2025 12:43:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744919037; cv=none;
        d=google.com; s=arc-20240605;
        b=PPx2t0MaTJlFVfL62gP8XPRmZNnFQ8QcPqHBEef/RZ6RGIGaGixzkhYMQRbWEeeXQT
         vygOHFVn1KTzAqObcs8rVUwaJGtBWZpExD55/HBQJAabzZMhW8/2LlIan/+wUYdRff4X
         JWDj6erpPq07eqaWN0cu1sBsTNP8Zng7E8FanWCgsMLKqThCZsEylGkXR9Nfsb092Tmp
         IzK9B9t1FqHakp6Yezj28OqMlFDgBx2bzuwEynVIazv0y1G4TyPIMoCALR2TnTBwOdQi
         DnbyAGCcr/0Hc0rW/VtbJdDGCTguaaimVa1AIAw6Mxl8qOlOdAy43TGAKD9aeoC160Mx
         GgRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rYo3jxKCye0dqDCwno5JHcRnzatOv0mt+5gN6W9sfks=;
        fh=9r0/Kxbmj/FqukwDL79CsvhHW1f0oD61/YXlSNnO9YA=;
        b=SEAFv3sqFWGyEMvxsghhA81vSE9shzm6szdmZG7gKJtihtMPjZLx4CWgds3wAx8GBW
         FoshlHwZKPVNGz5CmoLe/Nuto2Lg2gAQUxyHVpF29l5IN/E9NVGg7RjNrkcQF7nvYjwx
         vJ7p3FiPdQ8GTEqZnZThJ/MC+AeCxqOq9VjGSerujmoSlzFfRm0P588nWtC5WZIIDNsi
         rAZ1hR0Rvu6AbZrxgjP1F/g/ifVT4NHV4u+XS0HD9SegDBj0/gaCZVnZoberWsWkDw/N
         ZgT4a9G1SEW167NIJI8FZW0wNYN+dH9LnLjbcT6bHCcXdRQBQEW39L6Uw6iFsj5NRzl+
         bD7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q5MVLLDF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73dbf688e16si23935b3a.0.2025.04.17.12.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 12:43:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b074d908e56so869550a12.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 12:43:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXTumSalVPVHZuyVQYLVMzk4nznwoQf/KZAY1/89Wtt/aCATMi/LMNlJJlYITIwPMFxX6WEMOrwECQ=@googlegroups.com
X-Gm-Gg: ASbGnctWiKMKXoCMoHN2MgMNb9akkh3gkhpuoqNDrM4oGD+mzMWFrIGa5OwFmPe60gq
	EGTCTU4PzFwWqSdXgGyGskkK559YMadxGa8jDQNbJW1X4tJlJ8fPkMgpJHeMcj2rRbPzJmm32oq
	pG1WOqdKebsDJ9lrc9vK16Pr4ZAkKGmSdbuCIazO//AslsXzS5NF0aBgr1vYQzN//P
X-Received: by 2002:a17:90b:1f8d:b0:2ee:af31:a7bd with SMTP id
 98e67ed59e1d1-3087bb3965bmr397478a91.5.1744919037245; Thu, 17 Apr 2025
 12:43:57 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-4-glider@google.com>
In-Reply-To: <20250416085446.480069-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 21:43:20 +0200
X-Gm-Features: ATxdqUEE9-qQchyPLigAckRascGi6jw_Ms76PRy6A848FlY7vwM_NhxkCcDNZEw
Message-ID: <CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ@mail.gmail.com>
Subject: Re: [PATCH 3/7] kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Q5MVLLDF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as
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

On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wrote:
>
> The new config switches coverage instrumentation to using
>   __sanitizer_cov_trace_pc_guard(u32 *guard)
> instead of
>   __sanitizer_cov_trace_pc(void)
>
> Each callback receives a unique 32-bit guard variable residing in the
> __sancov_guards section. Those guards can be used by kcov to deduplicate
> the coverage on the fly.
>
> As a first step, we make the new instrumentation mode 1:1 compatible with
> the old one.
>
> Cc: x86@kernel.org
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  arch/x86/kernel/vmlinux.lds.S     |  1 +
>  include/asm-generic/vmlinux.lds.h | 14 ++++++-
>  include/linux/kcov.h              |  2 +
>  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
>  lib/Kconfig.debug                 | 16 ++++++++
>  scripts/Makefile.kcov             |  4 ++
>  scripts/module.lds.S              | 23 ++++++++++++
>  tools/objtool/check.c             |  1 +
>  8 files changed, 101 insertions(+), 21 deletions(-)
>
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> index 0deb4887d6e96..2acfbbde33820 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -390,6 +390,7 @@ SECTIONS
>                 . = ALIGN(PAGE_SIZE);
>                 __bss_stop = .;
>         }
> +       SANCOV_GUARDS_BSS

Right now this will be broken on other architectures, right?

>         /*
>          * The memory occupied from _text to here, __end_of_kernel_reserve, is
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index 0d5b186abee86..3ff150f152737 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -102,7 +102,8 @@
>   * sections to be brought in with rodata.
>   */
>  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
> -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> +       defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
> +       defined(CONFIG_KCOV_ENABLE_GUARDS)
>  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
>  #else
>  #define TEXT_MAIN .text
> @@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
>  #define SBSS_MAIN .sbss
>  #endif
>
> +#if defined(CONFIG_KCOV_ENABLE_GUARDS)
> +#define SANCOV_GUARDS_BSS                      \
> +       __sancov_guards(NOLOAD) : {             \
> +               __start___sancov_guards = .;    \
> +               *(__sancov_guards);             \
> +               __stop___sancov_guards = .;     \
> +       }
> +#else
> +#define SANCOV_GUARDS_BSS
> +#endif
> +
>  /*
>   * GCC 4.5 and later have a 32 bytes section alignment for structures.
>   * Except GCC 4.9, that feels the need to align on 64 bytes.
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index e1f7d793c1cb3..7ec2669362fd1 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -107,6 +107,8 @@ typedef unsigned long long kcov_u64;
>  #endif
>
>  void __sanitizer_cov_trace_pc(void);
> +void __sanitizer_cov_trace_pc_guard(u32 *guard);
> +void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
>  void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
>  void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
>  void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 8fcbca236bec5..b97f429d17436 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -193,27 +193,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>         return ip;
>  }
>
> -/*
> - * Entry point from instrumented code.
> - * This is called once per basic-block/edge.
> - */
> -void notrace __sanitizer_cov_trace_pc(void)
> +static void sanitizer_cov_write_subsequent(unsigned long *area, int size,

notrace is missing.

Can we give this a more descriptive name? E.g. "kcov_append" ?

> +                                          unsigned long ip)
>  {
> -       struct task_struct *t;
> -       unsigned long *area;
> -       unsigned long ip = canonicalize_ip(_RET_IP_);
> -       unsigned long pos;
> -
> -       t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> -               return;
> -
> -       area = t->kcov_state.s.area;
>         /* The first 64-bit word is the number of subsequent PCs. */
> -       pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_state.s.size)) {
> -               /* Previously we write pc before updating pos. However, some
> -                * early interrupt code could bypass check_kcov_mode() check
> +       unsigned long pos = READ_ONCE(area[0]) + 1;
> +
> +       if (likely(pos < size)) {
> +               /*
> +                * Some early interrupt code could bypass check_kcov_mode() check
>                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
>                  * raised between writing pc and updating pos, the pc could be
>                  * overitten by the recursive __sanitizer_cov_trace_pc().
> @@ -224,7 +212,40 @@ void notrace __sanitizer_cov_trace_pc(void)
>                 area[pos] = ip;
>         }
>  }
> +
> +/*
> + * Entry point from instrumented code.
> + * This is called once per basic-block/edge.
> + */
> +#ifndef CONFIG_KCOV_ENABLE_GUARDS

Negation makes it harder to read - just #ifdef, and swap the branches below.

> +void notrace __sanitizer_cov_trace_pc(void)
> +{
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +               return;
> +
> +       sanitizer_cov_write_subsequent(current->kcov_state.s.area,
> +                                      current->kcov_state.s.size,
> +                                      canonicalize_ip(_RET_IP_));
> +}
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> +#else
> +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> +{
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +               return;
> +
> +       sanitizer_cov_write_subsequent(current->kcov_state.s.area,
> +                                      current->kcov_state.s.size,
> +                                      canonicalize_ip(_RET_IP_));
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> +
> +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> +                                                uint32_t *stop)
> +{
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> +#endif
>
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> @@ -252,7 +273,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
> -               /* See comment in __sanitizer_cov_trace_pc(). */
> +               /* See comment in sanitizer_cov_write_subsequent(). */
>                 WRITE_ONCE(area[0], count + 1);
>                 barrier();
>                 area[start_index] = type;
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 35796c290ca35..a81d086b8e1ff 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2135,6 +2135,8 @@ config ARCH_HAS_KCOV
>  config CC_HAS_SANCOV_TRACE_PC
>         def_bool $(cc-option,-fsanitize-coverage=trace-pc)
>
> +config CC_HAS_SANCOV_TRACE_PC_GUARD
> +       def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
>
>  config KCOV
>         bool "Code coverage for fuzzing"
> @@ -2151,6 +2153,20 @@ config KCOV
>
>           For more details, see Documentation/dev-tools/kcov.rst.
>
> +config KCOV_ENABLE_GUARDS

The "ENABLE" here seems redundant.
Just KCOV_GUARDS should be clear enough.

> +       depends on KCOV
> +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD
> +       bool "Use fsanitize-coverage=trace-pc-guard for kcov"

The compiler option is an implementation detail - it might be more
helpful to have this say "Use coverage guards for kcov".

> +       help
> +         Use coverage guards instrumentation for kcov, passing
> +         -fsanitize-coverage=trace-pc-guard to the compiler.
> +
> +         Every coverage callback is associated with a global variable that
> +         allows to efficiently deduplicate coverage at collection time.
> +
> +         This comes at a cost of increased binary size (4 bytes of .bss
> +         per basic block, plus 1-2 instructions to pass an extra parameter).
> +
>  config KCOV_ENABLE_COMPARISONS
>         bool "Enable comparison operands collection by KCOV"
>         depends on KCOV
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 67e8cfe3474b7..ec63d471d5773 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -1,5 +1,9 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> +ifeq ($(CONFIG_KCOV_ENABLE_GUARDS),y)
> +kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD) += -fsanitize-coverage=trace-pc-guard

This can just be kcov-flags-y, because CONFIG_KCOV_ENABLE_GUARDS
implies CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD.

> +else
>  kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    += -fsanitize-coverage=trace-pc
> +endif
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   += -fsanitize-coverage=trace-cmp
>  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
>
> diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> index 450f1088d5fd3..ec7e9247f8de6 100644
> --- a/scripts/module.lds.S
> +++ b/scripts/module.lds.S
> @@ -64,6 +64,29 @@ SECTIONS {
>                 MOD_CODETAG_SECTIONS()
>         }
>  #endif
> +
> +#ifdef CONFIG_KCOV_ENABLE_GUARDS
> +       __sancov_guards(NOLOAD) : {
> +               __start___sancov_guards = .;
> +               *(__sancov_guards);
> +               __stop___sancov_guards = .;
> +       }
> +
> +       .text : {
> +               *(.text .text.[0-9a-zA-Z_]*)
> +               *(.text..L*)
> +       }
> +
> +       .init.text : {
> +               *(.init.text .init.text.[0-9a-zA-Z_]*)
> +               *(.init.text..L*)
> +       }
> +       .exit.text : {
> +               *(.exit.text .exit.text.[0-9a-zA-Z_]*)
> +               *(.exit.text..L*)
> +       }
> +#endif
> +
>         MOD_SEPARATE_CODETAG_SECTIONS()
>  }
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index ce973d9d8e6d8..a5db690dd2def 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1149,6 +1149,7 @@ static const char *uaccess_safe_builtin[] = {
>         "write_comp_data",
>         "check_kcov_mode",
>         "__sanitizer_cov_trace_pc",
> +       "__sanitizer_cov_trace_pc_guard",
>         "__sanitizer_cov_trace_const_cmp1",
>         "__sanitizer_cov_trace_const_cmp2",
>         "__sanitizer_cov_trace_const_cmp4",
> --
> 2.49.0.604.gff1f9ca942-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNmyXd9YkYSTpWrKRqBzJp5bBaEZEuZLHK9Tw-D6NDezQ%40mail.gmail.com.
