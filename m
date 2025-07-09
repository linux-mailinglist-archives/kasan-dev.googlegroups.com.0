Return-Path: <kasan-dev+bncBCMIZB7QWENRBS4IXLBQMGQEIAFXBFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id BFDFDAFECF1
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 17:01:46 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6098216df4esf1129422a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 08:01:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752073294; cv=pass;
        d=google.com; s=arc-20240605;
        b=PsfNhmPG/dfFX8ZZ9Y43VUxxDP8wpCm3KH7NI0KB5g2Q41/rN+pAev/EUcN2cKovxl
         Y0+mBsp52QuYNaQ5oL0RUQ2Qahiu6C6CwQahOYyhGQyLxTgZBxMjm7KpTl+vvrAQfKQB
         luKwbP6uD0nV2whT1HmBcsDR4rYXLboLHu1k/5dxwHK2G+Ir5wAcqmuEmWPDjyI/XfGi
         7iBASF312fvhu9x/5LseAsT8X+TnhlE+ZHJZIyKp8/96i87zg4mxicFjCfCLphKMMAVI
         puOItLH3SUAaRo8m8HzXnNYTtSCqEfWMC6qZR6mFC7jLmuTBzInyKgTIC3q+V1XGXsOG
         /AMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P54xfMby1se2r7q0HO2EJLD5jdqqrEPdwjqEEIu//DE=;
        fh=iSKiJ/fsqZaQ9f3fmpRhkEy/wajGNarh+wSu50TGmO4=;
        b=OWbZXf34UbxT4WDzFRJW1CuZBSG9X2Rp2Blf7MM1SiCyzvpvh0zqoZ3Bj2IBCy+Viu
         VcrktiRO8O58ATjH6Sjts3Wnbzp7MpdAREvt8lIUvar1GG778ujrMAKoaBqP6+9bsbqO
         D9GFcF4MK+CtB+YATN5ZPkagL61anecSgOSamda9eQOI0so6IdL0sE/EvRb3qPiwzu4t
         jBsIA0lUdDiEr7FwEOTQrBc1EwOShzise0oXKs5xqDvevH2acLcf33T7ISxFLRQNvLk/
         8xWBBSxSqASGD77PiCixVBnyAbXeY8LprcBAiuut8Zjwfe2QWiob5E3nWYbzDe28MwaD
         jYMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2cqTnvY8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752073294; x=1752678094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P54xfMby1se2r7q0HO2EJLD5jdqqrEPdwjqEEIu//DE=;
        b=xzpZALFl/kK4jR3ndeoXc6WfOPkMfegXb1HMf/s8VLolP74D9X+v2O3CpdzLfUNABj
         VVklXo9OCUGx2r6m/paRExRVnqOftcNasB5+ehrr1kvFImhYhdaBm9c2/MxyCGOIU5Lu
         1MtOAUgM3oEZrsKDn5DqZ3wePogYuJQxlTYxG1zev9gxtH6LiJNXNksZ2+xcbrn3OfU0
         aQYYtPTooX4IuEWX1/76hFk5ZH5Gf88xhj/fRawKLMAGNaXeOzIUIn2WLJMK15k0yjNJ
         5oHOudXoVdXoSiTtaCvCSyRA5oA0TF94vdc/MdAUhIAwyo5vzDxX2xyv0IlGSSOZ55R7
         qWTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752073294; x=1752678094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P54xfMby1se2r7q0HO2EJLD5jdqqrEPdwjqEEIu//DE=;
        b=d/qtriWpltbRztAmbzmbojp26yT1jlDsgHhlMwvEqA3yMy2rwnCG18otsmZy0RSEhQ
         ONCjXooMnJQQTrgGKdmJnrPP5HI1qMriBEL6xf8mS4/uvG0zYveIgOufDcBkhJWiC8ke
         JxhfxVJSjHW+W5ldyO2mxmmkanp0RZ/nP//B5P+sc0B9C7/c/VmaRHMzBN8PpzVTlVGW
         G1LA0rcw+mFTtlOtA19aSIBUt1OQp+mPmM4f9quEeSk/0vHzKT2reQ3m1tuw3RvvqQNa
         i+b80ImT3n8Smiqfvf2CaczpwN2y35mrztOScXmVOxNtibxxOBFf2I6ahoYhL2lT/632
         vopQ==
X-Forwarded-Encrypted: i=2; AJvYcCUWXqKTdD7LCdbphuABLRIf7I55W11fayDE7EkqL2P5A3wJuOxnxUqaKDwH36UinbfBeL12QA==@lfdr.de
X-Gm-Message-State: AOJu0YxlOyNGaawxKRvO8vWAUvsuGbUIMo07XxsP+HEERsXnx1To8Xyv
	6/S8DTw7XKTyL/FHk8PKGiRqXj76ArQnYOa7jFsgiUOlGkW4NdfD9/Ml
X-Google-Smtp-Source: AGHT+IEBDRJiZ3MHb5X27smgF+sTEuAR3NMrxMsImn7cNTnnXzAfRgRMr0r0yGGEvKNodlCsdmD++A==
X-Received: by 2002:a05:6402:51d3:b0:60f:c32a:834 with SMTP id 4fb4d7f45d1cf-6104bf2097amr6217147a12.5.1752073292484;
        Wed, 09 Jul 2025 08:01:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZebTJe6uhtd8sY7YjEDnbtsB/CSklnBtM+hn6HXNuNMIw==
Received: by 2002:a05:6402:3482:b0:607:2358:a304 with SMTP id
 4fb4d7f45d1cf-60fdb610f69ls4046791a12.1.-pod-prod-00-eu; Wed, 09 Jul 2025
 08:01:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzMHKRUzNMyUp7LQAqP45wcC5gRYtermkBKwVglb3PXLrv90w/0zMgFLwNU+UQ4VXSfdc/MuKrbOA=@googlegroups.com
X-Received: by 2002:a05:6402:210b:b0:604:b87f:88b4 with SMTP id 4fb4d7f45d1cf-611a5d6d2f5mr2938916a12.2.1752073288038;
        Wed, 09 Jul 2025 08:01:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752073288; cv=none;
        d=google.com; s=arc-20240605;
        b=WjYes2kWQEzohTsU3TEHToufTQnj4kU1Pu6grQaf9bztfmM0dOkUqJ76A44oWqy7nx
         uJm5QfTpufywEr99KUU1ISjTp1QLQk2hlNj+3J5vT6fjSBPKU24lQxRO2GyPDLbZjHjY
         jXWvMqz8F6klenLE9/lDmiklIkkims0JQoWlECviCWPFY8Vc+/yL+y3ecsuXJ6Y7hld2
         SAowJEc8JePxCf2lFomaUYRdY5imsNGzYao/RvX03Er+TQItNpovnwCWArhM8hL42BfH
         STigUXLF3FYpj4ExUHXGOTVJAOaSP74Ek07TTqK02YgPz8TMSQgFN4VtO0iCvGtcGR94
         oDBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EXZ6H+YoWJArAnXa1Z6UilH2W16N5kp2UTPdU52uK04=;
        fh=g+Ewirzb2s6svLpOyq5XOVbQHDrDFAHbLmQHql6S9uo=;
        b=gI/BzTpJDw+kCS0Xh9zAYv7DfqvVXeWyYrTot1L5OtNs8WV1i7KonvKPtE9b57SZ8Z
         b7XfksI4SFoWGtBhEJw4vo9bMMxtWWo5/ln277CQGev7+GKOXl++BpohMfg6O2vglPlf
         RZAwW8iPGUqz3FA117CvIvvXejo9A+ejqtMsFlSitk/bxUAUF5+sKDazTDZXWvTr0eoj
         lIWfxrnjQPHwuG25NL8xudinRGJp9qi1cYqOR/mbdUMCL1zuWQy6rxo//KclxoTbmCzI
         /jYCdWDWfaXMTBy+6Vbexxr21oz0m8n9RKRhRP36zSZz4svleRBnmG6gd/FAVG2py9W9
         ZRyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2cqTnvY8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6101796b095si142000a12.0.2025.07.09.08.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 08:01:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-32b43c5c04fso10270701fa.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 08:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/Qn0e/OxPE1chNcnzFHwLLZVunYSTHvJ2YcuvEYmjiao6d5Jc6Yo/bnKDsk1iKNbiJL1+YBtyAWI=@googlegroups.com
X-Gm-Gg: ASbGncuu5uRMjUC/hi7vnYITqlhmH51Q2PDxEUmRXqILe6hSRrHp7k0uivKmlahxNQb
	OEwQCUkM/hXGFwN9sH8eBZ26CtSURoPnJRBaoymovHhdC5Ryac+SB1sa2KNCkKAVqBFZf4B26An
	2wAghNUpHuVHgEXBItcvdPH4C7ZrHu+GCdwsVPcIAMEVfrhtrUWLqh5dSYqrI9xJpj06UMurp3m
	KA5
X-Received: by 2002:a2e:be0e:0:b0:32b:7811:d451 with SMTP id
 38308e7fff4ca-32f39b49274mr23241471fa.16.1752073284044; Wed, 09 Jul 2025
 08:01:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-7-glider@google.com>
In-Reply-To: <20250626134158.3385080-7-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 17:01:12 +0200
X-Gm-Features: Ac12FXyg4ttgAUhDWzibcPhOOzL0-kmtMxmwZUbc31PqG9SfpgNYhtV4DobNjeM
Message-ID: <CACT4Y+b_KkqF0dm8OM1VUfwzDph6gHisk2amkk9RrLiGV24s9A@mail.gmail.com>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2cqTnvY8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
>
> The new config switches coverage instrumentation to using
>   __sanitizer_cov_trace_pc_guard(u32 *guard)
> instead of
>   __sanitizer_cov_trace_pc(void)
>
> This relies on Clang's -fsanitize-coverage=trace-pc-guard flag [1].
>
> Each callback receives a unique 32-bit guard variable residing in the
> __sancov_guards section. Those guards can be used by kcov to deduplicate
> the coverage on the fly.
>
> As a first step, we make the new instrumentation mode 1:1 compatible
> with the old one.
>
> [1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
>
> Cc: x86@kernel.org
> Signed-off-by: Alexander Potapenko <glider@google.com>
>
> ---
> Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
>
> v2:
>  - Address comments by Dmitry Vyukov
>    - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
>    - update commit description and config description
>  - Address comments by Marco Elver
>    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
>    - make config depend on X86_64 (via ARCH_HAS_KCOV_UNIQUE)
>    - swap #ifdef branches
>    - tweak config description
>    - remove redundant check for CONFIG_CC_HAS_SANCOV_TRACE_PC_GUARD
> ---
>  arch/x86/Kconfig                  |  1 +
>  arch/x86/kernel/vmlinux.lds.S     |  1 +
>  include/asm-generic/vmlinux.lds.h | 14 ++++++-
>  include/linux/kcov.h              |  2 +
>  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
>  lib/Kconfig.debug                 | 24 ++++++++++++
>  scripts/Makefile.kcov             |  4 ++
>  scripts/module.lds.S              | 23 ++++++++++++
>  tools/objtool/check.c             |  1 +
>  9 files changed, 110 insertions(+), 21 deletions(-)
>
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index e21cca404943e..d104c5a193bdf 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -93,6 +93,7 @@ config X86
>         select ARCH_HAS_FORTIFY_SOURCE
>         select ARCH_HAS_GCOV_PROFILE_ALL
>         select ARCH_HAS_KCOV                    if X86_64
> +       select ARCH_HAS_KCOV_UNIQUE             if X86_64
>         select ARCH_HAS_KERNEL_FPU_SUPPORT
>         select ARCH_HAS_MEM_ENCRYPT
>         select ARCH_HAS_MEMBARRIER_SYNC_CORE
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> index cda5f8362e9da..8076e8953fddc 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -372,6 +372,7 @@ SECTIONS
>                 . = ALIGN(PAGE_SIZE);
>                 __bss_stop = .;
>         }
> +       SANCOV_GUARDS_BSS
>
>         /*
>          * The memory occupied from _text to here, __end_of_kernel_reserve, is
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index 58a635a6d5bdf..875c4deb66208 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -102,7 +102,8 @@
>   * sections to be brought in with rodata.
>   */
>  #if defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || defined(CONFIG_LTO_CLANG) || \
> -defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
> +       defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG) || \
> +       defined(CONFIG_KCOV_UNIQUE)
>  #define TEXT_MAIN .text .text.[0-9a-zA-Z_]*
>  #else
>  #define TEXT_MAIN .text
> @@ -121,6 +122,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
>  #define SBSS_MAIN .sbss
>  #endif
>
> +#if defined(CONFIG_KCOV_UNIQUE)
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
> index 0e425c3524b86..dd8bbee6fe274 100644
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
> index ff7f118644f49..8e98ca8d52743 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -195,27 +195,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>         return ip;
>  }
>
> -/*
> - * Entry point from instrumented code.
> - * This is called once per basic-block/edge.
> - */
> -void notrace __sanitizer_cov_trace_pc(void)
> +static notrace void kcov_append_to_buffer(unsigned long *area, int size,
> +                                         unsigned long ip)
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
> -       area = t->kcov_state.area;
>         /* The first 64-bit word is the number of subsequent PCs. */
> -       pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_state.size)) {
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
> @@ -226,7 +214,40 @@ void notrace __sanitizer_cov_trace_pc(void)
>                 area[pos] = ip;
>         }
>  }
> +
> +/*
> + * Entry point from instrumented code.
> + * This is called once per basic-block/edge.
> + */
> +#ifdef CONFIG_KCOV_UNIQUE
> +void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
> +{
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +               return;
> +
> +       kcov_append_to_buffer(current->kcov_state.area,
> +                             current->kcov_state.size,
> +                             canonicalize_ip(_RET_IP_));
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> +
> +void notrace __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
> +                                                uint32_t *stop)
> +{
> +}
> +EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
> +#else /* !CONFIG_KCOV_UNIQUE */
> +void notrace __sanitizer_cov_trace_pc(void)
> +{
> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +               return;
> +
> +       kcov_append_to_buffer(current->kcov_state.area,
> +                             current->kcov_state.size,
> +                             canonicalize_ip(_RET_IP_));
> +}
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> +#endif
>
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> @@ -254,7 +275,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
> -               /* See comment in __sanitizer_cov_trace_pc(). */
> +               /* See comment in kcov_append_to_buffer(). */
>                 WRITE_ONCE(area[0], count + 1);
>                 barrier();
>                 area[start_index] = type;
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index f9051ab610d54..24dcb721dbb0b 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2156,6 +2156,8 @@ config ARCH_HAS_KCOV
>  config CC_HAS_SANCOV_TRACE_PC
>         def_bool $(cc-option,-fsanitize-coverage=trace-pc)
>
> +config CC_HAS_SANCOV_TRACE_PC_GUARD
> +       def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
>
>  config KCOV
>         bool "Code coverage for fuzzing"
> @@ -2172,6 +2174,28 @@ config KCOV
>
>           For more details, see Documentation/dev-tools/kcov.rst.
>
> +config ARCH_HAS_KCOV_UNIQUE
> +       bool
> +       help
> +         An architecture should select this when it can successfully
> +         build and run with CONFIG_KCOV_UNIQUE.
> +
> +config KCOV_UNIQUE
> +       depends on KCOV
> +       depends on CC_HAS_SANCOV_TRACE_PC_GUARD && ARCH_HAS_KCOV_UNIQUE
> +       bool "Use coverage guards for KCOV"
> +       help
> +         Use coverage guards instrumentation for KCOV, passing
> +         -fsanitize-coverage=trace-pc-guard to the compiler.

I think this should talk about the new mode, the new ioctl's, and
visible differences for end users first.

> +         Every coverage callback is associated with a global variable that
> +         allows to efficiently deduplicate coverage at collection time.
> +         This drastically reduces the buffer size required for coverage
> +         collection.
> +
> +         This config comes at a cost of increased binary size (4 bytes of .bss
> +         plus 1-2 instructions to pass an extra parameter, per basic block).
> +
>  config KCOV_ENABLE_COMPARISONS
>         bool "Enable comparison operands collection by KCOV"
>         depends on KCOV
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 67e8cfe3474b7..0b17533ef35f6 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -1,5 +1,9 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> +ifeq ($(CONFIG_KCOV_UNIQUE),y)
> +kcov-flags-y                                   += -fsanitize-coverage=trace-pc-guard
> +else
>  kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)    += -fsanitize-coverage=trace-pc
> +endif
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   += -fsanitize-coverage=trace-cmp
>  kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)         += -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
>
> diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> index 450f1088d5fd3..314b56680ea1a 100644
> --- a/scripts/module.lds.S
> +++ b/scripts/module.lds.S
> @@ -64,6 +64,29 @@ SECTIONS {
>                 MOD_CODETAG_SECTIONS()
>         }
>  #endif
> +
> +#ifdef CONFIG_KCOV_UNIQUE
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

Why do we need these here? .text does not look specific to CONFIG_KCOV_UNIQUE.
Is it because of constructors/destructors emitted by the compiler, and
.init.text/.exit.text don't work w/o .text?
A comment here would be useful.

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
> index b21b12ec88d96..62fbe9b2aa077 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1154,6 +1154,7 @@ static const char *uaccess_safe_builtin[] = {
>         "write_comp_data",
>         "check_kcov_mode",
>         "__sanitizer_cov_trace_pc",
> +       "__sanitizer_cov_trace_pc_guard",
>         "__sanitizer_cov_trace_const_cmp1",
>         "__sanitizer_cov_trace_const_cmp2",
>         "__sanitizer_cov_trace_const_cmp4",
> --
> 2.50.0.727.gbf7dc18ff4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb_KkqF0dm8OM1VUfwzDph6gHisk2amkk9RrLiGV24s9A%40mail.gmail.com.
