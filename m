Return-Path: <kasan-dev+bncBCMIZB7QWENRBZOYULCAMGQETQIX42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CFD0B14CC4
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:11:35 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4560f28b2b1sf17570795e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:11:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753787494; cv=pass;
        d=google.com; s=arc-20240605;
        b=VQe256uyXqPfWBWXnPRYxnsiti5DwdwS5tgIkfyV7aGAb0KWSt0V5P0K3ljY+p7T8l
         Ndhzzu+pgINWNwFkw6xW2ZzlnezYrS4SkPMyUe0zLgIjmBuaXdA7y18+/XsvOb9iIRO6
         GUnsHSqOm+Jj1/loAVDdtd3PRimDPHTlUN0pP5Y0JrTf8V69Uqa4TzQAjA7ETsHG30Ym
         DorcsuuROdeWZmZPnau3fkuozn7qn4tmOvKk5zlcPmhBLNAITstG8hzOnHF5mzPzV5HP
         QEmR8aqnPY8fEqc7+DciStBDcrPT7+8fmPirdSgop+bOsAm21gKzLrn5ZAzDOGFvGACq
         gccA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=heUJcZ+H9eF0KbO0B9k1uNiSg8ej32lCGSIk4nKmfZk=;
        fh=vdiZTPcxgls60lwr06wMelm3QEaou0Y3Rq1HQeorGVY=;
        b=Wn9b7vF04RlN79LPY0Ia4KS6bt/YYcwXNs0vwhzn6fd8m7prHo+/S/ieIqJQUR9ypV
         ihWGkDHdEqu6kv6h1dGQg5KXJBNU/HghOdnIvJWFO6K6bML7AZAOLf2+jVQvZsXW00Eq
         FoDYOA1eRBuXFRvlHykNnEanhKYA5NZRbCKnyO47rIaN6ZUZIVwPSlVyLGLNikX9cxS9
         a7T/A9B/Tv5rjB0hZyLJK3Jne9N76yMRy+x0xgQ+OUrfwnwF4tiWmKIhbKRV1uekbzaH
         ChnMWJATAmDeIXOnl6OwFI38bSyeZ4Oo3X6XCBN8hR+LCxp0jxgpYN0kYfLmt7EpOrun
         8N0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fu1R5p6x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753787494; x=1754392294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=heUJcZ+H9eF0KbO0B9k1uNiSg8ej32lCGSIk4nKmfZk=;
        b=N/sMcU3XJ/zHKihwadIVnMlbsmJpMA8iFy6Mu4V7P+hcpsR2Xj/yIxnknYY5lCeZho
         /w2Vqzzjwp/omsD1v8kugWg1ZTdy7VmsSy9s2GobThmIc3+KJQ0bI51+3gLc5mlpNdwc
         c5p0vN621noc40UxE5VZ2yR6NtlhSYHCASQcvPURJ7tMaVIyzyK851TE9164mXDlAR2C
         2S64bEV8Q1KrHCh4o2pxukBKBDWZjgk7WTAYoxU7Vc+yKB9qYLQ7yvwRcawpswO3FXQk
         un4pqKo5tXOnUdYgxc8/D5sV56H3W4FPmmn7DfYNZHW64KZyNVLg9mJGCX8zuT3gY4KC
         ILDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753787494; x=1754392294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=heUJcZ+H9eF0KbO0B9k1uNiSg8ej32lCGSIk4nKmfZk=;
        b=Ah+Yq/dtLkh8uBze7E0CUfPNi6nX4fMrHGRfRuafk81ddDCz3Wdtybg+OlZl4LEkdY
         Lfh2xq3KOG8gtZq4RIHYK6qJwZxeP0Z3nUBIqsb0KILzY7It+x24sxLLwTRNwlNL/zSQ
         xOut6g3nY/ULzS8xNZgl5c7KluVJE+CECGzrCvMAaDvYmrueJEUtlCttVx/1GzIJYeug
         WB0m8nhjv0/zqxWT94aKksebfAjIQClHUoVxtts/1rj33c7yGRbur3R3X1e1xcWHKYwa
         wI9oYrQR5EKL/aPD3pHI8slgrdDPii5nKVZEusWq/mDe3/hjMOb5hvYSGgNo9yvxr1xn
         N4Nw==
X-Forwarded-Encrypted: i=2; AJvYcCUz0dh0gY00HqDJoTs0/n6sircDQWTCjO+PUF5OzDSwAnfWC5J5ZaFn9VSU9gyDxdYHWCo0vA==@lfdr.de
X-Gm-Message-State: AOJu0YxDS8QjqD6QDJEwDYykKGyDrOnmoiXVbssRfQx1HD47MjS74Ov6
	ei/Do/0p+D8qMqpDnOGLh/1n3Hg6FBjAiehjZ4iIOYaUpD2NmGiGzu8r
X-Google-Smtp-Source: AGHT+IEcnJ0E356OXIv10g5ixCjdfSyukVGumnthAHJYbi5fT60M0FJWpNJkrPPxH3zZoi9nZH9Lpw==
X-Received: by 2002:a05:6000:24c6:b0:3b7:8d6f:9fe2 with SMTP id ffacd0b85a97d-3b78d6fa2a4mr2415202f8f.23.1753787494270;
        Tue, 29 Jul 2025 04:11:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdRaKEmEM7XvZ/gHW/4Nd/XSL00av6kCoxZYhz/tCxnQg==
Received: by 2002:a5d:5d07:0:b0:3a3:5e77:439d with SMTP id ffacd0b85a97d-3b76e3aa399ls2166015f8f.2.-pod-prod-01-eu;
 Tue, 29 Jul 2025 04:11:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzmI+l+3DlncA+fzusoORax12IHgUNbRtErppoNbUMiF2ZfycmpHRbpbqC4o+aMN41r/ElTzsJixc=@googlegroups.com
X-Received: by 2002:a5d:5d85:0:b0:3b7:8128:161 with SMTP id ffacd0b85a97d-3b781280f88mr7717112f8f.3.1753787491514;
        Tue, 29 Jul 2025 04:11:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753787491; cv=none;
        d=google.com; s=arc-20240605;
        b=C8bEhEbOxMVxfhryCasCf8/fSkj4PKJnmHyJgqnroDDh3SsW1Uu2/cq1wd9Du39C16
         TtIHpaQ2cwfx4++zJltPy2FDkWiZS/UbC2bDvqpvZmsvNOg5y2lMr6Xyr4ie+A/fNOpv
         FtbMPfNU1ltO4u3yPnJn02G/tOiherFOC34/wqrF92Wgq0xkxQmxJSoKYVq8fGMlX3JN
         CqSzRTKE1zsETc/nLs8QS3LtTSzDFqtwEZlJMX1lWO7cMgVMKYRMTxPqvPI9kqivJRsU
         Of9QyWYJ5Gltt2tfssPr4sTm+j/5EfM+IQDzMvD4IvKxzYH/aBWBaUhiBnBvv39Ot90R
         yohQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=geMEPUiSmJiNkIaRsYiTOZ0Li48P2NhVSHcF23entUk=;
        fh=huOT2BNMGN+takmBysYyzPZPS6e33m7SIcq/gYDhwMY=;
        b=iZYMbjnvMylgk+HpuMb2ztlZ+qes16PO8i7nXlGbsLq3SvzsXMiqXur5CHARX41FJf
         hIKExNqMGVhfybePiuwnNhmWzhNZlg+7ySo6f5B4d7Wb2PKNF75Dc9/b44DI2x2Qlwdl
         KU1zUa0d0Zid+UNd/ZsgSbvTtQCEZwIbq+hk87DnjujKh56UVxngXpiWOyQ9kK8JqBFZ
         Dd05i2cFSI8IoH9LU8WZh/2u4RijU0X+nmqnwSjQGX/kLRo7MpjWcxatLMBDo+uEuMvy
         OV6WS9X/u93w4SM1foplRMsSGZeqvz4cjddUoGF1urO6bFBQATut5QptyKAN1epXs1DR
         ylew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fu1R5p6x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45870556504si4467555e9.2.2025.07.29.04.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:11:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id 38308e7fff4ca-32b5931037eso44379991fa.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:11:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVmLC/QG0CmobIwkXRERg1p3i2+TMTUvVLMGhC1n4kgO9FAd5Mn1sOm4M49uJjTCRVxDx3T3yYWbto=@googlegroups.com
X-Gm-Gg: ASbGncvkDqTlL0BTVBBqYXFAVyL1r7Q0EKCFBj1dO+tmQ7+smadTzSpqGAm2dxaXeQN
	EkMnjk2BnP7HHsfJmYEq39s2WbjDnPyCMDAwMKSrFEYz0+QWYwnnEOpU/tZXwY2buTwqJUxbs0/
	6lP7o93PfcEFwVI+V1BHseV2myNeqzs2ax9U2xSWkf7WfJkLm/pRdF1RX6eDNTDZBdpyvGJb/ye
	8DNC99cBW7gs3KK4aMf0eWh4LfVBuNXqBrSgqwUquxglkBL
X-Received: by 2002:a2e:bea5:0:b0:32a:66e6:9ffe with SMTP id
 38308e7fff4ca-331ee7d3804mr47508031fa.21.1753787490459; Tue, 29 Jul 2025
 04:11:30 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-6-glider@google.com>
In-Reply-To: <20250728152548.3969143-6-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:11:16 +0200
X-Gm-Features: Ac12FXyE_yOxvtIZ9BhHw-sxSVPKEVbpNzROyHI24hsB_aKzQ2JBO_NoNNA7L-8
Message-ID: <CACT4Y+a5ZLpHEwd5LDK7oc8g9HgjsTbo6XgvEBTDBdqU8zCj8g@mail.gmail.com>
Subject: Re: [PATCH v3 05/10] kcov: x86: introduce CONFIG_KCOV_UNIQUE
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
 header.i=@google.com header.s=20230601 header.b=Fu1R5p6x;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> The new config switches coverage instrumentation to using
>   __sanitizer_cov_trace_pc_guard(u32 *guard)
> instead of
>   __sanitizer_cov_trace_pc(void)
>
> This relies on Clang's -fsanitize-coverage=trace-pc-guard flag [1].
>
> Each callback receives a unique 32-bit guard variable residing in .bss.
> Those guards can be used by kcov to deduplicate the coverage on the fly.
>
> As a first step, we make the new instrumentation mode 1:1 compatible
> with the old one.
>
> [1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
>
> Cc: x86@kernel.org
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


>
> ---
> v3:
>  - per Dmitry Vyukov's request, add better comments in
>    scripts/module.lds.S and lib/Kconfig.debug
>  - add -sanitizer-coverage-drop-ctors to scripts/Makefile.kcov
>    to drop the unwanted constructors emitting unsupported relocations
>  - merge the __sancov_guards section into .bss
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
>
> Change-Id: Iacb1e71fd061a82c2acadf2347bba4863b9aec39
> ---
>  arch/x86/Kconfig                  |  1 +
>  arch/x86/kernel/vmlinux.lds.S     |  1 +
>  include/asm-generic/vmlinux.lds.h | 13 ++++++-
>  include/linux/kcov.h              |  2 +
>  kernel/kcov.c                     | 61 +++++++++++++++++++++----------
>  lib/Kconfig.debug                 | 26 +++++++++++++
>  scripts/Makefile.kcov             |  7 ++++
>  scripts/module.lds.S              | 35 ++++++++++++++++++
>  tools/objtool/check.c             |  1 +
>  9 files changed, 126 insertions(+), 21 deletions(-)
>
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 8bed9030ad473..0533070d24fe7 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -94,6 +94,7 @@ config X86
>         select ARCH_HAS_FORTIFY_SOURCE
>         select ARCH_HAS_GCOV_PROFILE_ALL
>         select ARCH_HAS_KCOV                    if X86_64
> +       select ARCH_HAS_KCOV_UNIQUE             if X86_64
>         select ARCH_HAS_KERNEL_FPU_SUPPORT
>         select ARCH_HAS_MEM_ENCRYPT
>         select ARCH_HAS_MEMBARRIER_SYNC_CORE
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
> index 4fa0be732af10..52fe6539b9c91 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -372,6 +372,7 @@ SECTIONS
>                 . = ALIGN(PAGE_SIZE);
>                 *(BSS_MAIN)
>                 BSS_DECRYPTED
> +               BSS_SANCOV_GUARDS
>                 . = ALIGN(PAGE_SIZE);
>                 __bss_stop = .;
>         }
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index fa5f19b8d53a0..ee78328eecade 100644
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
> @@ -121,6 +122,16 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
>  #define SBSS_MAIN .sbss
>  #endif
>
> +#if defined(CONFIG_KCOV_UNIQUE)
> +/* BSS_SANCOV_GUARDS must be part of the .bss section so that it is zero-initialized. */
> +#define BSS_SANCOV_GUARDS                      \
> +       __start___sancov_guards = .;            \
> +       *(__sancov_guards);                     \
> +       __stop___sancov_guards = .;
> +#else
> +#define BSS_SANCOV_GUARDS
> +#endif
> +
>  /*
>   * GCC 4.5 and later have a 32 bytes section alignment for structures.
>   * Except GCC 4.9, that feels the need to align on 64 bytes.
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 2b3655c0f2278..2acccfa5ae9af 100644
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
> index 5170f367c8a1b..8154ac1c1622e 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -194,27 +194,15 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
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
> @@ -225,7 +213,40 @@ void notrace __sanitizer_cov_trace_pc(void)
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
> @@ -253,7 +274,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
> -               /* See comment in __sanitizer_cov_trace_pc(). */
> +               /* See comment in kcov_append_to_buffer(). */
>                 WRITE_ONCE(area[0], count + 1);
>                 barrier();
>                 area[start_index] = type;
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index ebe33181b6e6e..a7441f89465f3 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2153,6 +2153,12 @@ config ARCH_HAS_KCOV
>           build and run with CONFIG_KCOV. This typically requires
>           disabling instrumentation for some early boot code.
>
> +config CC_HAS_SANCOV_TRACE_PC
> +       def_bool $(cc-option,-fsanitize-coverage=trace-pc)
> +
> +config CC_HAS_SANCOV_TRACE_PC_GUARD
> +       def_bool $(cc-option,-fsanitize-coverage=trace-pc-guard)
> +
>  config KCOV
>         bool "Code coverage for fuzzing"
>         depends on ARCH_HAS_KCOV
> @@ -2166,6 +2172,26 @@ config KCOV
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
> +       bool "Enable unique program counter collection mode for KCOV"
> +       help
> +         This option enables KCOV's unique program counter (PC) collection mode,
> +         which deduplicates PCs on the fly when the KCOV_UNIQUE_ENABLE ioctl is
> +         used.
> +
> +         This significantly reduces the memory footprint for coverage data
> +         collection compared to trace mode, as it prevents the kernel from
> +         storing the same PC multiple times.
> +         Enabling this mode incurs a slight increase in kernel binary size.
> +
>  config KCOV_ENABLE_COMPARISONS
>         bool "Enable comparison operands collection by KCOV"
>         depends on KCOV
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 78305a84ba9d2..c3ad5504f5600 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -1,5 +1,12 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> +ifeq ($(CONFIG_KCOV_UNIQUE),y)
> +kcov-flags-y                                   += -fsanitize-coverage=trace-pc-guard
> +# Drop per-file constructors that -fsanitize-coverage=trace-pc-guard inserts by default.
> +# Kernel does not need them, and they may produce unknown relocations.
> +kcov-flags-y                                   += -mllvm -sanitizer-coverage-drop-ctors
> +else
>  kcov-flags-y                                   += -fsanitize-coverage=trace-pc
> +endif
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)   += -fsanitize-coverage=trace-cmp
>
>  kcov-rflags-y                                  += -Cpasses=sancov-module
> diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> index 450f1088d5fd3..17f36d5112c5d 100644
> --- a/scripts/module.lds.S
> +++ b/scripts/module.lds.S
> @@ -47,6 +47,7 @@ SECTIONS {
>         .bss : {
>                 *(.bss .bss.[0-9a-zA-Z_]*)
>                 *(.bss..L*)
> +               *(__sancov_guards)
>         }
>
>         .data : {
> @@ -64,6 +65,40 @@ SECTIONS {
>                 MOD_CODETAG_SECTIONS()
>         }
>  #endif
> +
> +#ifdef CONFIG_KCOV_UNIQUE
> +       /*
> +        * CONFIG_KCOV_UNIQUE creates COMDAT groups for instrumented functions,
> +        * which has the following consequences in the presence of
> +        * -ffunction-sections:
> +        *  - Separate .init.text and .exit.text sections in the modules are not
> +        *    merged together, which results in errors trying to create
> +        *    duplicate entries in /sys/module/MODNAME/sections/ at module load
> +        *    time.
> +        *  - Each function is placed in a separate .text.funcname section, so
> +        *    there is no .text section anymore. Collecting them together here
> +        *    has mostly aesthetic purpose, although some tools may be expecting
> +        *    it to be present.
> +        */
> +       .text : {
> +               *(.text .text.[0-9a-zA-Z_]*)
> +               *(.text..L*)
> +       }
> +       .init.text : {
> +               *(.init.text .init.text.[0-9a-zA-Z_]*)
> +               *(.init.text..L*)
> +       }
> +       .exit.text : {
> +               *(.exit.text .exit.text.[0-9a-zA-Z_]*)
> +               *(.exit.text..L*)
> +       }
> +       .bss : {
> +               *(.bss .bss.[0-9a-zA-Z_]*)
> +               *(.bss..L*)
> +               *(__sancov_guards)
> +       }
> +#endif
> +
>         MOD_SEPARATE_CODETAG_SECTIONS()
>  }
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 67d76f3a1dce5..60eb5faa27d28 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1156,6 +1156,7 @@ static const char *uaccess_safe_builtin[] = {
>         "write_comp_data",
>         "check_kcov_mode",
>         "__sanitizer_cov_trace_pc",
> +       "__sanitizer_cov_trace_pc_guard",
>         "__sanitizer_cov_trace_const_cmp1",
>         "__sanitizer_cov_trace_const_cmp2",
>         "__sanitizer_cov_trace_const_cmp4",
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba5ZLpHEwd5LDK7oc8g9HgjsTbo6XgvEBTDBdqU8zCj8g%40mail.gmail.com.
