Return-Path: <kasan-dev+bncBD4NDKWHQYDRB7W3T2GQMGQE7GNMFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id C7D5F4653C0
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 18:16:47 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id v20-20020a25fc14000000b005c2109e5ad1sf36833303ybd.9
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 09:16:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638379006; cv=pass;
        d=google.com; s=arc-20160816;
        b=KUXFd3wTZ26nm7mjERMU0eQ6xnlWUMMJxDtImcyyYHjNS6oTGsRSY/zZpPvT8gvLXY
         x1WE85D53c8m4jZEdLncEiMOjdI2NJCZfTVY/aMd77F6FuOpcO9O945Lzfs6/gaOii1F
         WY8narSw+c73JC841dwpOmH/R7CuWtQ+060M1SChzJ2f20Vp0j+JhOt22aEuX6nfgn4/
         B3roj4paYikHjfJ6D6Eomu/fAhrjCEfhlMc/UYN/NtkgK92GyfghXdG7HcswcMUB+Jgh
         jN6ccAsrn04IwhH92n6dc5/IoYUEIoBZj84/qhUOMG5ilCvM9eflHwIS8n5y5dfE+Nqt
         D3eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eAXty5tPaDcv9Uy6obsl0isf+YWTpuFfunA+Bhsrudw=;
        b=m5pOOQy2oQ/06B8HI39p09UmNWmwS29ANRCYzISTdiY/lwVUXlUFdoxU3C7Nutqku+
         7A6mGkbI6G6A1QIuE5VySbJnxo7FxNTlZIxNiQB0zd03H/20RIfPByzylKAELxsm9x0M
         JXrjwu+upW3aIDMtiU9/vJMGPkiIQhxvUY3vS+caMLfwNvjEsuRufVEH77NiuAI8hzPd
         eHT8BCAkXbsvmaVHKAyGms8D3ud17lGoIwh8FxYqs/CocVNUVT1tNIrAM5XpDd71HBfL
         eVfqnFbcRaJ9aV5C3/OSF9hj5Fh+MHXTYNfyQtELynmRKGnAz928EM4eEVa37H7aK7ZD
         ghWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dkBZyK01;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eAXty5tPaDcv9Uy6obsl0isf+YWTpuFfunA+Bhsrudw=;
        b=Rib397J4R+zzURXoohX2ceKe5BsN/9UFWHewHhV7JjaULLwvv+XqjvRKEhHsMZXetn
         MNjN+tU5LWwbJBjHZPP62Z86JxHjegoZv+fLY1dgy86Cj0vM0txQ+LBJGdq5NeMgabiC
         L9qWXfcFeTF6Ok63LZYcO4FlR7MH7T46F4Oi8ZgdKuxmoTFb2qxbJ/PuZj0t9NBh6Yj2
         OWGxU6M5zJXKV+pVXeXWRAtqxJd1R6SIRlblqh40sgOvveAqEZw86LF+4gn0DLukH4BZ
         jrGdg3Jp879FDccIOKuej+eG8+MuOFbkMUDEjOTni3VlCQLq2t1vy0YgdxkktvWhECRJ
         WqVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eAXty5tPaDcv9Uy6obsl0isf+YWTpuFfunA+Bhsrudw=;
        b=L/VY7r6dn9feKKmCocrnaX2gmxLiYPWSE9hpbVRuFOMeQHnmp1/Tdng8C+ZCWzOluT
         GEFOX1E+GZ8qoDCuOM3c9arO6WCtTdsN/GdGNK0g6n3wmAR0StAyHm5ve2GBNYKkS6lw
         xN+E+p7uq5dDX5CTXB0BVGt6IJNde6WB7MFaJ7Ag3aCt51B/Z/36jOgrgWVKGSMkJIHP
         gGHUx4OicmkZUHgutyEodyj49MXHof85y2uIv2hyZ5QB8MI3nRXwMNKpJvkEfbpDyyOo
         gL67nG0eyKWYWhfLPjZ0+ifbUQxrlUof5xeQiJ60QWEhMnQZhzk3jSMqO3KQL4MZ9M77
         EwPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NnslZAEwO05X12P//PJ71w/4K/9y/R15UfpiE1qNyXNkiUAPH
	zeVz7dB6pFHl21zbdKXy1Zk=
X-Google-Smtp-Source: ABdhPJwZ5mgByEQfjChehO0xm1ywZ98B/+tgzAumr16AEbIhPTTqdvb/8a7Xf4qQLo5dohz/06osVw==
X-Received: by 2002:a25:cecf:: with SMTP id x198mr8895711ybe.430.1638379006678;
        Wed, 01 Dec 2021 09:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a94:: with SMTP id q142ls2655011ybq.7.gmail; Wed, 01
 Dec 2021 09:16:46 -0800 (PST)
X-Received: by 2002:a25:1854:: with SMTP id 81mr8589468yby.671.1638379006210;
        Wed, 01 Dec 2021 09:16:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638379006; cv=none;
        d=google.com; s=arc-20160816;
        b=j8Gqx2/I/lVa/QcfS8/rQnUPosMTWmuo6GMMNiW96rV9po4FU/wybhgI2+NWd+qZpf
         pbhiw6qFVpb7SRI+tBZI5IZwJWsu2V63nr8RR4D+eFLY8fzEsClqOAl9xQK153ZfNq9s
         RFApRRMXJYA1VabbHbWE4W5t6lb4Q4QHGHhKWu2ccHamV4Hd5aXqI3RwMg0xkgwdpR8+
         B73xHJrzLZ0r+ahPIJIkzIdfhTLDjULRIfg6LU4cH3mkwa0t1apnWlkln5JnGvrm3NRH
         11N9c6BOzRPYCecFU/W5I9qDJekUU+nUKZ7U65BZuJzSZBzKTcEFr3+m7NcnhEfoBg4i
         3GLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/ybpHhQK/dVXFjX/nEtgI3iV1+8fk2hSvttf+AfNMqI=;
        b=GJpYtsVRkvtej0XDVaiMr+AD/ofdklAsRem82yIAB9z8HofHRWYjxJ15UULX73pbH8
         uBo1+AwlGeQBUWjJ+jGSAVWZPY8f/bkKQ1Iys31KEQI9hACbNoGerrn/aWMH7Lmdk0YT
         lNSACU9J2DVGyrwkBFRPut7VWUrhf6Jev8wzHQcCB+laWEYyPWwUYQqDtDzT73dk8i8j
         f+RoLfCCiy7zZrJJdlL2yTzhqdjL6X6sSqF4w+J2iaGKesAsweT+iGGJ8D3g5MVKypuH
         sl9zbcg2EuQkl6Vpk6jR72xarevjRPN9kbKEj3VOITDbhqqmSrn+taoZ6tj0WEUuMs9u
         DFxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dkBZyK01;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id a38si45497ybi.4.2021.12.01.09.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Dec 2021 09:16:46 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 74A27CE1FF7;
	Wed,  1 Dec 2021 17:16:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F2980C53FCC;
	Wed,  1 Dec 2021 17:16:38 +0000 (UTC)
Date: Wed, 1 Dec 2021 10:16:35 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <Yaet8x/1WYiADlPh@archlinux-ax161>
References: <20211201152604.3984495-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201152604.3984495-1-elver@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dkBZyK01;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Dec 01, 2021 at 04:26:04PM +0100, Marco Elver wrote:
> Until recent versions of GCC and Clang, it was not possible to disable
> KCOV instrumentation via a function attribute. The relevant function
> attribute was introduced in 540540d06e9d9 ("kcov: add
> __no_sanitize_coverage to fix noinstr for all architectures").
> 
> x86 was the first architecture to want a working noinstr, and at the
> time no compiler support for the attribute existed yet. Therefore,
> 0f1441b44e823 ("objtool: Fix noinstr vs KCOV") introduced the ability to
> NOP __sanitizer_cov_*() calls in .noinstr.text.
> 
> However, this doesn't work for other architectures like arm64 and s390
> that want a working noinstr per ARCH_WANTS_NO_INSTR.
> 
> At the time of 0f1441b44e823, we didn't yet have ARCH_WANTS_NO_INSTR,
> but now we can move the Kconfig dependency checks to the generic KCOV
> option. KCOV will be available if:
> 
> 	- architecture does not care about noinstr, OR
> 	- we have objtool support (like on x86), OR
> 	- GCC is 12.0 or newer, OR
> 	- Clang is 13.0 or newer.
> 
> Signed-off-by: Marco Elver <elver@google.com>

It might have been nice to do a feature check in Kconfig like we do in
compiler-{clang,gcc}.h but I assume it's highly unlikely that the GCC
change would get backported (and it obviously won't for clang because
older versions are not supported) plus the attributes are different
between clang and GCC.

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
>  arch/x86/Kconfig  | 2 +-
>  lib/Kconfig.debug | 2 ++
>  2 files changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 95dd1ee01546..c030b2ee93b3 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -78,7 +78,7 @@ config X86
>  	select ARCH_HAS_FILTER_PGPROT
>  	select ARCH_HAS_FORTIFY_SOURCE
>  	select ARCH_HAS_GCOV_PROFILE_ALL
> -	select ARCH_HAS_KCOV			if X86_64 && STACK_VALIDATION
> +	select ARCH_HAS_KCOV			if X86_64
>  	select ARCH_HAS_MEM_ENCRYPT
>  	select ARCH_HAS_MEMBARRIER_SYNC_CORE
>  	select ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 9ef7ce18b4f5..589c8aaa2d5b 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1977,6 +1977,8 @@ config KCOV
>  	bool "Code coverage for fuzzing"
>  	depends on ARCH_HAS_KCOV
>  	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> +	depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION || \
> +		   GCC_VERSION >= 120000 || CLANG_VERSION >= 130000
>  	select DEBUG_FS
>  	select GCC_PLUGIN_SANCOV if !CC_HAS_SANCOV_TRACE_PC
>  	help
> -- 
> 2.34.0.rc2.393.gf8c9666880-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yaet8x/1WYiADlPh%40archlinux-ax161.
