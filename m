Return-Path: <kasan-dev+bncBCV5TUXXRUIBBT4FUSGQMGQETOJNVIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 793A146691C
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:30:55 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id y4-20020adfd084000000b00186b16950f3sf36328wrh.14
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:30:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638466255; cv=pass;
        d=google.com; s=arc-20160816;
        b=MpldveQUDNCNzDn+dmjcFOLp+INIheP2A1RgIpGKyTvPoOD+RQpnYcvSh/k6I/MRHl
         AIn/YDMbuv0TeF2e4eaN0+GngDufNIQZXbXU+1aYHLwSfg2JqqCOhq593ZWKtR/7Wp8Z
         SJ1SCz4zOVhzBy/z/xCayKtx80dtGIw+p/W6VRJe9CsB6b2FTmm08D0E1MOMn6NSs5Pn
         rK/p+ASzgxT70+bNn0i/Gc5eESETUE25OPXoMLVgM71UejPE/UXf+8kXYY5LZSoPD811
         uKFHT8MiwLTSNNmgrFFs0HflNU+yIrgMcTXGNIGybzY5oahu7erMt1xDByn/CvqccS9X
         3Z6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TCEwNnO0+XnbpeNENLXfyFgmxCVtfDWYTzALuqXh18I=;
        b=BTxavtTeFMCPxKiJCmHa4fXp/fXANAHDx3UpjFi54gtIgzBI+m6qED67M7JvlNiIZi
         p5MYKsVGf3hahs/ElL2PreOi0Td9554kGm0SEHqsjf8fjEyVeukFF6c3yTEMQDqxv9Mi
         ZgRDcHLt+1FEOR6lbJseO9IclD3mhKwgBSKYyI7JitSKd2NYV5NLjMttLlp7irMFzNPA
         D6QwTupQPnqFdm/MbHGTMa6vP0t1jo2jGiJzECrO2IW6xAMcATNrYhnSWz/h63zJ9iyT
         iBeDsgpmJTs/QR15xFSE/2zkCNcXQxypI46+K0CSOsAC1I0hz69q5x+AGj82mZ9aHwHD
         sPDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=oQbE09Pq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TCEwNnO0+XnbpeNENLXfyFgmxCVtfDWYTzALuqXh18I=;
        b=aawCVt0nSO0i5GXrJtB7YGcvQ5+UTooZANe933asXrDs99r4OLvD+t8KJT5a/RqjYG
         p4HPYXb/qYa8+D67wkvI/W0JHKcpp/UcfT7CLzP4IUejeva51i5+jF1/LQyg6A8Okrv5
         I79IhBsDQp5eQVKCKgnxp16ub2ii2RjDSgoiSA8AH2baTw0IDphC79i/A/Ggyml9ah0V
         oBwItk4yg5frELYUETCChaXkONvF1517aDYe82rmybUGPKwsI9tfH0G1skHLmd3RSqOK
         Pv2F1vPTFn42vU2bn60wzCODUP8FGGkQrJMG/4V1WuN30CAYI0Jyh0x7IOJoSxSeyldC
         2flQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TCEwNnO0+XnbpeNENLXfyFgmxCVtfDWYTzALuqXh18I=;
        b=Xh5yHxl2mmIWXFfvYygLQbznzo+Fk54YjjV7J52kXCL5byEVqrUeA/gDsfYgSJ/BoT
         +wF93utv+5pRtaTMqtmI8MYs53kGwyO1hGh+ydPVjQRdtHV6xEIFoaWsMshpEQj6b+Y4
         nTnhpcj/rAXXOPZQtWoqnQf8kVPvdCHpiA2C/yivlc0yNEqhB7rIX0+0gyaMCLcLZfao
         6dE/x+P9Y0aqBGDWHK+6TqPaUtdKhtwlpa/eXO4kKg7UxXXu3tmo/s3YKgV/2D1amx0n
         Fp8Apdh2i+GuodcCKR7rDDEUJNeUnXg0MiaPtfeShggCGDn141bAIOJpa99a8TB6TAQO
         d1fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZLbqPeQNMOOii9zQMPicsceGtDuBM4gA8KJ46F7UDQyZYPpDB
	HikysexxhaXoGHMVdqW+9SI=
X-Google-Smtp-Source: ABdhPJyvTP8jx7iOt10vbJhDJLVzFOPntH0diS6LKe1tOpEJgXSRzUtbAXUW7A+aqLjJv8Qwo09DeQ==
X-Received: by 2002:adf:edc6:: with SMTP id v6mr15873367wro.461.1638466255199;
        Thu, 02 Dec 2021 09:30:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls3322134wmd.2.gmail; Thu, 02
 Dec 2021 09:30:54 -0800 (PST)
X-Received: by 2002:a1c:1c8:: with SMTP id 191mr7912836wmb.90.1638466254313;
        Thu, 02 Dec 2021 09:30:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638466254; cv=none;
        d=google.com; s=arc-20160816;
        b=psUh/9IH55wZ3QJGOw3hq2/QGAItv0r3zNVs+GqOerA+IC+Wr+uqNBnSVzVWX8kO2/
         zxAAgyrjKTAJoNA2Ib51V3TLt+pT4RgOnyg6YhVfa4GwfEZrKsrOzrv1Yco08HgUyVEQ
         ThA4vztGP3m1X6ADoeVInnPz0AXboWPGcBNuI6bw62dgp1HpyYNXpQIrPAuc0TSoGK1j
         1o85EOUR5V5rdTK56xn2feJCs/Rk97xV5+kEH5Y3dRZHYilqnpWxgi+X8hUcq5mWYacz
         WZtBrBU3Z6f9EQGUmeRGFO47FDrIQg62dCgjFTxKpVQ0JZXSYuPpU5ldvL6HsqhQfFkL
         Ta1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8y2oxAvRHeBlCuC/BEwUyt1WOm4Rdt3hzU8cM2cFMjk=;
        b=rcTaehn1sQ3pyxu4oCqHmBekWXz1Zdb04Bt2hreVQv1ue55Fs2ZYPASLabN/3Rjidk
         7QbAEl3l5rxWU1PI20keoQhOj0Mx0F0QBNUObLphSdv3R+WXxlwVa54vV/exPVW8E22m
         AxEoxGoC02vNkQCloQzaS/o//Fma22Tbr8tfczrphCDLw20xxolNz/pDLiNVBqFoJSbr
         mdIQxSyESez03gY9jEDrjYZqvKybKS/r+5VxrouMGVBWPg2MIeyeqUzuQBiXcRUCmExY
         e6+1hKwfKrupJf9j7mr2FoYdlBpP4KJ2K9dCTm+T5HgZSagtJD3Rm47CVSC2zME1D0ES
         ZQqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=oQbE09Pq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c2si482408wmq.2.2021.12.02.09.30.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 09:30:54 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mspuv-004vAd-Nb; Thu, 02 Dec 2021 17:30:46 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CA20E300792;
	Thu,  2 Dec 2021 18:30:45 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0453A200F8FF5; Thu,  2 Dec 2021 15:50:31 +0100 (CET)
Date: Thu, 2 Dec 2021 15:50:31 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <YajdN5T8vi2ZzP3D@hirez.programming.kicks-ass.net>
References: <20211201152604.3984495-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201152604.3984495-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=oQbE09Pq;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Can we write that as something like:

	$(cc-attribute,__no_sanitize_coverage)

instead? Other than that, yes totally.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YajdN5T8vi2ZzP3D%40hirez.programming.kicks-ass.net.
