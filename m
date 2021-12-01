Return-Path: <kasan-dev+bncBDV37XP3XYDRBANXT2GQMGQEWMRXBWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C0364465237
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 16:57:53 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 83-20020a2e0556000000b00218db3260bdsf8817072ljf.9
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 07:57:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638374273; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2ik6NJwrxrXvUVVw+mTu2fFX7d7fcAHXtb19EdWzwGzPLSpW0uC8yWdiUEVLVeDw4
         qJosE+Xjh45Rnm7AUYjHPQAK3HfcMDAtWXCJ97TcVz0IGDJbH+qnBVs15fYpcpup07sH
         /4wJ8kWFM3PjQn+UvBfNXymD68nfthRwgVqGEIUi4RcdtQnPXmVSgH4hhXLSFRm/GtMo
         TKoPCOOSN/Nl6/UVyrAG0M9d0pMlJY1Vk15IJNtPNFQYxMb9fItdHLq21yM+rSbGLrxO
         9Qv6mbW2snrw4hiHnd4bgfacuEitF2wZbr2yIzZusZ03X+v70beZlfzmQAgx4A2vLXIm
         uIBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UZen73kjkopMRbzqelaVDLMBPvcRBRVX/a0lHSMI1zo=;
        b=dI7PKVu5Tm/k8LzLcmukT2BaXj9l0gWQEi84MH6Y85vfRS8cYriOdYOwZ0QgDJ5qnL
         s+8QeQq/V3CTg2+gIxrR5DlrPzyo1rbPIDBn6wnlwRNKDu07ezTC2FXtq56LHPUbbzW6
         zBCIdGFivdfCKx8sZP3/rgiexe2FB8OijQYo+rGT9eiOvDkmAo5dRjl/MiS5Eb06Znkw
         u/g0FkI1HliX+xcjbHPxZk9+xgYhTWEkSLv9T7jO578mL7DOM53coRNfgj1El0Txa58Q
         SyzXKkQinp4xK6Ba1/YRQ2vqQdpnBZekdhIxGKqS4CydKxT36pkeg/Revq5ru8gaI9Wp
         FuNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UZen73kjkopMRbzqelaVDLMBPvcRBRVX/a0lHSMI1zo=;
        b=IYO2Msnjd9Aoc5XuZGDxjYEmqXpHAphp1grJ9z8ESFlmBHcK/fU6uf7k2vYBOsnXkR
         MwoZnupkKcHcVERYb9r4rl+JzCYfoOONPJBPKjAgF8dwbRUYGMhd0lsXOuVgUyw5BOIx
         zZxbC2u073EkhdKmq0+ddnoI4XKxWhQXZYff2CVsokeFFqVuR/4BMYLQqK+3DEwTxQFB
         EZN6T0AyLX6ZsyALudf+HNJP80Na9gIzVmnIv8v9mb/iU+aIL9MbIjSoPUAVCOOA3SbR
         8e9hb2qLVmTiUrwPjEUBskarnevA18UdqjL/LqIf22xMOznYUmC8acc6jtp+PjAJt0C4
         nGsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UZen73kjkopMRbzqelaVDLMBPvcRBRVX/a0lHSMI1zo=;
        b=bagABQhg8viWsjv9XGd0/0lGRNRLAwVcVgRIiFh11sIJitsa88iT4lDBQ7k3R70a+0
         oJcX0Hs5QmazhBMqrfIvyCudo57UGfoLxkNUbnFexcjnYqCzkehhOF7hLNjLi2Ys9FwA
         RLsvxxge2ABfdWCf6sefjgBoyLF2I/m/u6qVnpHMJ6BtR2o51Hpji2FNE23bEiQa6Z7l
         eWrEZnyTgWe8Iv3uuKFCpElcmhY/LFW++2KesJEtjU7Gyhw1DuHRjlq18YysIQVGWlzV
         BDImx+gxume4uwnwnOZVJRuRTm9nT04X6f8lRvBdML0XjNOUaUxxG6Fm3VmfBaZKK8s0
         LT/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oRXXiEmVlK4H/xI7/ZDMC2edbTC2bI2/Mg+CMcnXMKE3VwQp1
	SuPHXSbgIF9+wRpE3XEMY8w=
X-Google-Smtp-Source: ABdhPJz3hrr54LYuHZ6t7VXfSR2w0JzU9/U/NTdiVop8Ooidz1T1076xWbTqSCZdz2kxI7bihaXGbA==
X-Received: by 2002:a2e:9699:: with SMTP id q25mr6480289lji.6.1638374273354;
        Wed, 01 Dec 2021 07:57:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls479288ljr.0.gmail; Wed, 01
 Dec 2021 07:57:52 -0800 (PST)
X-Received: by 2002:a2e:a78e:: with SMTP id c14mr6694163ljf.162.1638374272233;
        Wed, 01 Dec 2021 07:57:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638374272; cv=none;
        d=google.com; s=arc-20160816;
        b=aY1mrmE2JTDCiI3lfKu28QqiSvX0cI1DjQVwlFBLfhn6JiCAEyhkik2GcqLAb/besT
         aih2sXXUoT9ymZMJUERhxIpxtGpdkJcUjF7T5K77Fpib6T83hGCqttoe4MmoaDztPuZR
         3vs7jznyxw7OpWSfYPUBthmIiPBQg3IXxvXVeM7wlIlFzCOZ8sqcx/+JekWDlb0CAJBS
         hQJ8/y+wjno0jHXE+fllJ5K6xutcO7enR9bNUD4Y4um83luquOqmae6Ow8QXPOHWIO7Z
         ezBG9detYqrWLdFmvdALzrM5IAzs1nrYJS/GHqZVNR91qvRf6cuLxotkd+RslLHuq4qS
         Ywwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=WJR0/oQFXBt5MkH/8lm0rV2gXlrgEecB/Tq/qkNnVBY=;
        b=eD8LlZry66clSOpRa+FPVl2a5spyYeVrGh8veDzwYxMnV3lIvUhyvplisJVp+6+ERd
         /GGgyzDPsY9B8G9kwd8ohvgf2QJaxSm93N4CRg71yVb+s4LZtkhWIVKXDBHKX4HxcZXm
         TM6SGe6Yqkv6h8348v4/77PsylT1AnomyEn5wP0FVmM/Wmaysv5qjtpYLN5zkNA5aFUX
         Nd/sBNZCL1WKmaIZsPfTvsA++z3UIU5aEdrVdfabc05gfk4EbG4+wW2JamMa76RZFkOR
         TQ06ux8EpLNh2szN0LHEmvQfT9ov5GtP90yALGKjZIsGv8pwB+anHC69VFACd9rliP2B
         wp2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b9si14718lji.2.2021.12.01.07.57.51
        for <kasan-dev@googlegroups.com>;
        Wed, 01 Dec 2021 07:57:52 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C397C143B;
	Wed,  1 Dec 2021 07:57:50 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.65.205])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 254243F766;
	Wed,  1 Dec 2021 07:57:48 -0800 (PST)
Date: Wed, 1 Dec 2021 15:57:45 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
References: <20211201152604.3984495-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211201152604.3984495-1-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Marco,

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

I agree this is the right thing to do, but since GCC 12.0 isn't out yet (and
only x86 has objtool atm) this will prevent using KCOV with a released GCC on
arm64 and s390, which would be unfortunate for Syzkaller.

AFAICT the relevant GCC commit is:

   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689

Currently we mostly get away with disabling KCOV for while compilation units,
so maybe it's worth waiting for the GCC 12.0 release, and restricting things
once that's out?

Thanks,
Mark.

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
>  	select DEBUG_FS
>  	select GCC_PLUGIN_SANCOV if !CC_HAS_SANCOV_TRACE_PC
>  	help
> -- 
> 2.34.0.rc2.393.gf8c9666880-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaebeW5uYWFsDD8W%40FVFF77S0Q05N.
