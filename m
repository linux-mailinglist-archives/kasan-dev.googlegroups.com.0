Return-Path: <kasan-dev+bncBD4NDKWHQYDRB27T2CHQMGQEABNXZJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B0AF4A004B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 19:46:04 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id g11-20020a2e390b000000b0023679b779d9sf2844219lja.5
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 10:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643395564; cv=pass;
        d=google.com; s=arc-20160816;
        b=ysSp9BmyanwYF11oFR+wTZs8uUxX/GDyTkT7IRarwml4gkc+GRNM7kERjcaqQLrH7+
         oj9tcfK5grB8jyfKEmnerb4wmn9tibRzLQ9KNeBIp2MljNQqLJA9SPo5Z8XTUOw4x+u+
         fMQV/MbQQzSkKQjrOaE8zPKS8JaULhTPJeFb8Tl6fHWIsd+YV91QosF299TAHXTHnDh5
         jV+NL3EAQkUmHjR2a9Los8lcTxdzuQIJzSrMMBJzfYx8vRwCZhb5Dsv5J/eILyZIDPXd
         GP6vLJ4CKfu4ITLZTQ93dOTkLz0wy8VQOkK7fw63Flydno1tA1ma0N+eaR0gWAoDA5bE
         bgaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=H3VoGd0mwVltH0o2g56qoURfnmzmtcwHP2qMZyU3f4E=;
        b=YToyVUXHLtsDjHEJPeRhK8mFam+DOLQ43F52+U567+SCu2UhayVxUyoRsUxQg86iN3
         5cSBVLx4zq7WkczQkKMih4EGy2F+3Nixs9vQV1mlTaW/xMJX/TXd81BXfm877PlC2EtH
         wVvrKEXEe+pD38mWnRyiH2VRIkoAfHyUrQKPrWww743Y26KZztFTcli5oLfljduQOLJm
         p/nK37DC9E/TklASWImmx+ikEs7yMyBBEP/Nw57hWnz/f+qndwU1ikCLuEgspb0oiuZj
         VNynb0sHpVCBGvg+GibY7wfaEUeMP+6h0IViotGNbX8q7RxXHPThGqHtyXv/8UoZDtSk
         JOSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bbUpNxC2;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H3VoGd0mwVltH0o2g56qoURfnmzmtcwHP2qMZyU3f4E=;
        b=HMPCiieqaiJNaFizpxRyuzk1DgJgbiBxX+Yh/txtjK4tGuCUmLepyetlvqNcbfUmcv
         ma+9t2tVD1cijyURVtC0dJ8HC5I3iDxSToeb9h4xkqZhZM6evPAJtw5KeBsJiqZud+u9
         GO7jOYbc6Jd2fTKAPaR3oK+PRG3KT0iHS0l9Rwx4tg01jRSfuqA3mZxTJzXSHUnN24ZG
         gu09pLzbExrzV+QVHqN//BIlflO2uodv0QZitd4QTI7wUhiTm9zpeUjI2BBASlIdDEzT
         +bYIo9n4A5M8LOkZ4HB0n/z6Ugkh0DMOcNRQTSQrsowanKcHQfe6FTcvAYimVHVh9X9r
         JfDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H3VoGd0mwVltH0o2g56qoURfnmzmtcwHP2qMZyU3f4E=;
        b=NdO5hUggUOjkhTWU0oZx4zEuW0eL4YQfPQXm+dNp62P+sT9Up9brxDJhJ8nQW+pt1s
         4sSLlSzBOIDCu731XtdCBfEb7cDN9adiAJOKSmSlB7aYcHKC0t6D2cjjcMKc3EY2EFkB
         cu/SCafqTKCyzXK/1cdXkKR72vvPlBBzzcRaYOyNsf7WGIKWAGh383loL9ewzYmDBmT4
         Kjue4YXA1R1x1AJIMjbgP/LiFYHl3WfSBY8G97h7ZmIC0rNP+xnDPjCGeJ/hvRA7M8yM
         YUhf7S4lxSk4UmvstSclJeduc/85MmidzZy3DO05d6500YEwvvhTHpCFIcPgQ678vW10
         5RlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ry56gdg99JdFHRAxn5PPXgrNdOPPP91dTB6i9CCNUyjorHFss
	cbss1L/RhiH77cB3iU/y4SQ=
X-Google-Smtp-Source: ABdhPJxCIxstGEAsXbSNl8eWWRMEuvp9oxKvN06kiJkw313wuSKv6hC36pHFcd5brQ66X/WmvnfqhA==
X-Received: by 2002:a2e:2e16:: with SMTP id u22mr6513124lju.205.1643395563878;
        Fri, 28 Jan 2022 10:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1599:: with SMTP id bp25ls341206lfb.0.gmail; Fri,
 28 Jan 2022 10:46:02 -0800 (PST)
X-Received: by 2002:ac2:5dc3:: with SMTP id x3mr6993390lfq.73.1643395562872;
        Fri, 28 Jan 2022 10:46:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643395562; cv=none;
        d=google.com; s=arc-20160816;
        b=NSiNwHo0p/fORb8lwR0/bBWxElWgmZN/HMYq/sMfAo8rG0aWlC00KU6NnUJSOqcIgu
         ZjI/upPmyvHeGOars6ixVAmjO6VZM5Wgxr5ZG9Hk9iFCHOJL/kZpAw5urQVb+E351t5q
         ElRww9ENPZs9dlITE95SbIZh+UkGPWz/ciRH5AFqsCV1MaDXnmskb8mnqN50wt6yLk5m
         IglGuPkJqoX5XU6zmd+1UZLt9iGO9YTWR1yx3GAmh4LaOXVpWY9HLq3//CDyg3X9wE5l
         cdtuBEeCZ+Amqfm3UqddIz2WqEPM+90zPLgk6fWvBG4Iy9dkTPFztjQ+z/K0BhC9/sny
         3y4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YwLM5LLsvNIv509ATUMaoBoNHSGTOlpO9PFSlugm/sQ=;
        b=uKrOwLLtaql9YohWpjUZyMfHu0cdemEuA8Uadnqv9Mzv9lQombuASH2+9c8zweqW8o
         6D3Y2oVvvrA2qk/O4gVFtozUxHeK9bfKRqncfb/QnR0jyl+JpHpEcw07ExCC0iL/ew1o
         leQzxOmoqxqL/7q5wAcUhH3Eb4UCbW3EjXf8fJOGmivB2m3AjMTLamMVEdkNgnpz6+W+
         f8mYtabsHx0XwUbVB3A2r0JelAsy6g0PTF9EJIAU+TgA1PD99w+69Cq7feyVPyJE653K
         8f2K8tE58IBbVV89woDzDBGmXLa6TWSd+OSO3W28O9EFaDgXHrcAK+rudWnwNllftbF6
         CQ5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bbUpNxC2;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id o24si294570lfb.1.2022.01.28.10.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jan 2022 10:46:02 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 288FEB825E4;
	Fri, 28 Jan 2022 18:46:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF8B3C340E6;
	Fri, 28 Jan 2022 18:45:58 +0000 (UTC)
Date: Fri, 28 Jan 2022 11:45:55 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
Message-ID: <YfQ54x8zglPT/YnL@dev-arch.archlinux-ax161>
References: <20220128114446.740575-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220128114446.740575-1-elver@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bbUpNxC2;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as
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

On Fri, Jan 28, 2022 at 12:44:45PM +0100, Marco Elver wrote:
> The randomize_kstack_offset feature is unconditionally compiled in when
> the architecture supports it.
> 
> To add constraints on compiler versions, we require a dedicated Kconfig
> variable. Therefore, introduce RANDOMIZE_KSTACK_OFFSET.
> 
> Furthermore, this option is now also configurable by EXPERT kernels:
> while the feature is supposed to have zero performance overhead when
> disabled, due to its use of static branches, there are few cases where
> giving a distribution the option to disable the feature entirely makes
> sense. For example, in very resource constrained environments, which
> would never enable the feature to begin with, in which case the
> additional kernel code size increase would be redundant.
> 
> Signed-off-by: Marco Elver <elver@google.com>

From a Kconfig perspective:

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
>  arch/Kconfig                     | 23 ++++++++++++++++++-----
>  include/linux/randomize_kstack.h |  5 +++++
>  init/main.c                      |  2 +-
>  3 files changed, 24 insertions(+), 6 deletions(-)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 678a80713b21..2cde48d9b77c 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -1159,16 +1159,29 @@ config HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
>  	  to the compiler, so it will attempt to add canary checks regardless
>  	  of the static branch state.
>  
> -config RANDOMIZE_KSTACK_OFFSET_DEFAULT
> -	bool "Randomize kernel stack offset on syscall entry"
> +config RANDOMIZE_KSTACK_OFFSET
> +	bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
> +	default y
>  	depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
>  	help
>  	  The kernel stack offset can be randomized (after pt_regs) by
>  	  roughly 5 bits of entropy, frustrating memory corruption
>  	  attacks that depend on stack address determinism or
> -	  cross-syscall address exposures. This feature is controlled
> -	  by kernel boot param "randomize_kstack_offset=on/off", and this
> -	  config chooses the default boot state.
> +	  cross-syscall address exposures.
> +
> +	  The feature is controlled via the "randomize_kstack_offset=on/off"
> +	  kernel boot param, and if turned off has zero overhead due to its use
> +	  of static branches (see JUMP_LABEL).
> +
> +	  If unsure, say Y.
> +
> +config RANDOMIZE_KSTACK_OFFSET_DEFAULT
> +	bool "Default state of kernel stack offset randomization"
> +	depends on RANDOMIZE_KSTACK_OFFSET
> +	help
> +	  Kernel stack offset randomization is controlled by kernel boot param
> +	  "randomize_kstack_offset=on/off", and this config chooses the default
> +	  boot state.
>  
>  config ARCH_OPTIONAL_KERNEL_RWX
>  	def_bool n
> diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
> index bebc911161b6..91f1b990a3c3 100644
> --- a/include/linux/randomize_kstack.h
> +++ b/include/linux/randomize_kstack.h
> @@ -2,6 +2,7 @@
>  #ifndef _LINUX_RANDOMIZE_KSTACK_H
>  #define _LINUX_RANDOMIZE_KSTACK_H
>  
> +#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
>  #include <linux/kernel.h>
>  #include <linux/jump_label.h>
>  #include <linux/percpu-defs.h>
> @@ -50,5 +51,9 @@ void *__builtin_alloca(size_t size);
>  		raw_cpu_write(kstack_offset, offset);			\
>  	}								\
>  } while (0)
> +#else /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
> +#define add_random_kstack_offset()		do { } while (0)
> +#define choose_random_kstack_offset(rand)	do { } while (0)
> +#endif /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
>  
>  #endif
> diff --git a/init/main.c b/init/main.c
> index 65fa2e41a9c0..560f45c27ffe 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -853,7 +853,7 @@ static void __init mm_init(void)
>  	pti_init();
>  }
>  
> -#ifdef CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
> +#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
>  DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
>  			   randomize_kstack_offset);
>  DEFINE_PER_CPU(u32, kstack_offset);
> -- 
> 2.35.0.rc0.227.g00780c9af4-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YfQ54x8zglPT/YnL%40dev-arch.archlinux-ax161.
