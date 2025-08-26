Return-Path: <kasan-dev+bncBDDL3KWR4EBRBI4ZXDCQMGQEJQ6Q5KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC585B37335
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 21:36:05 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-76e2ea9366asf5411494b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 12:36:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756236963; cv=pass;
        d=google.com; s=arc-20240605;
        b=cFbPtfGs5TI8Vep/upJzd2SgfU+MY3CqV64Hx5q6ahKdtjrCwQubIpWtAGLoafsmIq
         1IQYSzdUwr75qDGYkSBcz5Ku/FIehksoaA1vmjezq1JnGNvqgQvjlKWvDMBd1HyiCl7U
         ZA+94q0IxrUgY5fSZ3QhRGuI2dKI+tR37BTl2z5EKc1BUeNXGEWRTFaMro34j3rlVnY+
         2VFg7S/813y30qTSqmWvBrYL8fg++E1VSp28LGYSSJxaFbeu3XeOhV52rYa++y84WYeu
         06slZoVw69CHmwrozy4BNJljpBgC8x2NKtvC/ugxJfFikZo5deN+fbw2mexrlFYRFdXu
         yc/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y6eNpvvADhEp5g0kMgjxcgRmfbTBJ0QB4DskPt0XQEA=;
        fh=w2nHPpVo8XmRzT17x9so5kZOPZ9kggA3tyuvV34dgYI=;
        b=Sy+n9eiWofVS6OGUpcfTsL4G4rNr0ZkxGpEmgD6MVYj9Df3mmdN06JlCdBW7nJU23C
         sfILt+nY3fM6xDMZCBo7Moq8vbg8W1sx1ZQekPWwQ3WsRxSnJeKykDvfvudE73/tX3Mv
         oY4QhixyzucAIWGb2qDs9ac3M266Sc0iV3GClRSecsvjz2gBTTtDXfurAd5QTzaqPttW
         pSzClx9QQAG5mlnDlRx7FT2/vBRi5mlrpOTeLT+oV/jEB6KiUfxM9d/g9yfwkRy6Jlp4
         SZHFALBFMjrdtOApyidvGqVLkZytpQEw314Kf3ggmR3+gf2besM+dizi51F9cM0kkgou
         xAIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756236963; x=1756841763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y6eNpvvADhEp5g0kMgjxcgRmfbTBJ0QB4DskPt0XQEA=;
        b=M+yHMJHWNueOAh13V2y+lum6eMagA8YZVev9JdYKTIklP3ShDSa3lKHfRgroow5m52
         7U0T7ae+EZj9/ktoVVU+S6K6EuVOzzMt6DsYTjl4qkNltQg9PzZ97KHmxkizMrK5bSL1
         jHqZEVjMALf72nH+QxXtnInsRDEz9VnGMjWOZ3/ac+JBPU0oGnsYD1UnfZkOSEgSuE1F
         rwKHDrHaZhk04/ajKFIP4C6b5YHsccr0rkFIOYirvoOMhXd1L91KnP6rtYGxt2pkOckD
         fYsaadxdFHQ+vc4MlSpUlfRME0eFBU4Mq7r5hXrfXIupA5kZKXlTnIw9x1dn0R6njTqW
         7ywg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756236963; x=1756841763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y6eNpvvADhEp5g0kMgjxcgRmfbTBJ0QB4DskPt0XQEA=;
        b=Pscpg+J3Mnh6x3hFZMB7GzzWWxYHnJphVFbFvGLD6SwOuevoTWuH+5KAXETIdaoqSD
         VWIETEWYRaN1lMhTNYQTqVREy/UXVV3xxEfLVjDh6Xdd4xIlVpdDjSo8CCoKCaxGPakk
         ZRwyvId7Sq28JUdrsmsh77NpfUBQZpxIhJWXLgMHaBc7zdXBEZloTcHNy6OgxsUjPb12
         NS+JwyHmALGK49oZfnMfMWSJdWI0n/tMw/Cp0qOr+5dQsiblgiYHFuC5yFIb9QJEpr4p
         mfhI/E/KEIoCiaCyfF4XIzjoLqv6g8TEXiT4wVnZEIC8XKzhEjRIe0Y3MHBliKeCPfoB
         NZ2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeRw45qU/lUzP9XZPX7x4GBHEHeSVjIRsKCIGDuQD4g+ZmrNdPYpyLE4u1dtgbax+FHnAE6Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6lQpm4YLTkvY72pVX7EOExS50AWF7fowMsOGswA9Xiy25PDoz
	kFVYUUfPsVMHPaOaVX961HCn4XoVJn3NtpfyQ4KWbVPNELIjTq1LkCRn
X-Google-Smtp-Source: AGHT+IHezGkrD0AayFirSBJEaWrSxXWlnrarEBdJmR5Z8ln/otSsoY/9QG1EJDLO7ofwRxC5iGWsOA==
X-Received: by 2002:a05:6a00:2e91:b0:771:ea2a:6a5f with SMTP id d2e1a72fcca58-771ea2a8747mr10827630b3a.6.1756236963389;
        Tue, 26 Aug 2025 12:36:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf0CpBQi85AF4dHz54dqWWVul6y3o2cY6fgcZyoj6kbZg==
Received: by 2002:a05:6a00:301d:b0:728:f8a6:8599 with SMTP id
 d2e1a72fcca58-76ea01e7376ls4885298b3a.0.-pod-prod-09-us; Tue, 26 Aug 2025
 12:36:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIlx3o5DaCc0hLTtEzMVv9zFcM6muRFhngpLp4j7dUciV+LNEJbYxEtA8U+qX5b8f0hXBSs9caNCw=@googlegroups.com
X-Received: by 2002:a05:6a00:17a3:b0:76b:f063:a3cb with SMTP id d2e1a72fcca58-7702fab4414mr21183914b3a.19.1756236961759;
        Tue, 26 Aug 2025 12:36:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756236961; cv=none;
        d=google.com; s=arc-20240605;
        b=d8NgemsjrBYVlU+Ypa6ELzyZKgJgDUJJqSYglVglBNk1jl+9SnHQ4U0svdyYe8BME+
         I+PjEWHtRzccpa2zTX8dOISiieY6asbcbFDmMa+OLSNcg8tFcQfBSfe2Sa5WP6/l5gi5
         JpUJMcvgUfIqsP6yVaeoR0i0dtgq4T+8YMJ2sR5G1iZP26odWhSzGi1ApQZ0F5Y1qXnE
         Fex0/dPQLn+et3lVXtZKAKPoAe6p2mjfOZjOWmAeTFJrswn5DO3C8MaxZ7TR4ps6MM0P
         8gMnwHV3vQs/zhinC4OPqcA57QBd8W8mpudlMtQ6MzS3Znl3sWcGbEgSmG+mWxX3x5C6
         iJOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=bhqILukENv/ledIyFSlAii39xkbLgWJ8CFSuI0YMkPY=;
        fh=uTkSF0dNU1MYXKmorvv1rtxiUrLMnPQKHSlvrKIvDjg=;
        b=NHJDE1PBZntxnRLhw50qqVbbbBosMSH4DyD/l+3GSqvv0aXsTlwmSIBI6iDq32wQ30
         5sfKjctdKQIwwxLeXftWSNk7/rLLIMV8ev/khAjkRHr94S8yfETMTlBKpRuTtO78GZ7U
         ChSitQJXxGdhz4mRj6RJwqcm8+RQsR5tqXsRkhs7HQx7s5WsJB0GWaEZ2q92CJRdCmcw
         KOpes62b3HAmW69GVSfW8XaplU3/oprfpH5AwhZaEMFotneqM4doXOwEjzWs+HGqz4Cl
         PYcRd3R83vYSA0gQ6AysPOlXJZcoB+z+V9ZFGjHjugWy6R/X+584k5P7xFweqQQcxmPi
         yh2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77052993994si296147b3a.2.2025.08.26.12.36.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Aug 2025 12:36:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7E166601F5;
	Tue, 26 Aug 2025 19:36:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3AEA5C4CEF1;
	Tue, 26 Aug 2025 19:35:47 +0000 (UTC)
Date: Tue, 26 Aug 2025 20:35:49 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com,
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com,
	dvyukov@google.com, tglx@linutronix.de,
	scott@os.amperecomputing.com, jason.andryuk@amd.com,
	morbo@google.com, nathan@kernel.org, lorenzo.stoakes@oracle.com,
	mingo@redhat.com, brgerst@gmail.com, kristina.martsenko@arm.com,
	bigeasy@linutronix.de, luto@kernel.org, jgross@suse.com,
	jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com,
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org,
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com,
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com,
	rppt@kernel.org, pcc@google.com, jan.kiszka@siemens.com,
	nicolas.schier@linux.dev, will@kernel.org, andreyknvl@gmail.com,
	jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 01/19] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <aK4MlVgsaUv-u7mS@arm.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <7e314394fc5643def4cd4c6f34ebe09c85c43852.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7e314394fc5643def4cd4c6f34ebe09c85c43852.1756151769.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
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

On Mon, Aug 25, 2025 at 10:24:26PM +0200, Maciej Wieczor-Retman wrote:
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index e9bbfacc35a6..82cbfc7d1233 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -431,11 +431,11 @@ config KASAN_SHADOW_OFFSET
>  	default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
>  	default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
>  	default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
> -	default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> -	default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> -	default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> -	default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> -	default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
> +	default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> +	default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> +	default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> +	default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> +	default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>  	default 0xffffffffffffffff
>  
>  config UNWIND_TABLES
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 5213248e081b..277d56ceeb01 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -89,7 +89,15 @@
>   *
>   * KASAN_SHADOW_END is defined first as the shadow address that corresponds to
>   * the upper bound of possible virtual kernel memory addresses UL(1) << 64
> - * according to the mapping formula.
> + * according to the mapping formula. For Generic KASAN, the address in the
> + * mapping formula is treated as unsigned (part of the compiler's ABI), so the
> + * end of the shadow memory region is at a large positive offset from
> + * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
> + * formula is treated as signed. Since all kernel addresses are negative, they
> + * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_OFFSET
> + * itself the end of the shadow memory region. (User pointers are positive and
> + * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memory is
> + * not allocated for them.)
>   *
>   * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The shadow
>   * memory start must map to the lowest possible kernel virtual memory address
> @@ -100,7 +108,11 @@
>   */
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_KASAN_GENERIC
>  #define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) + KASAN_SHADOW_OFFSET)
> +#else
> +#define KASAN_SHADOW_END	KASAN_SHADOW_OFFSET
> +#endif
>  #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (UL(1) << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
>  #define KASAN_SHADOW_START	_KASAN_SHADOW_START(vabits_actual)
>  #define PAGE_END		KASAN_SHADOW_START
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d541ce45daeb..dc2de12c4f26 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
>  /* The early shadow maps everything to a single page of zeroes */
>  asmlinkage void __init kasan_early_init(void)
>  {
> -	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> -		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> +			KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> +	else
> +		BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
>  	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALIGN));
>  	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW_ALIGN));
>  	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));

For the arm64 parts:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

I wonder whether it's worth keeping the generic KASAN mode for arm64.
We've had the hardware TBI from the start, so the architecture version
is not an issue. The compiler support may differ though.

Anyway, that would be more suitable for a separate cleanup patch.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK4MlVgsaUv-u7mS%40arm.com.
