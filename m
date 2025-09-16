Return-Path: <kasan-dev+bncBDAZZCVNSYPBB7XVU3DAMGQES3YFKEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D64DB5A16F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 21:31:12 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-770c244009asf70464856d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 12:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758051071; cv=pass;
        d=google.com; s=arc-20240605;
        b=IURT6GYAY9SLpzhW4TcdrFvOz4WTkNBA6XKaVCml4jTXv/Z/LK09TcHwms1Ea6khvq
         7ahgMzmBsAmA5Nyi4oWy0ZBNZ9ZEcmWkwM/3y1RBxMA0rZUWL93D2sWPT3vB6VFreF6y
         QCRcVB+eV1om2/jzjbzMAJZ3oBHvkgDxLb1emn6OOWQmgY5zV2WbsahhXaRwPcFoLK7F
         ILT4zAHHDM9JleIgIUjsMqARBnZVCbfU0+JIySb3nz3fV0DbeBYLZw8G6m3gDzEnmfTw
         NrdKr1V4q0tSe1m5F637sNJECSwnKL00y5UBmdZjjGlVriLvPCvBJagG6VXJD+7jhJay
         nkKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bezcYGbU8ZoJCFGv00ETbpL3fRqUjNC7rrjJPWrSQTE=;
        fh=wLHKF0Y8PhBQGIWeDlFeWWCH06OWjUvz5akyjSEmrCY=;
        b=kEzJ6bGx9iFKjteeBUispy+D+3NnTeDsKExJpYZPCZX4MK6Qq6JsfuTbAsd9Rdcr+M
         4wT4Sz4W02ZcCuTAWsquLkJgbuTHe1+Cu69Lym71zIh0AyWRkSDfRwz7R6BSlkY9YdbQ
         mYhSsF6p5KBgbbtzDg9TIQ2j5oUvqTjcyExGIsCht4N+AuHwHVWou4PVmDikYoZFgKCN
         8VGBcHp9umPiHnZsmi36hSLnVB/NgjfgPj0D91CD6SpfsCIH2PzrLQzkwWGb/9V+ITdo
         Hy0WL3QB6A7FBG9PyOJSADBvq/VQQCYk3uJhMs+bZD8tXKR0/s4coN/0+tQ4hWvz1XMb
         UzuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AlDQEdc0;
       spf=pass (google.com: domain of will@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758051071; x=1758655871; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bezcYGbU8ZoJCFGv00ETbpL3fRqUjNC7rrjJPWrSQTE=;
        b=a0Zilq+jEz/xdYTNnQZonKGZTFE42jDoyjAbtWQerKE9xGQzNr0mEjFna/Wlvs21o6
         KgTPQueNmG4cR4Fua99PRhbQGi5BP4lQB1P/iqpbHXun+vya5SMQLTpVGnnM4HX24hwv
         HPOWFULzf4w8OXPbnz3/fHgoMAr0NEKPb9vGs+EJiioZC7cWKfjmrqBP0yf5tQD2n7kS
         nuH6BkRlECXdzWggRF5p/c+RYHy1ze0QAL5gBEuSdewYyEBoYcEjbNKRNfq/Sse3DrQM
         hHsFTy22AClF109vCF+Un/Mhvoarrgd63JOGNe4xhfCIFjvB4lTFSCgmpnKmTq/2d1bL
         wBGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758051071; x=1758655871;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bezcYGbU8ZoJCFGv00ETbpL3fRqUjNC7rrjJPWrSQTE=;
        b=fnX8DEMcgsd9/d6TQ+s5H0lTcROs9/XBa0CYEApjn+wFRdwGZd2xLl3UBvFdKU6st5
         /PvyxBskYl1tvvOV3pwaDd0340vrrBJSo9/4/qtgcvADw4DClBCtRHhxHUzUR75N6Uob
         hrxkj3YOvy1DPeRKANTW3lwHBsGjaFbtDT0VuRtxAad2vnb50oV4F2j7U865cpilmnkC
         k+mHcJSGqLxVCqDAJBdxR2IQQYPyBtJGhaFaVEk4WVEoOnlDeasjxK0F7U5CpSNrGpcX
         /bcQwTM2UFmqsSNnKRz/ep/xhGQt09uZ3s7m8uYl8tLxxVQp7kDXay/YQX3A4I7Q9HPW
         oFiQ==
X-Forwarded-Encrypted: i=2; AJvYcCVajduyXloLwBG573ns4GV3TlAsPehy8vc8QAqZ3pulJolVXc/nOjmP+Lxx2hUTha/14GxYVQ==@lfdr.de
X-Gm-Message-State: AOJu0YyqmzenCT8rtdDqAg3QT+niYTUKiuIemNIOVp0o4KPXcg+EBCdX
	vCSxSCcTk9EKdM40glvtexSeQTV4Rryp3imu03SFdW/OBz9aFlOWhl7N
X-Google-Smtp-Source: AGHT+IGapZWcZdaPY/pPiMdUD77Q2eNEfEobxp1Lp7hC5/dgfexAzXhrgItlt2McTeqe4WVQ/X5q9w==
X-Received: by 2002:a05:6214:dae:b0:78d:4b58:2eca with SMTP id 6a1803df08f44-78d4b582f82mr43559606d6.26.1758051071214;
        Tue, 16 Sep 2025 12:31:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6TmCDbGP6NdwZ1y+p/W0VdjFRGuxS24FZTbSZNIEG0mQ==
Received: by 2002:a05:6214:d6f:b0:78d:7ec4:d664 with SMTP id
 6a1803df08f44-78d7ec4d6b9ls19383986d6.0.-pod-prod-09-us; Tue, 16 Sep 2025
 12:31:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcYwioDGFxg05a4uKx4TSBFYwdQyrMv3d8vLr8GPVZP+1yyrjn+NOlBvJwib1wQ70q9Ao5Mckjx2g=@googlegroups.com
X-Received: by 2002:a05:6214:d0a:b0:785:16e9:1093 with SMTP id 6a1803df08f44-78516e91753mr91685096d6.31.1758051070292;
        Tue, 16 Sep 2025 12:31:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758051070; cv=none;
        d=google.com; s=arc-20240605;
        b=LbdOnusBrt2yGCMvCzQRkCpa4RA8vtPwsSSpsFgyNsk3S/wBvBMGDmFzT+9o9dCEXU
         tQQ0u9F/FybGQKvh0NYBlbovJZSG9JvVPGiqyYIMqWMD+tsdfSE+NbxORgcUtk3Z/8XJ
         gueQJgVYaJmO0Dn6ROh5F/zzRSbFHEZodExYlaBQsXAmACJZaftilZ3b3LaN2xaI3AQP
         tmjBmEaUPysTX4NxNm0Lz6eqwJhVh5pvSPAig0z4yQIQVqCplkO0qpafdNj9zRSW5LHO
         3/CEdLBtuL2YPK6T5sBrtjHPEV9tC1tamRNFx4zeROZMbBdNwftrEqExv7yuaOWuwyiY
         73Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0xFsZI8OPS+4kV2H8RyqcgVFs/zzzOZHJrs+93uaEC4=;
        fh=w2ZV6jCvet0xyt+7iiHaphknVWnpo8xfeOrr3xOJ5r0=;
        b=Xik9EceqhfH6DPeuggQsc7T9G8GEEA1qgoMFrIAHS87TirPr3gROBjrWAIw5uM+pGV
         JSRnvk9oZKEOa7FFi7+3VHbncdBsgnwPeMwL3b3rEMTgj6OkChGMj1QBLyGeQ+Hug/go
         BrQU9Ewex9iphPJ/zCQjC7eNNorvMxAjDmwaMx/cjIUaZ29ffDWBArcy5KHVhzqrpxBu
         S+0BhfmWIgULKK3PlNhSyjT/VYv+qo0D+j0caBOnVsCJOAIeWs1BpBT0JNo0VFuql+bo
         tb12H5x56iLdUlNc4e451Rzryt/lRgEXLdfusGpMElTkfV6kI+UsjAnCs9/vHINiLT5J
         lepA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AlDQEdc0;
       spf=pass (google.com: domain of will@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7802c9d08aesi2594696d6.6.2025.09.16.12.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 12:31:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 79715601B3;
	Tue, 16 Sep 2025 19:31:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1697BC4CEEB;
	Tue, 16 Sep 2025 19:31:03 +0000 (UTC)
Date: Tue, 16 Sep 2025 20:31:00 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	catalin.marinas@arm.com, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v7 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aMm69C3IGuDHF248@willie-the-truck>
References: <20250903150020.1131840-1-yeoreum.yun@arm.com>
 <20250903150020.1131840-2-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250903150020.1131840-2-yeoreum.yun@arm.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AlDQEdc0;       spf=pass
 (google.com: domain of will@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Wed, Sep 03, 2025 at 04:00:19PM +0100, Yeoreum Yun wrote:
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN write only mode based on this feature.

Typo ^^

> 
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
> 
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=on", KASAN checks write operation only otherwise
> KASAN checks all operations.
> 
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst  |  3 ++
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  6 +++
>  arch/arm64/kernel/cpufeature.c     |  2 +-
>  arch/arm64/kernel/mte.c            | 18 ++++++++
>  mm/kasan/hw_tags.c                 | 70 +++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                   |  7 +++
>  7 files changed, 104 insertions(+), 3 deletions(-)

[...]

> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..d5b5fb47d52b 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
>  	KASAN_ARG_VMALLOC_ON,
>  };
>  
> +enum kasan_arg_write_only {
> +	KASAN_ARG_WRITE_ONLY_DEFAULT,
> +	KASAN_ARG_WRITE_ONLY_OFF,
> +	KASAN_ARG_WRITE_ONLY_ON,
> +};
> +
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> +static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
>  
>  /*
>   * Whether KASAN is enabled at all.
> @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>  
> +/* Whether to check write accesses only. */
> +static bool kasan_flag_write_only = false;
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT	1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
>  
> @@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
>  }
>  early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
>  
> +/* kasan.write_only=off/on */
> +static int __init early_kasan_flag_write_only(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
> +	else if (!strcmp(arg, "on"))
> +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_ON;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.write_only", early_kasan_flag_write_only);
> +
>  static inline const char *kasan_mode_info(void)
>  {
>  	if (kasan_mode == KASAN_MODE_ASYNC)
> @@ -257,15 +284,28 @@ void __init kasan_init_hw_tags(void)
>  		break;
>  	}
>  
> +	switch (kasan_arg_write_only) {
> +	case KASAN_ARG_WRITE_ONLY_DEFAULT:
> +		/* Default is specified by kasan_flag_write_only definition. */
> +		break;
> +	case KASAN_ARG_WRITE_ONLY_OFF:
> +		kasan_flag_write_only = false;
> +		break;
> +	case KASAN_ARG_WRITE_ONLY_ON:
> +		kasan_flag_write_only = true;
> +		break;
> +	}
> +
>  	kasan_init_tags();

I'm probably missing something here, but why have 'enum
kasan_arg_write_only' at all? What stops you from setting
'kasan_flag_write_only' directly from early_kasan_flag_write_only()?

This all looks weirdly over-engineered, as though 'kasan_flag_write_only'
is expected to be statically initialised to something other than 'false'.

>  	/* KASAN is now initialized, enable it. */
>  	static_branch_enable(&kasan_flag_enabled);
>  
> -	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
> +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s)\n",
>  		kasan_mode_info(),
>  		str_on_off(kasan_vmalloc_enabled()),
> -		str_on_off(kasan_stack_collection_enabled()));
> +		str_on_off(kasan_stack_collection_enabled()),
> +		str_on_off(kasan_arg_write_only));

It's also confusing, because now you appear to be passing the funny new
'enum' type to str_on_off(), which expects a bool.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMm69C3IGuDHF248%40willie-the-truck.
