Return-Path: <kasan-dev+bncBCSL7B6LWYHBB5UM7PBQMGQEWOAGOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 12F76B0CD69
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:00:10 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-451ac1b43c4sf29619165e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 16:00:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753138808; cv=pass;
        d=google.com; s=arc-20240605;
        b=BoSLqgEMnCSZWLM8VuS8VrZoEr5RXTYBip4hzw2LyeaJ8vSg2udhXSoGKRK5o8U7cN
         eyiZcnjN9tN/GgGUFVDzBeiZYLBAgeyLAuZrIFQbj6oraGZJCeCtnr8rLlW+rp8vrtER
         RquChv7LllQofuZ/3AGPgDzlMvQxQkK1CJKg5FGLxQsmVRdOc10eOmu14q7VrsdA7ytj
         9+scxPqHH6ymLp+7M4OKUvp8/J14a7x7luX7IRVK3H3G4WL8czFJ8J73hGu8kKoP8c76
         MrUMUte/ynDjDQlVIU9JNRbyRE6tHSXB4FKF+JbNfdO3cJoo4PvWtbVFNaq5x5tF/0YA
         vHCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=1v9ohBf90otDCTGdoVTT/sj4O/oGVaFPgBqaY7p4NwA=;
        fh=21NQ0TTiaAlmVPBVeGncfyAxWTdHyYg4D2zln/8tqtQ=;
        b=JpxpUYu29WqNwF9O4q62ivMnTXCCxJAZBvJIDTuMxv3nuLObapu0FgEujWyyrk16nf
         HXSx9T01mopeo49eSCS12C59ovHzU07v2qjJXsI3EHOscVGiyVsc98kPNsATPcvoQerG
         RFS87Hyemn2eWYtYIzYi9RjVyN7EdOjZqV/rCn6dqgcEhxWNZa2T0gjw2CP4gUFbmJne
         /7V0FUfR11y+SDCLl18W1EHisJ8REOAyhsItI3Ve49E0rh+xTXSlcxQ8JapKDpVqdi26
         JLTVGhngUl8zWLOWl16vLs3RxI2ocUnHJ51rPPsGw4A0Z6RlbHcl+WPoDjgnTNDvST5F
         5NrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Pg/KiKWT";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753138808; x=1753743608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1v9ohBf90otDCTGdoVTT/sj4O/oGVaFPgBqaY7p4NwA=;
        b=hFCM5Kxc8+qvZCLXgOY1dfTAQ77g8On3uX11Rj0Wu5yEeU35NXQ6cXYDnuezmbtx3T
         tBulu9OjCA4aPXuLAOPljrsdd82EZyBk/eBzB5RQNGdVcgMXsAAKsJqD0kOTfRF07Cs5
         y7DH8D/VNi91Jg9bBkumZ7VTqnujjV9sjAL5hhpqLsVe4dmgyN7tOz+dlnCcYQoV8j1S
         lesFbkyv50IdA4houR9s6JUjFRCtdgjYLE9/ksoxKbLHOPCuLahFTq7DVE4Z4du4f4BK
         xkaIeCuGZVHX08Hh7h03xvFjDMWtc18wN/kvrVGU0kRP5bvGQpUMVuax/j2wZM53AQkn
         m1iw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753138808; x=1753743608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1v9ohBf90otDCTGdoVTT/sj4O/oGVaFPgBqaY7p4NwA=;
        b=LYBhxruTa2rMla/SumzFTgLH1IaZYqWvBauH53WgrN94INsukc+QmU0em7EjDlmQXV
         qSgY+P0tUNE1pGT1EzO+GodwcIU1avIz3DSAj36CKGO1Q1cdkVFpr1EpEp99vpnmRht2
         BsqLue0H2szDsPheTn9lfnrmF7gjoNnm2GBm0BSwZt1ElqUgoHutXUmmdXYscIbIfPFl
         Bc7nCxRx6QdOgtDzesxTW02v6A7Ep6hBO2dfZjmMWcZB82ddKIiLUBpW9WeiMTnqcX7e
         Oy7tWkzNnXTxh28m4/1t149ehehaOSwEY/zcIMMHk00elOEdacL6K1F+Hh5S+Eby4EA+
         ITLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753138808; x=1753743608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1v9ohBf90otDCTGdoVTT/sj4O/oGVaFPgBqaY7p4NwA=;
        b=tNC0bMzPkBT1pZQ4JpH1e6tUyGg2Lg5Mv2Jo7uq1uBBURXObSnF/in9KhhmfHGtk6Y
         xJ4UvXs1BP4Qf5+caYG1SmB/l70+Si3jZYE+gAXCWZKRAtDNBPe/CfUt59l0ZlI5Pzkp
         XX01L/zkPTvGlsjveACyL2FxSh2X450Dg250CETqcOSHVgygu3OFV+/Ws+O4hI/Xb8Do
         ecCPXTDw9+/H1nn0LMeVJ7yFoENiAhB8hfQZ5v6XA5WnfevIIGyCIJ/9ExUC2LIJvDHj
         QJ9j0sxc/ksNd6vzyb2zPGA4kTjVgltHF3z4ja8/Bhc31hy/AXcyyr+Rc5u7pAPUHdf9
         MoeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuXa5s53v1eIMulJnuPq8WqibGOii/iZRL0mJlxC+EOiXiHcPNjGGwNlzgJKNszn5sGNmXRQ==@lfdr.de
X-Gm-Message-State: AOJu0YyHkJ8VRLxd+FwluY2xFJGcC4DUfrb8WGY7H05WblNn9j10FHJ4
	bEizYgh6Jsq1Km7ndiia6CJWpqnMnQIycLCXlHtiTg1TzXEZZSB3Qfe0
X-Google-Smtp-Source: AGHT+IGybG6jEiDXC4So+ArrF1j+YFEeDkcX+/uhYAgVIDRoM3zvFWyChj8KRt6fAzLfjMBvejR0fQ==
X-Received: by 2002:a05:600c:64c5:b0:442:f4a3:b5ec with SMTP id 5b1f17b1804b1-4563b89f065mr118422025e9.4.1753138807263;
        Mon, 21 Jul 2025 16:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdr4mmg7XJzYlgsggeOedbBD5owxtB2xtyDgWUqsEXlSw==
Received: by 2002:a05:600c:3b91:b0:456:18ea:2f64 with SMTP id
 5b1f17b1804b1-456340bdb25ls26876565e9.0.-pod-prod-04-eu; Mon, 21 Jul 2025
 16:00:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHbKVqbSMEHlqI0nCie29Hroc01ONqz8SpJDHusczbSUniVPlvCSq4eVk7I8uV09hgv0one19+QIU=@googlegroups.com
X-Received: by 2002:a05:600c:1c03:b0:456:285b:db29 with SMTP id 5b1f17b1804b1-4563b8fc975mr115877285e9.29.1753138803389;
        Mon, 21 Jul 2025 16:00:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753138803; cv=none;
        d=google.com; s=arc-20240605;
        b=EOipJW+XrrxltIScExizCDlSQkDEkVxcxG9q7im7cZSkuFKIe1bjY7WTb0BhoDd/DG
         RLSlXPR44Npi8T4y0ekWQvJJ9jrC4MAA/a1BuPdtX6qQhg/tc0rJKH50Q9MlEYSGY/M7
         6Tu+gvsojSqVkOegOcJqrK+aubhT4bLpspZsTbJPrEVkZNwYxruZsVNECeN9Vb+YUrX8
         qcqnZ+S63Rd8P1SJC6d/3ydYP6pJB41Hn0nL4/7ysQNJhtMOlCbSA6MLrZik/eBUdYgD
         wBUEOX+oacFE3PWkgzhOs+rUQdTIWu26DV4SHvGMnayuOr2CoLXl/Gkuf3NhiPttbIiw
         w0fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/MErh+IJZfEbaFHl36LqhlLVHvlXTKmbu8riveWqw+Q=;
        fh=xY0hcqB4nMa8mZhk53tyPppejcE5X5NUrgXfcpayBtM=;
        b=B/t+bVG+t8aJ/5E2AdR+RA652tpQMOse2K8IRpvNMrzWhNTZx4eBTSMaSZ8PvQ1nu6
         dHckccwR+sGnb+BFkZ65VydiJYyYPrB9b0miKBXbbFNvlFpN4y/j1qpMx050eVUQ9eVQ
         SBJiSbnbNfyNmItSpDIBKwpUmEmiekudIdjCPTTAdG9wqxPTsOIV7f95yY+9a3RQGvxV
         5waXlhH9mZ9D4HUoDjPbi5d3L8ewiGRlOujBibqyc9ejpM84RfaNhTQWjMYht8Dj48MV
         eVhQQ5+wqGrP60TQl+H9xb5SLshXlCCjkRA4ha9XqKd+CdTKdhHAllifo1/jdmpfu3f7
         /8YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Pg/KiKWT";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b61ca42ddbsi190129f8f.4.2025.07.21.16.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-ae0b98ccc57so84289066b.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 16:00:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWv9KQ746ujk8hlwCoBEy8rFy5vkzohlR+B9jq+dhO23ShQ1sF9sboT4PFu9mAhSX0FpJDGZ/uXV3o=@googlegroups.com
X-Gm-Gg: ASbGncsgqzNFBPIl9/zu/rUNlATtv/0A6YDsAexLfQBzSByB0egUPsA9D3G5kxU//vg
	A5JtZRPpPQ8oy0zbsvJvFquce5+V+UoHRMJldFjnDl3YRxAI0io0kKS2q5XG2MdRv8C1wOQlzYm
	fegKwXCrWXWInDmv3lhhMGXRwMN7E9EAEFHiUSdSGTfXtmkBa9hQjdDT4ZAzIFU+/iyZdPOkcKK
	1Oav9EnzXvjVkkhbXsB3MpgOIwZQGiASIF6l65cNiTVFOoGOFI/dKMp/+/RbnFlvLAOddkT8N+6
	HdkQ45xb30djwfKmthZL3UKYNe/PdO5fyZNiK/hUfdZx+HqhUCzb+ZjWm3P+mffusructMCZKwF
	8wy+QLoEwI+jxOyD6ZWprMNJGLzFP67jSufWMuG6yzVegiL9oZ6uQXcoeJU83FhXJ0ds3
X-Received: by 2002:a05:6402:3582:b0:612:b0d9:3969 with SMTP id 4fb4d7f45d1cf-612b0d93f03mr5896945a12.8.1753138802656;
        Mon, 21 Jul 2025 16:00:02 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-612c8f543ddsm5962670a12.30.2025.07.21.16.00.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:01 -0700 (PDT)
Message-ID: <8f93322a-84c1-402b-b8d4-9c66a2b07b0b@gmail.com>
Date: Tue, 22 Jul 2025 00:59:41 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 02/12] kasan: unify static kasan_flag_enabled across
 modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-3-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717142732.292822-3-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Pg/KiKWT";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
> Historically, the runtime static key kasan_flag_enabled existed only for
> CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
> architecture-specific kasan_arch_is_ready() implementations or evaluated
> KASAN checks unconditionally, leading to code duplication.
> 
> This patch implements two-level approach:
> 
> 1. kasan_enabled() - controls if KASAN is enabled at all (compile-time)
> 2. kasan_shadow_initialized() - tracks shadow memory
>    initialization (runtime)
> 
> For architectures that select ARCH_DEFER_KASAN: kasan_shadow_initialized()
> uses a static key that gets enabled when shadow memory is ready.
> 
> For architectures that don't: kasan_shadow_initialized() returns
> IS_ENABLED(CONFIG_KASAN) since shadow is ready from the start.
> 
> This provides:
> - Consistent interface across all KASAN modes
> - Runtime control only where actually needed
> - Compile-time constants for optimal performance where possible
> - Clear separation between "KASAN configured" vs "shadow ready"
> 
> Also adds kasan_init_generic() function that enables the shadow flag and
> handles initialization for Generic mode, and updates SW_TAGS and HW_TAGS
> to use the unified kasan_shadow_enable() function.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v3:
> - Only architectures that need deferred KASAN get runtime overhead
> - Added kasan_shadow_initialized() for shadow memory readiness tracking
> - kasan_enabled() now provides compile-time check for KASAN configuration
> ---
>  include/linux/kasan-enabled.h | 34 ++++++++++++++++++++++++++--------
>  include/linux/kasan.h         |  6 ++++++
>  mm/kasan/common.c             |  9 +++++++++
>  mm/kasan/generic.c            | 11 +++++++++++
>  mm/kasan/hw_tags.c            |  9 +--------
>  mm/kasan/sw_tags.c            |  2 ++
>  6 files changed, 55 insertions(+), 16 deletions(-)
> 
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index 6f612d69ea0..fa99dc58f95 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,32 +4,50 @@
>  
>  #include <linux/static_key.h>
>  
> -#ifdef CONFIG_KASAN_HW_TAGS
> +/* Controls whether KASAN is enabled at all (compile-time check). */
> +static __always_inline bool kasan_enabled(void)
> +{
> +	return IS_ENABLED(CONFIG_KASAN);
> +}
>  
> +#ifdef CONFIG_ARCH_DEFER_KASAN
> +/*
> + * Global runtime flag for architectures that need deferred KASAN.
> + * Switched to 'true' by the appropriate kasan_init_*()
> + * once KASAN is fully initialized.
> + */
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  
> -static __always_inline bool kasan_enabled(void)
> +static __always_inline bool kasan_shadow_initialized(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
>  
> -static inline bool kasan_hw_tags_enabled(void)
> +static inline void kasan_enable(void)
> +{
> +	static_branch_enable(&kasan_flag_enabled);
> +}
> +#else
> +/* For architectures that can enable KASAN early, use compile-time check. */
> +static __always_inline bool kasan_shadow_initialized(void)
>  {
>  	return kasan_enabled();
>  }
>  
> -#else /* CONFIG_KASAN_HW_TAGS */
> +/* No-op for architectures that don't need deferred KASAN. */
> +static inline void kasan_enable(void) {}
> +#endif /* CONFIG_ARCH_DEFER_KASAN */
>  
> -static inline bool kasan_enabled(void)
> +#ifdef CONFIG_KASAN_HW_TAGS
> +static inline bool kasan_hw_tags_enabled(void)
>  {
> -	return IS_ENABLED(CONFIG_KASAN);
> +	return kasan_enabled();
>  }
> -
> +#else
>  static inline bool kasan_hw_tags_enabled(void)
>  {
>  	return false;
>  }
> -
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
>  #endif /* LINUX_KASAN_ENABLED_H */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2..51a8293d1af 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -543,6 +543,12 @@ void kasan_report_async(void);
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +void __init kasan_init_generic(void);
> +#else
> +static inline void kasan_init_generic(void) { }
> +#endif
> +
>  #ifdef CONFIG_KASAN_SW_TAGS
>  void __init kasan_init_sw_tags(void);
>  #else
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed4873e18c7..c3a6446404d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -32,6 +32,15 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> +#ifdef CONFIG_ARCH_DEFER_KASAN
> +/*
> + * Definition of the unified static key declared in kasan-enabled.h.
> + * This provides consistent runtime enable/disable across KASAN modes.
> + */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +EXPORT_SYMBOL(kasan_flag_enabled);
> +#endif
> +
>  struct slab *kasan_addr_to_slab(const void *addr)
>  {
>  	if (virt_addr_valid(addr))
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e..03b6d322ff6 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -36,6 +36,17 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> +/*
> + * Initialize Generic KASAN and enable runtime checks.
> + * This should be called from arch kasan_init() once shadow memory is ready.
> + */
> +void __init kasan_init_generic(void)
> +{
> +	kasan_enable();
> +
> +	pr_info("KernelAddressSanitizer initialized (generic)\n");
> +}
> +
>  /*
>   * All functions below always inlined so compiler could
>   * perform better optimizations in each of __asan_loadX/__assn_storeX
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b5..c8289a3feab 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>  
> -/*
> - * Whether KASAN is enabled at all.
> - * The value remains false until KASAN is initialized by kasan_init_hw_tags().
> - */
> -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> -EXPORT_SYMBOL(kasan_flag_enabled);
> -
>  /*
>   * Whether the selected mode is synchronous, asynchronous, or asymmetric.
>   * Defaults to KASAN_MODE_SYNC.
> @@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
>  	kasan_init_tags();
>  
>  	/* KASAN is now initialized, enable it. */
> -	static_branch_enable(&kasan_flag_enabled);
> +	kasan_enable();
>  

This is obviously broken for the HW_TAGS case. kasan_enable() does nothing,
and kasan_hw_tags_enabled() now always return true.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8f93322a-84c1-402b-b8d4-9c66a2b07b0b%40gmail.com.
