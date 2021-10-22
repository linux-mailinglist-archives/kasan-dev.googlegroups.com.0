Return-Path: <kasan-dev+bncBC32535MUICBBEG5ZKFQMGQEP3332MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A2FFD43771F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 14:29:05 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id y18-20020a25a092000000b005bddb39f160sf4706383ybh.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 05:29:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634905744; cv=pass;
        d=google.com; s=arc-20160816;
        b=K48poroh+bPZFqB4sy+bVaL6cDbI3+7IB++hNFQufo5gmmsr5h3zTuihUlc8LLbS2P
         OxTHSQH81iw6S+0YkNNyAwi8xgLzj78jnHsVfzUaMSo6rekQTyr3n6yfyhi16YH4HH1u
         J2N3Ps9UMydnXvxcA3SzBgQi4KUfaWS3GF2cwv91ESHc0NQ2fFY/QZTCiImH8BsPw8Hy
         asTV8e149NEvX7rWVAZr+h3MXHAFBn24rza/sz7hensxQCakm7gt4U2R/hlxGLAJLDUG
         p/DZry2k+rawnSuM/DJ5c+xJDN62PdaSb/nfiPTK1yk5ptAUOxtcBXCPaicZcx1kyPTh
         iPXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=hSfstX6SKoV/IObwZo5mqcx/R957Qqmx3peoB6YUPeI=;
        b=p/D8jRZzQukbf6y/kug62T4hU8rOYsZ81je0V3hHd/ICs7CPhvRdNM62TWkek/JkLk
         gbWEUpBiwfpO1VZWbdD3hxtm1luiYYqG9Kmq0gKiQMpdzRcuVNYnd+mSmieXo5yyawiI
         9AOEwnkpC1+A0KE6VRxarBMVXC+kN3KLeHcygQ557XSYxfMlOUhFoPpUJKBAGaVLNAtK
         Y5FLt8fs6DOZHhXKtBFifeUJHnHjJ5skzeSeFSiuf2qGR4xgsNibOBCumOVpuZvs9vO/
         cc81ilMIvLn3K69HVZ7COS1sA0IuASRK4OhCoNE6j4ZaaaVxsJymAe7cGaa9TSg5Xjhk
         SxiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Yo0ReFKC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject:to:cc
         :references:from:organization:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hSfstX6SKoV/IObwZo5mqcx/R957Qqmx3peoB6YUPeI=;
        b=rG1tuupKpaSKE6HxU2Vo66en3CPl4EVHpoEbl/9rTVsZlXVOagpmnoryNzOnEu7EPV
         hjrRrWNh4M2AW+TCImXilNUiMEgbp50QD+GU7YsddWxJ5RJ70rKqTLS057ntWvPEdQ+k
         9K1u821/IqKvrpOujTH8z2y3qEDmgWUrXTicGgonqmjvh1G2Kk/qePQWCUqt1IwlhToF
         QyRsbDNZLd20rhJL1jK6n2pTdZj/FJ1tEvinV2mxFv/n3lHMMj+36SIEyfMqof6xllJK
         DNnkSDfwimS2TxvLmjpNZ43xakR8ifOzUmlySsg4dNslFHovyqf0jiOl2osF22/rpFdL
         S7cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:to:cc:references:from:organization:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hSfstX6SKoV/IObwZo5mqcx/R957Qqmx3peoB6YUPeI=;
        b=LFuc2MmKrNAYOogjtYowkAVxtiV1mMKn4KKxljgqHEin1G1XF/+XtVDr8OunJPsHNV
         ONp7/DM9nCY8fkPdOQ0Genu+E+PdVuoZj5Yx9rsQrbUgIpr2JE2vbxuoCL4lOVptXB76
         TT4Qu7N+eYw/Rmkqnt833q64a1QEdDnltXce8mPCPWI1FTIeAam0ziV3p2wHbbXRzl0M
         IqEqVc9T+l+OhqvSjrQD3i+UtKjf8tAznHNdB9640P0DjZQRo/bABPNl6ycyLIM7/DKF
         InRD4qL7yvG6uWFwebU4nAKy8AOhRKs3dhWuA1iWYXu8MzQ8iEbP/9bp91oOGBTVReWm
         3XQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bqpm9ZzBtQLE4T1fqDbI7clISOIIHe9lw/fagMmBCOv+tb1tk
	MRazOQ6XaojTQAxipz1rqdk=
X-Google-Smtp-Source: ABdhPJxH5j2OF6vSRMEA1Oqe4iKtHDfcTsEwb9zvYwrIhj4ds+6FR1j9A9WdT3+B91eS929LX5w+Tg==
X-Received: by 2002:a5b:385:: with SMTP id k5mr13705866ybp.65.1634905744600;
        Fri, 22 Oct 2021 05:29:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:320f:: with SMTP id y15ls6191877yby.10.gmail; Fri, 22
 Oct 2021 05:29:04 -0700 (PDT)
X-Received: by 2002:a25:e406:: with SMTP id b6mr12486309ybh.134.1634905743989;
        Fri, 22 Oct 2021 05:29:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634905743; cv=none;
        d=google.com; s=arc-20160816;
        b=FJA8Ka1oQZOhZnGjnHjkjTIR6s4KJ4a1nBeiIotkJEbOW1av+2lTyRo+7AQO0YugYa
         xHP7+ymjPxOov/bI/dkhEqQ1TVXo684J9mY7KPTzNS7dKEqIBsry1jMl6Z9z03L29KdQ
         jHnileTe3Az8hw8SYyisCrvWfQEzzYdFoEUCZgK8sEy078V1Se77ACTiqb7raOzzB9lZ
         ry5XMi+Wr2HcYgVDfxU2Orhu9f6rqDSwBvYmYBK6CRZbQwexuEPjepci7p4B71njDC+0
         JK/4eugSLSw50TvJUy0azVKg+E/1LSNOqE4AMEAxk34lVjJnX65nTU8q+EMPuIjwOvyr
         EU1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=YuUgTaC7SncRn/56fPFHOc3RSrpIisjOLVPx5zTF8wM=;
        b=rYRgWP9IhKu50q++DS60c7v4rBcXF+fDLxBr0R+dLBxoVZsB42dObhy6c5s5EZk1dq
         SyO0qmd54CZwhgG05eRFwW5MMpmRfCHyAgOJrTp2n6pW4ScgvTbnT/1WO2XGXnpxv/VX
         89bzE5O9YS267dZubBoNp1+Xc1UbUMWpmMwtWAHL1+pFl3OY0WlZ5w4E2BQv5Ur4f41s
         PcxAMvDgjqzMUhczyXQ2/UVh/47xN4yJSFx00+C8kyaiAUlkmv3lDoBQ2aNmjzjKiM20
         qdSpPuIdYnxnKS5BLQfwTFTjrUi/Pot2glPyuAmyofWEADX3H3fRNCv4N3/MJCXgyChL
         pGnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Yo0ReFKC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id v16si901979ybq.5.2021.10.22.05.29.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Oct 2021 05:29:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-466-ttqNmjhyPkS6hs9XHLupiA-1; Fri, 22 Oct 2021 08:29:02 -0400
X-MC-Unique: ttqNmjhyPkS6hs9XHLupiA-1
Received: by mail-wm1-f70.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76daso1082523wml.9
        for <kasan-dev@googlegroups.com>; Fri, 22 Oct 2021 05:29:02 -0700 (PDT)
X-Received: by 2002:adf:b355:: with SMTP id k21mr15307019wrd.380.1634905741162;
        Fri, 22 Oct 2021 05:29:01 -0700 (PDT)
X-Received: by 2002:adf:b355:: with SMTP id k21mr15306985wrd.380.1634905740893;
        Fri, 22 Oct 2021 05:29:00 -0700 (PDT)
Received: from [192.168.3.132] (p5b0c6324.dip0.t-ipconnect.de. [91.12.99.36])
        by smtp.gmail.com with ESMTPSA id h14sm3553851wmq.34.2021.10.22.05.28.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Oct 2021 05:29:00 -0700 (PDT)
Message-ID: <d6f6bb06-17a5-92d4-82f9-f8350d0a7b0f@redhat.com>
Date: Fri, 22 Oct 2021 14:28:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.1.0
Subject: Re: [PATCH v3] kasan: add kasan mode messages when kasan init
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Matthias Brugger <matthias.bgg@gmail.com>, Marco Elver <elver@google.com>
Cc: chinwen.chang@mediatek.com, yee.lee@mediatek.com,
 nicholas.tang@mediatek.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-mediatek@lists.infradead.org
References: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Yo0ReFKC;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 20.10.21 11:48, Kuan-Ying Lee wrote:
> There are multiple kasan modes. It makes sense that we add some messages
> to know which kasan mode is when booting up. see [1].

s/is/is active/ ?

Looks reasonable to me

Reviewed-by: David Hildenbrand <david@redhat.com>

> 
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
> v3:
>  - Rebase to linux-next
>  - Move kasan_mode_info() into hw_tags.c
> v2:
>  - Rebase to linux-next
>  - HW-tag based mode need to consider asymm mode
>  - Thanks Marco's suggestion
> 
>  arch/arm64/mm/kasan_init.c |  2 +-
>  mm/kasan/hw_tags.c         | 14 +++++++++++++-
>  mm/kasan/sw_tags.c         |  2 +-
>  3 files changed, 15 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 5b996ca4d996..6f5a6fe8edd7 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -309,7 +309,7 @@ void __init kasan_init(void)
>  	kasan_init_depth();
>  #if defined(CONFIG_KASAN_GENERIC)
>  	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	pr_info("KernelAddressSanitizer initialized (generic)\n");
>  #endif
>  }
>  
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index dc892119e88f..7355cb534e4f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -106,6 +106,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
>  }
>  early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
>  
> +static inline const char *kasan_mode_info(void)
> +{
> +	if (kasan_mode == KASAN_MODE_ASYNC)
> +		return "async";
> +	else if (kasan_mode == KASAN_MODE_ASYMM)
> +		return "asymm";
> +	else
> +		return "sync";
> +}
> +
>  /* kasan_init_hw_tags_cpu() is called for each CPU. */
>  void kasan_init_hw_tags_cpu(void)
>  {
> @@ -177,7 +187,9 @@ void __init kasan_init_hw_tags(void)
>  		break;
>  	}
>  
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
> +		kasan_mode_info(),
> +		kasan_stack_collection_enabled() ? "on" : "off");
>  }
>  
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index bd3f540feb47..77f13f391b57 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
>  	for_each_possible_cpu(cpu)
>  		per_cpu(prng_state, cpu) = (u32)get_cycles();
>  
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
>  }
>  
>  /*
> 


-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d6f6bb06-17a5-92d4-82f9-f8350d0a7b0f%40redhat.com.
