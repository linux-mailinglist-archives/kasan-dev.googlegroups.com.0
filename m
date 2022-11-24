Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBCM47WNQMGQEBSDNUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AE706376E9
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Nov 2022 11:57:14 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id k21-20020a5e8915000000b006de391b332fsf707524ioj.4
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Nov 2022 02:57:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669287433; cv=pass;
        d=google.com; s=arc-20160816;
        b=b2FRZWMzhyfZClTwh0OqhMh4I0lHcYjXg1OUhl1YMMMzHO1u6JdrTSuopkflonTNGH
         yYbH5rJvZUU6lk0ryzexGkEMo7EaPJlZAl66/5drqmt7Q2MUKYpiP1ztPZ2yU3YdE3Qe
         Jj50fjUKb0t7l6HbidzdtAyq6UtOzgkUFacLSbzYoSM9j0N2cVMJg+eM+6dDDklEYMqm
         7B+kfWpINmWcMsrfGtWfEdJ04er5gddc/IBBAEgZpCs0ix4nbvxvqh3/gE5/antjQ7Ef
         wQyAOSoc663jR7k4GoY3IFNDu2KncmnXK92aUMADC92vUtNX2UD3yPgi5OAmfF+KftTy
         nEaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=YsRnWbco/CvDFLAzwR9esWVfATaiIBK925UGmL4oboU=;
        b=T71uiA8HjjYvQfk+YF0yT019/xq+uuz2bY7Oq4zsLez4ycU7J0jM+ybEM92O//zXiC
         mvDhBUCnUjkaFytPKsar3GGi4s8hFNfkLTjDt+k2fRfjxZT9wwALuM8H6JQUmbgvoBw9
         FUTIX53HrCfiiMq0m7YxSbYAwoZEOIQsaKyRW0IpKKSDlwWtIU13emUTGiNzt4D8fK+R
         +JYb3DwgIhV9RMTBNd0RB2kO5qo3ewGQsJMcJi9eY/1Kpu1DNdsdvJ+AY0UOYCd5b1Mo
         q5xCBteUKnxFvxNcFz1OooMnghtBZK+ToOeFiRTJlSB+0vItqDIt/tvCMcDIJwAN+Hnq
         ztTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Wt6hrqGp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YsRnWbco/CvDFLAzwR9esWVfATaiIBK925UGmL4oboU=;
        b=IQtAH1dzu8Xxxx4ti42jbpZJ84J6PQZ6afjtE8+SpUz4aCK9JANBCKk1/gXmsSg7AC
         gGsh7r0RI0mrJPhv0ldiULO8DlSzVTomjukpJpumGDjsWL8Rr2qVMx/84qkxC6O+bdk+
         ZShnIM5Q/g0E8SZIvwBNbUdwDEFNj7+06B64cnkeGXTbqfizn1QCU1ixWbPIlhcJjXis
         GYRiDLNE+LykyE0mvZlcDZXZIru9yB7e5V76zipK8J3IcjWh8hMfpBLMlRSsXnb2A69I
         fmsqjfs8zvQu8ULgVZw7Bxfl8ZcQec62Qh4Z1VJabfchCpBBPro3NfbO8N6Q2F+2TpZe
         kMNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YsRnWbco/CvDFLAzwR9esWVfATaiIBK925UGmL4oboU=;
        b=h2bUappqo8AI+XYOMXamJFXavgwe5jOWsvAEbaNmvGgbSnLmf96k5tjpBaJ209AlNe
         JhrC1n3GhyMWFR4I5XfGREboLGAVGvorfH7qfJrWtCA18GLSQFxi0TKGEI/Vw2fZIkQo
         4kNOnn3FKszux/tjHY6GucFQdP6ch9j+9aTz6B0dhZb/eYo0mji3+a2jik+8hCgnbIKd
         EV4j9NIrM96+3QfN1QMDAvZJNx5mTFLbi821aV6gX/JzhiyYthsI5N97H/igna+FbCJh
         gJnGYPrP2p1sNNyVFr9v8mmRnFho6/iqCuHoGbBRcAZKfsXleEX/DCWhd9iu2xAAeBIn
         ytBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YsRnWbco/CvDFLAzwR9esWVfATaiIBK925UGmL4oboU=;
        b=3NlWsqg6IDxMJvrPd0GV7Nv29/kXiAR+SSvrF8RNdj5y5HMQMJH/X1xxmwQ9+2sgr6
         WfVg+9MOa2/pzxGL2WRTOitp5LYGlydxc2Gj2vdrlF/gcrpDNDLcDvzKSFeQB2lQTSNm
         ZxGNZA0UmDYw9yi3l1pJZbVc3YJTZoInOavK0QT9S7rP76u4gyqlWN0el5vOWxmeBjnv
         OrnDS7m1gd+/UuFkHZYj29BOdYUwu92o+4vYcaqqLKrN6ubWVnhHg8z0I8T48AoNPzZm
         CAydciwgCF3Bmkqtm5ItgCa9pJ40vA9lEInBvO5B5atfeWiVb6ShWGs9hI5gG3EtWWYl
         1vhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk1v94tWpTtOZhInSeELMp1h9PJrLeKM/Jz7Dq1y2lQKXi6Cv6Y
	1jtG1XmYT7kbxp/4H/ZPjoE=
X-Google-Smtp-Source: AA0mqf7SDOeS2qvgSGlApZtASplXXZTTi9pbh62sOZvwvYELHD10FW1veOm2j6bCLcrpkyyKVUtqGA==
X-Received: by 2002:a6b:c411:0:b0:6dd:dac4:7d4d with SMTP id y17-20020a6bc411000000b006dddac47d4dmr7270772ioa.208.1669287433361;
        Thu, 24 Nov 2022 02:57:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:cc4:b0:302:beaf:a2f5 with SMTP id
 c4-20020a056e020cc400b00302beafa2f5ls237724ilj.5.-pod-prod-gmail; Thu, 24 Nov
 2022 02:57:12 -0800 (PST)
X-Received: by 2002:a05:6e02:12c2:b0:302:e38e:761b with SMTP id i2-20020a056e0212c200b00302e38e761bmr2498079ilm.61.1669287432814;
        Thu, 24 Nov 2022 02:57:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669287432; cv=none;
        d=google.com; s=arc-20160816;
        b=tS8GIRe91LlgGOVQzoZWbe7lM4XCcydzOB7dUUt9DWr4anjnEfrpG3pDcEl+H03Qoy
         dYqTOAwmtJqWGRcLfDXAblBhPfvm5sNR2yDRmdPyk4mt6tF2B7i9ICC3aXiCEPfehK7b
         YHXoqPSX4MTNeRUKsELFhxq7bmkdSrIE5pz9XApzEAOwXpB41orhR0dJaxOz4GkZThx7
         Lg+XIp8WlWzz3Zdgk+eHWNLtkEbyMWZI2Z0keQx4EiC9rGXWNXctNAJBdBNUA9v1VqrF
         8fSRO2fnhGj2ep+CX4tl5oWjXELnMEwuIQ21NAedwsK1LCq59dNLLVswn/wVS0ddYBm6
         txlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DvR5jjAQ32QrpwiKXRFx0nsQpDhgkCSnhCfnlCZrw8c=;
        b=kED5RlwN+Bn5TiheJLFOgZvZ2LZzUdxF/ElQxfseBiB3oeo18XIu7WdaoPPengoA5h
         Iw8PDP0Bw0QjqphFPohJWUleasgbcQRqCFSWFXyOs3S3rSHGxtblZchDrjqnCeFob4ps
         a1yP+skv/R5qm6xvZF0hWg8drF+0iSF3Y7YR691I9M+LpaT9q9No9oTJWFrWNZ1o98og
         T9uy6+dlH+1LhxPL+2u+J5lUle54Ps3ke6MvKXmrCRjIPLk19h/OpymUINEr9up14A16
         hvmYDRChZcTAr7c5ANmm4/YRfSpaPCbbyJU8EL/lPuzzT9klqnDGxl/K+9lp1akDE7RW
         8nPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Wt6hrqGp;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id z2-20020a02cea2000000b003636f49184dsi52200jaq.7.2022.11.24.02.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Nov 2022 02:57:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id 9so1318267pfx.11
        for <kasan-dev@googlegroups.com>; Thu, 24 Nov 2022 02:57:12 -0800 (PST)
X-Received: by 2002:a62:54c2:0:b0:56b:fb4f:3d7c with SMTP id i185-20020a6254c2000000b0056bfb4f3d7cmr34951232pfb.54.1669287432162;
        Thu, 24 Nov 2022 02:57:12 -0800 (PST)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id c4-20020a17090a674400b002189ab866bfsm2956687pjm.5.2022.11.24.02.57.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Nov 2022 02:57:11 -0800 (PST)
Date: Thu, 24 Nov 2022 19:57:04 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 -next 1/2] mm/slb: add is_kmalloc_cache() helper
 function
Message-ID: <Y39OAFcm6svORad4@hyeyoo>
References: <20221123123159.2325763-1-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221123123159.2325763-1-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Wt6hrqGp;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Nov 23, 2022 at 08:31:58PM +0800, Feng Tang wrote:
> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
> kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
> kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
> dedicated kmalloc caches).
> 
> Add a helper inline function for other components like kasan to
> simplify code.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
> changlog:
>   
>   since v1:
>   * don't use macro for the helper (Andrew Morton)
>   * place the inline function in mm/slb.h to solve data structure
>     definition issue (Vlastimil Babka)
> 
>  mm/slab.h | 8 ++++++++
>  1 file changed, 8 insertions(+)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index e3b3231af742..0d72fd62751a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -325,6 +325,14 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
>  }
>  #endif
>  
> +static inline bool is_kmalloc_cache(struct kmem_cache *s)
> +{
> +#ifndef CONFIG_SLOB
> +	return (s->flags & SLAB_KMALLOC);
> +#else
> +	return false;
> +#endif
> +}
>  
>  /* Legal flag mask for kmem_cache_create(), for various configurations */
>  #define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \
> -- 
> 2.34.1

With Vlastimil's comment:

Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y39OAFcm6svORad4%40hyeyoo.
