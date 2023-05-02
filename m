Return-Path: <kasan-dev+bncBCLL3W4IUEDRBDEOYSRAMGQEBJOQKQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A4A176F4438
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 14:50:21 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4ec81706fc9sf2155419e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 05:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683031821; cv=pass;
        d=google.com; s=arc-20160816;
        b=E/PyuWOkuBQv5Hk7WiXtOznMtJrrz90SwpBykgPNR2QDyY5DrzzoZxRoO7V2oFWAFp
         YGUGoPy3vafP/4i9Oc4cL6g+psn/x4TpWVtVOKV/xLY2zzXHKrmoov+j+TFgR2mVLHzx
         gzmbyPWqTH6OPjLbIcYSfwvRi6cNBOP9dXCB+bLcPuxP7XinwcKdWbGl0j8GdVsG3a1E
         059Nf9PqT5Q+Iq8Ba9RPvlx52MJ5GwIxrGBVrxVgXhgm5SMCx13+W6tIQZ+VXaHqJYwd
         Qq316VsmcGdJumUCYkU3PtIZdnpnsX5JYouJqhAg2bpf8U8j/6kNaoFl7PuZlQ9w7QeM
         rNNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=S9Gaa6ZiPp1nZQkU7Vjk5qiEFyFN+Fm9eOo3wT52+N8=;
        b=Ux3Z+0nUspK8yOQaGHJNycrXyK/6bQpOqj4AQFnERhVNiTj1ystWtq544viYXFgmv8
         obmDww2fAzC4YLi40DHKlfNnN1zkswvAGb284SqtTO23pU9GyPTRU4i+TrOnNhHCiiO6
         jAixeLhSpN1tliVXIa8w48euhVujBaWF/o72aZbYbtV++NYTi7e1O1KrhQY21V6VPHl6
         oBjKvwD2DRTQR05tbVg0U+oeVILgke3borhjCkhVDf4BCtTOWd51lFTarYeuVyyRAYPR
         /8LOWPvkjglmVtOfujSkAHLZZC/sM4gUwh8iQWYThA3BAiIkhrMIMN8GIDk8fi4RXQGL
         z+qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=LdYat1px;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683031821; x=1685623821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S9Gaa6ZiPp1nZQkU7Vjk5qiEFyFN+Fm9eOo3wT52+N8=;
        b=rc2sSxSBRZwypgxFe28IsHieWAEvHLlcf4oMJriozl0LTBYbQiO5huj7t87cEkwmzT
         pOi2GVPZ55dcKHU3eiud8b159zFnMl3v/nOC500XfmAwrL2D7me6l6znV7/7a+HdaoBp
         nyybY5P5uvknav8FCwdOpuCRehMf7sIFaE3Gc6fawWwZt5EIPMlkAgOrpVVlHl8N4dMT
         6bmp/Pu5hOZhXInFS64jJ/rGBZEcXkRLpy6qlebteIf1PimGvBpozEYpxNpcxvTccjuj
         y35B6cSbBIF/OaK3TECJwH+6ziB4/rRp9bOHUUiazzAuwVZh3qP7ZCFZWMmdFgiOSmsU
         kaUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683031821; x=1685623821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S9Gaa6ZiPp1nZQkU7Vjk5qiEFyFN+Fm9eOo3wT52+N8=;
        b=YHBQqBw3BJZfRQg05CbLDkhxhqUQaJsZiOduRaGhZ8rqco9duJSsYrOycANvSreYH1
         epTvMoZctdjrzre31J1/XiZ5Jf13WTxD79tylhQ/EzqxdbCbvH0KXZKdzMLCY7JfzmBg
         BisYpC52+HHNW/uBiDRzU5ChcneCG/rk3CDHIWc4dbqNShku5vbi/shzrfmFeWPP9Lnr
         npsfTIZaaRliV2o0La9cGeNY2AcMU7UxyPZQNJH1wSUSHe2sh3y9ZFzRdzbiM2LEc3cq
         N/sAq3W/1+C4zgxfkwbcZiMpuB12fq4OALL/5PfpV1IU+392iBcrWsXGWqN1v6O3oFo5
         BBog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyKecK16G3erHQDY+yhF/yakEqiIEsM/O6aYUbqN0R9imN1aAYV
	dlZ/+w+lb8nMzSsUq5dtdgA=
X-Google-Smtp-Source: ACHHUZ4UzSNJMYbmfg1cCtbWaZAVRvjzFZr/VSFQCS5fLfeKNrhuYARYMt0SCYpA7AfJX4ve6Xy34g==
X-Received: by 2002:a19:f00a:0:b0:4eb:1316:a2e6 with SMTP id p10-20020a19f00a000000b004eb1316a2e6mr4102678lfc.3.1683031820762;
        Tue, 02 May 2023 05:50:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls171863lfb.0.-pod-prod-gmail; Tue, 02
 May 2023 05:50:19 -0700 (PDT)
X-Received: by 2002:a19:ae05:0:b0:4ea:e5b9:23b7 with SMTP id f5-20020a19ae05000000b004eae5b923b7mr4661130lfc.2.1683031819434;
        Tue, 02 May 2023 05:50:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683031819; cv=none;
        d=google.com; s=arc-20160816;
        b=WBxFTd4FPvXItXmrFU2UVwQggNTG4TmS3N/CJm3xh9hPpGslfe0HSSLSQ4O/sZ6wOT
         xLHjliPy4dX3Xle+303oa0+BODr+lv4rTaa5uKwIfkCUG8Lj3FcxjvQoaWx/FX4H+eLD
         RFOlKdlEc4nugIb8BSSvBav6jmPLWdGOivx5yffZs5wLbVjqcq91LKBQ+XXVu8yQaF+x
         tDv0OnOdyDn1JJF19Kclqq/j7DoyROzT6FtnLcAn77nk+FrvjVAvcPo68woYse7l2ne6
         LIh3Q8vc7ehXM2BHlMEBCPD0GwS6MdQQX0Nqkv8UNBhVQK8mOa8Yp10exHkFJaCMwmIu
         agcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XG4/MRaALQe6dh4kRVLQlZNXSEwHyBhmmZ+RRh7Abac=;
        b=Jw/EhpQf6BMftnkGBzGVcV7shZ6dUdYdjhy/Tr47NrqVPymeZ8GZ1tJIxCi37NEx07
         F7BwVbEO46B22sXGgN58fsWAICejOxFstMCTVWbV+EzqMejktoKbl1A7L10lgbytdxIs
         uN+0RK2d1tp9wP+6X6ljkOGSxOKG/H+q2tTGOV/H9Dctm8DoVAmd3/jQMmz0vmtNIJS2
         auO38RUSWBIbhS5lfAYfnchWQEjhrTvYLfLMmkiJPU61adsYlY97aiigAhoSNoAk8fLG
         wKhJJa+k8PMihjDqnQ3yL6cTFtK1IbDi4ACKEJV1K/Z2aWdJuGA+xb0qzL3cCRCTD4a/
         yRzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=LdYat1px;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id b33-20020a0565120ba100b004dd8416c0d6si1977381lfv.0.2023.05.02.05.50.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 05:50:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 11C1F14D391;
	Tue,  2 May 2023 14:50:16 +0200 (CEST)
Date: Tue, 2 May 2023 14:50:14 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 09/40] mm: introduce __GFP_NO_OBJ_EXT flag to
 selectively prevent slabobj_ext creation
Message-ID: <20230502145014.24b28e64@meshulam.tesarici.cz>
In-Reply-To: <20230501165450.15352-10-surenb@google.com>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-10-surenb@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=LdYat1px;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Mon,  1 May 2023 09:54:19 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
> when allocating slabobj_ext on a slab.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/gfp_types.h | 12 ++++++++++--
>  1 file changed, 10 insertions(+), 2 deletions(-)
> 
> diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> index 6583a58670c5..aab1959130f9 100644
> --- a/include/linux/gfp_types.h
> +++ b/include/linux/gfp_types.h
> @@ -53,8 +53,13 @@ typedef unsigned int __bitwise gfp_t;
>  #define ___GFP_SKIP_ZERO	0
>  #define ___GFP_SKIP_KASAN	0
>  #endif
> +#ifdef CONFIG_SLAB_OBJ_EXT
> +#define ___GFP_NO_OBJ_EXT       0x4000000u
> +#else
> +#define ___GFP_NO_OBJ_EXT       0
> +#endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP	0x4000000u
> +#define ___GFP_NOLOCKDEP	0x8000000u

So now we have two flags that depend on config options, but the first
one is always allocated in fact. I wonder if you could use an enum to
let the compiler allocate bits. Something similar to what Muchun Song
did with section flags.

See commit ed7802dd48f7a507213cbb95bb4c6f1fe134eb5d for reference.

>  #else
>  #define ___GFP_NOLOCKDEP	0
>  #endif
> @@ -99,12 +104,15 @@ typedef unsigned int __bitwise gfp_t;
>   * node with no fallbacks or placement policy enforcements.
>   *
>   * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
> + *
> + * %__GFP_NO_OBJ_EXT causes slab allocation to have no object
> extension. */
>  #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
>  #define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
>  #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
>  #define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
>  #define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)
> +#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
>  
>  /**
>   * DOC: Watermark modifiers
> @@ -249,7 +257,7 @@ typedef unsigned int __bitwise gfp_t;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>  
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))

If the above suggestion is implemented, this could be changed to
something like __GFP_LAST_BIT (the enum's last identifier).

Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230502145014.24b28e64%40meshulam.tesarici.cz.
