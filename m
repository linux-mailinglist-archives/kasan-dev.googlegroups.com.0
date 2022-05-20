Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOUNTWKAMGQEGD6GSJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A4C8052E66D
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 09:43:54 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id z5-20020a5d4d05000000b0020e6457f2b4sf1914306wrt.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 00:43:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653032634; cv=pass;
        d=google.com; s=arc-20160816;
        b=QEqF06vfvxq9dT2FlJkATXX/wMvAT5Hn+T8yip77/s2JC/f9XarmCCQiNkeT2QnKvk
         qh4W1gO26Lb8g2LPJi7MgqctjgDwsCoG8I3d5bIlqBku/MEOgSfbUqbSGIkvXvaXAnoY
         BQOvWwnJt3mo7koli3UJxOPzkBZVSkbsBLM0m4ohmpILKwDTute9wmmEOMeU732WCii7
         lWW9L6kNwnVIfLwH82lZbj7VYktmIeBjU7UcDmpKuPx0h3uhMgSNtEEPWGI3JRH7e5Op
         4/DdgSPuRWTVxaI5W0Bl4z+f8In+VzW94RhEJZqecnICefElh2pSczW9MVN1FgG3IMBV
         z+GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UzJMzggvQTyWB3SQn63Es5usZXLfp0ML2Xh+yRm7TH4=;
        b=UihFIAx96kRhBRZcF1nBGI8j16gOPhw0ove36fejOcm/iTs1fcSK33Y2Xg6yi9cqon
         lOKoO7HQ92YjmfskgJTKjSor2EWlBALdG/z48gIFfnrHMPJzve3QOSOdtBRJ+RJ6KK2Y
         MM01TdSQgTih/1MBxVzPuUHILRBvkR6LUdqhDaGi59gTPLbI/sF3/l2cUailX5EoEvmM
         00Bxns6KccrPR0tYy1wQvpnSdK1M8qZJAa/XQAmu1FKusLEpIvQa1N5vtokRq951DiD/
         KB5A1WH9CaYmC2ehwmXstxBFBRllfg/8RAX8eNAcKyDyk8wgZOeAS+TdTF4Y2+i9rv7X
         OZxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B2pSvrOk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UzJMzggvQTyWB3SQn63Es5usZXLfp0ML2Xh+yRm7TH4=;
        b=Gz/Afs6m2YatEGCr1rSgfepnBromf4Zfag91+UTTToH3lp+xX8dscHrGxiHe5Gvg0/
         ooZ4D0OFxY4RFD5UhgziX4zj9Nrn37TvLPaTpwAhUjZcSut+xah1fOBZJpoYLc8nwymZ
         m+4P3KDs5AAAp01B+a4ttisv8KoCMPsnJ9VyBF5AaauogQwDJ5OFLcuOhAi5z8zsRi9R
         n8Mti29X2Uv/T1MlX2midaJAf+GTxTroT5GD/cWwgAcqA1luvxYTg/KmUMq7w9MVXkdU
         OtKi6kEiBpsM0f7QEjNOqOoj0CGXuSjGwGWFXhcVIvCOXGXZXEfWepzTaMxRyH1YdvJB
         cT+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UzJMzggvQTyWB3SQn63Es5usZXLfp0ML2Xh+yRm7TH4=;
        b=dk2awZJVMrFd9kuF+bYHyuWgPiQDPUs77TyfLJjXQNsQo9HjWzZZaGgDopQPnvSeyq
         e8Ngs+b5OWX9TNmL4IQnGMOMa6FjjBiDSDX/HY99UBJ0ft+1EOsef4Mtg/v3IWaVDRuG
         9UhEtRgnN13EayMCNSE2a4N9i6MEEJmGHQNslsC5oKVihCr4Y6UBIseoDJgv2tpL2hUa
         rSNlIU9vLt22/71RWBVSGEFCyWalcaBglMqTdKBE7ZcTWu0vjnES4hxjaoW1IplL6kig
         HzaQ4r1BfkWURv8SpI+y94OllmFYo3HNhij7e7Q0caBGfsPZm0iiiGIb1MI1+t1hFALo
         3OaQ==
X-Gm-Message-State: AOAM530pI5nJY/XNgAYxCR24MssZtrJP/c6Xa8NA4u+ij7SO8QNffVRS
	6B3sbz2PHAFoMQR1HqYw56U=
X-Google-Smtp-Source: ABdhPJwCWKwbLm2/UinSJu+Ka4cqnoP+6ivIuUqXE7i3VNIULVWG39FcQqKBApkg299/5HyyT/mTgw==
X-Received: by 2002:adf:e385:0:b0:20d:daf:c117 with SMTP id e5-20020adfe385000000b0020d0dafc117mr7134616wrm.545.1653032634371;
        Fri, 20 May 2022 00:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d9f:b0:394:51e4:7b18 with SMTP id
 p31-20020a05600c1d9f00b0039451e47b18ls5150761wms.0.canary-gmail; Fri, 20 May
 2022 00:43:53 -0700 (PDT)
X-Received: by 2002:a1c:a185:0:b0:392:206d:209d with SMTP id k127-20020a1ca185000000b00392206d209dmr6740177wme.168.1653032633106;
        Fri, 20 May 2022 00:43:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653032633; cv=none;
        d=google.com; s=arc-20160816;
        b=L0WpKrAGS+ZIOsSKRYazHHf/riy19dvcdwvv6Q8LUFTyTU/xa7Ih6A8m1VijIStIx9
         qGwhnIOKW23YroA4OeTLM6n1ggiAQunp5YAv9CUq+NnWBso8RQzt2gw0+aM+OfKiGFS/
         E2SfVmm1f+tKwaGeWmeijyqdPITeMZu7GRGwNjYF8skRrtMlBERMLyz26szDky2u3rzx
         z9MMTsSzwHa9i+dziNkJNOERxU2Q52aEoPQeoE+ukeI32HQgsXQcTyh5I3/PlbyvO02H
         r6ZEQuxYqDoWkBe2k7Z1iMW2Rx6dpqKmeu1/+uSRiJy8A84dEos6Ah7egegdlVliFNK1
         wmBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=R+xTlbVgKdrZc+/7f/CN0UJSdf1T+UIc9vh0/IvStRY=;
        b=iYyI2tdeuMIWrJaNz54+oYzzKp5tFx82TuE+rc/MbUEdtrA8TQ8IDV7G96kLKGCFQx
         ecjDppTLKzFqZ/xZXGOjPjiShd1cHGc046pO/B13gkfFoQnddTU7MrVS5pJDchek759W
         iCpaZNJFPPWnDETfboQ6990gISfo2+e9U+HJ2T8RG2fKrczwjROiJvkagOQENR7wHQ26
         donBrYKmswzIlYX7sZ1Dcu7lay1NHEcjnMyYR8vk0Nrc+235WIQyi62KWzlGsdQasA4P
         mOyUyzScyXSEdq9T3FfyBQK1VfEDgsGlWqzsVa/jcwUBD/8ffzSmZ14ddySca5FxyQRk
         YTUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B2pSvrOk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id n189-20020a1c27c6000000b0038ebc691b17si85723wmn.2.2022.05.20.00.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 May 2022 00:43:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id t6so10308956wra.4
        for <kasan-dev@googlegroups.com>; Fri, 20 May 2022 00:43:53 -0700 (PDT)
X-Received: by 2002:a05:6000:1e08:b0:20f:1b8c:799 with SMTP id bj8-20020a0560001e0800b0020f1b8c0799mr1136247wrb.716.1653032632688;
        Fri, 20 May 2022 00:43:52 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4060:dc55:7d4:3443])
        by smtp.gmail.com with ESMTPSA id u6-20020adfc646000000b0020d0c48d135sm1763904wrg.15.2022.05.20.00.43.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 May 2022 00:43:52 -0700 (PDT)
Date: Fri, 20 May 2022 09:43:46 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] mm: kfence: Use PAGE_ALIGNED helper
Message-ID: <YodGstrh0kfh0o1j@elver.google.com>
References: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=B2pSvrOk;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, May 20, 2022 at 10:18AM +0800, 'Kefeng Wang' via kasan-dev wrote:
> Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/kfence_test.c | 5 ++---
>  1 file changed, 2 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 96206a4ee9ab..a97bffe0cc3e 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -296,10 +296,9 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>  
>  			if (policy == ALLOCATE_ANY)
>  				return alloc;
> -			if (policy == ALLOCATE_LEFT && IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
> +			if (policy == ALLOCATE_LEFT && PAGE_ALIGNED(alloc))
>  				return alloc;
> -			if (policy == ALLOCATE_RIGHT &&
> -			    !IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
> +			if (policy == ALLOCATE_RIGHT && !PAGE_ALIGNED(alloc))
>  				return alloc;
>  		} else if (policy == ALLOCATE_NONE)
>  			return alloc;
> -- 
> 2.35.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YodGstrh0kfh0o1j%40elver.google.com.
