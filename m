Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBDOPQONQMGQEGLU7WPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D3E86146AD
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 10:31:59 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id i17-20020a170902cf1100b00183e2a963f5sf9763823plg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 02:31:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667295118; cv=pass;
        d=google.com; s=arc-20160816;
        b=N39tdTq4F6sDKJ29tXCUfA8+Jvykd2eNkZD0D+hVZJVSoWzh3yft1VJOpk1OrRdBbA
         F2p9HC9XienfCMgJXlyWFYrrRRE1p+Cf/vG3xlFYw6tCXo78gIddcn/eUx5GMfImxY9b
         yDld9692Cbz4oRV2BD3evFbho5PQmycvPGEXeHBi6UnMnyXGG7razQdzDsEKEwPn0tYq
         uOdVJMASif5GCxwWh41p7MTdc967DMBoA6NRx7wt+PcFLHZOjekU6dU4EELnaqyu05pZ
         uP538+B0iagavcW04fWVvFwVJ1DQmLnYWkkPvVEG0zzo8fvAhLyNl1Ye0EfBhlCC2KNw
         krWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=xzXFkWa5Bci8dt2R2VJ8kRLOLZ4ahHzXOv3pdslKv2o=;
        b=iZ97p5EQIErifrNsBT5mfHimaTWpPXKXTnpp+Zddwd2eBylL2/XP53pgX7D8an9NVf
         GRzxRVlKTUDTKNrpWk5b1yxa7stODq+M/kxWo6CHIwNKI2jvMSlqHan+AUI716yZgaho
         2lg4H3HRAmrkFaUUydFRm1lneNMwJ2rBMCLf3Xo/78vcDpdsKG8G3RUg8NV2z44X4Uch
         guqrIvZJoU4msJWHm5ftPuWbGpEoZNK2uglqVoKHf+78z+woLck7VJGDZiw1KH1NUHet
         8nkGM19QlVXDFd0BAlb1kCIb26aSAdcDXoUV8Lwxp1Jp8OszEGb39UL6f2B1uH5oyrwl
         LKxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=a4+Nyl0d;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xzXFkWa5Bci8dt2R2VJ8kRLOLZ4ahHzXOv3pdslKv2o=;
        b=Z57eXlsy8npPXsRxyhGJ8oLW1RjAw0swerQBxhuBkU9dTqV4od7qaJ7BJ4uG6EYI0Y
         ASJv4Xxu6H4HCulbXJryMN3vkFD48yjJqxEcAiQyrgsei/hSlz0FxLV7p+aDeDT4qPYu
         1srdfU2iLA3KielFuNOa8BICieufASJaaBVQ+8aX3+dYbKyr3NMfW5K/849Jcanyy0x+
         1YdGM5nFZzH4EBwDd8PfXMpX0P5vHZ1A2C3DSAn3PqO/kyW+0qYXMICHsGLqHqBT9svR
         jbYo3Hvtn7hYDXzgryrG753UTD8UPYbTnZP5i20HylftnHKtykylO+mY+yDJQMOalapU
         dglg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=xzXFkWa5Bci8dt2R2VJ8kRLOLZ4ahHzXOv3pdslKv2o=;
        b=q1TZTTMwuoY0GEW4yOxVYDWdqBt0wC2n5OFVlPqvGgf2LrJQNkVvInxYe1X07AHISC
         8eXzN+mJMX6i1E8k1Axro+q3bO2JDrAWeQXfrq7ickdq5M9S34w/7812uRNcDv6oJn5K
         /G5FA5VOWuNJYDvl4wKX2lBCWEe5Lfua3AymcuRJBYyfnlOM6x0jVg2lqZ6thzCGiAGo
         6+Ic1L6GExRo72CwB2E0iI92OtQTB3INc0bsBstVm3dg3jYoMm6dmWcs04gNQtvkxBnD
         PTdpB2FoSl+o2B5iHgd6drhVM0YZ2PgjknOegBi+Gv9ewCuVILLoNy8V19xPr+0DIHHG
         QLuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xzXFkWa5Bci8dt2R2VJ8kRLOLZ4ahHzXOv3pdslKv2o=;
        b=sEWORPmtJm5kjvxV4haDFc2CVBvfaC9Dd0neOIiDO3He62yceqr/e00og0qEsU5ipe
         DomysoMWLWuW954nC2b8la4uUeMuw2oM39Gx426fBOdyOQ6QY8yo6VLbpSECaq14NCyV
         FJxbfA55B1Uana0qccW7d92ShhiNGuRp9oQj856RqjyiWCmJmeVkMmteAPTT6yocr3bP
         9XEqJ5v4l6tK9dDZJrL/FlPsRlTaQWa0/s0fIQr8Kjrf3l1XoEJG2B4iczq0StiFewB3
         TWCJJl2xENEBjRKW6xM8p8p/NkuD9H7WlhdAbOeN24jZQIuQXM5YIpghhShJSTPKDX9P
         tS6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf23N+d7V3Zf7aspdynBGa5f+fBhG3KuXszoXotuwrsbliucJLQq
	riWV3fNLr+T1gcfQK+mggps=
X-Google-Smtp-Source: AMsMyM6k5iwZb5mcU0T9Fm+SrB2Mu7H0epmkLy675ujwuaPPxyOR7iHLMKxpWrKXu3x/GCcKSJMWqw==
X-Received: by 2002:a05:6a00:22cf:b0:56d:1c55:45d0 with SMTP id f15-20020a056a0022cf00b0056d1c5545d0mr16258176pfj.54.1667295117946;
        Tue, 01 Nov 2022 02:31:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f709:b0:178:3881:c7e3 with SMTP id
 h9-20020a170902f70900b001783881c7e3ls8643936plo.11.-pod-prod-gmail; Tue, 01
 Nov 2022 02:31:57 -0700 (PDT)
X-Received: by 2002:a17:902:aa46:b0:186:e220:11d4 with SMTP id c6-20020a170902aa4600b00186e22011d4mr18653047plr.163.1667295116983;
        Tue, 01 Nov 2022 02:31:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667295116; cv=none;
        d=google.com; s=arc-20160816;
        b=dKfqJ/twxBphvc7EY3oiLK1+6q1XJ6flGMUNrPCqkwTBBj0RD6QIKjfpTmg9E/XHUx
         LBcKPQxtQM5JEmXKISkjmvuDq3+q4H5bza0Q8WMZLFgxuYw5Ibx9Oj9lbpicrJGiv2tf
         vJ26yYJbmd+wk8JRRfTWryDtGL9xRaSKex1lyOLoHzgicQrUSiD0QMvocBjgSclEuQH/
         dl9uJ4/Uyw9u0lL9b/t4pXmQXDApHmhMwidRq70ognP48BnHOaSQG3vEnx4a71OFgGDR
         FvuRBj/8CBP3uO/0fWJZuvoXJG5+aNLODG5hxHkyVqqRBcWsSBmdwuWhDcPi5U2RqShK
         S/Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=O9VIRZCiJ5gmKs+BRWjCnVIEMt23r/xHSISakg/E7V4=;
        b=DAH+EYhOquCzZYRROh+llKqar+p8SwRX6W2kh4f6Y6erqecVWiz0QL67iW8B2DKimu
         dyBLzoaqlbU5Mm934ufx8odWFnd9AY+2ozxFexpMBgPUOZdTClZmfYU8sRWY8Iotox/Z
         iqbAx5VbhdSsaZMOoAG0v+Z2E/jOqDvHgk2CIKnURf1bUlWuORXlcQ0CjH3QPewWsYta
         dMm39HNWlsDlhwKDIWCW14isu9dfbw8jyKNfNB6l9G5GCfY6R15qbvFttPjal03oHFE0
         4P8AVuqc7ocpJno6tTnwqFZtwffoy3rptHiz29mvadPVw65iClfP2kVvnmX91Y/RnlIa
         X5mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=a4+Nyl0d;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id u198-20020a6279cf000000b0056611e6228dsi438411pfc.1.2022.11.01.02.31.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Nov 2022 02:31:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id b185so12955891pfb.9
        for <kasan-dev@googlegroups.com>; Tue, 01 Nov 2022 02:31:56 -0700 (PDT)
X-Received: by 2002:aa7:88d4:0:b0:56c:ae9d:6fdf with SMTP id k20-20020aa788d4000000b0056cae9d6fdfmr18949920pff.41.1667295116599;
        Tue, 01 Nov 2022 02:31:56 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id e25-20020aa79819000000b0056bc1d7816dsm6216189pfl.99.2022.11.01.02.31.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Nov 2022 02:31:55 -0700 (PDT)
Date: Tue, 1 Nov 2022 18:31:47 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: John Thomson <lists@johnthomson.fastmail.com.au>
Cc: Feng Tang <feng.tang@intel.com>, Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	linux-mips@vger.kernel.org
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2DngwUc7cLB0dG7@hyeyoo>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=a4+Nyl0d;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::435
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

On Tue, Nov 01, 2022 at 09:20:21AM +0000, John Thomson wrote:
> On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
> > Hi Thomson,
> >
> > Thanks for testing!
> >
> > + mips maintainer and mail list. The original report is here
> >
> > https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com/
>
> I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->object_size when (kmem_cache) s is NULL?
> If that is the case, this change is not to blame, it only exposes the issue?
> 
> I get the following dmesg (note very early NULL kmem_cache) with the below change atop v6.1-rc3:
> 
> transfer started ......................................... transfer ok, time=2.02s
> setting up elf image... OK
> jumping to kernel code
> zimage at:     80B842A0 810B4EFC
> 
> Uncompressing Linux at load address 80001000
> 
> Copy device tree to address  80B80EE0
> 
> Now, booting the kernel...
> 
> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
> [    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x0
> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> [    0.000000] printk: bootconsole [early0] enabled
> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
> 
> normal boot
> 
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 157527d7101b..10fcdf2520d2 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3410,7 +3410,13 @@ static __always_inline
>  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>  			     gfp_t gfpflags)
>  {
> -	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> +	void *ret;
> +	if (IS_ERR_OR_NULL(s)) {
> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
> +	} else {
> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> +	}
>  
>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
>  
> @@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>  
>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
>  {
> +	if (IS_ERR_OR_NULL(s))
> +		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s);
>  	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc);
> @@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
>  			   gfp_t gfpflags)
>  {
> +	if (IS_ERR_OR_NULL(s))
> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
>  	return __kmem_cache_alloc_lru(s, lru, gfpflags);
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
> 
> 
> Any hints on where kmem_cache_alloc would be being called from this early?
> I will start looking from /init/main.c around pr_notice("%s", linux_banner);

Great. Would you try calling dump_stack(); when we observed s == NULL?
That would give more information about who passed s == NULL to these
functions.

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2DngwUc7cLB0dG7%40hyeyoo.
