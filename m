Return-Path: <kasan-dev+bncBCC4R4GWXQHBB6W5RT5QKGQEDD5PLDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05CC126D7D4
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:40:12 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id j4sf187946uan.16
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 02:40:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600335611; cv=pass;
        d=google.com; s=arc-20160816;
        b=x/d1RrHKMczm3+aptZsKGsIk0KeCUdUXaFZ2g4AgeZwyZTnqKcaG+eCVfQcLq38647
         vELNg3BT00898NnwXE2/k8SDXtZy7XGvRbnnDEDzKAKDfh5RHw/gWAG7iIKaUOO2Xhbr
         CanvDi41azB/W3CuIfNknStcKwLR+Mn58B8L9gnGSB7B2NPCNQiqDuLV5KSBk63AkLFD
         1zoEZbokmlc5Dd/rcaxNSL7WjYH9Yr538vcb+yPl1vaEDUQQ0taSrkl4jdxh9IDrU855
         lbQMEuMAVDAYE87xyU9cv+9gLpSGDD4Pusp0/UxMWRt8zbMFmYz9ckCfe2iZ7V3AnX5y
         o15w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rt+wZy8AndfusXAMH9/h1/ksuVbYEFI55iooEI89sl8=;
        b=0SQKwPIV6C1JKNpqiTcq+LgeTD12ir/fvPDLeselAbFt0c5BVjm06WPf3YaHYRP8pT
         o/K1Gpj8gH19OoUA9AKKhwSK5+cpieQi+3nSwmVgvtUu8x7sn1jwiiengt+uVfM+4ae4
         8qfJu3zWzQSfo3hQFSnTtnTBTemJWX4681Mf9eZjMvarFHhB4hySnWn6YNvIY4hCCngs
         WB6TepRIc5N1qcSUCV0nmlWESW5A6k9kVZTALBen9tyDWZkKdhondFDCk09wcS77M+98
         ChUYZf1Si+S40Gpx/5eKSfrgvjAKyOyi3UJg3CPUg7xma+KGQ5JFiizSMkKLAH564qSt
         gpfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rt+wZy8AndfusXAMH9/h1/ksuVbYEFI55iooEI89sl8=;
        b=VszOMv06rCKuqL9tArK7bKpMF3HX/DA0I6ffJpZpvOgXpgYyTQIipngSjsTjh7c+1i
         iIfdKUYHdjFxgvzJSHs7aO63LleAlIKWpDaN2csfqx47V3is4+EbbDZZBXUVhJwOX2ns
         ADb1scyxizSea3Ok+r6vxPKCDGLs6iGsj6Kj/rLx9LO2D6HG+7Af/epdW/swolGRJ90k
         LEm3g4TS4EEJdqnlhq1trgynwhYE6DbnciniSGTq+ogSnqnWpDPTzXN02cxkafUHGqHL
         NtRgxqobegeNsk4hwSqRXdhACHHv9ty5UvCvqTl12BybS/jFcT1vpqQ+jT92d3sDFKt3
         hwNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rt+wZy8AndfusXAMH9/h1/ksuVbYEFI55iooEI89sl8=;
        b=C5le2MW10uDaVCmthApBuz7WDi2/DTfHW+3tsSYWrdRrbcd1bGgSxfxXGEpKSCDr0A
         oE5/Av3vlhzl1gD30/h5IXqmM7WWjdvrzq6ZVNu9nDnRbi5tVaIk42B8CGBcS8duYrzz
         h3GeFVZMlvc63asXEro97gmlXx1xy40l1iL0wIk4LbvMoyaIlJ+rkJ6bU9mYLzPSGYAJ
         zw7HIQq2o3aRvxDw7Y5hB6UiNqlmLyOQXLout9fxzsH/Zn657gxG0fVfCdnlgCLdWuZe
         GDCR79HAc9rVmH8q+1do3bvmTrHqL840Hk/3+KUsyJu3Ft4pfjt89kGo8raoW/2glc1A
         7meQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531M6aS1M/zhW67Ramm/Nr1qmu8CEUHRPLgIQ2Z0rk4utZacmwv9
	vaFN+HG2DnMJZmHfxP7FAj8=
X-Google-Smtp-Source: ABdhPJyNmnsgQ52yTJaS64f5VUDNk5weivHp2eG1AmHdO7/z3AhTHyzT6d5FcXJ+Bv5EXsN7E9NMtQ==
X-Received: by 2002:ab0:393:: with SMTP id 19mr15130333uau.51.1600335610848;
        Thu, 17 Sep 2020 02:40:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls153365vsd.9.gmail; Thu, 17 Sep
 2020 02:40:10 -0700 (PDT)
X-Received: by 2002:a67:7948:: with SMTP id u69mr8644560vsc.30.1600335610375;
        Thu, 17 Sep 2020 02:40:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600335610; cv=none;
        d=google.com; s=arc-20160816;
        b=jIOGw+xP/AJEVJ9mIYTzmKJvfuNjzdO+49ubfAk+3bu2Y0kNRI98015KGJb7NxSW8c
         D0Wkl9GMt82zj79m6/bFaas8j//9n2v3OMHxy2ckLE6hdRJNDSyX8SSTIGYOZhmO3LuA
         62ZRGpcHyI47/g/dcOiKdswOciIXMuKMhvG4RhCA2X/lbOF0yyPItcSlwCi0Yr4is0JT
         b/QHn40Pxci/8T6+Sdn/muySOi/4F3XE5AOPiQJ0efqufKKN0zOmizxu1gb7yz0fA0IW
         mvL8omdjfNblsHCrKMYgIRm6LrYxfV8iO7QP+lmWYzham4flLXu4Q75gGGCi43VovJtz
         cCjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=5/PD4HsTGZOsCxTZ8k6JUAt6yUp9v1gnBHtopj8cz+s=;
        b=ASoEVpNcPizUcdQAtMYD9BCWVM+ZhSQm3OFZ+fJrqz8iNnLvYeTHQcZY88/Au0KhAU
         Jz9tBQmPg7EN6Ank8485JodQvlbf5uGAuW0hLurrTosJW7cHycQWXyOovWA8vkVivwBL
         LlhmmzuoDMdzpzLcbXbvc3vQkl4QsZqDmKJOxkjgQ4M2COgPy0ydAo++//p5SKghVLks
         BarHdJc0AeZaszENKQKvDY/MX9qRrCHw3uCQk67UpveuWU8c8w/IGQdFm298cPzufb9I
         yrOVZB0AqYSCwdy/Wu9p292I1VZCnvI6DC4b0nbhlxzLAYgjH2Zh/RFRy6AvEuiSPkrV
         JN3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
Received: from gentwo.org (gentwo.org. [3.19.106.255])
        by gmr-mx.google.com with ESMTPS id y65si1410882vkf.1.2020.09.17.02.40.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Sep 2020 02:40:10 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) client-ip=3.19.106.255;
Received: by gentwo.org (Postfix, from userid 1002)
	id B22FE3F0AD; Thu, 17 Sep 2020 09:40:09 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id AFE5B3F0AB;
	Thu, 17 Sep 2020 09:40:09 +0000 (UTC)
Date: Thu, 17 Sep 2020 09:40:09 +0000 (UTC)
From: Christopher Lameter <cl@linux.com>
X-X-Sender: cl@www.lameter.com
To: Marco Elver <elver@google.com>
cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com, 
    paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com, 
    luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com, 
    dave.hansen@linux.intel.com, rientjes@google.com, dvyukov@google.com, 
    edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com, 
    jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
    iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
    penberg@kernel.org, peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, 
    vbabka@suse.cz, will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
    linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
    linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v2 05/10] mm, kfence: insert KFENCE hooks for SLUB
In-Reply-To: <20200915132046.3332537-6-elver@google.com>
Message-ID: <alpine.DEB.2.22.394.2009170938030.1492@www.lameter.com>
References: <20200915132046.3332537-1-elver@google.com> <20200915132046.3332537-6-elver@google.com>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@linux.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning cl@linux.com does not designate
 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
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

On Tue, 15 Sep 2020, Marco Elver wrote:

>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
>  {
> -	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
> +	void *ret = slab_alloc(s, gfpflags, _RET_IP_, s->object_size);

The additional size parameter is a part of a struct kmem_cache that is
already passed to the function. Why does the parameter list need to be
expanded?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2009170938030.1492%40www.lameter.com.
