Return-Path: <kasan-dev+bncBCT4XGV33UIBBNW35ONAMGQE6XPWX5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2526102FD
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 22:44:39 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v125-20020a1cac83000000b003bd44dc5242sf3286692wme.7
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 13:44:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666903479; cv=pass;
        d=google.com; s=arc-20160816;
        b=n0wJQMGQ8rKZn76CyK0ZJAXHngy8NXboik03uaAGY99Roedi6c3VSD99LRRmJiZoZi
         BDI4vWTJU+xdwX3YgFR6G84d38y9QLvyHhI2OX1ICd9oQwghXSNjsmG8XV1QEjKJQpCQ
         2MZn/SgK7msePivUja7CVPYEQ2wtDi+tbjpR70HXuJInVT7Tn46cf47+1oi3i/8VtC29
         IkLHxjKnrxvICdfyJxvEy7xZs8uwdH5u3c5Bma9bSPNvsAqge4AuGSPYwhVwmsr7xg9W
         qRUOzRNH8DYqADxmr80kjQnfp0dypmzC2K7Rnujf2IzmVpNtZyI4ACGTq5u66MVXDzhb
         CRtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5PQuuU5FSjLKEvFCtLgqJJ27SMhqwYRAXfI85xRFews=;
        b=CubpnZukecjNeF+8ch1cPK1b4HZqXKpniMKuGM+RLPsZgN4umHYkqLocFZ+4xW4ChM
         v+a+zZ/dKc1u35onCIbghHaAGzTEY5RjDVtorIYX/e7Kf2mpNDHMlHgXhbcrPNUCDTC6
         LQMNddki70QK02r2o+1c1m3eYYQL64r9UYtzWM7RakZl4PBQlVEHvGgyOK8bcwSThzk0
         VGDlazTX3ijQARxouzcxA09A0Sz7foiIJPLioG+WI8FnNK/wtEWISjjRoIq0oki3Em3N
         6G3u0Z+K9RdNuTk6RXCqGpp1yPjY2h7Pg6OL67qGu03VVFpPOhxAIbl/5M3X5hiF7CS6
         AaaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cwgeAse8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5PQuuU5FSjLKEvFCtLgqJJ27SMhqwYRAXfI85xRFews=;
        b=dLtqj/b7Y7bA/K9YE2bmeR5xNDHmj+HcX5Khv7JZM2436Tcbbg91VFNgnXdzxmMovf
         dD88Enxs2xBev2NrBMFmj2mgcFq+g7WYAdiKI+Vv/013sX8lBffrGcuGFRHNqd5s839m
         deX66NvLB3fX0X/4lqzVEDMnqOQKGFZjdpKh3gfpMXmZqSZYCks/zZKAJfNbxAQGW082
         UnuIlRXJBVMLtnrXz71e7c+fVFxXRkRTGAlQFIerJieWEmz98dVIZHUjxT0WeI6KJiio
         wl1CWKyTqmQ6alLbvnDH+ENr1brpzDYxkKiTNvmAfHFfRcVHdrHxk6xH3gSZpqxjatKB
         ob+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5PQuuU5FSjLKEvFCtLgqJJ27SMhqwYRAXfI85xRFews=;
        b=NoXG/40EmxLzX6r2MeHaFZESq3E+BjiOQcHWY8+njKJAnxwJ21MGKGl9VJCJ0IvPYH
         /IO90WnWSSDuoUP+3XctENKI84A0DJLEHT+BmfXiFMPnyUP2imEVdCXeggbD2TcBIMi/
         3HvQdgx4OX0NNWoRvFLzxk2CD3O3qsN7JVODXzwowF6Ci0Z7WlPj/jBJhreMdmVMEZ1l
         id/dXSGaBKcmVc2u51D3L9t9nZzphdhu/xbYC1rwzQSrZtSwH00znUZAZIqaJqsBswXI
         MeSgfoX8gJ4iVWGx2t4i0SMUyl8sYG6BvkTjAXLbeUsa28AzDWHpiNXQRGg41UJgDeyS
         UGfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf03/9gE82VH+EER4sb7so8Q09RIkkc5dDv/CMkl3GjnCqoPzONQ
	e0aQrseAvb/vJbR/s9zDhyg=
X-Google-Smtp-Source: AMsMyM4xHfEW/Hk0seUoXYkOuKkk5xCxnp61HyVz2G1gtBvXXoda0qyM+2LiKKyn4v9qdzZrmkXeDw==
X-Received: by 2002:a7b:c30c:0:b0:3c6:f26a:590f with SMTP id k12-20020a7bc30c000000b003c6f26a590fmr7218193wmj.205.1666903479024;
        Thu, 27 Oct 2022 13:44:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e13:b0:236:8fa4:71d1 with SMTP id
 bj19-20020a0560001e1300b002368fa471d1ls624930wrb.1.-pod-prod-gmail; Thu, 27
 Oct 2022 13:44:37 -0700 (PDT)
X-Received: by 2002:a5d:47cb:0:b0:236:4b94:7236 with SMTP id o11-20020a5d47cb000000b002364b947236mr23828242wrc.243.1666903477745;
        Thu, 27 Oct 2022 13:44:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666903477; cv=none;
        d=google.com; s=arc-20160816;
        b=HFFTh70PQqdOOtszlMviRMo7DK/ieaNCLEi8qVdDXrjh61NtvPEYTkzex4j2iMME2F
         3N+OoFUmG120WvoN0lzvKoaicSjWfjBb4AHEWWWl+uFF6Vx7PknTuYnlk5MmvGZuNzJA
         NlLHq+58QcslDqYHw4rYfXSOkXHYMShI7vEWxIW8y3D0RYkyqnJhwdZ2YNji6CgTQSdR
         qeQLBhuKmh9AVZCR8i3WjNH1sZrr48fhdb/jSR3sag5dKmFo6x2uVNY/9XGa7OQPNCX/
         9DzuH928wHjmTSHQupnGuTT+NOuI129b4v052p5vxsY+nDvBAEBo4rpeLOCsvMALb5mk
         a1xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=eX5iswCEFEjamv9gIuEx12HIvGG8RCEeLnd91qn6Njc=;
        b=fwfUorqiYvE50kn/t+g24/4y3tQjURmGsphxNtBBnUBzD1A/m1Kr5STYD7Vj54zuV3
         qh14eptI8kvplyYZLPRZJnYfSn6RS6oTpV2MQo3NiP1I1BYaE3AOAZ68Dy+2jKCTK6/H
         akgF8VqCQisLw2hXDRMULKGFuTlSSfbSSBz3Ja+AlcLo9KAspE6oyW8ZkH51xkjX8wTd
         30H19vRR+FCDu7mtlPgXpfZhxmdReLyv/HUVJdks3KS+6O2Mau5t1WwlqvHWHq0PMvz5
         98VMAJ2fzhDWNze9+xt0PMmgUBTyDJBVPU29vOUyZ3UrnBkNU2fEHGuTATwv9/hauT+M
         YY9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cwgeAse8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f4-20020a1c3804000000b003cf537bb09esi71201wma.4.2022.10.27.13.44.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Oct 2022 13:44:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5AF86B827DA;
	Thu, 27 Oct 2022 20:44:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0051BC4FF0A;
	Thu, 27 Oct 2022 20:44:34 +0000 (UTC)
Date: Thu, 27 Oct 2022 13:44:33 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>, Evgenii
 Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>
Subject: Re: [PATCH] kasan: allow sampling page_alloc allocations for
 HW_TAGS
Message-Id: <20221027134433.61c0d75246cc68455ea6dfd2@linux-foundation.org>
In-Reply-To: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
References: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cwgeAse8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 27 Oct 2022 22:10:09 +0200 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new boot parameter called kasan.page_alloc.sample, which makes
> Hardware Tag-Based KASAN tag only every Nth page_alloc allocation.
> 
> As Hardware Tag-Based KASAN is intended to be used in production, its
> performance impact is crucial. As page_alloc allocations tend to be big,
> tagging and checking all such allocations introduces a significant
> slowdown in some testing scenarios. The new flag allows to alleviate
> that slowdown.
> 
> Enabling page_alloc sampling has a downside: KASAN will miss bad accesses
> to a page_alloc allocation that has not been tagged.
> 

The Documentation:

> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -140,6 +140,10 @@ disabling KASAN altogether or controlling its features:
>  - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
>    allocations (default: ``on``).
>  
> +- ``kasan.page_alloc.sample=<sampling frequency>`` makes KASAN tag only
> +  every Nth page_alloc allocation, where N is the value of the parameter
> +  (default: ``1``).
> +

explains what this does but not why it does it.

Let's tell people that this is here to mitigate the performance overhead.

And how is this performance impact observed?  The kernel just gets
overall slower?

If someone gets a KASAN report using this mitigation, should their next
step be to set kasan.page_alloc.sample back to 1 and rerun, in order to
get a more accurate report before reporting it upstream?  I'm thinking
"no"?

Finally, it would be helpful if the changelog were to give us some
sense of the magnitude of the impact with kasan.page_alloc.sample=1. 
Does the kernel get 3x slower?  50x?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221027134433.61c0d75246cc68455ea6dfd2%40linux-foundation.org.
