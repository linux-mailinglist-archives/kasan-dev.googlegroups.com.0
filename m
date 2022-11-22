Return-Path: <kasan-dev+bncBCT4XGV33UIBBA5R6WNQMGQEA3KT2LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53865634AF6
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Nov 2022 00:17:24 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id a20-20020a19ca14000000b004b4acd62a84sf6033047lfg.23
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 15:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669159043; cv=pass;
        d=google.com; s=arc-20160816;
        b=PcLKjZgnDP6Ydy0/wYxJj5NOnXhnmNIGnHNKWweDfA/vJw77LqxsQMMUlbiThJSzXB
         v2S3j7iryrsVZXIb7kQoDXLgyIlVENeaItezhNvNYuk7gfEhruW9Sx0omJSSVjJZXrex
         18vD9ATMWS1QMcPXTnv4oXeez0XsMXItOOySEoPpH9vTNicx72OW6uz97wIvChWSwwqz
         HPgJH5G698AX6mEO3KxPA6S21Lefmin4k5ur8PFxx+xK3hX/URdDo1hLQVBqEXOYLCPV
         R8FjsEDeQKc1TG4/SxgC3dIiFWsrNA3tSdP5VZthXXNSLBP9gR5g9hMdd7ZGtN5VvNki
         t05A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Rf3kqRT0vgXJCv0orhSROOF8GQb6Jfc3jaGeDzlMS4Q=;
        b=Kbk9SNw+Q6jynAWwLa/7uTA6LbFjpBu0frWOr/OyaHfz+kK3q5q9F7SOcAbs2s7Vh6
         W86HU50bTO1jXtXcLryEAU/N4MfAUXR0GnF3mE4XC+n8zzniAaR4z33F1X4S7JE6Kadb
         055Q6NmCTDhqZ1p6p9+7JkosMpIjhgcXVnssnt4ZpQ4oUafLzKRxCpcqNC7qS8RDouxJ
         sonsqVrn6bXEuz3GWkEngNIhiEvhDwoJEyK5J6HF2VK2VFZtRFMfAhmjefUuFvJJYJjR
         eUYJvaWpRyZpilJgcHoYkFjAVw0KNFrhsEuoYvJEJtPXsnxXhbjRh6DdkQ//OHyd1GG0
         m5dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uwYg2hnR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rf3kqRT0vgXJCv0orhSROOF8GQb6Jfc3jaGeDzlMS4Q=;
        b=t+hq5hskXNs3HEUe0Jzzwk8hKSQNvCG4gnn1ihis0zjHkbX0rWwO7tl8VCafHKjs7d
         p2RXFEU1fPoRfPOEXrddVr74gq61ZGLv8Z78j7ieAYxEobt/ZlL9soa2tkrn/kOz313z
         vi5a3sLwqjtargJqL8N55UEjFZv7ulanX7pORs1ZFTOiIvZoFzShqW9KX3wZhd7/PPKC
         qDXHiIH7aowPsk0I/5v6gCtT5IKHh5ZNBbsK7j6W6tPqO87tSSopoOF0sxJ2zIwUW1Tt
         Y0hqJ8lRNr8ddUeOIRBsKDV9RYYz6YZkUunvdZpDolb5rz9q0sJSprRG+CF63CgMgvq0
         sA5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rf3kqRT0vgXJCv0orhSROOF8GQb6Jfc3jaGeDzlMS4Q=;
        b=4C7qkcZpEt3OOMkzGI4TXHePg0BBPFzjCspUtqm/10TCLc69KPrV5BD82034vSp+63
         xzqw8XPiTQDBdaGzYG34wDAIeRpITNhSfUyR/xBHtZhYwChgrkD3ZZ9JHg6i+e0vmdNS
         oTvGcq7n7j7mgdteg/o9q/6DAIYP+T4MKHLQNLam29fnGhtAcB/YXlDUm8XNtnjkW9E2
         l24zqhkXuNrZWIzK0+tCix30vviJVEyzod4HKUkrIzoRd9dlSL5EEBpyyg0QxMdsbDS3
         7jOYCK10eHGxbmsTVjr1qugCT/wvtZEv03KjR1j3jYhRXzLI7XYL0nGxjPwBcBoPGgHW
         JFVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn7tsqSO7LU5Iw9sWzvEJH7xPBRLPojaumItdF0K/gbSKdT20QW
	jxQLZH+h8yYyBudgbgaHqI8=
X-Google-Smtp-Source: AA0mqf5Bh1RSYoDisx3oLWdxTlzwb/+eClE3b2XfmjGHyOeOxs6tnkPNwyws1x/yaYuwHnh3eNG1wA==
X-Received: by 2002:a05:6512:3b1e:b0:4b1:b7d0:21e4 with SMTP id f30-20020a0565123b1e00b004b1b7d021e4mr4122509lfv.72.1669159043492;
        Tue, 22 Nov 2022 15:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3603:b0:494:6c7d:cf65 with SMTP id
 f3-20020a056512360300b004946c7dcf65ls1023127lfs.2.-pod-prod-gmail; Tue, 22
 Nov 2022 15:17:21 -0800 (PST)
X-Received: by 2002:a05:6512:2989:b0:4b1:753b:e677 with SMTP id du9-20020a056512298900b004b1753be677mr8057498lfb.407.1669159041895;
        Tue, 22 Nov 2022 15:17:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669159041; cv=none;
        d=google.com; s=arc-20160816;
        b=xDa8iW6q5WvlxWGJlau5Z/Xb52qofMqvGToCMS2mwHhk2KMHhSgSdlDxeXJN26pr7r
         ENEKh5ex4spKL0LT/ytJb4/kZL9rJTKO36oRrsppaGTS94fUxJYJGDzF9aE2Fb5eocyY
         dMtx2SXCV2pQZj6XL5R0Xy2UOSEMf+axS1Oeu3lVy1yBr6VNanWyzKHAqMh2V5GzxL4e
         oW3kRM9fmvLnnUhRaaBNbNgkbifycTkkWdcke//GxFxVZurXGXuXRkhK7Z0sk9SBmu2B
         vliB9a4xZqPtPEqRLiyx7LMkC6pw0ujhcAXxHK3VsLwn5PUu0BoinmSi5PHmuobjunGw
         OXjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=M1znmgutLrCFjTkMaq+U3jKSr+3xsQnRhI7CvhGKo6U=;
        b=ayyAddahVzxF7N+Z952oUJUFjj3HELqn2P1zDeJfdYzfdU/o3kBKS17E8c/OVmRD6a
         ZRezC1Z5RxQFFDQg4hFTRQfZ00yyyNWloSwh616jeXBQXORulLRWkjbDBZxYzmF0+ILQ
         p8IWI9BPQH57yBSnjI6jOK3QTW5Tfpc/ulSMWf0P64NatL3ni5qN2UAOp5+JqlZ0PP7z
         PAr4seHqNGAej4xFDrFyljZUwMVvNmpG+NYMO1xMZl28DXcpzfnyYYX8zK1AX3b7Ux2d
         iRI9xRb6/6BGQhB3Y/50ZDvESX2nxnUF0q1gSSlCoDd9qJm0MBsiT4uNcxF2JFdyw34W
         uJjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uwYg2hnR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id h8-20020a05651c124800b0027976ad74c9si28422ljh.5.2022.11.22.15.17.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Nov 2022 15:17:21 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 38754B81D4B;
	Tue, 22 Nov 2022 23:17:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67CF4C433D7;
	Tue, 22 Nov 2022 23:17:19 +0000 (UTC)
Date: Tue, 22 Nov 2022 15:17:18 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 "Pekka Enberg" <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>, Roman Gushchin
 <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 <linux-mm@kvack.org>, <kasan-dev@googlegroups.com>,
 <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -next 1/2] mm/slab: add is_kmalloc_cache() helper macro
Message-Id: <20221122151718.4f7ffcb656dd7dc0eceb0ad2@linux-foundation.org>
In-Reply-To: <Y3xeYF5NipSbBFSZ@feng-clx>
References: <20221121135024.1655240-1-feng.tang@intel.com>
	<20221121121938.1f202880ffe6bb18160ef785@linux-foundation.org>
	<Y3xeYF5NipSbBFSZ@feng-clx>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uwYg2hnR;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 22 Nov 2022 13:30:19 +0800 Feng Tang <feng.tang@intel.com> wrote:

> > If so, that's always best.  For (silly) example, consider the behaviour
> > of
> > 
> > 	x = is_kmalloc_cache(s++);
> > 
> > with and without CONFIG_SLOB.
> 
> Another solution I can think of is putting the implementation into
> slab_common.c, like the below?

I'm not sure that's much of an improvement on the macro :(

How about we go with the macro and avoid the
expression-with-side-effects gotcha (and the potential CONFIG_SLOB=n
unused-variable gotcha)?  That would involve evaluating the arg within
the CONFIG_SLOB=y version of the macro.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221122151718.4f7ffcb656dd7dc0eceb0ad2%40linux-foundation.org.
