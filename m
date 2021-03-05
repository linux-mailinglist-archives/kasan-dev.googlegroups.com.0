Return-Path: <kasan-dev+bncBCT4XGV33UIBB54TQ2BAMGQEVTO53UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3460B32DF1B
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 02:31:36 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id d8sf565479ion.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 17:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614907895; cv=pass;
        d=google.com; s=arc-20160816;
        b=yF9Oi+nnZ6fjeRd6qspdl2OpE0exikrtEEYAy2KagpgR+k5hyr16Bb2/SNcbHzY3/x
         i3XOW53ctD0xQU+moHUZNjExUAexLFl030U5P52h9QTH2S0DeOtuCKYEB0An99nxs6EV
         ZaE4nVoPqr71ybtPluY4OPVjR9j9E2LgloTM9JFRdzKbObr8WCTYSaY33ycpyICs4CIk
         /QC8LRZ9QHkT8TXP/Gv1sYvPVik7Wcxwo5KlpIxgUTJyTTug7fM6cAlBppyuIRlQXQz4
         8k8yttG0nraSrl8kfm3qce4wJ0gsg+FZBBrXw1ITzFFsf+3EcgjFd4vUq2XMD+5S66Vj
         MGZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=oxMQUDndfcndsdTn6PuUkIWiC/uoQIoCrF0YtHPV+84=;
        b=Xlw2dc6l5BLmalC+nMeGY6FkRHMz37ggm7sOuLrDv/uMBMLNKhqBuxi8AVY3ER+dz9
         hrRybIozd+LvSKUddlNSUEMSSgZIJY/6gUFxI6pGElcTtltaS69umCpQTaGNjIJVGBGe
         kIsozeSQMMXGZ8hUUgGniYGreGkcOhyldyPCGHo9IloGcDC0GvAeSM/jr/Y7eaxrn5a5
         /Sn0FXFbhIVY0RgZ0fDmB1hBmWuMsVyshoL6vkxDvrDZYxUNWtL8VPKlcKQgOqxz8KnN
         zgM4jXaZxCzMdap+Kuh09ZbszNtoAQojWqIKcHj7LwclqrmQr4ZZLpKPWW9Lpv+FteQn
         tzRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lFKVIahp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oxMQUDndfcndsdTn6PuUkIWiC/uoQIoCrF0YtHPV+84=;
        b=aRJpO/WD8T+RVSI4tTg13Hhpog0RshjGYFT99OkARPV3tGDjBvtldMBamFUYIusk2b
         NWg9jYr/1Bl+4eMWA+WnmRfwdVA7LxNhb6WGjdv8kfCSV53ME/2p4OBxDwEoOWW+lgOB
         D86w9S6uR99LNaMKMI9g0Yuca7glzbnxECVv7fCyFXDHYnt1pdD3cmeD37v6CA+Wk9qi
         FEpRdNcE8faOMUJKehw6f8bzhRTi0FVr4TsAYAz0BcBaiIk+kEUYlGu9QTicF885IJuC
         W4gvIgYRc8bMcsQCZ+29MJm+mJWosghqcmIx5Dor6HfPI/FdcmQiYzIiz3Ha6lgsKeJN
         wfLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oxMQUDndfcndsdTn6PuUkIWiC/uoQIoCrF0YtHPV+84=;
        b=L14ysSK/uzstJaFiHzHgMfy6Pn7qfeNevv6Vc7IcXXeE8Xgm3bL+15yJ4Nqf2Zc3GO
         X1ZIcetkJRHIXMrBp3tquKmLwng5qXJdfFJdjLMjlSS+LRMkx8/3r04wR8rSzmMwfW/6
         grq1DmYdtpUC+eokyYjJMGAL7ve8VaKnGL6X7S7aI28vTjgB69fLAfFN6ThMWccSFvs2
         tLlGnqiXYKsXo//YTwqxb2Bb1xjfU9O+e6gB3C8NSJLcumv/YIjrFHjIx4zldfFbXJt1
         Mq8MMZRUHXc4lUeJFPbWBa+91Ahc+5zW0B/vu3wTrMl3f59jvxXjPT+956AdyslKtLcD
         PT+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dx5c2Dh8tVIaCWzttr7gBFed2NjPdakLpFm1U+8pMbntTPJgR
	0109yN6wHk6Ayd4RjNWjLAM=
X-Google-Smtp-Source: ABdhPJwZHxjVKMkA6iHY8rUAD+hkuCRc7sR1HSUGA2KzvRqWd98CGukfIu/S1I5OsZ4AHauPFIbieg==
X-Received: by 2002:a05:6638:2047:: with SMTP id t7mr7141000jaj.134.1614907895207;
        Thu, 04 Mar 2021 17:31:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2195:: with SMTP id j21ls1962233ila.4.gmail; Thu,
 04 Mar 2021 17:31:34 -0800 (PST)
X-Received: by 2002:a92:ce84:: with SMTP id r4mr6396161ilo.112.1614907894878;
        Thu, 04 Mar 2021 17:31:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614907894; cv=none;
        d=google.com; s=arc-20160816;
        b=dKsasmA85wosVDh5uQ++GK5IojhqCfEc0KHwJrIDBSiH69XzTFOwhLq7BMxVKkFXWA
         cWx3lOlRZ6MX7KJR3QrTRu+6q7Wo1agOEKbTSiE3qUnB1CWc1JAG6WeJv42whNoPs8IG
         B70j8gn6BLcokx1ej5ACDhtlAhPqntTsJVC6uiTCVKoJ+wUhJ4EPVT48iwHp/gn6tEl0
         +XUhM1RpPINJlzf9tigYt0/ApAYYgplA3v2elo+y5qAiGP/8IEB7rEzIrRl2HSD7Q3Pf
         w4H3/5bbeUTHZNUBQTyJ9eKRWeF4Xe/0U+2kFyAQybJ90S1K6qkfDU3RXHF1CY1IbjfI
         Tp6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CCtqt/hNJBZlh8hAG6WxfqlXYAmtx5ELupDTqj3GoIg=;
        b=ntSbWBFNtm4SuZWkSV528TT/PtTjn1UdVIKUKCoxUQMRFh/10puLyaqjk2AviF8mvS
         Tux0ioKTF0WOfkdyGpK/3mb/7GNbQnmm2dxc0KEMdzlFWwTpV+zgAwOQI/dV7g60+8C5
         ExOdXC7LA2Am/nHH/9zvt77RxN8yMoqCS3UlNcSyUhq0Pulfn43m8gO0atL496WdncN+
         8r2hEbWB0QmRGpsiy2TwkT9HqxXZr5w/uG3X3EEfVs9hBGDaJJcqskLZJZvSzgr04aCG
         xEg/siyH/q1y7RMxf1yW9Vy5v5bm7v7qY34awgWeVnO36KgBtE4S5YCFuLBfBW6+GZy2
         P2jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lFKVIahp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si77812ilj.4.2021.03.04.17.31.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 17:31:34 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9966D6500D;
	Fri,  5 Mar 2021 01:31:33 +0000 (UTC)
Date: Thu, 4 Mar 2021 17:31:32 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Dmitriy Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@google.com>, Jann Horn <jannh@google.com>, LKML
 <linux-kernel@vger.kernel.org>, Linux Memory Management List
 <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, Marco Elver
 <elver@google.com>
Subject: Re: [PATCH mm] kfence, slab: fix cache_alloc_debugcheck_after() for
 bulk allocations
Message-Id: <20210304173132.6696eb2a357edf835a5033ee@linux-foundation.org>
In-Reply-To: <CAG_fn=XVAFjgkFCj8kc6Bz4rvBwCeE4HUcJPBTWQcNjrBLaT=g@mail.gmail.com>
References: <20210304205256.2162309-1-elver@google.com>
	<CAG_fn=XVAFjgkFCj8kc6Bz4rvBwCeE4HUcJPBTWQcNjrBLaT=g@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=lFKVIahp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 4 Mar 2021 22:05:48 +0100 Alexander Potapenko <glider@google.com> wrote:

> On Thu, Mar 4, 2021 at 9:53 PM Marco Elver <elver@google.com> wrote:
> >
> > cache_alloc_debugcheck_after() performs checks on an object, including
> > adjusting the returned pointer. None of this should apply to KFENCE
> > objects. While for non-bulk allocations, the checks are skipped when we
> > allocate via KFENCE, for bulk allocations cache_alloc_debugcheck_after()
> > is called via cache_alloc_debugcheck_after_bulk().
> 
> @Andrew, is this code used by anyone?
> As far as I understand, it cannot be enabled by any config option, so
> nobody really tests it.
> If it is still needed, shall we promote #if DEBUGs in slab.c to a
> separate config option, or maybe this code can be safely removed?

It's all used:

#ifdef CONFIG_DEBUG_SLAB
#define	DEBUG		1
#define	STATS		1
#define	FORCED_DEBUG	1
#else
#define	DEBUG		0
#define	STATS		0
#define	FORCED_DEBUG	0
#endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304173132.6696eb2a357edf835a5033ee%40linux-foundation.org.
