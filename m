Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7NUSJQMGQERQJURZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E1955116B8
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 14:27:36 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 30-20020a0c80a1000000b00446218e1bcbsf1057107qvb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 05:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651062455; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZaZ6Yz3drcqIH1oWI5KL3clAw1bfvCsHfpFpQpfhEpadao8sH5XbIc0kvC/yLAt+s
         wAnxhJinyFhTk9z2uTTnRIVunNtoOL3wTsPAoK+7bW/Wh9tVi5aAmewC+pioDhhqSuHC
         FGTOTqLSrhTm0hQxNvZiBnFMGyi2iHVVBcSsJCIu2EK6AfDeHErdnBxnGSVHvPqT7n6Y
         OMmt1ceIXdRfAE+WfpsyxYaouzE9fX6VCV1DMOKsvbw+qBB44n1odThK+8wOt6IgRoNP
         faWDaTk0BYC5tns6IbRMgaROAZ9NMgATKllPd4R476wPMzURzVDaoHYCcANKLIH7oAYS
         9pDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xW5pRd7I5NkvasJaSi6cUNWgdC3qm+aWSUPwC+ChBRI=;
        b=zeLAQZY00bE4OEKyRRrDkbMTlU3WUcmI+FzGon9UkgTAL38XlfMW+/KZBC9bRefOYa
         SckRH0G7zVTKL27GuqPM31Dz6qq5OkunBNpGsnFOEv9FHGe8qCmTR4Uta2b9beMhcOEN
         RtHKDQ2KiFjJpQ0X4Wl9Jq2WlqBps6AQRjPGeWg0h0b1+vZvOd6gHCl5oHK91UcjL6HJ
         2IE1tEhsjJ3GLjjGPO3bJuGUHsIOWNmzD3cOADWj2ZPShpagXoFAU0rMYiMX6JW8k/bL
         nmZwi0Dv8eR6JvVaM5wadBAfa6s2VRca1bykRkBKyZRLPdU1bF/SRPxlOWLb3Kh/q00U
         b0+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GltEs0HX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xW5pRd7I5NkvasJaSi6cUNWgdC3qm+aWSUPwC+ChBRI=;
        b=iFr6NhBxgn9Ce/HXauEBeD5RXsDAsi2JrN8FNQDnoUXT+cxADk/jt6VhmNZiDCZOYp
         nWlq1LESVrI57vY2jCR8eeUj3+ycII6z19IxoEV6QaoRCD1L85wenbIGPTGMPdqstXJI
         ye1cQUPJeoVfd9K+Yx5mACbLQ0VlAD8hU/GKBP/7VnnLePfnRw9UEzBTKu8VxIZqbOaC
         7qrID93SLH5Y4CK4Tx8gQi9lis2NXjN10GMICaYnfpyb2RvQJa7/UCMpNockX81E9MVZ
         +mqc72rECzqkiHp7//F1VLyZ36HEjoSTnwbCC/8Hc9A4XqIGEQVZCTQTBng4c8AiRgPa
         i54A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xW5pRd7I5NkvasJaSi6cUNWgdC3qm+aWSUPwC+ChBRI=;
        b=yPVxJPKkvApp4gZlKxgaq2TTGgeeUX2Zv3CaMxewCNVvhZ4TYJFgBcleEBapX6j0Ft
         txq0iTSE8Kvj4pYe2EAT6rYeUUD4GZMatf8JA1KMRku2l1XfLxEgYPt+QCDBFh5BDgSs
         fDIjfIdORd5ixFZOc+UP1q3QvDnpn3RWTYnOQ3p5OXJt7p7QGEjZqzrPkF8CnD1M6qg3
         aTaVI5PXpR++NxsExbnHTuso5/LUox88Scjq++0XOsuZCjZqLQ0hVuvhlr9q9ELWzhgO
         IJsJ8A8vvcUeP7v6PBl5RCcDwScPxobMF7scaQF8g+UkX7AELnT3ZdTUUOdAeD4GIfs4
         05Cg==
X-Gm-Message-State: AOAM531N1opgfxilHmNxJyNo2Y0CdqO5DLUXbmYuGCLS64wBugU/s/JV
	1kSXa4jKSuXDCq7nQW4eCYA=
X-Google-Smtp-Source: ABdhPJxdoc0r4v9YsJFefJO4oWE30cYSkwOJh9GrOF1RSbBcVxRv8H1+MpApLgb1sFudoGHMAW3BZg==
X-Received: by 2002:a0c:b381:0:b0:443:e12c:141c with SMTP id t1-20020a0cb381000000b00443e12c141cmr19400495qve.117.1651062455345;
        Wed, 27 Apr 2022 05:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2585:b0:44e:dd77:819e with SMTP id
 fq5-20020a056214258500b0044edd77819els2396322qvb.2.gmail; Wed, 27 Apr 2022
 05:27:34 -0700 (PDT)
X-Received: by 2002:a05:6214:27e2:b0:456:547e:4188 with SMTP id jt2-20020a05621427e200b00456547e4188mr372046qvb.17.1651062454806;
        Wed, 27 Apr 2022 05:27:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651062454; cv=none;
        d=google.com; s=arc-20160816;
        b=g2QRG+vXzMYQN3pBy4Pf5r/XFS8NH7rzySPJVl8obEPIYXsL03QDsWwxk8Tyzk6j7/
         lbz1o2QSV4N+Iz/t16a4HUDwlTR30pHHT7bmAn9A8tQi365AAp2j/ofOUeo8ETw7ytqN
         PMi8u8h/Ty2A+z7zvIvx3AOnztGBebZdd5hcZ+y8KB6zfU3NnF5oBdBXNFwKhJaJ+1dP
         pauUp5Pr9N5reHwW3Fai1VMpE8TIS+DPFOToDUYPRwaU5p3xc8UvzZJBWvzmPjrM/iXP
         sKF85miPthAZ69Dg6VCfmeiu7YEoDy2KsGzZp/TTQ7HfOlJQhqj9At7uvXmC7tC3SgpA
         F12w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fjpx2T5yzcLE2/+jTUfdNrrPpOB1Xc2EmCzrb/sNyOE=;
        b=1KyYuRI4dm9rdD61FzGktj6vfINnAwfqiMGiT9oec/rxbrDvFLmundV9ID2KLEEuwR
         Ixf+vTwT3iFD9/zTP2M7jmsVKiL9hhHHFlkxK6XMmU0ZjdEiTab3K2ThXcKRtWeiCjaA
         QQFSX0kWp6xek7gSXt5mLXAP+x+BZ4WdTQR5fhO6P5dr6048BqmmxXLC79DpxvXMsBfB
         EWFjepkto8ge9HFOKbYkGr2vM5Fv2cKQf5SGDW1OrqAVhxKB87KkAdYla4CTroUwqoDX
         gR7DSEVtHJuVkxCv70jDunuT+BClVIqEyQFH9Qa+5pqnlew51HZMVY4qaoxLhgMaOqOi
         t7BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GltEs0HX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id 188-20020a370ac5000000b0069c74198388si113311qkk.4.2022.04.27.05.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 05:27:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id w17so3027095ybh.9
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 05:27:34 -0700 (PDT)
X-Received: by 2002:a5b:5c4:0:b0:644:dec5:53d1 with SMTP id
 w4-20020a5b05c4000000b00644dec553d1mr26476481ybp.1.1651062454334; Wed, 27 Apr
 2022 05:27:34 -0700 (PDT)
MIME-Version: 1.0
References: <20220426134924.736104-1-jun.miao@intel.com> <9c951fe6-d354-5870-e91b-83d8346ac162@intel.com>
In-Reply-To: <9c951fe6-d354-5870-e91b-83d8346ac162@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Apr 2022 14:26:58 +0200
Message-ID: <CANpmjNNxOX12NcMjXJr3XWcoe6d+Dp74pR+2naVW0anwcYfmoQ@mail.gmail.com>
Subject: Re: [PATCH] irq_work: Make irq_work_queue_on() NMI-safe again
To: Jun Miao <jun.miao@intel.com>
Cc: ryabinin.a.a@gmail.com, Dmitry Vyukov <dvyukov@google.com>, bigeasy@linutronix.de, 
	qiang1.zhang@intel.com, peterz@infradead.org, akpm@linux-foundation.org, 
	andreyknvl@gmail.com, ying.huang@intel.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GltEs0HX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Wed, 27 Apr 2022 at 03:49, Jun Miao <jun.miao@intel.com> wrote:
>
> Add  To/Cc : KASAN/MEM , since I only used the scripts/get_maintainer.pl
> to irq_work.c file.
>
> Thanks
> Jun Miao
>
>
> On 2022/4/26 21:49, Jun Miao wrote:
> > We should not put NMI unsafe code in irq_work_queue_on().
> >
> > The KASAN of kasan_record_aux_stack_noalloc() is not NMI safe. Because which
> > will call the spinlock. While the irq_work_queue_on() is also very carefully
> > carafted to be exactly that.

"crafted"

> > When unable CONFIG_SM or local CPU, the irq_work_queue_on() is even same to

CONFIG_SM -> CONFIG_SMP

> > irq_work_queue(). So delete KASAN instantly.
> >
> > Fixes: e2b5bcf9f5ba ("irq_work: record irq_work_queue() call stack")
> > Suggested by: "Huang, Ying" <ying.huang@intel.com>
> > Signed-off-by: Jun Miao <jun.miao@intel.com>

I thought this had already been removed, but apparently there were 2
places: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=156172a13ff0626d8e23276e741c7e2cb2f3b572

Acked-by: Marco Elver <elver@google.com>

> > ---
> >   kernel/irq_work.c | 3 ---
> >   1 file changed, 3 deletions(-)
> >
> > diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> > index 7afa40fe5cc4..e7f48aa8d8af 100644
> > --- a/kernel/irq_work.c
> > +++ b/kernel/irq_work.c
> > @@ -20,7 +20,6 @@
> >   #include <linux/smp.h>
> >   #include <linux/smpboot.h>
> >   #include <asm/processor.h>
> > -#include <linux/kasan.h>
> >
> >   static DEFINE_PER_CPU(struct llist_head, raised_list);
> >   static DEFINE_PER_CPU(struct llist_head, lazy_list);
> > @@ -137,8 +136,6 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
> >       if (!irq_work_claim(work))
> >               return false;
> >
> > -     kasan_record_aux_stack_noalloc(work);
> > -
> >       preempt_disable();
> >       if (cpu != smp_processor_id()) {
> >               /* Arch remote IPI send/receive backend aren't NMI safe */
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c951fe6-d354-5870-e91b-83d8346ac162%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxOX12NcMjXJr3XWcoe6d%2BDp74pR%2B2naVW0anwcYfmoQ%40mail.gmail.com.
