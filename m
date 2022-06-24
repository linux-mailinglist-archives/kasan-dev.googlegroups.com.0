Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPPL2WKQMGQE7SYQCDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BE6B455956E
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 10:28:46 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1048dffc888sf1290131fac.11
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 01:28:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656059325; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z70/VjY5gjwwTNtcJ1JY+N95iZ+MYYxv9twyqYc0s+gJp4Z2xZGe0OCcgvkUQGlqB9
         QfYsa9X/R+w01zsQ3H+TF3WhZDj356o3VCdvB7oL9gdFWvb8FS+9/9+bKpszkfUlMLzN
         a30WX9WXyS3BKjuInv5q3DfLwP6VOtXJ+z9FkpvSciO8hWhZ96K/S5VWY4c6wbCMVrGj
         fJ9X+nIyYahs5UUQFEdUGy8xSf15UG5skerO0JWyZD2iD1w0jOBEy2oX1qIudJb10DwU
         usfJaR9KVJ2CJWF45TKu3nsvmzhX1aQZJD89EMy2+dbq8x26p8EYZzTiKoqUQkZEW5Hw
         Vskg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JaxO4xLCjjpkYn0VAqx/pXoyICTE1/91+/cZDu61oQg=;
        b=Wy5ge5kYtAcJZqJQyNCVZFtG1piwYPPcSE3otgyamJy/3b+w2v77fSIuYtNjqw7Jx0
         Ij728P53fxI3yyRk1zTomQTJ5tY6SsYqcZ4z3/efykZ0P1zn+LmIOJKeVo10y09M9AOO
         hxWthVtJPNCkdMa6O/t0B3XRRsLVf/sO+JGExY/IRD7JVSN7Q7zourMkXquIOmYuYtPH
         wLe0Bhm/o862ztj6+7C9N/Auwm2RpXnJIk05CV5ydjxS3egRXy2PIlP/KUtyGI26wgFi
         LEx3+U4fU64Xx3UV2NudFQqCRfU4sDrnOXB0B3NfF53GHF6Uy3jmwkoMimngp9um6qaA
         XRQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Yen0y2jH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JaxO4xLCjjpkYn0VAqx/pXoyICTE1/91+/cZDu61oQg=;
        b=RgHygl0rvVbEWYjZG0bnSWB6CA2fUt1rm5kRstmHZnfSoe3Fwjuz8ytE13ibcpZANP
         7/clfubkXem/fU59Ke/SA8zVG3ECkadi8RT0PUOm5JmndQlx/dlavmQ6A8C1+WGdTWqG
         kBTHyQgeGQUHTPxvcleC2SMOPjtOfwZgsTKNtmhocOPI+Entq2p39gW5rU1p75qZGEfu
         6ubu3F71t+2W90klngepGMH6uuuP9WlwMpZlRs5400DTQ+IxKxSpUiCcoivhnaSLllAH
         cn+H/nkYc401seHltJ9lvvU8JFZBNaAEHy2RRVwIpWkaEfAJx6RwjR3kSYeY8gJXFhTA
         tbJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JaxO4xLCjjpkYn0VAqx/pXoyICTE1/91+/cZDu61oQg=;
        b=8ATdHZG+EjZotR60LNlf7juUvs0GPqjtipQFeSooIR+28LZk7Ea7GszT7xei+7idVq
         iZc0NZjMaBq4bdzWI6aY8hKIW+7QMhRCpqEUlM8VkssGWjoBqtRGFyJAcaEcQm+VGoxl
         NkncYILPP08k4Mi9+DBtjOrIyaTqThMYxJViP+6XkLVWsi9sMfYcCvrSbZqB/d0J3HQt
         ZG6fcGYWshUiugNc+cVMSX0W5zYG4RdbrsSnTippGc5LkixIzh8k4vu9R+xZx5/DYvLB
         fd3BsU8OTasmAScageOcpnNSMcVyqu6BMn13vun8ilhRYKJX3kzKZqFOKzJVhwO+1h5t
         G6Xg==
X-Gm-Message-State: AJIora8Vt9Qjt48Mg76DcbAmqccyScMxdgCDg6z+16AP5OrEXycWDyj7
	RVR0xvQFwdocsnMYAzNFxTM=
X-Google-Smtp-Source: AGRyM1sOnAVel9Zn7K0tn7ck8xmN/RWVyMwBIriIpI4IyHXSQ8uM4d65TvkfMvXHZNkH+iRABw+pHg==
X-Received: by 2002:a05:6870:d0cf:b0:ec:4559:86e1 with SMTP id k15-20020a056870d0cf00b000ec455986e1mr1266096oaa.225.1656059325468;
        Fri, 24 Jun 2022 01:28:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:319c:b0:60c:6020:aa7b with SMTP id
 p28-20020a056830319c00b0060c6020aa7bls4488275ots.4.gmail; Fri, 24 Jun 2022
 01:28:45 -0700 (PDT)
X-Received: by 2002:a05:6830:6306:b0:614:c6db:9d3e with SMTP id cg6-20020a056830630600b00614c6db9d3emr5491091otb.60.1656059325041;
        Fri, 24 Jun 2022 01:28:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656059325; cv=none;
        d=google.com; s=arc-20160816;
        b=t4+lBc4620Sx4RFwOa44xu/fwei73Kl5EX+pxltxb7rF8LUfaKV55rE/ol6CiYmR9p
         Xh77TGFGn6RO7Gy+iEnu0OXCSWjb6dIlN2M0vv8gmXKZI+SEW0/qHYi2QjqjuUsIHF7o
         KBE3lZIMN+t5jRF+3KiRaW7+QIBx62aVL1bxJcGcXnwYAxpGv9lUHuvQIFb3GcS6SM75
         0RZLlzWwYK62y/29Aj/HRFPdg59MFH1gPYDIIQCPXViSjXABTXNq2DEwfvxLhcbNSjLB
         NOJfSouaijiCHFquFVdtZ1A1VSCBdX+mtaqFi7Xx1wQBWeK5jnVO2v53zCv1IEJQKUm/
         UvNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=juJPwPR296pSJZwsH9/Iy+TMiLjsg5L/e3X7qop/D3w=;
        b=O9gjjCIGVmDEBTpbuSzWxtaFsm0/SRgFD3qZRWSH/CRLhwY6tlb0h4ANeK4uOVGg8h
         K/PyaIADOywdD3H5fmUtnR0FJ+4HcPPqpky5Zpj65N+XXrLSXsoHgHTOfpJM62vnLb27
         S3/0/RSnt9d2fAdC4S4ivIT8BcZv3+Z7MW/sZDYvpWWiWUSTdyvfhrEJguWuZwzUKQ1I
         7Wk/ZEA7d2bPE0WP3LzBg1KIU7eAFOQhggC4OCdgaYJUP3kTduGpJHmxeAlabd8ECq9t
         wuoWwGyZ5fdZ0Eo0Sg2xeAQTAepWKeeuwNfNvwxm4helg5h3k70/VelcjJJ/DAuQrT15
         o8jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Yen0y2jH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id o17-20020a056870969100b00101a5546931si314077oaq.4.2022.06.24.01.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jun 2022 01:28:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-3177e60d980so17393747b3.12
        for <kasan-dev@googlegroups.com>; Fri, 24 Jun 2022 01:28:45 -0700 (PDT)
X-Received: by 2002:a81:3a12:0:b0:314:6097:b801 with SMTP id
 h18-20020a813a12000000b003146097b801mr15576175ywa.512.1656059324577; Fri, 24
 Jun 2022 01:28:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220623111937.6491-1-yee.lee@mediatek.com> <20220623111937.6491-2-yee.lee@mediatek.com>
 <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com> <bdfd039fbde06113071f773ae6d5635ff4664e2c.camel@mediatek.com>
In-Reply-To: <bdfd039fbde06113071f773ae6d5635ff4664e2c.camel@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jun 2022 10:28:08 +0200
Message-ID: <CANpmjNPfkFjUteMCDzUSPmTKbpnSfjmWqp9ft8vb-v=B8eeRKw@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
To: Yee Lee <yee.lee@mediatek.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Yen0y2jH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
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

On Fri, 24 Jun 2022 at 10:20, 'Yee Lee' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, 2022-06-23 at 13:59 +0200, Marco Elver wrote:
> > On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > From: Yee Lee <yee.lee@mediatek.com>
> > >
> > > Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration when
> > > the kfence pool is allocated from memblock. And the kmemleak_free
> > > later can be removed too.
> >
> > Is this purely meant to be a cleanup and non-functional change?
> >
> > > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > >
> > > ---
> > >  mm/kfence/core.c | 18 ++++++++----------
> > >  1 file changed, 8 insertions(+), 10 deletions(-)
> > >
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index 4e7cd4c8e687..0d33d83f5244 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
> > >                 addr += 2 * PAGE_SIZE;
> > >         }
> > >
> > > -       /*
> > > -        * The pool is live and will never be deallocated from this
> > > point on.
> > > -        * Remove the pool object from the kmemleak object tree, as
> > > it would
> > > -        * otherwise overlap with allocations returned by
> > > kfence_alloc(), which
> > > -        * are registered with kmemleak through the slab post-alloc
> > > hook.
> > > -        */
> > > -       kmemleak_free(__kfence_pool);
> >
> > This appears to only be a non-functional change if the pool is
> > allocated early. If the pool is allocated late using page-alloc, then
> > there'll not be a kmemleak_free() on that memory and we'll have the
> > same problem.
>
> Do you mean the kzalloc(slab_is_available) in memblock_allc()? That
> implies that MEMBLOCK_ALLOC_NOLEAKTRACE has no guarantee skipping
> kmemleak_alloc from this. (Maybe add it?)

No, if KFENCE is initialized through kfence_init_late() ->
kfence_init_pool_late() -> kfence_init_pool().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPfkFjUteMCDzUSPmTKbpnSfjmWqp9ft8vb-v%3DB8eeRKw%40mail.gmail.com.
