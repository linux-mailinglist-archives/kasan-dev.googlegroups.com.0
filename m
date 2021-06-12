Return-Path: <kasan-dev+bncBD7JD3WYY4BBB5VPSODAMGQEQ32IWEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id E858C3A4F8E
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 17:51:19 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id g12-20020a056602248cb029049182acfe4fsf21516356ioe.0
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 08:51:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623513078; cv=pass;
        d=google.com; s=arc-20160816;
        b=IDn7y2tAFPEmwPClMR36nLRToWaGJs1zrifkWmQvqx9xFPJ0UJwGQm+pdOYKxLIkhs
         INDJFdSffVdCD6zsIcbgN8goU7i+lj7DWrEaMxlANy7QbcClRz1pYsfwZMvZkyf5mfe0
         WFoHcFJVmMKbMbxhLi8iRbJWK5zUzX0qe0RV71nw8JgdLUrV1u/E1VTbF1KuvFgBnCPu
         jJBdF73O1jW71K/n92w26+Rt45Nz0hriQJDqE5WAZViZtnz2bcGyFxFgYelgep9arVdT
         2E9qqlAShMCMNVcavuIYvNZyU0zHEcJhWhk18Rh1vUKubr9/mQhcT8pWcZGTLpDOSXE6
         954g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=QxF6EPiic3ls9pvOtBnu5PzCMW3TuP9Mckz3IFtmhik=;
        b=zmMbSRtAMQLYupEq07W8zWGx4c8rsiFgoqZ5fuDe6FZavenD52xoyEPnL7uaD69YwK
         2Y7SiLVjaCSvvVFp4xtuZDOd/sHOpMszA3nCpg6r03Swomt4N8891LPwJFDWNGBr1UxN
         lEQb4d5hZmf7bE1OdgRq6lVs8NQ6yqzjuB2kQiyoydslVPOk4NFyrzPdgVQr+3CqTAFJ
         4dcw+cpLTZj1VOjtLYqBvHCenDjLo340Zx8mqpbldJGiJ2/tC+jwi5CqrTr8mLD2F/Xf
         XWLaTRPiOyGE9HXawXnt72Wqu1gaJ4s54LxKkK++sMIQV5JvU4sL7EI619tmnWp9CEIB
         qiqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lSSHhbMP;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QxF6EPiic3ls9pvOtBnu5PzCMW3TuP9Mckz3IFtmhik=;
        b=SQPabiQSUO6d60pxqgSCGyT7ZAFBqMlxhUsy8OiSpDdD4vCzbfwoo8kWl7LwdjUo+j
         ET4R190GfzRv3COrsIjFNE0vReF1MxTQpBFTonGfyeynoXiClTvcOpncMXYuYHUveMu1
         d+csGgztu7rC/svtK/Kni/GQK63akV2P9nv05JDz0dPxGk73QMTsLWmZH1m99HboIhtU
         VoDiHx82de7Z2BaE9XVmZ26xA56QSQQELquBoBSPeu37hPtiHfpHmXIXEREoAz+ySn5y
         L2/d+XpR8r7jhcDkdnd+nzIoe92S+vBsk5w6SVFApCfSRKAPIUYtryYAFw1EsntibKaE
         Rwtg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QxF6EPiic3ls9pvOtBnu5PzCMW3TuP9Mckz3IFtmhik=;
        b=ht9Xqu9QOMs6a2nhaTs3yxo35L0oFW4lOgm4eOdKc7ZqCpObhE6bXM7e+yxBgyTKFh
         i1NkFrzBQHKgIwG2t1V/5wsopOIpUiIqTj7zRBoTvAQL0atOArrtjriCf2cWWgmgn5yb
         2JXLM2Nh1+n+7LhbUdiKGaFTmH7/zoAM+q/lgkSGp2g0zeGdbagYwPlhnC+IGMNtxX0W
         ZnO+137Wj9nGt9MoqJNDrXxAghDhvcgoV6HZwyRGmtHlDx16zw5WN1SRDUyEcegTjvGA
         RSJuPBOpAs/3PptdG7E9j9Uy/Lc8sNQKMVAgGQS7vAa1U+j76nFUwfjcNlqByxc75TjQ
         qLMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QxF6EPiic3ls9pvOtBnu5PzCMW3TuP9Mckz3IFtmhik=;
        b=j0bcen6UcSrkEcaiLwoVAX9TX2CRlFtufjbWB6JP7BlWULR0HrEEAEQ0wJT2LyJ+j9
         gjbUAuf2dXYSzaa/inqgpsTdyEgBQMjVZC/ZUdnWWuKR+j83Spu39YM2c9EMBNGEuvUF
         o9nMw5ykt4ork9NxpMubk/X7hf4erLLH42PrwSHXKD3icukWga4lFCcs0UJvzrl24xEX
         wrMAqXBddILAw7klEmMlcwYW1L8UYiDIrJg9r1e6p3SITH0tjhMiijqPdoAfHvnOXKRv
         UpwOziw5+0a+1H3R7Y4VQxuNJosdHaUhHelzBwuCyse0Y5MjaX5xCV1qTe8dP0Ko4AVn
         yfqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307kH6+8yTVpptYbZOEbq1suJAfTT//SOMmrlQC6iiSDl+OGOtm
	U3U563ltvqtourolR8dWOK4=
X-Google-Smtp-Source: ABdhPJyNVs0hjBlO3TzaTqlc/9o1fFco/reuwB4QxhyhvYrHKp1PEmda60CE1F84g40ay8e+0i+IEw==
X-Received: by 2002:a92:c152:: with SMTP id b18mr7458523ilh.282.1623513078570;
        Sat, 12 Jun 2021 08:51:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9454:: with SMTP id x20ls2282394ior.5.gmail; Sat, 12 Jun
 2021 08:51:18 -0700 (PDT)
X-Received: by 2002:a05:6602:2344:: with SMTP id r4mr7691065iot.69.1623513078196;
        Sat, 12 Jun 2021 08:51:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623513078; cv=none;
        d=google.com; s=arc-20160816;
        b=aDMiSwT2195FOKJz6JQ/4RVRSLk8L8WoUg9eh6OYsCJZUOfdxX0J2XqkBNpIdaubF4
         G0Eue98VBUYAjtejFXLnq5aA32Wuh83V6+Ad0yUvUGpMJ024vrsD1vpHySmYj+Ul7gxV
         hw6oPw9UfRbbub2Ae1cEI4x/uiNIy2GEJ4GXEikTvpNHtJhmE6pytjKAS/ogYGHMV+8y
         1QbxyhgxfZ8PZ+M6oVggDz9MA1LkiJVlZxmTYU5sI5RhOwFt7RvNgolrz23R785Pqkgi
         WwbOG/oqR2qr8pFhah16qLOyY3VkVjRLtymk1SnzptSRcKLhxKb4tCGlAUsbDrkKOXhv
         dlVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=13vDzbI957CXDNEDtcZR2S0juOb9uGtVIdJ1VlmUGxM=;
        b=U3DSqvPmBHFkJKzs65lcTnqs3rRAp0AzIcQjG9ApyPXHikxKe1do4mgnL2rLkDC4FE
         dz2mr+9zKMsS28mDy54CT/TunjeYIv7+zA3b0mmZ3P2jGTSOui9uhGnIJpz8Tm39QaY9
         H69rSmADrVNkl7Khg/tA0LQhYNZVzbH7QNQ0Rdj+BzUmCAWMDeil+/8I6Hss7F77+oza
         QgyP7BEvrzgwSe0U8+kqX+dRECNVcOjcNK+o+jZ8HIh6xX61i+w/956QFqg0ek9o1NpI
         DG49M1GLJ6447k+IPJgwADGQzzSVxGT0NAyWjVEbssztzjNNK8NMpickIDhLQ7Rcy+Nr
         fYYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lSSHhbMP;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id h15si720833ili.5.2021.06.12.08.51.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Jun 2021 08:51:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id q25so7009994pfh.7
        for <kasan-dev@googlegroups.com>; Sat, 12 Jun 2021 08:51:18 -0700 (PDT)
X-Received: by 2002:a63:b043:: with SMTP id z3mr9161280pgo.89.1623513077639;
        Sat, 12 Jun 2021 08:51:17 -0700 (PDT)
Received: from DESKTOP-PJLD54P.localdomain (122-116-74-98.HINET-IP.hinet.net. [122.116.74.98])
        by smtp.gmail.com with ESMTPSA id t19sm12891513pjq.44.2021.06.12.08.51.14
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 12 Jun 2021 08:51:17 -0700 (PDT)
Date: Sat, 12 Jun 2021 23:51:08 +0800
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v2 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
Message-ID: <20210612155108.GA68@DESKTOP-PJLD54P.localdomain>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
 <20210612045156.44763-3-kylee0686026@gmail.com>
 <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lSSHhbMP;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
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

On Sat, Jun 12, 2021 at 04:42:44PM +0200, Marco Elver wrote:
> On Sat, 12 Jun 2021 at 06:52, Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
> > 1. Move kasan_get_free_track() and kasan_set_free_info()
> >    into tags.c
> > 2. Move kasan_get_bug_type() to header file
> >
> > Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
> > Suggested-by: Marco Elver <elver@google.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >  mm/kasan/Makefile         |  4 +--
> >  mm/kasan/hw_tags.c        | 22 ---------------
> >  mm/kasan/report_hw_tags.c |  6 +---
> >  mm/kasan/report_sw_tags.c | 46 +------------------------------
> >  mm/kasan/report_tags.h    | 56 +++++++++++++++++++++++++++++++++++++
> >  mm/kasan/sw_tags.c        | 41 ---------------------------
> >  mm/kasan/tags.c           | 58 +++++++++++++++++++++++++++++++++++++++
> >  7 files changed, 118 insertions(+), 115 deletions(-)
> >  create mode 100644 mm/kasan/report_tags.h
> >  create mode 100644 mm/kasan/tags.c
> [...]
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index ed5e5b833d61..4ea8c368b5b8 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -216,28 +216,6 @@ void __init kasan_init_hw_tags(void)
> >         pr_info("KernelAddressSanitizer initialized\n");
> >  }
> >
> > -void kasan_set_free_info(struct kmem_cache *cache,
> > -                               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -
> > -       alloc_meta = kasan_get_alloc_meta(cache, object);
> > -       if (alloc_meta)
> > -               kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> > -}
> > -
> > -struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > -                               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -
> > -       alloc_meta = kasan_get_alloc_meta(cache, object);
> > -       if (!alloc_meta)
> > -               return NULL;
> > -
> > -       return &alloc_meta->free_track[0];
> > -}
> > -
> >  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> >  {
> >         /*
> > diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> > index 42b2168755d6..ef5e7378f3aa 100644
> > --- a/mm/kasan/report_hw_tags.c
> > +++ b/mm/kasan/report_hw_tags.c
> > @@ -14,11 +14,7 @@
> >  #include <linux/types.h>
> >
> >  #include "kasan.h"
> > -
> > -const char *kasan_get_bug_type(struct kasan_access_info *info)
> > -{
> > -       return "invalid-access";
> > -}
> > +#include "report_tags.h"
> >
> >  void *kasan_find_first_bad_addr(void *addr, size_t size)
> >  {
> > diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> > index 821a14a19a92..d965a170083e 100644
> > --- a/mm/kasan/report_sw_tags.c
> > +++ b/mm/kasan/report_sw_tags.c
> > @@ -26,51 +26,7 @@
> >
> >  #include <asm/sections.h>
> >
> > -#include "kasan.h"
> > -#include "../slab.h"
> > -
> > -const char *kasan_get_bug_type(struct kasan_access_info *info)
> > -{
> > -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       struct kmem_cache *cache;
> > -       struct page *page;
> > -       const void *addr;
> > -       void *object;
> > -       u8 tag;
> > -       int i;
> > -
> > -       tag = get_tag(info->access_addr);
> > -       addr = kasan_reset_tag(info->access_addr);
> > -       page = kasan_addr_to_page(addr);
> > -       if (page && PageSlab(page)) {
> > -               cache = page->slab_cache;
> > -               object = nearest_obj(cache, page, (void *)addr);
> > -               alloc_meta = kasan_get_alloc_meta(cache, object);
> > -
> > -               if (alloc_meta) {
> > -                       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > -                               if (alloc_meta->free_pointer_tag[i] == tag)
> > -                                       return "use-after-free";
> > -                       }
> > -               }
> > -               return "out-of-bounds";
> > -       }
> > -
> > -#endif
> > -       /*
> > -        * If access_size is a negative number, then it has reason to be
> > -        * defined as out-of-bounds bug type.
> > -        *
> > -        * Casting negative numbers to size_t would indeed turn up as
> > -        * a large size_t and its value will be larger than ULONG_MAX/2,
> > -        * so that this can qualify as out-of-bounds.
> > -        */
> > -       if (info->access_addr + info->access_size < info->access_addr)
> > -               return "out-of-bounds";
> > -
> > -       return "invalid-access";
> > -}
> > +#include "report_tags.h"
> >
> >  void *kasan_find_first_bad_addr(void *addr, size_t size)
> >  {
> > diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> > new file mode 100644
> > index 000000000000..4f740d4d99ee
> > --- /dev/null
> > +++ b/mm/kasan/report_tags.h
> > @@ -0,0 +1,56 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +#ifndef __MM_KASAN_REPORT_TAGS_H
> > +#define __MM_KASAN_REPORT_TAGS_H
> > +
> > +#include "kasan.h"
> > +#include "../slab.h"
> > +
> > +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> > +{
> [...]
> > +       /*
> > +        * If access_size is a negative number, then it has reason to be
> > +        * defined as out-of-bounds bug type.
> > +        *
> > +        * Casting negative numbers to size_t would indeed turn up as
> > +        * a large size_t and its value will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        */
> > +       if (info->access_addr + info->access_size < info->access_addr)
> > +               return "out-of-bounds";
> 
> This seems to change behaviour for SW_TAGS because it was there even
> if !CONFIG_KASAN_TAGS_IDENTIFY. Does it still work as before?
> 

You are right. It will change the behavior.
However, I think that if !CONFIG_KASAN_TAG_IDENTIFY, it should be reported
"invalid-access".

Or is it better to keep it in both conditions?

> > +
> > +       return "invalid-access";
> > +}
> > +#else
> > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> > +{
> > +       return "invalid-access";
> > +}
> > +#endif
> > +
> > +#endif
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index dd05e6c801fa..bd3f540feb47 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -167,47 +167,6 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> >  }
> >  EXPORT_SYMBOL(__hwasan_tag_memory);
> >
> > -void kasan_set_free_info(struct kmem_cache *cache,
> > -                               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       u8 idx = 0;
> > -
> > -       alloc_meta = kasan_get_alloc_meta(cache, object);
> > -       if (!alloc_meta)
> > -               return;
> > -
> > -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > -       idx = alloc_meta->free_track_idx;
> > -       alloc_meta->free_pointer_tag[idx] = tag;
> > -       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > -#endif
> > -
> > -       kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > -}
> > -
> > -struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > -                               void *object, u8 tag)
> > -{
> > -       struct kasan_alloc_meta *alloc_meta;
> > -       int i = 0;
> > -
> > -       alloc_meta = kasan_get_alloc_meta(cache, object);
> > -       if (!alloc_meta)
> > -               return NULL;
> > -
> > -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > -       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > -               if (alloc_meta->free_pointer_tag[i] == tag)
> > -                       break;
> > -       }
> > -       if (i == KASAN_NR_FREE_STACKS)
> > -               i = alloc_meta->free_track_idx;
> > -#endif
> > -
> > -       return &alloc_meta->free_track[i];
> > -}
> > -
> >  void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
> >                         unsigned long ret_ip)
> >  {
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > new file mode 100644
> > index 000000000000..9c33c0ebe1d1
> > --- /dev/null
> > +++ b/mm/kasan/tags.c
> > @@ -0,0 +1,58 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * This file contains common tag-based KASAN code.
> > + *
> > + * Author: Kuan-Ying Lee <kylee0686026@gmail.com>
> 
> We appreciate your work on this, but this is misleading. Because you
> merely copied/moved the code, have a look what sw_tags.c says -- that
> should either be preserved, or we add nothing here.
> 
> I prefer to add nothing or the bare minimum (e.g. if the company
> requires a Copyright line) for non-substantial additions because this
> stuff becomes out-of-date fast and just isn't useful at all. 'git log'
> is the source of truth.

This was my first time to upload a new file.
Thanks for the suggestions. :)
I will remove this author tag and wait for Greg's process advice.

> 
> Cc'ing Greg for process advice. For moved code, does it have to
> preserve the original Copyright line if there was one?
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210612155108.GA68%40DESKTOP-PJLD54P.localdomain.
