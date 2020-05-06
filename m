Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6OLZL2QKGQEIQKQ2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E8551C6FB6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 13:56:43 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 186sf2316957ybq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 04:56:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588766202; cv=pass;
        d=google.com; s=arc-20160816;
        b=VQyn4ICK4xUW8Ne5vZV9D0kzeRPNE9WimlYGxgKfkjQRDr+mJiDdpDVMiwZSJxlK4K
         p/9o77+TPH1HktOAqU/h+Q7hhdjpHFps2FAinij68RQsxnQC6NnwNR/Lc0Sbo+FEbue0
         GJO1PkRU+8cUuHzNvztu8UegHFtkxtNfD3wr1SXE+dC7JNOl+pppUt7Rb2iORSLufFuH
         2e3rw+LaYxKvFBSzh3p/4CuXX5iw1WoMYOKlVhIZ3qBVVjsLrnNWSWSQ3gfB61bG7fm+
         fgK/kNMW4LWHvPeCxtTyS2Fl8qPgaDh2KFM+XZG6iROQvXpG/dJzoh5q/3J6tswulnY8
         RFfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=IKLjTnV33665+DRNMdTP1xtOBCq4KrFae1OEXwuwkJ4=;
        b=K1xpNjTmS1KATrdnRzl5C5Im3PUkxGoLM/+185Ci9DNdAZP19slFlC/ie57+b6z2wQ
         6stYbUPtgUTNEt9caTiC0vOUW1wpag2Zvk3OwEzuOYdrAM3mdbPm1tmjnRKkkE0R5bDK
         DbJmrzxSCJ35uHCkPoOHwmn32+kootIElyEaQjXTYswff89W17S0P28F5kT7HnpfzcXN
         iL65y9mx+Iennnemm8Kkhx3Pbz2BO1gcBgK9qD8QQT0XN7NBsMO7WaY8A9W6YThu/6jf
         ZJqbPeA8QElOSYLbpBnro0dy/hNor32nd11pGPglBbqAPCJ3uQBxB70eGx3NG+TW94By
         DKdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=PXJKEtd2;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IKLjTnV33665+DRNMdTP1xtOBCq4KrFae1OEXwuwkJ4=;
        b=lw/A/qP03ZcyRWEppvJyp1Fqc4GxSZgShFLBM4bgkzlyBGpDQpC3cyc23K8pVaVxFj
         WDnucCXl2jYzAOlPxYnTXut8zucnjF8IL4jbmpx8GZ+AaPJxCb9o75NPQM0OsROXMPE6
         m2vlSTB+JQf0Uk/V/IRGLwjbw1qZwsyXLettm3n7JsLB+dU7X5UtWSBcMApKIphyzg6o
         X1C9g7hx6z41fm115oiuNx3mHA/9NRv5Nvz3RIqvAZhH3XyKuCk62Rlw86OIwFBFa7Sa
         XqvVQpmbH4Abw6mV5KfgFHmRjBospjhYA06T5GvAujijBtxSzJl6i1QbVzuVJ9CYQZk4
         O7Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IKLjTnV33665+DRNMdTP1xtOBCq4KrFae1OEXwuwkJ4=;
        b=RY6AFX2lrWWbzZdUBztf9P4YRpP2SvqehwHKPTQJdymrDZoAhj1ZRwbeUfjvEV2dEw
         zezgUaMFGGDQpFhhRCopRJS0/nHY5IGNbHkulgjmgbs+YzCm48QBcZuItqYqb6EluZFa
         +yk9eX3VNrp5NYzf9FYSynD9Y6jB/YVkTfzUAS9S264RFDuJW7R2ufSHKWvmZ1ocVZPT
         jAv77/95XeGksNHfron+o8RILr9YLpYKGP4eA+luLo8O1i57AtyAnyvszHxcEU6QqCOL
         ENRaOo7CSK0dXxbQaecBBXd9ZemcfMY/OJXPZuE1XQ1Edkc2Z4PUtRfQ/1Ej7pfmyOY1
         fZpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaJ5pbXFaxRmYMIbzhYCpqcw4+iLoyHX8tkVb1UNXSktiQZstJi
	F58Qw0OlrFb02Ck8SxszrXo=
X-Google-Smtp-Source: APiQypK4V4Ta8Qr/m7UNQOJ6yItsaE9K066BY6zuKAJ6WnnFCKRaJ98UMhYDuAGL7IKlRxCXP4t/iw==
X-Received: by 2002:a25:2315:: with SMTP id j21mr13781103ybj.8.1588766201799;
        Wed, 06 May 2020 04:56:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:71d5:: with SMTP id m204ls71358ybc.0.gmail; Wed, 06 May
 2020 04:56:41 -0700 (PDT)
X-Received: by 2002:a25:bb08:: with SMTP id z8mr44749ybg.129.1588766201423;
        Wed, 06 May 2020 04:56:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588766201; cv=none;
        d=google.com; s=arc-20160816;
        b=p9RubyjFCJL6bioANfmAuWuIm/0HS1QOQeac6W+VmtIgPD7GU0zsrzWhZkxvMn+LLF
         Z7bIudmBCfpOWL/gQo7Nqdn/TxKsN2xYhCPJGRWLfMlfeNM1sURCoUrnWVgw5Qb5G7WC
         0c1FTT4qlWRzulyMGWLjv4hLDPnCo8HXA5uDEoRmkh+eCxBPbiUOzOxAqrE+RlAUf+Vt
         wqrPcs+gzyOlMfwBOe13rRmWOdVaSL4eMgP+M8wvt4F4EucfN8QNGNsVveMu7g0zSGR/
         n2YnHDyj+Hl3/FbEuSnkKoiL6bhUdOQXWGz5SmxzMQ71ylj9akTe60WhAEptZq4c6is9
         YGbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=MNY7QjHyK2N8v2XPbveR8rY3W7ehZggZwWilVhYjlQw=;
        b=n7eytXj+HsxRAU2QfBIKNlnzsmI3Dre2huCZjGoRVwIDc/Q+ZcNNFbXCCHy3JgcOi9
         WS4XeUjbKhJ+7r8V9PpnS+4Mh0HJB5Y8EAIqD1Wthq+rcdieySI1f7X7vNNj9lb5aXm7
         7zXxAZpkci1v5eDrp9OWkqfDRx1HHyI01adghPS2vXjm6H3vXTOQD7H9qMQFpZKaunBo
         Pzx7QTxPppG/6koMTrWMkqCpNOZxUtmRDVnpOoN+PUNtL8S4vtNGA9NJLbzNlLVY7B9d
         LFeQnV51sFdUtV9ILSU+FylxzQYpWSlKWGdt3C5TUPjROeIFUjRIkWVtfBssUFjZtR5m
         oQKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=PXJKEtd2;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id o65si80836yba.5.2020.05.06.04.56.40
        for <kasan-dev@googlegroups.com>;
        Wed, 06 May 2020 04:56:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 02a666bec23c4b3eb4474929ed893b68-20200506
X-UUID: 02a666bec23c4b3eb4474929ed893b68-20200506
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2131291375; Wed, 06 May 2020 19:56:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 19:56:31 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 19:56:30 +0800
Message-ID: <1588766193.23664.28.camel@mtksdccf07>
Subject: Re: [PATCH 2/3] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 6 May 2020 19:56:33 +0800
In-Reply-To: <CACT4Y+ajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA@mail.gmail.com>
References: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+ajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=PXJKEtd2;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Wed, 2020-05-06 at 11:50 +0200, Dmitry Vyukov wrote:
> On Wed, May 6, 2020 at 7:22 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > We add new KASAN_RCU_STACK_RECORD configuration option. It will move
> > free track from slub meta-data (struct kasan_alloc_meta) into freed object.
> > Because we hope this options doesn't enlarge slub meta-data size.
> >
> > This option doesn't enlarge struct kasan_alloc_meta size.
> > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > - remove free track from kasan_alloc_meta, size is 8 bytes.
> >
> > This option is only suitable for generic KASAN, because we move free track
> > into the freed object, so free track is valid information only when it
> > exists in quarantine. If the object is in-use state, then the KASAN report
> > doesn't print call_rcu() free track information.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > ---
> >  mm/kasan/common.c | 10 +++++++++-
> >  mm/kasan/report.c | 24 +++++++++++++++++++++---
> >  2 files changed, 30 insertions(+), 4 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 32d422bdf127..13ec03e225a7 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -321,8 +321,15 @@ void kasan_record_callrcu(void *addr)
> >                 /* record last call_rcu() call stack */
> >                 alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
> >  }
> > -#endif
> >
> > +static void kasan_set_free_info(struct kmem_cache *cache,
> > +               void *object, u8 tag)
> > +{
> > +       /* store free track into freed object */
> > +       set_track((struct kasan_track *)(object + BYTES_PER_WORD), GFP_NOWAIT);
> > +}
> > +
> > +#else
> >  static void kasan_set_free_info(struct kmem_cache *cache,
> >                 void *object, u8 tag)
> >  {
> > @@ -339,6 +346,7 @@ static void kasan_set_free_info(struct kmem_cache *cache,
> >
> >         set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> >  }
> > +#endif
> >
> >  void kasan_poison_slab(struct page *page)
> >  {
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 7aaccc70b65b..f2b0c6b9dffa 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -175,8 +175,23 @@ static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
> >         print_track(&free_track, "Last call_rcu() call stack", true);
> >         pr_err("\n");
> >  }
> > -#endif
> >
> > +static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > +               void *object, u8 tag, const void *addr)
> > +{
> > +       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
> > +
> > +       /*
> > +        * Only the freed object can get free track,
> > +        * because free track information is stored to freed object.
> > +        */
> > +       if (*shadow_addr == KASAN_KMALLOC_FREE)
> > +               return (struct kasan_track *)(object + BYTES_PER_WORD);
> 
> Humm... the other patch defines BYTES_PER_WORD as 4... I would assume
> seeing 8 (or sizeof(long)) here. Why 4?
It should be a pointer size, maybe sizeof(long) makes more sense.

> Have you tested all 4 modes (RCU/no-RCU x SLAB/SLUB)? As far as I
> remember one of the allocators stored something in the object.
Good question, I only tested in RCU x SLUB, would you tell mew how do
no-RCU? I will test them in v2 pathset.

> 
> Also, does this work with objects with ctors and slabs destroyed by
> rcu? kasan_track may smash other things in these cases.
> Have you looked at the KASAN implementation when free_track was
> removed? That may have useful details :)
Set free_track before put into quarantine, free_track should not have to
be removed, it only have to overwirte itself.

> 
> 
> > +       else
> > +               return NULL;
> > +}
> > +
> > +#else
> >  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >                 void *object, u8 tag, const void *addr)
> >  {
> > @@ -196,6 +211,7 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >
> >         return &alloc_meta->free_track[i];
> >  }
> > +#endif
> >
> >  static void describe_object(struct kmem_cache *cache, void *object,
> >                                 const void *addr, u8 tag)
> > @@ -208,8 +224,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >                 print_track(&alloc_info->alloc_track, "Allocated", false);
> >                 pr_err("\n");
> >                 free_track = kasan_get_free_track(cache, object, tag, addr);
> > -               print_track(free_track, "Freed", false);
> > -               pr_err("\n");
> > +               if (free_track) {
> > +                       print_track(free_track, "Freed", false);
> > +                       pr_err("\n");
> > +               }
> >  #ifdef CONFIG_KASAN_RCU_STACK_RECORD
> >                 kasan_print_rcu_free_stack(alloc_info);
> >  #endif
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052155.14515-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1588766193.23664.28.camel%40mtksdccf07.
