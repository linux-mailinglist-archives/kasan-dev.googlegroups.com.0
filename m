Return-Path: <kasan-dev+bncBDGPTM5BQUDRB4VW2L4QKGQESUSEBOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D50243230
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 03:46:27 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id a13sf2082304oie.4
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 18:46:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597283186; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEIMyvfftk9s8W42Efz46O0M84bfHGwR0yb72xl6ph5e6xjnYIsONskPDTqhidrAiE
         sBDogRLe/Niv2v44R06icrFhiOEPFoSDbThR4zT6n0+EFzDn4B+fzdWbQGHI4AFGaegs
         hNIuy9zmZTEb+3NGJRU8sKNKv0jh4F7NV1KdbdG26qeYIblYDc4gLoJ+RuVjU5zLgwd4
         Srjao4J4bg5f2GdaePs8JeOwJEFlcho6QRt+wVfuZzMxPuwAAAAZmU7jZZNCpmv9fDBP
         Pz+4chhnZLL3q8hVdteiTEd1vC1/Xoj0BU6QU2xIKXu72KUTinYgsg5jAL5qJ9iMQwSP
         G2GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=eH8cT2mQ+2VklXeC+MIWvxclm0yE2XjI+pNkHvRPTZM=;
        b=bHHGAjTYeo1vfZP5QSeAWMP0tF5OmDCxWLVKweYNwjEaIiCQx4NDGz3dHivyQSShR9
         zoBlzfYxN9kzlOoap4TIUsIz/E+nOaYlbqn0c6k1CAwK9O7YyouMWhQbpNeyMksuu+1C
         k6boAUQ4zUd9xfGLXSJsSiMlAacnvM5MqGkAii5c3auiLUtA5riaQ6N8nmzzF5+PKent
         Rjs5iWGdxphHs0X6Sr6wHbhOOvyxB/iSqynLbbkJikYc2mSX03gEhFa+CjumIhoOIyA6
         AClE/Tb1SUS0cLSNFIAM8H0YylLd2f5fdm1BSnym38iSz2bh6+Q5C1rTfRE4nzJWBUvA
         YabA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=PVYnGy0Z;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eH8cT2mQ+2VklXeC+MIWvxclm0yE2XjI+pNkHvRPTZM=;
        b=Ds9QXtmW+nKnhd7xERyPA4070EUbGq1mGybyZ1T6nDh2aGcJ0zmJJS5aLVGXdY52Vb
         hC/88k2KhXkSw19Cy/AaCMTBa0H9PWOIjTGfBXFNfXZD3Pteqwtz6fjYqiYwfzK1r+wM
         AapXVTPJCBiDFCdJzUPHoyc1mRPJuqRd6Hf7jYSAf5r7H4iuNMpu7+vDYx0HMWZkfEgr
         HmnSOKL+53+WBGPr+7wVXZtyhTH+Pu8PknUKCS6Eo2f+zcwwsHO5jSk0j7DEQPplm/Mv
         fzZoDMKGBl6sW9m839CCiPaFBevrxDoEhyGqz7waHM29xLLlsQJmqckevKoLvdT9sBfe
         VJ9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eH8cT2mQ+2VklXeC+MIWvxclm0yE2XjI+pNkHvRPTZM=;
        b=Ib+PHqNZRt4VrHnOVsT2LyiDWyOY/mFngQHa7ha7wJMARZaVyR9YuaxQJt6MNKcYJG
         6WW8D+X6foyL5eEPetG9J9iOBg+SRlG/Gy656mtKN7/HOell+AnHXri43Fw4XFxT2ErA
         O/fTOMIchyeknVqXArX/8m7qYIYJCIlZOWL5anRcOSWsVOkWxU0N5h5/vDuL4TKqTJvR
         aZrmwBP/bU5i8vQeMiqD7hXMzFpCSnOgbHqF8BDTsk28uqJK22R4Xcl+MEE4W1TT7VK4
         NnXBtmtuW03ZsagzVg/E6LKfEBaP9ZC8YSk80Ld7fRTDzwBEUfgX9d2CdqAuNtu4OnK5
         GvLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532346HV2l496bTSubFt4aHq8oO9/b1cXQ5i/xVSswkZXx24iT8J
	Gv5RQxFvUf5b4F95JeeN4+E=
X-Google-Smtp-Source: ABdhPJwBpgVt281z6OcFZaTgQJd2zdXk7mt0H+psWJLHYj4ON6167duy9EzOT9CGIsDgA1IgCzL3IQ==
X-Received: by 2002:aca:654c:: with SMTP id j12mr1708222oiw.25.1597283186418;
        Wed, 12 Aug 2020 18:46:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66d7:: with SMTP id t23ls899154otm.1.gmail; Wed, 12 Aug
 2020 18:46:26 -0700 (PDT)
X-Received: by 2002:a9d:621:: with SMTP id 30mr2315667otn.261.1597283186080;
        Wed, 12 Aug 2020 18:46:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597283186; cv=none;
        d=google.com; s=arc-20160816;
        b=wDDUPNNzUtnezFEtN4V9FR60KPwRTeVr57VDqX3CtQiTkoqBUpaauY2Vp6o41/FPtI
         CprEHSqPgc37wZwyrGjcQ0Boj9WoszWrOSmAGBj1q0utuCHM7oDqpKBkX8nn6Q1JHVGe
         P8bQq1tKGfWjUPhjihJxBBIFyO3RTX7TCXOMKyOfgrZyLfOEmDnyJE0atQanf26w/O9p
         KhGYjaOPnOJttWIxouaY18WVqAQ5qG6IYGLVR/TLaKwHG/2u4SGf5feF6HsOcXX2l6NA
         11p69rD5RUmdOPVnZOauCKpa3EzDeBIcnCWOyxMSXRDBb3L8XDKY/ssBh7wR+nHkm/EZ
         q98w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=asJV3IBv1/0dhV/oRZH8LjXOLv7AOsr87CflwjOG1gY=;
        b=uq2n8BmguAf+cZEQyywLmkaKjt0jC4mOFUd9kuoL/kzd+tQboTFtnl++wq2YyoP8Fs
         JHPhTZlFxGYzm42vQ4oHNVb+7vV8Vtz/WcaBEpRNxTuoWqC4m0FIcq0MS5TtWKlV0dKG
         APgkkdLcmBdwR2O+r19oqPGTSlsHX1V9e8mv1qznCZTKED2sKMZHcV+MqnnwJRZ4XJl6
         zuDqVdKaK3hD6pvBBDx30ZGGFxwlRsRgocFN+FKdwXOGgY/ScbVElIavy6ljVvBCC5fJ
         66fj86Rb627YoxGqalu4ixmKOcKVOKlgk6xvtHBBTjx0SNnNF11IoS5VV4mwnXd2tV6b
         rbwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=PVYnGy0Z;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id r64si173823oor.2.2020.08.12.18.46.25
        for <kasan-dev@googlegroups.com>;
        Wed, 12 Aug 2020 18:46:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: a83d17fcab4e4f118142b12a28016c02-20200813
X-UUID: a83d17fcab4e4f118142b12a28016c02-20200813
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 636757711; Thu, 13 Aug 2020 09:46:21 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 13 Aug 2020 09:46:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 13 Aug 2020 09:46:15 +0800
Message-ID: <1597283178.9999.19.camel@mtksdccf07>
Subject: Re: [PATCH 1/5] timer: kasan: record and print timer stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, "Stephen
 Boyd" <sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>, "Thomas
 Gleixner" <tglx@linutronix.de>
Date: Thu, 13 Aug 2020 09:46:18 +0800
In-Reply-To: <CANpmjNO9=JBcSV-nif9a=4Zt7gTCp6e5c2jVXMCSFgP3v2P9-w@mail.gmail.com>
References: <20200810072313.529-1-walter-zh.wu@mediatek.com>
	 <CANpmjNO9=JBcSV-nif9a=4Zt7gTCp6e5c2jVXMCSFgP3v2P9-w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: A828CD4FB1E137D0EE7E3C33E0D2CE14A46CDB2C1BF3FFD27ED08E538949AC012000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=PVYnGy0Z;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Wed, 2020-08-12 at 16:13 +0200, Marco Elver wrote:
> On Mon, 10 Aug 2020 at 09:23, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > This patch records the last two timer queueing stacks and prints
> > up to 2 timer stacks in KASAN report. It is useful for programmers
> > to solve use-after-free or double-free memory timer issues.
> >
> > When timer_setup() or timer_setup_on_stack() is called, then it
> > prepares to use this timer and sets timer callback, we store
> > this call stack in order to print it in KASAN report.
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: John Stultz <john.stultz@linaro.org>
> > Cc: Stephen Boyd <sboyd@kernel.org>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >  include/linux/kasan.h |  2 ++
> >  kernel/time/timer.c   |  2 ++
> >  mm/kasan/generic.c    | 21 +++++++++++++++++++++
> >  mm/kasan/kasan.h      |  4 +++-
> >  mm/kasan/report.c     | 11 +++++++++++
> >  5 files changed, 39 insertions(+), 1 deletion(-)
> 
> I'm commenting on the code here, but it also applies to patch 2/5, as
> it's almost a copy-paste.
> 
> In general, I'd say the solution to get this feature is poorly
> designed, resulting in excessive LOC added. The logic added already
> exists for the aux stacks.
> 

That's true, we will have refactoring for it.

> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 23b7ee00572d..763664b36dc6 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -175,12 +175,14 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> >  void kasan_cache_shrink(struct kmem_cache *cache);
> >  void kasan_cache_shutdown(struct kmem_cache *cache);
> >  void kasan_record_aux_stack(void *ptr);
> > +void kasan_record_tmr_stack(void *ptr);
> >
> >  #else /* CONFIG_KASAN_GENERIC */
> >
> >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> >  static inline void kasan_record_aux_stack(void *ptr) {}
> > +static inline void kasan_record_tmr_stack(void *ptr) {}
> 
> It appears that the 'aux' stack is currently only used for call_rcu
> stacks, but this interface does not inherently tie it to call_rcu. The
> only thing tying it to call_rcu is the fact that the report calls out
> call_rcu.
> 
> >  /**
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 4b3cbad7431b..f35dcec990ab 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -347,6 +347,27 @@ void kasan_record_aux_stack(void *addr)
> >         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> >  }
> >
> > +void kasan_record_tmr_stack(void *addr)
> > +{
> > +       struct page *page = kasan_addr_to_page(addr);
> > +       struct kmem_cache *cache;
> > +       struct kasan_alloc_meta *alloc_info;
> > +       void *object;
> > +
> > +       if (!(page && PageSlab(page)))
> > +               return;
> > +
> > +       cache = page->slab_cache;
> > +       object = nearest_obj(cache, page, addr);
> > +       alloc_info = get_alloc_info(cache, object);
> > +
> > +       /*
> > +        * record the last two timer stacks.
> > +        */
> > +       alloc_info->tmr_stack[1] = alloc_info->tmr_stack[0];
> > +       alloc_info->tmr_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > +}
> 
> The solution here is, unfortunately, poorly designed. This is a
> copy-paste of the kasan_record_aux_stack() function.
> 

kasan_record_aux_stack() will be re-used for call_rcu, timer, and
workqueue.

> >  void kasan_set_free_info(struct kmem_cache *cache,
> >                                 void *object, u8 tag)
> >  {
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index ef655a1c6e15..c50827f388a3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -108,10 +108,12 @@ struct kasan_alloc_meta {
> >         struct kasan_track alloc_track;
> >  #ifdef CONFIG_KASAN_GENERIC
> >         /*
> > -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +        * call_rcu() call stack and timer queueing stack are stored
> > +        * into struct kasan_alloc_meta.
> >          * The free stack is stored into struct kasan_free_meta.
> >          */
> >         depot_stack_handle_t aux_stack[2];
> > +       depot_stack_handle_t tmr_stack[2];
> >  #else
> >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> >  #endif
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index fed3c8fdfd25..6fa3bfee381f 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -191,6 +191,17 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >                         print_stack(alloc_info->aux_stack[1]);
> >                         pr_err("\n");
> >                 }
> > +
> > +               if (alloc_info->tmr_stack[0]) {
> > +                       pr_err("Last timer stack:\n");
> > +                       print_stack(alloc_info->tmr_stack[0]);
> > +                       pr_err("\n");
> > +               }
> > +               if (alloc_info->tmr_stack[1]) {
> > +                       pr_err("Second to last timer stack:\n");
> > +                       print_stack(alloc_info->tmr_stack[1]);
> > +                       pr_err("\n");
> > +               }
> 
> Why can't we just use the aux stack for everything, and simply change
> the message printed in the report. After all, the stack trace will
> include all the information to tell if it's call_rcu, timer, or
> workqueue.
> 

This is a good suggestion, next patch will do it.

> The reporting code would simply have to be changed to say something
> like "Last potentially related work creation:" -- because what the
> "aux" thing is trying to abstract are stack traces to work creations
> that took an address that is closely related. Whether or not you want
> to call it "work" is up to you, but that's the most generic term I
> could think of right now (any better terms?).
> 

Work is good.

> Another argument for this consolidation is that it's highly unlikely
> that aux_stack[a] && tmr_stack[b] && wq_stack[c], and you need to
> print all the stacks. If you are worried we need more aux stacks, just
> make the array size 3+ (but I think it's not necessary).
> 

We hope that next patch keep it as it is aux_stack[2], it may record
call_rcu, timer, or workqueue. Because struct kasan_alloc_meta is 16
bytes, it will have the minimal redzone size and good alignment, lets
get better memory consumption.


Thanks for your good suggestion.

Walter


> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1597283178.9999.19.camel%40mtksdccf07.
