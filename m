Return-Path: <kasan-dev+bncBDGPTM5BQUDRB3OQZL2QKGQEQ2MRUAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 419B21C6FED
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 14:07:10 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id fe18sf1896528qvb.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 05:07:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588766829; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqsxlVjdVmB7klmicHUFXhy/gcfNzOfUzCOUYF19H4sWM9AgL3hrJGHGxothyCaSZu
         fWByEIqavmOJFJubG7z3ZxXKgN6ibrW6tjGvo4soxWxqlQd93iViC4qDh/scdz0/WqpN
         voAGfzLYa9WM8R53xJmsmMJ60ZkSBcY6vGHCMkdGarb7pB+z0DJjVu9neL7ggaIv9pzo
         FumP6lQc1X5hapVK9TBDiRNGgzs9BCJpFlezNhKb47DTh6+9IRW6F885KfxMzm4Ey+vv
         NQpJTmTeMbAj17oq6x3Jjuy5RIg/wmMhfPX0lbZ80fhQIH+Eld1WiD32+tP2LNdH5ESf
         kAeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=qXA2EQ+o4FwmK8e+UEUO5QRro/iZCsHE4t0Z1+O8kC8=;
        b=S/3Pz1i1GvkxtZM5Vxf9psfVf/I1Vs8yISsq6XOmbhBLQdfo1CcDAT3Ddsgp+lUTa2
         ji8fg82lP7KjF5sGCFvAEXxiZR2w5/CYoMcBvCV0rmSL7lTD+c+LPmlElPMr58atTMpN
         BkJZ0mugO/umImTf05VxZUZSIF6vKMUpfwNPEEio7rWYejI5hy1TzKYPJEB9G/H0y1kF
         cS74UVUxJOLivtmBPyBLPC8ZiP8DZfq/jdrGrKK0c+W9I3e/nIAaCdl25ZZmQH+pqqCA
         sQbExZbL15ZpmC8apEZHNaKxzcv4217Zvy5DEGN9CbnUPKeoggeZJWB6aD4znJdjYdg/
         xy7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=e2XxZSMn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qXA2EQ+o4FwmK8e+UEUO5QRro/iZCsHE4t0Z1+O8kC8=;
        b=jYqlMK/Ad/gmqpp0UX4NBkGxv/Cf5pF71cpXe2j0+ylOmo9das4Il7GoW7LfSNjpSO
         oqxnrqQE062iAQGFD4uBFtPvxEBUmdkE5QSz0kPZ333ScTpZC0SpaHHpwP7CvdO1xpAB
         aq+v8eKgu4SKJuDo7k8awwDduOKiByBFAJvw/Ibvva3Jn6U9dJQf6HpldVMA3nC6wfv4
         JfHoAgiN0OLP+8emgx3/LZnkYz72DOyFG6aup3Mzn4iwjsB+3Lr1UXIKMi2RsA1TfCaS
         CV2AdBN7KvaZg/Q6112j441tWblire/BSAaj3VxpbaHNWft0vDaehKJgAqn/oRUhliZz
         /qMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qXA2EQ+o4FwmK8e+UEUO5QRro/iZCsHE4t0Z1+O8kC8=;
        b=NyT+tlbemHQtJMhgIPda3aMpLXyRJzYbgvJOJ/YGQ3GsppOa+TiUHpSbJ/k5MVROak
         yf9Pp3KJRWOfUXATECHaQt1xZocLXJFRPdIGSzL5xv5sviqeMe3FMek1+qe5happYcji
         VFeZnhpmqflE7Wen9HXBWKia7GlEC6rKevsCS/4wMsLQpblNYcRHEHyGBRVEzmHS7+LX
         mszv1JsfAIYJTXMeQPtDEFI4IjFICmYu9KrieoLB1hphkyyfn/vQ5kLC2wG9hOcWUERV
         /sKlYghjp0Y49ZtANjgySnvrHT0IkXj4PQbGkJJYI6rpN13yJ6qvkoKg1qL24qJ84oax
         jc+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYPSgxs9gb96oytrN/YCAVeeBpnCInxxY52+wBYoJc3YqlO9X+G
	/LnhG9MdRlolvm6KLan48r4=
X-Google-Smtp-Source: APiQypI3H1GDHgqR0+It2ZxcZnxUHaKpVcfcoLlZVtgisdFNDb3K33tktyLIx/yDN5ffKLhoHFLuwQ==
X-Received: by 2002:ac8:19fd:: with SMTP id s58mr7933112qtk.354.1588766829129;
        Wed, 06 May 2020 05:07:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:609:: with SMTP id z9ls849064qvw.5.gmail; Wed, 06
 May 2020 05:07:08 -0700 (PDT)
X-Received: by 2002:ad4:4c4d:: with SMTP id cs13mr7439312qvb.207.1588766828791;
        Wed, 06 May 2020 05:07:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588766828; cv=none;
        d=google.com; s=arc-20160816;
        b=TfEzH7k27lAjfCQaN0ilLmy2yqe6ZtjA7qe7YvrkFwLxn1GUemb8atiYOzvh/UM/EZ
         HGnyJ8E+Nt2mjD0jiIQAAfPjBosJXq0IdiF8sdy5XtqfeXj5gmcfZL98j1I1xj9yFAnH
         h7QVkXPEA2jgZdEEVUqgZpSr92dK/IaVBmIxbVpzNCUDkYXP+ZSW/2Pw6LNwW/qax3pl
         EF0mbjQGmNUzsH7aaXXoXCrXVy6PAbCFw1eCROc9Eu91ECE2JOJ31IealpyZiWR86a+4
         ewBK1PjVq7UdkXLVZVQqvOWL015/elN8zs+/gLIRnx0+f5vozY5l0pje+0W2RQmwSOCQ
         W9ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=xiv1xlLmws1dThuPdvPP+yLmXez/7eZ0aRvlqDySsPo=;
        b=xwTzrcJX8VkbxlAwcVild2d6+/uIpTmRnS9DYhMdSTM72PmBpfjVHM3K9fcf4J+Z7a
         dyzMxrwiv4HIg4dFC7+eXcy8oj8I83w4vbOVo+HpAAeeSCBIEETQstNhQzTTVJAKgfPi
         PPQKZaCdl9QAzzdeWD2yJ+nRtO4mXFkQ5T7QAIZg+AMXVIvMRMCnx7I5oZX26+xWNOOd
         1xXE1b1yAA44rzkgAW8sMSCoJwNYqyo/kbVzgzbicRn/ss4Eo5YNdK2OFsq/v6gcsNzS
         f6l9qXf0X2lYlG25HF+vfVwzLz4gCjA6W0gH8uoSGtrgW4kmOPXicvwsd8+kbLa/6UHT
         dPuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=e2XxZSMn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u20si165570qka.2.2020.05.06.05.07.07
        for <kasan-dev@googlegroups.com>;
        Wed, 06 May 2020 05:07:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: ff308a5594514d7bbe8000d0922390e2-20200506
X-UUID: ff308a5594514d7bbe8000d0922390e2-20200506
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 939732597; Wed, 06 May 2020 20:07:03 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 20:06:58 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 20:06:58 +0800
Message-ID: <1588766821.7534.3.camel@mtksdccf07>
Subject: Re: [PATCH 2/3] kasan: record and print the free track
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 6 May 2020 20:07:01 +0800
In-Reply-To: <CACT4Y+bOxe+Y8BuzC=0k6rmkDiJ7PBnVcsY=jzZe1trVj476fg@mail.gmail.com>
References: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+ajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA@mail.gmail.com>
	 <1588766193.23664.28.camel@mtksdccf07>
	 <CACT4Y+bOxe+Y8BuzC=0k6rmkDiJ7PBnVcsY=jzZe1trVj476fg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: C775F1E3319AFBF59C1D207AB67E55811CC5F8909591D57E3E5AFA2BB1C54DE42000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=e2XxZSMn;       spf=pass
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

On Wed, 2020-05-06 at 13:59 +0200, Dmitry Vyukov wrote:
> On Wed, May 6, 2020 at 1:56 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Wed, 2020-05-06 at 11:50 +0200, Dmitry Vyukov wrote:
> > > On Wed, May 6, 2020 at 7:22 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > We add new KASAN_RCU_STACK_RECORD configuration option. It will move
> > > > free track from slub meta-data (struct kasan_alloc_meta) into freed object.
> > > > Because we hope this options doesn't enlarge slub meta-data size.
> > > >
> > > > This option doesn't enlarge struct kasan_alloc_meta size.
> > > > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > > > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > > >
> > > > This option is only suitable for generic KASAN, because we move free track
> > > > into the freed object, so free track is valid information only when it
> > > > exists in quarantine. If the object is in-use state, then the KASAN report
> > > > doesn't print call_rcu() free track information.
> > > >
> > > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > ---
> > > >  mm/kasan/common.c | 10 +++++++++-
> > > >  mm/kasan/report.c | 24 +++++++++++++++++++++---
> > > >  2 files changed, 30 insertions(+), 4 deletions(-)
> > > >
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > index 32d422bdf127..13ec03e225a7 100644
> > > > --- a/mm/kasan/common.c
> > > > +++ b/mm/kasan/common.c
> > > > @@ -321,8 +321,15 @@ void kasan_record_callrcu(void *addr)
> > > >                 /* record last call_rcu() call stack */
> > > >                 alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
> > > >  }
> > > > -#endif
> > > >
> > > > +static void kasan_set_free_info(struct kmem_cache *cache,
> > > > +               void *object, u8 tag)
> > > > +{
> > > > +       /* store free track into freed object */
> > > > +       set_track((struct kasan_track *)(object + BYTES_PER_WORD), GFP_NOWAIT);
> > > > +}
> > > > +
> > > > +#else
> > > >  static void kasan_set_free_info(struct kmem_cache *cache,
> > > >                 void *object, u8 tag)
> > > >  {
> > > > @@ -339,6 +346,7 @@ static void kasan_set_free_info(struct kmem_cache *cache,
> > > >
> > > >         set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > > >  }
> > > > +#endif
> > > >
> > > >  void kasan_poison_slab(struct page *page)
> > > >  {
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 7aaccc70b65b..f2b0c6b9dffa 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -175,8 +175,23 @@ static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
> > > >         print_track(&free_track, "Last call_rcu() call stack", true);
> > > >         pr_err("\n");
> > > >  }
> > > > -#endif
> > > >
> > > > +static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > > +               void *object, u8 tag, const void *addr)
> > > > +{
> > > > +       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
> > > > +
> > > > +       /*
> > > > +        * Only the freed object can get free track,
> > > > +        * because free track information is stored to freed object.
> > > > +        */
> > > > +       if (*shadow_addr == KASAN_KMALLOC_FREE)
> > > > +               return (struct kasan_track *)(object + BYTES_PER_WORD);
> > >
> > > Humm... the other patch defines BYTES_PER_WORD as 4... I would assume
> > > seeing 8 (or sizeof(long)) here. Why 4?
> > It should be a pointer size, maybe sizeof(long) makes more sense.
> >
> > > Have you tested all 4 modes (RCU/no-RCU x SLAB/SLUB)? As far as I
> > > remember one of the allocators stored something in the object.
> > Good question, I only tested in RCU x SLUB, would you tell mew how do
> > no-RCU? I will test them in v2 pathset.
> 
> I meant with CONFIG_KASAN_RCU_STACK_RECORD=y and with
> CONFIG_KASAN_RCU_STACK_RECORD not set.
> But if we drop CONFIG_KASAN_RCU_STACK_RECORD config, then it halves
> the number of configurations to test ;)
> 
Ok, I have be tested by RCU xSLUB and no_RCUxSLUB, It is workable. So I
only miss this SLAB combination. 

> 
> > >
> > > Also, does this work with objects with ctors and slabs destroyed by
> > > rcu? kasan_track may smash other things in these cases.
> > > Have you looked at the KASAN implementation when free_track was
> > > removed? That may have useful details :)
> > Set free_track before put into quarantine, free_track should not have to
> > be removed, it only have to overwirte itself.
> >
> > >
> > >
> > > > +       else
> > > > +               return NULL;
> > > > +}
> > > > +
> > > > +#else
> > > >  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > >                 void *object, u8 tag, const void *addr)
> > > >  {
> > > > @@ -196,6 +211,7 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > >
> > > >         return &alloc_meta->free_track[i];
> > > >  }
> > > > +#endif
> > > >
> > > >  static void describe_object(struct kmem_cache *cache, void *object,
> > > >                                 const void *addr, u8 tag)
> > > > @@ -208,8 +224,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > > >                 print_track(&alloc_info->alloc_track, "Allocated", false);
> > > >                 pr_err("\n");
> > > >                 free_track = kasan_get_free_track(cache, object, tag, addr);
> > > > -               print_track(free_track, "Freed", false);
> > > > -               pr_err("\n");
> > > > +               if (free_track) {
> > > > +                       print_track(free_track, "Freed", false);
> > > > +                       pr_err("\n");
> > > > +               }
> > > >  #ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > > >                 kasan_print_rcu_free_stack(alloc_info);
> > > >  #endif
> > > > --
> > > > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1588766821.7534.3.camel%40mtksdccf07.
