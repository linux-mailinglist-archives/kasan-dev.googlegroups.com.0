Return-Path: <kasan-dev+bncBCMIZB7QWENRBNGNZL2QKGQERWN4W7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA6F1C6FC5
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 13:59:49 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id o6sf2173187pjl.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 04:59:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588766388; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ao6/snLBi8RHoO+N9+4hBntC4xMrdokRY45pdNczyKUPp+r6Bu6yANY7Xol+zAra/L
         7YcT4ezFeTBZiMyfOSlZm8EXsNkLr+TBsGZeAg6UxTemga/h2tjVrAjV73w1pcfsq6LQ
         1KIjnZpitj7cwUD3qE7t0GDrBM+xoWpcNaaKe+D3Vp9V4JasHZcPdKxlQ/MeXeP7j02P
         ykCZ8WyL+K+LT0qWrgwhapCjO2OVGCP7iZtpcm2U0pNAo13LogFAfTa0WLvr5a7WkuOn
         RQFIVX28pLNPOc5JZ3qhrTISEh/BMIJ/tYSG2SW9+gO6/omOehF42ZzhFaixRTguzxE2
         7tbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Omd/tNg/zdlYBoZ6Py+M8JDfCTkeKXIAts3VtNoRnxQ=;
        b=NxftmiBfuE/lRw0KKoWiYsgPKYjlloSUWwuD6s3S3lSWbkxb8uAlJeuRUZ3esqzgGH
         DL7zad1fortLuVDMqBU1PS3vF9fZhlYQKnj+zL2f4YUyq28tCy2BleGZ2M8ikZ+OqVwc
         kcNTYzHAga0BaIpXe0xxJVPaBMIZs7FPzWnJkpPT3B3U/AeB1Z3Vkxwcok2L43hmYcV/
         oYX/oqfOSe6Vt1l2XALyXzbLJUpQtRvXKUfv5R+0ZsNOKuffq2iTS2h1Kb9OJp16LpH7
         Cj3CxZ+gqmXohlyPfYvYyOxFpvHXfNkKoN3KG7SUD4x0elVKw3T5lY2n6XAwPnp5Ppso
         pLcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="J6UjhI/2";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Omd/tNg/zdlYBoZ6Py+M8JDfCTkeKXIAts3VtNoRnxQ=;
        b=ldnWczIa/aueB8JizpBmeO9yn0Dg7+QkD1w/cVP8HSnHGfmptT0J6OrZTpqObkCazh
         TwpZhO+poQwmuB0/cRSWn69zcyWwjAIdxGY/O0Io/tHqcqn2qe9TQHE9Fl3SJRqnkYul
         DJJeeUKT5rSNuyMhJPmAQKDrJWPX1VylsI8a5arUt6nrQznUulMjxpzxBVSca/88s2OJ
         ZT3RW4yB96IQc2EviV8FIth67M0L4PUfKFCbAr65eraC6Q7cE27Y3v5/Yk6fwCCuZZCn
         RKgRy6i6YUZp9zBO5ig5LnwiJTiBn9PVbblajBhAcWnEjiv8rm8Pv0tKtLGkxSxLkOnE
         M8qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Omd/tNg/zdlYBoZ6Py+M8JDfCTkeKXIAts3VtNoRnxQ=;
        b=PVOkRwB9S9QAu3HWQVlsie6xHTdEh5B2WCW6halMEvPgD5RYZ+uO5tsbm3Ux5c0Rwm
         8jcSLL+Hqe2aGZ/dEb4Ekhb+j3STORA6LPYzDX94qEX3FTB71ioWovrKIvHo7PMV6G2Z
         PRnK1lQULYa0Xd1gHULomix5DaxoYOjTMMjzfSBbaL6MBRRpuHJE1BAexSIZ+RPltlHf
         iRIGNAX5dYKqwP/X3uZnbIht/bRsuaW3Xmnu361HZ6CvctlVHjLFZ4LJ/YjbJhx+0Nro
         shHGe6UfJegmfwLmJQf5gTTHmRfd2DhwhIXyDmhAYcBsD+ESlY8uLBr4ERwxB9EIRZJ4
         oOjA==
X-Gm-Message-State: AGi0Puaoey2P5nKoQd6grw8AUlOXrjKqkyn9gtQQHE3XcN4hwB0HttKv
	2VV+4c1d+O9X3MEkfGSA+H4=
X-Google-Smtp-Source: APiQypJnSUIb4voabJ7m/NCAgQl0rvfA8uETjakOiGoPpQY5V8dNXYgt3CWwdzeg0O+NateekZxSnw==
X-Received: by 2002:a17:90b:2385:: with SMTP id mr5mr9284693pjb.172.1588766388050;
        Wed, 06 May 2020 04:59:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a98:: with SMTP id x24ls3409060pjn.0.gmail; Wed, 06
 May 2020 04:59:47 -0700 (PDT)
X-Received: by 2002:a17:90a:dc01:: with SMTP id i1mr8934808pjv.166.1588766387652;
        Wed, 06 May 2020 04:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588766387; cv=none;
        d=google.com; s=arc-20160816;
        b=img/0saxenJ8vrW8m7y4ZJAIIIAaO0QsmVH8HM0laIFQjDznBdsQH1m8tkIcnnBenz
         2kl1AvsbH3bbZeZCVgfwchgf+DkAbn4FndNT6BPVU319SmwaZ7Xtc6A6Xt0G/4oBMLrj
         VuTCmT+1fPRTqw85MVsjqEIGx5dd9YFbuD5nAbqU9Z5GeIn9TJutx0sLA3bEchh7KvCh
         OWEvJzE1jlJCT3zWqD3OxvhKc9J9cE2ymf9dNdd5KLdygNaISFt+lbN1kS/Ga7tDjR6V
         oE1Xu4KRYz6r6i+FoCF2jkn8kNdMYKjP/j+eYJakhU6lFiJk/XJYAOEVCCIrYhDw346T
         /ACw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=neznKY+6L7BaBR2xiVWj7fZLdLOn94ic/5ND5jWNOV8=;
        b=s/u3AUq4VoGRzh+/9Ep+nyo9wdRahDBeSxQnSNck5deV++mL/7mABMqaN64qaFED/7
         ysvs2RwW/wMBHODf0nSHZJJP255zftJMQL+2Yeq1/Z4sPvYnTa0JZ0PP1XSbnEMhRtgW
         lAsoeiJexOd4ORYBG824ICRL+qcUIsvQx71mWs6qaZZiMI1RY1xlTZljIiIwfrrSl6M2
         ouTa6ydMhT2uH7hW/p0wCHFuBozIr5O+BwGZY1kKSvGAySXzTkvucOZQnxUMl37LRngF
         qWhZSL+nmAENXHkMw9bjbi+f8MnKvmbWbALcYWNK6G2hPi9/CH68ZYTGhWAuJ4Xdc33v
         /9SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="J6UjhI/2";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id f3si68201plo.4.2020.05.06.04.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 04:59:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id k81so1531900qke.5
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 04:59:47 -0700 (PDT)
X-Received: by 2002:a37:4b0c:: with SMTP id y12mr8038443qka.43.1588766386312;
 Wed, 06 May 2020 04:59:46 -0700 (PDT)
MIME-Version: 1.0
References: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
 <CACT4Y+ajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA@mail.gmail.com> <1588766193.23664.28.camel@mtksdccf07>
In-Reply-To: <1588766193.23664.28.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 13:59:34 +0200
Message-ID: <CACT4Y+bOxe+Y8BuzC=0k6rmkDiJ7PBnVcsY=jzZe1trVj476fg@mail.gmail.com>
Subject: Re: [PATCH 2/3] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="J6UjhI/2";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, May 6, 2020 at 1:56 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Wed, 2020-05-06 at 11:50 +0200, Dmitry Vyukov wrote:
> > On Wed, May 6, 2020 at 7:22 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > We add new KASAN_RCU_STACK_RECORD configuration option. It will move
> > > free track from slub meta-data (struct kasan_alloc_meta) into freed object.
> > > Because we hope this options doesn't enlarge slub meta-data size.
> > >
> > > This option doesn't enlarge struct kasan_alloc_meta size.
> > > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > >
> > > This option is only suitable for generic KASAN, because we move free track
> > > into the freed object, so free track is valid information only when it
> > > exists in quarantine. If the object is in-use state, then the KASAN report
> > > doesn't print call_rcu() free track information.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > ---
> > >  mm/kasan/common.c | 10 +++++++++-
> > >  mm/kasan/report.c | 24 +++++++++++++++++++++---
> > >  2 files changed, 30 insertions(+), 4 deletions(-)
> > >
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 32d422bdf127..13ec03e225a7 100644
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -321,8 +321,15 @@ void kasan_record_callrcu(void *addr)
> > >                 /* record last call_rcu() call stack */
> > >                 alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
> > >  }
> > > -#endif
> > >
> > > +static void kasan_set_free_info(struct kmem_cache *cache,
> > > +               void *object, u8 tag)
> > > +{
> > > +       /* store free track into freed object */
> > > +       set_track((struct kasan_track *)(object + BYTES_PER_WORD), GFP_NOWAIT);
> > > +}
> > > +
> > > +#else
> > >  static void kasan_set_free_info(struct kmem_cache *cache,
> > >                 void *object, u8 tag)
> > >  {
> > > @@ -339,6 +346,7 @@ static void kasan_set_free_info(struct kmem_cache *cache,
> > >
> > >         set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> > >  }
> > > +#endif
> > >
> > >  void kasan_poison_slab(struct page *page)
> > >  {
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 7aaccc70b65b..f2b0c6b9dffa 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -175,8 +175,23 @@ static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
> > >         print_track(&free_track, "Last call_rcu() call stack", true);
> > >         pr_err("\n");
> > >  }
> > > -#endif
> > >
> > > +static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > > +               void *object, u8 tag, const void *addr)
> > > +{
> > > +       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
> > > +
> > > +       /*
> > > +        * Only the freed object can get free track,
> > > +        * because free track information is stored to freed object.
> > > +        */
> > > +       if (*shadow_addr == KASAN_KMALLOC_FREE)
> > > +               return (struct kasan_track *)(object + BYTES_PER_WORD);
> >
> > Humm... the other patch defines BYTES_PER_WORD as 4... I would assume
> > seeing 8 (or sizeof(long)) here. Why 4?
> It should be a pointer size, maybe sizeof(long) makes more sense.
>
> > Have you tested all 4 modes (RCU/no-RCU x SLAB/SLUB)? As far as I
> > remember one of the allocators stored something in the object.
> Good question, I only tested in RCU x SLUB, would you tell mew how do
> no-RCU? I will test them in v2 pathset.

I meant with CONFIG_KASAN_RCU_STACK_RECORD=y and with
CONFIG_KASAN_RCU_STACK_RECORD not set.
But if we drop CONFIG_KASAN_RCU_STACK_RECORD config, then it halves
the number of configurations to test ;)


> >
> > Also, does this work with objects with ctors and slabs destroyed by
> > rcu? kasan_track may smash other things in these cases.
> > Have you looked at the KASAN implementation when free_track was
> > removed? That may have useful details :)
> Set free_track before put into quarantine, free_track should not have to
> be removed, it only have to overwirte itself.
>
> >
> >
> > > +       else
> > > +               return NULL;
> > > +}
> > > +
> > > +#else
> > >  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > >                 void *object, u8 tag, const void *addr)
> > >  {
> > > @@ -196,6 +211,7 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > >
> > >         return &alloc_meta->free_track[i];
> > >  }
> > > +#endif
> > >
> > >  static void describe_object(struct kmem_cache *cache, void *object,
> > >                                 const void *addr, u8 tag)
> > > @@ -208,8 +224,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > >                 print_track(&alloc_info->alloc_track, "Allocated", false);
> > >                 pr_err("\n");
> > >                 free_track = kasan_get_free_track(cache, object, tag, addr);
> > > -               print_track(free_track, "Freed", false);
> > > -               pr_err("\n");
> > > +               if (free_track) {
> > > +                       print_track(free_track, "Freed", false);
> > > +                       pr_err("\n");
> > > +               }
> > >  #ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > >                 kasan_print_rcu_free_stack(alloc_info);
> > >  #endif
> > > --
> > > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbOxe%2BY8BuzC%3D0k6rmkDiJ7PBnVcsY%3DjzZe1trVj476fg%40mail.gmail.com.
