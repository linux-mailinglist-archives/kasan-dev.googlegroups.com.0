Return-Path: <kasan-dev+bncBDGPTM5BQUDRBVOGZL2QKGQEVN6AW2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D5001C6F94
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 13:45:27 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id q142sf1293247pfc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 04:45:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588765526; cv=pass;
        d=google.com; s=arc-20160816;
        b=0+YkbiMCErNZlFAY0rRrfGpAUDJqgQd5gm17r+q6KeiqF9xc/m07HE0FV+OR3SvAmd
         T4gbj7qr0zxPm8STMbhnnA6Zr2kGepjK3n5fpGTx/c+W7K3+9XDYN3f9GetK3FjoYcwB
         aMQOSCaaa7M+F6YNnj6tervJpK7/gEpFjGMrVn5OezkRq94SEdAWSU3AAw8zOTrSeB7C
         68+Kqd/z7tRoM0j15BHhomBgBvUcMLhWPbB/C5DLK5ah92n6TqqDwSFfqaxiJtog910o
         gaFWZBlpMXHJrqwkoO03Zs0bvJ/fMeUxhaPHxA4s+po8fGKyFKAjTn7oeJRDEfa0eLcC
         6UDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=PGuoTGANMjQAGbTFRRIYPs5prrq4IZkcSLoVxclq/VA=;
        b=Hs2KAWxnY3a6BLLBj496OVXZhIrR8S+/po/UnyVo4T8AHPhFwicFCeFkBU2Cvfj5ud
         HC9jxnSdMUr5HPTi4Yd1z4XT+CbhOdkSJAPggQR6OUhUhauyuEwotUfl6ji6ZQ5qqnEf
         Y3GjtlIn9DBtaigZ5fsN4vpVwsDFrRI1GY72QZYG3t9mRUTRpoy8eJqfBubwX6KhNi2Q
         HZ+mL0fFJDMF9lhQf77T2YFXe8x2vXx77PB12ZkOh9Cs9/PuQVd9GMUezmrreLk5iltj
         SOKZdtrQTFQYFQP01FhMOsainarJ2jcU5WdqPZAz9rUUcm5PfmU/RDvuLBWFHxPbbGRQ
         le4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Row5HprT;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PGuoTGANMjQAGbTFRRIYPs5prrq4IZkcSLoVxclq/VA=;
        b=Vxk5RXv9a6heym1lnlGqNq8YRKR52Cxv8g1S4skU+gvpe7V9i6djGVVpsQGwO5nb72
         BtgMnHyviuIHcNDAD6VkGLtOhVe6cu9gjJCe9P+avIzjJhqx47uM6iX0f00x9CnBrYJC
         jwHkW/TTFQvLC0yfO0svW1o1b+rWihGZZzskmTigAg9CyRwC6pSoBB/MhbtfvsnNIm9v
         vPxvxehNo0Tkphc8KBYmwR5lvuXZL//SYtr2v0Jrpf9WYL9fKQMGpO1wnajlSnVmwUAd
         R/BsEoJH3PGEhayFz4ESqGtkUJCoWL70paX0NKnkamXxQQGKKD21JiaaO3Kn5lNY8/dR
         yBLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PGuoTGANMjQAGbTFRRIYPs5prrq4IZkcSLoVxclq/VA=;
        b=fxniPuNwf9wBpAFHKZxoALzQl2IcOdSwFhPQtZhEK+20P2IFhhdLn+FAJzOsJoWEIU
         +KPBxty/D8zz7+dFBTT9YO6uUNwKgcy1itfKST81uBVYgUNpuBTiWfdhMaC62x1n7lnm
         gbmGUaUms+cXODcvdyJbHjUPF6blh1DXC+X/e1Zb+s4/Jg6fJA42Lz6kUFIBVLlvhDiC
         NUdyCmWl6Y9CceKxVUNFvWPVOIiVIqWA3sl1ruPKKk+Xlbdyt982+J+vA6M9VV+Vs5bH
         Yc/rYLJ9O3DnEBd1Ye3rQezskNPpcWjZ5KAd0bfaaoe5tXfcHhDMJc1alkmRML1O0UXh
         AcqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYShDp4IP37IJ40iEG4IUWHwX2Dg/2IstrFqkgAh1zEWzZ+VGrm
	+dmXnfHNnRzxSGTSRKjeX7w=
X-Google-Smtp-Source: APiQypJscfMorxbYZZY85Ufkp9nNRoh9fx6+qJ6Zt8HdfIHLGDgI0zBP566AvY42ct9MBdxX58rHeA==
X-Received: by 2002:a17:902:748c:: with SMTP id h12mr7819857pll.310.1588765525624;
        Wed, 06 May 2020 04:45:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d68d:: with SMTP id v13ls2445112ply.2.gmail; Wed, 06
 May 2020 04:45:25 -0700 (PDT)
X-Received: by 2002:a17:902:8b86:: with SMTP id ay6mr7319986plb.338.1588765525183;
        Wed, 06 May 2020 04:45:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588765525; cv=none;
        d=google.com; s=arc-20160816;
        b=tny8/UilSRnicxBn/S+sqBwaj5B9bBqARNFgIN4Xmffq9TRvGTD+zZDLSglVo5yLsN
         er6QWA9i2eJHkM82Cmd5cnUjXdBTOQTre5jiMc0xYJ9eufxCWWiYfTznfTRSMcpBFgSA
         GXJA8YljETbiUU4gBaSAtLwaKvTtJQG+hKQMYOu35UA67CLs3Z4o19KUjH5Y4jYEG9aN
         YSKPKN6r7y1XQBPyCxZApwQ9ArvZzr9n2zIraYySdNSs+J68PBR6P+8w8JoHGmXa3FXD
         JRofMx7qNu2jyaR1kR/KnL7cjMy2wOgB52quzMTkxB3phAu1kfMxs+jfqpfqwnDbFUBX
         mjjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=HC1C5JU9o2lOZOLuLLz92jALWgAK6MhyRnRurn0tSl0=;
        b=WdWGt87dIgFfW2lo+6Bqtm52lPOqxEnVzMQctEyyRaReSKahxc1rgKikP0WkyKAfUy
         159NxRqz81Pveexuy2Fk8GqGX/R+6PpQAw4qEa9RkvMTAI2xBifjiN5txG1RFVmVLanw
         2krFJVhykzzSO4E+icnVeU5XqaqbQEdKkwlrkKzrm0xT+85bjHE10K97NK+6HowuvsKM
         YyBG+9w3IUrjvHWIVzFzmapejvE/1arLAMlPCuYiA8reOPBHt5GH4ssi0yHbtPbAAhC5
         2ukdiIm98uLhPI6/i0izivoha5ehp4yuvObieHC+4xiQiwpJNE9hfeMuW+hfZwc9tZ9D
         lhjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Row5HprT;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id t141si165726pfc.5.2020.05.06.04.45.24
        for <kasan-dev@googlegroups.com>;
        Wed, 06 May 2020 04:45:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 55a93a0206564a3483cce296163898a3-20200506
X-UUID: 55a93a0206564a3483cce296163898a3-20200506
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1814852193; Wed, 06 May 2020 19:45:21 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 19:45:17 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 19:45:17 +0800
Message-ID: <1588765520.23664.22.camel@mtksdccf07>
Subject: Re: [PATCH 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 6 May 2020 19:45:20 +0800
In-Reply-To: <CACT4Y+beyYmoTn8GR_Y_Ca5XypxpRac-9ttu=zTtS-J-BYTfMA@mail.gmail.com>
References: <20200506052046.14451-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+beyYmoTn8GR_Y_Ca5XypxpRac-9ttu=zTtS-J-BYTfMA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 394EFE9EF3BC220BD62FBD36B53299AE0F17607FF8BE54C4C50C762437373FCB2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Row5HprT;       spf=pass
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

On Wed, 2020-05-06 at 11:46 +0200, Dmitry Vyukov wrote:
> On Wed, May 6, 2020 at 7:21 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > When call_rcu() is called, we store the call_rcu() call stack into
> > slub alloc meta-data, so that KASAN report prints call_rcu() information.
> >
> > We add new KASAN_RCU_STACK_RECORD configuration option. It will record
> > first and last call_rcu() call stack and KASAN report will print two
> > call_rcu() call stack.
> >
> > This option doesn't increase the cost of memory consumption. Because
> > we don't enlarge struct kasan_alloc_meta size.
> > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > - remove free track from kasan_alloc_meta, size is 8 bytes.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Josh Triplett <josh@joshtriplett.org>
> > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > Cc: Joel Fernandes <joel@joelfernandes.org>
> > ---
> >  include/linux/kasan.h |  7 +++++++
> >  kernel/rcu/tree.c     |  4 ++++
> >  lib/Kconfig.kasan     | 11 +++++++++++
> >  mm/kasan/common.c     | 23 +++++++++++++++++++++++
> >  mm/kasan/kasan.h      | 12 ++++++++++++
> >  mm/kasan/report.c     | 33 +++++++++++++++++++++++++++------
> >  6 files changed, 84 insertions(+), 6 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 31314ca7c635..5eeece6893cd 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -96,6 +96,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
> >  bool kasan_save_enable_multi_shot(void);
> >  void kasan_restore_multi_shot(bool enabled);
> >
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +void kasan_record_callrcu(void *ptr);
> 
> The issue also mentions workqueue and timer stacks.
> Have you considered supporting them as well? What was your motivation
> for doing only rcu?
> 
I will try to implement them when I have free time, maybe we can do it
step by step, finish the printing call_rcu() first.
I remember that I saw the following link, recording call_rcu seems like
be needed.

https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack
$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ


> Looking at the first report for "workqueue use-after-free":
> https://syzkaller.appspot.com/bug?extid=9cba1e478f91aad39876
> This is exactly the same situation as for call_rcu, just a workqueue
> is used to invoke a callback that frees the object.
> 
> If you don't want to do all at the same time, I would at least
> name/branch everything inside of KASAN more generally (I think in the
> issue I called it "aux" (auxiliary), or maybe something like
> "additional"). But then call this kasan_record_aux_stack() only from
> rcu for now. But then later we can separately decide and extend to
> other callers.
> It just feels wrong to have KASAN over-specialized for rcu only in this way.
> And I think if the UAF is really caused by call_rcu callback, then it
> sill will be recorded as last stack most of the time because rcu
> callbacks are invoked relatively fast and there should not be much
> else happening with the object since it's near end of life already.
> 
Yes, I agree with you. I will send v2 patchset as you saying.

> 
> 
> 
> > +#else
> > +static inline void kasan_record_callrcu(void *ptr) {}
> > +#endif
> > +
> >  #else /* CONFIG_KASAN */
> >
> >  static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
> > @@ -165,6 +171,7 @@ static inline void kasan_remove_zero_shadow(void *start,
> >
> >  static inline void kasan_unpoison_slab(const void *ptr) { }
> >  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > +static inline void kasan_record_callrcu(void *ptr) {}
> >
> >  #endif /* CONFIG_KASAN */
> >
> > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > index 06548e2ebb72..145c79becf7b 100644
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -57,6 +57,7 @@
> >  #include <linux/slab.h>
> >  #include <linux/sched/isolation.h>
> >  #include <linux/sched/clock.h>
> > +#include <linux/kasan.h>
> >  #include "../time/tick-internal.h"
> >
> >  #include "tree.h"
> > @@ -2694,6 +2695,9 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> >                 trace_rcu_callback(rcu_state.name, head,
> >                                    rcu_segcblist_n_cbs(&rdp->cblist));
> >
> > +       if (IS_ENABLED(CONFIG_KASAN_RCU_STACK_RECORD))
> 
> The if is not necessary, this function is no-op when not enabled.
> 
> > +               kasan_record_callrcu(head);
> > +
> >         /* Go handle any RCU core processing required. */
> >         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> >             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 81f5464ea9e1..022934049cc2 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -158,6 +158,17 @@ config KASAN_VMALLOC
> >           for KASAN to detect more sorts of errors (and to support vmapped
> >           stacks), but at the cost of higher memory usage.
> >
> > +config KASAN_RCU_STACK_RECORD
> > +       bool "Record and print call_rcu() call stack"
> > +       depends on KASAN_GENERIC
> > +       help
> > +         By default, the KASAN report doesn't print call_rcu() call stack.
> > +         It is very difficult to analyze memory issues(e.g., use-after-free).
> > +
> > +         Enabling this option will print first and last call_rcu() call stack.
> > +         It doesn't enlarge slub alloc meta-data size, so it doesn't increase
> > +         the cost of memory consumption.
> > +
> >  config TEST_KASAN
> >         tristate "Module for testing KASAN for bug detection"
> >         depends on m && KASAN
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 2906358e42f0..32d422bdf127 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -299,6 +299,29 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> >         return (void *)object + cache->kasan_info.free_meta_offset;
> >  }
> >
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +void kasan_record_callrcu(void *addr)
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
> > +       if (!alloc_info->rcu_free_stack[0])
> > +               /* record first call_rcu() call stack */
> > +               alloc_info->rcu_free_stack[0] = save_stack(GFP_NOWAIT);
> > +       else
> > +               /* record last call_rcu() call stack */
> > +               alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
> > +}
> > +#endif
> >
> >  static void kasan_set_free_info(struct kmem_cache *cache,
> >                 void *object, u8 tag)
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8f37199d885..adc105b9cd07 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -96,15 +96,27 @@ struct kasan_track {
> >         depot_stack_handle_t stack;
> >  };
> >
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +#define BYTES_PER_WORD 4
> > +#define KASAN_NR_RCU_FREE_STACKS 2
> > +#else /* CONFIG_KASAN_RCU_STACK_RECORD */
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  #define KASAN_NR_FREE_STACKS 5
> >  #else
> >  #define KASAN_NR_FREE_STACKS 1
> >  #endif
> > +#endif /* CONFIG_KASAN_RCU_STACK_RECORD */
> >
> >  struct kasan_alloc_meta {
> >         struct kasan_track alloc_track;
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +       /* call_rcu() call stack is stored into kasan_alloc_meta.
> > +        * free stack is stored into freed object.
> > +        */
> > +       depot_stack_handle_t rcu_free_stack[KASAN_NR_RCU_FREE_STACKS];
> > +#else
> >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > +#endif
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >         u8 free_track_idx;
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..7aaccc70b65b 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> >         kasan_enable_current();
> >  }
> >
> > -static void print_track(struct kasan_track *track, const char *prefix)
> > +static void print_track(struct kasan_track *track, const char *prefix,
> > +                                               bool is_callrcu)
> >  {
> > -       pr_err("%s by task %u:\n", prefix, track->pid);
> > +       if (is_callrcu)
> > +               pr_err("%s:\n", prefix);
> > +       else
> > +               pr_err("%s by task %u:\n", prefix, track->pid);
> >         if (track->stack) {
> >                 unsigned long *entries;
> >                 unsigned int nr_entries;
> > @@ -159,8 +163,22 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
> >                 (void *)(object_addr + cache->object_size));
> >  }
> >
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
> > +{
> > +       struct kasan_track free_track;
> > +
> > +       free_track.stack  = alloc_info->rcu_free_stack[0];
> > +       print_track(&free_track, "First call_rcu() call stack", true);
> > +       pr_err("\n");
> > +       free_track.stack  = alloc_info->rcu_free_stack[1];
> > +       print_track(&free_track, "Last call_rcu() call stack", true);
> > +       pr_err("\n");
> > +}
> > +#endif
> > +
> >  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> > -               void *object, u8 tag)
> > +               void *object, u8 tag, const void *addr)
> >  {
> >         struct kasan_alloc_meta *alloc_meta;
> >         int i = 0;
> > @@ -187,11 +205,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
> >         if (cache->flags & SLAB_KASAN) {
> >                 struct kasan_track *free_track;
> >
> > -               print_track(&alloc_info->alloc_track, "Allocated");
> > +               print_track(&alloc_info->alloc_track, "Allocated", false);
> >                 pr_err("\n");
> > -               free_track = kasan_get_free_track(cache, object, tag);
> > -               print_track(free_track, "Freed");
> > +               free_track = kasan_get_free_track(cache, object, tag, addr);
> > +               print_track(free_track, "Freed", false);
> >                 pr_err("\n");
> > +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> > +               kasan_print_rcu_free_stack(alloc_info);
> > +#endif
> >         }
> >
> >         describe_object_addr(cache, object, addr);
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052046.14451-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1588765520.23664.22.camel%40mtksdccf07.
