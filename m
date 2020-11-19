Return-Path: <kasan-dev+bncBAABBG6C3H6QKGQECXGCOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 80FA32B9223
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 13:12:12 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id s1sf2517135vks.6
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 04:12:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605787931; cv=pass;
        d=google.com; s=arc-20160816;
        b=huLsnecbd2i9FO35ZfAaBjd+rNhrlcwFp/UcwdSOxTM5iVjh+MSkhlRt7olygikxBI
         WN8MheGQ2iPexiy838vIOxoOlj+GHcEHv3siHfa6SHGdonkyqifYknccrLTl5Q28JcMl
         E3mUcUCWHgTIGaH0FD18+mbvfpQZ0wyT3Y5xIZkR3zqOV/LfUiBWgVfiH4ncG4U+1FJF
         AeDLwJYccTQV+qIjPJjsRmbACa5ljYdjvgHdwykqoNMmiu7RyjLtYawWUbj2xv2shi31
         KEy1lSfkDBuckH9vX+9yLpChbrLHUpr5pBJkA+0BRi5oIAsBD+xnQhn0lKsGsKdHJ+kP
         4MBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=RGeLhDgQNj8PRfHInMWYj6vrw18WGWmVyMNL6IvviIE=;
        b=RC+KmctBxQ8eTC42yC575vKjUP2XBMeE/8HRXsxsl4aibLtMQpGyP+uUuutY48jEu5
         QeW94vxxgEOhuU4TNDQxrCOYjoGTr1hEVUqMbSol1HSGai1KQllPgn2sBLZ6oFcQhpqN
         wgoa7pzJS3dx89wMYjHPlNhD1W7A98CZ0CMjNFrWouFSI7jfM8xOVtlVVsxQwDc/FAoh
         ueIvfCqEXY0yNrqiB88tNKa34BkQ3ZSxg9KdnycUvlvVHeQGEhsxhSQ9qDuhY09p2T3k
         BuxzoZKhfjncMWQG7JXNjMmm/f1ONjF6uz/Vhezag5yeK/7o+L8h3k6Xm6d+z39YUgmb
         nW7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FbwBuPPN;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGeLhDgQNj8PRfHInMWYj6vrw18WGWmVyMNL6IvviIE=;
        b=OmmCOCJbZd5exhg29ipZMyicVpC1pKSNxo1MCeNi/vaxM24Ut9ojzoCWsV4jAkxPlR
         yQfHX2wEjMEfyBB9y7VeW73JwF6tnIbIT98yCNgIYkT7xLyaQRcugwtZfIWICCBp9Wm2
         xHOEt6+SfFwNrLuMuj8ZQEJp2xwrAe6tkbQTMWtMwLkFPDECuIGtQUXn+4GpRGdkwfRl
         FICiIr5NVvjtCHe2FidfQg+lNXGcPzyOnMwKj2O9qijP25pxkG/h5g7lhS82rT5+xLPp
         v7a1a8uIoedVWY4W0la9w4+gbuq6P4itpFNJHp4j7HKJwWLiYuKrbMcU+3ar152bfH1t
         5fzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGeLhDgQNj8PRfHInMWYj6vrw18WGWmVyMNL6IvviIE=;
        b=Fkocvux6HLOSlHzwy+bhKEDzKPq2cGQnA+ocrzaBdOstB5G6O2tQ9FWIs3E18jCjX8
         QDi+kbadTLtE46syz6yDAvefeCWpB+LBLDgNSaZ+tnldUH/+bWB5YRwT8vj/X14+y27R
         tNrw9MjT5CGDCLSbZ5thrFxUzJo8BRSFeBZuShi/pDA5rzJTu4nAXZzJJ0+SLHSOQaPn
         A9FemkS8My/gCKHTvJRskqVq/xik6FCLVsBIakkwhozyP9SpQNau0nXvm9To3yQVAv81
         y22X3SSudlc1Ilq71tHJcUsiI47ncXwoAIxOczPv1fBosfoYCCfcvLDsQAouZuQ3K8k/
         +jAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BE2/1oplbpdVvZDASgVp/R/dnXUSavHaWt9bpBVyFMNMFtmCb
	xGgoHPvqvmhvz/oj8KR98Bc=
X-Google-Smtp-Source: ABdhPJxIHzuEvJB6gujQMvl+rRdt3AZWwpi5xv+/fSuAtZnZBn9VTiz5QoZNp+qcLkxcFJloQiXIdw==
X-Received: by 2002:ab0:4972:: with SMTP id a47mr6673459uad.53.1605787931324;
        Thu, 19 Nov 2020 04:12:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:22fb:: with SMTP id b27ls422492vsh.1.gmail; Thu, 19
 Nov 2020 04:12:10 -0800 (PST)
X-Received: by 2002:a67:f80b:: with SMTP id l11mr6118882vso.26.1605787930331;
        Thu, 19 Nov 2020 04:12:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605787930; cv=none;
        d=google.com; s=arc-20160816;
        b=fIyBOFuVn2gZs53EFhN6H0vLltQrTbarap6FSDgvZYBDa+hrz6wKAVOVN+INWbsJCT
         e3h0wq4cFja201mBTPlUUcal2TWoNYYjReA/5gBnT225PZC4ko0lgnSwIBCxgTInA8go
         tcv9GVTg/NE4YpCg6acghR3OC1lK59j5L4osY+1K0OE9G3xsPzh3ErQwfpjgYWyOkzZC
         t/eSQ4a7ykbgkqaOpnas4Bfvz2Ee4tqvH9iJNP1z3N8fVTzuK9fp2U9XOE0nfmHr6ZUm
         IJbWDvFj7RDMcoEb+hxu3q4ERHYwo3+TS1PjZsMEazJY6rJSAllg2auXpXsQB6EtRWXY
         Uuxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=BxaKCvbGMroRDKzMiJNq1cYSi2kIAUSuDsxHbXnM8mQ=;
        b=T8aGXoaV2MhlNWcwl0Le5kCG1JBD9HYjjCoymsWeWycPTo8dMkS/2TbmPY67KYI+/K
         c0D/EHvZwmR14Qqqur9rysvhTiBTGLk/nlGVuqnlsZKOib+e5NrLbyvPXCMwCKwPXtlD
         oM8hIs6X91PXYFr3rxvUl+pMq4MFfivCnLtWTrZ/Q0sl03c+B79icXtkYr5mEr8lALaW
         K4n0Mae6nUrqrXRAYRsyM6vwboOVuoMGZZItX55Q8GoI6H69Z1DGea55zfh0Fc4gwFby
         GBy7oGvihjWM4RD6UsLgX1WsPXHvhhmQCGshMo5KqzAlJhbqWoxh3nburQkFvWa5XGb3
         I+fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FbwBuPPN;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id b25si656354vkk.5.2020.11.19.04.12.09
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Nov 2020 04:12:09 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 791bf6180cfb4282bc04daf6fe3c4266-20201119
X-UUID: 791bf6180cfb4282bc04daf6fe3c4266-20201119
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1422574732; Thu, 19 Nov 2020 20:06:55 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 19 Nov 2020 20:06:53 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 19 Nov 2020 20:06:53 +0800
Message-ID: <1605787613.29084.32.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/1] kasan: fix object remain in offline per-cpu
 quarantine
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <nicholas.tang@mediatek.com>, Miles
 Chen <miles.chen@mediatek.com>, <guangye.yang@mediatek.com>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Thu, 19 Nov 2020 20:06:53 +0800
In-Reply-To: <CACT4Y+ZpK5YKLrN_jvaD60YFKQ-kVHc=91NTBzhX5PZRTHVd7g@mail.gmail.com>
References: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1605508168-7418-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <CACT4Y+Zy_JQ3y7_P2NXffiijTuxcnh7VPcAGL66Ks2LaLTj-eg@mail.gmail.com>
	 <1605595583.29084.24.camel@mtksdccf07>
	 <CACT4Y+ZpK5YKLrN_jvaD60YFKQ-kVHc=91NTBzhX5PZRTHVd7g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: D7C440176C6B4D09255888CCD89F8353F4DFF4A81CDD6B698FE89F10231667002000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=FbwBuPPN;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

On Tue, 2020-11-17 at 08:13 +0100, Dmitry Vyukov wrote:
> On Tue, Nov 17, 2020 at 7:46 AM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >
> > On Mon, 2020-11-16 at 10:26 +0100, Dmitry Vyukov wrote:
> > > On Mon, Nov 16, 2020 at 7:30 AM Kuan-Ying Lee
> > > <Kuan-Ying.Lee@mediatek.com> wrote:
> > > >
> > > > We hit this issue in our internal test.
> > > > When enabling generic kasan, a kfree()'d object is put into per-cpu
> > > > quarantine first. If the cpu goes offline, object still remains in
> > > > the per-cpu quarantine. If we call kmem_cache_destroy() now, slub
> > > > will report "Objects remaining" error.
> > > >
> > > > [   74.982625] =============================================================================
> > > > [   74.983380] BUG test_module_slab (Not tainted): Objects remaining in test_module_slab on __kmem_cache_shutdown()
> > > > [   74.984145] -----------------------------------------------------------------------------
> > > > [   74.984145]
> > > > [   74.984883] Disabling lock debugging due to kernel taint
> > > > [   74.985561] INFO: Slab 0x(____ptrval____) objects=34 used=1 fp=0x(____ptrval____) flags=0x2ffff00000010200
> > > > [   74.986638] CPU: 3 PID: 176 Comm: cat Tainted: G    B             5.10.0-rc1-00007-g4525c8781ec0-dirty #10
> > > > [   74.987262] Hardware name: linux,dummy-virt (DT)
> > > > [   74.987606] Call trace:
> > > > [   74.987924]  dump_backtrace+0x0/0x2b0
> > > > [   74.988296]  show_stack+0x18/0x68
> > > > [   74.988698]  dump_stack+0xfc/0x168
> > > > [   74.989030]  slab_err+0xac/0xd4
> > > > [   74.989346]  __kmem_cache_shutdown+0x1e4/0x3c8
> > > > [   74.989779]  kmem_cache_destroy+0x68/0x130
> > > > [   74.990176]  test_version_show+0x84/0xf0
> > > > [   74.990679]  module_attr_show+0x40/0x60
> > > > [   74.991218]  sysfs_kf_seq_show+0x128/0x1c0
> > > > [   74.991656]  kernfs_seq_show+0xa0/0xb8
> > > > [   74.992059]  seq_read+0x1f0/0x7e8
> > > > [   74.992415]  kernfs_fop_read+0x70/0x338
> > > > [   74.993051]  vfs_read+0xe4/0x250
> > > > [   74.993498]  ksys_read+0xc8/0x180
> > > > [   74.993825]  __arm64_sys_read+0x44/0x58
> > > > [   74.994203]  el0_svc_common.constprop.0+0xac/0x228
> > > > [   74.994708]  do_el0_svc+0x38/0xa0
> > > > [   74.995088]  el0_sync_handler+0x170/0x178
> > > > [   74.995497]  el0_sync+0x174/0x180
> > > > [   74.996050] INFO: Object 0x(____ptrval____) @offset=15848
> > > > [   74.996752] INFO: Allocated in test_version_show+0x98/0xf0 age=8188 cpu=6 pid=172
> > > > [   75.000802]  stack_trace_save+0x9c/0xd0
> > > > [   75.002420]  set_track+0x64/0xf0
> > > > [   75.002770]  alloc_debug_processing+0x104/0x1a0
> > > > [   75.003171]  ___slab_alloc+0x628/0x648
> > > > [   75.004213]  __slab_alloc.isra.0+0x2c/0x58
> > > > [   75.004757]  kmem_cache_alloc+0x560/0x588
> > > > [   75.005376]  test_version_show+0x98/0xf0
> > > > [   75.005756]  module_attr_show+0x40/0x60
> > > > [   75.007035]  sysfs_kf_seq_show+0x128/0x1c0
> > > > [   75.007433]  kernfs_seq_show+0xa0/0xb8
> > > > [   75.007800]  seq_read+0x1f0/0x7e8
> > > > [   75.008128]  kernfs_fop_read+0x70/0x338
> > > > [   75.008507]  vfs_read+0xe4/0x250
> > > > [   75.008990]  ksys_read+0xc8/0x180
> > > > [   75.009462]  __arm64_sys_read+0x44/0x58
> > > > [   75.010085]  el0_svc_common.constprop.0+0xac/0x228
> > > > [   75.011006] kmem_cache_destroy test_module_slab: Slab cache still has objects
> > > >
> > > > Register a cpu hotplug function to remove all objects in the offline
> > > > per-cpu quarantine when cpu is going offline. Set a per-cpu variable
> > > > to indicate this cpu is offline.
> > > >
> > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Reported-by: Guangye Yang <guangye.yang@mediatek.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > > > ---
> > > >  mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
> > > >  1 file changed, 35 insertions(+)
> > > >
> > > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > > index 4c5375810449..16e618ea805e 100644
> > > > --- a/mm/kasan/quarantine.c
> > > > +++ b/mm/kasan/quarantine.c
> > > > @@ -29,6 +29,7 @@
> > > >  #include <linux/srcu.h>
> > > >  #include <linux/string.h>
> > > >  #include <linux/types.h>
> > > > +#include <linux/cpuhotplug.h>
> > > >
> > > >  #include "../slab.h"
> > > >  #include "kasan.h"
> > > > @@ -43,6 +44,7 @@ struct qlist_head {
> > > >         struct qlist_node *head;
> > > >         struct qlist_node *tail;
> > > >         size_t bytes;
> > > > +       bool offline;
> > > >  };
> > > >
> > > >  #define QLIST_INIT { NULL, NULL, 0 }
> > > > @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > > >         local_irq_save(flags);
> > > >
> > > >         q = this_cpu_ptr(&cpu_quarantine);
> > > > +       if (q->offline) {
> > > > +               qlink_free(&info->quarantine_link, cache);
> > > > +               local_irq_restore(flags);
> > > > +               return;
> > > > +       }
> >
> > I think we need to make sure objects will not be put in per-cpu
> > quarantine which is offline.
> >
> > > >         qlist_put(q, &info->quarantine_link, cache->size);
> > > >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> > > >                 qlist_move_all(q, &temp);
> > > > @@ -328,3 +335,31 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> > > >
> > > >         synchronize_srcu(&remove_cache_srcu);
> > > >  }
> > > > +
> > > > +static int kasan_cpu_online(unsigned int cpu)
> > > > +{
> > > > +       this_cpu_ptr(&cpu_quarantine)->offline = false;
> > > > +       return 0;
> > > > +}
> > > > +
> > > > +static int kasan_cpu_offline(unsigned int cpu)
> > > > +{
> > > > +       struct qlist_head *q;
> > > > +
> > > > +       q = this_cpu_ptr(&cpu_quarantine);
> > > > +       q->offline = true;
> > > > +       qlist_free_all(q, NULL);
> > >
> > > Looks much nicer now!
> > >
> > > What is the story with interrupts in these callbacks?
> > > In the previous patch you mentioned that this CPU can still receive
> > > interrupts for a brief period of time. If these interrupts also free
> > > something, can't we corrupt the per-cpu quarantine? In quarantine_put
> > > we protect it by disabling interrupts I think.
> > >
> >
> > Here is a situation.
> > After we freed all objects from the per-cpu quarantine which is going
> > offline, the interrupts happened. These interrupts free something and
> > put objects into this per-cpu quarantine. If we call
> > kmem_cache_destroy() now, slub still detect objects remain in
> > the per-cpu quarantine and report "Object remaining" error.
> >
> > Thus, we need to check q->offline in quarantine_put and make sure
> > the offline per-cpu quarantine is not corrupted.
> 
> If an interrupt can happen later, can't it happen right during our
> call to qlist_free_all and corrupt the per-cpu cache?
> Perhaps we need something like:
> 
> // ... explain the subtleness ...
> WRITE_ONCE(q->offline, true);
> barrier();
> qlist_free_all(q, NULL);
> 
> ?

Yes, we need to add barrier to ensure the ordering.
I did not think about that before.
Thanks for the reminder.
I will fix in v3.

> 
> > > > +       return 0;
> > > > +}
> > > > +
> > > > +static int __init kasan_cpu_offline_quarantine_init(void)
> > > > +{
> > > > +       int ret = 0;
> > > > +
> > > > +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> > > > +                               kasan_cpu_online, kasan_cpu_offline);
> > > > +       if (ret < 0)
> > > > +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> > > > +       return ret;
> > > > +}
> > > > +late_initcall(kasan_cpu_offline_quarantine_init);
> > > > --
> > > > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605787613.29084.32.camel%40mtksdccf07.
