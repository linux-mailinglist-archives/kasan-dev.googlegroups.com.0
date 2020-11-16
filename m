Return-Path: <kasan-dev+bncBAABBAVTY76QKGQEIUNGTMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A68362B3B33
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 02:44:35 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id t77sf5274542vkt.18
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Nov 2020 17:44:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605491074; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJcinIrngtePnP5TXZ6jQdvPGpkWSxwV6ysQu4YvrMa9G/PRox0RWLmwOUAz8StKi2
         GmPxm3+J+0s7Cqw1lcJgkS0MZCLMTrcCFcQhRXuwC2hfbVCS2Uot8ij1eMgSr3m1qNlc
         y0fC8Ba7eS5kKm6MCqg8V7y7ITCkQ9wamUVHdHLGKH2gwMaNgXnqEAWyp7nzAkTJOwaq
         m+95mjYqwSsb9q309gyFeCNjwVw0rnw8WeFVpb/tIPRwv29q+DqGtP6Azc45XJwxoLte
         FLqgGzf1kXn/BDSOemNG/UnMX82yGUn+cCn7A6OgDPEuRO6uWQd4+RAgfehudvC8yohe
         oGiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=XN0JP8+wvklSFF7baCrsThWjlNJSC85KmvfEy9/wd2c=;
        b=zd2CfUX2cQN2PwJ22Oh8RboVFKddLKL8Fl+Ggkng/OsVKef6+VYI2PRi+VC3fu5S0p
         GvGexkalYM2Q9mGDhwJNEnIBH9//Pn5CWFVoybDI7TDIoTfdSxKcyb+Eszk/+dVAIH/Z
         PurN3u8A8Gl3eVPULh4PNQUWt0nH1HnL+pVZXU8kniLwitCIJm/TWiE3rwmXrXoSu0YG
         M+Kj2fNnCngbUS3jGUlsPHAhWTvPuNZrj4la4CIM1Q9P7Uod3qsN4AuKd9/lFWP2yurj
         /06MytChdp2SHuFH47g8ndeQdbi9ViLAPXIm79KQd07tUiAEutzvLgbd5J0f9OxT5bxV
         TO1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=QQ60WSJl;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XN0JP8+wvklSFF7baCrsThWjlNJSC85KmvfEy9/wd2c=;
        b=Ax4c/UtozVUmHP7bIHwmzca16IWZbs3Jh5FoNrtF2umnnRGLTGxlMv9sTDPY+HOc18
         3gnRXez/UjTvrsg/0P5T+ZoEW8/Qsph0IfUKpOfnPmFVUikbRH4+fvxBNmPVCqt7pi0q
         GiSwuaOwXIaHLpG9jT7i9NUsMoWMdxgvYmFbjbAkSC0E7BRD2/75MEc8HK8k4Ct0c/SN
         gP7WhvfCa+I2IuzAnemV/T3/pGTTZ2HfOAsFOYyCKf9FBpxjOV3Snv36iNFoaubJFXKa
         M25QW6eognOPH9nwJDstTmqsXOTkNjfnZ+H2a33bZfRcH8WiKSV72Ws8s09nA6cjJE4l
         HEyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XN0JP8+wvklSFF7baCrsThWjlNJSC85KmvfEy9/wd2c=;
        b=SsXo/0d2hxGPeX68Wtkr4lmG2nW1zkSVDSeXQgO+xdnfn7X5kikPT4+1rSL83qu8QL
         vDXwYsn0dR/bk198j8UXiZYgwhybBnq3GzYLdki7Xmi9dAw5s2ZhE0XjDhYKVaRGWVPK
         h4vPgRklL6/BE40NPb3Lx2ytQgIAIeL5Kbg8eHzwF+zMZ8XgkArgO6wfjzhPDdbhaTiC
         qflYT2utUCCJeYXkWF22vxrh0uVBxzQMgcGL3fePBelXjJLhuT5jvW5lTNfmI4AuPbjx
         7Fnj0qovzRDP233l541YjuZ4XgAeWkhPnUxcSDQ65NWboaoqjxWGfWFy4A8z0j4+jTzi
         XcqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+PJlR0ipme8MYho4BifSOCibqrwqy/o+9oA1JunMnf2fOaxYi
	77c5sF0kfVQpKI73N5el86w=
X-Google-Smtp-Source: ABdhPJwsT06HFoUmSX8kxE3GuKuq6ApjqMRHjjpChgslHtI38HaxzrtO/6yyYDvo2apYVK75zKYA2Q==
X-Received: by 2002:a05:6102:22fb:: with SMTP id b27mr7058781vsh.49.1605491074741;
        Sun, 15 Nov 2020 17:44:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f583:: with SMTP id i3ls1491815vso.4.gmail; Sun, 15 Nov
 2020 17:44:34 -0800 (PST)
X-Received: by 2002:a67:2e43:: with SMTP id u64mr6947024vsu.52.1605491074236;
        Sun, 15 Nov 2020 17:44:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605491074; cv=none;
        d=google.com; s=arc-20160816;
        b=i9lhDoUrT3YOLCjNsHK/k9x8s+u3wZreNN9Ar12mpUIc6+S3STBsYGEBYhkOqQCmH2
         CPTGp4HH5t1mo4bu0lw7VyNm7oX50z8ISMg2oYHSaNxMGINXDDjN7hfeeNWi0zOEgELB
         SY5Vu12YycTeX0sieASfs7uEQkuePMPe1mlUjjFmoKQ15blR2YpPyy1T51Kx8hoxsXSs
         4onc2oDk/2dGXxf7s/TWmL7SdrPe3dXE/6Ih50My2OYg0SrH3FJ6FpqSrgduBMqI/iZc
         nDBGQdMwhbsI4/CdwJsLM+bV/exen+mHGyTaV+IO+KdqcXqn3uZT4Ck2W001b9eiPNZq
         Sq2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=5zef3sILoFC/Qxr+vbXApTKUmQnZIlDEA1uxAbrnje4=;
        b=zzXfkFHNTZUsWlBAg8i/BaT17yGWO4rGeLBFiItrTv44WXNzGsd6A7jVAZWjGFxKZY
         dk76ToNYRt9BKfaYXCYtBow7y98eJseud/3yPlV3O4jGMol8IzP8nqQrB2DrdwSeu0lh
         SassIhS3DvSS3CYxA5C2YZto4QnMVzYzzwRQ+/4Nrt5os2UkKQYLgs8mpGG5kJDdf4Xe
         xN1gbA4jDxh3ik8C44nvBHeA4uj4hhPiq2Yire/V4w48sC4RSLYJ73mb/ISrmv0yL5/U
         XJTxlEQZkVNXl0AGurihqbJwn7pzsTuTppxzJaLrhBiLru1yD0iI08n/aSgRw8iQvGc5
         yc/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=QQ60WSJl;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id n1si768227vsr.2.2020.11.15.17.44.32
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Nov 2020 17:44:33 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: b18a56d0b1fc4dffa3e049261059c991-20201116
X-UUID: b18a56d0b1fc4dffa3e049261059c991-20201116
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1793712508; Mon, 16 Nov 2020 09:44:27 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 16 Nov 2020 09:44:23 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 16 Nov 2020 09:44:22 +0800
Message-ID: <1605491062.29084.2.camel@mtksdccf07>
Subject: Re: [PATCH 1/1] kasan: fix object remain in offline per-cpu
 quarantine
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, Miles Chen <miles.chen@mediatek.com>,
	<nicholas.tang@mediatek.com>
Date: Mon, 16 Nov 2020 09:44:22 +0800
In-Reply-To: <CACT4Y+b7F_A1E_FMKQMK4cg2SwpniLjq9Nr988J6BVSF5rkDGg@mail.gmail.com>
References: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1605162252-23886-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <CACT4Y+bpDTqQRRdV0_O07H=Kczj3nXUY9ngQgX5K=BtT=Y60RQ@mail.gmail.com>
	 <1605234714.30076.18.camel@mtksdccf07>
	 <CACT4Y+b7F_A1E_FMKQMK4cg2SwpniLjq9Nr988J6BVSF5rkDGg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: D66A5C08AA565297E4DD3C222B41601357186A840CDB0C0DE06C3F51EF81814B2000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=QQ60WSJl;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as
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

On Fri, 2020-11-13 at 08:03 +0100, Dmitry Vyukov wrote:
> On Fri, Nov 13, 2020 at 3:32 AM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >
> > On Thu, 2020-11-12 at 09:39 +0100, Dmitry Vyukov wrote:
> > > On Thu, Nov 12, 2020 at 7:25 AM Kuan-Ying Lee
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
> > > > ---
> > > >  mm/kasan/quarantine.c | 59 +++++++++++++++++++++++++++++++++++++++++--
> > > >  1 file changed, 57 insertions(+), 2 deletions(-)
> > > >
> > > > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > > > index 4c5375810449..67fb91ae2bd0 100644
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
> > > > @@ -97,6 +98,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
> > > >   * guarded by quarantine_lock.
> > > >   */
> > >
> > > Hi Kuan-Ying,
> > >
> > > Thanks for fixing this.
> > >
> > > >  static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
> > > > +static DEFINE_PER_CPU(int, cpu_quarantine_offline);
> > >
> > > I think cpu_quarantine_offline is better be part of cpu_quarantine
> > > because it logically is and we already obtain a pointer to
> > > cpu_quarantine in quarantine_put, so it will also make the code a bit
> > > shorter.
> > >
> >
> > Ok. Got it.
> >
> > >
> > > >  /* Round-robin FIFO array of batches. */
> > > >  static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
> > > > @@ -176,6 +178,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > > >         unsigned long flags;
> > > >         struct qlist_head *q;
> > > >         struct qlist_head temp = QLIST_INIT;
> > > > +       int *offline;
> > > > +       struct qlist_head q_offline = QLIST_INIT;
> > > >
> > > >         /*
> > > >          * Note: irq must be disabled until after we move the batch to the
> > > > @@ -187,8 +191,16 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > > >          */
> > > >         local_irq_save(flags);
> > > >
> > > > -       q = this_cpu_ptr(&cpu_quarantine);
> > > > -       qlist_put(q, &info->quarantine_link, cache->size);
> > > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > > +       if (*offline == 0) {
> > > > +               q = this_cpu_ptr(&cpu_quarantine);
> > > > +               qlist_put(q, &info->quarantine_link, cache->size);
> > > > +       } else {
> > > > +               qlist_put(&q_offline, &info->quarantine_link, cache->size);
> > > > +               qlist_free_all(&q_offline, cache);
> > >
> > > This looks like a convoluted way to call qlink_free. I think it will
> > > be better to call qlink_free directly here.
> > >
> > > And why do we need this? Because CPU shutdown code can still free some
> > > objects afterwards?
> > >
> >
> > Yes, it is because IRQ can happen during CPU shutdown and free some
> > objects into offline CPU quarantine.
> >
> > > > +               local_irq_restore(flags);
> > > > +               return;
> > >
> > > You add both if/else and early return, this looks like unnecessary
> > > code complication. It would be simpler with:
> > >
> > > if (*offline) {
> > >     qlink_free(...);
> > >     return;
> > > }
> > > ... all current per-cpu local ...
> > >
> > >
> >
> > Thank you for reminder. v2 Will do it.
> >
> > > > +       }
> > > >         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
> > > >                 qlist_move_all(q, &temp);
> > > >
> > > > @@ -328,3 +340,46 @@ void quarantine_remove_cache(struct kmem_cache *cache)
> > > >
> > > >         synchronize_srcu(&remove_cache_srcu);
> > > >  }
> > > > +
> > > > +static int kasan_cpu_online(unsigned int cpu)
> > > > +{
> > > > +       int *offline;
> > > > +       unsigned long flags;
> > > > +
> > > > +       local_irq_save(flags);
> > >
> > > I assume this local_irq_save/restore is to prevent some warnings from
> > > this_cpu_ptr.
> > > But CPU online/offline callbacks should run without preemption already
> > > (preempting/rescheduling on other CPUs does not make sense for them,
> > > right?), so I would assume that is already at least preemption
> > > disabled or something. Is there this_cpu_ptr variant that won't
> > > produce warnings on its own in cpu online/offline callbacks?
> > > This whole function could be a 1-liner:
> > > this_cpu_ptr(&cpu_quarantine)->offline = true;
> > > So I am trying to understand if we could avoid all this unnecessary danse.
> > >
> >
> > Yes, it's unnecessary. v2 will fix it.
> >
> > >
> > > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > > +       *offline = 0;
> > > > +       local_irq_restore(flags);
> > > > +       return 0;
> > > > +}
> > > > +
> > > > +static int kasan_cpu_offline(unsigned int cpu)
> > > > +{
> > > > +       struct kmem_cache *s;
> > > > +       int *offline;
> > > > +       unsigned long flags;
> > > > +
> > > > +       local_irq_save(flags);
> > > > +       offline = this_cpu_ptr(&cpu_quarantine_offline);
> > > > +       *offline = 1;
> > > > +       local_irq_restore(flags);
> > > > +
> > > > +       mutex_lock(&slab_mutex);
> > > > +       list_for_each_entry(s, &slab_caches, list) {
> > > > +               per_cpu_remove_cache(s);
> > > > +       }
> > > > +       mutex_unlock(&slab_mutex);
> > >
> > > We just want to drop the whole per-cpu cache at once, right? I would
> > > assume there should be a simpler way to do this all at once, rather
> > > than doing this per-slab.
> > >
> >
> > Yes.
> > Is removing objects in per-cpu quarantine directly better?
> 
> Yes, single qlist_free_all call looks much better than iteration over
> all slabs and removing in parts under the mutex.
> 

Hi Dmitry,

Got it.
Thanks for your review and reminder.
I will fix them in v2.

Kuan-Ying


> > struct qlist_head *q;
> > q = this_cpu_ptr(&cpu_quaratine);
> > q->offline = true;
> > qlist_free_all(q, NULL);
> >
> > > > +       return 0;
> > > > +}
> > > > +
> > > > +static int __init kasan_cpu_offline_quarantine_init(void)
> > > > +{
> > > > +       int ret = 0;
> > > > +
> > > > +       ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
> > > > +                               kasan_cpu_online, kasan_cpu_offline);
> > > > +       if (ret)
> > > > +               pr_err("kasan offline cpu quarantine register failed [%d]\n", ret);
> > > > +       return ret;
> > > > +}
> > > > +late_initcall(kasan_cpu_offline_quarantine_init);
> > > > --
> > > > 2.18.0
> > > >
> > > > --
> > > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605162252-23886-2-git-send-email-Kuan-Ying.Lee%40mediatek.com.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605234714.30076.18.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605491062.29084.2.camel%40mtksdccf07.
