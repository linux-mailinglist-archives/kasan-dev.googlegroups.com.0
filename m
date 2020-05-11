Return-Path: <kasan-dev+bncBDGPTM5BQUDRBQNG4X2QKGQEN6JGKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1901CDB32
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 15:29:39 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id x8sf7767081pgh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 06:29:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589203778; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVS75BD4ZTvUBPItIv8HSRyvI0UaU0T6cmYWjDaVP1JeL60rj0QSPQPTxWNz1J16dK
         PPq8qdCNSn4Fah6Guwwi4rC7J5Na6xBJKLZvZjjGpPZbDbAy+3bHZOEY72iHUlG+2w8Q
         0YV3dnUZ2IEwOEen6RzKcPMoO/0uRDXMAMLvfbJGI8+WWYLXHnNft2BA0PCYRKca/ak5
         X3JfgyxGchnYZY+Tz+DM/ZcisDqVX7sIUpdNjv9Q+C2eOaLyFTKYqhUhbic8IXD2oCiR
         r0dateCQ4A6xEwGSeO57+7WtneOaPIBuC5HIm6zWczlJiBSv90g2Z/B16+SKHJ/5Mqqb
         VrQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=4kvEcNvpmxceD0f1ZSDk5+G1yb2QBDPJ2MdK+uvqRCY=;
        b=CRxx1KRTaVhnLvWCvdS8abodBTaMrbK0x/QlgmAL31LLIqgn2khhUj5jPVS/TkWsMc
         4XS2HrAvT50JO2kQw1hmTdHw+dTg9ICm0pBD77CPEsuzp2ARcbmnzNwAyBnXWk1lVZbc
         xul20uLZJHtoi87tFXzU0CV2K8x/FS++RwP8U+N8qSgtq/+PdVOuZ+DkJmQgPXWdcL6y
         9tceqWG/h8d2fSswWMVGBeamc9Z/eMFPVrhdgKIBLY+q/Av8HWdHuZBWWpktzjqX6zOK
         mF8WBZkHhx4G8eiSk003ngng8lGuSbF4TfSFYAENitDs8K7LOoNxAOyw+93STQ8511jq
         kXwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Gzet0xTw;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4kvEcNvpmxceD0f1ZSDk5+G1yb2QBDPJ2MdK+uvqRCY=;
        b=fPz9SMc+yo5QkiizS7Xy3Nt8hnOUUCDgi8j+/G//FO3QZMactvGlHIf6DmNqTmfRkX
         DP4O9UIDJD8c+uyWYzodFAMPDOXUDVBi+V2kFq4t/zr3AlxJ6kmHMgjIOiIiUla49+us
         +Ap58+8G9VsyfBivTx2bWkJkI9p8n477q10cat9dL2AwlS7c4Vd0iEyAq3/t7Ob5HVPw
         2qC7voV+845g8knL66fybRSdqxpXChlxqnqOLwbTAoCMvhuQElIZaHGpBJOtDKdzq/3R
         rlKGyhxtK6xY++AylWmYtGUubz28mft5T3PixhFl3MjBLrw0J6J4hESY5aD90IDpJXng
         YNoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4kvEcNvpmxceD0f1ZSDk5+G1yb2QBDPJ2MdK+uvqRCY=;
        b=JZgF03/0v6ChckXtUW+jM3yOFTR2I2/FhKwxmqnLQ6hau7BUtt+eIxSRj2uU6PIOyp
         vf5AiRqAJQZZdpvJbx4TIpf01HY1rLSCm10LTIK3MxJdHWJqlThEabOPqtYMIkSYcn/O
         T9ILIA0C1ZcWamezikjm/ezD51yj3uOWH+jA74QjbsoDAfdmkDL8YOZW/wGfJEvr0KNW
         trYhhtf8PwW2sikBihNrI+MQ+fP6SX4igUc5n0Tm4m22Fbj/Ln/QTyPV9lOzQlL6PMGb
         AsfGNR79/GL3PLOnH+/nukkMrMtl/g88c0tm8Em/zvLpSk0JVse2eW25GWJk/8HNPdYl
         169A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubGwMxw34eNnV0MmCyCAH2yv0ZsHBvJsu33L6xpmXFLSkCO6LZG
	jBNe/RZ+QfeU5jTM3nf76Co=
X-Google-Smtp-Source: APiQypKo5NUf2JFJ3T/BYUWnA/x8YLo3CPikzuwQjLRy2n1lxnEnlcrBXwP0d8oT9ewjocS7RpPdWw==
X-Received: by 2002:a17:90b:3017:: with SMTP id hg23mr20688261pjb.150.1589203777794;
        Mon, 11 May 2020 06:29:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7790:: with SMTP id s138ls4580778pfc.11.gmail; Mon, 11
 May 2020 06:29:37 -0700 (PDT)
X-Received: by 2002:a62:25c6:: with SMTP id l189mr16557062pfl.28.1589203777259;
        Mon, 11 May 2020 06:29:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589203777; cv=none;
        d=google.com; s=arc-20160816;
        b=XxULy1WRaU2v0UMpSchjOfvsEW/PenMXaL3zxHaW67UCfslb3HuoF+eWLwnxfmxxps
         PA/p7avyKcHjfHjuVZAcom+tALpYhabDRmF6ChbvBh/n7cet8gMYNwB7Yg1AAoWpzyf6
         XnxRwAmrwBU4F6dQM4MUd1yU88V1SW1eorGZ0WiTaYb87jLPglK2Kg3oSl8NCrYibYkZ
         HkL0k6vORDFg/JCiiOMNit7nHLaTRIY4vRI60lim4+tQnYD/xY1Uedm7VoinjMGSwnEl
         H4VUk8J79mUXhPy8DEcFdVCdnRivNFML4+bNUurh0tbpUjmTUCgigvUSAt50bggdNwP+
         Of4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:dkim-signature;
        bh=zx/FT5efn+A50fIfzwFNm4qZkei5t6eHZUidE0t98+I=;
        b=ETTP5y4amyanZPvmdqM7ip5CpU6+lcGkC2AzNqPBhoAYLYsY2miWXaUHRGhebQxb+K
         sQDVkRMSF0NEm9BBHvmRofaQ4Bh/qV1UPnIPC7axxLP68W9detvr5z4T0K111pcwhyaY
         TY46ZfoYsuiefC/DzCGiPNycB3868UXaI1Bvqfd9bFnH/sqUPzNz+3uT0P9NW27QbE1G
         VWP0bQ6r8FPdOTx8ooEHZFuSwptCDT5wVgAPx8o1BaPaDv3QR0lyPSJgfZVrl+qZqfCE
         r9otHZZC9/D+109CxdOU1zXne7aXYiVdHAfzTSUrYJ+MoFnPg4L5x5M7qKGSRTsmEEIO
         xaVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Gzet0xTw;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l10si463703pgh.3.2020.05.11.06.29.36
        for <kasan-dev@googlegroups.com>;
        Mon, 11 May 2020 06:29:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 850bb01fb8084c60a3342a2de9f0ec53-20200511
X-UUID: 850bb01fb8084c60a3342a2de9f0ec53-20200511
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1314611580; Mon, 11 May 2020 21:29:33 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 21:29:28 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 21:29:29 +0800
Message-ID: <1589203771.21284.22.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Paul E .
 McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, "Andrew
 Morton" <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>
Date: Mon, 11 May 2020 21:29:31 +0800
In-Reply-To: <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
	 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
Content-Type: multipart/alternative; boundary="=-zzz+4sJh7De0VKt8SICN"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 906183CA6AFD033DC37498D65AFF5A25F5E0B404E04664A58508061213F02C112000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Gzet0xTw;       spf=pass
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

--=-zzz+4sJh7De0VKt8SICN
Content-Type: text/plain; charset="UTF-8"

On Mon, 2020-05-11 at 14:43 +0200, Dmitry Vyukov wrote:

> On Mon, May 11, 2020 at 2:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, May 11, 2020 at 4:31 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > This feature will record first and last call_rcu() call stack and
> > > print two call_rcu() call stack in KASAN report.
> > >
> > > When call_rcu() is called, we store the call_rcu() call stack into
> > > slub alloc meta-data, so that KASAN report can print rcu stack.
> > >
> > > It doesn't increase the cost of memory consumption. Because we don't
> > > enlarge struct kasan_alloc_meta size.
> > > - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> > > - remove free track from kasan_alloc_meta, size is 8 bytes.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Andrew Morton <akpm@linux-foundation.org>
> > > Cc: Paul E. McKenney <paulmck@kernel.org>
> > > Cc: Josh Triplett <josh@joshtriplett.org>
> > > Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> > > Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> > > Cc: Joel Fernandes <joel@joelfernandes.org>
> > > ---
> > >  include/linux/kasan.h |  2 ++
> > >  kernel/rcu/tree.c     |  3 +++
> > >  lib/Kconfig.kasan     |  2 ++
> > >  mm/kasan/common.c     |  4 ++--
> > >  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
> > >  mm/kasan/kasan.h      | 19 +++++++++++++++++++
> > >  mm/kasan/report.c     | 21 +++++++++++++++++----
> > >  7 files changed, 74 insertions(+), 6 deletions(-)
> > >
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index 31314ca7c635..23b7ee00572d 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> > >
> > >  void kasan_cache_shrink(struct kmem_cache *cache);
> > >  void kasan_cache_shutdown(struct kmem_cache *cache);
> > > +void kasan_record_aux_stack(void *ptr);
> > >
> > >  #else /* CONFIG_KASAN_GENERIC */
> > >
> > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > +static inline void kasan_record_aux_stack(void *ptr) {}
> > >
> > >  #endif /* CONFIG_KASAN_GENERIC */
> > >
> > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > index 06548e2ebb72..de872b6cc261 100644
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -57,6 +57,7 @@
> > >  #include <linux/slab.h>
> > >  #include <linux/sched/isolation.h>
> > >  #include <linux/sched/clock.h>
> > > +#include <linux/kasan.h>
> > >  #include "../time/tick-internal.h"
> > >
> > >  #include "tree.h"
> > > @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >                 trace_rcu_callback(rcu_state.name, head,
> > >                                    rcu_segcblist_n_cbs(&rdp->cblist));
> > >
> > > +       kasan_record_aux_stack(head);
> > > +
> > >         /* Go handle any RCU core processing required. */
> > >         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
> > >             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > index 81f5464ea9e1..56a89291f1cc 100644
> > > --- a/lib/Kconfig.kasan
> > > +++ b/lib/Kconfig.kasan
> > > @@ -58,6 +58,8 @@ config KASAN_GENERIC
> > >           For better error detection enable CONFIG_STACKTRACE.
> > >           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> > >           (the resulting kernel does not boot).
> > > +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> > > +         call stack. It doesn't increase the cost of memory consumption.
> > >
> > >  config KASAN_SW_TAGS
> > >         bool "Software tag-based mode"
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 2906358e42f0..8bc618289bb1 100644
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -41,7 +41,7 @@
> > >  #include "kasan.h"
> > >  #include "../slab.h"
> > >
> > > -static inline depot_stack_handle_t save_stack(gfp_t flags)
> > > +depot_stack_handle_t kasan_save_stack(gfp_t flags)
> > >  {
> > >         unsigned long entries[KASAN_STACK_DEPTH];
> > >         unsigned int nr_entries;
> > > @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
> > >  static inline void set_track(struct kasan_track *track, gfp_t flags)
> > >  {
> > >         track->pid = current->pid;
> > > -       track->stack = save_stack(flags);
> > > +       track->stack = kasan_save_stack(flags);
> > >  }
> > >
> > >  void kasan_enable_current(void)
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 56ff8885fe2e..b86880c338e2 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
> > >  DEFINE_ASAN_SET_SHADOW(f3);
> > >  DEFINE_ASAN_SET_SHADOW(f5);
> > >  DEFINE_ASAN_SET_SHADOW(f8);
> > > +
> > > +void kasan_record_aux_stack(void *addr)
> > > +{
> > > +       struct page *page = kasan_addr_to_page(addr);
> > > +       struct kmem_cache *cache;
> > > +       struct kasan_alloc_meta *alloc_info;
> > > +       void *object;
> > > +
> > > +       if (!(page && PageSlab(page)))
> > > +               return;
> > > +
> > > +       cache = page->slab_cache;
> > > +       object = nearest_obj(cache, page, addr);
> > > +       alloc_info = get_alloc_info(cache, object);
> > > +
> > > +       if (!alloc_info->rcu_stack[0])
> > > +               /* record first call_rcu() call stack */
> > > +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> > > +       else
> > > +               /* record last call_rcu() call stack */
> > > +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> > > +}
> > > +
> > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > +                                               u8 idx)
> > > +{
> > > +       return container_of(&alloc_info->rcu_stack[idx],
> > > +                                               struct kasan_track, stack);
> > > +}
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index e8f37199d885..1cc1fb7b0de3 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -96,15 +96,28 @@ struct kasan_track {
> > >         depot_stack_handle_t stack;
> > >  };
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +#define SIZEOF_PTR sizeof(void *)
> >
> > Please move this to generic.c closer to kasan_set_free_info.
> > Unnecessary in the header.
> >
> > > +#define KASAN_NR_RCU_CALL_STACKS 2
> >
> > Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
> > well use 2 instead of it.
> > Reduces level of indirection and cognitive load.
> >
> > > +#else /* CONFIG_KASAN_GENERIC */
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >  #define KASAN_NR_FREE_STACKS 5
> > >  #else
> > >  #define KASAN_NR_FREE_STACKS 1
> > >  #endif
> > > +#endif /* CONFIG_KASAN_GENERIC */
> > >
> > >  struct kasan_alloc_meta {
> > >         struct kasan_track alloc_track;
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +       /*
> > > +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > > +        * The free stack is stored into freed object.
> > > +        */
> > > +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> > > +#else
> > >         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> > > +#endif
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> > >         u8 free_track_idx;
> > > @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
> > >
> > >  struct page *kasan_addr_to_page(const void *addr);
> > >
> > > +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> > > +
> > >  #if defined(CONFIG_KASAN_GENERIC) && \
> > >         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> > >  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> > >  void quarantine_reduce(void);
> > >  void quarantine_remove_cache(struct kmem_cache *cache);
> > > +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> > > +                       u8 idx);
> > >  #else
> > >  static inline void quarantine_put(struct kasan_free_meta *info,
> > >                                 struct kmem_cache *cache) { }
> > >  static inline void quarantine_reduce(void) { }
> > >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> > > +static inline struct kasan_track *kasan_get_aux_stack(
> > > +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
> > >  #endif
> > >
> > >  #ifdef CONFIG_KASAN_SW_TAGS
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 80f23c9da6b0..f16a1a210815 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
> > >         kasan_enable_current();
> > >  }
> > >
> > > -static void print_track(struct kasan_track *track, const char *prefix)
> > > +static void print_track(struct kasan_track *track, const char *prefix,
> > > +                                               bool is_callrcu)
> > >  {
> > > -       pr_err("%s by task %u:\n", prefix, track->pid);
> > > +       if (is_callrcu)
> > > +               pr_err("%s:\n", prefix);
> > > +       else
> > > +               pr_err("%s by task %u:\n", prefix, track->pid);
> > >         if (track->stack) {
> > >                 unsigned long *entries;
> > >                 unsigned int nr_entries;
> > > @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > >         if (cache->flags & SLAB_KASAN) {
> > >                 struct kasan_track *free_track;
> > >
> > > -               print_track(&alloc_info->alloc_track, "Allocated");
> > > +               print_track(&alloc_info->alloc_track, "Allocated", false);
> > >                 pr_err("\n");
> > >                 free_track = kasan_get_free_track(cache, object, tag);
> > > -               print_track(free_track, "Freed");
> > > +               print_track(free_track, "Freed", false);
> > >                 pr_err("\n");
> > > +
> > > +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > > +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> > > +                       print_track(free_track, "First call_rcu() call stack", true);
> > > +                       pr_err("\n");
> > > +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> > > +                       print_track(free_track, "Last call_rcu() call stack", true);
> > > +                       pr_err("\n");
> > > +               }
> > >         }
> > >
> > >         describe_object_addr(cache, object, addr);
> 
> Some higher level comments.
> 
> 1. I think we need to put the free track into kasan_free_meta as it
> was before. It looks like exactly the place for it. We have logic to
> properly place it and to do the casts.
> 


If the free track put kasan_free_meta, then it increase slab meta size?
Our original goal does not enlarge it.


> 2. We need to zero aux stacks when we reallocate the object. Otherwise
> we print confusing garbage.
> 


My local has an UT about use-after-free and rcu, but it is hard to test
the printing confusing garbage, because we may need to get the same
object(old pointer and new pointer). In generic KASAN is not easy to get
it.


> 3. __kasan_slab_free now contains a window of inconsistency when it
> marked the object as KASAN_KMALLOC_FREE, but did not store the free
> track yet. If another thread prints a report now, it will print random
> garbage.
> 


It is possible, but the window is so tiny. It sets free track
immediately after write the KASAN_KMALLOC_FREE.


> 4. We need some tests. At least (2) should be visible on tests.


Ok.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589203771.21284.22.camel%40mtksdccf07.

--=-zzz+4sJh7De0VKt8SICN
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 TRANSITIONAL//EN">
<HTML>
<HEAD>
  <META HTTP-EQUIV=3D"Content-Type" CONTENT=3D"text/html; CHARSET=3DUTF-8">
  <META NAME=3D"GENERATOR" CONTENT=3D"GtkHTML/4.2.2">
</HEAD>
<BODY>
On Mon, 2020-05-11 at 14:43 +0200, Dmitry Vyukov wrote:
<BLOCKQUOTE TYPE=3DCITE>
<PRE>
On Mon, May 11, 2020 at 2:31 PM Dmitry Vyukov &lt;<A HREF=3D"mailto:dvyukov=
@google.com">dvyukov@google.com</A>&gt; wrote:
&gt;
&gt; On Mon, May 11, 2020 at 4:31 AM Walter Wu &lt;<A HREF=3D"mailto:walter=
-zh.wu@mediatek.com">walter-zh.wu@mediatek.com</A>&gt; wrote:
&gt; &gt;
&gt; &gt; This feature will record first and last call_rcu() call stack and
&gt; &gt; print two call_rcu() call stack in KASAN report.
&gt; &gt;
&gt; &gt; When call_rcu() is called, we store the call_rcu() call stack int=
o
&gt; &gt; slub alloc meta-data, so that KASAN report can print rcu stack.
&gt; &gt;
&gt; &gt; It doesn't increase the cost of memory consumption. Because we do=
n't
&gt; &gt; enlarge struct kasan_alloc_meta size.
&gt; &gt; - add two call_rcu() call stack into kasan_alloc_meta, size is 8 =
bytes.
&gt; &gt; - remove free track from kasan_alloc_meta, size is 8 bytes.
&gt; &gt;
&gt; &gt; [1]<A HREF=3D"https://bugzilla.kernel.org/show_bug.cgi?id=3D19843=
7">https://bugzilla.kernel.org/show_bug.cgi?id=3D198437</A>
&gt; &gt; [2]<A HREF=3D"https://groups.google.com/forum/#!searchin/kasan-de=
v/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rN=
UZprRBgAJ">https://groups.google.com/forum/#!searchin/kasan-dev/better$20st=
ack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ</A>
&gt; &gt;
&gt; &gt; Signed-off-by: Walter Wu &lt;<A HREF=3D"mailto:walter-zh.wu@media=
tek.com">walter-zh.wu@mediatek.com</A>&gt;
&gt; &gt; Suggested-by: Dmitry Vyukov &lt;<A HREF=3D"mailto:dvyukov@google.=
com">dvyukov@google.com</A>&gt;
&gt; &gt; Cc: Andrey Ryabinin &lt;<A HREF=3D"mailto:aryabinin@virtuozzo.com=
">aryabinin@virtuozzo.com</A>&gt;
&gt; &gt; Cc: Dmitry Vyukov &lt;<A HREF=3D"mailto:dvyukov@google.com">dvyuk=
ov@google.com</A>&gt;
&gt; &gt; Cc: Alexander Potapenko &lt;<A HREF=3D"mailto:glider@google.com">=
glider@google.com</A>&gt;
&gt; &gt; Cc: Andrew Morton &lt;<A HREF=3D"mailto:akpm@linux-foundation.org=
">akpm@linux-foundation.org</A>&gt;
&gt; &gt; Cc: Paul E. McKenney &lt;<A HREF=3D"mailto:paulmck@kernel.org">pa=
ulmck@kernel.org</A>&gt;
&gt; &gt; Cc: Josh Triplett &lt;<A HREF=3D"mailto:josh@joshtriplett.org">jo=
sh@joshtriplett.org</A>&gt;
&gt; &gt; Cc: Mathieu Desnoyers &lt;<A HREF=3D"mailto:mathieu.desnoyers@eff=
icios.com">mathieu.desnoyers@efficios.com</A>&gt;
&gt; &gt; Cc: Lai Jiangshan &lt;<A HREF=3D"mailto:jiangshanlai@gmail.com">j=
iangshanlai@gmail.com</A>&gt;
&gt; &gt; Cc: Joel Fernandes &lt;<A HREF=3D"mailto:joel@joelfernandes.org">=
joel@joelfernandes.org</A>&gt;
&gt; &gt; ---
&gt; &gt;  include/linux/kasan.h |  2 ++
&gt; &gt;  kernel/rcu/tree.c     |  3 +++
&gt; &gt;  lib/Kconfig.kasan     |  2 ++
&gt; &gt;  mm/kasan/common.c     |  4 ++--
&gt; &gt;  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
&gt; &gt;  mm/kasan/kasan.h      | 19 +++++++++++++++++++
&gt; &gt;  mm/kasan/report.c     | 21 +++++++++++++++++----
&gt; &gt;  7 files changed, 74 insertions(+), 6 deletions(-)
&gt; &gt;
&gt; &gt; diff --git a/include/linux/kasan.h b/include/linux/kasan.h
&gt; &gt; index 31314ca7c635..23b7ee00572d 100644
&gt; &gt; --- a/include/linux/kasan.h
&gt; &gt; +++ b/include/linux/kasan.h
&gt; &gt; @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(st=
ruct kmem_cache *cache) { return 0; }
&gt; &gt;
&gt; &gt;  void kasan_cache_shrink(struct kmem_cache *cache);
&gt; &gt;  void kasan_cache_shutdown(struct kmem_cache *cache);
&gt; &gt; +void kasan_record_aux_stack(void *ptr);
&gt; &gt;
&gt; &gt;  #else /* CONFIG_KASAN_GENERIC */
&gt; &gt;
&gt; &gt;  static inline void kasan_cache_shrink(struct kmem_cache *cache) =
{}
&gt; &gt;  static inline void kasan_cache_shutdown(struct kmem_cache *cache=
) {}
&gt; &gt; +static inline void kasan_record_aux_stack(void *ptr) {}
&gt; &gt;
&gt; &gt;  #endif /* CONFIG_KASAN_GENERIC */
&gt; &gt;
&gt; &gt; diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
&gt; &gt; index 06548e2ebb72..de872b6cc261 100644
&gt; &gt; --- a/kernel/rcu/tree.c
&gt; &gt; +++ b/kernel/rcu/tree.c
&gt; &gt; @@ -57,6 +57,7 @@
&gt; &gt;  #include &lt;linux/slab.h&gt;
&gt; &gt;  #include &lt;linux/sched/isolation.h&gt;
&gt; &gt;  #include &lt;linux/sched/clock.h&gt;
&gt; &gt; +#include &lt;linux/kasan.h&gt;
&gt; &gt;  #include &quot;../time/tick-internal.h&quot;
&gt; &gt;
&gt; &gt;  #include &quot;tree.h&quot;
&gt; &gt; @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callb=
ack_t func)
&gt; &gt;                 trace_rcu_callback(rcu_state.name, head,
&gt; &gt;                                    rcu_segcblist_n_cbs(&amp;rdp-&=
gt;cblist));
&gt; &gt;
&gt; &gt; +       kasan_record_aux_stack(head);
&gt; &gt; +
&gt; &gt;         /* Go handle any RCU core processing required. */
&gt; &gt;         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &amp;&amp;
&gt; &gt;             unlikely(rcu_segcblist_is_offloaded(&amp;rdp-&gt;cbli=
st))) {
&gt; &gt; diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
&gt; &gt; index 81f5464ea9e1..56a89291f1cc 100644
&gt; &gt; --- a/lib/Kconfig.kasan
&gt; &gt; +++ b/lib/Kconfig.kasan
&gt; &gt; @@ -58,6 +58,8 @@ config KASAN_GENERIC
&gt; &gt;           For better error detection enable CONFIG_STACKTRACE.
&gt; &gt;           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG=
_DEBUG_SLAB
&gt; &gt;           (the resulting kernel does not boot).
&gt; &gt; +         Currently CONFIG_KASAN_GENERIC will print first and las=
t call_rcu()
&gt; &gt; +         call stack. It doesn't increase the cost of memory cons=
umption.
&gt; &gt;
&gt; &gt;  config KASAN_SW_TAGS
&gt; &gt;         bool &quot;Software tag-based mode&quot;
&gt; &gt; diff --git a/mm/kasan/common.c b/mm/kasan/common.c
&gt; &gt; index 2906358e42f0..8bc618289bb1 100644
&gt; &gt; --- a/mm/kasan/common.c
&gt; &gt; +++ b/mm/kasan/common.c
&gt; &gt; @@ -41,7 +41,7 @@
&gt; &gt;  #include &quot;kasan.h&quot;
&gt; &gt;  #include &quot;../slab.h&quot;
&gt; &gt;
&gt; &gt; -static inline depot_stack_handle_t save_stack(gfp_t flags)
&gt; &gt; +depot_stack_handle_t kasan_save_stack(gfp_t flags)
&gt; &gt;  {
&gt; &gt;         unsigned long entries[KASAN_STACK_DEPTH];
&gt; &gt;         unsigned int nr_entries;
&gt; &gt; @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(g=
fp_t flags)
&gt; &gt;  static inline void set_track(struct kasan_track *track, gfp_t fl=
ags)
&gt; &gt;  {
&gt; &gt;         track-&gt;pid =3D current-&gt;pid;
&gt; &gt; -       track-&gt;stack =3D save_stack(flags);
&gt; &gt; +       track-&gt;stack =3D kasan_save_stack(flags);
&gt; &gt;  }
&gt; &gt;
&gt; &gt;  void kasan_enable_current(void)
&gt; &gt; diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
&gt; &gt; index 56ff8885fe2e..b86880c338e2 100644
&gt; &gt; --- a/mm/kasan/generic.c
&gt; &gt; +++ b/mm/kasan/generic.c
&gt; &gt; @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
&gt; &gt;  DEFINE_ASAN_SET_SHADOW(f3);
&gt; &gt;  DEFINE_ASAN_SET_SHADOW(f5);
&gt; &gt;  DEFINE_ASAN_SET_SHADOW(f8);
&gt; &gt; +
&gt; &gt; +void kasan_record_aux_stack(void *addr)
&gt; &gt; +{
&gt; &gt; +       struct page *page =3D kasan_addr_to_page(addr);
&gt; &gt; +       struct kmem_cache *cache;
&gt; &gt; +       struct kasan_alloc_meta *alloc_info;
&gt; &gt; +       void *object;
&gt; &gt; +
&gt; &gt; +       if (!(page &amp;&amp; PageSlab(page)))
&gt; &gt; +               return;
&gt; &gt; +
&gt; &gt; +       cache =3D page-&gt;slab_cache;
&gt; &gt; +       object =3D nearest_obj(cache, page, addr);
&gt; &gt; +       alloc_info =3D get_alloc_info(cache, object);
&gt; &gt; +
&gt; &gt; +       if (!alloc_info-&gt;rcu_stack[0])
&gt; &gt; +               /* record first call_rcu() call stack */
&gt; &gt; +               alloc_info-&gt;rcu_stack[0] =3D kasan_save_stack(=
GFP_NOWAIT);
&gt; &gt; +       else
&gt; &gt; +               /* record last call_rcu() call stack */
&gt; &gt; +               alloc_info-&gt;rcu_stack[1] =3D kasan_save_stack(=
GFP_NOWAIT);
&gt; &gt; +}
&gt; &gt; +
&gt; &gt; +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta =
*alloc_info,
&gt; &gt; +                                               u8 idx)
&gt; &gt; +{
&gt; &gt; +       return container_of(&amp;alloc_info-&gt;rcu_stack[idx],
&gt; &gt; +                                               struct kasan_trac=
k, stack);
&gt; &gt; +}
&gt; &gt; diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
&gt; &gt; index e8f37199d885..1cc1fb7b0de3 100644
&gt; &gt; --- a/mm/kasan/kasan.h
&gt; &gt; +++ b/mm/kasan/kasan.h
&gt; &gt; @@ -96,15 +96,28 @@ struct kasan_track {
&gt; &gt;         depot_stack_handle_t stack;
&gt; &gt;  };
&gt; &gt;
&gt; &gt; +#ifdef CONFIG_KASAN_GENERIC
&gt; &gt; +#define SIZEOF_PTR sizeof(void *)
&gt;
&gt; Please move this to generic.c closer to kasan_set_free_info.
&gt; Unnecessary in the header.
&gt;
&gt; &gt; +#define KASAN_NR_RCU_CALL_STACKS 2
&gt;
&gt; Since KASAN_NR_RCU_CALL_STACKS is only used once below, you could as
&gt; well use 2 instead of it.
&gt; Reduces level of indirection and cognitive load.
&gt;
&gt; &gt; +#else /* CONFIG_KASAN_GENERIC */
&gt; &gt;  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
&gt; &gt;  #define KASAN_NR_FREE_STACKS 5
&gt; &gt;  #else
&gt; &gt;  #define KASAN_NR_FREE_STACKS 1
&gt; &gt;  #endif
&gt; &gt; +#endif /* CONFIG_KASAN_GENERIC */
&gt; &gt;
&gt; &gt;  struct kasan_alloc_meta {
&gt; &gt;         struct kasan_track alloc_track;
&gt; &gt; +#ifdef CONFIG_KASAN_GENERIC
&gt; &gt; +       /*
&gt; &gt; +        * call_rcu() call stack is stored into struct kasan_allo=
c_meta.
&gt; &gt; +        * The free stack is stored into freed object.
&gt; &gt; +        */
&gt; &gt; +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
&gt; &gt; +#else
&gt; &gt;         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
&gt; &gt; +#endif
&gt; &gt;  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
&gt; &gt;         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
&gt; &gt;         u8 free_track_idx;
&gt; &gt; @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object=
, unsigned long ip);
&gt; &gt;
&gt; &gt;  struct page *kasan_addr_to_page(const void *addr);
&gt; &gt;
&gt; &gt; +depot_stack_handle_t kasan_save_stack(gfp_t flags);
&gt; &gt; +
&gt; &gt;  #if defined(CONFIG_KASAN_GENERIC) &amp;&amp; \
&gt; &gt;         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
&gt; &gt;  void quarantine_put(struct kasan_free_meta *info, struct kmem_ca=
che *cache);
&gt; &gt;  void quarantine_reduce(void);
&gt; &gt;  void quarantine_remove_cache(struct kmem_cache *cache);
&gt; &gt; +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta =
*alloc_info,
&gt; &gt; +                       u8 idx);
&gt; &gt;  #else
&gt; &gt;  static inline void quarantine_put(struct kasan_free_meta *info,
&gt; &gt;                                 struct kmem_cache *cache) { }
&gt; &gt;  static inline void quarantine_reduce(void) { }
&gt; &gt;  static inline void quarantine_remove_cache(struct kmem_cache *ca=
che) { }
&gt; &gt; +static inline struct kasan_track *kasan_get_aux_stack(
&gt; &gt; +                       struct kasan_alloc_meta *alloc_info, u8 i=
dx) { return NULL; }
&gt; &gt;  #endif
&gt; &gt;
&gt; &gt;  #ifdef CONFIG_KASAN_SW_TAGS
&gt; &gt; diff --git a/mm/kasan/report.c b/mm/kasan/report.c
&gt; &gt; index 80f23c9da6b0..f16a1a210815 100644
&gt; &gt; --- a/mm/kasan/report.c
&gt; &gt; +++ b/mm/kasan/report.c
&gt; &gt; @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
&gt; &gt;         kasan_enable_current();
&gt; &gt;  }
&gt; &gt;
&gt; &gt; -static void print_track(struct kasan_track *track, const char *p=
refix)
&gt; &gt; +static void print_track(struct kasan_track *track, const char *p=
refix,
&gt; &gt; +                                               bool is_callrcu)
&gt; &gt;  {
&gt; &gt; -       pr_err(&quot;%s by task %u:\n&quot;, prefix, track-&gt;pi=
d);
&gt; &gt; +       if (is_callrcu)
&gt; &gt; +               pr_err(&quot;%s:\n&quot;, prefix);
&gt; &gt; +       else
&gt; &gt; +               pr_err(&quot;%s by task %u:\n&quot;, prefix, trac=
k-&gt;pid);
&gt; &gt;         if (track-&gt;stack) {
&gt; &gt;                 unsigned long *entries;
&gt; &gt;                 unsigned int nr_entries;
&gt; &gt; @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cac=
he *cache, void *object,
&gt; &gt;         if (cache-&gt;flags &amp; SLAB_KASAN) {
&gt; &gt;                 struct kasan_track *free_track;
&gt; &gt;
&gt; &gt; -               print_track(&amp;alloc_info-&gt;alloc_track, &quo=
t;Allocated&quot;);
&gt; &gt; +               print_track(&amp;alloc_info-&gt;alloc_track, &quo=
t;Allocated&quot;, false);
&gt; &gt;                 pr_err(&quot;\n&quot;);
&gt; &gt;                 free_track =3D kasan_get_free_track(cache, object=
, tag);
&gt; &gt; -               print_track(free_track, &quot;Freed&quot;);
&gt; &gt; +               print_track(free_track, &quot;Freed&quot;, false)=
;
&gt; &gt;                 pr_err(&quot;\n&quot;);
&gt; &gt; +
&gt; &gt; +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
&gt; &gt; +                       free_track =3D kasan_get_aux_stack(alloc_=
info, 0);
&gt; &gt; +                       print_track(free_track, &quot;First call_=
rcu() call stack&quot;, true);
&gt; &gt; +                       pr_err(&quot;\n&quot;);
&gt; &gt; +                       free_track =3D kasan_get_aux_stack(alloc_=
info, 1);
&gt; &gt; +                       print_track(free_track, &quot;Last call_r=
cu() call stack&quot;, true);
&gt; &gt; +                       pr_err(&quot;\n&quot;);
&gt; &gt; +               }
&gt; &gt;         }
&gt; &gt;
&gt; &gt;         describe_object_addr(cache, object, addr);

Some higher level comments.

1. I think we need to put the free track into kasan_free_meta as it
was before. It looks like exactly the place for it. We have logic to
properly place it and to do the casts.

</PRE>
</BLOCKQUOTE>
<BR>
If the free track put kasan_free_meta, then it increase slab meta size?<BR>
Our original goal does not enlarge it.<BR>
<BR>
<BLOCKQUOTE TYPE=3DCITE>
<PRE>
2. We need to zero aux stacks when we reallocate the object. Otherwise
we print confusing garbage.

</PRE>
</BLOCKQUOTE>
<BR>
My local has an UT about use-after-free and rcu, but it is hard to test the=
 printing confusing garbage, because we may need to get the same object(old=
 pointer and new pointer). In generic KASAN is not easy to get it.<BR>
<BR>
<BLOCKQUOTE TYPE=3DCITE>
<PRE>
3. __kasan_slab_free now contains a window of inconsistency when it
marked the object as KASAN_KMALLOC_FREE, but did not store the free
track yet. If another thread prints a report now, it will print random
garbage.

</PRE>
</BLOCKQUOTE>
<BR>
It is possible, but the window is so tiny. It sets free track immediately a=
fter write the KASAN_KMALLOC_FREE.<BR>
<BR>
<BLOCKQUOTE TYPE=3DCITE>
<PRE>
4. We need some tests. At least (2) should be visible on tests.
</PRE>
</BLOCKQUOTE>
<BR>
Ok.
</BODY>
</HTML>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1589203771.21284.22.camel%40mtksdccf07?utm_medium=3Dem=
ail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/158920=
3771.21284.22.camel%40mtksdccf07</a>.<br />

--=-zzz+4sJh7De0VKt8SICN--

