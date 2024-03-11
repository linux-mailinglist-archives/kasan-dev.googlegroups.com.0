Return-Path: <kasan-dev+bncBAABBRU6XOXQMGQEN2VDELY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 50370877CBE
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 10:30:48 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-36630680c5dsf30227845ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 02:30:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710149447; cv=pass;
        d=google.com; s=arc-20160816;
        b=prwL17It703NpzsO+n1ZtjpqZgpTLa6ukLho57JKt/Ei+MYR1+N9/lyU7UQ6WXPyqI
         poKc6NuaOLWGdqWKxrytIvReEXvSY+xBry9WrQO+zhAPngbvJfAiBMPz6wJZraVypPNs
         5iTMRBi5tEA9GuV68Xlz+Y387gs0hw4vE9U7iP8okW22UNWSmuxLRRDJRrMEwpQhtfoD
         BGfgdL/1UzWMbEquwy8LwGfzYAxHkCqLfXnr7V9ct9xR39zRaGjQCiiBUCA65BSkE5MR
         ma7p2FsGmSgkD8It+IC0JPCUMGeOAao0woHGhZXBwtdyzVh9yYts/awSD1D6UN0gRhUc
         pyhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VnC9NtcDaxkQQZMXWXBlrJthBYtFcYqPtVqBCS0wW8A=;
        fh=4Rk+Y1QO0nSnsISKJYpjBscrpD6zoJCNE95bN4b6vKE=;
        b=LKgDbTF/pZMiOFzaScK8095IUIZo+UIKcJWuWnnCZoTzL6qjy4JZIrQ3l7u4JGOY2F
         rI6Y58kBBJw3KFCga9r0+tODxzmRLT/3TcngPJJI+0rdW+7/cUzjAienExWpvtiFZTzK
         HoCBiuKL1Z8QJZ+/+DfI/MtliioOFfYyR6WOCxunGYaROUnKMcjWasltlXwXPnM33Eit
         2j0TEm7uKLFGxg2XqYVhLkQMIWPGKgjllAtaky9lOwypWyl/XiHakthPlzgLdc12hFTC
         QrmEYBLHFzzPac9o5opZ9OQ/jwQ3XhOg01kvYtv0oiO4/B5zpIJuruHU3R9zW79YkhR2
         GMUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710149447; x=1710754247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VnC9NtcDaxkQQZMXWXBlrJthBYtFcYqPtVqBCS0wW8A=;
        b=TvKgpGlnpYNOzVTPCPL3wOJBsu2NPZa02VBomFA203O3Gduy9IsEESYvBqySQHQWno
         rZ30n+4MQ391W4Pk4ts57a9ESsgSS/yxfMpx2sZFuh8u3MaWgJjhbbv7ZjbXeEwSSca3
         e0SP5+jp/BYgWV0qlbnbqcNEJdYjfUjlsttwbVJN2yOgxfR8YxdxHHhiVYY7w9pk22mB
         9+WzyV9/zFChxE4NFsJcTPM8y7OX+VcvxP/02RL7TJGYfM3C/I7Vk7JAnO6nda3l+NZK
         4jAG6PN6YvyZASH+PMXDqqh4jhMBJBuO2hWuM9ra18j1ymeyRVd4As/Iao+bJn9Dxo69
         /33w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710149447; x=1710754247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VnC9NtcDaxkQQZMXWXBlrJthBYtFcYqPtVqBCS0wW8A=;
        b=izJtDg8UMMzt5SDWIHWtq4stn3MjuZOaIclWb4Lnb8Dp4PqVbQbQ+F3dQmeQdAsoYs
         Yxy9q+LmtVbLWYyDbdRvf1mq856+6aTDLHAMbxyLzwk+il/w1l6kkRsr7ginOeIOEu4W
         6dfPWP1ilLtmgfB6pyjplFUvicWkMkseqTyFQvW3rq5TQuPVpIGBy2pgz/ilhUpRG4o7
         bOnjAEpPiPO4E0ZQqJ/T12VayX+ougHETSgMtLokFHPmiKgL8ONNUotRt0pu3+gW/nyU
         tyDA8Mk62zd2MbEsPg2pNwCKp+sUD/pK9LyPcs/VIW+skopB4Fz5SjY+kEdUGf3BLyH2
         vE0A==
X-Forwarded-Encrypted: i=2; AJvYcCX3Jt0uvlmW998B/hZPN7gWaHkiNT6Xloqgaf5xkwt5n0qm0TW6QI92BXFHHubYv+bVR8iH9bLKHnxtIy3KOMEjSOizbM1gTQ==
X-Gm-Message-State: AOJu0Yyw6K1/XQ6Nl05pImv7JQOsiKq4wcrJ8IJL6vSlk+50pLPQrrgp
	56rnzYJzgpd2lDJT2E7UQcttO2ZFXnDIwrtHNGjlyFUG2aMWww99
X-Google-Smtp-Source: AGHT+IEb0S+lCFfCWBJfj6+pnReKKriSOKut35KdWAxIkf+uDKDZuWTwlkMky6e82hyCtXwyUmk3Uw==
X-Received: by 2002:a05:6e02:156a:b0:365:cd40:c1e7 with SMTP id k10-20020a056e02156a00b00365cd40c1e7mr7865332ilu.11.1710149446730;
        Mon, 11 Mar 2024 02:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d8d:b0:361:9298:e7d9 with SMTP id
 h13-20020a056e021d8d00b003619298e7d9ls2207535ila.2.-pod-prod-08-us; Mon, 11
 Mar 2024 02:30:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSjIB73xryqwaQiB+068WCCsUS2Xhcn0Q2YrmBCUe05QaGMs1bJ4TOXx6acgw4689A5N+vtmSfTu+4WzUzrt6EdUJTNEdUc6rccw==
X-Received: by 2002:a92:ca05:0:b0:365:1044:4dcd with SMTP id j5-20020a92ca05000000b0036510444dcdmr8457883ils.16.1710149444749;
        Mon, 11 Mar 2024 02:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710149444; cv=none;
        d=google.com; s=arc-20160816;
        b=QQEsh1WZ8LXjh407yan3Z924O5wgMVT9co1K0RzoSZ2+/tEpxA53WOKTUVTnC5qvKc
         zx/1/AFbhzgCyfaYgO6xHg1paSDKoddMb8wR3i/HSUjzM1GxCjUK9d+1dMEYKMNIvbAz
         RdR87ZKNCie7iISDrKuslCSZoBCA+HHMgvuK0xT3VmnFkTQqJ0wNZ3D1Cj10NEetigHs
         M25f1I8JjB/XdcIGDzPYld15Wr5dOqryc84LAt1vjduRzvqYnv6ORzYw8rNBr/nTmDjm
         FyKK8hucGcAAt91TjCM0/bCIuH14U6nOuVfOOrRBEbieg2o2oXikiGoVrR9rNUzbjNG4
         tkcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=OOREsHi53h0aMH3pJm8Hl9w4EN0sLOYVJ8BoshkfZD4=;
        fh=rFhXia1eMb2njlZBQ2+h96Vjll0tzf7z4xew2OluTME=;
        b=vxC+WkswJqQc5z9iUB4EKK+O0Ax75h2Q0ZTw/GC7/ArcWYJ83CZw/ShZhs1UOMvOhv
         NWZPTZVPgA9F2/qm2puH5XHT7Qm4uRgTfarn5gfiPcyfLJ9UNSmP4T7iHEYePxu/4+VD
         Sn78iBhVKMr3RNWtYmV3ziLDcQpSBFqFKp45ApaIzCKCiHyaJQLuT0TWlmkZSvadh8sq
         z+7E89Pk3G4cQbrupTC1kpAdIwEfo69ExBqY2kb1gR+fi7tdjlRDeiUkGkFiawAknzU9
         vY3k45sP9mvOFM4PqVji7E7bECqQkI/jmMsRkzBJ/lvWXY3iUFL5znsq4jFEME6F3am4
         2VoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id l6-20020a056e020e4600b00365e9e3139fsi352217ilk.2.2024.03.11.02.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Mar 2024 02:30:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from mail.maildlp.com (unknown [172.19.163.17])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4TtWhR2Szvz3F0MV;
	Mon, 11 Mar 2024 17:29:59 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (unknown [7.221.188.204])
	by mail.maildlp.com (Postfix) with ESMTPS id A72B11A0172;
	Mon, 11 Mar 2024 17:30:41 +0800 (CST)
Received: from M910t (10.110.54.157) by kwepemd100011.china.huawei.com
 (7.221.188.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.28; Mon, 11 Mar
 2024 17:30:40 +0800
Date: Mon, 11 Mar 2024 17:30:36 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: Changbin Du <changbin.du@huawei.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
Subject: Re: [BUG] kmsan: instrumentation recursion problems
Message-ID: <20240311093036.44txy57hvhevybsu@M910t>
References: <20240308043448.masllzeqwht45d4j@M910t>
 <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.32 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

On Fri, Mar 08, 2024 at 10:39:15AM +0100, Marco Elver wrote:
> On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Hey, folks,
> > I found two instrumentation recursion issues on mainline kernel.
> >
> > 1. recur on preempt count.
> > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
> >
> > 2. recur in lockdep and rcu
> > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
> >
> >
> > Here is an unofficial fix, I don't know if it will generate false reports.
> >
> > $ git show
> > commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> > Author: Changbin Du <changbin.du@huawei.com>
> > Date:   Fri Mar 8 20:21:48 2024 +0800
> >
> >     kmsan: fix instrumentation recursions
> >
> >     Signed-off-by: Changbin Du <changbin.du@huawei.com>
> >
> > diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> > index 0db4093d17b8..ea925731fa40 100644
> > --- a/kernel/locking/Makefile
> > +++ b/kernel/locking/Makefile
> > @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
> >
> >  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> >  KCSAN_SANITIZE_lockdep.o := n
> > +KMSAN_SANITIZE_lockdep.o := n
> 
> This does not result in false positives?
>
I saw a lot of reports but seems not related to this.

[    2.742743][    T0] BUG: KMSAN: uninit-value in unwind_next_frame+0x3729/0x48a0
[    2.744404][    T0]  unwind_next_frame+0x3729/0x48a0
[    2.745623][    T0]  arch_stack_walk+0x1d9/0x2a0
[    2.746838][    T0]  stack_trace_save+0xb8/0x100
[    2.747928][    T0]  set_track_prepare+0x88/0x120
[    2.749095][    T0]  __alloc_object+0x602/0xbe0
[    2.750200][    T0]  __create_object+0x3f/0x4e0
[    2.751332][    T0]  pcpu_alloc+0x1e18/0x2b00
[    2.752401][    T0]  mm_init+0x688/0xb20
[    2.753436][    T0]  mm_alloc+0xf4/0x180
[    2.754510][    T0]  poking_init+0x50/0x500
[    2.755594][    T0]  start_kernel+0x3b0/0xbf0
[    2.756724][    T0]  __pfx_reserve_bios_regions+0x0/0x10
[    2.758073][    T0]  x86_64_start_kernel+0x92/0xa0
[    2.759320][    T0]  secondary_startup_64_no_verify+0x176/0x17b


> Does
> KMSAN_ENABLE_CHECKS_lockdep.o := n
> work as well? If it does, that is preferred because it makes sure
> there are no false positives if the lockdep code unpoisons data that
> is passed and used outside lockdep.
> 
> lockdep has a serious impact on performance, and not sanitizing it
> with KMSAN is probably a reasonable performance trade-off.
> 
Disabling checks is not working here. The recursion become this:

__msan_metadata_ptr_for_load_4() -> kmsan_get_metadata() -> virt_to_page_or_null() -> pfn_valid() -> lock_acquire() -> __msan_unpoison_alloca() -> kmsan_get_metadata()

> >  ifdef CONFIG_FUNCTION_TRACER
> >  CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
> > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > index b2bccfd37c38..8935cc866e2d 100644
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -692,7 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
> >   * Make notrace because it can be called by the internal functions of
> >   * ftrace, and making this notrace removes unnecessary recursion calls.
> >   */
> > -notrace bool rcu_is_watching(void)
> > +notrace __no_sanitize_memory bool rcu_is_watching(void)
> 
> For all of these, does __no_kmsan_checks instead of __no_sanitize_memory work?
> Again, __no_kmsan_checks (function-only counterpart to
> KMSAN_ENABLE_CHECKS_.... := n) is preferred if it works as it avoids
> any potential false positives that would be introduced by not
> instrumenting.
> 
This works because it is not unpoisoning local variables.

> >  {
> >         bool ret;
> >
> > diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> > index 9116bcc90346..33aa4df8fd82 100644
> > --- a/kernel/sched/core.c
> > +++ b/kernel/sched/core.c
> > @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
> >         }
> >  }
> >
> > -void preempt_count_add(int val)
> > +void __no_sanitize_memory preempt_count_add(int val)
> >  {
> >  #ifdef CONFIG_DEBUG_PREEMPT
> >         /*
> > @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
> >                 trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
> >  }
> >
> > -void preempt_count_sub(int val)
> > +void __no_sanitize_memory preempt_count_sub(int val)
> >  {
> >  #ifdef CONFIG_DEBUG_PREEMPT
> >
> >
> > --
> > Cheers,
> > Changbin Du

-- 
Cheers,
Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240311093036.44txy57hvhevybsu%40M910t.
