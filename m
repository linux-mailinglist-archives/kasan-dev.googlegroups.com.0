Return-Path: <kasan-dev+bncBAABBR6JXOXQMGQEYIGD3QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id BA84A877E8E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 12:02:33 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5c670f70a37sf4041722a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 04:02:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710154952; cv=pass;
        d=google.com; s=arc-20160816;
        b=VPVo3qaFTfk6WI5RxE4YoVP6pDp9kcZLqMk2Y2btpQ8EHzE2rtFyy3zMleuzFmb30V
         FhGQpWykJ6i2ChbeXIxwJaqWqhM4XqHP04cQTEH5oAufvHPoEd5f9ITwBzOzK9JW3tM2
         GoCu41yFc3CAh56zzJP2wMrziNX2P5vFMWyLF8GKlaDzIIDyiiJmb5d1QYnFYLFd1LNy
         7GRu0pNalRIu6gfCKFzo0WkDgROgH0HwRcBvYq4pLzVXwQODN3I46ZkzneQgye2K67/6
         F6Wjkduax7AomxawzcHhVsNF5HUO+WXOlk1TjV7qHZpzplwnHOCuGcB+wvQakqyqlCQE
         9GCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QheMp7xgev/Y7wY2lblQU8UiPSlRcZQcztTkfs7unKA=;
        fh=yF6W+59h0fZh2RIa18TZps/Q9zDzd2En6RchdhP9QSE=;
        b=ZTsvgSY2D5q+9Y6bNSt7cqHblzZFRl4dJxT7Ky/FJYyBwHvzyjpQd62RHlwWwmVujp
         BYYQY0SvwXc0aVo8tGjus3FejM9z8GsawEeVcDzWyYQaWe9yUnd347bNz0/eVoafdDdK
         XSyrXnwcK3LAUqVnmvY8NOe+z3Gtk/l3qTOKlPvwtyH3BdkyMxUPQFupOfZF0Y706RxY
         LDL14QLG5Or7128SbYel7aCSkkjNNur1HgbQdQiJ0UHRmFBkHQ+XtMve1dbsbYh3+7EJ
         XmT7qpfJj9goB4+xFF+rM2JANM7kIJQ2zxGklrRTRSBilgtmPXK1rCIwtTNHTOcOQDPb
         Ephw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710154952; x=1710759752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=QheMp7xgev/Y7wY2lblQU8UiPSlRcZQcztTkfs7unKA=;
        b=OTjn1ynUmG0fJElXFfA/2axkLB0tNERScurY6kW/AYTIBwfGpvSKeVUZAiemZNHe8K
         271Yb0tiMVyOGuD7wOAFakRJaGHNIG0xeBI+avYut6qMvG7hMeOydJgGkG/aoSCdhKtf
         ED9UD192o0JawnjKRQ05zpR3oCCKnrLa8VLifWRyqH5YTTIiBK5Xpb+8Gtz025L4W5nw
         7VLqURSRb5bu5mrH/7EvmzZlJt0c7GX3r+CZR3z+mmcKhOSE35KnBDf5C9bSJTHC/rG1
         t8Xyy1YP2mKyuDt3Cb+VMkZ9EFEiK3zRKrzDK9yM4dQVyW0TJUDDAY0eLKo6QBp1/Mpt
         Hsmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710154952; x=1710759752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QheMp7xgev/Y7wY2lblQU8UiPSlRcZQcztTkfs7unKA=;
        b=SUFn45ZlZ546Y1EV697Q0FGc5ay/Bgxhv56gMbDYyucyzldry4hjkLadOZcmrCgvRv
         NYs6fU/jrKHF0yuKlw1UgAz/hpw7Z1uoANMyVK2Nh29+P/VtihwLz6OQCVb1C+s8/d+W
         VtPEVY6JrewP0nksImP/XoIIn2k0GFkeyYjYNEfmK5BweqijDFGANKJOBh2qb/dRvOKy
         R1uMaUQMUPi+kBwfvtL57thmpus3QNr+YhNxyZBn2kx5bj4OcN+2BHdpdgNbPI08gQsB
         usrrRnnpBS/Z6nnb/KYg8NTFI44mB43ilnFns3bfCKRfpRHSPmIiv6n6dmc8OFhDp0wF
         f9xg==
X-Forwarded-Encrypted: i=2; AJvYcCVOtWUXI3XRUnFdapV5EiUD1ZKzEnVa36awfUaHisHNTTQEDBu+D1W7S7/S3Rfs6QWrQ/cFD0BaqGJ/qsPmJ//cjrfn6ozBWg==
X-Gm-Message-State: AOJu0Yzf0akJDTe6uCB1L+LhqCP08ifa9MaeC7veci58gLKjINnCb9jv
	4gYm07YdXoMK65cuuH49AA+HsO0jEqQewFQr/DOI0WN1eLc7Tv46
X-Google-Smtp-Source: AGHT+IG5yy7c1zf6sVnr1F/zmXEqd54ZAOw2eTxcKVMJmouu3umMsLVM+iO3BYzotlUVnrStK5cImw==
X-Received: by 2002:a17:90a:bd17:b0:29b:ecf0:c788 with SMTP id y23-20020a17090abd1700b0029becf0c788mr2358185pjr.4.1710154951843;
        Mon, 11 Mar 2024 04:02:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc2:b0:29b:64a2:4484 with SMTP id
 x2-20020a17090a0bc200b0029b64a24484ls2393861pjd.0.-pod-prod-08-us; Mon, 11
 Mar 2024 04:02:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnoHRyLQ8USEb+qWEUzaZ6X4d8ss/odlfUk5+avCxIOagKSiy7lyDHKLjDgNVbz2peqO029qkn70OXP553eq6gmnjAUIedgAxLXQ==
X-Received: by 2002:a05:6a21:339a:b0:1a0:df64:26c with SMTP id yy26-20020a056a21339a00b001a0df64026cmr8034998pzb.16.1710154950820;
        Mon, 11 Mar 2024 04:02:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710154950; cv=none;
        d=google.com; s=arc-20160816;
        b=dfeo3XNpd5wk+3ReYMv3uRRUurJn6EiOiINfIj5FFLiKquybUcw4nkfY1XJFdmUqtt
         LYxIekokm3fpoRY2hGNTcYUw4tSv2Ep+SizZud7yiIXZ2oB4szTAq0Ci8s8ZMGVTGp8/
         ETKGImX3wcwAdt4bB6cIpluSRUOO9wa4trolMT1Q9yIuJonoL7Mj5ZuxMlDUsHJiJ1CK
         CmG8aYVoETDr+iMEJv9TiVJI1GG3O5bo0lYzK+a/LQSpissuhGxNPH4gwc2oOaUOxrOX
         munGm+Sdt+SGMyALu7eNJO4ikxsNLe4K2BbVZlKB96GDYYbvAEPaTLL2qrz9cpmoO4Zr
         Jniw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=gcidNvystXJxtfC0sxmBbDb3AOrGrNTytJ4nsg3MVhA=;
        fh=FM0f/aovtzZ1X2zuxXrjPkln2HUFVXGHxTlEb0gOFHM=;
        b=gatexdmokxNnesbIcTuho2HxVNS1nye0lWwFMq2GJy/zvmSNRaaigeVSkXpE89fk9V
         /DX3RroaWbVvDg9AhxX960N8skJ+PzWPNpMb0QsdFvwXPiZ9fNYolUCwztSxzCENj3/S
         1poOCAsy5mDT9zuJfF1+Db7zunWjEyZUhjwuEOnIc2lBKbB8oZ0aWkb+9IY0LkguhXMK
         bLOuckvHZUAlKLUdpL3AeCJYIEc0fgeak96vQPzLjvzeX+eU2eBWyUZS4DIgLxjHkGJk
         631NKbKUsvJm/1kWw5eCm5XkkBMv3seaDeZoz5P/wO0KLXtoWDCZfGa1RY3O+0kpAjAL
         N6nw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id p8-20020a17090ab90800b0029bbd2c38d1si624300pjr.0.2024.03.11.04.02.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Mar 2024 04:02:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4TtYhm5LwNz1Q9Ws;
	Mon, 11 Mar 2024 19:00:24 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (unknown [7.221.188.204])
	by mail.maildlp.com (Postfix) with ESMTPS id 0484414040F;
	Mon, 11 Mar 2024 19:02:29 +0800 (CST)
Received: from M910t (10.110.54.157) by kwepemd100011.china.huawei.com
 (7.221.188.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.28; Mon, 11 Mar
 2024 19:02:28 +0800
Date: Mon, 11 Mar 2024 19:02:23 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>, Changbin Du <changbin.du@huawei.com>
CC: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [BUG] kmsan: instrumentation recursion problems
Message-ID: <20240311110223.nzsplk6a6lzxmzqi@M910t>
References: <20240308043448.masllzeqwht45d4j@M910t>
 <CANpmjNOc4Z6Qy_L3pjuW84BOxoiqXgLC1tWbJuZwRUZqs2ioMA@mail.gmail.com>
 <20240311093036.44txy57hvhevybsu@M910t>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240311093036.44txy57hvhevybsu@M910t>
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.255 as
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

On Mon, Mar 11, 2024 at 05:30:36PM +0800, Changbin Du wrote:
> On Fri, Mar 08, 2024 at 10:39:15AM +0100, Marco Elver wrote:
> > On Fri, 8 Mar 2024 at 05:36, 'Changbin Du' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Hey, folks,
> > > I found two instrumentation recursion issues on mainline kernel.
> > >
> > > 1. recur on preempt count.
> > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > >
> > > 2. recur in lockdep and rcu
> > > __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() -> pfn_valid() -> rcu_read_lock_sched() -> lock_acquire() -> rcu_is_watching() -> __msan_metadata_ptr_for_load_8()
> > >
> > >
> > > Here is an unofficial fix, I don't know if it will generate false reports.
> > >
> > > $ git show
> > > commit 7f0120b621c1cbb667822b0f7eb89f3c25868509 (HEAD -> master)
> > > Author: Changbin Du <changbin.du@huawei.com>
> > > Date:   Fri Mar 8 20:21:48 2024 +0800
> > >
> > >     kmsan: fix instrumentation recursions
> > >
> > >     Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > >
> > > diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> > > index 0db4093d17b8..ea925731fa40 100644
> > > --- a/kernel/locking/Makefile
> > > +++ b/kernel/locking/Makefile
> > > @@ -7,6 +7,7 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
> > >
> > >  # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> > >  KCSAN_SANITIZE_lockdep.o := n
> > > +KMSAN_SANITIZE_lockdep.o := n
> > 
> > This does not result in false positives?
> >
This does result lots of false positives.

> I saw a lot of reports but seems not related to this.
> 
> [    2.742743][    T0] BUG: KMSAN: uninit-value in unwind_next_frame+0x3729/0x48a0
> [    2.744404][    T0]  unwind_next_frame+0x3729/0x48a0
> [    2.745623][    T0]  arch_stack_walk+0x1d9/0x2a0
> [    2.746838][    T0]  stack_trace_save+0xb8/0x100
> [    2.747928][    T0]  set_track_prepare+0x88/0x120
> [    2.749095][    T0]  __alloc_object+0x602/0xbe0
> [    2.750200][    T0]  __create_object+0x3f/0x4e0
> [    2.751332][    T0]  pcpu_alloc+0x1e18/0x2b00
> [    2.752401][    T0]  mm_init+0x688/0xb20
> [    2.753436][    T0]  mm_alloc+0xf4/0x180
> [    2.754510][    T0]  poking_init+0x50/0x500
> [    2.755594][    T0]  start_kernel+0x3b0/0xbf0
> [    2.756724][    T0]  __pfx_reserve_bios_regions+0x0/0x10
> [    2.758073][    T0]  x86_64_start_kernel+0x92/0xa0
> [    2.759320][    T0]  secondary_startup_64_no_verify+0x176/0x17b
> 
Above reports are triggered by KMEMLEAK and KFENCE.

Now with below fix, I was able to run kmsan kernel with:
  CONFIG_DEBUG_KMEMLEAK=n
  CONFIG_KFENCE=n
  CONFIG_LOCKDEP=n

KMEMLEAK and KFENCE generate too many false positives in unwinding code.
LOCKDEP still introduces instrumenting recursions.

> 
> > Does
> > KMSAN_ENABLE_CHECKS_lockdep.o := n
> > work as well? If it does, that is preferred because it makes sure
> > there are no false positives if the lockdep code unpoisons data that
> > is passed and used outside lockdep.
> > 
> > lockdep has a serious impact on performance, and not sanitizing it
> > with KMSAN is probably a reasonable performance trade-off.
> > 
> Disabling checks is not working here. The recursion become this:
> 
> __msan_metadata_ptr_for_load_4() -> kmsan_get_metadata() -> virt_to_page_or_null() -> pfn_valid() -> lock_acquire() -> __msan_unpoison_alloca() -> kmsan_get_metadata()
> 
> > >  ifdef CONFIG_FUNCTION_TRACER
> > >  CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
> > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > index b2bccfd37c38..8935cc866e2d 100644
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -692,7 +692,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
> > >   * Make notrace because it can be called by the internal functions of
> > >   * ftrace, and making this notrace removes unnecessary recursion calls.
> > >   */
> > > -notrace bool rcu_is_watching(void)
> > > +notrace __no_sanitize_memory bool rcu_is_watching(void)
> > 
> > For all of these, does __no_kmsan_checks instead of __no_sanitize_memory work?
> > Again, __no_kmsan_checks (function-only counterpart to
> > KMSAN_ENABLE_CHECKS_.... := n) is preferred if it works as it avoids
> > any potential false positives that would be introduced by not
> > instrumenting.
> > 
> This works because it is not unpoisoning local variables.
> 
> > >  {
> > >         bool ret;
> > >
> > > diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> > > index 9116bcc90346..33aa4df8fd82 100644
> > > --- a/kernel/sched/core.c
> > > +++ b/kernel/sched/core.c
> > > @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
> > >         }
> > >  }
> > >
> > > -void preempt_count_add(int val)
> > > +void __no_sanitize_memory preempt_count_add(int val)
> > >  {
> > >  #ifdef CONFIG_DEBUG_PREEMPT
> > >         /*
> > > @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
> > >                 trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
> > >  }
> > >
> > > -void preempt_count_sub(int val)
> > > +void __no_sanitize_memory preempt_count_sub(int val)
> > >  {
> > >  #ifdef CONFIG_DEBUG_PREEMPT
> > >
> > >
> > > --
> > > Cheers,
> > > Changbin Du
> 
> -- 
> Cheers,
> Changbin Du

-- 
Cheers,
Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240311110223.nzsplk6a6lzxmzqi%40M910t.
