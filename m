Return-Path: <kasan-dev+bncBDDYJV4J2MORBT6EWX7AKGQEZBMHUFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 491E72D07CA
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 23:59:29 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id j128sf799349oif.22
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 14:59:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607295568; cv=pass;
        d=google.com; s=arc-20160816;
        b=mzOnop7AXckbVTduUrBf9TAfC9yTSa0Jnb5etTd/k9XuDNAxwLt2fewcIYBWKYPUAK
         H/F3xYKCf8A+ctW+iQkavLF6zNE2amiktGK/MBZBrWkfXAjMrmtfXPJ//ukzCuEm59TA
         1IP4U2rdH+EKNjh7v5Dj4t+stv+fnpL2XkCLZDFf0zpHbKIJL+dwJXxusBSKoovT+yrx
         YclZuN/hpyM52NLHsZqjlcULjUPbqDG7kdl6o8/fkYOOqEMDa7ISlphTEneE+ixTsLiG
         OsImdf7f1Z6Nj603SXqTLAl6gPDyrsq9c2JI4MRLFmPd5SW3b4WztG9MDITCUDoIbLgQ
         Q26Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=IRQ41der5+ITl4hsRkAYXyumeF/MNv0pM19VAy2r7t4=;
        b=tRnbazlEdofQkbzmBKBmh74jwBY5LhT5sE/hbdqoNw+Khhi25KQCVN3JUwQ+6Pa29L
         lxBZEoKFiebTD48lMhtxElNd6+9lWWuO9JoBCIbzYK5QA0zCd0ICdKe8dp0Vq/x01yqq
         pixSO85f80F++jbdkQa2I9bLBhwTmy0ngVFAe3hs/MZAJV0Nq98ngrTdOkSxJjVH4l2D
         UdgBFFNzP0k/UJTIthz+xjKBHDkYXwndLuxp+CR0Oi4KWlTtM257vpOw1LGXrFeWij+r
         Rgu1UxNMwpFm8rpcwIePI4msksHnyfWKJ817ZGdncxVHB9ZYhnL5jrwHWxwebpiDrTp1
         nFww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="rOYi/8c+";
       spf=pass (google.com: domain of richard.weinberger@gmail.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=richard.weinberger@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IRQ41der5+ITl4hsRkAYXyumeF/MNv0pM19VAy2r7t4=;
        b=AwezA6X1fMuei+VplzXhiZTHG1JHGBLk0PxpRdh8mXBFf00XI3Y2/JFY5qp2JkVgRv
         3Kxw3olzcmAkwGnaKPL6AOnW/Nl5zySxQ864QJAQwhJSGxG8xqVOWGAvB3sKBoal8t39
         k54JtVo405ncPueQqavvEjij4Q2Ls+NZ5KhIZJl17az6RftCogE4PgTc9WBQS3VgjU54
         aC1BzyLnnOqd29xMTwK1HahOgI1cjJ/YbuMaXs0mR6yt1yoLhuGRYH5CDfUminwSVOGv
         tqdFcOTzwLvI3EM1+3cnROUoayGTYvEY066f0Y1qp6nqoFnWZ4DucXlO+hkQ87Tlyfz1
         iUtQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IRQ41der5+ITl4hsRkAYXyumeF/MNv0pM19VAy2r7t4=;
        b=T2ATzttSltMw04gS1Rq4kCtjkEJzHZ4vjVkq2oc3aBEYeCx+wwfHHFbS9nOhaovdEu
         0zeYYVSZOjwYK5vQuiPc6sVyZZRdB26edph4zhHBTijMoxFmUBkk44hzppxj1v3gTCpj
         9OTdgGt1wIIQyFEYaDPaQ/LdIcY9N4nRJxl+RkHq2EAkJ9z6FDti2GTVdOG32B3dGNUX
         X/zqv/os8kQX1KIa2dRcwfTzBmkOARGkyU+0mFhGVNE2C/UW+GtG8nduURbJu05UuiRS
         zo8PZH48GBA1j3HAX5csNtA0lmFJxny0/n181bWX9XkSag9NMQomQ7Qle5bwNshkQA+C
         UZgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IRQ41der5+ITl4hsRkAYXyumeF/MNv0pM19VAy2r7t4=;
        b=FlB6BfqrQpCbE+Pg1VUo5pZs4kMqfbTR3BY0KNU4L4Y2M31ASfurcknzIT9mhVB2+9
         re5XQn6XTBMofZWM85faQySGjtqDcKZBvwIIoad5ZTNUicDI8uCGjfkNjbWoGvInrBqV
         Xbf2vNdAQTH1hMZc3CsSGyon+x6mxQG7n+/WGi/b+6w27rg7g6HAo8j1eTLEIhzNP8/q
         Kb+E8Ci6RuDrgqgWvrq+MrvKBaNiug8jmdZ1RswOu0Elm32YyTMcCJHjF4qY1kCyB6QP
         IwcddBgSdxYbkdx/nC3haZ80WMy3RTON7A2JRf6ZctyLXN1XzABTFefnvGpkMRlIGz6Z
         RWCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RajU3bir7RFXkeyDt527EK3ES+/2kJ8VGtJ+T1p5BjvEtBj+b
	Lnhj7AqFdP/ThkRkBFg2N/0=
X-Google-Smtp-Source: ABdhPJy53hko2kFFDLvYUAK7evoxr+bb7BesGXHOXhKBejSZjDKSNND8HzsQu6tOzrsw0ZOwzwbVSQ==
X-Received: by 2002:a4a:9589:: with SMTP id o9mr10575043ooi.59.1607295568041;
        Sun, 06 Dec 2020 14:59:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:24b0:: with SMTP id v16ls971513ots.10.gmail; Sun,
 06 Dec 2020 14:59:27 -0800 (PST)
X-Received: by 2002:a9d:3e82:: with SMTP id b2mr2298934otc.329.1607295567696;
        Sun, 06 Dec 2020 14:59:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607295567; cv=none;
        d=google.com; s=arc-20160816;
        b=HLgzsaJTd2gsUwgVD5KVWSSHkohKCBbuXMD+oT0mAfwrEVcgRI0+59THQOK31J3sls
         XjPROKh/Woz8o/pNKPt57SQK3gFsDv1embBR0wFHY2fT3Ko766uTtIuA4PvbZqr/+1W1
         dmN/YhCyCaHDCGKTnM64hHkgVlcwyZ3JvHgf8Yp7kp3pw5Arbh10pmpDzvoFmRA4gbNc
         hlSDZ9Up0aGRszOgXgRnNLVxZh8AXOK12WQIwiWIyBY+FwTOadNAg7QrWkRgEG347Z/P
         6bddOljFfUYA2Bu/o4L3SdU7APx9bt4yBnmBa0YEX8Sb+ejRUvpyJ2v9Wl1J93yVLWDo
         tZ8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=vv6iFUqkL94sPwQ2xC06XNtvXitukry4+NVPo/3bk+o=;
        b=Hea4lHIVqWnyETlOqrR17vEPYhElr7E4Fws6aPf7CMAkBL8HLqCQZC2kQR2id5jv0h
         5PVGkps/L5giM6QfqnhHQe1Fph1IaI83hN9qW/QoP36Ko4ywkFaYd4c53AE7m9lkDCL/
         GVpWieeY9scKNhCKyQbDAO4pxo2M76sK2mLEdI3bj3SJ++w1rmdAJjKsAerMG+kiRckz
         iOC0ZEE14jJkRsc7gWENILvIV7+kJUMSr2o25uyPv5OTSjdMhB/pX/PgkqQ34K8Sk3FW
         Gmde87aouFObAPyncnYlE+CJrTyWuVlYcxNwx/FRLTDNdt3r8GeNI3tvJ9t5X63e6zWa
         XCdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="rOYi/8c+";
       spf=pass (google.com: domain of richard.weinberger@gmail.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=richard.weinberger@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id m13si1012125otn.1.2020.12.06.14.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Dec 2020 14:59:27 -0800 (PST)
Received-SPF: pass (google.com: domain of richard.weinberger@gmail.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id g19so5697882qvy.2
        for <kasan-dev@googlegroups.com>; Sun, 06 Dec 2020 14:59:27 -0800 (PST)
X-Received: by 2002:a05:6214:114f:: with SMTP id b15mr17948421qvt.34.1607295567389;
 Sun, 06 Dec 2020 14:59:27 -0800 (PST)
MIME-Version: 1.0
From: Richard Weinberger <richard.weinberger@gmail.com>
Date: Sun, 6 Dec 2020 23:59:16 +0100
Message-ID: <CAFLxGvwienJ7sU2+QAhFt+ywS9iYkbAXDGviuTC-4CVwLOhXfA@mail.gmail.com>
Subject: BUG: Invalid wait context with KMEMLEAK and KASAN enabled
To: LKML <linux-kernel@vger.kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, aryabinin@virtuozzo.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: richard.weinberger@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="rOYi/8c+";       spf=pass
 (google.com: domain of richard.weinberger@gmail.com designates
 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=richard.weinberger@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi!

With both KMEMLEAK and KASAN enabled, I'm facing the following lockdep
splat at random times on Linus' tree as of today.
Sometimes it happens at bootup, sometimes much later when userspace has started.

Does this ring a bell?

[    2.298447] =============================
[    2.298971] [ BUG: Invalid wait context ]
[    2.298971] 5.10.0-rc6+ #388 Not tainted
[    2.298971] -----------------------------
[    2.298971] ksoftirqd/1/15 is trying to lock:
[    2.298971] ffff888100b94598 (&n->list_lock){....}-{3:3}, at:
free_debug_processing+0x3d/0x210
[    2.298971] other info that might help us debug this:
[    2.298971] context-{2:2}
[    2.298971] 1 lock held by ksoftirqd/1/15:
[    2.298971]  #0: ffffffff835f4140 (rcu_callback){....}-{0:0}, at:
rcu_core+0x408/0x1040
[    2.298971] stack backtrace:
[    2.298971] CPU: 1 PID: 15 Comm: ksoftirqd/1 Not tainted 5.10.0-rc6+ #388
[    2.298971] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS rel-1.12.0-0-ga698c89-rebuilt.opensuse.org 04/01/2014
[    2.298971] Call Trace:
[    2.298971]  <IRQ>
[    2.298971]  dump_stack+0x9a/0xcc
[    2.298971]  __lock_acquire.cold+0xce/0x34b
[    2.298971]  ? lockdep_hardirqs_on_prepare+0x1f0/0x1f0
[    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
[    2.298971]  lock_acquire+0x153/0x4c0
[    2.298971]  ? free_debug_processing+0x3d/0x210
[    2.298971]  ? lock_release+0x690/0x690
[    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
[    2.298971]  ? pvclock_clocksource_read+0xd9/0x1a0
[    2.298971]  _raw_spin_lock_irqsave+0x3b/0x80
[    2.298971]  ? free_debug_processing+0x3d/0x210
[    2.298971]  ? qlist_free_all+0x35/0xd0
[    2.298971]  free_debug_processing+0x3d/0x210
[    2.298971]  __slab_free+0x286/0x490
[    2.298971]  ? lockdep_enabled+0x39/0x50
[    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
[    2.298971]  ? run_posix_cpu_timers+0x256/0x2c0
[    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
[    2.298971]  ? posix_cpu_timers_exit_group+0x30/0x30
[    2.298971]  qlist_free_all+0x59/0xd0
[    2.298971]  ? qlist_free_all+0xd0/0xd0
[    2.298971]  per_cpu_remove_cache+0x47/0x50
[    2.298971]  flush_smp_call_function_queue+0xea/0x2b0
[    2.298971]  __sysvec_call_function+0x6c/0x250
[    2.298971]  asm_call_irq_on_stack+0x12/0x20
[    2.298971]  </IRQ>
[    2.298971]  sysvec_call_function+0x84/0xa0
[    2.298971]  asm_sysvec_call_function+0x12/0x20
[    2.298971] RIP: 0010:__asan_load4+0x1d/0x80
[    2.298971] Code: 10 00 75 ee c3 0f 1f 84 00 00 00 00 00 4c 8b 04
24 48 83 ff fb 77 4d 48 b8 ff ff ff ff ff 7f ff ff 48 39 c7 76 3e 48
8d 47 03 <48> 89 c2 83 e2 07 48 83 fa 02 76 17 48 b9 00 00 00 00 00 fc
ff df
[    2.298971] RSP: 0000:ffff888100e4f858 EFLAGS: 00000216
[    2.298971] RAX: ffffffff83c55773 RBX: ffffffff81002431 RCX: dffffc0000000000
[    2.298971] RDX: 0000000000000001 RSI: ffffffff83ee8d78 RDI: ffffffff83c55770
[    2.298971] RBP: ffffffff83c5576c R08: ffffffff81083433 R09: fffffbfff07e333d
[    2.298971] R10: 000000000001803d R11: fffffbfff07e333c R12: ffffffff83c5575c
[    2.298971] R13: ffffffff83c55774 R14: ffffffff83c55770 R15: ffffffff83c55770
[    2.298971]  ? ret_from_fork+0x21/0x30
[    2.298971]  ? __orc_find+0x63/0xc0
[    2.298971]  ? stack_access_ok+0x35/0x90
[    2.298971]  __orc_find+0x63/0xc0
[    2.298971]  unwind_next_frame+0x1ee/0xbd0
[    2.298971]  ? ret_from_fork+0x22/0x30
[    2.298971]  ? ret_from_fork+0x21/0x30
[    2.298971]  ? deref_stack_reg+0x40/0x40
[    2.298971]  ? __unwind_start+0x2e8/0x370
[    2.298971]  ? create_prof_cpu_mask+0x20/0x20
[    2.298971]  arch_stack_walk+0x83/0xf0
[    2.298971]  ? ret_from_fork+0x22/0x30
[    2.298971]  ? rcu_core+0x488/0x1040
[    2.298971]  stack_trace_save+0x8c/0xc0
[    2.298971]  ? stack_trace_consume_entry+0x80/0x80
[    2.298971]  ? sched_clock_local+0x99/0xc0
[    2.298971]  kasan_save_stack+0x1b/0x40
[    2.298971]  ? kasan_save_stack+0x1b/0x40
[    2.298971]  ? kasan_set_track+0x1c/0x30
[    2.298971]  ? kasan_set_free_info+0x1b/0x30
[    2.298971]  ? __kasan_slab_free+0x10f/0x150
[    2.298971]  ? kmem_cache_free+0xa8/0x350
[    2.298971]  ? rcu_core+0x488/0x1040
[    2.298971]  ? __do_softirq+0x101/0x573
[    2.298971]  ? run_ksoftirqd+0x21/0x50
[    2.298971]  ? smpboot_thread_fn+0x1fc/0x380
[    2.298971]  ? kthread+0x1c7/0x220
[    2.298971]  ? ret_from_fork+0x22/0x30
[    2.298971]  ? lockdep_hardirqs_on_prepare+0x1f0/0x1f0
[    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
[    2.298971]  ? lock_acquire+0x153/0x4c0
[    2.298971]  ? rcu_core+0x408/0x1040
[    2.298971]  ? lock_release+0x690/0x690
[    2.298971]  ? lockdep_enabled+0x39/0x50
[    2.298971]  ? mark_held_locks+0x49/0x90
[    2.298971]  kasan_set_track+0x1c/0x30
[    2.298971]  kasan_set_free_info+0x1b/0x30
[    2.298971]  __kasan_slab_free+0x10f/0x150
[    2.298971]  ? rcu_core+0x488/0x1040
[    2.298971]  kmem_cache_free+0xa8/0x350
[    2.298971]  ? __ia32_compat_sys_move_pages+0x130/0x130
[    2.298971]  rcu_core+0x488/0x1040
[    2.298971]  ? call_rcu+0x5d0/0x5d0
[    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
[    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
[    2.298971]  __do_softirq+0x101/0x573
[    2.298971]  ? trace_event_raw_event_irq_handler_exit+0x150/0x150
[    2.298971]  run_ksoftirqd+0x21/0x50
[    2.298971]  smpboot_thread_fn+0x1fc/0x380
[    2.298971]  ? smpboot_register_percpu_thread+0x180/0x180
[    2.298971]  ? __kthread_parkme+0xbb/0xd0
[    2.298971]  ? smpboot_register_percpu_thread+0x180/0x180
[    2.298971]  kthread+0x1c7/0x220
[    2.298971]  ? kthread_create_on_node+0xd0/0xd0
[    2.298971]  ret_from_fork+0x22/0x30

-- 
Thanks,
//richard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFLxGvwienJ7sU2%2BQAhFt%2BywS9iYkbAXDGviuTC-4CVwLOhXfA%40mail.gmail.com.
