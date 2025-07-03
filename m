Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBEEPTPBQMGQEAB37ULI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 043DAAF7F9A
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 20:10:26 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6fabb9286f9sf1665946d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 11:10:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751566224; cv=pass;
        d=google.com; s=arc-20240605;
        b=kB1QokmQuMJizQ2cPfd9jty8k45VQQRb8SbeL7u8TDg77pOdqttO+Xeo7L2k0psvzX
         ChqKvmnBM/VbvuXXaNqoAT+RB9DqUUbMs65PUxB1gn8hajVWB6x9WLXODsxNAMrLP1P0
         UDoqa4UdqF/pcCFFa3fAwO3G/Ju9Wi+tfYQ4tzb1dxLKbvANddcAWvDUeslNCrQPJPmU
         3LEG9b+oc1q8hORQs2KxCzfaKayEq8dQqtVUxAk32JJNsnXeZhhL717o4NHPrbzYbO0D
         npBZLvuPqnJwyJnmSHlXmjqJTBsNfjdJeSLn2xz9a74oUbWvTIbE33ENFFsWgR5YqfF8
         nSRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7iozdXTytf9811hF5Tz36khM1kGtBfHixDjn7tEDmHg=;
        fh=V80ZY5ycMvo0chpV6Vk6ByK0uwNsMgBkPmmDqiuHEfg=;
        b=VwDf8VlEM12gElHAgPXgkHiTF3W5KYU6E5OOD3rOnxBeVPaopzaMQevDdNcAbM6epE
         4IjrSloS8TmTxdhKy82KEU83xr2IYWBg5J92OHzCj3+FVgmO3EsCRsG8bB7wtTykwihD
         CYjYZwmmLQD4N4yPDOAP+DinN7xluYkxocukQ9AbaZUjfToBzh1pjxjnsGaWTVvVg5MT
         qdmaZ0u7tPnbV9x48xMFz1FEvksCIskbeLwDp+rfAMB2MMdwXfxi+onz3SoU9O7lVsj5
         dVSlE+hE9NCXdz1SkAEiDM0HfyETSmollzLrHcXkUn5QF1GqdDOxQomHzA7k7GIPK9mn
         z4Gw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751566224; x=1752171024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7iozdXTytf9811hF5Tz36khM1kGtBfHixDjn7tEDmHg=;
        b=ij9boSH7rueQqhasY4Mjdqbq5rIzY78/ngN0PV0yagCdvWuP7axEfbwrBTzPEgfnzU
         pIJYr8hOFrqPbfxE54y30UaockF3Jrz+AUXOfhe3C/8YITauRdtDm5Xg7PHVrj48uWR/
         Xk9l30MmBHnxdew0zz15U055tB+rCLHH2FV8glEd5z/IttnoeLyMgIccTLZdjV8wG3Xz
         GdblSgyQS6MmpjykzbTlyqTGPsMjx3/9PcffT1uulicba8LRMZGglovc63VIV+WCtviH
         5csfape5WJ0ejsB3tS5tAm/5VHzj6z+ONDpaLa1PudJNi/D48JiVS9SRgUj2Goz6/yRg
         KPiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751566224; x=1752171024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7iozdXTytf9811hF5Tz36khM1kGtBfHixDjn7tEDmHg=;
        b=N3twsXnrG9DKW2IbQneuxm5s+9qX1LI36YgksK2qL+ERABSGWHbskO45BQdpkYzQSl
         bqWtsMW65c77mBYmpQf39EE1nIlZEo2LnsDaGUbXicCaGtpvqym87p3RYgObIB6PA0yr
         JLpbim4YnnPt2EnPU0S3sM43Z8XBR5eHfrtYFrOgbKBEYsG9j9nGgUYTHwBVM/7OGhcF
         FGlZ7iLL/LfGtagLxPEj0gZgSUM5ugC3bFxMIQBv3X+3k2vLNzgYtcmN9IvkjjZ8XGg0
         lWDW4LTl/bsUkwNbkRgiCuZwTnmlNnN3YrIsaWsO+Y9WjiHMl5iMW+XtN0yr0KhGCIvf
         oR8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVG4EWQAILcqAV6WgFQwHbn9ox7wcIuM8l2zSh7k7RYhBHy21TqopW2B8F95o0yxdlr9RepSw==@lfdr.de
X-Gm-Message-State: AOJu0Yz46SWfDxOeZD7HbWASTbhz39k37/GgX4XGQzWjKAXM4MzlXPwf
	13JdBrCbqEQNjBT/VuxkXR42sQwCa2t/Q1fgiQjqOQeXstla55Tc44EQ
X-Google-Smtp-Source: AGHT+IE/O/Q5NSMB8XcQVgNzacm/PS8bdN7/e5avosAQmozy8ERy3QVZH0DUigzZVFCISX7iWZZb2Q==
X-Received: by 2002:ad4:5f0c:0:b0:6fa:c6e6:11f9 with SMTP id 6a1803df08f44-702b1a5562amr122868996d6.11.1751566224601;
        Thu, 03 Jul 2025 11:10:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZepWF2JWcz5aDEKBeIriM/4JSSp9UMakKPv2VVOgBBifQ==
Received: by 2002:ad4:5ce4:0:b0:6fa:c598:5a6e with SMTP id 6a1803df08f44-702c41f20d3ls4310156d6.1.-pod-prod-09-us;
 Thu, 03 Jul 2025 11:10:23 -0700 (PDT)
X-Received: by 2002:a05:6122:82aa:b0:531:2906:7519 with SMTP id 71dfb90a1353d-5345813a00fmr7307725e0c.5.1751566223711;
        Thu, 03 Jul 2025 11:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751566223; cv=none;
        d=google.com; s=arc-20240605;
        b=f5h71yZlVBGvnMnkEP9/U3M20cVlDdjCRXZa50+ffFGi1StT0lhH8Srz3gcvQfj2Di
         DBV8OOz4QnFbgfDgcytCKYhbXNzNtdsL6Rav6UyicrAQgjWZPsoodiVRNTmi8Pq+iAte
         VE4vGmQlQCuk3JSfSwty76lsnlkNb3kcN0mV9Nu8GpLMZreiK+spBiZXPSLC5HBU0ryV
         P84F/3bSLqSJSguuNjM1nbwB2rsvObgX6HGhYjsHX4bYCAL/xpOtu2tTqg9X//aoMKFO
         MmOGdaGiGME8oMpWAOWSRGThHxfLeLJYjUR+sgm11iHA+7mvogDSTp+wGnQVb8RMVqqd
         Mj7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=lolusLIRzLYiZalFfpTvpoQ12F50EzzSc7AByuCxmeA=;
        fh=QbBFtt5fh3EATTIqGE7Tg/BKKusxMPT1E+TbM0lHoJY=;
        b=SovGzQHnB/QO09kGV9nORr2R8uHVXinjGYebqOYU/gzo0UGF/Iwcmd7Wur3iQqBJx6
         e9pzoQ5x1Wq5M/cai2ajS1sAfTGGbJmRWzlITeVDA91G/XhXvERditeSBGgGCDFT03l3
         yrnsELp+CZEOcUNoH8neUfBM8sa5qN57UVHvObxTsbZyfhEg/wocn4wUt+ysw/RqmrR+
         T9fEyP6cqJScjFv32zucgR4s5lkd16j4kuwlZi3E13S7L70wuaPISQ5PNdPTiq43l0/p
         94fbG4U5XX4+Oym4PsIX1+BeR/W7T4sIkLeOeX4gG0lGuphKG8RtiqEeaP2tXkLvy9zK
         l4lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-53479025791si6479e0c.3.2025.07.03.11.10.23
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Jul 2025 11:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7DA3E106F;
	Thu,  3 Jul 2025 11:10:08 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 889C33F66E;
	Thu,  3 Jul 2025 11:10:20 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	bigeasy@linutronix.de,
	clrkwllms@kernel.org,
	rostedt@goodmis.org,
	byungchul@sk.com,
	max.byungchul.park@gmail.com,
	ysk@kzalloc.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-rt-devel@lists.linux.dev,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock
Date: Thu,  3 Jul 2025 19:10:18 +0100
Message-Id: <20250703181018.580833-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

find_vm_area() couldn't be called in atomic_context.
If find_vm_area() is called to reports vm area information,
kasan can trigger deadlock like:

CPU0                                CPU1
vmalloc();
 alloc_vmap_area();
  spin_lock(&vn->busy.lock)
                                    spin_lock_bh(&some_lock);
   <interrupt occurs>
   <in softirq>
   spin_lock(&some_lock);
                                    <access invalid address>
                                    kasan_report();
                                     print_report();
                                      print_address_description();
                                       kasan_find_vm_area();
                                        find_vm_area();
                                         spin_lock(&vn->busy.lock) // deadlock!

To prevent possible deadlock while kasan reports, remove kasan_find_vm_area().

Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
Reported-by: Yunseong Kim <ysk@kzalloc.com>
Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---

Patch History
===============
From v1 to v2:
  - remove kasan_find_vm_area()
  - v1: https://lore.kernel.org/all/20250701203545.216719-1-yeoreum.yun@arm.com/

NOTE
===============
Below report is from Yunseong Kim using DEPT:

===================================================
DEPT: Circular dependency has been detected.
6.15.0-rc6-00043-ga83a69ec7f9f #5 Not tainted
---------------------------------------------------
summary
---------------------------------------------------
*** DEADLOCK ***

context A
   [S] lock(report_lock:0)
   [W] lock(&vn->busy.lock:0)
   [E] unlock(report_lock:0)

context B
   [S] lock(&tb->tb6_lock:0)
   [W] lock(report_lock:0)
   [E] unlock(&tb->tb6_lock:0)

context C
   [S] write_lock(&ndev->lock:0)
   [W] lock(&tb->tb6_lock:0)
   [E] write_unlock(&ndev->lock:0)

context D
   [S] lock(&vn->busy.lock:0)
   [W] write_lock(&ndev->lock:0)
   [E] unlock(&vn->busy.lock:0)

[S]: start of the event context
[W]: the wait blocked
[E]: the event not reachable
---------------------------------------------------
context A's detail
---------------------------------------------------
context A
   [S] lock(report_lock:0)
   [W] lock(&vn->busy.lock:0)
   [E] unlock(report_lock:0)

[S] lock(report_lock:0):
[<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
[<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
stacktrace:
      __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
      _raw_spin_lock_irqsave+0x88/0xd8 kernel/locking/spinlock.c:162
      start_report mm/kasan/report.c:215 [inline]
      kasan_report+0x74/0x1d4 mm/kasan/report.c:623
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176

[W] lock(&vn->busy.lock:0):
[<ffff800080ae57a0>] spin_lock include/linux/spinlock.h:351 [inline]
[<ffff800080ae57a0>] find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
stacktrace:
      spin_lock include/linux/spinlock.h:351 [inline]
      find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
      find_vm_area+0x20/0x68 mm/vmalloc.c:3208
      kasan_find_vm_area mm/kasan/report.c:398 [inline]
      print_address_description mm/kasan/report.c:432 [inline]
      print_report+0x3d8/0x54c mm/kasan/report.c:521
      kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85

[E] unlock(report_lock:0):
(N/A)
---------------------------------------------------
context B's detail
---------------------------------------------------
context B
   [S] lock(&tb->tb6_lock:0)
   [W] lock(report_lock:0)
   [E] unlock(&tb->tb6_lock:0)

[S] lock(&tb->tb6_lock:0):
[<ffff80008a172d10>] spin_lock_bh include/linux/spinlock.h:356 [inline]
[<ffff80008a172d10>] __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
stacktrace:
      __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
      _raw_spin_lock_bh+0x80/0xd0 kernel/locking/spinlock.c:178
      spin_lock_bh include/linux/spinlock.h:356 [inline]
      __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      dev_close_many+0x290/0x4b8 net/core/dev.c:1731
      unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
      unregister_netdevice_many net/core/dev.c:12034 [inline]
      unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
      unregister_netdevice include/linux/netdevice.h:3374 [inline]
      __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
      tun_detach drivers/net/tun.c:636 [inline]
      tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
      __fput+0x374/0xa30 fs/file_table.c:465
      ____fput+0x20/0x3c fs/file_table.c:493

[W] lock(report_lock:0):
[<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
[<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
stacktrace:
      __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
      _raw_spin_lock_irqsave+0x6c/0xd8 kernel/locking/spinlock.c:162
      start_report mm/kasan/report.c:215 [inline]
      kasan_report+0x74/0x1d4 mm/kasan/report.c:623
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176

[E] unlock(&tb->tb6_lock:0):
(N/A)
---------------------------------------------------
context C's detail
---------------------------------------------------
context C
   [S] write_lock(&ndev->lock:0)
   [W] lock(&tb->tb6_lock:0)
   [E] write_unlock(&ndev->lock:0)

[S] write_lock(&ndev->lock:0):
[<ffff80008a133bd8>] addrconf_permanent_addr net/ipv6/addrconf.c:3622 [inline]
[<ffff80008a133bd8>] addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:3698
stacktrace:
      __raw_write_lock_bh include/linux/rwlock_api_smp.h:202 [inline]
      _raw_write_lock_bh+0x88/0xd4 kernel/locking/spinlock.c:334
      addrconf_permanent_addr net/ipv6/addrconf.c:3622 [inline]
      addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:3698
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
      netif_change_flags+0x108/0x160 net/core/dev.c:9422
      do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
      rtnl_changelink net/core/rtnetlink.c:3769 [inline]
      __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
      rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
      rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
      netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
      rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
      netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
      netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
      netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883
      sock_sendmsg_nosec net/socket.c:712 [inline]
      __sock_sendmsg+0xe0/0x1a0 net/socket.c:727
      __sys_sendto+0x238/0x2fc net/socket.c:2180

[W] lock(&tb->tb6_lock:0):
[<ffff80008a1643fc>] spin_lock_bh include/linux/spinlock.h:356 [inline]
[<ffff80008a1643fc>] __ip6_ins_rt net/ipv6/route.c:1350 [inline]
[<ffff80008a1643fc>] ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
stacktrace:
      __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
      _raw_spin_lock_bh+0x5c/0xd0 kernel/locking/spinlock.c:178
      spin_lock_bh include/linux/spinlock.h:356 [inline]
      __ip6_ins_rt net/ipv6/route.c:1350 [inline]
      ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
      addrconf_prefix_route+0x28c/0x494 net/ipv6/addrconf.c:2487
      fixup_permanent_addr net/ipv6/addrconf.c:3602 [inline]
      addrconf_permanent_addr net/ipv6/addrconf.c:3626 [inline]
      addrconf_notify+0xfd0/0x1688 net/ipv6/addrconf.c:3698
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
      netif_change_flags+0x108/0x160 net/core/dev.c:9422
      do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
      rtnl_changelink net/core/rtnetlink.c:3769 [inline]
      __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
      rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
      rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
      netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
      rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
      netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
      netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
      netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883

[E] write_unlock(&ndev->lock:0):
(N/A)
---------------------------------------------------
context D's detail
---------------------------------------------------
context D
   [S] lock(&vn->busy.lock:0)
   [W] write_lock(&ndev->lock:0)
   [E] unlock(&vn->busy.lock:0)

[S] lock(&vn->busy.lock:0):
[<ffff800080adcf80>] spin_lock include/linux/spinlock.h:351 [inline]
[<ffff800080adcf80>] alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
stacktrace:
      __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
      _raw_spin_lock+0x78/0xc0 kernel/locking/spinlock.c:154
      spin_lock include/linux/spinlock.h:351 [inline]
      alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
      __get_vm_area_node+0x1c8/0x360 mm/vmalloc.c:3138
      __vmalloc_node_range_noprof+0x168/0x10d4 mm/vmalloc.c:3805
      __vmalloc_node_noprof+0x130/0x178 mm/vmalloc.c:3908
      vzalloc_noprof+0x3c/0x54 mm/vmalloc.c:3981
      alloc_counters net/ipv6/netfilter/ip6_tables.c:815 [inline]
      copy_entries_to_user net/ipv6/netfilter/ip6_tables.c:837 [inline]
      get_entries net/ipv6/netfilter/ip6_tables.c:1039 [inline]
      do_ip6t_get_ctl+0x520/0xad0 net/ipv6/netfilter/ip6_tables.c:1677
      nf_getsockopt+0x8c/0x10c net/netfilter/nf_sockopt.c:116
      ipv6_getsockopt+0x24c/0x460 net/ipv6/ipv6_sockglue.c:1493
      tcp_getsockopt+0x98/0x120 net/ipv4/tcp.c:4727
      sock_common_getsockopt+0x9c/0xcc net/core/sock.c:3867
      do_sock_getsockopt+0x308/0x57c net/socket.c:2357
      __sys_getsockopt+0xec/0x188 net/socket.c:2386
      __do_sys_getsockopt net/socket.c:2393 [inline]
      __se_sys_getsockopt net/socket.c:2390 [inline]
      __arm64_sys_getsockopt+0xa8/0x110 net/socket.c:2390
      __invoke_syscall arch/arm64/kernel/syscall.c:36 [inline]
      invoke_syscall+0x88/0x2e0 arch/arm64/kernel/syscall.c:50
      el0_svc_common.constprop.0+0xe8/0x2e0 arch/arm64/kernel/syscall.c:139

[W] write_lock(&ndev->lock:0):
[<ffff80008a127f20>] addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:4025
stacktrace:
      __raw_write_lock include/linux/rwlock_api_smp.h:209 [inline]
      _raw_write_lock+0x5c/0xd0 kernel/locking/spinlock.c:300
      addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:4025
      call_timer_fn+0x204/0x964 kernel/time/timer.c:1789
      expire_timers kernel/time/timer.c:1840 [inline]
      __run_timers+0x830/0xb00 kernel/time/timer.c:2414
      __run_timer_base kernel/time/timer.c:2426 [inline]
      __run_timer_base kernel/time/timer.c:2418 [inline]
      run_timer_base+0x124/0x198 kernel/time/timer.c:2435
      run_timer_softirq+0x20/0x58 kernel/time/timer.c:2445
      handle_softirqs+0x30c/0xdc0 kernel/softirq.c:579
      __do_softirq+0x14/0x20 kernel/softirq.c:613
      ____do_softirq+0x14/0x20 arch/arm64/kernel/irq.c:81
      call_on_irq_stack+0x24/0x30 arch/arm64/kernel/entry.S:891
      do_softirq_own_stack+0x20/0x40 arch/arm64/kernel/irq.c:86
      invoke_softirq kernel/softirq.c:460 [inline]
      __irq_exit_rcu+0x400/0x560 kernel/softirq.c:680
      irq_exit_rcu+0x14/0x80 kernel/softirq.c:696
      __el1_irq arch/arm64/kernel/entry-common.c:561 [inline]
      el1_interrupt+0x38/0x54 arch/arm64/kernel/entry-common.c:575
      el1h_64_irq_handler+0x18/0x24 arch/arm64/kernel/entry-common.c:580
      el1h_64_irq+0x6c/0x70 arch/arm64/kernel/entry.S:596

[E] unlock(&vn->busy.lock:0):
(N/A)
---------------------------------------------------
information that might be helpful
---------------------------------------------------
CPU: 1 UID: 0 PID: 19536 Comm: syz.4.2592 Not tainted 6.15.0-rc6-00043-ga83a69ec7f9f #5 PREEMPT
Hardware name: QEMU KVM Virtual Machine, BIOS 2025.02-8 05/13/2025
Call trace:
 dump_backtrace arch/arm64/kernel/stacktrace.c:449 [inline] (C)
 show_stack+0x34/0x80 arch/arm64/kernel/stacktrace.c:466 (C)
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x104/0x180 lib/dump_stack.c:120
 dump_stack+0x20/0x2c lib/dump_stack.c:129
 print_circle kernel/dependency/dept.c:928 [inline]
 cb_check_dl kernel/dependency/dept.c:1362 [inline]
 cb_check_dl+0x1080/0x10ec kernel/dependency/dept.c:1356
 bfs+0x4d8/0x630 kernel/dependency/dept.c:980
 check_dl_bfs kernel/dependency/dept.c:1381 [inline]
 add_dep+0x1cc/0x364 kernel/dependency/dept.c:1710
 add_wait kernel/dependency/dept.c:1829 [inline]
 __dept_wait+0x60c/0x16e0 kernel/dependency/dept.c:2585
 dept_wait kernel/dependency/dept.c:2666 [inline]
 dept_wait+0x168/0x1a8 kernel/dependency/dept.c:2640
 __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
 _raw_spin_lock+0x54/0xc0 kernel/locking/spinlock.c:154
 spin_lock include/linux/spinlock.h:351 [inline]
 find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
 find_vm_area+0x20/0x68 mm/vmalloc.c:3208
 kasan_find_vm_area mm/kasan/report.c:398 [inline]
 print_address_description mm/kasan/report.c:432 [inline]
 print_report+0x3d8/0x54c mm/kasan/report.c:521
 kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
 __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
 fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
 fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
 fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
 fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
 fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
 __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
 fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
 rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
 rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
 addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
 addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
 notifier_call_chain+0x94/0x50c kernel/notifier.c:85
 raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
 call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
 call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
 call_netdevice_notifiers net/core/dev.c:2228 [inline]
 dev_close_many+0x290/0x4b8 net/core/dev.c:1731
 unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
 unregister_netdevice_many net/core/dev.c:12034 [inline]
 unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
 unregister_netdevice include/linux/netdevice.h:3374 [inline]
 __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
 tun_detach drivers/net/tun.c:636 [inline]
 tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
 __fput+0x374/0xa30 fs/file_table.c:465
 ____fput+0x20/0x3c fs/file_table.c:493
 task_work_run+0x154/0x278 kernel/task_work.c:227
 exit_task_work include/linux/task_work.h:40 [inline]
 do_exit+0x950/0x23a8 kernel/exit.c:953
 do_group_exit+0xc0/0x248 kernel/exit.c:1103
 get_signal+0x1f98/0x20cc kernel/signal.c:3034
 do_signal+0x200/0x880 arch/arm64/kernel/signal.c:1658
 do_notify_resume+0x1a0/0x26c arch/arm64/kernel/entry-common.c:148
 exit_to_user_mode_prepare arch/arm64/kernel/entry-common.c:169 [inline]
 exit_to_user_mode arch/arm64/kernel/entry-common.c:178 [inline]
 el0_svc+0xf8/0x188 arch/arm64/kernel/entry-common.c:745
 el0t_64_sync_handler+0x10c/0x140 arch/arm64/kernel/entry-common.c:762
 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:600

---
 mm/kasan/report.c | 45 ++-------------------------------------------
 1 file changed, 2 insertions(+), 43 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..b0877035491f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,36 +370,6 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }

-/*
- * This function is invoked with report_lock (a raw_spinlock) held. A
- * PREEMPT_RT kernel cannot call find_vm_area() as it will acquire a sleeping
- * rt_spinlock.
- *
- * For !RT kernel, the PROVE_RAW_LOCK_NESTING config option will print a
- * lockdep warning for this raw_spinlock -> spinlock dependency. This config
- * option is enabled by default to ensure better test coverage to expose this
- * kind of RT kernel problem. This lockdep splat, however, can be suppressed
- * by using DEFINE_WAIT_OVERRIDE_MAP() if it serves a useful purpose and the
- * invalid PREEMPT_RT case has been taken care of.
- */
-static inline struct vm_struct *kasan_find_vm_area(void *addr)
-{
-	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
-	struct vm_struct *va;
-
-	if (IS_ENABLED(CONFIG_PREEMPT_RT))
-		return NULL;
-
-	/*
-	 * Suppress lockdep warning and fetch vmalloc area of the
-	 * offending address.
-	 */
-	lock_map_acquire_try(&vmalloc_map);
-	va = find_vm_area(addr);
-	lock_map_release(&vmalloc_map);
-	return va;
-}
-
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
@@ -429,19 +399,8 @@ static void print_address_description(void *addr, u8 tag,
 	}

 	if (is_vmalloc_addr(addr)) {
-		struct vm_struct *va = kasan_find_vm_area(addr);
-
-		if (va) {
-			pr_err("The buggy address belongs to the virtual mapping at\n"
-			       " [%px, %px) created by:\n"
-			       " %pS\n",
-			       va->addr, va->addr + va->size, va->caller);
-			pr_err("\n");
-
-			page = vmalloc_to_page(addr);
-		} else {
-			pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
-		}
+		pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
+		page = vmalloc_to_page(addr);
 	}

 	if (page) {
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250703181018.580833-1-yeoreum.yun%40arm.com.
