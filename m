Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBKMNSHBQMGQEDYNQRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 78AB7AF04FF
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jul 2025 22:35:57 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2354ba59eb6sf60625645ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jul 2025 13:35:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751402153; cv=pass;
        d=google.com; s=arc-20240605;
        b=OtoGdb3yPFfcQbc7EveqrSQmpO6C27Ln5QtoN3ttpuJDFE/U/HMLZ/xkWPCSX++Ick
         zJuSputL8xucjdx2PPNNDcRnQAUiguVZhGVWIYEY6yoPz1NlWlvwm4dd0hRa5TlJ7j3m
         yCuLrC0gFN579Uv1PmKHA4ZlvLXZE2cbDPB3qOMusO6UOjR5Uq1oZcw9nIt8omr7lFwn
         Yk57aXnTYXx3dISAFk2ah3Xh9jaTQdQgMD4Gs3h8F04mWdGFW/hyEroe6T1naqk8oZeB
         YU8ef50oy9JQXEZN1Ofr9ssjB4KlWR3Yj8szeDg14Q5YBE2Y3FP8XIrzdePmMTRfkXyf
         KrZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HmEOvglP811/jWFAmAZdtluyoCEwgA1vOM9tZ6XkHRc=;
        fh=p20tk+qoW0LKwfQ684vqxI4uo/SAs6612iNPjnMjWuI=;
        b=YDYuaPlzqIWdSAeh3qHfnugXTWt/ubS2gaLOiKNYBPvzBMaGscwX+BX7D2fplt9kr1
         R+Wr3uDlJKu0YEuRw8MXf30RMESjTKRHSEf+T5UqbwIzH+pEj1QqJWsEKIDfnfFYnG1k
         HQG7ZXYbVpdSlfWQ6x5uG+ljEfw88wtR7nrwx1FeYA2qE5IoXgc/P67TRG4ISscCTCoX
         qXKezWDK0Px79gfEpWtjK55v9G5raL5P2Gtae0tPmNEQXPeolydRCXHbBfbcQZ+wUcMc
         W6dEMDQf5AHO6n3rR5SxC3ZoEFhqW9s7N7QqwW/lv3cuQiEjgitDwW9uKcy+Vcgc6+pb
         XHhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751402153; x=1752006953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HmEOvglP811/jWFAmAZdtluyoCEwgA1vOM9tZ6XkHRc=;
        b=pC2erNq+eQcP2mQQkqcI6VXmMQQRCHXZDZ/b+yMgbUV5JSivupqsUmUJQIMfoL2PVj
         m5km7RSv9BcOd8/i/xaXSSoSVRgY2GIqImR/wlEYBBpGdYhweXmbfp3/28wUJv2VC/VJ
         AW+NytpzeKqdAShvmiDI6sjyawpgKtQ6m4pBtMP7uLIJ8E8GYOt+4uhHP2+tkv+FuouV
         PKYa7D7lwh7JXiaFYTgpVU2RIDuXxKbvGVpIhVWIOJ1HMS3QQ3M5mnkl7/Upw3HL27tp
         kPzGcVDs73BstcmVzljdkUmIBLFj/AHOedguRpa2YIsiP6MSk0YNmoxv/lOJbdRe5EQC
         ZbJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751402153; x=1752006953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HmEOvglP811/jWFAmAZdtluyoCEwgA1vOM9tZ6XkHRc=;
        b=sbZHh0bsNKnIFsp+cQR6BvsanipmrhL+7Dulzcbf7HdcX8YRfsvhQvGPtZylxEPbdU
         FvaPSkzAR0leZjfD9nmevUl9z6EbA2/SzVEJYMUoWNiK0cJxsHVYnSpTySpt41pT5aaO
         RrJV8Z3TZXG1Ymd29xyMFcHHBk/EeZjbI1WeHVHwy/c+EF055Y1YiEX7X5eKnghXshBv
         jkTYuBMKbkLLi5BiJiYIHg2dcSb/PxvvgzjXwLQpaxGVo1mgqot5x9RAEsXHlQ8Phgmk
         v0LKcUvNLNtd9xiFi+NTqffQ99ILZ+llS0ygA/jXj01RihgeI1wlBKMoz/IK381hSLPE
         yj6Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfbiqe+dNgedz40Y3bOA8WSWMM4I02eJWygp76n/wnwik+pbJfCh+3n3NlmDlqqCays/Ko6w==@lfdr.de
X-Gm-Message-State: AOJu0YxMhML39m4DRe5EwAMUfOa+SjBaxQBsp2zJniDpLi7zSFb8z9R0
	WjaLphGb7i95V+F8+M34TH8DI6Vt/GupxpnF9z+2LERiOZAVyoaUzRlC
X-Google-Smtp-Source: AGHT+IFdQXtQ1Dfkuc5ZYoxIZs2QOms+/hlXu71MPM+NVZLMQA0qN0Mz64KeFSXnjA2uE67dDx1jCg==
X-Received: by 2002:a17:902:ce92:b0:235:27b6:a891 with SMTP id d9443c01a7336-23c6e54e231mr1737315ad.28.1751402153447;
        Tue, 01 Jul 2025 13:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd69DM5DN4+T2gv1Z4FAEHXiwoggavi7dUl2vrZvuRuWA==
Received: by 2002:a17:902:e349:b0:237:f1a3:b134 with SMTP id
 d9443c01a7336-23c6cf50fb0ls1472115ad.1.-pod-prod-06-us; Tue, 01 Jul 2025
 13:35:50 -0700 (PDT)
X-Received: by 2002:a17:902:cec4:b0:234:ed31:fca7 with SMTP id d9443c01a7336-23c6e582734mr1325175ad.48.1751402150640;
        Tue, 01 Jul 2025 13:35:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751402150; cv=none;
        d=google.com; s=arc-20240605;
        b=IYrvu7enbmUkPlr5yn8Iy/ViMDBgS2/CTMpkP+OaBSwHB/YhzGBLvsrD/j3obMjzze
         GAo+adzuVnkkBr+laoyi8ONhfaOlVp4cLsJ/dsXCAQaOumsB7ggb5ghwYLurh6R3e8qa
         El0KZjK4VnaMd7TJRFPSWoc6uOyzem5TufckYvTWnL44DmJEC5hvoJemOKbeBK4pVBmP
         SUmglRtjv8Y95eZh2/KyqNeG6mHwGO61HY3+iUdJLEXcIsCEgVnPzCFAFP47gfa7FFBR
         mVTGpcxBqjUegcj6aAVOw+yaX613XWigx5zwtTZasjmEnMNaPFAvg6pg83YUpA4hrK3O
         LpLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=JWGTfER0wc9g7xPwsifLByMebxF8p1dc3sz4iai1vZI=;
        fh=KqGntFcjChECfnm+GZ7PSlQDur9dr+O0kfPAuzkJN9k=;
        b=UCTqPavmmloynfsg44LYRGMPjx0bnDnP24UVMDzrwnP1NY61uNB9TbBtp4dqkAJJt4
         B50PvkCEB94nchugK/QULbB+tQZ9I2pzJi0yLInUS/+OKcE9e71sIfEqE1pB8v9bTasi
         UXzjcAR/nNFooIVCAFoyLl19bSn1N/zwO9Thcp9+2oqpQswF2eSmn2oT8qYrYPkf9UDl
         ebkJS0kL4Czc0v1Gr7CDHNuM/JCK3m1z10GLO+bpc5+yjaFqW+V3WctMmndn3NWo90T+
         WXKuNgOZMjgEhonLbF6NuBkzluQRdSL5uWf53a6E8rZ9RgxLeRUfPPcazRmonE18+13t
         qqCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-23acb2fa636si4902095ad.5.2025.07.01.13.35.50
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Jul 2025 13:35:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8E15E1595;
	Tue,  1 Jul 2025 13:35:34 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 42BF13F58B;
	Tue,  1 Jul 2025 13:35:47 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	kpm@linux-foundation.org,
	bigeasy@linutronix.de,
	clrkwllms@kernel.org,
	rostedt@goodmis.org,
	byungchul@sk.com,
	max.byungchul.park@gmail.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-rt-devel@lists.linux.dev,
	nd@arm.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Yunseong Kim <ysk@kzalloc.com>
Subject: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for possible deadlock
Date: Tue,  1 Jul 2025 21:35:45 +0100
Message-Id: <20250701203545.216719-1-yeoreum.yun@arm.com>
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

In below senario, kasan causes deadlock while reporting vm area informaion:

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

To resolve this possible deadlock, don't call find_vm_area()
to prevent possible deadlock while kasan reports vm area information.

Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
Reported-by: Yunseong Kim <ysk@kzalloc.com>
Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
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
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..61c590e8005e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -387,7 +387,7 @@ static inline struct vm_struct *kasan_find_vm_area(void *addr)
 	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
 	struct vm_struct *va;

-	if (IS_ENABLED(CONFIG_PREEMPT_RT))
+	if (IS_ENABLED(CONFIG_PREEMPT_RT) || in_interrupt())
 		return NULL;

 	/*
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250701203545.216719-1-yeoreum.yun%40arm.com.
