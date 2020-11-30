Return-Path: <kasan-dev+bncBAABBVPPSL7AKGQELWXFAUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 222322C80B0
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 10:13:59 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id i2sf5782607qvb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 01:13:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606727638; cv=pass;
        d=google.com; s=arc-20160816;
        b=b4OprD685WenmT1iSyEJwwHXvR779szZkQkLsZFODHsBqXvJSxQUK72HoP3yYs7yDb
         9RcCH6ifD4M/40rXpy9UON7U0TIeLj6po3Y4HZJ3r+jRNY30XCW8MkIMJesNo+j/5pfL
         V0gILHCczyvzysyPfSVKqoSsQJwFDDZ23xsYkACuucRjv00BK6xRlGNTLs5tuJFQ9eWQ
         Hb7vZMIO4jEPlnf7cjJTULgvenOMAgILpeHElK8Dz2Ox5XCexNzwf6HrOVn3xSwBWoWX
         BGK+kP+EpJIQuOLGrr3/gqHU7X9UCbGOws4wxs051iQbf69KPr/f7CXo5IzjhziiDw+f
         GEAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FJTdkpbO3Ao9OMBpBY4aGFFi7J0tCNa0tcgjDJuV/QM=;
        b=0kPmbSGwLzULB1Ldj8KtqhY0+tlc3aizUc18mQNXqp7sc+tY9DtzGyYNRjvxDSdJpn
         eJWNtA8cZyJ7m63W6wJ2pc8nvGEBMw+95LamsLoK5c00WKiQY3QWbpKw3URmwABDNExD
         1dchkTwib9BahdHuwtSXAr7NnMD30wqOiwPW2ljyEWGU02RkJ06lNnaiteiQytilTV5X
         cXyoLZr+7+4rpTmvtcjQJJ2r0yY7Q/9ST2F7wozn+V5pD6uqRetUWOb7tYY7wwj6idwV
         c+ZuJzG3UClSnicoebPf0baiUxLLL91e48OZjJp4ydh7A3LJVuH1+1h1UfqF2lw0IPW/
         RNzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FJTdkpbO3Ao9OMBpBY4aGFFi7J0tCNa0tcgjDJuV/QM=;
        b=j4R19gmyxJ7OmlYGomGVyy1kAjxODa3TWes7u1JNqce1i4gC13OFr+mlr9dvJFiaGA
         conaHutzKvtOYzG2C/MG44VXsN7bw8287xH9x9V54KamWyl0T7C54IF9ejBw1G6B2aVm
         /wKkLYx789HZUS6pgWLabQCqH5o8E7mR5xDgEyCKLHlr9lHxS4uGlbWSQ/4s+8rybJ09
         r1VWThIsqg5LPl6qCzvqFy/ZQu9amMdhl+p8Yd6do/mdMUZh7UgSLn7Txj0l7nVpjiXZ
         Jp9/CFDrSlMrWuydZMXdvUKkOoO3RJ87+fbHx3Kf8WzsrzhE/WevL+KzA1Y/04W1Kpir
         aIUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FJTdkpbO3Ao9OMBpBY4aGFFi7J0tCNa0tcgjDJuV/QM=;
        b=QJ3HuJyA5qPSCY3S/QehPSK7OH9z65gqX7z++cYOQB6TeFWWBQxKlIP5YqCFzLtdMt
         OQSTrohrusOO7PnoKIPEzysm7SMgUOsTiD2mA2UFHLSpekf0hRbc7BN7lDmwUNnxj6zD
         1XWOE+JCo/nMlWeUiRPhv7nu3T8DgTCm1mgzBS26hE+Q/uEBi7OEBdpxUj82svd/if5X
         2mdBVjEv84GGuqLG8BttXDJo4Ru12ydV8Bv/cwhXhWNiiL8bdiJ4ggpNP5Q+ANMiusci
         rLBCrcqNaEdLRvNtXfnXqGmPw7FQn+rY+s16f+rDmmtzZ2EJkItbm3l3Cup9iC4msPOi
         IAEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xwkbt/sTRMyylhjEYWj3e03jxdR4VzqCbQWVtQqHdkyCndiv3
	LHISxtHbl6CXHhX+peyYl54=
X-Google-Smtp-Source: ABdhPJysUQfmqlZOHewQ/TbYZjJQVtOWr1CWOvSSghWpEOccLZWx6t7hWUWTLFX8g0i2H2p4sOIimg==
X-Received: by 2002:ae9:ef4f:: with SMTP id d76mr15770218qkg.95.1606727637973;
        Mon, 30 Nov 2020 01:13:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:648:: with SMTP id a8ls5702640qka.2.gmail; Mon, 30
 Nov 2020 01:13:57 -0800 (PST)
X-Received: by 2002:a37:793:: with SMTP id 141mr21733433qkh.215.1606727637419;
        Mon, 30 Nov 2020 01:13:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606727637; cv=none;
        d=google.com; s=arc-20160816;
        b=SmgQ3t5RO8TgG33ktqIdXrvPLcnF2XVy6YDJa5qRZiT1KktfVjOcvi5VgEw4qQvZ3k
         EGEGHqn0wzjqCEAqyHaJ7LMJGdwqT9RLIqmfByjzcenZrxNHMXLiAz7QLEuSLRlWyPNj
         ivn6SItBO2Fevnk2RDvPW/3meDcMhBKka0Wsl83ltdlWfL6URDHt8Gw45Y9eUleJfIVh
         ZVkr8u2zNZLzzMBRXVHVv7RG7kg6bax9uZXQvM8K7xLeyEp4rEfTSq/Ee1uVA2FNlhEy
         InuDclaET13jJJMObP+i7eabtw8j/nMUhrEIcOUF9cEMCGfI+CWm2bImPW6WBiOBDasw
         +ntw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=sc0fD84WpOzTwR4y/BZEy6/062Fy0nMdgfvf+RaexLk=;
        b=TA2glVuRxmoUsDOy0Wt7/hz+cp+NA5DTKNM/NfKft4D1ll8jzDE2mgoDMgqNajLZ3x
         pfUWofN/LBTcLRPdDSF5LqBZZbneV5FQVaVRZs6DRj57g/RLJkxLnZtL+oNPggUAKQ85
         Pl6qNNehiMzoHzZ97rF4PXWKgLhkoH813CyPPj5p+FQyJAM4BZQe0qCauFCw/7mfbqlw
         63ZC0I8qQQyqVSI0FeI+dxKl2L1sA2WM9jwo/AWQZU2Kc9+NwsLty78+OYr8nmE22wAG
         2GRlpCMqaFgeaQgCNT4YE3IVIpPHk7lpwpkzeWoFJwEOlW6B+L0hnS24k/k+orY3tqiH
         iQQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (exmail.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id g2si114403qko.5.2020.11.30.01.13.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Nov 2020 01:13:57 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 0AU9DvK7078755;
	Mon, 30 Nov 2020 17:13:57 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Mon, 30 Nov 2020
 17:13:33 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
        <paul.walmsley@sifive.com>, <palmer@dabbelt.com>,
        <aou@eecs.berkeley.edu>, <nickhu@andestech.com>,
        <nylon7@andestech.com>, <luc.vanoostenryck@gmail.com>,
        <greentime.hu@sifive.com>, <linux-riscv@lists.infradead.org>
CC: <nylon7717@gmail.com>, <alankao@andestech.com>,
        Nick Hu
	<nick650823@gmail.com>
Subject: [PATCH 0/1] Fix Kasan test module run failed in RISCV architecture
Date: Mon, 30 Nov 2020 17:13:18 +0800
Message-ID: <1606727599-8598-1-git-send-email-nylon7@andestech.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 0AU9DvK7078755
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

When you run Kasan test module in RISCV architecture,"kmalloc_memmove_invalid_size()"
will be executed and then kernel will be hang in infinite loop as below:

[   26.228433] Memory state around the buggy address:
[   26.229824]  ffffffe066e11d00: 00 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc
[   26.232098]  ffffffe066e11d80: 00 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc
[   26.234461] >ffffffe066e11e00: 00 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc
[   26.236650]                                            ^
[   26.238149]  ffffffe066e11e80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   26.240400]  ffffffe066e11f00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   26.242646]
==================================================================
[   26.245312]
==================================================================
[   26.247607] BUG: KASAN: slab-out-of-bounds in memmove+0x2e/0x8a
[   26.249160] Read of size 1 at addr ffffffe066e11e49 by task
insmod/106
[   26.250855]
[   26.251755] CPU: 0 PID: 106 Comm: insmod Tainted: G    B
5.8.7 #2
[   26.253454] Call Trace:
[   26.254509] [<ffffffe000203256>] walk_stackframe+0x0/0x128
[   26.256027] [<ffffffe000203530>] show_stack+0x2e/0x3a
[   26.257467] [<ffffffe0005ab9e0>] dump_stack+0x84/0xa0
[   26.258936] [<ffffffe000367120>]
print_address_description.isra.0+0x34/0x404
[   26.260686] [<ffffffe000367676>] kasan_report+0xda/0x132
[   26.262141] [<ffffffe000367a68>] __asan_load1+0x42/0x4a
[   26.263610] [<ffffffe0005c1c4c>] memmove+0x2e/0x8a
[   26.265241] [<ffffffdf81cdec26>]
kmalloc_memmove_invalid_size+0x94/0xaa [test_kasan]
[   26.267829] [<ffffffdf81cdfa2a>] kmalloc_tests_init+0x94/0x14a
[test_kasan]
[   26.269563] [<ffffffe0002000d8>] do_one_initcall+0x40/0x134
[   26.271106] [<ffffffe0002a2e5c>] do_init_module+0xc6/0x25c
[   26.272610] [<ffffffe0002a5692>] load_module+0x257a/0x2bf2
[   26.274096] [<ffffffe0002a5e70>] __do_sys_finit_module+0x7e/0x94
[   26.275676] [<ffffffe0002a5eaa>] sys_finit_module+0x10/0x18
[   26.277207] [<ffffffe000201690>] ret_from_syscall+0x0/0x2
[   26.278677]

.....

[  579.407314]  0x0
[  579.408267]  0x0
[  579.409222]  0x0
[  579.410198]  0x0
[  579.411206]  0x0
[  579.412151]  0x0
[  579.413122]  0x0
[  579.414080]  0x0
[  579.415026]  0x0
[  579.415964]  0x0
[  579.416912]  0x0
[  579.417871]  0x0
[  579.418834]  0x0
[  579.419781]  0x0
[  579.420738]  0x0
[  579.421841]  0x0
[  579.422805]  0x0
[  579.423764]  0x0
[  579.424696]  0x0
[  579.425638]  0x0
[  579.426599]  0x0
[  579.427538]  0x0
[  579.428467]  0x0

.....


if we define __HAVE_ARCH_MEMMOVE and port memmove to RISCV can fix it.

Signed-off-by: Nick Hu <nickhu@andestech.com>
Signed-off-by: Nick Hu <nick650823@gmail.com>
Signed-off-by: Nylon Chen <nylon7@andestech.com>

Nylon Chen (1):
  riscv: provide memmove implementation

 arch/riscv/include/asm/string.h |  8 ++---
 arch/riscv/kernel/riscv_ksyms.c |  2 ++
 arch/riscv/lib/Makefile         |  1 +
 arch/riscv/lib/memmove.S        | 64 +++++++++++++++++++++++++++++++++
 4 files changed, 71 insertions(+), 4 deletions(-)
 create mode 100644 arch/riscv/lib/memmove.S

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606727599-8598-1-git-send-email-nylon7%40andestech.com.
