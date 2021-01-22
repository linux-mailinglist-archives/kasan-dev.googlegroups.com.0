Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWOGVOAAMGQEUY3KF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 55E4930059F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:38:18 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id b35sf2315040otc.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326297; cv=pass;
        d=google.com; s=arc-20160816;
        b=ejH8H8nmRhLR1t9H2LHr4lfTnChVb/I9fJoFP95K6ZCKaVlOplLHcRzioKkl1wGhaM
         DR1J4ZAwTkFxm+JQWtflZguH0gQF6zbXC5XZV2pPEGOPsX+0jPIVolx8IePVrPfPJeRx
         hFBHz2tIw4cSAJ+wJ2rWH3mQ/RRb5onR+kS9EkfXHy4mCLQAVCkYuSkFJMRWvp5N2JqL
         1XMbaUs+7I4gAGXjpNjFQwUDVhTB7pJZ7pqDckbCPHgSTyDwg8jcdYAS9BFVqCDTW2Ia
         G+/4i/9CXIiQ3T78K6Qzmu+Ypx5mkJsV5Mq58cBLs9B9guDhN2uCAENLmn+45nsA6lBL
         6vZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Vxh1zIS/n/5fLFi/MD6BekpAAfaD2SujRXHFYKTOfo4=;
        b=oUVZldOXVL098Sf7Y2sCWn0JDZmkBvgOvUBRdb/FSEJZIQcFaqPqq1Z5T2ZXbWYbso
         uhcEdgz24eJrGUsHKNyoeuVAO/HRi9pDzAx7e74NMOKar431hPpfPEgorQy/EHJKvTTB
         A5osCn4/Iywbi+gtMzlqZHoz4yrZeUo+tDJkAzYJqgyiY3M/+7wnPD02svO2diyZmfiF
         qD8nNpkdzXetEbNp3ThoP2NKFwef11TlkzefxrdOAa3ZKKgD8PZoXsa2Xs71sdnkiWPJ
         GkE+j6uS2lgvp6BlK8X8te5ItOghJ7sauC6cCVN2SsyLEN2scZPATQMgxWYgnOUyHuo4
         Ovwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vxh1zIS/n/5fLFi/MD6BekpAAfaD2SujRXHFYKTOfo4=;
        b=TxDu9tsMmsV++8ioKWAkPqHHvL9/cxhuLx05ym/VSqmBYog4U6QGWvILjG3fd/vXvw
         dAJ/HA1gBoV3Qre5Q5d4wXtZtdKwaWvrv9zwukz0JnCueWIwgKy1a6YCbzmDSjwfzrPT
         TA+8Lpju/RfStUrfP1qLdF7qvTdF14E1uv396Ze+iItCrSft4WwhhnHPqMxHhxNtVROS
         D1TRqFJg1sV3Zf1ZsVubUcgn1jgZ+OYD7yGqE1HnH/QfxzPcsjvZgghFPCCTwyHbT7L6
         XN0qEphjstN3M1308RMN4daUoYOiPGaWU4V3AcX1OBt72yUXe3oTeJCIXxxQTiDjQksR
         6aQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vxh1zIS/n/5fLFi/MD6BekpAAfaD2SujRXHFYKTOfo4=;
        b=aFBeRi/U+fiPWZ5HC7dZb5xA/SVa3RGz9azraMouxjgY7XDek3ykwZgYexlCnyJRBK
         5ec/2VyWyKJFjuVt86jg8Ls0DQY4YMu4jAGdYvaqLgisRmSAYoVY9HiECIznYRFawxTv
         K1daovlehykt9VwfECn5ZsqLwb8JuQ7QRi9Mgm4aAFX6utjmtn52TDbzxeVO1WfMWnP5
         hGtvsDXwTUpzZo+bYDPQ3WqRJjd473R6ipkwnHcnuwbItpTU48gjxnjUw9ocCZOfZ0QV
         4h99+P2NmPlda+lENS1fj3SG0/uMKpg3p8SxNSEX3jk0FXRS0qD1fAcgGllLwb8OvQrp
         EFFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530p7LeLGDE4iyT2m1NsLyTlY+LBgDTivVRcTOlnpXnLfLFwcsC0
	4n3Mdh55ptoBFvz3VC80de0=
X-Google-Smtp-Source: ABdhPJxCIjXRUnMRbNqS+MuyLvIrBRpcuHgqwSy/rRvpC0le2wHXLLwj7yCH2BnOnVzE9Zks8C0zCw==
X-Received: by 2002:a05:6830:1da4:: with SMTP id z4mr3502070oti.295.1611326297357;
        Fri, 22 Jan 2021 06:38:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls868919ott.0.gmail; Fri, 22
 Jan 2021 06:38:17 -0800 (PST)
X-Received: by 2002:a05:6830:1e50:: with SMTP id e16mr3562309otj.149.1611326296990;
        Fri, 22 Jan 2021 06:38:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326296; cv=none;
        d=google.com; s=arc-20160816;
        b=Ojnzpiw3FaZG2gtSyDrQ7aQAynmeqVUz7wB0W6IhWxz1VsSjwS25Bc+klOG5nD0Qxo
         29RekaHfbkVFgH0a6qq4ApvBY089wqYST+CsEwNXVX9egcnhB2En3+/1JaY6hI+JW+Zd
         cy6S2yIpJGjnAWoRuksTdZMMRt7bZ8YAl58QtMml84rXIVw1fT69nwgNuxy37v1BrdNE
         E6GyXkFvM1ketiEO2JbmY2hi7Em8N7cUbAAqhe8F/blW7uPpPW5ksPA7DRLvVcWLwM+s
         vQ0jJ21Jie5XjLpZ20fDqZ4r0va2hSKhDUyIOJYmz3/yZ+pevMRiGqJk/WU08RwugH2H
         WKNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=fNShuAnqNTlb4Cuxd4cwDG3dRDMyiG3okVAAuWc5pIQ=;
        b=nXviCaIxdKe1C/AtwefP1oHSa7POaPHLQgJs9XQth4j5xvwDx1QgkX6nESiw55d5Tc
         txXtGhSdYSn+iegA672k8SJ9dKLwOBLRikwvqcGbzY8juVTq8n5eALidyiLe7bvj+Aci
         SbM5WuR1mZJult2igdzDOReDsQugIB3pt2IaHOd56PhqTsQKHiLWn5n5tHDOuATVvVq8
         C82zBqVlVAVFeBD4wGOTMVllbhS4L8Kma79L6BOBTBfQ66es/hDkQe25MEeulcc00BZp
         SQ6ZZqnCqHDwuMenqhArx5Q05gkgkZAk0Biaw9kEg2N2VlP3mh0T+a/Ek/5nok/XDvB8
         zLlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b124si549472oii.4.2021.01.22.06.38.16
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:38:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BA21D11B3;
	Fri, 22 Jan 2021 06:38:16 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F2DCC3F66E;
	Fri, 22 Jan 2021 06:38:14 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v3 0/2] kasan: Fix metadata detection for KASAN_HW_TAGS
Date: Fri, 22 Jan 2021 14:37:46 +0000
Message-Id: <20210122143748.50089-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() currently assumes
that every location in memory has valid metadata associated. This is due
to the fact that addr_has_metadata() returns always true.

As a consequence of this, an invalid address (e.g. NULL pointer address)
passed to kasan_report() when KASAN_HW_TAGS is enabled, leads to a
kernel panic.

Example below, based on arm64:

 ==================================================================
 BUG: KASAN: invalid-access in 0x0
 Read at addr 0000000000000000 by task swapper/0/1
 Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
 Mem abort info:
   ESR = 0x96000004
   EC = 0x25: DABT (current EL), IL = 32 bits
   SET = 0, FnV = 0
   EA = 0, S1PTW = 0
 Data abort info:
   ISV = 0, ISS = 0x00000004
   CM = 0, WnR = 0

...

 Call trace:
  mte_get_mem_tag+0x24/0x40
  kasan_report+0x1a4/0x410
  alsa_sound_last_init+0x8c/0xa4
  do_one_initcall+0x50/0x1b0
  kernel_init_freeable+0x1d4/0x23c
  kernel_init+0x14/0x118
  ret_from_fork+0x10/0x34
 Code: d65f03c0 9000f021 f9428021 b6cfff61 (d9600000)
 ---[ end trace 377c8bb45bdd3a1a ]---
 hrtimer: interrupt took 48694256 ns
 note: swapper/0[1] exited with preempt_count 1
 Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
 SMP: stopping secondary CPUs
 Kernel Offset: 0x35abaf140000 from 0xffff800010000000
 PHYS_OFFSET: 0x40000000
 CPU features: 0x0a7e0152,61c0a030
 Memory Limit: none
 ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---

This series fixes the behavior of addr_has_metadata() that now returns
true only when the address is valid.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (2):
  arm64: Improve kernel address detection of __is_lm_address()
  kasan: Add explicit preconditions to kasan_report()

 arch/arm64/include/asm/memory.h | 6 ++++--
 include/linux/kasan.h           | 7 +++++++
 mm/kasan/kasan.h                | 2 +-
 3 files changed, 12 insertions(+), 3 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122143748.50089-1-vincenzo.frascino%40arm.com.
