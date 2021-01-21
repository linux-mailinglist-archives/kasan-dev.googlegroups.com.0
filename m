Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCX7UWAAMGQEX7IV7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 255C62FEB70
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:20:11 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id p80sf2181824ybg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:20:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611235210; cv=pass;
        d=google.com; s=arc-20160816;
        b=RNIF2qjXh1nnx/Gy0grNFD2jRU7fq66vc8RemKgBwy8oNDLszRtnfN8MmEEw5cy08j
         e/ZjXv6zTU730XM70m7zN1MsC1R0jmnCq30/yyjcXBOi2v2qTeaa8gYq4qkW8LQ2dduR
         VIIE+o8J5fnCNX3mw+SCrdxoJS1QHg5OTKbXW2oDRWej3mZ9RkfcWvm//NOnAKFFxBv1
         lF1dsK0Swdvdi2HdhTqGkf4UeuApBrHzvDxseQUL4+vWXTVkWTQ+ndHAv75yQh80ruGJ
         TBEIjws1U8e+uSssFDeaKj9eWE8jrov/WFFv/hCPBfMmWpJFwKurQ/SjXXfXrQIABp8o
         7h5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AnJqreWbxMXJhc3D6W5McxKGCbP+vbauOjGHLIT0+zM=;
        b=a1qcfsZuMNO2/iB+5gy+AJ2gMuoc7cZ0F5aEMCAQPJXCqEAQBVWNIzlpjM7DXbkedl
         zFccuEGioT33T6orIsBzeU1y23zTA6Ds3xySW0HLouoVPel0pCp24JKveHTnWj9MHmzV
         ZXU56M3Vtf5gLOrdMnXOUhSPFtS7yKcZhJdWxgpN7+LcQZbCmuCbJ0OR2d8khvoDfzdb
         eBdaEtTHo8QgMbp3YEpBYq9CufYmAQCpA72OLSnYuTmQCA/poEDcQRY/WF5ktai8FsIH
         w7bvwaRe2d/+YYMjXTsAgMWcjzepBC7qHEo74/ixJiZkV+7A+t05yFAj7TOLp+5QzBbR
         7e2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AnJqreWbxMXJhc3D6W5McxKGCbP+vbauOjGHLIT0+zM=;
        b=Fzf+6q469n/XGPasfWeVAWM2LP/YbMLhT9VAAVjUxASx6514YofExlnm6/mKN1ZVIv
         D/FUYToX0yf2bkBjYFEsDPuGUOibIcq2ls4S1sSrKtDyQBNeNypiK/uOrqaiotWjeZzn
         BG0WPSi1n8ixKKQkn64S7wfir2hk+06wdvSbsXYjcPjRtNCPCkhIfZ3JoLMW9AJAVENp
         Byl/uUpWJs7pM7ttM/HRdAZPdIzq9paT87BWJ1BxX/Ix9fSit5IraqN65sc1/BnsA0Cb
         udPj+E/bXFSYSGZ1Vyk6Qhsvm4Dj1+oNz5N41mqTeljHa9mjmMS9ChyWxGlBMBk5sxDv
         c+SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AnJqreWbxMXJhc3D6W5McxKGCbP+vbauOjGHLIT0+zM=;
        b=VpUmJToikPDdVgesV8ayXwWJZNp5sRSRiK4aOcY5DSuSMiuC1xQ7yxnqzPs/ulkBEY
         U63z0pBa6imZSV1MYdh8o5R8osZKr/0eYcxvZEysRKcQoAIjZFgtO/wrGoEs5CAZW2+V
         TcuLP/ZNWGAmSpVLX9tia4Im9JTjnjh4/z2HYNQFMxN+9x7rPR6eQR8x9Xw88Zc8t/qL
         uTsymmwk6YH8E+70zPpj3HMe6MI7yJDl+QEvYd4k9OcL5wXGryuLtDxDR5jDbVi3/EKs
         wr2hlOzi6TmMbluAJn6VhHexDv613imJE+NkvDX4dmLjqhheuQQJWp6nOA0ldk/ojhEH
         KxtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dldcQgviEwq2BdIjCWsV69xGSKn2oi1lwaE2+BpiJuFqjPOWI
	aFLai5Ju/EzV2ZfcjMNyS9Y=
X-Google-Smtp-Source: ABdhPJyBSxBtuxbHOhDQ8H4Xs/SunG3Gkbo5VaY2K6DStXQzqytW2rrvwEZ8zJQqYJz04VlXcZ5Z9Q==
X-Received: by 2002:a25:db94:: with SMTP id g142mr20506691ybf.161.1611235210195;
        Thu, 21 Jan 2021 05:20:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ff19:: with SMTP id c25ls1258193ybe.2.gmail; Thu, 21 Jan
 2021 05:20:09 -0800 (PST)
X-Received: by 2002:a25:2fd7:: with SMTP id v206mr21371401ybv.420.1611235209768;
        Thu, 21 Jan 2021 05:20:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611235209; cv=none;
        d=google.com; s=arc-20160816;
        b=jyWyINRHzWOiPRz100SNmaFkbqbGKTA1+XsNY+hifkA1Ti27j7zCHn2WSzZPKEOMnE
         rffZ5Exh0Mo3k9EAjyNcnwIplFzzSPcPbaWJXSn0F+PxpayB90iqVGgaW5F4H0gn49Ka
         GJlNIE5tw2p1Ap/MV3NOh4NBraR+VzMrUqnIUu0TKat3i4Rt4NCKqvPyhM9qud7RilTd
         eCnbkIDQW4QTEuw+zXVHYVT7pbZPpfI/0lHe4YUtroqhFLWS5Stmf7xuozqOEnUAUWNC
         YHz/iuIHRp9/6KJihyVkDbb7cn7hza3SaHYFvNbd+qHZXt/YkYnlCV8Tk89CM4Bz77DK
         R/Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=C/7e0LOzXZDehjW7UYY0Fg3bDq2XpnPi1t/ILIFXdr4=;
        b=0nWRtxgHTcmZdxO3Wm/cXa0JzFk1kzdV0ti8kwnoO5xAbN4TA7mGFk/DrILoveACuy
         exQfGhhHOi3WdTbNl1uuXXDildYuhypjeamwGLvQ/CEPtFThUY6pCs5o1HGw0TVr58fb
         CNLZe5Drsbw3cRY9hZ8Qj6GDiKLhwb7pK2jxhpAqLp6bqzG1CxdxMsLaoW0o2LCJNRuN
         z68fj7CNDxA6rPcI0pul1gGLYL+tkmfOt7neATz0e61f9Eatvj0RMRiTQd7AajyCoQZF
         yYXz8JzDwvzMl2fM7zTYt/+Pl1LKxNwPkGxJVhmUuhKeoPdhphMeZds6Akpqn8hZ4SUJ
         YJ3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x18si404042ybe.0.2021.01.21.05.20.09
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 05:20:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3B1CE11B3;
	Thu, 21 Jan 2021 05:20:09 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B3C073F68F;
	Thu, 21 Jan 2021 05:20:07 -0800 (PST)
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
	Will Deacon <will@kernel.org>
Subject: [PATCH v2 0/2] kasan: Fix metadata detection for KASAN_HW_TAGS
Date: Thu, 21 Jan 2021 13:19:54 +0000
Message-Id: <20210121131956.23246-1-vincenzo.frascino@arm.com>
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (2):
  arm64: Fix kernel address detection of __is_lm_address()
  kasan: Add explicit preconditions to kasan_report()

 arch/arm64/include/asm/memory.h | 2 +-
 mm/kasan/kasan.h                | 2 +-
 mm/kasan/report.c               | 7 +++++++
 3 files changed, 9 insertions(+), 2 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121131956.23246-1-vincenzo.frascino%40arm.com.
