Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKN2YCAAMGQE32T2UTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 88077303F23
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:46:18 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id y187sf12394742qke.20
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:46:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668777; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjZkyS1TTT+kZX5EX4/fMKT8b9htiU3HlYrEQcjzBS19eZ+G/W1cfX2qs8LeG1Aocp
         ggdtaYmVzKi1DOtuJc3FRTL37+5LB/w6y15TTHzvDk23x4zoocF3Adx5voxiVRbUe4XH
         EzyJkg7nzp9eHc+oZqjXu5F8VFt4ZN1OWAKUZfhGNly9+RhZEX4Qs+AuLVjZQ5LzcNRH
         kOvYgopAWA0EhCmrukIXHmrCmDCMDpEaifToFLo/xWXdS2gGhzWvzmg7Y2jvumB39Cnc
         /687UVPe+1jPaW7dfmc9P8IwD4Y2bM9YHoH9whVBYhPqLOoYjNaKTPbYJVuC/BztXOTJ
         ZufQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pLxOUvcMCLifnyNQ2Kd8Em6KqfC6ZAjVr9OPgJ5MHNc=;
        b=wufrAfHPxMm8wtAejQPOWamNHn+p2bEkWzuQyevkiwcqwET84eOqf55YxIiypq1VgC
         rpcGY38XFrysllO/q6WqA8BlOikJ4yQaqbcc8TjTHioow6ErBdj6YhBekRafk2ChDY3M
         F9GzQuAVREVTR2NCnNa+4+jLUIsPcsjw78Epak5fBTg0sMi+Up/2Gd0L8s3ziQTHErmc
         /kv+c78Ky1i6YHlOXgPviVLZG0yjAS4vgfwS5JhTq7oianPW6ojtU8NNtGOg1SHn9EMH
         datNXO1D+vIsVYsbqC+WCc85B+SJXDLNn2dFZOsDdaQoKHUX4nXYXT+PnwTdpausbwx7
         BzSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pLxOUvcMCLifnyNQ2Kd8Em6KqfC6ZAjVr9OPgJ5MHNc=;
        b=k/I2aRvWTbsSdid6WqzFhuk8rYigOExRkhaTdHQwzhZ2NghCKRKEWNKaQ9YBDHmABY
         s8FwR+sfjHI57dbFuBO+XTGOviEBRssJ9G9HeddhrwcxXuM79RsKk3WO5MYXrfbEc+Ge
         p23H20gt3bZo/oNPDZgeR9LVB+g4W+3clG2ChNhkeXmo+zYHjZ/D+UoXyKsC5HQBKCDV
         c5kyNABMcLp/sb6B49QokCPHja7+AAKloyMl4cgLlLp7glR8p+tTJFCSN26u6rCDhIIt
         sC9lFL6P+RmaTZgCIIjXlOi97zmdZB3yw6yAszth2IXZRhnfT0hvrzlc4kHTQyr0RO4W
         eaJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pLxOUvcMCLifnyNQ2Kd8Em6KqfC6ZAjVr9OPgJ5MHNc=;
        b=UAEi4Yfya+/04PJ2GxHYqwTncIiHgy26b2v9Z/QU53iKI2WJdC1Yczq3eWQKxG+dyH
         fHIlZ5i6/ktar4D5nN4aBGYxz+G7qBHpdiN29ikQmIT7Cp4KlQ7sxb4ocrjca/iv9Q8q
         TsSSebkrgDia1DzQAMabzwBJNkLMrVgEv8j9Xa9508mREUGzAoRNgI0Ae1O/tlClUIBV
         JNaVlbG6Ueu9aHLVXuxFbEJGNAPD+XL+5mraAw50eoIYBFkSLnX5MAjTUN+nRhtXeb9+
         eGhJyp88Qqg8MuAG0ej97p71evSYGvbuG/JSRJ/cdzQbV4T7fQqXWSkLAAvLp1N1mflS
         bz8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328+FpAYvpnJA1RD/HdOxTC7bnVVDp8CwtWaAmqLWz2Gfbg4JMH
	TVB2BWzKIvBHKJBwrJuseYQ=
X-Google-Smtp-Source: ABdhPJxtexE/HlJKviXgF7K/Q5mFHr3l5lAFeaplIb6/vhnDlaesGJZiltTAZGELzXvfbiQq/Xvrig==
X-Received: by 2002:a05:620a:9d7:: with SMTP id y23mr5771232qky.181.1611668777506;
        Tue, 26 Jan 2021 05:46:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:12cc:: with SMTP id e12ls2463446qkl.10.gmail; Tue,
 26 Jan 2021 05:46:17 -0800 (PST)
X-Received: by 2002:a37:f504:: with SMTP id l4mr5684930qkk.363.1611668777068;
        Tue, 26 Jan 2021 05:46:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668777; cv=none;
        d=google.com; s=arc-20160816;
        b=ucBIrZe+oISJ4rc5YXMYG0nKi9UyVJSi2rN4Y34kpz4hzlkCXKNk2rtayyBkMF6+rj
         HHkFT8XDHnpmyWtbJnizULnZFGTxpbZaOhYZv58G0Hg60d+F8YgYMRh7oCXwmgS/m09C
         emy/ZcQ+BEvgLH38HfKjYq58CoKReo62lJE/CjsulYbc0UuG2yK8AtFrD+QT3BlZR60U
         EnCYawAL6ApO33xbmBDl8DQLUfXn1JgVwvVRvDPeArHmeFm1HgONPUlB1LvNKIs5zzPn
         ay4R9EyycebBcB+hU6rVWm9A1FE4gHnTKTEQYaGZt9oafJmKsafChUvQyGwGtxz8qDpR
         uoRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=TJEP4RrhgOrzcsbClH+3IsFmSTHPz70MGC6xdjU7+8M=;
        b=Eo+6a7CkohtP2yXU5q7qRkrXCGhAW2OtHAYvKNwlBuyq9StTwzWaCb0xtNpcCARObY
         yk7mRZaIv8LjHLl2xRJZIGnkwrhRaHJsjVPRHs8x7D3Kij1hc4MetByZJ1tLZyV/HaRE
         OTQ0gliNyjoxF6fp1kzfMItibtZ6OGPF2vrgbWJYdgRUTkhcJYO43F7LahPoSWgLhKkq
         0dbRnWotZ4U3Ta4XOTpKWJ8rAgUQdyMsHe7o3OwgSSUzCfKd49k0IuozEq/J8yKZ33mq
         cOKBKSYY9oBySsor9j8XY9gC4yOcK8NlcgrIDVYEYdVgSUEtp6NYNs2qeu09CkgrPoXH
         mxXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n6si350729qkg.7.2021.01.26.05.46.16
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:46:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 91BC731B;
	Tue, 26 Jan 2021 05:46:16 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C7A2A3F68F;
	Tue, 26 Jan 2021 05:46:14 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v9 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Tue, 26 Jan 2021 13:45:59 +0000
Message-Id: <20210126134603.49759-1-vincenzo.frascino@arm.com>
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

This patchset implements the asynchronous mode support for ARMv8.5-A
Memory Tagging Extension (MTE), which is a debugging feature that allows
to detect with the help of the architecture the C and C++ programmatic
memory errors like buffer overflow, use-after-free, use-after-return, etc.

MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
(Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
subset of its address space that is multiple of a 16 bytes granule. MTE
is based on a lock-key mechanism where the lock is the tag associated to
the physical memory and the key is the tag associated to the virtual
address.
When MTE is enabled and tags are set for ranges of address space of a task,
the PE will compare the tag related to the physical memory with the tag
related to the virtual address (tag check operation). Access to the memory
is granted only if the two tags match. In case of mismatch the PE will raise
an exception.

The exception can be handled synchronously or asynchronously. When the
asynchronous mode is enabled:
  - Upon fault the PE updates the TFSR_EL1 register.
  - The kernel detects the change during one of the following:
    - Context switching
    - Return to user/EL0
    - Kernel entry from EL1
    - Kernel exit to EL1
  - If the register has been updated by the PE the kernel clears it and
    reports the error.

The series is based on linux-next/akpm.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm

Changes:
--------
v9:
  - Rebase on the latest linux-next/akpm
  - Address review comments.
v8:
  - Address review comments.
v7:
  - Fix a warning reported by kernel test robot. This
    time for real.
v6:
  - Drop patches that forbid KASAN KUNIT tests when async
    mode is enabled.
  - Fix a warning reported by kernel test robot.
  - Address review comments.
v5:
  - Rebase the series on linux-next/akpm.
  - Forbid execution for KASAN KUNIT tests when async
    mode is enabled.
  - Dropped patch to inline mte_assign_mem_tag_range().
  - Address review comments.
v4:
  - Added support for kasan.mode (sync/async) kernel
    command line parameter.
  - Addressed review comments.
v3:
  - Exposed kasan_hw_tags_mode to convert the internal
    KASAN represenetation.
  - Added dsb() for kernel exit paths in arm64.
  - Addressed review comments.
v2:
  - Fixed a compilation issue reported by krobot.
  - General cleanup.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (4):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  kasan: Add report for async mode
  arm64: mte: Enable async tag check fault

 Documentation/dev-tools/kasan.rst  |  9 +++++
 arch/arm64/include/asm/memory.h    |  3 +-
 arch/arm64/include/asm/mte-kasan.h |  9 ++++-
 arch/arm64/include/asm/mte.h       | 32 ++++++++++++++++
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 60 +++++++++++++++++++++++++++++-
 include/linux/kasan.h              |  6 +++
 lib/test_kasan.c                   |  2 +-
 mm/kasan/hw_tags.c                 | 32 +++++++++++++++-
 mm/kasan/kasan.h                   |  6 ++-
 mm/kasan/report.c                  | 13 +++++++
 11 files changed, 169 insertions(+), 9 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134603.49759-1-vincenzo.frascino%40arm.com.
