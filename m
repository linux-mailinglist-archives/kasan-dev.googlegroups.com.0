Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPG2QWAQMGQE7YXZP7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC10C313A2A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:29 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id o6sf1788353uap.10
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803388; cv=pass;
        d=google.com; s=arc-20160816;
        b=K+1zj+3btcF1arwmUDWZmBEqdNZMxZ/CKT12CzyakTQGhlGgpwoNlAgl7OEuKn04IY
         9TeUEF/DpxwcIJk62LefxmP9KPN3bu29+TlfCoUT0ylZOgFJvfQmtOMavJGls4F8IAxs
         j/VMFNpxzt1sKRLJlh1a3ZJ7gZv5ODZuJbaGHUoNN/ZhVmzIjdZyqSXwwPB6JDlXu0q7
         uUrs2GzgqQBbJBols2Q06BEMke++9UOzhhekl5sjME7MFYJNcaJHiGR8BOOEPIH9/TCN
         6SKa60w4CtLtRMxukR5mzsQo2X5SWy66VPpevL2labqPBQY129lFOckmlxbBjUUIdOup
         cuFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xu7tvGbNOuv9bvwSX5w5Qdq0ub4Gn8P4fhdggTvNQjI=;
        b=InzXV7Xn9U3oDKfbjgEqUjXhNW+bFajnhz+HvhtrkhYgB3OeKj/O7oPNoUgNxMKd2C
         tjnc3VGowlplHFoW2bvbTGiPaQqBpZMwz8PpqMkCQCH792LU8Rz6CDp1peJ363bRUxRv
         rnHhWXfcl0lUN1B1rMWqIGHgNm8r5lZqVYAvPJIH781LXXywEDMiHGj8GxzwQU3sXZCB
         E9qLpbqm0e5+xN8Yc4IAwO+SPEn61uuPEOz+g9dev2NG1eHiVe4rbi2aLXeVBjtVNpkl
         0gd9aqdiAYe0zZSwsw5GSMIUDLCkaU2BHjCJjMC8C5kR71junsIFvwOmz6OHhCOUaieo
         RRVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xu7tvGbNOuv9bvwSX5w5Qdq0ub4Gn8P4fhdggTvNQjI=;
        b=NJnBNQT2RqPw05EyhkLOpTw+Ai9qkg4wpg/wVVfotXnb5uWMvEVZ+gc7UmcErtJSjp
         h682wGnhQY102G840Q4Qipocu/aGA3qq3Ah4VEm5Dar1X3jgqsJ0X/VcdMzijKFwHFVu
         97Ez615+3R1e8rr3YpRw4XF0zr3OF7j5Ei2KFV1yPr28f1sAQPYw/8hKKPKFH3iMdjYD
         vTmHWGFFEOQfgxeAy2MNk2gkIJPOZp6pJ6p5wIiSVGMYx6OME9/hth6FVySJ/f5Wf8KT
         Hg432IlO9vToYlS5WwCDKxvv1X2mIYSEzcj42nnoSxzoB4IPk7n94WEouK22xG8JEsO1
         n1Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xu7tvGbNOuv9bvwSX5w5Qdq0ub4Gn8P4fhdggTvNQjI=;
        b=eW+V2FjwXpkt6RBX7Inp1S9E8AHwex6w4WoKjaf0ENqYb9rlWJz+Jpjlxzdu8lABri
         AgZZ5jdxsL/XylJKNZm2geoirCccooHhd9+mGmPeeVwqalbGk1EApev8zcLDjwrP4c0T
         D/puh+/eo9298IAOKeq2aLNRxnS+M6ENBm5s1SjQfLLUTXcslieD3x+LAkabDMBBS6IN
         D7ivmU2zatVgIVFPN74FxDaSxp5+RJFSsJN0XIskeNs3kHoeRxTWgg25PBm9RLszyF08
         IQRx3MIdlCmoznHxcu9zIn6PHeTL2RSIArwetngwebHtd6XXZ2ntl817K/LhswQr4vGu
         5ZIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jy8BqjC4as9k40JxJ38bPdFmqDLk9Yyfy3Kj3Hi0cowEt0/p8
	zjD/E4YyPdvGh7D/AaWO9bI=
X-Google-Smtp-Source: ABdhPJwTKuvzCHLXz5T6XKCN9e9B8EHqC3cwJ6Q3askozJI0+218/6DO/I47bPB1LylH0QteL3qS8w==
X-Received: by 2002:a67:2547:: with SMTP id l68mr11630219vsl.44.1612803388728;
        Mon, 08 Feb 2021 08:56:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:30c2:: with SMTP id k2ls1356423uab.8.gmail; Mon, 08 Feb
 2021 08:56:28 -0800 (PST)
X-Received: by 2002:a9f:3562:: with SMTP id o89mr2733898uao.129.1612803388245;
        Mon, 08 Feb 2021 08:56:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803388; cv=none;
        d=google.com; s=arc-20160816;
        b=BIbQmRpRBXN3p8Ftn7dc/F4kAQc1hFkn0VaE+Ol9Y29EZSAoBROV6lqgQ1QSXm0a85
         ah81ZaheWqFD0Ad/DYEGPSOboRX4cGoRYysb8lYPRJZO0CbfZ+Hnjo3NPJ5EJeBShRzd
         lCEDvosEl2cWVvy+qUlT5gy5x832kmmnC0vcBWb9fYlqIjdM5256JYlmUliAbwLhcLzI
         L/9bByxf+wjv/eP3nmonFpK++qXU4Fzc6TNkMkK0yc+YTAajmUR3+0yP3IP935jnOxh6
         OlvwA+dizauykkFxo/3KRYPQ2VvJ5swMWvprPdE7PWAS+062wjBgAcNS1Uec7G5d3x6b
         ti1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=JMxl0ikbzKLEug44cLFQFocWJTAoWqiEYthWX/sOBVk=;
        b=awsQtJtLK880Tqb9ivrNLqWTsYFfOSJs+1LjroXaqjcYglLw7poDGf/hbu/ufIxbuX
         t+rLGw8qBsIUJchaWwzqNPRwaqQZ7fRjiMOyK4c4GqOm+znakFBGFziLJinaVyzFCP/V
         XaiZW2EVi6Fmt/BCZfe33zrPLfVzIg3ptz6TG9QGtlHE5LmIMz7drbxCnaLN2a446dJy
         f9rICR8t/GaF8tOBwTm43m4yKXxaX4u8MtPA0laA0fbKroD6sdV+OWm1T7OYUMXU7u8S
         i7pV7p2GKFc8vseIJ7YWoVXW4NfaUCnUwDzyda+64jE3NlOxwS4zadXcx3Sy8Uz2eMIR
         rwXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j25si1091734vsq.2.2021.02.08.08.56.28
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8829C1FB;
	Mon,  8 Feb 2021 08:56:27 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A519F3F719;
	Mon,  8 Feb 2021 08:56:25 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v12 0/7] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Mon,  8 Feb 2021 16:56:10 +0000
Message-Id: <20210208165617.9977-1-vincenzo.frascino@arm.com>
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

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v11.async.akpm

Changes:
--------
v12:
  - Fixed a bug affecting kernel functions allowed to read
    beyond buffer boundaries.
  - Added support for save/restore of TFSR_EL1 register
    during suspend/resume operations.
  - Rebased on latest linux-next/akpm.
v11:
  - Added patch that disables KUNIT tests in async mode
v10:
  - Rebase on the latest linux-next/akpm
  - Address review comments.
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
Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Andrey Konovalov (1):
  kasan: don't run tests in async mode

Vincenzo Frascino (6):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  kasan: Add report for async mode
  arm64: mte: Enable TCO in functions that can read beyond buffer limits
  arm64: mte: Enable async tag check fault
  arm64: mte: Save/Restore TFSR_EL1 during suspend

 Documentation/dev-tools/kasan.rst       |  9 +++
 arch/arm64/include/asm/memory.h         |  3 +-
 arch/arm64/include/asm/mte-kasan.h      |  9 ++-
 arch/arm64/include/asm/mte.h            | 36 +++++++++++
 arch/arm64/include/asm/uaccess.h        | 19 ++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++
 arch/arm64/kernel/entry-common.c        |  6 ++
 arch/arm64/kernel/mte.c                 | 84 ++++++++++++++++++++++++-
 arch/arm64/kernel/suspend.c             |  3 +
 include/linux/kasan.h                   |  6 ++
 lib/test_kasan.c                        |  6 +-
 mm/kasan/hw_tags.c                      | 52 ++++++++++++++-
 mm/kasan/kasan.h                        |  7 ++-
 mm/kasan/report.c                       | 17 ++++-
 14 files changed, 251 insertions(+), 10 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-1-vincenzo.frascino%40arm.com.
