Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB344SWAQMGQETDFVFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id D73A6318EB1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:08 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id t3sf1402943uaj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057648; cv=pass;
        d=google.com; s=arc-20160816;
        b=KuatbB7y8XoMPvf4misJbx5HTrP/2Tz6xtLbu1rcHeAxNgWCo+7jF0QAT1MXSZ9uj2
         pK2W02S3PXjd7MsrSpByLQbqY51C3EK+6TE297jKeCh5pIadhQKupfVryMSbsWG9fhVM
         c2jmED4UDH4C/kmEo8xcg7oKSITLp+RzCLBKNYcV7xgpoxOUB1SBvArLmCcRl9/KhrNT
         1Ppta8p7QvUBTgcPlR/aR8Op0RTpOcC0xMinVHfBT9Ms6mc7n1+jlR6kLaogftchr4lO
         g7Gu/oh+VkRgWrV5kDB4uiU7OmImpNealtEo7tcVCSV10umlCevWRz+U76oTmbm6+TBb
         ETwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GzRanjgZ4nmU7Y+T452N7r38PLlHq5weX/A48wuUAN0=;
        b=zDrQKPV4uM+u62XYjBMVd54nhuU3VIFMsS8q7RVrZLHCZnCcghKHBBIxHXPywWYlyo
         DnSZ6rQcuAuvJDBwf0mvChpaWHebK60+DRTULm+Cp/NGbOZOkh0oT5K9VAIHeuMt/QTw
         R4lkhxreyRGCTzwRzoVOFJLASb/h2TU1dUHikBu0Nom8BkBtuozxw6Jw1QxF5My3X8a6
         atQoCMZJbk4WBG6JI/lgSSyRZTA2KUbCIPWBP+q7GXuO+PCmiWELY+bojuhtmVCqdd1n
         HvLx1WNOJIJDXbadB1zR3ihV2yHcEp2PDnoGQ0BoXx1OU+M5vwAK3qbFmJ3u6CUrkt9I
         sMpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GzRanjgZ4nmU7Y+T452N7r38PLlHq5weX/A48wuUAN0=;
        b=fTmTO1S9GxpzRZWrGOjW/Aeg9PLkX2L44ClxQHBedh2+uv9bXwUYjRgqYa0yQmIahL
         /4J7jadFQ5u7zhkkohO43O+nXRm+SycW3nuxLI9woiQsv0ps8I0ldbQkWcWqWttB3Bir
         pyl+dX816BvDkTe+crB4hiOBWTdjE9Jm6Y9P3JhUs9Nm0TZ7CIbiZytOOM4k7Na9BalA
         NYDogGNjMl1nkJXQaCxspKl1tOmzlJnQUaoSeC972g3Je+drsokhBCifiQ5/oCJHaXnm
         YZ3Zro3FFd0SB/3kc+iBsBG8vBL7uQK94eHn3DYIgt9JTRulciXH305yhz7U0l/Io31k
         ma2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GzRanjgZ4nmU7Y+T452N7r38PLlHq5weX/A48wuUAN0=;
        b=qEcF//Ym/Hxu0ctq3nyHfLb8wURJ//865wZAMNLmJ1gjnBoD88GylJmJl2ePZQrrPV
         QuPe4fKEueuPa5rqj3rvqpKGBgW6/zjh45U32qhx7fxk09K8wt4pB6qcHYoE18PWBPAY
         i/DumVoKNTQM7DrE+FjXfBrIYQsVw8kcbcFnhihvtfrtpKS5RMMPVUMXuqShsiKzECIf
         m2B9G+WqNf5U0vwkn8gMWl5bi0t/cokeC0JghbFQSyfUNfYrCn9zW8I9qPL/VgSo6mPk
         o+q93n6ti7gNlHnb/pf0YtfZG7uAWyYTiMnQlbMY2b9ZJd4Iy/S3Sx1X/Lj5WHXHR7FV
         kPjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jHxbD2IulfTCD/cy5+UwyXJGf37EualNBrsX4Tuj2V/0+8kRZ
	6dVi33XaLl3ROmNfjudP9is=
X-Google-Smtp-Source: ABdhPJwhXi/RueT02Vwajkv7fgxcy0oCwOi0KH9omFL+vDIWmtmgqmx8zxStxnicIe+gVZ6rgOQtcA==
X-Received: by 2002:a1f:1bcc:: with SMTP id b195mr5750911vkb.5.1613057647932;
        Thu, 11 Feb 2021 07:34:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8886:: with SMTP id k128ls684181vsd.4.gmail; Thu, 11 Feb
 2021 07:34:07 -0800 (PST)
X-Received: by 2002:a05:6102:8f:: with SMTP id t15mr5350805vsp.19.1613057647515;
        Thu, 11 Feb 2021 07:34:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057647; cv=none;
        d=google.com; s=arc-20160816;
        b=ffAjSUMlEvN6dq+5H79/wBKirgIgWjjp8d0EfhARN0zNZyX+0VUqr9MPcMI8nrRFZu
         m81Inw1oiMZ4Hbvih1+qFSbpzjToCaU7hvKLGgNwON6553mUp5Qa+Dpf8Yz3NtH3DaFK
         R5FcSf1Qlis5Pb0UXUyMPeh04rvF2va/Jo3O9nhn/BN1R5S1wqBy6/nFTMRgWtiLSnwp
         H6BwTa260xHtQ376HAaAmJecPNGmZ2hWD6+DrY6voHrpcQLOJK0Ht56o8A9BQNDJQRwW
         TRJ8P4cYTioFbk6MtStmn4L1y3vdKm9IfthvNDhVmcn2yUSa+aEz22H9eF6cKN9+uOl8
         5H6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=oY739KWsLHG+PFr7fP7G8D2rWk5YuKouZ85rjBvAI2U=;
        b=XyNBT6RaXv8hXM7oHFB8wUNw9Q72ve2Yg6i7ThuRMH2wp5G1FqX2o3B2HJ5tNmOwqM
         zwnBVZEFPzuzDm75Zs3YJRhg9yqW1HVdDTVuzFRyNiZycDDNTRFCm1wosmw+lHm1dKiI
         xU9Qh9/yDtUyYYgIMDGRm11hbho85soRXhVOdtgByJYXv4ldLSN0kb4zSfqlOXMqKwc5
         +SiqOvIp0Xk40edhvjKa769P8ebjj/fSWS5WlrXzMdFSyapMG11HybNqqwercPWKwlN2
         y2RTfOY14Dk4RVKGbHY3EEgtJqibdUGomziyvOLe9W7oGj6qzh13OfeBt1CV5ER+FfCg
         m7mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z9si452096uaq.1.2021.02.11.07.34.07
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 82F0C113E;
	Thu, 11 Feb 2021 07:34:06 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9F3F03F73D;
	Thu, 11 Feb 2021 07:34:04 -0800 (PST)
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
Subject: [PATCH v13 0/7] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Thu, 11 Feb 2021 15:33:46 +0000
Message-Id: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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
v13:
  - Rebase on the latest linux-next/akpm.
  - Address review comments.
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
  arm64: mte: Report async tag faults before suspend

 Documentation/dev-tools/kasan.rst       |  9 +++
 arch/arm64/include/asm/memory.h         |  3 +-
 arch/arm64/include/asm/mte-kasan.h      |  9 ++-
 arch/arm64/include/asm/mte.h            | 36 ++++++++++
 arch/arm64/include/asm/uaccess.h        | 24 +++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++
 arch/arm64/kernel/entry-common.c        |  6 ++
 arch/arm64/kernel/mte.c                 | 91 ++++++++++++++++++++++++-
 arch/arm64/kernel/suspend.c             |  3 +
 include/linux/kasan.h                   |  6 ++
 lib/test_kasan.c                        |  6 +-
 mm/kasan/hw_tags.c                      | 52 +++++++++++++-
 mm/kasan/kasan.h                        |  7 +-
 mm/kasan/report.c                       | 17 ++++-
 14 files changed, 262 insertions(+), 11 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-1-vincenzo.frascino%40arm.com.
