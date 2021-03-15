Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHV6XWBAMGQELZ44GOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id A693433B3B0
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:31 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id 130sf24477235qkm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814430; cv=pass;
        d=google.com; s=arc-20160816;
        b=TqdihcbYtl9Yo3ZAFUpK35Dbn1CKfGndqizq9MhTgfWvxRveyfFA0epoG+JFBtJjJS
         sc/RGr8LTe7KxOOq5e1OOGGtnzoJLHkZH2bqiic2Bzqi1XcyAfHScyD9BWPQX3imrnYX
         Lj/Rw6xh6Xj2ah+nZSMZAyBOw35sH0EaEWSEvG8Sj6xFcRiq8+PXT2pbapzIgU7WDoYH
         Mcd8kbt/NZ1hQb1U9qoqcJAdx4IRZtF/u0qKMXASQEmIIfqq79mIZipJOtBvRqVhmRVw
         s8Ui4os1pEdck1CEVq40AFp/zpqeq2dmTtIklW14clN5vtSdMrRJL7AZab3DuYvSBvHk
         6Izw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Pw0l6JI852MnHoJ4+dQtJg1C8NP283q1GmX7QxRF9oo=;
        b=Bhlu4Abnhh5zSwwcG+YUmQGdjOnB84IwQIP5AZQRtHIjko2Xgh6hrp2IC4yEDc0I2o
         Xre3dYN1T7Hf6MBrg4IO+u5Wo6e30f3bH8zCr5jWoYM0GVQ7UeCKi9h4z1CVPe7i9WbG
         h44Onuvqd0azcXhEXGFoPVXtBookB5tYGbZ/5cZSk4o/TnpLH8hFviVTzSr8aBLjGRqB
         usfeS1RjsuRDcDHaq5RK5GnV54Kf4+z4JjjJ7cPTMJ33d6N64ks8TBLtnKDf3e8zy9xm
         C146p4+R83ImEVMiNQxeChyHlalmUfm7fIqM4VIr7TS5Wly95HFdFL2OfDy6QDJJzswB
         lb7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pw0l6JI852MnHoJ4+dQtJg1C8NP283q1GmX7QxRF9oo=;
        b=s7oxC6/M82rh+jxH57cHuiY2YarRfgRCAidPEQZbmsbvc75FsGkJC2W1by26QEA/55
         zAH5yxfF+264lZhbzxZUeg3ijtXr1Em1QIcwRn5wliBKLkQMXvhzMVzqGnWDVrXQXRAi
         LaA7aDTwtM8+b0NA0E0n7b8o6BEoocL81nUTnIuEay9V70AOO2I8qZGH554cfxQJDR4q
         EYKXqRxysIYcNEXT76I70i5EAKKqjuc6Hhb/weKPFNRjGvs3OreiBIxM5T6NsUt/zJPF
         WwJ0VFUcHKeqX1jMKiSa0nZ98nfcYqCDopkpeRQlzxsGl5ZtVWzAZ28OkggSFR/GHwtN
         iJPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pw0l6JI852MnHoJ4+dQtJg1C8NP283q1GmX7QxRF9oo=;
        b=iF9kWcE9H6dx+55tfZ+4hf4iGNsIzM5cKOVKZTgIlnMgkOMmQ0VHrBGUGYKcmBsX1x
         VvjB1OiZQJT4o8sCJUmBQXkxrA2vud20kmtBZDWfN8GoanNEDardOOr4Gooekhn5lPcF
         x2LTDjtFfuOIQWRH7Mqz/oF/6yOvDPSfsaC1aoHp2zYjJo/wnkk0H9bh+eH4dRPOccfQ
         MKg1p3AjNkYN7gCyjVUSURGomIIf1wH+nqJATsbrhsEHkgJ7KSidhtu3kYrTQKaLkt6E
         rEMyi3m0ze1HhB4yCwEa+7nwRw9ralh2wprRvPSOo+mzbzR+wMKfqkN2u8RBL1AZddty
         Nijw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vmgzxu3lHJq95fLQosiE9zz/ojtoqvCyOWjCyOVIppres2PyD
	MfSekVzlNpCkbtHXAc8Zk6k=
X-Google-Smtp-Source: ABdhPJw3Gs9VUAEPG1Nw08DvnELDs86Gx6SEwpQQ2kbB39PL+hEdD1+dQsmzDjoToMXd0q2aGlY5AA==
X-Received: by 2002:a0c:f053:: with SMTP id b19mr10682115qvl.7.1615814430637;
        Mon, 15 Mar 2021 06:20:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4e89:: with SMTP id dy9ls4284641qvb.10.gmail; Mon, 15
 Mar 2021 06:20:30 -0700 (PDT)
X-Received: by 2002:a05:6214:1454:: with SMTP id b20mr10628406qvy.24.1615814430101;
        Mon, 15 Mar 2021 06:20:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814430; cv=none;
        d=google.com; s=arc-20160816;
        b=nLj5V+2Q9ZoWUelEmhbWrNH5ktSQtQYBsgP67etc8AwfUklnXjTjU9MTwi3UcTxysp
         i5Kv5W73AnjwaNkEQR4dvAf8tYomq5cAWuEksaf50/JyL3Mem57Ci7Ut8caZpXJgiyUV
         i1Aa7Vd3EccReAmRk1s3O9NPSWG+wmh1wiS1WngKnbS+U6NRLqWmkKXdhVaVGSx0+yNO
         8OBAWweiwgKG8IPOEk6b4TUkJi9YYtMVye4knVZkv92B9znISO3CWZ/l467ZuT4z44TX
         rTzpxMNtNCQWnaiaDAdRwhe4h66ypAHyJNhbh2LlKKJ2oSOdf0sYfkwa7VhB0ieMS1qS
         QwpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=b5BLKSyqe5FjHG6O9bjWMWPjGaBHovUifv5dE66U9mY=;
        b=f4XN8RlX7wVqXE7gD6diOs9lryjuDOg00AGVOt3D+cDvhq09s4hva5/82q6dwFfNrz
         rnYlew/Ms1w8Mb9+SSZH38cKcA5ZMXr2uzU25b77UUlr1sR/tM+/piU1mqIRig1f1YaV
         C6ih6vvN7nBsLOtnoFUexFGQ/m+dJFR2y4T5b/Vb1wlI+xozEvCdIBRZL/JfaoXh4BnU
         Vi9GoPMZmO4k5dhkIA4yZ2jARO89dBPE81Uzg8cxag6f6RNCccgjodws/cQ0nso5EpCV
         GEOaW1vLD9YIA0zvfY+Z85JBZbeYcqL1ipsYBG9GZXzw3tYBahf1tZkgRFzayIiGJfxb
         XK+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o8si505746qtm.5.2021.03.15.06.20.29
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2B64C1FB;
	Mon, 15 Mar 2021 06:20:29 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 472C13F792;
	Mon, 15 Mar 2021 06:20:27 -0700 (PDT)
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
Subject: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Mon, 15 Mar 2021 13:20:10 +0000
Message-Id: <20210315132019.33202-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
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

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v13.async.akpm

Changes:
--------
v16:
  - Rebase on the latest linux-next/akpm.
  - Address review comments.
v15:
  - Rebase on the latest linux-next/akpm.
  - Address review comments.
  - Enable KUNIT tests for async mode.
  - Drop kselftest that verified that TCO is enabled in
    load_unaligned_zeropad().
v14:
  - Rebase on the latest linux-next/akpm.
  - Address review comments.
  - Drop a patch that prevented to running the KUNIT tests
    in async mode.
  - Add kselftest to verify that TCO is enabled in
    load_unaligned_zeropad().
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
  kasan, arm64: tests supports for HW_TAGS async mode

Vincenzo Frascino (8):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  arm64: mte: Drop arch_enable_tagging()
  kasan: Add report for async mode
  arm64: mte: Enable TCO in functions that can read beyond buffer limits
  arm64: mte: Conditionally compile mte_enable_kernel_*()
  arm64: mte: Enable async tag check fault
  arm64: mte: Report async tag faults before suspend

 Documentation/dev-tools/kasan.rst       |  9 +++
 arch/arm64/include/asm/memory.h         |  4 +-
 arch/arm64/include/asm/mte-kasan.h      |  9 ++-
 arch/arm64/include/asm/mte.h            | 48 +++++++++++++
 arch/arm64/include/asm/uaccess.h        | 22 ++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++
 arch/arm64/kernel/entry-common.c        |  6 ++
 arch/arm64/kernel/mte.c                 | 94 ++++++++++++++++++++++++-
 arch/arm64/kernel/suspend.c             |  3 +
 include/linux/kasan.h                   |  6 ++
 lib/test_kasan.c                        | 19 +++--
 mm/kasan/hw_tags.c                      | 66 +++++++++++++++--
 mm/kasan/kasan.h                        | 40 +++++++++--
 mm/kasan/report.c                       | 22 +++++-
 14 files changed, 329 insertions(+), 23 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-1-vincenzo.frascino%40arm.com.
