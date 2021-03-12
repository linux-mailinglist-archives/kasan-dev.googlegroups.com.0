Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIHSVWBAMGQEWA4OVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 15850338FB9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:26 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id u68sf9483391pfb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558945; cv=pass;
        d=google.com; s=arc-20160816;
        b=ULfBC/utEO+P5nZxL7HO/tnZwEKl3F/b7veu15p5kLvTrZ6cFO3bSQ/lfURUeHGsN1
         Vxb6JbCecja6nsiZJvgNe2YTI7M9hLn1dxFE6YChZ7+ZhgbRC3jLCeQlhP2SoAJ0tzHE
         stuynZMPAE1b74qUy7kHVcB2S6IN+ak/ZlXwKUXV3SaMxtP+R8p/fmcA17lCgy5KyFR/
         iqMVIPH/A5zEeOE4yY6naxy/AQyBNVnNbEIE9QCwN9T40yBdWn4MH+7iN68mbmWrLLTu
         RF3oskTmVIkh5JAcAsM6nmc0LF0oQJwU/6aFgU3BjTMQ59jtWtnFKuGoFMdIciYmA5Xq
         w2Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=J49IN7U4aG8GfCU1IUKqx38qJDne0N7vAuzngPJwGl8=;
        b=UDf+PrEd/LY+xAruvcKzpdpbjaEwL0hvuF2xF0c9Z9q4FR0CRNe0lMgc52P9HgWdTi
         u4+/NoyqPkTUjx/u0ALCMh2ubSvCVY8Ba4wI2L3bZWFd+wvNPzmclkycJYaEa+BuABJR
         p5jc+x4O/2+65W3o3Lca5i4y1nTjndzWY3ZSe1x7GjJmXeINGV67EdMwj8qtntfmJMHR
         H8x/6kmPJ9HpMzl1hvIkyJ49WJnPmWrDXBrCEoZ1KKzeglfhwshseyiXI1eRqKb+kLtS
         B96oj90I51fLxhS6eAeb6673yVrzRh/pTDJl3nhngQlpSc/1YtDjc88seVeXKGmvjyGF
         Tltw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J49IN7U4aG8GfCU1IUKqx38qJDne0N7vAuzngPJwGl8=;
        b=p6A/iSvnUNLpBakrwD+r5mzJdUv0LSAdaZSoyt9+A0EOQiNdE9eYXdFbiJNMZnTp4I
         dOBDUkm7r46XUfqal5er79kWugREj1gnL+ejM37aDOeRR9RoibxS9T3el9Nb9xTFIvUm
         +v5z2DKe+Nf2SDkmxq+11OI7PqI9qyoCjDrR6Xiw9WR/wSsSoigP1L7RbCpRZGMM8B4E
         tOF6kROm5aFGkIEXiDQR2tUiInv8y36QCQGXD/orTdDXCs/c5Yh7eAQUNUk2qltRNzZ2
         FdDL+5rHZ6zHaKDtVRwhekuBIpyCqWqAXIvBMqnIoemfIly49u1WN+IVvzJuiGmBujSt
         fl4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J49IN7U4aG8GfCU1IUKqx38qJDne0N7vAuzngPJwGl8=;
        b=N/jU2NCmn1ZZmfH17fJwidQdKGS0Y7vK1DQPbEAkS5qIBV0WXp8Yw5XRTV89e7ZeBY
         uU/mcsVJ60Salbl6nR2fHT0G+cCvN5Cvo2FtxQkl9LAI3OU9XwJWd48BoT4OZsR6Z2Am
         k/ZJRjtT6+2It7F4L5qFj95YNQed7r8Cu9XHJzQB0o62pdGjmE4UzIjueGrOYaXWtASx
         tWCOO8kvtcq1bV+FBpDANvhcwP5i6hzsWrnOscecHuN14yC0BFrCMj9LQ0Reaj+zMMVk
         aNgywZxz36rzg7XH8aZQlnC2UuaFFrbOS3xkmYLkB8088tgeMp9eoEi/6cdtYRAx6mFh
         ADgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EzMu5WWF1U7H+dMr5cFLQUyR9fJfJVF+XxGt5Rm9XvqxIJu3b
	ouOVEWpkU4mWGuNHWY1p0jA=
X-Google-Smtp-Source: ABdhPJzMx2MY0VhQNi1PHcsQGPCvbgTCW3kAmW0MCCCUNq1fBXx+vrvH51w0tYjeh8QIpjkKbnGTDg==
X-Received: by 2002:a17:90a:bd16:: with SMTP id y22mr14769951pjr.46.1615558944488;
        Fri, 12 Mar 2021 06:22:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9d0d:: with SMTP id k13ls3823440pfp.5.gmail; Fri, 12 Mar
 2021 06:22:23 -0800 (PST)
X-Received: by 2002:a63:fb11:: with SMTP id o17mr11907966pgh.282.1615558943765;
        Fri, 12 Mar 2021 06:22:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558943; cv=none;
        d=google.com; s=arc-20160816;
        b=o1Ec7xjDWYYjM6SOktAuZ/S+/X3yMn6j8kG+QHeTvICaoJ0WMb1NEJW/VTh8gpMF2F
         e6QblDxK0GQm/+Nrz9bFZNWKHEfd0Jdut5rNHWYK1TQvpZSdUuz2n4atu7gBOv1pqCYJ
         0mTb8SuQb8NSqUPvTT3UEh8BcTs5MdYkDtCBLBAroD104WtZgT0vogVIZajt1UPuLflj
         x4q41fcNp1do6iBw+Y04k7qMsYjo2QVGMW5UEMopsS5q7s8kFZLnEw2UyTO9G8aTr1bq
         L+QEi8qrTqm/s3spzaJwguVW//7VVVowgL9Fpue8bA1cRZwgiglELtPbBOc3Ew5n38Mu
         0gQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=tkZ+XaFX9RarhS9KCbvI9aL+kEMPHCPl3cmXpcxUzXo=;
        b=BA5IZ0dwGDqavaewFbLzJh2jpVcss1kJDSMPr20KEc//XuBjzM3nBFSw3HTSp99LaD
         4lDNFp3SOmL/Kd/LXQ4imdyGa6KpP7XL+booh7kX+UDtbtea+EEtug1O40CQ/uYTZfrZ
         DX+O12JR0VnquehAHE7O3GlZodNF5vFP9VcjYZNvXfDwNrWMBtzUNQc01miKDwPX8vdv
         1CLNgorMPBpTmYq4xDY8QeUFb1OEV+FeHiRXWFCUhA4wMxkP7HxWXbdsU7bJr0TF2P3k
         HeC3kfFDrTnks22weh6NFk5WTIj99n/lAKJLIDZHnC3tS2wJvzQlRfPod2skh2cIr8/0
         3bUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e8si284233pgl.0.2021.03.12.06.22.23
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C78AF1FB;
	Fri, 12 Mar 2021 06:22:22 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E40BE3F793;
	Fri, 12 Mar 2021 06:22:20 -0800 (PST)
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
Subject: [PATCH v15 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 12 Mar 2021 14:22:02 +0000
Message-Id: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v13.async.akpm

Changes:
--------
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

Vincenzo Frascino (7):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  arm64: mte: Drop arch_enable_tagging()
  kasan: Add report for async mode
  arm64: mte: Enable TCO in functions that can read beyond buffer limits
  arm64: mte: Enable async tag check fault
  arm64: mte: Report async tag faults before suspend

 Documentation/dev-tools/kasan.rst       |  9 +++
 arch/arm64/include/asm/memory.h         |  4 +-
 arch/arm64/include/asm/mte-kasan.h      |  9 ++-
 arch/arm64/include/asm/mte.h            | 48 +++++++++++++
 arch/arm64/include/asm/uaccess.h        | 22 ++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++
 arch/arm64/kernel/entry-common.c        |  6 ++
 arch/arm64/kernel/mte.c                 | 90 ++++++++++++++++++++++++-
 arch/arm64/kernel/suspend.c             |  3 +
 include/linux/kasan.h                   |  6 ++
 lib/test_kasan.c                        | 19 ++++--
 mm/kasan/hw_tags.c                      | 66 ++++++++++++++++--
 mm/kasan/kasan.h                        | 40 +++++++++--
 mm/kasan/report.c                       | 22 +++++-
 14 files changed, 325 insertions(+), 23 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-1-vincenzo.frascino%40arm.com.
