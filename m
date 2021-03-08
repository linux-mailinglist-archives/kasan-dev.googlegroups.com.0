Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBAE3TGBAMGQE5QP2NQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 904FF331318
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:14:57 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m5sf5959154pgu.21
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:14:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220096; cv=pass;
        d=google.com; s=arc-20160816;
        b=h0E2RsdtG6OAHh7/hEUJHTSImC/vsl2fIK1oGi9JJdPkjMSKuF6liBJap5atKy/wsl
         01lyYzr98fLaKjgM3tytewDEEWbcCUMdN2oov8pgTUl24H7b/JlGc3m+/4c5xh+XNgCW
         u/SwvFFMyRNnFqaLb0q8+4RjnyHwPkyFtJtaEc4qeETdh+MlV1ysiooLewI0mHBRx2sf
         u9nWQKSXQTwddWENj3iUyzKdgrgbDfU7auBWahd+CHPptxlsIkt/jVYmDRY7pH0CKsS4
         qa2pG8FtjFvjJiGF0eFUd5+YCKz8K/EHPwp6ODR76W20txJFKF6Uo26rq+bYaFcMu8TD
         F0GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pJSkQqadSxgD4TZbe8WC2+ZD+HBK6Jk2MUAtBJfGrsA=;
        b=p/sFXbGd44eK1to0yYNYLyfF6FRuTS7pt5QBmMAbTrTUeqU0YogX3pi/y1Hx3szn4D
         OOpuvxIBFoUTBM/kOvA0TUR+2G6Nlme6V3y19NiqDUagCLpCR2dT2j6zfk7LwURmyTe7
         BcdyU3hmYEDiGFCY0DYWBrL+kpwEiCP0AxmZ2xvAi5Dnu4+LBqwu/rnzjk6az8raOC/O
         wx5DrRUjVHynWVVVAd0tsIPp2+gHiHVwCuKsCn52rQbI+6N0K9OMMIm5iM0grCu2QM8q
         Pxkor5VfToBPt4/aUbIlmeLmKtz2xBizTyA8koL9hXptooUt1NiQZl9xfu9dangq9cel
         rcwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pJSkQqadSxgD4TZbe8WC2+ZD+HBK6Jk2MUAtBJfGrsA=;
        b=T4XgAWhbeYxpz7IctO3UgUNyBLyFlZ/zSwIqSyvxGEHN7M2Jq8J5qz7EIKnAKSa7dj
         JEPwTUjgOUCn+f8pMZtql/uw6G9I+Vsz+AC/9H8kNnBMUWKPnn3HoXrVOwEA3Kuin+/O
         +gxMX/eFLecNw0tjsI2vz5LoM18zs1kf3uWmZYNOMhFQIrq7eWD6XAYUWJkKB2nmWN/k
         hlpjMV8Vy6r4NIIC5kM3a6WxYcZPmHr+qLxWlrXuy8JdXKXu0nFfg1e319Mz8zP9eqXz
         fw757M+WlcutqN1E709rqJR937XN1ELcRdcxk6jSrUSSxk9SkFPzuoctnqeztD/mibnG
         z/8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pJSkQqadSxgD4TZbe8WC2+ZD+HBK6Jk2MUAtBJfGrsA=;
        b=BJ3cYoToud/V0rBPJFzDkQZ1c8ausM2Sk+ls/TJH8XUbMX/iDzbS0udcI29Lxlliku
         520qGj8ZT9nPvn4Jyhf9GJF4aaAIqazw6Z9BvumuUeA7glC6lHIceQDW0vIjohjcyIsB
         GFJyQJ5qUni/Gt58mfsSrS4PiQGGgsNqa4QSvITNtrO0eCcalnm206EgFNc9wCgeIB8d
         cZp2uuJ56/FYoHlysL1FjQ+O59U3/G9CWHdLU784QETxwUkYvoqCgBrSXvChxRCglrLw
         PqxLgv7sU7oXST5VxlvRgdY8t1DwNDQRBvorzmPwaZGr9qsIAU2z0FuOjmG9KsYEaMKm
         nd6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fsALJvvKpu2XesdkJweUqAZVtrBGEi7l4LxrQePpFRjwDjcDI
	znZyjaij600JcRG1ZiHggzw=
X-Google-Smtp-Source: ABdhPJxwOJ6p1G2Z9sKhNyXKo1qrEUTgCHrmxBIn18NqPSnfiQNrq9LIKSdTe9fSVHkilbRZfbGrsA==
X-Received: by 2002:a62:e502:0:b029:1e4:d7c3:5c59 with SMTP id n2-20020a62e5020000b02901e4d7c35c59mr21679614pff.51.1615220096225;
        Mon, 08 Mar 2021 08:14:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:f212:: with SMTP id m18ls1860441pfh.11.gmail; Mon, 08
 Mar 2021 08:14:55 -0800 (PST)
X-Received: by 2002:a62:3c4:0:b029:1ee:9771:2621 with SMTP id 187-20020a6203c40000b02901ee97712621mr21260673pfd.47.1615220095663;
        Mon, 08 Mar 2021 08:14:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220095; cv=none;
        d=google.com; s=arc-20160816;
        b=AiTB06g5ORpZH49pJDOUSeazmjrevYEBCbUFZq9kCrRu08HY2u/qIGFAO+mFF8VENf
         BhVe1Vj5ZV15ge59ALZ6v0bwajDlxCrc7+5/DhlUc5vpRNcRGaPtIAhoe3Y6mkMTh4eq
         RsVRdmZ3p4ulxXvRS+kOP3ndTDJrDL0Zg5+EYzrgz3p5RiJjiYPI5G0chljKUVuCPpG6
         pJP5AWdpg1rSzi2IuZls7nVoX2DShoRHDOs8PIyo9DjhYWRHsXdybnlx8u+q2vtlx3/B
         8jyqo8HggsruB/rZMtpWSH+cspkyPnkqk8LMaOfl0ZaWDLp5AcETSsKKHBbt3Ad5h180
         iqyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=+4gXhfOTcRwpXmW1T8TfYkYek32Z84QPssVvIW00keo=;
        b=YvKSZDReBUIRiCD7NYDX7YTElAAddyMMdWssjit0SwCUHBH/MaYFfVPHEBEvXIimtV
         EY5mRm29D2cbJBIyNh4ORwmpSMtIKllvFiHSKNDlX2t6wd3OPI0HnoKWEls6L1GnhK4L
         8uGax+YWDC2bmlMsoVXTIKu6nSGTe/2Wgzo3G6Hcmy9l37iTV+mzVW1U7dWYy2KaJcHv
         GDMhhUB2HLPZmmPMyRbAqO+o6HsFYcN4lVnQbyuzz88Ns8d9VLATXPXHnvyJLV7YqvXE
         2dLuho/mYK1dTPjibUm9hgtnafmg8mkq44bRXHkI/Udjv7hQP4PlNn0x0XiCE6UoZnjP
         gq3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e15si733267pjm.3.2021.03.08.08.14.55
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:14:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D8A14D6E;
	Mon,  8 Mar 2021 08:14:54 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F0B1E3F73C;
	Mon,  8 Mar 2021 08:14:52 -0800 (PST)
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
Subject: [PATCH v14 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Mon,  8 Mar 2021 16:14:26 +0000
Message-Id: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v12.async.akpm

Changes:
--------
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

Vincenzo Frascino (8):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  arm64: mte: Drop arch_enable_tagging()
  kasan: Add report for async mode
  arm64: mte: Enable TCO in functions that can read beyond buffer limits
  arm64: mte: Enable async tag check fault
  arm64: mte: Report async tag faults before suspend
  kselftest/arm64: Verify that TCO is enabled in
    load_unaligned_zeropad()

 Documentation/dev-tools/kasan.rst             |  9 ++
 arch/arm64/include/asm/memory.h               |  3 +-
 arch/arm64/include/asm/mte-kasan.h            |  9 +-
 arch/arm64/include/asm/mte.h                  | 36 ++++++++
 arch/arm64/include/asm/uaccess.h              | 24 +++++
 arch/arm64/include/asm/word-at-a-time.h       |  4 +
 arch/arm64/kernel/entry-common.c              |  6 ++
 arch/arm64/kernel/mte.c                       | 90 ++++++++++++++++++-
 arch/arm64/kernel/suspend.c                   |  3 +
 include/linux/kasan.h                         |  6 ++
 lib/test_kasan.c                              |  2 +-
 mm/kasan/hw_tags.c                            | 66 +++++++++++++-
 mm/kasan/kasan.h                              | 29 +++++-
 mm/kasan/report.c                             | 17 +++-
 .../arm64/mte/check_read_beyond_buffer.c      | 78 ++++++++++++++++
 15 files changed, 367 insertions(+), 15 deletions(-)
 create mode 100644 tools/testing/selftests/arm64/mte/check_read_beyond_buffer.c

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-1-vincenzo.frascino%40arm.com.
