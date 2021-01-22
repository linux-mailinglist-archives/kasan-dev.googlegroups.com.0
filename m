Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7W6VOAAMGQEVSQTTFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 04A2930073E
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:30:08 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id d38sf5670521ybe.15
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:30:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611329407; cv=pass;
        d=google.com; s=arc-20160816;
        b=KL7UDmmTF2FG0TiO/DUlVjiu5HH6fpfzccDaK2VVfumu4XM1mp2DeoFtfqkO/4/I9b
         kSlG90HNjOlWCGdj8kwVPWo3ews2sfhJybZU9Jrr4o/4IIOR3LQ0tXbjKQLifzgyjoHD
         lwo6Zllkx0LQ16VrIazT/DqlNbUPUoH+eUw50o2dDVwz8o9ngUdPZvpYJaIpoOKI//r2
         wY4C4JGaKw6RODhRDPUfiTgGbLRWq0pidzATZAUMYrBeXAJuvSAAmo8uXdWoNR4rwbon
         dmJNvKDPWn+68ArcpXXVP4akveeo5d81ld1qXMdA2xjqvz+h/1e4dylfzFGqeTbxPY37
         AwmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fhIZZorIAPz6S0PMy0uThZTAVp/9Ap/xG6ACey6ZM84=;
        b=iMFgJFJobUYbzqz5DcJwbZFI+FtEfq1hzmeJ5zNi8MfdRbVzjGaFd/8dc3e96gvMIi
         EavYNkxsi07BPRm277e77Prfqk5sbOJPZcrwFjLEIOw6geP2ENBl4lH7L2HHmlsBvNdz
         mNWHaP5abWEPOcumhCoeODNOBC7ybxu4WFixcqdxA3p9IKey7QsQO9w23P1pK8lKj1Qv
         ajO7PfQZPI++VfnRu36WkAvY95Z3A/uNN/34ydqiD6t/d8aIpxZkCkSuIhEu7VMM53kT
         djogC4o2bbLmeiUBPaD/FZdAj1EeFNCp7BIygxDkhs/03zWREpJlsLVjf52vrIuyxpuT
         zh1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fhIZZorIAPz6S0PMy0uThZTAVp/9Ap/xG6ACey6ZM84=;
        b=ivFErCxTL6kJfs8UfXJXMUsQB4svROOQ9W5FF4z48MllTrSRAvxktioZpNqtO1A9VY
         Y2PcrgVlg6BLZMsX/qQWtiu4TcS5qhHjzqVLsWyMBBDvYhgSP6FlkJMHX2tG16AdKCAF
         PRq1YoIA7xAwCkwiTkLCgaDHbm1kyZXpsHBOjm1oK+FLk9Iw0b/IqqIL/8CP2j82iTDJ
         1MOytPds6cT0987VVqsjQCwIKUnFD4g5ikM6fKRmnNaw+SMJHzRV8nPlO+qobRyNY/AZ
         +49UzTvxtiAEyOkslcJms2eGGIjpeUOShdqK4jLwI+WK2NsM9tJJ6Phneq5176oP/CHy
         Aymw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fhIZZorIAPz6S0PMy0uThZTAVp/9Ap/xG6ACey6ZM84=;
        b=LsopCb+0tnBC7g8GAxItCgb0zNbDTOdZbIBacDU9B92gNTqlukynJWdEqVL4ng6oGc
         qrdOUKfApcQCfegpzcoxZ1NCQ5CTJGgcM8ti4ccqqH7WbGaTCGa1adK2znd16rt0shin
         St6yYC7HrNYsedBNpATRal4mdgaLRJFetqf/QQHNyXfK1hdCTCnql6/njfXjSCemSPxP
         nuztpm5lwLoPp2iopjMmOjaxqh3TD4VrIJXuLcYKtHpUhFcitw+BruFCtNxYm1YEfaxm
         3yQOp/KxTsMWGDayUtjg/ifaW6Gqxq89RAXCDNZ2yqlgbYuhXvAiO+YUF6+RF4ubd4BX
         MB1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qf8GAIiwqOzKPzGpONWBhrfXtK/3/xugEsGzcSPIqJ7V0tkbA
	vEo9ZTSVcjSr+GCtTUAy3dc=
X-Google-Smtp-Source: ABdhPJw7OFXds/2M++5jx66jp1OYhQpFKr/Nvh/3E5ahOfb2ilMjanHWG52CSQW/T2ycx1PYB6/K4g==
X-Received: by 2002:a25:6951:: with SMTP id e78mr2985813ybc.51.1611329407035;
        Fri, 22 Jan 2021 07:30:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:515:: with SMTP id 21ls2822596ybf.9.gmail; Fri, 22 Jan
 2021 07:30:06 -0800 (PST)
X-Received: by 2002:a25:d601:: with SMTP id n1mr7530284ybg.121.1611329406607;
        Fri, 22 Jan 2021 07:30:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611329406; cv=none;
        d=google.com; s=arc-20160816;
        b=mZr1FYjTNTTIdkgG/Qe7a4/mjzYpoT8pri7jPegDcG8BQGrdfn5M3HJcJKsSj1ffYE
         FPLyKugWhNhxmUG0za5XdANYqcmNAY6VjUc1TEBe5PjUFmkO71IMFLgThKpdiZurOYU9
         QZDzbGHkLBON5G46vRTWuP/C7Xk1hJG3lyG4BIJsEJ5voTvXVD17IG5wQwL1MPLU5/EC
         7eYA5sbTdsOmxeN4YeMmYHyrrNKW91Sx+eZVpcMnhsaRBaJkX18ICoFSRFOqfuRqeXFC
         7xZ3M2oE6bnMTpEnIggIqc/6TjKYgO7Ra6eWkw5jDcHDaybRYFXd+bA2U+6c2xMAaIkV
         VcOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=6mQB7hHVxSg1aWCmij++zkzXaBOSX8/SRTrljSPE3E4=;
        b=Xln5NrXJP6tTccuFNJl1B2updhi3aooihb0Eu5jwipS1zCVB4ZaWbNst0j2fWAmxmR
         OpZ6Auq2XJqMGXX0kX/sJZOtpHMVsJAxdj1OdLqUXqeQI9G7v8UUQVpKTX/PnuFYUrGI
         O3qazt1nU6sZHsJAEFYtnZ7PUwMtiC+sCW4S4FCkS4cqmTQSJQvzpMw/U9E8PeCTkCgm
         OiiS5kXVERaIHIhVRO5RfffEYT7FGNhKGkdFNJMpnPxjF+ClUlJ+5EHlYXi5kvbse/IF
         qGap4qI1BT7F4iIrgBo/fZ/7qwy4Gc23gPTPdt1WVdtpCtZW+UCX+YTtnYPfuizam3ni
         e4sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s187si915355ybc.2.2021.01.22.07.30.06
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:30:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D2EF6139F;
	Fri, 22 Jan 2021 07:30:05 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 24FD43F66E;
	Fri, 22 Jan 2021 07:30:04 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v8 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 22 Jan 2021 15:29:52 +0000
Message-Id: <20210122152956.9896-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122152956.9896-1-vincenzo.frascino%40arm.com.
