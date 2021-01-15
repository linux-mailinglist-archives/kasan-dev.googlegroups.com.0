Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5UHQ2AAMGQET47BG2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 35CED2F7824
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:00:57 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id 189sf7719983qko.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:00:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610712056; cv=pass;
        d=google.com; s=arc-20160816;
        b=0iBJ5FeS+eE9sMmRH/FXkZS60WoLHTKa/klyYwHDl8MhKbMmLXIImJ3poYLjVAOv3U
         pu7fKh0taX4e8z6bMhX/WYk5ZOq1RLInwgmSolh5kboDLG3HSrm7/ge3vLTtlHTFTlzE
         bRneJ/y2LRgHQgkFcJZCc12mbPGlgIrRcUrXmRlAF18O/sfiRFM1MfIOXj7iCVSUT7CD
         bT3G9u+4meZNxSD3Zj0RHDMSW6YZ8AdCRy+c/mkjVnMFRJeo8DCA/W8NfXwAd2ni/ziX
         bWhyOI8rngeoMXDQn1VFCZriwQ/SOx2zHUte0tN53bEe5IeANWAZneH234LealeByuuJ
         2NEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=RTUKU+s2JnYpxVX+MmKQZGRfLSUGeAgeYTioBoeM/QU=;
        b=ONDe85qmCaQxg0TZai1J/XGBZqAMhwP2pECWEnKWonVnkRamI52kIM3xJQkp8EUsqE
         oBaiTDfeUlwakbaTf46U/c9pcEQUxEjG3cn5ic8T3IwqZZcI3PYQ6mK9b58mVA1ji3F1
         Yv5leQBaLvQJ07KdM7AxR3qvRStoKmiS2n41Hzrwz6SAwJWultu24T1hwz/47FqxfPbw
         gKXeCcoZjbYxGrAmufvZCdv8skndHTaEDGq7EhlA8+7mz+v8G2qTFiDfbt70wRaoxJJk
         k7L94Tt6PKRxe/0dgs79NgGbfIL5sfdtHvycaixTdmZ+BVlK1U+/YZbDt9Cyb75DfHJO
         zQFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RTUKU+s2JnYpxVX+MmKQZGRfLSUGeAgeYTioBoeM/QU=;
        b=pXKoOA0Xe1fK9BU/x4peEYHsNyFoQr63wPZE+tzJEdPQJSjza3m85M2zjq9qMx1f1v
         +0UIWDwMJsauoSQyaYCTDhr5aSOyEPfpX6Wm/+94XuJ6ILKewSay96or/HEtgjg1U6fD
         GrfBwjqatAw3ORaZrxGFTf64h01GRHImdu9tlYGSkV2G9qYsfqwkL4AJPWWDQU6jlfJz
         F6d/crpI9V4btslpC45bkVMQTF65q9wXWh50zjPWAFWrPxdHAD9UZWy1wrtVSdMcc6o/
         pJVhV10Iv/LFYU2QzCo0udzaWOFOK19w7AlCmFLpI7suugxSUnd/J3SXLTiTkuxXWKSh
         N9BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RTUKU+s2JnYpxVX+MmKQZGRfLSUGeAgeYTioBoeM/QU=;
        b=Zu6UFdN5whuSd6oRJ7lP5CLMFU95VkprTioLyNkFrYTlbrmf1JezKY5A7Tn+fHpiAM
         sKFnUBzVlo6/EVJJwTU4Juj7TOFWkFV1moJi0MqDcg4xJTDwTCnZz9NCo929vj1yINCH
         fCBPpuUWsWMV9SjUTu1m346P0eaYyoJPiuxyIvsE8ZgD9XUTaLdlehhWnbEffmkIlF98
         mJwPezhnqI45qvdsa0Vks4ldom0Y44CLbEtecTspqbD/+FwcdcL/4q4DgztSGtTvebY5
         LXdIbINnXTh16q9uYKbmvTVcD6qa6QC2EalHVbRDJCrXrhTwKfGCy9gvXTsMkDhHaHgc
         UcfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aUAblIJjs3H/E2bCWa4DbpYzbR22TxLqHdQ0iiW0Kmvt5wOH6
	65wUj+vptQ47koWwdfOwquw=
X-Google-Smtp-Source: ABdhPJy+dP0cBia5Ay/0ojHZWfD0V8KC0zIjAVoRsrN9cavrlxpaVFfy9WtHCUqfh3ET4i0LEMS1BQ==
X-Received: by 2002:ac8:4692:: with SMTP id g18mr11199289qto.255.1610712054664;
        Fri, 15 Jan 2021 04:00:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:132f:: with SMTP id p15ls4464772qkj.0.gmail; Fri,
 15 Jan 2021 04:00:54 -0800 (PST)
X-Received: by 2002:a05:620a:16d5:: with SMTP id a21mr12290678qkn.188.1610712054222;
        Fri, 15 Jan 2021 04:00:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610712054; cv=none;
        d=google.com; s=arc-20160816;
        b=J1aw8b0Dh+uhIBq2gBH/xtCWQSlRffY462J4yvlPvPAzJX17+shFZ47cWM5wSRYwwN
         daPChG3eR5WyJVHFzRuhZ9nBQE+TRk0WOlpMq1OU9EpK3cuKL2YoL+vq+8HirLkyINWt
         z47hn88/1LRBwVCpDax+JnJjLkSqJIymdgKfhO1/oRPiHVqjr8WYQXe5dFz/hXA6cYI7
         RTf+YWDtpZ/i+vjF8sxyQ448SGwYdxVoOil+W+5dFHKxlf8IteWca0uFTpuVaxo77tUD
         EV0MGcBbJqtKPCAgPGm+aAEh9p448ezRP0POqQKg72rqudziqCHOI/LrmkD+Q8HQPul6
         Nx5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=ZP1qiAuSBLVGYrOmK+oEqR0K5aJAFElOUtKRlujutIQ=;
        b=dwm5D3LVODt+sTt29KCw5uANcWQ35osc64pi/Rji3UjSPY8SlZ2miJqD/hhKBTElyN
         MgFqFMlD55fp95TYOHAnsfTKOp5fulmSaoZ+59ipMCZkNaLEUJAgklNemigP1kl9/Fdy
         eQgbmsAcFa0M3UINOTPMnaH+Fy48MHnQgr3G3cQHhp4g3mW9tmbs9dDSaF09Gn32u7zf
         O0ZtY4sVgT8tQVsL7/inW4z5szAB7FGedahog7rHngJ3tVXfO99wiIlUBglmqaeRrA7o
         5hzA/7Gej0AHz3fMR2VIr06L0wqIYM5+n2uNAhV4MOBkYok2AkfOsnAFPGBrgY3mPKyA
         TIRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p55si877464qtc.2.2021.01.15.04.00.54
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 04:00:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7716AED1;
	Fri, 15 Jan 2021 04:00:53 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CB7AD3F70D;
	Fri, 15 Jan 2021 04:00:51 -0800 (PST)
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
Subject: [PATCH v3 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 15 Jan 2021 12:00:39 +0000
Message-Id: <20210115120043.50023-1-vincenzo.frascino@arm.com>
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

The series contains as well an optimization to mte_assign_mem_tag_range().

The series is based on linux 5.11-rc3.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async

Changes:
--------
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
  kasan, arm64: Add KASAN light mode
  arm64: mte: Add asynchronous mode support
  arm64: mte: Enable async tag check fault
  arm64: mte: Optimize mte_assign_mem_tag_range()

 arch/arm64/include/asm/memory.h    |  2 +-
 arch/arm64/include/asm/mte-kasan.h |  5 ++-
 arch/arm64/include/asm/mte.h       | 47 +++++++++++++++++++++-
 arch/arm64/kernel/entry-common.c   | 11 ++++++
 arch/arm64/kernel/mte.c            | 63 ++++++++++++++++++++++++++++--
 arch/arm64/lib/mte.S               | 15 -------
 include/linux/kasan.h              |  1 +
 include/linux/kasan_def.h          | 10 +++++
 mm/kasan/hw_tags.c                 | 19 ++++++++-
 mm/kasan/kasan.h                   |  2 +-
 10 files changed, 151 insertions(+), 24 deletions(-)
 create mode 100644 include/linux/kasan_def.h

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115120043.50023-1-vincenzo.frascino%40arm.com.
