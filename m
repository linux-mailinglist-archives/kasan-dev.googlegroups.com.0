Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZNUVOAAMGQE2ZDZDAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9433004AB
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:00:06 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d26sf3604355qto.7
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:00:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324006; cv=pass;
        d=google.com; s=arc-20160816;
        b=sGKdrqxzDmdKxOi6kUfMm6xmLnRnuukPSE8XmWXo+u0u+q5HjzoKDvaiys3xfp3n93
         vC2sr1nR9taSy2AoHATijwz+T0DfMrsISAG40NRpuiqO+HUN+uxeaRWDfIxR5UZqVuCs
         n2OxIPn6oZIsBN9m7V/yZkDR6Fu7gYGVsu54SIg0ivJuS9vy+cNdG5anH95e7/6I0dt2
         LrMTyCtTaagI2gaP24bkMfA1yWVWW5vENUTSfb/Sci2IcvxmdDoZutFgXCwZag/+U4W1
         A3FifObu2ANuLFzG5wZr9eef+dIhLZYHF9jv/a+BzrJxIwI3pjueWSR/Z20yaHqfOVZR
         nINw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8yDNGK2UDXocofBD3CrO0RNY4qbw9dN1Dd6AUSDJzhk=;
        b=t/MmQbEG765eCJnRx3tw69faKW+TH60rPrESZwj64WxnGWWv02ZA8TD6MhGctl11ac
         pX6HDPeSrQRxWW7lnuP/S47V4tbJ2j6A/1Vaj3wE+ncH6ABYyk1i09MbkMHwSXZYVxzP
         of44KoS1JqNXZOO11skrWO15ArWbaxNPCZROho6vrZfNqg+jHltKyKsi70pSYmAKJqvQ
         evys0+TfDMMvGtnN/c2vxlOe/15ImhTI1lcB5fNBbVlSTnVJo9U/M1rwY3NF3+DOMeRe
         sA8aSLspqIC/bCxFT4GEI/ywNZ44QbW2JP8yTTBagNBevZbPJhLo5uXEbgsYZoMbmM93
         GlCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8yDNGK2UDXocofBD3CrO0RNY4qbw9dN1Dd6AUSDJzhk=;
        b=JGM0kXJi2qmmgImJYkaDx+cqjykJALBWGcMJf0G6vGgs6AVtb57S1g7FCialWwrktF
         KMsXFV0q3b8jOmLuHbtPAyNS8iKOtyUZb+4D65078m49FQt2utUw6YQ06qANFeVbDHZi
         JoQE4zufvE2DrJ6//WINW7RXVEc8oFkzDW5ZQSngX3XqwJnhtF4IMW6m/jxNjuz8XfTu
         n2EMr7dXu9aUR2Ouw/exEkiQCouzktjvDOoxLs8XPLiDAeCFX1uzmUnTG+Q4Wk1I1qvE
         FwZeyCFa2lJ4bYldkVmVEPCt4gztvntE2xXe0gSS9l3T9etKr9Zhgo3mBXNjNkkU91fk
         pvow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8yDNGK2UDXocofBD3CrO0RNY4qbw9dN1Dd6AUSDJzhk=;
        b=gA8izdicqc4JcPyt/QgxNBgXg4gbkLbLPLWrsKQRM4ggDAYync2AX21fR44GXz5xAH
         TAT0teR0AFmuZm50sykMflFp0esmIjrMdgI8IibbOQWqKK7Vqo5B7ZKGbV/3esf4enXs
         aupf7SB9rpf+mu8sAlmA4vGXdp/WGHMqSNAyN915D38qC3GHiYAp5saJ1nBj4SASm0rT
         TxCzEKRyAHE5D+Bxrxk9k91/v6lqsQfj4lcX4p+wUNJZq1XbO7EkBzDfpDNmSLvytcd0
         PT3x2/vbbr5QAiyB4zGVifhYnsvFDTt6IM7oD5H5VVs5OfpR4OTKdsesSQ6T+Yt4puNy
         GApg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/mwfNDUZdBjIT1WrP7JLxA/n9l+0SHIYSlarojU1CD+n21Ej7
	h2c38Se1q/poQg+PC1ri7Jk=
X-Google-Smtp-Source: ABdhPJwngmJH+jLmCYHXkO2XRZr/X50/SNOSX9JDTLouB3sFhNQWyO1tWYCfSn8sA6l18Yb3JFSDqw==
X-Received: by 2002:ae9:e119:: with SMTP id g25mr4861960qkm.124.1611324005924;
        Fri, 22 Jan 2021 06:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4242:: with SMTP id l2ls301936qvq.9.gmail; Fri, 22 Jan
 2021 06:00:05 -0800 (PST)
X-Received: by 2002:a0c:e8c8:: with SMTP id m8mr4605665qvo.33.1611324005433;
        Fri, 22 Jan 2021 06:00:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324005; cv=none;
        d=google.com; s=arc-20160816;
        b=KEfys2GJ+sWD1aubAIKsw1N5L3IwuhxheEJt/CMAiLal1Bpmsd+/sPjwdC97DjTD2d
         Q2CU9rF1zxLj+rdfYGcOAXoBnmnP+xixWqL9x1MDFSMHNxgFzZEbWrc1dGRa4AdeYqKM
         G4aDmS5ME63tq4S1Hpxx8tZfecO1G3yAHRh1DVxjl+yJ6MXx1t0TwIBvcafZHg47L/7P
         bJROG74yJ1jrD+bO9A1WQS8m3AHj/1g8mfTEeGvqkcP0lYKjIKXuEwsckmjR5/5i4eWd
         hi8QwIvo3+KEGRl5cMaKlIvd13CQPdKejWSPXUi/q/0uqr3ElGXFuwA0Eos/7E5qlMrJ
         +8rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=kg06u2gwBy6w1+ZKYHDfFmJ0fNabTDTRmT89S0APjPo=;
        b=GenmZeE35sibNTlYTEWyGErvv8C1TWSDiJbAEJGjJFTrabUQEYGxEcQnoeJwQxa0RN
         EbmYhm7XokPZspwcaGw8dWs+QVVM1j2daRF2qBHAPWnshkVL5Vj8aws1I9XkE216j2ad
         hJU+2rBl/pN1xyJ8eEuwg8jAL2Yh0wUd4yrgkTIUNecAlZwMaqHm4vom75lIpapiO2PW
         nCVwMFdYcoiORGnEWqB5iuQbn7SkOrRdTMv46P44r3QlLNzt6ghLgilV7B5fZWM546rZ
         m+c7GJO/1my6tzzagZT0QmNMn40cJKlQPnPkQVJQxZ9qpa4BRGrl0JK5Sw+7EWIxag6/
         2E/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j33si715079qtd.5.2021.01.22.06.00.05
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:00:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B3932139F;
	Fri, 22 Jan 2021 06:00:04 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 11F633F66E;
	Fri, 22 Jan 2021 06:00:02 -0800 (PST)
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
Subject: [PATCH v6 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 22 Jan 2021 13:59:51 +0000
Message-Id: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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
 include/linux/kasan.h              |  2 +
 lib/test_kasan.c                   |  2 +-
 mm/kasan/hw_tags.c                 | 32 +++++++++++++++-
 mm/kasan/kasan.h                   |  6 ++-
 mm/kasan/report.c                  | 11 ++++++
 11 files changed, 163 insertions(+), 9 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122135955.30237-1-vincenzo.frascino%40arm.com.
