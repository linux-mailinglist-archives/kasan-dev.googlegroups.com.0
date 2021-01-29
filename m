Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLFR2GAAMGQEZICKHUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D3BE308CBA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:49:18 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id x21sf3857077plb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:49:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946157; cv=pass;
        d=google.com; s=arc-20160816;
        b=nBYMG7nGlKFIQwh/OZ7om0UKKUzft8MSXx45cB2vUeVsgEfzTwwYcxFfNni8NHHhW1
         qrAyzJ/p1QhkSWgwnmi2ZWjg+Z3ztrEzrws/IBc7udQ/+njmn7ULcEXkLA6QoGisXMW8
         BmYAN0Rp/OXRDDzgoY2ybRp7DMMTOA92CIUMnLB5qhAs+4iwXYBeaVoFVH5SrNfp9Xv6
         9vM4boN4d2ZHVW1/FDr5ebz9Hk7/vIeor7gsMUFLJoxOhYw1gJVno3w0c02dkukJ1CDd
         LY0441v0CFHJrCBi4RmPZ/fzKnJMxX2whroyYbsKFPq2sanaMnR6u/c5kXsaToZraW0+
         h6zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=u9VUWO/E2yPcnLlSq1RfjY1FF6l115kbRF4ftnYwapE=;
        b=oAKvBBXniTs3jML1gdYiEVNUMCGv2Br85cwmfe0ieSmLeOEOoYtw0r1hQL9GU4T66L
         cng40cGt1n59JW+e/5anSCs/7bDIw9pdzCcostqpT1C6FPiOjl2R6PusqkwsRb0G4PMN
         vr3L0tuZVk3a1YfVXIVfX0Jlm51u8iUdcy8JXI0TMgSV4DzgJUs6xloOgRWBhCy6Cucw
         7TOF5OI5rdGCkRzZdz5DI350B5jHrr8Ht36G6ehsyVgitJlu8PKd+kl8HnIN14HUt4OA
         cwB3uvn63c76BRTo2Esd2BO7sZB+KU5UuVTqXNnF6SV4T8TZiukP5g/EQqhIs/xZ0cMQ
         pVlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u9VUWO/E2yPcnLlSq1RfjY1FF6l115kbRF4ftnYwapE=;
        b=pIie1g+W6JYo4bgkwKGSblSdwSusfdmJGYOs3o3cE36ZxrGas4e1s/CcD0LKtRZMFU
         A9V/SDwa0dQdqQCMylVO5W7FcmRnvU2ZgfXiJ06B21LXsmLkD3YsHCfPwPhwrTf+s2CQ
         uxV78OmYo7C+jlltzYrgN7rTb5BbQSF6FC1XfwMRbx405O2kXSItv5wZVv5QCHM1C6/i
         L/H64MgwHBB1nXvJrR25eT+BQvob1e9rLPD3dJr1ncV9h7RbL64DRWT+B/ah+SWT75MY
         453san0BX7PJ4I4hvU/buq+nP4b5PpsiTeKTKQSPIH777hJrBAKA5FOY84cXjuei3A31
         9szA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u9VUWO/E2yPcnLlSq1RfjY1FF6l115kbRF4ftnYwapE=;
        b=H8i6iNUCRylan9IJJ2GNSgJI5AOmHpmrIQXPqRkSP+PgNQiJwrprIrCcaEPTA2UrR2
         v58XI8Aznvbcj2AXKGFtWpx5GxXbUNSt1CZQQQDMajvMmO2iUvRK3OnVTtBgfWS7x06v
         u1F1UlqByQutvZJNvjvDdqlfTFXKostwA2b7me9s8CEMqZq2ELhXJsFAwvGvNhHIGiKn
         hkC0fRVChhuAIQnezlDYHDeqxyZfpfGH11zJuv8qdyjvEedDsGjnfyWll48Uefyao57A
         Dmn5LP8GGiEMbW933QC4CDmQ2i8L9YyLcTTuZq2PmIjCkN40Q+HOnFXfyK4kUfk8EjC4
         ByEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532fxHU10+/kNTlAdIl1y0CGlkAiARoxZmIPutHkdUqQA+0ObSFc
	cwa335Vutx4RuqfJLmGahRk=
X-Google-Smtp-Source: ABdhPJw0OuRlYBp+6g/TwNbeI/loHZJTmMVzuuw4IE1z5QHPaMOapiqVdhgMAV/JwboZFzeSKwqIKw==
X-Received: by 2002:a63:4504:: with SMTP id s4mr6002818pga.284.1611946156755;
        Fri, 29 Jan 2021 10:49:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e8c8:: with SMTP id v8ls4763983plg.1.gmail; Fri, 29
 Jan 2021 10:49:16 -0800 (PST)
X-Received: by 2002:a17:90a:df84:: with SMTP id p4mr5758078pjv.81.1611946156029;
        Fri, 29 Jan 2021 10:49:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946156; cv=none;
        d=google.com; s=arc-20160816;
        b=qR3pOUUNEM+w38fsQJynEMJEtmHVUBA+pNjrJb+d2vsCB0RWkTtxh04ovvWWQPoPIu
         QDU1mihWib8ATu5AWRVJT5cgdMbAi8MLuUR6WGUI1+/bCN8WupM3LdnvhHmIOPQ4TVqh
         DCq6I0H83u5Yw+g9xPbLlCW0gRYcFdYpt6Io7dFWW/nBRElhAa8LOQPqhhlLSNcQzSzU
         3aSX0sqhOLEnVIx5ziduuWmNrizOZor5x5ElLZ+NI03KQfLCl++SC2mHHCxYs8JbeI5u
         Go43ARKT0Tf4SpPxGmVIWgZyXwT5ZuEsYu79ADnlCPk0LFU/rpoYZa+1J5qbfq9LFD+U
         IbDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=VEsNooADjNGODg9evAaMQTPNDZZlQSo8vhdaGb5cPYY=;
        b=ni7QSD5TDi8Hx/9l9yJtDkKOdSAsREjFxqDDkVMntIjUTUYu3h3e+/U3uUxYgDh4mM
         cdUbkEUnmEorgUuhOZ8WhnwFUeEpq0BQ65y+lbF9Ba/cQuUCXAM9WHp9XFqDF2xFhg/M
         Gu3m6HFthaKxr92KmVyR+gvEgL0T020PJmdkDRbEVzWWB5Ag5iXachIhVKSvOWiyLz/t
         w5d1QzPc6o7ux14Ml6FBcAB+MRdJYuFpaCK4w3SnQ5IqU0uQLzYfPqjt/+vyCaDlmlDX
         tLRJNuSM509sEcZsolGSxF8IWUh9WcakVX+UrIlU1zxVx2m7MdwZwdZmdktGFROumCF1
         YGrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si605915pfr.4.2021.01.29.10.49.15
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:49:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5A09E13A1;
	Fri, 29 Jan 2021 10:49:15 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8E60F3F885;
	Fri, 29 Jan 2021 10:49:13 -0800 (PST)
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
Subject: [PATCH v10 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Fri, 29 Jan 2021 18:49:01 +0000
Message-Id: <20210129184905.29760-1-vincenzo.frascino@arm.com>
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
 mm/kasan/report.c                  | 18 ++++++++-
 11 files changed, 173 insertions(+), 10 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129184905.29760-1-vincenzo.frascino%40arm.com.
