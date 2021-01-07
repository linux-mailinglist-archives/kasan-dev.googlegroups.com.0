Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBL4K3X7QKGQEASMCS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E14422ED5A4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:30:24 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id c3sf5276109pgq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:30:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040623; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNOOfSebF2csWOCpSfLZBRTHK1ZH4MQyAG4lzdPVV0ifE2s4l29QbSj5R9yhBeuWcX
         8vIyv/kgQbx94GTovYuUGuIHEkaGn1+1HyDfCBxMs+eppOS1bev/7OtKMF7PWM9ehjbf
         QMpr8DGLfaCyxymerZendGgNCXWYd9bYi912Ub1CY4cT2Emw4NoSrCrJ0rEJFc3fHq2X
         HuvrbjXIbBCB7TrXBtj7ovWxsDul1qzw1S84uPoMAsHb3W/VkNEj9sff15fDxaZWZ2ST
         M9I1FGGOyzpL15kPVIHAMAu9c0g4hzG/OK9kJ5xJ36tkir5kJjFXvenFlaPw88zKfsXK
         dm+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=EB2deJoAyU2E22SEJ491yYIPkqApCK17KxuHNT5WmRU=;
        b=PwdTxuOHHdWBgY3kkIWUJkDJcCArfnebQye9//asP9fU2osIW54QiT8nXuTdlQzNwg
         vEFmNv3PO6Q7AgiK3Bs35yuyX3wgG8wQO6wCvCP+j9Ko96wwrNA76jCbUv+JsY33ivb7
         K+qgAdujKdn9WQhFKdTJEYNioYE+n3b9HqcEJA2GA206jP90Zablj9lSn143mJkVSR/o
         nrQAUWSOKDyLX7ifudQho6YVsfBTk9bztWJZneRtbyMVaJuQxBlNAYw7zQ7OVMWI5FRq
         r6pDCGOSDgeFmt8pSb2RMwt6rMTbJ2XKNddzKAn+gavl8CVkyrSaYkYFVd3kT+66CtRo
         m3RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EB2deJoAyU2E22SEJ491yYIPkqApCK17KxuHNT5WmRU=;
        b=jz6Vr3IFkQTHb6rvhDMSSIngnZA7MUZQYN/j7YRj/Y9qf2HD0cy/S7jnCcvAgexqwA
         BpoTTDSuKLiN4j5w4aoF/i/AGR6WgOjy7UZ0dX2eg6tqSBVaMbk93olrPkomS7k9Q2e4
         6Mjrb/15E5iNP2Be5hLDt2enZ7uElBfkXZtsZVwgDeu5y0LQXvffShb6ky7/AK/Rd6Dp
         HLUFhDjGCx3Jlnejw60T6VbRwPan7mGYRs/gvRAQ4MVo6fmvsJXf5okAxcscEVTQX6Fl
         db1aMjjcgKLrBLhujI/VEfLaIgIuIg7pK7jEPb3ofPYGEocuUB1fd0Bbtux5pSv3U1TN
         Xn+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EB2deJoAyU2E22SEJ491yYIPkqApCK17KxuHNT5WmRU=;
        b=Tm1j+JEAPuvlq8WoN309FAl22dR+zMb61o042AWOuXLG1RVqArhFyoXr09jHpKbwAs
         TCuNP8vhf0uT1QVEnjQIIliC9Ta1vMCmk8T1GTe/aAmyZ6h2bCU4TcAukvo9cdkYDFmx
         0maPQQupFTjptMOMCGarrznMpHyxf3r2nv06KRSg2dW5dNpKsz/5q+ERcHK2zxe/sjgK
         C0zKLo0xLqhWzU+dsTVV6nASFMH8jMZ9ptRmcSJXyX3OteqV2eog7oTV0U36mJ8xV24P
         M3nEliultww/StDSik16g1c5ntpLu8jq6JvbHfkntAgp/DDSaH7fLZOXox0ZfEcaZLWZ
         vNYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530AOVFnI6hE8GfcBfBLhc4luJtTRcTmRWZMaHVgBXMcV9dwvxyg
	SShk8PKpXhGH2TNHJyoLZ6w=
X-Google-Smtp-Source: ABdhPJwrejXGSEMP73xAm/SYzIcQY5DFDYQKnZ6GQ8CiqgrY8REOHuIunxUOO9hOxBrNik7dCGlmbg==
X-Received: by 2002:a65:68cb:: with SMTP id k11mr2871904pgt.271.1610040623635;
        Thu, 07 Jan 2021 09:30:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac0b:: with SMTP id o11ls1595804pjq.3.gmail; Thu, 07
 Jan 2021 09:30:23 -0800 (PST)
X-Received: by 2002:a17:90a:fc83:: with SMTP id ci3mr10360199pjb.145.1610040623018;
        Thu, 07 Jan 2021 09:30:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040623; cv=none;
        d=google.com; s=arc-20160816;
        b=K+71qaToIcLlK1996srZlsqLKKHuCDNJM4r/VJkjzFktOaKMfsaWd7U2F9e3O9x0wV
         ZbveLNTH2wQRjfS6ljfEaaDx4Alhv4XWBWO5LDGAN15tn5tu52pwJf0JSBEr8tu24BBR
         oKl6EUhSfZbCTFUntN7o/+Glt8J+gPeu/Q/DCkoWjIjQAqNYiJVj7EvqYBb1iBDXMW1Y
         Nch0m4v7oj9DwWI4t9OXVokmB8w3KDS9QLsBYTTNJjOLo7H363xJqceBP0/8PgtZ8XQk
         YcHR8LHuJrwYwioRUGNKx9P2au/XsklH/3a9V6liB3DZ3kHL1Aed5Pjw28MgOCuRmBqf
         1rqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=2wrQpyqCxJ9jGmDH4zKEQuDJ5ICfBW+XmxJ6YZ3GdTY=;
        b=RDw+nyIXV+0ORvpiNkN5L+k8ERow/W9IdvXLbZiW+Omzwogi1KBWigtOrLNML9soGJ
         yZEmLus4nGt9vqAZ6rG/TFvjkwfgkHUiEFbSga6gaXFNEcy12t1oWJYAiKlXrcVwCfGM
         rfC6x5au4cuiRYNKvIA1L++K4taUywuJPK7y7K5d8gt9Qu+hMwvRNjaCtW8yuBvBVgLg
         0tl6lhuL6ptLYcjHxJzw2T6FGUHi6keBHQc8QZq/frwPDTYj5cZla4eP5PmpI5xfXCb6
         nb7phn9WBZohbDmssiAhaOA74yUyGe6pg11p8YRn1Dll5dV842/kvxlKXSdFM0Vxtx4d
         repg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b18si503057pls.1.2021.01.07.09.30.22
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B876D31B;
	Thu,  7 Jan 2021 09:30:20 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 15B753F719;
	Thu,  7 Jan 2021 09:30:18 -0800 (PST)
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
Subject: [PATCH v2 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Thu,  7 Jan 2021 17:29:04 +0000
Message-Id: <20210107172908.42686-1-vincenzo.frascino@arm.com>
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

The series is based on linux 5.11-rc2.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async

Changes:
--------
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
 arch/arm64/include/asm/mte.h       | 30 ++++++++++++-
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 70 ++++++++++++++++++++++++++++--
 arch/arm64/lib/mte.S               | 15 -------
 include/linux/kasan.h              |  1 +
 include/linux/kasan_def.h          | 25 +++++++++++
 mm/kasan/hw_tags.c                 | 24 ++--------
 mm/kasan/kasan.h                   |  2 +-
 10 files changed, 137 insertions(+), 43 deletions(-)
 create mode 100644 include/linux/kasan_def.h

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107172908.42686-1-vincenzo.frascino%40arm.com.
