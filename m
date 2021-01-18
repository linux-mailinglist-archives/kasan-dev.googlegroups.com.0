Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWFHS6AAMGQE6OYMRSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 33B812FA8D6
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:50 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id n18sf10760024ioo.10
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994649; cv=pass;
        d=google.com; s=arc-20160816;
        b=zLmjOWe5hcMLejiX+fgi49zDY+m06bRbNJxcvzs10ciMWBgHsP9NTfoxFZZpIMRpZ5
         D9S4q4mQWcXmh0qspHo0o4tlgniyE9fEuP2jmvKjygxoObaZTe0+SnUcRJaEz8s+8uxM
         jLp9l+OIoK8I8lrdDM/o681REFhStbhRwoGp5MC/GaLtG5uhOC6XbHVW9hbmU+c65kmL
         wN8yIyhwcRpqZbLMT1tfRhltRtYFkafB2teBy9weGVTAgXvq9eGoR1mB7bUhUaqwMVnC
         8y03Hxd7EemnxPByrpGrRuL1kGy6/2RHuXWvWvKdRXmlRAI35Tmi06qtWnuFg/KgDzWw
         ox7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=v3ctWz7lGkgm2xR+Eg8mzrN2f9lXESbeBya8yas4h+M=;
        b=0g4F0rOUZu0kd1sbuct77pu4YMJ3VO0KcLLGIWCumC3eiTluaimqtW7zqp8IOltlma
         6SW0NK2j0V9i/2jfU3edz8ciBLitaWi3I4QCg134MnoO9tUdzXLLVRGpJOdzKblYfCAE
         EO/6H3GQSK2+U8C5HOXVaXW5JE3MDrmtDx9erYjKE3kCi4SEabGr11HsxC9GVFWybyOK
         AJkvctpYn+8ClWSuBLQBw1h/krLjIqz8fF0Hp6VIdj1YedEOXIKAwD6wr64t7uzIURx3
         HdQLA+8Q83X59udP9SoJhToZ/g/AnbVYLWbZhNpXKCaWV+ykjD0DrhzYvLrA0kmVQhAB
         t9oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v3ctWz7lGkgm2xR+Eg8mzrN2f9lXESbeBya8yas4h+M=;
        b=RP2oNtA4+yDw3MBQ79Mkck4SjlAAgEXr3WuYVlT3wXcnh86XRHwlwQdW9HT7BHTIv/
         JQF+zJRqG7ArVX0JbxH29NOwPkVZB+j1hqA7MO8KzqkNhk6zYxboygQsfOjuSz4wSi2a
         d0lEKeeubnnrDr1Vn8Nm6w4A2rGDBCTtwGG9UZjl/yA7DWzilITrlZo1MKG4ONjNOQUm
         Df8XVMUNK9NCEi1Bkmarmgpd3k03Yf+13sDzekUgGAcpoVYM/BQ+/s/MzfGgBxtuHwgd
         1MswJVPQWulReiyBeehXoChZoaNCkVQNUxS8Rok64D7iJhzIgp86MMIjTcAvwby5Jnrk
         kHEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v3ctWz7lGkgm2xR+Eg8mzrN2f9lXESbeBya8yas4h+M=;
        b=NXvxlqMImBOG6P1g4abN78LJujLENoBGyov6wQ8Iequf1AeTBRbCuMoNsYgcKsh8gM
         pNHy0cE+vc1XAEQX/ojJW7v0coyQWkuRA/lKY1NuxkJyWNdRx3SleDB5/oj7TlRJmFTa
         zUFgzXQHC0InckeEPFN8fhk6AP1lUrKWjbdq6nMIa4R07gEu0d45ZbjvbVp+25jn2EI2
         3wADmTtsG5zXEjmBuFOFVP15rIgp8/1LGlmB4FDjdzXMAq1vnzcshasXqz9QWXUwXvHR
         /6BzHlnYKOFbG14cyuEl6xrmep4eV9/LE1TU2ppetBxSFjHDF0iBZURlOnFwgzvOrZNt
         Nkqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uQCHXPigZCbVQwSkEG+Ayb7M0dOXVCvMH/z4XhZaj1T9hFlGu
	+K0o3P8APEOKV6yKhdXZtuM=
X-Google-Smtp-Source: ABdhPJzD0HJZ/l5MOD0XZ8NVUWOE6rkcpwokA+8pLIQ8PceRbCgohQGFWXEgP7rDh/ncmitfXCcOHQ==
X-Received: by 2002:a05:6e02:930:: with SMTP id o16mr405901ilt.289.1610994649038;
        Mon, 18 Jan 2021 10:30:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4b06:: with SMTP id m6ls941040ilg.0.gmail; Mon, 18 Jan
 2021 10:30:48 -0800 (PST)
X-Received: by 2002:a05:6e02:1aa8:: with SMTP id l8mr430523ilv.251.1610994648698;
        Mon, 18 Jan 2021 10:30:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994648; cv=none;
        d=google.com; s=arc-20160816;
        b=qBo7GFWt1s9VRelbaB4HSW7tLviUyY/5svKxF89uXuRd1Yy3z7RFOMw+pyJaujunbt
         spRXWPUHqv6byRI86PLju6TjwmTXV+tR3WgN+U3xN+bpDt3evCdAmXfLGiS0jePQ6Acp
         Da+71vXcKb7kiYyvRmoAVuYh1puXuscBBZ9YTa/+4uGMu/gwCXLnoQqerOUkm+oAtdd8
         UkkuhSpRPs7WqSH1U91QKNA8SbGCRq45sY4GSZKYFF7gzMKlBEzrJZeprOUV4+9xQLCs
         vDdWbevqu9MOh4NtlKkBrX/qLhHILXyPGpRCrk77xd6eKcOKACaexAUL8gB0588E/6Ca
         4yjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=z9vcxTCXklRAothkDxq2Qp1Axc4rlphqKX7NA6cY+UQ=;
        b=f1ITtdUYgLhOPQtTsSnT2umFSAoEMJZLVMV5yqOZPjNgosSm0jDzH8wk97G5ODa2G3
         +qjxAtslQ+zJPCfmN/GBxbvJZGCO5Z/Q8al09hQfx/roIrslWbgZm8YZyMEVKy+qJ3NX
         qigdYe6b0/PLWMzslhzgwjmDT8TNro1LVZj/oqYjwwQC+ez+VVA3YNBhHEPiEKVsgBsQ
         z09DZ7G7JK5CJEu8lk2dEliDWSaIaDNM1/5k85IZEVbtPgc8g2l76r7gBE8osoIAqGt1
         dfi3+POlE0nfSE/Vnc1E8EfQpFR52e5nFCMf3B5ft3iTb8FWNvnWoUM07FecwqSlCS/n
         9wtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d13si817841iow.0.2021.01.18.10.30.48
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 224C231B;
	Mon, 18 Jan 2021 10:30:48 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 74CF43F719;
	Mon, 18 Jan 2021 10:30:46 -0800 (PST)
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
Subject: [PATCH v4 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Mon, 18 Jan 2021 18:30:28 +0000
Message-Id: <20210118183033.41764-1-vincenzo.frascino@arm.com>
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

Vincenzo Frascino (5):
  arm64: mte: Add asynchronous mode support
  kasan: Add KASAN mode kernel parameter
  kasan: Add report for async mode
  arm64: mte: Enable async tag check fault
  arm64: mte: Inline mte_assign_mem_tag_range()

 Documentation/dev-tools/kasan.rst  |  3 ++
 arch/arm64/include/asm/memory.h    |  3 +-
 arch/arm64/include/asm/mte-kasan.h |  9 ++++-
 arch/arm64/include/asm/mte.h       | 58 ++++++++++++++++++++++++++-
 arch/arm64/kernel/entry-common.c   |  6 +++
 arch/arm64/kernel/mte.c            | 63 +++++++++++++++++++++++++++++-
 arch/arm64/lib/mte.S               | 15 -------
 include/linux/kasan.h              |  3 ++
 mm/kasan/hw_tags.c                 | 31 ++++++++++++++-
 mm/kasan/kasan.h                   |  3 +-
 mm/kasan/report.c                  | 16 +++++++-
 11 files changed, 185 insertions(+), 25 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-1-vincenzo.frascino%40arm.com.
