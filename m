Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWM522AAMGQEHEFJ7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 259323096E6
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:43 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id y186sf5765724oia.3
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025562; cv=pass;
        d=google.com; s=arc-20160816;
        b=nq0EL2EsHrCc1U1UTtCumR55NA2yA6GK75P0SpEpOqEKV7amF0pYtyivBLyf0m73gU
         QO/hiihpjP4ce6iQ5gtP3JaMy2BrkTPVO2wiAD/+6LqaXSrXIB8wGW0aCcBLiL65nQLm
         +UzUOWGsvS8boDefWVs6Bl8rnDTRsNWrAje/R3nuzq2tWDPmxQyww9U+lwscn6/grnQO
         Z10QkaLFRdizPblTVwHjZCBPamZDhe8JrH8jN9CRisTdJ+8tns+FYPlUAIAsAgTwaoN7
         VSvAwgNFF1pO55xIxftpcvnu5D0lUafv+CNvI7zo6A3vzSCY7Sp2r3WkyvijVc2kYcmS
         L48A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=yKSRv/VigAKpoI6J8lNQLlc4c/3YodfXqdxWCAaT6CY=;
        b=nkhM/IQ7xVhj4XtOQarqCV7EhuV61VUfR0IIOstGCEFeAEuQXM3xdjougvFQmEp5pm
         HcnTkv/vekpWmeSkp0HS6EH3UUuRYeXYtlij/mO+2vRZVKLQshJA4TjVvqBIcFdWggoR
         WNtMB7AecNplSwQgI8qtZRmTiKMfTSdzC9Sj3TjqsFZeVmCxvDQZZ9DOX2dHfvaoh+v7
         4pxPdfXH2ezHoGm2qbwPoJEt6oKfIrkN0YA/Ts3YKZ1vQXLexnpX0HU9w77UqCxhLOah
         9mJHpUpS/y5lcrPau8uWwi6QrwyKYQbHMtEpUHsw6ZDnxU03yvStRdcbGd22Vm/AlXSN
         6+lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yKSRv/VigAKpoI6J8lNQLlc4c/3YodfXqdxWCAaT6CY=;
        b=Jq79IoTdxwQ/7qVQcLZq38zsQhyC5hwP0Hzdyo23xwT/TIIO38hg9OB3Zrj8rlgYL4
         X0HbZG/migAwWwYiRjMq3aeBnyMivfnJP7AQkK2pU5ssfZjKTMsJjE33wae/tc3K9A63
         k4F9migmdr1BM/XE/n+27iXe7LZAdkBTmYwmbyQWTYYg/cJ/Bv3+6muwXL7EVveQMgnG
         ITlxPIY8iEZi8bjCpWx/7QIR7p/jIvM/UWVv6sbuFsLcXNghaO/JmVimJhgHFNx+Uymj
         BewHBlfHKISf19i/YLZwjepWlf2HXAp+47edbbWGospzZn8y3zQw6HT9ZgJM5S/aZz9v
         hkFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yKSRv/VigAKpoI6J8lNQLlc4c/3YodfXqdxWCAaT6CY=;
        b=E/16Z4UIG+BAoNCbGI6dOR7987sdY+PI6muiIt0I9XA8eMDMxND2c4Q3d6KpB2McPx
         UFRN5KbYYnlAYfiLMRjpfoJpaSo350e5vmBjkaKX3HBB3VhIZfwwaPeRRDpqnhl3k+rG
         Z6gCxHyQMbuBFdP5i383nLpXpF50YArnS8fcyVkY0PnArMaD1b9NtSD/oCeR/vHuiA5M
         YTOlIHaenHCYqWV7jc+MI8GiV969+/KVNBJdy766+H0fbnMPcasAuNCSGmYXbNDq14+Z
         YBu/UdSzqK5RKpNMR74vdLE3uGtuTH/UvMuO1YmfHsJt/OsjfKXgf32cEYxY6HE9RDUW
         YZng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MoHb1VKMuOR7/JWQC7oYa9Z3tMaq8Q3eXbR0aR+C52FI/LZiq
	9EEvJVwIJDlXuE1fpRG0h7A=
X-Google-Smtp-Source: ABdhPJzwSFFG3BH489xrlFMxB3PzPxRLYM+2ZaxK2CBviDX1EN5pShmGCIhs8a5WmYoD3703SoLZyA==
X-Received: by 2002:a05:6830:1db7:: with SMTP id z23mr6354133oti.314.1612025561937;
        Sat, 30 Jan 2021 08:52:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3c5:: with SMTP id f63ls2958563otf.6.gmail; Sat, 30 Jan
 2021 08:52:41 -0800 (PST)
X-Received: by 2002:a9d:5e6:: with SMTP id 93mr6617202otd.35.1612025561535;
        Sat, 30 Jan 2021 08:52:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025561; cv=none;
        d=google.com; s=arc-20160816;
        b=SBYF/FK7l03+ILV7+IqABen06yvDAC4CEScyLxTYBoTwc7UFGrlKtzkpzWX5+/RxpZ
         kq8UuCCJUJkX5tIA7EdOxUpwEb6okzdlZ+3o+wluIC48faYSld+IX07zwpYwSoJaOIgY
         cgWWOptswbjmQOEYo2eh93dkYMUBQZGXRgaFInA/9OspnzE9T6R9WQMItQn3V8bwJIoz
         heqt0LH+xtUHYaBJP1YN3VbbMxazWdQwffFdoVE4gKcJo1eQNJufnMNgf0FNQRACOJBd
         MvY0IgWc39755QJOOTnRHAb0o3T64MtUN3LDCUR7rf7gC4I2Au4INNrtBG/fh4Y+/wJ4
         VL+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=jPs46D3qaCS1SiS95U7RzzIR6a2Y17BcKt3wpmUqLj0=;
        b=oq3A7c/FcXmkzU9uDKKwnNfJHsEU5ZGr0OaffLQaiihB8e2LX7gK8TuZNybzIodwZX
         4IEizggwTQFpa13iXQtjwgPxRxnSnYYPhLxvNNdHlwzlKyIohLEPOqwxPfx+8Vxlkguq
         Gjm+eUfP9UUiJGQdoXoi013J2BMb3dYBMEA/eLdIwGWa5EdzTE1z2gb3I9JG2KlvSfPd
         yfBfmD4DY/XryBpvZimTwhJvtu03dtb8+wg7T5sc2SaaeDDnkdivf0fzZwJrpCuh0bn4
         uqHwQfM3wBvAsk5CpcKOJ/R/a06phFnTytU3oorwLKANqhUI+s6XlzXTjQszYs5RpMm1
         udLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m26si512697otk.1.2021.01.30.08.52.41
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 386F81042;
	Sat, 30 Jan 2021 08:52:41 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 499F13F73D;
	Sat, 30 Jan 2021 08:52:39 -0800 (PST)
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
Subject: [PATCH v11 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
Date: Sat, 30 Jan 2021 16:52:20 +0000
Message-Id: <20210130165225.54047-1-vincenzo.frascino@arm.com>
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Andrey Konovalov (1):
  kasan: don't run tests in async mode

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
 lib/test_kasan.c                   |  6 ++-
 mm/kasan/hw_tags.c                 | 51 ++++++++++++++++++++++++-
 mm/kasan/kasan.h                   |  7 +++-
 mm/kasan/report.c                  | 17 ++++++++-
 11 files changed, 196 insertions(+), 10 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-1-vincenzo.frascino%40arm.com.
