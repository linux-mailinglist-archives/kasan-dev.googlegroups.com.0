Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4MQ7SEQMGQED57MS7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F111408632
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:42 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id v16-20020a2e7a10000000b001ba9e312de6sf3807961ljc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520881; cv=pass;
        d=google.com; s=arc-20160816;
        b=0jJgWlrYUEjhNxW91wvEo29IXxdD1B1I0omlG9HY5fLjgjg46cxnvQ04ISaaQ0yj4n
         trmCjPfcbcJYzmxa2RogKmYQRWABUSyh3rkY5FH5XJ+kpamRUljV2xqHC/6euGxQFUEE
         P6LMyn+MYVP4Cy0AkVbk+/uuQAi2cJ45ONIXVtTKsWuF6ENFgfJ6uRVZGLFaeC0vUlzp
         /Xgc+kyH/O3FODwMUwocLyJi2BbknoMhVf8xhXDH9XmY5OsPXfm7epI0Ga7zjPrxeIz0
         EgFdjTVZF4HGBBTu5tTYX7YaQIlQinZ5b1W35TNUQ9AuILSFhMDlHBab7nurQ4Ep2EMW
         Ll2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=p/ytENSCoHbQK8nxaI1yplb4XCcSOyjSTbrlYBI7WlQ=;
        b=AJJvLqxcwKUDglPHVtDv8hzb8na7xEUN3Zz9YhGIa2JOWeo4LUoGIG8zgmC8I98lI2
         uebWvFOlh2wv7M++qcgwAXbGpZ9lYf9JQgNAtvJbsoPqNzaoPCkSOmJRgJAx7y+7ghqV
         8q3+XvvpZspIHo+6xoW4K9avLRehXrHchiACklUc9Bb8ZhiYCNIZDQzbMbfp6Hzrt12k
         2CmCIyTFS0f/A9PqRgTrnyCwR3AKYA5DFc5KGn0dVZCp13O2Q8096n1IWI8fYWGBPlBy
         KsCCwS+9UyOL72C2wMihS+n5tH1F4uFcm65X7gW1x0Veruij/vZl1ixrR1iRY1//msdp
         IZMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p/ytENSCoHbQK8nxaI1yplb4XCcSOyjSTbrlYBI7WlQ=;
        b=M/GQnm7e3hehUPQMnW8xQ7wWsFd9xDH/Q2T0DEbLHZoDjCJm4UI4BqtljwebrwAhvM
         3CdThd2ybCYoPNFnNO4HeisMw1POWxWMLCaY2AneYyaykc7AGciF1r7mIniPruAXmHxI
         8eQ7VvQoQDM9dN2O/jeNynXc3dAT9EHjwJWCgff4F71olXFIW+QI4+3AlMAG7ARcTyW7
         VoA+tmFWLgYDD9zeQ1lJ2SHEzjddK1sZge3yNGDagJY4LTPgSxWBtmIVe9hAEXBS0cSJ
         W1BF95sa/uWbuA3qZMCsd6b44UGO7M2gupw2he0gwAx3EvIelR4k4uy7XiNWeYttrWFU
         3W4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p/ytENSCoHbQK8nxaI1yplb4XCcSOyjSTbrlYBI7WlQ=;
        b=lxOisYvSiDleCox7fgu+g4RxDmHyHU91IPseFvTbDpGwruawpp1fZk1gllKnKG7zDn
         bFc6eGCzJvLmJzWuaa1ojibkfMJvMc12JcmGmYLpuKVyyG9yeW5PNAUw2LJRtedyYpXm
         mX1gneeyhMx1jD26H/8ca1f4sQPebINVCYLGwsRkMwG94L1RQJvQRTyyO0k1fomuv1ma
         PmMqvl+TRFX9BRX7SPXw2L0nwgLFfXmv50ve63r+l4l+HRM0yp8RO03zpAdzqdtiWgph
         BG4jc/my8uNCDk9zJNRuYrzBQr5yf2v9uOOk8jkA9XqWIZDvEfWE8dLJY3qKMmh/1GuO
         9Xpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312NCpz/J9jjGycEKEzF13g91QdWTGCt7OCfCG+uAf6xNJvO1Gn
	iUSrxJ934M8qmNij82gnO3I=
X-Google-Smtp-Source: ABdhPJyQhKESP60ZSeiHiAda+dy1t//eAmFwpzY3B2rdM1mcCRzxI3bgSrRfcKFiJOhVEO8K3HVyGw==
X-Received: by 2002:ac2:4a6a:: with SMTP id q10mr8401978lfp.259.1631520881556;
        Mon, 13 Sep 2021 01:14:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:597:: with SMTP id 145ls963677ljf.7.gmail; Mon, 13 Sep
 2021 01:14:40 -0700 (PDT)
X-Received: by 2002:a2e:bb85:: with SMTP id y5mr9627727lje.207.1631520880449;
        Mon, 13 Sep 2021 01:14:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520880; cv=none;
        d=google.com; s=arc-20160816;
        b=hnKuV6+nUnqILJ9iCsxlEK2KEJPTdRb/0zH9RpfuvZEuqpAZmxOyvhpX/P2Q6mumKf
         JNNiYNmF1mkXBJNXbScoTyMFy3IxPLJTVW9Cwz86rQX1MLD9v9fq55Y/pdhfYWzIz2To
         3eZTH2kY+/qXc5nUe5bgxFCIWNZTF2JcGhIzcWw0fSKDOSEsq2+KB7OHZHPiDYDmo8Kg
         dbHR+CPqD1D+7Xe6L2mjxD65lw/lpA2n4mmytrxQE96XR3MUnfCRmys7SBz3oVBkgWed
         Ddx2kpVZ2kU+boubHYLdA+GjpbKWPNeRWvTv6IILa7+aNRRQ3ak8HyndX3dGZdxNPFIw
         HyOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=B1AD/3Y7xReFmCU1cJSMLM6ARE2RzrL0fPAEo3OULJQ=;
        b=zEGEqjkhkjlVxSNYGPLB84EkV41xlTHpqXEI2Le2tN9/fIuTvW+Iuq4VRbXQoE5M2N
         JRbzTppc/tqsopFTxs1WX1oJoQ+FWOoO/ec+/E3z6Dukv84C0GQe0NKis92aacHD+YKy
         MlR5JS/PZMVrFvAMc2jaCJc6N+t2075u+Sv9ePSZr5STNl15BrXGD7Wvl/CDAkoLelUb
         212rHbayqlVesd5rNW4Mn7wLyTM5674xirHZMF1/utQx48JxOAN7lpGkXry8GSvVeEOU
         wqo+9cgNpmR5YxvOxUNdblg/YWWLlwhHViiluYTtqzuli0YJu3Hr2eMkHQfMyJR1Pnrq
         sAqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l20si610094lfg.9.2021.09.13.01.14.40
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 652EF31B;
	Mon, 13 Sep 2021 01:14:39 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 820D93F5A1;
	Mon, 13 Sep 2021 01:14:37 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH 0/5] arm64: ARMv8.7-A: MTE: Add asymm mode support
Date: Mon, 13 Sep 2021 09:14:19 +0100
Message-Id: <20210913081424.48613-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
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

This series implements the asymmetric mode support for ARMv8.7-A Memory
Tagging Extension (MTE), which is a debugging feature that allows to
detect with the help of the architecture the C and C++ programmatic
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

When asymmetric mode is present, the CPU triggers a fault on a tag mismatch
during a load operation and asynchronously updates a register when a tag
mismatch is detected during a store operation.

The series is based on linux-v5.15-rc1.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v1.asymm

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (5):
  kasan: Remove duplicate of kasan_flag_async
  arm64: mte: Bitfield definitions for Asymm MTE
  arm64: mte: CPU feature detection for Asymm MTE
  arm64: mte: Add asymmetric mode support
  kasan: Extend KASAN mode kernel parameter

 Documentation/dev-tools/kasan.rst  | 10 ++++++++--
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 +++++
 arch/arm64/include/asm/sysreg.h    |  3 +++
 arch/arm64/kernel/cpufeature.c     | 10 ++++++++++
 arch/arm64/kernel/mte.c            | 26 ++++++++++++++++++++++++++
 arch/arm64/tools/cpucaps           |  1 +
 mm/kasan/hw_tags.c                 | 27 ++++++++++++++++++++++-----
 mm/kasan/kasan.h                   |  7 +++++--
 9 files changed, 81 insertions(+), 9 deletions(-)

-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-1-vincenzo.frascino%40arm.com.
