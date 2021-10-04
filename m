Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMGF5WFAMGQEZ3ZUEYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0DF421858
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:12 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id t14-20020ac24c0e000000b003fd392f9a5esf2584595lfq.13
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633378992; cv=pass;
        d=google.com; s=arc-20160816;
        b=rUmujpGBEAvN8oo8HFRnnqRiUIEftOYmRpyyulP74Rl/PmuZaayKUS0oTcF2C/xcNP
         cAsbQ9AzbMChrUCsVii+cZWpaHtkckerb8jvFfURy3aYR9oVLlxsUzQqAno2o9jJsbUT
         QFLNkt3Xtp1kPR/CoT9ppPL5wXiRR6htdWp2RzyZ7yGCZiqGtkSTz0cfi2THby6K9jEV
         YL6pCdzsVGb0gTBOi6qlF12CsQu7+6+Zji4hFKnKQOYERHkXyWCa43DdgO4USmzj+HqY
         qc02L7Us6jWPSnKpkCIZnu/jB2lAqHLxV8d0pa0u8SWdgw4SQbP5HHqynbiPHiBA0ok/
         SoQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=jEtoRgM/lNM5oR2XdHodl5vh6qsZJn1cwmEnXOJlQTY=;
        b=b8INffTnIrMs4aphahRW0M63PXCN1QCAc3PHHVbq1N16PfxZPYVj2rXA15D6THqdm4
         E3yM7FVKz2COQbv5t7pESM4sAaYdC7jBlR9G/aiHiewF/Bpp8Fhx2uq7yHkSJ4tMKe1G
         bnpWKp9PRD2wFIyUMKhZ63WebhkAGImKSnWv6bIxDmvSUW1iDyNGq7+28L11pihXNtqm
         9XqN1p4sW4wKmRFaius5ZfqRJVcJrmKua3wFaViRKEQnCaR79/X6FhrHgdEqsB+Ham9u
         boQa9ur/HRMVBVMmkgTQfZ65aHsWmD210zp5qiS+lxdRfXZjk66YkxrqxfiVqA9d8SIg
         Ypcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jEtoRgM/lNM5oR2XdHodl5vh6qsZJn1cwmEnXOJlQTY=;
        b=QLFmCUXJn8NSC5XuEf3ry9PEXI4e1BJ2wC8jviYEfn/49ioP/4TW2k3Ko5JvGZsy2y
         BZ+OnWaXWJ3GqbF2fneAhuGjQYz71juYep9OBXMhgJy4FOQs6nAxlivafkjq4Hx2in2q
         uyrRN+ysjp75izwkuwdnS3gYm0SJhc1MFLCLqkMCZ1Q74YpF7Vs9Q+pyq4mNmduAmrr1
         RUj3uNciIN59fKgk0smG3xiTJdROlR+AO/k7keKpcffjzL28NvJskIlQrzy0FRLsi83v
         KpJRslm6RDhF5fXrTVw4Dew3GeiM+X1hjkvg0LeYZ+zigDJl9WyayQSVODuaEU9eA7h+
         5i0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jEtoRgM/lNM5oR2XdHodl5vh6qsZJn1cwmEnXOJlQTY=;
        b=R9pKHJ5vIve42crvcMpbqbfvpCxSTN6Ge0tyGuvdFElLr6jLQWKW6zMM3WdmthFomk
         U4L/eVSWxbiofea41q51rTktSoqVlhnTcHC88lnvvXTaJMMjAZ7zOMjUOCa28MB8xxlC
         CmWg3xIlb4Dlu0ttUPOWAT8Fa5lo0Skug2l+pRngVIZUpGxSPPxOpeqY9aoBvYiYjLrc
         RQtBn5S/UH5ufyEkdBXCVpbAQ030wHXKC6p/CC5hBsBBhWuFsnm4bWZ3pAPgzrcYWiXJ
         zS2mzeS//f116Un3gFFrUfLDUaywVQJ3tFXqv3EpSHRUTOBmQkDpCVS8vyhdvU/5oGFQ
         gQFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VVyChN2IgYzOMDKAa2jbEGsVW0foG9nE74n0Hx0xywDqJ0iWa
	ulUBsu+wxYlwTPs0Ps9oi8s=
X-Google-Smtp-Source: ABdhPJxGcOmrcR45ZEd8jTRfk9Eik+7Ug7tBCtZQveThV/wtTczfSAzEt6Sg1J/go+FCrv+wEt+QDg==
X-Received: by 2002:a05:6512:3b08:: with SMTP id f8mr16377573lfv.88.1633378992373;
        Mon, 04 Oct 2021 13:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls1220967lfu.2.gmail; Mon, 04
 Oct 2021 13:23:11 -0700 (PDT)
X-Received: by 2002:a19:4855:: with SMTP id v82mr10445830lfa.478.1633378991032;
        Mon, 04 Oct 2021 13:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633378991; cv=none;
        d=google.com; s=arc-20160816;
        b=oL7SeUEb9Sv90WSn67k2eOMoI/efGtvc0d3i42lGksLv5IzIZNUah6f7TYhY2w4bav
         kve0aAskeK/hv8xfv6lWwWYEL0L3a3wDrB0/UkH+yO8hy67x1U2EYUdni5YZhs77hkQX
         oOyRW8eH7vztGMbgylwNp8OShRbTGNP98fcmSSEQ8j6fMjTvHbo2XzNR4SJmESLOTMIt
         YiQo2Kln5uY2ndvOE+dOFQKft1yuevADKFbEHJBD75oY2zYRLorzgdqjtPwPiXAGCPB3
         D/jrugFFf+5xuttBLcUHQAUJqp03x+lI7DdFxmun1qpF6JOBaL1eM7h7nE52U0V6qXnb
         QBYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=1rMMZ6XRqNeLibFIOD28Hhk6e4k4oCjz+ZsM80JYK2o=;
        b=wdsCr2/qTRIlX0feJWMIN2QlLKFmUC5EMA+MehwkorK9pgBTN0/aeGLCx30iDuoZZy
         6oGw4Yc2qe3WPMTAXMKrMAXqJWHmQpb2UoXv4e/Xn9GqbZxFtspLlzC8JponRM4zLLcS
         qkTSWlMa4/SaNXDQAlPcoSHEpbqJxQBQfaKtR/U7iLOwmhr97kR8MQD0gBhHi0MfZdD2
         dpavxh9DzgRBRjUCZXwHkrokBRUXIIjuoGcuEZJKfDwqj/cw6yr5yH6Efoik5ubTLN21
         qxZG0G7p15tsIYRvLo7Z8UlMu98uZMqlydruKkIgBAHDs7EaFFOum8bbe6iB/nk2OrLx
         PX6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p19si565696ljj.5.2021.10.04.13.23.10
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 99E6B1FB;
	Mon,  4 Oct 2021 13:23:09 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B322A3F70D;
	Mon,  4 Oct 2021 13:23:07 -0700 (PDT)
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
Subject: [PATCH v2 0/5] arm64: ARMv8.7-A: MTE: Add asymm in-kernel support
Date: Mon,  4 Oct 2021 21:22:48 +0100
Message-Id: <20211004202253.27857-1-vincenzo.frascino@arm.com>
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

This series implements the in-kernel asymmetric mode support for
ARMv8.7-A Memory Tagging Extension (MTE), which is a debugging feature
that allows to detect with the help of the architecture the C and C++
programmatic memory errors like buffer overflow, use-after-free,
use-after-return, etc.

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

Note: The userspace support will be sent with a future patch series.

The series is based on linux-v5.15-rc4.

To simplify the testing a tree with the new patches on top has been made
available at [1].

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v2.asymm

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

 Documentation/dev-tools/kasan.rst  |  7 +++++--
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 +++++
 arch/arm64/include/asm/sysreg.h    |  3 +++
 arch/arm64/kernel/cpufeature.c     | 10 +++++++++
 arch/arm64/kernel/mte.c            | 33 +++++++++++++++++++++++++++++-
 arch/arm64/tools/cpucaps           |  1 +
 lib/test_kasan.c                   |  2 +-
 mm/kasan/hw_tags.c                 | 27 +++++++++++++++++++-----
 mm/kasan/kasan.h                   | 24 +++++++++++++++++-----
 mm/kasan/report.c                  |  2 +-
 11 files changed, 100 insertions(+), 15 deletions(-)

-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-1-vincenzo.frascino%40arm.com.
