Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBM4K66FAMGQEMZHQXJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E879C4241BE
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:03 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id d13-20020adfa34d000000b00160aa1cc5f1sf2401265wrb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535283; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUlsVwdk25R/ubaQlnBbMdHzx8s3XQcGuyFOaiiGLgRThSt1L+22D5/9YHsnD30SPO
         B321I4iylo1Csbbuhnm+b/J8SDi6z45h+5NTQwM+/1iyL+/nZwgOfaN71hcvNYIrvmPf
         HrnMUF7lw/bkLq7Pg7kIAKYGvk7GaFZiqfr7BT3TuTBkrOMoym/veS/9xhi4f8vjuwu/
         mjFHpYedLMT2gV/Bf+fxxBZGkXd1gWAQpLOJuThudT7dyvkEAojHbhJLCW1aFX6GHU3M
         +wsp57Ewr0fNFyk+gdNMKiBHKB3IwNz9CT+BwXzRo7FbJvg1g9N/RPMCb2bMdQsRYf17
         3WFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=G9JXGzdDU7ZRxKnZoJNVIX9pnylXbRp3eGZQix4s1pk=;
        b=QMlI7GXqPW9nf5kObEy9kZKCn7NDdUE9spTJcq8A+m2LDGxgqGF2Jv/LezbHfaHFzO
         rVkL7FgLJDdjPZhKV6DOAZXakttVblQg5KH6xHrMFQXCZJfD3g0c/v04AtMm/OouAsvz
         QNiXACvTZ94KkpuwF7oZb0/Z8uB3Kr/lB/SGd54Pcj/vuVr0gNsfEu3cwiECI4GT6o5E
         U1Em3majQXB21c8oFJ4JyB1faBihly1hqU6NHN5eITzBfEhGesqnxJvVeFJwRnqqJfns
         kXz1urwNaXloDMnyFXk1R4XqpwlvYZsj5QGOhaB2OJuP1Gd+E86iu6RaEqeKvkQgiqEl
         Br5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G9JXGzdDU7ZRxKnZoJNVIX9pnylXbRp3eGZQix4s1pk=;
        b=GOQY4KRmNHv707A9PyrQnEdR/0xOJly/kKupdoCGJmI01RUVBrMblvxU/77X5mAUZK
         HFqm+St/S3C7OOV+92/cvCfk3P1k92EE6/JmopA1WEnzNA9tEYCKTSuyIGwTcXyJnGeO
         yETzgEZ3ZyaPnhw2/7OeO/JopJQXBwwWliZR2yoWOTw9lfchGzhSpiFejPL2UfCmpsgR
         44IHC0B5kJypIo68Rp2UssL0/DpB+r+G2dokyHv1dmH5y6A82z54E+pClFRxA4mXpqej
         AnQ1ysJZkPreLNaIUW9cQmCkZvasRzloNYi8NnWp/aJF1eSWEGswhogTZLIJ35UgkMWB
         0+ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G9JXGzdDU7ZRxKnZoJNVIX9pnylXbRp3eGZQix4s1pk=;
        b=a5dCKVWU4PZ0BDPf3i6qzv0Kaz76oxLShtpP3ZZoE0wQgnTDuXpw5w1T9kn81hvnv8
         7sAnVRw667pWyIQ0PeSxx9/WiAw0mlToQHEeVvrl+x/SUmN5EsjfVuymXqsetYFNzHpA
         VfYQgmtB4z6nFQiptb8zRl3C6jc23xeHsGzDd47Q/O51VYbWm3J6RvMWRu5CWGOIfSvp
         dTBVmj3Xr5wi8lC/r9Usl5iWIHvVXCaX3Fawx0aTehMIgl+IXkI87AeYgSxTpSK7+t52
         nxUuHGH4kH1O95M0LDoHFjsL1IJTzalm/bkIy2EkGUcGr6Sw9g59et3iAboPm0JNgPL7
         xe+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533O5NjmMGl9FN/ShI7Ww/+/3luEBVGInwwaD9TtFXXFb6V0Jjc1
	cZsR+lHbfiBqDx9DL/V01CA=
X-Google-Smtp-Source: ABdhPJw8mO66SsNlXnW4YuD3rzJv6zOocTOdDUleEYBtywe55R5oALSjk5ps75c2ZIfv9Z2HwSlFsw==
X-Received: by 2002:adf:a48c:: with SMTP id g12mr14275203wrb.341.1633535283721;
        Wed, 06 Oct 2021 08:48:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ef50:: with SMTP id c16ls695671wrp.3.gmail; Wed, 06 Oct
 2021 08:48:02 -0700 (PDT)
X-Received: by 2002:adf:a4cb:: with SMTP id h11mr5921001wrb.88.1633535282803;
        Wed, 06 Oct 2021 08:48:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535282; cv=none;
        d=google.com; s=arc-20160816;
        b=aLuYP9pyrUlkFv6fFq4BXH6DuvqNNRuGGhm1RFgqqnUElmVVWwrznU/amNncFvFdPX
         Xi5NzJmdeFA91mWhVubYRUn96lUXSBp1sc/vJJVeRFlgPfE17QDGj4MYlgNBX3IWSbAS
         M7pLvBoTClBnXcf+JiZ68bjWNurqrHOiaKsNff6+1mOrZYEyAEaM48U3E98R19uf97S3
         10f53rVScKFMyk2Twd96yRl4JnTZm1kkdWeQFSjUQJgzKBeQEYTOymJuh8Lng2EPi1Ss
         OyuShM8Hd6Eha1fpf+CPFOP+u7rctdNjR4waZzVcTAq+HwdWMR8RZH5xQ7HnHYdthXSo
         UIrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=OP5ZcUpyqZiD5sd7DOi8F7NJm3Uvf2VEpTRS/Z4Ye4Q=;
        b=ZEyNCk+JEOznMEIgMxdg5fGekwOjlGV2bX/v9JvB7Wf9XunjpqUrgL/iIb3G+K5ak6
         npCXtlrE0M4KsPlrM+d24UtSYjm59D0kMdKYTGs+hT0c+2wP1S6Oy8xWNSiAPlqC0XlZ
         KTKokx18ulMMxYZsPnb0W1HEUi2yYJ5jcuNTeeIoe+nckNO9CWAZIIj2c1VCaZimjL/R
         rndRdOl8ELm8x9U+jv4Zu8fNAuCmVpsjn3u4CTPcKQhIQDZOo77BPX3+Lub7zOKVG7J1
         BzEO9i+bh8lHRofqcuQ1n1l+yVQhsDiyY9gltcqeXYyP0ZIlx9p0VBujp8J+g7iqBJmG
         H1cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s194si352272wme.0.2021.10.06.08.48.02
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EA0296D;
	Wed,  6 Oct 2021 08:48:01 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 114773F70D;
	Wed,  6 Oct 2021 08:47:59 -0700 (PDT)
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
Subject: [PATCH v3 0/5] arm64: ARMv8.7-A: MTE: Add asymm in-kernel support
Date: Wed,  6 Oct 2021 16:47:46 +0100
Message-Id: <20211006154751.4463-1-vincenzo.frascino@arm.com>
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

[1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v3.asymm

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

 Documentation/dev-tools/kasan.rst  |  7 +++--
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 ++++
 arch/arm64/include/asm/mte.h       |  8 +++---
 arch/arm64/include/asm/sysreg.h    |  3 +++
 arch/arm64/include/asm/uaccess.h   |  4 +--
 arch/arm64/kernel/cpufeature.c     | 10 +++++++
 arch/arm64/kernel/mte.c            | 43 +++++++++++++++++++++++++-----
 arch/arm64/tools/cpucaps           |  1 +
 lib/test_kasan.c                   |  2 +-
 mm/kasan/hw_tags.c                 | 28 ++++++++++++-------
 mm/kasan/kasan.h                   | 33 ++++++++++++++++++-----
 mm/kasan/report.c                  |  2 +-
 13 files changed, 115 insertions(+), 32 deletions(-)

-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-1-vincenzo.frascino%40arm.com.
