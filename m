Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB4XKSXCQMGQE7A5LEDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7987EB2D48D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 09:12:52 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70ba7aa11c2sf105835976d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 00:12:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755673971; cv=pass;
        d=google.com; s=arc-20240605;
        b=ip5mPQMNWcTOkHfth6FLfFqbaoGzNY2uk7GPhrzm44tJtpCByBJVDIkx0wj8pK2cIL
         j/30z8EHUA+YTb7M8IRtKjH6Gu/FxsMat453hEkyheg6x5LjuDL6dQmp1xazBir7+Vsy
         N1rUxNzlo0+u92NEAqnX+6n3womC7/CMXcMCL9dhNOss5qgkk43+63feKj1J2q1SlGzl
         O8zSW+Xa5rDa01y88bMqwKpUbNcPJqAe+cDfKXR12getCgFkxr2QoaAiJufCi8UkUWes
         BzjrvImelaFVCLTSQG6y5LQS/RaAgjz9Bm6ALRtrzpsNbRbe34qr5mR9tIBZoBm2W0Y4
         EdRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xrrN5SYLCAp1CZXkRF85l3faAx00eHiC0lt0d1OzWNM=;
        fh=Bap579ih1kjJecZe0gxd548N2/9qAFxr9JfIopDr7fI=;
        b=iIxhL6drGlGos4fiG0eixturJproABEFe+D+0tZPVD0kdYddPt3RPuJWPeaYDWSpaq
         RY74UFTrjQfE3BwpDmNy4f7xXSPDuxzCdHKfiX4IV9GMzeHyOUl0oeV3tXOwQqZWjjXD
         UN4ORtc+pR8amzCB9+yAQnFfX/AWHTxeB9kUvFYIxD1p1w/cMvOhyuukQM0baxnpkB44
         JuS+F1rf+1HijzxH7R4PE8ak00Tl5Ur2cm0PVoy7k21N393jMhFmaMqMten/Fd0tKM6m
         Sra3/PF+uHuFmqC/P4bWZN+kztAiMxvQQwnrWXLAKXZFeg1lLyPBQoN5dALyZFvZLMpE
         W2Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755673971; x=1756278771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xrrN5SYLCAp1CZXkRF85l3faAx00eHiC0lt0d1OzWNM=;
        b=RHLrfN2VA3G6z2uGEigAmZKXQW+XQkgHsSbvOujBtlpmSPfi7NIyfXsjHcqoZeuoWR
         C3ijAtt8tlR6GO870QJakCHHOPcv48OvQ3OnVHdz/5K4jxNsn4zsi5tv3xqn9Sm8TzFv
         3hjtYYKVgPh772FpV1BXY53zezkkxEKSHZ2TYYQj4xLA+fu8+mBRXZxMypIOTWJVxT2v
         Vc3VOI/hNTBoWT+LaAu/dfXKMLzCzwTS00k7KethcsmZfWPsIXXGui+o3R8tJu06RYqE
         MtDuwli+mRRGSosdVlGr47Tz5+aTG/Iv/PNyKBNr1CQGmqfZKajIPEv6g6l8RssHX9Kl
         ZjFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755673971; x=1756278771;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xrrN5SYLCAp1CZXkRF85l3faAx00eHiC0lt0d1OzWNM=;
        b=tHv8Rtk3qxFydWMsHEWTKhyzj7TlrebAylsjRoaVkuqmGA8TOR6vViwRp2hkwEDj2r
         3tEv/Uzczz/hpDvoe3hSDzGNV8OPrDKETXTj8tVzR1qioRRiVL4xaW6kxM/Mt79FXRlp
         pjKLGD/DDIfmZrbkh0MkgkBqXivp+Z6H1pT4gTrzc8tW4ndoZHss2hQsJ0rCcSIETL7y
         LxBdvA6uGpWl3GaRWkGmCbfZZZLEP5tA7PEQtD1IaH9/dUZsdOlIrl10djJqS0mkxpyn
         DVqojkKykOWMxRotSYmvBG097QIX3W6KV1EN/1ZiKWW+041Gjm8OhJrk113a/y6kyqLm
         EFjA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkOtAX/7VqWvgM7cArpOEQQCsE5ahS1yuK0pSkI0q3RwrSLw5IC7JQM3y3Fh6UG4sT3HBMlg==@lfdr.de
X-Gm-Message-State: AOJu0YwyXLIZfJrYsFUueEPomYW+8BDHt/8NRwNxwo++alfYedFlfV/R
	ZKgkwu0Yx/1Lkrxv4gfGmftHd1elEAN60fOLHtE6FAJQsvN6OK3r/E+D
X-Google-Smtp-Source: AGHT+IGCkNyGPjNMy2Ywl0Mj/e+5A5nA20FOhzG5hoFTccMpbwLFwffyjDQ1A4fhh7TIsbaatoIcoA==
X-Received: by 2002:a05:6214:2481:b0:70b:9a89:c2d with SMTP id 6a1803df08f44-70d76f392cemr16653186d6.11.1755673971195;
        Wed, 20 Aug 2025 00:12:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe35/8LBHqJk9ZriJDGC0H+orIQg+bsmffROz/QWic1Dw==
Received: by 2002:a0c:f097:0:10b0:707:4335:5f7 with SMTP id
 6a1803df08f44-70aabf21027ls62103786d6.0.-pod-prod-09-us; Wed, 20 Aug 2025
 00:12:50 -0700 (PDT)
X-Received: by 2002:a05:6122:20a1:b0:53c:6d68:1d36 with SMTP id 71dfb90a1353d-53c6d6826ffmr678059e0c.14.1755673970084;
        Wed, 20 Aug 2025 00:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755673970; cv=none;
        d=google.com; s=arc-20240605;
        b=C+SkkzhLZnG8ASDoxc1SaOJV/qMaGUd+hRAqesjkRUAdevDhFQQFjsmdspdpkrHO24
         zXRBw+P+r5zXbneULTzTlZ2vewkKoeqzR01oE0E96gH8dnrVnUVD5rVCZXH1UjypZAFI
         9cvpiutYr07ny3rIZcY5psljdhzyoCdXTepIm/ftH76Yqhg+Cf6uGMXo4pQiWGN7lXDC
         eTAB1PLmXEYtB5AJ0S24wh161gUz4dwyo1bRUM32V0nocGhsUjaPQCoa7dSGDXhjuFTY
         t9LFQC4KTLVwH7kGIcaFtwE6885n3S2ffGiEoMebuq58FNLllXwMFxsg66OU9E/DpyLa
         tsSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=85/+YiMW/jNPE6Ecxn705UrLwZ8ZaKSJ5XDM52Fxyfs=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=SHsH420LHDhoNmEH3P+on/XzMttGLX4iio2UU4L9w+rVKzOsG+K/C8bO5Ai04PA9Gz
         4bB3WeIqRzLq6Ge7rcVJ8SSa+jDM756kVjFEUhXZwzCXF6HL3YpelgqwUB+L29/k5Naj
         cgCrUsNDam6DIdZTBg87dplDq7LUfxwWXJmJ7eFuExGzko5A5IMQab4ZkaPQjo4nSxRt
         kHBkpdNhd4zcAW1P3sP0FdM37SmiN9pGnCv+7sN2YTouW5sUUZW4gMETb+VGeTJPJWfz
         wyRX2KLibvPm6zBJywAmqL7L5xrKDAkIAvfhpCPSN8RtZSOrdbMEfIg2MQ5c1Nr+FrO7
         QvYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-53b2be22c8esi582751e0c.1.2025.08.20.00.12.49
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Aug 2025 00:12:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C3F94106F;
	Wed, 20 Aug 2025 00:12:40 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 19E3F3F58B;
	Wed, 20 Aug 2025 00:12:44 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	catalin.marinas@arm.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	scott@os.amperecomputing.com,
	jhubbard@nvidia.com,
	pankaj.gupta@amd.com,
	leitao@debian.org,
	kaleshsingh@google.com,
	maz@kernel.org,
	broonie@kernel.org,
	oliver.upton@linux.dev,
	james.morse@arm.com,
	ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io,
	david@redhat.com,
	yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v5 0/2] introduce kasan.write_only option in hw-tags
Date: Wed, 20 Aug 2025 08:12:41 +0100
Message-Id: <20250820071243.1567338-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Hardware tag based KASAN is implemented using the Memory Tagging Extension
(MTE) feature.

MTE is built on top of the ARMv8.0 virtual address tagging TBI
(Top Byte Ignore) feature and allows software to access a 4-bit
allocation tag for each 16-byte granule in the physical address space.
A logical tag is derived from bits 59-56 of the virtual
address used for the memory access. A CPU with MTE enabled will compare
the logical tag against the allocation tag and potentially raise an
tag check fault on mismatch, subject to system registers configuration.

Since ARMv8.9, FEAT_MTE_STORE_ONLY can be used to restrict raise of tag
check fault on store operation only.

Using this feature (FEAT_MTE_STORE_ONLY), introduce KASAN write-only mode
which restricts KASAN check write (store) operation only.
This mode omits KASAN check for read (fetch/load) operation.
Therefore, it might be used not only debugging purpose but also in
normal environment.

This patch is based on v6.17-rc1.

Patch History
=============
from v4 to v5:
  - fix wrong allocation
  - add small comments
  - https://lore.kernel.org/all/20250818075051.996764-1-yeoreum.yun@arm.com/

from v3 to v4:
  - fix wrong condition
  - https://lore.kernel.org/all/20250816110018.4055617-1-yeoreum.yun@arm.com/

from v2 to v3:
  - change MET_STORE_ONLY feature as BOOT_CPU_FEATURE
  - change store_only to write_only
  - move write_only setup into the place other option's setup place
  - change static key of kasan_flag_write_only to static boolean.
  - change macro KUNIT_EXPECT_KASAN_SUCCESS to KUNIT_EXPECT_KASAN_FAIL_READ.
  - https://lore.kernel.org/all/20250813175335.3980268-1-yeoreum.yun@arm.com/

from v1 to v2:
  - change cryptic name -- stonly to store_only
  - remove some TCF check with store which can make memory courruption.
  - https://lore.kernel.org/all/20250811173626.1878783-1-yeoreum.yun@arm.com/


Yeoreum Yun (2):
  kasan/hw-tags: introduce kasan.write_only option
  kasan: apply write-only mode in kasan kunit testcases

 Documentation/dev-tools/kasan.rst  |   3 +
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |   6 +
 arch/arm64/kernel/cpufeature.c     |   2 +-
 arch/arm64/kernel/mte.c            |  18 +++
 mm/kasan/hw_tags.c                 |  70 ++++++++-
 mm/kasan/kasan.h                   |   7 +
 mm/kasan/kasan_test_c.c            | 237 ++++++++++++++++++++---------
 8 files changed, 266 insertions(+), 78 deletions(-)


base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820071243.1567338-1-yeoreum.yun%40arm.com.
