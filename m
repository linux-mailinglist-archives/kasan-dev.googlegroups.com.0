Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBZFWRPCQMGQEX6343UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BBEDEB29B3D
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:51:01 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e9339d00734sf3335596276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 00:51:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755503460; cv=pass;
        d=google.com; s=arc-20240605;
        b=RZTtflC4Ggt4gboTfEew3a7k04/6Np0bZZmfcssQLbw5KCxrVMXO95LqSwk45La/rF
         zhnC+wbDZCq9zRAK2WXrXnOySHkczI0YcXShV+h4hcytC2PNpPgEur8C8uh2AlI8ASzI
         kJnOSTqsgkDHhvgGrcTOVzEUa9MLQpEask9+oe2o9VeBY6CJ4QQhvSM0JR4YZIzyjMr+
         /fUiO6NYDBURzkuKRFGn1V4KqjYvpJP/3w2rEjwh+ElvY9JBcEJfVF2zIyiZSn7cPSGl
         Qh36NKI6SeuUpw7lY9QbRY7cAa3K3F1xNmhpIYfhEAJhdnKM2zS600MiYEDTFKi+6NI3
         q21g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2xVS6Z4mr3OT9Rno5QkyKSAS4rWLy4uqLnOItMCxMaw=;
        fh=34lYUuK45xD+NlMXFkWMoPUYLe4W4C7qvFjNDX2yab8=;
        b=MbZJThAnvzntEWrRiKxp9JbwR1mIQq/DCAx0hVRB0Wq3upvFy9SGTFiX8M6pQkoPN1
         vR1dWqhXC7sZQ0MBE1yoSQI6Rap56F1COWuLLS0RrFwovQM396Lj86B6PSfUHYkUqYOs
         wflbRDf09C9HDTvxMRCZgIyk5rOIcR3+h6TMsnjyZHu/HkKC2psSXMit+D5C6h8uR/mD
         sQrOK7n56B+ilVTyBVZU41xmWT8CML2aUuOE1BWe51NMs9Li7WruZIjBCUemknh2X36b
         NCPCLt0KwBeDWR78cltsURFisL+T7zr9SzFtWD+5t2iZz2IkF+uc8+Y5j/4khHM6DkN0
         47mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755503460; x=1756108260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2xVS6Z4mr3OT9Rno5QkyKSAS4rWLy4uqLnOItMCxMaw=;
        b=Xk3L03om3+UjWkzHvjyuus83TFr73YKcY+jhXzZ7uiazw/wRuAaE54mZuoVSs7RjC1
         4J5zlR1E+Y/mF9uevxM5BwmAnrkJFok27r2GQRIymWbMGaHTcBvltvMMqLeUK6fTDf45
         VnTrOe/TMjYWorhzylk/NmPVGW48v7EmtfwgEQi5mjxGTYVfQaOz7AX7gfSu8yVnMbgI
         NY/NCyeZgjBjjsumEO97oNSYIFuiO5xQnUpLgt+sNO5hYCHiFasDnRUHuhpc1uT0belM
         hRditQPZgcdxSkI+6CHnC01B8LnzAl06Gy1NOBhlnv/RVp35bzHUXrLfgRI9kw7kMW70
         aizw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755503460; x=1756108260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2xVS6Z4mr3OT9Rno5QkyKSAS4rWLy4uqLnOItMCxMaw=;
        b=xFzJUtFelhwBOSUJz6jp2kSGBgX8AeswOSshUlYy3vJ0YYDZWZwIm4juNYSIBAmGte
         F+aFibNZS3Q5lBG4pEpu4a0SuCbD4/ZP+/Xl+G7aSSmoQj1Bx0s3yPjsPtrs6VNtV3RK
         EyDEkScoWGXuzd8l3PwhAp87/mvlXnCcMEzuY5tRvHw3cDbXIJ4IhQrzV2F401ntSyRs
         GN73kr2JAbQyUI0CdO1fTIn28VDxM99NkzZPXcpgXb1bfB3qdaeYziVt7Fn/zk90N4z6
         x5x/yd2l+/1MtZe5Db2o+oK8I5CJpPqDxevWf9MW5eoGn22+z+Bf7rf0R0DvErV2duv+
         E0bA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQOH6/eB55VSKbeF63xxWpiWX9Z3YXo8pVHEm61UCZA2VDO9xq4MXdAmvO+Ot49XjGWk6+rA==@lfdr.de
X-Gm-Message-State: AOJu0Yxyys1IQGvRvHRs8+Xh5p/0zOPQWO3lpryTNbl9ZxAIGou7Aw5S
	nf7Ze6xc9H8qUeiaiDgEGW64Lpqzc1Hv1YRO2aF0ER9XAM3zajS3MTTY
X-Google-Smtp-Source: AGHT+IG8KGAbKdxMhs7trc3ZeIbriOKXRu6IA9dCYfDHsn/Ekr98xlDetPf4pouPtZPrL8nCHheyHQ==
X-Received: by 2002:a05:6902:1146:b0:e93:4610:5a26 with SMTP id 3f1490d57ef6-e9346105af8mr8046127276.34.1755503460269;
        Mon, 18 Aug 2025 00:51:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeeZ5WYFISlP7ilAKMlDDW/+CEZU6hzCWeUxL3uXIZB7w==
Received: by 2002:a05:6902:907:b0:e93:469b:7684 with SMTP id
 3f1490d57ef6-e93469b7950ls1284704276.2.-pod-prod-01-us; Mon, 18 Aug 2025
 00:50:59 -0700 (PDT)
X-Received: by 2002:a05:6902:120b:b0:e93:43cf:3d6f with SMTP id 3f1490d57ef6-e9343cf5371mr8505685276.2.1755503459510;
        Mon, 18 Aug 2025 00:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755503459; cv=none;
        d=google.com; s=arc-20240605;
        b=JwGz37LTsnenn2WDGMtMBugcJ98nDsFsWoI7+AWib+qqFt2yBSNFL5i3xUeE7dV4MC
         I3By+TYSdPKA3/kHOIpdmrA2EMM/3OtH16hvHpZNhhjYDw3P/FaG5hY/8F2aHUkcCIgf
         5itt5fSb4CciGAB3TaViWr1SBzSNAZwMH+WAkxt1X7n4CXJyENBBaPmAtDOu26NFYEXT
         whjOvjNtJ0ggDj8J6WXCt9PiNWGcdTRLrMyxpQBRwx1XiIYWG4oV7GTrjSxs/n5pxzV6
         0JIQFyYMthI1UW4f1Lsq7l+8T5VeFSky+7CNtxE9pOYd3lJupmlUji4olup8i2JmBnDx
         qCbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=LzlhayvUx39iJ+7QhG9gpaKkV1t5aRSU+oJ/ZcslHk8=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=dlELruCS+RX43TwtD8rvDtDOo5L49CEkl6OYmKqtzJRy20y8oGOrldY3s1A86NLOp/
         u6095IW8R53zNbgUm2DMIF6H5ASmLZGUAN+mvzMlZ10JP2uz729qFjj7LwwiHq8JxFik
         x+9En5ubDKEX7YUBl/6gdQi2UePYPy8hl2RJCEBiksWO8zAin3r6zIdu6aUEGm3dIctq
         mcOZzvyUs44BOqy7kfbQo9TxOs2mZLh6G+sR7jZwW3B7LRolJ94a6osJrVv/JTyrgh1h
         lvolbclyqi+qCiqlERHSRuMx1x+a3ftiCf3oZnur0qJrE0BjdSU7pm/BN/tbI6o6h6cK
         VjsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e93323a167dsi411587276.0.2025.08.18.00.50.59
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Aug 2025 00:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A088C1762;
	Mon, 18 Aug 2025 00:50:50 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id E2CF43F58B;
	Mon, 18 Aug 2025 00:50:54 -0700 (PDT)
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
Subject: [PATCH v4 0/2] introduce kasan.write_only option in hw-tags
Date: Mon, 18 Aug 2025 08:50:49 +0100
Message-Id: <20250818075051.996764-1-yeoreum.yun@arm.com>
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
 mm/kasan/hw_tags.c                 |  54 ++++++-
 mm/kasan/kasan.h                   |   7 +
 mm/kasan/kasan_test_c.c            | 237 ++++++++++++++++++++---------
 8 files changed, 250 insertions(+), 78 deletions(-)


base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818075051.996764-1-yeoreum.yun%40arm.com.
