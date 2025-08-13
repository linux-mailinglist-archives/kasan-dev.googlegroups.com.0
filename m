Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBJ5C6PCAMGQEW5CZ2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 864DFB25293
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 19:53:45 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30ccebab467sf293892fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 10:53:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755107624; cv=pass;
        d=google.com; s=arc-20240605;
        b=jqHkdTHo+iEFCfn71agNL9Sj9KiL4qJ1Lmr0ArOxTQQybctkbi1Knh3M0rk/++ALmK
         sasdNLFxE2BSgrDbdf5FUBvoHzWJXc6Mvl2wZuFQs59Y/4RVSjbfmjlEHPmb8bxwStGk
         LoY8ZqBQfygdygOsUDKM1r2SgVwNhoBc2uCTdB/o4MEipYPzDMJtMQlwCfYjl2Y6Eu2J
         ppAfWj4ETP/h12gj2u7B76W0q+g7rB1l9xRkqjTJP0UaoeGsuzTiVnH1Iidpr1oormJj
         6g/zxaNE5k7WA6j/Y6TF5DLd7QR4EPPi7KZQJPT0V9pKQxxpGT3D2hFji5kueDdBgQtZ
         I7sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sJo9Z3agdea7DHdQs20QTVsc7Ovd02i7v+W1FEgCX1k=;
        fh=mc+v9yL89fpCN2U8guDO9v7LRHtwveX5DLU/Ux7uVyU=;
        b=eZbFKIeFwNutk7H/+AreCwEn9zcMDDd+Bj5ZOwV/JYBH1mqw7FiCtf9WDODy5duNFT
         rpTlfPHSNJ22svi04GLI0BNE7QJz4F1wztmXa2o1L7enSR5vpz/HhzmopV629MqfE2KK
         xWZBDfRa1tV6tafhX1Dz4piqpVUX27hDbHHEd0FKS6uO0bkdjVzCFJEEocuEU3C6ii6j
         zeFN6+CI5uDJxt6lazYokwlUdZ7ylUP13qufAj/vqQGgzvcxzowHeOmE+vJ9cEUZKWdT
         Xg2jxg6sbEhkgIR0hr0apMyLhcqywBrfYpj1yOCD1+TLTUj3yU0a1QTIwFAwN5+F+/wG
         pUFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755107624; x=1755712424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sJo9Z3agdea7DHdQs20QTVsc7Ovd02i7v+W1FEgCX1k=;
        b=cwZgr+YrxoZyfF0Rb8352stfgy1r6mGZE5pYE8UmIkTsaacDhwk1rg9ca8kmOacrXF
         vPJ/98wcp1E0gruunFHkskBvXrSyarj/7Ex9kpAP1NohaPiFP8VKaOFP0HCRdYw2YFAd
         m79/u7B3rB+MsGnh9de+qTeGbv/eCh19hyZZ8syZjZbrHtjV2R6GQ+9v8NDSmwuREvso
         KuLIqLlXHfkJrO/+z7fkDFF0g35rBZcAFz7/xNYU7I/WXAgXAR1FwBxFiRcCMvihgfY7
         J56MwwnrflAeoqG8hl2mMmlyDn5Dkpi22t7VF7xGVjy26YagQIsyj+pcGW08RCA14CXD
         wbpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755107624; x=1755712424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sJo9Z3agdea7DHdQs20QTVsc7Ovd02i7v+W1FEgCX1k=;
        b=rUGC9z7E0Rg/v5TKg2SMv3rcNoqSfgrxVUZImrp5hGedRJuHvvEejseVyDczhvoc/S
         +IIyp3aLcXcmxNcuvrvNNhIhlRaFn2CRHnLamIqWmAMfJ5lR8VAzx9o3CjZ9i/pPZmBU
         KYMxulHYticH1iZ4Ac0+4aUFKLrgKfECcqEXDBKXGOe0+h37dQ6y5zpkzrecK9Kr2ZLU
         v7/FScw2+U2c2OlUFZaVT8xpD/iAfWpNOoBLmdSZZsf4qtn/Rz3fQwa0Zv7yVQdG711P
         UMCBy0Z628IbpxkbmD4vsgQb4Isclyymc9ryi8mEXAYU/3XIHpH78a6KNHEjwXu8I2Z6
         uu4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVu7WsYkmYaoePR8Gh4gV7tmNIQzA1F+ubxOq60sWUWFKrUaUKPoWlKhJf8oJldAWW7IcBig==@lfdr.de
X-Gm-Message-State: AOJu0YxcNDlzuN+ELWNRRuPasifPY2FA6K5G0kGH2UhuY52PaG8PdXD2
	Glwo1s6poMxpWdYmNyEdHZWOe8Rui1/EnVBRxJzvoUmC2iXb3NqiZWh9
X-Google-Smtp-Source: AGHT+IHiFzDz031TD7VQFaKcg5u6gez64jIMwJ9Ikjf64CooP56rPyw9enAOeSqeGHqOvhBMWCud1g==
X-Received: by 2002:a05:6870:6286:b0:30b:6fa2:694e with SMTP id 586e51a60fabf-30cd0e34b08mr57525fac.9.1755107624154;
        Wed, 13 Aug 2025 10:53:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcqxOAwTOOvkpCmq3JrM8IbG3zprJIFG/j5+UPwVoFqhQ==
Received: by 2002:a05:6870:170f:b0:30b:af41:d3a3 with SMTP id
 586e51a60fabf-30cceb49217ls68073fac.1.-pod-prod-09-us; Wed, 13 Aug 2025
 10:53:41 -0700 (PDT)
X-Received: by 2002:a05:6870:e24a:b0:2ff:8822:2912 with SMTP id 586e51a60fabf-30cd0daf6c2mr78775fac.5.1755107621712;
        Wed, 13 Aug 2025 10:53:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755107621; cv=none;
        d=google.com; s=arc-20240605;
        b=GFCJG49xm2ftl0UJ2Z63DJUR54yaCmhtVF5Hpb6mPkud96ppcAesL4ESPJr7BOXl7k
         rjIMJtrVAA/95GhGILkp4rwPoR/TKYLWvty+4fFwJZroJdFau3iHxn9Srkx6D4+LQTHU
         AuIB7qmrrNnCpnggnwQ/W7Os/25rt0K+2HvWIbq59Xg/3zoPkvXWk//HpE3+Bbch+q8l
         UZ7DQ14JUl2oWiLRMmYp2v8ifieHfJMQZsTZl64XDMIhNX1/IfASaJOxQ4o8CcJoJF+8
         No8MuXOG0rw6xzCJunGT86HyoWhJxwKajjvsRcykDm9OUPyi/DyvYaUtdO8lUdLdOBvj
         x6ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=OyceOdpHfLwsfhvuMKGP5wYK/mN4SgG7OMbdOTVEmGs=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=YGzm24E4joGgcxeAzQnsdPjY6lRGAQh3BOKs7yhKZm/+spJaxu6cK5O/5qhaQADCDM
         WjKEZY2B1JbzJ30iHXpmxwSr7Tjq8rBxvJtjxHZ1l/bMa6TDaH3zTJoKxwJ/WIiiUB0t
         yNVgRpASP/6Xx7kAZUk5UXEq31KAAVLZClST2vL9dcvPT4QLXoq/8TnoMqjzRETlrsZR
         m7GCqHagndH5LlM3PqbK15YiWXcTjERM6pflAwQ+6cQgcSATFSU9YI/7Nu3xyCSSJFoD
         5Ip+27n2V+CO35aWUTY8co1rccjkBh2p2Bz29VRfYoQaYWInNeWiwaG8AIg0Tt3kEhwB
         mQ+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-30ccfe22501si10115fac.2.2025.08.13.10.53.41
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Aug 2025 10:53:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1D3F212FC;
	Wed, 13 Aug 2025 10:53:33 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 5C05D3F5A1;
	Wed, 13 Aug 2025 10:53:37 -0700 (PDT)
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
Subject: [PATCH v2 0/2] introduce kasan.store_only option in hw-tags
Date: Wed, 13 Aug 2025 18:53:33 +0100
Message-Id: <20250813175335.3980268-1-yeoreum.yun@arm.com>
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

Using this feature (FEAT_MTE_STORE_ONLY), introduce KASAN store-only mode
which restricts KASAN check store operation only.
This mode omits KASAN check for fetch/load operation.
Therefore, it might be used not only debugging purpose but also in
normal environment.

Patch History
=============
from v1 to v2:
  - change cryptic name -- stonly to store_only
  - remove some TCF check with store which can make memory courruption.
  - https://lore.kernel.org/all/20250811173626.1878783-1-yeoreum.yun@arm.com/


Yeoreum Yun (2):
  kasan/hw-tags: introduce kasan.store_only option
  kasan: apply store-only mode in kasan kunit testcases

 Documentation/dev-tools/kasan.rst  |   3 +
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |   6 +
 arch/arm64/kernel/cpufeature.c     |   6 +
 arch/arm64/kernel/mte.c            |  14 ++
 include/linux/kasan.h              |   2 +
 mm/kasan/hw_tags.c                 |  76 +++++-
 mm/kasan/kasan.h                   |  10 +
 mm/kasan/kasan_test_c.c            | 366 ++++++++++++++++++++++-------
 9 files changed, 402 insertions(+), 82 deletions(-)


base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813175335.3980268-1-yeoreum.yun%40arm.com.
