Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBJGU5DCAMGQEHJBYGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B746B21353
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 19:36:38 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e5142a6c57sf118528455ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:36:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754933797; cv=pass;
        d=google.com; s=arc-20240605;
        b=DEstVL5kEtUrKwaHiuPQaK4R6EeoWqqJP8lv19GLxYWuSG4taT9NXgTVR/aqmwR67F
         PojCwy71lUZIfZc0kSWJO2MQlfWpyPuanjoyDyerRxVvAlvdq8+opar5wYCaIp4J6Rfg
         WXAY8hWfOKHVz456ZPVeXuWsn5ruQZK0Lc/XgvSbUNghxN1vVXPcafSZ+JhK0Q2a46/7
         /nfhVsisA3r/5+Fq+y4/3IJx2ZN9T/yq9xCfXVgFgrzCU4Xbx8lZ6Kb41o2mY09F/56C
         Y0H0zRtBuWwGF7q0LOm4Px9jPTW6ipwByIe42bYx5RM29T1/cSaYFE5mT1B2KO+vbxja
         YT9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=It7MlEIqgZSIsTufxNcL/JKYOKYnhm9G5cgmSW6FvjE=;
        fh=N+y/rUsGFp+r3W1yguZQssdsqLTl4EqzAf+gyP8x884=;
        b=iD1TMVmt9SlX1GnIW27egWSsiSwWZ/W+MgjiJzc/D5mNxwQbSvLNPk0bkps7HTWVTe
         bctxFsV8r+ukzOEnmFwRwLM38N3rRy3F5X6cWmSJVjKx2hMKTRM2tzTEZ/iOg0QrE5Ti
         j32Mw33Ni7Bpa0T9krqPsIt7zWkuE/WlvVc30Rx+cHB89hQg3bCCE9NxAvIOeFIRgVXK
         K1Zo9W5ERDikp2QampEBEQUdTTqyw62xYMIIwuFSwB1i6YjcmG08pMjhpnIe2ZbIrDdM
         q2U3J9EaQjb7gP9VzO/fTNcL4Yt40vnu3KWsw/WcZlsY3VsFtlPts5IPz3VfBHBfgouv
         qH/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754933797; x=1755538597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=It7MlEIqgZSIsTufxNcL/JKYOKYnhm9G5cgmSW6FvjE=;
        b=kJ2XGwMpeYfByXH/EufvCPT+qigqc3kRkgwGMY1CAo8oBV7EwGodvrYO3s4HJ5pO7+
         AkFtD8YvKfxrWdhWxxjaATRpVufJooIPN5FQ2JEH18FTfnptPJ8srDED5nUtS7QtPQUi
         QIUljqdEEgbzYtU32WIQTMjzudCdSwTNPrSco6So4Doxi8qJRkgs5UU54ZLjL1WViKHM
         zjxJwrAXipkS9f1iTisq+QnpGaJWdxMlZX4hEThP8YekfvklUZg9WsBjslrZidys4ga7
         uuKJzanyjE/JV+KMG8h35kIbXkdzc9OhetmnqwGxmQufX+U8Zy5aRelHPC21bh9RSIs8
         r4VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754933797; x=1755538597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=It7MlEIqgZSIsTufxNcL/JKYOKYnhm9G5cgmSW6FvjE=;
        b=E+lRy/i0bvf7nGea0QXg3pKhM3mAeCHykp6cLK0AjWqiF2BGwhoK9VWShOe67tbA8w
         v+y2+ruzblTdgZSxkZLPC5XFZ+lRKCFhkBsRwCS4bCBT1DXamvV4vmbDNRgHsZLDa3g2
         6iAHFXbraQ7Lk610I7UKLXBU3XFzVQy/47X9yBSQMVy8A3lpWcf+BoPkkOZSPTgyjz69
         AIehdlwQHJQjMnBjXRSq6Y3fiYDbjCN3xP/gysbOj22MOZwLwwcYVqYPRgnBq/ChJu7p
         TNsMlmCpd4lRVaUVfNpcHfSOr75V9XcMxQSHvZoO6isx8hGVvNOJbQW6vRwtvkGupSVF
         jlbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWR04MZtX+jePb+GvVZtmQJ3D5MYLrZB7hftn/ieTYX4DHfflXaRU5BQaLs5p8eNaU0AowRug==@lfdr.de
X-Gm-Message-State: AOJu0YwG2XQ+pWKoln+HrnUMylJ3qnhgZvdw8S0bP+Z0kWwo/bvIagtI
	4ajmCATZiYqS4oUslYC0qAea/PefoZiQ7Yy+XfqCmqB7iYBl55IJ2lG9
X-Google-Smtp-Source: AGHT+IGCc04jxvdomfoVMIQlGK2juTViO25gDsK3O+e9LVYXW4/tMG+EGGMGIgzRUKXiuj1jIH5Ssw==
X-Received: by 2002:a92:ca09:0:b0:3e3:ef06:674c with SMTP id e9e14a558f8ab-3e55b059546mr4416465ab.20.1754933796736;
        Mon, 11 Aug 2025 10:36:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmx8hi2kfKUUrAObqRdgLLNn0RhbnmzZYiLSTsCmQ/ow==
Received: by 2002:a05:6e02:4903:b0:3e0:5c71:88f9 with SMTP id
 e9e14a558f8ab-3e524aead8bls55719315ab.1.-pod-prod-02-us; Mon, 11 Aug 2025
 10:36:35 -0700 (PDT)
X-Received: by 2002:a05:6e02:1aa6:b0:3e5:4351:ad0a with SMTP id e9e14a558f8ab-3e55af4eaddmr4198385ab.7.1754933795534;
        Mon, 11 Aug 2025 10:36:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754933795; cv=none;
        d=google.com; s=arc-20240605;
        b=WmsK+Vh6dQyryiNc2hXw9RNFdhYb1jteFyK5fwf+vDXnl3HP2W4DfrenTwReH9ougs
         QWxh7Qvd321AP3ulbUpsdTax6GkXz3JtyIhtCbOZITZZZd+efd1Y/UYjVxOPguu/DLoo
         qds9u1/ygydYduGixd3FUgjk2JDOr5w0Vh4xGR41BBcR/MVqpoTb7SQKzw2leHZe3RWr
         brnnjB29qR8FNVZik1TcKp4rDpYH3DP1XvcBnVWiL/97iQPHKKTWxXgthicfUrwncMv2
         HTpalW8a0yhaVHENH7fJwuZ80aDqagLOdUHE0HLIQBVSgvmgc9+ch3JTr2EecvCOYWLK
         g4ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=0J//ZXltFEFiHPuvSR5EwE7cIsv7sl+t1JLUFLvA0g8=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=GUYj+bGb32G910WrrdCg5INn2qjro7QmzkWzfSZHyw5KMwJuyJo78Ag6QM+dcS4HtQ
         gFeUht3dMmWS/XE/L1rXZfDVP+yTGl3t6Z6p6Y6I8JgJ+UjR2FXCpKbTmCZmnf+Y4DJW
         rh7mVz9/uYHcvd0uhS5ZzgnTNnDwUghv6fQb3L1QeNRTp6oziOyRDFpSipzLHfJKE1eT
         3ldBOTd0wBatpyuTny76oyEPstLBkp31h8TzX7iwqHww5RvLctqG6uOxfdNWMTz8Pdln
         xfC2ce7/ibOBRhMcVMsvMhI+MrgI3+/V14IPsi75RrrXR1Cg4NrUvt8xt+cNa1pS6eii
         lFQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-50ae99c483esi358539173.2.2025.08.11.10.36.35
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Aug 2025 10:36:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 96350267F;
	Mon, 11 Aug 2025 10:36:26 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id CDA733F63F;
	Mon, 11 Aug 2025 10:36:30 -0700 (PDT)
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
Subject: [PATCH 0/2] introduce kasan stonly-mode in hw-tags
Date: Mon, 11 Aug 2025 18:36:24 +0100
Message-Id: <20250811173626.1878783-1-yeoreum.yun@arm.com>
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

Yeoreum Yun (2):
  kasan/hw-tags: introduce store only mode
  kasan: apply store-only mode in kasan kunit testcases

 Documentation/dev-tools/kasan.rst  |   3 +
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |   6 +
 arch/arm64/kernel/cpufeature.c     |   6 +
 arch/arm64/kernel/mte.c            |  14 +
 include/linux/kasan.h              |   2 +
 mm/kasan/hw_tags.c                 |  76 +++++-
 mm/kasan/kasan.h                   |  10 +
 mm/kasan/kasan_test_c.c            | 423 +++++++++++++++++++++++------
 9 files changed, 457 insertions(+), 84 deletions(-)


base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811173626.1878783-1-yeoreum.yun%40arm.com.
