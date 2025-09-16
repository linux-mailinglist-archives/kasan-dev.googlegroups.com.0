Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB46IU7DAMGQEMFAE5BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9549BB7D588
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:25:23 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-32eb864fe90sf2126943a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:25:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758111922; cv=pass;
        d=google.com; s=arc-20240605;
        b=h6avSFgxIBHqlH+/iawZ3ytNAzxwP3IDE+lls2of1YGgaLS7waWbaCyB2X71hIB1Y1
         +u7ForpuDHHtsFU5G2g4JoNIUC+p8wGqME7LKfa8AbHQQSIZsJViZF/BLZvHgCrwPo7e
         hHN5K2+EVsymhzMrKejkguYp/4xY6SNyJNJuK7tUZP5/tAfQ9CeIW8r2eywmN+W+aSK5
         zWC93TqVhIvtfAv7R56t2wbFbt6rSjuMDfgEDDs1ZS8Nf3nuXSZWxh0aTaclO8B6+JrC
         XNg5SnK3SaKY4OrxSZEOPZJ0PMGUWMnj1Yx0zkNlVpXXQinrellNFvcmqPC4EMyPHYQ1
         cCqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Kl8mwGfh/bSAb313qOK6+RWXwbpMtOJe0onAoPmNCJI=;
        fh=ZfB2SGGDFIxSHWKeliWRqvqQansW0kldWupLRbFMRR0=;
        b=Xm8usRN3crGjmORHe+wciGlMHkwAd8QpRXWySdVJtw3P/1NlRiAS1jwItfYnO/abxs
         uHhWVsYltYs0cgemk4gvcUK6Gn7xHiwmql/H9cW9cqisZ/lSoLsXxAcsmvtdpfkMym4k
         dvBgqWlDcjW6kY6AX/oUJbNLUO51fAIzjyu+Fe+CFJZnXgSze3Y8j6R2QH9rW/AzB9r2
         wT5N3OFBjwqSn4NPaQQBb2WNn6+Q5GeSbSuzLokGmznkafyJaxQdaKLJG/vYO7lRPm5z
         UG5OiLfpQ1LAyP6vBrBBhP0QURXiUMod0AoE2JDZrYcW4Pkrv0avLGqzC1WpNtlw1SMx
         GXtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758111922; x=1758716722; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Kl8mwGfh/bSAb313qOK6+RWXwbpMtOJe0onAoPmNCJI=;
        b=sFQIABd2kLzHWoM30JYdWmNzhP+9OxzL5DY3vqN3Rq7Xb3N/7mY+kGMb/XlIFLzCZ5
         wq8d07I+msXiJvSdAsXE9kuHCsapQueSLELGDAYWZxJX9hO53H61epSNQh0pr2GH2HMV
         mV4tNITXFq6UxpUhLvGXApWgIllAbEE6B0FYyK/+QVL3hno9YZZp2wzSbygkf1J9OmTO
         +tSqnTUDnKCgM4IRznDsYH8j3Sx+MwwR33D3jgd07XHlhG5cDSqADZ/GAzDoHd/waqx7
         T4u8FLtiCHmit/uul0ESFFmGyVLJoPzLoyIeRW3aIBaA4NSDYwF7xgFLTiOpfSGGDoHN
         okHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758111922; x=1758716722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Kl8mwGfh/bSAb313qOK6+RWXwbpMtOJe0onAoPmNCJI=;
        b=Ic7hVyfYB4mkMbmO8eOpo15xEAn5CSa/5argNImwBEfHDgmMHkq0c1YR94xr+Huumw
         GjQVPv3xjGSc4iYHYEhCkd/pri1ntD3+puCepDBCLSVaRvE2YH+gOzo28Zko8Ly8pgV8
         kfw0sjaggIhM/G2GgnnDxcZ2iJ9IJ8O1kJVQpwpbeBtg3hSpxbqWMGfNpwufb1/0Xyas
         9mocJ3SmDbjCyjCOE2U2IsG3Y/LwnVrghwOwBcIYDgpbJvMtwRlTGCnAZjbKbfVN6ym/
         0DlT2zaXbIpdq6O2xbaoPR/xEBWbtEIr9ie/C3nQ2wQ75qaJTOayB9xTpyZkmPOBWNnT
         Kppg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUe7ldFglXfKDAlxlqGqi02k23bMLoBSB59ejtQfi9YH/BtE2eG2IZ42T8YzkKfB+1lIbBVkA==@lfdr.de
X-Gm-Message-State: AOJu0Ywi6cAzh183ucr7g2rBubg77J/h2jvFt/lp188PJ1Q68JwDbruj
	lYWmQAiDyeOcHve9o927MKVRDJT9+IJafte46s//zVZiFSy4sxf+kNtZ
X-Google-Smtp-Source: AGHT+IHWglE95rvUPUJEBu/ndC0ZLEouiy5jaE0ojh6yWVaXBJwzl8MMQUbLjuBgaJV6NpYmaG/OSg==
X-Received: by 2002:a05:6e02:12c4:b0:424:826:4f03 with SMTP id e9e14a558f8ab-42408264f9cmr74258925ab.17.1758061683560;
        Tue, 16 Sep 2025 15:28:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6OyHdo+YWmoUGNB3Ni/uYYbxlQXZ9jHmDdkpzv2yH+/w==
Received: by 2002:a05:6e02:4604:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-41cd5ab6765ls35683885ab.2.-pod-prod-06-us; Tue, 16 Sep 2025
 15:28:02 -0700 (PDT)
X-Received: by 2002:a05:6e02:b2d:b0:3fc:733b:326 with SMTP id e9e14a558f8ab-420a6110205mr201124845ab.32.1758061682672;
        Tue, 16 Sep 2025 15:28:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758061682; cv=none;
        d=google.com; s=arc-20240605;
        b=WfOzjCTaM8TGk/4sAmIJlumiullbsjfUgk9iUW2cEXXbzQKjvHNVw8uqam4XiqiYO0
         H0w1+UQ7TBmBoJk6jccEZ70YDeRfLS2G/VhqKqwG3wiSiinxs3atp9dB7Y9ptTTA3usy
         gtPawLL6mn2UmbwKhUoptcJOLOfBNwQ2bKTUZonWEPq9Z5HcZs2fdqXls5JuSENoU5EN
         CoYC2rkODbAX7ciBApgZ7wIsg6aTzrSTbGNgtmkVVEEgr8k1VVj+YvvPgmXYHl+gBKoS
         vFzoMvLZOA2s0qbVz0QoTmz1ck2LNq4gRLj1dyyKLY/3oFCGVWoUuyLXcCVb1cKwLUnE
         yPrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=d6Ja7gN74jIaFJCh7E3Hv4bPB5sQNmEpCjuGsIoX0Dg=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=X0ITmugAtLFIy8f1fneq0FrXuHvh+xXAeuTeHtjqDIhOjDZd/7dBaEKy1R58MEu0hx
         Ia6tZpGDHr0JGUKoY3U6vUNK18P0wJ30gDnAnYk9yw0DFRBQgMXnsOmgLhqlJUaUNaoq
         FLgKPBbdhCGYU/LbuQd+DP++a5hKbTXvaWOy8mjo1MHvZsK4eEMZWq4GbRFJjbjnegC+
         5tTtLuDAOB2wTTziYSBe9XL+RLNZBiivGbEOxCWIJtiMowzftiZVTUsM/eWK8E7TKawP
         ntKZeO9umi9HAsjTD3Yk6y++VwtGmRo1xPOKLiQooTVDU0+cehmIbFQUyIHhhVBqfWZh
         V4QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ca18e2360f4ac-88f2f0f9a8dsi18539739f.3.2025.09.16.15.28.02
        for <kasan-dev@googlegroups.com>;
        Tue, 16 Sep 2025 15:28:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 909E212FC;
	Tue, 16 Sep 2025 15:27:53 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id D3F533F673;
	Tue, 16 Sep 2025 15:27:57 -0700 (PDT)
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
Subject: [PATCH v8 0/2] introduce kasan.write_only option in hw-tags
Date: Tue, 16 Sep 2025 23:27:53 +0100
Message-Id: <20250916222755.466009-1-yeoreum.yun@arm.com>
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

This patch is based on v6.17-rc4.

Patch History
=============
from v7 to v8:
  - remove useless kasan_arg_write_only and integrate it with
    kasan_flag_write_only.
  - rebased to v6.17-rc6.
  - https://lore.kernel.org/all/20250903150020.1131840-1-yeoreum.yun@arm.com/

from v6 to v7:
  - modify some comments on KASAN kunit test.
  - rebased to v6.17-rc4.
  - https://lore.kernel.org/all/20250901104623.402172-1-yeoreum.yun@arm.com/

from v5 to v6:
  - change macro name for KASAN kunit test.
  - remove and restore useless line adding/removal.
  - modify some comments on KASAN kunit test.
  - https://lore.kernel.org/all/20250820071243.1567338-1-yeoreum.yun@arm.com/

from v4 to v5:
  - fix wrong allocation
  - add small comments
  - https://lore.kernel.org/all/20250818075051.996764-1-yeoreum.yun@arm.com/

from v3 to v4:
  - fix wrong condition
  - https://lore.kernel.org/all/20250816110018.4055617-1-yeoreum.yun@arm.com/

from v2 to v3:
  - change MTE_STORE_ONLY feature as BOOT_CPU_FEATURE
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
 mm/kasan/hw_tags.c                 |  45 ++++++-
 mm/kasan/kasan.h                   |   7 +
 mm/kasan/kasan_test_c.c            | 205 +++++++++++++++++++----------
 8 files changed, 215 insertions(+), 72 deletions(-)


base-commit: f83ec76bf285bea5727f478a68b894f5543ca76e
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916222755.466009-1-yeoreum.yun%40arm.com.
