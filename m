Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBFFQ4HCQMGQEGNM3ZKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E91CB4243B
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 17:00:39 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-329ee69e7desf1943437a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 08:00:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756911637; cv=pass;
        d=google.com; s=arc-20240605;
        b=dKLfixmCFBGNVWq7HCLv+81ihoFwdu+ymIY5zTqLonSOEdh0FCBTilrjeyhKXZXFWs
         kCQ7IlCMiAejoV4xcbuzwseXTim18nIv7L9DtyBSY1eOyCHplmV0nfGow3M3hT5f/lrf
         YuYCRCYOr/ttCjzCEmCjn7XEHE7XNTEeP5HcZu1CgROdGrFMDCuQxeXjE9YwSWoin3lN
         Nlxlr+Jw+ADYnV7/Ydezv+vXqhu1YoF9aTm+6vb1UZ+zBIGIPGNrggA1DkZrTb13zu15
         GIRX2fHiWXMvayWGllNXam96sFZn9dOZoPbEPbdBZooIhLOFPh8b4C9h4YMUwCAdbQkE
         cmdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZZsBBgqoj4OoBqMb6dq/HsQn8/2ClHcFMBKG72oLpi4=;
        fh=jP6l/7PVHn3E+hZIOIbLzTZkea6+PspIZfZzWduhz4g=;
        b=Zr5L4zagAD2PAAT/Y/B04ic+efWejEfs6IfS6mZ184QNcH0bPPz9X+gG7HVwWkafgw
         dPqGbDk5hKcyW49YTbgAtsaJnTdtx3xWnRofdXaFe570NucI46eOPwWGBG9Fcu2sI+p6
         HlQ+pmyDJpovYeoalRZcvjjisvwPoyCsMGpckbfm8MbhDShxy6Fp3/cznid0XyX4rkco
         DnbKXipgG2FyB7XUmA+DzXX9nJsbS/rFCVeDg7WS9Ir7X0uegTUW7vQYW8djqX+iPyLX
         QG0GR68D5hQcOFS/3U+nB86kZf/L5CNj8+LcI411lHIV7DycN1G3kPQeAh9RsU0LfSwO
         iRBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756911637; x=1757516437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZZsBBgqoj4OoBqMb6dq/HsQn8/2ClHcFMBKG72oLpi4=;
        b=QxZ9wvMVPT25t54iEETAa89Tmf0UES9Io+QfITP1mfHqIPv1nQZVBtLQF4l9lrBHz3
         ey+iJ8OlRKBthidT3w2zWVSiESSSOCXQ7hb+3kl0D43TBNuLJEy9iNWxa3W1T9zyurcT
         USypfk8+XM0fBBrk/YaeR3LmL6+pbqS2TCrNnU+lkZyT/8reJssmir8y52l0PhgJII6U
         Eahbx3U+695JI2oXY3fyJeVJFyhtUWb8QYd6l5crq7o0DZpeAX98+a5ZbWVnWJvpdLD7
         AyhOXYjGq2Bbqze0rxcgnXQ9cB7Ax6GYe3ckG26Y8feU9x7B3agPVhlGrQ4H9+yagD3Z
         HeIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756911637; x=1757516437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZZsBBgqoj4OoBqMb6dq/HsQn8/2ClHcFMBKG72oLpi4=;
        b=jS/S4fqFxQho4F1+IXAwXgkifOoWL8+p5c5Na/UDm5D2L1FaXa/gDEUPfrfBDIL4gc
         jX+o5DAs7BqHPBGwbf/YFITXW1axJDNljnTKQ2ePyCfqxc0u5+nSIq9OTg/kf37skGEF
         R/ORbim70HZhdIXgi3mYSAQeLIDH2og43F97i57GRko8Iprwp6s8bIiGK2Xr/TeL5JYU
         eUCqKSRc1f/uqLvLcKIOixYFZyAUK4fxFETiN0qz++6DcE/oQFV3s+CVUUbibaNZ1zen
         ioJjFapK9GQ7MWpEae43fo1t7iKny+lheccSTSRC9/bOIMUd9SpEc9hdPbpTFWSPnUWi
         MgQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKgBVI1bxI4F9E+eLpKNQtlWpCWYtIoWLDFN9kczhYVNuI0kxhyraoiqYukph3xZp0PqX4wQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbMBuCQxft0PAELMJSszdvoPxu8g8NmlxHcFr6OH0oL6BvemQG
	18ZjyYa/TyIob/emc1YETBmqg6oj5xEO7G97D22F5O9eGf/72QUG9ZUu
X-Google-Smtp-Source: AGHT+IFJnhYAxUSXU1x8GaX2e+U4NK680DFObF/7DMZL8cvx+qlUC3FnP/iW2tc3Qn3Feegg+M3ZLQ==
X-Received: by 2002:a17:90b:1848:b0:327:6de3:24b6 with SMTP id 98e67ed59e1d1-3281541223dmr19750196a91.8.1756911636730;
        Wed, 03 Sep 2025 08:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfVmP4JuizXQ+uJiu2m+megwiMSFVi+vvoe/h2UsdJM0A==
Received: by 2002:a17:90b:3754:b0:31c:c0bd:10f8 with SMTP id
 98e67ed59e1d1-32b5ed78079ls944730a91.0.-pod-prod-09-us; Wed, 03 Sep 2025
 08:00:33 -0700 (PDT)
X-Received: by 2002:a17:90b:3148:b0:328:650:4e7a with SMTP id 98e67ed59e1d1-32815412274mr20795377a91.3.1756911632885;
        Wed, 03 Sep 2025 08:00:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756911632; cv=none;
        d=google.com; s=arc-20240605;
        b=Dz0NAAZfvqbqWrK6fyQTAczjvpHjfyoTLBCRXmx2au4dJsvMWPdBd2KRZrmJHGkSbX
         6MK14xkkBstIf3Tkptj1awDLHQnSmXfLcDEotBiEGtvuNSjemlfnB4tsRIoZz6Hv82H9
         g9i9j6M5VK+bVGXjnD9t9ytcHhuFyT659Uc+rhmdXkyssN7qOiHgfAVDXHXP4TZMLsHO
         LKL20kul+gf7zq5b11uzpcnjsTJh5NQg3EpZQ5dYOqldDd2jIQwh2wpNUQLoQLllamdw
         Jl+aD/R344Q9Akgb1ii481HK7mgTsA+b8uze67G0Wc+tACGCuzjnGk9DePYQu029IhbC
         ePLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=GWtECCYO/W3ZeQTeOSKG2/hfJYDhLePie2ke5lizwtk=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=GaARG3pUWxz3lIKaMAb3kuhjFZQssgfHC4TyuIGxtRv3sNyUKC7qp1RlSITdCSkco9
         ddELRIX9LpD4EoJ/rciVwSFS7dfN4TKWvOLRTv58TLSkmy2iFfICkWuqD+pZUq1v/CwO
         Jrj/mfR35TfpJh8l7nJL3xuX1XhvkZ1QabshKUx6BvhoQmuabU0nIy3JYATk6NaSk3D3
         Bs6roxd6s4z61wLjtr2B6ZWDWZ35iWb6ZfpUQ3zuqPUc0n67O5hFHxdZl8GCpmTSX8nQ
         BVx8HFxFwLUro5MDmmmTiVfDKzpcw1vFluSTzoB2QqrdzUIHLf4DUfx91dHRmbTx1aXF
         e2qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-327914df480si492528a91.1.2025.09.03.08.00.31
        for <kasan-dev@googlegroups.com>;
        Wed, 03 Sep 2025 08:00:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 65C9A1688;
	Wed,  3 Sep 2025 08:00:21 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id D89543F694;
	Wed,  3 Sep 2025 08:00:25 -0700 (PDT)
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
Subject: [PATCH v7 0/2] introduce kasan.write_only option in hw-tags
Date: Wed,  3 Sep 2025 16:00:18 +0100
Message-Id: <20250903150020.1131840-1-yeoreum.yun@arm.com>
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
 mm/kasan/hw_tags.c                 |  70 +++++++++-
 mm/kasan/kasan.h                   |   7 +
 mm/kasan/kasan_test_c.c            | 205 +++++++++++++++++++----------
 8 files changed, 240 insertions(+), 72 deletions(-)


base-commit: b320789d6883cc00ac78ce83bccbfe7ed58afcf0
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250903150020.1131840-1-yeoreum.yun%40arm.com.
