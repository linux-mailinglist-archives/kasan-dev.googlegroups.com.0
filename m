Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBSWJQHCQMGQEDBF2TKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 373EBB28D35
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 13:00:28 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e8704a883csf656710985a.1
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 04:00:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755342027; cv=pass;
        d=google.com; s=arc-20240605;
        b=GRvu6cP8uR7sH8cvE33dRCYW640fR0TWHnmW1InMX8Mve/Gl5Kr4a39kc6h3u3Gqgn
         u5RQwCICNa0qKFIN1OGodKfkjsgvXhVj+G4LhehaedVQWW5ofRMACq9fBWB9h4pxqhiP
         kiDgmIsH5v4E7fzHsz9ukrSdnHg9czzPTp7/fokvQX2BBsYOaX4eF26lQWz/cpv08U+R
         cp+AH/r5N+4VRXWYjU28DxXkHRyzBqP2Nf+KGsEfD5/BX8kWeDBAm2mnCyZvjgJaFCND
         w2EF4+xSgEHpiFfQOxV7Ine6SuHkdeqFfDincrK1h28erijc1npvdDNgH/UD/L71s/dp
         F0RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zgwXI88pV8RGvezSBPpyv8A3hLCLVi7LwYf/rtNNhug=;
        fh=2A7CWjWLje7QKe61m6LPcQvhM+RPzhWxXt83BUIooX4=;
        b=WBIPHOdtPnwWVKXn+rBVmlaeOqOuI+FS5SAAVOTk4OhYLyyw85eIwXV/6/odW23gXy
         pUcLNcljDF7+pzKDSQsN9F8rT1+y4EKOHPfahw+/JuFXw/ZW+PrYZZHT5vu8+fTaLany
         kx2v5C0C36x701dOS/1fkrFEw5S5sKhWYdcUNboSFpG5tuE6aF3tTo2LiJ62a4dTwiSD
         C/kRNLa1UUPMP/4zAOnQFXzDEFtx/KvsMUaaidxOMqyLi1VrdqbmjlRmUvUjWGUeWj5K
         YnN4OLpWYKTRbdqd39JL/lFppsG0gPce5vTKMbtdmUOn9MxpwRYVay2gOiaRokS4Myi0
         GJfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755342027; x=1755946827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zgwXI88pV8RGvezSBPpyv8A3hLCLVi7LwYf/rtNNhug=;
        b=n+yPKGv6s4LKEdJ7pV/3K6kmu5bqtoFJ9vLPo8G+MIteMINxvOIuJ2exr759UlmgXB
         lUesS2oprK3m/65gwQmDU4I9N5KlaVd5tQpm2SJFkm+mwY5ehEpU9yM1SZIjeAfTVPLB
         mJSB7D46eYO+XTHHpstEBGKW1E8VeHkPH7MMdzKMWO525aUmwxAOxUn+oJAbrtfuk7Y3
         85jXYvxhdT+JXoTEDkMRIetPTZ7B3VAhSZSIuXEJf2CtdPk0VhIotLelxofGfB/sGPjC
         EplNAn1w46anvodqDoSlhbpT6pz57BVOqyFAJtVi7qhzUhQmk37Z0xKuXagk9LPuknya
         QMvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755342027; x=1755946827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zgwXI88pV8RGvezSBPpyv8A3hLCLVi7LwYf/rtNNhug=;
        b=PGXNwXcdORwBIjMv9L0ooiMZZp5+y1PR+fTu/W6CRVOZZRTXO1nJG7mBmX6O7YFzko
         v+uX1ceAz+zbl8NDhKn+oD6FAj5zCm77DmeXlYUpeDSddiwgIM+T+xGI/dwEIC0hcCV/
         oaqXuFseKww4MA04z//+evYhBAZpTTfGX8G35X090bYZ8c19MywNHUnYtHrSdhX9F7Tc
         aON5rw6V2nt13DvxHE+cfHPIMF5oE7y3yNP9W3DF+WemqUT8Oa5PvYH/xIB3+L5eux8+
         mR+IR+NeCUTQx+PN9nHGU+Zc2Q/PP/snK3oVndZ36vaH9YTs0VtR8NjRArqMMoyuQMfS
         fsEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSHbKAFRDvBD5OejzUMgbZ3YTqeSgR3k69oh7LL4R4hKbpEYttQKEgseIE3rzOatRB+ea/kg==@lfdr.de
X-Gm-Message-State: AOJu0YwxuMYBjBFa25hRJa18muX4gDJnb+dow4dz/UIDebOkn2l/EEMC
	mXGVDjbdTRi8zhVnLhynLwtGxLfFnXJw7wV8Y7UMD1LYHjbfcgh3PbL8
X-Google-Smtp-Source: AGHT+IESqEwu+CkRfsvfylPF43dacw5ns7d8wuJyQq1tjfofq/qxnEM2E53zZe3bLqY+DesHdhkuDA==
X-Received: by 2002:a05:620a:40c9:b0:7d3:90b3:28f with SMTP id af79cd13be357-7e87df68797mr697505485a.5.1755342026504;
        Sat, 16 Aug 2025 04:00:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwLKzf1TOXBNmlHXyFhq2NmjY/EcUzxfaTjcqY/p0Nuw==
Received: by 2002:a05:6214:d6a:b0:6fa:bb85:f1b9 with SMTP id
 6a1803df08f44-70ab7a18ff7ls39425426d6.2.-pod-prod-03-us; Sat, 16 Aug 2025
 04:00:25 -0700 (PDT)
X-Received: by 2002:a05:6214:2a83:b0:709:ded9:5b1a with SMTP id 6a1803df08f44-70ba7c537cfmr64844636d6.46.1755342025517;
        Sat, 16 Aug 2025 04:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755342025; cv=none;
        d=google.com; s=arc-20240605;
        b=jCmuBoGXAeHh25Fc1mQNAkheTPnxkg5lkgCBnvijpHx39IRai5qOUb1y9JhhinU2/g
         X7cuD9vJTpczqQhy2V/tPoyLs5GrLKmTnq5yBc70FuIRnAej6ejLOeEh9vZOzpuVRUwZ
         btBHcSDRjk5s0WVw816sDh83IEzQqEZQhcLvbWrVVNolxtbjf9ZLAx2Gedruj2klV9tj
         giko/egKxZwLRBfZ8CY0IX8R42cjpPS/Ef1jZ0Gm7dyf11vZgA1sQWYdgkUyIc3HqUnN
         Flykl9vBHMkz6fNrLsc9N9N5VB1PirehdzTPuVLGWPhv8VqNx0aQnGyhcwSE3I9KIslQ
         2QsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=79D07NhcoACxwO39xy+5B94I7RjXRqTsb/zfTzN/WF0=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=ac79J+q7OxUJ8ahxsTqBLN+EIDemy64qz5y3GwT3J9tqiKZMWqzudPF9GcjBtlhfr+
         WAgl9FbXxqpYTCRi9AR5xY+2YTOvMakvHCtEpacE51ijH/HWHeTfFAaaUbbbsKxsLG41
         gGIiJTD5oCrTYFgqK3hLg2FCeuxOQkaMUOWtkYUPUrL5wbpNYXCW4ppeoSXq0sNzqcks
         8JvAUGYYdbu18dZnPQfwiNmlgs7Cqu1XdZDe9vW5tVt3MAV2pxTdAIbUgN+VNpjrUDNd
         jwwm9SphnFqwXXbz/RdFmzAmClzfUNanzV+o0YxOWj6NtKFXnaBQQEF7THKkvJbd4soM
         Fe6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-70ba91e59e2si1285736d6.5.2025.08.16.04.00.25
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Aug 2025 04:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5C7BD1F60;
	Sat, 16 Aug 2025 04:00:16 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9F8873F5A1;
	Sat, 16 Aug 2025 04:00:20 -0700 (PDT)
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
Subject: [PATCH v3 0/2] introduce kasan.write_only option in hw-tags
Date: Sat, 16 Aug 2025 12:00:16 +0100
Message-Id: <20250816110018.4055617-1-yeoreum.yun@arm.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250816110018.4055617-1-yeoreum.yun%40arm.com.
