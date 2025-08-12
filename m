Return-Path: <kasan-dev+bncBCMMDDFSWYCBBT4E5XCAMGQE5F3GCQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B3667B22887
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:32:00 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4af117ffc70sf139977821cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:32:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005519; cv=pass;
        d=google.com; s=arc-20240605;
        b=WPhRRsmfxwiEtjdqQ6CqyNAN8+ENbRJPF1YFGmSzzEDx5OSUPAsoD8aYeAoUEXu8Tt
         zLFECpv9P0LXXAaEW83gJE1T7HoDYlQ5yJxTa1FIzP6rYXIYpgen2p8jmJexEyT3MM9D
         A8jrioY9EGnGvXQ/2vYRc8/oPk0sAUA2EQIxZ3BnLivSnF6Lax6iZiDkZAOSgIg6OthX
         PQTq1kUa8W4bPpOuZ/tOmqPim7GT1WhY9kJV9b6hYiHUpoC2IXdBmaVVwJiY6qxM3+Ql
         lG3VOc5/zD/VcBWTIrYhjVdgerMCyzsC7In7GYVJ/1lUvHLm3HXjZreUNN1/3vI292KX
         pRLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9G3xuqS3BLom/BKWPIV00f5VJdM/aegG/g1JUiDwUIQ=;
        fh=IbDJStHPD/mCSrYIB9tmNZw+X1mECiWUibbMGVk64UE=;
        b=gvPnxf6lTH8TJsxiDvdjgf3JfltiML1HVYrhPYaBQa7Aq7kuYbqyci1Ga3tCan+SFl
         tM7+e4HHi3JZGq1jM3gDjz2s2k92I4/pOtceYzYC8Ork6Z16z7XO8XMYOrulCd5pXKAb
         eSTKlRjAnDvuXQJ4/SUmRY7VEF2ZjNeAeiASErNJrhB6Pmx1gxZNVui6IvPvOPuRbl5U
         f4o1nY/o3Zsx203iYIBWokUw8FdCDl/YT9ruqD8PEy7+easYQYbbG7DuyNqyEaXpwWyj
         f+MkertMiCfGOPrBFSDtUuY+SIV61M4nDhS5b8k64ZUgv6ABpjEI6C3wxwuaSTqtlHhy
         ehuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BvCs7dxe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005519; x=1755610319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9G3xuqS3BLom/BKWPIV00f5VJdM/aegG/g1JUiDwUIQ=;
        b=hqu28T6udJNtaTAiOqF8FOLntQN65xzBaEb2Py5mo3qfWIvvBVkaQ2GzOWQrpgfZZQ
         901R7N2/Fw4kocoqYCUZjww381rsdpu8fzkAHg0TuPm7qSGa6gJgSTsXgc9bGxwcKjCv
         xTbxVIKjzayersltq1EW0ZzUs7Ozh+GDFhmKgzvpT6DJoAkUz4o9JoSUiUIrHFyloByP
         fSZyPhD5yADrDBObO4q/NWhYSeBoFgQqaK2c/xw8M/ksnFcei0gPJejN1WNzT/K/kWHq
         +vHMrXhcZW4p8ZmLjQIyZyPeO3NmfGrTzn/PWV+rPzty0xHMs/wxtYwksdiFW+Cpywzj
         vtfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005519; x=1755610319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9G3xuqS3BLom/BKWPIV00f5VJdM/aegG/g1JUiDwUIQ=;
        b=qR0S+96rfVZn3bxZ9m1TPHjqVLT72OVFq5QBD2HVFmEZferdxl9Xr0aDjUD5mmpLf+
         jMdsDoqJIlZmNKnEyecy1Pmz8I0mOpRMAFTcTKFZJ8Jd2ZWIvX/wcVkDHhluBvjD1ZDK
         1gzvwKe7xgeMvRPTYE+duC8jahyvzNRCRxmwDOQ4hEwSdsqugFsOKRPF2A1SxqeHLR18
         q7+lEdzDOa9+KhgbCh/tFO2sHDSYK90AbSfbYhXLyLQI2IGiKcsIuss8Ad1nzKNRSDa3
         4z+d1nP2PEo5aTyiLg/9KUhLD1XtkBFomoWohskJw5gT7zDAQmefTVSGGFvUxozHxxoO
         qsoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0iPGrx+rWZb4wR0yefSm7IF419ExZlOQa2gqszua0t1DzYrsD95ilxoN5i04GZIV6ZqhAPw==@lfdr.de
X-Gm-Message-State: AOJu0Yw2Eodyq2bTkVEnbLVgcuOZDKb3wdSHYS9NXmfj1SB1UaerPdt2
	lh7kx+KyEozBm06GJmqfArq6jqT84AFDdrvkOKM3NnOYuG6NwXM2G+99
X-Google-Smtp-Source: AGHT+IHIUfPHGmRST0b1smGFCryIk7gnzpcCK391uSKYxLgaibaAOX7hQuXEd5+kUH3phqx7C6kKIQ==
X-Received: by 2002:a05:622a:255:b0:4af:230a:dadb with SMTP id d75a77b69052e-4b0ecba7ab7mr40714891cf.5.1755005519272;
        Tue, 12 Aug 2025 06:31:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhZ9Ruxy2hlNbU8cXi97Y7JNzfH3TCiNvLng6u7Q5JyQ==
Received: by 2002:ac8:5891:0:b0:4b0:889b:5698 with SMTP id d75a77b69052e-4b0a045815bls87503121cf.0.-pod-prod-03-us;
 Tue, 12 Aug 2025 06:31:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1MSGjWzabT56DUtrJ3UCbdDMPWjMo/Q3H8C7PZZDlA9zQeu+NUfEZ/ovTaBbk7cwx3vYzzB+qI1o=@googlegroups.com
X-Received: by 2002:a05:620a:612a:b0:7e3:35e3:3412 with SMTP id af79cd13be357-7e858897035mr319028085a.34.1755005518173;
        Tue, 12 Aug 2025 06:31:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005518; cv=none;
        d=google.com; s=arc-20240605;
        b=WUZSsdE1XYosrOxnbXpeABFfjDs4U5srjPeJ9tacDI5guXl6db0rrFBAlDGlj4NgXr
         /oCXTeDRy+/7a3wWA4aZNMVAemJm4jFbtjkXvU6l/2MaFYaDt1CdktD9pv7c7234V5Hj
         3Kce8XEENKt+Bpa34OqDsEDsaAErMP3ph/YV6EEB0n1dPbk3BFG4DW2Htz8CtfonxsHi
         Hlyp1xEh4UUUGt8PZ38UzLHe5zeryjl+lJhEsY7azZukvxTHjiKdnrO9C3ehyjSdJ17y
         yWaswhkG3izxIlvt80MtfLMa5+Vj6dqURBbSduAgXqaUTaobTu2omlSy3sy7j0fBhT+G
         l41Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e9dZ7HYFm04sYh+3FqLYILOU5ulghIY66izoMMIko1I=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=EWp4Zxhu7DnI0LC3X9p0QzHzvzIGc0oMgogFWxE8RfMNc03pIZcpwEyNkxxVxeAoch
         40emyzDlwrUndTkVyOCbax6Bkregs1yTbOl2+ht1Tvi8IT7m1cOKHKGGzq7vZL/Z5kad
         xWp1UGVGU2X0XdZ0mLKtMENQy5I+XQ0dRMy3YA5Rx1azlmKbPse793pNcDNimTVuRNOm
         PIkXDpZmo9xKDVf+UWrZUdIgbHMK1omyI6n8ZELMncC1e6so8sD1XFJBg2wTYttd3O7u
         V8go3Rt602aGNp0LIjhLFkAzzC3Ao601ywA4W6G5Jvh7CEg3vjMKJzlNAKGjEyf3qGt0
         +V8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BvCs7dxe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e83d42f1ccsi2656485a.7.2025.08.12.06.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:31:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: nkjy8mpNRfaALXrTMGRR9Q==
X-CSE-MsgGUID: OdLmRHYKQCaJ0u2qAKWatg==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60904200"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60904200"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:31:57 -0700
X-CSE-ConnectionGUID: uGwnKofIQG2MO3tLlIilYQ==
X-CSE-MsgGUID: HOOQUTfdSZuSH6R+h2pTMg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165832158"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:31:31 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 18/18] x86: Make software tag-based kasan available
Date: Tue, 12 Aug 2025 15:23:54 +0200
Message-ID: <414e258b828b4710966c3864aebc7a9bc598eb4f.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BvCs7dxe;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add x86 specific kasan_mem_to_shadow().
- Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
  KASAN_SHADOW_START/END.
- Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
- Disable inline and stack support when software tags are enabled on
  x86.

Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
 arch/x86/Kconfig                     | 4 +++-
 arch/x86/boot/compressed/misc.h      | 1 +
 arch/x86/include/asm/kasan.h         | 1 +
 arch/x86/kernel/setup.c              | 2 ++
 lib/Kconfig.kasan                    | 3 ++-
 scripts/gdb/linux/kasan.py           | 4 ++--
 7 files changed, 15 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index a6cf05d51bd8..ccbdbb4cda36 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index b8df57ac0f28..f44fec1190b6 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -69,6 +69,7 @@ config X86
 	select ARCH_CLOCKSOURCE_INIT
 	select ARCH_CONFIGURES_CPU_MITIGATIONS
 	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
+	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
 	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIGRATION
 	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
 	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
@@ -199,6 +200,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -403,7 +405,7 @@ config AUDIT_ARCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	default 0xeffffc0000000000 if KASAN_SW_TAGS
 	default 0xdffffc0000000000
 
 config HAVE_INTEL_TXT
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index db1048621ea2..ded92b439ada 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index f3e34a9754d2..385f4e9daab3 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -7,6 +7,7 @@
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_SCALE_SHIFT 4
 
 /*
  * LLVM ABI for reporting tag mismatches in inline KASAN mode.
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index 1b2edd07a3e1..5b819f84f6db 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1207,6 +1207,8 @@ void __init setup_arch(char **cmdline_p)
 
 	kasan_init();
 
+	kasan_init_sw_tags();
+
 	/*
 	 * Sync back kernel address range.
 	 *
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..9ddbc6aeb5d5 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -100,7 +100,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
index fca39968d308..4b86202b155f 100644
--- a/scripts/gdb/linux/kasan.py
+++ b/scripts/gdb/linux/kasan.py
@@ -7,7 +7,7 @@
 #
 
 import gdb
-from linux import constants, mm
+from linux import constants, utils, mm
 from ctypes import c_int64 as s64
 
 def help():
@@ -40,7 +40,7 @@ class KasanMemToShadow(gdb.Command):
         else:
             help()
     def kasan_mem_to_shadow(self, addr):
-        if constants.CONFIG_KASAN_SW_TAGS:
+        if constants.CONFIG_KASAN_SW_TAGS and not utils.is_target_arch('x86'):
             addr = s64(addr)
         return (addr >> self.p_ops.KASAN_SHADOW_SCALE_SHIFT) + self.p_ops.KASAN_SHADOW_OFFSET
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/414e258b828b4710966c3864aebc7a9bc598eb4f.1755004923.git.maciej.wieczor-retman%40intel.com.
