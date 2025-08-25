Return-Path: <kasan-dev+bncBCMMDDFSWYCBBPMNWPCQMGQEFXLCHXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 99669B34BAE
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:25:35 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70dcd8b49easf1938176d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153534; cv=pass;
        d=google.com; s=arc-20240605;
        b=O0zhGwhupV31fP2cMKprytn/7qyFbKS6hOYpzhGQ1xeGNrJaeWiYVAmGgiKq7+wL+A
         Tr9oQUhuPHjggq+0ez+H8UA5vhBmcX1M+aE0BqeSn4oXlEpmez2LjJNNoF7mQ/5PyQP1
         +v6ZD0DxnizK5AOsy5MB65LUaD8opcwItMYmVBGARaPavSOO7pSCmQnhkCU2vmBpbQrq
         1rFgMxA68WvWuYpnbSGcX2V+YPYIC30cmhQDrnxMYjrj2HuofxvksnLEppmtfwFKjh3y
         F52vHpfLqWV2ININm5DAfz8uhLMJwfOr/L3xz2c6m4Pi7+xIWBpAFPnimGGgmRKpYd/1
         WpPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qEQ5uDEKrqsbxHUmIDwnzZIHxdbV6jykUGB2ZutIxP4=;
        fh=j68vb2rqMlKGVzn3USnJa6g2IwJbhPZ8aNYpbMOdXK4=;
        b=FzaRIpsGepc4f8Tc1nxMsj1FeSHC82VZ3Os62wV2X/SlCKBEXFRypa1pXPl/+Lka+m
         wVmtfbrfK5j6K/vKWjxIHSIqcKvCQ7YEAHPkH9xoOKNyb1CIR9Ofl6FpYh2hkm9nuqnL
         rwikHBpQToGub2UjLgcBHvJ8buQmi7aUyhTUV28qhIx+WlA/5i0yxFBwmUcNaUHCxn2a
         40Rw6o8vayko5FtrIDn8zsbcnfOE+UjiiYX76qNXvclMBlBhICO7ZDNQJrONorKORtoL
         JJrmeDEwkdlbjjJCy2D3L7zMZdMFCxLy5lwwijHNk7Ra7dcR9JRIgsgNbl4MODd3LAUB
         8FWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DOwUWWK+;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153534; x=1756758334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qEQ5uDEKrqsbxHUmIDwnzZIHxdbV6jykUGB2ZutIxP4=;
        b=dobxaNHCp8Jdzv6wtXsQeu4hUnNeZTH47yeuZEheLkFxPEl/jzvnjr13qVecOKsoSi
         25+wFp7B/eoY7Nosb00X9EsneMoJK8+P2QYoR45cWwqbJQk5KaIucW+mzjydDSpkaaXk
         KF/XOvm3r64WvpFHPOCmQw7GOpWjuDdvbTLFgDyZ9c21AsBDj6F+4TkRLAO2SeBcL3PQ
         SlPI+XtXHjkFU/HLt2lwychwRyPT9FxfuHKNCIl7NK0y9BQWGHKZei6xf7EnevrE648E
         b1x1HZCqm/79WnwP+QtFBZSFEJJ6mrydM1I/XRdKR0xPtYSn+R6EtGSSv6oxvTD+Id4G
         wkrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153534; x=1756758334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qEQ5uDEKrqsbxHUmIDwnzZIHxdbV6jykUGB2ZutIxP4=;
        b=W/Jpm9zAQbCcqPUHWaRxhoFILujpLDbJf/2hqxArtqRQfkIird8PkkW54DgbTL2bRL
         cBpXCXbVwatEl6DRJK0OnWHN2nFlqbPen/p2yZYyhOYupUYFJpwJrzVRfdmEjfxmYH93
         8MSH+/NaEAUeAXmneCa+vNz9qpzQA5p3Sl11H1C4QsGGVf71zC+FGtxEgOEa4anb/I4D
         ycX0P1V4Cdf7WSgB4a0EkOej0X49MSheWKmY3MrGAWugxsVxGyBMicCZzS2LKS5OzoKM
         CyXW1DTdEwYcdVaS0/iJB437tcUtR542AgWyB+Uf5F+YO13krthiVHjYQsy/Yx58c33s
         3zug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIgt7e/9dA4YVoGkmEhNPmpLn/K+LBqEhquDSthm3LLqDrnKB880TzaqN1YvcXqeEavrJsKg==@lfdr.de
X-Gm-Message-State: AOJu0YyDRQs0SX0aPua0hARql5lVl5RkeZyw2dEZlSOpq2fmIPn3UTQV
	OvEXNzOJVsFkNjyhJLGHesklbEQ3oDChHep9PumI2hPHuRk0LE1gd7f5
X-Google-Smtp-Source: AGHT+IFkXzEigppCgK6orpLpp3N58DHzqluSvWebcrnn3+bepYumuBtymrO4y9z2zWMWSUshdIXYIQ==
X-Received: by 2002:a05:6214:27c2:b0:70d:6df4:1b21 with SMTP id 6a1803df08f44-70d972431camr153591396d6.62.1756153534029;
        Mon, 25 Aug 2025 13:25:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWy66ChPDlA/5l+pODsYsb2lMOlyXSiQu3jjDfqRfIcw==
Received: by 2002:a05:6214:20c6:b0:70d:bc98:89ea with SMTP id
 6a1803df08f44-70dbc988ca8ls26012246d6.2.-pod-prod-09-us; Mon, 25 Aug 2025
 13:25:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyAOjR5jvtTbDsloNqySdeaYW44TR2gSgpNGK4zvg5w0Jdwxfw3CyY05BaMhELkGuDIzXYYdWZzFk=@googlegroups.com
X-Received: by 2002:a05:6122:8c9:b0:530:7ab8:49ab with SMTP id 71dfb90a1353d-53c8a0d1923mr3968484e0c.0.1756153533112;
        Mon, 25 Aug 2025 13:25:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153533; cv=none;
        d=google.com; s=arc-20240605;
        b=NbAkqlCy6b+4Jr1waZ4vkloEnbte2TkzotdJe7Xjdtv6DSlrj90/lMAsj6VbHuohN0
         Oo8wbi0DZ6dbTKdVkt1TrqcfCdVJHZan4vKgpXfKL1BYcTVm+ggWqx9uNWnXNnn8igDA
         o0Xp0bjUD/lnnPU/p2Kbbb+rSiMJCyyS36gQK7TxLh4qJZQVXBNwOQE/tJri7qYFSULD
         aWsa2iM0T9+z5vn/URcCeFw2bVipvwSox5R3n1WEyeU5yVvfa++LeYu6LEB+oRKxvF0V
         /ZZqlF8il4NsPbwkEy2wmkPnbQrESa24F52UW0EPrC7EHy+WeRx56Ep53SYAdl/5onx2
         xoRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GNTQYom+KW7VhFoWZp6N8RuSaQiNEKsPGcqxWRxcTiY=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=Lez2IwvBwD5h77UmxW8CVCKEK6Py4KQC1RbiQhOakUSfa3+BVLeFyQkqfTb7rLfJ7S
         FrX/oEVS7ljkMrHPSEl3BYGVWmY0EQ7crX/UpktBYSnVqyTepo8ggMT6HuFfGWOSVCha
         x2diMnxRZpdNsZ6qpgcsZWpcYXbLYiCvbVUfJoqsJ71pVly6b3evBzhULohdF74cOe1f
         yr5fDCXF1LU/yGvO0TMUieiOVDZBZQA0oJlANYMKb1yL4uiMvX1GkfHa6Y1nZtAiOyqM
         fKUIGEvJA6GDvLsZX8cuIL+R63IsveX/Zdb3HVU7mzZkD+bDRQjlJKhCF0O6Teiw2tE8
         OwEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DOwUWWK+;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-542559b78a1si90481e0c.2.2025.08.25.13.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: IIoh3z9VS4K1HdlfiTg9Mw==
X-CSE-MsgGUID: 2kyQbFbHTR+2S/TiGTBBUA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970200"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970200"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:25:30 -0700
X-CSE-ConnectionGUID: v0l8wPnDRseIF+WuDhd5XQ==
X-CSE-MsgGUID: Pk42Kdn4QW6rrQ6H8KxS7A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169779848"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:25:12 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 00/19] kasan: x86: arm64: KASAN tag-based mode for x86
Date: Mon, 25 Aug 2025 22:24:25 +0200
Message-ID: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DOwUWWK+;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

======= Introduction
The patchset aims to add a KASAN tag-based mode for the x86 architecture
with the help of the new CPU feature called Linear Address Masking
(LAM). Main improvement introduced by the series is 2x lower memory
usage compared to KASAN's generic mode, the only currently available
mode on x86. The tag based mode may also find errors that the generic
mode couldn't because of differences in how these modes operate.

======= How does KASAN' tag-based mode work?
When enabled, memory accesses and allocations are augmented by the
compiler during kernel compilation. Instrumentation functions are added
to each memory allocation and each pointer dereference.

The allocation related functions generate a random tag and save it in
two places: in shadow memory that maps to the allocated memory, and in
the top bits of the pointer that points to the allocated memory. Storing
the tag in the top of the pointer is possible because of Top-Byte Ignore
(TBI) on arm64 architecture and LAM on x86.

The access related functions are performing a comparison between the tag
stored in the pointer and the one stored in shadow memory. If the tags
don't match an out of bounds error must have occurred and so an error
report is generated.

The general idea for the tag-based mode is very well explained in the
series with the original implementation [1].

[1] https://lore.kernel.org/all/cover.1544099024.git.andreyknvl@google.com/

======= Differences summary compared to the arm64 tag-based mode
- Tag width:
	- Tag width influences the chance of a tag mismatch due to two
	  tags from different allocations having the same value. The
	  bigger the possible range of tag values the lower the chance
	  of that happening.
	- Shortening the tag width from 8 bits to 4, while it can help
	  with memory usage, it also increases the chance of not
	  reporting an error. 4 bit tags have a ~7% chance of a tag
	  mismatch.

- Address masking mechanism
	- TBI in arm64 allows for storing metadata in the top 8 bits of
	  the virtual address.
	- LAM in x86 allows storing tags in bits [62:57] of the pointer.
	  To maximize memory savings the tag width is reduced to bits
	  [60:57].

- Inline mode mismatch reporting
	- Arm64 inserts a BRK instruction to pass metadata about a tag
	  mismatch to the KASAN report.
	- On x86 the INT3 instruction is used for the same purpose.

======= Testing
Checked all the kunits for both software tags and generic KASAN after
making changes.

In generic mode the results were:

kasan: pass:59 fail:0 skip:13 total:72
Totals: pass:59 fail:0 skip:13 total:72
ok 1 kasan

and for software tags:

kasan: pass:63 fail:0 skip:9 total:72
Totals: pass:63 fail:0 skip:9 total:72
ok 1 kasan

======= Benchmarks [1]
All tests were ran on a Sierra Forest server platform. The only
differences between the tests were kernel options:
	- CONFIG_KASAN
	- CONFIG_KASAN_GENERIC
	- CONFIG_KASAN_SW_TAGS
	- CONFIG_KASAN_INLINE [1]
	- CONFIG_KASAN_OUTLINE

Boot time (until login prompt):
* 02:55 for clean kernel
* 05:42 / 06:32 for generic KASAN (inline/outline)
* 05:58 for tag-based KASAN (outline) [2]

Total memory usage (512GB present on the system - MemAvailable just
after boot):
* 12.56 GB for clean kernel
* 81.74 GB for generic KASAN
* 44.39 GB for tag-based KASAN

Kernel size:
* 14 MB for clean kernel
* 24.7 MB / 19.5 MB for generic KASAN (inline/outline)
* 27.1 MB / 18.1 MB for tag-based KASAN (inline/outline)

Work under load time comparison (compiling the mainline kernel) (200 cores):
*  62s for clean kernel
* 171s / 125s for generic KASAN (outline/inline)
* 145s for tag-based KASAN (outline) [2]

[1] Currently inline mode doesn't work on x86 due to things missing in
the compiler. I have written a patch for clang that seems to fix the
inline mode and I was able to boot and check that all patches regarding
the inline mode work as expected. My hope is to post the patch to LLVM
once this series is completed, and then make inline mode available in
the kernel config.

[2] While I was able to boot the inline tag-based kernel with my
compiler changes in a simulated environment, due to toolchain
difficulties I couldn't get it to boot on the machine I had access to.
Also boot time results from the simulation seem too good to be true, and
they're much too worse for the generic case to be believable. Therefore
I'm posting only results from the physical server platform.

======= Compilation
Clang was used to compile the series (make LLVM=1) since gcc doesn't
seem to have support for KASAN tag-based compiler instrumentation on
x86.

======= Dependencies
The base branch for the series is the mainline kernel, tag 6.17-rc3.

======= Enabling LAM for testing
Since LASS is needed for LAM and it can't be compiled without it I
applied the LASS series [1] first, then applied my patches.

[1] https://lore.kernel.org/all/20250707080317.3791624-1-kirill.shutemov@linux.intel.com/

Changes v5:
- Fix a bunch of arm64 compilation errors I didn't catch earlier.
  Thank You Ada for testing the series!
- Simplify the usage of the tag handling x86 functions (virt_to_page,
  phys_addr etc.).
- Remove within() and within_range() from the EXECMEM_ROX patch.
- Count time it takes to compile a kernel when running kernels with generic
  KASAN, tag based KASAN and a clean kernel. Put data in the cover letter
  benchmark section.

Changes v4:
- Revert x86 kasan_mem_to_shadow() scheme to the same on used in generic
  KASAN. Keep the arithmetic shift idea for the KASAN in general since
  it makes more sense for arm64 and in risc-v.
- Fix inline mode but leave it unavailable until a complementary
  compiler patch can be merged.
- Apply Dave Hansen's comments on series formatting, patch style and
  code simplifications.

Changes v3:
- Remove the runtime_const patch and setup a unified offset for both 5
  and 4 paging levels.
- Add a fix for inline mode on x86 tag-based KASAN. Add a handler for
  int3 that is generated on inline tag mismatches.
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion.
- Remove patches 2 and 3 since they related to risc-v and this series
  adds only x86 related things.
- Reorder __tag_*() functions so they're before arch_kasan_*(). Remove
  CONFIG_KASAN condition from __tag_set().

Changes v2:
- Split the series into one adding KASAN tag-based mode (this one) and
  another one that adds the dense mode to KASAN (will post later).
- Removed exporting kasan_poison() and used a wrapper instead in
  kasan_init_64.c
- Prepended series with 4 patches from the risc-v series and applied
  review comments to the first patch as the rest already are reviewed.

Maciej Wieczor-Retman (17):
  kasan: Fix inline mode for x86 tag-based mode
  x86: Add arch specific kasan functions
  kasan: arm64: x86: Make special tags arch specific
  x86: Reset tag for virtual to physical address conversions
  mm: x86: Untag addresses in EXECMEM_ROX related pointer arithmetic
  x86: Physical address comparisons in fill_p*d/pte
  x86: KASAN raw shadow memory PTE init
  x86: LAM compatible non-canonical definition
  x86: LAM initialization
  x86: Minimal SLAB alignment
  kasan: x86: Handle int3 for inline KASAN reports
  arm64: Unify software tag-based KASAN inline recovery path
  kasan: x86: Apply multishot to the inline report handler
  kasan: x86: Logical bit shift for kasan_mem_to_shadow
  mm: Unpoison pcpu chunks with base address tag
  mm: Unpoison vms[area] addresses with a common tag
  x86: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Support tag widths less than 8 bits

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      |  6 +-
 MAINTAINERS                               |  4 +-
 arch/arm64/Kconfig                        | 10 ++--
 arch/arm64/include/asm/kasan-tags.h       | 13 +++++
 arch/arm64/include/asm/kasan.h            |  2 -
 arch/arm64/include/asm/memory.h           | 14 ++++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/kernel/traps.c                 | 17 +-----
 arch/arm64/mm/kasan_init.c                |  7 ++-
 arch/x86/Kconfig                          |  4 +-
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 71 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               | 18 ++++++
 arch/x86/include/asm/page_64.h            |  1 +
 arch/x86/kernel/alternative.c             |  4 +-
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/kernel/setup.c                   |  2 +
 arch/x86/kernel/traps.c                   |  4 ++
 arch/x86/mm/Makefile                      |  2 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 19 +++++-
 arch/x86/mm/kasan_inline.c                | 26 +++++++++
 arch/x86/mm/physaddr.c                    |  2 +
 include/linux/kasan-tags.h                | 21 +++++--
 include/linux/kasan.h                     | 51 +++++++++++++++-
 include/linux/mm.h                        |  6 +-
 include/linux/mmzone.h                    |  1 -
 include/linux/page-flags-layout.h         |  9 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  2 +-
 mm/kasan/hw_tags.c                        | 11 ++++
 mm/kasan/report.c                         | 45 ++++++++++++--
 mm/kasan/shadow.c                         | 18 ++++++
 mm/vmalloc.c                              |  6 +-
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 41 files changed, 375 insertions(+), 77 deletions(-)
 mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h
 create mode 100644 arch/x86/mm/kasan_inline.c

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1756151769.git.maciej.wieczor-retman%40intel.com.
