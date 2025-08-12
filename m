Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGMC5XCAMGQEBM67Q3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E1C5EB22855
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:26:50 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88177a20e0fsf1112263539f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:26:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005209; cv=pass;
        d=google.com; s=arc-20240605;
        b=cxnxY3VSwEpjtThWLN0Nds4oIBE7IWIHXMxhKTr7U3F2RLr+JS00wQKfBWl5N2KYqY
         /T+s+KlhAzCK+E6R9bGJ8gEZHbTV5cMjeO/DGiJBoVlkpdrtki7CkdmYEb8NqHNNsQaF
         NboOtzqljKJcDP76yNn6nBfM3CAmi2FQ5eK3fExdgBGvGNVjdT/NC4OWbLMTVEUVQ0Ha
         CNgdt9SoX7NW/q3BIpMTPnfE2++bY/HJXjjPMg2HNNY2ihBTdNSJ6nVsoLrHq0pZXiP9
         tOsi7n9PJoQ38gv7+yTlVYmy7TrTnOmQJhJr85tH0L77j3AsR2MkkkkPd0uMfK6Gb3uH
         MkTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=moP6GPpoWLCGBmcP84PIRH+9zEcCUlzoBo84GXBZp8k=;
        fh=S2eDWYpDOloSSNH0c9UL747b9T5yrAgtdneuLD0uloc=;
        b=eyG8xJC0RB0kCCY1mP9zzM5aJUCEdlr1Qb3toVvE13n5I3/8jNBm2dmm0LbX7YW7A+
         izovdv7dFvVePtfvJD7SnyWTfx7fJoMebokopHl/2Mm/1BGIaHQ7D4U4JsLG5+hx1Lub
         tvRxD+TDLWgbqihN3IvFDR3jYuQH7bV2Ia/oqIkGK0grTTLgwktswmW/NLyub1cDuWaD
         TKqfvkndlq/bLMIycIpmN2WFoTD+0hZdyNsnYyXCXCLCZ0BYzCr3dZqtWT0iDSQgaWeh
         jJpi1lF6T+HE/sKPMxv9x+FLu+dvDanXzdjjYoEz3M+oM/kidJnhAJSERHLDrFAo03o/
         JpDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=oAyNIymx;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005209; x=1755610009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=moP6GPpoWLCGBmcP84PIRH+9zEcCUlzoBo84GXBZp8k=;
        b=fyUwN4jQblwC2fiO2cn0J32yfCykDoRd8PptBc/zbpBG/2G1tVJF1oi0yTqvsp8Er1
         jms6LapdKM7/2UdWtB5G4xMqqq4OolFuT0yE34UxTPzF1RXEU0rOMea7zdC2MGNLvW2D
         TCgPNOm8dhcCEAA01JPRXNhwxsip7EHZvL53HOv1Yw32fehAo0ecj0ThGPKMc4DBTHg7
         3aE8ZAhAFJUI7hNCjiQQhJipOKa8qTE0mIXR8HNReK8k3saMKV9L7AoQmZ60tFQxJYBi
         ypiws6pVG1idYeVuIUvhTjne8Jde+MAGgJksWD3EyvBmwQVghXeUUf3AoDwcy337i3/6
         F2aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005209; x=1755610009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=moP6GPpoWLCGBmcP84PIRH+9zEcCUlzoBo84GXBZp8k=;
        b=Npn+38UmF5n3eRzURZ/C0r/QprMT3udaKs70Hi7eCM+i0TZJfp0P9KX595pbAN8gqo
         MsWvhzi/8wlGsTGohShubOBW/M7u/czz/cC8zjnEaV/5Jp/9q8+xAgTPPYebsXHIbNy1
         ZsZSxymp6bgKmnyH5QxajDGt2vHZoJw1M9Ngawkmw0z58A8U3o30/710tkaHEyiLCjmS
         EcaI8B7KdtBcmuQIzKoJCCvmS/LQ5kcMXpZhBuV7FXblglZIjiBrnXFimTgEUI//9K01
         PR3pd74P4m2Fuh9Ow6KeurOA0cAJuvpFpEqKzN4eHgzouu+THrqkvCyKOOR6J0VCxuDn
         X8sQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUd6Hh7o9UM3fMZEnNsRw6VfCgEcSJWZgbNyaPoNRZ/EXVgJ/Chf8usaIUC63qhAc1kZjlGHw==@lfdr.de
X-Gm-Message-State: AOJu0YxkC4KnZB7sloFsCoVVQUxujlgX/c1Wa1PNVJ+dZtB0IV2EeRaK
	A7Bx2YffWDzOymuzduEfXkDo+D55cZKf03jgIzcwlyRqV4Qsfld5tADl
X-Google-Smtp-Source: AGHT+IGJ/0kefOycUdAaQDHhbpNhgtFbT5/sYvObJIvJSxDoh/+W6yrWB8KSRKL5wKaG5IElenVB0Q==
X-Received: by 2002:a92:cda7:0:b0:3e5:6313:4562 with SMTP id e9e14a558f8ab-3e563134752mr13712255ab.14.1755005209407;
        Tue, 12 Aug 2025 06:26:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcdspHD+OYWbCMFCZfIFeJl0YTPJzTh/VZdKtjYD3OxCQ==
Received: by 2002:a05:6e02:3f07:b0:3dd:bfcd:edd6 with SMTP id
 e9e14a558f8ab-3e55a8154a2ls11346605ab.1.-pod-prod-08-us; Tue, 12 Aug 2025
 06:26:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVkU+qPxK9FiZgvLnPDLkkSdmN4qTOh9VCXCpTsU8FvC7FNmVioxJjQ5dRWr4oxM6e1MMyQirNETY=@googlegroups.com
X-Received: by 2002:a05:6602:1492:b0:881:7837:6058 with SMTP id ca18e2360f4ac-883f10dcd58mr2967973639f.0.1755005208225;
        Tue, 12 Aug 2025 06:26:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005208; cv=none;
        d=google.com; s=arc-20240605;
        b=UCIX4MPNFk9FzAl4X5XNeu4xed1QBd2C5y9tcSAUaZzr36R8E+YQ9aVjzK2rGYt56R
         6MhLLtp+xG8KHrn/pdDOqU93JjUpdZe+z4f6IOdYLAaEmyT1P3DVplfg2KDmLr0VZumE
         Z+LWOAT6yxlZubuZi/vlIHIxXTN/KBbpRGAArdMiki/8602W0HJBeyTJHcxtCF8BceKx
         bwoNjBol3U9sYF9TWhvH9qJf+r0dJ4PJ2s5+B3MkY6/uWnvpmmA9wwW1ldAoNpoewZJQ
         GjeZR9zwhMpIxvA+ns2kt3bEETx0107U/p7KIYPLiVnWzQg/3NRcb6lC7rkburAGahLN
         7zgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2lO1JVCFxL3U/ib6c/wvRKRlvNz5jZEUGFdS/ayOyBI=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=ihj3MslWhoAkS3HfpcO0zclGh6h2N2dp55UdcU7CZQJUdyPgNIaO5wgMn5TElWDWzf
         z52ShYj4vbsWwOpdSVAYgX+lovnQr4dBt/xpHwn2wHl+ltPlLpRy0ge2rLbYDFk0z4uT
         Wrt1Ua+zsOAeZwC6i7p7hQba+r8PRu4gukDsGz/3dx63mtMXKMSQ4dKwqPmqQK+U95uH
         zBrnY3+SnEoTbErzwpyBc82Czi9BgpTC+1/mXhMioJrCm16/gIBAe7MlCJSyQC8cTGIF
         t/UeR48osB1W8aG17i4XNWFlCy0NeeAmaKFF42G1kdccqZ6mIr4ekL8vb+YXLo583w3t
         n1Og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=oAyNIymx;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si49156639f.1.2025.08.12.06.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:26:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: unmExbRWS1yv1Y1v8Tbdlg==
X-CSE-MsgGUID: ngp3nR/4QfamjFiJ1uuAiA==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903102"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903102"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:24:59 -0700
X-CSE-ConnectionGUID: kayhpomIS0akEcqtG//q8Q==
X-CSE-MsgGUID: VWXG4HKqROyugDxAls9HoQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831255"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:24:35 -0700
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
Subject: [PATCH v4 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
Date: Tue, 12 Aug 2025 15:23:36 +0200
Message-ID: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=oAyNIymx;       spf=pass
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

Compilation time comparison (10 cores):
* 7:27 for clean kernel
* 8:21/7:44 for generic KASAN (inline/outline)
* 8:20/7:41 for tag-based KASAN (inline/outline)

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
The base branch for the series is the mainline kernel, tag 6.17-rc1.

======= Enabling LAM for testing
Since LASS is needed for LAM and it can't be compiled without it I
applied the LASS series [1] first, then applied my patches.

[1] https://lore.kernel.org/all/20250707080317.3791624-1-kirill.shutemov@linux.intel.com/

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

Maciej Wieczor-Retman (16):
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
  kasan: arm64: x86: Handle int3 for inline KASAN reports
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
 arch/arm64/include/asm/kasan-tags.h       |  9 +++
 arch/arm64/include/asm/kasan.h            |  6 +-
 arch/arm64/include/asm/memory.h           | 14 ++++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/kernel/traps.c                 | 17 +-----
 arch/arm64/mm/kasan_init.c                |  7 ++-
 arch/x86/Kconfig                          |  4 +-
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 71 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               | 24 +++++++-
 arch/x86/include/asm/page_64.h            |  2 +-
 arch/x86/kernel/alternative.c             |  4 +-
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/kernel/setup.c                   |  2 +
 arch/x86/kernel/traps.c                   |  4 ++
 arch/x86/mm/Makefile                      |  2 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 19 +++++-
 arch/x86/mm/kasan_inline.c                | 26 +++++++++
 arch/x86/mm/pat/set_memory.c              |  1 +
 arch/x86/mm/physaddr.c                    |  1 +
 include/linux/kasan-tags.h                | 21 +++++--
 include/linux/kasan.h                     | 51 +++++++++++++++-
 include/linux/mm.h                        |  6 +-
 include/linux/mmzone.h                    |  1 -
 include/linux/page-flags-layout.h         |  9 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  4 +-
 mm/kasan/hw_tags.c                        | 11 ++++
 mm/kasan/report.c                         | 45 ++++++++++++--
 mm/kasan/shadow.c                         | 18 ++++++
 mm/vmalloc.c                              |  8 +--
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 42 files changed, 381 insertions(+), 82 deletions(-)
 mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h
 create mode 100644 arch/x86/mm/kasan_inline.c

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1755004923.git.maciej.wieczor-retman%40intel.com.
