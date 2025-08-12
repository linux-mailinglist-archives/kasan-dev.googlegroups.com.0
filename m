Return-Path: <kasan-dev+bncBCMMDDFSWYCBBDUE5XCAMGQE2YIVXXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id C7AD8B2287B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:31:09 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30c30f4937bsf2156010fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:31:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005455; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z1sh56/ewqt9biP2GXNJI5xObYXWfHymoGF7JI1t4z4J0MBmpCg30Ds6g8+0NBJHHv
         aSHWOmskJiIVeCTB34n4TnzN9NXS1QulGGJFkCEcxP9LEh7Bs/yc+J2HPKjkgo1VClWU
         NdtTXPgYDeP8X4R4psbK5iLKJlQViC2AOBcCmoxcgn5a3wGvQKeRh0/gVfwA0IHDKMpi
         Ay028d40tGlfpAuCodc3l75txVV5d6b3iDqPF93fDN1V/l82nRCylN+EC3duO/GOqH+n
         zvDTlgUuJ6Q+dytm5Z3jGr1TlvO6N85VkscaRaAMyv+k7Jgay/NpTw6gtmCMytohQ0dF
         6q4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5HxaGJgZj5/KhQ5cn6/7jffy83KHXWUiyym/SGfOMY0=;
        fh=i01Lq/VXnW9BzB+cFQFmYvmDUVEitJU9bkPg05YwV30=;
        b=QOENd2fcx8W/c7mh4SIBoaWwVcK+XvEjN5+4FwWD+n4agMnCH2JPXrtDgxYOevzXmP
         e3mtEWJciqFcVZW7n5EajZdvKBzZl3PylbJ2Lr2cOL4rmeRmb21hDkCLZGWdynR+TXic
         pBXO5KQ+wCXznc8kdFUIXkb2sCJPSw90+PZvdl52X7/YhsQgz214ApU1wU1+JevNLc6D
         DioI6Ka2ZM4tLw9iDxZ71JCaTwxy3+wFey4vCETxGjAsW9CN86jzHpZYLE3VbZO7j6AL
         /q+LqN82EHcStSxP61pGFLjQOHzHyvt1DGhOz4oDFwC2wgGm51XPsId2/8l6b9hNdlOo
         GBBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Bb5zXZft;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005455; x=1755610255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5HxaGJgZj5/KhQ5cn6/7jffy83KHXWUiyym/SGfOMY0=;
        b=eiUYJIGtLuuib9yI3solCEUXnujvbWlTPW9LNqRQ7RNpdQz5upslJue/3h90gLNaFk
         mlkzIO2i0HHXbxioQ83OoElCWGFfMlFk1ltBtzSelTiwED9QRS9HnQWmH8lqmV7K3kvK
         uvH6d87mP2/9ktcevbH/CW6k0+l3iPQl5plbqainhVTQSQOUJ5HWrqBv3B5D0/6RCrbj
         zilQsHGlFOZ4nRtox5f3P+huyBM1qBrLrMt23HZFdPm61O6Rt0ZvJZ3PGEzyH9mTNZND
         9kS5G6cSC7z1q1sS5LyOH+X4LmgACSlvOB+lqSqmATdEpMfjLHf0IG1ixLCPtn7/jB1p
         7rUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005455; x=1755610255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5HxaGJgZj5/KhQ5cn6/7jffy83KHXWUiyym/SGfOMY0=;
        b=i2Pl/81ctuGIPW2iuzbOZe5XCYqXQupOz3XEn27bNZZnR+SRrHw1xFRJTTl9lmEqp8
         uuutu2ov59SPsFJAOa7xxSchQsLIdW3v9fUMtVs9x+Lwe8yEJOsSOqpfkHlXaQoV00GZ
         4OjR/nNC0/H4uP+li7xZ0sk683/5IiCI7w8usSOfsM7FLxc+90seDW+EkkQa/nxr+nYS
         2jyQqPFXlZwn+Q9wZmJ7r5BlE0mY+CAmotTA3zwKAUK+mFvNb0cx+XJ4Bm/qLA/TIuVN
         8bf82QYHOBWh18b6Y2yzGtAiXZt2CzQU02NJLA/scRHe32ZE6txllkly8/UiYuIGxbXR
         WYhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8+AcTCuyfT2R05agHh+CIjHYuPYzDMdvQPzexLJ3I9PuRTbD//s3eBFSP8PgTc/PiC1gHbw==@lfdr.de
X-Gm-Message-State: AOJu0YwWfuqdk+oiAezDySPgNWfmGOU7wTEl7MSz1lqdAx96xskwyepf
	bhj9OcVeoqBmurrJaaUl7A7/6o0JYpQ1lQrZI/BzBVXpuaTPg+N//gJE
X-Google-Smtp-Source: AGHT+IF3Ou1QlrmG55A3MOa1Mp1GAWrjHk5G4O201BtNkQonqJhPYkJJaVi7E1Bjx8JX28HNoWON5w==
X-Received: by 2002:a05:6870:15c4:b0:30b:c4e1:7945 with SMTP id 586e51a60fabf-30c94e56ab2mr2009694fac.1.1755005454954;
        Tue, 12 Aug 2025 06:30:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4IeiH+r0pPoARoajaA3HY3WZi/mRwCjdvDxGKSVxtEQ==
Received: by 2002:a05:6870:c791:b0:2ef:51df:c05d with SMTP id
 586e51a60fabf-30bfe42819dls2062694fac.0.-pod-prod-02-us; Tue, 12 Aug 2025
 06:30:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSNP6KTkAO0vxlH2lYik2fWkqICf+QPjv2lGoCwzdZmz8lFMQ0qUslzQ6kLkCBFg+y1ZvbktCFzKI=@googlegroups.com
X-Received: by 2002:a05:6871:b13:b0:2ff:8852:da88 with SMTP id 586e51a60fabf-30c9503575cmr2034936fac.18.1755005453967;
        Tue, 12 Aug 2025 06:30:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005453; cv=none;
        d=google.com; s=arc-20240605;
        b=Z2hYPDUUHrJnjl3FQEuspPVc82RV0NeZIpS/NygncranjpyR7DLY6ixKdMx+tSQTkQ
         HiRaHfKoa4XrwLGWqED/Uy1MRqPaZoUwdYAL0kuqlWaAlPMtcJQJFqLjS4Cq+AaXBWka
         6r76m15tIvjot2hZozvDFU7ZL8fAtdm+WyLhMDFx9Vx8rUp4M7Eurz5qJo9UNJZkiysc
         60HabWNcy/EwPT7EQR4jI6Qupx2JEub3/9Cmewul3bKzfJZ0alfvwzQHUhsgIoPEGAEh
         54L5uOGDUfO51cN24NLtn8yZucDClXFW+OEPDZ8MphHdlR6tzo4kFmr8QL9m9hEJFRL9
         kapg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9pMJ3Vo5IMuP6mFoJhewFUZLR0jAiqJe8Z9tK6dwhQE=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=cxFCRlYoA/P99Ful1MO45KNIj0AzePHVeCtjQFmKyjbjK3EWQf/8eyijIroFOIg2HH
         qRHTYKE4NenSPArL6Zsd0ENeqjtGrpMhqGHw4teq1VjkpR/HItbyDBRQcxf2RD7ySEtu
         Vpj3J0gqNqE2KgjhvkslLE011pJHH8q33z82r509nNGFt4IIpLIFZHrN6HHGSQ3nzcKo
         +QzHtxWY29evJ/InxS2RjsukDgBIwWdiOxdnV+NfCl0MKzr41kruPO1biUkntuLvxM5q
         GqzLJckckfuAO9MSa5dV9Kl2t73Qr7LD804MauemK/+W/n6eApafyUwbVkqAZGcAsdRY
         XuVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Bb5zXZft;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bd07efb28si506112fac.1.2025.08.12.06.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:30:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: gnUvhuPcT4uwtrnCJkK9ng==
X-CSE-MsgGUID: 57Kmaiz4SaSRpii8XkhfCw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903985"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903985"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:30:53 -0700
X-CSE-ConnectionGUID: Qs0HalWXTxanbhip8kE5PA==
X-CSE-MsgGUID: lUt/yXQuTg+taKHifBrAyQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165832023"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:30:21 -0700
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
Subject: [PATCH v4 15/18] kasan: x86: Logical bit shift for kasan_mem_to_shadow
Date: Tue, 12 Aug 2025 15:23:51 +0200
Message-ID: <a1a7d761bad9ead5596edb2dbe62cab26c24602a.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Bb5zXZft;       spf=pass
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

While generally tag-based KASAN adopts an arithemitc bit shift to
convert a memory address to a shadow memory address, it doesn't work for
all cases on x86. Testing different shadow memory offsets proved that
either 4 or 5 level paging didn't work correctly or inline mode ran into
issues. Thus the best working scheme is the logical bit shift and
non-canonical shadow offset that x86 uses for generic KASAN, of course
adjusted for the increased granularity from 8 to 16 bytes.

Add an arch specific implementation of kasan_mem_to_shadow() that uses
the logical bit shift.

The non-canonical hook tries to calculate whether an address came from
kasan_mem_to_shadow(). First it checks whether this address fits into
the legal set of values possible to output from the mem to shadow
function.

Tie both generic and tag-based x86 KASAN modes to the address range
check associated with generic KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 8 ++++++++
 mm/kasan/report.c            | 5 +++--
 2 files changed, 11 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 5bf38bb836e1..f3e34a9754d2 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -53,6 +53,14 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
+static inline void *__kasan_mem_to_shadow(const void *addr)
+{
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+		+ KASAN_SHADOW_OFFSET;
+}
+
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cfa2da0e2985..11c8b3ddb4cc 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -648,13 +648,14 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
 	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
 	 * both x86 and arm64). Thus, the possible shadow addresses (even for
 	 * bogus pointers) belong to a single contiguous region that is the
 	 * result of kasan_mem_to_shadow() applied to the whole address space.
 	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64)) {
 		if (addr < (u64)kasan_mem_to_shadow((void *)(0UL)) ||
 		    addr > (u64)kasan_mem_to_shadow((void *)(~0UL)))
 			return;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a1a7d761bad9ead5596edb2dbe62cab26c24602a.1755004923.git.maciej.wieczor-retman%40intel.com.
