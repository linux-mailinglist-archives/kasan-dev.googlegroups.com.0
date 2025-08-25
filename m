Return-Path: <kasan-dev+bncBCMMDDFSWYCBBOUPWPCQMGQEKWJZJCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 82219B34BE6
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:29:48 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-325228e9bedsf6129068a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:29:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153787; cv=pass;
        d=google.com; s=arc-20240605;
        b=fnSE+aYzb4k1WNdaC4DMKwHwGkrzqcnH0vXLzptsBwFLJb6Iye2cVCDG03N2oTB+bb
         gLH4F375kvw2et4vwTOliDJDuEgFks8U9d1wXbjntriq8wKDsUB/wp08PWsRhyubU5II
         DChRnJs/JilXA7fef+OFbeEQv8xqirNLlThCJtdAGIj51K4fUCUwS5FqcyOTaECx4mbL
         Yg+C9NT836olKiHYalq3KSYyEsbRtP8+pPPW3J+BOR3oMim/5+aoqxMB68goL91+wC4D
         v0OOT/SMcMlPXyzdXicgRClqjGMr6dSPxW4aN780exHvm3yQXFdv6ynP11Xjn9FG+WCA
         ZNaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tQsxXkVFoLQCJyzeekFvt+qmk6gaVj2puJu2sZiVMhs=;
        fh=3o1JA9TuiuM6rp3a5vBal8vNsPNPZ8swYj4bCBrMhTY=;
        b=FJOHVrVVf6Pm3TTZldlWoT7yYUK0tsuhkaBYpXgk5jjE4Q/+P0FFQ3imw3HRkR26a8
         g+Ag8VCavLkgO8IWpmqSdRIEJVeCHg9bUmdML2NB6TZvY/sBeRzem49/uMjdnCHj1kCO
         tYuTxVY4wYGqfUxeQQmNmF9GGYidQ/Uk75zWKVKNUe2VINjp71oquUyhkp2EWJIPF1Ix
         QSqdmaq8Os6G4BUSD34zegbSqDk1kYYJT+bN23LjPh9W0f83CAIn3X2GtuG6lL3y842o
         jf0uOusl3WBO9GziBYoRrvAkKq5a/CbOOxVIuWplMJMVaU+Fopt5vQeNEuSjIavo20pj
         RUuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dian+jXT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153787; x=1756758587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tQsxXkVFoLQCJyzeekFvt+qmk6gaVj2puJu2sZiVMhs=;
        b=iGVivbhuhA7r1KyTr5CiuSAGWjNA8FYeaINI47eGKk9NT+00zGWn4S14UMZKqOVJ3E
         IqUVjh8bhE80/FtZfrz4iMdV+pA70vWYVYiEAHEQXdTDbFtVJxw+vZMbOKA7H/xAxFOE
         wi8mPOCotDBjiq14yyJdCDbfdQrV1ICDEmUhLuVxacHrCjDwSbiKKscJ7V6EFGW4pA1W
         W4pDwXPhNKIVq+FyAC3LzjyQAiR6oYhGrdBw+7Jll7ZY5IbSElU1SLV82pSeNXV/X6Ca
         aFvwaqbl+Nbb7vCLIWFAOtKIo7Z7WAdz7axghw3lutTtQgRx3YpqaGilAjhZy+uTVTi6
         Yh3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153787; x=1756758587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tQsxXkVFoLQCJyzeekFvt+qmk6gaVj2puJu2sZiVMhs=;
        b=baAH+tSvegEpoUO60wZDdOCxia2RrmZC78TJAZPz2Jqr1WOb8kF0QZJDm4wlvENXZ/
         JaGXuwOAh8Gik5V6mga1JjR+hgyjDjN8yk72pzWCMWwD0325de+nbIkfo9KWPCI2+tP0
         xm4B8jhUPFUZtD4rcasBT0X3V+mn9OoQybk3mdIfkGfFd3Qa1ZDnCMPEZBqwdcNbs27z
         eS5JavVjkLDwXFYciS5Z5Fa7GuB7T//w4rVYU3iY38l0USr22+Vhw4RncLAOOXBAK0Cp
         Ftmsrm7Zi3LrATiWfdmTr/ba9j2ozoGtAdKQMlDD3HpmBJC5+4gIYrXBZG/NGvA/I4Js
         Xdlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNsbfFST4i/GzJ/kvoCkqLZiIAx/gnZhhuomgSBK+Ac0mh7sozN/PXAk8l8l67bHprX4/0Xw==@lfdr.de
X-Gm-Message-State: AOJu0YxlM560UZIPiQD0yDaJ5kvVqIQefRMAtSiKnGiPdkKC8bFQXIIo
	w2c3s/QXeEg0lsGq6AW6Z+p+tqD7P4mGYJBpCGsyYW1aAE5gw9PqcIry
X-Google-Smtp-Source: AGHT+IF32+OjN3ULIKBrz1JtlRTiq1XPqiBNHH3n+0wyoFn2BCCk5hkuGORTOgu0Ay0EgLgE+GLdKw==
X-Received: by 2002:a17:90a:d610:b0:31f:762c:bc40 with SMTP id 98e67ed59e1d1-32515e54409mr19754779a91.16.1756153786880;
        Mon, 25 Aug 2025 13:29:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcT8ZJKLkxQFTbrzFRKNowbkRoruPIsU5UL/5KtOg41Pg==
Received: by 2002:a17:90a:1589:b0:324:e4c7:f1a2 with SMTP id
 98e67ed59e1d1-324eb85e147ls4462535a91.2.-pod-prod-06-us; Mon, 25 Aug 2025
 13:29:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDGbU3/oAa7wlFzUEQlhVVN+0+2+68GqIRRaCA8INO5MGUX/1/VSGhTAgVK/iDuZMMGPB3TAtSThQ=@googlegroups.com
X-Received: by 2002:a17:903:1a2c:b0:234:a139:11f0 with SMTP id d9443c01a7336-2462edab80amr186755795ad.7.1756153785646;
        Mon, 25 Aug 2025 13:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153785; cv=none;
        d=google.com; s=arc-20240605;
        b=aJUgAqrno25eQdAwAAAeFYIXs3JIS4I/cmhWtI8bzkFQeezE3YcO39VUStRMbqv0LM
         5S0ej8YNwwEh0i7PcTr426xcIUAIKsb9627WsYEzwOzF6WI7A1byekMXl3yFiHW2eYT8
         nMmWyn7UgPih69Ej/M/TFyOqt0t82JiH13dTfoo9+gu9WEhhAiB0KGouGhBswfNe/WOZ
         e9DuFQAneVUkEoUE7TNHc74ivCo1RjekpQgFghUCH0HqggADs8zmxPdfw9LeZPM/cj7L
         Ib5LvNT/HOW2ktLR+LsbioVALZ25B05mlRYj0RNDFTse9F/UBVzJK7mzETbVUUwVmC+/
         bTpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ex520mDAAluSLXFdiYJ04d7IrdUaRDN9zWUBH2TlPCk=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=Kn1LSooBmlrVSFCsEccmtlVXf6nSDKdQk0QNhbTN4v+At0h932JVm3D86Kf0lB983d
         yD2u7S4yTLSwdte6UahUAubmYP/7bCNdFywUycHkG78P5K7gSTWwN0WRX1h5I1lpXz+0
         X7oewAaPk3Yyf5Zvmy97J/hsYSq7GgSeSQm7wdUZQtcufvHsUg77RYiIdgDv5Q4uq7Lp
         Gh6mMYKQY7a8WlgLsRx4JOCE2X0axvc63yACb9Ps25InyXN8bPdx3PW0WU+tk72kzQXd
         HM0ZpjN+L1QHgt78IOGAwtuRX1cVfYirZLTC2ba+teeccuOZ7P5Isnf0q+9Hs3NzOWXU
         Z6OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dian+jXT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b49cbbdfbcesi285050a12.5.2025.08.25.13.29.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: i3fBx1ieQ8aWex7I7RnssA==
X-CSE-MsgGUID: ibdX7O50SdaGrvNhgg1rnA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970810"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970810"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:43 -0700
X-CSE-ConnectionGUID: dPjkVayTRFCsnqA9Ybv36w==
X-CSE-MsgGUID: H249bgJTR6CaQrcj46DBWQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780586"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:23 -0700
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
Subject: [PATCH v5 12/19] x86: Minimal SLAB alignment
Date: Mon, 25 Aug 2025 22:24:37 +0200
Message-ID: <c9dfcee8bd04161394f41a21f78fc3e01a007ddb.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dian+jXT;       spf=pass
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

8 byte minimal SLAB alignment interferes with KASAN's granularity of 16
bytes. It causes a lot of out-of-bounds errors for unaligned 8 byte
allocations.

Compared to a kernel with KASAN disabled, the memory footprint increases
because all kmalloc-8 allocations now are realized as kmalloc-16, which
has twice the object size. But more meaningfully, when compared to a
kernel with generic KASAN enabled, there is no difference. Because of
redzones in generic KASAN, kmalloc-8' and kmalloc-16' object size is the
same (48 bytes). So changing the minimal SLAB alignment of the tag-based
mode doesn't have any negative impact when compared to the other
software KASAN mode.

Adjust x86 minimal SLAB alignment to match KASAN granularity size.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Extend the patch message with some more context and impact
  information.

Changelog v3:
- Fix typo in patch message 4 -> 16.
- Change define location to arch/x86/include/asm/cache.c.

 arch/x86/include/asm/cache.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
index 69404eae9983..3232583b5487 100644
--- a/arch/x86/include/asm/cache.h
+++ b/arch/x86/include/asm/cache.h
@@ -21,4 +21,8 @@
 #endif
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#endif
+
 #endif /* _ASM_X86_CACHE_H */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c9dfcee8bd04161394f41a21f78fc3e01a007ddb.1756151769.git.maciej.wieczor-retman%40intel.com.
