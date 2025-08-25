Return-Path: <kasan-dev+bncBCMMDDFSWYCBBUMPWPCQMGQEAG6T77Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CB7CFB34BEA
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:30:11 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3eb14eebe86sf58750365ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:30:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153810; cv=pass;
        d=google.com; s=arc-20240605;
        b=SaewqneYh+v4MQBFPF5onHU5B2mvm3QQbOUj7toMpCwX+yJHktCRiwTWhZQYeViphY
         vbw0wLGiTc8vAzF5Ee2ePVoTSwDHyDH0c2frdDixU2BEf+UjmqLKjhg0oZoHVL9uhcEV
         lmQ9GMHv/R9ms538f7ZxFMg4rRF3S6s0VciKXSSf1kQjYgJyG6Hut/7LhMCIPsxs4ETa
         CC/ELqUV7eN/undrWQ6naCzIz/1atfV73hrR2FmqqEDiP+SH3pWMhvAq1YhGXmYgbeGw
         Pww+wOtmAYMbj7t2UX39FkWvNCv1mK3ycL/gmU2neCP3ohUkTdc4suyeY3droF/dnebc
         6roA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1Kh7AhNtNWho/s4Ykk22ZLopGtgDBglUByT2RYso26c=;
        fh=Nv8qE4ENT80AVCGLqbZFr6cYi5qx5Iic1weKqFewYxs=;
        b=FfuzNh2xFodY39sc2aHvnmSuItlYDDDj66IeLcISiX5+oOtw78PrBwFGljHKH/NWkW
         dzr8CMQgL6QxOHG1pcj9ksQk89rjf4AhogmRDls3W51PZJkjx4QE4EYSW9nH/ecAeTZc
         7j29ul6IMGf1ziOuH3bVG9L0/Rz05VN8/KMflPV3yCM1YGZJQaZqwutZ2e9Dds/ni2El
         uj64S9bqCnzJJtHn3Hdw5ZrdaHI99AWGaOnT13PhOUu2B0E8C0ugYUn6BOimLyrbdPyn
         ZD2tlm3V9wsTV2F3tjkibXFS5yt+iSshxeLrN0Q971hs6fjA51Kj1Ll8jgnx8HNnUsNq
         9J8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="i/qPBn4k";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153810; x=1756758610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Kh7AhNtNWho/s4Ykk22ZLopGtgDBglUByT2RYso26c=;
        b=lB/RBnpGWFvWOAQifWHYRl8oyC8yaRNY/C7pMyfRwW/K6YVulTW98tdL8tuu1vfeft
         fA2z620XFr25XDJu/0bOOko6ViB+liEoMWJM28PemrUzQbz9p8XB8pWJtk2vE2coLzPn
         sDHe3J9K30ZumZhn3tZnYVASXj3tWyw22zdbL+tfgvG4V1elvmThs7Z7jgEb0y5vP3L+
         woFDhBQWKLtYxbYnnPYWiTaHtLd+YWsR1turTKCgEFYXpQodofGQxAL4NdI9AbOR6PJi
         w+N11WoAQFCwrkyjMvP8vEwnZ5vb95U8MpYeEqpZfhgg0GL+oJX7bHpRYhn3g1XQPbkj
         JkzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153810; x=1756758610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1Kh7AhNtNWho/s4Ykk22ZLopGtgDBglUByT2RYso26c=;
        b=fz768TgP3XRIA45nwqgERNjiFON+579pHn3vMn7luYtLZgMcXDagQHljxuhe8JmhYl
         6/5MGxRIX7x0EMnkThMhzLbhkrQr9IMMkCkkn4zgaaObOlvKjoBF3SwxISF/dRsAudcX
         86f9rD1iDOPbxak599g290Lf9Zm5m9nAH7Vl/e4x+nQWwzYGbfzHY2m3HYRAXsXPTwcx
         NIUcqizc/c+L3Gebo5UlGpiS2GztnZpJ1t5niPC/jI+25F2vPM75RD0dEq8gauNAGFWC
         NnJkiL1Wf0Hr9ox+V9lVRKpnIPOcMhIooPvjosNJzJ8S16ZOHJz0UQ9pkLF1NpRdLiUj
         vGfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxcewxxE2hcH+0T0l+rcxPnY5TiEawdAVkThIuBq/3UTjYz0wJdd4mAH5BwKyFV6xqHyL4/Q==@lfdr.de
X-Gm-Message-State: AOJu0YygkzRgLAaSg/K9sR22PZcXe54xzQ73B/+9jyc0GFoPCHP17bNT
	sRgWSyW6zaCrrsC/nTQEisXnh28HFPeFmFQg2nYd1viyEH71WfR2DBa6
X-Google-Smtp-Source: AGHT+IEOAAH+ez2ZuRAe+IteLO2gcc3vL14br6r+FBz3cUIFII/318GjqGq+okAdddZSkZIgs2cv2A==
X-Received: by 2002:a05:6e02:184f:b0:3eb:5862:7cea with SMTP id e9e14a558f8ab-3eb586280a5mr32904965ab.15.1756153810053;
        Mon, 25 Aug 2025 13:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdw3dmDLGl5+pTCdTu1+x6OzZwQLJmGfFt2nTe37e0ozg==
Received: by 2002:a05:6e02:4811:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e6835fdcfals50033485ab.2.-pod-prod-02-us; Mon, 25 Aug 2025
 13:30:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyFQT5b85jsJk6YG5GnWTQvX+c6/CC4qFkK3CJKv32EHx1/KN6ujnI6UH5YYvOf6hE1NQB7PxOt24=@googlegroups.com
X-Received: by 2002:a05:6e02:1486:b0:3ea:9da1:b655 with SMTP id e9e14a558f8ab-3ea9da1bc20mr107374765ab.21.1756153809082;
        Mon, 25 Aug 2025 13:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153809; cv=none;
        d=google.com; s=arc-20240605;
        b=Db7CXxiDaP9ZpgAZXnag80kGkPJfzPKmDimAq+AdbGgLCgJEt/MQLIHsk00/yOClPx
         c76QD1rhqTDh1hS+kGE7MGi5747tCI4c7l5X2H3cdhGu1mK+lFKtM1vYyi63wIVVm8Fm
         7JYE3WQ89BkfB9rpQ73TUtITlvtGOx0/+GP+VGawF1JD/EeslDkGCO6l5dMyfTrz+8xq
         0SEvNWdPgZrdKGnMG99IM/+w//xXhbDZ5IK75bUkM6GjTgWftLi7PDx+rxp2SzOeZ3yy
         MlC6PJKWNV5rnuWahlJN+ACrH3Ygse4dJJ61cgPezeLrJ1MjG1xJOkB5Ia1xm/9+Pj6E
         TCrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=z0YCoxoZqLoXaL5waUCXEhDq4RCJHfZGu425YupVVaA=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=DvH6fsgKRuIfCFLucTGZ6PLwrVauKTn2jjM8BbAnkBBDRy4X5jNp1+rwoqdaSTd6nY
         bpOWZ5nD9FdaD7wAUtJtdjg3lh/75Ax+MiaFtqL8J6Pzeo2hUoZ/q+8JXyXKuvuONt/+
         79aj0PTrVEu1aNvI5WK0jGpMutc0tXRcH59NZ66qwoyB+PeM5cgQ2sbVkm1HmD9mNZgK
         LQcJ6V3x7RU380WvUMpAAXC1/za62pQQ/fBW/xNu4uT0JPJlpwZMoXDphAU0JUYsHEBG
         ZaOC14XWTBO+MVZjrcnOye/2bwRxA4VutTE3tVk2gBtZEoj3VyrCwODhXnyF8PYNyFDZ
         X2ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="i/qPBn4k";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3ea4e266abesi2577655ab.3.2025.08.25.13.30.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: c2XJkJsKRQmJAgrFw9xRng==
X-CSE-MsgGUID: zXlcHVVpTX+FRQOqLgKbww==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970886"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970886"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:07 -0700
X-CSE-ConnectionGUID: vVb0osiSTzynXkLiboYB/w==
X-CSE-MsgGUID: DrJ+CdCFQni2g9dVLCwjCw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780722"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:44 -0700
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
Subject: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
Date: Mon, 25 Aug 2025 22:24:38 +0200
Message-ID: <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="i/qPBn4k";       spf=pass
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

Inline KASAN on x86 does tag mismatch reports by passing the faulty
address and metadata through the INT3 instruction - scheme that's setup
in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).

Add a kasan hook to the INT3 handling function.

Disable KASAN in an INT3 core kernel selftest function since it can raise
a false tag mismatch report and potentially panic the kernel.

Make part of that hook - which decides whether to die or recover from a
tag mismatch - arch independent to avoid duplicating a long comment on
both x86 and arm64 architectures.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v5:
- Add die to argument list of kasan_inline_recover() in
  arch/arm64/kernel/traps.c.

Changelog v4:
- Make kasan_handler() a stub in a header file. Remove #ifdef from
  traps.c.
- Consolidate the "recover" comment into one place.
- Make small changes to the patch message.

 MAINTAINERS                   |  2 +-
 arch/x86/include/asm/kasan.h  | 26 ++++++++++++++++++++++++++
 arch/x86/kernel/alternative.c |  4 +++-
 arch/x86/kernel/traps.c       |  4 ++++
 arch/x86/mm/Makefile          |  2 ++
 arch/x86/mm/kasan_inline.c    | 23 +++++++++++++++++++++++
 include/linux/kasan.h         | 24 ++++++++++++++++++++++++
 7 files changed, 83 insertions(+), 2 deletions(-)
 create mode 100644 arch/x86/mm/kasan_inline.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 788532771832..f5b1ce242002 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13177,7 +13177,7 @@ S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
 F:	arch/*/include/asm/*kasan*.h
-F:	arch/*/mm/kasan_init*
+F:	arch/*/mm/kasan_*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 1963eb2fcff3..5bf38bb836e1 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,28 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_KASAN_SW_TAGS
+
+/*
+ * LLVM ABI for reporting tag mismatches in inline KASAN mode.
+ * On x86 the INT3 instruction is used to carry metadata in RAX
+ * to the KASAN report.
+ *
+ * SIZE refers to how many bytes the faulty memory access
+ * requested.
+ * WRITE bit, when set, indicates the access was a write, otherwise
+ * it was a read.
+ * RECOVER bit, when set, should allow the kernel to carry on after
+ * a tag mismatch. Otherwise die() is called.
+ */
+#define KASAN_RAX_RECOVER	0x20
+#define KASAN_RAX_WRITE		0x10
+#define KASAN_RAX_SIZE_MASK	0x0f
+#define KASAN_RAX_SIZE(rax)	(1 << ((rax) & KASAN_RAX_SIZE_MASK))
+
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
 /*
  * Compiler uses shadow offset assuming that addresses start
@@ -35,10 +56,15 @@
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+bool kasan_inline_handler(struct pt_regs *regs);
 #else
 #define __tag_shifted(tag)		0UL
 #define __tag_reset(addr)		(addr)
 #define __tag_get(addr)			0
+static inline bool kasan_inline_handler(struct pt_regs *regs)
+{
+	return false;
+}
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 static inline void *__tag_set(const void *__addr, u8 tag)
diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 2a330566e62b..4cb085daad31 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -2228,7 +2228,7 @@ int3_exception_notify(struct notifier_block *self, unsigned long val, void *data
 }
 
 /* Must be noinline to ensure uniqueness of int3_selftest_ip. */
-static noinline void __init int3_selftest(void)
+static noinline __no_sanitize_address void __init int3_selftest(void)
 {
 	static __initdata struct notifier_block int3_exception_nb = {
 		.notifier_call	= int3_exception_notify,
@@ -2236,6 +2236,7 @@ static noinline void __init int3_selftest(void)
 	};
 	unsigned int val = 0;
 
+	kasan_disable_current();
 	BUG_ON(register_die_notifier(&int3_exception_nb));
 
 	/*
@@ -2253,6 +2254,7 @@ static noinline void __init int3_selftest(void)
 
 	BUG_ON(val != 1);
 
+	kasan_enable_current();
 	unregister_die_notifier(&int3_exception_nb);
 }
 
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 0f6f187b1a9e..2a119279980f 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -912,6 +912,10 @@ static bool do_int3(struct pt_regs *regs)
 	if (kprobe_int3_handler(regs))
 		return true;
 #endif
+
+	if (kasan_inline_handler(regs))
+		return true;
+
 	res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);
 
 	return res == NOTIFY_STOP;
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 5b9908f13dcf..1dc18090cbe7 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -36,7 +36,9 @@ obj-$(CONFIG_PTDUMP)		+= dump_pagetables.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o
 
 KASAN_SANITIZE_kasan_init_$(BITS).o := n
+KASAN_SANITIZE_kasan_inline.o := n
 obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o
+obj-$(CONFIG_KASAN_SW_TAGS)	+= kasan_inline.o
 
 KMSAN_SANITIZE_kmsan_shadow.o	:= n
 obj-$(CONFIG_KMSAN)		+= kmsan_shadow.o
diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
new file mode 100644
index 000000000000..9f85dfd1c38b
--- /dev/null
+++ b/arch/x86/mm/kasan_inline.c
@@ -0,0 +1,23 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kasan.h>
+#include <linux/kdebug.h>
+
+bool kasan_inline_handler(struct pt_regs *regs)
+{
+	int metadata = regs->ax;
+	u64 addr = regs->di;
+	u64 pc = regs->ip;
+	bool recover = metadata & KASAN_RAX_RECOVER;
+	bool write = metadata & KASAN_RAX_WRITE;
+	size_t size = KASAN_RAX_SIZE(metadata);
+
+	if (user_mode(regs))
+		return false;
+
+	if (!kasan_report((void *)addr, size, write, pc))
+		return false;
+
+	kasan_inline_recover(recover, "Oops - KASAN", regs, metadata, die);
+
+	return true;
+}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 54481f8c30c5..8691ad870f3b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -663,4 +663,28 @@ void kasan_non_canonical_hook(unsigned long addr);
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+/*
+ * The instrumentation allows to control whether we can proceed after
+ * a crash was detected. This is done by passing the -recover flag to
+ * the compiler. Disabling recovery allows to generate more compact
+ * code.
+ *
+ * Unfortunately disabling recovery doesn't work for the kernel right
+ * now. KASAN reporting is disabled in some contexts (for example when
+ * the allocator accesses slab object metadata; this is controlled by
+ * current->kasan_depth). All these accesses are detected by the tool,
+ * even though the reports for them are not printed.
+ *
+ * This is something that might be fixed at some point in the future.
+ */
+static inline void kasan_inline_recover(
+	bool recover, char *msg, struct pt_regs *regs, unsigned long err,
+	void die_fn(const char *str, struct pt_regs *regs, long err))
+{
+	if (!recover)
+		die_fn(msg, regs, err);
+}
+#endif
+
 #endif /* LINUX_KASAN_H */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman%40intel.com.
