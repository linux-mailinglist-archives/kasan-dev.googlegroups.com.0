Return-Path: <kasan-dev+bncBCMMDDFSWYCBBE4OWPCQMGQE32CPU2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E5B2B34BBE
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:27:01 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce5cb529sf7179874fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153620; cv=pass;
        d=google.com; s=arc-20240605;
        b=TasFkdCb2FpYYGXLWHVCpu2IBHLFK3CSY/D2mBgzjh+NNm40aQpAS5Ox97V8fRqKUs
         HiGNeGE3i3T6vGWrhwv1xwaAutQN8Te5eFjvvqCNuprQppWuLnvKUAElxcrDYH0d12OF
         pJX1M4ZrREYPNoWGbj1mpYVtIfZ4YCLvTk9DiHMoFOE6CF30HdqOYZyC8AsXxkFALh4B
         Of9MKKqpyiLUjUsk1ERVLDlpnW6bOgTKQUqPSNLgv1GpUBXXYjOECBMjqi6G3P1JQyhq
         8eZCspYpTaHdxB052fjR/N7sAj+KRe83TKVwumw46lXNOeO92mvwnMHiRs+49RvbNPZ+
         4XLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cuC7CDRmk/clq+e33CQu+7/42t9rePEduz6ZIv4PyyY=;
        fh=HdTkVZoLopwpbgVJUiB5jDIGBaKQBQh2k0QUHvW8E5o=;
        b=PO9YjIdcqVHQQ9ByIuktVFSeyS1payJ99Ic9sFJJvWkamd5p0WvIyAzJMGs3FIe106
         BbrFPdX2GMWscU4wxUkUpcLQKZl8nf3tYoUzA6IxkshUXU7lo/feh1Q63ovxBx4KP857
         8QGGb6St/0i/EnxqcYbGGUa4Dnm1UIQcql3gcKV9nUNs/8VoH56L0uE6g+Sj8cKX2/7m
         UJb5WJcoXoGOZuJAjmuj+zY8iRGAAkHVAf0OX/r0wVaN8T0JZY/kaVIRGSADgwjAQSHL
         Di6k5qatus5P4S3mJ+JOpgmbrZ+zLMCAB0OD9wnlHWxB1GvfBa02ez84bsnAzdCSyNf3
         mmDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nUypk8fH;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153620; x=1756758420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cuC7CDRmk/clq+e33CQu+7/42t9rePEduz6ZIv4PyyY=;
        b=DGM0FIFMENTlQsTvGlXEMRdh+6W51GUiAhZbpE7jHvcuDsSbFvfLZ8ijc0DYOCRARj
         n9EpH61l1an9wuQbXf8PXR7ue2q78aTMK/3CDrWCZQbq3jyicwbxY2gH4r4GQ3Oef+je
         Kv+UKgvG4FZspw2Bo0+CNchNc+K9pjq2PHghhJhLQiwgyYLE7dIhLQakQJjiu3KKCNDp
         VtQEe4wI+1ynaYF3h7Y+V3p7qM6tCFBwJdcwxJt7MdbhxSoN0Omo/X8jtUknqmjR8QaO
         05P+OKMNpfx8Sw0p2QaF5o0bacOpgCchiVHbNefAGt5qWHGyOq8TFElrjGFCyYnExCXT
         kliw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153620; x=1756758420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cuC7CDRmk/clq+e33CQu+7/42t9rePEduz6ZIv4PyyY=;
        b=B14jXyw5OyXpVY9AMrPrFMwU8OU2P81vcJfzrX8HAv9dGv5C9NWejEm8Z8vesk6yMh
         /fBlfCtamP07oE2ybiv5sWtW22RQr9ovPbr1Z8SkWw/lZs/UiJjmQJ6RC1itYmWgBIHI
         xpjyReJhdWnPE8S24o7ZcmHBww5sSg/zkKmbiQJ1wF9SuWaJfO2ADy4B9tS95k+ECXRN
         7FUu4POyRCwQMa6i09wIqH7d1rP3j3jCvOX9D7S+ivGz8DqaNhIsses/Kr0TXuD3XsDO
         HBukYwaNdBIEwEhf0ijB2NcsXcX+yL3RVGzZO/dZRzQI6FWVC9QsbFb3Qf+nKqeRhcrX
         TE1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNbI9ld4cagaJFAaoye1lRv3S7QuUiq1OSPeNtSC2p90gR6yUbqn4aVtKFx4Tn98Vm/Ox16Q==@lfdr.de
X-Gm-Message-State: AOJu0YzPtDK4PtD6q8t8zD8SnHOpL9baxWJQTv5/EQkO7doXoFU+zM7R
	q4y83hvKnS2jmLJCoV+J1sViDMznqt0ptSwk/BP4cegJQMSH8mMFkba4
X-Google-Smtp-Source: AGHT+IEKrNCnCqqTI8UDsxf1fppfrkmL08U9oypYf53Pi+QgjFJNYYgBhsoxe9zM9Ypw4H2ayTlNVA==
X-Received: by 2002:a05:6870:e38d:b0:315:3d07:6e2d with SMTP id 586e51a60fabf-3153d079dacmr1297399fac.29.1756153619706;
        Mon, 25 Aug 2025 13:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7valNHQtLfeI2B1l7oTEcx6mdS1s2wzVYng7xCAlb9Q==
Received: by 2002:a05:6871:c30f:b0:30b:d6e4:3de6 with SMTP id
 586e51a60fabf-314c231454els2319736fac.2.-pod-prod-01-us; Mon, 25 Aug 2025
 13:26:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpNfYBIi8rz6HQuL29+KaggyUcKAFZUCx0gTkkLn2MlSRDxBqXxAzf4iWUhY4EVEIPGDurebVh6RI=@googlegroups.com
X-Received: by 2002:a05:6871:e7cb:b0:30b:a81d:b56 with SMTP id 586e51a60fabf-314dcdb5049mr6415005fac.38.1756153618876;
        Mon, 25 Aug 2025 13:26:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153618; cv=none;
        d=google.com; s=arc-20240605;
        b=lDunTMUXD99B5t9Rb/PjO1lXjnnFv5nRAo9UuUPnsWaXlvG5e1sjfQ3XrdrIWTECCR
         REiBZGtA4gnKo0Q2Pqr2GTmYrDMYAORJkijSID6kVwj5nFsuVYb1/OTWLNwpIM58BHxZ
         EdITIXeSCT4fX0Vn+JNd5M0p59vAr8sLAqTDwlPrPmVU9MhfqNjbX4PGx/YE3QC0Jrs2
         UdYUP354d2cU8/jnJEcLbokojClyOKrPZgBb3JFDvAlYXZWp5M21SIKHsjg2rxvFZ+1o
         D+eI7SQRXweXL6PDMg4SnkECFdUGyVExzwKZQb+yw4gr3S0hKn8T4w69Umo5bT7Fobi5
         PQzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E1eXm8xfKIhjDNACz9/lPozC75PsVZy+RO5JY/jLRAo=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=jXApKwyr3D1vr/Fm0RTD7kuRNwU/z1stq21Kub0pued5w0lj16IqohWMzeajzXIOUn
         jv9Ca2k39g5Zlw6wa+KnBCR3p1aKBRCtzcMn+jdu07UzRcgM1bq581hjSaNXIFV3CuQl
         dx5bc07GW/i8BXS/xKXHo5Wtw+SvSNNIwFf4dApNsGIY0JflO+7HvD30SCcPQNsWwdO5
         BOxtkpDsPN04owli0buKiCmlY5BLHmJXUG9aiSPoWNPsChaxPedkxfAQqIvHQ/V7L9PO
         hlNOBXryhq1crq/lr5cwY0Ws6VXUmbLwRpN40ZLQhsppN/fkLsilPuCnbOxav1FVWIIR
         9aYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nUypk8fH;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7bc3b10si319115fac.3.2025.08.25.13.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: U3aD/0+hRW+i9gh1jX3sHQ==
X-CSE-MsgGUID: 5z+nXOz2TE6r2kaRElxXtw==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970385"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970385"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:57 -0700
X-CSE-ConnectionGUID: NLx4kw5FQRqFjJVf8cE+Cg==
X-CSE-MsgGUID: 21hF26/3R2SLuLwXAqtixQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780102"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:35 -0700
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
Subject: [PATCH v5 04/19] x86: Add arch specific kasan functions
Date: Mon, 25 Aug 2025 22:24:29 +0200
Message-ID: <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=nUypk8fH;       spf=pass
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - to set, retrieve and reset tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Rewrite __tag_set() without pointless casts and make it more readable.

Changelog v3:
- Reorder functions so that __tag_*() etc are above the
  arch_kasan_*() ones.
- Remove CONFIG_KASAN condition from __tag_set()

 arch/x86/include/asm/kasan.h | 36 ++++++++++++++++++++++++++++++++++--
 1 file changed, 34 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index d7e33c7f096b..1963eb2fcff3 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -3,6 +3,8 @@
 #define _ASM_X86_KASAN_H
 
 #include <linux/const.h>
+#include <linux/kasan-tags.h>
+#include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
@@ -24,8 +26,37 @@
 						  KASAN_SHADOW_SCALE_SHIFT)))
 
 #ifndef __ASSEMBLER__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
+
+#ifdef CONFIG_KASAN_SW_TAGS
+
+#define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
+#define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
+#define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+#else
+#define __tag_shifted(tag)		0UL
+#define __tag_reset(addr)		(addr)
+#define __tag_get(addr)			0
+#endif /* CONFIG_KASAN_SW_TAGS */
+
+static inline void *__tag_set(const void *__addr, u8 tag)
+{
+	u64 addr = (u64)__addr;
+
+	addr &= ~__tag_shifted(KASAN_TAG_MASK);
+	addr |= __tag_shifted(tag);
+
+	return (void *)addr;
+}
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+
 void __init kasan_early_init(void);
 void __init kasan_init(void);
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
@@ -34,8 +65,9 @@ static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
 static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
 						   int nid) { }
-#endif
 
-#endif
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASSEMBLER__ */
 
 #endif
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman%40intel.com.
