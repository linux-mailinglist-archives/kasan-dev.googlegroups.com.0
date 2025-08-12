Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJEC5XCAMGQEWCJUB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A40C8B2285A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:02 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e3fa175c41sf64085405ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005221; cv=pass;
        d=google.com; s=arc-20240605;
        b=ifdDh84pFmLd6fbhfr6J8bZ6SgmhDk0c32eNQjdJnCyo5mh/7BJs4/F5Ga6wsve8uT
         LxH791cC/k2qWDsW+d2WIO2HBQSclZ5bXzvvZp3wXvaOBa7YGfwx6qYhZXS63ZmSfm76
         oi4pVbTbJWDVpooaoTLq/H+vsa8V/eMy+kRwK8LPWjAJ0lS6bli2GvyLKxQuBYF9J/KS
         rMc9t0x5h20BScF2qp2fMb82Fqgc+g9vbOu6ikLBztCL4QRUblreZmkJZKBxjMoFx1/6
         p/0WnRfgBD2TP1Gp9/ucnrCwOcd40zCthO22BJJDtUEpoKciIHPoYMjgNP9T7cre3Jte
         kXvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nZwsm2AqcijJmK7Tp9t1q7qNUjJMJCMv9atBedoqYUo=;
        fh=4LuNezN0mR42hpdhJro3f59/lJK+54OarmSQ2xd/6EA=;
        b=c+F6Q8+TszbPv+TreSp4yKuQR7gDW95ke9CkHMMyFP8Eh1w+G4qpd2p+sFzIJzd+DA
         YMEn4yH3xJ3LLWRORLEsWVNsrsSkk8ZInxOSp0iBOe9W5gGHdjo8wRvYEAJZncA8sBvt
         3xRWKj0Dbf2/K6Je6/NrPCIo3nhDSdwn6VqhVYAKJD0uMXN4XIz3frJc+a4dUqEbAN3b
         yd+IYu+CvpItEJGIEcNy/mp4nK4wWBQ1iVRxDNrtmp+s5RDRZ1qoPe0LG0HoTQCUEiB5
         ugCkOrs4l739wnNhzJ5djPOOLiK6zMst35v08EfbLc+Mp0NxpcZmMAuVNK5CWbHRPddC
         +/RQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=clHCw6zN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005221; x=1755610021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nZwsm2AqcijJmK7Tp9t1q7qNUjJMJCMv9atBedoqYUo=;
        b=guDyIvrwn+yft/LWyD7+dnyc+e0joSxFrlvrlyScUcwVlq7l9QJNJpqGeGSX2k1MO+
         rckTPokV4Zcdey9yEwOhtfWqbtdC+MeZwcsbqIHU0hbjYGUyfJHj0KJNkCWRM9bmy4hP
         eMO78BYov6ApsGIQqfqsMgucTbuWrwkpgNhCyr80LjWoBEgxcsmBAnMM6i9V3HujeGAY
         ch3mFi5sRFMKe4ARBxdgHlTdWSAacAlEaqmyn+6n0Ow1SVPE1MIkMEYG+A59diCwnEBT
         KKkQTIXJ8nNY8/7ezBbgtDnFtwQK04Vz2FL1tYdJuapvauMUoQWwX9MxnHOxj55KUtw9
         3PXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005221; x=1755610021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nZwsm2AqcijJmK7Tp9t1q7qNUjJMJCMv9atBedoqYUo=;
        b=I2sd5MJ/qr/wyZ496mXMZWM9Tl6CTzkCZrEpZrw2s0NoHiVvX7nJhuImlOo+bowoXq
         Bb/JdXB5maylKl58GllXYQDZb0DgdinKxGw5UXjXC93PHvQlsJhBFso3YMwzp71MqKg/
         c7o5kKEqeB7pxpYQXQ4Xm3QfMaLBSlqFYOZP131jEcPVxOCDBKKKKPAjXXDGZVhdNF46
         jfWSHh/GtVKVlhENCNdP/wEFBA4844mYMTs5tIhB0zH+LSXV+T/rqVHc2YpWba41zP8d
         5rsoQLxCSHRSRqGUyuras3fqE9QURNiM2e6Gf7t7M79xCJqUHyErlctj5x6Ltnim4n9l
         f+SA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnwVL8dXCaK4BQKhAWW31p5qVGiJicoKra4xzOx76MzJRveyJrmgw/FHhrTuBGntNS3dnC6g==@lfdr.de
X-Gm-Message-State: AOJu0YzXAAUPqo1V4Eu9IyJ17pF15W66R26ITtuLc6/krN9y55yeLpQf
	ToYBL7tlyclG7fRG3IeHodjsjoPDOzu9YtH0evQcVOCa5fyxc/6cRm3G
X-Google-Smtp-Source: AGHT+IF4xylH5I4+lXCusXGddtTC4Woxx8gQ8eCBUV70/7Wgq71hPylcjuDCIkSx/e4hujeKo9gR5A==
X-Received: by 2002:a05:6e02:16c7:b0:3e2:a40e:d29f with SMTP id e9e14a558f8ab-3e5330ab6f6mr277234735ab.9.1755005220999;
        Tue, 12 Aug 2025 06:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkI1XFfkgnGcDj2ABW3LcWCZKF13pzokQzvyqlP4hv+A==
Received: by 2002:a05:6e02:4409:b0:3dd:be50:e1f8 with SMTP id
 e9e14a558f8ab-3e524ae09b8ls49761685ab.1.-pod-prod-07-us; Tue, 12 Aug 2025
 06:27:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnJZLHgL2YOpO2Llk5PdZgZaEzBarf5mlkAwc0wgdCygFtpG262dKA0+RYiMmpZn46sygu7eQnBBM=@googlegroups.com
X-Received: by 2002:a05:6602:3f93:b0:881:8bc8:b02d with SMTP id ca18e2360f4ac-883f1268a38mr3197412239f.12.1755005219829;
        Tue, 12 Aug 2025 06:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005219; cv=none;
        d=google.com; s=arc-20240605;
        b=RjZ6IwHfOcYrRVq9ooQC8xugFIuPeDsAg+JhNJzkc4q0lAROdGU7U8HIqj2Vt4cE4r
         1vzHWbxFBHZe/tXs7+LuGn6rFOkU9fh5VSQQIhjVCPzrXwf5egSxv0bEqPeYgPXhwIeb
         MNXOy27PdyLwAm5IZsqisxluf/DtgybPjTfU7mZ6QedXouVAjxEwcpcDOprKVmYhQ/WE
         LBQDIhoVYCUnpS/cMM+Gqe9jZU+B54/odMF3Kz3hdqyXTVp+ND3Bvj6bJnPYz0pyySGk
         Q88RuYYH7mOqL5sf3pOpD1keaNxx0DSF30urzr3cUXpo0/918rCMErH/RLYQlA1m7P0T
         OHtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E1eXm8xfKIhjDNACz9/lPozC75PsVZy+RO5JY/jLRAo=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=HFqxW9Wl6avfhrToGKY2ls+E+ke9Xre6Q7xcK2SC3q5TwYdLmzT6lU9YhsvBFjvhvM
         Af22RhiNt4zAGzrHpDPjzIpd35qV/CFXgX/pCVb1fQekQ1SAmJ6fQHmTbcCJLy2gaLM3
         f2ZSfp6tDAcmXy1YJpHBwgMOV4DuWl8EeFkhpEMd0XJ5ttwAZfV7tRFF8yq7ihq+8upr
         ccK+EIYJsUrDSQgiZnQD3+fVocCo7K8f93ZutOu63pepvrSY8VTu78qFGkDU3MTRo1TT
         0e2hzw8MHKIjSQUy3LkOIR3Bp0XKMBS7j+Od1VXRLx9hpiElRdIW6X6hsMR/vFjHQ3qa
         KAiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=clHCw6zN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si49156639f.1.2025.08.12.06.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: pbVUiQemS9Of2GFJ4SeEQA==
X-CSE-MsgGUID: 2jBDTMR2SZC+vGO/ExoKYA==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903341"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903341"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:33 -0700
X-CSE-ConnectionGUID: ZdcdAsOcQWWTFu4OTS0rRA==
X-CSE-MsgGUID: cCyGXKgLSeWES9FNw89vig==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831396"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:09 -0700
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
Subject: [PATCH v4 04/18] x86: Add arch specific kasan functions
Date: Tue, 12 Aug 2025 15:23:40 +0200
Message-ID: <b8d16cb57dc7ebfdcd0652eab030af4c6a3d0d63.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=clHCw6zN;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b8d16cb57dc7ebfdcd0652eab030af4c6a3d0d63.1755004923.git.maciej.wieczor-retman%40intel.com.
