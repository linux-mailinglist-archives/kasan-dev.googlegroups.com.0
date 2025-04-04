Return-Path: <kasan-dev+bncBCMMDDFSWYCBBBNXX67QMGQEUKIS3IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A4AF3A7BD63
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:15:51 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d5b381656dsf46780655ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:15:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772550; cv=pass;
        d=google.com; s=arc-20240605;
        b=A0mnFd3+gF+rgI+RWmJilw8BSva7swAMZas9/tF1T6CNLn9/RjOkwgXJ+Ny/G8JvuH
         pEBR2eJ+i/EyIEMJ76UT9bjX6c4yaQ9V19Fzbjk86FwSGxQ1+7eq92roZUzu3zNw93aa
         WGsPlEcGnUPaar0auikX1Wg+MsL+bQpwBB+bihrvnVi+gu4PeRu7q1CmfiBAYC+uCC0s
         gZvlNtmrkZWN9Fkt6iM0xQ80pxQnwoNKyEumhaLHyWNSxnMiGrAbTOFT0+T8U9+b5PLI
         vpkkdHhUT1CeEg0rmeB54Z0CvXgpC/QiUhQm+aubvl8PF5eURZLk1S7+V1KagfWurM8W
         iKKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t5CYhEprkHnBfQqiglBZeGI0Age52BkqvH6HiSf1Uug=;
        fh=6qXf6y/R2npOhHCqzisqGvJGB2LcCnT7YKQD1DGzpeI=;
        b=gn8vJDwCHn9omVBYtyPi6fRqc7VRIifqHAngFOlq8GMkbuvIoz7Uhuwdm2BL6I395K
         Mb8ryb5YoRI40t7oYvAinoOvZLNXXEO88azeIEo5mOfWI3y3UK1bWngWtgPXf9wAKh6y
         ygs7v8qVuJ1oaADipwXK5KAFPH9xjsEDoHtywF3y5o7Rl2YBaI3su0MIx+ItXTnHM+US
         mt5hGEk5S6n3NGOXzPbvvoRd9xiKX/2UN4T1KFVJL1kahBDdDzcwgf+ORkeFd3X9jsBO
         nnuMxqauhZQh0Ih7vHVYTAGmaqQhLbOSPafbu3HT9tPu5HYciTnj8GWwFWqaS0zNsn5K
         pVDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GmbHFPxc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772550; x=1744377350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t5CYhEprkHnBfQqiglBZeGI0Age52BkqvH6HiSf1Uug=;
        b=MKVa2K7dsjjYbSrT4QMHwr62aNqPCjFVy32N6vchftOZb/fJ3KkJeFYOJD6UOR794B
         8VRpSElDYXr4lvHzeMHr6NHYVCpP6CtP2TdS4hCwOaTSWk3p2d17DguiuvqoMH76aAIA
         Cw+9wlzdcR1G8HgFO8RFdJQbpNRSi+0i3R1d5jDZRR4G4ZO6PsvS9uKQyMetDZOlh59H
         NiyWP3jDOjnEPjMMuSaZgGD/lRK1lc0Xifw4EqhnQ3KPhmAkVjJkf079cPVVEph3pv67
         xqGGOMgjuVaA7jsZg1gpbfScSUEBi4jtubmBcKGwvfNszEVPLCMBtyApTb3lEG6+Z/lD
         kBhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772550; x=1744377350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t5CYhEprkHnBfQqiglBZeGI0Age52BkqvH6HiSf1Uug=;
        b=IcFYo1UZUH9U4luF9pqVpNIKmRUlgbijRS97Rgw0Asb/zsYqsyUEbsOzJkNe5mMl5B
         YS/hkQgmmuIN2G20DzwB/Ybt0caFmKCmIaN9+ApR5pc3GhIv5Sxp2GPlUlXf548xHx+3
         jwaWgze4cD888saWTHXGmiIQN1BvSVgmLCtRcr5Jxe3zaOh/1XurfGQAocIhzjZe5RVy
         tb3fnTQixy06PBWlwalj+25ssLBHwXYCtsjDEyaXgVgYfurCyDMAm8G6mhV2I4kDzFZi
         9WaTP2B8bo/bsbqKMd9a2zhVm7Zrg3dmshff3jEX5a4O/wwSawzYckDXQelYT9mN9QXQ
         BABw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbeJaCrk2gqeej+7lvjc8Vk9B+/x2N5Eb7CidqPldjW8ztH4sxavHzcI2r/ZUV/VD0AsYHDA==@lfdr.de
X-Gm-Message-State: AOJu0YzlnD3PerztzH/YorPAcAvxlAiUCJe2ONnqqZewDEhr/BML8B6i
	Od8z0HhvYM5yeSlzRTno1uS/y+Sy7wAuxxjkZTBm9QWr7jqiphCi
X-Google-Smtp-Source: AGHT+IE29yhiJLs3vXUIM/UffFQblq8RiX/1cSk+q/t+ZDQHHvTgk/DoQEriN4KjujEZTEFaDgee+A==
X-Received: by 2002:a05:6e02:1447:b0:3d2:aa73:7b65 with SMTP id e9e14a558f8ab-3d6e3f01668mr29519585ab.6.1743772550102;
        Fri, 04 Apr 2025 06:15:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL7RmUiNLaUw9XzRVPXo/3u/th1TV4wFJFXyoUgq8VYcQ==
Received: by 2002:a92:50b:0:b0:3d4:58a3:f62 with SMTP id e9e14a558f8ab-3d6dc8f15fdls32390805ab.0.-pod-prod-01-us;
 Fri, 04 Apr 2025 06:15:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVid9Ivs/Q8noQAl06TNuBTq9p8sc0LJ3bbbkFg1dOearCHSQhktToNu9iFtjZhJ9OrAdmR2Rsh6NM=@googlegroups.com
X-Received: by 2002:a05:6602:274b:b0:85b:5e8a:9fb1 with SMTP id ca18e2360f4ac-8611b4e058amr364209939f.10.1743772549342;
        Fri, 04 Apr 2025 06:15:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772549; cv=none;
        d=google.com; s=arc-20240605;
        b=lpDvEOWr0Do2c4wA6Zq8NY0vYIzltj3Gk+xbnX8mftz9xZgcQgvgVFLR0VXnccjaHF
         rFKXCeM3CkAsAVcqmVWETfsVR1GNHCjxboBlqEmsCDiR2NQZFsawWQG+reh8a76bSSTL
         Xn8IHCnw9foeTTf4t72rZUm82Bor2jQEn1WH+ZzWK+n3EyquoWFBA7rqxIE2Gtp5Z4HD
         SElX0UjR3lWHlxrEAGD5zyLC8am19Mv0C/yJss0A93jyDdIT0hN2eZd0zoxSdg1vFqlZ
         5PcuXKnKSw1mxZB5iGR1LgWSw6muo7n40Wr2m32zs1BWhs00JpFhTNBLcXfnjxjZtW/u
         aTAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1M+o1cDr/cejiJebPvpehZ/hYd9tAcNgHmEsRZx9DNY=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=MnleBKrKXDJoMxr/zxqViS+PBibnX2XLTISKeBe+RjDlAEnJvBujYxC6CWxkY061pH
         etZLdmU01tHP/gVyZDJNAq9xNaAj9HNgPEXExS4yO3CNimxj7aw7WJkVPHZ+RpZckXI8
         tOQWfAVdIhuGu8uQ97f0cUTzohwhq8lF1Up5UJoXhcQGmG4jO7j1CW2tMXxrURurOvP+
         bJwXiBHKMOxJAPxZ9pEnml/snu9OMRAH3xVYuFJv01m/da5RceETRLWir3ctkKeuISGS
         370q52lAllRr2JI0TnaDHudUgZcDv79FpQ9PLDEzwFH59FwCbUH5posjlsOFmDiSrs2n
         vqTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GmbHFPxc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5cff316si150996173.4.2025.04.04.06.15.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:15:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: BFlczNvmQJGZxstQ9wyA/g==
X-CSE-MsgGUID: QBHiD7i2Tq2MXWB13HTUsA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401669"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401669"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:47 -0700
X-CSE-ConnectionGUID: pzanETZmQhSdtpOzW63ogA==
X-CSE-MsgGUID: Fj7gxPnqRE6y35rxD0gliw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157039"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:32 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 04/14] kasan: arm64: x86: Make special tags arch specific
Date: Fri,  4 Apr 2025 15:14:08 +0200
Message-ID: <716de282b80fe47895ebc876885e31e344c676cc.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=GmbHFPxc;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

KASAN's tag-based mode defines multiple special tag values. They're
reserved for:
- Native kernel value. On arm64 it's 0xFF and it causes an early return
  in the tag checking function.
- Invalid value. 0xFE marks an area as freed / unallocated. It's also
  the value that is used to initialize regions of shadow memory.
- Max value. 0xFD is the highest value that can be randomly generated
  for a new tag.

Metadata macro is also defined:
- Tag width equal to 8.

Tag-based mode on x86 is going to use 4 bit wide tags so all the above
values need to be changed accordingly.

Make native kernel tag arch specific for x86 and arm64.

Replace hardcoded kernel tag value and tag width with macros in KASAN's
non-arch specific code.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Remove risc-v from the patch.

 MAINTAINERS                         | 2 +-
 arch/arm64/include/asm/kasan-tags.h | 9 +++++++++
 arch/x86/include/asm/kasan-tags.h   | 9 +++++++++
 include/linux/kasan-tags.h          | 8 +++++++-
 include/linux/kasan.h               | 4 +++-
 include/linux/mm.h                  | 6 +++---
 include/linux/page-flags-layout.h   | 7 +------
 7 files changed, 33 insertions(+), 12 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index d5dfb9186962..e6c0a6fff9f9 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12728,7 +12728,7 @@ L:	kasan-dev@googlegroups.com
 S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
-F:	arch/*/include/asm/*kasan.h
+F:	arch/*/include/asm/*kasan*.h
 F:	arch/*/mm/kasan_init*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..8cb12ebae57f
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		8
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..68ba385bc75c
--- /dev/null
+++ b/arch/x86/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		4
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index e07c896f95d3..ad5c11950233 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,7 +2,13 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
-#include <asm/kasan.h>
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#include <asm/kasan-tags.h>
+#endif
+
+#ifndef KASAN_TAG_WIDTH
+#define KASAN_TAG_WIDTH		0
+#endif
 
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b396feca714f..54481f8c30c5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,7 +40,9 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
 #ifdef CONFIG_KASAN_SW_TAGS
 /* This matches KASAN_TAG_INVALID. */
-#define KASAN_SHADOW_INIT 0xFE
+#ifndef KASAN_SHADOW_INIT
+#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
+#endif
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
diff --git a/include/linux/mm.h b/include/linux/mm.h
index beba5ba0fd97..610f6af6daf4 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1815,7 +1815,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1828,7 +1828,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags);
 	do {
 		flags = old_flags;
@@ -1847,7 +1847,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 4f5c9e979bb9..b2cc4cb870e0 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -3,6 +3,7 @@
 #define PAGE_FLAGS_LAYOUT_H
 
 #include <linux/numa.h>
+#include <linux/kasan-tags.h>
 #include <generated/bounds.h>
 
 /*
@@ -72,12 +73,6 @@
 #define NODE_NOT_IN_PAGE_FLAGS	1
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-#define KASAN_TAG_WIDTH 8
-#else
-#define KASAN_TAG_WIDTH 0
-#endif
-
 #ifdef CONFIG_NUMA_BALANCING
 #define LAST__PID_SHIFT 8
 #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/716de282b80fe47895ebc876885e31e344c676cc.1743772053.git.maciej.wieczor-retman%40intel.com.
