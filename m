Return-Path: <kasan-dev+bncBCMMDDFSWYCBBYE7RG6QMGQEWXLFJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 50502A27888
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:35:35 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-21661949f23sf194599735ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:35:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690529; cv=pass;
        d=google.com; s=arc-20240605;
        b=FeOHyyK2z1OYwB4e+e9Gc/hguVUTNhvPXBlRoF1MEOJZqIYtZY3GlQJ6g3bo5Xircr
         psyIDTuKhYeoJOH9HKjGr3veXp2bwYcx32z/YlGZ08cZPcoDQCgFLBfro6pW7QQczS1j
         cEz3Mlcp7kacfVSEklIDQ+M8TzPrqmwFj1nlmm3E9mR/8+7rB5OPQ2t/UTVaUYvxKGDk
         +0v5HQDpSaGDVVjVUbSGQrpO8dpYSuLZpkX1mhLrGQcH8UeEihB8x8d0SnZsK/IjFdIZ
         JZ452ai8Akzqn0XNjDn0BXIzQRmoKig0Dge6qXKfAZuUC/h8GmzvmCZe91K+XEkOxeW5
         /BRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0dbKg3mzUmr2bJI/9YSO8vuZsJa0emWyqefO36fxDig=;
        fh=eOsiymQhEpMjSD4lkzA00AH1BKK0Jm6qjsFd4mA0EuM=;
        b=fTIv/qQIIG1c81yfm6FWYyQBhaPhe3AAGc5vulmZKTXb4I1y18PPUDXRzglZl2O/dJ
         aFEPEKPZ6uHo/AMHnRHcauJMvOCBFzP1w6VaRy3sP+Az8wUg9QU8bI31guBa42ZR7gR+
         3layPqhCelQLFFE4shdwYlw2J+km0nF8AkQIaF5xLeyrtX/oAUqJ+IeUtpEUwTlPHj2j
         ViFaMGdGSzPpyq/20yV16OVKzqm2pwk7a/dWI2B9PKQpH+kmlz7cJjP3XjGmPm6Ct6w9
         XeXaTEwHNu8LQxYp2rfpxLHpROHJnKORToUl5qojJVillIxI8PGFpqabFH/7+TSwlj6l
         pAiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mpFAEIXA;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690529; x=1739295329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0dbKg3mzUmr2bJI/9YSO8vuZsJa0emWyqefO36fxDig=;
        b=aEzQPX2Vhc2wb9w79UdMEPUD5QhE+6l6oLEyp5QhfPbdNIGxYTzSCoHO4MvHnaVeUR
         RQkbfUQj1yOkQ1rkrXe72wVJ3mb28OPK6ci2drNMe0W0VEVOIU6NrcoBj9hCNj2OsKlK
         WkjGB3GUpSGwGROqmsSFGnIVv7ipUoTCG3wPqZGGPyDBGhyYLjo12fNsPcr9/OW8L4Q4
         2B6QImzxtCxKehDU/7bMAOffVL6iU5/FtrqSaLG8UH7/0QJTmjxk60nNDUcdiIzTpOWg
         rl2mOnvD82UZ9Fz63jg1C2aIHARTgLf+b2byHFDW/WTk7Nhq8r8Cl4xyLPdx9ZnFdO9n
         CJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690529; x=1739295329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0dbKg3mzUmr2bJI/9YSO8vuZsJa0emWyqefO36fxDig=;
        b=rEQs0m9OKACH+qRZp6yJBdsOlGVfZwAh2M/B6EX71oLbm7hPyk2NrubXWNb0qhlrHp
         ULPlyrRkC37g/lXJBPNJxzNzIetiNrBOmnneX8TRvbMZImFFLoud5uV/xThNoOFpPwY5
         ZRAcHcPtapyOaIEl24Zv2zOYCCxv5fT3e9hMbnVxHsRldM8hii9MVm8PW8nluH7TySf4
         HW09F1kp+ktm6gh8nMWWXd1x/pYkpACE/Qz2Siju0hvebp7LDGd7kcBC6zGEgnScgXse
         9KBD+Ms/JQ5BMpKamA+fqDJz2lahzAE4ltwkZBP26v/3PHN1Crl+i5rOJMtI0DjGzkPS
         7ehw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUh54bZEnoiDDuDd+cbW5FkolzEMqR+dDOPHCAqWtj1v18q2bIt9LnT8E03JzfAgC3DA5DMuA==@lfdr.de
X-Gm-Message-State: AOJu0Yw5Ufw3jrXzRbUgw5MzozTauQWQ1RwMNLLnIVskjcRbtxOZJWnG
	D3bqrfaAgJ/4oiD6wbg95Kl35OR9Jsp2fcTey/QQ2yJrJJnpjX72
X-Google-Smtp-Source: AGHT+IH1Oxs97nA5DMT3qwYaMe8vZ6WTJgCsLzBNfeph8ac/VK9eWjJAwjpd5oDvfcP0vxJy9cDr5Q==
X-Received: by 2002:a17:903:166d:b0:215:b74c:d7ad with SMTP id d9443c01a7336-21dd7dcd00dmr427433885ad.36.1738690529026;
        Tue, 04 Feb 2025 09:35:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f68c:b0:216:59e6:95c4 with SMTP id
 d9443c01a7336-21f14fa56fbls1140295ad.0.-pod-prod-03-us; Tue, 04 Feb 2025
 09:35:28 -0800 (PST)
X-Received: by 2002:a17:902:e54e:b0:215:b058:28a5 with SMTP id d9443c01a7336-21dd7c6540fmr346451865ad.18.1738690527884;
        Tue, 04 Feb 2025 09:35:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690527; cv=none;
        d=google.com; s=arc-20240605;
        b=X8BvxsHNLi2fZzS/k/aI4Wpw77oemDsSm3FhWcaQRQVsHyVZoVxQQHwXtcE/Of8c0h
         fvD5GbU1X4iZAQUnd0uY9yWMlYmVAqjqv2WfqapLrM2D1+xLZThrdP99M6O5efr89zIL
         ule3EpDz6urIDlD61UiQ2JC+LwSTojhOuKTMj+XLhDLKnolBjhho4b25pIaanOz5x/X8
         hY9Frg0JE/b2q7lSCMYiFggpofWaoZZgGXVKdwRvcGRLpS3TbZzl/w5vKNKdF/6FPf8S
         7g/0YpuvQBuX9K6n+PWLN578kBwV1p2cvPzkXCTtUyyljPNqIp0/2TyvkXqeX9cYNG7L
         7NHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NvaRO4UHPd/bOrfuOO4NoEzfTdAiR2iNdaeHPrh09jo=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=cb5xcoNeKb/bKhHTozkg7RVO1EzwVecUFtRfePd6nMwdZMovOquNNYJHFRQ4hNAvT2
         hT178FTLemqXsg+soJakvS6FaSNeCmxi8vLJBajg+fov5AXeUBPJgIc0AKWmCxOa+nol
         bF+jdAS+y1SLDoWO/SR74hq6u5/t2FfeF8ifWtzlnB/CWXMlf7ban6YXxWdYYCbrfSpo
         p30I41ppw/5xdg2tfqON04PSJId3wxj4DYoWr3TuhOZGtbaOUtFdHQj2GeFPsdcjDStl
         nITSqYk4S2chBNIZOkHfPUd2N1C74RJL9STZkWtaodZCnjLXNW0w/ORu+4jjE+tNWEyu
         QahQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mpFAEIXA;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21de32e5132si4345355ad.6.2025.02.04.09.35.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:35:27 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: sI+R7GsTRnuYdtB/4aIhJw==
X-CSE-MsgGUID: e//6lvneTXyOv9Rf1pHqrQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930498"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930498"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:25 -0800
X-CSE-ConnectionGUID: /sEOqI4kSuqYrX4FgQuozA==
X-CSE-MsgGUID: zBO7dwN1RyyrRSQp4bH21Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866447"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:14 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: luto@kernel.org,
	xin@zytor.com,
	kirill.shutemov@linux.intel.com,
	palmer@dabbelt.com,
	tj@kernel.org,
	andreyknvl@gmail.com,
	brgerst@gmail.com,
	ardb@kernel.org,
	dave.hansen@linux.intel.com,
	jgross@suse.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	arnd@arndb.de,
	corbet@lwn.net,
	maciej.wieczor-retman@intel.com,
	dvyukov@google.com,
	richard.weiyang@gmail.com,
	ytcoode@gmail.com,
	tglx@linutronix.de,
	hpa@zytor.com,
	seanjc@google.com,
	paul.walmsley@sifive.com,
	aou@eecs.berkeley.edu,
	justinstitt@google.com,
	jason.andryuk@amd.com,
	glider@google.com,
	ubizjak@gmail.com,
	jannh@google.com,
	bhe@redhat.com,
	vincenzo.frascino@arm.com,
	rafael.j.wysocki@intel.com,
	ndesaulniers@google.com,
	mingo@redhat.com,
	catalin.marinas@arm.com,
	junichi.nomura@nec.com,
	nathan@kernel.org,
	ryabinin.a.a@gmail.com,
	dennis@kernel.org,
	bp@alien8.de,
	kevinloughlin@google.com,
	morbo@google.com,
	dan.j.williams@intel.com,
	julian.stecklina@cyberus-technology.de,
	peterz@infradead.org,
	cl@linux.com,
	kees@kernel.org
Cc: kasan-dev@googlegroups.com,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org
Subject: [PATCH 04/15] kasan: arm64: x86: risc-v: Make special tags arch specific
Date: Tue,  4 Feb 2025 18:33:45 +0100
Message-ID: <cdb119dcade0cea25745c920aba8434c27e4c93b.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mpFAEIXA;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

Make tags arch specific for x86, risc-v and arm64. On x86 the values
just lose the top 4 bits.

Replace hardcoded kernel tag value and tag width with macros in KASAN's
non-arch specific code.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 MAINTAINERS                         |  2 +-
 arch/arm64/include/asm/kasan-tags.h |  9 +++++++++
 arch/riscv/include/asm/kasan-tags.h | 12 ++++++++++++
 arch/riscv/include/asm/kasan.h      |  4 ----
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 12 +++++++++++-
 include/linux/kasan.h               |  4 +++-
 include/linux/mm.h                  |  6 +++---
 include/linux/page-flags-layout.h   |  7 +------
 9 files changed, 49 insertions(+), 16 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/riscv/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index b878ddc99f94..45671faa3b6f 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12227,7 +12227,7 @@ L:	kasan-dev@googlegroups.com
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
index 000000000000..9e835da95f6b
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH 8
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/riscv/include/asm/kasan-tags.h b/arch/riscv/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..83d7dcc8af74
--- /dev/null
+++ b/arch/riscv/include/asm/kasan-tags.h
@@ -0,0 +1,12 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
+#endif
+
+#define KASAN_TAG_WIDTH 8
+
+#endif /* ASM_KASAN_TAGS_H */
+
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index f6b378ba936d..27938e0d5233 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -41,10 +41,6 @@
 
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
-#ifdef CONFIG_KASAN_SW_TAGS
-#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
-#endif
-
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
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
index e07c896f95d3..b4aacfa8709b 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,7 +2,17 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
-#include <asm/kasan.h>
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#include <asm/kasan-tags.h>
+#endif
+
+#ifdef CONFIG_KASAN_SW_TAGS_DENSE
+#define KASAN_TAG_WIDTH		4
+#endif
+
+#ifndef KASAN_TAG_WIDTH
+#define KASAN_TAG_WIDTH		0
+#endif
 
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5a3e9bec21c2..83146367170a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -88,7 +88,9 @@ static inline u8 kasan_get_shadow_tag(const void *addr)
 
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
index 61fff5d34ed5..ddca2f63a5f6 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1813,7 +1813,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1826,7 +1826,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags);
 	do {
 		flags = old_flags;
@@ -1845,7 +1845,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 7d79818dc065..ac3576f409ad 100644
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
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cdb119dcade0cea25745c920aba8434c27e4c93b.1738686764.git.maciej.wieczor-retman%40intel.com.
