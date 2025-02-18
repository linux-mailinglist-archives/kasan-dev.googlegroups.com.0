Return-Path: <kasan-dev+bncBCMMDDFSWYCBBLUE2G6QMGQEFTZZPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A303FA394E5
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:17:51 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-471fa9d2854sf18055181cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:17:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866670; cv=pass;
        d=google.com; s=arc-20240605;
        b=G3oi3DPW2kCXaaiHd3vPxQafjynVdVpa7TVCKVq1nkBxONUepeP+XWwtN29SlblvwK
         qB4gV991LHdVSwx77tKeYAXda3kjGAbMiaVMwPUC1Q85w449cC6O/nAjTCx8MInmCoJM
         6iEyU6/VhQWbu385C0LDrLl49aX2/h/ZRZ8YxBhUUN2C11JP+RNNeP3pFK59n9+YbtP0
         kseWTqI2KusotJ/Ko+XslXoyJkgckzXsAgj+svLDeZeE7x6S9o2iRtQ1DYopOsyApYgv
         bcP8FBLWpI28bqKksbjpp/nZdB5qtOb3vgLadgNZpupovzfznjwAK1MJwP4uQpC7fw5x
         Jw6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yO3b9SSo6m84oLoq7GEuYxDXGbVVn0c0Xgw2jFkldf8=;
        fh=G63sUnUGt0FfFO0acVOqxufxJe6EtdkZYAUvsbP/No4=;
        b=aUzXG5dpa9YOpmWzhjY84LfOlNSJ1iOeEnJm7ZCczs4Eyf164isyhUuzzdc/HDSI0Y
         CuGYHKonQK2m4JtXjFRyLIIJEXGTvrTbwUgPwcB+IUKz7O+pqt/WrHdjWl25ja6Da1hW
         8u/pdao8xYj5RoNdJwfTbDZ13Fk++SBrVYClprh4veKp2rhAnnEKF+kCyj3ODpYmVYcs
         SrvfQ3zb0/npyZtfPH6gpMsQem5gyKBkPprMZatKDjKp8daTG6xKkNX3svfOA5JKN3Sx
         YQlB1Lcd+86P0IsDyKNb0WqzhIfLnPlIcF2gJk0Enm9N9XAUxJ4Qkb16tRN4hMzorx1T
         HRiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WiUjdQKc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866670; x=1740471470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yO3b9SSo6m84oLoq7GEuYxDXGbVVn0c0Xgw2jFkldf8=;
        b=JWarSc5arEXqAyqfVQxCVsME9LGG6BXiNC0hWXdlZgGveJg3FmtEROVy+lpj/9qfEE
         Y4Giq0w944r7luyvexOH0rjbKudPPiQcLA/XsEpOSmqBiIC7a+fDl7rVQjLxkU+gQ8G/
         lrN8oNpaW42x6iCQJynJVLcoy3/HBr7ZjAKxr6sbdi8gXTiLO2TaYAVXYQa3KrHTCFLR
         XjjbVX9aRFRs7xFCsJ0J63lQz+CPDaIsmkpkpfVMOfIMevLqIAgmkZzGoiDygAx8Yuyy
         94zOCjbmVUhDBEGk1WSZwaIYE7zJ9zpS37YInMHJe6wYQxj2P57twYQeLlNRzoL6StFu
         DerA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866670; x=1740471470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yO3b9SSo6m84oLoq7GEuYxDXGbVVn0c0Xgw2jFkldf8=;
        b=cxhHcekr3FchPL7vGM/5vBz9FkxJ0Int49QAqGLZkehxfbaNmLBNdBYF7w2RIELv0O
         5ANe2F8ibXB3VOh71ZcsvpHigjdhcTuavFr6QUsK5RurOaHJl8kZsjFwvmcQdEeGoIBG
         wVhrN/5zbzPdCovAuYyqEIGlys/K/Vnfikhe+uWF38t+dVBYdTNZqDwgz/XQnse7+Qpd
         B82ruAF6EZ41u+pSUgwgiFgO677yhAwxsKZtlw3w5oPNkI2pzBvUWeqAfBgPkPaMxjOw
         Lgl3XZ5OEarcqL4g6vfuBjEqWgYiaWQnVE1iH4mBI+pHGzLuBbzszYB92+y93/smcnSd
         fBQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWclEtKYvjyJjUu2hw6PPgnRYLIGdP5o0ltiB4w7/Vk2j3hY8ICP9atWwu3eVaKCscZZvzLGA==@lfdr.de
X-Gm-Message-State: AOJu0Yy5PaERbb/k6X0jgP9vFtSpzW/8M0gJCmZnZYmVyxHGu15hxwFy
	X/gMOWeF2A/sRIiz7K48RSx4JJ3rMb0yQdXcTeghZw1AbtU34jpm
X-Google-Smtp-Source: AGHT+IFkVTfhOzLWH4ZjbRch2US3PPb3JrcbPnLJ+f+Oru+OUt1Q5FCpr07ShEKIllN+oNgpLeQTng==
X-Received: by 2002:a05:622a:28a:b0:467:6ae2:75cd with SMTP id d75a77b69052e-471dbd1417emr174586521cf.20.1739866670563;
        Tue, 18 Feb 2025 00:17:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHrNW0ZErOppb9PO7atCV///miiWxP/+Vzk4GYZtOZ6kg==
Received: by 2002:ac8:5e4e:0:b0:466:9e59:9807 with SMTP id d75a77b69052e-471bf242e92ls63954861cf.1.-pod-prod-05-us;
 Tue, 18 Feb 2025 00:17:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZQBGnqsPAiFDNImrikG9QleFOdTr3KEceTCFaMvJbLaP0aY8SCthwo/29q/ngXpx9IF5N02BLBHA=@googlegroups.com
X-Received: by 2002:a05:620a:2942:b0:7c0:a46d:fa8d with SMTP id af79cd13be357-7c0a46dfb97mr623449285a.31.1739866669661;
        Tue, 18 Feb 2025 00:17:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866669; cv=none;
        d=google.com; s=arc-20240605;
        b=kIaUGtjzpqN2t4yqiqn3x2q1ucbIg5zhKuNfoFlQSW70OkbWIaDMNjqAnvDxSiSskk
         G3NBlmFhjSIOuqHcpOelJoDAeZz14fU5BE4RsyCqpDHdRzwm/hDE3CtpAerNl56tCtJa
         B4BchLTxWWlouNTXXIw1r/Kbbuqo2aM4Yu/r7RgjrybNdDpBYgaMSB8PVs6pL4buYWZk
         0/ABq6YItHL1edRn3HJBH0sauzSQfLRDl5vm7qnuk8ARgUgtx7fr3RUKSxTvIW0I+xnT
         apFKUE4MRMFkMYv8n55vSk/JnKjNsx6UyWkK+Y8raRpC/9sTxLJ0EBBUOh6KLwYJm+br
         HLJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yp9z/72mv2QLx/Ef/ffuZlQr1HZnsXUELIZaKdEAc8I=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=YVpYP7kyZw6I25xawwBonyQzI9BXbt0JkPtg007cLZ/VdRjKYihgsPKD7nh/oIjBXG
         CXrUIUchcW8FumLkkZirSALIG0cZD/d4BV5hNy6z0QqL9BwU4ESQMwXgCgIsEyu9xo8g
         fMfetnprCXoSzbflw8KkgFw1XKJhp5dBiG2bLUL7IujkQ/Ksk/ltsPXJFr/HIYoXeulk
         XDvFEgnv0X1CWCx+h9ErIdyIEQLeyUJFyAK3PZBe9dXBvP2B+Y4o5Du7jSHrUB0mNIoC
         nQow2kvnHHASqXG/fvU0w1VPLeSwHgLAlh5SBsRFiwfSeElonZ1WpYQm/8Ur4fVHoQXz
         8DZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=WiUjdQKc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c0a80886absi7317985a.0.2025.02.18.00.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:17:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: oAmqRH79SiO+C7swLOOk6w==
X-CSE-MsgGUID: rIpdWnYcTCGRbkb/0tVfNA==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150179"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150179"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:48 -0800
X-CSE-ConnectionGUID: PLYcFuuUTMCNDg97bomtmQ==
X-CSE-MsgGUID: IjcorwQURzO8cEIwpFujCA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247610"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:28 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 05/14] kasan: arm64: x86: Make special tags arch specific
Date: Tue, 18 Feb 2025 09:15:21 +0100
Message-ID: <e1cffdd3ec7aac6c047650141ba3be96888cb817.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=WiUjdQKc;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
index 896a307fa065..37971952c24b 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12478,7 +12478,7 @@ L:	kasan-dev@googlegroups.com
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
index 7b1068ddcbb7..0b1d21864294 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1824,7 +1824,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1837,7 +1837,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags);
 	do {
 		flags = old_flags;
@@ -1856,7 +1856,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
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
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e1cffdd3ec7aac6c047650141ba3be96888cb817.1739866028.git.maciej.wieczor-retman%40intel.com.
