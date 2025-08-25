Return-Path: <kasan-dev+bncBCMMDDFSWYCBBKMOWPCQMGQEZTZ2F5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C5DEB34BC3
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:27:23 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-71d4cc7fa4fsf97232897b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153642; cv=pass;
        d=google.com; s=arc-20240605;
        b=iEMzJxbHTHwlD+d1PORnxmnuf6ZiVfbpzliBJH0CufMs5iYqES2UxGp49P4DQ7aURe
         oBuf+BXBr8Avijtui+r0k0yMIfQQUFLII6xsfJO0v4C1slUq3k/CvpQzt5fHzKByS5V1
         FNknVT4GEkN99d/dpzt98TMeKGJoLiv0I1k9RFt0Yp/iXaj/lWoAUknh8zaLB7D3jRdN
         CmyKihIwxpB14mdP4Wjo1vElO361OcSx6cV41HBV+359hkos34rXMY8FvNRfKF1c8TdZ
         Y7aGkr4OzaVDyVeFtb1N2VWvybnqMir4WDHB1x7bxXft9zNvkJ8aTtTyfibz5i1ezvZR
         j34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mMJ+wmvLPiJU9G75z5c1BHgS14J4oWb5zy3JsIpttq4=;
        fh=0vNey67z0Lu0IsuqJDCoZWcO1gBRhsGc9OCsJAGCQjM=;
        b=keYhPwhgiP1ulF95khPQUfd74Dy8duxNFwq/dyoPJn9G0B9XsI1hYOhEfX1KhvPXsd
         DDkWOo5gG+IXp8cjRo6QyiuJ47KlPeypJTkaJjDfb3SbDBjAxNEJLOYXhJ6kmeMdwQma
         5M/g3FQco6hE1eBjgqZrGNuWw2cyXzgcXrDlW5je0ecvMa+BZPPktnEPoXeb/YxGcgH9
         Eq2Dv1d4uS5qoyNcdeurzROY2jmCaAwmDEHE+CaUUJu8wm+Z8C4zRBRZBAImUyUg9JUf
         XKSeWocjp8FriMwLN1voSbDUrMibB4MFeBf1YtGJwmm3YRpogXReRfvVVh9pqMAX0BCZ
         KX/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JxZpDelG;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153642; x=1756758442; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mMJ+wmvLPiJU9G75z5c1BHgS14J4oWb5zy3JsIpttq4=;
        b=hwuJWhrbA+K3kcHZ0VAvtypSgsaOTY/gkExyKTir7qwkAzQW+DxvAIzqhWxALZ6zCz
         B8OAIqh4jnVAcpmpsYG7b/CtT53FguDo5nfb4foFE6pOTSU7ZLyJeYJQKE7D9a1F1kBT
         m8dkNG4xW8zxSkosqEuiMTJXrrzAHH34km+8z0UQqfvxTjxEtHN+WFrXQ1udA+gNxexj
         k6lXI5Q2bGJvHvyRDp6Yw8/TpXcAoYpd9UUxm3PJKNyiBU2KEGN+ZjsGAS8M//vwGgKU
         EH81rjNE735Ph8xZrXMp+mExuy4VP0Oj7n0SqOz8LOnnLUOyhlbym9vrpVr56USaWrp9
         K3cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153642; x=1756758442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mMJ+wmvLPiJU9G75z5c1BHgS14J4oWb5zy3JsIpttq4=;
        b=JUuVMSukFHyNYJCuTTBpJuzPfV0RxWIeGxWLB8TlSrechfCuIbckpm9sAFc6fkMDdr
         08WZ172TJc+LKXk5mThfzq050knxwJ5t8+CGcDmWBhGS0lBl6P1wmCziIJIF7Uf8R1Tc
         4s+8eA5QJNf9Fi4NNB+jgzMqSMi2M0XjWk9XcYjyjNVTnOHoKdMZC84xe9rtN8szGJSf
         zCHiRq9Na7yDdyfotrUQu06mFLQa2Ih2pBHYmC60R2coYOfr2CeYFnwnL2QSJKrSX+l8
         2pI+BG+4bBwwK+I4yCtY2/jldeX9HqIxu03cQHqNVUOPBoX4f0VVGHKZ6+qzrC6JnrIQ
         PbaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPRHfRCGlrBjQ8TEHMrm1tRF3BcPUl/2Kk12fmuBiFMrBAPtQfxjPpBhH1hTlK7GLkhV6VDw==@lfdr.de
X-Gm-Message-State: AOJu0YzqI9StlH2+tDSznm/N6CZ2E8HJV3Qa9UK1b631ZG+Wg9SSQoOv
	P/+bzQuON/OIGMHhanO6j0QZyZWI1BUE+40C0GqzvF0tInaIJq2D4gJO
X-Google-Smtp-Source: AGHT+IGx9wQqAyKSVvbjXOYqD/1rgTka0qPTCFfyt5hDtjg8oGrJifIrDtf6cCpWJI/2EGJWnh1CmA==
X-Received: by 2002:a05:6902:1888:b0:e93:2a56:543e with SMTP id 3f1490d57ef6-e96dbc2cde6mr1036075276.4.1756153641702;
        Mon, 25 Aug 2025 13:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeUglq9q4AY+IFn2YhshoET/0ZGGGFRiG/yi0U2z90eZA==
Received: by 2002:a25:c384:0:b0:e95:3ad1:9e01 with SMTP id 3f1490d57ef6-e953ad1a0fcls703550276.1.-pod-prod-00-us-canary;
 Mon, 25 Aug 2025 13:27:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvguBnl5eOtnjsXrsXbycq89coKZMH+xCbIDmZmKFmWxVBRtzU72ysdySSJ7kMcipzMh60vrGGW60=@googlegroups.com
X-Received: by 2002:a05:690c:4b0b:b0:720:58e:fadc with SMTP id 00721157ae682-72126968195mr12175537b3.4.1756153640839;
        Mon, 25 Aug 2025 13:27:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153640; cv=none;
        d=google.com; s=arc-20240605;
        b=UZLTfv5kpQiI26h9gTinwdLXr7I1lKhW4yOSxcB/mGuwSfQasO1QjPqBkRFVzdHIx6
         SnrjCuQcVpVC2PvVmu8eXV3omQLxzE3sDaTpTT8XeweqALVVnqn7n2E4TE/mnke9PoQ/
         AAos0boP1/ACdBiyg98MS9blGM9PtpAVLuOtb3uFpvgL7qZeS09JW5wFELR6VBgogao2
         Q6Lqzqc6nJkT4SALywrKoDrr1HF1pSoJimEGhja9EMjW6y3QpZWTdtrI9kNvZ2zJ5+iU
         el5HczxTodAR4fSCNrtUDXg+uur/Y27cHwGMDZupgnsHRwy4f0xkdUuP1E+dxqzrF+/O
         WYBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=siX9X8C1ebWNpAl8jAmF0YHWnm6v4zSBKwYpTwwyAIU=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=diAGJ52fSr9icKATa881TwoAeLHVsH9p0eImFYMiy1aHAEAfdoafGvcYUzX0BkH9/x
         PW3FBbi/HEfGhDatCOc0xyZeDcnslahMY5/sZOajSZw2mZrGDIhZmOjPDK2ma4NyPbou
         8oF6Gb54Q1e0Rp4Ttlg36KpswrcgEEd3R2sbhFw/Hhz15bxty/6FNDJJOcimB997nRgC
         hZPKilwiCglqG2dKmR3PnKhBZp7gt80/WcQKt5tfn697PDE4oreF3h11VEXRhdfETsbS
         mCj8Tu/sHoPZ+uG615xdni09zr8+zqwJz6vrsm7O+okinGziTD2aYV8pzxIdfxZiMlrt
         fiow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JxZpDelG;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72123c5c91fsi534607b3.3.2025.08.25.13.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:27:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: aLZTX4ssQ/m2xizrqoFKSQ==
X-CSE-MsgGUID: LshJZFXOSD2lAt6Mv7dkBw==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970447"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970447"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:19 -0700
X-CSE-ConnectionGUID: aQ202IPqRcWU0JmqPLmwhQ==
X-CSE-MsgGUID: fhmF8QYeQ8GO7LAXlViwDA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780311"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:57 -0700
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
Subject: [PATCH v5 05/19] kasan: arm64: x86: Make special tags arch specific
Date: Mon, 25 Aug 2025 22:24:30 +0200
Message-ID: <7a85ceb0918c6b204078e6d479b85fef6a6c1768.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JxZpDelG;       spf=pass
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
Changelog v5:
- Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
  mode case.

Changelog v4:
- Move KASAN_TAG_MASK to kasan-tags.h.

Changelog v2:
- Remove risc-v from the patch.

 MAINTAINERS                         |  2 +-
 arch/arm64/include/asm/kasan-tags.h | 13 +++++++++++++
 arch/arm64/include/asm/kasan.h      |  4 ----
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 10 +++++++++-
 include/linux/kasan.h               |  4 +++-
 include/linux/mm.h                  |  6 +++---
 include/linux/mmzone.h              |  1 -
 include/linux/page-flags-layout.h   |  9 +--------
 9 files changed, 39 insertions(+), 19 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index fed6cd812d79..788532771832 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13176,7 +13176,7 @@ L:	kasan-dev@googlegroups.com
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
index 000000000000..152465d03508
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,13 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		8
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
+#endif
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index 4ab419df8b93..d2841e0fb908 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -7,10 +7,6 @@
 #include <linux/linkage.h>
 #include <asm/memory.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
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
index e07c896f95d3..fe80fa8f3315 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,7 +2,15 @@
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
+
+#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
 
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
index 1ae97a0b8ec7..bb494cb1d5af 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1692,7 +1692,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1705,7 +1705,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags);
 	do {
 		flags = old_flags;
@@ -1724,7 +1724,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 0c5da9141983..c139fb3d862d 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1166,7 +1166,6 @@ static inline bool zone_is_empty(struct zone *zone)
 #define NODES_MASK		((1UL << NODES_WIDTH) - 1)
 #define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
 #define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
-#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
 #define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)
 
 static inline enum zone_type page_zonenum(const struct page *page)
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 760006b1c480..b2cc4cb870e0 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -3,6 +3,7 @@
 #define PAGE_FLAGS_LAYOUT_H
 
 #include <linux/numa.h>
+#include <linux/kasan-tags.h>
 #include <generated/bounds.h>
 
 /*
@@ -72,14 +73,6 @@
 #define NODE_NOT_IN_PAGE_FLAGS	1
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_TAG_WIDTH 8
-#elif defined(CONFIG_KASAN_HW_TAGS)
-#define KASAN_TAG_WIDTH 4
-#else
-#define KASAN_TAG_WIDTH 0
-#endif
-
 #ifdef CONFIG_NUMA_BALANCING
 #define LAST__PID_SHIFT 8
 #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7a85ceb0918c6b204078e6d479b85fef6a6c1768.1756151769.git.maciej.wieczor-retman%40intel.com.
