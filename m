Return-Path: <kasan-dev+bncBAABBCO6STFQMGQEZLX4YSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 66F56D14590
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:27:39 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-3ec31d72794sf14935207fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:27:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238858; cv=pass;
        d=google.com; s=arc-20240605;
        b=H7hmMXIPNFU35SyWl2qkkOgS8lmqCb7jY40IrykWDG1UNbPncAJHpVdZVXTPaiMhnx
         lLCLVR3jZFxWzAlebf0UMi7Wlfrk+omnlttOSp8hiZWJ+Cz7kDvp4RU70bj0g/cg22ai
         DoLl7wMlC7u2XGxXJhmrWYs1W2ro8g0iKe6eLZUg18JYPDtB/xI7s15FPlCV+b3JPSVV
         xaDNtpopjeReqgRxD2vVl1RnLorWSdJT7K+EELPDLMul1TPOVD/FR1kRUtEkTZI2sv8V
         FZafNtuuuHoDRf6eWHtL8b8vMCulA+3TmJK/lv72bTntvV34kiMba9WWid4/5nOZLCU5
         ocxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=qOu7JmM5GYwWE13w5hVBdwXoTdwp6ysQtq/IzYqsVYA=;
        fh=byFVd3rNRftYtX4EYLhUtSDSgnc0W4gDAM3QmxNR7RE=;
        b=SQ1nfl/izFRoj7N1/3tyyNpyx4UJ8Et2yxNB+oU2cXgbg6ELnz7BC+iTEosyjKVp+C
         rRLXNQT6wknqBiu4R37dgp/jDivSOn2LcTy5smXoV6u4HPY+SjBk/+VtO9LJdh6Aw/4z
         IKi1qTN8wleXsZpH/bYSsBopoZLIEBMpR2FM4orhULV3mPvrexlsaisnapScLmJFCu1Y
         pcIDvfEjbomFKIlAfPgSDfL9QrW3aTkAricYrD5Xppcp6PPKPzTN+erivHbXUyBHa2jE
         eGP7qAGRTcZueebxG7tuvuBGoVNVkFnnjtHoSBBmTVl3NVAYffnOOUFs9QeOxJ9Vu4zo
         m9NQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=eXbCNbAs;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238858; x=1768843658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=qOu7JmM5GYwWE13w5hVBdwXoTdwp6ysQtq/IzYqsVYA=;
        b=AEruwURi27J7K0alJ6Lg7tsUSwlo+bMUBhoVIYHGahMXfhDG1yrCOGwFt43mXVAl9z
         gmGgyvCSPiuydaa79HD637rMHh/es27M9E2dtl9LlbR45EG9N+nw289zIa56nOWFURyz
         IjCgGYhUJ7jDxv3HPh6J0KMDwfyvb2zBHPbsWLUp2KKg8uSnmIldNDyMZ9Wh7OL3ySu2
         xaOajngGFl9uFIq4DzEm7Uhu7/HoYo9eAZYAi0XWVxibKmZXWoqrC/PZ4H0NG/xLXm+X
         Bv0ucG1gsMMuMVcNDQJiwnRhCvqJGZMFSOKyAd2v54PJSylMRL0MQ8BdOVMvRkAXIKu+
         z0hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238858; x=1768843658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qOu7JmM5GYwWE13w5hVBdwXoTdwp6ysQtq/IzYqsVYA=;
        b=VxODkCrsDgg0TznXpoad6kAks6zbKc9mvZUwf6dWfO7re5w3/F2F/ssyrdad3xDZ9B
         TS6VlCJ8HMvyd7cKxVRzWCV9SqeewTzSIYaF2PqdN4T+hgm3b4pfmpzsRApIG54QUG8M
         1GgipNtihk8EZE0UMQfn7ktPCYiqrz647traTopmWyZZDbVYBpx/b9Dmt0JJ4pEo4HzC
         O251MCVaAw+VIXeLcHyfuU/IdBgrQ93flbGn6pn2XzIydM1TS5nHvsF5/wwYqGPxRe9r
         /MQNCInrBd1DqUVu1uLBN7MtnQuj4lad65i+bf9X4uNYR2j1lUHmtiACrSgqGWi7WexM
         /w+w==
X-Forwarded-Encrypted: i=2; AJvYcCV/601LHAe3K6wyOTfR9F+WkA0vubZPPPoxGncIDyex8GDmFC8reM2DyW6rdv4eMT9LRPy5sw==@lfdr.de
X-Gm-Message-State: AOJu0YwzKp9EStx7I7nB4G3vey7QDZZq9DgtjQkGl3Q/CO/x3tJyUeVk
	vNYUhUxD0tnhOGspMJBLSr56sSO2P2YiFRK6Gw8nNhn6akDj0rjrk/mU
X-Google-Smtp-Source: AGHT+IFs+a9x8kzeoWNvew+mjvrpcDTKriSMQ+VW8Fjq/S1/XLMaPtDEq+rdvMmG+1EoUXKZTGl38g==
X-Received: by 2002:a05:6870:d886:b0:3ff:c029:d24c with SMTP id 586e51a60fabf-4006e494fe3mr105854fac.17.1768238857699;
        Mon, 12 Jan 2026 09:27:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fr/JHyt7e+aIbC79bOQ3nc1Ox4KmretixCn1vqRKbHPg=="
Received: by 2002:a05:6871:c94a:b0:3f9:f658:fe8 with SMTP id
 586e51a60fabf-3ffc014e00dls1992379fac.1.-pod-prod-00-us; Mon, 12 Jan 2026
 09:27:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXr5ckgx3Hc5uA8eB4XunkSsdXc1klJ9+kQx2erxYNYJaPj6tq0VSTxJCt+XoZUQJu0ReynafbgvVU=@googlegroups.com
X-Received: by 2002:a05:6870:4686:b0:3ec:7947:33ac with SMTP id 586e51a60fabf-4006e4851ebmr87729fac.16.1768238856688;
        Mon, 12 Jan 2026 09:27:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238856; cv=none;
        d=google.com; s=arc-20240605;
        b=SG+4YT9WvwltPK0MpcnyzMJtwr1/cuHQ1ijDbYEZCuZ/3aOb+u1Y3nTQSQaa2oQDfM
         uH3Ei5ykYutoIa+LxLpgrklkvF1zXGC+ExcwiZ++vxZBeiaz5C5Tqq/F+B1upHsO7ywB
         QqMMFo6kucLoFuCRk9rhUL1ZU2Hh7/JXE3NcvDNupFn8vTPNIka+bjH5+YD/WjNPojgu
         YtUwyQWMqt6YfeHgS/l/XUi+VyJZvkET+XBgytaww8yriKjsi7p+hEzUe5Sg6D6NDhsl
         7Bx7MJCFbJhI/T+e+s0o8XXyUSE25bd1YcphAu+MH+RLQN0gVDpKqvfZbQ5ut6p7NTa6
         r0vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=zYoTsocZClxknlYhcC3iOmUo2Nj+iM7h4tlwilxbfpM=;
        fh=uZZjx8zNTRhDZ822FZcs1jFprs7O36SIqgpEkngJLy0=;
        b=EWzP/2WZTMFexMWdX3VEu3JIEIALcE51t/R/nMW8/1lRVZHNsVpNwpvLjAnG25iPaY
         4Lr8FsaKQOB/XETiBo1bUnINYB9gtwQ8fTfunPjFjCgyX0ybHMdkMXMJfPDsqfUrY2aw
         7fYOTwnabMV3nxkHtE18WwTuz5vK/9+lpqbCx8UGqrTJbqLlJ53f5T9zi2VyDlrPzEV9
         vulXHgMRFxdcsQEq5lscPq0NV35e2ZuUWSR1ZQuR98rU7/ujN027QkBt/urButJVUBTE
         +So8hAzoiiESpsmeX4QQR+ForW42p4Cl1n21T1aL81tgtD8uAdsanjTPdpR+bakqATAE
         bNYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=eXbCNbAs;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3ffa689cb6bsi602968fac.0.2026.01.12.09.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:27:36 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Mon, 12 Jan 2026 17:27:29 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: [PATCH v8 02/14] kasan: arm64: x86: Make special tags arch specific
Message-ID: <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: f03de1003023037700aab2cb9b05c2dac6dc7c44
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=eXbCNbAs;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Samuel Holland <samuel.holland@sifive.com>

KASAN's tag-based mode defines multiple special tag values. They're
reserved for:
- Native kernel value. On arm64 it's 0xFF and it causes an early return
  in the tag checking function.
- Invalid value. 0xFE marks an area as freed / unallocated. It's also
  the value that is used to initialize regions of shadow memory.
- Min and max values. 0xFD is the highest value that can be randomly
  generated for a new tag. 0 is the minimal value with the exception of
  arm64's hardware mode where it is equal to 0xF0.

Metadata macro is also defined:
- Tag width equal to 8.

Tag-based mode on x86 is going to use 4 bit wide tags so all the above
values need to be changed accordingly.

Make tag width and native kernel tag arch specific for x86 and arm64.

Base the invalid tag value and the max value on the native kernel tag
since they follow the same pattern on both mentioned architectures.

Also generalize KASAN_SHADOW_INIT and 0xff used in various
page_kasan_tag* helpers.

Give KASAN_TAG_MIN the default value of zero, and move the special value
for hw_tags arm64 to its arch specific kasan-tags.h.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Will Deacon <will@kernel.org> (for the arm part)
---
Changelog v7:
- Reorder defines of arm64 tag width to prevent redefinition warnings.
- Remove KASAN_TAG_MASK so it's only defined in mmzone.h (Andrey
  Konovalov)
- Merge the 'support tag widths less than 8 bits' with this patch since
  they do similar things and overwrite each other. (Alexander)

Changelog v6:
- Add hardware tags KASAN_TAG_WIDTH value to the arm64 arch file.
- Keep KASAN_TAG_MASK in the mmzone.h.
- Remove ifndef from KASAN_SHADOW_INIT.

Changelog v5:
- Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
  mode case.

Changelog v4:
- Move KASAN_TAG_MASK to kasan-tags.h.

Changelog v2:
- Remove risc-v from the patch.

 MAINTAINERS                         |  2 +-
 arch/arm64/include/asm/kasan-tags.h | 14 ++++++++++++++
 arch/arm64/include/asm/kasan.h      |  2 --
 arch/arm64/include/asm/uaccess.h    |  1 +
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 19 ++++++++++++++-----
 include/linux/kasan.h               |  3 +--
 include/linux/mm.h                  |  6 +++---
 include/linux/page-flags-layout.h   |  9 +--------
 9 files changed, 44 insertions(+), 21 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index 0d044a58cbfe..84fdf497a97c 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13581,7 +13581,7 @@ L:	kasan-dev@googlegroups.com
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
index 000000000000..259952677443
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
+#define KASAN_TAG_WIDTH		4
+#else
+#define KASAN_TAG_WIDTH		8
+#endif
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b167e9d3da91..fd4a8557d736 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,6 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 6490930deef8..ccd41a39e3a1 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
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
index 4f85f562512c..ad5c11950233 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,22 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#include <asm/kasan-tags.h>
+#endif
+
+#ifndef KASAN_TAG_WIDTH
+#define KASAN_TAG_WIDTH		0
+#endif
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 0f65e88cc3f6..1c7acdb5f297 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,8 +40,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-/* This matches KASAN_TAG_INVALID. */
-#define KASAN_SHADOW_INIT 0xFE
+#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 6f959d8ca4b4..8ba91f38a794 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1949,7 +1949,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags.f >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1962,7 +1962,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags.f);
 	do {
 		flags = old_flags;
@@ -1981,7 +1981,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman%40pm.me.
