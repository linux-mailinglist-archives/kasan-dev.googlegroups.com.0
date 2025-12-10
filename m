Return-Path: <kasan-dev+bncBAABBVG343EQMGQEBP23WUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DA4DCB39F4
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:28:54 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-8b245c49d0csf22312285a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:28:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387733; cv=pass;
        d=google.com; s=arc-20240605;
        b=ev+QABb/nvyCo/9BIX5hkEYjCt5zgTm7ZIhw7dKCAvzIOPSYEryJOFwkSkw+6XO9cc
         n8V3WSQ06pUm8yBIh9PnfoU9XpFI11uby9ToQJTB4453MxAIGBB3cKnQHvXPBUDgGACa
         zNDZdaSrzC00q1/ZRUyPP0WyeNGdM8oxcOSmg+Wy6WJAL50nPerzSO5yyhgosAkOMXYr
         N93EwCkyCaQIoqrWL8UB3qoexEU0PmMT2tvfTLKRRmTEctrYPw5vaxC3s4txhw4j85wO
         I0/JKR992tfDSysDyjWBCYffoaZldSNm0K4GYcTlHQZJRffTh+GmZodSsB53jKDPokre
         8CqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=WcodwupXOLSb3cgnig4h1A3RySFZ+BXWrqqWexmE5vM=;
        fh=mZ+qbax/285aAjw1Xu1EoDTT+0soJzTxCCoQSw3NDZQ=;
        b=M4wSAytso3eCHNah9tWqGN9zgmE6TEvKF4ZDVT//roUMCIAzm4qD29B07M4ubRjgaq
         We9Za7Sgvm9KbbUk2SZpD/esuDDJpUaNtDFgNoBVI7v003aUgzQx5O0dapKKHiLnLOI1
         NsTR61PBiqGNWZSIdRgiBLeuxLpWDB7Zq6tfRNapmsu+InssEMfZwDO41OARvFmDLImE
         gU7wUcdfJUwCMi/JLAQcs3DX17mzWvseDe1QC7VcC+Gj0CtuplDsXS4bYxgSQaEfQaEe
         emJ0jCFzvJwENEqxbaSrG6dD9CF7u1bjRgTog9uVIiJ3PSc+9N2bxpdFbeZjS5DoreE2
         Ozcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=XQg25V1L;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387733; x=1765992533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=WcodwupXOLSb3cgnig4h1A3RySFZ+BXWrqqWexmE5vM=;
        b=p5D27OmN2K73poZhHfJrpC+pRqp9Ba4fFt4ZVF9BcwPohEtJW7JmNWbxvq/BaOWHNb
         VDUgjEzvotk0M3VMU9VaxiQQmt95Wj74v42ZndBijfcxk5rRg4IjIKYsatXPxtkZXHuZ
         9Un426bCDCbepvvddA02KusCCBhNLceEYmW7cjjOf86/eS7HWlQJrGHOybXe4AJo0yYs
         rK6CLpgsEHzE7JFuVf4BWSPLjXDWpLWmwXWppzXGQOyVYF5W8lL7+D1RmVlwTvHTb90P
         vW9Mwtui3YkjQUD31clvrsI6qjo+rG2ss94BR+ehd1sMLjI93jI6Uc52b4NUw9Oh+mWt
         ntGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387733; x=1765992533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WcodwupXOLSb3cgnig4h1A3RySFZ+BXWrqqWexmE5vM=;
        b=IdIf8jbtmJXfTKKwh/9ONnpx1ov4nZJmd9Y4zBq2aVvxX/FT3dS+42f2quDu56qu6Y
         eMKUZvr8sH1+2QXRx8SM3GN+DvqAjJEiJZy3Vam9u5YuROgaJABwzLJ3dNliWia+XCFk
         ZiCyWM2vdwTVQ5UjyeZlafmnFBELeEdSvYTYEzEvpwjNA/oSbJ/Yi8tEGuD6I2yc5EMi
         ujP8SVu0RJgppIOzLOq26lol8kFKAeejb3aGazal+/zdM8M6rzhJB1d4KPmk8OZOeNrw
         YDLz/y2g1gecKg7l8n1YyV+YYupDd3RlUOb+GReVk3Lw/TA5CcVaC7GlcTgDQoCUvPC0
         yQNQ==
X-Forwarded-Encrypted: i=2; AJvYcCWgc+ZlgIfyb7FkKpU4nSgX6tGwv8Gi3U0IRTKd1DE+war8StqHkOEbPpJ9yMvyZMqdJzHrbg==@lfdr.de
X-Gm-Message-State: AOJu0Yyz6J2mMpsO8Z7y0AVNI/J5a7n7p6bm9wlmybHTXAArSwrQjb97
	6oRG+vlcdRQRsVaCxpUU8xc7Y3etKimCbjB52fqKKtOWywhhcR+s0tJU
X-Google-Smtp-Source: AGHT+IF5ZDy+I0doBGEFcHP228ldVFjfZcDCj++WnKDM0271S9Y/BFdN8MbnJYKz0Qgs3S28ccnVsA==
X-Received: by 2002:a05:620a:4708:b0:8b2:dada:29b4 with SMTP id af79cd13be357-8ba3a45dda6mr493803585a.63.1765387732938;
        Wed, 10 Dec 2025 09:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbQmWn7Ghnf6DjVlYpQxfdNphBl9BoaJNsTSwUbTL/rpQ=="
Received: by 2002:a05:6214:1707:b0:880:59ee:ba5 with SMTP id
 6a1803df08f44-88825e4b041ls121568886d6.1.-pod-prod-02-us; Wed, 10 Dec 2025
 09:28:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3qVleuGcz6SQN8Nwqu2s89bwSYuWO8tGWJQFKN43dZkqnF5KA3wf5BCoPF7CgyiWqSQNmp3/esH0=@googlegroups.com
X-Received: by 2002:a05:6102:26c2:b0:5e5:63e3:ebbb with SMTP id ada2fe7eead31-5e57217413amr1192497137.42.1765387732269;
        Wed, 10 Dec 2025 09:28:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387732; cv=none;
        d=google.com; s=arc-20240605;
        b=ku53zw+pVXnMifCY4471cMgfi2z57O5fx4WX1HXoCUnvbdtDWM1IKrfJv5TiTShLEa
         c/+LdeNh7uRjFhu3QtyFN57zCguagKwnkFn07RuS0lg/TAJT33OLIIKEm18bCrH467SL
         Xis6il0o81D8jKpYZIG4gnk9pkg7IlD/GV0kQLq3wdtt3zeQVVUOmpDRjKEgEQa2OExg
         ZG8tbeOLwKV/rRhk6Bb+JlwyiqnsFgZY1kv8oEBRvDBEkAKTxM5inPcddwdn4B2v9Zxj
         aVre7BBXRiFalUHm3CTRyIULrQ+CixlqvKw827GL3KgIEQ15cVyVqUw6TjiEoPjxiwJc
         jcjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=uKUcoWRGEpioVsYqfJYYUwDSXTCCDSTxDl6r47kG8IA=;
        fh=KQhpl7mxwZv8idz92Qj8BcTZceL5KUXACbAfQjf4Oac=;
        b=MsaaIgURxQI4K4AKpKne0wzBg+cY+RoxTuE5bwRu1ZGU5D9Polzfy/q9yIcGpkVVuZ
         rxvAgkK6IJUNBNKR1HHn0etVIgqbElwx2Ii5F8CCu7LEoQ2O0MLD0PrsBOleKB8yVhzt
         W/UhTIo0V9uIUau4J9+qY/5yUBiRRY72ooM1eRuOrasXrDhJJl8c4ZNUWchagq8J/4TM
         aVWjr4QCEO+C7PK60Icdt89WpoBlYqmnZSWFmPzK1cEFqvY/f9TEqbNdLiGVn0bxB7AU
         ivK/sY/ERJrmQiq6uLOamlwili9SulV9YP/EwhVQVmpQj9Q4t/E0rD8jtva0tmn3gPwF
         6QvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=XQg25V1L;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-93f583e3420si4048241.1.2025.12.10.09.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:28:52 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Wed, 10 Dec 2025 17:28:43 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: [PATCH v7 02/15] kasan: arm64: x86: Make special tags arch specific
Message-ID: <0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: dcbf8ea52fee4f67b789474d9088b2f73bd5f9cb
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=XQg25V1L;       spf=pass
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
index 7bf6385efe04..a591598cc4b5 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13420,7 +13420,7 @@ L:	kasan-dev@googlegroups.com
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
index e1b57c13f8a4..d2841e0fb908 100644
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
index 670de5427c32..5cb21b90a2ec 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -39,8 +39,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-/* This matches KASAN_TAG_INVALID. */
-#define KASAN_SHADOW_INIT 0xFE
+#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 8e9268cf929e..b61090a80e3f 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1762,7 +1762,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags.f >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1775,7 +1775,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags.f);
 	do {
 		flags = old_flags;
@@ -1794,7 +1794,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman%40pm.me.
