Return-Path: <kasan-dev+bncBAABB4OLRHEAMGQELL5VA6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id DEAF6C1CE77
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:07:32 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7c2737654f7sf42007a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764850; cv=pass;
        d=google.com; s=arc-20240605;
        b=CXU9NKI7wGDnJ9tc0VHyJHvtsJ2z5/qQ7Y/37g8k2koJy12XhJkqi7UC6QGei2lEt1
         tUBuV5kIz9dDySBgxVPoxd3a16a/KOQZjI/S/4MrbwT2dkX2OidNCIYEqRDPIhbqJ7I3
         QxH8W9CvbKJfp5NTRMoVJsdx0ijmwZ5IesffCVcV6qUb+DRzdHqvu6XaaJGapHwfgjYO
         X8rzLJwf8BTpvWoVn4QqEE73YhwOyzMF3j4QPR7P1pzkMpbleLpfS8d+h8y/zQomyP2z
         Uon7yLQ2GPPKfyRFO8WQ9NamaJIXG3pJUvYh4FKfanopbu66VpiiEjNb5/g2qPVczo02
         oneQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=ESD2k0SNNmYwe3/L+rw/4DmjHTwblya12fguwAa0v3A=;
        fh=AZZsYTqkoLHWzjJPZdnyXnlBS8T5RSW/dW1MEBSDVXg=;
        b=IxTQGqDWLRfJFk37FPeGpiezgglwN5Z7XfxndHsNpeZ8AY6hIgSPMnbd8tbOlqy9ms
         eu0s1V6i+EoOaMsXEimTWkd5JhdktEUCurMtmCM0ymAOLFTawqc/mPfTFG2RO2ABsruw
         83k49VOHgvfP905C8CE+BXinouAI38+TzpgFIs4WX37IIMYlDuSuvfpTw4VpuHYFyuXl
         zdmcWjruAPvbp0Y+jDMLY0xLtGh314R4H68tpFX/0BnT4Lffm5mhiP1Gl+FvO8W110Wy
         M9yHYmoGU2G+0YVag7DYP0bKXwSw0TT2gntcYtEYLrGqTDpvXb+yOsnvSQ5Mhid15Yik
         BLhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=kVBnL3t8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764850; x=1762369650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=ESD2k0SNNmYwe3/L+rw/4DmjHTwblya12fguwAa0v3A=;
        b=nLlXttOtyN+mElYwamzU/rMHNeq/nkjKVo+PdI4u9smRhiCOUg9IS0HL3DLPlPvI6U
         m9TLNsB8s/YbeQFOIszppBKrCSAsT6OqlGo1wvMkHCElfkNIqUISquUZKIIB+gJHG18K
         DU+b6cowSdIBkLvjFSqkvqRQyY1jrr+pIBkt/ozBL364EIrkh181EgZU8Z/DsUHVQ4k7
         n+W6qogEK0qIufDWa2CHLN1q6QNUueIrR2SWe/qDkGYlpvhj+dKlcp9wxUHmCt/GAVg2
         aJ1diJA/dzltMB0C7QlEsrCQkyhSiIi1lg+Dr8q+k4r+MlpXujAQ1Mi+OLTM3XZIjHs4
         KA+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764850; x=1762369650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ESD2k0SNNmYwe3/L+rw/4DmjHTwblya12fguwAa0v3A=;
        b=CBl2xHQFC+KIHeTgXsHd1L8VWRKbqAMEAkDV8+2Y+b5DROcn/a//5RvTinKh5Tcp2O
         95OoK7KIJJQsN2Ia1x1evp2l9vzF7MqwiK6q9jwrkuwoSBxttvlx5Ex2qvVTcBHrmSlv
         zsmlsy7gIjdAzEcjspYA9pYsSrXktZoTSchpe+7aI3Mr8INtxO+jmpRjlrG4xTGIuScV
         Tl8FFugD5/W5C1nOCjXGFRnhZAM5zBKshocTfPfrFrakRKHnE/Uukld1YH0lGTDgjaA6
         1+j7gbyW7fKfY/zubiwCwpn7M3KicNH1pT9dAND60bFgutDDuVe+uVHCQMsv2PP8PEaa
         tCkg==
X-Forwarded-Encrypted: i=2; AJvYcCUA3jjIXnKrEwcfGYg+EA0K1B/900/ILyi1vTJcRR9+sgZrpB99XcruF6RXzqJ0vvhn1avCag==@lfdr.de
X-Gm-Message-State: AOJu0Yz1kovh8MOh6Q4FXAfCwGMqqmxKvzetPYkPv3/+ZwzQN2EUfa2c
	rvGKQICQ5MvVA/Gw+OuQG00hjZ+85w8piC3jOgDoluqOpWVH2Ny8qJuN
X-Google-Smtp-Source: AGHT+IGbPbS2DGRZAqVBqE2dPhbJ8b3LPPLdgbgGvOMk4xbWJedd8mloB3qGvI1r7ve8A0JlLdGzAw==
X-Received: by 2002:a05:6820:780e:b0:654:efd6:7b8 with SMTP id 006d021491bc7-65677eede0dmr711211eaf.2.1761764850130;
        Wed, 29 Oct 2025 12:07:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZSYQrwNeaxSjITSmkh/o/7yh4qQ19yJvOezCh9h60BuA=="
Received: by 2002:a05:6820:4585:b0:654:f519:683f with SMTP id
 006d021491bc7-656823c6e7cls35572eaf.0.-pod-prod-08-us; Wed, 29 Oct 2025
 12:07:29 -0700 (PDT)
X-Received: by 2002:a05:6808:318b:b0:44f:7562:1a73 with SMTP id 5614622812f47-44f89e61ccemr196539b6e.35.1761764849222;
        Wed, 29 Oct 2025 12:07:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764849; cv=none;
        d=google.com; s=arc-20240605;
        b=dKG4JLZuZL6nuExuXdTJYRMe1BvnHaXrAUtprijtvUWguzYTfGK6eIk/SPyrEbOrwq
         wMxK26tJlQ8uZTNnEbBS4YILioHhgJS//iCT5LEYoFBR9E7XL1Eld8gAoiVnI/Vi1Irq
         zeFzatBMjNUfO78c8dLqL7JQ3cqb5xL6kdwFS/YF0HvYVksJM2fOxudLoDaCnzK/cYsy
         aK/4p+NDPt8L02gn742F5FAssFMEEczg8TyFPu4JPlQmpWzIN14R2Q+9V7yeXGWJdJXo
         AVQCXZ2TFmsCo6uy87sLHUDA4GE//ZF3VR6G425qEDJe2SDJY3cVIhVk8mr4ZCz5Cytq
         MepA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=lbXAxn7Fr4Nsk0Pj0RuqXVl7zH+aG4MTOYlJmhasqg0=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=han/UTbxuwa9w3KjMs6SNE6A+4G80gnTo5ku349oVwQa8oQEKdVlP2x4uDH8qMQe9K
         c3XJv1+QJyZNkxzaFceEPIjVhyw2bCwabys4pmewxfqXueyupWPKaDeUUoXEvjoHCm7k
         9/romsUvYtpqqsjtCVe8f5BazHLYkwAo91/vxFf9GPJVYRpk0YAQzNM/S5zfXgba7XLS
         3TRW3vFIj4vzDwEYEDyJoRiOUa0NU9gL9VB7vuNot/40GE7bA9osXaZ1mdvRDWe8rMVx
         TFr9OHzGl/dX5jikEX1UlqZxo8VOruYju74AnLXg3ImzmqankZmLC5gLJcF8S/NiYIEB
         3d/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=kVBnL3t8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-656784960a0si219023eaf.0.2025.10.29.12.07.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:07:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Wed, 29 Oct 2025 19:07:18 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 07/18] kasan: arm64: x86: Make special tags arch specific
Message-ID: <fd549c974b53b5410dbf85c0cf6a1f9a74c1f63a.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ce29df287bb81048c364d183798873981c136eab
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=kVBnL3t8;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

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
 arch/arm64/include/asm/kasan.h      |  4 ----
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 10 +++++++++-
 include/linux/kasan.h               |  3 +--
 include/linux/mm.h                  |  6 +++---
 include/linux/page-flags-layout.h   |  9 +--------
 8 files changed, 38 insertions(+), 19 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index 3da2c26a796b..53cbc7534911 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13421,7 +13421,7 @@ L:	kasan-dev@googlegroups.com
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
index 000000000000..e6b5086e3f44
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		8
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
+#define KASAN_TAG_WIDTH		4
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
index 952ade776e51..3c0c60ed5d5c 100644
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
index d16b33bacc32..09538c7487f3 100644
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
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fd549c974b53b5410dbf85c0cf6a1f9a74c1f63a.1761763681.git.m.wieczorretman%40pm.me.
