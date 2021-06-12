Return-Path: <kasan-dev+bncBD7JD3WYY4BBBIP3SCDAMGQEBKEB2WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C3913A4CE9
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 06:52:51 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 4-20020a17090a1a44b029016e8392f557sf2212287pjl.5
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 21:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623473570; cv=pass;
        d=google.com; s=arc-20160816;
        b=TuCXhQ/hd3BkUIUaciWNRW9FMrtPs1ff0V5DPRurkUZjFK3m2Vv0Ya27DzikUwey3U
         x9WegfYfz2P6soRZvaf+RqKdLdO3DqU1HzT4mj+pX0159saK/I6v+BF2ROKo5RCYIFlk
         rgQN1OrZ3w3Ppv4aE3Qo5XUZDGJWYSZvqkROCDb/0Xelf2ulBfettHhGDb/ZbOXO2nGC
         IK80vNOlpF+TlycBySQ03jcwmLMiS81lA4pmRueJIy2qY+ijR88XguVnRTRcylzUHxtx
         JQ5oLKxP/E2AMohbtpIr50M54cKSobs7DPYwT2W6lyhkVPGDNCTyrctLy6T38HKH/cne
         wmkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=570sCc/v3wYPmQHyBN4+288cjViHj7a2k9W+CZMZOic=;
        b=cvumV3aPYNyU1HUnKoFhugmXn+21aQdGxVj4MfC9UszUs7j3/6zu5wIZTLiA/LkUK2
         ZVkFEDsXv4p7dEqWf4MIMzY7fryaqdDjWh52V59ohl5CduBaXJ1PKvYcvoTt1I1ywM/1
         cY9RuGNqD32ik8QHn7KY0Budpw7ThSNZ64iPgY/Pd2ndtmKdAWNW5jjOm8pptc5vNf+/
         rb2WvcD4q0r1lajqhDRVasgjVzFNTdTCeBgMhSPwfy0SNLFPVsG7pWwRNjCs7op7O+4c
         M+q8i3clKEGDdQd5nEi2oRgrEdXeL5gnFcVWbOE6t1Hk5c22Kti8PfKXCoe/OmcxyHGu
         FOHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZcoSxJxr;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570sCc/v3wYPmQHyBN4+288cjViHj7a2k9W+CZMZOic=;
        b=Fr/8cyGi6qtUozdfu3DRGE+PHIpltuCm+WsTUkQ7yAgfelhWc/TDI7qQHMIcHJ1Xa7
         zS2M5LmjoDku1RMmNS0D0RMKyV0wv1wNAOblr+lqDw3PE9FDhSA1fEFztmslFt8G05eC
         0fah8uVu+H8A1JVPt9wkKj5kGS/S05za67Ks+U9AftIU7ukorgLIBViWTZyC3O0Ojjm9
         kzFAq206+gTpze+yz2nKYSMgb0UCj/1RnbEE1UTxkljwACdxHlpvl5qRClLq0wdix/Vq
         EO4Pt+20FGmqJ1lXkIEIGMX8tT0swYYBV8sUiXhBzW9QXilYshDjpC/3sUr2cxCb9G6o
         /yKw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570sCc/v3wYPmQHyBN4+288cjViHj7a2k9W+CZMZOic=;
        b=seKqfT7HGDLGNdj2uIps9pJRInVwXPJc10L7dPbO21wnWW4iqgBC36bHRK1a+9U3QQ
         Ww0ALx3v79YuQp5qLnlir9Pn6zoAkAv6hmWnaA1aYbzVYaMajNNM8I0S92fSeA3M/Y06
         VzTCKRWPJXHGHoCTAq7aW/9/hu4QdF4/nSlVNi1mb2O5CddvsTCGjmlKNPrTU4mmKMKF
         5G8XlJV6mIjE2GtBj3q/aeidm1ruBhpD58XnLvsJ1/568XvLNIvRmm8p0BCikHs0iIxa
         IPeG45PqqDl5orvGvYjA2ksIe0NVS6IyjJ3vgCSDXnwonOHbAtg8R+FUaz26SVwavFm+
         u4JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=570sCc/v3wYPmQHyBN4+288cjViHj7a2k9W+CZMZOic=;
        b=cJhA/fOfiocwKTS6stQhh8qOyNMGMs8B1D3xHya57HmSXeT3mBVpgnovGLUdZAiqZH
         F+AgdtMz9ic2xuVRyDykrecc1P/eplWocYAP0BVe4Fsc024OPmwEayDtiWyxVl/hoPWu
         G7qLnKOQ+WbHpeRbOMhxOqACkT2SR9cusdCB4u0SkwqM5Yqg9z0B8yxRrha6WrcjVAbf
         W8ikxqwsQqvCOFmtUFNg/u21E3EuSP0LqFcaSDgXo5kgTv4NTsifN77BHL2AMYK2sBFM
         N+wk8JSWSnOKh8AEXVJMbC+jBNOuuTG1QNO9omueoiuvrMzhKbnPGhmg4V/joIAWaTnP
         qQtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533C4Yc09Am5VBVE8+wJgA2ZrSUetGrKNr/zzezprjhgHUXOIPNs
	OlFuJ1vJ21x1z3rSuGbqHoM=
X-Google-Smtp-Source: ABdhPJyZ9K6tygmoHZDiXmVHRomxxXFU3BIwGEXS8Z1TRskDO4s7IbDb8gKKHywcH+J76HHJpkE/Fw==
X-Received: by 2002:a63:f344:: with SMTP id t4mr6932316pgj.314.1623473569990;
        Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c713:: with SMTP id p19ls6461500plp.11.gmail; Fri,
 11 Jun 2021 21:52:49 -0700 (PDT)
X-Received: by 2002:a17:902:b48b:b029:118:b709:9f50 with SMTP id y11-20020a170902b48bb0290118b7099f50mr4724814plr.74.1623473569455;
        Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623473569; cv=none;
        d=google.com; s=arc-20160816;
        b=UmiEsMPT0967gMwV+4hCXxvNKqbpdU+uipjXCU7EAYbYwH6ZoJ4iAA+AVVG/zfmhTY
         f9N8z6O1y3k+xDXpVCd87Rd/lo7pGDAasQq2+uNdxtAVtVnLb+2cUJw39wo4QT2bY7hw
         VomTynVcrJMxvJCamZR22OrgoBbX9k61g02rILfa0ppRYB+aLTh3gq6I8rw7tb5Gz9MF
         fV8Y4cyHY5URZIDIwkFoo3p+wm+YLE84n+bFZll3j5dhWxOKH6QxX8MY4Q7B4W92fc3A
         ABWRoIhyANJo10bmfEovHN+Qwl9Oyb+PKI5QMiYNYU4N9BOrm7KhCQjOTbM6wgYqYLrZ
         Rp0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xZpi/auc1uYGQ0mhRO9DGP7asmsg6AhH3/5v7rWbUt4=;
        b=UFM/J96n/DZOx0Bc8k6KYIbme4okl+v+bGUtdhd5JAl8RiWg1tN3xKHjs3FQiSPA0w
         Tosh80MD9bR0NPA31PS6nPi0bI4H2Q3n5pB8kU8VmzZrRWwAFPdouJKUwvfSOg0IOPCl
         XHxuH4XKmdQlHYsVJPKppy2Oi/dM08Ei1MdXhiz2sIGYNDFS6t1A/XRuHScU0SuWlxAd
         +TFH+kYw+nDxrwezEjnmMpsPJJntAi6rbLjzLXYm1wvPh/p9VBpVqHTeijUbmwZ+2Hcj
         KyMutcW0SwsWdqSWBrnahEOTZv1C8bLqhdzxAu9gIAHfksG16kctGAkvglI9MZ3/zvVr
         j1gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZcoSxJxr;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id n2si484326pjp.2.2021.06.11.21.52.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id y15so6101118pfl.4
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
X-Received: by 2002:a63:7d2:: with SMTP id 201mr7032031pgh.14.1623473569284;
        Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
Received: from lee-virtual-machine.localdomain (61-230-42-225.dynamic-ip.hinet.net. [61.230.42.225])
        by smtp.gmail.com with ESMTPSA id m1sm6076572pgd.78.2021.06.11.21.52.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jun 2021 21:52:49 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Kuan-Ying Lee <kylee0686026@gmail.com>,
	Marco Elver <elver@google.com>
Subject: [PATCH v2 2/3] kasan: integrate the common part of two KASAN tag-based modes
Date: Sat, 12 Jun 2021 12:51:55 +0800
Message-Id: <20210612045156.44763-3-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210612045156.44763-1-kylee0686026@gmail.com>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
MIME-Version: 1.0
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ZcoSxJxr;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

1. Move kasan_get_free_track() and kasan_set_free_info()
   into tags.c
2. Move kasan_get_bug_type() to header file

Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/Makefile         |  4 +--
 mm/kasan/hw_tags.c        | 22 ---------------
 mm/kasan/report_hw_tags.c |  6 +---
 mm/kasan/report_sw_tags.c | 46 +------------------------------
 mm/kasan/report_tags.h    | 56 +++++++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 58 +++++++++++++++++++++++++++++++++++++++
 7 files changed, 118 insertions(+), 115 deletions(-)
 create mode 100644 mm/kasan/report_tags.h
 create mode 100644 mm/kasan/tags.c

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 9fe39a66388a..634de6c1da9b 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -37,5 +37,5 @@ CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
+obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index ed5e5b833d61..4ea8c368b5b8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -216,28 +216,6 @@ void __init kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_set_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->free_track[0];
-}
-
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 {
 	/*
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index 42b2168755d6..ef5e7378f3aa 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -14,11 +14,7 @@
 #include <linux/types.h>
 
 #include "kasan.h"
-
-const char *kasan_get_bug_type(struct kasan_access_info *info)
-{
-	return "invalid-access";
-}
+#include "report_tags.h"
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 821a14a19a92..d965a170083e 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -26,51 +26,7 @@
 
 #include <asm/sections.h>
 
-#include "kasan.h"
-#include "../slab.h"
-
-const char *kasan_get_bug_type(struct kasan_access_info *info)
-{
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	struct kasan_alloc_meta *alloc_meta;
-	struct kmem_cache *cache;
-	struct page *page;
-	const void *addr;
-	void *object;
-	u8 tag;
-	int i;
-
-	tag = get_tag(info->access_addr);
-	addr = kasan_reset_tag(info->access_addr);
-	page = kasan_addr_to_page(addr);
-	if (page && PageSlab(page)) {
-		cache = page->slab_cache;
-		object = nearest_obj(cache, page, (void *)addr);
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-
-		if (alloc_meta) {
-			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-				if (alloc_meta->free_pointer_tag[i] == tag)
-					return "use-after-free";
-			}
-		}
-		return "out-of-bounds";
-	}
-
-#endif
-	/*
-	 * If access_size is a negative number, then it has reason to be
-	 * defined as out-of-bounds bug type.
-	 *
-	 * Casting negative numbers to size_t would indeed turn up as
-	 * a large size_t and its value will be larger than ULONG_MAX/2,
-	 * so that this can qualify as out-of-bounds.
-	 */
-	if (info->access_addr + info->access_size < info->access_addr)
-		return "out-of-bounds";
-
-	return "invalid-access";
-}
+#include "report_tags.h"
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
 {
diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
new file mode 100644
index 000000000000..4f740d4d99ee
--- /dev/null
+++ b/mm/kasan/report_tags.h
@@ -0,0 +1,56 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __MM_KASAN_REPORT_TAGS_H
+#define __MM_KASAN_REPORT_TAGS_H
+
+#include "kasan.h"
+#include "../slab.h"
+
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+const char *kasan_get_bug_type(struct kasan_access_info *info)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	struct kmem_cache *cache;
+	struct page *page;
+	const void *addr;
+	void *object;
+	u8 tag;
+	int i;
+
+	tag = get_tag(info->access_addr);
+	addr = kasan_reset_tag(info->access_addr);
+	page = kasan_addr_to_page(addr);
+	if (page && PageSlab(page)) {
+		cache = page->slab_cache;
+		object = nearest_obj(cache, page, (void *)addr);
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+
+		if (alloc_meta) {
+			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+				if (alloc_meta->free_pointer_tag[i] == tag)
+					return "use-after-free";
+			}
+		}
+		return "out-of-bounds";
+	}
+
+	/*
+	 * If access_size is a negative number, then it has reason to be
+	 * defined as out-of-bounds bug type.
+	 *
+	 * Casting negative numbers to size_t would indeed turn up as
+	 * a large size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 */
+	if (info->access_addr + info->access_size < info->access_addr)
+		return "out-of-bounds";
+
+	return "invalid-access";
+}
+#else
+const char *kasan_get_bug_type(struct kasan_access_info *info)
+{
+	return "invalid-access";
+}
+#endif
+
+#endif
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index dd05e6c801fa..bd3f540feb47 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -167,47 +167,6 @@ void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
-void kasan_set_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	u8 idx = 0;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return;
-
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	idx = alloc_meta->free_track_idx;
-	alloc_meta->free_pointer_tag[idx] = tag;
-	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
-#endif
-
-	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	int i = 0;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
-	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-		if (alloc_meta->free_pointer_tag[i] == tag)
-			break;
-	}
-	if (i == KASAN_NR_FREE_STACKS)
-		i = alloc_meta->free_track_idx;
-#endif
-
-	return &alloc_meta->free_track[i];
-}
-
 void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
 			unsigned long ret_ip)
 {
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
new file mode 100644
index 000000000000..9c33c0ebe1d1
--- /dev/null
+++ b/mm/kasan/tags.c
@@ -0,0 +1,58 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains common tag-based KASAN code.
+ *
+ * Author: Kuan-Ying Lee <kylee0686026@gmail.com>
+ */
+
+#include <linux/init.h>
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memory.h>
+#include <linux/mm.h>
+#include <linux/static_key.h>
+#include <linux/string.h>
+#include <linux/types.h>
+
+#include "kasan.h"
+
+void kasan_set_free_info(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	u8 idx = 0;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
+
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+	idx = alloc_meta->free_track_idx;
+	alloc_meta->free_pointer_tag[idx] = tag;
+	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
+#endif
+
+	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+				void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	int i = 0;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+		if (alloc_meta->free_pointer_tag[i] == tag)
+			break;
+	}
+	if (i == KASAN_NR_FREE_STACKS)
+		i = alloc_meta->free_track_idx;
+#endif
+
+	return &alloc_meta->free_track[i];
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210612045156.44763-3-kylee0686026%40gmail.com.
