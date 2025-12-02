Return-Path: <kasan-dev+bncBAABBQXPXPEQMGQEX4A5NWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D222FC9BC70
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 15:29:24 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5957a623c61sf588321e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 06:29:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764685764; cv=pass;
        d=google.com; s=arc-20240605;
        b=TvR7SrgJ0w/hw5RRnr8s87uq7YPDi5mxSDePsNOmSnwbhLQc4tdAN6K0Xl6iWWUOa5
         uao821yx55HYoZFPbDQ12Hq+nUspDlE7qJ+GPTdBv84crtNDObJOftzyQuSDDDzldbvf
         8dz+TuR8IXqw5+1eomALuFyiIsLIoK41T7L1sU508Ik7BPzEoogAfjITcwn+L7ECwk23
         LA0WwlkDjKvTdsQUxMgDqQLxJGfEAiU0/dCrG2PRCCLUpY+inED/Kwk4hOtOuU8+7Twj
         rpt16dEl5mH6zXgIsXyC83Tz/QhVsBhsHrsGVHkqzANPUOXcvDmG+qW8Mvw0wbtYu3bC
         ivZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=bbLnumufCk4yasGbd5/aIOyYkKNZLjgQELAe1WTPnok=;
        fh=6OVkcilZo8TTDKpTsciLC7x4BIGRsie0+c1lndP7IqM=;
        b=M5ZbxtxlnqKY62Jhc9FJY/CzQJ4EnHxiPLoQA1HQnJaj5zGTB+TD77RVTVWeV4Xqb8
         ZgVM8MX+PAuw73ztcNxoXGn9lS40lUqjzj4q/FrwHmzx6p3RiXL/3fZgwCquNRz0ZtKQ
         3pgLSKilL+Jr4Dl19Lm7QPiRIQlkAhnJn/mWYOf27k05fxM7OLgdktmNAofLNALov14M
         YMo26LWQX1oyQ5CYWmXeUSQapDeGRHp5wmeQlE3A90Lbi4yiKY5petDsCAFTPm4yW7ld
         sDyOM9zQZb5psbjBiwTshIBLUiz8FFoEbwRdhwd3EgDFnymP68Pfzz27BGuJlnr87LK3
         Mg0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NRGZ6d4+;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764685764; x=1765290564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=bbLnumufCk4yasGbd5/aIOyYkKNZLjgQELAe1WTPnok=;
        b=lFoYBEjUfHXr9Kok4/P1EJOuyeOX0n06ZzhLcWQR5CvlDhouCfWufVfhM3NLi627IE
         8iaUHeFOxS4A/TENlTybUh9wh4/MRwlvm6tsNLpIpWGq3meXHguLFt8q3PXxLrsQxtcv
         BrHogu61PKYTM4b4IdFucwQ1J+Mzk4dEMfhCeIIif0/zx/gi1q+k79tS3qYygFYw+N9q
         hNtBx1bGXzVWH4nPjFV93EAMKBO8oTVq6RKeteljT2U8rOGumQ9xYuFdG5X8g6VfZ04i
         DYbOyk03tiF5brqSQdsEYWKaE9irzUO1QU7wYm4Rv+2ceIY639JWEJGcI8X1fn+2fmST
         ym0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764685764; x=1765290564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bbLnumufCk4yasGbd5/aIOyYkKNZLjgQELAe1WTPnok=;
        b=wLeSSHXJguVNvFq01dU/VCCBzC1PfGSUBl7xqrgewBFzPAT59/C5H2q3xkNVIyVTu8
         vEuInOFbSCicMkqOT708EzQ5AL17/OOnT4SVyio3dVV7miN4WD89mznUh6CUSmAMr5t4
         4tYFlYvfp1vQT/Vd64qgx4K3luWhsJjqnJEfIPDF0xU1dUUbfkbaw+ROHfmFDmsDXBzU
         QkvgFr8OaSrw/J5t5mis5mL/wsAf1pw2odTjqnjc9xL9ceoHcRImp2Vij0TfbZicYc7l
         jOf/UC66lohsVVZbsY6xcwAmnILwwZFS07C8Tno1yxrduJAkD1KFoUe/GQYzd6J3BlHt
         Nniw==
X-Forwarded-Encrypted: i=2; AJvYcCXLZ0FV2JpwmWZOpFS6jkZRhOjSgrZpPZsG55rr6wsPmG137MMIvqXr3RTAaSC5B7lgwAH/Gg==@lfdr.de
X-Gm-Message-State: AOJu0Yy/W1JMD9/0s5mx4La5abVwfl3udOj8DdV4JynYl4oeSqZ2ScO5
	qaSCK4TCzQ7tNZj7xroLmzJyrKwPcSoMm/QHitnxN44SjB6HP+btXb6H
X-Google-Smtp-Source: AGHT+IEAJgLbTVkKi/pfPYtV9M4zcccVAkV6x/Etq6Zf7mKLKXRsq5Zf97sxKi7UoMKpaUNDwqw9Pw==
X-Received: by 2002:a05:6512:12c5:b0:595:9161:f837 with SMTP id 2adb3069b0e04-596a52e84c0mr8041108e87.4.1764685763687;
        Tue, 02 Dec 2025 06:29:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YS1oV3yuiG0IUb4UWqp3fLjEN9XBovUNofbRHcPpOpeQ=="
Received: by 2002:a05:6512:40d1:b0:596:bdb9:a27f with SMTP id
 2adb3069b0e04-596bdb9a2ccls1285814e87.0.-pod-prod-07-eu; Tue, 02 Dec 2025
 06:29:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7tDRH80hWuMTS8I52l/WGxHj/xKDAVlEcPKF26yUSHzT/XHvfGPEdJ8MjgJWrhMvRR9D/AUKggMI=@googlegroups.com
X-Received: by 2002:a05:6512:308a:b0:592:f818:9bde with SMTP id 2adb3069b0e04-596b50598aamr11032249e87.1.1764685761225;
        Tue, 02 Dec 2025 06:29:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764685761; cv=none;
        d=google.com; s=arc-20240605;
        b=AC+jacGwr1+xvcO5tnKXkKKqC5jtq+nSJY22311N/daXEqyrUupamEnn5hFcY6kvmg
         wm+YKLBbnQR8/BTm+6eNpIorsWP9DUijl00h4oWUjYFDxe56uZLzCZ1PFAa8tn4K6cMP
         +1MaZga22RQRYksWH6FhsuWSKHBW6eUXjNpZrywiYxNOCdjouWCjTnlNnN4Pc9MliYoE
         bxxlQt002k3TRrqdAo3wiTcD6OIJOSTW1Hq7mxRGRVV5I08tjGWrUrJwzWlzOlcmdrib
         AMp6I6uh0EqYZ8Q8uxCVImbK2qulpahqCMio3hzM4HX9/1wQC8W881JyPNRIoafMQO0Y
         GDTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=cxvGIY83ye9YgTgKuvjuMWrA1hnR8fL/ldcb4UtoE+A=;
        fh=ClEAq4QRoCEER0P7dlI03xQ1EzKzEdoLKEGMqAsVixg=;
        b=TpbjJPkfZTGXTpoOKhsm8fWcj4VxAmrqFpI8Z3CylIrmOAWkEGzwLDwLAYJNpjmgdI
         yYmZeyOlBtperBWs08Wmmyda2U104YOxumMYP19jTfzirrjsPP6udAglr4g6UphdgyP0
         eBbObQbXXs7mk3EOTbDXYf3EF24CvQ213Y9PdFEoE4zK6zl8O2dHYYwbbQNN7nl3tujZ
         FyqjvxfFTej6gmyW6H+iyVxJv4SNHQRVoqFbxFP4Opv23bTVWRr+dJ71R5ESNZBtPlGY
         toEGw+9B9UwftRC3N6izZvmryr5m1BQbPEnikE/k0lVgybmcfa00AGpnFCPJlX0292Pr
         EtGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NRGZ6d4+;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43102.protonmail.ch (mail-43102.protonmail.ch. [185.70.43.102])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-596bf8a7b09si203749e87.1.2025.12.02.06.29.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 06:29:21 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as permitted sender) client-ip=185.70.43.102;
Date: Tue, 02 Dec 2025 14:29:17 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v2 1/2] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <3907c330d802e5b86bfe003485220de972aaac18.1764685296.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764685296.git.m.wieczorretman@pm.me>
References: <cover.1764685296.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 39231ba515aa7720d08908d2e3bb7dc16ac86540
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=NRGZ6d4+;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.102 as
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

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Refactor code by reusing __kasan_unpoison_vmalloc in a new helper in
preparation for the actual fix.

Changelog v1 (after splitting of from the KASAN series):
- Rewrite first paragraph of the patch message to point at the user
  impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Redo the whole patch so it's an actual refactor.

 include/linux/kasan.h | 16 +++++++++++++---
 mm/kasan/common.c     | 17 +++++++++++++++++
 mm/kasan/hw_tags.c    | 15 +++++++++++++--
 mm/kasan/shadow.c     | 16 ++++++++++++++--
 mm/vmalloc.c          |  4 +---
 5 files changed, 58 insertions(+), 10 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..4a3d3dba9764 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -595,14 +595,14 @@ static inline void kasan_release_vmalloc(unsigned long start,
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
-			       kasan_vmalloc_flags_t flags);
+void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long size,
+				      kasan_vmalloc_flags_t flags);
 static __always_inline void *kasan_unpoison_vmalloc(const void *start,
 						unsigned long size,
 						kasan_vmalloc_flags_t flags)
 {
 	if (kasan_enabled())
-		return __kasan_unpoison_vmalloc(start, size, flags);
+		return __kasan_random_unpoison_vmalloc(start, size, flags);
 	return (void *)start;
 }
 
@@ -614,6 +614,11 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
+				  kasan_vmalloc_flags_t flags, u8 tag);
+void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			       kasan_vmalloc_flags_t flags);
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -638,6 +643,11 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static __always_inline void
+kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			  kasan_vmalloc_flags_t flags)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d4c14359feaf..7884ea7d13f9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -28,6 +28,7 @@
 #include <linux/string.h>
 #include <linux/types.h>
 #include <linux/bug.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -582,3 +583,19 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+#ifdef CONFIG_KASAN_VMALLOC
+void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			       kasan_vmalloc_flags_t flags)
+{
+	unsigned long size;
+	void *addr;
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		size = vms[area]->size;
+		addr = vms[area]->addr;
+		vms[area]->addr = __kasan_unpoison_vmap_areas(addr, size, flags);
+	}
+}
+#endif
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..4b7936a2bd6f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -316,8 +316,8 @@ static void init_vmalloc_pages(const void *start, unsigned long size)
 	}
 }
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
-				kasan_vmalloc_flags_t flags)
+static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+				      kasan_vmalloc_flags_t flags)
 {
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
@@ -387,6 +387,12 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	return (void *)start;
 }
 
+void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long size,
+				      kasan_vmalloc_flags_t flags)
+{
+	return __kasan_unpoison_vmalloc(start, size, flags);
+}
+
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	/*
@@ -396,6 +402,11 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	 */
 }
 
+void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
+				  kasan_vmalloc_flags_t flags, u8 tag)
+{
+	return __kasan_unpoison_vmalloc(addr, size, flags);
+}
 #endif
 
 void kasan_enable_hw_tags(void)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5d2a876035d6..0a8d8bf6e9cf 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -624,8 +624,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
-			       kasan_vmalloc_flags_t flags)
+static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
+				      kasan_vmalloc_flags_t flags)
 {
 	/*
 	 * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
@@ -653,6 +653,18 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	return (void *)start;
 }
 
+void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long size,
+				      kasan_vmalloc_flags_t flags)
+{
+	return __kasan_unpoison_vmalloc(start, size, flags);
+}
+
+void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
+				  kasan_vmalloc_flags_t flags, u8 tag)
+{
+	return __kasan_unpoison_vmalloc(addr, size, flags);
+}
+
 /*
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..32ecdb8cd4b8 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	for (area = 0; area < nr_vms; area++)
-		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
+	kasan_unpoison_vmap_areas(vms, nr_vms, KASAN_VMALLOC_PROT_NORMAL);
 
 	kfree(vas);
 	return vms;
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3907c330d802e5b86bfe003485220de972aaac18.1764685296.git.m.wieczorretman%40pm.me.
