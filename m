Return-Path: <kasan-dev+bncBAABBYXGZPEQMGQE3ESLQPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2452CA80CD
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 15:59:47 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-88050bdc2absf54852616d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 06:59:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764946786; cv=pass;
        d=google.com; s=arc-20240605;
        b=d2xNv9hbChWQF01uVCOGT0H7iZkdng+3P40N45uGtRR45kJ9CfxASy2kyyGq/KlglI
         XIxY30BpdL6xOW947hFMfLvd9Pr9R3P1mmBto3CJk9DGzZrMB1pL64AaJ4+WWxCzTPlQ
         BHuTRm+8Fbi98tzFF6LAzEH4O9Tc8qcj7ZhWBlMeTH6D1bowyEdNX6ZvL00bS9Vq/5Hy
         fPOPu5T61aUcpGob3ITDhGA/Uoth5RHhVzbt0Vv/qUEXXCEfvlWJe8hPhvPtpIf1F4cG
         zq5xXOj/CurIuVHgahRLMnX6v0Px6RSPM6QJHV4XJxh0Nysa+ay5lhAYMhfV0YFS5g8J
         Re5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=N6Gn5dYw+4415B4Uaf+SgT/1p53eMI3vVPDttVE/SGo=;
        fh=t7j+i1P1bufZ2YgHMVFdNL/ygoUNKXOlEE/wkPNB83k=;
        b=Z3bqd+KiuMBxXd7va11Wa26Y4hfCALrgbqoSxksrdqp9QsAJq82n+1JXsZHPA20Ks+
         HQP6T6GzNy4o/AMWRh1idWKoZxB/JV09puldthfnrqMMadiI998wGpacgFJtgfIlsMOk
         xGBzcZyeGykAIsLkKMPpqsRaAL2zZ6lWyKbPP+428obVgiI4nll80jnw3nrHjrGBYAFm
         EwzEVEiewSswyB8ETFPkHV/escBhHmN6SuXM6AgzTcf42rEGMsZvUay6FJ7aJCsRDO1C
         P2OfZmVgw8EtFxhC07bz24iPOON37UY2YrSCEnA0DdViYm7gYFJUw2rnbFfCCJNBQuVP
         59Rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="ZOWGS/m8";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764946786; x=1765551586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=N6Gn5dYw+4415B4Uaf+SgT/1p53eMI3vVPDttVE/SGo=;
        b=Tf094xKtVYsErJSus0dJmqssZZ4O/44UbOhrkkmw1ntBegMkSOS8RDUdSaJ+BxFL5c
         J/84vOup3EM0dbVEsZVfWT2xG/Oct3HYGZlP7FlawIdTxJNqm6MxJk3Mq1nhxvnP82OI
         QskL7UrgkGQygJJfzHG+/gRgUTZuW6VtdcMbTQwAaT/gRMY3rjwKEmhaM4tb4nEx01jR
         mbzYSlM1jDFguP5eMKxRo9cEnjDTurzDeKvsJWxGfW6/DpkmcJgCpYTvv6ywYxOUI9lH
         7wy8h0D/pWwhhmG57d7RWhCTfHc3Pyi72LsbEqwDA/KAcvf/vruZkMDGVQjdaEpkmgte
         63+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764946786; x=1765551586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N6Gn5dYw+4415B4Uaf+SgT/1p53eMI3vVPDttVE/SGo=;
        b=TsIIBTFIY8Il3S31CJMqPp4MisjDkvqKOJsQoj0wyADbrNPRna+suyxXuslUmX0hsF
         8HC8Ezyxnj23bzCel7W6IXfQsNfvBdwLpAZJcl4QIQlmioDWRU45vqiu6hLjloT9Uj8d
         ccGwIVfeK+JkFqIz2V5lHEojygjIAeIBo3tUWkd9vQi/2/gg0dSuU+N5JxaqWZKQaL1e
         RTZOFwWgWI2CXF1nPclH7JY1QqsINKMSOmIKKdP1nS5F58FcTsuKVvVAcMwy4Rf6rHTo
         NSIptHlEbt5zKThnoi7Uf7dC5E3fof7FRtjJvueeq57jvLlimW9z0bAIpEEXeMPuJ98Y
         G75g==
X-Forwarded-Encrypted: i=2; AJvYcCUDeuP8EvB+zKsk2GcjJ2eWPkrPWevzQVnWI2gQr162Lvb2cJUyV3Yls885sj+cU15htJc4Ow==@lfdr.de
X-Gm-Message-State: AOJu0Yzw/yMZGEhFNjhVSN+cLn3PGLSDiPFlPGiZ6vwyQsZrBqOBY7hh
	R49plW8NmK3rG1V7Runrgu2ozR3n6FeZYyAC1jJHLV3NfFNJ6fNnZu0z
X-Google-Smtp-Source: AGHT+IEYkEtJlVOK041KuoVM9IQO2WGV8VxsX5xFVmR/SbFYq7WyYSDw7C3nCcsMhroTqrrA7TrWUA==
X-Received: by 2002:a05:6214:5006:b0:87b:f43b:89bf with SMTP id 6a1803df08f44-888248cda84mr105981536d6.65.1764946786497;
        Fri, 05 Dec 2025 06:59:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ+kpmOnU3Idqjfa3kE+0y5BG9EtjaduPs2/e0PVWuZ6w=="
Received: by 2002:ad4:452f:0:b0:882:3acc:d7a with SMTP id 6a1803df08f44-88825c8652als29925946d6.0.-pod-prod-07-us;
 Fri, 05 Dec 2025 06:59:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQVL5wvm6tkXL1GnkKu+vvVaJMj/hZsQf+jFbPni7kwOuhmRn7w0iQm93tDUbpGIkyAXIgooMAiWw=@googlegroups.com
X-Received: by 2002:ad4:5aa8:0:b0:87d:fde1:f88b with SMTP id 6a1803df08f44-8882481342bmr104591116d6.4.1764946785556;
        Fri, 05 Dec 2025 06:59:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764946785; cv=none;
        d=google.com; s=arc-20240605;
        b=dLS+O3U/veJ9lm8QViK5IVdsaVSYVTT9fv9ivZnIAl/E56EUxaL0EgF68lMyGa2FQG
         tU9F2PD8fLvGTztzAw7kIlwWNH/27vevIJlRmaJxVkojs+vQ7JYaOJ08uylJeBgeTtd2
         nRnrKxhwBVal3u8LoCwQgYoYGgljkhaV/5Gk8oh+hjATW7LbPoKEFqNtRnoBz6mjGQWj
         ubThllAINWmiUWEQn+d3L8F4cbBBTxhwPpcAaKG4rcMK9tSMR2rlJlN/oh8DBlZrFgEP
         Us6wt57486y/bkCmawCgSsU4noEO36AyWSjEKrXShAbG+bOf6wbRvzgO2WP5OdZz1JkI
         gU5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=qIyabYfRYXeVwZVp9LPPfWirGseEPkYszpblk/XZ5Dw=;
        fh=Q62I/a3cma1xfG+DoY2hkIOTVBio5FSBGAAddRE1Zq4=;
        b=iUcZnlNdWgDtWoimQHoMMK9ivVRga2v9XVMVpeq7s0bku8LFXmT7zZLtz0jjDmE+6W
         wc1WME0GrrbsU3Q1brThk5c4ap/uemnwbenxInXH35+DZXgZ1PmD8GHaFeXDaNuNJPrk
         M3HAH6iAZ138b0u75GNA0a4xKCB/XvgeeOd6Zi0UUo28yhJzfEeBUOhOmAsESxPVCHC0
         7p1vVEIK/ieV3e1KKhzAZ0kn2CdGLcGOzQGAeOhhIW1tYNgy3U+v7UCH9Jg1xE8QT8FE
         GuY5fcYJoqXWk8nvMhgDh27BHkqXfwYdfXAUXqPk8l8A9YgKbyeGYoxvty8IlzR3G/+w
         9nzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="ZOWGS/m8";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244116.protonmail.ch (mail-244116.protonmail.ch. [109.224.244.116])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88828289524si2402006d6.9.2025.12.05.06.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 06:59:45 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) client-ip=109.224.244.116;
Date: Fri, 05 Dec 2025 14:59:17 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v4 2/3] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <6dd6a10f94241cef935fec58c312cb846d352490.1764945396.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764945396.git.m.wieczorretman@pm.me>
References: <cover.1764945396.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 948f454a99eeea8eab949328f562c02766404396
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="ZOWGS/m8";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as
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

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: stable@vger.kernel.org # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
Changelog v1: (after splitting of from the KASAN series)
- Rewrite first paragraph of the patch message to point at the user
  impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

Changelog v2:
- Redo the whole patch so it's an actual refactor.

Changelog v3:
- Redo the patch after applying Andrey's comments to align the code more
  with what's already in include/linux/kasan.h

 include/linux/kasan.h | 15 +++++++++++++++
 mm/kasan/common.c     | 17 +++++++++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6d7972bb390c..cde493cb7702 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -615,6 +615,16 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+				 kasan_vmalloc_flags_t flags);
+static __always_inline void
+kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			  kasan_vmalloc_flags_t flags)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -639,6 +649,11 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
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
index d4c14359feaf..1ed6289d471a 100644
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
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+				 kasan_vmalloc_flags_t flags)
+{
+	unsigned long size;
+	void *addr;
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		size = vms[area]->size;
+		addr = vms[area]->addr;
+		vms[area]->addr = __kasan_unpoison_vmalloc(addr, size, flags);
+	}
+}
+#endif
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 22a73a087135..33e705ccafba 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4872,9 +4872,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6dd6a10f94241cef935fec58c312cb846d352490.1764945396.git.m.wieczorretman%40pm.me.
