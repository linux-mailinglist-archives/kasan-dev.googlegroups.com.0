Return-Path: <kasan-dev+bncBAABBHXKRLFAMGQE6TQ3IYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E342CC7F69
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 14:50:25 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-7f89d880668sf5255109b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 05:50:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765979423; cv=pass;
        d=google.com; s=arc-20240605;
        b=IF3mBcKq4cJK2SjLNZut3DMRk05pq5Vl9rurr06GoKC/QhQBNTRn+B5gjsJeUwxhlZ
         hJ7TkZdpW4u/QBODb9HGpgZ36J1BWyq6PuUar+02tG7/m9eRd6SuEdVLzZndLtuRuH62
         8BaLcROON1JsYHHjUKgjmnPudODqeGMWIerLayDD9YXwSf4SUbxkqO5o+df9b1Ghfm16
         WeZnkuCSfokyoA13AyRaKJiJRh/gz73z8C6TzqRTReUl4RRUjte4Me4fsFnVCC3aItx5
         s0uLH9CWQf5xAmhRy65YNQUN+nwtMClb9Tb2uoEzAPzAAalt1lGIw9lIfHQ0POq73nF7
         zPIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=HkUSDPdrNsKGV6HImFBnHWMGGFzTFzorSj147mxLaWE=;
        fh=0JTbINkhirWM2/guQCq3QiYTnjYfU8r7h94cvoSDUtU=;
        b=Fzcs1mqyV7gBOFe7gycTjV9zL+Zserbnpg1woAAPxkkHHuzejwddf1cU9bpRPOMT9l
         yGEGh7KhJBLsICtM6m4mr3ZFALYNwgPjKUWvvtjmHL+2vuEtXOIujUiJhOIjWiHHOzj3
         tkU5/plnoPFuxJFp3ILTK9Szx12FZ9VK4kot4ij3kyxAqWYsUpFvXaRXsJAGeifNqZHO
         YOtl/Y6WnGTmYiC4eECk0Z29mdl5Rgxmx2iz5PH1r/nX5NmImVMiIgcbG+/DoDlU5LCJ
         J+FzM8qqsIVrdeF6FUrzAvmlaAar3guDGJCOEICxRnYHGmUOhp3x2Sf4Hw3GNGhHp04X
         NI6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aaO2qhro;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765979423; x=1766584223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=HkUSDPdrNsKGV6HImFBnHWMGGFzTFzorSj147mxLaWE=;
        b=Vi7WX2Gwo9jymf9abKL+FzZHX/0rkuTd/7ri9c32yVWjRbMprF6TRKBi3d3wdkw6U9
         QYA4IB6PYByuSzL8MevBs74OOLOLuTVeL3RNSJaiYHRpImXAyCGerme2yQBUKyxjmGtY
         OFzpKzyvbgLgtlL29JbpWFZSLroys1p8LScxIm0Q17N5n8BOS0Wkyoph7CzXQWPKFTRq
         H+hFMox97AiI8KIiQuMVjkFfzZYADYPkk9tFeZghP3JRCPnVduknDrKoO/+vQL3Q2X9s
         ZmrhMedGAmhbmDrlrknGyUf5IHJm1P20GavThYKhQ6DscdSZd1oQg5ZRBUOJFHg1UXR9
         desQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765979423; x=1766584223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HkUSDPdrNsKGV6HImFBnHWMGGFzTFzorSj147mxLaWE=;
        b=GfGsjGjRFtBn4LMu1U/eq2gUVbOP3joJaGyc4y/lsw3ptF8ZkFs3BOh0JDsT4Jt5wa
         gmIgzBvtR9g380O0O7cXkXjofW9vIAp7b9QaC/igbU2K3JKD9zfbBfyCTs+6Q7nrhlgb
         T269tsSpCZrS3uAbvFvmXGrbIiWRUTEL6sBN3keQbp5JieLp2Tw5C1bNuBaiPg/1tPTV
         FsJsmDCKt2kg+oDvd2ohO+feUoq+VHy+e1ZCM2Y0plnKzwSkJej6ioqGwGUoKjbACH+L
         dH1OZik4uh3RQkR6ilYLm+48+4CaM6HygiGBPXrCHlVimtUjueRoBmg6lNGqwzLQrvUP
         EeoA==
X-Forwarded-Encrypted: i=2; AJvYcCXVqF7djpjnkEd/Qhq+IEOyHvw7Q56cdzoaByMFauxYNssC+3bNab4l7bMBLTLLsDqmPzeMLQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjTG7kklqy20bopmnkvq6jVbiwG0GhasJViIS5xuMuUb6a9oJo
	NQVZiKkVbRac/uedWAjLlVmLApg4SbsSGc/IHU01VDgxYuyfe0Qz8/sC
X-Google-Smtp-Source: AGHT+IELDwEe3qfcxEMuA9+zv4bQR6jKE53HX7ePQZVJKTmb4ij92Rz+7bnspdAe7SYzHKTeB7w6Cg==
X-Received: by 2002:a05:6a20:e292:b0:35e:8b76:c94a with SMTP id adf61e73a8af0-369afdfbbe0mr17550099637.45.1765979423277;
        Wed, 17 Dec 2025 05:50:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbJX3red+0fkdn2q1GmhB3mOA6/WnwMWeRbs/slBIdPlw=="
Received: by 2002:a17:90b:111:b0:343:63b8:b29c with SMTP id
 98e67ed59e1d1-34abcb9622cls3710280a91.0.-pod-prod-02-us; Wed, 17 Dec 2025
 05:50:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVMGdZe7FCpQcLmPsyxkod2WhdySMHsdO6h5fatKEhLpDrUFZmhSJZV8UA+RnkfOKSlRDfiP08L7ZA=@googlegroups.com
X-Received: by 2002:a17:90b:4b82:b0:340:c261:f9f3 with SMTP id 98e67ed59e1d1-34abd6d350cmr18457184a91.14.1765979421760;
        Wed, 17 Dec 2025 05:50:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765979421; cv=none;
        d=google.com; s=arc-20240605;
        b=JT4wmUr0PEJJJ9oVZ9XZBsBLivClIuf1gMdEVSIJRnjtsoIATsV8SoIu/ppNK/M+sd
         1wsdEQfx/Hc6qnu25jnbEWoJXTYqSyLtMJ36vJNajY0nGBnzgTtgQtMjElliVOyasiBj
         jLKichifEabXHz6u3Mxbwp2eq7XQYuFc/noeNBpcXo9goAHQYyxM7ndOOxsvebivC3Yc
         Ls81kGkxzdxa44LB7/66Ye27pOW5+S0KOqrp0TSXBFA6JU8ALVpe2W+PAsCIDwIwYnuq
         kqAk8q/vcU/MPqoRSSvkGcPZqJQG2BUzWWmiH1d6i20PEtp47We4oDHAaC6JeF4x5HNs
         Iv3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=s2JYxSYT5Izoz83uHW43rnJd8Vyki+WsPGIbQcYTHRk=;
        fh=aqCEAX6O4H2ZnFi00eAjOvKUkTzdgq7GuBdDReHMTi4=;
        b=F2H1zeVyltCuVN7+r7tZPWtfEZ8XXLxz0VRFBIMC5CiSZP0VLCsNNbN3kgKWWOC66V
         YRxDbiQ8kRdAaEyvkdgEiH1EUUh50FfSnHmRFLYyKBY1Lz+2DNqfu/v8QGhirIdG3jJJ
         XnjXmBtGYs96QYNCW3OreW9tRiSv50nEJO3M1t7kvlpvjxxktWEuvVwCrUmtNfvqHnvv
         xfzZSLjOPBK+u2IyojLS9ycDHhnN8CAVkyk65yFuOZR84iejVXbzgIXSo5V9CamUSKcT
         tJW1oSdG3R1+6bEPEqbaS4XQcllS6zU9aHeNvrINZahv2H50dsI8jne14/MIF0Vq6igF
         Zc1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=aaO2qhro;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244116.protonmail.ch (mail-244116.protonmail.ch. [109.224.244.116])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34cd9918bcasi63744a91.1.2025.12.17.05.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 05:50:21 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) client-ip=109.224.244.116;
Date: Wed, 17 Dec 2025 13:50:15 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v5 2/3] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <aac5a2493bdd16e99d879d2f92944e62314f2465.1765978969.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765978969.git.m.wieczorretman@pm.me>
References: <cover.1765978969.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ef69e21d81520e5a8eff366705d9de1d575b6ec0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=aaO2qhro;       spf=pass
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
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---

Changelog v3:
- Redo the patch after applying Andrey's comments to align the code more
  with what's already in include/linux/kasan.h

Changelog v2:
- Redo the whole patch so it's an actual refactor.

Changelog v1: (after splitting of from the KASAN series)
- Rewrite first paragraph of the patch message to point at the user
  impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 include/linux/kasan.h | 15 +++++++++++++++
 mm/kasan/common.c     | 17 +++++++++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index df3d8567dde9..9c6ac4b62eb9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -631,6 +631,16 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
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
@@ -655,6 +665,11 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
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
index 1d27f1bd260b..b2b40c59ce18 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -28,6 +28,7 @@
 #include <linux/string.h>
 #include <linux/types.h>
 #include <linux/bug.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -575,3 +576,19 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
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
index 94c0a9262a46..41dd01e8430c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -5027,9 +5027,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aac5a2493bdd16e99d879d2f92944e62314f2465.1765978969.git.m.wieczorretman%40pm.me.
