Return-Path: <kasan-dev+bncBAABBFWLRHEAMGQEQK3P37A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D5FE4C1CE39
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:05:59 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-639494bed86sf163905a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:05:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764759; cv=pass;
        d=google.com; s=arc-20240605;
        b=CVZ07LbO+DZbiVkozf2kPQaRskP/xmBznswtxS32IqWZbnrUX/hYJFu3YpFiixMtDq
         jdgyO/mP5UnNWlO4KmtVnHol0LgVnsiQELyHYH+zxFM/g8KlYaquA52GSgVaDmi9Ly06
         PobAiPOfuKZQ6t2zRjMWeCOv2vzukYlZXOvI/vt6VH/cMjNUW6ehmDeKFG9kolulORQx
         hjDfNu/OGkgq8Z4/PB85rNxeS9fJaUw291gbF/KqBxYZnkX1hMOpfivKI3z5/TFl0syM
         kDXqjtUuiS4St0jjrEaAXCGCp5PKMvDxVj73+KrAIxk/aEfKSkdgIghm181udslFJ9WX
         gKhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=VO58LNtIY2q9o6HgFRiN44raOeuXqnkzcpO5dxglYn8=;
        fh=PijmFwzV5wiA6+otpTcWnIiEm9XkVnVNxVnmb/PEV5M=;
        b=UjvB17NxbqzBdQquFBWf9Xt4I3uV5w8PgMa4LZ0UmAT+EPGfX/cEEDA0lEZQeYgLsl
         KSBicLbTxdQyRe2L6+IzvEdmMQafB8AKQcwgIZ6i5LM2JsNdaNdwfFFHdKHhyd5UD1++
         9k14Sd6tlugENrejKBa7SYTJDS+3wDcSoKEJppWPw97Yls/B+5GTKflZ4AczVABRurHX
         kIE7kl1e+aL1lVDVTzdK9PT8AwT52VQ4GPfA25GilIDj+2Y3AdPecwLXQyG3aKdqpqb7
         ERGHyCVmlzO2bZ+TC76pZCC3lT09s1GTwuJqqGBz93zFbvE/32nFoT0KR+ks+Mnj4rYA
         1ikw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=fFgp0OHh;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764759; x=1762369559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=VO58LNtIY2q9o6HgFRiN44raOeuXqnkzcpO5dxglYn8=;
        b=N4367/9T0eHXmmnk2TH5MZWpKiY3O8An3ot6nNKchb/gVfaVGYjNRKPbos8RxE/cuP
         p2m3VM2mjjNlathHlK54ROtY6mo9wBd9JNsTgNuUhHi+LAsci9bZvfEKzAUKuGyIlsHj
         jzxJT6fyaGs3/CjbCAkb7ii1ZWwvsjQWjPEbessr4V/KzqIN/xDcWhWft4WZ9t7/QWQA
         bFn6x05wV8+8MZ8ziPrdz2Oox24A5pHk2f6EmG/YC/OaHjQxjCkPuWrCWc2wfRPvbZFF
         mZNnx4H5FVtDNJhTFO1i0GvyJBpg60hcrsdakgjIBN6if1te10XAcczeuyj7C5Vf4SOm
         Ju0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764759; x=1762369559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VO58LNtIY2q9o6HgFRiN44raOeuXqnkzcpO5dxglYn8=;
        b=nD+0jztrem2SqETTRc5RWwxnREcO5YY3UF5vWEsJpkIaK1nbkCKSi9U5y/WMRphVR6
         UPnvAPw+/sjCWtL9KNa/v5P+vakR4W/Krw+Zf0Z1s2WHObccDx6j9pH1aRYDQMdQyX45
         hshIBoe5eovco5nZ9DqpMP93tpnI0zjmso1VcxR9s467TQO+Gxox81nP6dadrdijMZZ3
         x6g9UoovS42GmOOZA5pCgqx8DKEepkm+1AYaM6XKUqJdkNKzd2frl091kEVoAMV7oPrJ
         +w+wyHMa9wpbFSq6P0Aa59saDL3R10yu7IcZ+aYNJE0p9jQ1TkYmXvW6uFJh0XFS8CK1
         t6MA==
X-Forwarded-Encrypted: i=2; AJvYcCUqp8RKMyETmf/G7Pmyv1dT8T1IR1CHDYjcC052UyhlJyizT1goKx/xMJ8q20N0UAEZt/17tg==@lfdr.de
X-Gm-Message-State: AOJu0Yxp9ZNPvsOe5SleLUF864h1ScPun4CtWdEqdCHagoRxti+/B+pM
	ZYrTDOfTAgJZnDTj7rKLVD/9IweWsrZnAlFJaH2yIkVVvf8AJa/NBzuY
X-Google-Smtp-Source: AGHT+IEdCuVE1hwJnA7u09aIFoSoPueKxtksXGeDkSejZHNX8ejS2tS/pY/zJasus7B+1JNbQmEYqQ==
X-Received: by 2002:a05:6402:520b:b0:638:d495:50a7 with SMTP id 4fb4d7f45d1cf-640441e5873mr3403347a12.16.1761764758999;
        Wed, 29 Oct 2025 12:05:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+arGp3H6ZCffciuei9kWWbFfLXei5Adct3H8kmpcRblNg=="
Received: by 2002:a05:6402:3055:10b0:63e:169b:f6ca with SMTP id
 4fb4d7f45d1cf-6405f7c9876ls131985a12.0.-pod-prod-03-eu; Wed, 29 Oct 2025
 12:05:56 -0700 (PDT)
X-Received: by 2002:a17:907:bb49:b0:b6d:801a:5f5a with SMTP id a640c23a62f3a-b703d2b1cffmr407058566b.10.1761764756775;
        Wed, 29 Oct 2025 12:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764756; cv=none;
        d=google.com; s=arc-20240605;
        b=G687Ab5hHJX7Ka1kMfTBlj8ZmbrgEpN6TuSbpMiBpyysQAkHkShp7g8WcFVbZhSpCf
         ALAgCPVCS5yRnvBE3ip/WvAu5MI56hBioCN7eDBzYf7k43wH2IL9RlcO5wS+XOQkSmwD
         p/GNjZjYB0WUOXlGK3RkYEdolnRxPXZJHHZ1uvfREZxGNC1/wmb+3qSOlYIFZtpKE6Tf
         JbvwoSCLfgMLNfsFID/Q9UF0nzZwZDn3PIwLEZBz3Iw1afABqw4EAtrL7rRVXOGbvbZX
         uRLOboGlvZSvAcxDHvyT5EMUjVRDTEOI7hrbnsUqsdICkMgSKbZ8fKsddfJ9Dmhr2i+k
         SO3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=rr0Rm1n5HeBo5Fap/+IfVyHkvEn5nn0dcbxf514Q+kg=;
        fh=rQP7JB+9lidxxodnhH8izoSGXGEyo87czx6Msjgnu+o=;
        b=Fp6vV+S4ybw+b6scyB7iAJXG/52nK6NnGsAQIfcdF9bMVEX66DnQ1BshCbk+7Cmcxn
         37TaX7/mc/wCPLIFfgR83WLSTJpRBE4aU5sM1voBc16daewOBdtJOLXjyRnnJarvH39T
         puyT/ixs4s9pesUZi115UjxDeuctElB7KdM3mrjP0s2RTh2B7nEPrH9k9z7jjVR9DU4W
         6KJ11oW/HL9XeCb7SPH9qixw+HRrlETjK6QojpbyQNkThVLCLeVaweKR7QnTiRTtPB4E
         7ikz0Ef3MMFxYoTABGCpY/RG1NkdklStxDtJYiXyuxg84O+KACPlA6O+sF6HzGFrJp1X
         rLBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=fFgp0OHh;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10629.protonmail.ch (mail-10629.protonmail.ch. [79.135.106.29])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b6d8728c76asi23392566b.1.2025.10.29.12.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as permitted sender) client-ip=79.135.106.29;
Date: Wed, 29 Oct 2025 19:05:49 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me, stable@vger.kernel.org, Baoquan He <bhe@redhat.com>
Subject: [PATCH v6 01/18] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <fbce40a59b0a22a5735cb6e9b95c5a45a34b23cb.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: aef5b12294c25038010fe20ffdc227c541613b14
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=fFgp0OHh;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.29 as
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

The problem presented here is related to NUMA systems and tag-based
KASAN modes - software and hardware ones. It can be explained in the
following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Refactor code by moving it into a helper in preparation for the actual
fix.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Tested-by: Baoquan He <bhe@redhat.com>
---
Changelog v6:
- Add Baoquan's tested-by tag.
- Move patch to the beginning of the series as it is a fix.
- Move the refactored code to tags.c because both software and hardware
  modes compile it.
- Add fixes tag.

Changelog v4:
- Redo the patch message numbered list.
- Do the refactoring in this patch and move additions to the next new
  one.

Changelog v3:
- Remove last version of this patch that just resets the tag on
  base_addr and add this patch that unpoisons all areas with the same
  tag instead.

 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/tags.c       | 11 +++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..b00849ea8ffd 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -614,6 +614,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
+static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmap_areas(vms, nr_vms);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -638,6 +645,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b9f31293622b..ecc17c7c675a 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -18,6 +18,7 @@
 #include <linux/static_key.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -146,3 +147,13 @@ void __kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	save_stack_info(cache, object, 0, true);
 }
+
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		kasan_poison(vms[area]->addr, vms[area]->size,
+			     arch_kasan_get_tag(vms[area]->addr), false);
+	}
+}
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..934c8bfbcebf 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	for (area = 0; area < nr_vms; area++)
-		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
+	kasan_unpoison_vmap_areas(vms, nr_vms);
 
 	kfree(vas);
 	return vms;
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fbce40a59b0a22a5735cb6e9b95c5a45a34b23cb.1761763681.git.m.wieczorretman%40pm.me.
