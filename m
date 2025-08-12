Return-Path: <kasan-dev+bncBCMMDDFSWYCBBH4E5XCAMGQEVPVC3YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CFB5B22880
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:31:13 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7e82b8ea647sf1145921985a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:31:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005472; cv=pass;
        d=google.com; s=arc-20240605;
        b=SsrHtaoNIvGxruEA/Cw0rlgGcdlGUbb//DzkSA27MP0jmq7pLU2oTB5xe8E89ekUSf
         KFuFuefmFKThe5iE5Sy4unC048mJhFLm3D3JISXnFS9a3MTWTyq+KIu2MMnnCD50KWrP
         vcgWayGRJ6q/BAqEOhJLeyBJCqKOZWTGoi2UYDY+IwqkE3rdAthjoM8varrJIhEbZ+Pt
         x7R8WDFOMY0LCjI+O0u9fLFz5M9Ua+3+oW9OoGOcRomYyeka5Hpc4WWI4o+0Iq4Qdcqe
         l5XhVpp7bZsiz+EqXLLxMEe77R3JzXzGEcV8TRUL+NUroEsTqGuhA75IJcVdMIEvJMwI
         /5eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WrZnR1a/Wnqua2oBIaLz2sIV4Ym6GzRrtYiTbxHsL2o=;
        fh=pYy3ilctRcg7FThULdAEHIpcTKUNu/O3xKT6+ESDJnM=;
        b=fd5ntgnpFWv8lL9G7J9f1dDcAGiTOj2XAFHwTnHoac14fHT3c4R702/BmWaj+7s2t5
         58VokDsX26JFK57c+S/6cuQPZtulyjOM5TyKqiXKZ4IpoyXyK/05hEOi2UNMJD77K92c
         2RTddPqIHh9JZ3MoZcKlob/l5nxFlKX774V6YiLSlRIJLe5vkgXnzklhD+GAdcgkyaGF
         vPsRSzvl0NCegSdqJil/SlEblf4Nl0ICqNBkZTVh4OMep30sofwXG+W1By2eJ12yssqF
         WYCceefUCv71GyJDe7jCEF+Cn9N/9XmTkvHmZ08DYcvzCLr2/FLDt/L1czGf3xc2hHc9
         PBTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nK1AKjUy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005472; x=1755610272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WrZnR1a/Wnqua2oBIaLz2sIV4Ym6GzRrtYiTbxHsL2o=;
        b=ZecRDOsSGhIYYVOQECkXtomAGq6khHybm3FbL8LL54FNfPnU4zqZaT4KJJyHYdThKv
         khSNQ8b3vNximhEcgPzyfaKOndai0lIWqWWDtSdrP7/U7fRL74TB1oWUm/7wq++ZHA4t
         pIhxS9s0RYG7eztIidFhLw4+v8Rse7O54E4vPeTuqRCsM9xBr9v2uGi9AcPyiNeR7Swb
         tf7CFVhKolnPv+4OQxgWSP8W2Pw9VYadVt5i3u93Aeeis3nL+xLklKhzjbT6YxK7YHjZ
         h+XVh9jQX+ZD5Vh8yFT6W1Q4sIJHLtnN78sgzjLqQJ6E/h7lZcZOp3CqPVRoPUlZrRd6
         UTrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005472; x=1755610272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WrZnR1a/Wnqua2oBIaLz2sIV4Ym6GzRrtYiTbxHsL2o=;
        b=ZRHWQO86Y4y8/5vKuWC2qd3Po5+ptvkjqhAfnkLqfos4F9Gtxiutb7WX62uwGkTqVs
         HhcCbY4wQuzw7SYkIN2HqFxMwTNmZ8zWIcZqK+j2DVZHOzrxLZWOaRGISERTARxI99Ea
         yrLh140eMztMqZIPqjW6+6Gi0rfyoQpcgSENsrJHjHwbFPWqzbcJaEAX/eMGDmY9YbVS
         rU5d1BdXOVC8ZUNKo2MF93eusuo90uawxjpysjpe1QQs7oSE5G508oSHlHXpImCDB44T
         vw5vfTDrv7IGr6tXQc6unsdHZmVNNS+Z0HtlnTMsB6V13dBlTs+xMWQ2z9k5hvhzhbC5
         0CxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoIKrAIMkJiqsBI+9BDldvXtlPE8WiTltHMZmCYeMqQxvxkfsKKJBxPRTGazfocCJVIzgYsg==@lfdr.de
X-Gm-Message-State: AOJu0YwwVy5lrjuBVTENWDiq8Y95f0b4MSWF3mfC4ZKxx0DxHOFoy+S7
	pkVWs7pWClqCVQna/BTi2YCwm+qAcafsEEJpTBKgGcCXzX1VT9tv8I6m
X-Google-Smtp-Source: AGHT+IFpmTXJwDZIk8NysgpMf3jfGSbouUSF3p1JiVvDQsCiyPJPa3xyh4n+biUQOGwCsCtpHV28LQ==
X-Received: by 2002:a05:6214:5090:b0:709:994a:f8b0 with SMTP id 6a1803df08f44-709d663a889mr47932396d6.0.1755005471778;
        Tue, 12 Aug 2025 06:31:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdfVBxb8CY3j/o/7lK2dU4Yd5KW01l8At7It5qZqjzBQQ==
Received: by 2002:a05:6214:4e8f:b0:707:18b0:de30 with SMTP id
 6a1803df08f44-70978bb2475ls40645716d6.1.-pod-prod-00-us-canary; Tue, 12 Aug
 2025 06:31:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFZ2x2LnVknBU+mmMoOATCr/8LeIDHgyOT7XhonYbAlHn3lNNs+F9vG7y97vA7whtBZl2lG4LnkyY=@googlegroups.com
X-Received: by 2002:a05:6122:794:b0:539:4bf9:233a with SMTP id 71dfb90a1353d-53afa0905bamr1471697e0c.5.1755005470466;
        Tue, 12 Aug 2025 06:31:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005470; cv=none;
        d=google.com; s=arc-20240605;
        b=LJf261mOefY5WTWgPMYf5t7Pdj1yLp/2LG63dJWto9Zp9bEKwGye3/0ytkFP3qIqzV
         HXGrVelCHgcVUCQEOJMv1/Xf79/qKNN7hRASHgWs5oiDEYfvQfPw0N0MukitUcTn7PdP
         OVI91NAJnFl1N1ETAkO1BvWMxlxnbknj7vdFbn2DjacVEy4JZScnTs7W1h0NOrDl5IIn
         dubu3HTyeGzuXZ3QKrawvowclyWsYvfwHh3C4qcsOSq1Urf6m8Mm1MLFd7C53FbLJtFo
         TmMG2A5CSqX5ax2oBUtfBbBdRURwreAn6oENeiinJ43LzEEbBH0UxBJZSC0O25zuB6cU
         JREg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L+edTXQcTXvLIKifsLnkJA7/3GYnbD7057WahxLr9Lg=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=Y1h43D0ekRpThhC3M9g7CRlkFH2qCx4LTeQUgCwD9vLF85wMZDD/ZJ937B+Rfxn0wX
         JpA+TTeZchqNdh5/BlZGzv3wclAxQI/ZW5pXO418bCV3eFKKBx5l0PFfbjqcdtYz1oXk
         R7+ETsew2ikAQg472dmi28Jqn5Lw5lPYTUWACzoOXuO5g73HRXCbitI51TmRQY72qyj8
         QI6me54IxHGA/4wLNhBUb0+oYHc4SlYSTa474iAYY/fK+apjImoltKVYAowrze4hSK6S
         uv4btnzzm8jEJynf8HqJLl4UtaWhfIA9RuYXy5zpHWstVyZK482+OSJ2Nung3R/fey7/
         WygQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=nK1AKjUy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b0258660si679566e0c.3.2025.08.12.06.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:31:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: JCSKQHU/TniOP2UcZpabtg==
X-CSE-MsgGUID: cz/9iiHBS/ybmBqWfUYa0g==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60904054"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60904054"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:31:09 -0700
X-CSE-ConnectionGUID: 310Nw93RRXy9OmSdy8cVzA==
X-CSE-MsgGUID: xzKkOVDzSASmChbZfONGbQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165832087"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:30:43 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 16/18] mm: Unpoison pcpu chunks with base address tag
Date: Tue, 12 Aug 2025 15:23:52 +0200
Message-ID: <f3519195a98428998160d272997a3d2ed6c53c6a.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=nK1AKjUy;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

The problem presented here is related to NUMA systems and tag-based
KASAN mode. It can be explained in the following points:

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

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Redo the patch message numbered list.
- Do the refactoring in this patch and move additions to the next new
  one.

Changelog v3:
- Remove last version of this patch that just resets the tag on
  base_addr and add this patch that unpoisons all areas with the same
  tag instead.

 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/hw_tags.c    | 11 +++++++++++
 mm/kasan/shadow.c     | 10 ++++++++++
 mm/vmalloc.c          |  4 +---
 4 files changed, 32 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 7a2527794549..3ec432d7df9a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -613,6 +613,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
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
@@ -637,6 +644,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..1f569df313c3 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -382,6 +382,17 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	 */
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		vms[area]->addr = __kasan_unpoison_vmalloc(
+			vms[area]->addr, vms[area]->size,
+			KASAN_VMALLOC_PROT_NORMAL);
+	}
+}
+
 #endif
 
 void kasan_enable_hw_tags(void)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..b41f74d68916 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -646,6 +646,16 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		kasan_poison(vms[area]->addr, vms[area]->size,
+			     arch_kasan_get_tag(vms[area]->addr), false);
+	}
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 83d666e4837a..72eecc8b087a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4847,9 +4847,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f3519195a98428998160d272997a3d2ed6c53c6a.1755004923.git.maciej.wieczor-retman%40intel.com.
