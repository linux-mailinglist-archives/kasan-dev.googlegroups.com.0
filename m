Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJEQWPCQMGQE2SLRIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B15F9B34C02
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:31:33 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e96d4ddc8ffsf1095096276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:31:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153892; cv=pass;
        d=google.com; s=arc-20240605;
        b=JjsucejCibW7Y9U72K8UC6qiGQoErGm1SuW9zg6JUiW5BnwfLkwzpvoRFKJTlRympf
         YOxS2/SChWSDxi0IFLMr4aXpg9kXSuaVfXjeSQNunIIlERa9dvAPQeVvysoiZO5ECKTr
         RKMQJgDvVbiMxN5UcTy4Q2+qGqldQGY2sUPI5MxgwY6XJCE4BR7aVWnm1f2kuB5O5E7p
         Jl58+cmQgJpaelZLPp4gz9zgyIVqc2tbqYyzN06ffRRykC+lL7sVls5NvqvDJGT+34mk
         GqNBayUZuluGy/qlPOTBvGv7kQ+fndVriUuB+VlZmsIRyYyB9x6JvdmyLU1VvwYE6yCz
         LaZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JNp6HEonXeMIFG4X2mcvDtGufO+EV9VZl3H7OvB4KEI=;
        fh=vQyP9YQR3rLHKqEv4NB9Q7JVWRVkcLcdBjPVK58X/P4=;
        b=GDP+mO/H8WD2hPb+kqMcjAc6JMQUHq/tqKNQ/I/T5Hq4U3pOCmYiE+S6IAss+21wT/
         vGxaen2Ole//2bBRwA9vVockk2QRKjC5ciaoKojXbjmw2ycknT+WvWo969qrJVdxypG+
         +T8Tq+caB0Qw2p/mkP18r+LosDUGRvAIzJ8svI8nG0ax9RJUc1bTkU0a9i9p65zZUtds
         ChIQC/jZ/LxFz27u0vf2uy+LO5bGJuiGPEqN+BSVuoqcPZbIVqM6fVJj5lu0wUa+jyAh
         lO+whVVkBGV7qQFIE/nWW5Ju1DepULzIy5wQZUO55UXVwo8oYJdQavwSqCoHOc7BZ//E
         u6TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UdaeRrQy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153892; x=1756758692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JNp6HEonXeMIFG4X2mcvDtGufO+EV9VZl3H7OvB4KEI=;
        b=Oy8ztt8+8ih236gFFCL/VmMaGD8ja/xGGwchdZ+NErnFn5fbYaIgyVCboWiI3s8706
         1u+9kvQ2P27Xqaz7dBnpJOwzRJExy/KSeuV//ma9T2ZUag3bpmMxP/qHv/OMcDUpzwuv
         FMjkyZjU6ssYDOn2S/qdo6zEanLDeInj2a/jwyr6qJydNEgK1rggz0IHzDgQ1FP5+6Q1
         da9VGrcZHLZXamQz/Yx5J5izsjMUm2Q50ao5LlpYkCWDWsBlnIxCKY4gvPJE6wNgSBuL
         X3yA/6k6+JtejqA17LL+10EDNSOuid+Q9pfzZ/BDJ2YFxqHtRJRw/U4aQLeWw57paQga
         Xm8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153892; x=1756758692;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JNp6HEonXeMIFG4X2mcvDtGufO+EV9VZl3H7OvB4KEI=;
        b=cV6U6RuLBtl3+2Ngty9M6dnu4lC0rh+OPz4mKAgItiOG7mnytma3jTpAMPpXucNrrx
         EweA52ykTUNv/LV6APxm99dA5MG+jsuSrnX3M9iS/GsP2KuObz46C2mYiNfw4U5cEoyR
         EcWgFMvZgW6mUCgETRtXqsu9jzsdkPEjCwFwYGnDZb83WaEcM8STSmd9lF1/PUGQHdjw
         iVvv1ToNwB6McbmhuPHbPbeezO5q80QBNtaDrY/AubWqoiV91T48wDwnmfADy/7SJTyM
         J2jG5H6O6f6vHBax6sjS5lV3RNaXaFPZBrwv0JL+Y3fKbn5fxvi7jkOKifAkGd4b9OmX
         vpqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOCjzadGZHTn88ZDmshmZqbadKorPJNKWwl9zkVYblYxG22EOKP60RtxdeQ6ibPhv7QYn6Xg==@lfdr.de
X-Gm-Message-State: AOJu0Yw41BWf0UHkYA6fLXsfC4eD2m/O+veAwKjGuit92IG1K53465OK
	/FxCOi+eqQJWfF5yJA1p38kO46XntxRcUzlJR173jnrJ2AE3exacQQg0
X-Google-Smtp-Source: AGHT+IGCWvwzX3/cZ63qG7KWCgP6LxHGF6x7fk6s2SONQoV8TePrUWKPzqmK5SPqVbT2JkYBusMJJA==
X-Received: by 2002:a05:6902:6b11:b0:e90:6c38:b391 with SMTP id 3f1490d57ef6-e951c3e5336mr14856585276.47.1756153892387;
        Mon, 25 Aug 2025 13:31:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeCYgIv+W0+1f8skcBewNy91+yUVsqAukAc1LElWkcvEQ==
Received: by 2002:a25:1f46:0:b0:e93:349e:511f with SMTP id 3f1490d57ef6-e96d52de903ls690264276.1.-pod-prod-05-us;
 Mon, 25 Aug 2025 13:31:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIoCtTTqLGl2B49wOlGD8qDqxcfmyQXiv9uM4AVY/4Jzxj2+ETei/lQab3ranVZcI//w0sRRg0j9E=@googlegroups.com
X-Received: by 2002:a05:6902:3004:b0:e94:edc8:9678 with SMTP id 3f1490d57ef6-e951c3c59cemr13396310276.45.1756153891513;
        Mon, 25 Aug 2025 13:31:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153891; cv=none;
        d=google.com; s=arc-20240605;
        b=lAtJBDFGvdvLPgCSCRmw8xjD44vPCc2/BC0wvtwY1GxJ9qqK1IceuLEHvpAn+DYq4q
         +t/poKH7ohu4AF+CGLsUQyM8/dkwQUMp9l/QM3qwdrFDd8pE/YflHfMtvZ7DYjZtXOp9
         1KP0WD/djaqBK5aqUh4fc1o17Pafv+URRngi0Vn478SR5UzpjfJnAq7l29MpCvQGJTM6
         RW7le27yS2knJxC6Eg6e6ugIvh8omFIU5DycFwaJRZfEjOzpskDV0ECCw4pkEwk9UxgW
         2HE9dOFrmP/k8GIG9BwpidM4lP6L2gVJB3lR8wg9iTNsy/kgQpCr3HIt24j4E+OHGV5j
         mJiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FgG19j2BqQ8cVtEc3PQrHQvOEoJlx9KCZ9IJnwkLDpc=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=OqNdh9nv4C0EBIxRlGv+XbMke5eJejB4Tif5mOQ8ZNotOxM5zU2K7zZteqgVdOBfRR
         hFqb7PSsM0yh5ZqCNcRQ+KCwsjptbRVCALo/1gbv80VpkA8JLRs4lw9hHnY4BnjKazj4
         BhrFM3QEjl0Kl8CVVPogUl0mfXuK4Tg/7Z4hfd2Kzp6xN1VvlzjmiUgN9HJuTcXyLO3K
         FndE7RFOzBk3nXDPDmP9ajZZ62Y/vQ72hpxzmf2b+8a92orvSTUPoprTojIqMZuiE9e9
         uxsPZ+qwmiKuuWXNF5tGgYgbrQW5fnNNdlRfz1tMhq/9mn061hLrvH8OaOnYemX/VetB
         +shw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UdaeRrQy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e952c26bb59si353352276.1.2025.08.25.13.31.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:31:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: BTlbi3esTyWGoxMz+CyP4w==
X-CSE-MsgGUID: Co8KoqM4Qbm6lDHtEU2aog==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68971140"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68971140"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:30 -0700
X-CSE-ConnectionGUID: BoQjm7KIRB+2p+yFhmf/bw==
X-CSE-MsgGUID: iY6qVZe4QbiO9mWsK80olA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780999"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:11 -0700
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
Subject: [PATCH v5 17/19] mm: Unpoison pcpu chunks with base address tag
Date: Mon, 25 Aug 2025 22:24:42 +0200
Message-ID: <bcf18f220ef3b40e02f489fdb90fc7a5a153a383.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UdaeRrQy;       spf=pass
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
index c93893fb8dd4..00be0abcaf60 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bcf18f220ef3b40e02f489fdb90fc7a5a153a383.1756151769.git.maciej.wieczor-retman%40intel.com.
