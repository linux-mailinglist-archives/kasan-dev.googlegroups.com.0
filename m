Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBUVWZK4AMGQEVTNJQWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id ADDF39A44AA
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:59 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e02b5792baasf3304293276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272658; cv=pass;
        d=google.com; s=arc-20240605;
        b=ULM5ohgRbrH2MQeSkOPy2hbpqGaN8p283jXeGaO7wMoX1Rs/Mo6O3gOcGV81zXuaCi
         W72MMtPRQi9DKlBSALUcBr6dKmjde4OtmxaswrFx9q99v5VXmL5SVPm2FptadEwdEyh2
         1GPTa8Hz3TFXqYxpvDUpo+6F8A+2dpWZSOUt4RBBde6gKrr2uRXyax471JMQ0kLJ6ozN
         Rqu4Y2UwyNkcg2eRkT3BHm53VyugF9bNPAVym4Dz97rrl8iuck4tpD3wAdiU4ve5XWPj
         f5hM5QDEdvfYZiWhWA+tKb509VtSsOq0xADRPbyirdfrj1rLMptb93sXFZSUkRL+a4zm
         F4qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=UI7/zSr1JhnPQcIhB0c0L/bx0ZWLK+sziRyurzRyH+4=;
        fh=XC8bkkPn6Q3hUoqeLmcVTVGDB3EiJuAXUiw15C2sCDs=;
        b=QoIeIcpMuDdTXqeteW+JQyJ/p1UuqBtLV+T0A98CDS/vXKCEJEVyzjkLOVuaspYepi
         M/0Ey/dSfSEafYA2pVdbnv3sZgWVnDBIyGREaFgPM/STr2dm6HthgwcHIa7BLsyivgGB
         Km8cTKEH5GGENZAYG0VOur7xEkWgWcko+kUEjP02HAhXlXOH8VrvNUll26h29hhUXGE+
         5Wd8fZ5dT24qQx7NSeLN/kbHwANvvXjh8LzAogt5ggYe6vtaQbP6vu0kvgkcKe8y61lo
         BZ6OMuDQgRix2qT0V0+1fnOU0abMh0+kkM1mrsQPIgGkDZ0JxnYXiXUXKkyEBWf+eiHE
         mtbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PIztoIby;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272658; x=1729877458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UI7/zSr1JhnPQcIhB0c0L/bx0ZWLK+sziRyurzRyH+4=;
        b=grFyTjLucYdCs9nsbBfxcOOslomKIBQ92j/ciDHd7ksz4LFDXlNh9lp57JcQfIYaAQ
         KAtcsBFz9kHsXS/P/COW5L4SF9XjtVrRFJEAge6rjjlLUPCpzeWrw7ypQIwPVNByNfMm
         s0sQ+BXG5MjtCQEBstzed15ASGyVrqhkU7lm/4jtY6ur2qMPzSWIgOiHgaOrfoyYQDkn
         mbrW3+kvV6HH6LtlzNOAacnFW5zR3g4wlfXzxEOq3MrsXoVFOHftJSv+71QagHyQJ243
         GL5MDqCPGhm4MMKtDvi9IeJQioYgGwLiT3oYmn+j3tpFaF5qM3dRt3A5XCc4LtCOU3tj
         2XDg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272658; x=1729877458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=UI7/zSr1JhnPQcIhB0c0L/bx0ZWLK+sziRyurzRyH+4=;
        b=DJv00wAeA8bPzOFGTilkon9OWdA7OIYJsaS5Vvp1T/T5pVYz8urlDUDBiAOM4U2n35
         k2whYMO1bHwDoudcaL4Q9XKofzbvpEjMkv8HkmzbVfb+n+IWeyBpd6E+RhjTZmwRDh6c
         KBGaR41e/dXISvcrWcZO11ZrEtOSWAzL1nJwccGKTdUgAqZaeZpt0cIRdTC3EFepzsk/
         1PENMHMP0FF5UeEcqNDmQXJAdhGgyjlj6uMcStI2mMp818EFeQq4Ao8zP7kH5TtBPAHk
         OlfkOgn+Lc4BE6Dj6V6UgmSSgQHXeBEafMhGaVIB05J24qB/MPAwKH5YiLMHXwwr8EWT
         x1lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272658; x=1729877458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UI7/zSr1JhnPQcIhB0c0L/bx0ZWLK+sziRyurzRyH+4=;
        b=jw50xe4HCRnMvKJmvHtDUNZCNQCd0HWiCu7bKDvHoxXHaNdJK2pxH8vCuYXBzQ+q61
         6a8xvDGCeOemx0wiCV2FKswdQywA1y0+GDfMUY+h/vCDv10cGxNvEdM45i4Leid2cE5p
         T+RPz9M3LZr5fhJ8BVvWZrZzATjWHLpw3R2tXvHz672ujBXNyVNBykzgwrbtb8RH2PoN
         lj9iFrrj9xUaLCmWg14j+/P/JAkRbO3kqt7xmbh/tdx2raUrIVtrTsmx2VkR/Id3Xpqy
         GQpk2g+8n9Avn9OTxz92JMXszDVzSn883tCtCKrnnrGRJzG1mRlO8Z9NSRJVWbrDWpwh
         4vTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXs1BdQdGWjRQwpd9LCLqfSR3LZ+dN0Sgauqdz5lMhNAhQ2nDDlulqHiqDd0WjE1E5v/n6wCg==@lfdr.de
X-Gm-Message-State: AOJu0YxhcZ4D/TBcSBRzwrsK2BXq6HNcU8JJhMdWhxbwZ9IP5fu1BCMA
	HNlrCmi142gWfjpovSbByXA+S3lFgLGI8gIvlMlxBKCwTNYMuh8p
X-Google-Smtp-Source: AGHT+IEhWLx1dUnDZ9KNvtLdcicK+iYl6u7zKApN5C0rDheKlXjx7yW+ID/Q0oxKh5tBk1ehBEUAlw==
X-Received: by 2002:a05:6902:15c5:b0:e1d:c07b:a680 with SMTP id 3f1490d57ef6-e2bb1309c26mr2960990276.22.1729272658458;
        Fri, 18 Oct 2024 10:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1893:b0:e24:96b1:6ae with SMTP id
 3f1490d57ef6-e2b9cc5eff1ls2772463276.0.-pod-prod-07-us; Fri, 18 Oct 2024
 10:30:57 -0700 (PDT)
X-Received: by 2002:a05:6902:1b8b:b0:e29:67ed:96ad with SMTP id 3f1490d57ef6-e2bb16d49f0mr2992480276.51.1729272657592;
        Fri, 18 Oct 2024 10:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272657; cv=none;
        d=google.com; s=arc-20240605;
        b=AJnB+cXLgPCNvg/OMuvQnh70QgyApgG9u+BsyKUSiIyWHhOaowAOGSmrhnNxicQFtX
         sgwJbafVhEMKNRPDWwPrpaRsE9u8AHLdF2tWTFboPeUBRNn6bOf9asvC11htOklusEeP
         o+23gr3cNbPWyKt8SztGDB5hzfGfjFRy1w3uTodNBcuz804f11DE58mxgQhtujmvELMZ
         MrFiG7wu7116uInkAhhmoZnxZ4J9OKJBPFq/+Ykvu9dNi9B8fL1lqXMmDpG/HxLGig/3
         t0IPPo6X/WjA3e1eD8z87TlmNJNU6a9Uam3VlKkExPobhdDZAxz8q65u9AUH6USFEVNk
         HOVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SYv3qxbJ8XzSYVM3O5y7o2xiEmCUj8b+8LHRXlL50QE=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=Hj6EGIUwmJHobUkGECBo9NPOuiJC5R6Y+xzJJtgTZjaLatI7ZRJPZ4oo3f3IMlG8UG
         ZoKVXSOO9TPCKxMNwpzqjs0sch5/llGTxDe7KMk4tcC2BAXBUvoWUrpJn5wELJ7Ho6pJ
         KLb3hujVrSXv1+6eFbkDxsNY4n3euP6SrVdi/sUKuJujYvn+upuHvKxi6wZDA0R7yDjd
         K64bAsE3NyF08uJPARFm4YyGpxhlOkdLa6eW2Qh7J8AvI62Yk2MBfQrrv/sckIAOPYC6
         8RyVCLjp7E+mB65it7qUs47slVltUXF70Idqse7FsC1Q+kSEKzkTw24rUJlVGw0NxzAA
         TcCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PIztoIby;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bb03fbe9bsi101883276.3.2024.10.18.10.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7db637d1e4eso2453750a12.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:57 -0700 (PDT)
X-Received: by 2002:a05:6a21:a4c1:b0:1d8:f1f4:f4ee with SMTP id adf61e73a8af0-1d92c4baaaemr4986521637.8.1729272656623;
        Fri, 18 Oct 2024 10:30:56 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:55 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 07/12] book3s64/hash: Make kernel_map_linear_page() generic
Date: Fri, 18 Oct 2024 22:59:48 +0530
Message-ID: <5b67df7b29e68d7c78d6fc1f42d41137299bac6b.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PIztoIby;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Currently kernel_map_linear_page() function assumes to be working on
linear_map_hash_slots array. But since in later patches we need a
separate linear map array for kfence, hence make
kernel_map_linear_page() take a linear map array and lock in it's
function argument.

This is needed to separate out kfence from debug_pagealloc
infrastructure.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 47 ++++++++++++++-------------
 1 file changed, 25 insertions(+), 22 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index ab50bb33a390..11975a2f7403 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -272,11 +272,8 @@ void hash__tlbiel_all(unsigned int action)
 }
 
 #ifdef CONFIG_DEBUG_PAGEALLOC
-static u8 *linear_map_hash_slots;
-static unsigned long linear_map_hash_count;
-static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-
-static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
+static void kernel_map_linear_page(unsigned long vaddr, unsigned long idx,
+				   u8 *slots, raw_spinlock_t *lock)
 {
 	unsigned long hash;
 	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
@@ -290,7 +287,7 @@ static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 	if (!vsid)
 		return;
 
-	if (linear_map_hash_slots[lmi] & 0x80)
+	if (slots[idx] & 0x80)
 		return;
 
 	ret = hpte_insert_repeating(hash, vpn, __pa(vaddr), mode,
@@ -298,36 +295,40 @@ static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 				    mmu_linear_psize, mmu_kernel_ssize);
 
 	BUG_ON (ret < 0);
-	raw_spin_lock(&linear_map_hash_lock);
-	BUG_ON(linear_map_hash_slots[lmi] & 0x80);
-	linear_map_hash_slots[lmi] = ret | 0x80;
-	raw_spin_unlock(&linear_map_hash_lock);
+	raw_spin_lock(lock);
+	BUG_ON(slots[idx] & 0x80);
+	slots[idx] = ret | 0x80;
+	raw_spin_unlock(lock);
 }
 
-static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
+static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
+				     u8 *slots, raw_spinlock_t *lock)
 {
-	unsigned long hash, hidx, slot;
+	unsigned long hash, hslot, slot;
 	unsigned long vsid = get_kernel_vsid(vaddr, mmu_kernel_ssize);
 	unsigned long vpn = hpt_vpn(vaddr, vsid, mmu_kernel_ssize);
 
 	hash = hpt_hash(vpn, PAGE_SHIFT, mmu_kernel_ssize);
-	raw_spin_lock(&linear_map_hash_lock);
-	if (!(linear_map_hash_slots[lmi] & 0x80)) {
-		raw_spin_unlock(&linear_map_hash_lock);
+	raw_spin_lock(lock);
+	if (!(slots[idx] & 0x80)) {
+		raw_spin_unlock(lock);
 		return;
 	}
-	hidx = linear_map_hash_slots[lmi] & 0x7f;
-	linear_map_hash_slots[lmi] = 0;
-	raw_spin_unlock(&linear_map_hash_lock);
-	if (hidx & _PTEIDX_SECONDARY)
+	hslot = slots[idx] & 0x7f;
+	slots[idx] = 0;
+	raw_spin_unlock(lock);
+	if (hslot & _PTEIDX_SECONDARY)
 		hash = ~hash;
 	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
-	slot += hidx & _PTEIDX_GROUP_IX;
+	slot += hslot & _PTEIDX_GROUP_IX;
 	mmu_hash_ops.hpte_invalidate(slot, vpn, mmu_linear_psize,
 				     mmu_linear_psize,
 				     mmu_kernel_ssize, 0);
 }
 
+static u8 *linear_map_hash_slots;
+static unsigned long linear_map_hash_count;
+static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static inline void hash_debug_pagealloc_alloc_slots(void)
 {
 	if (!debug_pagealloc_enabled())
@@ -362,9 +363,11 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 		if (lmi >= linear_map_hash_count)
 			continue;
 		if (enable)
-			kernel_map_linear_page(vaddr, lmi);
+			kernel_map_linear_page(vaddr, lmi,
+				linear_map_hash_slots, &linear_map_hash_lock);
 		else
-			kernel_unmap_linear_page(vaddr, lmi);
+			kernel_unmap_linear_page(vaddr, lmi,
+				linear_map_hash_slots, &linear_map_hash_lock);
 	}
 	local_irq_restore(flags);
 	return 0;
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5b67df7b29e68d7c78d6fc1f42d41137299bac6b.1729271995.git.ritesh.list%40gmail.com.
