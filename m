Return-Path: <kasan-dev+bncBAABBEG5Q6UAMGQEDNLKMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 215B779F036
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:17:05 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-401dba99384sf170425e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625425; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfxMLdjeaXLengzDWzLXFYm8GMIaIyKm6WSemJ3Ci5wYxZRX4YDXFmW+O9+9STxITE
         /eebKtNYzzmYIn23FGsPe9SeOzLiiqRwBLKmy/BckPZYtr6x45o2osO6KcpzYTgc1jzR
         Dl9MR/keY+MqCqyl68Am/ANmteMdl0iQnSzTtOG3wToSfXeEGuUVM8WbjTE0s3+kab2v
         MgsfEjrQ4Wtz+0jGZaibUd1gx6lfsmC48JZ4EipupdBgrA2BkrrWxLTD9Gl9XcA+QDuC
         imnlm0BbnM/DC7IIRr66eEe+lPmciNBMOW9UyKYY62gqTtST9IKZDRu7sj+Aydr/+G3V
         mw3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5YE7vosm6MsqpGAC/C2DtgTNCTrRvXEovayypOhbOaA=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=kTNyPkwjXRU3XwZRnWTCiuaWdH4TKhsnMT4u1ixFR8CFWj9pZx/nAXTLZimaIi0Lbq
         KJn2zwu9s2uojo84FSd4suxpjs5s+2LqNwa0+TO2OcLVzcTVyeTjG2tYhMr8iXrwxhIv
         mwoCPNfMMNMwdxMzMIys4PkBO7wh7gWiZJ4eUgTSRgZFKa5EzOv6tu/Tx4qTykYf0Jfu
         sgF4G2paWcrwOpyI+NrzlJkrlCEl0byIWfxuf/gG1OAFrUrh4YWUeFv0T0z3CHmAgBLd
         VgVr7w6dEsAbVip9YQ1hpb3nZyy5aV5SMuTkT8UWuNxMw49anaRTAU0d8+XijEppBtyX
         hudQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dUDWfm9G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.218 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625425; x=1695230225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5YE7vosm6MsqpGAC/C2DtgTNCTrRvXEovayypOhbOaA=;
        b=pYL00WzKEY5iBPS39vrSMM63rI4EbuFSPORM8kYUugalnOrJzIVxAJlywQdZnyIWdJ
         7t8rYOqgMkas+XWh+S5Ib28gNcgH/ScJ/6UJaQXlN4KR8ZucrsQz3xdrdjMrE19mzrT3
         3eKAFYaqgM4WWqjoUe85DGs1bup/jyatLKTUn1mcI78OVUUIXaTKNVTxqbcpMXRIf3cE
         XEWbnCsKvoW+QWk5U2CqDNFE6jHoXvPRjNmcWKrNHeZAXAuezUIRxMm89KeEBGAH/NZh
         ia2BrBxUnrqbeX2wAJSdWdgsHY0CNdYJg4yACWIfZNHr739BNnJWB9AEzEEClo/F53Fq
         cJVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625425; x=1695230225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5YE7vosm6MsqpGAC/C2DtgTNCTrRvXEovayypOhbOaA=;
        b=R1ZOHh10vhdEhZF6ZdRajOMsD5rfKDuippen7e0wndjFjn6y73Cm1Px2Yockj1Ui8u
         V+mZWIiChYsBmR8vESQEHKrBuAVOrjwK4h1H633Bv+WTxV+zXeTKmEZPiQGAbwV3FoHt
         4/3cjtGJh9kGrpNvG9nY1SCocXpbM24dbzoHB/wZaNbyX1cpFg1Qc1CqiZVE4maqTHIK
         HNmsjkPj/sinkdrvqOOo6kc5VwVU03O2LMAFCPe+iJI/tCHvhCvEXJ3GzBSt/1kNX356
         E2EfM7xSNJwS6qk5ZO9xA+OpTRUipbbMWtqEaxbAt89uGAyf4t/xMuVq1bgTNossHj2g
         6X3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxwbGxJ1q4u4N/bhX6ZpmDP5EHKefz98F3vz24XgC+osnEKkGjN
	pEABVYlZice53SAkGxr9ElFJhg==
X-Google-Smtp-Source: AGHT+IHW0tAU5vpj+uRjKiHfM/7vpQZNEtRyuYq56/iCxAOGjKzCJPaWlGB5wLYOCJQ+79OSnA358w==
X-Received: by 2002:a05:600c:2216:b0:3fe:f667:4e4c with SMTP id z22-20020a05600c221600b003fef6674e4cmr2669655wml.12.1694625424373;
        Wed, 13 Sep 2023 10:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba4:b0:3fe:e8fc:6975 with SMTP id
 n36-20020a05600c3ba400b003fee8fc6975ls3747908wms.1.-pod-prod-04-eu; Wed, 13
 Sep 2023 10:17:03 -0700 (PDT)
X-Received: by 2002:a05:600c:214d:b0:402:8896:bb7b with SMTP id v13-20020a05600c214d00b004028896bb7bmr2715453wml.6.1694625423142;
        Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625423; cv=none;
        d=google.com; s=arc-20160816;
        b=KT1491pTerpwilkUhyFxdVVMDTjBiMnOfhHyaFqvcmjSvfbKXIjminLt6RFl5wwtA2
         R9gq1OTkWqcx7Dh2W8d6tjpaEDbXKO7AuYg3kLqABJ3IOxAbM30MeOn6D+eQPSejYoRJ
         Hv0omgE43X6bBlTbJHu0YjH9gab3KceEdlMbzm1S4wNMAkjNhhhSkhOK80cnO+xywk3E
         iEsk4S5q9XguSPC4tXqCaxGO/Hb9zELLXWi9BHfBzGRJVLaJLHjSeF+JK07MpT7yxwYt
         xtWw+A4Se8pyEKzTLvwwjDasKequOl6zkuKn8AF6s2xnUs/JNqtNvTzbI31Yfrj0gUuq
         Gtbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=P7zzoSFiMvzmGoSw/qnaD/dTzTEPv955C3ixzUuxzB0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=z2m1ziOgKg9cgyTulif79XgcgGg7Dbifn73KPgHbp+gcUpeelisN4dRCEwU0dm1V+O
         AlyhsrILUaUR9xbuLA3lngVtjhctArVs3jC+apVcHPLdqWyk0O6txxsafHu595wU/N8o
         14bJv/yCFqb1ZMUe42J7O5zD2vTIt1ULehNFKzebolnni/8c1eH2bMvxCpbki7iLjPlG
         OrFiZCPqUiW5ec+5LtVfJf/bAaGx/YYfg5Skb+z4oAs7neGNkNroIUrns8Gyc7x/mewN
         mQyBOpOFKr7fLXu1EkYxupUBt3WofzuGy5daWhO57ofCIXN+x4uP3wXmHDUF7w6REAY3
         hEPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dUDWfm9G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.218 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-218.mta1.migadu.com (out-218.mta1.migadu.com. [95.215.58.218])
        by gmr-mx.google.com with ESMTPS id p25-20020a05600c1d9900b00401bbfb9b35si235056wms.0.2023.09.13.10.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:17:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.218 as permitted sender) client-ip=95.215.58.218;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 17/19] kasan: remove atomic accesses to stack ring entries
Date: Wed, 13 Sep 2023 19:14:42 +0200
Message-Id: <556085476eb7d2e3703d62dc2fa920931aadf459.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dUDWfm9G;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.218 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Remove the atomic accesses to entry fields in save_stack_info and
kasan_complete_mode_report_info for tag-based KASAN modes.

These atomics are not required, as the read/write lock prevents the
entries from being read (in kasan_complete_mode_report_info) while being
written (in save_stack_info) and the try_cmpxchg prevents the same entry
from being rewritten (in save_stack_info) in the unlikely case of wrapping
during writing.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/report_tags.c | 25 +++++++------------------
 mm/kasan/tags.c        | 13 +++++--------
 2 files changed, 12 insertions(+), 26 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 8b8bfdb3cfdb..78abdcde5da9 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -31,10 +31,6 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	unsigned long flags;
 	u64 pos;
 	struct kasan_stack_ring_entry *entry;
-	void *ptr;
-	u32 pid;
-	depot_stack_handle_t stack;
-	bool is_free;
 	bool alloc_found = false, free_found = false;
 
 	if ((!info->cache || !info->object) && !info->bug_type) {
@@ -61,18 +57,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 
 		entry = &stack_ring.entries[i % stack_ring.size];
 
-		/* Paired with smp_store_release() in save_stack_info(). */
-		ptr = (void *)smp_load_acquire(&entry->ptr);
-
-		if (kasan_reset_tag(ptr) != info->object ||
-		    get_tag(ptr) != get_tag(info->access_addr))
+		if (kasan_reset_tag(entry->ptr) != info->object ||
+		    get_tag(entry->ptr) != get_tag(info->access_addr))
 			continue;
 
-		pid = READ_ONCE(entry->pid);
-		stack = READ_ONCE(entry->stack);
-		is_free = READ_ONCE(entry->is_free);
-
-		if (is_free) {
+		if (entry->is_free) {
 			/*
 			 * Second free of the same object.
 			 * Give up on trying to find the alloc entry.
@@ -80,8 +69,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (free_found)
 				break;
 
-			info->free_track.pid = pid;
-			info->free_track.stack = stack;
+			info->free_track.pid = entry->pid;
+			info->free_track.stack = entry->stack;
 			free_found = true;
 
 			/*
@@ -95,8 +84,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (alloc_found)
 				break;
 
-			info->alloc_track.pid = pid;
-			info->alloc_track.stack = stack;
+			info->alloc_track.pid = entry->pid;
+			info->alloc_track.stack = entry->stack;
 			alloc_found = true;
 
 			/*
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 4fd32121b0fd..b6c017e670d8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -121,15 +121,12 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
-	WRITE_ONCE(entry->size, cache->object_size);
-	WRITE_ONCE(entry->pid, current->pid);
-	WRITE_ONCE(entry->stack, stack);
-	WRITE_ONCE(entry->is_free, is_free);
+	entry->size = cache->object_size;
+	entry->pid = current->pid;
+	entry->stack = stack;
+	entry->is_free = is_free;
 
-	/*
-	 * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
-	 */
-	smp_store_release(&entry->ptr, (s64)object);
+	entry->ptr = object;
 
 	read_unlock_irqrestore(&stack_ring.lock, flags);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/556085476eb7d2e3703d62dc2fa920931aadf459.1694625260.git.andreyknvl%40google.com.
