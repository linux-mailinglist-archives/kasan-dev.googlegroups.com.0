Return-Path: <kasan-dev+bncBAABB5NY52VAMGQEEXBDZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DE427F1B8A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:50:46 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-507c7db3bf0sf329e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:50:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502645; cv=pass;
        d=google.com; s=arc-20160816;
        b=GxOdxvxy3f3TadnvXTSPaxHw7DFsRl9smAHe2ecUdP8tHvn341y9E+uO9g4ZdC8hJX
         kzVAt5bY/ynkoA089TSuCKVNCKBCXqFMadP76g/YE3qrlm18eA65oUqbOM2JcpZZl9i2
         kRuUXkWjyvTRcQY8+d5lWYlrTYHsXvje0wcrXzWl6Pw4x5PnVTReEQ7o7DUGFx3P6KXW
         zwKaZVv0yiypHXwwoBhxfQR5RFf26gPK4T+kVp6P0FEUq/U9pz+xf/Cr3EUpALVU8lTT
         81Bs9875y/u821r3sCnb/JIAvj2DiyLNFcHK7FfwET3u3jfatahvI49FS1omfAC297kL
         v+qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2+00RPODpGWYRvkxB3iTrT2rAVAgd1zQIskVzwDSmrE=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=NBf/oO2wTkliZs5C2JVuA0s/EYr+SRKUFZLEf4uzOCP6GQq4o5phctnPeQHYImEE23
         DVReSF2fG5wTrv/o4lcDOSJ2p5W8K7gnb9dHMWA7czhmiiaCJuPtEYB2T55klv87xk7w
         sV0tJqw+TGwCBYOGiYN2s8dHd9kW3JpKc850Y81ZbEr4c+tLl+iFSScPwLnS1w+0REme
         Diqtc4eyPCkUkLbwPm4foCXbuIZMXgxomIT3nVQam84/OHSk/tHB9wOElVMRC72QRFpy
         WUT9JA5QBT9dEOEFfuhpP33gjV+JlLkZo2W2Hwm1oHGDJa0R+TDRDO4nteyX6bSxUe3p
         AO+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="altZ3Y/X";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502645; x=1701107445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2+00RPODpGWYRvkxB3iTrT2rAVAgd1zQIskVzwDSmrE=;
        b=Aqtcii9x/Qjs8tPoT5PcVTuo7j1/kYcpz7lkFVIkbgJnSI0Ey7kJMTKcbLIkslNzwk
         jdjsD3D/wSRPvEDwn+9Mk3K3S/nraW4js4V/5jGJyT+iByxCTnaJwXcsH3DLmBF25yrf
         ic+i6PYiMkaB54ruyyhbmIbkKTQASQ4o5/GzioY64BTeVM8+PBFd96nyg4aMShqcb8EL
         sCkRCa3xoTKKSMibMVShFrUkiPDTxh/R/3SR3kiHwCRd4xlZ0vwYgmfoNAybyzWuaEd+
         UmKbvtbY7cJif5DctNXZq81Ot5g5u97enxz4H0QCuGPytDVwU85mNd3pmnsIwA4pz4QZ
         BufQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502645; x=1701107445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2+00RPODpGWYRvkxB3iTrT2rAVAgd1zQIskVzwDSmrE=;
        b=ZD8KrnEgzEyu+LRJAwTosxp4mjnOYWAKXxbQBa4zW2tTQUVnB8aZK1FpY62Pn1/Yij
         TOweoyhIwLIJYc3xm+xn/DcyFE36DpOvdZmVA9StGZOS493BtpGumXbj+3weoUiK2i/K
         e7ItFhlfgldFOUCzVO3BqhYlg9XXr9bCuCJF76PVe6B0pl2ng/oLV88a8AlRfQdy63ou
         Zz08F06sN9dtqSGyXYvGkk2uw6QjUVtD8LpQlcc0+84Vc9hMVtTWabJZseZqStCzfpQQ
         rkrhqSGEELthgLUuUvOSHolDtECjjvaAiJngOPtmM5fIQzp4uUZBcVdfkb45jPeyoEMB
         qqXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzzZLUCV3rgCyS8tRGWQtmZQYe6h0Q7l1Gg2uAWbrU8LIQNSDw/
	lcuqtQXNfs7glGGHjK/MEXk=
X-Google-Smtp-Source: AGHT+IEWpJ/XpEOGnkUGc8pDAkdL9k1F5NYh7mdtFR4HMzzW1wKmtXRMFcAMSHLcHDj7E4D+GXUhuw==
X-Received: by 2002:a05:6512:3b84:b0:50a:a790:30b9 with SMTP id g4-20020a0565123b8400b0050aa79030b9mr148513lfv.0.1700502645296;
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:23a7:b0:50a:a6b2:1d1e with SMTP id
 c39-20020a05651223a700b0050aa6b21d1els47253lfv.2.-pod-prod-01-eu; Mon, 20 Nov
 2023 09:50:44 -0800 (PST)
X-Received: by 2002:a2e:9f47:0:b0:2bc:c771:5498 with SMTP id v7-20020a2e9f47000000b002bcc7715498mr7017825ljk.18.1700502643626;
        Mon, 20 Nov 2023 09:50:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502643; cv=none;
        d=google.com; s=arc-20160816;
        b=q2aKbdeSBHTlf0z1yKxNBrAswhkOLohvPntH4JzahU/M68FYbCkYpbWK5FiMzRDQX2
         vXmv1Pdfc7PRrfUXtjq348xpu+aP93t5D9InK6gdNa/j35XUiYuZo24+sebPn1jD2HU1
         IAFElQ6atyOs16d5ckTADN0m3Ue5VJVhctb66MR8IBNS1JGAGqE1L+++3kApyLzOk60o
         J5veqqtldFSLZO0AvcgmJkLdafh1AAmlv+HZWZhx2/BZlsbx8gzELsfE1fX5El932+Gw
         9XeKoSG7LCxrf1DhetwKdfN0IG3hbCgKsN0uU1Y33f/PegaNgAL7sO1CnQb+Dl1Zdr1m
         cdaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=h9lSbnFVvjj2GZw0LrViVCVgXWgHHPxOTEIrM79fNvQ=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=je+3BI573mC/fuKk85XfATh2AhZG/1FQjZz/3V8P/vEIYy+S8COQNmmPGniMRCpe0X
         TP7vBC09+NNyHQJtYyA/aMHjLhHTqg6gtQ7iFG6UQ77L4GsUTs5dyzM6KOECjNOWwHzD
         MsUI8n4XL5kgXBWjEaksLQZPzJwLEv3b5cDGE4QugYzun2LjPtRNtAhbHOodfr8pboNX
         RvVpH7OT+soIaRYkUurMPmWtfcMxwnYy5AL0XjvM5ejfRi3R8+KSlCivRdpluzejHed+
         5DM7DyjGHjB/K9q0SHpX6X3z8uwQvyUqFq4TwLqOWqGXQMjVFQoLOMsdmDd38zCb99j6
         qplA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="altZ3Y/X";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [2001:41d0:203:375::af])
        by gmr-mx.google.com with ESMTPS id e21-20020a2e9855000000b002bced4ef910si338059ljj.3.2023.11.20.09.50.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:50:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::af as permitted sender) client-ip=2001:41d0:203:375::af;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 18/22] kasan: remove atomic accesses to stack ring entries
Date: Mon, 20 Nov 2023 18:47:16 +0100
Message-Id: <29f59126d9845c5257b6c29cd7ad113b16f19f47.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="altZ3Y/X";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29f59126d9845c5257b6c29cd7ad113b16f19f47.1700502145.git.andreyknvl%40google.com.
