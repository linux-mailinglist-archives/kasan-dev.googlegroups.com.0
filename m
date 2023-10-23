Return-Path: <kasan-dev+bncBAABB2N43KUQMGQECETRJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDF5C7D3C5E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:13 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-53e49871d5fsf2283531a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078313; cv=pass;
        d=google.com; s=arc-20160816;
        b=09/XXsXmdM/251zOKlukxrmlgTtwkYqfgNrPNUh+cUyEYYXKTbItUX4U2XxaODTr73
         PUFWNN5X0Qr5TcpesdXKp1D35g8rR0/+X9z9J3NP8zXhAtX6sPS4YttbQPIklwKAIdC2
         rXq9SFJaBPWAa84IGpE0vtg9TTAMNo14IWYYuCwjnuQrrCqwCdcNOWo0cXjJdQfXl7mZ
         nvzxvBbJAyo5NBlvDGbHi+veUF7610FgXnyb384sHojLIDwMrYpKcNlcGzVhQ9NhNR3f
         yNoMpNjsRYhDDnmcZOMptazCuI+CcyZ0np9Z3zc8d6gn86z3mb9dwEdoGZ5odwJZTK8n
         72qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dkVst3G3xy5L6njjTsdH83MVSeReL3czQTZGkA3OlLk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=XcAtVYtFbzzUzSAuOaHLc5c42Q7QmdPYljV3O619NakuPpIp5GW05V4/E433G1q8Y0
         STVh2PNaCqSMvWdv+703eC5jU5HWpHHnm3tUSPH5KlEc43fGca2+OMgUZ4ko4ocXp+bF
         PNA9JeCW+RtWVb200+8m2wZfC5rcnmQyX3T7JqEQJZ7na61/cGUPlG21tZKOiUtAGh1X
         qzpADwgC0yZtduw1a9L/NjyL0yP018tqOG6kFrUAGH+Zfwa2Q9472X7wbzpAvh9/UoTd
         abF01TgJsBSN4h9wXDPy9wjx5yTqWEGo86mzOiM4jksWQzD2Ma4XoDOoPu2IDdKouFL5
         YeBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CQBo9f5r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.193 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078313; x=1698683113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dkVst3G3xy5L6njjTsdH83MVSeReL3czQTZGkA3OlLk=;
        b=Ieqhv+DJDH6XzfzRLoDn2j2F6dLHwEnoM7FP213opDt9VNhD88NW0is70BLdkTwtyT
         ecvY3GFcUKaI78VCnalV2E/ErKCxbzqsVs9Ks2lHb+6Lv+1YRhARbhdZAYhOIWQUH3Ei
         q38KO1SZ8jrNozT8LOsfkEV1WBZpjvDtD2Qj6BfwUIMdgr8onYhGbl2NsGwcDeyr2sFj
         Cy97ENdWRBJiWNgvVVXmqbkuJ1rbkLIrEAfRKKfEYjm4dwn+JbfF1d7WfQr9kK4pjwm5
         zUnJ+wjc2JElw70VqVcZLMlQkBDRi+0f/EkKKsy2qxVqdleJJXX2UjuOqxRA++HtKhZN
         1nJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078313; x=1698683113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dkVst3G3xy5L6njjTsdH83MVSeReL3czQTZGkA3OlLk=;
        b=tvjZwTE5yw43SosZDjAK2RcXzfkbLr/6cq2tkIL6Pquy7spnuPAc0/2ULqfRoAkIwa
         9oOstkWen0GmeDswnzt7avl1kty/jlE8ucnjWH2v0P1Qt+m5rrXkd6xRzj8jXsEf/ZXm
         72RxCuAW/bwMDMMhZZw7a08a4F1KSgSD012AeffJqNlPtDBiSVmNOCv16nSRr9Dd2Y5N
         qyQ3NWLiYjT0uzwgMaKupWMpsN0B0E1bznsHTKpT7j0oX498+VdQhdTYzKXA9VLpBo6D
         QbaeC+4WzdHZzqYComLbUtt/F2KDRdR+4BJiM/bYSisBxgNKxIVVu9JIjS+UUZV0Lv8E
         gpqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywxvst4HDoSialOMAtNLGBHRca5mjqWo00iqr/jjig1yXvuAx8E
	xO12FoIO0muGOtmQ3fnmDCQ=
X-Google-Smtp-Source: AGHT+IFSqH5Dtuq5go24iSlskvgYheVyEw19G7LAr3ObAIKPqNatlCUyO894b7H8lN+6iYAfl8aY/g==
X-Received: by 2002:a50:d518:0:b0:53e:467c:33f8 with SMTP id u24-20020a50d518000000b0053e467c33f8mr6690693edi.20.1698078313180;
        Mon, 23 Oct 2023 09:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2482:b0:522:aa6f:afb3 with SMTP id
 q2-20020a056402248200b00522aa6fafb3ls410926eda.2.-pod-prod-03-eu; Mon, 23 Oct
 2023 09:25:11 -0700 (PDT)
X-Received: by 2002:a05:6402:4404:b0:51d:f5bd:5a88 with SMTP id y4-20020a056402440400b0051df5bd5a88mr7543969eda.38.1698078311636;
        Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078311; cv=none;
        d=google.com; s=arc-20160816;
        b=ckLodQehvIosf9gqIDKE9pu0o2p9mrsVHenbu7B4w+YLyllac/33WBdll9FZOaFx55
         0A9nvOXWCE9fYPyUjKOgtMysySd4oiz+FAdgLALVvk3g7jzETc7dk9oS/s+H+a5n1HEW
         CdPE05IA0aoP2cHanQ8QNwr5h+nkOrM/4QoSWmkcHNjOdsE71c5QmwskJR/VhAk5U2BI
         eAtitWXl/FDWoRP645VBMg50xaEAAY5LRnzN7C/mWuxtLH5IQg7UI9zgp05eDZyMrfIR
         g7etaGF6ohDbkcaTerIpiz1n3QOqbUBZ3pN+beSzQR5ZyF47mkeim1Q1zazPrkxCHlNj
         B3ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=h9lSbnFVvjj2GZw0LrViVCVgXWgHHPxOTEIrM79fNvQ=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=B4Nnf2hPOf0TEYCmS/miqB87WHtTnkb2WcGMf9xUIWNRzh+OMGyU2Z44D4DLKohafX
         uTesNU2/YnhKakeJnD6Ss30DBOkrpRW9x6jr/lvcTAtT/Khmoxx0Rcgqy1HR9lItolOS
         fP9GcjOcxk6QnxdiDgl/tlmpxM2vIwqsqrtHaor0G97NPF0Jmje2cIi3/1lqKPJVOyDh
         tMnMQFRLRnX+ceHanI17xFfO1/VfHZUNkNIDYFPw/z/Ji0bBYP/FIKsu8Zi7Od+Hfit/
         L4HUwY4IOxLW4lxNqf+kj0T0qdBXtP6PflOf3DZO5uUZ1VmgeE1FePOg5iFjRzMmNZbC
         P8EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CQBo9f5r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.193 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-193.mta0.migadu.com (out-193.mta0.migadu.com. [91.218.175.193])
        by gmr-mx.google.com with ESMTPS id p10-20020a056402500a00b0053e326c0717si211256eda.3.2023.10.23.09.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.193 as permitted sender) client-ip=91.218.175.193;
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
Subject: [PATCH v3 17/19] kasan: remove atomic accesses to stack ring entries
Date: Mon, 23 Oct 2023 18:22:48 +0200
Message-Id: <81b8b7984846e0e7abfd794aad3bafee97c89c29.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CQBo9f5r;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.193
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/81b8b7984846e0e7abfd794aad3bafee97c89c29.1698077459.git.andreyknvl%40google.com.
