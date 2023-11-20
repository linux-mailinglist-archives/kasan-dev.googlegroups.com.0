Return-Path: <kasan-dev+bncBAABB5NY52VAMGQEEXBDZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D0CC7F1B8B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:50:46 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-332c9eca943sf508107f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:50:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502646; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZV4BtVJ8x3MFFlTR3AdwoJFYz8CfShAvc4zs7KvYagg9XmtEJY1BuOVnCmSre7bjUf
         6QHf35hqiPR0wli4Mtu4yatgaB0Yw3Tr86Ea7DNjRMLA41ehkaNFtTHlodiX2qzIoNqE
         AGS9A+sp7dKxFn1SpHPdipJRO6kVsYLwHAyoMyUtoZU6PBvGn9R7b+LaNaglt1gkSPG+
         nbtLqg9V6fSPGj5djkS3h+58CV4eCSgm4tBhYGTrqscRNLxhU8L6wdu7UZp6I648Ybma
         LEbo4gPBDGlBxQTCNJ3f9flJkzRqnV9OhNW0JlIGC0Vcjvf4gWAsi0A5z5t5+V5UhB2a
         lczg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yf8kAsNsbWJOKwmBpL8Yna0x79cUTCFda+8CnKPSOJM=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=nVPwWViJ/GDqBFOSxYC8glAsnxk8J4AnyYKBzcsO3dFY4F4uJiHhUqY398KH+SblWz
         j2mXFG/qQpNYHmGChBDDbiKOUkgX+P+ffebfQkcDV89WnbUGoMrkrdn+ySeSn3b3fudS
         ewB39RlSL+hxG3q+6iAM2GiijLsLHL5SDThB/hsrcShqT/HQpYvKR9qLMKX89SPy7fEA
         QseQoER2WA/z2Hcyba4nt4y4Nfai6HXygJEMARkYcibCBS82v1tx0msgJJIerYuAAfhp
         4MgSK+eNp7Er16USa9Ojrs49Fh2Ta6oDmrcgf+JjUB7iDNTn7CDyQ6XJWYP9oGwMnfZc
         +jBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SjlBdcCR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502646; x=1701107446; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yf8kAsNsbWJOKwmBpL8Yna0x79cUTCFda+8CnKPSOJM=;
        b=dOdhlLyPMLWxjHjMTJSBwAiXme8LGxb/cJyxEtVcZNvyXPNbQBS9GIKed3XoT126XT
         1l4Fo3KZBjln9PIEt9hhIPBFEfoj8oN7JQc27GWyCXwRGPSjB1qDV+cLzFN5ckV+WKeU
         THks0Afh1jB3v6IvvDKetpDCMIyVO4RhTUvJKXIokAxe5WTdb+r+K2jaMlgRxNaADX+A
         xwj8alr7hENfnWtanFnRf3dXGNjg2NSFwJYvgHtF36OwvyhphhSmVcGW7KV2oO8f8z2H
         V8Yc/73gFwkU94YxtCSusDVCC+2oxBi3rDwtIyijYhk1NqrotT0gjhf4UawGnNu3joXQ
         6ARQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502646; x=1701107446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yf8kAsNsbWJOKwmBpL8Yna0x79cUTCFda+8CnKPSOJM=;
        b=lVrw8KXF1F9rzBYulGPojTLC0eoD0MY8XoN+jVQpAeBUfERSzh2Aubq6ch9dmxuhIC
         r1PQqubpm/x+eq5itGbP7n7sx3qih6yXOArKg/2uA3XuALodJ4ixNcg9r9tpYbghOOVM
         2haCw5VMRhStk2xKey9fARIP4xC0nXboiU/SmOYRpq8qDZHtWLeIFOSukoNJjGm68K+8
         RBOMpwMesvbqtMr62SN27XK/Ada9UlH67DyMX55pAHCCjwaIb9NsTYHMWyI6YFe5KaXH
         BKy3aM/iqibTym0lH2xaNkvbii/LPB6QrMDb/kXNQKb8Y9liNTR1sJcLN9i9SSrchVnz
         Czuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YztxDyozdv1XU7K6RAq0hu6RLeGapXLnYCJpOJXs2J4dfhLDqZT
	aC0Ai0B9euh6VwWokuk3Idw=
X-Google-Smtp-Source: AGHT+IGyzRgzQ0UIqrfa8ZoG6n7rPWUdzkMV/1OLm17nXxWGK15SdTBNNflN8oMonLB13xD8BiiM6A==
X-Received: by 2002:a05:6000:1ace:b0:332:caa2:fd30 with SMTP id i14-20020a0560001ace00b00332caa2fd30mr1593783wry.40.1700502645820;
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:24b:b0:313:e6b1:8d51 with SMTP id
 m11-20020a056000024b00b00313e6b18d51ls41592wrz.0.-pod-prod-02-eu; Mon, 20 Nov
 2023 09:50:44 -0800 (PST)
X-Received: by 2002:a05:600c:4f84:b0:404:4b6f:d705 with SMTP id n4-20020a05600c4f8400b004044b6fd705mr7456385wmq.17.1700502644422;
        Mon, 20 Nov 2023 09:50:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502644; cv=none;
        d=google.com; s=arc-20160816;
        b=VSkSkbV32dQ0im/Gcrvkz1Xf1OLkv+IC2WXglQkH43//pEg7BxxCipOht52UhUQrow
         NwW25EBHhpMEVERlIjiu+22O/lGBKv/AQitKRqbzDSYqRHAarOkY4k577FxD09I1kspb
         eOKVWiINmkvzGVoLPe+A6s9lFDHeH3QIlmx2A/u4P+iwz08Kf8xLR6Yyi/Hgkeotrx9m
         EFpANWTeSV+V/niTeHL636jl2ITOLKf56uzee/+sFYJYC9Foi4BN5wInH24vShrS1nY/
         P7XG22a7VBcpwaLjXb3qd4E8TZPAVY82cOCryBbNcteiEcza4ZMHXZnG53qP/ahUFKGH
         PFDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Qc2DDhk7eSddbt2Q3kjJLSbCNGbLZWOl9JsGZF81sG4=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=QFaE/vYC26dx83fCzMiaBoBNMpF0FY7SB/nXMTyuDl5h9x9Mv3CALvCvtd69ZHvMdJ
         t6DSkCJ4W+VPnrWXBhVlRjyWeuH72VJvj+ttrj/YjNjpxMTm5vQhN4JhjaWnwXQ13C8J
         Eb7rH8Plu65s5FzKuEG03z9nA2GQO2IaeqEOnol6YKEN7wdxKxVvKvF7UJNjO0jO2bL7
         /LfHSjR+j9s10OtgzfRQ5BgcoMiS32azCXxfWOxdp9Hq/fGqzCPsFd9bqdqfK26+r8CR
         5k89JeRjS8KduGRr2FlRX4tzEp8VKMmgA3W0x1Z0uB2cjDKI2hqTD20JvdHdqwQ2APDo
         n6lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SjlBdcCR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [2001:41d0:203:375::aa])
        by gmr-mx.google.com with ESMTPS id n39-20020a05600c502700b0040b1a51c246si259504wmr.2.2023.11.20.09.50.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:50:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::aa as permitted sender) client-ip=2001:41d0:203:375::aa;
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
Subject: [PATCH v4 20/22] kasan: use stack_depot_put for tag-based modes
Date: Mon, 20 Nov 2023 18:47:18 +0100
Message-Id: <b4773e5c1b0b9df6826ec0b65c1923feadfa78e5.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SjlBdcCR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make tag-based KASAN modes evict stack traces from the stack depot once
they are evicted from the stack ring.

Internally, pass STACK_DEPOT_FLAG_GET to stack_depot_save_flags (via
kasan_save_stack) to increment the refcount when saving a new entry
to stack ring and call stack_depot_put when removing an entry from
stack ring.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Adapt to the stack depot API change.
- Drop READ_ONCE when reading entry->stack.
---
 mm/kasan/tags.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b6c017e670d8..739ae997463d 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -97,12 +97,13 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
 	unsigned long flags;
-	depot_stack_handle_t stack;
+	depot_stack_handle_t stack, old_stack;
 	u64 pos;
 	struct kasan_stack_ring_entry *entry;
 	void *old_ptr;
 
-	stack = kasan_save_stack(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC);
+	stack = kasan_save_stack(gfp_flags,
+			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
 
 	/*
 	 * Prevent save_stack_info() from modifying stack ring
@@ -121,6 +122,8 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
+	old_stack = entry->stack;
+
 	entry->size = cache->object_size;
 	entry->pid = current->pid;
 	entry->stack = stack;
@@ -129,6 +132,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	entry->ptr = object;
 
 	read_unlock_irqrestore(&stack_ring.lock, flags);
+
+	if (old_stack)
+		stack_depot_put(old_stack);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4773e5c1b0b9df6826ec0b65c1923feadfa78e5.1700502145.git.andreyknvl%40google.com.
