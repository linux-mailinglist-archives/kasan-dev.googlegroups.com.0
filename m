Return-Path: <kasan-dev+bncBAABBM5X52VAMGQEY3K7UTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D87B7F1B59
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:32 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-548a12a78d4sf1217309a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502452; cv=pass;
        d=google.com; s=arc-20160816;
        b=1GcniAzLDkHX5gRs4Vh4HqV+dvlrq8mfvHypbX1265oqcmX2DrSBZ6m4NRCJ2g4w8v
         8SdYAPxdaz8hCZ/uJpd2J2LQ4DU13bX+mg0F2allK7uGKmzkPKcUOKg1uugipcHiL7jv
         +O3pLhroVA6kCL6WWmJgak8+uItpbBko5NjVWDIH//tl9SJ+L0o+z5SxbnkJFdSh1LT7
         JtkZTHyHbH5qkLdwSvIP587ilVBOrNMnvRqF6tPZF732NW/k+M+VDdHKpjgfLxb27u6i
         qHcGjhPRKzTQIQhh6Tb8DCGqPN8tzXsgTk+DdfXyvJk7WcN403jyUMn+TZFJUINeBZuN
         70lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OT0sr1weeKHxUInPmLdA1599I0kzR1pssRYU71ro6FI=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=ivuzA3MwCv8a6VUpyXgfLt3ijL4EP8brM14BC9US0LR/tq+DH0LWgnlaMf9s0B0zEg
         cFoJaq7E1Ypv+0Y0xB6kA9Xy6fkAih6rAiiZCNPTgtWCE21CdR3BZMJTiG49w1PcXVzT
         r0LWeqNmDelOzsnkGfbw64BF4YNKpz4HqKK0c3vALY8S0MIIINtFGfqHML93LR+dJ5Ce
         HhBTF6gnwuZaD0L5B7Bhe4GJrxASAnMjgUfMhyXWCyXNlUzYQCqqo6oiza/oCBshr3tZ
         aePHejSPq5k7E5ZOZFZBUOk2VorJKLHsiIm6bPcVI/Skh9GExccUpXbLsNnlVxalZt+L
         fPMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ql85St5S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502452; x=1701107252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OT0sr1weeKHxUInPmLdA1599I0kzR1pssRYU71ro6FI=;
        b=jihALW9+OGyfYjcrnBLNDmmSVMB+/KtyfGUhAk8eSXLDk+IC2RDceF/lWNwTf/jQNv
         KcUBzUbbn6CqC8+JCU8Yq2vi3qHfGPEyf1fO45VZDHz6fTHrq+CHKluObur6wADjKobU
         xU77QeNX5By6HDqb4og+cejIXUgHUSFRrZVkEZWi9F4ga+vGL/qz+pjDse7J8jQCkxSf
         ORUj0at0rHBwjPafV4gk8fPFKcQfvR2YE+oqUKTUuJYGUkB0tHhJmIB0HL/7IK/RX30f
         pM88asq/3hpLgO3K+POnFBlavuSGfkWxyiDSmlnsNR/31Nt/4lVRzms3xrLhojRnJKhl
         o0sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502452; x=1701107252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OT0sr1weeKHxUInPmLdA1599I0kzR1pssRYU71ro6FI=;
        b=PwkoygAEh2UNb542VBOLI1s1W+LFeAKOPC4fmR4ozC742WvQIcu//KiYpvhJsU71Nh
         txaEv3NX303sz2HeI1JSvntDEcZEKQBixDDVCbF/wTTnMxN7sSRe2Q/4WsrDvTU0AC+c
         /RaF6902dNHnczy5AX+WLu02mByLO2EwRBsELYPxGi0MU1U9MJYvVW9x0QrP+dop1iui
         KZXTaqoPGCVtlNAePc+pdGtKyvXH+iMet5XKBEL9IjBcSai6gDLXHay6fioo+tk+uCnb
         8tnvJ8IPXhX1uQBcrowo4v8FBHtSl6YlmryfP2xYpatHCOXV4H//U47sq1VnPTQkGgYN
         OsKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhirurIYNEZvpf0kachWWZuC98z/UQp1NAbxZuaQlkhmY4E//A
	P/ElQYPpZdd8s3FV7EhtCTg=
X-Google-Smtp-Source: AGHT+IHmIisujavj+7p6SxaGajrARlE4ABRPC9Z8m/id3x1LDa71hz939QfUY12AmhkX5i0c6MkpOA==
X-Received: by 2002:aa7:d84c:0:b0:542:d69d:d075 with SMTP id f12-20020aa7d84c000000b00542d69dd075mr95151eds.6.1700502451657;
        Mon, 20 Nov 2023 09:47:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:365:b0:548:b5d4:1a61 with SMTP id
 s5-20020a056402036500b00548b5d41a61ls199852edw.0.-pod-prod-04-eu; Mon, 20 Nov
 2023 09:47:30 -0800 (PST)
X-Received: by 2002:aa7:cd95:0:b0:542:d56c:ed67 with SMTP id x21-20020aa7cd95000000b00542d56ced67mr103157edv.4.1700502450063;
        Mon, 20 Nov 2023 09:47:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502450; cv=none;
        d=google.com; s=arc-20160816;
        b=unYDRczRTWvMxZtTq/87peYMQ1sF8OjiZkq9EhvVwbHJvPisBmD84Du780JUV13H3K
         xifxUy5EMZEaanV7R3KwaHNOvzZB9fRwUj4P3VF04oF4Zz7QW6V+k2muWFhdASK0uMxI
         3I/ZSsUieyV8aSt/f57YfVJ49OBJvShO5eBLVeM23fuzD96yuo6ViT6TIhjzrDk0j0QO
         9WzFvHDUphGkYDblDGHMEjmWLp+JNrl7cLTshfY5mT2CEQse6ZLfJVIK6XdKkKImNOnp
         uCqPjh09bbw+plMVxO9Z2GPoJMpEjofnFQ+cGl5dHWtAdFCRyBTjsHIcXfU5S3D3cbf3
         ot3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4+Y9MGkz9f3yZSUENZCgBAvLs1CfO+kuipQPdiyYS+c=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=FSfObSuaxfJKQRulwydP9K61kxcRPbMWRKUn1qS30PO3rzSoFDzlqevY6HJ7f8zhr8
         UvH+doZQEAX57l5tOMd7mPkOlhvJseXrEB5oIm4DJl/e84HKrGsQ9d+2oZOeLr3qFKDq
         tM12j1guw9lBZzbYmbIPgDc38hNRJqZVcEmzT2/nrqHK9w5s/FBnqBcWiCST1pgzpPy+
         gheHA9vRwIiwTT/PtZP6I3MExo4A3VmH74i1WoDyFbwGdGZIpTYMSokAmZNpYEdx4K7Q
         XupjM8yilm/OsEbWjvIPg46mza7dDrEA7rimX7Lx+p5cXNTJEzqsp0qJdPXq8/z8g8d/
         cGWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ql85St5S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id t2-20020a056402240200b0053ea9bd0510si315821eda.0.2023.11.20.09.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
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
Subject: [PATCH v4 05/22] lib/stackdepot: add depot_fetch_stack helper
Date: Mon, 20 Nov 2023 18:47:03 +0100
Message-Id: <170d8c202f29dc8e3d5491ee074d1e9e029a46db.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ql85St5S;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as
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

Add a helper depot_fetch_stack function that fetches the pointer to
a stack record.

With this change, all static depot_* functions now operate on stack pools
and the exported stack_depot_* functions operate on the hash table.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Minor comment fix as suggested by Alexander.
---
 lib/stackdepot.c | 45 ++++++++++++++++++++++++++++-----------------
 1 file changed, 28 insertions(+), 17 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 46a422d31c1f..e41713983cac 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -310,6 +310,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
+
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
@@ -319,6 +320,32 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	return stack;
 }
 
+static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+{
+	union handle_parts parts = { .handle = handle };
+	/*
+	 * READ_ONCE pairs with potential concurrent write in
+	 * depot_alloc_stack().
+	 */
+	int pool_index_cached = READ_ONCE(pool_index);
+	void *pool;
+	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
+	struct stack_record *stack;
+
+	if (parts.pool_index > pool_index_cached) {
+		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
+		     parts.pool_index, pool_index_cached, handle);
+		return NULL;
+	}
+
+	pool = stack_pools[parts.pool_index];
+	if (!pool)
+		return NULL;
+
+	stack = pool + offset;
+	return stack;
+}
+
 /* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -462,14 +489,6 @@ EXPORT_SYMBOL_GPL(stack_depot_save);
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
-	union handle_parts parts = { .handle = handle };
-	/*
-	 * READ_ONCE pairs with potential concurrent write in
-	 * depot_alloc_stack.
-	 */
-	int pool_index_cached = READ_ONCE(pool_index);
-	void *pool;
-	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
 	*entries = NULL;
@@ -482,15 +501,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	if (!handle || stack_depot_disabled)
 		return 0;
 
-	if (parts.pool_index > pool_index_cached) {
-		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-			parts.pool_index, pool_index_cached, handle);
-		return 0;
-	}
-	pool = stack_pools[parts.pool_index];
-	if (!pool)
-		return 0;
-	stack = pool + offset;
+	stack = depot_fetch_stack(handle);
 
 	*entries = stack->entries;
 	return stack->size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/170d8c202f29dc8e3d5491ee074d1e9e029a46db.1700502145.git.andreyknvl%40google.com.
