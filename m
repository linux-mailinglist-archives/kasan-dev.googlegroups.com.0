Return-Path: <kasan-dev+bncBAABB3O34CPAMGQECPCHPEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F3B93681BD0
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:51:57 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id lf9-20020a170907174900b0087861282038sf8012214ejc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111917; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpSHJf8qF6sueW40xCIeBKlwTLTKNZ8Mw/w+5rtPjKX1Kw+jKSgGRhb6XxKbbNup1A
         iYyyMobWjXSCC+hFvmJYuQkHAfOdJDqbDYIpuqVzGZv57AINE6pd6lCdrRD057Gw73bo
         58jEOomyv0nUepsq5aqjCRCOs/KShvtKDnp8dMtMwGeMUcxwEhMWIB+Xcr+ahvNunaAK
         6b3eZ39JMxInxwHtK+E+532MficzUXTv0+mlasJ5zBgth+Cp96EcMiqzvOFvShp5SFxl
         /OeL5Y6qehLlhADJusvagCbFg8cNYXlK0w3on155Z+0AvOWSjr+A1Yp7j9Rs4+1n/BSx
         8iYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=byupR+5DkvBv83osbEpGtWt9hbBP2PXWifZhNMz9YTY=;
        b=lS1C8W5VMRMhL7dNYTsHdQYQWqkIMjMpEAUxcP/VDrdXETZeh7g4N4eKlGnqp6rG0g
         J9hSm9eCuU8hvlSjUqZvgi91Zm/40QXBL/AnbQBtfeIN2Dvg/yPabpObCcw6ayvHy6wL
         Ka1sy8Zj86q+/SI0+PCus8W/X9QeK5sY/morfEwUFCLZWI7HutOJa0ES4PiS1yp+oAEb
         1F4Uea6W4+dnSlr6Fk5h4/lDGvWXJUuA6IWadkZK8/pMdG7htwprVDV3XRtC7M/0KAbq
         oJQb3yck1Ksv66rMwCvfcb6jFKQcsMz6+gpHjI0We49VAiJUo0tRPzt+RFcPhAcguHga
         oxkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TCrjIwKJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::79 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=byupR+5DkvBv83osbEpGtWt9hbBP2PXWifZhNMz9YTY=;
        b=MfSrZpSK5x8Jhqe5OdpOQbCSf8T33TM4NDPDT2EqKR5MY03FIOdsCA8MBziH5yTIO1
         D+je84rqVKS+sk6rfP9HeVPs3jkhXBtrEc3nQ2sb5r+BqfG9dEgRJJiGhdb0SmiImYiy
         Eefo0v1LTg0C5fxtvGbbIbwuXUK4FLiJKAhK+C1Yen7Y+H4dhkcJ9PMAZnQHD9UxUaSl
         PD1SpnEdWliMys4UJhhuXE3ovB8ylOZIoi8JxpuGzO1MClmJtANrcPK/ZnpQy8Coyb4k
         Kd5zKMb6zY9K+KIhzJF8Z/g74MXuJeKFm+o2nY5equQlhxZElT05tR1IFZ1jEobGeIAU
         TKKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=byupR+5DkvBv83osbEpGtWt9hbBP2PXWifZhNMz9YTY=;
        b=F/CkTb1esP+fIrOCmfM0BvOh1QjaQCJJzxgTlNdahJVM7RsugaECZhbV5nIp2QKlnI
         fcn33RXJE/jD6PXNr0ZyooRxA5AlC+pMIM9FY4fFlukZkzJcK3EFF8vRfbQ35Zg2Zqvs
         jj3mcq5zZbNbI2JZNUXKhgCc6gwmHsufzGs9B6KLJ/+pgArW1nQ96gRR9H2vqA/+IBcP
         29JwP1l0+CxkVF5WsauJlXQfr8DY9gwHeWrI3+lgpMdZlnMKlL/EomWJ7p9Uqs5oflrj
         OiwKApVfBFFa/RuPVRZ2jXcpn1dGWT0dmAvKCtAPnBfwyLxLkmBGWbAcowOq2eaQgh1d
         obXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqmVG18SyqzQkaFi/ekic69rSXmiQTv7UPMjdozpGZvPJyLgNHH
	eVC+8iDEdXP3SPExTc5MzDI=
X-Google-Smtp-Source: AMrXdXsm0+8c/qga0xjzTFPcnfN1YKE54yAj5BwBIYRbXqsdNzN5wbMS8hJaz0c4MKM2TLTvhc3SSw==
X-Received: by 2002:a05:6402:10c9:b0:49d:a47c:dbc7 with SMTP id p9-20020a05640210c900b0049da47cdbc7mr10439537edu.28.1675111917640;
        Mon, 30 Jan 2023 12:51:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d681:0:b0:49e:29ce:a2b with SMTP id r1-20020a50d681000000b0049e29ce0a2bls13250889edi.0.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:51:56 -0800 (PST)
X-Received: by 2002:a05:6402:5c1:b0:48e:94ec:b7ac with SMTP id n1-20020a05640205c100b0048e94ecb7acmr907573edx.7.1675111916611;
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111916; cv=none;
        d=google.com; s=arc-20160816;
        b=tNjjO3/7Bm5xDcooe5VF3h6VTFheCrjSy89YN/W2fK+IK0WxF4xnci8pMta2CPoVg3
         kYVoNk8HgKDz9gS1sf0MF7jD0On2mqVHiI4Widp4RH5782e3O9V8ZV15NIqYm4dGmNqs
         CaodRAEmFtwFBfKezG1b3K9zQ7EVwPWhwcgSBa7Z4h+FXba0jTGSLjgT5vJxMjjsbrGd
         mCE4mRyB6rMzsOAFDvUqPjyd2MjDSP3fDqYFnvxUxzyNubAzkEH8cTrXFtFT+DK+1TNk
         yHVAY02wQfrD8S535HzJBh2UBMn1KOPQRdfraCrSYVrXM1tWOuHmcSE9zDSvx6IF/tx4
         euUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GaiPOQJQg/3eaR9Q8OYjD4xHiibeiKzRxzXBSSG583E=;
        b=sSuLEKt9NO/DwkpQjdAbksrew0pQ4KoTFtvv1u/4US7WUjUK2PECCOtw5/nEaBSsvI
         AbTOYGwzURoWqlLRyBlSKHmjgiHvH88GsDbRwHY9gr7Pilz/YfU6kx987ZCLImb0qnVv
         CUt8jih9tE/1g7cBRIe7MMU4qy4Y4DtB7cuI2BMQ8czDKmAwwL/zduf41zrBxaM7mgt9
         /iLI/M7Vvh6T5hL/eiT2dcXlVxJArfCG/fYLnNt1p437sXD8QQmgZBA/+YX7xinkwyPe
         vVCcMnIGs2aemTCuhynCMey5508+7lCrZOGEDat/joI9hyfD35VQeM7Snqug80XfeWrh
         Z0SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TCrjIwKJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::79 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-121.mta0.migadu.com (out-121.mta0.migadu.com. [2001:41d0:1004:224b::79])
        by gmr-mx.google.com with ESMTPS id f9-20020a05640214c900b0049ecd39787fsi713282edx.5.2023.01.30.12.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::79 as permitted sender) client-ip=2001:41d0:1004:224b::79;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
Date: Mon, 30 Jan 2023 21:49:39 +0100
Message-Id: <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TCrjIwKJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::79 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The current implementation of the extra_bits interface is confusing:
passing extra_bits to __stack_depot_save makes it seem that the extra
bits are somehow stored in stack depot. In reality, they are only
embedded into a stack depot handle and are not used within stack depot.

Drop the extra_bits argument from __stack_depot_save and instead provide
a new stack_depot_set_extra_bits function (similar to the exsiting
stack_depot_get_extra_bits) that saves extra bits into a stack depot
handle.

Update the callers of __stack_depot_save to use the new interace.

This change also fixes a minor issue in the old code: __stack_depot_save
does not return NULL if saving stack trace fails and extra_bits is used.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h |  4 +++-
 lib/stackdepot.c           | 38 +++++++++++++++++++++++++++++---------
 mm/kasan/common.c          |  2 +-
 mm/kmsan/core.c            | 10 +++++++---
 4 files changed, 40 insertions(+), 14 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index c4e3abc16b16..f999811c66d7 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -57,7 +57,6 @@ static inline int stack_depot_early_init(void)	{ return 0; }
 
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
-					unsigned int extra_bits,
 					gfp_t gfp_flags, bool can_alloc);
 
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
@@ -71,6 +70,9 @@ void stack_depot_print(depot_stack_handle_t stack);
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
+depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
+						unsigned int extra_bits);
+
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
 
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 7282565722f2..f291ad6a4e72 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -346,7 +346,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
- * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
  * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
  *
@@ -358,10 +357,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  * If the stack trace in @entries is from an interrupt, only the portion up to
  * interrupt entry is saved.
  *
- * Additional opaque flags can be passed in @extra_bits, stored in the unused
- * bits of the stack handle, and retrieved using stack_depot_get_extra_bits()
- * without calling stack_depot_fetch().
- *
  * Context: Any context, but setting @can_alloc to %false is required if
  *          alloc_pages() cannot be used from the current context. Currently
  *          this is the case from contexts where neither %GFP_ATOMIC nor
@@ -371,7 +366,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
-					unsigned int extra_bits,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
@@ -461,8 +455,6 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	if (found)
 		retval.handle = found->handle.handle;
 fast_exit:
-	retval.extra = extra_bits;
-
 	return retval.handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
@@ -483,7 +475,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
+	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
@@ -566,6 +558,34 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
+/**
+ * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
+ *
+ * @handle:	Stack depot handle
+ * @extra_bits:	Value to set the extra bits
+ *
+ * Return: Stack depot handle with extra bits set
+ *
+ * Stack depot handles have a few unused bits, which can be used for storing
+ * user-specific information. These bits are transparent to the stack depot.
+ */
+depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
+						unsigned int extra_bits)
+{
+	union handle_parts parts = { .handle = handle };
+
+	parts.extra = extra_bits;
+	return parts.handle;
+}
+EXPORT_SYMBOL(stack_depot_set_extra_bits);
+
+/**
+ * stack_depot_get_extra_bits - Retrieve extra bits from a stack depot handle
+ *
+ * @handle:	Stack depot handle with extra bits saved
+ *
+ * Return: Extra bits retrieved from the stack depot handle
+ */
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 833bf2cfd2a3..50f4338b477f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -43,7 +43,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
+	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 112dce135c7f..f710257d6867 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -69,13 +69,15 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 {
 	unsigned long entries[KMSAN_STACK_DEPTH];
 	unsigned int nr_entries;
+	depot_stack_handle_t handle;
 
 	nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
 
 	/* Don't sleep (see might_sleep_if() in __alloc_pages_nodemask()). */
 	flags &= ~__GFP_DIRECT_RECLAIM;
 
-	return __stack_depot_save(entries, nr_entries, extra, flags, true);
+	handle = __stack_depot_save(entries, nr_entries, flags, true);
+	return stack_depot_set_extra_bits(handle, extra);
 }
 
 /* Copy the metadata following the memmove() behavior. */
@@ -215,6 +217,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	u32 extra_bits;
 	int depth;
 	bool uaf;
+	depot_stack_handle_t handle;
 
 	if (!id)
 		return id;
@@ -250,8 +253,9 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	 * positives when __stack_depot_save() passes it to instrumented code.
 	 */
 	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
-	return __stack_depot_save(entries, ARRAY_SIZE(entries), extra_bits,
-				  GFP_ATOMIC, true);
+	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC,
+				    true);
+	return stack_depot_set_extra_bits(handle, extra_bits);
 }
 
 void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl%40google.com.
