Return-Path: <kasan-dev+bncBAABBHHJTKPQMGQEOCVEXPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 37DAC69291D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:18:21 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id bx20-20020a05651c199400b002905fdb439esf1888845ljb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:18:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063900; cv=pass;
        d=google.com; s=arc-20160816;
        b=ytxgs/z9k/4X+dXul3sOsGmoG/cDmsMJEOQj6t6H22QQHXRYkwcqrDoqZH5SZRHMQp
         1ITIgwA0JnQz8NdjGI+0uL7ghBJOqkyu7Y/ha3ZpzbrDiCRbHe5MRDDOYvpSjah6ccBK
         IYk4SN1MUDT27WaN0xuaXrZj+K9sim7VRtNDp4E5iE2B4OgYXrkn8PkfdHRnvX/Z42W9
         hpkc5ALz1LPSlccRwYLFbcGhaZjCwVXA03IPDDy0afESKJuCbHq4+Y/+Kejgm0N8PzPz
         vTnTFj4OGmZQkITOSPF7kHQbn5YFAZGjH94v6xUuSiZvD6rFmq/l3F5EP1KgDbN2fbMz
         qmcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5fFFX+05pL+JtsLgHxVNFU5Xa6aOHtrWCk/GS4EinFk=;
        b=M6BO/CdQQ/e5FB16uJ6gZelPq7PD083pXdEnv2CaOSrK65rflYqnwcXLCbGJS2ctSa
         dvnK17EkZLu+Sv3IkjfdKMkhz9IxTbpOGS3dYgd8cE0KAZ6H1QomldrL52KWPuoxXPdP
         4wn3eNGm6/2/8IbA9H3ssjcE9ZaSan3tGWCrtXCJCuJhJeVJBDA3ogAN5H1QXeOjMQoG
         2eGbRzo6VSVF4FwrsCKdvIremq8Uq9/MZWPynTra93yTg1H8Jod9uugnGpsYKVNt6dRh
         vQoN638FUid54dfGEALsp4pfoBqH6/U3PPBX53Ai+wNv5U8bx2B+f62VGpcvuCeelEi6
         p7og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mZ77UXQw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.147 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5fFFX+05pL+JtsLgHxVNFU5Xa6aOHtrWCk/GS4EinFk=;
        b=rhP5UkNDYlilvCKIYp2seRyAjyzktx3I0H/wvJ5ZyqokV5KIh3HGHFZaQGjj2qSIpQ
         8DFN8+8+SqYJK99mAp5NqnhLhpAs7HqwamoL0IfX7G+I4Vwzr/ZjPAA1ygrIEMGVDBgY
         zdCF5UdAyBK6WlBjoWqJwFp7fpDjI2h9S3meyve3wIkfzZ7+w3TVQtGhrn+ui2wG9E9t
         Z+9cyGjdoxgpGBElxtSYU3Xvgu23XhVSEC4ZK3/4FIgu/+ntg1PDU/aoYATmmE+FLQ8e
         AzDceo+aGrgSHmXMga9as2vSHC+r6qcLzQJkfxmaK9U730OIeY/CXbxznfxBrE8+ucse
         5E2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5fFFX+05pL+JtsLgHxVNFU5Xa6aOHtrWCk/GS4EinFk=;
        b=WdY0MRxRrHLT2McwCJRQSQ7ZjKtFu2dQUpzc1ftAp3GjQr0pnMrU/RyamNZLhbLuAI
         pk/5vFnkWRTkMGRcuyTpfFlNNj7TitkIf9dUT/JqbDLMrFlmT2A8a+DbgV/Qc0y47GrY
         TFE1nIjmtQC87SkTMPtat5kPYsxd1mTLg6Tkez+XKx3ueV6jEzP2n2vhLP+WK5VXTFRh
         NFo0SonZv/LSJRZaoR6RATgI37cq6JgGukX/VeAi3+JVt/SQFud9IBMahkfVy9ir2fTY
         GtaAzq6fqo0/68pV9Ch7xbSd8RfMJcWOxlLsMhTQUTvCA0BHPU8NMSNc7CNepPRTK5Kd
         b6gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXM3NQTF6/tvzYJuFrR9xfG7Y19zQZWQkSXzADJowf7QqFwNrnj
	k+ErXwo2gzUMI4NfPFjYNv4=
X-Google-Smtp-Source: AK7set/qJotWoC+65FDCYYhjM2UbGD+RtSpEXDb3oYADGjzu2eEyeD+cZn1wspvL06+YifjpRYvz2Q==
X-Received: by 2002:ac2:4c02:0:b0:4b5:886b:d4af with SMTP id t2-20020ac24c02000000b004b5886bd4afmr3154313lfq.276.1676063900785;
        Fri, 10 Feb 2023 13:18:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b25:b0:4d5:7ca1:c92f with SMTP id
 f37-20020a0565123b2500b004d57ca1c92fls1441075lfv.2.-pod-prod-gmail; Fri, 10
 Feb 2023 13:18:19 -0800 (PST)
X-Received: by 2002:ac2:5483:0:b0:4db:18da:1bc9 with SMTP id t3-20020ac25483000000b004db18da1bc9mr2987497lfk.60.1676063899838;
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063899; cv=none;
        d=google.com; s=arc-20160816;
        b=CZkyKeaiRRBSdhGsaD7iz3RGNUJFAadC0qPQ+br71lbRzo5w1QD68Hn2xEkQQ7PbYz
         jrFHvfmAd6sj34mj8JFx4qWctgXUBhpvYGUSMjZiiveGToXvGgMeIXCe6DT53puC5Tqb
         3BZqJ4z4YXyog3LkblTwFAU5wCBo6Kg7hONxy2T5wQKqr6l0rsvUxkpOK+7EGJhqd2mf
         nB6ePk1AYpqa4RBcQ7bdo+ZWrM/9xM27wHVYlilclqQv76tRzOf/BJYwySbLafS9iYVH
         xAXxTLI6P+DJTQtwqfEBu26YC6yolSgxnXnmQOKT8em1EazGM5RaRu6rqiMw2WZ9rknn
         Qk8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UVeF/wdyK+2zAJh1QGD4/79VjlNXyPEki9KG1Xr/HS8=;
        b=A+h/kr7az0JCrIfIvl18D3c6SpvEq/S9+Vavmj2D8XIRx+O2dVRAOoOlkG4mtGOPn9
         enh8plWSuJ/9HKjhxTl4tdvGT220TGr3gkPtW9dI6F4cufl+jdQTvFW2oA0KS9rq1KHL
         E2QEMf7+5WycRilwYmuO3R8GI+QQxjHscq8OB0Z8Xwm7hev+I2WhoqLugZjbeSzGIhDu
         rQTSMf7u4ZLhWMV6fgDwCU0GWrJ/d35mx6o6S5qJeyTgMzslvwwNh/j/qcnl/2RfzDoO
         TLeRtpcFX5ikIA6Q1aMHiw+/WiSI12xMHtmozlVBAdyNpDiHCkhjuIru0PETS4Lw3zuH
         vwWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mZ77UXQw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.147 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-147.mta1.migadu.com (out-147.mta1.migadu.com. [95.215.58.147])
        by gmr-mx.google.com with ESMTPS id bp27-20020a056512159b00b004d57ca1c967si315942lfb.0.2023.02.10.13.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:18:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.147 as permitted sender) client-ip=95.215.58.147;
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
Subject: [PATCH v2 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
Date: Fri, 10 Feb 2023 22:16:03 +0100
Message-Id: <317123b5c05e2f82854fc55d8b285e0869d3cb77.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mZ77UXQw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.147 as
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

Changes v1->v2:
- Mark stack_depot_set_extra_bits as __must_check.
- Only assign extra bits in stack_depot_set_extra_bits for non-empty
  handles.
---
 include/linux/stackdepot.h |  4 +++-
 lib/stackdepot.c           | 42 ++++++++++++++++++++++++++++++--------
 mm/kasan/common.c          |  2 +-
 mm/kmsan/core.c            | 10 ++++++---
 4 files changed, 44 insertions(+), 14 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index c4e3abc16b16..267f4b2634ee 100644
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
 
+depot_stack_handle_t __must_check stack_depot_set_extra_bits(
+			depot_stack_handle_t handle, unsigned int extra_bits);
+
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
 
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 4df162a84bfe..8c6e4e9cb535 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -357,7 +357,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  *
  * @entries:		Pointer to storage array
  * @nr_entries:		Size of the storage array
- * @extra_bits:		Flags to store in unused bits of depot_stack_handle_t
  * @alloc_flags:	Allocation gfp flags
  * @can_alloc:		Allocate stack pools (increased chance of failure if false)
  *
@@ -369,10 +368,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
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
@@ -382,7 +377,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
  */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
-					unsigned int extra_bits,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
@@ -471,8 +465,6 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	if (found)
 		retval.handle = found->handle.handle;
 fast_exit:
-	retval.extra = extra_bits;
-
 	return retval.handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
@@ -493,7 +485,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
 {
-	return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
+	return __stack_depot_save(entries, nr_entries, alloc_flags, true);
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
@@ -576,6 +568,38 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
+/**
+ * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @extra_bits:	Value to set the extra bits
+ *
+ * Return: Stack depot handle with extra bits set
+ *
+ * Stack depot handles have a few unused bits, which can be used for storing
+ * user-specific information. These bits are transparent to the stack depot.
+ */
+depot_stack_handle_t __must_check stack_depot_set_extra_bits(
+			depot_stack_handle_t handle, unsigned int extra_bits)
+{
+	union handle_parts parts = { .handle = handle };
+
+	/* Don't set extra bits on empty handles. */
+	if (!handle)
+		return 0;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/317123b5c05e2f82854fc55d8b285e0869d3cb77.1676063693.git.andreyknvl%40google.com.
