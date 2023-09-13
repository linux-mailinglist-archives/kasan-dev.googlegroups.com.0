Return-Path: <kasan-dev+bncBAABBDG4Q6UAMGQEBC5D7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 84BA579F006
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:53 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-401e1c55ddcsf318175e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625293; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZxDI/vfwLxeELjZSUKXUUyVCr8iSnBlJqkH4ccQTfO95Tb6PN6nSG4Wg6Ve9Zp9nP
         lQGe3QnHIH6N4v9nprF9u0+vFf2Ca3kN9onP1gkZ34/1FKRcJRTZMvZd43xqPtvLr1E9
         ikMeVymOwwfShJj4dM2PNhc9W8DkNg1WCNIH9sOvSnzvcEaRJkcJAtoG/ByXJ6U2gs2W
         07FzhuiTkbr5GzpahMvEGkl46mzbAsfmLZqvJ+kig0iVuVZ3VbWXaQcQMpFJRE+SzVH4
         ASQqMf1alpqOVyaWFfAZbV6N3bqTVl0e/o03+KahUEh14hcS1xaCegldilFH78Nc08XZ
         V2nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JBlGnKrlIrMyeFnLaxlo2nTF2HozIwo0dIBXMQgS+Pk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=g3PoCs02nxk+eMChW2/lcYDaksX6+nkrhlsSZaxmOgAgdDVlERr+YLkZ9rZxt5/eTP
         rSclEZFSCiFq9bomfpUy9iiurE8emvmXEWwVzMSWAFs7pb0kSWvF1j+OmJuH2Ui2Ls7X
         3zwGdBGdtlEZjzq8sTYgOD4rvulRQK0lhsxcZobRCjkx9/8cY7DbLKzoP16diNkKxbvN
         mx0CQbLLGEe+USceZ+/Z94LDnk9pzxstTI+WcSvcYbLyGj8Gy1cZZRNdhf/wz8JZeLlL
         /c2UKq/DxyPHHb0uF9WSTaEJkIPy3+7+dqpD0CiDnEGpA1xDGj+9nultEd1mWNKLArtE
         77AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ctPU1P8P;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625293; x=1695230093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JBlGnKrlIrMyeFnLaxlo2nTF2HozIwo0dIBXMQgS+Pk=;
        b=FmSJ2pnOfvOGlGIhv2N76gZjvBsZ39/ynrMLeRQcAap2yWh+GSHXN470deZin1Drry
         YJpVrqcFt2Ylc0fFgaV30qtE1ohB8aGh9NLLZDM6zQszt+tE0KkbTiW4VpqOm+jmaBkC
         tVelfBGOmx3o42T2G9bB2SwkWnakG2lzKwDwp6rhFX0gYof16T4iEcdIXWnllWKVsnNC
         MtEPBkslVPynVNoRWhUiTq5vO67jk0B8Xz4Kib8YJhJjvPuu7O9/y/rA3xqtpy9ENTx4
         yHswxb7mFXx4lUyn7xrffABU0PW3kudbYivvxdOfgJsjybVPYMcQM+fNIBlww9tE7tVc
         khXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625293; x=1695230093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JBlGnKrlIrMyeFnLaxlo2nTF2HozIwo0dIBXMQgS+Pk=;
        b=WwvOtZLUwsAdTuuwVADFvga+OMyncH1ZHgiWSEhmVUtNRh8+1zgHGHG7DlizMcXeWX
         0+KCLeA3CTtebg9mpU0p8nQlqafSeTtmyz/4vcoEgrERMMy5b9M+Nl/a6eRthvwtME3i
         ato7pmmhlmLnNSWTi3Uv+AB3ew4+KIMsrs4GzXDigHzqon3ZXU7tDKEMcndlAntBxrxN
         YZ0bbwHsLkblA6rPJRhxFVMNNLfWowWYyAKtvQCsukNrgKlbeOQZNZ4TXaRMoj9NbcpF
         zIIWljEouT7rLPOcbIggldQWoDSGUA1FRM1hoZO1iVMrESuo/fJM6EBkvqz1wW2bzj72
         aeQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxpbK6vsE4KSPMW6sR/Rhu4nHrjT42TuF84xlwHT6jsBmfJlTOh
	BsU1fjHBiHK5nNhPwV+XJcU=
X-Google-Smtp-Source: AGHT+IHqW7CSZaHFzEdCy9SAaHLVenPaKXe4lVkG3/+uKFthk9SUq2NLQRqdiPfpt4sMuE5svYUunA==
X-Received: by 2002:a05:600c:209:b0:3fe:16c8:65fa with SMTP id 9-20020a05600c020900b003fe16c865famr2590328wmi.4.1694625292376;
        Wed, 13 Sep 2023 10:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:511e:b0:3fa:95c3:7e99 with SMTP id
 o30-20020a05600c511e00b003fa95c37e99ls2076152wms.2.-pod-prod-08-eu; Wed, 13
 Sep 2023 10:14:51 -0700 (PDT)
X-Received: by 2002:a5d:6687:0:b0:317:6fff:c32b with SMTP id l7-20020a5d6687000000b003176fffc32bmr2722267wru.53.1694625291021;
        Wed, 13 Sep 2023 10:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625291; cv=none;
        d=google.com; s=arc-20160816;
        b=T2dMSHKPF/4ZcWiybeMwJR64M8TpYO+y0X07PvqOtMuNp00NzsE4l52QNvuwR5XS3P
         F6UBb/B9sBZcJMBbf2TwxIrcvq3FZ3qzTX1VkgB3SBUjrV78BFc9BvgF0ZI2MQT7qUMF
         VssHukIjfeIeXvCH2gTuVx83p4rwKTBczy2Z5A+fYZeqUsVcaCKOReA7YgcJVdtn83wh
         QJ+HtFX9j7rYa2w+WRBJ447dl+P//JbqMLXsP5a6dBhYDUyumRr8Fl3M8izWRK/6y7sX
         4Lndp3Vo48tr9fP2HssXXdC3FuhzFkaA2gtS8ah09ZTDN+KpnQKFQkgoLoUPZ1JSp052
         klxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9Tw+dU2o5sfOuuXbX4FJVP/5BAKc6p0/nQ7cBmUzv5Q=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=kTAFS6Q7hzBqqUs5LjJwx8NzdTOxudai+6WPuolqmXSp3dxo5T0LOf6w5NdrBPAsTY
         5dv+9w1CXetdEDBsfQKPZotey1qe4B0H9H1vvieDpfd4273n3HItvVGn9oz0UK4WxKod
         Ght5bMN5lMTTFtXJYTXVPEryeCRXuz70anyE9xWMntpguy72ZlWXrfx8kAkVkZzKQdfe
         ZsRXFyf1UBkPOa0nzH6RDfubmCIopawjl0YJ4mGH3NeYvFM5KWLfDvRhj4pym0q2xlS9
         0bbTfOgh0LP+TnxSz3GkLDLq5GXumS8u58C288OS0fqfIL6vLajzaLOMmn5sWh4h1I/U
         0Kzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ctPU1P8P;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-210.mta0.migadu.com (out-210.mta0.migadu.com. [2001:41d0:1004:224b::d2])
        by gmr-mx.google.com with ESMTPS id o33-20020a05600c512100b00401df7502b6si224503wms.1.2023.09.13.10.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d2 as permitted sender) client-ip=2001:41d0:1004:224b::d2;
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
Subject: [PATCH v2 04/19] lib/stackdepot: add depot_fetch_stack helper
Date: Wed, 13 Sep 2023 19:14:29 +0200
Message-Id: <74e0a28a38b05f27f3a4b54d5fa93213672fcd30.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ctPU1P8P;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::d2 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 482eac40791e..9a004f15f59d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -304,6 +304,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
+
 	/*
 	 * Let KMSAN know the stored stack record is initialized. This shall
 	 * prevent false positive reports if instrumented code accesses it.
@@ -313,6 +314,32 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
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
@@ -456,14 +483,6 @@ EXPORT_SYMBOL_GPL(stack_depot_save);
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
@@ -476,15 +495,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/74e0a28a38b05f27f3a4b54d5fa93213672fcd30.1694625260.git.andreyknvl%40google.com.
