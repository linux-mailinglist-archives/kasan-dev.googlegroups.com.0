Return-Path: <kasan-dev+bncBAABBS6NXCTQMGQE2YIECNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F08EA78CA53
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:39 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-401be705672sf25753175e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329099; cv=pass;
        d=google.com; s=arc-20160816;
        b=O1qEWSNjvktGrtli+XPcm6KAr+OzD/GqWFf5AOROlKG1eJBr6olxYPgp6wW4/J5S64
         IS10qIDeKwS+jhELCylfBz8t747NMSbJo+ZhR+hUuiMZCuKe/osqU/vsajagUq+5B2Sa
         nyL0vOSDYZE2kgbVXhQAEDh4m+iS80erYZsf9S8KM7QrqX9Ni0pLuh8AAY6lYllGyp3q
         OrV5hQezIapjfb6wJUpwso6sMIHdH7Pwn9M7l5XnnNGurv+6O7VbXlO71n2v6sUdfbds
         YASr1a3VRSmr4ajP5F9EvpLnOpMhd6VNyIUaOIogvmK/aiTgf+SOWrOk/o1EDAv9+FDj
         vi0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JgIg8CdQnKg6/BZ2CBYi+d7Nu6nSSu73R3wKMXInZCo=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=ilWCSwAA0qIXnmJUymy7LtA2MZGt8I1sCXIOYE2XZcSl86E7qCtet+Svbod5c8D1Hw
         jDcfavjv49JtAFeft8xIsARr8rwEB+3yich/TGPPdeKpU+3jFUOHTFnRP/t18NBKJUqe
         HspHdVVCh5935z9IA3lJ34dgaCuMZLiCVRwsPsRX0Mkj+yvs4yqT88SzvS85W2bjG7Z7
         H2Vzu6YhM0ewj62/sAwKYreIcJWXfesOHPOgLjGc6dc+OFfTx0XJkQ2SPY/BFdoKJVlB
         VsafC/MNQyyrNu9GWmS+Kv+qbVmJw9tX7ZHXaLVeVWHR5sA2a1hDkuZ/vnCSuQVpm0dk
         dVcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LIEnc9qf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329099; x=1693933899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JgIg8CdQnKg6/BZ2CBYi+d7Nu6nSSu73R3wKMXInZCo=;
        b=OAR+dbyRX3d+KX88wiDXq0n5hYvdGwDNsq8W8Byfb+HklLV3kRSmiNrN8ca9wZv327
         jB/FQ5YGOzg/GMFgWMaYck11H5C3S8GxwPBf1UaIuDcGar7fl8PR2wQUprw821el8L7d
         SxCCTnowZlnumPN0MqeqZpKhHsLWbMlFhkav19qsxQU3FSwjIU2OQunerXf6Ipfsvl6Q
         7A1fQ8TukjUTskv3W/BmKdq8ZYPMgxp1RSWME2YURx2SfUThMDMgcRrTuB2RiljxSv4X
         xWyFg5A1E/pr2JkyYh54vHsApZnOhRiotTxkWj8pl+DTungLMRwW4jUb19Sm3EQFmRux
         wtkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329099; x=1693933899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JgIg8CdQnKg6/BZ2CBYi+d7Nu6nSSu73R3wKMXInZCo=;
        b=BnRT91XtdofHLjc0hb44Zy9xj1RYS//k44hg/I4tgsjZkS40XXXZdkoQV9w65X5ZSl
         GrqbWbIck30zJcvp14nB1XBEr1JW01X08t4/nmVcVdxJrQqhlFGAtmK/bYgY0OsDt0iI
         hYdZuyF+5nOiWCsBGQpL2oMd2ZrPAnXIPHs+SyNTJdRf1HVu0JfvDnyQKzpZ8I7VEqJK
         DMx2CAAQruFS1Md2A96/tObOA0SwDnwZvofWn172oNSpOwJIzB2gFWiSGBrGZc+dGzer
         J2JN7cu1b9YkGW/3rkciG2wTrjNxJA+x7moMsKpmCPwJodJaEFNRo7bwpyDtqTJakE16
         /+pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyHp5k8gAJ7qEE5H1Tv9lSrbH/ofHEIJGRPh59EOjzCh99IORUK
	9bHEjqEael1sq49Qg9I/Pbs=
X-Google-Smtp-Source: AGHT+IGFgn/ieqJi33ENJV/duYu6xREwe7wrVWNiDDUUNnCK1EBJzCkUSGAaWFtz3FZU87DMBm/B8g==
X-Received: by 2002:a1c:7403:0:b0:3fe:4e4e:bedb with SMTP id p3-20020a1c7403000000b003fe4e4ebedbmr23144404wmc.4.1693329099434;
        Tue, 29 Aug 2023 10:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4c06:0:b0:3fe:e8fc:697a with SMTP id z6-20020a1c4c06000000b003fee8fc697als233410wmf.1.-pod-prod-01-eu;
 Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
X-Received: by 2002:a7b:ce8e:0:b0:401:bf56:8ba6 with SMTP id q14-20020a7bce8e000000b00401bf568ba6mr7263214wmj.28.1693329098022;
        Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329098; cv=none;
        d=google.com; s=arc-20160816;
        b=KLtCV14P/4nN5Yx2s3+BRNO5wqWlDMHjsVAKqYB9SHoGqDlPdWwDaF+WpM2iRFT91v
         Br3Y5p02yO4S3tQRhiP4GOW9OkKP/boZd8yeYN9a3fF2TuhliTtKYn2AVShQDA/oigW2
         OTG5vhA/sKK+iJWStkPjhDpRmc/2qG1PHC4bWdfZVGSAyYE8DM/frymm6n1aQK46QNsP
         sPJ/29xzdcJEYLaomfEI4N7BVi2BssfREuTRcFtWugK2ujXGgf6wqBi39cQwq+b99o7F
         RfyS7y9MZFHMp9k/qKZE47oQwGivilWpM9oPdDQqpRo3QfAANu6qMKCJrgRyue7JN8xV
         m5Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iO6rOKx0E5Y80aTOb2gdl835Yi8CPfP2ICeqYsm38a8=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=GBAPOBqbyFovbqip5Sr4qAEBscnLV0PqamTTi/CygjkG9JUriF+ZZais0j79EOld/X
         HUB9lIrbQsD0cMLG57GusKduhDXFtz8IPinC7uoQYZa0GG3U1jP6BvnPO/a7tAi7rO84
         rTIjJYI8KC4itnnxtyxxc8G+Yvl7TBgg+seL3D0AyPIofwvppATFJr5ojuvZY1t8Oyr/
         eG1rQH6qPFgL7Y+RLTmG5UBW8ltuAusk6lbE5Y4gOQ7/8hEVz0eG2K5Gcb4bBhO2d0Cr
         ePaI/3uL+mmQ46OMnK4ua5ZsKToRL0JQ7ZjWpExgACZK01OMJekYw37VbpM/FMTcCwcI
         mJYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LIEnc9qf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-242.mta1.migadu.com (out-242.mta1.migadu.com. [95.215.58.242])
        by gmr-mx.google.com with ESMTPS id n30-20020a05600c3b9e00b003fc39e1582fsi90082wms.1.2023.08.29.10.11.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as permitted sender) client-ip=95.215.58.242;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 04/15] stackdepot: add depot_fetch_stack helper
Date: Tue, 29 Aug 2023 19:11:14 +0200
Message-Id: <757ff72866010146fafda3049cb3749611cd7dd3.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LIEnc9qf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.242 as
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 45 ++++++++++++++++++++++++++++-----------------
 1 file changed, 28 insertions(+), 17 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 482eac40791e..2128108f2acb 100644
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
+	 * depot_alloc_stack.
+	 */
+	int pool_index_cached = READ_ONCE(pool_index);
+	void *pool;
+	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
+	struct stack_record *stack;
+
+	if (parts.pool_index > pool_index_cached) {
+		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
+			parts.pool_index, pool_index_cached, handle);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/757ff72866010146fafda3049cb3749611cd7dd3.1693328501.git.andreyknvl%40google.com.
