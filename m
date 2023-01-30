Return-Path: <kasan-dev+bncBAABBK644CPAMGQEQUDOCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 063C6681BDB
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:53:00 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id z2-20020a1709060be200b0088b579825f9sf910993ejg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:53:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111979; cv=pass;
        d=google.com; s=arc-20160816;
        b=vPLkPVl2wRZuPHGocM5eD9ve0vTE+u+HRDa/91RGoggsD4ASuK4B7+0YbP5PSpVHsH
         +j1+pd8aYqe9UZ/2GIEcLcYQ3R4ADnkaqO0GF0yJS+vJKOc5am+TMlHA2qrTq1E8Nusc
         m4ygOL0XwgqY3d9Hj5WM3PMTU0zk8T7t/M1Lf0p5kFRe0p8YKLcSBeb7H4RMJhuFuk53
         SffObTKiTb2Fjmify9tSEECF9NuMlLBlqNrDK+epu8N3TYVOfACOxaeSSIU8vDou51ob
         rk39V7ZeR5RadbfeHQ7TZypmnOR9ShDveElpAJ5JeLOTnKoTSF6pYKe2foWV7Z62fw2B
         jarw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yO+lBBAlz/j9pGENiJ38miq7z0EMQxVAog4TOecjGuM=;
        b=j4Zhy2soURLCbPXF7wdRv/YIy7Nvmn1NfqWAzbYnn/4PlkmCo0TQnYiOd5QppXYQZh
         jcsYSeEhlv2qMFzUIDpfOjI94kjJ3XNs9wyNB3Z9YqXkWlsBDjfQWsEJdV+d5fW6CidS
         y8hgfY7eqhhBA44hgEpLaKhhj5NPGHERfjoytd2VENlpSvXDCVNDq6VoulmY1qU9tnJX
         s+wbrXY9xu44D8VB1A4/O+EVJ0bsYIsRwo7RQFa2p6+/IFf5Q9GemgDHNsbKqeHoKtbM
         w5HtcDD73G4kuTqprFL36bFIrQ5Zr889Rjqr+sSMr24b/r5VG98bB4cKeJjAPCYhJBna
         zxqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=g+SFAUpU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.85 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yO+lBBAlz/j9pGENiJ38miq7z0EMQxVAog4TOecjGuM=;
        b=dM6zrB6ZtabP/9Zz7o7AQNAgj9b9vhubMGzDPWAmIN9R4myY/hBC41n9OKqoERqeCh
         w9mAhMzaqYIa2TC1bOmLfzb5xCyhTI2VzkuGgvmrOcrjfHVeQ1wUI5a6g0I74HS856Qp
         NIBkzFtP3h5EEYqzVkQxcs1cYuW2900+Z+WYi210RrpZitjL5yzUz1YXsQJH5nMkIyBa
         6myw43wa9iuEsESI98qiC6ki3SekNh1GV8IV7bKBfWucqmqh/aKU2xaBXqCMJ5QfSSOD
         AJ2fZiURGc5/HbHRSJLPz4Jt90JdyOPe3I44zjq4YtOcky9vNGEiG2WUlm3C/qE35jpe
         AosQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yO+lBBAlz/j9pGENiJ38miq7z0EMQxVAog4TOecjGuM=;
        b=diYCbEGRq2bRVBnboxlbQvFwp6q8S7vdGgA6WT4KGMVw4hyTvvavRSWhLP561WlKoB
         P/maRyuJ5mXFSHAaK0vOkN870/oFdSCusttt0g2clHjen9DIzcLElXBJll7yGUv6cw9t
         B/43jfC3pwyqtpKstpncnoZhvC/JXZs+FOokduMp2mxr8+/EJ8/ybpBZoO/bERQDGsMa
         l14aMXgv7J0b479in5aUrZE2Y3P7GlzswcdUC9VrRqM2q9IKmO/q9WEMkytGaDz5beh5
         vGvz7uj2OKzzmGhF/0ODPiEnbcVqqKOl7v1TG1ElUqPdyB5/t48IGQbjQaohs5OKUwqG
         ZL1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqBfRJeWKxBhG0+hnd+UxZDeJIxg8iXU6wo2ikqQNEPu4PmWopN
	ml5oDfWN9Bd8zz8HwBaP2kE=
X-Google-Smtp-Source: AMrXdXtpW88BUY8qyAcAVcnftZi8gbPrS0dWJufqltOQ2cB3DmeWBN3s2Bhkj0WIMLR25jSQOjS9Yg==
X-Received: by 2002:a05:6402:e9a:b0:497:382a:6a7 with SMTP id h26-20020a0564020e9a00b00497382a06a7mr9031720eda.9.1675111979593;
        Mon, 30 Jan 2023 12:52:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:358e:b0:884:37fd:bf43 with SMTP id
 o14-20020a170906358e00b0088437fdbf43ls3893459ejb.6.-pod-prod-gmail; Mon, 30
 Jan 2023 12:52:58 -0800 (PST)
X-Received: by 2002:a17:906:ee8a:b0:884:c6d8:e291 with SMTP id wt10-20020a170906ee8a00b00884c6d8e291mr12140092ejb.57.1675111978579;
        Mon, 30 Jan 2023 12:52:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111978; cv=none;
        d=google.com; s=arc-20160816;
        b=neO6l0MZELM1c4agT9Uw9bzrHFA4/1QqEBenIC4qXOrZ276AP1I+8V5gSMm53f25Uu
         Es8j2y7PR5zgla5eQPZn9MPtFTL5lhN3zO9cu3q4fQGoSClk3LAhbT/sdkfcI4/wSPWi
         ickrQYkbQJmnm3m27zb/0gFfXeIHW2XPvUFBOSrF7ugB9NZl4IxDQQgsKgoPAhMKOoWC
         LTEopVlbsB0tSrfXPzqtl1/9Bis01sRtQ+nv538UgRL+jiE+FO+zqczUEmRW2SlQvZVL
         c+yA3oJDi7kkB3fL8Y12DLqow+rGjT0E//TM4wSWp0boLLh7aTlLdH2i949k/ZcjUT19
         ccWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1w0jiNXlV5BHI7ghVa1ATPJTlO9YwfzPGkwsURa7liM=;
        b=G+j3U5A2jeJtEvEfA/cAN4NT1JjNuvyZXaeCHDmomH1+v8ALGTRolKKL8kD94zg853
         Y7H93kmDVZXg0ib1SZau+av9gPvVYqdzDLT2RlM0467AkKfeFctlo9xLfsOVfK3kGiad
         z/BYLLg2Np2O2xVkQWMfYYHn9GXbLD8NokpHQdBa9wWu+6yv5BaZrlYktb2hEpXVi4ef
         3CFXhV0KjRNMLAt4L/6xLQOdpiA0EKMzMaEgDc/Ff9DaNuvlpFo7FCtpJkoWtkyVdTDH
         W8sgfTiVwCeUDYjIrZlDKmsKiV89fDo8S2Y4kHEGybJvJCzdWEWS+NxSxQaGbaOU3jVp
         uW0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=g+SFAUpU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.85 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-85.mta0.migadu.com (out-85.mta0.migadu.com. [91.218.175.85])
        by gmr-mx.google.com with ESMTPS id ca22-20020aa7cd76000000b0045a1a4ee8d3si519225edb.0.2023.01.30.12.52.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:52:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.85 as permitted sender) client-ip=91.218.175.85;
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
Subject: [PATCH 18/18] lib/stackdepot: move documentation comments to stackdepot.h
Date: Mon, 30 Jan 2023 21:49:42 +0100
Message-Id: <341353394ec1134c5a92a2b298348ddc4c48c8a0.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=g+SFAUpU;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.85 as
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

Move all interface- and usage-related documentation comments to
include/linux/stackdepot.h.

It makes sense to have them in the header where they are available to
the interface users.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h | 87 ++++++++++++++++++++++++++++++++++++++
 lib/stackdepot.c           | 87 --------------------------------------
 2 files changed, 87 insertions(+), 87 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 173740987d8b..a828fbece1ba 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -2,6 +2,17 @@
 /*
  * Stack depot - a stack trace storage that avoids duplication.
  *
+ * Stack depot is intended to be used by subsystems that need to store and
+ * later retrieve many potentially duplicated stack traces without wasting
+ * memory.
+ *
+ * For example, KASAN needs to save allocation and free stack traces for each
+ * object. Storing two stack traces per object requires a lot of memory (e.g.
+ * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
+ * stack traces often repeat, using stack depot allows to save about 100x space.
+ *
+ * Stack traces are never removed from stack depot.
+ *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
@@ -57,24 +68,100 @@ static inline void stack_depot_request_early_init(void) { }
 static inline int stack_depot_early_init(void)	{ return 0; }
 #endif
 
+/**
+ * __stack_depot_save - Save a stack trace to stack depot
+ *
+ * @entries:		Pointer to the stack trace
+ * @nr_entries:		Number of frames in the stack
+ * @alloc_flags:	Allocation GFP flags
+ * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
+ *
+ * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
+ * %true, stack depot can replenish the stack slab pool in case no space is left
+ * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
+ * any allocations and fails if no space is left to store the stack trace.
+ *
+ * If the provided stack trace comes from the interrupt context, only the part
+ * up to the interrupt entry is saved.
+ *
+ * Context: Any context, but setting @can_alloc to %false is required if
+ *          alloc_pages() cannot be used from the current context. Currently
+ *          this is the case for contexts where neither %GFP_ATOMIC nor
+ *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
+ *
+ * Return: Handle of the stack struct stored in depot, 0 on failure
+ */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t gfp_flags, bool can_alloc);
 
+/**
+ * stack_depot_save - Save a stack trace to stack depot
+ *
+ * @entries:		Pointer to the stack trace
+ * @nr_entries:		Number of frames in the stack
+ * @alloc_flags:	Allocation GFP flags
+ *
+ * Context: Contexts where allocations via alloc_pages() are allowed.
+ *          See __stack_depot_save() for more details.
+ *
+ * Return: Handle of the stack trace stored in depot, 0 on failure
+ */
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries, gfp_t gfp_flags);
 
+/**
+ * stack_depot_fetch - Fetch a stack trace from stack depot
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @entries:	Pointer to store the address of the stack trace
+ *
+ * Return: Number of frames for the fetched stack
+ */
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
+/**
+ * stack_depot_print - Print a stack trace from stack depot
+ *
+ * @stack:	Stack depot handle returned from stack_depot_save()
+ */
 void stack_depot_print(depot_stack_handle_t stack);
 
+/**
+ * stack_depot_snprint - Print a stack trace from stack depot into a buffer
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @buf:	Pointer to the print buffer
+ * @size:	Size of the print buffer
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return:	Number of bytes printed
+ */
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
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
 depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
 						unsigned int extra_bits);
 
+/**
+ * stack_depot_get_extra_bits - Retrieve extra bits from a stack depot handle
+ *
+ * @handle:	Stack depot handle with extra bits saved
+ *
+ * Return: Extra bits retrieved from the stack depot handle
+ */
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
 
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5128f9486ceb..06bea439d748 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -2,21 +2,10 @@
 /*
  * Stack depot - a stack trace storage that avoids duplication.
  *
- * Stack depot is intended to be used by subsystems that need to store and
- * later retrieve many potentially duplicated stack traces without wasting
- * memory.
- *
- * For example, KASAN needs to save allocation and free stack traces for each
- * object. Storing two stack traces per object requires a lot of memory (e.g.
- * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
- * stack traces often repeat, using stack depot allows to save about 100x space.
- *
  * Internally, stack depot maintains a hash table of unique stacktraces. The
  * stack traces themselves are stored contiguously one after another in a set
  * of separate page allocations.
  *
- * Stack traces are never removed from stack depot.
- *
  * Author: Alexander Potapenko <glider@google.com>
  * Copyright (C) 2016 Google, Inc.
  *
@@ -348,29 +337,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 	return NULL;
 }
 
-/**
- * __stack_depot_save - Save a stack trace to stack depot
- *
- * @entries:		Pointer to the stack trace
- * @nr_entries:		Number of frames in the stack
- * @alloc_flags:	Allocation GFP flags
- * @can_alloc:		Allocate stack slabs (increased chance of failure if false)
- *
- * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
- * %true, stack depot can replenish the stack slab pool in case no space is left
- * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
- * any allocations and fails if no space is left to store the stack trace.
- *
- * If the provided stack trace comes from the interrupt context, only the part
- * up to the interrupt entry is saved.
- *
- * Context: Any context, but setting @can_alloc to %false is required if
- *          alloc_pages() cannot be used from the current context. Currently
- *          this is the case for contexts where neither %GFP_ATOMIC nor
- *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
- *
- * Return: Handle of the stack struct stored in depot, 0 on failure
- */
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t alloc_flags, bool can_alloc)
@@ -466,18 +432,6 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
-/**
- * stack_depot_save - Save a stack trace to stack depot
- *
- * @entries:		Pointer to the stack trace
- * @nr_entries:		Number of frames in the stack
- * @alloc_flags:	Allocation GFP flags
- *
- * Context: Contexts where allocations via alloc_pages() are allowed.
- *          See __stack_depot_save() for more details.
- *
- * Return: Handle of the stack trace stored in depot, 0 on failure
- */
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries,
 				      gfp_t alloc_flags)
@@ -486,14 +440,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
 
-/**
- * stack_depot_fetch - Fetch a stack trace from stack depot
- *
- * @handle:	Stack depot handle returned from stack_depot_save()
- * @entries:	Pointer to store the address of the stack trace
- *
- * Return: Number of frames for the fetched stack
- */
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries)
 {
@@ -523,11 +469,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 }
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
-/**
- * stack_depot_print - Print a stack trace from stack depot
- *
- * @stack:	Stack depot handle returned from stack_depot_save()
- */
 void stack_depot_print(depot_stack_handle_t stack)
 {
 	unsigned long *entries;
@@ -539,16 +480,6 @@ void stack_depot_print(depot_stack_handle_t stack)
 }
 EXPORT_SYMBOL_GPL(stack_depot_print);
 
-/**
- * stack_depot_snprint - Print a stack trace from stack depot into a buffer
- *
- * @handle:	Stack depot handle returned from stack_depot_save()
- * @buf:	Pointer to the print buffer
- * @size:	Size of the print buffer
- * @spaces:	Number of leading spaces to print
- *
- * Return:	Number of bytes printed
- */
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces)
 {
@@ -561,17 +492,6 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
-/**
- * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
- *
- * @handle:	Stack depot handle
- * @extra_bits:	Value to set the extra bits
- *
- * Return: Stack depot handle with extra bits set
- *
- * Stack depot handles have a few unused bits, which can be used for storing
- * user-specific information. These bits are transparent to the stack depot.
- */
 depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
 						unsigned int extra_bits)
 {
@@ -582,13 +502,6 @@ depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
 }
 EXPORT_SYMBOL(stack_depot_set_extra_bits);
 
-/**
- * stack_depot_get_extra_bits - Retrieve extra bits from a stack depot handle
- *
- * @handle:	Stack depot handle with extra bits saved
- *
- * Return: Extra bits retrieved from the stack depot handle
- */
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
 {
 	union handle_parts parts = { .handle = handle };
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/341353394ec1134c5a92a2b298348ddc4c48c8a0.1675111415.git.andreyknvl%40google.com.
