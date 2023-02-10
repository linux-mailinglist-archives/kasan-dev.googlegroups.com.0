Return-Path: <kasan-dev+bncBAABBWXJTKPQMGQECUC3FWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DCA91692925
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:19:22 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id o8-20020a05600c510800b003dfdf09ffc2sf3224217wms.5
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:19:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063962; cv=pass;
        d=google.com; s=arc-20160816;
        b=k8Dd3ic6i06DghBvf7fkV7CsCrdnnNndfF276yi2XOSYxy5VRAoBg9Y1UcB7wKv7SE
         lmo+oHwzjjfvry3obI88e3wGN3EIl84T0+YNU7l4TPaZc5SRUAyEIxxWReX42Gz5Wnuj
         sJ4jwa4dsM9jrbuALHd31xRUZpdE0KxuxY1QLy9Mml6NcKMQUrS30ZpULyWw81w+Yw3H
         QfW7c17cO9lWgYmOuxj9+jgAerqh1khnel5I+U20tMwH4gAJGSKMtn7lKIoswZKfWh5M
         Rf7otz/oFbLvhCdv3dndTLeFuTBF+NsbJpR4Bmypfgeky2jtp/cAeAZtFwebhC3hjfCv
         QFQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cscdyEUy4+cEOavAqSybPVFLedZbcSDZOU81EZS4koA=;
        b=Xhq9PF4FPJLZCPIq+vvpMNkdCit+2A6W69mOHZC1Pu7QURTMnLAumWeAQrA9cfxWRk
         KZkwka+wZNqfGmsGQSAMY++UGm0YBI+up3LCxNlLnnYGXS9Egcrd9l2BG/+6qwgW1e7I
         y4+0Ejkn0/Q3O0k7dkeg6NfmvL3Eg6bCbXLSiCfB58mwRdDC2jwsSbZrTeBPNPcgTxBH
         deRyDLrDrwUcTo/zOR1W/2YCXmVKf1sP4Dr39LbVi6fTDenfyZJy0sCGzUCt6zkWZzAh
         VdYNtKY3nICLdjgOBJ/ncYRMwJjRpQqgbpvmlx4iqAsIu5G61oO6grMOWSVtasuqkLzQ
         Q69A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s10+K4Rz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cscdyEUy4+cEOavAqSybPVFLedZbcSDZOU81EZS4koA=;
        b=JOLry2ggTVWIWZ5vEh8BG8SLOfD22Q6voc17D6EKmE4imoiRo8g9FYAZ69CiBHZO+I
         mG54QN3z0Y5PKLUwGaEGF7TPVaIh9P1qCRgKM3VcfJXXFqf33fnovaePqX/pd9/+n8AJ
         /dnVFhFpe/mlGHgbu0jORa+m9qGbQgRARAh8ML3LblhZYcmIDrhwnE+clotszL1qqtGP
         fZm9E9q0pR9/jboperlv1e9rKETjyLSDXJVLSMlz1thVzS1tlxdpFxjMbaR4Bqu9+oQR
         LflLqb3EhZM2FakNzN0neQi3wonyvMxLevSZQEN0rl+j02AcQ+1dzwsWzfmWRdxTWdHJ
         rqWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cscdyEUy4+cEOavAqSybPVFLedZbcSDZOU81EZS4koA=;
        b=mtYT32e0qIfCca9OUd1wGWP2T+x6tEvjN41kvBomngA1saOSanxPDePuvp6fQYlWqT
         ZK/ZtCAJXrz7kdhb/DiOtGVK8I32JlVogdlgqgigqXkXUesUWBue8PAWEIpi4eaOqqec
         ko93WgI6AtRo+Z78LviNFUQv0+A9vMQr0swQoVCNsnCZWt7vw09lIp+HfChSVWhnNmJO
         yzGCrUQXwcW7334ypL6PzK7fJ6jiD2EKZ/MqNuR2ynpHw+Wa4QFlD7PSfauxn28+5Aml
         r8UcgccCsWr8pLg6XxMYYIN5qxE+iuXk3un8OqtPUZh0E3ZlAYJdLBqmK2yGEyXCN67V
         VgDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX8DmhYGKcIvnTytvWNUrKmoTPTSOG2IHSlmRW2/LiQUaN61Z/7
	vHcKtiUlzqaJgnXvzlYkgAE=
X-Google-Smtp-Source: AK7set9YcAfVkx9brRxdb/XXDUoJDFvKJWwW5TZ+8j3i905T5txlvN0uPIRvtWZlbpZ5zvM7RBSSUg==
X-Received: by 2002:a05:6000:107:b0:2c5:452e:6b10 with SMTP id o7-20020a056000010700b002c5452e6b10mr245509wrx.345.1676063962501;
        Fri, 10 Feb 2023 13:19:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ea50:0:b0:298:bd4a:4dd9 with SMTP id j16-20020adfea50000000b00298bd4a4dd9ls2235803wrn.1.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:19:21 -0800 (PST)
X-Received: by 2002:a5d:4808:0:b0:2c3:c0a9:650b with SMTP id l8-20020a5d4808000000b002c3c0a9650bmr5339599wrq.13.1676063961705;
        Fri, 10 Feb 2023 13:19:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063961; cv=none;
        d=google.com; s=arc-20160816;
        b=frCevCMOxNJKXIM50CL8YlmKukICmeFfD0KKt9yoo3gnD7oPtTcuGSjk+IqSbgHfJD
         +Oc47ZXmUhSNiaZPQog/huBhs0nj/Cc3xvoNunvHgpb2mnpkSmWej5vseEaDRr7UFfVX
         ZxOpBui2sLRg5kdf4C6Vwp/P4R7hetNCg8l1osQinSimExcpFP4m61k+mZLNGfc9EFvf
         GBYt+nF4dqYk0AuFNDkD1lrudVUKATmex2H7oWy9CPDn5FlJVubXW+UdHQohDjZeQpau
         w6mDG59k52JJ9OqsEeGa6W4hYlo7v3mC5JaAYVvKrrY8bdt7XN0sPRwJUl+OaOkEVWgS
         Iqew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FT29KRMbRE0UIrHSR8VL9ToKxsY1mNQpa5JLen40C60=;
        b=BqeN1tURMk1+cxIANw4733d1jeYLHEX/351UIl6Z7T+sDaixXVHA+KEvgUGGmvdZO5
         zvY3bJcqOkKGbnQrDnZE9sML+SPtod8JMrZK9BKopy9HtPo+4lrShCNob9Sr0xdMt8Nz
         cEvZS4DnrxoMeCgYzkKbnZ5w7HZ+lfvLSnVA/k7+pJGZUUxQrbD8F8b3B4uOyMTGPUxw
         OsiD39/966p02QcjqjidhRJk9/2VB2UXLXozxJLuEXLouCXT785qFbFHgSz7n65BTEOH
         gvBNUY151qJmpun3tdzsPG8JgiW54Jn/XOYZ8glibCLKQLdvNwJzEkOOhvr8HqyisqPR
         byEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=s10+K4Rz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [2001:41d0:203:375::b5])
        by gmr-mx.google.com with ESMTPS id bo28-20020a056000069c00b002c3f03d886dsi280944wrb.2.2023.02.10.13.19.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:19:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b5 as permitted sender) client-ip=2001:41d0:203:375::b5;
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
Subject: [PATCH v2 18/18] lib/stackdepot: move documentation comments to stackdepot.h
Date: Fri, 10 Feb 2023 22:16:06 +0100
Message-Id: <fbfee41495b306dd8881f9b1c1b80999c885e82f.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=s10+K4Rz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b5 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index afdf8ee7b597..91f038829eaa 100644
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
+ * @can_alloc:		Allocate stack pools (increased chance of failure if false)
+ *
+ * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
+ * %true, stack depot can replenish the stack pools in case no space is left
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
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @extra_bits:	Value to set the extra bits
+ *
+ * Return: Stack depot handle with extra bits set
+ *
+ * Stack depot handles have a few unused bits, which can be used for storing
+ * user-specific information. These bits are transparent to the stack depot.
+ */
 depot_stack_handle_t __must_check stack_depot_set_extra_bits(
 			depot_stack_handle_t handle, unsigned int extra_bits);
 
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
index 02bb6cdb69dc..ec772e78af39 100644
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
@@ -360,29 +349,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
 	return NULL;
 }
 
-/**
- * __stack_depot_save - Save a stack trace to stack depot
- *
- * @entries:		Pointer to the stack trace
- * @nr_entries:		Number of frames in the stack
- * @alloc_flags:	Allocation GFP flags
- * @can_alloc:		Allocate stack pools (increased chance of failure if false)
- *
- * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
- * %true, stack depot can replenish the stack pools in case no space is left
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
@@ -477,18 +443,6 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
@@ -497,14 +451,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
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
@@ -537,11 +483,6 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
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
@@ -553,16 +494,6 @@ void stack_depot_print(depot_stack_handle_t stack)
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
@@ -575,17 +506,6 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
-/**
- * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
- *
- * @handle:	Stack depot handle returned from stack_depot_save()
- * @extra_bits:	Value to set the extra bits
- *
- * Return: Stack depot handle with extra bits set
- *
- * Stack depot handles have a few unused bits, which can be used for storing
- * user-specific information. These bits are transparent to the stack depot.
- */
 depot_stack_handle_t __must_check stack_depot_set_extra_bits(
 			depot_stack_handle_t handle, unsigned int extra_bits)
 {
@@ -600,13 +520,6 @@ depot_stack_handle_t __must_check stack_depot_set_extra_bits(
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbfee41495b306dd8881f9b1c1b80999c885e82f.1676063693.git.andreyknvl%40google.com.
