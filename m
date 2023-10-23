Return-Path: <kasan-dev+bncBAABB2F43KUQMGQECU6HPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D2D57D3C5F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:14 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-507b8ac8007sf3748851e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078314; cv=pass;
        d=google.com; s=arc-20160816;
        b=XxdfBo3jhcZG4UAUJjSbZedADgHlwqtezl4jjPCG4G2luFCF2Uf/68ycWTsJX12Ne5
         wvRui5UJ+sJsW1s/5ZvMdbx2Qil63+ZRNHoba/a3vDgoc+v24UqatLli6G+PcCjGxTPx
         FBCVWzDf2mG2K4ERBdTIol3jVeeUKgzajHfxuhqchnO3TYjZldQv/rfy2WBJDLEFhO8Z
         QjaJevO04949DDS9m3odszm6ZXkEWmU9lZ9v8wo34P15XGtkX2zCIDYPs4R0mzKxUbav
         Fnj20E9hKHmlEYo6mnYgPDrzvMe7s18msNzFi8uQZk0TLgb41YnT6jZ3T/tHhzkcjskD
         pI8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zpYIUvNliDw3mJeVitdKkaMQMAswOFuO1LhlFppl5GM=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=PdmemUYVSAt+JvXHEHgSluT3WNJeuW9QrDfPDbd4YzgVGPiqnBb0B8OWOQxkLemayA
         K8pG0hdK2X2OMEe5X1T12/RQ7poa0YY5lyHk15fHroUTDv0WGe2E0Go2+0fqgxhsUsi5
         8Jxk+NAjtbjYy7HWTPR+3d407QPod9/02YvKgX3G6ZZlLdjkn0Whj6S+/+I618hqYIbF
         P0nvbZyUthDjb75oZU7aM/RC1sj2R1e7646RXWia2SWaBxxzX9BjPvKzxDIyzBG5A1DS
         uJ6i5tqYRD13NaXPy+oAZ3S+yEZyPemqBDOTLAT6I4Jb3WiD6j+dINDyiSGMYMWeG7YQ
         9aRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="oyH/s4RT";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078314; x=1698683114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zpYIUvNliDw3mJeVitdKkaMQMAswOFuO1LhlFppl5GM=;
        b=tuqHO2IKiLAhxfWVycieXW5y3ns+q5pgTdZGlPQpD4n9v+l8iawavIHRbDJL5clvgv
         7Z1URKnKFI10YdR0dzgXxQ2C6gJXx5sK+FESEzNztXEDuDYVs1NYJiKcfYLgIqP11NpY
         1PnWUg349UL9PiKiSHRuO5ddHBWQZ93tWCBA8fE7u8HeQhCsOv/dOrguuJIutByN190c
         X4JjTP0mr5XFDXXErSuMgew+4sdN8MHS1HCPF2UYT6aTO9PPoRL11lG/zItl1O2Li8d0
         eKVAtlBLWhZiKl11SJLUrZOnKdwrolGKm+ttEeybyiJTu88mwSl0NmY4s7SeZyvFsEMg
         qHaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078314; x=1698683114;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zpYIUvNliDw3mJeVitdKkaMQMAswOFuO1LhlFppl5GM=;
        b=eIqWnPtOTZ0EKUL6dkZ4VEwTuBc4Oh2zg8hKLp9N3Lc1zUfj6IflzwCFJ2b9jhuRo7
         dCu0RPAf7HyAkxHEBR3Rdov60Ogpm2UN9bYfaCEDNl0p2C45VBxmS9wCBK1gVdRN+0h4
         4Wp2oPF5DyTvgR24KDGrzJ4W26bxOiiTFxnpMHxXv0NammhXnprO9ekrJN81EIn4exmu
         oIGFJ0dfmaZimgcL3k7jPFuOLTfn1oiY8NYoUfkwu7+LCSVXIxxVYidFOUR7V5V33CkZ
         SxpfTeG+tFHDfIf9YLULkdTXOuWir/uYhVAbjoBDk5UE4lm53L5jZ533PMhKsCHfxzhT
         GfMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzkD4gSAp3qCfGkvcomX9FDsid35+m7ANuEm6lBhm2jkbb5GzSo
	Gks6C+HsN+GRydE1mgcnK/0=
X-Google-Smtp-Source: AGHT+IF46JihnFEixg95dRLEs+jQBGuoJVv5m9qnD/wSWWDnj9TL6NDQVkicPmKLYEKrOZfdmeQywg==
X-Received: by 2002:ac2:5550:0:b0:503:258f:fd1b with SMTP id l16-20020ac25550000000b00503258ffd1bmr7002312lfk.18.1698078312459;
        Mon, 23 Oct 2023 09:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:eac3:0:b0:540:1929:1578 with SMTP id u3-20020a50eac3000000b0054019291578ls706682edp.1.-pod-prod-08-eu;
 Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
X-Received: by 2002:a05:6402:254e:b0:53f:5467:cc5e with SMTP id l14-20020a056402254e00b0053f5467cc5emr8099403edb.19.1698078310960;
        Mon, 23 Oct 2023 09:25:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078310; cv=none;
        d=google.com; s=arc-20160816;
        b=uFEIqznOLP2pM1o/xRP3ZqyLx3Ltb5aONQSQamyIenBdeKNW2x0yzpNW1m214zQecL
         JVluRo+U9zJXmhRrjBBMmrslbGXIh1iOdyIEGo4dsM15rW3vSjohzKcBmDNzsBg1saUP
         4sJeRthOxAw3iUIeUHj2Ne9YZCeQg2ojBQ4hJdQ7mh9EYgvKqOXonlRevPdJyRahgbIv
         Kuv+LK13en90IWX53kFDlTm0zlA/iWhNP2A5s/MQ49glxcgArg03KzyctDLqqunxx/MB
         MtCpEgVE+L3GmZ39TxAqTYtiMixFmpW2xoxj8Zn8+UWv4Oyy+V9YzSd0K+CatCNY8cBm
         hOZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KyQaV2ck0CZBTZjrz6rGoXlFfvUUwlefDCsA1d1OnDI=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=eqvcc9CaUIkzb43DNVjgBf1IPYiGQPQjjOdq7UI4FS/Tq03u2AiXzWRvGf3Gx6Xurp
         98XWVviLpzwLRfVfggkglEFNiXoC9JVFvHUij0aQQ6VDvOcQ7jnOL5Pte3kMUvaVwML9
         OEvC2mnmE3r85cbcPjJgUYEuAt5eqCB7fV/Gt8t8Yhk3tRc4m/fdCxBYIl5rZdnax1nW
         ewbitX1quKb/58XjOHdFAQmmIP9bg6p8Xnc1bxx4GBsCGInnb5rkhSqkDP1Rz6dlrnyz
         45jrn8QUel8CQNl7YfP9Djgr7xacGHx0U9rG1nsaGtDWGdlDTpxWt1vfwikgQpZkPJs1
         5KXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="oyH/s4RT";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-199.mta0.migadu.com (out-199.mta0.migadu.com. [2001:41d0:1004:224b::c7])
        by gmr-mx.google.com with ESMTPS id z92-20020a509e65000000b0053e90546ff6si520760ede.1.2023.10.23.09.25.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c7 as permitted sender) client-ip=2001:41d0:1004:224b::c7;
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
Subject: [PATCH v3 16/19] lib/stackdepot: allow users to evict stack traces
Date: Mon, 23 Oct 2023 18:22:47 +0200
Message-Id: <8ba201688d0e4b8f3ec56b426bb350965a30c8fd.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="oyH/s4RT";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::c7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add stack_depot_put, a function that decrements the reference counter
on a stack record and removes it from the stack depot once the counter
reaches 0.

Internally, when removing a stack record, the function unlinks it from
the hash table bucket and returns to the freelist.

With this change, the users of stack depot can call stack_depot_put
when keeping a stack trace in the stack depot is not needed anymore.
This allows avoiding polluting the stack depot with irrelevant stack
traces and thus have more space to store the relevant ones before the
stack depot reaches its capacity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Comments fixes as suggested by Marco.
- Add lockdep_assert annotation.
- Adapt to using list_head's.
- Rename stack_depot_evict to stack_depot_put.
---
 include/linux/stackdepot.h | 14 ++++++++++++++
 lib/stackdepot.c           | 35 +++++++++++++++++++++++++++++++++++
 2 files changed, 49 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 611716702d73..a6796f178913 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -97,6 +97,8 @@ static inline int stack_depot_early_init(void)	{ return 0; }
  *
  * If STACK_DEPOT_FLAG_GET is set in @depot_flags, stack depot will increment
  * the refcount on the saved stack trace if it already exists in stack depot.
+ * Users of this flag must also call stack_depot_put() when keeping the stack
+ * trace is no longer required to avoid overflowing the refcount.
  *
  * If the provided stack trace comes from the interrupt context, only the part
  * up to the interrupt entry is saved.
@@ -162,6 +164,18 @@ void stack_depot_print(depot_stack_handle_t stack);
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
+/**
+ * stack_depot_put - Drop a reference to a stack trace from stack depot
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ *
+ * The stack trace is evicted from stack depot once all references to it have
+ * been dropped (once the number of stack_depot_evict() calls matches the
+ * number of stack_depot_save_flags() calls with STACK_DEPOT_FLAG_GET set for
+ * this stack trace).
+ */
+void stack_depot_put(depot_stack_handle_t handle);
+
 /**
  * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
  *
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 278ed646e418..3a8f045696fd 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -404,6 +404,14 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	return stack;
 }
 
+/* Links stack into the freelist. */
+static void depot_free_stack(struct stack_record *stack)
+{
+	lockdep_assert_held_write(&pool_rwlock);
+
+	list_add(&stack->list, &free_stacks);
+}
+
 /* Calculates the hash for a stack. */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
 {
@@ -586,6 +594,33 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 }
 EXPORT_SYMBOL_GPL(stack_depot_fetch);
 
+void stack_depot_put(depot_stack_handle_t handle)
+{
+	struct stack_record *stack;
+	unsigned long flags;
+
+	if (!handle || stack_depot_disabled)
+		return;
+
+	write_lock_irqsave(&pool_rwlock, flags);
+
+	stack = depot_fetch_stack(handle);
+	if (WARN_ON(!stack))
+		goto out;
+
+	if (refcount_dec_and_test(&stack->count)) {
+		/* Unlink stack from the hash table. */
+		list_del(&stack->list);
+
+		/* Free stack. */
+		depot_free_stack(stack);
+	}
+
+out:
+	write_unlock_irqrestore(&pool_rwlock, flags);
+}
+EXPORT_SYMBOL_GPL(stack_depot_put);
+
 void stack_depot_print(depot_stack_handle_t stack)
 {
 	unsigned long *entries;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8ba201688d0e4b8f3ec56b426bb350965a30c8fd.1698077459.git.andreyknvl%40google.com.
