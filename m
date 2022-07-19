Return-Path: <kasan-dev+bncBAABBMXP26LAMGQE77V4PXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D18B578F16
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:15:47 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id z23-20020a2e9b97000000b0025d7496a2f2sf2298577lji.15
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:15:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189746; cv=pass;
        d=google.com; s=arc-20160816;
        b=tKX210rXaJ4sCeyeAeyx74p9Gzl/pc1RWWnJynD6BdbpX+0w+qZTMEfdQzWcpP3ecA
         aPjA9LwePJG17leLw9aCNlZYg91IKY/j1tYP/732d0UUGGVG3WQM5muxyPbuGhWC2wkw
         o0gh55sTIrKEciqj0NRshM5bFenxquDD4eHI80lv5i90u+v6sUR35f+SKoKZmbKCHzrz
         v/z4sMgXLaAdKPetTN2VzV1R4buMWLLMDX3/HPwqF+NgKfMWGYUIPW+xMFRDE42VgCkY
         +HCoa0JG/wU0R+ivh81yH0VWpaEFlKfeMvRCjKDouoyyzGE3W4Pmg0jgAePNJZpGfrLq
         PDZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AHgwEpwNfHKSgA1NrWjJWCjZcfr8n1980SwP/4QAwFw=;
        b=GHM/uKQnvY6Scdij5r8aB15IFRAEKogMJoCpd86eVD6ILX9rqIndh6WyLzPH1qn4zu
         PxO7QbtKxN+U0jChlRExqh1O+GHUzzb7tKWNzoTriSNK8d+pQCplvD68y49EEHilSv0T
         9KmckKRNgx43mcltOc87+IfestDjVQkwRDavIs+lO3vLsPt2cDKRKrY5GM//T5VCpFCx
         jYekSd1HJMeRxODCU59CZl6qtQ2D3rBSnnkqbJgHOinFHDDZtkmbS6tr13OCW0W+IzVQ
         WN2jMmPmxu9bC/ba7iUK9xV3nV0SWR2sVU2XOHKwA6vfJe+FTu8kOOLLNiW6/RhNR2tV
         kFkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZ9H9Xz4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHgwEpwNfHKSgA1NrWjJWCjZcfr8n1980SwP/4QAwFw=;
        b=jTr8SXd+DtFjE5QKvPDhxbZdKiJS5WZV9O6Lpdt3z//azESERAW1Q5Wzc5FPXUD17N
         1v3Co+MdOn609PMcAKJU/TSI4RLLIS1004davRizgA8hCtZRABnpxq3r0oDTdpecN6FK
         SUTWpO4lwdMvTRwru6YgsE3WUVFDYekiMJMTNI73tzwqws7FqTe+x9OgjG1FU8brr616
         Rza1jKkGvsAbOuDXoBIN2bm2xOojOSgfLFmxzCDg3Z+dGxghU/46WnlX/nPiRODzMQIT
         ai3kr95+/rMX3FU/vueoq2rRwXQMYnK9tjU1JQROICZ1NQmDy3IQmE6+fqCQzFxVE5aG
         KJCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHgwEpwNfHKSgA1NrWjJWCjZcfr8n1980SwP/4QAwFw=;
        b=bl7g2GmereyIdJQVlPs5HzyV+jzcvui0gYpfP8QaweCpCm3VcZKlcbh0J4kxg7QdlF
         hrZaMj5YUEHLd0H4QEeQex095wvct3ahCjM9I89ahzSuaTCqSVxEx+HqOeRfzyOKquRH
         KrK2XoVEnbBOAklx2tbJJ8SZFTqh5AwSH8l89LjRHcsMIMsbrb8Jb80LlwxPaoUOp30J
         PYoV0eUc2ulTvklB6L+Hi/6WzbhMtUAnGZrpIA1rTsxbJJ0tbX85KpjLoWQyTjXCUo6V
         gYRFXvjIEWmIl+TicFYQASytU0OoIDkU9dUH21UnT2YxpQ1XusvMiKVsTXnTWfrKbfkM
         Jpug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8/LTw/v2wAh6G4I2tlT6Pf1U5moeoCNDVFX7GM7O8qLL1d6aYI
	JsshLETLxNxyRDg7AvSw7Fs=
X-Google-Smtp-Source: AGRyM1t4vwzjQO5LL3e7oQYh6ku98M0ekahGIaQTktrDDrUqpzwqHd+MTtjHkaUEoI5bx5gI8ztKLQ==
X-Received: by 2002:a05:6512:2315:b0:489:cbc1:886a with SMTP id o21-20020a056512231500b00489cbc1886amr14960201lfu.428.1658189746386;
        Mon, 18 Jul 2022 17:15:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0e:b0:25d:9c9e:d165 with SMTP id
 k14-20020a05651c0a0e00b0025d9c9ed165ls116929ljq.7.-pod-prod-gmail; Mon, 18
 Jul 2022 17:15:45 -0700 (PDT)
X-Received: by 2002:a05:651c:4c7:b0:25d:8797:cd4b with SMTP id e7-20020a05651c04c700b0025d8797cd4bmr13697536lji.253.1658189745616;
        Mon, 18 Jul 2022 17:15:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189745; cv=none;
        d=google.com; s=arc-20160816;
        b=oz5QeHCEiPgkuk3JkEl1GUahyVv69H0ApJLFO75UctjATiYAlis5rXOJL7JqIfO47I
         hYUX8rNZ9KU2sP3xdjGiIqOmpdJocEmGF1MWMg2pzxGTcGc8wQsDsMrTrik0quWSBbQ9
         wyspG1dCjnwIcjiLsTjnVLm7srUxlQZXv0uMumlPPngtv8ugSjaXNERfUfZxuDrfatVt
         7MThTYkQv0mGUnkCPriD+rYKsaDHtk5wfxe0pCG1YxNWWK/e9Q4pYZs7fAudDlMHS98N
         8eMxPI465JgMhYtYPktoXyyxAxIe7ah/obU0GH8UzZLur61p3FifEheCZHSiyEkSllZk
         0GqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dEFlK3m+j6HFWp7YvmqmB+B3IIIjJFQIUVXb6/Nzt7c=;
        b=Bssk+vHdVmNsCXsoX5ViEvoYy+FaxFqVrgSQWqX0zUDWjA0bE6cRlIs8nZcpy0B5Tp
         hBXCZLokCS0Tr+8c917FaMA/zMTwhDf5Mt+JgFEZhCHeWy4f0zlb+dTLtmk8DKwFEEfb
         5FJPFcAAnxRZ/lpCGAYHwyIJTBczePD6R+n14AGOQwOUz3otz8K+nISr+E6u6R79nFWL
         Z9VBGyER0N4w7Kz7jrfTB0+Je1y71pVOO8iUyUBJQGbf6bADG2mtj9Wjlb9DDsuP5aow
         V4TdCwjHEcAXdhgC8/fw+/ObzgPltUtpQMyTfnMoE+/MJraje0hPV9+akgMda9WvL4fw
         7S9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CZ9H9Xz4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e1-20020a05651236c100b00489f4f3f541si325632lfs.12.2022.07.18.17.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:15:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 32/33] kasan: dynamically allocate stack ring entries
Date: Tue, 19 Jul 2022 02:10:12 +0200
Message-Id: <4db564768f1cb900b9687849a062156b470eb902.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CZ9H9Xz4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Instead of using a large static array, allocate the stack ring dynamically
via memblock_alloc().

The size of the stack ring is controlled by a new kasan.stack_ring_size
command-line parameter. When kasan.stack_ring_size is not provided, the
default value of 32 << 10 is used.

When the stack trace collection is disabled via kasan.stacktrace=off,
the stack ring is not allocated.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/kasan.h       |  5 +++--
 mm/kasan/report_tags.c |  4 ++--
 mm/kasan/tags.c        | 22 +++++++++++++++++++++-
 3 files changed, 26 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 447baf1a7a2e..4afe4db751da 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -252,12 +252,13 @@ struct kasan_stack_ring_entry {
 	bool is_free;
 };
 
-#define KASAN_STACK_RING_SIZE (32 << 10)
+#define KASAN_STACK_RING_SIZE_DEFAULT (32 << 10)
 
 struct kasan_stack_ring {
 	rwlock_t lock;
+	size_t size;
 	atomic64_t pos;
-	struct kasan_stack_ring_entry entries[KASAN_STACK_RING_SIZE];
+	struct kasan_stack_ring_entry *entries;
 };
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index a996489e6dac..7e267e69ce19 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -56,11 +56,11 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	 * entries relevant to the buggy object can be overwritten.
 	 */
 
-	for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
+	for (u64 i = pos - 1; i != pos - 1 - stack_ring.size; i--) {
 		if (alloc_found && free_found)
 			break;
 
-		entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
+		entry = &stack_ring.entries[i % stack_ring.size];
 
 		/* Paired with smp_store_release() in save_stack_info(). */
 		ptr = (void *)smp_load_acquire(&entry->ptr);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0eb6cf6717db..fd8c5f919156 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -10,6 +10,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/memblock.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
 #include <linux/static_key.h>
@@ -52,6 +53,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
+/* kasan.stack_ring_size=32768 */
+static int __init early_kasan_flag_stack_ring_size(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	return kstrtoul(arg, 0, &stack_ring.size);
+}
+early_param("kasan.stack_ring_size", early_kasan_flag_stack_ring_size);
+
 void __init kasan_init_tags(void)
 {
 	switch (kasan_arg_stacktrace) {
@@ -65,6 +76,15 @@ void __init kasan_init_tags(void)
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	}
+
+	if (kasan_stack_collection_enabled()) {
+		if (!stack_ring.size)
+			stack_ring.size = KASAN_STACK_RING_SIZE_DEFAULT;
+		stack_ring.entries = memblock_alloc(
+					sizeof(stack_ring.entries[0]) *
+						stack_ring.size,
+					SMP_CACHE_BYTES);
+	}
 }
 
 static void save_stack_info(struct kmem_cache *cache, void *object,
@@ -86,7 +106,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 
 next:
 	pos = atomic64_fetch_add(1, &stack_ring.pos);
-	entry = &stack_ring.entries[pos % KASAN_STACK_RING_SIZE];
+	entry = &stack_ring.entries[pos % stack_ring.size];
 
 	/* Detect stack ring entry slots that are being written to. */
 	old_ptr = READ_ONCE(entry->ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4db564768f1cb900b9687849a062156b470eb902.1658189199.git.andreyknvl%40google.com.
