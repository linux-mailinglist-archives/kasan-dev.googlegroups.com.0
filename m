Return-Path: <kasan-dev+bncBAABB457RXFAMGQEKNL7NJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id B9635CCA072
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:59:16 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4f1d7ac8339sf4027121cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 17:59:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766023155; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZppjfxTuiFPjVWf9CYP2smW5kbT16Eq7nGX1Lsw8V/LHtZFI2bh7VdgZ8+kPjZMHLQ
         2Ye4hSPF9Ve4IN1wlX5jrVhszxxMcI6iR/nuFjBc33kM9wQmjL9UV27t2Fq0qFYn7T2b
         3lNgEcXhxI1yG8I2cc+hXB32ICZq7KYv8eGK/XhjNY+I/txyaldR8mh5ktdY2KG8tUAg
         xX6KTpzsbEr2KDOS5AVmgE8X7Z1F3VwvoYIp5kj9lWFdG8KfeIudQicswlDLq4zFyTEh
         b3le7bsNhyjvEd4PsMCyf047sCcL7L8jmN00PVofiVdtkZG9e530M/ng5QlXDy7hau77
         AitA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=N6bCrCt5fXdnzxyz5JW2Av/ngZfTagiH3+CGvohd4j0=;
        fh=3VVY9wt10SdMcdt++bc+oZFPksYX3qcaxmqgzxPDWg0=;
        b=fjYjg/SrZhnkdU2tPKx9qwXEpni8Ctxc1Sdp9G0PkzZjcAzbAFhnyH83IVhErZa1Xl
         3ot2a59NIKznxYfCCBSnWEy0Z8fTzvq/yYZutVNd2uq0SkCW/n558uSnqp8BUUpgIybY
         Kv4c8L0TQPgX61qKMtvA0BcwmeV4ahYfiw/Cxc0ImNuQJzfXgvw/z82o0GvJr6L+XO7h
         IGr4egbyJ85+ZQ3Dcofv7GxltmCiRWcHGABUbYLIx1iDnxIsrgaEUCL+FAyAWmHh85HW
         dm5tbBZpp1Ai5xhjYcEf+1wl9QBV6G/nXQoZ+ZzChs5Va7zzJdLAKUqHc77hOx35Mwsm
         qFsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=iU94+Fuq;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766023155; x=1766627955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N6bCrCt5fXdnzxyz5JW2Av/ngZfTagiH3+CGvohd4j0=;
        b=jZ7kr+A+vhD8CCQfTvaBwAwJQyjLYiHy2fC1HN3ByhumS5JkbJxxLMK0SeFaeoqgua
         NXwzQxASrbQLQooRsi9FWZvUaEfE+udCdY0PEmI1uKxUjfqzPoo9egVLcoVA8QXAbijE
         9yNGJQhuMka5Lzw+dJe/r0jcm1pXKxteBIaR9kiUganEJxGZYMJA0txerMY18aiLJxu6
         fUQgZrXRAoxU29R+gQVNOgDyjl6m4CWIypUi/gcZDInmaWsXx9IqifKMpDuebeXWxTPI
         4KEg9jgRdJUXJat7IefpvD+umzJC0DJIsqscvr25OOlfBr8caQaPY6AZd4dIIXKCZ8OB
         4YAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766023155; x=1766627955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N6bCrCt5fXdnzxyz5JW2Av/ngZfTagiH3+CGvohd4j0=;
        b=URhFA6U6KFCtNXRWYdadxlhLoqI8Hecy8AzRw8JylT7pN6uyBnD9UFetkdRFpaU7cT
         khhKKbi0wYRj6KCK5qNL9qmdr9oc8Dmd1aKZCLSj0AXaeHYh4cSYOZhEx7dow1vXMLpZ
         NoYi9ua2VcJEiQhgpsybesKSvcqlmZo7XoyeTgOtZG/osrAMYtcyxzCVlwE+kzXaqGa9
         3HG60SFMLOv9GFCIKbI2HqfUc0XJnLqbwQC5lNNKi/T7c2d7N3us79Hti2KZjOiT6/5j
         g6RrwEjX/fbXU3QZ1zWX9u3Bq7h/aZdyyyqdQyegnQ+CZ1ZFNTYqKmUL019MUqZ0P7D7
         6QWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXaYSzuzJ/sHSQqehhcgn+fE/kMZ2/1QZzhR1zwZp1I7C+z16y4rWzJCPQve5/YtmycCXR7EA==@lfdr.de
X-Gm-Message-State: AOJu0Yx8Pxoo31WCUqP4ttblS8u7ZfO0IMnOySKhtzCDyVt9AnmX2SiI
	ukOhZJIDNkgjkBt69l7yq21jA7HkWO7gSSdr4mP0fwxaVLOJX0/B/bYa
X-Google-Smtp-Source: AGHT+IH7B0OSHjgpHu7CXn4CMk6/OHM80VFNG/eBR+zo4mIQ0b4rf8wVmCETdWJn6XIk4vU7IDzUBQ==
X-Received: by 2002:a05:622a:588c:b0:4ee:26ef:7f4c with SMTP id d75a77b69052e-4f1d047a359mr238998591cf.17.1766023155298;
        Wed, 17 Dec 2025 17:59:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYLcOROKf+b7wIOxDzgxmR/57z5xNmDRYRgkjySMe+MFw=="
Received: by 2002:a05:6214:519d:b0:882:4764:faad with SMTP id
 6a1803df08f44-8887c9609b8ls46322406d6.0.-pod-prod-06-us; Wed, 17 Dec 2025
 17:59:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWzmpoL4mdue3w5tj7Rqbv9PPq5Xh1S4sC1c7/cqG77YiiSk+a638xxmqR7npaO+ZTO7xw4oa1/7f4=@googlegroups.com
X-Received: by 2002:a05:620a:2a04:b0:8b2:9b48:6052 with SMTP id af79cd13be357-8bb3a3903d0mr2620182685a.84.1766023154360;
        Wed, 17 Dec 2025 17:59:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766023154; cv=none;
        d=google.com; s=arc-20240605;
        b=cgeJCvHagTaezBiTCugv5PCjxL+MvlzjF3d3wT14/83NA+0w2M1DhKGm1pElhPW7XL
         htbQPdv6QfqeOZa1xhTVm3BKpX9C220B/sYUnNHQErD6llj8mzqXRvLlsAL662IfmrxO
         mOD9M6n1pL0OMMMy7MFEaB8Y9EyOQAA7mRjeMaamCoQ7SeJOmCRCmULFUoMDBaborpBR
         hlZbMtHnbSc06CTFR1aJTYSL4hLMYijK6PANry7fpBgPcswMVdoz8sKUVdibuGtpmZEE
         R5f8kdepkhCcdQSRla6T1fxaHUFkLGnp+2xeelA6HKPw/oo5RiAwC4iqfHvfhfWQ88yY
         Ks4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hU40RLa4jRhtk5Sc+fhCSmQtLG8/DL1BTepfIHBkGLs=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=DWu1ixiuvFcnQ98bt1syK8fv9AgWEEzh2S9z2MZq3TOH2/TL0jAEdgBiOvGrCnZlTY
         eCn7aikq0wgfnP3z3CvdStDqJsEtxqaSwto/a5FxyeavPu3XiqBolD9qy7eguaWQlzmO
         EjkqqXniYH2zfwOi8gInbC8hCzfaLb82LY9XOONvRJpQL+40ctJWFRgY0dvM04Neq4t0
         lWthMP270Mu1PAoqVViVeM8Xa0AXHF7+U30KHc/xUW74ZYs3L+i4UG6ReoM0nRnymDIY
         vXme7mZKTsLGzjzWFvMnEpVc+hHz1ll3lj0C5QobkohAMKK3FquWVEIENgeURzsyb7el
         v0Pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=iU94+Fuq;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta22.hihonor.com (mta22.hihonor.com. [81.70.192.198])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8beebb3954esi3864285a.9.2025.12.17.17.59.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 17:59:14 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) client-ip=81.70.192.198;
Received: from w012.hihonor.com (unknown [10.68.27.189])
	by mta22.hihonor.com (SkyGuard) with ESMTPS id 4dWv1B6lt7zYmf8k;
	Thu, 18 Dec 2025 09:57:02 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w012.hihonor.com
 (10.68.27.189) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:02 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:02 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH 3/3] kfence: allow change number of object by early parameter
Date: Thu, 18 Dec 2025 09:58:49 +0800
Message-ID: <20251218015849.1414609-4-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20251218015849.1414609-1-yuanlinyu@honor.com>
References: <20251218015849.1414609-1-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w012.hihonor.com (10.68.27.189) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@honor.com header.s=dkim header.b=iU94+Fuq;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

when want to change the kfence pool size, currently it is not easy and
need to compile kernel.

Add an early boot parameter kfence.num_objects to allow change kfence
objects number and allow increate total pool to provide high failure
rate.

Signed-off-by: yuan linyu <yuanlinyu@honor.com>
---
 include/linux/kfence.h  |   5 +-
 mm/kfence/core.c        | 122 +++++++++++++++++++++++++++++-----------
 mm/kfence/kfence.h      |   4 +-
 mm/kfence/kfence_test.c |   2 +-
 4 files changed, 96 insertions(+), 37 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 0ad1ddbb8b99..920bcd5649fa 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -24,7 +24,10 @@ extern unsigned long kfence_sample_interval;
  * address to metadata indices; effectively, the very first page serves as an
  * extended guard page, but otherwise has no special purpose.
  */
-#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
+extern unsigned int __kfence_pool_size;
+#define KFENCE_POOL_SIZE (__kfence_pool_size)
+extern unsigned int __kfence_num_objects;
+#define KFENCE_NUM_OBJECTS (__kfence_num_objects)
 extern char *__kfence_pool;
 
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 24c6f1fa5b19..82425da5f27c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -132,6 +132,31 @@ struct kfence_metadata *kfence_metadata __read_mostly;
  */
 static struct kfence_metadata *kfence_metadata_init __read_mostly;
 
+/* allow change number of objects from cmdline */
+#define KFENCE_MIN_NUM_OBJECTS 1
+#define KFENCE_MAX_NUM_OBJECTS 65535
+unsigned int __kfence_num_objects __read_mostly = CONFIG_KFENCE_NUM_OBJECTS;
+EXPORT_SYMBOL(__kfence_num_objects); /* Export for test modules. */
+static unsigned int __kfence_pool_pages __read_mostly = (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2;
+unsigned int __kfence_pool_size __read_mostly = (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE;
+EXPORT_SYMBOL(__kfence_pool_size); /* Export for lkdtm module. */
+
+static int __init early_parse_kfence_num_objects(char *buf)
+{
+	unsigned int num;
+	int ret = kstrtouint(buf, 10, &num);
+
+	if (ret < 0)
+		return ret;
+
+	__kfence_num_objects = clamp(num, KFENCE_MIN_NUM_OBJECTS, KFENCE_MAX_NUM_OBJECTS);
+	__kfence_pool_pages = (__kfence_num_objects + 1) * 2;
+	__kfence_pool_size = __kfence_pool_pages * PAGE_SIZE;
+
+	return 0;
+}
+early_param("kfence.num_objects", early_parse_kfence_num_objects);
+
 /* Freelist with available objects. */
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
@@ -155,12 +180,13 @@ atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
  *
  *	P(alloc_traces) = (1 - e^(-HNUM * (alloc_traces / SIZE)) ^ HNUM
  */
+static unsigned int kfence_alloc_covered_order __read_mostly;
+static unsigned int kfence_alloc_covered_mask __read_mostly;
+static atomic_t *alloc_covered __read_mostly;
 #define ALLOC_COVERED_HNUM	2
-#define ALLOC_COVERED_ORDER	(const_ilog2(CONFIG_KFENCE_NUM_OBJECTS) + 2)
-#define ALLOC_COVERED_SIZE	(1 << ALLOC_COVERED_ORDER)
-#define ALLOC_COVERED_HNEXT(h)	hash_32(h, ALLOC_COVERED_ORDER)
-#define ALLOC_COVERED_MASK	(ALLOC_COVERED_SIZE - 1)
-static atomic_t alloc_covered[ALLOC_COVERED_SIZE];
+#define ALLOC_COVERED_HNEXT(h)	hash_32(h, kfence_alloc_covered_order)
+#define ALLOC_COVERED_MASK		(kfence_alloc_covered_mask)
+#define KFENCE_COVERED_SIZE		(sizeof(atomic_t) * (1 << kfence_alloc_covered_order))
 
 /* Stack depth used to determine uniqueness of an allocation. */
 #define UNIQUE_ALLOC_STACK_DEPTH ((size_t)8)
@@ -200,7 +226,7 @@ static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
 static inline bool should_skip_covered(void)
 {
-	unsigned long thresh = (CONFIG_KFENCE_NUM_OBJECTS * kfence_skip_covered_thresh) / 100;
+	unsigned long thresh = (__kfence_num_objects * kfence_skip_covered_thresh) / 100;
 
 	return atomic_long_read(&counters[KFENCE_COUNTER_ALLOCATED]) > thresh;
 }
@@ -262,7 +288,7 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
 
 	/* Only call with a pointer into kfence_metadata. */
 	if (KFENCE_WARN_ON(meta < kfence_metadata ||
-			   meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
+			   meta >= kfence_metadata + __kfence_num_objects))
 		return 0;
 
 	/*
@@ -612,7 +638,7 @@ static unsigned long kfence_init_pool(void)
 	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
 	 * enters __slab_free() slow-path.
 	 */
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
+	for (i = 0; i < __kfence_pool_pages; i++) {
 		struct page *page;
 
 		if (!i || (i % 2))
@@ -640,7 +666,7 @@ static unsigned long kfence_init_pool(void)
 		addr += PAGE_SIZE;
 	}
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		struct kfence_metadata *meta = &kfence_metadata_init[i];
 
 		/* Initialize metadata. */
@@ -666,7 +692,7 @@ static unsigned long kfence_init_pool(void)
 	return 0;
 
 reset_slab:
-	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
+	for (i = 0; i < __kfence_pool_pages; i++) {
 		struct page *page;
 
 		if (!i || (i % 2))
@@ -710,7 +736,7 @@ static bool __init kfence_init_pool_early(void)
 	 * fails for the first page, and therefore expect addr==__kfence_pool in
 	 * most failure cases.
 	 */
-	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
+	memblock_free_late(__pa(addr), __kfence_pool_size - (addr - (unsigned long)__kfence_pool));
 	__kfence_pool = NULL;
 
 	memblock_free_late(__pa(kfence_metadata_init), KFENCE_METADATA_SIZE);
@@ -740,7 +766,7 @@ DEFINE_SHOW_ATTRIBUTE(stats);
  */
 static void *start_object(struct seq_file *seq, loff_t *pos)
 {
-	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+	if (*pos < __kfence_num_objects)
 		return (void *)((long)*pos + 1);
 	return NULL;
 }
@@ -752,7 +778,7 @@ static void stop_object(struct seq_file *seq, void *v)
 static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
 {
 	++*pos;
-	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
+	if (*pos < __kfence_num_objects)
 		return (void *)((long)*pos + 1);
 	return NULL;
 }
@@ -796,7 +822,7 @@ static void kfence_check_all_canary(void)
 {
 	int i;
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
 		if (kfence_obj_allocated(meta))
@@ -891,7 +917,7 @@ void __init kfence_alloc_pool_and_metadata(void)
 	 * re-allocate the memory pool.
 	 */
 	if (!__kfence_pool)
-		__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+		__kfence_pool = memblock_alloc(__kfence_pool_size, PAGE_SIZE);
 
 	if (!__kfence_pool) {
 		pr_err("failed to allocate pool\n");
@@ -900,11 +926,23 @@ void __init kfence_alloc_pool_and_metadata(void)
 
 	/* The memory allocated by memblock has been zeroed out. */
 	kfence_metadata_init = memblock_alloc(KFENCE_METADATA_SIZE, PAGE_SIZE);
-	if (!kfence_metadata_init) {
-		pr_err("failed to allocate metadata\n");
-		memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
-		__kfence_pool = NULL;
-	}
+	if (!kfence_metadata_init)
+		goto fail_pool;
+
+	kfence_alloc_covered_order = ilog2(__kfence_num_objects) + 2;
+	kfence_alloc_covered_mask = (1 << kfence_alloc_covered_order) - 1;
+	alloc_covered = memblock_alloc(KFENCE_COVERED_SIZE, PAGE_SIZE);
+	if (alloc_covered)
+		return;
+
+	pr_err("failed to allocate covered\n");
+	memblock_free(kfence_metadata_init, KFENCE_METADATA_SIZE);
+	kfence_metadata_init = NULL;
+
+fail_pool:
+	pr_err("failed to allocate metadata\n");
+	memblock_free(__kfence_pool, __kfence_pool_size);
+	__kfence_pool = NULL;
 }
 
 static void kfence_init_enable(void)
@@ -927,9 +965,9 @@ static void kfence_init_enable(void)
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 
-	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
-		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
-		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
+	pr_info("initialized - using %u bytes for %d objects at 0x%p-0x%p\n", __kfence_pool_size,
+		__kfence_num_objects, (void *)__kfence_pool,
+		(void *)(__kfence_pool + __kfence_pool_size));
 }
 
 void __init kfence_init(void)
@@ -950,41 +988,53 @@ void __init kfence_init(void)
 
 static int kfence_init_late(void)
 {
-	const unsigned long nr_pages_pool = KFENCE_POOL_SIZE / PAGE_SIZE;
-	const unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
+	unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
 	unsigned long addr = (unsigned long)__kfence_pool;
-	unsigned long free_size = KFENCE_POOL_SIZE;
+	unsigned long free_size = __kfence_pool_size;
+	unsigned long nr_pages_covered, covered_size;
 	int err = -ENOMEM;
 
+	kfence_alloc_covered_order = ilog2(__kfence_num_objects) + 2;
+	kfence_alloc_covered_mask = (1 << kfence_alloc_covered_order) - 1;
+	covered_size =  PAGE_ALIGN(KFENCE_COVERED_SIZE);
+	nr_pages_covered = (covered_size / PAGE_SIZE);
 #ifdef CONFIG_CONTIG_ALLOC
 	struct page *pages;
 
-	pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_online_node,
+	pages = alloc_contig_pages(__kfence_pool_pages, GFP_KERNEL, first_online_node,
 				   NULL);
 	if (!pages)
 		return -ENOMEM;
 
 	__kfence_pool = page_to_virt(pages);
+	pages = alloc_contig_pages(nr_pages_covered, GFP_KERNEL, first_online_node,
+				   NULL);
+	if (!pages)
+		goto free_pool;
+	alloc_covered = page_to_virt(pages);
 	pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
 				   NULL);
 	if (pages)
 		kfence_metadata_init = page_to_virt(pages);
 #else
-	if (nr_pages_pool > MAX_ORDER_NR_PAGES ||
+	if (__kfence_pool_pages > MAX_ORDER_NR_PAGES ||
 	    nr_pages_meta > MAX_ORDER_NR_PAGES) {
 		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
 		return -EINVAL;
 	}
 
-	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
+	__kfence_pool = alloc_pages_exact(__kfence_pool_size, GFP_KERNEL);
 	if (!__kfence_pool)
 		return -ENOMEM;
 
+	alloc_covered = alloc_pages_exact(covered_size, GFP_KERNEL);
+	if (!alloc_covered)
+		goto free_pool;
 	kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
 #endif
 
 	if (!kfence_metadata_init)
-		goto free_pool;
+		goto free_cover;
 
 	memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
 	addr = kfence_init_pool();
@@ -995,22 +1045,28 @@ static int kfence_init_late(void)
 	}
 
 	pr_err("%s failed\n", __func__);
-	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
+	free_size = __kfence_pool_size - (addr - (unsigned long)__kfence_pool);
 	err = -EBUSY;
 
 #ifdef CONFIG_CONTIG_ALLOC
 	free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata_init)),
 			  nr_pages_meta);
+free_cover:
+	free_contig_range(page_to_pfn(virt_to_page((void *)alloc_covered)),
+			  nr_pages_covered);
 free_pool:
 	free_contig_range(page_to_pfn(virt_to_page((void *)addr)),
 			  free_size / PAGE_SIZE);
 #else
 	free_pages_exact((void *)kfence_metadata_init, KFENCE_METADATA_SIZE);
+free_cover:
+	free_pages_exact((void *)alloc_covered, covered_size);
 free_pool:
 	free_pages_exact((void *)addr, free_size);
 #endif
 
 	kfence_metadata_init = NULL;
+	alloc_covered = NULL;
 	__kfence_pool = NULL;
 	return err;
 }
@@ -1036,7 +1092,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	if (!smp_load_acquire(&kfence_metadata))
 		return;
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		bool in_use;
 
 		meta = &kfence_metadata[i];
@@ -1074,7 +1130,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 		}
 	}
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		meta = &kfence_metadata[i];
 
 		/* See above. */
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index dfba5ea06b01..dc3abb27c632 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -104,7 +104,7 @@ struct kfence_metadata {
 };
 
 #define KFENCE_METADATA_SIZE PAGE_ALIGN(sizeof(struct kfence_metadata) * \
-					CONFIG_KFENCE_NUM_OBJECTS)
+					__kfence_num_objects)
 
 extern struct kfence_metadata *kfence_metadata;
 
@@ -123,7 +123,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
 	 * error.
 	 */
 	index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
-	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
+	if (index < 0 || index >= __kfence_num_objects)
 		return NULL;
 
 	return &kfence_metadata[index];
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00034e37bc9f..00a51aa4bad9 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -641,7 +641,7 @@ static void test_gfpzero(struct kunit *test)
 			break;
 		test_free(buf2);
 
-		if (kthread_should_stop() || (i == CONFIG_KFENCE_NUM_OBJECTS)) {
+		if (kthread_should_stop() || (i == __kfence_num_objects)) {
 			kunit_warn(test, "giving up ... cannot get same object back\n");
 			return;
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218015849.1414609-4-yuanlinyu%40honor.com.
