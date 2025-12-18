Return-Path: <kasan-dev+bncBAABBGWDR3FAMGQEB7ZXBNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A88A2CCA7EE
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 07:39:24 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-7d481452732sf722213b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 22:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766039963; cv=pass;
        d=google.com; s=arc-20240605;
        b=K/lbnm0Zsu4hP3VkRXKAmumd81kXUWbKmelphwvNqcdTOM+4D9Vjsx4pJBfDXAgLQe
         F+8GDe/yva+h0zQxi89Eqfcj1BXvG2ikg4ijKTXDPVJZw/ED8YX/XVzsPUAzSpoh0FNm
         ow1XxleUKkh/IQYs5CNO5c3KC80OBg++tgZcBWxahC71zkVLx+aTW6psqzb5X8hJ1g4F
         ehrn2HlOaqB0eC4lECr6Ai1y9gJKVxiIJf2af7zgeg/WCHe6AkYHA7rdK/YHx0atotN/
         964CnOiDHVpJj1TQFiDGdhXr5FDOx061r4wsysdjXM4bBiANhrb2AhS4D6zqq0oignDw
         AzzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2pTSPKRamZ749BtDubziMlur4M9fP7ryRfkGeP+21xM=;
        fh=DpkTL+22+KWS2wQkvjNv3D///9xK0NUCqiutezBZYUE=;
        b=Z2k/sxF+AQqv3Pp6e/Br+BaRRnfpkFTtMF/+vfe9ERMtzlREIsGpwkzPovEKl4keC8
         ZF40oZgCHwaKg3kbQJUIENVknathpfjSzyNvDIybn0dlY0LjMSkvtRxDnNZzaPgpvS+a
         0I6PVlXx7kYefWadVkNdO5e3VP+XSFqkuOywDK+6WgWwe59eiB8cJuIIGTouJV8WETSW
         E+ZBf9aEbncwIX88GymJvYexlj2mcV6Y1qnPDbkzMtNa7RYrsvzUdQ/boDwGYZOWNZId
         T9lirQoqqR47QMuw29/PYbS5Sur4qI6uu+mYgOnJkiHBDuVXSPJJixagOoFcMKGOpuki
         kRCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766039963; x=1766644763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2pTSPKRamZ749BtDubziMlur4M9fP7ryRfkGeP+21xM=;
        b=d4Re+0h5PDpMUyOi5T8Kq6v2sAHbsR/XzLO+2IltVUAQQgaVQs3MXZdQGHI3CJdcGP
         XTb9HJu0Ze9mR1j8rao7y310gM0atHbwh7KLVuM5BezCbURyDUjQ/dZIlaVzj0j4hHm2
         XMzDQZyDqIh8QSlHGjVAc8psMnbo1nkWjl8XZB+chLOFTTJbyBRtqWMxhowHLfH1b/VD
         LsBWVZR4jVn5EAkPqP6Dt75FD9PBPfzFrfcDxkVStCyky2RpDR1xkOxOwNg+t2jwXxXB
         lLi5LMwxyM724ZQyAYdnB0fajKwvVTA9N7x5XFjXhO6/sMigAM9wQFqdc1BaRX7pYiRM
         eGmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766039963; x=1766644763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2pTSPKRamZ749BtDubziMlur4M9fP7ryRfkGeP+21xM=;
        b=L+iSVcot+ZzFuxH9ciXyl0EK1YUSFdqOtq3LlkDPJ+nriVWGosPVfO0VFKbjTmU1kx
         /WcDYs4E+GfMpRiMHqmqMJd+b+tYZ3IcYkDqKww+9tAGzDKIIIt/XL9y9Tr4B0o4wsVi
         M7u5EDHyuLXgPdG12UoKe/ZlKS2w+yugURH1USdl0v3z3itrFbNKGUC2kO7mF/wdxhFt
         hhaScdbuuqxA0F/RnGGjNpeW/XIKR1m6Fj57+maEh3DniwtQdYCgofR0o2CjrToBwJvn
         AbbKtN9f4LioAgLorJi/EOQ/Z3AjPf24zdTwlOa36Rs+FIDIaNXIz+9dxdshzRKwce/i
         iiLg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4a8tLMnwNp/BnYnBmlENla8zleHyx351sZ76ST1WU1Ew4eJYUKRY18Dj3uloGZr0Ou7JvwQ==@lfdr.de
X-Gm-Message-State: AOJu0YzU5rmCF3ptZBXO4RxCWG21XDwiifAE3PEFHWKaIXO5dVAQik7m
	IyzRufKrbIvv2pgws3TZOc5RJ3FDxA9h6XjUHhtmmxdjLgoKLyWpNKZz
X-Google-Smtp-Source: AGHT+IFLxGgtgp4hIUihPEfy6SFznzXzJ/t1XbyzCwlBsLvXIMMjP9yH77XEFzCVBDUgNCUq+R0bBw==
X-Received: by 2002:a05:6a00:4004:b0:7e8:450c:61bd with SMTP id d2e1a72fcca58-7f671475099mr18340406b3a.45.1766039962903;
        Wed, 17 Dec 2025 22:39:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZvetIjnyunziMq1l/ONesabD0Hafjzrjl1i1HMm0I1NQ=="
Received: by 2002:a05:6a00:4285:b0:7f1:9aaa:f35 with SMTP id
 d2e1a72fcca58-7f6455dd3b0ls7451411b3a.0.-pod-prod-01-us; Wed, 17 Dec 2025
 22:39:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtbXHXGWzYYaNjCzhF+oft/AassV7uQKHuCGzZjh50SGGbHVFsaoJVh6fzgsmf0IfHDoMJcZP8Mdo=@googlegroups.com
X-Received: by 2002:a05:6a00:6caa:b0:7b8:3549:85f9 with SMTP id d2e1a72fcca58-7f6702be6f7mr17604993b3a.30.1766039961579;
        Wed, 17 Dec 2025 22:39:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766039961; cv=none;
        d=google.com; s=arc-20240605;
        b=Qvk2VCeV3vAMK7olyB+8LVAMxEFSiSxl2H0mJdnnV4OqS4xNX/zw2CX8ZH+y4PyggZ
         tFd06F8lcg2CoQWoGyQFbNoBh6PWIPMFOwxYCJZBukMJNPsfeu1q74c5f3CqjfcEyGX2
         wl3CFtzUv6vTagAhS7E2P5NOqXbBsUzzcGWKgade/TUtHkqSe+StPkZKMkjU7Ae4OOef
         LCLrqEyuw4oy8aPgorT8E5r0hN9eDzq/iW90zHfkH6yF5ifV6G6uPwUy52oSJWAqIsWw
         vTGTCCh2BJL3NfZyo5x04S+ybru2pSaqzea0vGm81PzBn2ZlfzeiG0iIswx0VbJb9+sw
         MEsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8G2GzlDrWZYa/IhAr+v5xcy2G4534Lh7iaRUF7M5DRc=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=BxPLVurk2tKOOqDp96GqUHti7+jX2nC9vAZYQdqCseqAfUp8BwbEYP+TRECda3Iu6R
         pFaltUrKCC5KADopxVShq990w6pcX9mZti4/2ykNbQY7C0fuD98ErEnlC/k2bkdkk/31
         4pvhKXkVLbnZJJTU2x49/b2MxMxxgfJO4/RzTl5OvQ2NbJHZ3Z+IU4RBWGYZqyUaKjWG
         GaCeifT10LOAJVuMz5uV3BTV5EmiCi/HlR+QURxUGrlWAkaa6H+f/07ElZOrZkuqnjvJ
         bfOtybyr2j4wKsRHVAGRA6C6EginpkrFZGkeJkMBUrpuvoCEEeGfvPbcTaGgbj1R7pTm
         CfWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta21.hihonor.com (mta21.hihonor.com. [81.70.160.142])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7fe1456d090si35279b3a.7.2025.12.17.22.39.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 22:39:21 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) client-ip=81.70.160.142;
Received: from w002.hihonor.com (unknown [10.68.28.120])
	by mta21.hihonor.com (SkyGuard) with ESMTPS id 4dX1Ct237wzYl7hG;
	Thu, 18 Dec 2025 14:36:42 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w002.hihonor.com
 (10.68.28.120) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:19 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:18 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH v2 2/2] kfence: allow change number of object by early parameter
Date: Thu, 18 Dec 2025 14:39:16 +0800
Message-ID: <20251218063916.1433615-3-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20251218063916.1433615-1-yuanlinyu@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w010.hihonor.com (10.68.28.113) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as
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
index 577a1699c553..5d5cea59c7b6 100644
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
@@ -799,7 +825,7 @@ static void kfence_check_all_canary(void)
 {
 	int i;
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
 		if (kfence_obj_allocated(meta))
@@ -894,7 +920,7 @@ void __init kfence_alloc_pool_and_metadata(void)
 	 * re-allocate the memory pool.
 	 */
 	if (!__kfence_pool)
-		__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+		__kfence_pool = memblock_alloc(__kfence_pool_size, PAGE_SIZE);
 
 	if (!__kfence_pool) {
 		pr_err("failed to allocate pool\n");
@@ -903,11 +929,23 @@ void __init kfence_alloc_pool_and_metadata(void)
 
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
@@ -930,9 +968,9 @@ static void kfence_init_enable(void)
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
@@ -953,41 +991,53 @@ void __init kfence_init(void)
 
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
@@ -998,22 +1048,28 @@ static int kfence_init_late(void)
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
@@ -1039,7 +1095,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	if (!smp_load_acquire(&kfence_metadata))
 		return;
 
-	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+	for (i = 0; i < __kfence_num_objects; i++) {
 		bool in_use;
 
 		meta = &kfence_metadata[i];
@@ -1077,7 +1133,7 @@ void kfence_shutdown_cache(struct kmem_cache *s)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218063916.1433615-3-yuanlinyu%40honor.com.
