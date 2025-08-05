Return-Path: <kasan-dev+bncBCKPFB7SXUERB7OGY3CAMGQE2N2RCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id AA0B6B1AE2F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 08:23:59 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-23fd831def4sf40605465ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 23:23:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754375038; cv=pass;
        d=google.com; s=arc-20240605;
        b=TH6dXwuqGRh6A0qdEv52XtkLw105fhpKYu+dnZ9uja2zOBVeuaxCJbUDqX3wlH/Fkh
         O+8AftdnN25X7zS8EeO/55oaUzJB2XKyNCenQ8timv3uHKVH0kc4VCqFghAG8o0sRxw6
         ClE9kleDmZEi+rESPfkN+CSu621G0pte87ok8Ig6Q2IGY4zUUA8kXQFeaOkdm1oIYDzg
         jq8Ms4d5fAHxedz9z51DJV9ZBnZ2/j1riDUynw0wb0j1lhzPdeFPa0VTW+t3KFPOc3m+
         vQQUV4YU7MqYt0bxIxxxE5Pbl7l+7Txcps6PWVaOlDXD0Rp2fs5HNtaW/2ivNGeB8EkU
         4Mew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+PE4i0DSvyBx9WGvvXXOiB27zc23UdzMbJMM2vGOpjI=;
        fh=fQ3d4Psii27flgn6wD9UD/PGr1iF66vRY3v7H5dG2qo=;
        b=BCvNGDI4c5QzfJKMB4uDKn6m65PVLgUsB35bnHwWqR+uyoS8rNx6IHIKKl60lsP2e+
         +4jmpxhPMKxUK8jD3GQR9jnshoxaLERibI8e3X1vYEb3lU2IO1apUuGRrNmHX4grOANe
         vW4J/FGKs9fmumz16nS4ELHgcEuZQL7yUmLTsXC/7A4g1Q3SQuCcyHnr74557EodQJyp
         5zHx0K82WnQSiFzZhnQY9NPZZEYXmJXkdaQZYYb1dT1DPn91P1ACkWS141851/0ggvyq
         4/6fp+E4JeAfWiQWOQ80I0DyoNBcw+jp+VcvaeSVghoR55ljE5Xqie7wHSahV6PlhoEp
         8btg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y5F2GMYs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754375038; x=1754979838; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+PE4i0DSvyBx9WGvvXXOiB27zc23UdzMbJMM2vGOpjI=;
        b=Q8E1EUsYERmOgQyqBRu4aefEuAIH165B+VkX3pdxpma4/N0GKv61eVWBDLOwumi0yO
         DymLX+Z7kDcFc4XvEXOLwAv9q4wStCg17+LL85DPg6fRW/a00Y/cnCb6u0Ah7gHOetyH
         T4SsZUW/8vlOp1zW49z5bnGq0MncR8rkRlfLyx96ZLGKpTg6Z/t8fogomGAzlLyiZg2r
         5KJY9ijdlzGfpBCmukW8KBzW0hrqZ/zeQasE1gHu79EtfusjQ5TL+zBOjafatCaRhePT
         azuQuJ2dXS4CTeUQbrzwN9ac9icF2lm3VC+u+hw9v77R3aJdG8Ng80no34uFaVofhDbm
         5u8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754375038; x=1754979838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+PE4i0DSvyBx9WGvvXXOiB27zc23UdzMbJMM2vGOpjI=;
        b=MVFT5kPT8ZLVzekUOZeKtX2axMiEJ32k8DfQ1W5w55DkEIypBcCfcq7vGfGidYtRHh
         dpZhMNcYYyrcDF+am4Lh3V2wlnm6QfAbCNhue/ohyuljNOxyA90bHPzrMf1xaU10vLHl
         siZ24+bPQO6XoQouVv4RmOOvtgfzvkBd/XSn9U+kDrYT11ngf7RNm1WxZxJfaYgTRVUg
         74br4I1RKeA3yLS3XI9EVqGAXf4W7A8grUZvQWFerXcQewMrvr8bZMOpJU+Aln1phtNP
         xhOP8R4B0QNKvFEajW10/2FTdF6yGqXetWLeDhR9YtjmddHL9KTXW/AA543O33SefVij
         pUkw==
X-Forwarded-Encrypted: i=2; AJvYcCV343bsj3CrEx2IgeWiwVGC4ilzmA0bpTtmLa1QDgi07eZmeJSEFmfeNq758ykNngR7lKzjkg==@lfdr.de
X-Gm-Message-State: AOJu0Yx9shr1Vmkm9acYqvgJWYH8pTmR2fR4TW0ey2UPZEvNmr8U2fv8
	pUgfuMYbE789smpnyh3FQ7XlP6zmGpebna4+X+S1xjpZ+uSl46q8vdKg
X-Google-Smtp-Source: AGHT+IGet1+y4UOOKRiPy6Vg/+lpNhmCTW1oLd8to0HV5Xqp+PCEKFnThtQzCCJMPM2oCl6TgMZVPQ==
X-Received: by 2002:a17:902:e84e:b0:240:3f43:25f with SMTP id d9443c01a7336-24246f61ad2mr179250885ad.23.1754375037748;
        Mon, 04 Aug 2025 23:23:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd0sqP0GGkZG9ot6QS4CxpN4urSysiCDs8FYYWsu9mXSw==
Received: by 2002:a17:90b:4b:b0:31e:bb37:5ffe with SMTP id 98e67ed59e1d1-31f95d5918als5591581a91.1.-pod-prod-04-us;
 Mon, 04 Aug 2025 23:23:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5H5v9l4j2OK6BqSy7SnBmDSyMdRpACbhlQqUhaCP8vUSEBTU4A1tNBwReT8o9Mk3XR6mI6pTb7+I=@googlegroups.com
X-Received: by 2002:a17:90b:2dc1:b0:31f:7160:df4b with SMTP id 98e67ed59e1d1-3211620385amr18161627a91.15.1754375035917;
        Mon, 04 Aug 2025 23:23:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754375035; cv=none;
        d=google.com; s=arc-20240605;
        b=B/FHqCSzshHKkb6F3RhIQ9lvChoRh4KPH+9eSzoaBrSh4EX0GM1E+uuer+DJgseawz
         rnqYD++EF1ppKylpDl0saNk+wm1r716Jv26NawZJkfXlDx0t8Zwxv9se9yz3yabSiCXZ
         JssdPeWx0XWmEc3r7CVtyiAENEE2wt5sfoy3c9ZH5e9H5ZdeX5gaLdA1a2Pa8A8BfRyJ
         4ilvLenBc/orz7+/Nv03QzpfFIkpIXBr6lT6WXT5S1+fd+3d6BYz0ZQ3ZDRHfQDx4nk/
         3dMhyaw7us778LO+uWzmPnc6EWirnxMXGEzDJhunpA1enjtD9aAIJ1Kej6YuN4+1Lrk1
         1kbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YU51QcBxpYhMcGyh8yXmd1ecFtbJIeZYT5VTxJvHY9k=;
        fh=zdgUGJ5AVcpjW6c3+faZMlslsU1+4WtDOSxOnvwQO5s=;
        b=Z5a4oQTO+Iof327MoPKp79FmNGRbpMEuWML3HOP7H3M+qAYcNwzpc+YEGzXTZcB/TT
         IRSEDmDiXhLa5zZ4Vg5SKpUUNyX2ad3fY8ygnO+JYFKwmp3bqd+ufxehzUsRqzyVLE+e
         ROvHdW4MBjhF2VA3bq+8BVUp1W0GQfT9rCsQu5vgq/psOKosmPYY9BxMXRR8VYOWnogq
         Rx7XOvMD/hI5Dl+i/a+U77A3q7x8vXmEZgfhFqOPVzjH+3JbhX3U1MQhMIJbi2eTXzyd
         rNGP2I/8tJq4arsIj6GgegUGJ8hCrrfv4UXtIsRqfd27ODmhfZCgmEJ2QMctMIqSvJvh
         3KbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y5F2GMYs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31f63d9e126si745751a91.1.2025.08.04.23.23.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 23:23:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-308-8_Hp1WdPNaKVrdPYJCqwew-1; Tue,
 05 Aug 2025 02:23:50 -0400
X-MC-Unique: 8_Hp1WdPNaKVrdPYJCqwew-1
X-Mimecast-MFC-AGG-ID: 8_Hp1WdPNaKVrdPYJCqwew_1754375029
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8F8761956089;
	Tue,  5 Aug 2025 06:23:48 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.136])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 5033C1956094;
	Tue,  5 Aug 2025 06:23:42 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 1/4] mm/kasan: add conditional checks in functions to return directly if kasan is disabled
Date: Tue,  5 Aug 2025 14:23:30 +0800
Message-ID: <20250805062333.121553-2-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
References: <20250805062333.121553-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Y5F2GMYs;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

The current code only does the check if kasan is disabled for hw_tags
mode. Here add the conditional checks for functional functions of
generic mode and sw_tags mode.

This is prepared for later adding kernel parameter kasan=on|off for
all kasan modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/generic.c    | 20 ++++++++++++++++++--
 mm/kasan/init.c       |  6 ++++++
 mm/kasan/quarantine.c |  3 +++
 mm/kasan/shadow.c     | 23 ++++++++++++++++++++++-
 mm/kasan/sw_tags.c    |  3 +++
 5 files changed, 52 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e7..ee4ddc1e7127 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -165,6 +165,9 @@ static __always_inline bool check_region_inline(const void *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_enabled())
+		return true;
+
 	if (!kasan_arch_is_ready())
 		return true;
 
@@ -203,12 +206,13 @@ bool kasan_byte_accessible(const void *addr)
 
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
-	kasan_quarantine_remove_cache(cache);
+	if (kasan_enabled())
+		kasan_quarantine_remove_cache(cache);
 }
 
 void kasan_cache_shutdown(struct kmem_cache *cache)
 {
-	if (!__kmem_cache_empty(cache))
+	if (kasan_enabled() && !__kmem_cache_empty(cache))
 		kasan_quarantine_remove_cache(cache);
 }
 
@@ -228,6 +232,9 @@ void __asan_register_globals(void *ptr, ssize_t size)
 	int i;
 	struct kasan_global *globals = ptr;
 
+	if (!kasan_enabled())
+		return;
+
 	for (i = 0; i < size; i++)
 		register_global(&globals[i]);
 }
@@ -358,6 +365,9 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int rem_free_meta_size;
 	unsigned int orig_alloc_meta_offset;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_requires_meta())
 		return;
 
@@ -510,6 +520,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
 	struct kasan_cache *info = &cache->kasan_info;
 
+	if (!kasan_enabled())
+		return 0;
+
 	if (!kasan_requires_meta())
 		return 0;
 
@@ -535,6 +548,9 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
+	if (!kasan_enabled())
+		return;
+
 	if (is_kfence_address(addr) || !slab)
 		return;
 
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ced6b29fcf76..43d95f329675 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -449,6 +449,9 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	unsigned long addr, end, next;
 	pgd_t *pgd;
 
+	if (!kasan_enabled())
+		return;
+
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
@@ -484,6 +487,9 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	int ret;
 	void *shadow_start, *shadow_end;
 
+	if (!kasan_enabled())
+		return 0;
+
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 6958aa713c67..a6dc2c3d8a15 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -405,6 +405,9 @@ static int __init kasan_cpu_quarantine_init(void)
 {
 	int ret = 0;
 
+	if (!kasan_enabled())
+		return 0;
+
 	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
 				kasan_cpu_online, kasan_cpu_offline);
 	if (ret < 0)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..637f2d02d2a3 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -125,6 +125,9 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_arch_is_ready())
 		return;
 
@@ -150,6 +153,9 @@ EXPORT_SYMBOL_GPL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_arch_is_ready())
 		return;
 
@@ -164,6 +170,8 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
+	if (!kasan_enabled())
+		return;
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_unpoison_new_object) pass tagged
@@ -277,7 +285,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 
 static int __init kasan_memhotplug_init(void)
 {
-	hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
+	if (kasan_enabled())
+		hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
 
 	return 0;
 }
@@ -390,6 +399,9 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
+	if (!kasan_enabled())
+		return 0;
+
 	if (!kasan_arch_is_ready())
 		return 0;
 
@@ -560,6 +572,9 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_arch_is_ready())
 		return;
 
@@ -655,6 +670,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 	size_t shadow_size;
 	unsigned long shadow_start;
 
+	if (!kasan_enabled())
+		return 0;
+
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
 	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
 				KASAN_SHADOW_SCALE_SHIFT;
@@ -691,6 +709,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 
 void kasan_free_module_shadow(const struct vm_struct *vm)
 {
+	if (!kasan_enabled())
+		return;
+
 	if (IS_ENABLED(CONFIG_UML))
 		return;
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a37..01f19bc4a326 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -78,6 +78,9 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	u8 *shadow_first, *shadow_last, *shadow;
 	void *untagged_addr;
 
+	if (!kasan_enabled())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-2-bhe%40redhat.com.
