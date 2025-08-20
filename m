Return-Path: <kasan-dev+bncBCKPFB7SXUERBHN5SXCQMGQE35KCIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E113B2D386
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:35:26 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7e86499748csf189115185a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:35:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668125; cv=pass;
        d=google.com; s=arc-20240605;
        b=WXkfyxBRRz9oW8CAoOrgt/VDyBw9DrEi8cvjuq0ROE0osJ/OZFPBEXoIvNKM2ibfGM
         W6bxSZtcbJAeWT2KXuWbZEXFWLxiGsSADxF5+/x1usRJoNyvoQVWZNOoCG72qheKy/fr
         1rmveiYTOcE1+uSwLEQgAaHhoSoj1HLbnA+BZDFeToM9CVgN8J4r+b7AiT7VoH8Xu99D
         LIx7hsnC20cMG2mQklbe4MGYPwovRAyrB9aEwqp/bEIcCKYnIeD0EI2NdH2YFP352sJ8
         2C0Is+2X1NvMwLBfKBHJwm8gmQF4PCmEiwIMcxOVXDYvGKLsMMRU5hbV65574C6ZPrts
         ylVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UuUWh8gpAsEund4qpVI5i2NveJQYZs+thIWZAw9IzF8=;
        fh=IgPIn2yhUyJG36sXz5eQqjkWG//xG/+Eqz2pCirz+wo=;
        b=PhGA/h1Czp7XjLO/lY+kbW6t6Faf0hGGdEGd25NdddMmued8CB5B8OXhItegvrBAYy
         jI9fk9CL0FO5A8/T7iJDpaHclOuNW4DDMo9cmZATOQIPEVfDjds0WnYKyLEqH+hMJO/p
         1uV23+qnd1tQi4oLs/5VNv1ykI/xk1OSNFHqUfloPwl94zDbPasjNbn9aj/qfHYieQ3u
         QtOB04tzlx37xNWRMSx7FkUWQZb/aQ2AQSYnLbCGaCR/aRysKRPHCClAczUVEmx7Kndx
         7SVgvzQ98ZZD0hBL752U9hvFZSwYChcsLmcI37iXpnvtsdnUG6cRopcOzUs82cZS2b2H
         RPTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aZiqvL1t;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668125; x=1756272925; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UuUWh8gpAsEund4qpVI5i2NveJQYZs+thIWZAw9IzF8=;
        b=gMr0iTfKA0Q+6OPZyJVb0s2fG/JjbD4KY43toXq6/Q1uETN+Et9je3/t+p7sK+Um01
         2vecvlkeMgF47PZ5K5utu67fIUdTZVReAYoZfGb07tAZq4PhEc/VLTrX8VHI0pMoYT0g
         vorZc9OffCcgkIs9jkY6D1W+u0tIJ/cknjnEmVaOrd4SqNyWR3dVuDhIsvfLkOurhpQ4
         JfFtwb16fle1zVEc9itqhACNTXxiQnT6fXU+upgYa/Auab5YOMz1kYLdfxRgx7dBkIP5
         Ozw59Xa9BoV+smSlluSEgAyRkLFWAjDIUQVk+EH7TvOEU4wIifzlNz78tAfB1MVz6L0T
         P5og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668125; x=1756272925;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UuUWh8gpAsEund4qpVI5i2NveJQYZs+thIWZAw9IzF8=;
        b=NGuvySw5vZy+v0gR65rCA4B89f39CpJ8t+KVg2f3oN4P3Ym0ttRPx3Nvwh5xdYE7rM
         77rrC6MWB5aOzp4y5w80/Gf2BCl66iRIXfxFdArLZwp6a17R3gWdTq9koxbwALpqMQPk
         xlxgsTCVL6GOfLDYjDgLsb2/VXFrrr4shCt+DjFAs72elFpkQWI+UHe8UceUCSsdMC14
         XtTh7JNDus4myY86fAMtLRtyEfw1EWkEy8Ln08oRkFEubdLLWkiUnM31GlMg8ouTtf0g
         kyjHC8m8vNfIp1U6LnjRAhxOijtnJjzpKPbFUK8loDnbxuU6mi08MW2EMu0hz6tTYSwt
         04ng==
X-Forwarded-Encrypted: i=2; AJvYcCXcrj5Rqyw1L/2GEQ4TXlu7RCIw3i+/qP8ujhXKJH17gGMhaYq2s8/BqBszIw0hk7tF++x3tQ==@lfdr.de
X-Gm-Message-State: AOJu0YxgmSYFrTg6wlxCy3FjDR8qJl5AM7KjtzZKmMscxF3ieXws43yl
	2LYvkFjeHZ1xwqXmpTErABZ39zphfxY7B44AmS2WEP1W2ecTFm2qIIu1
X-Google-Smtp-Source: AGHT+IFdPZZe5ps2uBCVfY3EEFrj/GocIbMZrjxNm9Cpb2PVZtZBXXrjIiO/zl5t44QFCKsp6piD8Q==
X-Received: by 2002:ad4:5cae:0:b0:70b:afb5:87b1 with SMTP id 6a1803df08f44-70d75e05055mr18019666d6.3.1755668125292;
        Tue, 19 Aug 2025 22:35:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBqOA37JgwF7zYqh4Ypcmx8eYovwibnfcfNIZ2CIrbvA==
Received: by 2002:ad4:5b8c:0:b0:6fa:bd03:fbf2 with SMTP id 6a1803df08f44-70d75879cf5ls5644976d6.0.-pod-prod-00-us;
 Tue, 19 Aug 2025 22:35:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0b3x8t6abaIopSqKaczV8LrguBj5U5OrAli0OjfDwHd76BFZmDSQ9OcDz0SbqDXwWQajOi+sUTtI=@googlegroups.com
X-Received: by 2002:a05:6214:1c0e:b0:707:757:aef1 with SMTP id 6a1803df08f44-70c5a4700efmr52798456d6.2.1755668124500;
        Tue, 19 Aug 2025 22:35:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668124; cv=none;
        d=google.com; s=arc-20240605;
        b=Sv+xEdgO6iLQBjHYiLL6aOdZ2ZENzKPFbiWGVnSesPWwyfwTWLm6cIhmNqTZJhPnFR
         qmu3WJLOQAbXzJmHM1ERRDozSE3vWkynLkY5QMX8YdQ7zL912PQcjFs2VYmf4pb7UAcu
         JlZ8q5g0ixaVXwdBn6g4DxOkFn4NUwyc5DEaWO6USpI2p4mh3FKC9i9/dH2VBcVdS66O
         i7yhQxcbD0RvATobCN98PKGWE+gZfO25nFdrDFTl/f9YtADbiLpMdrMgh+HsKkE+aM7/
         FX4TypgdP1ZkOuuBFj9Ko+6qbmn7TvknAQiVZ4P4z/hEa8SdR+qUCpiw3x9fnCTN73m4
         w1pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nAFiQLTxZfWIjT2BgzBfUHBH1TsYFyFlhKTQvwrw4NE=;
        fh=yx2TOEA8OAv6JgprDRqBo1i40dkdP17DWUnpFH3PSuc=;
        b=gwZdU5daQ+RbWZmRxoECbSAvTxhPBVzG19+g0Fte0V/QnbfZGl8DmUaT2YhOhAsbLA
         Nw6BY7DnHC8PXHwDu3SmeTe10eOKj/2cVJvTk8bFchiJxszHgkkTljkBhj+yVyk19Da3
         MdOs1XuI9C/KHp9BYLvVgh+sxU7tvtRZ2JADWDKgEZfl66348AkYHitMed7V+iWjFHKH
         gqXqjrkfXlmb7YtGDi9xxzljSocN/ZvUbOkj8VzAhbskF7p8SNFzwLIRltq6NmKH1CKM
         5ghTdUdZMlZZdCJl+/xBZcaP6/j/DVDn7TQu9SZ5ncSKMEWBe/r55urIz5uk68JTuFv3
         TkTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aZiqvL1t;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70d70191d92si1137076d6.2.2025.08.19.22.35.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:35:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-185-SZJqQwM0MQieMhFfhK9-vw-1; Wed,
 20 Aug 2025 01:35:22 -0400
X-MC-Unique: SZJqQwM0MQieMhFfhK9-vw-1
X-Mimecast-MFC-AGG-ID: SZJqQwM0MQieMhFfhK9-vw_1755668120
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B55A11800357;
	Wed, 20 Aug 2025 05:35:19 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1D33719560B6;
	Wed, 20 Aug 2025 05:35:11 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v3 01/12] mm/kasan: add conditional checks in functions to return directly if kasan is disabled
Date: Wed, 20 Aug 2025 13:34:48 +0800
Message-ID: <20250820053459.164825-2-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=aZiqvL1t;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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
 mm/kasan/report.c     |  4 +++-
 mm/kasan/shadow.c     | 23 ++++++++++++++++++++++-
 mm/kasan/sw_tags.c    |  3 +++
 6 files changed, 55 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e7..8daea5892754 100644
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
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 62c01b4527eb..884357fa74ed 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -576,7 +576,9 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
 	unsigned long irq_flags;
 	struct kasan_report_info info;
 
-	if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
+	if (unlikely(report_suppressed_sw()) ||
+	    unlikely(!report_enabled()) ||
+	    !kasan_enabled()) {
 		ret = false;
 		goto out;
 	}
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-2-bhe%40redhat.com.
