Return-Path: <kasan-dev+bncBCKPFB7SXUERB77Q5TCAMGQE5GVZ73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81169B22755
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:09 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-23ff7d61fb7sf52666445ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003008; cv=pass;
        d=google.com; s=arc-20240605;
        b=J+5io5LeBbA1rmCVW5ISVGVkxahoIbnUfw58J/fO0lFiTkaVvztcFc871SEVbUrTU2
         NiG5s7HJXB2g2Fs7b4YEdq0JeqQwn6F+pbP7r8sXjlyAs27L4gpDTmcG8B3De6qOX/I/
         tWFKz+xHpP4vVe3BAukcO3rqg2/P+t5gB5noOgWdgMsR8sKXuUZNh8QX6KVuXdI/CNUR
         KgWgiizIQjgfMptCFfMz4cpC9GwEwha8jkQUBpU2yMBj73PmhIzPYbsawdLv0yK9hnku
         JTJBcbYUI6fMDgOs/FTbsEKW24WI/z93QUCYo8xEjhDtpheXlC0aILDWX9AL5uoav7Gg
         cn4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4K8J8yJvOsozEPOawHXEJJjV53UDlP0ThqIilztqKkY=;
        fh=yAxUTjUPneamhoiD/ralS6q+wD/SrUuQ/c5ZGyBJxAc=;
        b=G5ZlvOgTYqX+v8V0GDN9K+lqBcM+udtAw7qi4riohGaqjE6TMWzPbjqLke1VfnbtKG
         ZQ1oiAPuI15vu14EwQ0RidEI3EPMXo+T8EeCBJx8qQgSVwbJlS72uO1+mi5oSC9YpanA
         oGkKI13jUNq9CRexDJo0/14WkQI/+WzgsF82bQ3AbJ7ZKwCa9vK8Bmi6/adSQcDyZrbn
         ZwtygD22B4HEel1fWzCC0SCid0kQe9xWMLd9ETW44sSEOdXeojVazn/jPhL3upyaSiaC
         WDohEVXD6R0hz6l3ItBr0mRgJg3OEn+/oxVzw7E/6F+PomBGbP7U8TASmsjzavGBCUlU
         +h2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="fh/RgANA";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003008; x=1755607808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4K8J8yJvOsozEPOawHXEJJjV53UDlP0ThqIilztqKkY=;
        b=S2PzWML0PNS1obZTPlymQl8XFXlxuFUnFCh4pBwQuLn7llBqO5oDC8vXysrnb9Ztnc
         SjiHXc65U4/YErRb9N46Y22fcqdqvQjVka2vtkYz+MAonHESW5ssu4QNcxYhN/h+LyH4
         7CDxMciuP416GVk0siBEH84x4YH0HkjWODolR0vUomUDMqRRBU99WN7WkIlPVA7UwcAy
         QfKBQW3xei+j+GHfCy2j0WyRamUEu7SuEQUza55FP/bshjEb+ZVmDO1FZau5Lew/eL5k
         5+XQeiVwdV0nkTGh4eiNPFaZeIG1k2LD/NEWKsD0hXGc/EoFDNnVT6tJOPznRlEKkwZ1
         84kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003008; x=1755607808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4K8J8yJvOsozEPOawHXEJJjV53UDlP0ThqIilztqKkY=;
        b=uWAkH2smEFiLaTceHLyOOjEqYhgg6L50DVTbuPEWBCs7AOSAL19OhD3VkrGgVEYywU
         Daomt4Bs37XUAH0WairHJkkHUbgdMHa/5hZ3q/zFJlUs/7HMlJO5UGm7YClhHvLZaeHm
         a7nAY6abeUKl/37ymdbhhzu2IW6qFvOQeL4M9YLgHH/iCyvhgpI1iaSqJ+JhTXia0u5r
         0jDdP/tOme1uOBMYbbbjAbsAgRVJv7tUwahq5KWjELq4lQ6F16xwn/MGvsctOY2nROvp
         jOWccMkm2oBPfWGQjP4BGa6WPLT3IiaIh0w1TwrXHW0OljgIW+AMW2Y+Ah8YlRPJ5Ev4
         YoZg==
X-Forwarded-Encrypted: i=2; AJvYcCVz+aJY+7YWR3Fp3BAstQE/KpGIm25fNdGEP2DfCvnilYg3b1eCE5xKpuX/sebCbRaEVTO9qg==@lfdr.de
X-Gm-Message-State: AOJu0Yxhg45You/YLwdBYPOjsWnT/5mW2iIifHzorT8z+fzdJzlV5ogH
	CC38t11ioxs9qbNN+66Pk4k428cNZNlnoX3776YBjTTyuKissjAiQzyN
X-Google-Smtp-Source: AGHT+IE2e8xQ66BLm4BWB5RKUAkZ2jh8nYH5ZNA9F+cW50En4xXavUm7uYSWTcf6c8VrYqghF2APcg==
X-Received: by 2002:a17:903:3c44:b0:234:8a4a:ad89 with SMTP id d9443c01a7336-242fc2df93cmr55949675ad.1.1755003007815;
        Tue, 12 Aug 2025 05:50:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcpCznQYCsUTkWkRqwcPuHYPYPQbVt7eMD/E3GELfwGtg==
Received: by 2002:a17:903:3c24:b0:23f:8cfc:8dee with SMTP id
 d9443c01a7336-2429df7d72els31354395ad.1.-pod-prod-00-us-canary; Tue, 12 Aug
 2025 05:50:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDBpC+9b+zmughXMJdgsCVocEsIGzC7eOmu+Z8Ul0QKLeraL2EGiGVByhlxipydrCW1dycakuwYL0=@googlegroups.com
X-Received: by 2002:a05:6a20:d04e:b0:23d:45b2:8e3c with SMTP id adf61e73a8af0-2409a406139mr4980887637.6.1755003006458;
        Tue, 12 Aug 2025 05:50:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003006; cv=none;
        d=google.com; s=arc-20240605;
        b=GWnVNQe0TQ/lVXN0ExDzWMTOGihUzgbdRudYI0793smLgoEXVeSq7ZUy35/eMsuFcD
         Xvrd8qb0aRUxeG1R6MEQKAmuGm85CoNnRisSGsW5glMnMuguLHvN4nFEIgIQQIQT5KN+
         uGJqfRnOMGXyl6xbDwdmbSR4XMvTyLrHC1AtDotPgsQ8TCY34IQIAoQslWJBUrsL/l8F
         wnuZpVV3nc1wcTOG+o2DdBcKifgR9q68eRK46018RG2QFHzAX3O0aiDfIlBz2/RiFdom
         Q3MXSfrb1yZWpnbsDzDlfpnOY3gAkX2+cI4LyB5FEremoB0kkNcBCwuNf4HPBiD9q3Uz
         4UJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nAFiQLTxZfWIjT2BgzBfUHBH1TsYFyFlhKTQvwrw4NE=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=aiwyb9gcnsLdautiUrJdUdzUUleFcIl1LX2Iq5PvOgy8bRa5FrDP2+5D5yFY8l2tvz
         CCMNCJJc951qcZAjkfwiAy6C/PobtFQiTTXy8oKRagxsNjumFEZo4NToPNBKC9fKbTTn
         7pGC7+e32LG1DmjO0tMhXQI4Okdr9tPIeY5g05EKl9a5sVXXFc5jfYYuf25DY1PlS+7g
         99PyNsjz5MBjwJrJkvJ0h5htkZwZlGGNNtIebZDmwDx6ZP458usuVNoiHOJon3sEZgT5
         ufYaxhv1nz5ROtEJNoWkmqOaoR+DnPHltxcNGXDms3C3UkFzG5R2gMXPfniEMtuhA9Sl
         i7Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="fh/RgANA";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bde87104bsi1039491b3a.4.2025.08.12.05.50.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-21-pCgxLexbPZWoogFBtgeuVQ-1; Tue,
 12 Aug 2025 08:50:01 -0400
X-MC-Unique: pCgxLexbPZWoogFBtgeuVQ-1
X-Mimecast-MFC-AGG-ID: pCgxLexbPZWoogFBtgeuVQ_1755002999
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 937D9195605B;
	Tue, 12 Aug 2025 12:49:59 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A119E300146B;
	Tue, 12 Aug 2025 12:49:52 +0000 (UTC)
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
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 01/12] mm/kasan: add conditional checks in functions to return directly if kasan is disabled
Date: Tue, 12 Aug 2025 20:49:30 +0800
Message-ID: <20250812124941.69508-2-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="fh/RgANA";
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-2-bhe%40redhat.com.
