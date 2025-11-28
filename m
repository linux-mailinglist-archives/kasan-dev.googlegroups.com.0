Return-Path: <kasan-dev+bncBCKPFB7SXUERBIVQUTEQMGQEFNRIZ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DDC2FC90C21
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:33:56 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7ba92341f38sf1457897b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:33:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300835; cv=pass;
        d=google.com; s=arc-20240605;
        b=L1amSpZit2OKpnOh8vMAs593rPRd6E6piy/diSz0/uh6lKjIf0V5CUJlGmQ6nI9vsO
         0NlwXR98HwOjNeVY9PvGkbzKN8WI8zU49Q6BmkojKGgeAxs5+ZQ2kl4hY5VcEGt6kSVB
         bsk0yndJ7kB0zLvpKmhZjup3m4W4CFusMr3y2IkDfiZHBqZiYsnBlxxA7/3vI3/4kxRV
         dlqOAp6iwKRDbzDM1SE5ziCG2k2tk5mN9YtJ1yY+u2TWcD17sm91183vYNz7xa0RR2of
         ayuNzu6o3849KiFXXNrsq9M3//hYjL9N6UQjhnSS7SsxPvpKg8JRAx+C2fzXI+955Fw5
         Y9sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IWdV0mVazZggayZy7zvBRkJTF5Fokc1P95GBsY/vsgM=;
        fh=Ie0HiLznD7tvSc8xpbvrVcBz3lkBS+BWfER0Br//8sE=;
        b=Qs9r8hAS8eQqMD8TOHyEiKTs68ctnBk9YALT9mA/z/9uC6mRE3UHPJPKK3oHjVMlOl
         0Mkn/1TV7WykYpmL5b1S792eiT5BCfnJkY/rqHArBayv8OwJCxFk79Y8+rmmZJF4LOae
         VNgf3hU1RnaanPXRCN/+y5B1joAZkAwSqWOXgoHLv0JzCY70HQPPQRlP4YmLMVTtgqy6
         zG6QVXkHqHf9jANhyHe6W4DLfIuAKjtEi2lUxr1Ak9qjDFt1xFBWoNh9TrEGQYCxZolX
         TxtSeQjxsXPq0c5AJYSlghSMML8P3wE+99Gof4o/d6MpS3tbkOgbXCOiFq43p5rexUUQ
         KOjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iEOcklDV;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300835; x=1764905635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IWdV0mVazZggayZy7zvBRkJTF5Fokc1P95GBsY/vsgM=;
        b=k2NG1A3eXIogrwT50oLsb5Nf0wZJsa6/BVDHBVKOFTkbdKIOKIeNnBboKlSqQqpZ0F
         p6hJ0GN2EDKsx7+FDTp+aZfG1SwMRcaMwVQRIBxekY2F4eX7pxSd4fknvNm00Ax/JSIm
         B1kqd1nwoMyZcVCwKUcMxoxCwSohhK7SdbvGeOKy+zkkB1cHmr8HtMHEg6SPdNqXyfos
         /fty9rlaIFdG2CdLry1MWMYykNxPbFJOZO2Hw+JLM4okZ0D+wRy617zleBLEmJp5dGPb
         MiAAVfsi13T4OCUtzh4q9+48mbDx/tGBqHmZCdWztUNHarvaViSs8xWFRApcoSn2yRr0
         7m5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300835; x=1764905635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IWdV0mVazZggayZy7zvBRkJTF5Fokc1P95GBsY/vsgM=;
        b=RvzvZMFoJGpOBQHBUB++XbV65wMeqCkvumNGRZyprVZlBvTmt5AFD0k0HRq6pwGPSh
         ue9AXDJPMQ0vSHI9dKwWT02aH3TJvfBu8oFkr4LSLiNn4xdyXPnaPdjfPgsZCQgTKaze
         qcsMEOqDNp0yWCGixi/PPO4bd/FCtnBHlZALANcp48++ydwZS4tbfMDIeimLxBdYw3Kj
         cS/KkFRIwynb7y+8jgIzN+RVCmbmCoe8mNfRrP5pUxcif20/AsUNGyDvnC3WMg8JiGOB
         bJExmgtwz2Yq0miABXIFrPZhpJQ96wTISSqoMdlBIN9LZmS3BV8UqTsTcNc5ELzpOK4s
         odDA==
X-Forwarded-Encrypted: i=2; AJvYcCVM8I+H7ijEoruTFtXuWGoCGC1i7/cxUYR3J/4lNDbfPNxiJou7vn1BDQtYMOVUo+pYZysCGg==@lfdr.de
X-Gm-Message-State: AOJu0Yy0ZPsFo1LZccIvsds125O24MXeuMhfZdWdPindJyPPgAJ/k586
	uxCpQaxUHqe+ywOLeAR/Py1X8LFDnc3hpyM4yIzLxtbBJygR8ONKGrYB
X-Google-Smtp-Source: AGHT+IHpMxbnhXyGUf7xMs0YnzZVFrfpbjNpP/SjUci/I3H5gg7vhy4eoGTnEfnBO6AEJMjb+hi/fg==
X-Received: by 2002:a05:6a20:a125:b0:341:e79b:9495 with SMTP id adf61e73a8af0-3637e0bd69fmr14260467637.54.1764300834592;
        Thu, 27 Nov 2025 19:33:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YpGacyYsiDVTVH78EK9keXTbnWmfc+mph1QxA+AZwRCw=="
Received: by 2002:a05:6a00:2da1:b0:7aa:cb6b:6756 with SMTP id
 d2e1a72fcca58-7d05f7ca1ebls1205333b3a.0.-pod-prod-09-us; Thu, 27 Nov 2025
 19:33:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMcXqBMSprahp1JxpyQ40FZiqw9xRkhUG+1G/MRZRxSPtMISZfNkZP5zwU44kyBsecrz+ASfXummE=@googlegroups.com
X-Received: by 2002:a05:6a00:3cc5:b0:7a6:2c97:eda7 with SMTP id d2e1a72fcca58-7ca8b596b39mr15051183b3a.29.1764300833023;
        Thu, 27 Nov 2025 19:33:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300833; cv=none;
        d=google.com; s=arc-20240605;
        b=XkQgaAa68Bt2wUPDeKcNSZTB1uUvQ/fUIhzxj6oTJvd0+mfBskyeX2eeOX1IFKOYzC
         JJFOs+OjxgFwNIKYevEiyGY6H6akxqtV2Uraf/Gq3K+5Qdf6HpN/wJeI5gtEOpML4zru
         zeaMTJSUSgpuMgv6UEaZO4cAKoO/z1tcpW7uwzA9Dqt7hDCxMyjaG3m/4IPLaBx5dW6e
         mLl5/HprkZbDyEkGYHXDFgJAPhKfvUAL4VHpPgmyIZc0T3/ErVUAFo5vECupAsTARex4
         ylpZwoPstU2jEXYhmEQrtEMB4182kSm6zjd/knTNjajx1rmxeof6ivudCFuYzR8MBXyH
         P7ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UdCEhX0QnAccjf1ifoDBiGeeToccBUA00HLj78ygtME=;
        fh=5SDByJ3Hs0yfOCoQGEuG1sRE6NAvqIWBUeJICelOz9U=;
        b=MtTjYldBdgY2pBNN8QA23SenWeuO76dfUHPsyGOwEyh58QrZgIbRIpAqiVAs5jGda3
         kWc+Sfmpk577c/al8xXg7h327gCRfIWC8gbkq3ulL26y2MQ5la0ioYJxbj/e/aL7RBer
         o9xLZnyjvLBh16wmMUyrk1qZlOXMsWPL5+eLRKU4TAGqPGAQKi9I6tzEbeF+mDvdeuKe
         rBw4cFwIkFcPHzIzXqinPoWCzjLMQf92U2yB8vE/8ti0NeP6uKSf4xCuR02tLZCkab2b
         0BVHUtCfXYbbTVIctSyMZHII75u7WgTzUvfBXMH0XEDyUbmiXjLOXsqtFEX9d5pvADNJ
         lQ+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iEOcklDV;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7d15d4a6750si73650b3a.3.2025.11.27.19.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:33:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-561-UOimTxoJOkekNTmxQjBXig-1; Thu,
 27 Nov 2025 22:33:46 -0500
X-MC-Unique: UOimTxoJOkekNTmxQjBXig-1
X-Mimecast-MFC-AGG-ID: UOimTxoJOkekNTmxQjBXig_1764300824
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AE5031956095;
	Fri, 28 Nov 2025 03:33:43 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 003BC19560B7;
	Fri, 28 Nov 2025 03:33:34 +0000 (UTC)
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
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v4 01/12] mm/kasan: add conditional checks in functions to return directly if kasan is disabled
Date: Fri, 28 Nov 2025 11:33:09 +0800
Message-ID: <20251128033320.1349620-2-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iEOcklDV;
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

The current codes only check if kasan is disabled for hw_tags
mode. Here add the conditional checks for functional functions of
generic mode and sw_tags mode.

This is prepared for later adding kernel parameter kasan=on|off for
all three kasan modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/generic.c    | 17 +++++++++++++++--
 mm/kasan/init.c       |  6 ++++++
 mm/kasan/quarantine.c |  3 +++
 mm/kasan/report.c     |  4 +++-
 mm/kasan/shadow.c     | 11 ++++++++++-
 mm/kasan/sw_tags.c    |  3 +++
 6 files changed, 40 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2b8e73f5f6a7..aff822aa2bd6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -214,12 +214,13 @@ bool kasan_byte_accessible(const void *addr)
 
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
 
@@ -239,6 +240,9 @@ void __asan_register_globals(void *ptr, ssize_t size)
 	int i;
 	struct kasan_global *globals = ptr;
 
+	if (!kasan_enabled())
+		return;
+
 	for (i = 0; i < size; i++)
 		register_global(&globals[i]);
 }
@@ -369,6 +373,9 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int rem_free_meta_size;
 	unsigned int orig_alloc_meta_offset;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!kasan_requires_meta())
 		return;
 
@@ -518,6 +525,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
 	struct kasan_cache *info = &cache->kasan_info;
 
+	if (!kasan_enabled())
+		return 0;
+
 	if (!kasan_requires_meta())
 		return 0;
 
@@ -543,6 +553,9 @@ void kasan_record_aux_stack(void *addr)
 	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
+	if (!kasan_enabled())
+		return;
+
 	if (is_kfence_address(addr) || !slab)
 		return;
 
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index f084e7a5df1e..c78d77ed47bc 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -447,6 +447,9 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	unsigned long addr, end, next;
 	pgd_t *pgd;
 
+	if (!kasan_enabled())
+		return;
+
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
@@ -482,6 +485,9 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
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
index 29a751a8a08d..f73a691421de 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -164,6 +164,8 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
+	if (!kasan_enabled())
+		return;
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_unpoison_new_object) pass tagged
@@ -277,7 +279,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 
 static int __init kasan_memhotplug_init(void)
 {
-	hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
+	if (kasan_enabled())
+		hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI);
 
 	return 0;
 }
@@ -658,6 +661,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 	size_t shadow_size;
 	unsigned long shadow_start;
 
+	if (!kasan_enabled())
+		return 0;
+
 	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
 	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
 				KASAN_SHADOW_SCALE_SHIFT;
@@ -694,6 +700,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 
 void kasan_free_module_shadow(const struct vm_struct *vm)
 {
+	if (!kasan_enabled())
+		return;
+
 	if (IS_ENABLED(CONFIG_UML))
 		return;
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c75741a74602..6c1caec4261a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -79,6 +79,9 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-2-bhe%40redhat.com.
