Return-Path: <kasan-dev+bncBCKPFB7SXUERBTP25TCAMGQEWPPSASQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42DD9B227DD
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:10:39 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b0ca325530sf20189751cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:10:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755004238; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kr0D5fYOgedte9HlrShbmQt+QV5oj8NVIyIUTY2OMvEGxWif5aBhOGFicUMBflMMmY
         GEyqLWeEWct3Q8OHeVdbTGHEW1QthoQH4MhDq9fauPfUbLrw7pdJKMggd0Fqj/n0BGIw
         E3P4bRoqSEBtfcBgG02TycagqD6tn6GwfGZJlkyyGe9WKtIkZdfDKd9aKuBrsln+VHRl
         uw8qMDhIqLHXRFzrXkp6aJfwyyUI8MI11TG01UQtvSjt93ZFgQacFn8hsEkZ1GHMNH51
         UllOs8zMKXVvtNtDnKu3QZTL03BL3fK1HjmnTr0dg9jt4hQ/1fo0zAwxwu0SmCeSrMPE
         FGpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Msrps/aGmuY6jX9LVfr8rv2wYbO/1d4uxN62DH6Dtu4=;
        fh=yk1+SDTzY1R5RxZgbj9m7ejSh5A9w656s7oOnFtib+0=;
        b=a6gT6sjxOrxB6b7cNu5YEtBcs59gGWUSQjwutj3Ao20uXlyQ4g8A4L3ZdEDx98T3LT
         nFAIQ0raIYP+h+fPXxqpIwv01blmZNZ7Yk6t9t/Pgt2RhWclsgPisaezB5IPQrxC8pm2
         kIwIOVjHu/5BiDUEY+Bi4EirUWbM1hnojQhvF3b1u7LlewxgtIeLUrnYzesbFXzopbfQ
         aZEE5O1opwnk14qsR2dzoyzb3/UAoZ0Zni85062UbJwYjKcLqvF9eT3FpCQO9U61dZoa
         nzAQM0+xpjrwYAg8dGS+kA761cDaBMghMaASE8YwFihLe9oWy+02tpnnjshpcqIWLzlx
         qQtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SCHNpdA+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755004238; x=1755609038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Msrps/aGmuY6jX9LVfr8rv2wYbO/1d4uxN62DH6Dtu4=;
        b=rYqrm6Mm3K1uhvjucYYNo7cCzd3tV06tRHCJx9nKhTWv5OJgbzuNKvNd1CLKGzKQN4
         odNulp/eNUv7Rtax8OZAyLE5ixD4WkaTYhvFJEyvdH/QjY+XrvqlzOnbOKOrVYIxRXeK
         BAhua6MCZiVpePjlFnxIT5JqRAAinuNjv5eh7xiSwfNvchXvMUpwKmHQcddJIn0P0g2A
         TDZe34gZHKtBX7foc1qLv3BJYEsduKWHDfcLOIlLM8J9kZJg5BmY6PEXgCVU3ppPWq8t
         PgVDRUIH8LCEFNqb83CEXa2hgfMtjWZFeLLkApIjFVBRugkrsobATLim0hHemtsMaguT
         RXkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755004238; x=1755609038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Msrps/aGmuY6jX9LVfr8rv2wYbO/1d4uxN62DH6Dtu4=;
        b=Jn16t/GzM0aY9GBbIWQOTEmh5t/vtzTDkqSs7EBewXCpkzfv/8EFwu3Jq+4nOzrdYC
         UvZzNysHlGJ/40Cb1dPvU2ljfxvpjhGo8XNfnJggUAcBqhaGzzve5hzyetDodZYWsGk2
         15L75BBOxZSaIURvKiVzScF0XdljL0r0d99L4fFAE0QclgTXFPS1WpVXTL/+x9M67AGP
         pFs7jNgmWANjqDnsJGlTU0jEYePdsFGGz1eGQxGi/hpxL39hedMLf8RMnlFWBwPJTM3O
         yKLBFDvem3cPL3YKq3jXuSwfxSN6T68LBdDP9blq9PvRTc4l11LhN6k8SQK2IT4LHKUU
         EPRw==
X-Forwarded-Encrypted: i=2; AJvYcCWFmxUHsh2NJlKYnkqrrG1hhgPLtyFOnch2jF3e4/tzxlWxfNUJ1Qu3DKhsChT3daXoJXDeXw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4QofJqYuhDFbnLfZ+dEwH+3YGQH/uUzQrMeTA7jnSo99OerdJ
	CSNB7onGDSf2Kx3ho9R3wl4Oo126blFnAaKRvB9BzJj3HvwQuxk0WoIt
X-Google-Smtp-Source: AGHT+IG3jtFZVvCaS7PBcnNvP0QBSEcw2dG7cruTVfb3W+8a9kIME3OX5rVuyWl6b3fY5mnDkiqT0Q==
X-Received: by 2002:ac8:5749:0:b0:4b0:670b:f21a with SMTP id d75a77b69052e-4b0aed0b64emr191331271cf.5.1755004237918;
        Tue, 12 Aug 2025 06:10:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeRkFkjT/izs4L7BI05v2BgWxelPsnZMtwiDpMnTeFhdA==
Received: by 2002:ac8:7d91:0:b0:4a8:17dc:d1ee with SMTP id d75a77b69052e-4b0a02fc628ls68508141cf.0.-pod-prod-08-us;
 Tue, 12 Aug 2025 06:10:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFnNhVH/uK7LdeGnWCPP24OnatL0+Dax1DzGpDKkURNm3947WcntPjDOvmat70jSFceFi87xua1/w=@googlegroups.com
X-Received: by 2002:a05:622a:1c1b:b0:4a9:a3ff:28bb with SMTP id d75a77b69052e-4b0aed5a7cdmr222768241cf.25.1755004237139;
        Tue, 12 Aug 2025 06:10:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755004237; cv=none;
        d=google.com; s=arc-20240605;
        b=AV+XM06TwPvmonz7v5M8cSYeC7NzZ9mqdGRHCaTVAhs0tjY21re/2uHA0ncTdPStGB
         0SJ5/mDQ7yzKhM1LH1u1JQnOBcsg57YwUVzlubE0n3CsRHFJ+BB614nCRTXoos18uyPP
         /6PgCZkMxiIdH7aFXKTsFl8FO5e60IGS6C5G5acdgir69tmGtmRERJzCZSKg5YvoDTVf
         IanHn2VoeuyTYv2ozMUAwtRWg2dqbc/jkrdjkUc+7du7BmJVDdyzIwvdT+Xzpmgz7F8/
         +nxuaiGqJMatbBW7UfgDBWE2fye3cl7nkPPuq4rrez3CSB2sJPNDtHig0en9b09wyFAR
         t7ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=90kjOoDlgJxvROpKhCBaV42MFQEOcPlCS7aVoYrLf2Q=;
        fh=tJzQ5qxkJm0zG4QpcVmXzoBYu5DFFVue0Z3QtfeLqEI=;
        b=hQQKJwu1nX6sCK7uwBwDCYAZExqFBUYWMx4WmcL+RkHY21r11g1fZstlF34OTM7UO0
         Ov9SQGsIEx+YRv2yc7KWmWIofBM1mlfkUOhCoQGeg3bYWkplW6w93YJGS9iTy48k3qQw
         jNjX19No6+notEt3qDDY5NLtU4L/zmNXgkUeixpTEpJmFXQVFZ7OjPinDz6dJfcXGY5C
         L4E+eOwzGwLOM399ZjGConL895PeRV0mG5U5BdwPIN0aEdTsowbBvYLiR0MZ2o4GrtR+
         jQOzhrKqHA7wXahwkl5JP/0AC6FbNcXODioVNkFq4qtrxemn0lTMBX8OqxVwVv6awyyq
         AYHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SCHNpdA+;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4af1ed86199si6889631cf.4.2025.08.12.06.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:10:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-675-TQnxb7SJOn-5DJ0f1i7kgA-1; Tue,
 12 Aug 2025 09:10:33 -0400
X-MC-Unique: TQnxb7SJOn-5DJ0f1i7kgA-1
X-Mimecast-MFC-AGG-ID: TQnxb7SJOn-5DJ0f1i7kgA_1755004227
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5A40B1800291;
	Tue, 12 Aug 2025 13:10:27 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7D1B71955F16;
	Tue, 12 Aug 2025 13:10:18 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: snovitoll@gmail.com,
	ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-um@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	agordeev@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 4/4] mm/kasan: remove kasan_arch_is_ready()
Date: Tue, 12 Aug 2025 21:09:33 +0800
Message-ID: <20250812130933.71593-5-bhe@redhat.com>
In-Reply-To: <20250812130933.71593-1-bhe@redhat.com>
References: <20250812130933.71593-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SCHNpdA+;
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

Now there's no any place where kasan_arch_is_ready() is needed, remove
all its invocations.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 mm/kasan/common.c  |  9 +++------
 mm/kasan/generic.c |  9 ---------
 mm/kasan/kasan.h   |  6 ------
 mm/kasan/shadow.c  | 18 ------------------
 4 files changed, 3 insertions(+), 39 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69a848f2a8aa..e48c1fd60edf 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -271,7 +271,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
@@ -279,7 +279,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 		       bool still_accessible)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 
 	/*
@@ -318,9 +318,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_arch_is_ready())
-		return false;
-
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
@@ -547,7 +544,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return true;
 	}
 
-	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+	if (is_kfence_address(ptr))
 		return true;
 
 	slab = folio_slab(folio);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 8daea5892754..d513e3e2e136 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -168,9 +168,6 @@ static __always_inline bool check_region_inline(const void *addr,
 	if (!kasan_enabled())
 		return true;
 
-	if (!kasan_arch_is_ready())
-		return true;
-
 	if (unlikely(size == 0))
 		return true;
 
@@ -196,9 +193,6 @@ bool kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte;
 
-	if (!kasan_arch_is_ready())
-		return true;
-
 	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
@@ -505,9 +499,6 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..e0ffc16495d7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -544,12 +544,6 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifndef kasan_arch_is_ready
-static inline bool kasan_arch_is_ready(void)	{ return true; }
-#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
-#error kasan_arch_is_ready only works in KASAN generic outline mode!
-#endif
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_kunit_test_suite_start(void);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 637f2d02d2a3..d8b975282b22 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -128,9 +128,6 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 	if (!kasan_enabled())
 		return;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_new_object) pass tagged
@@ -156,9 +153,6 @@ void kasan_poison_last_granule(const void *addr, size_t size)
 	if (!kasan_enabled())
 		return;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
@@ -402,9 +396,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	if (!kasan_enabled())
 		return 0;
 
-	if (!kasan_arch_is_ready())
-		return 0;
-
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
@@ -575,9 +566,6 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	if (!kasan_enabled())
 		return;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
 	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
@@ -626,9 +614,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
-	if (!kasan_arch_is_ready())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -651,9 +636,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812130933.71593-5-bhe%40redhat.com.
