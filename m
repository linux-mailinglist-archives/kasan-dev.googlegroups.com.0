Return-Path: <kasan-dev+bncBCKPFB7SXUERBCWHY3CAMGQEAF63JGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 52702B1AE32
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 08:24:12 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-30b78e30d40sf6404034fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 23:24:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754375051; cv=pass;
        d=google.com; s=arc-20240605;
        b=FEF0WIZCcuJtNKiZYkDeYvpk/olW4jHzd4BCUYqfmQSnOddwCsnG1K5YZ88pyBuXzQ
         by8CB3Yn1XpxX5xAa3ZcDSCGp1ljZRKt65McUgEu/9uUqoAPimHtN3mB28VuM//pcgJ6
         HsoxbIIFR5kG14x7Tr+hLQ2wzozl7m96MKE1yi36DM1EvW++8TXYQdpTaLIaw9seRAG7
         msG2DfzLKF//30z1tn18V/zIwm6MaBYmtO4ejQFmkXeDG6why3+C9RS4+xbCo0N7Up8x
         3020uwPg7ktkx0dc2Zd+3QEI2T6yM+jz+xeDo8pKX2f2eDIKawgzEeilv+ijFdg5zTKJ
         mJ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=q+zdOKak7N6SGkS0lbrvbD/pgRW0/lDG8JHZdTj+Yc8=;
        fh=biTIXF8LAxzoD61NeZYAvVdZ4S7N6tn3fvVW6CxRmgA=;
        b=IHuxqyO6plxUwXg1rjDZSr0LgvRyrrXFI+90ZFz16oWnxmInDpdgoTet8lR68QPkHW
         Ch+hKYX0+hat+lFjqyouk5mm7lbuOXNnu5InVK3wqOWzGVqVpKmolPFxCCBxhgdqAGJo
         ZAXg4mxfgrB8aawQ5spSer8OupO5O8W4+6ZViSNWMwtiilI6iPkZXz5xItxiiK33TzsX
         16GZhKt1t5Rh3i0iLEwHCz1fJVN/gzwl91RLkbuad+sSZq+hNijKiKQ7ydtYYiu30Dbx
         7Wel67UXrLKMdi/cUmQHOIar3L9jySWMreIvlxXThO18c2opZQQWdMqhpguZHIp4eN5e
         AVyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z47u530i;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754375051; x=1754979851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q+zdOKak7N6SGkS0lbrvbD/pgRW0/lDG8JHZdTj+Yc8=;
        b=SZbYyQniL7zHqKqUkmpAw7mjNwmbRaOT0XSBqBKrvVrGN2BAnWdn8K4jgF7rwoSxwo
         L/s2fZZyJVSWSiSi+iu6Dh5AcUIyI8+MhZJmtA7YpBtyKxcZLvChy4OCKXRS8l+pH06P
         JzR23TSPBTLg8RQik/NL/ilhFQcFo1S68Kp87V3hsOWReXzYKcD5m+TfU2hMlh4ydVuE
         VqdPwlLmq4WaFNWDQjXzvthknYwx2v450d8yB1qIb5O/6iBdBvUIFEECzt7nrV8Bnah7
         Zlv9IUrdjheNMtO4o8hosgCM7LgUpMG+e+KM9ckkLhSss/q9vJsgyYBYjm6+nKPrA83y
         fzcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754375051; x=1754979851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q+zdOKak7N6SGkS0lbrvbD/pgRW0/lDG8JHZdTj+Yc8=;
        b=JjZrRunOJ0zlz3YWHPfDMQAzGz5zd06HgVGhhfr5oXG76TZ9wbVgZ/L3d+fe9ODnXV
         xPY1WOwdoxb4236wxgsc6sGPIlm6YlOoVR1amo294YkZQ2sWljH5vl9+16mAX6NGGclH
         KmSUCyxqvGOyCCkG9on6W3FcspJURlrDLVZEKjsOyj3VQcuVoLCIve6FRJ8GmVEAO8Lp
         FM+dIjkCN9LlyMK7aTouyWYoFy0qkmBYxyMgd8PMJuhwc9yzTHFqnGqhPrTsVLaLzQRA
         Tu8ePFTUfI2HqUq3NQgQ+mFT0gJzmUBfvJEcfrQnid8xWYP/kA3YQKxUsPJNKYaEhwlO
         vBZA==
X-Forwarded-Encrypted: i=2; AJvYcCVN2GLb+yKPCDCk92R11AoDUbRqwxcCpLNSpKpU3FyDtXG1r02AWGl+mjGE2FTwLXjUCj8ebw==@lfdr.de
X-Gm-Message-State: AOJu0YyDqO3CKBp/F7xQDVjmQEUrG8jaWC0OjWJPV42zwfVIHi2Pzht/
	LAlLIp06qYOnyXEuz6E1oL5clqP1jKg+r1+0h9YvrRCjV+fdlEpQYKQb
X-Google-Smtp-Source: AGHT+IFLh3bhWKq/VLzr/S+1R7FqO/f/VRTnxEwoLu7qI8n6s1GUCxcRGVKSXO8iV+d52RS3oZ5GpA==
X-Received: by 2002:a05:6870:5ba5:b0:30b:ae4c:2e82 with SMTP id 586e51a60fabf-30bc0fe7805mr1333674fac.12.1754375050835;
        Mon, 04 Aug 2025 23:24:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeRYr2aH3L9HvqGxfScTh+P9s+jTSeJ+qzV2sYwLSsafQ==
Received: by 2002:a05:6870:7a0a:b0:30b:c87c:7857 with SMTP id
 586e51a60fabf-30bc87c8f85ls217214fac.0.-pod-prod-00-us; Mon, 04 Aug 2025
 23:24:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9jje8hhQ/9DphZu02Qk83f3PGCnP2pUQszvox+rHFgF6YA7KSncMz1Tp/5nN3sKjlFF2mjNFEcaY=@googlegroups.com
X-Received: by 2002:a05:687c:2b9b:b0:30b:b593:85e8 with SMTP id 586e51a60fabf-30bc112eb65mr1266673fac.19.1754375049138;
        Mon, 04 Aug 2025 23:24:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754375049; cv=none;
        d=google.com; s=arc-20240605;
        b=B1Vcg5B9EjcPQoxuk+qK8UuCz8DLkjk9Lt4NVboYqu431uDEbVJQ40fc77n7VyGN0y
         hBZWzX7Umn4x3nx7MCShau767vl0X0CG2fag+Yy7IKkscQFb9kSQkHRk7VyiUptzk/yx
         mI1KfK4fkHJ8DZBVAaJpIp+s5JGhkMJft1ioGdzXW/4UNTR5wWhB6e0M+2bzwN98xm/n
         a5CUI2KkHB4ifLLe9XzB00v/GhcsDC24iTywHHokLp28DEXPwrVUKZOdnYDQAAHmeymh
         Tbzq4OLOjCuqKaaXasoqIsKcVZmITiIzvsuMk7xf3a4+XWvJwE1IyLkPZ2WLldbWV4b5
         AciQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c+hY2uT3rtX0jxqTDwr4o0wnNu5PQr3WJ9i3CgsATwQ=;
        fh=zdgUGJ5AVcpjW6c3+faZMlslsU1+4WtDOSxOnvwQO5s=;
        b=ihEcBIgvzWK9R8jVGLywnkYycUGbKXSsSxmIJrwptWdgACED9tAP3Paf/Tsst0L7gi
         fJsdUvMtP8M/tQrKn3IkNrk8HSHj7i7V3Kn6xjsegsbfngrFbExBrjfEhufi+Xke5z0e
         qY1EdfmKVqukTDfsE+vJRoJEFgfRcR3p1l28vQx/bXz5iQo/Is0fLoOr01Y4j+/CUlpa
         SRDyg7eCeac+5uGxl3lCtLm+QLOGfKNSqd0XyLG8Vzmc64WOkxgkepGTFtLtPmaNDvlm
         aA50ZN/S53TMOthZxErIvT3DAVnBgYmYK91U8uQL3egaEDboPVy8LpB16ILWvHjrfL6I
         UBqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Z47u530i;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bd07efb27si11038fac.1.2025.08.04.23.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 23:24:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-357-zuByUt8SMlOb-KzlFOuhUA-1; Tue,
 05 Aug 2025 02:24:03 -0400
X-MC-Unique: zuByUt8SMlOb-KzlFOuhUA-1
X-Mimecast-MFC-AGG-ID: zuByUt8SMlOb-KzlFOuhUA_1754375041
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8C4B71800366;
	Tue,  5 Aug 2025 06:24:01 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.136])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 55DDF1956094;
	Tue,  5 Aug 2025 06:23:55 +0000 (UTC)
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
Subject: [PATCH 3/4] mm/kasan: don't initialize kasan if it's disabled
Date: Tue,  5 Aug 2025 14:23:32 +0800
Message-ID: <20250805062333.121553-4-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
References: <20250805062333.121553-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Z47u530i;
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

This is mainly done in all architectures which support kasan, and also
need be done in sw_tags init funciton kasan_init_sw_tags().

And also add code to enable kasan_flag_enabled, this is for later usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/arm/mm/kasan_init.c               | 6 ++++++
 arch/arm64/mm/kasan_init.c             | 7 +++++++
 arch/loongarch/mm/kasan_init.c         | 5 +++++
 arch/powerpc/mm/kasan/init_32.c        | 8 +++++++-
 arch/powerpc/mm/kasan/init_book3e_64.c | 6 ++++++
 arch/powerpc/mm/kasan/init_book3s_64.c | 6 ++++++
 arch/riscv/mm/kasan_init.c             | 6 ++++++
 arch/um/kernel/mem.c                   | 6 ++++++
 arch/x86/mm/kasan_init_64.c            | 6 ++++++
 arch/xtensa/mm/kasan_init.c            | 6 ++++++
 mm/kasan/sw_tags.c                     | 6 ++++++
 11 files changed, 67 insertions(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f703136..c764e1b9c9c5 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -212,6 +212,8 @@ void __init kasan_init(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 *
@@ -300,6 +302,10 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
 }
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45daeb..0e4ffe3f5d0e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -384,6 +384,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
@@ -397,6 +400,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 
 void __init kasan_init(void)
 {
+	if (kasan_arg_disabled)
+		return;
+
 	kasan_init_shadow();
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
@@ -405,6 +411,7 @@ void __init kasan_init(void)
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
+	static_branch_enable(&kasan_flag_enabled);
 	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index d2681272d8f0..0c32eee6910f 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -267,6 +267,8 @@ void __init kasan_init(void)
 	u64 i;
 	phys_addr_t pa_start, pa_end;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * If PGDIR_SIZE is too large for cpu_vabits, KASAN_SHADOW_END will
 	 * overflow UINTPTR_MAX and then looks like a user space address.
@@ -327,6 +329,9 @@ void __init kasan_init(void)
 	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
 	local_flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized.\n");
diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 03666d790a53..b0c465f3fbf5 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -141,6 +141,9 @@ void __init kasan_init(void)
 	u64 i;
 	int ret;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &base, &end) {
 		phys_addr_t top = min(end, total_lowmem);
 
@@ -163,6 +166,9 @@ void __init kasan_init(void)
 
 	clear_page(kasan_early_shadow_page);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
@@ -170,7 +176,7 @@ void __init kasan_init(void)
 
 void __init kasan_late_init(void)
 {
-	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC) && kasan_enabled())
 		kasan_unmap_early_shadow_vmalloc();
 }
 
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 60c78aac0f63..1e1c10467a2b 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -111,6 +111,9 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL_RO);
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &start, &end)
 		kasan_init_phys_region(phys_to_virt(start), phys_to_virt(end));
 
@@ -125,6 +128,9 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 7d959544c077..9c5cf2354c8b 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -56,6 +56,9 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
 
+	if (kasan_arg_disabled)
+		return;
+
 	if (!early_radix_enabled()) {
 		pr_warn("KASAN not enabled as it requires radix!");
 		return;
@@ -94,6 +97,9 @@ void __init kasan_init(void)
 
 	static_branch_inc(&powerpc_kasan_enabled_key);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 41c635d6aca4..ac3ac227c765 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -485,6 +485,9 @@ void __init kasan_init(void)
 	phys_addr_t p_start, p_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	create_tmp_mapping();
 	csr_write(CSR_SATP, PFN_DOWN(__pa(tmp_pg_dir)) | satp_mode);
 
@@ -531,6 +534,9 @@ void __init kasan_init(void)
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
 }
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b5..6961841daa12 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -26,6 +26,9 @@
 int kasan_um_is_ready;
 void kasan_init(void)
 {
+
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * kasan_map_memory will map all of the required address space and
 	 * the host machine will allocate physical memory as necessary.
@@ -33,6 +36,9 @@ void kasan_init(void)
 	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
 	init_task.kasan_depth = 0;
 	kasan_um_is_ready = true;
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
 }
 
 static void (*kasan_init_ptr)(void)
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d216..d7e8c59da435 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -343,6 +343,9 @@ void __init kasan_init(void)
 	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
@@ -450,6 +453,9 @@ void __init kasan_init(void)
 	/* Flush TLBs again to be sure that write protection applied. */
 	__flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
 }
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173a..4a7b77f47225 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -70,6 +70,9 @@ void __init kasan_init(void)
 {
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_START -
 		     (KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT));
 	BUILD_BUG_ON(VMALLOC_START < KASAN_START_VADDR);
@@ -92,6 +95,9 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 01f19bc4a326..dd963ba4d143 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -40,11 +40,17 @@ void __init kasan_init_sw_tags(void)
 {
 	int cpu;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
 	kasan_init_tags();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
 		str_on_off(kasan_stack_collection_enabled()));
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-4-bhe%40redhat.com.
