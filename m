Return-Path: <kasan-dev+bncBCKPFB7SXUERBN725TCAMGQEB3HR6SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EBA91B227D7
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:10:16 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-709dda08151sf7645016d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:10:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755004216; cv=pass;
        d=google.com; s=arc-20240605;
        b=E8JbVd2sbTmqKJwDa1RVuQvFq30GXtYcNqL7WUDeSRhX2FICWMJBPndHbLz1bq3wF6
         Aay8BVecWpDJS8ROLytG3K8yurneQRCFLeI8cyMOiq52CwyhnYFBUiTqAHArgHecmrBm
         n8p5t465vI763z+uKKiNXf5soqJ1GnjDVHtfy8VCDZ/xnt44uZiIjzpLUB2rQgY4B06c
         iwV1MM8enfwNjI3Qr1UnrdTJqPHaxaDokeUnRC3eGwQJrX85C2V1Ix7YrwAhXukTyCw3
         /9JLnDxPcNaYslru/KVW8JJX7uubaNRYqU/m+21V8/Xh9GOMe/9UN8pWREyHCqgvfXf8
         dYdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=la2o4PI35N1Hud8qQn1G+kS82wQMv/c05vXUbEwT5Pc=;
        fh=uCzRH6e6/83BxX9yVkEF/PzikmLB41zh0yfHj0RYK18=;
        b=CTuWhMHtn4tmAcmrcgTCasZbSac2VbmCEgf/RkjBPaVkeU5lc03/G7nemSWkyWNx90
         kHrC//qI06PwueCV1XA5mcmTdSxZXIBpD2TJXkqujFML3aBSjzPuBiXLZXeQAe6HWPDn
         5xNoknAqrFXHK0IlsOS0wkcSkId/LTQLHx0CW7U2FJ1fM8+fqiSqi2LXYSJRxf7dWjOT
         UNlYzhykIhtVrblqXzSP+yaJDlvpwhoDfF+2vl7k77CDycRdSMSFzKMugzPs3xv45xjk
         l9OYS+gfATK0xcIqzMSxYtoOFCaSjPhXZpYEipWuAWJX4QuLeRwevaFNx79/ZwMli9Zk
         p9CQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GNi+pwJb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755004216; x=1755609016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=la2o4PI35N1Hud8qQn1G+kS82wQMv/c05vXUbEwT5Pc=;
        b=UJD//Dcq677lBXqMKmYcLO68otakeyQOvSMpy4wrobTL+i8uq6K3FQF5gBVh79civo
         RI5DhAxozX/dQPSOamZi2TNlNZVd3rtlrnqKyvgOsqAZQ6SemirGbBW6X1d5OlfKarqy
         YJyCaW/7D90f23T185c1PEDelOl0RRNw9kvj1zxThDYtr7HJm8x94AewLJrXYsoOtcsl
         SRvwitftzppox22H9KXxp303sJHbj4j3wwSRKXZUFcAlClpry0g5zyRT37zWQEt9G1MX
         fLYuaJK5mpbdJy3C/5zONgj6fcsx26MWytuOKs4u0kKObUpNCGkTVIPzCVnFZH0aT61j
         SUrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755004216; x=1755609016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=la2o4PI35N1Hud8qQn1G+kS82wQMv/c05vXUbEwT5Pc=;
        b=mDcqskdGmJnsLMGmoYoHDtoDjkoF89urQpFCFVHRKigM7uhrdpzrt5njaQR1EnJBdO
         PuPnjlWVVzASjmYNIko3MMZQ5g9UaT5NfgD07xQAndzpjv6YZVXbeS3YLCwIu+RM4HCa
         2ad91r9OBQfpuIvzO5ksECjCnIQ54IENphQXW+ZiJF4poHsKJWSYIJZ6OZQgVw9FodZ3
         5pzscCGqdoKP1tUrxQYdMdSKe8X64RjzRHUxDbdOkhoK/pISwY2w4qWSgYHIOSeguDYG
         vRBo7GF2ykO+2d7rVAtbXKTgzI46oSyNcPmMK1ot8nAvlrVSBSb5+Y0gpijBv0klkNJ1
         rwmg==
X-Forwarded-Encrypted: i=2; AJvYcCV01lbwW1AggfZKPeQTF2xjtaYfyk9vwagsizkV0Az1J7EZXwWXSMQUaCodYgj7jFDbNsUMEQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyo7KSoe8gbySnrFmCJoX2jEVz6bNJtme+/l7pyoztPFXPK2tpH
	hB6OY0Q6i07LVxUF4E/ttihZijBQdkHmjMPfakVza+OkU8N4ZdKUTP9/
X-Google-Smtp-Source: AGHT+IGveH8oqhjYnfIX+g3HAjLL79phLf8TUAOeQHG1s7xgntviufA+VBBZco+TPGKrtib142WR8Q==
X-Received: by 2002:a05:6214:21ef:b0:707:3a63:136f with SMTP id 6a1803df08f44-7099a27f6f0mr201291826d6.4.1755004215396;
        Tue, 12 Aug 2025 06:10:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3wyvzxpiNlpu7oRi7kCvDCN5W32jqULIN2DZ0q8dGzQ==
Received: by 2002:a05:6214:3315:b0:709:ad61:708a with SMTP id
 6a1803df08f44-709ad61746fls34173876d6.1.-pod-prod-08-us; Tue, 12 Aug 2025
 06:10:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+9L6mYOZiqQ4rGJTktpK+v4Oo5B5NAXKcgTIrCM5Onds9+kNhGmlXQQIeR56AWepMH4RcDuMfv6o=@googlegroups.com
X-Received: by 2002:a05:6102:c94:b0:4e6:d784:3f7 with SMTP id ada2fe7eead31-5060eae4dacmr6003941137.15.1755004214092;
        Tue, 12 Aug 2025 06:10:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755004214; cv=none;
        d=google.com; s=arc-20240605;
        b=QDbqDopScyizI4iaWd4pjhToyxhrkkArfb8qk6lE5iZTm2IV03of1n7F+tWg5yTlH4
         34T+A61hc2oFI3yXv0gNmLEHhCsSrmafYm5Kne/Z/tQzhtC3dMMlqFZbsYhHt5wxZTgz
         ePl78NcSYean16TUEK/prNy37ouEjpYyNbQj61pnqfB9emTsfHSaqx1Bpx5dEW1PNZvw
         bJmAPKnBY7rrwscVhxCsdPKedyqcqsHndqZ2AoJbDe89zWTHOHkRSKyJeM2wVZJCT7ix
         EnbzEslMHGp6PjDVWB3LIUkSZFLk2gX2vO5BkZDadexrdvHSygmHsK1P+Kx6eIdL00yX
         3XKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SMz5O7u0akvXjVncCick/hCZpGXIHb0iYHhbJTqmUJE=;
        fh=tJzQ5qxkJm0zG4QpcVmXzoBYu5DFFVue0Z3QtfeLqEI=;
        b=juZi8xAhqaDGmD4qrgGHAHkIyB+0IdjZBeiDyXvyubZJJxxB717PFKtvNaziSceq/J
         DaRlDZUZMlQr5TaBM0Sfo52rqg37gQCkgZpKBKsHSFPb2VIjIPs/or3vfUic8Lek/k+K
         o1rfvqef0eTSLiNdgoXyKDIITZc+oz0VLRU5FB4ef3726wnSppe0uGaErnZmrWT2q01m
         CNBZA3qrU1n/sG6xAegBf+G/O7ECto6uLz0xtTPsHEazUzhEdo3/FW6+fwbRD7NaCN/c
         mLrs2hw1V/79mUV4lTCMGKOsePRwNaDxneJSgByhaGO/qRyMjo1oo2qhYgSBZRLyWYm2
         0XZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GNi+pwJb;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c3b7ba9si5627476d6.0.2025.08.12.06.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:10:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-365-087PP938PFqZR3S46zQ-3g-1; Tue,
 12 Aug 2025 09:10:10 -0400
X-MC-Unique: 087PP938PFqZR3S46zQ-3g-1
X-Mimecast-MFC-AGG-ID: 087PP938PFqZR3S46zQ-3g_1755004207
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1F303180034D;
	Tue, 12 Aug 2025 13:10:07 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 499F41955F16;
	Tue, 12 Aug 2025 13:09:56 +0000 (UTC)
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
Subject: [PATCH 2/4] arch/powerpc: remove kasan_arch_is_ready()
Date: Tue, 12 Aug 2025 21:09:31 +0800
Message-ID: <20250812130933.71593-3-bhe@redhat.com>
In-Reply-To: <20250812130933.71593-1-bhe@redhat.com>
References: <20250812130933.71593-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GNi+pwJb;
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

From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

With the help of static key kasan_flag_enabled, kasan_arch_is_ready()
is not needed any more. So reomve the unneeded kasan_arch_is_ready() and
the relevant codes.

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/powerpc/include/asm/kasan.h       | 13 -------------
 arch/powerpc/mm/kasan/init_book3s_64.c |  4 ----
 2 files changed, 17 deletions(-)

diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index b5bbb94c51f6..73466d3ff302 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -53,19 +53,6 @@
 #endif
 
 #ifdef CONFIG_KASAN
-#ifdef CONFIG_PPC_BOOK3S_64
-DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	if (static_branch_likely(&powerpc_kasan_enabled_key))
-		return true;
-	return false;
-}
-
-#define kasan_arch_is_ready kasan_arch_is_ready
-#endif
-
 void kasan_early_init(void);
 void kasan_mmu_init(void);
 void kasan_init(void);
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 9c5cf2354c8b..c1b78a9cd0a9 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -19,8 +19,6 @@
 #include <linux/memblock.h>
 #include <asm/pgalloc.h>
 
-DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
 static void __init kasan_init_phys_region(void *start, void *end)
 {
 	unsigned long k_start, k_end, k_cur;
@@ -95,8 +93,6 @@ void __init kasan_init(void)
 	 */
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
-	static_branch_inc(&powerpc_kasan_enabled_key);
-
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812130933.71593-3-bhe%40redhat.com.
