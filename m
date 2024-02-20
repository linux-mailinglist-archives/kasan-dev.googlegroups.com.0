Return-Path: <kasan-dev+bncBDXYDPH3S4OBBR5U2OXAMGQEGQUX3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C58285C1E3
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 17:58:48 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40e4303faf0sf4217875e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708448328; cv=pass;
        d=google.com; s=arc-20160816;
        b=lhGa+Lph1JXd15CJw9VZqH046RGjaTgtv7OHYdpFU+FmNneqvGp4+paHvxqg1bgXyQ
         Mpstnl/cLV5NLq5MnmM+aohdjTHYlTyT4MyWIh6mrACZJ+pbaO+Xz1UeS8FoW0s83tHc
         fo2w+BiSiRGNC4I5T7h/MAOkDfFmPxPuoaLpyh5MBRbTAdxgrXaDtv6FBEg//c2JEBJx
         /RDIW25oQGionYbdrYICCk5EKEnLPLtkbXK9DCC5d0VOtxGcpNNCFwqaRGkETcY1WjeK
         IwGCW7fq7KKn/khpH31lWQ6fTAorUv/iDEp7QiIeMKLn5xWfwJZ+KIVRrZefSbV/Y9HZ
         /jug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=upaFyLA6K2mLcUOovKSYNJ7GmmOn7FLUTMGTK4o9o2I=;
        fh=m65yvKM32pK6kGGX27R3Iq9zv6yd0VIqcKEf7lXwTik=;
        b=yWU5ZMqraL/Zb12m46bB24K4f+5Ur90zqWRMsPtPHwFUdTV7AJ5URTM9zsUPWyYPFN
         GgEXbPSOmAkD6RHs+P1UVXTsS+SS6B0gPTGYxHNnBqPC68QNGNoXVfNiSGq/LL5TuosB
         R2aV3D8MWB/6taeilJuJai6s3IWeBh435d0Wnd/n9/+NSkQ0rw4t24YVdFIeV88lizur
         uKZXA/qAy3lM3IX54wqY2Afn2XUbijXVxWlqvUJNHzVcho7i9UjcHx5JHYEk8vklNZ+Y
         eFRwz0dAbnTcgecJTMU4KIPifUFAVU0KprLd5XwEEI3yVx0wJwKJq8ZXwFlf4OzTQHzl
         9S5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708448328; x=1709053128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=upaFyLA6K2mLcUOovKSYNJ7GmmOn7FLUTMGTK4o9o2I=;
        b=M1sbn29O63NXi2G90IHeDge2zz3kfiZGvZ5B9oN1NXx9MFNmN+pj/LdXICfl/N27PW
         Ru/GQRw3YpRiaur3p0pTiwpdDInwg17mmt5rvVYWoSYug1OmXhfYgZvua4bp3A6LSUxk
         C12oFrglVaEJoX+nHGBsRl2IXVgIOjD9YDaPy3HJHvzjaaStGwtUeSgP4CIAQceO+EDf
         FCKpB96mVgqYpbwMiB5Pss7hcUxGxAEWzxpOfgHPqzi8vnn0JI6jjyCFbYafOOmOarki
         esFamVhryeOVn9fX1B8CCFJtl3OYbXCIpbNvpXfgmnERk4IOADJad9IYvOtmLHgX7cqp
         K5cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708448328; x=1709053128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=upaFyLA6K2mLcUOovKSYNJ7GmmOn7FLUTMGTK4o9o2I=;
        b=LOItSlcwMsdrgE/4SMNmIPAeE+YvmpIhBw7NnYFnyGcRYsRM8MM7wsaojLWWsZsDlL
         4K9notLh1SZe8QhrMVQVpPQp/wAUtKqzaQH7c/WpyQHOUEdeHUg8cmtYbGSY+B4qcPhk
         nzMGB8iolNZSW7CeDwk3VNQODtNja5zJYqv1Sgvol7J3EfGVMs9cFB776/TWHMrYVKLt
         qVvLXjRelt68S8PYata+4+DpvUcMWYNSMyJtpEQzxpCXuY5uuUmKhofkWfyemKpht5uJ
         ZCkLXfRlTRbpHjuvjwKHuKuqcKXYURayqYxCCbGVGLYRYUI8mupwYlhIa9t5QmOXTgYn
         Rf+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdhOGWThlAfb9iBzcIg8Csmep7gd4no8IRbIc3jRoA/nM+hEkdNOi8CKalwWlLA6p+Vn52FOqTEDr34dKceJGf7/ZpqWC3rg==
X-Gm-Message-State: AOJu0YzTMXklnMnG1nkuTC/LkckLGzBjqgliBibnqZ9n2sk7Z3URaBwH
	dSUcZjpBiU4+XdpJTB0eUa14oVgsuqWQOeEO3gfyF59OEP+GjAlC
X-Google-Smtp-Source: AGHT+IF9I47+RHxysPbDtvdtgiO484FqrX/WgNUxEaalWIW45/UtmwkpzBUKKNMZD8LArDn7L8QncA==
X-Received: by 2002:a05:600c:1d9b:b0:412:6fe4:6356 with SMTP id p27-20020a05600c1d9b00b004126fe46356mr117126wms.0.1708448327633;
        Tue, 20 Feb 2024 08:58:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d45:0:b0:33d:806:1b41 with SMTP id k5-20020a5d6d45000000b0033d08061b41ls1461978wri.1.-pod-prod-08-eu;
 Tue, 20 Feb 2024 08:58:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUkuem26xTtUWSNbhJLsOafYC6TlAAS6lTXGDeiKbCnOMDOHsLAtqmW/dcbqvL/SD+rIJJ/P6/q1VY9UyjWNE3yoHgr/udZcqbLsg==
X-Received: by 2002:a05:6000:12d1:b0:33d:3a85:a5a2 with SMTP id l17-20020a05600012d100b0033d3a85a5a2mr4886943wrx.21.1708448325831;
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708448325; cv=none;
        d=google.com; s=arc-20160816;
        b=03LU2xh5WDrGjXPSd0yqcc7TM2R9KcPKGkfjG0w9JmnI/PZ7GnWITgsawH0a7v76Xx
         MaHdG0ghIFcPgCC/29jtGiT+qsoA2BKqv9/xQNZszauB023AN6MCxDzLG4TXzH31tsyA
         TLNZvgo0EgFvbuuVUCxmGKg0xvZIH8DKaBZyi3a5NABqYI0sTO/Vf0aBRbLZWJ6pl3JF
         ctzPS94RwkSiEWNbfYDy70pTj/QiZ1hvUZqS7e6geBb8vppiZlWL7hA+jQjctSB47EvI
         LcRgOpwfjPIp+56da/ZBhAwHzF/CBQp4kFsAnxV+XOB+SF9An1ZO8tcF/nWJvKd2T3nG
         PoFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=bDwZLyEk1WMILC8wJ4ZtAG5w+ulImAgRHCRAxEjy7QI=;
        fh=iiw6AxRn834Rp3X3mGFcQcmYTlAscmlxQxZZCAoI+ts=;
        b=rhsVCjVbsZ/IcAXO6GaROUVBEVnM7yxPpCFmxT5kuavwVxZ9rCxweejZGuGe2YMeTx
         V/a1+YObT1h18YG+XQUqcli6d5bR7SKDUFDIfogHGgnqPibQJmWpcSrWEcDIvJh5OvVE
         8IFBmFlbMgAPhF/ZC3iTy7d77iMZw5ObLqLgTuguu0KT6rtY4NzBM9gqXVemgSVuWF4G
         4vdp0TR2DyqIAnMPFsjOsfJDXKpMgEpQ6jjJHgL8i7OsghZxxRxr/m5e86FLzunaOBVb
         ggXqii+bBBwCQ638LAF9fl1kCekhGxmlGjosn3REMXxi8Q4AZoRBEm8MjYES3OHNNkuV
         PO/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id g15-20020adfd1ef000000b0033d24322b09si397577wrd.0.2024.02.20.08.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7BAC91F8AC;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 578FD139D0;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CEsVFUXa1GVKXQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Feb 2024 16:58:45 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Tue, 20 Feb 2024 17:58:27 +0100
Subject: [PATCH 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>, 
 Xiongwei Song <xiongwei.song@windriver.com>, 
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3299; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=8dSL5GfjNj31WZBzU1RArK2AdDIYjJIAED64yK7aPeY=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl1NpC+Ron5uAKKATthXFJII/xHLgqduJBWbRQt
 JULEgGEAwCJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdTaQgAKCRC74LB10kWI
 mt6zB/9ix1+cbRLwfxeQ4PhmyOPOXIy8AuaLRA62hsETFxjPOeumiQBXsvdbnzwsuTrbTPtKCkZ
 d9K8yRw2rpCG80loeAT/9uGKYzkw3j1XJrIDpXnpsp8/Jtb8zF38E0za2jDekAKVKziUs+xQQ1c
 VGAgxP7oyKW/Scrkzja41qVLuoQIjHK0k+XLXLFgkgs+iCPInGvRs4Nw50YuoG4okbZHICuchYX
 EJ07EGSqae4vCKCv3jipCwptC1gLJZ1gNSnfYu6Xla4IZmsWsXnVgCegTbcY8e9LdmySCBYecUL
 5FttxJXT+6E5QTHUN3Tw59fKT1yFq1PkGQFvhgv0TDslB5er
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	 TAGGED_RCPT(0.00)[];
	 REPLY(-4.00)[]
X-Spam-Score: -4.00
X-Rspamd-Queue-Id: 7BAC91F8AC
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The SLAB_KASAN flag prevents merging of caches in some configurations,
which is handled in a rather complicated way via kasan_never_merge().
Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
for KASAN caches in addition to SLAB_KASAN in those configurations,
and simplify the SLAB_NEVER_MERGE handling.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/kasan.h |  6 ------
 mm/kasan/generic.c    | 16 ++++------------
 mm/slab_common.c      |  2 +-
 3 files changed, 5 insertions(+), 19 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dbb06d789e74..70d6a8f6e25d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -429,7 +429,6 @@ struct kasan_cache {
 };
 
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
-slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
 
@@ -446,11 +445,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache,
 {
 	return 0;
 }
-/* And thus nothing prevents cache merging. */
-static inline slab_flags_t kasan_never_merge(void)
-{
-	return 0;
-}
 /* And no cache-related metadata initialization is required. */
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..d8b78d273b9f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -334,14 +334,6 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
-/* Only allow cache merging when no per-object metadata is present. */
-slab_flags_t kasan_never_merge(void)
-{
-	if (!kasan_requires_meta())
-		return 0;
-	return SLAB_KASAN;
-}
-
 /*
  * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
  * For larger allocations larger redzones are used.
@@ -372,13 +364,13 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	/*
 	 * SLAB_KASAN is used to mark caches that are sanitized by KASAN
 	 * and that thus have per-object metadata.
-	 * Currently this flag is used in two places:
+	 * Currently this flag is used in one place:
 	 * 1. In slab_ksize() to account for per-object metadata when
 	 *    calculating the size of the accessible memory within the object.
-	 * 2. In slab_common.c via kasan_never_merge() to prevent merging of
-	 *    caches with per-object metadata.
+	 * Additionally, we use SLAB_NO_MERGE to prevent merging of caches
+	 * with per-object metadata.
 	 */
-	*flags |= SLAB_KASAN;
+	*flags |= SLAB_KASAN | SLAB_NO_MERGE;
 
 	ok_size = *size;
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 238293b1dbe1..7cfa2f1ce655 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -50,7 +50,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
-		SLAB_FAILSLAB | SLAB_NO_MERGE | kasan_never_merge())
+		SLAB_FAILSLAB | SLAB_NO_MERGE)
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)

-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220-slab-cleanup-flags-v1-3-e657e373944a%40suse.cz.
