Return-Path: <kasan-dev+bncBAABBUHPXPEQMGQEHRG7J4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E437C9BC79
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 15:29:38 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-47910af0c8bsf37680445e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 06:29:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764685777; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z+rxuaonoG0sq7xKClaFSJnAhHOIf7AaH2f9PdB7JpB1Y6WIYZwKjG+WYhQPazZYDj
         zbXqN5/kHIDmPZC8eJhcx/Xfqs9goZQvYpAc+YfPPNer4rdhwSGllR2wef4o5Z6HcOMN
         WfRQlxM3HYwwed4uTusv2+fdtJ8Va/iQ+cJZyiqIVDPbSaPfMzPb3RRtEIOtE5RuOdW4
         Htm2ayMzcWRluEqW7pThskXF7QGBVZw6bPVjsmngValxtPcRDIM2I5+S4Wux66/2YJAV
         vuN/4n8X0woNPkeeBvumj7wgMXP7il09PrFpW9y7lRhV/WzCaa6yPBjRLi2CNUCeAJlQ
         aH2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=pnoGHvMbMunAtz4f0f7K7FOoDJ+9nMiClljwIzZ1fPg=;
        fh=leB/faClz6eZfBpToEWABLKzHpoTBI+rSHJ+dZGjIw8=;
        b=RsldEQ+i+eZEmrrUOg0jFtLVsXaZsHnR1PIeZtVzl33V5c1y673PMp+X4znF5UgZzM
         D9xoUpuGsxiD6/Ku4dqD5dVi6piP35YwKksFhQk3ZyrcijfRgl1NS8YM6Jn4LdqfA+rd
         cwHp13Ydgur7IXWy0yMB/et9EkihOntq3IBUGhpBHfo2eZtDC92dckpFiNRv0zRnsZhT
         yzJuvfXTwsGRT0qQN1wSxTCnxhXQ7VAbfx3jms5BjsSxRixDnRI0zaFYEVkKlwWMSFMy
         0U5IeCKR73lIzL8/C65FR9mCtWYbfS+XEsBbjVmyVNGeaP7n2sHoWntmvMw1ueppTmc1
         V1BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OLO1VZQq;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764685777; x=1765290577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=pnoGHvMbMunAtz4f0f7K7FOoDJ+9nMiClljwIzZ1fPg=;
        b=js+PA38eaY5cvtuukP0J3lDEN6l5Yjytd5HQ/QkkM/T6315tdKypU7f5FjATmsWEYG
         GMevve7kNAreC71GlOlKvuLZ/GVVprVNA2u3RFR1qOjhmMh5VD8dSyVBVC0a79oopxs1
         cGN0uwCHZsIFoBSWXKm+21t5IiPJM+pW+IZxuBRYJagfDl4ft1h5kcJb+QvP6UZCkKxc
         p67+rOfGlF8MCP11Qqye29uISgx0NsH0i/x+FKO3b22OOANAu4rBWjjdeYTx7tWeDns6
         VhVTYWfXjgJlgR0pT4wzc1jbMj3l09ogd3eqKLmurSthKa4tC4Bab79PK4uL3vewLCwh
         i5Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764685777; x=1765290577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pnoGHvMbMunAtz4f0f7K7FOoDJ+9nMiClljwIzZ1fPg=;
        b=ZR0ek6KxufEWEm0V+cvyEi81xzvdbZL6AvbMnkVaWcsNya65mgmSLbHXIe7+SegVJn
         ib6a+2H5fuYcvouQvwkI2t4IxwOoJTn0VR1grGi2dgxPZUmmDEf7OBfEz8uMaDlyfaW8
         6KImI1PtYGjxnG83kQBf3Nys5Z8ubPSq3RzhvYP9lmz21l4WVPplClv97iyzNckr1cQ8
         lnz2ODlVn7/LvjXFJz3szOiIWQl2XHikuE2TluSzv0lXEqSwK/m8pVhdDSu/DBv2kZJT
         D7l8w7r8nLtHXVQkjSu9fj76qBtxD8hcGPeoyheeWh6SiPCaD0+F58tTCqe9Sp83ugfm
         UXVg==
X-Forwarded-Encrypted: i=2; AJvYcCVX48svmZMvP2PnAVWA8TNHRVTb64mYwsmSHyOyfnIAnHA8pLWtZMltlEomiQpSrd9lseDrvg==@lfdr.de
X-Gm-Message-State: AOJu0YxDXxJtARBOM2t9bnR6fHgsfBy1XzZqb19tm5M+M6ZVAqoyl4Vh
	NX3q0MOLOZF6EimNkDxAqOfGsfFRkNTBTIrV5YODm+nZJtIbBd9Eo61H
X-Google-Smtp-Source: AGHT+IF8cKbvFfLvq2Kd+yky3Rr3/TZU3520V2wFMr9lzFvWtSTLOfQFyr7u7AUB/DsDXt2qzq1odw==
X-Received: by 2002:a05:600c:3592:b0:477:9eb8:97d2 with SMTP id 5b1f17b1804b1-47904ae0689mr364133725e9.8.1764685777475;
        Tue, 02 Dec 2025 06:29:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bNRf7jFAq+GkOUr6Cu3m6XdaSp2pit5C4Y7sUulTV7bQ=="
Received: by 2002:a05:600c:1d02:b0:477:980b:baeb with SMTP id
 5b1f17b1804b1-4790fd87637ls47595965e9.2.-pod-prod-09-eu; Tue, 02 Dec 2025
 06:29:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWklBqjRnIPIdSQudtk5BOE3wKcfrso6DlUqcMxXatywiApuGQfsVnWiueg8lcWzLZep1bl1imWuy4=@googlegroups.com
X-Received: by 2002:a05:600c:4e8c:b0:477:8b77:155e with SMTP id 5b1f17b1804b1-47904af05b5mr327468825e9.15.1764685775327;
        Tue, 02 Dec 2025 06:29:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764685775; cv=none;
        d=google.com; s=arc-20240605;
        b=ZDcJuxODhkoayEAKSGRSFurGSMMdDCtk5bQRG57lJC1RImH4ZRmt9MD3e8HUsGBm/+
         WHEIs7hpd0Zo+BbBgzny4c5qTZMqmdRm9SOUxq+ZKFCaW/MeZ3l/FHG9U4grlQ9nNBew
         i1PTGXWkycESYEUUN2d8tDJNdZar51giH+CIdERFOFmNg7gUjjPtYgeAS8n6mUIyHvMg
         3s6c1xMybWCJO20QFXHx1F8mhu0oBJrhjuAWA/bQwYo/xQikByaJ83//61Lclq4DAUx3
         LQf7n2PLQcP9M87KMh6ZghlAipRj0mfMWKgXR3RTQ3tzD5DHpAQrPlBE4EE1diM/zREM
         LBNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=N+YMyXrUIDlvdwT88k+hzchw//5574kLYOWxbowQd+Y=;
        fh=jpMYZ6fr+9g6uUSWMvUk3l39o/GWWKpHm/abw8blV3U=;
        b=HA3yhATWkFsw263PGKxPGn7xg/xJ9P1vQZge5U0WoRiY3Os/NucOoyHrkoiVyezJv4
         s8V3JusBt7914xWEiDeqhtNEebzIvx8GEATppMdH1lZ8vqw6VxwMAXx7j6SKQhzJTweT
         WpSemIdhZVMyzKqhJOfBcEulC/2HPObHjUyF7b3fEuWGjindtzQG2rAS1niM7oGTuO+S
         EYLdW4WYG3PUF49Q7QtFmNKGsaRzAqAaUEM9QsorGeXXZkD/5kH1SpxNeZGcaj8W0HKh
         IAvyEKWAr/8lU5+UJMUX6qBm57Al3l/ZEUKRU0L7nCKai5If9AT+Q02tOHnq1U90/9B+
         u2eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OLO1VZQq;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47926ecad61si159725e9.0.2025.12.02.06.29.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 06:29:35 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Tue, 02 Dec 2025 14:29:28 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: [PATCH v2 2/2] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764685296.git.m.wieczorretman@pm.me>
References: <cover.1764685296.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 87d59c9c44924853cf81bc1e8bd9a2df71af726c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=OLO1VZQq;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Use the modified __kasan_unpoison_vmalloc() to pass the tag of the first
vm_struct's address when vm_structs are unpoisoned in
pcpu_get_vm_areas(). Assigning a common tag resolves the pcpu chunk
address mismatch.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Revise the whole patch to match the fixed refactorization from the
  first patch.

Changelog v1:
- Rewrite the patch message to point at the user impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 mm/kasan/common.c  |  3 ++-
 mm/kasan/hw_tags.c | 12 ++++++++----
 mm/kasan/shadow.c  | 15 +++++++++++----
 3 files changed, 21 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7884ea7d13f9..e5a867a5670b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -591,11 +591,12 @@ void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
 	unsigned long size;
 	void *addr;
 	int area;
+	u8 tag = get_tag(vms[0]->addr);
 
 	for (area = 0 ; area < nr_vms ; area++) {
 		size = vms[area]->size;
 		addr = vms[area]->addr;
-		vms[area]->addr = __kasan_unpoison_vmap_areas(addr, size, flags);
+		vms[area]->addr = __kasan_unpoison_vmap_areas(addr, size, flags, tag);
 	}
 }
 #endif
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 4b7936a2bd6f..2a02b898b9d8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -317,7 +317,7 @@ static void init_vmalloc_pages(const void *start, unsigned long size)
 }
 
 static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
-				      kasan_vmalloc_flags_t flags)
+				      kasan_vmalloc_flags_t flags, int unpoison_tag)
 {
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
@@ -361,7 +361,11 @@ static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 		return (void *)start;
 	}
 
-	tag = kasan_random_tag();
+	if (unpoison_tag < 0)
+		tag = kasan_random_tag();
+	else
+		tag = unpoison_tag;
+
 	start = set_tag(start, tag);
 
 	/* Unpoison and initialize memory up to size. */
@@ -390,7 +394,7 @@ static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long size,
 				      kasan_vmalloc_flags_t flags)
 {
-	return __kasan_unpoison_vmalloc(start, size, flags);
+	return __kasan_unpoison_vmalloc(start, size, flags, -1);
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
@@ -405,7 +409,7 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
 				  kasan_vmalloc_flags_t flags, u8 tag)
 {
-	return __kasan_unpoison_vmalloc(addr, size, flags);
+	return __kasan_unpoison_vmalloc(addr, size, flags, tag);
 }
 #endif
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 0a8d8bf6e9cf..7a66ffc1d5b3 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -625,8 +625,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 }
 
 static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
-				      kasan_vmalloc_flags_t flags)
+				      kasan_vmalloc_flags_t flags, int unpoison_tag)
 {
+	u8 tag;
+
 	/*
 	 * Software KASAN modes unpoison both VM_ALLOC and non-VM_ALLOC
 	 * mappings, so the KASAN_VMALLOC_VM_ALLOC flag is ignored.
@@ -648,7 +650,12 @@ static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	    !(flags & KASAN_VMALLOC_PROT_NORMAL))
 		return (void *)start;
 
-	start = set_tag(start, kasan_random_tag());
+	if (unpoison_tag < 0)
+		tag = kasan_random_tag();
+	else
+		tag = unpoison_tag;
+
+	start = set_tag(start, tag);
 	kasan_unpoison(start, size, false);
 	return (void *)start;
 }
@@ -656,13 +663,13 @@ static void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 void *__kasan_random_unpoison_vmalloc(const void *start, unsigned long size,
 				      kasan_vmalloc_flags_t flags)
 {
-	return __kasan_unpoison_vmalloc(start, size, flags);
+	return __kasan_unpoison_vmalloc(start, size, flags, -1);
 }
 
 void *__kasan_unpoison_vmap_areas(void *addr, unsigned long size,
 				  kasan_vmalloc_flags_t flags, u8 tag)
 {
-	return __kasan_unpoison_vmalloc(addr, size, flags);
+	return __kasan_unpoison_vmalloc(addr, size, flags, tag);
 }
 
 /*
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman%40pm.me.
