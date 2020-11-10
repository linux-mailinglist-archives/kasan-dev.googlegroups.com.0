Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGVAVT6QKGQE5SOHSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 285422AE2BB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:40 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id y62sf154106pfg.13
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046299; cv=pass;
        d=google.com; s=arc-20160816;
        b=zFhlkYbInOOm2Ms9lkbd/PSqDZlLo9h215ZURFosi6qV3oy3cqm3LQUy1SpJcPn0o1
         j7fERLe036tbiLQleTDvyCTgYkWS4M3W4d7M1UbnhDeCNW4rmVYdeAG37nkwiHDJSH09
         78HsPGvedNDgpYVzxpQIYV1rFngbuBjfFp3Aghojp6JkwxWQHJxn9z5XSkPa7PK5yJm3
         5yIpSjSbEVqaXPeVOSQ32NtM9Oj0ydEW8tNLkGYM7BQs6iED1pqhXgzr482tLcGe/9Rf
         zcFaOxMxCLcTPyj9YO9fs0Zgph3vy0d7+9XOIQk23wSnLfX1n3n6UDDvvC4hI36JcKd8
         +FXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vRWGaYq62J/G0aZht1m31f59j1KlNlTBPMrfNIUAvM8=;
        b=wDC+PYRzHsHLUuYFCW9W07fmstKSFDIGxeAJIZ0a/d/woraBeU5R3Pqq47Kgce0i7+
         gkcAC9o4Vv+kjoW4e4kQMkV8jPwP1Dcw9lFLOg0XDmpxh5nL55hpdii/mDZOvZGS3Qn6
         7Q+9lkAOfEZyOeXtbcdjZRKbBNHbw16q6iJ696dChb9GgjFt2sUWw8uzKLcGInH4UNSV
         ipgHJt8kvYm0VeGmeY32TT928RqMYqCcFvr0mmxLvh7LzpBGXmp3i2SCiF1zstUbHH08
         khceSE+tciVkoZBQwVzY/U3tukYYoPmy7BXkoLF4c4swohWQwv9xWpuePeW+ZkfgR1y4
         DGIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eiTOEKy/";
       spf=pass (google.com: domain of 3grcrxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GRCrXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vRWGaYq62J/G0aZht1m31f59j1KlNlTBPMrfNIUAvM8=;
        b=YeNR5cd9v4k1tShGYPvXgcg+refbpQaLWuk/CJ/qV/OMe3eCNCb6ftknZOFgDvCjAi
         hBerheSAthZR1CCZYmL1FxAeEk71tAIePkRnJ4dSnoWzdJAsaO0JZH3awuJHvBF7Zqlw
         LLyzOcV+Zjl9+TNafsmySl4HXpCO/KKLUyIaqcQIVN/p5G+u6B2kHn8aYG/RsAJUgNqm
         sqpXzrefqGfl/2K9hJB9BaLQyNQJtkwCvhcbYiOAAT3eRH+Jg1gyAhepxHoIe7L12KpZ
         UpN0P8Czdb/RE9tFzbtr6EXtZlksy5zNR+F5lh6r+pKrZ1bA8ilhnRFe4ALo5nRX/hw+
         k9Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vRWGaYq62J/G0aZht1m31f59j1KlNlTBPMrfNIUAvM8=;
        b=krICSbxmMcOji5uqveHQM6i8513me6IcB0AIBx/YWqGTuSzC+reOzX1L39hm8N2AL7
         PTxi2+U996OqhfdNi0iKDqSv2gbZRJeq8mWL0q2as9TQ1Tzqp7LpnUw20n1KHBn+upNu
         9QID4D65N5gl6huaLbCHHUaRbJUKGDxviOR4Qh7LIw7Pnam0/3UOD2V5fjO3UiNjq000
         L/kSi5DiQHBd9KonhTXDy7wka55WEDTMhucISsH/S1mc0xDwHqV4cvhCsopI4ZufT/R1
         wkhRWpuTwn5vuJ3HYCnXPdNHcT5TFQlrOfA2P28UgAD75SxnlgACSEWlapdWrld+xdLO
         TIUw==
X-Gm-Message-State: AOAM5304vtqe6rICOSBPpRmoZc2RsjhhBVu+vbTKY5AAOPkeLv0DwlVV
	ARVq1ULC6FqqmvEb7kJetd4=
X-Google-Smtp-Source: ABdhPJxEd9NW/dD0JbxTXz4Kj2N0fW0OnHwUy+VTJbN17v3KpVchw9fGJblPs8dysh+h0QzRkSgWoA==
X-Received: by 2002:a17:90b:19d8:: with SMTP id nm24mr309020pjb.144.1605046298921;
        Tue, 10 Nov 2020 14:11:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5a46:: with SMTP id z6ls4643406pgs.7.gmail; Tue, 10 Nov
 2020 14:11:38 -0800 (PST)
X-Received: by 2002:aa7:8586:0:b029:18c:3aa6:b8bb with SMTP id w6-20020aa785860000b029018c3aa6b8bbmr7283314pfn.39.1605046298387;
        Tue, 10 Nov 2020 14:11:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046298; cv=none;
        d=google.com; s=arc-20160816;
        b=UgWqoyeeIu9p1OJ89HkMoGlx8jD1YgCLTCTrfsrpNuD5c3c4wV8tO0E/skmh8cSrLO
         yT9kbNTSPB9hdM5Hl8y6fl4kyjUxlqcFXtgDFTl8NreuZSJ0+9zKVs+daev/cls4sS/p
         3t9lsBzpfvdFhT43DSC/+qidVPDnjJly10WoHSJ7QAgvt9OC8MjIjJOP7e9wc09e0+ao
         62yOfo7kRBWugKa+n8LWnf7wNJ4qme+47352YmTMmKFSjZFaYdcxn+4pI8CAIhMC3aPK
         1SN/ojWopWvjdZ5ril2J0EvT1AIk8wBhYDBPD5Vpcu4hiaXRavuPQfHF7LTMpms+To9v
         sVXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=j+TFieADiUKw2x5AzsTIkkuZWnBD6LGUhFcNfxhuTZM=;
        b=tBJrw3g7Bv7iaMZXlkEMHp7NpZt+b0Fk9A/58Q5e8TsgjWJTBHCs3waQjeCazwmFgf
         AFBhoHKfY/bchlqVD/aAfSSnCY71rbKcV+i6kd9wPs2zLeZ91Ga2G/+iCmBz/WSbsu3K
         6FTo1e/OdrHh1SojtLEb1P9rSEG8jsMXZ3dogYFx3nsAvXTJgqRKt3C30bikbdGIu3Fv
         BaigwBBirIyruzC0zVSdWHSwe0mNEbM+1orFeaA/Y4But5dWCrIjdkuht905RIGFqho/
         qo9IVnwbKFEr9F2IJmSIjKCS/mCU7/6o9rWomaZyadwB+eZ4h0WlYGFbzN3AhgqQvkPr
         86dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eiTOEKy/";
       spf=pass (google.com: domain of 3grcrxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GRCrXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b26si5115pfd.5.2020.11.10.14.11.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3grcrxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i14so8446022qtq.18
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1507:: with SMTP id
 e7mr21116424qvy.50.1605046297470; Tue, 10 Nov 2020 14:11:37 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:10 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <427d46e86c81f3ec77147b0ade4bd551d878cf7a.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 13/44] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="eiTOEKy/";       spf=pass
 (google.com: domain of 3grcrxwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GRCrXwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

For software KASAN modes the check is based on the value in the shadow
memory. Hardware tag-based KASAN won't be using shadow, so hide the
implementation of the check in check_invalid_free().

Also simplify the code for software tag-based mode.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/sw_tags.c |  9 +++++++++
 4 files changed, 19 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 123abfb760d4..543e6bf2168f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -272,25 +272,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
-{
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_GRANULE_SIZE;
-
-	/* else CONFIG_KASAN_SW_TAGS: */
-	if ((u8)shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
-		return true;
-
-	return false;
-}
-
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -309,8 +293,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index ec4417156943..e1af3b6c53b8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -187,6 +187,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
+bool check_invalid_free(void *addr)
+{
+	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+
+	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+}
+
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
 	quarantine_remove_cache(cache);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1865bb92d47a..3eff57e71ff5 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -164,6 +164,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 4bdd7dbd6647..b2638c2cd58a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	return (shadow_byte == KASAN_TAG_INVALID) ||
+		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/427d46e86c81f3ec77147b0ade4bd551d878cf7a.1605046192.git.andreyknvl%40google.com.
