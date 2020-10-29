Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA5P5T6AKGQEPPVAARA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7863929F4FC
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:00 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id f3sf1654610ljc.17
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999620; cv=pass;
        d=google.com; s=arc-20160816;
        b=KQDMpkvMYr33Dwl5Hj79yNXpv3GmjUL4gKvi2wAo+BDzx4YhtC+a4IP2GylcVO2tiS
         JjHy+zrhU+ONV1qIDRJZV4PWTZC2fq7ui46fN8rjgCIju93So4HRPM0QSOvYa/pN4kE0
         GkpG9ez+Q7SqCTPuwOred2DfyvkboEr4CcHDSA5MNDGCOesKL2lw6tC9cKbgmweM05Ct
         VYQLP9fb4PCtHItdmjzCB5RN50h6/ABYa5qoPKRGgql68lcxoMGNjpyfvt+3UqoT7mDl
         v9SRTnZ0vCKnzrWAJk4Hh1ZgYzg4BGSjkHHxq3V0kpQWEX83tzIH9SYtvAv4/0R3AM4D
         vDkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=PLICRG9FR5GfCtr+Niww8EmpYBIB1bdRniBH0N+ddlc=;
        b=G9I51XAmT7I5K7kB9JWc5iT3Ec3ekqsC1CKJQNFclPFrCym1zIYq6VpSeJAfR6ImPh
         ofR3iw1inMZWB4AdZhdSoDEjn0Jb4Mx/3yrxzS/WhC5QiTjzhFmEN3lAh3RrpYye1p1J
         fOvU9hdw3AgVC4V6DdTnF5BNDAXTz0aZrAtsPXYnb5r9GOOy6a4F4pr8Bk8soqEyAHFo
         YK91Aq/UJvGKPfuImke7Xt9DzOialPGeVT+ZqyH697KedLPe2vNcztpLJCNVyqOkPV4H
         3S2TQv7aqZRzDi4wxbFS4TweuXw+ilrsjNDk+sNzOMVTMffeGTzK0mXbcrhidf2Mprli
         OLPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GSWuFAe8;
       spf=pass (google.com: domain of 3ghebxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ghebXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PLICRG9FR5GfCtr+Niww8EmpYBIB1bdRniBH0N+ddlc=;
        b=IlaghMzjZYQ73AlvwRoMEHTv7SX6z/ScGfb1ppZJVG3rKXvEmjeStkxbOh12DG161v
         TGCfdTmj/OUAEHV/z3iUCSBJN5s8wubr1lhMrRBw39q1AbByFCxt7wJZ6G8dR8VT3tje
         tnmAbSqxLSYd9zlnToPt5UNMK4nVOdK8XGjCmL65H7PIktaZJKONyU2bKwYmzMHCOCDy
         kP1fP/tZkBbwAAnDv3bcroDyMI0n20kxroFA68yZeBMZEb2nqG8kKSdpg9dMmO4+uPz8
         iAy49Jz7jFhUtqcmdcQ0mgCpfdibJX09SZqE1l20QUgsMKCAyyoN57D1mNR/QQR2TDgT
         KEkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PLICRG9FR5GfCtr+Niww8EmpYBIB1bdRniBH0N+ddlc=;
        b=ai9RY5LObv3VE2C4qDYklJdxI6q4w/Pa4d1FOhpGwRk6Sc16SkGYfjdHhxAIiXauWH
         a1fyjrU2jpSVCc9gKVzsf+bn1Z0Yyz8/CjE2jhqoeFexj5om8Igar2KhG6GqylroWnSk
         VSJQMuBL4OZq+GgEBrQxuA4eCTIc1jiPImX6ox6PnS4dBrYRX7JiVf7Qh69bZqRbWj3R
         Le4aZZ0VZ8L0xuqSCCuwwaymuXuWZfqPIL+j6104aWCiv5ahtgZtCELtOQZFEQ3BoBlL
         NxatwMGwsR8gdbnsNhWTQLlWo1uvJvxIcml8bYb5XuTtru/C43VGBQy2aMT4zm+8xaq3
         eWxw==
X-Gm-Message-State: AOAM530LyMtrsj7edIIH9sLpsAS3szJE8TWOVzmmOH3ChRFIeHP+U8fQ
	VQ8KjeVZWDIWPl5ghpX7gqo=
X-Google-Smtp-Source: ABdhPJyLNWmouPShyMGNGETmnTn7XlsK7YjvFT2WB3TaVYFWJVbeYftMeWx75kQl2/toUmUg7cntZQ==
X-Received: by 2002:a19:becf:: with SMTP id o198mr2375402lff.519.1603999620086;
        Thu, 29 Oct 2020 12:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2396554lff.1.gmail; Thu, 29 Oct
 2020 12:26:59 -0700 (PDT)
X-Received: by 2002:ac2:5a10:: with SMTP id q16mr2386605lfn.239.1603999619184;
        Thu, 29 Oct 2020 12:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999619; cv=none;
        d=google.com; s=arc-20160816;
        b=umWlnG5wVARAlWq8qMfwp9v2yAjMptNFQDvG317R8pBYEh8GjGIXY4KvSh1ThP/+8Q
         zkE/ATMDyzc5F3NlQVoTlwcvSQGYeUgXNMjNYP/0xrddI0fXCLueM2hrA+N/ycetGA3A
         XeErvGv1LaJBas30yVNtkKrfQAWnCraWyFymxfVeP2ksbH8m/8h9Q8AWJ/xOTPZfBW6V
         YRFzrqqtKpolJLTZ0vyC0lWreTfBdpdpGYCyd02yGe80eYe+yKRxb7keqOELr3NRtThD
         9rLQkvdyXIN9DfDbcQ+8mggKgAhgeXlzlIWyewrF9AL7jzKiY2Un6CJXWPr6qft/Bfcx
         ZYJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HlYwNXx3lb4nJKfNwmLtK/HiZ9cAJm1BiI4i6PXyeCs=;
        b=R5RX0YmnFoO+EE8CiEPTQq7tvXUGE3Tcz/Ow7fFjT8Vohz7HFlkLPsoBRBwus0ydPJ
         XQC7DqR2ShUxPlRpncpQc0AZSD8+5Tg45NnyRTWxMeBtAa7ElqVN3Cw+cvynw1uNlfSq
         tZVd5iGL0Elu5ofooi6YztOK0jl2QRHviJWo3/cu5rU5Kx9tulcQyBplNs4pqzkJwSdg
         oektQED+tPsKcxg0TdCF0xV/r603O3BZv58I/wXxH8ntXdCi9I8j+hC9i1xJAvzbSAR/
         D9UgFMblAfZU//kW7ndq3CSouDx56eHDEOTUH4ZF9/YL3gsQ7X/Z8KVxaS1SYiKM2iDL
         PNAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GSWuFAe8;
       spf=pass (google.com: domain of 3ghebxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ghebXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id w28si116047lfq.3.2020.10.29.12.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ghebxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j15so1679104wrd.16
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:59 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e403:: with SMTP id
 b3mr424156wmh.79.1603999618631; Thu, 29 Oct 2020 12:26:58 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:42 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <dd5676faa3c92874d90f486df253cace3c05641e.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 21/40] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GSWuFAe8;       spf=pass
 (google.com: domain of 3ghebxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ghebXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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
index a2e71818d464..325bfd82bce4 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd5676faa3c92874d90f486df253cace3c05641e.1603999489.git.andreyknvl%40google.com.
