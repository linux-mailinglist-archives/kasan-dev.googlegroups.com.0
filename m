Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2GFWT5QKGQEFRRH7ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 433C6277BD0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:21 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id l9sf276098wrq.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987881; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAN6JmardRpXOgJ0ov2XE4m5ggtQSDKEK7R64lbKAgu7/l/Dmvjsgd3IuXy18AOrI8
         8F1+p71L1ki24KyiDQmVGbAQf2KuqVM6s/V2vvCllhudmvC7YwVGxIBsnccCBYY/tQJM
         HmSLpy5k3b4emtz+5OckyI7K+GFsRp677swLwGsUqxf8/MKFxDPV+LIasrnquocAenm1
         n9pG+tCLiGsRZANQ5+4F2QMwAHuCBqcCgDM9+hKlLc2GQAKctg25wvSdohXdWZA0ae/Y
         abVew5CfKrG+3La6U+Q5KHEUIn0U9UlEI3sP/6X/8klVDXVRYQIvepTa45b83FZJCC01
         locw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=bPUJRoDNdAOSwi3qYDh/ZpXyrW52lOleAelq8OJA/iY=;
        b=d7UwDSws8nejWIJV++N0pL2QkyDowqkyoI+pkRWCapiIptF99iXuh1FlhgBKsqCNUy
         yRcmpJI8WJT2E63Joxvyr3m/1eJdRnCAhoJquIfdeiAYKdgUlmr2wYZemqAHT1nRD2l/
         DaQn0EEDDHLZOSgqO79ejCmEomFpZsbBk3EepG9BQmRRJhoUrCnMPatrWmMdUC92oZek
         tMbPATFYHLDCMNzO0BdDfFyTYmBbWWvgKWyjv5c8yZaUoFX/PNa0pHArFFtktI1H+Qsx
         QrCQIUBLxPDCE5dyIkXOUD2SRCwhAfDMml/bPoOfrMsdOZxDscVZGWZvqgqlBYCn6zmN
         eB0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i+4U0HOR;
       spf=pass (google.com: domain of 35yjtxwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35yJtXwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bPUJRoDNdAOSwi3qYDh/ZpXyrW52lOleAelq8OJA/iY=;
        b=nUtc4qYco0jx8N6Uvb+hrnjT2Fl6bOdDEfFdBGYmrQKBL2+aUCQq+g37Iu7VSy3UA9
         QT6qcu9sTvREojH5NSjmgPBuRfNVqzBsxJe8N1tAMwa+RDfxoiuVl0seLd0zRIhexoU+
         N+vK4quCl4AgpVU0kUrNKAroOJRECTIq/AZZPWLUy1OZg4N+LSkV7+nLuH4gOoAAibr4
         +Xcbmda/6izZRMjnUXzTWKBWK43xHO5U8w1EgNkZSH4duc/urriVzd/djIRq0X2TgclD
         vscFlIlV8IzoFq73HgdvaUNVcEvsCmNwth01u9hGv+iHdpPgx+vqwMq85+u8KWadv5Bg
         jIFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPUJRoDNdAOSwi3qYDh/ZpXyrW52lOleAelq8OJA/iY=;
        b=adqx+Kb7ePKcT0e1GnX6sO1Tn8OHpvxDwSwf/64ZvKk6Hjf0HlQ0FmRyNj+1ZQs5kZ
         x08WTg6cEJs9Njj+vNgD19s6WWEranWSAD3kQe+RapdgYAE09r+X3yVHtEdMPCyatAOS
         nFvlhCWPfNaPjC3+NhgcQRK8w6fV1UDQo2P+CeBrJ5HaUcUgCm+Ha8s+KFCrJHXO6EkH
         /K3cXo+iA3E2en0Xcn//FkKN5uDUTvjCReKomI/TL/1zJMfbrZj7rEmZSCpFA7mDXnKX
         18xZDHBONKfdDndx672naWjiDIYp1PzwuDlaKH3W+OygLA9SXp2rZS6GO3aJUfxq/Mzs
         aIFA==
X-Gm-Message-State: AOAM533zFBTW2FXRj+7NQuwff5jg0QymGEFpTMrQC2xYhjDOUsNxQNlI
	L8B3bVU/7UHu4tO+5ECG/tc=
X-Google-Smtp-Source: ABdhPJyxSUHXANsdjnrz2v7JWeulF2niAL6EffKXsZXhXjHpnWEMPwI0mzBKkZzDHIfiOHGsjcXDhA==
X-Received: by 2002:a05:6000:108a:: with SMTP id y10mr1240603wrw.41.1600987881001;
        Thu, 24 Sep 2020 15:51:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls219632wmf.2.canary-gmail; Thu,
 24 Sep 2020 15:51:20 -0700 (PDT)
X-Received: by 2002:a1c:9ec1:: with SMTP id h184mr867497wme.180.1600987880148;
        Thu, 24 Sep 2020 15:51:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987880; cv=none;
        d=google.com; s=arc-20160816;
        b=Caw1R+5cQepH5zIFKef/CX5+IYWsgQb5URb+G3B7jYTNVEA+kCmMrhy6QP4i/o9GYX
         ekPpXeC1xEsFlBJg4vNq5MfpD4IJbMZwXuUOwfsG7HbtgAIq5eHv+nZSsUEqR/+ARHPB
         ajGz97JHLYaRosIbaBjj8CF32ElRixR8mZU3rYpCrU9WpsbDwxk1vD1TrmrT0ILPM6Q5
         mQ4oahgHavMiebw+0IYoOWfP4cUedHa0XXjMuL+c2h09WY5ZAus/VTtVu0mdwGQqP26h
         0bD/HP4uyHQjVxbU5SrC/cKUp0aDSqHN0ooduqsrPwvdNFLmo4v0WKXXqqj4IjrAwuDZ
         jeGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TX6p/0gnBn0otXI/5R+K6UE5Ge58VwzldHyRhW7QMf8=;
        b=JAZEFfMbphOc+4yz5G+12fxVbRX2f2vgN4vtk24ON02gluIgRze9E1+s+YNSYjEC17
         Q7nm3GCeZHtmbv5a1PhcPE3AlrZ8FZWWNxiWK+okiabVsdl/7n0CT/6sEtG4iGtFzM+w
         TluasaNhIFlKACxiTVwq4Iri+izbRIZq0a5GPDBTrHYaF7UYYFvOqFmAdpt+qKDYNTQS
         70VlSZ2kbpEpC2rXF3xM1GZzChQHoCyf9qyEYBKBI16Lgouf3pXPB47SZ/RZ6W+Umc/O
         7LBTrPhJ3RunZyD1gthNYHG+cy9d6RroNHOl6HY+eapcZxFlvLT/ksvT+ArzlSYrr+eP
         BokQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i+4U0HOR;
       spf=pass (google.com: domain of 35yjtxwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35yJtXwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 126si18551wmb.2.2020.09.24.15.51.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35yjtxwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r16so278305wrm.18
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:20 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2403:: with SMTP id
 k3mr791100wmk.153.1600987879636; Thu, 24 Sep 2020 15:51:19 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:19 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <c1cef2ae4f4c5640afc8aac4339d77d140d45304.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 12/39] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i+4U0HOR;       spf=pass
 (google.com: domain of 35yjtxwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35yJtXwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1cef2ae4f4c5640afc8aac4339d77d140d45304.1600987622.git.andreyknvl%40google.com.
