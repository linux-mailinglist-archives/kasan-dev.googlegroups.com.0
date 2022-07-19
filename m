Return-Path: <kasan-dev+bncBAABBLHN26LAMGQE5CDI5BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E98578ECB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:25 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id k27-20020a05600c1c9b00b003a2fee19a80sf8426472wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189485; cv=pass;
        d=google.com; s=arc-20160816;
        b=auie9YzpWsGndAubCu6zR6uRL9yWTbNkNgly49Ak30pXSC7JRd7eYRMFAuYXbDA/w3
         FCp6+XG9tvz7ctaoUxVtNvA/qWOezjAO5iZkEIRb2fnBPj7VkttXOwUrzYcN1rAb4rOx
         IjHcazHUpZy69dF2AMLr5yRYzFDQD589CFgU6u98TQVY7xU+OJbwbki4HFjR4TG5EXmL
         1QXTMTZUHoAXOv+JLNniGCedu12UpgyDT2uGHbuPtiDi3TXPr8EP2qcm6/Ntta0nLfL/
         l58WC5/WNkgqD0sqe4LSnVq8wm4tgPTJ7WiSJeFlqANXfUMVklxdTmvvdIMb3x48AI2K
         VepQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H6PmAz+u76AoVwtMi1BDaS3R056FSmxpynFgZSYErdw=;
        b=dUkwUipuEdWfGdFmQE3TFYBmxoLVoql2SP7B4tvt5mG6MGMgyHDmrzr6T8Qy2Uloab
         8p21/bhqrVZjvvtsHoy4TMbpMedwv1CtF7hNaFrcBgD07nHRmVYHqYCUHw+qOoW1zwfH
         oZPikaLU6kRhV0RHAA1Cz2nleqwXX7mALjfRUsk3mSCuwNcACDhpP15iBwC4m4kNM2BM
         eDC1SVajeOYU/VxBS+cAx9WT4Jf2UPhOOBtWGOxHayfFHct6UejPHrjGzSyID5eqlvSi
         69Vz0xZfEgvTgN+VZ8fAYyUxmdzVhaw/9/JeImjY7Qd7L5u48coVBta+9yFMVjb+TNSJ
         Cabw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Aknc4hn4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H6PmAz+u76AoVwtMi1BDaS3R056FSmxpynFgZSYErdw=;
        b=TrKzG485RtXDkrxeYlHylCc+cpB4c6BMc+ifDZOKI3L1bnEXyEtHuwj1sec5QSkHmu
         nfO5M1p8q25erzhVe6Pz5at2zOlI2pB1HQz0faYO9Krp872lfL4f+TzFMgjHxqkQtm74
         F/faFOhFKkXPlPukzdOEQc7rp/hqhb2qpJqTTHGWAOXuplkkWSBjfWNdeChspwQWOHnM
         MS77SNYFXV5F4BExMSa6ptIlO/9fAQg9fglK0TGWcd3IXD1BjoXXJOKXfcR4ok0xubQR
         bTMceVGtAqd6y207T4EUZDrWQIkzD/8DG/I4uFDoAOpo+rxiIIgJcxIbfD+ACh9oPR6r
         bTnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H6PmAz+u76AoVwtMi1BDaS3R056FSmxpynFgZSYErdw=;
        b=tYssWEJVnSIHIWM0vKHoxsBt0KYZhXFczzhsVzY6dC9sGWuChh42wefaKKoEyPzlZH
         r/nTy71GqcrVa4AUAzzwEibyN+A0jUlf+LxdUin10wPCgmW2WTsEfugAQJtMPAduWqOu
         JhmACibGgzh7RWy7p6tOPeiBH923+dcdPo5hJ4Wn6l8onc0hUf+eDhsyxgdGynv1c5Qj
         Hf7uMiaMKf3970EFWaLHNM+oSF/5uZ3GypbPX9YAa66v/M4pW4mrEC9e5tMMyeZBNvE7
         N7aiSoSmU46x/P+cxx0gn2HASEbpu3uvd/2F/28Bu/PsIp5aaAbx+AH9Q2/5Z0XUStHg
         in7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+A3kRxM51wOnqq8pm5RIB3gNhsSw9llTwrdFZirqfdja14gcaS
	ZNqsgHsOtpQCc3zdhGFkbBY=
X-Google-Smtp-Source: AGRyM1sc9XWARD6IVfZA4lF+CrncH01y1BQdgeTbVPSZPvWXJou32oX6wQpeUtHv+L9l94blFkw9Lg==
X-Received: by 2002:a7b:c354:0:b0:39c:6753:21f8 with SMTP id l20-20020a7bc354000000b0039c675321f8mr28565012wmj.113.1658189485053;
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:784:b0:21d:a0b5:24ab with SMTP id
 bu4-20020a056000078400b0021da0b524abls11062wrb.1.-pod-prod-gmail; Mon, 18 Jul
 2022 17:11:24 -0700 (PDT)
X-Received: by 2002:a05:6000:1a41:b0:20e:687f:1c3 with SMTP id t1-20020a0560001a4100b0020e687f01c3mr24033894wry.415.1658189484349;
        Mon, 18 Jul 2022 17:11:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189484; cv=none;
        d=google.com; s=arc-20160816;
        b=rVw7GhL7I2xWaATFYHevCjDFd6swrNnaKrWagfnaek0mNHxjHyVXYmikksqoV333G/
         WJqh8j8M4oSyBkTonPO7BabNFoP0W4RkOGH1ks52rmetJ4X2FE4r98tJwT7okH2CfCYE
         WvFNJPITPrIsPWiL2VoRcXAuz6JLkCi4FeDjpVO6JhCaOd+NGgcufgCarpJMyC5ZYNjA
         g6jBs6BsmDOgc+fREPRSAhOVAdSrA8lParj7P5D4vEALkEXnymWcfKaodezxMsvdBh1r
         C/MQ4HyUu6e6o5D/qvxTGwmsb1HcGg9UmIsRj659ROP+jxJ73Sgy7RobPG77/a65Qqjl
         kmSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1P0OL5eJBC/VWyzrUzzXy/PpMlaQ+HYTExB/Z4qpTio=;
        b=EUXO+I/DD29iYtKYPB2q+HmH8BAamXRzMbg8S6AgEgdKXtbAqG9M6yEghxsbk2mVLH
         V+vXyU6C6NjRu+NEFQlMaYxtYqR/yIlfwEbEFgflQq0mjinxHcQsXjGGqnD26k3rXO9+
         kaTtQ8dFXsNv7HkfIId97n+Fl77TxQdYhwNTLzUA50YloXDt+dHceUfT/iQiXTlmlMqm
         p9KQx+B85UIHQx9mlj4pdHfgoGk+l1Zk1N4ewK6l55ycBiEwyjLh4TTdHAQOTmsJTrFn
         g1R79ZAUyEReQiD5dhB6YnWovAWcDvRXyp1knLcnJGqa/fCri63XF+FzMQvdkVtnyBgk
         9Qmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Aknc4hn4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id u10-20020a7bcb0a000000b003a2ca59af2dsi326066wmj.1.2022.07.18.17.11.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 07/33] kasan: introduce kasan_get_alloc_track
Date: Tue, 19 Jul 2022 02:09:47 +0200
Message-Id: <739e26fae1f62b2775d01eb42068b32b7406126e.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Aknc4hn4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a kasan_get_alloc_track() helper that fetches alloc_track for a slab
object and use this helper in the common reporting code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common reporting code.
This is desired as only the Generic mode will be using per-object metadata
after this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 14 +++++++++++++-
 mm/kasan/kasan.h   |  4 +++-
 mm/kasan/report.c  |  8 ++++----
 mm/kasan/tags.c    | 14 +++++++++++++-
 4 files changed, 33 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 98c451a3b01f..f212b9ae57b5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -381,8 +381,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
 		return NULL;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 30ff341b6d35..b65a51349c51 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -283,8 +283,10 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag);
+						void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cd9f5c7fc6db..5d225d7d9c4c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -255,12 +255,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object_stacks(struct kmem_cache *cache, void *object,
 					const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_track *alloc_track;
 	struct kasan_track *free_track;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta) {
-		print_track(&alloc_meta->alloc_track, "Allocated");
+	alloc_track = kasan_get_alloc_track(cache, object);
+	if (alloc_track) {
+		print_track(alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e0e5de8ce834..7b1fc8e7c99c 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -38,8 +38,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/739e26fae1f62b2775d01eb42068b32b7406126e.1658189199.git.andreyknvl%40google.com.
