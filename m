Return-Path: <kasan-dev+bncBAABB7UQUWVAMGQEDHP5TUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 51E437E2DCB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:11:44 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c6edd8e12csf26225751fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:11:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301504; cv=pass;
        d=google.com; s=arc-20160816;
        b=ahRlATffmWfUIsqNP3sVzkNbqL/TkJAMbgFwifoypoPKCiL+8AXRGh6q5jiKEHuegh
         nt9VSQO1+zE2wYTTQklbJvgdtLxCVCirIPDNjjxcdEh5C/bR9gAdJkz9+LWSP+0WsvKp
         cb86Hjf1D+/+qxmfo/d9hdAWuZ58hUPW+LR4XqTBxHkY/NV66liPTQz/EBqBWnHSJ4Sx
         vrervuyyBvP4c6Da313oMzw8m1caPJCWZpuJBfb0KhYV25lo9Uae/FjAjY5B1PFn4ffq
         gG6qRfd9hJ+IA+KmAy04MEkrKVUWuLoTC19e6p9fXqPbMmGeTsblnsD2Z9lRWx+Quuvh
         o4/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W6nZXi7VxIZVzyCWobE0Lg33v2WsLtJb6FV/1DesYds=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=IYG0YR9RcblMRfALKKb37fzUvw7UKNgsW/uQeXGMCBn75/vh5qNc+4R0Y+28qGpIE9
         cP8b17lE4JBlMjut+g0PU39RINWuNeYBTBmr5FKWMTMqr0hnmr3q9L4rUl+s3CJKZitC
         sQmnQ616QAEgwAYn08P0rdfhCjtnGdHk4sgiTTzPHZTz/pZFArb3Ya8yxqylKxwE79V7
         MqBO/vgYlN82a7neZKTrqkrEBwgIBxk7ch+jmPRBNrISzlJ/8agbEChXsVVuyIsb8wJr
         NFm7YEY+nUg3jVGoV0vuZeVp3nq6IpQgEIh0u+EwVOJs1ErU+OyG967pGjWOD9T7lHOR
         aeug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uCxP18Kq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301504; x=1699906304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W6nZXi7VxIZVzyCWobE0Lg33v2WsLtJb6FV/1DesYds=;
        b=U7O6wsqE/VXQ2pRBA1ZKHqurVAPemzWRYSrQe2CRqB/FNrzw+17z+0T5xclItp3dy4
         ZE5hrjRzFSeKsYCIRuniYmg4v9exZOLf5RIdn6cQzuG0Gf87dUyK0+JEOQbCmoxlmd4i
         +ObiGHL4AlkoR/pTC3t3s0SM4vbGRFFTQ8UZ6UyPtq/8M8s4JKBgL1tXWDTzLPV/M+5L
         yICvKJYkeMwQNYMc+k+avL7db5emrCdy9AwRTZy8w1DHJRDHVbupphNxPxz56Jws0ZqY
         heZfXky9vY9PyqY3k94G4V2NzjVLQZLBliEtg4Yq7Ymk/l4SG3WL1dOxsGz5VCaYlACw
         WzLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301504; x=1699906304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W6nZXi7VxIZVzyCWobE0Lg33v2WsLtJb6FV/1DesYds=;
        b=W2KRFTFxaS48qXky6RZHAwnJC3crewE2HQI5X1PEbe3cn+ra+Gvxc6lBu8pNuM0la3
         17slU079+WFt0kmddSnxP0oQD0+9r2fOhTSwYEdkYd3IS2S3Y+2pCKfWx3iNLXrJ1OOv
         TgVuihGlD2O/yr/c34FDvZ6Lcg9FgxvEo6qnjTGaAwLkTQJXEglfUkMrnplHgRVqWkh2
         7oaEHmksqz6BagjNnoVMFcaTX63nkKssdTORsqRLOTPYWmMXzVzmmuPWv7ptYSvA6i6B
         JKthYfHpoS5in7ufYobaf0PqvPExD3/m/89aqrkbg5pqQYDjm1AdM9zs6JnqqrzeKORx
         9CQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy/Ua6z3k7vT2GxzpIed2ZenEmTCUU0o9kuI3SNTg/vp6UPXLLI
	jlQSNxUWaizeWfqN67tR8LQ=
X-Google-Smtp-Source: AGHT+IEp6hVBgWOgh1QEcVyv8hkfzrVvN+tBdCA0CjxjenQNDCEOV/YoKPSy7cI+iNmsS3aTKbQkpA==
X-Received: by 2002:a05:6512:31c5:b0:504:3499:7c2b with SMTP id j5-20020a05651231c500b0050434997c2bmr186309lfe.21.1699301503020;
        Mon, 06 Nov 2023 12:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea3:b0:505:14bb:6259 with SMTP id
 bi35-20020a0565120ea300b0050514bb6259ls201925lfb.0.-pod-prod-00-eu; Mon, 06
 Nov 2023 12:11:41 -0800 (PST)
X-Received: by 2002:ac2:4142:0:b0:508:15dc:ec11 with SMTP id c2-20020ac24142000000b0050815dcec11mr155202lfi.30.1699301501320;
        Mon, 06 Nov 2023 12:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301501; cv=none;
        d=google.com; s=arc-20160816;
        b=Ui1kVwofTkD8VGXM9TBtDpkm4AcTcrIuo4kklpCqFcnM+mHu0gBx0ulosxA3+3Vm7H
         3mlDXT0yZOBRksEdZb6B4CgUblsiFo5d/BNhMdt/qpvdePj5LvG3h/mQhQd/4rxlsiOf
         kmVxGa+B5BXp0az56uzl3PZklEs7KYIUGxhkzpPNSL4UrTNrYHZM9FmMLjj69WdfRp2u
         qUQ9wiek+6HFCqX/zlXoUPKOQXBDO5fJwcfqm354kP7Blo5ikgH8VYyTDQ9NtPw2+rU4
         NDBJc+9RGpc++PUf4AHBMLJK92fMfeMpcSE2WmsBbC/ns+SO6SAsjitBxGZJ5MZoHs7C
         hScw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=22d9hHWXVi8zazHV61QMl0VMY5WvMEtggwgAvi4OURE=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=Y5MtyDEKJXWAGBZ0ClFPIm5l+DHJhwQVR8neaCLKoR7ZW+JEZhAKr/L3bZQOqBEoIx
         2LhpRLDzpiL+xgtox/aunUZejFGNpq2F/5DAOmY6NkczTx+xIbF6Oe9AYYwJheu4JrRs
         fc+SSx7My/XwEgt/37KOkzKq5lqhf2YHR52JWhCZoX5jtpzn5J7mRkHc/HfNyJDFjAPJ
         gb1jvb1mZ/HpDcYIT5uvjKZjcHWDecIlP+cQFwUFv/+LKygN8oLThbwgnUZNMcpti0Me
         gmOKtG4k80rrgbgI899uJCDdhOOz/lkodu0X01bE16ptx53Tdhpz+BrC1ymfr0GqPfIs
         3AbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uCxP18Kq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta1.migadu.com (out-174.mta1.migadu.com. [95.215.58.174])
        by gmr-mx.google.com with ESMTPS id cf6-20020a056512280600b004fe3e3471c8si535950lfb.10.2023.11.06.12.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:11:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) client-ip=95.215.58.174;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 09/20] kasan: save free stack traces for slab mempools
Date: Mon,  6 Nov 2023 21:10:18 +0100
Message-Id: <52d80b4c1d42b10b6c2c3cba57b628a88cb58e03.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=uCxP18Kq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as
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

Make kasan_mempool_poison_object save free stack traces for slab and
kmalloc mempools when the object is freed into the mempool.

Also simplify and rename ____kasan_slab_free to poison_slab_object and
do a few other reability changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  5 +++--
 mm/kasan/common.c     | 20 +++++++++-----------
 2 files changed, 12 insertions(+), 13 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f8ebde384bd7..e636a00e26ba 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -268,8 +268,9 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  * to reuse them instead of freeing them back to the slab allocator (e.g.
  * mempool).
  *
- * This function poisons a slab allocation without initializing its memory and
- * without putting it into the quarantine (for the Generic mode).
+ * This function poisons a slab allocation and saves a free stack trace for it
+ * without initializing the allocation's memory and without putting it into the
+ * quarantine (for the Generic mode).
  *
  * This function also performs checks to detect double-free and invalid-free
  * bugs and reports them. The caller can use the return value of this function
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7c28d0a5af2c..683d0dad32f2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -197,8 +197,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-				unsigned long ip, bool quarantine, bool init)
+static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
+				      unsigned long ip, bool init)
 {
 	void *tagged_object;
 
@@ -211,13 +211,12 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (is_kfence_address(object))
 		return false;
 
-	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
-	    object)) {
+	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
-	/* RCU slabs could be legally used after free within the RCU period */
+	/* RCU slabs could be legally used after free within the RCU period. */
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
@@ -229,19 +228,18 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
-	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
-		return false;
-
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
 
-	return kasan_quarantine_put(cache, object);
+	return false;
 }
 
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool init)
 {
-	return ____kasan_slab_free(cache, object, ip, true, init);
+	bool buggy_object = poison_slab_object(cache, object, ip, init);
+
+	return buggy_object ? true : kasan_quarantine_put(cache, object);
 }
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
@@ -462,7 +460,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	}
 
 	slab = folio_slab(folio);
-	return !____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
+	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52d80b4c1d42b10b6c2c3cba57b628a88cb58e03.1699297309.git.andreyknvl%40google.com.
