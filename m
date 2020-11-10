Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMFEVT6QKGQEIZTPWWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id DB6BB2AE31F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:32 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id y8sf4839167edj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046832; cv=pass;
        d=google.com; s=arc-20160816;
        b=RBhPJ7S+qh6m8XRzVACaWd/5F/JWPW17e6b+itJZvNzR8YFpzF9/40gYYFAkDhjAWz
         CsU3t447le7sKF1Pz6wNpAadUIasiamdTcbGJnNNRR5z3sZpDB3v5sgB4YvA4Rmrnm8A
         rllNuPDUWvyLfwgvVQ7R+GAAB0gT5+zub1H77oTKd6XmCNhu7IxP1TLrYl/nBQURdLB1
         IP2cg5fF3wVtziamBjEmtsaauZf6qkfgHlA4E1XnEuV20KyFxwldYdJJtEFdxfncAadS
         HJmt7Vd7g0xwLPC9uYQ68Rq+NNLL2Cd3gx4BrETeo/VnOS1n0uQ7UK4wG/D0OQ1Tm+M+
         6C/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=W1YLetEQwqdyvck3iFAk0YX6xYSwXx4OsULWqFppa10=;
        b=RcSI9vzXklEU24GgUBr5+pv0kZhLLRHtwjNCro1PhmSWA+hwe5/Buct+Aw37h+UYCn
         xYog9DdD65SZAOXp6ncxymKKa9aQrPPMsNhkv9BP1ObHciZJnxj++HDdAvxORoa3skKM
         +BOzz2laYYHFw56h9fERK99skm/2U8larXR8TNhGen9nhe56chBHtIPuxTVbZIFU3F5y
         2kwwMnMAv5cxgqV+HPmJewYNd9Ckmqtj4skVBNj4qkUZlkJrTC99hyGBnREJMJlb7/Ed
         AG99eXZFfh2HBoePQr/hYai/ZqdeDQy+BkhBrFhyPLZBDse66iqmWVZCf8pqRAfFvgOG
         1eMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B6QwfVBA;
       spf=pass (google.com: domain of 3lxkrxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LxKrXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=W1YLetEQwqdyvck3iFAk0YX6xYSwXx4OsULWqFppa10=;
        b=oZtHjI1yktj4jhHqedbS4tZBkPXWqSe6d9YQ5aHeApsc9pWxexlgB6UmjZdhITeJEc
         HbhFlaoQHc3c3p0NqVfxsU3fLCpMICvhILMUa3betGesb+xmmKR282c1M2E5Haun8AEq
         kgbBJS9CNAn71yXyIgza8eQzHIHhYDS/Lhz93NR9SyceHu8bOwvjNiIsCjjIFuxTDjGY
         rFstqKdgd0wtpW7FhFd6EDGf5FrQ08Mkotg6IiNMqPeEQJSBaTP83P7cTdQdtWpJE7ye
         dc/9D9DqolUvtHHpgVO3dcK7rb5xYexhjBMhqVrx21DrR+//ILSEVG1z9rCEy0L9iF8I
         OXVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W1YLetEQwqdyvck3iFAk0YX6xYSwXx4OsULWqFppa10=;
        b=QfAcvBrutAz8GmFyiHRCSs0OdurwhpopK9eUX21gMmjExqlbPaWjArNKmnkKJPciP0
         fZnYYeyi6xHw/+2Bt066ecJAaHTCv5S3tMJzkprMfLwlED2LcKSwa+pQCICNaF03IRgv
         Yt224NvEH00yLdYnYg8nBrdJuZ/Lko59jgn2n2wGuVjMtjCWQha5Qj46oxRp9R0y8l5m
         ZO3zP8dP5NHgBWFtJ+p8OKsErl5RXJn7wSG53zdgMLN99G86/Z2dIXHu/aSisWtTZ8FC
         iuJH/axrjA690caiAxMX2Yd091+Zq75Izv/LuKZ9gCiupUG2xG65BzcMutmehE6j70aj
         m+Rg==
X-Gm-Message-State: AOAM533U0PxqvgscGQa04pEbLci5ISEWRmOlO62Zcefzl2mgtQMibBN4
	mEOLXmBb5M3FHRVNE/mN5us=
X-Google-Smtp-Source: ABdhPJytMNZT7fdWYG98jrvJoBFo2P91wecRXgvtzeF7S7f/Mj3rQX2+bgO/H1LcCNXAp03eYf0kWg==
X-Received: by 2002:a17:906:aecd:: with SMTP id me13mr14251035ejb.433.1605046832634;
        Tue, 10 Nov 2020 14:20:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5208:: with SMTP id g8ls6867608ejm.11.gmail; Tue, 10
 Nov 2020 14:20:31 -0800 (PST)
X-Received: by 2002:a17:906:4d93:: with SMTP id s19mr22925586eju.271.1605046831817;
        Tue, 10 Nov 2020 14:20:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046831; cv=none;
        d=google.com; s=arc-20160816;
        b=QnEZeG2OT7o42qQ+7e/FcxZQv2FSsEEOgA0IZ+woI3/d699U4PFj4AZpW6LT8PKURh
         3tgPf0A6Sm3De4oNI14shc/jK9r7oFWcp3aTCYN9za9ZqK/tA2IuzyyKx3EJvypVaJwg
         2S42S0mhgBoCfGyRSOW8ByY58MRsFWJLAasL4F1Z55C5DRlAY7wd5I22KbME8xfGXW40
         I6c35yz6S9XsJDt8Hi+8UeYIeSOMI3rJjOMMonpsQfXk00JZrrxJNFxUN/6fuIUPQDAh
         IeFq5D6hwjM/releDF2S5ixfZhYGU4TkOonld/UA0D+JgVo/Va5Np6JmDU5HT/sgE5vp
         vECQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SMV12gvgXWyti1wWozncOBF2sC/NzCwG5tM1W9vYuH4=;
        b=lChMBXMZMQc72jK9ZhIw2AXZYIS72Mb5cyg/Ovv0ooV6+iFUjBrUJV4xpa5lv0B9DQ
         1jPCmy3k/xXZn5V2LTSwKmxMvzjY7/JggX0Zm4lVviDHsVKEH5G493xNguNWiUrPajLk
         DgztH/yZ0EchcXhvxoSui2VxBJaRtfEOFYZkea/FUI39Xjt5ZXjPsREaTchbwGtv0L6c
         3Svk2oLEUa4Q226MTwyEgZ+nF2VIilOfm98NNcbawukVZ2rJonQPVbRFN0F6UMQHWNDS
         9GeI2ZWwaYH40/AOCIwsmaPHVgJPUH3XJMQwi2VONQG0YqPkUo6Orfr0wHnaT3QspexS
         XS/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B6QwfVBA;
       spf=pass (google.com: domain of 3lxkrxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LxKrXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v7si9302edj.5.2020.11.10.14.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lxkrxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 14so1386127wmg.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:5f45:: with SMTP id
 t66mr315013wmb.20.1605046831528; Tue, 10 Nov 2020 14:20:31 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:05 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <d7182392511522e5b3ab7b0c1c0933b4f5963ce0.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 01/20] kasan: simplify quarantine_put call site
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B6QwfVBA;       spf=pass
 (google.com: domain of 3lxkrxwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LxKrXwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2bb0ef6da6bd..5712c66c11c1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 21fe75c66f26..c2c40ec1544d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d7182392511522e5b3ab7b0c1c0933b4f5963ce0.1605046662.git.andreyknvl%40google.com.
