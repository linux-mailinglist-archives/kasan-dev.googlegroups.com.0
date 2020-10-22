Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCEOY36AKGQEK6ME2VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49AD5295FBB
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:09 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id i3sf693067lja.15
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372809; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWLLe5ztPRBtX9oo9OUNTzx2xSIGgHncy64fSZ90/aXRvwWxZJoq2AceSoQVX+hIrg
         k8c6LqVuzq3jyV5QhfY+NjqZ9Qn1R412TZPXDIovsKvjBn8hYMLk0B5OQtiLcplgtod1
         kWH0W63NQn3BujaeuF+ErnuGQ+Gt2V4CewVvoNY3pQNpoi1dXt0UqkIskcaif4tMkS+H
         eFT7+Wx7vhQZ+sq5YqDzbaHmh6Y3xcxppcmrPJmVLiJb7DRtpRKGKsbPNzcBJvkHmy1j
         30c2oFibEn/GdulmnDqAYbVCIH4ZG4jsPbHKKW/+n3npMkgSorkWDXLbgVmYDhb0z9/s
         9hiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ceh2FYeYG4wdOsP8Ton+Q2Xukw7IV5BLMJe5sBNbCaY=;
        b=GQGUd+Kbc3hbek03bUmlecNh1L2/YHgrVIW5sFBWn7gl51HP255RMiAZniGcM7xMGa
         vYHgG4X8gqzt8g/XLTQu/9OHIQz4hIYRpJFC92VbC7+1ERkbq0hTqT327nR1cRPM5pbu
         wjPJOlC/smmey+aDxkiU8TkkhQJ+j9TOelSL9cRB+UTq613kaJZfykYtuKcFTetJ7iGy
         aXpHn2FyWJVG2WumH8C2ADnF/k2EbhN/k5WctMGifXTCR/GhYpyOPW5Im5ZWAdDVb86x
         1geFrDZFcHKzzLD+y3FZhNwosFSKGo/8JviMZf4COoIB/n/TTqQtAzWNiO5YePQhFb+7
         T2Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WMfS9dRt;
       spf=pass (google.com: domain of 3b4erxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3B4eRXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ceh2FYeYG4wdOsP8Ton+Q2Xukw7IV5BLMJe5sBNbCaY=;
        b=RkktRil7gG3bZrSXeW96u2N4flI/XuQA6gN5DhZ9aNNslyeCX/MT6LS/gD8g6VceIR
         0AKeIzRlLwAPuR26MXGcZyUPf2HedPf8itFZBvgd6gCSPx6VHEaPajIt5F62J1vzO7CK
         h9ykgq0aO5Vu4TfL8p9uinP3HZSawAyueQCB+RduhfQn+yqSPQtSBEopBqO/f7F/MiPj
         4eN27bE4v6pLHTN4Pj7k318Uc4XFV4zpNi9cJ2RqVcsn79gozbf1ca4twkM2FdGVI6u/
         ly4u4Mjo52QyVTDWY7nzEHgr6u01aZtA31Br9Es5iYVpSkQ96JeFpnP+o8Lqan9fzeYp
         gynQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ceh2FYeYG4wdOsP8Ton+Q2Xukw7IV5BLMJe5sBNbCaY=;
        b=latmGcwP6lhmTUTtbYNVtf2KCngOSb3H0NH69doP3IQvjqxgRVDyJbdeB1rg5OT0a4
         9QYhvbkTOIJM0XJ1UBeOI0TDcwIjzJ3i6sftHtZjSGXr2yP7KRMMFkcmtDVRv+IksxVd
         24dcRGwwq7I13S38K3yq+/2CdVkDOmxqeabEBO3WHBe0V0j6SGlh/NpKx6GGGFGPriSQ
         rvAY6gAt5AQu2sKyqN+Rkl7rHcFSEqZnOCfQWaFfhN2kkHrkE9tkwKt2acEFk5t/sTZb
         xeQBD+6HCn4yeSGdzjPwRLVCWkCXxsYyCODn64Mg+AauaEt+knmyhtm4Lw+ZOAG6PUyu
         INnw==
X-Gm-Message-State: AOAM532dGuOd5aPUN4hIbBCcZ/bDcCRMv4YLhRG4ITXLraDCQ/ZZG7jV
	WHN5oEck/mkd8+/ljCW/Gf0=
X-Google-Smtp-Source: ABdhPJwzqDIX+dUIlqTxTyHf2wTXR9LHTRwbrktPiEUHNunZNBgE/Jfegsw8W1zrzSTihJqzzz5ZCg==
X-Received: by 2002:a2e:b889:: with SMTP id r9mr1081007ljp.378.1603372808834;
        Thu, 22 Oct 2020 06:20:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls334851ljk.3.gmail; Thu, 22 Oct
 2020 06:20:08 -0700 (PDT)
X-Received: by 2002:a2e:84c7:: with SMTP id q7mr983456ljh.415.1603372807963;
        Thu, 22 Oct 2020 06:20:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372807; cv=none;
        d=google.com; s=arc-20160816;
        b=Ng3KIeVzDGARQvPyCuNnPenJU/ylw0Ezvrwyq56uqtJI7GH6PRHrg/1S6Vndg4IEhc
         WTfBe8cT2JirVoRmR88FdFhbBozQvCE1JhbaRl924PnImfDaO9dCWlKdVQuJUhZ7AJFo
         0h6Eajk21cZS5rK5TshlcEUU+3VSXtPmPlGWjGWJzzEONPu6kbiO2t4LwgpAro7+//B2
         CuVGPET//rXo9HpWOlYx0SAj4UtmJ5FjtNPQvrRfooT9wAOey/fxImzoT2GUf1qk+2RS
         ptC77/CKnqsBIowwNFAXYIBQrhcLPhMUbpDTYlL0hLBZg6tv+6JzH/kyA9j9d73W3Wqa
         lggw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mi7vvSs1Xj6QP3ZrLQqzK4ZcKPoucW49C95TbzYwJvE=;
        b=ixISG0gh93wcO+0fD1u+UQaLjyFA1aoZUIKK7WzAF0xWab6jv9FvNcbbn0zZxeq8QS
         q/ftWiF0KLpSjr6jLjkoTTAlucs/VtflrzKYo7oKCcuENBTHv/tOCFiwAU1CNGzT62bV
         q1yhn3ZEmfVepc4XXOAZfEERrMtt00W5w8fD/w7qMeEARSIfalQ5MLl6si6f5qZmSS80
         yHT0FChZ1KueLdhtDr84tyzAG+XHm6KXbAlxVfPykGmRr6vIKOO8km5f1Q2epi7sBplG
         YMV6uyowvvIEQyP2znFpxBA6FmPUFXjEI5pwFHg6CyvjrdE7hFyFVFLPxAgpSXS6TS+F
         mOiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WMfS9dRt;
       spf=pass (google.com: domain of 3b4erxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3B4eRXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r7si36552ljc.7.2020.10.22.06.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b4erxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 91so608033wrk.20
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:07 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4b09:: with SMTP id
 y9mr2666404wma.90.1603372807440; Thu, 22 Oct 2020 06:20:07 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:10 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <5a6f32308101c49da5eef652437bd3da9234c0da.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 18/21] kasan: rename kasan_poison_kfree
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WMfS9dRt;       spf=pass
 (google.com: domain of 3b4erxwokcv46j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3B4eRXwoKCV46J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

Rename kasan_poison_kfree() into kasan_slab_free_mempool() as it better
reflects what this annotation does.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 16 ++++++++--------
 mm/mempool.c          |  2 +-
 3 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 8654275aa62e..2ae92f295f76 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -162,6 +162,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
 	return false;
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	if (static_branch_likely(&kasan_enabled))
+		__kasan_slab_free_mempool(ptr, ip);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags);
 static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
@@ -202,13 +209,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip);
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	if (static_branch_likely(&kasan_enabled))
-		__kasan_poison_kfree(ptr, ip);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static inline void kasan_kfree_large(void *ptr, unsigned long ip)
 {
@@ -244,6 +244,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 {
 	return false;
 }
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -264,7 +265,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b82dbae0c5d6..5622b0ec0907 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -334,6 +334,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	struct page *page;
+
+	page = virt_to_head_page(ptr);
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
+}
+
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
@@ -436,14 +444,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 						flags, true);
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	struct page *page;
-
-	page = virt_to_head_page(ptr);
-	____kasan_slab_free(page->slab_cache, ptr, ip, false);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
diff --git a/mm/mempool.c b/mm/mempool.c
index 79bff63ecf27..0e8d877fbbc6 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -106,7 +106,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_poison_kfree(element, _RET_IP_);
+		kasan_slab_free_mempool(element, _RET_IP_);
 	if (pool->alloc == mempool_alloc_pages)
 		kasan_free_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a6f32308101c49da5eef652437bd3da9234c0da.1603372719.git.andreyknvl%40google.com.
