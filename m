Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBVU4GAAMGQEKU7OGTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E039B30B0A4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:44:07 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id w3sf9150300oov.16
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:44:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208647; cv=pass;
        d=google.com; s=arc-20160816;
        b=hYVXL8QDlBiLwFbjYy8lDy+KHneuGWwMO8Bb1aFzIuf35lChtKvs1Crvbp8a6cjy7p
         eGGinAiZxJNXbItPlMcAY2llS0fKKCikPDF8A+RCfkZsUhZ+TYX7m+H1o54gAoIAGiQB
         naRg4f5ZpYlQxUmKDtVITz0ru82oMqd0dtaHjvxZeK5mh9vpB5rwV6JSEnalH1nePIHb
         0m7834xfyqmcmrn32WwvQ0n4/glUG2HlViUO/77UHAD8LhE+auhM1WVOTs6wdVwUQkOv
         O8t8vf0+ue/aKXcU9k+uToys/oK+99n9hlBTkh6ZMp6+hfAMPg6omAwYBZFzAcYhAfFT
         +33Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JPUtf1Z3mOxnIckfmIuxekyOzDDNKpymx8YbwSuOGxo=;
        b=DntCQC/Rc+cibVK164gtYoldzjMRF/XRdN8x+DAawFtkJmzu8FdVRziWhOiia6ItzN
         IBZx8w8pCV8WqjbE+tHd+sNPgCoXL1JHo6oPF9+ep/FhpRmb04NB04AWK8t+TAFBdB4w
         N//bRfhnGa0nA8X1mtoqUkiExANhbXoRpKLUbFe3+tt6P87i5s60OtnELaqaZu+KLUw2
         e2LQNb8yMn02+5bryQ33YroP1MRxRAqVlbu/Q3qtnt3aMqPwXE+Az3ziwsQvh7hLugk6
         6weHcB/H2Y8xrNRSIQdLiITO5iZJTbBTiWp9gJhrPQBW0JoJhrkOohKPAJ7xboYf8rJR
         ntWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1lXS5TD;
       spf=pass (google.com: domain of 3bvoyyaokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BVoYYAoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JPUtf1Z3mOxnIckfmIuxekyOzDDNKpymx8YbwSuOGxo=;
        b=Pvay1+rs3ZuwRJhkWkWSP5JnkQnF4F1k+quqAHy2o5WMTWoZu+GvWOa34h+I93x7pL
         03cTc/3M0SgosshN534ydPjNOg5SFTMTgFRlvJ0HseIG+eoKUOIWh1MZKmNOagJH2F6L
         UaxF5rplWfVDfqjUaiF/5wfp73l7yeTsUiSH3Q/Ply0dkEwPnOtHVZ7ldodUXX1yMlrZ
         jiv7fiaRaiGZrxuQNgkzEuJF5sbjmexKsH7xe1VFqcwZhr6n0SbKDtoEQRHGEKAv1nVq
         kS5KkXpzn2gdvuV17iiAki0e7Q8nSGPRKVoCM6ppcvsBX8n8VmC24W2ANlEQOCKwl/lW
         y2CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JPUtf1Z3mOxnIckfmIuxekyOzDDNKpymx8YbwSuOGxo=;
        b=V4GSuk0+WT66dKXaavM4rrv6ur5e9pv0KvfbyW25nCG95U9Etr8hAZ8oP3EQaYLoQ3
         xHJn+4IQ8a+L2EZcHOI+aD3qY8LFuFnbkJIDytp+irP7w+8dUK8rb29TIM27e7E6me0U
         oTwtaS/dnr4zRydvbEaVOstY811nHFx2J5piQYWgZLr1mML9FC70suCrrStB8933fIQX
         bzroxRsCAijABYTeEFb1doNV2bInmt0+VX3BAml4n7l7+gNABo9m9Z1T1UXXXnrXVJlx
         SzezInjYDPtTdZRjvH1ZgBp9nAoRizVdF4CnDKHExm4x13geb+XpAzcVbvlPmOVc5EG9
         xUPw==
X-Gm-Message-State: AOAM530PTwQ3Def/SX28iONn37yKtNND03h6Cm+WeLJ8qqPiUKrezAva
	8HgZZbVkMroEXtJiIEib7hA=
X-Google-Smtp-Source: ABdhPJwPzAzCyyujaGhUN/gXWCG5aChg3MXUSjFCWHrPVhBzsUFCz4ZDHYLFn0OHtNvsZQW1z4iExg==
X-Received: by 2002:a05:6830:2114:: with SMTP id i20mr13320321otc.91.1612208646821;
        Mon, 01 Feb 2021 11:44:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ad50:: with SMTP id w77ls4289622oie.11.gmail; Mon, 01
 Feb 2021 11:44:06 -0800 (PST)
X-Received: by 2002:aca:b286:: with SMTP id b128mr347302oif.126.1612208646333;
        Mon, 01 Feb 2021 11:44:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208646; cv=none;
        d=google.com; s=arc-20160816;
        b=F/Rmo5RIxPcgeHx0tfGRbkzjSX1DntaNxLibYwX4r77RYXu0cYzHXajeeHCxFO3ziu
         2V19GeIn3sPbSeQj/mDO3xz9yM0yt7M9KgLWX/saTNWmFr17Dsd1xDBvlbW6aMkwjW9I
         Jo3529UDjcwb8KVXcLmhnlx2iEHfcOvnUg2G2L7oftyAzeuDGZ17EVb3/wMUV3z9MWQ2
         zXwmuT1fU15F2YCuuEvz32KojtvrqFLtiJCAUyD5PxH0d3ySpKc9XSQkeI2q25Uz0K70
         FKXZy4mQ//yJsvLgWDK1wQJGQNQmXEPScNFa1gzMl3DNUYNIjUBx2mEez8yJ4ccGRs8K
         At1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NVeqfy8PnyvgWAdKHeCgVfqveCjCMDJegzzrq5UVB6U=;
        b=mpRnkFMemPnTArPn9OMe8GfZ+CrKPhVjnCB8lzMPKGBX88TiJMZpjnPlWACvrY4SjW
         mmwlZHqjMU9fa/Cx/Wp9RY3BjUC04748QQbkzzKCOyTVJTbJW/becUp7VSJ+h5+Aqj9v
         lEpOgVQRN9PG7V61QUKINrWhBrv7DAaFFTbQKwqNthrn4VxjhtP5FmDmZDTTlUlD0lTQ
         KvB5sIs2637Pgnh2XaOGq7rXQvA3NES27GBeVIliyuCfnNZwtBerB9xGJWfCa7gMiEKs
         aWb9UNDs1YWPeE1HJIvY0sW43zqvXSMlsrax5m9dhsXEyumzoWm49+smIZoo68kS9Sha
         jnrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1lXS5TD;
       spf=pass (google.com: domain of 3bvoyyaokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BVoYYAoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id l126si1018026oih.3.2021.02.01.11.44.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:44:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bvoyyaokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t5so11422532qti.5
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:44:06 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:725:: with SMTP id
 c5mr16904134qvz.27.1612208645795; Mon, 01 Feb 2021 11:44:05 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:35 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <05a45017b4cb15344395650e880bbab0fe6ba3e4.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 11/12] kasan: always inline HW_TAGS helper functions
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b1lXS5TD;       spf=pass
 (google.com: domain of 3bvoyyaokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3BVoYYAoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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

Mark all static functions in common.c and kasan.h that are used for
hardware tag-based KASAN as __always_inline to avoid unnecessary
function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 13 +++++++------
 mm/kasan/kasan.h  |  6 +++---
 2 files changed, 10 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 5691cca69397..2004ecd6e43c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -279,7 +279,8 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  *    based on objects indexes, so that objects that are next to each other
  *    get different tags.
  */
-static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
+static __always_inline u8 assign_tag(struct kmem_cache *cache,
+					const void *object, bool init)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0xff;
@@ -321,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-			      unsigned long ip, bool quarantine)
+static __always_inline bool ____kasan_slab_free(struct kmem_cache *cache,
+				void *object, unsigned long ip, bool quarantine)
 {
 	u8 tag;
 	void *tagged_object;
@@ -366,7 +367,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
-static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+static __always_inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip);
@@ -461,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	return tagged_object;
 }
 
-static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-					size_t size, gfp_t flags)
+static __always_inline void *____kasan_kmalloc(struct kmem_cache *cache,
+				const void *object, size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 2f7400a3412f..d5fe72747a53 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -321,7 +321,7 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-static inline void kasan_poison(const void *addr, size_t size, u8 value)
+static __always_inline void kasan_poison(const void *addr, size_t size, u8 value)
 {
 	addr = kasan_reset_tag(addr);
 
@@ -337,7 +337,7 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
 	hw_set_mem_tag_range((void *)addr, size, value);
 }
 
-static inline void kasan_unpoison(const void *addr, size_t size)
+static __always_inline void kasan_unpoison(const void *addr, size_t size)
 {
 	u8 tag = get_tag(addr);
 
@@ -354,7 +354,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
 	hw_set_mem_tag_range((void *)addr, size, tag);
 }
 
-static inline bool kasan_byte_accessible(const void *addr)
+static __always_inline bool kasan_byte_accessible(const void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
 	u8 mem_tag = hw_get_mem_tag((void *)addr);
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/05a45017b4cb15344395650e880bbab0fe6ba3e4.1612208222.git.andreyknvl%40google.com.
