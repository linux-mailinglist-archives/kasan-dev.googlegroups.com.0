Return-Path: <kasan-dev+bncBDX4HWEMTEBRB45T4GAAMGQE5QIR6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C83530B09A
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:49 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id h13sf12062684qvs.13
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208628; cv=pass;
        d=google.com; s=arc-20160816;
        b=pwTpVlV7zvgEp9PXp3DZTcBjTBPa0tPDcTK4CmnTGpKfOG5E3GAsxlClaRqZyMjpma
         ZnwcA+hLi9NtQwHW50HyL7C2mOiMut+CDgxqD2NqfoUJCgZEBM/OFGjr6LOsEeMGBK6/
         HIIwwDysadibQ0jS9/iAGEbmIiVyMwXKYOmBLswXUPrGG7PRBJynnzgVJCveO8egjgj1
         18OxmMeGMyzEEstkeraD5l8zTC8kyUpUJL7roORy5K/i3wN6A20ES8ynZ9U3Mfm7nnNc
         t+0gRFzxHzyDEyuyycMY2gP5mrVXTjGRoNlIzULmoFEkvYNAULIYjs4qVUMYn70q+kcI
         kR+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=iv9v3O47ry0pNQt4YRIwAlqJJUb7SBlcEsduYbxJChk=;
        b=uiFWplL8dskFmK2aIRaNG/yh0ThwwkeFpi2/zJUWPm6a0wZazBH4UdHGl/US3F+bWc
         2qRsLa7MmSJX9/bKzkREPqYwwXAKBEb+zQ86mvwTE+Axo9Ikq9ONf53ESm1SPkiqKBNN
         hywTuNopyWYwgWAWxYczIrmsaWibplC9eNPSNUr9UinE7H2fMVJ0A6TRP/z28afUeXgn
         59Y6yxdSHKKt/m6dIVDeYk4JA9To/2T8be0hkceB3GtKxej3CBiC3HSg844bIIs/glSW
         YeGKCLdXmOOR2A6d9gaVeost6tRavSdg8C8lCTpT92d/UeuKkhr1CO8i8E4Ooy0MqZEh
         8f8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=icvI25ft;
       spf=pass (google.com: domain of 381kyyaokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=381kYYAoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iv9v3O47ry0pNQt4YRIwAlqJJUb7SBlcEsduYbxJChk=;
        b=R9nbfp7hO4b4JLyrd0SHZ5MzJu7aoRefLr8rG+oZ+Ci7Y3ZoMaW+rGIFnjOHut8w4M
         yeliljZeX9q5IPrV4rOMqjmTna1eX0BcDO5kWxg+aUq9+m+h5hEX/po/w40//ZMlwWGg
         HRRBEH0ZQ5FYoklkISs3JKdpvODHSdhzfdXmDXTCf7YAFQkJ2+G4gWmMWbi5ahp5QZLQ
         vQ/B/Yn5autay4jZ+ERmwjqZk23olTt0Hn1GmsetRoWeVldrQrGWOS450r6LI1OGDpGQ
         tg+8yV1zrrutVgiR3LYQ53xvCERaRKpKa8RD8EK4lMIzJ0FrauxJC4aGN/gxgCciBfkw
         9JJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iv9v3O47ry0pNQt4YRIwAlqJJUb7SBlcEsduYbxJChk=;
        b=jxhrsgljFEPktQvL63leFSnWzwrzLsPK3Pz+dOYC1DSQM4CIA03cbzGGy4Zoam7fkb
         FSecrAyMZqf4KjawpykEGYQ4mxVQ+CQWwxcLThVwBcmG6ggmAYz2Uxl6v9rnfaXCfdDL
         irYfARC7jHhOfOpclRshzvgs+m/JjiSRmgqh59McvzJ6H2wqri1Jh2VjueaoFNpHtrqT
         V8yFka1ufbDtIritqt3YPChS81vnN/KJjF93yN8TleyLWjZ1Kw94Dkotmf07eSpJ+GLW
         pJJbdj7pTpdlcaANMdfLu256hzugnGduxpo+1E0RqcP2IXsNUuUsDYvyyU8pZQ646Y7Q
         DUXg==
X-Gm-Message-State: AOAM5315nJgx/qu50uLWhdF425inCbAJ+hUuLqII5nKkxAnyJSbwT+o+
	WVcdx5bx1f9x415Tt79m/C8=
X-Google-Smtp-Source: ABdhPJwCOXneDWpfjKvDNBr+oPCUhkcAJOoPnwtzEQaHK0mUMWM+a+7rOWyG9fNwUxOojucU0s+/Yw==
X-Received: by 2002:a0c:8ec1:: with SMTP id y1mr17215306qvb.11.1612208627823;
        Mon, 01 Feb 2021 11:43:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2e41:: with SMTP id j59ls5143785qtd.6.gmail; Mon, 01 Feb
 2021 11:43:47 -0800 (PST)
X-Received: by 2002:ac8:5909:: with SMTP id 9mr16650307qty.39.1612208627504;
        Mon, 01 Feb 2021 11:43:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208627; cv=none;
        d=google.com; s=arc-20160816;
        b=AcD0ryc0uScoFnw+VN9YRIDEeNE9cOut6W/sWo/w0rm4po+A3IvTogwqlsmMbNdewI
         +JnhEsZskdeH1yIC/Uv8yEfTQAWkghJ0RcXA40mpmgq9pX1zRjFSaqwFxQz2Z20jI3FC
         D5eHDcxlOWlO2SSBbl7UmePkwEQAZiRuy6LO5M9zfq+5ZOzN8CAj5d5F/K40guqbufb7
         PkhGKXNdC5qbt4r+uAm48DYFPKhVFuZ1Rz6PFGXGh3pQ7HiBzvnpa5zKswM/n5Ai1ugt
         8Wxks0O7Bkac7Xe8FGDRQtA6Oa98qmS2u5CaVmqnIbGAdNqQ0yKekyqApNJx+rg5WBnj
         8ESQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5os4NdBbDONsbLVxABgdrPD9x64VnOptbOzgU3pEDKs=;
        b=ImfvXxqr5hpPdnafe2VbD7sjzHYcX14o5Xw1Vqevbb+uEkhC96ik7xkvra30iZFcjw
         HiPNx0UK5xWu8uwFvf4/Jwk9UfidqodzpD3DVkitxZpiptDTEmXE8RK39455Mm84lPx1
         YWySqrokHq58QjIkpZ9CPuJ1V72/6q6XlSBqgZjaR6WeFN4/B6ImekS7lD5cnMRdnxxF
         rZ5ON12dRkh07+WDV0+sCCC8EeA9TIX6nnFNxAuquO8r+4flQFOit9S0Ev6HOTD7ETSC
         /WGsmo5pPO+RGMlNcZV4WkBSXs/8dYCrSPBYi5lyEnhUP9roOKHhmYd3LhpAlsCKZJJZ
         7CVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=icvI25ft;
       spf=pass (google.com: domain of 381kyyaokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=381kYYAoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id h123si861962qkf.6.2021.02.01.11.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 381kyyaokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id r190so14155892qkf.19
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c488:: with SMTP id
 u8mr16899450qvi.9.1612208627196; Mon, 01 Feb 2021 11:43:47 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:27 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <8fdbf86842f4eaf2458ecd23d0844058dbc2c7a2.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 03/12] kasan: optimize large kmalloc poisoning
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
 header.i=@google.com header.s=20161025 header.b=icvI25ft;       spf=pass
 (google.com: domain of 381kyyaokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=381kYYAoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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

Similarly to kasan_kmalloc(), kasan_kmalloc_large() doesn't need
to unpoison the object as it as already unpoisoned by alloc_pages()
(or by ksize() for krealloc()).

This patch changes kasan_kmalloc_large() to only poison the redzone.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 20 +++++++++++++++-----
 1 file changed, 15 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 128cb330ca73..a7eb553c8e91 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -494,7 +494,6 @@ EXPORT_SYMBOL(__kasan_kmalloc);
 void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 						gfp_t flags)
 {
-	struct page *page;
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
@@ -504,12 +503,23 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 	if (unlikely(ptr == NULL))
 		return NULL;
 
-	page = virt_to_page(ptr);
+	/*
+	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * alloc_pages() or by ksize() for krealloc().
+	 */
+
+	/*
+	 * The redzone has byte-level precision for the generic mode.
+	 * Partially poison the last object granule to cover the unaligned
+	 * part of the redzone.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule(ptr, size);
+
+	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(ptr + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = (unsigned long)ptr + page_size(page);
-
-	kasan_unpoison(ptr, size);
+	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_PAGE_REDZONE);
 
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8fdbf86842f4eaf2458ecd23d0844058dbc2c7a2.1612208222.git.andreyknvl%40google.com.
