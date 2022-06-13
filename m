Return-Path: <kasan-dev+bncBAABBIFXT2KQMGQEQ6JK5NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFBF549EDA
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:41 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id k21-20020aa7d2d5000000b0042dcac48313sf4669046edr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151521; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ibo5dd9cSN1NlURNQnV6y2ET2M5iYUVOoGWnEpRtJymLU02goaSrJBKoZf6E3/lUht
         DbfTfpfC32R5BmocJtwXEcDd2SU86lOoA7HDxaKor1N36OSEaJ4xr3kma/XYVF7E9BPI
         Y3eF6p6T3lKfaF2jMyK+MEcSIHzkwXFJNyN0pwpkUQg8d8dWoj7qNNNGMJPzksXpyTgL
         QtmYrT7ANrjYXD0WXPyqhPI9mszUwD2rphl711W6U7DdD4XJEyB+nkE1o2HRb3jfiXNA
         zAgrmUnBQU2Z5DJtTjPfQu54tbruTnRI/GrVgPhXpXDgqTNR5G+L3//BAX+WIQ9Rb/5c
         644A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3bXyJaAl2Vse2ndZngzHol1gJcHONejXSWkZd2/OoZQ=;
        b=OamxLQlKxVDKGihcRLpvL1m+NcE5OONuWgkh0ksJG1RKjtuzv4NKXk6OsYBHjzy3V6
         Qc9OaZynbdDx9CHi8byfP67jKZq9AvEEjLfUQzvRxzH5mbuCB6g/xjZOi+svcP1X6929
         qRjEWnBTHZRdgnHFOy+sXweWsLV5sG1PdJfc+tX6Qig3z87bDy6bCNzkqBYO7TaePwnj
         +W4hfa0XBqzsYeKMEoh12+8VpYXhc3a6utc3qKO60zYxd5GgbPX+BrJtPkJA7mQwk142
         i9nkZ6y81TNddbhBh+OhYY0t1Yi3SViEKv/N7khHTM1oeOMp9+yFOZtJJzvrSkzRXQcH
         IP1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F5EnSyRz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3bXyJaAl2Vse2ndZngzHol1gJcHONejXSWkZd2/OoZQ=;
        b=T4RltlhrKB5w6nLvyGtDime7ppYDh1TO/EAxVW0DDJOUsKcQ57T2B6xFfeIa2HBTa9
         UCTzmVGauOOrpEc75Wj4R34GM2/0+pUUrCEqd0v6qv7jJ1NPgpT+57oAvnKrs2BQbYf7
         d4PnB8jbdGTVrhdKFgL42QJlVh+gYw3sO2lAZc/9uW54ltKjpCjp7F7OBtsKLIdyhmBI
         KmATdizEe5U7TUkv/Uz8ldMykXQHQRilB4elSt+EQ4b26sS0Wciqd1OyyA1AWeCUBZNm
         m/tbVvkGmQ9mJ9cBCsKCossQK6aeMOhU/6Zcd4YzrMQWvn7oUNzbXKgLLQ8++Qk9+l4o
         TckA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3bXyJaAl2Vse2ndZngzHol1gJcHONejXSWkZd2/OoZQ=;
        b=3ZXba306EUgfZduLq3o/gIf6rlSgg2SSPLX/O/IAg4eUxoaOgdtrtwy98P+b426pn1
         hMjnO243oMoZenajkm4kTFh/R74f78rIGPTPak0J3K3nZ4h1Ov7YyOQIAPHlnIPRmvQC
         Kp3WuUsCwKoPpGwtikfgoMZlWYZygMfUENAzjukTjjGHsrVIvq4yLCHubGaXI67rSwbg
         xxq4ICVQbrmhdkV9po9JFK/BuiXBlL6rzzOb6u4MG/2THDYkFmMlacH0G94sHmfSPuV3
         j0DNIKzLlHN+GzcsNmV2kebgp/WsuRRqIOqj14LG+0jBq5MpUxBX9Ro0FFWYchBfiNUt
         p/Ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pxvcqNLIEJITJL81nib4EZkj6/aH1DbCbmsMO8FzkG41bjbx6
	gUmjUUC4Hz61q7O7bpIUbwg=
X-Google-Smtp-Source: ABdhPJze5p83BX4BX1h5L54/jctodpi4IlOTV+aUu5mUKaFB/wV/iiiEUVf92+FmBjndHlXhCgMn8Q==
X-Received: by 2002:a17:907:3d8a:b0:70e:6b1:b004 with SMTP id he10-20020a1709073d8a00b0070e06b1b004mr1315468ejc.61.1655151520731;
        Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d1c:b0:70e:611f:3585 with SMTP id
 gn28-20020a1709070d1c00b0070e611f3585ls139428ejc.8.gmail; Mon, 13 Jun 2022
 13:18:40 -0700 (PDT)
X-Received: by 2002:a17:907:6e01:b0:704:8c0e:872f with SMTP id sd1-20020a1709076e0100b007048c0e872fmr1285310ejc.387.1655151520013;
        Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151520; cv=none;
        d=google.com; s=arc-20160816;
        b=UDPnqnKM7jGYe1mldqlcNoTSND5f9kb6cnTohbgFvxmmHtDQqfJ8DgdjlQE3Y1tp7z
         f8CI21Ynqlir04g7TZbnI44E0kuL5NRW1RZUQcSyW0bgsWkiEFwsDSoO36MtFu0RhDhk
         fxNtXdjWLjOxUMTO9oKerLqUrarJ45eNBB4GJiggMuvXuNfQf2SxLBA80RxW8Qg5Rc3A
         /DLFmYUfO+EP7hsRX5qn7qWvZEqtxzXKy4OdvXlAsncf8ICssg+NR+eNjbRbts4+KEyV
         Ld/uDF+ze7Je4PDU0sL1Px7QwAt5y9GsGBQBLWan42qjOkvNjSfJT87DGJfz+ykRMzGZ
         Z4zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=T+1jiBrKGTOAkQ9I8eaP4PIHMCNWMSHqgu/PvHey6xE=;
        b=fM/n4HKi5KxsWmUQgk2Dv4XiFjxU5cjYgSMa8dPegUz3o5TyG1cREDcdneSxfn/Ksl
         XSFqpEoTEz6mFHSa/z9cmvorXtR8G/cRH2llm9spswa6vO/mc02rpSh4VxPo4jPcrrhD
         9jXNkJO9+nttae/XsowtJXcjYpHVe145s4Sv6s2ow6iAeLxl8AAsTQ2yPOY0+qTo/eZA
         GQy2mvwnBWB0a85mHkL+zkh6OZgteOyLJsLVDs1eVyEI875yKk6btPjdycZNC3viqF5Z
         fPSlK+y5fckQ0aXUSgL2fE/wmMJ/b6llu2XcDZQnHpDonEv+wWCA/2hwTgZBrEg9Fr+7
         NFKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F5EnSyRz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y27-20020a17090668db00b007104df95c8bsi353368ejr.2.2022.06.13.13.18.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
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
Subject: [PATCH 20/32] kasan: move kasan_get_alloc/free_track definitions
Date: Mon, 13 Jun 2022 22:14:11 +0200
Message-Id: <8c647863a2ea158fd2ddc0c79e5e937bb03d86f0.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F5EnSyRz;       spf=pass
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

Move the definitions of kasan_get_alloc/free_track() to report_*.c, as
they belong with other the reporting code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c        | 21 ---------------------
 mm/kasan/report_generic.c | 21 +++++++++++++++++++++
 mm/kasan/report_tags.c    | 12 ++++++++++++
 mm/kasan/tags.c           | 12 ------------
 4 files changed, 33 insertions(+), 33 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index aff39af3c532..d8b5590f9484 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -512,24 +512,3 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	/* The object was freed and has free track set. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
-
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->alloc_track;
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
-		return NULL;
-	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
-	return &kasan_get_free_meta(cache, object)->free_track;
-}
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 348dc207d462..74d21786ef09 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -127,6 +127,27 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 	return get_wild_bug_type(info);
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
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+						void *object, u8 tag)
+{
+	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
+		return NULL;
+	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
+	return &kasan_get_free_meta(cache, object)->free_track;
+}
+
 void kasan_metadata_fetch_row(char *buffer, void *row)
 {
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 35cf3cae4aa4..79b6497d8a81 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -21,3 +21,15 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 
 	return "invalid-access";
 }
+
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	return NULL;
+}
+
+struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+						void *object, u8 tag)
+{
+	return NULL;
+}
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index fd11d10a4ffc..39a0481e5228 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -24,15 +24,3 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 }
-
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
-{
-	return NULL;
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	return NULL;
-}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c647863a2ea158fd2ddc0c79e5e937bb03d86f0.1655150842.git.andreyknvl%40google.com.
