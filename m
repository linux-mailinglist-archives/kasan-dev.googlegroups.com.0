Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVFQ6D6QKGQE3K3VJYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 477792C1572
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:17 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id g14sf13691786pfb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162516; cv=pass;
        d=google.com; s=arc-20160816;
        b=EjiejtrO8cUxbuUPJJG4ge2+xlXRkksQXbaRn3ee0nRKfDPbhYll8nJfeTpb2lPJUo
         Cp+cCVubGSrVsGOKOA7IqnPSdi4Ao/yh8O7Cf0fQ1sE2oJdk4442jzWtVEs50uVJrXp0
         GnpKj8nWeIxSDg0YbWfxOB0sXV+mXvlIRu7LkszBFp5ks//n6PaiWC0QTCl1jQwFXUJL
         Wd9qRpHE41uYoLLy+NqYSb+7d9Svk4WfZHB88RvQCealvzDi7RmuG8WIG6qTPIAqP+Tx
         /5n5QarQtiaZP9G51pDCimif/SD4XtwqtYmo95RtLvW/E69IeGv/lH1xgQ0yJfvG7J1h
         Is0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xBHDm8DvNkkWLRp5e9W77NHwTfD3p5G5OnFmeqeyXco=;
        b=Sgm1+P3unoooyJyfXvMO1e2ULfK3yQM8zSU4Py6jJRzvK/lph7isAMy/9B8s3luMoF
         cfbkC6vNl1A1x5Ah1AuiYNs4CPKOGAF5WDcOYxkMCWGUvufVDoHe0WhDZUVFdmWASgih
         3kwE6ioSLJfoVvj29Xa3nVRy0QyY1gnJ38SKbpMYJRVDXxkcEy6rYW/126flPRYtoAov
         j9/j+BZWlLhTJQdJC16OSB4pv/6wSIx80iG/3Dm7vkQ4k4zBCH6aG+iXJAvTIGueS72G
         HSebH+pyg/VqLlKITgVReInAMNZaOp7/6wppiWjJwSvMnZXckHKoIICiLUPCODf9wqif
         HDyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sEEd+SR5;
       spf=pass (google.com: domain of 3uhi8xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Uhi8XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xBHDm8DvNkkWLRp5e9W77NHwTfD3p5G5OnFmeqeyXco=;
        b=K8mDjJTAuEEy5lQI3ciz/bee/SLWyoUCs2miH5Uz72kyt8aRhyR4lo5meNDa17ZeWq
         wngkoCd1gCXIb+Sf5Msu+thzKJIOvE1g+FKL5uAhY1sXLccOJtzY0jxT2/mjZ4+4ibZW
         VYGE578xeDfunheBqvzGygpCHrdXWYE/i+FsU/nS7gEcYYsXhK8rTRzjLaUDY662y9+3
         0bGfRIE4lZaiCHFedvJeJ/2BWt9dZl9B3LN29iZIP433Eqk3IWJ8mbMxCLLRoCFdrFzE
         ZLBE5xPckcNpz1vFBihLEITMwplAumbVDQU0XhBUf3VFJzSjshes7suY/fQElQ4RWpvD
         JWtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xBHDm8DvNkkWLRp5e9W77NHwTfD3p5G5OnFmeqeyXco=;
        b=ZsBXOyELUt5kf5KlVkVSMaSA7vHkO2/48dypC/HxHtkRh8xemy0Io4JLSYG+rYm9yv
         syDaUYCScJxdSwPI7FRBtWfnhIX0OvB2Z+3IULrcT22qQ84Kiv1FGX/tij4Sl5SlSTgm
         4qWlZNii8LuMYSeGNtVroJTtZkuQuq0GJA+jnV/HB0bfpgcnG6EP1IUUXwBaFZemhpUn
         WGJlmcVk65+ma2zHBnFViitMQaZeK5HTa+tKbYaBPXmR4W048S+YIlJxlWysoTt22I+R
         0Hcp9fDtM//hJi+Vn3j/YFBgopFNKVtkdinfISuqqL9sNISwhKVyy87oA406AhsZWwZ/
         n4NA==
X-Gm-Message-State: AOAM531HZemVwHKBLs3kecnEh2mRj2vXPebmsB8MlgXAuWbyy5NlQUFG
	NzshCSre4VJLICU3ZwPXYUI=
X-Google-Smtp-Source: ABdhPJwbqV8I+qL6wxR+c9NFgycnDxVu8SdZdpw2QfHTry9ZtrFW8b757ucGt1V87lj5uAGclAYsTQ==
X-Received: by 2002:a17:90b:344c:: with SMTP id lj12mr629875pjb.115.1606162516098;
        Mon, 23 Nov 2020 12:15:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee93:: with SMTP id a19ls3580707pld.10.gmail; Mon,
 23 Nov 2020 12:15:15 -0800 (PST)
X-Received: by 2002:a17:90a:fb4e:: with SMTP id iq14mr683556pjb.117.1606162515613;
        Mon, 23 Nov 2020 12:15:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162515; cv=none;
        d=google.com; s=arc-20160816;
        b=eTNmuCWLg4Bq627lBe0ZD86Z1EO/Dh7vw+CHw8bxeKf22jbDCW8aosHDuhNPvVIu1V
         3OpHhehAB/4siV8w/PmicKIORyVxJ+gHQY0HqnyCZj6JEmrWC1KQc5M9phWX5ChZgAwm
         K1c9o/bCwi983Wu85l837kpKUDvNDZE7kmd6izYlV38g9EZcTJvhSEfpW/MQCOm65JXZ
         DsLEiC8jwJunfqGmBpSzC4mOVS8O647hpobtMLM9O7EtCo8e4aGDbA9GppmAY5XRvkUe
         cOaDLrQMH05mmVidgnOt1a8Dv9lUeVFb7ejdsf7/T7fkGQQlB9aqlnQubXJEz2t2CocD
         mXpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NLiVUxn9nGZzjemtf3cQRZI6tHXp7YKQ8dqUNAbFdqU=;
        b=rIxfvIQzfuJth0tr+1KFmNjsdjPK8kluQc61IMdW7gKXW703by1uERsXXl8osangKg
         Xl4FaKt0XYCYA6tj+r8aVjZuoGgRL6Pz3Hxe8Hd5OERXrLKk0SjkMKpn6NbJ1cA+o3Qr
         UrvTO/syPaCbC0ZpPtME9laJ11TL0rX37spNh+9ZJEBSsJzUINdV5NKwgcL2kQBqldaj
         4n71E+gXh/vjcTQ9ByWWXHQAjYVwd7TwgYNoeJVl6rGJIYK0cqVJihCemYY5MOElkK4Y
         9n4LDkQnuxcLHKZEun0ACADFh/h7gANqjSVLzFxvlhLUa5uByitnnUDzkUHSUEle9sBc
         Kz+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sEEd+SR5;
       spf=pass (google.com: domain of 3uhi8xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Uhi8XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v8si826894pgj.1.2020.11.23.12.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uhi8xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id r29so14383249qtu.21
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4a8a:: with SMTP id
 h10mr1086459qvx.55.1606162514671; Mon, 23 Nov 2020 12:15:14 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:39 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <131a6694a978a9a8b150187e539eecc8bcbf759b.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 09/19] kasan: open-code kasan_unpoison_slab
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sEEd+SR5;       spf=pass
 (google.com: domain of 3uhi8xwokcxcviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Uhi8XwoKCXcViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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

There's the external annotation kasan_unpoison_slab() that is currently
defined as static inline and uses kasan_unpoison_range(). Open-code this
function in mempool.c. Otherwise with an upcoming change this function
will result in an unnecessary function call.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
---
 include/linux/kasan.h | 6 ------
 mm/mempool.c          | 2 +-
 2 files changed, 1 insertion(+), 7 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1594177f86bb..872bf145ddde 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -106,11 +106,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-size_t __ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr)
-{
-	kasan_unpoison_range(ptr, __ksize(ptr));
-}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -166,7 +161,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/mempool.c b/mm/mempool.c
index f473cdddaff0..583a9865b181 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -112,7 +112,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 static void kasan_unpoison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_unpoison_slab(element);
+		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/131a6694a978a9a8b150187e539eecc8bcbf759b.1606162397.git.andreyknvl%40google.com.
