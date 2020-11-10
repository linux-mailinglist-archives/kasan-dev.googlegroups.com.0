Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVFEVT6QKGQEV3CPEXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5734E2AE337
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:09 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id c2sf92687lfr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046869; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0APVHwQ6E4wfpoo6VOfLj8HLcoY7OB9S1feaFwfyeGmOjKbv9x5kUW+g9vCVe1c/H
         9lsr3ycHB05XDS2LrYahlRVFjyVrBLCGc1xR4VkHdsJcOiasp+966bbBdN5Mb6b+moyL
         12EyEu4xp8UG/7toz/Nya+SCcSJCRS2/7HKUU0+GPoqgOe8fnzi22EGOrHFWk1e8T+zv
         UCA9W14HXbxocKJXsgWLPyMsFUg0NOGedbT3D5rxFoEWT1EnCEX/i3qnDuNdK12o1ZS0
         O+cixm4qPPHV7al2iSSNOBzL8jGN4c88MyQXovIQrfGcBlB2xY9i/EMjjX2E1QYBFGGw
         g9BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dKO4infNeQMJZXJ0AI6STECSU9uTRSk8YBgwnQ72qtU=;
        b=FgiGvQtvb3X1P96Fog1ZsLMSVB3pu3fFi0Vx1FQAJwWHtwa34QPGjRRCzNWDzyDypG
         fiIJHAggrs+pKjYfPwi6Er14iXl19Vu9fz7AfJndpaxz1UsfnEwKJDnFqtObnlqbs5EE
         y+h90BRJRuH4Y5PA/EkpIE20c0GrlI1Smr/UQCfUh5YaHQjyzXGxJpTaElOZ8sqaTmmd
         IZHHe18HWlFZeUg3LqgVExbdUJMgLJf598dx2B2PbO4mPmUsIDL2vEGMNKaSDvlL9Wn4
         dchqhRCf5GR8MqZ9aR+RdN8yCFo4I+KhS4CzNcUVJeGMVeg7RQ44pVuxqAVAy1BtTt4v
         j7EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QP7TuVPx;
       spf=pass (google.com: domain of 3uxkrxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3UxKrXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dKO4infNeQMJZXJ0AI6STECSU9uTRSk8YBgwnQ72qtU=;
        b=T5GUxSeLzlpTrk/HXsLCqy+0nOxut28d739iowfs85p1LOnPGj6EuUTalSgGxAEhQW
         4X7qRj4JYAgovVM2pfLxm/citl9wkaFiiYAh4v+1LH5w13OSSZViXr29039Ju5CBztau
         i2utmSpwJGLugZf4NA0sv5XwE+CmU6cJ5paZIZ2pIOucAB3amkXUwX3pg7b1ED0gOavA
         A/EO4cqzC+rUlkBJDC4i35zzekRPJcI88JrAwEw+8VXQ32j1djlCMz1HVhZF2NkR8Nsw
         5CRwfdXaG/HahY7Rle/V5WuvmMnIAH0tqBKi1FN9HE6+D2IEn/0t0cEjGa2gKwAnTNaQ
         VZ/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dKO4infNeQMJZXJ0AI6STECSU9uTRSk8YBgwnQ72qtU=;
        b=Fitv0E8KdhXocp3gm0ZdFWrryCbQ3zmnsj7d64w/pYfUqNv4bnXgVqX/vZrMAli1jf
         9C1rCS1DyYnGf2hztFLudLQ1WrmnnKKIZEVXLOo7gRdG9SYwCIpSzudCnSM2P5El1XKw
         +FhwIXnJ81v7TpkGxWdCCTc7xg7V4kEg02nNLj346uwLpUQGuryruzifS/WNrYfQr7eg
         055sTCSM5rEuHA7jIRJ3KM8Oif3dbOq1zRh297nLlIkysti/W7xltMfb6zlN9w04bsfD
         GR1xmZLvTmkARD/RfdC9LGyNOXCBULuW8UfphXi61fP6fK0MV+JzGBeT86/KuzJ5v3xU
         61Tw==
X-Gm-Message-State: AOAM532lu5Z8E4E/NhdmUX7rMQ7NRmf+Aj0tegaBj0SdPC0ijfDg3oME
	B++egugixOKUAJ/khXUrzSo=
X-Google-Smtp-Source: ABdhPJzNvP6q1gf5knDGEe+qtDhZJq1NaK1q7m1p87fZnK/7XSi5GpIt6pmSp3fAte1Qgrgj5u+tRA==
X-Received: by 2002:a2e:9208:: with SMTP id k8mr8737495ljg.369.1605046868949;
        Tue, 10 Nov 2020 14:21:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls2398926ljk.3.gmail; Tue, 10 Nov
 2020 14:21:08 -0800 (PST)
X-Received: by 2002:a2e:a175:: with SMTP id u21mr8910977ljl.160.1605046868076;
        Tue, 10 Nov 2020 14:21:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046868; cv=none;
        d=google.com; s=arc-20160816;
        b=I1ePo+/gSrEBIMczMa3tmK3rO7Ievi7P6vvYqteThnSWt2PX0ITXQxEMYJuEfqF1R+
         Whs4Binh3GYW8Rm7dhdQvwSznqXRoUnkDg/yUo8OmxpjI4YAa1UtoTwPHLWV2H5iGrTB
         4IiuEEd3OQfRD+qkr9QEvLpGDOovjxie4hRLim1gXKAJL313/Fzs8t7mB7ivdsZbHU95
         yBf7GWP5x2NmcsSY4fUG11I/VDyJSnSGs90Bxlx/HKG1JP4VJpVW8ltqpTT1ycKILsaN
         5fb5LoxfqQlYy8Hb7Ig3W8h643kklrsG0+fHyUPYcvbtDTLZv+jTCUfbOzJ7TCl3vMIz
         9Fqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=UUb16eez1SBPDEo4INNWK7vyjFOxlmk1eUi1izfNnGk=;
        b=gPao5zF2BWw7gHkEtHLOwGFXK0WJ/rt40woRWAh1eAUJwwXAN08ZGkk/lJWU+FU6jk
         ek5vRA/SDsOoKgiAliX+Is/AaqBPO5txiIKmwwyWQpDg5B+xnlEnOeTXIDTsCA4E/qJz
         x/0vDME11wEgoT1eThbluRQ6Ys9xUKV/sbi9HyiXGKMgsiGU5hboXP45qrK7qGf+NnJ9
         R/H2LqeH3/gv+FeX5Pk9+4p1VTcnORn3JtnNRiXiMT+70JBExhMxplb4DyXHEJn+HkIv
         OE/vBAEL3R6mwYm7abFEbH0DfUAtr6wGgmhFbqgUmY1F9xFmTwvgQYS6NGnl4hyrWZ9x
         iDyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QP7TuVPx;
       spf=pass (google.com: domain of 3uxkrxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3UxKrXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 20si2988lfd.10.2020.11.10.14.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uxkrxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id 27so36266ejy.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:b043:: with SMTP id
 bj3mr21951070ejb.543.1605046867367; Tue, 10 Nov 2020 14:21:07 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:20 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <eae2f21f9e412b508783f72c687cb0b76c151440.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 16/20] kasan: simplify assign_tag and set_tag calls
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
 header.i=@google.com header.s=20161025 header.b=QP7TuVPx;       spf=pass
 (google.com: domain of 3uxkrxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3UxKrXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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

set_tag() already ignores the tag for the generic mode, so just call it
as is. Add a check for the generic mode to assign_tag(), and simplify its
call in ____kasan_kmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
---
 mm/kasan/common.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69ab880abacc..40ff3ce07a76 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -238,6 +238,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 static u8 assign_tag(struct kmem_cache *cache, const void *object,
 			bool init, bool keep_tag)
 {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return 0xff;
+
 	/*
 	 * 1. When an object is kmalloc()'ed, two hooks are called:
 	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
@@ -280,8 +283,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		object = set_tag(object, assign_tag(cache, object, true, false));
+	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
+	object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -362,9 +365,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison_memory(set_tag(object, tag), size);
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eae2f21f9e412b508783f72c687cb0b76c151440.1605046662.git.andreyknvl%40google.com.
