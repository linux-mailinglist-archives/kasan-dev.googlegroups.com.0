Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUVEVT6QKGQETBCYJPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC4572AE336
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:06 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id w1sf79027lfl.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046866; cv=pass;
        d=google.com; s=arc-20160816;
        b=KGWdHECZMjpY6J9ds3EiKotuL1XV4OVicQOOw95eCqIs2W0PFBycPo3h7/dlGnotoe
         fb2XJjzJVroluepXrmvYMdyt3IlZxwMSHelNhgdMEcIf0k+yL+5YEapjmxG4VadoH8is
         tiYMUX2Wf8hSyONS0NKyBqLp0Up7gldOEMcU2hKt4Nk+oC/4btajzYZu/P7hxF07kcEx
         pXxroopuOq0yD3LFx14qWvyolrdO0nYsiXaEmD/yd0KRgbCYdP2WZlfnjpHDovJzrCTK
         h/eRkgh/C91D0TEldv4G3+5KYISKnkVNEWFykcuLG86l1+Ii7PUV1/OyZud4A8NjeSnU
         gChw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vyXICpychbbrFifmoN2i7GulYU+A8yfDFBKvK8rTMRg=;
        b=YMslZPFLrphebTvsyBdK0Gws4M1u3fy8rL6A2puL1JODYpWEHVAT9fOW54S7eT9vnq
         rp+4T+/MwCkAv/n4Z3hbY1TkcLOnIzJ/0ivwm4h06XtEn3KZ9qTArRJjVIPhGs4Hg3vf
         wEEEeHVyxVNIgbRts1up8msCASEj5imqaobDlZkdODGCkOmMvHNT2oZcCm3edwWngrrb
         WgnhqKetNyuVQiETJYqF4NsuE3KJoiGUnmQ+WePYOmTy1kp+fHaxzJY851+5CoUI6VOB
         cVVbkT8jUUvbJKtPSYvrJEejtyoySUQugPAv6V1xASjkqJ8g3wI5gLYUpZ1vV0tbmvcT
         4jiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uANlXR3C;
       spf=pass (google.com: domain of 3ubkrxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UBKrXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vyXICpychbbrFifmoN2i7GulYU+A8yfDFBKvK8rTMRg=;
        b=Qqfn5VUPBy26VA4K5STH87tWTa5ZoFq12F1M3ZHOrPC88mPIZsvlf/3RI2ZhaMoDmU
         +FycAu6V7JwEEVgIhel9xWOWRUmNDiCoGy100Cn2IB5QH50Fp4JD1JS94OSEJMc0E8sC
         oCsMVV2u4k78EbHTftIJNRHeGSdANfHc+v0cw+tmpUAv+jfn873QnfGcdDhN23WuS/kY
         2GsTo86tcjRETmidSilerEpR9P9Yzmp7HmjbnIubnnG79I+IueWpNb7GFRsoKSxqabLx
         +S6G1ia3TQfMMOUZ/keCfJatFP2vA0qc/me0dEwkpj8cIRhinXncz50950LQ6MDMlW5Z
         hTdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vyXICpychbbrFifmoN2i7GulYU+A8yfDFBKvK8rTMRg=;
        b=jkTgL08ZiHROMqShKkfwDZuC0T3d6u9eichQxhjUP24eH7rU2PaYyBBdA2f0lYckfi
         WmJ2FI/F/hJlXt0Tn4Df8swmOWHzKuzzDRM9SOl2HcUIA/STg+OHoS4Om1TLb9YUAi4F
         OaoDLCMdUf8shlSjUL1m1zGOyriH2rt2tgVeyuNv5D+2wIw6XgAZKRPvY8y66dpDaDxz
         ccAq+nVLz554o0YANDN8osa875CSPGYDCAyHH1ie8nSx754qT8MH614eyuWJTRLeMFga
         /COE6Dk++14R3MsUpyRKjH5N5idQ4JmJEGmNoVUdWinuOBWTNgBX3ADKpnmzpXTtuozs
         wF4A==
X-Gm-Message-State: AOAM533+FePxpA5RaY+p4bCivzRu4kO+SaJxueIg1CIxe39qwZ+To4g1
	5WDzwWUl4GnxrDbdu/WNPwM=
X-Google-Smtp-Source: ABdhPJxSfy+7Fvh7hvZjGdu7K/8eWagPLWVw07niWFUfv9Yh89F3qy2OdTGfFmYdNSawEtE6mT5/yA==
X-Received: by 2002:a2e:8ecc:: with SMTP id e12mr9396835ljl.98.1605046866323;
        Tue, 10 Nov 2020 14:21:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls1301446lfa.2.gmail; Tue, 10 Nov
 2020 14:21:05 -0800 (PST)
X-Received: by 2002:a19:794:: with SMTP id 142mr1336860lfh.232.1605046865432;
        Tue, 10 Nov 2020 14:21:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046865; cv=none;
        d=google.com; s=arc-20160816;
        b=S4FLnn0cc4xQPxzoKYIIFQ/qYe9r0CWDQJlOeERM+DaYBIDqLYwePGRE4f/GUBWc08
         roYaDgNvP6Wy+AsUl/2ky7rqlK5ZaLusrymMfK1AVmmRNXbOHPSrgruSnqZT7EkPIbnP
         DJ8riwLbCmWRolLzX0AX984Jymtvd/5niSa9sDRAcw3BWtS4Z1W9mHBbuxy8VzTNz+Kf
         X/jGsFkqTegno+vHx2qyF7cZDtFtlU1md2odioj5eSv+1J7Qe6cbZiXINw7aEDRZQXfR
         lOx2HS4D7ExXPRXNhkWEykn4jJQw9s6k8JULu0NMGCozsJm6e5E5zVoZZKNPaiGZK/nL
         jyAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=pq+zpW/Hw4XDGIR7N3eqf6sjflzq5qp4Op5FmJmOOa8=;
        b=nGybORfN3w4W28UsMAumbKlsCORFkjWE9YZB5AjQq/AFGdg9GM6HRJoewPbMCU8WrS
         Y+yygl5tBIxCsIz8/KeIOxD+zk7r3Z3ae3BIbo+Uv0ux2tIcTvffxX+NU9sGtD0aj9BM
         1b+yWGUioRFB+sumecpgocl2LSDMZxC7aa00GSscPCAThJugsZTAzuxS8sTTV+koDMrG
         Ird52w0uax5o6uM+NwukSAYsPADQbOfjTZru99pqOdHTRy6sl2SFUSN1hCJmL3zW9ygg
         141/uvY5PpwJiTORNq1DCOoaiAM/lRgqdK8frthS0tv2+vhOYPkSDq4gen0UbS/dUqsJ
         guJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uANlXR3C;
       spf=pass (google.com: domain of 3ubkrxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UBKrXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id j2si3363lfe.9.2020.11.10.14.21.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ubkrxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o81so1241505wma.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:b387:: with SMTP id
 c129mr303876wmf.58.1605046864904; Tue, 10 Nov 2020 14:21:04 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:19 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <b11824e1cb87c75c4def2b3ac592abb409cebf82.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 15/20] kasan: don't round_up too much
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
 header.i=@google.com header.s=20161025 header.b=uANlXR3C;       spf=pass
 (google.com: domain of 3ubkrxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3UBKrXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

For hardware tag-based mode kasan_poison_memory() already rounds up the
size. Do the same for software modes and remove round_up() from the common
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
---
 mm/kasan/common.c | 8 ++------
 mm/kasan/shadow.c | 1 +
 2 files changed, 3 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 60793f8695a8..69ab880abacc 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -218,9 +218,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_memory(object,
-			round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -293,7 +291,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 {
 	u8 tag;
 	void *tagged_object;
-	unsigned long rounded_up_size;
 
 	tag = get_tag(object);
 	tagged_object = object;
@@ -314,8 +311,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
-	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_FREE);
 
 	if (!kasan_stack_collection_enabled())
 		return false;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 8e4fa9157a0b..3f64c9ecbcc0 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -82,6 +82,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b11824e1cb87c75c4def2b3ac592abb409cebf82.1605046662.git.andreyknvl%40google.com.
