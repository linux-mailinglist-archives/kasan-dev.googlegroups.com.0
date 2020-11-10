Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTFEVT6QKGQEUHL7RPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC3ED2AE334
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:01 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id t18sf3364306vst.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046860; cv=pass;
        d=google.com; s=arc-20160816;
        b=HgkQEr/HYAPhLtK5M2gom+rELfoXS09RkwPA2J+bzV3AR6E4qWTrEduTLWel+wrKdr
         VZvuqb3Suph6WQUD3Ay9FUKwqAyu38TVFHTPpT97MHz3qvgDH0lNLJop9mKA7TJw7fHb
         J67+l6/rTABsyiv2+e9OxqNRhE04pybECPu7zbSLASeT4PWt52aNCHZ73qYmEdiHVWm3
         ia+Gp3XOyEzsQTTLt5pNfDWtYsWlfrlMa0fBkWhP85EYWt+W1pMDf+gG2MOnWZkcSYTC
         t5gt8/1ukZGYLODOjnh4Tonkf7KTBHuHr5v4spf0voiOO/iuwotEisUTOiNGWzsXQM+4
         qIkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zJe5rHqfz5qFb9eyhe6cP/dzrAaxhYK3lOzXYTXA0xM=;
        b=QlAhEQ1j31Pq6t1RlSAWu5jYBjUQy+74rKe4xGRTvogzHRN4uL29J6L1hJuEIgE6PG
         UYhJM4B+SR1dJd7Gt0muxkwiabykpTkT8V5ixWyjUfJELnGAMdwk1hF2taqjhuBeo8Zv
         etbGrCCD+tmqV2b69YpymceNe3n8ujhZoKsXGxbYrgJPjrAXiuomtsGOZxIr14W69+uX
         lPDe6C4H0mh4qyP74YsdgVnfPcNMxC6EHadkNhGyiZphlCBtjaBMwIlg9hApRYTvdBOZ
         TzKsoVUAtLDJoStEuXTVxV0MUUyBTywxIN3lX/3zf71mENFEsQkl9zkTYgXu8WHdrK2g
         tzMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sorzbxjl;
       spf=pass (google.com: domain of 3sxkrxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SxKrXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zJe5rHqfz5qFb9eyhe6cP/dzrAaxhYK3lOzXYTXA0xM=;
        b=oYgaQOtQDUa2pAU6bPPeRs4B9Qx6Xd+cOzJlBhiNNmcD3GQOVJ389rUukgyD7f2jZG
         g8EVI9E2dBm9I6r3ndIPpOoirZ5Ke1x3XGk3iJPYpjvac5bKhymmDRw/e5RKdMWDES4H
         rDgTrmjIfVEiii01FT57Lp1CsIbqcGvX9I5xq0YnI7M3cYEvDt5itJtPQImhXmNT1OfK
         pCcYTqQnQgYzFPvVCUfSXjVtXTlBAyiauO/IzyZThjlOP1J4tMMRHNygnyP0XaxsIX/0
         DkBPHGl/HsTejvR67JO+nMS85liSzkBaJqepz2ZJyz9D+kK+LKlF/7yWuK7jTSkJSUpH
         8z7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJe5rHqfz5qFb9eyhe6cP/dzrAaxhYK3lOzXYTXA0xM=;
        b=ZXMS1allakRD0cuNqiDs+pt2FjU6dR1aaNf09hX5EtOt4BGKwElH8/w3QJTDBoMZM2
         Xp+YFlyoJ0daZel2huOsnj+MFbm2V/ontZhHD3QoJf/cvg8YQrunCrSSjUzIxyMWC7rS
         UWMMkQK6mdDHcrisxBdvACDXUAyZ9x3/2Lt/Ixe/zJ8PCapoMxrmf3ivQyEyKwNysDJR
         Hln8+CvhwDSjAKWKEtLh5qiCED7dd3XZQHvsL/eXZt6KZ1Hefew3JNUsvf3BqVVkS6y8
         4j30yjWovZhpfmJ7Fx2npVUVWDxGB75OITNOjP8TO8GsJOy++fSbUmaMgn//qUrBWhlj
         3zgA==
X-Gm-Message-State: AOAM5317BaHlbjpKHV1/oGZd3wkLlBirT8uUhO8mLKO2mkK06SEpVx0u
	DPSPzQsEoxwT//Nn1urp7OA=
X-Google-Smtp-Source: ABdhPJxK4VDJtHURFbfRoqsiscrrqEGzoanjIag1sijJjYlDcQ31miuxX2rMXUcEvm5srq+Cb+ouBw==
X-Received: by 2002:a67:1d86:: with SMTP id d128mr12637598vsd.55.1605046860817;
        Tue, 10 Nov 2020 14:21:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3fc6:: with SMTP id m6ls614538uaj.11.gmail; Tue, 10 Nov
 2020 14:21:00 -0800 (PST)
X-Received: by 2002:ab0:30ba:: with SMTP id b26mr11799901uam.31.1605046860361;
        Tue, 10 Nov 2020 14:21:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046860; cv=none;
        d=google.com; s=arc-20160816;
        b=YLZnup9IJ7tMStT1iTHLfUk4eC0BHuPdtYYc4um+/QvViZuSqDzWHg3XTtT3/1zGWP
         DkJAqtOfnAH1wQ7DMY5e1iNzl0G2ZFRxpKJbE7O/aXXkdL/OQT5rZrluiTrGltpY1Ibu
         rU3usPOhYY/Z1iqrq7byUsEVWgrfAYR4DbBDYRtg+1yIuBGfxV6ncR6Ym8yd4Ryn84nL
         j01unR7Vh50CaKzsuaZQrwoHrhJwiJK+8s5G39ShKHOmt4EumSFVzd38JEMmudlZs9qu
         SJ6FboboRDulP7VihXc0KoRhlSad8VlcBI7v9biNBcQEogN3r1m/rAHrC6cCnxaW8XDC
         BsOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JVfCx5YoVAhsMAMzq5Ib4xNDNXTPugCAXEdF/9ZfK1c=;
        b=S6/MPyYSThHS7SZZvdn/75UzgYZQnUydxyODhI+6jVMAhzahq9NaxMJMSn9WKdO9qs
         HMQPtQOqvVal4HT/h/YUnIWYMQQmZsU7wWZCb4U9x5v24Vyi1DxkqJChU6cWUAYtyyWp
         REKU4kLaZmK11oabeV25kBRcs8m8pGgOSR36cQ3tXSmt6NDfakmWYljrXlKS1iYPWXS5
         I7K7ehhrNFo6F1hjps27Iz59G/KlsJ66adlpRpqCV/fNnC/wfD74Qgt+eSPw9U5eDwei
         Mshmu6TZRvAPso012N0djv2+ZtIf9JQ7BKkn3cPdZ2wlQqepdJPosT6OFeoRlnxUCmAH
         etQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Sorzbxjl;
       spf=pass (google.com: domain of 3sxkrxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SxKrXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id m17si16392vsk.0.2020.11.10.14.21.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxkrxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m76so222692qke.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:00 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e790:: with SMTP id
 x16mr12244792qvn.21.1605046859712; Tue, 10 Nov 2020 14:20:59 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:17 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <a1c57043fb19effce240355e7c57b0d9a58d389e.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 13/20] kasan: simplify kasan_poison_kfree
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
 header.i=@google.com header.s=20161025 header.b=Sorzbxjl;       spf=pass
 (google.com: domain of 3sxkrxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3SxKrXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

kasan_poison_kfree() is currently only called for mempool allocations
that are backed by either kmem_cache_alloc() or kmalloc(). Therefore, the
page passed to kasan_poison_kfree() is always PageSlab() and there's no
need to do the check. Remove it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/If31f88726745da8744c6bea96fb32584e6c2778c
---
 mm/kasan/common.c | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 385863eaec2c..819403548f2e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -432,16 +432,7 @@ void __kasan_poison_kfree(void *ptr, unsigned long ip)
 	struct page *page;
 
 	page = virt_to_head_page(ptr);
-
-	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
-			return;
-		}
-		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
-	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
-	}
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1c57043fb19effce240355e7c57b0d9a58d389e.1605046662.git.andreyknvl%40google.com.
