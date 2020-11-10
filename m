Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUNAVT6QKGQENBJG4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09A682AE2DF
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:34 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id i14sf8447590qtq.18
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046353; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPhIev2TyUjsAAcGXhaCjfy0Yr40Ein6JtZYcgkLhgzcC9uGxdpW58fqe8yu/cn3KM
         xsakk7ymYyOpZrkhe2DD1i8RZRyqf6W9SZC/cgy1T4zL8/dQlcMuxajAT4Z1PJUI64Np
         +VHPAcoNLzCQVvAZ56/+F47Fz1jLDSnOLQMnmMbsWUNd5TzpnN3Ki+GgL87/cvTBiDUV
         wUoK3fOpN3xmzoqXYT3wntTISHTzni3Wyrx5u9Q5u7YJah1IyxTdXxXvpvdefNrehGQx
         QmeB/kWw7mgo1tGPq/Rp/Bk+VrJO3f6boAnr3bHnPtnNWejRk+5B5Bo7BQU48lVCZjPF
         GGIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4Znu9kkAN5fHcrc6aHpKaOIybFzBUxx3htD3K4thXfg=;
        b=N69I3eokpMSPfGLPkLqtPqG7+sCmdwaAfrLcpqIjixRrem68akSKlZO82pxHTq76kc
         BxGzbJ4IKyMhBHGn7AjwUkXND/qRqp3tPt82PM5j5X1n19jQqBp4qY+AMWdf61z5bG/v
         0pvBFLmb4JCM8x5iKwsPZ3rMlDmnogeZTFVtbA7H6XU0idq42bzUn72rGvWs2ffx1hgh
         bJrGpRk3qRHKe4hGVIcyUnWBH7zGyQtW4liomJbknCHrUlzgfSTim2en1/cHuPBO2ZY8
         G8lm2RkTUTiseqDlz6+jD7+5CVawlqbQ5NkN8srB9Iat9LbjPxwEhPD5zHATimOOxMVS
         wwMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rDfcg4Wv;
       spf=pass (google.com: domain of 3ubcrxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UBCrXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4Znu9kkAN5fHcrc6aHpKaOIybFzBUxx3htD3K4thXfg=;
        b=CnZmfFvQzovbXxagmKwfZ2vXru89+/f39+C4GjD6yJRVz3qKM5DNuvcyJ78Y+P3xgh
         naZZKYoE17Uq1ai/sJ5XjGOgK/LP88nochU0AHFvCzWI/17vm16TOPztuZK2iY3qdCah
         kQKNB0BVPShgP0/FhfOjQGai27KF1nSQiExRbE++RjP6U8m6g48J+KGTeIPBhNeFctWS
         6KUj+bvccEYLGp8JssoQSiW+464WFqGAXGk46Fq/ttkrZ8gnUuXiHoLmhUxg6Ll/Uu/p
         KyXCTkmlMVXqUc6cAR/Of/YWpPZ2qG3rRox3XGDkRLC0iJRQdBFj3W9+nx7oV8rZz9Ic
         Kn0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Znu9kkAN5fHcrc6aHpKaOIybFzBUxx3htD3K4thXfg=;
        b=ZdwzHFHDAqMD2+4JtKVuy/xEFxRIGCW7OIdaIEYaxTWsBlsoAdNazqfJDap1zaX3EI
         moVyH7MTel7eefILfvwecXrR4oFck1qL4yPAsB0GZ6kYF01BqedEDu6JIX3dsfYFlkzy
         iKmPjioEGZsKaNeYs6nc4QxmvhJT1tE0CyEefrbJ4uSnfnJluDtBmz6zccDw8IKYbn7w
         0kgLuDSRVP3fUZHCc71AxA93MIdMpZcHxQbC/uLCB7GA+XzIcMiO0IQXA34F44EubBV+
         GIf+AwydsZZpUu2NGad83/JJTodJhWOd+chkSZEreKV/1BsMdO6scMIX8dh8NAN8M5u5
         5AkA==
X-Gm-Message-State: AOAM532P0swJdGeu02VUYlbLaAbv7AyxZXjc2PM4S4Mj1XMgMd2ocuT6
	bspWN9oX97X5wMYamK49sMk=
X-Google-Smtp-Source: ABdhPJyxK0Zr4juoYt9+5KnPGQBAdI6TpIoyidlY74jRjf4nM45UzlP2M4/DIOkqiqJO5tnL6vL6HQ==
X-Received: by 2002:a0c:a9d0:: with SMTP id c16mr21543406qvb.5.1605046353108;
        Tue, 10 Nov 2020 14:12:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls6662300qkd.1.gmail; Tue, 10 Nov
 2020 14:12:32 -0800 (PST)
X-Received: by 2002:a37:c04:: with SMTP id 4mr22269665qkm.491.1605046352718;
        Tue, 10 Nov 2020 14:12:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046352; cv=none;
        d=google.com; s=arc-20160816;
        b=cMDCPJHiPt3PDPwOHCkjv7MOWHuiq49sdqrIgNXBvU7QGCXWVn+GzFdPWuutzCovc2
         bc+idvlj48S3I5ISqLMfEmer64w7qXanyZnK2trBxy92PGY3qWBh0+Kjyqol5vNjCxK6
         KZ+y+qAo3R+d1zfFKgZJwjFICLfNmO4qgXXq0Ug55NoiptGfz58SL5fhvHLxoCyGzPSl
         trunbnubTRDnjCOKgse8NdIx1E6wKywAu3UwcA0PtJruNFwxWD5y6h5ha2v0qMBsk6O5
         /zvD40JC5nL3ivyagrpTDAG4nH9QhN7Ztfn+qWWo8fU2Riz4/jKzXTV+Q8b0CCwCgMKY
         wjYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=OeZS4n3Ve5zgesVM2BV3JwByX9ZOkMptVCR7dAgVH0s=;
        b=NOq0OXSJJBnBASOWVRMJv1CPdjBtTfbhFKYvwE5fsAYFscn6z2+McBVjtEK6pGpW+b
         SeCGppKseXpxNB7N3UTsJRod2t+Cq8QCJeMP9NdJeuOP9zRejeYbJrwOggDmWx6S46Pe
         z0/t56NY4C2D3gqSjnKgTzdOTilCioUB+sVpNPqzCZoG9EVLL9FOIMyVbj3wFcC/LwGU
         nEKEaRWCDjc4V5rk9e9T0nIWuncfhOSkgbFmi0k7NLoIfWwum6LtbbnG5Y0zsYAqHx3y
         Fi9lDArZvlZ4W9KjKulZcdqdGvrUUYBgGBkZFEgATh4Emp02p0pipIz/WgeTWxrj3qrN
         ms/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rDfcg4Wv;
       spf=pass (google.com: domain of 3ubcrxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UBCrXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id g19si14937qtm.2.2020.11.10.14.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ubcrxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c18so181760qkl.15
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9719:: with SMTP id
 k25mr19774260qvd.42.1605046352358; Tue, 10 Nov 2020 14:12:32 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:33 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <71fcf23cd66d690afce1d80dc2f4659b2342152c.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 36/44] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rDfcg4Wv;       spf=pass
 (google.com: domain of 3ubcrxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UBCrXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ae7def3b725b..d745a78745dd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71fcf23cd66d690afce1d80dc2f4659b2342152c.1605046192.git.andreyknvl%40google.com.
