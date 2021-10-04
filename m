Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMOF5WFAMGQEHQUYK4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A73EA421859
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:13 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id d16-20020a1c1d10000000b0030d738feddfsf313405wmd.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633378993; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpVWaCr6DWouk1vcurDc/vpGMXVK8BU7Wxbb+3DoNT4rGGgIpdvuAEx6PzHJodHRmR
         0gmF1zN0FTmqANjwBKECmBJzMo8QgZr3XhKzDXXeHfi6NDKt8mspm0qCcaA37er496r3
         +mNDLDc0iQo2nCyr3oaYy4FJe80Qz+YVA8i7MNjSybzTGStSJ3+ybr8EGj2vdS/F9h3y
         4BxyV/f6ptMppS0kLv5Lw1Ev+RcfCYNCxy95x1UgnNFuwVE75xPx/Dt7xcpRM+YpWnc5
         p9ZO+odz3xfM87u1Oidyy+J4jrJMjEMjGyA5s0rx+U7RGEqu/BPLgLVT1zshlFUR+WRv
         CaKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nMf+gZW1BXGoJAl/EgM66fvhorAQzEhspQy98495cE0=;
        b=0KHyO3xTHKTReBCXNnVOmK+Aejm3xbrIOmurISpUMi1Lvk2LR5ZAZ55qvFXQRYzjbN
         TWCsEctIDlhx0yLpaKbb35yeJ+W4Bm8d9IN/vNRUO3xfcsFak7bqpo/TyeLHMihTJDNB
         3LkElI85fyPiDFwiGHJGXMjLsGsBtsJpLcOdHUiTR47JhWSEnVkGKGbKoTXI34RtglVP
         opyZUWXFQI10CWDPgM+1TQjBBI92bS9ujgqypI/uz3Pbcou9o8KOD8leWL2qwiFZUmkb
         GQJC7UXFPOXNG8pEnNK37CTgOCOgiy1XpQMmJvI5FsXkXHKPYGDDB75xd3crHIceBaKJ
         Y98Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nMf+gZW1BXGoJAl/EgM66fvhorAQzEhspQy98495cE0=;
        b=daA5F8d4/8/hsfAJikI5THhpfF2GhpmDkYDVu9Xtxz+mp7sD04SYZlzm6zm56IyF4W
         O3e/8XjVx1vshFHqvloeuOOTxVbi95zq9YYoE1Xty/97eVTrrHfThoOZi7bmW9xqYTcE
         6TfLXD8t9sXcSMeZNpqTztWYJDceLCAHLmsP4l1KQBTU18Rr4sAPpINX8Ura2w/54qAK
         SPTqjG9AWWNhAWjwHKJddZs21ZUHF9C3PKQYkdEj4rl/QkXGj+u961qz/OXY8Sx3RmnF
         s2nyqqsW2YK16BN4Sph8FHg/R/Rh723m2YQI5pCXihf+QbVCt5X+PbjT8FwgIDyiYig+
         fF2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nMf+gZW1BXGoJAl/EgM66fvhorAQzEhspQy98495cE0=;
        b=skS95rtCtp5dM0P1zWJ1HAIqIMFLdMpb5GODdcgPEug4cuG0UwtBzwYwEaKw4e0N1k
         o239Gf1fWC50/dLf4NIvH3hGy9FIixy/GbouQVYOytMJfF8Bwu6QqVPPSkTzSY+M/70n
         /s4C9jkisJrt7XwYMQPIS0saMzfvSqNZsGvw0F89oTxff1FkmaIwWitgw0uecIPlFGq0
         E2T2DJkERRQD6cXhqFoJR3dBdts+H8gIZ6c3xqjIYrRVJSb722DWvbdgWfWMLdbDDFCo
         qsJRJc52wfQqf9XtOGgssB3y1y9AsAJlbiy3mW53ACFMYslxbsmez/UJ4mHgglr+AD80
         k/8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nYnPIz1st4mVQ/nQp3EMQo8FqHBap5MADaCx/pOt/gCowMyzd
	tPA0mHjxepFz88yLAToIGB8=
X-Google-Smtp-Source: ABdhPJwWrxcyFhQS9MTAwJYU5eWLH4NUeqMr7D5Qf0I1Qgjq1sKk6K/RILZoNwa9ubBA6G44T7MuTA==
X-Received: by 2002:a1c:7905:: with SMTP id l5mr20696576wme.90.1633378993447;
        Mon, 04 Oct 2021 13:23:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3c8:: with SMTP id t8ls10341566wmj.3.gmail; Mon, 04 Oct
 2021 13:23:12 -0700 (PDT)
X-Received: by 2002:a7b:c359:: with SMTP id l25mr20486413wmj.84.1633378992617;
        Mon, 04 Oct 2021 13:23:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633378992; cv=none;
        d=google.com; s=arc-20160816;
        b=s9LRmv3JDJxIJISxWzDA3x95GEVflwZIY0aYPISXXnrz6jz8BSlECtpdwUkD1YzREZ
         QveHIQDbahYD3JUB5Wtw6nkTbAQrKKQ3x3dD6SaTqkwx3kdfvI/ty9TNBMOVunSesYww
         +4ONIbX8lL06g5HYiiqTq8p6SMO6ktMQdaubjXXtdYLdbf59KaCEPUd6Sbj90nSlRFP7
         hS/gY/6B/pImweoxnbPTPTJLhmAuF8dp3HtZWx/BiTTncAhEOv6RgTMGZdPIa5NbEagR
         h0Fw8jNL5o3copJlz06cspiJ03Ms7dNu6/+1GcE1QBJOVU/wNCBomPD9Uigg2UFk3txa
         GI/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RapyTwWeba+y7tCKIlQPQjKJo2fmz/nY0R26UQyz7u0=;
        b=TRMuayWQvzUtJMXdlT92MI+4ik6hz9KFyPcWMgcDJC2Y18Wp/309umgi2Gy/McS/RJ
         tNgQthCAx74E6wvOHivHN5dnxrHzXqL6ZSEwBhs5CVAf5yPyKGKjiiKWMlYKGTE7FUtO
         7dYt1FvJcRu9AFkR/1nrO8p55dnu45HRSn4ClWSWMIO9h3Pm46PyB+cDjULDkcvAjYVn
         2nUHqZE48sn8d9kjGiF+6DWH2di5Bf1gdY2eJuTUVAC6sgzzwT3+vv7iXsENWXRxaJmP
         Sv73AFBClitWNbYls9jemnL5r8Wh2+LUszjaysdKvRSbcwDnnx3ZSZYS29mTiYr23Dic
         LSSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y1si738993wmj.1.2021.10.04.13.23.12
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B1B5CD6E;
	Mon,  4 Oct 2021 13:23:11 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CB6C73F70D;
	Mon,  4 Oct 2021 13:23:09 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v2 1/5] kasan: Remove duplicate of kasan_flag_async
Date: Mon,  4 Oct 2021 21:22:49 +0100
Message-Id: <20211004202253.27857-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211004202253.27857-1-vincenzo.frascino@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

After merging async mode for KASAN_HW_TAGS a duplicate of the
kasan_flag_async flag was left erroneously inside the code.

Remove the duplicate.

Note: This change does not bring functional changes to the code
base.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kasan/kasan.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8bf568a80eb8..3639e7c8bb98 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -38,8 +38,6 @@ static inline bool kasan_async_mode_enabled(void)
 
 #endif
 
-extern bool kasan_flag_async __ro_after_init;
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #else
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-2-vincenzo.frascino%40arm.com.
