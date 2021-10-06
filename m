Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNUK66FAMGQEN7HUAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CBD2F4241C1
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:06 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f32-20020a0565123b2000b003fd19ba9acasf2340127lfv.10
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535286; cv=pass;
        d=google.com; s=arc-20160816;
        b=biaXJ/tO6N6SK9/H6C3FpqSbTQ7zRQZwNhpHotG0lJEJyVajAlMW5YNcUZrmr/JziR
         k6ZmVCSyb79gwt7DQqOsJ+n5N3tTorN3FqyaJWG2CgNfqahUXUCLf31v8JJE60Plu0JE
         734iyt7NPHQA/ELJ0jqumFwKsP03cqA0/fGwAMQ6hNOh1ouuGhlUAnEVt+t+I6HxGaR4
         /e3yhvOqJHvy8JC0IcNmu4tLUihn9u1rAR06N4XD4RZevY4CrZqBfoJlBwi74dWY9XIF
         wWW5m/NZ+9cvJjFgd8j4YNMQpUr4t3HMGGAaorfqsLNtswBy8A7hJRftQNhTYuiUBoeJ
         DmWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r6oGf336x4hbaq1u8td3R5c/3EtW+1oU6eqry17Udwk=;
        b=mpNXzUO8yuga9D1ICDXAwbrJG9QMFt4+jpjgZtKKyc9XZwOW+2ib2g7rLDWF/cMJAb
         iu3i4coZ/5z9k7KrGuezBum2NYD10IWtm3FVbmDauC+iFuLKhmwuN0BVeRFCXe4ySWKG
         g4lZxvIXkuyoLKBISgiilxdKgygzOcv1dNgMWkQS0kQb3Sb4JOqIQOHK3As+T8lUtO04
         0p0lO/BDjI480QhLKcq+ZmXAm2wzif2nqudOggT0GIVEPx1bD55OfLRPrcvEXekX5bYk
         qEuPPtI5UAWJ6gjGmTcJwJGRsEa+tyWWKZWuz6XymMdcwilJ/5Yztqb3VkuvPHGZK8eb
         V/Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r6oGf336x4hbaq1u8td3R5c/3EtW+1oU6eqry17Udwk=;
        b=NQDowlPLwzq5d6qjJjrAOE23unYuXwjLPBpuhE0he9FDfFkOuyk5kgEqTrbIU+Btcb
         TanBWO8ILSFlTntidnVC3fvSGpYwieRPX3aqTmE9uCYK2mmoBUAUOsIgRDkUkMshaKjU
         ggjiQVVZUK5w8jmJao0TFU9inddTlaC549hTWBs71IQMejz7TKzwaOTvquio+XbXQ9Sm
         +mjf999I3V28Pb8bUIlvnn8IO67ELFr2PqDwGaw1Rhkoms+VkXscg77j5vWVKZQK5PEc
         pXFUYWZAK2um0DR7bwB7hFCtJmVk5+0nnQRaGDehhIV/z3/VjXVTHz4AI9AbO6ANk7Ea
         Jt5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r6oGf336x4hbaq1u8td3R5c/3EtW+1oU6eqry17Udwk=;
        b=0CCIXs+amHmv7iunYR7/miBiI7TtFH7UAX/eoN3EX8qaU09cdbuui4hIu9zehwzCz2
         QlbxJAyVN6UnP68YiiN6medbW01JiCIjmf3VedZ15+5h/pT2BwlIGN7/9XP0wTbfma8N
         lLoRQFYOnVfe0DT8zYLrkWFqDLzB3/DaeMfiJqUSw1L33nZv21EVFH/R5rGJQ8X5B+SL
         oPlN/+ZxtBhgoeB+fWUcLzcjUV67H2P58j9FtLYjr8mg5zI4G/QoaC2GB4Jkjz+Eb617
         AwQF8dVxbyQWkpdKV6QOGsxxzrb+McTNCt8LCzug5FDkwaOyyhIiVDWCcYlaG7d50GEt
         yrxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Yd0tOZ43OmOLKNki5CB1dI0dTiTQyKMmU2h/Z2m9wlm5JnXwt
	ayKhUe8CxM9JNnEQyMcZW2k=
X-Google-Smtp-Source: ABdhPJzDhFar+JJTmtG2vmohCWd7EpPCEOkOkXGHeS2Y8yF5GWq2WXZoe42TR2W5U1dFafk8iywuQA==
X-Received: by 2002:a2e:9893:: with SMTP id b19mr30340609ljj.112.1633535286237;
        Wed, 06 Oct 2021 08:48:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1132:: with SMTP id e18ls55517ljo.6.gmail; Wed, 06
 Oct 2021 08:48:05 -0700 (PDT)
X-Received: by 2002:a2e:140d:: with SMTP id u13mr28936922ljd.298.1633535285276;
        Wed, 06 Oct 2021 08:48:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535285; cv=none;
        d=google.com; s=arc-20160816;
        b=edArVYnSuC3ILDWiIpqoRWLxvAy7y/KbPBSldI8/+vid62OrtS8gpPpxEPNPbsjtiL
         Y7jObH8s9LFZUY4F6tgPT22CXpcpNM0BOEUgMMPPYF2M6ia7jDQWC9EDqJSkKUP23CXB
         26twCQZmgLP9obIlLvgCeejUjPBsfCzD52tgsgMIv+ulvMez7BBwgo5MqmHVpJLfzCLH
         dGWE0JcwS/oUNFtIztOmpFt3IhlI1SUNyrKWiIzFASOUb7cqgPBbMqRh/KWuHe+7Tz2t
         2I7E2k9IIvlLG8E2nxnin6zYQrfgj4I6LZpfQ+jyqbiOF9XGXUZq5FKYf+xHYjdkmgbC
         V8Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RapyTwWeba+y7tCKIlQPQjKJo2fmz/nY0R26UQyz7u0=;
        b=wZk8MWOtrjBjqqCyt2a1ybMzC0uUgW09b8BgK8nadPU/bXLDFccmFq08iQBta7eB3+
         z4I0VulPNxkDmCrN3IphQzeyGzulvjQwvi3ydLKUcd5DjyDMv2tlbv5EpIMbpyjyBiTw
         5fL+vgXetoFX7GvjZY4R3LsUPs26aw+8ky0fY4QIIJvPbc3q2ze4m6SJcvYGMjEozEO9
         8Ggbxu56isZiGTiOkwYIBRWjUVJUIhyOU6/iItd9EFkTjmThnlbSL0zViu+iChGVYv4O
         JPz0Vj7ypRr+4sR5el+uu985YPLPq5ntwPZ4y26fqXYFBgsSMcAskKAcEaMyRq29QR4G
         gBGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a3si1389280lji.6.2021.10.06.08.48.05
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0DEA3ED1;
	Wed,  6 Oct 2021 08:48:04 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2A3373F70D;
	Wed,  6 Oct 2021 08:48:02 -0700 (PDT)
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
Subject: [PATCH v3 1/5] kasan: Remove duplicate of kasan_flag_async
Date: Wed,  6 Oct 2021 16:47:47 +0100
Message-Id: <20211006154751.4463-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211006154751.4463-1-vincenzo.frascino@arm.com>
References: <20211006154751.4463-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-2-vincenzo.frascino%40arm.com.
