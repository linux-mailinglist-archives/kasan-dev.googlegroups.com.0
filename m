Return-Path: <kasan-dev+bncBAABBSONXCTQMGQE44DCCLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D6B378CA50
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:38 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-401c19fc097sf21921525e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329098; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZtvQF6LVz/h4gwZulGOB/tgLxzYzNnXSAJ7WXdY8dBhYRnYpWiZXScHv8wcfol2jNy
         ANtDHvsCTza0+cpwhqyIt1e3yBLk4kuj8DW+BXkoZKuwYMADTI8Faz0OKt50W0vp8U4q
         4h4cQFn/Ie6KUwrxSs6NxklT/E9NQqGPxcyWgSRJeI/nVqEIN+ubF3zSK/IoUXQjNBrq
         oDeGMwmNywm+VyPDgWCyTI1AaELM80jRjf+/BYuQLHsm/jWaEO8ZieZcpg0penIzwNo+
         yILw7NWXnwXpcUZHbKf1pJQ0N8Oj72JKIXg3sqWXs9Mf2LmhEHuvaSG9Z+cQDrNoKqkM
         OX1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j6JoIo12TUBNW08myOTi6u3j8UYY+6p81rpciXKlv7A=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=y06BrK9ZkVyrGUNtelN4WJTJMnZkSopzI3XRbReOTkU63+31+3skeLuxs8+7w3SneU
         JbDdhjAMSgqcjdRYnKgEOdOf9TEeAy3dFOPUYOqO0gVWyHCvaxXo6EiXpPRYWVdBYjgk
         fCHN8D5LbNuvVkpEfw68lcuq8PW5kPuPiP9aOOc9jR4hMP0jvZa50Zl8EwMEfl/UYr1t
         MEyBGbsEnepRKG6JIZcmtCMJpxS0MlIPttYQlc/mQQm5Laa2XN/Yle6ImPWRayMs/LLQ
         6nvG1YL+qLKqmCAMWSI1tlDG3vQMyfgv/s2wSvIoaD9a7nmHBZctpwSa64rYMfq/AgMI
         b8ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DeG8gVsP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j6JoIo12TUBNW08myOTi6u3j8UYY+6p81rpciXKlv7A=;
        b=J77eN4hf5tH7W6eCt3mw+2rvBglmMHrp6dzO6DtgOiXhLtSTh0JWeHdoA6F8StR4sa
         lo7NrZkAu7prc0VOiOHKSF2dFd3omgpbn9rk2gkRG7FZnklBrcvoopgwQUht9i0lat+e
         NS3ZKNETsFYkERFx+n0lOOjnTRp5bdOFjFJkHzz0nWKdUJsZ6pdj5Ve262rqM93/32yM
         0D9YBErn3jxV8tDQsyH88u6wNwsgg/ZR9pMFH6d37g05Usf8oX1TkY4R886IgYci2eP0
         41EZwFtO4qjzUUyheRH5PtUB3adNWL7pmNuD9730Ep3zv1J+p6S25BeXdL4po9TYUPUW
         NiLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329098; x=1693933898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j6JoIo12TUBNW08myOTi6u3j8UYY+6p81rpciXKlv7A=;
        b=jfgvruUeaRxoRP7iGwAvfZLnA27pmx0ByFPBf4bkvlEo2AibCBa/7NIsIAOpnztJvK
         +uDeRVTge8y0tUOTl6U7FNXr1m+d0JC37SDAredMxHheo864hhz+Sj37zGWM2zWDGral
         fiBTn60ZjGBOY/kzpAfMyYnU1p0g2zh5mWmzPZ20o0ylJ7bSrieHyeuLMNuKhGI5EgTM
         fxv8JGGXqIxqaWFYi8YgC123mX6I6ls5ggdSN9OhjKq6aZPZT6DZEp9Wegn4BWEi/i+r
         mxVCZCDZ4IRZrW7m1OZPzqH15jNsOqdI5RX2lGusW0PZDRr7ysx80mSkUls1Jd1sitx7
         0ZLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwNuiaYyzmizksSBPN8ykUjJAiwJrwaZ2+hgsGJLjLbks+QACs4
	9BGIdcY7I/m6wlDyLi8w8d0=
X-Google-Smtp-Source: AGHT+IGqRT695nKhLFIkwOvGKMPhUVNzJE/JiuSOZREEHK+PK5V4zC/4OKlyUifTqUab2nrqJBkadQ==
X-Received: by 2002:a7b:cb41:0:b0:3fe:1b4e:c484 with SMTP id v1-20020a7bcb41000000b003fe1b4ec484mr22145738wmj.5.1693329097394;
        Tue, 29 Aug 2023 10:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4c1a:b0:3fc:1365:b56d with SMTP id
 d26-20020a05600c4c1a00b003fc1365b56dls1347585wmp.2.-pod-prod-09-eu; Tue, 29
 Aug 2023 10:11:36 -0700 (PDT)
X-Received: by 2002:a05:600c:210c:b0:3fe:238e:b23b with SMTP id u12-20020a05600c210c00b003fe238eb23bmr23332182wml.36.1693329095929;
        Tue, 29 Aug 2023 10:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329095; cv=none;
        d=google.com; s=arc-20160816;
        b=jt4YYUFniphRI1I3PWmt1iSNQewnGvRbJCuyzzLKDIyNigowaPuDGkpFF/5QTVKwPB
         rYnTrUj2ENS7c6jAuP9iRcbOOLHnKAQyCm/w2d8Cm+rfjmbu+k6fjG2afloRh1Xwzg9b
         laWH4yyEoLfUFT6PVQMi33we0skAgL3FehKfRugOqV41zhjDzyEmhLLhDiur+bLMnjx+
         6U69qNBthz6RPMxRJtSW1MNP5S+Qe+8DdfU3nDgtlX7fj+X7ROlhAPZmdqzaS42aWR6z
         6Q8alSppRbhWR3m102++isu43zu4I2DnkSid4TVcoaoMZ7UA0inQJGge2xmB8qUs1Dvj
         YawA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Gxqstvn+9KrGAurRzEA5+xZd4FpeRy2hmiRTg5iKOfw=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=Ctip0u6nRlGyiFCWGZn1rJh0N+gEgATf9GvPPg+njCSf0hxK/o0UvdVBgOGAAac+FX
         sUViDT48aanCysZtd4kWh6K6g1ryCW3q/Id5pj9+iLa/ZjywfSu1L7yBw/zRaXZb2ccr
         dup1cb7LnCyJs8KQlhYJO8o2+w6YqlFAUcBM/xc0rBxKy74Buw9F6lAdteGzFe7BC2rd
         eVIHT5E+ODqJv/RBmi2/MaVmqgzoXvbBoKaW5r6toDQVrc0apjleIB07dk0CGobOCR2+
         hJ/9EbDZaYNtFtHE4kfr1S+ZZQ990l3N6vJWe8JvFAyMy2EW0YDKaNJGdalERDim5rtx
         Rf5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DeG8gVsP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-243.mta1.migadu.com (out-243.mta1.migadu.com. [95.215.58.243])
        by gmr-mx.google.com with ESMTPS id m3-20020a05600c3b0300b003fe16346f71si131445wms.1.2023.08.29.10.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) client-ip=95.215.58.243;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 01/15] stackdepot: check disabled flag when fetching
Date: Tue, 29 Aug 2023 19:11:11 +0200
Message-Id: <43b26d397d4f0d76246f95a74a8a38cfd7297bbc.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DeG8gVsP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as
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

Do not try fetching a stack trace from the stack depot if the
stack_depot_disabled flag is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..3a945c7206f3 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -477,7 +477,7 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 	 */
 	kmsan_unpoison_memory(entries, sizeof(*entries));
 
-	if (!handle)
+	if (!handle || stack_depot_disabled)
 		return 0;
 
 	if (parts.pool_index > pool_index_cached) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/43b26d397d4f0d76246f95a74a8a38cfd7297bbc.1693328501.git.andreyknvl%40google.com.
