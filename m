Return-Path: <kasan-dev+bncBAABBH6ATKGQMGQEMZ6FC7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 139804640E5
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:05:20 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164sf14524963wmc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:05:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638309919; cv=pass;
        d=google.com; s=arc-20160816;
        b=XaPaZ8EZmfXvQae8iw5v0gUg9oyyBZNuHtYull6YG5HgUX3DJAlRik39ph+J9B4SzR
         BIqAZ02J9Tdvp02gyuNQ51R82kq9M2NKOtUzEY+droE4WCdXLMFMwpXT0QmxkBzs3kJH
         vSxrtQ1P3l3OBMRCE5I9UCdSJ5nCnHIoSflNb+Qjo8Ui9uUFj+e62Jdc3jKnC34O30uI
         VhWAvlZuEhMhjlGUHyEzQbGpDvIXeYBYZQ9aztqnabaz91vAB7DcgYXfkFan4MBZ/juV
         dsej2VH0CF+URPLEcdEQmaToCDwr+xDStBK6CziMWV2g6r2kiL9/W/TH9H26z7qu9ZV6
         Fq5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HJlz+RWbx4Yid6tvJWCPdmzlsNK46uVcHH15VLaed9Y=;
        b=lM4ZgZn2tl+EYpHtACc441chy8ntxaYV0FWIQEs9VFNdewdqTeKJgCmOBaGmS9Ivrs
         kZvROHcZnjkA6MqZUjEqTtRnaJGBKmljzPnBZB+T96jgTHCcgBq57NpXz9Yson1VCryB
         7LfvJPqWdMm5InahZ5UrYG1hMMEp6muge9zEomvQAywMrAS/Q5iwL7LK8FRm9e3f+gqt
         /xOZpxa2ro2vUDLTerGUGuBZaX+O3UHWKxKgZxmedIuw3MW7RRB4ciSZR6T5reGzFJMC
         2eq5HD7yH6rP065fJZe9FazzZ7wV+ey0krEHmSHhjpTc5GXzCEj06YTzevBBMurEBwpW
         8MAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UKwfrCxe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HJlz+RWbx4Yid6tvJWCPdmzlsNK46uVcHH15VLaed9Y=;
        b=lXQH/asla++fvEYMUKJe60tK5AgdCp2hyIvaKZr+adKzab+CkMWj8maC/bdV61XbKB
         og0EIW0gUsW7q5k1zjadtPms19a4fBx5i3ev+mFslcLJCarzw4ubbp0BwBSJMhoTtkIw
         cHjq+KZ52ecO7W9dSxmVrBCSLJzbnLsHnX4UvOdz9ePkVtpRrJtbORth2aU8g4QWNsL6
         pD4PITDDu8iuaVDMRX74k8jqz/Zu10s1+XSeUVogAjLR7YOpfZv6FN3b7JhoNIGLMjkS
         ijfCBPpL5dTz0YpuVVtAcy77dGd/QbEFaummWXSCF0V1lR5xFiUCdA4xQTbyQMlMTkVa
         I6sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HJlz+RWbx4Yid6tvJWCPdmzlsNK46uVcHH15VLaed9Y=;
        b=dyZTfbDsVIQBHkd7BV2Nvf0yKYrukpqNtu2OaEm1KkYyZq+fy4CmJEmgnq2jCNGDAH
         XGU42KDe6s1UrTiNwIY5/JLp6aoGDhnz7Nb5WXIkY6qFSwaxbKpS8gzBt1PG/SFeo5VN
         Dkjc/q6OVptjVOqlz3xGBEG7V+vFVr9WTyBqPnjZifSg8BoGmUg1f01wbaRub0jJRUzF
         y8zGTJyBQRHU7W1OUh+2CMM7poGrkyYsc7qL9SFZZpaqyepySybm+6vACjCxgbxiDP3o
         KQy3VTbr5UUTmIcrTC7CdB6cNBWxcyh+9O17JKoSY/Bq6asewIwcKK30+6DH6ctRb4Um
         3iAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dIBfxRU33HWUSDC1cVlgQKWtR7zT65CiGHaIz7uorTBADccNP
	kZOS1HWZQcN1z9coWujgsoQ=
X-Google-Smtp-Source: ABdhPJxNYVGKi7Pf5wPbu0CuMG3kXuDwIA3fbLjNCrY5Kegv3PCJEd3uHv3l1GYLyimLhHq/SIJxdA==
X-Received: by 2002:a7b:c8c2:: with SMTP id f2mr1732067wml.63.1638309919844;
        Tue, 30 Nov 2021 14:05:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls192567wrp.1.gmail; Tue, 30 Nov
 2021 14:05:19 -0800 (PST)
X-Received: by 2002:adf:f2ca:: with SMTP id d10mr1841691wrp.79.1638309919227;
        Tue, 30 Nov 2021 14:05:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638309919; cv=none;
        d=google.com; s=arc-20160816;
        b=sWxTCmclOR3CtgLo0XrLa1kJK/6zFYyETZWnanedJY5UA/o8rmGfYrVqr5Oaw2aUl5
         u+xdIKT13E9x77aY3JG+qXgsrejdqxPLdSE38jNe/VV3N25dD5wK3Zi5FMJ2oQfytH8y
         9nHK04BXbFp0GlMi+7Bajef9xGfN6lmQ4I5qk5M20CXTAj+SokSSwoXVd3bNG/jj0FUZ
         s/7wlYhLBZDBW01wY9JC2ooVJDVIBW3/BSokZBZSp+RhtybHs9U7p5WoxPd84TBVjdQP
         O6fWOhS3vMIQ+2rL3ViLA3e6ELsBY0teBsLxPPsaJWg8kgdPPKkig0b3qIYediDVZoIQ
         N/ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=whZgRCTMmjC9f+f+aMuttd9b8g4xgLeF5Aiw73UkA4Q=;
        b=bGiVBdVefGORIsbghCBdooYkllKaajoqLlzLvm/hi7qwujQesmkZsMqphv/W6WpDnQ
         g/iIj72MpP4Tu2gIn4mQPC/lEuzg+W9mLiQ0rZMvkzeSkUD893ZeAG5GmDsUsRPoZuta
         fjd6Byp0WMX9u1xxaizzbkNTCkD3Qcef/J8DCd7O8BdvhkhkQXmqXgto2n23zEyLexwE
         rHGOj4ygSprymLPqB/ESTJiVaMGoFyDHfOxFRR+7h/JDL0nEgeWLglyvbdCkqykCsXXU
         zy1pvj+zmXePph0eCqwsh8+Hjic9AEU+lAAgZ0K/iqGcYt5rP8dtAa0qD40WQTQsdbDq
         ENFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UKwfrCxe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id 125si538666wmc.1.2021.11.30.14.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:05:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 11/31] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Tue, 30 Nov 2021 23:05:17 +0100
Message-Id: <e38327856eb2cc233e478e22e618d9f0454db62a.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UKwfrCxe;       spf=pass
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

Pull the SetPageSkipKASanPoison() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patches.

Also turn the kasan_has_integrated_init() check into the proper
CONFIG_KASAN_HW_TAGS one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e3e9fefbce43..c78befc4e057 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2421,9 +2421,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
-			SetPageSkipKASanPoison(page);
-
 		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
 	} else {
@@ -2432,6 +2429,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
+	    (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e38327856eb2cc233e478e22e618d9f0454db62a.1638308023.git.andreyknvl%40google.com.
