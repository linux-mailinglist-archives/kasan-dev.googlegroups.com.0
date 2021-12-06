Return-Path: <kasan-dev+bncBAABB5UIXKGQMGQEMFNJVOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CD91246AAB9
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:26 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id a85-20020a1c7f58000000b0033ddc0eacc8sf181139wmd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827126; cv=pass;
        d=google.com; s=arc-20160816;
        b=lmaNaiZv3oAw3FZCiPH0u9oiUNvdFHF4L6P/IbMderMdIPB9GlGs1oBpw5qAGrTXIK
         Bsg9p1fhYgHo6MTxOLkDwChsv/XpoRSoeJRWvZ/xUbs8yKzdxM/E/qJdf7ZmyfJDw6gm
         tUh7VOmR+iuK8Z4l+xaiDocWOyEKi7AlFqM8XsvKeRTGOXPvyb/iwgJlcbYPLzR/r7K/
         qD521dm0yf7yp5aAUvWu2XJXBQJNDq982hBQDd0GRNMhI64ebnRpAgLQdOtOeFLxME6i
         BWhynW5VVIlqCdmFjefzJs7tW8GPy0isMjuYmRd4G2McrdqmwKDhgzvlAULyTXitom8I
         28Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Tk8rlFTC9Uwmu5DOLgGopgcIYlW/fWBPGkPFvE31rO8=;
        b=GnwtDfgtbKZRC9Rxc41YMhUfjiAzn7YnY8+RAVZTikhraRn6I6WHXCa8VLSsCw2fnB
         UUpvsSN1QIrdrvyg0xkuX4BqpEoSLKKlbaU0Ug2pcVVVb2iKHLLMo1QeNFC3slEgzFdl
         QN4IdCjWKQYapxjDwGqIqIN6KokiSlxtoLKWD3p0T0ii8eGcfCfAm7z+XlNd/fx5qQF6
         lB6TP+Uo9L1XBk1arBOZLavq1uLzHXyJDdkDee7Ijq8gatD2NXrk1z+iia/k/8NYY3Ko
         1+wYwEy2zyV7U78++Isk7xpXp5PzYTYkI4Kl7GIvjv3pUTe09T1G4ykfBg1Coa04b5om
         rBlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ka0h1Ym0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tk8rlFTC9Uwmu5DOLgGopgcIYlW/fWBPGkPFvE31rO8=;
        b=XIV24+bIOwUO9o0ZDN+bjm7yVbf2w+YUh8Zt/71rMuFR9KxtelSczIPeFb73XY8hHn
         uWTYTvaAr7ctIjKbrvmU2TW1xht6ANzDIj1/b+TA6Pfi5GPTNPzKdMtMSi9gPGpZxcXO
         7qMLEHE6jyD/W/wpcjYUEd280UFSL2D9qjO+OGTvIiQx3oTYNWl6vF63Bq+BS1hpB+Yc
         Y3Vs6/WR53FPBamoRXQcX3zMoTItVYfghc00sfkLx6aDvBCX6uJimIZnTthixEEUwUB7
         0CIgonkvWz7rgGy0MGxYufWvGOecqmy3HMlmYRG33CjZ6dotaOvgcpYdhraKZ+rNTd9b
         NSvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tk8rlFTC9Uwmu5DOLgGopgcIYlW/fWBPGkPFvE31rO8=;
        b=cGcsf8CLAUaydh4Fqypcl8fi9L4T1pZrfXWVUPEI9Eeaj6BUNTRzhVgEXPJ6u/hHgD
         Ta5demo0xsLL3hdsl3pgyUJT4RSRFD7dBqJbcnEQbFKvgbgzJj1JZHAZEiTCT4jOKNON
         j1wdFQRf9+Ex6VvTmwK3KhqfWLyliuwJv5vY2NAaTImlYd7gUTSv2Qp3feqjtM4B7nyE
         G4lZCTjuMSEo0gEKXXoYeVZxq0LTGRLAwu8afR1DdmgOYRaDJ8XmxaE06JBeCNMKa+7Z
         N716mZXOaWKih9/m+YzMdhLPEe1QGvKt63h32TaY6c3mHaDZp+LyRCoQEnHQ8g2NcIoN
         c2qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UjWFT5qxt1RGW2F35NHCUxAurb3sWCjkiZgKiGZJWsEmNMR6z
	jdgCxCJoyxOURbAOuzWe1Ok=
X-Google-Smtp-Source: ABdhPJxjXJrnpXC2SCSDjJghM8i8NSgrauvJj1OxMoHHwpVkCAnbgqY1XSDChkJJGfywR7XYpaFuFg==
X-Received: by 2002:a5d:6510:: with SMTP id x16mr46840498wru.2.1638827126620;
        Mon, 06 Dec 2021 13:45:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1148490wrr.0.gmail; Mon, 06 Dec
 2021 13:45:26 -0800 (PST)
X-Received: by 2002:a05:6000:1010:: with SMTP id a16mr46790954wrx.155.1638827125999;
        Mon, 06 Dec 2021 13:45:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827125; cv=none;
        d=google.com; s=arc-20160816;
        b=IvLne/3GGeg8Hwt5I8XDBEzQhZNCGR4LOjsNU8C5Dwpb71IZ7ZaKnSCzExFzP0zrNa
         PN/D1Jpl2N8Y/idbbkOvM9sms6mjnfNoOSTheWoZNkgXP1pK8xy3/lcDM2q/8S/FysKl
         8iJq0oPGR679m5AMpBG6ufXAxbi4TD6NTJfhP4zpjukt+2XTez2RFSvtbb59mmOGGleo
         tqpPcQbf7gwin6hxcD0OlliWtiK7n+U+oAhNHs6UA5bRWi2kwp34ZjomT824rjT2cKOp
         YG+sGSy1dt15xfePJqZLCS1oLwyNOQOqPfLcfNnO2OGDm9H1uE+M3lC0RDXUvgGSyjxN
         LoeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DzChjposR8HVqGI1LyY9RFr0jz+Wu5dx9pG+xQIWYf8=;
        b=v/7G/x/hmONLorfpIVGntJBjZb57ZG1L7jYbgk90vdCAa2hH3qqCUUEfXyEP69GE9E
         T3rmOD1/lEe5Ve6z+49l5lAmmeCdHOXp7Lcyhb84GO0PwNSJUQ4RmylmRTMvPq6ygEij
         YhfvNPm4YP56sg8pXH6q8G5REs8yF/H9PUSwXbaULTOiXoOz0qf4suXq24AjRAX6dID1
         i5x7oHZSzPDp2SDSmvkGDrqeI8DXlM9DE+zeOcImfm3UvH9i7mdSRdR0byPxvtD3KUbf
         2ina/GJWKIv3CDNPmMy8pHT66NkLq173XFmiHGvV/qfE3/yXgSEgv01lMT21xVQNm8M1
         uBtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ka0h1Ym0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id x20si553646wrg.3.2021.12.06.13.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 14/34] kasan, page_alloc: simplify kasan_unpoison_pages call site
Date: Mon,  6 Dec 2021 22:43:51 +0100
Message-Id: <10ba3c7a7524a912098d3b1747c0ca2e1e626ebc.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ka0h1Ym0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Simplify the checks around kasan_unpoison_pages() call in
post_alloc_hook().

The logical condition for calling this function is:

- If a software KASAN mode is enabled, we need to mark shadow memory.
- Otherwise, HW_TAGS KASAN is enabled, and it only makes sense to
  set tags if they haven't already been cleared by tag_clear_highpage(),
  which is indicated by init_tags.

This patch concludes the simplifications for post_alloc_hook().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 17 ++++++++++-------
 1 file changed, 10 insertions(+), 7 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 5c346375cff9..73e6500c9767 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2419,15 +2419,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	if (kasan_has_integrated_init()) {
-		if (!init_tags) {
-			kasan_unpoison_pages(page, order, init);
+	/*
+	 * If either a software KASAN mode is enabled, or,
+	 * in the case of hardware tag-based KASAN,
+	 * if memory tags have not been cleared via tag_clear_highpage().
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
+		/* Mark shadow memory or set memory tags. */
+		kasan_unpoison_pages(page, order, init);
 
-			/* Note that memory is already initialized by KASAN. */
+		/* Note that memory is already initialized by KASAN. */
+		if (kasan_has_integrated_init())
 			init = false;
-		}
-	} else {
-		kasan_unpoison_pages(page, order, init);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10ba3c7a7524a912098d3b1747c0ca2e1e626ebc.1638825394.git.andreyknvl%40google.com.
