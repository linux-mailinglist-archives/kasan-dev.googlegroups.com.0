Return-Path: <kasan-dev+bncBAABBK52TKGQMGQE46LWUQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 142344640C9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:52:44 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id y23-20020a2e3217000000b00218c6ede162sf8019312ljy.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:52:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638309163; cv=pass;
        d=google.com; s=arc-20160816;
        b=J9rAkjMH1CQAyzHUfZFFug1w0IVqW+brPBtDkn+aogcs7ZHC0oXON70iucqgyV0sZC
         X9U0oNpiGBbliqus9Efmbzem04mYqz2PbnT8oklQRJOoHAVHxMXTKsZ2G4Gp9UHeo6bm
         6GE5KdbTiIlafswMnbD8/PxZOmQ7zMeWyHky01Y3yrA/eAPgUsndyg/In56IAfLCpP0h
         PQUe7PaP09E5rJuFrEowcg2zX4Wg9MHAdjG6xGNDMJ0fqUvMwY3/X6KpA/pYi+seJFA/
         H3sYoFbFTRFgNHPKg3U7qKepm+vYKxqKuJyEL6nYvil/Ky9jIycXM5stdARfPagis+ZN
         ZUjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mmRgqYxdQCA9oSNt2g+mKRGaGp6Xiuu2Gp/pKbratL8=;
        b=wcxaJko8EKn182qo3TGlSBP1aR4Lq0v1zXN0V4sxePT+xWBrUrsO7680EoGekp+mXU
         Ipr45Jcw5LCM7MImKSVo/cJiLQaXkJm0+5Ajgij8YQAQhBKMyks4wvcB0/hgaoKxcv0j
         ylpNilD+tvcouT2XTfGAaXKsqxRuPEkuA9TWkKAXqp7wEwVNpX/2AVRWAt3y9CA4/VK0
         VJ0uIRWf0lw9yp6ps1/gRZGZoBHHVeTZJh9c0wJY3h8C4IDJeuotnci6zrA2R5h80jhN
         zCgQR4yOT4Bem7QSjF89vgefQV2XXcFixhepjA0nXUPBpx7dFaG1169doqz52QTeWNFV
         3L1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ovqDCQ5W;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mmRgqYxdQCA9oSNt2g+mKRGaGp6Xiuu2Gp/pKbratL8=;
        b=JuqI7LF7UEgzk6RmS9HG31O6abHeSctBcXU+i1Pb62C3rp/fQp3H9eoPasI6RvWBln
         b1oezurXYWaD/zOErH8oeiw90gBQ+i0bhVhCRmQA6riCTltU2l0Q0Pf/U1ePnspWkobb
         4EFAXLHv/eoUrPK9zHBmb079gNsYk74QQsSbwePuNxSAHDDA3fc3CUI91SRoPzPGQ3Sp
         FLcm2btero0mIGr/fqyeRlmKo3Pvt1fQWJfJXsggbC8T3cL20JCT8kvoPohssMz8/Zr4
         YPZlH6xDPNtJ3ZdI4CqDFxJLTkjuuBmDMEYUdFGMreBmL0aIqQcdtMIWPKWmAhKm05Xi
         LwfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mmRgqYxdQCA9oSNt2g+mKRGaGp6Xiuu2Gp/pKbratL8=;
        b=ic+2CxSxCA3arnnxFSrd50U4MGxlNKJtM063Umgv9JB+SFc6Hoo0mc8QNHOLTwOQOi
         vr8v5IeHMzJgDMSDeuQGOCNkQWITToj0dWlPQ3xzxkIub3UeIaoa+3Cm3mzu/QdzVx0L
         oLWSkUtWOUhXhmRq6kCe2gvRWr+wyeQ89bClr8cAs/hIl++IcN1CWdZAXBMDuvEKaGFt
         JU0duHG17FsbkivmHYNkmP3SC20wBYomyQWN6J23qM28zzDKd0UoL45SBAxhjihh0Ntj
         Uwf+sfd89duAz7hbb95WaTH5LZm++Fe9KgsL8Lc3Ah30EWJyRfgh7Enw6pb64AkCUUZI
         nhHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309ocNrXYUCT4EEav2wiTFX9aVDCD5jSG/fjR90rICZ0w9CJOEK
	rGWSby+xcuz4Z/Rq/wk0QPM=
X-Google-Smtp-Source: ABdhPJzBZDnqAOGzbZu5Pl9f2yWTXJnUjniUfzW9hF02dwjGCMM757Y9wD9wBHzl5Xf0SuQW56fI5Q==
X-Received: by 2002:a19:4f59:: with SMTP id a25mr1817748lfk.22.1638309163605;
        Tue, 30 Nov 2021 13:52:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a222:: with SMTP id i2ls7106ljm.9.gmail; Tue, 30 Nov
 2021 13:52:42 -0800 (PST)
X-Received: by 2002:a2e:b88e:: with SMTP id r14mr1462547ljp.365.1638309162773;
        Tue, 30 Nov 2021 13:52:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638309162; cv=none;
        d=google.com; s=arc-20160816;
        b=ImRQUQQWEnMyO7FfqyLy+5k8/YoMFC7Rlsisy80FljzcP652IQXT6nUN+PmGEk2i5N
         GE5Y4+pHuxVns5/iBbXmRfU3Rma03FWZuze66NQRtGZU2yofw9jJrKbmv9fISJBQvLwl
         mZmiuv5oJWYDDyTmWU0WHdX9qvGhZo0L9Sd1VjZmev6FS+gmXhr0Wa+PmfxmFVxiKg87
         hjTAkdKSUXwY+1jpsGvQ5D273RqaCSm/2Him8MVvCI6CvS+CaMg5tCtwDJg5BPJaiUxP
         upD1bf6FCHL4m5piierhOgPdULjz09ivYIVrx+s/bOPpe5mzgSJosJxYWI0TjTYVZQYI
         sOtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Pa5aYso7nciPjt1f2qi7koMfMaeRn4xXqoVuFKoOwqk=;
        b=CriGtXucAWPah6OuMhWOb5CdQZ9rT0vQQfSVb4vGFfJNfRWN16NRIYge4ooOFpaG0V
         GaGT5gkW7mknx1TeEW0/dLSNJu+QRPOeVnnBrbROENxx/4u5tdn5I/XwMUUBehwZFJbJ
         KbDq0wipGgd8d5FPRCRt0k0ObAFvur8GuNgEfKPXnKS4rYAyyVQ94n+fcE8SUIPxWWS3
         QvxWKc+sjiXQyu+Ia0jxJ2+oVtN1hUYUGm5Wsh0MXCantqciIDtYo+7tYYEAdf46D0Hn
         4kbLl42JIUdPfNKB06QydJmqSSwHZ/NL+ycy+nNCue2vqV0o1QldssAaeELAchNV0N1N
         EssQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ovqDCQ5W;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id h12si1657008lfv.4.2021.11.30.13.52.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:52:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH 10/31] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Tue, 30 Nov 2021 22:52:40 +0100
Message-Id: <48a7a39ddb6fbee4bab6750121d7349eb0364be7.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ovqDCQ5W;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The patch moves tag_clear_highpage() loops out of the
kasan_has_integrated_init() clause as a code simplification.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2a85aeb45ec1..e3e9fefbce43 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2405,30 +2405,30 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
+
+	/*
+	 * If memory tags should be zeroed (which happens only when memory
+	 * should be initialized as well).
+	 */
+	if (init_tags) {
+		int i;
+
+		/* Initialize both memory and tags. */
+		for (i = 0; i != 1 << order; ++i)
+			tag_clear_highpage(page + i);
+
+		/* Note that memory is already initialized by the loop above. */
+		init = false;
+	}
 	if (kasan_has_integrated_init()) {
 		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
 			SetPageSkipKASanPoison(page);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i != 1 << order; ++i)
-				tag_clear_highpage(page + i);
-		} else {
+		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
-		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
 
-		if (init_tags) {
-			int i;
-
-			for (i = 0; i < 1 << order; i++)
-				tag_clear_highpage(page + i);
-
-			init = false;
-		}
-
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48a7a39ddb6fbee4bab6750121d7349eb0364be7.1638308023.git.andreyknvl%40google.com.
