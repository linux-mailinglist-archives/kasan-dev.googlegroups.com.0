Return-Path: <kasan-dev+bncBAABBZ7ZQOHAMGQEYSF3PSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DF39A47B584
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:07 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf2447127wmc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037607; cv=pass;
        d=google.com; s=arc-20160816;
        b=JTaucbM3jCH+Lj4Ho9DZqYRlJrcq+BHDnmcQQqmIlnkiocEc8EGUMB33VMZWJ51S6X
         O3X7ubAt6M5jAw5kOvJsXNAvx894AtnceoSWKrNMuUgwjRSPO0nPmz17O8DtYbzfBkHS
         ccRGR0VglTJJ7EQ9348maCMGJgQU1Iqb7+ie7bzktB4/2iiu9xop9CDTCgtvDSwwLrbJ
         VZMpUp26kPApDEkiXcqPVGczdzqJAwoL4ZMkEOcOf0QO3tP1NAGiAekfAccTczwwgwIM
         K8gWWg9uMzlDJPR1J8vmMMJbOh3m/7TGh7rWnSpx+VUPT2xZdg+oVNLoT+rY+iggB5VM
         SPBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4l9YTxnzz95db/DQ1i/F4ZhEMnWCfGzPXmzBxtKAK7I=;
        b=Qohu/1OhJN2xN+0gwNiNSaiBMn0UAEx3GPfp04Pge2PyTP29F3fJ9MtvO5BXExRbqK
         JyunK4xsYLPsVLf0BXJErz1LUXDyINit5YDIc17qbOyAKorl2eBl4an8Y8hLEoaxpAVr
         nPdZCHl3coe8AzzCdZbDdP3Lyjg+Orm2F3hJSln00xfcbEN+otFdIkT8bPy1PIYym+gQ
         Sd2UqIhVWf43JkSaSOHUurtimztlf6TyunSuFUUJPbHTbv+aRPfKlfmDv84YUljFH1E5
         W1QOhnX3AxuYh7T0x7qPBarel70YdJ/d9pJlTld13l9abi/ykLlwtk7KBRv2q7xfA+UF
         T5hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xW8dg9sM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4l9YTxnzz95db/DQ1i/F4ZhEMnWCfGzPXmzBxtKAK7I=;
        b=NLwNU8xfGBgSKu/TG4aJuELIPeQKx/ux3MlqLzGaAhTlgsZ2LEsJaHAhtvKSlz3RSj
         pOyjSqxx/0cp7Fx6IM9WNceCVqrp1nXMsMt59K4tcAy7RcMIXV5tdLMRPz/IoUbPc4xn
         4mcF321GGzRxns5vsv9pnjs47dP3LHM4tW8DShL5LKxaxyJvFbu0pxfAMN1wYhF+JTwq
         C2gUF/XBZB8Pc4hFljVWLgVRtv4WLw7jgtO3HNMorEj4oyvE5FHdPkybQglSbQGQtKnr
         eKGCTadOO6J6TrkJE+FOU+uvhdVvG+JmPzhF7T/xS/7cIZT5FwGqJlNkPNdHJlXZGN6n
         niWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4l9YTxnzz95db/DQ1i/F4ZhEMnWCfGzPXmzBxtKAK7I=;
        b=2mWSYTDG8G9efhvregm6uDKiM7UZGwCzcKgiZPfQvYNJ2dR5jf30nd21j0sUUXXiCw
         SXrmlzcWV0HE6p0dkbOVNESm5R8/+Fv/YmtGNdzbYw3Gl5CFcXDUmcU6Gi/HR3VFCi3z
         MOI9wRY9nShbrymKY7zUNvnBS/lcmfzopddCjpT3psf6T4CUma9AAwsnROy/zI0HFLlu
         pKQK2d2esRcd0akv+60C8VL1SPxFBwVtGxHV2n1QOsVSVrezX4hDwIUHBHQ8LPbVJW48
         1JBbtU/J1ac4AITjuSLJBZXxN7Q4ARkPRDYsaAlJqmxOC/rJCrY1U6405ZeiM8K8AflU
         RDVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LGRMge2TxKGSeVVSLc+p/pf20/jEYkDAkP6yPNNNRwmmPOmcc
	Examr2X++xmx1IvEpYEYuvM=
X-Google-Smtp-Source: ABdhPJw9wogDO3Hx4jgzo+Kz7V+NrgyDseTBJyyv26d/DNSznY3L4YXlhNWH+bcWPqyakjkxU2eXLg==
X-Received: by 2002:adf:f252:: with SMTP id b18mr92062wrp.341.1640037607742;
        Mon, 20 Dec 2021 14:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6380727wrh.3.gmail; Mon, 20 Dec
 2021 14:00:07 -0800 (PST)
X-Received: by 2002:adf:b606:: with SMTP id f6mr111862wre.310.1640037607182;
        Mon, 20 Dec 2021 14:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037607; cv=none;
        d=google.com; s=arc-20160816;
        b=SY/4ZPGmQZ86v+SULwUvM4fVtdQxVgQRrPn2qHLb4Xn6tC/P3YZMdXxXDleaKCR/DB
         5GbTaEY4q0QaD7Q21b6M2CKbJgQG/isPFK+SyKqiaaa0InjDXuk14XXILcAsJ3QvpJvj
         sCwg7TNYTrKzq3LInA/7lrLrINxpJDZmKZYuOJtRvCx2nWA8rtOMTQDC4NMs/sOElKPl
         2ri5nKzt1bWKOmBX1Ga/WpyniyBoRASbWGk7h6Rfl2aYjoJIexE23HBYvkRyk2zxgs+h
         fAfUkAKzNRaae+vmm1OzlR/BEoAa23q2v9v16HfkEIlWJ6QBhmjHLhmCDDtJDuzb/L20
         MxwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cK3vbmhsL9nbofQKGkzhrZlj//vXbx6r4DVOI05kkJI=;
        b=SVn9f8dEwcUkStBmpPpTYoLcePecXd97vcdvBA/XiHGOLhDkBp1KYXgBOw/2+WQn3s
         SqwATZHBKlD094mXEqTPHkSSQb+Wkzxa7UdZsPNxoeWV44mCum0jHakjeMOak9PgNuYG
         TaVtm3seML+C/tC0mmbpZT3E4ui40b0U+obEetUZe3c0BS7dDbuNb5ltnKAXp1sJykZ3
         8YU0CwBEYTwI0ke2UA/D+56wjLREPt1n0odh8tqLTTaD6uO5vfe+9HA/LKjiIjYPgAJT
         FWnIM1URZtbPmCboV+FPrlgRaK7WYCPy2PwXUhYaH/YqBUJXhDNVuud2VkkCHXweNrRP
         UjQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xW8dg9sM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id f10si880670wrf.5.2021.12.20.14.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 13/39] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Mon, 20 Dec 2021 22:59:28 +0100
Message-Id: <b64a4baa49cef85a1668cbdc6214244c6611e843.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xW8dg9sM;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patch.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/page_alloc.c | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 076c43f369b4..205884e3520b 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2434,14 +2434,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (!init_tags)
+		if (!init_tags) {
 			kasan_unpoison_pages(page, order, init);
+
+			/* Note that memory is already initialized by KASAN. */
+			init = false;
+		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
 	}
+	/* If memory is still not initialized, do it now. */
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b64a4baa49cef85a1668cbdc6214244c6611e843.1640036051.git.andreyknvl%40google.com.
