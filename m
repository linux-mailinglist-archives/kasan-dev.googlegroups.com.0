Return-Path: <kasan-dev+bncBAABB5OTXOHQMGQE5PE5NJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B6C7A49879E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:35 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id c5-20020ac244a5000000b00437739a41a0sf2399666lfm.10
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047415; cv=pass;
        d=google.com; s=arc-20160816;
        b=RdLuDwnamHpz9aGNn7Hb8zn8MsuKZW/OfNWoqtrr/IOS5zljdo5H33F+87FSNAzkRK
         DmaF8OAIFysobZn8xwT2vILbUemzO15JU9loiZ5AEl6/Vhf8k/0QDB2MB++Y/sbpMTlP
         2CdiDfDbstDRjvkqV4IU9j9dYSNmTduVpIDdYdTxgB9qRVuFu54eksTnJOyCH7KOiz3+
         nQds5iWaGihYtogX1y0+nHoAOb6zcD6eL+iMvd2rJzHUQi+bIcGYsnzb4sK2nGS3pOuF
         fiJeyIcbW0vAMiviyHU9s2xW/6OVsDFqSPufrDcidH8z0Xg2ALEy/X5xEYu8DUORgdbE
         rAMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xL/sTDLFsl3PEnRoHvX9kgmtxNDYxiyeNDRu/QOEsF4=;
        b=mVzY/c/qxDWbD1+oP4VEi4srfadX89T9QP+ZWc2MwbzttBn2MgxnP3jElfYGUk/6v8
         oCgzGZlrYLQaYIqo/eWI7CHWltio8HNfCBVk8xr7j7jmm7wk1AzPinHric6FkavvdFN0
         j0ffJJgJSPk7UGrqeM9SPNhWP51NyoaECgvYcXNhPwTZr57ld8yrZ2DUlIh09jYLEcOF
         bP4tg/ptU32ADRcNR5bpD99W3cOyQ7zWfgP/AMnXKSVo1oDT47HTDrb1YMWY39jRR4I5
         1lEn2+GSBg7WZgNskEQ+o2ZJpvMQr9QyJ6Zkpty6up+4jmuj/ngO68zhY4MLQIbon5WZ
         nP5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lqAs+zT4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xL/sTDLFsl3PEnRoHvX9kgmtxNDYxiyeNDRu/QOEsF4=;
        b=hqH+XhQ65gCB0GYWBJDh4fnlZQfU6r3DWUEToEjFD5w24EjjWGCT99yuC69v4/iwGf
         LU052JaJrL/1k4J5JQteDzSa3jGxjj2VAdRWciNNLXdD0X5GPO4JsSxMMSy5hNlUL7YY
         FosOnjMhGkHUTSUpDA1pXJBofxa4nERylf7687fAr+BJ1B49q7wlt9VJd9ukBDx0bXl/
         Gl6vHqaOxcr+crYBweZEEZ1ZwyNVkw0BObdmLdLeZslcySKNYLZYh2+Td1iqLk7YiQiB
         Ot4igYCxrBYTXem9yrwixAtDvJZn5ZjXdmU8xoUzHnZxaoxVZ2CwztGSQk6W/Zz4Baij
         QomA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xL/sTDLFsl3PEnRoHvX9kgmtxNDYxiyeNDRu/QOEsF4=;
        b=mfD2p4tYdlsk/3e/1c7ARVBKb619sG7NWnvRlwis0ew8Tf3vT20zAOWwGbGF6uEiEZ
         n0UPsEwWDun/KXgCWoOjkNk+fyrjxedrAZSFYxXSp2LDhm+BIYLDCYzUVqFPKJErytLN
         3GziGpA7QroKks5MxDC3A5D6OEYtn3m0bRWE2OBH4SbqESgEqOL8Sd0dIaa7qz2XvOE3
         xzF76LI/GqW5fNg6kCKvnGsoBbikxVpmjGxmk6C51naNgEfCELa8A1t89pUZ+RqpSkTN
         fILWB3cWLB53rE6XVX/bYQSZKl64UTRrbf50OdJ1FpRKVOhN5qoIdJ20mB0wXexJzol1
         FkQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ccF0472oMEaUhn5rK32hh1HRFge0xTPWZENqNrIeVZITnJu8e
	lZpcyxDyLJA7/inJwfRgRIk=
X-Google-Smtp-Source: ABdhPJwMWUIbZ7xixaQR8rQP6G7dkq0DPvjy1s72CGUdY+P+o9gHGHMeggZkQwktkQ+fVpNt0K2xyQ==
X-Received: by 2002:a2e:bf04:: with SMTP id c4mr12426797ljr.271.1643047413811;
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a2a:: with SMTP id by42ls2480214ljb.4.gmail; Mon,
 24 Jan 2022 10:03:33 -0800 (PST)
X-Received: by 2002:a2e:a792:: with SMTP id c18mr11971629ljf.421.1643047413019;
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047413; cv=none;
        d=google.com; s=arc-20160816;
        b=aB+hXfRAI+qTCk/pxY50T7uRPMhMGoMRWMoKbvpljeIaeYSzny6Kq9hYIPly1oMGg/
         V5eoNYldWfUNxgL8UR9TETORYWi2FCBirYtDtnXMJHGg3NeeVlInAuQAfkc/zNFYOIUB
         KcNv7vtELSVzDhjLdB1KLbzoR480DB0ezu6s3r4/IbQbJD2WE/8ZwhS6cDvEYLwYjHxu
         TzoFN1VDJ7x3wEKMdfqBlMubWJCNTHV8WvEsxagI6+wCAtWgzBY5icO+B25L8pMrLXV2
         u2JyvvZ51p0Pu+Xi7vCUXx4XD0tX+9uiW0ELHYb1C/Og2HLz8RRaJ7ZF2tef8wYGAKaH
         I3OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ahnJF7fiV1PQKb8mnNBqV+WM+Otng1D4UaEsnbQTJqk=;
        b=LV1QXdxAxbpCShLmcUDMfzcOwmto6Vcfi0ENttGqTT0HoKyscNggmfKaTiOD/EhaX7
         erckngNNHPJp22/hIbANCBDtOLHRn/eNAVWJe5XHIYf/DqJSWhwE1QwztgXx7eezTW/e
         kswu4PCtACM7WQt3hDxhgJFq9U5jZzfTx4VFWBPSh9PEd99Pw5WYwjn2Z52y18UzuUDs
         NXZOMQN4K06M3CvRXlzYda2j95jn4HLkr8LyfTXnO5U/VULgrLvQN0Jz14g/N3lOnjvQ
         xPE3PdKkNeKjSiY4VjDAU0AZTsj1yz651AklBZ0tuPutJ6upTJtBC1lg/wbeITo8YrbX
         9BaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lqAs+zT4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id z19si486301ljo.2.2022.01.24.10.03.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 09/39] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Mon, 24 Jan 2022 19:02:17 +0100
Message-Id: <2283fde963adfd8a2b29a92066f106cc16661a3c.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lqAs+zT4;       spf=pass
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

Separate code for zeroing memory from the code clearing tags in
post_alloc_hook().

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 8481420d2502..868480d463c7 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2420,19 +2420,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		kasan_alloc_pages(page, order, gfp_flags);
 	} else {
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
 
 		kasan_unpoison_pages(page, order, init);
 
-		if (init) {
-			if (gfp_flags & __GFP_ZEROTAGS) {
-				int i;
+		if (init_tags) {
+			int i;
 
-				for (i = 0; i < 1 << order; i++)
-					tag_clear_highpage(page + i);
-			} else {
-				kernel_init_free_pages(page, 1 << order);
-			}
+			for (i = 0; i < 1 << order; i++)
+				tag_clear_highpage(page + i);
+
+			init = false;
 		}
+
+		if (init)
+			kernel_init_free_pages(page, 1 << order);
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2283fde963adfd8a2b29a92066f106cc16661a3c.1643047180.git.andreyknvl%40google.com.
