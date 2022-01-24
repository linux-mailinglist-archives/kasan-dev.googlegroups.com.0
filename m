Return-Path: <kasan-dev+bncBAABBT6TXOHQMGQEXKHJ5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7700B49878D
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:56 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id o3-20020a1ca503000000b0035056b042desf300538wme.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047376; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5MvOSGsswMk90HkWzZ8RnMduuo0jG6vw3k1qvBa5DMoejb3rABcn7FGD9wowGAxrv
         t2eZbgRMCOz29n0NR4bYh00QNlLc6HaJG/wfeS8nSpMK8OQP+r3egb152Uq47jKjC6sH
         jKuQdZfu8wSpfvZ65W27iwql7g+VWeWfygRE4YMzOiFueemFgRxol1QS0LFIG9ppbxiZ
         FqpFbkDO0OtgZ4RUGZJfwEqMPHduaVueoNlI47KY6VVBZKzLDSYA9kvep+bMIEYbTDQG
         jjKmDv6MY/nujZTYcEZMIH0x22VThk/a6f9cB8p7FC6H7V1VtRQUKhiTNE2kgagWtD8A
         zvYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4GocVZstpWTyl5WBo1sOj+vDV54u4zEolPxtrxmY5oQ=;
        b=pL0i6CWWpcnE6ygR12RarSSftc7P+qv+DOj1LlDaGiCopzqgOgCsY+RUQSs7GUY92A
         8vWLcQUAYImeO9iwN+p4ouZCFu3oOYpkiZ2eSIj3amDbZkm5/PNa6EMOfXy6B4KJS6IN
         gQobZh3KhMFhuQxJqDs46B/CdjYmCzGuqcMGYIyZLXGJs29/vwP590lSgb6k3tO8exs/
         kcYBOX/0W/jviIv7KPvXfoutA4TImLqVWau1pEtetDWNnXsWWmrY50NOHOFmJmPU9Mg0
         ZVM3EKHnEtruWp8ZZtGShdO4zajhaB6QZMZAGty0mJ30rXy+8Pv/pGEkddVdBk4TPYs1
         35zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bKBbSy6f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4GocVZstpWTyl5WBo1sOj+vDV54u4zEolPxtrxmY5oQ=;
        b=iYKe9Ztu9IGyZRsuzUzVsnFa6+LOY6eIfdP8wBSqFwde1pW8/rxtkcKWPfGWoHNM5Z
         Nkhv+kVfrtnwV26UQgBIxdYrSjpjIez/5UJWFdlIQWQXtawtBKvPWEjApf9V1bEGavNS
         3w/fsUQKiEZPH1gHlAzEg6AmiatD0lPsBApuRVsDzVsQHThqlbtsymfj3Fu1kcBr4zzk
         r4wxCurGSrrr7qBCHZmPuxnayXBk7+8W2RpTCcvghxX54AC7sjlrjszEOQLMhrUp6vZg
         EO1R0HoaO0FeuEgxb1F4TeH+pNsRzE5g/sp62DvF0Zmlxb5yoPO3nWHf806g9rRlXKaj
         XCtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4GocVZstpWTyl5WBo1sOj+vDV54u4zEolPxtrxmY5oQ=;
        b=dCK4ERtHmS3I50jBrDtt8gsd498lgD646PDoZOWrdMqImCz4BRxYMYAOqWj5sQXYKq
         L4rFBe5DMgR3fi6xDU28hrYtA7Zg6N9+3+y/tHZTD2uKlUBwN9g6gb/A0ZkUh62RIamF
         pj4xXoF12Y3vrHbr5k5TRRjGTaqYbEOFOuf/k1Hu8ndQyItf/a38y0njLxWHhHhpagLE
         PMXsk+oHKMCosoL7wICR4ZnPpfDhwxy4ECFqYYlp8AAL5mBf6hhCJ7LSLIZeoipT1pMV
         PVpEqNcSMG47JPBMBnW74JBtUWYXzMjlzL7I8oiMYMRJDSEcRVs6+jhqRRcPmE+uwlxh
         YjRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TM7i3MLFboF2hze/0y/zle/8TLy0kePJ0or6QPYFiHECoUXl6
	618Y1OlcCnT3ck3b05mMuE0=
X-Google-Smtp-Source: ABdhPJzH6x43dwzgAqP9f4ykJLA0FTgTHBJs1CJ1ruQU2eCq3P5It1y/5iaxUG4UkzEc/OgdxWLJzQ==
X-Received: by 2002:a7b:ce08:: with SMTP id m8mr2869699wmc.127.1643047376105;
        Mon, 24 Jan 2022 10:02:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:448f:: with SMTP id j15ls287273wrq.3.gmail; Mon, 24 Jan
 2022 10:02:55 -0800 (PST)
X-Received: by 2002:adf:ce87:: with SMTP id r7mr14917302wrn.259.1643047375415;
        Mon, 24 Jan 2022 10:02:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047375; cv=none;
        d=google.com; s=arc-20160816;
        b=c9Ewct3/9bWZC5UTrTvMAmY/cgrnLKf8c1oKmyLiofrljsuIzg2OrvhUQj3mX5fh+U
         sNAIUrMTGtIKNL33kegBCSo/3ZSN0SFCLN3+311ugNw3wipOa773Au1FRcmVrRHyJ+yv
         o/k5cDYsHGPUm5NgMWzAolf1TasgZpn2vgIvFfYAtZwejC7K5hWIroVki1S0wN0GQa9v
         v7zWUN9c4mi7HnlUR+i6fCRT+qw/TbIuUt3qVLwNWNAzKu7sPWGUdMEu36cnMR7Bxcmg
         d0mGQBnPSoG6WjGj2Cmdx/nH6foEW+f9Qp1HGn7COcm/IS1yDvKFXj9a8DGIgha6HOR5
         8M2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NtjC8GJtWhPCzF1O+E8r8kpeY3QxluInaVM8vIRb3RM=;
        b=u0sftVoS0S809Gp/qNLdHSCqJ1KXKS3nBPpmQ9paqrXuxErabDEZ01kFhrvdKJPsnz
         NaxcSyyMKv7JyObKmMa1ISbI/SfPwzJCGv12AXd63SN3oR/etoJOZUJj+NU6JD/JGqWU
         89bWJLnzCCt/e2HrBClp+OfJGeBJUU7UOfcRmdVCL4UeA09DPauzMIkJrDBbTRHqsZ4p
         KSXI3SKg1lrbIpVGCM/Cx7ZGM74D8CakaHMY0yq3q+ambsP95jsF0KSoyCz1sGFeZP1n
         UVHK6hw7pH62AZQBIYeXah9xc2ILAatgZvH2apOwGXsDaIP3qtX6NCckBFOfwEMwdxnE
         aF7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bKBbSy6f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id be15si1546wmb.0.2022.01.24.10.02.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH v6 02/39] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Mon, 24 Jan 2022 19:02:10 +0100
Message-Id: <7719874e68b23902629c7cf19f966c4fd5f57979.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bKBbSy6f;       spf=pass
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

Currently, kernel_init_free_pages() serves two purposes: it either only
zeroes memory or zeroes both memory and memory tags via a different
code path. As this function has only two callers, each using only one
code path, this behaviour is confusing.

Pull the code that zeroes both memory and tags out of
kernel_init_free_pages().

As a result of this change, the code in free_pages_prepare() starts to
look complicated, but this is improved in the few following patches.
Those improvements are not integrated into this patch to make diffs
easier to read.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 25d4f9ad3525..012170b1c47a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1282,16 +1282,10 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
+static void kernel_init_free_pages(struct page *page, int numpages)
 {
 	int i;
 
-	if (zero_tags) {
-		for (i = 0; i < numpages; i++)
-			tag_clear_highpage(page + i);
-		return;
-	}
-
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++) {
@@ -1387,7 +1381,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		bool init = want_init_on_free();
 
 		if (init)
-			kernel_init_free_pages(page, 1 << order, false);
+			kernel_init_free_pages(page, 1 << order);
 		if (!skip_kasan_poison)
 			kasan_poison_pages(page, order, init);
 	}
@@ -2430,9 +2424,17 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
 
 		kasan_unpoison_pages(page, order, init);
-		if (init)
-			kernel_init_free_pages(page, 1 << order,
-					       gfp_flags & __GFP_ZEROTAGS);
+
+		if (init) {
+			if (gfp_flags & __GFP_ZEROTAGS) {
+				int i;
+
+				for (i = 0; i < 1 << order; i++)
+					tag_clear_highpage(page + i);
+			} else {
+				kernel_init_free_pages(page, 1 << order);
+			}
+		}
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7719874e68b23902629c7cf19f966c4fd5f57979.1643047180.git.andreyknvl%40google.com.
