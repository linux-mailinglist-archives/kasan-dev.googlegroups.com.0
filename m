Return-Path: <kasan-dev+bncBAABBJNVTKGQMGQEJ72GFEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 50E6846406D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:41:58 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id p17-20020adff211000000b0017b902a7701sf3842554wro.19
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:41:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308518; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ej8qKTPIv6rv1AVyxuIFpgICs4obSZQ7jSc7EvwIdR35SrDi7WNmhMKN9LPKFByqWP
         p/CFs+8VjZgb+L308mMFe+xtJDmqjcruXshNaD/Nd1tlynscq6rfH6tuUqZLrLohdfOR
         rpQeaymQavk9F4FDzOCtZegdFF1mJbXhpAI/Sm8sDfZ2y0Iprc2KgnolLYkdpRwTHZPM
         zr9qAhRc+ImLNSjsGBbOomacmK3pd537ktXNN5BweUee/sOwgMGF3qqu+toEpk5iMmNL
         64N3nGUEJy9h+yNaQvVY6kzxYpPqAJxfwj8AUcXO6R7TZM9KKCdNejVL/IMce2HhFEzU
         WXPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MOXlXxKmSeeDcGQ1HEvcojbyu4Hy4aMwr7X/wryTWoQ=;
        b=lX/lqMvWK63iwWUEI6vg+HMivb4inG/nTaqWC43jAv0mEH/8LRZzat3EUfnmpXNBng
         acx4vqna9gKXTEuuaghHAWrMuuQOisEqDrckx45HbMDNbAEP4TgzCRqJ09wQZOGtiHLD
         7WfW+3HZtERPrpnS6YiLcQzb9ndWXGBNCKiy/tYL2+MY0fjYnAIl1gzpvcXcHdQm7zfW
         fuV5msb6xG4lGAXM1MxuG9OHPFBvmFbukkBGR1MiUE5pQAP2HObTOgegaCPqVrKJNY+p
         mYnrRe5hTvbX9gtx+SY5mM/Zt1xFeWv4pMhsOaXXOEJk3cb5dos7a7KVGBNK+XrIX+Jj
         AN/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pd5RQW1f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MOXlXxKmSeeDcGQ1HEvcojbyu4Hy4aMwr7X/wryTWoQ=;
        b=B5t+olkC5ZGyxujHWQydYZ4gr5PjCB/94tJgRtW5XyVMULC59JRXdRLEfuP+bFDf7K
         RQCZ84SyRVLyxyE3XgewsPHjw6Lj6Gg3458gTWXEapYu4INWtHNZ980wiHk2e/+OUtoT
         6+XcRTVAIcCQjrdem8EoRJ4V4mCm32b+Wq4oiR8CIDvDmoySgimrZ72g3Hvon1fDN4K4
         9VYwpLyummB9hUS90xmGQNNvnjUfq/sv6c8R5Hz/iBMA47V/ezJO10mNak0kVeL4ZSpG
         k6wDhG/+9aBduvpapFX0fgArdDs2sj8kzGcMkuNd8GQH+xni5ItyaDnPTQ++OR1bluD5
         W4YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MOXlXxKmSeeDcGQ1HEvcojbyu4Hy4aMwr7X/wryTWoQ=;
        b=plXOK0b0/GBBUeVcu0PHwDUko1HH54TLV/tSdKP0RD+Z5PpgK9JnsCwxepnvKSeXTO
         emEXe5DLy9r8PcX2fyIM0ZaRENZcWSGAqrhy5utnRpYop+YnYrQ6IL+jK6IAX5DrwPoK
         SwPFu6A6x7OUWd1oqDkz0xhNYNvgZBKs7LRYmWg++KrtZPtVmJ/qRW+1J0zUkn/3LMkP
         ZToRMyKe6K2Ps1JyX0N6xf9jgcNHNYz58Uz1d3dPQPJjJA3qucvtPPq4QjLge3fh5y8W
         6zxRU6xxRvW4zCPUR5KhDlaSDmAGzIriqAnmPV7Yw/uAw8Ygn+uI1mHXRRKg1p+i8+1y
         hYCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335MRT0mBCCl1HL8pa4en4r7L4diFBy8KrHhW52+GfrrNkDOaQS
	gvzeOd3r07km/jMmPuYyd4A=
X-Google-Smtp-Source: ABdhPJzAT7LO9KQTzaj48gOUzvEv8EbGfHr8pkiq2hWMj7PzynpH/qQ810Zuz69XXFHSN9TqHdVAQA==
X-Received: by 2002:a5d:6843:: with SMTP id o3mr1746597wrw.174.1638308518104;
        Tue, 30 Nov 2021 13:41:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1943:: with SMTP id 64ls75799wmz.0.gmail; Tue, 30 Nov
 2021 13:41:57 -0800 (PST)
X-Received: by 2002:a1c:8:: with SMTP id 8mr1661041wma.106.1638308517424;
        Tue, 30 Nov 2021 13:41:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308517; cv=none;
        d=google.com; s=arc-20160816;
        b=LWy2lN9lzBVA/uMRzKzDlkAqmF9n++iD4eatixALttT/hO57aWFWOlZ7dVmB3uFZ88
         SiHk0CP7uWO1xMNnHbRFHuNpzvjy6NTx9ZpdzUkXOATg7iEpIksAlqj9v+iobikdVpIZ
         ASyMThRWvZnmgihrFA2kpGGVjavqRlWeJD4/Bqwj3aJRGPpTZ/pO3s7m6JXIBB6IQ7DJ
         IbqJdo7KCBfRibhTcnTkwWj1V01MFijvBxmbykDOujM3MTRlyvDZK/SUqIcsc4eBcao3
         cm25Lz17fH814U76Jxu0giHsQ2eMj6/l1b+tumdqO4/jOD8FOCo6Q5Q3bdVZZPEB+KPs
         RAwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=65+U35KJ8uZeSN1gKPKurxIT8sCbICO1X6+tJPPU8p8=;
        b=nGt1f/F3xo8RetKGkadlHhheBNyahU9AjeFKZQL/FEOt0qPjvfFAntUHE/YUVDtZw5
         dLglJe93Rbj+YIR5EVSb8LpahP9JR6GNuprikS1MiRJ+ZWL6anD0Pb6rGfj3jP7ft4EC
         lCnYpPIWnwa6678CF44zULGyPP+hUtdHCs/unMELm6OuPGNSnSCYAKjQN8iO2XJQAuZQ
         2GI8BSOhegMjdGIonrT7IH5vB1lHjnas50zl1DJh6+D0UVKsooWq21P8p0yQQfZ1heqp
         pYdHvGvQR7Zp0o3QnJxSX9BdzAyjNQ2VEIKUxpAxIDpxQSPgvinRENRWev6kBCNntabA
         PkBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pd5RQW1f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id z64si495034wmc.0.2021.11.30.13.41.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:41:57 -0800 (PST)
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
Subject: [PATCH 08/31] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Tue, 30 Nov 2021 22:41:55 +0100
Message-Id: <984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pd5RQW1f;       spf=pass
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

This patch separates code for zeroing memory from the code clearing tags
in post_alloc_hook().

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2ada09a58e4b..0561cdafce36 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2406,19 +2406,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl%40google.com.
