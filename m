Return-Path: <kasan-dev+bncBAABBTMJXCHAMGQERO3FH5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDA5F481F89
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:17 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s11-20020a05651c048b00b0022d8722e7b5sf2907501ljc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891597; cv=pass;
        d=google.com; s=arc-20160816;
        b=K06QDlOKkZ0bIEcIeKqOPbWi9Zzi2yWQFqb5HC2Q2xm+H48rYK3SGav8ajNqV7fiKg
         j97rZa8Df4ml3fzc+18opi2u7eMcpYIprXDFXdAsWvB/ubVs9khpyMSLiPUWDgf/9tR1
         FzegZBTVX9R4NJJa+F0McnPniDGc6PHI7U+Jwx28nV26QjktzqKoCu0I4dgD6PPST+6k
         guKVpdIaYS9bFDaCDJCN+AQByg5SMMbkttQ740A0t6Xz1GWP42LhYuc6QFE+Hm9dc2KW
         Oj9uG/BjMP/qH1BXVKqkgzYcr5DIliyUK73uhyPDkTogkf+5bwh1fFPgASxxYiJvnNE7
         fQig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=afautXF5D8N4hmU/44WkeFHidv8vBfWmzl2/m7dFFKM=;
        b=ocDON1I1gQ9h/tnSWvhjzz48sLke7F4tD/5x5i19nLNdWlLhW8Etdr+OE5+Luj3DLs
         itWYfzb2u3VhUcwSFwhf1R75MpNbiznWQT9qMmgucTNk/fVtYDj6EDmc2JuCYEwOwzbh
         Fhng5O7P6zAf/SkwT7gCaKk39lQH9hLsW7ky9bzY7zp0UWXwfNs8vk/qWPZ2//jh+CPI
         fu+721z8q8nyUwVGjNpV3atqnJP57oItXnDqhdFolEVM/KMKUT7h/lF46ySNdUQQqtyo
         DTaJIK4UjBpOgbygfl7mzKDY9OGgsYQLf10jYfa9euanky3yw7eS2f0/Efyj55rhRoyu
         M4Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oPMLFAyt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=afautXF5D8N4hmU/44WkeFHidv8vBfWmzl2/m7dFFKM=;
        b=mbytoCbgazEbal3WCWxRYBEZdR1wCSxgJ2CWkE3Y09gqYRNuCDdIap7c9GASEiG4uW
         r1WV352hsspSy4pF032oM7taHsPmvcJvazwKcVM/1TMfXq6R4E6oR+iPa93JtyxnoiU3
         W8ATDp4RbjzGa8E3JFtUGYdROFjqH1RqIeWLERZGj2JZbUPhaJOy0Itm0gTeYi4q2Lp0
         Y4xDvM3yIG8ayZvzxndWh6hl03h+CeWhA9eQJi1KtKhYYSbT+mu8zDn+eX72kPjc/3ZG
         eRkHLJfsuQ7w2nMZiiN04W7dJdpXCqOnXQcuwwHTXUGiUtF25scBqUI0fItroC1uEw7z
         3TeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=afautXF5D8N4hmU/44WkeFHidv8vBfWmzl2/m7dFFKM=;
        b=pz36eeKroGVZYRsZx18GnXmkkzA81fdcYIakJE0kjyiIwkEcJ+kemaliBqd0eazAY/
         nRCmeQ5oZYm+AIxEYYev0ajGQaFXcICqkzYWSc5vb2A2Bngw+DQzmOQXPZzkpIS0vI2X
         dDZEL19E0sNpg01xTzsz/vz9RuwuqO+Ze5KPwiDg5jl2alao8CUTlObpJwaYQvjp/PwT
         pMqfI32QxQkR+t6R9IdisnBPqM6/aRm5TGcAYsttquI61P5EiuiBb0RhrdUJFV4QHDh7
         GeWHLxy7sCRIwTwRz9b8MqSI5rjRliPmTouLJYC4X0IUxE/NTn7ypEPhkmoqPL7GQeGb
         sagw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KaTlC/A97YY5Wk3yO68qHnqfoQDsUbit7hJAkWDDNZP3h6wpc
	irLNgNhRhyACUGRHz+ZHMP0=
X-Google-Smtp-Source: ABdhPJwRNl12L9vtP+pDsiCauc5JO8OQDLXZefYxlbI9lpqEFTEjyiW5O3RPfTQcb2g+lnRcs+8b8A==
X-Received: by 2002:a2e:bd17:: with SMTP id n23mr28249281ljq.64.1640891597541;
        Thu, 30 Dec 2021 11:13:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d2a:: with SMTP id d42ls2236142lfv.0.gmail; Thu,
 30 Dec 2021 11:13:16 -0800 (PST)
X-Received: by 2002:a05:6512:308a:: with SMTP id z10mr29236025lfd.594.1640891596749;
        Thu, 30 Dec 2021 11:13:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891596; cv=none;
        d=google.com; s=arc-20160816;
        b=X+/ekgtu3zSZgQoGidGdjrxIAji4JzDeNbaZrQj7i6i254rBi1O8YD8+t/UcV4pjMo
         /hzd46Ce/cFf3ZrrUG3aepWvzlJm/gV2T+sIjtwVRNRrPjPq6Z7BVZ8PaN6oLMz+uB99
         K+KqQO0HK839OOL7+DoUUSSeyKNCwflneFHEfSFxrV3FR8z89F+2K/BsHdDIu88jXtRd
         z+tjY1NLjk45DyB5oq5zORW6CXFC8vEnopTPhDBVDTdwtRcnJZFPO5YVlSwvvF4P4Q0+
         VKUfUnXxgkoyD43lLSSj/ABKx33mCJPeRJKHBOq50IEfPIDjPa/NSISFWzHnUtkdU+P4
         zehQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lUPF5Ob0/DgWPZoL5Avuj/Wi725rX++w+mIgShQArV8=;
        b=dgP6Pt+etnudVI3Ic3QY2nBHIIwXbj2oL1gxSlLfYFSVK9eNfbmpGyfDO6lxYhZON8
         zrtvZEfH50skNH8bQVrU0wrkpzPo8EGjih0mFmScNQ1GyWpSUWMEXE95yT6U10KiRdSp
         W3yCgPzNmkGqabQA7yYJg9QwClTbo5D4/FilJhf9X4o5SBxD3KCFxELb75DfICQhndyf
         w0yajPpjyqg5p7mC7cUyoKHOu/50BWjtaFB6cMEXiZUnBDMvovbQRx4MPIR1pV1G/O83
         XvkpOK/WodZUnXa9ksnfT+//KiiHaoLXW864BQVsuztME4ZGy7rKYW92swbs2y9RByiH
         B82A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oPMLFAyt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id m9si509978ljb.2.2021.12.30.11.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v5 11/39] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Thu, 30 Dec 2021 20:12:13 +0100
Message-Id: <831f77cc1cd02ef2a55854e9d71d69f49d99e465.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oPMLFAyt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move tag_clear_highpage() loops out of the kasan_has_integrated_init()
clause as a code simplification.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 51ea8cbd2819..2fe02d216c5e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2419,30 +2419,30 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/831f77cc1cd02ef2a55854e9d71d69f49d99e465.1640891329.git.andreyknvl%40google.com.
