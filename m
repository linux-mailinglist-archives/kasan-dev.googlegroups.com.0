Return-Path: <kasan-dev+bncBAABB5OTXOHQMGQE5PE5NJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E7D9A49879D
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:33 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id w5-20020a1cf605000000b0034b8cb1f55esf15365928wmc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047413; cv=pass;
        d=google.com; s=arc-20160816;
        b=PW63AVeP/qHygMA7IOIaCKFNix8JNA/BoaU0OIjBfne57nlK3j/BaCKCMYpCqFkGkL
         yqLD7vmFbiFYT3Q+21eHbJJL07bWuF200r5Yy0uJ1TyuTAJXrrBnhl8SbUvz0IipbGvP
         9sQMVvbIvXK2pmugo3xpKC8KP02ckOUEsw6pkiWVCmY3eAgMTgeP7M4Y4zGCtwe0H+XZ
         BbhsmysVwAgjq+4u5t07VxuJmaJcvhqa2quhDcZZdtOcVl9pUMWmumL4rrBys6Z1PZ2g
         lOq6T8ZD7O5RCHmP/N9vNrEfMGg32JkmIUeQCj7FOcZDoCpPA3KV7DbnloNnLuRYxzLK
         Lz0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=efSduObW7N9ForDtMWtGYMZHLSVSAW0JXwqBrUnntuI=;
        b=SGWvuCDvWKltj7kEApc0L39ErAizIOnG7LA6ugsW7G8gmBlfXJRD2voQWpTNPn9vWJ
         ZVeNMRv3meORCY+7xMIBqkIDsQEIwC+gM3PomUY14BiFSrOV9yNbpLWRPLXHwAcxT8HJ
         G/tJuPX76oWxUlnR4B030MBsF1R12T8Xyaowd61Cu14Vt3maM8QaQsCCu/TWt4hSxf4w
         LbqOUa9CjcG9tBYCVOUsJOSGb59Btj6EV1oAhf1b7ZyLuZbA0G+kL1Y1Iy9i/8YTpgYS
         DUUNhY/UtJkG6wghwW0GG2kw6l6A2KuumENiXnYoT/QdKo8IUYtmcYPvpiuA6dimpDr9
         FAVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SU6d7Bv0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=efSduObW7N9ForDtMWtGYMZHLSVSAW0JXwqBrUnntuI=;
        b=JeyaptUou/RnS+fmGTR7ita8mRa++lpl24rfzabVcJsQolBzTx9ZXnNXca+CPGfRBQ
         iUhndLS0FJolGtkRrzg1s9DAY7JA+GoHKRMmZ8/9jMkL4EWJGHP6LLHz6yAeTQYWFvwT
         +W4ovqvagIY/o0GunETWvhgzdXK5jg2i337p23JFBqE5yQfVhOG6mAyWFQV20u796CM4
         kcULOhhFDF6F/r9jcyxvJM9c7x1DgoRe7NG/8XogeQ7N1v0+zHTALGd5fsuM/4LfnSmF
         bNKJtHvM2+5Jd31XaHGpdVqr7TTGzcr4uIO/PMqClTTAnJedbamK1T79btbrcm09k0Y+
         88JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=efSduObW7N9ForDtMWtGYMZHLSVSAW0JXwqBrUnntuI=;
        b=5B2P1QEzv5cBbIrGZyKMEEVvNR9Zf261I/BSFSN8KhywRIH6oWOBDRof7SK8OmWmY9
         9RilS8/qaSMdTwpTB1D4wHp/XVnNkMzIzkkgf9xfeEJ5FKcwFVbVFYgo6sJsFavkKT/R
         xhbefn81JVrQfZ/zyKTSzwzMoa0lLtlD14v6cLSV5On5HwO4QP/IXBa2z8UWBLO22eZG
         0sQRB1RgFVnGLPmwnmm7pObHaHlB4+y1PGoU5po02vupj/gReKYfq81F1GDS0tIscZBd
         R6lcMVMNdBUrgAN1K0XEMisP5cQANBE39UIzMwK3uPxiBOlMrSrVwK9GqP+Cn10VWJV8
         McZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333hqYrBbarzvqLSTpPyaJMFHACObUdiE45M7VT2G4olIGO0SKv
	UN4HTha//CYkE9Wfj7q1zSs=
X-Google-Smtp-Source: ABdhPJzE0IbeOI3TjUMSggeW7hyNyroyAk0fQiHoABk7+DvDQBjwAQ8zgM2xyWYXoYPup6BKPOGeqA==
X-Received: by 2002:a5d:68c9:: with SMTP id p9mr15476050wrw.435.1643047413655;
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6017:: with SMTP id az23ls30753wmb.3.canary-gmail;
 Mon, 24 Jan 2022 10:03:33 -0800 (PST)
X-Received: by 2002:a1c:21d6:: with SMTP id h205mr2799139wmh.164.1643047413095;
        Mon, 24 Jan 2022 10:03:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047413; cv=none;
        d=google.com; s=arc-20160816;
        b=fY1qjBG1fd86QgQAtEh4LNtJzAVCdmWau+a2PHx0fKSVZ5bpZbADcHZAGPRVbMeTbU
         ovqRSdVMpMpf5e+NEA3+8u4lweH7qlXIOwBURxEA+CVVDVAeizWkG69I3XXCgY6LQnBh
         NHsyFeCbTMr3lpBgXkXKOwpvvEXQuPfHT1oxMnELrf7k/lxmmxD7ROB+lAZfjwFdZ5rH
         oW2kIYbPLdQRA0m99kJRQggq877Za4LJFcf05OGoR8SQGdLf5UCobA8Lg9mRSnhMN3K5
         6ZwfkflFWuiESbwZh0a5C8Pd8kc2guxz6/SFIwbzSiZJdjIpIG8ozmKMz4ZMIxApynHC
         izag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bVjXHubzfURs5BxSD6VmUXrd7L08/2QwTbUc3U13ubk=;
        b=0TZ1QKC7lYru31bE58NqslwQp+0hlHuRBNSwdspwIB+qOEgBt7rtbkZJB2EFxv9lNX
         cNK7MgsgJmlMyk/D8EE+uZuvfDSS6MU3sp/cD7GpS7C640g8eqlcqLJWV/MUzKYBzLyU
         iywcmxxo7NmcTPMBiWULW0AvEayv2mxOu7yllhvEiCPegh4mGp2PeHWNSDd5XMlhmLQv
         oujvoXdkW2POkdhg0XtZtB97nnfA5sb1R3OXqV8a/RuSwS47oWKzqwXoFwBTsRAlEPNf
         tmT0E7z+no1gtv/TavCcWfLYq9/jJRzlhpzb7ibtjaoqHTC4Vr1fFnRmjTjEy5nyd7wI
         2iAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SU6d7Bv0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id v5si22413wme.4.2022.01.24.10.03.33
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
Subject: [PATCH v6 11/39] kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
Date: Mon, 24 Jan 2022 19:02:19 +0100
Message-Id: <587e3fc36358b88049320a89cc8dc6deaecb0cda.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SU6d7Bv0;       spf=pass
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
index abed862d889d..b3959327e06c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/587e3fc36358b88049320a89cc8dc6deaecb0cda.1643047180.git.andreyknvl%40google.com.
