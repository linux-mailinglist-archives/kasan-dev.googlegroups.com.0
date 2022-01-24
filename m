Return-Path: <kasan-dev+bncBAABBFGUXOHQMGQE6RUXGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 085844987A5
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:04:05 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id m3-20020a7bcb83000000b0034f75d92f27sf286126wmi.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:04:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047444; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/iO92klH4CukyzfJ8CLRTdcVkH13HJi7wQfhBMtmU2wEvBvmQcBRiKHeZ+ykHOeUY
         mR9dpkiiAKpBaSFG6CkEPhz9rl8VadB+HGl1/uql7gMNiS/xQvinrx/dcTLIejQhCOFl
         RPfs3lx1rhu1tZ/C32A1P4RFGUjxJOdOw8inAZsi7kob8LX3ALUyIEN1s59OJDmOQyBz
         tK3b7AuZpgKz9kCRVj1ci3sCZxuLE+BzzKslEw7mdbEhd+Q9rNPMkd/+FdJYugORULwu
         Ph6Gw3dFc3af25qjIfSUbrBaE123/FQa6G87YuXPcv9uzI6drOMpedk72Wq/9qhX/M2F
         up5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jAgBqok1iiwNlcswUeJh2oybRYIXvWlL3QJpMn6LDGo=;
        b=g2wQZwQZeR1POGpQToUztRJerwqrWn4tIPGQyFNtv1PWED0TFkpjMwdcOFM8ImB2R3
         PDUWdDOLy104M9GILVqlQq9rvhQDELYhoh8RT/aLPd7F0oElJtAcbJUc/XcFsqV4cxvU
         SwZtCjwGzLAtkvuDrsvdEEHk5yU9glM6Q+nHEMI0Iy/mGeJc5jAG/sc4N0daJMbgYXdz
         O/m2TGpKYjDiyCLxXcCIgWA+eZ6F8EghMmNOWFFmaK5NvBFYNz7irolQm5dE4RBJO3KU
         SKJt/zK+gAOuykxtMx+l1m0CT1MNTrXYu11V16UXV5MbVUKWYcymbkRPUWskhYOWFNRt
         WpnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kLmRezKu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAgBqok1iiwNlcswUeJh2oybRYIXvWlL3QJpMn6LDGo=;
        b=IBFyhcgdRmd04DMUGWUfY6YrC6TF+TodtID8uBRImt121LXyqraSkXVjS6fsMFiixy
         xhE7Yj5h1YjzXjjFnArVqMS1+5NqSAhkopbY8ZZaR5+JLEvevREjNrpYKsZqx4LX5vY3
         nI0AXxv2KVUpQrNOL886RUttmw4FCoY0dQtwpHk5PziRphcbmr3qiQCktn8cRU8SLxZm
         inRDwoLZxwmEmfM2X96HcZilnVivoWNhNNYaQyR9kq+gcuijCwj//DVSej6RZwHgrzUr
         gNSRGwfan829rohftJ51pch2k4cF66B+O4xmrlA4sa9+PBH0pTje93O5qbX1UBFsw5+0
         QiOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAgBqok1iiwNlcswUeJh2oybRYIXvWlL3QJpMn6LDGo=;
        b=jHnhgPz5DOeeWJYk9NWDRMlw0lYiS74Qb00YBJQniDe6XqWYpA5eXj/nLilD1rIdZc
         r10GiVKPlqCZRMLLHPLj6c0A9LZc9CzQhaF7Lx+Z8TKutqxgHQNn/Akw8nn6Q8kzD7B7
         7cxMw3OplpCshNZ1Ca91KJGNU7zu2wZV+9VZFkrEze3D+sldCd9lwMqdFWlo4gFe3/Jx
         O8Piij0zryEqhR+Ss4COdHemKMnqtBcF3tyXD+8LfSwzvMY733w2wGIFcv630BU80Zxj
         pjDJcBYH/qjWk9c7NCEOsFKlpeEbAiyeXFjn1TB3s1nALnKAhYicdh98f1yTg413rk2p
         vAeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QTc8xAqcyxAOgZS+jQnY7IY4Md/nvotF1jhhI4DLluvlDSfZ+
	71rRaQfQJRus05LzBeK3o1s=
X-Google-Smtp-Source: ABdhPJx84l2ZXs2D+9HFzqReqffv04Ub2Jyi16HuTl9+Jrry0J1HSlZluW65mOJ7aqru1zN9JAqjdw==
X-Received: by 2002:a05:600c:4ca7:: with SMTP id g39mr2881980wmp.158.1643047444678;
        Mon, 24 Jan 2022 10:04:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:448f:: with SMTP id j15ls291549wrq.3.gmail; Mon, 24 Jan
 2022 10:04:04 -0800 (PST)
X-Received: by 2002:a05:6000:1acd:: with SMTP id i13mr15808058wry.232.1643047444105;
        Mon, 24 Jan 2022 10:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047444; cv=none;
        d=google.com; s=arc-20160816;
        b=ZhXSBpqRHCmJd0ADJHDAyQhPitoWjKzOAib6UXdtj0nuRa6pSsdv99TD0qFNq4FG61
         cUHm14wyxqIU+NlgZj5+U4ZZZ1BTSJqf/nNDJ7H2LdtCb069JWD5PFHMheUCokKAD1Iy
         o3ePFEWSfx/Zk8fb5jHxKvkvh90Rmd1CmgkJ6WY6DRFRpU+vNTFzYqaDgFB6ctVtg8mC
         2Yo0QZi+1oxemX6YV/yfvepfFAnARNrPYs8inSj7/MM1HrQ4cSOmeCtpFkl/lEcRq9/B
         48YWSXpMlor8UcarjVwYDBzMzNDFAihwEG/re7VmIouAuRCmRRPPAEVTruGpDdLu2amd
         H8Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S5E8BX4t2WOGndjQQ7xLiyrqvsQHzLaEF763pxkUAQ8=;
        b=Tv7g5FiSsEeqPRJ6Ih02cIGC0veYHN5cB95SC11bUj5VN2u5QYFR8h7Lk6pMFx4Hbk
         /eerkVTVQBCwUiZBe8mnZw6tuULRPm8P7ytEObvjlTHSOoWTuCnHujsrTMsP+ZWKSqdJ
         33Qt7nM0Dmdc7l7li8m8DZMF1ALBFfuUd/nQujg8KGT+K76dghWmaO1Uf/UrnJ5Phsns
         qSHk2wzMG1frDfeKqyJudAblyi01iy/zrsMS4eg2s51AymfPQUIpRm5E63pCyeQnVh+c
         fVz89sOsxOqY6Jo06ZeFFdaZ/GMlp0bwubCi+YUsHxb+JWA+wzagaPuA/LHY72ibeM8v
         J0/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kLmRezKu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id be15si1615wmb.0.2022.01.24.10.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:04:04 -0800 (PST)
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
Subject: [PATCH v6 12/39] kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
Date: Mon, 24 Jan 2022 19:02:20 +0100
Message-Id: <7214c1698b754ccfaa44a792113c95cc1f807c48.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kLmRezKu;       spf=pass
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

Pull the SetPageSkipKASanPoison() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patches.

Also turn the kasan_has_integrated_init() check into the proper
kasan_hw_tags_enabled() one. These checks evaluate to the same value,
but logically skipping kasan poisoning has nothing to do with
integrated init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Use proper kasan_hw_tags_enabled() check instead of
  IS_ENABLED(CONFIG_KASAN_HW_TAGS).
---
 mm/page_alloc.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index b3959327e06c..c51d637cdab3 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2435,9 +2435,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
-			SetPageSkipKASanPoison(page);
-
 		if (!init_tags)
 			kasan_unpoison_pages(page, order, init);
 	} else {
@@ -2446,6 +2443,9 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		if (init)
 			kernel_init_free_pages(page, 1 << order);
 	}
+	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
+	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
+		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7214c1698b754ccfaa44a792113c95cc1f807c48.1643047180.git.andreyknvl%40google.com.
