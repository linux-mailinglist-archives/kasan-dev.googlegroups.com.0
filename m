Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSX433WQKGQEWQRIO6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31DE9E7F24
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:31 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id b5sf2024205uap.6
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322890; cv=pass;
        d=google.com; s=arc-20160816;
        b=sj9LzjYxauW56nSpQfWU857fmWF/HlLKn20mNV2pAPQ0N54l4ZdRZBjbsQ5E0iifeT
         3+j2ocWBZY7YbbOv/vA/ncz7h16/YMOW/KfjxtFgA96wpJHDkzsGW1LXWxdAGzEgkNc9
         62L9xXG/udFaUKUgELjoJcvxmeN+K63t5Kxsg/BrQ03zi6ecKyORAzsDtFeH11R0ciGf
         U2YrYcekwJ+qn6Wmsxyj9XBHo4PZzXPcgQ7KztmCT8vveRVQ8hUtEM9ZBs+fs7ZU5XEl
         0sG9KDRSPuPAUfZFMx66EOjRDZbDrLwKrGQoMXAoNXDxWKQJsnVMA9AmYAH/eo1PEd5t
         AK0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qp8QtrrcqaTxaKb2Lu1LgGVECtW2po5xaV1E44klvqE=;
        b=o5MR/Lm8RQmGvgDyM0Wr11907rp8UhUa4vuO0A2HcITVxEQ2MohF6YXGAnwbXB+wdK
         8R7PR2R+IipgnLSmCQaqIoceruAwUQWksiWsdVqi0cSKQmNtb/aXR3kCb1t2MzFd/zj1
         Jtb+fxtgBAT1Q8NSJOZNOEP9whlhKTM0t8XkSGy6yfVI1miPYIkI7T0UFTGov0Li1QNM
         oR2JMsM2NnFCTCy3bWK4l82oVAR4mMRkX6EDzsliyXl2lYWF6iO7qHIc/4YgWizSUZTA
         75kjlypbhlBQlXPt6QF3ynS0fk6Qh0R5FpIz8Ew3gRPg7Y2d8Qf+geouiXqdsil+w0cT
         sGaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=q37hvvFE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qp8QtrrcqaTxaKb2Lu1LgGVECtW2po5xaV1E44klvqE=;
        b=BxhyrXsi2dcT0w9c7jXuQpxBUi8NBku7LBIuPJLppE/dALRF7nqpesTQzNh2htAvEh
         x8vUw4qVFfi1TsVwo1weEPLrtZCQPH9YYLnlwyKvln4zrFptUhh7ee6Gc64h1TvP18Md
         fffk1FgRz432CZr93+QzWHw3L4q0tPi2DmCX4U5NHLIWulM7jZ4WVOBQ05sQn6/hdkPL
         zc68mZklCKhljRoK7eYAaipNyoB0F5zNS7WYEO3QSFhtoClRphY9tN9DuA1C/qgvutai
         kCT1CtdmitUXWY1bqH9AHZRI+LjlyqclW4SZw+86SMWarMdhUzM/PqucaTF4pn1nyM+S
         b+hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qp8QtrrcqaTxaKb2Lu1LgGVECtW2po5xaV1E44klvqE=;
        b=fcs7tZSUTmgSBQ/j7kgOwUwzouKHouErxfaVh9uVD/BjrAwMNpXJ3bWn+EeQbGYGWM
         BQa7RTBSGCisPf/5axW28UdXmcZrb79qUaAUwqtFqKx55LPMMZYmpvIfgJBx9Q1N6r8D
         oslLIyDATNXBGGydbPiTsionYnSeSjCSLG9i+bZsOLFhxxFQiZmM2qv0nxzKnbeqOrzP
         gKcMzXU6u5RBqKHz6Rlda8IzQbu+UNN7WY2fkuEWQssfp3YfP1dXidUIyfYxhU7ZPgYt
         Qv79/mNiigDlEAifQywA+k6eNJeM088eAs84XRzTg0Q6y5C0CTuKsMv+T/Bvouvt0EI9
         9mSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUKmkEgNOU6kupxn4xzRvOXD+noV1fuwTDMa1gSxgDTk+uqETPs
	btNFz2atGMva8YiPbd/K8zk=
X-Google-Smtp-Source: APXvYqxHewQ1Wrvv0cTlr3Om5te2VQkcGr4E4lL2ONwSOj8z9MvIPsHe4xIgMQslPRpB/qgcWp5pdg==
X-Received: by 2002:a05:6102:226a:: with SMTP id v10mr540549vsd.71.1572322890260;
        Mon, 28 Oct 2019 21:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f68c:: with SMTP id n12ls1819979vso.14.gmail; Mon, 28
 Oct 2019 21:21:29 -0700 (PDT)
X-Received: by 2002:a67:c907:: with SMTP id w7mr539394vsk.59.1572322889778;
        Mon, 28 Oct 2019 21:21:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322889; cv=none;
        d=google.com; s=arc-20160816;
        b=oHWUfrqgyzVKcjBZMcxt3SA5ieqf9xP+FPtxtGAn5bDHgwyt+pWZqGdhPJH12f/fkX
         XjbE7BP7CH8Yf3Xb7RpS7ESyXQaeDyQUK2HK5y+PRY0ciSXUz2vJ/ig0PVr8m0lG0iF3
         nrH86wjtznDOO4Cnjwm3uxcRtOqA2TA4xW8SlTjxB5sMZPYBL6TmOZT1fv9bbm+Zs7t1
         9Jn46wINR7/wt6rUpkUJnq+eAq9Ovu4ZvpEgaj8AyDUWOuGKEI98vMa52mmxSzpDfDnR
         UydnGC2CvvV7BrMG7i7BOygucfAB/E2kVV5eEz8vLvf1ZxhDMOZjPJY6cuDwV3JkpmY6
         ki8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E6G/cbdwI55VRIDPH2MzPtSSwLNnlVDKj+xUqyB9XvU=;
        b=O8ca1sLNEJtKsSuCPRRJP+bgX3fbfGGrch1tIReppOvo1CZORWKx3kApT3/K69hfaX
         C2pkNTB8WOmz5gmk0QZFc12KoF1JxfAWklDGjD55fL69I3u/1W/ChWw4iOefukE+ThAy
         vkToosxjOL+8c/eOfRAZcYcPdo21yTBYQWfX8VSyhYsuQFig8KkB2wMdOXwlri9MAkn/
         qR5XzqdNqWEm/UiMLypELaUvX88wG/K3Ps6+wfs25PMJjSHZD0I3aYvshPMfzFvFZzxY
         jCkUrJQrZltkPpEpFwit5RGuhXDkHQ5AhCw5M6dKWs8b0YkcjPvd0D+cr+avV6tMyE8P
         TSLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=q37hvvFE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id a12si182663vkm.1.2019.10.28.21.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id c13so8585414pfp.5
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:29 -0700 (PDT)
X-Received: by 2002:a63:e60b:: with SMTP id g11mr23118732pgh.119.1572322888371;
        Mon, 28 Oct 2019 21:21:28 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id z4sm957607pjt.20.2019.10.28.21.21.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:27 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 5/5] kasan debug: track pages allocated for vmalloc shadow
Date: Tue, 29 Oct 2019 15:20:59 +1100
Message-Id: <20191029042059.28541-6-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191029042059.28541-1-dja@axtens.net>
References: <20191029042059.28541-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=q37hvvFE;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Provide the current number of vmalloc shadow pages in
/sys/kernel/debug/kasan/vmalloc_shadow_pages.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v10: rebase on linux-next/master.

v8: rename kasan_vmalloc/shadow_pages -> kasan/vmalloc_shadow_pages

On v4 (no dynamic freeing), I saw the following approximate figures
on my test VM:

 - fresh boot: 720
 - after test_vmalloc: ~14000

With v5 (lazy dynamic freeing):

 - boot: ~490-500
 - running modprobe test_vmalloc pushes the figures up to sometimes
    as high as ~14000, but they drop down to ~560 after the test ends.
    I'm not sure where the extra sixty pages are from, but running the
    test repeately doesn't cause the number to keep growing, so I don't
    think we're leaking.
 - with vmap_stack, spawning tasks pushes the figure up to ~4200, then
    some clearing kicks in and drops it down to previous levels again.
---
 mm/kasan/common.c | 23 +++++++++++++++++++++++
 1 file changed, 23 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6e7bc5d3fa83..a4b5c64da16f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -35,6 +35,7 @@
 #include <linux/vmalloc.h>
 #include <linux/bug.h>
 #include <linux/uaccess.h>
+#include <linux/debugfs.h>
 
 #include <asm/tlbflush.h>
 
@@ -750,6 +751,8 @@ core_initcall(kasan_memhotplug_init);
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
+static u64 vmalloc_shadow_pages;
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
@@ -770,6 +773,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(pte_none(*ptep))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
+		vmalloc_shadow_pages++;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 	if (page)
@@ -858,6 +862,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(*ptep))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
+		vmalloc_shadow_pages--;
 	}
 	spin_unlock(&init_mm.page_table_lock);
 
@@ -974,4 +979,22 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 				       (unsigned long)shadow_end);
 	}
 }
+
+static __init int kasan_init_debugfs(void)
+{
+	struct dentry *root;
+
+	root = debugfs_create_dir("kasan", NULL);
+	if (IS_ERR(root)) {
+		if (PTR_ERR(root) == -ENODEV)
+			return 0;
+		return PTR_ERR(root);
+	}
+
+	debugfs_create_u64("vmalloc_shadow_pages", 0444, root,
+			   &vmalloc_shadow_pages);
+
+	return 0;
+}
+late_initcall(kasan_init_debugfs);
 #endif
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-6-dja%40axtens.net.
