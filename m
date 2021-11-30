Return-Path: <kasan-dev+bncBAABBXFUTKGQMGQE23W3AAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DC0B5464061
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:44 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id h7-20020adfaa87000000b001885269a937sf3863406wrc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308444; cv=pass;
        d=google.com; s=arc-20160816;
        b=nUlaeCMxd9fd2R3ndyWgoh8jUHwVlw/MyIeipnQft6mIdsTpfxxR99RHBmB85IWEmu
         1hmQKz3qJaNj+gjetYR25Kb9ANo8C/I3FwWIQSH2ZD9xK5TVyAghhGlhhl3Wx8H+TNH8
         /+0OMhMclQ0l8Liw6Z7daG7HwJ/gXToHXCN8Joh7mG+RCEDnNqksnvY5z+oXqhFeOJS/
         5BQk1CUWj3PXacUamC/tgOq6tPTY18tk3KMmLYkCgAzjlHiujsW34ju3Ibrn66i2BEWX
         BFXxTO914ZUfQktVjshbp6zsg12sXMeIQyPZvZp6C0aptCJvCKNxDkFKM6xtw+NXzIyQ
         NpWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T1KY0l0TKMrTMNPSDKxSF04x541IXb4PhcFg37I1EDw=;
        b=RlIUa791LsahJur5o5x4sroObTGwmX6XeLcykemLnZecs3VipEIYuHN/b2yLKUSo6V
         wJ3bBZdiZ5pyiqBj3FU4LxCoLrszcU8EK0/jqv2EZ6CVGsuGgpc5jV8Qeea+VZpCKl/R
         /jQQuEfSqSChIHN/17+QgPzB8cN6IN8zH3zXDlZPfj/PnKMAN/jLK9nhvAhJpgTLYwkK
         n1mbdHZqqKQA0rOukZ3frx3dZXt8DqRLkaNHb7gsu3tG4fK9xadzvkfiw683ptcxtXNw
         CG8B7UX25EThcOxE8KwhwFrqJVjKzKaoubAksr3llTFr85pMHjZg6fa+rkdm+qTvp4H7
         rBvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1KY0l0TKMrTMNPSDKxSF04x541IXb4PhcFg37I1EDw=;
        b=KW7ronoSoC4xNAd2Fbd879jfNeTwLiC6cC2EM2GrQrDMR8JnTeYN6KvjEl+7/GGA5x
         3gKI35RKG4t/NufwbI/FoqYV4o7Ag5N04OS5pX5nfa97ylL5M73RZSXFk+k3EryYJhDv
         7LSIjoT8HFENwCX6NSdTYHyxFHxfofA9NqAFDnDBMYysqt1puI8Du9zH3KYL5KBCTKCE
         EIjmGMlrfOo5dBlUoYZw/hlscBdV9lzGrwfIvIf3gQHrv7+nduuKeKPH9uEQ2LxeFwx7
         BVGJHCQUgLEnBlIKLbMiREpIrP+KytDN24iIpHfyaIEBtcHg+PZe1ddje5IDzTVPxlax
         6Nug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1KY0l0TKMrTMNPSDKxSF04x541IXb4PhcFg37I1EDw=;
        b=Bf596c5A0Bzik891Xr0kQvXOeSQmZ5pXM/L2vjbqAexSZBGAl6N2PakRK/CsfxfNV9
         8ECCIGimrQzj2EtrjSNMTO19BQ5Uo/5fKoU+4f5FwSvfg2lD4xJZrhcDL7Tf1e8K/3d2
         zh4V21ZTOU6o2orgPtajlnMBqE0Oq1c4YkbXqJcIf5J/AJt02SjysLXXY/UK+knWoKRf
         nm+IO/X5V8kHK7jDUCQyZegr8W1nY50zCL9stMslFHCkN7EO4NN51o0+36znrzsj1ukr
         5+lfD6ehYiGH+QO+EZayNmFBkxHXqjoqtZ1ZHs/dPDOOYmSM1hRV6yf4jqBop+B2vway
         pn+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XXizAUBKBgcnAyuIwdqwh9nueptVQd7Ie8BbhhCRGOi/Egc5D
	a5nxeRkHyX7EiXIpRDaLZiA=
X-Google-Smtp-Source: ABdhPJxYMKmTcMA49c1JocctZ2ECh9NDcpRKRKqVO6kpuoBUg7+nxDoaWmLvxNvWrMXM3xXczfgkEg==
X-Received: by 2002:a5d:4889:: with SMTP id g9mr1747584wrq.455.1638308444664;
        Tue, 30 Nov 2021 13:40:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls2108096wmb.3.canary-gmail; Tue,
 30 Nov 2021 13:40:44 -0800 (PST)
X-Received: by 2002:a05:600c:4e4a:: with SMTP id e10mr1617867wmq.155.1638308443932;
        Tue, 30 Nov 2021 13:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308443; cv=none;
        d=google.com; s=arc-20160816;
        b=uIOuVQniK7CCbBpJHNXSwAxGST3+44LL8qhiqm7mIpyRXQpW7yo2f0FI7ngElhbioe
         9KQIixk3U1KppWyJWLf7IzrZSjWd087Z7WQDaCauYCtk6pfWTgE1egaYazdx0dyF01qM
         jGTgCWmo/QwQTcupoXggcNIAb8U2sZWcMO5xMw9hG0Cpqr9uvXDqAI/sv6QjD91Qpgjb
         nurw8EqmZfWUivxj4kKTR+QbSJiRH1yRdlhdURwVos6eUiFJjNY1i6jBgJuUssjr5uOr
         7z0R5gqUuWcVGa9LiHEsJTFxBCt3a2wUM8c8FlIvwCyvQdZsLXTQoym5xrzimgWmMuCJ
         ET0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ts/+vKQtXDSJvPr19r3mwGmXA1Q9MgMIZloK2e1q7WQ=;
        b=qwvXYsD0+En8KZb1G+EX8AdhzFX6Dq7P1B+1lG7/6+Lj3OQ8QVr9RFjqqxTKXHLlGe
         MeZHdS5FA6yw1vF/7o06vuKrdWRn4VOudwFQIpXCeRjIvE+Hgz5kvwS+jwl4AnGWu955
         aoPTjVbYAhesZhKlV4v3ofgfU5HxKaz4Yu7Aobn+UDMfmXEgrVx8jMTR1kLAs89P9/Ts
         TPtlFqSM3ATl7ERN3oEaSV/7kEe0d+Ozig0ow8XvGWeERe4jlxUrE4Ae+ijykc/3owSk
         sMWCOw6ORKO9uj7wTl9AAitSbHyTQugDmuZ9QySv175F6OYd55trFbNdtF26Z1LpPhTE
         IXRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id c2si672886wmq.2.2021.11.30.13.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH 05/31] kasan, page_alloc: init memory of skipped pages on free
Date: Tue, 30 Nov 2021 22:39:11 +0100
Message-Id: <62e844bae175b9f354cda6f72ba140438e83791a.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Since commit 7a3b83537188 ("kasan: use separate (un)poison implementation
for integrated init"), when all init, kasan_has_integrated_init(), and
skip_kasan_poison are true, free_pages_prepare() doesn't initialize
the page. This is wrong.

Fix it by remembering whether kasan_poison_pages() performed
initialization, and call kernel_init_free_pages() if it didn't.

Fixes: 7a3b83537188 ("kasan: use separate (un)poison implementation for integrated init")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0673db27dd12..2ada09a58e4b 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1360,9 +1360,14 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!skip_kasan_poison)
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
-	if (init && !kasan_has_integrated_init())
+
+		/* Memory is already initialized if KASAN did it internally. */
+		if (kasan_has_integrated_init())
+			init = false;
+	}
+	if (init)
 		kernel_init_free_pages(page, 1 << order);
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/62e844bae175b9f354cda6f72ba140438e83791a.1638308023.git.andreyknvl%40google.com.
