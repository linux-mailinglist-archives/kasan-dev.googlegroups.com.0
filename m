Return-Path: <kasan-dev+bncBAABB4WTXOHQMGQERPNT2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B7BF7498799
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:30 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id r27-20020adfb1db000000b001d7567e33basf2198697wra.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047410; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeGdwWAN6X7DNpNY7lnSH0xVUc2NYW1vZC8kwvGS1/Di/FRuyRjJ+XXZwJMVBqp3a+
         dkU0RkZVlpdzuHl0x3gr5n3e5QfVlaRKw7dHENF4vOekHO4lLywx72DhfTY2xDcnC1tY
         e0QaLQURWcvuDrXNkQYXm+x7Ln8FqDGDpbnuFTHAUNyhsGx5iLTCgXWeuIUGOOxMEIPl
         b0On90BbJPZ0St2GukERQnykyg0+IFa1aGh1y/i+7WSqot/RL2MdXtZvkcuiKgkAcGlE
         RM8X32L5v7srD2s2NNauCvO4LyD8gjPXXR7QyDzUcDsPZ5YfG5taSmYO8yfDNjJz0Rnu
         1nFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6mCmoe996eDyWuHU18AkUueBAwSUxsbVDWcPzoWr3Hg=;
        b=WfqS8EZ2RBK7uQmnppgeh3pAXUYGctNkqGVDA8EBtA0sVdWwi9iclxVPOfZ+0FffaS
         lIidllcgrC6cd5Q072xgEvhs1Kjev1WiWEIn2GP6HjCZBXUDlNl3bpVtlNgAD92XIsWM
         dGCht4b2n8LGTVEIuKrRNLfYvJJ6fwCK4zCqC0lGRjg47Iud/fNMIFfRpDCsdj7hOAIu
         p9spv28QVsmazFnXXtYyCmdVx8iA4pGuu0kUV8FWfvTp+AFROH6zU6NSXD+08K1NS6O1
         3ks+Nf7Jb1Su/bkfFbqhYLGxVd2q9OZ71SG/mbC0C1qKSckXIJHy4uebuPeFiYlpLy86
         nzrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J6XktU+x;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6mCmoe996eDyWuHU18AkUueBAwSUxsbVDWcPzoWr3Hg=;
        b=rtG+vRJHm74cFnJDOFcwa4SRlDPc2AwifI0rduCaEC9OpV28h9T0YOMj087jjjHhbj
         WQv7IzrTRDwvbQMnYeb972ploUCtOrSZ3oQqlYnyHzFQAHNQ01F6kzb0G8nERAUh9wuA
         Po2LukwRz089598ji5zmIIFd2jYSVBAvZgSliaeDF5Rt1kGC4Oqw4NZxh46LYYzexP04
         nrXmekN66LpRsmoICCt7EvfjYgdXIjS9vuiA7TQyk4A5g+JpO3EpMbGeYxBxax62tkll
         wqRE8iK+dwBn8avBWB2RqFvSGh52AshRY04AbMoKBAqY86rFkuK4mNOF/WIjH12E4dEc
         oKxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6mCmoe996eDyWuHU18AkUueBAwSUxsbVDWcPzoWr3Hg=;
        b=ZyizGpq1B5ttea30u8JaLGQNXWKvX+Cr0JmleqLJ7JA5PRiwAG5Uqys/pMA/0KhjUZ
         eMzSVVZrpE4/iuURkDqdrA3A4uQgpwaMEUBgjSRv24Hq9Mj0WxRTKL4MAz3f+YH8A36A
         mDrPNw23Ne1x3u+wx6aDyfF7Kwg16If1HgTlzAiJRxhDhNDgZm09EWQ70g6YuL1k5vIa
         TRvRVI3mM3s7uzhEsfohr/ubyUQYMGgVkw2nE8EQQsNLDssqsyvBKysB11w7+HZqsj7f
         JLPXGzRZ+uRlU3W8IFZ7CgVog5mqIROVzwNjFe+Bb2xA0MyDgSaOj2q7XTojyw8QdVWZ
         4KiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NfKtVdQWhq4Aoz4mc+NKZ499gIKjBtWhzen1D1T6tnaE53qaL
	WECWXWqDL69ty0UekG+UchY=
X-Google-Smtp-Source: ABdhPJxtTvY3gTLm4nwuUsKIqbkOkkJnCjmtzbm1I6utVB58UoGck1PWSox6NNSHvdlon7C4mNpXUA==
X-Received: by 2002:a05:600c:1994:: with SMTP id t20mr2827559wmq.79.1643047410408;
        Mon, 24 Jan 2022 10:03:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6017:: with SMTP id az23ls30692wmb.3.canary-gmail;
 Mon, 24 Jan 2022 10:03:29 -0800 (PST)
X-Received: by 2002:a05:600c:20b:: with SMTP id 11mr2710814wmi.146.1643047409700;
        Mon, 24 Jan 2022 10:03:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047409; cv=none;
        d=google.com; s=arc-20160816;
        b=R52TalgFRADhUCcrdHiMphEEeXpMGIiTujRbeoF/jwsZCv+nlMMW3jSGJdqjsWmm2f
         pEeyuFZ9fbhERTRDH2VkeOBTl8/0Yfm97jnh0nTfSOOiQCZscJKeNmEEFf+dkyFawNvW
         lL3sCS4c8/HhQpdlfWSYJ1LujBNtrV03m047ZDMU6wHU0Gkla+shmpvV5J9KWa+Yqxtr
         T0KiPpX86sZax1m1pXpex7M+q/yfKpB0hR3kaTpqOTyFO9JY7wAMxq0X9prIdF+ZvwIj
         Okldv3rSl7A6C2Clh0vbd+7u8nI6ZGXCC2aQ23sjkd5fYkQnpdfMb+cZ0gVA+cm3ah2t
         Sl8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YUKFeRnU18yjbXq2i74hXRIrDf5f39WtjIbACz6CeBE=;
        b=EpHh7Km0IVEfek4g76YgHdx6/MCyD+e1FuSRGbDNLG1zRSORL0+XU7f6Xyv23Av2Ao
         5EB10sUrOlQT73WZvONLWzsOGCEUN+4nGlST83Il4JS32Fu3Dl3hTMr3muDDskbxNPn9
         WMiRJWFh1b065sKvOXuVeb2JUM2YfebAom+nIw4nyF7GPXlieoYLMPRWzpnSS5v4nZ1T
         0PYeAwuEZH80Q0qMfzo+ETHgBzkvXRzTGw+RFwN+rBp8KEzxtTM0S5ZpwfOWBpF1liS0
         Zh8F6WOBMvq7uaJ5ksgN62kIUC9LsS0FKdXmQfz5Mf0TkxQthANq6dwi9HCy/cBzwflE
         uOtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J6XktU+x;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id h16si3275wml.0.2022.01.24.10.03.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:03:29 -0800 (PST)
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
Subject: [PATCH v6 06/39] kasan: drop skip_kasan_poison variable in free_pages_prepare
Date: Mon, 24 Jan 2022 19:02:14 +0100
Message-Id: <1d33212e79bc9ef0b4d3863f903875823e89046f.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=J6XktU+x;       spf=pass
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

skip_kasan_poison is only used in a single place.
Call should_skip_kasan_poison() directly for simplicity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/page_alloc.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index f994fd68e3b1..8481420d2502 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1301,7 +1301,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
-	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1375,7 +1374,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!skip_kasan_poison) {
+	if (!should_skip_kasan_poison(page, fpi_flags)) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d33212e79bc9ef0b4d3863f903875823e89046f.1643047180.git.andreyknvl%40google.com.
