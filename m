Return-Path: <kasan-dev+bncBAABBYFXT2KQMGQEMYGSFXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84E27549EE2
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:45 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id br5-20020a056512400500b00479a5157134sf3494986lfb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151585; cv=pass;
        d=google.com; s=arc-20160816;
        b=kDOMu+xhOCQj1MXnVT6czpstpDABGFv1AZV9p4ExtrY/NaSq4pPlLeQEts1lS2Kq08
         L7LbIYwK7mT+Occ0E2ARlUFmU/6VkViiNf12b7iwrjTO71FNJAQRFrtGnp5DTCGGFHyj
         LUgxmTsolWij+/TmijkLBPLeANKi+D/ySvcE2N3wxiopxvSnZ2lPZnf+ytJ9dm9luOOF
         wFb3lHCDaQgkI2YQ4ZtmZdnWF+1o/33z7/UeKK6vM1Ka3R802TPMXpQOzyP5faW5F33/
         YJCQmvQNXhgoCg1hfQG8qi2gL0f/Y0p8U2Ss6uJBJvyRCwH2Xl4tTSy1mp1MYFvWTieX
         soYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FlgZh27xTlNlrq9O2p7AK2D5VYx6CxHFxtnZeb1tq44=;
        b=AAyWKLlPeqDKnW/kAouFBcRB94/kVpWzeS/m6Qs+G20i7keSMO3xVt/Xo0ydwLWebY
         omb7yHESL6ZbxpeZ2jT23rEeeK9bkpWumKoDfm1eRQ5uAmT/vUFFBt2k7IaNX9+UmkXl
         KwOMyNa39ZuESljJ4sWQ+nRAhOuRMJvFsvx9CYZBaj/1Iaz0eH7IVihwB9K+je3QKN4I
         Xoj4McX1GYybWhTFSiJWvLVkfmdwxhTtkj5v84VIUxCsrxSUw3IXZpBB9HEJUaf/NnrE
         uZErhPg614JlR28CdZtFPcwhvJWomHXCYBgT6kT5c5YoH6EchpiiDFJYpPpAKElYEkgZ
         ewmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="U/iYTMjj";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FlgZh27xTlNlrq9O2p7AK2D5VYx6CxHFxtnZeb1tq44=;
        b=N32oGuBJ0hFvQzId007TNgZGD+N/xWIJ4IheLvY1VgKcUelB/mVyd7eOWGHXbOKzPP
         C38y/klTz1Q20tpLs6PIWeJRe5RYwbrPyUDVj2vc7ZJysiYqgpg2SUYYEB2kAcyU+1Oz
         fJ2+XOiN91OhlVuGUbRwUcafx3FbTUdQAPzQ8HD9Ro5MczKXYTWqarQDaMKEE0b8v/J0
         JOW+7UjFWJMyKY6VRNesCUVaKiXt7asA3CvFt41pR2WtjD6acJkwd68jso0fKVnLHhcC
         3py5sySpk2ndm4CnuSa9qWIwPEIcnhNp4Aaw70WETd3PNpSGAIsfZfuNavDyJWNWhMx7
         tiqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FlgZh27xTlNlrq9O2p7AK2D5VYx6CxHFxtnZeb1tq44=;
        b=77aOlSOdt0mSCv83nrG+gStzvqttzZAgkoD98+doON8rdcZjZ0jrP5QpnCzr8rQKv3
         SPQnJ/Rb67SnJQ7vl3p2/yVyC8RxG+bIJulF5gf8y1SJx356a6jhcqdXUlDQyoRNH/Tv
         QiL0BYuvyRZLDGQC9NUW2pDJ99SWCaeP7VmJiIoMrSUvUPdxSxw54e3bEIBdYlCmM+rf
         FbYhXbNpIYld02xHk0Gf1DC1ZO5Wljv2q1qRVL5VnbySdb/yncGVEw5wQXcB5f5nFgI4
         OlpWKHjiWClO8Msv5TuLcXqpL1cBkgJWplpMvCMNVgtNeBDZZ++BLNFefc2bKvDmsVMV
         g2uA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora93X12RgcZ+sa9R4AlhBj3oFPe+k196GDIZxnCAuzFHyQFA858W
	hnY5FJWeaNE1qEVMVDYxQp4=
X-Google-Smtp-Source: AGRyM1tQcc4FaQzsXQvEAIbw+EARYVSUcAnzqKrSVOOldGsDZ31i3EQWCjuoaPiJTlg0su9Lv/RTRg==
X-Received: by 2002:a05:6512:239a:b0:479:2a:3717 with SMTP id c26-20020a056512239a00b00479002a3717mr930757lfv.512.1655151585063;
        Mon, 13 Jun 2022 13:19:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als188419lfa.2.gmail; Mon, 13 Jun 2022
 13:19:44 -0700 (PDT)
X-Received: by 2002:a05:6512:4c7:b0:47d:aab8:8be5 with SMTP id w7-20020a05651204c700b0047daab88be5mr893522lfq.628.1655151584396;
        Mon, 13 Jun 2022 13:19:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151584; cv=none;
        d=google.com; s=arc-20160816;
        b=pB5KZdd5pyxcz/Jz7fG9IbdgpT853YlJdpyCmXasvBGARDdMMXRB7foz6h9Toj3sW4
         PL0Amt+S23w8JMksJS/cpeNYmmoE7LvWtd04M83Px1xUAtojeD3ICXVp3ocKZdt4Oeuw
         YTUgey1d5WKtHAM7ZOSYdNOTX+X6HisrXNjUGhnhQhMIEwyJa3rYU2ew7J6F+YGXitUr
         j9JVbQB20d0ryuDDADHmydirNqVBEXsrqBgzd2req1jwogp3601Zc57MASpkWZxb8OF4
         V2yB1qQ6H4whakLiv8/HmRrjcIE6c9KXo67nrs3q7BGPsD9et7QofI8dEnld1um6c5Xl
         S8iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NlTYbbmb8K8Hz7QxoFNu4DEEzvlhQuGMJFGkSKrxTzk=;
        b=UjCF3SSIz0B2usnxvSRNIGa4mFw46714EXfWX234OqK5/TNlgcCKj9laWBviI2hlyU
         cWIsLkWb3/LfrDBtT9mZcLwopn17urtgRtvscb8a3mzHtS0Q4Z7ZcwrXzQtuBhss8yfw
         4oHzK/v0GWIumxB8QkGugXSjvvtXj+Fs/p8lZwTn/7HdhScsAjDsIuznyl84VdGvLmlK
         H65TPZYmYkCk5M3mDJovatBmbk4vDjJ26j+LmuSW1eOpbsdnup/UDItYPdfr33JkolrP
         p43CYk7XaZ5VtnlIHtmoPn7M6Ib8rqt/KqBmkIrecv6dxZEBwVQdP3N23cB1Tk5WiCiB
         QN5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="U/iYTMjj";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id h18-20020a05651c125200b002556f5e21ecsi262633ljh.3.2022.06.13.13.19.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:19:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 25/32] kasan: make kasan_addr_to_page static
Date: Mon, 13 Jun 2022 22:14:16 +0200
Message-Id: <810b29bfb50dad8cdc5a5a7075e0da1104de1665.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="U/iYTMjj";       spf=pass
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

As kasan_addr_to_page() is only used in report.c, rename it to
addr_to_page() and make it static.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  | 1 -
 mm/kasan/report.c | 4 ++--
 2 files changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f696d50b09fb..e3f100833154 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -285,7 +285,6 @@ bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
 
-struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
 #ifdef CONFIG_KASAN_GENERIC
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ed8234516bab..f3ec6f86b199 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -200,7 +200,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 		pr_err("(stack is not available)\n");
 }
 
-struct page *kasan_addr_to_page(const void *addr)
+static inline struct page *addr_to_page(const void *addr)
 {
 	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
 		return virt_to_head_page(addr);
@@ -283,7 +283,7 @@ static inline bool init_task_stack_addr(const void *addr)
 
 static void print_address_description(void *addr, u8 tag)
 {
-	struct page *page = kasan_addr_to_page(addr);
+	struct page *page = addr_to_page(addr);
 	struct slab *slab = kasan_addr_to_slab(addr);
 
 	dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/810b29bfb50dad8cdc5a5a7075e0da1104de1665.1655150842.git.andreyknvl%40google.com.
