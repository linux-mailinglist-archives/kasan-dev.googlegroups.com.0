Return-Path: <kasan-dev+bncBAABBNPZQOHAMGQE6ZPKNII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B6E347B576
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:18 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf5161990lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037557; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxBp2Dbf5Vt167XTj/5Wd4e5sFLsKH6VZQu1PGj+oajqIXA/+UqVspQX/Y0E24/fwb
         Y9sPMdjTVh9I/xejx1BC37aZitOZrMwhlXDIiYsUUc8plR7ufUsjjm5HJyNkAlQIsb7v
         8mnorMEd92Dt0pB655O9EBb5iHP6FGLId2DBQDyMiFb5nc7uMMYdtB0GrzgKVX9o/VmY
         L9Wrm6vKXlzRO23yeXiF21lrzUawH8ULS9UayMfIc4sroJi2cULxcNZdV8XSFnzgBizL
         gONB+ZPjU/7ySYh/q6oEOrmvUPCXMmpKPAgnOa6/p7PnprBKcjyZir7NTS/hYbDNgd6A
         BtGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KXs7Tj2MZfdy1dzlTXJFnww9SnrADvaXF2JUfd+qNis=;
        b=V9TIrecBj5nBM78oPy1QUgtuPdZTHcfQBpTINbodicARRkyOKZYaA9xuAPW6Yq9T2F
         MupQX7FdkBiVa6rOx8flKmrIWX7iARrA3lbVUdxFqYTr/7SOz1tclluo3JCkr9IUe7JC
         rHu6aEBorEf2OT2GvfUrH5QUBAYQEs4U09UP/0WBiml2F76lZ7x1MxKpvJgeOdaLvPco
         9LREvUk7L7ugHH8TdD0GxiRW6L9yp9pQo2GKGcSZ1dQhVqJJmOPskv8/Pjzt5J3rbWIQ
         WS7/zTvYmAqlKXQg4GJINRT6MKQTcxZzQFB0D2WL8196LyyvHimS9sODXFh5G9dZwHsP
         8weQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=it34flvf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KXs7Tj2MZfdy1dzlTXJFnww9SnrADvaXF2JUfd+qNis=;
        b=VHl7Y00fRwdqOZY18IJX4fBfQorKuWHiiNDLueqSo9p10D8SSusMSWHL6RDtxqqN9N
         QcxHzjN77Wefyu+EtqiQnaGIwtK0i6vC4/s2PvRjnqpfyGLP0B2uqUs0KohxFiwx1WMT
         cLCvTZIL4oSimBVCFqkhJClW0JgAuHSgGKUHstgWxoJzj6LUfwUQtVuBmxcyyXBtCm6j
         TUvgRi4/kS1eUlwJG2THPyIvLNOEJtqmJLEY2f4jW3WZr3k1cEVvwKL2Ubgo8dgVoX4d
         ue6ePpbf9i8Lr6Y9sk+SBhYtTLHyeF+TkgU/ltyJ6ZCB9CmtCqwEeXtNalv6ioA+Xxv5
         R0BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KXs7Tj2MZfdy1dzlTXJFnww9SnrADvaXF2JUfd+qNis=;
        b=IO/tdt8uF+yPZX0VEIAxMSEvHOCasDTFNBjLGaZ8eGV3lUHuYnFHSPwHlK461dZ0vq
         aoQzn+40WkWyB30NxmOKEr0+pNCXO8h+nDJRxGZH2TZGQLwPnjjDBEsZWgqx/4b34eWE
         FZ+qTWH8k16wbiSAynk9amV5iCWAJnjtMQ5IQv4SvOGJed7jnDrBkJA7bfchF438p9RM
         0EJCQeQe9tVxK+BgsnwREQFd18XjPGrcn7RTH36+hLV8ff9KHGBRLsQsqqZIP1KyOyzy
         mqt8VrU/hEwQPFQ9w/YJAp82KTk0TVwa9AlqzGG6LsWvGbu5/u4ScoEzmn6Ieb9ZmT5Z
         kwJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533yM/BSoxBhMwKl/ZNzVJK5MBwfzUbo9JIaE2122MLS4kRi7Txz
	GnZnUow2I0FkWpwi85YGQd4=
X-Google-Smtp-Source: ABdhPJyc+ifUBfsKSvb+S4BJMtQXdTi142d1S/zeZooK4KyTEesoSBa3G6FUn1c4/78eZPgermA2tw==
X-Received: by 2002:a19:7902:: with SMTP id u2mr153546lfc.512.1640037557709;
        Mon, 20 Dec 2021 13:59:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3389:: with SMTP id h9ls796908lfg.2.gmail; Mon, 20
 Dec 2021 13:59:16 -0800 (PST)
X-Received: by 2002:a05:6512:31c4:: with SMTP id j4mr119679lfe.395.1640037556892;
        Mon, 20 Dec 2021 13:59:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037556; cv=none;
        d=google.com; s=arc-20160816;
        b=d13IzgN+HmoGkm/F4QYKzAOOxTB/EkkWdq06PnlJORFrJ830rb53Vm+TcTHMRDhwI3
         43EMpNZNrQ/ngdH/bpPcVbR/qtgDkHaNN9ywiBr2olkwLTknL/eUxi075YWWIgpw1m4Z
         0MZoQBobzJAu+x0K9u9ESD2flgXy9kbCe14isGbG8cAEA5757oPiu2jqbdscNXq/rOSx
         YE40gwX8KVBwk2mRJlCOd9FyuNEN5i8WGe5LhT+MGkxzlE1y8XVCVImceIuhmdeIAQo8
         zMlClZNUfdBCPjA8jwb6Butb7qMFM5mux3pFCu4Op3GoLBRPja0nsuvk4yz0d3pJPr6o
         gFOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TniNgsonCV7N4x8CfBP962yTwJ3ZQbzv223ievd0EoQ=;
        b=S/ufbSV/7VTUj3oWCjjXe+dPU1hv69KHHA2bTeB5Awa/CITiKPCu8KtEy1PwzXFILS
         hpNhnYveu1hIyTZJIFoL3ND6wrxcAvHAkmua5ASZb8rok1XpsNMF0svtIKsYGVQxJFd/
         qf+ISHgGk6k7H/AQYFjWJG6aLsidLf9HMNWflJhhxNm3u6p/O8T9ga1M6lm0Fv8DTSln
         wHt3lc3Irmvf70c60vdgeYP9IvjAVU+Kt2C0Dm6oVdjSQuWG7BbVTSSiuRYyT5h5gmgs
         7nLR1JTs1IXbw2WNlmM9SAP1vHjIYzxbFZ3b+N/cAaAP5ylfAPcFH/86av305DGsDwXe
         PNgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=it34flvf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id l13si864368lfg.1.2021.12.20.13.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 08/39] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Mon, 20 Dec 2021 22:58:23 +0100
Message-Id: <705af53a07d789b2f139ff91fb7a18343e980989.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=it34flvf;       spf=pass
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

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/705af53a07d789b2f139ff91fb7a18343e980989.1640036051.git.andreyknvl%40google.com.
