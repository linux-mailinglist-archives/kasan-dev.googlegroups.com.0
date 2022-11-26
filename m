Return-Path: <kasan-dev+bncBAABBEGKRGOAMGQEOL4QYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3868C639806
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 20:12:17 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id l42-20020a05600c1d2a00b003cf8e70c1ecsf6075071wms.4
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 11:12:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669489937; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsYYoJWtxdH4CZMWhllWmTMlS29uHgrDqFTjyhpfiHfPI1aOuwM3SEw+qVz/kYur9z
         zvRfQZGjYvXLuvAaaVmZYtdeVxbXBExY7qG1mdtD64GOn37rauKuWiaVj3YAroirx7Zd
         O0nJyX4m5O9PqADiTK60UPieHURKe5n8zATQMu9wnhIYWov54dnj+h3bLdVTMJJGoM7M
         9v+RhcSO82zpnUffv/0xHZAJ7AdJFTHp1VFUxi30Muf257zACrgkjcSEG2VvOjCIgVuI
         kKev/D6U260OMkh1J1LPvGnxCEtwigTc6nkiMik0o/WA4yaOOcs3PrF9ZSoQST1ymh4t
         ySxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Cc5cE2EgB+riF9PGGxvz3hKDrvu4x0/2XPD3M7MZykA=;
        b=wHlNqiORHlVSJGbWvemEa9FsmQ4kmSJDvw+Um3SAWbIZUpIEAZQMOyBOt9F0hv7Kol
         CEr6D56HJ3xopzsaaEILPPqkZwVsis/zlHEWeBoB4z+0MIF82BJcMvFC8dJIHwW4lkB5
         smeMw8/orDCJqa7NVhtPvLwXrxXpsax0jlo+venkTZuoPSXjw17zfkOV70yWsPf4mTSX
         SRkhfTX9qdXlIh0B1MW1yIBTL512MhsmyJJ/iWLQ95JfmC52mV1iWx7+inTtdiFwtGod
         sv4PGfnOyYyseid4DJeJVNvzMN6ipGAuJipPqUX9zeUeazw0HnKLuEGarrAxLA/W1z6o
         zRYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JRT26BDv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::3d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cc5cE2EgB+riF9PGGxvz3hKDrvu4x0/2XPD3M7MZykA=;
        b=pMrDFZkm2bPSCxa0F2SNTojsoBwyBrkBbkSUAEXwnzLJ5WhIj/8YKP+cDx7XfKC/ao
         Yf2g9rzXeXAeN3pX17k+ECz1+Wgc7YhQSWKpu31So/Zkj+ndxt61F4+jJyNevJucj0xz
         7T7UbCmjOYcQkwX6RX319VVrmCHgQMPpDax4SSn1X+J6N1Zz5DiWfL2LzuB5Qd+/Ides
         lcA7EIFspSwIoILhgkTfLqzA2yFLtyx8Xd7M9Uc/rq+cbet12O1sB6ptAaXZGPJN6ouC
         EbKXUqHQt6nFDjycvc4SOaCmf7UDxGxggt9G0bwb/aPumwGP48/Lktqxzv5XLDj4RxBu
         QvKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cc5cE2EgB+riF9PGGxvz3hKDrvu4x0/2XPD3M7MZykA=;
        b=FfkLmEPItozkI1hGV6Rgg/83j/AYRedgEhglgJp4pQKnZFs8I9X+beB2/J+qz2nXBQ
         gktDfWv2bYv4fEjbmsYI1OrqyVh8/FbMpdyIBE4eR7O/36ikdJAhiK2dA2WwSShzVE6N
         D3Guh/KruDj9gw++7DOWSB7zOp9uWD45KG2LxR3LHkghtqBOMFZRTx8Zl/6bm7weoad/
         O3IZv5NSwApHHPJ95WFXGVqcNQ+GgKAXVQ4Vdi4XOTK8x3MM8yL9MwwKoSM5DXOBp+kL
         8Uh4Ys3YX9fBUEQpeHV7qm27VuAl9F389B5zHEOICZy/qLcc8rr/ctKgc50WkSUbyfcD
         kXaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pke8hCX/dLuFS1kS3SzpT1DJDOdmEOCN23iUivUa9C5A7Ugs+eb
	z4XqNshvx5UV7Hsihd6ArBo=
X-Google-Smtp-Source: AA0mqf5V2hJqBhzy2NBNBtm8hcturIO81GPLGRNEam1vLU9pXQeBNwFqKRrXy/JOH0IZxB5FX8J6Rw==
X-Received: by 2002:a5d:5948:0:b0:241:e929:fc44 with SMTP id e8-20020a5d5948000000b00241e929fc44mr12686717wri.27.1669489936936;
        Sat, 26 Nov 2022 11:12:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20b:0:b0:228:ddd7:f40e with SMTP id j11-20020adfd20b000000b00228ddd7f40els5423968wrh.3.-pod-prod-gmail;
 Sat, 26 Nov 2022 11:12:16 -0800 (PST)
X-Received: by 2002:adf:e283:0:b0:236:58e5:290d with SMTP id v3-20020adfe283000000b0023658e5290dmr20997365wri.2.1669489936224;
        Sat, 26 Nov 2022 11:12:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669489936; cv=none;
        d=google.com; s=arc-20160816;
        b=AET06XX3Wqt6wlWoSi3F1zQsZ8qfu0z/izU2Gy8KPcO8w8YT9+zfj2W5F5i25UOwbO
         43DoXsG7AdvFfoBcS5NsSF9pcWkwM9eUilhC2HjS1TH7LqeSo/nH5nWj2suEj3ftPxzV
         kWLE8MiY3ppwpygrlPnEZT9u4ONBs51LsrqLDeFEAl8C8KLY258Oqia+vlXHbWMwD346
         nDXmo1m4XKGhQUe0WzZqmWnaeLsk2c1HfIk4UNn6eLKWWLOGn6d20lM1aPkj89I/+U+p
         Z835jKHWzd3V3+rwJOFfLAlvE6EUH4xp7WpVeCMYbHp1uwWT6Rxux/YKxRvTvtyu9ssV
         I74A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mld0Zf5BHHuTHmAamXf8kUapqnIfndf6LF73jgEUyOU=;
        b=XfVXpbKf+Bu+YE5T+gCoUzuAIyOzgnxqO465Myuuss18Cl2fAfsqeXraSYnrwMoZbd
         sTaOaACuUdRMbdZAf9QZADIEA/Vel38Eo5bikePzfaP1eb5rsXRrcm14BstVilYY5iUx
         GmaDVPpG0+ROaZiTQPiCfKr+oCQKouGfemg8MtHUO373USPMY5ws9+EebvcKTU/IZPk4
         q7y2FC6drElPCL2kXlm7he0dgEHax4cZ7k7P1h1RkrVv72hweG0TYLRcBkSsOFWrtAGe
         +UOXW2UTvAjgMJI4wgQbYLgcxTKz7mozWs2WWFdl9DvxH41eoyq4Ov4Vwp/ejXZkRVZW
         8I0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JRT26BDv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::3d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-61.mta0.migadu.com (out-61.mta0.migadu.com. [2001:41d0:1004:224b::3d])
        by gmr-mx.google.com with ESMTPS id h4-20020a05600016c400b002416691399csi333884wrf.4.2022.11.26.11.12.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Nov 2022 11:12:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::3d as permitted sender) client-ip=2001:41d0:1004:224b::3d;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Jann Horn <jannh@google.com>,
	Mark Brand <markbrand@google.com>,
	netdev@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/2] net, kasan: sample tagging of skb allocations with HW_TAGS
Date: Sat, 26 Nov 2022 20:12:13 +0100
Message-Id: <7bf26d03fab8d99cdeea165990e9f2cf054b77d6.1669489329.git.andreyknvl@google.com>
In-Reply-To: <4c341c5609ed09ad6d52f937eeec28d142ff1f46.1669489329.git.andreyknvl@google.com>
References: <4c341c5609ed09ad6d52f937eeec28d142ff1f46.1669489329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JRT26BDv;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::3d as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As skb page_alloc allocations tend to be big, tagging and checking all
such allocations with Hardware Tag-Based KASAN introduces a significant
slowdown in testing scenarios that extensively use the network. This is
undesirable, as Hardware Tag-Based KASAN is intended to be used in
production and thus its performance impact is crucial.

Use __GFP_KASAN_SAMPLE flag for skb page_alloc allocations to make KASAN
use sampling and tag only some of these allocations.

When running a local loopback test on a testing MTE-enabled device in sync
mode, enabling Hardware Tag-Based KASAN intoduces a 50% slowdown. Applying
this patch and setting kasan.page_alloc.sampling to a value higher than 1
allows to lower the slowdown. The performance improvement saturates around
the sampling interval value of 10, which lowers the slowdown to 20%. The
slowdown in real scenarios will likely be better.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 net/core/skbuff.c | 4 ++--
 net/core/sock.c   | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 88fa40571d0c..fdea87deee13 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -6135,8 +6135,8 @@ struct sk_buff *alloc_skb_with_frags(unsigned long header_len,
 		while (order) {
 			if (npages >= 1 << order) {
 				page = alloc_pages((gfp_mask & ~__GFP_DIRECT_RECLAIM) |
-						   __GFP_COMP |
-						   __GFP_NOWARN,
+						   __GFP_COMP | __GFP_NOWARN |
+						   __GFP_KASAN_SAMPLE,
 						   order);
 				if (page)
 					goto fill_page;
diff --git a/net/core/sock.c b/net/core/sock.c
index a3ba0358c77c..f7d20070ad88 100644
--- a/net/core/sock.c
+++ b/net/core/sock.c
@@ -2842,7 +2842,7 @@ bool skb_page_frag_refill(unsigned int sz, struct page_frag *pfrag, gfp_t gfp)
 		/* Avoid direct reclaim but allow kswapd to wake */
 		pfrag->page = alloc_pages((gfp & ~__GFP_DIRECT_RECLAIM) |
 					  __GFP_COMP | __GFP_NOWARN |
-					  __GFP_NORETRY,
+					  __GFP_NORETRY | __GFP_KASAN_SAMPLE,
 					  SKB_FRAG_PAGE_ORDER);
 		if (likely(pfrag->page)) {
 			pfrag->size = PAGE_SIZE << SKB_FRAG_PAGE_ORDER;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7bf26d03fab8d99cdeea165990e9f2cf054b77d6.1669489329.git.andreyknvl%40google.com.
