Return-Path: <kasan-dev+bncBAABBTEIXKGQMGQEINCP42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C76F46AAAD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:45 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id j9-20020a05651231c900b004037efe9fddsf4374637lfe.18
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827084; cv=pass;
        d=google.com; s=arc-20160816;
        b=yWjfRqvzVK9DZmO/VHGLRBIQucKT1tQcd6r95MFOZN1O1bOgWfotxv4ns3e7ocmXgN
         nUXnlSwsWIp1Tmnp5cXQEkQa4kxDWRJCXCOWcTPxiVvE1wgMF5n1KL/oxKMgLBaTDC86
         3jV6RowjuaakBjjWgvEN5oirnbJ6z2ouiTPbjMrzCRTz4S1HAoDq0C1qfzxD1Y2NUD06
         jAP856MhmGIxdTuGkbGImSAtQPUedEhoYzQF1KQbd1YBdUf/hEUEL5amTOTKmbMhXA/z
         xolInQk9ykrKfWStGyyPiyMHZ1k/xdb01+JVzx1FE8DBwv12LiUZUIa2KfhBiCnQR1J1
         k57w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ESmHwqyrnVMbdPQzrUGwTzGia+CyQ9w7WwT57+nxMZo=;
        b=w68Z0x02UeMC86zXewLKgBux99yi5RESncQFcMNJcOSagY1qIDn/B1qdt9CHXh2SJn
         Et4F01iAonPN9LAmV3jLAjxYEQ06TxKJW8IfvG3+b6Gl1BBbpNWFTxvqIeIl/BD13+YW
         GJQlps6Bw+zsQKPHQAhblQeXal7212To+ie0I2ET0IpShHaNr0w+LRgO71lHTXWvoD6o
         L76GYnTynsn1/PSI7+X3zgSSrC66tnN6Z29VfB8EJgv5bSqNTrn+as9TfwWXv2zKkoLr
         sy4msGzUpRWNfke0RDuf+y52aa/32RiG43KuoFaUVJlxTub/cDvU5ViLwsz61M+Ml4uf
         WHGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ki8a4uqZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ESmHwqyrnVMbdPQzrUGwTzGia+CyQ9w7WwT57+nxMZo=;
        b=dvHE/Wx4SyFflGLsuAeJC4SS6nnv46R1qziCdFJbx3zxPJSHWH8/DS5i3lBKuxoTR2
         aKe6cV+2sVM/zFT3PbkfRoKYvwLdyfSFrCcRkAgARu5DWgEEIEHyHxrc+Zi7krkWjD8s
         cGzCa35BX4vz9mOf5iwGpw2tqYmJyQztByW+wMlPpgKmFQN/k8m/ZRu+R6Yq3g0a9mLs
         FJ1iwUD1+abcUXPYmj7zZlRZei6k0F+B+UxLveRm2IT8gshCjRBJHwJbFwgrofP9m97S
         zqgTHr7LWyn20v+ZNYcLtGsVxwif+cTzjVGIqFm4jAX7BGiFHU4mdaSc5cywwEKM7tn6
         ls1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ESmHwqyrnVMbdPQzrUGwTzGia+CyQ9w7WwT57+nxMZo=;
        b=ytD58uST3HLDPROP0H97K3j1bl4GyGjRwPWSVxZAmc3uyJEdqZMEm9YEJaHVIFFcCs
         Lo9ceB5Jfq/T3/yNNd8b6yMvmYJJGTMQ+FIg4QNgLNtfJn2Sm2w0vJFaLzCnbzXLRF7f
         TSrvCt43otnmrsK0ZTaXy+ajTqnTNPvdwB4XOULkhDEq8i8fjQRlqqxkD17Iy27opeFb
         QSvKHxgubwN+sNpa++Nxznq/LlfmqBguW5MYLy7WXngQdOvIjxPJYaQMhytef3CKwasm
         iG+pmTfi7b26tPb0JYERlBPoVAUQgwVhDaZeQ2ZOPX58Z+m4wOTL9pYDXVg/Jet60cp+
         zAMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532h1teTqVcYt+sKigXv+eXunEHTexnlEAh2Vm7ItninXqROsbB+
	5RIuSu9uh4EWU75k14H/JP8=
X-Google-Smtp-Source: ABdhPJwrv21E7DxsCbFVywHNzmg9cX+HWKoUHBfkzRVXibnpKKrtGiNvLiA/f86NHbXhpZq3BkYP0w==
X-Received: by 2002:a05:6512:22d3:: with SMTP id g19mr36309478lfu.404.1638827084736;
        Mon, 06 Dec 2021 13:44:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1924822lfv.1.gmail; Mon,
 06 Dec 2021 13:44:44 -0800 (PST)
X-Received: by 2002:a05:6512:1506:: with SMTP id bq6mr39089207lfb.118.1638827084063;
        Mon, 06 Dec 2021 13:44:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827084; cv=none;
        d=google.com; s=arc-20160816;
        b=LK+kU0ArTG+QIZM1CwopV9kxETiJbLfzJFEJ1L69L7IdpTFA1s0XUSdIJAivioONuC
         l2PdPx1in9sbQI+sLdjBmxXNJatiMGcYihxebTT0dNQvOK1K5atDVktkQYecWuLJkc3c
         zXCqhXC2GRFNfrBamOoN8Gd9oCXz9OfoCJ4hRANCdLXjmJH1yhCXLRDvha0rG1x/HenB
         rlb0qCI+J1Ssqu748ehBU0upZrZhTtO6CzHy2XoQiW7EQLUEk6TMPvYgf4DiUZH7ivEE
         dmVjt14mu2w4COaYHWeiTHBv1gIYWyxlPMTnA1wDwOKVZrYl6iCBRHpymED/V+knJsnK
         z5bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=i2FffCVJttNjYU5fhxzifZEfN2PNcPmkAgEoBkLN39I=;
        b=yd2O26tY6uYrIss7ULQvFd4A5+8qKIRPwiz3yomDwKnt1zWKwztQewDa7Wshfy/Jht
         pCZAHaK+roed2mgI0fKufh1mYzeCPFyuovRdv45Up2Szfm33tOFr66LbC4rN5WY/oK+Z
         8Y5VsiHwyOUSNcYc431nzrYqzalsVDOm8SQnRwyhTgZBuZFJ9eGXaiv2PaMO0ax8+tLs
         FMQYpHurnJ8P0WZ+qR751BeuXoF9DKuaQQkzsqWxIF0NTRu93Xnyxe9g/mQQlLOwHT91
         lqRJIZRbjD13x4rKL2B3Ia7z9nDpNEtKnV6ZZ7bYCl0LldXcVpxeWHrhylk0MdhLxH00
         wmiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ki8a4uqZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id u19si820807ljl.5.2021.12.06.13.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 09/34] kasan, page_alloc: refactor init checks in post_alloc_hook
Date: Mon,  6 Dec 2021 22:43:46 +0100
Message-Id: <7445f15afeaeffd92956d7093ba6aab62781f637.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ki8a4uqZ;       spf=pass
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
index f70bfa63a374..507004a54f2f 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2405,19 +2405,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7445f15afeaeffd92956d7093ba6aab62781f637.1638825394.git.andreyknvl%40google.com.
