Return-Path: <kasan-dev+bncBAABBTPR2SEAMGQEUDPE4GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 905F93EA715
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 17:05:49 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id y39-20020a50bb2a0000b02903bc05daccbasf3189304ede.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 08:05:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780749; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZuOscsXEf/mF4sKgadrDP1XePOjiIZBmso6rEnyRtJ2I56c0qk23SYtAqoz0/1O//1
         ID+wyoSZwepn/mEcpuqjiDcVa6SVQ79OVF6hIVt5n54bOdbcpgDmUDV7VkUU8vgJKBCy
         XvKbl3zSh9ucadkJd9vNJ7k6dmHHqAtz1cS0+Vrbemfc9oJnFfOjuf92bve6Bv4mEnEl
         AYzkBa1PJRHGehu/abGcr+WC7MUfK4BFzyNtdbO4ZQ327gMhrtCzFwZXIz6zlFp7mb0B
         a2NrmQj7z9OH6ei8Azi48j6l1lbffn+K0ieRxuSlqf2nAaBjWaNk+H/a1RZZmbrXUTKz
         r7iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kjZUgTyF4np2dkuBLixAl5VX0XzfMsUsFllV5g5/+sM=;
        b=eHianitBmRlbzMrQsXFa+Vn/5Lnj4DQTG657Kmnov+CS2bUNz2RK4m4MQD8RtVtfvt
         Uof1ah3ArtHFegD/l8or/9O/Gx71pcjDffxQYGVaxCmuIiIuSlbUAHICpzt4TcCJepvr
         8qc1sVZJ6W3lDY1tvFdcSaBLAc2/WxLc9VXRkXhiWpJF0MgMc0mNq6GsaAXZVza3kCPs
         rTUGADAUEppWMACp1sMiBpNWl5tgNNnysqigypTdeu1vCib3TgKkzm+wBv5tflAIhdFk
         8Qy7koH0DbXjdvCOHfpp8TdblAqg29Qepuk0KyF3nOgBSGnxlPwz5BtuX+a4PzhmJHAa
         Pa+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="QSI/+PvP";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjZUgTyF4np2dkuBLixAl5VX0XzfMsUsFllV5g5/+sM=;
        b=qy0gLltGWunDtJgFy/ydCXZZUmFqYQE2Bwqft2YhETOpGh+TV4O4RlG1qGJ2La1QsT
         AgnX2OiroD6Y0XwnY2njUaf+I0RJJ6/3873adT/dQxiNYbfNOAHUM71gYWnW/R3MOd9y
         gPd14aZ1GCthrel64O0Qb9BG53TV1Zud6F2GtrmYxztqerofm14lugx33H3zUnnXq3p7
         VrQ63SLyKH4Mk5SMYOv2vgFZXzzbNrmoAGXQXBYiXb5fVEhTRiMixdpvaFpK8yboZ/eT
         7P/j1igmw6LiULiW9dBK4FnaYRzHR7RaFsv9rwhWy3UGG0z7x5Dw4E13mumDXcsiYI+W
         7jOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjZUgTyF4np2dkuBLixAl5VX0XzfMsUsFllV5g5/+sM=;
        b=NU30eiYEp1f2aJB+8lzlZxAKO5aBQXWaDTZ2s2tOI9yQUqnw+IAtUYJFgTRvTPqpxO
         SJbuKWGl7vKCDpB0bZD0CnxCFmGkmb4HwprfKy5NBKfItbw8VWtGWSFPaNFc3rnAgyYl
         2qGSYbbousDrHvz4mgq5OyCRbqyKg5OfHwGdzYWlSAyU4gd9cdfq4NuTKw/f0+N+LKzw
         d/7neHpqSr3TKCqjMZkKRb9MDsT4omEJj1/JPDcLzR+RUqlBUEhT5v0PaXkNOKeMICHq
         1q+RbCah18JWET7NZQu+RRL8re+CB4oDcRCKtY4Hc26BVKpsDyANn5MSwhow2GAUAEj0
         i/Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Moi7YrJJ9HbS8dn0mtXfOrQdDtrat9R3OFr+D2Mf27pX7s6wR
	hy1XeRxC0xmljbrerT16Os0=
X-Google-Smtp-Source: ABdhPJxj/M+gZYYY6CbP/BgfzpUmRUI0tUe7SHG5xUYxR9XerqwjE1OneUrMC3vlXDSXKRdxC9cIqw==
X-Received: by 2002:a17:906:3bd7:: with SMTP id v23mr4231181ejf.446.1628780749318;
        Thu, 12 Aug 2021 08:05:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:ca0a:: with SMTP id y10ls7091728eds.0.gmail; Thu, 12 Aug
 2021 08:05:48 -0700 (PDT)
X-Received: by 2002:aa7:c519:: with SMTP id o25mr5984269edq.305.1628780748552;
        Thu, 12 Aug 2021 08:05:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780748; cv=none;
        d=google.com; s=arc-20160816;
        b=RkZmZU+mxAM1eouG1c5/dUiTwp0BUJkYMHOv6aWEXpZfgML++wQv4SMZNACLF22H0y
         eMsxWLKbsvGpgSAgZOnaVol24ZydHJKVc5Ms0WBDVgHard+2pgmeRW/rn/g2jDa6V8He
         5LPzBUJZw+l3NGAGhBiQp9X7dMsH07dEJp+rRZfh2zvLvLoq+OAoHc4MRMA8qPTU8SXs
         Pd6EmNSdhYxpW1PJBqd+0FzpbvgzbpHNjWZhnWnaUp7efwpiPYuKWf5y0qjQ3LzPcwBp
         /BOd+/bp3+VP8dGkb7YZDi/Blqfx60PF1LWZzVPnaEnPSNrCC239E+xZb0I8dfWasTZL
         978Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ikZnRm2MVtJHm0Ia+fXtL9BHvKn2N23olNLH7huqioo=;
        b=h4S4G1MBGMkubb9BgXyDfzl6koTVq2+rwK9sAL5HfxblhfusBJ58NM/bghyjx6fmT5
         een5M/J+DY7GIXSPE4i6FbQcxZn7Xsq0kxNVxhcjpMcTiyYo2w5InV/ZLkaxZ9Xd7QQ+
         niNonDUqqg/ax91gD3SIURfPKpSf5nqaLO/zpPH6aLzibkvXScQmg31b62UJcJvR0pJK
         t51STrFZf5Y/hZ1xo86QJDlkZrdlMugaTv73YQXA036VLntpHN6FJOlLfnmBHS57qwIx
         mt0qZNRqSeoOmSWWkT0Q5KcZXuKL+JyJUYN/+skcbiS8GCaYESZLNbNIAN0o8obiq4oB
         J/GQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="QSI/+PvP";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id z11si118108edb.0.2021.08.12.08.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 08:05:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 8/8] kasan: test: avoid corrupting memory in kasan_rcu_uaf
Date: Thu, 12 Aug 2021 17:05:46 +0200
Message-Id: <b6f2c3bf712d2457c783fa59498225b66a634f62.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="QSI/+PvP";       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
only safe with the GENERIC mode (as it uses quarantine). For other modes,
this test corrupts kernel memory, which might result in a crash.

Turn the write into a read.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan_module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index fa73b9df0be4..7ebf433edef3 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -71,7 +71,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
 						struct kasan_rcu_info, rcu);
 
 	kfree(fp);
-	fp->i = 1;
+	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
 static noinline void __init kasan_rcu_uaf(void)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6f2c3bf712d2457c783fa59498225b66a634f62.1628779805.git.andreyknvl%40gmail.com.
