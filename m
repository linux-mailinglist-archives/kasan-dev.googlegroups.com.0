Return-Path: <kasan-dev+bncBDA65OGK5ABRBJNQWWUQMGQE463OGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ABE27CAD9A
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 17:35:03 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2c512a53e82sf18505021fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 08:35:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697470502; cv=pass;
        d=google.com; s=arc-20160816;
        b=AtZ/d6BUnV97bCocuU8oyq/EcgaOpYiV4F8FBzymTAicXkkfQY1I8XKuFyPkd39EpT
         wyCrxagmTdrSo3ysQolmfDxd/w8HPBe5GejTNgmFrWUkfaaQk+fkq9ETXDwyPfvy6Cbu
         dZNyQweRRZ6rTkSOzrUxOgfyodsPvqL3/PH5XVqTYsiSKHdWKuhDbxuRwvLtShQ3z48U
         h1/HnedeiFbKod1S7bPP3Wg4eguPggeH17Eec018jM2hzK7KK0lmirYKx6TKUjaF/fIb
         Y7QOBUpFuBIQcTjDHB9h+bLKUJ81vJiXKZQeSyuhXJCPVvtfepv/SEEaIYi0yKx0FKCG
         84Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=AOcHqUMXoa0Nm9xKDfVouRB2Wbuv9MQSJcMhHZHZRNI=;
        fh=8wIzoGKF/8WwnpUbhDb2usV0+hxy+4E6rjXfhoczKno=;
        b=xEOAa7+RoQm1eaJ41Rj12fNJSO+Lt+9BVxEG0QI3dIuKKILYcTOY1WOoRH4MXOB2g1
         mi51gshp2qNhELBg/Aek12zUld6G3SAZyqlXwG657abnCnrlVcPDAq0sXICzjv/lVPBP
         ddkxNvtHfuSYpTQlR53Bmqdy8eVKFrAZ/BRftZ0MvAZaCEZl1tDEPVj2FxLb2zCxg9km
         XpTn36+y6QNSkCEmhhmIG12UYLXVaUGX8+AAmtDifB0uu0Gu7twJuxO1Ah696+2t9KWU
         r9Nrq24HQRQ8oiZg6IAqwloP1ZxsrkeHOXGOWfeuSPiQRp5pa3rgI6xYMnOFfV0qeliQ
         0xtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IMO9qqDd;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697470502; x=1698075302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AOcHqUMXoa0Nm9xKDfVouRB2Wbuv9MQSJcMhHZHZRNI=;
        b=VorsuS0bjuCvI8veSdv1W0HpnajatCsGNl79QMaU49zH8jaL3vZpKjvj6jN+cAWCoq
         deAkhCUPlWBqMOql2A+NbV2hsT21Pf6TrYprUMh5tSod4mZRoWhye2bjtTlae+ODUMTv
         zpsRaE+aLAXUd9ybhvX4HrrYLwbFV6OLISJhKc3VKg9n9HE69tXK6V1aHyXfgwoXXl+o
         wLns1jfbHwbxa+vEHj25uuz79Ws9TNgPlGER56pAkqNhEcjG6isKmO/p+rQuC0GrRFip
         4IthJOFYZP31w7SOD89GivxR/hm0wRKyMV5NMdit9dQRPbWp4sM2xgM3sYtfjYxWUP2I
         lXhg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1697470502; x=1698075302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AOcHqUMXoa0Nm9xKDfVouRB2Wbuv9MQSJcMhHZHZRNI=;
        b=UdmM7qyYEH2dpuaoGywTy0KpK0lqpsw9Em6HxvePseVyvjaOp3wHPUXaBoLTBY0oV6
         5IdxYB2BRSj+bRzH9abPa9hDfbIbIyIAsAxaI9kaVTg82ZKKunhDgCmlJuRBSBWhe77W
         Huvj83pVQ3g5xHdT3e36qgttp9MVjuAfb+rIk/Xczji1yfP/rMIbIPD2XNEid+4/2MOM
         yeDQcNGe5CK063ZupbIyGd6mCVnEA9tAFq0dCHQ1pJuP2Tqy2j8ttjznfKf8lU0iSMxO
         18hsQ0qEpU5gSDTlvJLMBwb6heJwwk96nAoUj4UtnUt52EpXIgEAIUQmwb+Ka2fJd08T
         SbpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697470502; x=1698075302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AOcHqUMXoa0Nm9xKDfVouRB2Wbuv9MQSJcMhHZHZRNI=;
        b=YzmayhyW5nqdAr0QRsOQrbCFyCNYlTFkDESvUPx+PW+nuSnGrmigU1hbV3YpNYYozG
         RctIFOrEuiHUXkgmX1gfQsoIPp/n5x5X+0yAuePfBeIsbv49R08pAEgbhuN5EOhhJ/Ed
         dNJUIKfO+kKPZohMBAvhCgGlbD3/BUVMYQyg7eoPzVZw8mjtCR4444sLYWpYrRhQGvkG
         0F0RMoQbZnSw8btO3h3pOdAnk+TU4VRiW0W+2b+HlWcsazB5LKK5r2epgPnzLJvegA2G
         fS/+swQmjjCgGj+VD9vdMgMNPNlbSYDDblcXuTpXn2b/F/DqTkDV7R7tXDahc9c/E66a
         8kKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YymWesjwr9GoionQl/r6ronIbaHgBpZuarJ0chmX6MvZVbSEOEm
	ZsS3UDB+0FmcHp2F9a9wHTk=
X-Google-Smtp-Source: AGHT+IHcfltsQZ+ElM4mXymalfD76My8yc4/tI0ga6evyqHHqsTQ89C5Jgpb77VLEHlvb+kRNWsbSw==
X-Received: by 2002:a2e:bea7:0:b0:2c4:feef:852 with SMTP id a39-20020a2ebea7000000b002c4feef0852mr8734001ljr.32.1697470501815;
        Mon, 16 Oct 2023 08:35:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:487:b0:2bc:e36a:9e4a with SMTP id
 s7-20020a05651c048700b002bce36a9e4als724359ljc.2.-pod-prod-03-eu; Mon, 16 Oct
 2023 08:34:59 -0700 (PDT)
X-Received: by 2002:a05:6512:31d0:b0:4ff:a04c:8a5b with SMTP id j16-20020a05651231d000b004ffa04c8a5bmr35077832lfe.47.1697470499679;
        Mon, 16 Oct 2023 08:34:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697470499; cv=none;
        d=google.com; s=arc-20160816;
        b=tje8plg5F/rd27Vl+OyQ/Ng7kFsDW87O6qnu9LXQmT/6jJ1Y0b+6r6AktddtqQPDkE
         tBnNd2He5HWQ6LQaMD/vGARqNg+wPYAgGkXBBRWKSCuCwXAQ9jX758n7SoDrutSkJdWc
         hIqiZq1EPxG+0irqHC6nx3Fo5sbWv4DNOFTWZsbCDONFIt/JQJiy+Z3ZQaOLVCC/Knj7
         A1Uvr6m6CFzysIi6P26SqfBlzQDHqAa3qr3fgvgxNXSKQavoJDdisuIphSgn4FJR8uWb
         O0ZY5ZomKyxV9793JVa2guojWlvXRn+301qVwGg+X+xYCfOjvA4qndzNQMo5g3JKd2kr
         NAKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wB7/iWqEpIuTjd3/Y3wkGwJ3ek+RrsFECJqLSfrqbjo=;
        fh=8wIzoGKF/8WwnpUbhDb2usV0+hxy+4E6rjXfhoczKno=;
        b=HNDfIXACI6U4fnrd62uIYc14eVaXWPjBQ4J1XHGGpJtRPtDjcbNaC3xpX3yDVyI6wt
         RsdivOC+F8ppmaYqFrcDE4tHXrWerNoR27PEGS1uAHv4AY7Alwqs6U6d/489kh6uhAGX
         zh1nvpy8BygPOfHo6FkRcuD6hGd4vprLC8EcRdkFhKjrhCS0HLe13iNUoIcp87gzK49A
         YoDizuQzKAoFJqZLtDqxCpm04kXCL1PKncGy793C3nK+PuiWIXn2szirHIK1RKZSI2QF
         BRTlyCXE9UC1/WiPS7P/mx5m7gAnr7S4rtK7+mkBsFR7Pq4w6+0OHOCTIEfUIe76sw5Q
         FvdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IMO9qqDd;
       spf=pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id j28-20020ac2551c000000b005008765a16fsi3370lfk.13.2023.10.16.08.34.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Oct 2023 08:34:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-40776b1ff73so24328695e9.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Oct 2023 08:34:59 -0700 (PDT)
X-Received: by 2002:a5d:420a:0:b0:31f:bdbc:d762 with SMTP id n10-20020a5d420a000000b0031fbdbcd762mr30244049wrq.44.1697470498637;
        Mon, 16 Oct 2023 08:34:58 -0700 (PDT)
Received: from PC-PEDRO-ARCH.lan ([2001:8a0:7280:5801:9441:3dce:686c:bfc7])
        by smtp.gmail.com with ESMTPSA id bx7-20020a5d5b07000000b003232f167df5sm1955283wrb.108.2023.10.16.08.34.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Oct 2023 08:34:52 -0700 (PDT)
From: Pedro Falcato <pedro.falcato@gmail.com>
To: kasan-dev@googlegroups.com,
	Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Pedro Falcato <pedro.falcato@gmail.com>
Subject: [PATCH v2] mm: kmsan: Panic on failure to allocate early boot metadata
Date: Mon, 16 Oct 2023 16:34:46 +0100
Message-ID: <20231016153446.132763-1-pedro.falcato@gmail.com>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
X-Original-Sender: pedro.falcato@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IMO9qqDd;       spf=pass
 (google.com: domain of pedro.falcato@gmail.com designates 2a00:1450:4864:20::330
 as permitted sender) smtp.mailfrom=pedro.falcato@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Given large enough allocations and a machine with low enough memory (i.e
a default QEMU VM), it's entirely possible that
kmsan_init_alloc_meta_for_range's shadow+origin allocation fails.

Instead of eating a NULL deref kernel oops, check explicitly for
memblock_alloc() failure and panic with a nice error message.

Signed-off-by: Pedro Falcato <pedro.falcato@gmail.com>
---
v2:
Address checkpatch warnings, namely:
	- Unsplit a user-visible string
	- Split an overly long line in the commit message
 mm/kmsan/shadow.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 87318f9170f..b9d05aff313 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -285,12 +285,17 @@ void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
 	size = PAGE_ALIGN((u64)end - (u64)start);
 	shadow = memblock_alloc(size, PAGE_SIZE);
 	origin = memblock_alloc(size, PAGE_SIZE);
+
+	if (!shadow || !origin)
+		panic("%s: Failed to allocate metadata memory for early boot range of size %llu",
+		      __func__, size);
+
 	for (u64 addr = 0; addr < size; addr += PAGE_SIZE) {
 		page = virt_to_page_or_null((char *)start + addr);
-		shadow_p = virt_to_page_or_null((char *)shadow + addr);
+		shadow_p = virt_to_page((char *)shadow + addr);
 		set_no_shadow_origin_page(shadow_p);
 		shadow_page_for(page) = shadow_p;
-		origin_p = virt_to_page_or_null((char *)origin + addr);
+		origin_p = virt_to_page((char *)origin + addr);
 		set_no_shadow_origin_page(origin_p);
 		origin_page_for(page) = origin_p;
 	}
-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231016153446.132763-1-pedro.falcato%40gmail.com.
