Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBDM74OIAMGQEMEUXTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BAD84C44D5
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:46:05 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id t8-20020adfa2c8000000b001e8f6889404sf884448wra.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:46:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645793165; cv=pass;
        d=google.com; s=arc-20160816;
        b=ApzNPA8ZwyM5cw++kcwp0QA12IGiOnIi3Vrp9V+rnM+TVKHiMxHyl73HzCwkbWV+m9
         tEpGpUqJivI6DM5Xt4TMT3Fq3RUWlN7o6TnRG5YM8E7Lv6Dvk6spDBq8+0ZH53hUINgJ
         tyrMu731Ac+MAP2OWe72KfDOLm6X2mVSti76Yg4iztkhi8D4IeGLZlnnP/sazYgDsc+1
         dINPrqFr7jqxdwb6qPcgkHnBwIbqDtH4rsiMAQq6ta2RMDSbSvRhcnXLJ9VaQ0YKBM5F
         cU8F4FNIzV45FdMjHOUd/RdeSq7KNLkGfUdOp0Y9b4paQRfAhNPcZn7NMptOFkQcCcvQ
         2v5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zwnXldDG9MG7FAKsM5bqzxazd6F8R3e9hILMpjOMC0w=;
        b=tIYoRiwj5dDBZhRO/8i0SIRxSHBJi0hWaZgKAdetOBCtAT68UK0jlH46nWb0ooG/h6
         OTZprZ9L+FR0Yvv0GFM4RDNDSocv2vxEFimz1OJk3fkixsgn3vTb9PfQPwHedYGUFxBB
         9y4IXu5drSvekYD4th2MwDRYBYQ51MOF1K4zFXthkNjL20X8ja+s2ZVZe9dBo35MnyJ2
         qwfWthXn+dbHgpOPyeqFZuS4A2q7qdXTFJSy1WfuVK9eYzWHt/bqV33lqDWWvMRTMZoz
         r+cTTnpJpmz4pnAZrnu9Xw8BlmegeN7k2LpklzJ7+wsws3tWZfqzIpQmSZcQtGHL2ghJ
         fpZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NbuplYwp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zwnXldDG9MG7FAKsM5bqzxazd6F8R3e9hILMpjOMC0w=;
        b=sh1sLq61wd0jns5FU4bjGHy4dYIMVddOmsMyg654pUFxMhNFkBvgMY2V7XAoAQ+lT+
         NfqYJCMthFVgc/fY6C4+EJ82iHYQgYNmG/Im5KmR8oqbIhwDv6vC8Oji905tCyKbzB4O
         ZOTPcUC2iMSvTnYyucvWcIgljj7gvcyWIc5gGAsm0PXyq12sQZFP8K4a1+4AHrZCw0Rk
         1ujoelq4HUnCwpQdvcc92bRIckBu2xac2YnDyCGD+fmsB8+9O6BENkOIuMctRmV3jSsF
         R79QhXufUfMKka5GsGJhKmZUQd2nUNMUGxivDeVH0wUYGGOQOjI1izaxfObLuxtmNocr
         iKew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zwnXldDG9MG7FAKsM5bqzxazd6F8R3e9hILMpjOMC0w=;
        b=DvDrzag6Qlfa1//xrGuB5SbWSskTjMXDtUwLyRzbH/E+AnbRU1iM8EbpMSk9t20z9x
         990SCgSM0vY/gB6Zng1ch87FvbUiWM7/wtkSlOe3l3icGtUl1n3VmnzrWhoOQQKDugnU
         q2BB/rNsecfgbsSXGxX2OmNMqfNi9/pBnrxI8l01YmbDu8h2FeN7Kx5wpzw1FxqPQpB0
         cNWFiVTtKMBIEHawK6nXlX8L1beUAyvtyyUsB3lzR9v7xRiUq5BXa/IxPUdOLeojOjyl
         gmE7WTZcj+oJmk0dh7wRnR2k2Jn2VxRAsAR67KUIfTaZNlTbKwKGbDld05RyuxJJ5GQe
         MVfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WlMIdF4ClMchSNQ4TPQGYuj7f3ccQCg9uCDvfxGmGJa8s5Qk7
	9+Hsb81oCcykRtQEqd4cwwg=
X-Google-Smtp-Source: ABdhPJyUuTObTfuYqLivhfwew8m6fiq1F5NLkGITbjTj8D6fP0fXA4gaE1dMEU54lwhvTXQoHfc87w==
X-Received: by 2002:a05:6000:3c8:b0:1ef:64e8:9235 with SMTP id b8-20020a05600003c800b001ef64e89235mr2187140wrg.498.1645793165428;
        Fri, 25 Feb 2022 04:46:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e8:0:b0:1ed:e0b0:6d3c with SMTP id g8-20020adfd1e8000000b001ede0b06d3cls21338wrd.2.gmail;
 Fri, 25 Feb 2022 04:46:04 -0800 (PST)
X-Received: by 2002:adf:edc1:0:b0:1e7:140d:db69 with SMTP id v1-20020adfedc1000000b001e7140ddb69mr5909729wro.429.1645793164569;
        Fri, 25 Feb 2022 04:46:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645793164; cv=none;
        d=google.com; s=arc-20160816;
        b=Lx9xJ+qZNXJkTVtGT+QJrIN8mq0ksIEIKX5uprSPPI8Tj4M3DZMqUrwnkdFiEh3NPn
         F2KEahTRaSPTYNYqbmaVGwj2BsXuc2VB8n1v0CrHgJDac3/BXcJiwr2rb3sB8bslDtHL
         0YmjR7fvZJ787TSTgn1dLCxzIuhuoKA/6yI8qf5Rq+kbPY7G+XMQKyPJ4AXNSendReVg
         S9EiDDwrxthIEAsxaNXOEdDz5h8O76/ALHT9/3SbDWyf7jxld2Ifd9oK7IuOB2CAFgWO
         QaiLrm4ziOUP4555NTno3sfhtxw3ZvUBD2P6sx9WVtPwjFkM3H/mMC5psZLTbBZoGP5P
         1AAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=IZZDTFAqzc8aGjWg1aZGEvUIk/RV0NTNXI1qwgw2jtM=;
        b=phrswGEPo69eIG9aEwtUXhK1C8aROFk+kbdhyqOatI83IgJxPofAigdsfsnpTUv10Q
         gPwLvLbn8ZN8ynDO5PoV1Fp5aLT/OuMvwBgIJ+7CZ7eL1Lg4v43/P3qhEUsarXcjkFd/
         G1qUHSIHQv3zus5hC2xaewJmqsgkDgMeBoXFYmKbLtEdupIvRXE2d0ee0arhFT6jq7gt
         28MQAycsApUpIHKDficbPOIdNU11WtDgfH7U0qU1pcrzIUqVytRziJApoUpfeiKPBv0+
         vkhZlkIugxTUkadGJQYQXINkHER6Xs2lCPo/JU5ROlpChH/zgqju5wNWri/MA/nga2S6
         V+cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NbuplYwp;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id i12-20020a5d558c000000b001ea830df1aasi51318wrv.7.2022.02.25.04.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:46:04 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com [209.85.221.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id B4B483FCA5
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:46:03 +0000 (UTC)
Received: by mail-wr1-f71.google.com with SMTP id g15-20020adfbc8f000000b001e9506e27ddso844671wrh.22
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:46:03 -0800 (PST)
X-Received: by 2002:a5d:59af:0:b0:1e4:a027:ce3b with SMTP id p15-20020a5d59af000000b001e4a027ce3bmr5811401wrr.318.1645793163265;
        Fri, 25 Feb 2022 04:46:03 -0800 (PST)
X-Received: by 2002:a5d:59af:0:b0:1e4:a027:ce3b with SMTP id p15-20020a5d59af000000b001e4a027ce3bmr5811384wrr.318.1645793163068;
        Fri, 25 Feb 2022 04:46:03 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id e33-20020a05600c4ba100b003810c690ba2sm4741109wmp.3.2022.02.25.04.46.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:46:02 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v3 6/6] riscv: Fix kasan pud population
Date: Fri, 25 Feb 2022 13:39:53 +0100
Message-Id: <20220225123953.3251327-7-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=NbuplYwp;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

In sv48, the kasan inner regions are not aligned on PGDIR_SIZE and then
when we populate the kasan linear mapping region, we clear the kasan
vmalloc region which is in the same PGD.

Fix this by copying the content of the kasan early pud after allocating a
new PGD for the first time.

Fixes: e8a62cc26ddf ("riscv: Implement sv48 support")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 85e849318389..cd1a145257b7 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -113,8 +113,11 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 		base_pud = pt_ops.get_pud_virt(pfn_to_phys(_pgd_pfn(*pgd)));
 	} else {
 		base_pud = (pud_t *)pgd_page_vaddr(*pgd);
-		if (base_pud == lm_alias(kasan_early_shadow_pud))
+		if (base_pud == lm_alias(kasan_early_shadow_pud)) {
 			base_pud = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
+			memcpy(base_pud, (void *)kasan_early_shadow_pud,
+			       sizeof(pud_t) * PTRS_PER_PUD);
+		}
 	}
 
 	pudp = base_pud + pud_index(vaddr);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-7-alexandre.ghiti%40canonical.com.
