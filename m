Return-Path: <kasan-dev+bncBAABBKP45P7QKGQEFJVDEVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D2A2F0760
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Jan 2021 14:16:27 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id h4sf15017058ilq.19
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Jan 2021 05:16:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610284586; cv=pass;
        d=google.com; s=arc-20160816;
        b=MTDTri5Y0Lalw2RaOjglw56N2RvdWAtu9kgoD05Dg/mmgfF2nf23cyd87VP46CSr1S
         2mnS67jy+qdbEm1NNr/jlxOm2egvqBIiHUkqppp49KRpSoMJzXl+KkkV5QJyE2M74+w9
         zBAxLTHItUBkcTp0Mt7na4g5+LdjsM/RfoFaOe0WkIAzxAVKwsr30XxfqROzNnlI3v8t
         l4sFYF3aqXzBga25q0gBcx8AJAhNNBGNSrpdWnAqCSb98vKLn1UtUFR3B00Ta6TSoRaF
         I9NTfAfNv17ddGCwVJOetbJXzm1tA0Da9WZc8a7SNEjuH0dRIuI/gHkXGPbtfa2cthUm
         KiDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=udpvLAYMXlktfzLjUQ5/nk4zkaSKwZ6VaVgrCXJ6FH0=;
        b=LMHjEeFv85LUFKt9IkONG77pkR19nUx7NIvEjrgifK23py6TcBUMSxXJgyXLL7tMuD
         b2qwOv9zPsGkI27tQgOS3S4PDB1yKAWWaaTsfs1Oc7TX0C63gdrHVZTyG1+ABk83ariP
         sNJ2/oQHG0TEehCNMKBgg5+lt9ntbGPd+mGZsUx7LR8cbafx4xcA2VS6rpG7RfSantoQ
         WZ4ilxpuCAVHxjZF5vZ3268DktEtyGnfqK+LsOYsnsKxBdNii14WcjqugrMTUBYdJFjY
         1ujRe68sgVK3cCHjwe12vXA4cCw1Y6d3QUQH+Jm+AR0EHRxkycAAwYDTZ0gWfpjx2bHo
         TqAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=mq1FUfXU;
       spf=pass (google.com: domain of liuhailongg6@163.com designates 220.181.12.18 as permitted sender) smtp.mailfrom=liuhailongg6@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=udpvLAYMXlktfzLjUQ5/nk4zkaSKwZ6VaVgrCXJ6FH0=;
        b=rVl9hD9h6jzV0/CfAndqLDrtze7152uCTOf+sLvN68b1FMOkRiV2vwXxj7UCWkuMMd
         ZUDgU9bg3LHAlrHaGfyZ82l57I9SUfzUAuBk32W8eM/qUTksCHJDTidvmavVKf7xNTVA
         tmYamwKW8MoRd0AdKY8SOYDIVIBoDRE7nY54IY3eMqLHFjB52f20upyjGaTJjeyT2Eo/
         d9OTNBr76S4BrO//Pp4b9Sb/N9Ff6/8fOXYZcMQ3cgHWWnNjYMLfpTPgRA1/Ot45kYQr
         dnZr0I5hSEimgZZjepYAAz70Lu7elhSUgRWvQYPIJgiyXuQQsOnDPPIIaCQOyHeMhxxG
         geFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=udpvLAYMXlktfzLjUQ5/nk4zkaSKwZ6VaVgrCXJ6FH0=;
        b=W5K5MUYzgWFpx0lbvKTEmF7ck77bmQORjIQYl8sZAUIxq6tOfchdxDoL5fSar7HZf0
         mZlRR0IryJKpzkVg/Scr8LjbYbJf574+7lwHwONU7lxmFpycLNsFwhITpift/t5BiVZx
         hgY92MrTPzyijbQigPwMeUYofjYKeupNgAF/Zd2Ifj5Km0cjMPINqcIqWRL/vglrkfSV
         WqyX37trVjWpgamJyvmbw+UR8ZS4buVGHrd140LFUTCZFTkBobS3QUOQGpsDyTVzJbON
         v3vKyIL9+C68d9hjk3/g5jJzRK15JsZs6I6uo2L5ZVJG7GyjIAXhsCjT1KvmZlOkenGt
         05Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PcxZDDLQ8IF1ByuxUG7uY2X+aNfWczhR4d8h+h0uPgua6ORfx
	IX8sNqtQjjIL3yW/anPVavs=
X-Google-Smtp-Source: ABdhPJwzaT68+ZaRIuePDKNGmimKES91k+UDuCPYYqwXRX7nrP7chYFDHb7/wBcasao8JcKuXN5iyA==
X-Received: by 2002:a02:7428:: with SMTP id o40mr10762653jac.130.1610284585948;
        Sun, 10 Jan 2021 05:16:25 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:12d0:: with SMTP id v16ls2017682jas.11.gmail; Sun,
 10 Jan 2021 05:16:25 -0800 (PST)
X-Received: by 2002:a02:ac03:: with SMTP id a3mr10778799jao.71.1610284585563;
        Sun, 10 Jan 2021 05:16:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610284585; cv=none;
        d=google.com; s=arc-20160816;
        b=ZlTtJphPd5wkviu8UVECEioDnL/cJcjuZkp5gfjRXhk04dq3N2hAy6GINfMWcA/vAV
         SI9tdgg0O7b5GPIXhnRWybPUtja3T6dALxXORIeQB1Er9o8NiB1VjRAybkIrV0Be+Mz4
         oM5Tz38YdO/v+6VSjicxlYpoIbDmTcwwk3zoJeZG7ipAn0H2WSxzheQTLcA19Zs8LR4m
         tD9FwMzBw43adz1TClGkEvDdTFN3jah1SxN22xZQnHHY8gKvkYrRfpTDh2/JFvOcj6Nn
         KaJF9XtBiy3gU+aUr0vfv/+oPmpbwDB3Oack5GBLXP8OWDgmv9tmgt/DGvnY2ofJaHeV
         7PJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=PDPR1EvJ8p2jFoEYZJ/H6tQbh9r5SwukeSGEZ5VrZLI=;
        b=PNIdJTkjyAf52m/wta9MU+lMoL7icnI1iN1aWSNm/RUnCnLuRVRsvY6sN1swFVAtdK
         +uY+cXEm9l03QiPCQq4Xs8+c3Neoa6ZKMaY3qYIFZJDfVAue+Cg3A/ffXsBgkpCfVkwV
         Oj1Ctafjddd1NMcdAPS7pSN6mn1HPI3AjCah1DDfnGpgJOSEISoiQY63z+ow+8JMaG/L
         QIImMGjKGzq2rjG4mQ2P6JgcdocWVm+BlYHGneNcNHzP8j1E3OdcUKdYhGjXaGZiRLp1
         cFfdos6HdUGFKFkLSVGYQveiiakSEqx029lY/a2rf4HXjk5stjntda3OJ0bBKgaasmcp
         9/Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=mq1FUfXU;
       spf=pass (google.com: domain of liuhailongg6@163.com designates 220.181.12.18 as permitted sender) smtp.mailfrom=liuhailongg6@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m12-18.163.com (m12-18.163.com. [220.181.12.18])
        by gmr-mx.google.com with SMTP id c14si3438ilk.5.2021.01.10.05.16.24
        for <kasan-dev@googlegroups.com>;
        Sun, 10 Jan 2021 05:16:25 -0800 (PST)
Received-SPF: pass (google.com: domain of liuhailongg6@163.com designates 220.181.12.18 as permitted sender) client-ip=220.181.12.18;
Received: from localhost.localdomain (unknown [36.170.32.128])
	by smtp14 (Coremail) with SMTP id EsCowACXmPbp_fpfpmHJOQ--.54130S2;
	Sun, 10 Jan 2021 21:15:22 +0800 (CST)
From: Hailong Liu <liuhailongg6@163.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	linus.walleij@linaro.org
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Russell King <linux@armlinux.org.uk>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	liuhailongg6@163.com,
	Hailong Liu <liu.hailong6@zte.com.cn>
Subject: [PATCH] arm/kasan: kasan_alloc a more precise size for pte
Date: Sun, 10 Jan 2021 21:15:00 +0800
Message-Id: <20210110131500.12378-1-liuhailongg6@163.com>
X-Mailer: git-send-email 2.17.1
X-CM-TRANSID: EsCowACXmPbp_fpfpmHJOQ--.54130S2
X-Coremail-Antispam: 1Uf129KBjvdXoWrZrWkZw1fGr43tryfGr4xCrg_yoWfXFXEg3
	Waqw4I9rySyrZ09asrXF4fXr1Syan2vw1kJF13KFyUZryjqwn5Ww1vq3y3Way8Wr429rWa
	yrWYqr1ayw1j9jkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUvcSsGvfC2KfnxnUUI43ZEXa7IUnkOz7UUUUU==
X-Originating-IP: [36.170.32.128]
X-CM-SenderInfo: xolxxtxlor0wjjw6il2tof0z/xtbBFQwWYFXlna-WSAABsy
X-Original-Sender: liuhailongg6@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=mq1FUfXU;       spf=pass
 (google.com: domain of liuhailongg6@163.com designates 220.181.12.18 as
 permitted sender) smtp.mailfrom=liuhailongg6@163.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=163.com
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

From: Hailong Liu <liu.hailong6@zte.com.cn>

The *PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE* may be a more accurate and
meaningful size for PTE tables than *PAGE_SIZE* when populating the
PMD entries for arm.

Signed-off-by: Hailong Liu <liu.hailong6@zte.com.cn>
---
 arch/arm/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 9c348042a724..c2a697704d6c 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -99,7 +99,7 @@ static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
 			 * allocated.
 			 */
 			void *p = early ? kasan_early_shadow_pte :
-				kasan_alloc_block(PAGE_SIZE);
+				kasan_alloc_block(PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE);
 
 			if (!p) {
 				panic("%s failed to allocate shadow block for address 0x%lx\n",
-- 
2.17.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210110131500.12378-1-liuhailongg6%40163.com.
