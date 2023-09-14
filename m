Return-Path: <kasan-dev+bncBAABBC77RKUAMGQERWK4AHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 52C1779FDDC
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 10:08:45 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-57332cb9adfsf979745eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 01:08:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694678924; cv=pass;
        d=google.com; s=arc-20160816;
        b=ahWqZKo3rrLEAxS94ECszDAbZA1fy/d98RUWr8/pl9ZEsIxTQ5drtebzgbl4ngQZsT
         wTUviFw9yub7YGBjRWI9+3k94PsPRhCqHAoiNQLrXwx0vC+JhYdD8BaBXe0tOFALmXuI
         n2QJu81cm/XSKYdxwjZ8ZiOUTzGYEPxZja/YGZMudEYp40HICkbgOUuKTYTYaQmjsGzM
         sBd4j1MKUgrIPk9YxusoFpQZxysMr1j9WUT+GjRo+YmKNLNO7JCS9KthCOObmQYlXKj9
         60Fm6dsToYsV4hOBEemv+LZnagLPQ//LiGYbCxPpubrD/DGgWvZJyfgnbdX/jII69SrH
         bbLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=d+bLdhHdR0ctxgii+nq0CtIrgnqddJ2OQd2Ib/PDVCU=;
        fh=9tNOOOHWf8rh1v5D9hdTIAxFWVvKZVqkP8B3+taMnLI=;
        b=mEkSgU1FMk5jLVXi0ZYA1F11bFq9ySW5AZv/posOeijBccgKlstjg2mcK+mtkxLuIj
         ylLiHLCnJbG4oWZNFRpZ3Q4nkroeHCcUmPxanSZU0r1dBREGxiNhUCg3xc3hkJ1KhZ8d
         l8rKZdPVEbQynH15MTy/PEv7WpMrRj/87pJEJIBSL02JHKmhc084NeI7awZfYI8cQzOY
         InpRGj/m62zsCDkx3l/h/t32bQgw/NEQlL4BKZd6062voI5gdTbdyZU2PewtXAJtxrpb
         K7M/NrPmYWfYTbSImE/qstWjZoOpRX8WSPUfY27hv17pSyq+oQRwDdtO74QL8lX4Rq7y
         l/dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nbN5kH2Z;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694678924; x=1695283724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d+bLdhHdR0ctxgii+nq0CtIrgnqddJ2OQd2Ib/PDVCU=;
        b=KVP6PMRIw75TLK86x5cj+9G48buiUX5Z5N1UbJBVTNxHP8dXGXuE9wPYQTixv4XE36
         TQD9csufDX32xknaeJHf8A2yzCGlvx52lbGo3H7jNwR+G/4cIS6EhzOV7UU/sJupMG5S
         xNNSv7bD+D3p9AVegfoUv7hKy3nfdWnW4njMP7RnCVVX9avNWuuRk715fQEJyj/ymY8O
         HAA1fcmMUdjApFdq9o0Wk4d94+2dKNwYu0EN71+RimSQFPaqyYA+6oxcrRUT0FECBhdE
         kGiy4Yr+a/hRMlOozOvCHc0GlcxAV44unitUWy89t4PP67hl96G3ZBBGuEGPuGhNTKO0
         V5xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694678924; x=1695283724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d+bLdhHdR0ctxgii+nq0CtIrgnqddJ2OQd2Ib/PDVCU=;
        b=kl6a58SPwjaFdSBTrGBxvipI8M6jRxLqDzzDe+5YI0bVVAovq65b59NJyGUHIqSs9o
         tLXeSBIu6Z3Xe7hd/JISGA0GuXDQbQMwdP0lafob8MMY8PfZ4gCW5VcrbwBFtOL1ohSI
         iq7z0J3DK0Qkc9mKSKob55HTezzw38YIt8jw3NfWNGWq0vWnqIRXneP/ZprAjj1iv5qC
         Q+n5vrL21zyQTflqsRRhg1bN9g/Hw4g0btQ4C87UrJd4Sw9D6Uf03nXULjRgHS2Brmcy
         O1hLVWIBG6cNDJ3pyu+7cC9UMo5I1z8NseJtvSYSnmXpUvGFmuBvS8hf99pRwm639kKT
         lezQ==
X-Gm-Message-State: AOJu0YzgRSjv636N67t9Gi+tiEKIB85tMUz9w5QufzDbDv034xrt17oC
	Ks4xf1LrzGmYKadz1sGtAaU=
X-Google-Smtp-Source: AGHT+IGv8s7g2VJQYaJ2a/XI4BTklJJ1+WhVCLQaS2yX/Bn677xWa6PYwg/jSFogz+tUayGygo+cyA==
X-Received: by 2002:a4a:610b:0:b0:576:941d:3154 with SMTP id n11-20020a4a610b000000b00576941d3154mr4871453ooc.6.1694678923961;
        Thu, 14 Sep 2023 01:08:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4944:0:b0:571:1c89:f1e2 with SMTP id z65-20020a4a4944000000b005711c89f1e2ls500999ooa.0.-pod-prod-01-us;
 Thu, 14 Sep 2023 01:08:43 -0700 (PDT)
X-Received: by 2002:a05:6808:3098:b0:3ab:7adb:7b35 with SMTP id bl24-20020a056808309800b003ab7adb7b35mr6337936oib.50.1694678923202;
        Thu, 14 Sep 2023 01:08:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694678923; cv=none;
        d=google.com; s=arc-20160816;
        b=JSXo3AqTeFWEUKVaAKVwiBpuYauSnQ0QwRMUuilD8KAGEgfwIYvkiCjw1zmEGRMsSb
         hfkIdyCkcGabxb6JrA6XX4HHuD0lpTo1Z+hCFOLT1WtudS5C9WDM78NDJD3os1K/M8Cl
         u2PKqsZxEl8CKOWXQM6SFVNikkx70ofmjyszvftCr87qZ2rm/2lopIqx4yYgeNCpsCEf
         L4o1PfjLvl7+i7W/VelanlLft6ZxUk8yPbn5ileUFmAxdg/TPhxbQiq6WE4wkHCXtPbS
         Q4sFkpH63bh2RnhVAwEOKRtojm6ov5twcRj/qGb3QqrGcT3LB/UbuPkKoOfjJc0nNP8h
         djww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=mlOEeXuSL3Jd9KWoAGMasqY7uUX1ru96a24IVEsPgXk=;
        fh=9tNOOOHWf8rh1v5D9hdTIAxFWVvKZVqkP8B3+taMnLI=;
        b=XgDSKudq3mGDhMjA+yHIF4QCXTboD2Gcp7TFfY78HhztTdZi7G19Q+f0UhOeH96uET
         5mL5I47JH0vjc0g1V/zRAxEkzhO6rAYjqGwF4SHYeqFdA6Nn9F6IxRxeGC9ygfsMwDap
         p3MZVvJLfUyHS0XOmm1cUzqrZnjX7CB17CWn/GOyrkrrhfZBsp6IqJznkPf1yqQQRzsY
         lJ83tqtrP1AAlxbZRFajzA2njdQErwJU8pb/zijv50b9HJXP3rOOkSJ6nSFOeq6iqBjE
         XBk7jV2RdMlk8kBUoIMSjeuXIHll2Y05g8IbdxOOudN8dAsmKhXa8LUrQ3q8WGGDbymz
         HBFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nbN5kH2Z;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id et15-20020a056808280f00b003a843f1814csi149249oib.4.2023.09.14.01.08.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Sep 2023 01:08:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: e7bd0d1252d511eea33bb35ae8d461a2-20230914
X-CID-CACHE: Type:Local,Time:202309141550+08,HitQuantity:1
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:e318bec8-4d6f-4264-ad9c-b8bfbcc41368,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:228104c3-1e57-4345-9d31-31ad9818b39f,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:
	NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_ULN,TF_CID_SPAM_SNR
X-UUID: e7bd0d1252d511eea33bb35ae8d461a2-20230914
Received: from mtkmbs13n2.mediatek.inc [(172.21.101.108)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1145535570; Thu, 14 Sep 2023 16:08:36 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Thu, 14 Sep 2023 16:08:35 +0800
Received: from mszsdtlt101.gcn.mediatek.inc (10.16.4.141) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Thu, 14 Sep 2023 16:08:34 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>
CC: <xiaoming.yu@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
	<angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Haibo Li <haibo.li@mediatek.com>
Subject: [PATCH] kasan:fix access invalid shadow address when input is illegal
Date: Thu, 14 Sep 2023 16:08:33 +0800
Message-ID: <20230914080833.50026-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nbN5kH2Z;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

when the input address is illegal,the corresponding shadow address
from kasan_mem_to_shadow may have no mapping in mmu table.
Access such shadow address causes kernel oops.
Here is a sample about oops on arm64(VA 39bit) with KASAN_SW_TAGS on:

[ffffffb80aaaaaaa] pgd=000000005d3ce003, p4d=000000005d3ce003,
    pud=000000005d3ce003, pmd=0000000000000000
Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
Modules linked in:
CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : __hwasan_load8_noabort+0x5c/0x90
lr : do_ib_ob+0xf4/0x110
ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
The problem is reading invalid shadow in kasan_check_range.

The generic kasan also has similar oops.

To fix it,check shadow address by reading it with no fault.

After this patch,KASAN is able to report invalid memory access
for this case.

Signed-off-by: Haibo Li <haibo.li@mediatek.com>
---
 mm/kasan/kasan.h | 13 +++++++++++--
 1 file changed, 11 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f70e3d7a602e..bd30f35e18b2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -304,8 +304,17 @@ static __always_inline bool addr_has_metadata(const void *addr)
 #ifdef __HAVE_ARCH_SHADOW_MAP
 	return (kasan_mem_to_shadow((void *)addr) != NULL);
 #else
-	return (kasan_reset_tag(addr) >=
-		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
+	u8 *shadow, shadow_val;
+
+	if (kasan_reset_tag(addr) <
+		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))
+		return false;
+	/* use read with nofault to check whether the shadow is accessible */
+	shadow = kasan_mem_to_shadow((void *)addr);
+	__get_kernel_nofault(&shadow_val, shadow, u8, fault);
+	return true;
+fault:
+	return false;
 #endif
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230914080833.50026-1-haibo.li%40mediatek.com.
