Return-Path: <kasan-dev+bncBAABB4XJUGTAMGQEK77M7EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0115A76A73E
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Aug 2023 04:59:00 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-63d41d15574sf40595206d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690858739; cv=pass;
        d=google.com; s=arc-20160816;
        b=dn0GjwHb0L8+jJw+7dsv7l31Ij2K2r0zHTK2qXWgmGUd50lnJp7TaYHMBz0kB1lbJ7
         fQ5csXVgePZhmUyye7oeOmJch6wefHv3419COMt9TWaL7uAn/PCHjEcq2KQI2wiq3XTU
         /aWv7yNJ1DrlPSLDo1ImLV/3d2Eka0Hb/tudAxOYUHlbxdIG5q/69wmEkPQ6UiDW1e4B
         ZQWqsgzEKaio8oGLThIaWjSeFjXWyVGZ/YlboglaQ76h2e4GS7/4siYqiW7Q9tlgdVrU
         d1rp0dh22hF0jHUbBQAcbbBYmjxGrilJDc8UiCAb+z/+ZqUvhMxKog2Ng5ZlLpj8KI8A
         Ikbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=i2RyO2/M6vmH8fvYr0PanSZWKgJp6pJTsHec4adS+Fg=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=XHMZOKI6x/hJhAZ6tGgjUGuL2TINYWY1o+lRBZhrdv8/8ucxReCSB08hvAjGQokCA6
         wZynkkduJ/dJmyDwLM6X/UVQ0wP+guuz8YRV2n8cha3OH6Xx+eFA9hjDiUtAn9i44gmj
         vFaP2mXXpvkmLoCtTYpSuehlpLvVmBQy1pOr/fHieDqH37On1u0x4fSbWBzcWcpXtwDG
         ql+R86hYU1dB5IzbLrzve/BXstDtlQr+C3BD8VTka0Ja8dETxvRIhxzcMreesOLZW2Z7
         mo5Ds8ZQf4JAf1hIbYdXoA1l8pne07yIsoSDAndV4OFbtT9GBUu/rSn9YSCVC8kt8Aq+
         8Lyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690858738; x=1691463538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i2RyO2/M6vmH8fvYr0PanSZWKgJp6pJTsHec4adS+Fg=;
        b=NidLHHLIxe4xmR4929kaeGx1mXrpXuFcik5I/zAaeemipfxTIin/pt6xbkusR+/e3e
         aEH7ap8t0/p/YHmCadOElfl0lbPWL5pAxowv+qBgWH2iNG4hew9+sxg2WfZE5JBBZxQo
         zcUIAxFeLEHQMO6nfKIhEea93qupiu1DDPeQHu5Pvyu7LoSGw1L9ab4MbaZGZfCmPZFP
         U6mYgGPMYv+L6djHphTQO+4So5ygyxoGYA3kpZ5mb/PZBctY5T4D7sXvWC341tBo1lZD
         ZXqL4ZxPvq3S+1LOuWK50mz7XaxezggaYYVmtmJBBV0HJtOKHngLHWj4wUo1maUTz75c
         q/cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690858739; x=1691463539;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i2RyO2/M6vmH8fvYr0PanSZWKgJp6pJTsHec4adS+Fg=;
        b=AWr7DIqTje3f1qzbcxyip8nQMPF86MCbP2GB8tMdx3kQTsdLVh7vb4XXmhDF3cOCo0
         zCjKjl30HzcpcvubWQYEWXhhpDtv9zN31/WMKZQRIHrKsa55rDB3CG54Q4gsSGzod6au
         7c1jSLektIzaAvaVn6jkX9xIAjOQ7rtqPJvJL/f9lovcNYxKjiI8pqTHSdWTnpm0Z70f
         IZRTuSJc6wWSeGDNshDqUyTgWh3kzx2lx/+2HiqXIdWxPJ/QXq6uhvAz0aRxq5fE6yFq
         6W4wzyjtjoTkCrnhZEi5srkwbD2HEeRKCuzY5d6OjEv/Pak0UEAMzBt8XSoog/fOBUX5
         y+eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYM1YkCwIN9RNOoZVJDsM02OtstrG+PA0/o4mxiXmmO/2yx5fl7
	dTSuoXQFvJWHq1DGz+XNuZc=
X-Google-Smtp-Source: APBJJlE51KgvcFYVUNXuVLNYJEYHYZmdB5BlcV1ILrGLXGPZCm0vOVDjDn5U6lAPXW9nV2vWrb6GDQ==
X-Received: by 2002:a0c:fec3:0:b0:626:3dee:6091 with SMTP id z3-20020a0cfec3000000b006263dee6091mr10999855qvs.49.1690858738782;
        Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e0cc:0:b0:62f:e5ab:e5f4 with SMTP id x12-20020a0ce0cc000000b0062fe5abe5f4ls4115154qvk.0.-pod-prod-05-us;
 Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
X-Received: by 2002:a05:620a:258e:b0:767:82e8:eb88 with SMTP id x14-20020a05620a258e00b0076782e8eb88mr12339965qko.7.1690858738230;
        Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690858738; cv=none;
        d=google.com; s=arc-20160816;
        b=rcmbE9NBzITK60Of9kxzx3CXfAH7USLhss6kpH4c6alSexr1PeV4UFinRIIy0PpX3x
         clRHbPTIjIAO86POBCrM/8zH9JV07OKJMgRvPFB8K1j3tXy8Eq1AeccaCHdufJDvf13E
         u2G1XZwjx4mDCIJ7iNCXRhor7T6BQdGzSepZw9eBK48rSKyFEcq2gRcyB6g3dI0TTHtY
         x5GDT5wzlUfFtoGTj1dO9o/DfmjWrmxoIdDkKln+FlYk0lksjIfvYxuJli8+dkaxdOs7
         v+ArrgENx/PM13JmE9jXZ0bDeWC68V8daf9LlXXHrI1S/o9GJGIlBB+nATKWOAA/N/5d
         ggRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ax87EcoYzEMFko+UngAuu4BzrMqvrK/QnibTDD/L0Eo=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=lTU8QoCJcvo0u64tH96Yprb1Zhxw+uM3A9txfRO1e4Vyy70RoQ3f+dNNlh6nd6Za4V
         X3WaNsBAES+7Bt2mp2VOLd6FHFa+m+RzpsIufeSFunmsBj/+4w+v9Hg4valSmC1mtrPq
         DTBGBrByo0ZQ3SGZd0P29k19RPNFcuBE6sUO2fR4yFzq0Bq4gahuuFIUl789yjBdzHcg
         tVwYgHFlcwIALswLtaDIhuk0H4Ij0RvhEpA7gYOFt9IVthQJHYZIQhtpNUW/f3ChWp7M
         rnyVREp6Cq3zBdHujT2vhX3DDrPr25EZIR37WhlAPt6XZOzXD8b/dpM5v2lq6p/xdPU/
         3yFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id cn8-20020a056a00340800b0068730bbed1esi221310pfb.2.2023.07.31.19.58.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 52fa4f5472c44d73ac863173de1bcc84-20230801
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:b40bd80e-2e4a-4240-8880-6d26bd3233ca,IP:15,
	URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACT
	ION:release,TS:-5
X-CID-INFO: VERSION:1.1.28,REQID:b40bd80e-2e4a-4240-8880-6d26bd3233ca,IP:15,UR
	L:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-5
X-CID-META: VersionHash:176cd25,CLOUDID:66d68ad2-cd77-4e67-bbfd-aa4eaace762f,B
	ulkID:230801105842P6SEL26B,BulkQuantity:0,Recheck:0,SF:38|24|17|19|44|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 52fa4f5472c44d73ac863173de1bcc84-20230801
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 833643488; Tue, 01 Aug 2023 10:58:41 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 1/4 v3] KFENCE: Defer the assignment of the local variable addr
Date: Tue,  1 Aug 2023 10:58:12 +0800
Message-Id: <20230801025815.2436293-2-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230801025815.2436293-1-lienze@kylinos.cn>
References: <20230801025815.2436293-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

The LoongArch architecture is different from other architectures.
It needs to update __kfence_pool during arch_kfence_init_pool().

This patch modifies the assignment location of the local variable addr
in the kfence_init_pool function to support the case of updating
__kfence_pool in arch_kfence_init_pool().

Signed-off-by: Enze Li <lienze@kylinos.cn>
Acked-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index dad3c0eb70a0..e124ffff489f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -566,13 +566,14 @@ static void rcu_guarded_free(struct rcu_head *h)
  */
 static unsigned long kfence_init_pool(void)
 {
-	unsigned long addr = (unsigned long)__kfence_pool;
+	unsigned long addr;
 	struct page *pages;
 	int i;
 
 	if (!arch_kfence_init_pool())
-		return addr;
+		return (unsigned long)__kfence_pool;
 
+	addr = (unsigned long)__kfence_pool;
 	pages = virt_to_page(__kfence_pool);
 
 	/*
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230801025815.2436293-2-lienze%40kylinos.cn.
