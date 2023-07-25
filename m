Return-Path: <kasan-dev+bncBAABBPGR7WSQMGQEM2ZND3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id DBB3F760A1F
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:16:29 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-403ae7d56basf65881621cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265788; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZNXRzQlK7Ibr2LIymB0CWNo5Im5Lh28eNtVLbnFp6lD10pR1nwCwuC5FqTGOxZXpyL
         9oXvUJORey9lPJ4NbAUbQpRmpaW7IMs/vURin10ZsIQMpfn84yXz7yEIznNLy5W6HDPj
         cVY/VZqJ15cOALqxhZJrPTqMAU118HZNw5NTksxSm3DQ+JzRk+98ZymLDOxovvghzsbU
         hH+KSZZ28geFSE1RoXi02Bd0eRCcj5R0BD5xbuNgs+2lP0vHrHCfhTI4vY16PGYoHX+1
         kDtF02cTgNvBUTxhyyXHa22sHDSu//LY8wYZNcLzluMenR1JV1Ez20gZmNm8xggeqGD+
         bvMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6mhgojcUmr+ZxeozTh9HEe5UGVEnwo1/MDm353KkL1o=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=tR3pJ4eUcqP13jPBXYrbYfk6MTJ8nmPKdvdxxaNGbHCbgb69qmGKnCQOeaoapUkLvx
         Wjqoj93X7g4YH7YnOipmCcYykAdwBYalZ5RgAn/XI7xed4Y3fd0y5axdldSKRx0J5m3l
         uQIaZQT+YEe5muCEr5V/ykTG/1fU576Ld0fwMlHKmU9Y4D99ofzeUUmbXiMgB6tXKvEQ
         S5bqf3OMTecLPPqLhOf0nDhffeXoRbQWYy5xiHw9ZW8nU3jlmdkXi+K3z4pwQZjW2Ina
         G0slRR94U/RPyqlvxt8P1XJ+1qu0xVYaVJ2gP0SP8HftA4pkMIDoLx22zlA95kienVzK
         CNjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265788; x=1690870588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6mhgojcUmr+ZxeozTh9HEe5UGVEnwo1/MDm353KkL1o=;
        b=i3I9ahr5J0vhKgmxv2eylYG4MFI85EVX65uoklnGttzpkexgJeAqBQ+QXIa8Us5Qpy
         xdhzpU9uE4LrhPRNjzMEd4OhvvIRpNVU0tDLpB/x3z2pyXQi0iAIT+cZ+wdFTFy2mZAZ
         V10QU+qLDPDV6coHpPfeauxTOJgesSGAp/rRoj4R1Iy8j0ZPWYvlh4LnWJIB9MwbQ/Yz
         /Q7a7nDlg6DjOGweo4iK63fGgqQuFzpAverTqGYlhGs9e8ZkDUUwunzXc50OCacMeU0A
         8G2U58KfJ3MZhjxCvzsaWV2OoCdWrn0RLpdjbk7TqfmWwhOYO9GTraQtdBzCWdHWGObZ
         bLJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265788; x=1690870588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6mhgojcUmr+ZxeozTh9HEe5UGVEnwo1/MDm353KkL1o=;
        b=Pw9BzJ1I2MEv7pHZB8wWKEEtqnCAUXjux1Mb86hANKCRnSr5u12yh0rHWEYaIky40V
         MypU/fDoihtgZzBaLGcFQ9uC2gMzfnisU4mkT7Ak8gIVsGVl6Qc1TI0EBKTBgA1tKSc1
         lYF97JnQLk/JJwuC/jf7LmbQkmuy68LymztJEP3zB67xX/TbsCVX0zuRsz36F7smOLOM
         kkTHCLZNHI7yg9ZEFkZ6szmcYgrcQ3cN2As9s7AGJmbFP8vZ38GBAAGzaK/8lKfxNC42
         eC6BvTGd07DtG13St41OGPMCfZU5Qv6utZdBWfNXlBGM4eWw9NlsztOAKdchfYjpKTaq
         Ha3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaOEc2OgftEVROjHJEaEKfMM5NVueXkd89D/fx7Q73jZHDnftDO
	ep2V8k6CKt9/5W0YEr7RCzI=
X-Google-Smtp-Source: APBJJlEMQyGzLpZQoQ6PQbxeaRx0UAznD82GgaUIVVRJ8vhDg6L2MQRmxyOADT3OGio0ulqZIsxA+Q==
X-Received: by 2002:a05:622a:1041:b0:402:8ecd:810f with SMTP id f1-20020a05622a104100b004028ecd810fmr2683507qte.40.1690265788620;
        Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:44c9:0:b0:403:9f44:95c4 with SMTP id b9-20020ac844c9000000b004039f4495c4ls4765822qto.2.-pod-prod-02-us;
 Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
X-Received: by 2002:a05:620a:46ab:b0:767:ad41:99c9 with SMTP id bq43-20020a05620a46ab00b00767ad4199c9mr2320849qkb.6.1690265788098;
        Mon, 24 Jul 2023 23:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265788; cv=none;
        d=google.com; s=arc-20160816;
        b=fWmYBDpSU9Vh7rzbiBgS7DOUyN8MPhBr9I4mZp3nhXaBC8j4AvjeMDIAaCYSA6rdZ9
         gRJY9U72ckn8yKfLvrAZfi64fwoyTfiGpkqJrK54G5qouYfeWRXCGwZYbtm7VUyXI5JT
         JRBHyquKHRT6n6XFwvWo1qDoWXSQU1NslNb7sBnb57c/YRnp3tl/jrhQTk/5HpbcP+26
         oPkEG0Kk43IZc7dnP4hJcuzDrBPSZDF8VkxPV8CV0+PzSmTEkB+S/ckAwjfqoixL0mSB
         feJkblXu8kFQqQg1CmtOYEBIYM1yEygmPMZmQA1Cb0icn3GUwILBJ0cefpl/Rf2UeLtB
         oFbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ax87EcoYzEMFko+UngAuu4BzrMqvrK/QnibTDD/L0Eo=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=ZMA8L/z55JDacKLF/SoYBvxI+mEZx5dkya0LAO2Qdimy5zgoQA/l1xIQdFIAserPZs
         iZGZU9SG2Ipf4NXP+AjXYy7uCFCvL7bS0jeyINXfWDYv1wn6IC6NQp0DOsB7nSHVLfJY
         xmf3S2AqMagqe/OlensetvyqNdVvL7Z6/S/Lq9LgI+dwGYfwnSLJbbdLRJe3QbZnIAVk
         wnK2O3n+hGFIpiNjIMn8fngaLrI+P+8nUnCi++OCidxuoGRNqpryafkcLOIvWI9aZXFa
         92h9/KAsGh7iwQdVChbIlkIh9F3Fn9aWsKhbhQff/QuFUMaYscXM/kQrh2LAlDYVLqma
         /wig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id bp13-20020a05620a458d00b00763d5f6718esi563697qkb.5.2023.07.24.23.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 23:16:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 8e5b3e4a0453435d8408d3e21c20e6c4-20230725
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:68b8ec71-7352-453b-87a7-33a33507e392,IP:15,
	URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACT
	ION:release,TS:-5
X-CID-INFO: VERSION:1.1.28,REQID:68b8ec71-7352-453b-87a7-33a33507e392,IP:15,UR
	L:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-5
X-CID-META: VersionHash:176cd25,CLOUDID:1b3b7fa0-0933-4333-8d4f-6c3c53ebd55b,B
	ulkID:2307251415132XWQSSO0,BulkQuantity:0,Recheck:0,SF:17|19|44|38|24|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 8e5b3e4a0453435d8408d3e21c20e6c4-20230725
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 715763335; Tue, 25 Jul 2023 14:15:11 +0800
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
Subject: [PATCH 3/4 v2] KFENCE: Defer the assignment of the local variable addr
Date: Tue, 25 Jul 2023 14:14:50 +0800
Message-Id: <20230725061451.1231480-4-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230725061451.1231480-1-lienze@kylinos.cn>
References: <20230725061451.1231480-1-lienze@kylinos.cn>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230725061451.1231480-4-lienze%40kylinos.cn.
