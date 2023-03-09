Return-Path: <kasan-dev+bncBAABBKGKU2QAMGQEVX3WUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60B266B1FDF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 10:21:45 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id p13-20020a056102274d00b004215e04e139sf466096vsu.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 01:21:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678353704; cv=pass;
        d=google.com; s=arc-20160816;
        b=STKqWr1VQF3eohwOq4E3jpOxzpT9LBD9MwFB2gPXpq+8vZGzxoG3CaL7aJMDBkVyoV
         q4tVnfqQnRwQZokxQ4jFttqR02FoPOI8QG8mgN5/8mxJxYE64pGD28m4JfBHATDlU3iP
         jfQIb+AxQiN+5R7NyuuhFFtDKLNcajoNWKOlg1ydBt0Xi4XhQcfG7e2LKS4ua1C+kEOh
         EqF0fypQsraz67gaQ03Y2XGufHDsTlASc//UV6LzMc8RgsG+vdf7BcOoNiF4o5Ez/MFC
         Ujid8cAfg4EBDJHzKb44H/PDEo3Y4MiAogZDMVv4YGNDQysktO/vEUEjjitXfcpKZ/Iv
         qeSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=slRN3V6at2wL8QERIe+J2azdsYU/5Tyg0E5wxu+hewI=;
        b=trm4jYgJbFZCGPehHUKJM4IfF6kbx3PwtrThrYvGzqfZlkRgswbUeNRMsp4KUNbgg8
         gHY3KeiAhwkdEP9N2VpwBjUkb6oSJcUElApdtzpj+1GydqwK4lAs4jmfDsM4PHtgx5sN
         IdGo6uLdYSjt+j0OUkiJ7IU2yqtrPMUnJwDXF4Qk144xHhoPVaft0qYd7NCBDooTU98E
         oBgLfKLA5o8870B80f5QBzIiTu74lPeQWTSJi4Sh1LBcE22ipKX/bb7ok0hOMbVsCp5A
         FZ2JIl6x40oVX+7Vk9RFGWoPQ1jtrWprNjg2fyBRZyBPzTtqae6aE8WoyJh+kcFFrP7R
         p8BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BnDhUGjz;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678353704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=slRN3V6at2wL8QERIe+J2azdsYU/5Tyg0E5wxu+hewI=;
        b=CrqJTBDZwOwLpRBsOZOxgyWTMaAjcAusYBd5f5LAel5WG2XckKxBXSodgs/ArMQJy/
         FqGZs01H44geCXKT4MWTa5A12ujVhetLrCzIGwZ3SE0UEbE+qsTXWM1FUWeFDBjuZbes
         JPoX845QFm4nJYAUTZlSLgtnxY9cToTIO+2Lvtw1LR5cqDaoi1LwkwICSPbJQnZuefwX
         dV91EvNcEM7rJHEUZGF13XTESpWX5A9gnPReM+1cPEDONDKGeKvLq7Rew/f6J6uKA5YZ
         E7argPlVXlSMJHCQlBlC2pRfN4pZmKQMelUEg0nprJV1dzWMSru/sz5XBO+et3MD8KHr
         QcxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678353704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=slRN3V6at2wL8QERIe+J2azdsYU/5Tyg0E5wxu+hewI=;
        b=dvJMCURRD0r3m3yVt1YEwe4ItVXOumv+IA/5CnLTZ9ZzYvZ4zPfOsnvZKwF1kQh8Kg
         ZcbGBsBESPYPDUHu/I3v0Lz2P1oFEXeZ//deAtUhWoc5dG/9ZBgpXhoe94DgnGAKjUOO
         DxMi5C0HOumMyAkZrYrRsS9Qqpl/JTqE4Sj20GfPR6IEW7ksKE1cjSlr4Pt6CvOhn920
         aP2uqEO0KlEhpOhv7BVNhVw3HSSL/47wSgNWiegqCi+dB1a4BlFOWi91+YXV2knqkIJr
         kikmflgrNug/+fFVpnYATCgIBzXzkEKvNfIz9oVv5jrudLrgT0syrSjQOi2zco3MVr1o
         i1RQ==
X-Gm-Message-State: AO0yUKVLNA1hsDYJ9iGaAlAH1ZewoeT8Luy8xZtcL1ow7N89/KtFDvSu
	OqKr4ieD4nCMAHyotwTPaW8=
X-Google-Smtp-Source: AK7set/gZyLKfdmdFR7wL8QjkWRqnW+KXBq/rsM27KzXp+JNwkxnclejuEdm/IW3VQSYnE+zk501Ww==
X-Received: by 2002:a67:e98d:0:b0:402:9bf1:289f with SMTP id b13-20020a67e98d000000b004029bf1289fmr13622200vso.5.1678353704183;
        Thu, 09 Mar 2023 01:21:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3f4d:0:b0:406:63ad:d0d with SMTP id m74-20020a1f3f4d000000b0040663ad0d0dls191272vka.10.-pod-prod-gmail;
 Thu, 09 Mar 2023 01:21:43 -0800 (PST)
X-Received: by 2002:a05:6122:14b3:b0:404:1020:4996 with SMTP id c19-20020a05612214b300b0040410204996mr10373447vkq.9.1678353703666;
        Thu, 09 Mar 2023 01:21:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678353703; cv=none;
        d=google.com; s=arc-20160816;
        b=Vir2tQq2xUg3G9de9KNxyZphoZxOdmvjWPgmUq+jTfW4c8/inXf1MIUO2nHnvdnS6L
         TcZZoC1I6SIlLupzvs91PcEmEe/00qa5lnb9ku1ChsxMaptO+S25JuAr2khQr8saa+iD
         R15ohdR+V2Prc8/hfNOL7P7tdoNZ0ESOQUjmGg4/zYqQqTw5BaH4LchKg5hKW++AAs2C
         vEwzxSv8QlmmRVqmLRz+lMaFLB8UY8cdLpm+HiazT7Xid0U1GzZyv8rm2Zr5exIknISK
         UgkXcxR1PRX3k0xONm3+Z7dWjTMk+CAswVsFoRlc+B+ylHMCMVN2EQ5YmDe81zIDP51B
         J7dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=u2Y+lndMZvPCQFgYhF0b5tZdi1oGwpOpzR4P4QFlUvU=;
        b=zbrFYawy2qqoFePXAp3KJp85ZCT/+YQIduaQtLMxFXlOJlg8rHMSXgrBxWNlPcna+6
         r6BNXFB5L/byAoF5p/GLCderC6amDI6VcGJGqbM/ViOsBNCs7UGqbk3IiT5tHOyAsCgP
         OiBmjDKmqFm8qSxUxtOEU48Fhoi4aBS+JuADdS7q7Oi6+1wTcmRhE6XIKjVBvXQ+kZIZ
         wjidDm2Ry9LOZfYjmYAf1DhHCwqcxfsHP4rTK2DsOa4KGK4TYy0oZkmq+sfb7MPlbbNO
         /3QC5XvxncqV6rSJhUQmvGDxwMdDcHCOXxu7X+I/sToRdvvTAUKWuIMkmDYDUwxRg18c
         mStQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=BnDhUGjz;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id y10-20020ac5cf0a000000b0040679ae1c37si953610vke.2.2023.03.09.01.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Mar 2023 01:21:43 -0800 (PST)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: cb63d448be5b11eda06fc9ecc4dadd91-20230309
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.20,REQID:fe97114d-fcb0-4547-acde-789eb8b9fc75,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:45,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:45
X-CID-INFO: VERSION:1.1.20,REQID:fe97114d-fcb0-4547-acde-789eb8b9fc75,IP:0,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:45,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:45
X-CID-META: VersionHash:25b5999,CLOUDID:141246f5-ddba-41c3-91d9-10eeade8eac7,B
	ulkID:230308155434OUYWJX05,BulkQuantity:35,Recheck:0,SF:29|28|17|19|48|102
	,TC:nil,Content:0,EDM:-3,IP:nil,URL:0,File:nil,Bulk:40,QS:nil,BEC:nil,COL:
	0,OSI:0,OSA:0,AV:0
X-CID-BVR: 1,FCT|NGT
X-UUID: cb63d448be5b11eda06fc9ecc4dadd91-20230309
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 442448829; Thu, 09 Mar 2023 17:21:38 +0800
Received: from mtkmbs13n2.mediatek.inc (172.21.101.108) by
 mtkmbs11n2.mediatek.inc (172.21.101.187) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.25; Thu, 9 Mar 2023 17:21:36 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs13n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.25 via Frontend Transport; Thu, 9 Mar 2023 17:21:36 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <angelogioacchino.delregno@collabora.com>, <dvyukov@google.com>,
	<haibo.li@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <mark.rutland@arm.com>,
	<matthias.bgg@gmail.com>, <will@kernel.org>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kcsan:fix alignment_fault when read unaligned instrumented memory
Date: Thu, 9 Mar 2023 17:21:36 +0800
Message-ID: <20230309092136.35799-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <CANpmjNNw6utf5ozpwu1keDG92Ew_vL6B=LZoRw12p48eVJeNnw@mail.gmail.com>
References: <CANpmjNNw6utf5ozpwu1keDG92Ew_vL6B=LZoRw12p48eVJeNnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=BnDhUGjz;       spf=pass
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

> 

> On Thu, 9 Mar 2023 at 01:58, 'Haibo Li' via kasan-dev

> <kasan-dev@googlegroups.com> wrote:

> [...]

> >

> > The below patch works well on linux-5.15+arm64.

> 

> Thank you, glad to hear - may I add your Tested-by?



Sure.Appreciated.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230309092136.35799-1-haibo.li%40mediatek.com.
