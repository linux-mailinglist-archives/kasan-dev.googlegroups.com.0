Return-Path: <kasan-dev+bncBAABBAPXT6UAMGQE5NUHX2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 814C07A423F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 09:25:54 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6557c921deesf50999396d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 00:25:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695021953; cv=pass;
        d=google.com; s=arc-20160816;
        b=NxQtSghJ/9PUoHEZSmR2ZpKLc9MxsIDtacUSm4veRa41OnibaOT9czzOW3XgNGlcVn
         OaFjFteqRG3MMv1YmVXaSPHAWYoowXn7JBLgmnaTxSBKdx2ega1D/pqSEi6VD0x+kBCn
         z3sUSLsdQXG9zYwdLZF78a7IHLftrvfNRiuNBHCN1u5PLXrhd3NrODX7ZbEgbTBlmN/K
         7sBK0S3q8aWCfcp0SH4i0npEPFFOUOkA10tSJAXm7G2AHNwdlXFHmmaguZNiF7C9fRoS
         Y8Rgw4reY6TLoK5YdgIB3mPglZGjK+Zz9lNwGOkatNLTO0L4tFeUiGG9vvCsWnaw6o33
         vaxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=5xKjFrrbxWkzYNiuhnuNPL0Qi/fdkPvBiddkf1scXRY=;
        fh=xnjHze2hhizWMWL+c23S4hdacx+DEnw7TyPmO82Bvos=;
        b=WOKOgP8inBjtaCaNccMnydpWFyVYx+GZwLaTx1G/GgZMQckavJeMXRbe78xl0NqKhI
         eFcI5WRkK90hb96vGQGPsyUnYcHYe0sBU60hFhGM2kEhmBwo3ZA3OkCXfV0qnS4UIW/A
         xP3BCymyS9zrue1P9OJCuLqnYXXb0AKBiKbip0LWsog49j10BNNgfoBS3n/H40/PsLGB
         vXExJZUYJc0K/DMapGnI2MWyXXb0gXqRNoeYY9UBJh8rniU9arL6mo+egdtaeEnJR8Wz
         1Ls3cGzNSTvGjzaeE/LMjs0t7DjyVy+WC+/F8KJuY1/HK9lN6g0GXilGJwvRs4DpxCKQ
         qcCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=iXQBjyY+;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695021953; x=1695626753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5xKjFrrbxWkzYNiuhnuNPL0Qi/fdkPvBiddkf1scXRY=;
        b=nqSzsB2pTMHb5sMyVlFEqWbNOr+3/5gJbDYMHNbQI27KUB19w9ruN8yAsM4JELmjgU
         6GrqiNhaLVTEhYT8qVJ+/Stuq/RIFJagTym+YobptzM+Efq1fjHWU5XcwwAz8IEHHOpT
         W2CA7GTUut+08X8VJiC9HGOOW1lV8WclyJlz4JGINWKPFnMgZLd1LVvNwiR2HIEyFtfQ
         bFABRwFRqaLKLUK2dryVWI4bds/hoG9Ur3VkG9CsRxCOjGP4Sg+UHRJfU1xkK+OppH6R
         dkXllHRR2b7Gl95SwNyHmIJ3UEwE/LEj0KZfqDf4rbiCI9scbE4296Hk6TPB79RahNti
         ylBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695021953; x=1695626753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5xKjFrrbxWkzYNiuhnuNPL0Qi/fdkPvBiddkf1scXRY=;
        b=LdAjIpet6q1WoQQdy4q90LQVg26KygNwOaEjk7v9BqJgUQFnODQYSwpGN2LwLBvm/J
         KBLzPyHEa6hVneS2HlIr02BZbjwg4UXmCtPzdS7kdlSBBjIpjjRFzq+EhIwuzclEazwx
         TgFdmZcKNKbuqj0GLBI80AtJnp+ogxXblsdTWbYYcaRHyS4B5edUxk1UxOe48ilvu5EY
         EkuxVwbOIU3bv+Q7wVhe8/uMENyAt7AcBmupkkpvDbyIozpAsbpSGzjKDMPJPzQQRJBY
         G6f4jWp/jjRaaz9RfjlcL3hXsFznyd5MSqgbKUWlWRODFzjYkwjtny18cBFNMGh9en8c
         CiCg==
X-Gm-Message-State: AOJu0YwWQv5J74HSij1Svp5oYta9/zAJ4HZfJJBkquj3ZktZ3cnmMgga
	NpeXN9ffKZQjisH0onoH/Fg=
X-Google-Smtp-Source: AGHT+IEC/MqPbbkwMW6ekdMmWRy8yKz0RWLV7CQZ+i+QCd4c20R3qMouYeDdxiv2QGLtrOJF6E2xCg==
X-Received: by 2002:a0c:9c8c:0:b0:658:2eb1:10d9 with SMTP id i12-20020a0c9c8c000000b006582eb110d9mr328669qvf.14.1695021953108;
        Mon, 18 Sep 2023 00:25:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f389:0:b0:648:190c:a15d with SMTP id i9-20020a0cf389000000b00648190ca15dls2309217qvk.1.-pod-prod-09-us;
 Mon, 18 Sep 2023 00:25:52 -0700 (PDT)
X-Received: by 2002:a1f:c806:0:b0:493:49ef:59e0 with SMTP id y6-20020a1fc806000000b0049349ef59e0mr6113161vkf.13.1695021952524;
        Mon, 18 Sep 2023 00:25:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695021952; cv=none;
        d=google.com; s=arc-20160816;
        b=E0Bb9eNmDC22/PLQJlUOX+HNhRwFdUGMELG31iW6T2vaAMd8jBPDJf4obfYhK3V87P
         HDitOn/6+w5goiPPsKW55cN/8rRlV9+wrMfThOk9qwGFKv9+3eB9GuhEtkbGDcA9jhVx
         5Gl9Wf/uBXtRPOLtHQWhU4V/9LMIeIEeiUptfeKML8L+kJWsnhlaQ337bLYWM42esPKd
         iWls5r+4LJnFx6jGUxWgL+sOjofFG2/xAj/65sKiK5Pz+CRWTXwPfAWOFNQvaf9HOedZ
         W+T8qV7WHcO6IZuCa5G477IwJuAVfgl+f5xk+W2Parq0PryUb7KC+cwpg7KSgALaG2My
         FPsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pmAQXDi1eFJFIz1BbU82J1+CnIbylJEmn229iHCJQIs=;
        fh=xnjHze2hhizWMWL+c23S4hdacx+DEnw7TyPmO82Bvos=;
        b=LXsCAUiFD3FxUwbzvn+XnXTDecihlPmqKt54LeuN6UU2i599jsHZSF0rvUmPtAkO+b
         CTAilXtPnjzMt95/0Zz44GDWgTaevtaJKCm9vGvYJhfH+xk7d+TNWXbj1bEqzf676Ovk
         dqTPUIhF/Ex1LD469ZpXTP4EFI9PkYV+rgIklehVjMtpD2PWFxDosMf89lO2IbgDHU9w
         Mkx3Y3nHMayawgWK/H3O0Ev0KLVUkaMkV9HibHJZbhUWrHIjqY8yW8Ks9rGRWk6DseND
         FbAKJheiKgMke25Dji3jqrQQenWAwHrXlVQVCUhMgQ3ZEwG6FsXRkf6vqlYV3DRsrzJR
         W2hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=iXQBjyY+;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id dk5-20020a056214092500b0063d2253bb8esi884803qvb.2.2023.09.18.00.25.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Sep 2023 00:25:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 961e5f3e55f411eea33bb35ae8d461a2-20230918
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:7d7382ba-4a4a-4e4a-9eb9-67af55be4359,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:31a6f5be-14cc-44ca-b657-2d2783296e72,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 961e5f3e55f411eea33bb35ae8d461a2-20230918
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1752200225; Mon, 18 Sep 2023 15:25:47 +0800
Received: from mtkmbs11n1.mediatek.inc (172.21.101.186) by
 mtkmbs13n1.mediatek.inc (172.21.101.193) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 18 Sep 2023 15:25:46 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs11n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 18 Sep 2023 15:25:45 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <andreyknvl@gmail.com>
CC: <akpm@linux-foundation.org>, <angelogioacchino.delregno@collabora.com>,
	<dvyukov@google.com>, <glider@google.com>, <haibo.li@mediatek.com>,
	<jannh@google.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<mark.rutland@arm.com>, <matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>,
	<vincenzo.frascino@arm.com>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
Date: Mon, 18 Sep 2023 15:25:45 +0800
Message-ID: <20230918072545.87653-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <CA+fCnZfuaovc4fk6Z+p1haLk7iemgtpF522sej3oWYARhBYYUQ@mail.gmail.com>
References: <CA+fCnZfuaovc4fk6Z+p1haLk7iemgtpF522sej3oWYARhBYYUQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=iXQBjyY+;       spf=pass
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

> On Fri, Sep 15, 2023 at 4:46 AM 'Haibo Li' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > The patch checks each shadow address,so it introduces extra overhead.
>
> Ack. Could still be fine, depends on the overhead.
>
I do a simple test by reading memory.
Read 4096 memory by loop and the reading unit is 8 bytes.
__hwasan_load8_noabort is called 512(4096/8) times.
Measure the time of memory read.
Here is the result on ARM CA7X(repeat 100 times):
---------------min-------max-----avg----
before patch | 77.3ms | 80.6ms | 79.2ms|
after  patch | 77.2ms | 80.7ms | 79.2ms|
----------------------------------------

There is no obvious drop in this scenario.
It may differ in different arch.
just for information if you are intrested in it.

> But if the message printed by kasan_non_canonical_hook is good enough
> for your use case, I would rather stick to that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230918072545.87653-1-haibo.li%40mediatek.com.
