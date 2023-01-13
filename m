Return-Path: <kasan-dev+bncBDY7XDHKR4OBBWM6QSPAMGQE2JUVUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id D67D8668FCA
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 08:59:22 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id y10-20020ab0560a000000b003af33bfa8c4sf9157344uaa.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 23:59:22 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1673596761; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fbo8rtM93rVXw5n2MvPgK45GoAjqAmvyyjTTLCYl9hOLiJGBCSUNuRJGZmhbxfuBJ3
         SrBNbcLR9DlqYZvASbTiulapmiVi1QxNE2QKwfip1R0O3n6gfE/qBLamt8qB2dQKhj9u
         20+wlcbb9sxY/N4lPTC6slRiORYrzq/mvuo+6d+Utr8NcXEo+8/h46jMJQYzOXAABoh9
         psGgNDDS0kA+tI1rzrrC8DE7iPs1B1fEMvHi820m7xBHEUMXFxdZtQJrWx8WuliwqRsv
         ggarrxmOqLzf7ZlX8fd0ePMWf7nf1GKcdHu4O7Zzt7dC4V3zfvHMflM+SmvYZGWONYva
         g39g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=OEpilcQTg+gW/yTHbTvUpeKYp5NfZ0Qx4jWFb7yb7gI=;
        b=VSlO8P9ftx92MByqruGPX1d9IJAY6COmP3DQtNMKXElp7zar7mFa2TJAzzDL/hdhLI
         KUUBzqOnnbfTr0MPABb9mVQAm5XouUMqTwI2dn8uCiXwMoS8rm2lHd07hoTSjkpcCVho
         Laks8b3YhBtsAf2HDw2b7vJQrahr0MWSsTHrKiYeD1GbmQTH6il4lCkZ/jNIkxNtTZbB
         TVFZFqP/4hmzDQJMzocJNy7gB/2rZTyVHxpq3rQ3IGNz++Tjwn7BC9rn5yW4Cn3kU+s6
         ft2+U18ckSW5BIsAf+Aup8KNog3I26UzeZBSGaDjRgeDPqj2IPaC7o3XpesEBpTu4tTy
         ze3g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=k5y3S1zv;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=a8pw4MOX;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OEpilcQTg+gW/yTHbTvUpeKYp5NfZ0Qx4jWFb7yb7gI=;
        b=YG34dH4MITBxJXMVcTzQ/WcldD7qSSijH3zieOlvyEBneoAzULNsdvsgJnV5prhqZQ
         ECTNBylXpVl7wAPNf99QNOnF3d7idznu+DFhX2HOiaZhQAT0RstKvy6TLIN8/E0JcQOf
         7V4hJJ1E8Wp0Xe2SJCyaDkTPMV5H5nDtgBimcobuSCMAcHla0rvWLR67AS/9VeB3rQSw
         qq0ku3I208JbmoFrwjiejiXQMUhTY/F6K6C88gHLB8icSXZxdwU58nO9BgAjjqimQuts
         k0WOs78jcJDvv/v/QMLwCvJr9G128/hrkjzfaw4LAmAfo2aL3Qd9ylHL3cLXrbnDtZc8
         YSXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OEpilcQTg+gW/yTHbTvUpeKYp5NfZ0Qx4jWFb7yb7gI=;
        b=tJMeum93RXliu/xpv8jLPL020VPWmsXP46twPXF/+gT7sipkw7hVO5jAEBnvBuXvO5
         gjbLgv70ZmGqRs0lezS9jOuRawMvRcGFnQ1Nqo0IpFXOSy2McW9Gy2X98I/Ilws6CTwm
         V3MgU2G21Ge7N/RYeALXLgOmS9eX9rAaEfwUBONf7NySzvYcVnAdU83NWGl94/XBoDfK
         1XiBqK/8gsqKvQ2wrAYzxIHGbznBFN1CRn/XwDFn2wB4LLzahehoFbkV+u1B0dsurivX
         AWqsyiTOR20gUeQaC//4mu2lwbbmxWi5AjBtqVhjWqSQRnLqbgJD1oD8ogs5SyIB9X/E
         EUrg==
X-Gm-Message-State: AFqh2kqFE5MfZ47Lgm7dDzYA8IFiDgrUJiccqO7vWtcOBtc0Rqnslu5k
	I0J1zJ38ildORtw/vgEz1sU=
X-Google-Smtp-Source: AMrXdXsy6RpzzbdCLglXVyAZC1X9TT6mVyVmTd08FeN9wdTAw1cehT+dFUnTOy0do3HEi3+7JHbB3Q==
X-Received: by 2002:a05:6102:3710:b0:3d2:c67:fda4 with SMTP id s16-20020a056102371000b003d20c67fda4mr9033vst.46.1673596761573;
        Thu, 12 Jan 2023 23:59:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:28cb:0:b0:3c6:6b56:89bd with SMTP id o194-20020a1f28cb000000b003c66b5689bdls781799vko.8.-pod-prod-gmail;
 Thu, 12 Jan 2023 23:59:21 -0800 (PST)
X-Received: by 2002:a1f:2707:0:b0:3d5:3cae:232 with SMTP id n7-20020a1f2707000000b003d53cae0232mr38262060vkn.1.1673596760952;
        Thu, 12 Jan 2023 23:59:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673596760; cv=pass;
        d=google.com; s=arc-20160816;
        b=p6VnH9A+C4SlaWnVnt01Ruwn5vpoOVEn78Xoeb2JDwI2s1qGrTN27p1YyVvKgcCWnt
         f5cIE6VHwWYwyQi0uunprjQ4KIH2iRb2/h+B/BW1ggkRA8EpbKS1TdAprNYZu3KFz6Sl
         liaAVdxXMGSANIA53jaF6un4mmoyNOGP43Cp5SC2S04p8tMQ6cLYt6Ki/pwR7cOfglg/
         jDC6k57VnxIaXb3+kwaov418rAKLYfrt5brJ2uDdLrdIOtf1QZq/spdg7IR0Qw55vi9a
         lAizpyoc/pyGNYWx48F0yMBK37oWxnRnGBOz5SWrLSbRg5ylQ34WB8zD9KqNERWQSpqq
         NWfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=X3u/c4SmJA3aO51WS2mgBKu8IlQK0n46XIGgyksUFh4=;
        b=Th/t219Nk0yoFj3LapvH0clIhocxLN5M1QIq5zcVTQf2hmRjS4qW1kgjOp+6Yoa/tx
         ucCvqg3iK7O96mF1Tt8l7qW/JDgjqPzIjQqpEmlZNYWKcOZEK4zGzQ1hlFGh27acqzK+
         0hVEFDdSC6qUf3ys9KnsyYCYtPJgaLdkBIMjg92lG/pe1JHNMRoJtGJYrREzMjDOgbWL
         47EXSWz3JLG5jJkMFOpTMK1jJjRYxYMrGZOjIcobxJ/1b2gkmImiHCjwZwQPClw0q9yL
         sXTpcEYlt0Sc/sl7Jrt6a8JfZx9pMqxuMarXEa8b+qv8uE+GqlfqVAk8hjX1xZgR8COS
         9YHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=k5y3S1zv;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=a8pw4MOX;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id 140-20020a1f1692000000b003daf0a8001asi618279vkw.2.2023.01.12.23.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 23:59:20 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2b4c34d2931811ed945fc101203acc17-20230113
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.17,REQID:4e024dc7-aedf-48db-9442-1c5c3c630a88,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:-5
X-CID-INFO: VERSION:1.1.17,REQID:4e024dc7-aedf-48db-9442-1c5c3c630a88,IP:0,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:-5
X-CID-META: VersionHash:543e81c,CLOUDID:fc858e54-dd49-462e-a4be-2143a3ddc739,B
	ulkID:230113155915PEDXBJLE,BulkQuantity:0,Recheck:0,SF:17|19|102,TC:nil,Co
	ntent:0,EDM:-3,IP:nil,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,O
	SA:0
X-CID-APTURL: Status:success,Category:nil,Trust:0,Unknown:1,Malicious:0
X-CID-BVR: 0,NGT
X-UUID: 2b4c34d2931811ed945fc101203acc17-20230113
Received: from mtkmbs13n1.mediatek.inc [(172.21.101.193)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1575061550; Fri, 13 Jan 2023 15:59:13 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Fri, 13 Jan 2023 15:59:12 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Fri, 13 Jan 2023 15:59:11 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Q8REKUTeln9fnS6g21goWpmp9RrthJtdPNW3bGNWN/jiC8p8HtTPFl5zhWBgSnHcOYKayCwRyyINi7yy6jxMgXLqSOC4wAVFS0pjuUIsEjWG+se2hkEZ5d1XbihDaJIUsw0HVTW20DjCESLE63QQnWcbI+Cq+S7tVnBldjvMFCnbQ/3e+xS0jRjsXdXZKTNuKER19XL0bVGt1EH8Zoj0AtqhGpHms9N1uHxLrWzBjsSW3EFv6e42FkNtrcToZDP2ojcO5/JJIBJ2rds73rsxSj821Z/Ei1j/jA5FUHs+rcnpVrPD8GFaAugeTzPEyUhXSozAc/znAVlvSHQuWnQAkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=X3u/c4SmJA3aO51WS2mgBKu8IlQK0n46XIGgyksUFh4=;
 b=F5Z6aKxyI5pAf/LxpV0AmjiHPq2hJvtVgZTDN0e5nmM8vHVDGumkRCZ9f3QdmeLfceQp75GeAK76IC4n6R/Ssl3b8We6Q2T4Csw7PYPRDJst8LIaaBEOalBKMcblrLmZbRK4AzCI3Cil1RDXpFEMNJzx/zT3ywIPKHHt3P3GBTWsGQMfWMmWteHrrlCfvxGfeBxy8GLndkiufT+iTuuqed23mey+sPx1WGVMzxaxqcwSCleP7mam+QppNu6LLPGqGnAaUaihLQPLc8bLGAgwakrAXiZZQwwfI8vI8UFEw4ntak1hPLMeyUUXM8aLJSmIb8EfBq7joD9aztz5qeTsrw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by TYZPR03MB5856.apcprd03.prod.outlook.com (2603:1096:400:123::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5986.18; Fri, 13 Jan
 2023 07:59:09 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%9]) with mapi id 15.20.6002.012; Fri, 13 Jan 2023
 07:59:09 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "dvyukov@google.com" <dvyukov@google.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	=?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, =?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "glider@google.com"
	<glider@google.com>, "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
Thread-Topic: [PATCH] kasan: infer the requested size by scanning shadow
 memory
Thread-Index: AQHZH0jgINbB3ihm8EOrOsTiVH1z6q6VruoAgAZcVwA=
Date: Fri, 13 Jan 2023 07:59:09 +0000
Message-ID: <edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel@mediatek.com>
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
	 <CACT4Y+b5hbCod=Gj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA@mail.gmail.com>
In-Reply-To: <CACT4Y+b5hbCod=Gj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|TYZPR03MB5856:EE_
x-ms-office365-filtering-correlation-id: 500a0f8a-d4af-4bff-f3ba-08daf53c0d36
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 16tlp0J7sEeBZItS8n9ecc3EnWEAVFyYF42PBolDA983cjXyof5yBGQmtytIY/ChyTCJHJhQ72O7UrwgVLJsE7zyDYLtV1ps0VubEtd6IhJizhhdL2SyvCfnvkRMXy60epWyDfxiHO7pbmfXdyiro55ZGreLxsdar8F00JcJ8lVfZuvA8NU9a4WAsP2PHiEm3eCOmcMWsqXDPCUaO82j2xFzzTblaAp4JTtGouVFOYiOC6SsMuU7pP/sV6qZsVfHMF17vOSx/Gt0uETpqA27xKk08hH4vQABCqg4DI1ouda/g3x6fCIfi5C5aUZyrJsq5zL2bk71LFEWramKMxrHuW96yT3MdDVEZ5q0QieAn5/lC5rDwmgObEsEtELanVF85mZO42GcwghMtxEoFDfn5b2lLjDdPQOZg6j7L0g8QpqFfDiHa1lEVtOqzKba/GGJKgOUDEz1sLbjIBPlk+RUzQl8yJOAZEDKIlCYgXtLkhvJKqnlYRraXPnVEIz0sekTsgizI5leh5dgqzT5trstjjdArrQZRFWE9NChfg7R/RpmCtekYr4gFbo1SQBgJGJgg1DEfUQFW5BKcUyrl452uk+zTGmW3oN6pYy4/61zEJVjIJ5rz7eKmRI1pU0MKn+9G1+hSr21G2zrIn6TZPccxsIyIhQPrm6zkq71FEgBITQPHeRvSCYdZm0MC+zbplCOX6R1vWguNnWfKcxRjXf7tcRBBLIXu/9p5/cE3JFRj5ZKDp2rC2K9TVwiITDBjn5l0dZLjz37XoaUAQeGo6LvnkVMbvzLzg9YkFMjbfWzyHSYcczH/7rnpmIAeAQNYo6RgbRPYwf4R/fPcKxLrMo1Cw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(4636009)(366004)(136003)(396003)(346002)(376002)(39860400002)(451199015)(86362001)(26005)(316002)(71200400001)(6512007)(186003)(5660300002)(478600001)(6486002)(966005)(2616005)(7416002)(64756008)(91956017)(41300700001)(54906003)(6916009)(66446008)(4326008)(66476007)(66556008)(66946007)(76116006)(8936002)(83380400001)(36756003)(38070700005)(85182001)(8676002)(6506007)(38100700002)(122000001)(2906002)(99106002)(505234007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?b1U2Y21sOE0veHVJRE1kUnZaTkFoYmNIbExsSER3ajB2VXRCMkF0MURKMyto?=
 =?utf-8?B?bmpDdnFsLzFMTGtJSXpqTmthLzFYRzFBU3Ewa1c4TDFMQkNuL1NBaTdRVXhV?=
 =?utf-8?B?OGxKZzlxM0VLc3haUDBRT0dFQTlWNnQyd0hRMi9Kd20zQUpGVlorK24reHNK?=
 =?utf-8?B?aUhhN1NaeTh4S0xLT2JRSnBMM1NnMVRnNDRmREpDZFNwTFUvVUtFN3ppMnlU?=
 =?utf-8?B?QVRyL3ZXdENYSGJIZ3hWZVlRU1hqVTJqN2xQUUF3WGR4Mm8rWGVsVkZUdW04?=
 =?utf-8?B?KzE2VnkvY0ViT3gwcmFmTXpRM3lsTWREcWtabGdsb0JOUG9Ib0twTHR1aU16?=
 =?utf-8?B?c3J3S1BaV2E0aWNzNlM0OXBCTFhGNWRuUHRZNlk1OFhZRnZuNzJkUlZYdTdl?=
 =?utf-8?B?RmdncVk4ODV0RWxhMHBxVVZjeWs5eWhOWkpiNzJYQXJTbFd3bk8xM0ZUR2ND?=
 =?utf-8?B?cHhwT2pLVGlBVE9sa1lKTGFId0E5Q1JzQVlsUEhuWC9kcS9tVmZjZDU1NHhV?=
 =?utf-8?B?NlkrRDZWY3VoQlVZLzNwdzlBb3NGa0RGU0gyMjZxOWl2dG13YS9XOTRKTU80?=
 =?utf-8?B?TmZnUzM1QWErSkFrWkhKVEdtai9qR3hsbGJLS0RtSVRrczVjUTFwQ2p2OGEx?=
 =?utf-8?B?eC90cnJuVG5RZ2dORFo2VnJhTmxJR2NWcnIyM3ZLdHN0dndWVUorU2dvWVBH?=
 =?utf-8?B?SmlBU1p6ZkR2cGRuNFFjNEFqZDZ0VFBQNGZWU3BrdlpqcGplSTI1Nnd0cHVx?=
 =?utf-8?B?QlRPYVJXY29TNmZUWDk5TFoxaFRFeTJEcllWdEZWR1ZMSFdsK3RzL0IxUy96?=
 =?utf-8?B?cnFFblFrVXdHVmcrZHlGOHdPcEtuSURyVkE1US9MUFp3dkk3ZnZKUG1mdjNu?=
 =?utf-8?B?MjdTVkxnRDBCSmNhenpJeEN0bUUyQ25yZTFSMm1UbWJvNFo3b0NUSGtrbHNL?=
 =?utf-8?B?ME9XZFluRXdkaGRWek9kUUF5eWFqTE4wMkdPeFhsRTVmZVhaSjN2MzRrRzBi?=
 =?utf-8?B?blN3YktSUWtjUnJxRGhZVzVweVk4VWFXcHlBUXhtelAvS0dneUFGNXM3ei95?=
 =?utf-8?B?UWdiNmhNY0NzSWxJTzlJdlhGSk1YZW15cDlWUG5WMnlkT3FpZmNKYzV6dVdk?=
 =?utf-8?B?TFRZVTYyU2V6Yk5jVU92aWU2dVFUMlJaMm9lajd4WlY4Zmk4cGlSS1BML09C?=
 =?utf-8?B?NUxKYjNhMXZFdjBlci8vaGluZGtiQTBoV09nZUpSYU1CTFdJazBJSVJDK1lt?=
 =?utf-8?B?bnpXQ2NWMndsYXJCVy9KWTEyOSttaG5ZakI5bE5IYXgzMklLdERQNEZmU1lZ?=
 =?utf-8?B?TTc4dE13azNHcUdUVEtJQ1hFNlQ5NnVaRWtOTUhPZ3lsQlpoZ21WbDlYUVVO?=
 =?utf-8?B?OXB0ak13dWkrTDlJODZRYXIraDFXRDNiSXVGZEZ1SlNoaURLcEJSV3o5bWw1?=
 =?utf-8?B?Q1Q3UzM2MkJLM1ZhVURTVTdPRVB3cldEQ2hGajBkdFhmRGVkdk5SenJLRVll?=
 =?utf-8?B?Sm1DRGNST3BGOEh4dWNBMVd5R0lyQzJtN3NKTWFEMlRRRXJHMExLcU9id24y?=
 =?utf-8?B?N0N2YWswa1FhQWNFTElSYUhKRFNDemllbmRQMXFkUDg4VUN6bytDRHQ4MElJ?=
 =?utf-8?B?ckRuK25BaWlKU1NSMlpGNHJTcDFobWNvLzZHMEdraW1UMXBiK0JwS0xqd3hF?=
 =?utf-8?B?L0taNys1a29wL1NRUWRwVHdybGJSRmtxYURRemNyZ3BCNTZPYlp6cDdsd04x?=
 =?utf-8?B?OUtVMFMwNWNyQ3A4SFhUNHJxRXJ4QnJlVUNjMS9ZMXNSeW5nNlEwNmwzV2Vs?=
 =?utf-8?B?TGZ6bE14b0dYN2FyVVdtdnJ5b0dnTHpmbHdHNUpITlA1UUFrVWREejZ6U3or?=
 =?utf-8?B?ejR1QTdLZTdtaGN3ZXVxZmQ3VHUyVFA0NGVHS2tDdnk2ZEE4Vm42bGZnLzJn?=
 =?utf-8?B?N2hMaU9TOWUrbGRzS0ViOENWNmF2L3YrUVpzYW1XN2VLSnkzR011YVRWM2xB?=
 =?utf-8?B?azVDMEppdG50VG0wclBaYitTL1NDZ2hJTGFpRU9CcllVb2tXeG90TXM4R09y?=
 =?utf-8?B?VmFQZmhjUTU2cnkyU0dicUZ1djVWaTU2Y0ZSUk10TEtmUkJoN3VqSGRJYWVk?=
 =?utf-8?B?bkd4Nlh1SkpVYzh0aDd2WjVoaWQ2M29oeWx5bkx6dWFKUFNQOS9oYnNHT2F6?=
 =?utf-8?B?R1E9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <FBBFFEA46E45FB46BC35692726A2FB98@apcprd03.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 500a0f8a-d4af-4bff-f3ba-08daf53c0d36
X-MS-Exchange-CrossTenant-originalarrivaltime: 13 Jan 2023 07:59:09.4269
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 1ATO185TH+PM7+Ac224CxxnK9o1JFUQwUsl322ZWXfORfKQNDxLdPJS1tnhDGGhUa1FgnDmFyq7+Rs/5nqOAvrRdu8CwcWjfj72rGGH63QQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR03MB5856
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=k5y3S1zv;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b=a8pw4MOX;       arc=pass (i=1 spf=pass spfdomain=mediatek.com
 dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates
 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
Reply-To: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
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

On Mon, 2023-01-09 at 07:51 +0100, Dmitry Vyukov wrote:
> On Tue, 3 Jan 2023 at 08:56, 'Kuan-Ying Lee' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > 
> > We scan the shadow memory to infer the requested size instead of
> > printing cache->object_size directly.
> > 
> > This patch will fix the confusing generic kasan report like below.
> > [1]
> > Report shows "cache kmalloc-192 of size 192", but user
> > actually kmalloc(184).
> > 
> > ==================================================================
> > BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160
> > lib/find_bit.c:109
> > Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> > ...
> > The buggy address belongs to the object at ffff888017576600
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 184 bytes inside of
> >  192-byte region [ffff888017576600, ffff8880175766c0)
> > ...
> > Memory state around the buggy address:
> >  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> >  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
> > 
> >                                         ^
> >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > ==================================================================
> > 
> > After this patch, report will show "cache kmalloc-192 of size 184".
> > 
> > Link: 
> > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=216457__;!!CTRNKA9wMg0ARbw!mLNcuZ83c39d0Xkut-WMY3CcvZcAYDuLCmv4mu7IAldw4_n4i6XvX8GORBfjOadWxOa6d-ODQdx6ZCSvB2g13Q$
> > $   [1]
> > 
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > ---
> >  mm/kasan/kasan.h          |  5 +++++
> >  mm/kasan/report.c         |  3 ++-
> >  mm/kasan/report_generic.c | 18 ++++++++++++++++++
> >  3 files changed, 25 insertions(+), 1 deletion(-)
> > 
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 32413f22aa82..7bb627d21580 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -340,8 +340,13 @@ static inline void
> > kasan_print_address_stack_frame(const void *addr) { }
> > 
> >  #ifdef CONFIG_KASAN_GENERIC
> >  void kasan_print_aux_stacks(struct kmem_cache *cache, const void
> > *object);
> > +int kasan_get_alloc_size(void *object_addr, struct kmem_cache
> > *cache);
> >  #else
> >  static inline void kasan_print_aux_stacks(struct kmem_cache
> > *cache, const void *object) { }
> > +static inline int kasan_get_alloc_size(void *object_addr, struct
> > kmem_cache *cache)
> > +{
> > +       return cache->object_size;
> > +}
> >  #endif
> > 
> >  bool kasan_report(unsigned long addr, size_t size,
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 1d02757e90a3..6de454bb2cad 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -236,12 +236,13 @@ static void describe_object_addr(const void
> > *addr, struct kmem_cache *cache,
> >  {
> >         unsigned long access_addr = (unsigned long)addr;
> >         unsigned long object_addr = (unsigned long)object;
> > +       int real_size = kasan_get_alloc_size((void *)object_addr,
> > cache);
> >         const char *rel_type;
> >         int rel_bytes;
> > 
> >         pr_err("The buggy address belongs to the object at %px\n"
> >                " which belongs to the cache %s of size %d\n",
> > -               object, cache->name, cache->object_size);
> > +               object, cache->name, real_size);
> > 
> >         if (access_addr < object_addr) {
> >                 rel_type = "to the left";
> > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > index 043c94b04605..01b38e459352 100644
> > --- a/mm/kasan/report_generic.c
> > +++ b/mm/kasan/report_generic.c
> > @@ -43,6 +43,24 @@ void *kasan_find_first_bad_addr(void *addr,
> > size_t size)
> >         return p;
> >  }
> > 
> > +int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
> > +{
> > +       int size = 0;
> > +       u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
> > +
> > +       while (size < cache->object_size) {
> > +               if (*shadow == 0)
> > +                       size += KASAN_GRANULE_SIZE;
> > +               else if (*shadow >= 1 && *shadow <=
> > KASAN_GRANULE_SIZE - 1)
> > +                       size += *shadow;
> > +               else
> > +                       return size;
> > +               shadow++;
> 
> This only works for out-of-bounds reports, but I don't see any checks
> for report type. Won't this break reporting for all other report
> types?
> 

I think it won't break reporting for other report types.
This function is only called by slab OOB and UAF.

> I would also print the cache name anyway. Sometimes reports are
> perplexing and/or this logic may return a wrong result for some
> reason. The total object size may be useful to understand harder
> cases.
> 

Ok. I will keep the cache name and the total object_size.

> > +       }
> > +
> > +       return cache->object_size;
> > +}
> > +
> >  static const char *get_shadow_bug_type(struct kasan_report_info
> > *info)
> >  {
> >         const char *bug_type = "unknown-crash";

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel%40mediatek.com.
