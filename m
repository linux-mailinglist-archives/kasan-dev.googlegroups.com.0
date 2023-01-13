Return-Path: <kasan-dev+bncBDY7XDHKR4OBBLGIQSPAMGQEJL6NZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 51AE66692DA
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 10:28:14 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id p15-20020a170902a40f00b00192b2bbb7f8sf14581799plq.14
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 01:28:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1673602092; cv=pass;
        d=google.com; s=arc-20160816;
        b=inj2abtqQwcpeE8Ge3J7fafsHnHOLpQSIYQq44fEaFnSq0sN8909q5g7fF5v1y8bW2
         jWo9386jK2NCoTjvtcckuxlid4XAlQf3VSVaJRqDaMdaNr7dN+7WDzXlZrBI/6FqkGtM
         wE6Y7IZ7R0aCAym/t/zyILoMYw5Q/rmXquxiXP1+B/0XOen0KxvDnhArD8DtTn+UHQJc
         gmdYglaRL0OM07aEr1v9h0Fuk+L+BhUCCkoIB2Pz3WSCRDzXwLQodqzM7MZtACRtbK6f
         2H27fxiLxDEx4ah7Sg8r+ef2W9qUPmtV21qC7yYERm/pd/UCMp2yUCuTq4kIKAvgVlAp
         csUA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=UT6zq6Ua47f5z7MASGa8BDB875X0joFGlUAD5gmynq8=;
        b=mUWwc5QUaBB3uejMG0D29AjS08GXwOL/oDdHzEYSVKv8hCmjs6QZ5hSL34NjhNk5QR
         t6YQK1AyVlYFqCdt3JLX4msdaayE8UDgwbaiHctR15I8UNXj6inXJPDWFiWwKEyRzW3C
         T5dJvDfrKKsJIz2PONvJdYVTvum2ognySn43Zf6I2CcQgRcoOua42+I2+dE3PyGaxirl
         gdlnhouK2TilkeHWyfsqcTzCY61CDaThiXIj7cPUtLe6wbfg7dHW9NjSgFG1GLStsOv8
         RmREY9QgWY67iHsdFYX9KdlRJ16GSzaYOafspax442IKCSzWg2HlAn6O3fwPIfDyp/3Z
         pJsw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=EMWRrwfN;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=BhnONllX;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UT6zq6Ua47f5z7MASGa8BDB875X0joFGlUAD5gmynq8=;
        b=S3IBRXTuI4gTKqOgomUXRT5GLmscjJcVatSIVYtaNc2r8kVqv/TMx8sUpUncBnliQD
         Tm2G7h0vxi2h9vq33/J/Q4nr9/PzMho2EQ6GLNYiXuwJ5aV/523YMHmcKoFJG7g+tv0Z
         tGSoySdQ0BG19YK1R92/NTRiFOulAzVUbdb7xjxKmTs/KIgJ3t23OzZZvWEo54TM10cC
         4kYX4pTfXDshcRz1AXY1T7Cqace32bd6GBiSt+HQHrmPLZl2pZmNWjZ6vXMyiejaSCmM
         rVwh5z280spkfF2Uo+Bcemwf/+6ZTwW/5G9KR7BYLIjXFbwA+kUaMvKp8OpJ0A9ZeI8h
         Go+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UT6zq6Ua47f5z7MASGa8BDB875X0joFGlUAD5gmynq8=;
        b=W4pfMI/aNpo4vqDI50q87wpYL8E02dGEvaErRNlH6fG98UMEEH1fOgHHV94PHjRDB8
         WVAk3dIA082HnAV1PoNJkbbigPVSrxFVPZ8G6i7iNW0QrS8j4KrTTf+3Tux8KlTGZqco
         jBR0uIlxkAmi5ErFiAtdOx/PUaRWlLgZ/lo3vPcTBDPFp6EY7R0TvHP7RIYYd3+LezJf
         HG3aXM0Jtti8UJCn7B4seB/JQmI3YQleMyXOH9HX7NZZX8yRYCMoWyWocAaTX+GF9R+X
         AoGLZ28DydeDA4fOYwaCWpge7VH1+UAbYlSPzM/sRwELmexZMxlXMpXqg1W8/HcidgCy
         FwoQ==
X-Gm-Message-State: AFqh2kqRzegneLLZOyEUwSXWi4dXWrSWmKoETKS0t/vTEZxj45EcOFUf
	QGscguUa7Jka4bPCo8JWN30=
X-Google-Smtp-Source: AMrXdXu0BqGd9Mye6HrTr/UzveWr+nAaxzxuLoA1IP10mCzFrYxrrXssf6Vc0PO5/cc2ui4OlDesLQ==
X-Received: by 2002:a17:90b:811:b0:225:e96b:5080 with SMTP id bk17-20020a17090b081100b00225e96b5080mr6486182pjb.128.1673602092244;
        Fri, 13 Jan 2023 01:28:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b88e:b0:226:caf5:8958 with SMTP id
 o14-20020a17090ab88e00b00226caf58958ls5378655pjr.0.-pod-control-gmail; Fri,
 13 Jan 2023 01:28:11 -0800 (PST)
X-Received: by 2002:a17:902:650e:b0:193:a5b:cd00 with SMTP id b14-20020a170902650e00b001930a5bcd00mr27273339plk.47.1673602091475;
        Fri, 13 Jan 2023 01:28:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673602091; cv=pass;
        d=google.com; s=arc-20160816;
        b=bbioMVZhObUbVAZhxwvoXZl6e9Ofw6hN3LjJqgOUSj5oRVWxOJKLbR5S+V9wr8O/Be
         Rhtsz3xOx+nBZOjQ/JLmrZK4T5VmUNihaPLtSunyNCXS5epDT9POubZlvKWzCtOVbpjq
         zuTal9Mg52eReCMbLmoHobFn95zrqHfGZED9hTdabTljnf7bqhlaVAuM8IwFWMscdyDg
         fuvrEADouQJhYCdMz7ll3rK2/GT9YroDyNx4BlU3SJXwGfjQRFvF++do93oHg8DnzB4g
         gYY1y1XbZnPO4G5KhXHHFZeEjlgD3OHbjb4ImEkcrL4BegrBSU6K8ipXewBqJMxAClhA
         vzbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=sFEHe+7kyac9+TwVlNk8AKjZeqS/JsUGXKztqZOIRxA=;
        b=Fa1bZ+0Xc2mTfbRVB7HNSGahcXj3LUvL177cfrUvw4WdEYXVBqzlI+nf43j1bUTL8e
         QFp0n2TKyw2BoKbM197t8x5H8ZM8ngmw4zjI6UUURjZcKTBoh6MIespe/hSRaZnR6l8o
         rMmENqc1qUjYK2Wj+siSo+vbwDtURK0dHi4/AzzQnqRnGgnUiGYYA8SDghcwrftXmY53
         H+3l+b6H2KhSmlJ9kLko2MwblfN9f5fWPDFL6GW3EWyow5X1nqcigAX1DqFLq/Snh3vp
         UfZdDrs1vtqU+sIFN1bCcMpSN854xhg0jqcLi9RQcHr6/+d/sS8QvCKpdpTuoqfquv0s
         L8nA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=EMWRrwfN;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=BhnONllX;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id d17-20020a170902ced100b00174ea015ef2si1585660plg.5.2023.01.13.01.28.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Jan 2023 01:28:11 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9539e9f0932411ed945fc101203acc17-20230113
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.17,REQID:529db113-c995-4dda-94e2-f9590ca35180,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:543e81c,CLOUDID:22632c8c-8530-4eff-9f77-222cf6e2895b,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0,NGT
X-UUID: 9539e9f0932411ed945fc101203acc17-20230113
Received: from mtkmbs11n2.mediatek.inc [(172.21.101.187)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 518369325; Fri, 13 Jan 2023 17:28:05 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Fri, 13 Jan 2023 17:28:03 +0800
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Fri, 13 Jan 2023 17:28:03 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=kvXS6rIR9IxrSKdBjeb3/psNR7Aw9F7jUYDHjA/LWWZPSHfFBbQ3Ws6BpUQP7jPt6a92jsagFSQmJEZdlkRgUd4KF87zQj28/i+VW8Lo20LpQZflMf2KuWZpRjVmyZunYnWjVK7L1Mbb44X+TEjGxyHnpMwg6BSomnyootXoVfJTGDHyoXqaE5/prducmSG/lPl+UBfq1x08bVjMD2+JJYHtpVSf/PtM7VC4p6vqwnZgXxrkzESFSNB5ZEXSUHQRNvsiIA3sOdfBWqtSUp2VYmdNX6KpNixmABuK1qWQpfHB49scoxQxTSDKE8vGh3UFZfMre4p7wYA9uF1DkvqzWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sFEHe+7kyac9+TwVlNk8AKjZeqS/JsUGXKztqZOIRxA=;
 b=ld1erZm3myWBn2KSyPjxcP/GYytuGBZ5GdmKZiZl6Rswi7d7pn0Jb7og6NrARLk56fj6YjEkVangYDOe68Ti5d2P6wQdrH5O+erMXRT1UGVKWw4GM1pR132EvAII/y86904dLDHOCPy2WOt8Q3VvRpQyxYv/9qZRSGxcTneo2z+5+2JpheJy7H8mwUNG36POaZfH8GUl9UrFgZdTlbskvcky9Lqh72NrYljsUHZUx5g9lZNlPy96swjrTjqFJA62vpoPWka98kQUC2ZzGJi9AIBWzKUH+BYfntF3zNLesSuRrBkIjYRZi4TMvDM/d3L6qDmtg+/Lyce7m7YUgE1NUQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by TYZPR03MB5711.apcprd03.prod.outlook.com (2603:1096:400:74::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5986.18; Fri, 13 Jan
 2023 09:28:01 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%9]) with mapi id 15.20.6002.012; Fri, 13 Jan 2023
 09:28:01 +0000
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
Thread-Index: AQHZH0jgINbB3ihm8EOrOsTiVH1z6q6VruoAgAZcVwCAAADLAIAAGAoA
Date: Fri, 13 Jan 2023 09:28:01 +0000
Message-ID: <1804519e5b05793f2c121c407b3633c4bd8e67be.camel@mediatek.com>
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
	 <CACT4Y+b5hbCod=Gj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA@mail.gmail.com>
	 <edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel@mediatek.com>
	 <CACT4Y+Yx+8tjTvE5oR3qzHa4oMoPoj=+BTgcFZHA8jwxgtp1Pg@mail.gmail.com>
In-Reply-To: <CACT4Y+Yx+8tjTvE5oR3qzHa4oMoPoj=+BTgcFZHA8jwxgtp1Pg@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|TYZPR03MB5711:EE_
x-ms-office365-filtering-correlation-id: 6e6da515-c948-4698-bf53-08daf5487775
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: B9ZyieW1D9P3s/CgOOmJ92w4c/o93wtwqrHoebSo3pXqkZi8UBV1UKAvAu/zOu1YppS07Zw0oLILFzmRaRXd88BsFEuUYt5cueVV/oDKAAyRmrFXM2E5E+uHvplAwvqW8Ry64bJoCJnfpddFhUej918IOTbyfd0fC8hR0E5zSyBAnRxzVnLEtVfN6mN752qlgWI/DuLWa9Zfpp82+BNSZ4z8sQ773vIXej8knJhsxASIBcKzA091ffRxlrl2VH6K6iZES0owOS3axaJOIG7pWWkxCrW0XFnepSpxXsJzcHwL+OFMf1pYNkCbSUYd7i0UrpvIiAyfGnSzIg75hbB03Oys5jnfLa/tCi4aqDPVVQ8PYU5WzivOt2zt4QvklKaOhEzV02tVP4YYxnsFqXgyegMBveXSqdZh9np8q5ewO+EZ1rkp1MqV5h7IRvQUNrY85DukckxcSix+mNxvmYDUF7ZR4vnyX7kofkTOfPdfzy4h1ErJ6+FXqte8BYQbtENKrD1ALh0bXnD8/osPvZEDiZzi7OiZ+5lngwMGIRaJGCJVMpPYdgG1g2RtZtzMGguTNeiabhgjIAP8XsO551bp8CrEZKzO3hS+cELMvgRkTKVOVk03qeJYt4HOU4OfJH9iamPkXrSVcPpUrOUHneIAdUQGH8aXLBfobovKeH0LWSiXtxu/sWTtE30gKm2hyXZQsl1IkgWiKgM5ZjCrucPfQunlk5gJXKioadUrknvnBQsar9Z37+GNaPg/mjgW769iik4mkrqpycKX3OT6Qjrm6Q==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(4636009)(346002)(376002)(366004)(136003)(39860400002)(396003)(451199015)(66899015)(2906002)(54906003)(316002)(5660300002)(8936002)(36756003)(85182001)(86362001)(7416002)(66476007)(41300700001)(122000001)(66946007)(4326008)(64756008)(38070700005)(91956017)(76116006)(66446008)(38100700002)(66556008)(26005)(6916009)(6506007)(8676002)(83380400001)(2616005)(6512007)(71200400001)(186003)(6486002)(966005)(478600001)(99106002)(505234007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?c2FMV2l3dE9qOG51ODUrYURoTjg1RG9WTGJ2QlBYT1p5dGRlM250Wk1UNXB2?=
 =?utf-8?B?TGgrMTRDYmRVZzdYbGwrRWYzOUN0N1MyZ1JtdTlUNjhpbzZXZnBPSjRPUGFY?=
 =?utf-8?B?THJVclhrY2lndE1tZ1o3NEtlVEZGQmhtbS95QVZVVEV2RSttWmJmcDg2WVJ6?=
 =?utf-8?B?WGpIdkpaMkdFNFkwTlVyM1Y2dXNQNC9abDlTU01GRll0L3d2QnFFNjJNVHZw?=
 =?utf-8?B?bXgwV0V5MHg0ZFBpOGxSdk1vYnBVRmRNVmRmY3ZKOVJSOFEyaU9HRFArR3Nw?=
 =?utf-8?B?Q1hnbXM4cjd6L1l5MDlNVWFadkpiVTZxYVhJL3VuZEc2ZlNNb3pBaEk2NGVX?=
 =?utf-8?B?SXVBOTFWMTFTRWFZME4xNUpwb2t1QTh3eHEvYkpYdmZ4V2ZUbDZoTG5IY01G?=
 =?utf-8?B?b2k0ek1xWWVFWlBlUkdLc2NQbmtZOUd5SjNKck9ncWhGWEEySnAyZmtIc01S?=
 =?utf-8?B?bW5jZ2xxd2Uxc05oUmRlVkNpa0FmcHR2ZzV4TlVLVWxOUjZhTXdIZzNYcTBQ?=
 =?utf-8?B?MC9qc2JJVDhia2FJMjNWUlN1RWVXWEMrelFsbGhqR2JPNXBDOTh4YkpEd2Z5?=
 =?utf-8?B?QmQvVUFrY05BSXg0NXJ6cDJ1NjgvbUhPS2lOQXhKSjBQSjU5TXBxWEF4TUpy?=
 =?utf-8?B?WHJQVFUwUkh3T0ZLam5JcFIzU08xTnVaNnZmM2pOaEgzRVpGNXYyUytkSGVv?=
 =?utf-8?B?N3lscnRJWkoyVXlhSHVXb29zcnN4a0o1ZWM2eGJvYlZCSWpYaDVKcTBkZjB6?=
 =?utf-8?B?dDNFZ3VmY1VTUithZnE3cVF4UjZYZENiZXZkNmRxVmJ1VEZkY2hrS0RpMzdn?=
 =?utf-8?B?QVd2RU1meEZSS2d1dzVHa3ZnY2k4VURoa3lyb3dOL0pvNFZ2UmMwNzZpV21k?=
 =?utf-8?B?WHlCdGN5Z0o4TDZ1dlMwYVk3cEdtdDd1cjBqWTVFSkVRY2dKTG9YbEh3d2h5?=
 =?utf-8?B?b1JWVDVEWENLSkZaZ0twSGdGUyt1ZnhpUDFKZENSRlV4dXVBakZMUlhvMlIy?=
 =?utf-8?B?MEhvbjQ2T0F5VVd6aGxHSjJna0xUbmxWLzYrZmUyMjZGbVdJaWRPMFdhMEE0?=
 =?utf-8?B?Tk94ZXZTRlNaVWRZRytybndTOGpRd2ovNjZDK3JkeHFZaG1lcyt6bDFSWFZK?=
 =?utf-8?B?bzNzTE03RmFZL0taZHcwTm9QNjlCYVJWbGgyNVRJNjJGUHpuTzA4Z2ZiMHA2?=
 =?utf-8?B?cFJtT09zaERXK05hKzhNOWkyK2p5MUV3NDZFNHovRUZxT2IyRUQ2NU5nY2I5?=
 =?utf-8?B?OFJXVTY2SnZPdnNYS3pWY1JQSUdoWVFXaW90T1l3MzV2Nzg4Uk11NDl1dUhS?=
 =?utf-8?B?S0UyV2M3andmQitKc25Rd0I2VlJIeFdoUDc5MFpIQ1FmYmZlM016YkZnRlBF?=
 =?utf-8?B?dTY1WGZLZFlXTFNVZzJBZWtRVzZVS3Jyc3RGbWNSU1hCYmNPZHAvYnFLUFFR?=
 =?utf-8?B?WTdNR0Y4eFBtZ1gwd2RXUE1rc3d0cmtGYzM2UEEyQ0ZPazZuWlVBbzZsamJZ?=
 =?utf-8?B?R2FWTU9HMGlxTGlaRHgvUEx0VDRRWm9lQU1YY2ZvT041QTduQ0hsYTN2OW1a?=
 =?utf-8?B?SXV1dk4wNFF6d1p2S2dvSDBRcmRsQm81cGpOZXpWNWlpOVFRSlNHOE5Fd3lX?=
 =?utf-8?B?ZEd0bDkzN0N3WmdPY3JDemdaVnhKTVhuM2Z6YzRFWHhRRTIvckg5RE41TlhI?=
 =?utf-8?B?b2lHMzBIQmNMc3NzTFVFbGU1VTlTdHE0WThpazRkcGZKcUdxYk9UaFZnTEc1?=
 =?utf-8?B?VXl0TjVodUNRNUYvUG41Q1A0eERpVkppa3lWNmVoWCtEVnkwSjNTUU83UXRa?=
 =?utf-8?B?QWpOMkFrbFJ3RTdRWDlqeXpxVlc4Yi80WW1MdFZUNzdGK0N5aDBxaUtzYVdC?=
 =?utf-8?B?VlN6UituU05YZG01UUt1eVlGRWpHcDVaN3M4ZTh5Q0laMjBCWmJZcHYwRklG?=
 =?utf-8?B?ZC9TWkl1MURaUFFlVDY5MjJmVWIwcFpidGttdTI2NyszbVNkbFZTMWEycW1u?=
 =?utf-8?B?Vytjc09wR3J5cFVHWCt3YTZ0a0ovYURpQ21ieHNRbGFxRTd4bUIvaWZtdHZh?=
 =?utf-8?B?QWRzQzJ0S1ZySXV1ZVBQb0I5RytPZDA1dUNNZDNCZDdUV2pWQkcxdWRtb3lm?=
 =?utf-8?B?cW1XaDBiQTNkNGdvNjNUclR2VGxWR2tKcEF2Wko3Mkt5Mzhac2ZHRXNianRC?=
 =?utf-8?B?WXc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <9FB230E3B35AFC4794C9A84E459C4937@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6e6da515-c948-4698-bf53-08daf5487775
X-MS-Exchange-CrossTenant-originalarrivaltime: 13 Jan 2023 09:28:01.6533
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: cIQZS2kLJnSmYbtmTsTzdL1PGg9AV9HBbLW8qJ3h4+MgwXi+O+zDkeswAMro/UAwA3KKiuCKjR0E/EBichAZ4sPFgeGSRgvjauBDkbyQDto=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR03MB5711
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=EMWRrwfN;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b=BhnONllX;       arc=pass (i=1 spf=pass spfdomain=mediatek.com
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

On Fri, 2023-01-13 at 09:01 +0100, Dmitry Vyukov wrote:
> On Fri, 13 Jan 2023 at 08:59, 'Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E=
)' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >=20
> > On Mon, 2023-01-09 at 07:51 +0100, Dmitry Vyukov wrote:
> > > On Tue, 3 Jan 2023 at 08:56, 'Kuan-Ying Lee' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > >=20
> > > > We scan the shadow memory to infer the requested size instead
> > > > of
> > > > printing cache->object_size directly.
> > > >=20
> > > > This patch will fix the confusing generic kasan report like
> > > > below.
> > > > [1]
> > > > Report shows "cache kmalloc-192 of size 192", but user
> > > > actually kmalloc(184).
> > > >=20
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > =3D=3D=3D
> > > > BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160
> > > > lib/find_bit.c:109
> > > > Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> > > > ...
> > > > The buggy address belongs to the object at ffff888017576600
> > > >  which belongs to the cache kmalloc-192 of size 192
> > > > The buggy address is located 184 bytes inside of
> > > >  192-byte region [ffff888017576600, ffff8880175766c0)
> > > > ...
> > > > Memory state around the buggy address:
> > > >  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc
> > > > fc
> > > >  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > > 00
> > > > > ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc
> > > > > fc fc
> > > >=20
> > > >                                         ^
> > > >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > > > fc
> > > >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > > > fc
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > =3D=3D=3D
> > > >=20
> > > > After this patch, report will show "cache kmalloc-192 of size
> > > > 184".
> > > >=20
> > > > Link:
> > > >=20
https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=3D2=
16457__;!!CTRNKA9wMg0ARbw!mLNcuZ83c39d0Xkut-WMY3CcvZcAYDuLCmv4mu7IAldw4_n4i=
6XvX8GORBfjOadWxOa6d-ODQdx6ZCSvB2g13Q$
> > > > $   [1]
> > > >=20
> > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > > ---
> > > >  mm/kasan/kasan.h          |  5 +++++
> > > >  mm/kasan/report.c         |  3 ++-
> > > >  mm/kasan/report_generic.c | 18 ++++++++++++++++++
> > > >  3 files changed, 25 insertions(+), 1 deletion(-)
> > > >=20
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index 32413f22aa82..7bb627d21580 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -340,8 +340,13 @@ static inline void
> > > > kasan_print_address_stack_frame(const void *addr) { }
> > > >=20
> > > >  #ifdef CONFIG_KASAN_GENERIC
> > > >  void kasan_print_aux_stacks(struct kmem_cache *cache, const
> > > > void
> > > > *object);
> > > > +int kasan_get_alloc_size(void *object_addr, struct kmem_cache
> > > > *cache);
> > > >  #else
> > > >  static inline void kasan_print_aux_stacks(struct kmem_cache
> > > > *cache, const void *object) { }
> > > > +static inline int kasan_get_alloc_size(void *object_addr,
> > > > struct
> > > > kmem_cache *cache)
> > > > +{
> > > > +       return cache->object_size;
> > > > +}
> > > >  #endif
> > > >=20
> > > >  bool kasan_report(unsigned long addr, size_t size,
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 1d02757e90a3..6de454bb2cad 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -236,12 +236,13 @@ static void describe_object_addr(const
> > > > void
> > > > *addr, struct kmem_cache *cache,
> > > >  {
> > > >         unsigned long access_addr =3D (unsigned long)addr;
> > > >         unsigned long object_addr =3D (unsigned long)object;
> > > > +       int real_size =3D kasan_get_alloc_size((void
> > > > *)object_addr,
> > > > cache);
> > > >         const char *rel_type;
> > > >         int rel_bytes;
> > > >=20
> > > >         pr_err("The buggy address belongs to the object at
> > > > %px\n"
> > > >                " which belongs to the cache %s of size %d\n",
> > > > -               object, cache->name, cache->object_size);
> > > > +               object, cache->name, real_size);
> > > >=20
> > > >         if (access_addr < object_addr) {
> > > >                 rel_type =3D "to the left";
> > > > diff --git a/mm/kasan/report_generic.c
> > > > b/mm/kasan/report_generic.c
> > > > index 043c94b04605..01b38e459352 100644
> > > > --- a/mm/kasan/report_generic.c
> > > > +++ b/mm/kasan/report_generic.c
> > > > @@ -43,6 +43,24 @@ void *kasan_find_first_bad_addr(void *addr,
> > > > size_t size)
> > > >         return p;
> > > >  }
> > > >=20
> > > > +int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
> > > > +{
> > > > +       int size =3D 0;
> > > > +       u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr);
> > > > +
> > > > +       while (size < cache->object_size) {
> > > > +               if (*shadow =3D=3D 0)
> > > > +                       size +=3D KASAN_GRANULE_SIZE;
> > > > +               else if (*shadow >=3D 1 && *shadow <=3D
> > > > KASAN_GRANULE_SIZE - 1)
> > > > +                       size +=3D *shadow;
> > > > +               else
> > > > +                       return size;
> > > > +               shadow++;
> > >=20
> > > This only works for out-of-bounds reports, but I don't see any
> > > checks
> > > for report type. Won't this break reporting for all other report
> > > types?
> > >=20
> >=20
> > I think it won't break reporting for other report types.
> > This function is only called by slab OOB and UAF.
>=20
> I meant specifically UAF reports.
> During UAF there are no 0s in the object shadow.
>=20

Ok.
I will check the report type in v2.

> > > I would also print the cache name anyway. Sometimes reports are
> > > perplexing and/or this logic may return a wrong result for some
> > > reason. The total object size may be useful to understand harder
> > > cases.
> > >=20
> >=20
> > Ok. I will keep the cache name and the total object_size.
> >=20
> > > > +       }
> > > > +
> > > > +       return cache->object_size;
> > > > +}
> > > > +
> > > >  static const char *get_shadow_bug_type(struct
> > > > kasan_report_info
> > > > *info)
> > > >  {
> > > >         const char *bug_type =3D "unknown-crash";
> >=20
> > --
> > You received this message because you are subscribed to the Google
> > Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it,
> > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit=20
> > https://urldefense.com/v3/__https://groups.google.com/d/msgid/kasan-dev=
/edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel*40mediatek.com__;JQ!!CTRNKA=
9wMg0ARbw!nLk2eBIc9qAXEy50sxxXRS2IRZKY8WSfVt_T3VtaMDrIrRHx31xOy5cTmqZa1py5i=
fu9UiHoqrKmxtnVKcWfJQ$
> > Q$  .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1804519e5b05793f2c121c407b3633c4bd8e67be.camel%40mediatek.com.
