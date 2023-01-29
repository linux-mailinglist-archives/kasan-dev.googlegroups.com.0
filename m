Return-Path: <kasan-dev+bncBDY7XDHKR4OBB3NL26PAMGQEY2KMBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A841C67FC47
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Jan 2023 03:11:59 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id c75-20020a621c4e000000b00592501ac524sf3332202pfc.6
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 18:11:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1674958318; cv=pass;
        d=google.com; s=arc-20160816;
        b=o9HeBBkNq/hcMnDvhdyNVi73eiP1Zi/jDy5iSNLoYFRmf+4zpJNRbqtiZlQEUBO9fs
         FFBeibobqrfcd8T1JUYUuYObJH6b/xvmkqXDN9dYsT4mDC6tj2nnU5dNrXV329E/1CmE
         dxZkK4BG6ZcY38AQRCTM48ZcRxyr4NW49Fml6JjgQZw/ix3NPSQAv/Zgfyn3mRcYYZp1
         o0u8RTtkWrHFHtqfeNyPMWytCi6mWQddBKqvRWEqV+LXV7JpNQHLjvqnQd6hJxUoDv1s
         o3scq3ugmKTAAjQcR0q+/tYShXo9jxT/ZQE9tCAdOIX2wk8jROaSDV+yxyG413g3oqHt
         Hn3g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=E5EXADThAzBw+e8qBMiPOKjsZ1YQIEZ+WCZT3ssEXMY=;
        b=x1bLDHZ7NOK9QTrLQV51fk+n1iheOjx1nbcOAQXF4EX297c2pqQuViBXOiHoBKKYGT
         FQdHPpsuXZNpcYH292iBonyTogOn40638mI8pdcoEhJUvlC3qJP/Z49XgehzLCA5Oavf
         wQEuXb3XgnQAKZZrWhPstSdRx63rFCr5G08FsIoC9rQLSUgi/niA1kdgLmHq7Aj2zaLR
         ifPBHKoio/PjEA4/UAs6dlH4W2X0/kmIH4jzXg0IEoARmbSxUrxNt5drGXz9a0w6yMbQ
         aEejIp4rxANKrg87KodMShV0+J+fXT9cCJqlybok8PMsx6JF43mN7KwaEtx/oErfNXBp
         WQzg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=TZbPYm4i;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=trl6IIXP;
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
        bh=E5EXADThAzBw+e8qBMiPOKjsZ1YQIEZ+WCZT3ssEXMY=;
        b=qbW/d7kUwgWbRz68WxZhKaqAPblIRXRIoIFwp7Ce/QNTpyZ2JQAb4yTm/8Lo5ajLEK
         cjEx8kQ8MUq0AW8QD42uANqsFvwOK8Z/f9rZ72nvxXz3bzzgYGLvYwkqprNR8XdkfceE
         1LIUvrUdYO4jqSRKUjDYrZ5YkZAAm9D5TeUzl3yFr8qx9tLZUomwGiZrDCtUarIkK0Ce
         qvvBbRXc/xgun4S1CGKEBghIMCb54XbPgz0re5Pgpm1Cte4oZnTAOPkZCTA8nySlRfyq
         CNNQUQ/COp/KzDJ+QG6x91BYQufIatmuJlEkbLNLBKHIbDxmcNt2J2+BFPM1eMaAlpSU
         8Dog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E5EXADThAzBw+e8qBMiPOKjsZ1YQIEZ+WCZT3ssEXMY=;
        b=DkmD65H7CBxXK+fnXsohkdjxl8i0pekDp9ROJr5WEUb6+0FmD27Vx5iSIHozq56+3c
         9UACmi/WZ67HeGrWVHR3yGWhLaeAyJbiB9021ghBIyi0CfFOrOpUzVbkrgNZ1tIV4ttk
         PEsnigoEVzjk9EGJKKJIZj+IxyGqAzpAZQ8atF86XxhhQyXOI5jowMFLL+LogD//ZC88
         ZLpjJuVVKXgpAdEwqWSbYjIiE419OdyZr2Fal1yCxIBBw+7+VZrQL4XbF7ycqjnJvrlc
         is+EyPzgKQyK0/EgA7S5KZpAlir9ZUpjkJVm7AQK2VPPvGeGIGR0ma5DyGi4SeG/sA13
         cxDw==
X-Gm-Message-State: AO0yUKVf9vGMtbCdKdQHNlrr+nUy1sZQg33FDOnUmRIQF46hnoj5YCQL
	6RXAF2qblzN62Fx7mrdf/QI=
X-Google-Smtp-Source: AK7set/quFl7Jd668NNZArh4n6VVni6KPUJLZOXaWZ669gwAHfRqBpjjABlBcYGHZCg9rs6HLtDDTw==
X-Received: by 2002:aa7:8807:0:b0:590:762f:58bc with SMTP id c7-20020aa78807000000b00590762f58bcmr1901130pfo.50.1674958317767;
        Sat, 28 Jan 2023 18:11:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d3c4:b0:22c:7ea6:5e91 with SMTP id
 d4-20020a17090ad3c400b0022c7ea65e91ls1271231pjw.3.-pod-control-gmail; Sat, 28
 Jan 2023 18:11:57 -0800 (PST)
X-Received: by 2002:a17:90a:30d:b0:229:f58a:9f65 with SMTP id 13-20020a17090a030d00b00229f58a9f65mr35970188pje.2.1674958316954;
        Sat, 28 Jan 2023 18:11:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674958316; cv=pass;
        d=google.com; s=arc-20160816;
        b=0njmyG3Ik1lf5Q1Nl3WMXxZG6GupkgybTK7xnBE3i55vEdl+fqnDI/oBH/WiGlKFJt
         hiA7sKBCSXJhbXPLOpu8ba3FQ/CAGChsUaqUTtjW2LLCCinXO1AIHv6eK28AdgEeup8t
         g4A2+8xWrxi09a/Ws+h1gwSfZKIYHLCkkdofhChpLV/ys2ZJIPcVoyyXGwVKehQK8kTU
         h/j8kkxuTank9nabH21yv50YYFqDZbkpBjs5bNOQ2VbXJdL9+sRnkzPDZxDCYJTCZ4kW
         x9wlvw8hetIKUyeCPY3oUIGeU3hig5AKiGU1++dNix6fU6y8N16DUuUl70ZrxpCEAZU0
         6qTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=30SSnO7qx6MnN6mfmHxwzljdfVMCUCxClCM7lh0+rJY=;
        b=fcd8z69pZgPYjcyNUASt8hx2Uk8jU6lf4n+i8DC0X3Yoi3Ldq0tlRtlnnFs88dcNWC
         tDCoeWIAPdTBkTowDAx2s4jcyOIGS7MKSZJWKItP0CQ1kcPD50DSqzTtnwOS6vep3tgY
         WNI2NOrAF52VtAC7wAJ4TXkAhzW8oiIGQgSZYVRHvAqVYp93ajqUaxlNXNayZoWWh5pO
         l7kg3+GgY5a9lQ96YW3Ten8W6FVr9P2uQsdK4Lc1M7WYDnzuALGDeH6HyBX9p8yLrqNH
         l7FWNZCEkwVxLlwrVH9HTXAWWd2ZdKbgQGmaWYJNx7CFkPIxiqY/XzyT4SAgm7qk7NAI
         +00w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=TZbPYm4i;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=trl6IIXP;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id m13-20020a17090aab0d00b00213290fa218si461952pjq.2.2023.01.28.18.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Jan 2023 18:11:56 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4c30472e9f7a11ed945fc101203acc17-20230129
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:069314ab-76e2-4145-81aa-6741b4eb7a54,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:589acaf6-ff42-4fb0-b929-626456a83c14,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0,NGT
X-UUID: 4c30472e9f7a11ed945fc101203acc17-20230129
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 415328906; Sun, 29 Jan 2023 10:11:53 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Sun, 29 Jan 2023 10:11:51 +0800
Received: from APC01-PSA-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n1.mediatek.com (172.21.101.34) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Sun, 29 Jan 2023 10:11:51 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=mKWOTLOrt9ZHyBOSJ8XANP3X68TlonPsMHpFPjxBkS6D9R7oMU9n/ZWA4ooppr5yJSUhhXnudQbgjC0db66WwzlEpu/PrIF18A9sqC8V5FpywoKHW8KS0LFIqcVCepvz7I2+EOozXcTQrh6LC5Ciupzc5w+YnlV9OH2rfjz19CVUwd5dsdQvKzvn2vmxU9nJTB/bqDrSzg6kp2snq5xoMCsuwfbr5+JK8m/EIwg5+/WI5TtT/a20O3m5mghCZrHvrxVEKiXKhnTbECrVgOv658A/LEhq4upXBqZmhDhY2eQCMvGDawbyjqhA6kmMpKSoqHv1EBIgl/T28ZaPX/fC3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=30SSnO7qx6MnN6mfmHxwzljdfVMCUCxClCM7lh0+rJY=;
 b=T8NNZizi/cEtOYOqRroVfVadS3E0DMZZTzIiIrRNXSyEvhDRkTFYiXmLLCwzqnYSfYYylBsSD2lTE1a8LRVoOjMojqfeek7rPvSHkUf9KSBLLDcpbM/HCnylzJHvXQ4slo2lXgR2m+K8V/DhOD1kVczaYuwrm0TEWNYCa54Y6YwUTjqY6iVPSfYSnMjGtHdjQBxkRb9afV/55zGD75OHZp0h7bVus4nEyRes9atIdpIF/1M0RarS8ZDVYronWkKpM1aJLL4rId6WwkC+ux8ecHxupAt3YwMGumKVzmx+VXXHnLjts82qeKHUdrnsUjY/7xSoZ6rgODgXqv1C2ip4lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by TYZPR03MB6469.apcprd03.prod.outlook.com (2603:1096:400:1cb::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6043.30; Sun, 29 Jan
 2023 02:11:49 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%5]) with mapi id 15.20.6043.031; Sun, 29 Jan 2023
 02:11:49 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>
CC: "andreyknvl@google.com" <andreyknvl@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	=?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	=?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "glider@google.com" <glider@google.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Subject: Re: [PATCH v3] kasan: infer allocation size by scanning metadata
Thread-Topic: [PATCH v3] kasan: infer allocation size by scanning metadata
Thread-Index: AQHZMylWg6CakGr5YUCWiMoGh+lg9660a+mAgAA72gA=
Date: Sun, 29 Jan 2023 02:11:49 +0000
Message-ID: <60c63554d2acef7b93d589909f0df5f89d2deb45.camel@mediatek.com>
References: <20230128150025.14491-1-Kuan-Ying.Lee@mediatek.com>
	 <CA+fCnZdSvTR=Ug3P9ZVxq9AG9Dh+TqLxDMRVOhvE8Sr1a2Oq4w@mail.gmail.com>
In-Reply-To: <CA+fCnZdSvTR=Ug3P9ZVxq9AG9Dh+TqLxDMRVOhvE8Sr1a2Oq4w@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|TYZPR03MB6469:EE_
x-ms-office365-filtering-correlation-id: f9cb0e14-d616-4201-8d2d-08db019e2e5b
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: Ff6C0AgDvmNa2MeRZy0/rQnO3VXZokh55/pkVrXGry27D6AZVPRtLOhHu6Ntzo1jTWjD9WNwnCZ6TaAX8zXMCSVHkRaiq0FpxbA1cAGbs+c5IwdXr6iIe5Z2RfnG/6WTGfxKb6+7pic10gP1T4ysaAXOMZCwtik43bOz6wgKeJqnsvIpvzohUW5DbrjIxgrw3skoLby+PxW7mnys51EVH9sP3fgIY5IfpqMImUBaZgsyU1873wm4ZNURR+b/GRhqtVSxdpIkNypJKbWbtdLYWlyNw1WtTLqZx6WCRynW1VIOJOHPvD7NfrHi+J9gLPvq8q9ZQ0wQDMB5gu4HOPMxsw4FTVAYpMO/5QMBqMnbZS5ePOem/zA2abMbSBo1LFz0paX9QLnfAJ0PyT6jiB/vq+pA0H13ZPVXo+sayVq+37OBdG3NxUDTzu0Wl61VtDVJh8byWZZKYJWl+ceKLBuymTHZBsQ2+egx/HFcd+TrhVXn8RxZ+kA7Pa6KueiFZ/2P2BGlC6kQc7h3JpJ2eTWbI8E9ifOws1QwQpjp2DaEVTlGIOhPEXACLrwFOmswNmfDBjc6rGCgBnGD/bg95/bGmXp7eXREt/gYWJkZcX1UsrMZr89ePC3P4jyRMsQ9RDLvctcRuO5E828ryAyNZHXs+Nr2KuqTMz+WEtmFfO3bjIVc1Pq1hdFhKIScrkVtsmZr7mMsTBS0hscv96jd/UlNnAlD/NvSjDbGDr77SHs4KMqk98WY6/XR7z3tEpx+pg2XtKXJkPoH1F5Jgt5WsqaYfSkJBmaFXVJfXP8inFgy12o=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(376002)(136003)(396003)(366004)(39850400004)(346002)(451199018)(38070700005)(38100700002)(122000001)(86362001)(85182001)(36756003)(2906002)(41300700001)(71200400001)(54906003)(478600001)(6486002)(966005)(7416002)(8936002)(5660300002)(66556008)(316002)(64756008)(8676002)(66946007)(66476007)(76116006)(6916009)(4326008)(91956017)(66446008)(83380400001)(6512007)(186003)(26005)(6506007)(2616005)(99106002)(505234007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?UGg0amlVSWZaZ2w4R01Ed3hCREh6M0xpTm5EMEVoMDBOOUpSUUFJQjR0a3Rn?=
 =?utf-8?B?VEswa1gyMnRVWW5rY2VLc1lKdmYyeUtkNnRmQXkvdWJ6UnBlM1EwbHpJeFNs?=
 =?utf-8?B?UGxwaDAxZHRCV1V0WklyRUhDWXp0TjhnWkllanZVNVVKKzhyV1hNYUtQTTBL?=
 =?utf-8?B?SjgrK1kxNkJza1J1b05UWUVxNER3MTJjNlFNNUNWL3RoZmdQL0gzd1BkWFZJ?=
 =?utf-8?B?aG5QWjN2dDNxWUQvbzJjd3JhL1QxZ2dPZGtIQy8yUDAwa1V5Rlo1bjEwQm93?=
 =?utf-8?B?eE1ZeDlqdi80bVRySjNBcXBsNlE1aUFwZ09XeFIvMTlmaE91UXZrVmVRYnJr?=
 =?utf-8?B?elpWMk4xUWZmSzN1TEpMRGF1cHhvem14L3IrS1Zzc054eTZRVmRwZXd1ai9h?=
 =?utf-8?B?NXorR0g0UDdrSzZ0d1BOdXRxeEpieEt6MUcvREZzWlpBZ3JEODB4bjhxT1Bv?=
 =?utf-8?B?ZndWaTZjVFZ6T1ZReCt0eitMUEpIZ3lTT25ER3NoaDZ4d0FEbEhOVUZyb2Rm?=
 =?utf-8?B?OFNHOU82ckhrZTNROE9FQk1RSU5nQjlwVXFmUk9QZENObUI5bEJJUFFNQzZq?=
 =?utf-8?B?S2lkWkJLYnJGdmFJcTZHUnpaWTJnQTg2QUtFQk5iSEU1SXpjcVAxKzV3QTc5?=
 =?utf-8?B?WGZIcjlnTE9GeWdpZCtzcTRaakZPSWVJNmVkdGZWVGx6M0FNb0NNZUNOR3FC?=
 =?utf-8?B?NWFXazA1WmJqV2tNLys0bVhqS3JPZDdtNFI0MEdKdGNwMzMvL1pGUi9JVDB4?=
 =?utf-8?B?MytpQy9BZ2hUUnpEOWgyOVRSSzNGK2I3bmc5aTI2YU1neUtGcFVmNmNlcGZR?=
 =?utf-8?B?UWhOS3JBejlIZ3Z2RE5jN0lBSEFSQzZCM0xuS3FLajBKcTdyTFVjRHI4S2pz?=
 =?utf-8?B?bUJjelhBQnF1Qk52QVREUHllUEgrK0c2MktIMHdOd01BSlRMMjNreVZNc2Jr?=
 =?utf-8?B?blRtZ095LzQ1dm9KVGJTd0JVNmZKSGRhT2trVENkT0svQVBvV3hZK3puOUNn?=
 =?utf-8?B?VE1mOGhvdUY1YUxMZ1YyTU1MM0ZDSmIxVWZjVU5ub0d4ZkIxZVBJVi9pZWI1?=
 =?utf-8?B?cHh4Sll3SVh0ZzlXSk5mMW56Wk1EeEVoMTBGdWRWVGJYN2M0MzNvV1Zxd1BG?=
 =?utf-8?B?ZkV1WDlhQXdOQkFWNFVBa29qbmhGVFdvYTV1NTlCU2J3NTJhUXpjbHVxN3Ra?=
 =?utf-8?B?NllEcWVPd3E5RFhiUFNPTGFXaGgvekZIMmkwS2VaT0ZTOXkxSlNVQXRUTSt4?=
 =?utf-8?B?VUZ1MVY3bmFRQUh1VnlNUmcyZ1llV25mSzdYTWJmYTNSNm1INzVQMmppaE83?=
 =?utf-8?B?Rzgvd3k4WG9nT01HQlFOcmJoT3dxWWZyZmtsbVQ0cWp0Qk54SGpXZnN0b2lJ?=
 =?utf-8?B?dEwzNHhTazZxdVZabjdYTnlTeUhZZFFVV0liRFRVR0hxZVlOTnRpb3phanlH?=
 =?utf-8?B?aHRJVC9sTlhncWh4dERucTlYK2d2ODYrbk5CTnkvNVFlNVJMWEU5RzBxc3k3?=
 =?utf-8?B?UCtuVFozNmpOTmkreGQrbHJMVnIvODhuWDZLby8xZkRHeHhNQjFSZnJRMXhv?=
 =?utf-8?B?WWtOMjJOS05NdldDRFhMSnVqeU93c3Q2QWRIMVhzck1DY0IvbXE5RkI2a3JW?=
 =?utf-8?B?TUphajR3UHJNN2FzSlhGSXRYajd4VVVCZmxkTGQ1Z0s4Y1JHUXBNQXpNUDZB?=
 =?utf-8?B?SjlVMkhjbzNQckQwY0xhSzJUeFh6ek4xMytEdjNMeFJqT1oxSFRpWG9aT3cw?=
 =?utf-8?B?Z0kwaVNNTzdxakZJRnhxM2xUNUdIbDFma3BjVEVubDI3NVZYb0J4N1Rka084?=
 =?utf-8?B?Nk9JVDdPS0NjU0ZDVm1DL2wvUlVqNzd2YTJNd0lHVG1uMGJyV3ZnQStuNnFv?=
 =?utf-8?B?SFN1dFY2aVRyQzVPRWg2NjJpczZOa1k0cVJUNjErT0VDQ1ZCRVJGVDZRQWw5?=
 =?utf-8?B?RXpyam8yMGNvTENuTkROcFZ3UzVNNE0zaTJDYi9aQlQrRGZzRzAwbm4ySExq?=
 =?utf-8?B?NzB3MTVObEpBb0FRMGdxTWlxWisxOGY5NkhybmQ1amdQR1ZPYXZ6K25kZzhF?=
 =?utf-8?B?MVgzMGNKK1lXbzNpTU5YZGdMSU9TeWR5TldmWkNKcU84SUxNUWdMR1pGdkFE?=
 =?utf-8?B?OVUyeG1jbEMxZ3lGL09nQXE0WmZhM2VsaFFQalAzdHoyc3k0bWRpZlBaL1NT?=
 =?utf-8?B?Mnc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <F0E6E644C662FB4B82B82CBD2FC2B8E1@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f9cb0e14-d616-4201-8d2d-08db019e2e5b
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Jan 2023 02:11:49.7113
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: m+FqJODXFznoE/KQL0WC0fspEzgno0zAjDCfB35q94dtQ7vftMQQUpuz9q2XE0rHO3zvXyG2zSkb7AcTUiU0PJ8LHhxiPg32avVrarN0zrM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR03MB6469
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=TZbPYm4i;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b=trl6IIXP;       arc=pass (i=1 spf=pass spfdomain=mediatek.com
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

On Sat, 2023-01-28 at 23:37 +0100, Andrey Konovalov wrote:
> /On Sat, Jan 28, 2023 at 4:00 PM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >=20
> > From: Andrey Konovalov <andreyknvl@google.com>
>=20
> Ah, I think you need to reset the commit author before sending, so
> that the patch gets recorded as authored by you.

Got it.
Will do in v4.

> > Make KASAN scan metadata to infer the requested allocation size
> > instead of
> > printing cache->object_size.
> >=20
> > This patch fixes confusing slab-out-of-bounds reports as reported
> > in:
> >=20
> >=20
https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=3D2=
16457__;!!CTRNKA9wMg0ARbw!mXW4Z05dX9YXnBYWxw-OOBYutqBM0JFoaApK61lFCSldptsVi=
0JEtWNSU9uaSnXbGq5oiKCBfyHLFFtEmY5uFgDl$=C2=A0
> > =20
> >=20
> > As an example of the confusing behavior, the report below hints
> > that the
> > allocation size was 192, while the kernel actually called
> > kmalloc(184):
> >=20
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
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
> >=20
> >                                         ^
> >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >=20
> > With this patch, the report shows:
> >=20
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > ...
> > The buggy address belongs to the object at ffff888017576600
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 0 bytes to the right of
> >  allocated 184-byte region [ffff888017576600, ffff8880175766b8)
> > ...
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >=20
> > Also report slab use-after-free bugs as "slab-use-after-free" and
> > print
> > "freed" instead of "allocated" in the report when describing the
> > accessed
> > memory region.
> >=20
> > Also improve the metadata-related comment in
> > kasan_find_first_bad_addr
> > and use addr_has_metadata across KASAN code instead of open-coding
> > KASAN_SHADOW_START checks.
> >=20
> > Link:=20
> > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?id=
=3D216457__;!!CTRNKA9wMg0ARbw!mXW4Z05dX9YXnBYWxw-OOBYutqBM0JFoaApK61lFCSldp=
tsVi0JEtWNSU9uaSnXbGq5oiKCBfyHLFFtEmY5uFgDl$=C2=A0
> > =20
> > Co-developed-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
>=20
> Or change the Co-developed-by/Signed-off-by tags.
>=20
> I don't mind either approach.
>=20
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/60c63554d2acef7b93d589909f0df5f89d2deb45.camel%40mediatek.com.
