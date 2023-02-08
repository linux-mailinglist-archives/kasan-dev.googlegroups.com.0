Return-Path: <kasan-dev+bncBAABBI7MRSPQMGQEYZ4DD5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 29C1368E7D3
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 06:41:57 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id w9-20020a9d5a89000000b0068bc6c8621esf8628638oth.9
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Feb 2023 21:41:57 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QUIysjgGviAkqvqYMtUxWpXkLmJ1z5gg9+oW9mgtolQ=;
        b=HOMUe8vgj9aoDywyFmrlAUTkna0BcYMOEsvQONbV5W9Uu2nAIrAVhgG+8grZzGt9Z6
         5kzG1a79jSd5TXm3KqLSVKFcd7QU3EumGCWbVSZnJo+s5Vor7GWyRKy9nCPEC4zAY8sd
         AH8roN69lheqehuvqlaELGzdOipeczNBAbR7wPGCMWYa9+H1yqhp0XkftkiYN7HagTUy
         lvYg08CDrhLeNbtJM+9pRNfQMIWAlaG11lpEQSrGrV5jYOppY1qdq0Gq9gvlSAmaQXLd
         qAmGR5R0U+AbKM/wxq0ZvqfMmZLSmt+3zLZo1raCZActcTVgGcW5/0mbCwvRDwcWzzdB
         IqCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QUIysjgGviAkqvqYMtUxWpXkLmJ1z5gg9+oW9mgtolQ=;
        b=SyLfT50xjtRuT5YdLh+t8o/WZ9ntqjYifv27tG5qLGkCtqO8fJOx8BDdiPtn+HYZpm
         ehZAJiKSgvQmo7sr1SXStgFcZVu3Y+6nZvw80kDtkItYlg5WHKQyMDV4UkfkRPd2qz42
         0SC7Z2Q/Kltjy0cy+C51uR3pYVoIjHmgeOcCuNKRn2HsNPo6nLRn+6AN6b0ydVJkCc+I
         48PIF9fpSNPUXq+vNHpx3lXn+kBa5qlUz5EAbiG9qQ/8T48upEEjYLr2Hzom8LLpt2be
         r/tCjcRUS8B/kra8pDfuctoA4dfokrEiFvJe1kT/fKonK6YDpVMhOnjfrqL9fdV0AkUd
         lJaA==
X-Gm-Message-State: AO0yUKVQsfdKrRr6XJEbWMYu6PO79E0b3zG78tlnJCeW276szIyd0lXl
	f04SkLIDO74NayH/RY045fY=
X-Google-Smtp-Source: AK7set+tJSniykZnynThHRV04DQJiZCBN0NmCLQXoi/MGvlj58dyrnoTGfXZdcxu2ANDCPwuE/ppGQ==
X-Received: by 2002:a05:6870:170a:b0:16a:2334:2b52 with SMTP id h10-20020a056870170a00b0016a23342b52mr164728oae.167.1675834915455;
        Tue, 07 Feb 2023 21:41:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f00a:0:b0:36e:b79c:1343 with SMTP id o10-20020acaf00a000000b0036eb79c1343ls5507663oih.7.-pod-prod-gmail;
 Tue, 07 Feb 2023 21:41:55 -0800 (PST)
X-Received: by 2002:a54:4086:0:b0:378:79a4:867 with SMTP id i6-20020a544086000000b0037879a40867mr2464539oii.33.1675834915033;
        Tue, 07 Feb 2023 21:41:55 -0800 (PST)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id q2-20020a0568080a8200b00364bb6b07e9si1043299oij.5.2023.02.07.21.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 Feb 2023 21:41:55 -0800 (PST)
Received-SPF: pass (google.com: domain of qun-wei.lin@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 47ee2a9aa77311eda06fc9ecc4dadd91-20230208
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.19,REQID:5543638b-ea9e-40f0-b813-8d868cc1bc1d,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:885ddb2,CLOUDID:097ea356-dd49-462e-a4be-2143a3ddc739,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0
X-CID-BVR: 0,NGT
X-UUID: 47ee2a9aa77311eda06fc9ecc4dadd91-20230208
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw01.mediatek.com
	(envelope-from <qun-wei.lin@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 122011755; Wed, 08 Feb 2023 13:41:48 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Wed, 8 Feb 2023 13:41:47 +0800
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n1.mediatek.com (172.21.101.34) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Wed, 8 Feb 2023 13:41:47 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=MtIoe5jnAUBsvwg3beuAd7ASSyKuy8MRxaStaE7Qz4aELJhsOpec4G54qxPk1dYe4HyKODNWNcP3Dg+bGMLTxzS0yiDYOxDqbxRwcTmPos0fImU4mNCvqx8uV4CdCvm2V3sJshRea4f5Ed64YsrPkPChNYFyX1gEZfRCDPnWDiHzSKHNdiEQHK/Qf727G3m2i+LdIg94hpW5uZ/zHNVtEU/T+He6rJM1/VIIW/m3IzkiQHXWzTihw+BPnj4chnOyEpkt76RKiE40VZ/nb7pb6NDBzdAhEqtoljITcDDPMK7zM4kWkqpXyC6lPBzrB3t6EwcGcyu5LHi3RU44VcK5oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+siWBfiUXlUJAIfsnyKsteNI/+62zh7/EATNuZoNe9I=;
 b=VYQr2NB7JXFVhVKsM70Mx57ZYCXLM7CY3CA49xNbOMMU7dndDtO4SU+rHO9Xt8y0JVEDUREQYNr8tlfCy2g5pAyM5t8xkFrhhOON/SEDJA1xheDKVd14o4ZEmbt3UeVL9e/N1FSB9odWLkVRF63iLH1Jd15x6mK00oq/GwGfuYRE9buCcYJO3cNjDUcX20SpN/mwb2pWUXj8yLRgHidx4VLngltoKFZGZbE0PZ/+m1O+pNTX5mffIXBnlHXjTAzCapkydc2KtRvg+BXI5D6CYIDZ/stZFaYP3cn3VmaKoHAnE/BofLHnULVBYE/xCj9w9PvdRvXPB/1U6BQHNjl69Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com (2603:1096:301:4e::12)
 by SEYPR03MB7069.apcprd03.prod.outlook.com (2603:1096:101:d6::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6064.31; Wed, 8 Feb
 2023 05:41:46 +0000
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::d95d:2759:fb36:cecb]) by PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::d95d:2759:fb36:cecb%8]) with mapi id 15.20.6064.032; Wed, 8 Feb 2023
 05:41:46 +0000
From: =?UTF-8?B?J1F1bi13ZWkgTGluICjmnpfnvqTltLQpJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	=?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
CC: =?utf-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	=?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "pcc@google.com" <pcc@google.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org"
	<will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Topic: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Index: AQHYfN3UQ2ZS5zhImUiCo/W/1QNefK68k6aAgAB+/YCAAPZ+gIAA7XQAgAcPvAA=
Date: Wed, 8 Feb 2023 05:41:45 +0000
Message-ID: <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
	 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
	 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
	 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
	 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
In-Reply-To: <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PSAPR03MB5542:EE_|SEYPR03MB7069:EE_
x-ms-office365-filtering-correlation-id: 1cd428fe-ad5b-4dcf-1521-08db09972a6a
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: CLVP+AXiZnTB+XlpqDF04COnv7pSKruk0xGWsT1pWuem5g2GMwDJyAqWv5Hb6k09lSR34NngZKOKmGDDojNEtumUpT+VkeeexGnd9EMNJqngqs3olBc1ezKf0xKpJYs/Pvw6B09sm9cLPDlwe2CLsAfxmJ02X+L07KziUxyyXnriP84j3yovvvEiDE+9VkRvhpLEzQFJiyl8V7R1DZ2wTPydteJCbyNF8NKU4BhrTA4Ik1+duAtDN4ids3/U59RzIosM1bve5A6Y859e0YfLGfj7WOaw19G7w1tVafJFPvchiwpAm/bi/sinusrHVVOYKibhDA5GX4tYwOLeAFspScdnlPF86b9QDVTZbF17lJS5IyhLJFAll/wbaZFGWEkW8QVxzpsuu2nDQKq5ljLbKujg4WkreDyyuEfthHiJljiCRZf7FJgH1/JlncqRcWIqY6XIEJVnE1GLGQgvZ/A7BjuLski2xoJfW7BNsdnzTS7UHLj3OGUfsDbA3vhM+HP4JSmBQbJR8hFnUqcAuJGOFrpKcRZQd2Dce+SE+bKKGEpQoy+Y9MWKwBHoZEq6VsQWP77Ckof1ZxasBVkPBV+sc+KEHlFFhj0d+lMmkHaMkskhpnsfl5fPTQVWfa3SkFMuWMOHBklwxYlQ+2TMWYfjsJ6jc+L+OFzHUJ70V+bKSmK4pMTvwJhTps0q1GpdJHjtrcff8UUUHcquLa3vda7NXYIYv6zlDcwclxG2EyAtknU1VMNfC9AAWMaz19RQpvXVdaBwLqZ9rsWaNuVsM1CuH3YAcytGaDrQ+aEX6L0+6vTUQLJKu8Z1bUrvX1VbuU1K
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PSAPR03MB5542.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(136003)(39860400002)(346002)(376002)(366004)(396003)(451199018)(5660300002)(6506007)(86362001)(53546011)(38070700005)(26005)(6512007)(186003)(8936002)(2906002)(8676002)(66946007)(64756008)(66446008)(66556008)(66476007)(91956017)(4326008)(76116006)(122000001)(38100700002)(41300700001)(966005)(316002)(2616005)(478600001)(71200400001)(6486002)(110136005)(54906003)(6636002)(85182001)(36756003)(83380400001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?aHdqcnN1MEJrY1I1MWFGV0grRGJscjFUZFlERkJ3TEJtcUxnZjZ2azZ4ZUpY?=
 =?utf-8?B?T1NyRVpSSlQ0dnZpenFBS3BBcisxVUpPbWJ0U2NoUnR2cXU0MHdlZU9sWjdC?=
 =?utf-8?B?WDJVb0J4RFFHVkZmT21IczlEVUJCS1ZRSkVtZERUZXlxakljazBXSFd4amVE?=
 =?utf-8?B?V0FUK09QUGl3NGxsVlR2UTFoemtUMzNmakxWS1JoaVQ5S2NaSDBSeDUrdWFa?=
 =?utf-8?B?SGw1M1llM1g2RHEzaVpaMjFzUWlCUGY5VlUwRkd4VGx3endyM3dYVXY1QUdZ?=
 =?utf-8?B?endDSU9LZ01iSVp4TnVVdDJhZzNhYmVSWTBVS05UTHo4Q1lvTHQxZE9EOFBy?=
 =?utf-8?B?NUhTSWtUTFZ3bjVIUDhmV2VNUnZQeEJXbVNyd2ZTQTdNQlVxM2YxRHdURkJF?=
 =?utf-8?B?cDdsK1lxSGdOMXhVVUxsRjlqNldlZGZnQStDMjZ2eUxhdkJrc2RsZ1g1RFc3?=
 =?utf-8?B?TldKa0h3YXlYeU5TS0xQRStvemk1SUVUV0VkSVBqTlJUYnF5dTRpeEllZGVr?=
 =?utf-8?B?OTBReERvcmRYT2U0RkVEM2kwV1pQRXpzSU9NcktjR1NLcS9oWHRuTlZUOGh0?=
 =?utf-8?B?Z0h5U1EzQ1l0Njk2NVkzMmg0VmJIek5Mdys3R3JxOWRIM0lTY1d3QTZidE5S?=
 =?utf-8?B?Q0g0Z2JKdnBaSFNGTmgvenRRWis3Q0I5cCswMVdyeXBNZXpROEtsNWRWazlY?=
 =?utf-8?B?NnpRNDJjNG5UQ1FwTys3eXM4Y0pZRmxOVlpRTXpHdXlFSkUrNkQzQU9sbGt4?=
 =?utf-8?B?d0hmU2R0Sys3bXRIU1RyVzhxVW5seVRBbmp5SmY2NWZHNGI3YU9adWw3Nk9S?=
 =?utf-8?B?OEx2RnZjSjZxaytGbjkzTTVVOTlSZWZkeVRST2RKU0lpdHBXbllFRkMxSGhp?=
 =?utf-8?B?bitNWC9Mc01tTjRlZnZlZTY0MGZEMWUwOGN6UDBtNVI3N3dsVkFpRVZjYVVs?=
 =?utf-8?B?UFJydngvR3ZsMzM5bThaWU15TG5tZGRWd2ZBRjJNbGtzdGQ1SXFvaHY4MkQ5?=
 =?utf-8?B?bXA5cFVrMis2alJvZC9oMDZvQkp3SHJQd0hKajYwQy9vVkhXY2IyUHlpbURC?=
 =?utf-8?B?eTl2RG5qdlNPTUsybHl3akp3c3NUaUR0VisvelFKb3ZCUHJTeE12TTM3RWs0?=
 =?utf-8?B?MHNMM1d4K0lCblBDazcyT2hmWDVoWG9hdnIxRWM2THFxQVJiWjNKNnd6VHVl?=
 =?utf-8?B?V1lYYWpvcUZnZCtLOHlaZ2FaalVnR3lMT2VzZ3VyVGdoMDMvREpJQWhHb3lZ?=
 =?utf-8?B?NGt1SzF6amtkbDlMZ3dWRUpQNkJXSEV0QWpQbGthUEtxWGtId2phTDl5cTlQ?=
 =?utf-8?B?NGNKUTU3d2h2TmdhSDdPdlJhRjM1RnlaYnZDRTlZMmhUd2JINVZONm9ETU8y?=
 =?utf-8?B?NFFqVlRZNk84QUlDKy83MXl5YlRtZ0haSFQrckRCOHJuM0tuNVBlVGNqMHZ5?=
 =?utf-8?B?elFNOFE0QnUvMU1hZVdkQ1IwcGM4N2tDajcrdGdyMG9weEpYWDZmY2JtV2ZF?=
 =?utf-8?B?WFBDZGpUNlp5NW0wZnJqZ0dxb0ZnZ1Q0T3preDIrbjNGZllPUDhiV3NSRFo0?=
 =?utf-8?B?ZnJVOFRyVktjVW8xUnJFbTZDSG55V3VhUnFKd2N6M1NybXUyR2hUdWc2K2dQ?=
 =?utf-8?B?YVFlTnJtYWRwdDA4Q3hvZTFDVGlUMEcvT0JsU25ORVhoWWlHbng1TE1BUExl?=
 =?utf-8?B?czFNU0pSclNGNHdqRnUrcHpKcjh2bVFSSDl0bklnOS9aMnR2OEJuRCtNNXEy?=
 =?utf-8?B?SlI0dnhlclptdXJGb0FxeGhOUGFJQnZxWmZMcmpPMnVTalAzSXU1bml4bVBU?=
 =?utf-8?B?S0xlTXlHTHRIT3puRmxxWmJiRmJUNDAzclgwS0ZHZ0Y1OFA1WUFVd1laV1JL?=
 =?utf-8?B?MStScnM4L3N1OWtIV1ZKOStwanN2WXpIWEtkMGVYR1VnbnA5TmNFNkFOWWJz?=
 =?utf-8?B?VGhxUndsRm80OFZiY2F6L2MzOTFEQWt3VjlrUXF6aWN0aWI5RVA4cldyU3Jl?=
 =?utf-8?B?bXJXcmZQZTJLWVRCNVpBcUF6Nm1FOERoMDZrWGRNN1JSZmFzM3Vpc3BuZlhU?=
 =?utf-8?B?blQyYlRCNFQ0L1hIdXJmOWtLZ00xaUJHZHl2bVMvTnRtS2ppaXg0TTFiMm1l?=
 =?utf-8?B?K0I0TjREdG1WUzNaSVNRdWZyK21ZSjhtM205VEJ1aG5pQXpSMkEva2o4UTZT?=
 =?utf-8?B?U1E9PQ==?=
Content-ID: <BBE7741B62EACF48B1F052D0B7E2A1EC@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PSAPR03MB5542.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1cd428fe-ad5b-4dcf-1521-08db09972a6a
X-MS-Exchange-CrossTenant-originalarrivaltime: 08 Feb 2023 05:41:45.8739
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Zjj7wygJjrog2ZZEgso+O4Ln8EZuzo9sbyLwr8ecM9s6eAo3gKIv08NH2UJ4Kd82G2mQjQ5dPOWiXfCN3FAebFaOVDDYlTfgxeL8bPhUpbQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SEYPR03MB7069
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_003_2123684117.2004379187"
X-Original-Sender: qun-wei.lin@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=YRwUU4F0;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=IFsvxp7u;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 qun-wei.lin@mediatek.com designates 60.244.123.138 as permitted sender)
 smtp.mailfrom=qun-wei.lin@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Reply-To: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
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

--__=_Part_Boundary_003_2123684117.2004379187
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<pre>
On&#32;Fri,&#32;2023-02-03&#32;at&#32;18:51&#32;+0100,&#32;Andrey&#32;Konov=
alov&#32;wrote:
&gt;&#32;On&#32;Fri,&#32;Feb&#32;3,&#32;2023&#32;at&#32;4:41&#32;AM&#32;Kua=
n-Ying&#32;Lee&#32;(&#26446;&#20896;&#31310;)
&gt;&#32;&lt;Kuan-Ying.Lee@mediatek.com&gt;&#32;wrote:
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Hi&#32;Kuan-Ying,
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;There&#32;recently&#32;was&#32;a&#32;similar&#32=
;crash&#32;due&#32;to&#32;incorrectly&#32;implemented
&gt;&#32;&gt;&#32;&gt;&#32;sampling.
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Do&#32;you&#32;have&#32;the&#32;following&#32;pa=
tch&#32;in&#32;your&#32;tree&#63;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXirPM=
SusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNTJE=
5Jx&#36;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;If&#32;not,&#32;please&#32;sync&#32;your&#32;6.1=
&#32;tree&#32;with&#32;the&#32;Android&#32;common&#32;kernel.
&gt;&#32;&gt;&#32;&gt;&#32;Hopefully&#32;this&#32;will&#32;fix&#32;the&#32;=
issue.
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Thanks!
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Hi&#32;Andrey,
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Thanks&#32;for&#32;your&#32;advice.
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;I&#32;saw&#32;this&#32;patch&#32;is&#32;to&#32;fix&#32;(&=
quot;kasan:&#32;allow&#32;sampling&#32;page_alloc
&gt;&#32;&gt;&#32;allocations&#32;for&#32;HW_TAGS&quot;).
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;But&#32;our&#32;6.1&#32;tree&#32;doesn&#39;t&#32;have&#32=
;following&#32;two&#32;commits&#32;now.
&gt;&#32;&gt;&#32;(&quot;FROMGIT:&#32;kasan:&#32;allow&#32;sampling&#32;pag=
e_alloc&#32;allocations&#32;for
&gt;&#32;&gt;&#32;HW_TAGS&quot;)
&gt;&#32;&gt;&#32;(FROMLIST:&#32;kasan:&#32;reset&#32;page&#32;tags&#32;pro=
perly&#32;with&#32;sampling)
&gt;&#32;
&gt;&#32;Hi&#32;Kuan-Ying,
&gt;&#32;

Hi&#32;Andrey,
I&#39;ll&#32;stand&#32;in&#32;for&#32;Kuan-Ying&#32;as&#32;he&#39;s&#32;out=
&#32;of&#32;office.
Thanks&#32;for&#32;your&#32;help!

&gt;&#32;Just&#32;to&#32;clarify:&#32;these&#32;two&#32;patches&#32;were&#3=
2;applied&#32;twice:&#32;once&#32;here&#32;on
&gt;&#32;Jan&#32;13:
&gt;&#32;
&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/a2a9e34d164e90fc08d35fd097a164b9101d72ef__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745_3oO-=
3k&#36;&#160;
&gt;&#32;&#32;
&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/435e2a6a6c8ba8d0eb55f9aaade53e7a3957322b__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745sDEOY=
WY&#36;&#160;
&gt;&#32;&#32;
&gt;&#32;

Our&#32;codebase&#32;does&#32;not&#32;contain&#32;these&#32;two&#32;patches=
.

&gt;&#32;but&#32;then&#32;reverted&#32;here&#32;on&#32;Jan&#32;20:
&gt;&#32;
&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/5503dbe454478fe54b9cac3fc52d4477f52efdc9__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745Bl77d=
FY&#36;&#160;
&gt;&#32;&#32;
&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/4573a3cf7e18735a477845426238d46d96426bb6__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745K-J8O=
-w&#36;&#160;
&gt;&#32;&#32;
&gt;&#32;
&gt;&#32;And&#32;then&#32;once&#32;again&#32;via&#32;the&#32;link&#32;I&#32=
;sent&#32;before&#32;together&#32;with&#32;a&#32;fix&#32;on
&gt;&#32;Jan&#32;25.
&gt;&#32;
&gt;&#32;It&#32;might&#32;be&#32;that&#32;you&#32;still&#32;have&#32;to&#32=
;former&#32;two&#32;patches&#32;in&#32;your&#32;tree&#32;if
&gt;&#32;you&#32;synced&#32;it&#32;before&#32;the&#32;revert.
&gt;&#32;
&gt;&#32;However,&#32;if&#32;this&#32;is&#32;not&#32;the&#32;case:
&gt;&#32;
&gt;&#32;Which&#32;6.1&#32;commit&#32;is&#32;your&#32;tree&#32;based&#32;on=
&#63;


https://android.googlesource.com/kernel/common/+/53b3a7721b7aec74d8fa2ee55c=
2480044cc7c1b8
(53b3a77&#32;Merge&#32;6.1.1&#32;into&#32;android14-6.1)&#32;is&#32;the&#32=
;latest&#32;commit&#32;in&#32;our
tree.

&gt;&#32;Do&#32;you&#32;have&#32;any&#32;private&#32;MTE-related&#32;change=
s&#32;in&#32;the&#32;kernel&#63;

No,&#32;all&#32;the&#32;MTE-related&#32;code&#32;is&#32;the&#32;same&#32;as=
&#32;Android&#32;Common&#32;Kernel.

&gt;&#32;Do&#32;you&#32;have&#32;userspace&#32;MTE&#32;enabled&#63;

Yes,&#32;we&#32;have&#32;enabled&#32;MTE&#32;for&#32;both&#32;EL1&#32;and&#=
32;EL0.

&gt;&#32;
&gt;&#32;Thanks!


</pre><!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality N=
otice ********************
The information contained in this e-mail message (including any=20
attachments) may be confidential, proprietary, privileged, or otherwise
exempt from disclosure under applicable laws. It is intended to be=20
conveyed only to the designated recipient(s). Any use, dissemination,=20
distribution, printing, retaining or copying of this e-mail (including its=
=20
attachments) by unintended recipient(s) is strictly prohibited and may=20
be unlawful. If you are not an intended recipient of this e-mail, or believ=
e=20
that you have received this e-mail in error, please notify the sender=20
immediately (by replying to this e-mail), delete any and all copies of=20
this e-mail (including any attachments) from your system, and do not
disclose the content of this e-mail to any other person. Thank you!
</pre><!--}-->

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_003_2123684117.2004379187
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, 2023-02-03 at 18:51 +0100, Andrey Konovalov wrote:
> On Fri, Feb 3, 2023 at 4:41 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E=
)
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >=20
> > > Hi Kuan-Ying,
> > >=20
> > > There recently was a similar crash due to incorrectly implemented
> > > sampling.
> > >=20
> > > Do you have the following patch in your tree?
> > >=20
> > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXirPM=
SusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNTJE=
5Jx$
> > >=20
> > >=20
> > > If not, please sync your 6.1 tree with the Android common kernel.
> > > Hopefully this will fix the issue.
> > >=20
> > > Thanks!
> >=20
> > Hi Andrey,
> >=20
> > Thanks for your advice.
> >=20
> > I saw this patch is to fix ("kasan: allow sampling page_alloc
> > allocations for HW_TAGS").
> >=20
> > But our 6.1 tree doesn't have following two commits now.
> > ("FROMGIT: kasan: allow sampling page_alloc allocations for
> > HW_TAGS")
> > (FROMLIST: kasan: reset page tags properly with sampling)
>=20
> Hi Kuan-Ying,
>=20

Hi Andrey,
I'll stand in for Kuan-Ying as he's out of office.
Thanks for your help!

> Just to clarify: these two patches were applied twice: once here on
> Jan 13:
>=20
>=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/a2a9e34d164e90fc08d35fd097a164b9101d72ef__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745_3oO-=
3k$=C2=A0
> =20
>=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/435e2a6a6c8ba8d0eb55f9aaade53e7a3957322b__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745sDEOY=
WY$=C2=A0
> =20
>=20

Our codebase does not contain these two patches.

> but then reverted here on Jan 20:
>=20
>=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/5503dbe454478fe54b9cac3fc52d4477f52efdc9__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745Bl77d=
FY$=C2=A0
> =20
>=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/4573a3cf7e18735a477845426238d46d96426bb6__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745K-J8O=
-w$=C2=A0
> =20
>=20
> And then once again via the link I sent before together with a fix on
> Jan 25.
>=20
> It might be that you still have to former two patches in your tree if
> you synced it before the revert.
>=20
> However, if this is not the case:
>=20
> Which 6.1 commit is your tree based on?


https://android.googlesource.com/kernel/common/+/53b3a7721b7aec74d8fa2ee55c=
2480044cc7c1b8
(53b3a77 Merge 6.1.1 into android14-6.1) is the latest commit in our
tree.

> Do you have any private MTE-related changes in the kernel?

No, all the MTE-related code is the same as Android Common Kernel.

> Do you have userspace MTE enabled?

Yes, we have enabled MTE for both EL1 and EL0.

>=20
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel%40mediatek.com.

--__=_Part_Boundary_003_2123684117.2004379187--

