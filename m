Return-Path: <kasan-dev+bncBCLMXXWM5YBBBUMR32GAMGQEO35JAAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CD3DF456E25
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 12:21:53 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf6400997lfv.11
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 03:21:53 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1637320913; cv=pass;
        d=google.com; s=arc-20160816;
        b=wMjEwHy8/BmEmHCCY7SXwLN5MWUIOqWXQu4t2xGYknDo/j7ilq96iDPq46tkdsboJ7
         XE8fRCrZWF2EcpwU7JxT1+3DiHQhd632dIfnoiObn2qekPLRSbfksqs+lsAKfLcz4K1B
         pXj8Vj4G+cnVFeHi3tvlxlkU+Cjv2CM8oZJ/XHB2+9bom5Mn3VyWkiukfcdKj5XBStm5
         yLfgPfgZGQU3felkSC76PWbTBh8U06peASnx/0iOe4Uru+d5aSg6PAftdppsqACIJCL7
         +pYlbgwKSlzXNrVSMTI2kIT8uB1xs8YeWy+7E0rAgLeVsl70KT9ux40QgpbBOSyNhExC
         q1Jg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=WjpvYNxUtS9AQ2NcfNi7q6OMWZGw7KwKdXgEXB4KdP8=;
        b=saxeXy5oRQy+6kYZ+bO1g5gUl/c7ST0GQNk3vRBNizLjNRO4vtpgYN3PLBsCRAtwpC
         ZtN9Y7iBNP2vu62vYBrH4lPhY6jdHR1SgaSjwLW8w3UZgUciY9+He9+aIGVj4PuRhlvj
         B2Q3YrWyuwjXfDgAv4CaMz+YkQMX2g4UglSVkm1Gec0jDkQdVXREsnn60Axn+JbRFnRV
         kdIdJWMZgRpbXQIZ3vf+SOG2nGr4UygZO/xE2F+vlHlRWxKEEEnOkK5F4TO8xPtHplpS
         BZdKGgRiB881JafLSJVB04wg9ZBIEm2/yMpeAv8LRA9gvBrcSjW/RjcLtNAlTJzMPeX0
         brag==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=HcOB9QwO;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WjpvYNxUtS9AQ2NcfNi7q6OMWZGw7KwKdXgEXB4KdP8=;
        b=OkPFVBWS1rq2wZjF/VHN8lFpDgXZBy0j1B39LxKQTtPJPC8T/4IQlP89xK7JRSWAmT
         HU4pRwStEuGpUPsgv8LIXyPEMqgLsd/gDtMmxDDYJkiyCufIacrwuEAxsulwCw10GpAX
         cQej/rAyIJJtmRl/C4BMWjUUJH4ydDtKNLKmahOwkaF885i9BjeEJUg+Y5VWYAnKYyK/
         So/tS/6JGuRPcbkO4NCjR54ZFHTzqGtzpDFoEX37ih2hTvuM1jRhMPPg+bvDoDviFG0g
         aPZc0IoAjn9PKi8zPvvXNGjF9Rl+6UVWw6s4+0KolhayN+EEHLc2n3KgWIxAMg6dqTjO
         OYVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WjpvYNxUtS9AQ2NcfNi7q6OMWZGw7KwKdXgEXB4KdP8=;
        b=eMUEFo3vXmWxCOx6nWvl/NneC3ExVxhRwKvpIsIo46ckXhoObhazEtZ8pYHwO18kf6
         Tfgnp+nXslCk4y0PNZGLa4O8LckTbWBNdLk6ozPhhvx4Z5K0kAJVHXDQU+VPb9ea05d4
         /Sky4d0h2zT+dyyW7buIDh2mLsVTUlOkbKkGVXmrwqbGK2cK6t/+yDrbtbGciOVrBGFe
         Z8Sn6JAb80TEcpqW0KYhq+bUlXvY6SQ+8gZpxiBTkWcxFjt9QhL1Nj8uOW1YoHQ68c44
         IyQj+WLUH5M5h0Yc1w5hFfLNQTd3gDmTup2TRHq9zvBZuqtebIpvgubZZTF/IUl1MHgN
         X4HQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530o449ev7m5h3THLYkPSbdB5Y3kASwEqTn/Ldb/f/5vDPk9EMiv
	viMJmD16SeVtS3+JnKTc1o8=
X-Google-Smtp-Source: ABdhPJwwNS28bF4F7M0E9vpQFFkktNBf3Xhbo7MDAau79l78GzJqzcL0z0bIH/NV4na7jUIszqlo/w==
X-Received: by 2002:a2e:864a:: with SMTP id i10mr24575191ljj.395.1637320913233;
        Fri, 19 Nov 2021 03:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls125887lfv.3.gmail; Fri, 19
 Nov 2021 03:21:52 -0800 (PST)
X-Received: by 2002:a05:6512:3501:: with SMTP id h1mr32603221lfs.231.1637320912132;
        Fri, 19 Nov 2021 03:21:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637320912; cv=pass;
        d=google.com; s=arc-20160816;
        b=qlGafyFx+Z0+yoeWGw/354S+PTuB3eOXePAU+7hoOcnSocH9XVXMjKN5/1XaT3rduE
         xDBtn5uRK+LXCErUwysVNabmaGAaYxw6siMqiWpR2n7b3DMjNBxNZkZSqXbbp3mNRxaN
         G/U/jk5G8LcwOcw4kk7PpiCorbTSS8jU/lNdqaJRdx1l9XdJoDBxi398Xos9wKh59e99
         PUWxzqhtjK0Yxu5BXPWxRd0t90oy46bpz2hOCdGKqEugfsWaX2rEW30A3ooy2pAgS0H+
         yJMbs0kWU/s6M1JJBM5ZJmJ6HRF9mTui0bRWVRcHx+gd+5dDEbkfP4YyccUzc63DKYzn
         Aw0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=y7sfLmIOu1C6T51ndyTlo5JtZ3EssEr3WEmRa1tewAw=;
        b=Qd9coQW8iiK9B17x4o4ITG+d3xjTTYtybDWZnUBbcqOT33jOoq1lqDwzs7dCt41uZs
         bzAytORRDmQVBsQlwjZ+9seOrygWZAN+Zt4kQ01Ng8DOfow74zN7OAPowZIo6Ivo5cvF
         Iv3LfJl/QlYgmeF1AjUyzdXpoNRl20meavXjhNPO6wmoj1TdnkIJCYfIP6OJTVuRYHzS
         6eZuMusGnQRZlqTCawEFPC3Q4uwe++z+trS8YWxWNGBKVubjAYClWcHGs7y1+ZXBsGaT
         DpnnfChwTFz8dDe0/ZzOwp8apnBXqu9gQ4H4cFT6EUTzYHbgP5Jr1B7ZwmOkxWTHEdAu
         iu5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=HcOB9QwO;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from esa.hc3962-90.iphmx.com (esa.hc3962-90.iphmx.com. [216.71.140.77])
        by gmr-mx.google.com with ESMTPS id x65si127191lff.10.2021.11.19.03.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 03:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) client-ip=216.71.140.77;
Received: from mail-co1nam11lp2172.outbound.protection.outlook.com (HELO NAM11-CO1-obe.outbound.protection.outlook.com) ([104.47.56.172])
  by ob1.hc3962-90.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Nov 2021 11:21:49 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=RtpUwMS4JsotY2smWiliY+wHoe2eqP2AXBQgzGJo0kuat0xUff8jqPXMCsR5b1AOxvmPo7vfETZmxXJtR5Ekvi7ToNsgWb6qVyeQ5VbojGcyiohQTo0xQKyV8xsHW/tLwdWoI/ZrW5EJvFAdJDjuAO6l2Z47VU0/ScCWzCacPpWoAVnKfN/XedrunozKHBZu3aYC+OczktmJ5IaeDdsSBDa1eD2hNYqS6eqfSjHIDQ2wg9d0Ej1CIhJ08vDOtUkGSU2ZCz5Df2+Ag9Gyql7jsyIG/d0zhFGhGtMM/N/ob8p2gNXrNMr2i94GWcoM+yLVI2INqun9FbKB5z0Iwtun+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=y7sfLmIOu1C6T51ndyTlo5JtZ3EssEr3WEmRa1tewAw=;
 b=hDghpW7bVz5mbFOZSZhhsJ4GEyiUUr4VkuLSUyZxbsd4RnWcNuddNgkbzZ6HmZYUxS9VAImjR9nzuf31avWuyCb+RHxqXSbVsZlOrHMmnRlzfYnzh+vTda+7ckyDduB0Cu3wJXoqWFrV2EMsDv/YUAfayRoOWFeUvtRRG9r9vaOr3K7zU9VCEcrQbvgIOCoFZHmgvf0D+pwCWTu/uPG9nl5tU4bHe8ORdMIxpLXM2mLorZbruXyH8rXaTICmqo2tka3GNPQP7eKEPsdvozgaYMwZhnOrjJcTHLssZ6qL7Q7UtyAXWyV8lduaUcuUoDzrKBUvv09lSchzRAeogCHabg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=quicinc.com; dmarc=pass action=none header.from=quicinc.com;
 dkim=pass header.d=quicinc.com; arc=none
Received: from DM8PR02MB8247.namprd02.prod.outlook.com (2603:10b6:8:d::19) by
 DM6PR02MB4379.namprd02.prod.outlook.com (2603:10b6:5:2d::19) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4713.21; Fri, 19 Nov 2021 11:21:47 +0000
Received: from DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3]) by DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3%9]) with mapi id 15.20.4713.022; Fri, 19 Nov 2021
 11:21:47 +0000
From: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>, "JianGen Jiao (QUIC)"
	<quic_jiangenj@quicinc.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Alexander Lochmann
	<info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vD2nRqghWy5Eq5zUX4/l1PcKwJUjYAgAC3OuCAAKLFAIAAC+bw
Date: Fri, 19 Nov 2021 11:21:46 +0000
Message-ID: <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
In-Reply-To: <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-messagesentrepresentingtype: 1
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: d71adb80-6e4d-432e-3f54-08d9ab4ec63a
x-ms-traffictypediagnostic: DM6PR02MB4379:
x-ld-processed: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d,ExtAddr
x-microsoft-antispam-prvs: <DM6PR02MB437997E105DE6CE24BCF1A38849C9@DM6PR02MB4379.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: V7sPRbLsL3tdGiz111/z7F1FNWp3KDuZSDZKVYMzpWKLpQotsPGujDgQnmpqgdo/pZShH/bhAY2pXBqJAx1+aGG2ARIBtfae4aLSmstItw+w4KQxxyqjRfUADDIfXdOQkgugrBFwGwUFGJLGSiyc/7XP8qKCmXmDyQx57rEeFG3j9xnKSWI99g2j+25XCScGItL1tdjohhzGlL6yWXpKE1Htgl9QwuS0hEMeZypOH7+AVP7agoO519MWEEjP6Awu444coIGcuC4niJu6lGqRkNoAqyyepSSaiRRYLTFoWNaYOI99MFPzJeLFCu9Q3d68fpUsBa6zY2r/JlvHp7Un/iMDDDkW0BXIOVmnJg2FYoDHbSpfmPhqDJApZ8CZX5PkjoSKj4/hdr/zdTcdl076gOW1/d2In0TjCQq3l9UtYwefgUQE1PZx4d1mPwAvxxVSNAciPQ5XR0nV9AAFqb3Y2Uw+NfBHjyMwjAqxYYKSdv5MiNhSFhdEkwI1GDz3K0P/Z9SBYScCGgYBztoyteJfWV3GaB+yr+ptvKh+2bR9uTb4V2WyuT6fFydHTURHoULK9vHxQgsROJyT2SPdUiL4wLSVE4bBopkr5Xrmhw5G38Ne62xXdfO7S5vTcRTopRah5Y/6F+UvLRCgcaXwbzhb/yYM0Tj+6lzTRno+rv4ups42e4u5xgylQSGAzyiaTTePmplFabjh3sx5uzLR6D4DPV/b06eoyW2SgSJjjPjFdbCTxZ5+3WkPYh6RrWyksZcnAW+bzG81iUEq2IT7/xRXx9kITeKypIqzgRbrjLkj9XM=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR02MB8247.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(52536014)(186003)(7696005)(107886003)(83380400001)(5660300002)(54906003)(4326008)(110136005)(122000001)(8676002)(8936002)(38070700005)(53546011)(9686003)(86362001)(55016002)(71200400001)(6506007)(76116006)(966005)(64756008)(33656002)(316002)(66556008)(508600001)(66946007)(66476007)(26005)(66446008)(38100700002)(2906002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?VHB2d280anBlYlZ3Yzhwc1ZValNEeHFrVkF2a3lEOGZGTmM1T0dzZURPcDNS?=
 =?utf-8?B?S09iSGdvMlNGbEJHTnZBb3haMUdFODNmYmtaaFAvUUswY2lDRWs4ZCtoeWJF?=
 =?utf-8?B?VGRERVlQYll1Zm1BMDNGWTIxWWsxSnp5bGUyaFJ0djE4aytldmZtdWtUNkxL?=
 =?utf-8?B?NnF0aFA3R0VULzNkTE03Z2dLSklWWG9KQUpNQXcyQXlzTnczRXg1c3JURElQ?=
 =?utf-8?B?aTN5YmdyOWMrTkZBUm1nZGJlcWhFdFZKbFY5SWgyckRES1lLSW5wNjBKdGxV?=
 =?utf-8?B?TkhGL2ljajR5cXRiaEdFQXBPaWdwSjB0ZzZadnpRVGpLTklpYjg0NkxTN1FN?=
 =?utf-8?B?c3h5RGhkc0ZweEFaa0R4eldQYnUzZXpQVVdHVllDeHpVNzRUUk15T1JZYnVY?=
 =?utf-8?B?MzBCWTZ6Q2JtNWluSFc3UWFzNnI3aHk1eHBScC82ZGFROGU2RCtScGxVZlRY?=
 =?utf-8?B?QS9HOG5OanUrTlJGNlMyVmtnNnJuVGp5VVUvMmJZSmVWWkVFUU1RNnFTNU9H?=
 =?utf-8?B?SVZrS0JQdVRnZVJmMkF3UFNWdW84VUp3cTZ4V0FIbFBVc0p6czFCMzJhZmVt?=
 =?utf-8?B?K1N6aFlUWjJ1OEI4SDF0dVcrd2E0SkJkVDE2WWQ4d2t0SEt0S1NZam9ENTMx?=
 =?utf-8?B?NE1qV1hQOEdxeSt3NzBOMnBMczYwT2ZrODloTmlGZWtxMDJKVDUyUVV2anBR?=
 =?utf-8?B?b21EdS9oSVZzdzllNzVJMDVGb04raDZlQ2g0c2pkbkFjKzJqVCtRR1crWjJ2?=
 =?utf-8?B?RHd6bnJ3SXlkaEdlakJ5SE0yTTNxVlkyQ3lYRmJDdkdiL21zaGxQUHBQclJ2?=
 =?utf-8?B?eEV5c1BKZmE5WURSRThYOU1IN2JWM2JrZ0hKUjFzN0NzVHRQYnJKZVh5OUNl?=
 =?utf-8?B?MUlZUEV5cy8wTjRhMkFPYzRwR202ZFRrd3FmZWliL0VsMkgvWkoyTUgyNzkw?=
 =?utf-8?B?dldwN1Jja0MzVVQxOXF6Y1ZIYWNGbkZHYUtwR3V5WTFUcmtsTTF2RGQ2Vm5S?=
 =?utf-8?B?UzNwVGdtMS9Vay9OWUxzUjBIaXJOK3p6VXBUeTVwb2dTd2QrYUJxZXdlZWE5?=
 =?utf-8?B?TGFkMFFuNlpSZFk2Z0h6N3hucHIwc0dHL1Q4NHpMVzZvUXlaSlRIWXhJbmx5?=
 =?utf-8?B?bmJBdFFNTjBUaGJBYmlMQUduUXNrUHpSWm0xWGxNWEVPTkxNd1R5Vi9QZmVr?=
 =?utf-8?B?MzFHQ0xqS0FWVnZocUYyY1BzS1BwUlB6SDR2TFZidHI5Y28wQVpRSTJQL295?=
 =?utf-8?B?b1o0K2h4SHY1RU9JbnRNTDRNVWtnVG9FTjBWb1I4Vlc5MzJ0QlJiQktFZjky?=
 =?utf-8?B?K3JoYzUwQkNhYitXUndIRm5rd2FDUFJuV2plNGxtWlZzaVk0eFV2RGtGTjRP?=
 =?utf-8?B?WFpkM090ejJHS05UZndZb0pHN2svOEdvRUhtM2piMmpvU3dicFV6NjhNbnkr?=
 =?utf-8?B?ekdqd0JIMWhSWFBnbjNhZFB1WXpPdTBCMUJ1bDRZNWc5djBlUmt1ZzNmVU44?=
 =?utf-8?B?V0UyajRXSGF4M2dGcVZuSldBcTk5ak05OXlmcnFDZDRlWmVidEF5MWcvaHlT?=
 =?utf-8?B?UmZFM3ZmY29UQUlYNjJQd0hkakhLcGdGMUJUUU9yOEZpTFZ3S09yZEJOK0Nz?=
 =?utf-8?B?cEl0RWtDbm1WTmNtVlBhRGNqejVJQWJzNHlFbXJmWHltQnprcW5yQzJKdTdk?=
 =?utf-8?B?MEF5eWZSdUhpU1VqMmVNOGN4S0FjRWRBZ1FzSUJSeHRYUE4wR3pYZy9wdUNX?=
 =?utf-8?B?L3dLRDBMSEFBTG4yVTF1Y216UUg3eWFIeXc0ZkM0UDhYSHlMdkRJcWNZMGUy?=
 =?utf-8?B?dkxqaWh4K1QyQ01NU0duU3QzUThqVGd4Nk96L29QS1RpemYxZHlzeFlGZ1FP?=
 =?utf-8?B?cWFiWEM1bDlwSm9CdVViVEJ2Z3lHUUMxSGFFdWRVRDAwcmpMQ2V1bVVqbGNl?=
 =?utf-8?B?bzdPVnc2VnJSYXZSUVc5eWpSdVUvRXhwNlN0RlFsb09sQzRpeHJ1Y0lrU1E4?=
 =?utf-8?B?VGhSMEJjZ05MZ0FDUHVrVm5EazhrTWJFOGxCa3FVQ2dZc2kxeWpVWW54S2cv?=
 =?utf-8?B?bHR6NFNjS05wYUFXRUpZZTFKQUtNL1M3Z3VrUG9PN3VUK0JBdEFhZjZyYXFW?=
 =?utf-8?B?S2hxZU1WVlZjei9aeFAwQ2t1S3lwMHZjV2FzT0xaM0ZBTkRGaWM4TGtQN1hj?=
 =?utf-8?B?dWtoWE42aGxSTUtTbHZiRWdscERQYnMyeENOK3VVWWRIajc3VjByN0RmbGhB?=
 =?utf-8?B?NUNncTRxbmFCTWt1NkhSNm1SNDJRPT0=?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: quicinc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR02MB8247.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d71adb80-6e4d-432e-3f54-08d9ab4ec63a
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Nov 2021 11:21:47.0085
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 6+YN+qv/nzhzj1M+ZffP8cn9uFkgnGq0WQuajKgsAYYEwtBNgFOHSbGGDEAG1Oq54Vwa7IRb7nE/fkPsQedOeOlBXQBUG4HmQ3WYa1Apa6c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR02MB4379
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qccesdkim1 header.b=HcOB9QwO;       arc=pass
 (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass
 fromdomain=quicinc.com);       spf=pass (google.com: domain of
 quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender)
 smtp.mailfrom=quic_jiangenj@quicinc.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=quicinc.com
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

Yes, on x86_64, module address space is after kernel. But like below on arm=
64, it's different.

# grep stext /proc/kallsyms
ffffffc010010000 T _stext
# cat /proc/modules |sort -k 6 | tail -2
Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat /proc/modules |s=
ort -k 6 | head -2
Some_module_3 16384 1 - Live 0xffffffc009430000

-----Original Message-----
From: Dmitry Vyukov <dvyukov@google.com>=20
Sent: Friday, November 19, 2021 6:38 PM
To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <linux-kernel@vg=
er.kernel.org>; Alexander Lochmann <info@alexander-lochmann.de>; Likai Ding=
 (QUIC) <quic_likaid@quicinc.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

WARNING: This email originated from outside of Qualcomm. Please be wary of =
any links or attachments, and do not enable macros.

On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@quicinc.co=
m> wrote:
>
> Hi Dmitry,
> I'm using the start, end pc from cover filter, which currently is the fas=
t way compared to the big bitmap passing from syzkaller solution, as I only=
 set the cover filter to dirs/files I care about.

I see.
But if we are unlucky and our functions of interest are at the very low and=
 high addresses, start/end will cover almost all kernel code...

> I checked=20
> https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ,
> The bitmap seems not the same as syzkaller one, which one will be used fi=
nally?

I don't know yet. We need to decide.
In syzkaller we are more flexible and can change code faster, while kernel =
interfaces are stable and need to be kept forever. So I think we need to co=
ncentrate more on the good kernel interface and then support it in syzkalle=
r.

> ``` Alexander's one
> + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx =3D pos=
=20
> + % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos <=20
> + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L <<=20
> + idx);
> ```
> Pc offset is divided by 4 and start is _stext. But for some arch, pc is l=
ess than _stext.

You mean that modules can have PC < _stext?

> ``` https://github.com/google/syzkaller/blob/master/syz-manager/covfilter=
.go#L139-L154
>         data :=3D make([]byte, 8+((size>>4)/8+1))
>         order :=3D binary.ByteOrder(binary.BigEndian)
>         if target.LittleEndian {
>                 order =3D binary.LittleEndian
>         }
>         order.PutUint32(data, start)
>         order.PutUint32(data[4:], size)
>
>         bitmap :=3D data[8:]
>         for pc :=3D range pcs {
>                 // The lowest 4-bit is dropped.
>                 pc =3D uint32(backend.NextInstructionPC(target, uint64(pc=
)))
>                 pc =3D (pc - start) >> 4
>                 bitmap[pc/8] |=3D (1 << (pc % 8))
>         }
>         return data
> ```
> Pc offset is divided by 16 and start is cover filter start pc.
>
> I think divided by 8 is more reasonable? Because there is at least one in=
struction before each __sanitizer_cov_trace_pc call.
> 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
>
> I think we still need my patch because we still need a way to keep the tr=
ace_pc call and post-filter in syzkaller doesn't solve trace_pc dropping, r=
ight?

Yes, the in-kernel filter solves the problem of trace capacity/overflows.


> But for sure I can use the bitmap from syzkaller.
>
> THX
> Joey
> -----Original Message-----
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Thursday, November 18, 2021 10:00 PM
> To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> <info@alexander-lochmann.de>
> Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
>
> WARNING: This email originated from outside of Qualcomm. Please be wary o=
f any links or attachments, and do not enable macros.
>
> ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com> wrot=
e:
> >
> > Sometimes we only interested in the pcs within some range, while=20
> > there are cases these pcs are dropped by kernel due to `pos >=3D
> > t->kcov_size`, and by increasing the map area size doesn't help.
> >
> > To avoid disabling KCOV for these not intereseted pcs during build=20
> > time, adding this new KCOV_PC_RANGE cmd.
>
> Hi Joey,
>
> How do you use this? I am concerned that a single range of PCs is too res=
trictive. I can only see how this can work for single module (continuous in=
 memory) or a single function. But for anything else (something in the main=
 kernel, or several modules), it won't work as PCs are not continuous.
>
> Maybe we should use a compressed bitmap of interesting PCs? It allows to =
support all cases and we already have it in syz-executor, then syz-executor=
 could simply pass the bitmap to the kernel rather than post-filter.
> It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander propose=
d here:
> https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
> It would be reasonable if kernel uses the same bitmap format for these
> 2 features.
>
>
>
> > An example usage is to use together syzkaller's cov filter.
> >
> > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > ---
> >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> >  include/uapi/linux/kcov.h        |  7 +++++++
> >  kernel/kcov.c                    | 18 ++++++++++++++++++
> >  3 files changed, 35 insertions(+)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst
> > b/Documentation/dev-tools/kcov.rst
> > index d83c9ab..fbcd422 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -52,9 +52,15 @@ program using kcov:
> >      #include <fcntl.h>
> >      #include <linux/types.h>
> >
> > +    struct kcov_pc_range {
> > +      uint32 start;
> > +      uint32 end;
> > +    };
> > +
> >      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned l=
ong)
> >      #define KCOV_ENABLE                        _IO('c', 100)
> >      #define KCOV_DISABLE                       _IO('c', 101)
> > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, struct k=
cov_pc_range)
> >      #define COVER_SIZE                 (64<<10)
> >
> >      #define KCOV_TRACE_PC  0
> > @@ -64,6 +70,8 @@ program using kcov:
> >      {
> >         int fd;
> >         unsigned long *cover, n, i;
> > +        /* Change start and/or end to your interested pc range. */
> > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =3D=20
> > + (uint32)(~((uint32)0))};
> >
> >         /* A single fd descriptor allows coverage collection on a singl=
e
> >          * thread.
> > @@ -79,6 +87,8 @@ program using kcov:
> >                                      PROT_READ | PROT_WRITE, MAP_SHARED=
, fd, 0);
> >         if ((void*)cover =3D=3D MAP_FAILED)
> >                 perror("mmap"), exit(1);
> > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> >         /* Enable coverage collection on the current thread. */
> >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> >                 perror("ioctl"), exit(1); diff --git=20
> > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index=20
> > 1d0350e..353ff0a 100644
> > --- a/include/uapi/linux/kcov.h
> > +++ b/include/uapi/linux/kcov.h
> > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> >         __aligned_u64   handles[0];
> >  };
> >
> > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range {
> > +       __u32           start;          /* start pc & 0xFFFFFFFF */
> > +       __u32           end;            /* end pc & 0xFFFFFFFF */
> > +};
> > +
> >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> >
> >  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned l=
ong)
> >  #define KCOV_ENABLE                    _IO('c', 100)
> >  #define KCOV_DISABLE                   _IO('c', 101)
> >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remo=
te_arg)
> > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kcov_pc_r=
ange)
> >
> >  enum {
> >         /*
> > diff --git a/kernel/kcov.c b/kernel/kcov.c index 36ca640..59550450
> > 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -36,6 +36,7 @@
> >   *  - initial state after open()
> >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> >   *  - then, mmap() call (several calls are allowed but not useful)
> > + *  - then, optional to set trace pc range
> >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> >   *     KCOV_TRACE_PC - to trace only the PCs
> >   *     or
> > @@ -69,6 +70,8 @@ struct kcov {
> >          * kcov_remote_stop(), see the comment there.
> >          */
> >         int                     sequence;
> > +       /* u32 Trace PC range from start to end. */
> > +       struct kcov_pc_range    pc_range;
> >  };
> >
> >  struct kcov_remote_area {
> > @@ -192,6 +195,7 @@ static notrace unsigned long=20
> > canonicalize_ip(unsigned long ip)  void notrace
> > __sanitizer_cov_trace_pc(void)  {
> >         struct task_struct *t;
> > +       struct kcov_pc_range pc_range;
> >         unsigned long *area;
> >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> >         unsigned long pos;
> > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
> >         t =3D current;
> >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> >                 return;
> > +       pc_range =3D t->kcov->pc_range;
> > +       if (pc_range.start < pc_range.end &&
> > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > +               return;
> >
> >         area =3D t->kcov_area;
> >         /* The first 64-bit word is the number of subsequent PCs. */=20
> > @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, uns=
igned int cmd,
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> > +       struct kcov_pc_range *pc_range;
> >         unsigned long flags;
> >
> >         switch (cmd) {
> > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, un=
signed int cmd,
> >                 kcov->size =3D size;
> >                 kcov->mode =3D KCOV_MODE_INIT;
> >                 return 0;
> > +       case KCOV_PC_RANGE:
> > +               /* Limit trace pc range. */
> > +               pc_range =3D (struct kcov_pc_range *)arg;
> > +               if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kc=
ov->pc_range)))
> > +                       return -EINVAL;
> > +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> > +                       return -EINVAL;
> > +               return 0;
> >         case KCOV_ENABLE:
> >                 /*
> >                  * Enable coverage for the current task.
> > --
> > 2.7.4
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM8PR02MB8247A19843220E03B34BA440F89C9%40DM8PR02MB8247.namprd02.p=
rod.outlook.com.
