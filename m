Return-Path: <kasan-dev+bncBAABBRNU43WQKGQEE2YOYWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id AFB54E9D35
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 15:12:21 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id q22sf670233wmc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 07:12:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1572444741; cv=pass;
        d=google.com; s=arc-20160816;
        b=zwF6HmhIhE3g7O5KZ7/S5394Y8i9dPKQre/CYVPgUPFU4LSlCwlue2IIsLyX7kDW6M
         r7sTMYR6M8V64/RzNvHbfxDtVK5uPTRoKOKEa19UIUii7G8SpOMw5CGaSGCSMtGk0KwU
         28eExwA3/vI6UqLFWrmFYVvGEBCL3cEUGJ87ImMDusmjKX2N8uohoXnCGyL2yOqV7ELe
         hYMYWhrhKDl9Q/jaXUQqsrCTZP9VF3AmfMimyr46f/Kv4Nv74guB9iVKRoyt+8py+qZy
         MvSDmS/ufXuCafjVn/2fGT69FwFWO4Oig0eCL1dW3b0fLvfrEyI/Sdxoe1oA2LC25V9J
         o4Ng==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer
         :original-authentication-results:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=bC8SFrnqNvu6MBZVygMoCj5EO2xlpsLDL6y6eG+7D1Y=;
        b=T+DZjNbGmGOFDKEZlfrMEvNOWEcJI2W6xZW4QS1ZSAX03gcWEFy+jwL4qMgLqU5wP5
         nj3r59yr9pRj3niHb5OwO1/ckHU/OLr5m5kHPX6I89vECrvNxi+WmxEC+Yu5qNZqbjgY
         zKPtzdYBdmdZTSbam6bk1P/fbYVYqF8CQe+Q/tsiDnnBk4N4pe0ImSsyZ2RyRzxwFJKr
         Sbgn5o4kEHeo5r1TaaLf2oRF8UvDE1s2kqVMIcbhd8msVR6zrTbD6wFMnxT21EiGvb3O
         lx+K12U0ajUP+v0S848yCkbfwnwsLj2K1gkHOJibB8BPCXvywJ8sxlMfoJQPgeCWc7ux
         SHOA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=v8vzZ1Uf;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=v8vzZ1Uf;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.72 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :mime-version:original-authentication-results:nodisclaimer
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bC8SFrnqNvu6MBZVygMoCj5EO2xlpsLDL6y6eG+7D1Y=;
        b=SMsR4Smj3SGdhast27yYyJZ0QE4XN4V5bczh33WFFj+029O1ztK0Gy/nHV0ru54E9g
         HrLxIEA8lC+MScHLIhRW0DnEE5orVNCbCgjg7SXiU2pcxs7rXV6czIA2jioFFFxEBeQj
         0unEpwH9JKt75O/s2QoLGHM3IQQ2xpFLo0iIELo/1CPib6e6jAz4/ozBI3J9IpPCBeLo
         rzzuwzNFH3PU3UcKOkorPIQk/ejME8lv23PDk1ccFriruWqDhFylftpJ60hEVw9hiCJR
         R5Q8gWk/FRCM7iCiieT0p6TjpbIyFjCqYiqhOQXzXTy2/Yrw4TYb2ZsyhkJOUiMSw0NM
         i+Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:mime-version
         :original-authentication-results:nodisclaimer:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bC8SFrnqNvu6MBZVygMoCj5EO2xlpsLDL6y6eG+7D1Y=;
        b=Pn/xIJsEk6U03dacPxz/VDxU1fEfgdxq5aPrXRWBZXR9VJ19unTpI3fVA474agvwpr
         2Ov3lcUh1i5TaM14fsszoZXl0jQ89xo+59ye05Il78dYzt3Yfyl3ii6/30jxMH+75wOb
         Jicq5l+ZCekLEFHKoZrs/U3GqX4HSNChpD93b4Yvl8XSWU2LOBMiR5rJlXmwkBxGPDfQ
         XqsAhml1LZ3tModkMdg88x9j9bzAoVox/J8RcS21lsG2T4E7emzuaObwWpq7o78O082E
         29bzRM1BAWVHwUL2kuRgWOOJ40I6d2pndd+nsOJ1kq8izFsbAhF4AinqsO4P/BJWzrmP
         qDbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVM7HS6W2GJuloIkSi/a3EfBubFmxO5Dt7+gJigIcFMqIVPoQAm
	vwY43i4mGjmkoThd4ZVPodo=
X-Google-Smtp-Source: APXvYqzGtW5XQC4XRLgMrvkT4Q6ibbAOb2wGr2RAc9m4O+AeBzwxmmHaH4ZDl8ejHUoZltiArbKmyg==
X-Received: by 2002:a1c:998f:: with SMTP id b137mr9498388wme.104.1572444741436;
        Wed, 30 Oct 2019 07:12:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:c4:: with SMTP id q4ls17464912wrx.3.gmail; Wed, 30
 Oct 2019 07:12:21 -0700 (PDT)
X-Received: by 2002:a5d:4446:: with SMTP id x6mr66853wrr.103.1572444741018;
        Wed, 30 Oct 2019 07:12:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572444741; cv=pass;
        d=google.com; s=arc-20160816;
        b=zI2FniORWnmAf82lwUAqsFA78+UjGRfdBPtv00UkVNCnGpBsfIF4+aTEDAsLxMYan1
         mJV7C1mCaf9DmhCnK8Os9Y2HvSp931wtksLpmlyBKO0ngTRk7gfTdpld81gIZAAmlgmb
         ss5pQ1+c6ybamIeHvobxcFcPSpAIiO49UcIulLCg0xeJocn58/F6VLCUpj/ZParC3FRz
         EwgKdzjJZUKXKW90Q8F3JsuSCyNw1IwA7yZZtGLghYBx3NJTOptZvsHdj+EuMvWch7kJ
         cMbWht4tpkVlaD7nkJc/WkNYrCpVBSE7s27LfDw2pQER7cA1FcwB6AEZkS3g1a6LWMEe
         aApA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=nodisclaimer:original-authentication-results:mime-version
         :content-transfer-encoding:content-id
         :authentication-results-original:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=HDAs3J2RMnki7F86u6cApDPb7M/CJP/mGFn0HEMrtP8=;
        b=PT3Ep9BUzex3PHzV+RSn/AwFgj1GI3XxghE2Hv2z8l/lXjIqOYe/bL8JObrxbsvi/t
         BdYFJh3BO7GI6+SR0QVY4QxbFsU/i5x2tGheQYzO7bSSjos4anldiq27w/iaECqwgWdh
         JXvnOqj+5rgVy5XhPQQtWg8K6ue/F5LgU/TOxYrlFIPfTP5JKhm/SPqq7ZpkKM5iVw8Z
         e54IhHtT7CmVXzE3vaps2RuF41MqkAGf9MriCQh3bsMitchUrwc70PfwuYLpGHfNmPgQ
         /qGNZDH1m2jwUUA8FcxrCYOjL59Kpx59xf2WWjP1BLhdoH5qdJHpaHPvDGuE44oiDplu
         fBrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=v8vzZ1Uf;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=v8vzZ1Uf;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.72 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
Received: from EUR02-AM5-obe.outbound.protection.outlook.com (mail-eopbgr00072.outbound.protection.outlook.com. [40.107.0.72])
        by gmr-mx.google.com with ESMTPS id q22si199233wme.2.2019.10.30.07.12.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Wed, 30 Oct 2019 07:12:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.72 as permitted sender) client-ip=40.107.0.72;
Received: from VI1PR08CA0124.eurprd08.prod.outlook.com (2603:10a6:800:d4::26)
 by AM0PR08MB3764.eurprd08.prod.outlook.com (2603:10a6:208:ff::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2387.24; Wed, 30 Oct
 2019 14:12:19 +0000
Received: from VE1EUR03FT050.eop-EUR03.prod.protection.outlook.com
 (2a01:111:f400:7e09::202) by VI1PR08CA0124.outlook.office365.com
 (2603:10a6:800:d4::26) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2408.20 via Frontend
 Transport; Wed, 30 Oct 2019 14:12:19 +0000
Received-SPF: Fail (protection.outlook.com: domain of arm.com does not
 designate 63.35.35.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=63.35.35.123; helo=64aa7808-outbound-1.mta.getcheckrecipient.com;
Received: from 64aa7808-outbound-1.mta.getcheckrecipient.com (63.35.35.123) by
 VE1EUR03FT050.mail.protection.outlook.com (10.152.19.209) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.20 via Frontend Transport; Wed, 30 Oct 2019 14:12:19 +0000
Received: ("Tessian outbound 0939a6bab6b1:v33"); Wed, 30 Oct 2019 14:12:19 +0000
X-CheckRecipientChecked: true
X-CR-MTA-CID: ffdd18919f8ce9c0
X-CR-MTA-TID: 64aa7808
Received: from 954e6e9751ce.1 (cr-mta-lb-1.cr-mta-net [104.47.8.55])
	by 64aa7808-outbound-1.mta.getcheckrecipient.com id 2F394C18-5E23-4E54-99D9-F929441466D5.1;
	Wed, 30 Oct 2019 14:12:13 +0000
Received: from EUR03-AM5-obe.outbound.protection.outlook.com (mail-am5eur03lp2055.outbound.protection.outlook.com [104.47.8.55])
    by 64aa7808-outbound-1.mta.getcheckrecipient.com with ESMTPS id 954e6e9751ce.1
    (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384);
    Wed, 30 Oct 2019 14:12:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=B9uj09nz4T6GS0se2GPHnwzjTv3AAR2oGPTZqyiCjbn0Eb2/NEMocXEiuUTUg+Stg1KsWlm3AfC/WvntVdX4Ji9PN1GGYWxv0m6o8tVAfqwBkhok/W9gIIEoKDsmCxUUrx/+ZXvPzDH3Wx/5GJiKq1nxtY+jb9ot/Nm4vFeGyk/MuvF4+7qMXlyrDA6ar8s1yN0q1ivkzmB1RmND6mEih0FGdAb46FqhSHQWlbZw5dYfN7vJifwqqC1M4edGsOctYjsHC5IGNgghW2lBIFhNxZp2QA4m9BIX4e+wWmlqQl3GV3O7zKU6ivInljJgDw98b3TfERV3do/BUpfcT7LwkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=HDAs3J2RMnki7F86u6cApDPb7M/CJP/mGFn0HEMrtP8=;
 b=n3uqw5/STS4A8Ujq3EICbeSyHg7UAPcUS8T27bp/ftzGdjbl2VWnSV0Rkz5omgcfKruqaXfQrB+w4uouX0Bex76hMx6DVcVsXbV0AtyEHPGXvc5Ejfmjs7BEQcwlRwT6nfyyB4/Q4YlhOdkxL40WrO0MqEJ8IQGq7mHAyyFAuJ6Lo5h/orHphdqgLZpOX1FzYlnImvA0EqIj4/zQVnFsDrOqe5ptH00aOVACY7MkqMEbZs1q7wBKId07WE/4ab2TUQHeuox6qd+0PZZSP7bkzlVvyt/icAclFP1NG7tUnHghu5EhAaPc7ODw35Ddxh/wJb7Q+SBSMqaDCb7uYTGwVw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com (52.133.246.83) by
 VI1PR08MB4319.eurprd08.prod.outlook.com (20.179.26.78) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2408.17; Wed, 30 Oct 2019 14:12:12 +0000
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339]) by VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339%3]) with mapi id 15.20.2387.027; Wed, 30 Oct 2019
 14:12:12 +0000
From: Matthew Malcomson <Matthew.Malcomson@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, kasan-dev
	<kasan-dev@googlegroups.com>, nd <nd@arm.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: Makefile kernel address tag sanitizer.
Thread-Topic: Makefile kernel address tag sanitizer.
Thread-Index: AQHVhCNNoOSr1ytgiEqSG00mmgt5mqddSDEAgBSwtgCAAAFugIABScIAgAAHMQCAAAR1gA==
Date: Wed, 30 Oct 2019 14:12:12 +0000
Message-ID: <b23a7e55-0b95-1db9-fedd-3f96d3967d0a@arm.com>
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com>
 <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
 <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com>
 <CAAeHK+yP2vK06tnx2p=NT8cD_qz_gV_xkuPZ40b2OAe+zxM-EA@mail.gmail.com>
 <b135bdce-8fd3-c81b-72d1-6a162307f6be@arm.com>
 <CAAeHK+zArL=ru9rmsbuJjertMtF+PwdqV_Dpd=xJ=mKF=Gfzsw@mail.gmail.com>
In-Reply-To: <CAAeHK+zArL=ru9rmsbuJjertMtF+PwdqV_Dpd=xJ=mKF=Gfzsw@mail.gmail.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-clientproxiedby: DM6PR02CA0048.namprd02.prod.outlook.com
 (2603:10b6:5:177::25) To VI1PR08MB5471.eurprd08.prod.outlook.com
 (2603:10a6:803:136::19)
x-ms-exchange-messagesentrepresentingtype: 1
x-originating-ip: [217.140.106.49]
x-ms-publictraffictype: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: 91a7c9d1-e93b-42f3-d925-08d75d432d32
X-MS-TrafficTypeDiagnostic: VI1PR08MB4319:|AM0PR08MB3764:
X-MS-Exchange-PUrlCount: 2
X-Microsoft-Antispam-PRVS: <AM0PR08MB376476603F43617157EAB034E0600@AM0PR08MB3764.eurprd08.prod.outlook.com>
x-checkrecipientrouted: true
x-ms-oob-tlc-oobclassifiers: OLM:10000;OLM:10000;
x-forefront-prvs: 02065A9E77
X-Forefront-Antispam-Report-Untrusted: SFV:NSPM;SFS:(10009020)(4636009)(396003)(136003)(39860400002)(376002)(366004)(346002)(199004)(189003)(51914003)(6246003)(6306002)(7736002)(486006)(305945005)(4326008)(66066001)(71200400001)(71190400001)(14444005)(256004)(26005)(44832011)(6436002)(2616005)(476003)(6512007)(11346002)(446003)(6486002)(186003)(54906003)(316002)(36756003)(229853002)(52116002)(99286004)(66556008)(64756008)(5660300002)(14454004)(478600001)(966005)(6116002)(76176011)(3846002)(31686004)(6916009)(2906002)(6506007)(386003)(25786009)(31696002)(86362001)(81166006)(8936002)(53546011)(8676002)(81156014)(102836004)(66476007)(66946007)(66446008);DIR:OUT;SFP:1101;SCL:1;SRVR:VI1PR08MB4319;H:VI1PR08MB5471.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;A:1;MX:1;
received-spf: None (protection.outlook.com: arm.com does not designate
 permitted sender hosts)
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam-Untrusted: BCL:0;
X-Microsoft-Antispam-Message-Info-Original: fSgz25WK6skgHuut6XYa/Pm9tEfPGS2S9Ejy6r8RohD3AfUIieEn5QuPpjQWjuY0md0o5AizCEP5EUZJmJzI3reUf4wmXmi39hgXHqOKzn8AHG1JWkq4n02XmrJXnH0sExMS4Qc1G5KlFyBzAoLja7zX4eaVwJTgDFzBTQF0jYK0GJ3TKJ2CXKAvoV70q01ayP++jpPH11Ord1NHi37U70iUlFhE9IFBlrqu9o630uzz8XUE60kU9cjc4A8UJUKwYJDZRgKnsBmpXGyfztyCm4rMn4PUpqesQ4zSh1HSPllPeND23Zzt5WxGGEsVngwuz+IAfQmK+UYUVbW0irLzBgNim0IxgVRTuRr/QDtJVly+BY4/qY0aQb311otwOSHawuWPgyj3lJ0sZ5xMnZsF5fx9Q9I/rDoRfdLp+SWe5Nqx+3GnN5+udlYNHOq8ugamsO2ZrZ5Q5tGrwmDbadoLKjYU25v55Bw3BWHeDfLUNHw=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-ID: <F10CE450970A7D4C91C5B66849C6EF4C@eurprd08.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR08MB4319
Original-Authentication-Results: spf=none (sender IP is )
 smtp.mailfrom=Matthew.Malcomson@arm.com;
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: VE1EUR03FT050.eop-EUR03.prod.protection.outlook.com
X-Forefront-Antispam-Report: CIP:63.35.35.123;IPV:CAL;SCL:-1;CTRY:IE;EFV:NLI;SFV:NSPM;SFS:(10009020)(4636009)(136003)(39860400002)(396003)(346002)(376002)(1110001)(339900001)(51914003)(189003)(199004)(229853002)(6486002)(81156014)(47776003)(31696002)(50466002)(31686004)(107886003)(8676002)(86362001)(8936002)(36756003)(356004)(14444005)(4326008)(6306002)(66066001)(2906002)(6512007)(81166006)(6862004)(105606002)(6246003)(26005)(2486003)(76176011)(23676004)(53546011)(386003)(6506007)(102836004)(186003)(3846002)(6116002)(966005)(446003)(7736002)(126002)(76130400001)(99286004)(5660300002)(476003)(436003)(70206006)(22756006)(70586007)(25786009)(14454004)(486006)(336012)(11346002)(2616005)(305945005)(54906003)(316002)(478600001)(36906005)(26826003);DIR:OUT;SFP:1101;SCL:1;SRVR:AM0PR08MB3764;H:64aa7808-outbound-1.mta.getcheckrecipient.com;FPR:;SPF:Fail;LANG:en;PTR:ec2-63-35-35-123.eu-west-1.compute.amazonaws.com;MX:1;A:1;
X-MS-Office365-Filtering-Correlation-Id-Prvs: b632559a-b433-47d1-a052-08d75d43288d
NoDisclaimer: True
X-Forefront-PRVS: 02065A9E77
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: oqD6+Ethvf5Q3hbSzBvH8FsvCv+cjynUwWho9HxAi+IqP5W9wOhqIOikbSui0fp8p3AenRCO7bsDrzLaikWn+n5P4l7ZCcQYpTC+UzWDaGxO8MEX6K1B8+c/V9wF5PX+FYv6NGE1XR4wfgY7BvZaL0C9iCIG0TcxRTSM9SVcnNayLtY8T0w26nWnVxVYTCkKvR+nbM30ORS6YhSpAWrjsdhregRGrg+UWQypIpSX3SFyS1gUyAA+LP5IcjZ/SHXoMeyV5M9f7SVNeFT2UAwp4mxDncdUPznQWsE3iWkItgYcFa2M2tc3/WalYQBwsR3RIz6yD9qRtXcpfmjfXaLNZx7nPW+YW08uw1n78oLwV0RuC9YW2B+B3MkuDppQxeMQ/0vhNaWx9ispKnPhA7UxKKZS3YgNFv8NVZ55U+jG/XeKM/VDWRzw4qoDcy+cAdXXV3+mcVcZzCRNZ1dZrSZzYsAZIWG6TuCIK5xwNmgfhgk=
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2019 14:12:19.7442
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 91a7c9d1-e93b-42f3-d925-08d75d432d32
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[63.35.35.123];Helo=[64aa7808-outbound-1.mta.getcheckrecipient.com]
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM0PR08MB3764
X-Original-Sender: matthew.malcomson@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com
 header.b=v8vzZ1Uf;       dkim=pass header.i=@armh.onmicrosoft.com
 header.s=selector2-armh-onmicrosoft-com header.b=v8vzZ1Uf;       arc=pass
 (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 matthew.malcomson@arm.com designates 40.107.0.72 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
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

On 30/10/19 13:56, Andrey Konovalov wrote:
> On Wed, Oct 30, 2019 at 2:30 PM Matthew Malcomson
> <Matthew.Malcomson@arm.com> wrote:
>>
>> On 29/10/19 17:50, Andrey Konovalov wrote:
>>> On Tue, Oct 29, 2019 at 6:45 PM Matthew Malcomson
>>> <Matthew.Malcomson@arm.com> wrote:
>>>>
>>>> Hi Andrey,
>>>
>>> Hi Matthew,
>>>
>>>>
>>>> Thanks for the clarification on that bit, could I ask another question?
>>>>
>>>> I seem to have non-stack compiling with GCC running ok, but would like
>>>> to have some better testing than I've managed so far.
>>>
>>> Great! =)
>>>
>>>>
>>>> I'm running on an instrumented kernel, but haven't seen a crash yet.
>>>>
>>>> Is there a KASAN testsuite to run somewhere so I can proove that bad
>>>> accesses would be caught?
>>>
>>> Kind of. There's CONFIG_TEST_KASAN which produces lib/test_kasan.ko,
>>> which you can insmod and it will do all kinds of bad accesses.
>>> Unfortunately there's no automated checker for it, so you'll need to
>>> look through the reports manually and check if they make sense.
>>
>> Great, that was really useful!
>>
>> I found one issue in my instrumentation through using these tests -- I
>> haven't defined `__SANITIZE_ADDRESS__` (which means memset calls aren't
>> sanitized here since a macro replaces them with __memset).
>>
>> Looking at the current kernel code it seems that for clang you use
>> `__SANITIZE_ADDRESS__`, for either hwasan or asan.  (commit 2bd926b4).
>>
>> Do you (or anyone else) have any objections to using
>> `__SANITIZE_HWADDRESS__` to indicate tagging address sanitizer so they
>> can be distinguished?
>>
>> I can provide a patch to the kernel to account for the compiler
>> behaviour if it's acceptable.
>>
>>
>>
>> Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan
>> equivalent of no_sanitize_address, which will require an update in the
>> kernel given it seems you want KASAN to be used the same whether using
>> tags or not.
> 
> We have intentionally reused the same macros to simplify things. Is
> there any reason to use separate macros for GCC? Are there places
> where we need to use specifically no_sanitize_hwaddress and
> __SANITIZE_HWADDRESS__, but not no_sanitize_address and
> __SANITIZE_ADDRESS__?
> 

Honestly, I'm not sure ...

I think I'll come back after asking a bit of feedback from GCC upstream 
with this in mind.
A discussion with a colleague has already brought up a few different 
options.

>>
>> Cheers,
>> Matthew
>>
>>>
>>> Thanks!
>>>
>>>>
>>>> Cheers,
>>>> Matthew
>>>>
>>>> On 16/10/19 14:47, Andrey Konovalov wrote:
>>>>> On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
>>>>> <Matthew.Malcomson@arm.com> wrote:
>>>>>>
>>>>>> Hello,
>>>>>>
>>>>>> If this is the wrong list & person to ask I'd appreciate being shown who
>>>>>> to ask.
>>>>>>
>>>>>> I'm working on implementing hwasan (software tagging address sanitizer)
>>>>>> for GCC (most recent upstream version here
>>>>>> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
>>>>>>
>>>>>> I have a working implementation of hwasan for userspace and am now
>>>>>> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
>>>>>> CONFIG_KASAN_OUTLINE for now).
>>>>>>
>>>>>> I notice the current scripts/Makefile.kasan hard-codes the parameter
>>>>>> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
>>>>>> variables, and found an email mentioning that stack instrumentation is
>>>>>> not yet supported.
>>>>>> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
>>>>>>
>>>>>>
>>>>>> What is the support that to be added for stack instrumentation?
>>>>>
>>>>> Hi Matthew,
>>>>>
>>>>> The plan was to upstream tag-based KASAN without stack instrumentation
>>>>> first, and then enable stack instrumentation as a separate effort. I
>>>>> didn't yet get to this last part. I remember when I tried enabling
>>>>> stack instrumentation I was getting what looked like false-positive
>>>>> reports coming from the printk related code. I didn't investigate them
>>>>> though. It's possible that some tweaks to the runtime implementation
>>>>> will be required.
>>>>>
>>>>> Thanks!
>>>>>
>>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b23a7e55-0b95-1db9-fedd-3f96d3967d0a%40arm.com.
