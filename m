Return-Path: <kasan-dev+bncBAABB65A43WQKGQEPZXNCNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C17A6E9C48
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 14:30:35 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id i18sf1645486edy.6
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 06:30:35 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1572442235; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlKzEyFBMOf8uU/2yfs/SWXfHVIyAAh0uEHPkP3Mpp/tuzQ0NY3XQcGgwMKTDSYcez
         y3l9aw439nb99rSG82tlBVAeRaMJz2QfV4vSc5Nvw9JyDpyNbCVJ0JV3I03ss88Se490
         JIPifGcrJZ38LjhmO6JDjjilekzOBGyPUrLOnGxpaRA7FgDF5AxeDKdEVhj7Y/c85z7Q
         2eDImK8A5kSBngJ0pLF/Rj7NctNVv7zjpRnjabi33FKuXwFHp2J7Y41OaH0k12dHOjOw
         +r4idARVpCFkndsBUISyL8vkukpS1Pet5F6/RGIp5KLAImGOr80FTpxuh0ox0AgpXGV+
         pZ1g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer
         :original-authentication-results:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=+99ogAEXTfmzz4OWDaKj1ilmXfOBrwM45sPfyDMWkUo=;
        b=TzVKoGntlIhORyNjBKUWSUTfZusSOzsj1ZhjSWHv8ky6prZybkgIBYqI+sgSWbWYHb
         kq3i6irKCwGwVowv15/8HevzRdToE0clpbm0vUFBjrnKn5Dw6yRKSr28Bqms4DwW8XXI
         ZrYAk/kVxkI1CigQVjpcLT8JuViNleNDn3Dlzo8Ym2J+szVAc05D2arbDDZTYtX7satv
         xtbaOkQD94RNvg9G3rrbEpytC3no8fdPKWuzLGWw6rvBvarQrs7IZXW1UzWHjbnhnORF
         YfsfQNqDxmFB13OB0ZmPlTlq45i3Yzg/tWZQD+TUJi1uBhfZz4GoawL5Dgieo2ZUKKr4
         qjPg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=IyqnrH5c;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=IyqnrH5c;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.7.85 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :mime-version:original-authentication-results:nodisclaimer
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+99ogAEXTfmzz4OWDaKj1ilmXfOBrwM45sPfyDMWkUo=;
        b=Q46bXbEMJ3fxTii4AsP9NuTHL9TP9RYywFHoY0Evv2f4MD+esBhvpGoPF3GhwDvnH6
         9XjBGpKwjGHp25tCZHvGag5W+D5L3xi399jaKfa0uFuK6WNV46T5lngR7uLJPZlLZxIZ
         AE2HlCLLuUOqKllXwkZSbCILE1IXmKFoYHb5PkzOLttKDjRU37IeCsZNoT9DpVRbZEhO
         dYLHh2t4ezLznY5sCplEne+GzPWF3rZO5Q+h0caXuD0kYIXmCZINGBN8M1RE5kmMsLf7
         M0Vp7PJdeKTfOVCcvvO7o+yFqth0EsVdB9tHCwhKHSnqQ+u0qmiYMVw9AQU3uf4CRzUz
         RQeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:mime-version
         :original-authentication-results:nodisclaimer:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+99ogAEXTfmzz4OWDaKj1ilmXfOBrwM45sPfyDMWkUo=;
        b=VyvKuWhT9wBKcb68ZfHsTXm+p5RBZ3IlsssMtxhqO8IZmQoW8fgT04K2oFDMiGIYQ/
         9V3+NNtNhJEIXXNhhWFVd+PzgNe2xsGOt/RMTnJSD8bk5EGdC4PB+KC8rR9OzoyumVkw
         wfeTjhpiIUbSWp3M+xknruurnvEs+rwIkaaL2LhyAzZBEe1gPnMZyTrolpt9WpoDAVmV
         64Al6ReZWXTtITiJ11nw87aTXe/4CgP3CEruVGpxh+lUQ0NQPBYRte9yXdUkkaN6h4Do
         yH8B+shN9lCQtEcrJb9ik1ZmvdGwDGgh68FTL3qsUeYcvekVw83n76oOV1QcBLGO7PAH
         W9/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXqZJLeJAkqZT9pZB9o/aNNHVqMr1xWpy2VVGjx2lWCL18hcaif
	YLsX2aLlodAVVuR0z+shPyU=
X-Google-Smtp-Source: APXvYqwdB2HSu1fH2+KHqnXkD77wSWifxF6vAd0xWnjzZo1KDL1kKMSSE3Tb9W4Ca0JReeF/Jo2l4g==
X-Received: by 2002:a05:6402:1acd:: with SMTP id ba13mr31096235edb.141.1572442235462;
        Wed, 30 Oct 2019 06:30:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a0e:: with SMTP id w14ls3350007ejf.7.gmail; Wed, 30
 Oct 2019 06:30:35 -0700 (PDT)
X-Received: by 2002:a17:906:4b57:: with SMTP id j23mr8908356ejv.7.1572442235063;
        Wed, 30 Oct 2019 06:30:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572442235; cv=pass;
        d=google.com; s=arc-20160816;
        b=SWKPf1UdBOoWoWuYGOiRUsIIf8j5yVx7Bz0OBMF3TWb2ioT1ZKLvEVXcuTIOJ4GUeG
         fQ8ZzMagFmcMTiU5fHLcPHQWxCiT5+PrnxN9V4HKYJFR9MEFk7LHfjSceUCjBYy4t6sc
         kRDgsAzCbYgIeqwuCf/hI0tyzE8tLqskQt6xeZV8hCL7JsdmQfeEA3qM1sAMXYCcIvGo
         9u03HRSTBIZ2wavBW+wzjDwFIG2av9DAwAVhBJpdr/lxpfsw3AcMyix/81vXwxaDW8Ck
         PLWNci8G5NYUd851QuchMhJZsKafHwyrmc9Y2bYq5v3EbsdEuEaj2OHLz943ZZXC/PSt
         FsYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=nodisclaimer:original-authentication-results:mime-version
         :content-transfer-encoding:content-id
         :authentication-results-original:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=YOlQJdpxvqJTdWGHUpQma/U0lGkPu5bZidooTum2tUM=;
        b=cYx2xtKrgvtzqLqW3rCE3llUpZkUU1qIfdSMclWelv7eQckyLJAsAeORc0BHWrWy78
         y9Bhg44jGh5Dv0AlNU+Yxfz8WBMlj31GYv5UzKpWDP5OJECclt0goSvP/8IMjz95a8tY
         PS80Xy/XtIALa5ZttlNRcnQ5uCALlMBuv7SK2Kwnso54rtrtgepuBfWpQadhNW5F23c4
         10zG9YRGW6VLNm3Zt5n9bcV3aAHY2rq8sJz3sW9DdvvE7AZv+cgbSQEtjlsHE9+lxThm
         M6SEX2pJtThOeNAhtWO6KT42Kqc3TbzdggfxbHfi5oNo7SdKd1PHtrEh1fwRU1ALkvGq
         8eMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=IyqnrH5c;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=IyqnrH5c;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.7.85 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
Received: from EUR04-HE1-obe.outbound.protection.outlook.com (mail-eopbgr70085.outbound.protection.outlook.com. [40.107.7.85])
        by gmr-mx.google.com with ESMTPS id c31si121273edb.0.2019.10.30.06.30.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Oct 2019 06:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.7.85 as permitted sender) client-ip=40.107.7.85;
Received: from DB7PR08CA0019.eurprd08.prod.outlook.com (2603:10a6:5:16::32) by
 HE1PR0802MB2507.eurprd08.prod.outlook.com (2603:10a6:3:e1::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.22; Wed, 30 Oct 2019 13:30:33 +0000
Received: from DB5EUR03FT043.eop-EUR03.prod.protection.outlook.com
 (2a01:111:f400:7e0a::208) by DB7PR08CA0019.outlook.office365.com
 (2603:10a6:5:16::32) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.20.2408.17 via Frontend
 Transport; Wed, 30 Oct 2019 13:30:33 +0000
Received-SPF: Fail (protection.outlook.com: domain of arm.com does not
 designate 63.35.35.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=63.35.35.123; helo=64aa7808-outbound-1.mta.getcheckrecipient.com;
Received: from 64aa7808-outbound-1.mta.getcheckrecipient.com (63.35.35.123) by
 DB5EUR03FT043.mail.protection.outlook.com (10.152.20.236) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.20.2387.20 via Frontend Transport; Wed, 30 Oct 2019 13:30:33 +0000
Received: ("Tessian outbound 081de437afc7:v33"); Wed, 30 Oct 2019 13:30:33 +0000
X-CheckRecipientChecked: true
X-CR-MTA-CID: 9c4973174b14c2cc
X-CR-MTA-TID: 64aa7808
Received: from e3cb1f4e04b8.1 (cr-mta-lb-1.cr-mta-net [104.47.5.50])
	by 64aa7808-outbound-1.mta.getcheckrecipient.com id 2054DE4A-5624-4EF6-863A-06BF4650E203.1;
	Wed, 30 Oct 2019 13:30:27 +0000
Received: from EUR02-HE1-obe.outbound.protection.outlook.com (mail-he1eur02lp2050.outbound.protection.outlook.com [104.47.5.50])
    by 64aa7808-outbound-1.mta.getcheckrecipient.com with ESMTPS id e3cb1f4e04b8.1
    (version=TLSv1.2 cipher=ECDHE-RSA-AES256-SHA384);
    Wed, 30 Oct 2019 13:30:27 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=jAj8xqbb8Vyohnh4S26skfmO6VpgTPbsLav/IVnOogUFOtTEKftroXh5cY3wJVUW15u5JFYiiSohM0lbdriYz83SMGHVF5aQZKYhAfq7kV0hq8aM5oYQR8S9XTrbTwCdqf3WK2hwXLGJNPW1HcGZVKo3Ym+wx4uqE7To48WLgd+wja42mpi10Aw22YkNlA14czbsjeMn55/9WAYh+Zj9FVUpBlP25NwJiCXOgJuEz5qT5ST37o/dQnNrG93VsOC+c5oDHfK0YTtvPWulG2J63j87ZjEBeZq89V76PqhSBzgE4v66VJsh+qKEi94TTWipHpvGCfGCHgMny5Mi6Xhcqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=YOlQJdpxvqJTdWGHUpQma/U0lGkPu5bZidooTum2tUM=;
 b=Egbpaw8lA/vEwqVfdlrvuPTKhPrA7sacwJcvBJddd7aPbhNKv88S8HhfZ+p5dOg7cIogrCDZAFSLuEYnZDfIbDYK9YwRRcrEEi0ecseNlFL4GVQslE2bN92edXmG6UjwC9t75P2C95T9oiG3No6mWfMTkZgOKC0dz/DS8Zce3aUNgNie58l/w37nWaVOOUhN0DE4aYUUCYlnt2vM3e56H647sdQLu33Y4W1ewZn6HR5W+33Ihr7C9KXywSmXCT5M7yyeBt/bxf5H0DhBVPfpQJntcnDtdPtRBOEt8GUBdZTxKpDch6t7amOnPi27PS0crEomIedzGNKCuhIfPaGrLw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com (52.133.246.83) by
 VI1PR08MB3855.eurprd08.prod.outlook.com (20.178.80.139) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.24; Wed, 30 Oct 2019 13:30:26 +0000
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339]) by VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339%3]) with mapi id 15.20.2387.027; Wed, 30 Oct 2019
 13:30:26 +0000
From: Matthew Malcomson <Matthew.Malcomson@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, kasan-dev
	<kasan-dev@googlegroups.com>, nd <nd@arm.com>
Subject: Re: Makefile kernel address tag sanitizer.
Thread-Topic: Makefile kernel address tag sanitizer.
Thread-Index: AQHVhCNNoOSr1ytgiEqSG00mmgt5mqddSDEAgBSwtgCAAAFugIABScIA
Date: Wed, 30 Oct 2019 13:30:25 +0000
Message-ID: <b135bdce-8fd3-c81b-72d1-6a162307f6be@arm.com>
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com>
 <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
 <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com>
 <CAAeHK+yP2vK06tnx2p=NT8cD_qz_gV_xkuPZ40b2OAe+zxM-EA@mail.gmail.com>
In-Reply-To: <CAAeHK+yP2vK06tnx2p=NT8cD_qz_gV_xkuPZ40b2OAe+zxM-EA@mail.gmail.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-clientproxiedby: LO2P265CA0393.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:f::21) To VI1PR08MB5471.eurprd08.prod.outlook.com
 (2603:10a6:803:136::19)
x-ms-exchange-messagesentrepresentingtype: 1
x-originating-ip: [217.140.106.49]
x-ms-publictraffictype: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: d2a8f6c8-6103-4d49-5a39-08d75d3d5725
X-MS-TrafficTypeDiagnostic: VI1PR08MB3855:|HE1PR0802MB2507:
X-MS-Exchange-PUrlCount: 2
X-Microsoft-Antispam-PRVS: <HE1PR0802MB25074966256A5BFF8F856F54E0600@HE1PR0802MB2507.eurprd08.prod.outlook.com>
x-checkrecipientrouted: true
x-ms-oob-tlc-oobclassifiers: OLM:10000;OLM:10000;
x-forefront-prvs: 02065A9E77
X-Forefront-Antispam-Report-Untrusted: SFV:NSPM;SFS:(10009020)(4636009)(39860400002)(346002)(136003)(376002)(396003)(366004)(51914003)(199004)(189003)(8936002)(71200400001)(53546011)(86362001)(6486002)(76176011)(26005)(486006)(71190400001)(52116002)(3846002)(6916009)(31686004)(386003)(229853002)(6116002)(44832011)(186003)(81156014)(81166006)(6436002)(8676002)(102836004)(99286004)(66946007)(66066001)(66476007)(66556008)(66446008)(6506007)(6306002)(25786009)(54906003)(14454004)(5660300002)(256004)(36756003)(966005)(7736002)(305945005)(2906002)(316002)(64756008)(478600001)(4326008)(14444005)(11346002)(446003)(476003)(6512007)(6246003)(31696002)(2616005);DIR:OUT;SFP:1101;SCL:1;SRVR:VI1PR08MB3855;H:VI1PR08MB5471.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;A:1;MX:1;
received-spf: None (protection.outlook.com: arm.com does not designate
 permitted sender hosts)
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam-Untrusted: BCL:0;
X-Microsoft-Antispam-Message-Info-Original: JapaDIfTpVOJuHLKEj2PI/aRyCM0nG8EK+s8pgwZTcfFAGVObk7si3TiAM8DWCI+5X5S3GsGxan/4JuoQRmq1BIYZADSoJEDpX6sSHY8491INql3Rb8hfwroLeF7xVGefG8oBH95oOBnBHV3rLM9vMeoxAuhlkETHTunUe/RB8uCTPpKGNcB13bnNbsLJq+jjzi56g0IM68//IK7wDsqJxgueTw+emn4P3IoANHNoBR88u0P4luzsijvLSEQCgGV2ym2LFk8VayxojTFJzNv7btA/ra0rRJYn3fiFDQqa7qYkI8+M3Ni4rfFgEXEm4zNegoUegiuhV/ah9GSpf94M49gVBtlG1wbjx2YUF1bjLxp4BWqzV0M4srNFBMV5rmhVnq9MNdRsqcZuKY+vmooF1GxPkKOEXFypbiXEUAiAwPEOsmQSoPaDu8ziELQfisYXvVHaEmlJQKPKOizN6Tweunqj3g0vxsTLBuwuAnQ4kc=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-ID: <FDF62D1FA8B6154F853004C22F2D525A@eurprd08.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR08MB3855
Original-Authentication-Results: spf=none (sender IP is )
 smtp.mailfrom=Matthew.Malcomson@arm.com;
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB5EUR03FT043.eop-EUR03.prod.protection.outlook.com
X-Forefront-Antispam-Report: CIP:63.35.35.123;IPV:CAL;SCL:-1;CTRY:IE;EFV:NLI;SFV:NSPM;SFS:(10009020)(4636009)(396003)(346002)(136003)(376002)(39860400002)(1110001)(339900001)(51914003)(189003)(199004)(14444005)(53546011)(6506007)(356004)(81156014)(81166006)(102836004)(4326008)(386003)(2906002)(6246003)(76176011)(23676004)(186003)(8676002)(8936002)(2486003)(66066001)(6862004)(47776003)(26005)(3846002)(229853002)(36756003)(6486002)(6306002)(54906003)(6116002)(105606002)(6512007)(99286004)(70206006)(486006)(70586007)(126002)(11346002)(25786009)(446003)(31686004)(7736002)(305945005)(14454004)(50466002)(26826003)(76130400001)(86362001)(2616005)(336012)(966005)(476003)(31696002)(316002)(22756006)(436003)(478600001)(5660300002);DIR:OUT;SFP:1101;SCL:1;SRVR:HE1PR0802MB2507;H:64aa7808-outbound-1.mta.getcheckrecipient.com;FPR:;SPF:Fail;LANG:en;PTR:ec2-63-35-35-123.eu-west-1.compute.amazonaws.com;MX:1;A:1;
X-MS-Office365-Filtering-Correlation-Id-Prvs: 8949a9c6-f3e4-4d9f-d05f-08d75d3d5289
NoDisclaimer: True
X-Forefront-PRVS: 02065A9E77
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: zr3eS2M+taTon333HqTe14svNIlFdc/ZNNFTJmt9CSKiE4AWlQFjDGqAIylSX7TUULtDVI9VLNEBFd5i3yZIhjdQj7uo92FjRbElRuV0zPTpI1VifTHArLWmb4KfYbZHCTCuSGRLK6GSHFazxhn91Ql6RVD+jhfhLkuPi85D7fNBfCaM67UJtgWs7qJNCqsYeIqBB1JCePT5WSVC9PeqCptZbcrt5vsq6FzSoKOWa5QD7AYOpBDAB9/1VDz9UCTQJcxKsnz7LW96QJ/oOpD2xfE7qHqiypkdtKIH+HC6+bTQH//N4tSdTxNbmlOmTkwEwah1gbnfOtMjWQ1mqfxt/GA7t0yFKYRN+okdFXD7/qtGFnIgnegvFBKWBZS49BdZ3mfc6jiInLOOxwnJIJ8OUgLkpxoIQqGSdwWxpXRHhbqD5onzgxIiMbovehCap8ntIN+emfnIAHFcXxSiblX0bLUrTk4dkGKlEeY/gt1inRA=
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2019 13:30:33.0907
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: d2a8f6c8-6103-4d49-5a39-08d75d3d5725
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[63.35.35.123];Helo=[64aa7808-outbound-1.mta.getcheckrecipient.com]
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0802MB2507
X-Original-Sender: matthew.malcomson@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com
 header.b=IyqnrH5c;       dkim=pass header.i=@armh.onmicrosoft.com
 header.s=selector2-armh-onmicrosoft-com header.b=IyqnrH5c;       arc=pass
 (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 matthew.malcomson@arm.com designates 40.107.7.85 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
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

On 29/10/19 17:50, Andrey Konovalov wrote:
> On Tue, Oct 29, 2019 at 6:45 PM Matthew Malcomson
> <Matthew.Malcomson@arm.com> wrote:
>>
>> Hi Andrey,
> 
> Hi Matthew,
> 
>>
>> Thanks for the clarification on that bit, could I ask another question?
>>
>> I seem to have non-stack compiling with GCC running ok, but would like
>> to have some better testing than I've managed so far.
> 
> Great! =)
> 
>>
>> I'm running on an instrumented kernel, but haven't seen a crash yet.
>>
>> Is there a KASAN testsuite to run somewhere so I can proove that bad
>> accesses would be caught?
> 
> Kind of. There's CONFIG_TEST_KASAN which produces lib/test_kasan.ko,
> which you can insmod and it will do all kinds of bad accesses.
> Unfortunately there's no automated checker for it, so you'll need to
> look through the reports manually and check if they make sense.

Great, that was really useful!

I found one issue in my instrumentation through using these tests -- I 
haven't defined `__SANITIZE_ADDRESS__` (which means memset calls aren't 
sanitized here since a macro replaces them with __memset).

Looking at the current kernel code it seems that for clang you use 
`__SANITIZE_ADDRESS__`, for either hwasan or asan.  (commit 2bd926b4).

Do you (or anyone else) have any objections to using 
`__SANITIZE_HWADDRESS__` to indicate tagging address sanitizer so they 
can be distinguished?

I can provide a patch to the kernel to account for the compiler 
behaviour if it's acceptable.



Similarly, I'm thinking I'll add no_sanitize_hwaddress as the hwasan 
equivalent of no_sanitize_address, which will require an update in the 
kernel given it seems you want KASAN to be used the same whether using 
tags or not.

Cheers,
Matthew

> 
> Thanks!
> 
>>
>> Cheers,
>> Matthew
>>
>> On 16/10/19 14:47, Andrey Konovalov wrote:
>>> On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
>>> <Matthew.Malcomson@arm.com> wrote:
>>>>
>>>> Hello,
>>>>
>>>> If this is the wrong list & person to ask I'd appreciate being shown who
>>>> to ask.
>>>>
>>>> I'm working on implementing hwasan (software tagging address sanitizer)
>>>> for GCC (most recent upstream version here
>>>> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
>>>>
>>>> I have a working implementation of hwasan for userspace and am now
>>>> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
>>>> CONFIG_KASAN_OUTLINE for now).
>>>>
>>>> I notice the current scripts/Makefile.kasan hard-codes the parameter
>>>> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
>>>> variables, and found an email mentioning that stack instrumentation is
>>>> not yet supported.
>>>> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
>>>>
>>>>
>>>> What is the support that to be added for stack instrumentation?
>>>
>>> Hi Matthew,
>>>
>>> The plan was to upstream tag-based KASAN without stack instrumentation
>>> first, and then enable stack instrumentation as a separate effort. I
>>> didn't yet get to this last part. I remember when I tried enabling
>>> stack instrumentation I was getting what looked like false-positive
>>> reports coming from the printk related code. I didn't investigate them
>>> though. It's possible that some tweaks to the runtime implementation
>>> will be required.
>>>
>>> Thanks!
>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b135bdce-8fd3-c81b-72d1-6a162307f6be%40arm.com.
