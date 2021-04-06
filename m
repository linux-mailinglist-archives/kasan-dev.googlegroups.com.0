Return-Path: <kasan-dev+bncBDV6HSHYYYKRBPVWWCBQMGQEBXFPS2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 94CA8354E86
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Apr 2021 10:26:39 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id v19sf2155131vso.11
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Apr 2021 01:26:39 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1617697598; cv=pass;
        d=google.com; s=arc-20160816;
        b=K4QRXfdo9L8GGVJq5FAoUSjDfB8VjBbV7QalMaHoeHOAslAsqV5km3D2g3NNmungvr
         8XTfbCYyOamcMbpN89Hescyx7rMgJoFE5EZ3ndxRmTmnz2IXdt7Nz9yinboyxyEZbSEJ
         Dz5c+OCuBgON8GH+Zp5WLgs5C2gMZ+bAcpf3sYg3n0skNUhxFNpRA/2yPXux36IAZP9N
         ujsr/xfmwkjx+CRu1a6gEkaNAZ1nV8/1F6ElP0HfFCJmp+2t6WXdSTUZ8I9a7Zi0F40Y
         XRGtsVtrvS8U72b9gq755FTUpBksueXU97eMv8MD0g/TrCFz4YO0l6Jrw/LpBO5jlHSv
         RA0w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=hJZ3Yg4s5RqYsTwBPHM6U6bIM2d4Wft2Bi+ObC/C2us=;
        b=YwR34jOjVHNTJu5IM/W3MCkOOxyeyEvHRGeRUShOQomDWNDFyNwkzzLlCdL8+jtN97
         AvEs+imJo2K6u3MevPJgqeyGJIdxgwKGnCyeQHLhTnWhknotiUVgBmII9QHR9bBp9N6L
         qxvcYyCUs7gZw4F6mp9mtCOM1mRRMmNdBONU275Bk76alAoiXqYoQchX4DUw1NUrwjJ9
         OrhSEIFv3qGZPK+aBZFuGn6f3fj2lHdHTpIDnkefVIHYTrgEx6l6zuqpUbEVsdb5N3T6
         CHZ/mdseil1I/Grar8kooYTIkDhSuDgDYkH90eU3vCFDrY8l8twRvqTqQeDqQIaWdQdH
         imug==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=G0hvW6Wh;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.243.44 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJZ3Yg4s5RqYsTwBPHM6U6bIM2d4Wft2Bi+ObC/C2us=;
        b=ggKTWdXvmBqrVm8/fcWZb7BvpTl2sAb5xLyWwlO5C5EEayP61Jzm2CV/Wfj6f2h/Ao
         swCnK11gHyxZYCpnLiOhfDWGT1VletiIrbG6GtliAj1xOKjXboZUCTS2tsHnlLY13h3i
         dI9Oy8KCYG1JXFcSzrEcYNSA+Fmz8xHE4dtjw8GmnOBMlEAO82HRCM0T/xr45a94YdLV
         yhI0ul/PtQiCwC7Hpmw9fdPQxSyRTHy2FBMYRcbZU11FghvfikHoZQba5gpskm32nB92
         jrLoGO6tyZhyHbOzWPVqhMqyUAv/vQ2wiMmvbR8Uw+nSI4iTzNrN6XYZBgJGHrN5Krw9
         cQkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJZ3Yg4s5RqYsTwBPHM6U6bIM2d4Wft2Bi+ObC/C2us=;
        b=COTxN+QvmcJ8Hb4znWXXz2dg+AgyVajpVIl5ncUy9TKlvnjfMGko3AfmO7Dk43Qpig
         N5bF7vH5bsVmPxSmEsNNTdplYQcOMh8l7rpZRISLVv/jq1ZuhvioxuSNHCJ2BC5eTRUd
         y1Kme9Y3an3EY/hm7osLyfGQC6vHYZbJmquDEISsNdKTuIAu64SKlqDkcVd4A2U8aZrf
         Bt/9DxFV7Z51NqQVfnYquQRPE74ex062xo2k1DVta39eNLyWfJqy11wESu3K6oXfDB8k
         jcl5Ef81n5LF3wgYPB1ZzRTP1S5Kg4GlmTKrtno+nmLThPXoZX6ZX2NF9MVhGCAVOkpP
         2r9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531b8CTJUZn423h1sUaX1gIFp4fVGKkONCnmhNAWXLifhOGt8xLB
	70iSaTLy5Zyx062w4QHmaVg=
X-Google-Smtp-Source: ABdhPJwtKtrFaL2wZkmGJaD9BlRZ+83EMz30IsgpuQFgdLLVx5Tlmi9dWMojY6EPImXHve5bI6VEXw==
X-Received: by 2002:ab0:2104:: with SMTP id d4mr15711181ual.105.1617697598270;
        Tue, 06 Apr 2021 01:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:a4d:: with SMTP id i13ls2166044vss.10.gmail; Tue,
 06 Apr 2021 01:26:37 -0700 (PDT)
X-Received: by 2002:a05:6102:734:: with SMTP id u20mr13094309vsg.47.1617697597606;
        Tue, 06 Apr 2021 01:26:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617697597; cv=pass;
        d=google.com; s=arc-20160816;
        b=XnzZwBzTJ1r0XgKBflA37r3h480a8Mt1S5KxF5KZ1RfEZFCkrUzgCorQoU2KjQybn3
         gcMRyyKNdCRNDWKtaojdTrv5L6J0pJz9p7yVUwY5lsb7hLiL5jWXeCAJ3MoT9F0tSByP
         Bs80CrjDlnRMzb4j6+sKWMGQBS35RuVakU0Kmr3DL9iwfulxTZrKQFHfwShkyczLhLTN
         BFZFU1UeI6OZrBxcQp+sLXTdlq0vW0TIstP2WRM5uWFgjtXNPbtuoe96M/XXgEAw+wKU
         i8t1FoIuKDPCF3b5UXojg/EbTEhHUH0K2X4wVNQoFtB+cStW9hlV2hCYCVdWLtq6lWCR
         n1+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:dkim-signature;
        bh=qu2eGzM0r8xe6NO0RnCDtJD4yOdyLaF1eaXsu4SovrE=;
        b=eevurNvIax8DlqP3829Holm/iNwTbvGF0UJefSWpRW+/Y30x6e36vj8JprZs+ck2QT
         Zz+LXLXwzd0OLAAjJnV0regzdBXx5F4wjbu2zrxuv6ijJ5vrjAxHjgq4glgsvmc7TUaI
         h+/GXxpi9XQBtacl5NEuq9/kYOf5ul8q+cB030UDO2mZC3KQKrZQGS4U9GAA/yU2Wrq+
         LNzXjA4aT+eJVUGR93sT1GlkL9gwi09UbqaVwLP/Mbv8fUk4N/0tLFy5TvIyKuP6UBvC
         +LAx8umnkmGQr80/2VbSBMKqhb5OCSZC/QHMsoKpsGVZj99pjWwerrmO29bnw0oOaTLW
         qThQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=G0hvW6Wh;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.243.44 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on2044.outbound.protection.outlook.com. [40.107.243.44])
        by gmr-mx.google.com with ESMTPS id i8si1299861vko.4.2021.04.06.01.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Apr 2021 01:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.243.44 as permitted sender) client-ip=40.107.243.44;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TvJmQSIrj66Huugzx8wz+MM3sJA3owjteMJgOh60e33InEo6senD7w62wZiaZwofgrLKn4/7xHPvUyZ/V8fR+KVywE5GUAvaMus2VDojtPhidXlgN3xmtgk79KWxi1a7VRfIPkx97jOJmdnWGXqzyPg+4gO6vBLnLbpRJN5A8XfU+Jf7n+ZNrNRWXM0QZCGkqvCLjdHb/rSKpTVA+S/9ApbY5qx7xMtcyye3jDrCNJzEP/aJGhAjQDBsr7QPI89Ox9vLc+j/uAcobcyahP3NPQNqu+RcE8HXzxfHDN5umf+bJQu2wZLoeN36tAduKVpwC2pLajYN1yMSAh1TEotAWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=qu2eGzM0r8xe6NO0RnCDtJD4yOdyLaF1eaXsu4SovrE=;
 b=jgGTlm8BlXPH5PgvxHAykm/PozlrtymkwwiKM5dEXoALDCS/7X3oYbyICfb/h8qQb0EWndotPkZ5tkp7spx742LRAzoDIAE7pNihamvPcUCMmZXgGvx+pMqx12fA0CEqPXfzIa3GcUNDuVL3VUfPTh6RZ6hyfKn7BBOllzetVXZQ0qh5YEJlT9/z03oIgu1WSDwLL6zBJNoWn6ajJW/W4ZXxqvsRuMHR/0764nZhNmE02qQt69rOuINp0rQUB5DUU9lxTFq0fWRypDFBns5fttry51GX+hkRLUtCmXYibtT8zzgI2ZQYb7llxmquicmN6L+LEMGlH/YWKI8S8HW6/w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from BY5PR11MB4193.namprd11.prod.outlook.com (2603:10b6:a03:1c8::25)
 by SJ0PR11MB5119.namprd11.prod.outlook.com (2603:10b6:a03:2d6::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3999.32; Tue, 6 Apr
 2021 08:26:34 +0000
Received: from BY5PR11MB4193.namprd11.prod.outlook.com
 ([fe80::b17c:f05a:9c88:8f65]) by BY5PR11MB4193.namprd11.prod.outlook.com
 ([fe80::b17c:f05a:9c88:8f65%5]) with mapi id 15.20.3999.032; Tue, 6 Apr 2021
 08:26:34 +0000
From: "Zhang, Qiang" <Qiang.Zhang@windriver.com>
To: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Question on KASAN calltrace record in RT
Thread-Topic: Question on KASAN calltrace record in RT
Thread-Index: AQHXKrzDGHQ+LKiz3UinMerWnn+L4w==
Date: Tue, 6 Apr 2021 08:26:34 +0000
Message-ID: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [60.247.85.82]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: a9407824-ab5d-4176-a512-08d8f8d5b080
x-ms-traffictypediagnostic: SJ0PR11MB5119:
x-microsoft-antispam-prvs: <SJ0PR11MB5119B7277D572D63AD76C8EEFF769@SJ0PR11MB5119.namprd11.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: GT+VCnlaxgEcLSPe/iqKDZD/tf78RHLK2MG8shaoQ0nipC5urLRCMtEn0+7TxKOcV1yaKUa+3+cTgsvrJu9OfVVNyloprMWx9y6uqb9kXwsBMUVqBzCHflUmg6VSZHlD4eNYWFkkCC5NVqzAtZ6I3rhmpAbOfsc6qd4+ufJTrPx+YhXWgOCHpJPUgZqcia9pCfq1OsvSivtAO4HqzHxSR67kj+L6hvV7TNifSnVZmyxSG63z9oGclDGr1rrAfznLk3xjS2GCdfCXP+IGleXUq3/pRkAQZgYlw8bvq+sVuYwWWTHPRoPNlZC9Fuk2bl/gsbM1hEoXM8SMzXdKgUExVswYZU9sZdPJlmy+0j152FGXT3UvBp9cCdmESjLid+2gsBlaoG6+7LkTKlyPZYzFa6tDSXGF9Vspk2WdbESPjDEfFcHx4YWob5sspthWPqWJN5K3NgL+qHgE+fZMaih9H5yXgg+mVxkuGt6B4VIuX7I5eAVILR4il9Mb2JZXCSIB4fAduClwrGlF07V+xJ0GsUq+BdFTd++y8pCNYTnqW9aZsW1dctXLpyYS8LD2I/sP3skDML7mLmPN00q9dwJpUbcFKUR3LKMT+2Q3+Wf0iuTGTH6vxJX9cUH7CfB/9F0CU7ZKLbboRoPthyWn10RMFw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR11MB4193.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(136003)(376002)(366004)(346002)(396003)(39850400004)(66556008)(33656002)(76116006)(7696005)(2906002)(8676002)(5660300002)(66476007)(6506007)(66446008)(64756008)(66946007)(4326008)(8936002)(52536014)(71200400001)(83380400001)(316002)(86362001)(38100700001)(478600001)(55016002)(9686003)(91956017)(26005)(110136005)(54906003)(186003);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata: =?gb2312?B?SVp4WmR0NFV6Vnl4UkVTZUM0VmRIeFE4bEpkdFIvdkdQY2wwTUNEUGdvWnpv?=
 =?gb2312?B?RlNmU2Nlbkc5Rll2QTU2cWR1ZmlIY212TUpmbEk0eXBsZ2tvYWhxaWlxRUVS?=
 =?gb2312?B?UEJiL3NXekNQRjVNbDZOdWg1NWxkQ3NYNC95YVM3U1crVzVLaUJYdkpLUE1B?=
 =?gb2312?B?a0o3a0JuUUdKMEMwRDc1YkNzMTRQbXNhbUsrdlpNTHExd2VUV3NyRW5MSGph?=
 =?gb2312?B?d3dZM1E5TERVcHErN0V2L0V2VHpFNjZYdmpKczJuR2tZU3htME03MzQ0ZVpk?=
 =?gb2312?B?NTdEVGhKcUVTQzZKVTIzS0dWVGdaMWtmNkhTNWRFd3o1U1Z2Wk1RMXNYblEw?=
 =?gb2312?B?ZXk4NmFKTVlYdzEzcnV6UHg5dnE3a3JrTTV0dVdtRjk4S29tTnBLM2EzWU1P?=
 =?gb2312?B?anRRUktCTWZqL3NJVUJhaCtqWFYyRy9NQ3JWdTE2Z2tmS2I2c2UwTzBLQjQ1?=
 =?gb2312?B?NlVRSDhyYS9hK1FveFVRMHk5YXVUeUg2WmpYWE56aHgySVQrTjFLcktKUTRP?=
 =?gb2312?B?NEZsRlVXSm9rVVA4RzY1dTljU05qdStUeTNSQkpXU2N6V1FlQzFCQ0JZd3VG?=
 =?gb2312?B?YTZaRnRUUC9MYTUxTEJ4b0VhdDk2eTZ5NFg1UkJsZGhGcnJkUjRrMGp2UWtu?=
 =?gb2312?B?NmxLY0w3dndtMkdlSFJnMmZhQ3phVUFvTjJuNm1RQ1FIYU0zdkJGMmZpR1Yw?=
 =?gb2312?B?NjViQTNXTWtBdW9DRWNISm90Y1FMVHduOXRhdjRaczM1RFIwcTNqLzhxUWVJ?=
 =?gb2312?B?VStsWC8rS3VjeTVaYm5ya04wcjFadVMwSkt6MGgxQWRUSDAreGZIbmw3NndV?=
 =?gb2312?B?dHZJZGJtTnNKL1hlRDNFb3RKd29McFduQVlXS1k0cERJbmk1bUUrYkJZbkpC?=
 =?gb2312?B?ck0welhNeGQwMndwTmJRVHZyTmtTa3NXZXFTNnJ5WGx2NFova0V2ZUY2YWFO?=
 =?gb2312?B?dzROY3hUL3FEMytMNVlaYk4vaGJ0UkRRcjBKVnBTZlV2SVlIb3RYcnY5OHNw?=
 =?gb2312?B?TnZGVWJNcERSMzVOa2Y0RHpDZVFUc0FKZlJhYk94ZGU4bFUvRGhwVG5hSExw?=
 =?gb2312?B?cWIraTZOZXAvN0JrTnczUStDbDVTejlaakI5bkM3RU04clZJaVVlMTNjQUJB?=
 =?gb2312?B?dDcyM1A2anN4RGJ6VjhBeDUvcWtQd2wrMXRKWVp5VElISGtnV3RPckdyYy9u?=
 =?gb2312?B?ZU4wbFZQNEIyMEd1cDYyajJMRE9WNDBITW8rTVc4cEhQc0RuUjRnTWp4WUo5?=
 =?gb2312?B?Z3VzUFIxOVdwNzY3SEpWVE10OVh3M0owdyswVHQ1OG85cElUN2V6anpVa1JK?=
 =?gb2312?B?eWpQUnJwbEJlaFQ2TUk2Y0Y2Q3htYUR1eXFzRkxRSE93U1c0UHFUWGNhcnVX?=
 =?gb2312?B?ZGVVNFF2T3pWWW5HT2syTnpsTzFCOEc3R005ajUrbitNU1VxM2xxK09jMC9U?=
 =?gb2312?B?V0FzbURVQkRob1FuV1k3TitMczdiTElhUE1vOFRLeEhSY1dMMndOcVFncDNY?=
 =?gb2312?B?MHFJUGRoNG11RDVuenBvRmtDVGcwdElvNmtON1JsY0l6SkVHZE9WWG1uZWh0?=
 =?gb2312?B?d3I3dHpkV1pnR3hBQ3E4WWFhNjBxMTNJSjF5MHhNVHdYTEQ1cWl2K00yZDky?=
 =?gb2312?B?M3BEUnB1VFJSeVkxa01KVFMwc1p5MmNQbDd5WVNmUGNrZEhEek9qL1ZBUjFB?=
 =?gb2312?B?bUxJTUpYNk5iTXRrUXRqaktJeGwwM2pXWUJla01SQmFOUURBcVF1MEJsMFJG?=
 =?gb2312?Q?nP7pXtxrhw+lpJCH0g=3D?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR11MB4193.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a9407824-ab5d-4176-a512-08d8f8d5b080
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Apr 2021 08:26:34.3789
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: TFVkcvFCRziJDnBu3Bk1Q04uxZVsGbFOdpYVbkh1y7hnO7KaT/BaItSfMc19zrXWZOaMzESaMtfYgMgmh34592IpLaE6zX2RB40D2kARtrs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR11MB5119
X-Original-Sender: qiang.zhang@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com
 header.b=G0hvW6Wh;       arc=pass (i=1 spf=pass spfdomain=windriver.com
 dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates
 40.107.243.44 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
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

Hello everyone

In RT system,   after  Andrew test,   found the following calltrace ,
in KASAN, we record callstack through stack_depot_save(), in this function,=
 may be call alloc_pages,  but in RT, the spin_lock replace with=20
rt_mutex in alloc_pages(), if before call this function, the irq is disable=
d,
will trigger following calltrace.

maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record callsta=
ck  in RT system.

Is there a better solution =EF=BC=9F
Thanks
Qiang

BUG: sleeping function called from invalid context at kernel/locking/rtmute=
x.c:951
[   14.522262] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 640, =
name: mount
[   14.522304] Call Trace:
[   14.522306]  dump_stack+0x92/0xc1
[   14.522313]  ___might_sleep.cold.99+0x1b0/0x1ef
[   14.522319]  rt_spin_lock+0x3e/0xc0
[   14.522329]  local_lock_acquire+0x52/0x3c0
[   14.522332]  get_page_from_freelist+0x176c/0x3fd0
[   14.522543]  __alloc_pages_nodemask+0x28f/0x7f0
[   14.522559]  stack_depot_save+0x3a1/0x470
[   14.522564]  kasan_save_stack+0x2f/0x40
[   14.523575]  kasan_record_aux_stack+0xa3/0xb0
[   14.523580]  insert_work+0x48/0x340
[   14.523589]  __queue_work+0x430/0x1280
[   14.523595]  mod_delayed_work_on+0x98/0xf0
[   14.523607]  kblockd_mod_delayed_work_on+0x17/0x20
[   14.523611]  blk_mq_run_hw_queue+0x151/0x2b0
[   14.523620]  blk_mq_sched_insert_request+0x2ad/0x470
[   14.523633]  blk_mq_submit_bio+0xd2a/0x2330
[   14.523675]  submit_bio_noacct+0x8aa/0xfe0
[   14.523693]  submit_bio+0xf0/0x550
[   14.523714]  submit_bio_wait+0xfe/0x200
[   14.523724]  xfs_rw_bdev+0x370/0x480 [xfs]
[   14.523831]  xlog_do_io+0x155/0x320 [xfs]
[   14.524032]  xlog_bread+0x23/0xb0 [xfs]
[   14.524133]  xlog_find_head+0x131/0x8b0 [xfs]
[   14.524375]  xlog_find_tail+0xc8/0x7b0 [xfs]
[   14.524828]  xfs_log_mount+0x379/0x660 [xfs]
[   14.524927]  xfs_mountfs+0xc93/0x1af0 [xfs]
[   14.525424]  xfs_fs_fill_super+0x923/0x17f0 [xfs]
[   14.525522]  get_tree_bdev+0x404/0x680
[   14.525622]  vfs_get_tree+0x89/0x2d0
[   14.525628]  path_mount+0xeb2/0x19d0
[   14.525648]  do_mount+0xcb/0xf0
[   14.525665]  __x64_sys_mount+0x162/0x1b0
[   14.525670]  do_syscall_64+0x33/0x40
[   14.525674]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   14.525677] RIP: 0033:0x7fd6c15eaade

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/BY5PR11MB4193DBB0DE4AF424DE235892FF769%40BY5PR11MB4193.namprd11.p=
rod.outlook.com.
