Return-Path: <kasan-dev+bncBDV6HSHYYYKRBA5F3KBQMGQE66E5OJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EBBE35EDA5
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 08:58:13 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id g7-20020a056e021a27b02901663a2bc830sf706236ile.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 23:58:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1618383491; cv=pass;
        d=google.com; s=arc-20160816;
        b=H50iqr1wuyVjtgh43taVO2xhduafHR1F+6jJ75GQaC5bePX8GOm9fWF1oK7MP7S90e
         QfyMGvd+k/hoH/ne42je5yT22JH84OYfQuieRo9Xmjo3Y4gl8i5Xz/Eg1jN7ylhnBdO6
         PM+Sd4fniVa118sI7oKsNTr/oUt2bSb7KcTE6Mx1HJoX3qiIo8wqJ5y0KDV6gydYlvTp
         k9UbIceEytL4ZLD3qvIT11f6QbJkkDfjBtPbLO9rWxDn4AlHojziKnIF/H5xrLeB1Yyy
         cHU4me+fn6g3BbmCuO6JtW/iXSXnQUYtPXQWvbLnssoy0VnjKVzdiI2PO1lsjCaD87GQ
         P4Fg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=D7sNQdfbJr34kYu4f8an8X01HM3P+vltPzMbaJKmF1c=;
        b=VbT0k1CyMBdgckiXqEMBPuxSHrLcz12/MBaDDhnh55WoLNCk3Y14KCan+PzIh3zNR3
         1OM3FyjqkEwjsDxYWnZlGKWEAHGv0RIyyfY1oWhMk5cgwM4oUa7gMZOQU6c2UdivLhYv
         17IqHiDG8x3GhFuRHHM4LuwOf/ZPC3koi1/q/7O56f5ZA88O064Bon8VmkwDWYAlJS9X
         Yqa+uRnl0Ldxhpyukjd0tYFAX7r2T+hNXvQYuPo9IWjpf3+CRKQkdAKAxxZuODjTC7f7
         V99sQd2DtfeFnZfapVhSd8Xi2j3T/x47kyC8FDRBSgh1JU9zUppC1IHa1Fv6lePdstU0
         LWBA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=llaDU6xb;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 2a01:111:f400:fe5a::605 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D7sNQdfbJr34kYu4f8an8X01HM3P+vltPzMbaJKmF1c=;
        b=VdxArLoYoao2YkjvpzV0dSZhW7OBFlicin5d6cYFyrugJqqkost3nJBbmaikhXNMwt
         YbUPXU0MH91ldWMzI+FIQEULBa6eDQagwTI8xURvQcBSGHtd46I+K/MQAANko94Tokcl
         eSJ7BkggfuasyecZJASvoWRd/I6fXln9TkFWOShbIVYQjAIjyH8T/TdDVxl+YA4TxNpM
         T01Z1/YeeANfMeOoZdovbd4v/6WHanG3xASRNiqKkPvdvaklDJRku+sCGykpOs7SSpPc
         lNg+xNKdM25H+4LptSAHoc0CBoT2S7Pt75r8ZJQ+kAMfijN2/vZ+8/JzdryjUSdcXa+X
         EYIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=D7sNQdfbJr34kYu4f8an8X01HM3P+vltPzMbaJKmF1c=;
        b=SFdC9dCnu0p9P91WeyOT6lHWv9hqNk0R6yJXKdKL7XZ0DK1FH/7TZxYvEcfb331elQ
         OMqowPIHQ6o57/Fi54LSq7972PVjsvosZV7O8J9SQYqRiIjqMzwXvvzrFlVacSzKE5mU
         VSlsUlMY1IC8HQK/iiC66+zsXWDmnAWnct2EcDGBC2iff8HSJvWLOupnJo79xUI+nG36
         o64ovvpfB2+/tYgJcQaZE5goOUIIQBP3BB9ZftsnxHWpT7uIDQDluo5TQ7DVb1aeIkdZ
         cqH6BwA+0i1BDTI6fIChi5yu1UBZ3lSxQFEazST15UMxzqBsPqDQIUdsZ4vxpF9g2JNd
         lceA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530c/dtk7BZw7ujiQ3IewCccZzE/1GRCwnkNBpG42EeWdsnLW/LL
	VCuYu13VNS3hcbveHbxpyzU=
X-Google-Smtp-Source: ABdhPJyrVI9UufNx/hOnDTzJfkIfeAlUigDIPL1OS9J0dLoiq1MT0CbL1qNRfLYA7z0kyT+9kO1r5Q==
X-Received: by 2002:a05:6638:389d:: with SMTP id b29mr11117986jav.46.1618383491642;
        Tue, 13 Apr 2021 23:58:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6213:: with SMTP id f19ls169570iog.1.gmail; Tue, 13 Apr
 2021 23:58:11 -0700 (PDT)
X-Received: by 2002:a5d:924b:: with SMTP id e11mr10651938iol.133.1618383491227;
        Tue, 13 Apr 2021 23:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618383491; cv=pass;
        d=google.com; s=arc-20160816;
        b=cnkO+WZkFoKizPatqA1iiOcQpFD6VkeJzhwXCj0K5COsI5tHGtXmeS8zsQYI7JgNkf
         aVgwVFnHgiIaWaSugEppRPJdox2sjhIVoKWJgcm0tZIDSsdG5TyyFbqEvmtf6q5ZCjMI
         BiuG5BHw+rOj9FTOeSApTlKPlEe6PI5DZhkM5n2gSuifleTW7VxEHEmcqEkZ5gugIMTG
         +MlRZOeF2k7olLj+Hlxha9L8WoTF1X32Te3pfao8ltWRIiuwnz7E6k/Z80NBFgfy9id2
         TiWEdkcFmcI4j83HLnW+3IjxQT5I2Ew1008dv8PtxjdQWoi9rbDvfUJJLdhEhAm2ZfJ5
         +oOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=1PhsjksrTr9zX0bfaRbqZ9HbLKGGnRNMeJIcFiSmngM=;
        b=ni6fqaeilaiFQkLLxz5qxCfAo9DiXcEO6JC4jPNKK6/oqQ79EjRY+6AUBLVG10/6hV
         W2UxrL+i1+VjYoXpm01WBkFGH/Wz5cVuY3QGFCm+JwRJY9mWU/+HtE8t49ys8xKtY8b3
         MP6PFdynhgP7Gchskdg70lwjKFZ/IDlzD2UiFJz/uiwOxI+hDJYGVYKH9sqjp+PiV7o5
         UmR6kfsT5YcOxuiwl1TSIYDmH52sqv3BjLdfdWx6lPHue9u2wGKTql+TNLFZENkFtztG
         qlG08nzp1nE3OPSUWbg/4CR/X9zXFFJqD7hk/ZfvAgE8/IY53tyroZz65bx/sRsxzMag
         gf8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=llaDU6xb;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 2a01:111:f400:fe5a::605 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20605.outbound.protection.outlook.com. [2a01:111:f400:fe5a::605])
        by gmr-mx.google.com with ESMTPS id w1si1069282ilh.2.2021.04.13.23.58.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Apr 2021 23:58:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang.zhang@windriver.com designates 2a01:111:f400:fe5a::605 as permitted sender) client-ip=2a01:111:f400:fe5a::605;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=PpfX2eVCksVtQqZeppP6WexvOOfWq61agUZFT2korqAHPO9z+DoA3SrqTUR1zR1eFmcOVGcAu7c+WYeJ8weIHmNRxpIH9jllxnSrRKWDj9b5jtvUkrS5trO73broQAQm4ZwV3vavc+p+weTIk8WvAIoTZIgRh0vFAjNnRGIpb9tdAaFO5lrfdwe1P+qeYtP7SCbcWodwU2L2w0Pw2323UyKbzfvLlyKVY5QrOVQQR0ggsBw/CWdLkUoPA5rMFkiFDweAvUmy79lc/DqdIZnoIjWVNOs7mA/uoBLs4K5lAsnykQJZwzjoko3dvBUP9fm4IAif8hRsGJ/DIfj4TK+nvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=1PhsjksrTr9zX0bfaRbqZ9HbLKGGnRNMeJIcFiSmngM=;
 b=XBXfUPIhYg9TaqPHfjx67cxTZ826/4a6r5x5OTOvG4zr+hMNi9x0Erg2yj5PHhvWkNHZ7+FYW/bqQBbC7O1ZNCHv2FxiiVUcj4SgJ2fi9ALGN4+jKjNB5azXCVHqyzHrYtzZ2sHhd/4ZifwHkf9S87NOCuqjBp5JpM+rHLgPAyW+Mm58wmlg/Uz7r1r1OZSJM0lD0JihfCplMvYdBiPk6N7y1gHpwfM5RsLEblI/BVet/Xjv7+rmZA3g/kYPeR6LD88bp3QEi4Re5yvARbon9wa0Up5tol39V4oVB2LWhzdtNTtFLVOjs2MXvLQ7/2Slelev9jMD4br8afqwwMLYeQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from DM6PR11MB4202.namprd11.prod.outlook.com (2603:10b6:5:1df::16)
 by DM4PR11MB5390.namprd11.prod.outlook.com (2603:10b6:5:395::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4020.18; Wed, 14 Apr
 2021 06:58:08 +0000
Received: from DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274]) by DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274%5]) with mapi id 15.20.4020.022; Wed, 14 Apr 2021
 06:58:08 +0000
From: "Zhang, Qiang" <Qiang.Zhang@windriver.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Andrew Halaney
	<ahalaney@redhat.com>
Subject: =?gb2312?B?u9i4tDogUXVlc3Rpb24gb24gS0FTQU4gY2FsbHRyYWNlIHJlY29yZCBpbiBS?=
 =?gb2312?Q?T?=
Thread-Topic: Question on KASAN calltrace record in RT
Thread-Index: AQHXKrzDGHQ+LKiz3UinMerWnn+L46qynjeAgAD6uIg=
Date: Wed, 14 Apr 2021 06:58:08 +0000
Message-ID: <DM6PR11MB420213907FE92BF6B6B5EB44FF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>,<CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
In-Reply-To: <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [60.247.85.82]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 476d222a-a13b-459b-3f39-08d8ff12a902
x-ms-traffictypediagnostic: DM4PR11MB5390:
x-microsoft-antispam-prvs: <DM4PR11MB53900DBCEA5FF6AD8498894AFF4E9@DM4PR11MB5390.namprd11.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: wi2px7Z3f/WLvrjZ+YaH3Az/XwzcvMKV+jGRmPLo7lcEcLj9CAhATIPOS04c4qcZ3lhXDPPajqLDBfwrUBWxlKFBNlDgJWVkVUo3bc3E3Z4NoTYJttM5015dw3Q6yA2LiJXUGhwUH+m99+j+81Oq+sCEDBtxVIetK+aqL6H1bLPg9Pg9h/Y+/kyf5OBbtmgHtasE7kQRNduhRyAGz85e8m6axt+GNnUHQ9iHx51rIloUu3rh/n6No1CjeDd5PYgFREfbbhMS08QVeabdK/hsrLp+11A5j0PLawtUVWMC6ZxOm/siVVQMjb2eCJQvGH5btTHxSNcGrxotZEDSSeNMhfj3hpHCr5t58vdq8Spe8rJ+ZPafIis/5lxBa40b7iKzvLP5OQBpePgXCV+H2ezpKI5csp7asRzGxyva9Z/8ydsD4L7DbLwzcjQXen4blSa0HRCeSBVFOqhLNAGpslHics83LpRwaKRk5t5GYZQmBqOnRtieQA4UYw0q4R0NjlX5qCctUWXz4CoGikJkM+I7r+ggZmfSsnkEJrKwBnUD936olJICSxpA5kToEMAQK6mtowb0qQL3rrQhlvirTaG0WhLSZShh0/YMTyhQc0QtmKH0aaAzfqFi22NIuvAGQEcjNoNTvIZJeSXVZnNQvFxHxJndw2ZszbV3dSf8QsTe/A19kRMAo31hOounw6uQmYTB
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB4202.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(396003)(366004)(346002)(136003)(39840400004)(376002)(33656002)(53546011)(66946007)(224303003)(26005)(2906002)(76116006)(91956017)(64756008)(186003)(38100700002)(71200400001)(122000001)(66476007)(8936002)(7696005)(86362001)(5660300002)(66556008)(54906003)(66446008)(52536014)(316002)(4326008)(478600001)(83380400001)(6506007)(55016002)(9686003)(6916009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata: =?gb2312?B?WlFwaWY4bFNkeGJFMWMxUTRFZWxiSXQ3THZpczRIR3lsQ3hOQVgxMVdjU1Av?=
 =?gb2312?B?YmhnbWZ6UlRKN3h2em51MS9WVTRVSDZlN09vZ2lyd0lNYndRanpTQzVXdHJa?=
 =?gb2312?B?MndlSmJaTUptRDVrdmVudlRaR2hZSFY4Q0VvK1VIcGdjbk1idG5QT09lNGJj?=
 =?gb2312?B?UHN6cGJOaVlnWDNDVTRReHFMdDQ5M1VFKzdra2pOL3IyTVpnUEd1Q0NXNDBI?=
 =?gb2312?B?cWIwUWVyTU5pRFZjVFMyVUUzeTgvLzFwcmpWdXFlanRDL2xZeFp1N05OL1Nr?=
 =?gb2312?B?SExNYStqdkZrb3lFZU5yRDBOYmxWNThYS2pzR3Nsa2J2Sk5CZGUwYmFhZUcy?=
 =?gb2312?B?Ym9MZTdrdElXMmtyYjJrdU5vMDdIaVhDc2thRWp6Q0lKbGpSZS9jS1ZHZ2I2?=
 =?gb2312?B?OUNTUUhJVHdlamJUckl0ZUE1ZVJxcWJVY3hnZ2hybXI4a2J2NmlCNENxL011?=
 =?gb2312?B?akZZUkQzYXl5cFhPSzZpTkVEREljSnRvNTJsMlVlSzBpZi9vM0NiVU9QODNG?=
 =?gb2312?B?S2ExMjUzVW9kcmxGY1I0bTZncjJ3ZVhCUEZxQ1pnd3JyYlNocmFPNk0zV0xR?=
 =?gb2312?B?bHV1MmcvL2JWVmxjdVRaQXY0dlFLTHMrUDBqTXlKaHBnZUZTaUQ0ZEw1d1I0?=
 =?gb2312?B?Q1ErcjE5Qk55ODI2c0wvWFhDUFhjb1ZwK1dEZWdBcGJXSzVtbWdhcndFcUkx?=
 =?gb2312?B?eS9KN3BuTGpOa3dRT2FIaVliUEdlVndzYmhrTXVzbTFqVTdkd3ZucWN4TGVE?=
 =?gb2312?B?dEtXZmNVeXlaZzlyUjdjc2xNOUhiY0wxNGtHcEdBam9CZFZHTVNxamxJRkNN?=
 =?gb2312?B?cDg2Z291NVdvS0JwUm1Zc0JibnFDZUJHUzJEMCtXdFNXYnBZcGJXNGV2WU5T?=
 =?gb2312?B?ZXlJTnVyKzJmTU5FMityNVlLNTd2Z2ZOeXJEQTRYMDA2VS9mZ2xMNVNQMzE0?=
 =?gb2312?B?OE9HNVlyai9CdzBXaDVTcURSSVpxV0ljNjVBcUcwSUUzUjNQQkZRMi9NUWE3?=
 =?gb2312?B?Mk4xRlRGMG1uYmMyT3AzNWx5OTQvdVdMaVlmc0tycFFjbXhvSmpLMGllZlho?=
 =?gb2312?B?aEFheTJ0cnZDM3hOMVlSZHVtdXpmdmFoMGt1K0RLQ09KeVc4dVo2UUt0ZTla?=
 =?gb2312?B?QkxVaTBBQnJFd0huZ0hBcTNjU3U0WlN2NkFURndpSDd0SDhDaUhxZHBMY3ZF?=
 =?gb2312?B?Zk1PLytDM3ppbG9EMHBqdlBCeWM5bTVJVm0zRENSVkI3ZE42UEJ3MDZVMkt4?=
 =?gb2312?B?YUwrelVzSmRrZzJEWXF0a05ZNVR3bFIybFNOeWt1Q1dWY1lmcUJhZXRFdGpU?=
 =?gb2312?B?SFFMbVpuVkJON3lobEdNczcxblBkb2VDUGQ0Z08yb0lGNGQ1dzJ5THdZMGRV?=
 =?gb2312?B?c1YvRmJ3M1JKL3RLZXZjVnVuRlhyZ0pEUjN0QXpXZmFRUVF4MTV6ZWdPMEov?=
 =?gb2312?B?Q3ZJUGs2VzJHdUtPbDJBb056M2JmOTYyNVloaXpMMmVVbUVGMVhxZWsxTjhW?=
 =?gb2312?B?d1JhVXdsKzR4ckZmNlhtcFFVNUZQVGRYL29VeHFXbk1UMkFoRS9kU3Y5aVEr?=
 =?gb2312?B?TkUwTDQwUDdLU2VZbFJGSlorVkJ1UnNYVjBBUno2YW1JSUdML0o2ZTFDck1o?=
 =?gb2312?B?M2tNckN0R3M0OHhrL3FqWmdWSVJpcGNmakFXczdXdG5IOG9VblFBeTNBN3RV?=
 =?gb2312?B?NGR2V1YzWnF1UzFGTUFoV2hFSiszMmV6Lzk5MWE0Z25maEFMc1IvQ0xsMUVC?=
 =?gb2312?Q?9LFQYPU6aU5gKqwOCQ=3D?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB4202.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 476d222a-a13b-459b-3f39-08d8ff12a902
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Apr 2021 06:58:08.2296
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Jaw+mDRwUHXXj8sE6GDpJRNqyuczuHXr9VbIazZLoHAx4a+1uIzQBOAh8ct/BzULz41GEHeLOJZF/7IGyaP20MLJlUm9/UjYdckMYlspMg8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB5390
X-Original-Sender: qiang.zhang@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com
 header.b=llaDU6xb;       arc=pass (i=1 spf=pass spfdomain=windriver.com
 dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates
 2a01:111:f400:fe5a::605 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
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



________________________________________
=E5=8F=91=E4=BB=B6=E4=BA=BA: Dmitry Vyukov <dvyukov@google.com>
=E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2021=E5=B9=B44=E6=9C=8813=E6=97=A5 23=
:29
=E6=94=B6=E4=BB=B6=E4=BA=BA: Zhang, Qiang
=E6=8A=84=E9=80=81: Andrew Halaney; andreyknvl@gmail.com; ryabinin.a.a@gmai=
l.com; akpm@linux-foundation.org; linux-kernel@vger.kernel.org; kasan-dev@g=
ooglegroups.com
=E4=B8=BB=E9=A2=98: Re: Question on KASAN calltrace record in RT

[Please note: This e-mail is from an EXTERNAL e-mail address]

On Tue, Apr 6, 2021 at 10:26 AM Zhang, Qiang <Qiang.Zhang@windriver.com> wr=
ote:
>
> Hello everyone
>
> In RT system,   after  Andrew test,   found the following calltrace ,
> in KASAN, we record callstack through stack_depot_save(), in this functio=
n, may be call alloc_pages,  but in RT, the spin_lock replace with
> rt_mutex in alloc_pages(), if before call this function, the irq is disab=
led,
> will trigger following calltrace.
>
> maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record calls=
tack  in RT system.
>
> Is there a better solution =EF=BC=9F

>Hi Qiang,
>
>Adding 2 full stacks per heap object can increase memory usage too >much.
>The stackdepot has a preallocation mechanism, I would start with
>adding interrupts check here:
>https://elixir.bootlin.com/linux/v5.12-rc7/source/lib/stackdepot.c#L294
>and just not do preallocation in interrupt context. This will solve
>the problem, right?

It seems to be useful,  however, there are the following situations=20
If there is a lot of stack information that needs to be saved in  interrupt=
s,  the memory which has been allocated to hold the stack information is de=
pletion,   when need to save stack again in interrupts,  there will be no m=
emory available .

Thanks
Qiang
=20

> Thanks
> Qiang
>
> BUG: sleeping function called from invalid context at kernel/locking/rtmu=
tex.c:951
> [   14.522262] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 640=
, name: mount
> [   14.522304] Call Trace:
> [   14.522306]  dump_stack+0x92/0xc1
> [   14.522313]  ___might_sleep.cold.99+0x1b0/0x1ef
> [   14.522319]  rt_spin_lock+0x3e/0xc0
> [   14.522329]  local_lock_acquire+0x52/0x3c0
> [   14.522332]  get_page_from_freelist+0x176c/0x3fd0
> [   14.522543]  __alloc_pages_nodemask+0x28f/0x7f0
> [   14.522559]  stack_depot_save+0x3a1/0x470
> [   14.522564]  kasan_save_stack+0x2f/0x40
> [   14.523575]  kasan_record_aux_stack+0xa3/0xb0
> [   14.523580]  insert_work+0x48/0x340
> [   14.523589]  __queue_work+0x430/0x1280
> [   14.523595]  mod_delayed_work_on+0x98/0xf0
> [   14.523607]  kblockd_mod_delayed_work_on+0x17/0x20
> [   14.523611]  blk_mq_run_hw_queue+0x151/0x2b0
> [   14.523620]  blk_mq_sched_insert_request+0x2ad/0x470
> [   14.523633]  blk_mq_submit_bio+0xd2a/0x2330
> [   14.523675]  submit_bio_noacct+0x8aa/0xfe0
> [   14.523693]  submit_bio+0xf0/0x550
> [   14.523714]  submit_bio_wait+0xfe/0x200
> [   14.523724]  xfs_rw_bdev+0x370/0x480 [xfs]
> [   14.523831]  xlog_do_io+0x155/0x320 [xfs]
> [   14.524032]  xlog_bread+0x23/0xb0 [xfs]
> [   14.524133]  xlog_find_head+0x131/0x8b0 [xfs]
> [   14.524375]  xlog_find_tail+0xc8/0x7b0 [xfs]
> [   14.524828]  xfs_log_mount+0x379/0x660 [xfs]
> [   14.524927]  xfs_mountfs+0xc93/0x1af0 [xfs]
> [   14.525424]  xfs_fs_fill_super+0x923/0x17f0 [xfs]
> [   14.525522]  get_tree_bdev+0x404/0x680
> [   14.525622]  vfs_get_tree+0x89/0x2d0
> [   14.525628]  path_mount+0xeb2/0x19d0
> [   14.525648]  do_mount+0xcb/0xf0
> [   14.525665]  __x64_sys_mount+0x162/0x1b0
> [   14.525670]  do_syscall_64+0x33/0x40
> [   14.525674]  entry_SYSCALL_64_after_hwframe+0x44/0xae
> [   14.525677] RIP: 0033:0x7fd6c15eaade

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM6PR11MB420213907FE92BF6B6B5EB44FF4E9%40DM6PR11MB4202.namprd11.p=
rod.outlook.com.
