Return-Path: <kasan-dev+bncBDV6HSHYYYKRBUNT3KBQMGQEPHM2B7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F13EB35EE57
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 09:29:22 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id p68sf12339563ybg.20
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 00:29:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1618385362; cv=pass;
        d=google.com; s=arc-20160816;
        b=OmVkstnw/idTf2uatANp7XuOn0LGLxFxklUGsghb6OLu+tk3qhyMOQajn+kos7gAIZ
         +PpMkXBihEfTLt7xM01wwwWYf8T6NufSgiA+6avxB5VAnuuUFwci/DYybfgpMeDW0pqV
         KEoMPAew1LmgpM0swOfGt6N2ppp48Q5v70yxyJz9iPUXOfNAk/C0CptsD4hN6ubRMKAD
         GPey60rBs1iFeQDizhXvNaRvcyHd6TCXwT94H8sdqAu9GCwqwaddSO4drrvVeWqG0son
         v03dI/eVzUtVe54nW/FCo9Gf6WuNl7a3eBWMrjuHfTzvHHzzLz0wU9PzZ2z6CZYDJbg5
         ZDzg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=2zVNVWiGsoo5HI0AMaUolZCB2AV2ToCqZYiY81N5HQ8=;
        b=yabLAvFHIm2xxBhYdA+xGHb3UQVNm6FkzZBY5T11yq2Cu76Y6t8ygAmoN9d+hYY+8x
         wqugTpFpTHHf7FtSM6PEOY9OXOxn0nq34wxE8vQQ8OKh5ZDuaq1XyW9jwY9SBTSGkedl
         su9yqq7E8VNJMhUQGu1PIi8vrdgWLy64HlLun2EZSAEykjFlRNMrAfC7h1MVZmADdP8V
         YEJq5jZlKdlDXi/FG7TpNX5N2FJX5Jf3GIYlt1KwtRR0Pwh2Zqz1VOxwVkNzNIcL2Gzr
         cEZt2jzOg5MMJ3aAwMFZziKmSJEvj7zq8TGu1HGSJe8T3HAV7NohS43R/MeCz245qlQD
         yrZg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=jf4zMxio;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.77.77 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2zVNVWiGsoo5HI0AMaUolZCB2AV2ToCqZYiY81N5HQ8=;
        b=BhuGBmYDC0GrLgf0szpET4DeIboTtx6Tg7Wh275ppsgTNwn27VosWQg5k/Rdk7XnKU
         Yotk9GuqQNLmzCvLbBOWNyyIwgqzjAi6GgVjn5Exmyp5k+Kx2E/mIgWJALZQJT7tM53z
         8AOJSwteFRCTGqRJUc2xcZYIDLs2/WmKvutxTvbKaoKf3XG7WLXza0JwdsFc2qPbji/S
         PPcb5/vtutN0ALbk7V07j1e74xXK5A4TTArjdPliSsxvLNRUCHP3LECw/cDR/uR2ponj
         s6XIGyrQ0IJ6jpZEDN0PvYZfgmIE830ta2daQt7mIJUiaDJoQjnSYyybArjHIP1bgjU8
         Huqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2zVNVWiGsoo5HI0AMaUolZCB2AV2ToCqZYiY81N5HQ8=;
        b=qmnjEOcEGuhggFemTgDdUUh/HrqcFrz7ofbF32Bx7yxi81+5IZ8ZqdB8G05WOpziUA
         nxAwFlcEJ5FRxSKcOhxZlFgCEEAQXZwEXUHtHvPa7OgLuQ93x8URYkc7KVFzI6aRED2F
         4Dp4onvx4MdAyv/ZZtznFmedsm2j+cjrrsxct+97abh5ZehtCsDVPxbiBuU3iOf7BaNn
         ThG2VgbVhPqeNqMxHKL772k3KyxcZIgqeU2NXJD2pc0gt5fACV26PjTsQpIwFCNEYvrK
         8USKgGvOhbD7Svukk8t3Y65pXTPRbx+C0pn8vW9nFdSuTgqwT/F6MYVM8Sz4cZD3VBzJ
         y+Kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533L+ob1trybRnAixTUaTDg5Q2Lu+lsh8Z+KimYyI81dCmDeD0Lo
	npn0Vyu+R87SfSHByfovORw=
X-Google-Smtp-Source: ABdhPJyBI4lAvan785zKoEqK76FDuIe2AXkDoBMbd5Ty4OKryewlLcHUrl58kRaaRlGaWq3ndJOcvg==
X-Received: by 2002:a25:da4a:: with SMTP id n71mr44766955ybf.351.1618385361789;
        Wed, 14 Apr 2021 00:29:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:b47:: with SMTP id b7ls581680ybr.6.gmail; Wed, 14 Apr
 2021 00:29:21 -0700 (PDT)
X-Received: by 2002:a25:ac48:: with SMTP id r8mr19020056ybd.488.1618385361184;
        Wed, 14 Apr 2021 00:29:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618385361; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bnc2GfYupurkPqySNXHpBrFSH5WqQ55lVfPPEF01isZcZ6khOEdabPLAIm2Res2Rnb
         V4mEdVIFrtkHeDYGchIT9Zbnx0LvT7/JhgDnPrps0lhjXO5qAJofTIREUwSE8szOcjXi
         ABAUfgg8BVltkHGQ8lsV56X5fcMl/CQjqVKBcA12pqt14LioSkgBH1nT0cwZZAI28hhp
         BSS73Z/XxzZ8rOqkBxrzAjr9mqpwjqE6CovVpIFhmDJyE54k7d96DQ5L0OFBYhLM3U2T
         YHYsdLfANc35oM3w+8ATEV0/KdJ6zuAqdjJcIdK4HEFvVZ9zMDcryA5fFF3Sz31gHv99
         jcPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=caKZqWa+tb8VcxHfxwrSKAvG6u5xbTxRCj0CUTiM79g=;
        b=UFHxAZls+1CkHs1vIgCuZkgPjg2nKdoZ/HdnUQj8pU7QGjkCy3/6c7sdRNvmaGTWMj
         BlFQuzoMiHkRoyxzVzRkdH4Ook0St0VdeOXgnjlpo1mZ2B00Zsp4FHqVDSp3B+w9lR9B
         VsfGt+CIpYmgUd6yx5gVRuJ7NOMiBEL3XvVx9gyMV9KFiZ7ARQz2QzyXYlQmOd8UdQPt
         YMAYB61EkvGeU7OW7qSk5BQQnQgmXHQlg/USBR4+DHBKmUB6blEQoyZJEu7SS8fgHsYk
         4BFvDn0TFavjurCmgp63UyJnzh6aCRpETtRlkVZZe96GConES5zUN5fRM7O3gD4AF0ig
         oQgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=jf4zMxio;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.77.77 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
Received: from NAM02-SN1-obe.outbound.protection.outlook.com (mail-eopbgr770077.outbound.protection.outlook.com. [40.107.77.77])
        by gmr-mx.google.com with ESMTPS id t17si620767ybi.3.2021.04.14.00.29.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Apr 2021 00:29:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.77.77 as permitted sender) client-ip=40.107.77.77;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LIgZ0n5bf/jp1RxTEnEg23CDEyefjD9vXj9uKJP9aIcYp6g+C0swoFzRuuY/IzYVmBlYTHdns+VkA8vn1lw3mKzHUC0yYx/6swE1N7+nxvyT4+HdX3OFnjcg88VLmhv1gwthXA9aGAus2rNWSlbWnawwDxZVGWQOskL8Phe6wFzT/y1BQJX2ZTw+KHFn62XXwpTibO7ZoJ7ZzAywbDdg6hSmreMvCan6XDasYGVV5vdXZ5ZM+o9GYQIuqi+7nj+arHz10zgS3vqCelLt0tibdLVajI9Pn/WwVeY6JZoz1PJmrbsmnk43AAJbPILiguyFcs+biIdMhaW1xjs3dLOHcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=caKZqWa+tb8VcxHfxwrSKAvG6u5xbTxRCj0CUTiM79g=;
 b=WDwXFJl7YafdrzyIQAy/NY792QLdxXksj5IC0MmGL1hWwFcaSSUCoeyEwH71JOlGYE05OAxByGeV+837j2EA6dOx2rENaxdwm1uIaejBP9TGJZY4tEjCDK1wFtaEGlZl3th75nupgOUpFEXHOByMiF+gTIMW7nXD6BBD9+ISw5+lUhKhHtOPM2AQ0+uyzkFm1idTw/QcrDajFrpN3HyzTCw1JH3F75cyfzKQkFsZiwAk6kT27Vo7uXNXk73nT5+gOUZYJoxidAOuTqgRH+ttVkVhL7/ftRVoitqLSLrqTPu5Hy3O02XS8IZ0RKTttASQz6HI2u9O5oTbXjzXjMhqTQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from DM6PR11MB4202.namprd11.prod.outlook.com (2603:10b6:5:1df::16)
 by DM6PR11MB3418.namprd11.prod.outlook.com (2603:10b6:5:6e::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4020.18; Wed, 14 Apr
 2021 07:29:19 +0000
Received: from DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274]) by DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274%5]) with mapi id 15.20.4020.022; Wed, 14 Apr 2021
 07:29:19 +0000
From: "Zhang, Qiang" <Qiang.Zhang@windriver.com>
To: Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>
CC: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: =?gb2312?B?u9i4tDogUXVlc3Rpb24gb24gS0FTQU4gY2FsbHRyYWNlIHJlY29yZCBpbiBS?=
 =?gb2312?Q?T?=
Thread-Topic: Question on KASAN calltrace record in RT
Thread-Index: AQHXKrzDGHQ+LKiz3UinMerWnn+L46qynjeAgADR2QCAADfF8A==
Date: Wed, 14 Apr 2021 07:29:18 +0000
Message-ID: <DM6PR11MB420260ED9EC885CCD33840EEFF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>,<182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
In-Reply-To: <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [60.247.85.82]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: b7258dc6-b1cb-4d84-3fc3-08d8ff17040f
x-ms-traffictypediagnostic: DM6PR11MB3418:
x-microsoft-antispam-prvs: <DM6PR11MB341813F0293FC6BBD1890D43FF4E9@DM6PR11MB3418.namprd11.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: kzVzWorQm+9dXQvmLOsADQI4v4cG4k6ykljJ0DG/6zcRQfmi6THWKilB6/3aOyC6mCmJrmSRjlw1Tnw9O+24D/W93KopbvsLD/N9m963hKozSf7gA8knBTwFGTCD0YxrklRPoP0pCEZ4vWb9QztxOvIKlSAWcqXlPg1IdBOPJt1Fj8Tob16jiNEC7ph+/gLiD+vwAgvJj94pogSwbZTkW+3Kmk4q34yNqoTCkSopLulEeCsJ64Yc8QM1sx9BU2GGNvy9qPYQWF5nqwHTT0TcmgQCyv2no7HPjfsc+yGPssHnPHbJMH3scVhXbCxGR051bKU8p6LQgF2HDibNhlRRyyHqIjDJBOxFLpKwZHfx48SoB7/WNDwXWAQ0bxNz83WvljB+8sDvzciXc67anzHrwYk++6cnHOMJ5NbvSXa13xRdJpkgyncu7ZByU4XldH2g/8FMBedi0Emv05LxdTy6wC+62iAJJUfQv7GfyFRoGT6TM64yTVA6yF0OIVMJVX2hqRV27UwKFISZsISrMCEVI0iYdwjBh7ZCxgLcFZbiA0/qtwrYWPG4iFzNINNMOYvBHWiXHqI5kOFpuq9m56YnXnj4lTonwk7iNyZhErDPauv95a/MLjj0fZYvXdp7bKJmxduAuq6PFaEGOCZu1ztHaU5h73txeN1t3GvQbDoFs63FPtZnGOrXZJrvfqa4aMzb
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB4202.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(376002)(39840400004)(346002)(396003)(366004)(136003)(76116006)(64756008)(66476007)(966005)(26005)(38100700002)(54906003)(83380400001)(5660300002)(66946007)(8936002)(316002)(66556008)(186003)(9686003)(52536014)(86362001)(91956017)(122000001)(4326008)(478600001)(66446008)(71200400001)(33656002)(53546011)(110136005)(224303003)(2906002)(55016002)(7696005)(6506007);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata: =?gb2312?B?eHpOamxBMTRScEEvNTVlYzdEb2tEcjBpZTFNbjRnZnlrRTlKL3BTOStGOURh?=
 =?gb2312?B?UEN2MWQ5cXR6RDNXbnN0S2NSRGFRaUU1Q2d1WFozRHJyZTJtV1huOEJqb0xv?=
 =?gb2312?B?dTdONHBBdTVqR0pKdGMyVkdiN01GZU8wSWpqODVWalZjSXZ4UVp0YzVSSm1l?=
 =?gb2312?B?a2ZEVXBtejA1ZWVocGpQbzVuOXo2NlovcUpmZTlBcFVWbVEwVmk3UTRwV1VB?=
 =?gb2312?B?NnNlanB5RzBUMGJna3ppZXJRWVdPVUdndGRrUW9CSndnNnBXOGVuZEJEVWkr?=
 =?gb2312?B?VjVja01nWkRIYzNtNXhDOFlZdU1RdjRUVnVMaVhqcm1sTExtZ09va0U2THBB?=
 =?gb2312?B?RytENk5TZUl5MFdWRU0rRk9hQ2pMTm1ET0ZnNncvbGNqbVFFakFnN0prc3pY?=
 =?gb2312?B?cnRsbDc0ZWViNUtuRXRMNjdHQjZXcFpXVHVJRVdXelRxL0RYL0RaNWNXVk9m?=
 =?gb2312?B?cVlBNmZTdlUveWZQYlZ5R2lSNklmOHJmSEpBQjVGdVlBUGNQTE9RUXQxZXU3?=
 =?gb2312?B?L2NzSzkrcjlnTGtiUC9Wc0hqc2xIaTNlWXVOZkhkOVRmR2lOTEFUTWd4Q3FL?=
 =?gb2312?B?WDY3bWRaalAra1BBVG5ubnlERjRwSE5qYWJHK1JiYjV5YzMzSVZPMXFUTVA4?=
 =?gb2312?B?WlVOa1hvZlByN1F5S0hZd0t2VFRCSGFQcEp1cVk1ckh3VWU3MWMvRC9mMnhQ?=
 =?gb2312?B?NzNVMjE4RzkvdzNzNFhycmlvbXkrVjlUcGJnMnYvV0libndPSjZlR0dTQmc1?=
 =?gb2312?B?aDZZMTZlNTZ4OXNld3J1OUVYRXF1emxiaEduTnkwL2tvT1RZR1U1c1NuemJ5?=
 =?gb2312?B?TmZ0b3JSZ2k4Y1NzUTZINWVlTUcyTFRkMU1DQWtYaHNBQ29NYUVPeXlReTFi?=
 =?gb2312?B?SjhCVEc2Ylg1bHoyczd4RmQ1RGVrVmo0Z3JZbFhzQ1ZJR05LNytaUlBCS2hO?=
 =?gb2312?B?S0xOejJWNjJVRlpsVGdLT2JOUmhKVjM3STlmZXFOTFBndzBEVU03WUVVUS9r?=
 =?gb2312?B?YmJFaDdvK2dTa0l2Mm5oUGNEUWw5K2Vpc09YWEZPL3JpL2xRQktKRXZldkEz?=
 =?gb2312?B?cXgzVU9KOVVNOWJ1NVBLY2dFNUdDeWxKNHdyb1JLandtbnBTdEtFcHN6T1R3?=
 =?gb2312?B?cFJod3E5SldObkM3TmVwQkFRZDhjRFhPbndyMUVvK0tKMy9mcFBISVdyem1j?=
 =?gb2312?B?MWk4Nko0dU9KWndSOG1LRzBjTXNmRC90emJ5d0djQVp1Vzg0dnZPZzRxRkx6?=
 =?gb2312?B?cmlaVVZjSlZGbU9qaEhjOTRWRW1Mc0lJSUVmRnhiZUN1dW9sSVFpQ3IvNjhL?=
 =?gb2312?B?U1k5WElRbGtmQUlIbFFrSExVRXhtQzRBWXFJcC9ZbXFDYnRqUzNBQ2ZLVzAr?=
 =?gb2312?B?U3VqU24rTU02Y3p6bFpwZnpYVk1HMUp3RHRBZXE4cGlib0JhZEp1Rjl6eVNj?=
 =?gb2312?B?TGRSamdMK1ZxS2cxRzNOZU4xR1Nua2ZZc1laZGpKUUIxVXZMbEJSaDNHcXM4?=
 =?gb2312?B?OGM1WCtWOVpDZFpMQkdNdEpCZFNYVjhlQjNKMUhnQ2IxenE5UStIR1VVckhI?=
 =?gb2312?B?OVZPZUpqQXJQNFNyUnJhdjFKM0JjRGVVWmhzYnA0L1pwNUdhR2VVV3BrSkJ1?=
 =?gb2312?B?SGhQZEtsVkUvRUJ1bmRtU2Q1d1E1MFFacmJSdkZzNWRDNFhBNTRaeUpGYlZK?=
 =?gb2312?B?TVBnWEU1NTFsNGUvcW5DTjBJK3pQMDZ5YU5UVFNkSi83Z1Q5Zi9ncFBjdUp4?=
 =?gb2312?Q?JO3Ape4k3HR1jdLBQo=3D?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB4202.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b7258dc6-b1cb-4d84-3fc3-08d8ff17040f
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Apr 2021 07:29:18.9094
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Lw2s8U1RDayf7u4uQgFr84yhEf6IotXa749smE/WTVPj+G4z+aLIi1R1ftYxfmG2GRGTqvhE47lC1kPLveo9jTwd02hCySWdhdn1tQXFszk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR11MB3418
X-Original-Sender: qiang.zhang@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com
 header.b=jf4zMxio;       arc=pass (i=1 spf=pass spfdomain=windriver.com
 dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates
 40.107.77.77 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
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
=E5=8F=91=E4=BB=B6=E4=BA=BA: Mike Galbraith <efault@gmx.de>
=E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2021=E5=B9=B44=E6=9C=8814=E6=97=A5 12=
:00
=E6=94=B6=E4=BB=B6=E4=BA=BA: Dmitry Vyukov; Zhang, Qiang
=E6=8A=84=E9=80=81: Andrew Halaney; andreyknvl@gmail.com; ryabinin.a.a@gmai=
l.com; akpm@linux-foundation.org; linux-kernel@vger.kernel.org; kasan-dev@g=
ooglegroups.com
=E4=B8=BB=E9=A2=98: Re: Question on KASAN calltrace record in RT

[Please note: This e-mail is from an EXTERNAL e-mail address]

On Tue, 2021-04-13 at 17:29 +0200, Dmitry Vyukov wrote:
> On Tue, Apr 6, 2021 at 10:26 AM Zhang, Qiang <Qiang.Zhang@windriver.com> =
wrote:
> >
> > Hello everyone
> >
> > In RT system,   after  Andrew test,   found the following calltrace ,
> > in KASAN, we record callstack through stack_depot_save(), in this funct=
ion, may be call alloc_pages,  but in RT, the spin_lock replace with
> > rt_mutex in alloc_pages(), if before call this function, the irq is dis=
abled,
> > will trigger following calltrace.
> >
> > maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record cal=
lstack  in RT system.
> >
> > Is there a better solution =EF=BC=9F
>
> Hi Qiang,
>
> Adding 2 full stacks per heap object can increase memory usage too much.
> The stackdepot has a preallocation mechanism, I would start with
> adding interrupts check here:
> https://elixir.bootlin.com/linux/v5.12-rc7/source/lib/stackdepot.c#L294
> and just not do preallocation in interrupt context. This will solve
> the problem, right?

Hm, this thing might actually be (sorta?) working, modulo one startup
gripe.  The CRASH_DUMP inspired gripe I get with !RT appeared (and shut
up when told I don't care given kdump has worked just fine for ages:),
but no more might_sleep() gripeage.


CONFIG_KASAN_SHADOW_OFFSET=3D0xdffffc0000000000
CONFIG_HAVE_ARCH_KASAN=3Dy
CONFIG_HAVE_ARCH_KASAN_VMALLOC=3Dy
CONFIG_CC_HAS_KASAN_GENERIC=3Dy
CONFIG_KASAN=3Dy
CONFIG_KASAN_GENERIC=3Dy
CONFIG_KASAN_OUTLINE=3Dy
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=3D1
CONFIG_KASAN_VMALLOC=3Dy
# CONFIG_KASAN_MODULE_TEST is not set

---
 lib/stackdepot.c |   10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -71,7 +71,7 @@ static void *stack_slabs[STACK_ALLOC_MAX
 static int depot_index;
 static int next_slab_inited;
 static size_t depot_offset;
-static DEFINE_SPINLOCK(depot_lock);
+static DEFINE_RAW_SPINLOCK(depot_lock);

 static bool init_stack_slab(void **prealloc)
 {
@@ -265,7 +265,7 @@ depot_stack_handle_t stack_depot_save(un
        struct page *page =3D NULL;
        void *prealloc =3D NULL;
        unsigned long flags;
-       u32 hash;
+       u32 hash, preemptible =3D !IS_ENABLED(CONFIG_PREEMPT_RT) || preempt=
ible();

if CONFIG_PREEMPT_RT is enabled and  but not in preemptible, the prealloc s=
hould be allowed

should be change like this:
   may_prealloc =3D !(IS_ENABLED(CONFIG_PREEMPT_RT) && preemptible());

Thanks=20
Qiang





        if (unlikely(nr_entries =3D=3D 0) || stack_depot_disable)
                goto fast_exit;
@@ -291,7 +291,7 @@ depot_stack_handle_t stack_depot_save(un
         * The smp_load_acquire() here pairs with smp_store_release() to
         * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
         */
-       if (unlikely(!smp_load_acquire(&next_slab_inited))) {
+       if (unlikely(!smp_load_acquire(&next_slab_inited) && may_prealloc))=
 {
                /*
                 * Zero out zone modifiers, as we don't have specific zone
                 * requirements. Keep the flags related to allocation in at=
omic
@@ -305,7 +305,7 @@ depot_stack_handle_t stack_depot_save(un
                        prealloc =3D page_address(page);
        }

-       spin_lock_irqsave(&depot_lock, flags);
+       raw_spin_lock_irqsave(&depot_lock, flags);

        found =3D find_stack(*bucket, entries, nr_entries, hash);
        if (!found) {
@@ -329,7 +329,7 @@ depot_stack_handle_t stack_depot_save(un
                WARN_ON(!init_stack_slab(&prealloc));
        }

-       spin_unlock_irqrestore(&depot_lock, flags);
+       raw_spin_unlock_irqrestore(&depot_lock, flags);
 exit:
        if (prealloc) {
                /* Nobody used this memory, ok to free it. */

[    0.692437] BUG: sleeping function called from invalid context at kernel=
/locking/rtmutex.c:943
[    0.692439] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, na=
me: swapper/0
[    0.692442] Preemption disabled at:
[    0.692443] [<ffffffff811a1510>] on_each_cpu_cond_mask+0x30/0xb0
[    0.692451] CPU: 5 PID: 1 Comm: swapper/0 Not tainted 5.12.0.g2afefec-ti=
p-rt #5
[    0.692454] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 09/=
23/2013
[    0.692456] Call Trace:
[    0.692458]  ? on_each_cpu_cond_mask+0x30/0xb0
[    0.692462]  dump_stack+0x8a/0xb5
[    0.692467]  ___might_sleep.cold+0xfe/0x112
[    0.692471]  rt_spin_lock+0x1c/0x60
[    0.692475]  free_unref_page+0x117/0x3c0
[    0.692481]  qlist_free_all+0x60/0xd0
[    0.692485]  per_cpu_remove_cache+0x5b/0x70
[    0.692488]  smp_call_function_many_cond+0x185/0x3d0
[    0.692492]  ? qlist_move_cache+0xe0/0xe0
[    0.692495]  ? qlist_move_cache+0xe0/0xe0
[    0.692497]  on_each_cpu_cond_mask+0x44/0xb0
[    0.692501]  kasan_quarantine_remove_cache+0x52/0xf0
[    0.692505]  ? acpi_bus_init+0x183/0x183
[    0.692510]  kmem_cache_shrink+0xe/0x20
[    0.692513]  acpi_os_purge_cache+0xa/0x10
[    0.692517]  acpi_purge_cached_objects+0x1d/0x68
[    0.692522]  acpi_initialize_objects+0x11/0x39
[    0.692524]  ? acpi_ev_install_xrupt_handlers+0x6f/0x7c
[    0.692529]  acpi_bus_init+0x50/0x183
[    0.692532]  acpi_init+0xce/0x182
[    0.692536]  ? acpi_bus_init+0x183/0x183
[    0.692539]  ? intel_idle_init+0x36d/0x36d
[    0.692543]  ? acpi_bus_init+0x183/0x183
[    0.692546]  do_one_initcall+0x71/0x300
[    0.692550]  ? trace_event_raw_event_initcall_finish+0x120/0x120
[    0.692553]  ? parameq+0x90/0x90
[    0.692556]  ? __wake_up_common+0x1e0/0x200
[    0.692560]  ? kasan_unpoison+0x21/0x50
[    0.692562]  ? __kasan_slab_alloc+0x24/0x70
[    0.692567]  do_initcalls+0xff/0x129
[    0.692571]  kernel_init_freeable+0x19c/0x1ce
[    0.692574]  ? rest_init+0xc6/0xc6
[    0.692577]  kernel_init+0xd/0x11a
[    0.692580]  ret_from_fork+0x1f/0x30

[   15.428008] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   15.428011] BUG: KASAN: vmalloc-out-of-bounds in crash_setup_memmap_entr=
ies+0x17e/0x3a0
[   15.428018] Write of size 8 at addr ffffc90000426008 by task kexec/1187
[   15.428022] CPU: 2 PID: 1187 Comm: kexec Tainted: G        W   E     5.1=
2.0.g2afefec-tip-rt #5
[   15.428025] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 09/=
23/2013
[   15.428027] Call Trace:
[   15.428029]  ? crash_setup_memmap_entries+0x17e/0x3a0
[   15.428032]  dump_stack+0x8a/0xb5
[   15.428037]  print_address_description.constprop.0+0x16/0xa0
[   15.428044]  kasan_report+0xc4/0x100
[   15.428047]  ? crash_setup_memmap_entries+0x17e/0x3a0
[   15.428050]  crash_setup_memmap_entries+0x17e/0x3a0
[   15.428053]  ? strcmp+0x2e/0x50
[   15.428057]  ? native_machine_crash_shutdown+0x240/0x240
[   15.428059]  ? kexec_purgatory_find_symbol.isra.0+0x145/0x1a0
[   15.428066]  setup_boot_parameters+0x181/0x5c0
[   15.428069]  bzImage64_load+0x6b5/0x740
[   15.428072]  ? bzImage64_probe+0x140/0x140
[   15.428075]  ? iov_iter_kvec+0x5f/0x70
[   15.428080]  ? rw_verify_area+0x80/0x80
[   15.428087]  ? __might_sleep+0x31/0xd0
[   15.428091]  ? __might_sleep+0x31/0xd0
[   15.428094]  ? ___might_sleep+0xc9/0xe0
[   15.428096]  ? bzImage64_probe+0x140/0x140
[   15.428099]  arch_kexec_kernel_image_load+0x102/0x130
[   15.428102]  kimage_file_alloc_init+0xda/0x290
[   15.428107]  __do_sys_kexec_file_load+0x21f/0x390
[   15.428110]  ? __x64_sys_open+0x100/0x100
[   15.428113]  ? kexec_calculate_store_digests+0x390/0x390
[   15.428117]  ? rcu_nocb_flush_deferred_wakeup+0x36/0x50
[   15.428122]  do_syscall_64+0x3d/0x80
[   15.428127]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   15.428132] RIP: 0033:0x7f46ad026759
[   15.428135] Code: 00 48 81 c4 80 00 00 00 89 f0 c3 66 0f 1f 44 00 00 48 =
89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48=
> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 0f d7 2b 00 f7 d8 64 89 01 48
[   15.428137] RSP: 002b:00007ffcf6f96788 EFLAGS: 00000206 ORIG_RAX: 000000=
0000000140
[   15.428141] RAX: ffffffffffffffda RBX: 0000000000000006 RCX: 00007f46ad0=
26759
[   15.428143] RDX: 0000000000000182 RSI: 0000000000000005 RDI: 00000000000=
00003
[   15.428145] RBP: 00007ffcf6f96a28 R08: 0000000000000002 R09: 00000000000=
00000
[   15.428146] R10: 0000000000b0d5e0 R11: 0000000000000206 R12: 00000000000=
00004
[   15.428148] R13: 0000000000000000 R14: 0000000000000000 R15: 00000000fff=
fffff
[   15.428152] Memory state around the buggy address:
[   15.428164]  ffffc90000425f00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8=
 f8 f8
[   15.428166]  ffffc90000425f80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8=
 f8 f8
[   15.428168] >ffffc90000426000: 00 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8=
 f8 f8
[   15.428169]                       ^
[   15.428171]  ffffc90000426080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8=
 f8 f8
[   15.428172]  ffffc90000426100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8=
 f8 f8
[   15.428173] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   15.428174] Disabling lock debugging due to kernel taint

kasan: stop grumbling about CRASH_DUMP

Signed-off-by: Mike Galbraith <efault@gmx.de>
---
 arch/x86/kernel/Makefile |    1 +
 kernel/Makefile          |    1 +
 2 files changed, 2 insertions(+)

--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -105,6 +105,7 @@ obj-$(CONFIG_X86_TSC)               +=3D trace_clock.o
 obj-$(CONFIG_CRASH_CORE)       +=3D crash_core_$(BITS).o
 obj-$(CONFIG_KEXEC_CORE)       +=3D machine_kexec_$(BITS).o
 obj-$(CONFIG_KEXEC_CORE)       +=3D relocate_kernel_$(BITS).o crash.o
+KASAN_SANITIZE_crash.o         :=3D n
 obj-$(CONFIG_KEXEC_FILE)       +=3D kexec-bzimage64.o
 obj-$(CONFIG_CRASH_DUMP)       +=3D crash_dump_$(BITS).o
 obj-y                          +=3D kprobes/
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -72,6 +72,7 @@ obj-$(CONFIG_CRASH_CORE) +=3D crash_core.o
 obj-$(CONFIG_KEXEC_CORE) +=3D kexec_core.o
 obj-$(CONFIG_KEXEC) +=3D kexec.o
 obj-$(CONFIG_KEXEC_FILE) +=3D kexec_file.o
+KASAN_SANITIZE_kexec_file.o :=3D n
 obj-$(CONFIG_KEXEC_ELF) +=3D kexec_elf.o
 obj-$(CONFIG_BACKTRACE_SELF_TEST) +=3D backtracetest.o
 obj-$(CONFIG_COMPAT) +=3D compat.o

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM6PR11MB420260ED9EC885CCD33840EEFF4E9%40DM6PR11MB4202.namprd11.p=
rod.outlook.com.
