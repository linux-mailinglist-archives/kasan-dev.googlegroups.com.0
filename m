Return-Path: <kasan-dev+bncBDV6HSHYYYKRBV6G3KBQMGQEE7UWS7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CB0735EF1A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 10:10:01 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id f12-20020a056a00238cb029024936cd4de4sf621683pfc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 01:10:01 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1618387800; cv=pass;
        d=google.com; s=arc-20160816;
        b=fcX6JHtMk8WzAlv4yjPcivpVndY8hyYArAoICm1SrsRHyxIArOiiO4pWPeSTTcdOf/
         GvnePO1uwa6/iPLmpZ4NdJ3kzJB/4OmdiGIzEhmmhzYG3wvEAYlVmC5Se0WqaNnfMnXg
         tDbYc+q5drhXtCNI1+uI1KJOs9VTPLT3R3lJYZ+mbmlLbYuwbbY3ND6eJB1M39wr8/i4
         jmgqQ1Nrah9TkIJjO04U5ULwWlxs3gavlfng+rEZRmPjOEAQUuH9KkQkqvzjPo0d17wA
         VedCvwpUn8A8mWTBV7FaVZ8xedrKdM1IlPXK2oYkoXfuhLCSPac2AZoKeCDe6actADw4
         pm+w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=cx8OaOoQ4RSnImdYNFv/TiJ6HRTeplCDonHzSWUinWg=;
        b=mhW6I3Lz4WXnStIVRFA+6EtleVk+IKiJetXMEIefbc+1LEvS87RI/Jqq10gFCZDQFs
         5K6yG3hWPfCPTv3RN97S/8+S7scVzvpZrl8ltWJIrphuY9zzb4TnNJla0kDbMrgRmlC/
         j3FcK/Xkb+zOG2j/jgvFNI/r8Il17A4oKOHIoer7k68lvWCte0wu4rQxgmYwyxuYbRqA
         WW0y3F6K7WVD9JNP3NQhx7Ur5T7tMxvCcecnzZfbvg/Q8xUZpF5itjw6Oof23RVofgXx
         b5ThsoeEtc8q+lV0gsqEoEzryf/u/Vak3hvp33OVvVztEfm/JuOTuU0slXNO3R+qATle
         cXNg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=dNP0lPzV;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.223.52 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cx8OaOoQ4RSnImdYNFv/TiJ6HRTeplCDonHzSWUinWg=;
        b=ddqUEke9G5rOi5wzgej04gCJ3ypIE+UaRD7UwhXW04FvLdnsLaqxk9Shf4fsIMi3vt
         BtvlFXC/V9GWd05F/YWF5AvLkNiJfEf/r/Ef+LFcMyPnN3IBGQNCr4gI+muVyKUdLj1J
         E69gFmvhEiODfS11eBgGzWnE+aw2TXFejTEduCIll7yIGq7ylo+jc1xSDNf6hWYNHm1e
         XrSelFl8BWfyZLEh01eaXk9OiixP71fq39ltN9LQXYy/6o/2BKucnHuxFs8gnAW9FShA
         iGja/A+XU+ySen2pjGPJnvMRIJRDKH3XFYAZW3A5u1yNKSKBBwZOyh5oAMS1cKhZ4BTh
         c5cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cx8OaOoQ4RSnImdYNFv/TiJ6HRTeplCDonHzSWUinWg=;
        b=rH4lmpaZbk8U/ewd7Wwp5pnlsFCXdL/gxPr0F2jjowNrL5Cta1r5frgLV964DyY7W+
         2nBJyO88HFsE9sHwzZM5Ro5pEexQ32uV7II6bgqywFTtgr7FAdK4zRKQOqodmgwljF9Z
         jy0StdOZnb55MW3FbLS9bW71RhR6z0I8ozpeB087nCh9Qk3rORF1scTaRCZJWo9NiqnA
         RDUY36/WjRvpO6pzfehrvn67UyeJXPMZhRT0d8nnf/qB9Bvk/GULvIJtBOur4aYBLJmk
         I3TuqOc7XzH0w//PCycBA8hKIU0B3ggOKFJXTC5lKlvYXYVorpjgjuhyqsLFMRrMkAHS
         E7mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IvyIUuDcjRi7JnG5VHEWU917kTIZVL3e1ddw0++98SSeoWOdG
	2kVn7ggT8ezsvUzYj2141FE=
X-Google-Smtp-Source: ABdhPJweyUXXQpRgGjNSWeNwbfsGT/Ff9RTrWyMHa9M6fWdTVLKYn8ZWhmUfcFO9eeKKcLyUqfQGKA==
X-Received: by 2002:a17:90b:120e:: with SMTP id gl14mr2340743pjb.196.1618387799872;
        Wed, 14 Apr 2021 01:09:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1315:: with SMTP id i21ls728047pgl.8.gmail; Wed, 14 Apr
 2021 01:09:59 -0700 (PDT)
X-Received: by 2002:a65:590a:: with SMTP id f10mr36461062pgu.358.1618387799027;
        Wed, 14 Apr 2021 01:09:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618387799; cv=pass;
        d=google.com; s=arc-20160816;
        b=tSz+H1fBCdtvH1YKP84gLF2vAr/FuktiUuvoM/7rZPPY2xRCQAsONbiJOhwjctG9m1
         DkO+iXEM+sZkdbPIFItjB6vYiLk0elIHWkn9TvEduDpJTrh7d+zKWuUSb/C9Vvameq9J
         MIVXMppG5miHFPjNxAmrdXI4rkingEvVj9WHU+jmSvzMFQjrieIPSAf8OT92r/1PPNaW
         7Q/p45fgdVohCjg33J7D/2W+aYz58vZ3Ln5a1nRYVQrB5WCyeAciqZjDMi9dr/jBFOoQ
         uy/MVfBx0XCMcSYh6gxUJN8SSI2FXRS3gaCk20FyZsD6XoOOA9LGaMFGJzbQOMM4ezgg
         cTFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=XXbgXXgbkplKhi1qXP4uJ6TOwgdHfG0zKj0RTvp3xyU=;
        b=kOHDWaNPyHPY++nbn2/uC9OJnFRVLHyuu7flbRPcUC4DEpYyleg7bevI1xJwYZcp4u
         4ZzAHWMQtffM8DuYCvZAbESZ8Qn6jNDyqK9eVegcU+ktUYOrl1pFCNexyHjxb8rOCDkv
         nYBYkHEuz3TSBU3/Bcz9ikReQi5XIRa37nTaRaP/gLHPVIpXzsQ93pJSjVrKowQESkBc
         xWHi0kj4EHY3NH89/GBfxihx8VZE/ONfEdJMoXNc6+uXRH8F6+9hV4UYnvRYY2R9Upq1
         /sSHtU46uZX32I6YASQ/u4lcyCLJH2evQ/WEyMZkFc9IuFqsh+m2pbbySb12QVN5r8R7
         oYFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=dNP0lPzV;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.223.52 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2052.outbound.protection.outlook.com. [40.107.223.52])
        by gmr-mx.google.com with ESMTPS id i18si495900pju.2.2021.04.14.01.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Apr 2021 01:09:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.223.52 as permitted sender) client-ip=40.107.223.52;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=EvLYVLFRzqjZvPs3NyZewNZ1AvI+TmNIRGm7jjW3MlPyF8PSWtdotWvf9VArHkAg2HUBFmRFRUlEDBcCyLel5N0+ojM4OmuSgkKxLmx5p1vfqReknnMReEGDc8lVudCMQkISHXqo5ZpYofejsJqDPNaJ0zFVIoOnRaSjt5RqEBCMsigp1afvZwcJrFgmb/wbw89FJF/WGcfVepnaBDA5O9MMbAi/Nu0wuyHAl9nURTwNLP2V4jjINSK8y8+1sYnIHXGBik7Y8J099yY4EXFhCy5q0fhAeMgxut3x6qZfStbrXE2pWt0BbINKsVzBRbqITqLC8v7oSNI20K9DgBxYvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=XXbgXXgbkplKhi1qXP4uJ6TOwgdHfG0zKj0RTvp3xyU=;
 b=VJZijoL3QxCQAxCOFldKUGslYv4sKkdzodb5DnF/PsdQgEuvf8ufqvnDAqW20iH8b0g61UKQtAUohLQ/ilMZxfni796hcxeN3lALLcJSLlIlP8+i2f7JIEBqGoWImnyFa93vUmjpwELMhDHXg/nEtCI6CgH10CGO302AbIKcUfe1eGQuBNFRhWYbWyf0VuRwP319Af+4Rj/z1Lo9CEGbMBfrd5fIVN4J/SsfteSwjWuv+OsbCbpdi4W08TkJ6cq9dk5tk+nJEULeqBLum40b/WsrEjNeDr/2pPi4NuUILbWMBtdG6pGo48J2LgW7Jid6wAbEG9uC8SKDktjF4jF1vg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from DM6PR11MB4202.namprd11.prod.outlook.com (2603:10b6:5:1df::16)
 by DM5PR11MB1243.namprd11.prod.outlook.com (2603:10b6:3:8::23) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4042.16; Wed, 14 Apr 2021 08:09:57 +0000
Received: from DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274]) by DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274%5]) with mapi id 15.20.4020.022; Wed, 14 Apr 2021
 08:09:56 +0000
From: "Zhang, Qiang" <Qiang.Zhang@windriver.com>
To: Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>
CC: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: =?gb2312?B?u9i4tDogu9i4tDogUXVlc3Rpb24gb24gS0FTQU4gY2FsbHRyYWNlIHJlY29y?=
 =?gb2312?Q?d_in_RT?=
Thread-Topic: =?gb2312?B?u9i4tDogUXVlc3Rpb24gb24gS0FTQU4gY2FsbHRyYWNlIHJlY29yZCBpbiBS?=
 =?gb2312?Q?T?=
Thread-Index: AQHXKrzDGHQ+LKiz3UinMerWnn+L46qynjeAgADR2QCAADfF8IAACicAgAADA/o=
Date: Wed, 14 Apr 2021 08:09:56 +0000
Message-ID: <DM6PR11MB42020E2F3A57E285D512A7B2FF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
	,<182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
	 <DM6PR11MB420260ED9EC885CCD33840EEFF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>,<d47e3abad714ddae643c7e3a10bbf428a65ddd17.camel@gmx.de>
In-Reply-To: <d47e3abad714ddae643c7e3a10bbf428a65ddd17.camel@gmx.de>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [60.247.85.82]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 406e4296-d119-4ce8-e43c-08d8ff1cb12b
x-ms-traffictypediagnostic: DM5PR11MB1243:
x-microsoft-antispam-prvs: <DM5PR11MB1243CDD79B522916A86985DBFF4E9@DM5PR11MB1243.namprd11.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:8882;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: TlTZXAjN6QuK8rV1ZnY0MBGu5lIfQZ1v00pM3m6c/jsfXiuGwuZ16lTyOweI0AustAWOYp1NtO5xh9KuglJ9dm6SZpJi7lpcBo3IqiJH4P7OhrdG2U9CJgLcA8XJ0Z/SFaVPVCBQbKIVGN+hwL27+Ltn/7reLIwiHJKwm21lVDcSPSZfUSzwFHk0X9WVNCkQvlnJxO8+zgZQRNmakLhKmVo3ndC4gdHwori433gbORy0fpYJVhRS9bRkDlmXPYlDWS1VsBeXtxqDLZioK4Ipur4scHsbX5/TK2KSeVbDODx7mEZvW5ZMZAErxiMsvlnGmC+hkNH6g5+Rh1FHOHPBJ8cfn2KOQZkHrS3kF0etDZoy0JN0imPh8JATaN+XV9Z5T2RgSGRXz9dx7E1RsNasoero8VmQ3ALGAExTJ9mm9ITXg9ZTG3vLXnIkLKrtKQE1LykmN+/hfUXHHodGfoeYQ538HiycJzgOTUAqufR4kg8aiuccZUGTe3K4BuizS8hwCfZzPjKEweysODSCMRLAcRp2e66jwsnI1GD2idwqyAWsvKnXGWOF43UB8nnR9wpsLv66fBFEUZET3oC9MXYWvTQRQVYDd96ve6H8uOxKoKc=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB4202.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(396003)(39840400004)(346002)(366004)(136003)(376002)(5660300002)(6506007)(7696005)(26005)(4744005)(186003)(38100700002)(122000001)(224303003)(71200400001)(478600001)(4326008)(33656002)(91956017)(76116006)(8936002)(55016002)(52536014)(54906003)(110136005)(86362001)(316002)(66446008)(2906002)(64756008)(66946007)(66476007)(66556008)(9686003);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata: =?gb2312?B?TUxuN1FBNHc0V3h0SnQ4SlphR08wTnd4T21yclRvVmJ1aGNBWms2REtKVUox?=
 =?gb2312?B?T0F5bjZuck1oRVdWS3dzRW5XZTQzeEE1ZlJreU5DSmJZY0dGYllCbTRmWWlP?=
 =?gb2312?B?blg0UjVHTnN2TkVYZEtkNzJVWFF0OGNPVVFIcEQzTm0wSTdBQkFQT2VsMCts?=
 =?gb2312?B?cHNaOGhGUUtTeXBoN2pPWjRNZXhyaGt6OG4rajBhUTRvVWwzODhsZnY4alRO?=
 =?gb2312?B?Rlllckx2WVVnSWZ3T3Urc1RERlBiZ1pCalFZb3JDeE5kLzVsOEppK1JyVnY4?=
 =?gb2312?B?Zm9iSlFJaFVueVpHdEhmVWU4WHh0MDA3WTZnVE5WLzg3Nmc5VGZBdU1jM085?=
 =?gb2312?B?Q2UvTFhUbUN1YzdQZjZvWTJSaEFhNmt3bTZWYmVpajJqeFBFMGpjNmlLdXRp?=
 =?gb2312?B?bXNPS0hldkRTUytJb0g3K1ZVcDlSZ3BSNkplU3VhZTFNdFRMQmpaRDIyQTgw?=
 =?gb2312?B?ejUzUXFmdkZEZTJ6WVVPSER5Rm44UkhNZEJ2T1RicXZrZVhUckNqVXplMml3?=
 =?gb2312?B?UUZ2Uk9rcy9rb0lSQ1FCS3dYalJjUGlkK0xiR3BTWEQzYkp3SkVoUm55Y3ln?=
 =?gb2312?B?SHVWclcyWnF4WUNyYTZuUFJwWUxHWERKNnF5RFM5TU9YcUhQbCtzcy9ZcHF2?=
 =?gb2312?B?a2ptd2YxdDVSSDVYMk1iclNJZS9ZNXFYeHY5dWxZZGZ2UVZubDl4VWxIa0c1?=
 =?gb2312?B?aExnZWJSQi9LYVRSd0VnZm5QbDhJZ3pTVWVnUzFQUHoxVm81Zlczb0RSc0pk?=
 =?gb2312?B?eU1UbDNuU3VscmVveDlsZS9FNEs5aDdsd1pNUDJvOUk1a0hVSFppV2luNy9V?=
 =?gb2312?B?c1ZGKyt6YktaUHBia20zZ2h5Vi9kUUIzUXFrTlJrWmZYTU5EcFhuRkNZaWRr?=
 =?gb2312?B?Tlp5YmljNFlmSkNaU1RZOGNweEsxYkpqR2R5SStBaURvdy8xcERKMFlOSkhB?=
 =?gb2312?B?TnVXQWtRa1JYOWJtVnYwaDZOL3VtK0htc2J2QS9DMlhEeWhod0FGMmtrVFh4?=
 =?gb2312?B?VG5Ja01mcGdCME9raWNFU0d4bVJBUzBKL2o1R01CelFQV0Z2U3MvcEhBSCtO?=
 =?gb2312?B?Z1ozaFZOWTMraG1McFpaaHdCaFpOdkdhMExJVkhUcVdvN0VrYnNlWmtTdWVu?=
 =?gb2312?B?L2xtL0s5R0pnMS9pVk4yUTJ2ZDdUTDhWaWZ4alVlZ20vcG1WVkkzSEZtbjB6?=
 =?gb2312?B?MUlMRk1UTkpoZFdaa2tGRFhnNmo2d2swZmluZU9WQkd6bHVlaFFmb2xxTFRt?=
 =?gb2312?B?d3BzTUxjd2xpSFA0Z1drQ01TU250cGVNN1pzSVVJQ2NkR2VHTk4wWUZRNm8y?=
 =?gb2312?B?d0o3dHl5c1JwWlhVb3hHVDFuYk52YXkwT1h0L0dPMkFDQ0JDZENkWVlyejlP?=
 =?gb2312?B?a3lxV1k1bUFHYkxXZjZ6b0VBM3FQc2lZcWlrdytDYVl6b1RBS2ttRDRxcWN6?=
 =?gb2312?B?eHpZTWdFcFZWRmN6RkM2Z2pEemlSZW9FWE9iSVQwbzVmVGhpeHJNVWgyQTRu?=
 =?gb2312?B?QmJKQ0NZVW5jelZlUzZzWHIremgvOWcrNzN2RnBxZVJPaUpObVBBeXZJYjZq?=
 =?gb2312?B?MjBiQ1J5WFIrNDluTnAyTmN3Qkh3Vm5QYXo1ZFhITGVUdWFONUFDVFU5aGhx?=
 =?gb2312?B?ekNQa0N2em8raFkxd1ZQWmNwWUcxOGFMRmlvektSUnJsc2RvazBhMDhrR29C?=
 =?gb2312?B?T2JRUDVVcHZEem9QM1ZGbm81RGZ4RmdGSk5jRmxrMGNDTnB3Z1ZYYndpY2lZ?=
 =?gb2312?Q?uI985C8LNY1qtYtZrc=3D?=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB4202.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 406e4296-d119-4ce8-e43c-08d8ff1cb12b
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Apr 2021 08:09:56.8456
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: MytB50pMoqLthg1VVkefiVu4kXRDIXICht3ZB0utQy0YEedXjKnGhSfEEaKdGiO24E6Cxn6pLC92fve/gHq5M9XrRz8LgmXlcwjQ3G65PzM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM5PR11MB1243
X-Original-Sender: qiang.zhang@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com
 header.b=dNP0lPzV;       arc=pass (i=1 spf=pass spfdomain=windriver.com
 dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates
 40.107.223.52 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
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
=E5=8F=91=E9=80=81=E6=97=B6=E9=97=B4: 2021=E5=B9=B44=E6=9C=8814=E6=97=A5 15=
:56
=E6=94=B6=E4=BB=B6=E4=BA=BA: Zhang, Qiang; Dmitry Vyukov
=E6=8A=84=E9=80=81: Andrew Halaney; andreyknvl@gmail.com; ryabinin.a.a@gmai=
l.com; akpm@linux-foundation.org; linux-kernel@vger.kernel.org; kasan-dev@g=
ooglegroups.com
=E4=B8=BB=E9=A2=98: Re: =E5=9B=9E=E5=A4=8D: Question on KASAN calltrace rec=
ord in RT

[Please note: This e-mail is from an EXTERNAL e-mail address]

On Wed, 2021-04-14 at 07:29 +0000, Zhang, Qiang wrote:
>
> if CONFIG_PREEMPT_RT is enabled and  but not in preemptible, the prealloc=
 should be allowed
>
>No, you can't take an rtmutex when not preemptible.
>
Oh, I'm in a mess,

Thank you for your explanation.

>        -Mike

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM6PR11MB42020E2F3A57E285D512A7B2FF4E9%40DM6PR11MB4202.namprd11.p=
rod.outlook.com.
