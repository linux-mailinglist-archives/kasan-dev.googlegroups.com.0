Return-Path: <kasan-dev+bncBAABB7FESDXAKGQE62FRKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8A3F2E6C
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 13:47:57 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id k184sf694091wmk.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2019 04:47:57 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1573130877; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ph5e6yayVComMtJDXqqgHoRR7yF/PlzWd9uVfV1vJbnfOfl1uBEWITBtBcEJyhBj7A
         NT9iWlYSQnSgzEj6vO0h3csc10czjUKAS5Bbz2Cp7CEtPnKkRE2BrPf8JljTB8+8ozDJ
         vyebbuh4K0BzbhL3oM0Mv6eTB6W8V9L7wtIEe1kYRwTUlapEOtnaBvnPXS/7Xeou867m
         aMXaK7U3CYMNCvwgUxJ/RtWspYEyx46sG0faB5+a8syLC3QDz37+MNfkyzKaQvNAfaLA
         jmPTQffEqEHFBY9irJmiKMNI60fx6fbER13g5XkvwwkqfkRKC2Q2KS/zNepiF1kdmyVd
         2TuQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer
         :original-authentication-results:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=sNHwhbI2YpvSmpAnTKae0+4f7TBmQgxAkstm6d1uTIY=;
        b=iPXCFfjmoCgIqvdLF7IVOUPrecah6NIOlPoJkFf7Ay3XIvCllXVCen/Dkh7DjOrs42
         BYg688YcTZwLp6XfTgPkvpgCj2NZ9rPecPWCD5LKrqPVgXXBAJ6355OrpIh9aZ5Gq1zH
         dIyH4g83x3ux4G8CnaXGZqTpoafD2wpy4my3NzCGcKkOLhrlYZFMrkiwx+8ICsHEyiP9
         c3WCmrwkXaD5Gxkj0cyFRSaT2FJjJtn9hsPy0M+1TERuX3I7yoa8RDWepYZfS0iC9HqG
         ncEcWxGmwSTNu5oHuPEMnlsMIxPhlSb/xQ87OK/VYy+fBSzVu2JtXspS5KRCK4kdb8dF
         eTIQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=fTIFiuf5;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=fTIFiuf5;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.71 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :mime-version:original-authentication-results:nodisclaimer
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sNHwhbI2YpvSmpAnTKae0+4f7TBmQgxAkstm6d1uTIY=;
        b=E0v58kWK9wtXnoP8lhwrYzK5Gvyu764SqQ0OOCVq7iAUihrWzT8bpD7u29QKN7Hpqp
         NsaEXbZBTSFTOdJatAX9a3IBy455iIZCfpF+jhU2SWFCnyEbfpblxTGpMyind3/zmc4Y
         +TwgqIrNJevD8Pvo9+kWxaD7njx6g5fWb+X+mN+lG2P4KmIhvCG3KOKjFLZXlGyMfPhn
         7llwUt4a/xeLrbS1hNxV/UJcGdbAD5ArAi4zuKStZwE0BoOBQsVvzJnbxUmQ4vjIGfkk
         nzyZEqzXj7posMZ9sqfNjDXis/c3lfcYT9VhsLvtldgLSGS5BKqwiFNP30dgnEhdPiYk
         Y0LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:mime-version
         :original-authentication-results:nodisclaimer:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sNHwhbI2YpvSmpAnTKae0+4f7TBmQgxAkstm6d1uTIY=;
        b=oiNQw+LBABuWsPheuF1w9FpuHuSEPlE7ODeqZ8Oc987MUPE3vNS6HWgl8KkXpAxoBx
         XqYPLX6LKAePea1HF4SjTh+7jzdGQIvsNLeh4BP68ICRVMVyG/blcdKevTkySIY5guD0
         ZTNgwbpJEYO4Goy/GQMDqyAsFvcyGIG7FQEbMb02HqHzxwn7jXp+KmqDvnAd38Z44uKu
         whJg/Smo69Vq0t+oPHojiQF2pSAoIy/tzC3JLYDXc2VXMUpWoLV2e0Es4OOARrMslYZQ
         hB0as88ZLsrKiTueOEUS1lBGrWiLMrEHk8uzz6c1uihcBOTxMZXqxriK7ZGfYQmhEwJr
         uoDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWEFQNYcPQIZEs/S6ANww27TIxcvu3vupaVcQkIxPB2wuaK5XcR
	qKMdOc39gciFozcadWhiG9I=
X-Google-Smtp-Source: APXvYqwhWu6B1JKPk1zsTeL5G0zj3Ylwa4UF/aqtcIhqRWW9UxIWXpohsXvvD1UNi14mYoXIYxv+CQ==
X-Received: by 2002:adf:f150:: with SMTP id y16mr2641373wro.192.1573130876960;
        Thu, 07 Nov 2019 04:47:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b1d:: with SMTP id n29ls1528181wra.8.gmail; Thu, 07 Nov
 2019 04:47:56 -0800 (PST)
X-Received: by 2002:adf:e944:: with SMTP id m4mr2820738wrn.49.1573130876362;
        Thu, 07 Nov 2019 04:47:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573130876; cv=pass;
        d=google.com; s=arc-20160816;
        b=c4DUimA4BD+qH50yoH5HMyrZwIx1Gm6fyBPawNEI7iWJUWb5kXnaSUmazqOW99ABlC
         cmAJTLhXlw9lg5ZoAjsZEr3IVC9GrNBKAbi2mkmwNmbnC21ZKWXrtX3EoBDLThZwcxkP
         Vgkny/xFlg5+2v+bSjFoTa/Mm2GHnn+YGha9YhHLVxRapv8icaf4aSKwF4F0xUDO++R6
         +qdKYnVEt0Yet7GCb8cn4jENbiLda9ka0Hmv/GJIaXH1EFocJOCE0Mp/cEdgup7uJuYJ
         Vb0MDU7DUDwfafmHfNd0lF1Yr648aCxK8rdZnzXdefhcBZ5YSyyN8waaJL78kieavdEt
         QDrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=nodisclaimer:original-authentication-results:mime-version
         :content-transfer-encoding:content-id
         :authentication-results-original:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=dr3GeADUajNO7RwSsDbRqBV0UP/Ms437yNOgAHx8qbY=;
        b=CYBGcAF0XanvNt1Oc/FIynco28ScN2oxDE3pftNEpgiGC9R/TyE0jKpkf2/HoOUd9J
         0SwDKpCAkFNT6j7sPbPe/kNdVXE/R8VPIWWyRJeT7YyCGt6n0yM/DfOJGAWi3RmMOOw4
         H+v8fX1Rzq3fYSAbLN2D2hjLWgywqCImB04nXCbpot12OVLRAJskuAfeVCylcKKt1IZN
         y3zPBmNGnSvZWBlEMJw1u6Q43S2pb7yn2WrfZNtEnEikH9xC14bEANmdeFxZeGpnVu6Z
         Toi4PdMMAE2IUaiJSOZMj6VI1KCd4XgNEvsPzlgDYBsDm2g9XJhqlO4qnf3gjeiGTz3q
         vTgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=fTIFiuf5;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=fTIFiuf5;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.71 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
Received: from EUR02-HE1-obe.outbound.protection.outlook.com (mail-eopbgr10071.outbound.protection.outlook.com. [40.107.1.71])
        by gmr-mx.google.com with ESMTPS id e17si107157wre.3.2019.11.07.04.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Nov 2019 04:47:56 -0800 (PST)
Received-SPF: pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.71 as permitted sender) client-ip=40.107.1.71;
Received: from DB7PR08CA0026.eurprd08.prod.outlook.com (2603:10a6:5:16::39) by
 AM0PR08MB3940.eurprd08.prod.outlook.com (2603:10a6:208:124::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2430.20; Thu, 7 Nov
 2019 12:47:54 +0000
Received: from AM5EUR03FT049.eop-EUR03.prod.protection.outlook.com
 (2a01:111:f400:7e08::201) by DB7PR08CA0026.outlook.office365.com
 (2603:10a6:5:16::39) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2408.24 via Frontend
 Transport; Thu, 7 Nov 2019 12:47:52 +0000
Received-SPF: Fail (protection.outlook.com: domain of arm.com does not
 designate 63.35.35.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=63.35.35.123; helo=64aa7808-outbound-1.mta.getcheckrecipient.com;
Received: from 64aa7808-outbound-1.mta.getcheckrecipient.com (63.35.35.123) by
 AM5EUR03FT049.mail.protection.outlook.com (10.152.17.130) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2430.21 via Frontend Transport; Thu, 7 Nov 2019 12:47:52 +0000
Received: ("Tessian outbound 0939a6bab6b1:v33"); Thu, 07 Nov 2019 12:47:52 +0000
X-CheckRecipientChecked: true
X-CR-MTA-CID: 1a4c1b5064bbc139
X-CR-MTA-TID: 64aa7808
Received: from 9df16ce65598.2 (cr-mta-lb-1.cr-mta-net [104.47.12.55])
	by 64aa7808-outbound-1.mta.getcheckrecipient.com id A6B01231-891F-44A1-A6E1-7A3DB2531073.1;
	Thu, 07 Nov 2019 12:47:47 +0000
Received: from EUR04-DB3-obe.outbound.protection.outlook.com (mail-db3eur04lp2055.outbound.protection.outlook.com [104.47.12.55])
    by 64aa7808-outbound-1.mta.getcheckrecipient.com with ESMTPS id 9df16ce65598.2
    (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384);
    Thu, 07 Nov 2019 12:47:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=e8Y+PV8s1lsDW0syQqzZQVR7efIWDo+2iNB+jwleRVW1HMI8FMVOigvEaJFpovxWTs3VECE5brdwmk1ayuile76PnLN3C5g4PKUh8Jc4nlAbh2EOrcizV6t6WI316ZiaOcMlPj5ZFaeHNvNHQ+fgouuGayP2j47dzW5BfoEKWBB272vHB3kaseSMtSRVoS7Oye3Nl1FXtosA/fW/nk18VBcl8J4b4siYfH0aFz0GR16cb6ni9oT2r4oapc84NFdibPuVXZFqc3BFgXcMdLhcDC6AdHsIeLTjjoAg6BPRknnxaMnu20yB/VOMJB1FqZUuCtt3I0Ck0WTikkEhOU20HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=dr3GeADUajNO7RwSsDbRqBV0UP/Ms437yNOgAHx8qbY=;
 b=eCDt9V1MT7S915ysxhR2K4VYOzZpe0L29TEMeyLZZIntbBkT8ifXqXhWynaw8wnKsZAQK2AkN/HIPE8P6aXCZMaSLlRc+5KvguDO0I7PYWvUgrY83PGQhOE/xVeyYh7CF7hLE/TrZ/eM6plKFC+YCDD3ckRGTri9X/fNSvx74fIKgip/lQb8JpJsgM3Beg102UxNVHZG8qIt0PDB/w5ttvSGKG65qTnnWCifPEpotGxF5dwXAU53cKxThQbghC89qetYt2Iv92xEH7SQ2KbUzhG7wleuSymPmSBxDjQTC73ByxtD5Ye4bHc6uOMX18OrsdBbBIZOq5gtL5xmq1bxGw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from HE1PR0802MB2251.eurprd08.prod.outlook.com (10.172.131.21) by
 HE1PR0802MB2316.eurprd08.prod.outlook.com (10.172.130.141) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2408.24; Thu, 7 Nov 2019 12:47:45 +0000
Received: from HE1PR0802MB2251.eurprd08.prod.outlook.com
 ([fe80::e120:9a38:bcf4:6075]) by HE1PR0802MB2251.eurprd08.prod.outlook.com
 ([fe80::e120:9a38:bcf4:6075%5]) with mapi id 15.20.2430.023; Thu, 7 Nov 2019
 12:47:44 +0000
From: Matthew Malcomson <Matthew.Malcomson@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>, "kcc@google.com"
	<kcc@google.com>, "dvyukov@google.com" <dvyukov@google.com>, Evgenii Stepanov
	<eugenis@google.com>
CC: "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>, nd <nd@arm.com>,
	Martin Liska <mliska@suse.cz>, Richard Earnshaw <Richard.Earnshaw@arm.com>,
	Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>, "dodji@redhat.com"
	<dodji@redhat.com>, "jakub@redhat.com" <jakub@redhat.com>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
Thread-Topic: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
Thread-Index: AQHVk8z+/6P4LKLAqkOSZsJwRpLgNqd8jX2AgAMd/wA=
Date: Thu, 7 Nov 2019 12:47:44 +0000
Message-ID: <e5ff9f02-42aa-2515-29ed-837f8c299d26@arm.com>
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
 <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
 <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com>
In-Reply-To: <CAAeHK+wcYBtNn_ST7L2yEz2Zwge38UGCWthOKuepn3zQ90gZww@mail.gmail.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-clientproxiedby: LO2P265CA0088.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:8::28) To HE1PR0802MB2251.eurprd08.prod.outlook.com
 (2603:10a6:3:cc::21)
x-ms-exchange-messagesentrepresentingtype: 1
x-originating-ip: [217.140.106.49]
x-ms-publictraffictype: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: 478165f6-4004-416c-78d7-08d76380b420
X-MS-TrafficTypeDiagnostic: HE1PR0802MB2316:|HE1PR0802MB2316:|AM0PR08MB3940:
X-MS-Exchange-PUrlCount: 12
x-ms-exchange-transport-forked: True
X-Microsoft-Antispam-PRVS: <AM0PR08MB3940807C3A4642760F0E727EE0780@AM0PR08MB3940.eurprd08.prod.outlook.com>
x-checkrecipientrouted: true
x-ms-oob-tlc-oobclassifiers: OLM:10000;OLM:10000;
x-forefront-prvs: 0214EB3F68
X-Forefront-Antispam-Report-Untrusted: SFV:NSPM;SFS:(10009020)(4636009)(346002)(136003)(376002)(366004)(39860400002)(396003)(199004)(189003)(6116002)(2906002)(966005)(25786009)(44832011)(71200400001)(4326008)(52116002)(6486002)(66066001)(3846002)(7736002)(2501003)(478600001)(99286004)(6306002)(316002)(256004)(31686004)(5660300002)(86362001)(2616005)(8936002)(8676002)(81166006)(64756008)(11346002)(66556008)(66476007)(476003)(31696002)(66946007)(71190400001)(6246003)(66446008)(81156014)(229853002)(14454004)(14444005)(6512007)(2201001)(102836004)(186003)(76176011)(110136005)(6506007)(53546011)(26005)(54906003)(386003)(305945005)(6436002)(36756003)(486006)(446003);DIR:OUT;SFP:1101;SCL:1;SRVR:HE1PR0802MB2316;H:HE1PR0802MB2251.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;A:1;MX:1;
received-spf: None (protection.outlook.com: arm.com does not designate
 permitted sender hosts)
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam-Untrusted: BCL:0;
X-Microsoft-Antispam-Message-Info-Original: nUMyam4z7mTZIkJgeT7NyA6Re5o0TnKuUC/ny3SNbpLRx1yeN+9stWmsCYSCbEJkKeGXgRd/56CG2NSXNtBGvu6Pw8UNM9SQiv2bzVIkdeFgOanzC5QaE4IBbtq5IBbHlK7Xiq9q+YprlOhr2cDvzGw2IzkA5LiS8MXTxFw8Z3R+0lTF3EywPe69UCyWBWYgfrcmyu8hylqfT462uwBtA+ZfF82m/npIThkL8EJB9uRnNMVWoac0g8uGAs6UxUNUAKQ7BQtIWHOuHD55t2N2Stqo3eAH/tf5VAErCEdw7ig0Zu1k7zwB9R0QrvwKZ7h4MBv+xrv2AOVlnKk5RlSWIXBIBdGaujSPECSmeIvedrw9ljfPqKu948XUFUWD93lPNW36YXJIRTpSCm85t/wBIcNu/4XIdm6BBsP9GNe0yXmgoZvEtrnsox5wd+xeDVgLz5I/gAKFWUOFi6NKjf/vXrRKYCBmto342llK3dEGGHs=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <2B3CD901378188498D2A0CE04FAADA77@eurprd08.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0802MB2316
Original-Authentication-Results: spf=none (sender IP is )
 smtp.mailfrom=Matthew.Malcomson@arm.com;
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM5EUR03FT049.eop-EUR03.prod.protection.outlook.com
X-Forefront-Antispam-Report: CIP:63.35.35.123;IPV:CAL;SCL:-1;CTRY:IE;EFV:NLI;SFV:NSPM;SFS:(10009020)(4636009)(396003)(136003)(376002)(346002)(39860400002)(1110001)(339900001)(189003)(199004)(4326008)(70206006)(31686004)(66066001)(2201001)(386003)(26005)(81166006)(2906002)(6486002)(47776003)(8936002)(105606002)(2501003)(102836004)(8676002)(6506007)(31696002)(81156014)(86362001)(23676004)(14444005)(76176011)(36756003)(26826003)(14454004)(966005)(478600001)(50466002)(53546011)(186003)(486006)(305945005)(36906005)(476003)(446003)(126002)(11346002)(336012)(229853002)(2616005)(6116002)(25786009)(2486003)(70586007)(3846002)(22756006)(356004)(5660300002)(6512007)(436003)(6306002)(6246003)(316002)(110136005)(76130400001)(54906003)(7736002)(99286004);DIR:OUT;SFP:1101;SCL:1;SRVR:AM0PR08MB3940;H:64aa7808-outbound-1.mta.getcheckrecipient.com;FPR:;SPF:Fail;LANG:en;PTR:ec2-63-35-35-123.eu-west-1.compute.amazonaws.com;MX:1;A:1;
X-MS-Office365-Filtering-Correlation-Id-Prvs: a721515f-0c72-488c-c90e-08d76380af14
NoDisclaimer: True
X-Forefront-PRVS: 0214EB3F68
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: EUGz1i9dlUiYv7bVw3B5hgIMJQhuAloQambfKXl0RbUJTUqszabSEir4UCQcObpEimg+WpSvkr2jhkKSSOaQwwv42fPE26Wi/qgHexzK1pc1/Ot2eoPUVyeo0wz1mS2dbvY1yhEIOT1RUvFaAmBY8T46QmzAAtjgZDx2diiL7uyXKmPZqhMBvpGYFtj5qBjR2MiLxNXpWRLSrCq1Pwqn7VXt6ytCzSi4TCycFUJjqP/y4xY3zezpbyYOVt3gwb8r5JBr5Qo1AV83WUO9888k9x/ejrIKaWgkKGCW+LIu5LaBX4gfhHa3UMigXeh241tWZBiKvdhGGoC1bZINwK9M7MFo38a9y8Fkj4T3UkbdNjv6ZvMz70bddpNTyh5itBwFUp4UU8sJos4q3P7wpUrM43gk0mV+3pYjBTNacBgibNrKrKZPx6LIqUFwhRCT+l70IOGvnQCwqXzYV8B+EKYczq56mzwvFX9zFl7ol3oYd2I=
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Nov 2019 12:47:52.4564
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 478165f6-4004-416c-78d7-08d76380b420
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[63.35.35.123];Helo=[64aa7808-outbound-1.mta.getcheckrecipient.com]
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM0PR08MB3940
X-Original-Sender: matthew.malcomson@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com
 header.b=fTIFiuf5;       dkim=pass header.i=@armh.onmicrosoft.com
 header.s=selector2-armh-onmicrosoft-com header.b=fTIFiuf5;       arc=pass
 (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 matthew.malcomson@arm.com designates 40.107.1.71 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
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

On 05/11/2019 13:11, Andrey Konovalov wrote:
> On Tue, Nov 5, 2019 at 12:34 PM Matthew Malcomson
> <Matthew.Malcomson@arm.com> wrote:
>>
>> NOTE:
>> ------
>> I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
>> automatically defined when compiling with hwasan.  This is analogous to
>> __SANITIZE_ADDRESS__ which is defined when compiling with asan.
>>
>> Users in the kernel have expressed an interest in using
>> __SANITIZE_ADDRESS__ for both
>> (https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/690703.html).
>>
>> One approach to do this could be to define __SANITIZE_ADDRESS__ with
>> different values depending on whether we are compiling with hwasan or
>> asan.
>>
>> Using __SANITIZE_ADDRESS__ for both means that code like the kernel
>> which wants to treat the two sanitizers as alternate implementations of
>> the same thing gets that automatically.
>>
>> My preference is to use __SANITIZE_HWADDRESS__ since that means any
>> existing code will not be predicated on this (and hence I guess less
>> surprises), but would appreciate feedback on this given the point above.
> 
> +Evgenii Stepanov
> 
> (A repost from my answer from the mentioned thread):
> 
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
> 

I've just looked through some open source repositories (via github 
search) that used the existing __SANITIZE_ADDRESS__ macro.

There are a few repos that would want to use a feature macro for hwasan 
or asan in the exact same way as each other, but of the 31 truly 
different uses I found, 11 look like they would need to distinguish 
between hwasan and asan (where 4 uses I found I couldn't easily tell)

NOTE
- This is a count of unique uses, ignoring those repos which use a file 
from another repo.
- I'm just giving links to the first of the relevant kind that I found, 
not putting effort into finding the "canonical" source of each repository.


Places that need distinction (and their reasons):

There are quite a few that use the ASAN_POISON_MEMORY_REGION and 
ASAN_UNPOISON_MEMORY_REGION macros to poison/unpoison memory themselves. 
  This abstraction doesn't quite make sense in a hwasan environment, as 
there is not really a "poisoned/unpoisoned" concept.

https://github.com/laurynas-biveinis/unodb
https://github.com/darktable-org/rawspeed
https://github.com/MariaDB/server
https://github.com/ralfbrown/framepac-ng
https://github.com/peters/aom
https://github.com/pspacek/knot-resolver-docker-fix
https://github.com/harikrishnan94/sheap


Some use it to record their compilation "type" as `-fsanitize=address`
https://github.com/wallix/redemption

Or to decide to set the environment variable ASAN_OPTIONS
https://github.com/dephonatine/VBox5.2.18

Others worry about stack space due to asan's redzones (hwasan has a much 
smaller stack memory overhead).
https://github.com/fastbuild/fastbuild
https://github.com/scylladb/seastar
(n.b. seastar has a lot more conditioned code that would be the same 
between asan and hwasan).


Each of these needs to know the difference between compiling with asan 
and hwasan, so I'm confident that having some way to determine that in 
the source code is a good idea.


I also believe there could be code in the wild that would need to 
distinguish between hwasan and asan where the existence of tags could be 
problematic:

- code already using the top-byte-ignore feature may be able to be used 
with asan but not hwasan.
- Code that makes assumptions about pointer ordering (e.g. the autoconf 
program that looks for stack growth direction) could break on hwasan but 
not on asan.
- Code looking for the distance between two objects in memory would need 
to account for tags in pointers.


Hence I think this distinction is needed.

Matthew

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e5ff9f02-42aa-2515-29ed-837f8c299d26%40arm.com.
