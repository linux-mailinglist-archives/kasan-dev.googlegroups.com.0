Return-Path: <kasan-dev+bncBDD3TG4G74HRBTXVVWCQMGQE3JJ3ZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id AB54F38E3B0
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 12:07:11 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id pf14-20020a17090b1d8eb029015c31e36747sf8148580pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 03:07:11 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621850830; cv=pass;
        d=google.com; s=arc-20160816;
        b=hhdLs9aElDEnyRrTy1IRTuMkdC1q55BtTByODOK/xViARlCzWLwNXur6Ornq9Y9bCJ
         4yj8EfPTy8lPsFpWT6zhzDv3GDuzHqzn6hGeCsl4R1c+Nrcb5kp6FZfIwPVAuBxDbXyN
         gWMDhoChB7/AiObM6CjsKq37HT3Ku6Vbpo886Tn3LSbFZcnffACpWkHHk44sFPtoRSXS
         AS8SHRXLkIvsyfSxbjoN+5L4CKlBw/uqsBbw9iCtwKtxM603mJQxoonvxLuy2CnaNGgn
         UbXY3LAqQhavC4ZZ2ikTjF7zczMo3zHOYB2EaOCw5GquXAMbMrD8VYCoo864/KWtA/jm
         XhcQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=bgp+cSR6kp1zZExiaEIB8MDOJMqdyE24nxacxwgNidU=;
        b=BtLlps3/4A2HmvUxT47QL2I8bQw1oPS9zQApw8MQhOwY9MyKwPkVLuFR6dZo54pZHu
         GgZEsS6BtayI9UDJyQo6NrJC7pW0hNWwqlIlJLW5PInDaRvkM5Ws3TKb/9be3QTIS5UP
         H12i4LRqFWiMrO+Qi7+iX4y7i8m3bAPu/1i3gHI86weqKTRiX6P47kZq87qSdZeYOP9J
         L4FMvJxGaQuq0dITfbOvbJrWUV11lSrvtegejcfRy8wsE6vHm19CxfQNZZg+MPqO4Ihu
         tTDjooUvsSMIc+KUvy4vqgfqhe43jYQFLCjn46CZpUXq+64eG6wUN9yCixwB/TXSvHrI
         Xmwg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=SjS3pH8R;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.100.65 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bgp+cSR6kp1zZExiaEIB8MDOJMqdyE24nxacxwgNidU=;
        b=m1jmAbyQeoLxqwYpsDpRJ2o6So+zMo3vNOhZw/J2A39mW733ZRluO+NM6YsMYfHFV5
         IIvzVKS8pSgGJ/D2TUQRcv0QaDMsOySqlKGdApy9V+P+ukj1LUk0WGTzGebxC8pQtm+K
         BCUx14tI435s2zk7Sxg7YQQQ64rvl0F+yYHf225VWr+2hQEuYDMpSTvun4MYgGCoXpz0
         86Cc2Fm6uHD4XcUsWayyuKvTr3csdFBTTSv4MFMY9N6ITF5qOaq8aG38MW2RJhl8cjhw
         4LhMbPAiXwk2wNbXXeoxFgyYvMdCJW5y14Vyx7QSL/j+/ogFBDZbX0iR6HQCqF+KGcir
         48pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bgp+cSR6kp1zZExiaEIB8MDOJMqdyE24nxacxwgNidU=;
        b=Bbi0jTLsKWSt2Lgp3FO7UYwC5tSayc6/PIDEghB8ZBrEMuWiSTvDHHpbCMBkErRmB1
         +bdiD3nJaaw1wwAhtxJu0hDWd4y+clwtENYxLlQZIO4PqxaEaG9OSC5PPrsdhYjbzO1J
         B6mhEda94DDCLsslawjHrNhTRgQtiCyKtWazwQVDaS+Y437dqI/EnOqJHYY2G7iX3fDw
         25xk9l7c0HMoSEDHRqPkN9+ikaVQh9BIXMhKDAkoettdMFQcMZHp9FEECXI1wL0Ai+LY
         z4h7DjZSlH4ScevhfqwVh3NF6rqnDOFpfvAm1lI+CabUdU8ac9ATF76iyhKibIfhkypV
         opPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530H8d82Xc8jeDsCE6jEjiLifO0v3tIiwTzin1/t/dJJtgNp97jg
	LprsnweasLQiwRh3VImYChM=
X-Google-Smtp-Source: ABdhPJyjng7VSBivbBj0I7MkWidK8hMaBTYyq2vNQgsBNoTS4wi70x4yntPv/GWtqeRq9KikoiHtuA==
X-Received: by 2002:a63:e14:: with SMTP id d20mr12993655pgl.35.1621850830473;
        Mon, 24 May 2021 03:07:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d09:: with SMTP id y9ls1639212pfc.9.gmail; Mon, 24 May
 2021 03:07:10 -0700 (PDT)
X-Received: by 2002:a63:5158:: with SMTP id r24mr12753890pgl.41.1621850829937;
        Mon, 24 May 2021 03:07:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621850829; cv=pass;
        d=google.com; s=arc-20160816;
        b=X4h/q1jINJ3dNBRF5Dca12KV6EFf8VRKXwpF9Gr6CYnY/QWx/lgskGdGMJaDV1Jb5s
         shHLLYWcFv2IaA2f9NAd8XhKHUAstse/JjFAqiojl4iOvkLQTjGD+OAfWNYqYnKxRPp+
         dZR2DosrZJGTKnbP67LKrFiEf98mtuWYb0uq3KEj408R84tfPHLp9txzszHz68SxNOOB
         tP7y6sCrFn4Mj43vEPFzU6VejBu8/BvVuZzA71oH4XQi7SLvYWrk6gcnC/npZou3ubYa
         wOieXziHQQUOaZQadUhQnlysGdugds1gLqrajj7uHfC/a3Qv466BZ3HjWR9FUGQ6aMwZ
         DaFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uwcl5RsaNsLK1+EwM2BkldY1b/SklL+hPVRv3Co2kE0=;
        b=iIRQQdfnj1zILDu7vU68BR2hoTfMf88wPvf+nJzjOxJO3rpFkrL8siCg5Ol0wyCNmV
         XobKq4tozdKd8mx3ZapFef6I/T4pog4UMSezXdFRE3HxxN+qpDVvD7M32E7HBPQ6B+GS
         F5qZ3QQRj1AfQI1qG5pusQDBdkFPZ+NtAl4hm5fD6iA4JBmGjR/gbooyNW+SEWOnbYsZ
         iLRNbDhvYbx9BW5Nd+Vcg9FXfiVjj85cztBbRgdtFDwSr6H9HBMaCi04WNbVCUXI3Tl0
         U5vh6rUI8HD5ofRdvViP1XZASlOpWpmCZKVUuCuxSCW7oeEclcwUAUrJ58LWb1eJwlpb
         ejIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=SjS3pH8R;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.100.65 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (mail-bn8nam08on2065.outbound.protection.outlook.com. [40.107.100.65])
        by gmr-mx.google.com with ESMTPS id i3si1621176pjk.1.2021.05.24.03.07.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 03:07:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.100.65 as permitted sender) client-ip=40.107.100.65;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=h3jblEco8koxS+C5FwrneLb7JVBLOn+QPc1Rz3TX0bqr9OG93yeN+COkOxdMt8EdGqY//lQfMYzMXKiCJNBMyGztrolVkUHmH8VxarAFFmf88nmQh+c5WUkKBXWnYfdMFC7Ru4Z0mtkRqT0MyuV668xrrPO7bNfvvwbNxmjEaEB02xlaENdL7oyX/k8tUCoZiFHD58xToQjvljEmej0w1aeuHGV9jsQ0wKqNXnVFv3Yjnv9Sp7pdPMgHpAbSzhyRAmbC4Af524mdCu9vF+jN5jhC4fwjRa2Zhx8nr1EwaEzGy3SU+oyXanWh7bujjo9DcRMDlYlkMIsXTZ98iIXaxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=uwcl5RsaNsLK1+EwM2BkldY1b/SklL+hPVRv3Co2kE0=;
 b=im/OnC7vC52azxvxrwUpoJ1A131BtcOS+g/i0vL47cjqbQtfdiQ1hUvhJIqa6+TXnhBWGsN2jAxafW+VXE7+m1Quuq7JcrQA1lg1MRwMYEq3RbSHMg1VsLs33iiK40l0xbPdqJWxTxulB2Sfh0fx7hR+PUXMSsmYlvRYa4SmZF5TKCmPRKvbBq6OHOMgO0etboD2+PJ2ans1u9QjB6UvYaWNYSOk7hp+CbAn4biTEd6e8yNgFH4BWdJ1NAYzrMyCWZo7AyhNL19ub4mAmOEBBxdqSht6WmT2xU5TJxqt/TyM/k+VgWVBHZgrb/3gPsgJJ6YL066p9YR7ndYtHiH2Tg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BN9PR03MB6058.namprd03.prod.outlook.com (2603:10b6:408:137::15)
 by BN6PR03MB2916.namprd03.prod.outlook.com (2603:10b6:404:10f::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23; Mon, 24 May
 2021 10:07:08 +0000
Received: from BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791]) by BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791%4]) with mapi id 15.20.4150.027; Mon, 24 May 2021
 10:07:08 +0000
Date: Mon, 24 May 2021 18:06:56 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, LKML
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>, Mark Rutland
 <mark.rutland@arm.com>
Subject: Re: [PATCH 2/2] arm64: remove page granularity limitation from
 KFENCE
Message-ID: <20210524180656.395e45f6@xhacker.debian>
In-Reply-To: <CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
References: <20210524172433.015b3b6b@xhacker.debian>
	<20210524172606.08dac28d@xhacker.debian>
	<CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: SJ0PR13CA0136.namprd13.prod.outlook.com
 (2603:10b6:a03:2c6::21) To BN9PR03MB6058.namprd03.prod.outlook.com
 (2603:10b6:408:137::15)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by SJ0PR13CA0136.namprd13.prod.outlook.com (2603:10b6:a03:2c6::21) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4173.11 via Frontend Transport; Mon, 24 May 2021 10:07:04 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: a3914c7d-b5ae-4d04-7e04-08d91e9bb03f
X-MS-TrafficTypeDiagnostic: BN6PR03MB2916:
X-Microsoft-Antispam-PRVS: <BN6PR03MB2916B9FFF837C639BF9EF83DED269@BN6PR03MB2916.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:6790;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: pST88dq3lqlrbynmMAD/WXSjL7IyJtNjFfzTk4DWyWQ6S5+eAl9gJZF9NaqE5I0AF8aAmiMkZyjjG2tpb9UgQbcAykR3O6mg3PPgU/84aE5578PqwCG51oRmPzMn+WgpE2G1WRVemx7tQY3dgL2mxkAH9U+v1FJEW32mQAEPgqz4LG48K3JrNIVNHqwGfshiLli6z8SOZvaECOArEmg8lvX4ULSFr3F4HnNYziBQ+OrjyDlrTPDV1bKm8NcnNRL0G71eXqUaTgb2V5wjPWIa2lD2R8DzSaXmNN2P28za+hlInM3+o0jy6/7ueQS/scy4cIeUGmlg0A0jUt9JlgfTfsT722FSWGQcUwNLdeEhDKrdVtHB54J2uuIyPvc+4cP+yiYb7yzqQxTtmLIA5WJ6GCMYLRerDrpKkxqMSy1tl4UrZfHf8BxHQ6hMTzFI9SgLJo87KNYMn036HsSLeH4Hfjus+sSou4aLNFY/1e1ZQ4CGk19/kBnQgOmvS+WuHMjB0qudnafa4lCju8/k+sGb3Vaoy+yjN6PUOBZ6rLbQ4FgpPdNu2ExuwhLvCXy7oK+FoduQhS9P9vtdb/QgSN6v4+p9AnaI/6uRUg7dv8Dx98VBlr0A3VcZ4YMEGV6mm5kMJxpgm4B32MfJhYj9SKy+2az31h2u6mzNgcpPb973QEc=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN9PR03MB6058.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(396003)(376002)(39850400004)(136003)(366004)(6666004)(55016002)(316002)(54906003)(9686003)(8936002)(8676002)(38350700002)(2906002)(478600001)(956004)(5660300002)(52116002)(7696005)(186003)(83380400001)(7416002)(6916009)(4326008)(26005)(66476007)(16526019)(38100700002)(6506007)(66556008)(66946007)(86362001)(1076003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?s3pQEW5PV1jGpW1PylaIre/b3KZp2HZepQRkwm5SrAhL2HnJCVksSk217O1r?=
 =?us-ascii?Q?O05Gu73Tky1pGIm53DDM4/R5q/YQeJSTS62D03gTdkDSR8FNAgAoEqnKah6W?=
 =?us-ascii?Q?gfq4rY0DCUte1UKkWK3Y5cu0W3WR2Egeox9boOw2psjmrwSJ07BJuMro68Ii?=
 =?us-ascii?Q?2IpY/7EuePH8mDFON2douoME9RBNapg1x9VIYnRdLauZXTXTMl5y6KHD5DIO?=
 =?us-ascii?Q?dKpFEwjNG4hcd3WSESzCFL3vHUBDzXCQQD7/RHXWH8m4aw96J+eJAm7/oXm1?=
 =?us-ascii?Q?s3NBsAbTLejXzCMVKcOiQlFLYVpoCUmSk45hZOeE9cSXR1F5pHX2oy+TlHL3?=
 =?us-ascii?Q?VDWSn4NwBHjzcTADN3bWsCRvJJh0dwpV7/8f9oOoIlqlnFL4t9D+cYQYdR/7?=
 =?us-ascii?Q?wBiPbPrcIrWBRgeQvdhBi2cj/ZEIUsUKgcso7QEU2nLzQnG8vG0co/nqRbDw?=
 =?us-ascii?Q?MF06HtLbb7iYH5tQHSOLsww3AAF1HCvqNrt5MIANT8503G4jh9aip7zMhhv2?=
 =?us-ascii?Q?Xk5jZaC//gitgxwRmEN5upvFkiBBfzgSJ8erINwCT2RH3vPVCd6LdP2yMONX?=
 =?us-ascii?Q?6RTapTXwbdHFJ5KF6TBgC//6y2xLo5ZzALy4R/6FfXWfuG6sYp7S6SK+GGl7?=
 =?us-ascii?Q?y9pF6/MM0X4N+iqMaNFDeN0u4YjS4ak3+L2z3yzEnsONspACntHs3WjKSqa5?=
 =?us-ascii?Q?gxzW56Ke3+IzVIcxjpCrFeiJkrpf5ckX0LdmDPBHdC/7+aYLJ0HNIb4jQ/3a?=
 =?us-ascii?Q?LuRZXxo/Ze54Xwy2cGHUGEIQISUmtb4U8CQm7S92vYEf3jEx5FaEpYAQ4Rw8?=
 =?us-ascii?Q?4y0dsHDwrxjGN4B3pTpaajio918qsINr0WYsOAuFkf3bONKdu8ImhiwHhJdJ?=
 =?us-ascii?Q?2qIgfLQakPXj7fTjrnCvfBXRzHf4V/XO4cECX9MFzjUBaqK+Eod1h3hiAQE7?=
 =?us-ascii?Q?8Z6YUHeMDfZmmAs8WQT9Apqjxl0EPFvj2LAzJFC9PRYxMzFv635BTEUcLmcq?=
 =?us-ascii?Q?m1D/rH9XtaaxZv+2+uWfbGl6Xf4QGcKXr9YjQl5DuSJDY4Bijtge9kALNa79?=
 =?us-ascii?Q?ryCoKFfyl1fnA2AVmXSGqpShzsioWqXCg8QmwkQTmmg5qaomyH2hhP3OhHRC?=
 =?us-ascii?Q?sacCH6vchlv5lplTs8h05EgVuV95C1JLP7tAqfxGtUlpTta/LKUi54ZGzOK9?=
 =?us-ascii?Q?H4q8rDdl07FwfsfxSd2d3tkoiOLjF3UoTLMV4Hh9Oql/MMotGyFodowtGJ7x?=
 =?us-ascii?Q?5DO3baNiUs9w6oatPrku7dCvHwnTt6D0AHuT7urkDPgzXQ1so4eBaQyEU6S8?=
 =?us-ascii?Q?ElcZOec1XrdZHGeYJQL6KYyN?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a3914c7d-b5ae-4d04-7e04-08d91e9bb03f
X-MS-Exchange-CrossTenant-AuthSource: BN9PR03MB6058.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 May 2021 10:07:07.5978
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Zc7LqYPjiEPZ/yvkGkdgVinOeYTOaXXWd0+8rEZTMmt+V9d2qK9jZ/2tb/8bqZZW/Nq+kOlUeNV7f5v+LBWiIg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN6PR03MB2916
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b=SjS3pH8R;       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.100.65 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
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

On Mon, 24 May 2021 12:04:18 +0200 Marco Elver wrote:


> 
> 
> +Cc Mark
> 
> On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.com> wrote:
> >
> > KFENCE requires linear map to be mapped at page granularity, so that
> > it is possible to protect/unprotect single pages in the KFENCE pool.
> > Currently if KFENCE is enabled, arm64 maps all pages at page
> > granularity, it seems overkilled. In fact, we only need to map the
> > pages in KFENCE pool itself at page granularity. We acchieve this goal
> > by allocating KFENCE pool before paging_init() so we know the KFENCE
> > pool address, then we take care to map the pool at page granularity
> > during map_mem().
> >
> > Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
> > ---
> >  arch/arm64/kernel/setup.c |  3 +++
> >  arch/arm64/mm/mmu.c       | 27 +++++++++++++++++++--------
> >  2 files changed, 22 insertions(+), 8 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> > index 61845c0821d9..51c0d6e8b67b 100644
> > --- a/arch/arm64/kernel/setup.c
> > +++ b/arch/arm64/kernel/setup.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/screen_info.h>
> >  #include <linux/init.h>
> >  #include <linux/kexec.h>
> > +#include <linux/kfence.h>
> >  #include <linux/root_dev.h>
> >  #include <linux/cpu.h>
> >  #include <linux/interrupt.h>
> > @@ -345,6 +346,8 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
> >
> >         arm64_memblock_init();
> >
> > +       kfence_alloc_pool();
> > +
> >         paging_init();
> >
> >         acpi_table_upgrade();
> > diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> > index 89b66ef43a0f..12712d31a054 100644
> > --- a/arch/arm64/mm/mmu.c
> > +++ b/arch/arm64/mm/mmu.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/init.h>
> >  #include <linux/ioport.h>
> >  #include <linux/kexec.h>
> > +#include <linux/kfence.h>
> >  #include <linux/libfdt.h>
> >  #include <linux/mman.h>
> >  #include <linux/nodemask.h>
> > @@ -515,10 +516,16 @@ static void __init map_mem(pgd_t *pgdp)
> >          */
> >         BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
> >
> > -       if (rodata_full || crash_mem_map || debug_pagealloc_enabled() ||
> > -           IS_ENABLED(CONFIG_KFENCE))
> > +       if (rodata_full || crash_mem_map || debug_pagealloc_enabled())
> >                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> >
> > +       /*
> > +        * KFENCE requires linear map to be mapped at page granularity, so
> > +        * temporarily skip mapping for __kfence_pool in the following
> > +        * for-loop
> > +        */
> > +       memblock_mark_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> > +  
> 
> Did you build this with CONFIG_KFENCE unset? I don't think it builds.
> 

Oops, nice catch! I will fix it in v2

thanks for your review

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210524180656.395e45f6%40xhacker.debian.
