Return-Path: <kasan-dev+bncBAABBPUPSSVQMGQEASGXZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 481EB7FAC73
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 22:18:56 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5bd0c909c50sf4571379a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 13:18:56 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1701119934; cv=pass;
        d=google.com; s=arc-20160816;
        b=GLTOghNFKhMXVt1RpOmw8eab0oCUhBIACg8A+S5kwycKfnz8cODDWwAafwAr64Z5OY
         Ztwcf2HerPiD+g7r6imf3SUMar/TFznJi5QjndS1eihWq/KUmTjP508gK08IcKq2UFrl
         hfi4bjyuNwT2+2k3jwrL0hVMBNJNpg75QF9+aODQP3uP33wG0v4xI6LxVggilY/filn/
         3Qm6hZ2/MORCj3QLORbozPrEBfhscn4P/zdaClC4CUzgWWTfuMkV8FnX4SwDvgJ4TJ2K
         aE72hZGePYcQdrNGKnb2NPnrFvO5+wNyYoBu/55Iif5MTUnZJ3UlfI0JV3cuW20CuMkf
         Cr+g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kxbmbxCzPm8Q3yTroWAXuobnLv+Q1/350y91tC+FX9M=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=sqmR8EknMN3Gk8fl9c9E37RXF47AT6jm+LUOgXDXD9QTIGYOdZIPh0ELLqSyqfrkhN
         rEavQyqVrWNZSiT2l7YTbJNS3eP8z7sbGwLBnBfaPWynmFX5HfFVz+PQRxRDvmgITNPG
         y2N36M3TMFcn3uz5LAmT53M4v5SdlBpQ347jQMMg21rY6zKMfNtDtPxCZqE1iEB5C/6b
         SFn0rgvoctgexYajpWSWS+zW3YhSbo0iMR92hrAIPu6+g4GLzq7fJQimd51tE7CCh2zg
         +DRIXs8vPPEeyMMI0YW0/7nEI7XKrv6HVA5EyTcOJ/gave600/fcWkWK6jBzbKBp2uhv
         hcoQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=WpZ6Eq8c;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1a::821 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701119934; x=1701724734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kxbmbxCzPm8Q3yTroWAXuobnLv+Q1/350y91tC+FX9M=;
        b=m3U4bGJZJOmYdXVvdw26PTSEonqP8Q9pibuZwkBRZaruPaEEKV2x16kUPfXw3gkcHO
         oKZv12cfI/Qoz3rYwgaQqzBbmYlCBnsOQxizP8JEE7471ohcvxF3PhjaWrvl9O1HK+aL
         utiIPLiBxLYfW2HMrZ0ERZa/DVlMlIpGEi685YVv06LBgtQY3cIRIZGxD8Il/7jMzUiA
         THUcDC/RS51an5PfJHb4xnOjqTsuHp2BZ41iR7YhqUrfnkAZ0C7dKfROHl2CtgVW9LKF
         yCHLXIVlnZ6hveFGQanIvDUu7ajcQoV3N52hdTSaheaBTKho1TT3DMJwdSMpDeSPAAuT
         Gs9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701119934; x=1701724734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kxbmbxCzPm8Q3yTroWAXuobnLv+Q1/350y91tC+FX9M=;
        b=H9lltO1YfxmhmmAmFlmKvasT0oMXgvSZVwsBStYm2/AIkPQWKw8AzD4TE77YDpeDtu
         qHHWY+8fMKslo+cH+vfjq0IAM1kmwa3XhWHpf5wccrKgYdZMqY1/DCrhjvcO7ZmEKRsa
         2BerMN0adZSFLGTwqOG2K9f6TZ7zCIaljkrPFkMoXQ7ExFipli8sFw0CrKDMAnLQsVrv
         nN6wbDZuNIlOHmCLuNElDa+WMUkeZVErzrqTFhf8zPDqgsvHtn84u/VTJpNKYuxQ8+kw
         mfrMVvtLlyfEUyqqltiatK9J/OlDEhmO+zZMoTvL4fRv0kvyfWrbPTodb1OE1Vl3KHDH
         4oGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzq7WULUYRWoNyTQkmRI8g8Nvl+NJfVXGJbQgyYShht8XEZTnMR
	zivjMELRjT/Vv7TucKHYpUE=
X-Google-Smtp-Source: AGHT+IE2Ecw4J2ehBY/tH0Hrm7Lgg99OQ2JWw2PKHItRjLfXGJsiFfn4eGT0h7+iat7B+GbGML5Iug==
X-Received: by 2002:a17:90b:4b4b:b0:285:b928:e2e4 with SMTP id mi11-20020a17090b4b4b00b00285b928e2e4mr5708091pjb.30.1701119934277;
        Mon, 27 Nov 2023 13:18:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fa89:b0:285:12aa:ad9c with SMTP id
 cu9-20020a17090afa8900b0028512aaad9cls3464936pjb.0.-pod-prod-07-us; Mon, 27
 Nov 2023 13:18:53 -0800 (PST)
X-Received: by 2002:a05:6a20:728b:b0:187:804:91fa with SMTP id o11-20020a056a20728b00b00187080491famr13880154pzk.35.1701119933319;
        Mon, 27 Nov 2023 13:18:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701119933; cv=pass;
        d=google.com; s=arc-20160816;
        b=n6S0OfFsahlK4HWXgW7zbQB3N66cjF4sPvZXBWUAgUtjRQ8G7HoUzK9qjhJd8OGJgB
         7hXOJxxrH7nf1g96cbNYDZSXfkXnEt19TZ4WBq/Rlkc1rS3k9vK/2bv6VbgDEviECvK1
         b/K0VcB94OOJixpswKz/DRw4RM6+Gsm5nU+1LBV//Ov/ZStutRtJQUEQfcRLp7qgv711
         Dndag61nMON6ecqAzO4I8fRAP+HRGdKUEuqQduWGRr5rHxyS2GHsloheOW8SQKgltM8H
         4yWms5oTTvGjQuetHr0kELmHy7KUfolO58Xj/ia5AwoV0HXPRTJ2Y+rwTA/ehWEz7Xle
         8ArA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7a8sAfnyzU8RwB1qe95F6+6w65cx/kPYT3PrEBc+32U=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=NhO2Na3CEiEquPlVXNWA/yoMD3w9EF3eIiOOqUBb8uiF0vEYgG7nY7/cj+xRmiI+EA
         SrLu+hm0UQpCiZdsDdorMnL4vKxnHwwd5CP857z3zFPFueIqcutj99s22BOvjEe5R9S8
         4nIgk11KqgPJujoAZNZvBioLLrOBc6geGquj4LZ68f5B6CAHt3LkKrCiol567X4ugeC6
         qwUxcT1VaFnzoV2Yn/wGCcqM/5QbSY+PntPBKd9wbTAwFqKV+F1BTOQ95wppBzv6IxQ7
         sVGDaDFpVPAjz8GvVI9agsW5/CozwYksmiJaCP+r4U3ozAC7YfVCraAX2l7eeyRcenmK
         fRDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=WpZ6Eq8c;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1a::821 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR03-DBA-obe.outbound.protection.outlook.com (mail-dbaeur03olkn20821.outbound.protection.outlook.com. [2a01:111:f400:fe1a::821])
        by gmr-mx.google.com with ESMTPS id p17-20020a056a000a1100b006c99448fdf8si643649pfh.6.2023.11.27.13.18.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Nov 2023 13:18:53 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1a::821 as permitted sender) client-ip=2a01:111:f400:fe1a::821;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=oYo3LQ+y4r9JbvYAN/TafUiF3Jc1fWWFvcj7UE10v50WuOFa5R9fHqoXFRwr8YabPm4cCIhRpyVwdRjiQJvlWfr7h7L8TQOcyzSA9KZ//t3olEocdW6JHoYS3klglbchBfkuIkCoZJ8Bkypp+FTrLjxB+EeCmsOrpzPOmMklAezCot+Mfkp5OK+bK7p8S+Ou+LkhB0li92vK4H8mh1a2IWww86X6HOi44rWmVzuk0VRBog/BR8mbbXjbgzb4GGOedzUMamqhjyXmuPInUJxFH/ptZxXSIa2PSzhifrovOPoxXVwNj2R9iOUK9md2AO0Q0v6FJPv+NuxqEdGLX0q7NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7a8sAfnyzU8RwB1qe95F6+6w65cx/kPYT3PrEBc+32U=;
 b=U7IxAmduMxX0LEyLAmMwsi6m/t3vm0nf2xMAU8LSaZdFg4lhsBPgk1DF9/X7uHyJqAt4cgrKCv4yyP4yMEmmat0IJwrnJNdJu+02Mk/69BUJ9zhP2MiDEcpLEE3k4GGbpSXsRCGIRP6mcmkfpz0URangKbbtZ+phyKwZNVPi9ShL5+cVJU1p7DbPbX9yBGZhG4f7HMRZKK606Y++Zei5M8gkVyBz9RCQmh1Bo5OmEJHXzWZ0BEy/covXhi8bmm6n+yfCcRU7NRFd/dTmXTQOQqeWadWByRM5yi5KpjmnAyZOI+u3Tk35nkCL4Qoy53M4zUai3m/IKGkADrijktUxuw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PAXP193MB1823.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:1c1::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.28; Mon, 27 Nov
 2023 21:18:51 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.022; Mon, 27 Nov 2023
 21:18:51 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-kernel-mentees@lists.linuxfoundation.org
Subject: [PATCH v3] kasan: Record and report more information
Date: Mon, 27 Nov 2023 21:17:31 +0000
Message-ID: <VI1P193MB0752BD991325D10E4AB1913599BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [d5+hz9hkTuMPEdBF6GuiwOVuUHHASSnp]
X-ClientProxiedBy: LO4P123CA0055.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:153::6) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231127211731.265280-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PAXP193MB1823:EE_
X-MS-Office365-Filtering-Correlation-Id: d65e40f0-146a-4bca-8ba7-08dbef8e7398
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: zYIO4JzvCkKjxydC+Tg/doriKFHBIMW4JR0fdK/Dis5pNpz+uuav84AXFezrZyGW0qHaYauT6y6x+bU8+5di2dsq4R103eKOigRwFBlw4pvdZ5LlXsCfGaD1cMfdUmCrtvGFILF2V5WJ3Cxh8O65X6WqZUA0V+FmRNBU4nX/hHzzuuOyuwGO5+jPh31nNq2Gnda+jXFpxn/act8Dk2RLQkWg0H5ExOt/CCLy+QV4NuIUy3TMb1+ss1pJN4I/kaow82dVN1SkVG825bf06kU/97p7zOXCu0lujEA9JMEFfdicYzF0QRelOQw2X460l37paEMfSVVG4ZaO35zvUEEBfJ7cmmSD9vWCogOp9HjacFFVSxD/ocZaRLUPrvnEXao6ecv3DVaYXYlGk0YGqViNVtboX6B9cy4fRedFw0Y8SP3ve1vFmG5BJcasP3KWXgcJjBHzhLVUidTARwVffpRbfdavcqjSiRDrhoMkN5Sh2dfl1Q5v+GSl6PWWMj0OEfF+DLpZRV2d5hfXQlx7yxH+o6Lyno02APVLy2uj1do09fSCeTcCaKb7Y9yTKyrA6hLI
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?o2/MzpGyvH7ZTpXA9WYm6gNcn8YAwBILsxVHKdL5TnjNfwZULtEnTjqIGWpV?=
 =?us-ascii?Q?HnuzksBqrzJxb2tR2FeNLBzTGcpZy4y4KXLENXjLoW+hGcMWARzpSoXOj9es?=
 =?us-ascii?Q?B5qoqcbLcM3IuQ25Ke/CR9N6zHWCzHJ7JveSIvQbMc3kmwCcXEFcqlH3Ckyz?=
 =?us-ascii?Q?8KPXJUlVZOOGx7u3vlK8jyqTTwyRqjuV2JflYv0EgvpBAaLQRTI6ijfXBgmw?=
 =?us-ascii?Q?cKjasuYnZFizI9FPW6ULNmDMLEMxjBOfGRNdEcpcRiLtg/n2blBOlpXoB3id?=
 =?us-ascii?Q?t7vIhlDXvHW/g0n+U/C0x8ovFBA/HGE43NMNIWQcCwQ7leSykVYvJJPJWac+?=
 =?us-ascii?Q?9v2fdT8qQggxUk8vQctExXh334eXsVCeZCQgXE/vbQ2W8tTx23tf5o9MTLQE?=
 =?us-ascii?Q?uBLzlkRFgcQCLqT/HvDXVlsYNbzrx02wryxC5rGbJanotrosU2iH8cFpbo+q?=
 =?us-ascii?Q?zJQQscDpZL9HafYZY/hwzzDSPy4yMpfneFP7xKcLMzQxyN2YRKwHTk+A45So?=
 =?us-ascii?Q?C2Z4Tcuw6fn217gAu2X7rEMl+Dkx1m0xwSl9+hjjQ8zQ40jKQi4s/MltHwwF?=
 =?us-ascii?Q?APulnwNENYCZ/aXBbAlaK5T5ScQ1VGSEZGVRcGO7BUnXx31UYTitXhNiROxL?=
 =?us-ascii?Q?CrBVb5nlVQOOtoz4YF0gVbZ2cj1mMxTfxGD6iTPqLkDNEpvAu/OpCl15KbeJ?=
 =?us-ascii?Q?IyWGrg03qOJaxx22WVg28BLx99WbYhO/5beuR7A/xa/eBNtKX82zkmDFfq+B?=
 =?us-ascii?Q?YlXA15VBjBruPfCg8UHExW56MbmjHtTJsiNdxklreTnfZmAGo9bK5k25MmIh?=
 =?us-ascii?Q?QT2e6SZ4UMxyIOA2bn17R+LlNfAGFejNI0ox1Af/DPsaFAXblarDu1IfIxGc?=
 =?us-ascii?Q?OBxaA5v2TbJk9VjBjU1daBRWuxLLYrbun31s6SYEbAuhTph+1MtO8Zs2Blh/?=
 =?us-ascii?Q?Iry9Nna84oii9YQpAd7UqINLJzsfXM8Mgcb63nB/HQ6qpj8F6DDLXV9+guoJ?=
 =?us-ascii?Q?0gGxcysKaRoNlGaPFDbkIul0rtBKmVwD90prTWAfEYnLXwp+lBx70G2bTroH?=
 =?us-ascii?Q?XPZPRBGGLak8GCtbjvqHzGtQhJUAvX6RyA/ndyprxRlH3Zz4lP16gQf3qd2n?=
 =?us-ascii?Q?eyejvbuWImGqcgfVvbJax8AXo1AOgdKX3O1H5zoGKUCazSngIRgQ4275t0Qx?=
 =?us-ascii?Q?wKktbfzdh0KywkUh+duRwxvFtObzafWSSMcuFnRZM8BpXPUhwzW5Ncn7lds?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d65e40f0-146a-4bca-8ba7-08dbef8e7398
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Nov 2023 21:18:51.1139
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXP193MB1823
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=WpZ6Eq8c;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe1a::821 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

Record and report more information to help us find the cause of the
bug and to help us correlate the error with other system events.

This patch adds recording and showing CPU number and timestamp at
allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
timestamps in the report use the same format and source as printk.

Error occurrence timestamp is already implicit in the printk log,
and CPU number is already shown by dump_stack_lvl, so there is no
need to add it.

In order to record CPU number and timestamp at allocation and free,
corresponding members need to be added to the relevant data structures,
which will lead to increased memory consumption.

In Generic KASAN, members are added to struct kasan_track. Since in
most cases, alloc meta is stored in the redzone and free meta is
stored in the object or the redzone, memory consumption will not
increase much.

In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
struct kasan_stack_ring_entry. Memory consumption increases as the
size of struct kasan_stack_ring_entry increases (this part of the
memory is allocated by memblock), but since this is configurable,
it is up to the user to choose.

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
V2 -> V3: Use a single field to store the timestamp and convert to
sec/usec only when printing the report.

V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
config help. Cancel printing of redundant error occurrence timestamp.

 lib/Kconfig.kasan      | 21 +++++++++++++++++++++
 mm/kasan/common.c      |  8 ++++++++
 mm/kasan/kasan.h       |  8 ++++++++
 mm/kasan/report.c      | 12 ++++++++++++
 mm/kasan/report_tags.c | 15 +++++++++++++++
 mm/kasan/tags.c        | 15 +++++++++++++++
 6 files changed, 79 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 935eda08b1e1..8653f5c38be7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
 	  A part of the KASAN test suite that is not integrated with KUnit.
 	  Incompatible with Hardware Tag-Based KASAN.
 
+config KASAN_EXTRA_INFO
+	bool "Record and report more information"
+	depends on KASAN
+	help
+	  Record and report more information to help us find the cause of the
+	  bug and to help us correlate the error with other system events.
+
+	  Currently, the CPU number and timestamp are additionally
+	  recorded for each heap block at allocation and free time, and
+	  8 bytes will be added to each metadata structure that records
+	  allocation or free information.
+
+	  In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
+	  16 bytes of additional memory consumption, and each kmalloc-32
+	  object will add 8 bytes of additional memory consumption, not
+	  affecting other larger objects.
+
+	  In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
+	  boot parameter, it will add 8 * stack_ring_size bytes of additional
+	  memory consumption.
+
 endif # KASAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b5d8bd26fced..fe6c4b43ad9f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -20,6 +20,7 @@
 #include <linux/module.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
+#include <linux/sched/clock.h>
 #include <linux/sched/task_stack.h>
 #include <linux/slab.h>
 #include <linux/stackdepot.h>
@@ -49,6 +50,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u32 cpu = raw_smp_processor_id();
+	u64 ts_nsec = local_clock();
+
+	track->cpu = cpu;
+	track->timestamp = ts_nsec >> 3;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 	track->pid = current->pid;
 	track->stack = kasan_save_stack(flags,
 			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b29d46b83d1f..5e298e3ac909 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -187,6 +187,10 @@ static inline bool kasan_requires_meta(void)
 struct kasan_track {
 	u32 pid;
 	depot_stack_handle_t stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u64 cpu:20;
+	u64 timestamp:44;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 };
 
 enum kasan_report_type {
@@ -278,6 +282,10 @@ struct kasan_stack_ring_entry {
 	u32 pid;
 	depot_stack_handle_t stack;
 	bool is_free;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u64 cpu:20;
+	u64 timestamp:44;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 };
 
 struct kasan_stack_ring {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e77facb62900..a938237f6882 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -262,7 +262,19 @@ static void print_error_description(struct kasan_report_info *info)
 
 static void print_track(struct kasan_track *track, const char *prefix)
 {
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u64 ts_nsec = track->timestamp;
+	unsigned long rem_usec;
+
+	ts_nsec <<= 3;
+	rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
+
+	pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
+			prefix, track->pid, track->cpu,
+			(unsigned long)ts_nsec, rem_usec);
+#else
 	pr_err("%s by task %u:\n", prefix, track->pid);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 	if (track->stack)
 		stack_depot_print(track->stack);
 	else
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 55154743f915..979f284c2497 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -27,6 +27,15 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
 	return "invalid-access";
 }
 
+#ifdef CONFIG_KASAN_EXTRA_INFO
+static void kasan_complete_extra_report_info(struct kasan_track *track,
+					 struct kasan_stack_ring_entry *entry)
+{
+	track->cpu = entry->cpu;
+	track->timestamp = entry->timestamp;
+}
+#endif /* CONFIG_KASAN_EXTRA_INFO */
+
 void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
 	unsigned long flags;
@@ -73,6 +82,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 
 			info->free_track.pid = entry->pid;
 			info->free_track.stack = entry->stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+			kasan_complete_extra_report_info(&info->free_track, entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 			free_found = true;
 
 			/*
@@ -88,6 +100,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 
 			info->alloc_track.pid = entry->pid;
 			info->alloc_track.stack = entry->stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+			kasan_complete_extra_report_info(&info->alloc_track, entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 			alloc_found = true;
 
 			/*
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 739ae997463d..c13b198b8302 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -13,6 +13,7 @@
 #include <linux/memblock.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
+#include <linux/sched/clock.h>
 #include <linux/stackdepot.h>
 #include <linux/static_key.h>
 #include <linux/string.h>
@@ -93,6 +94,17 @@ void __init kasan_init_tags(void)
 	}
 }
 
+#ifdef CONFIG_KASAN_EXTRA_INFO
+static void save_extra_info(struct kasan_stack_ring_entry *entry)
+{
+	u32 cpu = raw_smp_processor_id();
+	u64 ts_nsec = local_clock();
+
+	entry->cpu = cpu;
+	entry->timestamp = ts_nsec >> 3;
+}
+#endif /* CONFIG_KASAN_EXTRA_INFO */
+
 static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
@@ -128,6 +140,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	entry->pid = current->pid;
 	entry->stack = stack;
 	entry->is_free = is_free;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	save_extra_info(entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 
 	entry->ptr = object;
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752BD991325D10E4AB1913599BDA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
