Return-Path: <kasan-dev+bncBAABBG5XXGXAMGQEM7UQOZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B4539856CFA
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:44:44 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4120c9ee485sf99705e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:44:44 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708022684; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvVWl/Q5r0mafYwVRgyxdNIHNFu2NlWaKGDbob3d4LHWkwdCWwz5pYYxN5HIPHkdvS
         7JB4E0CrB420ygHFLnGnWd6hY0WHVkX13xUf7JQvZa+t7JlATJ+U3dvP73qbMMhvC4f+
         OoRYoPIKc8+qIBihtJmkorTasq5rXguJBIlzkyCn4t20FxiNkaA8+mJ0n3SBWM1KQhOz
         4WJSJO5NuHZtyYG7ZkqDaQiXPoCl1bS6WzByn8CwTxLzKBviVh2abx+TXRfGJUX2WU6n
         Bm6zEFVdUyYASKXLK9Khpzgg/ttrN9BXxT1aro0BI7NoHFo7MzMM9kSPApkJrrynNawS
         GRJw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5Obso0DPd4M3dl9T3j2RyBEk8hy+UWgsPAGso/MWrSY=;
        fh=Bs9mZGo+Xkl/1x54FGJ0MLRKbPz8DHOzBdQf6U8fkr0=;
        b=Ae88sG9n3Q2eETiKKazh1kmXEQ232AGVKwfoF5V42OTGiT6KuO2hxoN9VanUu5I/dK
         TzXngGmobkPWrFXEBMCE9z/E/vkaQr4HnrPGf6D4hcS1WtCQpAxCT7O0B8KhNZb/iHvR
         EV6B7bv5xYZUEPTwQWEcxb0BQb3f2iOW8jFazvdKi/hpvTnhgcx2lzEe+oGAlEWiU+Zi
         1zBZ161J9dRsuwiezM8L2a4A+twuH46C0G6hjBqzL5DDeMP4bmT8wYTRYOppvNXEO6iW
         gcVwte+sKiK7u3FSNlt44YUxuMJFKHLEvonFScFtUJxSBc4A5NqSGwNrD3whUTnDCrIq
         a2xQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=h6TaWYYL;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708022684; x=1708627484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5Obso0DPd4M3dl9T3j2RyBEk8hy+UWgsPAGso/MWrSY=;
        b=ROgUW0GGLQe9tHAC5uVPzxwCPJZejup75hC23od55Cs34Wb5KQbRX7rqf10gUVM3w7
         lJOf7DMuK7zPr8MAhwwaNwd+kJIanE2M8YzFx7X2U5J8tYnWzid5ld0uH5mZFOS3bD9E
         x/10Dn+FgVDB23BAPB2SARC42CBQcPFVA4gXpzQGXEdmjvrTxM3J9T6MmnKRveCSYotn
         3BvrWskEpcjwkNP5BQHyYmgmEe+SNx5WGU8dFOmGHU0ghwqjRKJnh4gbDnZTP1NTZH5Q
         Q/A+c8il7eeE6x7qtv1li5z6sYbtyr/3czKH2m9vg/3MeRJ4xQI4IOSIyLOEh5N2pQUP
         9tSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708022684; x=1708627484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5Obso0DPd4M3dl9T3j2RyBEk8hy+UWgsPAGso/MWrSY=;
        b=YRp7pliXYMWJz6Cw67UFzN5ZXCdLeBPh3TzBbK3GBbuzfuqJmgH9ZJ6a5MuG1/aaHV
         lUZ2Ww/eZ2OOvkVqo31fKRp3z+vHa/55F9+QpbE0Qgjh141xrFyci5DEOQZbi0t1/OOF
         ZS1USFjChdQgFUhP9L0mxfth2bLw4OpbR83veBVy8dhpdHtAVoPSqfF3nnDdkcS+Wh2Y
         c0VhDNftSFsYGnpHxbtjTP0S3nymTxJePGJnuurHcuv+HNTgKr37Sa8MuqZ43vQFEMBh
         vw7CRGpbJMTKign0DNHRxU5O5OvJx0vset7P1ZT1zXRXFxa71+XuFG3YFLhJ0/k+vqBb
         8wJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCX2k0nNpOw8H/GeNN2UMvVfZpLHn+Z2GpRyKG8btnOOkx9Xr+c2QmIqwz2XHlK2wH9noWm9qNFUSBJA5JwJJFfKQnCk4cn3eQ==
X-Gm-Message-State: AOJu0YwqO19hky7KC3ZrdEXEg1ywu61gyd+2sIbJcdLmdZ00ntaRujYH
	fA4zMbcaBnV9BQqGmnNRK2y3J2fqTK8JyuXuW4EuXGoieDXrZA2n
X-Google-Smtp-Source: AGHT+IGkMvqY9lJn5rJJ+e4rRQLxvVoY/Ka9TSrz3HMoAsVh9Ygh54QdmvyP5nhNhTmlL8vHm0WPOA==
X-Received: by 2002:a05:600c:1da0:b0:411:c03e:217c with SMTP id p32-20020a05600c1da000b00411c03e217cmr25746wms.1.1708022683961;
        Thu, 15 Feb 2024 10:44:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4cc:0:b0:2d0:f95b:25e0 with SMTP id p12-20020a2ea4cc000000b002d0f95b25e0ls15654ljm.0.-pod-prod-06-eu;
 Thu, 15 Feb 2024 10:44:42 -0800 (PST)
X-Received: by 2002:a2e:7a16:0:b0:2d0:f96a:23b4 with SMTP id v22-20020a2e7a16000000b002d0f96a23b4mr1726460ljc.7.1708022682216;
        Thu, 15 Feb 2024 10:44:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708022682; cv=pass;
        d=google.com; s=arc-20160816;
        b=eiExAHPtSY1ivZMSZIqjYPuHrSoUwX25nkf3BeMEriLBWNoqSlGFtITHgyf6sSb9wm
         WmQUYXaHGo1TWC480hCGWrPzH4YutVNjAR6/HrRBULUMW9KullP2gL/hCJj3swoRIVsF
         edMmHtI1tH/LRyymjozImkaV3Tgbi4l1/eKTCgjpCe4/XuyEBKAxuJfrqsIetjqDFYcC
         +IPqUZL3SI0ATcOEYuxtWj3SKu3RN/JKZs2SV5Lz8v46gwHFxhQj+uJQ6W1c5uPMbz2T
         XlNljNFNjnWFhTaAmhWRPnRhSGs/cCnZ/0FBnnmusXZdylVFvCJvwzVTpeN3evTJKOl/
         2Lsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6WQnFK7iGX6Ikr5ADyyfNApbj2aVc5SoJtXog6qH1PI=;
        fh=gs3koJsRte1hkBBOJcSQX014JRME+LB8R7AyE3W7NUk=;
        b=tEIp9niB1ibiWLU1Etoh2YlpPCaefDWuNGY5sdGJzm9hOxAX4xa4a/VOMn2wbsO3Cp
         FrG2T9Vs5o/BD/QtK01bNk+eiHEPqqfWoaQ2DZQ17mpqs29JK6alcogNovpvM0RU4OPd
         lJqtBPScLwuHFIzqj2HJvlUfbDyhIuVmmUXu/YdhIE/tXPR1UGlW1zJso/ymziTRl2i9
         q/RVRzpfX4Sf16k5Otkau7PL2zuoA5PvN6f7YYgLbX94AqPyNKYDoDSC8DsczTR+Sd/w
         CMvTlA6u6S9QcaG1f6+qimlmsrQvp3B+UDcYNNEIlrqp6icbAfbxxei8FkOjlFU32PkD
         lSgg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=h6TaWYYL;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR02-AM0-obe.outbound.protection.outlook.com (mail-am0eur02olkn20801.outbound.protection.outlook.com. [2a01:111:f403:2e06::801])
        by gmr-mx.google.com with ESMTPS id p5-20020a05600c1d8500b0040ff8f0e6acsi216059wms.0.2024.02.15.10.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Feb 2024 10:44:42 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) client-ip=2a01:111:f403:2e06::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LMBqxm/2taV0fa/Jb1OJz+8Wo/jeAQGjLOcSeoHB/nQiCheczEnzoSZiJDtYXFKQXtVbb1FqoEqgJyDQyGMF1HgzgIyCGkmAjphu+TXWBXn+u6eRjHMZPEiAj4MRKgcdQRnKI1wm/DKivTRVxhN6GeNvtqcObDmVygdskSefTVF6rxPyU8PNoT65kvr0a31BQlHQolpzsYwZa5d20FiA2ubzeBg8BhO9IOZRgEX2cDDUFbxYmLiERfcoZIxQIXohgzfoo2lfb9O2f/6vyI+3qk9zVzi0O9/O+oxI0zNGxP7xFCHkWUugWbTssbtz2yVKTkzXA5WpGM2puE+OvmIO4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6WQnFK7iGX6Ikr5ADyyfNApbj2aVc5SoJtXog6qH1PI=;
 b=mLva+0Aby+4K+jubkg4T6IYQYc9697ZXLcFe1Et17Qo6bZn2CiiB1ugpuDQynNQQn13yygSd/3NG9pGIVrL/5zZIhdKMnAUMNIYLnYncRhR1DFGwqPMVuLrv3wL3HohjwXXXB6SqD3tdbtz76UvM0Mjoo9eOIQaHrUKpw89XhIbrzkCLawh8h6kFLKChTwUJt2anr8/mMuSPBw1mPH5xltGmymMkhPryzzvAQFiWaS/ujVgcaKeHXeBC1nVTsKn1KE5dUalVMN9Su3YCOYP02GAERX8Ge9B9mhvjKEYAEFX8iN3FNw2dW2+l+VWDYCDPOc4q8LHEn8RBPbW6JK61Cw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com (2603:10a6:20b:e4::10)
 by GV2PR03MB9548.eurprd03.prod.outlook.com (2603:10a6:150:da::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7270.39; Thu, 15 Feb
 2024 18:44:40 +0000
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18]) by AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18%7]) with mapi id 15.20.7292.029; Thu, 15 Feb 2024
 18:44:40 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net
Cc: kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: Add documentation for CONFIG_KASAN_EXTRA_INFO
Date: Thu, 15 Feb 2024 18:43:04 +0000
Message-ID: <AM6PR03MB58480786BBA03365CE454CDB994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [QWaWzb8MH7tSszj9rgRVqXWQobk9go8o]
X-ClientProxiedBy: LO4P123CA0277.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:195::12) To AM6PR03MB5848.eurprd03.prod.outlook.com
 (2603:10a6:20b:e4::10)
X-Microsoft-Original-Message-ID: <20240215184304.33039-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AM6PR03MB5848:EE_|GV2PR03MB9548:EE_
X-MS-Office365-Filtering-Correlation-Id: 0483777d-6dbf-4172-53d9-08dc2e562ac0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: qKTfpCsur8tEnwmDr4uqAxWSfBXw2lNDdfD4vnUwgQ7WH9Grn2oHUV5802aiaJZXWTe1vWQDnOxqQ1ZWz8KidmXGjF2Pt599h8XyqWB5bUwBrDGwuCTV+gkGsGU5b53NyGszE7WVpjfcfjNK0we/1mNRcRI5u7XW3v+2CSZmGQcuubBy9VLuCnFzR41fEJIvRTSJpWAdtU40pQQ2iJcTPopcOmIH3EelDN28ZQgJ/e1vGeKNakF9B7f88/vUGaSGC1xmgsJVu0XvRqcVgF//Wp04BPOakeqVPCfL5B7x7DP+BxlsZ818Ys0zHlBD+hPJgRD3r7B9ElaVx2cbrkM49J7yroUMJOaJuR9GBFD6ehNeGd6A/aKYvKrcsANtMmGwDveQV7xOSVS/Cjl/FcoQr1fzNM2TBzO+jbIYsQu9EFEySR4qNKfelRaH/oue5L8UpLNDwR8ePESK3wegyr3kK3p3oVb3HPHe2iVDHnXzuZvmgob3iioFMlzfAhBzjIJN6MT98tLvehzERGRyb/LIUrC16eTRRepedchM7xSbs4pcNamuBBS4yHrMnnjAyvws
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?EyevmFmA+P0L6hwGgLQojtNqLwnZR6hgIf4gfw0NF4NnpiwZbPzs5TQxae4w?=
 =?us-ascii?Q?JHWHBhqtycc+K/in1B0ZeYZFsqcsq2sL3dYcICtB844UyW1HEbBgHBTL8V1X?=
 =?us-ascii?Q?lc8M7C7yck7T4vdz341SsuQQznqMXrDNe8eKoRUX+CjcyzHe0uUiOS4k51wS?=
 =?us-ascii?Q?wl/LpLZgqlvEDTyWce16LSatGJW3LkxQteF4/lFahnqlF0zA7ds9FUsTcUx7?=
 =?us-ascii?Q?qxfXrclhgjyMUiqnaJ+0to7UsIjnm+rA9HQcd1rTvUJ67pI5xyw5UsKuqV/J?=
 =?us-ascii?Q?lIkgADDgUWsJ9Dgd4k4EeOEMTdY2mBcItlGUIWbcJ4DGtTOWQrUSQ1Gm2Fa2?=
 =?us-ascii?Q?0d+2oggMmLo+O0koW/31n3r97nhwSd/F8patLaM9FF1z7r2LnGnt8h4G2+Yw?=
 =?us-ascii?Q?QMM7ud8XC0z9sfYBMvNlWjDelIxUand5BQpmahyXH0Hkck1Jl+3A/Lu9Nl1D?=
 =?us-ascii?Q?XqAPfSgtyaKCppA4+QKwTpCSfjmN77FZGTz86NItU6DdEXWNI3iB3+ukpcA6?=
 =?us-ascii?Q?tlM/YyIlXX4slx0i2t+7K3d7bJHu4Z+4oaDp2sYhcgskS6+rxIAX/2o1EY/u?=
 =?us-ascii?Q?x1LRncxQZmUwyGqcz/gUfaJfhb5WAMjMvvspoAQmbtFRh1LIGsvsVWM7vM5T?=
 =?us-ascii?Q?8N3RERYpyo1YJfKIe4iuA/divxcIBuuDNz00ZB8FUsm2JjVNuNe3c8oXXNi2?=
 =?us-ascii?Q?qCfojzi9gnOLD1YZWvEjye54EN/DOYW8raREJrkWN4bcp/8Jx2ALikrbPf2O?=
 =?us-ascii?Q?WDthEdZ5ELWviVhiZ81whe/DfpVj/WeGq7qtr3GjkdGR88yE2l6I24bkKW6O?=
 =?us-ascii?Q?NJnJ4tpRlkEUJPbANlbkMAdQqW84G6SzcjyKB87gjEKbzhCBBkYOpb2xKwWW?=
 =?us-ascii?Q?7FNhcvHde5eaaTyJbJN3rlUVMkAuiZuqb+r1JDIjjiopviggKiWWIIVQ4OH6?=
 =?us-ascii?Q?cZC9aHqSxshxo9OwMDx5ye3g0u3CGnVQuzNWUjFmxzBIdFpYP2KfxcGWMvy1?=
 =?us-ascii?Q?xPUTbYc3CQ5T+Rn2qf4TUMUonCohA/3eyuHPLXy/1R3e53gKsLDs/fvV60+a?=
 =?us-ascii?Q?tW8LP8cBKys3dcZrmuobDbFTyKxfZlvUuPQLkd8S1YNF3ELQreESiE7Z1Egr?=
 =?us-ascii?Q?uXor9gXaBKjHfXrfhsznYp5a8G8nZ2A3IpFTReCm3A8BKBH3E176VmgMRhNg?=
 =?us-ascii?Q?BmOEu5f5Q2TwekNyqCWmHbl3wTP+HlSy6lHvTJUvo8uCvWJPwKUAqD9QzOCj?=
 =?us-ascii?Q?jXJ2MPbAS//Ob3E4Jh5o?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0483777d-6dbf-4172-53d9-08dc2e562ac0
X-MS-Exchange-CrossTenant-AuthSource: AM6PR03MB5848.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2024 18:44:40.2897
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV2PR03MB9548
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=h6TaWYYL;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

This patch adds CONFIG_KASAN_EXTRA_INFO introduction information to
KASAN documentation.

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
 Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
 1 file changed, 21 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a5a6dbe9029f..3dc48b08cf71 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -277,6 +277,27 @@ traces point to places in code that interacted with the object but that are not
 directly present in the bad access stack trace. Currently, this includes
 call_rcu() and workqueue queuing.
 
+CONFIG_KASAN_EXTRA_INFO
+~~~~~~~~~~~~~~~~~~~~~~~
+
+Enabling CONFIG_KASAN_EXTRA_INFO allows KASAN to record and report more
+information, the extra information currently supported is the CPU number and
+timestamp at allocation and free. More information can help find the cause of
+the bug and correlate the error with other system events, at the cost of using
+extra memory to record more information (more cost details in the help text of
+CONFIG_KASAN_EXTRA_INFO).
+
+Here is the report with CONFIG_KASAN_EXTRA_INFO enabled (only the
+different parts are shown)::
+
+    ==================================================================
+    ...
+    Allocated by task 134 on cpu 5 at 229.133855s:
+    ...
+    Freed by task 136 on cpu 3 at 230.199335s:
+    ...
+    ==================================================================
+
 Implementation details
 ----------------------
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/AM6PR03MB58480786BBA03365CE454CDB994D2%40AM6PR03MB5848.eurprd03.prod.outlook.com.
