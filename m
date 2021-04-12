Return-Path: <kasan-dev+bncBDD3TG4G74HRBGNZZ6BQMGQEJ7TFQPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20CC135B9DF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 07:37:31 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id az20-20020a17090b0294b029014daeb09222sf4117455pjb.3
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 22:37:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1618205849; cv=pass;
        d=google.com; s=arc-20160816;
        b=BkuoGioNhBFiqplji3RjPnQ9uA5S7Um+QmoO8D2tH+IBj/1F4aVAFFKHu4kUtxh3dG
         3lOgNWX3R/UDF5Nj8ULV9g/wbH4+OoLoKOV8I9qQ6IsIX2mK5m6RjCUYsmOSpWl2xRZD
         qLKVZ3QdVmm1MTlStq/7wLsaH6Cwhzpc4iMrT14N4oqPYBt0HasjdmgcPzQBhlPr9fP1
         Qkez6Z31qNfJtZ4VGfgBCE/vSoItP/lpRZsr4QsaJGbuJAPMr44Q1NOVC7RKwXwAbjyB
         WhFWd91Z6aikntSBZ+MZY9FR8yZvjaOy76aN578XHVdkwhM6uBGapVE3oeVqXatrTOw9
         PI7A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=aDKnfYRxD9QxgJNU2+1tv1YhKcrnJOvD/g8ZJsP+r9o=;
        b=mQ5pJ4+jM/nnK9dhR8+gfltmCH9W0Ixnm83SSEsP9QjzwE9W5TGP5tT8jNZZngCiP5
         nbmq0cO7LVLTlmfxbYalA5uz2KbcLnUIzM8sY24UC/g9FHJ/LTSZxMtcDLX6Jija+DZu
         oTvO77Gsb2nJOc9MqtJq8TfQz88mTNjTA0ChSlAxwS7bB6iNir+gWu7pHpFIg1dCsyQT
         KkaTMHQUHNnnKtBwz5GUJVZ3P1OiyWwBLk1RmoDbteQo4kUeDWvwdbqN9Fy+2sZZGLel
         8SPya7m/mC+0eG/5f+YfmIdu9NBjg4YpKAHrtyUch9mbBvU120AF98J/+mkwQiT6m1Wt
         oUGw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=MbOTBEth;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.243.59 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aDKnfYRxD9QxgJNU2+1tv1YhKcrnJOvD/g8ZJsP+r9o=;
        b=JJPwNIdfuUmhAqxOe1kt9CfdmMulJ6l5x6nBmRkepoF8/F2MD5uZT9ktpgzPNMMZaD
         PKLJJD0haz5Dv7e1nDsl8zPbblXDSfzlqgFrHfdjodaC4GaOTQS9EmXOZVjltkV5xVlD
         TexxDykPj/Vvyab+sgO8rczA4y3wIvR3068dXunGeBMz9tTCZepNTy+XmSWLc59xhfXF
         NLSuSi1v0/eP5T2siQw3jA4uauF37GBDCba/r6wfxOCGUECEdBcM3zgjlXqdh2EiOMz5
         B5F7uxdL4v4qIpnPo3yKx/Wu+pC+q0e2PY+KC/+3qUcjNn1G9ZfuCnY39f8Li/BxWRTX
         7dqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aDKnfYRxD9QxgJNU2+1tv1YhKcrnJOvD/g8ZJsP+r9o=;
        b=J4qcDHG5LOwKZviEuniue1l7irEJoXduzVt1msHfBHI2OBfaDCwLI1RdccWX5L9DSh
         PCrZ9XoC3BfINmYc/eXnywkcnUIvO7BdDoFXAv/ciCnwLiVsZwy0FEY8zPKg16n/6GDb
         TcfXtdLNl2OyCXBo1mLCQ0eO5ZtGZQ0UwsBW2ys7CXc9+mGHUqm7tD/KeRfxtdKKhoS+
         4uoROB3N8wJ/Dxp/2PlgiIITZ1sXqkN4vSZ1+im9qb59ZS1tD9XaHHoktult0Hd+aYTv
         OatLRVSZv2NKh1RR/JbtD2e8/nxCb1+hpLIV1bhiI0lwpo/j49pQR4sKz5V52yd4rlnK
         2ZRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300PqYRrUtfGv1KuR/sfmj2NYopilirMqe9cpFUiLPN1XIPeJgU
	XdsOQSSvuHhrjab001H3zXE=
X-Google-Smtp-Source: ABdhPJzfqWGpD/g9C3/cPGNEmw2Sv7cIkMLsz7gSbr9XDt6WM8F1p98dbT9SBF9vsYaQpULjYK2+0g==
X-Received: by 2002:a17:90b:4005:: with SMTP id ie5mr26652598pjb.195.1618205849602;
        Sun, 11 Apr 2021 22:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b942:: with SMTP id h2ls7097493pls.8.gmail; Sun, 11
 Apr 2021 22:37:29 -0700 (PDT)
X-Received: by 2002:a17:902:b117:b029:e6:81ed:8044 with SMTP id q23-20020a170902b117b02900e681ed8044mr24059556plr.13.1618205849111;
        Sun, 11 Apr 2021 22:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618205849; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJ5qMeL9WgLCQfF4sZL6bnCFb76cDumpsyL0rihEo4il969f4BznOP4YxUYi94mMsg
         E2HmNqvV2zNJoHd1gS8bz8bmjA64qRb2eR2RefnXOGNBX0L0OlHF/12j9OwEwc1UoYnC
         GkxsjaXT+6SsaE/i6cHIpwZERhReF798nxf9KRkO3qBVwrYUTR6uO750iBJMvpoUCc4Z
         d9B9aYFBNyJ66e4B6rmZW5x1oDOoHK+mFd/7hsWxWYnIG5uiBjWzN8nhNAZcuflPw8iy
         ekU6AOKwWYvvM7iCeMCq6hb2M3czttfUE+VRvfpX7n60iZ1ua4aiCe0DWVcutKOZh/fj
         QLcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0HyWMggtiuCprit4TgYCubO+2iv3tDIcJ1LNHMmF0wg=;
        b=Cn+rBiyPbwB3KaErRIkZENH4ZjGs95FV30bWG9ldAn2AxCk9Ts4gYOuWlXJvi3Mfic
         Afm2P4F2gks5mivGr5gWdVZG9O2TtqjC+S6Zm7e/1tRddEYvMaAs34Zh2TVldsoLMjxd
         bMopcMuAGRVyeT+SXYWRQZvM58yfL31mNaG3SiG+0SIhJk5QLfvcYl/bsBm/DVPunPgc
         lCBpcbzBBp3fUwnDWsaC2fcn17+yTn0A2fRm2LQkG+1qrv99HPc1/ya8KhAhsm7R3DAZ
         SrCcRpxVXK57AApQ4s/lsW57pSnbwQtqIyO2felKUzRVp1gB2xVWlL3IeiKyZgRYKWjS
         TAtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=MbOTBEth;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.243.59 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on2059.outbound.protection.outlook.com. [40.107.243.59])
        by gmr-mx.google.com with ESMTPS id mp9si730596pjb.1.2021.04.11.22.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Apr 2021 22:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.243.59 as permitted sender) client-ip=40.107.243.59;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aFREYCECw0e8QM0EugRbBCMsUBp5qzb/eb3JxkQCQydrP7+w6LWbWqOYtJj355lxPKoVIg+A4rkh/mVQ6ZsVI4KU15S8gMgGkc2QmGP/bGir6zsT7OIcpcayEh4tGj8n0CFogogXGkTGMn5qrUDW+R0f4YETVLXA5WnMANRRLfTC7pV5tOTvCBIBlSQInbQ5AlnO/80A7QseewdzM6mCNSryCWc80uJTsquAvRK7KtbtZ/z19vjYcCE0QKHH35LfCI57VsrLbnN/okQUYqycHHHCReW+rPQwW1KELqUaL7cbPja22X4c1ckhjgifhywbyHsHq5In0E1Npm4qAjZ4Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=0HyWMggtiuCprit4TgYCubO+2iv3tDIcJ1LNHMmF0wg=;
 b=dozUTVfaA+il/snJWzW2cpWIBQ9u/jePdmzmjMwGw9ZerUSuv9zrD72LYNVdarUAocIjc/c7SKuSQ5Wa50BGiLWp2lZDUrS/CdJas3EjBInfZ5P5T1B583LnerllHSCOWd2amRzv2Acp5w54NvQhwWyRpBcSddDtXpp5Cy6yGumlutvMywj6CpnsNLSNNSr2gfM/mqKF3wmQMLzJ+lB2cyz/Bz7wIAYkq9+7S6P06uUy0QbbIUT2b0tcaIwCqaB4ZGAdmUCQqpkGbdeiBY/EzmYQFBQSN2TrXX/ooag94JYsau5jFXRKhs/HQa6ZDLpQucJ5FmyDF9GdJUBmS+3plA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BY5PR03MB5345.namprd03.prod.outlook.com (2603:10b6:a03:219::16)
 by SJ0PR03MB6239.namprd03.prod.outlook.com (2603:10b6:a03:3ad::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4020.18; Mon, 12 Apr
 2021 05:37:27 +0000
Received: from BY5PR03MB5345.namprd03.prod.outlook.com
 ([fe80::8569:341f:4bc6:5b72]) by BY5PR03MB5345.namprd03.prod.outlook.com
 ([fe80::8569:341f:4bc6:5b72%8]) with mapi id 15.20.4020.022; Mon, 12 Apr 2021
 05:37:27 +0000
Date: Mon, 12 Apr 2021 13:37:11 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Anup Patel <anup@brainfault.org>
Cc: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>, linux-riscv <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: Re: [PATCH v2 1/9] riscv: add __init section marker to some
 functions
Message-ID: <20210412133711.7b625842@xhacker.debian>
In-Reply-To: <CAAhSdy0CgxZj14Jx62CS=gRVzZs9c9NUysWi1iTTZ3BJvAOjPQ@mail.gmail.com>
References: <20210401002442.2fe56b88@xhacker>
	<20210401002518.5cf48e91@xhacker>
	<CAAhSdy0CgxZj14Jx62CS=gRVzZs9c9NUysWi1iTTZ3BJvAOjPQ@mail.gmail.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: SJ0PR13CA0159.namprd13.prod.outlook.com
 (2603:10b6:a03:2c7::14) To BY5PR03MB5345.namprd03.prod.outlook.com
 (2603:10b6:a03:219::16)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by SJ0PR13CA0159.namprd13.prod.outlook.com (2603:10b6:a03:2c7::14) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4042.8 via Frontend Transport; Mon, 12 Apr 2021 05:37:21 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: d4b3d65e-3f10-4ac8-da1c-08d8fd750e83
X-MS-TrafficTypeDiagnostic: SJ0PR03MB6239:
X-Microsoft-Antispam-PRVS: <SJ0PR03MB62391076B51DF15413E545D6ED709@SJ0PR03MB6239.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:8273;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 3GAciX+Jg7Rqb/SH7ftcrqi9XKo6wTuMWLj8pkq213uxsUyX487RYzB0J1RDhMiwl1SXhGR2aHm3V09+RNuQamXbkurWBGssxgoO+RmUbxJGwvW36BDu9IlIzGe8bMp3TRU05FrxMLiot8wD3m+7BwOKQBjOHESPVV0DfW5aDv4HgZX3xkCEJ7sUivgr9F94lq0s22b0r4TmhEaZOfjpegJ9rP6ou3BTx576cMlatU+00h1s+yL5hAZV4bDMDI27Ihn44Z9+2leyv/1dTS0/+YgsbEXETpmFSCG2HHXTwtHFhZ0Bidv8a4LsL+I39FmvJhAp/IrUVS+R76a7tRXP4Hgj85G2jCDkPh1+pC5Ur0cb3ydjddnLrPkYz701ubWqKo+nveAQFv6dUrp4/CIoWZKS6i/qWxBEE9i2BjhCXUylAJJX0q9DblBCsomoCzKJT4VixnlwVkb7DjlTRZu5fyXtXJwkmkCna4xMtVV3Ka4xnzRgwYEwmaDdHCQOjJDH/FkGLJ22c0JJMhaK33KcnysIgkznf5sR1EuunFno3Dq/rGakPdjFhmS9Jb3VV4CE/O93R8CEMefiOHlHndCc1NN5AfBAdrE/E0B2US2x+0DowXaspX2dfQnSBx5YCyb78fjZlt9/BRwRAFvcRGeQYwSca2d5YglS6p08KoJTuGk=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR03MB5345.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(366004)(39850400004)(396003)(346002)(376002)(136003)(7696005)(52116002)(55016002)(38100700002)(38350700002)(2906002)(316002)(26005)(4326008)(1076003)(6506007)(16526019)(53546011)(9686003)(86362001)(66556008)(186003)(8676002)(6666004)(956004)(66946007)(7416002)(6916009)(66476007)(8936002)(478600001)(54906003)(5660300002)(83380400001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?bLYrPWHF8JJ2Cl+59CWRQovnlUXJ5MKx8TwAMHcnFc3RDO9l0Yi2lRntLzXd?=
 =?us-ascii?Q?qvvXZZaCJmsDbEXDg56iyNpDKORv0lq+BY9hwFqgTO7GPXZi8AtDENdHz4hA?=
 =?us-ascii?Q?TAlTY03dc/Ja+oHQW4nSoafkrxQX9Lmwt4uMmqqW+Jdg9eQdRZ44m083Y1TL?=
 =?us-ascii?Q?qm7Dfe4+r2PFpCsAjZE3V9a9eT5enLiEHj1XlUf6EvWaiSZAH/N5Cd47TmQu?=
 =?us-ascii?Q?4MAPHdlznCghDd74BoSxrBItLSzkvgZwM+besQwK9eTVxdYCt4TTDpo3kQCA?=
 =?us-ascii?Q?2h8UOkVg6QwWWsGVYThYYthoSTr+CVzoJDYFJ2mHcBj5OwPJnHd7c/kum7dX?=
 =?us-ascii?Q?CCQoTlrCZ94h/XU1zq2i36IzTWXpyx1buF/jx9bwC0jMDT9VESImuvHZp7UF?=
 =?us-ascii?Q?FFsWfOZ91ubbL9RtrceYXitDWv3AehsRY2iynwRLHMT+xkeOgdOnxrUxFxTq?=
 =?us-ascii?Q?bMw68Oa90zExVgoAaDkNoVHARJ3mC2nwDZuIGJJgDwOv64ywmrkKK6KUUCW4?=
 =?us-ascii?Q?YZF8pvHb38teciIQDThiaBifzFMnF8A2Ne8tHuQmpOQObpmRl6pozY//P9Pj?=
 =?us-ascii?Q?4QcGxVcYJRP9EiyH+uRfrPY5zD2qBaPCblFHcTajTcKC8bkH4uougsAu2Fev?=
 =?us-ascii?Q?hsuamdFkkMZcyAQQRrXg1eIzy3cGmBkB0FTqOMcJB/oLXILt3ZES6vYObAR4?=
 =?us-ascii?Q?hsesKe3pn0f6goz4xu6VR8YgUJ8RmEzMoxnPCphkT+9thQM2uXuXWrFJ7XJ7?=
 =?us-ascii?Q?ey0+9L2S6cG090TtC62Ry3OMHXfTjA/ah7b8WEOxkYREK/kPzROmQRq44j2T?=
 =?us-ascii?Q?m/QbKPZ4JjotVCVO0TOW+Yg0dIHI1WHo+MTBz65YQFC3mK85Hg9qMdFjHAy7?=
 =?us-ascii?Q?l5thFTEKaztCuyaWmVfRlkOklSr5LcUEEQTTOI29Nv6a2p1uhVZdCEOMDHYo?=
 =?us-ascii?Q?oVRQhQcWgS5Yed1E0ur15xlicaMduxnkiPsDRYS34AxA18g0cxgjKfV7DCbc?=
 =?us-ascii?Q?mZWnoYXVQcdw3FxNTAl4HDtSAyv2+ASP39DJ7j0PJawe4xFKbZz5XP7TOURj?=
 =?us-ascii?Q?apQDJPUeaF1NorlZISlBYsUngzd3R46wiM3ndXKqwxmIH0sSkjV2s0tLQKcV?=
 =?us-ascii?Q?a37uEzjMgbjQX29fp1DLIHi98FBbDMUTpP4Wk3/+0NempLlx4CcTebb14Wzr?=
 =?us-ascii?Q?qyKOq8rkQZ3H7NmrrIi58krQKfzhDikVn9UABRS15XRSCxf/rrWysMCDGviy?=
 =?us-ascii?Q?/J56/BYfU4jYVLFMwq1eN2aTW7zbsy+lflbf7hnllqQciM9BK0MdxoSOVS3C?=
 =?us-ascii?Q?9b184m6F0fnGkG40s5qbQeGZ?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d4b3d65e-3f10-4ac8-da1c-08d8fd750e83
X-MS-Exchange-CrossTenant-AuthSource: BY5PR03MB5345.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Apr 2021 05:37:27.1768
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: NYlbIr71RZ2/13b1wPPqXxEXBPhYgu3cUn/KoPoVLKJrCsribjr1dy9tCnb5b9HzD8P+DwZd+Oz6nPQID8GuZw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR03MB6239
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b=MbOTBEth;       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.243.59 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
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

On Fri, 2 Apr 2021 09:38:02 +0530
Anup Patel <anup@brainfault.org> wrote:


> 
> 
> On Wed, Mar 31, 2021 at 10:00 PM Jisheng Zhang
> <jszhang3@mail.ustc.edu.cn> wrote:
> >
> > From: Jisheng Zhang <jszhang@kernel.org>
> >
> > They are not needed after booting, so mark them as __init to move them
> > to the __init section.
> >
> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> > ---
> >  arch/riscv/kernel/traps.c  | 2 +-
> >  arch/riscv/mm/init.c       | 6 +++---
> >  arch/riscv/mm/kasan_init.c | 6 +++---
> >  arch/riscv/mm/ptdump.c     | 2 +-
> >  4 files changed, 8 insertions(+), 8 deletions(-)
> >
> > diff --git a/arch/riscv/kernel/traps.c b/arch/riscv/kernel/traps.c
> > index 1357abf79570..07fdded10c21 100644
> > --- a/arch/riscv/kernel/traps.c
> > +++ b/arch/riscv/kernel/traps.c
> > @@ -197,6 +197,6 @@ int is_valid_bugaddr(unsigned long pc)
> >  #endif /* CONFIG_GENERIC_BUG */
> >
> >  /* stvec & scratch is already set from head.S */
> > -void trap_init(void)
> > +void __init trap_init(void)
> >  {
> >  }  
> 
> The trap_init() is unused currently so you can drop this change
> and remove trap_init() as a separate patch.

the kernel init/main.c expects a trap_init() implementation in architecture
code. Some architecture's implementation is NULL, similar as riscv, for example,
arm, powerpc and so on. However I think you are right, the trap_init() can be
removed, we need a trivial series to provide a __weak but NULL trap_init()
implementation in init/main.c then remove all NULL implementation from
all arch. I can take the task to do the clean up.

> 
> > diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> > index 067583ab1bd7..76bf2de8aa59 100644
> > --- a/arch/riscv/mm/init.c
> > +++ b/arch/riscv/mm/init.c
> > @@ -57,7 +57,7 @@ static void __init zone_sizes_init(void)
> >         free_area_init(max_zone_pfns);
> >  }
> >
> > -static void setup_zero_page(void)
> > +static void __init setup_zero_page(void)
> >  {
> >         memset((void *)empty_zero_page, 0, PAGE_SIZE);

I think the zero page is already initialized as "0" because empty_zero_page
sits in .bss section. So this setup_zero_page() function can be removed. I
will send a newer version later.

thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210412133711.7b625842%40xhacker.debian.
