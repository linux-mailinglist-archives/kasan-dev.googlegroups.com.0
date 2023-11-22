Return-Path: <kasan-dev+bncBAABBP4Z7GVAMGQEPTUO5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id BCAC17F4FE2
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 19:47:28 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-679e650f9f0sf1227316d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 10:47:28 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700678847; cv=pass;
        d=google.com; s=arc-20160816;
        b=KqHxvnBh7ESDZ4f4s8UBBff1j4gzZg1niCWcDpONJbNc9nRg95jgHsJC5aJMSWtgIM
         Cb9x8reos3hR3tBaZlTuiwvhCM5MiHaY+fsoYuFaiXt7gFU4ydnqrgeYmYpAsFF61SmU
         652uWvOW/ykYocSi17w668A1pA621DXkWS+FRrqG+6+g60vkupUzQoBH1f7bLFofkgOK
         P76FCbPSRN5fQFOvLLhejhqJpJabcwIMeVPjT5cH5jJOlfae75FCM5+nJGktbL0Tc3dS
         u9TRKRO9w0QNjnK/v4NWDoAvBFD48jEXJbfoi33ATdJDrq1jQ5gc5sAZDrt8lJj+DYpt
         ljzA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=c60nIeohHr2ONXZEeqe2SiXioOpxhUfbxr84M5zPlo8=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=A7kBk9aNg7uYTzZJnBQGeonsTC4YV38AuMwaYyEurAXyUn30v3CzxFvSYG/GNP6b5l
         SjkH7xeJXBXcOUw2mZiZnOI8g0ztxey9SGri74j7oEgy36LxB7ofd+cw59UsP1Ar6KdG
         8sRb/INoJEkv0oP+Pa67jgqpuGjlImIdO0dpQaroy5C7hJFdlf9F6b/oGZ/dbqxASs9Z
         KIHzOKX3tqj1mKKbrHQBAH5Ltk2KwVz4cpbvUMxOCnQnWzq1PGiopFXFIN8dOrM4RoFX
         OCJ6tKxfqPe+tysjDlzYsHE/PgEmZCaX1mWGbAQR9XplcGJj4RfC42xt/QjmcRnSds1M
         BrOg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=D9eNX2KA;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700678847; x=1701283647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c60nIeohHr2ONXZEeqe2SiXioOpxhUfbxr84M5zPlo8=;
        b=BcNfadghGhKxR0QB7KG8xotOaJn6GFgjKn1zLc8hL3hcsvjn9WoR+gnb8drbEiagef
         YQuz5lzR4vySr93E87mkF1xGuAy6OOK4Qo54Al6DWJE3odnYr2EtpPwS+cmwbkidRasq
         0yZazfAFUStPC+oCMsV3YyPqd10eXtJ0vCKWVQcJZagHoZ9fXfnt5DAiayK20UZP6CCe
         5HWRDHDPs8YHm+1HkTYMgIKh436tugUzXhbmw1oEchMpxoipn5Wi9hx5mXj1ooDJ9K88
         2hU9dqUqOnaUvmV9xjmPtBta1wz0GfXigebmSPYx7DwjSEjxBnFsSz/81Te7P5ThigaX
         LV9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700678847; x=1701283647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c60nIeohHr2ONXZEeqe2SiXioOpxhUfbxr84M5zPlo8=;
        b=KsBwknHyAdRzNuiXiuNeAawvZ1SPrGFSJqFFZiKYAkOouk0Y1idIEA2MlIQ9ZDFqSz
         A+R+ndfB+aM8Ym9Et7WBDuuxmyFrNkvva8zFYEgWJNS7aSg0wEPLDaUTlOG5W1u2d/4T
         sVCHGtNhuQXZ53mNYdGl/zaXlhVZJZr24Ub0ChedEvTVRdUsF93/YDN22F26+FT3VTMX
         D6GKo8eaOW5z/3Tnm0OkVaQeY9gWtJpDzkeK37mZG22beBDdrNS0OK4hzaN059Beum3y
         qn8dG9bb9OdqdjhKYkqGrbLmQO66WHlV3a2qm50QYWFeFmlStNvRFwmSuDwmbB0Sf8ZL
         6Okg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwPf1EVH/qGJr6tNZDVo+fdJSPBdTNtUGrcgqyJ1DfrVXlA86e2
	U+RufPf+BoXmw329FVJXGtg=
X-Google-Smtp-Source: AGHT+IEnfm1ynVtM84KvMsQkgGfAr+oYAuhmqnF/jK/425bA6mFJhqoqxI/Rq/St2lchigaAOzP52g==
X-Received: by 2002:ad4:5dcc:0:b0:66d:6526:d605 with SMTP id m12-20020ad45dcc000000b0066d6526d605mr3053101qvh.63.1700678847532;
        Wed, 22 Nov 2023 10:47:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ec10:0:b0:65b:e4f:d22c with SMTP id y16-20020a0cec10000000b0065b0e4fd22cls125485qvo.1.-pod-prod-01-us;
 Wed, 22 Nov 2023 10:47:27 -0800 (PST)
X-Received: by 2002:ad4:5d4c:0:b0:66f:addc:9882 with SMTP id jk12-20020ad45d4c000000b0066faddc9882mr5501633qvb.0.1700678846883;
        Wed, 22 Nov 2023 10:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700678846; cv=pass;
        d=google.com; s=arc-20160816;
        b=bwnEqJwzB2BgywSJv2djQPW7eTlQR5P2u/WpSBfA3AFwHvswBvdNDlKfOev16WYPTL
         gsGbxUspPpHUiXpAEyFy9AuiOUpVugQLVKawWSsVylPz7MSEZm1Mh72Yf4yFarakS8Ic
         XDB21BxZDyFkkyia/i6e/9KPC63pjZpon/EJjiBqVWMl1Lf+LGi/1D+zIzqAR+6NRpeQ
         kPw+6jan4hSyGGOtxVCyzaCcNFrewuX61m81ab5lCpprHQGXfVVSUTNajWQmf4bKZ44S
         tXVd5jDCGUlcDae4yixs3O61LxR2+Jv5X6di5TNWci8/uugiwSarpt83bEo9gyoQqP9+
         NG1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NAdaREqpc9sX3X6h2LLoWCzx5FXjxLWvu7E/lWR5lEU=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=aeL0etgJ6gEBtPS8jf92LoK8AhDpzqoetBKwplfQdQ+rc7OmNue3eTyyxz7J3ZYI8E
         PdXGIajQoIcclHDjOw4b/EITSw50+FybGmFqgI/9nEZiOFNPdxYUoRu3qwqdtY6yO/kZ
         r9F/n1fxx1GPLU/95FWetWmOjGoRRTtNXI7d1DYPRZb+JJFI/czDA7f4Ink0gkOLDAr5
         UtkPgRcyUy3xyA18abcBil4N+Ar4pSLPuSdiO/gPlbFwZIQ5GXFiVYJGFAujc8js/fKn
         ONjmjAzQrXOLciHAUDyp9D+G2iRibpWW5wKIVbtfnvyGF83Yl7jeA/N3VKwJPu7biahz
         iggA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=D9eNX2KA;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn20814.outbound.protection.outlook.com. [2a01:111:f400:7e1b::814])
        by gmr-mx.google.com with ESMTPS id ef8-20020a05620a808800b0077d6b231f5asi30145qkb.7.2023.11.22.10.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Nov 2023 10:47:26 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::814 as permitted sender) client-ip=2a01:111:f400:7e1b::814;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TO6s2M75oijk/6jx5ac/dtlHQVOZFkyzvUMxVPG3LJ0M2Cw06/MuYc4rSHAmEGqTD3JGTGyh85VqUlZH1Eow016cxu0LUTZxuZCadEbtCZeQcqzElwnhB/dyCdWmQMVwjcx68jMpQPhyj4z3jdH5lV1/h/srPaIeQVv+MRuUjOKJdhuMhhYMGmWvslCt7NDPqLiDKWOvWQuaNEq9yyI0ALAMnNdqocJcqJCi70xrBfVNgqSrmg5ahhp83zYXn2cU19sLYjZRUum8aqu1tjvHCNC8Lr8rjJahlUuHnGtTks75+DCltEGh+9A2Q1Ht9s07HnLao2oyIx9geu+bxEwZlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NAdaREqpc9sX3X6h2LLoWCzx5FXjxLWvu7E/lWR5lEU=;
 b=IhDR4kZ2gqcuGKjsQ39wPU6gYTXND6EUfl+VAF8n5W6KvFSrb+V8xCgzww/80eWEim8W9TDmSmv10fNg+7vvg12C1EuZXA0ACirag601kEYLpfAjLv0DSEsaVDC5y2c8efAhhEH/h6ywIpTE60NmLPBJRdgSnbgFUpCvaY/QKbztsBeJTc4iB2xau7Up7uMZ/TW/B+FUPVmVQb8wRx3FIrDhZ7s42ycnvV71crd1oUSyB0XrLxS74delr8okVfsveCNYEXIOiPUfXaOPou/LLBRY8/nQmLzNcS4Z+8mQGC/qe73ZOL17OjgyYHWjegWypFM2snisJWbt1natxZreZQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PAXP193MB1215.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:151::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.20; Wed, 22 Nov
 2023 18:47:25 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.020; Wed, 22 Nov 2023
 18:47:25 +0000
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
Subject: [PATCH v3] kasan: Improve free meta storage in Generic KASAN
Date: Wed, 22 Nov 2023 18:46:31 +0000
Message-ID: <VI1P193MB0752675D6E0A2D16CE656F8299BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [8w/MP3zGraWS4uWjx/FVeWYwAJLviw+P]
X-ClientProxiedBy: LO4P123CA0670.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:351::16) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231122184631.32266-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PAXP193MB1215:EE_
X-MS-Office365-Filtering-Correlation-Id: fe5204d0-7ac3-4dc4-126e-08dbeb8b77e5
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: FhFwHOj97K3IaSouKOz2ZtU+bW284QYopMpEajKo9iqFb8wTBwfOL87yi3PqxkkPGSJAq1AiRorWmvjTNblB577xrfAtJhTprHIPOWHcUAuwIPaVQOPJZDyHdkF5WWzIiqJSe1XBx5dswX9yK9LM6hSIkPGlWYAFu63R1eXIsid1wY2g35wnC554gYlRUyN93mOy+l2OPvJxBPnuCzHwMr18etiyWNrCbYZgOg7rjEfQZxBwRSSsLK++26Jdd4IuweZgP1SKrl91ykfl4LRMRnv/sg8Bk0DNiBTQrYGWouG8GHnXLXLzuRUUDJwsBRiq8PJef9m0sCixlGTgzCzPRLlHNT287MrR7nA7kJIaZjNbj7X+RjHtNEn10nVdanb93MgpGZutPV63dX+9l/+nGXhW+4OSfqXWgI3ZU5EQysQrFfAz6b0fF4ulS/jfyquuLm3vuYvK6v4CXrlQ04FZ75Lts8DoZavZ4sZhCFGC9pko3upacnB6uw9yUACm/6gl1Q4YijPyejsR1g1D3ki/dNViOG/crz3msdWT4XQ806viDcqfGC01sDiSZMAaNxcd
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?NykJukja7eguyySaGEKB75IHOb29H2Xo67LGOQGcfROv03MsIXaQi06/j7BX?=
 =?us-ascii?Q?JHxfccaF2Qy7tUNbZ/iujsiadwbcnepdGkulfvYcU5VbK3M28QL+wckQQWTi?=
 =?us-ascii?Q?D8z/m7pLhhbZ0PkOYVMKeuNgPujR68cCbVCBhJGzG81aIidGjnmnH2vnH+7G?=
 =?us-ascii?Q?fZ3d1bOl+gf5zrZ+oA/f2HwvHEuggq1qXREV/krvxZh1BuL4GaVkGOBKJ2lw?=
 =?us-ascii?Q?SOlHZ1nfBXSdCPp2H9EGjbPhbB6zNdMH9EjyRDpt0j4I/PkiHsBGiotRdE4v?=
 =?us-ascii?Q?NHqsCM4VeajXTfWgv5FnG8tkNZ5E4+GIPSts+VwcnSZ3caU9FmUo7CvSnZns?=
 =?us-ascii?Q?3NyybYNijhnlCtKPzSLFiZR686XcTvIIXWVGFs/i0bVGw8zyvYa1fnTRNIZs?=
 =?us-ascii?Q?beFnTOpNQos4wcdaMN4Ien/3Y1jfUpfYqFjhND58r0pfIjOUYjMT0sd89yEo?=
 =?us-ascii?Q?Y2PJGXC61iVbEcuVwKF/Y7tJA0uPjV0T9iqNcVKXcpOx9SLBdxKclrFT7LCB?=
 =?us-ascii?Q?+o2gBO1xHu4tomRcMgGJ4xhMkb+NtsGvBqOA4eeursAmS6t3OpA7GgBKTs43?=
 =?us-ascii?Q?SIPSQcPdKQ8Wom9jPxi7vZIDZc+gT6u/x4Kp0JSfcrQOkDI0lBqIeuHBosrn?=
 =?us-ascii?Q?unP2z6MYwqRnX91P3BhAV8EQkHVfOVvv13OMYEvXEjXUnzXGkrx06Cz7PDPf?=
 =?us-ascii?Q?M0no9FEbqbMEhmlaf9kaj6eQH/7vdWEuW1wZr7RATE/bqmQjtExXlxCjY+FV?=
 =?us-ascii?Q?V2Ewws6MU2EAtuFv6B8y2RhgFSaZQwnkOSQObk1xau+ucPtEvgYcMjnsJ/Sn?=
 =?us-ascii?Q?t5bh1XYZFLtS+njieX6Zc1B+JcbnmNMnkbGuo3RD/eK9slOt2YC6l9FKGX+l?=
 =?us-ascii?Q?W8GLQ0xmVZycCXXnwhTOYTxJeZfiIKdVUbXIFj8+B1C6urrZxtxWWjwG0ENk?=
 =?us-ascii?Q?PfRXbSqNpNRXeje+tCGkak9sYaUk+QYfRT/Ybo4FQokzD/Mc8WN+nbU37f1b?=
 =?us-ascii?Q?i6BnybE1bGKjE6gi3qxuhybSHWMgdIYOBu1jUIar8FJ79KAFK/3gD8lNG2P4?=
 =?us-ascii?Q?LjbaSOZbv4YtYcLK8bG4gwl8psg2JR3bu0vosRppFMqrZmqqGO96onQ3m/re?=
 =?us-ascii?Q?fzZ4isoJOhK1IgIdzeBq6JxKFjYaU5iPjKt5jLgNi/y1/PZ6u2NzYhoO+GE+?=
 =?us-ascii?Q?dTpn0pCGWey8LamIbCs8N0cZFoLY5h0osxFcvBTNWTJSTuVtRhdzVm1JBgU?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fe5204d0-7ac3-4dc4-126e-08dbeb8b77e5
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Nov 2023 18:47:25.1541
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXP193MB1215
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=D9eNX2KA;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7e1b::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

Currently free meta can only be stored in object if the object is
not smaller than free meta.

After the improvement, when the object is smaller than free meta and
SLUB DEBUG is not enabled, it is possible to store part of the free
meta in the object, reducing the increased size of the red zone.

Example:

free meta size: 16 bytes
alloc meta size: 16 bytes
object size: 8 bytes
optimal redzone size (object_size <= 64): 16 bytes

Before improvement:
actual redzone size = alloc meta size + free meta size = 32 bytes

After improvement:
actual redzone size = alloc meta size + (free meta size - object size)
                    = 24 bytes

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
V2 -> V3: When SLUB DEBUG is enabled, the previous free meta
storage method continues to be used. Cancel the change to
kasan_metadata_size().

V1 -> V2: Make kasan_metadata_size() adapt to the improved
free meta storage

 mm/kasan/generic.c | 39 +++++++++++++++++++++++++++++----------
 1 file changed, 29 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4d837ab83f08..97713251053c 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -361,6 +361,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 {
 	unsigned int ok_size;
 	unsigned int optimal_size;
+	unsigned int rem_free_meta_size;
+	unsigned int orig_alloc_meta_offset;
 
 	if (!kasan_requires_meta())
 		return;
@@ -394,6 +396,9 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		/* Continue, since free meta might still fit. */
 	}
 
+	ok_size = *size;
+	orig_alloc_meta_offset = cache->kasan_info.alloc_meta_offset;
+
 	/*
 	 * Add free meta into redzone when it's not possible to store
 	 * it in the object. This is the case when:
@@ -401,23 +406,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 *    be touched after it was freed, or
 	 * 2. Object has a constructor, which means it's expected to
 	 *    retain its content until the next allocation, or
-	 * 3. Object is too small.
+	 * 3. Object is too small and SLUB DEBUG is enabled. Avoid
+	 *    free meta that exceeds the object size corrupts the
+	 *    SLUB DEBUG metadata.
 	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
+	 * If the object is smaller than the free meta and SLUB DEBUG
+	 * is not enabled, it is still possible to store part of the
+	 * free meta in the object.
 	 */
-	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
-	    cache->object_size < sizeof(struct kasan_free_meta)) {
-		ok_size = *size;
-
+	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
 		cache->kasan_info.free_meta_offset = *size;
 		*size += sizeof(struct kasan_free_meta);
-
-		/* If free meta doesn't fit, don't add it. */
-		if (*size > KMALLOC_MAX_SIZE) {
-			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-			*size = ok_size;
+	} else if (cache->object_size < sizeof(struct kasan_free_meta)) {
+		if (__slub_debug_enabled()) {
+			cache->kasan_info.free_meta_offset = *size;
+			*size += sizeof(struct kasan_free_meta);
+		} else {
+			rem_free_meta_size = sizeof(struct kasan_free_meta) -
+									cache->object_size;
+			*size += rem_free_meta_size;
+			if (cache->kasan_info.alloc_meta_offset != 0)
+				cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
 		}
 	}
 
+	/* If free meta doesn't fit, don't add it. */
+	if (*size > KMALLOC_MAX_SIZE) {
+		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
+		cache->kasan_info.alloc_meta_offset = orig_alloc_meta_offset;
+		*size = ok_size;
+	}
+
 	/* Calculate size with optimal redzone. */
 	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
 	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752675D6E0A2D16CE656F8299BAA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
