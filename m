Return-Path: <kasan-dev+bncBAABBX4I2GFQMGQE252IKJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ACBF43846E
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 19:20:33 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id t25-20020a05620a005900b004626b1578e9sf765478qkt.14
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 10:20:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1635009632; cv=pass;
        d=google.com; s=arc-20160816;
        b=fC2UFToP/icuvlVM3dw2qca6Y++7MDqTc36iYTuKvYEFUzSB4or1ZlzJQfGEAjGs0X
         cqKcG1UMOR5AjENtD4mFn6CO3/H8CA+47QNa9wc4rOIQmoZuhQkgc/8te0ehomV0BAXY
         lD0Qh1dsghFNbtubc4DWxGpdNti/Kf8t5li7/qk0hjuTf+FRhc5uv1GT1OMcjHKiJphg
         gEgyW/8440/2iaWzVIag5QKxOfaHZQn8uhvi0pfgSF4DUFtDYC4lOBAXVWsva5kQPoB0
         zqBQjuPiQgGmPaYapKGQDti7TOGZGxrzO7d0hlNQAcRaofTabpXamWZBkIe+sJpB4Q8F
         ofjg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PASj7Ahu1fokxz1e2zo7N9OtKk8hkG0KeIAyhd8Io6I=;
        b=wv0MUhE80C6S/hqL3eHXkJTSzIMf9lLO3wfSFrE00dng4A9Uw2zWIf3DljeJO/bHoZ
         60OazHIFBysAwh8GgfgR2fNB/w1XjIozDG3qM+F4/BfauOHYZafP8GutmJFzwWhxWe9T
         UKoNoDZP67ZZRpKO0pFvmdeqJHO1Cs0ietxlpb4tA1TsZbk19eYJ3m2LW2UyyMoV9pat
         ZB1jSlwWqhqSdQoSXvbF1ltZn7aHz2rdM3xvZ0qwGQn2Hwyh8riQgZA4RKAhJzv4AR3v
         BwMpRADoKZCVzn/dctuIZncPx6Q4LV81VTQEyqa0pfDKqShmjqSYohmzfw/++x2vZ1xN
         4bBw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@connect.ust.hk header.s=selector2 header.b=qZ3nn9bY;
       arc=pass (i=1 spf=pass spfdomain=connect.ust.hk dkim=pass dkdomain=connect.ust.hk dmarc=pass fromdomain=connect.ust.hk);
       spf=pass (google.com: domain of cyeaa@connect.ust.hk designates 40.107.140.99 as permitted sender) smtp.mailfrom=cyeaa@connect.ust.hk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PASj7Ahu1fokxz1e2zo7N9OtKk8hkG0KeIAyhd8Io6I=;
        b=fIawQKjm2VLpBCgrneXYTXrGoZvxtBbxPIomsJ+0RmQT1rnEB1/dMCZWeQK4xbvqfa
         9LthCQJISDSa8VopCLGfC2SP45RP/ddkaLUeDjj1vAZZCMZ0jzBVq//6dXd1FoODWZrr
         czpK8LW3QzCjuXbiiV3ZcGFGTs/ejv/EdScAK1HTcF+KkzfG50MbpqwDngkeYY+VibkV
         buu17K1zBUQqpNbLYUX3UMr2XFkx9rIl30IBaJwGK/jQvCSykgPDxrfVs7i94UJQuO/k
         NGbBb0VyqPCIpYNZd29ibjmErhGXQE0mH9XZfAPBln52bz1oJG8MRW2WCsAeAJmvg7Hm
         W9oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PASj7Ahu1fokxz1e2zo7N9OtKk8hkG0KeIAyhd8Io6I=;
        b=TNx58eVA1H8YRUM//PToMbFzu+EA7VsNa1fBzVSbvr6uhwZRfyY7yvaotoJ+LhFy7f
         /zh9Nmgi5d+OChxv8m0OPDvqmJTnYw6BwXKgSBjbtcRlSIDz40fl56ZnHzZ/SNXZXire
         qIlt6mmEC6rd6zJiS30YKnRPlgsfdBnP4Nk1MHBm74kpg8LHxzWRSPxSRovHAR9tRw1W
         BPVcgqDPEy/3eVzMdDVZzyWhn1fqvdJ4R2O3henlqho1cbziVxTrYee6kz9Z8qSkqJ9l
         di9vmPvsVbnLVQHHowxxVGwg9GvPh1vRl27oBnTmzySVmes0TXBGfkeeCRSMOPn3XDrb
         RlOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531y16M4Ip/m1WKIOSvQ5OmRdsL4alueLnOFmz9R6UZ0dlumcyoh
	2f1xXvXbUhZsKl0aW8raG8I=
X-Google-Smtp-Source: ABdhPJx6mACm9INxUwlz1DV+ouj6Z4gzO7kLIZSt9jfR2QCflz96LRhkBmAS9t9AMYgKlISTfjfIcg==
X-Received: by 2002:a05:6214:f6b:: with SMTP id iy11mr6355477qvb.22.1635009632062;
        Sat, 23 Oct 2021 10:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a8a:: with SMTP id s10ls6442328qtc.8.gmail; Sat,
 23 Oct 2021 10:20:31 -0700 (PDT)
X-Received: by 2002:ac8:58ca:: with SMTP id u10mr7350122qta.403.1635009631486;
        Sat, 23 Oct 2021 10:20:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635009631; cv=pass;
        d=google.com; s=arc-20160816;
        b=qyIEOyhZlGcpdN1o5BVtkkN988EFn+2hfq7dNo7Rjw1hV8imxX4RhZSaCSvqDmyAaT
         8Hj8S1dmhGdM/IhQTigq5piCmJFoegfaDPV/EstvGkRfO0nKCQyWH1or+TsLu6/wx2mn
         GsWpIFY3zon9q2KnCuKVytZJ3iKbed3TJ8D4srlKuekMbYnd+cQaKV5Ek4/JZ5Gsjznj
         A7Ga1UjZGNxKTvhc2DA/0Srvm+XIqpPPN3pfEZHTGR/rCCQjJcdPWF0e10wd0nXdoTaz
         dH7sJSWaMCYp1s1VOEjoSDis9uOW3MI3yKyY3M3DrQJeK40cybimf7YnDL60pvS5Ba9k
         6OQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ewpc90BOJj4gY+d3uyYUqlpEWeNTrP3/D5ropDD5kIs=;
        b=ElBxefM0dh3sJ57t2JPws8VSqGjkwmxqD+laLK/4WSpKFPJJ/vzUq/KXv2/RzWWg5X
         AeqcuNBM/uvlaXaJNiFVwO+U4S4/TG9rKSgJHdJrmwriCeaXMuxuLLT7/mxXIlrt1Fmj
         CR61C69hw9FdEv92w9MoDKluSIyCXqnbHIKOvuGfISCWynHKSpwgldIhKpaeIw7bvqlt
         VLAgyff+r9tAp6ISjFlQyrVZhrfUKqGyxIG4fWdgn+Mqy2MLb/5BR5vdkZACrxl7DkEm
         ORiSmhDryLunivApaFW2+6boCMbf9DHJtGdLw36TyHTehd+VF8dTNU9CfIbu4u4b0/JP
         bkJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@connect.ust.hk header.s=selector2 header.b=qZ3nn9bY;
       arc=pass (i=1 spf=pass spfdomain=connect.ust.hk dkim=pass dkdomain=connect.ust.hk dmarc=pass fromdomain=connect.ust.hk);
       spf=pass (google.com: domain of cyeaa@connect.ust.hk designates 40.107.140.99 as permitted sender) smtp.mailfrom=cyeaa@connect.ust.hk
Received: from JPN01-TY1-obe.outbound.protection.outlook.com (mail-eopbgr1400099.outbound.protection.outlook.com. [40.107.140.99])
        by gmr-mx.google.com with ESMTPS id s15si948570qkp.3.2021.10.23.10.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 23 Oct 2021 10:20:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cyeaa@connect.ust.hk designates 40.107.140.99 as permitted sender) client-ip=40.107.140.99;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Iq2db6RabtKb5DbaKJa9zIIHlvVGi8ZrnrvLXPs2K4EbEys0zNA99PTbcetkR3YAxTmI4Y8ihwbLnBE+4MSTzSkksLK6nZvxXa0yBL/9FWXN627HBaKko289JzAYQ7P8jx6MClXBFHinNUZnMp8jZTLI1ONQ1nwN8dzuV2LSYzQh9AzyQh8xDDd4nArejJVUqtMwf9Y9ule8xvrUtLtwWSwxYMo2biBg4vljPMhNObX5IrVy5gfGscDUZpr/CpdmM23GINgePH9o4gIhtqYS5uzBL6pannGB0FPpj6n2LIzGEgDJIfZ/24AhlAhpHSqxNxByhaYQ2/d596/arHbHFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ewpc90BOJj4gY+d3uyYUqlpEWeNTrP3/D5ropDD5kIs=;
 b=ZZgP72tacQ85O6Y9cQUHrl+5J5YoerIXjt31KolItoitU7iqtQVhf7jJWhgk8C3gioR6NlVNB0XDxPMCcIryLe1qitIlJ5ZzfkhMNSy1g/ykZGJlaq3762XqBBJu0lm1Vk6JyenAyPU9k9358RZMrTyTe/wPSwUKSMTt54BcMO8kQ9pHRszVs0zBkm0QHIbWVT19vJX1rLfSh4j4X/ri7uLxGddbfHj6dncJWajYiEwPTIrb/73PdbUOoDGxwDyDmZI2SXxczMfoXnZ1JNrmX/Yi3XCRTkdGkQKBmnImLFN/cgbhtwP7bGfcdRX698EehfyL1kqiXpM/M3dWuz111w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=connect.ust.hk; dmarc=pass action=none
 header.from=connect.ust.hk; dkim=pass header.d=connect.ust.hk; arc=none
Received: from TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM (2603:1096:400:b7::8) by
 TYYP286MB1098.JPNP286.PROD.OUTLOOK.COM (2603:1096:400:cd::11) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4628.18; Sat, 23 Oct 2021 17:20:26 +0000
Received: from TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM
 ([fe80::c0af:a534:cead:3a04]) by TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM
 ([fe80::c0af:a534:cead:3a04%7]) with mapi id 15.20.4628.020; Sat, 23 Oct 2021
 17:20:26 +0000
From: Chengfeng Ye <cyeaa@connect.ust.hk>
To: glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org
Cc: dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Chengfeng Ye <cyeaa@connect.ust.hk>
Subject: [PATCH] mm/kfence: fix null pointer dereference on pointer meta
Date: Sat, 23 Oct 2021 10:18:02 -0700
Message-Id: <20211023171802.4693-1-cyeaa@connect.ust.hk>
X-Mailer: git-send-email 2.17.1
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: HK2PR0401CA0005.apcprd04.prod.outlook.com
 (2603:1096:202:2::15) To TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM
 (2603:1096:400:b7::8)
MIME-Version: 1.0
Received: from ubuntu.localdomain (175.159.121.169) by HK2PR0401CA0005.apcprd04.prod.outlook.com (2603:1096:202:2::15) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4628.15 via Frontend Transport; Sat, 23 Oct 2021 17:20:26 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 94891ae3-6029-4965-4b57-08d9964967a7
X-MS-TrafficTypeDiagnostic: TYYP286MB1098:
X-Microsoft-Antispam-PRVS: <TYYP286MB1098461515332BD5ADD29D058A819@TYYP286MB1098.JPNP286.PROD.OUTLOOK.COM>
X-MS-Oob-TLC-OOBClassifiers: OLM:2958;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: VSu3iYCfDKzU3IVD24QIglLcDGgglIiXHXqCV1FrxSRMrtm7/QjHEZltnTcZuYEKpZHmDAakluAljUidOh+a+MADjr3rF+eHga74O6GfMDbUzDhAZg5RpalMTiF7U9IBBXS9BOYgLarqON+GtNpgKuUZzYBZKt/KetFYhFpV5IZJ7VfI0e5Tp+4RA+6HADNdquivMuzeT0id1y/AF+IASJ338eaIws1yhVYGiNLUeiIcEJBpQSBlB01B8Yo0T+/nPpYKAhigmr8zzlWDvXOe7jQqedoCwM+bEB2kniKwTIgcfgEEbvNRM5Glnz1t5j9uqCmi49jjw7Z4Mv/MW5OveyrOEaZ2p/e2/WY0MZeltZZQS1LMw0gIUEFIQomgAwKV3UGEvVqfPrcAc7n49pvgMRVHRnO+db5T0rPRS322E9ShWOt/AtWNRp5ZCNx5y9W5jatyQEYufqz+6euQZx61WgpaOtTtalhAOVNWXLXp8N5l4wgbTupRaF/fQZHw/4Js8HC6N9NGl2TzBgYhOFj7Tt1PccVLgkAARPEqITkJmleYH7fzU4vuw+z60kZ5FrjOW/jED2spoAsVEzsBpZgfsnGaXIIzvmHyXc/Be4qKhZ7y8QdbGOxZ2HSCOcZCNXytxU7p5asYYiIn+KFA8O/FQQTAfenMA9fXnHTQNJnF89tJRaFzMrc1tCCxIoCyV86Bd12rKGzbLPa2Y7Y0AAEZKw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(4636009)(366004)(956004)(6486002)(8676002)(508600001)(66476007)(38100700002)(186003)(2616005)(36756003)(107886003)(2906002)(83380400001)(4744005)(1076003)(52116002)(4326008)(786003)(5660300002)(6512007)(316002)(86362001)(6666004)(6506007)(66946007)(8936002)(66556008)(38350700002)(26005);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?jXHBoMUhEAL9yw+XKuren0fCV2J4IvRuM8QX3i33Lk5qpJpD8kB/A8WHeA/K?=
 =?us-ascii?Q?EyK7YEmrcSmF17leJxYBoqR073hDsGCJbodcOfDHKXgJ+PjUFX/HoS96nsWR?=
 =?us-ascii?Q?f9AtAfyFU/oAwO3oy5PkYbVQ/zSeMIHNkHcKn+ZNjItZHPUYSjq1i1C+TBws?=
 =?us-ascii?Q?dnLpAzHtfC90iOxMGgJqLwreLJ25QOE+i0b8VVx93KJRp2FvCntCgbjRW2t6?=
 =?us-ascii?Q?NkObRAngWn8684KAsgzur5uq3f9dMyGmaFemmR6vzxNrKt8opxpe5uSMCX78?=
 =?us-ascii?Q?WhM6VquQCX16oVU2Kv1allM3TDQVFzgO2C2Ll7TFAcYA5M4bStc86+1Wy+Am?=
 =?us-ascii?Q?W48Ib+v5uTSp8HhOzgWyDEWtsMoipejkxGlexzRHqQGyWrN1tadMJsNKm8Bj?=
 =?us-ascii?Q?KybsEK42tKrHlMv/xzc+u/jvjmpoHLUCyIzm9PM2bVW9BxIUIV1/9KWjnUsf?=
 =?us-ascii?Q?zFt42sYzkjyBh5wTBom4c74Jx8XJQMc78KU9oF9jWF00YvKw1Jir55OnSBay?=
 =?us-ascii?Q?lsPh6I7lNZg81jlpqJsArGh8n/HRNWHc7IVPr2+87hBnq0TfJNDOYyuBjpzd?=
 =?us-ascii?Q?zZG3C0ScRMjf95Z+P0aNvv0Juu7X3oOE70wuJNmDyL3CYekxuRGhxzwX47es?=
 =?us-ascii?Q?yGnLDuVRXV6ZjtVK/+uH9OixzBdpSdlREwOGs5qdoGz6SiqiQivMlxEvA/LU?=
 =?us-ascii?Q?1LXPiPmUdZabbeNCE1BAQ4jvFu7yG1HO6TcTWFokegcJEjv4YOZdZvfVlWGE?=
 =?us-ascii?Q?JxVw1ESTQkAGoItsJHvncYWQddjaGhi+XBnNPDEvBMiRw3P7eGcM/t/oEsf6?=
 =?us-ascii?Q?3VY1yqmIyhOSKCrZ06gqOrSEs+SAO/LRMGg0Y0cJ4jfRPLrsADodXHIBPxhq?=
 =?us-ascii?Q?39xn5bI/B+Pmb1t3JSMVQKlJP0QVPiVcNWCmlAZ+deXl6J9r1M7vL9RrWuJc?=
 =?us-ascii?Q?2SwZp9PbdmVtydWERlVuT+nTr4dd6aSlpwgE/OBxUzlGm4rbpVm0E65sDNg3?=
 =?us-ascii?Q?x8ikWVuN7PV4Shy6xuoMABqxQcLvH6WXh0g5iXrXDRxGCvIY03fYeQY+iS7t?=
 =?us-ascii?Q?UQ1kEjcBCJr6C23LgaDdvJq4ludc8J0hwhdhoYNtcP6RDvzRZVZlSQQHxozq?=
 =?us-ascii?Q?Nj1lPWZkAbr1C/S5eXEUrHxCd01kuMgas7/MYR4L2fWftCZe2vGwgoW8xCaA?=
 =?us-ascii?Q?Fs7MMIGKCcwyXaZGk/NjuFa/xHu9sIHdkJenMFRh9Jd1ZLO7xfZo/pnt5HDS?=
 =?us-ascii?Q?KBjnnTBk1+hOb8CUceGskG2IEXz6HjJ4v05Pnl0pTFpABwpCOVAENySswnzS?=
 =?us-ascii?Q?T09rZf5aThrosBq4QHZJcUWqWULTAXVFM72bbKaARbii2PLbnCMgsEQ8AqcK?=
 =?us-ascii?Q?7xgAgmSP9lzaIT2XP6Vws3v+oBHSNJ8aNb71hzyoE+yqhIZvVAeUb+KXcMVy?=
 =?us-ascii?Q?ATj5eTyQT8nNpcfUwEqDBBFRlkZaAXo1QAB/6uBXrnYGkS6G4eLL4KmfadI2?=
 =?us-ascii?Q?+1pVgG8Q+jROnLhN2oMXvqfYI8NR0HgC3mLgJxYDzS/zmnTeG1h1MT6MFonF?=
 =?us-ascii?Q?+c0jo1sKXGoezpCmKF/3DOkB/iY2AMINyNbqDYIt3fDIor7FtE3GNUYddKlP?=
 =?us-ascii?Q?38G9TNgxMYFUoAxxdnVo5+8=3D?=
X-OriginatorOrg: connect.ust.hk
X-MS-Exchange-CrossTenant-Network-Message-Id: 94891ae3-6029-4965-4b57-08d9964967a7
X-MS-Exchange-CrossTenant-AuthSource: TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Oct 2021 17:20:26.7682
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 6c1d4152-39d0-44ca-88d9-b8d6ddca0708
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ckoXgvJMJo9z7sssEXMYA+rQn9AjiQHunOsXDDP3y2+Hfyy3Wz94ymFQrJg9PdYFUwCjpwCJdmy5udZPy/ofYQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYYP286MB1098
X-Original-Sender: cyeaa@connect.ust.hk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@connect.ust.hk header.s=selector2 header.b=qZ3nn9bY;       arc=pass
 (i=1 spf=pass spfdomain=connect.ust.hk dkim=pass dkdomain=connect.ust.hk
 dmarc=pass fromdomain=connect.ust.hk);       spf=pass (google.com: domain of
 cyeaa@connect.ust.hk designates 40.107.140.99 as permitted sender) smtp.mailfrom=cyeaa@connect.ust.hk
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

The pointer meta return from addr_to_metadata could be null, so
there is a potential null pointer dereference issue. Fix this
by adding a null check before dereference.

Fixes: 0ce20dd8 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Chengfeng Ye <cyeaa@connect.ust.hk>
---
 mm/kfence/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7a97db8bc8e7..7d2ec787e921 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -811,7 +811,7 @@ void __kfence_free(void *addr)
 	 * objects once it has been freed. meta->cache may be NULL if the cache
 	 * was destroyed.
 	 */
-	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
+	if (unlikely(meta && meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
 		call_rcu(&meta->rcu_head, rcu_guarded_free);
 	else
 		kfence_guarded_free(addr, meta, false);
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211023171802.4693-1-cyeaa%40connect.ust.hk.
