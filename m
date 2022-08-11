Return-Path: <kasan-dev+bncBAABBE662KLQMGQEQ2CQZYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 39A9958F847
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 09:26:13 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id b4-20020a92c564000000b002df416e18a7sf11917563ilj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 00:26:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1660202772; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGclimjhPK9krOnooGycKW9q/3f14fhvQ2Xa5jbvO6kNgI87VB/RfHBiWkIFp9Uc9P
         Zqw8E78dRFuNe06HM6vuiAeHrD66r0ai2V9Eyp2PRwDuQkWXQ8wCiP5WdrbbB7G2QIFF
         F6z+7FZL734vSh+kTpHqmIuxPUYmWwRhHn6YaONa7aBsWVpBeQCDBq1rpnpPEE05vk0X
         S2joItHydNc5o/ctgW8PwXHU6Xl3elaD4787FNUIwIdMQEkiwmgnRVrz7pQg+fXE4itj
         tTbboDNEnq9ys4ghXkDB6HXbC77Cv8mIxOTYsXD1Cs72uxVVr1qBwp3UYsrjTqEX6W/k
         M/7A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MH4ej8f0z/xz5Uo54vSpnweL7LLkkMqSInxyoEnwr5U=;
        b=mHcjLxe2Rm8wtArDWz4MH3L64EVKL5re7SDLJIIUSpOmcNOH7qn3vVUi8zr5YG6jPg
         NkgjrSVVNzE1GmYcAhcgyQCKuzogxYGQAAWOxGcPc9iDQmlZvGEgDnClJRmyGS4bslkP
         m3xJV6DNERhK6geVfUppu+w098wSg/QVOytoHHFLUKmRR6Y2I+Ej9qGDWBoq5fvpuifj
         Yg2HLlKNHg9UwKPLjmzOHOnnRJn/E76xjM1Ro6uV05JqSBwdDemEnyw3CMB4XHxqO5tb
         QyO+jAhYkgq4chR+SfYcLLAiVHPz6Cw6EGcRTd6iSqAkmDWYt/Q3nEn1ir3CYcgWr8Su
         DDAA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=T4c8Fae9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=gvN9TaZ6;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc;
        bh=MH4ej8f0z/xz5Uo54vSpnweL7LLkkMqSInxyoEnwr5U=;
        b=EPVb3bQML3xAu1xMa616xFIhFWzsONg9vue+mS9kyPOKx2195KHLGMC9LuLI7L9gdM
         3ZuSOkH+OsL2/s7NS1sMedxuox5/K658RrQ9JjmaGyuL5VUnhipsrCqUuLFjF2xA8o/+
         QwArb8l4UjgMyL51EekDFQ7J1Ci/hYDFRc3UBTcVHKyKH5isJHhK1hh6gNihB/PhD0iR
         rx5jf+9JVaR9A710k9eeES6nM3wC8nWowePlYcLTTHLk8DZoU09j1z0lrJ8J/2VLflU6
         Mm7GUGvxJof7mKS3Dlp42b4Txp/eRpFS2hpNhjALiLJBrZGnH3gukRqw0rR+tm+FFD3Y
         UOgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc;
        bh=MH4ej8f0z/xz5Uo54vSpnweL7LLkkMqSInxyoEnwr5U=;
        b=1jKyseXfuzoWMhA7XkV6SqPGzUVTj+douuopiY4PLeCdHi78IsEDQm6EI5EokhWl3+
         G4WECWc8T3/zemyAvFcWzGznHmNkigAU+Gfc+hiAChMM4Xp631BaISVixqqVv87KAU6k
         VEcyg7nfO1M2ENGkfahg26DXxnpZghgciM0SY9Wm6l14IWbFXC5c5lMWKXoheZIJ9eio
         aUkwV60RkMQOYDTlOp02yvXkHKeUMu3FngF9Fi0NSwMlsqSKB0j+UBKML3OARAVuzvi1
         YGRqoJtQtAE9Gl1DT12rkmICs6GXwnuLZj6GdBGgXZ98FywYikYDvHF5CjKv6qOXtpms
         Xhyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1DWCEjfVCf46I4BLabkPeRY1N8PIB41g6Zj4u4kkyjMw/jCmyv
	QxC68QdVbAXUsj+2fcgagiQ=
X-Google-Smtp-Source: AA6agR77tbIU4bcIFv2GGyIgYC1nhmQKYpM4rOcP47jZ8aybNMAbHEPAXZkbDnavW9TT3SXUkPzNgg==
X-Received: by 2002:a05:6602:1355:b0:669:40a5:9c26 with SMTP id i21-20020a056602135500b0066940a59c26mr13550063iov.105.1660202771917;
        Thu, 11 Aug 2022 00:26:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a8b:0:b0:342:7484:cbc1 with SMTP id w133-20020a022a8b000000b003427484cbc1ls283430jaw.3.-pod-prod-gmail;
 Thu, 11 Aug 2022 00:26:11 -0700 (PDT)
X-Received: by 2002:a05:6638:d86:b0:341:4ece:3c4 with SMTP id l6-20020a0566380d8600b003414ece03c4mr13720095jaj.235.1660202771379;
        Thu, 11 Aug 2022 00:26:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660202771; cv=pass;
        d=google.com; s=arc-20160816;
        b=k2TIPBbziBVOyxDuH77wteOXUg7JnaNTC7b8YdRTfMNkopO3AwXCBj/ORXMVEjWmQ4
         YDAtsEXsRiLtBceKPXRnV9S1E0yMHjOdWm37qxjqEEtbcDfxwgziFxZ6F7QombpeEGx3
         rzsENESKL+DruVMy6SJnRB+px8zx2eaqzo/B6oTorrilXOmpKUONGZ+qOozhpw4tsi2f
         MrpmguFRqgMRmKcBYYI4WRxvJ62BWAOYSeAS227wPC+hxa86Stm2a7FXn2pXbE5f2P17
         Nq6sKFHHlGcIBY3Rl2gJQfgeN6mE0wQesEaSIIiorHg6+UnHgrkaAcK/i8sQ4ngrCbbc
         zyxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=veyhhhSDU3ycywKUlAMF6vUD7N6NwCH6ybieZSHT1TE=;
        b=DdCbVhqh6nbEyU6cI1K0YFRyIjsqKUu8Qk/k50YMgXzxF/N3jYGS5x+AcF7A9cge2t
         nKFD3OOYfk3qzG9MDo0i+AA61RiBf1lb6oHuWyGfIiNxDUnZ4YaO5JRoiz0N4JID+R2X
         s3bDagQslVxbkVhnUtv2B1dLaNk4aBKR813XhRToJLKWkGOH6eDqseqGZ1qkQb88OWMU
         pW/jx0T8i10EznlVFprSJX1pcU6ePUAb5BRecMWX3bZCPh2t3jMhJDx6eLfVDoJZl6T0
         IGXM5z5M/yTP5Xz7M4RCDuFibh6fs5+FUxG6qu2NCYLDiIQtuBHhP5uwWLTlYzYjU+Tw
         vrcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=T4c8Fae9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=gvN9TaZ6;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id l10-20020a05660227ca00b0067898a22fbfsi406670ios.3.2022.08.11.00.26.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Aug 2022 00:26:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 27B70UNO003239;
	Thu, 11 Aug 2022 07:26:09 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3huwqdv0sf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 07:26:08 +0000
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 27B5eREt005040;
	Thu, 11 Aug 2022 07:26:07 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11lp2168.outbound.protection.outlook.com [104.47.58.168])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3huwqjcn25-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 07:26:07 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=O3RXxPKTin63/0U3nyYymphnjIj/TwUIFRSwxZJiZKzOu12mN8W//4R1JYtwKLT6HJ7D4qLhExGLdRCu3nqkVMyY3qbxN/QDUqxwxgbwQhpKq59Jva0o6cZ6no2ZhdOCtfgS0b5GOeW91JQ48tuVTrYbD21MTntD5RfGmVVfPEhiuC4Vs6kGJHkK3glQa6l9jbwfVtQLxRGnqiKFxCESOdkxeBLFqN+7zZX1a3clO6ramUTlZt5FpM7n2wYAjNKfLUhnM8ba/FV70l0vMLxK4Y25Lwdrj3wHWEXSXFN9QBmefud/hrRZea46UlBhqMxn/XW7UJMeeglBYQ5k/nGufw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=veyhhhSDU3ycywKUlAMF6vUD7N6NwCH6ybieZSHT1TE=;
 b=Ex4zesJmydms/ftdTifZKhZUmY5lMPsuKuU7Jk1kAFs/tFq0ZRaf6yy/NwzXRJgqfpKNo9ayMKpDYQSo7+MKMPDgKlFtztD/xMqKy+RX0ElegNgDJfZnna4INLAzYWlEBgxmIh35nklmvqWHhI4FCOWOcFk8oWPSoga0frWArjU9h6yM7aiZwBupJnwfFDWI/2mntg7az8sI+3bVhlMMMgQmgHlltVD+3aObQNH0qEBTvlSUgV7+fhES5NR0w72ynauzmfMZZXx+H6TKKLGiBpr4NpnaOGefadhVmk8zkQaeZAwpZeM4UtS4eI/Qz8GT3PKeD3RGA1gi2ggDR7jeNQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
 by DM6PR10MB3209.namprd10.prod.outlook.com (2603:10b6:5:1a2::27) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5504.14; Thu, 11 Aug
 2022 07:26:05 +0000
Received: from CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f]) by CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f%5]) with mapi id 15.20.5525.011; Thu, 11 Aug 2022
 07:26:05 +0000
From: Imran Khan <imran.f.khan@oracle.com>
To: glider@google.com, elver@google.com, dvyukov@google.com, cl@linux.com,
        penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
        akpm@linux-foundation.org, vbabka@suse.cz, roman.gushchin@linux.dev,
        42.hyeyoo@gmail.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-mm@kvack.org
Subject: [RFC PATCH] Introduce sysfs interface to disable kfence for selected slabs.
Date: Thu, 11 Aug 2022 17:25:51 +1000
Message-Id: <20220811072551.2506005-1-imran.f.khan@oracle.com>
X-Mailer: git-send-email 2.30.2
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SYAPR01CA0016.ausprd01.prod.outlook.com (2603:10c6:1::28)
 To CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 4b00545f-8b8f-4ae0-d2d1-08da7b6ac058
X-MS-TrafficTypeDiagnostic: DM6PR10MB3209:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: +l3GgizNre0QNRs4tC2XBVYsEmI1Q/fj3w48qbPSmO31Q5nXiL6dgfuTOp8DMPzaC71CfHFsACEs1OR5TmVRQ++Tpxq7q7jPM5pN4CWJZbwctMGhk2jXPEhBkRqf3XwWh4pZ/xhgpq2MZZ5QpP1sz4FoghSgnoZ6bPgdIO2ptTbRMQ3U9Q7lrnPVuB2R6fISPGzsZM/ZY++mEP2oruHvdaynkEJb6f/YZSaxCjTDwbJiSoBHkGuVIcxwVr/MtwA0/gVR3OqWgAPc5h0E7whEvUqIqKy5BhSdXgqyFtwYJN9odq2f+wP+1lKT2N7OIcXZuR44RLOgq9wYsz0QL+2YhZKzOopzuO/B/Qs/AdswnGyssSYPPGXEh0I4em5nV+Llw9R0QxsSIY/ptxH9dS9YnH9oc9yEqxTfICheUteBhAfYFhadsaOWknPLUSuWcfIR6FAb8V6QkGpdRwGqIllXR0s2BkT7nqpzIx/SkcrhOTf5F0+lhCJ+/WmjDdSJ9QECDZTsUzu/eHEnb2Lx2bqEWhv0c3d5Faat+J5TvSa3rIqDA7mcgugVGWcO8j1o8ZDju30aG1AJs4ELoiAvvApDYBP+vTy5CRSEOQNNZFsPQR4FNQNMu20dbotJzA5b9gpG1Kw9rTD43Du9OXs+L8/wBwqKmu8ZEXEni95iVmT3A6834W2In9LymSkGHa2ro/yMii5OVtMTMO1hLiQstHPRsLXUS188EB6uXltvMIM9nnqV5MQiPWfR8nsqtZs9udxez+el5aTkD7fbeLGVezif41CDdEScXUDvl8QnzsmVSeRHFJMO609H1hszfTv7g7sE84r1Gsc62arOnYTH01NSsDQPcYcoTnThYjgz9tyN/r8=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR10MB4468.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(376002)(346002)(136003)(39860400002)(396003)(366004)(921005)(316002)(36756003)(478600001)(6486002)(38100700002)(26005)(6666004)(52116002)(83380400001)(4326008)(966005)(8676002)(66946007)(66556008)(66476007)(38350700002)(41300700001)(6506007)(2906002)(86362001)(6512007)(2616005)(8936002)(7416002)(186003)(5660300002)(1076003)(103116003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zuNYnJyDiVgbLQkVTNEwAAONCc+6s68Hq3ewHqKP4+0oJtU9GoQLqW8a4pO9?=
 =?us-ascii?Q?py/ATOgZIAaRTle6d05pxEP4UU5Top6DSXH4VmJsZjjJubq80Ys3ctVf4inU?=
 =?us-ascii?Q?eqNLB4Z+STjgDQl3lyYErVM0HAPAwq+8IOaKcsxkJVOMNS6tI7PmIOzcBJRr?=
 =?us-ascii?Q?6UOxtHuuE4kvY1Dp7OpZ1sFdema8/ZVmOkrKRzGFxzKJoiY313kJmslH44QX?=
 =?us-ascii?Q?DpHlyVMATpCLgx4ZSBmtpMh4VKUDku5Yi+Whj+Gyo9aAo0SwJTq83LQIh2x5?=
 =?us-ascii?Q?e4OyOAuevcmXflyX4W59qE6SF2TuOj+LT0ztcBbAQ6riMZolsDswojULekl9?=
 =?us-ascii?Q?VhBSC0FJu093un6xuDtjsdJO9TEBMeHgUYZco57Rh00i7vLNSZc7GXrRg6Zt?=
 =?us-ascii?Q?RUwTHZMAro1SiGQpL71ExFV+Xk/AETSTIeA7of5m5trrLzSIUzj0Ag7qDtqj?=
 =?us-ascii?Q?1xiVc+qNwO1UgDAePzJdW0viBMeGfpG0gcaAoj1AaXHId1SsX8bLJAPJdDqT?=
 =?us-ascii?Q?9VNW+aIzGkeDWR3BQuwvgODvFZOV32OW3SCYpx4Wu5obe4MfLQkK3G7woYGO?=
 =?us-ascii?Q?NvmMtwkbSokheBrYytQ3+HJvej9a0qzlqHOahp65kYTl6XNJ2iadgJEJ9Tec?=
 =?us-ascii?Q?CVK1OCUWVbhbz2UfpvnB5zmmK44pFadYcyi41pksycifJbD78Si9G/cgLyCM?=
 =?us-ascii?Q?uTAeVpsKIik+Z5ZPX8RoDaynkKpgiTCS4N+N+VqSBBt1lIAj8QpFCSQpUbTz?=
 =?us-ascii?Q?xgy7UKVAe37HDCljzSyiWkyP0HtuUILfpaIZfaH6zEW1jyfgXH58C6NF3UkR?=
 =?us-ascii?Q?khYC3l83ye+pouYeekLUjjcCJDOonURahy0c6Be/7iBu5vrsiWP3ISYl/iKd?=
 =?us-ascii?Q?DybHgao36LtIUWamXlTPBLlN+bC30gVL/BgNCP6r7WDdIsjIGywxD92fYoNU?=
 =?us-ascii?Q?IDN+I+lHDJXDEf08rWEPvXcDWEV+gV+pRXJmEuPWgPAxSRoIPeeHbL5Q4bhG?=
 =?us-ascii?Q?ntNIH66RHunZPWZ3lLvXgPwrx/QDjruEC1i4dyqCS8kG5IDj/n8ItfzxwIq/?=
 =?us-ascii?Q?niO3ZonNMq8HK2MR02KmzXpNTWZQfkRzG/8NfrxYV1GfiLXhgwLaTuB00Ouw?=
 =?us-ascii?Q?tmbJsThMMOWKraGAJdKc7qKoYvH37ww86RRI9aeQ1iiUZOwV6AgICmeEaHXe?=
 =?us-ascii?Q?F1LYU/RYABtrN2oVe+Bqyao6BJXJDyvFQXZAy1oPYcrcTLMsJmnZJybTR59y?=
 =?us-ascii?Q?a/TC9nCx7CNNiL75qEjoQZ20u3RJOeICpv0vd4+E4qFO2A7aUmExzCRiYgD3?=
 =?us-ascii?Q?4PEHzmiqWqQ1m1nLIrRo3qiEAXybOLtCOr34E5BRIH3WSGTpy0p4Rj/NiRvg?=
 =?us-ascii?Q?lJcOFPGbmpAJV67wLNOrsQOXCufzJUTLrJmjM5f5Oi5J/49zXyIEVsUuJ/1u?=
 =?us-ascii?Q?k+LytNkrfSgZnvvk+K2LxuJFTR5bQHzIwB7gxzQyt0/dwYjcyAd24STAQEAk?=
 =?us-ascii?Q?ZezKD4iH5soNpWLpDIW6o6Nck/cwDDSpGPHdlUocbNUSpt6veB4HEbZuUpnf?=
 =?us-ascii?Q?/c8MlDzUXQYFNQ+ucxuyRayRj0kRXSnyolBMZLpOm5KT1rlbeJQum8NpPywB?=
 =?us-ascii?Q?VA=3D=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4b00545f-8b8f-4ae0-d2d1-08da7b6ac058
X-MS-Exchange-CrossTenant-AuthSource: CO1PR10MB4468.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2022 07:26:05.1548
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: N46hpew1o/ccJAGFgBRce25Tr94UlzvqGR5OxjH74HW7ZYd97Vlgt8SWz983lSqMDuO8gorlfCgsFL26zCohbg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3209
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.883,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-08-11_03,2022-08-10_01,2022-06-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 phishscore=0
 spamscore=0 bulkscore=0 adultscore=0 malwarescore=0 mlxscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2207270000 definitions=main-2208110019
X-Proofpoint-GUID: YTQ-qtCnZh4F1Kyl1gK4VoxWi9grwK_Z
X-Proofpoint-ORIG-GUID: YTQ-qtCnZh4F1Kyl1gK4VoxWi9grwK_Z
X-Original-Sender: imran.f.khan@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=T4c8Fae9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=gvN9TaZ6;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

By default kfence allocation can happen for any slab object, whose size
is up to PAGE_SIZE, as long as that allocation is the first allocation
after expiration of kfence sample interval. But in certain debugging
scenarios we may be interested in debugging corruptions involving
some specific slub objects like dentry or ext4_* etc. In such cases
limiting kfence for allocations involving only specific slub objects
will increase the probablity of catching the issue since kfence pool
will not be consumed by other slab objects.

This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
to disable kfence for specific slabs. Having the interface work in this
way does not impact current/default behavior of kfence and allows us to
use kfence for specific slabs (when needed) as well. The decision to
skip/use kfence is taken depending on whether kmem_cache.flags has
(newly introduced) SLAB_SKIP_KFENCE flag set or not.

Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
---

This RFC patch is implementing the sysfs work mentioned in [1]. Since the
approach taken in [1] was not proper, I am sending this RFC patch as a 
separate change. 

[1]: https://lore.kernel.org/lkml/20220727234241.1423357-1-imran.f.khan@oracle.com/

 include/linux/slab.h |  6 ++++++
 mm/kfence/core.c     |  7 +++++++
 mm/slub.c            | 27 +++++++++++++++++++++++++++
 3 files changed, 40 insertions(+)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 0fefdf528e0d..947d912fd08c 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -119,6 +119,12 @@
  */
 #define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
 
+#ifdef CONFIG_KFENCE
+#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
+#else
+#define SLAB_SKIP_KFENCE            0
+#endif
+
 /* The following flags affect the page allocator grouping pages by mobility */
 /* Objects are reclaimable */
 #define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c252081b11df..8c08ae2101d7 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -1003,6 +1003,13 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 		return NULL;
 	}
 
+	/*
+	 * Skip allocations for this slab, if KFENCE has been disabled for
+	 * this slab.
+	 */
+	if (s->flags & SLAB_SKIP_KFENCE)
+		return NULL;
+
 	if (atomic_inc_return(&kfence_allocation_gate) > 1)
 		return NULL;
 #ifdef CONFIG_KFENCE_STATIC_KEYS
diff --git a/mm/slub.c b/mm/slub.c
index 862dbd9af4f5..ee8b48327536 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -5745,6 +5745,30 @@ STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
 STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
 #endif	/* CONFIG_SLUB_STATS */
 
+#ifdef CONFIG_KFENCE
+static ssize_t skip_kfence_show(struct kmem_cache *s, char *buf)
+{
+	return sysfs_emit(buf, "%d\n", !!(s->flags & SLAB_SKIP_KFENCE));
+}
+
+static ssize_t skip_kfence_store(struct kmem_cache *s,
+			const char *buf, size_t length)
+{
+	int ret = length;
+
+	if (buf[0] == '0')
+		s->flags &= ~SLAB_SKIP_KFENCE;
+	else if (buf[0] == '1')
+		s->flags |= SLAB_SKIP_KFENCE;
+	else
+		ret = -EINVAL;
+
+	return ret;
+}
+SLAB_ATTR(skip_kfence);
+
+#endif
+
 static struct attribute *slab_attrs[] = {
 	&slab_size_attr.attr,
 	&object_size_attr.attr,
@@ -5812,6 +5836,9 @@ static struct attribute *slab_attrs[] = {
 	&failslab_attr.attr,
 #endif
 	&usersize_attr.attr,
+#ifdef CONFIG_KFENCE
+	&skip_kfence_attr.attr,
+#endif
 
 	NULL
 };

base-commit: 40d43a7507e1547dd45cb02af2e40d897c591870
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220811072551.2506005-1-imran.f.khan%40oracle.com.
