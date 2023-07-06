Return-Path: <kasan-dev+bncBCMMFP7V4IARBJFVTCSQMGQEO4GT4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 415A1749324
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jul 2023 03:36:38 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-666eb721e75sf280778b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jul 2023 18:36:38 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1688607397; cv=pass;
        d=google.com; s=arc-20160816;
        b=pD4UUwGRmxCMGQF7KR9hDvcANUj201xnJp236iUKgWzIB/CBQoBvBJPvE5SDxdAD4Q
         dEF0FZsq35mr7YFir6RzMGK0oLi1VfC0lmYUAU5DiWcBo26ZVbXwR/gyKb3pkk0SYXSo
         iyJINLOR6X/YuGKaoKmNdtFjmj2WAV4axdf6tsgwfrfbbtd1GzdzK4gWRLzUNBIaMnle
         QUHhj/8gSLNJp8RvDfWIsesFduyUD2gYzr9dTCRM5VKE77V6w1grvvbqWxbbEzSf9sU4
         Es1lGMT78I+m2mV++4/1nbbL3r90O39RA8DXQxul3QEL6epdgPuLB2wJkqo/VCifqL26
         Ujrg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:date
         :references:message-id:organization:from:subject:cc:to:sender
         :dkim-signature;
        bh=hEiMGILYOlkMNPhoSxgnUoD0jsyKiiKP6SUVGOnjsX8=;
        fh=2iZJtPVHv0GWBdz3OfHnaApdBuGsPMWNK8Gxx7G5KSM=;
        b=wZFScQrrpQ8B4UEaVqKHHTVytGrwg0NP4MkSwDqWvFm6sNkUrQuwK2CkwhiODRz4b1
         BTQJYlSZRwnYy41bl38LDDzLS72WRiAWsIclurtZHQ+iRsmwDqkAJIwtAAhEYDsSqW3x
         Z/rlqp6/5nhC6gw8eutz6wQzedNo2XZ9+hKsOIcui+/pBFv0mlMdpEXtiqQNL6u8B5jO
         /IDI7tCK51kp1n/11hucl/dafKD6DripxY4AbbNiIGB/HzpTWXiOVAQIE7ncANgPI646
         JTeA0TsoXJPUPwJxsbR6a2njWcQS4bbnQFRBjs+Y4fnUctAOxlBnbpg9UtM6Y1nI8jYu
         8vcQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=yzFqTSG3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KSuCsMGm;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688607397; x=1691199397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:date:references
         :message-id:organization:from:subject:cc:to:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hEiMGILYOlkMNPhoSxgnUoD0jsyKiiKP6SUVGOnjsX8=;
        b=XBXhaA9fAPJIpylUb+2tXWywzahBox9qwk4+aALb17kxHFT1+KvScK+OiEEgRKOp0m
         5q2xV14d/TUReNR7EczIs6yJ59SZfJSCy73pApgb+5OEtaTf1RV3YfIrxW2eHi3thvYD
         Wz6kC9goe2yWGNYqn32hOhKN7wRf6mzxVRjstbThiZcOTFk9g38U0vAyeGKyBhPbTR0z
         EkpMtr20HoTi71NvwKlswZW5QIYrc+qf7+rpak4dMM0jh9GJ7eftQpTTncTSS8zYVOKS
         /M0aVsGAfK7rtp6pr6nr1Q1iCPPlojBpMRCg03FIv/W14Dby+0BBZs5Vc3eveN8qn85t
         jMGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688607397; x=1691199397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:date:references:message-id:organization:from:subject:cc
         :to:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hEiMGILYOlkMNPhoSxgnUoD0jsyKiiKP6SUVGOnjsX8=;
        b=cuHxzCD1F4j8+XX+P0L3WkRK73zD9rwEy4sLKLmFvglM/pbm8GqNeWX6MkO3JKbAFg
         c54/2EOudwB3gTwBaAmaSG6Y9qWOA/StOPDmjqgzCCa8kT+YKQNf31d2OUOqV+ccOjwd
         AYppo+YSgZ6cv3OBi3Wn2gt7+xeVqvUKv+Ahfze0+85buUfDwLEiEK96hLGoSkvEXg0v
         pX+yKGn2WpfMQGH7t2EE9WBbqbxb/qK0LIlUBPlfi7QTBmNSX1vfDhncElUZFTkH6TR6
         sF+mSgpCLudoffDBWIkCnQ1tTxM9TsZAn4WpI6djIDYm/R4sIfH6DFZxlVrXm8EH3v+p
         tgbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYfRAmXpI6kqVj2I0QWSccv8eQw/UKn8i80lr/XiUhQyB8j2rB+
	EnBDix5fuh7TRjMwKYpBQUc=
X-Google-Smtp-Source: APBJJlG2yTL5qu2MAnGmokS+/8CYPO+K0t0fQ6GvPZbkN/LBuMARwx0K+6pByyfZoHiRM5rWlyD4Rw==
X-Received: by 2002:a05:6a00:2d90:b0:66d:514c:cb33 with SMTP id fb16-20020a056a002d9000b0066d514ccb33mr461914pfb.6.1688607396630;
        Wed, 05 Jul 2023 18:36:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:84d4:0:b0:672:26c7:59f2 with SMTP id k203-20020a6284d4000000b0067226c759f2ls133059pfd.1.-pod-prod-05-us;
 Wed, 05 Jul 2023 18:36:35 -0700 (PDT)
X-Received: by 2002:a17:90b:3b45:b0:262:ea30:2cb8 with SMTP id ot5-20020a17090b3b4500b00262ea302cb8mr303419pjb.20.1688607395528;
        Wed, 05 Jul 2023 18:36:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688607395; cv=pass;
        d=google.com; s=arc-20160816;
        b=bhv42NXlYe9CFw/ZbwOZ3etVTooEaluHOaJQn04Gug+PrrKbduN7YUjg9ZNJDlK13p
         DZqjgg1akgdfVSAfMMI0hZI/QRhbvqU25um398Ny6JsVjDUtejEyud3WspjP//HCM0Rz
         ys5PAfdLdsnjwECI5Jf7EWL7Cr3SFITvT1ZE3z5VJZEXAa6qiu4QeEBUNQkK+ravAVSz
         GihVm4MB3Ntz0bPqDl578Sb3LLm4dcGnVsPfC9rxj/9FaaZ5d6Ix5OlVZnfYYQiCANxV
         98pQMzrOKZMzmhMBnbh7omKRCACTgNzGLMTOJjX6uuDlAupFv0oIrJmby3RujeeDWgfq
         Soiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:date:references:message-id:organization
         :from:subject:cc:to:dkim-signature:dkim-signature;
        bh=ECk6RBdE1tZAtA82Ulx/bgaLkPQLBbE+JmlmMx51VYo=;
        fh=2iZJtPVHv0GWBdz3OfHnaApdBuGsPMWNK8Gxx7G5KSM=;
        b=O9UiXGqwsfkqWD+PNJRjDWzT44Uwm+DOb80nSTs6KSvLlBAZKMUeURAkc/+8uYy/vK
         clJ1PfGd93+JJjPbL9k7tIyeU021MQwfOgWnRzdXrhO5MujN4v88jOC1oo9hjz+LOk04
         0IJ+wh6e2PLOTTUDC9o3sTcB3A94MLBB+qNjWfFQzY7zsVyPMot92l7YW9D/aBjhD5SB
         jgjtlkbi6TL9+mkh5WtVgwrU5hkyRu/mt6+YTwQyZZozctzF9EQJ2o1ntiXre9S9tgIH
         qxpdPguifw/RqmSTljeynzA+IOhKKspVYnP2is55g3e3SnXv1T+bY6hQjapXJ5GjGfvM
         ox4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=yzFqTSG3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KSuCsMGm;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id b7-20020a17090a990700b0025bf8494938si26473pjp.2.2023.07.05.18.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Jul 2023 18:36:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 36605GLR021479;
	Thu, 6 Jul 2023 01:36:02 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3rnf138d13-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 06 Jul 2023 01:36:02 +0000
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 365NSuDK024885;
	Thu, 6 Jul 2023 01:36:01 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10lp2105.outbound.protection.outlook.com [104.47.70.105])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 3rjak6tqhn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 06 Jul 2023 01:36:01 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=XQbax9RZnI2PcDkgnQWmlYd7ttT5w8t/PvR1DvUv/Jc1SU7EyHTcn2q4HJZnSyW1x/4QiC1OuktvNNHOd+TZEM2oWsF2ws5boQLbdD7Tm0vcdB3K6ESu6qBmSW5ArqE9XS1lHTwH0l15SJAkm/1oeZc8M2AbToDTnjJ1OK+CvyWnGcjs7p4H63xh7Xr//jF4j5gGeUwWgh5mdBIXHGpBTmLaQ8Gyu/YylBnTQDwD93l6tv0Ga+fQznD5NeW+omzhvaGdtU1CTdddsrElGZ9REn5gumkLgiO8PVLkAM8Ku7naKu5xS+wruMa6dn+FczXZqJXxgewHs4hJiISmOJf4MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ECk6RBdE1tZAtA82Ulx/bgaLkPQLBbE+JmlmMx51VYo=;
 b=YUVpsHIAZGSMW3JjOk79IhT9XyLKLvkXFEUPYi78ha06wdSkxYaZJeJD2uiGhWa2kGFVjqCPpgIHjiNKjkfEEibrs0AFiuttiCuZTETpZLgjDmtZd3HT2rzueqhsF9FN6cbw/I0qnBbieJxiiKHtQkcxu+VYU6XQl1DREtn54rapoKvRtl3qy04BLATSh8G7fbLqabdXjKUhYKw1FKvRR/x3v8pOw2XfZnZxCxWuEnxCeAGYQqOQ0n7JNMbz97UEpgU1Uaf1+5FDEIx15fD75FjPDcgUg1O20fHkBbpyppbPiN1YEwZbDsJXXUPFPch3bYFTnbtMkjiaTAd7dOdogA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CO1PR10MB4754.namprd10.prod.outlook.com (2603:10b6:303:91::24)
 by BN0PR10MB5254.namprd10.prod.outlook.com (2603:10b6:408:117::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6565.17; Thu, 6 Jul
 2023 01:35:58 +0000
Received: from CO1PR10MB4754.namprd10.prod.outlook.com
 ([fe80::9f29:328c:1592:d5bb]) by CO1PR10MB4754.namprd10.prod.outlook.com
 ([fe80::9f29:328c:1592:d5bb%7]) with mapi id 15.20.6544.024; Thu, 6 Jul 2023
 01:35:57 +0000
To: Julia Lawall <Julia.Lawall@inria.fr>
Cc: linux-hyperv@vger.kernel.org, kernel-janitors@vger.kernel.org,
        keescook@chromium.org, christophe.jaillet@wanadoo.fr, kuba@kernel.org,
        kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>, iommu@lists.linux.dev,
        linux-tegra@vger.kernel.org, Robin Murphy <robin.murphy@arm.com>,
        Krishna Reddy <vdumpa@nvidia.com>,
        virtualization@lists.linux-foundation.org,
        Xuan Zhuo
 <xuanzhuo@linux.alibaba.com>, linux-scsi@vger.kernel.org,
        linaro-mm-sig@lists.linaro.org, linux-media@vger.kernel.org,
        John
 Stultz <jstultz@google.com>,
        Brian Starkey <Brian.Starkey@arm.com>,
        Laura Abbott <labbott@redhat.com>, Liam Mark <lmark@codeaurora.org>,
        Benjamin Gaignard <benjamin.gaignard@collabora.com>,
        dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
        netdev@vger.kernel.org, Shailend Chand <shailend@google.com>,
        linux-rdma@vger.kernel.org, mhi@lists.linux.dev,
        linux-arm-msm@vger.kernel.org, linux-btrfs@vger.kernel.org,
        intel-gvt-dev@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
        Dave Hansen <dave.hansen@linux.intel.com>,
        "H. Peter Anvin"
 <hpa@zytor.com>, linux-sgx@vger.kernel.org
Subject: Re: [PATCH v2 00/24] use vmalloc_array and vcalloc
From: "Martin K. Petersen" <martin.petersen@oracle.com>
Organization: Oracle Corporation
Message-ID: <yq1pm55lt3y.fsf@ca-mkp.ca.oracle.com>
References: <20230627144339.144478-1-Julia.Lawall@inria.fr>
Date: Wed, 05 Jul 2023 21:35:55 -0400
In-Reply-To: <20230627144339.144478-1-Julia.Lawall@inria.fr> (Julia Lawall's
	message of "Tue, 27 Jun 2023 16:43:15 +0200")
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SA0PR12CA0004.namprd12.prod.outlook.com
 (2603:10b6:806:6f::9) To CO1PR10MB4754.namprd10.prod.outlook.com
 (2603:10b6:303:91::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CO1PR10MB4754:EE_|BN0PR10MB5254:EE_
X-MS-Office365-Filtering-Correlation-Id: 80bd8360-6f2f-4f07-bdb3-08db7dc158f2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: aXgzwYBWKBECwY25Ix26qaJznGDbEV1pbi+zF6JHCoR4tzCR2uwIxluJ9EM88bfvzLko4PH9fHWVp71ViS+9HtqKN4fnuIHBL+053NdcREM/fWxtqdKVTgYfbjG8Cgn2AhtWR83BfrBgDBy9k7C/uRXwa7lCGI24uIn+l+y3E24K7x254c/jC6a9UtlKGGqPvmVU3YLFzFxcwkqxmrcP9WZGdkmPwHbHfHrLUkteRTGgKnY+nCZ+s/vN1mArIKdQ+zuUvmU3chmcr3JYAc2Yqxhtmg6t9ZHcBcVvgarwJO7kFjVp11mL0ToJhDAOSBN34roYsmCKxVlGZ7BDC9qf6iZsy04T8SOlrXERoeJS22wgxC+pa7oUyndTj2uDjcOfN8YJVk9wiSgb/FMW8/e3RxTjA9jxdLcBNxzJKcI+ZbM9VkYobgVv4LlZUQ+ha61IAxqQevjo+fqx4dU+lHt1AsTfhhbRd0sNxIj1UYR/JqwP0Hsk6R/RIVHNKFJ9ObsFzvtrm9XJjMHS+Qbm3fjbwIEDC4BCJCweEHDqMKfyh+tuxadpGc3i2mlyrvJ5COEA
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR10MB4754.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(376002)(366004)(346002)(39860400002)(136003)(396003)(451199021)(66476007)(66556008)(6916009)(4326008)(66946007)(186003)(86362001)(38100700002)(6506007)(26005)(478600001)(6512007)(54906003)(4744005)(41300700001)(8936002)(8676002)(7406005)(7416002)(2906002)(5660300002)(36916002)(6486002)(316002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?oZnd1vC+ZeSjMXdCx87EfRMyfwojEc/Frm0T5UjAVAeGh3aMFwJZwHtcZYCa?=
 =?us-ascii?Q?5girqPHQNfoTvj+0scFQZwophCzQ29Vdsf1nyW9SmOxDojXLXNqV5cyiwkDG?=
 =?us-ascii?Q?u0ZeCvqRizVf0YmePuS4B4XKPRXZeWtdBJgERhesq84h5MmbVMVJzglbthFd?=
 =?us-ascii?Q?bnr/NulJ6XSj3aE858oqQ1ZgjMnpi4EswZTnTy4FuH4asu4vDTRD7ecFnS7U?=
 =?us-ascii?Q?/iVVD69XgZYO32khyhPpVg7t5rEQbmKhMwpAwEf7uy6Md6fHTk2nUBxrYDVL?=
 =?us-ascii?Q?z3RE/jCrrERGegYqMdeS+NUnQdHVq00Q4Qz//Yh3avlokJ+bHA13Xrfv3Taz?=
 =?us-ascii?Q?Y0XGCe5PDmvPzFngLaVikR9MCbDbdu/otqWYWs7SsPq2eEpa/TLEOOUpJHNF?=
 =?us-ascii?Q?/fm3z4/wipteA2ZPKUTq7LSb+SdrQxLsFdWD3f9CzLDKZbWiYLB3pBl8UBer?=
 =?us-ascii?Q?cD0MGDGas7sRwDph6c7M963dHI114loaLB1S8qfrGlNz7drSencAOBwPV/bG?=
 =?us-ascii?Q?hwWX8/4SMht4TTWkEeMZ7K4HTblN+XA6g0Ob4DIHMUSVD1tuVjs4uV4sAhLQ?=
 =?us-ascii?Q?KefngYRZlXIHQ98wJOZLgeqh2YE2A9FdANa7S5ThTmSNNh36i6DpVTWNx4Z0?=
 =?us-ascii?Q?yBzuTLEGwluhP1GKIXdVvOngjBMf27+bjTlAsJu5QqsoxWu3OXpNcKmQ0eR4?=
 =?us-ascii?Q?p1e5jR78m+7FwpIm5t56IBnY71UMj8OlcH9PjJahIiF0ln7RUQ3+8KF8pIuX?=
 =?us-ascii?Q?01auqN5+6CyC/uBWntqvT0oxr/+uPgQ3I4HnOZBu+8ZYUACa1PJ+qrpyBaR1?=
 =?us-ascii?Q?AtJPUxq8iAvvx575iPQpvxOc1bh6hkADYQWigA0pIkpVh6vfTjwkV29pC6UW?=
 =?us-ascii?Q?NFJq5tIw/UF/2Mf5V/pmmCEKsJ+dJecwzfKzPbrJaHI//cP7bp3f7WlEHuVI?=
 =?us-ascii?Q?SOpHBjHKvMb4BRPt/D/PvaShaFqXOcfY+ZVv9FB9QFAqdtlcPpjuB2czHXgU?=
 =?us-ascii?Q?4menLEzYQsNw/axT6f2gnilPKfh4BiAGCuQ66Uvatz0M5MgSuA/CtzFIAmQJ?=
 =?us-ascii?Q?FqEO0J9NgzixAh4zHM63V0ovofeW41L2NnomwNKsOK9oxWFMRRsioOv19d52?=
 =?us-ascii?Q?96QfpRTMrdcHRc55+/pMwl0USPrMcOFH9PpwX5xFmXSCBoEISzcX+sygb/mB?=
 =?us-ascii?Q?R9gMq4NyWCxJiYOUiiEYDxrefAsdtoThDurMu9IZFy4E6/n0NK0iscydE4WZ?=
 =?us-ascii?Q?RK1qD8b31FXIjqlX0bLP438f9D6RR8rKS6taVYoJPXPe7EIOOfYE8UhNyVpD?=
 =?us-ascii?Q?rAEoirTk5+B2r3WCD5ljks3RDuzLdLiDOh9gATgGDOLtO840Bstb6LE3BXDc?=
 =?us-ascii?Q?+6DpYKyhk3xqSa6yyUE9cn0fVyE42IsiOOT3BIw/vp/5XYmVXdIxq17vkuTV?=
 =?us-ascii?Q?WihMR3SE79WDmg8Aem37dJy+qnQPq3NvBKMzrSlqa+NT5wV8r4JgtYtPCBfy?=
 =?us-ascii?Q?Sik12ACwKJmHRbKp+5lQ4wvv59FMPO3E0Qom2+UleSA7sPgeY05Bz/8tSNE2?=
 =?us-ascii?Q?J731y06zhKIaGkcqT5It5FR7tNfmSxm1/UyvvpgdQdwueYYmpUwK+E8glJpn?=
 =?us-ascii?Q?xg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?us-ascii?Q?LgKkHi00kqRPLGHs3CCY+gNJJssq2gGm9nnjkbhWEA25FOZreU3WRZwKsCH6?=
 =?us-ascii?Q?MzMxdnU3lUcZ+48PfahkR/hAFgY1WKlGMwIOLH9+Guyf8+8n8H4IWl835Hoi?=
 =?us-ascii?Q?hywIRZp8P/gNZX3jeHBst0l7zrQ/Nqg6D5+1pv8TIidYuOYDHz9F+bglQ0uD?=
 =?us-ascii?Q?6EIDJtfso9PBdTW6TgG6KxuUg6K7NuMEXqxr1abkvLb6Vnj6UkUp3WN/JAip?=
 =?us-ascii?Q?DH4pHsOyyyVmapTLD91F7Izk0PWQI8YYm7qicRhSdo2BLGkYsR/AHUOWZ9r7?=
 =?us-ascii?Q?jr6edtHA4Jkq3yxh7R6QmK1A5AaYosmDZNKY373wzb7hntWECXQufC0vSmF6?=
 =?us-ascii?Q?WrQpE5IMkQ573cSJxoqUdTBwfJg0+o9fgvdtu4qQvWD8BAU0wL69/WMg0G+Q?=
 =?us-ascii?Q?IgGe90KGejmPA627NllcBQJYK067QViXu6akhpuSCF2mopMi+kPe20hzOkNC?=
 =?us-ascii?Q?EZR/yhTyOYqeLlVhsJ4hz5Vo5OB9vYqNkcCROtakAkAxJKp2pLQOpm4kDJHY?=
 =?us-ascii?Q?lO3ZG+7rmYbrJOWVE43wu+Gc9NLahPbZ/aJzBPurpla9YvZeZZRMQ9o2huQz?=
 =?us-ascii?Q?O68t+TtGVDFhVxZFVLOxeoy1RxoALc+koXh2pG4gfFmlhqJtlldiYM4EMNiS?=
 =?us-ascii?Q?mK6wuXmDX1QTuqpyeJv+qEt7luU8HgaMmFMnxq9qbIcelyhnabJxmOFqg+Gu?=
 =?us-ascii?Q?AAVOlWMugLJvhA2C8w+vR71PVtd9n+ts9vsCb0L8lHgCMefGoS/DPSF5pT1/?=
 =?us-ascii?Q?jpC42YAYb3gFgW3yK9NlFfrAQar0IZc/eVdO00J6M40MrmUZlGq1jNao368H?=
 =?us-ascii?Q?wSnY6hpbsh1DiMVZIMezDuX7aXM8r+OXOoZpM+NQEliYnlbX6yw3IgG6qJ9C?=
 =?us-ascii?Q?2cW+aGhlnGQHcj6lBJukReWifB8ntl/ZANV8sDB3iljtO9ulcNfEU1GPChOs?=
 =?us-ascii?Q?JsIPU9hPIJyhjpY8GDaJonEhZceGKBNIzQog+gMdPLLnHup3wQmrFqs8tGRv?=
 =?us-ascii?Q?gy1yqBzHJ7TcDjoF+CdZ/wWnSxTIBvqsZoa3ifZhjfmP2ozgtKudXNiHMbXI?=
 =?us-ascii?Q?WB+KFD7Uv9kLW9NBPiErOA2iuKMPgQuAa3DPf3PuaBmQSUzY99fs/0B/RGIe?=
 =?us-ascii?Q?HCVViB19o2NtGhfJA/uDj4OlzievuASc+rI9XypGNpzSL2V+MdnXPSSW7YCF?=
 =?us-ascii?Q?g8QE4BAsXcsmR/E0fvW+0TchRoX/aYG+i3s2BBC0rxgYM5ThsLsmd1NvgJ6u?=
 =?us-ascii?Q?d2si66re7OTOynmKM8OeX/Ki2dfjqpYRtZKOoMcM8pOhLVQvcPFwBMn0TDM4?=
 =?us-ascii?Q?4wFBmMPg2gE11bKrTCB6WZbR2Sc1VC+zZP+5VY6wGom7IUwSfABTguALJA/I?=
 =?us-ascii?Q?qQKegHo7UMhaPSoTmtWDBv2DgKZQpSPP+79X5+7u1xea8uZMGTk4sBGooThc?=
 =?us-ascii?Q?bcx4UcXOcaPwUkZLr9hMeW1FackgQLSmwMJTgJaoCOgToQXiBl5ghA=3D=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 80bd8360-6f2f-4f07-bdb3-08db7dc158f2
X-MS-Exchange-CrossTenant-AuthSource: CO1PR10MB4754.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Jul 2023 01:35:57.8748
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: eAhclqw7W/GWz8jwtzmOYOJlGA61zQkb/N+8gSuF1yF8N+VWkMqA0mH/RuvAR1OPH92lDBO5L4wE/ANS+D+HmMBBOcW3Lzeyt7JF6w4vCtI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN0PR10MB5254
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-07-05_11,2023-07-05_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 mlxlogscore=682 phishscore=0
 malwarescore=0 spamscore=0 bulkscore=0 suspectscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2305260000
 definitions=main-2307060012
X-Proofpoint-GUID: su_bl4C-U7ciyxbD_1fxKbYxq45udROG
X-Proofpoint-ORIG-GUID: su_bl4C-U7ciyxbD_1fxKbYxq45udROG
X-Original-Sender: martin.petersen@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-03-30 header.b=yzFqTSG3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=KSuCsMGm;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
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


Julia,

> The functions vmalloc_array and vcalloc were introduced in
>
> commit a8749a35c399 ("mm: vmalloc: introduce array allocation functions")
>
> but are not used much yet.  This series introduces uses of
> these functions, to protect against multiplication overflows.

Applied #7 and #24 to 6.5/scsi-staging, thanks!

-- 
Martin K. Petersen	Oracle Linux Engineering

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/yq1pm55lt3y.fsf%40ca-mkp.ca.oracle.com.
