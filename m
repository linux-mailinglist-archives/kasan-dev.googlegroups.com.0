Return-Path: <kasan-dev+bncBAABBD4K2OLQMGQEVTALSOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id BD3B058F9A2
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 11:00:00 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id j11-20020a05690212cb00b006454988d225sf14245061ybu.10
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 02:00:00 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1660208399; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJXTsIau3vO7YaZCNnt243m2nWMlEMjGvR8AKPGhBTGUTZJHUQuzaRyA4BofHNg1NY
         lFlkALk9RyYBi9+i/HR5mSwRKKccHwHSLvDYEPEkkAE6YlcA7+lqigKrfl2KLuwiAD0y
         opPKCM6aXHnWwnwvQ2uTOg0vUen2y8mrjP2Q2Epg+5rtm5Etc0YrEdtPhd7GtQqLQ+Sa
         DZRiQu6ZmlIP3RChOE4yIy+JnTfi5/pzKZyjCkhwCe1YNgcYU3MeDGhVmvJf7dLESn6J
         etfxYmsPYy8jEwU/43lKr33vN5Sg76MJRO2POCNGeGKz6uvHBAthBUSW3M0nSERpsZbW
         59XA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Rd29zkidQtmNAwwVqXTGc2mrUPGQ+BgJFe1brB9TCk0=;
        b=Qza0N4tT72ub8ws6y8uFEerRhYLkcjwlem5KDMtJ+kSKIzuKqASWtSHE9J0bEc6u5S
         ijvjcdHo9fqCTZUTj5+1zRxMdyYkDHVvq6JdaDBorXWLbJ3H+IvICnW6p68Dlo98V+2w
         1MrFAd/9utb5Yb8lxOp/XwJKxUju3RjJ1GAVh/zuzpylln22ZCVLMXWpjPMVRIcSzRpP
         eU90BBJ+dMugrF+PPqr0G7iJ6oj7QP3IVn40Tsbvifc2LtoAg0Qhkj5ZeXhKku/SFzL6
         9PNRBj802xP/tIYnAEzBYAQbr/TgCMgWvuzH333W5HYLt1WJYogPC2ihgSJQjLnEVSbq
         dYxA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=A9sIssYt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=LME0GOPd;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc;
        bh=Rd29zkidQtmNAwwVqXTGc2mrUPGQ+BgJFe1brB9TCk0=;
        b=jS4IxPAtQS+8YoR6eLtKOy6RuKUwC7gm2tAFqAS6Tdz/Qp+MzxVd4uWXRKAKZvCbA+
         xyJTiEbcPhZWJJv/71tbINq9GtxZnuAH5yWEfiPimDJVkE5SznD3WLfPkwWZU1NmRwSm
         Cz+VQCkj1DKTN5ioEEkwSGMcVh3YRjBDumUK6QjhnJaOJzSlhIkmD5WKtdbtN33WCU3o
         EbzhGP1gZqZVQB6fT4VIeCKcBji93gp47Z7efOK9c5IG0t4vbRvoqa60dmlCULjujWSL
         rZOUJVt9mEmI/4lhSKHtB4lFCCEp42FozkcyOEnOhVtiHgikXMzg2ODDIkGdS8sqsDFE
         2WfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc;
        bh=Rd29zkidQtmNAwwVqXTGc2mrUPGQ+BgJFe1brB9TCk0=;
        b=2qAl5V/B/kcMsNyGAA3gltwW0dlVA7dPNxVJKAwZtfsGPFsBvbf8Hl6rAIZ2awA2qr
         Z2DPeUyKJL58lnbawIdTkEGeaknqmegly2QaWgzzdTt9cO83L48DI9IL/GDJWy/fq2Ds
         imwrETEbZfxmYllE6MUcxqkuoVzEIyKAELvKo8w/bSvNd71peuwpGTFv1eFIctXB/QV3
         WLsG/E7f1VtgCPH5Tb9h+DMhgSEuApw8csM84HNLkTs7DAk1YMnuLg2rhVkqTFzpOj5a
         DxhevZ09B/30IwoFc8gdbAaNpHNOUuMxAm0rrlAweULcb00sKoaENz/+phrWDnabgnDo
         suCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0GoPoqAG3CPIu5WBiXd2bpDsr5qHuh9QMyTQHSleh9dqHRMEgf
	W3fAI+v3irpFjg2EYMrL5lM=
X-Google-Smtp-Source: AA6agR6gGTuczqyhPexIq8Zm8KsFa6oKhjnwoI/bbM71B4m6VFSJKldVzyhqoutKgQTnk+wmXYxe5g==
X-Received: by 2002:a81:7756:0:b0:328:2dde:3336 with SMTP id s83-20020a817756000000b003282dde3336mr33216659ywc.81.1660208399540;
        Thu, 11 Aug 2022 01:59:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3608:0:b0:66e:7859:9c23 with SMTP id d8-20020a253608000000b0066e78599c23ls719263yba.1.-pod-prod-gmail;
 Thu, 11 Aug 2022 01:59:59 -0700 (PDT)
X-Received: by 2002:a05:6902:124b:b0:67b:5d4e:c98d with SMTP id t11-20020a056902124b00b0067b5d4ec98dmr31097668ybu.475.1660208399081;
        Thu, 11 Aug 2022 01:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660208399; cv=pass;
        d=google.com; s=arc-20160816;
        b=f7bO6un22XdQTcJC0efMKFacLNX+9VrWxBI832UEmGwL6hjC5e8soKq4gHH1rPot8i
         XMW51IC/UJY5zKeFlIj6eHZ7BGGuEp5tdKF+YOMGbKH7UhpAUxEH44vM3K7+FUBZlphf
         iPlp3jqMbVR2CQyOCEFFdyWP0qAz61FKbYAWOaIZrq4ij/z3150DHqoGMjHFwbFh8ySy
         A2/wuh/3flZu1IiVlnT9Vq/YlaMRQ738nueqEQoVxiu1qz5qrkYNCXR0hS8jAwl3Q4yx
         u7yYSmXGW3G9W0pEpNDG7YtIrszEPlyh1q/J1kgCvYgHlCiuMhOzfcX7a8etWPxnP8n0
         lpTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=qAM0pn4UF0rTJdPp3mQT8Fre9fDAqiSMo99z3uMd/ao=;
        b=tAZAR1WMqVbIQsmdzRw7R8zzEDtSIDgZYNVbbgqch1vfGyoZrZU8Y+1QoPJKLVdpBf
         zlUQ81V+FPI76aKu5O6l1Wenxhltblc+4awaPJvdcvskU48EA7KtsvhMdVSCAIRA2u78
         0p2N4AosRCid8I2hQ/cs2g0/Wu6wUKz2KNtunAEa6u44MwcgKIjv5Z+ytq6ggSsX1zAt
         mAhB0uW+j4zMGC7YkLS9B5LVFf/AEU7+qM+QheVl0JyiHetru7SB1tMGGTSKvb8mSIpr
         gs1xctLchD1uTFOszfjvVm6jYHs/+wDzQMtLShFhJ71EGuiUfD5XLDxXbhmrTXgC5IGe
         jGeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=A9sIssYt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=LME0GOPd;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id c80-20020a814e53000000b0031f425c34a5si1527515ywb.4.2022.08.11.01.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Aug 2022 01:59:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 27B8k3if031585;
	Thu, 11 Aug 2022 08:59:56 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3huwqdv7g5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 08:59:56 +0000
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 27B5ZHbM040694;
	Thu, 11 Aug 2022 08:59:55 GMT
Received: from nam02-bn1-obe.outbound.protection.outlook.com (mail-bn1nam07lp2046.outbound.protection.outlook.com [104.47.51.46])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 3huwqgnyea-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 08:59:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=WdPXrLvjJ8mHf2B2wqtewTYPfHxKx2Rz3EBoArPiMpjlCwqAd2Y/M0Z+s8fyN/MQUfa6cIge0W0fLiuM9WCbjviZo+BZuQMNjDfgFs9PWHU7WXrWlBzNiCCenJCJGaVENmga1e2IUhuzsFLQykcDqcI/vqadY98tKpxptcqHXOT5FXTf9kvOWeZjcDeMij+L9E8zjsSVNlb/lbWNLZxHnsjVkGOrsJzrDHuFyhiHfWiYUzjlnpw9nuaJx+jf1j5tASrBfZsQPo1spWtFWessXsfWZ4m9VnZWLMBBhORTwaER/8m5NaHj5O0ep40rVVW5BD1VoXtjhFiwrPM3oggyzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qAM0pn4UF0rTJdPp3mQT8Fre9fDAqiSMo99z3uMd/ao=;
 b=GOeIIPWF3oy5C6i6xIGzIKef1xwVJ/43lnhFpkALELi1y8BY0+9oIPEglQmdWZaUgRcICkeNjEKX27fy8Abj2I3Gw+s9Ii6e/eTdFxy+WXc3vx5zL1m4/mfFANkXUFNe6zDYbMWB/AwyockSS/LjxR6GgzbUUQmMi0o9LBNSuOOINVdtMjMmAwQjyMd4wekCMsic94zp+PUwhw8D8Gm5JSRWWIiCvhcQ+g4s03ydKHXgnD7SP/qmVs85Ihb8cNxOLs+1HPd/uB17OXqZcbCookp/UkirCTSfDMX5hONTZTyw6ihl2myK78DeivKF3vQETuHxccvf62I9NXM5LSU2UQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
 by BYAPR10MB2744.namprd10.prod.outlook.com (2603:10b6:a02:ae::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5504.14; Thu, 11 Aug
 2022 08:59:53 +0000
Received: from CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f]) by CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f%5]) with mapi id 15.20.5525.011; Thu, 11 Aug 2022
 08:59:52 +0000
From: Imran Khan <imran.f.khan@oracle.com>
To: glider@google.com, elver@google.com, dvyukov@google.com, cl@linux.com,
        penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
        akpm@linux-foundation.org, vbabka@suse.cz, roman.gushchin@linux.dev,
        42.hyeyoo@gmail.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-mm@kvack.org
Subject: [PATCH v2] Introduce sysfs interface to disable kfence for selected slabs.
Date: Thu, 11 Aug 2022 18:59:38 +1000
Message-Id: <20220811085938.2506536-1-imran.f.khan@oracle.com>
X-Mailer: git-send-email 2.30.2
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SYYP282CA0018.AUSP282.PROD.OUTLOOK.COM
 (2603:10c6:10:b4::28) To CO1PR10MB4468.namprd10.prod.outlook.com
 (2603:10b6:303:6c::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 7d27ce05-7068-404d-187a-08da7b77daa0
X-MS-TrafficTypeDiagnostic: BYAPR10MB2744:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: cpkK/Gc3vzbFQYx0CoQKzzlnfoofAD6xKkTAtL7LIj2lRu1880VdhwS2BNFxqExa6tONingnBg5sTxocyjBxaUX8L550StLFMnlcBd2OcfLz4ZdkJLfE4qQulomdoJ+7WPIzkEq0v2dCGjO6svP2Mk9J88BY0QfVc+rOayULpo27nc93aK8csh4Bfi/gcaXVExrKgBmXEv5WkcwWkT+XNAnPvB0GmPlCjYpSNN9MD3UDYlMdoAh4/RNsNJUJZPAuWV8Kfe1hP5vkD0nnzedLTIwYRIopGodrMCJN2Si7fPWxz5TvBOOncyBt5hGqD5QcfGwsdw+WBR+4SEuvjMGRMW3T1XqBgu1jvg7Vvqi/Lo/wDgN9jo8ufaKP+XYbrFQPF1Xd+YniIhoVdaDge4gEYWATD7ia3OTGMr5AfK2PNqjjOG6u5nu5ONem3JdCQLrg2O8NRwqAZRFPmk8bUVj/nZHVjTRaPbcG03AlMgUMT9xP85jcbm5sj4jDffe96MR3p34yV/WJ2j/96ggIwnF43mAL49bqkbBM4PKnl+kR5BzdP8LJkqZ8MinUrqMwvuCSTcproE4Qcnb2FpEtUwm305Ek1m070v3iptJazvh/5drl4IpZ8lHC03zXh5pImytktWdBTUqT7pjsTS6RV8NFCwYrIk9/Ht8xT4aAx8iRzGCcgF8Zu+f21Whpy/e+wVAAuE8gtXspLzaeUDZsf/cHk8sKe266gMnqOrKL2UO5Z9V7Nlhmtwh0v2Z7ARr9yir0li4UuC4dw51InYUsOF0xrTzUp3TOmlwjCEzGzLihqnQlthhbgnCQSAhfsf80SY98
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR10MB4468.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(136003)(376002)(39860400002)(366004)(396003)(346002)(66476007)(8676002)(5660300002)(66946007)(1076003)(66556008)(36756003)(4326008)(478600001)(7416002)(186003)(2616005)(8936002)(103116003)(52116002)(38100700002)(86362001)(6486002)(26005)(316002)(6666004)(41300700001)(921005)(38350700002)(6512007)(83380400001)(2906002)(6506007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9GqUdBWyOAN5hMc1++zQvan46+BQq49DgtPH+Pj3WjmkGHVFvsTIWhoKy3eG?=
 =?us-ascii?Q?C0ycTxmIYvTAnqW140WqdjD4uhpsEI0XpZ/aFsZASx+YbuPcVI6i2Mvl3VSp?=
 =?us-ascii?Q?bT0vDdMA/7QQZSzH7NIoUOvCEl2GtM9flZkjyy0S0VF5sUcr8DhSL0sukop5?=
 =?us-ascii?Q?aijfMYqtkXGHepmeAiTvKtIOhD+2sfDc2gRuzbB5Ph2NUH1V+rxCNcPvI9l7?=
 =?us-ascii?Q?eYL0RAnvNyD3yzEDlnr/7+LwryZyizeEURtMsQm3X59N8O+OLaTYDzVVHfja?=
 =?us-ascii?Q?Z7AblR7Uw+Pc4+2o/ufrDhGDksBfvZzaYjyTg0nC8Drclb+plLCJUQWy2Lrd?=
 =?us-ascii?Q?0Z0RUFO2hFQZdRC1Lio+CS2U0BMV71TWv0tW6LCE4iGhfnTJ6+YSGKQoi4y2?=
 =?us-ascii?Q?8C8Hrjoch6kYiIq5O3ky9irsg86ZYsh/eW9Zhn6qMVIvQJsOl7x6iJzgckkI?=
 =?us-ascii?Q?j5BP1jjg1wkZKF94wwE1UYAWlyvE6cqKcKQHgxZCRqGUFs0cPPY4Se7z5ta0?=
 =?us-ascii?Q?grxn1rtG+jIVkJh9KwmFGEUxgI8vgSBsmkAD5Y5vKqd8lEA3wslzB2FNvVzj?=
 =?us-ascii?Q?OCZURI4sF1+TN6DyXdPiih8ok7/DonpAvXb/p9m63Gxqdtz2YBcuq5gDxYvw?=
 =?us-ascii?Q?kmhBntwCD/F5d8Og/u8BrydO3o0wFjqrxbXI476N4bDPAUHoMmjDXcz9gFMZ?=
 =?us-ascii?Q?1euPl4S8gpbtqzozqWES/Q0sSa22mn41/cX7KbBeuHnARFxQJo59Oi4sNvkx?=
 =?us-ascii?Q?pY0up/Wj/TkiwlueS9nLcVf1XVp0CJi6aLnog3GbmPoP1WGtXnMsrAIKmfmI?=
 =?us-ascii?Q?azQvmNKeESMJuYwIene4Pe6XNdCrayolgIq63MqdGXLGY8XqivXvYqjcbB/G?=
 =?us-ascii?Q?xoct7T4aAZ0YWFE7uS+KmxKZ/jww0SvPNdd6uKx8unmrloBbskYL7OiwmIYu?=
 =?us-ascii?Q?h1urJyYq9bi3UVJDXSmvgstIsEnjcO25sfBHsHyXFegMt+De251ven0MPo5U?=
 =?us-ascii?Q?vx+bKaRY/CTYveUNdujahy28y3VOiGn9aHpgJ+yejkGUch4AlPo1fMcINynY?=
 =?us-ascii?Q?Iztzw5BGGqb0Xq/sN0P/wtMqLzoswyg+3e5yO1LbJYjcBcT1Vj/IbEWvnUHb?=
 =?us-ascii?Q?rsOdrwNOe5tkX2f0AIVvRr9rJCJjlq3F1KBbAxEly/SK9F5eeP4fqkNmMdjc?=
 =?us-ascii?Q?5LImzFto0xVHmPKPUdXur6wW5Uiv1Pe87qpT0oZw6mw+utNQGRW3/DypL8T+?=
 =?us-ascii?Q?c7FAYDNweLX6jYteBcudkvTbd+rYFmiMngvtg3hGAt4CriO2DH4SM5GG+kL8?=
 =?us-ascii?Q?6FA4I+3QYpyW43rakcHQgHD/kgQ7cx41BulboZML2OtDVD6PCNBD/bYvc+ml?=
 =?us-ascii?Q?o0GLwoxP5baO1skDQphYsbYbT+4K2DlVA1X8eut3gprxQ/j/GQXAUMPyvsZ2?=
 =?us-ascii?Q?u91RLkPKhUUdFWBL18YcN0ODWzZnKgVk0iPTm8KkbU1q5KeqbFZCi6UvXPq4?=
 =?us-ascii?Q?gGm/nIqxike6rG8X3jnwYg3kFNMtnlQOI/AFfUFLM8GdZovOiTOejyY9D/MI?=
 =?us-ascii?Q?YeGVMyiCuieDdbT7iKdZQ0it1fq0YCd69WYMowUe+VoGIbr8tAOmqPJpQSwG?=
 =?us-ascii?Q?Gw=3D=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7d27ce05-7068-404d-187a-08da7b77daa0
X-MS-Exchange-CrossTenant-AuthSource: CO1PR10MB4468.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2022 08:59:52.8720
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hxyXyzPho+HDe8qFggmu1tFnvdULqc0G3McV/X3CwSO2xmHBuRpeUbWR3HgJVoojzODbr1LBlQNUA6Yei4aZvA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR10MB2744
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.883,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-08-11_04,2022-08-10_01,2022-06-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 adultscore=0
 mlxlogscore=999 mlxscore=0 bulkscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2207270000
 definitions=main-2208110025
X-Proofpoint-GUID: I5rzd45phqQAHhlue27uqgBrxxq93oWo
X-Proofpoint-ORIG-GUID: I5rzd45phqQAHhlue27uqgBrxxq93oWo
X-Original-Sender: imran.f.khan@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=A9sIssYt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=LME0GOPd;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Changes since v1:
 - Remove RFC tag

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220811085938.2506536-1-imran.f.khan%40oracle.com.
