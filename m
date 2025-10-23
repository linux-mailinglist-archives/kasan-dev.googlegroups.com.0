Return-Path: <kasan-dev+bncBC37BC7E2QERBJOV5DDQMGQEET3UM4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 33320C014EA
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:16:25 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-87bf4ed75besf15356906d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:16:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761225382; cv=pass;
        d=google.com; s=arc-20240605;
        b=de+8a+Z5R/DR5u7MbF0BMiIhPLI8FQgSwzC/XTto+c+aEjUdiyXcXsJmq8Qx+7BzLP
         On/5xi67oQgBm8+BqzpJZNMwneSkBFbPq9+dr7xraVm/qJPB4b4eh7+7/YZdWniTmguT
         t0JunDdoMTCtHzwvgPX7DgY6ot5tny49YFOpwQFaxCOk7gHln4AbKKdD7NxZoWCybVXK
         bCP4/02if741Q8Bpo4IatY7liaDg7nQmvcwhUxbUPcUCy7zaZuKlh6+6WWcbiVNHCwKC
         NxK71Xd48Kn2mkhExDL4wpGGcfw9Uz6UBAqvoAlHJy1rf1V5n10+GHmX+FJjYXaYhbtk
         lPVw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=ldTqAPudvzyy4CoNLANft0rah1P2GKc7c2a9YisUmvI=;
        fh=FOgD8ouNwFQzo+MNtiTje8hRh2tUtveIBsvvWwAgErs=;
        b=NSfHuBveWNO26mbk2CwJAK5oCVWv1OSFFFOIiRJbj+BiaJs9bjVOQPC1StgzrSV3sb
         lBD3D9MiQlyPKEo0JA+R6bguz0MIZ75SHDk3H5l46B0SLlKFkNaEY4ujqHweXToe1D2o
         ywiuFIzBcAe8r2jzXLgzuLCUaznzBvYahKbF1GVH21fO/urQubB3/CN7ssFqa09TE6Iz
         fyPuhsFBufVzWmVfaZ+Lfmf3QTPdOv+3/9/2XYarOB4QXJgt6umdUrcDmbuKX36LqCIF
         sZB/P2vhSr6wlmgDWkWAmBSqJiziyHLYXbQJSS/SeUYXB5SWdmkzahBkhgw9BxAerjor
         8u4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qhCtQU1G;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DxVl6Ffx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761225382; x=1761830182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ldTqAPudvzyy4CoNLANft0rah1P2GKc7c2a9YisUmvI=;
        b=sApQp1yBuwshrQ/hiuw22FrbR3Ny0fvnTfCqLoLnI6GzpGHx4b4LwqOrAWqUifmIWS
         QrKVGWKAcLHvu+nu9msGTxLFHVkLH5t4GN3sz6NmNJg0xawmoTt66yGxJrSkBwgTmex5
         QhD/Cn551aQqPuk+SIkFsODckTwB+43J0TxFIMy3Z4X+BZdLsC0wzzZl7jhcU2xhUHjg
         1S037txc8cZjYryf8jCCqjwetjNL/Q4Oibwjfuzi331gyE8Ldqak1iU6epIFzkdwnONJ
         K5kb+Qq60ch62fQyMjEu3Qk6CyBznv5awLFSyWt96g7Cjf/JotZObgGK8XlfFdYDtXOK
         Ia0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761225382; x=1761830182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ldTqAPudvzyy4CoNLANft0rah1P2GKc7c2a9YisUmvI=;
        b=WmgUvfuYJtIcmJlYfUDx2Wa27glYoklna9wjygjaYekzaT8ECY2JL6VCMwr5U/Slyp
         OUaiT6XTrOO8KegDXBHjD/TtgNtcV8m1W4eacgp52v3aoHpM2I0YNMNIhqSigtbsVpNp
         R84XJxAbD662XnHbIop6CASJ3/MUGYdL5YvodSxYSHw5CHdo2OmaRLM/P6LRkpfYlLSB
         O77Uz7qxELwgRyLssgO7M83jyPOlVOhCEZ6N0oEqigNqpqzDFL2/EPVizL6BzvapwtTg
         i0KSbg7v8zOIgAUMQV2RJeoL1GHCABCAwC1hFxOhmQfEK4yurI4yYA4zxDCDGaVhcbxs
         dFMg==
X-Forwarded-Encrypted: i=3; AJvYcCW/3IvzNHKKQk6G3i2eXUWxHpxNaN4i07E0rCcowo8jgCaa234B88YUGB29Fgxj11YC5CsswA==@lfdr.de
X-Gm-Message-State: AOJu0YyrQsFSYOgyjOlSWsEyWBvMT92mkB97arZ56a/4xSw/7612nVxT
	gaZhuMvEA8sb1DYrJ0qD7gs0A41CzF7BaiZ/c2kYOp75LBEAmZSeiFtb
X-Google-Smtp-Source: AGHT+IHOnzSimSF0BDombpQ5E2MM9vhZn531M8vYGR/lXiwrF3XZE7a+CvH46VRvEeqJ70lQiMrSSA==
X-Received: by 2002:a05:6214:406:b0:87c:1dbf:2c21 with SMTP id 6a1803df08f44-87c206314cfmr240652206d6.51.1761225382130;
        Thu, 23 Oct 2025 06:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z6CngQ9nUNxWIKjiCN9ovtVK19qW4gYpGohYHVOjAV4w=="
Received: by 2002:a05:6214:29e9:b0:78c:3f6:27af with SMTP id
 6a1803df08f44-87f9f665c3dls9287206d6.0.-pod-prod-05-us; Thu, 23 Oct 2025
 06:16:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWfqiDV98I/aEc4U0rMAngyz9rW86h7Njiu9pSqdL0XQENHmDeernfbEi6xmVd/NOeKVni2Dka6Dm0=@googlegroups.com
X-Received: by 2002:a05:6122:3d07:b0:543:53df:f3c with SMTP id 71dfb90a1353d-5564ee1dc21mr6639992e0c.2.1761225380791;
        Thu, 23 Oct 2025 06:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761225380; cv=pass;
        d=google.com; s=arc-20240605;
        b=ViY5PkYMawUXuE4+rm/5xVK6/VH9NJg5+s/s6/g7MBE6rpG5+dLbxAloJqqvAVUcZW
         b4VKRGvsVR/Jv3xw1uZe92nTtPG1K+O0ib1DEEtS9EATXnUNvU0MuXrgGHl5BUr2Ok9k
         rqT7muXK+DQLezRoE7iqTjIzVGkrxhDcftneeDOaSlIT5NAvnahOwInUpCXbinRYrEyl
         B6coT/GyRFWm7pwtSq3z+HiJ0JNKiLQItGXLckR1jGhdCMKFDz7wZMxcJxhRlEs6VOyB
         AbPpsRROxR74DmEN1ZxqZ+C2Q8qqVLiixxyqNhHGat4F0CEO3SuprKu9fXVTGIAjfbOh
         B+AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=bsQJuwD4CadX5nGc1HnQQSbObqQMv4ChtZaZKXVIvLY=;
        fh=7EXewbRkjLGFY7kwNHCznuJy6CXKSVidglOWl5IDdEY=;
        b=PvlMp47YWW3hkmg6652G7uhVphHsHJNpFb5B7u6O051xlaG2dvYCTo+ohXyA8rYUAx
         dPSaLEl2pCJYoq6Bs9OTINiqgnpCd/OEuZqUo7WiQNj7ZlJkTKMQy8fue+/fVLgk95oT
         h4nt0026FsWTrdp1mt2ayDEAI82IKu/iA+Cb1VamnPomhtnmG15Vbm6tewtT+l3N50uj
         xYvZT8t092ZH8F31Ym1nbMcznjbyPjxrYFgA7AEIw06yU6v4VRon5XjKwuy7N+WW4z3O
         rcBBW0AymcVu2HLWI9nK56YtdG9aFMWxr36M+efM5DVyF/oDLiDcoMwfVDMnh2QERsz6
         T6xA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qhCtQU1G;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DxVl6Ffx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-557bee0afe6si61260e0c.4.2025.10.23.06.16.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Oct 2025 06:16:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59NAtmUj016338;
	Thu, 23 Oct 2025 13:16:15 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2vw1qqu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 23 Oct 2025 13:16:14 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59NBlIpu035546;
	Thu, 23 Oct 2025 13:16:13 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013019.outbound.protection.outlook.com [40.107.201.19])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bfkgv5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 23 Oct 2025 13:16:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=FLjk5VHiN9eKD7kid6kjc2foV7jwFl/XJ/MveGvNnW9vu0AfwYgWR2B0OQ4FEMRleSAf7m0jbTeKLfwg7IfpMg2UDirZn4OwjvtWb5eE4/Ig3SjYTcwDMdqKEHeZPkyGumBpCgp/vXp0Hbc8/4WYPp+pFV2vMoLY4Ai5gUIa9pNNMmzF9abzDT3AIlHVA70g9ak/lUuT9hnxBeabAcYA8aXoJcmtYItOeKB5Qf1EWTX1Z3MVwUGYc44LQXoTBqtd1SyQCH0QtMkORBeVKK7ucxFpMcMsJ+p5rsuwYQGW2NTQtZ/P3U8eoO6ZDhhOnu/9Ey+L0ABkTztNEf4+LlOsCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bsQJuwD4CadX5nGc1HnQQSbObqQMv4ChtZaZKXVIvLY=;
 b=fKeCt7He7qcCKQ6FhGcrZhi0qBh+Uk2fbbvFfuAGf9gt7Ba1XKXcK/qLw/jF7xF0sKvI3Vf+KfkOpIk9A9OQb+WQQta0hbuSZEzDzbfUz9ILd2ExJyEYs2GBf3dCbrfi+pe+DFR7avm9uax4ygFNugxW3jImptHsBXq3z/2iswl0fQRRNB0y7PUMLQU5iA4TwGh5yT7dubEIEx26x4s4q1alH036ZhJ3EI4TJd/w1fouaoLDzu/dvCs/ICaLZYf4D4pEV7HN6aJUpcJrsumujteUpWfmVo7Rdmizb5cWDyOr0ByFjvPosX0tk7stJ8S6d8QceyHvZwNnNCDVSVSvcQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB7338.namprd10.prod.outlook.com (2603:10b6:930:7e::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.13; Thu, 23 Oct
 2025 13:16:10 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9253.011; Thu, 23 Oct 2025
 13:16:10 +0000
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>,
        Alexander Potapenko <glider@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Harry Yoo <harry.yoo@oracle.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Feng Tang <feng.79.tang@gmail.com>, Christoph Lameter <cl@gentwo.org>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        stable@vger.kernel.org
Subject: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
Date: Thu, 23 Oct 2025 22:16:00 +0900
Message-ID: <20251023131600.1103431-1-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SEWP216CA0096.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2bf::12) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB7338:EE_
X-MS-Office365-Filtering-Correlation-Id: 849c520d-f462-4997-d595-08de12365527
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dDn77kUyEIHxkowc+lLN4w0/X3fDtXIHR2164q9+sAHL0y17Ac/jkefM0brM?=
 =?us-ascii?Q?0Nal3PCrJ1XYmn+lmB5DBm9/baVxJvwYeaRP7WSIF2VpvUC2fMXK7gMRhVgS?=
 =?us-ascii?Q?Pcft0xod9pNHOHkIT0Jxa54+RHtV8uw3zX/y70P0/+plFZ0dDVJuasGOtH7O?=
 =?us-ascii?Q?erugiPDeqnNj3fRShb+t87Vj8gUxv7nnTjNRgC88gNYCOYPBJ//Ve6d3Khyp?=
 =?us-ascii?Q?oCAvH7l1Vh2Lxfgd6Te8j95tvtk2idYN+ai/wE8B5mg6iv+x2XRstjkV1WEc?=
 =?us-ascii?Q?Nh3apDAzw/pKvKLC0HW1tjNHDwZG+O1pD0fEyEcC6de4gnrNuyiJXxnriQ7r?=
 =?us-ascii?Q?ysRf8o4k4LMiAF/GnO5q851bHjT1g+1fdV0ZJouT8GnqLKq8s9r4gGDWimBu?=
 =?us-ascii?Q?c/9BCAfGRVxwyCMs6hSWfAt0qPRiF8i4tsMUrM/Ltj0XuVdMD7eH3J9woDi+?=
 =?us-ascii?Q?HyEok895PTE6W0WQMtzT5wwmSq4pVAtammzbPa7R8bzK08fk+8pWQ4M1ugX+?=
 =?us-ascii?Q?xZvQN0G3jrBOfsd1PvNza/7kKp7uCR8J7NygrCsDhflsaVQ6QLmoVux1acGC?=
 =?us-ascii?Q?+BynNfH1dy6MXF1zU4zx1Vk+XCdGGg4MEhWzwRwCm0I2iefwOjyWPrSO115O?=
 =?us-ascii?Q?q0SwsoHltKVyVBddHRl0D6+EiBLMcez/8Kzm7jAidIsPsisABIweWv3Z4Gn5?=
 =?us-ascii?Q?cS5WAGkqKU8tdNGbOK3FSr2ycJC3PkUz+WS6aW3IDKbO3qpVx4S7+1izHAtK?=
 =?us-ascii?Q?u+pK66Lfmc2dxD5rS+lar2cDKr5d75Mek+VpcXqZ+iJhqGVRdpbHcTdyBHdM?=
 =?us-ascii?Q?zSqHMDTjCFPROYJziA58hYyoZT5WTviLemCFk/W/rdPu1vD5LveUfen0rUIo?=
 =?us-ascii?Q?/hq4nAGWnlVcqkmLKkns24llTwzcpfH0fDFJ/RDQih+1CSyf9bhrH4QTSUdx?=
 =?us-ascii?Q?PActAVK6F4CtpMSckT8Is7rplCcG09AMa58AgsobXc3KsNTouyNIhbq2WONi?=
 =?us-ascii?Q?5fnFFWlidvjtQEH1V80kN+VcmBNVddKl3usVLx3+vXtLYS0xw9rR70Z9kvU2?=
 =?us-ascii?Q?SrevCKoLbzbAbnlAsYu3sKsC8YZ8Z2GDcM1DDoNiYdY8JK5M4kLqFLaUUmvl?=
 =?us-ascii?Q?QTkBYhNMuszhuIbyqPtS/5VWSdUR7yDk6HhiN5rccWZ9KMEOLiJkO0j6eUvI?=
 =?us-ascii?Q?kr0zaVenwLKKVq+uQZpI4eGUwLvTxq+526NX6rQZGNhORxra+ZcVqm5yMAj6?=
 =?us-ascii?Q?0Ou4iv6vzJaziE5Zriv1zYUVf5tKO5JymRI+3F51TG/MnFnW6T2eZRuUVMrb?=
 =?us-ascii?Q?mDRQjiu4ruWwd8i7TYqiBLvXa3yQMnEEyC545CDOSyy3SzKMZx9qflYlu4HO?=
 =?us-ascii?Q?G317LZhyqEVCdIh6+N20RP8cn2qPI76mBb8XerVnYl0HbDZs6WncVCKde272?=
 =?us-ascii?Q?FBSzW0gzMZ0/MpMyJ3HdNcdQGYkbfSzN?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?etakS2lHSCox4SVGlZeCb6nY70IndMITc98CQYjKbM81+AsehGLSM3FNBCav?=
 =?us-ascii?Q?+UVWYgacM7UuNu6HCwNzpwhEGWXFDEFdPi/ksDfho3If8m9FJaGfub7RPIqD?=
 =?us-ascii?Q?VBBoLAxZDo9kPXtRaSxKsvSr/HWeiaQpkWydYdry4M0fIYPwrhxGRYEUFzsd?=
 =?us-ascii?Q?DEo5E3bcNz3LZMEo5J/Xi5cXrqvBB5PnANPU4D9HMwElmkMScNjFTP2z/Z3J?=
 =?us-ascii?Q?hpjU5u386x9v8TrCQEpzf6VFV5aNBIKlYsc7evA9bs8HGOgJqg3ZqCY9v94u?=
 =?us-ascii?Q?7GGFJZFDmkLa2omK1NEUUOvCG4nnYIRcfFbx12GcOdfq1QB3lxDpq4Gg1Sj5?=
 =?us-ascii?Q?Qzdh8C17JXduyOHz78vA59uPNFksvkZM2zBSnw8oy2efW8yhrKx0zruwdSdU?=
 =?us-ascii?Q?rhPeSRUEVWlA6c1yqxNPiSFSOYO2NYckjqXoVJ7o6xTAL4gKgfu7PvoShNVC?=
 =?us-ascii?Q?4MWm2z2d0TwseHLw152Y+AcjLs3YNHBLJdcph14cA/sFX8WdYkldAX5BON7K?=
 =?us-ascii?Q?/fLG9EFhKL9LofhpULAKhpkQLrCD3pP42+KpeJ6gphE/+V0D1XZXNGOGGKaT?=
 =?us-ascii?Q?/rk8gb3eh6fqNlqBg3VW4xndMh1gwNyQGE3KZ+NKicb0NQHOv4Q9dhifWsm9?=
 =?us-ascii?Q?r9Ii/D1wQMfuV74I3LUSOW8Y/kpjeSIrwbHHtpBk0OueFO9/qd5f7QNBXRpo?=
 =?us-ascii?Q?a4k2jaDHnGrpouJp+uVe76Ys/IObeRiYLL0cO5ak+SCtA3AIhMgSOMN2LUNs?=
 =?us-ascii?Q?MsgQxIvEkrd9OV9aYapCrt0Bk4c2NdLzek/zqZS7c0Bu9JT1pXMA0wDtkE4N?=
 =?us-ascii?Q?yJqbh5U45iGTJjKKwqj62BQYw4o5H69jfRkKkoNi40fx/UDNwteVJD90fL25?=
 =?us-ascii?Q?HIhRxgee379nxeD0MqHyu6AKQ55a4i+gVQrWXcJGvLhHr5+bqld+d2F6nPRg?=
 =?us-ascii?Q?yeuerXNSZP1riDLNa4ESscEoPrIpdkcPGtAomyCnPBu4q85ZBBFaMLVzpuNV?=
 =?us-ascii?Q?sq1sLUoxqVyfCAzlu7kpvq5+qJIE0ZYXVT/Fh8e4VOUc/D5rt2uDfDFnc2j6?=
 =?us-ascii?Q?BtyESDKZYoPicmA7qGXXMqUvbXvxV3QHamNf970dx7fYzMvSapb0rgbmhyYO?=
 =?us-ascii?Q?++KRmwnfTiJnzShpi1e5twqUH6ZysGFeULAxhJv8ABl2R2xCknisaXA2Rn3E?=
 =?us-ascii?Q?PUkP7GGRpzkFmq0OXHuBO6m+1m43qdhNkxhvhIZSI/XBoAPSpzHKBdoyj3Vp?=
 =?us-ascii?Q?xAwizrMEIi9Lltf6KDAN4Do581wg2W1IkAT0WaJXhHQxlu5WcW23eLLnZTcx?=
 =?us-ascii?Q?f8v05hpfWhtmKCOF1awX2YxEtxx7rzoFXtc0/PZy0iCMHZhUw0iRuQl/hcJs?=
 =?us-ascii?Q?g2FUBZuKuMAxsv1DDlQtJj+EyEETsdoO49nVuaY2yfI6JrK2Uc7/ZeNlCKNt?=
 =?us-ascii?Q?7s8OhGPX2zAzry2q9iTy6MkXdpP5KiKr7rc9DDYEyYseYSY63lnZBOf8xRew?=
 =?us-ascii?Q?bbVtbtZV33G7l+fm6JGGQ7dPbWdRSc2QlIRiqW7jgfiby851qILXqjjVldyX?=
 =?us-ascii?Q?5rt+bGzivcCbcqkd1Ur1WjKMxd/INJu9glnSAGD4?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: A5qSIMgJj4BhO16dP1J8VzfmqJmXOEIt1lC7ywpWt+D3hpYn2rfVC4F1TwDuhqnzYlrVE1m8hrjE7rND3k39WUouBg2/qwBffdigk4kxeGShkBnzMIDZWIx6I2b0BoTtdh3ijujKJjiB68PwAtfd5w5HSSCzqM+wmBK7PUEOewuqsYpOAon4/ahQu8m2OLt1S4EaQkpIRviCNDYKXtb5G+7BVb6uTyD2+Gi+Xfs9sHWJ6CIKBVtOh7nn9mK6/LvH7QWSbU/7rXNy2d8eGp88PkbjS3jP4xsKMUnQ/RZKljA9C5qrpZYNqOWB/Z/CFWDhB4ULLrE7BiPzXgi27a39QouZsDEdIFUoV0DnfyhIP+C77yiLctGfxJqcu85+3geoanwap4ipznyD5+Obb5YtqR1yLRat02u0eyB69NVh277/a48cMxPVYmX8iH7FY06pQRwcpPFGRC8EqarCdN6yS2kM/vl3pboR4FOGeQqPGXu1B8RdfPWqH6uH4hfCkGc5HFysPvgYZRxGc+Ujj5hJzHLQFEOV2Ao61GywXfSC2L1BBcvLI/C1m94LlyqEff/FRMVkpwwv7Zd19X2kjQclq9dLq/QqIiNx0a8FDNzOil0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 849c520d-f462-4997-d595-08de12365527
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Oct 2025 13:16:10.2882
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VWWWKNQBXexuf9ohPUnsaSSgmPbF1vusWEmKrvWubEdueQq4zcyKJ/w82JrgbD0etxyPFJ4jVrCIDn5SdcsJ9g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB7338
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-23_01,2025-10-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 malwarescore=0
 adultscore=0 bulkscore=0 spamscore=0 suspectscore=0 mlxscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510230121
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfX/AkoSYxgUNXQ
 xwAF24cGB9axR9QtrIkC10sy+//+6z0AUPP9YXGbM6CSBFRrwRuqPQoDmM7sd6qHETNMgvWC0+6
 BixbWU26yv9Elo60rcy+P8IgcFmW/l34BKP5VQFLWS+63EAVJ7CX7ffA/ec7Kq2z8c0VS1sUYES
 ME3svANmR5VHaq/I8XdJF11qt7tL3CRysmOhTIveHhEA3jd6HT6+yVS2r8cj+A4mmtqnG2PvZJZ
 /eHt7iotuUPCDvfl66tVPlAlh2mwrtMSS8MiLIpoCbzagTPXgFsR5nd6lhsXPdQO/DR4tZKjl/1
 KQIU0HmztkVGEzfWQvUouqEmLm4VAoMZ/qQRUje4H7I0bNQo5BZVqPmAvCXrUsMgJ9jsEVkkBNR
 oOxGiBKAzLxpoWcOnKXJ8Fv7Q49yZ9L6doF2GNwf1FAThRdKnk8=
X-Proofpoint-ORIG-GUID: EgyMXjmvwlQscQ3okzYNcY25jZPjN2P0
X-Proofpoint-GUID: EgyMXjmvwlQscQ3okzYNcY25jZPjN2P0
X-Authority-Analysis: v=2.4 cv=FuwIPmrq c=1 sm=1 tr=0 ts=68fa2a9e b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8
 a=60bAUpEqyJ0hnt3RZ0MA:9 cc=ntf awl=host:12091
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=qhCtQU1G;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DxVl6Ffx;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

When the SLAB_STORE_USER debug flag is used, any metadata placed after
the original kmalloc request size (orig_size) is not properly aligned
on 64-bit architectures because its type is unsigned int. When both KASAN
and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.

Because not all architectures support unaligned memory accesses,
ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
are aligned by adding __aligned(sizeof(unsigned long)).

For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
make clear that its size remains unsigned int but it must be aligned to
a word boundary. On 64-bit architectures, this reserves 8 bytes for
orig_size, which is acceptable since kmalloc's original request size
tracking is intended for debugging rather than production use.

Cc: <stable@vger.kernel.org>
Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
---
 mm/kasan/kasan.h |  4 ++--
 mm/slub.c        | 16 +++++++++++-----
 2 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..d4ea7ecc20c3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -265,7 +265,7 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
 	depot_stack_handle_t aux_stack[2];
-};
+} __aligned(sizeof(unsigned long));
 
 struct qlist_node {
 	struct qlist_node *next;
@@ -289,7 +289,7 @@ struct qlist_node {
 struct kasan_free_meta {
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
-};
+} __aligned(sizeof(unsigned long));
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/mm/slub.c b/mm/slub.c
index a585d0ac45d4..b921f91723c2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -344,7 +344,7 @@ struct track {
 	int cpu;		/* Was running on cpu */
 	int pid;		/* Pid context */
 	unsigned long when;	/* When did the operation occur */
-};
+} __aligned(sizeof(unsigned long));
 
 enum track_item { TRACK_ALLOC, TRACK_FREE };
 
@@ -1196,7 +1196,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
 		off += 2 * sizeof(struct track);
 
 	if (slub_debug_orig_size(s))
-		off += sizeof(unsigned int);
+		off += ALIGN(sizeof(unsigned int), sizeof(unsigned long));
 
 	off += kasan_metadata_size(s, false);
 
@@ -1392,7 +1392,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 		off += 2 * sizeof(struct track);
 
 		if (s->flags & SLAB_KMALLOC)
-			off += sizeof(unsigned int);
+			off += ALIGN(sizeof(unsigned int),
+				     sizeof(unsigned long));
 	}
 
 	off += kasan_metadata_size(s, false);
@@ -7820,9 +7821,14 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 		 */
 		size += 2 * sizeof(struct track);
 
-		/* Save the original kmalloc request size */
+		/*
+		 * Save the original kmalloc request size.
+		 * Although the request size is an unsigned int,
+		 * make sure that is aligned to word boundary.
+		 */
 		if (flags & SLAB_KMALLOC)
-			size += sizeof(unsigned int);
+			size += ALIGN(sizeof(unsigned int),
+				      sizeof(unsigned long));
 	}
 #endif
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023131600.1103431-1-harry.yoo%40oracle.com.
