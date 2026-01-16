Return-Path: <kasan-dev+bncBC37BC7E2QERB7PVU7FQMGQE7KWXZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C35D7D2E39B
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 09:46:55 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-6610d312bc3sf5448002eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 00:46:55 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768553214; cv=pass;
        d=google.com; s=arc-20240605;
        b=UtcKkI/dlQH/tt5BXY5joTxuVkrFpMAwN/26036+Fvvzjwx72jqeGhsP/nhj9spQgi
         Ml0MIRt0rejbz8HjfANNsjXotUQgFjNZxwny8R6/MrNRGGm4YEEGYoFFWJINeW6w6e33
         /KgYNJ04J3fHT2PYpgUtLbvTJBDjYiiCtClCCxMg4xd0toJeWsMa0Eioo1gjPNHufPI/
         nyYzJyfh1iYKrDIMXxFQAr/pGQWjlbFZt/HaPgzhfQsvRnii9C+AvNKXwSiyVbTzO/3w
         OihTvI85A5ThRYiFe6kDkweRuQVNhTC2nd4AC2uMH2y3He1S+AHL7Pyb887IIYSidOv9
         z76w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lJdhSWMuHj1CvqUUY441pHPRA9fUxQm3EGAUnvYvvko=;
        fh=AyXeycDuoNvXac2Ou6F5E+SqECYDFSftLdq726j3PGU=;
        b=OURbf38GwPAPp5VOzmCdNGAfz3PyHTwroilTqXEKm3UYtKJG7HYDessOtUNBcfeBnl
         Bhimx+IwzYXBiB4F9YoBNFq1iG1mKBEKBc5YneRBvNdKDkAHZXG7d9P+qDBdpKim9Vf3
         xFTYt9B27i6hk7b+SNEPezc/ul4bA4HPqBd60M5/MgdW4XxK2eTXGu7lHQG2LIjhmWu3
         TY9M4Qt1Uo4SP4w9akeHI7rnYpPwXEwJEuCW59vGZ7HiGYHH0lMRDutIeU6sw59ikj1z
         y8mKHUJ/YBoZDzmKT7kV19HCmoJEgR2ulG1Weyx1pt5/MNVRCvl+CAPyXvCWl942/b2L
         uetQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RdGhYwHS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dJBI0aZT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768553214; x=1769158014; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lJdhSWMuHj1CvqUUY441pHPRA9fUxQm3EGAUnvYvvko=;
        b=TbQZI6mr75gvlVDX16VRVLrPPEzThSIg+x7PrY9tGlkJFXmUIXOjB2C2QhKrDzURrd
         32v8eab/oScnzbALodigAM21C2KfBaETEEQxTGL0QYmADd8L0C5PWKUdB29/J2m7eJo0
         lQuQ1Yu6loNqyAxP9JdTburnEKh3J5XXudFSdZv4UYQbcwJVS067GI6J0IIXQHLLOKKi
         EGtbGyLDR/MdrDkAzZ9E4JMWYTi0z8Re3sY4ebjVK8N50df3dZPUBmIeVM4pA+o79Zhu
         Dgqk0Rvn3RYecFBG55bDH2ITV5/r9kNy+8V2FaAKPnC5Vjw/Cgs8W9zWMXTTZw9NKaXg
         NQwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768553214; x=1769158014;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lJdhSWMuHj1CvqUUY441pHPRA9fUxQm3EGAUnvYvvko=;
        b=jLDHZ135pHSGoCTUa7e2pYX25sNjReKRzQJsmr+3w2eiliLZZa9tCVvs+Us1osAgA9
         yoL6DKldAN997KdfF+Lz4qJu3P953giJ4ocF36SNMZYfmlU9tsRbIFGT9ujLGCR2bWUy
         yKOESqm2sXbZc9KCou8aoovkH2TARZtmNUkUno674ZSHKtNxzxAaLD2UkcwG78iw40TM
         WGv99y9QPyZi2TqcQvJ698Gc9FdFo7crwk7Lvb5zZVlSRojZMwbZ+uMta8kx25o2nkJZ
         CfRz7BDmnM9uy+mObOZ/RcK4zjS5rLAv24H+QP1B71yZrOQWEYesp3YF6eOpRnGlXmwl
         mL0A==
X-Forwarded-Encrypted: i=3; AJvYcCW11Vm6SZ8LFYC4GWeQ+vTq7k5BTI0UR4/bWjyWDyIGcvHAmfls1FmI2a6iMEmfIzamhvx0/Q==@lfdr.de
X-Gm-Message-State: AOJu0YzM583ug4dTmhRYR8T1sU9bG0pXUgPPcsGly5NV4VKWvu6vHoar
	26GJFQLWbYDWU3Y6bhtWXc4ihpWxtY6cZKwIlT2+vhrdIjPuT8gyJSAJ
X-Received: by 2002:a05:6820:3084:b0:659:9a49:8f62 with SMTP id 006d021491bc7-661179d83a6mr1032897eaf.39.1768553214215;
        Fri, 16 Jan 2026 00:46:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G0Uotm8XDSAUTcysm62yOPShekjUIkujF7T3MT9epC/w=="
Received: by 2002:a05:6820:c09a:10b0:65f:71be:f286 with SMTP id
 006d021491bc7-6610e3c3b12ls809486eaf.0.-pod-prod-01-us; Fri, 16 Jan 2026
 00:46:53 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVkcvPLdyS55MTSHQVV4KAOGjzyGAkhQ+R2mu/mOamt2YjYtn9+UcCpLQojjry0cFC2SQxeflpoOj8=@googlegroups.com
X-Received: by 2002:a05:6830:6f8c:b0:7c7:4f2:e15d with SMTP id 46e09a7af769-7cfded700c5mr1288685a34.16.1768553213322;
        Fri, 16 Jan 2026 00:46:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768553213; cv=pass;
        d=google.com; s=arc-20240605;
        b=O0jrisGrTSfWCCq+cCgiH5ZkXSPcYhsR6XJ7C5ZHI/ZCVsd00FKJEmUvjhE/ECKOvr
         gld9KJbZmZ3jLFhmAsx8Cjty+8adb8tVlB+pFekBAkJpmTEQ8ApW3fXVU1bpDM+ptDpt
         3tB3CDCwRgJDHLlj5g6k9l/NWW+kylSLv/YX0GUkx9+NAXTowVgxZFdj97XiRFmDLS/x
         JYoB/8EdyU3X1/pgo5xuNS6ok3tXGE1FsRCfEi8OSFBhyA2cz0+wag/6alDhjHr2CUQu
         nChtJeY1USrEA3PHCVpNGUr1n3Pn9+ECro+Rp8NCHaNXv3wTFBaAfuZTws/CNqrYHkd8
         cmGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=Jpg5f7dY/g7pcBQwW96MP76n/f5t1ExbGSpixHlo1BE=;
        fh=QhtactPCmB/lvSWG6dlThSec4OV2cygmpDMsaG29a9U=;
        b=gyII2UutQ2VPJfpH+0M4+bi4RBdgrKbRQr57AnD1RVcx9mjdcOFPs4Qy3amow92vK6
         j3GWT2gw+qzdlk0BkjwvKINl66qGIKRuIWs/LIhlNMUXp+iQXk3SWXjVo/3hEABxcuBw
         xuj58aAhZuoGNprHDt8Ndi7s2sK3LIzwLmLG6v+sZDjf72bIUPTq78es6lP8WTaNXCVR
         8DrqhQsknDi0CNaESRWh17b8xNWnpzrCnE7jxEfCxDYIg5brkh/guHhKqLRXqMPQFAI4
         yQJvkjmevFQHWT4b+DVnvo8jgzgwJ06OoQ2e/wR/+syIeiuFoYsVV1gLFFEVqgQ9Rjso
         4iHQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RdGhYwHS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dJBI0aZT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cfdf0cd472si90197a34.1.2026.01.16.00.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 00:46:53 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60FNNLvR1430046;
	Fri, 16 Jan 2026 08:46:49 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkre41nyj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 08:46:48 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60G84j8b003564;
	Fri, 16 Jan 2026 08:46:48 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012068.outbound.protection.outlook.com [52.101.48.68])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd7cmujc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 08:46:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PpvXVC63g0Z9kTgh8XCfwatFnY8gYXd04Y4NZudpgOwOg92NaCXxTECLyE1OFhFNjTM6E14V72SHw2O+Iznq9EPz8xE+6FDq+YRTs1Nb0Esy8kXdfmteNsiYbgF7eYvo1WnjhaGi3eOoVxk3VBAcWXrMhEU8eA86QtG2eFhuXmVx6VCDGxpRFkyGl4mBBnwiP+THmL7NwYMIDC+JFrbOvjj3Y9BR9vv5NmFYYiS4tZNRSGFOIMR4JJZ2I3H6wwzYM2Ihx+GR0wBJDC4uYIwMvtiEIlbgbneP8qfGbxyn/WSUcsCZtFIYXA9hkr0qQ4fSZjv2OAHB5uiRV3IefBrP+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Jpg5f7dY/g7pcBQwW96MP76n/f5t1ExbGSpixHlo1BE=;
 b=D0c/o6c25cNqh0lj7bH6ZHl3HHtOBxlUQbrFOa2VtGI+9Kt+h1MN9G0wew2EqrZwPtz6Rm+hy1FGJ6/mDAy2GvgMl25H73wEREmY/L4mChxBf9qKCoqApDlryVg4Ao0pVUxrUqFfhXex3DLs9ZaYWTRvLsMUiH+py/3a8nGLjrf5lsAI/gL0pH4PG2fGwhUdpZa6ycaGZI4F5AECyKDlSgTBrNsoh8NONC0MV8I9klbZYfntE2apgos8snys87wMAlveAvyPpQRou/VInn7xgt1iEJzl+vLx0VqV/75psuEq6KHUe2QlanuaeT/aFrumVk3oIkNJ0ibFt+WOt4Yemg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA4PR10MB8254.namprd10.prod.outlook.com (2603:10b6:208:568::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.4; Fri, 16 Jan
 2026 08:46:45 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.005; Fri, 16 Jan 2026
 08:46:45 +0000
Date: Fri, 16 Jan 2026 17:46:37 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 03/20] mm/slab: make caches with sheaves mergeable
Message-ID: <aWn67WZlfnqcWX46@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
 <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
 <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz>
X-ClientProxiedBy: SEWP216CA0024.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b6::6) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA4PR10MB8254:EE_
X-MS-Office365-Filtering-Correlation-Id: 9a5d2c0b-b904-42be-af54-08de54dbc6fb
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Ti9pNm9RamVnM0F4OGs5eksydk9TNFBEVlhWbDJTNU13WTRKM0tyUk1aaVFi?=
 =?utf-8?B?MFUwSThDQmY4K1RqRlMyUFFvMG1uUUEwc0pTb0JDQWVGTjJPNm1pMjdSTnAw?=
 =?utf-8?B?OWk2R0NhYmlseDdtVE81VXlORnJRVGVOcTBUVlhrdTFFaGdEdDdiRm8xTlky?=
 =?utf-8?B?bFRvK3V1VzBSSjhKcHB4RDAvNkFhanIranRSelQyZDBmZjRvSytRVnRTQjRX?=
 =?utf-8?B?MXFSWWlnRXZ0SC8yc25zdll5ejY0ampISUlSRjBHU0VOQ3pCcVByU3hpMjlE?=
 =?utf-8?B?UzcrbDRETXIxSkJoUTR0TmdDYTl3ajZnYzBIWkpHUG1TbDUrcUpMTHRLWTRB?=
 =?utf-8?B?NGVOQ2xtMWRaajZyM3piWWp1VTZVY1pJN0NOajNkcndZaTZYTVRoYUFWd3JP?=
 =?utf-8?B?THVlWk84WU9aMXZqUUhQUnZEVCs1Y3BDOUVPL1FsNEV5RForMjJYM3g3OE9h?=
 =?utf-8?B?ZTdRWkIzN0pzQXJLVzVYVTVkSldyOFR0SW5aSE0rTjB2VXBhYlVMQW1MenhF?=
 =?utf-8?B?clRvS1JDbC9FakJpQU1DeVBBdXcwNWdxR2w4UWM5R1BSZUwza0RndTFxL3Ji?=
 =?utf-8?B?N2F1SmRTZnE5OHlEeFVxNHBMOXBvVkRiQ2gwemdoY0YvTlNEeDVCTUlKREpB?=
 =?utf-8?B?UUIxZ3lQWFZ5b0xwajNTSXo5WmwvcHNwNDcrYTdJMUs5Z1NEeEtYQ3Z4MnFC?=
 =?utf-8?B?YmxOUG1zKzI4UERINmtKYXltVm5zdStPVkMwUS9JTU5Vd0dUSjdrOTg1eWpG?=
 =?utf-8?B?clB6NXNxRVZuQk1sd1hqSXhMbG1rZXV1MzJkWTh5WmJSVndhUnBQNjFVaFRF?=
 =?utf-8?B?U0V2c1cvWHRtdDhycUcvbzdkRUJaR0RXejIyQklJNTE0U3AySkpxU0FWOFpz?=
 =?utf-8?B?MkoyOU54TGxDalBFZnJ3MWgvVGZvM1BDdTM0V1pNNnA2bUpkenZES3g3bUpF?=
 =?utf-8?B?SHQ4clVneHQ2S2p5S3JGZjQ1ZWVrb25XTy9kejZLaWZLR2lneHZJNjZQaEpJ?=
 =?utf-8?B?SDlFVjFGd1d1UWtmZ0ZoYnBRbVlScXlTSmwxNU1qdFNzazlzdEFqaUpneTgx?=
 =?utf-8?B?OVMzbXFpMisxd3lUbzFZNDVWYityOWtJUSswK0dwRE9VamxnZkxIK0Vpbkh0?=
 =?utf-8?B?emVJRjdOVWxsMjMwa2JXQ1FpSWlIc21VLytybG9FQkdDV1NXVkNhdGFCN0tl?=
 =?utf-8?B?enRGdU9tM0R2Z3I4NFcwcHpsSkJMRWN1NExYWUpRQTRGN1F6WWVaSWltbTE2?=
 =?utf-8?B?WnhhQlllcCs4bmlzbDlBczJ6dzJQb200azZqL0dKT1hySWxRMlJiNWJKT2xD?=
 =?utf-8?B?LzVkenZWZjJhMlZMTkhJV2xxbXJ5dkxpM1hjQnBwNzVYaFd3SGNzTWRmRTdn?=
 =?utf-8?B?cmhZWmpjVEJzT1NFcVQ3d3NTNzlzRjl3bXpBYUVWYjk3MWZPNmlUN0xYOFpm?=
 =?utf-8?B?VFJsdG5xSE0xU3BvaWJrWWRESXY0cWNRcVFjOVU3RW1sOVNvcDhBQ0dRaFA1?=
 =?utf-8?B?NmVTclUvQjRoVEZNVk9lNXZLNmtMeVZ1cDVEMXBMTDJzdVZrTXJoUlJ4b0NK?=
 =?utf-8?B?eXBoKzNDRjljMlFkUlFGUC92WGlERmxQb0dBejdHQjBwMzRnNDNVV3FMRmZX?=
 =?utf-8?B?cEY3TWhhNHdENGVBanJJZDJUaTlhUmhrYVZ6alJIazFib0l2alNka2FRWFZq?=
 =?utf-8?B?RzQ0anlCaHRSOUxaR01UTS9VVzY2QStYZmd3WUlraFR4RVdvMjhxTCtNaExR?=
 =?utf-8?B?Z3FvWHlWN0RTQnFFZnFWUjdhbmJUeTk0cXI5U1FjaDBxcmd4a3JVbWd2VXRH?=
 =?utf-8?B?MVAyelQ2S0JFWFhSRFV5bFU4ZWxqcGRRa1lOeFl2QmtlamsxdGFwVkc2UVlO?=
 =?utf-8?B?eE4waGExOHJlTkF6YlA4VkNRMHVrUjljb0lCTFFmUUdqTlVhOFZGQlkwNU1X?=
 =?utf-8?B?a051OTAxV2pxc3RXMlVSc0p5SXNxVlhiNnM5TzRNR3FNOUN3UGtLUFRZT3J4?=
 =?utf-8?B?T2dwdTFEdTlOajdRMmozL05mNnlMNG9yZU4zL1hORVQ1L0cwTXFNNzJVV1M2?=
 =?utf-8?B?bzBLTnFHMElsazhGU0F2ZzV0SmdsbHZLNGF3WnFrekFEbmF0dWM2MU52dmhC?=
 =?utf-8?Q?x6yw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?ZWxqTUZoV1dLZ2g1Y1VXNVh0WWJlQXZGLzNBbkFmUFhvTXQ0S2xXMW13ZzNp?=
 =?utf-8?B?Ym1BTXNhbEJKVy9IUXRrQWV1WHhGZWRjZi8wRmEyT3JRN2xnazlrZmFjZS9p?=
 =?utf-8?B?Q0plOHdPVFE5KzM1eElaZU8xTm44Nld0NFd0eHVNOVRCTFoyeEJoN254TE9C?=
 =?utf-8?B?NlVWYzcvZVJWSVZTeVd1OWdwV2lVbDVBckI0UU9DUWFzZDlNZTFPQ0loR21L?=
 =?utf-8?B?TTFsd3E1dDhXM2tMMjZmT0lXNkNBZFQ1NG9HN2RyRUJFZEpmaEwvMW5sOVNl?=
 =?utf-8?B?MWhwcVltdzYwWVFsTldMU0ZzSmlvdkxzQWdnY255ckFraU1yb1ZwL2RXbDlB?=
 =?utf-8?B?WUcva21sTTdXQ3p1cmlFZUlQcEhybGlUeTBMZGJUMC9TbzkwSmtqRFlsbXhF?=
 =?utf-8?B?Mk5DQVBwbkpxMEp2NFR2QTZiUUl5clF5ZWR5UFBwMDVWYzBuRys4U003djBW?=
 =?utf-8?B?R1QxQlZLWFVoM3J6bHpjN05IemlxU0VrSGhGVjRYMGRCMlZiNnVvZ3htL2xi?=
 =?utf-8?B?OUhiQ3hrYmxsdnJ4M0hBYlZSWm0zT3Q5UHpwZjJDRTdlWGxDNEdvdU13eEx3?=
 =?utf-8?B?S1k3cGR3UlM3cFBuMlAvSFFQZUhoSDBacFN4ZWZyNW9DeG1XZ2VxMVFoTDJi?=
 =?utf-8?B?Mnh5N0o1WlF1Zlh1eHlTeVY2RDJmcDdhaHB3ZS9nZFRQVnlhTkJieG42N0o0?=
 =?utf-8?B?UDEyazQvenBidnUySXhXQ3RiRVhCYmJ0UnBGdHROdTNHRzNGaDN0MTBJWnNE?=
 =?utf-8?B?VTF0NjlOTmJpSEZjMEc4WGNoWk5RSmNpb1dtb3BaZUZSOVlBekpYQU5VRGNx?=
 =?utf-8?B?VFRFeUlQMHhseFpmWEhTTTkwNDFxNzR6ekdMbklIZnVlbkh6ek1lcHFwNVR0?=
 =?utf-8?B?MHJjL2VhcWxkaWo5Vzg5QTJZd0YyNTJ1dkdWVktkSGMxUzlkOTYvenZ2eUF6?=
 =?utf-8?B?bHcvb0h2RFFuQ0ZUSnBCMTdsUFA4QU5rZ2hwNTRnajlyYUZzSFNXc0JDak1D?=
 =?utf-8?B?ZHp6NzBBZm1yZVk3cWZDWHkvT3dNdWJtVytiM2psMDZCZ1hvUGhTTTh5NjRo?=
 =?utf-8?B?S20zNTNmVGNuWGxmLzFhS1p0WWM5RmdqQ2VpTVV6c1NTTWpCSTBVbzlDSGZ2?=
 =?utf-8?B?bFZ2M2ZRbE9pU0JENC9LTUZmQlhQTWJINjd0V1czaHFxSG1hN2I3VnR5ZGxD?=
 =?utf-8?B?M2J2Zk04bHUvUmdDUzZzelMyRnlidUhqK0ZVdkVCdm1oMG4za21iWCtmTzll?=
 =?utf-8?B?QlZJY2pyanRlQU5lV2ZuWG16Sk9XNFdyVVRBR3p3K2RKS1Jva2lCQU42aEhM?=
 =?utf-8?B?UlN4NEtveGFTMXRkTlBkQUtmMDR0UW5oVzRsQkYyY2ttZ2VYaVdrNUlSU1VJ?=
 =?utf-8?B?cnFiY2puK05IR0RpbmM0ajI2c01XWHQ2TmpNOWdvY25wWjgvVkpWblpBMkVX?=
 =?utf-8?B?MGs0VVFyajVJYnl3cDVjQ0ZPZWw3cmFoWVBWVCtaQWZlLy9OaWUrSk9rMXJ1?=
 =?utf-8?B?aWFaUTl1SmtUMGhCRXl2ZDdnVVhqbjhxck9hbG1CcnJmSjNxV0wzdGVmWC9P?=
 =?utf-8?B?U2ZYYnVjbE1SNnRGdTBzOHNHZUd4ZlZRdCt2RnkwSXorOEtMaE1rR0tRVjNM?=
 =?utf-8?B?aXlrQmtZRmt5ZjlZcFBLLytiNU5BMjNLUHpNeXMzUkJmbWZIU2NOZkppSUVL?=
 =?utf-8?B?ekgvc3Q1aUZKUXR1Q0lwVVZqdjUwNk15c3c1MWg4MDRTdHdHNjV3VjVkaXd0?=
 =?utf-8?B?QXpUOTVleFdNYW9qRWNPUUFJZnZBTDJBdERodmsvc3FoejR3QTQ1b1IrcFpq?=
 =?utf-8?B?T3NGZktvOXFESUJRcEZ0NWZHSHF5ck5kMFVQaVhvczRZcDdVaTRpNDJDck92?=
 =?utf-8?B?NGdybk0yZTJoVUlya3ZkMG5qVmdkY1RlZ25pcmtleWxGbG5EaWh6TklNZjdF?=
 =?utf-8?B?SHRhQklUeXVqMDh1NTQ0WXNqVXVjZHVvbCtYNGM1TEQySDhMVTN5cUwzMy9m?=
 =?utf-8?B?SlpHSmE1cnJlQmprdHZBeWJsZytrY2lrMnhqQVdhcGxxcVR4WVlkcE51YjFN?=
 =?utf-8?B?TUlhNGI2aUNUUXo1U1lsei9SZkxjYjJJakdKWXJTUFNaNHhXZDNxa3RBWWtS?=
 =?utf-8?B?OWcvRnl3Z0ZZdDlBQVZjd08vSTg2MCttUUZUdDVWZjZnS050SmFCTDVnVWxH?=
 =?utf-8?B?QU1oSzhibU5yM0tnK2V5a1IyL2JhaU1zWnNBaUNQR0RUY3dIMG55TGxiaXJL?=
 =?utf-8?B?RjNYL2FrNWR0OGJzdjdKNjhhQnlvbFZGUUUxN05hUW1TSEp6VDZFZE1LdFZh?=
 =?utf-8?B?SkFoTFBhTzBLUGhEckNSRGhiMit3OXZoc1hmcEZ3cjdwR2N6Y0Vndz09?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: QYTT7Jf02uolCswBsgrowkCKhjZ8a450NxKM2Ihy9oUT8G7EEdgpVaMeBP8o6iZdWC7mFpUj+cCyvpeUE80bLXNamvHpGosccbDnhd61MN+hlHpZ2VG898bZqXcBmZRqvxevWQKng/vrh1tLfI5z06SKLLBsLwS13Fny9JrBzE5exowGPR+eO7UhNqzOPsKA3Vla1rWCuGawdw/8V/KNXCz7p5V5EWnNT+xDy4MZ3+oa5Wxy3v146/OExeJgVMK1SLELIuvInZ9fGCU1MYbIG2OZTel9KncXO4tvBqjK86CRLr/oQEoG3cYOBPie21Cxdzs4ISP11tLY+/aEmiAZUQgbbFzt+q70uIV8HoMJXFNhjq+jWjxsGmJkiSDpIyTrpMKW+VC4hHBEfOO2tM/ipw5fzWdIefvcIK9hwpMYZ4QaNZBvWUwI1VwmmRv9oRbscW7EzqbVWY9lih2yQxujwZZM3wWCGATsTOvPlD8gKLSYrCsI6Ou4PS6T6nCHw5TCcu+iONgRH0LX4xUkrZ1GAnHTFvVhGTZlvpCQO0Ijc7h4WK0AS3PDL5muv+iVCKdxzkHxurujcz+XrVULiKEI8st+7pZnYxXfagM+sTtlOHE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9a5d2c0b-b904-42be-af54-08de54dbc6fb
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Jan 2026 08:46:44.8396
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rnSO8cNbCWdeO8UvCmG4hAeN4MxkXSOhIoW1zilzU186tN1I3sOhGo4LMsPdTVG3dVkph5OHSX5HIfyyyM/vRg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA4PR10MB8254
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-16_02,2026-01-15_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 phishscore=0
 mlxlogscore=814 adultscore=0 suspectscore=0 spamscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2512120000
 definitions=main-2601160063
X-Proofpoint-ORIG-GUID: AEhZB1PruTUrlwqCem9-0S1QjKvQJRA1
X-Authority-Analysis: v=2.4 cv=YKOSCBGx c=1 sm=1 tr=0 ts=6969faf9 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=IkcTkHD0fZMA:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=krPbT0nLj78Er1Qms1gA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE2MDA2MyBTYWx0ZWRfX1Il22JYnvUWe
 N5EqOGJd0bU3nYWWA+HUBzn2e7JWgLgHq66ZrHOLzvJ5+eadH0l5H0MNVhYWhGEsKVQsfkUO4vw
 wh9QzKzixc53WvfC5QI/wJGOfzUrWLRufjdS1F8etRL+reoANjGd2s3o81a2K2KXmkZ1cqAf2hL
 QKhI5MAq9jpeHo8O2HqSsmXGLVGyJ3n35Lu1B0g9CwqOnVWnBNAWCwu9uUcjA7n0yUmmP4rLvXT
 0uHkmt2vQODy1oYe1I20/EetHaHLo25XCOFuZ4OrbCeFbcm7f3RE7F0QRuAUGRGsIjMoZM06ZS0
 cdviAvTA5Qt3FoQc2vO//PuHAFXY/reweuZsISFtktoJ2YLf25kcf680U+xqdyZz5eN4un7NXZS
 x8yzFua/9pte8xoduj7wQL+lSaMmkbuQgtHJtvJGg2vlNl6eJ9VUHZTp+9I9M7wSXw7A9lwWJI4
 q5wTntPKHUppzQ6mkPw==
X-Proofpoint-GUID: AEhZB1PruTUrlwqCem9-0S1QjKvQJRA1
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=RdGhYwHS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=dJBI0aZT;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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

On Fri, Jan 16, 2026 at 08:24:02AM +0100, Vlastimil Babka wrote:
> On 1/16/26 01:22, Suren Baghdasaryan wrote:
> > On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >> @@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(const=
 char *name,
> >>         flags &=3D ~SLAB_DEBUG_FLAGS;
> >>  #endif
> >>
> >> +       /*
> >> +        * Caches with specific capacity are special enough. It's simp=
ler to
> >> +        * make them unmergeable.
> >> +        */
> >> +       if (args->sheaf_capacity)
> >> +               flags |=3D SLAB_NO_MERGE;
> >=20
> > So, this is very subtle and maybe not that important but the comment
> > for kmem_cache_args.sheaf_capacity claims "When slub_debug is enabled
> > for the cache, the sheaf_capacity argument is ignored.". With this
> > change this argument is not completely ignored anymore... It sets
> > SLAB_NO_MERGE even if slub_debug is enabled, doesn't it?
>=20
> True, but the various debug flags set by slub_debug also prevent merging =
so
> it doesn't change the outcome.

nit: except for slub_debug=3DF (SLAB_CONSISTENCY_CHECKS), since it doesn't
prevent merging (it's in SLAB_DEBUG_FLAGS but not in SLAB_NEVER_MERGE).

--=20
Cheers,
Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Wn67WZlfnqcWX46%40hyeyoo.
