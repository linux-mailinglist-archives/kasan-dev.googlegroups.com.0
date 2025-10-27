Return-Path: <kasan-dev+bncBC37BC7E2QERBHGB7XDQMGQEVKNMV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A4FE2C0D66E
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 13:07:58 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-431d8643856sf193998615ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 05:07:58 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761566877; cv=pass;
        d=google.com; s=arc-20240605;
        b=bdOlwHKOLFLUNqHd3ArY26/jcMwz1ex3CxfDv5VXzzJAqOUz0ciVQsd5Px2+EnDRJc
         Rm13Gt+8T/DzW6HBV8lY0IwFKv2VoSxTHzkzmBF8WTaeSQPevaQCsVy2qUSr7VEE/iJV
         f1Ds8KLfapC84450Fp9oafTy8Ek2R96ExlyQAmvUPXYQNrEV676dUehbnjqrRjhCp/H2
         55w0Y/S+AcPyes3qCU59xhM9VL9OsaMWUhuQgkPUW9RIMgT/1DwpyOmw0H7s54WbeZb5
         9v4hioqIZLnrzgUCqHNdKh/MSfytUzwVUThNYX8qjWTe/rYM40TBR8MoYRr1OQcEVnca
         62Ug==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8SOgTVZ2aeOl8wrc0Y2P+vC+ciRLZTYU99Z2PBd4nz4=;
        fh=MAh38qWgkz5NkcU2kF6BRPE80ez9oA83se3sxVxqkTM=;
        b=OaNcKx++1Bu9R6Yc0k+EQgE2j/jsuUIG26b5EsPh3qrh1LOS3b+KbUkG+zrlhXTy/Y
         87jpliIPBC5e/hLJmDDpoUA/SiM1PlzK0RfAhw0Hf17CpVFUlNCsKnPGVy5O3Qtr/r4q
         7GUDSVokvnK9m2tfnSE+yri4c2p0LUiJb8/S2FT5K307AhKOf+2n+opPQFUFCFfV9nIM
         UoSjWLbLqJIx2gie93YGwYyPJJShsPYuaohXaHckS9T6maosWldHcXa1EMbGDHOzf0wP
         nv1bdMa7SkeA+w/nBiCT1lQG0MNQ8GX4LDIoVSWoHkK+QxPnI4CIQ3/C2s1ExNCgc2kf
         zZ7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=SsQdJVOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UI2Nh5kt;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761566877; x=1762171677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8SOgTVZ2aeOl8wrc0Y2P+vC+ciRLZTYU99Z2PBd4nz4=;
        b=sJZNcZqa1Sm1XTvIaIX5iFdOsF4c+ybqsp0Z2YiIdYPIdje9FaQ0+OaVX4YozrKQq/
         QJC2AEqpm45JjUBBUkbJiVlT5Xf5NxQKD/OIlei5XOMcCqTYFIXoG5c2QON2ORkRB7ZH
         h0wpjWwIFmY0LDKJmiPJpLDGsGrTb7PdHS7v/5eLY6KHiS+KsUrHUfCBnaanWiJokT06
         DFUk3in30gIyilpQKsIjIbgDxPky4lSczrvIaI4YALDVyugU8hZ7wgvCbjJLW+lK0pWQ
         lRO7ArmTr704DV/DKsE7xoUjCE+AlRaYv7s1VD9NjP9Ta+6rg6wIFKkyWQZ9cILf7PHX
         aGEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761566877; x=1762171677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8SOgTVZ2aeOl8wrc0Y2P+vC+ciRLZTYU99Z2PBd4nz4=;
        b=s3MjTUtzBhx6TKNL492C3XTFIQtx6PgM3O+inO491uYfVj4JXaDO5btFMHqtnTMiIe
         Ks5d7t6h0T/v8o9JqQJeEfjD1j8rRRPUvQWDd11BoDHRpzxoC+9CuvASwtV/jONtIP+z
         pak06mc4eInpJcLXV3ELiYPlWpAczof2+4WclWC2BKLB35FVXsnbPllt8G+0y+PWCiPJ
         udZB8SxA9N5ah15bVsqBSr3gRoh/ovd1y8RsPLnanmL9zO96WyZMHMuy5DiQT+gGJ8Hv
         0J5ZY10FTRoTPNo0YfwLNFshBYxaJ3ZdA8qdoZSDKTiyG1pxcGQijC1JkGZU9lVwDbNw
         qkvA==
X-Forwarded-Encrypted: i=3; AJvYcCU7O5cAFvTEj3raJnC7cJOjeUR8hdJV8aG0LzbQ2Ogq+64sF0LFLn9pWEFbZq2UwES5n+PcHg==@lfdr.de
X-Gm-Message-State: AOJu0YwncKtuvphGW8z+gWLA7F3kwyVwUTv1qwgIfHY1UYqdxi4vVeBu
	bLcVgK7VESeC4xVIxvvuk4txgJ150XPz+/nd69bYcuVVWPF96q6mjOm/
X-Google-Smtp-Source: AGHT+IFWzCEWQFIa6fZYrCeXGhBvoXGQhe23rsrWaYx7ss1rJgeivSi8aARlcOMuB0fzJZn6JfT6BA==
X-Received: by 2002:a05:6e02:2289:b0:42b:2a51:f50a with SMTP id e9e14a558f8ab-431dc232994mr196799985ab.31.1761566876967;
        Mon, 27 Oct 2025 05:07:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z1C5MQCXfrgkfpMicswUwkRqiugdY9KuVBrgJtOTPf0Q=="
Received: by 2002:a05:6e02:3b88:b0:42f:2c8d:eb0a with SMTP id
 e9e14a558f8ab-431dbfa8e02ls17431245ab.0.-pod-prod-01-us; Mon, 27 Oct 2025
 05:07:56 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVbY7KTrG/7Ty2OEgd4+aED3oAbkJXNge3PdRe6JgrKfa1O3kodndzTHkuIaEVgUVxvSVIiSSEUO0Y=@googlegroups.com
X-Received: by 2002:a92:c263:0:b0:42e:2c30:285b with SMTP id e9e14a558f8ab-431dc1e2690mr165750545ab.20.1761566875982;
        Mon, 27 Oct 2025 05:07:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761566875; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZTUt48EekkbbhE9W7vFQ1JC+GknI2AelwN5kkFN1dW2o1POBM7n9gOi5ysm6Aa9/RS
         1nhz0RoDlKx1EiVB6SgluxNNAmFioPtRyBOi6FWeErOE9e1yRM/siLBgSFBtjp2w8FWw
         PT5HSa31zUr2TtzeikBWzbRWtM0bwu+xkzVLgSFMXJ34ReGhid6NQzatOuJ+tdfbmfkD
         SafmDUTO6R6iYqkM2aqW9cvKmuknhT5+y+yFOxW8/wYlu3y8bzw9xmJBvxfBBFvCscSz
         VQayaiTJYfgcF95BGaRGFCo05+yrVBqOTNyuda5/r3BLUx0sn1p34TRPmmb6HTeKk3Ar
         fm2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=E9mVtzrW90wEgF2/VwP4F4lDUbTCau0npQjtKqtdj3s=;
        fh=edAigfLCiDF0v+NTBEQGhY8KmcC2cmhGshDNFti1CgQ=;
        b=UNZednVXC6Urt4jCL0Vqy8/i/QiTRM1DYyVdacJSDTKsJDIAZ+oPhdUK4s5SW+WwHd
         +V87AREmDdxydixKahWgWl73pXv7bo7JaKAChbt09H05MJvZcIdh1cdw4SzHlEcSgtwX
         Do4uHCOzWAFzvKm99hGBAcq1Q8M2h6BqafPyX8XBNHy4M6Kc9c+bRZegGU8VHRtW6gt8
         yOCNSX9DwUPTYZ8qjFJXAjMTX5BlGMxxeMwRLkkaaGsA6/mi9B7fUM3Vj/1X9Jv1A9oj
         eiKHNV1CDwlrI/ek56HimBOmN07emE4NMqmAWsygW4hdypgtavtZZp67J57jLCgaucAl
         M8AQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=SsQdJVOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UI2Nh5kt;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5aec4a4b062si136311173.5.2025.10.27.05.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Oct 2025 05:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59RC3T5N008537;
	Mon, 27 Oct 2025 12:07:51 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a22x6rqky-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 12:07:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59RAkond015256;
	Mon, 27 Oct 2025 12:07:50 GMT
Received: from sj2pr03cu001.outbound.protection.outlook.com (mail-westusazon11012066.outbound.protection.outlook.com [52.101.43.66])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4a0n06pvr2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 12:07:50 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kc1mpBAkxcHNnsJWkqfB1HQ+zSCmntJSm68Owvxlwt7nTAzx+XqB+LvIZC5npkn+OcRAg31LzpazDvcjaHWhA6TIOX0aSkks20g6WLPbL82CiuGxhTfvqq+TRN0hVFMPcMTEMwHFxOPpAQnlrMByD17ghZvVCWt84ZLe6d/cXkg4jon8FziQLwSIDiobNAHo8l3LbH0NUneDFhV6+0WM6VfhrVlgzJ1UrP02+BNvPIyywy3LW1wOIzUCDXIN+70Uubb3TG3UIK4hQI5Q3X5Ox7AgBhLPHr3Fj2UOHbuTmw9cumONOqXZCgS3YBF2UVXNu4V13m7iSXWpo8nGu3e3Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=E9mVtzrW90wEgF2/VwP4F4lDUbTCau0npQjtKqtdj3s=;
 b=oDErs1brOU7WQGrXYISDjcWGa81E4NbFwWnwojwWvVe+uJPtUUhkLQufkBbEUzJ7lqgHzJ4lt90TZQKwT7n4KtEL+1aeBI0Qm5hPJlkdFi3h0HbYStKqrX/yBs9ZX2WfGEoGnLpBizSYwrZEjYurMjsr0XGegKsLFNrwCiK3Gf32XLs/fKmpOILWcHjiUA86KwyPZiKsPDeFIkMvUBtiPGnneEeo4EyYBUqOU5iF/mMUkttUcqCmUpygURImdbTLhe3izLG51o5nZ/Wn7fuspAySIChowAbNnyppVN6FJMUSFeW+9m9x/gGM+q0g5F97C4V3BQ1o20gjmLt6kd7p3w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CH3PR10MB7715.namprd10.prod.outlook.com (2603:10b6:610:1bd::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.18; Mon, 27 Oct
 2025 12:07:47 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9253.017; Mon, 27 Oct 2025
 12:07:47 +0000
Date: Mon, 27 Oct 2025 21:07:40 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>,
        Alexander Potapenko <glider@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Feng Tang <feng.79.tang@gmail.com>, Christoph Lameter <cl@gentwo.org>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
        Pedro Falcato <pfalcato@suse.de>, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, stable@vger.kernel.org
Subject: Re: [PATCH V2] mm/slab: ensure all metadata in slab object are
 word-aligned
Message-ID: <aP9gjJJ33Zzo9TyF@hyeyoo>
References: <20251027120028.228375-1-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251027120028.228375-1-harry.yoo@oracle.com>
X-ClientProxiedBy: SE2P216CA0153.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c1::9) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CH3PR10MB7715:EE_
X-MS-Office365-Filtering-Correlation-Id: 667c4b36-7506-4db6-7ed0-08de1551717e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ibSB4VW9CKV9+m4LgrD2vMipC869iJmPFLbOtYZMto9kKF+iCS/SZBp8CGCF?=
 =?us-ascii?Q?eCznqDiWMRv81++Wb3ro5kML3/HAi9QjrZWyD7VwxJt+NKmAcYWhpKh1SDom?=
 =?us-ascii?Q?EcfrHoAsCLaSiu3uW2O3sbrNKNVGRMx2S7nSUBebI6csgsOFVSoYKHR6Ya3+?=
 =?us-ascii?Q?iFYlyZflm07Yp36YbyE4BZA0cD6A5NZZu8vPBicDahgQd4LeS4uqW8mubJYj?=
 =?us-ascii?Q?MYO9Wg7oLSeCTv3/qs1/EARc8hPUAAfu8j5dm2bYfLjYfN16WG8IvbDuyp3Q?=
 =?us-ascii?Q?xmRnzKZpj44EdIp/TgLmfVGsX/xZHCacRxNriHs7bUvhcbbQkC+oUrrj4g2K?=
 =?us-ascii?Q?iVlcVjKysFKVFrpUDJCHS53AtKc9ciIQ6Uziqr9DmIduB+XEcHbfG5ByXXXv?=
 =?us-ascii?Q?yUQ8Di+lQ9mFm7OC/DE/HA17K8u6KDK8vL6mWSIOAmDqSRJFr1XtE1frkqUA?=
 =?us-ascii?Q?+ndM1AwOq2CP4FNzfDdrSrCADoTq6k0Hq9YPH2YDsBe1JRHVaNN38q2m2r+f?=
 =?us-ascii?Q?KXeFvksfxkrfkj3KX1+IH/ZGUHH9UVNjJqoiPefh59iG9aQbc3SZmlQm/ZyQ?=
 =?us-ascii?Q?6dXpBoUcyNWWiknnsSuABijlIYWfXFzSzN0RtTLT8/AHsjHaVncvA4rYS2tX?=
 =?us-ascii?Q?oofV/xeUJF8hD1oPKy0J2wVR8loE0AAjZ1Hc5q7N6X2907A9aTmHZUWTd+6n?=
 =?us-ascii?Q?sybnw2ela3QTILKBXBfO8OYjFNmKuRpp44sZjSdT75FrJKnMOb4idPLaxpP5?=
 =?us-ascii?Q?Xv1i0BUcmeCqCWDv45eqKXhzTyi86HAGSoMzZ901TIOx2AIP0oXnwL8j+XAF?=
 =?us-ascii?Q?y+j71MlNW1V3CCCraEskuc3v2A6DQbTG+XVPfug1y0ACZyArX8ZBlgRCPrsU?=
 =?us-ascii?Q?g+C2dLCRG1FjnAMJX0P7MvUELsswzC8RR2diF7ypdDdc2fyiUeDULS9GMT0L?=
 =?us-ascii?Q?3KIw7XWgUPOAtvjHuYmL8zHmonSS8mZZHr0yHS+BIcNmRhjBx3HFAqAoKoQE?=
 =?us-ascii?Q?UNm8GkyuAJ6EaEwmtwYvfWVDnDtIRAdDdyINqTsaYeF/QKBIy5d70Xmoxy3j?=
 =?us-ascii?Q?Pg9iIu+wHoCualQ6J9S+SZdGSMqhmoN+t0D6kBGZnuCHcainrVNXinl3uN+a?=
 =?us-ascii?Q?Ys+3YKYTpRpDuA3Kkp/8vJNdPIUDCfvIby39kkGx7rgbiGkEwrFk0kDz0hBt?=
 =?us-ascii?Q?cnSIt6UK/7vkTHBm5eeMbQFEyrUdcnlAFfnwRCWBrt1cg7VJ9fnv7Efz8zBJ?=
 =?us-ascii?Q?WboKakeX5lWZyDhua5QvGlyqhyj7Wnp/d0i3c2aL6IRxCwQGWbYeLFKSVVt1?=
 =?us-ascii?Q?NxQqmf+p6Tr5qVkxFZGeO5ACt06+u6x30f8C6KQBRlpoBW9ZRkTApfYAwBkR?=
 =?us-ascii?Q?WM64279QIvcXq6pdR7gZDYyMq+8tVQhEGLFacwJi+9bPNM3G42xYB9ei+YSY?=
 =?us-ascii?Q?ljPTeZqCHfdrR8RxqrkROz27f4a1bqn+?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?aNk/Zif2B3Uqz8TjjwSsXropOTy85iNTYzKJa/ShGbjW3mVL8nU6+MjlwQfC?=
 =?us-ascii?Q?fEuqBoL5e1eaQr+qLbjvz4jhevw6ZP3m/7+PEpiiApnKp53RlmNr1Fa19Zji?=
 =?us-ascii?Q?FmID6Qm2+0npZ7nmNtT4DwR33J9O4vNHW8jOQMsvtr+p/LB7uy8NsXOxS2zu?=
 =?us-ascii?Q?ZS+4MQJn3+V9L+kEJpOyVeWtFy486L59fTYcAVyHFdwuOte4ioHJwk1zyvFv?=
 =?us-ascii?Q?32sjgPRNpxqzXQ5srUernF6vX58Mo9cTFxdjb63J/fia98F0DcY+KjtdaPLi?=
 =?us-ascii?Q?WoBo1/wE3C2LTBHiMXKJwPvplIG5lHjZ4zuAl42xKumxDxPbVsdroDfaNlqX?=
 =?us-ascii?Q?ITHYR9W1R5ASpAkwwzcfXugCgKDcV7VKRiUFs98bj0cUXBN65YNzmGZg7ASY?=
 =?us-ascii?Q?9CatAw9aqel5r0yfQhNMlK+3Mxo2TSGUVRtChdpi+YB24YtsDAyn1kY5L/zB?=
 =?us-ascii?Q?bMKETplCCs1p+rqlgCJLLvhttQh8gQP6X7tkvM+p4UKwLs4XZAMI50ere4EW?=
 =?us-ascii?Q?l49Fy58GWpfw90AsOkIc6UmoDe8r7LYS14L1okj6eJEtAdgPjUjhfqjY1/Md?=
 =?us-ascii?Q?Vpa/YNNpQ2lHfVPcX/ODtW65Ki1KParsfAkeRq1Ap2+WDxnpfGjSox4jju2I?=
 =?us-ascii?Q?D06bCEpEVIpXZkdBdKTcSI7V4nNAf7PcOIJXDyT2wH/50nfev8f7+NuyDMa3?=
 =?us-ascii?Q?nDIgSA7dm8BvghfuZSU+sG6a+ATYO844KacUhg+p/BOANTc0LVr/jjuLyelM?=
 =?us-ascii?Q?o+u3XlsDwBBiqtQLg1E4KAIzElVE5IrWhLytY5HCbGuZOFXTuvG1b10/RUZ9?=
 =?us-ascii?Q?b0TaIQUhedYbn1b1Bron4a92zhh+J0N2XRVjVioG72lAMaw3GUK2tRNxgP2T?=
 =?us-ascii?Q?qU7yHyVzee28Xfx437vX0iPJ0ZNVgmW80NnO7EAvoPlzgdXVs21IRJCaaaN0?=
 =?us-ascii?Q?j4rACI8RLyoVwZtyFjVMMfUfYCx5FhEJhJZjQnoVoVq7el/ssU2IM1l/kPZ2?=
 =?us-ascii?Q?HZ94hGqd7lxGdBajanDvlEvKmY1SYC57OjuAcPHxju793Kmx3thjYZW31cIJ?=
 =?us-ascii?Q?z5f00WqBLbQ3lTgjeQPBTBxIXcQbiTdrPAZ1BpStiTesApbB4lxqMZOeEnRv?=
 =?us-ascii?Q?z/ZMPNaPz9g/ky2pOPLez79Jy9tU1RJhKcUEySRL3Wljn9nQUIthSUWVD5fe?=
 =?us-ascii?Q?O4ucALvh+0qK4Lu3h6duUANmovfIfjGx154PGoKmizv5uwi9NL1obHXGNBBF?=
 =?us-ascii?Q?NOrbmi49iHdwbCanPbkjuAdQYVFBAkbnTJOYDOlwqrbfg2p5h6KRJklceTVf?=
 =?us-ascii?Q?JGPgmLyJIA5Zm29pS5t+xsKoBRK9jjyHlxN/Ui7Aw5lusPvYaT2M3cEIyjjD?=
 =?us-ascii?Q?8SJwxJEy0cL2ofwdi+03iPx6kJuOt7lbiKGP6b64jXyibl+fBcvnFk2oM81L?=
 =?us-ascii?Q?Xd50shw16wPdn9x3nupr/3UjARHsogOW5vlXshTSSMeuKtDNGdfL1QYBvnSV?=
 =?us-ascii?Q?QVvevB+NNlTeUxBoDSN/IkZkYTXC77TjdaaMdIqugZy9vpe3IjkLBpe73jaO?=
 =?us-ascii?Q?s0H7pPHIvCP+Y59WyLBNLuiOQsorlaJkxLDBSC1o?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YEwtP2glnExykGBS36aXNboW2RmVAtRCRK5OewcHKrYDhdBsDmOlS4scPenLv37QM6ydbqzwUurYFxi8g+VDV0hurN+M5pTw7qwYeqNUyddKefGrWNmmtS6rswW5oZbDmFjzOmr1v/jZoWBNcmQZU4f7c4wDNumFnD1JsTFKUd/UKpJBPoh6pcMCRzaREe1QKDzelP+cLQ74wP29wOWDARjoyo/t0A9fqHfrm2DkTrbeBW2TvR3r8jqTnEn7cqRheWomolOllyVmvF8vJHuz7RN1DkuSw/Pm1js/sZvCZGrthKEbcS+BlNi9ouKKVqpss/9F1Ffx1aAoGB73ypehF5MbcHwYYKXk0vL67T8BNPBHfbGoTn0X9tHXSc0UJ/XeF8Mlb9FkzhDrEbPJjQE1lCRdLK6a8jMMSA/u9F6WyOzVIjk5tpTeniNr3KkHGEI4BskW+hsXuYlQy7ATa9ItUC2JIFrwy3BKzjFNL9Ct+x77BDT1BBtxXImkq/EMad0zWPXwi0mBIBjiQSbc8szaOuUIn33k858B5O/d+o09uHThrXep2gvv4zM3XgL1dFvoNAbvikz4lF43EJPEHJSa3bNqjZk5VWY+ELeOokWIXaM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 667c4b36-7506-4db6-7ed0-08de1551717e
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Oct 2025 12:07:47.7557
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Pqe7ELvojaqPNgfPgua7OERymKhs5kj0htLUSmr+cWFrOn06buD9sGPNUncooT6RNxonim2Tel1ZHCojh6ERJg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7715
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-27_05,2025-10-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 suspectscore=0
 adultscore=0 bulkscore=0 phishscore=0 malwarescore=0 spamscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510270112
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI3MDA1MiBTYWx0ZWRfX2gVOa1my7IIp
 Qq3yAKdqsKNzMRhO/LPY8HGKvtGBhgavtZs3bfycFAB3t22J0tGPQV4lcZtHy5rCDD2DMShrZ4/
 IH21lSoyycQ2rX/y4Bx+7HYQLLT9aNlyw/5xXE5LektEivg2/vQ+TVnInEXnHfH7XkCeimKISM8
 RK/l+dHu4ABCSqfLaoDdM+2iead8FbxHu2qs8NP+MjX2pTlLVOzVW7O3nN2WFqTGV93MICMA6iN
 ASV/XFhDBAKUCsCOFJ2CmEMVwta8u7YO8ZB+BZX60pUIP09vbHoygWwtrRV5vctTaYN/wJ1DV2H
 9x3+OFN1nlExDSPpV2bEbJvx/lnk2rnf2pjfoxwR9UaPNcKLkoo0EHS3ytc43W7vtJ4+06lkrGq
 n+Y0Q7PigOr9e2tc3TIQS3lCqeIFXw==
X-Proofpoint-GUID: yEKhdw84Qw7ZlIUnwiEw9hb0YTWOa2qI
X-Proofpoint-ORIG-GUID: yEKhdw84Qw7ZlIUnwiEw9hb0YTWOa2qI
X-Authority-Analysis: v=2.4 cv=dbiNHHXe c=1 sm=1 tr=0 ts=68ff6097 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=pGLkceISAAAA:8 a=yPCof4ZbAAAA:8 a=76m_zPySzxTZ2m3io_cA:9
 a=CjuIK1q_8ugA:10 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=SsQdJVOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=UI2Nh5kt;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Oct 27, 2025 at 09:00:28PM +0900, Harry Yoo wrote:
> When the SLAB_STORE_USER debug flag is used, any metadata placed after
> the original kmalloc request size (orig_size) is not properly aligned
> on 64-bit architectures because its type is unsigned int. When both KASAN
> and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.
> 
> Note that 64-bit architectures without HAVE_EFFICIENT_UNALIGNED_ACCESS
> are assumed to require 64-bit accesses to be 64-bit aligned.
> See HAVE_64BIT_ALIGNED_ACCESS and commit adab66b71abf ("Revert:
> "ring-buffer: Remove HAVE_64BIT_ALIGNED_ACCESS"") for more details.
> 
> Because not all architectures support unaligned memory accesses,
> ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
> in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
> are aligned by adding __aligned(__alignof__(unsigned long)).
> 
> For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
                                                 ^ Uh, here I intended
						 to say:
                                                 __aligneof__(unsigned long))

> make clear that its size remains unsigned int but it must be aligned to
> a word boundary. On 64-bit architectures, this reserves 8 bytes for
> orig_size, which is acceptable since kmalloc's original request size
> tracking is intended for debugging rather than production use.
> 
> Cc: stable@vger.kernel.org
> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> ---
> 
> v1 -> v2:
> - Added Andrey's Acked-by.
> - Added references to HAVE_64BIT_ALIGNED_ACCESS and the commit that
>   resurrected it.
> - Used __alignof__() instead of sizeof(), as suggested by Pedro (off-list).
>   Note: either __alignof__ or sizeof() produces the exactly same mm/slub.o
>   files, so there's no functional difference.
> 
> Thanks!
> 
>  mm/kasan/kasan.h |  4 ++--
>  mm/slub.c        | 16 +++++++++++-----
>  2 files changed, 13 insertions(+), 7 deletions(-)

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aP9gjJJ33Zzo9TyF%40hyeyoo.
