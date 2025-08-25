Return-Path: <kasan-dev+bncBC37BC7E2QERBBFIWLCQMGQEC7CGPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B5FFFB347EE
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 18:49:09 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70d9eb2eb9bsf64824656d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 09:49:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756140548; cv=pass;
        d=google.com; s=arc-20240605;
        b=DnNsfKm5/HVzJTRvbbc1lqRv4JIz/dkhLhbSAE+85jfNf7RdywjIfyfTfOvFX9cwm+
         7APwHBnJmRI0GPvZHiss7apCCylYn2K93XWwCVNkaXvFCEC7XQmQbausU3SB+euChCOL
         +hy1T5eUv9l19EnqPm2Jde5MO7zZP9eo7WxEnwb1bh2xxPvZFRYjJIXssEup2UUxJ2AZ
         wTp+zVRyFE6jbNxuwYKexLGKsKCzOwbRK54dODsXc0vURI0DVSK2UuB2IsAmPHDAFguj
         WpLR/r1OMVNtTI5+tCn6JWn6i0jnKsgTT01lyVw1hqaRL4cQWIDw4SakxsLikdc9I8P5
         cARg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1en3dwnNdKaUgCIEO6xEb1ANNBQtT9pG/ZQzg4NCxps=;
        fh=sWVHWxeJOEd29TsSxODacKw7vdJ5vYyqcykqk3Ffc24=;
        b=OUKNCZVO9DMeznE8ECt3gHqdgWHfcy6JkPlqoBjhyg8Y4iMOw0wZATKt17gSRBWv9J
         uugmCWX2S+X3qHMtoK76oNjtEzm6EtNDjEU+GwaEbz/iPeu3hD3xkJry9S8ge9Wc/hZD
         DucWsT3RbhB6tC2+SaXCsh7QfPJA15i4XA1mFSH+iYs2VL/kfbUJPQ5thSERHkRsx9zI
         h+z20pF88chiyQOkSsC3TDXD4HNkIgzJAJurAbfoSSTUB+2bY7L2ccrk0bTipLYLjqpT
         hds47RV8aYLgLk7Fmw80cShf66e41vJDxD82wCAW0cflxbweCR081Ic9CyrwAu3mQLkG
         6Q8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qyCW2XRT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tcmyRe+P;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756140548; x=1756745348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1en3dwnNdKaUgCIEO6xEb1ANNBQtT9pG/ZQzg4NCxps=;
        b=F6MpmxL0UPesyybk7M4cx2GAGPp1JqwnIzU4rmXCVzD7FDQkek1CxjQhPsInG7vp00
         mk5KSIcWxTxFGZxPwXOnOD2vMU2/uHGrsOf5rgP484We6sAG8iFOTpc5CqfmuRV2eqKA
         14sEhv2kU7Hx/PfcBRExPrGLRrn9O+d5bFY6geKqr6qtvBdfniLtf05FAoEKaiihsETB
         WvpgCTQkwTHTuOOyNsRHoBLav9RZtodSg96UAzYbuugwtl0mBfwS28+fkyjQJX6HjbJY
         gcK2pMYVa4SMf3v2Ovs1kpyXjqZtwqgNA1md4MeCMHVyejDShKYgLQfS5BOR7DSVck5T
         OHmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756140548; x=1756745348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1en3dwnNdKaUgCIEO6xEb1ANNBQtT9pG/ZQzg4NCxps=;
        b=IXMVklKTdkfCn+ayQTuYwZNNR9mwQhmcqGGFkqmzqewr2BegASFeEQ1IU6MPudmcGf
         bzSAOAzPl09qwmv+4VihMxHII+9CO+X4IhSRlOdBYERIhCUnqIoZSxxMLmoJOh+Npsib
         mXXAKLO/ySKG7D7g5dNbkKtDIc0w646AGrd4UNT1vxeXcEhxeY0Mtl6kcp/0hPxgwzUh
         U/J3bMR0nn2yiO8XjpP6sv1ecZgU2wzF7vVsNZIdd9yzBl79mm/OnDqW8EEJSdL2XHvI
         EPHMLnyG5m7W554QYpgw5H/GTQVMMMi4BPq+wx0sp63y9DoZ/CVWQzOJ76xxTu1Oto4C
         ERXA==
X-Forwarded-Encrypted: i=3; AJvYcCVm68r13CEWigTf1bFu7o4STzqlXfWlucMyJ4woZ7mUxRXg9b20mGe+KryAOcyBYGwVPOYoqQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx7E1YsIOOi7Enp09Y8egNrYJVUQoxziJAPabNuASa4Mdbccimn
	GVVAW2vzA2m7mHNMODqZLtEkg9JLsuJRyWwLEhCMgLbdvvk0CuKbloc3
X-Google-Smtp-Source: AGHT+IEOM/iY9pA8rm9HPlgmAeETNj8xQp+je6b24vqJlUG7gyrJNcGKSOBbdtfNtvrQs/5e3MEndQ==
X-Received: by 2002:a05:6214:2a45:b0:70b:7076:cd13 with SMTP id 6a1803df08f44-70d970c4cd1mr165066216d6.2.1756140548209;
        Mon, 25 Aug 2025 09:49:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZebrLyux2zKOvd1PDZnEdswxl4VlJiMO5qRsGFQT7uTpQ==
Received: by 2002:a05:6214:f0b:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70d9522245als56818066d6.1.-pod-prod-01-us; Mon, 25 Aug 2025
 09:49:06 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXutYaLDF/jzM9jCfCisNg+AILvNo7dlhPLD7pVSBWINo+4l9dY+dRdmfoGofNAE9W7nRUnL+p0Pfw=@googlegroups.com
X-Received: by 2002:a05:620a:4147:b0:7e9:fbbb:18a with SMTP id af79cd13be357-7ea110dd5f5mr1249301585a.81.1756140546631;
        Mon, 25 Aug 2025 09:49:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756140546; cv=pass;
        d=google.com; s=arc-20240605;
        b=dRP89xukzeXhg2UP3WJYAyONo6US+omIA+vuI4VJSGdCm3imOeWi81+QsxpsWvPfJQ
         fCi0TdqlJJx/qNhX5plUB0zK6yab9WEOuG3gMa6Lx1c2EQB7/rIxq7PnN8806vmUpeDb
         Z6uRiMlnDMnTXjL8SOFBuhor+z+XRJjMDYb058Njq9rDvDhrP7h5t/aK6x9Vpt4C5ZV3
         rmqlGcOWljN4keesSkDOWhtKrgrnur9XIH99sxdNzbPsC8PakoUUg4yNLPRlsYMPB53K
         BcqQ1DA8NF+0Ye8mgHcyk4AC97hCN+GXAsUUuDcAyDdkFE/PjcaDHFMzwMYuCKTTXXaN
         g4Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=mr+7oe7+GxNHzPMJFG0Z+83h6tjj18cS0qE1HtztNag=;
        fh=LPjfD5tbvtoGRuqv3073fBzyRScIkk+F/KYxpEE7eTM=;
        b=WZL9emy5HzzUMnVahf/npOqKD7b36h+hT1No+wC4PwXGyNTjSELKHoHfg0n/TYO/Ux
         P17Bb2aRUO1QX+Q4f6CVrp1bmegisZNCW47zTGhuv+4LmiO65fMX/PYQyteRSXw/qoA0
         fV0Qcjxr0BflBhgH/xtRgQXI6TzqUz9qMQCyippPzAamgmhEPeNghmyFShH23WBQMbc2
         y948caJIb60cVaM29H0RuuJSKUqSStoVpW59BMeetNB/lHQLd0O3CxFjXh4iXXWD3l9D
         J0N+DR7FzYXh/5wokEeelRg6A7PXWTNkXd5EKu6BzvIuL3N8m4+BzCRi9XLMC29ImBPc
         p53w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qyCW2XRT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tcmyRe+P;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebec276de6si31884985a.1.2025.08.25.09.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Aug 2025 09:49:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57PGmXdN017797;
	Mon, 25 Aug 2025 16:49:02 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q678tpr8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 25 Aug 2025 16:49:02 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57PFDerG027115;
	Mon, 25 Aug 2025 16:49:00 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11on2040.outbound.protection.outlook.com [40.107.236.40])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q438d9pf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 25 Aug 2025 16:49:00 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=jjf6sbWYpFyMyH7y7TEY25AGeaSnk9f8/IL8x1hMC6bU59gSEj3ZgbYUN3XQlqPS/idX1GgB350tRzFhvmYqvsTotIoKmH/LaLdeGr9LvKFNtVB66Ggw6Rt2g7zCqiqSbrQ32wCagVSLs64vtnQB8s/hFKyBLC4nDcus4sYTZkl/dbg/KksGOFO1jv3vHSVj1Px23XVCDNljhhc8hZp/yv50Wj/o4LuH0U/Cgd2bOeNKjHj+fI8pbiYBKIwcA9nQCUQk91AQgYUXYOAfqD+l5VyW1KLceIZWQbcKfx4dRsOGvYQGcegH88nB4rrUATay0llzTWV0SW1LyvYl5jOjSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=mr+7oe7+GxNHzPMJFG0Z+83h6tjj18cS0qE1HtztNag=;
 b=Xt5rRWp264i5e2sVtyifLjKSL8IXwUQqZUijGN5OD1eCLCsY960idSDAlwxzZtDo+28UtOnq+k1B2hbicOBXbppWdf01hTfp7cC17xJL4vMAYmJJgmkhP45UahiPcU7gL7//7ojSUaTX+6oYQ7M4FusTFoP+L14w8G5WZfsTh4EgSImkS723+wgqfIsShxgoIKlk4PqUVEmNWg4UWltN2p3tfN+q0QGmusRIcX6u3KA7ebZOpveEcefyi6VmtTu81G6zhOmHzpvsmKhKsYDrXp6yNdQ5bhK+Jltyiat1MFbG6FLM3zuElrdsWuIhSGjFpBg+vcYw3TaxSJEGvdVoqQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CO1PR10MB4707.namprd10.prod.outlook.com (2603:10b6:303:92::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.25; Mon, 25 Aug
 2025 16:48:36 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9052.019; Mon, 25 Aug 2025
 16:48:36 +0000
Date: Tue, 26 Aug 2025 01:48:25 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        "Gustavo A. R. Silva" <gustavoars@kernel.org>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        David Hildenbrand <david@redhat.com>,
        David Rientjes <rientjes@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Florent Revest <revest@google.com>,
        GONG Ruiqi <gongruiqi@huaweicloud.com>, Jann Horn <jannh@google.com>,
        Kees Cook <kees@kernel.org>,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Matteo Rizzo <matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>,
        Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Suren Baghdasaryan <surenb@google.com>,
        Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org,
        linux-mm@kvack.org
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
Message-ID: <aKyT2UKmlznvN2jv@hyeyoo>
References: <20250825154505.1558444-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250825154505.1558444-1-elver@google.com>
X-ClientProxiedBy: SL2P216CA0148.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:35::19) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CO1PR10MB4707:EE_
X-MS-Office365-Filtering-Correlation-Id: 3c865fb8-05a9-4a37-9361-08dde3f73bf8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?JKt6hEVRHycJmZhy2g47ALsMybszRfM6X+Nw0ptjyWHUqSCHUEiyQp8omQKZ?=
 =?us-ascii?Q?Y8mhcxD5yScdKqukZLnsmPzOxALsME2K0OohnKQT1AF9URZdZxfVw7xjGBn/?=
 =?us-ascii?Q?JhzyIhWa6x62ot5Igm33AJNAIyuKO757PefhR/Qhj06t5JgN++VfxfjeogEq?=
 =?us-ascii?Q?fuy5BPXwIm8puvAMAw6obz8E8Lj9jRtOp71TPzEBBW22Z7jfNnaeHaWKNXdf?=
 =?us-ascii?Q?MxmAC/jmz/Dh+IGnrox2ZOukdmJ229Q3AlFV82xln3hVrTrrCakjl8cGulM5?=
 =?us-ascii?Q?D9RSI35GzB6Rb9gIfWuKCsEvmyTN43TVNMea5hjg/hqFBLhLRugmQqy/du+7?=
 =?us-ascii?Q?YnAuy5goMpXUrQPXs8X80v/v7/hcOmuEezyrNtk72QO3ZreNR6xOYGUgKp8+?=
 =?us-ascii?Q?knKhZYwMaiPzh6D63fLhwMgEqgsCOPJHsfv5iopVHkPHhsyB1oyF0OWe7K84?=
 =?us-ascii?Q?pDhYJ3JdlZlk+SUVFeW3sghm/NOqdcgrnzy7Y2U/qP9jGokd+wdNnM9JQr26?=
 =?us-ascii?Q?AMKlUCUTUef9I52S5ws57O8xs8OtqsCcjx8HjnmvDAPTff2EOMeHjYNVGwk6?=
 =?us-ascii?Q?S+Wrcn+rVk+DyB9VOr/ZpP35b9vUtgfxT1XTAl6S2LplSMHDd+DZK24bzYvi?=
 =?us-ascii?Q?Rp5R5e2yOgVcyqzf1K3uZk2Nq8XNDBNUf/yyX2H20nLsRAg1NoKXginINPja?=
 =?us-ascii?Q?Kvketdynm/eVDvhdjAZAxmSmAc/7S3JhWj7da/J59BbjYRzaSVRebuMGBXmo?=
 =?us-ascii?Q?GJooYg2gkB+gWMNrJNvWMoaBLz5+pwq4g6b2jBXpGBb3NyIxsLKLzGnGRGk6?=
 =?us-ascii?Q?pq56W9eYrXGdxAjzxV6PSALzHfbucMwKMlE8TnxsKJYKjKcRUXo/Q2GhtSoA?=
 =?us-ascii?Q?hagISV9auwCY0v7Ll4BQLIMx5+MwVDLdtIjk7ZXk16YArRXJwNyrrqj8fUcA?=
 =?us-ascii?Q?dFjcqTdmRzipyFVsEj1UXOL6wEaj0xKJJrlAbuPvg6IBsoP4fSdEnvd32Pxh?=
 =?us-ascii?Q?DUQWsOyDyQQZFlk9V2fU+x4gHxPt6fu0V/STlVfSHAkZ4u7RJV64i0V9T1Lk?=
 =?us-ascii?Q?+mftBvq/nW8/NEetyYXTCPdn5+KjRPK01dR1MX0ipD9JaI4V1ie0W25xXu/t?=
 =?us-ascii?Q?7rC50p/IvOqXGOzg/tUertA4XGZqZjQsL8x4huhkq72qNRNjg/NyloRZr3+e?=
 =?us-ascii?Q?b3TPQ6CZ0kqPE+E+VY1DAInTcqDYS7qQe9VS+0Yjp+m88us9BhyaOKBJSvHn?=
 =?us-ascii?Q?w+tJr+XxK+tp0Gveew05LXRCLzBkaHd8FiExOFuWBvrjr0x4SWQQO8N327Hi?=
 =?us-ascii?Q?s5hLQX7s33UOlLYbL0gkJqD7zpme0BOuMXUPAJz7fgNo6eMhaIwc7iMwa/S1?=
 =?us-ascii?Q?phnFBl+Z+OpwkYfIkFrXrsaC1deI?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uTWAQb8W9cg/pDuZtoo6RoTJos3bm9Njr5cBH1VLnI1RvZpF//0ReO/V/mYB?=
 =?us-ascii?Q?PqBmi0YLPYiw0l1yRQzSWCy1tB/sYxPmIFL7tD8bwxQo9zoCaj3eC0uDC2Q/?=
 =?us-ascii?Q?QUuJ4jgJDheEUKdmJXgUvvpMoP4UvW7DGccCTx3Vl9FULgum3oF/tJr+g7h4?=
 =?us-ascii?Q?Qrt/C7rfTcuWLBW7GVT7DmvsKRk5+X6nJ69t3tPRSf3a8E4quL6SHUEjghNU?=
 =?us-ascii?Q?WdWxJo1jJUcn1T4y2E44gC+kHSiv0UJKCYbfXS7iniJOPSQe8+0yDWQrecHx?=
 =?us-ascii?Q?s3Q7NmQAyx8a7CHUi2RZ+/G6rOVJaND23xpv4oh9fVpurTTQFW9H7fztNd4H?=
 =?us-ascii?Q?5iA8ri53ID7CL/zoEtTBWZUwcRlb/zHf+UVN55z/HRDKnwxWQz4X6sEpJyr7?=
 =?us-ascii?Q?i+4xkGL0FqT7KrrcHxgNs3iL7VS0KQDHN6Xw76xjKR0AdtvNfELqY3nupcdA?=
 =?us-ascii?Q?kxlnBYz2Mkasr7oZqmKLv4PK+iEMH0/1XvUddAmtJDNK4sj96fdEex2zBZzB?=
 =?us-ascii?Q?ND0nCCVbXpsLuK02xeBgqIj1d+Owqn9ja0ApWh/l2Lw2LH11HNsC9YH09OLZ?=
 =?us-ascii?Q?JWnzobRucQrmCMkEFDUUsrsrE3mySvX86M5qqKgSUFB0gAVv+UfeuAHqLz9S?=
 =?us-ascii?Q?qSG3ns0vDQsU0FiRUDLkuDGb9FdJBuPZSSy0lHepmy52EfMNS3bgaG5DOUFS?=
 =?us-ascii?Q?gQftOw07CvjhDxqpgIJfikPJwbIPx7dr/BZ9cZ0mdj6LmbIxrb/EdIkdMwmi?=
 =?us-ascii?Q?1SGinNllWZKVHQOb5/OAAGZnAtyFVYBQZp0Rfn1dgBgvdARd7E4/5c/RX/FR?=
 =?us-ascii?Q?CebEuJlSkwENb0tTCriru92d+JLj73fHPBMQHzU7/oogTAydFOdDHA4lpgLl?=
 =?us-ascii?Q?gW9tKEZjcCXzV4U8UW9n2AGPcG0CkwMBFjw+njJ0TCTM/gHuoMvpOdUgKIpM?=
 =?us-ascii?Q?Bczm2U2lJo+LbixdyOJTl6+cnmslGKNxrYYOlF3b7OCZB1pj9oCzkHFM7ava?=
 =?us-ascii?Q?NG73qDjmy+Dg5ZRKmMCNwMwM9GhsVii9sQHDN0/wPhovb06gBbufSRAEGPhz?=
 =?us-ascii?Q?MDwBqL2DS1pqz3SVPZsTX1F6glS0W612Ul6WKdipCAN1ra2ND8gHUSsy5TtX?=
 =?us-ascii?Q?guSGAevHNhdps66gBz+uiswf14qqDg7U1vEZpCjR+1Ka+oqTG4n1VYpt4L0M?=
 =?us-ascii?Q?cDtlthPdkjh7OrxRM5VA/lKHR/tOu5BqZtaxFUaiKDqSq3nXroAHzTz7UzAw?=
 =?us-ascii?Q?nPc6l5CRI7fS/qsr49Ggn6xaP+MfNgS3hmdHJhodXkQO7RuWTQ+Ga6WNSPm+?=
 =?us-ascii?Q?CWMr57+iBnhKoEtCpPUdEY8Q0DBjGusocQ7cJI5hoYooYM5t8IBk32VA6ojm?=
 =?us-ascii?Q?cxcouifDDgnQPV912KJ42Zsm4D2axHjq8MoDxdr/ftlcuznR8ga8EF6i30FK?=
 =?us-ascii?Q?DGlW/7CzxBoIJ57DZuoDjnMapKA/outRcvGLXfdMNR7Yh+hpsJn1gLyfepqF?=
 =?us-ascii?Q?HBSu0g4IPIrTIc5w+z8RH54q3iRKq7MUlVsUaerLI9xDOL93JOFWgihA6DIJ?=
 =?us-ascii?Q?Mh4wQRVKafKhHxp7iZNO2N++a1dEiDZUgJkO0nSo?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: wUtxIkwVThk9WUyJ52momCqYhFe/5ckJb1e5546OHSXdccTQr0dK/d2GrRTrx7LYQ215uKgEhe4MoVNtSGM9V2QeHZRWOGOX4EJNscRc2Xo3koIQ0bXsXuiY/2NJY9G5CrWI2BtYB2+/CypXNgk0+xzdZM6z4sYH2lyQuyZWL1a4Q4tkLR+IMBuUWBsL9MDYwxvu5z8+gVjlmQmwQBq+eM+TQ4wWCVcxNFEMsVHyu+p1pMeQBkdCN1qZAimO/ZAcQb70n4kVfF7l/XZcjLAs3TYRG3hH1ohkU051h+oBPD5s8t+5c8HvRb0AZDsxTEf65/OkrlLHf80BurZOsOcaIKJ+YQzD/QnqssSd33w4+mpzuEKVhDFwTSFiIV2GdhLVxVXI3Jnm+T5CJtGGCS4W7gLvybw5pKfFYQ7N0wmRPF6/i1/f80/0jVz+R/KeNx6wYILvSHJJRH5iADdh7phvEnpVyaAuahWx8k0L5PUax0B6BczdEDOoUndtL9aS+vpJIcDnFNbSY6bUji+MCywQZWtejq9ljmlQZGOdwBo6Nt/ajIWkyrQte5BbwuWMGFOHqCkr/frJJHKuIKiPr64MHLLT8W0t24zZw40nvjtBujc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3c865fb8-05a9-4a37-9361-08dde3f73bf8
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Aug 2025 16:48:36.0506
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +J2irPtPsqM08DbOIjDHfopo5wosGz4Luo1zvuYpzSHk78+ARz0wzAd6vGUtnC9kyUa2oe21cVSJGk8dL9bpxA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CO1PR10MB4707
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-25_08,2025-08-20_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 bulkscore=0 malwarescore=0
 adultscore=0 phishscore=0 suspectscore=0 mlxlogscore=910 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508250152
X-Proofpoint-GUID: FAoVjG1JL1ZneHmF7S2-Rl6wafGz4Ms0
X-Proofpoint-ORIG-GUID: FAoVjG1JL1ZneHmF7S2-Rl6wafGz4Ms0
X-Authority-Analysis: v=2.4 cv=NrLRc9dJ c=1 sm=1 tr=0 ts=68ac93fe cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=NEAV23lmAAAA:8 a=Twlkf-z8AAAA:8
 a=RaiE-mXtAAAA:8 a=07d9gI8wAAAA:8 a=1XWaLZrsAAAA:8 a=1XCi5IOhF-I_6B7-_WIA:9
 a=CjuIK1q_8ugA:10 a=-74SuR6ZdpOK_LpdRCUo:22 a=6wq-4gwl32YbjisUuCrp:22
 a=e2CUPOnPG4QKp8I52DXD:22
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzNSBTYWx0ZWRfX9/69+ejzgd8Z
 4zYWpfisyoW3U2ND7xNuUJIYpbJGPucV5m3V/Am8cHYhTGW5Kq5KS1A2dvMf2hvxfW7Th3oIfS+
 rH/GOxfzFLavNWjshV4y9+UWsQW4zLbP0qeCNyDRUDhy/mXiSJqXezi5MzfG3IBzM6b7ZTKhbhD
 hHR/NyJJddd0J2F/COXcVUDIttTkWSXVGhguJiS4fNDXsKSmoBiQ9ySx18ZYirw11+BJAw1NeR+
 Zk9VAGeTKu+cUl0tbxQetoxhCKoo/G/whnOqMsnQ2aTezCe/vg0VAsCa6nal2Dhrccciyg0IWxK
 paonTT7yxSPwFLOJoAuGhgT56NS83hsxa1Ij9BL1oVY0e1JugRHNsIsY/y7Gq6TsTU1HqWA0Fkm
 gJQmMvcJ
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=qyCW2XRT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=tcmyRe+P;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 25, 2025 at 05:44:40PM +0200, Marco Elver wrote:
> [ Beware, this an early RFC for an in-development Clang feature, and
>   requires the following Clang/LLVM development tree:
>    https://github.com/melver/llvm-project/tree/alloc-token
>   The corresponding LLVM RFC and discussion can be found here:
>    https://discourse.llvm.org/t/rfc-a-framework-for-allocator-partitioning-hints/87434  ]

Whoa, a cutting-edge feature!

> Rework the general infrastructure around RANDOM_KMALLOC_CACHES into more
> flexible PARTITION_KMALLOC_CACHES, with the former being a partitioning
> mode of the latter.
> 
> Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
> "allocation tokens" via __builtin_alloc_token_infer [1].
> 
> This mechanism allows the compiler to pass a token ID derived from the
> allocation's type to the allocator. The compiler performs best-effort
> type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
> Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
> cache to an allocation of type T, regardless of allocation site.

I don't think either TYPED_KMALLOC_CACHES or RANDOM_KMALLOC_CACHES is
strictly superior to the other (or am I wrong?). Would it be reasonable
to do some run-time randomization for TYPED_KMALLOC_CACHES too?
(i.e., randomize index within top/bottom half based on allocation site and
random seed)

> Clang's default token ID calculation is described as [1]:
> 
>    TypeHashPointerSplit: This mode assigns a token ID based on the hash
>    of the allocated type's name, where the top half ID-space is reserved
>    for types that contain pointers and the bottom half for types that do
>    not contain pointers.
> 
> Separating pointer-containing objects from pointerless objects and data
> allocations can help mitigate certain classes of memory corruption
> exploits [2]: attackers who gains a buffer overflow on a primitive
> buffer cannot use it to directly corrupt pointers or other critical
> metadata in an object residing in a different, isolated heap region.
>
> It is important to note that heap isolation strategies offer a
> best-effort approach, and do not provide a 100% security guarantee,
> albeit achievable at relatively low performance cost. Note that this
> also does not prevent cross-cache attacks, and SLAB_VIRTUAL [3] should
> be used as a complementary mitigation.

Not relevant to this patch, but just wondering if there are
any plans for SLAB_VIRTUAL?

> With all that, my kernel (x86 defconfig) shows me a histogram of slab
> cache object distribution per /proc/slabinfo (after boot):
> 
>   <slab cache>      <objs> <hist>
>   kmalloc-part-15     619  ++++++
>   kmalloc-part-14    1412  ++++++++++++++
>   kmalloc-part-13    1063  ++++++++++
>   kmalloc-part-12    1745  +++++++++++++++++
>   kmalloc-part-11     891  ++++++++
>   kmalloc-part-10     610  ++++++
>   kmalloc-part-09     792  +++++++
>   kmalloc-part-08    3054  ++++++++++++++++++++++++++++++
>   kmalloc-part-07     245  ++
>   kmalloc-part-06     182  +
>   kmalloc-part-05     122  +
>   kmalloc-part-04     295  ++
>   kmalloc-part-03     241  ++
>   kmalloc-part-02     107  +
>   kmalloc-part-01     124  +
>   kmalloc            6231  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
> 
> The above /proc/slabinfo snapshot shows me there are 7547 allocated
> objects (slabs 00 - 07) that the compiler claims contain no pointers or
> it was unable to infer the type of, and 10186 objects that contain
> pointers (slabs 08 - 15). On a whole, this looks relatively sane.
> 
> Additionally, when I compile my kernel with -Rpass=alloc-token, which
> provides diagnostics where (after dead-code elimination) type inference
> failed, I see 966 allocation sites where the compiler failed to identify
> a type. Some initial review confirms these are mostly variable sized
> buffers, but also include structs with trailing flexible length arrays
> (the latter could be recognized by the compiler by teaching it to look
> more deeply into complex expressions such as those generated by
> struct_size).

When the compiler fails to identify a type, does it go to top half or
bottom half, or perhaps it doesn't matter?

> Link: https://github.com/melver/llvm-project/blob/alloc-token/clang/docs/AllocToken.rst [1]
> Link: https://blog.dfsec.com/ios/2025/05/30/blasting-past-ios-18 [2]
> Link: https://lwn.net/Articles/944647/ [3]
> Signed-off-by: Marco Elver <elver@google.com>
> ---

I didn't go too deep into the implementation details, but I'm happy with
it since the change looks quite simple ;)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKyT2UKmlznvN2jv%40hyeyoo.
