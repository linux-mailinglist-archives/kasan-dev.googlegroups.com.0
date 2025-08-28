Return-Path: <kasan-dev+bncBD6LBUWO5UMBBSVQYLCQMGQE4KJASCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E47CB3A8F9
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:56:28 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30ccebc5babsf546082fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:56:28 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756403787; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ax9vUwp48sMjEdOmkdCgnCvjQMlkqhyr7abUHsjMSKZpAeHH4PQuTbaw7A7AoYMnZ7
         g/2oiNjbdmf4dW0zMvxi8urvvXcbJTvzTwTjwHqEuHMa5RjSBEnWn6qKQHh8R2F7ia3C
         BWY/BaKz/1ttkq1txfflXuHoT4WSLy/+5Mg2TyGThibJ1LLoctV63No9FEvzNnV311N9
         E4RDZuxgvVSypPSDaqfVJb2IVGass2qk7zJNOkwH5qRzcQth4pzki7+BtSNFU7IGy29S
         08Mv7WPbkiYkOoxOHEZMA+wZVR/Z3FVlplHA4Syzq+s8SxKsCii0pVGDQnyt8/ED2p9K
         9SVg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=AK2nnHwDRSCL/xci4n8wZlMYWfVBbhjc03GZP30EAZI=;
        fh=16nZWB4gw0rGjnfLD9HxN55cc5p5pfLPBf5r+di4jSk=;
        b=gdtO+I8z9o6C6uiaDJXz83SPEDgKCb7uj0KQWElVkwz+QGpT9te6ERWZdGSTMyuKb0
         hb2VncG3NAtt5NWfvYZqrJb7cvpWfk7US/IBcEiCEz2+U3GgRqrxoelv0MRwQTM4fV8A
         ia+rPG+3hu2e7FunUOe/fpCp48Q4Xy7J9teVhARqRzzM5spxKXYFjQp8kEIpq1fz8zid
         zCLhYyxr/K/lLZpLtZbJc2bHgPxkhaZpEOSSFr8BjO9MH+fLvhmBNgrBoKvYTfdXSK3M
         BSkUa07j+5uCkqpHO5d7Eg4JUSjtEsyJCqW44dzWao+s5Y0nTlP+Qv7eLRsQDt/hBvOQ
         f7/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dPrKQsul;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cGpZPlJZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756403787; x=1757008587; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=AK2nnHwDRSCL/xci4n8wZlMYWfVBbhjc03GZP30EAZI=;
        b=XIHb7jRblHHgrpZHbqkKkH3SgW6O59iEKFTiXtNGibpKQm6H3wIN1HmVV2GZ347GWO
         r3kb28ao1k/Q3MUYAUkAYE9tII+jSUF5YuJE2P3PJaM52FKRCb5MihEOYTl1G+xgIgo9
         nWTi1ywgylyz2AU4u18hX3Km/b2A5LLBesDTy5u1ivOxYeAz+IUxP6vbyf/zFCcXDLdl
         pfWdcpayMjMP1+X/LAwFjnbMcML+/ZnmEFrkA0bITO/zrYTHyPnroOVNjenwuBrIU62V
         QVDlycttwDIUj3NvMYF4eR/aOrXZEDr4OWxiJG/ombDoIaPjr74FFvvZtqKhYnUHdQmM
         d+kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756403787; x=1757008587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AK2nnHwDRSCL/xci4n8wZlMYWfVBbhjc03GZP30EAZI=;
        b=okq8TiUdHreGSEJwGwj+d+ww+MFimK8uJscQ3fH+OoAsorxt+9/HfKXDJcFjDtRV51
         aTV7xMOKJ5/5f/CE1yKkVvnH7/ttxSAWdJ8jaGMyCY7PlJl495TxlMf0DXZYFYg5f1Tm
         RsVVoW2TcHxLQlOAxt3VyqEVoYt7KcVYnv9T3nTUqBkL5KbSOYG3L9hfDDLaQ/R6Vyo5
         b/t63/t+gJ0NTO0KQbekkYYdYN8mr2O1GXrul4CGRzqLl1rLpohWa0HJRomCNln71vuK
         vxxT0UqmMQAVVzZLI2Muf+OXHijKx8zNxnIdnG3Zz+V4cI9h7jpFNd1q3e/kMnSFHMFd
         FssA==
X-Forwarded-Encrypted: i=3; AJvYcCVuFnCsKG4J5swn9cYg5fxbmEhJ/OlNKpWmH1UxPiHll6fiS0YWa8bw0bwpl6prCwg+29Ehww==@lfdr.de
X-Gm-Message-State: AOJu0YxnXfklCfRrnJGVR2t/aaFnPnyVB+42zxHFj+jkrc09/lmnXfN/
	906VO+HJLZEmDOidbzOfyFk1zfY1LTnzkeI5m3DsngFy1kgRx529PtC7
X-Google-Smtp-Source: AGHT+IG0Xj0e8KkP62pwN5dqiS4Bsui3qWMsPsZDvdJ6JI36pgoaHLI4qkUKTexdgIddixgx6IRnjg==
X-Received: by 2002:a05:6870:d8d2:b0:2ff:89c8:44f4 with SMTP id 586e51a60fabf-314dcb2cdfamr10581288fac.11.1756403786985;
        Thu, 28 Aug 2025 10:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZceEwRnP/OtsP0DSuCzj76/CDAdpwPCOkt10tAS4fDYkg==
Received: by 2002:a05:6871:58a9:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-31595d603ffls358750fac.0.-pod-prod-06-us; Thu, 28 Aug 2025
 10:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUnMjWcMH0VwyW1b/CiT5GmcCNcySvo54naKhp4GOeAniIGFjWlu1gBvEexvEqnEBqAMmXvwMq3C84=@googlegroups.com
X-Received: by 2002:a05:6870:a70d:b0:30b:beb3:5420 with SMTP id 586e51a60fabf-314dcb33d68mr11721860fac.17.1756403785453;
        Thu, 28 Aug 2025 10:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756403785; cv=pass;
        d=google.com; s=arc-20240605;
        b=J2f+gPKeN3UDZE8sHXGEe1yneeIWwkHuIDW6PWwIeZuRpTGc2SkAQYfs4LzpCXmtnc
         SgxpHhUmMG/nLlGadO4qwP424xjEkq9iFrMxvXCwyLixEfRTXQTMMUEdkfTpDYJu7+4I
         Ionjy0k93dGVOil3yCpt8PZjaoOVwRbQDsxhcWIWDLWCmAwJgzJgWUKZXc+luaIIRG0N
         fNdXt0gvUlgylTj2VYOP74kApOn2O5VhNFTFWXeMOfz8mWNelDOwWw6N1IFzL5u14UBq
         BFO1hWPO4GVTmfkz/LsSniCHP94N4CIkmVGuYIqptJROsLxsZY2cg/n6n7pmtbGMZ0er
         ETbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=7w1S+knOBj7nV6WKoNanS2ygqVT+O6eCbvMAtMi3SCY=;
        fh=gveW38EDW+gYwwSOpuYt2hf5e8bXtF802oWsFV2ctnA=;
        b=e4pdw2MccKhPksrzaQyA0wJ8shZ4pkOZ+iorLiGQCtg+aHTpXEIPczm9c1e3LPUlI6
         2sxzSQFHeXnUa48n5v0DFBFKMZDDwr056Y8J9cCWFCu4acgFC3/LwUPAdOoesfgLBJnp
         Hk0oRGPha9miHA8VZhvyFtoYCplUGxUdPfPnvC//HChgowMSlj0Fg7166wCTRmAU7TbL
         41nokOdkyAWCtUVvgN8SFQeZdWwvIkIEm2+j8XjBjLl2MegFVPftjo3YPB6x3NfCgzL2
         q5r6HQyPhOw3Q6VOl9R6q0Jzc3Pya2jNh5870UuUOTsbi1/G28byQcECcKn49MOrk+QA
         V/Sw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dPrKQsul;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cGpZPlJZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afeeabb9si31471fac.5.2025.08.28.10.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHNUVJ018833;
	Thu, 28 Aug 2025 17:56:14 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4jas3qt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:56:14 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SGMBL5004951;
	Thu, 28 Aug 2025 17:56:13 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02on2047.outbound.protection.outlook.com [40.107.96.47])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43cb3jf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:56:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=mPRyjvPcCJd4DoRjcBV1rhRYAZ3Xy+6P9aFxGJ/Ge3vZXDvDE25WJBJeXlZXsSEFwg4dUcTrzwj1e75Yv+R/eWxd0Dt1EP87CAdu4mlGYDJch5/zTpPFG7z8JjG1/KpTjIR3+KLotQpLqLBPh1iQoo+2mJh+R6vIepej09rjFbp5Hl3w+mGMaY3rSfYrlkBB1ftQFynhm8CVIfLSKUcD5tx4+ZeFdUG6PmTNXDmZkYu97iigqWMuvY90ARDp5NAlfnDH2tAQGQa9mykxHDSXwZ5v9UfCzZHJIxC5a/h8ZVy0jZMyod0A83pb883Yk2up5RgiIKkcGaT+8xsMIWEjNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7w1S+knOBj7nV6WKoNanS2ygqVT+O6eCbvMAtMi3SCY=;
 b=DTpwPPaR5dHyiah1BwflfTk3rUPZwXVdPLBvcUrAremeld0trUaqThXzW8ua28Wfqb+iN9qRK7xhrtzYcturd53mU41cNidM1Qjy9II/XprLhadng0xlcRPG9qRd6dL89y7oEoXeCn+FRXUJmIfI+EDa7DjL1ESRBbv1gxRN0jvajRcg4c595aNe3vlvQ5U3olztUh4l9b3WKE7VGMkMS82hOFKafVIbgnIfq0JnPR1R3uQ2WSnqKbst7c5CRE1RdahUMtNE66GnVopAWeqEqoXArgX1L+4XtIcIU+gj+YzEPHxaR73RpKKrXZLIRHbgHyvsBnTXuQR4bCrmzxz+/A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB4573.namprd10.prod.outlook.com (2603:10b6:a03:2ac::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.19; Thu, 28 Aug
 2025 17:56:06 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:56:06 +0000
Date: Thu, 28 Aug 2025 18:55:56 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Jani Nikula <jani.nikula@linux.intel.com>,
        Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
        Rodrigo Vivi <rodrigo.vivi@intel.com>,
        Tvrtko Ursulin <tursulin@ursulin.net>,
        David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 25/36] drm/i915/gem: drop nth_page() usage within SG
 entry
Message-ID: <f5d12153-f14c-427e-8294-8b8b44485895@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-26-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-26-david@redhat.com>
X-ClientProxiedBy: LO2P265CA0002.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:62::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB4573:EE_
X-MS-Office365-Filtering-Correlation-Id: a3c561d5-c0d7-46fe-f9a0-08dde65c296b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?kUMLk3MvHnXdcRflqSuqdQ2vj9rC8s/U3tVaT0XfZznWchW+wQRqEIJDW0wp?=
 =?us-ascii?Q?E0Spg5a/Fsw8N+7Y/XJPRhjr4vfS01/Am7cYu34NnoDn22NW+Xae8MBjOFVA?=
 =?us-ascii?Q?I24CbZTMI0RO/d8bEuBPY/11NkKUOa95IgrA35NQj3Y1cALrHSmZKkvFr88+?=
 =?us-ascii?Q?h7hewcVKC019U6tq//tmpS1wVsda8Cjz0BiGxqscPO0c9ip0kW49Vl3y3ZFt?=
 =?us-ascii?Q?GNdWpx6j9zoPrgFD0LehOIpHiQe0P0uHZSqIJVXBXguZ/jKZSK6pBOXGnPH5?=
 =?us-ascii?Q?8q0XtfYIabBqGrlvi5guTcomdsx4aYCKN5OE/hn3QzckifgRhvwrgcrBOgBp?=
 =?us-ascii?Q?FQukLSuKA1bKo27Ie5Ky43h5S1CkD238ZOkvZXDs8NXVi1C7ESrUY5tIKefm?=
 =?us-ascii?Q?PeqP7JcS3GR+y480AnL/6bMUCF93lyknY/f/JNIFIl4cBzH76uhsyilVZsGP?=
 =?us-ascii?Q?TG2PmSm7jI1W8cxMtx9NuN/RGofBpgoXrgaP4SaJ30UOWcZteDkGsOtL4olp?=
 =?us-ascii?Q?9QouFLl+K1+efunXzrJU2TDrWCmIki/MufU4Ka2A59zrnj8cb9qjsvLDnVsD?=
 =?us-ascii?Q?wcy9hyf7T85cpRReNGlf0cFE9kR4Uk3QWxc2mJ7vg4/brjBv0L/mWsHrwc6M?=
 =?us-ascii?Q?Relir9Kvp+MZuLe8OSAVQHzjqqOC13wWptSahsLD+a3pLlpnxnhWElJJx6dq?=
 =?us-ascii?Q?BjeMvFviEcJavjIRHSj20Af0ZUeAUPdxbzZ3RXG0LRfDKRSnJ9bOQHOe8gTd?=
 =?us-ascii?Q?DUgx5kZU8EWtQ3YxNfaFcZBNB8rZe33AbLelFWAFLrx6gduIj/QTu+kAZg6n?=
 =?us-ascii?Q?+w0Buyvfi497lo6xW5v3jyEnK1ckXGPrnMlrSSXgN495q/SJoJSmMWQDafee?=
 =?us-ascii?Q?2LNBqKozICjpO0nNm3bEQfH7suJ2OeluPPZz9zfcEtcHdCSWhktDWaXkO4+B?=
 =?us-ascii?Q?j4P7VrRf1Uk4FhW/XiCdGXlJqjGqlD0CNuYI8QK3qzUylA2LwDV+/VQTJwiL?=
 =?us-ascii?Q?8iHirfOGYyx3xUnUO/T+I8bjcZHtsEDmMb1sHTULvEsz46NWT1zvxoKMFH00?=
 =?us-ascii?Q?t9f3LSrGZAgLywNFeR507EDqFCcQ5Q+Nh9Yjc1qzg9MFcu6/CaCqToUw2y3b?=
 =?us-ascii?Q?/3CyeZr0MOvWMD+9Ouybpz7SH+5fTRm2DaDZEyQ1oa1zSmheK448whxk+VTK?=
 =?us-ascii?Q?lEzRSqpw6j3Zo0E8YBiMeXiP2f5U1s4uUXiPC8gtFZptr0eMWkng1eT9vOUL?=
 =?us-ascii?Q?1tXrdFztmHVZWPw1uRK3QFZQ1R4NeM+QfZDrGJwaUwjG4cRybMfrVnDbelIg?=
 =?us-ascii?Q?WHiKpCjenJP/uRvmH/mAkrD//ic62eOrqcsFdZWLcqCszwFC7ju/GXNZdyI3?=
 =?us-ascii?Q?Go0sDi7uEX7KrOEfTUbCuulTb95u1vYiw3xqIF7BH3svZxnj1g/+Uj7eq9kW?=
 =?us-ascii?Q?YmQ3DMjC68o=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?cW/WbED34VBpqlxHBjbNzPP9Lvn0ZuvtLRGCyZNIK3LuO2CCc0zs7rOrm+yM?=
 =?us-ascii?Q?AxRM3UlkGDA4WUucZRd3cWyECHg/VpTlZvLQ5gPRJoavABGb14JZgqJjWfVC?=
 =?us-ascii?Q?RQPIVZPY9KvucVX5Jyvlsm2J3ASN7AwgV09Luv4GRVVeg+ZKGL8D3WIEN4eE?=
 =?us-ascii?Q?X3sr6u1rqvW+jNS2a9UxQs4bGkoJybXSf2fEEehjmuMZN1KWv1CH7MAe2/UG?=
 =?us-ascii?Q?8H/D8p1jL6HfOKfCMgKkSC/vHlYTr19+KoPWFIdzFC3DVG7IHrILOD+xYdMq?=
 =?us-ascii?Q?LNn2cNBgz3yw9PTnqQgokKfzLdfhUYeZ2v6iMUtonCMAWfHNzBRy4QDu4eeI?=
 =?us-ascii?Q?RzYJ4X3ql9jJJ0vkVCIq7q/w+FLX5DnRgnzmFDYUCrTSD8QiZoXdXTBLB5jU?=
 =?us-ascii?Q?EPa8h59IhKXgoBJIpU04TmgvDbhwtMMPvXUI6IV9CzmQ/aMqoPFbrlPiMXQo?=
 =?us-ascii?Q?sVhUJLuHdIaDLaynTcbYlNOgoasNPMxA/UJ3ndA1v7o+kOAVgty3nPNBNE6T?=
 =?us-ascii?Q?/IaQruccIVcStcv6GWQ1EjRCIYU1WM4lak0bAB8pGPyT64pkWEr2L6u7yNTe?=
 =?us-ascii?Q?jSJnYqQRmvdHi+oRFlBGc1U00DcrOdTdm8rcTl6MCIqsWzbdzeAa6Kd3JmLA?=
 =?us-ascii?Q?cxXR31C+fo5sIKG0CgTpZSzfb5JJJk4MAl8b4m9NokruiM9feUr2aN8ZIjNq?=
 =?us-ascii?Q?gVnPi4XPuKghhx3c/O1QmWh3RD1zHq49kvH4ZPrwwFSHj8QaDFCiAC58hesW?=
 =?us-ascii?Q?hpNlGGLN9IPzMXBh1kHwEbJ6uThxoUwrI1lIydDNQujDI4qOYOsqaKIzedA7?=
 =?us-ascii?Q?VkeLQC+20+lIiBCZoLLU7T1W8I1N+bLZUi+m1N2wfx1kcO3yDGicchHcbYgk?=
 =?us-ascii?Q?bJgYHpYYtpphRFX0a54URMZwfNMt3R125O6tk+ePKsbjv1x5VOdl/640R/wj?=
 =?us-ascii?Q?QAHcDbrHEdBhFsTrGQ9W6nJEYgRg622ed8QB7MnXqFhvyA9LgqTkHJTCBzif?=
 =?us-ascii?Q?pgEZEX79vq7cQr2s1iflitwYdnU8SuIrytglz2NtF0YdpxadSUyiZCxLeiyH?=
 =?us-ascii?Q?Fizh3NVbzYct4pdK5Q0nLAIvPN6izlpMwJFWJnJOpafevkVRGNO1QRTGkiVN?=
 =?us-ascii?Q?f3mt991uXSTNwwFBdtnb2Ev9zSdK6CA23Ybu3B8vB0VTG7iHPF0lUtfzeNUH?=
 =?us-ascii?Q?9otDHK+RLlcrH97/jPDHwIzAL5q9JtbnW7wEK8PjUbQkddiWNW3P4Egabpyh?=
 =?us-ascii?Q?JhwUgj3G/VecsCGNlNu/E5NBO4Dp0wrs6cFzEDd8GIPMyQDsrRcRyr8BvtMy?=
 =?us-ascii?Q?nSzOrKviVSU5PfximTDQ45G1A1HIKqnwCu/dWZO6F4gkltuBHOq9VkX/g9OQ?=
 =?us-ascii?Q?h7SvfEMXXV80qeYdrXY9yJjjL9tbLsloXJywCGhcfh/jl0kI7WhLcssB458/?=
 =?us-ascii?Q?eqqvHjLvtq5UIWt6pucx0hq49w730oooaswACUp9zcca03OndeKnBeyM7KvC?=
 =?us-ascii?Q?zprBLRH3Jl/M5rfUPUcdjIsUztHSX2d7mP6nu4eu0DAlYYPYGS6/8EhBtk2c?=
 =?us-ascii?Q?6aljTxo/pC59Brx5eD1XQRpMFGre8CHrTvFn0UBukxijjc47xLCNIOfyDV7E?=
 =?us-ascii?Q?yg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Nc7pg2ZV6ofvP+1FkL+S7JZtbwVBdHE0vLUHVef26/dNMhumfBEHyVtvdQMdX+rmwIwGh/Jh9ubujzr37yZcSfElrYRevDbObrQS3NbXiSzBQi6BfP8wM8SvTMOmzne4s7l5FqMgavUJ/JznBaZXckTOfeuUQrfviG3nUKF18J+OnFBuEN3+qdDCuJiDQTi6oGKco9g/Y5mZq2k1SB32apSUeE4uIxS8LUybd+7V8nTWyr2M9Eg1FTr7lEHPXFAhjHJH8/NDiYN2TxFLH7TuO4UYAXrQjYYxWtSY0aQqinjPoc0dVFp9kivrgBL2cqU8QBNKKACtnMRyQjRVSXSkd9zO+8KClb6AwNJ6pHTiz7ojzFlHi3D9EhUVlivkqpxrBhx7DyukYOLUEn3lw1sOhOYHnZNUxLHbTSod6zHRVPlOkLPqVLoCHnAQD5FWZ9dRc/1Fu++kUFTpt00s8g2bgqgUS9nF/PiGusOXB+/a+DCTm1M48EmdPrjUcY1qstzt2mci3t/wEBuUqarjjkXkj+sZ+VFrGoLeZ8dR38nKf1FxwO75OzJrjxc3Shw4lM0kDRfBJ8aewhiGUsx1SyO6+RThE8OOYSWV46KQb5/1T2k=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a3c561d5-c0d7-46fe-f9a0-08dde65c296b
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:56:06.3501
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xml50MadeFYIfoxRnlPDUoM+PnmSp+3DshVR373WyTZik0HpUig6yq+qfs9PpUbQz13IpkR3OmG6pIL4OCizoWj9fdPmKOc7Oqwi8pfDFWU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4573
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280150
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxOCBTYWx0ZWRfXzxbAkjs+tYVa
 tuTp+E4lV2BlhSmtv+dNQinsfDbE1nXIARW4jIODDYd37veG7YPVN7e/d/y714hi1pIspfTsWPD
 bxFOmOJCJRgfqtlljJQRM8AgKYVvGzVv3zDKnx04/xYmTIUjobdWvcWIhq851LV3t8HlkJ3Lk8y
 HjK7t3Wlx7ngjPCAumTlomT/rNDwpb1L0Y6ZuxNHEbyJAsf4QuCCyvcAm0yO+oWORpnveOTRjGG
 i6ym4gg4Vp+mYvKV1M8mpKINP79Hvcez6wzHA4thkuyq6Wvdh+LgoGaLAZSzkRsz6LnvZLw3oup
 PheRxzsw2IJuGhnLgbAluQDe2eSaxsi0tzRRzND7cTtEz0Z4lb5u144FTqU9SBaAYUIKGCKsMXX
 h8bbS1Td
X-Proofpoint-GUID: qrtNC7EmAmfMPZLfcyitJb37bF1z6sPa
X-Authority-Analysis: v=2.4 cv=IZWHWXqa c=1 sm=1 tr=0 ts=68b0983e b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=QyXUC8HyAAAA:8 a=GFqr32JmAAAA:8
 a=pGLkceISAAAA:8 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=eiIDkS6aHa7fVuAjpOMA:9
 a=CjuIK1q_8ugA:10 a=f02Ha7HRcztGgdyUxOxW:22
X-Proofpoint-ORIG-GUID: qrtNC7EmAmfMPZLfcyitJb37bF1z6sPa
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=dPrKQsul;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=cGpZPlJZ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Aug 28, 2025 at 12:01:29AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Cc: Jani Nikula <jani.nikula@linux.intel.com>
> Cc: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
> Cc: Rodrigo Vivi <rodrigo.vivi@intel.com>
> Cc: Tvrtko Ursulin <tursulin@ursulin.net>
> Cc: David Airlie <airlied@gmail.com>
> Cc: Simona Vetter <simona@ffwll.ch>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/gpu/drm/i915/gem/i915_gem_pages.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> index c16a57160b262..031d7acc16142 100644
> --- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> +++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
> @@ -779,7 +779,7 @@ __i915_gem_object_get_page(struct drm_i915_gem_object *obj, pgoff_t n)
>  	GEM_BUG_ON(!i915_gem_object_has_struct_page(obj));
>
>  	sg = i915_gem_object_get_sg(obj, n, &offset);
> -	return nth_page(sg_page(sg), offset);
> +	return sg_page(sg) + offset;
>  }
>
>  /* Like i915_gem_object_get_page(), but mark the returned page dirty */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f5d12153-f14c-427e-8294-8b8b44485895%40lucifer.local.
