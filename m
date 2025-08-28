Return-Path: <kasan-dev+bncBD6LBUWO5UMBBMWXYHCQMGQEZRSFY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16312B3A27C
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:46:13 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-327d1fea06esf162139a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:46:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756392370; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qcn8dJoKRFFLhMu0wGtr+okGlU2EjYWcYCj4kcDx71RdLM++PHYrv/Spx5jz7oi0XW
         N/3vOZpk5lMxDtA/XQuBLoupzogK5DMGzGE9/UONiJUOCvfjMN66iT8z69abJmcEey07
         oRsziKPo/PSI7Ph/W82UFY5psah+yeJafFrItvyXC8rIihbCzGx9/ckqoxgo1ZbBB8C1
         836KTgg4yXJtPQmoaZ/u9ZqPBp4uN8s1OfWE/gCywUsI78avhj2ohs79BZa5C1g9ebuy
         IRVBPBide4BQLhwy+NEIk25yuuwm3BeTgdcJHGxIdYuKGziB/3Ba/9IX/QQpzxfCAGRt
         keng==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NkJW2ZHoSUgRf824RT2uVfugo10jTL8HcGGVpMaYVU8=;
        fh=iBmu9U6GzcToRn61WCgkHijFf+ok4Ic/mTRFabNLMos=;
        b=TLg0grDH3pzhSO8u43zgiPHBOgowLUND3Zz9+RuZaE6+VKmOtZqZZOY7s/MDabQHXI
         twLXJiCLpQe2UvYzBCVusa/5Zy81ZYW3HqgdMZAghPKyx39vPMRRlZth+mAaWkTa1xBR
         nOxaej2Qo1fD5zXR68QpSKaao55Jp1hDmzlz9IyQpcRxKRHTkK3FFLViq0Ne/hdro0cU
         mxJLghDiKJXLSRwoc1HV4kI2V1rO1es6bkhXoUNmopqnhUgDJStcNVdyb+nlSl77kyYp
         DGmpivVFILp7klvMfX25sfLmbPaVjWhpVXpGRJtoU8saHMj6b2SbyY/mHiw4pqswrl1h
         48zQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=q8KoGuqQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XxG0pQFp;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756392370; x=1756997170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NkJW2ZHoSUgRf824RT2uVfugo10jTL8HcGGVpMaYVU8=;
        b=vDZwYAr0IWLBv7hFKm/XIoitVWsSiWCXShg/J3gJXbjOiJmDqPVDpvVYYRefy0+h59
         B8h1ZB/fPxoYd7ss78QceuzCCaO4BP66Zf2Yvvp3uUf45ycmfHz++jubDc+kQXPPt+D6
         7vpOGHXa9DO9g60UX5nFz/LRfwfLx2sS9/j+p20JNpoCQMjLnUIpAbner0CM1OfLrgtT
         tK6DTzESr1RdB3CQ0t4yH9cDLwVjjaKfwFOV5USY3CK7dbFF6Ah2QKEoK+g7AQkKS6Lc
         NEZRvGrcikli8V3YU2dX1nAGncSGrSJxVmvjwMR0/0RjKkA7fJ0mxQAkAGnRYaS62nzv
         0r+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756392370; x=1756997170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NkJW2ZHoSUgRf824RT2uVfugo10jTL8HcGGVpMaYVU8=;
        b=c46QvkCVJS6bt7QHnaILYS+/NmZlnhLpEOnJSi0LH+PBfK8qdeCTrezClfq1vyyzcE
         M3zlKFjrlRnikKbBZ4ZV20c5x13akSrw9nIv5oFxSXLTf0iqtJ7M+frURXFWi00D8BqI
         j1Q/bb9eDHu2sy4kGtF3qoV51K72xBCR4BP8zmywqFYWICLrxgZF46dXPlmoGgnYAIlF
         XgT+epp5giWdYCjl4mxvxTat5L10H2Qnw/bS2OeO/N41Rdh8P+CJFrkpuegGu0s/OovZ
         4Jyp4WO+0A0eEqQwiFASGNuMQrt4cmEKRIJsu3vei5KPHC7+KZmabeG02arZT9z7otol
         YDZQ==
X-Forwarded-Encrypted: i=3; AJvYcCWHKMl6OhhkOAiddhuJHCV7ZCcOLg/DCzYFAQJ720+wMwU7XkTlBtzYWeNLY+DG4gXEp2GEQg==@lfdr.de
X-Gm-Message-State: AOJu0YyaK9ur0arULXyedK+Cb2jA4yQFU1m1NSVquv0JxV90qcE55Qfe
	37RWIjMaBBTn0DZdYuPniMXMKjl3zU3GORwFG2Qo/chzqX384XdoGNtZ
X-Google-Smtp-Source: AGHT+IHjMUCklQjR9LKqgKM4eQ3hm2FoOVV4HJ5JCzr5DKeBxUEEPBJMK47c82xsGpl2faDDmNxerA==
X-Received: by 2002:a17:90b:388b:b0:325:40a8:56e0 with SMTP id 98e67ed59e1d1-32540a8583amr24480953a91.30.1756392370397;
        Thu, 28 Aug 2025 07:46:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZchzel3gB0H5zioJvlllwJi2DAQ979uJ0V3PvMaA45+Cg==
Received: by 2002:a17:90a:116:b0:325:c01f:f69 with SMTP id 98e67ed59e1d1-327aacde593ls886774a91.1.-pod-prod-07-us;
 Thu, 28 Aug 2025 07:46:09 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVh04P1I/sDGJ1YDTDT7u3/MHGrGvwFOtrSgf2oLvdYXK68rrdDdAt8MpMnAq3hKUFVZ4woVIw3IUA=@googlegroups.com
X-Received: by 2002:a17:90a:e7cb:b0:327:a665:da89 with SMTP id 98e67ed59e1d1-327a665dc18mr4396664a91.18.1756392369014;
        Thu, 28 Aug 2025 07:46:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756392369; cv=pass;
        d=google.com; s=arc-20240605;
        b=LpMI4hUCTiXXgC26cqF07t7kNQYayy7/BH57RdB9PYi+NrKa/Rcbegr49jExcpsTFh
         ty7ajp1txplS+vR7t0X6qpjjvHpxEXSAONPMBsQk7I4glhTBzmMzKZOVvcDUxkhtFkx+
         8E4ELpw0RWBscwBV5IIPqxGeOhV6tOwaY+hMNS+ZKIV4I5nc2oBhixaEWXVQpuHNe9Ss
         Mv0BefNfSaGp2gZBG9w/TcTX5ZiAxJIvDrcWCRJOpfLufH2xSPZ3HnDGwbPa8+jGW67L
         /Vu65Jl8uvC+NAX4crUrFvIBCclcsaMXKmqLfeBqu4IV2YZoS3yQueSHVDvvFK0/zM5g
         E63g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=wOJ0ZfETJtm2MQBK//l66cwel20ugHvoMZ5M+Vvu2Zw=;
        fh=nDVLMfpnt16dAvQHlJ/+ZWR3WaZCA+P2x3XNdYCnLhM=;
        b=dLCJEPK/LvuQ89zYZ6TvcIxc9wfPg/lWx/gWAHT3KpRLswErKuGllCSoJ5HvgorlLG
         uUFJbBIDnrlhriARutV020XxlD0taISne4gjcH+rTVQUSkMPT2mEXGyJ0WYplXW4RkC3
         x8PcRqfiEnFQURjpkBbTmuLxFhBouLHr3FNs02I6dRSACGy2jWfis4e7OLD17VbyknZm
         V++9Ps5sylXaIFYXysJO+TD8lENtoKLnGlItwtHLyHY9hJMCVYnhkP0ZROyMl2qvAGty
         K2PmFcV4dJsNS0yHr8jnsSD2tB2tOqYSbSit/al4lt9lBODH8kUcijvS7paXcYr8e879
         TRug==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=q8KoGuqQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XxG0pQFp;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327415067d9si379455a91.0.2025.08.28.07.46.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 07:46:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SENH1k024524;
	Thu, 28 Aug 2025 14:45:55 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q48errxx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:45:55 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SDtQ5E027313;
	Thu, 28 Aug 2025 14:45:54 GMT
Received: from nam10-mw2-obe.outbound.protection.outlook.com (mail-mw2nam10on2043.outbound.protection.outlook.com [40.107.94.43])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43burj4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:45:54 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sU4TVzZ7eBK2NKH/joqJJoi1F927Adma6LoQ5lIGdNnBuZAArvtzcetZP1lHNAGW3Z6iWDniNgoVEk7Dcz2r4zAshfkhisU8PyErFoTbIS38LkmAYJ648/leqhcs8MLaJpLHcOaZ+8y0PJ7BKb1D46yNlASFhyiIsR1Fay/hmVz310EPRZH/m4MH5mBrRtbWcHphkEmZmO2DZ/RbWOGBNjLrAkN70Mle9RlXnOs/INQLGrN9wDKUsXfbBhiwDu34nr7K/YRubvOkXvNs1bEnI4U2B2hZVubdDCTtLpQpcelgcR0G4ovnR2IorhYrJ9fkAKeTiCBrRxcwH+dFBvvThQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wOJ0ZfETJtm2MQBK//l66cwel20ugHvoMZ5M+Vvu2Zw=;
 b=dGOjHfb5yI/APwVS4Rsz3TH+xHNjL9Yqqw9ACfgZ1QK/BaewpOBtsbBcFC838BsK95kAbAXWYyahqaWlopsXDXd57Od3T34F/sJGPXsp5oZURRRSW/dVQWxsF+9DUjOymI+c4gxn4LO2rXqKUl87tONuCR2iF8iBqIckzqmfZLcDiTOOPdkL+9IoGOqzZW4YRaiL2hluQYx9d9rWmNDtXZs/DF0jhz0jS/c8q4GKZExHrjeZHLEKZXCSYs7eUWfPsL4RoNfzESd3FJIlwRRtHw7DbheFv+/GSS4p/ZXT6BRLX0vZ/brzMEMpRyDefDDlttnTHgD/TUiFyDZVqpguQA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH3PR10MB7530.namprd10.prod.outlook.com (2603:10b6:610:155::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 14:45:47 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 14:45:47 +0000
Date: Thu, 28 Aug 2025 15:45:39 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH v1 08/36] mm/hugetlb: check for unreasonable folio sizes
 when registering hstate
Message-ID: <fa3425dd-df25-4a0b-a27e-614c81d301c4@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-9-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-9-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0422.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18b::13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH3PR10MB7530:EE_
X-MS-Office365-Filtering-Correlation-Id: 40cc3033-4fe2-46c8-871b-08dde641930d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?sVaOtQgISIAtr1D8WGPkgV8r9k9NkDcDY4YsgvlcDHKBPHOojGeneot0ASdL?=
 =?us-ascii?Q?14OSc7znWUlv4xO7pzB9t6KH45Jv6YLApk06cchu5RQh4ogXUi3y5a3/Sz95?=
 =?us-ascii?Q?e0XRZrRYLwZwb9PMGloQKqnvrs9mxXL9oiqT1x9H2bSnLBPZUADP2ZuYp2g8?=
 =?us-ascii?Q?+wcrj/dHIXPapccVMnvSvUnRNvtctDCEAxRtWzf+jNLycM3BBqKBugy0Fff4?=
 =?us-ascii?Q?TFlm9l6TiL0jpdDd9PPwSlB7Huh0fsR9+fJjro0gcYB9lRHpVGXTS8ysanGt?=
 =?us-ascii?Q?QVDRMX06Pq5rRDqbG5dwaK/kFlwldiM3zEVr7PImAJ+QPX/0pXxxxVkUBYFx?=
 =?us-ascii?Q?Y43/fNyx/+mwvdxMqCXyvjvoWrl199jpsci7lpPWQ8oceGb0Tv4C621cDXDG?=
 =?us-ascii?Q?PwtrmwoUfFB3M8MrEW6MHB9VO/PR2LcIIMnaCz71t5Je84CjsreuNeJaPbgR?=
 =?us-ascii?Q?YcDLI/6YevuWEwPkiIgmLdSlhM7NEhcoUL+jZ+D5yfi4QyB6GwUQfVSbjc+0?=
 =?us-ascii?Q?89bUcYzzvKa5PfOktxtZWLu0ol2N/3oXPSyfFJfmHUV13bE7Bhg5+JSIOd4Z?=
 =?us-ascii?Q?W6V/jwHq+RP2+UlM2hKF8vICGGYzoVIiDSUwjd+ZB7VrjF8tTtmu85hAw3jh?=
 =?us-ascii?Q?gv84D+9tvKZ29cwOC0VOXpsyJr7S/Uw12lbROOUgeYcOnZ07rYmooLmXfgcH?=
 =?us-ascii?Q?PRYHq3yMDjjUhtFt2YhKvj5ktHPeiFrGspJJLSb8ujEPzIn4/evH8i1nC+Jx?=
 =?us-ascii?Q?1T8X11UJHSCHKO0oMyspIRlX9n0dl1B8wRayWB2pzwWuSRDzSTixQoMWaH/K?=
 =?us-ascii?Q?AU5NctfBanOlX/XUV1uEY0aYcGfqDb/mGFmw5t/PuILRilP3qYjlYhHwdk4q?=
 =?us-ascii?Q?sPhblrrh6PX+cSC/frWA25YQsPcmi89cQLif8TeOLE7BRNWkx6EDJVmLr7fe?=
 =?us-ascii?Q?UHK6pQHPW5tqJ327WKqV/WbpJ0wBHgTdweHtCB8XMP8LGtyPSmenqvO6wMfe?=
 =?us-ascii?Q?483I8DYcYu6/rwwkIX3i3J4Q04pn9Zc4hhXQdpNO+YbT0fOFO3NvX6rDHE+h?=
 =?us-ascii?Q?7RcPi/JJGGwoFaed2Em/j7qr30DdIDyCcvocTNuEGOWbeCIboVatkFmlfTgM?=
 =?us-ascii?Q?8WbzwrNFMOVdF58XJ4diwlvz2HrfdXQTONoskX4nOGWv4TfX8QBflkwUM0XN?=
 =?us-ascii?Q?s9UBda8LE+Uqopjf4hkI+x9Ru+0ZJtbSxxvmdu96rYe4C4QXpi2Dh0aqYdBo?=
 =?us-ascii?Q?jLxStXyoVDlsFPy6ZLbOjQc8IkIn7jLSz/tkrLWsd1Bx/fmufnMt7T/u+sJR?=
 =?us-ascii?Q?Ba3hhipffsslwxDkJA8nq+pWffgK7jz9pEu1jxv/pSxrOnpzwMWXX+NyjMwu?=
 =?us-ascii?Q?7RjipgBQPq5XQZWdEpOrzhFfwwiDMVq/7WVN1dghBT2+B52B9GGNvGqbjjSY?=
 =?us-ascii?Q?ci4epALYN70=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Y5ikJeMC3zmMyoqeBaQYjUa+pqQeAqkLMmSpQVZ32Om/8Cnrvpt4weU9NYSi?=
 =?us-ascii?Q?e+oH8QunvWLjVOjsHEBJAjW6XlZALMo6e9nYWW75ZGINg5cAmP1Aynry3zEz?=
 =?us-ascii?Q?hS3K4bvtHVthKH3xbLGHjCrnMfifTOOyZki8cZWvggHAwjGMBut+brQRWBii?=
 =?us-ascii?Q?FwcxGOq9c8fz3c5hr/EINNVzIbgBYvK22/2gWKB//s9mhi67ffPVtZnWSPJ1?=
 =?us-ascii?Q?f0zyUWDHAeI7oG5FjtXVDBhBQnCiSBD7lccVLscsU+1suSpq2OpMTsVD3G99?=
 =?us-ascii?Q?EgrkZbydJfEG7NIQ8NyrE4GHYtZu9peEM+FMFB7CXIcY+IoxCwm/Sq9G4vTg?=
 =?us-ascii?Q?vXJC5xpAZz+rqEPTW47p802pubSkeao8A07YAoSwy4q/IB0FE0OYYUJnHcQH?=
 =?us-ascii?Q?sDgKjL5FGCHjGIqEAnyUIsuwuYFzwa0rfHomyjWEcpOE0yLqBUUROGn3XIyO?=
 =?us-ascii?Q?DWpebCAKIXgz9VQX2NiOLLmWCBfEAE0VHXuxShzz5BECFy2idVptaxOXr+XS?=
 =?us-ascii?Q?gtPv4RuCdYRAY23KUNxB4xJzlZ50ZD/eeMv3XOThM3lgqKLq6XXohckcVhQT?=
 =?us-ascii?Q?RKt5ydSfIN4kH2D8BV4n6nTPPJjOhnIDGAUBVKhMGqYMzqcjaQpBEgDc2w2O?=
 =?us-ascii?Q?eL6Hyxc5iUiweD5tnPCnsNq8qG/ZwxJA+xrTidjs8cGFQxWFVxxxENuUzUZ0?=
 =?us-ascii?Q?94j8vYLKDgluHJ34eiEJs4O+eSq7IIS934QZUztzLBD6Xm4v3u6outQP/+QM?=
 =?us-ascii?Q?Po1X3QUg4qXL6H5lq7fVFMfxq4nlNtyqy8+KF9yGAMJiERFH5Q1vnnWOIoR+?=
 =?us-ascii?Q?xN3DyNywZVtb+HobPrCGz1ubKNeugIonnOmEqVCwq8R02DmTbKOB3w80zTiW?=
 =?us-ascii?Q?+kYjSQ+t6f/OQ4iB18pUOKKp6dHcDxOOPGjar+omccJZGLmxRcBtkHK7z1ve?=
 =?us-ascii?Q?KCnxKTS56m541tlp/Kce5QX/rZ82F7/Yo0tH4Z+X0tATwsodtSAfZrRLyHpZ?=
 =?us-ascii?Q?2RuKSyPJcBjIC0Fm1RUHnXiFsF0hcIIRnjcPJdBSGTzTdgQJGjFFJYn29duD?=
 =?us-ascii?Q?lbq+JAZJ4EeFUoJAu+lpYTL5KM8ZT+RxqwMLzOdhBFNtPpJosHzs4/aKIeqs?=
 =?us-ascii?Q?a8h8CLSM/U6fkbQXwQYJ/VLsljUMa2jKsIj9aUY+vLPaq8QmZNt3Suo5i0Md?=
 =?us-ascii?Q?DSF7CRLUfkYmlyvP+U24V5DHddVT+VeIylq+/1drcssNZ6jIpZSj5d4IU8j2?=
 =?us-ascii?Q?6UMFCzXYH1FGGD9RJBZgyNtZP9GMcQD4Z8srapAWG/371iJJWrbxURAJHxX8?=
 =?us-ascii?Q?1ztZkE1eaokXRFGNrgJhlA3mIeGpf1NDs7TQaq5EDV1DdkYuNmqyKgdQhaW6?=
 =?us-ascii?Q?/4EdtDYK5WHsOEskwZPvJIVPt3kifkn9nOAyFvjOLG1wxLvS8l76fsYwKQ7a?=
 =?us-ascii?Q?VEdzU/1s+0Z7mqczmCmc1B3NYGIhCjdRGDRZ+nxdZZ7J87myAbUaoLlbqKBs?=
 =?us-ascii?Q?x3Xkw+qroupWY2ZG5fMxbCWvIW54xbFiFl0eLTNem9TG4bnBomZImYRzm+mQ?=
 =?us-ascii?Q?N4rxz4hyIfwG1CoAZVRLG+Sj86H5tZ6wue/1uBxq9nOVHNhD2dlvH+hOlDXV?=
 =?us-ascii?Q?Rg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 7YiiDieuljhinE+0Eg0agrUS5WxqXKbmNwN1pADXO4BMqniudB6OQYXmMjgbIU6bcGHYYHt+XFOURGgoAAVDPNlpNAoMz2VXUOYqeYN3Q8xKPFefaV+hqULk2UyWIArqgwd9OOzh5/ASpuYMdRkJAeNy6ws2p1RAlJRqMr+2r4dFABWzQDInoAPvQB6e5CbF033twlrIts69Wl6wGo9X01yrwrLFIpez0BOhndwk67ld8uto2cNo39segCrCA1FbuAbXg0Z1epvMynq/fqoizQQ5Wb9tP7vbsEzgI55xr1SL1jShUUsonRW2gGJYoAHrWfPjlpexfdsdmDJKPKgSrzH7fw6vywu9h5SPkuyj9KXj4RP1QYlIAYz6U9U2TNIYdpM8E6efIP1KXcLZYbOkpPBtW1dTTR9XWuaQ6QLlLJT5RMJMfGf/kLw7dzIXHjAF1k3FIxUi0zEcrwIXKzb2S4CQJ0FAZ8qgl0BPYc/31xC+qjopo+crZe0bR/UvcN5htmx1kXb6yeRIA1QGczNUNJ7EjU8iHMz5KocIqjBNVCG9B/ksNQKtArcsurSlzx65KyRj1hxHSQDuoumPOgl/0s5eC++5qA+YiO8LB2aSHxE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 40cc3033-4fe2-46c8-871b-08dde641930d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:45:47.1735
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: toN5GIq5HdgHC/+W/X1VH5g6PItucSbripLmPDmzNyEVLnSdNy2UaNqDsEvUQXL5KzHEtGGMLQf2AJOiEvrXA6xDkYvVVDUKBtT+xWtLAeQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7530
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 bulkscore=0 malwarescore=0
 adultscore=0 phishscore=0 suspectscore=0 mlxlogscore=999 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280124
X-Proofpoint-GUID: UY-aZ_0k4KZBPJh5SQO_D9BXJ1eGFdM9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNCBTYWx0ZWRfXxVO9nhg6tKhm
 GWvB57uAbN1h8HfJQsqwVYi1kddfDdzMGbnAIIpf0s1luwOy7ejt8Ssy2TpQHfVjdZ5V22W8mPT
 dMRI6Z8stBaDnEtR26rFI0bbeTmKWzCD0y6t/ybf21wD0L2jY+iUTJ7+hP7Rd868bIHpMDuJfDD
 z6pTyxLP1VGrdEH8iFDR/6+C5bq6NKAWr13wdy89AvLHpscRZsKbjXK03TvIVVNGptU+ac/PhXU
 Lc80Ug5/48JOSVkfGbtaar3ODEcfd+LwH1SYjGpGIl23ivReju2iDjVfjnw1VmlUqHAgSq0Ef8J
 XFrkYUQKWqP1zOQl7qZti2T9O+ukcsHP3QW+i9X5820AbwE/d80DTgEsZf2J9tRJT+hcNsarkcr
 Aj9yWu+V
X-Authority-Analysis: v=2.4 cv=FtgF/3rq c=1 sm=1 tr=0 ts=68b06ba3 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8
 a=AC1hTx7W2U6TmaToLwYA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: UY-aZ_0k4KZBPJh5SQO_D9BXJ1eGFdM9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=q8KoGuqQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=XxG0pQFp;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:12AM +0200, David Hildenbrand wrote:
> Let's check that no hstate that corresponds to an unreasonable folio size
> is registered by an architecture. If we were to succeed registering, we
> could later try allocating an unsupported gigantic folio size.
>
> Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
> is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we have
> to use a BUILD_BUG_ON_INVALID() to make it compile.
>
> No existing kernel configuration should be able to trigger this check:
> either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
> gigantic folios will not exceed a memory section (the case on sparse).

I am guessing it's implicit that MAX_FOLIO_ORDER <= section size?

>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/hugetlb.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> index 572b6f7772841..4a97e4f14c0dc 100644
> --- a/mm/hugetlb.c
> +++ b/mm/hugetlb.c
> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>
>  	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
>  			__NR_HPAGEFLAGS);
> +	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
>
>  	if (!hugepages_supported()) {
>  		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
>  	}
>  	BUG_ON(hugetlb_max_hstate >= HUGE_MAX_HSTATE);
>  	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
> +	WARN_ON(order > MAX_FOLIO_ORDER);
>  	h = &hstates[hugetlb_max_hstate++];
>  	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
>  	h->order = order;
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fa3425dd-df25-4a0b-a27e-614c81d301c4%40lucifer.local.
