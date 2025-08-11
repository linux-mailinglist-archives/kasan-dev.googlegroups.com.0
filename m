Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJND47CAMGQEIM6ZZUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8126DB2075E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 13:19:14 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3e401ca74fbsf54800105ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 04:19:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754911141; cv=pass;
        d=google.com; s=arc-20240605;
        b=HUcO5l8e7AbKWOtpZ+Sy7VI4V4w8PLkmAe/C81+VxiPW9mr5kQEgEfLZIcS1ez3NY3
         5WLC7RyLAFFyWSQVPN6LXp06itg8h7exHNxbsyeKA/8KpMw+teT/HoqponB7A+MD76Sg
         XeaTL9jyGS+smeqKkwznNQSd6Izl98azu4kpDElTOw70rDlhcrcZgDQaFDpPiwhUIjGX
         BoAopMTolZQ24GjRbG9qdEaoGg7jInRo76j7jiDhdaaz+tDQWuHbWvE8f7zfsuIjP4TT
         QUyD4jy5hlJG9zlvZWF01t18Fw6lAfpzQNHqwi3/F4ebRs2YIdg3S3GiiJW7FBNbdWGH
         b7QQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=K5nd9KnOrqMyacTv8B2Z+O6M36Wf97v9ofCZMCPC52U=;
        fh=1pehrLUcC3R/SES8lgbAN/1Ghhp5CEmlx6Y52GUszCA=;
        b=PkvecmKhYdjtnsYA6RoFHtQIZelyDypnBHtzC0Zw1xmQ6ZBhNA+ePftIqVDKUqboLm
         M9eowYxd+wI4BEwAES4/BWIb33AYmGfXYAzcOStlI0CWO5B892K8LTcQ/pG1yvy1XfT7
         K6WqSB/f5uCl2Xcjn6HDvngTPXpQS/X7jRCFIHpwlLVHONRDxuHth+Jnl+v7pOYNQ4KJ
         csEjuhQ48FmtiFu7Z6UPEoh79dmDhtQHMGq74JA0SCKz4KoGfNfPma35G1fGyFKtruNn
         tKiqs68KP5HjOw7ZH8fnh72AS9FIvhJsfx4E1wwTI7v/qkwB/o8mieITBQlX/snAgVQM
         GIGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ku1TrKJJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Chvc3ltS;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754911141; x=1755515941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=K5nd9KnOrqMyacTv8B2Z+O6M36Wf97v9ofCZMCPC52U=;
        b=u0Xghhofqf6oox4+j/tvO1usLfJo1QbanrJO32lK+OjrE83MN617vz0CECKclcRkC9
         V9Tgb4tICo2hHsZhRx+V+37R2zCFEn8tV+soS9pn6q2OetWi9juNqxsxfsRuEQUPzAOu
         A3192mJUZGRCGqjHs2sP6Vq/fCR2WJ+LOBjhVX77Hcv692Grp3Tvr8ecxZ1gXJW0vcWr
         jfGLADdvN0yf3QbKbrdyi9Qff4HAg/N670f9vK1Cr6XChumcx7pTXVCQUeL2mFwPpBiN
         4yfoFl12wuvDdDyIfqAu/WWHeYmkw0QilwvLPC6iQYAswGijZ5TKJDFPxsOP9moRk9Q4
         8OXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754911141; x=1755515941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K5nd9KnOrqMyacTv8B2Z+O6M36Wf97v9ofCZMCPC52U=;
        b=jGqFad2zxwQiNDBq6kWu8SGAygRSJgcKBvNIVFdEheQ6J2i8EsGx56Z1WE11NbcSQ6
         bIfEohtvbHGYCqUn9WAQBMEoCZh8UyHm4/8Q4QkQSz2bxxBFGje5tO0AGDiiUynUU3EM
         4nJGl+xi3SQPe0R6SM/mM8/yVT/5KSS/iySAgP3HBVplwuyFJGzr1alU/G2BLTiQmAfa
         OekxZA1imLIytURl+xAsnRSd3hQwl79AKSyj4ER9c41IBO+GHoA1l7NQjhh2DHuJvpqV
         6nsFuq44Iw4IwO41lRCi3Ig8DIJVmWIVbftUmFA5UXDSnRUxYyX6koWt99T3luaKvKXA
         bR/g==
X-Forwarded-Encrypted: i=3; AJvYcCVUTDX8ryKzhurs0G/p/LEpVVmL+CLa1ZUQXfey1AUIs3Ks+wjppx6b9o/aXRfxO1qdw+fEkg==@lfdr.de
X-Gm-Message-State: AOJu0YzMl6CCYOdzwi2SFUp1kQ5ZaLATuNMGE4SxhtU4BsrtTFURm9w1
	BD3BlX4ugPrUkkNu9UR6HGi70qCfLt/L2/bgtPk7dSafF0ZnWwqlqVuT
X-Google-Smtp-Source: AGHT+IHqQelmG6o5Vdby9hzzochpgakNVUE+wJQXwPxoNSlrrBd38/vtpptfQHNNvZ1oogw8BYPiUA==
X-Received: by 2002:a05:6e02:4811:b0:3e5:4002:e834 with SMTP id e9e14a558f8ab-3e54002eabdmr110341875ab.0.1754911141501;
        Mon, 11 Aug 2025 04:19:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcq1DPuYsIWBrjOsGsd3FaqrXhs6/zkI9g4h0eRshvCWw==
Received: by 2002:a05:6e02:1848:b0:3e5:5703:c19a with SMTP id
 e9e14a558f8ab-3e55703d6b3ls2116995ab.1.-pod-prod-09-us; Mon, 11 Aug 2025
 04:19:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWvbKXdEJQqA231h5W/A082JSX8CA/JW05aPl6F2YNqUG5RiJOE9IAlcNaeU/1NjtFnR8A7dyezQL8=@googlegroups.com
X-Received: by 2002:a05:6e02:4811:b0:3e5:4002:e834 with SMTP id e9e14a558f8ab-3e54002eabdmr110341035ab.0.1754911140634;
        Mon, 11 Aug 2025 04:19:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754911140; cv=pass;
        d=google.com; s=arc-20240605;
        b=EiyvcBTVu+IAUqGcTOeuKfbmfmt9rVUOZzwgTGycxY6uJPdFd8w+Ons4qIb1cHaYwh
         wribtAtfFHMQ0XLrcBQCtQFD60FQzw+UFUrSBEpwvWQQVYZoc9Yx9t2R3nRNbNgboMfy
         /WSdzeAZQdViNRUKFAi2d5NAUkPjBQKYbRDphVWtLIE4Kn9eh7A/nunmBBNG4wggv5VT
         Y4CsTCPe79qTZScJFoqV8J91NT3QG15GXETkLSmxI6g2uVgkg/3T+dRpR102o+mUPX6j
         mAOltFEJnwDXzC5k26unR4tPru03A8EAp386waddDunT/IMPWjo9hQBZ/xpYBXBhP2oP
         tDfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=ChgID222U7AyEZTdsqmAYzdsQ6moDMyw0Vlv3NeNVEM=;
        fh=PLQgFxTRLyhcg3N9pmSi1Fg/j2fHtLGfM3ZloGi4B4Q=;
        b=KkYFG7lvns5f3fc3hN3e1mqosBdtKiQYFQycDBUIaCowsylOPArsrioVM6McaAukSk
         YhMRgos6q/kUU5DFoLFaiLPyWk0aigNrX2QWdpTNYEHiG5YnJp9wl96xKlDDnbhAOW0C
         fARA/4+U24pPovmcMUWWvMAXHzjPXQPmZguwew7clTcENgtLBAzy06TaPeXxziYfuwC3
         qKzc8LxvUj4Fvhi7iDmQQdycdaH4Cu350QTFC0+6+7O7/AUmSQIA6n+2njYLQO3xYD3l
         l8ZY6TsyFSbD5MEgD4dOWKxJm9xfuMIpZx+magmcOEVANQygjImCr/nWXJhPht1ckLf3
         kNfA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ku1TrKJJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Chvc3ltS;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e5535f6efdsi607375ab.4.2025.08.11.04.19.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Aug 2025 04:19:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B5uCk8007909;
	Mon, 11 Aug 2025 11:18:43 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw8ea8sq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 11:18:42 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57BBA9iA030150;
	Mon, 11 Aug 2025 11:18:42 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02on2078.outbound.protection.outlook.com [40.107.96.78])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs8gpa9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 11:18:42 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=eIAT61y32qt7NhwQXmxTmZHE/TFkgE3IjZat+i+aWJh9IU9oZQ566CDaLpfxoap9h/cBssg5HQGNZJhrQ3hclBgkfYXaFUU3SH3LZcFMWKdaZWeEMIjxwi3xjc4yVnDGk4LwV3DOjaAK0Hm6vp+69zHrsw95As3ZLsSFxo9zmRPuXmlQCzbd7l1TdEtgmiJ8NjXamjXU95DzHaMSDYsVxd12zxlczIQ/pWDECQUrrTcQUeLDetoHWm2X9VZdRpp351+Btf0bQwT3rdSos/DSjXkDf+oB+qZJEt1UOHDhzR4gFDXJxzcF2yM6osrMFd4NNdvsgIJpBh2M0azIpR3X9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ChgID222U7AyEZTdsqmAYzdsQ6moDMyw0Vlv3NeNVEM=;
 b=lABUjL5O2GD4LTeiexH56o901JYMvqO5cR/xs1SaXum59fJAsiruiAwYcA/SuVkK1Vp6LyvYqX3ztPedbcJDixTniAUFmeBPreBOBbvOrMo9tR3G4sWusxH9I5cX3SRP7Bt9ieLiPrXaBrBPI/g+zWXw4b9bsNi49/umIWiSyR7h6mI0gw3UIbvZ5TTzaIWQvGjl+VTcco7ijf/cxMaN0CPULwDInVKhWCTU+kG6SIjOOwjkl4og1+fMGMFF0lqTLN/qpmxPjL4Vn1A5cfBo8cPj7OheEVgVXDtxg1+ERmlx5Ya0/lfEM8/hF9vonEeLUttZp8aeouGApjoqcgIw/g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS4PPF6ABE13187.namprd10.prod.outlook.com (2603:10b6:f:fc00::d24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 11:18:37 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 11:18:37 +0000
Date: Mon, 11 Aug 2025 12:18:32 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>, Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <30545fd0-fd5a-47bb-bdb4-91246379b97c@lucifer.local>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
 <1e8ca159-bf4a-47ab-b965-c7e30ad51b28@lucifer.local>
 <aJnHvvb-lViNA5EQ@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJnHvvb-lViNA5EQ@hyeyoo>
X-ClientProxiedBy: MM0P280CA0020.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:190:a::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS4PPF6ABE13187:EE_
X-MS-Office365-Filtering-Correlation-Id: 79d18096-0fa0-4715-b4e2-08ddd8c8d110
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zIJd8VeXTjQtcXwo/8tRgg9jqCOCVys5TeJ4F52glLNzhjBiLet4v5RsEgCr?=
 =?us-ascii?Q?7jAixDEfzg9Hv4FcnuSS9xuQ/nUw45FiJZIu9JPDD4TPX/6IpoNFiLUSDgEl?=
 =?us-ascii?Q?NJN91F8aJT3ShX60KQpVUvM7bAxlPz+L49mBEnJMS85Cg13iT2rkJOOaqE3X?=
 =?us-ascii?Q?Ccj+hWZuqH3N3NvUz2D0HwDW1AOdCyIArVxgbCk7X/iynZf5Ah6wqcqgugs7?=
 =?us-ascii?Q?oNy80ux2nELAM9BtI3wgzPt8flQTLk9JI6FPx2x/2v42cD3DoHKgdRCBfFJ9?=
 =?us-ascii?Q?VBCcKjv32btor3eJBoFkhT/8ze1cIeMZI//sRVZZiiQ4ttuPgo7L2R4xew63?=
 =?us-ascii?Q?3Y4gRcdHQQy/G2NADJvTgrQR1ERKWqPYoGN4r/W0hhXFakV17odWXfN0SHMQ?=
 =?us-ascii?Q?k6Wb0ypP/NvBU9PGwI0n1nsMUt9Z951IWnBSi5DNri4K+CChdy/+VP9uVgGP?=
 =?us-ascii?Q?9AqDyKvu4YNwc70BtvfLYT7YWwVEDnl6wKVAtb+9jIS2wSsulmxZYPy/fWf4?=
 =?us-ascii?Q?CRG4SAMtllge6Eb6/xv6yOqPkbWBwwmMI6/YxWscDvusRNwcIasIoekV9rSV?=
 =?us-ascii?Q?yCY6W40rCS5JfSDdMjNZXZdJyLUlF+QRAuVT0MWxdx0caQ8FgeQ59hOgqXk5?=
 =?us-ascii?Q?CSlBw3wEovoy8aZSKEnk50vBzwTJ0VyAEgVmRwRa+AM6hBWJd53h7Sf6WLrs?=
 =?us-ascii?Q?mVocHQAXi4dlbdvdIUYupaGPolfgyf14/W+Z2VIN/cRrNHe4wi0UPEM9g2S7?=
 =?us-ascii?Q?tjADuHXfxom5/GtuqG4Ietqth/jyJ+EO7/8QLnNzKs1/a8wizP2jpHhJal/Y?=
 =?us-ascii?Q?eNWouaX7zWOPP1o8nij7gfojCNXsEanUHoBrrA/RoFo45AQill1vf46WtxEt?=
 =?us-ascii?Q?ZoKxVFk9xNy/L7dvP/fPn9dFWf+Zl+qpMHUWuwLBiTjE2D/e9PoIZVU1G7Vz?=
 =?us-ascii?Q?9vLSzxzxXb3X6pP04y1350q92ldAcTNzVvwhG95bfQmPL+YOTAZSRYIy4gRn?=
 =?us-ascii?Q?gAFi+gZj3axAsvebnK7s9RKx9SCqPRTe7eNwofZZxR/llvJ5Z7j0Jz/eYCkJ?=
 =?us-ascii?Q?WL7wO/vJROKHXdP/RPoTCQ/doV56CvOkShSWD3umwtQlYp4Z3k39tpMV67E1?=
 =?us-ascii?Q?o4/rlGfhf/gjHtVP+2qlbbdFe/yrrb7spgCgWCqJ/mey+N487QF8n6byf9hr?=
 =?us-ascii?Q?IMHWxvdwzOvq5aVkCT8s/jj/AHBOSrJZHm1HIQd0MRwW81DfQOERkbloNYJq?=
 =?us-ascii?Q?Ga9JRhJMLEo9t0A6Q5lrARonVE9Iz95D4Bkzv/Ox8PKMQ6ag280Ww1ZZ5omc?=
 =?us-ascii?Q?NMEaaGdR0HCEEw+E/XcosPvKuP7a6UGQoHR4T8EHKq7e/2e9rOcS6D9x7puN?=
 =?us-ascii?Q?wRVDphG0VwokW3EKgf6n55JooSZ6syOZ9MXViAtSCE6YcC3TZh8qVV5cR3kX?=
 =?us-ascii?Q?g8zv521T+b0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?jdkrLVxilT7UrptVJZlAnDlM9rbMRBAzQZixXsNgu1HAoSNJrmMQSnYAzwi+?=
 =?us-ascii?Q?VFpT7kKjNfhRzBxX92FHHvO94zRAYa2VpN6KfWNPRMoMWXwfwg+0/9a7umY/?=
 =?us-ascii?Q?tE5ldnepT7hBTOtobbxhWhGhFLRiOpcLt8zoAmBIq4kvDONp44K6HZ0Rr9nL?=
 =?us-ascii?Q?cQO3AjtkOeTUnZq/T6drU4MjPnouRf51gRuvEnBH/DI0y2vZsRv0CWDUPaeL?=
 =?us-ascii?Q?RgCVwsDKPIbNTlwE+HgcZCAl5IYHf+RlCWKhWMlvPYM+ZN11OkrvrtG4UdpW?=
 =?us-ascii?Q?0AmuNuQpa8KflO3mwy4T6HcF+1seVy+L/1Y9xYnyhNZnsHopuRyUQBLBsU/2?=
 =?us-ascii?Q?Iby582xl07oXKO+T/c/rBXBf+kbz3Y2xwK1wjhZQZkhMNe4LEmr0p0/gANr3?=
 =?us-ascii?Q?d+t2PvlPfeka21jTIQePhpqoMcMFGGsrG/nC3V32YG5jaVjAPfg3j8rfB7Ht?=
 =?us-ascii?Q?8jsCcGVZgfmHWLYgwH0jGvOvse+wXa3IZDpb+uRdrRhJiInQXFMvqqc/4632?=
 =?us-ascii?Q?TZkeAMCheH6HaRp/pULHVC9K8jG2zmNP1xfgJWPuMli5T+0CyRinQgyyA2As?=
 =?us-ascii?Q?43DDVAWkGnB92ToEaSLizHQvvq2Ywo0j/SBwwqaMZjSv5CoqmIs4mWZl3MYD?=
 =?us-ascii?Q?tljIgTdqqOUBhkwVJPLjCKaVza2tyTuwPxNURtImWTjZWWIfSvTrY/SxZHq8?=
 =?us-ascii?Q?dQzxTzZwul0vCHTLMhUGqEEoyekLeApT7CNtn5mj7tjvwhGcdAUkDb7lTZPu?=
 =?us-ascii?Q?oW7+ejm7p31Ed1nyZ4I7RKcf/sJzUNkBAt7yArOWr9Z5JyvU67Ydr82MKY5v?=
 =?us-ascii?Q?2aRsv2TizrYocH/LgSce93U6MzL8GL0/MoHrFywGRB4k2K4p2BRbNV3uwNly?=
 =?us-ascii?Q?bLxp6olPVFlCim6nS8QYLuTKscaGhk5UXFAWsWELjeG+mH+9RYjLOvMq9GRf?=
 =?us-ascii?Q?WBxZ4XjPXoFWQEbQyj1owEqoH8HmclJSwobB0NcSPaYneiSvWkn8+RtTRo/J?=
 =?us-ascii?Q?Kl2UvLLPDabEw41szjYDzO6qDQhn/IbvQ/ycwwSPd+UXQTYRYxchYyK4t7KP?=
 =?us-ascii?Q?RpaZYUnFJoWHtU5nttiQoJ9kt34M1k2G++uCNbYCbJ/0jBiN3JZjoUYF5JoP?=
 =?us-ascii?Q?gBI2OSS5ZyO2wyNqFXXk8XVCVps1CbSoA5NBzkvmM+Y5HB7l6cQgybYGTTaR?=
 =?us-ascii?Q?ZEInonU/HKKLMCje0n15Gg4sJujKRVG/7hO+kAFYNfu3wZu8AGrqM5zlrqRt?=
 =?us-ascii?Q?VKCw7rtjGL0M7qBYibB6he7NpbufJzRYGKXg+inNn4EGzVKdknhb+qvTS09z?=
 =?us-ascii?Q?mboH2mVrql2PAGrOMYd3fFH3ezQ9UJF0M7HlYuHeirN6vFhd6Q8JCKE60KZk?=
 =?us-ascii?Q?pKSDbqNtk1qE1NLd+xq9po3+9BcJRexzgc3faYnQJHbhcXqbL3gIzC90/n3L?=
 =?us-ascii?Q?m+oyRX7Jl/Z9uj2YQRa/NWv/aCUMaIR4aUiMYcLoP/oQGqIrMee5ZD7AuDQG?=
 =?us-ascii?Q?qAxSAKkW9cStm92FOGc5Xg3UDzuweYKOls3ZNrhMXvn2MD0zMqqVWBfX9GFS?=
 =?us-ascii?Q?JrrJyZA4+cUhrGqMCGEYkF4ybibAiKMP2QJBVm8rQ27qck+JUuieRM5ZZHWa?=
 =?us-ascii?Q?kA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: HV4Emffjq0pE07DZ5JcIQuYcon4EPsiJcoz/mKxnLXmJXzW/E6uKtdXcg2rdDMkWRqxnJl5yf5dyzqT/fdOYim5+GfAMK5J4KG5cD+RnQBWZ6APnIYrWo1eMTR9SWVofB++2y4jBlrIl0GMS8EVhTKAsQAdyAIWRZwg0r0/0VnjpKEDU1roogwhaasMXh91n90p3UuFRSmcbiphMyUWuXShVjBMRS9WY2pNMO9x97YOrpDsGGGWnSuQ9PWh3szliyADfF3NO508lOZvpiRFlhLkLj1z2ZqsVPYuISKtfegTLpvrX2iDtuWgj9Yh7NCeUmEHQGeXs+ruRTjJ9VV+NUUPzonHxrnqMT+0i2kFOS2gVHkUX2FuvvJ4Xb7MCGZeMIsXGk9EHoBxFh5xL98ZYYBLRcnzVCD0d6SnkRYLLXAvdq/xKJICVqd1ojirz196TWDFwzirJ5Vny0fAgLLT4kvzNs7knIdc6cMomk0ISpiGh15PVlAKxYtzdkagOwNgfwm/wZ/1j0QPfrs1CA56lHJ1XHliR1fAoGAV1SRPtHWEonjDzVpBwB+NtpHWUgVy5sbAUWUjRia7+/0mrdDYRaYd3QfbE7HyngulnHo9TGfs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 79d18096-0fa0-4715-b4e2-08ddd8c8d110
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 11:18:36.9891
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: iiwMVCbFp0CH5FRcPenj046cMa20tRyMIFMBqzqwPBWgkrcX7a6xvOdjVpt5GC3hJNMrcXMhHABdm1zVm+jnvp14k9FDDUELm/976/Om+fw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPF6ABE13187
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-11_02,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0
 malwarescore=0 spamscore=0 bulkscore=0 mlxlogscore=796 mlxscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508110075
X-Proofpoint-GUID: O8MGFDAShaoRuteVKLrCIJBhNwboh-Tz
X-Proofpoint-ORIG-GUID: O8MGFDAShaoRuteVKLrCIJBhNwboh-Tz
X-Authority-Analysis: v=2.4 cv=ePQTjGp1 c=1 sm=1 tr=0 ts=6899d193 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=LVX5BnHCf0ildCi-QIIA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDA3NSBTYWx0ZWRfX8LR95fI2+ACM
 +5j9Q+z5R38HWIgzJ2TclrzlUUtO3jXWEEB4NV0xT8XPIwHAFSHiCuqPU80YUEHV4u7VrXpwUO9
 S3M/0Tx0vUHLNgmbp3Wy5JeMD5HYjFdRQxNwcnL/NIqZ7wEcfD9b+2ramCXABCs9rAvXba30MUC
 GV3G2+WZPWtq7l2zpIN/v7rJ/9w4Mt9oWmSIocw2LbR52ynCrUlQrma4ocbXTQv3YWm9kTiyxl6
 RNcmiug4YhhZrx6eC6RTc7JCemhGEt1U3psVFfTi214bfujg/L2Lij9++Vm602bHUGhhLEIUWjc
 L12EndH9aEMuliEcctQF1nY4Rb09UY0wiIaAVnDImYUgNk5RknuXaayPGEL2tzCvN9BRadaJGXe
 wKSbEZaDJC2h9/XITxxCfWYX5iQgzpJ7P863/pdD0Nlwd+peXXlqC+rwV3oGv2m75nHe7AXA
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ku1TrKJJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Chvc3ltS;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 11, 2025 at 07:36:46PM +0900, Harry Yoo wrote:
> > >  include/linux/pgalloc.h | 24 ++++++++++++++++++++++++
> >
> > Could we put this in the correct place in MAINTAINERS please?
>
> Definitely yes!
>
> Since this series will be backported to about five -stable kernels
> (v5.13.x and later), I will add that as part of a follow-up series
> that is not intended for backporting.
>
> Does that sound okay?

Yes that's fine thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/30545fd0-fd5a-47bb-bdb4-91246379b97c%40lucifer.local.
