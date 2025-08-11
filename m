Return-Path: <kasan-dev+bncBC37BC7E2QERBS6X43CAMGQEV3ARXPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FFF0B201EE
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:37:33 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-40d04996136sf4731714b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:37:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754901451; cv=pass;
        d=google.com; s=arc-20240605;
        b=XFV06EeJu3YEzX6U3ed4D1FC7UYQyDn4kRSLlEyk1mVNx6ESF3L+1SbVsNOjySBKq5
         B5hYQJwgtkN1OuLsu8OkLaACZKL7aJ+uVXFhy0O9lQlSAKv2y1B7nYNv1H+vzLkW4Buz
         saViKq0rEO9f1broxleqHp6duSWK7U/r6Xco9QFRYozmDxVOQYI1Vjq1fZI2/YHN+9ll
         PnyVyF5Csog7NmWfZ03lwDjShgeKpK8jPrjXS8hFdv+niphsiuid8iRVe0K2wQaQJ5Kt
         yEMRuIQMlqUt1bPZHGyRjjcFPF4inmDxfUgZdn9TpAI6E3bEjD0vFwchMjh+NTm6uyny
         NjQw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=IbXp3CpXrHyKv6tq3Z9NnUI2wFW4eiDIh/h9pvPnaHo=;
        fh=03wAQM7Mo2d5nkbVY9YzFqyIUB+OXSS5xfhGKCYUGXE=;
        b=U7CAM4doHOOqMNwdAPgIsP7kR3eqSQsC2jsbiu6dpFNOva6qAFWPnFzvJ8NV2eDzFB
         0DovzZNuaTW89YZKkEKUh5TeTEaNpsf2+1ibkMNaWBdr9A7yhBqpnC1nS7kydgoQowlk
         igxrmN9LYjHg6Y4vDbq6s0R8shuL7ME3n5Cf8wmzbw6v/A+uSM8AVmwLr1W5EqBowJyd
         BzMeCSYoRCV8/BLBPfON2DgU8WLUY5OlijrTAGJ4yMf+0SUEcc/97+QYuWLd6BQRB/jd
         cvqoLkpuh2bqxK2PmI1Qqu0EUlAD7OByC+0vBp9Mnw1AkhiiB3roRnMNl5mHsVRA3GMJ
         CSEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KWmLdYfa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tO9F2p0s;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754901451; x=1755506251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=IbXp3CpXrHyKv6tq3Z9NnUI2wFW4eiDIh/h9pvPnaHo=;
        b=C+v+r9L32F5d256f0TG9V5dgypcUJUVSQXj2KHWQ1PO8avrE+ZYPuS+qmVMPX2i+7U
         ELuz07+vPHaCmGqZVnsxrjKGQfoH4Ymx7BuTH64L1Je00pXZjSPGck3xzFwth+QLjgoX
         pNX5nWo4fFcikoHt46dyLKD8zJ+BuKEn4ZtEY8LycksmCKUtHAYDwPmndUN2uraE7ruu
         WPVr62jWHIA4c1YJiHd2nlzWg20H2kKf1YsfqY12sUZEJrn0y3NnIbcvg77l2swodqKL
         Xexy6ZxHZZt7kBRT+HNiHrQGqecliq7gByAgqKRXvY8rxq8iMMgICViWMxsY3WHUaz/H
         3KhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754901451; x=1755506251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IbXp3CpXrHyKv6tq3Z9NnUI2wFW4eiDIh/h9pvPnaHo=;
        b=uzOcE217d78DIa/OMkG1fbLv3IULuJVKW2Zg3j8uTjNG0/QBl4ecgWXTRMF/pjyctb
         o9cW/wgVvK873kaaDcTIMzvqLNAa5nedpEfAyN35cM39Ev/fm96BfrDxqorjqOA19qpu
         vM312MPsSWCdHktUnCbBHtfrdXrnRv8abbvYeSKzIa6OMT5/smBrLjnyidCJcWHGZJuZ
         cwa5D1AJJfdunv5izRUiQ76BAkRSEQEIVgoLCAC71gavveEKXBWc5vgY8Jk4k89hLtm9
         P2pxcGeaqHCSpl2QgrdDF8v0iErPAwzwIXlq6POaFdZQe2c6Ka5fUor2wLeJowtyWE35
         1Ftw==
X-Forwarded-Encrypted: i=3; AJvYcCWhvVab4nlxuIOUv3wKVvRs0laAmRa3P3nEf9ofEnyf8HFRHuQ3mfjFolVRlPd9HwWhvORMhg==@lfdr.de
X-Gm-Message-State: AOJu0Yzt89kcTYqe1PMu5PFXOlZyWBQQCeqOpooifhdvL8B+FXwmeMN8
	M1S3hie/dYK7pNzQZrxw9a0k+MuEcPsZ2tE+7bRImNGSGS/YdsDgIzM+
X-Google-Smtp-Source: AGHT+IEI7H1Q2/7HFf4ChSuXH7qHpSWqoDYuS287V0yp5JAcE+DffBt5DN0e3slPPWb6RA2RNSDIYg==
X-Received: by 2002:a05:6808:16ab:b0:434:ee4:78d3 with SMTP id 5614622812f47-43597c0e547mr8435865b6e.16.1754901451475;
        Mon, 11 Aug 2025 01:37:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfGvWKu+n03ZSKQAuOYux1RBnxSwe7VI/3pqXNfcQoiCg==
Received: by 2002:a05:6871:840e:b0:30c:c0b:fe9d with SMTP id
 586e51a60fabf-30c0c0c15e0ls1389668fac.0.-pod-prod-03-us; Mon, 11 Aug 2025
 01:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU0wQQ0B5tUuzpqkxbl8k4H6VnkvMeJiRat4M1Yi+uWIzpx6dVaAvYpqRccx5swNltr+yeCTPGKa0g=@googlegroups.com
X-Received: by 2002:a05:6808:1b10:b0:40a:fb27:9e8d with SMTP id 5614622812f47-43597c118cdmr5691043b6e.15.1754901450597;
        Mon, 11 Aug 2025 01:37:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754901450; cv=pass;
        d=google.com; s=arc-20240605;
        b=LNStIs48daBC1Jup6D1c2oubBJ5brhGv+2jcq633Oadq6vGG4DRfZLabnyXP88xk86
         Nk2Tc8e0kJaX6dlvr6bFshXfTzLtxhPx0V53yIQFCHXN9UKRpM9O3pXtH1QcvoSNCLrk
         8X8V1LMO9CRfiT4TMpTaZOuTn/Y3NvjOLzhQUo4CpxG98Mmm39vKepM6aO4K6PmAl6qZ
         jH09iE3MvNj9fjxvSr1aUgwsMDo5uQ8442Hq+FmplL+g3jw8K3z2rUoi5l+0lPjaBVQe
         ejK8eIW8jzudzq4udcJ4Kop4C+x0MJ5OsZ1y1ngM9lxOgiNsGKFsBO2LhIMmb3GnAtX0
         3N9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=RveQkbLBMmMC1UC1ACnAmC7AzNS8IHkWHeyeoYnCwds=;
        fh=bJImh0MCl/IkFXU7CGTDINJ6Nsa1SfN6M+x7w4y8has=;
        b=LAhIp8qqdTnMIJC9tLuoKcIeWJIKpJ8Q47wwIQdQJ5iLzb22bJDM1+ZBAuI2Qn2m/G
         vaRrXDUAyVmY1YkEhHEGBhzoYSvlOS05nC8QOfQKc+W/ffbcnde4RVjx7rBJ/WPX3qrN
         bDid17pckdgQyQYP6eQKwSix0drIUI0U6nrpifWHU7t7wnkyxxA0FbmM8DD0nWHj2mrs
         PGoK1566WNh3T3RYI43r5tBI7MkXatrOwpnuwAPuZ0K23DRUcmGj3coxfv9QNcm849YC
         vwtVoMXwJjLgLP7R0MnbBEuwSlLxZ5A5qjvKfTJ3hs+sLOCaNkkIM+1rkgeFQxfBOMS6
         8mdg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KWmLdYfa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tO9F2p0s;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4357de83050si502130b6e.3.2025.08.11.01.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Aug 2025 01:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B5uIVB015118;
	Mon, 11 Aug 2025 08:37:12 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw44t1sy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 08:37:12 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B8CPW0006485;
	Mon, 11 Aug 2025 08:37:11 GMT
Received: from nam02-bn1-obe.outbound.protection.outlook.com (mail-bn1nam02on2066.outbound.protection.outlook.com [40.107.212.66])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs84e3w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 08:37:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yafpcwLOw926TojUf9vHxYKYrtkb9ZbRDu52yKRBeL2geEi+tGTDqLJQMb3CiXtvlGGtKZxo7I77TFKgOnKJZHUTrkTFOMQ2iGaVl0Lqi1fMalo1UiwULfDKWhxml/zqXIl5hxV8Db1qYATjpS6f+gYAN5/qWaT7KIB+eAkfea52/tkvlNAVub0k+HbM3afS9tcN2xfwHUK2X8smwZ7CeuA4Bmvf+AhRYFbmefrg4yQ/kL+s8cmxly758IG+t3LZgmUqVIwsBoFVIbu/m3NK5lvMCwJI//A8y0Eug0H8L1r2YMwGkPiJ8fPKIfimpr0spGxXFFa2f6ANPyfA1qOCJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=RveQkbLBMmMC1UC1ACnAmC7AzNS8IHkWHeyeoYnCwds=;
 b=rwLud9PWZHuLzrJgjjx6AL8GagM8gNRZka7n4+4HyxmdikLJ0A62i5lrLNTPfnqTZEXG8ujUd4LLxzQsRvS1zZO2jPHAZYDTq0X54uTs1thahYvcF9GtpmxOcAJ8gkpAcrSUIe3NNBsK0OvPHwpICSW5z3vmmhwjsoHwJd76vI5uc46OLY/G/UbZglCADDpeI/kXDcFv9BZ40hk++R2pVhLNacn8minRqYZ/kOgfCL05vSTiKkjQL1CBi1lla4VN6k6HKfr9iI9IS2Tuj1Q4CIbXUGfbzu9NpIUr03ZXVqw90vhPF01zDu9bc78EDkUPfQNOYR1jbe2dhW3RX/di7g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CH2PR10MB4294.namprd10.prod.outlook.com (2603:10b6:610:a7::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.22; Mon, 11 Aug
 2025 08:37:09 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 08:37:09 +0000
Date: Mon, 11 Aug 2025 17:36:53 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>
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
        Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
        Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 1/3] mm: move page table sync declarations
 to linux/pgtable.h
Message-ID: <aJmrpaeKKeNCV3G_@hyeyoo>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-2-harry.yoo@oracle.com>
 <aJmkX3JBhH3F0PEC@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJmkX3JBhH3F0PEC@kernel.org>
X-ClientProxiedBy: SE2P216CA0069.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:118::8) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CH2PR10MB4294:EE_
X-MS-Office365-Filtering-Correlation-Id: 86da49e6-8ae1-455c-c61f-08ddd8b2426d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?EAqD6QcUv931WFgh2M79m91rJn+ok1eprd25QjYOzO/Dh4VoiU9huStcUw9+?=
 =?us-ascii?Q?3WB5Yyat3A/vHyKwQzVRbkiIAraKpVBppQrChBXSR8YVjG/lY49kvIfErkCK?=
 =?us-ascii?Q?DAw1PnJBfiGFvAcy303Z2ljM+Olo0mB8Zpq2I3kuGnzIgLbUHWqudwh1mr6w?=
 =?us-ascii?Q?KbmKijiQy5Bn6KpWfwrU+3jLiurH3Eu08GUs6iMkcyrVANYdBHLtHcX0m00u?=
 =?us-ascii?Q?ksYvilJOUnidqhtatntWmoOs52565aUi5CTOK+gFWW78FTbzVgI6CrOHZiHG?=
 =?us-ascii?Q?NKGavKrDZNst8FAIjYrNoeBkmDViK7gRpC3kQKhXl+s6EDgildXzqHtWPVmD?=
 =?us-ascii?Q?EYNJx1CWH0RYw7YOGaD53z1pmo3LJuXuBCoUg/2Fw3+/LMgphtljgnMQolIY?=
 =?us-ascii?Q?PiPpegKcVo+Zhlq8j+22NYwWEFCDvwMA5C/UAzRN7UzkdPhbGmtddSM9mBiI?=
 =?us-ascii?Q?I+/AeYYpW3wen/WnOwJFwDABxvV0HEGkzjuJo6u/DlABJi28/fzoveROJVd/?=
 =?us-ascii?Q?ZQcGFSnnpRtx1MPbuwxUzMt4oJzRq4PLpm4BmPpxXZij6MG+GqWXZPLczpGx?=
 =?us-ascii?Q?+0tLtvIN7Dq6CBpcwap2x48JYIr1Z5fMtEXg3UbuaWu0R1t7C4HSs4jQr40L?=
 =?us-ascii?Q?7vW0MSyuMySAbz0rR/U19jvwDaHNJcWlEnYraougY0RRePhMO+koJtukv504?=
 =?us-ascii?Q?kQA3Ub7zRaCWLa+OOUzQekYSyEr/sjAb4NjWK3kIp9Ma6PZm1LehalIW4N6p?=
 =?us-ascii?Q?kPswJUuojjNEgqXAd69IMQzzQw/iyefKc1Xd6Nv5cy6pN8lgfPKqaw/FuiY5?=
 =?us-ascii?Q?zBx+Mz1EqM+q8tzYEWLtwdvN2chQ3VPOOEG9cjScRPSEvMF6PS8e1gt4PnO8?=
 =?us-ascii?Q?AQ2kjKa/dOwP94123TqaFSM3CbglVretWIhFEfgXADfXrDYtp17oG90YJWR1?=
 =?us-ascii?Q?oE9NkmuEdpvEOHoFxABjpqsxpR2WW3YNR0evheqsZbWiDdh1bP3j01wzoSCw?=
 =?us-ascii?Q?vhT3z/TS4aM42oz2m4mA4RBSodphcKG8eQgSQGNat7GwmuN/TogC6mEsQlWS?=
 =?us-ascii?Q?VnC9iN15hgsNHmPE5OXSX/JPM6aDfue9WbaVC3vzaCJ/igTtVc7Nrqa2PBwl?=
 =?us-ascii?Q?fOkdE3zzYOqYZQyuj4Y47CJO21jiSDQpMFichbpyHnW1fnihgp+gXpX6WVMO?=
 =?us-ascii?Q?x1+1l/cGGj77T1DkJAULDySp791ZYB9nnS24eWolAu18k0tfoYRwLLZtCg9T?=
 =?us-ascii?Q?e4Lq51i7pQGatVp1UuEUcevM8YgvEEPSvu7vb0hlhb59uo3K2cDzBqsYbt4O?=
 =?us-ascii?Q?epDtboCWKh1WXP23ekOKThtWBVk4GiDeejr/KREhDWmvkStTr5yFMzuvx99a?=
 =?us-ascii?Q?a7NIUOTT/HbWI1urA4W/tEhjoOeCaRVWjS3c9vV4K3brpXgG75UU1gd/CAgo?=
 =?us-ascii?Q?AossnFkz/7I=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?82sve2IIpUEWfZpFUOCGP4tM8bVuijhIkbh0tQOi1PsdgJ5fGEIMdX0DoK5p?=
 =?us-ascii?Q?xYusDHgZpmJakJoQKq3jjclwUOpY/DrPfiGDnRsprZIXa3sUIIf3Cb8n8XcY?=
 =?us-ascii?Q?PLxuNBeNh+EzWZXxMcuWEOvYRq4Omla7ylyRtIsBGSctXmESjvsJiN4bRvD8?=
 =?us-ascii?Q?5SlQCY+eF/f5Akgy1W4igKyXcRz2hPgeanMZxdyNECbSg8+PdQ8wf2wgJ7m8?=
 =?us-ascii?Q?qaSxz7pYX8eHz0ea1jhKedpWttrJjfCS3Zh1RF8/fEHPqVhGuocQ7Ld7bD3w?=
 =?us-ascii?Q?S73OuJiiuuNM+E+53IrubOL/W1qD6IaugaEniPSPeQtid7I3adSLyY/zy10H?=
 =?us-ascii?Q?F0kqdSGuKG/0jL2cP0V2ow5zBLo/tiV10Gj8CzR/d0NHsjcdiv60Yy800M+H?=
 =?us-ascii?Q?mOoNrLwjkllyMZpHXzCW5RhIScuiDQP/N8lEDMdrIvPg9gFRjh5Ce23uHctG?=
 =?us-ascii?Q?A3dj6dIpi58twOxIA+LIVyv4E6FcyhUWpaRujnczhG+UpcPrgNfJoCeNtChM?=
 =?us-ascii?Q?IT/TBabf5JX0ynLeSRPAp2yMXJyUYjPROeafnGiH1b6twxweVV3HXgjDGNrn?=
 =?us-ascii?Q?J7hzjf4w6pb6WPVw9+BN6wppB34/asshYiuf4A/hGIxfDv2UuwVuV583vZv7?=
 =?us-ascii?Q?XTvu+AVjdpK67saC+Py/i/hwVeOmaxWxjSHTPpl8fsEObS9t4LXvN5P9fHJp?=
 =?us-ascii?Q?kZfbaSNb+0d3+xWYSZhzoQSsnG69JPXN9YoM/c5feEfCVBFrjpvUgkrHloZY?=
 =?us-ascii?Q?jHuiKpKFbWkiD/p2yqhz6rCb5Bje6mTOiu6oHDJXoYOxSuPfZUbmMd4BKawN?=
 =?us-ascii?Q?kO4TJlttJ6a74gdn9DjmpQwh1qeb49XQ9PdW+rrBGn1JKJZ2xNeqk5H7qdkC?=
 =?us-ascii?Q?csphpOAcKWY0Zs5NXY0Wbb/UzQv0xcA3rScMDwemctU4lsCNoJOwlKBDjYJt?=
 =?us-ascii?Q?v6GEmQFBN24FEdjTW1LaN4DPqMaXZveKKf0HHNWuHpVB2NcRQXLATvn70Kk0?=
 =?us-ascii?Q?I2LHeAuErE1je2QSuNX3QgatHOHbp/+pw8EXMwn5xuZ2U9Wwe7xKlTZnyHKh?=
 =?us-ascii?Q?H0TpRuPCBKLCcxZ21AAVxCFqfjax7ATn1yV5VsRBvjwuaFmQRWBVaOdqbbTK?=
 =?us-ascii?Q?i24MR8RFJvPkmsCul1xCwnT4h86GYZd1ML4j2gGmDKDGBQZuclHZpcx/U1ED?=
 =?us-ascii?Q?042DDesh2CNSsAN8XVsZ26jSQ1jQ/pDWRoBMdPj8KrT0CyrwX/p9XEyqV8m7?=
 =?us-ascii?Q?A0pzPoZp4hLryeI6O4zpLLnkElj2yPsxi4ITBLvXljm7//kCBbZ5ONxDQ5ES?=
 =?us-ascii?Q?KFSZ26A6QsyGWjLBNJeqQFg73rFXIz+lar791NgcQ2X8yNxGw3yvgFp58B+2?=
 =?us-ascii?Q?iwx2KbP9em5OjKuE2VXzVOiSEf+yJoHNTx5AeDAvdw5Wr9yFExM6mjPP3Kt6?=
 =?us-ascii?Q?HY1FrfczL2H0aXBPpXxvdOTToiVktK3NBtJBJeeycA/mlmMV+1GEqPW3iTbz?=
 =?us-ascii?Q?q0lSXp2Fs9zo5HdpP3X7yIVE2Oa0rgua6fFbptq+KtMIXd8wsGyyVhb1wcOK?=
 =?us-ascii?Q?0TrUBE+rc6SOYb37gjImR9ODCfVmri14HAMJFVks?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 5n4l1gttv3sTWN9ZtXqb/M37Op0DSgOVHNX1TfbrjrBXuzZHwrizZuWR0jThswZuhDy2zfA6LDWCQf04trVab1+mXm5kQBt5qH9p1rzgK+N5xR/LFJSL9iqdUmmduW5+06EDhGHJaVXgISclBb03FsTJDSh7/He9g/NwuBhSbL4yCBRcS5tUyT5DdqV7mhQ5HJR+rWkMAJaZIS9cY+e9rzckaffMa4MNiQLa0I0KSo4r6lFmodB11xvpB5MLgFMeEGFliYzb8F7KwGA6TiahexWZnNVTng7JvOdoRh7ztUgJ2qQrbrOZltfk5oP9HG4uFzjWy1cY728hylVLJkD6j3T7z966Uc7+TZyZqAQcU3YGi9r76QFhdYkJxS9APcWIoLQBtpwZDdlyiz/PH+aolZEtuhc2sXYbZrzzkE2WVtYbiWkBvWaNT+Ugvt/fcn0fG0ULVlGAfIH/yP7HbFigR3VwYoGbGndOHzLG1oH3/YzlR2rE0znOOrgkgC2z6FXuUa8mR85bpISCncjqg3W/zz6NFFuKIVyMeOe6n0BGwzv0wWb63jUI18nwvjn4Je3RLPu2yO7vIf/kDbWmoTpTspj+j1FjEn1LO+VYyqkb6Pc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 86da49e6-8ae1-455c-c61f-08ddd8b2426d
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 08:37:08.8625
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: f1wswrzIWQAzUFKWp1jrGF3AC/yhQ/JZm6akFI4mIp6q8Efpju0k+oKpkuLpLiL5LpImOhP0V0mvGoehEwksrQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR10MB4294
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-11_01,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 adultscore=0 malwarescore=0
 spamscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508110056
X-Proofpoint-ORIG-GUID: yJRF1irmpsDlkPU_Io4wztFoYDrjOWZB
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDA1NyBTYWx0ZWRfX4opqey4dOHCl
 eXYSrshiIEHHGwHQ2SVPt9B/SdHvvBFcHhTWP1+Dn2hr2pAwGa8KxtJ/k4eR8i27smA82f5PP1h
 SlGWLWpFRMRAZ83TNCMP55y9sf2eYns3nfZoUiwLEqPY+Ku2zViJsp2cSUGP0ME8Lja3ojXzP2s
 0JdIN/dDrafaExF+Cwb0D0cP5Jk5xMddr3Q2DrcM5SqKOXX+ltWCFIxwUBFNU6uHWS8ln7kX5XN
 qveJ6Ko4vl62un8bJcKgE5WVNtbOSceAzdWHmKz5vd4g4xqJKKBjh0Pf1a/JRstRCOuitp5G3Gf
 bQOBqHCXoGlvgZENY08e4KzWJU/1Jc52uKrC7Ax8Hkmo6codhLWu0A5whNDMaY3dk3AdeS1ktlD
 VVdd3nXD970JKBcn8J/3wdh2RaeOxy1Non9n/g/U3wmgMeVpZo80QN49+FhbTzZFRxk5ZbHS
X-Authority-Analysis: v=2.4 cv=X9FSKHTe c=1 sm=1 tr=0 ts=6899abb8 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8
 a=0DxuVrdH8SgwYDiYD38A:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13600
X-Proofpoint-GUID: yJRF1irmpsDlkPU_Io4wztFoYDrjOWZB
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=KWmLdYfa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=tO9F2p0s;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 11, 2025 at 11:05:51AM +0300, Mike Rapoport wrote:
> On Mon, Aug 11, 2025 at 02:34:18PM +0900, Harry Yoo wrote:
> > Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> > linux/pgtable.h so that they can be used outside of vmalloc and ioremap.
> > 
> > Cc: <stable@vger.kernel.org>
> > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> > ---
> >  include/linux/pgtable.h | 16 ++++++++++++++++
> >  include/linux/vmalloc.h | 16 ----------------
> >  2 files changed, 16 insertions(+), 16 deletions(-)
> > 
> > diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> > index 4c035637eeb7..ba699df6ef69 100644
> > --- a/include/linux/pgtable.h
> > +++ b/include/linux/pgtable.h
> > @@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
> >  }
> >  #endif
> >  
> > +/*
> > + * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> > + * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> 
> If ARCH_PAGE_TABLE_SYNC_MASK can be used outside vmalloc(), the comment
> needs an update, maybe
> 
> ... and let the generic code that modifies kernel page tables

Right, and patch 2 updates the comment as it uses it outside vmalloc():

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index ba699df6ef69..0cf5c6c3e483 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1469,8 +1469,8 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned

 /*
  * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
- * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
- * needs to be called.
+ * and let generic vmalloc, ioremap and page table update code know when
+ * arch_sync_kernel_mappings() needs to be called.
  */
 #ifndef ARCH_PAGE_TABLE_SYNC_MASK
 #define ARCH_PAGE_TABLE_SYNC_MASK 0

Or if you think "page table update code" is unclear, please let me know.

> Other than that
> 
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

Thanks a lot for all the reviews, Mike!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJmrpaeKKeNCV3G_%40hyeyoo.
