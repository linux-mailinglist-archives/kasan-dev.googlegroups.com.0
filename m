Return-Path: <kasan-dev+bncBD6LBUWO5UMBBW5E47CAMGQEXAJOXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 39BF4B20773
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 13:22:05 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-23fe26e5a33sf65633685ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 04:22:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754911323; cv=pass;
        d=google.com; s=arc-20240605;
        b=hDm9aipczgedaLpaxWL6zxIxTItS5dRM0VCrv+lDcvreUGQuzeIPe3li2LIIajVUB+
         OaKr4hj8/PROUvF54iQXp63K3GYmGQkxUbd1GPK79rtYIwIwuAeO3JHdHTC82K8cIEg9
         VU1Hw1vlRLQKfgCw1JzFuJGwXTqlNEXp5OLkVjMtW2889KssSHB0CVEuAIm65HByNb4c
         GpEqa18exZP8Z7JojR1gpoCjWIBU4c+1qh35Tfqh99xMnercSxVLf3N7QbAZWgp1Hz7o
         pBgjLpJJo1vJwnWKmVh10mgMRKETf5zDjgoS0zoflZ4UvHAJq037nnaVF8XH/vGTYrFn
         iZ8Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=WgjZeYVXEYzGj1ZkYCUYib25p3oMlLlqUMNe0dmMUJU=;
        fh=jpyC84RW5OQQHYEfBqVlTPRYkOmsljVVq7eJwhMnN+c=;
        b=SqiP8KsB/3iNchqi/a2fkx7cQeiFwKNFu4/dUjQunmDluemzj0bkWT60uCGqywMpDE
         DhavTcTlM4E1E2tP7zqHjZ/cRhF4/9OMNK7hqdTNADRz/TmMBQph36S3MjaTsKEjinUl
         B+g7rel1dAcP5gkdeOcdwv85cwispg3YWxqkDF9IPJtVmfEBTxcmso6qv9C8Ia5Jnss5
         pNxjfL0tI12WJYEGS4N62uW7b8/L/FeJwSQKjdIGhEuJFnQec1m3vcG7smUzc7p+9jcg
         1vxGlXILdGr7a93oPwWczMfnBHrSQvmKsQE1shYLBoDUsHG8NHMV9n2X1WSGbndRV5r4
         OYYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FHiRvJof;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QroKQu6T;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754911323; x=1755516123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WgjZeYVXEYzGj1ZkYCUYib25p3oMlLlqUMNe0dmMUJU=;
        b=gMqsrCOP+9AIi68vUQHbTud9O8omLeYGjN1tU7EH2X2a11SR0Rg3pgVRFqi7BJ5TOv
         6xGjEQIPginQM8OC6c4uw0OqTpf2/8i7EDnrNu6+9bMMd7o+DH2TeD/VT3VWKin1/efW
         oKy5DBDcE4rQdUmCyhJVm2C4Xz0iDppJ7czZepsZsNCvbrPWa/ZvR1ljqtM0LjS7JCPk
         WlcnaRNM91khi2tbtC57jwe59Y8sMolRdrJPJwSSybBuRZWXZuPzEaFi5bGlb8EnEN1q
         Jag6TAeRwhn1v/WnX6zgUUOhtrqq0TVvoSbl6R+HglHiz8X8TVnMHnbCjRuIeitxCaEp
         5G2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754911323; x=1755516123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WgjZeYVXEYzGj1ZkYCUYib25p3oMlLlqUMNe0dmMUJU=;
        b=WQBnaVNjjDiYMdZ83ATvxFZeHZ0lnM1EPn5QaSbj4K9QSM+Wzcbxe+4LRkv1EG1gnk
         JA6taRIkCXnIbhTjCwZ3xgTFf5/xkPJcFT/4JWADMg6NSm+nvyZvZO/dj8x5Dr41Twfe
         pN6r82N5TYT4PAS0ICixCzuc6xz+fyRX84IiO7LRGntMWPXM0y2ryn6v9r6KgeYQeeIp
         3/eqFkbSqfyz2tLJNWfdI6BoggCdmhmYMMERjYteokhKX61/tjlfnPbiSDDuNKzPaqyl
         f7vNE9gzNJqrn5SMeSAnY0Ur8IysQ/E4hvztxXALXFUK5iIEf27BIFG5tNatD7i8gWVB
         +8WA==
X-Forwarded-Encrypted: i=3; AJvYcCU4GbnCX0KKVfiNSgl0YkxybD2odY9RHF5zFFh32QNLrnPSIaU/MoGyyzPrGDTJtxeSOR+KBA==@lfdr.de
X-Gm-Message-State: AOJu0Yx3pe0sRNWt8YZQr8iG4muCJzV7LeSYbjqB2SXEca21RDUkN2KD
	/GTupXDQe9D5SYQixFowsMYiKy8KqK/fd62Tgr1SMt5Fuc3yqMRV8fbS
X-Google-Smtp-Source: AGHT+IGtK3nYV0raUzDDiGk/6N0AOJrhURM62a8Y0H61UwQXH1ebIVitJiczExmxa92K5aFBGtO3Ag==
X-Received: by 2002:a17:903:1aa3:b0:240:8262:1a46 with SMTP id d9443c01a7336-242c21e355fmr164679655ad.25.1754911323561;
        Mon, 11 Aug 2025 04:22:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcFDVR/PbidsC8Zss2RfaWnj/wvzeLdbjTUh7TppRkOcg==
Received: by 2002:a17:902:ef81:b0:240:38f1:5c80 with SMTP id
 d9443c01a7336-242afd19af8ls39522505ad.2.-pod-prod-06-us; Mon, 11 Aug 2025
 04:22:02 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX+cvggkDIT9athk4S8JfCXrhnonCkCtuXTRKFoS4uViYYG5qIeyHrYCVVSutkYr943mOhDLGFW4KQ=@googlegroups.com
X-Received: by 2002:a17:903:11c7:b0:240:80f:a4b6 with SMTP id d9443c01a7336-242c2070712mr171086815ad.4.1754911321832;
        Mon, 11 Aug 2025 04:22:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754911321; cv=pass;
        d=google.com; s=arc-20240605;
        b=NowRUcfVFPBRGLgjSGNV7rCVR+izmqLs9ySOGA4WfESh7yVZHAsHLaxRq4PMNSHM73
         hZHIEIq4jRkdSWZsska5ivcHFuiLrbiXf/Qw4rCaVAjBgW8XqenQhJm9B9DMki01gJqy
         8uV9pXgsrd5nIS53t9k3/DR3PYQwfkCJvMSH5OLLJTuPov5v5QwsYosbKRX6FzITBDOm
         ckRVEq0Vc/unwRfADPgU+U2hyve8P1gcVOz4IdE7OH0nrvZpTNxi9/Ks5clAByidKzF6
         iNXUq3SUzzWvPK9EEFXDrt7EUgohtY11ahY1CMR8MEkieqCN9t+gU2trDuOIVsgoyk9e
         zMhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=TwKcLrd9oHZ7Q3EFT1TCVNnN+SWChnHgOAzOlGjBCjk=;
        fh=PLQgFxTRLyhcg3N9pmSi1Fg/j2fHtLGfM3ZloGi4B4Q=;
        b=fec4OHq26P5PqF/Zav6qOFtV6YdyDNPDp3YkYdQrgnl9b37GLxrg5Nk1Yx9o8HUuAH
         MlWvpfmZAOiGE5R3lgS75k9NJT+LXFuinbzY6v140JL2NTbuQALk26Pl4pbRuJ7FkCil
         Gf6o0Q6Vz81yW6dVCzNHMuCbpHR64/i6WiEWZYX+ZZfXoFexHBASI18VF46QnnOdTflp
         X8zGpud6P/W1PdSidTrZsxt5UMvn7FxmbVPARsjEG7mQwKGjVWhrxg8+iLXCw5ihZdM0
         +c2cbwsISuX54JlEXcPg4L9vUqQ0uBp1p9ftDkX2r67SjtkJVxOFbbFYFEpUSCgfp61g
         2lOw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FHiRvJof;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QroKQu6T;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cec02f6csi4312595ad.2.2025.08.11.04.22.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Aug 2025 04:22:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B5uMTo015126;
	Mon, 11 Aug 2025 11:21:45 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw44t93h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 11:21:45 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57BAEPFE038842;
	Mon, 11 Aug 2025 11:21:44 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02on2071.outbound.protection.outlook.com [40.107.96.71])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48dvsf1m7d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 11:21:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nGmI6sfjDv6bBHaqtcyAhnh5cNDXG089Svsna8Lh4OB7LdXuGAfLQScMRMkIW1N9Wgab0lQWW5zU1pXsYbkzFG+2s61QFhtnelop/y/vAwMtJelK03zbUGLZuXzCWXnx7TQZCtMLcK/g1AD3MlqFMKd828wFaqG/tBWIKauNjyTSweS5axIjJSrQv4GSBEYeRXnMuJLJnKFBUONHaT9Y2RyWz72VHmJu+smlRddIUpWcp/EpP02I8mE+XgPfBH662gYg9FN8cNCY2CmtVkQbTdXKCOEwWonx22agjlJT4+GT0wxSc1fsM2G7kP0hwGafSHWjLr7wCd1Qgfea+mVQSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TwKcLrd9oHZ7Q3EFT1TCVNnN+SWChnHgOAzOlGjBCjk=;
 b=v+DJ2TgOZkrIl/mUM4eiTrpVNaphT9H0kAb3zYBt7loOMF0Keh4cRYaSh4FUtwXBrqLVtF/JmR0DEcWZEtKsr1/pQ/KzOfz72kC0v9G4MXZ1F7f0FrBhP/lKTy0y4wLMRyxAiuirQWmbstq4oFxzpdrftF75uPt2qzWBW0zsKDUxCcbHZ7PpAJkslxVfRy6/fI7QygcQFXYyraXzzXnVZi/2djmILmfhlppUFvrJPiwAPWLIoppRXClOZw45orWSsRICb52A2JylrWTBCGYjxVOIbAMf8jhI4NdmRfWerJzAR3ucnB2KGiK5R6nECaEFJAZvesJ0rzvh8f60bSLKhw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS4PPF6ABE13187.namprd10.prod.outlook.com (2603:10b6:f:fc00::d24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 11:21:41 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 11:21:41 +0000
Date: Mon, 11 Aug 2025 12:21:37 +0100
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
Subject: Re: [PATCH V4 mm-hotfixes 1/3] mm: move page table sync declarations
 to linux/pgtable.h
Message-ID: <b399b898-9b18-4d4b-8a9e-d9f79ffa524c@lucifer.local>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-2-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-2-harry.yoo@oracle.com>
X-ClientProxiedBy: MM0P280CA0096.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:190:9::31) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS4PPF6ABE13187:EE_
X-MS-Office365-Filtering-Correlation-Id: 35a9a6db-7ed9-4f4d-b52e-08ddd8c93eef
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?HNpaduCmemuESYWp8Iu79Zloh2+1Azekmu1xnE7dCcFuewK2mCK/CmZoYhnJ?=
 =?us-ascii?Q?plKqNw1mOcddEgSezGcp7E7dQnXf4mBjzNkTgZ7cOlJEltF+NK6suBoIrZnN?=
 =?us-ascii?Q?vS8zH2H+YXr8N3CFXI3dkp2DaVx8jmVdhmJky7VuK8dKMF2awu6UdvUK2U/n?=
 =?us-ascii?Q?9K4YJopiTSeW8IS9iozQpKx1BK8+IbQzOXaTUYIdIRFJDZ7qlHtWaHCiPZR8?=
 =?us-ascii?Q?N3fjXQCVH4MdkxkUyLuaAMikdqA7YN7l2QRRZ7OkJv2WGlLhtNGNXv4TB06B?=
 =?us-ascii?Q?LxXCmFXgWK9c3/p7jBOf5KxK4dCldXDbJP1pVd/4rQ6ewZFvtWLHplRaFpM2?=
 =?us-ascii?Q?e6iMXHd83S/ywnHWG1w8CcZk3u2i6BFU0z5+QzAlnXq+OfvWS8uZ8z+oROQ0?=
 =?us-ascii?Q?iLf7M5TPwdhbE7PjZ/34AnqO/TNkLuaMO6eVkh06F4FWZVV2zZY9pkQNNBZ9?=
 =?us-ascii?Q?ItIBWU/jvq/IIWAb630HwiZhmdhvrMeFKJmPf0SktXSZWzkjOLcn8m+a279T?=
 =?us-ascii?Q?vnWCdnleonjY0yjat4PRegpG8699K1leEcpabQaozvK1CWbEbiokdACgupB7?=
 =?us-ascii?Q?XYyRNP9OxQl/4U70NuWUx0Aeb6zSM3pNSsZZMQ3NLRDUadOTkYWJnGN45Qi9?=
 =?us-ascii?Q?lsBkeF8fa9ezw9QRCmgRJvuRBCHlsX1sU6mZE8OWSnhl6sI0OgWQfuArOY4d?=
 =?us-ascii?Q?aLtXwH4XGBV+gpDJ3g3m7tGh+A+ZJYfwxHjwJA53nZg17MylTPnITLIIsb77?=
 =?us-ascii?Q?w7ZcFAyrUHjikGl1xVKGPQ7Ems6LZ6tPbuuZpyXNpaDRXyfJCrxH1FwffQpg?=
 =?us-ascii?Q?jl/wWHcCZq1oGAetH79AvjWtazPNXBJ6p4SzeLxNxt9ic0BlBrwS/VJFGTod?=
 =?us-ascii?Q?+9pluUZaAIgusT/xv92NVy9olhenOw7JuAgogJc9rQT4QLHX5Q8ctOND6bmK?=
 =?us-ascii?Q?E5O+aPzf+OyMQaJ60w4RLcqBPQaept7rgBRcACV48FiZCHvJH+b55fRkd4/P?=
 =?us-ascii?Q?fmvFa20ytE/kSDf1h9LgkT84JgO5ZWErvi344t5cmwTtnkRF2/u43tON1n1u?=
 =?us-ascii?Q?k7W/+7hR2zwYSvQtj92da7ENLDWgw6RIeoAuQ52nKP0kayeB+rQ3a2Envu5H?=
 =?us-ascii?Q?iEf2+No8lCCynf8NtKFBJvqrzVpi76vJZbq6IT8InT/jCPn34RRq/qe3eVOz?=
 =?us-ascii?Q?XJG5/r+V63AGaW+WS/tvy+B3z64M37JhiDlf7FeQBAGCRAF7Gt82IUrzhZGT?=
 =?us-ascii?Q?PMVyGmpESZhDNhF+zGpxtQ4zgkok7+tUcp5dP+aeNfs//syVdAKoyQ+zUyxt?=
 =?us-ascii?Q?h+RDl2/soIvzy/oZtIderjH749LD14fZO/6sapfdiP8AFYLxpm7mhKdr280E?=
 =?us-ascii?Q?3RUygYHl71Q4Qc+zP2JsRguvlUkt+ttWdmE5ErH6N/dqP6JufkHGr2xsuVXd?=
 =?us-ascii?Q?L7G1Fc6A9MQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?d+QtPOcVHolPPoavoC6o+nZ2H/r3zeCU30F3LRJm5wXN4hFtdh1T57IGDw2b?=
 =?us-ascii?Q?Z818nBsVfmEQDWIM4XBan1sbnpOzRm54QYmbgvtu6QMw4vBg8qWQIwYNIJF0?=
 =?us-ascii?Q?xurp4clN8gOMmCTpXTgwYqj0+g3Uhf3LPbIVw/xB9GEFqtXzIsAF3/0uWQqU?=
 =?us-ascii?Q?IOIf8yeXbKz7YNLKKtfO3UF6X6iDHQEvdaczT2buXzLJMRBFYutffG76gZhT?=
 =?us-ascii?Q?/8T617ftC0+LzE4UYnFKcMt8eq0YQZeQ/p+4EVFkEvcv+BZGIObK6Emq74JV?=
 =?us-ascii?Q?dSWUsTAPw8S9drgG1KOhtMQu9lkRR7Z/YiQWSZiatUPII8PYpGdTA4z4aqXP?=
 =?us-ascii?Q?UMbtPsy3TSZaL0WJk0TMAYInFsZzN8ppVhWkR65cDUxf6EzDkLpiIio5TeYV?=
 =?us-ascii?Q?TVwKwdHApsrNpkKez/rNsABepwmKYJsyaDZZpWxEmBtx2W8clyGgo4888GXI?=
 =?us-ascii?Q?lMPh87AALNf89FfHsm5xtdeyjn1xAKmdciJSokjSA5OWIHOeLgjXpSfiPVls?=
 =?us-ascii?Q?yXH6r//lxeGJRAoD391wpvAUL5emWcWzmx5WQS/Jdv72P0/Yw4A1VSfa+CPn?=
 =?us-ascii?Q?00EcwuvMuVUft8/E5veZVv0E5tO7J0219D9sfA6Y8l2thxl0ZBbseMVgYvhX?=
 =?us-ascii?Q?H5iBkUmVt6QcrvhLIY+yhGzO42yq0iYX7//ODcVgu45fPTjZNWOj4r8L5yTi?=
 =?us-ascii?Q?nSX7HQCRUHLTkI8Gwibfi6pGfDHhCnPxCSLKAswkt43Frm1oxl59bdcmh4xm?=
 =?us-ascii?Q?hZOGbgt3/LLjXzQgJQvn/lfBsC8QJFzwQjMKovO16RzAmbS6EvWaPE4ka+1H?=
 =?us-ascii?Q?v1n6eCWo7NDEtUIm0StPI+lYy/a7VioqPxrTjMztYwBzxKfpiXp00+DqKvBK?=
 =?us-ascii?Q?AGxb053i2l5LuSDbMtPw8G0f15lRdlPs2RYTLPP7ADvaWCV1vMWYkoenf4e9?=
 =?us-ascii?Q?iy7O2Ywhv6vZJ2mseiA4g28N3fzh9tYUo3zYUAUnd8Hkjc2Pu/SJS9Fh/Tuv?=
 =?us-ascii?Q?+mhyfX8uJfk5IQHnJQfCbMoQDgaL5IbxcaZRJU5DG4FUsEU/8vygvQtpztQc?=
 =?us-ascii?Q?vf7o+MrCDOuxaHPsFv0Gc8UrDXyxzum+/WfVoClRlbaHb47/x+DX7uEy0iIG?=
 =?us-ascii?Q?3eUfS3UH7m3fdOoL/o1JfkDNyRDw3nlCePSbjaBIck9romUEi7OxD6+a/kPT?=
 =?us-ascii?Q?NZ16FQ3sitRZIPPvHMcpUlcQnCIaV8f561CkRnt5A2dWtLcYqEd4yKzQpu/A?=
 =?us-ascii?Q?36ZWAUFkgOWqvXx0fUHo3Ay+OkfLEKT6FbfLwqqAFvqvFPWXrrKNMFhqdgI9?=
 =?us-ascii?Q?9RYnKAbvmvCyvv1gUlWjxHUo9s+gvflKbU+Xy5ouCaM0iI7wfmiNaRkTsMGo?=
 =?us-ascii?Q?jMy2nbrq2Dz5iyB8Patht++N12NPJQYeUKWzN8NGivfdCe//szSkIbDfUo9E?=
 =?us-ascii?Q?q5w52z9EKrfBQKZJKJy97QtkTT39+RD0qQpznWu7PHou6IGJPz87IWo3UZq4?=
 =?us-ascii?Q?igg0+/zrDaxwjtGEBtlTPU5o3jHWv9znVc/mC4yzA3QRlXGvnU9jwOu6WJOY?=
 =?us-ascii?Q?VJyrlYALuF+yfSZGbM8qHZTKXCCK9ewVwDxXp/2LvEvxECrjI6+nINGLP9fR?=
 =?us-ascii?Q?bw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Ktw3a0MwhWm5CJAHCeEhj1/5jlEB7mgn7eTZsL1kGDkPqpRATGkvJCrxBdRpspGbYRpG639/rhziwywGMi2HvUeWMsDr3g5cD7gLDaBOWD/bco0k7acImQWkDqpeGhW/jX+BBIlj9hjUb+BEIRb1zSPgBwS6PHQN4cWxAxLO7C1zcHd+hKLTZ4icSxvi3EkBxBuouE6Y/VD+myn9qpdf4fSV8mW/893r+9wST8xrUcqaAN6oSVn/x+LPyRh5F4cF8dok7VkP48OKxrVH20neL4VMDpIXMERAz+Wfz4ELL0fOOpA2358v2BD9sUjupaeeF/XJgd328QbZ7rvV/YKv2WmmQWZl2v1kIumubKqWEVfoF8/l5ItHDoxumy7D2F7g25xYL1WTuf3XlZUZH/U40nhnumAzTSyN+bOvNV9pbTY/sA8nrRMAPnPco0+KR1TdOKELLygi2VIJAf1xt8S+U1SZE8KuS43Oz9ynLL7/d4vOS89Bs1l7jfYWfd0m35hKj+HrvLq4WmnyEB5xtqcLLaF3mXNZJEYiyqBurC6yIftw2Sf9b9NiTO55tiTBccRHeOQV+rFnGJtT5JqL1ufFlG/TH3XboA+SYTC3tghrvVI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 35a9a6db-7ed9-4f4d-b52e-08ddd8c93eef
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 11:21:41.4121
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 2k1wkYC6sk4eN04wXRBQMZzDrQ8HaiU+tfnZCbyBgKjdXp6HJzjTudBBvEzCvVmtWOl/NnAN5kQhWAyXIVk9uTKFvZ1VWhXJpn006S2NgrU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPF6ABE13187
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-11_02,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 phishscore=0
 spamscore=0 suspectscore=0 mlxlogscore=999 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508110075
X-Proofpoint-ORIG-GUID: ZR8xNFlYMDsaTdAXXbrD41ZoNJNwO4HT
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDA3NSBTYWx0ZWRfXygwxCP/WjTsk
 VxZXq1WXw90WWQzsZPMBxeFy0XIbgdNCdw8oVcOiiK+o1h2IzR5eaJxU2oaxLCIrtPvTGF3D9yO
 ij0tDp4BsiAfp0lhvscVDBmlreYz3ZdQWiCkMSwM68jUwscI1yrmWC1vMlwkXQawFfR1NqlHHR8
 zV8UzWCyEbIcRPdhKwtQXU36o3EboRj9vHMt8ZcjZ5yP69Uza9iW/fTzs5NpsM2c7PxxMtrN0sh
 FN1cGQGfVYPXqrhlHTXvzuRePdjOSdoNsbg0VrJEddVO8dF55JOrHn2rrkejSfQUceF1tft9U/o
 aPXr34TKzhRpvDsrkKXxr6Lh/l4zjIQXWqRqSYosNUt5y+ELGvAZDlYkiUpZ3BbsLgeJ7Kjr4K2
 QfUA3tkrZ9kIUlyKvkiJ7JMDrR9MGLLjsk2JmdssJI0rV4Uh4NGXFCfYkx796mx9aedfRk/V
X-Authority-Analysis: v=2.4 cv=X9FSKHTe c=1 sm=1 tr=0 ts=6899d249 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8
 a=NsIIGTxukypT_2S8kAwA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12070
X-Proofpoint-GUID: ZR8xNFlYMDsaTdAXXbrD41ZoNJNwO4HT
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=FHiRvJof;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=QroKQu6T;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

On Mon, Aug 11, 2025 at 02:34:18PM +0900, Harry Yoo wrote:
> Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> linux/pgtable.h so that they can be used outside of vmalloc and ioremap.
>
> Cc: <stable@vger.kernel.org>
> Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>

LGTM, obviously assuming you address Mike's comments about... comments :)

So:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  include/linux/pgtable.h | 16 ++++++++++++++++
>  include/linux/vmalloc.h | 16 ----------------
>  2 files changed, 16 insertions(+), 16 deletions(-)
>
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 4c035637eeb7..ba699df6ef69 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
>  }
>  #endif
>
> +/*
> + * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> + * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> + * needs to be called.
> + */
> +#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> +#define ARCH_PAGE_TABLE_SYNC_MASK 0
> +#endif
> +
> +/*
> + * There is no default implementation for arch_sync_kernel_mappings(). It is
> + * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> + * is 0.
> + */
> +void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> +
>  #endif /* CONFIG_MMU */
>
>  /*
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index fdc9aeb74a44..2759dac6be44 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -219,22 +219,6 @@ extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
>  int vmap_pages_range(unsigned long addr, unsigned long end, pgprot_t prot,
>  		     struct page **pages, unsigned int page_shift);
>
> -/*
> - * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> - * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> - * needs to be called.
> - */
> -#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> -#define ARCH_PAGE_TABLE_SYNC_MASK 0
> -#endif
> -
> -/*
> - * There is no default implementation for arch_sync_kernel_mappings(). It is
> - * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> - * is 0.
> - */
> -void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> -
>  /*
>   *	Lowlevel-APIs (not for driver use!)
>   */
> --
> 2.43.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b399b898-9b18-4d4b-8a9e-d9f79ffa524c%40lucifer.local.
