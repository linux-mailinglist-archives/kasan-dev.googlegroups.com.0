Return-Path: <kasan-dev+bncBD6LBUWO5UMBBH635XCAMGQEA5MOSSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B6CD7B22DCE
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 18:36:49 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6fab979413fsf119237586d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 09:36:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755016608; cv=pass;
        d=google.com; s=arc-20240605;
        b=l0FjaiFE2gZr1/fs6iY9wA9D2Y/zSwfPVH4kakKJrb4TZj3iSmPYqDK6T+GbhAWww5
         r5ai6lRtmFyZATl/iVTLclz9jXJ/ygdQOA6s71iJWmA0wkx1Ji7Oy2DWEe1Bqqe0XwGA
         JhuoEfUOj6SzwJ+3WMfv6p7ImDUGfH78xfF16p/6zP+W03+l5hU1/qHGGJXcZFvf3u3o
         blXoUakVdbUmQNa7L6yV96x66B3GwRnWGTKJT0Tu0xQ8ZQzCPoCe/QfSc1rySKnLlgcL
         PXjxDhisq1IXPhZ2mJ/Lj2sZfKeye92+eWxCaKJgELmV+r64U+cRe8VuU3HSlly6FYkd
         ZMOA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=DURDP7ojFJ1V+tzwK2ddBOP7RDm+7B3GyG3YNYMU8po=;
        fh=suR/ue56YdXH80JQ2DmW7jdH+iH4hz0sqg9V2km5884=;
        b=fZTj3sovXK8wcYtvAP4dgvPIpl2cAq3KFVtP/Z1uHhs24qTNu52D8rQ8BhvpakCvHf
         Z8Rqt4RvPcWgSqmuL9wUdMllq6+Q/+VxxcWRwOWZH3NDrqZ2shqQyS1mKQq9OvcQuXXI
         9/fnzAjHXQeQgFdsfaK8bBYqKfNs7u7cCoS7BgiqMBb3a/WZ1EgR4CGOXuFdPAa2GSgj
         8UxX2VGd5czErBq+5/JA7PXgNqv/oP3pzvzX0YXaHntRMiN4+FhgK3ZsgrjYRg86nYdz
         d2yNWu5y893XnT+L9lYQl2rU56mSaMfJGdUTF41v6nKWDret5xZfg/xAiO0+p+42GaVe
         XJQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="AJ/VppHl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QyN7WfkP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755016608; x=1755621408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=DURDP7ojFJ1V+tzwK2ddBOP7RDm+7B3GyG3YNYMU8po=;
        b=ipU9DoRP93hZvGsKSV6XzL75XG722Upt4nyKzfMuiB/mFKBVHucD0K4bqPrwP3pRSj
         805DNX6PhlFHNkff9uYezm1kHqh9Mf5UwekUSo5lYIse9AYxO/Dsvsof/6CI+EQXTeZ9
         t3u/e0tilpaO8zuKnE6CSNpXWHiuUWeQ3Yh5xHuEcx8swWZBe3SXH6iib9AZ/4bymOCk
         wGcYHf/CQ1co8hNMZ70ayGJrxObhzo9UaFQSKtmDsj5fN2RSV9kI27f7Ok4mnj7nOxO1
         8jczYwKaU10ifiOtQ/jUz3M1poyp3Vx+j+Xf+fpd36nMjDxiOaFEyzaPwPWC+hWS4oaE
         2OkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755016608; x=1755621408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DURDP7ojFJ1V+tzwK2ddBOP7RDm+7B3GyG3YNYMU8po=;
        b=ODaSwUSOEu4iK+GpP7p02sLku6UcxCqp8rx2WfeGlhqU2ySU+vPBI9ywWJM/uW7GMM
         Zxs4y8mYmBFWVkakSjVAVNUq+JXGRT9QIdVH8XQrYkUTIiusN6TfNs8Tn+R5+bncuLc/
         +UWQ25gkP/clV3iv1ij20q0zLY1ImTqKkGJPqzBBGpGvcMhpFEQB1oEsXsN9ub7VaqL/
         oITt7ir1E4ZScgpQEbiGYbVTo5YdLbTPE+zo+DncxScK42QPVeUrfeYRlR5q9ns99g1a
         YMh4GSCXY6yJ+bgfuWR/TWNW8CoThnTHJNEw+gGFtBTh99pD76QASFBgvAGF6xbgh0/6
         KpJw==
X-Forwarded-Encrypted: i=3; AJvYcCWQebts7B3PKxzb+Ue+eKj04r+OdkMkrPqwmtiOCm2rN2O/RTU5BxvThobCyxv+/eJp0HzPBQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw/kqnx4R96Ev7KM30mZc2ppx3Yqb+uUy+322KHdAdExnpczbjt
	j5oSxYRQ0TKrcO2nEnpvfhhvKeUMnfftBXrM7+Yd6OHh2fOix2h3LJMR
X-Google-Smtp-Source: AGHT+IEomebPIJfac0vayDEO36JDAqPYMExNH41Y9UeD9A3+cn5xkmu2nnXv2PBBKMG7ClbCYV6rXQ==
X-Received: by 2002:a05:6214:508e:b0:707:5221:3071 with SMTP id 6a1803df08f44-709e6d4700dmr4286456d6.47.1755016608082;
        Tue, 12 Aug 2025 09:36:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfxo6b5uaTaZd9S3or4v4j0boZdaWzRMmSqnIjigpTSIQ==
Received: by 2002:a05:6214:5008:b0:707:1972:6f43 with SMTP id
 6a1803df08f44-7098834d270ls88561606d6.2.-pod-prod-05-us; Tue, 12 Aug 2025
 09:36:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUatGUxMFoLtXifuHSi+k6qD5PKGCZQmFaOIQkNidJ0GlXQEhb0ul5/rEGOISH1nNRheELP4WVLtQc=@googlegroups.com
X-Received: by 2002:ad4:5bca:0:b0:709:82dc:b1b2 with SMTP id 6a1803df08f44-709e6d5a82cmr5109766d6.48.1755016607068;
        Tue, 12 Aug 2025 09:36:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755016607; cv=pass;
        d=google.com; s=arc-20240605;
        b=gaSCmgJXT2oYAzXdXSH3s4o1spLX4KIe2P7S02RbIliPMTSc8q6H5xeUEVvYHMEfKD
         v0hPbp//vXWOwegNxOd1EnQopmwzhV9I7PYRBZ7PUrOy2g59DeUw2tVsHZ1d0tcKRfV3
         kUWCDjT4WFSeapw4o0IZCWDYGcof58s2rP7L91M1ri4XbFUR0aLs7HXRc9dGEd72zBve
         Eesyv+Q/smM1VuMOyKEqUyGcMAmtZD0Lu/sqtS26RikdF5eacUttpX25J8dUzAQGLMVN
         vkPhQ6rEojJ3LwdostsLlBLVur7sAUsOq3chihrv8g26bjfzhorBt4Z1zK+gDv/7UT/i
         QFBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=49zvGBJMxE2ccpjw3+7u2huZLYolCe1JiIqXQoAkJAw=;
        fh=PLQgFxTRLyhcg3N9pmSi1Fg/j2fHtLGfM3ZloGi4B4Q=;
        b=fzpRTatqm+5CLa9sLP/bfzPNihy4B725sY2v4YVHxx1l7WHVsVajMlUO6foJ66Yof5
         7x7dx1Z1jfD0YOUQd2MNtyam8/mPs9NFUy9xItz+jNf9xFBaWG7rqdmzPnjTlzBLgCXb
         cWVqWLpPSNlWq8ujoJSqB18LIDhCB95wUzwlq+EyzEOIzzCExTlxd2nlqYtBW81jeYzO
         PLt789yBZOBPP6wwwVvgBkGlJgy09vgpU+QjSh+ZEllo2n5TvUnDgvV70ISxKsAm0pDx
         +t9md3GQNUX3UvEyO8YKT7bbv1YWGy16us+2nM1FrJs//PryiCRzdajqZWh6lLWLJSqT
         V2ow==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="AJ/VppHl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QyN7WfkP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c3b7ba9si5824326d6.0.2025.08.12.09.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Aug 2025 09:36:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57CDBxBO007852;
	Tue, 12 Aug 2025 16:36:29 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dxvww1mb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 16:36:28 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57CGOkuw030234;
	Tue, 12 Aug 2025 16:36:27 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10on2067.outbound.protection.outlook.com [40.107.93.67])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvsa721r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 16:36:27 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=d23s5cCUsWeYe9mZR1P8FAUlxZSn+5Ilk6q+dKjyFDwlD8p+i8o0Li/3314TRN6qv2bxiFX2p7TcP0g3QDYYug9gfynrU9grV9Pg1ztKJOaAdEqVb+hKMzr1QCTHKCFuUDfnqhn+q1QumJKjasUs26yYb/zxoPTreoMistNcK89nFrJjuybfL9spcYpKuy/hyCPFLld0VeRh4brqlwcMAX9JySXavD1lFDa1tA5BbtOXte5S1iOFDkjSBZHVHWpn5cN+VXGmOAYlxfXp/GgRDh4cLH5YgQhJygOQu53DQBWznCTKSpMuSVTAtHsBvqakXqeomFQfN32fSRsenbkKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=49zvGBJMxE2ccpjw3+7u2huZLYolCe1JiIqXQoAkJAw=;
 b=oCV5qpQnsZN5+0i4FDSJzy0EMyLyQ0rxxLMp5E9TOruwWQKFAyC3YIETmClZOyoynqC1JjB1dM8/1fR+GBf0Sqiv2GiGQq9zWOpZ8rpIUThNfd7kW68HfzBNpvaB7kW13El+GUW4FTa82ddoP6WYSe59SF90XRdCyaMnT4zf09qOc/Ib7VQmFN+llOyJ57xgTc3vLnOHnw4LEyYlkaYOLVVY3Da8KUT+8SLlHYpiPN6v3+E9lYk2amsi2ErhiAXZvyNAY0YoFZCHtyfXXljDlcs7pVUoH8uNyA1JzSsiYGv0BHuAJ3TuVyQTBMdi+faTn77qPv34qOWvl7WmdBvpyg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB4478.namprd10.prod.outlook.com (2603:10b6:a03:2d4::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Tue, 12 Aug
 2025 16:36:23 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9031.012; Tue, 12 Aug 2025
 16:36:23 +0000
Date: Tue, 12 Aug 2025 17:36:20 +0100
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
Subject: Re: [PATCH V4 mm-hotfixes 3/3] x86/mm/64: define
 ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings()
Message-ID: <ca172db4-be84-4f82-9bf7-c65de8d997d2@lucifer.local>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-4-harry.yoo@oracle.com>
 <9b57f325-2dc7-48a4-b2f0-d7daa2192925@lucifer.local>
 <aJsCVtgfIVxT6Z93@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJsCVtgfIVxT6Z93@hyeyoo>
X-ClientProxiedBy: GVX0EPF00014AF6.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::31a) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB4478:EE_
X-MS-Office365-Filtering-Correlation-Id: 0ff93a77-456f-4c08-91f4-08ddd9be5fc7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QvHGG09qtHMsgWEdl1uCwtieaFHx46Cd7Kt6AhwtJpoZ2n20/Z4fwwC3GUpj?=
 =?us-ascii?Q?VA64gqf/lTZc18hhADhishG0UxiIUwKzDgSurH3Szck0pHSqGsS4pUZJOinV?=
 =?us-ascii?Q?NCD9UeRFzTuwP6evDLPyFvRqDcKi1zhPwbclRS8+D/R6e5EIxc823Bi7Y6p+?=
 =?us-ascii?Q?epJZ59cnNci6IyXhLbxCRZ/CaG/xL0CE7SgegIpdzAzgU/rU5NjnnZXeO//B?=
 =?us-ascii?Q?iFlnzffB8R1ig3LaEv5APKETxz86riC15DOY8tnXOpKfDzuY8VYDmMbyr2lL?=
 =?us-ascii?Q?7SnDSux/LvwH7kNo4jBQH2gHOHiLeCxU2GxD7nr/VjX1wQbSdHtCwPD6RLmp?=
 =?us-ascii?Q?ehlP1w6sL7IffqmgR7RR/ZSHbwupS/9M8V1wbljQCDuI40oi8nz+gNMwmv21?=
 =?us-ascii?Q?jlb4qyRBLMxLeG2gg1mdRDkQplwe8+RIo9F5VqhfhDKEGJ7M3sngx0BfvsPz?=
 =?us-ascii?Q?T0+urLcXW1GmtzDvhAu1u5mKtOu5yJ0JgxnGRsb+yuC9KrawL8GcZZt1NnZ6?=
 =?us-ascii?Q?HTSGK1mYUSuKghm5ZJt5VtLbEnErMoDolbmVeQqerYkFJ8S4nPe0nRSGqviK?=
 =?us-ascii?Q?kTViX/c58bgZIis+w/uJnYK0n1u4hA6xFicoY4poKmjrqXHe0PVaa3RpIFto?=
 =?us-ascii?Q?wY0NXNCohe+WNjGRIJJihFEviiGhHHNnW5FcXsed6Ezu/J3eCXvney8PuYA1?=
 =?us-ascii?Q?MtGG+LLhYRvn5EzwX9lZKCFQ2jh2PaEhQudh9T//4eBpPAqygYdNOFh1zUlY?=
 =?us-ascii?Q?PSXVYGMaQLUTt3fNMW5p91lUkOIsU1gmeh2cVN3nT65fX1nPMS5LNiOGff7S?=
 =?us-ascii?Q?zbzsO/zw9JPWPmDJyz8le2nQrN6DeD9ws7qCczMuR7Lxh2P1x3kUgHgdenXu?=
 =?us-ascii?Q?/NduFAiYsPMzpA1w8/edcUDhK6HhszBA0OdEnnQ9wRMD0KzY/1eMgxTumjf2?=
 =?us-ascii?Q?ImaBM8QHfSENVTyfQkDoX4YR7iQ2pgdqHXUGTyMsvReBgg2n0N5Z1ofNxuHu?=
 =?us-ascii?Q?eS69fkpJ1OKbZZz914BYo+WCiUnsLbBQxyQ9bWfZqGYRUUJdizHWUSUCbCfw?=
 =?us-ascii?Q?0ciNQfVM1VDaW4D96ElLh7/EnecQFgZo/JfiS0znCJzWzTo5sfzY9Emc1lMa?=
 =?us-ascii?Q?q/37qcjcW/ty6k7+1+gmsEgSVNiUq97XzqMNf99TS0+yLLhKGFF6GkhdT3X/?=
 =?us-ascii?Q?8/FPOw32g6FnoJpfWz7KP2rKcPjcEWg2wlvSPhCMDpfgVKiQgkFN7mzOXRMx?=
 =?us-ascii?Q?+z44BRjZ0PthcqGoOh8N5PSwtZAtrQxJgsMFTg2RI8s69HFLmx+UjmmHAmjA?=
 =?us-ascii?Q?XFcm8oPfHZCv/TAkAPXTwTk5ZtcfOg0Kcnm2gehVHmgYd7d2FUctKDyZ/JUI?=
 =?us-ascii?Q?x1fg3TAnkp9weiYIPJFien8pgF9c8BaTQ+FrUdwc5BeFGYpNq61+W5YXix/q?=
 =?us-ascii?Q?YuzMuvjmmjs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?+LkMo/VeDFGo/SnjsMz9fX9qH8ge+zEnX1y2Wqyn8HQGBPtHnLkMjMi16aQl?=
 =?us-ascii?Q?cpEDdcUJ+7V6InANPBJkDd/Gs0N9DmwDJwoFeYgf4e6vUNlaKa506pKsC7B7?=
 =?us-ascii?Q?zWJJyp2bdcEHg9bcQqpO6pLNjZn6VuMtNjCyzZhEQqm67IvJgjdJTLc/FF86?=
 =?us-ascii?Q?Y4YdzXlCNTFFw5LtSI13iqDjrOCd7EJFih5bz2JgCna4QG8rmFiatHtVvUCW?=
 =?us-ascii?Q?fvj6D0Iheco8NyoH+wpzsGuIhyLKbuSma3OuooCZlv2OSjCTJ6ZxTGbkVIZb?=
 =?us-ascii?Q?neZ8xG7p1ITXFENY4hygiWMsd3Ib5vmeZMv0OUD2/vWaHBMB3AGLDMX5wBCB?=
 =?us-ascii?Q?IiLb9qsnhIyvA9sP1VeubhuvMVohGcJ+AFJfOjkueB/YTB6JCZ6uC9qpIIlG?=
 =?us-ascii?Q?ljN+52pXgevbU/Vr/r/ikbBiJjhv0IxsRHVrXZwKQ+nVykMlktfLC1hM/uqp?=
 =?us-ascii?Q?DQfWHwUuXVuMpyIZoMrJPG0rer/iRvJQVQ+Vs4ObMyBHoA3YY4CuidqFGRfY?=
 =?us-ascii?Q?C6ecofz9jsq7R6+6KFmxH8nGPhyNzS2Rc9Y4z0liRYwRidTPWYuStbwdCz/d?=
 =?us-ascii?Q?YpYsehdTqsoPJGHRyc6Z2GCJyHbsXYgQi74j7KsEkjR5PxRe0mflfzqchBTC?=
 =?us-ascii?Q?i74Gq40c0jQSnqIBhBeKpVMoS0EM6F0agcAOPek30PZ2g6NuV1s0SpzEFfeR?=
 =?us-ascii?Q?J4TE7DBuO0HuWvdUibce6OlOvjvOLbAk7VCiKxt8Uttx2Ykcn9JVPucxgU31?=
 =?us-ascii?Q?5x2Eoodx1e3uPwOXO7ErAzh0JxCkm1nc6H7cR0XgOlDK72F/X+qUGDck6V/m?=
 =?us-ascii?Q?+OBGCzp6u6/Fp5M234KSu3RPpA0K07NPEIQvFtn2MNxORL7i62DQRB+wvRvi?=
 =?us-ascii?Q?fimFRtRJ29uMhqcWcS0OodwMfxAoEI68EL9uhGLRF+LAqw69HxQuPcOc0+tZ?=
 =?us-ascii?Q?dnHHmh4acf7FymEu/Gf5odDe6NpSUkD9GjTTBQ5f/wzgze08Rdi+uETQaPPQ?=
 =?us-ascii?Q?Ych7J3OwfFbb4BRjnAW01M/Pg/GUUUKeTf2cvG9h9Dn3JLXz8C4xhkOeqGHs?=
 =?us-ascii?Q?twB7l19JdnRKGDsk5fG4XExjDkgUTR3MYkD/uFnClNN6onZgFp092UgzZIIh?=
 =?us-ascii?Q?Eju39eGvqY3UwB2kGVrmb3O6HK/O6qJhFa5ovLOF/f/e10l2aqBKoX8KFHks?=
 =?us-ascii?Q?Zcj/AfuGui72c2ihMEs6T7jMadE64//BS8sGth6TclJTlyZriRzH1Sk1WC8M?=
 =?us-ascii?Q?09Jm6bNcyuTtn9KhugC76msTosTqhWYIdGvdIe9cl3yktywesIVY4TE5dHOZ?=
 =?us-ascii?Q?1wjQsSQVKYSvYPhpYa3SQlfWo/ZJKgjKCB0+uMvQSWqp353bElpC4j+jFbAA?=
 =?us-ascii?Q?s6FPe2/A+SGCI3pO5ThJZUkbV7Zv+Yb8e1SLmn4azg8OW7GW3XnKf0WpnN+c?=
 =?us-ascii?Q?YPE9jiXIjovFfuGVoMrNPz1vxmOCaLAI3fqutv5ugU0x6pLGS3d+9UxkyCbn?=
 =?us-ascii?Q?zLpWQfbsKX6CJTwo/cZEDQmS13lnlolG3ek8LrIvli4B3W3Ho6ufgQUFKrd+?=
 =?us-ascii?Q?BB6RWRc9tnVXC5PHVMhd4ow3IDsNy3fET+LftdyOG579z85mbAfkBLgqVlW5?=
 =?us-ascii?Q?9w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: SpkempXuKtg4MXfV/aejgJxqd+XSu5xee+2sNS/fkmoX1Dqf3wXy8cwp+oUcpU08Z+IVZUBLmLaL+CC//LaA9iUMTgEyMS9kEf3P5AX2pT1gikxFPHpUljoKP7tkFfvvm0Fm/Xb6xTpVk3KJ6s2UTpip9gGNR5Vnj3vxymlw8vULu5VX8RvX9Q/MzBki8oBECF7hm49JxHerqeUICrNQuKGlYDCHJRr/YlIMBcqVlAAaM4VA7YUlAHC3GXn7+8czY69YQjti0ICGBXab/sNAhOXqV6119s0+7eWA3wC8INCbwsoV5vBFvDLoK/8aqkivKygxIQ8ns6jNwzxzumFasIBt1m0sRFDW0ZP94p6y8KgeyrM9kZ34m2NhD5jQLosLLnJsi0q2uTkwKHlB6qFWYeueH3VEX6hk5Mwh4azElfiESH8ndwWKefM7patHq/zkQTpS97uBzqSM2P5G7y4PRluqdkM3dKbMKMlpIcVLUMPKp6X7V6v+2Vj4sIQz6e0c0KPo9wSDHHKbJZbqizEUc9XU7J/E7h4nlCKoLGQs7X667KPHldt93GNxexIooXOY/iBa9ZYS1/syNhtUECpvs2tSjWvnIBsVQCPdyKn9w44=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0ff93a77-456f-4c08-91f4-08ddd9be5fc7
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Aug 2025 16:36:23.1298
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0gVIeFBb9PKlG45HY7zvtxAwJiruirnZY5LLibronvXOkj27ERF+HxFCySdaf5iSe5aAWwN+yCm338qUo1FmYF3XQ8jlWZo4LBrPBOgUV7Q=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4478
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-12_07,2025-08-11_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 adultscore=0 mlxscore=0 bulkscore=0 spamscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508120158
X-Proofpoint-GUID: OMeiyPJLkJSOMUmF9KpSdehG6BN32xQx
X-Proofpoint-ORIG-GUID: OMeiyPJLkJSOMUmF9KpSdehG6BN32xQx
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODEyMDE1OSBTYWx0ZWRfX7k0T1uWEEAbe
 NhOeHcfhYjNZPmiWbW8qwUidZaqXCNhNCbmrwh02VOOAdx4V0KCr483fh9v/Cclbv+435PfkPqt
 5XLRHGJeWWWEZMs+L5MYgw8VxcPPx1/Tx0pnVC3nJVqngvMPw9+BYkKD4IB0L43xyjESU7pSrx8
 AyQAS9+H1r9fBnX8EKoPB3vWC5Osq9+9mDs205oGhkkbqmg8G9r52RF92z6jNV/UmT+HQvaUviy
 OLBvTJn67FtZIhDkC6MhtZOMbzOKG6oACpJTv7Jfv/DUw4TYD5Fw2BdIvrM1fuKvmVoZrd0X/yc
 xa86diGKhPkKDuXkRKNWBdhtczVAfHWcp5QQd/eveAdvdTPay4UGFmyIhASm/BNd/eS5C4sjwIl
 yZJlSMIP3xTagZyrsFsRu/pmjjRhgiXazlBpuyz8X1FXg0R9vm4lGYVdHULlVP+faMSvN8tT
X-Authority-Analysis: v=2.4 cv=dpnbC0g4 c=1 sm=1 tr=0 ts=689b6d8c cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=yPCof4ZbAAAA:8 a=WGoLGLEUZeYSAlKTZ5wA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="AJ/VppHl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=QyN7WfkP;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Aug 12, 2025 at 05:59:02PM +0900, Harry Yoo wrote:
> On Mon, Aug 11, 2025 at 12:46:32PM +0100, Lorenzo Stoakes wrote:
> > On Mon, Aug 11, 2025 at 02:34:20PM +0900, Harry Yoo wrote:
> > > Define ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to ensure
> > > page tables are properly synchronized when calling p*d_populate_kernel().
> > > It is inteneded to synchronize page tables via pgd_pouplate_kernel() when
> > > 5-level paging is in use and via p4d_pouplate_kernel() when 4-level paging
> > > is used.
> > >
> >
> > I think it's worth mentioning here that pgd_populate() is a no-op in 4-level
> > systems, so the sychronisation must occur at the P4D level, just to make this
> > clear.
>
> Yeah, that's indeed confusing and agree that it's worth mentioning.
> Will do. The new one:
>
> Define ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> ensure page tables are properly synchronized when calling
> p*d_populate_kernel().
>
> For 5-level paging, synchronization is performed via pgd_populate_kernel().
> In 4-level paging, pgd_populate() is a no-op, so synchronization is instead
> performed at the P4D level via p4d_populate_kernel().

That's great thanks!

>
> > > This fixes intermittent boot failures on systems using 4-level paging
> > > and a large amount of persistent memory:
> > >
> > >   BUG: unable to handle page fault for address: ffffe70000000034
> > >   #PF: supervisor write access in kernel mode
> > >   #PF: error_code(0x0002) - not-present page
> > >   PGD 0 P4D 0
> > >   Oops: 0002 [#1] SMP NOPTI
> > >   RIP: 0010:__init_single_page+0x9/0x6d
> > >   Call Trace:
> > >    <TASK>
> > >    __init_zone_device_page+0x17/0x5d
> > >    memmap_init_zone_device+0x154/0x1bb
> > >    pagemap_range+0x2e0/0x40f
> > >    memremap_pages+0x10b/0x2f0
> > >    devm_memremap_pages+0x1e/0x60
> > >    dev_dax_probe+0xce/0x2ec [device_dax]
> > >    dax_bus_probe+0x6d/0xc9
> > >    [... snip ...]
> > >    </TASK>
> > >
> > > It also fixes a crash in vmemmap_set_pmd() caused by accessing vmemmap
> > > before sync_global_pgds() [1]:
> > >
> > >   BUG: unable to handle page fault for address: ffffeb3ff1200000
> > >   #PF: supervisor write access in kernel mode
> > >   #PF: error_code(0x0002) - not-present page
> > >   PGD 0 P4D 0
> > >   Oops: Oops: 0002 [#1] PREEMPT SMP NOPTI
> > >   Tainted: [W]=WARN
> > >   RIP: 0010:vmemmap_set_pmd+0xff/0x230
> > >    <TASK>
> > >    vmemmap_populate_hugepages+0x176/0x180
> > >    vmemmap_populate+0x34/0x80
> > >    __populate_section_memmap+0x41/0x90
> > >    sparse_add_section+0x121/0x3e0
> > >    __add_pages+0xba/0x150
> > >    add_pages+0x1d/0x70
> > >    memremap_pages+0x3dc/0x810
> > >    devm_memremap_pages+0x1c/0x60
> > >    xe_devm_add+0x8b/0x100 [xe]
> > >    xe_tile_init_noalloc+0x6a/0x70 [xe]
> > >    xe_device_probe+0x48c/0x740 [xe]
> > >    [... snip ...]
> > >
> > > Cc: <stable@vger.kernel.org>
> > > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > > Closes: https://lore.kernel.org/linux-mm/20250311114420.240341-1-gwan-gyeong.mun@intel.com [1]
> > > Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> > > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> >
> > Other than nitty comments, this looks good to me, so:
> >
> > Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>
> Thanks!
>
> > > ---
> > >  arch/x86/include/asm/pgtable_64_types.h | 3 +++
> > >  arch/x86/mm/init_64.c                   | 5 +++++
> > >  2 files changed, 8 insertions(+)
> > >
> > > diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
> > > index 4604f924d8b8..7eb61ef6a185 100644
> > > --- a/arch/x86/include/asm/pgtable_64_types.h
> > > +++ b/arch/x86/include/asm/pgtable_64_types.h
> > > @@ -36,6 +36,9 @@ static inline bool pgtable_l5_enabled(void)
> > >  #define pgtable_l5_enabled() cpu_feature_enabled(X86_FEATURE_LA57)
> > >  #endif /* USE_EARLY_PGTABLE_L5 */
> > >
> > > +#define ARCH_PAGE_TABLE_SYNC_MASK \
> > > +	(pgtable_l5_enabled() ? PGTBL_PGD_MODIFIED : PGTBL_P4D_MODIFIED)
> > > +
> > >  extern unsigned int pgdir_shift;
> > >  extern unsigned int ptrs_per_p4d;
> > >
> > > diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
> > > index 76e33bd7c556..a78b498c0dc3 100644
> > > --- a/arch/x86/mm/init_64.c
> > > +++ b/arch/x86/mm/init_64.c
> > > @@ -223,6 +223,11 @@ static void sync_global_pgds(unsigned long start, unsigned long end)
> > >  		sync_global_pgds_l4(start, end);
> > >  }
> > >
> >
> > Worth a comment to say 'if 4-level, then we synchronise at P4D level by
> > convention, however the same sync_global_pgds() applies'?
>
> Maybe:
>
> /*
>  * Make kernel mappings visible in all page tables in the system.
>  * This is necessary except when the init task populates kernel mappings
>  * during the boot process. In that case, all processes originating from
>  * the init task copies the kernel mappings, so there is no issue.
>  * Otherwise, missing synchronization could lead to kernel crashes due
>  * to missing page table entries for certain kernel mappings.
>  *
>  * Synchronization is performed at the top level, which is the PGD in
>  * 5-level paging systems. But in 4-level paging systems, however,
>  * pgd_populate() is a no-op, so synchronization is done at P4D level instead.
>  * sync_global_pgds() handles this difference between paging levels.
>  */
>

That's great also, thanks!

> --
> Cheers,
> Harry / Hyeonggon
>
> > > +void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
> > > +{
> > > +	sync_global_pgds(start, end);
> > > +}
> > > +
> > >  /*
> > >   * NOTE: This function is marked __ref because it calls __init function
> > >   * (alloc_bootmem_pages). It's safe to do it ONLY when after_bootmem == 0.
> > > --
> > > 2.43.0
> > >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ca172db4-be84-4f82-9bf7-c65de8d997d2%40lucifer.local.
