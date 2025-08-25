Return-Path: <kasan-dev+bncBC37BC7E2QERBOMSWLCQMGQEFBG3YOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D101B346A1
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 18:03:07 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-61da04d1238sf4282031eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 09:03:07 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756137786; x=1756742586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=xg1cwEDBQWV0S8QzBLuP1WwLbkvs0PW0usnr38rjL2E=;
        b=jUH/rkeFkVnD7khLcrpLvJL46xmI5HLXUJMNQJosLdLabBCc+NOGZX5EhwRgJByuIE
         +Xs+nS2O4RWph86hdSVxU2hToKjO3SVsNX3b7oj/6f/EBLzGYEDph04sG3OFpUmB2SZK
         3M0gVQ0HVt9BdbnzlPVtUNYLUkfVaIPmbpjdOYyzabcP5tgsbfyk63hTBPsIMY+t0f9a
         699/DSdyRNUpENSSrLuApvQXlJS2YwHuAvWxWyLconoaIYiVQcm9RukxkZoDZvXLPlXe
         JznbaZsK8axilFIn1Wb48nzfv0F+AuQh+NTdjfH835x+pk+Xe3hD6XycgFWmVVbjxUBh
         gq2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756137786; x=1756742586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xg1cwEDBQWV0S8QzBLuP1WwLbkvs0PW0usnr38rjL2E=;
        b=OCNhV8vBx9KAoaKtF63FSTZkV0fyUjr9ruAO5dQ0qX68GH0a4ay8jv20NjTU2YugxZ
         C0b6y9L35upBThKuY2/up/5riV2kpbD/9tlxfAJXlyMFGmiVgzQgAZ4k1zILZ8LDPRyF
         J7FmQnZS9lnO6viHO7mawMgLYYIFnfzWsqbVSzfn3kgNBnyoZokErHaCQjKgktgRuHpD
         W17s7kRDs0tEH4D6JkLcicJAgRbdeN6ITnmlRvmEmhf90mLDzff5cO53gFj9b8ydrI6p
         LOUKZ2BGuwTU72OKgZOFqSOH1ygh6Z0HfP1S+hi0f+PvEfwf4h2TGww8J5FzZa36rZNG
         Lb+Q==
X-Forwarded-Encrypted: i=3; AJvYcCU4nbIAnYBxxl/iGgzzohyWhhKlcvngg1lK1M35iPX5PhiNRPJBd7Xb5nO7ZYNlfnQHjlAXuA==@lfdr.de
X-Gm-Message-State: AOJu0YwO5FodaddH6U0KSyKAjG9NL7p4Z1nRPDCqRysutnKKw4usw2TG
	Ga/ZUAD92UujuYP5cFaR2CJ+4DiFILW1+8CbYHjFhFsQO36MQCPK7fES
X-Google-Smtp-Source: AGHT+IF14UMnOQfg8liNEXJEHMJh1cQ512zneC1q2G1eGGW76TD9Agg9TCkYidYSbhAPkec0aAIkQw==
X-Received: by 2002:a05:6870:e416:b0:2ff:8c8e:c222 with SMTP id 586e51a60fabf-314dcb56717mr6931261fac.14.1756137785817;
        Mon, 25 Aug 2025 09:03:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdR9I/U2DFtH+zjAw8UQzqPxt+79P0bEgQ+911E0WKGDw==
Received: by 2002:a05:6870:55ce:b0:2eb:b30a:f5e0 with SMTP id
 586e51a60fabf-314c2285a1als1689231fac.1.-pod-prod-03-us; Mon, 25 Aug 2025
 09:03:03 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV3cOyK3MPFZRPN5801lCedlyn5MXgZqtOoDAVpvgY9PZvRGCK51Mq4/MtoQrBa9Y+7yNlx31jy+t4=@googlegroups.com
X-Received: by 2002:a05:6870:65a2:b0:314:b6a6:6895 with SMTP id 586e51a60fabf-314dcdd52d9mr6538740fac.41.1756137783091;
        Mon, 25 Aug 2025 09:03:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756137783; cv=fail;
        d=google.com; s=arc-20240605;
        b=Ox0JMfk3+7v5rYwKpxRipAhbmGAsXi8erCrJn45abMqcb96Dv0yhdvnvDV5uCIqRWJ
         Bj9lP0JAfKVnzC0WE9l03vvMn96XIUgdpt0WRMOuUEjmosP7IKwDKEThenlIqONczr0h
         xAgOeGZu0x0HKr6dmdOfAPSHvkX6LJYGKqBRtZZ7pJonLoACKVzNqdFOo7UZaak0+S4K
         eh1Kwc+k4+wrfCB7E/UEWuErGPMFz0+sEOIrUUzMNj+FuazZky/owJM6TkOS76uJkJ/q
         d/FZg8aTXpmHQpHktC79w1MDu7I1eMOKwO5UFMm8b/yWr7sknMs7jS/1RZPR9ihsqDYO
         CEUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=yvL6M5j4mPen5RcKYMs+Q3Sw0xLty6CObCpwStUhw50=;
        fh=mVq8/LUtmTkC35c+6yj53NxafDpIEbaC5M/bwYx/asI=;
        b=ZftmQlb91AUaaMs7HC1KhFsoJVxMPhuz5YEYGM6MT2jMjiohP4N5klhdeQXzICft3P
         qmyuQjmBFIFm+a2YguHkCN8cIUMW3A/QAfyRTiGDkQq0ANMToA+o46i4BNnqsFUdlmIr
         hySpmTOovBYSA+LiwmBkpqRJm6d7gW0XzsOcIiX7FP1B7919qSD3JsCbfLcN/jlxtCqq
         3cqKJaj7aUm9eZUCqupF61rqr5u44CXF0OJc2FzV/lRhS1el7lGqX2hVAgNjQz0d6NYT
         3Igje9XXalOyozYYSy/8hEpVGwRUTfVP6zsvkjqFepYZX7eSQtyeeWpSde8q0GCTi85Z
         k9mQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="onb/x+8o";
       dkim=neutral (body hash did not verify) header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pQ6ucEVO;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e26e811si338323a34.1.2025.08.25.09.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Aug 2025 09:03:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57PFfv3p012690;
	Mon, 25 Aug 2025 16:02:41 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4e22n84-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 25 Aug 2025 16:02:41 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57PFBSan005028;
	Mon, 25 Aug 2025 16:02:40 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10on2067.outbound.protection.outlook.com [40.107.92.67])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48qj88ne74-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 25 Aug 2025 16:02:40 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BXpPP23nfrz50NxWbGGPPbSjVAIXbyaR+S4pRCd9gUMJ7asbFYZ6BUlqZNk0fF7Zj3IjcxS5F9xyrjswUCXvykakaC8LU2hnvoweNsIb6ox9ewk1J2l3dCs0P9gQCjia1BipBnRNutbZLBEDRJqM5vnTxKJl0PBho/9cXNMCeKrm7GOdjykdZJybF5kRSG6x5SSDkkP3HH0eUNBhfTEz5e4aSW8IJW8aQlKdEWLbET0G685bslbQlX5IZRj8X3dJFdzCx5eOy3TMD9b7bDjF4AlZmhb6RA8+C139BuoNVHZgA9WhL4RdlvT0Da13uM01LyN9s/Mhx+APbTLy4sf5zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5rM7zJBqy7JZfT5ozsR6vQZpIBSGhID3PDQQw+swsaw=;
 b=RJxD77NtcPDXBAlLjqSGAa8/cCq9D6tqKG8HKXiKYaAcI/kijIwxIXiE6VGzhcZGFZMrLLhompYeHhpyLbj8EAp6NrdqNqGGkeucZX/Pg5XkAxBTg8yqw7jMV2StiqI+KCFrf5Cm4BhLLNKlVR9L5rh0IvrisanCXRM2cIFNgdb1bQCZZKLwSJBtpcdQmWhHqPqjgCMIluywraEGRWaQS9cKZBwgMUpuzrZTWE2C5f2WB1pCC+v+k+ODP80wHFRV53dQAmQpGg20EOJwnek/b4VRQs4sTbxcZ92rWV76WhVD5H4STM+MSxdAKtK8spFCLQ0SyCM7d1d1/XnbOm2RBg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB4607.namprd10.prod.outlook.com (2603:10b6:a03:2dc::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.21; Mon, 25 Aug
 2025 16:02:37 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9052.019; Mon, 25 Aug 2025
 16:02:36 +0000
Date: Tue, 26 Aug 2025 01:02:18 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
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
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <aKyJCsXC5dL3Olpq@hyeyoo>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
 <26796993-5a17-487e-a32e-d9f7577216c3@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <26796993-5a17-487e-a32e-d9f7577216c3@csgroup.eu>
X-ClientProxiedBy: SEWP216CA0016.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b6::10) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB4607:EE_
X-MS-Office365-Filtering-Correlation-Id: 9a9c0387-7e1c-4aa0-c4a8-08dde3f0ceaa
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?4slTHjk9SvjaYPkCsX5PB90gVyOaa33YVza7tQlUKi6i2tnLDHgauaNbUU?=
 =?iso-8859-1?Q?cS2bMrt+gO16IYP5r9IqkV7M4KYiF2escMItoMldUrVEKFU2EEnTpVgwrk?=
 =?iso-8859-1?Q?tUpZ9WH9v2OGp471gM33aLEHWsKyYZAvhfb6zDPbLvnqgRX5tU0Zj6MLKK?=
 =?iso-8859-1?Q?I59ROElCNt4pIbZSWq+z5af8Y/PvFxwFU9EDHqzTK3qtZP5jMxTAHw+lLo?=
 =?iso-8859-1?Q?HYtoZYPIVdYlLrcM7ysktbz65FgKk11JqmLDqLXVnu8ljnZLMfQ0T3gRMt?=
 =?iso-8859-1?Q?mVqOVYJyKxAN2dsWZCC6iCy3jhYZ6zXEc5dhuygNoDVEnrdHpFh1oh9Mt9?=
 =?iso-8859-1?Q?hvrc0FNZrkIeTzNberwXEjS7YTfXDtHroLHetGPecOE3FZd5dO+CmNDG7Y?=
 =?iso-8859-1?Q?PmKVaXHxDSDQX33Vgq65SJz3DV6vUJpewni0ZJG7Zy235qvaEu+W+RTc1Y?=
 =?iso-8859-1?Q?1NI39HoyNEe150xrzmm7WBXwhpKEqyt3Jh1fidLwNrpy3LmCSmxrGfyP8W?=
 =?iso-8859-1?Q?8U9VLZTnAm3NG5lzFGLe6KqcDqpGuwiRFMNyroYa7MACIuJ81Yckkq00bm?=
 =?iso-8859-1?Q?vwKELpgewk3oqYORKKO74RTt4xJAQSjPqGwBIiV7Gz/3eeRrv/cfCaW4om?=
 =?iso-8859-1?Q?R10J1zGajGnQw771Uh3GaJxxC1sLoxNK9FdDCt5J0Y+/smBn8eH7GWSNRj?=
 =?iso-8859-1?Q?eU3r5JtfEjqev0/hYYYVGIeJIobxeANoaMFxVvD8Rxl4plCWSZ3GeY/xF/?=
 =?iso-8859-1?Q?LNGhD5jvdnhdyV3YieNB1mBu3lFce85vR2OqKeCvd5bgcwBvBEWU3uojzO?=
 =?iso-8859-1?Q?ZnrGaGXLKcF6be6Ed6xaacN2JEro2ag2p4wp3kjxAlBnOjr75cgu5IXcGO?=
 =?iso-8859-1?Q?u95tEgN7i2LxgP43AghYxnbqfc8FUH0wXqK07crhUQYRB5n5OVf6hC2stu?=
 =?iso-8859-1?Q?60tuPoSUomEwpOBNkO5J1iAJFwMNshli2fwngDeEb39RyXPC7idAObofFh?=
 =?iso-8859-1?Q?7GgeumpHRi8G9t5X0cCocEf6XLgxH6bfBGTGUkVFMUjsPDZOLSWZkntJMs?=
 =?iso-8859-1?Q?komXwc+ggGEdjy6V/2xefobarIpeT+N1QyARsKCh0j4F0c/cMIprnYqDX6?=
 =?iso-8859-1?Q?zcNRqttURz9YiXi6CExmSp/YJU6C2kn4AQ6YWRiyfXdeH0d9wGkS/ei3F2?=
 =?iso-8859-1?Q?IEn+m+xwf/CGIbENXk9N4uiL2rtpbtyC5whiK+D/lRJc/jMNu2OA7cNjCB?=
 =?iso-8859-1?Q?T1frHBOrok4NFOU8yapmkjqRwWFNZ2RZdwjh1YGRr7srwIDcXAyIDuoLho?=
 =?iso-8859-1?Q?NWWlKz4SG0ZNi9qIdBxDymSXv3jXXFOCl91o7ViM9Z2OMLlz15QmEhpf1i?=
 =?iso-8859-1?Q?/WsswW0DRRARWErjXbu1VAkDiZusQOnnSAqfuaitYaGWxXAAeiw/ewCPS/?=
 =?iso-8859-1?Q?cG9M+S8fKrhCyd80beWtJrEusZPJRkS6ABFMbQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?hsymHHMkUVI/W6MC/qQj3I4JXW7qEH5IXncZSkZaB2E+LKPGG4Tf7RohNH?=
 =?iso-8859-1?Q?8hF22qjxQp5P6tsVWssvuXqhE30O45DsBu3SRA7n2ewlnz2Gb0Yec6ZPUJ?=
 =?iso-8859-1?Q?f9rrA3riLpGF8u0PGR+E5HfTav0ZHZvG9chbo8YP1GkuZFZumNfRotFOXn?=
 =?iso-8859-1?Q?JgPFCrXBRQNPL5cZikKuVurvUwBwIAxDQaxq9EMBzJuG5xj9vEK+80XV8Q?=
 =?iso-8859-1?Q?GjjDzemSIJ4TBNoOtcrH7GHAoQ6xTj/3n8qm3DHbU7te76cRSJHUtutMSV?=
 =?iso-8859-1?Q?UvTqLXZe6pAnhoH5sFPGZnFU0HuDuEwPvRced9U0urW1T+lE7bryS6SdJk?=
 =?iso-8859-1?Q?lzQX2U0njUkve6V7Zlj1YdBY+KiPMSKVPlJPEeDsY5i5X19E5uA7/fhQ8S?=
 =?iso-8859-1?Q?5O2USadx+4+8+ZWvoW1MX7dhb4ySaE/Fc2v+MOZwJm59+IDUhlQ8felaNi?=
 =?iso-8859-1?Q?a4lDSBfp8g7KzCJnvJBMbuISs5FBFsFOQbvgwwImWvNi9vu4Y0Bm6qx6LH?=
 =?iso-8859-1?Q?Imd2zDsM22+AxkgvedfpncHrTDDtDGKrhQRIICsp3uWnPWgTERY+3qM53p?=
 =?iso-8859-1?Q?AMZMLRAQwgZHyjOAvTEIfrwUIPvRKfSLpa6qC2QMZcHHByYFg0wVZq9gGU?=
 =?iso-8859-1?Q?3oZSLF76uP/GSMQGDf24EtDdMuorNQ+4Vi6FVKVe0xTNzuv2IO5O7xUmVC?=
 =?iso-8859-1?Q?unqrzydsrJTrxmNodcHFFoNWgNkwtHvbkm7mk8Zl+CYgWMum7rLh5xMett?=
 =?iso-8859-1?Q?psD0dujPHO6GXs3mk7BoPtv80X9C/evYeV1MaDbfIZ2n+cQI01WZYBKyhO?=
 =?iso-8859-1?Q?1sjHBQ4FH6XRJr6VZ3uFWjjqy4+0RvTfmw/ukCQbYLByiapYsCUnHJg6u2?=
 =?iso-8859-1?Q?2O6lehCCH96WBeTy+ygoNBVeLeszXfvP1/ro6dhgDIYrSd1qZIb9nux80y?=
 =?iso-8859-1?Q?6qDGY+d2cdbi7yVE/vFae/gAmTYdXy85lN2mQyDxw5EWYYaqXto6MxMn29?=
 =?iso-8859-1?Q?i8RorrKPFYXww/tB6CmJpKFcq8NfgVP5B09jK4P5GUlJ8S0+ouBSyXMXUN?=
 =?iso-8859-1?Q?vYnuZGGDEH1JWqBfdmuH+8/wUaChIB2H+sQR7l630oT9vbptSZ3Rj18kqB?=
 =?iso-8859-1?Q?iOxlhcvik2obtCCZr0F8leZk6KJHryjoTTBh6255sUs4kGRw0Vo+lIBJBb?=
 =?iso-8859-1?Q?1gQM6zJTikEFAhmP69jPOOsYyajwlYi0rSQ2eo1jsVzia1w7mankryCYPQ?=
 =?iso-8859-1?Q?+qjVuPEOBNJxkzG7RsVWycKlpb8XGoenOkfeJ5NV0eInptmPffS1cL/Sog?=
 =?iso-8859-1?Q?HPovCWMyoI5E2jff3bY9PKBPWTIDKRg/vZKIiglgCtNwsKBbazC17vkdF2?=
 =?iso-8859-1?Q?cUI1Y6bSnmZG1NCAOiPZ0v9Vm+LQGCIq4OuAZrF5lPd4w+5pQnVBJyHBdF?=
 =?iso-8859-1?Q?O0t+JB7d4U+cbvok6CF3XOPjL+fyiMUW9A67TmT5n90+2nrqt2qkHNJLVy?=
 =?iso-8859-1?Q?fZqPiQFG1lrWzG/OvmylsS1AmMh8ju3uzF54cV1Tbgp8haAOz67FA95rWq?=
 =?iso-8859-1?Q?uIIiNfxhUJykOkWYIAHCo87LxWwfNpjx/bjURLp3AhaNQRbNJF0AVYtoOU?=
 =?iso-8859-1?Q?/P++0vkCY0WHAS1BoNx5Dre3Ju5dyfqe6T?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: U3EdGh1NRN084yHAmx4KjuEnU2ZInNqv2kxqKfgzEngB6YOk57dbARIkzc8hrfaf5N3g5QTmDurOP3TYXNu2+68i8ESeaxHdlRy/sIGXGcsd+xggaoBfv8cbANeIZBiCqIIx6ivLcEwSFpz9wK9+sAC7l3Opxd+eh4IAxy/gqUOsIDd4/ROKD5gvOymW3XNJFDAq/nvsxb/pEx42s/Iz8cYEF/L1c6ugodquUsb66oEJGniTqADPz9iheVKpGmKnUIyuByPmzrfsv/vx04wqoRAY3oIhPrO8ubex7AIshMlG2AC6ilA/dgWThajBzB6C8aSMRDFQmTlQBiGdXCrd2CmJq20bODtEaV6wkaqtNwWGfcPmFued2YnN/g+GAqDbxUlF6lkhCkuXq7jE0zyfO1R6H+Q25T44PgpT58n4g64ZutG+8nB8DU/OrAkmNPsSDVwXTwlh4/88SfaUFVEZqHxNmfY81UzduEaQTmMqWz6B8tAsdygglbu4PgBN1QWpbNyuzxfBKOi1Ut1OTubKk9Qu0+z9RRCVfpuvAwHhAaGaLGospeWBsu/3jnv2NSUTRw+2n9lq3aybs5CCfW6GJeWbcA6PFiI8HmdGVcBuWfg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9a9c0387-7e1c-4aa0-c4a8-08dde3f0ceaa
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Aug 2025 16:02:35.9474
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: psWQrwHhFkvmYmZ6scIsUGr+sxALQ4w2Vg2pD3amgYPEyDtoX+q2zFS6+/svAHIoUcRckvCILgTvh1htPJpIAA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4607
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-25_07,2025-08-20_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0 spamscore=0
 phishscore=0 bulkscore=0 mlxscore=0 mlxlogscore=999 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508250144
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNyBTYWx0ZWRfX6pR0U+2O/SOQ
 mQY9tgh14sjBKCqmzGUzXLOXW0p0LJFK45dbtAMTFHZvmq8NFl0bwXEvX3bu4TeELXCazYvu5Qj
 epVbf/5t3WAbYvjANQrGKx8qSjb1LzRbeu7P+j9tYu1BPqA3eGlYaAKKTGmQ7dhxHuA/XpBj1Hj
 iqhECk6QQfpMUqxcckUXtf4tGBDdi4MPXDfhsV5aujEQjZznekyUThWxgd162HbIZXjZUu35aJe
 MmDy8jxPt9qCy5IUthhDVpEgf4KGCR4ADe0WHK2/atJ4SpCKUJ1xOraYOn1g0cUUzp4yBkoylrH
 2sOyvyR2PGCDPzaJQpbnGU6Tl+xf71G1i69d8wFuSpj1O1VGeem23g1Egb9YBsQ9I952dbFmeTG
 BwH+eg/xq89shu55EkDXNm/NbpZuhg==
X-Proofpoint-ORIG-GUID: dm-hYueEENp1RGfnegDKRoGjRSpae4Nu
X-Proofpoint-GUID: dm-hYueEENp1RGfnegDKRoGjRSpae4Nu
X-Authority-Analysis: v=2.4 cv=IauHWXqa c=1 sm=1 tr=0 ts=68ac8921 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=8nJEP1OIZ-IA:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=cI9SBmEsuJOggFUlpjAA:9
 a=3ZKOabzyN94A:10 a=wPNLvfGTeEIA:10 cc=ntf awl=host:12069
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="onb/x+8o";
       dkim=neutral (body hash did not verify) header.i=@oracle.onmicrosoft.com
 header.s=selector2-oracle-onmicrosoft-com header.b=pQ6ucEVO;       arc=fail
 (body hash mismatch);       spf=pass (google.com: domain of
 harry.yoo@oracle.com designates 205.220.177.32 as permitted sender)
 smtp.mailfrom=harry.yoo@oracle.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=oracle.com
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

On Mon, Aug 25, 2025 at 01:27:20PM +0200, Christophe Leroy wrote:
>=20
>=20
> Le 11/08/2025 =C3=A0 07:34, Harry Yoo a =C3=A9crit=C2=A0:
> > Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> > populating PGD and P4D entries for the kernel address space.
> > These helpers ensure proper synchronization of page tables when
> > updating the kernel portion of top-level page tables.
> >=20
> > Until now, the kernel has relied on each architecture to handle
> > synchronization of top-level page tables in an ad-hoc manner.
> > For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> > direct mapping and vmemmap mapping changes").
> >=20
> > However, this approach has proven fragile for following reasons:
> >=20
> >    1) It is easy to forget to perform the necessary page table
> >       synchronization when introducing new changes.
> >       For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve me=
mory
> >       savings for compound devmaps") overlooked the need to synchronize
> >       page tables for the vmemmap area.
> >=20
> >    2) It is also easy to overlook that the vmemmap and direct mapping a=
reas
> >       must not be accessed before explicit page table synchronization.
> >       For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulate=
d
> >       sub-pmd ranges")) caused crashes by accessing the vmemmap area
> >       before calling sync_global_pgds().
> >=20
> > To address this, as suggested by Dave Hansen, introduce _kernel() varia=
nts
> > of the page table population helpers, which invoke architecture-specifi=
c
> > hooks to properly synchronize page tables. These are introduced in a ne=
w
> > header file, include/linux/pgalloc.h, so they can be called from common=
 code.
> >=20
> > They reuse existing infrastructure for vmalloc and ioremap.
> > Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MAS=
K,
> > and the actual synchronization is performed by arch_sync_kernel_mapping=
s().
> >=20
> > This change currently targets only x86_64, so only PGD and P4D level
> > helpers are introduced. In theory, PUD and PMD level helpers can be add=
ed
> > later if needed by other architectures.
>=20
> AFAIK pmd_populate_kernel() already exist on all architectures, and I'm n=
ot
> sure it does what you expect. Or am I missing something ?

It does not do what I expect.

Yes, if someone is going to introduce a PMD level helper, existing
pmd_populate_kernel() should be renamed or removed.

To be honest I'm not really sure why we need both pmd_populate() and
pmd_populate_kernel(). It is introduced by historical commit
3a0b82c08a0e8668 ("adds simple support for atomically-mapped PTEs.
On highmem systems this enables the allocation of the pagetables in
highmem.") [1], but as there's no explanation or comment so I can only
speculate.

Key differences I recognize is 1) the type of the last parameter is
pgtable_t (which can be either struct page * or pte_t * depending on
architecture) in pmd_populate() and pte_t * in pmd_populate_kernel(),
and 2) some architectures treat user and kernel page tables differently.

Regarding 1), I think a reasonable experience is that pmd_populate()
should take struct page * in some architectures because
with CONFIG_HIGHPTE=3Dy pte_t * might not be accessible, but kernel
page tables are not allocated from highmem even with CONFIG_HIGHPTE=3Dy
so pmd_populate_kernel() can take pte_t *, and that can save a few
instructions.

And some architectures (that does not support HIGHPTE?) define pgtable_t
as pte_t * to support sub-page page tables (Commit 2f569afd9ced
("CONFIG_HIGHPTE vs. sub-page page tables.")).

Maybe things to clean up in the future:

1) Once CONFIG_HIGHPTE is completely dropped (is that ever going to
   happen?), pte_t * can be used instead of struct page *.=20

2) Convert users of pmd_populate_kernel() to use pmd_populate().
   But some architectures treat user and kernel page tables differently
   and that will be handled in pmd_populate()  (depending on
   (mm =3D=3D &init_mm))

[1] https://web.git.kernel.org/pub/scm/linux/kernel/git/tglx/history.git/co=
mmit/?id=3D3a0b82c08a0e86683783c30d7fec9d1b06c2fe20

--=20
Cheers,
Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
KyJCsXC5dL3Olpq%40hyeyoo.
