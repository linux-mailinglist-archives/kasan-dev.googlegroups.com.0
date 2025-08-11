Return-Path: <kasan-dev+bncBC37BC7E2QERBEMC43CAMGQES3POKAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id B6EF6B1FEA2
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 07:35:14 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4af117ffc70sf105299651cf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 22:35:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754890513; cv=pass;
        d=google.com; s=arc-20240605;
        b=B5E2PvsZi2wASprLLA6+1EHhGOFar/IlrpoAvgxLHd/WvmIhZbv8mPMkObzhEobhSM
         44qnny8WNsHu8x2768tETzOZZ8B0qHoYiPtWJh6/HCdspH/4/AzrAVEHaBG0u95mKnQ1
         0DPsM5aqPQFf5RS00M4fKfGXTMwzhC09iYMH1ck4qRDRtAxZdhtG+I2xfNqubbPZXE8V
         HnNdTJxWvTcpZLn0t9CY4d5AYIaiMFFJoDIycj2UXtHlU4IQo73BLWTyCYnXIqbnANh1
         d21XtbsUM2Yk0m7qn3VfwHjL7EZDPb3YboqJ6EsD+As8TqeJQIKAZlImH8UbolPUX6ry
         nFtA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eMqX7BQCq9XYQYZx/x7ihnbhYOmA/fP0O53I4Idx+hs=;
        fh=mikLlzxbZ67dUcwwlO9vtlCiXpxLu8hVwyapGRAt0H0=;
        b=FpUy74HCIOK3kW8/KGhMYJzp7/59A3iC87u5hEntaMC6anNoDLeUbcugOXgjL+C8u5
         bPNyh2C3SMIlCvYv7qn5sUBa5Y7TzoQ6ajbsL2C0ix94aXN/AQQKv++ACmU2oI973hX3
         zwYbpPxJ6sQ8DddYQRH6WQbc8nHaXwLJAXzBG/TfYii91vzt5fou0fZLwcOBbgsEXV/j
         7u3jlSFDRrXxWLnG2jt1pauSfrfU/leQj/r5dOoYrO01j0ea3wCPMiBJJ/bDAvPXFK22
         YXrYYYM2IzYt69Q/NH1X7B0Qy1x/yE+OD66r1Aq5JJ23PLj9DPkvU+f63nUvljp5oma1
         nvgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=D873SfkC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tvcCnxIL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754890513; x=1755495313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eMqX7BQCq9XYQYZx/x7ihnbhYOmA/fP0O53I4Idx+hs=;
        b=mgerv/gUMQxMhPWnHFSs3yG+i7N0pnoRi8BKtS+aUwNbbuoCDvbQKKJ1LtVD50A+xR
         nzCXMkNxTdwzh1SLZQ5Hc331KwqISHd6ZRs4vBhJo2F1rP4DyGa7rqjzfSHOkFAw6bI/
         OpDuNWnd5P1iMDxBYydMMVCPghbKnVPtLCTnhW4y+Dnhy8Fz+FG8ZinlRs0aVgsnbGUy
         G1RddH+PvNHAjRPVzBX89lQUdHVbJoGLZKS7B2jZYUGrGK/3xt4qMat93f4gV8zrW7Ck
         dMOwOBhyWPEs66ZEzwUJYE7FKDmI/cehS7NQCS5zNz3ucrg2iRrFfA5TPCpbVtqbbf9L
         b/9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754890513; x=1755495313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eMqX7BQCq9XYQYZx/x7ihnbhYOmA/fP0O53I4Idx+hs=;
        b=LwCyuojhA9sPNz3VWgAicXuiQgArOLJkIHf60IrVbcOzOcjiwXMP4qrl0CYY0DrNlj
         F3XYaKPCe/7uX/Wg0FZwL/4PVudSU5R2iIXbrzV6zKIJEAnScw12k9QQtLkl7ujsPXho
         JMWlfOm2Bryvc+b9xFI6tzSqBp0hE9FcjJAQgjBiUjrYgoartYIyKAUlAAF5xQZhVniD
         qh4u/EtVTqAi2SVaXi/AcOpSXJnJ1eq3SmNP2CDzNPdMKSak4bapufo3LWubcDHfnygw
         NND1yzrFNwPKLHkduKDz/Bfr8Emz5JGXSkf2dsG9X/DdY3swKKRGE4vvy3zj509Ar49q
         BV2g==
X-Forwarded-Encrypted: i=3; AJvYcCUnskTMZHCD5b/T9l+tDTZ27lCxoAehnGkU+HbU7mJ7ujduZUWInGmevy0U5YbKYZkk6l7PqA==@lfdr.de
X-Gm-Message-State: AOJu0YyPOcA23qOi7G/MfqQngjZftyX1sm2Z5G8QbiFQgwOP6+UjjUl8
	Lwzi6HqzBnndg1zMsx2lmaxBvBEmTq+S2z4qfmO94TWsQj5/N8pEu9YY
X-Google-Smtp-Source: AGHT+IEV6JcF0YhC6nV7HQkqZDmyWX6ij+TlstMVuXNcB2SNKuxonyYAqELflstaTuVpVUlSNFI81g==
X-Received: by 2002:ac8:7f88:0:b0:4b0:6a0c:4dd8 with SMTP id d75a77b69052e-4b0dbb0e93fmr28212561cf.48.1754890513421;
        Sun, 10 Aug 2025 22:35:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxtjUQHVTzb2aXt6ok7S5Jg1ICwvgQhT/J7JUiDMiBGA==
Received: by 2002:a05:622a:612:b0:4b0:64ac:9be9 with SMTP id
 d75a77b69052e-4b0a0704160ls65079291cf.2.-pod-prod-03-us; Sun, 10 Aug 2025
 22:35:12 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXjqEsDDpyrh8J+T3hI9lhyqvou8cYN5YEnRENdwxaMABNNRoRsrFS7kNqQXG6JULxksQX5r/xUSFw=@googlegroups.com
X-Received: by 2002:a05:622a:2cb:b0:4ae:ff58:dfd9 with SMTP id d75a77b69052e-4b0aed44680mr186084291cf.17.1754890512383;
        Sun, 10 Aug 2025 22:35:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754890512; cv=pass;
        d=google.com; s=arc-20240605;
        b=cXI3uFuy8iIY0elsBgorpakslRxlHBlexRBAK2rfWnJnGv2mILpt6Iyw+65Ma6SOF+
         ZMJL/RWKiZHqjiv+3ARr0ULZ3p9H5+tG+Zqg+l48eF8Wugmm9Fe2LeMogDcET5Kmatei
         IX9hvPAJlEeXEnL/td9ci3E76VOEjp0FtxTSSq2oYUSt7+mB8CLO9eTrQT+8AedJ0Xkb
         sxXwvOjII/ixPaJ2Li2nsugcAZ33MQ+58WFYdRNvbiuruxUXhtXRDyrNoF0QXV7FVTmU
         AfpmAD6cqWQYBVvZxecScmh68BbLCR5YFUmZELun01z/kUYyO4AIML2LHm1mcufMKrkW
         /onw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=kWHS0dKB9It/DEjUi46qnTads1jv9Dpy8htZPhxS6dY=;
        fh=ibbQO9U02cHhAxvOEUY9mWPo6+5ye4eWHkymspSm9Ck=;
        b=Y4wB5cYxfIa/IsoUYWDYXSSTO6SfI9LR7VXnxVqeVaCjF8KGs3/09s5l6p4Gh25A+s
         22LGf5jXkrQ505Y+IpjS/v8ct2Xd+0YUcZKlUykZrIGJPh84qM0azoFRyKUV9EnvRO2o
         Z8Tvn9GQwdFhvvMaPotz0nUSs4+6bMowdGJLgL/62avNVaOtRzqwWOZWhTNtGq44+1oG
         BihARmkLk49P3GSd1ypWL/0h02BtKAeO/YEY3jAH2Sq+A0z3IMFv5gsHDrPTHWnIlOlm
         sGsqQvCTepiFmJDBqQucwQ3V0KGe2KuTZtxaRMuNDxGUMAKI6WXPx//iu1ZFziytwuwz
         SiYw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=D873SfkC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=tvcCnxIL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e851a16976si3171485a.6.2025.08.10.22.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 10 Aug 2025 22:35:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B3NWiv020066;
	Mon, 11 Aug 2025 05:34:52 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dx7dhq13-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B58DQe033600;
	Mon, 11 Aug 2025 05:34:51 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2080.outbound.protection.outlook.com [40.107.223.80])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs86ud3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:51 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=R2xCZw6tE9x8PbBSxfJcCRWnA10XWnsC269J+HHNU0A/ID1QxSsMrDX9i+kxpC3BiYiLbFGCq5ksCwHfjJX69vwbYQ7ZbGrsJK435FAj4KqM+ptvGNO0/Y2Kno9PpAhdcngqxXydlKr8ejmvCy6NKuzy7CcCSOyqOb5Qbvm7Dqyo9KUieTOMxg76DuTnumGiuPCIKXh1g/qDC/LfMDWGXTNLoJn72xQZk/RvkFqiY28WoMVwcGfnpmNelRmq9G3OiTu4eFEWLMyY1follSK2Nq0SvZd8PpejeFvNf1cMnrgqz2mBU/DNggTYpC6TkQWMN6Nazeu7lkq5y1GcKyyJiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kWHS0dKB9It/DEjUi46qnTads1jv9Dpy8htZPhxS6dY=;
 b=Uffijha45AzmJ37tRPPdjPUSDy1jALdaXOjQgGcm70ARtnbLr+B9AVTYQKHD4dpbBpoeXyDDCnwDD0ERNimixnSQQS1fupSMOJOKQ6xKNtjyol8w3IURRfoSCitZZ2TsD3wJtmLsqEJAF3vp5j4Yn2s623sb1wlXQkoN4X0ydaKPKmNpiHKUia0vw66eJV+e7ch5a4nk7q8j75Wee1OZwQ9WGTPOx+MgE0mXFDzzo3wsfXt9H1bRb3OCHd21p7f5y9T2jVVHDAi0UB/hSAcOGt9o0Sk5wbH7r6nf463KZZg+AxuOWOlUQWI/M/bxBRlQfxrFDWvwfdAv9qVkjZoQOQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DS4PPFA0AD88203.namprd10.prod.outlook.com (2603:10b6:f:fc00::d3a) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 05:34:48 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 05:34:47 +0000
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>,
        Harry Yoo <harry.yoo@oracle.com>, Thomas Huth <thuth@redhat.com>,
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
Subject: [PATCH V4 mm-hotfixes 1/3] mm: move page table sync declarations to linux/pgtable.h
Date: Mon, 11 Aug 2025 14:34:18 +0900
Message-ID: <20250811053420.10721-2-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250811053420.10721-1-harry.yoo@oracle.com>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SL2P216CA0157.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:35::20) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DS4PPFA0AD88203:EE_
X-MS-Office365-Filtering-Correlation-Id: bbefe1bf-bbf4-4306-bf61-08ddd898c8a1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|921020;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?xFAU1VVxIZJ4zqhw6+l4YQYCgjLRylmg2T+5RZMGIS9BBvKZvnjINuUP2zAE?=
 =?us-ascii?Q?NC0NcW/6plgO6nChSgMjXyGZ9QivQuHyL/aqUaIbn8p9w9vYlJtsnuBgpU5r?=
 =?us-ascii?Q?wPILOdQgOyF1hDnFf9hIzZlg1ci+DQXp9LvA2o2b3kZ4UiRzs/N/3l0a//rw?=
 =?us-ascii?Q?HHMJmc0LUJmaNDeQYBnsGLuclO+qxRVr73SJ2aZy4WtpO8RFUQwCIntMCSaH?=
 =?us-ascii?Q?B6Ty/yV2TYipFLq0MGAztE+8/8DRQjZdj+mEPvVsXbpsp4b432feU+tA6zSN?=
 =?us-ascii?Q?MAuxfpzCeQEuorLqzaO2L7MD57lItVILPJfL9CfYgdrv4McfhsJGFQe9oHBw?=
 =?us-ascii?Q?6pHfHIBVLK1+xLZCGLfjQaU2rFmPpEyHsZxkypGWMxLj4aJDRkOsifIsGnHR?=
 =?us-ascii?Q?UyySjfY14riGrD484MFu89S011eWb631LV1o9NReNLSclYbaTtZQFES3Zugy?=
 =?us-ascii?Q?c5MrqVtWD5ZLrWSzBQ7BNyGxgAuNUhaE8EG1++9s7UPn3XnQHHoqdHIIKCZ1?=
 =?us-ascii?Q?v4GY0e8Tvehig6Ye6ODc15j2b5Zye+oDKsvfFRU3qO71GqGmfodWVUo1kGXr?=
 =?us-ascii?Q?hx4LGuIkrjeOBa/t6AkU4hN0Oy3I1TSgB9EceuY2tc4/xWJvGrSfzTnwQYj8?=
 =?us-ascii?Q?g7n/D4SRv8I5cCfG1yUciwnqabYyGnyOZCCRrHfZwCXABIemm3FTkiAeD5xm?=
 =?us-ascii?Q?B001p16Clut6++el0IeumLRtrFDtHWWndlJ+LssJ4hB4iXd/vCwaCpLK28Ek?=
 =?us-ascii?Q?/KyJED3aLbm6F9cuDmsQ0aaSgpC/Sjtj8YbvzjTSO8c1eqKvK/IS71KAARs2?=
 =?us-ascii?Q?AAY5fYsANv3H15xpVsBsHPI+dG/ZEQa6yuETToZL+W48srxYkj7Su0Vtlc7y?=
 =?us-ascii?Q?EY2wrRj9WHtcUtHytgJWRb33H2W1JFFayfeLXm0sc+GapBonk3vIiFoKEOUF?=
 =?us-ascii?Q?3gtRKkyrK7OVWa0Y0zk8QeCSyJloqfp4EtuiThwh+uECBPzB1QNiPYO7KmY4?=
 =?us-ascii?Q?x7cBt95S/WH038hY/ZqjLJlGH1uRLesgH9bzXjmfkZ008B+46akbUsxyN6DX?=
 =?us-ascii?Q?KHTOZH5l762eSLzn8r4flTZBwEArbLn3sw+L6vG3AxIjiEx8tPw9wrr+dVul?=
 =?us-ascii?Q?m6J237okQYRWZEImN8jyxgXSvTKzwE5Wwx2M9Ha+6sob+EKn46x0BNA1g4pw?=
 =?us-ascii?Q?Txo+fW1dQgOUmdKIHsa8ZcDza7fqIumvXP/T8fuDV5YpdfUrfDH8Wb3TaGKs?=
 =?us-ascii?Q?8vbnNx5u4iuelvF27mKugrmLLXAllMLd4uu6PE7DhRmM9wwtKav4Kcog9ifF?=
 =?us-ascii?Q?pkxa8jNZ0WCLykLVPbXO3JccmtrKUAjtiVEGAj82UYfhlOdSWvpgAPJ2i3Bs?=
 =?us-ascii?Q?pROYCcdG5HMTnKwAZKjX43OMeNSohbM4HlA2GFTIOAfAms1x8oC09dk72J2f?=
 =?us-ascii?Q?8BcLzOZX+1n6TCaCyJjG1lQwR9Wu3CZU+05YlcHZTfzlaN8sRsg2SA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(921020);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?fX/ernJ8IgUWBA5Ei5GE2M3hRENuzXMfAz25ed9oiCh6tosdCpz2YREuRCFb?=
 =?us-ascii?Q?/hH/yrOVzRKL8plvl+EvvJ3/28K6qOWxR0s5YrdKFy98rRoTEq4g3aOqsIDk?=
 =?us-ascii?Q?OYmlUT2Dx1+QK/n9YMVsIhY5Ff+ImMWeiYoIYKVeR08dZpK2Oq8ACDkBWJuz?=
 =?us-ascii?Q?YxEDhyf0M5qfcUMvBXKBmIei1tUK7KZC1BJbHVwwUKhJMi5QC4jhVv4natQ1?=
 =?us-ascii?Q?/HV8+hS09cJAzy/KSpmHuVxj19uEGBTk9+9wIjCQ5ChYlkLyqtfizJwl9kQQ?=
 =?us-ascii?Q?LE8I2VuOvCa0CV4uwvNrAolMMW9UgIGap1SnaQSL1g+OIDuGNpLwD59yy4C8?=
 =?us-ascii?Q?sOCJKoA1WxkI5APgNpGd67lC6mZxaS3W1sLdZvvM2synwBOZ96/4Wq2tY2uY?=
 =?us-ascii?Q?766yXiozyRwYjGM7VucUwdlmv8M20RQsmeh8dcIqrmAG6UGjsRyi6pfiFA+m?=
 =?us-ascii?Q?+vVcdjDZ9uzruoe7WU6XHZiuFCGd7Egxv2a7XHHP2FrML5xGmF2dabD0YPa2?=
 =?us-ascii?Q?4gHaHO3syHctrSyhbrb9LrkcE0LjFtNeE71qfmEzuceSC6ew26fsfT41fpy6?=
 =?us-ascii?Q?7dP7GRO/RX8fn+oxAmJvfmQgVS/jfucTLuA0tb7tUHZoHlw7eB+1VmGyem7G?=
 =?us-ascii?Q?uJy/4khCG1tp3BdtWwSW94r+Z/Jkd09AN1AbI5JdfdrRpOynL52a2v+92/lo?=
 =?us-ascii?Q?zDepYB+EiiESe2kLANvokL+CMKtgm/VZlKhNBKmnsjVNDvAf3fV2+nhVhKdl?=
 =?us-ascii?Q?acYQWtiEm9oaVdo32t7VZ9sNfaDf2AxCGchGjKJjHNAF28TEZSUw6QBJ0Owb?=
 =?us-ascii?Q?Ti5hPc3wc1pxQyYJ2BR4qs0/ZlP9RXchq3BCItCwMFL2zrDivAUO2TUtQ0kj?=
 =?us-ascii?Q?jG+wPRnvx2wT3nNCg34iYAXpPoNCm19sh2x8m8kJK07kzn7XH0V8k03pJLN4?=
 =?us-ascii?Q?VTH2TKA9/NzBtpbnWs9Egi6RwB3waimt6+b33oBfnRdcbLGzXzaYuRqUW4pg?=
 =?us-ascii?Q?R+sPxUWkKWzheVPZ/kxQGPXgeRRjTd/0vje9FK+WJult2XO+iVVSEKzU0y5K?=
 =?us-ascii?Q?CRxR9ASdB7i1k+xsK7dJUreqVaogR79R7wpaPJq5vAP/G4/HA5jtbBX3CMea?=
 =?us-ascii?Q?KJwdlplaJT5CCLJfUAxV9GBUoiHqdKo6s328eCUJKUn9J27K30jef/PoN8fA?=
 =?us-ascii?Q?d23e2MVQ+ACieAxkJDM1GDIcSR+Kgg/eldxlf6gMwBdcdJMpDm4yHcSpLy1x?=
 =?us-ascii?Q?b286xqmZwAQG/y8hhHb6/HV0KLfyX8UPL+2cuYH7qp0Z4K2PH9fAMRjDG2Pc?=
 =?us-ascii?Q?Fq3wNDN2G/X5Yu9Og89G333z7aOuu5RpCP8KjWoNZanYExbHFnSmbKc8LPOH?=
 =?us-ascii?Q?jIsCcXAjq+HoX8OrJydRwI0FzO2JH/n+h7/p5DPHE7BdO8FSBaiQGqqUaSQK?=
 =?us-ascii?Q?AFf7zZ2jkwJkmlJPxmWBdkD9qgrHHybX2sB1F4SiUpuEbFDHmB8PXTQgUbmC?=
 =?us-ascii?Q?ZLwuRf8VKFs+FbXm61tPdTMq9ZELeOeBJEse1zeC4hPJaBDPSHK1f31cqUJp?=
 =?us-ascii?Q?uv8l/ok5bu4AD+x98kEtceTOQBlYDMbNOhoCXxwM?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: i1T9ZHgtevV7rRBOwU4wV6u64BGfNki6PRq3QvPJDXk16wihVQ2FybmajKVbBX2RO0AR2S3IBcA1EWHk9wcMmTtij432mvui3eTSqU9Q/h5WcKHjLxxy+pnsxNpvU12czlkK/wr+TZ9NDjgzLkivz98l0xEgVC+P2Nza2JwpvjRYSzCcDxWOqWzLLh/38jvfGWzYBRlUqeXPo3fFJTk2oYrbins2MzQLkrLnvMj5fVH2ZT9TCWsicqMV46zh4lduwXuQrgdvlqnYBk1Gl9L6oIN6gNcP9GqAWv7REUhmJkd1dFwNRJlhg+SdhMP5NDChIs8sYfaGz3fyz8DEeTG3DjvlowEqtxs8xgb55LbftMfLDT+qUiLjhnL2xV86zj/w1OqkXzGcJgha5bditlpgihS0seSYFRFa6xyP0Y06DtnTcHQMV15Q0ujw5sOdhLUidOYbnLSCC2yjqSpx8fPbv7MWE8rkwia3e2hxcBRFVBGA7gOxWNga9qHt20JA1uh0CZhVkfVXYyXC+6/Cj5+XyZEJ7RP184TuNKbH9nOSp1MXSqk+lnM0ms6ZWh66kD//fjTNeqbymsLZXlyFvrqdKWIVDo7xEaZ7em0sdv7G0bg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bbefe1bf-bbf4-4306-bf61-08ddd898c8a1
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 05:34:47.3717
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 6arZVkT1W9OxLtbtWgMooRENzCxFgHF3amBZJqPbg6lWf9JDArfoK7waYgk8qOQBMxd0GX1Nnw/H4BTmVxe22g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPFA0AD88203
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-10_06,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0
 malwarescore=0 spamscore=0 bulkscore=0 mlxlogscore=999 mlxscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508110035
X-Proofpoint-ORIG-GUID: U4jfSUqr6XNw-GHllVwWJllLhFthF1tU
X-Authority-Analysis: v=2.4 cv=WecMa1hX c=1 sm=1 tr=0 ts=689980fb cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=2OwXVqhp2XgA:10
 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8 a=uplis4tbhEJsONv_2NwA:9
X-Proofpoint-GUID: U4jfSUqr6XNw-GHllVwWJllLhFthF1tU
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDAzNCBTYWx0ZWRfXwR0qggR0C0et
 lYpHi88wZqeg0TAPAo/xV2CJNcFMf4Pix/EeffHKsuSNh3tSYnP6soAlbSN8miZLxyT1p41C/+H
 8XNKfrvLHBrg6KeFMwBg9CVmeioxV1CDtQ23+18q1p3dYWMWnT6/SM02ntR0cJKRmKl3nl2mcdV
 UJf7DxPYpIQZjAHuIlyeo2PnTfzxH55ZU5H2bFR4L+0erBAdvj+D46m7Q1Dlr0GGA2JYUg7uJ6R
 UnLRGbRkS8f7Cpt6Na+JozShh5hBlgr+1Q1EJe3NpzvKNtWs866pYfU+oMB31PJrepndMgyEvhf
 HqDile/9n0qladI767Q4aekj8/VNg8erUJ3dV8B1A5o/iO7YdC+aPAccw3owvIymtGnDc1/r3ZD
 ov4SjySIb/nBKDytoW5/nNh5ioOYpT3to4z/vJvccZ8EflQbD4Sde/SlwqEl+j1BH503LDw4
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=D873SfkC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=tvcCnxIL;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
linux/pgtable.h so that they can be used outside of vmalloc and ioremap.

Cc: <stable@vger.kernel.org>
Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
---
 include/linux/pgtable.h | 16 ++++++++++++++++
 include/linux/vmalloc.h | 16 ----------------
 2 files changed, 16 insertions(+), 16 deletions(-)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 4c035637eeb7..ba699df6ef69 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
 }
 #endif
 
+/*
+ * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
+ * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
+ * needs to be called.
+ */
+#ifndef ARCH_PAGE_TABLE_SYNC_MASK
+#define ARCH_PAGE_TABLE_SYNC_MASK 0
+#endif
+
+/*
+ * There is no default implementation for arch_sync_kernel_mappings(). It is
+ * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
+ * is 0.
+ */
+void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
+
 #endif /* CONFIG_MMU */
 
 /*
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index fdc9aeb74a44..2759dac6be44 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -219,22 +219,6 @@ extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
 int vmap_pages_range(unsigned long addr, unsigned long end, pgprot_t prot,
 		     struct page **pages, unsigned int page_shift);
 
-/*
- * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
- * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
- * needs to be called.
- */
-#ifndef ARCH_PAGE_TABLE_SYNC_MASK
-#define ARCH_PAGE_TABLE_SYNC_MASK 0
-#endif
-
-/*
- * There is no default implementation for arch_sync_kernel_mappings(). It is
- * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
- * is 0.
- */
-void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
-
 /*
  *	Lowlevel-APIs (not for driver use!)
  */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811053420.10721-2-harry.yoo%40oracle.com.
