Return-Path: <kasan-dev+bncBC37BC7E2QERBDEC43CAMGQE722UXAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FD64B1FEA0
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 07:35:10 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b423aba05fesf3834563a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 22:35:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754890508; cv=pass;
        d=google.com; s=arc-20240605;
        b=FzYnGQqQxUmInitVLjUVAl9eAYJ3m0/fmbHoZNk4CUCy9yAID+LTZwutFZhSoE771e
         lTKbJYhVZYezJhN/hccyGUsrns7qWCkWkcnGiRdnahvz6IkSq7fRAEWBFSb/C88nV821
         3p2ZSULlBg6znCV1GlN1SRKZRCMqtoWbgd/569ODkTe4vYh1qdzFAU3vkl09bDgIpYjq
         eXhIXPvd5Fax/KdvXhavozIAv1sYFCzgzSZ/BYkRvkcainXKCk/GMUKmgYy7Itp5hULl
         QVZ4SDSKt110IjmUcOL52sTFT2bLdJMWERRi0lVx0h3rwMKTHaDD8Musy5x1Ezk0jcz2
         /hNw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=oXeegmqQhOfRR7O6tH/S+9jiH9ecFTmLGecSn2KMGHA=;
        fh=btVNuAcXqGNAg+RP7RspTa7P8HIIHtjvsCaDawiT5OU=;
        b=atqQh447+4MXuPIcrWZ21Z0xGIIqb57XfNsp/4AsDLSSb2xI6zYeMl7sthUlm9xBvz
         MYWdclu+7hYqnOcZcaVGcq1mkCNFDAALeHy7rnStfAeAoWN2lc/UGmovR9bxkSe4X8WZ
         f9g45Vy7szcCOaEci/bEwfoutRdm52cZMfx9ak4rL/O8dSsC4Ji8tI92kOeD2amWLhyi
         lCWUYONceL+8roEUiZpH/oZoInjxWk0jrL8mUlwjWKCSfG+6Be+D//J5yGgBYVpjmPLS
         872/pPmwfL13SI6o5LUWNkEuCnOBM6c3VXugf6IYVfNC2haP3HmnJ/3YQFpHySfXCGdh
         z65w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="jbwuUCq/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=l36mehxI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754890508; x=1755495308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oXeegmqQhOfRR7O6tH/S+9jiH9ecFTmLGecSn2KMGHA=;
        b=AMejalpAN4/ZP6C30F4RGcwY9AjwAA1Z0ZmghG1R5lp4BvqSTFEctXjnX5q48zwMkr
         vnKSO1h7BULszEtHrDUEEYYGs9ggxx6Isl1eQjZ/nwAyPlfTbzfT9CZtd0runzPPCC+J
         DWN3GGfbOp2Zf7WytYcoSYFliqy3JpnMenls390i1GFsWvmhq44oC0XKkcZXGc6+Jz6p
         1CtEqiWUabXBEpugVsj38p/Cqk34eae1ndiGh4Q389/9yPTuL1s57V+VaDIcTTah6LQt
         sFootvxA5Zc4KPUNrREVD1NmTwzKiJXcEsrzn+LHtdRn8FPgSTSR+iVr1ZeUpBNVHyru
         MbeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754890508; x=1755495308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oXeegmqQhOfRR7O6tH/S+9jiH9ecFTmLGecSn2KMGHA=;
        b=M8SwNSAen/hdr2X6EgQPw4Rql9vIECvW6T4n30hweWfZbS9OABtxMqzLTVwL4yM8Pb
         LbCFkq+VGwIgZKKjetqu2DIfiUbISVj+xTHkub5ee+vYOg5n/7uWpRiJuVJextx8vYDQ
         rTURNqMZA4WQ6c9WALHMQ9dWE+XySslbodX6m+IE+MG18XQYKwrEKFexqPBGTH2k+iXG
         6j+fvKZ5fsrT8w7xSEF/wVnf5ldMNNsazs7OH5CLeftxvd6K3LOGl1fjSjuVHXgPp03g
         exg0mz9D6nNOS6evlgto/I8jIpqNwruPbH/NmseOddxs+ugLIAIebnIzxi96nw/akba3
         XF/Q==
X-Forwarded-Encrypted: i=3; AJvYcCXFmo0AhIIhbzCMB5F/V9+wA/keOwbRga7gjgUTVjnZJrOGnl7gNVLEtsTXiNIWRHAT9qhG6Q==@lfdr.de
X-Gm-Message-State: AOJu0YzN1mSmMsOoi+BkC4ZHZJAhsUqdzLkztbtSantefr/R73q+LGPK
	tuY4Kzdp/GX2XamqpPlXIFucvzTObhokVcv5WsRQ4SE8hEK+7wka7gPV
X-Google-Smtp-Source: AGHT+IH/7QK47kLB7/P0CVlBwLJ+Q+evL8B9ZLLKqDSKYOEmnf7/z15vwePSOZlSN6TWeOCLFw4r5Q==
X-Received: by 2002:a05:6a20:72a3:b0:240:27c:fcc6 with SMTP id adf61e73a8af0-240551ff790mr16973535637.42.1754890508430;
        Sun, 10 Aug 2025 22:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvF/VZg2QHalv+4qD5dIRcQKFs89/qy3mvPNNOQ/LqaQ==
Received: by 2002:a17:90a:642:b0:31e:f73d:d1a4 with SMTP id
 98e67ed59e1d1-32175090b84ls3334146a91.1.-pod-prod-09-us; Sun, 10 Aug 2025
 22:35:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXUOFt2i8SmLHk8pHPWfPYoJkJHfd4KnWGzprVw1/tImK9mukJb+ZOfotckkjq7ZBLfztnWZgJ/NpM=@googlegroups.com
X-Received: by 2002:a17:90b:5202:b0:31f:6529:3a3a with SMTP id 98e67ed59e1d1-32183e54b03mr13173123a91.31.1754890506899;
        Sun, 10 Aug 2025 22:35:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754890506; cv=pass;
        d=google.com; s=arc-20240605;
        b=XStNEx/0NLlcU0nLsnAHcySLrbJIjQnH330CBd17P7vdOmlac7QCJz5P+DZIEDBqso
         MZNLchhWFTSgM4e3AaCuvtP9x4aiguLqAlnBkDuozJZJvevbrF8OXNIsxpRa9glItV2s
         9BqlgSI0dKCHe1NQdTw1a2jORSw+n04eLVRru5CytKHsk4yk29JaCDf+RGkmPly9kjoe
         9gfj7CLnaU2MKKwLxTLxVZhU3hu+6hny4jT5vrwu9md7BY8/v3OttavZpRyEhs87ymsk
         PuIuTSTr070xDRrqVUJn2P47tcqZILIirLnmn6B2YdTK7XylKBMh1Xe2Qs9Q2i5F5Xet
         vA+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=cd7d2fATAtKPVHiWiIGcfZERp8wP6l9dWyjkQ5McyXM=;
        fh=0EBLV78IJD5ujWZWPN7XNm2AWFwQBW73xN987KBCOfI=;
        b=ScfLe9mZnQLMgmNoEUOeb1SK0K03CuPpzdJHNohf0aHURiEo9w6gEG4ckfUXms1JVj
         XAfDrdMvWHQwJRws8yPiO1fhD9lXG8KCEhDC+pzRBpJ8RHVaeAjrUGDDrQeGUl6onSEm
         PDPIDYj9eVq3bzYonqcw5r72H+pjba2907Hxd90Mo7mgnWg5DW1I+NZ0pFK6Xk0mHhZU
         yAMV0e6Uc5HsMLUSvAmrcIPzz+xx2LTy5OYK3y20O972XSrvCFUh7ttw8cyMoGRWhddO
         C1UXmbdta59sUhPyRBd8zbogVY4WrxK9QCRYvZTEWoBGxOkcs/wwVLjZApQ1/8cvZMVE
         1sRQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="jbwuUCq/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=l36mehxI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3206334aa31si1389635a91.0.2025.08.10.22.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 10 Aug 2025 22:35:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B3NwxH018062;
	Mon, 11 Aug 2025 05:34:49 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dvrfssd4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:48 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B45M0l017411;
	Mon, 11 Aug 2025 05:34:46 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2066.outbound.protection.outlook.com [40.107.223.66])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs86m4t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:46 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XM49Z5fZLRCrPk041zRZmC5V21HvLGVrLBM53Bm0ILgoZK3vZu9VbP0nNZc7A36HWJJHmtn+LHK0/oLhfj8l/E0B5rQN0GCFMZwOnExcEYDqG/kw8TpeG16DimG9nZ3q9rIDPEHQH1n2TJ2DqQk0YRr9fxicrf7XIyZXyEdRXGnfn4YYnZv6aBwW1FL7U8HEbsCqKkNfKj3wFxCtMe32liLZ5JDYiGvkaTEZR2IHoShfeVrW2gJzoFUxDhJ9n54h/k2h4+FYbEjk9j23i4S5cgqVrmXJjmnlu56ALkrPO9Yu7ZyrEszJBresLOO9juQ3ccWvxc/aNcmDJw1hQv558Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cd7d2fATAtKPVHiWiIGcfZERp8wP6l9dWyjkQ5McyXM=;
 b=eZ+I9Ht/yNOKbDrFefqNTjenRn1JspGMKAGLrRODKPviA+7pmKeh04ytlcO3wg1/7DwF+Oubnk8bhi/0UpLxe3DbFCHisUAN+9s/BenAxHRsnlryy5GF7kHtp9ibQxwKrKoWpaW+0nbX8uRLlGWURZmvq6fPzRJPxCnSHdEUYh5tzTYDagPQF4NgmOqbHZ78oI6sVHE8LQQOBQFYx7Db7NYg1WiMzQpbYN3/j/CMpWW6UgY+gTRZAvjDVPywIcuuGsmhbH+AE69adaPwGBkcAdRqoxr8XmXoorcAjQSTSnKT/2ClXEAzJPgzQOftRBKa5IUM5waUfHaCwqXe9R6+zg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DS4PPFA0AD88203.namprd10.prod.outlook.com (2603:10b6:f:fc00::d3a) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 05:34:43 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 05:34:43 +0000
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
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org
Subject: [PATCH V4 mm-hotfixes 0/3] mm, x86: fix crash due to missing page table sync and make it harder to miss
Date: Mon, 11 Aug 2025 14:34:17 +0900
Message-ID: <20250811053420.10721-1-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SL2PR01CA0015.apcprd01.prod.exchangelabs.com
 (2603:1096:100:41::27) To DS0PR10MB7341.namprd10.prod.outlook.com
 (2603:10b6:8:f8::22)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DS4PPFA0AD88203:EE_
X-MS-Office365-Filtering-Correlation-Id: 55e53a85-a91d-4581-a498-08ddd898c5d8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|921020;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?POoDF+Sy3NnAX3rSAwrzJuHIstOXFb5Y+VPQSf//FFqxqy7eKoatrDYBx78y?=
 =?us-ascii?Q?PKDd7hgaBs942VFMCVFS86vLR3EnJYjMFuzTYtJr6Yq0Dda9UTPjc37eHVcl?=
 =?us-ascii?Q?MQ0xGLMzU8VnPDddp3HUybNCK7lSuVsy1j36adLR3qPHeK/kcxRw2XXEyhnO?=
 =?us-ascii?Q?y+Ciueo0thQNN8uG+63VH5hiMVatQv8lQj8fzUqkJvETrDpr3WVauRvu7xjC?=
 =?us-ascii?Q?pwQzsfa2rs3s+mLH7UsXsRd2tCh6l7wNqU0yjsH8pMzZRu25Vw5TOG5so/Rd?=
 =?us-ascii?Q?iIcxPVFGVvB0BVj2boSrmFfbf6hQwVOTTI9v/o5OUDPABVB6sy7t3tC3KLpU?=
 =?us-ascii?Q?af5PnkF1dEBfw7/nK+ywI/Xz9jW8Ja5RshWLQ+FueCu/ZTzS7i4/1s2UZn18?=
 =?us-ascii?Q?NGSO0L+PrbcC0TRL/eI6AM/sPxIzlYTVpT9q7X9hRFst06zzqtSZOJ3R2y7N?=
 =?us-ascii?Q?6kQip50sZWKAa4PJevJQogNJTyl/GxY8SICuAL7vQXj5vjmXS+nvL11Je78E?=
 =?us-ascii?Q?KNCYUoi+ABH5uYbokblnkvlZVYLnbAi0WiZI90b1UsRdahP37/ADSZyIw1wl?=
 =?us-ascii?Q?HeR9DyF47f+DP3Te7nXq5ZbQN8cq6LiZH0cKWQ/72QWFBDzlIIyQXtzuBHff?=
 =?us-ascii?Q?qotiL5VJ5gY9naFx+SZCw4JldJ/BnNp/sG9BtFq5e2w74jxIT9al2fcsSYZ/?=
 =?us-ascii?Q?8bRMAwV6CVp9+/RcTn2v3rR5QKWqqBID9s+g3GWwZad+LErq/bXdB+pKsykK?=
 =?us-ascii?Q?5ThfexC+Pvu9o3+s6J2xC9zOg8i3cGVfFXfDtL+inEnELyTKaRUXk7Ulq67H?=
 =?us-ascii?Q?Ly/0NFTeh+h+b32ZRVTfEdLmLI43aNBrk0C3dmB4sY8EGNDVrwxt+CshUhqo?=
 =?us-ascii?Q?iFvDj0xVmy/i3C0XYgPW24Al69LaAdVBOZu7Bi5/BhofRhFCETXt6NvJHM1f?=
 =?us-ascii?Q?t5ABAMAywFqE8lYLOQvCWqbtJpI0PdXhrxT0iTvfEpq/Zz7NsALjTMNK85+R?=
 =?us-ascii?Q?jQWv9tUG263MPwCDA2m0nrsqvG/ddVZ+vgiobGfqx8hcMv1Fjm2AMaUQC0kk?=
 =?us-ascii?Q?XoZI7m9vbKhjUafbVpI8SfgY4toafUeKQUBTczTWlrJz48vrc6TKTdAovkam?=
 =?us-ascii?Q?PE/HMnHdkrgrHKRkCtN4HFDfJ3i4ZQlTn4AARa6CLWHQEOKRKvCgj3AynT/P?=
 =?us-ascii?Q?hveOL9J4v9yHnRkE50AhBfvDqH0MT8zj/WsUeiddR13OStrFC61UQB+VXzjT?=
 =?us-ascii?Q?HOsZRaSoChr1gTPnZO/oZ9+Zgr72uIK8bl2KpZbtOFrPBBODc5Y+wpW0trY5?=
 =?us-ascii?Q?CS6TZgqxpmOfmCRP3LaL8eDjhSXW9L33mpQbLvHbJl5BPIZ1zVMtR2nF2htI?=
 =?us-ascii?Q?VKCQwhEEXSG8e/vTGdTMCYKcvhFwXIRy+dxjrNJ6igBsY23hhmt2hTN+7f8+?=
 =?us-ascii?Q?5tbLfeFQSYYD5vbzcpYdXEjL904zcisXN6AvMuYpezDDAD+areneHTNYHzhM?=
 =?us-ascii?Q?pHm4nf2i7eRZ+Vw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(921020);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Kdi3KFYQ344H5NKVvKaiMYmEbs9ZyW+AK3HZSrnCJmpMinbx4xEK0EFaXlEI?=
 =?us-ascii?Q?irlPX5m0J5POdFu1Mz17/VsWEm1zSb1g2GOkqcfYODzHgExI4svgMxMWGNzz?=
 =?us-ascii?Q?x0nNW1Gi2VoP9fpBQrBKeWar5atdEgvuPuhg8k0mzGxg+l64zGOXRo8LMi82?=
 =?us-ascii?Q?XHtqBEpev1uPUCbY636rGB/Q26xzkvk0Pck15zyGrCQu8iJsOu553NnwYYjO?=
 =?us-ascii?Q?Afaw/68j+mTff1Jsma8mZ8l4y6eMKrfEw3dgyg8fxR6Cy2yM3+2FsMMIxjBl?=
 =?us-ascii?Q?m1vrDzDBqnvMO7mqqpUZvaq+ypm8chybaxS00v+iozfGWyJ+i8Ztf6KfoboG?=
 =?us-ascii?Q?vAlKaculU7KmM+cBSHpV9C7jkyDGe46TGvIVzRORykTptv7f2ejP8UPqEFxx?=
 =?us-ascii?Q?pxx0+aZ26LiddJwxbDABXePvhy5+fQIAM51kjXfeamXVTEV+JFGr1qs988UV?=
 =?us-ascii?Q?VLPLSCSUdtPPPLcEBE9M3QQg1+u2Hi0IZLKaLJ5iQV6FoBgUoxfuGLY0MRk+?=
 =?us-ascii?Q?6efPO+Mdlei3fjn53WDNkTVX31QUWOrN9qpeZHnt+ilVAydcLKzVKXgmjuP0?=
 =?us-ascii?Q?E8t+M9QVIuiVdq9PVR+38Ukdoe4r5v/luA6vpyG0gH/QkvFjhOxLlDJrSIz1?=
 =?us-ascii?Q?Ea6pennLOiRBc7XzP0p5XpK9Wp1RpYiOsg/MQrvb6tBi7TgbClHPAG1jqpim?=
 =?us-ascii?Q?ixRsxaKI5SISd1AXttTNtDF569cupB4jYzn8HT35t2dmnEw2qdvLxnHbJnla?=
 =?us-ascii?Q?i4oHmMkFyoPWr6OR+lsGNwILu9WTJH+IaH22wwsRNjcAO08OOWgXwtGWa+pL?=
 =?us-ascii?Q?UuWA/elfTcwtvIaWje/2JSUpR1oEI8d9KTL15srIqPg4Q6leF7JG2gB6Y73j?=
 =?us-ascii?Q?67kQgrs/hCGe1xJaQuGwp6qqOldqWnNDjYWQ6ehcMleioZgOUadoXR2C2yuQ?=
 =?us-ascii?Q?Z43HKAei/dAUs1Zwd4G6CKJfvw6/sQ2ru5MaA6KFja2FCgTAgPnvAjbOTFlA?=
 =?us-ascii?Q?OqDjvywZfPGEczl9R/zs5j7v1VVnvZEybGLHxbcVTOkzBzt9jsaPXNxV7vvg?=
 =?us-ascii?Q?mJJEo4rbv7+Q0phWLVS7aDO4vB6dPzw+MkNwXQmPLmjCy3yC2/sKu7zX/8A2?=
 =?us-ascii?Q?6Qq1PxJ+7PdaP+UOk9qxVT7mxAifS06DeElaVMAEGBwQzxKy17SD3Mw7B59h?=
 =?us-ascii?Q?ENA71LIhT2WooRFhxqDOq+f6leKAiufghda1cfpwNIhlDTI7PIbCkBR7ubR9?=
 =?us-ascii?Q?pWoUeswn+PF+rqaYXtGr3WQhaIDLUB+/aJ7V57QaY7+AgpABwsrxQ6L6qqcr?=
 =?us-ascii?Q?pKkwzD78aRpSI6AoZ6NqVdLiS+XBmtMJWdVYeRvLo8AY/4UVy9HneEUf1J6U?=
 =?us-ascii?Q?I4sOKXif/+4t2ZPubBNvHaWvWD4CXJAL3kSzaiy+09dnNBIvbwdPRZjE+7dd?=
 =?us-ascii?Q?JBvtax13Aw0KHA9hh1N710UmM5pD2nuNI1YUnqYUOAswnN+ANKtsDD+Dyai8?=
 =?us-ascii?Q?WtNzbPbvqhRe55qzj0Jk5Is2vkZs1q6AezDimunZjtb8qqCdnmUwTYONsiVv?=
 =?us-ascii?Q?dVGYBgmvkAqel2dmwH2E5KLDGlBQPMRzq0fY2aHI?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: QqaUSScuFefG2SvRQvrO9tHFU3nGQNuov1SV6OSLmoTiDU1RWzScEgQllK5kdVx9GvTFxA1nrxUk0ymPAHfKJODzq3xjG6TkuezAleCWFy6pEICGnYkI/1/yUOP6OFAx60bDNt0zXeYCQP8R52n6dmnCcMfarhjpamqnuchC5VzWTzhl+AXgxbF6f+A5ea3X31H+g4yW1xS/Eh5dRIoLVboj+CU8htSytE/N0f3E5zBJYmyS5VmK+iuzezIuAY/MyYSe+HdzsNDGD+PSv/us/0KA1kbyqijVJ+jhNe7r8Uux9brTsPH0r6EfpMERmiLLyK1ZzQFiED0SqFK08cTWn0O0vBCOcWB3DNzDUKu8IzII8NM2439UoQDXKrjn4cwvFzesMcUbWASPI9MmTfMMYN3tD6ntOMnoyBGwOxmb/THIjU3BVJQ+Cb4rU8PCAdGNU3Ahd/R848uvyo5Xr58LrNS5YENioiDN/qY6BvUOwpOiWKvJQu5MQ8POedh/YEhQW2fUoApswzXLbw8k+5N7I7NsxAR2bHASePcJpQx3OWszCSEdbvcMx+OpT4/eIWfuOaym8p18QqcVvOQF8NJTOHcQ06OuobODkjho+xe889I=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 55e53a85-a91d-4581-a498-08ddd898c5d8
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7341.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 05:34:43.0055
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EEq/Sb2g/Z0honzw8crwWl8k2hrMkt7qtnfgAkUdICOSWNPPg4CIVUhdQwVJTMAAmrav6Wh3Yn9Rctgz9OeSyg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPFA0AD88203
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-10_06,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 phishscore=0 suspectscore=0 mlxlogscore=999 adultscore=0 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508110035
X-Authority-Analysis: v=2.4 cv=B/S50PtM c=1 sm=1 tr=0 ts=689980f8 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=Ut5Sv_cQT0ioXsQQ:21 a=xqWC_Br6kY4A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=OjyniKcQLBVGvT9PaUkA:9
X-Proofpoint-ORIG-GUID: -VVhk1-f8Wl6mVR_V8LBsVe8txOCGoq5
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDAzNSBTYWx0ZWRfX8ygFcBYwB5Sq
 Xlmnln/+WVlo4mHCv/mlcAQMptN3RaS2V5C7R+laIN7NLKPPBpN2wWkbE7XuwzZFsbbLE+Arss8
 /XTdZFrcRUncrAbWBrsvoq/3WHPOqh4Q0YUKYkC5+HDqEzUCstyvuJbW1JuDADju+pY6iXhKxps
 RcwVrocEyyqhxhwVZg2K136WgV0Q+pIKZJsPgtiQeLHOq/D32A4nzfWl3kRfmVjysPqXZ6T8zhS
 BNS6OYPsJ8y2G0EPsZXcl7ASGeqZldRfPwmvLW4//kBiQxYP+eC6yiU6M0xYCbjiVQ0aQ1thFgf
 N6Wroe0dj4K+L4UbalMEXRwHuzXOjr1OW6g97Mw2CvU5f+DzW2Hnp0yEMuPmXOUZWubGDo1kubF
 pGZmi0k0J+wJ0gCKGAWg20/uuCbyUBa3hcWoROCIjQQse9Fz3U2N8IamnrAQ645duxWncYio
X-Proofpoint-GUID: -VVhk1-f8Wl6mVR_V8LBsVe8txOCGoq5
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="jbwuUCq/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=l36mehxI;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

v3: https://lore.kernel.org/linux-mm/aIQnvFTkQGieHfEh@hyeyoo/

To x86 folks:
It's not clear whether this should go through the MM tree or the x86
tree as it changes both. We could send it to the MM tree with Acks
from the x86 folks, or we could send it through the x86 tree instead.
What do you think?

To MM maintainers:
I'll add include/linux/pgalloc.h to "MEMORY MANAGEMENT - CORE"
in the follow-up series, if there's no objection.

v3 -> v4:
- Updated the subject line to emphasize that this is a bug fix rather
  than just an improvement. (was: a more robust approach to sync
  top level kernel page tables)
- Added include/linux/pgalloc.h and moved p*d_populate_kernel()
  to the file (fixed sparc64 build error).
- Added Fixes: tags to patch 1 and 2 to clarify which -stable versions
  they should be backported to (Andrew).
- Dropped patch 4 and 5 because they don't fix bugs but are
  improvements. They are planned as follow-ups (Andrew).
- Rebased onto the latest mm-hotfixes-unstable (f1f0068165a4), but also
  applies to the latest mm-unstable (c2144e09b922)

This patch series includes only minimal changes necessary for
backporting the fix to -stable. Planned follow-up patches:
- treewide: include linux/pgalloc.h instead of asm/pgalloc.h
  in common code
- MAINTAINERS: add include/linux/pgalloc.h to MM CORE
- x86/mm/64: convert p*d_populate{,_init} to _kernel variants
- x86/mm/64: drop unnecessary calls to sync_global_pgds() and
  fold it into its sole user

# The problem: It is easy to miss/overlook page table synchronization

Hi all,

During our internal testing, we started observing intermittent boot
failures when the machine uses 4-level paging and has a large amount
of persistent memory:

  BUG: unable to handle page fault for address: ffffe70000000034
  #PF: supervisor write access in kernel mode
  #PF: error_code(0x0002) - not-present page
  PGD 0 P4D 0 
  Oops: 0002 [#1] SMP NOPTI
  RIP: 0010:__init_single_page+0x9/0x6d
  Call Trace:
   <TASK>
   __init_zone_device_page+0x17/0x5d
   memmap_init_zone_device+0x154/0x1bb
   pagemap_range+0x2e0/0x40f
   memremap_pages+0x10b/0x2f0
   devm_memremap_pages+0x1e/0x60
   dev_dax_probe+0xce/0x2ec [device_dax]
   dax_bus_probe+0x6d/0xc9
   [... snip ...]
   </TASK>

It turns out that the kernel panics while initializing vmemmap
(struct page array) when the vmemmap region spans two PGD entries,
because the new PGD entry is only installed in init_mm.pgd,
but not in the page tables of other tasks.

And looking at __populate_section_memmap():
  if (vmemmap_can_optimize(altmap, pgmap))                                
          // does not sync top level page tables
          r = vmemmap_populate_compound_pages(pfn, start, end, nid, pgmap);
  else                                                                    
          // sync top level page tables in x86
          r = vmemmap_populate(start, end, nid, altmap);

In the normal path, vmemmap_populate() in arch/x86/mm/init_64.c
synchronizes the top level page table (See commit 9b861528a801
("x86-64, mem: Update all PGDs for direct mapping and vmemmap mapping
changes")) so that all tasks in the system can see the new vmemmap area.

However, when vmemmap_can_optimize() returns true, the optimized path
skips synchronization of top-level page tables. This is because
vmemmap_populate_compound_pages() is implemented in core MM code, which
does not handle synchronization of the top-level page tables. Instead,
the core MM has historically relied on each architecture to perform this
synchronization manually.

We're not the first party to encounter a crash caused by not-sync'd
top level page tables: earlier this year, Gwan-gyeong Mun attempted to
address the issue [1] [2] after hitting a kernel panic when x86 code
accessed the vmemmap area before the corresponding top-level entries
were synced. At that time, the issue was believed to be triggered
only when struct page was enlarged for debugging purposes, and the patch
did not get further updates.

It turns out that current approach of relying on each arch to handle
the page table sync manually is fragile because 1) it's easy to forget
to sync the top level page table, and 2) it's also easy to overlook that
the kernel should not access the vmemmap and direct mapping areas before
the sync.

# The solution: Make page table sync more code robust and harder to miss

To address this, Dave Hansen suggested [3] [4] introducing
{pgd,p4d}_populate_kernel() for updating kernel portion
of the page tables and allow each architecture to explicitly perform
synchronization when installing top-level entries. With this approach,
we no longer need to worry about missing the sync step, reducing the risk
of future regressions.

The new interface reuses existing ARCH_PAGE_TABLE_SYNC_MASK,
PGTBL_P*D_MODIFIED and arch_sync_kernel_mappings() facility used by
vmalloc and ioremap to synchronize page tables.

pgd_populate_kernel() looks like this:
static inline void pgd_populate_kernel(unsigned long addr, pgd_t *pgd,
                                       p4d_t *p4d)
{
        pgd_populate(&init_mm, pgd, p4d);
        if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)
                arch_sync_kernel_mappings(addr, addr);
}

It is worth noting that vmalloc() and apply_to_range() carefully
synchronizes page tables by calling p*d_alloc_track() and
arch_sync_kernel_mappings(), and thus they are not affected by
this patch series.

This patch series was hugely inspired by Dave Hansen's suggestion and
hence added Suggested-by: Dave Hansen.

Cc stable because lack of this series opens the door to intermittent
boot failures.

[1] https://lore.kernel.org/linux-mm/20250220064105.808339-1-gwan-gyeong.mun@intel.com
[2] https://lore.kernel.org/linux-mm/20250311114420.240341-1-gwan-gyeong.mun@intel.com
[3] https://lore.kernel.org/linux-mm/d1da214c-53d3-45ac-a8b6-51821c5416e4@intel.com
[4] https://lore.kernel.org/linux-mm/4d800744-7b88-41aa-9979-b245e8bf794b@intel.com 

Harry Yoo (3):
  mm: move page table sync declarations to linux/pgtable.h
  mm: introduce and use {pgd,p4d}_populate_kernel()
  x86/mm/64: define ARCH_PAGE_TABLE_SYNC_MASK and
    arch_sync_kernel_mappings()

 arch/x86/include/asm/pgtable_64_types.h |  3 +++
 arch/x86/mm/init_64.c                   |  5 +++++
 include/linux/pgalloc.h                 | 24 ++++++++++++++++++++++++
 include/linux/pgtable.h                 | 16 ++++++++++++++++
 include/linux/vmalloc.h                 | 16 ----------------
 mm/kasan/init.c                         | 12 ++++++------
 mm/percpu.c                             |  6 +++---
 mm/sparse-vmemmap.c                     |  6 +++---
 8 files changed, 60 insertions(+), 28 deletions(-)
 create mode 100644 include/linux/pgalloc.h

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811053420.10721-1-harry.yoo%40oracle.com.
