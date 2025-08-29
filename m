Return-Path: <kasan-dev+bncBD6LBUWO5UMBBFVVY3CQMGQE3PRL6NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A98B3BAF6
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:18:32 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-74555fbe3f4sf998820a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:18:32 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756469911; cv=pass;
        d=google.com; s=arc-20240605;
        b=h7aQYgP9ToGQzuDJpZWKTu3Y+IRyrIf2TjD5zhoqpNla6maGzWcPNkicvqI6hl95YE
         1L3nspVCoRrm7hbZNEUl7Iz5TC8m3Q8L9JEsIWiH3Y6ZgAR/R0ZAQZT0qlYwfCWMFS7s
         6BhcpmRqhq7iLn2um1tn+FtbtdD3SrnTmZsK7BEhP0uadDk8LMfxZmxPclC/+ViOWsdV
         EpyrK01KNhY/cV/v7BghbeKmV0na65aTyK5MU7vJqEsJQMrnkTmMWT5qssvA+//4UH31
         zmW5LZzX/ZUo/lADXMQIW2HrksTm6vxbsISrnPQbnLoeqGPib1bsBVNvxbCYq4QAuT9t
         u8/g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=epiwFTg5YivsYM8Fl3TvyH/GNyG+Mmsjl1AB0lgw8KQ=;
        fh=ff5fjK0f/8zctNaRLIOvVkGNQNxy/l0LwNOq/itCc/U=;
        b=Uag79dMjXPk+n+dmuBSC8fW6bkvehlACF9oUi7IUTYbU38poydnwSdPCQbnguEKWrU
         FmIPXUSTe4nsTcHLrEgkuRsiSdJWzDojpv1Qb0sefD+DsbC7wCuwBbkU4/iFWSN4Mmu1
         g6ObCMRQ8IMWbNg62ustqWbtTcklSqpB1mSwCdh9SNYTg94qxWf/d7pFqeF7WfJNwDff
         Nh4dMGxAycASI5JXBq1J6sDfL11al0+kr8nL7wSD2ZoEkyRgYktF47Gxk+n999pR189P
         wx+Z02ueYJVVh4iBo9q1iEeOO3IflVN+UxzdytjLKDIKvmcvkQVdp2nqqyrrRWKTPiFs
         S4gQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kGM+MNYW;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VeKnTGYK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756469911; x=1757074711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=epiwFTg5YivsYM8Fl3TvyH/GNyG+Mmsjl1AB0lgw8KQ=;
        b=VmEc23ad8eBf/AoQqF2A+L97SoleiZlZ8rX4kVPbP7Qmtr8W66AhbABoq56vM2YxT+
         KQOUW3N8xkzyUkyyR1P3StRMU/GzZ7Fwv1NjTib9GXIoae1jjuzOmuIn3U4ZQ9Mz0NMD
         +PNGms9l2DDHjl+J8VAu7sP6sGG/okyAq7M59jdsxw9GVgn2pnpUHvLlDpd6ZIV3xUad
         VPw/CXYSXUZ0iOkDZ2Ip23TlqxcgPMDYmw9erpyjfhV7G0/oez2SJ5CQnY/vQ+71bOgM
         boF1TBkz0g4ScvXKVkop2EJT/1j3Dii1l2+ttwSY9rmkpZBD4LfBlHar87Oq5gMyomOF
         HZjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756469911; x=1757074711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=epiwFTg5YivsYM8Fl3TvyH/GNyG+Mmsjl1AB0lgw8KQ=;
        b=adS9et9JJ4HN/OvLnhQqU6wFZooWie0aZkAXPYIOPRSiyQVZQwuD3Mu9YWlnF/Rv+U
         Y3WpU/4e8Gxt+8r0oVa8UkciOxsnDwx830Xg7rdpwFfyFqBgwQAfnKTOuchK0qqMpt9n
         g1fNomhISdKi/we4GsIiYdb2vwCJ02U/SI3YybZNGrviqDIknvkEgw8QQU+bbori3B2U
         uQsC9DG0eequf6XFFP79MKb4DGG7Ky6RZ/KWcpQA9GAU0PXUQncsTJmgaWcJDda8d6lK
         mc3Kv0Yb5jqMfUiC/VW52k3giFl6/VnXmrdvLEak7istEbv1ydDJ7Ct4N+pQkfbodSJo
         IY4Q==
X-Forwarded-Encrypted: i=3; AJvYcCW67MGweHaYc7d6nw/BqkdXPmAFTrJwOMZ2xsmUizJ3q+HPFCFuCqX1SCdnAU6LesPwUGluSQ==@lfdr.de
X-Gm-Message-State: AOJu0YyDl44C5aa/01cQkmPgAxXNlH5dDsjziCQfZnqS3Lvoy9EUYAzG
	ZSLbbS1SGv5A9NYL35csVwl4EH2kv9huAgjiqDo/RJ0+L09MYd/aSTUj
X-Google-Smtp-Source: AGHT+IF744y3WSQXNSb/jCpZejNlI7xoXXTxbuSaZ0boQx4+PQkRcVWHQXc6JPv5546VdHYntq8HLg==
X-Received: by 2002:a05:6830:67d8:b0:745:5beb:a58b with SMTP id 46e09a7af769-7455bebabd4mr1191918a34.2.1756469910997;
        Fri, 29 Aug 2025 05:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetgYe7TOLjJgqX6dVDV3V7CvK7crwCHp6hdtd4hwge2w==
Received: by 2002:a05:6820:d8f:b0:61b:943a:28d with SMTP id
 006d021491bc7-61e124ea9eals447345eaf.0.-pod-prod-03-us; Fri, 29 Aug 2025
 05:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVEmiISaxT/z+X6eEmyPv4lxX0DMSaXuUQU7dLtIzTB4zX+rOUP1oEuXGNoE1Uusso7rksDpoq4h7c=@googlegroups.com
X-Received: by 2002:a05:6830:2a91:b0:741:b6c8:669d with SMTP id 46e09a7af769-74500a603aamr14105223a34.27.1756469910275;
        Fri, 29 Aug 2025 05:18:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756469910; cv=pass;
        d=google.com; s=arc-20240605;
        b=jUA9Ld5VWuz4bTFOhLD2dib+M1AnaVZOy7WZcjh6DSm/gjGkIupBHHYIF7bUmHxUbq
         DjNOl/yFVRaItCnfuJ+oInFerYO1uZxBb4u/dF3cZgyA2dnmSODwMLKaOvzOMpG0Y7/n
         JgxWAW8tTpbO7GrUvNjuE10UyiErFKoU1b9qPdxJJ4B7kwIO6lID5m9pC3WJR5sgsVdT
         d/QfTkykZzL9u/TCqNy4ASXaKrT2KiGFU/s+fB2G8zy6bjkMx/YiRDfcB51ukV+eZ40/
         k+pQSjxi2HoX1NgbcxgrjrmQ7o1SrVAhqwNx7Spn+Bl9dWYHrc87CrizWGr92dq+bila
         OXfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=txC1XkQsb2R6wgh4KvJ4mm4Ea4I8RAHr+f9h/9mME4c=;
        fh=5dY4eYNBEIKzJB7gwWuE5B80X0wrUhVJAA65PLzPjuA=;
        b=bJIIAeebzV8PjOd/SlB1bUDLYlXaNXaDoT7babZDx42209RxS4tfNRnI/jfishxUsi
         Wrhq2NKl/KYG0IhtekC3he2ObvAVdLS51QkM6f3bctzBBcBLvwV4AkdQXB0LrxaRlOMi
         2vq3zHoqTRnx02nUVOl38sky+cuw+EVFuMNwMJKsIoJ/79Soz5n1vTY5phBkA6J5VUGw
         cfOn4k8XSB6hHD76iJjg6SoYK9GmVcBB8SV6sdqV2dL8n2ML1CY0ndlIF1w2wxz2MOsG
         rcLv0LtX/czsCsvgVsrvn85mmeqgveinJHoHKyUktShyIiZjEI+3qXqZjJGFz4nK0M/Q
         3YHw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kGM+MNYW;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VeKnTGYK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745582dbc51si94259a34.2.2025.08.29.05.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 05:18:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TAYkR4026796;
	Fri, 29 Aug 2025 12:18:20 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q48etf93-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:18:19 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TBoEJ6005010;
	Fri, 29 Aug 2025 12:18:19 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2088.outbound.protection.outlook.com [40.107.223.88])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43d6avc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:18:19 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=hwNi74ysUvL4jP4P89tgTUz8zOiu1/k5q7p8jd49JBJefj2UAhlJEcndjxd3obJIDBatXeZnEwq2vrJauBpIQXsmCd9Top4KnawOTJOqI0yuGvYhPtLknV/RLkiJT5ZUXDLrZorQWcUgJbdEMx9OrX7kuh32JJFcf3Q6QTjCUCP7WH2wLnRXsgoUmzeU2AwCXaTAjVgdKWViocZlCRhkOijHy6vtaq9ATPmdlyT0enDpinxeaeHSfKK4HnCBZolAq6ttRBcULLlPU87FSWkOgZlwf+2LTfHVDl7WNHAMByEPWhfaTK1nJDan6wy/gQOYLMK6DTUyRnTgEe21+bShvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=txC1XkQsb2R6wgh4KvJ4mm4Ea4I8RAHr+f9h/9mME4c=;
 b=bDGGDmctCpKDwkB6zlkvHc2knEA/y5XcXkrdc4TOsa4zQdArXIj+cnvWHOJQSnHd8Bt9CNRS5QsFf4kejtLq3XB4XeabnW/hItrDgag+3HY4FGvktm1ZW2kax/19z5nnNkvu2M3CDyHG9wqGv7rYc+hhqYeMLIPDN11TcWlGltu/gXdYdJInG/o7UJnqeYJwkEsvdIpiyNq1Bs/gnd4OqwQ4AW/zb/zwJYi1k/GzpdhkeK6LgF3OWRO5crpe9qvQj1vDB0CMxMsvHZ1pZhuAG6Kt2dORTchaHllm0B1yBb1ipA/SdkQN8yAQdx5X+Qv6qKc8TIUpwGv3rSWjQJBmgw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by MW4PR10MB6372.namprd10.prod.outlook.com (2603:10b6:303:1e9::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.21; Fri, 29 Aug
 2025 12:18:08 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 12:18:08 +0000
Date: Fri, 29 Aug 2025 13:18:05 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
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
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 10/36] mm: sanity-check maximum folio size in
 folio_set_order()
Message-ID: <ad3ff8d5-a9ea-4f83-9860-a96cc1e728c7@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-11-david@redhat.com>
 <f0c6e9f6-df09-4b10-9338-7bfe4aa46601@lucifer.local>
 <a9b2b570-dc81-43dd-b2f3-a82a8de37705@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a9b2b570-dc81-43dd-b2f3-a82a8de37705@redhat.com>
X-ClientProxiedBy: LO2P265CA0450.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:e::30) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|MW4PR10MB6372:EE_
X-MS-Office365-Filtering-Correlation-Id: 1ec3c301-2c3d-48ec-39dc-08dde6f61d41
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?07hbUwOxBelOrEfLfSkvldmuNlKzvAotAP0oJehQfhVPD85aG2rvbDnSpdNp?=
 =?us-ascii?Q?F+3tY0K7+fKjUrPIWuzFXOwe5PV+LXG72E+lcWxkvDHxbmdRQ4EPe+1aryBI?=
 =?us-ascii?Q?BNbRp3OPCQVbdi3pT1WhNN+sjy0MrN4PVxWOCyMH7lUbhWFqGoknK1y/v+Zr?=
 =?us-ascii?Q?R5Qv6NbPcehL/1ztJo02dqyoQLin3/UOaMSahj21+DvxMqsPCnZMFn2tNUFi?=
 =?us-ascii?Q?/stgQN0s0IsVH+8NjZIkTT1xPlb90jFDWASfvc8ZgfiJ/rfZxvm00UhDFI4E?=
 =?us-ascii?Q?/fSAZb6+3vNqOxrXidFTbB4ZaX5S/BL+bCMPmZd9j8vxB52qxNnLJfNfptqT?=
 =?us-ascii?Q?Ss6c93zTNrJpN2K/BXwOrGIKpTX18pmlfCLQcnwBo/HXIpkEuaLwovzzX+nA?=
 =?us-ascii?Q?3v/8IRscKd9Ie+ZGA8rMaCePm9KSnTpYOCuOPMcT/5PfV2U93VmCvk78fK60?=
 =?us-ascii?Q?Pb5EFP2o7CROW9jRw39dk6FFZql8O353h/NKG3qcAt4IH9UjqLmeTe0PgVNZ?=
 =?us-ascii?Q?rDq1ETEb0CunxoQpNZe/iYHAqAiENF6/xBWwJfPewHNis8b4vVr7BTJ47UNs?=
 =?us-ascii?Q?A5WV/sKo51cSNutUPUwRvJX3m4v3M1wmv8HcvJelxoY20tMCmykaXjoykdrO?=
 =?us-ascii?Q?LZEVlSKa/Ndo8VYS5KYuVIMR86UmIdyoyOyjliFWZRnjxmcqDxoMAlL160zZ?=
 =?us-ascii?Q?6jolSPnNvkJBwVKz0gkb8EvIGhrTXtWS+YxbfmTdOsB+ilRzzUn+44bEa30Z?=
 =?us-ascii?Q?LApeMXjXxynCz1YYBiBgYVmKLZdSJI+cN8JTD8seA/UJOqHZnX/Ewvw5Go+x?=
 =?us-ascii?Q?jPSser+uKrIkXVVUfyQE9+6Odh1w2WA0IEh6O421N9ttQHoDvzJ0w+rZrCpa?=
 =?us-ascii?Q?pnWBjxB8lCiGM8g30NwEYo9yKTDbWYDPqYLsRj0BvPhUDGzPxeZnY/ehaIDL?=
 =?us-ascii?Q?VtieWGJXJNROTJfoJIQ1baHBT9zleVAAuxaWKwLHeSrwk2oljsSXLJBps1Si?=
 =?us-ascii?Q?DRZz0gvOvU5aSw0P8BKdpKcwXks0/1BnmuMFpl5lzNpy2RbKFRn2f4lC7XiL?=
 =?us-ascii?Q?5rzk4xj5OUuwT7eLGt2QKc/xJgG8MLwnVs/ncDVc+TDIHe6lwq+IvZhYQk7I?=
 =?us-ascii?Q?Adgb/RkRcTE/UbKY4n0Bsb0MF6UTIiN1rFijV4gBP/aLv5yJZJuUXk1CUWd3?=
 =?us-ascii?Q?/NMrGM4n5chNHTXDakGaO8S08v4jIwCElzdhzTYicl8RhbZFCPBBVREFYPwj?=
 =?us-ascii?Q?k27rLNxlr7G1PUQ0GqbXcHJj6tGhbczIe7wonAxVoS/2Yd9KYHn1KoTjNXz0?=
 =?us-ascii?Q?tsDC38Ut8XBQFrlSNqWEAiFu+ZnwjAvddbQ6/ny8yeP+ThvKLTcQlN3ywKDJ?=
 =?us-ascii?Q?BjcT/Q4iWMaiWBSwp6FSFthtj64Wf8hUhx6Raq2uyVk/Q/XfiLWy8o+WbUj0?=
 =?us-ascii?Q?hUHnmjt+SLk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?y6wUnjW9NT20j+EVtH3uR4ULhwhe/A9bP5DG0JNwcYGnvK2OGnCWD5ysNykZ?=
 =?us-ascii?Q?fq+sGlcbvcbH7k4xxZYPkeFS03wRQ0ZEWs4t+Kj3KFldQ6DY/H/aZX/RJg/W?=
 =?us-ascii?Q?YfF0Tkdqruutfs8rF9+q2u52wSvt2tkMhwLv9mnkGK8s8SaenSoX4ghvKSHp?=
 =?us-ascii?Q?TuNkQKP/cBFo+GIB03IUaUea68yyZq3xpOiKBUSieq68lPgMcTYq3Go6c25Z?=
 =?us-ascii?Q?RZncgMtQiG8d7J56+p2Nbv7tq9icC5LQBRHGAO4QU8YBkXMBl9lcM73RYhmu?=
 =?us-ascii?Q?t3hZXIJfF51H3o2Nuaz21WGVyIGnyHFGvKMo5kPuADn+IPvz3XPurfnvR9/x?=
 =?us-ascii?Q?4PMBOyzgntwQlmyIGFpPCNNrYP7rJ8ptq5izw1ilyGc0FAaQREWeXURDneJq?=
 =?us-ascii?Q?dGRgy3o0yZPRppl/mKW8Y0AqCkkVHjDLgu0lLCaQsesxJLY2/VUtldyVqMxb?=
 =?us-ascii?Q?0ze9oeKmibFi97ftRbFUywhIhYSa6w1X6TEmEv6iZvK+h4WViY/1LlFLLrFG?=
 =?us-ascii?Q?L3zWbqzbKS6ifZKfy7o8MNjVePu2O21gwd/igr3295MohszrMatalyjkmpst?=
 =?us-ascii?Q?w6POQ/TKDdoDM0t6Zi2PdhBm/FDyaym+0fZwz/DUWIcm4/nRw7m1cI4tW1iG?=
 =?us-ascii?Q?vgIBOziuuwT1t6dhChMr8CYamC8BFmJzFAXnMeNtQaBQTvBpndJJPf8dBYF6?=
 =?us-ascii?Q?WvALrXzQ4n/Q2/RM9rOWPNSBwm2caPQKjeKXFtEJIxS1WYDnaUSi0U1zSWBy?=
 =?us-ascii?Q?ebJDh2T+CQQRXarUBa5WN6qoQ2OnUNIAPlE33PvBC/oHm3uAJQVUZ8nBeNPn?=
 =?us-ascii?Q?aQ+oY0hQC/+5KBbvGOR4m8+VWSvZkzASxzUHBwRINl+05LCi2YCqofCQmjNV?=
 =?us-ascii?Q?ZcsbQFOuGGf0gn5l5oz1x3ZKkUDZ+gi/s/yz2wstTnJ7Aid4mdBIVROpiPJl?=
 =?us-ascii?Q?53wtCaDb5fE3pRtk7+Si/MXc/EwVaaGoexfnkbmVVE9uPFU76vI+hnj9h9Km?=
 =?us-ascii?Q?PBQ7P9AvTf20jtb6874RDtGa6KpQ3LNBeV0V/xV+f/m+V6scKa5Ss9+j7ACD?=
 =?us-ascii?Q?XEzsiuatkIHYOmahz23aIGtSXy2zNUTQkALRsQhb1CKBUNF/6v5q9VocVoPb?=
 =?us-ascii?Q?FdB9exN6+OwzN5VEpkQA6q9nAARa/ECoRVeoO4A6qNcrqdGZQVsE30N2EjQP?=
 =?us-ascii?Q?VtfQHnw6/8HisY8nkrQWr+HwfO0CDN/8eii4HznmAj6pS8Wd9ffLF0Bws4O3?=
 =?us-ascii?Q?MiPpnDHrB0pKkUWbT+UKrA1j6WbJn7rrcD3sett92IfZdCNh/0O+neWPCOFf?=
 =?us-ascii?Q?3iBLjmUI2No9tQeJlXocELJfy7LtZgr5K+O2lL/Rq/pNd9SeEjSZd/UXm2Nr?=
 =?us-ascii?Q?t+Vemk9VWh/tZifDxpilEyoUgxPUp24UQDS5NMERGi5rhEDQwiys1e8+g5fv?=
 =?us-ascii?Q?Nc3yW+OUvMIy2FUvrpVMDhPYiYc3wrxqM1j3X/dt1/ta9XXQCN1Jt9ogCSjd?=
 =?us-ascii?Q?XLzyTxu4nKUHRQ0yas8J7pJdPwZKjplmR9PEkgLD8/YfF/EVWubFdNFdH3uK?=
 =?us-ascii?Q?uQf68qYMjg16M3TnfRZmzcJR/VjBfjDpX7rRGsFjHkTGRWJhjJgBlSfZiKOZ?=
 =?us-ascii?Q?YQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: D0lc82rukZHwxtF6+vhsXDXlmz5e5oyToQLJvxD9pZQA+qWyNYh2aV63OxUfuFQYPaHED+j2cKTRLDAIiVzyufHZwOKglgslhLbZyYfXli91BUmURyUkqp8CVkS9Rly7oyq3XMQXsWV5z0wDHAx4OhM5PPPCgd68KqkUuhPJRQmVF67F8KU+XXKDFMDT0qPqjM11bwszv2j65AAkIY0EfC3h3VfLR0SPbZGriq8sYAD3N2324F4oAw55Ilie6RF/i8jYaK2/EnTMIIjo2Ldx4qezROyZIr90tPoXZ2a/B2m997xY/xPE62l/ZhqVKb5gWPmF+bJj8mHULm7M6Bbm5D/Uks7aR0tbEY9UfeDQK3d7ACKexoi9EprtAvmAIIbE31kkKv1GI4dIGacGL4l0b+ywtmkaMd3bFy+as75XVhA5Rk7COQII3zhRv30zunnXrUWhCp1UAroEyoAbiBurRE2wtwSIR61hbduF5/CwH0IMWMfkvt6KMrTBhtSAwsm0EbVzu081StmZmmqTjQqpsfrszF46e0nk5Vx/BD+BDuM/VYZP7aDdmuCljl2lg/q0RBVvl8khF81YqphHfed68S/SWv32lTRWUFstaOujx2o=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1ec3c301-2c3d-48ec-39dc-08dde6f61d41
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 12:18:08.4291
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: WEYAnIIbdMuhiMm6cpBVTMJPimWrU2sLD1un3aqASFaecY44AMu7lD9YEHrO7dYBrU7s4/pCdc1RCoZphQdSTvpBThXhKrBQplwMSAHNEAg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR10MB6372
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290103
X-Proofpoint-GUID: 9bl8cvboEeeC7gQtAnc9bmxC5BOjDDMk
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNCBTYWx0ZWRfX26V+ZtTsXsFy
 xs1yuXK2euGcI9pO7wuZDAh7oUCYEt2yzaaSpFCx8J/jeOLR1WNlcWHgKoz+ESfxLLEEtFs2q9v
 QY9CLYMr10ki9XynwYuxeLGY/FF9+ZKcesorTBOBTdgIGNb7v/U5bmbnh2je9Jvh1ajGXLls5gl
 Stti1onFvVWhboKyt7ucURPnppwhEIU+qTUsW4TqlA3F4x8VvZ84dEUTcr46Wk1eOUk4WsulHx6
 MVqd6ytKX7thIHLD3zxcEXB+RibmqMuJ1wJPx2nVd++kC3sW4IQgmAAaziwrHTzn1JaI+Os/vWX
 rsO/F4AnYWBzhMGsVNbHVTQOCuXdWDubZz9BhF6lUdnTIj1VkmIByCkwkIrCOzm4vVKe3pqxDwK
 9kOY5y97
X-Authority-Analysis: v=2.4 cv=FtgF/3rq c=1 sm=1 tr=0 ts=68b19a8b b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=t4HjgU3YqRTIp5Dt6lEA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 9bl8cvboEeeC7gQtAnc9bmxC5BOjDDMk
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=kGM+MNYW;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=VeKnTGYK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Aug 29, 2025 at 12:10:30PM +0200, David Hildenbrand wrote:
> On 28.08.25 17:00, Lorenzo Stoakes wrote:
> > On Thu, Aug 28, 2025 at 12:01:14AM +0200, David Hildenbrand wrote:
> > > Let's sanity-check in folio_set_order() whether we would be trying to
> > > create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
> > >
> > > This will enable the check whenever a folio/compound page is initialized
> > > through prepare_compound_head() / prepare_compound_page().
> >
> > NIT: with CONFIG_DEBUG_VM set :)
>
> Yes, will add that.

Thanks!

>
> >
> > >
> > > Reviewed-by: Zi Yan <ziy@nvidia.com>
> > > Signed-off-by: David Hildenbrand <david@redhat.com>
> >
> > LGTM (apart from nit below), so:
> >
> > Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> >
> > > ---
> > >   mm/internal.h | 1 +
> > >   1 file changed, 1 insertion(+)
> > >
> > > diff --git a/mm/internal.h b/mm/internal.h
> > > index 45da9ff5694f6..9b0129531d004 100644
> > > --- a/mm/internal.h
> > > +++ b/mm/internal.h
> > > @@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
> > >   {
> > >   	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
> > >   		return;
> > > +	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);
> >
> > Given we have 'full-fat' WARN_ON*()'s above, maybe worth making this one too?
>
> The idea is that if you reach this point here, previous such checks I added
> failed. So this is the safety net, and for that VM_WARN_ON_ONCE() is
> sufficient.
>
> I think we should rather convert the WARN_ON_ONCE to VM_WARN_ON_ONCE() at
> some point, because no sane code should ever trigger that.

Ack, ok. I don't think vital for this series though!

>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ad3ff8d5-a9ea-4f83-9860-a96cc1e728c7%40lucifer.local.
