Return-Path: <kasan-dev+bncBD6LBUWO5UMBBMGHYHCQMGQES2EKVAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B5A0EB3A065
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:12:02 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2445805d386sf11563825ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:12:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756390321; cv=pass;
        d=google.com; s=arc-20240605;
        b=fY8l/iYArpug0h4Apz5Xj8MW+/Gbjgz+0HSYY4OU3CaCfHnvGuovI9aCD9o1EhxTRW
         mRo5Y9YyDgUam1bzmTLMhLDQU8C16KBfmv0pLj9Kvv66ttV8Z66QZ7dC1DuKAE2Rd4Yb
         TuxGQv2m7PR63OLu5J64vUSe9V5zx3vKkhNkEk6bvJ5NlCb5NaOyNX2VnXAQM+6yqkWt
         f2WQD4xMgP0DZ5MJ8uTXdyJ6/dQuXki5rJ837sXXxdReoAgGlxZN1H36d9qY6OSI9V1B
         bEWsa48dXUR+faUIb2tdu1PBCO9zaLzs4K5F87TQHtkVSqg2kSYpVvnlNLP9cHj5M50q
         GoSw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=DJyxNLbXeo1zrwr/O8sQ14wVg7h0w1zoJIfz4UKAdP4=;
        fh=8haM/HvlWNS6MiJu2vU4eMSxd48DHj9ruQp2uDiRMvw=;
        b=dg4vJnm3x73MjqUsAwWFJFTvFrloYzSg7M1bgCbEZd2nMZE/qDnDVhBMGLwtJl/SKL
         vW9Hg10zKaQofZJNy6yobRHyMRhJ6X57eDgmzZNO6BtNL/zcfSFIgmhhvKahwsfpGuqC
         kFVpCYsURgBlSGld9ZRvQ69WqVXQqxLK50zQMQSasQ2bZcJvtAbp8cOzorXE2KFGNmux
         v6IBUd/Is2Sp7cEOXvTI5MH8XRNfz4KJn/szcVxjfDbx23/52m7xisPIHvfcxg+XzsXK
         HYij87TGH7tM5LjuZKpPRA/gXfs+SbYgj8TcuARuhXMyYu9dxmptIiDrzVovf2V63Y7F
         ITGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DODxQZ0H;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bOlSNCrS;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756390321; x=1756995121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=DJyxNLbXeo1zrwr/O8sQ14wVg7h0w1zoJIfz4UKAdP4=;
        b=lDoO/crdtitgRYkY+8EXM2j7TMYJifeRgQC1xcCRP87EunoX8wVw01RnUFpMY3ByQv
         XZtTLzeEYTK//+FoK7uMYHvRLPxCWh/vl3b3PyVZkYymktyw2prippJyzAby/QjaGV8y
         Srz2kmbwW+k3uKfwlNXlan5CsnPVNldGgjh4jPTpFimK9BSCnTS1LDVpahxAvG4hvaK/
         UZ9B5d2VSkiq+D874B3vsSRWwwu/y7eq8mIclmCZZRNx4TvpU54lzSXmYZi+5/Ogi+wt
         kjQBlylXY2HeOMObHnSj8h9+PyW+Jwcsch7WWvoeueMGZJJNWZzsg0kf/+kJxgmn/H+X
         CRuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756390321; x=1756995121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DJyxNLbXeo1zrwr/O8sQ14wVg7h0w1zoJIfz4UKAdP4=;
        b=Mmj0KhK7HLYNgtP+SApxnqTCqTL+0lFhn07yllFznHn8MeHQI1x/whwvw6ZSI/ZCFH
         6EiP/PL8gE0DqpBeyT1cFpIr965zHs5jnABL8HtPsM21QqNLTwWMlGSySoWIp0O6S1+f
         /f7Fn4EMNRBg7B1IlfVymQP2sMj0Am+mx2QJDAzky2rWi5FivhdkWGZpKLMR62sFVHXD
         CjM7ReDOrlYf2lN76boQzbDpFXo7p7XBzeQc/b7df5KqXRXdJ6pXOyctHx238DH3KEBz
         6pAi1HvUAgrJhh90Ml7GRwvW+dw1p+c+LQh1n/AdPiXYsLrOQYSaKI5ajmUkajG3MoRn
         01qA==
X-Forwarded-Encrypted: i=3; AJvYcCWqh1O8HtIxNMpKjHtkbdZ/t56sckRl4eZyiA2QgZFD6Ir0qQlrSpxktCYwLfoM63BypIl/4A==@lfdr.de
X-Gm-Message-State: AOJu0YyA1OyNjMWMsLqbSH4UhVVX7UQ+ZgQWaDVgVJ44qYf2ieFw/7Nm
	Gvt3ltkr5vA5tgpswcMjXvy7EhLT7pSH8Th2dam6VpvkjsgHJmuEFXA3
X-Google-Smtp-Source: AGHT+IFkVcKAVvFWYODWFVh21iDKS7Z9udFjhq3gZVq0lJPuk9uGR8VaxGpGEQ6ObxBzWw9djqxQ5g==
X-Received: by 2002:a17:902:c947:b0:246:64a2:63d9 with SMTP id d9443c01a7336-24664a26b31mr231102315ad.51.1756390320700;
        Thu, 28 Aug 2025 07:12:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeF1hYKLqk96g4Ah8d+CjO44tI4ZUlomk+8NLpuL60NoQ==
Received: by 2002:a17:903:a08:b0:246:5a45:dcdf with SMTP id
 d9443c01a7336-248d4b225a5ls6007925ad.0.-pod-prod-07-us; Thu, 28 Aug 2025
 07:11:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU6eF2BsF+u/Wfks7l4Uo3CMeoEIZH7DDBLNfu6EjXfZKZGKWAZTBEod/40GImAXysDrTHV4DgJwM0=@googlegroups.com
X-Received: by 2002:a17:902:f54e:b0:246:916f:f6b with SMTP id d9443c01a7336-246916f20efmr198321755ad.60.1756390319083;
        Thu, 28 Aug 2025 07:11:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756390319; cv=pass;
        d=google.com; s=arc-20240605;
        b=QdSEM+EvBM6tDbw1VMBOaAxw1pj2fJ1ESM96lOqI9HtSO/WD2fo+KNEJ9ABVXobwEh
         KX2vAWCzmQD5tcyBciiQJOYmObXeWi3m7EVAEtza9tHGE09q83vJBz1M6SMmeybSoQaX
         xNrGmCiOnPEfobyFBUdJCOUaumMT+vNri3UEgu/5bDOJqMKK/QFjDSyxnKJoFzThIjIQ
         kTGoXy1YP+rB5pkJ3MxrZyxdI9ejH75KoWYj0dtLGVIw28ZSDxwrqL7U72JuQd1otfc9
         6DEdaVUALmkkTJCichhwWuQL59mQxNcgVIIGzaMN1cd3XOGmk+eKpq+c242RMi2/a3G9
         /kog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=ipFAsEPyyh+QIxVLjKyA4crlS8XKgA5L2Eat/sMpmFM=;
        fh=QaxEBorub2MjxwdHInjXEEDqRBwvpVC8Xc/3Tn8W1W8=;
        b=h5RWeTVT/Ub8dxwQ7jr51T5v+/dzq7cVcUZRaRFdgLnlyhV5wFxaISXHoJb88Tsehq
         2DR9JlFnRnI6oXVsMmpl7VDUcSVb3ayNLMsVqE6K+oG4Cb7tmfUxJUlf36UwRNwsjhVz
         wzj5aN3wpdxCmJNQ6+Qx5h6fGNNHdsY1ahb/h/p+PMt9UAFudZ/lD3u5hNcsx+w+zOFf
         vNTUCUFFkMbHIbSagI7X7FQDfvQovJyGy85Ryrn8sym/nZV0VCc+2Ix0fhRPiZ6B9NFP
         KzlXC3Nf1xl7UGmIvF99VoVOZgpa6X2bi2ARFy2bsYwebntIct3wyJCMJgyCX4nqtxtG
         WaRQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DODxQZ0H;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bOlSNCrS;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2489ff0aa05si2054865ad.7.2025.08.28.07.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 07:11:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SCiq7s008992;
	Thu, 28 Aug 2025 14:11:34 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48r8twfayb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:11:33 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SCeaYW012167;
	Thu, 28 Aug 2025 14:11:32 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2079.outbound.protection.outlook.com [40.107.223.79])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43bwsn5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:11:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZocmddvaPdZEDC4On8QTgaIBmos/NzKq8nwnL8i29ddkJw/imSAqVA7s9tkqk28wRV/WeqxpgUiiqySISDRX/NGVxTYIjH0owoeZ55gnVwByFyMhFjNqmnkTESo5FHVI+kuBz0SEjLLmCP1+IakP47NtPa/d9yBRsSVjJkL7fmB+zGz435TDGoTRgetq2mLQqHgYwLCymBsYaX1uQtEpgW9rPI4AiA+ZRFVZW5Iu85Ld7ymKi4omjD/FH/0EDAQPYaIwVo7jYfSdsXB2qNg03mV967p7H/FmddUh0Fk/tAXIIvBvg9SQBkompHQZCQC164nTCU9tw23JaEAmcsxGjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ipFAsEPyyh+QIxVLjKyA4crlS8XKgA5L2Eat/sMpmFM=;
 b=JJ6vL411lIwFlYwag6itiniwKjcBmjkkDRv3IcHSmeMu5WNJTtxdX6IKGvrGOEHW/dyYURfLb+i5sUFB5BVN8VfPmaRJs6MvLr59Da+bKT7ZAQzoi4ONkXO2KfAtNwiW/IAFAI6N4k41ja2vyN3FB4iYNJ37ww9SyNx5yj9G91A4gqov+GNjN+CsbJCALcY5GbGlcaHLRnlFX6EiSMEuBF23DenygEdottnCn8V3Ug8DozwJs5qgf3a0xOErOkGOkm+bWvQnNRt7uwxX7bgpmgV0Qmn9x7gcZHdEBrJcCtpHnPQ36U1kJtzbgaC7//oDE1I0TD+djV339qGYj2q+OQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH3PR10MB7762.namprd10.prod.outlook.com (2603:10b6:610:1ae::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 14:11:18 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 14:11:18 +0000
Date: Thu, 28 Aug 2025 15:11:09 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        SeongJae Park <sj@kernel.org>, Huacai Chen <chenhuacai@kernel.org>,
        WANG Xuerui <kernel@xen0n.name>,
        Madhavan Srinivasan <maddy@linux.ibm.com>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Nicholas Piggin <npiggin@gmail.com>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Paul Walmsley <paul.walmsley@sifive.com>,
        Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
        Alexandre Ghiti <alex@ghiti.fr>,
        "David S. Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>,
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
        Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
        netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
        Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 01/36] mm: stop making SPARSEMEM_VMEMMAP
 user-selectable
Message-ID: <c452d577-a4cc-42aa-b4d9-fe591dc4a315@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-2-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-2-david@redhat.com>
X-ClientProxiedBy: LO2P265CA0507.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:13b::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH3PR10MB7762:EE_
X-MS-Office365-Filtering-Correlation-Id: bea88a2d-5fb5-48a3-9709-08dde63cc22c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?cpDpXr+aiYvqPhuMlqmi+25CBDnyZrKwWJKv9gXpX3SwhSA/cokPZ6znM6+d?=
 =?us-ascii?Q?D9A6uxaiU1mzun4TuDFiLmr9IW9YI5zeyNdmMK0jUL+UbOpH6TTXJb5E2Ymu?=
 =?us-ascii?Q?/8VxUFHI0UjIi9ozIbhvSCxHYG2AlynnCMnpxH1vMeL3o+TdulSpkHimjyHN?=
 =?us-ascii?Q?kTBuDoP/CXxZ+9No1koPvvTEojAWNaXzWTohJlCPZTG6spuWH6S1Z455QL2l?=
 =?us-ascii?Q?9tzSM6a3E9LdfQhJKvhi8c5XDklckz5y+We0ik2w7tbz6kKvSc5+yqYYeNGt?=
 =?us-ascii?Q?7kfklAnT4IUNCPWT/yNJM2Ph25rvNL37Z7fyM5l2AhLWShpVpeAhOPuVJrIR?=
 =?us-ascii?Q?Ddc2XVMHG18rEpRXc/pd0/qMHp2C2AcIc0pdfcJbL9E+Hamn0p8JmrVB6T7/?=
 =?us-ascii?Q?PXNrRR9m+g9ps/Ev/CcUhtWIXqd+0fElcc6jOmsZ15SojKGvWt01Q+HnqM+k?=
 =?us-ascii?Q?2q+/dgNe8H15awCkYabDN/N2Vurpy97HduT74UAEvB4gZisX5S8I3vzpc9Xe?=
 =?us-ascii?Q?6AF6x1sjqF95uXQPHK1Jpp505xBXRw5Eo46gMjZzPzrTQd2nRzFfthFYdOey?=
 =?us-ascii?Q?u657r13AvNlW9KOm1H33I87ftVx0qTug+qkypYq4Y0jD1dU6ajRxLymbDkqA?=
 =?us-ascii?Q?7Fz4E/I5hb6FU5goVFSY9IPZghEUOEKqFGSp8W/BAsPqb2PYe0p/t7OhTU+A?=
 =?us-ascii?Q?mkgZk9MA1nwHXRwzuJ+/qABy8ntJUF9qhSNEsaeK+igUmwYkFSGwNag9zBDr?=
 =?us-ascii?Q?tqEKTB37SCi3Lmt3HQ4MxcHoGSX2nWyH0wtUqUi23Nu5IJi1+tEh0y+/tTHv?=
 =?us-ascii?Q?EBQ/Klu8ZHOkuNKYlGEf325vyUnEMeeap90zNRps5H/QeUY407e9UZAWzQqx?=
 =?us-ascii?Q?KL9qoFkSpSIGNaA6XD54n84DJDmNnz+aJGpf/8jIaTG8bpy0Vk5BZUpplu8K?=
 =?us-ascii?Q?UHEK311MWLWao37NRqXlB2nFoQh6WHizQAAxUzRonMwZQtzdVbOrwR8AOWfm?=
 =?us-ascii?Q?7dFHq9HlskNGtkuqPpasMmDN+XcGAYEifmFnB+6DscmI4H8PROoHOlM/HD6J?=
 =?us-ascii?Q?WeAjf1Ly2iGZWZmoYBFCJpIMT2vbDRTdxjyNowWEm631hNfScHoyHJpA0ntM?=
 =?us-ascii?Q?MNEVhbroTzA/HSoH4PaOzUsfq3ke7xqVqGnR6MDzSZAHmYgXrGpj4jmign/G?=
 =?us-ascii?Q?1AhukG4KfJMNilm800dgdW1qXoQbdeIwCuy7Ar11jGiPQMpMVq0f+Ui22RdR?=
 =?us-ascii?Q?+ycqfDCo7rL6y7CMaqwA3Rn0Mz6LiKew6kRLoBUSfMx7O6VrB6kaXxftqkmj?=
 =?us-ascii?Q?pq247GTjFA5zcaqK6pLoveAfpRX6lTm/YBdqEmPwFSwQm+QI/2h0BQvUzB8q?=
 =?us-ascii?Q?SopOCw9lHtskWn/MCkSSw+oGT+Hb4xbmnawYMqJFQVOus0BCbH7aWdfMcNLy?=
 =?us-ascii?Q?Tb+C2K24Pqw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?rxgXB/dZU33ACFpPxvESNgy2I7tNytmC03fUa21HD02Y0WHXfMzNkMqJVLJs?=
 =?us-ascii?Q?qjRQbBX9lZwPpw1a8PGAdYiLFaaFiqit045op0s18QQV1VLV6rXmhwMF4p9G?=
 =?us-ascii?Q?ZHC22IzQpfM5n1sO+6HE+o7/G7vBoGDatkMsnl1eWE8OwjuhAiEfolOGNnxm?=
 =?us-ascii?Q?gKqF4Q+PV/3cI6afg2K/PlC6hFfnPc/jSo2vcn6ahi6hX2y4Cf4gVXJiVDA7?=
 =?us-ascii?Q?jVEaXY2tAIzaKiJzvSCwuDdNVfg+4VchA96Yjj3Aj1r1dYIlo4jtqThvroKi?=
 =?us-ascii?Q?9tKJAs0f/awhvvf8hbW6gSH3vpD++m+bKwbmdxFemdltrAn4VQkXPbvMHwnw?=
 =?us-ascii?Q?frZ6nMlV4Mdy6cti0WBOCWhHC9J7u06zXJAGrksGMHPe+wxztTEPeZ/IEadR?=
 =?us-ascii?Q?zI0tATiu9dNdGt4HTQjF25ICHo/dbnJu7/jxD2Dc6SZTDGHnWtSYuM3GOrB8?=
 =?us-ascii?Q?qxsYsKtrRarxv7tJm2beoRQbwZSgMJxGdDhvtsiVDgbAG76MktHNSuSqBhWd?=
 =?us-ascii?Q?o6rvuYQxn93xFCcGyS7oDhiKAXE6FBGLkX2pXln7HPBTlI4CewDmsHTkCsdW?=
 =?us-ascii?Q?7q8k6gjNHXT92rmj6DKDmGxGUQaOTLmdXUlJyHfJKsYiaxWqsqh7YrqI5BSS?=
 =?us-ascii?Q?8gtKeOeCD1nHNH7ZC9dQH/X3usaeybk6OE+CeGCit2svyipMYq6aclTuz+2i?=
 =?us-ascii?Q?vlPva4ueI5ExD0mfCT6RrGOYj0W9qhhmhe5g7Te/Yb7tUebwepLPZzWQEzeD?=
 =?us-ascii?Q?Ee1gO1iYrq1RQ4rk33KmsL3GJMdYq5UVjuEq9x2HbuhH/PkMUpk/Tmw8Vura?=
 =?us-ascii?Q?9en5PjZD+RGz+eWBqNaVZi4ttieI3dte1jEN2qeRA762+NIlrmCZbDIjoLYG?=
 =?us-ascii?Q?DQwt4Y9m2dQ2H9gtEf4OQVIbfdwvMAqkuCkc2r7wCLb7SybY8sDqmF7qOf11?=
 =?us-ascii?Q?6t8hDZznz2tilGQ5iLwU7tmelugKEf6NOxMiTJoxyh0gfIjov8xUEoHbsaB/?=
 =?us-ascii?Q?T5hxClYji8uSMEXMvMEOqRU8dwc4h1D1cDqa4m3hx/gT/Kuy4Xiwe3Wibeoj?=
 =?us-ascii?Q?e+8gEdohuXN7xfQeR4A17rkI0If2mFLmrg6w5vbPMjlPrn0AQruhWbKWEB7p?=
 =?us-ascii?Q?yNfDTVDlpMjFXnXib385rX+Fa8c+5ckUOFYJUvjQNc7IlOu5IcVwR+8xoEUR?=
 =?us-ascii?Q?C+Zw+wdm3bM9/9IUfuinvuamjArq30Crr8hGt+3R3O8kb/nkyKZ0dKQu7yDY?=
 =?us-ascii?Q?8bfAqD4KI7PLHyx2weW6qSAVsTn2v+GNiw1QBgkKV8p5sIF0CFS8kubSxPmN?=
 =?us-ascii?Q?NKKJUVq5BzNccXzUtmzoZOPuUGoTLE2/NGPYmXOta7cPZfA50WyQ2RzPoR48?=
 =?us-ascii?Q?lW0RcpmiobMWWzOK8ebkJ/K0WatmlVkXAD4YREJ9YEPKBdKwlXDA1gtq5z8a?=
 =?us-ascii?Q?CgVDp4hZ1e3bU7G1MHgobOHc/u/ylZ5P35U+ilG5jFCAp6WHOZ8yONqlEhIV?=
 =?us-ascii?Q?mkvPi2jN9BjjV5b5QnQmhBZr9pwtvkdvP+g/QdslAOpZl8GOdu6EPEbzwDYN?=
 =?us-ascii?Q?iWJ4SPXcxXxtJy0ISRVCWRSuWAn/0/kPa8RqKWu25kqL5QXuperk3fSNrj9I?=
 =?us-ascii?Q?rQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 9JhnRP5jA+fe6KnbgTq8C+eIomN5HSIHyGtAzmA/+hr8aMCDrA84jG9dufUGcPnsiKEYncJJIyDKzB05okfQOZCr2d3pyHAOxCZCON1tGVyfIqdwXrkIOh+PohUyObeCObpOwwM4QtbRNPtOvz8o+E27SCR1m4/vagMruQVIVENhcs3pappIDyzwa9OpNu6WamcvWrUefyH3bcDy6DDiK33CHqubAmjTDsZ9R/En+XwzCdwa4075vx1WVJjQTJTqsnlW4OshprlWAE3fM/dGbjNVKfoGqeAMfqoncSqo6JSXIPRGb1Rk0q0iREpxEuWqtEqrIJQqTb3Lis9y96t2P/Um/SDEcUWuo0D8znESBybs5CHwLdYnH4qH4bXo7b3wpb9D47lvpKBGO6S4g+G+ZJf+3RO8LONAsZemaKd49Rd8Cp13/aXtbyLPgajRymh+mR3GP0Fk4lW4esbt4NME3fM+xMDoCFx0J+prouUMEhNQnnHZU0wDjN+/yr215UzL+oPG9x+8h1+t2Yiw9m0sA3vpwxIefG6j4URYF5Kvl+AbFocmum2HW0Tc/uvKPtSKayAjRYPLTHUvlKq9Rcu1af/GnhTW7TEi/eUYzp8QJuk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bea88a2d-5fb5-48a3-9709-08dde63cc22c
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:11:18.7387
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xAFwmy5DnYjYPM7XdIC/sjoEecnuk+lkZAbspbsFlmiiKQZnUnVQ4qYE5lAL2lLFMIMkDb3FSGNcArPkQwS6jek4d3A8AvctNALfAwWE9qo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7762
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280119
X-Proofpoint-ORIG-GUID: a226pGVOmGX0L0igwtWlyzYR-1c2Cebx
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODI0MDE4NCBTYWx0ZWRfXzYhIGyB1uOMj
 7mGgD+kET55gVP66OL6DspHV81gw7xs79sxPzGk6I6QH9eNuHWGRme0x3D0c9VubZMN7nzkAZdD
 tBiCe1It8g5UHgNKiswHc1AY714U420uVHzokIM0zLhKrDPxxbDAYkp/NAQmLTb1djCa+EncuqX
 2IK8nbXx++/hhz1F011rW3W481SvdbX7hZzZjJjLDul4emCql46t4m8cEKiuKAzRY0bApn+pi9/
 I8qqL1cCVlMtTnNTDpdezu8ABRx3zEHBhPbc7Bel4rMwHFH0GNm55/mKArgatf2knB6X8i8MiJw
 o+200kqrcCydACs9KZJssp/croyXgUg0wZcCjpIlq0oXXytuaWe/mKSpEAo4XGegP67a+mT+mUs
 HpU8PZW+zXgbcGtHtJgYY5xeosMeaQ==
X-Proofpoint-GUID: a226pGVOmGX0L0igwtWlyzYR-1c2Cebx
X-Authority-Analysis: v=2.4 cv=IciHWXqa c=1 sm=1 tr=0 ts=68b06395 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=VwQbUJbxAAAA:8
 a=VnNF1IyMAAAA:8 a=pGLkceISAAAA:8 a=1UX6Do5GAAAA:8 a=pFyQfRViAAAA:8
 a=_O3DOGVWAAAA:8 a=J1Y8HTJGAAAA:8 a=ebG-ZW-8AAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=6WdJ6Q9QPumUFND4YEEA:9 a=CjuIK1q_8ugA:10
 a=Et2XPkok5AAZYJIKzHr1:22 a=oJz5jJLG1JtSoe7EL652:22 a=2TKV-7w1aU1AVAwN0oqT:22
 a=y1Q9-5lHfBjTkpIzbSAN:22 a=Bj2TwAA_C77lQ_X2_dkp:22 cc=ntf awl=host:12069
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=DODxQZ0H;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=bOlSNCrS;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:05AM +0200, David Hildenbrand wrote:
> In an ideal world, we wouldn't have to deal with SPARSEMEM without
> SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
> considered too costly and consequently not supported.
>
> However, if an architecture does support SPARSEMEM with
> SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
> like we already do for arm64, s390 and x86.
>
> So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
> SPARSEMEM_VMEMMAP.
>
> This implies that the option to not use SPARSEMEM_VMEMMAP will now be
> gone for loongarch, powerpc, riscv and sparc. All architectures only
> enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
> be a big downside to using the VMEMMAP (quite the contrary).

Nice!

And I see SPARSEMEM_VMEMMAP_ENABLE is selected by the arches which support it,
as you say 64-bit (or in other words - modern :)

>
> This is a preparation for not supporting
>
> (1) folio sizes that exceed a single memory section
> (2) CMA allocations of non-contiguous page ranges

Nice. This should simplify things... :)

>
> in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
> want to limit possible impact as much as possible (e.g., gigantic hugetlb
> page allocations suddenly fails).
>
> Acked-by: Zi Yan <ziy@nvidia.com>
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Acked-by: SeongJae Park <sj@kernel.org>
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Paul Walmsley <paul.walmsley@sifive.com>
> Cc: Palmer Dabbelt <palmer@dabbelt.com>
> Cc: Albert Ou <aou@eecs.berkeley.edu>
> Cc: Alexandre Ghiti <alex@ghiti.fr>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Andreas Larsson <andreas@gaisler.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/Kconfig | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 4108bcd967848..330d0e698ef96 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -439,9 +439,8 @@ config SPARSEMEM_VMEMMAP_ENABLE
>  	bool
>
>  config SPARSEMEM_VMEMMAP
> -	bool "Sparse Memory virtual memmap"
> +	def_bool y
>  	depends on SPARSEMEM && SPARSEMEM_VMEMMAP_ENABLE
> -	default y
>  	help
>  	  SPARSEMEM_VMEMMAP uses a virtually mapped memmap to optimise
>  	  pfn_to_page and page_to_pfn operations.  This is the most
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c452d577-a4cc-42aa-b4d9-fe591dc4a315%40lucifer.local.
