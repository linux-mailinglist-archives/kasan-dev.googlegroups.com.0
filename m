Return-Path: <kasan-dev+bncBD6LBUWO5UMBB6FXRHDAMGQECRQYY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F1D0B52819
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 07:19:54 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-ea3ca79dddfsf574411276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:19:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757567993; cv=pass;
        d=google.com; s=arc-20240605;
        b=kjLlx5hf52rwMxj8puahu2cg47iSI5y9W2bxDPBisH+HsZat5zyhJsimDKac2TKcOq
         PMuL37EkYtLj5P7mue0n005iPAR9uUJ7kxhM1mBLruOhPdNSHcSSwQ5qrY4cNiayfSV5
         dVHIFhYjKFTdK6dVTS/KTAUsMrOI3VU3j8I5N/2LyP+Mxmx9ml/Q47dWXAUd90YqhWMt
         ybEvmXGSKKgqBJoDS5LWN9K3qOGTHQQQar9zbCTzw6cE/q8DdO0ihXNB2M19a2MV8/sL
         CZ6RN61MQYfRAeaCEctdUzydZF2+++dfSwH9tD8zHSKf7x+AweMUKFn8jiMcyXLmBDch
         K4cg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/NmeCpGK3RPuSZpED10Fa2xUcmtFY7V9jmFvU20aeH4=;
        fh=wlM1mIUwhRXKQMJZtX2w0eklXUlWLGAC4fHxrnh9rus=;
        b=g7n3NW6UNd6Gpo4I7NKYpa9rcJwNAK59TMlFUcll5y0RXAAFletjILvkF1XvRuNuUT
         Ee7Bpn0NMYK28URAQkAgxg7Apbuy/E06KUQUmNm4IRHrQt9eh4yk/bIIHCZvidnUJLws
         dYCGR7BR7ncyt8yfcjnR+eEmbyr8YFD/NWew5fCrYgAZGoP2nCxn5s+DgmHmkJXuBbA8
         GQbCXpZmTFvSgXPqM4EYpoOTnAZZV7zJq+k53U+tqDZ7djNi+n/77UeJTwxrMUf91vOH
         +9fAvOrYByVyB8SWYrVnsjmR+c3JkpaARKl7JzXdlGFHBXpJ0QuhKEVEBD2Bl3OheEa6
         d2OA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="SBf1/pkH";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dTIseU68;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757567993; x=1758172793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/NmeCpGK3RPuSZpED10Fa2xUcmtFY7V9jmFvU20aeH4=;
        b=u+/2G3CRPC8CG9UIn3IOnS5gqe6/Rep4oW5Jxg3r5/xR6gS+c/IeDUCEzV5gHAH6nr
         Tbzf/q1m/UN3j+DQPtkiZ3DM+CejVnDi6Ww0bl+A7k14ITWJxs+P8k77I8pBSyQ2QBbW
         b9qc7IBgGGFiv/Pz69G63sr+psn9IxWn4N5uHVyweq0IktHVKZHqEvYmtn+abkNvFD4H
         UV+qvQPlDxmfvBdbMH0cgk+oluVD4QcwII/PM5YZJ1t7UFPV8uh/KT1E7dHjU3FC94JN
         b74p/NYYzADkfnG3e9veC4uORPkzrhaacXyIrBtIIhHVYSnR1Lkm+Pq1L3/5f45FoxLB
         XW5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757567993; x=1758172793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/NmeCpGK3RPuSZpED10Fa2xUcmtFY7V9jmFvU20aeH4=;
        b=em2XRKswd9hSgZoHqFKM8o3US7Thu1ePZXJw8nna3P0rnoHZSC+FRcdHEGd4z/VSn9
         KUd93Yyqx3nXQrEgLZIckh7w4vCmYRvAREuNWq8Dl9NeCHJDFP3Bsa11//iukPmtkoAn
         WsnoiqWPAlTpR/cY54ZiqYiFogBUbCLlFctOqHPIrUcdlk2ZsMArnbSoyzFSnTEGeGZo
         2FYuYfrPiCkS5iltXgllyWsqWrlyq/EgTO0+Xk3Ab0Web7SQr8EQW6iJj1h8alChMUEC
         Yx0IlcBUvJ1GA2k/LTehpXqExK3s9EcL5XxcxGWpyzuixDdO4P+AoaT7UCB2BFzQ6G/Q
         fSUQ==
X-Forwarded-Encrypted: i=3; AJvYcCWkUlMTHbOGhF3s9/ff3R3XqnYY4s2X8a0falicJl+ETJWR81lE9mZmR+d4B0UbVx8DZHJN3A==@lfdr.de
X-Gm-Message-State: AOJu0YxotQl63bm9t7TH9zoQNPfFGohyb+5o7YvETUEGax97jx74n0ok
	bOYN2BOcsQ4HQYxdtqDYwXc1doZ8PheeLJPOjbG31wgAOCzabLzQSmaf
X-Google-Smtp-Source: AGHT+IEiHgvXwhtOS060dUhdZS0qjR9IVZ6r4e0XXN++93M3Uadoqdu84Vxl2uohlhKcPDmY3qVxSQ==
X-Received: by 2002:a05:6902:620f:b0:e9b:cde2:488a with SMTP id 3f1490d57ef6-ea3ca61ef1bmr1683724276.3.1757567992955;
        Wed, 10 Sep 2025 22:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6cyV0p9RfbviDB2oY/yO1Hs62FJqZs6KAYcEEH2omRhA==
Received: by 2002:a25:2d0e:0:b0:e95:31c9:43bb with SMTP id 3f1490d57ef6-ea3ccb5f7c7ls149814276.1.-pod-prod-00-us;
 Wed, 10 Sep 2025 22:19:52 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXj3mj53wRrihridWs7b/r6rQnH8Ph38vpL0PDX1X5DKwqF2+Az6v1yJOFUbsve+PJzD4MneAgLd/U=@googlegroups.com
X-Received: by 2002:a05:6902:1586:b0:ea3:bfe8:d03e with SMTP id 3f1490d57ef6-ea3ca68809fmr1996101276.20.1757567992115;
        Wed, 10 Sep 2025 22:19:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757567992; cv=pass;
        d=google.com; s=arc-20240605;
        b=LivrkOGz2WYSfIPNjxsnSrvUzYrd5kZ77Ih60thfJFWXeTLzogMMnySkyvpvVYfv+v
         hx8CP1DcdRxbs2kp+UsZhMYdtEcXtRVIHMHrFQZBB7/jCfbpPy1u/7PpWIPrGMnfQwWg
         Mc7T/eZXJGH1snEVKRXHNMvrNYKAza29Sc41y9Ym1vJldJCkn9iV+XlnvWvtM+ZhpHuJ
         ZCta84fKo+f3VMRnpED34d21CvGtJDOU7CCFzuex93Z03O53qr/frhba2kVo3rA0BAPy
         8NS5QSbUe/22VqeH6qs4wr7z6lpjmXLKvFWX08+2ISG1Eddu/CZvd7/+h2JBb1H788uj
         ga6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=A69CJvin89ss56BnO21FlNR7rbDjsZWpO436mBwbtgs=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=ii+TQUWbehPuMG2n+GwmyTVvEtWYlHn96T3D1ftW12X9xP8hl9t9KsUOSkaxTTOTwV
         eLm7Gra9H3lWpgNr3o7TcXf1DLWxjTdsI7uOYR4+bnlpmNPrViirlcKxu3zmj1WqE9gb
         4dflK84WPlAQpRVxFe6EOX7zhcFYRpfCWqzFoZ6rqA0jOr29j042eksbElVU96829rJy
         ehzeAPK/iPdJLU8MduIuVtVga7dpQBCvhL5eojKBQ6joAOHLHzTyZql+cIIWWo6RPTh1
         WejTCpoc96ARdPphFfvPbXbThZYmojnUmKQSTKI1X/3bdld+bC2f9SnNLS183jiRQ0xG
         natw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="SBf1/pkH";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dTIseU68;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea3cf1ed1d0si21803276.3.2025.09.10.22.19.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 22:19:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58ALfmcS012727;
	Thu, 11 Sep 2025 05:19:36 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921pedjdv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Sep 2025 05:19:36 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58B4oAbj013598;
	Thu, 11 Sep 2025 05:19:35 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010009.outbound.protection.outlook.com [52.101.46.9])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdc51h8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Sep 2025 05:19:35 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Bu4GlzcsznNMICugZr/hkVpg5Fqn8oqQ5CntUC9YYNMDtkOM+A+qmV8KT9agKWptQolRaSleJaPxe2gdWbGa7ankQFc+J8cQxNU2S9v5o/9BBqT7Qy0o6JPSg4HBz3jTR+P9wpvC2mwNcRvHkS4hHXV0x1yeIJ8WIo4PbnQOhWoTiULT4mZQYvP9zKf1XqIEqKtteINqxZ5MvxHxEa5zFzM555b2tWh5qfTqB5onzAtM6bcmYfSXY17e6EhTxWMwVlnY5IN6s8hVVs+b8AhlvhSpSxbraAlZrZkIKodEvRdWtduuGi7DS9QGlFxjtU1JNt3AgGCmjCH7CDiPhprEZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=A69CJvin89ss56BnO21FlNR7rbDjsZWpO436mBwbtgs=;
 b=tEtJC6uZZ+xy3jA/2Ox/gZBJo3SC42TvcQzxRYXrfS5oE6vxUokApYcYavspjhVe1IjKo1qIoFPMT7B0DofbJlFLf2Q3ZiSYyvhUB1UYfogKcgylsV1fiiIO4LaG7I7GdZx0aLW+iCjSYQppOzxL2JD1dA5soJFNH/k1VkQm5pQx7wai0IYsxjquGnvGP58Fery9yICF6ryt04uGOfw8f38OtOZ3QRTYOJ0fjSQnqBwGRPpNR9w7MHIttxBO6ASSInqHPF9y+mNQmA6fZBrCwy24ZORWkWIJuw+lhA+fgNYFdSOd81kTHUU2KloWtfmn2Nj4/i4nHyQm4vmoa+0CBg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6887.namprd10.prod.outlook.com (2603:10b6:8:101::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Thu, 11 Sep
 2025 05:19:30 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Thu, 11 Sep 2025
 05:19:30 +0000
Date: Thu, 11 Sep 2025 06:19:25 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre <reinette.chatre@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 00/16] expand mmap_prepare functionality, port more
 users
Message-ID: <24895019-1473-4b1f-9d5a-8beea30e95b1@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250910143845.7ecfed713e436ed532c93491@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250910143845.7ecfed713e436ed532c93491@linux-foundation.org>
X-ClientProxiedBy: MM0P280CA0063.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:190:8::27) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6887:EE_
X-MS-Office365-Filtering-Correlation-Id: 7c183b87-cc00-4949-62b9-08ddf0f2c8d4
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?fc1QsD/0zrDph1YqLsTL1vA2KUsw/kMBf6PBDlkI3oqLuMsXZziKbx0GgKG0?=
 =?us-ascii?Q?6banCT69aFIpYKAg4QU+LLqkCCX2rsdE50kr79LfIyw8iF3qlQuToPP6tAi7?=
 =?us-ascii?Q?7oxXRwTC8+lg5xucApxvqVvijyijAIepY3rniK63gQTI6FP7Zo0dPUqBqVHa?=
 =?us-ascii?Q?B8KKMf/cBLOa/099wzfi6os666oH2cQAX7MDRHiscM/4492XTrsI8Gpzpl6V?=
 =?us-ascii?Q?n2uJdnsPDTmPnByGUirYNRfuTcnOaWkt/tIxRmfCgPbn3W6A07aHeRV/OrH/?=
 =?us-ascii?Q?vaZOv1bFx/0UQyovPG3FRLB8ObQPINs2IM7Og6vt6aVVoP1oSaUQ3bo/+DBT?=
 =?us-ascii?Q?A5e0QvUk3zpLuOubZgzideSzGVUEnTTR1V9f0LTB0T9OpfpwVBdEFNCBun/A?=
 =?us-ascii?Q?QsY424ND36XJ+/8GGOAYGAlQ4Pbv0p2Sj27hZJA+VdB6rnxsi7rrmruVl0uf?=
 =?us-ascii?Q?mEzuYeNBJtJOK02cZmfFB2MePvvRqg036HGBOgBNWOqjgiveohi0Sg3RZbw/?=
 =?us-ascii?Q?nd3pymqQgyUHGhwm3Ve+08gMKlafgg7+N+m54IudG13rroyTSrOeTYsCG9iJ?=
 =?us-ascii?Q?mHvYzqs0gcuOgaDqVnqDG1NFP8OMysYAyt60G88TjOYmFRG7BMocquhNrVK2?=
 =?us-ascii?Q?E0hSVIdrwWQpjrxe0taZdYW+tQIhA6QNLUNq+nQnjopxR+v3opRjb701IFrN?=
 =?us-ascii?Q?LriqxwRMKak8NZT0rpVIFhj/cUyyIq0HGwsqCYWDFCfxvrIktIEIACH9faEs?=
 =?us-ascii?Q?mX35oRWwHXHkXVbusCZvVZf8uOuhYsksYRlw5KCKXmA68svEi8qnXFqus+f4?=
 =?us-ascii?Q?M7HMZHo6ZVY6EnbB1iiZ9yl1mLlb9pJKF4Oq3RHykzk/g/ae9IL5Ln9na+oQ?=
 =?us-ascii?Q?bcmWgbQJE/FjcUqLzhU9JcU22ivTzwNfpM2GF81xXxqFdqvmzS+C2ZI9oE4l?=
 =?us-ascii?Q?9umHIVJ6lE0SgrJbWf2B1WogXkS8Ug38yYmrI84KAYT3xYAkhwKSIxaTFXDl?=
 =?us-ascii?Q?BjDq/5+a7zL94FSRi7phUXa62xcUi6S4IIe0TyrYE6KErgECB6AgxY5GTeBs?=
 =?us-ascii?Q?QTkpBtE19rz//t+PyVn3Z9QT8vjaIGc7nNmwYy5XgJT4r2G/1dTvJJ6Uw0c4?=
 =?us-ascii?Q?KFh8YWN3Uoh9+YVYcm3OWlOSx9K1oiE3KTPTPdp0OMOrbDbjGlo6VBtpPSXM?=
 =?us-ascii?Q?or8tsCroHIqbPGaPYOV54Mld4Uo6sVQdVkNmIAOwAYrcJMQW5NFpgLPtljyV?=
 =?us-ascii?Q?ZuPldvQ7GQpn6Nj335UfHnhm7hEgA3onBwptjCkfxzxOPzzaPZtGo5UExyaM?=
 =?us-ascii?Q?U9tv0wtnng0i8JAj2NOGfPJytrw7AToC/a/PoEixAlb3LqFiPbBbvYVyUnvv?=
 =?us-ascii?Q?+hJINh1h7h4mfjeJ9SygYrbTbgl6lPe3Io2ioc5xPxyW/65LgOwelbMGGvgd?=
 =?us-ascii?Q?FySQHTWA1tU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?yo75NIICyILrChwQX4rPGs9b9kw/nCLkWDM4lOnHbQg1ZdoalTCNOOArdJWu?=
 =?us-ascii?Q?pm6S/PnfFVeFbHTNHjTOPLqDbUCAwyEsLvMJkOMeW4/6Mg+Sqm7QtjYD8vk4?=
 =?us-ascii?Q?RP65k8+CY1T96T9NBSEqr9PWG7zd8UYIe40mr5mxN2t4pQtOHeLaJmesvt42?=
 =?us-ascii?Q?TcRVsJd/tcufeoKf80j2ESZ2GtExF58U0E6LpLAkcjB99E3JWRKd45/WySho?=
 =?us-ascii?Q?LOrdkfp56PbbcqbQnutUW3zw0mVOx2uC+OcllOtyosIJy/2dq9iDzLbsRbUu?=
 =?us-ascii?Q?FUjyDZ1chWj1SEAKOWAM3zIRsOenlqTlhapUJqASjaudWaHVxxxxlwaQPgk+?=
 =?us-ascii?Q?tkiE876EPC+4TJ4J+iMDn0huADvVkSxsci5Sx22a7Vz00uB0kHyaF1PRj/q0?=
 =?us-ascii?Q?aniKT/A6Zn64MC9JGRQyMQX4UP/Vl5VTtgCsPXJ3sBPd97sqRwSNee20EBXb?=
 =?us-ascii?Q?MhOcFVA7CI2nqNRwkFjPL+X69+FVtTocQnO/AeIvTSdHDCCRI/gi1FbDiTSR?=
 =?us-ascii?Q?8XG11Ua7qvYzQagvvS5u/gCmmw+Qua8SZtGOjZYLZjG8dqoHvMnIEvqv1Sxc?=
 =?us-ascii?Q?YdNjVKf7YX8THUrsGiG92Y8F20lMRMkykFUXYOGsppKEqRtQcA+QCWv12Rwh?=
 =?us-ascii?Q?QkC9NUPiysMNLiD1UQkyYPMDgB11GQxmZ/BloGavRMrYjgI1ncRmENHRhHTx?=
 =?us-ascii?Q?L01XaPTPGmrq8UxhQ3qeRfqRkrB/xwUpNd0aCvG4Zwqu0GKEcoSmXF6IyNCi?=
 =?us-ascii?Q?MroPKy+8HBB62xacLSFMikByfouQn8PbRmpDs6mH+BaO5/VAs/KYBqa3RKB0?=
 =?us-ascii?Q?b4PcYxWj1L2RP5Wt6KV3LRtE2Jf04sYW6PuL1KaN+5lbsD4E+LtYerdPkw4G?=
 =?us-ascii?Q?yLvUsMaKA41V2Yd8rBwYPfmicZzi4NRXiLgixSAnU2Yc/mPKcntX/vJk0r3n?=
 =?us-ascii?Q?U0s5j9fP1zhTlWLfp2K+3mBAVwXJKv05usoWo67xwzXoyxMVLP9Ww8rkwz+v?=
 =?us-ascii?Q?WiHjxJAWDiSemB2AdJZHmB7QDvG/hYizaDuRqoamebCHEXozjwLNrfHBJyG/?=
 =?us-ascii?Q?wlH6DBfmsgovCHzL56oWvTAeGLAM9ZoKCTgcEB5xUOOZWqJRHsLtULmA7QOp?=
 =?us-ascii?Q?NKm6EhRDHvKaUw7fDClOuvMR6jtWh7jxTvvJycBv4Z8tsqTx53rr1KWTq04b?=
 =?us-ascii?Q?Br/ljSHuB3wdvDlsuymrTna/nh1/AdHq1fYKd4Vbl+qN8s70gLyZw6bmWf7T?=
 =?us-ascii?Q?CKH6DHP3fU71WD9Bgw2HR4iWyt/qNG0O6B+99rXnsjeqHB7j2tmhA4Uqxgms?=
 =?us-ascii?Q?agFn07phhNCW2qLL+xAky3Ww6p+UmwZ8ieivjgwTtCMb+SwxTvjvrcEDsbZp?=
 =?us-ascii?Q?Rkq6amPirbg+CeBjb7mKYfWunlV07qmgqtXH/zvhbz0AlhvcxYRzCg8sz/SJ?=
 =?us-ascii?Q?5QWXxaUXaR4W79w8tgkzHEt8Woowdl0BPlwvVJ/DgF02KTGHPXsfoWLuPaUG?=
 =?us-ascii?Q?CCA1KVwFwQ6+/tsW5xQGD8FXVCl/klTPBX8pLhUUdR501Wa1KKf0CyRFtuIM?=
 =?us-ascii?Q?MO/NuBe7eaLLV1LZAGyrMUmbSV0QSVPdwQcSfNYjFhhQRllLeprICtzpeAEq?=
 =?us-ascii?Q?7g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: D9kOkDIo1oE9u6YmHE+fAoSa5aRi473jv2CfBofcth045WgCgBHfBIS7Q32PX1XuCM53I2bmE64i4xuSUUTkjoMAAYZBbumjyGRgn4XUzeJO9e73iiRBb2BUzm6q+hDT+VKP1Qs+acX5jm0CijkboifVNua5gMZJB0rp85s2HC2MeCZsN3ZxQ+ckcpZlN6JYwWqyKjGgg8+kB2A1aivNP0tNvUIHFw2/JoHeWdX4Ryyqi8CL0p4h4iJB0ekQebfWw2qxQOwCpsVw9U0BwV4ZobaqBh3EFiZEPp0X7uXzuJoe6BiDibCtZVLm1zSntXbU61+bnPj6Ud7C/jHTX2CQJeZMR4t9jZV4HMy9bam29nJh83xzXYzgiol2JibuNpLCjtceegCGy3uZ2EAdnbwJKIL+vDMdVDmmvaA2FtOWuAn2ss8YypXqvb11SNUHDeo05rY25bljRj+JIOvoHsI/FVGckDtiGfRri+lPG7D4sp+DbjLZRrOA0MC/wHfrmXPhRWlVZZN7ryFWmPGWusI/f+eHZ2Y/bc9t5Rsc4i2vcaPuEEC1/UvaQ0lbEpPiAKJn1BxmIg8bHHFAgi5Yba8wSiIHd47cEByET5GrCcH/CSs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7c183b87-cc00-4949-62b9-08ddf0f2c8d4
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Sep 2025 05:19:29.9374
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YVvhidX+uyD7Hg/IKDJgeYkE43ZJ5F6DbG7GhE9NF85ONHmuJ+ooKiebTFh9NpEcmRAUHtQ7RwV7ZHIpDPMVHsLJ54VrcojfGELuioIQ1iI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6887
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 mlxscore=0
 mlxlogscore=999 adultscore=0 phishscore=0 bulkscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509110044
X-Proofpoint-GUID: m6YDAT3BmsaEaJpX_6PXdDXsx2T_2Tub
X-Proofpoint-ORIG-GUID: m6YDAT3BmsaEaJpX_6PXdDXsx2T_2Tub
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MiBTYWx0ZWRfX63LuJPUYbDLs
 7my/hVAxzmqy7ov23GEIFp+rf6jTTmEzKTi93pO8yf8KrMP49qKNRyUneKJqj6BSDD2eB6xqaE5
 lIvA4nGJjcNNFJS2oZ8HJW5XV7838dhjeOJDOhupIda5iOoIfMym+zTr9vkOqstBgqBVyqOBpDy
 UsKwnEAV0lBs3umV2fiS7OV3yGm4rXOMhrRr06h8byGD1PGA6/1QBNnHu4SdMz5m8CQVXJY+D8c
 Dpn6uTbqnSbFz+OeWiA5mobfgpPmFRSJ/622R9Y2cTJMcN4Gh1+pl+JiY5ihP5nxgCVLSPbc+17
 /lgH/Py8eFejxv/hK6IWoztHD46o7Hz9fiSzeccaHvVONJU6YiQxXkwUug69mO8A4JHawFvGc7o
 clvfHGtt
X-Authority-Analysis: v=2.4 cv=b9Oy4sGx c=1 sm=1 tr=0 ts=68c25be8 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=SkEDMBO3KR2y4re9wX8A:9
 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="SBf1/pkH";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=dTIseU68;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Sep 10, 2025 at 02:38:45PM -0700, Andrew Morton wrote:
> On Wed, 10 Sep 2025 21:21:55 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:
>
> > Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
> > callback"), The f_op->mmap hook has been deprecated in favour of
> > f_op->mmap_prepare.
> >
> > This was introduced in order to make it possible for us to eventually
> > eliminate the f_op->mmap hook which is highly problematic as it allows
> > drivers and filesystems raw access to a VMA which is not yet correctly
> > initialised.
> >
> > This hook also introduced complexity for the memory mapping operation, as
> > we must correctly unwind what we do should an error arises.
> >
> > Overall this interface being so open has caused significant problems for
> > us, including security issues, it is important for us to simply eliminate
> > this as a source of problems.
> >
> > Therefore this series continues what was established by extending the
> > functionality further to permit more drivers and filesystems to use
> > mmap_prepare.
>
> Cool, I'll add this to mm-new but I'll suppress the usual emails.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/24895019-1473-4b1f-9d5a-8beea30e95b1%40lucifer.local.
