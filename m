Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPWLWPDAMGQE6ACYIIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 108CAB87E43
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:10:25 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3234811cab3sf1752290a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 22:10:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758258623; cv=pass;
        d=google.com; s=arc-20240605;
        b=h/0AOliZKQ61VjWjOpz0oMuPCPLI0AoPghRrgtwuSmZqnmzc1GRWF7p9n0P4s4jFbd
         /v3a0qlfClgK6cRWNr2cAwARCfx21D81QDox8gXETzsyW+X/LWKOyo/IOdATYtXVaX00
         JD+Q09jbSJypp782tmYOuwb9hr5lzGXiTeXE4XtlkhFUzZ1fiEPabeVnGEwfykhprKrB
         tUh+OwlLtEhKWc95G9ODRFzoM9aBXygL+cTMOupd/BeN9PvUWf51xa9lr3c9kTcQJyte
         RgstjC5XbkGhwOGR13ShraBnmOIbUzDy+Bnx4+6WEGag96XAhd6D9FVbIe3StcR94Zyv
         KYGw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=azXpPHqNdmlMlcDDLwEXIntvKBvBYaGf8rUSObW715Y=;
        fh=kMLvpbyuy6SVL/LnW9Pxc15Sx6ezZWdGk4HdDVi9MWc=;
        b=YIal3eDGGgduRY0XZ3Hvr7y+iYJo7KTH8GRQFO8HnNFZI3qLzBBR7qWPGOTHiy9gfo
         zGKpZ1J2hcLDhRK0xoExNpNOeaGIIjYM1tejD/4wQxKA76cNxuJpqAvdbGPwzZiF2v/6
         AsgoICGE/TRFrBidCboFJi1R6LHRWn1fxeYA/KVeGho/mV6VjlCx1NrEFC9pSxzz6b3N
         HyGPbZKoZNh9kw1RQyFJ6XYd1wNx9DRiCaeGBHnxlJQmFeWXCK3FmnSgAlZpCWASbc5a
         KdoroSnEVMekmyVqxqo5nkFLf1XtyUOwnnoqRfjcIb66L1G/Pvp2SUA8cPNtfTyB+gRg
         SOng==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rlXXHpSP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=PjDVnyqJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758258623; x=1758863423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=azXpPHqNdmlMlcDDLwEXIntvKBvBYaGf8rUSObW715Y=;
        b=C7nrvxg/zx/dIantsDjaT8KXpB1Cu1AzebVg7UuF/k8dSckvOxP/hAwna+whZt0HJv
         aSpnygH1Ru7reOxshenV+O1ebWxxrBZDoTYznX/ztWn+PNsFEWFd7bct7fSamVHYcdLB
         asTOecpUPhFAZtMzqMtXNejTmUr7oJCEaEbQ+aUgrtN5occHXyg9WXcustSbP364PXyX
         QurXljb69Dw39QyEQRuLpilS7ED3NwMcS6bD716snldzhOEXPdP7HAaSY0CGNJJtfNd1
         ylJh8R10ZYg1zXKaD7mxbSau7EW19ydQLQ33oKpm7BbWbJCfc7ThM1twjPRtvu2K/Ryq
         Ll3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758258623; x=1758863423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=azXpPHqNdmlMlcDDLwEXIntvKBvBYaGf8rUSObW715Y=;
        b=RHFnHJ5Dy7rA+U594xYlA7llZrOLxzGCMQGNv4YRovREfLGb1dz5M8y8o0TEBJvfpX
         S0xzq9vhgcqaRHdqqCC/16GM6SV9TqtuA7Fea4jkWWghP903BubeoJJdNe8HzULXtJic
         MjH/KedgwOVAJtv2AA2tDPM250PAh2ZVVt8f1SZGh4cKIvK/WWWYB1GIS66UcdiDgX71
         M+FxgfigDvGaZwcdrO9mBUYVzOs/zZ8w3G6D0XZmEMIdWKZZckbHIhDPWwVSFPq5bepr
         yUYI4IT3uABtSHCb2cicMBnPBGlEyo+3Sh1qjgm0cziIXE1hoDuQeXW3oKMp7kZwp9Sy
         1oSw==
X-Forwarded-Encrypted: i=3; AJvYcCXMdgaOAO7WWZgndg5wdTrWwavV22oaXdluJvqZs44qIrPanIak1mIBQO/grfxv8MWzTBjk5Q==@lfdr.de
X-Gm-Message-State: AOJu0YzPAFkx3HiQ0+66cezXD/l383sI/jmcM4QxhwO/717n0ciSEdYS
	wCtuF8SfNsm7KnDx19NrrZofxgmaD6SwTM129j1uftDpvw9fyJoMyOcd
X-Google-Smtp-Source: AGHT+IEz0YnhBfPXqhX0HoW+PkaBKbVCM6uFdbu4poFFlwNaRzKhqCCtxypkpleh0vuWKS413mVvWA==
X-Received: by 2002:a17:90b:1b50:b0:32e:859:c79 with SMTP id 98e67ed59e1d1-33097c2d656mr2778661a91.0.1758258623044;
        Thu, 18 Sep 2025 22:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5DpcYtFkST6hNVNJEzfQmAi2tfE6jahHpZ4WzJ/KQf9A==
Received: by 2002:a05:6a00:8c8:b0:77c:a5b8:1f1e with SMTP id
 d2e1a72fcca58-77d119b6892ls1751697b3a.0.-pod-prod-02-us; Thu, 18 Sep 2025
 22:10:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXqO9T0XAUfgU9lx3DoqX//4PuemqGK/KsXwfXAHE4OsGVFLT/T8XXMdPYS73X0FdcpdzSBYLWABEA=@googlegroups.com
X-Received: by 2002:a05:6a20:5483:b0:24a:b9e:4a61 with SMTP id adf61e73a8af0-2926f4ba3bfmr3252155637.28.1758258621417;
        Thu, 18 Sep 2025 22:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758258621; cv=pass;
        d=google.com; s=arc-20240605;
        b=AvVIPnSF1DEvjw6TiuIAQU9Q2vtBfbtLcl2ji5vEcv7Ixjs5GnJRQxR7agIGnetaI9
         9c5Z54lOaSKpVQBDKXAcB8+qD0678bUMtXBQpykI5xiST8K+e+3mSG5DDgyCfmFJSL8Z
         mMufRqRDPHM7qixrRXwmC2NjFoqIL/LLpehPKI7Uh3PoXcRo+91YcCQslkaa+lDDqxE7
         61LXkPInyqiE29xutlrOGwQs0A1FeKznLKSP0rCgdIpwvkWBnoXm4Ks7e2XU1mJ37n5/
         L0waoAvISTe+wbsqKPlvS6HNKrVk9jlx1MuZRBleY5pY9QeS3PAdAmBV5QmVPQQq4dz5
         kyWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=aWfh/j1hhKwhq2JXagnZPhERwMR1IqTqWOMO9u+TSDg=;
        fh=+CsWjhNySHYzWk0BfcDeKrmFsMNu6Klx9VpAlBuQKbo=;
        b=C1sAyBpSanLjjFHLrHS8yGkeONNcnlzd+UsHb3JqUOuB5ALT3yBz+OyhtbRMR0yKN3
         EhLXan2jaKGxTQdqZSvbZ8e/qTep6q8LBy+D9zSTCu9IzDq4xSrLBsD/M4K9UNqyeapX
         uHHeP2KyQTl5Px11l1ezDKeGzfMGeRm25azea7iZW3lEA4RXuxsOsvQsAXwA3zFzHEd7
         6IWaLAqTlCJsffvHEquNO1Y/uVCqBfB7uEHv4EYry3oNgYHimk5IRaGiKWyDYgw50ebo
         Lk6HSYHwQ1T4hM3Cmd2sPfxTTHCI0wIqWLtYL8ykSnh2eF8OGVNp5isb3DMukvghtL71
         ucgg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rlXXHpSP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=PjDVnyqJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77cfdca08b1si187172b3a.3.2025.09.18.22.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 22:10:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58ILFUSi007018;
	Fri, 19 Sep 2025 05:10:20 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx6mvn9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 19 Sep 2025 05:10:20 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58J31PUV035255;
	Fri, 19 Sep 2025 05:10:19 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010068.outbound.protection.outlook.com [52.101.46.68])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2pbsm7-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 19 Sep 2025 05:10:19 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=lJjhttsveew9lXZV5CERZ+KffX5FMz9cQxyAJdiTOUDwowCZrmDEpkpvxMmh679Ea0x5yiYeUrRCky6xYyZ3ZgSW1rhs0rLjTEArpMeoy64pmoJFvTXkFFT0uUKNZJq8g41N5Rm4QxZXXi1hft9zrDDwvbm3nqI3domzeXaiHyDRye28Ds+a6C5LMc8SNuSkgfzxJhkUH1H820695Jr9/irl6P2+NToqbxiageeat8eDHTJaKklxanNWsTL5ZmOue5JUe3qHJVdlFsFCTHKre9jXjL6EzSnxj4+bNDG9EiF34OxEdmiES9SYyq9lxCXMTQxQu2Akzjb3Cl/KpX7vfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aWfh/j1hhKwhq2JXagnZPhERwMR1IqTqWOMO9u+TSDg=;
 b=tvCdkN2gh+bpnVJ7QrlAhrOwEfglOnmfBLIVbIxX5BvepvBPKm5OBye5tBBWssMG0xzzcWF3M1ocvgQN02S33GKaf7RwbXrE1So2sH6/dmUL49o3c9VtyHjmMGsA9LDN/jjdxZ/Ma0568Ng5Nq11vveVDDuD22NsqucNOBlpKsR7131uwCak8U5YdyLC/ijppwbNCcH/xWNpMjg14HCJVp8RbaAu8gUYfifwj534Xju8jBGib3pMdObLZHbBg1jL4igCAwzYPkmfvGGR++cW/lA0dvx3kWb/pgKQHtMzGDRU3V75CrTC91iRcsCePcBAL0vltdkjlaogpf0AxWfCFQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by MN2PR10MB4333.namprd10.prod.outlook.com (2603:10b6:208:199::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Fri, 19 Sep
 2025 05:10:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Fri, 19 Sep 2025
 05:10:14 +0000
Date: Fri, 19 Sep 2025 06:10:12 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Chris Mason <clm@meta.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
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
Subject: Re: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Message-ID: <17bef9e0-575f-4ced-9884-3fd5a8f77067@lucifer.local>
References: <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250918194556.3814405-1-clm@meta.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250918194556.3814405-1-clm@meta.com>
X-ClientProxiedBy: LO4P123CA0685.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:37b::8) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|MN2PR10MB4333:EE_
X-MS-Office365-Filtering-Correlation-Id: 337628fc-9ef8-4431-b493-08ddf73ad134
X-LD-Processed: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/iIi/0qLwcmovAoZZ/f8BF+lliI56VQnYyS90qR/hr+tVloEtE3A0lTZE1IA?=
 =?us-ascii?Q?gT+ZKE6NJd7aj98zmGkYdlbsgOsnTT81qrE4blzLG10pYSzd2fkmqtndzLXu?=
 =?us-ascii?Q?nXHZ5gRBCoz+Too/mu2wsS6JISlt1Owq7LjYZU9I9t4GNZ8EKty7sku+L5dK?=
 =?us-ascii?Q?eoRXkqrl5aR54NpYcTlLW8EEHtB+sLmSDlT5izosJh30gP8wQab29G/F9hv9?=
 =?us-ascii?Q?n33ex8Pvnvo08vM5f/jG7L+9kpQ3KadJKs1aisu7oHDGx2UXp65vgCZv0XxG?=
 =?us-ascii?Q?GPcN8OsLWzLluUGVFQWjsA7QFfKLudC8H2NJ+uKiN/HQr+hVrrm6ic9vEb3s?=
 =?us-ascii?Q?IhqLrEBsoyrYMAFAIQG/ZUneMldSSZYHOf1aqSTMuB0AwHMtQg+heSwZBJxY?=
 =?us-ascii?Q?c6jKQd26FDfJiuRNlk3WyRLlKdlVzQ3eEtS8i2iiaVjHbOw2LSPtNIsTwrRU?=
 =?us-ascii?Q?u3BNFKBZrrzTCds6dUKRv11IbHf5cQV+HAU20OEtuVafv1ZrR0ky+jU3ccbz?=
 =?us-ascii?Q?/0/eHaJ7/fAO2bbuv/ZPyqnzWvgWoPZ/AEib6U5mqINrGYmTJRfTX/ujfV1T?=
 =?us-ascii?Q?6ri2JtcEejZkEqzTUsPeLVS10REhAKD3kpbJyuVWQRh2FyBYULMFlwb8uV7C?=
 =?us-ascii?Q?qo+2GE0tooytm6nLPOZBTxtqQYSgTJ217KffhxAwIuBn8TAxDonMuRliOm+W?=
 =?us-ascii?Q?KSM6ryOI0joaBmlUEFx/jdBdMQCs8EU4WOzRTofU7OShmCwqkxKBFOTmq6OG?=
 =?us-ascii?Q?kGANaUbQDCI4e0cEmYIYUqgc6BaRCQaPlKUAdyMS4q7SZLKUdYqFuMWDpPBM?=
 =?us-ascii?Q?dbHigjGqkAbwIA+HTmyBcgbaGwRC8xO+m+GA7wOOWQ9f9exb8nIukenZ93UC?=
 =?us-ascii?Q?9M0Ar/ODq9/iK1hNjOU227C3E3PAry+E6aP79tY1nXGLWKjpS3hFnxeANhoe?=
 =?us-ascii?Q?nyGy9zdnUIG1/4Pe7nq5XcuPc++LMtuut7PNbr50KsyP9NNytWn/C8MstnOB?=
 =?us-ascii?Q?amFTWtvsuO7Xw9hKZMFl1AjJY+k+citmyEKXwRxt+0JXajYgM2RQ4myN0MF9?=
 =?us-ascii?Q?BANXtFLkE0N4FIXCK6gtNSjj3L7dUFsZcF//NVowH+MEtsJb88/eTlXKnmWu?=
 =?us-ascii?Q?VUJSrdJ2fh1eojMv/OkOg8uzZ+cn/x8tHcjMvheX10TVJjjpP+VstrZgTAMj?=
 =?us-ascii?Q?zK7cV8qi1HmMadqNM5cXKdXphn9eG6xuuesxB/ZtrxQiwfx+/W13nDpvc135?=
 =?us-ascii?Q?I+ZiBaOYZdjzf+iie4LqYGvDEKH4zZeFdMJ/RosSX5i4SqDW//mKshMC4pBh?=
 =?us-ascii?Q?ZZaMMzmLdxUzs9iW4rbIuFU5OgiMZL+YLoTuz8XwnJ0z37DlY3ZJjbdls99l?=
 =?us-ascii?Q?q3+kDOQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Usb3VIbr3ciiLKdOpT5HNGN9rHkXtBIE+07S66RxDIaHixPCqV7r1hnOcggp?=
 =?us-ascii?Q?21nMfOdf+tMnJiqiB2j1N3gX1dAc8V4HyVmCXbqJs7eTKm3YZ+1gylFkWXCS?=
 =?us-ascii?Q?2niko9Cd+O2IFXXDR0wnoPkZCncB/HM0bOE9ozMyLR/zFO/31YaHJRbxsWB2?=
 =?us-ascii?Q?jY9a0rPCvvOR6sF2pNexGc7Dw8vHbWqswyUkDTkyAZbG7caV5bfOKMqK4jL0?=
 =?us-ascii?Q?/3XA2IRCF8uEwT5AIb5/qU3QvZ/Jm+kfMqwo5vMmrWx5iwOJlyEbAAMmBzXS?=
 =?us-ascii?Q?KbCcPGqtfbzUsb9kYUFaNfLftt8xWoK75anH50f94NYNioSCgoHGIOm1jcV/?=
 =?us-ascii?Q?Tn9X3aZvAWhDMnlLg0Oh7/CWAi+3rUH1sGOHZkFs8FO+Mxd8zUhppuLV7Stp?=
 =?us-ascii?Q?bEBtpF14yZsqRItJ1BhWoExYY4bmyzO3AsbRZTCuCrfU+YzwiYSCgEy51XnR?=
 =?us-ascii?Q?MEGhyjFbWGahshI7vgkBTpSSLCgwwSEnqiZXo1iuVFP0XVOS6pwLwGUcrNkd?=
 =?us-ascii?Q?0KIFOqpXSQPNePE/JWDI/wq3OtAhqdtOlvFfRoA63JUkQTE2AcwX4iOOMime?=
 =?us-ascii?Q?ibzredJMra+sMqWW+neZx5SqFBKxyokhYpT3jEa0AfKupNukZ5jbNWmjEyTR?=
 =?us-ascii?Q?abUgunrgH9f899eZBBawS/QBW/YuvjviRh1xAxgy18FZBFTEcAoh9jNduhAv?=
 =?us-ascii?Q?MWyQQglmYbtMw8s7zpM+ns1vEoKUwhP4sUZb2sOGiVlg+niTuTbRRIAq8jV1?=
 =?us-ascii?Q?rd40o3m7cdYUhnaZeWqpoI1IZo81QKq8rr7KUlDBeFK4kKm+GlhG1Nfn3Dos?=
 =?us-ascii?Q?m1adKzl+Vbkfb8vLO2tCyv2AoG+2CSyJQ2IPHuiSCoeKBS/G/AeIxBfH+42j?=
 =?us-ascii?Q?xxgzeq9gzS/b3vmNABIROdW2QpeMam1HFogX+/tj/7eEKPzG/ks46Kt+tKE9?=
 =?us-ascii?Q?N3ZS8SAT2XCgs9N4u1/w2KGvIV/rtJ8FycpbVUODof2nZ0rLaeHdp6gk2LeX?=
 =?us-ascii?Q?AIolYGLYMKTqOxK7h4TZX6RAdUcfV2H76lt/KWidCZ0YljJ7BqNYPMdCfMks?=
 =?us-ascii?Q?YKab42BPdHddMBN/+XmO/EHcnNItJZef/U/BxiBVBdXtyXs1LslXGo+tYvN5?=
 =?us-ascii?Q?849qUWu6fQ/YI79X0l9QXnY7Rk/6TFrzD2og3e3fjo0tZn3zdhgR924MCYkf?=
 =?us-ascii?Q?SfIclPZLtRaVL+u26dK9o2Veq6XfSjv/j2oIOYrWAhfzAY6y910361PhIPjm?=
 =?us-ascii?Q?z7LgiKVL+kpX5fORvo9TFvcwoZr/Eo5CqEwdJRGjXszL7Ygsw5B820IdS0wp?=
 =?us-ascii?Q?k8FDlEO1He/gY7r9JJqnqJkQmp4VOIjP8iF1Obsnd8YJg87odUEFIJAKFFrE?=
 =?us-ascii?Q?AZiQtEA5T1ycUI7wmSiz8QShud6VQZ+A5aZEHvgMP9iXpmNag8jI2UQNDrP7?=
 =?us-ascii?Q?cWchCvTAGpnbbNUSuzax8A7k47BxZKtOYcGWvKJK8L9Q4RHc4G9cTKBsJEju?=
 =?us-ascii?Q?qi3r5AbVG/pmrg5MP5ORgPXiINAM1kTlZGE10WJsTRxDfmXL2Vig1k6Y6KQz?=
 =?us-ascii?Q?2uZ1gUIewknJlyCVjd8eMsdJRl2maVkZftJBPHt6iPQEuj8ySMJjnWVdckdF?=
 =?us-ascii?Q?gg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YtCEfLcHvs59JJpIjX0O4QJivziSZkKTQuKsAqt75ECQ6WI/dlQiFiFNxYtkTYIYak+jpOfSDcByUVpiwAKz9gTzROiykMXWp4LxcqjmZQIo5Koc9Hqg5DfRf9lXY6aoLACq5twU5gjtShSxniHELOrijuv63T5hPjM1gD1+hA5dw2fOXHrvMQsED8CStPnmlUS4B8P3kJtjDsEiePmHCkISzc1tJ5gB35A0x8cA5ulQCU+s6vbDzUsVrL5JUby1xeU54i7OXT1osoVWUaMZlNhceSoet21CI/BFQZIlgnPqh3wCLeEIZf9WoFYMN0SuNqAkQGkORweU/96xWsWg8I+KbjQ0ofTTsXG7CzhK2ya0L8UAdtE4WMswHOMeMWha2VF9JdLt2a8a+HmjAvsFl0LILixvJ1TdXxbG5a4WAVqQxiIsWZZFHJve0rtogCSSx0nGYsGiGPTk6YqCiNhOiftqaHyVw+7Tn8KsJMhqEFkH1HH7Hxs3r60cbe1fuxfYAvcKLqfsOfF/qyafgL60hnqV2PeLMyvmKO8cNIdU/EGWuqakIDJ7R5bCJlS3TuDMzHuA9D0/qivBOAbMLrVbraDil4G1PTIgMtTA1r0fa2Y=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 337628fc-9ef8-4431-b493-08ddf73ad134
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Sep 2025 05:10:14.7467
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: XjG8PHHbB+lfNlLNwQKtsMl1VDQeHgG8u8GP78D8w/BGbLVwfEoKYfdVwarR85AxUaezHjZ2F35bBLL/huzp11MCW5fN6DrNzNmU34g3DyU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR10MB4333
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-18_03,2025-09-18_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509190043
X-Authority-Analysis: v=2.4 cv=TqbmhCXh c=1 sm=1 tr=0 ts=68cce5bc b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8
 a=GBp2PlFQoT0y_MyTeIIA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-GUID: ecjYxWYpJXI6zQglAenE4udjMVjWJdW6
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX2hTRdUr0zSms
 9E2JakfBMySOOL0y9aKEGT/w2wli4Yfjmp9W65oo1lZ3Lc5nQv3SHybSGh6HTDD3nk6bMXN8yKe
 /yX2EsC5m9Ypuc7TZbCXMAyMfgtTVrK/BALJyfTBZH9i4GGkus9ilqffCa0Ly68KXIMNf/Sv6Ks
 BireCZN5S5DpjKeCyHSmpZaHpcfgYNiDHN46Y3XNIEujLQxJ+OB4N1JMFWiRroadBqLvhV0Vg8i
 tijuM4iVAd2pCNMobjag6Zy/fnXkCo2D6hNWELo33B7yeTtSepxv2mHPgiSflIeHbUIbnHktjhW
 lELI3Iwng2acZ16u86VUKqiItGThOiVzsUTXhm+m6YI0Fin+x4VC7vTQRB7QtN4lLQSkHi/xJyU
 Dv+pQdGn6ZpcGPX4JerFg397u1qL1A==
X-Proofpoint-ORIG-GUID: ecjYxWYpJXI6zQglAenE4udjMVjWJdW6
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=rlXXHpSP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=PjDVnyqJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Sep 18, 2025 at 12:45:38PM -0700, Chris Mason wrote:
> On Wed, 10 Sep 2025 21:22:11 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:
>
> > We can use the mmap insert pages functionality provided for use in
> > mmap_prepare to insert the kcov pages as required.
> >
> > This does necessitate an allocation, but since it's in the mmap path this
> > doesn't seem egregious. The allocation/freeing of the pages array is
> > handled automatically by vma_desc_set_mixedmap_pages() and the mapping
> > logic.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
> >  kernel/kcov.c | 42 ++++++++++++++++++++++++++----------------
> >  1 file changed, 26 insertions(+), 16 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index 1d85597057e1..2bcf403e5f6f 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -484,31 +484,41 @@ void kcov_task_exit(struct task_struct *t)
> >  	kcov_put(kcov);
> >  }
> >
> > -static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
> > +static int kcov_mmap_error(int err)
> > +{
> > +	pr_warn_once("kcov: vm_insert_page() failed\n");
> > +	return err;
> > +}
> > +
> > +static int kcov_mmap_prepare(struct vm_area_desc *desc)
> >  {
> >  	int res = 0;
> > -	struct kcov *kcov = vma->vm_file->private_data;
> > -	unsigned long size, off;
> > -	struct page *page;
> > +	struct kcov *kcov = desc->file->private_data;
> > +	unsigned long size, nr_pages, i;
> > +	struct page **pages;
> >  	unsigned long flags;
> >
> >  	spin_lock_irqsave(&kcov->lock, flags);
> >  	size = kcov->size * sizeof(unsigned long);
> > -	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> > -	    vma->vm_end - vma->vm_start != size) {
> > +	if (kcov->area == NULL || desc->pgoff != 0 ||
> > +	    vma_desc_size(desc) != size) {
> >  		res = -EINVAL;
> >  		goto exit;
> >  	}
> >  	spin_unlock_irqrestore(&kcov->lock, flags);
> > -	vm_flags_set(vma, VM_DONTEXPAND);
> > -	for (off = 0; off < size; off += PAGE_SIZE) {
> > -		page = vmalloc_to_page(kcov->area + off);
> > -		res = vm_insert_page(vma, vma->vm_start + off, page);
> > -		if (res) {
> > -			pr_warn_once("kcov: vm_insert_page() failed\n");
> > -			return res;
> > -		}
> > -	}
> > +
> > +	desc->vm_flags |= VM_DONTEXPAND;
> > +	nr_pages = size >> PAGE_SHIFT;
> > +
> > +	pages = mmap_action_mixedmap_pages(&desc->action, desc->start,
> > +					   nr_pages);
>
> Hi Lorenzo,
>
> Not sure if it belongs here before the EINVAL tests, but it looks like
> kcov->size doesn't have any page alignment.  I think size could be
> 4000 bytes other unaligned values, so nr_pages should round up.

Thanks, you may well be right, but but this series has been respun and I no
longer touch kcov. :)

Am at v4 now -
https://lore.kernel.org/linux-mm/cover.1758135681.git.lorenzo.stoakes@oracle.com/
- apologies for the quick turnaround but going to kernel recipes soon and then
on vacation so wanted to get this wrapped up!

>
> -chris

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/17bef9e0-575f-4ced-9884-3fd5a8f77067%40lucifer.local.
