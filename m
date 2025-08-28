Return-Path: <kasan-dev+bncBD6LBUWO5UMBBW6HYHCQMGQEOZVVB3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4275DB3A076
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:12:45 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-327642d9c82sf1164985a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:12:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756390364; cv=pass;
        d=google.com; s=arc-20240605;
        b=MPyHhjjxz1vDbx3OtrZ8dY97iwYS3tzpga/6LilBow8LBBfqL0Rz3+LHDjaDnPTkps
         m6RwWG9SOqdufy0IiRL2LMGf0BGtwU3WvJGm3FNwM8Mo3vZg0UXeJ8NozyyG3S6sbAbk
         lJ/GdHFZALR8gt2gfSi2z/xk8nAsjE2SC33YpQwO6xIIu13yLEqZw6zAOt6USWhAK6VW
         HAMJBGk7fGBFU3QnRUPpX1ZtxGeupH+XTsvoYfIgidq6ngPUV9X617CNlMHB3oI1Nx3z
         wgJTULAZxVHCL/GZbdm2LFBcZNMkw+WpjIG7a9Bv++ggiVyRrATjmEMnPBS3CtMhWLf2
         3IJg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8pW13BHK65XK2sK46Xy12PhwDeowyPYGHcgihzWz0Kw=;
        fh=KoQO122jOoKQDc9DecQA2Sx4OdpQwzxxpme1QrRZZ94=;
        b=DbXfdseZhTTZwRxs2j+kGC2GODsAbbPUwX1r/47m5S08qzUQPm6YlenNpxYSZr4WBS
         KknNP4FqwY58JIvLKTuCw1BMq3stA2G0X+AIodeny9gCA3o6/2O4SWFGNz5MJpmSyyBM
         +0nq0oRVePLPXLAOgot9FhwUtuJmsaE4fJlHXCF88gF/DNsUoKk+p1lifRjsHKVeNw1o
         FsUKP9R2TIKmK9FyxNUytY4ed/o+eFaFa4RLgqKOHrFwzS0nawaKMB9q91MXfwPEKsKK
         ie4Hv6FoeOf2mSoV0OEUdgT4/aCgKGV6AjSSNUqrnuN3Zw7pMtApeh3sT71dsFSQfk0Q
         vlIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=NFJYpWID;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bFpbLBoJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756390364; x=1756995164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8pW13BHK65XK2sK46Xy12PhwDeowyPYGHcgihzWz0Kw=;
        b=U5Ojk9HfzK3b8TqdbLK7wmjWo90pS+WiKqaqIdj04O/c3xm4txkdBQQI8OxKrvS3EK
         BXSOcPEXT5eyjunhvEiP+JMVuwelPqsxh3yzT+F1qOC6hY/KlxO6GCFyT1VxpKltWAHJ
         sWjqCuaKDOeFA+iw4H6HsiYMJQMvmvElhumbqYr6oDPlkgK51KjVdrbmrHL3v3sdj0en
         4IdLtA+lbWhl15xlxbSm+6LrQcXTMpmEyDCSp04U/c+CmFu3ZMmTR/7FFzDhaK/lfTRC
         fvF0vn9jLq1VhxiZuuxeJz2OWjpdIFRj9Zvyoozw6ZzQnabLbuSFW6x5/12W9s14jMsG
         8ukw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756390364; x=1756995164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8pW13BHK65XK2sK46Xy12PhwDeowyPYGHcgihzWz0Kw=;
        b=C9Sv5d3gXZ1LeuRr3JttGkSDd9dzRPAbAQa3TrI1reFH74dVXd8+iHCZGUxSbX84vX
         KKPUVTMRm8gj3x+8NfdehJPsK0SRrgQuKljNeP0+hnGJMONCHgt6HN8hCYs7XiuC4k/l
         aNj6ZbeJWGpDSXct8Pw3B4Dcb6aN06GcSROejceOeIgqTELCRcV4w+VKhR3KBFgDdeP6
         z1Vq3rqgjYDjD5ROhP+kSbtdKwW6QdwraQWlFyTibDNnCKNXpFTL8ZpW2aj2hI44tEFd
         mql34MxgFr7hepagl21SUW5ub30IUXH+goDzEUG9EcNzu2vnC2WzqxT2V0/ursHo8Na/
         /XBA==
X-Forwarded-Encrypted: i=3; AJvYcCUDqFUTVVneFYnQ140Gbsn/w03QyXrErE9twDCV8BEup/GAfV9xlRko/SyMPUDyL3Uv8YoBFA==@lfdr.de
X-Gm-Message-State: AOJu0YziwYAp1viNztR5b7F8fn7ROn24PDNIX94ncA71d/SVopygTmzf
	JByyVJfuXWra3g+G1IDLdzN1oCTPSRdHn+TqQ6TYbior12IEnnSU05it
X-Google-Smtp-Source: AGHT+IEzhkRCcSNnHZlXRFGpGpONcTWjKlLPlCEM4RwZnxKO0EhdFCPpkn5eeclu4YNHLAJQrqlToQ==
X-Received: by 2002:a17:90b:2ccf:b0:321:1df6:97d3 with SMTP id 98e67ed59e1d1-32515ead940mr30245357a91.4.1756390363627;
        Thu, 28 Aug 2025 07:12:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZddTW4UGlHKrO8BExC8sQHN6xL7vfgvTsprZWvib7zr7w==
Received: by 2002:a05:6a00:9291:b0:736:a84e:944a with SMTP id
 d2e1a72fcca58-77217e557c4ls952763b3a.0.-pod-prod-02-us; Thu, 28 Aug 2025
 07:12:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV6co8wAHkM6+OqgkIM5QZQhszOn5pOW6gx4Z6wYgq4SYl+7tyPlUeOzRXUv1eewWJ/4EZDMzfoXqQ=@googlegroups.com
X-Received: by 2002:a05:6a20:7f90:b0:243:78a:826e with SMTP id adf61e73a8af0-24340e18442mr34750475637.52.1756390362227;
        Thu, 28 Aug 2025 07:12:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756390362; cv=pass;
        d=google.com; s=arc-20240605;
        b=g1tIb1iwJKzBDQ2RpRhPHBt11NaDAJbAWt4qXj+fK+cJPFEpR+VqKF5qGbtHygQ3PO
         3JEJpV+qzb8TRiPrYuyGrjne2m5ZW5FPyH/5YZHN66DWIFfH/U6mvHzi390jp/L/6dbQ
         HwuXlPAtGY9JdyCHLm9vRyHrQJxGpFT8X+gAd1Cu/muTh16B1dPHw5x6mzjhsfH3DL53
         JME+YJy0CLboOlBiyncY7HEMuSKYOFz20f4HcmvyDkaLVPo8I/BnU1lwcwWb8xqtcAyJ
         emidbhRznAUn+JVX7EtzqzQWUALF+zZtvnHBJqes4kRTBiCEZWurxbv3qjdZF2XjhjJP
         w7Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=yOlSoNj7xRkg1LgJGslfqgGpe6Rs7LEYJFOIYyxNVE0=;
        fh=piEpgsTsKfGCdhI9v6vB64Aao9S5uN07nLdyxgPkQ4k=;
        b=L3AcUcQuEavEjDrQMMKVcUCESTgiCuDkkPBgimBUyhKR67Ho5GxCEyXdCcVU1q3wFf
         cqELIMGPRTEJTVyISWzriRMAWecTRdoV+zz6mju+tVT0aXOgfcibp81xn3VL82/0QeaO
         1oGnlUyFW9x08lhDIVcugqbLHuF7pdQaFWPqslg/SZgSWR/dglmygZT4ebn/13oi/75R
         3Omb9F+J1ra34gdtEqoofQVmxDSmJc7puRzvqdeacgtCNs/FaUSOvYz1LRbJdtNTHRu8
         p5OsvU5ajxvw+demI2f3C6VwsuS3ujf69c59saa7cqDA+Dkql+FZUZrToVWUJCVEBXXw
         nnvw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=NFJYpWID;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bFpbLBoJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7720e18466asi55821b3a.3.2025.08.28.07.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 07:12:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SCisK7023288;
	Thu, 28 Aug 2025 14:12:35 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42t8f54-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:12:35 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SD8L13005044;
	Thu, 28 Aug 2025 14:12:34 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12on2073.outbound.protection.outlook.com [40.107.237.73])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48qj8c6ksf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:12:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ykeuGttpnFmGu/W5b1JVe1hUj2dHHO7lYNLTzc/iC/uMRRkFOXs70meWkNq6D6YJnIXpVp58mPa0Caw/nqXHVJfXJ+yRyaJlEqpe3AENLtORMyMcFe5/TaVcDz8y1hioLVtfFr0wqStiwmqLksTfsSgLb+0pqxyzU29vl3lWsKphjVCY3kAoLtCpm4pqow3Z02iGKwyMvyOUYs1fDwoD31Al3q/CjyMcQCwVeAccF43PHHJxJymUI6ywMLYfZ9QWkZAVYOdzE1wFv/YLz2T6hG96LrWe4+E62pnCkHN0nEN1olJn2MpXvt9yMcCnpW2faQ9vXs5rfr2vxwqgkXg4IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yOlSoNj7xRkg1LgJGslfqgGpe6Rs7LEYJFOIYyxNVE0=;
 b=IeQEeRXhmDrp4jISSmi21NKzyDjogHjZhzhjQu3waEJucYZS7+GAn+dBEqF0p+ghTJZnjAtkmi2WCEwBRBeVQjf/xDqq1tVwy86+qxyiwwRYhAQt1/P7sS04SNVsaENAEpkjNTz4hVg4I8OxQSZzKRsQkCOrdH+9jXvQYnD0IXp/bm56ySpRXN1vFnXjpaXf546XhMHvOzzPfpXmZwfiNOjVnfrCY2KwopwVHFAeKQO+fVLGBC5bPeWYtWhwXyU5tveIa7n9gjS8Ut+ErhrH1W9ClD7gsn3B/SeiMIWWmZvKkI2JS+B927lByR2W3LJc6QqyUcdQGgpOP6iqQAoW9w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB5944.namprd10.prod.outlook.com (2603:10b6:8:aa::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.15; Thu, 28 Aug
 2025 14:12:27 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 14:12:27 +0000
Date: Thu, 28 Aug 2025 15:12:18 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>,
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
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 02/36] arm64: Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <504d82f1-65c9-4835-9138-12f605b0aa54@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-3-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-3-david@redhat.com>
X-ClientProxiedBy: LO2P265CA0190.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a::34) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB5944:EE_
X-MS-Office365-Filtering-Correlation-Id: 53586d74-a051-4b1c-2091-08dde63ceaf2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?aVP4dVxTGoBUou3UXuB+T2bTwahiu+PDzdA2poMj1fzqDlbdfAb3I8nL7uva?=
 =?us-ascii?Q?ijYnOcJzZBY/JS8QLxyGHQD07ioo9RaMPhHqozG9Fr7JsCgMrujdKVeT4ITh?=
 =?us-ascii?Q?CA4BoYmQaMJ0OkCZD5gTriypSDLTgYX3t8T+tfaGrDabR0Wqj1o9761G9twL?=
 =?us-ascii?Q?pPiTCDJHtZKPgB/JWY1QT2Omafe/pU/+dVCf2KUacyk63GTh/DwUD9TCL9cS?=
 =?us-ascii?Q?2VKGI+g6EnK/A637Jfx4yNIYGNhbpel7RGgw50CeiDBHJaVNjU4PD4kNoqbO?=
 =?us-ascii?Q?0Ai7Kz8j+jeyCShf915KmS4KCjeWfnfscqWoOy340dxZetRAEWS2OlptEyDG?=
 =?us-ascii?Q?qALWiutlM5dvQR4MDCHZcVyGi8La4xEbCYHzp/aTJgj0SsQAg6ITDSTbZ6hh?=
 =?us-ascii?Q?kTOCSxnh+AZYRQorR2otdm3DPX8ihUm8zgexh/RTaamct5KmnbdHXB7JPgxv?=
 =?us-ascii?Q?6w9dklLuFV4PDRzWryITexhlDM/g1G4+TFKs1slGghYE0RIvYI2MnZx7WFGh?=
 =?us-ascii?Q?Ox4KSWKy4Z1y4fIXtxIIrhGGmsHwwYJ7vRy5TKCIko3dreY4xlMCjwiUVqSQ?=
 =?us-ascii?Q?ZjKwvYpeRXeuLqK3xmQG0VQHWPOqHTKX5A6a3XAsTq3XB6fwydd5fvqHUvGX?=
 =?us-ascii?Q?D9S2zhZa+1zoaXA0A1y9ZIkKXV3ZGnIL8A8ymmS1JCnSq5LU2YUPQk68wGt1?=
 =?us-ascii?Q?HetsDP5pMFmNlDGcTWcHCwAXGDUBtjkAIt4E25B348pbcp8WDECgFDMjbj1O?=
 =?us-ascii?Q?vpGtvAODIkjpVySQ5FDeaIGXdVP8GQ9Tbgmlbs0UHyUbv/LsrU7MZdQ8vKC9?=
 =?us-ascii?Q?Y1omzzYKHUJO8El89iYNRFafM8g59hmGZu6n1ybR6B8QIZn2x1FS/6APZwl8?=
 =?us-ascii?Q?jzoB5BVol+F1BnpjCajtktfZhYTIRD/iyb+fKRWEVBe5/VOiABTnCuDj7xSQ?=
 =?us-ascii?Q?p/r7qPD9kAmZvWf5+YimFfuUK9eWQxyj8nahXfJfFLjHCzszKbA8LYxlhrcj?=
 =?us-ascii?Q?SAA9FIv5xvZPK3DYGcT7kOsslR+PH+m6u9wTcgwGkrizYs9i2REz0UFwIzRj?=
 =?us-ascii?Q?WRdg/V0cOFe4rIrOCMMk2sF5BkHJ7p6V+T5ydpykT1p2SleHU7G7UD35jgSS?=
 =?us-ascii?Q?6F/rJyfAXSGgLt4E9deruetIh8SDCX4G1NI9oNT/kP4yqD4gcrF7JpUhzzc/?=
 =?us-ascii?Q?X/R0n5UQQ5RUrIIuXdpusiRRw1VQ+CkvIbziaoClgfnVf4Shu9SbXMOHa2sT?=
 =?us-ascii?Q?vjAXU+X11GuGeoDRNOdQ0SFSErncWBzIjF4XR2XZSjjqETYoeMouDvZAJoK9?=
 =?us-ascii?Q?72bQ41pQdCx1v+njKqiDMBfuFwdCKzOOrcfV1m3+c2WWZbigg+w96yUpUpCB?=
 =?us-ascii?Q?SX9i+qatUWvA/EqyAoONLwKOiNHh4ET63G+ePiFY8/5aIdttx2zjhaa6qiIC?=
 =?us-ascii?Q?P1CfR7+cuIk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?vC/g5pZAGe457+pv4kgoGS3DDUcoBYLGRjpStDgDMN3NW+2brEP9o/8j17+o?=
 =?us-ascii?Q?+jepdiiYLDIw7jU+BtA91ymdRovtkLBIFksIKJOx8fc2VrhPhgOP0kvbqLzj?=
 =?us-ascii?Q?keulKH8UUGYGyDttg+k6JrvYzRm83dzY+8G7cJnBCAXH0Ow2R2VEnQsZpo8i?=
 =?us-ascii?Q?lZxlSu8o815KF/C6uGx07n1vuAc0dbIX2hqXzQEAC7uiUCFO1EQD2Dm5l0F2?=
 =?us-ascii?Q?eyp2+Tz40GXmhLKyC8tijD5yrNeogCo9RyU7Jpx24k7CHS18MIbPjRYhX4h9?=
 =?us-ascii?Q?2bFTP/gQLq1kL+leo5+QUVsRa+K2U8mvgn9M8AL39iZOAaL79CxCJqams1AV?=
 =?us-ascii?Q?xlqzN89B6D1/QtHFSUN89kXLDUqGSDWFVwhZS0j5mJxdKmyLYFJtx4pDrnYj?=
 =?us-ascii?Q?Ve/hBZCjQktR7E9IS6xJjKv2jGx7CYKbeScVoRUjhlP4ok9N9+AgBJJ/3X9b?=
 =?us-ascii?Q?5A6E59E91zvUhadVgbeisiZlgq/FFG0rQ58YdtrZ87VBf805nyRhxSbMlgN7?=
 =?us-ascii?Q?CdZmKunplrpjUkPPVaIFYE7ufS6k2ZLpOYph9ZwMS7Yu3vMkZGhdypgodDDn?=
 =?us-ascii?Q?FPiLenDBz4fubR3mhxDj7ABobiafuPFNtz3bZIWmKm4HqMg2YMqsRe2O7AzF?=
 =?us-ascii?Q?zcY+qNmYHJl4efyw9L2wiR303kNvmEyrnBVHCoYwVJw42ITrH+XdfygI/8v0?=
 =?us-ascii?Q?MoEQ6ZheQ48UdtC7bMGaPMyMVwMBfA+XFDMLaKx11fe5i7cZKxRMDa6v1Nqd?=
 =?us-ascii?Q?TPyuV6BMqBMv+xvngFwi/8pBczmOjV8GFiPxiUalVnG5fu3yeimTddRUgtDh?=
 =?us-ascii?Q?dir64SWglOineZpSChYef9DsUCBt2jqR4OxJxEJSOO3jS6iYGwaoOQRTdapz?=
 =?us-ascii?Q?rjLDaXyW1qeS+CfyxobN7SaJrlO9bF9WKhbJ4HLZSIG/3SZ3YLj66K4iF2Rt?=
 =?us-ascii?Q?dMgu/c5KZN4bAIUpnbMKcXJoHSv3xvZ7XZDciEY0+5RGg0rZ/jCH6xHDAHF3?=
 =?us-ascii?Q?/5zomXVCHULh3VN1trKaD7VwCPOvBJD5ChK1N+ekWD/5nyNa/DMy/iQyAkTJ?=
 =?us-ascii?Q?TGdv36NA79AmtDXiaNU/kUWvmFluW6U12kxPaDqa7z80kh/4IhKSFojoYSAs?=
 =?us-ascii?Q?qJzhpovPA+r9PFSLYSyM1xjTkjfhjvfJXt3lc11OQ0hFkusx70w3usnUkHPe?=
 =?us-ascii?Q?4k62WETGiUsz3T3UhuCm1Lvot1R+XueTRRiqVykG4wIb3B97jd8lz8bPcjJj?=
 =?us-ascii?Q?NG1hhVeCwSCQRaLO1zMC5TVSyI3Xa0utV4nhfsa77C/q2QXiYcimLEBt3YWW?=
 =?us-ascii?Q?KcfFJdpDJtfm/MNcIBR8KXt1vW/DOTv6RWNafGZgs/Jf3QQNjwNcwYP3LMAI?=
 =?us-ascii?Q?FPSkEVCtCUaSn2Cw9FdxPIrkDvFEOTaje8Io6nIOcg3ktRnP/UKVV/PUoIEI?=
 =?us-ascii?Q?vl8R2jazlnnc2tWxXmdtWXj/oelF2/RpLiKsxa9dhcQpILeZG8wb1HaXGfqP?=
 =?us-ascii?Q?no0cLIIB3y/xEwnRP5P5QIMVvMXe6bFCUbZpCbUMS7xMDYQfWu21yevJk8Mb?=
 =?us-ascii?Q?5yP7ICiql23clemhxgka5oeSJGqggGlKSp19kdBoWfn8sCy37WY17xfpo1bZ?=
 =?us-ascii?Q?lg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: x2VY2myQUdtjdcb1ZCldm9uihI2Ikzs0z8NPY4FlW3C1kq7Pu30sxApzsTZenDKhxlWA1EMS3ZgNy8Xmv4MaVONxi9Q44HxR+XhB4687A7KpSr/eQRTs6aN6mB5TVLdI5lZjTbB5wsNU/r4DFDeMYvugdRBD1btVizq6GSCJJXxn2tf76Um6IoIOS+3MP8BZuCOPY/mZ+7aANPLUR/hS1dGFAT7MFRmue/ZQAYgiCt05UVeSCoco6dWB10aIV0qn28nl6208KYGJtSIt7A04p3B6pg+gVBLA+scx8Z6kFHf65zdA1gP5rkrlyrCX2Q9Q7D88DFR4kWoayuoP7Bw7iFng2GNsRZ7oq+a916dAfOAKT17cvPkpP31Ts2hDVT+TmJBSK0SkGyxXHvwAxawoiRA8r9eTb+TqahTuO9PBxJUmPZyIvoz1CyWsV1tNY78jo6+PDxnYi9vus+JUwoPwD4DkJu4+QX1cGpTDk96X/YyfxYholAyYLHdIsyOPnNC5TSlNlgU1IviP8Z4LtRBfGs5ycUYDOaAAQ/wHrJeWEQ+GGdF0SikfrOMhRZHxtmOGfg2y8lMG2/VXT0opNYvwp0wgsjnfhyeRCR8rsqTznkg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 53586d74-a051-4b1c-2091-08dde63ceaf2
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:12:27.1323
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: riHVoIIBB3o4/tQFuaemJUrSsesTMx9UKRHYXmpe0A5glIp/AfufpBMm/AcdrtrRAIgymf50rCDwf8c9f6+FGGCDwnaXrPsLHudHk7+oEnk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5944
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0 spamscore=0
 phishscore=0 bulkscore=0 mlxscore=0 mlxlogscore=999 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280119
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfX7AzXKf66jc4y
 U+5KTQ6vhy4plpMT+N7vwPUgDZOdRF/MGuR7ccqD5woF7s7U6lBEGg2ICc7vZJWJj0cKG1b4Yvm
 d1iDVRKSUFKb25YErb4LJ9ZJU7gHyBgdtEiTwTnLS7DRmO7tJpz55X8VT8EHxhDzKRv4/cEaYtc
 uv5ti+ew0pjZF+dXispGe4O8JCErkv6NXnksYgnH2DsVBt62V3+bW0oQ1FbhYVZRYD6ofvfQccY
 0q3UkjoMjU6wQdOlF3MiUO3I2NMfDdtgLlX1qoC0cRAVVHLqqJApJM/PhMTfWZRuS4wKlaO63GN
 mZNhrT7pmKi11KT5JlB4FncLpz8Plb3tGZT4nd8lwRRLbYNztHqjaS5sqicxfnaWEiTYw0o4c0R
 L+j7SMFvB2VOJfajyhot6Aa9h2PjFQ==
X-Proofpoint-ORIG-GUID: 6U9M0_3j6NbHR22RLroxER3bErSjvJ59
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b063d3 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=7CQSdrXTAAAA:8
 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=PabHib_kXikMvU6VWLIA:9 a=CjuIK1q_8ugA:10
 a=a-qgeE7W1pNrGK8U0ZQC:22 cc=ntf awl=host:12068
X-Proofpoint-GUID: 6U9M0_3j6NbHR22RLroxER3bErSjvJ59
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=NFJYpWID;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=bFpbLBoJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:06AM +0200, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.

Do you plan to do this for other cases then I guess? Or was this an
outlier? I guess I will see :)

>
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  arch/arm64/Kconfig | 1 -
>  1 file changed, 1 deletion(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index e9bbfacc35a64..b1d1f2ff2493b 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -1570,7 +1570,6 @@ source "kernel/Kconfig.hz"
>  config ARCH_SPARSEMEM_ENABLE
>  	def_bool y
>  	select SPARSEMEM_VMEMMAP_ENABLE
> -	select SPARSEMEM_VMEMMAP
>
>  config HW_PERF_EVENTS
>  	def_bool y
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/504d82f1-65c9-4835-9138-12f605b0aa54%40lucifer.local.
