Return-Path: <kasan-dev+bncBD6LBUWO5UMBBTGEV3DAMGQE3VK762Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D103AB8316F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:10:22 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7779219ccc2sf782534b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:10:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758175821; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZhTKu8AhElGHwwdvNM8EF0p8g004jDVc1AcEGt5CUq231HTLRDFyzSbMppQ+G+VQIF
         +fzPre7/uzHExWPCPeJkpu5WpksGAhYllrd/y9/aFiJcuVSnRLdmH/tdIUqClHLPjCBh
         7eI9lzP0Qp1IGiY8mn2Ob5RirZ1gmgwE+a7DC8jnZkZeXON+ri8w8tzx33ClXeyMYrW2
         4U6TIsFQo0nPqXQ20GR3y2al+YOaXQO2AZ9VATuvQKJgMIY3U0uNDHxuw+utY5zann+Y
         zpeLR+Pi6jp8mhQiySaZfcRQpvJr5Td6Kkk1TnhklSOQ+bjIRPJ59v3SM/WvCwJlRfMV
         wzhg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NYlH7VkHMfFAjOPv0IvPvghjyxUELs3iuMmKj0OA40k=;
        fh=gC3zb9KAmS2OT2fGexPSTgvaWGfkZnwDNS1W/+LWQi8=;
        b=RvQN+4IIVADDjUEpbuYrDl3tV3xklbjox4d1yBrnI0n1cHfdRHSF0Wto57dbYKUMy+
         neJoyHjRfpqNBT9X7MuJ6Ts4y7rC6IfkUJX+xYo4koh055KYPuP/FWwDrQuDC5j8jpUQ
         J1VxuDOCZaAs8iVk/YE5UKqWV58BDKMgADfAXKJJH2tGP1vwvUO9/rEhuiiBT49kJDrq
         SekMzLdpogfS0XdGJHcrUBD2OE7YD4hv+gq2CCPEhCTFE8yOMYXef7dls4K+clecowYQ
         yyeO4ZBY72kOytzeWcyz9SO/fbx4hrBqpx32I9TzejYxb0uN/2eO1AOz2gadqMTkywn8
         7/QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gdPJKKnG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CE+ZZUFw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758175821; x=1758780621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NYlH7VkHMfFAjOPv0IvPvghjyxUELs3iuMmKj0OA40k=;
        b=hgtUtbSC1trMFjk1An8rQnz/e+l5lQIoQQ+egfG6UGRqwN1E5Umiqwzg9uMpQwIdza
         VLHsUDI3hK9xrTzEkM4Z1fAzqNYNN3FfMbxVpAU37exvwg32Lig1I1d1jmcy89bdoJYX
         AS1dulUu5UdMNnrpYoW9CrCONur92NFbcmgjQrJ1pofmaEEiUCUF0AjZDfi2mFP9XIM5
         nO9CZ1bvCe80BuSBjFWfZxU1sY+9DZHvyILInONDnhX0ZVTgxurPggI2kWbyG4zdfAlj
         oCSecq4q//7ldFZkXhuEkTp64l/jisZg6nd/rsaMTU+03WiAr8op7UWx03U1UcIAFScQ
         AoGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758175821; x=1758780621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NYlH7VkHMfFAjOPv0IvPvghjyxUELs3iuMmKj0OA40k=;
        b=NMIobwxnEMYZO4EL261XyaiGltdV8cwJDuZwoiDMqbu9lhrNSr93XscEhX2BussS8a
         /vL+nDfw30TzLaUb5jevNg9zkLBqH2oNMLVrxGjUTqc3Ymc6oneHJLcKCTmfpfD6FtfH
         x/SAL3Vn5kMK/HZftBrRjlFHSKpkKTQ/dy8Kdn0R8ukyMefKLhPgbGj2ULQ6/moHlyYm
         LkRPLGFOLbqkFF66s/Q8tvy1eIQx7YXZHbrdJy1KOc+/9aFEzJSIZm1lRnUwfN4dshmH
         aJfntTLTz54w0wf05nHmF4kMubRBzAhS8yBDW8gJg40EJHdR9DEIUn44JPULhMOEk1PX
         K+PQ==
X-Forwarded-Encrypted: i=3; AJvYcCWdHWL5IfHGkmudyzrHW7KOA0KJ0dWlkML07KX4iop0i/aU2e38yIK6EDugh9Xx4AiLVXZ+wg==@lfdr.de
X-Gm-Message-State: AOJu0YxlNqXCUnHUO8xT2zPh8iCLoOOPPtF7o94612SEqR+D728ht97i
	ye/JVbFvF5r4j8Vh68nRMk35jC2tBbJTUinGZLidXd8Bf2T6hWhYemDj
X-Google-Smtp-Source: AGHT+IGXPfEEI+3jbJqPEqwNv/gyiXcVoG+CdH8ZhMqfOoJkyPD7QDzzoK7cPhejfTpTeMCIp76a2A==
X-Received: by 2002:a05:6a00:2181:b0:77a:a4b:9343 with SMTP id d2e1a72fcca58-77bf907485emr4814965b3a.20.1758175820837;
        Wed, 17 Sep 2025 23:10:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7lKrUuPUKcr5RrqOueoZmGvxWs6WLyO7sU/U/hv8akdw==
Received: by 2002:a05:6a00:8c8:b0:77c:a5b8:1f1e with SMTP id
 d2e1a72fcca58-77d119b6892ls607464b3a.0.-pod-prod-02-us; Wed, 17 Sep 2025
 23:10:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWFB6k2OYUy2u38WhPM/2CTkoEiFDRzWL8lUnLAmVw5NPZjTireQNIIcgPhaxaDyItFMH5sUoX1CME=@googlegroups.com
X-Received: by 2002:a05:6a20:7d9c:b0:246:9192:2775 with SMTP id adf61e73a8af0-27aa85b491amr6889562637.46.1758175819357;
        Wed, 17 Sep 2025 23:10:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758175819; cv=pass;
        d=google.com; s=arc-20240605;
        b=P4JXxZfxbgImNaXE7hOukpumKqJueJh7jz+EVgRYPG3DcMa4d4wjkmjf3a3LmlSW3N
         H1VIXjON63VMxLgMz3MnMFKVqfElxb/E1KktA6UP/ZGSgxC2F82we5IRLg8LhgyO+Ox1
         fnerIpAaJ20REMM1v9T7Duif/3px/HIIZljNhCQAOy/5J1AH2WhoqS4FeqJg2raPw0J8
         aqohKnXoi1Qos+sN97YmbCvoCGFiiDG8YbfUDgeLKB4TmvMy0NgTBuz6YNbL/JJp+qjb
         PbaKe8o3s8d6iL+Wa4ilac5VRoWnQjxa5zf5yw0YQYJADYfUkQMhB7luHK4bp5SVvuGO
         q+yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=8voVqakbKhMst0kGVvkQXgJx+Eb3V/U+OIQSjraWkB8=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=URdvzO/7BmWjmP7oPeF4/M0ebr8z0Qm4u70Ql+NFBIkq+JFIOaYhWRx+t4PR1r0bxl
         MDI172jzAHxKhlzfxfTCyXlqghh9EVoHqd679YkKpLbakylrcyKPiWWTai6GuC3pjH+t
         vtMDrp5FKp0V4UxMSh6BY4x+GZdnsbJnGJ4velhjq46ki16lxgE+pApsyuoeHzshuknH
         oygOhFa374mr6wvccEwEizTI85bEpL6HXdzlPdYX9NdzZbZCACFc7Y7JX8bVXe/W6h0M
         PFVxddUksDEF2IPCH0ZefhZvn6ov9zkcMb+qIq0xV4tb5Nsyh/sCSgQ0g8ykg4XiJtzh
         Rpmg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gdPJKKnG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CE+ZZUFw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ea3bde9e9si222420a91.1.2025.09.17.23.10.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 23:10:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HMqtCf007341;
	Thu, 18 Sep 2025 06:10:08 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx92qdw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 06:10:08 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58I4VPtA001512;
	Thu, 18 Sep 2025 06:10:06 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011066.outbound.protection.outlook.com [52.101.62.66])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2ewanj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 06:10:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Zog1FydjdiIwZl3So4BXJvZTU/DC1hwpuOX5WlTqjIv8rlxsX6ybeLx6MpO3VNG9+GekePmMX4aZRlKU1ClKNfM5zZ4W26tIl9Lpagwsqkgti6q0gb72RK9/4D+ain7fZ+BHwTIbDdd9xPRff9LdjEmHNjEVGTHrEgfTN7V/TEBnlnOhMM+EUsnTEYd4KySw7NS8Jmro0m1Jpe4VrDmZe7wF0Inyvm4R0FuV6n1L7k9PggVCctSgrydRjSk1dUbS8zGc/f1AC3sjEcOSBs2QLTnhY6p6yWdTmOfJ5y0g3rDock943tK+fd4b5A+e4jtl+O5hkLpGDVuPntsiIO0D/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8voVqakbKhMst0kGVvkQXgJx+Eb3V/U+OIQSjraWkB8=;
 b=M0t24630HfW5WQBe0UrJrAzJYbWsdcQQ2nIIfxlPfIJmp3RXnZ4Oc6lBe+kfQ2/kC7gUGVLLfVoMkYQ/U+WbSKJ95r//Lq7OMmpw2ttOU/sgqgpu9fsUqmrqLB2jeYJWon+/lvDTZ/T1ZxOfgfFgn87Pd7SxlhtntenzEzPp1zo45yQYbmH0Bx+ib4J1LJfrIh1ZYeTjR1VSWZ9qnPHBmwPoK3mI/JcBNNWhUiP1lVjwyWq6JA6ZzIo7R1DJ25QOAtubkuK/xGqtMkLUmyJsv5vkFzZPQ2C2v0908Amv21pIOZF4P9iaSG6Bi8V85JmifYgW+/i/Om8rURyN9oopGA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB5199.namprd10.prod.outlook.com (2603:10b6:5:3aa::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Thu, 18 Sep
 2025 06:10:03 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Thu, 18 Sep 2025
 06:10:03 +0000
Date: Thu, 18 Sep 2025 07:09:59 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
        kasan-dev@googlegroups.com, iommu@lists.linux.dev,
        Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
        Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 06/14] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <5d177369-3c0b-4c31-9383-aaa52b7e9185@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <ad9b7ea2744a05d64f7d9928ed261202b7c0fa46.1758135681.git.lorenzo.stoakes@oracle.com>
 <20250917213209.GG1391379@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250917213209.GG1391379@nvidia.com>
X-ClientProxiedBy: LO2P265CA0047.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:61::35) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB5199:EE_
X-MS-Office365-Filtering-Correlation-Id: cb16baee-64ad-4ea8-46dd-08ddf67a0192
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9+PuUUKaxxWaIPphDobBdJXJ4ZYgo0zcVLWBfI1eXLDc96jepc/5GTi32m0Q?=
 =?us-ascii?Q?BswMwj87aXuw1qo0/zQ5orVlQ2zP7oqOUaKWhPvejRynarbrsza3IBNOTdYP?=
 =?us-ascii?Q?j386tWzZYhpGV3NZwPzqnanTfgydgEOPOh+obFarrwX+HB513c8oKUIQzZvp?=
 =?us-ascii?Q?t0O3sxKEY0eatFteO27bRcQZSMuuUgLISXjbEi//QOLZKvhLpHdzs/4dWzCU?=
 =?us-ascii?Q?dtwzXfDs3olkZNNwXHlTUQZh9vCGgO3Cp0JruWeneEBm/PnVqmQLsBEsWO4X?=
 =?us-ascii?Q?kUZyy2TH6FXsLycTL/L+w9DC4Ipa63dSRqcIkP6WRYzE/ALe7FDmg6vS8uMl?=
 =?us-ascii?Q?WoixASrTEVbQ0Y+ECG/Bej8hSC2oMGG6JTReMR0dAjxDFHt/wwljda4Kug86?=
 =?us-ascii?Q?OwAHBfz0bq7qJiOs/tE/nTJUioQ/XIHUSQu49DFiQDRY5zaPw2u9TqNJgScr?=
 =?us-ascii?Q?4LsOlwS42hdF7q+LgXjjMAWy0/eG589cUYnQ4aY67npO6SUuZ23YDumgKkVw?=
 =?us-ascii?Q?MKjxA3rduy3a43dHQ9vx3bojvxOLKmeqDjs+TAQGPg3j8ZGdEuy4p5Bqso1B?=
 =?us-ascii?Q?p2bNTYSSLFbDjYoz6QMDx5yEU+IjDp0khsachNOWeF1sYj5VaczEH5oDrd7c?=
 =?us-ascii?Q?GQOzAwaqZRag1tvExnb5G3XxTYbIBMYylodB8SAzma2+7vPNjrf7KIqzJrgb?=
 =?us-ascii?Q?dK9ix7EbEBgsrWgUTRdEaOD98zcqacA3vm2ZG5a5XjZZlJPL4zdA8+9iiO+i?=
 =?us-ascii?Q?jK+mId9v4Ssz6qL09EM30HQ6vEaoMGU997SlbGv5x5PrqVQ7YIgJ0OHekM/U?=
 =?us-ascii?Q?KKsoTp8kt0AowKk9hj5c8TNq6Rouc1jOAZOkiB4GurqOBsbr3T7jYXaHsQNW?=
 =?us-ascii?Q?BSEDEJezZjhDnnTqoZKmzuBQZdxGDh13xKcB/hE+y3xdBQzRcF6FJYUOqkct?=
 =?us-ascii?Q?OpJ/wdL6BAIVliQ6RVilkcU1N4fE+YLbaW4voRmUNZ1gaePN9Nmw23/cn5aC?=
 =?us-ascii?Q?3TMsEflzoU6jSE8W+rGZEx6QEDqNLglsczvZWMeZoF8/u8nOUGAH39QKlD5O?=
 =?us-ascii?Q?b8nq8yDUsWpigrpuIHCk2sWXRG5IVPPOcNlhRKZunytCybpJdNHPjV/C7hNU?=
 =?us-ascii?Q?iwulf7Q8J2t2ztC3sW1F6t9xGNTUHN5KWFltMcLpawhSbC9ElImtvlLLhFJV?=
 =?us-ascii?Q?8TRjyqbz4Kpp8DGC4xq8Gu1K8qeFplo4BLgZCNkaAoc8zym+UdBxRQHfSNWM?=
 =?us-ascii?Q?EBNHKmMmeGze75Vqc2xEu0qRiXjs3fo8MQY6KmuRMZj/l2Xp4yMMMhjiXtff?=
 =?us-ascii?Q?4uOyQCr2suKzT/StMyLnlwdQTyH5q017L1BXX3tupMAxiaqarVq2k+1yv9rF?=
 =?us-ascii?Q?tInCUS/c8Hi3NfWLrCuW+fNPPI8Zrn5Npq/lk9ONqjvUYPcfRg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?GG21t53Q5RzVqQS44vpVvMwDQFvcrDani/WMQgpDpMyJOVUTg931LrlV6MYh?=
 =?us-ascii?Q?ydQUrUUola5tPgGk27fl0LQlUMfeKv+78kLM7sBU9q6eFVvCKbOLxnjwOzM7?=
 =?us-ascii?Q?Jqf2dw9pQe5kfXqH8lKwQt2i8FxjtFnCusgIwB24IMXKe7RlCHMMCo3VxyPf?=
 =?us-ascii?Q?FK2KIeQYKvqvzBFPautchEYOrqAtHSRzq0nBi6+Af9K50xBQSc41LfQcaQ5x?=
 =?us-ascii?Q?3vzG5FWXE3YTHUAgYqfNj+3gxVSROJVyiqgccqADV7zW6F6spA+5dwnFJ3Kx?=
 =?us-ascii?Q?tTH2O9pIr6Ng/+guhAxUWzusOEazlm0iEGklvL+hMMbiSwlTBxWzdhSEji6Z?=
 =?us-ascii?Q?26Ct9PYPdzeD20ARSLS3hxwJd6jMy01q/h+BSD/CFGPasXW+6ZOeix/91PgT?=
 =?us-ascii?Q?MPpwZJ7telZ32z7Id9QOzT+gXcdJmf0cgK266o35e74GB3R4rz453e8g7lHu?=
 =?us-ascii?Q?LCa8Xhj0T0I3c4A2NzJ+vK/8diWypagtX4m9ukz3X2mrYUSZBFdqUZVfIYvU?=
 =?us-ascii?Q?ZvefMqwDdEcxmiMc6ZhkipBI26Z3YKYQ3o19UZoXM1pJzImxzshfOg+py9Sy?=
 =?us-ascii?Q?AJc3SMgCPxBTlV2g5ZWHaLKwG8vU8YON01GSto6azW/FMGYhwqkUTxxImkg+?=
 =?us-ascii?Q?FKN7HzSRnE2C1Dce4Ip3EiSnnhph2V0SLxob3Pm9+4paWqtfCvidTpEy72mR?=
 =?us-ascii?Q?XHwnBZbuQl7eHBJs97p6Ks7Qd3+4PVhuTHfdcrJZcgi1vMIh7KGdfE1F9IHz?=
 =?us-ascii?Q?Y63HnB9NV8DEt5JcvdCIRs3Lnh0RbWZzyA03ic05PDZNweSPOrYzzahUynqs?=
 =?us-ascii?Q?/CnfO+cFmgahGMxcbCjmHSrGY+IfaBxdphExFIzCdJoBfX2cfgyxxEJZIMs9?=
 =?us-ascii?Q?ZkskFGym+SIsdAGONzIseZZocRWiDWN1FKr21ULAexiLRUChuWIlAIuMryCX?=
 =?us-ascii?Q?G8VX2lBKgY6idqZ8QCMGAd/0Lpa/a+bc6pDKGnIOsanPy0cVAkCSDQr5J9H5?=
 =?us-ascii?Q?VhXtzQTS4MZfcyGNw8x8woA0Nd/WN25zyOXaCcvu61R+rEDmk6O0bF3FsrJh?=
 =?us-ascii?Q?eBsKHmmV/88to0raxmQjteTYpwp7dWgUVQlzHZNf1+b8s09RDlKRtTY9dksu?=
 =?us-ascii?Q?v6a0HV0sw71wbYguFWTRrAXs+Kfn1yaTwKyp46l34kqpBlIk2DzslY6lrm+u?=
 =?us-ascii?Q?wC9PU7lwymO3fsbZqM7sUO0DC5+82xcQgFNsxy5XImmurjYOHk8LXHvKSKsS?=
 =?us-ascii?Q?+8piat4kxtnux22AlK/CE+xCry48bO0kSiFys6ct4IikQebQxRP+aPCYG6Gv?=
 =?us-ascii?Q?su53dTYCByAw2Ku7v3+VNPjJ4aCx4dSYnY0pxZJIWIDtpTERBnXALexfhV15?=
 =?us-ascii?Q?I5JV7GxU+Iae/41F6lKAFmr+6Els5LWK/H47Hle3N4kLw+WFwQISor2iXX+R?=
 =?us-ascii?Q?dS0wozkJtNBsLRmfrYMjOA+wRxK0EJIptwQRssyGOlDo4tmUGHtnAmQlYXUL?=
 =?us-ascii?Q?GHA/yWtmviegiHWJJpFbtgvFjsGGFQ/lPALNKeorl1ZQTUZ7dnOPdDxmLSyP?=
 =?us-ascii?Q?B4q4t0rBtMsl5IM2qffTsdsZyUbKMPM6ibTzzt+k3Ymq29vC+zj5HpKDdmEZ?=
 =?us-ascii?Q?EA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: lNXnrabH4oz5JSb/PBGfk7Mvo6G+TtAnCyRItcXtLnIHayx+1C/2iYhifB8IJFgj5XZ2mHqNHkC5Yt2QHl6ogxfxvjztezlkpsvfykCunFuDLHk0cnjYvjJZMZ4fkItCaRHxeF1iIaReZdQwsjZHLFh177zCoIIItvHrJHAizSslRTHCpVzzO36bScmeSXPxIxkm2AlPBosdIhTjNFAP+zWllAhbDQ4Q0IzdDX0wEohuXUcPwV3R0qv6zhLcRJ9LvRTWIlg14RCGJdQl+/9pot1o7HP6jnxUedYjlpyI9zFd0FeKLGIVMJ4+uG7Y/k+qp5zOcByBXVbTNCsJl2XnkaJM69yjRoapvjOSc27EaDdXPxnrGy0KTKct0OSFCv1+ditjpIsjlQvCUDCwdQjnDPN/t1uwQ0UyaV+YZIeX9PLY3bTmrDqjbxOXw/Qmip4yIZnuFjNryFuC0OPl1ZInphcM4Qx8MCNQx7QgvRsjtB4AH3W2G4DJonYtMXmVaPkoCm3ggZkX4KSpbooq1ur9QMi2ZD6kGud7cUJUOG25c6/zP2m+zNoJu96b+/HwkLSqDvGfimKM1B1vxBEPd9eyhoAnZx3nkS3jvmS2gywjl64=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cb16baee-64ad-4ea8-46dd-08ddf67a0192
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Sep 2025 06:10:02.9971
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: v2iBWoLPwNGqPUs71DTaUiHw2lM+UwEKrLYEF2mMucZtqXYtP8gIT4SkjPjLohUKzO19yCe2oVre2TMfMKxHD3lhXF3H6xSldKXFcEfj5LA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB5199
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-18_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=901 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509180054
X-Proofpoint-ORIG-GUID: XQUK8Fp3w93o9sXmhL8-P7hpJlUecf4e
X-Proofpoint-GUID: XQUK8Fp3w93o9sXmhL8-P7hpJlUecf4e
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX6oO8PlZClBcq
 yTvSHn4Ch9zNNjTjzHMgKJ1uNnPBlUXn4U1ZlqJuwyYvmr3D0TM1IsU0/5GmULYiOB9vBIzhhK1
 Qgo/wqkvyDtlqQpzVfVNOVKV+/LfqF1xus8f2L5VMUpN18zLAXGGbaNrhz/FrIy9yqwhejBs5sl
 FUNCXUwsY9EBwFQvwyQoRyP823AgeQsCNgqbqCjjmSIQbu7vNQ0q524RzY2z8LyWTOeBwSBY/Ex
 12F46oHp24WnXFF8dK50LMqe3299YlJfQUHLDVsvTl0ZvRlcIUPik/ESnjuL5CjRYMYnn+pO+Qd
 so8TAj0ek6wxspgm852/ET685lVI8fNL3DAc4Mc97DcXCSWYD4oh9YVUe7TIMzP0yln/tYKU97t
 eTkQWBsz
X-Authority-Analysis: v=2.4 cv=N/QpF39B c=1 sm=1 tr=0 ts=68cba240 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=kJZqd6n6nhv6pOpVBv4A:9
 a=CjuIK1q_8ugA:10 a=UzISIztuOb4A:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gdPJKKnG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=CE+ZZUFw;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Sep 17, 2025 at 06:32:09PM -0300, Jason Gunthorpe wrote:
> On Wed, Sep 17, 2025 at 08:11:08PM +0100, Lorenzo Stoakes wrote:
> > -int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
> > +static int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
> >  		unsigned long pfn, unsigned long size, pgprot_t prot)
> >  {
> >  	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot);
> > -
> >  	if (!error)
> >  		return 0;
>
> Stray edit

Andrew - can you fix that up? I can send a fix-patch if needed. Just accidental
newline delete. Thanks.

>
> Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5d177369-3c0b-4c31-9383-aaa52b7e9185%40lucifer.local.
