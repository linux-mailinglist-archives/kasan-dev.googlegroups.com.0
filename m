Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPP67PCQMGQEJHXEFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 81BFAB494BF
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 18:07:27 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-435de81edfdsf1068319b6e.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 09:07:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757347646; cv=pass;
        d=google.com; s=arc-20240605;
        b=kt+9P7aewHq0yJKmp9lSbdAdd/2EYrtcYo9PfwoT4qifFE/QtzAUuUuHsi2EGyHV6U
         +I1eaN8vorjknjoYic2sD9AnG97lVcIKWEyI+GxBR30+kdcyfoBfpKnLOnzfgy2Lk2CL
         M6ud0zJwEixCo7HxquPHVs8TVJXMDO68KigbpjkCR/E1VyQh0lWJtW7HG0UFB2XiaYUM
         H2lVgF19pxOt0ufuDwlhA031wlrdgk9Cc39cXQG0Zq11EdlUThi94pFkMqcgtzKxk//1
         GmIh90XAntIuCdmKNSaZnwO/JPhNdgCMFFEdBmdxmmipkph3eAbAYk0H/iqdM8UYCzzm
         Wr9w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Iv2vE8H3XjEShu0MVaJXl15Q5h412PtQT4pA0fI3Xdw=;
        fh=zXieTJIvowkv7tXbEs8/qNak3yMJLMyJBZjZM1wNohY=;
        b=kKw+2KSgbbyOr5ssGlUFmWZF2q1Lddj9ak9JfrX9Xfy3yNDE9key9tdfaIAiz8KrST
         bHu1yaTrwWHJY/VbiCbPUzto2sUFHPbNBGYJgApGAlJM7bw/dgebE1QXY3YQYgy40GoE
         p+vlXvvIuZhF6Zq0f6IdkliRQQ9TE7F8sjtUtdYBDEIXCUGZ3A+pfF/UTwSsY1sCQhwP
         2LP+d1ey+YCVPYSAT3g52iWcVlc0y92rNTbNvMGuft8E6UwzCMK+sirLZ5KBpoKoTRf+
         tSjzAR2LvVc02efCKV43FLtRAkgSHzYgYOx6TmnwUt2OxbxYeesBG3ylOdP4ySbBFJr2
         77lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gKlTZX35;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AoZDmHvI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757347646; x=1757952446; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Iv2vE8H3XjEShu0MVaJXl15Q5h412PtQT4pA0fI3Xdw=;
        b=uGCDBYJHLvkTLZu8gTs8bwLYFEkNc5qO0crAS7CrsUknu2bSjwZdTjKScWwRPClLMg
         dGX7E2vU8L2ccMA0SFd0ZhvW2N/1sj8lzLwPqMClBMf/f8DUb0XFpttIbS9qQfEEVrnr
         omkvLMN9tIGDwNbkAXWTXNyvNFPxFJTCerG1WGHV0ADi9Zf+C3zBBQS/sPkP7ho+M1UX
         W+LCgH7IccZfseybcjpm+NMJS7jTA8FN9TdPvC2HVW4jnwxtaB7wnF8trU81KuhDhFA8
         H/cP9rYUHRWB65hhbR52w1V2s9MzUXRVPTFTxO9F3HF/zWfOCDJl6yxUX5G0ShQdIhRD
         akCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757347646; x=1757952446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Iv2vE8H3XjEShu0MVaJXl15Q5h412PtQT4pA0fI3Xdw=;
        b=LwVViUiDQlRdSdyxE1/busGKXIzM5eB5rYMax8bY+5kg10ZNBMQnf7ujZTGSUCaCw6
         m6ySURxeQmakPBSLs+a4qAwrAZqJzdxxhHAKgCisSLRMr9CAr9zZ47RnI5GQADlTStoJ
         gjKAqLYdPfLX5CWCLwBbH0vLTaUHKDuX8OeIUDn6uxTgonFVOLt8SHkoz5Wzbgkobfyv
         DHCHiFCOx7xdCk0rMut4hgtL3/JCfsMSf5JeLhHKkVG5TS1cMxXOCxttYMD9o3BRZGsG
         yeMz/6tEr+em6Nj4dGXg3J/xe5GkltuT/yksqYtwGF1RSPQzwlH9ZlOmMd2N+9GI1hv7
         4RNw==
X-Forwarded-Encrypted: i=3; AJvYcCWQdahRQGWtwcP2BUEKzXd849KIem9XMPbsHcJ4d9JASEVaLaqLroukDebqijpxMuNp5f0Qbg==@lfdr.de
X-Gm-Message-State: AOJu0YxoDz0naO6i9BjtEPXN3hSrhFMr0l0tbqX9E2LeV17fkxMHqaGc
	cjB5jeOXmMmWEJSWYgqjF7F2j3xaYMgWW1QQZXcgbfzzm8CAgK1RxvvX
X-Google-Smtp-Source: AGHT+IGCxcEGP0Hm1TRXA4OCF9Jmn+yrOVxgw08F2pKhUdjIUhElN9qw5+XnFmca/X9aDC6LVi0Pxw==
X-Received: by 2002:a05:6808:3a0c:b0:438:3620:2ae8 with SMTP id 5614622812f47-43b29bc80ddmr3909355b6e.5.1757347646057;
        Mon, 08 Sep 2025 09:07:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfn5yhMgamsv8XPMlY8HHCwkiJlPe1TziUvdeEmbAQ7ZQ==
Received: by 2002:a05:6820:6fc3:b0:61e:7006:58a5 with SMTP id
 006d021491bc7-62025a3efd1ls638372eaf.2.-pod-prod-06-us; Mon, 08 Sep 2025
 09:07:24 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUFrqGcKGxJGEgEXJepTjIxItoRF3yRMqUvRNucin9tEnvvA8/BNu+6zuKfp6/S08jTXvPfOWb/uoQ=@googlegroups.com
X-Received: by 2002:a05:6830:7301:b0:74b:6a51:b829 with SMTP id 46e09a7af769-74c789f8173mr3366713a34.36.1757347644604;
        Mon, 08 Sep 2025 09:07:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757347644; cv=pass;
        d=google.com; s=arc-20240605;
        b=H0Nkc9OVttXdjogN48GbYvFGa0mP/kAZovJODKF0PtShxWHuUHJUZ95Lmx4+WZKG12
         h28wRAwxYjjaAFJm4jpjqVQfSmiwh+dqG3kF1PT5B56UwyQWnlLIBBY3VqijbglHuk6E
         mErBDmh8gD2AQFwV2hjdNexxyGu8UIUX6D/ZEtJ22RqXnFapW1CRGSEWHm9S/FEyuFJo
         cn4KsTnuQ3uwYYyoQF/4FPvSIz+sofyp5TbNrlJlV82lLXRXVs1wsN8D56oiEeVN/PvZ
         t6Pl43oyL0wuQ5FegvOr1epqQhRq00LBgTAp6bDdx8FCmLE3/GgdmoVa8s7W3BWSi6lh
         eOkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=vkg4uOpMyA1aCHZb1HdSdDvASR40lnJIYliH8rngG+4=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=IRq44BnRqx9YysW5lRqNoggxz1I6lMCCfZPfz0ojp96f99O7bDAAWptOaySXsh2nN8
         JSUb9mnAOWp0XMsDvqdEYEA+DIE6gqtT2rdrGgbztBNkwe22CUO0G0/jKhCr+TWl+ufK
         GbBX5TXd831sgvfx04cptS2d234xJINUm75eozOIrz2CkWXj/lqiNZe7St/Twn63S+gt
         2nILrlj60JP/XiHm2o29OmKzDdLchTvkNelMakMpEGfk3gU6qB5oSrGZbTfFkfcgpC4w
         R2WbxAahjLCkd4xXUNsknPA61CXIqeKzPcRuWOliW3eAP0gv5BPWy/fZFtE6p3yAqv2s
         9KaQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gKlTZX35;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AoZDmHvI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74773c1911csi408036a34.1.2025.09.08.09.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 09:07:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588E22qR017982;
	Mon, 8 Sep 2025 16:07:23 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491yx6rdk2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 16:07:23 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588F2JEP038749;
	Mon, 8 Sep 2025 16:07:21 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11on2075.outbound.protection.outlook.com [40.107.236.75])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8du1r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 16:07:21 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Dn3nUg74UEO2hHeVmpil15CUNdzFeEd7ssrKMnBTcYmLgtwU2xy7kYOwd+lf3gSTVF5VOft3cIPUfVDulBQUajoxMvFo69phEgPw3/b36CYBSw3yCpnvJ9AjssCPZ5vD+J7sI95NPtDNDDP9PCC7WYBlvP/TaBmH/U7CRHP6x/ROapX4xuSG+xN+rYA5GHn7b5BgVwHOb91h5yWB/co8Q3uCyjj8r0ZK6T0GuP0hFSF2UWrmaWtN1nDdFG2VHc3E9iquGHV52FX+aCKPMQDf2Cm2Ms+cbMUbYJQdAn73bwT+hb0jrYzLvZqt1HV5swXF7CsFo/4IQ/TapVoJISFL1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=vkg4uOpMyA1aCHZb1HdSdDvASR40lnJIYliH8rngG+4=;
 b=ZdhDmb21+qXMvBpSDlpeqiGBe+R7aPDT6YsPFwXkqmVOv3GkPl6h5MQTUlLopaiH7Fz5jgHrYXZZW7gBHXy/fU6FV1kgd89Rg2U9Ey9Xt8n/zpBMqK8zC5Ry9NbodFHV3u0gz5lZoKT2fQ0VoWLy9wgOlhYqX5t6VMRZ1UPmHo2ntY0npa4ERx7Ykvm6FboPVh0qaKpMwbtu1/SPE6Kb21NuR4GQrBferfS6xoYC/XkLunmxFphnNU0wwbtwU5ZTp3Wn++O0HEWmJ2jwKMXI/dBVxufteQZqJ6+JjvVkdmdDSTLozKRvw3SbeE5Z1dDaQrE9MCRi3RM7LByu4FMPYQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA4PR10MB8633.namprd10.prod.outlook.com (2603:10b6:208:56c::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 16:07:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 16:07:14 +0000
Date: Mon, 8 Sep 2025 17:07:12 +0100
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 08/16] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <0645c8bf-4d5d-4740-beab-10157d133725@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908130015.GZ616306@nvidia.com>
 <f819a3b8-7040-44fd-b1ae-f273d702eb5b@lucifer.local>
 <20250908133538.GF616306@nvidia.com>
 <34d93f7f-8bb8-4ffc-a6b9-05b68e876766@lucifer.local>
 <20250908160306.GF789684@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908160306.GF789684@nvidia.com>
X-ClientProxiedBy: LO4P265CA0195.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:318::12) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA4PR10MB8633:EE_
X-MS-Office365-Filtering-Correlation-Id: 493af79d-654a-4b2a-589c-08ddeef1c691
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ToaqnRm/bjzjj+siqsMkqH1rnZ9FTjtAgc9b5AaSFYB92ozB+GMwO+aq3gSN?=
 =?us-ascii?Q?rBHY6OTJkEjvjLes8cBcbZWGL8KoR3RLSs5ciY62NEdg1vYAaF/dZixBilH7?=
 =?us-ascii?Q?CWiBWTpxvQaAsOfRbw4TYYpR/a7PHaY5NA+mlyTu3bJXVqvDsHLFy19Hf2gh?=
 =?us-ascii?Q?E6kvjSyl4U4Z4KndZC4xsukCzNFaWrSm5jGEbxYZwC0JN1FXa/mI7xsRwOWW?=
 =?us-ascii?Q?PzaSxRbgjXWHNumVyXrpSuWYzEPAX3N1ttRtrTLMEqX13vy+7gYIV45srZE8?=
 =?us-ascii?Q?NqTQHulvdjnuhInVcJM77lk1tsJHfAfvLp+lUb7o4URH0lt2FdlO3SfKuCSR?=
 =?us-ascii?Q?iAFH1DoGMtPua+RAONvfi0dLZOMibeLHwhy3vZLvKFCACgrjqX3KbKKvFTkC?=
 =?us-ascii?Q?/4inNayrVg11N0EA9YlOu98012A2dAnm3B4PPtfCCxm8cOAx4xaIyIuX8/LZ?=
 =?us-ascii?Q?CqJX/0HXzfZpDNdYINvvpfAZ3JiAr+XTvtii8lB1Jyr7TEuDzc5B45CG6Pc7?=
 =?us-ascii?Q?0hIIs/Otj6u7ZTQhRO3d3Pu+5tgHnb0XyAHaLH+1OrhSVic7v+Jl/cDEReEj?=
 =?us-ascii?Q?l27Pn88eKgaSROqop4f6iqrnQtJoY6T0tDh6Fs+xxLT4r33zKpCH0wrr4HK5?=
 =?us-ascii?Q?JrvL2jV851S98ZUDBYV3cCu8ayW6LSYhQl2iwbb9/rl88UkoGGBN1/UNjMrZ?=
 =?us-ascii?Q?8Wl6mDzIMOA+G5Iog9GZXJ2d3EnWr+YsCoxVOKUGFEhlhgmz3CEzLugS3m9R?=
 =?us-ascii?Q?hryroY6cj6ttiBVq/cbMcxthV885CfGl+Aj77N/QNhYnJIXbOVhGTSZXtylT?=
 =?us-ascii?Q?IQae7gkgKXQ6r0Zb8ZMHJRSo9Zle5qEWQkS9GG2sq2mA7ib2DpAlzfIWugVH?=
 =?us-ascii?Q?ePFQpN6zInyrXJVbrxo6JonR9CfDoCUodfWgVxonw+apxQ0hNgU4wqMKu2pJ?=
 =?us-ascii?Q?7HAxAGNu6oClY5YUip+502xqAXqUN+05XFovSmRc8ApvQIw3ioWYAnYdx++F?=
 =?us-ascii?Q?+lQetdjE0HVZks6u3xqcwyhuSTUaxva9gMm/HZSgE7yA02bGvj4c5B+ssM7m?=
 =?us-ascii?Q?40GQdwU/eSLkGaxciTVWPbWPwK+E78r6JgVv7hL3ZSfTlknYEj3K1aUhOvk9?=
 =?us-ascii?Q?1An56UlluG517WI0mah6cT+iX+yHVIA8R9PadlKPhBnZYjOQoZ0G6DfD9elb?=
 =?us-ascii?Q?13Y6pWA/fgB7zfyL9rElympJ+HTR/R+hbYUAlMH3dG/Uw5sTVMSzGTCxt1vF?=
 =?us-ascii?Q?pE9fWyMvh6uyRCMWUnn8Zz77ulSsf9ArI2TUXZxx9/5Z881UbVallrVR0HW5?=
 =?us-ascii?Q?IMwNhmlGF/qXiPD+dnQqf/Cc+PSeTc7BI8TBXmZo7pxuzX6Hnu3uyAke4+9h?=
 =?us-ascii?Q?MT4D8AwR/U7tZthqd0jjQcvR3Z431bWLfT5MzFgiJDhhIAv0dyxiayLFSLVe?=
 =?us-ascii?Q?WZFNHheLlbg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?cNJt5PeE0qj3nWHlTYVFNGlbdvmtP88Lz9flstmkkHS6R9IwwlpQBFEMxSP2?=
 =?us-ascii?Q?mDnIs2Kx1G8UZ8RFFBK8RRsVRBmWwfDbJSFrsLb24QeMRcxTUh5Hqu/OzfbD?=
 =?us-ascii?Q?nZ5d6w6Fvrr9ojAxziCHtsZ5Qe06/yE0DWoxuMfbL6/G5SW3oscLTFbm87bL?=
 =?us-ascii?Q?ndqAenL2q0gnCXCI2RysrePPG782vAd4NOkeaO6/KmfcT+uXid4eICBx7xJy?=
 =?us-ascii?Q?odRtGP0naf9KZ/9c/eDc8sDkjGVg1wgNBVviL//788d+H2KGAuizNHahcHGQ?=
 =?us-ascii?Q?XQcs6tPfhC+8Go/vZlCWjclyc6ihET2qrseh6uWghoVKw9+szb0qTpogWCzN?=
 =?us-ascii?Q?K/Ys/wZJGQP1xQBDtt8QtXqFrSyFEyR7zO2vag6y+oVSISMdTvAariK87wsR?=
 =?us-ascii?Q?hDO9W3QjQaJ9q2KxtZkPDoJ3B+/gicqB3z8WvXsWC4wIZwFhXLQhW97mbeB/?=
 =?us-ascii?Q?E85I/dq2b5nMYTltp3kq9pswCPjFL9Nd1Ionr81+mLzJT0whc+tqWDR7TpVv?=
 =?us-ascii?Q?JrzaKLZ/s44GobJryMxUepBZvum8pBS+4QFvhdWHKbyNclmQRKLTe7Lr3dmW?=
 =?us-ascii?Q?5ATqr/lehsK1EN9eUPKZj5QTu+tyvdjNMeKNvMMqWCYsPAUbRBx9JVjT/ugx?=
 =?us-ascii?Q?dnMOKHn7xkClDW2Z9kNOGVWGlRluvhUXLxvFvHJf9Qvk6ZdLGkCoLo1HBpPd?=
 =?us-ascii?Q?ByMUpnrS616+dcblkPlkzFlIqnN5yzbPYCBjg4GfBwEQ0GHCP0aTZkIDO3lv?=
 =?us-ascii?Q?7nYjPMk+SdAqZzyQPR0LwMzGiHT5wKUDk8YnIhPekRhKLcdcup2K6HQ6jrc6?=
 =?us-ascii?Q?cAiLmxiT6RPg+Nvmic+PkhRcot+f8bgtLdE8lAYi+R8lvOyddngPZXz26V8x?=
 =?us-ascii?Q?lyHBM5ntfELs/KMxbL8yoO2eFKOqcIabOmpkbenoILFYJ3+60IjZyUpY2WE9?=
 =?us-ascii?Q?UtX0UmQYCMbuZ5Clb4SMgjwqXbaHz85ddSn8gw9ibt4LPsNkU5BTi5dKtlr+?=
 =?us-ascii?Q?H7BadYDtMKYqI0Gz6x5m6vRTq1XSWQItEP7+wLng9kamsY3bSJ/EMESHjp9U?=
 =?us-ascii?Q?kYW4z6/at+Q0fB4QfKfwW7ZPxFIPi7/tiwPuV+jLoECFuAax18sm1xJTXCq6?=
 =?us-ascii?Q?P2SjWC0egmGVNZCetVlcRL6f6RLWtsLesjdVhaSVbuulgpCkypKOsZs4QjzM?=
 =?us-ascii?Q?pdbipKuxbdSDw5PG7bkXD6skMUSavVH1XrNGdw9ABANueVj9vJWViLYkByhF?=
 =?us-ascii?Q?4bI7xmLhl5Phuf+HxBHJU97IfD7zBBcFvXUsbjOEIh7dtRftAu8iRlQGruie?=
 =?us-ascii?Q?omi6vQD6P9OeD5DB1VD33J4f8wrbRBjLuv+K1eBG+y6vJX62dX6JKcbyxekl?=
 =?us-ascii?Q?RUYg0McEZ+vU/h5LlVw5XDnPT2dGV8JW45G2/AGbhkTF3s/J/Zxhf9Xz4mc0?=
 =?us-ascii?Q?20Cu8FnRVnbB/fhl0J/1QCdDG6naLRiY09NcsT8HM8p3ps0yt20VT0bQafVe?=
 =?us-ascii?Q?ch5u9YE8j/pmWjKZWsCOmyKARleUkrvkSsN6RzMQv3Mq+nKoGZpPd4fiadWH?=
 =?us-ascii?Q?4YBjk+X225UkOYmHeD1ZCd6bEsE+cC9SHJ3ifW9WZiUcAAAUf3Zy1Yl3zSgN?=
 =?us-ascii?Q?TA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: vtFwPQivjAv7gJ0UbWRZ8AOUrkem02rfgj+IxLXHV2t0f7ig8yiO8/WvnYJTHT7odPcWwzp8E1PRWB7chNg22xZj0RasVEFPbQ15DZL6DcPATQJUthPOSGX3uTD3y6kIxkmIAzio2tYdM3bSdvt9Ukjr8BSR1xgSrT9ZePgjDBRzHOu8mdQqJpiVHyQOI3LsvDkf9B3Z8TGazd8fJAyGa/MQttywCLAMRbtg+VKjbB3fHjSPG/yLhgPLeFOyQBN9bOhTlCzEoxVRcCGMEUmbe7Td17uDZNeTViS4u6xyxtECXWhj1wGdW/pcxm2GftH8xqnMCy4Zn/WdvNqIxpVHL8Fae8RukGdFqL9w03Yb/JZk3CYr93cE4T0lzxvy+eCxRGJl/nN1Wt6GzsBZYCVIsYp29a4kZc4842fbssVEGy+V1TtyoL2g7wVlrg5EjyBJ7lUWbsBQcsY+L5vcddH7HebGUT+UsP4dvkEoJac4zmnmOw8ALOb3SgMOeIB32w0I0oOk6mT7ZDdDIxqvJJ88Z6PzCC+VFK/w0dzmdFjJxFp4BcxrcrxQ5NDulnY5g9YorQK7XwwPgVnEnG+VFG2UahxwrjSSwFHNO6M8Vm3cS/k=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 493af79d-654a-4b2a-589c-08ddeef1c691
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 16:07:14.3140
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 3ie21DXoQW5M6lSzSWmTXXOXPW5v7O6Z6wfiPsGyCyA4VnlrWBic5WKpk3BRYsdZyb0gVocDrumcaXvcjCjYQEZgDnUnP4aUGRECSdQfIGY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA4PR10MB8633
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 suspectscore=0
 mlxlogscore=999 adultscore=0 spamscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080159
X-Authority-Analysis: v=2.4 cv=SaP3duRu c=1 sm=1 tr=0 ts=68beff3b b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=E9Rh5klarhuv1F7PEQ4A:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12068
X-Proofpoint-ORIG-GUID: ES48ZHPJTOVivz4NcyeF_DQIqqJptWnn
X-Proofpoint-GUID: ES48ZHPJTOVivz4NcyeF_DQIqqJptWnn
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEzMyBTYWx0ZWRfX8p+GtSG05jv3
 ymZifiWex4rfWFu1fYzmCWDmV2qu3Q0X1RfQE9FzgVL0dTXnzmy6Msvay5FzUJ8gXQPz3dwJg56
 8MwBh8HhkgpyhI+ULSV8Kdblrb/IrlQq0Ap6ojS4bUxcBNsBQ+oNL+/sbYWdEYLPYzaUzv+3ARI
 yrlydLZmeqCrQdedBt9uUHCUChF25JsW2slWV4pJdSlnFltrM+HDQ60qlCJ9z7LkS9vibezHrJ/
 Q9F5zHS1MBBLlAwr0hIBGL+0jsrz93/PbY4Qt+pASZcYnKCA8XH2PXZaZoP0lS5JIAK8h5NRuWt
 PITjCEa5T71MAzbxIYc7YehrtQaFfhExe2AK6KqhwHMASEDxUW58LNUMWcqf7zAJe17MckQUsIB
 ELgVcXXcl91D0cDvnG89epH0l1NC8g==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gKlTZX35;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=AoZDmHvI;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 01:03:06PM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 03:18:46PM +0100, Lorenzo Stoakes wrote:
> > On Mon, Sep 08, 2025 at 10:35:38AM -0300, Jason Gunthorpe wrote:
> > > On Mon, Sep 08, 2025 at 02:27:12PM +0100, Lorenzo Stoakes wrote:
> > >
> > > > It's not only remap that is a concern here, people do all kinds of weird
> > > > and wonderful things in .mmap(), sometimes in combination with remap.
> > >
> > > So it should really not be split this way, complete is a badly name
> >
> > I don't understand, you think we can avoid splitting this in two? If so, I
> > disagree.
>
> I'm saying to the greatest extent possible complete should only
> populate PTEs.
>
> We should refrain from trying to use it for other things, because it
> shouldn't need to be there.

OK that sounds sensible, I will refactor to try to do only this in the
mmap_complete hook as far as is possible and see if I can use a generic function
also.

>
> > > The only example in this series didn't actually need to hold the lock.
> >
> > There's ~250 more mmap callbacks to work through. Do you provide a guarantee
> > that:
>
> I'd be happy if only a small few need something weird and everything
> else was aligned.

Ack!

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0645c8bf-4d5d-4740-beab-10157d133725%40lucifer.local.
