Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4GLT7DAMGQEALBA2IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 710BCB575A7
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 12:09:55 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-248d9301475sf60769655ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 03:09:55 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757930994; cv=pass;
        d=google.com; s=arc-20240605;
        b=kTHkTjj7x/r06+y7keNNlEpDzDc/XcKCqjOcPJbd9gXGbSxrK8DwUIftwcNykY/Ya4
         2sZFEdjmQfFM+0phlpNEnWXXwq2P6/VUf92HTzCJoTE3/cZeo79y4261FkB8W4WGlG/j
         ER9cpiQ7JqPEuBric188C6CDxBK8mOWhuTkKva6dKjsRqNijhAt3PO5dpCzB4iFe47+w
         L04+US6b1aa3gFWPGJzpfud4aqN2DFhAF6Chklyng5R7ybrpoRvzG3szWdxxXAy70L40
         +MyBAO3pEJYzvXBrJcOzraAlmdpb7+suhHjDZUhoW7CMtDwsc8gYkknnfcvtJP59no2S
         DwQw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vmGHiw8f6jlRAY2icBnyDHjDj+rkU2QILhcMkqhhal4=;
        fh=C+5SNIa+yn2jsd3/OwgriFCplA2BP74JzgZrFzIZRoo=;
        b=KayDr4WCCTfE//djTldgIBJ8Cv7QLC+vGPcgTmc6+1LiHUs1YDraiCcBmk5YPegC41
         Ktldmp4+FhUrqTq/9WEiKlDU5aBXcYXgDn18PX/kEdSKf6rJIXA9wfdEgku8+fZO5A/B
         stWxya8nt3qJ3VwmdXyy1nxE9wAZ1O+kJOn3DFH/CoQiVt2bnrkDNOM4DA0qNwmRTxtu
         YKCC5ItZc2KgU4UGtDCMHBGZti0LeBT/c2h2SPg9GrLVLyzGg5syTEbjmCbTkDHxFtXL
         WTnBI8TuxqoZSrNwV8HjmnMfhVJfi3YnjrUeYou5whK1+7jjf1oryqdCWvswJ/auT28Y
         xxpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zbqepl2h;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lNOx8fG5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757930994; x=1758535794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vmGHiw8f6jlRAY2icBnyDHjDj+rkU2QILhcMkqhhal4=;
        b=JvL/WTDcLlBL/Haw8aVYftXXwAVEQdvPFiubkd2KXKhG7on1nkH0ySHUQ6GnAjeBTG
         wDimoVstEKpsfV7/+z00GdEPx8rX9WToI37pWwdUMNr/M5tcGpRgRp8luyObrYXze6HD
         iBVvVBldx1DpZVfSfZcrcSdIhi4wlWzw/QvgwzM3BlwK/v+KhL4US9f4RQO9BrVdNVcy
         Wsm29Yz6CCv6lqjKtbmiRbyXN6vYvayzburmrvk9rTbR7wFLOVpsiF/BXMMwZUR7vfds
         E2kXoubMfTR6pcj7xhDN6NMuJM00U8wdIwGLkgK2GT655uRbsXveAEKRxDTbpkvrrACH
         fiuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757930994; x=1758535794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vmGHiw8f6jlRAY2icBnyDHjDj+rkU2QILhcMkqhhal4=;
        b=wgT0826t0/gacSp21GfCZ2Kod2wS7lWFRrJj2rWS7zMPAmli9MdklvOJO4SRkRNcYH
         /XvCTstHhotswJlIwNUkaQEXk+1J/pzkxXlOOgTaVXRZIEeF2XHiYxPeyWZh/GWbY2Zb
         UgczeyIkhCjf2P9l84oovQuLkpV3RKEne2fqKU4EA8hxIJxS4iaY1VN3Wsvus1uujiJb
         dAP6F7U+nfg3NKqC+LAVWORcCq1o1KAp4NqGp7SQqL2WDDBpxMWNv8wQE5lNWZ/6thQC
         mlBMRr5JfuwJtciqB2U9ezdiNY8qpXauZ3Tiyo7nklVJOoI/Vd+YiY6MI4qfeiqlGL8F
         Nucg==
X-Forwarded-Encrypted: i=3; AJvYcCWYe/0qDhLE+wLCKuVC55VNLzVbWutIIY/AJ7Y5FNnBnVrsk2IKz6jlFoiAohRh20BaBbA/SA==@lfdr.de
X-Gm-Message-State: AOJu0YzBgsTnJT6hEqSMfFgtDYGo+HGVh341CdjFb92G8wwT14iDOUu9
	/ByeO/h+S2sWP1bJ2tMtr0+h4rHEX/jLpgbif+Ilv9v3yRhYRgG468Q9
X-Google-Smtp-Source: AGHT+IHqlGl0+1cNfS41VIYoQuUhPSmqO0MMkyBGfU5oF4R88NdD3iGXI3+O8UgKlz3xkapGTVjwpg==
X-Received: by 2002:a17:903:1aa3:b0:250:6d0e:1e50 with SMTP id d9443c01a7336-25d24da752bmr157456595ad.23.1757930993856;
        Mon, 15 Sep 2025 03:09:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd52mPh/KL9V2ei/YjiDzn5eGR425zW7tV1vT4GRY5pX6A==
Received: by 2002:a17:90b:3d8c:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-32df96cffa5ls2103000a91.1.-pod-prod-03-us; Mon, 15 Sep 2025
 03:09:52 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVmVQhN2VjmiE8NWQ+Jd1NWluXR1YVt/+fF1Mr2cMQw8aoLluRuAhSFDm0g3fDrNwgA9FMe5iSsMq8=@googlegroups.com
X-Received: by 2002:a17:90b:5107:b0:32e:528c:60d5 with SMTP id 98e67ed59e1d1-32e528c62fcmr3849617a91.29.1757930991744;
        Mon, 15 Sep 2025 03:09:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757930991; cv=pass;
        d=google.com; s=arc-20240605;
        b=av85rCAj5QbNCOVpyDqNihSBUP82Ejdvx/nKIH+DxSjB9X9hmA1Q9uDIXYOfWGl7I+
         QLgcaFHWvItmiQAcznDvCKFf5otQFkd/kiKxrC6o93wHBtxp1RaU+a8ZsnItF1ArpEmO
         V0mfw7AWf/dwHpZKoQo3H47A1qO/2Vh9eh4Vqny0yop45VaGnPGsASCwxIHTzwkwi3K5
         6/r1tBg5mphZpc1cU4HE/5cCtkzq7OAmbbOShqDG5XxcZvDu+ysK6OKiU6GEXo00eN6E
         p0R9PRFymi7vFnIabLGcYJrftENp7h/c77RhhJB0O5N6fYi0WHGM4imjdbc4J5dfcfCj
         8AuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=931YDy1+BLx2DCO7kEgLsRNIq/id9/0hoehxfKwHkBA=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=On/ON7UsTjUMLJ9mopEzwQMz9tlOyDLDVrvBnz4qTv9RU4RJX22CFEE1hdHhXI24lQ
         Oz5IyRzjFDzsitsT2q0YPhvWqp9VzzWP/PmjAj/vUpRGvOJk80CJXVCbs44G1ywgF8vc
         dMFlS1iK6XEn+xcF/GD9qKxnvZfh9iTmbtwqhOK6hA4jyRO/dq12/V1BlBCHrO71EU2J
         otmKkVZauEGX1T/Vu4+SVtjxzjCRNfIaKw9dh4qgKriYQPkPN2zqSEyHdfVKS9BzR6Vu
         BY442B4tW78h8oe46x7hxs3mGyoylSURggh+qe0UIsu6H17YyNwTIH/L5tgIEeuFrs0q
         kypQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zbqepl2h;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lNOx8fG5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd62e8c55si390330a91.2.2025.09.15.03.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 03:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58F6fx20018066;
	Mon, 15 Sep 2025 10:09:38 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 494y72t28x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 10:09:38 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58F8G3ZY037281;
	Mon, 15 Sep 2025 10:09:36 GMT
Received: from bl0pr03cu003.outbound.protection.outlook.com (mail-eastusazon11012018.outbound.protection.outlook.com [52.101.53.18])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2h2ymp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 10:09:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=x68cyyRpzzmYZtQKHTwlM+NAACR94lkqcmx+t3D2jrzFDfLH11FDmi28/8ZPqnkb+nPu9qSKTvWRz+QxjiWjTNld46pZmywb1lZpYSYkarKgzbUGSt9mJvk7nGY3n0yOVYkPeFx54X6nmwoANVDEkeo8CqsUP8ncHXClZXUEnXVnoVZsHTnzF09m4VcfsaWbCWbXgFl0Y7VL/h8QKICHhAy7bbrHD0EwwGSPrYplRl3MvkXT9gNZ9d+3wVOj0eT0bFmg9OQMnOeBxV1vR7Gnj5JXdnbtVwH0x4ev1yCPDGHYTuhSpM89zpkKTSO/UZP7rgI/LR8QDsMOY1d1/9A6Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=931YDy1+BLx2DCO7kEgLsRNIq/id9/0hoehxfKwHkBA=;
 b=t8797E3Vl9IfzXJNwgIlGEfJIzZ9NdYz3aQAdKw1djh01O31JZOh32MITVVs3diXuIrKqVz2ta9VwmNYdJCA18iKJikHyXO9bsbkt/XkSh2Hf8mCBiG+tdL+PDjGCbxFC64daMeOyp/+xnDT/VkChvHaztTF9nTkndfFKyXzCYTt1Cw9lBDucJR77c3G3aw+pbinLlToptM3xMWu2L4VBmy+yXp4H0K/DsKGBQChEdqJ5t6J8wPRTyNXjh/Jl7EnDQ6zAkEUKdHW57/A0VDocYi1PEXiJXqd7+bhyIdFa00eHpZ91PNP91DS8lqaGLVKDP2HX/khKLJwGkVfkST/aw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS4PPFC31902354.namprd10.prod.outlook.com (2603:10b6:f:fc00::d47) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Mon, 15 Sep
 2025 10:09:33 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 10:09:33 +0000
Date: Mon, 15 Sep 2025 11:09:31 +0100
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
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <4ce3adda-6351-4530-92aa-103acf638004@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO4P123CA0388.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18f::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS4PPFC31902354:EE_
X-MS-Office365-Filtering-Correlation-Id: fe1009c3-1da3-49ef-201e-08ddf43ff7db
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?aING2/uF/9xBoXRk7H2i0ddV9mVhiMHC97Pg2inPQ8YFjh881Dfd9Om4xY/D?=
 =?us-ascii?Q?MAi+EyhnFdBnDhUhtMl4rUwZW+Ue3kDrbUJJoF1DgL9DyMDYghFsUFDrXAp5?=
 =?us-ascii?Q?PojRgYH8oT3QAUK/TfzOUPS9/7hozANIkrwzEQbyqa0JM+0g9hTswTfjmLV8?=
 =?us-ascii?Q?b32Zvz6Mb263WPPDBPfRhM9kO8CrtDf24s3HvANgDkYIdvfIHwiuhGJxpgYV?=
 =?us-ascii?Q?xxqUlvPmsE/vX5bX8VYptpcCXndydkLD8gfGTj1yaNFSGKnSsdVE2I7szQSV?=
 =?us-ascii?Q?wTfI9B03Bje+WD8+S3OSYWO0B0oT6KC1gNcmLlhIsnyD/Xdb7PZaQuMVVUO3?=
 =?us-ascii?Q?x6cmOStRRU9sFhulEFBV1muPehaDwt1yyS4dBGK6Iuq8m/NFzE6nlxghiSWp?=
 =?us-ascii?Q?sHuVXgqgeUzpgB98s0f0COPJO4q+e+LRtffc/d082cycsuPYJl/3o1v3o0ZZ?=
 =?us-ascii?Q?sgfo8L2SD697Ldrh/HbpTwYX0pJbhHu6X8nSNKiaieKhaP7GBRRClWyAH9wH?=
 =?us-ascii?Q?lw0nnLBfZJt3X9v/fhQbMns4KPOQEdMzWAIqgC0qa0DHEXA3EsMNtPCMN2E0?=
 =?us-ascii?Q?aYxQ/Roi401kb3mXQuaCmgP/7V6yDZ4c5SiDDiL4p6Ke6DLnQ0eyan3bpWSP?=
 =?us-ascii?Q?pQJTmYqEGnBBlGK+y3BD1k+AwbUuMxv6aJdxBVAmTdf8BnaoU7vJJ1Zm+ADU?=
 =?us-ascii?Q?MFEUaQY3DlByZHHVBdt8EeTgA5QO2h77mlDcm7Ck1js+3cRLjAIx9j0IYnCu?=
 =?us-ascii?Q?VfPS9/t/hMrtTVAKV9GCNvpBwxS2Jjm/+sgim0l1BBo/hUyyXadMpQHlF9WR?=
 =?us-ascii?Q?v9PzSyOM+Vd8NXfWlHYgGE10iW5k3XtsJWctSDNuXQNg/rLStAYG2Dn+I6Jh?=
 =?us-ascii?Q?RjsYM0GLXaUcjxpiRqJ+d1oXucJU58GaWlYEx6ci3K6FbnqMqX9Z3oYBd1/g?=
 =?us-ascii?Q?4DwZOtgsZL/IRcJwfgY5ImtYLoEWdcAVq50G6tQtT9xL5TxZy3WhOy7Eapwe?=
 =?us-ascii?Q?1IlV9DpaE6t6Wfv+iQOYjWuLbkvHjtoaH3pf1RVZm3lTm+ou5qs80yxS7zcf?=
 =?us-ascii?Q?2zGsQwMQAWIEHImvCVP9xtQA8Ly3cg8BA/+EkHaxzGtqZsvKbdlUqWN+c5n5?=
 =?us-ascii?Q?4iidcMpiR9gjcWseljSh9LE0MNAb38qHt2Cjf5dw20/ing89QZLLiPJ5EVQc?=
 =?us-ascii?Q?g7squswM02Tqmd9xlFQP44so5ps9lyc7rdxStmGx+Jg+kWpeBNtiejQ8Gw9U?=
 =?us-ascii?Q?Re+JKxiZSYVLPNQNAP6DSh3eINKi9DbhR2kS4AzY3kh+D3QVCGutRnZoEaKD?=
 =?us-ascii?Q?m91DMA5JzLyrnbZp3IvXROdW8Cx0nnB6uezoUO1xKPdAr8g6vS7EaTSStfkK?=
 =?us-ascii?Q?FtzfJh/50zt2Bf6W4vo35LIPnfsH5OiG+dQB2ZzO7N7A1aTopIeoxp8jEjFI?=
 =?us-ascii?Q?IZCfzGL35nE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?l5SApZcaWgytmT+O2wdql8UrhGWK1KHYPEIax7WFvTzbxvcQlluCU70UsUUn?=
 =?us-ascii?Q?w8ibQ8DEcJOvBnTbfadZ6c8i8vmNA2UyrIjMQUdQWzuaso52EbUeXbZ9s1ex?=
 =?us-ascii?Q?8dnqRTKuVAK+uvfw9d1TkNKfubmer/dqvZxvVjSOlwo9MbBu+Q2IgeVqJ4O2?=
 =?us-ascii?Q?sboZ+vbTYkiFvLayyX4xaEcHOVmfu72rKyOXTsgMSexQDV86N3/pFsNUT+TO?=
 =?us-ascii?Q?bTtKrSf3M27ctv3c8mLbZG3bSw8fs5ZHq/8N4pIAO3b5R5gOXHUq/GzzOEcu?=
 =?us-ascii?Q?0IkueSuXLxm3wljOBPA/moMMcP84mSzsulsVmYP5c0bKGIm7bQ42pHnR3a8Y?=
 =?us-ascii?Q?vDJWcZckY18JEb1CKNJjjaP8V1RVq1yi/6GIoEBxjsLI5bu7ZtcsUqiLZBJr?=
 =?us-ascii?Q?LjX9npjEjd9znLMhVxPvM9K/pfx30k9azDzlIh1Vp20q1z0HFkcOGDvSm9ON?=
 =?us-ascii?Q?dWdlBRyG9Rl2ZjP8IdLgOEz9Dymoa5tJ2UZfAto0+V1oOAj6StYErL8uySWc?=
 =?us-ascii?Q?EZ/5AVH0N0BO0jNrgIcjP144MuCtrztrt8zHZyfpMTpInZWpCItlJPhCrtBT?=
 =?us-ascii?Q?QWLqBllGB1pmSGDkq1OxyxG2OiIvuZzLubl+DirxRSojm62NUZ4jBJmpEyxa?=
 =?us-ascii?Q?JY21JoL5Sijyme6HlQ75b62H4eW+yBcSwo15xbs94EoFT3nIVYV/Ox7D+qJn?=
 =?us-ascii?Q?zHNX4h6+4yCDQ1dFmEtpZyPIFQSKJanLET03bTf7fyIUN2Y7LSQ8aXxS7WTX?=
 =?us-ascii?Q?u/VGt+0Pn0gQ20HkuJgoCYjrIuwYP8VUtDKuH/RulHBJCa5gqAYVDe6ypMXS?=
 =?us-ascii?Q?Q/ZgUbxsGn09JEtkWXNekAZaeV0lm9JAwevGmvH17W/EJnWJU+UiuOkLsb1B?=
 =?us-ascii?Q?A2kxM02FnuvnAhTYVBGBDFkWH5UPxlSHj9vo4U/VFFnjjSJLM8URdrPHrUkj?=
 =?us-ascii?Q?uvCV+pWICpT/7XRGWHcRXPGpG9Fr4DOj2QCpeXwSCqUMPd+sUBMaDpfNWJa4?=
 =?us-ascii?Q?rpBBL9qE/jt7z/eb27rP0rMUXBtPY37IBT6fk+8oX1bzzTYRpPsc63V1dj66?=
 =?us-ascii?Q?zgKPnh/TTEcXiz8hy6c/+E7xoO12NhDZlu6w+p6tAookRCkAICDJPj7v5/6r?=
 =?us-ascii?Q?av4SQh4aC/nzKh/N0i0zfRSjb8zhv7GWM3MubDsOG46ppS7S+W8PnBdNzqC5?=
 =?us-ascii?Q?U0QwI5RSMHDi/wrMFLxup+WMBWTuo2hNY8xlSLQ8HEKIjT+Dnv/XGzfCVZeV?=
 =?us-ascii?Q?s/+vi/B6SrZ2g/g8MQeThDrxE6BN6q2DloXzgBcfKKOXO0P8EhnDxnVUinPA?=
 =?us-ascii?Q?OFhCfn1DdzKsXvg5W7EdYWbR7cnzNwZd6SRzqJnDg/1szyl9xFWmTlmYJqeb?=
 =?us-ascii?Q?KHA96B0vHh7AEW+GmdVaMJs0vNfSPHE9hqOUxlpoJAL5WEVLcM3pnxqugU2+?=
 =?us-ascii?Q?9p3qqxTtyaQk1+4+oonoh4lgMxgFgs96vDXgm9bvRFW5eFb8w9XW9YYyjsST?=
 =?us-ascii?Q?zPCSY6fA4AP6JacrCrhCHpPm9rnENviAjUDjlFTx1Q7/rkYmsu4jN8+rIh8t?=
 =?us-ascii?Q?A7WPmzEPpfeVp/p0RLSebPaBrxgiHOZRwRCYmuGR2Xf2mBc35EejGpGp37PO?=
 =?us-ascii?Q?sQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: StCnvRVbVCrm2Eh1wTfqSl77MHmLxpTG2WVF8CHDM+LYDDJY6BM0uR8+MnTUXJXcU3J/LsvwdEEEg6LQd0j5lcI5IJL3ypvRXsCk/mL/asz+Yak4j3z7Vm6UQ55hc8k3ViNvy5iXrO4/ZbO2AY9F3jzVdRpQHxQxot4FQato1u026i3K+c0TOGZ8SMpiENk/L2mhP+c5HhnarxnM1vZ57sN7TRamPdAETey2puRa3QY1z/ihCkJVFnhIyZzrEF/cmq2vX/fFpJLVKoxQPnYN7I5Lt+HnAyKTZk3BO80gux97U5o/pQ1t5wtQuUsEuLBE7VtRdbdkrsXHck0QP4dKVvdFqr6c9+sTxAXqG37nRMM5l2TgRhM1aBc/7fOhPJNpbd9WmMeZqnNtUUaio99+BX/0CbMqlLiFuNHJHsVaggyuEihGFognfYHK40ytCajum3CpfYgX+QI9dj43tZnIyxboP07xKUYdBsP2B6gNZS4Ukq6v2Jn0xssfjvJeJ0qDZ09RszMKDyh0Ynu00pm6yk0xV9dXdaqtnN8uJG4K3h90NXUhtC/MmQ3sGflJ9vcITLg5AjJSt4YqP3WEYw5wkAIm8jCaa84ujfJ63w0oAvQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fe1009c3-1da3-49ef-201e-08ddf43ff7db
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 10:09:33.6713
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5MADsbPSpS1KWoILo7RcPc1t1iZe23xtMss1u65s/iIdjedB0fThxMrlMYQFl5ijYj8+6MOkf+ou9gUQMWIs8dRO+1jgTb71vq45lZYToSo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPFC31902354
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_04,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0
 mlxlogscore=999 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509150095
X-Authority-Analysis: v=2.4 cv=F9lXdrhN c=1 sm=1 tr=0 ts=68c7e5e2 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=CVgPsPjdnkoEphA2I1cA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12083
X-Proofpoint-ORIG-GUID: zQsXecpqG3qwOmvdKedr1kkNTKk6oKcx
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAxMyBTYWx0ZWRfXzNPf6sMEUueM
 zeMPQRgq1O6ORT5H7qAKYGbLks1qHTtx4impfrL/Ho8CsIFsKPKFu5jwmYJr6PjLVmt7mI0yovN
 iokOtVO17zDWpNdM7EBtH11UTuA9eLUyaCafaqWlWnGOrbUyLGrSX5Mn1sZw4ywW2za9O4b0sXP
 UyDofLf6yD9UXw0OZspkMeTfhCTIwAzaWIbMjPAHoGf0Wf8Z7JgVXCV0sQ9t3xY4RES3mOVs9Xc
 aOYorZG/iJh2GQD+sgkLCJhv5sgtDhHtCiQfkildv6gPjGmJbHmFXxduYNXbKtB0uCVTLK0/Pv3
 TGGtG95OTruFrU5UzQqW/0uzLXwBr+/KGOWDboQaCxX1LCissZZgjouKIDBeeYgGMFC/deqeyPS
 uAnpD/WIGkZnnSWkb6BrJ3+YN1R9pQ==
X-Proofpoint-GUID: zQsXecpqG3qwOmvdKedr1kkNTKk6oKcx
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zbqepl2h;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=lNOx8fG5;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Could you apply the below fixpatch?

Thanks, Lorenzo

----8<----
From 35b96b949b44397c744b18f10b40a9989d4a92d2 Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Mon, 15 Sep 2025 11:01:06 +0100
Subject: [PATCH] mm: fix incorrect mixedmap implementation

This was typo'd due to staring too long at the cramfs implementation.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/util.c | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/util.c b/mm/util.c
index 9bfef9509d35..23a2ec675344 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1364,15 +1364,14 @@ int mmap_action_complete(struct mmap_action *action,
 		unsigned long pgnum = 0;
 		unsigned long pfn = action->mixedmap.pfn;
 		unsigned long addr = action->mixedmap.addr;
-		unsigned long vaddr = vma->vm_start;

 		VM_WARN_ON_ONCE(!(vma->vm_flags & VM_MIXEDMAP));

 		for (; pgnum < action->mixedmap.num_pages;
-		    pgnum++, pfn++, addr += PAGE_SIZE, vaddr += PAGE_SIZE) {
+		    pgnum++, pfn++, addr += PAGE_SIZE) {
 			vm_fault_t vmf;

-			vmf = vmf_insert_mixed(vma, vaddr, addr);
+			vmf = vmf_insert_mixed(vma, addr, pfn);
 			if (vmf & VM_FAULT_ERROR) {
 				err = vm_fault_to_errno(vmf, 0);
 				break;
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4ce3adda-6351-4530-92aa-103acf638004%40lucifer.local.
