Return-Path: <kasan-dev+bncBD6LBUWO5UMBBIPFR7DAMGQEIOQM4BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 847AEB54911
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:14:59 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-71d600f9467sf17075817b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:14:59 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672098; cv=pass;
        d=google.com; s=arc-20240605;
        b=KAizUT6v816K3GxNzinw4PZUf31bIrG/agcHxwu97FzQhJ19NlyqPWT+uHtGkpJnvq
         UiUaWzA+lsDXlydzFoTFJMeSbfPdO12ln6q6aKibkjHyJI+FyLlFWQvdbgcyHfK2Yd1a
         zS70u7B1/M8KfraEQghJXzuuQqqZVnaW2uCYHyxtMu+pKGoy09oQI+XpGUemXzuawzx5
         gVCD+S+HN/WsBDoHr82bnR43+izyaBHMwCKGJsxd6CgXNnk8CK0simO+D4rdZFcUiIVo
         OXEjAxc+5fAz3mk6CKCpZPrX4w4JzIlpdK9X6LgP/X5CfH5jgg6O/hNAo14UYl78xndt
         3rvQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yMSZCY8BiVibv42v8TtTp5/Jxo2qkN0BV5Bo2jM50U4=;
        fh=E1i6dqdhHX+i/DumAiV15nSVxDHo8W+9n5ujQIZ9xek=;
        b=XQt1MxkdyjeiN8fugBDqUpU/se3Zt7QQXj0FiPh4cub5LE6Lg/EU7ahirz/+yEPhe0
         qHLFpKeBgzDKvJs4WBXMycw6lr/gg96dy9hqSvQ5z+BvDw4Ft9UZ5GDP90Jcnj6Hk8UA
         nhE+lid+LLRsG5Dr5rT7J0JCuTyjsbV0sT4Zn33aWePI6kOUSJSveP37oC7myhRG6zpl
         2wk2By97wtVaC10fVnApP/K6NRGVOQLv6kcFZfg9bfgwgZ8fTDf2vmXn17rhsi+lilwy
         n2QoLTZ7635rj6oSsIdMjfKtc4+pYRmM3a8j3xALjnPPBp0ie81ORBEFF8lfU67Gw0K6
         xfqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KhVj7WMB;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GGYSLKct;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672098; x=1758276898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yMSZCY8BiVibv42v8TtTp5/Jxo2qkN0BV5Bo2jM50U4=;
        b=jvzGaJldtHexFmbrC+7pN0CvRRONqZrrOSOTV9IefisguVPhBrcTQwy100D5pfxUIA
         3RoIP1l6BXPTRUfcDgekswgcU2t0XpW2TD2OhlViHNU0yS6AYPBZfp1aUbJtkAcpDQ5W
         ByEH4Tyx262P1MrwnvCvvv+UD6cb3SlKr/VsMdDzM6UTvldPEJ/ey7BLjyLAfSdP3WCd
         dfq0jKyzSCdg1ZxYu4uPDYZchR71cgMFMAmv08e7ARddFcslAPsq4rIw/E9ooBsHGkwa
         Uax9y6FVrNQy85AJQSHVBMNLsa65ZflLSLafMH9votFUtQgzIywlh57TJ0xJHKYwht4W
         UIYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672098; x=1758276898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yMSZCY8BiVibv42v8TtTp5/Jxo2qkN0BV5Bo2jM50U4=;
        b=Aj0HqAEErpGWyO+2puwJmivNifkEVo9BLTKFS6goG08QbdfK7UrZk400as8sXPi9dT
         k/OOnDiQm9I8sT2G0bhFHqVETNZonu7PVdiFX8hAyx397jpacANOcRD8oc/nFrrnof09
         reWX0dWscl/4X3TpsQ/k+u6Ois57VW7CCwQ0yvRaBO4mzdWJNqMBREQbuUdJgqPMviF2
         xEIvzkA/aulKLIy8vx6/oWhtsyL37vV7q3ufyf7FV9Nb6Zl2DoHIJucXURMwZNpNDgUT
         Ds8lFcAAzJguWpvZPLDB+ubZwmK1zgU3Y5z2RTNGA8uD1UtXjBxh5yXiLaNDT7j4sude
         1Fvg==
X-Forwarded-Encrypted: i=3; AJvYcCWvUF0WBwA3k2m7vAyVuuGpHzh7hMKqwkPz+lRJOptasXPeoBCAcPpo66PyKij0OchF6djimw==@lfdr.de
X-Gm-Message-State: AOJu0Yxz/VVauaFxGwc0bNLX2o9ueT6ytSMlo2pgeIehpBCv2TtG49Xu
	lZ+ZYbrEuhBYlciQzXng8pg74VWAhz+mtx1T9biNYTioOR2+NV8jqVRg
X-Google-Smtp-Source: AGHT+IFI2tBbC8eW60QgGstLczpzeEe1WiRQyHAWgAuieMo7cjEw6F1SKyzH0w2NlFyforWsMcKqDw==
X-Received: by 2002:a05:690c:6b81:b0:725:86e1:251d with SMTP id 00721157ae682-730657cc05emr17293337b3.46.1757672097676;
        Fri, 12 Sep 2025 03:14:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7oC9khFtJYpc5Lpvi/BBgp0As2KiVdJRIsH19qAQvXtQ==
Received: by 2002:a05:690e:42c6:b0:5f3:b6f7:81b3 with SMTP id
 956f58d0204a3-623f21254d0ls754590d50.0.-pod-prod-05-us; Fri, 12 Sep 2025
 03:14:56 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXHBjaRU3vrM+IAJs8wzYG8Cm0TzpKMZXvgFe2GFyYcS1cizlb6fW7diprZFxWWbNET5MOoE2m0eVU=@googlegroups.com
X-Received: by 2002:a05:690c:10c:b0:720:7f7:6991 with SMTP id 00721157ae682-73064cfe229mr22027107b3.30.1757672096663;
        Fri, 12 Sep 2025 03:14:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672096; cv=pass;
        d=google.com; s=arc-20240605;
        b=iA7SX36tpMhjdgzJAdmggSaQ1NAFB589UZp2hVz9ZprpxGuBd0qRbBsmTevEqRYrLW
         ySWQF7bCMEvfRAzTYF7Ds8z63rp1kyUrbVLJXrc63SCzMf+S4T/8ZUiXPlFM/aK1McBD
         tD3ACy4/7axQ0G36sd7BfdgrjXvlZ0ZcNmtsSgoRclFPWaDeLjonM5XLpksZRxL8TgNR
         mEgAmMQX/6+i7r/IkABiioM7eY/EuwjnG3sfBbTocQOOHSVK+nQZcOXO1FjEX7LmVFdu
         9+j8qGqiR5XT+3OEWeh2BCAp6FgtUB597IdzrO0/zJSNXSOiCFd8Q07vR6YEbIjIb+Yl
         rB2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=74szNepit7JPKNNRqPqFrB2B5M5QEMTeQmyHsfLNhOE=;
        fh=fxoU1dqsh2V77cxUchWkOU7qzZ3JmF6mdakC7cDNnyI=;
        b=F0y+fd0KqqCruX1FhWmeVK/w/1TgkK1kYE/4oIQxnn7O2hXZQXtXxFMBXWEO09WoQZ
         CujAgqcyWI5hldIDaMxhglVOny6pSbHyOKHbz8Bt6JNQHJl6ybBOjIY4endivdzaWXcc
         2UhOlTxB/rkteIvqDvAPhMkfiyE56zYgxtGWuZKgZuyOJumL1AFxQAEWHVqYmCFy0yYD
         8U4nmAjLZnbP90erqMy+cYpyOOsC3prfL+/vlQWvWejirqmv09aYE8jc+0nZg/gtFZqU
         MHyrAHh/k8Bedylm+PtyH/V2cgI9LB1sfW8gRbRAhRyv36dSOUT8R29mf1kqNcxdIMh7
         wgHg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KhVj7WMB;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GGYSLKct;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72f790a79bcsi1585127b3.4.2025.09.12.03.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:14:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1uOLf009834;
	Fri, 12 Sep 2025 10:14:44 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921d1r2wc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:14:44 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58C8uNbh038862;
	Fri, 12 Sep 2025 10:14:43 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011069.outbound.protection.outlook.com [52.101.62.69])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bddpjxq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:14:42 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=th4Kq8gHaEA3bAQmHZs2b0lolEfWI5yr/4M9eiFxDVAUBYNmEz90P8jQ1CpaOIkTy9FIIXB0CWY1Z5+IC+xEzEL4CnYzCtSlfCfoG7dpii7qHoOx6nZgfaADGSlaqoWtahYbRbgp0ovLGH3noNZSJWA9W1CJgecMdD5XAxhgymELhhLXaS18/FY6/dT7sICwJAKx9KHO3n7C8T1NTR7fpnj9MApbdKrldgI/3cclGLhJBBrcD1tINnVVAIvT2GdCFYY3HxyN5D2li024IgHZgoLbkSspWPtFIDPySfI+fU3VlgCLpXNdXEYrzlcnrovVYvmHXmJzYr8nIO7w7Wv01w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=74szNepit7JPKNNRqPqFrB2B5M5QEMTeQmyHsfLNhOE=;
 b=bLgFsCCADhDy+Nq5LC3yDtnqjS7zF2HTNY+/X6tSpKOk2FbMri0XFD0bVpdsa17YHKU3KTmeYb2c80Ly/jYeEv1qHMIjZjJlvp/M/FW2RYfiJZ38lTcWeRyCYX5nVxKEiNwE8sSReENiei82J0QVsvLnUzTFcUi1m55kMFIKQuQBqUvRGrn4A3DdRD9RXzrKoBo3MCqO4YgrIW+d+UQVBUVF+IuZ7Fh6IuQ7XskOV1Nc6/jZdklTGOT5Mnc2b7UcLXOHyKg3C2x+Slp9w/kFEghpMdaNVgmrTqKJVf8S1s20AyFA4YllkWaipkom/K5KEJLrXvpFk1XCNe5E77KB8g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB5566.namprd10.prod.outlook.com (2603:10b6:a03:3d0::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:14:39 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:14:38 +0000
Date: Fri, 12 Sep 2025 11:14:36 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Reinette Chatre <reinette.chatre@intel.com>
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
Subject: Re: [PATCH v2 12/16] mm: update resctl to use mmap_prepare
Message-ID: <b7ae95b6-e26f-4fc4-9146-b7ff3b0a0cc1@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <f0bfba7672f5fb39dffeeed65c64900d65ba0124.1757534913.git.lorenzo.stoakes@oracle.com>
 <f04792c6-f651-41f7-a960-56ca37894454@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f04792c6-f651-41f7-a960-56ca37894454@intel.com>
X-ClientProxiedBy: LNXP265CA0089.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:76::29) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB5566:EE_
X-MS-Office365-Filtering-Correlation-Id: 6fad6b7f-b515-4689-85ae-08ddf1e52e95
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?0lLVPBn0md+x6jXe/pFRYzbHvBmjbNdFXNbik7MpxLR02u//V6iGn8ggKVNc?=
 =?us-ascii?Q?929nruupgCx2fZz6bKXepemJ3cwrzL0M8jRIsKXImzj7X098To8ffr6UZ+C0?=
 =?us-ascii?Q?/nP8umtvgH3Q4ZzlpI3Z1Qtz3X/hKOSRX31TJ+FuveBLnxIpWQqW4XfuUVCs?=
 =?us-ascii?Q?uxXQzURqmY+7g+cnsMTTJIrHk8zfNX2sSCQDBEGtdB+R/vSA2of4f5wgKDWq?=
 =?us-ascii?Q?utDbQ2UokDZVa9PltPOIiX4+/CSCtisO6CTRNL+dQ+g2ZcNpmVQj9LomXe0x?=
 =?us-ascii?Q?DIWjcfcHjhengBOSqgDbm5Jne78GWJI6bd3/vyyA94GciDFhk43gSXJxJKNr?=
 =?us-ascii?Q?3d9SfYEiGTtqgb9xLWgoB4yIhb1KrX3PTvRJ8js49I0tdfQyyxNWcego6rbz?=
 =?us-ascii?Q?GNCVKXfkrJ21RHyxqt531nXB0yfkJKasi96ephdg33IriNMRkhISAxgUow5n?=
 =?us-ascii?Q?OyZ0NtjEADBj0PLH0eIMlAMWnonNE8P8qD6sLxrs9OoqLhhRhSKlDcLVIF/7?=
 =?us-ascii?Q?kUVw/NLSvODheubL5VDlNohJQbejjoFmXnnpLOHZut4daXnAXOmGedY5a/na?=
 =?us-ascii?Q?c7jVK8YOSVKP4ne5qizi+CIG4hbb61W8HPW5qMMBG5arowqM2B2rW1MPOrQh?=
 =?us-ascii?Q?c+GgSMHePmpyKnRWQomK92/NJ1cfQVYEITBUlxOAJYke5BdGxez3wnCQZBpU?=
 =?us-ascii?Q?socrZhYNEcLil/Qtm1CguwThiLI1Mm9u6wE1YOYdrBFu3lGctAYCfDBZhV3V?=
 =?us-ascii?Q?azLdEiabUFKo5HPctTXJfhee0HxwWeUAlnq0QtnRYyQiWCsnDVYgRuVcws2h?=
 =?us-ascii?Q?q8j1WaYzmLJEnyZ8VnURH19ueMXw6/Jz+b+SERk5sfR28aM4TCSsaaLQDLiZ?=
 =?us-ascii?Q?7E1Ik6nrqpwR6Tx1BmnMCAJiH6KtABKcx4+nlFa3Aj5XSTNPklrtAEGBZZK5?=
 =?us-ascii?Q?L7bCuDPiXUok2Cr9XEDRzEj1LOq1sY3EEHjQq3uJ9auKTEutvlwYMZ88Z3ir?=
 =?us-ascii?Q?6Rx2dw25VTqo21St7FT9dKGU8A2m0mRwJQa0ATDSwPbH25jho5BGR2dJIvvW?=
 =?us-ascii?Q?aSc9ZejLzDgo4LIieVVnWi6xTm9DoSh89JsIytMVAnf/1UbBPZkdCHz24kZ2?=
 =?us-ascii?Q?MpewDTogRCVy+/en/ni1Or7nDFcd3+fg8skK/o8PXDWd3+rwsBmzzB6wxzkZ?=
 =?us-ascii?Q?4SpP27NU94sm6nMv9GRCTVVHWVwonLY8xf6iLcdcrlSiZeUtVUoGB6Ol5Bo5?=
 =?us-ascii?Q?PEaWtEyT2kz9QaYeVVDfmGaGi6GDcyE7ulc8D5ze26ZQX0r/4ID+vwBHNP9d?=
 =?us-ascii?Q?+ofEJxms40OATZykYit0JhVo5jjpE3utVki2mUfFKV+9orE/LyL4+Q2nunR2?=
 =?us-ascii?Q?to3NrRIz0QBkm3n268y+1rN55MpbBvIMw2WIocjkfyX80KhfMOn7AC5OENS4?=
 =?us-ascii?Q?uKuvxfUQpv0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?tqCk7q+M+ywRrg54pEQ1/FwfN7+H7hG/C5pqaHrB9iBYdU0flbcZ9R53HCC+?=
 =?us-ascii?Q?LTvCjCJETPOwM1/O4dIpHgb8UoZ0ElBMZi5u5ssYDDJ68ITa/UpDYwvcyQ/5?=
 =?us-ascii?Q?LfZumGiQR+/wZxPjqLS/41pGtAySfufdOsbxU7j6Zy9VZ7i+3m5TMnAlQf7C?=
 =?us-ascii?Q?/MPe2Ob67l0HWKWCEHtLZzZd352AShqMyWVIKxNToQ35WT1OXyxBrHtJWkfV?=
 =?us-ascii?Q?4hYouwhqDiaK0nmjvYclp5ClEUo32yGc0iiaUQoFOZBIxEl4mLzN4iuJcWbM?=
 =?us-ascii?Q?Ltz/opU4dFu1Ji+Y69E8U1NiPvpQZBGNqhCNKF4QoAlV6YqByMDS45IthAG/?=
 =?us-ascii?Q?TevCP/LXxH80HW8GOWlmcE32c3yX575I0XzsWzlwSwF+DKBHVBcHiSMvJ6AM?=
 =?us-ascii?Q?QNJ70iClAe+W3NiWXaLYVt8kYQ3/LZshRst7SLXLxnqUkQcZymNxK7PbBQo8?=
 =?us-ascii?Q?Szp0PzhlWB2llj3xBK+hzcKHzR01G7e6fERpMfLveOtv+tH2fwwCAerrtbKu?=
 =?us-ascii?Q?dwpOLmvL8ueKrzdEOYRipauPvPLTaA/HgaXJY++k+IOFha9INg5Y9qNpw1gE?=
 =?us-ascii?Q?6RDHnOoWHnlAYoVC3qh+UWco32U5IThOwZHbD86JdHNXYoJkcLNysEbGIxGa?=
 =?us-ascii?Q?qWIX4d05BMV/UdUBmahw3QEKHGoxI9+fTUuJGj1i650LKU9xjori7r+k17Ml?=
 =?us-ascii?Q?zLYGUyxX3RqEUdgfKb0C5vwrskvYNDyKhWjJRjIbyNie46YQUgUgqzW2aHGj?=
 =?us-ascii?Q?Yn2SoVRq3d0QR29kJd+7W3m3amBKrXo3BV20crOdg2j8SrdYqkzqSk+Ba7iq?=
 =?us-ascii?Q?08MiqAR/FIS5RJgu0+xQPl+aitvp3hMJ2qg/z3TGx66Y6fKh8YRREr4+ceOy?=
 =?us-ascii?Q?Iz1Q1Sz/2jx/CBDpHIMdKvbXWItlSaAIoKxllBNwUTUTn1OBPrcQrahyCRI7?=
 =?us-ascii?Q?icfp0q8uDfGaFCjdAuRT5QVPBKCzCxFAfnh32LDrDzY3kiV2uO4h0PkF3LIx?=
 =?us-ascii?Q?VN0cDf9/wFceZSbOdbRJOfRgflmrjzuDtknzQmziBjzXgr/HMLgGAFoXCoQE?=
 =?us-ascii?Q?VJsHSdPUTW5TDoWDn02Ltjzv/n1W2YEfJCdNmpEDzBs50JzcK273deSmJ+1Z?=
 =?us-ascii?Q?1oOWSEG1TE6BHGeZop/FLF9qONMNBns6EhA3ApWYkxGSJAEqsYtNbrPYbTY0?=
 =?us-ascii?Q?o2KK5NJeUU9KicFrOjsLgXVfvxE5kBqh/l2/8hnD7UX9syQVSHkYCP+TE+zK?=
 =?us-ascii?Q?TI4txaE8IS+mH2QCWvGeQJxUofK41HtcKjn0J/Aoe7v1P5tPsePXxzaQ+mzl?=
 =?us-ascii?Q?Y9pFrgJr4+riuzKFkOu+e7l6+AgjyfUsSEyrFOEM65J8d8Z8Nhm0BIgKa7ZH?=
 =?us-ascii?Q?a9rBucHYfAx/TtmwT9jB/nfwU4P7QQWgXptdDDDRIGnL7oZCFg7X8hEc65T+?=
 =?us-ascii?Q?yJlgyxkWL8+atYzqkAX7apS3B1fi2N7cZUpv68XQqRJO2Xp6Ggbp8Go2GIhD?=
 =?us-ascii?Q?tSvBh0JMYUDg7t1n+SQjSOx9SGYkKFiTFBVbo6sYfTcZBQ6GAs9pPPhRMBhh?=
 =?us-ascii?Q?atGXTDcshCcDEpx89LoICy6PxmPe8isLJjbIhK5cBT2H64UnngBoyh4h9FcN?=
 =?us-ascii?Q?6Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: WvnQ55FsKGVNJa+dy9b9Nl9IzMc/WBwSQ3p+hAw4SzEYBqFN4ayIbFnVaFvL3FaI6u5oexFLGK1P+bQ8MCuzx9P7KWU3T/1aqsdwIF9CF9O78Tyt6qF02Vnhkxlm+yaXa60yBWEb/Mmd/3Mn7Bz8n6XZv8Eppw6bgyVJD9GhdjH/pWn4aJQWbKzjz13Ada1YUQQ0Jgfr0rYreFO7e+il6gqdw+LOu0OX8wSQD+NbsjynR6r0pyN3qDbfOaJkEW0RLt9TLiC+ZRyltivzJJPgBKpdONGmujFaoZxLiOkYiUv6SiVcVVMFasKz1W7qJWMDPmKQOGQSsx0G/xiOetN18E4sLEABScA2NgaHQSBjGowVbXIDvMUIvqOUW/bJa/Piaw2KClLnjvLbD1vkWriXBINYzLFqOB7c30FccIueBExLhSi+oODqJyd/Eprd8Oi3WU2JifycZPtd706HwzHvyVc03T8f2VLLlpWWQK+tYxF1cmUHz92jmCWej4b70pKMap4KXBAR/9bhRzkSi2VuHEfqqJGVv3bnRgn9ZIA836pbiLo8MspWWZZ4FT4Js4LreEUVFoXFa0QFp3wu3C7dcskMOLq2LnivFWd/VpYDbck=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6fad6b7f-b515-4689-85ae-08ddf1e52e95
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:14:38.8579
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rGzQaQoMUBYLWPnuTu2S0te7fUY2Tfs50XEY+RHWqE7dPg34VuioM6mhE2tbX6EgRjxOJd3JnDRhpt4yuN5kSamY9OUmUKCA1M+7yeQqkMI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB5566
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 suspectscore=0
 mlxlogscore=979 adultscore=0 spamscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509120096
X-Proofpoint-ORIG-GUID: DnovnlT_EjWlQPSfMaqHGWk7Lsgzuqp6
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MCBTYWx0ZWRfX4dNmXddAwSgh
 2WzGrjNM5pv7OaryeZ1vssPbLuitHCXBvLTiLyW3Exe/3TNlK5kfBNdowjkp99W5Zd1979rUq6N
 Er92DI/PsSbB32gmmGhsI82PPSpVvKw+2uUkgTUJ4AZK+VyyU9xhpbzwqdHRE90jmzTzkbldSsW
 HjLUpHpKKRiPICMTGfMR2nV9XszyN4EOM0pTxqNDajPkO39O5Iwx/gi8WAo6HW+FVDWZsWJ2djt
 AqvnFpB53Wdwy5ZPSynt6ZvKqmh4xvqD48V0UiPIrAfyczf166E6U0fsZP59/pSPD6ucA12wrwJ
 OBQhatbWRMO0pApWKGDxfYG/TAHAEVZBACtvYyGNuEm6g2L3UtFCywihB5vsTtDWUyIfj5VvFCU
 PVC3xSO8f5CluECRIt+0+83oL3szwQ==
X-Authority-Analysis: v=2.4 cv=d6P1yQjE c=1 sm=1 tr=0 ts=68c3f294 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=QyXUC8HyAAAA:8
 a=eReYpSRbD1796KMRBbsA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12083
X-Proofpoint-GUID: DnovnlT_EjWlQPSfMaqHGWk7Lsgzuqp6
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=KhVj7WMB;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=GGYSLKct;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Sep 11, 2025 at 03:07:43PM -0700, Reinette Chatre wrote:
> Hi Lorenzo,
>
> On 9/10/25 1:22 PM, Lorenzo Stoakes wrote:
> > Make use of the ability to specify a remap action within mmap_prepare to
> > update the resctl pseudo-lock to use mmap_prepare in favour of the
> > deprecated mmap hook.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
>
> Thank you.
>
> Acked-by: Reinette Chatre <reinette.chatre@intel.com>

Thanks!

>
> This does not conflict with any of the resctrl changes currently
> being queued in tip tree for inclusion during next merge window.

Great :)

>
> Reinette

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b7ae95b6-e26f-4fc4-9146-b7ff3b0a0cc1%40lucifer.local.
