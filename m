Return-Path: <kasan-dev+bncBD6LBUWO5UMBBX6MU3DAMGQEM4EYHZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B2C5B59FFB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 20:03:12 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b60d5eca3asf143985971cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:03:12 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758045791; cv=pass;
        d=google.com; s=arc-20240605;
        b=SqR3We3rnRGwuBi1n/2mbAsV0GPaD5jvIngMQvB/zSTtOSN3Xa6r7UU8BzAP/qLGpB
         HzLMt9unEOGl0sJz8U9CurfIqMrfhGVL6OoTw4PxlBPf8XGmfmqZt+GR9ukWg5uRCP+4
         surufM8P3UUOpgL9Uw+/wr6k0Ph8C1nEWnH5jR5kFV5v2gD5M7QFPT524k3XziveFDvF
         kBZ0967NyZcfDyPK07+iBuYt1TOhsAYnViyEInG0qvtWGaUMTXzXT3aYnQ3y6u5HUAkk
         gQ1x2Zj1rrBNmcMfHYR5OTutREzX++9eA603+HuygmgQ/jvFxkGOPYuD0LLcPBbR0xk/
         fkcg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=u8XWFLLDOsBahw4PjkS9IECZ6dGpyORGCovs0J13WZo=;
        fh=UXx5d5XmWGxbSorqOGeCoOHjYpK7675294+oubWevPM=;
        b=PdItTc4UBJzUtzz1gXAiOI4CZM5M4U24aLascEXlI40A4VPgos2vdmxpLnX9rjuJHm
         mrbcS8MygsyyajM9AEP54oSAcCEobGRFUEZi6AeKnmc3G0E+nSVsqDunFWAW+gy/uiYm
         I5tQn1ZBVdshQ1s+u5BVRQtZNeiF/zJLespw984efbjrFp86GWVbKJbZ8oMQoutU2gF4
         efAyoAxn8BWaPAGIkcOUXxrNfAw+DOAUSJ5svuJADQ/mW3x45Jsc6sNCOAHgg8C9sl0+
         t0QMIvK6mNolamqAZ+XGdy2wrs+q+2BC1OOcnLR9wkS5QVSmEYW7WY6cEtfOR1s+oAV8
         /3+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lb4pATuA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=qrEhxZYF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758045791; x=1758650591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=u8XWFLLDOsBahw4PjkS9IECZ6dGpyORGCovs0J13WZo=;
        b=I/2tI/wuSrY7g2OTuNFxYffjG/sofIhd3SPaTMH9M47qFYp0eSlRAcdsj5mzNQh2XW
         BSqpfOjCOyHQfv4XUNRgzftWYDyxk/7Frq2gUorXR9vUv0hfIdCDCWLq3RMwsjC6IyFx
         OByKSsh2Uiojrr2NojEGPIxfmyDy+QqPHp+Z6rfCnHK/mhiL5MpFBqVqDGZtIxOO4Vb7
         XFBDarWdT2bkH46VF6res9NjDN2fVA0sUi9h6Cx4VSlP3tbYiPgkc7E150NUdhYK5hBu
         yxCwNuMpGzzG/uLNQsBu5t5a3BKMbsHxWLORLOf6GPYPxSBTW3ElhcQRyCqQGXKAwLeu
         sd1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758045791; x=1758650591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u8XWFLLDOsBahw4PjkS9IECZ6dGpyORGCovs0J13WZo=;
        b=COkDwl6lz582iyOrONTsosBIgm6fa7HP+Q4wgg4TB/eEQxjbmVyV7DToThJhKNIMoL
         5EjBX3WSHNz8zfZEz3GFJNpLEn8QfkaeoZquPOZm4qA7JJd4QVDdvOeR+LOIohKXvwud
         PVCpOz/z2G8d6XhusobRHSTgOFRn96KNqQjzxUnTmOEn48/wI/Kv2pRvTKrx45wHrp7Q
         Tw3AWy0B9sQBAuk5TMO73iUTR1GvklcpNBv3ngBlNHCAVlYU+Y7EdiayfLi5+rQCVE7J
         K2/Wce4/16BiIKR6P0UTyYrBuuNqdFEox1x19O+sTKCtPIvvA/LzMvmVpDCQtrxTB3Ai
         A9WA==
X-Forwarded-Encrypted: i=3; AJvYcCXgagdvaNiFYmZW6KhzaBprd/y09gKlfZiuMnTNjXFAL1WNxC180JnIuKU7cULYaeyGI65QBA==@lfdr.de
X-Gm-Message-State: AOJu0YyHYSHSMPXGLJ56cEvkVazZ1IMSCdqb1WwHBRkP1cySEuyxcBxi
	rZrmd6dGQ1Dw2zwysxdiTbr4rmjjdUmo0WAr+zlMzQjc5pZ3ceEfvo0f
X-Google-Smtp-Source: AGHT+IGHAf9z5gHivYzj+jezK0VKddfq8gs1wUsQB5hNZtv+KbqVD46TArZdDgXmjJeEkb7fQK8WMg==
X-Received: by 2002:a05:622a:17ce:b0:4b7:9438:c362 with SMTP id d75a77b69052e-4b79438e5dcmr178605221cf.33.1758045791335;
        Tue, 16 Sep 2025 11:03:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5fJhOxEGzLUCTfhFIim/QCvnzP4O1Cp+5Ah5LXpHAGKQ==
Received: by 2002:ad4:5cc1:0:b0:70d:b7b1:9efb with SMTP id 6a1803df08f44-779d37886e1ls69480306d6.1.-pod-prod-07-us;
 Tue, 16 Sep 2025 11:03:10 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWOnFP+dewVt9+hEILV+5WDVD6M1Q397cKpHDhW9AEgDyINtWbkPV4rjosUnFhWlnrVbJBmEiDA1U0=@googlegroups.com
X-Received: by 2002:a05:6102:c07:b0:529:bfd2:382a with SMTP id ada2fe7eead31-5560e9cc071mr6828993137.32.1758045790337;
        Tue, 16 Sep 2025 11:03:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758045790; cv=pass;
        d=google.com; s=arc-20240605;
        b=cysoYq7tNrJ1gwpZJ0G8usi5pYCMo2ZHqtKK9Ix65t9MhFe9kDCwLNrGXKqV5n+qsJ
         Oy0B+XlRf5cnhosWMpnGJbEtaOf4eia+mA1GF/M3WyY9I9ASrScunDII7M0D6tZce4VK
         gnst9aNS6XyCCU+WK19i5QxOeUxMXv7yiuz3lbhVXnbk/Hqfa9ife9/tbW5QNOuNCb0y
         vof3g1dpBsw2Knfa/pXE5YCx6NOBrEpp67/2zqJYJmJope5O1kh/RvZAHRwGj+Lj4ubC
         t6OJ0kvdCy/WkuLfgiej8ryTax44hsW2NsSXW81YH4TSqlaemzVGOVayy+8RLdOUDQPy
         FjcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=xz+Z82U/O8OJmhyWPoqrstTDXlMFSWqi3gaQCvK4De8=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=idfZOPjcXAp8vLuSkwOjvQPi6773RKg6wFEDd7vDz2A58Cj7DtRbpwsSzT36x7BFud
         2bn5LUZ/SdSm/Y/x2R2Rsdme+Jdm674RRpTGXXu/Ua6eli4EvZkvvoYKDdKzm5ndkUi1
         zeOxN+oDy8V4gnyKCpAY1NuqLecEJDCNY+4UIklu8xLaGXzsxlM3u7vuC4qPfwPaLFum
         5rWOzUKnQeK8OEfTDBEZMTAv3aXrRys0sbGULo6t8FCSlr4fNWsAH18z83WzI7N6rDYK
         0XrWeSydrEyjncErvA7VtC+bOkHjqJAH2wJTRit+vF5dXuC5ToxaJICDPilANas/kls+
         uUJg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lb4pATuA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=qrEhxZYF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-78d59db1cc6si1037646d6.2.2025.09.16.11.03.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 11:03:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GHtwrO005615;
	Tue, 16 Sep 2025 18:02:49 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49515v56sf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 18:02:49 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GHJ0pt001628;
	Tue, 16 Sep 2025 18:02:47 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012015.outbound.protection.outlook.com [40.107.209.15])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2cyxdb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 18:02:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=e/4KOyBYp8eZsVZG54GJ7vw/IgpVjlXiLDkICgWPENDwGRPSoc/BAQIi0RJadDY+/lVr00OWriBvfX3+1hornINVWxW+ml8w49eGUeO1vvsrqcfCwHH2+c8SMLIymBvpZCfyToJPMWvIVg0klv+I0R3QI3ky/rshSM8fpI4qWSinehWGQ9ZNTshjgueOP5jZJDJIQ5wMr0kr1mkWFgirpwKijhP9LAgxuo5uslYY7E5xsFIoC4fWVCxbxwwvlEvc7wzs5pwDaG9cDdDtp4ob5Txu3g/1FhfdlraZ3RXAuLUF9auZset5bBvAl3jh1uuPYVpKHKENtr5IJQGAeFC68w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xz+Z82U/O8OJmhyWPoqrstTDXlMFSWqi3gaQCvK4De8=;
 b=Jx+rwtvbqLAaj4kjO4c6mbxF5YHvtpAmTcZDevfOPPOJqr8k6lZlCvRV7Ajqg8QxOtfnPzr2mH8wwef+DawyL1SApZoa+J0sxDPJRd5ymjvYxhw9M9gbDkWLY6UCz2P1tlD0l5w9+BRrNcLQ5T87AnpGv9RGNhV34tZ72doD6pLX+NKrz1XlIDJL+1V4RM70RBy/Ut82a7jbXKVIACLgN15hQTzYuBZhdVDBlFDekIQ9vGgRLpmAIkbuq+AOrPcsG/QUyU0sBJYRlrH6wECClgW6NY+0u+8WdXjIMcngVVRmmsJ5G1dfSTkB77mSP+GbNmsLMTlBnKEcTyao9OX5vQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH7PR10MB7695.namprd10.prod.outlook.com (2603:10b6:510:2e5::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 18:02:43 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 18:02:43 +0000
Date: Tue, 16 Sep 2025 19:02:41 +0100
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
Subject: Re: [PATCH v3 12/13] mm: update resctl to use mmap_prepare
Message-ID: <ef36f24a-2076-42e8-b9b0-0a64238d15d4@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <381a62d6a76ce68c00b25c82805ec1e20ef8cf81.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916174027.GT1086830@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916174027.GT1086830@nvidia.com>
X-ClientProxiedBy: LO4P265CA0071.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2af::13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH7PR10MB7695:EE_
X-MS-Office365-Filtering-Correlation-Id: 9e33a949-0a24-4846-693e-08ddf54b3bac
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?xjjE82MOfLNkUhf3ogu9z4FDMyapqZj4ebjBY8Hk3PctZ7F69XaNgIc/uiIC?=
 =?us-ascii?Q?oPmTW1sVLIdoEJw7rlSHd1Qb5cf/My71Tr4LIsUCkAkdF1peGJA3jYHuH8qa?=
 =?us-ascii?Q?pJ5L5xZkEXiCPIPYMAId1/4uvB6jp7ZixUeN/Gl+pHfA81eEpzBAAYR52nTW?=
 =?us-ascii?Q?cgIoF89eGTGfrByqdcp+FAtg3BsvRlbniVWihAah8eBgTDmf+IwFL1QlAgSZ?=
 =?us-ascii?Q?lp485vzmnk+yKK4vid9DXvZ6wxLK4kQom7e30Z91L6iMUf7qOHxIsqOYtH52?=
 =?us-ascii?Q?SI8wTAnC89ZJ/fr00Qg3J4ShNI2PFD1cu6M/2+sHvnVgjIq7WXlAl5EeuR4V?=
 =?us-ascii?Q?7DXJWdn6bbXnqxCtUMHCudWYX0huFs2LsA/1b/2C1yd3YnqiAXmDhxp/E4hD?=
 =?us-ascii?Q?E2RmVktCAopROMLjAdglKJj/PEL0UjFY2B0tKE5VDQxZYbkr2Z/TKTHZiLDW?=
 =?us-ascii?Q?ISobTVQDoagGPxfUlyXM1c9x6G0f7veB7snq+Oq6LLfGXQGH0tYfdJrcJp6m?=
 =?us-ascii?Q?40v/jI3xs+uNSiY05+olrUPuYIujfkG+K7CA4SiJBCuHFjftdTslscphRjXt?=
 =?us-ascii?Q?7YOrdCVco9+3kgOfUDjbUTapYVGQSwih2BDTGn7ObC9M6kY0Qktyg+YcXRhT?=
 =?us-ascii?Q?kEbPpueKYvwBCKWwRDJtHi2RAikOhG8IAhmvuZbgmGaWTpx6PI8vc3j8DGKJ?=
 =?us-ascii?Q?uWrLI16/iLOACbebkXz6UszfGjqPTjA4Hn+ozrLdh4dd38+KbSJwBAnDAlSy?=
 =?us-ascii?Q?WVEGBFdyZacpLBWSYoy3HX5//7yRV4TTrRA/78PS9AKWJ74jWcLJPJA0ZRIn?=
 =?us-ascii?Q?a0tvHnm2K9jEp9BbOPoYaVNXWVGWDXBSAIpxvtjmKJAdiVCnfgr0wcO4hxzC?=
 =?us-ascii?Q?nbQMrSZ/EJsRcO+B8B21+5n5kFJyzkRWfz4RmgaYO0F7vUR3S0jTHbouyISI?=
 =?us-ascii?Q?VUIMuw+2PCaYpp5w31G/I36oCS7erWsf8sXdpJLaQRMnWb3GclQnZqQin0lv?=
 =?us-ascii?Q?+DsbqcOaP9AjlPUzPegMSqj32zcDzYtRbcoj7v/f/QLktTOKranpGaRPhJGx?=
 =?us-ascii?Q?Od0FMP5zrDkQCzTmVB8zxWAHQuRG+rAGt36RTLlDBhEtH0MPpPzy3wrjGvpp?=
 =?us-ascii?Q?WRpTWB/m4AtBttvC+os2I2evsnnW4KZhlCI301k5pM2GQUhseCfUetSeuKHb?=
 =?us-ascii?Q?S9qMSP2h8JogdzaSfFXoz7UGRQRoUaE0tJTE2QXsNHbE+FbMI9lPWSE5g5G7?=
 =?us-ascii?Q?U5svTNwnk+H3MjX0UMY+cE4Plq03X3QE0IAZjlst3uRQwyJe81p8UGflEy6K?=
 =?us-ascii?Q?ixcsowhds5zOjJaFntr2SBQCAjWGEnhHsZ5ME5g5VkwFdugGBpgyJTHsXPTB?=
 =?us-ascii?Q?2k8IS1UdhWVNRYYJy8g/p3NGT2m6GMNsSrJ0Hjc/dVigS5YRy00IA5Z3FKf5?=
 =?us-ascii?Q?ppj72m+9uVE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XHRHg2C10YsL3LnGTblK1tzOLGufx0EsZK7grNQbzCn1VK9uFXXqFyLPLlnu?=
 =?us-ascii?Q?WubJJ26SfgNHfXPdrbijJbnoeEntK0mVlKA/CXbVWh9a9sR8FwPb089ecme6?=
 =?us-ascii?Q?ixl3k3ueQMDEbFjgRLxepVZN/tRLs1u5s9wwxDmeGmIVTNRjHCQfGIAW4wkj?=
 =?us-ascii?Q?Vowpv9DNwya+lGUtlPvcns9oGuGi9wW6b8eCk2DwmM+7PbS+WbNQYK+Fd57b?=
 =?us-ascii?Q?LyubsNYDk2RNAmhQdsQaPkMeaNigkdlch5go1Gfn6XOXlWPwyaoO7dIvTpMx?=
 =?us-ascii?Q?hPpirttbM7EkEE2dRZu9KrbSh5Zcx+Y9Ivt8VwRAxBd0/A5YnYBHAxny3eD5?=
 =?us-ascii?Q?Xs1aERknCJDpRGAD3kva4fMzjwYT3lB2TQ4MTz2fECbNm+eYkg3UFd7UZ40B?=
 =?us-ascii?Q?oC+5a9ZeCYLL5YuszXu7Hygga9McMMY+92RLlGdOhvFqPWpCuPzeQg4Yxjro?=
 =?us-ascii?Q?Mt+ogqO977C1IKMhVwRwFGd9/ECaSU8234BmQgWtMj8sjbn229ou1Pbi28lO?=
 =?us-ascii?Q?DoF0eM9V43DJ+JRpgs43cWtWoBREDNgnDEcPm0zAAJrwSqorAq3a2ybMzRy/?=
 =?us-ascii?Q?maN5oadpf8R4oRohpGXam1bAuyBtepyZrbzMwOEEoWk0YdW8mFZ0ahGnHj3/?=
 =?us-ascii?Q?QiT1PQGeUlh5MkmmjCof4ZF0zLTvd5ER58DzyATN6aTsTXl4tlptjxmwiZHD?=
 =?us-ascii?Q?9HoN6jW0/DJDM3agWyDbDK0flSD7ZN2mZAQc5rNY9GNaDASNAC4CRp2h5vaN?=
 =?us-ascii?Q?zZRe7VkoQFlWXRkUfrJLB2x4OYFCPVKgXBEkP0oMKDPWDvq126oC4ZgFiDYj?=
 =?us-ascii?Q?tH98rhQ7roiW+zRWrK5bwfr/xX11sRzCR6I5TQYVdtY0ygSvOkzd7vKKc0Qu?=
 =?us-ascii?Q?7NvJmaxTRBdbfohI2hBTDup6aAbc/LOcAX5YYCaoBG8Abafk2nZXyebqiQq4?=
 =?us-ascii?Q?GRxKvYdU2n/DJrGYVTPmyAhqTuK/udKmI8jO0W0hYYx21XZ6Z61m0yUsuRKn?=
 =?us-ascii?Q?YV7BtnDrNsFGb4v9MVHI/iRauhIWD/EZQPuQcEZykor7hD2bchyWOU01QaIa?=
 =?us-ascii?Q?o33Yjk2gDmhK5yNzvMzehxMntDi7WY33n5L7H33hIIYFeBMUVBaYrdi53YeJ?=
 =?us-ascii?Q?17lN5pOAeLG3xMty2WF+etnz6U/XnkzG7/MLRslntZexmMRDVq5IYN3w4Kh+?=
 =?us-ascii?Q?mlz0esRtv2TNechTih+eZDH/Dys4JljEK9UcyfDhrBpM5JPyE9oiG5R/d/r7?=
 =?us-ascii?Q?yqjC40sb4bO52Plp9hAFpuoBgVoIl+f/kH1Klto5oabE3Kbw6UB84nndqPJk?=
 =?us-ascii?Q?+YFFV0UPid38hd76GHhEbuCMkYVmP4qxbS4zuQcMjZZX0Lu+3TQznT6263jz?=
 =?us-ascii?Q?87inlUXSQjmw0pDSf8SWADWtZ2aR9g7o98n4lAxUJLlt+N9w2FbQkgS4zwVZ?=
 =?us-ascii?Q?xCF6//WPT7gb8tpJvfMwTpA6EMpKkqrLBRfOWNfZvTGEvsEhlizQ8iCfMlNr?=
 =?us-ascii?Q?wCbp5APJqck6EL5he1QUcAt+nqbU35zkSpjeCqKiyFToJf3ARYi1Q7M2JndP?=
 =?us-ascii?Q?S8Ba7sVPGyp79Ql5w7VTmNeHT9A4+sLzK4UdLo4U8tj8xK9dRuMOmha+tS3y?=
 =?us-ascii?Q?Yw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: RSE1Ee8EobaWtuC+44AQP31Y3aIB0f7W2HnPJqLibDt4uILNckFoIW0hVTx45ic/6LYJ842Xi306X/8m8UiIVghYp5TlV0Sm1q7nO+Pv4vGfV//fOSBDXTN4RXgFKNt4f/Fb1G1Pn0b92UIvzm6SYIfMHfrurMcFxsqpueFWrhtO8pOJdw8VzN3nlRQFUNdMBWtYdk+UKtKpk4PoohU1ly8LID9OL6SuGgD9JlAo9QPZBVgw7Hl8BdE3w2XwSYOVwukY6ZYScyVNe1HMUxbF9Iec095DnqnVdb6fFFR6mO39aQsyD1TZ8BfPtoQULVbQ/wvSSV5nDSIZgdwh8Jr51SytVW16yUO96CBFhOKDz0/pkuJxx9iLEmUouttItomyxkRLv/xRav7fIiBL+HZi/E8g4jPYDrJDHH0dkxEGz374mxb84HfJCJFWji3IaBluaSmsQ8nZQa3PgBhrZp7HwxRg1L7I8A/KjMQVnvRazzLOZ4d373xdejWMCUAH9e4EhtxHkGT/4hwA1wl5iwQZ8WdMW/s3bjFy2CFI0pKhyuCWmNAJZBzrpqx09P/V8k2k0I8C8WP5qjdnDPieUpwHqPSyaDlYOvU08KcpCuAirVE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9e33a949-0a24-4846-693e-08ddf54b3bac
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 18:02:42.9782
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: e2Of1oR9ioRNOH6XzNT3rYAIAr3lOtD1n/43RssDpXkHw3jFlZm9uxSAyx8BxKjkhe0IelvRYJGbG7E0n1BgjYQIN9i+BKroUCOyJ6CRYmY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB7695
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509160167
X-Proofpoint-GUID: 7JGEZG8HB2M9FRN2nThAgNFav9Hiy3JQ
X-Authority-Analysis: v=2.4 cv=RtzFLDmK c=1 sm=1 tr=0 ts=68c9a649 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=QyXUC8HyAAAA:8
 a=Ikd4Dj_1AAAA:8 a=QKhW7uEfI7EPC8uQ3rsA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAzMyBTYWx0ZWRfXz4wtpq8o/mM6
 gYOm7na02Hdkh8cBwypi19QdlmlnHBiLbTVikP8z8NWYMXGiMA0xJ4BT3aF0pIvkCAQYRk/0HQM
 BF+6JQCGnpPyzQqdeB0vBUG5UcSCwGRZKDA+QIwzIm8Zwe/7hrroOW8XiiKm+b8IJ0WGfUTqufM
 hO628hfJzlaNvoLqhbtCj7tbwEQ6SnwT+XT1TJ5y2A4CNgFSE+oNG4cQ6Vb16Bl0oCk2luAyD89
 RfzGkSAA0CfCEAU/4Mzui+ghwQX5PG27B7z9TZRGSioxCZ3GFfvuCHQNdYCPZ9DpoIlrHmArDgK
 gvZjyNSGtPpS35yNO8yEHUY7u9f/6nlih3pZu8tOrQu6mKuBU5k8bO6lK+grC+sspIDlu+8//MJ
 ZMBMDrM1
X-Proofpoint-ORIG-GUID: 7JGEZG8HB2M9FRN2nThAgNFav9Hiy3JQ
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lb4pATuA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=qrEhxZYF;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 16, 2025 at 02:40:27PM -0300, Jason Gunthorpe wrote:
> On Tue, Sep 16, 2025 at 03:11:58PM +0100, Lorenzo Stoakes wrote:
> > Make use of the ability to specify a remap action within mmap_prepare to
> > update the resctl pseudo-lock to use mmap_prepare in favour of the
> > deprecated mmap hook.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > Acked-by: Reinette Chatre <reinette.chatre@intel.com>
> > ---
> >  fs/resctrl/pseudo_lock.c | 20 +++++++++-----------
> >  1 file changed, 9 insertions(+), 11 deletions(-)
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Thanks for this + all other tags, very much appreciated! :)

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ef36f24a-2076-42e8-b9b0-0a64238d15d4%40lucifer.local.
