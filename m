Return-Path: <kasan-dev+bncBD6LBUWO5UMBBKVM7PCQMGQEXLALQ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id DEE54B48EE9
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:12:11 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b5f92a6936sf9594951cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:12:11 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757337131; cv=pass;
        d=google.com; s=arc-20240605;
        b=V5y0HalGg+zJq3jPZDzAlinxFvN3IdkPiz9jG+sG4x59lwzbZOJ3MWOvwTug6EZZlq
         fkAnFGsJMRLV2/d2zVLHd11jlJnkFFccQBVHQDWSSp37AsQFhuEEtMJ/Ax7+CiJN4jej
         ksHdnx8YsrBz4pmPbly+1Dx/hMFzV/JlMBfCE+z346VqyaQSpsuyBYx0r3zW1JZy/oWj
         w8LnthNYbtJXH+nrja/xlTS+CNCgYjiHbNFrEMgfSL35bnRtn6IMNumLqijSQCNhv008
         mRcL/mjNAS4qneMzPsy9FPTBoPEw4I3FNhHa71WabolfrTO9rfmCD+YjMsGIxObcywIs
         SLzg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=alUAsJNgmABizBZkC/mkntoXQQw/aKLsr88HAgnx8Lk=;
        fh=0YTx6GRTWGljW1Y/WA35uphlUqdgZBLmVAILiCpBnIk=;
        b=igEDf7/cvJiqc6rO0GWkuwTaQO0RyOmV8VEdWtCpLthPDcZ7DdVzyY9o1BXou/uJ1B
         Dr3M/NzkN47zjuenuBMwiimVQnmwb4cjcb1QmR7VrgdidN85uLMw6QsQ/0f4XLhSxT4h
         z+2zsUS3d6dx1MwCZxPzXlOS+6RdoMKMqDbkxVHtLLp5Dkw9l1scCPZ0JdMHux9dn7Y8
         865yJjV0EwzyK31QIn9YLo3k9rZF7vclxExGkPwgu+FZpw17GwW4yAh98mzBiPTHQH+E
         cq0I3V+tAT/KOaw+O0AGdLs2YlldzQqaYZJqwqun8ObOVBRDrUDcUBo9clhI9wlGTO1t
         eTrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=aVWI7bsU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OuP1uHjV;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757337131; x=1757941931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=alUAsJNgmABizBZkC/mkntoXQQw/aKLsr88HAgnx8Lk=;
        b=nY31UCv25mEteGtDcIIihg47cqIBw+wJQtIY2MNI5j+k37IgqBMDheIE1nS2Jiw2yI
         sTXbI81lnrvKe4TfMRltdV9hKWpYLAnbPdClZsIFjOzvLuflcuTLVRWmNmqYOS3+E+PW
         PiZEEe213nDxBj1X3GltB0h+GqZmUf1OIl68j1UWCnkq1TX7gz/oS+yX1YA/E933fSDE
         pPQSSm+Qx+WbZjLFepzIA9byFP0qd5V73CNmBDXw73JES19pSHhJNQr/6cZyUjVVm9lB
         bY+vKxFdSjAaAdOqZyJvr3Ejnc90JUkybgw4JXcm9PnkSJxx48OB2/vPgSunNmC2YhqU
         Egwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757337131; x=1757941931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=alUAsJNgmABizBZkC/mkntoXQQw/aKLsr88HAgnx8Lk=;
        b=iLNrrvYWKQUPYmYLcRFg1H29/3b64yzIF4Gezw8hPG+QevY4WkdmZPMCuSEYVNId4J
         N6BHNK0krshJGZC7zcu6D505SBFcdQX9jLFM/Z+YURyS385wJ35UzgYx3g35THjWbX5/
         l8ZhRGqZj8M3PsoSLSX6tRCILRFAyUnwMUGRiXhCT/lys9z56xlzlX0OI63Fuz6hpKLw
         4oCAgWM3O8zgaPBm6+EFQ1jwladIXOJusEhGTVMQyfu6YUVyW0Noie0kg9Sj0JUEXkwd
         1rlG8mEPl2BKS6xE5Evfdn8wAtXD8jfvFSyMSkhlm+lanym4/LIvsIJAU22TSSGgwoUW
         JWYw==
X-Forwarded-Encrypted: i=3; AJvYcCV/8RXJSwSRqXQ7dxWEkgrolSt01v+K29yl7XolXGTbviEr5S02wButWnDV2L+JrcNjIDubhg==@lfdr.de
X-Gm-Message-State: AOJu0YwZfEwk1yFZ5sYYyu4E5M+8ItRZ/CEPcb9FaRQrZTmi9pmKsx0A
	mnOycgjh0vyUq+mqpXgv2CA0WRieTm/P2eHI6YO30bszsQ+plunsyTOk
X-Google-Smtp-Source: AGHT+IE8Ag4Cd9Rk2ksjtUNXRdM10ypzbmeYTstv/kpOnVANDyLyd8oRFLQWthLq/5UqgMi4QjsKQw==
X-Received: by 2002:a05:622a:412:b0:4b5:d60c:3f33 with SMTP id d75a77b69052e-4b5f847ab52mr57481641cf.13.1757337130565;
        Mon, 08 Sep 2025 06:12:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7bNcwPMsLPRyLMEkyFwhVK+D+44kOxMTm/HXxSaCV9rw==
Received: by 2002:a05:6214:c4b:b0:6fa:bd03:fbf2 with SMTP id
 6a1803df08f44-72d1b4f0910ls33844736d6.0.-pod-prod-00-us; Mon, 08 Sep 2025
 06:12:08 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU0+A1shPqFES2Rk7i10hMY7eJWBUxO5eRyppMD7fy04CB4OYQ9KX2690V3sD1kduhxMHJrF+V5/SE=@googlegroups.com
X-Received: by 2002:a05:6214:2aac:b0:70d:cef4:ea42 with SMTP id 6a1803df08f44-73a1bd61d99mr71127226d6.1.1757337128507;
        Mon, 08 Sep 2025 06:12:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757337128; cv=pass;
        d=google.com; s=arc-20240605;
        b=gpfO0jxa7YsUDegccz7z0hkmgASn8sPQpsipwEw4EwKbwdNPI9hFaHwNK6ikIMskoh
         DK4PrDuTk0ft6/9dFXV3/0JlbkPLIwsqgU8X23Cedp4FI3lEiAKkWV+5IlpRULFRi7fb
         HeG3QNDSNAiTfhg9dhJLrqCRlEuVKkXwDT5yAGQ7CY2tyAbE65NgSvYBQfMME+MWz3RN
         0V3LdF8EowvnWhfmv8mCSuZ4dSsoTgMpwkjSrYM5gjMC6ZnDoIWYMOutSTh1EH79KqBP
         csNzNt2Di543ZVPiQc83sYF00rRZAaychlnlsBGA1gznjQdpLxtgKxpgjj1GE80AjZ00
         +r+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=YU+Tu05/qHr4538krBA/Kl4wclo2Q1y0o2qsoqpFs78=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=jrsMdc7AHo2dADtX4q+Jj4JnuGEwVjIdNrjR6gYCk/RjTmmTEKnvViiBZM3DUJIAbf
         ebRoKPqzXBVTloAGy5l0bJ6JH8Sebd4vKvXUzo/TUiOdx+pTXWyJkxncIYm2UZ6Z+dVJ
         Gq5JS7eiBnbRj2Wt+UhubKDo8FtGVbDvXJ/eLj29h6+6o01VlWH/vx1a4nsXbWfu+ju5
         8dp6PooHllb0TW2JsxB7KUbhCdEbOTdPaEFhWbyzPS5NfL6VuM1fasvDH2jzGvqNHAnW
         uKLiAJ8NmxGceU2YK764ZG3cZACPoWzPg/2JkoXt9duv7Awsysq1jBzsn6wFScme6WcM
         ne5w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=aVWI7bsU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OuP1uHjV;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b14475e0si6825536d6.3.2025.09.08.06.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 06:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588D0s9d000588;
	Mon, 8 Sep 2025 13:12:07 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491y92r2kx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:12:07 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588C2iI3030831;
	Mon, 8 Sep 2025 13:12:06 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam04on2061.outbound.protection.outlook.com [40.107.100.61])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd85ny1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:12:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=j23QdWw3/auCbAxNg4zz82h1Gdi3HEmOStSTbMaZh+nglKe73Dg0S93haclLnaMn3Vt87v27unkQq4pJDSdiNATczb5PpARqGQdtIUhceJEw0E/L9X2oVyMQfhAswfk0WDg/HYRC9pJeWUqkkPjcwf+qhlnlhOS8M9rw5/9E7VL5YaiPHY5GNDzH+tOd+gDW+oKyTsbcD/sMoo6Alyv1rN/JSkZaqjxK6gtzLkq9p5F2X92iG6UV5bwlnttZWrExjMW9OtUKfqzZWCOVS5tnPFpJOwnUjxsXPiu4S13UhRnvwqLYzARVD3EBZj3Xso0vF8ImQP3fWLGmFfAXG4wfpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YU+Tu05/qHr4538krBA/Kl4wclo2Q1y0o2qsoqpFs78=;
 b=Wh1/zn2Y3h9bOv0XEOEv2da8agtenqDqIPDZSM21u6oR3rh9U/wbsI5L9e3y3pQDEDSXNYMX6nTo7JGGumyRN8VqvN/aOzIR9TXw29Zuj0fbLc8MKphLbTyA/2embO4Vz9I1R54wfmJQc4/5oq+ZacSabTL13/zjpjPn1mELv1tDnt/xtSKp9bbAwWnVWyFK020SZIi8Ud6xFxOrUR1lcRZa7fiuoNLrluDeG+2o2J8tykM1CeARuivGGC6WUlp4EVeYJpZ1vpupM1UMmWyFl1Ak4+D9kreW9WizTF8dR/In+2hWCPrILjHn8l9fcvBY/31f+PBaY0v1cN/2+L+11A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by MW4PR10MB6345.namprd10.prod.outlook.com (2603:10b6:303:1ed::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 13:12:02 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 13:12:02 +0000
Date: Mon, 8 Sep 2025 14:12:00 +0100
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
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908125101.GX616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0434.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a9::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|MW4PR10MB6345:EE_
X-MS-Office365-Filtering-Correlation-Id: 30e72f36-0b5f-4875-7832-08ddeed94d0e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?7dhe8hPlnAlCFZ30RY41AzG1QJuu0FZelXFaI3lTEl1GOmwHUXcBbT4DkkEq?=
 =?us-ascii?Q?uN6m7KLJ5z0B4v/Vix+wzdnm5hxhx1sV8uqszE1bzei4gmqJQbYWzlpzD7EV?=
 =?us-ascii?Q?8H5ppPXfNy8KBwYInQEHW5oQqgNIlhcfiFilG0Q9yBTqisxak16rwJn42+oK?=
 =?us-ascii?Q?cPZFw3KDSVovmPkY0JYOQL/ivmiAt+FloIN3tR2x50N2Z95g0ce+Fq8l/17A?=
 =?us-ascii?Q?pjlS9Hzn9Dg1ffESw5aOHbgJbF+0t1CRiw9VJ2yCH1mupcSCUuK8pjU4FbWC?=
 =?us-ascii?Q?IEYtjfMhDsJWNrOsM+tI1vf5Di4drFzF+J5k0GWx0y3Jqma++G/gcQPtr999?=
 =?us-ascii?Q?9NEprZjuy++R+JTUAcvfXtl1G9Yd1yDYa6hU5451mChPUf+EqHCdnB5H8ebA?=
 =?us-ascii?Q?w+8K03By9mZUuBUx/Tix5rAnXp2TMgsA2lst0deR+KWVqEP7RHjYZdEx2+Kh?=
 =?us-ascii?Q?zM5Xo5zi8aa0/6mAbvxoj++EUJEIbLH0bdCgsiXsOHWXi8llWEs8BQRj1Psu?=
 =?us-ascii?Q?m4sCrQscVj27juRqdff+ww1hPyfgsADDAlcuofSIVDYAWdY92ThiKucnGB7y?=
 =?us-ascii?Q?3yFNKT3kyi6oov1JCr6Fh9E/dt9ekIlN1EgVPM+OdwDCMOa702sb/Oq9+psm?=
 =?us-ascii?Q?pyw9hVBTNKvQIhxwF4INf5QBOrcmtClbBwcPaZIZyJdxsDiQ3B7p+pXNjM6z?=
 =?us-ascii?Q?5x/11DeBrBtGxmvVH1+K3gDSUzcTnE46cxrXul5vP7AL6JzHapj5IHQ8k+N7?=
 =?us-ascii?Q?/HBMhs9LyAR07dvA5kWXk4tuYuhUbGnojokE9VbpvmesZ0WwVBMvs2v0sqe9?=
 =?us-ascii?Q?S4Jtm4hBmCu49GnWX9B5H3A5b6E1ESDcS2FQ//XMroGNRW1NoIj3Pif5oDfb?=
 =?us-ascii?Q?F4If39vlwO1Flyjp0e9NNnlASDhyMyEop3fCzIL4UXjpLda0y6VXeGGkJN45?=
 =?us-ascii?Q?ZLmWpRAJJE9YJZTW12apzzK+ezGBzWvNAjPeXW7EDW3kUZon1SBXq3L5umct?=
 =?us-ascii?Q?50PuUONy4ydPLBh0iE/hBTZOHYI3x/LEVwLJpVP5WWKyknJkBDdPmFVesH7F?=
 =?us-ascii?Q?Ct0JQIUVlG5N+hG+bGlkghzvJX//tQhzv4KdeovL83U4eAWMq80jTewKcLZb?=
 =?us-ascii?Q?n8YCIr/2bktX73/QeHxDPjCbgqwt3kyBVBycVoBFOm7ulKLLFAEbcCSzj1/m?=
 =?us-ascii?Q?806MmV7WVHywTtQ8e1eyjvqImukGic8qXeZzn+V2iWvHcLHgwktcGZsj642p?=
 =?us-ascii?Q?97e/kgzag1avxKgveOGZUDASrDHHTt+gplyfUkgM6bTEN/G/LqhBYL8JZTok?=
 =?us-ascii?Q?JN10UuD0asO+XxzU4ZFuPpV21/JgXzVbhXI14oHD7Hn+yVtSmulohgCuMfrN?=
 =?us-ascii?Q?61ZzbXMor7PdpxVr9AFqNceUEvxiI7rXsUFeVEQ3G4sQ2r+Yf2lN2bXhJGVs?=
 =?us-ascii?Q?adM/krvWTzU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XsqS0KiTGrnpPlEcU+MO4h+qO17FcJvQViuXWHRz5o1xDzFTmi2ZJVI+KYE+?=
 =?us-ascii?Q?xKoRlglJj7cxCwB2Yw2k3Lb+kRNrb0UIIcl4RdkGz3BhK/rnQZDVTLqNgblE?=
 =?us-ascii?Q?3tYWCPMCm73Lc+QYbkndhtLtm9O3gaKS2tkqvsgtXo6Csak9NVagcijDocGk?=
 =?us-ascii?Q?EkiYB/kHS+TC1bwYOBnbsY+qlKahZIIjsfXoUW94tyHMR3yxSkPh6v9MSnAx?=
 =?us-ascii?Q?A49KCGqC1tPvCKgOFzqqEPHhUohdv8c1kLoxcQbuxD2cXcC5DAvjkgxcK/kM?=
 =?us-ascii?Q?xNJH8o2kIVFfQjxh3HXnWLFy+RZv4ojOy38WRhYJH2aoOQSMC+SnjbX5S4fV?=
 =?us-ascii?Q?TdqpiAreub78NcEXE9OuAr8sYwux7riCiag8QYWTVuSubGcKnEOXhtoUkhwF?=
 =?us-ascii?Q?+O92sNyG49JR06e68cymr0MorXjvguIA2zGWuxCcc3bpxi2WUyVHsaSJlDWQ?=
 =?us-ascii?Q?3UcdaAWaZGeSK1xhMBRb/Ago5bX5rclnOmi8VsARSGC/Cbftf6BY8IxAtY6A?=
 =?us-ascii?Q?+Dkccnm27F0bhEokbO3xu5wTbWyonZSZgS0iNrh7CIP50o7xXY/wvh8fUVyR?=
 =?us-ascii?Q?RzQ+MEVPp4F7ttKZk4yaVtGE6SDFPpskCzTBjNFhv3x2PaJazCM8xQfAHEcI?=
 =?us-ascii?Q?Koz8pGu+fRFMP04tQirQEAUeBN6TXCSfnmSiu/4cxDv0igR4AhafPaVpht1X?=
 =?us-ascii?Q?rOs/tPPLRZZuBN83eh9UXUMJinesYV+X+GmqRzT8K5aCN2lvfd5+eHcn6TIs?=
 =?us-ascii?Q?+qjZubGbAKKjy56XZqVowFiDLz2zCNrODbhv6Jn0IPyoTQ+AGcz0CTRmTx54?=
 =?us-ascii?Q?gwq484HveU0mEaReBL14kvx4mewOR6W2gVmtuAKb2iDqm5mb6rb29FevSmov?=
 =?us-ascii?Q?d5qxXfDVVi7ctZn6ZzWJ984kreRKckT+kcL8jVzIjIwqkDyhqk8BnKxjf0gf?=
 =?us-ascii?Q?g2G15j9+r0l06KmfWujXDaHQEs804pTOqrcIv3fLQgpmWTUcy4AwbniiiOSw?=
 =?us-ascii?Q?r4ugdE+L/FPlFA13UM+YYFyvg5NF25OgHE6FM8J2DE/kUNICvPACvsN6pZvW?=
 =?us-ascii?Q?7JacHMu6u4VURvkZxWprAQ+/SmjSnOe90cSTvKusHpiieJmUCWt8yCEs5HY7?=
 =?us-ascii?Q?JG6ux3X/oHcSi0ADltg2E2AS+5RCmWNAYKpj4Wfyy5IR1N7QHQiFDtJsfhEv?=
 =?us-ascii?Q?WfKzzck+LT3VsVLIGu4XQrbXWO1m4/mH4wobiHcV4QR72gm0XJbrrtrfyuZz?=
 =?us-ascii?Q?+sj41nxqRxQ+K13PEGyQbSJBk8H16IaQ8LJo5pnnpBsP5z02xm9WNw37e3pe?=
 =?us-ascii?Q?+oetV0280ayhMk9scmVMTX44c8mDcjX1kOPuS/WX1878aTMw9f5RYBd5+7jR?=
 =?us-ascii?Q?hNKfd2aedPiherwDqzdmYJla+hBfs9rtdsA6ZDV6hKolcB0Gnrwo2bGr1VaX?=
 =?us-ascii?Q?wFwWm+0DJyULQpZzx2R15b9SNhjJEGkNxopZbRIcURnBk7mRpuroVKovUyq5?=
 =?us-ascii?Q?6UGVToOK5P1Z0SO7T83drtqlwY+r4WTd/pG56wCm9aSKzh/N5sjbUR1V+gid?=
 =?us-ascii?Q?LFe1hz3Z2dmR2hZ0dNlgFJbSuIEzqwoqx+L5HDgGHh+zWvcbLcpValTBYR+r?=
 =?us-ascii?Q?+Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: sbcWw8Z7Hw0KbIA52/SnhYqTcSDNKhMSRxB4qoPmtUCY4tayoi3sCrvyQgXeJDcXj9/I8xXuq0li49IAXPfKt7T37ttA/BgN0yhJjQgkvbX026RqJwtFAddOdRP0dTVBT4y2BPjJIKivmw+aeFrbNVimbymc9VR89Me9NL5zZbOj4dkVVWLJ7x8nU5Rc8kkNJPqD0dS/DAzZ47kysHS8WNQD7/Pyf7DbU4u4G64BIKsjJDtwzXEgjMNuJBM3OQ91QJs53iHIkOliCwxgiT000b+dU52AmxCi4wFrjpZbAGwsVPQ5KhopNSbcnrfYrQJlcFdLNvB6Z3WunLajiaWk5r2u2S4ETLK2slZXYQUrqjmaMeDGFmHH5UwjAnVgZfZPnlyhc8aHOBeR/SJ21S32WBci71hjukXEuT4Kt9rMnfacghXkiI3ONTfa1EPGwxrphUx6gnAXobXh3B5ngVNmhpllz85a4VUteRGwgT1k6WiiWurJLyNvHIDywMFtsWiaho95V0L2XRJNLNDsHwh/OkPtwWFrYDiIQiJpcIZ6+t2F13QRPFqjcSwMVBbLi263mw4u6gBvVgdKF/TQ7cCls6Nd5HOVVkBOX2bk/A/bn2Y=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 30e72f36-0b5f-4875-7832-08ddeed94d0e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:12:02.5266
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lGu7aHV/cenYNEB7Qh+vB2KtXSCY+u542pSiZvDErI6/fuYNZdkozXku3zWZAJBmbt2MGddqQGW57OWrHcBuEtdhGx+Hnh+YSfiyQffMHSk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR10MB6345
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509080132
X-Proofpoint-ORIG-GUID: UMltrZ3PGwuLtzqgYwveIyThcndNNd9F
X-Proofpoint-GUID: UMltrZ3PGwuLtzqgYwveIyThcndNNd9F
X-Authority-Analysis: v=2.4 cv=K7MiHzWI c=1 sm=1 tr=0 ts=68bed627 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=Kq8dobMbidePVuT2iQAA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEyNCBTYWx0ZWRfX/rJBEpF+FOD3
 UFqNTreqi6/yoZ56ioRESWCDNg9ZPFmKXzu9+vDOAgV/MCtwHLqMaRA/j9PmYlVVrkc4BreYfyh
 FLmjAYbtcO+hBFghVdg7fkjJQpI5MUqFC7aUUSBpMAdF7UmHXkw/pfj0cEqeG5Tc8Alm+5hu4p9
 wCnhTrb3iN42TQcLTpJaZvIZwfNdPgvKjibmXt3aRGXbMhqi+zKAsg9qZhybtSoLjU0TS8SxrbL
 W+EZYqRc9REMLejf5AraiaTcAgLILwck/esMx0NHUjwE0k4CNOrfW/CTIul2IwNnd3w5luGj2Wr
 l/bnEX9Q1tFdhh5L2BA7X6nLk7BGdj7D/axT2hp+o57foc4zytoDLcZF6900n3Y/ypHa2FGhtzN
 MRI2qOsY
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=aVWI7bsU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=OuP1uHjV;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 09:51:01AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 12:10:34PM +0100, Lorenzo Stoakes wrote:
> >  static int secretmem_mmap_prepare(struct vm_area_desc *desc)
> >  {
> > -	const unsigned long len = desc->end - desc->start;
> > +	const unsigned long len = vma_desc_size(desc);
> >
> >  	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
> >  		return -EINVAL;
>
> I wonder if we should have some helper for this shared check too, it
> is a bit tricky with the two flags. Forced-shared checks are pretty
> common.

Sure can add.

>
> vma_desc_must_be_shared(desc) ?

Maybe _could_be_shared()?

>
> Also 'must not be exec' is common too.

Right, will have a look! :)

>
> Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e71b7763-4a62-4709-9969-8579bdcff595%40lucifer.local.
