Return-Path: <kasan-dev+bncBD6LBUWO5UMBB6F47PCQMGQE3Y5V7NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 334C0B49010
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:47:38 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3f66546ad68sf42267585ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:47:38 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757339257; cv=pass;
        d=google.com; s=arc-20240605;
        b=d9fWc3hunqm2i9mJSvhUojS26sHf6NOr7m7pyCyedx53LqfW2qfE31EzQUVP149URh
         8mpdtE2o+GI2nkysjqA9Hy0r1Omr3OuugP2z01HJeeANiDnWisNAj8Zk1nYXJYiqtrx+
         2ZHv9jUm0Si5w2IVw5gDdA0vnfrlt/rvRwexIw08bxggO6qbqsKkUc+9x371Zg6wD5+J
         0KvSdSDEPX93Ad1lY+XReYXdNwwy6XnAegfjW8u4/vnjEvXh1PIxNw2iEfZTzBAi5svT
         +AdcUvbEmaGtVhd4Juv0bjzP60wioZqD7hFU3XxT+aIZk/EEqXK94JEZfUMN1mYTHsLv
         LNew==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lrWw+hJxEKkC80Zgi7/8i4Fiy4p56oZf1n/PzUfCKi0=;
        fh=hLxuvjl2zW+gmhJgNQVtgHWgavchEfNi2kbDjpUckFM=;
        b=S/jhZLIOzPs99j4RsobaTULFvMskKqCNfG6vS2z7OAp+MTnPPE4TiVW1qqYok1X209
         LJIVtgMe55PevkFgAQZ9BH/1bEaTX4/5/i1y2qXc6FEnwtK9ATHecGz4UUTYz5B7xIJp
         1XTu4vfN4WP9UmrAK06rFcJC6HvxkJTzO1pXGUCDA7Z9iyuFZxNGj43zCWBFUViruhZI
         44NVxIsrt2oYHSC33M0QB5K+05Uywpek9vAz2dAGHNZpNHoTScp/fF8+dDcheanb+HVl
         iyVIDmIzESwC0KRgSc8o7orbVk+VWcS3+avnwCqsL1+unoEef3D7EQCb6TPphRAwu0NF
         FbDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cVZYGxWf;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AQzjAv6M;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757339257; x=1757944057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lrWw+hJxEKkC80Zgi7/8i4Fiy4p56oZf1n/PzUfCKi0=;
        b=FsbgCVBw8dypdlFNuxmo5MNudJ07A3sxojn0bawBc9zzyBJ2qCF2BChYIO5dpLkWFO
         ukqw6NyAl4/JxWSSYK4T8N1E1w2ZhbdjXbqlstkB4iyfg8A8a3mPONNeKvnk1riqnw9e
         bq+N3YiqAcVApyY4w3iK81qwFBmCUSVx5oWntPAOUcwz3kbtrvWn24spwuIgRVvEHNCY
         vAJz70iSg83amAUsjUws+REKO7KU99MIyAiwlGKHVENCBHVRRbGwdpE0mA0nAENFRNlr
         vhzhXAk+RuWXwQVmwAi8Lg2z/vKwKi1rEryD6qMBX6ll3qnFr1Tqtipb1mfS3Ipvg5qW
         mIWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757339257; x=1757944057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lrWw+hJxEKkC80Zgi7/8i4Fiy4p56oZf1n/PzUfCKi0=;
        b=uCZaWpJYVLFat/8qldoTBPgG3UqxkCvvdwZ2ielcBOGf1IRx3ILaB5KF9IxQcdydNX
         1twwtHlMnReokGiANgaIlh719/XnkwvIAef6kaAEB9vySH07L20zprzkbeB3in5WPQGG
         ArJdv8a7Snesq/mMQU6EWEcrq9ShJpYX4OOjwvrNCsWrxq91VuJvjkbkaZJPRKe7GWX9
         uX1gfvSMh5PZCq9nDhuTL4gmgcc4Jj2dswLVox/5GS2WyFFPZWQGR4xai5Nc6lI9bBSe
         nH5t/xhb3mRLwNdQlacJkH/VQCP9OjcC8nLzUHd6ofBfTJTEEUc89z2jwGy8fO0Akuno
         6kUQ==
X-Forwarded-Encrypted: i=3; AJvYcCVnui9jSx5Z3BUq+yxOZc8cEoG9BHZVTHPePoqGb9j0XgtSZp/7fIqDV45ekiOu1EBAZz3n4A==@lfdr.de
X-Gm-Message-State: AOJu0YzBnzaz9zoeC5Ga84IXmvdyUURTiFU05iSz3WShlW/eDvLoMa2n
	gJctxJ46PDe8w56yxwmUZkdUMf4CnhS2GJZ8TxZJZQ0D53TGyGOAdqI0
X-Google-Smtp-Source: AGHT+IF2pQPskv8mBnzJN6iDXYIivBJy35d8/kZ0KnHIDdQcwJbyi4pXocJrEflUuuUfAELdSGq40A==
X-Received: by 2002:a05:6e02:164c:b0:3ec:4b19:1cff with SMTP id e9e14a558f8ab-3fdfe0eca2bmr141860465ab.7.1757339256656;
        Mon, 08 Sep 2025 06:47:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcNxlgbSaBMQ52G8rrobwai6wqVuolQ1uPaeMT24GrSxQ==
Received: by 2002:a05:6e02:470b:b0:3f6:5675:a129 with SMTP id
 e9e14a558f8ab-40d819a251bls887105ab.2.-pod-prod-00-us; Mon, 08 Sep 2025
 06:47:35 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW3fPXw1hPxMXaD6Cih0mNCkyBLLaMPjFIAgDGzYh3VxuojWhift4t3htxGgPT2HitdJVEd0e39TK8=@googlegroups.com
X-Received: by 2002:a92:ca0b:0:b0:40c:cf06:ea2a with SMTP id e9e14a558f8ab-40ccf06eaf4mr15464185ab.2.1757339255310;
        Mon, 08 Sep 2025 06:47:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757339255; cv=pass;
        d=google.com; s=arc-20240605;
        b=E135s92hWj13svDSt1HuWP2ZTw47YFlkNq4Ndo5O51+G5ayAtuBVrzudDIYS3/AV3E
         ascOD4ULiIj5yZFagAEmSR/DJDzNx2bR8De0jxIKuJHbKuk9Y6+AMwyfCBSvkhgNrY4t
         SJsE+TScFic0KHkl/5+4TvWi6G4t08qcsKkiFiDnx20Xth1J80QmLOs51EQjpwY4VVlo
         FS1vd8FO2zfw1VCxviaJbaHZM0FIFyLiNVPmEkJw80Q0mSgpMbmSXfARZB76j+Y713RC
         SEkgBKomgZGRNLEly+7gUbBVWfEwaOF/CMRBUQo4uwhgacBRBhH1YRhNCpEHu0XIVM//
         OqOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=xCk3OfISa6YG2vf4BzYC9DHLdrfy7yobDGmI4EOsGGk=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=ZoKVJfe7y1j85tppEBhwEZxLqbOKYysc9wlpVRiJ+hlgGdUGjWffHaKX82BOHOe9oZ
         APk73GzdUPz6bLZwbrsutQvdAX+D4IcDlgT1a+Bd0cpWMtnSntjQThjcrLh5ioWPgOIF
         COCIrWC4QT19e/l94qL17nUMtSSwW3+Q8cTAlwC5GPTo2SqbY7yn5J8MqtklhlaRg2Mb
         3Bs8sjpmzLmiKqvu/7tINvt2yzIIXhUqjpbKJ6hHK0YSUGL1FqBldtmpvgvzyrXy4T56
         /fVtlwAFqT3uB9xkuCA0KpWrBqsJa0AEpNYw7diPrXFJ4AZzMmP4rLBXvHWYbNrCL3fm
         px9w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cVZYGxWf;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AQzjAv6M;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3fc75243068si3091235ab.5.2025.09.08.06.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 06:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588Dl8BI008127;
	Mon, 8 Sep 2025 13:47:34 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491y92r4mh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:47:34 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588DHg4f032957;
	Mon, 8 Sep 2025 13:47:33 GMT
Received: from nam04-dm6-obe.outbound.protection.outlook.com (mail-dm6nam04on2060.outbound.protection.outlook.com [40.107.102.60])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd97cpy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:47:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=WUDaY0coeDz8MhfaQ5YMTW+ZqGCL/XTXqJGQETYfX5GQnYYLfeF6Ly+6OPqW+qC3dnYkDjyJkU9CKJyfIkNmYu04OTIjz1Ns7O6sH/24dJX7Xp73m8jk4ETN96vYpJQXE+XqcuhTnXhmGcWwlwQXfzRchW1dN1/zUnvyHTvWb6sgh4BWh9HYJpTfpaRy9J0LRF/V+I2d4zGqtnrhfk9TFWI9xjxyOuFTqNUfll8X5U0/YegbShjq4A4K6Hk+x/A7MGwVKoHDGZQK/Td9ZaSb4enteOJoYZRnlLrbKiEfBxPKoyGjV2m3iHowa5+iZOOVxuYRAwkvTeofhBRofdthtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xCk3OfISa6YG2vf4BzYC9DHLdrfy7yobDGmI4EOsGGk=;
 b=jXfsWGAuIZ1MdIAj1bW56I26l6mf8Mi9/zoE/t2rYk08JH6rFb4aEmYG7AXxKbbRloCr79Jr+ht64O5hrR2JM4yoDOXWfu+N1cPQD5jnIS6RrnP/lFgZNmgXAwL3Dwv9n/reJ0u5R4fAUrH20jNcC/3Fm7yAtilXZzP6zuQxcvhDDiVZXmxMw+EkU7ccvnew50LmRfwiIhK7Jx9te0hkH5nrIaSBA+zDmUV1r1V20XtdYEFh/t1M+dLSTMEAhFmLmkWMDL+dC7wIfHYa199G3euo2EUL+t0hZ79CJtnw0yTWv1lnJk++v7kQP5p3J13y3LpemPrwzYpIxi9DxT52/Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by SA2PR10MB4763.namprd10.prod.outlook.com (2603:10b6:806:117::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 13:47:30 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 13:47:30 +0000
Date: Mon, 8 Sep 2025 14:47:26 +0100
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
Subject: Re: [PATCH 16/16] kcov: update kcov to use mmap_prepare,
 mmap_complete
Message-ID: <c548e94d-5a06-464d-9076-b4a5d2e750dd@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <65136c2b1b3647c31bc123a7227263a99112fd44.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908133013.GD616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908133013.GD616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0150.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:188::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|SA2PR10MB4763:EE_
X-MS-Office365-Filtering-Correlation-Id: fd51ea9f-2893-4ce9-bb89-08ddeede40c2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?SfekJ3w52oiqcVmVNbzwUBRDyHzPLQfC0qjxyds7oxjtj3UUlqjRo19Cg73N?=
 =?us-ascii?Q?04X94+0O+AaWPRyclRArj0DQtfv0H6CYO9TN0VpluGwclQwNON2rNZTkRKog?=
 =?us-ascii?Q?OrM96IWsgl7F273mwNbIGHiB/3yjcZAahaop9eKYWGkW4UVb6FGaV0vNSOVu?=
 =?us-ascii?Q?lg3g1rBPV/3Tqre6i2A7owxdYoTEbu6Q7AUieHKitKZmv5l7alx44PYT46px?=
 =?us-ascii?Q?tc9kDgP6jTu12bzVNoKkDDqtmFsZwR9hPcR0P21/V94rwm2GSqXwC0XzEPV1?=
 =?us-ascii?Q?fJpthu5hbok7h99tK2fyj1UlJETg2O7wdGZN8nhAWgT7ayYxbqS+y5vXB0ig?=
 =?us-ascii?Q?o7V8xeX+i1dyXtdmhf3XBzlxEiH8l0Op/lcFz9XOZoNijEuMP+w4kUZz1XIB?=
 =?us-ascii?Q?JUtgNODxNZkCqmIBmDxNkG6Aao974JNUD7Ux7WkgB8id7qQ4ovBr+YsP2MT7?=
 =?us-ascii?Q?Fffl0sUgt7RgoVfzGZWSIGbn4ms3bc5GNtdK8ALdO7Q3SXQWGkTdBYP1NTYF?=
 =?us-ascii?Q?hznfRNey27kE3m1uW5VW9wWeCptK3jT1DzbrUeHRZeblCGRXy3aUQqCLt7w3?=
 =?us-ascii?Q?eIY2+Cl20g4iRMugI15k1dr5tM9Ta1NCbGfhI/wjG9IWpxgzNS1hkCXqjTK+?=
 =?us-ascii?Q?uYAqvJPv4oZViA7nNMZ0VYvcByccrPATbo7dZC5LgROh70J+RnuFvheZIeZx?=
 =?us-ascii?Q?/FBXyQ7agcpN+Te7qu4jprtaZdicLvKtK9fN2uLfW6NDLH0XFseKpicFiO7C?=
 =?us-ascii?Q?ZBGL+Aj844ceDdEwEuJOzVduHCRq+Ghn2bi+9EEW2LwZF+T47c/uATc72aoM?=
 =?us-ascii?Q?NuIY8p3WX3PUnW+TWErg2yj0qyai5LmntwrDfj33XlOe/MYzciRG3nTAH8rd?=
 =?us-ascii?Q?Ip9XhSj9eHr6WlzVPY2eEtlMyzpAm4dwLn0itJOfUtBHCQvgfa6utRyLbpox?=
 =?us-ascii?Q?+APi8asBpyrN2pRaT3c5yvZPHK8HSIf0MI+GukT63nODZ+V9BfIPIbsx28XA?=
 =?us-ascii?Q?2Fu+1x/NMvPwkzcgPrfrKb2r6MxNkMZttiKnW/QnT7SOVjem7fv6IMAnS2Ab?=
 =?us-ascii?Q?OsaytVN/KZrvR5aWULTsHWNZlhT4myrd+xEepC7yD+tD/IY8Ubb3zLdDdh/z?=
 =?us-ascii?Q?xdd3odrpYN/mWaWbPCZblJ6/sDyig33Oinu4ZgZYM4ZdND4MRuID4naPvfnd?=
 =?us-ascii?Q?osJ8I9IWexz0gl78I8yECZQ7PCHgH3EQcvJkA+xq9VNfemSYQ5kqclTaON2W?=
 =?us-ascii?Q?d18dOQFbZyT2IQF9FVm6ZAJqwqMgEL0snwoMDTKqd0kne2RpKFtsIQGYSKdV?=
 =?us-ascii?Q?2Y7O5qMT4SPZpE4kypFiyxy/b91yHOxAseNVAqIPPomg6ddI83VirrnOkAmw?=
 =?us-ascii?Q?fFZuBumPPXf6DRUan1AnT2JBq49UB57PvYgd8A0MaVZZwg1UX7xbyjCoejPb?=
 =?us-ascii?Q?AHpp1HBUSPI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Hbo8MPReyiQxnpsK40QVsM4xd+BgiBSC+TKsZKaMITvmZiEFhqHV6mk0w+h3?=
 =?us-ascii?Q?WQy/yzvoJeWKIAYwhM+yeO+3oOP3dl50uiyjvCgo5n8SFT2IE6rMIw+Hf0z7?=
 =?us-ascii?Q?/IXM+zw3AFCAQl3h/kDSn/+GjoqlgtmX1h4Q6YQeXwTszy6AS0o9q3HM3mXN?=
 =?us-ascii?Q?X9MyJe8CI9NbO4y+qE9Uds3NTfHEJ4GR9r0SU2j8Mmw8vldhtfWCTuViaXvd?=
 =?us-ascii?Q?t8V8O5tmtegTb/eO1yrOKiF+DbuB+TgEDzMu3+JAHCLwZkMUTzsXL5sGZSqr?=
 =?us-ascii?Q?WjxAtfR2iVQmXHW40EVRO4gXClFK4RJbYwKX9s31aL4yQwA+bVhcEpJVuWxA?=
 =?us-ascii?Q?/3cRFFp09kDZvu4zClWl652qKqoGLWtkwxSwaH0SXQufGeBBILY5UGFWyZH2?=
 =?us-ascii?Q?tV0N52fze4rq9zqG/h2hzdRiLEXkqtJeB2WXTwR7TS7REWCYWSFa/gO/GQph?=
 =?us-ascii?Q?We16c1UaJkI1rVDHjCVB5/nGxL5TXxjXgtPRkfKeZ5Nuu5HsLucaMGPgWqbQ?=
 =?us-ascii?Q?1e+lztEz2N3gIuaWXMpxvgcQCz0t6+x+Mkx+tr0BCyEhCPT1NqVjWrNF0u1j?=
 =?us-ascii?Q?R40t6BV+jJgOlytUktb71265JtxUT0eonCZDeNOAHf7r3JDkoX67w/931dMU?=
 =?us-ascii?Q?Kmcnu7lbR2DaEufsr9ZlTILT7IycaFS6Mkye0mtOIY19BmbYVcvsrnSaJDyX?=
 =?us-ascii?Q?1mvaZFy2iqOLiqPhaMTy7GUHNvwyLm5L29GvoJXq9HXIolenkBVkzchBphmV?=
 =?us-ascii?Q?s+NfKHCii1Ofk9M29YObUtJDii/kI0WqfL4spQdtBkmmvj09RFul/fkrozEX?=
 =?us-ascii?Q?wdkzsfgQTaIRyLCNMhOi7u5QtpBn8w+TaAp7CHQFxaW8HVTzMI5QiqZhIzn+?=
 =?us-ascii?Q?mLyoMd9LxdXhfBkOQVSvAMJiMW13szvARkwUbw92GB+ktTEL0glaD9oxgPuf?=
 =?us-ascii?Q?x6IIVfz2TfllLPhPz2rjP6v1zta9pDIK7TIJgzclxC656hsejuVQdRg22nM2?=
 =?us-ascii?Q?zVexu/t72ydcHYwIR4RNMOuLuEg1wY3qU77yhBn1D54Ddyk5J+RnJAhif5Vx?=
 =?us-ascii?Q?1A4uNd6Qqbi//dyaooyQd0Rz0WE0lKLH9b/DrwGeifRwPZAa5/PoXP+IP65J?=
 =?us-ascii?Q?5tvmS4/bndGiFMYj/SykyWwcMkEF1BEDzuZ/lD6XSMWIMoQvLr8XkO8igug6?=
 =?us-ascii?Q?2sXCvG7A8ZTNjqh+xJiwrA1HErXpK2IfdpZpm69tRQStEIQDbPrPTBJAqk8o?=
 =?us-ascii?Q?Y1UH959uDW+Hug6DPd/aDn+RMgGJx/vtuTuLVpfuKmG4vuvA2q3STj4XgnVS?=
 =?us-ascii?Q?D3aDrwlpg6DZ8ykHYVtvkWxXeHYHRSt2HaF2qpRcc1lqNjdpWljxdhADU/3F?=
 =?us-ascii?Q?S1xOd5WPt+v3Yah6huqlT/nY6T0kKf53xpxr2D8Nfd+zZueS5kTjZOwyOBi/?=
 =?us-ascii?Q?GLQRLIebO5NpvOeeRDXI7jW/ZCUBcjqEL8w0Jd5cHGPrtYxZBEjslkjfxuUb?=
 =?us-ascii?Q?Oyb1ElriuqkHwv6XgVLapH/o+wJ/BjXUWpXdD0CLZd3Dl2dWfaOTTkm7qeiL?=
 =?us-ascii?Q?gFR6wnE5obO2Ei8u5slqMzK/mU35x6WVg7uUNKBHRKMVOAFJDXBHaRFGrJPL?=
 =?us-ascii?Q?SA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: S4kzey3sxqybyLb4E4Q1Bp8aYwr3PIJKYXQC9rhPS7JfxsauA1wFkAsXnNUe+EuLQyjLCsRnA1Hbi0FwVyXvQd8wu8f9TTcRlRpLyjBqm5ituXenDxNWs8Pku51BfQfmttTlzCtXnSo3eGATk9epBxQ4QbHL8EhLVuH7XVzma5t45Ch7AO+XGgGXeQnduSLwnZsA7f3eD9z8UNy/ijSe/KWAXvvtIKpG2vSRvJR6uVqFMUCPW31UCQ/xRf5Bevodom2+/+52zExsuBrrEnQVJH03L4ozHA4y6szpXTAcYu3OgvcNyfIGEzvJKeaYOtbiwr4AlXq+wUtNjx+hh3b8IGjTkvQrTYNxYMsxBDoidLAiRi5vjGhg+tqhFkskIT5tDLFeKhmI++Wort+OuOOLZq/nOnq6QGNhfXpB6yabsfRgSRAZlLGgcfK+qrmnZvpirGcTMD3bDNHcN1eLJWqliqTegj67QSu+ZZsLJcy5DvQB6co7TumZCLkBfnz6AxJhQ7K3c17gOvEcTxRM49NshILB59cxjOjxtVlwgklvbLp6nlFJ4pss2CVgijESWqiWMhGwclL7ciKlPtIEV9dHk48dldz+tIPuryONzMLO6so=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fd51ea9f-2893-4ce9-bb89-08ddeede40c2
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:47:30.3949
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +Jd1qXpfim8AtzFs6NJLhI3DQWYcbs0FDEw4IZKbfAUyUhY+K43ON/4Z0GH3OJerbDAE/8Z/aJ6cOKFS9l2OB4jf6LORJ7b0+msBAFlc8FE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA2PR10MB4763
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080137
X-Proofpoint-ORIG-GUID: kFVvncrQnkrL4snqZ1ZTXErS7q_lAU1o
X-Proofpoint-GUID: kFVvncrQnkrL4snqZ1ZTXErS7q_lAU1o
X-Authority-Analysis: v=2.4 cv=K7MiHzWI c=1 sm=1 tr=0 ts=68bede76 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=SIcRoMYcOWurme2wFRcA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEyNCBTYWx0ZWRfX10S+UmhW/HIp
 qQfOftJQpVVXpgwn16F+/cLUYAv6xlgUiweX/MqrIe/g0vsk0Wp7bWGoUFzIZHDtbkOP/d5h+nI
 u5EUeAe0t8BGVM89GieWvThqu2Alh/yOp0mLGwFqItjV5mKnWfl4YwBdEdyl1DhQVAwVrZphjuT
 0U3MnWjQN3iGwbrCcsf5doBgk92E8jNp4hhgXhDmohyyrKeeRAPOtsqw3vfS/8FPxOfTDxbxl8/
 SsUENSZDK/1B0CxJL2oTw5ctpdiAB7tK+9VWGVH6RWG7RLy/Vko+dCeiViSa9rrAckFZYm85UeE
 XeDWfhQOgpCKK69JgkM/H13/LUGboPm4O6/i6r7+fNZ/liDzXPduJCqxOMkWa1HwriRgIJce6zp
 7cdRsYls
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=cVZYGxWf;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=AQzjAv6M;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 10:30:13AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 12:10:47PM +0100, Lorenzo Stoakes wrote:
> > Now we have the capacity to set up the VMA in f_op->mmap_prepare and then
> > later, once the VMA is established, insert a mixed mapping in
> > f_op->mmap_complete, do so for kcov.
> >
> > We utilise the context desc->mmap_context field to pass context between
> > mmap_prepare and mmap_complete to conveniently provide the size over which
> > the mapping is performed.
>
> Why?
>
> +	    vma_desc_size(desc) != size) {
> +  		res = -EINVAL;
>
> Just call some vma_size()?

Ah yeah we can do you're right, as we assert vma_desc_size() == size, will fix
that thanks!

There is no vma_size() though, which is weird to me. There is vma_pages() <<
PAGE_SHIFT though...

Maybe one to add!

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c548e94d-5a06-464d-9076-b4a5d2e750dd%40lucifer.local.
