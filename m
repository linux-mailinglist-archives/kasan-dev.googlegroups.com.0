Return-Path: <kasan-dev+bncBD6LBUWO5UMBBF6377CQMGQEQ7Y45TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E96B4A679
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:04:37 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-76e2eb787f2sf5658778b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:04:37 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757408664; cv=pass;
        d=google.com; s=arc-20240605;
        b=JkSSv7NWptd/2A62EQoG6wLA5EFAvb8kTHT3eFPnVaPQ7xgaVWjsYEam+GGjdOJlhC
         2OW5dVkfX7Mdk9kq/O2D4SfaI9MjD5Dgb0+vEIRS3pS9sysODCslBLv9lMctxx8nE0J1
         7Rc6aAWsjO1f64wXMODjt0vi2Utfr4P+HwOIf7xMGEcgXRKT7twxzc+E3sXpIhcIvauM
         PdW4jlfRIYuRSA9fsxNGsg/L1hhf4kf60MPw2ZFgKFuA/PYB2eIMO9BR3wGR0ZmQ/XQb
         qx6z3drxBZ+Z+qy1KG6pY5Ol0hg0s4+MNArcyQMCE9rPsXKRzufkqIerZQAIqkCrV7Xr
         CFig==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=LGLIPLnURvUWKpSm3YDlEmUWW5HmoMV0Pl53QKZmDsQ=;
        fh=pAtp9PnwfBV0S77U+qydQNckdeiDgsRA18R7YqDc940=;
        b=a5UpD/IVaooVBpxhRQYbndzp6NMDyXqaXTZXxugytBnbb0R8tyA3x+rfio28FW1ZgZ
         7gFOzeua6D5JEDJewDzQaiSmcF8llp0Dxqqr42Mcq0F6bu5NsTf29OJ/eK4zGhF1TPUR
         gtuW22MBQ5hmaQo5kZkF1iaOL3zcbZRPbGSYblCLBS1uVfST93YBD4yUHJpC5X/8A7+M
         ZTRsOfJKc8MTueCOkLLmIiNhxtJpr02IRYkLfZgtXWW7TE0MqpIg9em6ejDS2leDVCmv
         e3CiORi+BFDgEqOet8VyvdXELduudHkbUfDEob8UqoEGWbJcljkF2Ay45gUiWOT3F7wB
         rXiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gR+SbYYA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cbZ+YCrx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757408664; x=1758013464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LGLIPLnURvUWKpSm3YDlEmUWW5HmoMV0Pl53QKZmDsQ=;
        b=eXf2wgzbEPFiXcPV0a38x5lzPAJX3A7TY84cONrTBFGAls40Qr/FiDv5AKcsZfcUci
         H0tcCioPSqbNA1yG50t/8So127ap9zoD50BwDSyv/jgEYebwmEUMSeGeiPY1CW0KC9wM
         vjRxj+YomsrkOog8WxnLuBPAp9RUAusCJj4faEfud1KGE+Zaebhb4giQUjsisgZ6+GVE
         JPzRIgVgnwKkvY77h7PbbXxKnW77kPo+LjmOyihZlM5RF1pspyM0uTR4UjkAd/Fs4GuZ
         I0grlNN9D5C0qauwxZMAKmX3AddDFlSRPfOOe9yEPWI58auMjZdwr9hNkYDu1HNchTQP
         dmmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757408664; x=1758013464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LGLIPLnURvUWKpSm3YDlEmUWW5HmoMV0Pl53QKZmDsQ=;
        b=UrCu/C4a6m51jJAlg3HZ3p3UukTGqWwvoUAduso2OwMP6yLrASchB/1Sg3ouvgy3X+
         KvikmOtxGZAuWoFJIsmGxidOhuhGc8WhWHB2HHWEOdrUWlkmDeaApfGNjFPZ5iiAh49p
         PQgMJTHCnCWjvJloub/mruUDepIWJius7HxjOcSgVe1ZXlH16vD39A4Qk8zpGlyDPDXp
         gsXHBV5SkI6rNE7TSf7pQmKZ182v2mv22sqtTAnbJZGC5kaoFYpVKza04VZvn+FnAn8r
         96mrj51BYVMHJQEMUD1ODLSBBnaIcJ6jGL5CHlZZeVBz4l6+MIopL7Au9gLPJKe6/tyC
         1SQw==
X-Forwarded-Encrypted: i=3; AJvYcCX6GLuOHMptNnUAOKowXtmbFnqFwSuGQxYcrKsF39iyM3EAhHkqatkgJ/81j4eUIyDLnEp4YA==@lfdr.de
X-Gm-Message-State: AOJu0YxhMBQgNUDj1PgQLEm5M5FP2MDzDPH6GDkiRrBNuTmZUlMGSUo4
	R9ZTSLMUURf7zX2cyw2w5d68rTB/Dd2ef6JSuITtc7SVD/2HluVxLwkv
X-Google-Smtp-Source: AGHT+IEtEm3TPuWkJr8XBbsfPB03zoWeyXfimbe3ZCh0TYV1WQ2rN4VMD+hkEMR668dO3n0bLJGFzQ==
X-Received: by 2002:a05:6a21:3286:b0:250:720a:2913 with SMTP id adf61e73a8af0-253430a7cf4mr17276229637.40.1757408663737;
        Tue, 09 Sep 2025 02:04:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZco2TUF4pnknHMglKM9/dPoAvNNkU+cvyHA5udpvCiZrQ==
Received: by 2002:a05:6a00:3cd3:b0:772:27f9:fd39 with SMTP id
 d2e1a72fcca58-7741f0bec03ls4310288b3a.2.-pod-prod-02-us; Tue, 09 Sep 2025
 02:04:22 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWpAYxgm7GxTv/itLMKhQaDi4tR6UpHBSqwVvungI//u7ize7xZzINZH06DkIAsgxfqpewff2d6Srw=@googlegroups.com
X-Received: by 2002:a05:6a20:a107:b0:24e:2cee:9577 with SMTP id adf61e73a8af0-25341e68157mr13756946637.35.1757408662162;
        Tue, 09 Sep 2025 02:04:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757408662; cv=pass;
        d=google.com; s=arc-20240605;
        b=ic/ItTTcgePl5RiIIg3zp5uw5Wghnr9XTYuYNvrNbKWAWKbTjE90Vtmf/JJIAbtyTn
         xXIr/ZZKMrwITHm0oF8nglwksA+/Aib7POORfcU2dZuTPXZAXBACLUMX1lUm0uaxp1kL
         2h4Osove7aQ4zuZ5ClU+Jdm2OES74BaCMSdo5+cgAE0JuFxVFOTt2f3VfEumeawZ5fTy
         xyC7aB9gmeJUZMP2aHznWpRDV+WT9mHfwp/WCKNN8OR9V+QF3HA/zlvGVJielrYQKkLZ
         TqkYHOhB9Ozk9v66bcynQoeHnnveVBPTq8wWL1lx9CiRmMvsMoOhdbC9yobkn5+h/hAL
         JWEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=z8+NnwcdF6pCN7ItqA6l6osNNL2OzU605fxy98/w7no=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=kEFqOHuW56yy2RPtwKtA0xdqJbR15Bq7qQEdC+bHsknPjrH6IM+5u0Cc4Xyyr7q999
         HQpjgs2o+9tu+hQHSW0rVfwLqe3AzH3sAMC7lmZwawEak/atIwCLUVw5sKQdJhCns8/O
         p5BMpxDcKTA8oM4Qr7oPvVOovlSRgAEC/EgMW41YXPlwX+wQSk9L/GZwqJSFLTL6rSoo
         iP8YRh7zQeJDb8eo9zo8J1FFjfEYs45YwmT9x11N94JVAfTmGFAFjpmzOiXuE70EMoYs
         RD0yYyhuqI4IcnPrZ+MKvDVKkIB+1mT6Ohb+l037eR9Cfxqy/EaCe1HwwvExiWEEfRow
         2rnQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gR+SbYYA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cbZ+YCrx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e861f79bbsi1014262a12.0.2025.09.09.02.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5897g1PG009625;
	Tue, 9 Sep 2025 09:04:10 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgsdf5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:04:10 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5898UJAg032837;
	Tue, 9 Sep 2025 09:04:08 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam04on2058.outbound.protection.outlook.com [40.107.100.58])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdaaw0j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:04:08 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XrJfnmLNUH4xKUsUtcncRI3d+xxM2Wjd5NCqpVBEbZDQNTZHaoQrkWGb5SezxSH/kA0aFNy5tj0hIdtxHmd1z6C0gvRltCB67e2uJV6Mg+R5jEJggGH45E0rgR4wuGn4Xk1zfuT/x2YtGspadPjzQVZWh1HTKi8k2PKhxd5C0+HXM3oZjX6FKZtI8X+LL8o7VSdodml52zgs5Z6zZEuZP2d7I1K4vT7gXOwEZFgTSYwEzD8qIOuHx4YqwBKjgeMx+kZiLMy7bN6RqY7xbHi1WsAQqYampirlVdFfu56GfBVzGFEkcTxxY18JvmckCobvvgoUW5480zpHk7+bqAwtxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=z8+NnwcdF6pCN7ItqA6l6osNNL2OzU605fxy98/w7no=;
 b=u5rd2N0O6dmJzY/p3xsdAJMN3Yj6OY4KR6q80FrsCkJsTy2pinQzwxSx/Ic0iIge9WmE6AcM1l/1mFKeX4Y2R51mlgWajOI0mFRWODoy7LVF6uWtKBoltwsi4ar/dFTwEVuTqVL1T3jkzrt6aOK+O8e7JzO0crDwT0YC9C/hFQgwbTne1EFg3hlNGSN43rggKUJdsknu4FOARPCEGMJRr5aZ2cY5ybvYvuw55r/9zsYzuOtrobZRNb4HAGrOf1cLe9im21s7d4whAfiu4K/J5qJE9D1c//4TDBW+9Veqd1kCGbyiIputkAW1TOSbBcS3O0PN55Hr+ZB6WWMi1IQt2g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH3PPFD7011BF84.namprd10.prod.outlook.com (2603:10b6:518:1::7c8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 09:04:04 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 09:04:04 +0000
Date: Tue, 9 Sep 2025 10:04:00 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
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
Subject: Re: [PATCH 05/16] mm/vma: rename mmap internal functions to avoid
 confusion
Message-ID: <dacfa550-df12-481e-a47f-068c440e6a8b@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
 <07ea2397-bec1-4420-8ee2-b1ca2d7c30e5@redhat.com>
 <a8fe7ef8-07e5-45af-b930-ce5deda226d9@lucifer.local>
 <225a3143-93de-4968-bfc5-6794c70f3f82@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <225a3143-93de-4968-bfc5-6794c70f3f82@redhat.com>
X-ClientProxiedBy: AM0PR06CA0130.eurprd06.prod.outlook.com
 (2603:10a6:208:ab::35) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH3PPFD7011BF84:EE_
X-MS-Office365-Filtering-Correlation-Id: 24a52fa0-f087-4af3-0392-08ddef7fd32b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ZKJ7pwZx6vT5F3bq0DsvgNEhdbQXij17wE7pX0pEnvIxg0ZHEFIk154EZuDk?=
 =?us-ascii?Q?3bnhBnuzQhr0LAJNuDxRLDrKYC3LGFfH1xV89ggiT1k6fOXvaC8fatuTUbeS?=
 =?us-ascii?Q?HMoF8ViYeZ7sVCwNE245qJ4nH+oN6fFDFLirBvl6nYMhokvaX9fFG9MoQCnx?=
 =?us-ascii?Q?2IsDy+nwn1gxz7NDHzqYQgbs150J7tINdUnMjIKbfMKrZ2sqewRZdo+j3ZU7?=
 =?us-ascii?Q?9iHhJeZZx+gDdyNrQi78hEOULBTdCKk3J52IJvomMqfrCA7sMKNDpEL5k857?=
 =?us-ascii?Q?lbgFaODXmD9vhB6t3P8qmqaln7qLVBQbwKtaa2rrKJakRhTj8luvHg7FtK2W?=
 =?us-ascii?Q?DvTPTEuS6kHK/D08+5ZkB2PojuMOPmjQZPKSZLGdyjdzTuDE7J99ThzAC+tV?=
 =?us-ascii?Q?XTb93iQSvZIfYI6x8L2lMUJp9oA1jbsfN5eXgouZo83kfL3RullUfQOu/BNO?=
 =?us-ascii?Q?AGZu1zWu9E8OoZUVHkEJbIZw3j5BPvmr6h3Jm/dqaTHHsAJhVdibejh7p+tU?=
 =?us-ascii?Q?AIdPLqNFYobl4vnTi940oE9WOEr8EV9APG4k2nwptNemEtgbHnMRWH7aC3dK?=
 =?us-ascii?Q?JJGmk5AsvCXfZVMdyoDPkqRvnIO1hYPAjCDanU4m8AVpDNcty56YdvEmFcRT?=
 =?us-ascii?Q?rt4C//QJrSBY1yoQu887n6S7V0bdkmHU5GQvAz+oMNqM3Wiqhu7IhDT7BC28?=
 =?us-ascii?Q?BYe2IQG9i79pXNFng12cFOUzGpF+vRnBGc8jK82gQVLpVzhPrYiCcRD4YLlj?=
 =?us-ascii?Q?VHlc/YmV+oc+NkL0MkjoxkNoTWdE0dyJIwZiLHVoIOCsyovJCWaL3t/9Arg6?=
 =?us-ascii?Q?oCIMe4jlq/rlitwTWnDJhyIvg9a6AR8xIshrpJ5cd/PmQCC0qGsAFNK6CtaH?=
 =?us-ascii?Q?0xHeWqAj3Ok9u+PX9RgWYUPxG2tQCoKwjFNIBe4gt8zHiMqLxEWfRF2KDVrq?=
 =?us-ascii?Q?f6PN22VIQuLqI4iiU8SiPXmMr7n7BZVoPqgH6wsL5ywn6g4v3A9gJe8rbgyM?=
 =?us-ascii?Q?AA5zWZ/+O/8SsVx2O8Me+eEBkEtYamfMQqPForgmbs4dbjrpxqLxYA3NPxE8?=
 =?us-ascii?Q?aeTihL+TH5iMw1e/q6xSOP+7T/nMNBd+IysbEsOEcQRA1JymN3l1Qq6nQ+Cw?=
 =?us-ascii?Q?WnvY4hxI/hp4NdzbXbXVWWjOTXWsBATYtnbk7Xd2kovdQpMZuA4UDK5vauoj?=
 =?us-ascii?Q?K1/RB4YL2vROxIFfWFfgyozuw1QhMqbXyWHCPyJUjGTO5RViG+UW+y2gfRnH?=
 =?us-ascii?Q?G1XZwt7hyD3asLy7suvnKPlwsqWZFvCkBrssMJv4dN4PZsu5pkEbpsD5giic?=
 =?us-ascii?Q?wUqpRv1XP9Gv3QF/0jKOWCRxsdCUhBNj8tmJw3EJiGig8g6U+YqxqfaZDBWk?=
 =?us-ascii?Q?T+CBJycbJkQmJrKeKX9pHEpmPsj8FafVLCjuzWqABLosSiEMzf8bfcrKl7TA?=
 =?us-ascii?Q?XvP/uF5iK5g=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Mg3HRGywhIv2azhgo2OZ04NecRp5y9YzI+ef3dMJisd2MK7FbJerHlZUZrd+?=
 =?us-ascii?Q?P0f+RyD9a8lAR1SUt1HUu9BcQ8wtUuNhEQoZsXFHyggV/PRjODR9YagMF/wC?=
 =?us-ascii?Q?dgWK1lFwpOmbSsJfLcpBoShgzhGyp5ngonrNXiiUK2h+jJ8xMi3BNKiEgfYY?=
 =?us-ascii?Q?aSd4lMf+FlBupCm1p/wx+pbfVSo89XHCj0WKHpfmDdsenfZrdF8zccyoFyPC?=
 =?us-ascii?Q?IrzaSBMSNx+J8q/ViQTVcrXmvA6DEbuCL0d+DrbSxE8HstbMts1azDrj6ADv?=
 =?us-ascii?Q?e42cED0YXtQ0k6nR9UcMDr/mGgKx0X03SYXzSz2VIDWwSsevgGiAZIWv12T0?=
 =?us-ascii?Q?h8xwnONNJSK6tkzmq9ELl1R2KrcmEnlSYWj5ef0WknYv/7qLkZ0DxVH5uyTr?=
 =?us-ascii?Q?MkGKBsKWWtu+Gc1GHD/0ptRmiy4Yu45hotbH+Nt5s+IeDB8M9I0MvkLtIKNs?=
 =?us-ascii?Q?m0S82+XHieIQZjsjUmSvNsU2vtMkCtcE1oeHqx4ZAL5mdqNTszeWg/gW7l5j?=
 =?us-ascii?Q?UCm1E3t6cct2jy1AFMFpJUEb8P9r+FHOfMzYvdnD1ojXh+CbMXN2SwW6gNOB?=
 =?us-ascii?Q?+xn+Uojau7TI3HwMFjkZJoxZcOWbFIO1REo7Og96xwgqgXLuKXXfU9mK57Ia?=
 =?us-ascii?Q?QA8t5NWtuLHJMA8a44d3RWlqEKbkK56DQ+BbZ/2n58bCWJPHx4YO8ideDsuy?=
 =?us-ascii?Q?EeAdk+cmnAbaL98SJqMcv6gloo6aTs0p2C43fgoS33G62b8V2o8Lap6WlYoW?=
 =?us-ascii?Q?q0ZrC80XH6PPMbNwRKO7KT9toBlZt7u1xLdIHKzgyWo85v+9ONtRvzvh7nux?=
 =?us-ascii?Q?hZ1/eE4pFoeiAZR0JyIJA2hHvDQeT49JOsCWPg8W+PchqW2AomMoUJ8eWmyc?=
 =?us-ascii?Q?otJccO7HEOmZuhXKS0Ms281H9P2fU8uSI9F06Wxj9jMxjSvOf4FXSrcTl1Ke?=
 =?us-ascii?Q?+OjovU7SLp9b5xQcoPF1UV2QV48OWhoNY4tPNxKp4DIMLLDTY38cBdAGXn2m?=
 =?us-ascii?Q?Hcbmao0cO5vLQ3L/O5yuC46bjGE/TtyCtWc9Cg51z9viv9EYTqYLIXuv5HEF?=
 =?us-ascii?Q?O1YXcDZiMFmiOgnRCulfBNeUO0W6gpW4wiDgOGJpHFgfOwE2uHwGynMrfMs3?=
 =?us-ascii?Q?091HFMAtwu9QUBtsWiHBxjk0s/j9zb8AQ6usYgHPYsKHOwLk0JlQH+2Bwp5w?=
 =?us-ascii?Q?Vpjs/jhlf9wnu8HuvFEpU1SnuAa6kZpanIWn0/Jo1D3wyn/Lp+9ZC809XYU1?=
 =?us-ascii?Q?AvMqcMDeRgfOTnwJnibAZx1QkAz3EQfEEC61IP9LtiBhEFpbP5z+JqILUfnt?=
 =?us-ascii?Q?X1/K1OtDduX7rYDtLp3S2wR4huFRalOIS7Qgt971JNunPY1qgV2A3tGPQHGO?=
 =?us-ascii?Q?84ETBkN1W6W+IfhVHj2uoA/o76C4sG5ygbrcARjvGNUdyds2WEvOb5dUZnvs?=
 =?us-ascii?Q?p1sdHO9G1rbge5J55wVxGHa0IRN4oUTrv/0VtPBFy1j6CeqDOH7Nvz63fpo4?=
 =?us-ascii?Q?HVIeRBl2ltWMj21CzkB6ocppO8+ANErcQgLh7GDHE195Yu8hKew+QOoG5nWA?=
 =?us-ascii?Q?mp95dEY4OHykQPEEUrHy6K2ih77W8LYcHY3oJ9lw/3IoSvOsWnsIQKGwjYu4?=
 =?us-ascii?Q?Rw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 36Pf14rwLufn9PGFSbY098eIhPaogQd+mRxDdyDLLctgrJ9BkcCeDtaESsZsU41cZZ9YQsR/WpKgInhOCkf3b1fe2qya6P96MUH7b5AgGMBzWWPGoGEY+FzcnQYaHfL1sK4n/uLSFPNWLyIKqUKgVZ8VVHtQ1m3JZK50Fp7L/TB4TfMtmxsSEXbsQ7qKn2ynuNulT7c7D5/9DHGJVAEBiqwAzFm7jywnFv26V+pzklx3jNaVKdG8LZY3cxRB7e+MhjuovIBl5wUP/945NicxjweI/tVDhbt/1JLZme7HpmnmBiSOIEch3cP7L+TOgb6F6VcI2UXvnBD0IMHk9EYsRQJbu/hS6oq8ppK7U3cMUHMyv2WOPLUqr2elwSycn/UGymlohylkxLwWQDEh975l8w6mySZ/BnrOwy/gUiHeUVBN7p3GGjdka+r/KZec4geNlbtyLQ7ieScj1kTI2QWyXWvAwV509m4Ohef7zsy2qwd+t5i99S+CYCYkFqq4oOnzxu9C95MalbgnGP9Yr6edg8y/6803mUyBNVts76ejXWpCuziFT2FlJDNh2Bx1hMpmezfe0ChJ3RG3NVXvsB5IrHgNY4DGoKc6KHb+voglbWs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 24a52fa0-f087-4af3-0392-08ddef7fd32b
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 09:04:03.9839
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +2xjt+KBRDpp3XOF6i9I+mw+TJaGSe29G9trE1p2rNZLMk1qp/+ge8MHKOSq1WEsXN8whZGYXldudGS9nDxFxFz8mqnvjx51/3bW/D4I7Co=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH3PPFD7011BF84
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509090089
X-Proofpoint-ORIG-GUID: P5x6t0CgYSOdBKo1CrTAwMuGKUY3I1FN
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68bfed8a cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=gCCswXOMG9V64mD6cYEA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: P5x6t0CgYSOdBKo1CrTAwMuGKUY3I1FN
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfXyd/Qx6ybAQbh
 7Dj8UwskNE/S5odziWFy/3fYV1fKhcbnEw1/3qK0EBcklozh+3hPp8mkL6wYDXZYeTSSxWZzve8
 5h/SgfUANUf+aAQsu0aAZdgyodP3dVdOU+gFZLkG21cVGywj1M3uGGO857hYVnhEmxEjUukXcoW
 vhFjUeukeUd7cWB31tBK8cgDTYrkxLxVaoEpmtHHGjUEvMje20+sI8+oXSZiLonI92t5nYmVkGq
 KcJtQ2CBW2WzGb+MNKc8Sn+7RRyGfyCedTNDwkSV/ggPP3TrpMd6DxrlKV0j1eaf91XQ0jSyRJ/
 yqEZxW/qspnLQNwYjhSPGpu1O/2tk0CFOAU394nuw/5c2WJQ/ebf5lIUT1hcWb5Y9SNXH2tX2V7
 +r7EMv43
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gR+SbYYA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=cbZ+YCrx;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 07:38:57PM +0200, David Hildenbrand wrote:
> On 08.09.25 17:31, Lorenzo Stoakes wrote:
> > On Mon, Sep 08, 2025 at 05:19:18PM +0200, David Hildenbrand wrote:
> > > On 08.09.25 13:10, Lorenzo Stoakes wrote:
> > > > Now we have the f_op->mmap_prepare() hook, having a static function called
> > > > __mmap_prepare() that has nothing to do with it is confusing, so rename the
> > > > function.
> > > >
> > > > Additionally rename __mmap_complete() to __mmap_epilogue(), as we intend to
> > > > provide a f_op->mmap_complete() callback.
> > >
> > > Isn't prologue the opposite of epilogue? :)
> >
> > :) well indeed, the prologue comes _first_ and epilogue comes _last_. So we
> > rename the bit that comes first
> >
> > >
> > > I guess I would just have done a
> > >
> > > __mmap_prepare -> __mmap_setup()
> >
> > Sure will rename to __mmap_setup().
> >
> > >
> > > and left the __mmap_complete() as is.
> >
> > But we are adding a 'mmap_complete' hook :)'
> >
> > I can think of another sensible name here then if I'm being too abstract here...
> >
> > __mmap_finish() or something.
>
> LGTM. I guess it would all be clearer if we could just describe less
> abstract what is happening. But that would likely imply a bigger rework. So
> setup/finish sounds good.

Ack will fix on respin!

>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dacfa550-df12-481e-a47f-068c440e6a8b%40lucifer.local.
