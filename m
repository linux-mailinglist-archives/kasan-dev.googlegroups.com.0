Return-Path: <kasan-dev+bncBD6LBUWO5UMBBD6NT7DAMGQEFPGOMUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 58D83B575C1
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 12:12:33 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-7341cfed3ffsf10813167b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 03:12:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757931152; cv=pass;
        d=google.com; s=arc-20240605;
        b=YGltldguhaAAkQPkL2OPnZme3E8ov2cMKZLDwTH4CcJYBSKaMnTsOuS8RlDmXEr1tG
         oOo4FLTSsnFUms6XKUrpG6NaYy1sg70A2RINCnqhA/YFRFcbFsGGcnVVgKm5/HCrixYJ
         KGvmIg/7Hr2mQQHCdDelcErU7sgof8BoHBgZU/xUMaFab1xrtS3fh7Mb/8ZGVCbTJrVC
         Z/luUX0Uoiug9cz1KV6gf9bX8yWQ8exNIn26hXtomZWOE22tV74GZPUZNpYOhF6oh3+t
         hYWdL9+OIpgtUtmxF/vcikbKTv6ejPSs5nD41+WXUgV3K2ldkCnEClhC+b3JosJ2aHWD
         Ge2g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tnBB6NJEjLMpWi5/yxo+xtk5NsAlg8uJEJKy6E7HEmU=;
        fh=Ckh/Mu3lduTM9IpP8HYealRDhNw6wZbcCL/OWQWCUqQ=;
        b=Csu8tBKZ3Fo4N1w569j/iwKtVM08sn5LMJqlyOlUEsITopIqQhd4fGMCBjNil7vfhy
         o0bz1QFyoiB+XqxzbOFoZcyJuEiB77S0gpdCS0b1ia8cpGlfl9rNslOdIECBJCcOutKi
         SN/QmQSoE28t4oEgXjtwfwIidaLLD70HirlGGxv1d7csakX0ihVGRlV4vDqHBeG8GNHu
         Yby4NFCi1TGMrJUDY7MeP/wrinFryBrI5jp4bVO4Xbekwn7kQvrxkzWp5laFK2ekkeiK
         TFMJDimBL6GRrYRo9ct30NU/kfiyC5iVl2fPQffHvKUg4EZ7tQNVHZYHNyRuQvETIEHB
         pWmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=P8iCC+TP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=mlnIyfDr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757931152; x=1758535952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tnBB6NJEjLMpWi5/yxo+xtk5NsAlg8uJEJKy6E7HEmU=;
        b=DKC1aPSRPKxKJqvfq7b+Ru5AbWvJUE/GCN9oBp6lslpOGp2yA8vrXyjcuILK4FAKkB
         ue9yQuWIZNABoXQrr+jZnTVFihHVRvzhMoXszTw0L3QQtYll5ALN5vJ+lLNfZXaErNN1
         XkdD0JraHIo1Lj57fOvXWzqHA4WrrBHlbN3rGl86JIuYFEfXXmlv0PSfUK3YdY3J69fA
         rNhtxxiBn++CeMIg3Nkqrl1ap3Mw295R5r0sVLTqK3vA76oXvWgIaJrNgQJqEg00LfM5
         k7aTjopM0jrL1/YtAVdqywtFxYAM9pPRQ8pE6wxmjVou9Uy+tSS0dx8TlQMXoeYDTJPo
         8syg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757931152; x=1758535952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tnBB6NJEjLMpWi5/yxo+xtk5NsAlg8uJEJKy6E7HEmU=;
        b=jfi68SrwgbFWFz0QvgnjTKyTn/O0D/TWq540H8GMS14TIsQFMwEbNPhuPUj16c7awx
         y/iqbjtqTcJuqd8k/oWKUDrx94yYY9BqBEQFYoF8HZeee0fqJ8gLuWUswecyTmy8s53P
         6RI5ED8X/4P1jpO3h3Vamq634paXoiizll+zA5fTuaSCacnj/1oEcmUUtracr8sivpnI
         nSVr9VB5YJUWMT9gUwAfsi7cuk2e5mxb1F7MkR0e1EMa9k7NcBXWZjMriD7HA0AXzcvm
         Gno3I/c0v+6lBWtEN+h/9p4OaZeelRM2PJMhl7ec0O01DbRnYw5xboiod3101a6bEXPX
         7k/A==
X-Forwarded-Encrypted: i=3; AJvYcCWR2bGZHOULjthW5wuNmSDaUqgcZ1sGcPntZvt6MvJ4vqBUYE1hi1BF2DZrgn+YayGCbLnSFA==@lfdr.de
X-Gm-Message-State: AOJu0YzP9VpcoRRXd2xG3zsQZjPl8SelNYFlIcymbO1/PUdloiNeEqyf
	r+fWSr9LzPQN/inlFj0OHnbjbQwUo+0bfZ4VAtfRltFKSAFJxt3K3Ksq
X-Google-Smtp-Source: AGHT+IFQtu5nZ8n3n0FiYBfe31MdlTe2slqjPtkAY4thh7LeUvu9ZV7EHAQH+m+q0Qi9jP4x6i6zOw==
X-Received: by 2002:a05:690c:dc3:b0:71f:b944:103c with SMTP id 00721157ae682-73064fea3edmr108420157b3.45.1757931152054;
        Mon, 15 Sep 2025 03:12:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5+EHPC4w6FzgygTwYh0g59WVLmT4LgWHpnXtshXVdxeA==
Received: by 2002:a05:690e:d4f:b0:5f3:b853:37bd with SMTP id
 956f58d0204a3-623fe7548e3ls2285346d50.2.-pod-prod-01-us; Mon, 15 Sep 2025
 03:12:31 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX2CBkPRr+UBQExQAxq+7f9c4g78qa7XpDLQWMQjcNR8hHLaTSyh7m6Qos/9Rnab5mdoyjFGJmOIdI=@googlegroups.com
X-Received: by 2002:a05:690c:312:b0:71f:b944:103a with SMTP id 00721157ae682-73064df8ab2mr97554647b3.43.1757931150986;
        Mon, 15 Sep 2025 03:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757931150; cv=pass;
        d=google.com; s=arc-20240605;
        b=jig5BGti2wjsnsxP00EpwiKQ1QY1GiowVcR0lhw5K44Dly03RiUiijCwiwXRLElUXH
         au4JW9JKRrA4foFauIedGA3biW8H32pMTrd5sAVtwZdTa4u45a3JJyXT4nW+ZeMsnl2p
         9dtK0dnoGdZgNopZAjKCr63wnGgNXE7CyhtZ9Aw4KkDnHXUpb2YmVdtHCGGJ1TsCMRaS
         KF7fivb/7SmUMX9hzXdYObUqtNgDgNFe0rjU8I+v8ZkbmYMC4QDwZAzDxT+9w22clmVk
         Szq1TbaHEUd9fBTeko9EjK6bmft36NjVoTmAqcM0TuhiHQoxlBm3182NvzeV+HniFOCh
         3IUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=QHBSJI7x7Q8iVt04DPqkfJH7iJSV967KswShG/qUyOw=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=ZVMU+xQ31NoXKg37uLhHsyfLVeMQ0IMTnksJU6PoQt+mrMkv4pHF7F2sO3N2wGvjBA
         /YIGYnK6PZ+0Yi+5SIurE5o1MZLYx1ss522IZhONEuKhdrDAVtuQ5IxbpShRnaTxh9xb
         cGJonKMpkfIg6WD3/NNZbEA+drTE6VMV7gNvPfMgHXrCp3nou8tYYgA4SFp8+wnARyqN
         kzbLqH+BmwgEORndm3x+C+SRc/zTMiP0BugOv4+iV8TpkpjPZZFuUn9jD6g5St4hX5F5
         Wv85PUvj0bj8dJLyPcI7OwFz+eNAgg2KM3fCMxGlxMVzaaDvkV1b4UTXG+aD8Z5GWzNH
         RNrg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=P8iCC+TP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=mlnIyfDr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72f785c8398si4393437b3.2.2025.09.15.03.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 03:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58F6fr1S023242;
	Mon, 15 Sep 2025 10:12:19 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49507w211n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 10:12:19 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58F8HDHv015290;
	Mon, 15 Sep 2025 10:12:18 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011040.outbound.protection.outlook.com [52.101.62.40])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2h3cpx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 10:12:18 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sEar4JTYpsgHvH7S1iupzLIsN2E0SrfWiIldP3xxD7L+Wz77jb68IUf5w7SZImU+2r3yo48dN5YIa4nUjxWiJguwEXtVAHQu59i9IYxidsQlVmQTec7Q0TeXY+wT2hK/UTuuOvABGcEE3x8nkUTAS3qI/NEs5WhgnZAnfeMvkeHUKDp0ZBQj05AfFoQvHdc7zRJQwhE6vsDnKtUKYGHRZfmUiFYLJ0J91AJvJNZ4nZMC5lAm2h6our6nohaCsyOCfjjKobeRpE3hhbsIWkSeQ6Z9m/HfamBBN9Mk+ozBUM0ph0JdKx4pjKq8qej/TjJLNLecBo+9aN/C0msFKhoujA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=QHBSJI7x7Q8iVt04DPqkfJH7iJSV967KswShG/qUyOw=;
 b=mGsA9rxo/BWil0qKoGgKn9lQo5o6JDKQs+ZsVk5wXU3jNCG9k8adPBYLpAwMeK1TpD2u+CSXAU66AHcH5xDT0R+YKG3p8KqrJb1xzarXXAYNKVCf9mN5pZUmFy3FW7xP6mQuNhCu5fRruzWNM9a9D8tiOe327Bq+uoXzpFErsaVONBvFZtUWan7CrKVmJZvJkaE9+50l6PhIeiti0gCSzmfhx2CDA0fJy87r5y64vd8wc/95gpuvwSjZLhuDnfq07J+/Ql3fuZ1XYvnfbjn232GfIVDSWYsD3fwCF2Ogc9E+XvwcaOFXGoOx8VzdEtjY954Gd2bBC9rVnyzzk3aVZQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH0PR10MB5612.namprd10.prod.outlook.com (2603:10b6:510:fa::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Mon, 15 Sep
 2025 10:12:15 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 10:12:15 +0000
Date: Mon, 15 Sep 2025 11:12:12 +0100
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
Subject: Re: [PATCH v2 05/16] mm/vma: rename __mmap_prepare() function to
 avoid confusion
Message-ID: <9428453d-d67a-4c49-a71e-d0acfee7cc12@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <9c9f9f9eaa7ae48cc585e4789117747d90f15c74.1757534913.git.lorenzo.stoakes@oracle.com>
 <97117b3a-1d92-418d-a01e-539c77872ff2@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <97117b3a-1d92-418d-a01e-539c77872ff2@redhat.com>
X-ClientProxiedBy: LO6P265CA0003.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:339::10) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH0PR10MB5612:EE_
X-MS-Office365-Filtering-Correlation-Id: c8f7c5ea-95b8-4099-969d-08ddf4405842
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?6R08+CPKy035O17wIe4W+Yx/j0XGAagVqRwOxj6MEyGVRdutamC/mh489N3e?=
 =?us-ascii?Q?FkqDrzQKx2NIP7F62sxV4IhoViLPvsTGZABnVzwgAdC/gRiuuUhj5hC2Yp+7?=
 =?us-ascii?Q?Mv1tO4VEdX7C9m56nf9iMBsA5VyU2Ng8hzJthdmiJhH9t8AvGHZ/1mcLbWYG?=
 =?us-ascii?Q?b5nzes6/IpmVxEIjfOOS+nmVZvv1wvUYOlk0F+ysUAN94LtVFDXjzw1y3SFW?=
 =?us-ascii?Q?+LU1pzudm8Kb7AQ8zc7zJn4MFTWRT2ljzyB3uK+YB3k7jl8BOTVwektHsMRo?=
 =?us-ascii?Q?eTKCIhgaktfbQtVs5ev0GWIfF0mPz2PVZHvfLMVdoGC8m1iZIdAvrArUUU8u?=
 =?us-ascii?Q?uwykeHx/DEl9g7M4fD30/QtYVcy551YROfe57qFhdMvIlEteC0kY1G1yHa5F?=
 =?us-ascii?Q?pbvxW5Hg5/yT0Yf6LY8FNURLeehqLqjpnYeC8fsCgvVcd+mdM5JtUNhQgSK9?=
 =?us-ascii?Q?06vc4ekZ9uMOo1tHjy7xuaoLb2Eye+GtmY4VNkEleKKJWtjBEl2OBUozjUgk?=
 =?us-ascii?Q?WuWtuNuOWRM9O2sZiE5fyTNm+3AmyJ5Eu8jkJGbHejKowolkBp9Dt8ms9wmD?=
 =?us-ascii?Q?11avOvGIgIl8vg6AzRNLq6pC2m4H7aAyJuroyUrEsqJK9KWZl/nVWwRbtpwZ?=
 =?us-ascii?Q?w8TrFe0tQsR3pfNhRShel/WpEm/e3bsQ8aexksAU3bOJJfi8K/5R4Nx/RD4l?=
 =?us-ascii?Q?eaTw0mOKtkTauPItsy6s7wZS9ah0k+UTwKBEIYsN1DA52T1LHzmfV5kn41vk?=
 =?us-ascii?Q?u02elhiwxmO284WvJZB8wctXswcUEpJNZ0g4p/gVqg48adQRON9TrEe/R9WZ?=
 =?us-ascii?Q?SMRQivSImWUlMyl/f11shx+yWh6/IdvV//876CzAbQaDPOg53WAuoIeQ9iNy?=
 =?us-ascii?Q?IEXECySorydQOk/FjsmUDlC4vHsYVxKiUvHgKMKxCHbSEmmeIcWE40qp/MEz?=
 =?us-ascii?Q?jZbfrW8e9NwjsNNe4eshz0z2ozUqN6DAcf6M10dKJUJqXfwS82PKW+7idIV0?=
 =?us-ascii?Q?Eb59iHtTQ5x1OyMpeVvU+1nuPbuwLSaAnXDjTrJjDS4nLV28qZfcKb4IUitD?=
 =?us-ascii?Q?QWfleGeV7xvTr8Zs9yWpWD/c5150U1GQdtMEOMd+5B+v/9EpA+BKhGYVFkcK?=
 =?us-ascii?Q?3fTPumgJE1FB8XKKCBJVJBFx6l8JCysahYkJMUrSO8+cpjZi28l0FqP2qdFu?=
 =?us-ascii?Q?XL6X9DdJcmOonDFfCkFwCyQmRZZ4jxxREdAojd0Xw9sXI2BiQPAazZsf2HVO?=
 =?us-ascii?Q?gQJUpkNJOPtN0kL/asI6XJFqRFPhyQpUo/alU1epjZfbBKj772ioCjdiSo0w?=
 =?us-ascii?Q?OqPtvXfigdyUpntT0In70F1Z+by9fo4jD5FiZ5HwfW4YTFMiROHYlE+HncgP?=
 =?us-ascii?Q?rTPTcijTn3xHCI2ucpwol5emXR89aF/oElNib+fTKjIEqhxBQbmCnBt7+1s+?=
 =?us-ascii?Q?2+Itb3T/vK0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Ug8QOWvII2/1VBbtyY52FJDCHSEQ3N9FXD+SZO749waaRyq6bPcIJz85cCiA?=
 =?us-ascii?Q?dgwRXTrsKiHYBU81MSzVMXXXa1DubPUl2SnuMcZu4sTn1rKl4c7QTDP6gkX+?=
 =?us-ascii?Q?2LW9Ro5JlyMWnebVuvWHTrfFbfQNceclykfhNhBFcTIXsHVHRTxvLO6ZT8ob?=
 =?us-ascii?Q?P6U3jjnA0l3VQPcqF69bxX4EHSXi4/v7Myc+lwBNNd7ODbxRT5JwOwb4vJm/?=
 =?us-ascii?Q?7l8aN50RogW8lAXvrsZ0m54lelDR4R74lvPeFt+K6j5syojIu612NVCQJyLf?=
 =?us-ascii?Q?dfrG9qH5AMBTPdrpt5x04DCS9nYw4ES/4OX8P7qiV60g/geCVDWgNvRV+xFj?=
 =?us-ascii?Q?a1JkpXFyRPDerg84QyweX6Er06+VB+rlRhVPpv7Av/cUxGneeMUSkny30vSs?=
 =?us-ascii?Q?U8mLVsSjA0fG4/0syJZMGKrUVGPDkch5yXd4w591y2pLxTjypV7tQGfHsETk?=
 =?us-ascii?Q?DOVaWlXK8nttHRgbKZT1WbL7xe9OCOGXexDJUqTpIuN9PRJDDqDo7jC3roAR?=
 =?us-ascii?Q?fpHtCba9qIMCKjgFLUqlgTkQNSUpYlPMnsxGS0SGKihVM+AgyO3+wE3+u+Xh?=
 =?us-ascii?Q?VPMqnIFE9EM5GqtuZOc7ueHRL7U29p41i3jvxAtP0Eg4X7g+HYrKEeRgZc7L?=
 =?us-ascii?Q?WRBhTPNImgCYgvXHAK6R+FTgMcgZWr+NM3RbFZPVlbGhmylc8LfIHqw2WeJ9?=
 =?us-ascii?Q?TsVWN12tihSQJnOh3TkTvheByDRUV4GvtIy3LRbNUp99DNJLp09MRFGU+ORb?=
 =?us-ascii?Q?V+4QXwsu8kYFV33jgsVdY00gzILASPeqw6q0Guk6FW3lZVNZ2qv+h0ORmZPk?=
 =?us-ascii?Q?XL/SDOfDAs7s6loMC+T56xUd7MF1VTTZq14P435+M+fv1qu1rQkiUBMq27cp?=
 =?us-ascii?Q?ibF3OyK7FKOTDXSDdg5MX9b6+LBgkoDEpnBzCEICjWqbFIpxIpXRfZQCo665?=
 =?us-ascii?Q?AYhd0Q3xb6+FG/uwGBqEgORw0AjDxGiWqCFnhB3SFxovlNu8uLB8h649eDWz?=
 =?us-ascii?Q?dVNAPMTyKD6CQir5QCujzsycdNBRScnVQ/3vSYYqH/GUJEv3OgEZqY0sO2aQ?=
 =?us-ascii?Q?OLlOAg7oa7/lpxRgpL4KC7pN+vcxwLtWa2pDD4yxzj5VcEn+nr1o/7YGhOLi?=
 =?us-ascii?Q?CL13G3OaAUxvJaeRZQcEAVKFtptWmJzaht7VCLC6tWo3mJiQkgd43EFtp2k+?=
 =?us-ascii?Q?igvJtfpq/vKjQUSVp8/0FQz+Cn3X2JHdQuvZ+ffGy+Gre6MekiadQdZNwV9j?=
 =?us-ascii?Q?IUEvG+qHKd95eFXrNC5AHfL+M2Wr2/OJ57/7D+C9WwLVzIxYJZowkFXb+ana?=
 =?us-ascii?Q?eQd08CDe7MCLE9fe08VeKY7TTyuhsUO1bqGeZLyShlhL5TGZpod6u9CNQfPM?=
 =?us-ascii?Q?ZLw0ohxlG3pI2aLBTi+nXUgTQBrc6bcjfyR8F0sPHlzahtmperK4KTxCehrI?=
 =?us-ascii?Q?kDtA5XnVmRz9yGPUkq8apPjs7+/TID8/T+d4shWl6qjVvIXGco54/2/r+j7Q?=
 =?us-ascii?Q?Y/FqtXL5oQkhsZaDQVZTpoiRMPVgOtsafuqLvwYmZulMKQz+Weqjsaj9r/oK?=
 =?us-ascii?Q?tyk0pMH26ud6UIU5UxG4TwK0p6dcFWd7FPrFr6PrPtALTTXFfNHwxjfUTqGE?=
 =?us-ascii?Q?mA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: KrOFbTVQX57EHckIc+KtPMQQYJ76sLmrEEef1eWELD4BdHHQNPkM7jX3uoFIr6/Ez7I4/7zW9+RCVbx+UwxM/aFe2iSY1hZNBSvSf1JtTul2MDmO2bHNwYEL3356aEKTKXXkDGk37KyfKYL2nkmESuxJyWp19p9Uzr+bCXQLE30v0Dvuf7aZYerii5ccrEScu2XOjdFW1BBjkUx+mCeKv7glrI5tIXeDJTVZgl7nykW+KRqirzFcTMlQuDp/3Ia3r2ZAOH8ximxvjTCo+6Khb0rVplpPCxiws6PhIkLBviz3x1QCBaAr64Si26diFIjNvg2S6lpPYOVzoOCwmH6QQbbXF5XOb21DD+VOmutYMwyqn6vg6Sotb+U79CilLh7azBOQXfYuEmTLgfRhOaK4yIvKz55Ds1vM0/PeOeY7HfIBhXSh0MncTEb0/NLsCll7cf4sbIhAkGD96RU0vbi+d/a6XRc1xLGb21tz52N7wc0LX8WCpWcWkSzBZakyf6nKZoLbTAcb90VGh0d0NqevczcRZUqn0EATMSQrZeuioKHxg0+O3FdBjeykkMQIuqXuHRFWhQJKJkEEJL9iapCuwkXdapGDTWycNyAKxScsCyE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c8f7c5ea-95b8-4099-969d-08ddf4405842
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 10:12:15.3307
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZfU0QaxLFKSQNyeWnJS7Z8GIEWe8xGk1ZVtzC0wd7BmRDzGjKZGTSXX/5Rf1yd261rEIt8LhMgvyjjgAQIXZOfBw9WML8wgeJq2iWT6bv0U=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB5612
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_04,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509150095
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyNSBTYWx0ZWRfXwy0aQYRkhaK0
 hbzwexaJNfRKmiOhgI9ONLqeJJEvcnjyFWvJAVnLfuAIZl5ARRG4fwBmA8rvGEIM+DW0QIX8aE+
 0AW/QKup1eMe060xrheTaZNwsUFblVNWMdh3IaJPSl6e7dfa2pH+GoQ3xeqO/Pdo/BlF5i43WSs
 ZuZ/BRZ5YzMwdQtDfoUf28qpvyF6EGc9VjnKtf4wON+/kHpnvsQ3UXi3edBXuAkBZd1/gP2o8R5
 MjdLAlahjzaHyd+gdp9tNJ4RdM8Z7B1rROR50VDxz0uzNLTR3aDFnbrDF6GcA7TsC+ssSgbcRbq
 bVuPfEzqqP+curv3YPwCFr+f7kAUSah066BusJVjKfoc7tjK4S4IDXs0k2FZfCC/gyAwzdwSq0g
 TBbG6a7EoG5WD5WeXUqaQfxE+PyNgw==
X-Proofpoint-ORIG-GUID: u14swurpSvpzcWIQNC5cUdn7GLtVkmF9
X-Authority-Analysis: v=2.4 cv=RtPFLDmK c=1 sm=1 tr=0 ts=68c7e683 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=JVFVMCPGzHlCQygsS2AA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-GUID: u14swurpSvpzcWIQNC5cUdn7GLtVkmF9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=P8iCC+TP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=mlnIyfDr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Sep 12, 2025 at 07:57:20PM +0200, David Hildenbrand wrote:
> On 10.09.25 22:22, Lorenzo Stoakes wrote:
> > Now we have the f_op->mmap_prepare() hook, having a static function called
> > __mmap_prepare() that has nothing to do with it is confusing, so rename the
> > function to __mmap_setup().
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
>
> Reviewed-by: David Hildenbrand <david@redhat.com>

Thanks!

>
> --
> Cheers
>
> David / dhildenb
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9428453d-d67a-4c49-a71e-d0acfee7cc12%40lucifer.local.
