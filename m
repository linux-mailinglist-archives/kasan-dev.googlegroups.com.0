Return-Path: <kasan-dev+bncBD6LBUWO5UMBBF7G7PCQMGQEOFQMBHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF9BB492B5
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:15:57 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-40194dd544esf21506065ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:15:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757344536; cv=pass;
        d=google.com; s=arc-20240605;
        b=cRUhg5y2sZLM5gnTxWYvLPdASKveQRFNmAygjYnvzRPnzg9EmzV5GNyXX+siU3ghQJ
         kpGGtOpy1zZ2p8gn72o43MJDhEFKOjQEmuOIGnBzbMMijx2os5SPP62bfHCGDOQIYLG/
         KHYU+yQg/jE7KbJ4moAubNRGjleSmfVwKmKBe7n0LUt5gC9LDfpXIHRSiXrLmS+oZVrO
         Y0WrSnN0NTjOQEKh0YAsiM7zYiuqRC7Qrdfd6zbSg5Zssnd2VLz/MR3RKV+ECP/fBUwj
         4QIekZ53tT4K5ksnSOjx/5nb5gW47meZ/FI0TTM+ybTA6CRn7kPitbTLg4dfbLi3K677
         gkMQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=13ZrAyBxLGVZBX8WYHn+QXDuYnq9kU8McapgU1K1XDY=;
        fh=pSUaQo7WIiyz0Pgc4nBbKewADqHtUQE/WZ/JP/Z3LtQ=;
        b=NvEuWy9fuf3NDbo3iSVJgVFxa3+dJFbb4Ac77g6A68fSQbdhe7DOu0qDWben/Ogh54
         HQVWhCh+vvVe3GpJuxVwuvg7/NFIhqVVTCL5diKtjOi/9OGmj7sKV39EnW3KVvFP+Z0g
         ewgbPjxGNUIy+bYdh7zSYPUjH97poDqqv+hItJmWN1IzvenmzfNgwmi0HbxNdldj47Z3
         ICQHc/RyBZtO+nTp8zgmB59wj1OHuSxheSx9JhFKpYs7GTcPurd+mUzIrkLhZUkxowIv
         ZGAqJa7rUKMYS9fPQUzVuiz6Jx4n9ThBIH1DfkEzxNMDTcexfEkyblnZkQrLTU4y/qhL
         Z7NQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oHMDtuZk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xKeE4aYQ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344536; x=1757949336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=13ZrAyBxLGVZBX8WYHn+QXDuYnq9kU8McapgU1K1XDY=;
        b=pCtMQiDu1wqax81PFzfXHewTOSxYtVnEUNoAe/0h3WGFrfX/U3U9Tqt2ZaV6p1CKWR
         //LUPpb3S3fd2h93S80JFNvE3ndbItIOdwMK+Nm0XLZLqUo/e72W/alGZUOv2fyfaY3p
         oVMHvV2dOa25O3lZgnm+TUi/jdEwVoua+ZOjyFO27msYjvGMXRQwPVcl0z7wHJapfSyG
         iI5uvl2HZrUWB89mtcWBI6AgnBeezmMVRV3IulcQOl+T5EaTkJ8TTQrRz00VfBxw5jhX
         WqU5tCt38rTAJLJ8F4D9izBVgPDJ6zfobRJFdlHirhn/qscXaOVmO0CxFdAD6jX1Lrck
         Yqng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344536; x=1757949336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=13ZrAyBxLGVZBX8WYHn+QXDuYnq9kU8McapgU1K1XDY=;
        b=Uwhlz1KrOIeot+QYkZhilaUKkjO1WuwxBo65zf2GhwEIhImm5YWvAg7dgyvJ7gcrPX
         HZOG60GKKV+UslN2AjBwG5Vl/4d7m82TQNsKdoBjifH7PMiIUCOJLTp4Sdb/OuMx3Qbu
         jq7HluyatHdk3UT1F4cpJu14qpHtEomP2UCnr5EJnHeRqFKcpjHswyJZCJ/meq8HvrZO
         zpK2qmwA1wG31iuarJ8Qls6FcPWp5rlu/ADOk0cHl38AzXC/1XKBO2ESkAlGd9JmprxU
         XB8IkuHfOIhZ0qcHA8WaGLd8pYEk5MKo4asGyLD24qa7/KS+y4js8moEvWUwSGokhWCq
         +P1Q==
X-Forwarded-Encrypted: i=3; AJvYcCWPVjKRSeSH4UanbrH5Lm2Mh5iuTvcTuyQ+i3LbMQZ3XNC/+RH8digHNSkNKPISX6zEjl3Pcg==@lfdr.de
X-Gm-Message-State: AOJu0YyNr+T3sq7vx5RS2GVcwivMG8yECjimQrTbkG+X0/9AOBOQoxJK
	GdNO34+XaHXJhGFgvwy55g4JpWKpRCqn3s6mfgHCZ+HMM5ZGYtQ7ibhN
X-Google-Smtp-Source: AGHT+IFz3fTjL0VQXg5qt23oZpyqW4dAfA9X4PZVEIOYlxRUxMwh1abNWOmxwI0NNuGPBBEJBpcbxg==
X-Received: by 2002:a92:cdab:0:b0:3e5:4631:54a5 with SMTP id e9e14a558f8ab-3fd85316f02mr121609095ab.18.1757344536244;
        Mon, 08 Sep 2025 08:15:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSENFrTsyrTEKlRcDunUjAxCNyQWxsqYmdTXtDTDD/3A==
Received: by 2002:a05:6e02:4710:b0:3e6:74c0:280a with SMTP id
 e9e14a558f8ab-3f8a4dad274ls25619235ab.0.-pod-prod-06-us; Mon, 08 Sep 2025
 08:15:35 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXPMkl7U0RLA+Y/y3wxV0iSjORuIUuPYkh0xKKZNhtfBWF0CxQ142uKSvQpLj+Z7xZJ2KXyeb+RiZg=@googlegroups.com
X-Received: by 2002:a92:c24b:0:b0:3ec:88e3:903b with SMTP id e9e14a558f8ab-3fd86730fe3mr98989085ab.24.1757344534734;
        Mon, 08 Sep 2025 08:15:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344534; cv=pass;
        d=google.com; s=arc-20240605;
        b=KICOsKolDZAkoUfkFiQhlKBTJueSrpCAuCAfJchMUZESLEXUG8HXq0AidcMEyTPd+G
         pJiPZlS+srCrNfRNN3rxdVZxDRVHioCujxXN0xY+CyzC2eDRoONCQ2xBQkbhaHl9sdSu
         liwxRFvg3kkediy2Tmb3qRFf7LLSSHDOwpo9wAZytxzAK9GZuo6azui9LjT5ulkxcHMC
         Algo5vyAmApXqy2c02Li+hoUTrmfT4lkeN0jXna+Ytzbr7hvQb14kAiS897ENTcPFpsV
         jg0u8g+YLhPHfQ8DsbbT6yAcDsUMtazo+zwYm0d6/eYYynPsACCrKxg1qaSfr48nvwhj
         6Kiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=8PxhyAwodi59E8UuqgtQajPJ9vMy0eytkbOBY9y9VLs=;
        fh=9/EWNal0HC72kr2l9/9pAk5c4rZ3WP2rcxm2ljH7rmU=;
        b=Ai1c+Cj39viV4gSvY7wwp5dMhcaPw07LRwdRv3rko+/LP8jJIRWJoVhEqe5M6kOYDB
         d1JjwDMQTmdj2NhNYd6Ypfy++nZ/Xu0dpAnixPHsZe2RGye5x9BZzm3c0lXx6cXRIu4Q
         PQazHgrH7fkVpkrL5FRuQMCSDsDo6An+gfncG89eMMmMClG3nOFryulC9lt/odNQYwh3
         lxUeHbI5cxkx6odzBhgOJbYNVftU9IDxwlmbo5Z8p2XSbCzYEZYkoHc/CfrWvvdhvN/a
         eS3CK9AbxMpuwNlG/gEZBesQUvPajx4I0Qj07QWT7MmH4ZQPW+FIvFuo6AA1/C1FfPLx
         ggJQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oHMDtuZk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xKeE4aYQ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4007fc6c9ecsi1820605ab.1.2025.09.08.08.15.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:15:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588ExsYM029686;
	Mon, 8 Sep 2025 15:15:34 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921d1g17f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:15:33 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588FCHbE030655;
	Mon, 8 Sep 2025 15:15:33 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam04on2089.outbound.protection.outlook.com [40.107.100.89])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8b35h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:15:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EY4I7FEELTG5afiWHerGb1KitMdqleQaLvrAQG0qvedJQiQTAh6F6nBUep0jKmsoj3zsXCEePxGaZ6HZ1zK+zflM4gt4/2MPFBsuMPEkjVWM7rtH0KgVuyuJqDyLNesSU0XX/iRqA2IXxRxYjPyc3LzQQu+8FXKdSOcnNkbyhRC0ycMYgHsgIuxyxFNDEHoAMPNIkFE/YJaRzgqHLjQjtXnT0oT5paGEGqqSAuSyIcL/yQgra9joT2M7yE8qohuRAbFOYXaPEGQQt/VOd9j2zV49Wl29t3IYLzX85x3p7FI9JT4n231LGLlBLctxVwmQAyI998PXK6gI0T/lIjL25g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8PxhyAwodi59E8UuqgtQajPJ9vMy0eytkbOBY9y9VLs=;
 b=SpMuWzQ6+lsobEd27CPtdK7MY52UlkZlxS+pK1IJ6KEwA/shbCNEDLvmDMYdgrkQEFpB6GWFu28Cqpeu4s0Ihq8rC9IZaFUDflo6aXihZPiEFLWezXWa+gMXoEqqgiJ6FbBvaCjzvGUCVJb3ajgX9C7asR4yNrtre6LYAEP6E5BhO1N32zjZmyVHCYTUy7+8oNKfLKhQ7OL2C+KXfbV9qO6+630wSuX7H+AXkKUXf66bNFGN0IeXlV02l36TPdbtVLb30lY1Jo1ETu5lfgWsieKMxdhe4OErSFDSqiLYavpVbr/Gk4eGMoWzWZaFbZhTZcsgaBrZeyOTAiKxQGtn4Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA3PR10MB8067.namprd10.prod.outlook.com (2603:10b6:208:50a::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:15:29 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:15:28 +0000
Date: Mon, 8 Sep 2025 16:15:26 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Jan Kara <jack@suse.cz>, Andrew Morton <akpm@linux-foundation.org>,
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
        Christian Brauner <brauner@kernel.org>,
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
Subject: Re: [PATCH 00/16] expand mmap_prepare functionality, port more users
Message-ID: <4af2ef49-2695-4880-8d4b-92f11d8f9c7c@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <tyoifr2ym3pzx4nwqhdwap57us3msusbsmql7do4pim5ku7qtm@wjyvh5bs633s>
 <9b463af0-3f29-4816-bd5d-caa282b1a9cd@lucifer.local>
 <20250908150404.GL616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908150404.GL616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0327.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18c::8) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA3PR10MB8067:EE_
X-MS-Office365-Filtering-Correlation-Id: e9df85cd-fe6e-402b-6637-08ddeeea8b2f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?kdSm3E/wV/oqbe7dCa9LqIG69k0Ifbk/2zdCHMCFzjEcnbA9fNA4JsYnnWLn?=
 =?us-ascii?Q?wspacju+8ZL5+TWepNHLkyPz2LVyG/hpPJsyQPmSE8bpYcB1edNlDv28sp8c?=
 =?us-ascii?Q?HyVAVUWddrJk2c7oQD/TfLgzg39M+lUXEUKN05YcvQ/Vv/28DC+djFqJEz8g?=
 =?us-ascii?Q?pz7/yYDaqhbPRgrsCJjCSFvLeHaid2zoSVYpjKA/qgUN+sSOV/JV9E8lU8zp?=
 =?us-ascii?Q?/mkESgZroR09GhjawNlXfaaTi28QnnMEO0vAhaxWJsYNlQ0hF5SbkXZAS3FZ?=
 =?us-ascii?Q?LYelNkkRO0GMA+tftdsLJozCyLhqKth7j6Tfj+w9cjucNayhcQlx0bjUcqsi?=
 =?us-ascii?Q?+wzewy8eJjrX9EqYdAvaT/zgOYYDoGz666u27fV2b+JF0rRUmlU3FdIilBt/?=
 =?us-ascii?Q?vy4hyQCrQCVfMuJwn0xN1KqM080/7CUGO2O89U6f0KX2GwsOnBNTd4Zbi8It?=
 =?us-ascii?Q?WWUmdgIpcdySN5ks+38Y/YJle4MLqn6TyYaxxZ9RjWVPo2mYo6S5znhLqkCE?=
 =?us-ascii?Q?1wfAU/poBPE0nBChoot8DDDOItyUakF8bpI4DtkW9A7l+Fwvu0toskh4wxRV?=
 =?us-ascii?Q?q1T5BhC7lbOIPtqY0RH21Qsd8ZISWMWXInvbF+Sfg9qGh9GUpxR0FkQHpxxM?=
 =?us-ascii?Q?/ZNsI2ZoN3EbOGTygUn6cofe/1tYH//Kespt6QYIEcbo5JABYsk2kIb4Dkcj?=
 =?us-ascii?Q?jP+6f2cSxfSQ85kdGCizKLMkFr/L+RZii3gzTNxabIyGIsHlRhCAgGvKfAi7?=
 =?us-ascii?Q?wemkHQSWoU6fwBHizWOU1G7gIzWl8N+uD4T5axCt1RkSPmrnW7SRPipuTLCT?=
 =?us-ascii?Q?MR32UOmvXlMemgTPnrNorzX27JnA9qWkwaH0O1gFuf7qXRf5yewxvtRY9qUU?=
 =?us-ascii?Q?Gpj38RIYdSMXcAwzDRGSH+ba6U/rqo0rsenkNaqcKSLBcrvG/nSx5eO9Q8kX?=
 =?us-ascii?Q?5bm0ci9PfMnZbkJ8LnykkBApqtVdLmJIvfz3utPp5Fd0tcupV4BjW2Wm4xBo?=
 =?us-ascii?Q?tp8za4CitQyDxuA3x/42FxHYJnvrtqxv2Rnxctm++ZmNeyyor8BHsNhZqfOY?=
 =?us-ascii?Q?gFzqgwnLPWSP19seO6wj4oqDEqNIddHKDSxu9r7F74xEzOIX9B9bMjS/L/Xo?=
 =?us-ascii?Q?YVLXYzz5LvtnhlMyHg0kH7asa1fL4DijZCIeS+0BMqJEz9Kgdo0GHDochJv9?=
 =?us-ascii?Q?He/R/0Zt0KwVGjhF80lkMxH3lqyeDU1xgwlFJiPXfNZ4OZqxmzynpH7uNpHM?=
 =?us-ascii?Q?6vjfvs9aj/njejjaGFl+ZI1OguutMsXdhdowytFEdvLAuEjkWBi+Hi+iSgzu?=
 =?us-ascii?Q?IIvyg8gpZfWcWMF0wKcHeLCwBI8eX4kjdupQtJHwAztWmQ42M697QM9cybZR?=
 =?us-ascii?Q?NXYqz3pxIQW9cYKR1R6LLkAk7p35ZmhpSKgdJyO4bRJv/SnjNdLCYDAQ8Ix1?=
 =?us-ascii?Q?U/HMeHaRyqA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?FOrYrqldsJMWzT/1ajho25utWHaOpIQPrmYa2TYeuz38qFxCiLtWJDod4Nxz?=
 =?us-ascii?Q?9tmO3EhZncKC5s4EHK1igJU42oR3vwjbDsJx6cUnBIwy7YkIgM8PJQUdSW7U?=
 =?us-ascii?Q?CxgcGRRrHMGhk/dKlO02K5EujFtAoM3zqBylWb/Ua9JYpBgw9r4NPSc8gM5O?=
 =?us-ascii?Q?cUB8n5e2t5WUQk627JDkD3imrwmiEMI84JGf+F/yYAmw3BNYGNuKeImyNxy4?=
 =?us-ascii?Q?5WqRIUwwRFriLf8eLM2iKNF5s5CYHlzkQ0zM3SfqaBaKnnDXD6J4KVSy10PP?=
 =?us-ascii?Q?og5umGRXo2BMKm1DhazSd0X2JnIVraYFYcplxuHLOyBoOEXCyTc12303tNzF?=
 =?us-ascii?Q?FHmgdgA5epKrMRs6MsSjjs2/mT00Nl8SycN7QI2BTZs7pVmWEXY400trzJHD?=
 =?us-ascii?Q?ki3/C04zvk8ZJypfY2QRhiLc3zOW2DGLkQCLKqkJsLa0bPIh797WpKWhhZCI?=
 =?us-ascii?Q?rtytJOb+y83DYCiS4kUzr37x/F0wZQtQX/cvvwcV1uoFN5HqthmnkQoEKXgg?=
 =?us-ascii?Q?18HaFL2YtfSeVxu25fzAQ8091FXEci48y+I6WHuUaiiz1MjGRvyWRolCKbmA?=
 =?us-ascii?Q?Q2kztvnNUut4tzYBDoKAfKZoQUsKFZG2ib55SKoMD6sOAmTEsV6oSXnN3k9N?=
 =?us-ascii?Q?0B8mlMyFlEwjA0+vKZ118LWiAXsUV0llB/gq3IzbKhB09wUcJ04cEU7fbAdP?=
 =?us-ascii?Q?PbJ75bEPOB3DXQDxUn6nbGkwkOwZoaZgHVvXXM+0nNcnKzidVvNqFTah77Tb?=
 =?us-ascii?Q?I3x4GPLLqzT3qpJR7FUbKzR+MtH18KyJjZNb7hJsBSLqJcO8oKwbwTuBIRHC?=
 =?us-ascii?Q?03/uWLI+/G2zqbMiy0ZnKmhOYw+ejO73P/UzK3xTCWsH7nfZ7P1mQNKa3cre?=
 =?us-ascii?Q?XSDvv5N12eVETJdJGRU+N1HxKKiZRbDC8DdBVPxa5l6cocSMCTfcFweidvVj?=
 =?us-ascii?Q?M26DVZQR2Gq1Up9rIFIL06AHRdP/TxjuII6Y8p+I4mZSbhHkddmdc5sC+HPM?=
 =?us-ascii?Q?ywPKKyi9uTx/ba4FkYryIhSoU+QUaUVWW4mjakzwsVVDNrzhCsI2QG3h2ekN?=
 =?us-ascii?Q?4donOhaw9+odZsNJ8NuMUE6mVt7tlhkFG2PdOCTm35sBXm76DuZAc/hWyJq/?=
 =?us-ascii?Q?c6hRVoNtnb38tjz4/zJgq0Clxl/HtB69aErNs1pxu5Xcea6Io46IkL/BtCZt?=
 =?us-ascii?Q?oSfZCmTUZGlKNR/AUg7n+SyaIBIEHdiisewDgLiCg9tUjZMrDdsS2D90qhfz?=
 =?us-ascii?Q?EDa1S0Cii7SQvF4R52NBNBURYGUr18Np3ndIm7csFPH2FSThPC4CxCVXcAp5?=
 =?us-ascii?Q?01npTHd36C1+MCwVaiDV9S55OqP+x0u4ejOA9lKKwd7dSE8DhchceLgqBx0S?=
 =?us-ascii?Q?miutfdg/jKKI0a6NOUHnqFdiE7Ht8qN2CxAX94JHkNGLc7UzJHsRyDW/Vrtm?=
 =?us-ascii?Q?cJ+6fT9j0We1QUPBZhSNObCkgCpZDIiv1VlKY1Z+CQM/5qE38tX8ZPnFmgdv?=
 =?us-ascii?Q?6iJF0fIb+/w3FSzTR8hbexgoP91y2PMFg/JMBFl6xkSlIBlDgrUarWRLD8sx?=
 =?us-ascii?Q?ZYRUENCgTwQq9t3ylDQ+oqXw62qO4uks4Ok4RWVuBl0bNn5tXzwal7ZDvTKg?=
 =?us-ascii?Q?Rw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: GbAlnP7qUp54sKNzHjGKO/VWP0TJ9p/xgQ/VhBiiRRg8nqX0l+/r4gcaweMLcN/3d6BwH7zSkEWaknDCrfYTfYWmn2XCyaGyuMBLcDMYv6hzyEd0NSwhKW0+ITRnbdmvztTX2xDpjPYiIbUzK5YpXp8vDZCW0xXodyF24rlf7O4FceCFpAh7BLBND1bzeJf/0NWQUvv63vAvodCdm3t11cMn30vLedbf8n7JSBptDmT1PmvCJpTS25yJDeIX9bZtH7iV3B8/0jSnxKRb2/FomlkgM4s1Y7nTPXTob3MB+f1bq47xwXzJBvmdY4SX0CYZg1pYQLsZjhlD0SQG8rT8ZJbqrCQIqp0Uk17ipriumhaxMD0bA8I0I+coRIld/1GsUYlYtSyvhJiq04VHzBjSrjjeNxYCeLuWVXPCdGHao8wnVD5d+cIRhG+nKFom2VWW0fSnJ+VeQwItPbEEzJnw7EVpxVCNSSXcIAfN/ItIW0Lf42B7Qd/51k1PyFrCURq84lCh1q+II93MYTWm73quy5O/yw3nffqRr0kUKDvqM2Pym84zSopGYkxHgf22yfflfSAW64S04Xnp3o2MucGWI1bp7JwX6kLHQsldezPibBM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e9df85cd-fe6e-402b-6637-08ddeeea8b2f
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:15:28.2034
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: nX8jGN9xKNUYH9QptekPv2x1blScDIcAawNjUqixnl7HNZC2qEq5PsMk8TA35c0GhS2wemH1u+cbQqxCJHaDnhzOrVxtucANyKMddpvmfJ4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8067
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509080152
X-Proofpoint-ORIG-GUID: qN005XMaTBpHTBWiP7yc0Vbt0tT4bM3x
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MCBTYWx0ZWRfXyrsspPc5qqXp
 /96jz1jpvv1NEaiSRNeOMLehiEABlvr63tK0pUz+XowBbn9RlO2LMptwoY/BbiIsGEL1CDZZ3tR
 ISPG0O9jw9syiJ0R+vC7hp7aQxVjLzE5XTTKxkxbAlucblvoGy1XJ6Ogl1Iam786UgAnERiV30Z
 KYcp2vuh7L5RI35RmcYfBboW/nWMsT7IMaHHmqnPyHcI2focwMxdhaY+bk+1EpzaLEhALo7Rrxn
 w32EkF8j8HQ8MXXQC39wlIVB2JTfWNyam2pVr3zwp9rqhiIfmKODp48IVr0Fyw7SVA8m7Wk/IiX
 ccRNKFjfaLIu2DdEh3AAHW/dgfi+/zEuWtqT31dNA330AxztAQYxhiKnLrW9ZxVcEOH/X+GAHip
 Kfr+PNG1
X-Authority-Analysis: v=2.4 cv=d6P1yQjE c=1 sm=1 tr=0 ts=68bef315 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=nNzYDJPzH08bJ_AMMCYA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: qN005XMaTBpHTBWiP7yc0Vbt0tT4bM3x
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=oHMDtuZk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=xKeE4aYQ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 12:04:04PM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 03:48:36PM +0100, Lorenzo Stoakes wrote:
> > But sadly some _do need_ to do extra work afterwards, most notably,
> > prepopulation.
>
> I think Jan is suggesting something more like
>
> mmap_op()
> {
>    struct vma_desc desc = {};
>
>    desc.[..] = x
>    desc.[..] = y
>    desc.[..] = z
>    vma = vma_alloc(desc);
>
>    ret = remap_pfn(vma)
>    if (ret) goto err_vma;
>
>    return vma_commit(vma);
>
> err_va:
>   vma_dealloc(vma);
>   return ERR_PTR(ret);
> }
>
> Jason

Right, unfortunately the locking and the subtle issues around memory mapping
really preclude something like this I think. We really do need to keep control
over that.

And since partly the motivation here is 'drivers do insane things when given too
much freedom', I feel this would not improve that :)

If you look at do_mmap() -> mmap_region() -> __mmap_region() etc. you can see a
lot of that.

We also had a security issue arise as a result of incorrect error path handling,
I don't think letting a driver writer handle that is wise.

It's a nice idea, but I just think this stuff is too sensitive for that. And in
any case, it wouldn't likely be tractable to convert legacy code to this.

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4af2ef49-2695-4880-8d4b-92f11d8f9c7c%40lucifer.local.
