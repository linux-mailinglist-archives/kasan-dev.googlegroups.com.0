Return-Path: <kasan-dev+bncBD6LBUWO5UMBBTMKUDDAMGQE4KVH7NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id E86E7B57AAE
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:23:42 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-7814871b57dsf15387336d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:23:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757939022; cv=pass;
        d=google.com; s=arc-20240605;
        b=FIS90GNGNAK+VKAmlwXBzQvyEzWej/HIwaERTcMhe4H/c7pJI/QmZozOTmIqqvg0v9
         e2hFK4/ZAmPYygMsdjAXxOrCC8Z/lUaigECTfazKbamDEKxMRiHoPW0MbDKeLmZ6tt58
         vRypm09OWNJn27Ei8Yb1xzLYn7LIFVElodnYZm3iC6hEXoh3JBKSbjN/rCY6R6Delb48
         3sfIhET4tuHnUJfkw0ghqxcSRnuVRxm2nw0THqDmgY18VFxUVZLyYl7C7nxu1ANENyfz
         RPQSoH0e5CO7VUALX0AyYSnGstKNNW8eJUjDZYFDBnZ+3CBnj9H2JwFXwQEpM/qzUWBs
         73BQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=camRqRMCZNrOCh79feEWqSwXxjXP+ej6focVlmwr+8s=;
        fh=NkhlTVISgzzME50dnKckvpEY5EZJRYpIrsiTtATaqnw=;
        b=j5lSJ8K6c5ZFS8y9YsETutddyhnfR8giHkIKBxu2A/unahoOrYLoUh7LWEvni0LxNm
         ddn+EcuC8IKtfubAdDrrHwj3n3Hk18DnkeOC/qr5/nqnNdWWmKwPT3pstj6n9V4FCRs6
         vFb18j6LRBgBAPH2PzrClp6G1C+ipHnQzPSq1HqWxC5MYG6mGnHtW/1WZXJ5rhDbaICD
         HAeuypWw7MklAWsBKP/LDwLetaXaDu1Zd6TzPpBM3dxMsuHPO0V9IHhZWl6rodw3v/ut
         kPgzCy5gtpHRd/4vtq0JnfcFVu5pUSV4HQJYI2pbj7MrhqAgVPfRPwVhu0QuwSbqA6sD
         BRsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CIi83Q1u;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TzNSLqDa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757939022; x=1758543822; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=camRqRMCZNrOCh79feEWqSwXxjXP+ej6focVlmwr+8s=;
        b=RSqrrS+Ohrp5sixcoWZv+gYtAfq4uRDxyIqfeARLN1J/a9ENKZf0YFCLi20eiQ/xaO
         XMckC5UnSr5v9Wdpmb12o56gTkbSxXDJjcGu16Ne2sq2LWwmfGJPGJORyKlCPukUIUmB
         49cFzyjx8vXqva79AiXmAw14GxdmYYRQoF7vA0LXXhBgHYRZI45qIZfIALcrM19EmcMd
         6uqsP1+jcauKjpn48lLW9h51N2Cy5l31oF6znTW6rFmSHaRvoB0Eo69q8AMvAZnX4BpM
         3AUbuCkK/Ewz/ExGE5540mZiOax7OasBtOwZ+TeTHNrUeLy4TS5vjK23AQUIyizQiXjR
         GZIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757939022; x=1758543822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=camRqRMCZNrOCh79feEWqSwXxjXP+ej6focVlmwr+8s=;
        b=pdMOUArPPNw40i0opi2OyNVX6TGbiZ7b6i5HakmMDQDFQJwiPOOxnFb7VauenJrv3Z
         kcXEU+K/qL0HgBB/6FSnj6H6kw85XR8vCnsR+hNkf+zlIacvTYN1wl6+A4ndE0RflAKD
         yRibYplPAnNWCtNalaiDKM7UYwlMJxTTuTAJE4D7wy8z6+xqN1YhMdLRZrXl7FRDPrYF
         PcXXRn8njwcclgbAWfSwNBE/dR9ZoyfgHXz4BS+rL/i0G4MeuoJJlICH285VwlbMEp1Q
         SFjN/TSYhM3xjLMQfZgYtkF7t8SCzIon+cwFQZhwQ/L3ORn9I4DCIwPJiJ0jKFvWBHJ9
         FSgg==
X-Forwarded-Encrypted: i=3; AJvYcCU9qyKSEDjOMtv29e9ZJ/lGVg/Eq4qaAxnAQTef+CNFjpRWeK7cA25EdSrE+Lc9FpKg6Lp0Iw==@lfdr.de
X-Gm-Message-State: AOJu0YzKDVJ49RAHSC48OqI7yfdj8dqTKKOeUnc4xfuwn16v1zQEdkp+
	zFGhu5A+4l6WyZyjTRrOarRvi9ItFNE0lW+zptd+PwujFELwOSABHPbv
X-Google-Smtp-Source: AGHT+IHMvcR4tiCaiS67cwSXPpHuG9QAEJhY08bUoq/EFTjd0Yk4QHhs+W/5uPQuYA2P0HThXdBZxA==
X-Received: by 2002:a05:6214:62e:b0:765:1642:2ca0 with SMTP id 6a1803df08f44-767b83cbfb3mr112986596d6.8.1757939021494;
        Mon, 15 Sep 2025 05:23:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd48oW6xcAN/mkHJLlq/M9alFoe85A4yyW+hthuhLu3VRQ==
Received: by 2002:a05:6214:5287:b0:707:5acb:366c with SMTP id
 6a1803df08f44-762e6495f4bls42469306d6.2.-pod-prod-00-us; Mon, 15 Sep 2025
 05:23:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVQl4MHou+yJOoG06Vue6P/9yZIM4prhmrM7A4QfsHOT9bGyqVJv6IayjIDBG/8oqiGtn7kJyN7BTs=@googlegroups.com
X-Received: by 2002:a05:6214:268e:b0:70d:cabf:470d with SMTP id 6a1803df08f44-762262daa1cmr196875976d6.27.1757939020477;
        Mon, 15 Sep 2025 05:23:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757939020; cv=pass;
        d=google.com; s=arc-20240605;
        b=On1GgjUc0rJCtS0w0NhlK7ZiFDjNRnL+gM+cS95DPSjbvvmcyzouGAtJhIg7HpilwL
         oiWjZ0/lVBEECKQ4q2hjmrnoPwYzs6k5WHwyhSxbZHMqjpljC+FOoxpWl+ESzzQOIyQ0
         5H+XwJP25yDiNdLFCUe0NgVZmRJQ2a4W+qyOCN2nPKIsjXaOnjnAKNiEvP+GUd6WnPCj
         /1T0GJ8p/VE1SMrSHWyw+m4RT/geF8XTCIsJeEthhp9IyPql5mbqZrFt6U45DHRdf7Ty
         ec3h29Oc1miVb0Mobqfa8MTXxvKVrjfCHwTWCzReJtNLonRcjXe8PiBq+ubT4eJzoqO+
         nytQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=6UX+modhKlgAliljWps+Cs00h8uOWLdiqfWRV9Zj5mw=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=icEYWlxoUpR/XvrHUQCQmM0apdYCz9xt4lbL78ZA52oFEaqEMRqQK7U/QY9N4dNWb7
         Ytv+Pl1cd9kee5FK1JMxxA9WtWfZq0SDtpQ6AgO4KIsXQEGuC8gHm44C09p6cIY0xeX+
         bkAGvURN9YHsp7wW12Xo1ZULUBleI9TNuEwF+7PVIr/MDKz5ApRr1RuBsxm/+6q6Dd/j
         cbVdPfe/AR99jtdDwk8RoVLxdW6tZNNtZ4DoSRMAtGDM6Cc4THhE2JNF/UVB2C2k8lRY
         5TT8PhWFll/mSsE5iUZdncWXjybaO/jKPnsV3It/gaHxE/ipMZ5l1K+wz7Xl/AJbQS5s
         97Sw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CIi83Q1u;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TzNSLqDa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-778019a6eb5si1894686d6.3.2025.09.15.05.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 05:23:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FAu07j028237;
	Mon, 15 Sep 2025 12:23:39 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4950gbj7k4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:23:39 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FCBHFP016196;
	Mon, 15 Sep 2025 12:23:37 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010064.outbound.protection.outlook.com [52.101.85.64])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2ayr02-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:23:37 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=FY56Fy0imuchpMHPQP5kYyMyIM8Quly0SL007tZqTEje4QhVSB4XcZdckO5xVCvBbvS/eL+zcECfD7E9/+z8/go7IsIcUFwhqjrqhtV+j14kPgGuXsm/W6O953K+S1uY5gm+EMhG7HYOx/upae5b0R066nQwt7cxxGAm7qvXePrX2bMb2WA4pWoezw2pLx1pRi79vGK8Lxr+QkMp7k9HwA4VVC+B2ndeeGWukeGIGjr8QhiyzEivTnnFCkQhG1gkowwRQRpRrgNr9tUz5GfiNZvklG3ODn9gwjpH5g35SF+Ka39Wf3k+s/DcIb7FDWaYk1DxbzsVj+Hxjizn+oT03A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6UX+modhKlgAliljWps+Cs00h8uOWLdiqfWRV9Zj5mw=;
 b=Ar1havLuE+cDiot+U7rzNtqxTDI9tuniNYjya7EWLKGMeErM3RGPoErxXPVPFBr1ViwZyu4CAIOWyiTzfTl5h/+Qr14qqhSbFlCB5XnPSIEBpHW4IW4/LDgrxiuQfLwtnWHDwnj6UPXPoPKwP6pARKf4YLwi0OOjmEdPbzAn0u8xxqBua7d7O5RJ14FbTGeMW03jDfgVD0g3vT8NsISbz2rLrMrwQSjxRe1CWpYzyvAZzX1857zc5g4tj2sBDs8GV5UmyW5YXlpo0IJpF2X7W72U5xJVZ8lY1aolt8ydI+8Q84Gx6y9tXSSqPSgWuaMnykvxTx3qvkv+qTBCJ/Ugxw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by MW4PR10MB5884.namprd10.prod.outlook.com (2603:10b6:303:180::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Mon, 15 Sep
 2025 12:23:32 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:23:32 +0000
Date: Mon, 15 Sep 2025 13:23:30 +0100
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
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915121112.GC1024672@nvidia.com>
X-ClientProxiedBy: LO4P123CA0245.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a7::16) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|MW4PR10MB5884:EE_
X-MS-Office365-Filtering-Correlation-Id: 96e5e6e8-e3fa-4a0e-9a64-08ddf452af89
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?6fi6V87pvYIk+OntlJ+qpBWQIyYgy3sRnhCZMZ7wk8/pd1Z7MUQ+XevsHvZW?=
 =?us-ascii?Q?tnMFR5GLUaviFZO9nrNGBxrByhEhu1eh94KrpBxQWfX255jE57IPdf4ePk+S?=
 =?us-ascii?Q?VSkGFtqeDtowiR7qXeX0E3TlYwc/E54vhqy8usQPrt/P9aGHHah8cH7TzzHQ?=
 =?us-ascii?Q?+W7AyUvRmkOm9uJ7h4iAHcACGvLYAlcMKIG+BFB1UnX1qSCezn4aHLei/7Ip?=
 =?us-ascii?Q?hON3A85t9cbxIsE4HC6+l/+9V7y709LosOtPtHoQJ2pOcMHWrfHLFkYqR5Qu?=
 =?us-ascii?Q?GaTp1IPD+pZ4rpYe6huEBAzP9jxXViNcLwGPMov1F+ik7UXdvhx0Il6mZZ7S?=
 =?us-ascii?Q?A5eKOedM1UM0mm0QsAxZHy1jsHtkWLS29WIMj5wDcmvPiik/ScBGw/isQSbF?=
 =?us-ascii?Q?2oqkuE12zFVEBQI4uswgG/ArF4K3CXzG2BqD9Rr25fYHwZL0Ofgu993TnBum?=
 =?us-ascii?Q?Ex0CjSl8hwahSnPq4cur7cqvUO7WiVBbiWZ/KJVk1KyONoyWd+riDixHgSwK?=
 =?us-ascii?Q?Hqpg1o0G+uB+1YIU2oW4QhA21oYIInRCmPVKZ2qrHr343r5OfTVMOlJvwK3e?=
 =?us-ascii?Q?lH3rwQ4wlM/0ooCXuCUKUJUuYlGltBVxMC/FaClkytEefKw0RlHmHhuFxjEW?=
 =?us-ascii?Q?jw7CoQEg9ytBFd6H/Fh1Z3J5kwz2t3kldr+dVk2QPsVHvK6aIBSs18l4/2Ad?=
 =?us-ascii?Q?n5Yk2ohruc1cQuJMZ1IXmAZA/KGWEsQ4qNhdz1dbu2VOJ9UR+xMenVMUmcfM?=
 =?us-ascii?Q?cTrp8hVJNNxqwEcqhLUFZFrKZghSq/+ZD+FLWHPzpDH155FZLl2CEwFMTkxK?=
 =?us-ascii?Q?xcisAduPLcs57klvIaZdbNi/vf2Vd+vT5cuOEh87R4pcD1GS1pR1PgJUNSMJ?=
 =?us-ascii?Q?mjmgh+hHADkLpGMoXLaOmzRJAqcL7P/hPTov2n2FPSnrzqAuv2K1BgewCacK?=
 =?us-ascii?Q?frDni5J8oNBmF98q4Ovw21HQ7RIU/v4YVMb7OcYLHp1XN/fDO9u9rj6B57zq?=
 =?us-ascii?Q?96v9j49Z3+x17dnuUDVLj4hAmTbyiLY5MmwLWubc+7xQVVj0jexRzEdeqhLa?=
 =?us-ascii?Q?fqKk97aVspu05OBvMwXgN/vQdCskzuZ9Pn0ymU8Oz0C0sWb+kLPRB+W4fXuD?=
 =?us-ascii?Q?MSewIVi6UDgV+yvxj7qMaYs3lqHyHoD9KBJlK9+JbHx/ClZRWQ2n7CFNLvom?=
 =?us-ascii?Q?ui9rNQxtbpNkrwNdon2odrY9tNsEUOQxMfoyhP282Vm3lAad7DE3j/jZ21MD?=
 =?us-ascii?Q?WCI3kKmW68rxK7CpBTKA1i4xweq0INipJO3XC6nWSECnaOwMvy+aCZGzQaIp?=
 =?us-ascii?Q?WSHgq1/sf/BV3DEY4ebVgoP/GZZ0LCSAWqF2KpIHXeju+mg+L67RUDkcCLyI?=
 =?us-ascii?Q?ZAs49NC3ugPMOzmeKfwo3g46S2YrET/P/kPzIGNTkE8aU9pOrWEWafOMrG5q?=
 =?us-ascii?Q?2ZW+Q2rQ3AU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ksEQ23NT30huZOK/m6in0pVz9IXfD7te75Td48NlQzUl3x6GnLILN9kGnCng?=
 =?us-ascii?Q?RTtxWx7szPYV8cU01ZsSc84F9a1xSaKMbHSRnVIpH88el4qBn88fIvnEdS3V?=
 =?us-ascii?Q?71OaIbMRDdC1XNoUXR9vXz6xaYWjYb8gttuaaP1K7On07fdWic56Xfo2j66d?=
 =?us-ascii?Q?c1HPWijEsQuWnHELDb5wjJqAJSWoWtBxTeURjz08p0xII91EkpY1iI/sIqf6?=
 =?us-ascii?Q?fv981BYB4NN9c4mYVyxOMuv8ZdI1OzbTSpkdiedCavuIGs99iJCEIjB3P6eO?=
 =?us-ascii?Q?4KM4eR1jp2XNkbviiOmkm1j8aQiGd2C50ZA7tVC1ANLhoJkt93pLpCaRUllu?=
 =?us-ascii?Q?eaKZ1Dh5mXCEhfyqVAEr3/lg/e1t8Jt6ZaqoS7vhQ4r2LSsg4SBiiy+i5noJ?=
 =?us-ascii?Q?KWaYpi+NFPYH7VBvvwAVlBBAaX8ZARaNc5MLkjSP0AoP4u37BqkLhpUjDVSj?=
 =?us-ascii?Q?+mHmpJguotMRPkco/fHaUiProT3jNG/qgBdm7AFUPbjMOLerT+AiENMpwOjD?=
 =?us-ascii?Q?nrcheUOvAbEn8LeeMk1wJT9OJq7uLkDmY/dHuhhK0g8LB+0oJPzO2vCsT9w7?=
 =?us-ascii?Q?pZD65IkznGzWa6orBb9GePZiQPw03vf3s21iMOPLCzlwN1DDm4M02+SYzrNu?=
 =?us-ascii?Q?s+229wPvGD7QCuTWx5JhiI+6wGiGXF5jgL9WskAwc5aNo03sr4qz2A1YK5om?=
 =?us-ascii?Q?uVvQ/qAUFv9+HHObgIpCEVkofv+NXaIEdTRDBDD2Q17stWAnmIMOwXcKZryR?=
 =?us-ascii?Q?qMZb+N/BtzY+CrGnroNAGRXoarYW0tzdKsY0U0qEvlp/3fhIiqaI2zsqY5XL?=
 =?us-ascii?Q?1pFxjX9taSHUWMp4wJzUR5lHHVAdu5nBXSEWNT8Hj/G27uhjQ47erUC/ycPL?=
 =?us-ascii?Q?6HzILn34AcgC0cj86Ofx4xiVqrm4ZUpPt2SPQUfRZwB9S5hoJcTS+Uo2F03g?=
 =?us-ascii?Q?08YT7AWJ7emvIVsuotL+GnVuQvaAYxhXPR7DjxVDxIusT6GFYERo9BvQXAPx?=
 =?us-ascii?Q?6JSetxbRIxBiRietoHJmUi7CAuT+K2FtMURhCHVt4pxc7Y6xbRfZIneL0EyX?=
 =?us-ascii?Q?A66yrM8KlHjnR9e4Z4iThn9Z5qiaWnE5RA2VNHi1jt5WKrQsjRIjyep7WV4a?=
 =?us-ascii?Q?RKwJjxxt+4f9n08iSvrx7ZlYOe9a7tYwXgarZs00M2BHmzFfUXLtdpRku1Ys?=
 =?us-ascii?Q?VvxA/t1Ab0dPyFKzYFnZGAAi4sl99KYchTZfiqe6w4RkrvnhG9dgTJ0a4rE0?=
 =?us-ascii?Q?hZ+zsXB5wgBz6JWwUDQgTccBD9GW4Bn/V4yu8SY5DmtAY6EchnV+r8UtFlDX?=
 =?us-ascii?Q?+n0Ka+QpUoVPD0huCvI9IJM23LSS7tW4HIoa05L25SUs2mBORRSNMvgtOadt?=
 =?us-ascii?Q?GnfPjMj9eL5eh9SMs6T937ITlkoz2WXQVIhmU4r/ogRLVU6uXj/NvDynFHpZ?=
 =?us-ascii?Q?Sy9792ZdplHAQQP03n29ZzcNj7eQ6I7HL0SDSxKArGYA13inZTuheJRXsORY?=
 =?us-ascii?Q?lK3pNmCz7ao24rJr7SuCMXeY60/HncFcpQLiECDfE8ffRx2mLGJZfNJt4JA/?=
 =?us-ascii?Q?GrC7PXqbG83VuP59OX+2rrbAZ7i+U+l6HbrvuuYtAtSByfScrj/M5oDzmFwH?=
 =?us-ascii?Q?EA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EbgINio4psbNtXRIUX4kHBHgcXenr2RtpTrQr8f+AArisU14fq7X65wHlDvgbwjP92N11Jx8mWHwNfhjFCdrlPRV2SGBd9Z7EH3kBLREl3WP41/7OXuM20drm7AowKdrFZZYvTCrSJz+/eRyMXYCkgbMB9EGCpSL6CHJzHMTe38as64kUNXm2zvE3bJzXfllARMdwmCWXyJxRFjZhzL/Fh54X4j93Mh6Ft0Ba0grwaFMirP06FGciw6gcP5y0V/qiOq9GykdaHzyyCR7LNcx2TGeS8UU3sR4NjBdWwhfEE9VBvYq69r/aUFum4HQspRj1gOh/jgZLbyKzHhsMa9hwYXE5cbpefifKT9xvVg8LOUxrlNKxYHocvil4WSCiUWs5z4LXoh1K2EQJbB9s0W1QA2I5CCjXLbsFHAYR9WEWiOituzjIMakhpFFvdytF806TCVtjzls8Wh1qaDmYhlnx8AiQnRnRzye1PyBceZRxGGA06KvKmnPG1mzwmEzIz+4hMI1zop9oH0DEzecB9vXfJnPuYoDJo9uIQO6h2oVpdY8RRtc2i69ygij6mnnDLdL7JR4wFgNuj6NWqCcf69/2x9rlRVoCscUKQo0+r9vgZo=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 96e5e6e8-e3fa-4a0e-9a64-08ddf452af89
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:23:32.7631
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RPpDMz8Xa1mDzm/n6A68jaAZ+PtYriYykbCttHabcPZotwkpRP0rBRMsHvA2WUKODu9M+ct6dFOokWlZQRWWoOn/1faEgHhx5BUpRtz7ZqY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR10MB5884
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_05,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509150117
X-Proofpoint-GUID: FVG7zTe4fV_TgBNVw-rGmHQG8vNlcnmK
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyNyBTYWx0ZWRfXz7t+/gVBkCK7
 a9swryR1wTA3b04NMnz6mW/SduoV2ZdmO7JE8gApF0e6Q0+yz52BsL8HW3TZhlXfFYXzYskFLUA
 5I33FMODVH7Gkw1XyMm8vbHh75Lp+FrJTyANegP65LKgzJ2f8Ihj4DSTnnIRMqWC/ABc+6YtvA/
 B6shtKO0Tp6AfDDbj5OmhiTan2RJlISqSTg2nDUwtgiKXhbL5Xow1pW2eVoHc1xW39f/DyjoVMy
 DyX3gNLmxevoTg/9xLpSxDd3rWYGOVEB7Z/FehrPtMIQXohYpvY8A8j2ffkJDF5DfJPnwEOsT1X
 tV3D70BEJ5le/jSAyqylhrz3vcQcQYZFPtySCPK9/v/TctoMNv7OtRd9ZPfqZ8o3/u5c+7mXIWp
 +ihW6wVHTd6+YiNKXgpz8rU7SnfGGg==
X-Authority-Analysis: v=2.4 cv=QIloRhLL c=1 sm=1 tr=0 ts=68c8054b b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=9afJXiSWLFsG3sEkPHcA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-ORIG-GUID: FVG7zTe4fV_TgBNVw-rGmHQG8vNlcnmK
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=CIi83Q1u;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=TzNSLqDa;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 09:11:12AM -0300, Jason Gunthorpe wrote:
> On Wed, Sep 10, 2025 at 09:22:03PM +0100, Lorenzo Stoakes wrote:
> > +static inline void mmap_action_remap(struct mmap_action *action,
> > +		unsigned long addr, unsigned long pfn, unsigned long size,
> > +		pgprot_t pgprot)
> > +{
> > +	action->type = MMAP_REMAP_PFN;
> > +
> > +	action->remap.addr = addr;
> > +	action->remap.pfn = pfn;
> > +	action->remap.size = size;
> > +	action->remap.pgprot = pgprot;
> > +}
>
> These helpers drivers are supposed to call really should have kdocs.
>
> Especially since 'addr' is sort of ambigous.

OK.

>
> And I'm wondering why they don't take in the vm_area_desc? Eg shouldn't
> we be strongly discouraging using anything other than
> vma->vm_page_prot as the last argument?

I need to abstract desc from action so custom handlers can perform
sub-actions. It's unfortunate but there we go.

There'd be horrible confusion passing around a desc that has an action in
it that you then ignore, otherwise. Better to abstract the concept of
action altogether.

>
> I'd probably also have a small helper wrapper for the very common case
> of whole vma:
>
> /* Fill the entire VMA with pfns starting at pfn. Caller must have
>  * already checked desc has an appropriate size */
> mmap_action_remap_full(struct vm_area_desc *desc, unsigned long pfn)

See above re: desc vs. action.



>
> It is not normal for a driver to partially populate a VMA, lets call
> those out as something weird.
>
> > +struct page **mmap_action_mixedmap_pages(struct mmap_action *action,
> > +		unsigned long addr, unsigned long num_pages)
> > +{
> > +	struct page **pages;
> > +
> > +	pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
> > +	if (!pages)
> > +		return NULL;
>
> This allocation seems like a shame, I doubt many places actually need
> it .. A callback to get each pfn would be better?

It'd be hard to know how to get the context right that'd need to be supplied to
the callback.

In kcov's case it'd be kcov->area + an offset.

So we'd need an offset parameter, the struct file *, whatever else to be
passed.

And then we'll find a driver where that doesn't work and we're screwed.

I don't think optimising for mmap setup is really important.

We can always go back and refactor things later once this pattern is
established.

And again with ~230 odd drivers to update, I'd rather keep things as simple
as possible for now.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c%40lucifer.local.
