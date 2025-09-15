Return-Path: <kasan-dev+bncBCN77QHK3UIBB4OHUDDAMGQEZMUGBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id DEBCAB57F13
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 16:34:26 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-78739516cd4sf11094496d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 07:34:26 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757946866; cv=pass;
        d=google.com; s=arc-20240605;
        b=iKx1ILcDr2cSfnbjKULU/VNufPOe6pD6DDvfPsMPdg+HjMX/Rfvbyay8n70sqPBVGv
         T3tgqcSo6uqqpBJSnkD5H39dDF6qETt0k5/pVSTLrukl11PEazNxdpaapja0zSeLnRtL
         19HR0OL99n4kck8+J/Yfgm0YXPBoFUdk91u10wew1C4xkyrbA6An0Os+O61s8IPYpzzG
         8B/pQxo7qe5hIWxMc3EbCVfzILwhc86J4llZQFSXnrcVdqWw4ppG7DzcvMimkySpSLAT
         TlWz7QKm4wsITIsU40kBfWVnLY9GHfAFNuReRPawE9S8JPROcaR5tWFPqGykr4ksjY3g
         ZhHw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=N7Xyh8CYyklroLWOxc/fybEjDfoMiGmxXlwsaPIXzq4=;
        fh=99kh7ljlHENbweMT/cSenYl7w7yauy1BjKer8tsgazY=;
        b=cqEAm9AZ5sMp+LAe5fj8szDsWoUwgbYD7edaQw4iHAk2mc2KcU9LTCyGN6kxh5OvR5
         q9Ke9hOImNYZQ0L8gmW6IL574MhnnKFYmRGwf1JsqFg2hNv8aSlEX4VseZsAIB8GZG3Q
         aYmnN5Ch8xycEKyJ6w400PIaVQRovFPvNJkptBKTqvWOtIGZj5wroP2MS0/esKvnSR1h
         7BXZDxGAfqHXaGDCS92arARK2UwqeCoPpPt5++165Ktb18Kb+xHgm2et85zOLEbpZNe4
         01+t3lnxNQiDbY/y8/4jqp4jO3wVvCkGqAe9nRLl3cFd/02BTfxMCEX83w+joIrj50Iq
         ScWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=BgSdNvPI;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757946866; x=1758551666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=N7Xyh8CYyklroLWOxc/fybEjDfoMiGmxXlwsaPIXzq4=;
        b=HaNNbxjhyL9+eHoy2cVIO7OKwx8CGaHVipADZ0YrilcWp4pYjDgJ45uPGcWbeUoBLa
         QenOMUSiD+h9xd7/wKsxlcJGKgfHeb2tVJHQW4YPOQ6eq6FxVGHVsR75cHYuEjtZeY4L
         pLUZ+F9gjfFrf3WSTSf6RAUGOFBAZd6huAlWME+Y5qcpWgBMtLAnR6uLPVYCBd8lCSVQ
         IpN5tSjuyqlsxK+aYmyvW1/3xnu9AyKTHu7FtStOHHSnmC/GkempBPViZzuESnAhyQXz
         PW75jUjHPWkA72QTjNyD6gkiUhlKmDNcNsy+NB3tiSce4ea5y6u+To4MGrKxVpFeFrHo
         VbhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757946866; x=1758551666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N7Xyh8CYyklroLWOxc/fybEjDfoMiGmxXlwsaPIXzq4=;
        b=LyBtyOllwgTYveHHr5i+Zdxszs66JHiKOdOTvgxoOF1ZJOw50MUbXY7uvtJyX9sRfi
         IvBdQKsOCQowpwMelmDyP/RJnfGj6wfPG4MMj/xQumDrO7mXnfXdDCIzmhapFpWFSgNi
         cZugWuEmQpQRiScoBpmkFIjbOJVqGYu3bsPakRpDwe5RAjb+Y53Ky6CqJZnkkBjyLX2b
         j+RAAuAvqRLKxTaap4uG1ztwp/MwDZb3bKe0xDew7zwivrh5u6AgO/63KTeH+oI/ijMm
         Cq2YZTD1mftDIjX/vlfHf3+FgcTmkjCQjVsj1K3Rm18vctjKFIr9QD6fzKXiYjyqjCf8
         s8vg==
X-Forwarded-Encrypted: i=3; AJvYcCX3DA+8iwp6qRjE4ubqlobSn7GWroO88qzDIuKVHE+6WXGHIkuLRbWpImyWuDbk15e0v3Fi/A==@lfdr.de
X-Gm-Message-State: AOJu0YyEb4jNrn92K0W322K/xjp001eVhm/9zzanDLjz+Wy/UjPhGQmN
	bCuIcF4T0z0bjoxmDl4ms17NZVpxJmClIdhusItp41dXg+StfQBeHq+T
X-Google-Smtp-Source: AGHT+IGRjTQjIfNMcExZ8Rc0DGkPH8gd7iLKDNYyGvtl16wdpm/prLpmwHfv9xrykuqf11ymtIWbkg==
X-Received: by 2002:a05:6214:19e3:b0:779:b3cf:68f2 with SMTP id 6a1803df08f44-779b3cf6b51mr89200916d6.17.1757946865317;
        Mon, 15 Sep 2025 07:34:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7tvjJyk8YenPjxTzRXKMwFy5VaF3o/MJ6DfNzzFXmmig==
Received: by 2002:a05:6214:5287:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-762e61b7e2dls85678276d6.2.-pod-prod-02-us; Mon, 15 Sep 2025
 07:34:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV9/OdNIY4HcFo2ahza150W56X5jVW/05PHazf/5myj3RxBaCSEwhyCJ19It0uocXwQZ+CJZXXk8K4=@googlegroups.com
X-Received: by 2002:a05:6214:f0f:b0:780:24d7:fd35 with SMTP id 6a1803df08f44-78024d80119mr53099556d6.43.1757946863727;
        Mon, 15 Sep 2025 07:34:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757946863; cv=pass;
        d=google.com; s=arc-20240605;
        b=C1Nq7pjq/UJNAF91BvBKpIVvfhgHeENtDGEyC4VRw5CIPQ6wTCf+QfENi7p0dTKug7
         cNULDr72LFteHPFS1ifd8hIdu82/asxV+aW8unk2bs/EtSTl7tevLt1UtDJ8NRJ8xX7V
         dT6dfBVhsr/1vbLMkB2oAvLTTM0XwABbeUWTQ2m8oBFGnWOr8ktPvAdhxYnW09CF+N0A
         C/GaVxYpqSqilod9ruUiJB1o3iDurSeNI/V2sA84WM0cldeoReaBdKXJAMC9pTqIN2up
         uJJ43ovLodebJcyFasbiCZE9Uyi+iTvxuDateqcdDxcE+xX/ubPaDpa22ZeycyQJsNsp
         e9ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=w2OLPJGQr7Z+rVWzl8laX+IkMurJZ2I4ncppuXQbRPY=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=dW86Se/IHBCcWP2L9rkBFMgMTYTRRY0v/2Us5avPvaB/H17A7EVRolXX31fTFfK4oo
         eWODa8CV7w07jSYi0JhSbuqsPEEFcUJ5xWtG0ZliGhNG8EF0kTp9LpKjKmSdG5ERLllE
         2RV9gKjoV3V41opkl6YhvkykJHGHUwLSeFXzSgRqmpt/uvy+WlRAUQUjPtvpnRv8SXjC
         24nC9WjbR88Di9UBHhA6XZFPFDErCye2mzkYALmfaIW6Hqp+TwEc3vYbGQ8OLIqo0OvU
         yZ7ptd+hPtK34MYzxJX70pJLX6TqBezMbbb8vQOGDXGP80gj9Tl4+O2UvHkYgEix7MP+
         EN+w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=BgSdNvPI;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SJ2PR03CU001.outbound.protection.outlook.com (mail-westusazlp170120002.outbound.protection.outlook.com. [2a01:111:f403:c001::2])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763a69974e4si4955626d6.0.2025.09.15.07.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 07:34:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) client-ip=2a01:111:f403:c001::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=w/q1kqg7d7ctFBI/zK9lLnqh8AjDLmCNsuY5LQOet/RvaSn4blhi2b7gt3jNR8telINzeNVD5Q64QY5Hp+3o6QTVfu5K7x2y52jdT+eiqeA/ieRTpPOgFSpxwOjqioztXZGQ9EVRC3SMuRb03fn/d6hPpkABnNQ5ChGJfgu52dsOc5gXc76VcTeT9XQ48sl+cEB1b3CJG0kSOq7FSFLZTjyREvvWJlDnPu5B6BC7xqPGiCDoC6QEogZ0jKsOZ2/jcPoBrwPC3z6w85SvriUtO5FvKoojs8oqjhO4q0CJHGxZR5ycjdN3qBh2ioRJ0tvHPnKb7/GS+tH3WMkFrhc7UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=w2OLPJGQr7Z+rVWzl8laX+IkMurJZ2I4ncppuXQbRPY=;
 b=KhqKhJ/3Cde1vw4E30jBiU46PfZ02BAj7ciN1A2+XwueIqb4ls4ZsZLqX8XVtUP0EsuCD+1Ztwko3YyWggx3n7sl20hjpXv0c1Y++oLcfwIEQvFuFlDrsuFi6iJr5bMXpaZ1LxflgC4OA8YP8ocuMJ/B70fUZKxSNWU0/vVHx+sc9+5UHxLrDL44oTYWfebT8W83vdisqtqRpImtsmjRFoPXX1TSUSmU92/jALVRNsK2Mi83LB87uTw8qPe5qT5tYeQ9rfyU0pBzaf31KmhoEVtz3PHrPFEsRy1awYfkndoAwL4cOX/ek3kBDFiflOXeEwh7zIoCtK+KTNFtdzMK0Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW4PR12MB7213.namprd12.prod.outlook.com (2603:10b6:303:22a::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Mon, 15 Sep
 2025 14:34:18 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 14:34:17 +0000
Date: Mon, 15 Sep 2025 11:34:14 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
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
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250915143414.GJ1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
 <20250915124259.GF1024672@nvidia.com>
 <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
 <20250915131142.GI1024672@nvidia.com>
 <c9c576db-a8d6-4a69-a7f6-2de4ab11390b@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c9c576db-a8d6-4a69-a7f6-2de4ab11390b@lucifer.local>
X-ClientProxiedBy: BYAPR01CA0022.prod.exchangelabs.com (2603:10b6:a02:80::35)
 To PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW4PR12MB7213:EE_
X-MS-Office365-Filtering-Correlation-Id: c2eb574c-df41-4d7d-a0bb-08ddf464f360
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?J0fgzA3EZhDGT7KbfP8CmsywsIxKJJVvO2ZE9bGNw3Q/f2nhzl/evKYMDZ0K?=
 =?us-ascii?Q?5oDGq400RO1n/B4DIouUv+J4gk9rvdKMyDNUqnkctgYHpW99au5EiX6svH+Z?=
 =?us-ascii?Q?X6uwd6GedpE8y1sOxbU4hG5Nv/g+p59WJ6Ran3+HbKtLMqVEvwtyHprkup0G?=
 =?us-ascii?Q?L4hH4SsCITv12/C9g4PdZhsmAji95/qjColkRsM2hUZNcKBHMxfkkj89ofJI?=
 =?us-ascii?Q?BAk8wTkiUWz4TF4cm55a5WkPz65eU3JmNfiGqHm7Ie6iODS9oIXhdZZxlG5u?=
 =?us-ascii?Q?aYiIQi5B3oNBG7KqLH3mvUN+6lljkbkRS8+VyFSq6BD96wW/pz2bNEHtEByS?=
 =?us-ascii?Q?2IUJ3Y/0/TImRFH8gikcmCD/y27a4gt0lMV45CdXbEKblstTG/X5LDzCWans?=
 =?us-ascii?Q?/F8uJzs9ufYM78XE5d5boAE7SKf6XNnfhKbecpT2W26Vt3a6alHZa5ICx5E4?=
 =?us-ascii?Q?xzHyQOE2gfDOnsPUxAfWAxNvBC0o7MtC+IYvUH0FyYL9KAJbnHRbstlZB7cr?=
 =?us-ascii?Q?Jjs7YZDDkI/xNfdMJvrmmHt/o86+FQnST283wiqbSfX3dRkDRgTCQ9Xl0M63?=
 =?us-ascii?Q?PRMDFEKDk2tvjR2mz9DGcnazhNvWeKbCM5LKImHz5JlTI5xSZJtFMn5+m4El?=
 =?us-ascii?Q?7sIx5mEr1Bpobz0gG+uLmHdKKcb2JkZu7oiSxb4/n78KO66FM2lPOU8CJtWF?=
 =?us-ascii?Q?wDS7Q8mJcbnjDqK3xQIXrzcYOPD8O7WIuwYqAqgviK6xgvALVHqx75G1Few8?=
 =?us-ascii?Q?rQiqCbGcx2dkLpq/qe3fYjLOpK/6b4NzPiOhY26QfAff45JG6G28UfKYAMcW?=
 =?us-ascii?Q?8l7A13LMzBYtjaDC0YpLPjSz+lsxZTSGl8iewfhhfNhGfBHVdA21zCE5vnhT?=
 =?us-ascii?Q?Ljm9CHsLmRxWdomaXeAdsx6pWOWhDSZyjuKWEF12MF90x4T+P+wtO+OZ7IlR?=
 =?us-ascii?Q?ZaMe7qbwpQRUQwhUMgmd6ErDjx6w03zI1csGM4yprl48xZzNtbBH35bK+yzi?=
 =?us-ascii?Q?MQjh4qyyNFbJEp17TeB7iDsHAGf235EeH7s4Fo5gMA6Xzl9gotrzBmcfeoWI?=
 =?us-ascii?Q?d4BcoqdWbK7T5ni2GcLxr3sRrGgFHwtKDEFlsQcBAKRjxxzgvBKAg0GJYcHY?=
 =?us-ascii?Q?fgseRh15/pzRbUEbkrFuXIskr0rf46kEKCd3Wqum46yrLhS4YDYrxx0vKtKk?=
 =?us-ascii?Q?8D5KLnBbMg5wS509/16GtdXZU3zrajZQSVUyk1yTa88QfhiymthLKulNK6YP?=
 =?us-ascii?Q?nKHC2Rv888t6e9cDLWt1WyeYxvVRV1JS/McPEaM8Lt0yzmmFblaYJdga139e?=
 =?us-ascii?Q?9mHbKduwb3Ro7ZZG5+9eN4XyKZAjYhQTWX6M21UWOe71yCDc6cSfNkZ4qz/4?=
 =?us-ascii?Q?lqmhEBGn49dYQWg66wddSl1nQ2l3Iv5HYESMjyWRUW7dKyNWzL7h2cmM5Vyi?=
 =?us-ascii?Q?KQeg+Aew84U=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?/3WCFB0Gi/gwIic4Rv8tIjZqRx6Q/sGGJ5Qm6p67L9OhcuF316JvcdNoB0Zv?=
 =?us-ascii?Q?C4rLP8tZo0Jhy8UwiUyPDPS7BnokeqAXJ/PRnjNP3+hX1qeo6sCD9FC3CpM2?=
 =?us-ascii?Q?lP0SbNpOWvv3F4+X0wGNvsgm9WloWB4XWrgLMV9mtdLZyYcWG+duAsKP8wFI?=
 =?us-ascii?Q?dEc/3gdTdbNS9kqicJkAs3lDbeRg+rg5NIzKbIdCyJgGqHoVoSKMjr8rWx9h?=
 =?us-ascii?Q?savJcpcNanRKORwcB9+U96gwqpPNn7ctMESLs0RRkrwN/ALoV2pKy4XsUb0f?=
 =?us-ascii?Q?T4Xk91N/HsF4dfymJrT4PyRyMCB7IaGvkBJO+x83RAKTcpV+nZSrJSu8y1Xu?=
 =?us-ascii?Q?oA34OR2fZvbJav/qyShK+/wD0wD3Rox6c216DButK3DWll7puwEJQBX2UHBm?=
 =?us-ascii?Q?xy1kulgBJNXrO9w6r5hIh5xbnjN3zmv0g2i3TaIAr0a0RlUawSmHmR6Y4hoN?=
 =?us-ascii?Q?g1enrb0Gd2w8L5ZIP7RXCyQl+yExNJPY3P5/QsiXEsFBx5W7qpCP9y3LJ6CI?=
 =?us-ascii?Q?O2ftPOJfJfEPE6ncAOlz+d9ngPfbjh4+GxkKQr3J7Em4DBnfrJL/c5zY1LPf?=
 =?us-ascii?Q?wstDSaLl6ZK7aD+Qe4obdZqaznmxQ7AQ26BfYny7Z2pCD7eKqJE9V8+1y7jo?=
 =?us-ascii?Q?Cy2X7f7Pe2sm/ZXZpXICyNwkI7bXGFqEUmsLiPL7BWWsyRaL4Bf8pMJh6UDj?=
 =?us-ascii?Q?AU8XvlcclK81GLsEsoZhuA4KeU4cFYOwOg9o9U2Y1IuK+Rfjts1f/c92dE3f?=
 =?us-ascii?Q?d+oUeiwc3iveRXZ4sm9Fl0lZ1KnG+iP2N75Ii6pfm/fA1OIJ4JsLBjdCRdcG?=
 =?us-ascii?Q?tlkz8EweM9xQAeMIKRakoGxS2exPncZ6UU7dwPgOKQoSQ6r6Y7IEBh5tCbsr?=
 =?us-ascii?Q?OVxfiRdOfUpoRjdjF/6SJzNHzixxcULmWxRV8f9xWVaGlazPw1MCSWs+a8tx?=
 =?us-ascii?Q?C8utKH/bDXbwFMPDzOtIASwW8grrNTjCe5ipBnPeZAB6+cY2SG+UHwAVD84b?=
 =?us-ascii?Q?XuGxXURuPgV6GP3wsTBB5USxJWh39uQwlNiaSxpq4nIecECuWz6UoOlfwJ/Y?=
 =?us-ascii?Q?1uCAkNFM4T01plaUWjz5dyVTn6Uj9FlOSOBPfgcAeLOLXQVbiSOAq63qnwsB?=
 =?us-ascii?Q?oN5O2V+T2MRIG7mC1v6i/s0fytTnG1Pn5fhbiHWexGPUvwTbVlmbD36rAH2u?=
 =?us-ascii?Q?wm0dzulxmi5et3HAL8onV1W53DQgx6+ZXQmHL5Edzlu50Co6Jeim89hRgIcz?=
 =?us-ascii?Q?heZwAjVS+ewdGlAPwMNE12Ar1BV3lgNM72AUEdUQpQ3X4aTVgzY7wiDgfbJi?=
 =?us-ascii?Q?L1mUfEZZ7CXQ0NjiB827RFrbkh0cS5LhQoby/BjaqVACOluDAyqqfUrNAUQK?=
 =?us-ascii?Q?xIJpxn5F510cl3gnQlF13EGu1jv8pEf+z6kx5FTo73xPnFax/j/DqCVgwg66?=
 =?us-ascii?Q?IVIRidoFiaTrNbC03o8TnbL8GRQG/z9nG0KBfPLmWSCnnFRsHiH8/G91GYwX?=
 =?us-ascii?Q?TAg71dOv4QB9gZO9cHVntZSZaY110H3x5jEgMhes/qNmJNULMOUuvkh/CFBS?=
 =?us-ascii?Q?yMQ0+MSGOlIIItLUz6RTrAm+k+dvHmwygFweqt2B?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c2eb574c-df41-4d7d-a0bb-08ddf464f360
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 14:34:17.5723
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: nuekJOcIltSv64PXnhJ9nduz2Ux8IGU0sDYcCkCUw4OJvfDQhyOvEIyOeWPaznQR
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR12MB7213
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=BgSdNvPI;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Mon, Sep 15, 2025 at 02:51:52PM +0100, Lorenzo Stoakes wrote:
> > vmcore is a true MIXEDMAP, it isn't doing two actions. These mixedmap
> > helpers just aren't good for what mixedmap needs.. Mixed map need a
> > list of physical pfns with a bit indicating if they are "special" or
> > not. If you do it with a callback or a kmalloc allocation it doesn't
> > matter.
> 
> Well it's a mix of actions to accomodate PFNs and normal pages as
> implemented via a custom hook that can invoke each.

No it's not a mix of actions. The mixedmap helpers are just
wrong for actual mixedmap usage:

+static inline void mmap_action_remap(struct mmap_action *action,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t pgprot)
+
+static inline void mmap_action_mixedmap(struct mmap_action *action,
+		unsigned long addr, unsigned long pfn, unsigned long num_pages)

Mixed map is a list of PFNs and a flag if the PFN is special or
not. That's what makes mixed map different from the other mapping
cases.

One action per VMA, and mixed map is handled by supporting the above
lis tin some way.

> > I think this series should drop the mixedmem stuff, it is the most
> > complicated action type. A vmalloc_user action is better for kcov.
> 
> Fine, I mean if we could find a way to explicitly just give a list of stuff
> to map that'd be _great_ vs. having a custom hook.

You already proposed to allocate memory to hold an array, I suggested
to have a per-range callback. Either could work as an API for
mixedmap.

> So maybe I should drop the vmalloc_user() bits too and make this a
> remap-only change...

Sure
 
> But I don't want to tackle _all_ remap cases here.

Due 4-5 or something to show the API is working. Things like my remark
to have a better helper that does whole-vma only should show up more
clearly with a few more conversions.

It is generally a good idea when doing these reworks to look across
all the use cases patterns and try to simplify them. This is why a
series per pattern is a good idea because you are saying you found a
pattern, and here are N examples of the pattern to prove it.

Eg if a huge number of drivers are just mmaping a linear range of
memory with a fixed pgoff then a helper to support exactly that
pattern with minimal driver code should be developed.

Like below, apparently vmalloc_user() is already a pattern and already
has a simplifying safe helper.

> Anyway maybe if I simplify there's still a shot at this landing in time...

Simplify is always good to help things get merged :)
 
> > Eg there are not that many places calling vmalloc_user(), a single
> > series could convert alot of them.
> >
> > If you did it this way we'd discover that there are already
> > helpers for vmalloc_user():
> >
> > 	return remap_vmalloc_range(vma, mdev_state->memblk, 0);
> >
> > And kcov looks buggy to not be using it already. The above gets the
> > VMA type right and doesn't force mixedmap :)
> 
> Right, I mean maybe.

Maybe send out a single patch to change kcov to remap_vmalloc_range()
for this cycle? Answer the maybe?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915143414.GJ1024672%40nvidia.com.
