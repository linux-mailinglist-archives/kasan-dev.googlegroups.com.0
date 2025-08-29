Return-Path: <kasan-dev+bncBD6LBUWO5UMBBINOY3CQMGQELKWORTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FEE4B3BAB7
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:03:47 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-61dc9b82764sf2204546eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:03:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756469026; cv=pass;
        d=google.com; s=arc-20240605;
        b=SJGXrEzqsr1noRdbCIVAfXOFIU5ZVM2xTbIJVMsdKp4UeykNZCBzCnqrw/aQtrHij/
         v3XmVtjJkF3XxOlH3JqrTI9lNsUTq1nC5nk3k/A9opW6YHJX82P22lZvvathB9oIOLnX
         YXlH8BVUIwMBcKOyWUs7puPjIbtZHU87cN8+2BfN4ZIsUrop90zwp2eLp+lYBFGulZSC
         2S3ISldDys/8TJUTwWsJvNivY8XpPj3XZIeFm2i1aXTXgDCM/Caf2GTsQphfdom5lRwh
         CeQuUbHiD6St7KDMXg9282xffSw7c6JRIdERAE5rLLCPsX6SO5s8grsHUYO8zIh8UyAG
         wHfw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=a0Q6qi0hhvgrmyxJBzVsDyITEKNIjFD8HwhHuEvqxbQ=;
        fh=gq351cK6jODCJYbO1sIw0accJB3rt3Y9BWTJX6rJThI=;
        b=j2ckzXPQSBlxKPURZEVdf7wPbQJGnnauZI4ca0eWwTSdbKZLscXh7Qc4UUgsOxQ7CS
         YOoA2+M2ixQmFyKzFFnfm4pJMwqLpBWxMqdCHjz6Rkd0EyYwL4OvDSezlgK9b0q6rbyG
         mQwYRrOE+jMzuvKQsctfiVGw2uuh4lV/KJzbV0MloN186XOVL8h0B229beFoDVIShwNc
         UtMHgZbPsleMJntJSDDrc6Mwr3p9Lqfcu877xKkSM1IzS10vWPJMM52Gp0VU7pz0Qnlx
         LMbvFo7YATjzppb5hRfzCvCdcl6Fl7DPNhdcwPJ0Rp17z8m/oZJNs+XToREhnGriaXbD
         jh0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ntXTJP8b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="xFuHiKK/";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756469026; x=1757073826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=a0Q6qi0hhvgrmyxJBzVsDyITEKNIjFD8HwhHuEvqxbQ=;
        b=in/F+mKBaWFuu+reuiMytvQMh+sJOucEVcqVAHD6we48Qnflc/Qa8ziNDHHSVMUqWl
         vgpGk0UoHII5dUZbi/cg8CF89XiDes6l9aA/Ht1dQv7OzJNv2EO8W+EQtGD0ySMDfnJ7
         ZuiapUU5AlgZqog6+9gERKT+8JlKaP2ObWopdszXfAREqzsrQtndeCrUG/GOHOqA09HG
         H38Dvi3RrUneSuhaERYQ1K0e6Ecap1TRr/aC7jBppVy3FnDbZZazHa6E3Uukc8dRod5O
         NgFoY63CaOEDLPvp4J0i2pLGMmI5BiWV5jng6quK+Dc4zmEiwxe5D9BuvZT9yBIsXxaG
         yNIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756469026; x=1757073826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a0Q6qi0hhvgrmyxJBzVsDyITEKNIjFD8HwhHuEvqxbQ=;
        b=vn7a974SYQVvMar4hzSUbXN57gIvi8hWdUPRAK9l+mbDZl7s3UkK/pRC+2uHLb7dJD
         tqFwLHpsvd/V1Bv5UstU9ckklaybd8+/E9hxTXual6/D+iB9CKJOuVQgR0uIO65YPo4C
         g9bV9kFUmyM+xW4aaCdNvZvsw/WUDKlU0axWSizrVDZ34qpu66MKwLy9jZ5ygLL8YeX/
         /ZDXuUiuamdD3vYqooCzYFeSA/E7AtAxCGNOgx0GImGnQgMYYxbI+NO1NOPvudWVeklT
         2V85VJNmHAKb8GuwdBPzFBrHRzALVBryUzEXFsx+mZ2FZwJUAV0P7j9mmotxdiEROHFb
         iSaA==
X-Forwarded-Encrypted: i=3; AJvYcCXPJuldMPxaVOr9Nf9BWgXU0EjkQHQ7IC0VQaE6jQmq4gt8AcmPdGqVfrj05pVqYz66Wi+bxw==@lfdr.de
X-Gm-Message-State: AOJu0Yy092K1eoWdkco9eeZunk6uU36Q9lRQESKgEPH15PgeREiPcCUl
	wnQWcEaeSB5WEFtBARvx1muIX5ZXN/HqemZA3bz7Ks0Kfco9SYvGcxns
X-Google-Smtp-Source: AGHT+IH/FiHh7WrDHu2SH5C8VA5wUwSzvRDQg6ZBzMD7mLRbjsL/VIUW7znEoLrrUj0y3nIBRBcwYQ==
X-Received: by 2002:a05:6820:c007:b0:61b:5f26:7059 with SMTP id 006d021491bc7-61df7892f8emr3629100eaf.4.1756469025785;
        Fri, 29 Aug 2025 05:03:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc7KfIcZ3PCQF+QZEVT8yQnF8Bi7f25jJ5u9vIwpSvAqQ==
Received: by 2002:a05:6820:508b:b0:61b:5157:c2ee with SMTP id
 006d021491bc7-61e1276efe1ls481051eaf.1.-pod-prod-00-us; Fri, 29 Aug 2025
 05:03:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV49nYWtl/Q6F15rTZMzLcNhY2D0etg+WGVSo08wIhGiBMu7vwtwCDn1k4lZwtnWahpXq3wDVquwoE=@googlegroups.com
X-Received: by 2002:a05:6820:228a:b0:61b:e931:c6c7 with SMTP id 006d021491bc7-61df7892c32mr6459179eaf.4.1756469024714;
        Fri, 29 Aug 2025 05:03:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756469024; cv=pass;
        d=google.com; s=arc-20240605;
        b=DhaN7K0HcjD4suTqHjuw6rwRoAP03AVMwLzY+uaGelXcBbi2I7DRlwsGo51iV6jhGz
         i/WkgAETh9a+Rnp2T4zLuL6SMA6KGXqiDRzBstgk85LDNgbhUig0MAADr5sGregMQR99
         eNcFleRIheaBNjaYq0Zxf6hNPCFU/oVGL7bGkVcoRU1NfNAyX+swGOfHQgMTl9ldKHEc
         vT+mBnUrf6pU+myBNp2TUj5W1OgEEvA2knNBONpJI9J+8/fSxEWOZnbT2bUcxKkvVYrm
         JcIXUjlIl7P5KS9bcpz8epFcTcUfmKVXmtYXWcklq+kboG3YehLVnFwzM3oV5FOcXDBi
         4U/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=cHOV4me6sdlCwGO2rzwPW7odCdwnSehkArG7tlINzVI=;
        fh=nDVLMfpnt16dAvQHlJ/+ZWR3WaZCA+P2x3XNdYCnLhM=;
        b=VUYR7Kd0n5hAdJ1UgWgyf7YEPwbxjfzfShrSGMzjKrHPK24vbpIkbJ2e+focZdksLo
         wTUNMccTd7dNQsOQFGCZpfUjXyPqKjkCMudesi9PKJpRwOsw3caBkmpJG7g7OuSvpCmh
         Sw3rKxlma5Vt+GIhg5YqcAmQt0hvqLzqE82rXZPAmjCKotwSrtOkizRXWkha5ldTPX/Q
         l+fPAyBWl3qqVHGm6LMQM5+XsZw/VsLJCWoq+XCSYLeyOeswFFX7gWftcMq8PG8K/Wk6
         T20ximHvYJadMXLJEoGU6NLIyqQHYuKY2JzSccKsdjy1F/dbBPzXFTYe741UQVg3CQnC
         /F1Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ntXTJP8b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="xFuHiKK/";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745580bd4c2si88997a34.0.2025.08.29.05.03.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 05:03:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TAYGTZ019246;
	Fri, 29 Aug 2025 12:03:34 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42ta6y6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:03:34 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TBWruD005142;
	Fri, 29 Aug 2025 12:03:33 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02on2055.outbound.protection.outlook.com [40.107.96.55])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43d5tnx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:03:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tnXda8yH1NSCGTHaNscCPHYo+MEDwO8XbufPl8NbdOijODGxOuExeqIVJppQTzDnOATIJrGnLZ1/r89nEofOkWILpZzwhJOEOyHRqPyGCoxtS9WOgr9JIzyuurOaV/tY3LgsJAuAaBOjdcUAIsjPetdv5+diVGN5juSHVtS3O6cxhTGr/sMzxlJXeUCYkpk9/Njob8TVp14+dJ9AEFq+Fcxs/eUVLoof4oyPvfS7J43hvwIunHpTeKnzkr3ISVRWno6IDzxz4aWc40P3YSds1roJUlMqAwVMIGBN/OmS3gUWSzKetG3xSV+0AXZTcDTLou/DO9MuLdmd720nPoBiHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cHOV4me6sdlCwGO2rzwPW7odCdwnSehkArG7tlINzVI=;
 b=ckZOzX3et4OQlhNJyQXraKUx28hH+xpciKFx96V3BAER8e3NeSwWokWdpEif3C9YzkmJ+6CdnKOeSH/x++O4AAJaUb6Lt1ZjgK2a44/ImH6pEZg7n4ii3MxgE3v/a9ddzdn/V4y2gjc6rNBRPP+1kMmiuBhuPo11WyYC9Bw54qAjhGnvL50d8vkjfk+uOjzI+Wsl2qJhN47OaMFZ/zc8k7oz6huvlLmPjgWOfRHwYJOAwSzkPNdncEIIRQlkf7+p1x0mKXoXNby6zZr713jpU6IbxO9DzAaasdUkYJjqQz6qycELNZ5jA5+5oqc1lxg3NUWs0ZXPeTOsmQ1Qs4E7Vg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6803.namprd10.prod.outlook.com (2603:10b6:930:9a::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.16; Fri, 29 Aug
 2025 12:02:41 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 12:02:41 +0000
Date: Fri, 29 Aug 2025 13:02:38 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 13/36] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
Message-ID: <6552e67b-72fd-4d9e-bf35-872cbfae5de0@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com>
 <cebd5356-0fc6-40aa-9bc6-a3a5ffe918f8@lucifer.local>
 <0dcef56e-0ae7-401b-9453-f6dc6a4dcebf@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0dcef56e-0ae7-401b-9453-f6dc6a4dcebf@redhat.com>
X-ClientProxiedBy: LO4P123CA0136.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:193::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6803:EE_
X-MS-Office365-Filtering-Correlation-Id: faf93539-0af7-48e9-6ce5-08dde6f3f472
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tutyrE0Fu/P4xEqaElaoow9j2A2XJhVj1gTMpJj5tXxK1yqTlbsukUAse054?=
 =?us-ascii?Q?aOdVwR8RCWD5gu2qPw2+4gHgLr/DxQlYMOcBTmB7rV+sgtskIJNsOozQW5CZ?=
 =?us-ascii?Q?Gw5Eyrn2MucWODFf+CHRytQIU3zIi4eSpXA1bIpRvn+kMotRbeX+zwwxD+9L?=
 =?us-ascii?Q?8hz/4HbmKosOpdYgq5mcgyYcRsdmGZcTRzG/Vf6Uf5SWeV+6knLTjPAV4CtE?=
 =?us-ascii?Q?Y418QLcsg4ikWyQHyjZArDhzLsC3OGAntzAYo0WgLFXniDCLNnUARxpfgrjp?=
 =?us-ascii?Q?3BBR87Wy8b5oz1a0yfi3mwjbfnPo0kTmHuIxWKThuemY/snx6b97ccrkheSc?=
 =?us-ascii?Q?QPWLH1YB8kTzuTulMrsmqAKtnpS2HUz3ccepk4Bb5+xg/Hr4oXbaEXsz+QGA?=
 =?us-ascii?Q?05fiK9nmaC8BJC423aFfqeaBQxIhIT/3yQNlQBG0S1nYogqOEARaTSkORCSE?=
 =?us-ascii?Q?X0AMzQQfy7mIw/1EyX3CjM84OqfckV1cuE7K66UPVc3OoLMQ6c4q0gPuKG8U?=
 =?us-ascii?Q?Y3PpzcHaljRb5igsahNSh9mXIkvgKaXxFwlChKt751RcDaZ5hl2ZEatfJ7ZR?=
 =?us-ascii?Q?g2L4+qgHFRVwyCC03bFMH6f+5de4WWZHDyPaxxhiJlXWE3bqE169NrtLfw86?=
 =?us-ascii?Q?B/gnzu5RTrMkU1gl/9Ws/0FiZW0odDgP9FEdCNFkmVgG4aPd3dhnISrAntKx?=
 =?us-ascii?Q?ESjrwFTX+O08HWRQGH7n1Y3M2CIBBS85nOWHxG4nrGL7HleRNjUdsOmGsJ63?=
 =?us-ascii?Q?cehQNrQP4Ql7Kjpw0faQ3ZecXJu1Prc2WDqMoNwcmSE9586ihCyxjd8O/caS?=
 =?us-ascii?Q?bcMAp4ZxYBrwCUu2/NAu/Lo8hdohnqI8fDXcQI/61lhtW33b+K/reZ33jAWR?=
 =?us-ascii?Q?VpxBrz8TEB/kGvfA2IODJr6Y9qsu1eGgBctxlxk4/jgNTlFWy4KaDLsdJ1O5?=
 =?us-ascii?Q?ywvr/JcVFob2QptpcSzI4/O+/dV5un7fu4Srnj2uoYULYB2f5sbdyirI3i36?=
 =?us-ascii?Q?XM8CkoDbrfDNZ9niefGA/1fj/FH7e/Pnh7Ok8buZ1t0hQ3W9AxW1V0oI/aY4?=
 =?us-ascii?Q?b5nVvI9hbYfNYWBmfRRgKuRJ29mxM6N9JAtIczLPimdgtfyO4cIlVGmFFNT4?=
 =?us-ascii?Q?fFFJy4mEQL2e6vBoLo+Ujbj1ICtcMAM6wvlLc5c3obASckNDgl8kkl4y2djT?=
 =?us-ascii?Q?FsZ1mztyZ7hFuIOHonUvif+NcGFflDMmSzxnZMvHDNlK1nfSOVpGhBFvpoYf?=
 =?us-ascii?Q?7/E2Esan9bakeObSgvlXMlrUcoQL1gJmk0xx4WF4nO8A02tJm/K7YlITmBYy?=
 =?us-ascii?Q?wgPLD7VbJnfRK3zgCPKqaeoIuMYWrtugguA2+0TFdBAlQoeLkjn2Y45SI1l5?=
 =?us-ascii?Q?j5jmdcv37JhVeo5OXxZtLiyfimO4JulULi9NylAuSHM5x6MQig=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?fl0hWt4gjKqAit/1bPuR0KAF/lMkhtJpEsU9fe7xv48/YV2cZIGHGTQYNENT?=
 =?us-ascii?Q?PopNZLV/oVTD/Cfyn2sTc78ETn0R2vfkxvwEaCdPjSXe3Fu3fOS0bL3JuNTG?=
 =?us-ascii?Q?/xxvvbzObm8XOJNCKS165yetVx/Kqzxy5yTzbeQ31HYwqZEb3I6SSpV4dy7E?=
 =?us-ascii?Q?xt3k7Gi/phq9lzJyryaE6Q+rnrF8f+ExZYZaKjnbrOw3z/BrwE8Gqmm8q2AU?=
 =?us-ascii?Q?XqVMWxTca/PTP+O+X16CmFqmRSX9NFSRxiAkn+h81XglHaQaXuRghTtvuhzM?=
 =?us-ascii?Q?ZQojWMc1sOPyys2WGfjqGlbukgSO2M5ge1B1i2vPPgGsXraNfBnSME8AooPx?=
 =?us-ascii?Q?MPVqKn+ODOhlrINmH99YVOJAJdUncix6G7P3VycFkTaAPpUp5Wcmiyilwf0P?=
 =?us-ascii?Q?AFydmZQ8M68AEza1LmETA1C14xxh37DHk+chsxymExeLsJzeuGmBwjn7XRC7?=
 =?us-ascii?Q?HJ8EVJ4r2l+IA/7wC4syotNbCvFLXZSIRql5dCYXHD2KmVNqda/ivNBGVpus?=
 =?us-ascii?Q?4t7fhPkV3H98sF2IfZlwXegZUjqPeAtgVtuYnGMGfu4vIrUlanj6mDe54kgc?=
 =?us-ascii?Q?qsLJGuVN4edJq6blf9bKA8aCR3uwkc3LRgkNa5bMabqOxbK6eb1XUFGsBuvW?=
 =?us-ascii?Q?o4+gedmygjr2Y7lJHqTTetvyRbEnEeWalYzzU8pQLVL0dAICqN2vw3Zxz/di?=
 =?us-ascii?Q?MK3mezlMGpJOzie/SQDjNnlNQ7K9cyU8W5+wwwjFlXxqA3p9CqsEvYGJkLce?=
 =?us-ascii?Q?5TRZFE48ERs5Xegr5UM9Asg0AMSa66CYxdf/Pw0tHtdpTcKmEsXDEtYflDqD?=
 =?us-ascii?Q?3SOcQR11AhdB0WWDML2wBBmAcojUUsUB8zJVqWdLeXGLlzUsIg0dXnKeRDcN?=
 =?us-ascii?Q?hb+prRFkl20I/7jRmgcM5QCTgzmdbhOUt3HhFio8g4ZILp1XetFwfdd7YP3U?=
 =?us-ascii?Q?QW/ZL2MelyLUkJS2/3OG3Omcp7MgM9fFvhYuOH+lIqyrT1Lu84jgE7I1+/IH?=
 =?us-ascii?Q?hCSgOMJWYorZGUgOaFvGGStrLPhmC5BXy5CDJX5weScEWcpMqnNqzvlNi/PG?=
 =?us-ascii?Q?WnI0mEyhHHRk7tZnGPtAF3CjsZ7x7vAohdIdwCd5nXC77C02UKkJLV5lYS5/?=
 =?us-ascii?Q?XeO1Rp5YueiduJgPdAqhortgcjeG3khiXKB8VX3WBs0TwAJtcbfl/IQJGJJa?=
 =?us-ascii?Q?G3XVUUrp84/x7J05vFQZuVe4ZQR/iWTmwM0kCv0K50oUoauM3CTFcv1p5EXP?=
 =?us-ascii?Q?4owkIyqxd9w7efMzZhbthVXxA3LLLJCAUoHNSqtVdZh1soAbKGcMoTI0uQr0?=
 =?us-ascii?Q?svLueu2dOH1dZfpuT0zRZo2R+fGzxtgtYSSvx8TFx02YAuPRRMDT3kfc5n0F?=
 =?us-ascii?Q?cyBEyyVS1DvrnQ4GkclGhGeoL2B8IRoLLF5OQYSzDDf8gcOhagyRwQO6ovZC?=
 =?us-ascii?Q?btNlz1FhJeqaTJOb+8h3HDIYrBUygeLkjRstivzVCTAQ8QTu9saC4EfOBPCX?=
 =?us-ascii?Q?O+AarkK+RBu3zTWGCPlgwJRdeQ5gDfNXaEWeiqG+7q5FFqb4OUR0nyKCVV7J?=
 =?us-ascii?Q?J4wi+tTMseuM3/fBKQblr0f8CMJUZDFG622r4VA1efVoxycAFpDuePSH+9Gh?=
 =?us-ascii?Q?7A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: NVLZX8rSw6RlNzOR4/qDbPTmBoGJLP98XM3IVlzi9T6w5oxkTCTCFjj1PBjuetv1eZCD3qIZgW/4UTXp0vx6rKqV8BCmVbgg8cb0Q92HULr/Hng7g2DAmQ5aq2M1tJ1Lc6kAfxUHoUgsFocPczDJX2zf/l4fMg2NvEA1BOP1Y7tm2O+TEZbfa0PXWqQGgq3GsimRa8XIg7ydFLJC8rYjtO+mowD1O6MiUTUC5mfpsg2LzrAwwJoexe5l7oAKtg4L3Bj0TgOl5zwFzzYmKP2/128+VCkTLusBSge+1PMh15PWpyZNO0qWtm0t+v01XH+/7Zgx3irVZt63ozwYMkvDzQV1KgseQBvHiDEcWJ7dhHOw4z14OiCS31NctBY9Uh//ZTXN+kpw1crscYB8UZ9d4Ld2DNQ9wVhoE764maHaaYWrGqSq1TkG0xCz0oxCOw3uddVSvJZUHIbpvAPL0F+ckehxr+dQ76jdu1Rl6p9xAnkgm46/WZYH/SZhf+LjAOgoyRRjbuS7CdoyLLtrKydPBQROLRnksCq6KfxaiwEbFuCDoDVUk7TFmxxikV+UQ8jV6hHO8NerlgGOY3lzmcpl/fa2vWSiq725OK3Fnhy/Cj8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: faf93539-0af7-48e9-6ce5-08dde6f3f472
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 12:02:40.9718
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tttvj4EgvLIncRSFIFaBwPljoWNqbngAiUSIkzpYgt6GMGY7HX7cCpC162AuTLliEJ9HLk1earpBFYSFwl2Lee3Jctt0tND7VCB/G1lJs50=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6803
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=862 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290102
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfXxWvxlYo44F55
 aQgdBV+YJrtD3FRtdVU2Tnmk0lznDy4uIQVxTypJw6Q59I2loRFh/9HXn7Qx5GXYjR0AC4DXrQ5
 iKeaKNaCsSAwtHdT8kdgpYYDnO3gyv7836h7+t5SI/Qg3rI6vEcz86zruj9nGR3a+v8JL9YhYOj
 yKeblfBL7NvOvHMkvSB2bjiPB20vgtk6vmIApAc2aWu8DWaBuJ6C9RAgRUtdrmwnoGl62JLlfod
 neYEeT5830Opckl0LAMiRjRiVRKvY1bzG2IeZC/Ldi3AsLG2NBYl5IiC7SD2MxU6XH/92Ulbqdi
 b4waTpvd7K3YhjDdlaJcv29tqJomCl2J6fekLywo4x56SeWPvWJNUNUPP3MxDxESTIkrZnmu0vo
 AqVfaLjV
X-Proofpoint-ORIG-GUID: vElnQHCW09W2FrjjtsRdwfdgONOIgYzJ
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b19716 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=L1fS4YPRHCmu5w5ya-kA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: vElnQHCW09W2FrjjtsRdwfdgONOIgYzJ
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ntXTJP8b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="xFuHiKK/";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Aug 29, 2025 at 01:59:19PM +0200, David Hildenbrand wrote:
> On 28.08.25 17:37, Lorenzo Stoakes wrote:
> > On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
> > > We can now safely iterate over all pages in a folio, so no need for the
> > > pfn_to_page().
> > >
> > > Also, as we already force the refcount in __init_single_page() to 1,
> >
> > Mega huge nit (ignore if you want), but maybe worth saying 'via
> > init_page_count()'.
>
> Will add, thanks!

Thanks!

>
> --
> Cheers
>
> David / dhildenb
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6552e67b-72fd-4d9e-bf35-872cbfae5de0%40lucifer.local.
