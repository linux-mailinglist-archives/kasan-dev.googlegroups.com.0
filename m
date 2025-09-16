Return-Path: <kasan-dev+bncBCN77QHK3UIBBE6CU3DAMGQEFVUTOOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 193EBB59F95
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:40:37 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b5e91fb101sf156237741cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:40:37 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758044436; cv=pass;
        d=google.com; s=arc-20240605;
        b=DEcTnMOUwUITDXle/ubKfN9vNfM3KQIrHc2nEn8gllNQnHMIq81hqizVkmjs6bD9KV
         zsJFfApceV7V3vu6I2xuDG6l9/qhNfKTz/o/+uh3fjWWaayj7rCidjcCZjY3OnGOujy+
         dTA+LELczL6EdiTPKES0kWRpO9unAC5aSfu+J0eHcoIrjBdukeNHWccV65YrUSaH6gio
         DM5XhloZroKUV8H+fh/W4DmMZD66PQhC9TifSbO7ovQ8yRitEvTjZAtyNoy44gwOROyp
         QSFsrOiFcAYK54LpTo6nY3Phppwi7A01vesvMwMZ57Owz04dBqoliQghHYOT4NNX4tsk
         2K7Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=K3IX5d/bb4LCGItaek9RTpXoObz7KGZzqteOZ8uowsk=;
        fh=LMgfpvYsJx15jo5LIACunR+PitiPiI1pwwiPVzsVU+M=;
        b=DWyTvrzaiDeRehOMthu9rwiTdUy6XFq/5y6mDb4kN65fazc/YCPxSVZ+DP78IOuS77
         u9hiSN/wohU05j3fouZescVmxBdhAqFvQB2fW6A/mvqDfNhra4rzrIszXnA0i6wPl1As
         34je/SwyAeyQdDsc2+OwwttVgX3+mFjO/kyvdPeScfI5go3QXu5BQZYPz+CwCaFSp/CD
         h4VDuZrX2K4TT6eazM3qzA5ZqmlLW2veSGHfgFf+p1ai2h0Fa0jYNJlQM6nDTcLCuVVC
         Y7aZf5Uw7q0IHdnUhpO1Hs59DrIsgZzaSbQqxPpYD3gKZZQALShvPle6lAcc0IHwG6rN
         ZRnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=pL+P+FqA;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758044435; x=1758649235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=K3IX5d/bb4LCGItaek9RTpXoObz7KGZzqteOZ8uowsk=;
        b=WJqaQwObleO09vS0PMC+RG/JanKaYr0OKWfNvsdXHS/hjRxdP60CNolAcDmWIUb9MJ
         TixDNQ+L6RnmjGoRV4UrVwmgz67C8E1o6MUcmtQhf6lIbLZu4QQGd2gzmEY66K0PAR99
         zBCBWRsIiY0jh1PAlpgyJwQtkKzP7y4QwgA3eKBNDwo5I3gYIxBAUhr3mI2MSZCsseNx
         2Tkrm6mvWQZBAu0N5WIz0JbYh9J3PyAQ+EUmUMRi0J/LiHwT4WfEjkC46oK8M2n/IeQJ
         ufCbLYyOL0/KckJLsIzB7tRvyHo7lD5v1mOZoUHntVm0bbIHyeFo4h2RAPIzyD9NHV0D
         MXAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758044435; x=1758649235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K3IX5d/bb4LCGItaek9RTpXoObz7KGZzqteOZ8uowsk=;
        b=eqBG92PX3Abdns0htftczfICBxO01oD0kDRvdIS3SGTjSQcva4Vv4hGo6k/uGX8h/D
         3GMA2SNcHjnU8WcZ9UTzb58QbU00B0GubAWECkLjlCukWkxL3YbGAqujyMaANV4+Akdf
         dGSQ5TPCYjRcaAz5PN+1XYNKISl3v1kw/wb3MvNaKQe8DtAf2WveurXr7YyTFjvd8yBA
         kw7PY7M/N+SWozY+M/FTr/2eAmH3OHgND5Y1U+gSOjCtobbdrQBvIB7aJPHq1a0Nfnnw
         lislYng4awwkU3rIRmngntav87Xm4/jy6W8HvvTIMRTT1+sbeWipvXfZHqz9XZc8P+Ww
         CWxw==
X-Forwarded-Encrypted: i=3; AJvYcCW+KhgOUME0KkZMi2bMAemBVf+aq3vqml3G8+nW4QAqAH9IsOks+OuWuElfoPKBAKWhXJsiGQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy10+Yg0c6+cx3Rw2tvLZTYee5Xv+IZPzAh+ZxrKHpitYEPpXvR
	HN3NJN0l66/ykVaUBt4WydX6zv+SfkNs0S5gbWGfA4mZ1dl1Y3BLPb0v
X-Google-Smtp-Source: AGHT+IEChE95dyAvLSMDVxPIX4Mhok7k8QLxHCbZePcnYmwh0WpfF5on31Cg4NWWwXrFIIZeLQ2ZQg==
X-Received: by 2002:a05:622a:598d:b0:4b5:e294:b5d3 with SMTP id d75a77b69052e-4b77d059992mr219889791cf.57.1758044435566;
        Tue, 16 Sep 2025 10:40:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd46eeGfZefN/uNPeBalmZ5DON+r4Ugze4Dv42hfEajWcg==
Received: by 2002:a05:622a:3c8:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b636ccb94als120291891cf.2.-pod-prod-04-us; Tue, 16 Sep 2025
 10:40:34 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCURmasZbeFvWgo/jC0zH+Glgvd0WD4cg1fPX6vMNlDRpH+XHQbahyHn9SBbkcBGLghVXVUgwmJZRA8=@googlegroups.com
X-Received: by 2002:a05:620a:a203:b0:800:e534:ea6c with SMTP id af79cd13be357-82400c2387dmr1926624585a.77.1758044434617;
        Tue, 16 Sep 2025 10:40:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758044434; cv=pass;
        d=google.com; s=arc-20240605;
        b=YY+d/0v/5EuwuGVJD+B7uLeSS3hpmTM9uqBSwwdeYbCaFSN3aeThG5EUY4Xa5TIZLL
         csxwsaPfUc7x1eRNGswbbBfqUmpxDKXRFpvrPPefyP/VJhCr7Nv7LkLvZM2wQlgqfU4K
         6VseJM5LVcDL34zTSJ3tIwBxxDOl812dX+Ckw9nCQnA9lnCa505LGPVOvvVRW8ICjk3h
         /C77M3sd52XBwzd9+xLPzQZcKhHovLUcyMscgcR2tMjw+BXIhnJTb+8zo5f2R/DeIIxz
         gNACkDOE//Ds2vNNnJIOUeYg5dGE3r7d6Wpe33frVfUxlSXUyP4U5jusI89Dd0jWq50r
         5JSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZuOm7RAr7ULO4gzMgfQKYRi1nq8gzxqXtlxew6kKOQo=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=cBfdA7ORQPwwsG2Lo0hlQdy7sf9YlUWoIItbCjPhBrIz4m9EufFX97sXrp0llw9lBQ
         0nlpI4cWOaVfhF8lCZXLYZFQfuGJw5CSA0SSUv7f1x+giDtRYJBO1o/1S2xjJxUkcXw6
         UV9GyjYRIBqGWNqt7WufWYu1dRFzC2gxFbWFt30XkzaR83bQRscO7Jclrb/1t6i390RW
         IhUecu/T8wB4/pUuAxgFdwSQHk1B//G5OFxsmlWonBVmx+PTp24oqujGRDkkbyGfPbKE
         vVFocQNk07hPMaFIX56uhpDWzyIj0wlablzy414WDWe6lm5pZz7VXNXhkXY7ghgwWHdv
         0RIg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=pL+P+FqA;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CO1PR03CU002.outbound.protection.outlook.com (mail-westus2azlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c005::5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820cddbd643si63885885a.7.2025.09.16.10.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 10:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c005::5 as permitted sender) client-ip=2a01:111:f403:c005::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=rBgA4Hg1sov6XB3H+Dyfkvlo7JctE9hLSbuhC8CrcDy8EskXn5GhheflqXaJOPIIQnLZouyNmxxw/4j6hyowcGYFEI5+hYJZLIje1pk+UF9zzentynHBmMdbFnyhbbmzYNPmpqOqHkvrmifn7k5Pj3j4uHsYocT/Y/Zsm3KmrTIFOIVJ//KFKh/lEcNBdGFUfwi3H9i6dC9N+jxeOBnV6Mni8VXm/I+oEtdM6QP4w46LjJmA/P0OzxrI3nXo1Wqyl4QSgtYFam/9SnTQTuzvEXorsufvwF+lm9bvmgkW+zoUGZKkpelolwX6QcXutyxA5w/3DI/aJdLZ1kj860WrjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZuOm7RAr7ULO4gzMgfQKYRi1nq8gzxqXtlxew6kKOQo=;
 b=pI1svxL9HSDh2zpFj5thW+L5LeO3yInWM8Pm3ZEaE1qDTGZLdl3GlNN/NUJAWBlvtzP8rwpR2RqIAFzd2OxFWN0ZbilSr1ff0P/gSqBj6hxPx81A9GhcpC0/+43D0ld+ASSKjwcLqOkxKkf+d/fsuXzkpZQbCK7EPm80YzhFVnuMERV0w5WqkIqvDJgJD8DFDiB+Zlo3wilkscj9RcpIO+oW07q0z6PX8eAxfMaq0Legaok08aOzo4E0DdIyaPt8DZXknBs1nvQXG8xgK7OsC0sPQn2K5rRQKW2GCQNoyMulAxMpN/Upr9OioJpEDE9lDADlmPel+WX12Ej4p4pPXg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW6PR12MB8662.namprd12.prod.outlook.com (2603:10b6:303:243::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.23; Tue, 16 Sep
 2025 17:40:30 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:40:29 +0000
Date: Tue, 16 Sep 2025 14:40:27 -0300
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
	kasan-dev@googlegroups.com, iommu@lists.linux.dev,
	Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 12/13] mm: update resctl to use mmap_prepare
Message-ID: <20250916174027.GT1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <381a62d6a76ce68c00b25c82805ec1e20ef8cf81.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <381a62d6a76ce68c00b25c82805ec1e20ef8cf81.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: BL0PR0102CA0050.prod.exchangelabs.com
 (2603:10b6:208:25::27) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW6PR12MB8662:EE_
X-MS-Office365-Filtering-Correlation-Id: dc7453cb-6f04-40ae-ad89-08ddf5482099
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?jOUMyQKJcTwCYdsu4ieFTku4iJqky1IW1515otgkTCMR3Nulu2xlCmYl2GuV?=
 =?us-ascii?Q?perHlBRyjVXKAYyfHD8j+RYUx7HwBqIDB2+UCx8N7JTfGsV55zeq1yFEmYKl?=
 =?us-ascii?Q?zrbuDHNLkbxTlFxUDHh5AzdXnNFth7HFfhkBFh2W2ld12PBk/EaqToEPoj7V?=
 =?us-ascii?Q?ZwFyGN9NEB1KvqJ0jK/iQhvPihUy3shU2WSlsQG5H8+f6vv1yyJPfgpDPFuw?=
 =?us-ascii?Q?aJvfHhL5XxCXAAMtgkrCDYkL5/dJQ/JSPzWZQPCTX8hwxsV8VCWQReLgqRz/?=
 =?us-ascii?Q?LnI9ZaLz3bLihFFzD3kUexAp5/U/cXbPyesZCETCtc+VRGtVgBM9zNm42LNB?=
 =?us-ascii?Q?YUf2LQfQH/E5pBMYKJwPyrW4V1W7arLibPi3mlwuoKT/UY8iUitBCSfjRrp4?=
 =?us-ascii?Q?/AJS4WJze4ByC4jHHE5h7PSj3CMtl6ddXsfwXBmvqwFf9vxdIvOCjviW00Qt?=
 =?us-ascii?Q?JREuFqFXYXCuM+UMaEMBe/sY+bLDOjhAu+YQzn8v6lkR40yG87oJYrLlUqnU?=
 =?us-ascii?Q?DwSY9P1msB3BcTm2ACSAUNlWUAq+sw+s+K3JuvcBDIjdRM26lEL2W/Vnz75x?=
 =?us-ascii?Q?LpMX4yDek6g8NPrGJzI+7GkpBTlZqKFjvPDAp4Ow0IVwQT2jqn7cEUXichmN?=
 =?us-ascii?Q?AlWuAtHZarbinb4T+taQENAVyKVLzrxY5lI1PaephN3RLtLnxhogMVqikQRs?=
 =?us-ascii?Q?+B3fErB3c6CzS1wm4NT341tTX2T1CrC+B0oq5pVwnOyh9FuRnc/MCg5e66Gs?=
 =?us-ascii?Q?QDB19EADO8pqIpZ+KQmPmup5Mw5aSsh7bGrzkhqVfqpKfwg20Hjco21PCz2Y?=
 =?us-ascii?Q?N+Lo+M7XSkNiknUii7uFI9yYTv8uNimfGDZEfVdn9J+ICf5iOSAkYrMb31Pk?=
 =?us-ascii?Q?VngNHhjloNzwaJTxlJetD+a3pevZWqlfQNHm1+w00tSvBFqYj0454W89TOfq?=
 =?us-ascii?Q?fdhwkCaHiWUlaeybq+r1lRp6UfBrS0pcYN7dpyEkIMWXPdIlYxJAjHmec0+H?=
 =?us-ascii?Q?sa0Ot3FyXkMRZkgrq21mGaaE/ihvhyR9g3RARJoSU78mTB/j18WPTR5mSFt8?=
 =?us-ascii?Q?Llvo7oKLWZU0eKyUZSJgnysBHlm8j/2TcvFIqFrMVzEiIRfpw3DxMK0jVbBG?=
 =?us-ascii?Q?bvjaHApP4ZJWU3sVOEcxsmsKOT/3lmn1D6746m2DXaNNXahcluVUPgU6unwx?=
 =?us-ascii?Q?kWdx6j9I+TZD8ZUym16BfhhVi5cHwDYroOTx0JmMogs4N91VOvcjWOmr7oAH?=
 =?us-ascii?Q?la1QkG5s178WMJ17M313E7VE0qOYpYOlQpBrV7is+5OlV8GTkBL3VnbTlMgh?=
 =?us-ascii?Q?KOLIQV05gg+cv/AUgidDUkFYA8+UsmOv+zADids3x066mL+6bY/TIrB+P7YU?=
 =?us-ascii?Q?FqNPC5ARTJRPtL1kQiNgd9aTaHM87MPb/yb0akdXrZhniriT4Jz9uCyTaalx?=
 =?us-ascii?Q?lGLQGziD6Yk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?CdpyjK0FiSO0J+4AX4wH6kdK1JYSjeAeAvwt2qL7AVcAviDeHpcE0eYtcL7f?=
 =?us-ascii?Q?VwLGjYiaD/dsgPpMbM2gV8BqW7jewIv2Gd30wv7xr0arAMTsQLz6lzsMorOr?=
 =?us-ascii?Q?yd4WHtQjqpBrgXkz/KCkevpkZmpCTkaNYuIfRlv82pmvLM6pyXc0ctaYNjTT?=
 =?us-ascii?Q?KXdcLHpmIyUDLqPUtX0QTxsjHoImJ3zy3LPC0Ef1kLV44WHEB8vNLrjgOFaU?=
 =?us-ascii?Q?Kxogre4cvLyBlu2L3TmT6Zuvl9TrUw+9v/hpWZr1r3HDA4aGqXws5B4CVOTz?=
 =?us-ascii?Q?OztW3L+ja7dPX5y9k0XVY7AwZK78D6vmhU+gSTobMFncPBoaaE+oTaFJ6GzM?=
 =?us-ascii?Q?UBjaYBkSXPTaPV5ZvPFpWLvnA2sLaq3PYrxVhw1E6Np1rng7PjdhSw7OqxYt?=
 =?us-ascii?Q?ZagYNcwxnt+dST9ixQgqAqykkaHX9OBlKBzmzDecgglj9kO/xbflURn90yJk?=
 =?us-ascii?Q?c50zWdrxXyic8rlAcCHY0NL1LKpgkMJDRlTPYYEJVHXU3BRPjnCidj7KrL2f?=
 =?us-ascii?Q?BxcX1FlDAFGzIUJ7Std2wLyx87ysuGgApVFBmi447+yfOeSpdzfsxsh/Plax?=
 =?us-ascii?Q?3caNoZ24khup6xUoRtMO5xO2Ub5DEEEriqbEhG1+vYY2oar5bHIch7BE/599?=
 =?us-ascii?Q?Cg16b3jQ9qQ/G8ihfBTA7Z3a8R+FhZNxzrN8AkU07Coj1cZf1sMQupIoyb+v?=
 =?us-ascii?Q?/A25rsnft2gHcCK9Le2ZvFxp7YUCoDQBo7WDhN1h8YX5hUm5yEE+lAjQlYw9?=
 =?us-ascii?Q?mdFBvJ8nxM91J6+7cVGuU/et4zXZsia2Jp6lHHvMQf4NGplk7qAqTtgyoQQo?=
 =?us-ascii?Q?kdU2s6FYtNAoflX+FoVdAeyWEa1kvwgL/g5EW5T8r+0o/zeQF9JPI3u8Myqk?=
 =?us-ascii?Q?ePWMSkMI1S0RdFz40vdWUA2vUwZn47bNFw1ZT59ggqcn+JIndx7WAIsl3w2A?=
 =?us-ascii?Q?bAQW0gCSCQD0iSlUkNND6qlHqvGB35EReLqdbIZGh8D/xkM9WG6VyT/+180u?=
 =?us-ascii?Q?2UBKHCCcKHO0vEGuq1Ra3NZo3x5BrM+4+StGDNftBk+GQyzSvffKYV+Z72rG?=
 =?us-ascii?Q?SO9f2QHIqSy4aVugJtjHN5g92IzupR+1thp7+1VJzRNWUxaMUJXp3EIs6/Uk?=
 =?us-ascii?Q?SFEyEUXIb6U9jSy1Zrr70CE3jIchUnD5VIZBLYNV+yHids0sykOSPzJXWK8q?=
 =?us-ascii?Q?WqFdIGc88XBsIw9F0EUmrE1tI8fX/RTxdlXnRAV1kYMP07DTT7seLTXtdsQI?=
 =?us-ascii?Q?1PGdbEfJz5e+Q3rsJn5Ca24+WtbMsUy97akAzcgoCXODbLqY5WLPM56OfN/s?=
 =?us-ascii?Q?y1uJW2PvU2hrP6IRXBQTD8NbkHGRnrIibC1d7p1Ds0dD+Behd284xxaT2bjs?=
 =?us-ascii?Q?7YFQf7qYa4vn1HEVvywTuxM7d7UuKx2FxpcwvchRhrrxYaz09wIqPxH1FgwD?=
 =?us-ascii?Q?RNivrQLaLHsYUsHMnZ0uno0FsTpaWFbu3MdEBo+ljf1kiDNxzkCfELA3qqcn?=
 =?us-ascii?Q?T+rcTTU3Hs6Gi/WrFiP4PtxLAAUmK1xCrKE2Q2pWP48heB9w80O/4NORamka?=
 =?us-ascii?Q?EziSsDQS2XQWnUrAMyVegUfIQFZEEWgGvM+JlH8P?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: dc7453cb-6f04-40ae-ad89-08ddf5482099
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:40:29.4783
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CrHnireU+CQRAOmXYmtBwasgYF3N3WvN3x5h2upeCasL8XWg26inook7KFoAIqHl
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW6PR12MB8662
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=pL+P+FqA;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:58PM +0100, Lorenzo Stoakes wrote:
> Make use of the ability to specify a remap action within mmap_prepare to
> update the resctl pseudo-lock to use mmap_prepare in favour of the
> deprecated mmap hook.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Acked-by: Reinette Chatre <reinette.chatre@intel.com>
> ---
>  fs/resctrl/pseudo_lock.c | 20 +++++++++-----------
>  1 file changed, 9 insertions(+), 11 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916174027.GT1086830%40nvidia.com.
