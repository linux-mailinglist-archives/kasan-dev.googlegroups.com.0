Return-Path: <kasan-dev+bncBDN7L7O25EIBBGOH2W3AMGQE3R7BQEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BA43967FEA
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2024 09:04:59 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-39f5328fd5esf18204725ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2024 00:04:59 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725260698; x=1725865498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OQ5y8bt9124uSXfgnpGtl4dwguTVzudCloYnrIHb/+A=;
        b=SHrEUyqSMtIyCcrqY9JG60EerRJJjKNRXJ3Wq6HdNJDKsm0icpBqzwmruC3vQebpWw
         KLmZM4CNRiPH/SUpHh8xGXGbT722IBsBG5wDE64y8wtKbNdgOQsSdPlagzbjRCdya/UY
         5rKi0WqxvzqXAf5W/Y+2H1ewVIKA1Wsa3kstc8FLRDnjOsNWkmCSp2qI7GDC3fpmLU2o
         8WSswNKkRswtfuCjLpHEH0k2D2Euij4MQjAh93OfqDtSQuoaPDBKtsKSOtcQDTzj4Ta4
         sWi1oCcKxgcUIuCM6/Ck6S4hWDr3EL1vGU5wDirc/mJ3gEKlzGnaAg4Dcme6Pcjy4jZe
         xw5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725260698; x=1725865498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OQ5y8bt9124uSXfgnpGtl4dwguTVzudCloYnrIHb/+A=;
        b=GazDvXeLPHZaHUlbCP+wwkJaz3wy3FEwPDUN5HvjwvycRaBQTWZ1LtPROT1nmTjkPz
         qNaOIw767FdNsCMglDYL5YUTx4jmnnz1Rrhh3QQ/JOiSfJ8W0MEOv7fu3A4rVQZdn83D
         KIo/sXtC6rSmyl0jRwp09BRNzO9HGvizOhUTMyKj5Mr173izX0jdeZA64lH6DqCy+kI/
         vwRSkNFsSaMocJXl2uGr3hkEFQSmelWFo8q4lk/QdDbNjG0gf+Y/P14myfZ+sCLLZoUD
         nqlfSpm+et0sJVw1MtL3/w6snuPIr36kQF2RjCt9ABWeMK6phvpiJ7neSrTwnFzqc6p/
         PFRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1HpxfDorQhvyN1fhb0ypKPjTuV9tB0jmvnbw3REB/xbxJpr0qdtd2G6MyNkQ1JeVupCrlKg==@lfdr.de
X-Gm-Message-State: AOJu0YwDZ+dTo6o8B7bPDDVSKIP7peqbXgGSWA+R3wnCIeZtCFRXLn9G
	F3qeE1rgDGt9ExEDhSMs5fLn/fecgOnB6dJPwA6G4wpQP+5vGTxf
X-Google-Smtp-Source: AGHT+IHfHWm3FKcqHDeu0AjmnFsij5iZVFUqT1vx3duHHAuEQE08+mj5UBeZlXlPyBlSQacgYrOYDg==
X-Received: by 2002:a05:6e02:16cc:b0:398:acbe:d798 with SMTP id e9e14a558f8ab-39f378ed713mr143007645ab.4.1725260697638;
        Mon, 02 Sep 2024 00:04:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:11a1:b0:39f:56c4:645 with SMTP id
 e9e14a558f8ab-39f56c409b4ls6890495ab.1.-pod-prod-09-us; Mon, 02 Sep 2024
 00:04:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUotr5KiEuR3Gxm36p2ozKwM13hp6CXzD8hCX+7OMWBOXFyCesaT0IMkym9osAV1rauQwUXBENJR6Y=@googlegroups.com
X-Received: by 2002:a05:6602:2dc8:b0:82a:1c86:8ca with SMTP id ca18e2360f4ac-82a1c8608f9mr1164361039f.7.1725260696807;
        Mon, 02 Sep 2024 00:04:56 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-82a1a20d7absi36647939f.0.2024.09.02.00.04.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 02 Sep 2024 00:04:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: 9GTd3TuDQviNwS2z3DkHtQ==
X-CSE-MsgGUID: qpdlUcqLRV2GawkjCqzd+Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11182"; a="27700727"
X-IronPort-AV: E=Sophos;i="6.10,195,1719903600"; 
   d="scan'208";a="27700727"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Sep 2024 00:04:54 -0700
X-CSE-ConnectionGUID: BDqcK7agRxycVS5VbiS37Q==
X-CSE-MsgGUID: G3EO38nrT/KlPlH0dbKovA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,195,1719903600"; 
   d="scan'208";a="101983814"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa001.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 02 Sep 2024 00:04:55 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 2 Sep 2024 00:04:53 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Mon, 2 Sep 2024 00:04:53 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.169)
 by edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Mon, 2 Sep 2024 00:04:53 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gQkhxZ/tgz7oV6/LnZPnVcCC1E+eb46EfVDHZ2QCYSXPCY5fIpAi2vPnFDRNFPQYiNjNqgFtWqdhgX3MGEVGBxrFiMF0YtHffLJKgfu/Gh8R9y5n6ggEBEebAe9FiW4lJfxRCVECBdw9XJtS7nJGT9hjDTPmunGPOptV68cxKw4oz9cNXQmwL1Kx8rrw8ngj83IOfEIQuwRkcUkSG4RlIhMtSYf3PDpY1K6G/yHd1lquqRTTs8JIWqVORvHUQHfyJH20D3IYnqZEuRbTs90MopGFPhZknRVblI8Wfp6MMARmaZhqsno3kn4MPgXE9XLtI1qUW0X+8s3X+tbAdbk2XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qYjB04hTZo4bV4IGws6sHbzQxOuvfbAhF5+G2mTqzDQ=;
 b=sRf3pdDN1Y4unMPa7lbFnDvETjmyyRHC2rsxkPBp5pwarsXjzDw2bjfsQMuro0SlxP2svKJcoCh+icWikAH8bTMtMw0zfvoYoAqoj4zC3VHghZwZEwH9QgnE3sxgftAQa1s3t74GBmYNZiC12F7XAA9dezkADNv1UwZa1mkiyAGz3vGHAalvqavW5DPdrCYXzYw3FRWCpsmMt5Rr1Oyqtq0oX0QoN5RMMcNWtTzhGqdFPE+K7Vjcr1Ute+vartziK4/vUhRTV7R9Lg/KTZDOdsNCfaDJct06eJ3gRSK8KNwbc5P3crMRaFJpNUsyRHuGBSsnu1mYIu0ZHs+lhqFS1Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DS0PR11MB7901.namprd11.prod.outlook.com (2603:10b6:8:f4::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7918.24; Mon, 2 Sep
 2024 07:04:52 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%6]) with mapi id 15.20.7918.024; Mon, 2 Sep 2024
 07:04:51 +0000
Date: Mon, 2 Sep 2024 15:04:37 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Danilo Krummrich <dakr@kernel.org>, "cl@linux.com" <cl@linux.com>,
	"penberg@kernel.org" <penberg@kernel.org>, "rientjes@google.com"
	<rientjes@google.com>, "iamjoonsoo.kim@lge.com" <iamjoonsoo.kim@lge.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"roman.gushchin@linux.dev" <roman.gushchin@linux.dev>, "42.hyeyoo@gmail.com"
	<42.hyeyoo@gmail.com>, "urezki@gmail.com" <urezki@gmail.com>,
	"hch@infradead.org" <hch@infradead.org>, "kees@kernel.org" <kees@kernel.org>,
	"ojeda@kernel.org" <ojeda@kernel.org>, "wedsonaf@gmail.com"
	<wedsonaf@gmail.com>, "mhocko@kernel.org" <mhocko@kernel.org>,
	"mpe@ellerman.id.au" <mpe@ellerman.id.au>, "chandan.babu@oracle.com"
	<chandan.babu@oracle.com>, "christian.koenig@amd.com"
	<christian.koenig@amd.com>, "maz@kernel.org" <maz@kernel.org>,
	"oliver.upton@linux.dev" <oliver.upton@linux.dev>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "rust-for-linux@vger.kernel.org"
	<rust-for-linux@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
Message-ID: <ZtVjhfITqhKJwqI2@feng-clx.sh.intel.com>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz>
 <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae>
 <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
 <ZtUWmmXRo+pDMmDY@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZtUWmmXRo+pDMmDY@feng-clx.sh.intel.com>
X-ClientProxiedBy: SI1PR02CA0012.apcprd02.prod.outlook.com
 (2603:1096:4:1f7::8) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|DS0PR11MB7901:EE_
X-MS-Office365-Filtering-Correlation-Id: d95370a3-5f12-4244-375a-08dccb1d8a42
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?7PE6//t8RH4fJhomB1TynA6+ljTf7F70Ar6opzA0Sc+zhCsGJWabkLFM0ko6?=
 =?us-ascii?Q?WTLlCj0BLznr96xQEod/y0Lc2TxFFIDQ+RD2ZMD5Oo+P+VRIORV6pvhUhbTZ?=
 =?us-ascii?Q?oRLntqfCJGdfPe1zPDOB88TGdSlUoY4QZPVk+jkRCx/peLisiJY3JaDawnfZ?=
 =?us-ascii?Q?833b6CXHmnj68YWhDajrcRRrN+kwMwamKSoPrFMluEb3YgjHHkOd7lns4d9Z?=
 =?us-ascii?Q?aumQwqd+98NIlRi5woqdLs3hvgxV7R1Y/ve+zRKA5ZXnInjEY4q+sm+/IAbu?=
 =?us-ascii?Q?bTyu5qs9BBnjTs0899g+LfSbASK4IxCWzkvPaK7X2u44NALNtox+TcpGYzHg?=
 =?us-ascii?Q?8BuQbsvejwoldcsE9Z1gKNPTduMIEdSIupY9gP9jejsG0dVdM6+qhnYrvPv1?=
 =?us-ascii?Q?hqPYS1aKmqKXri4+PuEcMv1iNTj7MoUNe/V1tMDjsohHUiVh/EmfkmoG/96s?=
 =?us-ascii?Q?yZYfAwRT7sZvd1xL84hRwNCPLoPzd+z2P8WjD+1+48x5BFkaTm+ikor23Y6K?=
 =?us-ascii?Q?WqwroqNn+0JhqXpy2aLTEJMtxJxSkl5vD2zUN1t1mFZKSPTysEqATix9aBaE?=
 =?us-ascii?Q?VGkq/iR+jXIEoT37yLZ4e3d7PQG0NBxW9NfdXu7Zeiyfv8RdQR0Xq76PuWG9?=
 =?us-ascii?Q?zKqxGsVQpSn3Eoqq0QTxvMK7HfOj0uAXmBVCr4kn08vKsdnTHSNYk+VTP2S7?=
 =?us-ascii?Q?oHNeHmhefkFSzOoNX8r1XGR6It0QgQQ/3XQ/Q19d9iCCSmCz0Bh33RGX31t8?=
 =?us-ascii?Q?zjh6+aYBkqTP/ffcg8snfExwSiAirv3Hi7eVM0tw/EVO71ajz48v5giKaRxU?=
 =?us-ascii?Q?ne3PaJtDjjz4zR8ObB2qKLpUE7qb9OkQahkbeJuwfCYHZ0O3VfzaM42zK+xY?=
 =?us-ascii?Q?8XnpSG7L4RhsM7grO+A2jk8ENbeP9mMaUeoPtEggDfvRtnxeKxO3bBo3WfUE?=
 =?us-ascii?Q?zaXtAI5lMd9MAiBISQ6eePE/7J20m1aPoBkMwPSmzT8Q6okX0bbVCwiYRfYT?=
 =?us-ascii?Q?BsY2KvmVUN4RsnHQcZgXh+hnVbIt7XjJqN7g/K3fYkCzp8QmqChc/00goH9+?=
 =?us-ascii?Q?ncLgqdhjA86Nko7jw7IoGZ6zSJ6BT3OhiQ3CLlJ3P6hg2xS0KnfYX2kOv+AF?=
 =?us-ascii?Q?udlEKfm0Zdyxv1h9TuvQznzns6LEJDtwsZuqxKCbtfH1DoiNbWpcQ9BkiShe?=
 =?us-ascii?Q?ybRi4wLcqGVS7mhd1w+arFKoFeUBhrvNNiEIek5+vCbHEAiVH8H4F3GP2+Fa?=
 =?us-ascii?Q?ez4wCiKUtL4AqEAcYl9XxqY8ULVRLxQvLjE5Jx4MyutseSBU/Rx7t6Z4sIwW?=
 =?us-ascii?Q?y2xLho0NQhkOehwKhdENcUtCAon0Pe48L+HGu5UreY/1FQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KKe7ylRd3duvoDZUHCk6p0xZEyvfFPtTkVsA+OebJAGKVnwHmuOQoxz/Uvxw?=
 =?us-ascii?Q?0eeVQGoXX37CMQC9gLsTtVEs7ALzsOaJSuQtX67L1AVqAA6nOVdaaXSCrPkZ?=
 =?us-ascii?Q?H9R/zPYo0ucXNnqIy8ZyCAk+9XPvvHGopPwB8JShQ1BvwlL3AVA2GDhuE90R?=
 =?us-ascii?Q?3m6HgieCEL+jbBRu9Vd8yMWAqhJfdsPevDFB1ODTuhUz/K7vEnyHyaVapgXO?=
 =?us-ascii?Q?5sSkfdu5xIGgnjESVPxFBepfF4dLPllND34GW++PO7LRItDuNivgPfGHIJ6t?=
 =?us-ascii?Q?rI0huAIdfwj+LEj22aG2etv2Sy7ovNtAj3C8C7jZG9QFOoP5wN4DX4SOF0jT?=
 =?us-ascii?Q?o1NBoOhB+bcuZwnOX46S3rUhuvM7IaT1Dgo8RbGOZ/mXzbjImuux6VPqPH0T?=
 =?us-ascii?Q?bRa+fK5MSOXKXTLHnwGlGM6rqDZzLnYDBd2LzLlwCCpVTv7GcbCF9WBZkGOt?=
 =?us-ascii?Q?0Qw/lR62aPSLscBsCNk3w85kL7WJcAYqi23ybxW2wJDAcdVastn9ehvR/aYD?=
 =?us-ascii?Q?Uw4s19E8dJBnswKLEFVaBagqGUZRm/IS8F1dFbHAGUUBuDRnkzCjUgLISNuZ?=
 =?us-ascii?Q?Y/8xk41ck1RmOX2PbH7N00Z9k6dSSz8ETFYtT5QSKDN5spQxKpkUUwhH5F+b?=
 =?us-ascii?Q?YgEGL7iFT5nPfdWEuQ42dRzC72S10wb2CyzDrrmBPxUgF1Fhe/xKnEPYj8+o?=
 =?us-ascii?Q?gXbp32ZGrqgQ8QMG2CaydWp+tVURn3DNmpb0EYa4YuJ+YpxNVMAi7Zs/isBO?=
 =?us-ascii?Q?nDMlCuoKqbfibCBF2zypPyaSjMLAfA0GqaqmtltAXYG3YVXi4WtpKKmeHd10?=
 =?us-ascii?Q?wUmCkd2BWwJ55Ye+4jyfbVpwmt8cykn5j8PqsTVZXZ7J1/+Rhj5WdUKSdlLu?=
 =?us-ascii?Q?jZ5V77mvR3WAMTlz04lmquTMvn2EOvL1LEVE3OkRfowqWmbGuzHi0K0ezisV?=
 =?us-ascii?Q?NIp1JuRZnPmnsa1OvkO7cHYFU6t9fuw0CqDfkUF0dRM8T+xOZAZWC5iDL4UY?=
 =?us-ascii?Q?BaMwjBMghKRn8YfI23Bj7o5lWNpCSDbsjuLoGD/UfAP/CCssPTWO8L/GKIxq?=
 =?us-ascii?Q?j7NbFIjIz0B7VVxKQPciCSgLhmlL8TDqYoNZchmTy0AojDVZVnde5D4HQk/N?=
 =?us-ascii?Q?XTAdxiZ/FHspsijtVsNv98z1xGN53CkExUFQUMcpbbwV+6vGnIkHY+9Nq/yW?=
 =?us-ascii?Q?uzkEDGjLKFMLiJu24eOuuMWXfco6DIDyLAxYHTJG3uXzuBFbBizRX2JgUbPn?=
 =?us-ascii?Q?/MII/qtnSlVzSVMBazHzcRD9eneP7RN9QQW+CciBw5jMpNKtJn6vAyxBEjNY?=
 =?us-ascii?Q?4sp1v1q5k2ttSKKW+HsebFL3s9UFDilrqmpgpCj1oVzGEtKGDhQHcGLueBt1?=
 =?us-ascii?Q?ssNxjVVp6KrN4ymMdGxjoucI1qOtKADIPa1SW2HfNyLpb3sxjfhGZXIJA9tK?=
 =?us-ascii?Q?ZEXpb2sS9UwW9eLKdoNBdiVfip8wZCjcbp0/cBq19G069vSfhndUwEoIm3cG?=
 =?us-ascii?Q?kPJwdbJVvb8288oYoo1nmdUcX5Ul+oO3Ds90DVaq8cm0k8jZmsICSlVte7/2?=
 =?us-ascii?Q?taOeXA8ZiVmleV9OR1I0Q/inTgAw6iYt70i19JAd?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d95370a3-5f12-4244-375a-08dccb1d8a42
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Sep 2024 07:04:51.7342
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5kQycSVhv4IpQh5arn2z9/vHD4xbI4meHN1PiYw3pVX7bSwh1uxtaEzIGgonhT+p/dJpKERuKHMg3LgAI6/AfA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB7901
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HQktbILb;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.198.163.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Sep 02, 2024 at 09:36:26AM +0800, Tang, Feng wrote:
> On Tue, Jul 30, 2024 at 08:15:34PM +0800, Vlastimil Babka wrote:
> > On 7/30/24 3:35 AM, Danilo Krummrich wrote:
[...]
> > 
> > Let's say we kmalloc(56, __GFP_ZERO), we get an object from kmalloc-64
> > cache. Since commit 946fa0dbf2d89 ("mm/slub: extend redzone check to
> > extra allocated kmalloc space than requested") and preceding commits, if
> > slub_debug is enabled (red zoning or user tracking), only the 56 bytes
> > will be zeroed. The rest will be either unknown garbage, or redzone.
> 
> Yes.
> 
> > 
> > Then we might e.g. krealloc(120) and get a kmalloc-128 object and 64
> > bytes (result of ksize()) will be copied, including the garbage/redzone.
> > I think it's fixable because when we do this in slub_debug, we also
> > store the original size in the metadata, so we could read it back and
> > adjust how many bytes are copied.
> 
> krealloc() --> __do_krealloc() --> ksize()
> When ksize() is called, as we don't know what user will do with the
> extra space ([57, 64] here), the orig_size check will be unset by
> __ksize() calling skip_orig_size_check(). 
> 
> And if the newsize is bigger than the old 'ksize', the 'orig_size'
> will be correctly set for the newly allocated kmalloc object.
> 
> For the 'unstable' branch of -mm tree, which has all latest patches
> from Danilo, I run some basic test and it seems to be fine. 

when doing more test, I found one case matching Vlastimil's previous
concern, that if we kzalloc a small object, and then krealloc with
a slightly bigger size which can still reuse the kmalloc object,
some redzone will be preserved.

With test code like: 

	buf = kzalloc(36, GFP_KERNEL);
	memset(buf, 0xff, 36);

	buf = krealloc(buf, 48, GFP_KERNEL | __GFP_ZERO);

Data after kzalloc+memset :

	ffff88802189b040: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  
	ffff88802189b050: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  
	ffff88802189b060: ff ff ff ff cc cc cc cc cc cc cc cc cc cc cc cc  
	ffff88802189b070: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  

Data after krealloc:

	ffff88802189b040: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	ffff88802189b050: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
	ffff88802189b060: ff ff ff ff cc cc cc cc cc cc cc cc cc cc cc cc
	ffff88802189b070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

If we really want to make [37, 48] to be zeroed too, we can lift the
get_orig_size() from slub.c to slab_common.c and use it as the start
of zeroing in krealloc().

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZtVjhfITqhKJwqI2%40feng-clx.sh.intel.com.
