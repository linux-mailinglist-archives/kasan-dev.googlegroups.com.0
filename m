Return-Path: <kasan-dev+bncBCN77QHK3UIBBVO667CAMGQET2EAS4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id C673FB268D1
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 16:14:46 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-71d603c7e05sf15328567b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 07:14:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755180885; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZK3VQ/cq5rn2MJitHYJcQlZxVYSgHfwX/ds3tz5jM7mrIREXZ8Fr03Vh/VjHZp1sGU
         HFzey+5QXxe0lyeooTld+d7Hj+3eYmT+gbexH5pY9LHFIV41qlNRMz3mL2bARieY3+Ds
         e96nGb3I4H3drSKiu+MoPBurwuIJ8230sh2nXgDzz96SmAWVJdK6Wr/Z3aFWkKLarmCq
         mOVVMATjbmHa0hAJoFzv+mXNUXNYUON5vyWwFFerhXJdnEcX27r8Lh9kovnEQnXaekoZ
         i+/vi3giz0r2gmWFBL8pvF/QPr4KVf2k0aZrL+QRWQoPIQYpSn+qYAK7eZQowHRv5/+7
         owQQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ugx9TQspThe3dqJkVdd3zPujh7aUoRx1eTkdcRQxNus=;
        fh=IxrZbfdvtA55wVmeIia2R7ZksNpUcdRXJ6mLnwvGLEk=;
        b=Y+pyPWdlSPT0rSH/BgWvFWp3ovncXZqNEsHqpD9F4NMLBFvQfGyFv3kUPBDE3drPB1
         TyAuHKGkIyfY4zCi+ADLkgbNfgATSVygYXGq9YveEDM4IhuJwbcar1OYheFhKVuwLaRp
         NRYYYcJFOMNxW0wZM6Of3tK3Y1HB9osq5awJMrHtMsYI1SEwSX8n7Cmoiuc4TfV1UG/U
         0t1ZdR93qgLt0eCmjlB0Q6AP/qmzydoVOf0YktpVe+eNX8EFp+NWFYBMPCV/Qunwlpzv
         ZluO/wVtzYs+tgmDWOndGrRIqt/wSeAcvkdWMvQkhb0lY+sNlAONHqLbTdQEGuY549BZ
         gLlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=EiAYv4Ep;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2406::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755180885; x=1755785685; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ugx9TQspThe3dqJkVdd3zPujh7aUoRx1eTkdcRQxNus=;
        b=qtxPAheoP2Kn4wq5wu6mY6epKq1JOwGwo9iRzKanKgg8AaU8xAquwVp9NL974ZqP2S
         kDQN4peS0V2tqNCnjO7oqd0NVe+Pj0oyYfHdu7/CfzlHzHEljGWq6AOqE1eti8+n589O
         nDoZmbp9Tuv9gqXW4ZkPlLycJ2IvS383kD1pJcTpPAyI6OgpQLo+IyyWZI9qs/4mOZzo
         1qAmRd9wVT9IhnCe2+gd7LZcXsM8Exzd/kR5cC1gX5u5euNQ9xzccnhdABF1nxLDnBuJ
         Y2YH03VVvOs/Eonc3rVqbdkcJavg6JEXczqp3FqO5/QW5hiYaBNsFpsq6oV9prwXLK28
         6IWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755180885; x=1755785685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ugx9TQspThe3dqJkVdd3zPujh7aUoRx1eTkdcRQxNus=;
        b=q3XN4gCR5SN+wpaid7pYdzap/qmNuy1pfKowDCJauuOy5y8yGH5OCREFfxNStGBU8J
         2CcZVkjCypXzTLGfPdCqH2gqNVEVwBCBIUniNXiP9Akwd3R0vwYZquAa8cd+wqWawnUB
         FpF7JWU9URquuitV578q5gnvCdrE6pScyIYvm/zsf7IYOonAmzZQfD+zwuN6A90Oy0LV
         U9oS3odr53uqlbVkbTmzSvHdSOcj32gDVtV2LpiS+WsYk1wgoH1DP1HbLOvdy9EpGiPU
         HSD29JPvyKC3m43ouFShDXEIL91KsbsKyzmNp0B3vYiieRJhDqzCdyJN8gaGoZD6nSZo
         ORAg==
X-Forwarded-Encrypted: i=3; AJvYcCXrHfdIeukEBExzwDslg+nsrg2Kvb2gT3lI1WIWfgxKzoE0c9+sM24kv+daJJE31RT9rbKJVg==@lfdr.de
X-Gm-Message-State: AOJu0Yy+7lbIs5xoBI6UsI4mfYFe50yftbAUIfoFPCR6cRLoMg6lhPql
	8lzKWOSBXBnZCEI1UIOv90Qd1DdT5ABJO2h65QB8A2hJTcmGIJgedoVw
X-Google-Smtp-Source: AGHT+IEmhc505i1yHyoqfDXIyTZG8P07hajEa2Mt5hApeCj4juev+z6orOe17q2wdqEUVHFBrRXgOw==
X-Received: by 2002:a05:6902:4085:b0:e90:8a48:c3e8 with SMTP id 3f1490d57ef6-e931e2b2df5mr3276977276.48.1755180885410;
        Thu, 14 Aug 2025 07:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdl3VUJhWDi5UuuLVWORX3DgaWgdKBA7B9X4bI9Uq9gpg==
Received: by 2002:a25:d8d1:0:b0:e90:6611:9e1a with SMTP id 3f1490d57ef6-e931ceb509als1059182276.2.-pod-prod-04-us;
 Thu, 14 Aug 2025 07:14:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUl1HhPAZQCOsYIT1ZRYql6hIrZ03JjMhUQI6mClj63iwuVk4DrFMVZEGsFcRSdNbLU4yZ/JprGW4w=@googlegroups.com
X-Received: by 2002:a05:6902:1881:b0:e93:29f5:6f47 with SMTP id 3f1490d57ef6-e9329f57055mr805857276.44.1755180884440;
        Thu, 14 Aug 2025 07:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755180884; cv=pass;
        d=google.com; s=arc-20240605;
        b=aAhpO3c6Nl7eyTGoqKec7KhZ3KlVqoaCz2QvvtQLJL5pcmyOE89QZZkcoPEFr52eLE
         OlKc6o3o40lSRcV35WFIQY0f5jEZz2VrdhvMoXDLHEtXtMH85ITg5t2ACJTl1rpWTh0W
         KoKHvJcy7x2sgHGZravjatf7bQMXbiWDX5X3fA4i6IQIYj1Hof6NQO1c27YkBJblAO9F
         crSLm6Ie1RISLdIzVoHhzd+gCCCVmZhgeTORHcWSabqB4vp8+nwOm1RJgb4zJz9s7rC1
         zHw7UQtBSGM/vEh2ZQlblM2fBaD1iilQe0gm0/97tLXQBVjyKvcFi59aNZxBt9fog4zo
         fkxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ruO6zNzO4KB71Lkb6cSwWsEi4wP8AIx5i5wd80Kfkcs=;
        fh=7UGQiPUstHBdMrT+/gotlrsKf2dFOYLPDzCPmdRVN7g=;
        b=h8rfLGbtS6l3Fib+CQnJu5O1lWTLaX+9POt6x6UiMDaM0LA2Vw4ASw6ldyuWr3L4FE
         hlKpVsCkGEUmY7V2o/ICdK6xxHTLHpRtWBH5nESkzNuFLXWgZ3IC7SVc5pvDwN10+D7T
         yMfmIV2Y6pW4CS766S73YSTYYFlYUuhBZmA+h4KQnkSBFVTmBSiHoZZpPID2QixM5o1Q
         n6pZVXAKiDJm4IIS42NCqgGfJJLRFUadiD7LrjlXXH9+ixANRbhJlpEwCW2obqLUeIbJ
         0hE/KPgGaqt+uWFvoyNiN0pvbLhvY1WWo2wDGWKtySEoifiyACowxvkuvTtu9feqd0l8
         azqw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=EiAYv4Ep;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2406::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-SN1-obe.outbound.protection.outlook.com (mail-sn1nam02on20608.outbound.protection.outlook.com. [2a01:111:f403:2406::608])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e931d40ee1esi108608276.1.2025.08.14.07.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Aug 2025 07:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2406::608 as permitted sender) client-ip=2a01:111:f403:2406::608;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=GU/BvIQz3DTXmYOdGLkh+HDcnJ9GH6Ik0rR2UlhlkjgtsQw8N4vsmdx5kcxRf1WgiDTFsBFEFGCSOko8OFp8bcXwF0hLK8E2XfhX0cfhH5I7AKTc8bfK1oCZNB8hOUrPCxA7JqoaNyFbWZOU4PSR5v5zcdbb4Pi6IAJqPlmwtwt5n+8ppswVwPBEj5hbML3avj0BGinez1mF0WlYA/xUIcuC+4Yz/6i7lBq+K4ELNOTPkl/WJwqYJChB1021V9OXylSalQvRZo5fOoOymQUM9CxZOWx/1sXx2apLf+xlqGlUEg5dgzC29XiWSlL4YTx3cGe4DCq4i9yO3m3emvrROw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ruO6zNzO4KB71Lkb6cSwWsEi4wP8AIx5i5wd80Kfkcs=;
 b=yxXRDrAQc+7mUCPP3py13VkcS1bDJC/YtuPGqof3Dbi6jopCxGFfEmfXcscFobyNUqwyETyivD//2ExukT43zMU8DPwYweB66AXZvSW7ljhlr0o2/vukDatbk8XWea1IGCog2XUGb965zuON7Oi1oFRqgR/e5OGcC3T/24M3R2Jr8zGu7JUkfEmu/hSPmdnVDr1nrxc6Sv6eno/kHxyPD1iRzFQge7UqXIVIztrZq1sa2bpY5GJnhkzCLe3nTqMbnQxdBuWrjLPMcZpoJAQ+lzldYMFFiqton8T/2g+c7RazWm2M8DRfrfjZtFQlr8XAR0JE5uKUGS8qMHAMaeuh1w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by MN2PR12MB4111.namprd12.prod.outlook.com (2603:10b6:208:1de::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.16; Thu, 14 Aug
 2025 14:14:38 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9031.012; Thu, 14 Aug 2025
 14:14:38 +0000
Date: Thu, 14 Aug 2025 11:14:37 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250814141437.GH802098@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
 <20250813150718.GB310013@unreal>
 <20250814121316.GC699432@nvidia.com>
 <20250814123506.GD310013@unreal>
 <20250814124448.GE699432@nvidia.com>
 <20250814133106.GE310013@unreal>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250814133106.GE310013@unreal>
X-ClientProxiedBy: BL0PR02CA0137.namprd02.prod.outlook.com
 (2603:10b6:208:35::42) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|MN2PR12MB4111:EE_
X-MS-Office365-Filtering-Correlation-Id: 6e3ba93d-4319-4e2a-c39d-08dddb3ce778
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?WgfRGDEKKHuNso3gGtoTuh6waQ9PCACwW3Xer9wmxp9cTa3pI6GwFYV/fJwL?=
 =?us-ascii?Q?uMkVfKCSxkLu46+hc29ievexAGINSRbhu7JYwTU0XfwC3xuq+YaufFGnn3Vn?=
 =?us-ascii?Q?cpMOGqWuXDbpmMy1LmmxLX4aDD9c/RqOmAZJpv5mfDHm2clHXS4UgOzngTmD?=
 =?us-ascii?Q?pbnofH4YtXT0ZgTGt6BiOFvtENoyZJKCby7Mjhgffi7jeZkXgNkkuF7vGmDh?=
 =?us-ascii?Q?khvbdocQDP08VF8PzLtV9eIf8x5rWeQfu6y+bnEf80Xy+CimU6ZVs1mHDn8M?=
 =?us-ascii?Q?Va20NUjK0kGA2V9cveBWcp/bdylGfAuil7IpGcakYsc2DunpQ+m0adkeTAZu?=
 =?us-ascii?Q?pt97X1t1VXWEBN7qg11nJjbx87HF0c35kmDZeoane30eKI1Bwgqzk4KxsN0k?=
 =?us-ascii?Q?z2GHRAf+JSgcqz0hbOjiQq+F9anqyTVIQdz+aJh1ukalLlr/564G3PicNHbt?=
 =?us-ascii?Q?LPr49wr+78ylFSDEfISFwIgF+JSVYmhqvuofMjkbjsA2VuQjCYrOBrsJSYKf?=
 =?us-ascii?Q?wMjG6p7RvK/pfthf9CtYkKkCAiTp8ebvlOWY8iJxJxT8mucsIvDTNZU4NkDb?=
 =?us-ascii?Q?v0z/o73VHfPBC27fiQ7o+HO5EAktvti/ZcKDRf08rN7aiM8orpyNVQjVcAE5?=
 =?us-ascii?Q?VqHSsE83Ap2qOC4Wx7MWNvrlIahR76FdEunsArmKGx+5oAodiWNfvS0YGRN2?=
 =?us-ascii?Q?VrwJ3wryf4khSFgTIn+gN6nhx0u6l5XkEYHm7FDjqJl4vRLw4hASIP8RPhdg?=
 =?us-ascii?Q?FUVWaoCQo/loIiSItLdVI/vuuhQeMh4Pd3UBiEK+RdifW819zm9snPMqmXPd?=
 =?us-ascii?Q?yzLK5bGg6d9o7ql2oRHHkDSuSxqkaRfTpIPOj+3Ik6+IdkEH819IP0T984MB?=
 =?us-ascii?Q?GERjJw8I3qTw4+P9ABEaHpJZMCGPKunnLkCiBknbFemf3qrgbnlF4PYGUlEf?=
 =?us-ascii?Q?R9s9oEj6fb7pdgt3Z7D/tAq4XuVinG6vE9c0bI6Oie9pipyRh4zv9StX+RUC?=
 =?us-ascii?Q?RGoziCckT/sAPKLn5kmwdLJ2Bkrg6FP8q2mAIgX3tkXxcQyI5/yb17j9TwAC?=
 =?us-ascii?Q?lpzSIu+TbmEYvn8q5IdYZyx5DES0g/s71DK8Ti7Ec6jOzGc6oio27eoJysym?=
 =?us-ascii?Q?nGN83B0XBGN+5RqszR5hWf9HIdGLIWbj5T/HjUYiuiv9XOsIw9JalLguZMxu?=
 =?us-ascii?Q?Hf0Ft6F9d+Wvak/bdzCaK099hIAZdCOQOMhLaduD5CPwfLnd28P1Bhq7q0oy?=
 =?us-ascii?Q?zB5CNRS3xpulZ+kuvwZqEWJlgn3X7IkhLKPVXqqsSy7EdOFAsB5mpKbBM6jY?=
 =?us-ascii?Q?xXn942Pbh5gEZhdr6pQyBJvhkJWKgRDJ2qcsJ9lk/aMqe9n2ldHihoCyfuvk?=
 =?us-ascii?Q?LbSAMpXbaPP9O8ofI1/42MZWsfBTk9ZAceTNxZbfU7nYlIeRaEzyLAZLLkDf?=
 =?us-ascii?Q?PugFFIpY5EA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Ms6U7vBXPCNXfF0GBhVl67iuvMBy5svsyOMzkXNcqhzlYf1dmYfKq2Nmij66?=
 =?us-ascii?Q?OVFGvrCOTzbOh059BMs8Tv9pRrZyWfT6AoFkl6pqlLn1AwuNLIUBcjypj9Si?=
 =?us-ascii?Q?DisYDAzEuEmEY8ycUcNzX50mNwZqWctD3qkLmCe6DfDlcBmbBuzMI+ce+KUB?=
 =?us-ascii?Q?6B2e7Wgunr8p4yJYBk5XBHGix/CkyA6NI+7rhX+6KxvyJcboBaP7kGqSLNmq?=
 =?us-ascii?Q?+KxNz7lYKeI2HFVQ8imPYyMAANP6ep7ViJxkO7OUDseBi9qt/ce7kSCoalyF?=
 =?us-ascii?Q?wo/ef9acXkJMbu5DDF0AXieNFw7wQYWAjfko1OFeF1fe/cQw0JoTSj5MZzhm?=
 =?us-ascii?Q?LxPUPWHGEPd9ipfz3oTPSl5tb1ts4zqUOGB4W7PRmEsS1PQryPt1Auy+kCoo?=
 =?us-ascii?Q?x5HrqWo3yCR6xYlpJ2CKzWgAzDzJFjn3lA4RRzZW/5Rmja+E8m57KY2u1CPX?=
 =?us-ascii?Q?w00gf6QzDLL6kxLCEUGqHWvYlhF+TAVPT45UaBUe7+zAvpXZJWT4qK3BB+fu?=
 =?us-ascii?Q?nsiuwGIKa+U+yHvfI/3QxGP1J5OWvjcX1f8OmTtQxj7heNGEf2nYwiVKqRwA?=
 =?us-ascii?Q?zFpBrMRMlp4V2p+m7y4272Rvs+6mXdf35v1RIb1GwREMyrZXXTTEKFc/qesT?=
 =?us-ascii?Q?/eyXLujUQ7citeil4d8XUsdbwnea7L8Ng5Lj35chGwPoAAU73YMaupxQ4DJV?=
 =?us-ascii?Q?sDA3RpAfP+C/qKCvYjs+uDSQfg19c9GPIvAzL2mB5choh3ThGojNaTxt21wz?=
 =?us-ascii?Q?2OWWSQbqxheAY2Ie/XZUrM+fulMsQgneFpJfX1uCK3BYY3REG8qiHcYQcIDv?=
 =?us-ascii?Q?Mp/HyTJ+r5eeOqgN3rwUK2nEKoSXN6xcSN1K9PWZvCVVXw4D3bNH7L6s0+s9?=
 =?us-ascii?Q?wkySC5pM60VQHd8f/+hCv+tlHvaP2MPRTKmhKAkbobGb4WhBzQqSYZA7TY73?=
 =?us-ascii?Q?yukjLnK/vX0ZRyl/TVGMVuZ2lSdjNfFhBIQ7MG9eZi1o3TLQ4QDCFlR+ZiYT?=
 =?us-ascii?Q?Dfnv3T2LSKCksXjW69M239HzwkibI36EpyYyjfzZLrrnBWMQbRVqNKj4oA56?=
 =?us-ascii?Q?EYklt+EqszRlpS/LmjnVgif78n3Eb3RdRH8bYqx7oLD5mr01Hd6hGMo1fkhw?=
 =?us-ascii?Q?ALOjdVyv93NltYqgqO/AWdryKewXkFSpcQUI8SbO4EAlSL57X/PVnw3ixwyE?=
 =?us-ascii?Q?VnAcBOD10mUTQ4fztbJXcAmZWihBN+Dm1OKQmzHrXrOPblHtKgpos4Hcijne?=
 =?us-ascii?Q?yGBu3B1ET17jPIbAMJ/YiMb0MS6Ajq4RYxkfYfklDymLw4v697LNdTEA/e8T?=
 =?us-ascii?Q?S61phmSvM8ieJ7/mxeLujIRjQ+wkqDdszaaxQaOHVb9X/kh5Bzhcg3E1d+Yt?=
 =?us-ascii?Q?vmZ0WOYbT7opDnmYKQryUIbKXFxeYevn7YRSnKElJmwTNScKbhq8DcsdNnkl?=
 =?us-ascii?Q?exe1kSYhiadVK8Va5w7vBTB2ics02mUjfwdQQf2YkuOBJUcaaJFjCoPnyw/9?=
 =?us-ascii?Q?ZZgPIjMlMGxv5RQJU1oOs/y+Q35UxqyCbBx7IXQBVCRn464QWGHBBiSMnUCU?=
 =?us-ascii?Q?Wej8KLKb55TFSByZORY=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6e3ba93d-4319-4e2a-c39d-08dddb3ce778
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Aug 2025 14:14:38.6057
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7kxcnpRJdzkjJSknvpZS0FJdfGyvwWOi0/OrxCvD+JZOt7jnM+9F/HzOjYt2sbRA
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR12MB4111
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=EiAYv4Ep;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2406::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 14, 2025 at 04:31:06PM +0300, Leon Romanovsky wrote:
> On Thu, Aug 14, 2025 at 09:44:48AM -0300, Jason Gunthorpe wrote:
> > On Thu, Aug 14, 2025 at 03:35:06PM +0300, Leon Romanovsky wrote:
> > > > Then check attrs here, not pfn_valid.
> > > 
> > > attrs are not available in kmsan_handle_dma(). I can add it if you prefer.
> > 
> > That makes more sense to the overall design. The comments I gave
> > before were driving at a promise to never try to touch a struct page
> > for ATTR_MMIO and think this should be comphrensive to never touching
> > a struct page even if pfnvalid.
> > 
> > > > > So let's keep this patch as is.
> > > > 
> > > > Still need to fix the remarks you clipped, do not check PageHighMem
> > > > just call kmap_local_pfn(). All thie PageHighMem stuff is new to this
> > > > patch and should not be here, it is the wrong way to use highmem.
> > > 
> > > Sure, thanks
> > 
> > I am wondering if there is some reason it was written like this in the
> > first place. Maybe we can't even do kmap here.. So perhaps if there is
> > not a strong reason to change it just continue to check pagehighmem
> > and fail.
> > 
> > if (!(attrs & ATTR_MMIO) && PageHighMem(phys_to_page(phys)))
> >    return;
> 
> Does this version good enough? There is no need to call to
> kmap_local_pfn() if we prevent PageHighMem pages.

Why make the rest of the changes though, isn't it just:

        if (PageHighMem(page))
                return;

Becomes:

        if (attrs & ATTR_MMIO))
                return;

	page = phys_to_page(phys);
	if (PageHighMem(page))
                 return;

Leave the rest as is?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814141437.GH802098%40nvidia.com.
