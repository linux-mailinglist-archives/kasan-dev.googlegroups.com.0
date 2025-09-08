Return-Path: <kasan-dev+bncBCN77QHK3UIBBL577PCQMGQEDQPLY2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 881EEB4904D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:52:49 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-401eba8efecsf24211715ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:52:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757339568; cv=pass;
        d=google.com; s=arc-20240605;
        b=cdpRIaH1r8Qz0Erg3aLOJCSbM8axDTk3F0FX0qFs4Kv9hTy2NaNAHA7RnF4XHwlBnV
         +WRjRq1rU1bUlyjMa2Q4UETK+p2z+Rb1Wog7hokkzizw7JYj5ayJKcFzxbFWaXgNd5KP
         LpxQpfqYmrEFS7xheeFUeJZ9n1EapbuUVYNuvTIJyMhPKHPyLylOhscYUZtI/zbqdy8+
         OqG4F3tlaLxnpj4Y3ubb+2L1AD8zjuDSmvcedlRjx5veRvhIfv5mSrBvnI8vBClBFUsg
         3XiZ93jfo6hibdfwAx8Lqruh87r/rx9zJeKhRxhj13784oYAyhwHkAsk9/GaTHb87SZq
         Wgqg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=U0lsNZXMkxojBWgTizoroxZQlhb4ECmt6xTc0k3c03s=;
        fh=cYsVHCLd05BBFLbGCW7bVN41q/RfsQjxOS63bMrofME=;
        b=TlKMYpVrTcKfJDeNzIDUteAyf4IBS3b/OVnx9jHvlXg3bymUD8FZrnb+65XYtRLs8j
         G1LSPJ0jPoUGAsXZ0Rq+Wg0/ePmbsLWnbEmeI2C9ngn1BQFuXgFBYtDFyJ3/Xzlh286w
         HMjUnWsq34/meKgUDclrs16gPGdNdJ2OGo2eEDHOliQe9Q7DUav7hzWxPpcYmxQEJvgX
         qgJ8QoKZwV+O+iEXrNWaD3AS3IsSF+4qy7upvR/ag8+LBxmenWBtMVw8r8cU+HYtg/Qz
         5cGmoO8TrnCGkNjktAeja5WGCHfc9rZrONgz1SxdT26eldwh0BHOugi8CCQiNQHk74qL
         ynSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="mVi/3e4b";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757339568; x=1757944368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=U0lsNZXMkxojBWgTizoroxZQlhb4ECmt6xTc0k3c03s=;
        b=FNtwJ4j8ovhZbnYDxwax6UxE/3Rn72kA32M9lPVeIBgusnrmO+9kHwIM92fWv/aKmL
         RQrnFkyBFebQ8foP8xCxpwd4apKvUITixN+fXD7+Y3e/jqVuK6WDNBvmzIz+YkIJVrWM
         YgfCCSWn6WTMrn0mmcGgXy5dyLNWsErmX817BucK74872Mp/XaCBeboRege2BlavRRkZ
         wpxdWS0hRkU5cskjfLCnHoW+ynx3voLFWcXH/gyFVKy189qu1b0tHgxquZsXPFYDN7sF
         lw6k8CdqwsRildmrAtowK8npsm/O6uhHKkCD8w2zMdjwuazbkcgsXHAaHgJvC7hQ+e0D
         il2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757339568; x=1757944368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=U0lsNZXMkxojBWgTizoroxZQlhb4ECmt6xTc0k3c03s=;
        b=fP1mZIZGPaLPWGHorE6YiOjIfPWgv4uQ+gSl24tpWESQHbYliO1RZiil2+6ucQ9hnf
         q7BZd80ldB4xn+PgovgctQZNHEqmgc2+4whSgIn2QDtnJb98hOKJv3ZLSJhNAMviakQy
         LcTmx7i+y6OEu0UDRbArpT+wkfuLMcsjLtLev/E73YaovOWCpPT8usRxIm7wX6jJQf0n
         sGZmRP5so1O5rihjb25aZ1jdnf1vU1NSwY3VAHV4/Id7B1N71fFVQDUMnhcgkqkKthP/
         JoBGQ2lgMJIU0emkQ0yfoYTxCFzbTPgx/LS/ohaTrIK2XimFoJQMBqh7Xx8I2eeM0w1N
         sFBQ==
X-Forwarded-Encrypted: i=3; AJvYcCXqFMnnwqx/FMAG3aomCoE46IFxl03L28VK/kjAPd9HHoTY03YoEOX94cGNajjUgLQeuZsWjQ==@lfdr.de
X-Gm-Message-State: AOJu0YwFgVW40qmFSo9RIIZ6nsITmzHTsI0E1zMa5KwWt5XZQX4nGZSJ
	cSSBbyHf7PZFQbp7rBFgBvsR5p+pSo9Wbw1RJ9wNOGwUkjrd+66iIrOX
X-Google-Smtp-Source: AGHT+IFwyK8I+sTnZhoQSzlm6ANF3TCgNdoRAJSWHyQ5tec/CMgqJWy7t08Ursv9Mi8mKG50Gck2vg==
X-Received: by 2002:a05:6e02:2592:b0:404:e727:e52f with SMTP id e9e14a558f8ab-404e727e712mr82018615ab.10.1757339568068;
        Mon, 08 Sep 2025 06:52:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf5L2h1tmILZRWuQCb7COOAwMbp8SnAUUibZLqBp5W1xA==
Received: by 2002:a05:6e02:338e:b0:3ef:b6a3:cccd with SMTP id
 e9e14a558f8ab-401fd5d9cfbls11683575ab.0.-pod-prod-00-us-canary; Mon, 08 Sep
 2025 06:52:46 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW33K7URsi33Ky2gwyYlKW9qLqHCk/S+doT6lvZE1yXRjibBg7ffP7H4JLSeRA5DY2M1bGwbKdtgc8=@googlegroups.com
X-Received: by 2002:a05:6602:25da:b0:887:55d0:c208 with SMTP id ca18e2360f4ac-88767ebee4amr1642405039f.8.1757339566219;
        Mon, 08 Sep 2025 06:52:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757339566; cv=pass;
        d=google.com; s=arc-20240605;
        b=XtOV+XblLi6eAqK2UNjzXsHjEJPBhzEuKGGQCUtKdPF5rJXx7hL7QNjnewXul83uh/
         CATq4IZVnfw6B578O/uvpfIpw/hba7V+Q8dqCpwEeg3Dqrc0VoiK856rXI0Lhvm+G14n
         Qr8wiP2xXuxfO0dR3MNff0GNyMZnipWGVoFBUM7bHaJTl4sF9hVTKLkjVreNad1wuX1Y
         m//EKwyolh2fEAO0KE1EIrYHXVerra+SNxeBvyua8dI8m0JDufRlTcln5Ky6hZqzTfGM
         CmLQ26vAws3mZ0CjJmh05K4J4qjrXHMAFlQSj+L+6dMm9yVd+yWaVnK8UgV0cpSGbIFK
         okjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=df4NlJyJauiFtLXcc8Vk+3gANJIS+U/2yuXaR0+ipX8=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=NY6dmw+OZSuv5nCfBAp9EnSaFpcFu5zRhcCc5SeiAskYWgy6rCKLBxA+oboHs/lNVX
         mbLnbXbLFGI/MLQMQZIl0hFXxuq7xyxrnbS+3AUnrZRbjUSzhW9UAZYDquB5L3fdR/EF
         UuJ1RUY/KBR5ImcMhcdq2WXv4kA5fVYsHcbMhlMJJWaws8b0oyb8j0XFxPKPRONm1xJx
         RkZ8bX0PFOb8vsRYCVcSXfoMzxfDWL2WsV1Aee6yIxZ6VCQtTLBrkGnO25uA1rBl82L/
         YQzYxs7txtzRKEINk3mbVoIY202DDlIbqcNoTd2oHrcErTpADeWDMhBXkscz/yaKGndh
         3gwQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="mVi/3e4b";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20611.outbound.protection.outlook.com. [2a01:111:f403:200a::611])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-88c36ba10edsi3472139f.0.2025.09.08.06.52.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:52:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) client-ip=2a01:111:f403:200a::611;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RsXO2GFgHD2lkb4JGiHzutntPglYlu97kmjE10YwuAfoqVkcb3bFeqaY6kcA3kZCJslOzWGBvUCWFCCrxmftEtASVSbTAbTo9PRD742Srt9qccxGlwPoWmFRV2ZJcDK9iFoPd2MzJUESPzwwev+haHJVk20LKlKm5d6hpaMBTnUmdCB2AWBZjsPGbVz58dXOZjcCeEaHpSOByBI4y2oHXppvnbsSRL6PudyCJIANc+EJ4iZy1HvOCVsjKrfVWZ9xpcNwxNkO/WYmSLTmyqB/OqOAIKpxBUQiQltVzQfoysmRlsFmEkeF17x4tpZgpNNUNTC3DTR++1p3LOV72rE7rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=df4NlJyJauiFtLXcc8Vk+3gANJIS+U/2yuXaR0+ipX8=;
 b=x2nCwVW2yucAjdq01uzRkc0kPGpnxKUJJYhm4Kr1n3ho8KYz5aMLMdLv5084n/n4Spf7Pjwj5IrHqgbJEegv+4BX4Id6qg2VFljeoaJuwVM2q/65NmvGiJv2oXH8MsKxZIjDg9wSXkaM9+cyDpmWzZIre8vaZMYqLTms8Nj80p6J5OHXwKzZqfyPFzxTlDjIYE4tI/Ij7EqezlV7E/Tpo70iazr/5skDuWYfCdYYpP9Qvl/HGK9R97mCwCDGJClVrJJJLh2MJdQaZoYbY41x8SSXt2LDNske/iCcRBIXRwHZeXQVVSadXaYWdchTKECjwjWLUH0PYafJj94/guqfzw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by BL3PR12MB6403.namprd12.prod.outlook.com (2603:10b6:208:3b3::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 13:52:42 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:52:42 +0000
Date: Mon, 8 Sep 2025 10:52:40 -0300
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
Subject: Re: [PATCH 10/16] mm/hugetlb: update hugetlbfs to use mmap_prepare,
 mmap_complete
Message-ID: <20250908135240.GI616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908131121.GA616306@nvidia.com>
 <f81fe6d4-43d2-461d-81b9-032a590f5b22@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f81fe6d4-43d2-461d-81b9-032a590f5b22@lucifer.local>
X-ClientProxiedBy: BL1P223CA0031.NAMP223.PROD.OUTLOOK.COM
 (2603:10b6:208:5b6::6) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|BL3PR12MB6403:EE_
X-MS-Office365-Filtering-Correlation-Id: 138b36b5-423c-4e7c-ad4f-08ddeedefb5d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?bjwSF03mWWQGBQV9xcVpderw4SUHy4KrCQQyv4kvXf8zoc1JlerE+znIxeYB?=
 =?us-ascii?Q?G4gBy3+/nMMHCFvi3b+4N0iGFHxl7Oz7o9/MINhG5BHf0omutbvV8FUhas6g?=
 =?us-ascii?Q?jnXeo53eEMW/Fggtrpn1lUcuDu/h1D063fghkqO3etroSEZQ8CanStKiEywr?=
 =?us-ascii?Q?HAlZMZB7La7woILl9rXp748RuFRwvph9cDfJUMkiVBRz5rktBbDNuOkCr1zn?=
 =?us-ascii?Q?RdYlSlUu3i9xt80fGTfS9uKVzkQv4XBvc8K+pXoJoX9wrnRlZbO73vhhxQDq?=
 =?us-ascii?Q?SAPIgeoivM9mEBJi5jU6EWw5UstzmUrAXhi+qj3ZsYLDmzmNgU4XGrh2BcJe?=
 =?us-ascii?Q?SBsHbRidOEeYSIwG+001CevmncfApjVzOq3WCo+jKVjY2q2KhuGpgzFLIiqn?=
 =?us-ascii?Q?Y+WCkL9xl9ViBy3IMsTNqkJlO+AprmB/yiVRc2Dod6mY7do2PTZlVrzthju1?=
 =?us-ascii?Q?hWcK45cYniyTBXCi4C8FgTA4/1iCoD9Fj0yR7K8F1TjOKvo3N1EjR78a8O2r?=
 =?us-ascii?Q?f9wMT2VTd5Defetg6ZR503J8QhrqcpIHBNdKBX44Ommdu5NB7bZcZN3NMfIN?=
 =?us-ascii?Q?8XjBxWWE3KIaYQC1G3cw/aBwV/nEwy7O16sOCil+NxaVeLZjicL/EUbm+CL/?=
 =?us-ascii?Q?8/A7RFn6YcHbJ/qjVP6qwTJFcFxIPHmpxcG5h7X5pl46ecuZkRZSn0oDLVkJ?=
 =?us-ascii?Q?SHI/nuSi38F0061nNSpO9v4o68osXVXhaZlyBiwB5WmmzuxEv/p8iGIb23uP?=
 =?us-ascii?Q?kzdSBiUnJG1+Dxsmkuk4cAUMHmvwwQONlmXp/CnmbBNht6PMvDoU8r72BmVf?=
 =?us-ascii?Q?ole95X6RCUOv3atrJeqhU3C8m6ivNPo/DUOOnsA313Um0ksxWB56HqKxrm/c?=
 =?us-ascii?Q?1cFKI6YCZUOCwwrB+4PF6K/qIewhdQCBmt2d/DwDI7y+e00x6xQRdnhUX6AO?=
 =?us-ascii?Q?OdFbCySG2C1YERnVgk8lIXMRuDLNF5u9bOD0kAOhuPn6dXBD4t3x5ioQlVCf?=
 =?us-ascii?Q?wxkNhxXOkGHFAO9scnwRNLQgVjvmgNaTfxKXzvD4jUUtdyI9xSIvaeqZyHek?=
 =?us-ascii?Q?lTfItD+ZGWVfDdwJnTX10EQQTflk7Xy5RBtsUxIu6ANTPU1cCQ6LIgiFNXs7?=
 =?us-ascii?Q?uuRooupzA3UJtzIjHQMFG0uZXnJpZF8cX0TGsUCFoBHYlbrlkkOJR5JxvvRI?=
 =?us-ascii?Q?SWO2QL1if33r+X5SprIhaGov6ZUJJYvze/iUhODba/qee0qCPeZeYwImu2X4?=
 =?us-ascii?Q?Umuu4PN1785e/2vOsJj7zAp5xG1Aqm5M45sj+2k56FZhJmoBzYYE7LbkN5de?=
 =?us-ascii?Q?NC9kSDBqi4VedXYw39YrIpM0swxzhWZhqaCGi8TjZqeI4qCN8Qgs+BEYa4F/?=
 =?us-ascii?Q?dfCWkGK6YrXQIttZh0xxT04KThDtmhQpP0xPRHydaqLH4sLJchQSjR7gngjb?=
 =?us-ascii?Q?LLgShQy881E=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?aPrRPhrFQjv3SfE4vSQ1NbAV019tcqU1qVXsxZxVNICd1JIWa9Btp6PgGwbY?=
 =?us-ascii?Q?j36QykEKmw3MbKP3Ir8gVskSI+m2kYL2ZcEXiY2sOU79fkH4EfjJBS3F/mv3?=
 =?us-ascii?Q?VYUiclUy9JnHBK47oK/0gw9zrYVXRdhh6vIFQiExf72Ih3BjLDiZ3leiEWG4?=
 =?us-ascii?Q?WkQnIvfWQqB3U7nKO/DlqrVtsRKpBXHEIrtAjlvnk/x5s5hHdh7DBwq20GVX?=
 =?us-ascii?Q?HwBN15CGALZzJIKD60c35HJsTI+G/XOojXyd3LyL7MtbGLCuQRYkAalMpLcT?=
 =?us-ascii?Q?Q8ibCYPKspIzXdSxvTahKz0cb4kXWBvGDRxva2ATE4u0lxrdOObNOEAS1vla?=
 =?us-ascii?Q?GCtqKnKYYFCPd+lJQueYHqsA+iM0RhedisUFnyTyKt/asdNCAQnw/1X321+h?=
 =?us-ascii?Q?HbY2HvPH7QuIH03RVCIchn96RmmkSCrvLKwoBcLcyJeCE0XPhuEK2ZKSbKW3?=
 =?us-ascii?Q?UFjNYVjfNo6QeMyU+T+LRS+fMgShvmtiGT/7cY+80MMGEq5D+PPgL7tlTj3z?=
 =?us-ascii?Q?It/aRP67rKnXJtUkJX0JYy7tbLbnIL2rWjI2ZwRGQS0rZmfoQanypALvjACI?=
 =?us-ascii?Q?V9Fe3B/0Lsubnrq0QAFfLDPivuxFPCk9jb37pReyWrvg+q+WXtbJT4DXVFoo?=
 =?us-ascii?Q?qqqnOFA3OhagjBS2f2Ng3wNk2zZfzE7YriqbGyt/svbmnpg+Lc3vRm/uvFB8?=
 =?us-ascii?Q?LG9Uvum84+nJtwxdIXtePgR9I07/EcqQY1Qd/pk6kghilneAW+H5/WcqjNis?=
 =?us-ascii?Q?Op0tGlqFGHj0+T35arH/scobiVwNMC0KnzY9S+efQ5LlFKmRz+3WJKohl6Pu?=
 =?us-ascii?Q?Zi50Yza8T20DTbZ7yG+4KZhG6YFr6U04FG5fc33TJI/0Kw+TQ+LJiXXuKsmm?=
 =?us-ascii?Q?MIDIK1toAP1q4dT96OytNZdQc0l5uej2WAg7NXZvbyI1sccsb+cFmXeWwtZC?=
 =?us-ascii?Q?u2KorS9mMIr9I79HriRS1gEfsg8EF8KjgjvqoiyB3tK/lqxa9Jzb5XO4TDtU?=
 =?us-ascii?Q?4IkMlJquopjhDZmBMM2hvs8+3Nqe7fJ3rBie9hk8fvmtM3qa8fVgfW3yOkuD?=
 =?us-ascii?Q?ljJWhUY03ETvH9oKM2LiFVWil/Xt3oSd3rl/vDatmpzG1bwN0HlIbM3v6S+U?=
 =?us-ascii?Q?Ag3VsTM8lcR/6GHNUUQjdpOuKqPNjW/NNTvO0vMAexwaIoF7QCe3a7WNBGxa?=
 =?us-ascii?Q?w7eabV20HzvHFTBlqKjgxFHExrg2y/MqLHvp6I90bPqSVikQ/khp4XNOM4QN?=
 =?us-ascii?Q?pO+Meeozw/5+owDbiZceaVM14wxfdGDvxVnxJT8oJj8PMHXDVV62kYxo/hLb?=
 =?us-ascii?Q?fL/ef68sYwHm1VDIuTT6T+3qN0g4CcMztQYwIWHKRyeSjvzdjFYMJAyxjPaF?=
 =?us-ascii?Q?XPJ+1ScS7MrwVA9FWzfvqcj07vGKTn4VbNR97NulhumgoZcCQgOQ/Sivun1K?=
 =?us-ascii?Q?uNAs/vGfivsRe1vgQ+FYXWkDlUjO8oR+LejuUpfUHTRcsA7yaHds9DPIUkh2?=
 =?us-ascii?Q?juqdzv/maaavn7RycNnVOSZq92hwhZd/qI8esCEfzrPJ6sABNCVK4Rhkt9es?=
 =?us-ascii?Q?4+KMaf++WgJ/M9H73NI=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 138b36b5-423c-4e7c-ad4f-08ddeedefb5d
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:52:42.5830
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: B9qQ772z8XaykaPtdPYnP0aqwJ4R0lpVij/kI/kg6PbGH1JhimkgakmrVDSi4uWe
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL3PR12MB6403
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="mVi/3e4b";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:200a::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 02:37:44PM +0100, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 10:11:21AM -0300, Jason Gunthorpe wrote:
> > On Mon, Sep 08, 2025 at 12:10:41PM +0100, Lorenzo Stoakes wrote:
> > > @@ -151,20 +123,55 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > >  		vm_flags |= VM_NORESERVE;
> > >
> > >  	if (hugetlb_reserve_pages(inode,
> > > -				vma->vm_pgoff >> huge_page_order(h),
> > > -				len >> huge_page_shift(h), vma,
> > > -				vm_flags) < 0)
> > > +			vma->vm_pgoff >> huge_page_order(h),
> > > +			len >> huge_page_shift(h), vma,
> > > +			vm_flags) < 0) {
> >
> > It was split like this because vma is passed here right?
> >
> > But hugetlb_reserve_pages() doesn't do much with the vma:
> >
> > 	hugetlb_vma_lock_alloc(vma);
> > [..]
> > 	vma->vm_private_data = vma_lock;
> >
> > Manipulates the private which should already exist in prepare:
> >
> > Check non-share a few times:
> >
> > 	if (!vma || vma->vm_flags & VM_MAYSHARE) {
> > 	if (vma && !(vma->vm_flags & VM_MAYSHARE) && h_cg) {
> > 	if (!vma || vma->vm_flags & VM_MAYSHARE) {
> >
> > And does this resv_map stuff:
> >
> > 		set_vma_resv_map(vma, resv_map);
> > 		set_vma_resv_flags(vma, HPAGE_RESV_OWNER);
> > [..]
> > 	set_vma_private_data(vma, (unsigned long)map);
> >
> > Which is also just manipulating the private data.
> >
> > So it looks to me like it should be refactored so that
> > hugetlb_reserve_pages() returns the priv pointer to set in the VMA
> > instead of accepting vma as an argument. Maybe just pass in the desc
> > instead?
> 
> Well hugetlb_vma_lock_alloc() does:
> 
> 	vma_lock->vma = vma;
> 
> Which we cannot do in prepare.

Okay, just doing that in commit would be appropriate then
 
> This is checked in hugetlb_dup_vma_private(), and obviously desc is not a stable
> pointer to be used for comparing anything.
> 
> I'm also trying to do the minimal changes I can here, I'd rather not majorly
> refactor things to suit this change if possible.

It doesn't look like a bit refactor, pass vma desc into
hugetlb_reserve_pages(), lift the vma_lock set out

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908135240.GI616306%40nvidia.com.
