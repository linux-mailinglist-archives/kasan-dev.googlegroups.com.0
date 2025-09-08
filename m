Return-Path: <kasan-dev+bncBCN77QHK3UIBBQNT7PCQMGQEFGM3LTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 67CA4B48F6A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:27:31 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-31d6d276b00sf7349037fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:27:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757338050; cv=pass;
        d=google.com; s=arc-20240605;
        b=VUyfvLJXW3dQ/9DRHAdFl+Rb7aWrmtVADPv9kvmtAz4rnhlb4NCH2f40saOMMLo6Kl
         x6gPALo3XMiaxG+ZKp7noq86dMztwjoLNNB5Yf65cWGvvkgNnw9eYF/fJpa+dHhAJ5Hy
         UVp7BeWIXWX4eHZj/jx1vo9Kxksjwy8CEUAeE51Msv34+If8c0p7aZF/7X5NP80cPqbe
         qCujOqa5wHoRN7FK/Y3eM2Q+fRnHsKY1JL8Zk8/5rw4wNFVA9Ls6PM1PWlYfivOOW4GX
         7nWRc7GO0H3z4EVwKwkfptICMqzZyDrl5uYuWiiHhj3DZmfwxmcdY32GXPC7qKosfPM1
         StvQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=y1App85y80QOQ1BR7wsVn4yFiZUQQu9PERwq+2KapAo=;
        fh=8p4JS3gYKQhLeJTB34tXK0BjoQRylYCz+mnQ3SkW8wM=;
        b=KjA4wxS5pRN92J3yTuTevICs5yczDdbvoWFaq+8xKe9rgFgZ/dQ6MQsU/4l/F0GRbO
         36jslBF1PrhX0gIPisNiuHc+fGEbZDplOgFxLo0Q6zV+GoGewETt7uBD/3H1FWijHzuv
         NOmCdF6Cdk4kPo3ludrqjtcyLS2azQVHspho1bhZOMFOwbcUEoLyqIAPnIv9W8htas3o
         tHaiaR8A5dXrd1lii8sZBD61N+97xLL2yrRscYmxDv5DUOLRI68iVMP5HWPVJnPkpVuO
         7oKxI+34bJ4tagIpgevODCyt0qlluHVQ11Id4OEQA9SsJI8E05cep8xZFaVlaZjVHd71
         CRYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Oo+ahGwF;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:240a::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338050; x=1757942850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=y1App85y80QOQ1BR7wsVn4yFiZUQQu9PERwq+2KapAo=;
        b=VlK6pAHcmZD9OdPISyQuBtIWfWYjcNUYCrViEzFnh04T4G4aw/AbqYuKHCN5g2FFzD
         X9WN3EUFBp2Ww9xgzQDX/rsANO0IKnbvNW6T2qYkt1ZScSlwZLUNVjMoQSdpjK7dqWcL
         cC+vYwZKprwCNwsn1D7MB/VtbNL/2Or0DruHFV6XebiqnbSiVkgmEBpXFmTOubbAlTSX
         eYHyTu/OnJJTrNsKE7c8N57kZbeKiUlcLrezhOQ9SnkURyFz10jFPYrJdswzZVTQJOB4
         +rpeWGzZXfnJDtrD3+Icl38YFKrv01Z7nXRHvy5nWRt5nb8Rtykc29y2RnUaL76BkIoJ
         S7fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338050; x=1757942850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y1App85y80QOQ1BR7wsVn4yFiZUQQu9PERwq+2KapAo=;
        b=EpSV5xpVg6kKnmGW5O80ztas8Yj9LKfzUp1TMVFvWAzvukwOuqgYTcIn5UoH+FyiJg
         EnRVKW0X6jt7MV4ehQIYACS0l1NR+nWTTAcM3sJNPQmgcuNnjs7cje3Aa1c0NSuV53cW
         BD5Lw6BfwcfzR7CYxIKA163hMC4Z7h8EjqwzE0FneFj4xoM76Qg9hNMtMJZL6qeI29sc
         mUbqy5sfD9zwQa2iFWOWIQ1rzK7Q3IwoXIXVwo40kvmYFGWm9j6CP9Fnm/vsMELiEv6r
         UX1CI2773GuHSxWSZRNI2hAJKczea6t01YRbjxcSOtZfKcZT1xPmMoK7KWgK6mG3UlsQ
         Mc/w==
X-Forwarded-Encrypted: i=3; AJvYcCXr0uhzmK041V01i+XxNveYTAUQZRbqc1emy7PWxIqPJlwchmOxdq+wcshaqfDiRQCjxclW0g==@lfdr.de
X-Gm-Message-State: AOJu0Yy3PNTm3gpT86hthZ4Cd9vCO1soydt0Zp0BUK0l2DRo0IS5fpd0
	1UWVHDPh7IrQFWO4AyzPqr21VYWZQ7LO4ukmAnbpF68Q0xqpQ8bOlD4D
X-Google-Smtp-Source: AGHT+IEThZOVBjV+msV/jeQi/p7Bn8ZRIHuq0T2gieKGbUVx9YDhH2LZLUB9pmiJY0kRUnDM7Khzeg==
X-Received: by 2002:a05:6870:1656:b0:319:cc79:4a8d with SMTP id 586e51a60fabf-3226552f5a4mr3763611fac.45.1757338049821;
        Mon, 08 Sep 2025 06:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7yczukp0D7x9cLK5d+S2zCpwDP4HSkxdPMe3oMYJp80w==
Received: by 2002:a05:6871:e4c:b0:30b:b8a1:c8d0 with SMTP id
 586e51a60fabf-3212724a566ls903832fac.1.-pod-prod-07-us; Mon, 08 Sep 2025
 06:27:28 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVeuh9WAsZifBH+hsnTCD1xcKxm5+X3GDk9jyLddHz/noP/ExguHMogCzHfyWA8ljNrMttAAqOQwos=@googlegroups.com
X-Received: by 2002:a05:6870:3509:b0:315:2bc7:cb62 with SMTP id 586e51a60fabf-322648147e5mr3637339fac.30.1757338048774;
        Mon, 08 Sep 2025 06:27:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338048; cv=pass;
        d=google.com; s=arc-20240605;
        b=dFlvTpbENcBiUnpowJq7KAk7bnN7jgQOwlRApuqVshs6NKZQLRYs3CPcSeq1Kk37JX
         7Bkb/CN3oYLbV/mpvzZqmQZflZZsgFSbsd977aB40I7Tgm1fr/QRnWnY2TozrEUrqk3B
         8gxFc5HDN5SEYy/HO9bvFfUOZN9gC02zBGwEPdMNJ0WNAAp/r6+KASHiTf55x5aK5r9d
         I9WCjzAafW3SR7k4WwU0TpGoKoMw+yyAwcRh+7Ea9kW1suB/AcEqWxjC4n1DcYTHquPp
         xYB11phIHvbMAX8dpX177Nb9UT0488n0RNyKzuzOcmsv05qqNAgTFWbG7HT4cFOxLYiq
         R71Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f9p34D0WEtqrUL+JW7PiSoLZLSTppAYaehaQicFx1w4=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=OxRxx0TEtgil6hLCsV9pDRDLKqNSJNeVoDQ4z0Nc/Tkbm4CZ/wlDFL4IQb6yPSuMqA
         qOYhxv1/UWajZ90dd6Dh6oCDANh8w93Aj+PxdObG6mIXxOLjF+pKnhsNUxX2OflSmG9H
         xqmWXRCVoiSyu44ki0Ly30wriQ2TrhtkMncGhTs2qIoYUBHyElS/Nbe0LdqMgtj/rJ38
         dJKk5XdOyrEJhB92TGe4WHPFVSjIHlDCYzj1F3gTkzCoCZR5Lt7ob5QdXTlQ33ry+9hG
         K0PP3DVowc2xglKhJb+dFJeZro5gMLG2HgW2iHsUPIra7PzWuuTYq4AX6rmu+JK+3YZj
         JdTQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Oo+ahGwF;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:240a::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM04-MW2-obe.outbound.protection.outlook.com (mail-mw2nam04on20620.outbound.protection.outlook.com. [2a01:111:f403:240a::620])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-746d8345b65si406374a34.0.2025.09.08.06.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:240a::620 as permitted sender) client-ip=2a01:111:f403:240a::620;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=aDYPmDiIbM2OUCsFgBBnlWtXe0TXQnNWbsc/jRznAIb72Vlue9M3vikAQW9Qfs7gIEf5lmjPqWmcX1LK7x9KYTe4xECfN73e+SBg1s4Uj7TTP8znF9SIqGDobkfa+A6b4Zrp03J63yCx9DneF/tEy/g90RnXjzhFEF5FDQnvNUxZ0jLmjb+PmvvxVIIXSZudDKPic/Wgx7e0xAY8el8J7Sl01AcWlCSCOvT1EH7I+YUlKuQLYDA3cyEWgFiMlD0II10lqBsLmolXWHk1xTwJh2xlw9THMKNivnYQUzAdNHHHGkL52fLKKUr4GxGQvcPeAaz7jGMFlNMYH8P05Jjq3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f9p34D0WEtqrUL+JW7PiSoLZLSTppAYaehaQicFx1w4=;
 b=nx/GXbSsj7Z+eK2xHrw+Ml2OdHJiS2OPfjL77ZvfYVgcGRU9zhOtDgC/+2D1oal3sGiXDxKZ7iWiaDKOLEoeNEHZWogOjymmUkI39tQl9D7LbxHGYChYb2/3KRruGZ5v7u/HiZBoVS7kfpx6LEBrOOwrDpNZAbytapEuXhAIMF4P+YAfgKDOaEAWvM1L1GOFy+Z0KYG0v3wYOAw34pceWcgOO2+BeTrUEbs2x270t0biDdhB6dBgsNuC4J5vUAtTUifjHncF8tuH2Gh0ryiDDEp6Fvr99klojS/HPHIB03pXr/AiTVqsFfEjp2HhA++k4lfaVVXdf2gPGejlDzLm7A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by PH7PR12MB6882.namprd12.prod.outlook.com (2603:10b6:510:1b8::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 13:27:25 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:27:25 +0000
Date: Mon, 8 Sep 2025 10:27:23 -0300
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
Subject: Re: [PATCH 13/16] mm: update cramfs to use mmap_prepare,
 mmap_complete
Message-ID: <20250908132723.GC616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <e2fb74b295b60bcb591aba5cc521cbe1b7901cd3.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e2fb74b295b60bcb591aba5cc521cbe1b7901cd3.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT3PR01CA0100.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:85::33) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|PH7PR12MB6882:EE_
X-MS-Office365-Filtering-Correlation-Id: 50a37463-8ff8-4b86-3833-08ddeedb72ee
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?uq9GJoqg2FneTIq1I5qc9EGmICrZKjME7DgM5L1JilcVofR8CYb7YDFGktTw?=
 =?us-ascii?Q?BnjqwmcyrdVGiKRj+k9HlcqtCK8ZILuBcarl03311IGNxP4T2FUlJCKz/84x?=
 =?us-ascii?Q?BItsRm1AzIvoiP1Djr+DESPLu67uVShjVzlsRMprzZmBK6R5cGeFTpo0Obiy?=
 =?us-ascii?Q?XQelhewFzpaac6wCJzR9u9yYB4EMYXGplpcJ+NN03Hdq+/uAMFSf/TW7yqFn?=
 =?us-ascii?Q?mDfXGGrSw1qvotDMvgzyWIqbxmUZU2jX+3FWW7y7r8T4eTOcWGRgv5oimLir?=
 =?us-ascii?Q?lcNjTkxzgskPAQV9qMtSyEkLJkhxqxDK9uNIiBEEY+awLCLUxpdSCkJMp4nr?=
 =?us-ascii?Q?Ywb8qjUblVka5h2DY+JaJ+UfgmpGXJ7FkvtbYBi3VRpMoQz2TvQAJW0COHjv?=
 =?us-ascii?Q?QHqHVtCks6768JGJ3GYEnKVA7YLgdbI0HQKpVeOP4SNj0mUuOHQN/WzahWNF?=
 =?us-ascii?Q?MPT0OvASjdNrZymt7pp7Qfep0k7+92k4LkW34J1Qy5T9stqfqP2vuf7Hy6O8?=
 =?us-ascii?Q?V9IKxmVnBc1Q+FgqdOPtkG36ciZIz20fHq+G2i43t22xZKIuUSNoCxKBicSK?=
 =?us-ascii?Q?1SPF707HEbpD0EXYc7iygdXRzpFwrB0kpvOBvXwXkhY5ZxqNBho5aGLvpQII?=
 =?us-ascii?Q?8OQ/EB92j8JAaRRahgRPA//9Yrti2bYk3XeF8BrHJuzbCGCfqXLUAwnWndQ/?=
 =?us-ascii?Q?uq0PHjalrMWQ/v0sYZ1hEt3JVQCgzJphy8dsvdtWOHUAwOefPE7CQYVUSdsO?=
 =?us-ascii?Q?8IXq/UhEHYM+poyBOkXL2xrqBsEtvSY4UREmiyAbd5E7tUn3XqgIxksCmvi1?=
 =?us-ascii?Q?o6fdjSl+OvUCxD4WYjtzTtRmCV8pHMuDQW22gEx1RfY/1U4aw+ZzH5JaCTKb?=
 =?us-ascii?Q?fhDSVzCqGAnvO9a155hqQNFkJO33hFXYBrO1u1QglovQxxPpogNkFwFrjO5f?=
 =?us-ascii?Q?vz5jhzwif9bAomGmUh+QakKvfKVZU9PXjuussbPtKhS8RajEY7qFesr9n6Er?=
 =?us-ascii?Q?PS38gW4B5cgxTvmbXMPZ20GHBhBQWq2tYXc1y8IRE2ICO3HQt20LEsZb0aDE?=
 =?us-ascii?Q?5t13dOLR2qOkP/H+GWSlr0VoOhA8so0Rd/7GS3HO9y8S2yBZU5ZmTM2J2YrU?=
 =?us-ascii?Q?Mb5mXSj0N5Tm3VLub1+Swc7QL5ZjUBsbJHSH8YEKzru7bs9Z0PuFjcXRj5l7?=
 =?us-ascii?Q?7G+dNWxgOVIz21sAFfEkfIdg/WYmaEuwU6Iiilc3F7Sl5t9k3RusI2FbYdOk?=
 =?us-ascii?Q?UmKZbbYVKpmkIbnndfH6LfDDjIGndXl3R10DlFo73IxCVZa+mNgbaueQGmbO?=
 =?us-ascii?Q?lpPUj+qQSQQp0Y3IaeUQdHhKiEoVdO77zV9NI/M+kZKsY3bmmRYKmtRKV1VO?=
 =?us-ascii?Q?AKf22GJa7vG7JRI0P0hb2bKu3XadfAPvuTDkolL5L+Woj6g3nrZ+6d6NkvCY?=
 =?us-ascii?Q?nZRz0cGyWzM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?SewSrzVnveYhBlHj4DOX8dh6GBYMOvrr4kk5DK15mbbciiVOB8gJDPiraubr?=
 =?us-ascii?Q?HXsVpi69CbNZqpL3cXD9QduTlXk2ZvzmNtg3V0VoeCFHYtgaxxZ9kygj3GAn?=
 =?us-ascii?Q?7MSSGsTsLdfKRmOoQTYZVrOAvcCyH3z5xJuVUSyGgdwa84vXtBwd0UWf+wEg?=
 =?us-ascii?Q?oOjgCQHS57ZMebDWVOXlB6GssDJDIQakSkPKqU90yq2x7St3qOu2M5iEUOrl?=
 =?us-ascii?Q?zr9S9ozvjZ/nal1X1ZPqce7ckXrfAzt2JDcGROH2AiB27g8qq4BGibmw8Kkd?=
 =?us-ascii?Q?/vm0FdrOgD9eNi7qcNV5/N8xukN4kkBj2AbcwlevOOulJ2/bnrBEJUZfQex1?=
 =?us-ascii?Q?gQR5miVycJCdpjOQm1QNKg09ov3pu2cirwZAMOl/r1/HP5OjjuEcDgPNpK3p?=
 =?us-ascii?Q?90Z4QmM4M39eWsXdzs6pjOb+MNbQocNVls0v9pe8cerBfBi3Prh97aLD5vIL?=
 =?us-ascii?Q?4vaf3jbqL28fFoh2r3g1mRtQ0+dspUI1SHvWHk3D91m2DgSPYXBYTitPNfcd?=
 =?us-ascii?Q?TgSVeTnldXHS8BcBzW+oMBvdTTIUef5Umu1jx2mR8HvSvs/k0bsu1yfTaOcq?=
 =?us-ascii?Q?w0ZXV2WwTMDhcyqgeBZbo/NerihQnVBn4P0E0MJomL5r0aKf+CG3B6ww2bMp?=
 =?us-ascii?Q?VzoqT7ZQd3ADLc7tKAPxJLpIosvTJ1cbZwHYfpxlmRT17DZ8jATbU+h+PXOf?=
 =?us-ascii?Q?C3UxEPsXHCFstlqQx8INwvFwCK2zzvS/rJBuqn2ldkgNcQmXRAuF2IfJNEoy?=
 =?us-ascii?Q?h+06BzAJ6oygktQPox/D2cuBQn+ts0dlZxmj+dWABloz6ioTRqHtYnfQRKya?=
 =?us-ascii?Q?VUGKfC4gg+WeacOyDmg5x3uZaEcBduSWJg/Vj8nFWoEqgbi7iNyw7k0pKP+s?=
 =?us-ascii?Q?yCh0Gwc+1CMKMyTc1iz3LeP+qS4i23W2KSiD/t55zvbvafl29krji2Yp1k1j?=
 =?us-ascii?Q?gILxgVyclnMSOYrzG6R+t18YqigD0OGX19F0oYfvnJCGPWdhIwktWQSVeYzr?=
 =?us-ascii?Q?VtCZv0y/kz9y+7GTuJ9yZnmJnYWRXh97DKC67thLZ4ef5ilmRe0ZdPZZPGFd?=
 =?us-ascii?Q?+xU/GjZot1asIXiHFYHqfS39B1JMK7crvSqrgMTWpX7EOmtdTBi/eI0aB6dv?=
 =?us-ascii?Q?cUzudueFqVD7z+dplfpLoJyCLm+VNkG9wVEodOuH1bsGun1nObw3q4BEkdZG?=
 =?us-ascii?Q?bUuyOF8bDHj5sdKIhUOBu6dHeKbPR09N/6VnCYUQl1CecHuYSrAU2dO8KoXR?=
 =?us-ascii?Q?0OcnhdbNiuhk09hc/1qNTABLvIErCSkCrppdRpUQ7eEe+O57a9WnlzXi9pe4?=
 =?us-ascii?Q?cDx07qGUU5QtRYq/YE4eDIYEaALiLT5MENNObwTJC256wNk4bV+L+vQDOQXn?=
 =?us-ascii?Q?zOhbOj3O6zVbc1SE7ST8QXtUxB5auUkm/bsD+xiOEFZPP6GN7gQIzV8NBogp?=
 =?us-ascii?Q?l4aPYy7+/wkMfI6Xi+rVws9iUJmdAdrkdON52w5GAgmUiAJhe64vloFhTovW?=
 =?us-ascii?Q?gRBELjri5iFYmOg8OYUFUxlWTi+57vT0a6WPzLEDpPPfY2q/Pcqb4MmrnNtI?=
 =?us-ascii?Q?v3y4Me/3whUHDvzLsM4=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 50a37463-8ff8-4b86-3833-08ddeedb72ee
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:27:25.1482
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xCo0VXeHpyMrIO4wQH4i5/iTzRUaewESYbg/CxPLYZsdUCEKv7Pg++5MWUWx96Bc
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB6882
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Oo+ahGwF;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:240a::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:44PM +0100, Lorenzo Stoakes wrote:
> We thread the state through the mmap_context, allowing for both PFN map and
> mixed mapped pre-population.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  fs/cramfs/inode.c | 134 +++++++++++++++++++++++++++++++---------------
>  1 file changed, 92 insertions(+), 42 deletions(-)
> 
> diff --git a/fs/cramfs/inode.c b/fs/cramfs/inode.c
> index b002e9b734f9..11a11213304d 100644
> --- a/fs/cramfs/inode.c
> +++ b/fs/cramfs/inode.c
> @@ -59,6 +59,12 @@ static const struct address_space_operations cramfs_aops;
>  
>  static DEFINE_MUTEX(read_mutex);
>  
> +/* How should the mapping be completed? */
> +enum cramfs_mmap_state {
> +	NO_PREPOPULATE,
> +	PREPOPULATE_PFNMAP,
> +	PREPOPULATE_MIXEDMAP,
> +};
>  
>  /* These macros may change in future, to provide better st_ino semantics. */
>  #define OFFSET(x)	((x)->i_ino)
> @@ -342,34 +348,89 @@ static bool cramfs_last_page_is_shared(struct inode *inode)
>  	return memchr_inv(tail_data, 0, PAGE_SIZE - partial) ? true : false;
>  }
>  
> -static int cramfs_physmem_mmap(struct file *file, struct vm_area_struct *vma)
> +static int cramfs_physmem_mmap_complete(struct file *file, struct vm_area_struct *vma,
> +					const void *context)
>  {
>  	struct inode *inode = file_inode(file);
>  	struct cramfs_sb_info *sbi = CRAMFS_SB(inode->i_sb);
> -	unsigned int pages, max_pages, offset;
>  	unsigned long address, pgoff = vma->vm_pgoff;
> -	char *bailout_reason;
> -	int ret;
> +	unsigned int pages, offset;
> +	enum cramfs_mmap_state mmap_state = (enum cramfs_mmap_state)context;
> +	int ret = 0;
>  
> -	ret = generic_file_readonly_mmap(file, vma);
> -	if (ret)
> -		return ret;
> +	if (mmap_state == NO_PREPOPULATE)
> +		return 0;

It would be nicer to have different ops than this, the normal op could
just call the generic helper and then there is only the mixed map op.

Makes me wonder if putting the op in the fops was right, a
mixed/non-mixed vm_ops would do this nicely.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908132723.GC616306%40nvidia.com.
