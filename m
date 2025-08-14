Return-Path: <kasan-dev+bncBCN77QHK3UIBBR5U67CAMGQEQB3CI4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id CD79EB265A7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 14:44:57 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70a9f534976sf29085766d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 05:44:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755175496; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vbvt4BKug2dUS+tH14C41AgQejLUzl2uqfDcZzvJkiTstsQYJL20pHxBVNXbMZted1
         V674+NEtLzZXRb6sBtqfv/tNISbPprkfi/j7abhdvneBKfaqVDNNQ2WWxrObVcDRtJkr
         rHyml6ZT6AqjYWOCbTdH5QQYAqm7XaDbx3EZjuVJJ9xjR/BAjNacDlatqkui92IKC/8A
         5lIqda6YiEL56Rz23ErCVYA9z+OrSqjW7CYcsUcLfSw0lEbj8FaJnPyx3kuueLmGnDKe
         t9McfDQSHvAIu1/byMUzI/CNoPjkMZ3pi8QgX00+SySrutNN+FDW/QsDgRHvVQ1l6Zg2
         PC2Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=150/GNlGh2jJVy5bl/ExSZ4yKp7gnDBBdLWqgoIMQGM=;
        fh=7RJOAfjSCSp+DkJuplTHyplctJfILY5VudGNUOcZ1Vo=;
        b=Yp1Eka6Smn9/R97/AK4038cjc3M7gJS0+6DStrkY8sI6FJeSpATFkyXu4VwgMEJV8u
         S0kAVckfAc5AsxVvZJ9mIq7YjSFp0mDCMKohiOdixacptQP7rPzODmO3BWQ/sfU48zKK
         nP4KHJxuKPUT8DFVQEyaFRGsy8t/V+9xAxpVNX3vMVoQ98SaYHKQB/euVATea41fTPO8
         Od8EVhjmUx27EEOQrVQrKwPlyoROLk6IRvBGFb2SOAecduoK8mK6H7YaS4p5LA4j3QC8
         +lp1DHtrzzdyBKeSZBHY8IjdrdyeIMaZpuHc6CtD8zGsuK6xlvSlwHTcW7yJHt+RsC4M
         DSkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=WljPxQy8;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755175496; x=1755780296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=150/GNlGh2jJVy5bl/ExSZ4yKp7gnDBBdLWqgoIMQGM=;
        b=gv9jh6QQX5yLAWQ4zDZl5zf5A63yjoPlQdb6jWxjklVCniLBdB+qok5jCNP2zHfNj+
         ohUV4oP8UIDu7yb6NUtGII/zwBtEvMqWA+y3HbyeaVh3fSXrZAFzfuQbmD6Bj2aNdvjG
         Hmca2tPGWUHiv7/VcW8+8zWutbjyLAy3LSX06Kx9x+EK21Uy89qir2uOaqXn1yxt0pXf
         fHFWddjWXhPrw7sj3y6regBHefuF1DRml96aOcAh8GoN1fruJWEX4+7Z7fp0zYnrdsJ2
         CwWAmTXqst05h6GrSGeOhqMuuHIH9lAUEoOPeCnSpD9RKZt/THKLNb+Ug9ypYODtouPq
         UwdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755175496; x=1755780296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=150/GNlGh2jJVy5bl/ExSZ4yKp7gnDBBdLWqgoIMQGM=;
        b=Bugvvwx0fZJoVI+wNAQe7Jy/gIMlVoP5wYu9tei7cAqGX1WrD+4mwK8i+lQkKtrP7M
         ecKwty68rH5WBA+V9qXdODBtvtpHpTcQR/DZw+ZyvrJ9J5ilp3r35F6z5u0tZp/gVCc9
         X8HfiLmCI26DYghVKSWK1ghseif0DxLWGVWV5mybhnzlkRZY2CF/4+MyZFh/uz2feIPl
         zSlxc6XigiYUBqPqOId2zG+aMwQBa4/n0tYRli+wrQnWDVKrj/3DuTDckMayFHvtmW23
         NeVXaRvnnEr53rsifUTSNUizxK+x7eS/hDu5eZtDS5K2NNgu4FSembricAB+n6zcre4n
         nq7w==
X-Forwarded-Encrypted: i=3; AJvYcCWc+1hnz0+p5NZTAqE87LdN05Nh1OBtNzB7w9/B3xwSRN77KH3XPVGmCeMXjINYQLHmn5354A==@lfdr.de
X-Gm-Message-State: AOJu0Yw9yT1M5Xo9RDY+86GQoEtf49BeF/xKEsMTDOjxcCJg6C7lcttY
	qfVTQVms2LuItWpXqvdFQxdNgzIbmBAFSqrDwADW5PBDI0/O1BpzmIYJ
X-Google-Smtp-Source: AGHT+IGNQeiPCLjKWVcOsZboTcz6KRwsOA//MN3VKDKpToSriEtN+Vt1gbBes2VeqGbvu4hM/8a0fQ==
X-Received: by 2002:a05:6214:3007:b0:709:e2f4:9de5 with SMTP id 6a1803df08f44-70ae6fe1648mr39373966d6.22.1755175496153;
        Thu, 14 Aug 2025 05:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfzVkp0d/0Z6pzoRQ8LQUPs/ItUjalQsSOsHIIa82mb2w==
Received: by 2002:a05:6214:b6b:b0:707:1963:1435 with SMTP id
 6a1803df08f44-70aabd59a58ls13621196d6.0.-pod-prod-06-us; Thu, 14 Aug 2025
 05:44:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUj3jSaNxL/CmndIr3JgJBG91OlkAbISxR92JqRmY6+gdeonxtoLpx2QU8Cc4bOx2KMRAXelLjI84Y=@googlegroups.com
X-Received: by 2002:a05:6122:8283:b0:539:33b1:5571 with SMTP id 71dfb90a1353d-53b189bf464mr991731e0c.4.1755175495177;
        Thu, 14 Aug 2025 05:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755175495; cv=pass;
        d=google.com; s=arc-20240605;
        b=cR7rTS+BQWNtakYW4UOpan+zc5PQVKZD8TPUELfpIT7BCr0sOvoJgfmkHocKJDiahV
         plljjdRocPZZy5G0DF2CA/BCQvLqU2v8t/xxwOvEobJS5rFuqWf85L+hBDgATR45uGFL
         r4+TMoaSnE3AWO9UpdD2ZX5lUzExCnPB30F15KkZS2n9JpcOMv5tvLkxGFXv2rYhKAM5
         2V8f9Kkh31XbGX/IjZHcr/PK6ZUzuKtkPl5XQDsPoPduDljEzjezpD+LNf6bAGXBDyIL
         M3GJme8IA6Icox/STTE0aZXbxIMykdKkL2szt4kqX2buFwvy3ehONSVHWQ2jGpVeAgsz
         DwHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DT90r3xu+SF+TlQsyr1v1Z9fZmqXQG2CNUIvfqDHvxc=;
        fh=7UGQiPUstHBdMrT+/gotlrsKf2dFOYLPDzCPmdRVN7g=;
        b=ei/gyO0KK5Zq9e2v/Ce/xBdQjkHPI5PJFjl6ILh3BWPkCUElbvjmtuKT+CUhaq2EdU
         X5xqiUHTTt2ZGIwjmQYLIqMk2/TrjI9frpidBuWISQTxyCCucjwpyS4FX6Qn33q1ynm1
         Q93o0cVeh8fllnEk1owVM3hmys0sOiP9apP7logt1AC27lKZS2bF4RhZCw4c2EhG2CAw
         eoJ+DGGpAQUlmq1LP2NemtAUqtwRqhcoAOEOrR3wCARzSzo/EiFfP7o4DtvgmFvVVo5i
         axMURKvbbT0aoPnnxKinE+wou4cc4dqGxgY6w6DZx0+tbkZmP/7rXOKJ5Su1StnB1SFg
         AzBw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=WljPxQy8;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20611.outbound.protection.outlook.com. [2a01:111:f403:2009::611])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b02e6ad6si749816e0c.5.2025.08.14.05.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 05:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::611 as permitted sender) client-ip=2a01:111:f403:2009::611;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tcOS2/zres2nxM41T2hQWbwsLQ9dm/HITdiQxu/r2Ps7HMsHtXJjGiWQMdVQ3Ob9COGgRnuPQu/pMFJCbBo42Fto1nN4EgDvuHTIUavtT9NRbOTNkjhTSSMkaTT0efl/dEa/8ZSvIBsDUNgO6tRl00jM8JEHL7s1dfPVyS5R0JepOQ0Qax77Iu0tJHlLCbTGf3bpPHVWKQeIsNis+XuBpNRFySsoZqDHv6vg/E2s3rEs8cH+5LIErVkPa9AhfbZkWL/cFGPHusiOdnVdlA/f1hADdKEwXmT67WCV+U2uqXPPc0+sk7eqkzz7Vt4NogjJ5xmCg1nuQurdy7vrx3ooNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DT90r3xu+SF+TlQsyr1v1Z9fZmqXQG2CNUIvfqDHvxc=;
 b=ygvBDg/2D2SKo/rj7yySEhzu4g1IA5IhpUz41RVUfDmy+/I/N76eodOvDPVc95AkZ0zA0Nz+VbKpo0mSUCA6GJ4g38U0U+419Ls9wbcCVDMwcnI2zCHbFiX+7gdoNFFKwcyqMJaWkZNUEoX96wnOCUzjJjLS/RmNF6OmUbCluzD23U9wKm9QUA6HzbuyQQPQj8unbW9V8by5ypUitp9OzNjttN6Zcwr8+96nAxDwM29f9Or+kF6ZeskautfJnxWsomDl4u3OH+HHemAJ3S6terA5//8gf0KJgZAgwCE6VZUVFhQbpP9qr032bWvIVWGdHmce4K6xHw0E7JBKVLl+Kw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH3PR12MB8332.namprd12.prod.outlook.com (2603:10b6:610:131::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Thu, 14 Aug
 2025 12:44:49 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9031.012; Thu, 14 Aug 2025
 12:44:49 +0000
Date: Thu, 14 Aug 2025 09:44:48 -0300
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
Message-ID: <20250814124448.GE699432@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
 <20250813150718.GB310013@unreal>
 <20250814121316.GC699432@nvidia.com>
 <20250814123506.GD310013@unreal>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250814123506.GD310013@unreal>
X-ClientProxiedBy: YT4PR01CA0310.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10e::28) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH3PR12MB8332:EE_
X-MS-Office365-Filtering-Correlation-Id: 335a77dd-a3d5-4004-0862-08dddb305b7e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?IhONcx4t+6LzQCpNs17HUOldF3J6/z41LYdUhZDvfe7L7AAWMvN+Af+BT3Qm?=
 =?us-ascii?Q?agcu2dRQIYhpqv7vURMTj7spx0W8fejuD76ImSxZdromRURIVkIJeGvY7nn/?=
 =?us-ascii?Q?B75ZN183RjQ5qMDevDZAQ0JqT3caBw26BBhVZZNuc++iiMHNu0jRADderWZs?=
 =?us-ascii?Q?r03RPaQ+1DrT2t3U6XiYe8uJDI4DuZWL89wHFtSuVKCPSF5/oYWiGm3MHzAq?=
 =?us-ascii?Q?DkfdyaR7yz4Ao2/DFuhTwKzqbFnhEeBtNlgh/0BfAgi1+OrkX90MZOSzWf8p?=
 =?us-ascii?Q?HKNylEhtkxGBy38H8w+P0akz/iamIeypOgN4lU0dv82bHqV1z4Azpj3HOsE1?=
 =?us-ascii?Q?loGWSWWDUkm6pbu/VwVO3rBuSKWSZjz6ATp3WoBrJofFfUH/V+QFlwbtAOsF?=
 =?us-ascii?Q?3BvL2rNkzCksD9B23dH2ewiUQPZpz5DIuWRK6YoXxam5sALzA3qWrCj4HLP4?=
 =?us-ascii?Q?+9K2/qPffpm72eqiScg/MjavF2Pexh2d2yAmc48CAZFJyN2UhTKiGgvRHK7b?=
 =?us-ascii?Q?dhxuncm7pt3gVvza6ABXVQuvap2+P0UTgpSKSw6tBv9y46aIEAE/cs3BjNCU?=
 =?us-ascii?Q?JFxGSC+Bs2ccFT/jqgKWXTYt76n1UiUlYXg77vF0tOJO/tOgnmAt/zpfKlYn?=
 =?us-ascii?Q?i80Eij0ObzYEJY/jZ0sjTN3RSoAs5zuWNpWrccSWG2Ac4K+fbcuTmKeiB4yV?=
 =?us-ascii?Q?911AE/bkkI7B7NI+t+8qesNO8Mu6vr0deOjFS69kKOaTm1FVDNd9QTbrAGpT?=
 =?us-ascii?Q?DmZbHZdthP0xMJxPVjfx9f1zMjugQN0LfVHmmg8tgnGr9BH2Mg+SvM0MHIYt?=
 =?us-ascii?Q?CdetfLOBnaKnvLJ1+PHDw5cs7+4iGrTaTHsrXlAsXZw817cpZ/4cdUJLttTd?=
 =?us-ascii?Q?HIh12u0jy1JA9S9rHdgcvnrgXAQKSF8qaJXGBNky/Njdk3uZBWaU88xUQjf+?=
 =?us-ascii?Q?+fr7oMmd7SUod+bZ6A4QMlt1C2W7YocBv0g4DuE1AR7yvQCPR8V5xdw4TJXl?=
 =?us-ascii?Q?inPRqX5fh1WRsTGkBvKu6T+RloSJy6vcPzDHgditWSIX5twfvAtz73kzrASg?=
 =?us-ascii?Q?rmcx9/4psrMtQl4ooKEvCyZIwaZ2U1Vf/KfGMM6KQctnCLoBRWTAaFAdyYVV?=
 =?us-ascii?Q?nH46UG9YC6cRD5ZUvKpCf6H2SVDNQlpvkidfpBWcC6pQ+if8USY1ZDE8Zi0M?=
 =?us-ascii?Q?OzwmsydBnufvyFDtIVw5flHeTlYxJAqABARAaa3BVdqFWcp0Cc4xEGEj6Uz1?=
 =?us-ascii?Q?2bDWhv9TegAc+eOk6BXaDX4ckQVQkfpAbfV/tbT/iBpPsEfNr7S4VP3O+GwA?=
 =?us-ascii?Q?8pvctwaJN18AQ1pKEwRnQf/V5N+SFFnM/C01Fg+QrYLD1NyJGnsbYqirVz9U?=
 =?us-ascii?Q?a8OZaM6mS+lDnjtH/WKJ3NgALePJ95rdwfe1AHLYbrpc+iHyj4bdHFcmygos?=
 =?us-ascii?Q?WJDxl6u7UvU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?CgybZ76urSHfPkuNEm53VQv/l7tijjsayqvTIE+fUu1Xkf4jRMun4Debqpct?=
 =?us-ascii?Q?LLmfOWCWaK5suutZRHp/pT8m/zAsRCNkHy/iPksOMGdCHNFsJCSuuTr5ubJK?=
 =?us-ascii?Q?XXnXhpF9pHYNaJ97WOD9S3lsklEOB7K9RkragJ5VOCTHfm1O87DI/CHWyamn?=
 =?us-ascii?Q?2rVlJ16x9NoWkgdD96XN9rbwi7/xKv+g5QF9thgUJ86QhK0RlYoz0Dl+F11e?=
 =?us-ascii?Q?Ri9GsemQ/QaQuS1v9q1NGDHy8VS483bN0/SwNuTqnraI0vZsTFov7qUNYHMR?=
 =?us-ascii?Q?0UnNLDxASqkVxcRollviXPjlyPn/lhWhSzQrTG5U3lzCfaJml2mGUaTmDutz?=
 =?us-ascii?Q?fU5xvmEL8E5CCgo6ZJMr4i99e4gHD793fLYVwb0CgTu84SUL8rEwCwLeB3tC?=
 =?us-ascii?Q?8QtV3pON/3Lk+otW+JRZ4VhCIpOfF9jLBb7Flaijnrw2lV86xXEj4evJ6P1p?=
 =?us-ascii?Q?qbStwlUiCPcEM4qSbhBcejFy/nHImHBbF9rKL5mQAMA181DTK/gVLLQcKbhN?=
 =?us-ascii?Q?8kG4T0SkRV9HnXECIwhxzxk5bJisYkzHu2qMhGCHA2SRsrmV8pJ0kHroHXAa?=
 =?us-ascii?Q?xFeRrq3gAf5lOXXK6LV88ZIx6ICmxF7bOa7QI+6785lS99ynke86nFkmwszn?=
 =?us-ascii?Q?KgzvSl0u6JT+TW8/bghptYwcsgL0ecydf3+r7fCqVmidmPxwkpRhCDtwh4KV?=
 =?us-ascii?Q?p1IEoYeXrpQRKMVzF27BB7OMDtVZd65Fx/fLf+A+YJSx2kYAX3+velAeZJBh?=
 =?us-ascii?Q?GJdNfrMByLaKcfE08eNvDWjHnPsyhf/ziyUytQEhhS4qj6FS3+jJBpp5fvEX?=
 =?us-ascii?Q?SKW2lNxbzWTdUJ9v9XB9GEHCssJR6PaT6Nbfv3H3OFBPFKex5LZW4smQCTvN?=
 =?us-ascii?Q?pZqmS1BSP3rj5JtYRWFpwJLk7y8hL27Tsm7dSv+G8urYbspQNNJzf3S8k9wL?=
 =?us-ascii?Q?XwlQxPfEoUA1wLUDwX5TlP+/i8eQGHvI46kY0qTY/YWM9To4HH1lRymFunyx?=
 =?us-ascii?Q?KslNOgmZdZIWXOGi6P9EMKRah5e9ZHbagPqkuKgRs0z/nb8Nv7t39pzcNQSS?=
 =?us-ascii?Q?DNG4D5X7SQOY/XFNuWqEKIqbUiJhwTrjR/w9dc/8zNeMMJ/QVGk1MdTPOLUV?=
 =?us-ascii?Q?fkBTwurAOCF4eh2ejourrH89nOAaNU+sAizBuD+o9CccXwEbp9YGfxmubQpD?=
 =?us-ascii?Q?3ImYPqlh6QTcSo4VnlAvqDgBg+9s0n6mUQlp2QGwpi/IfS2Xd57bNvkffy7Y?=
 =?us-ascii?Q?oljThomEhgCiBOGdG89WWo4lMmpB9fPKpjO13U1NoSHsHz/BxDcKGnJw85ll?=
 =?us-ascii?Q?Fwi3BTDmfXK9XqqDlNYA/mKvw8DZAQbQ6Y9D+kQDd53R8vE19xrYUkfWnsHB?=
 =?us-ascii?Q?hJ+H3VbWeRJWQ2azBU23pEdicndshS+r60kwKBfoo2oGsDRlKvaPEvZPOpez?=
 =?us-ascii?Q?+bbj1BhfhKAeoY5wdb+LhD8R5kxA8DTMxMybEhM6zkKSmhBTUeY7rAsdMh7u?=
 =?us-ascii?Q?O+cWsaCRN1aL41I3LcIKST7HdfIHWxgBC0eqpWnMOll53n+Z3gmVrYeVj23v?=
 =?us-ascii?Q?LPPTFf97Prpj7lcopjE=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 335a77dd-a3d5-4004-0862-08dddb305b7e
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Aug 2025 12:44:49.7801
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xm66W7cAWmPEyimxT0zQRYAvPOIAYlJTwok9sFU6HfDYZ+5LrObHHojxvLOWdeJO
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8332
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=WljPxQy8;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 14, 2025 at 03:35:06PM +0300, Leon Romanovsky wrote:
> > Then check attrs here, not pfn_valid.
> 
> attrs are not available in kmsan_handle_dma(). I can add it if you prefer.

That makes more sense to the overall design. The comments I gave
before were driving at a promise to never try to touch a struct page
for ATTR_MMIO and think this should be comphrensive to never touching
a struct page even if pfnvalid.

> > > So let's keep this patch as is.
> > 
> > Still need to fix the remarks you clipped, do not check PageHighMem
> > just call kmap_local_pfn(). All thie PageHighMem stuff is new to this
> > patch and should not be here, it is the wrong way to use highmem.
> 
> Sure, thanks

I am wondering if there is some reason it was written like this in the
first place. Maybe we can't even do kmap here.. So perhaps if there is
not a strong reason to change it just continue to check pagehighmem
and fail.

if (!(attrs & ATTR_MMIO) && PageHighMem(phys_to_page(phys)))
   return;

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814124448.GE699432%40nvidia.com.
