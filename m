Return-Path: <kasan-dev+bncBCN77QHK3UIBBUFJUPCAMGQEH6JCENI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FCE2B14EFC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 16:04:02 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3e3c9a3f22asf84985855ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 07:04:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1753797841; cv=pass;
        d=google.com; s=arc-20240605;
        b=LTdIYvqMOAuXdJeMgaZtVGPEGIUOH2nlt6AHjssmG68hxpBZPNWS537cD/S1RSek5k
         LM5GCbbYtmPgWLJx+5mSxWXLG10u+XpRnQOz8bSm7v9if5FG3YB8j0Z6tsC+VQzgp7lU
         Y+rh15W1E6PoKAUkj8hwe3IGDx4oXe/AuTQlZUjLAtLTesYlHhWw+v7uv5z5sGlkhbN2
         g2Z0WdLupkP6zpqRNeZkyryk+x56X1Fjp3lRmSu/wsAwMtHSlCaQ6gX4y4qGooT0SUE5
         K0z7MZIDdcHERSQ2M6nF1DprVdHicZFyOoYXCul694B1YxDykNdgflYJpPLsirgs97lF
         Iu4g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3b5gbx2HYkeXTyMwlRXkKxu3xXhrJWQFPBGk8kqLrZs=;
        fh=OdjX8t8MlPKa/7MWiJCq2lqgxhF8P+nmFIx+VCEYCcM=;
        b=EzzuLoCrQGaonCkWMBrQ1nOqsdr3gYa4Ler/nZlr8ZVVGk7IrjvNVzGlXVh2KwLr0i
         r6T4HHGgAq1UHVpB9fVVZT6Uz8WfEHes0Eun6Lat7b+lUDgaXrOm/bptmgEPXSEUinry
         2pYgVJMW1UWEzi/u2h95SuhtqJaek+LoNieZTsSrpYVHOsojyZCL6vB0BbwEhP7xNSDC
         bRQg+hSw0jbbdProHvA7goh0vaypzGltPlKMGsDdBNVtnp9t+Lbtl3Fe/5gChCiZeu3S
         DzTP0o/EfOt4b1JfQbXvv/bPpZgUOUDdeoo/SBp5UcZmvdy+6ni7PHFrRfMM+aoQspRz
         Uj4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=MJGL0LYX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753797841; x=1754402641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3b5gbx2HYkeXTyMwlRXkKxu3xXhrJWQFPBGk8kqLrZs=;
        b=Hw2x15i7rfVr4ks/nF2tmWG5LukVbOsvJYVcebUWgKrS31idz87WKYEdaWzJYXgWD3
         cLuH8ICcUfLxOaTAyCzbIAsXd8ucvOoKLC4wjowZv/Bb13CVaN1ouMWoUEPo0vZOMGuj
         evk85hbDVAoL6JogI0Lwys7W17qtqPooEPn9T1vLuaWpMf+vBsgju3wZAAvAkfUTe2jX
         iNml5EvHOF6/6BmZcnVQIizP2YPlBx9U41vWcyPLHH84zMmm22vyVk1kWcaLlM/9aRVY
         Z6AY28hXeXA9JILI4j6xzYT1vFNMv3h/HgRvmncenK/+dd36R5TEZwH8VbUs5NC7vupv
         k0Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753797841; x=1754402641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3b5gbx2HYkeXTyMwlRXkKxu3xXhrJWQFPBGk8kqLrZs=;
        b=ibDNebxU48VByq1jCJh/mRzqcj5nIvzHPd55Ga9By7TL5WYCAizydFrDvmrNLER3zx
         jhRZXyWzeE55YS55stYVaLZ61JzojrTAM67+7S3rr7qg+ct5ECKdDy7u6rm7P9h5C/Wt
         ERRVCQFmCE1Bea6XoQUou4SJYZpoKio27i5hYb7YS5DrIN00ZEg0dipKTcg8ECxtWKTo
         VyOMPNQ4qev7JW74MIaJC80Pc9hcUToMN+tFRFAxQozyIPIeau29zaofkultrBClwiJq
         iEgmYnS0BuuTCkNPNLVhSpwg2JT0jU6/vJb9k+JH2QegbW1S6bNyJOBOmNGf2q0arGVt
         0+Ww==
X-Forwarded-Encrypted: i=3; AJvYcCWs9Vs8ThoteQ/exS6rHxZ+Cd9mJq+P7J9+jpKrBeZKo6m6rEDTntnR25FXONKeyqE/flHZ1A==@lfdr.de
X-Gm-Message-State: AOJu0YypgHn0zW3wOXBGHwnBrpGevSggHcMZc9ToOXq+U3hZWPKsINNn
	f8grPh5ynufKh2l+oxqnDj1z/Lt2OEO03YijwP71NwaVprLHOMAqdrmv
X-Google-Smtp-Source: AGHT+IGN6PZ5/DXt9GwNx1PmDGVZ01Zx2bHi9rXYGdzm7n8hQxmHRRAIOXDA+Kx5yKpF59HQd1V2pw==
X-Received: by 2002:a92:c24f:0:b0:3e2:9d91:b3dd with SMTP id e9e14a558f8ab-3e3c52271e5mr238266875ab.4.1753797840511;
        Tue, 29 Jul 2025 07:04:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcquKUZzxJqHnZ66/TxNstFhNCthyAJ2OYeTzzgaIUOYg==
Received: by 2002:a05:6e02:168a:b0:3e3:f406:c807 with SMTP id
 e9e14a558f8ab-3e3f406ca24ls350295ab.2.-pod-prod-05-us; Tue, 29 Jul 2025
 07:03:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVXCuECgijMmrfyVRklTwnEsOu31jc6xqVa+Kjy30i3Tgv8u2h+84hPyVs18OCT9wWifq8wF4UhbvM=@googlegroups.com
X-Received: by 2002:a05:6e02:16cf:b0:3e3:d14a:c083 with SMTP id e9e14a558f8ab-3e3d14ac1edmr185446855ab.10.1753797839566;
        Tue, 29 Jul 2025 07:03:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753797839; cv=pass;
        d=google.com; s=arc-20240605;
        b=K7flJyXXE+vrIhEciSJpq1f2/ZblEt2Xn1k7XNaCW4Kqx/ABWsFtZuLhIGPqQpuAPe
         82+7fTgVkQbqTAsS4ClJLpXtEpGITw3N3dh5ONnRptgtC3Fxl+Ud3penARA46eu8hx9N
         k0tUaTV4UWn5krCMB9E0e9+vahi3VpMIWcQCKDJuuB8VbuTjtkuwumGDlcYgCF15WJE1
         zwQ7BkwytEHPbDe+lmB+sRfALLhLpev0nChJ2j6eWh610CWh1l1sl8laSHm0itG6B4Fw
         9+O9JPsMtLmhPAU2Bx2zMwPSmZdGWyREAmfBGUz+bV4nx+g/UkCVXz9L6ev4mSGik/TQ
         Pokw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u5lfGgoFWb4/4+iV9JZkuHXLSYAa/T+6htV4L/MoZs8=;
        fh=Kk+uS675OgcI6GVgkC9TGNCPn5LJt51/yPOQUjzJfT0=;
        b=YOboOGVQTW3lBh2dWnUAnf1YbkN/PhkRZuFp8sImigvuvkM0+vBhcdoh2+nTNY3X1u
         VIhGGDnOCoklCkm9VhY5KmsADRxQvV8PfjdUd2Na0Ahrx71phHixhHSCsc0zOQrX/LK6
         rUXRB0v1YQk9TtG7hw7yXxNuYKel1nLIyPGZJdv0aTsnK4TziRMJkgTQr+hhLHJI9Or+
         n9GUz9/fvgvinrOn/rnttCD2oaMGN5tZveeSokLk3c9EfJ5dR58wy1sw46MuKoaeKNYF
         b5EFXrolwj6/aCxtXeFxJMO9VBKqrrV4hsXQygfsURPyBVuvtGURORk3sNr+NFi6hKm7
         8jQw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=MJGL0LYX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20600.outbound.protection.outlook.com. [2a01:111:f403:2009::600])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508c91d2af9si438742173.1.2025.07.29.07.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 07:03:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::600 as permitted sender) client-ip=2a01:111:f403:2009::600;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Q286QejTJDIXHFapfkibLNE4d0vW5g+yEXNtM7EoPxHznM6tdcrfV9yTmGPv8bbk5J90mOjfiEkTqlc88pslH1zmCXHlDwXhGdyaxL87Tf8LLCSIu/h8tqLRx9Y5hq86j5TCRSky2h+3HmvgHvQ12HSs6bKDlIhkogwMuryL4wuyGQ0lcFPNpWaaFPF/IF4Qlz+6u0zXtKes5XWtVo2YMe5aaJk8P+Fn+WF65S8kTmPD3I8O0vQp1LqMOE5RpO30vs6N04n2gpZJDrvK0Pf5+x+lNciEZDMpY0Q7+wf+MhNEbee9J8vD7z4ZgiVqYvZCDQokvuZtP+TJmJqYCKhQRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=u5lfGgoFWb4/4+iV9JZkuHXLSYAa/T+6htV4L/MoZs8=;
 b=Jpx1eV21ynmpqWNsWbpKm3/qanQ1OiPnbRMUrrIBFhZMjMt0tdV4uqFmdzzs0cTqKeTlUfhT0Nqp0B9B1Ep0hBXyi6YdUdgzheZSQuPus2n/m4Sko18LYJqqMGS0GwLju4/jUTcbZq9mRTGvyOECzo+67EE9cN76SS2k77Adp3wwzyvnwhDFR0tATgr9aXSiB+yzrpkgzuS+2HaHlnn7OGpiafrgwHal86f9uPytR37aa4WJbCgHTKY4xPhCjRSIsTlBwPNwRA4SBiBP8rM9QgpBy+vW65pbhk1MCjxtBqL7iyid2UzcOvuInJirgXlx716iwwVxaYEOrCty7/SGQQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CYYPR12MB8923.namprd12.prod.outlook.com (2603:10b6:930:bc::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8964.24; Tue, 29 Jul
 2025 14:03:56 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%7]) with mapi id 15.20.8964.024; Tue, 29 Jul 2025
 14:03:56 +0000
Date: Tue, 29 Jul 2025 11:03:55 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?utf-8?B?UMOpcmV6?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?utf-8?B?SsOpcsO0bWU=?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250729140355.GA72736@nvidia.com>
References: <cover.1750854543.git.leon@kernel.org>
 <751e7ece-8640-4653-b308-96da6731b8e7@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <751e7ece-8640-4653-b308-96da6731b8e7@arm.com>
X-ClientProxiedBy: MN2PR07CA0013.namprd07.prod.outlook.com
 (2603:10b6:208:1a0::23) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CYYPR12MB8923:EE_
X-MS-Office365-Filtering-Correlation-Id: 321d8f59-e99e-409a-58ef-08ddcea8c21a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?gBJ85slrc/H3Axac9i3cCda2aAxYQWMhciU4YT1ZSRIY3Kfj1odW5Uu/4uzZ?=
 =?us-ascii?Q?Th2nB+KKROUt3u6rz9IdwrR8/TMjCbN7YpyDFFLPyJUIALGgkA2WF7SCM8BD?=
 =?us-ascii?Q?N0j69f9ROq7UIhu1/5nfiyfke3rPQPVXm8RfwqcuZlQnbVRk8p4RUftoXwyR?=
 =?us-ascii?Q?IRdn2vASVZCKP3zaRumg1ZGu+r06zmH+q2013BUz01OCKwXVKKy+Hw8UTKOT?=
 =?us-ascii?Q?5Q/V5EJ80NxpqLH+pNIUPoyjORO40+JDgUd57m6Xr19x4x0pE4VQf7ZNc/Na?=
 =?us-ascii?Q?RdNX/bNh7T7QBRFnAPFE3kbetAvuoprNJhUeCgVjz2lCAr+hmo5oKK44/dPq?=
 =?us-ascii?Q?w+Mac16vk5mqZq0uuWaTvTIb5hu0eQ8ZEyYXqheRkategZEeVU4Y/TgvSk1G?=
 =?us-ascii?Q?PJRSItOO9GujEq6dHTURGE+HON9LT4Zu4fn3LNSRcLWMqbjYO/5LnX2clhoh?=
 =?us-ascii?Q?/j72Rj4sxB4f7ewSsdhlQ1EzVk//FhE33XrXRdmRoyX8XX5uRSzGMdz1REZs?=
 =?us-ascii?Q?THdBB3S9L7sl09+ZlZliJNC92nXYvDmWVQbyCELiPUHNZCi5CsdKm47n9Msw?=
 =?us-ascii?Q?mj0DL8V7unmIvsHOU3Rf8L2P7gxvj+7D4OUeae/2EJkdVrkCLW8ctWlCu27p?=
 =?us-ascii?Q?yTjH/vptPB4ZM2ERifpougXel9iCDO5HQKeW5JLXSocGXF0Kpcl9zTn1XyXu?=
 =?us-ascii?Q?0NO3OVL5VsNmVz6LitocZXxZ3GcVfZzX5OmOYeUVTyBLEKxpBMlAAoDQ7AtP?=
 =?us-ascii?Q?88j13QO2n/n7ixeLPN6GqN1Kh6mmstX2inBpDcXkl+RFTO8rTKsMfbafuhq9?=
 =?us-ascii?Q?lZEtQ16IZT1zMpsEB0XyrbAjfwQB72vXkE+7YhssvjGK71tvUwn9fr9UPbIi?=
 =?us-ascii?Q?1wUWlYdrOvqvpw1VOJI2xPvCwwX6+hPqMMRgnH4kDh9+dEm9KQ8x1w01Me8U?=
 =?us-ascii?Q?V5rMVNEPKHNFL6RlxRHmxGl1DQ/o4DihgXMFyLRg7FWNpGx0DkG+BibqBCFM?=
 =?us-ascii?Q?mjlFyK916g/pCunDrYOdDWxw7aJRd1H0dmBxA+lDVARx736rw9tatnN3Y2vL?=
 =?us-ascii?Q?gYc+T2mPFuqQCUeo+nGBItlQIGzdnI+qOdkm8dtrXZETDbT91oeOGpiY6wkH?=
 =?us-ascii?Q?olqsT06as2CZ+gQUhcOuXnmau812h5/MaLQcYcLMnfkitR+D3fx5PY/UR4cw?=
 =?us-ascii?Q?FtOHYqXIjjXmWbmnzTOLsL9fOeYRQP4tNVSVbRuX5mlceZ1yvqhpi2o+zsU4?=
 =?us-ascii?Q?NSjEuQpKmhPUsW+e9gLRVcWU/frzhLhgs64v87vKw2PzijOI8VdxABFtdF9c?=
 =?us-ascii?Q?Gs3xt2UETfVAgTd3/0IDhYjJvOkjUoTRxR+7Mc/1fZDkOZXgjE5zwxBVVuXk?=
 =?us-ascii?Q?FK0aY2bGBnYM8AMsJkl18BySU6wZCFMTEO9bPRke9JJi+e8I9dOmu918iAaK?=
 =?us-ascii?Q?VInu15SYAPQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5a1dp+PcEu42Bl4LnHwXyTw4eSaLO+UzWWWpSfLrouzmGwET7/dbWIljD0mZ?=
 =?us-ascii?Q?CqPH6aXmSdGs4teQg6zaU5brTHgD7e9bNxvGw4qsJvik+a0hHu1CSkmiQrK9?=
 =?us-ascii?Q?dCUqNmWNMgFkWq4iqpZ8fjRZccNQ8/zw0B4j4CFAsDXvOVNnwOaQOoR1Er1i?=
 =?us-ascii?Q?FPnLdXahxGGUjZTAB+bBIyIxTZwLmTEO14tNkBLZafgRuWxrDDpBMVHyASfI?=
 =?us-ascii?Q?POlKLSDszgJ/TKgFiEE/9IUyT0jB0HOQd/jkioQG4gL5omeOGKXGWogZj7kO?=
 =?us-ascii?Q?QHLCRaKAMNEPptNoNC0bWMOzDk6uO+OZnsa3XuBmsWI0LDFCa/g73PhZwPBP?=
 =?us-ascii?Q?6hNCEbwD2z0DaCJnGH2xynjxVPaEPanwjZ351oTP1Wgf+SfkqiSrSQk4DMVC?=
 =?us-ascii?Q?KM76VulrzGW2+TsxyVx3/iSGNBMqWRArlIsJGPZ33EYuXvt4FuzRcB1yLNrt?=
 =?us-ascii?Q?qJAwHrQHCpoVR0VvjJBTxluNh0xUaCfAXy5vN5gQfxM9kqK7sgF18vo8VqFV?=
 =?us-ascii?Q?uPaK3RrMsYzngXpRpbKfv8EC4mGVto+EZNw6ZeFQFGBmZuOMYZ6Uo7nFzccs?=
 =?us-ascii?Q?NDthcpIoL1qEiqrY3rzI3XMatWoo4Xu01JhkZhCH9klsZJ7cWwgThyU/abq/?=
 =?us-ascii?Q?3hbIE5muaIIHLO7stJImcl6trGCdB8ISgJ1aYLredv3xfAmXVtE+1RauvVQp?=
 =?us-ascii?Q?xTMZNTzC3D3+xLl2BJF7/0MNo2d+9giIbsVEK1424l0SjAVCu/EmVPgQfve8?=
 =?us-ascii?Q?IQAIF+7/jJUCSGb5cDtEjWIfp7cBsmoTSpMbvem0oE8qml5a0SHOAIICBYiL?=
 =?us-ascii?Q?HAtZT3KrX6cr/nJrat6mOZfsylmrdwTYtg/aVg7koMsDOFJKQqWoWtOsbxXj?=
 =?us-ascii?Q?ZoPNBykCwjRDfT/ou0WgQI6Ejcisub1huUrGeqDl8carEa98BL0M1X3J3hMP?=
 =?us-ascii?Q?gUyxRYOA5Tw9FpdXhzs9lsC1hXoukq6nusIdFwiJYDVBcbtcgLUJTDMm5zuc?=
 =?us-ascii?Q?r6dzw+LaJaVy5KcJuozT7WyMinjanxiweMzTSsNyu7rbbdSltFwNpAE5Cv0W?=
 =?us-ascii?Q?r+fTNIEguGVqblJwp3NBoxjB+5s16aeB9u+MxVIzvQvdh40YVqSbqYrbSLqy?=
 =?us-ascii?Q?y9Jwm0hymchv6jQXLOInE5Bd6Cq06tuEFKMZIAmg/CamXzQV/KErVsxG1T4S?=
 =?us-ascii?Q?yHdDY6Qm9OCokTOPoLLET3C9HFn/vS0AmM1nlzq0P/9XbtEypa5XbtKzBUIp?=
 =?us-ascii?Q?8aEOprdpGrlK9Ozowi7xn8YKS1ij9Yx1h1hOFs3yAJx82IBVokA4LbZ2sZlp?=
 =?us-ascii?Q?aqI7vFFduGfhaqKFRIYasvPgkRNnj9OGKpnSvWlIsk1/QfIJM30cRl0lc2iQ?=
 =?us-ascii?Q?Id6+TNyaeEMgyxgiNR4rruaLm4i/3CPoqBCEf4ANExLAdfkYUYcRKc3bL9ef?=
 =?us-ascii?Q?02hQHm865f2g36+CMO4vy1lVqUOj6pjOaTeQ3Pq+LRRs2hc60uSoPyulLOXH?=
 =?us-ascii?Q?wAXeNeaesJNf1zN0674/HdTpKrORnwcaj9ypKitSHA1eZ1LkOfW+pUrGHDzL?=
 =?us-ascii?Q?pL70o21MA1cmbIY0/lk=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 321d8f59-e99e-409a-58ef-08ddcea8c21a
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jul 2025 14:03:56.5173
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: yc8LWxbq5e0SbTKy02jNs5Q8GqwjmWV3o9MPp6uCqLldf7/dPEmD7gEtGg23bxk4
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYYPR12MB8923
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=MJGL0LYX;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Fri, Jul 25, 2025 at 09:05:46PM +0100, Robin Murphy wrote:

> But given what we do already know of from decades of experience, obvious
> question: For the tiny minority of users who know full well when they're
> dealing with a non-page-backed physical address, what's wrong with using
> dma_map_resource?

I was also pushing for this, that we would have two seperate paths:

- the phys_addr was guarenteed to have a KVA (and today also struct page)
- the phys_addr is non-cachable and no KVA may exist

This is basically already the distinction today between map resource
and map page.

The caller would have to look at what it is trying to map, do the P2P
evaluation and then call the cachable phys or resource path(s).

Leon, I think you should revive the work you had along these lines. It
would address my concerns with the dma_ops changes too. I continue to
think we should not push non-cachable, non-KVA MMIO down the map_page
ops, those should use the map_resource op.

> Does it make sense to try to consolidate our p2p infrastructure so
> dma_map_resource() could return bus addresses where appropriate?

For some users but not entirely :( The sg path for P2P relies on
storing information inside the scatterlist so unmap knows what to do.

Changing map_resource to return a similar flag and then having drivers
somehow store that flag and give it back to unmap is not a trivial
change. It would be a good API for simple drivers, and I think we
could build such a helper calling through the new flow. But places
like DMABUF that have more complex lists will not like it.

For them we've been following the approach of BIO where the
driver/subystem will maintain a mapping list and be aware of when the
P2P information is changing. Then it has to do different map/unmap
sequences based on its own existing tracking.

I view this as all very low level infrastructure, I'm really hoping we
can get an agreement with Chritain and build a scatterlist replacement
for DMABUF that encapsulates all this away from drivers like BIO does
for block.

But we can't start that until we have a DMA API working fully for
non-struct page P2P memory. That is being driven by this series and
the VFIO DMABUF implementation on top of it.

> Are we trying to remove struct page from the kernel altogether? 

Yes, it is a very long term project being pushed along with the
folios, memdesc conversion and so forth. It is huge, with many
aspects, but we can start to reasonably work on parts of them
independently.

A mid-term dream is to be able to go from pin_user_pages() -> DMA
without drivers needing to touch struct page at all. 

This is a huge project on its own, and we are progressing it slowly
"bottom up" by allowing phys_addr_t in the DMA API then we can build
more infrastructure for subsystems to be struct-page free, culminating
in some pin_user_phyr() and phys_addr_t bio_vec someday.

Certainly a big part of this series is influenced by requirements to
advance pin_user_pages() -> DMA, while the other part is about
allowing P2P to work using phys_addr_t without struct page.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729140355.GA72736%40nvidia.com.
