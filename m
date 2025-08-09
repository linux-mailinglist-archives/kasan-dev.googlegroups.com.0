Return-Path: <kasan-dev+bncBCN77QHK3UIBBBU53XCAMGQEPCEGJ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E7B63B1F4BE
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Aug 2025 15:35:03 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30b86eb2291sf2445714fac.1
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Aug 2025 06:35:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754746502; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sr8rFmIaDabkVMN2rGV9HChl4J9CsnWnSET5mexGZmOquencs1Gdse2C/HDtQZb9x1
         S/c5qjWbl9Az2eFqQnG6cTeSY511+/suFJKby+25RvnNK0f+akxo65jPeOGGTFYyJyT1
         5h1X18kwaQPda0V8MKA+DaYF/Hzu+w/cuS/uNojl4Aac5jyhdJNIFtDxbPIHGuCvdOlg
         ImnInotPYXjJamvqSqagYz7fWMq2X16VJ7peS3dcu5HsB5rChnaQ9/W3hSeXuWtguqc9
         Y5mcgEuuoDxsPd/L2YOhnbb+xJipjv0COo6Eq26sU6vsmiLaZAVRt8MeCARTcDFi0+pd
         XrBQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vyauQ2Q/jqpCiQ6lV6wwhN/wBYxqWMF8jsynqk9cMMM=;
        fh=emc89HsUINynNyMOXva0lkiRiIUXWT122AKORep6/kM=;
        b=PWuArfejBpXPvDGUs8p//xI+oZj2JXcDDIAfYojrGQDctMJRb4mQKL7HZWy++7RSH5
         oh3/tZ/mVyNaJ/GaInut6+JZ8xu//Q1DWpuJExfaaQgwmDbgrGHNxQClw6NBgsHf/fEF
         rsRXh3MhPxMc3Nhmsg0LwpxzxSsDeDA6ja+SS8YuYhwahT9RLwyr/Qv2jt6dRrK1b5zP
         2EClwLKDVaBV3rutujtXmmAY+QkP+7VuVu14JF6Bf32oBAXbqYjxVjhGt+j5UJIj8SjF
         ZT7A8vuEkHy4sczgemPuKSWxSYvQWs8tvljmjEhE0jXH+rdtaGbwDK4U4qyInR/k7ILH
         uJgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=ixJwxTcm;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754746502; x=1755351302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vyauQ2Q/jqpCiQ6lV6wwhN/wBYxqWMF8jsynqk9cMMM=;
        b=r6QZD8E9jWg5xjkoJMc/+y7VUfYQ8O+vrOa7uDKI33D0G8h3VCnDAzS6D84RznUqo8
         1pD2YsqhZ0hbdEWw6HROLfrYo+MIl2wlxr0dWhsuoHPwy9nhrCS+L68JoKwxBOFHN/G5
         WolQOTYJv8nLx4/QPGeZ2ysPITbu9N6tcbkv5RmiwRZFR/gFSJ2h5YDiEBkhdMQLjst8
         yTrRWh1Rfmxwe6l7rNxwnA0cgoFPB2qkhmXQTCq+eM6t0objZBF8fEndq2Zv9uX6A9TX
         +1/ynIAV54khfRkulUFutu7WM+g1VZmyrZ/T/4N+s+9c7um7xxUB360q3/lgbq0UcDSk
         Xw5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754746502; x=1755351302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vyauQ2Q/jqpCiQ6lV6wwhN/wBYxqWMF8jsynqk9cMMM=;
        b=Ca7azl3KMnHf2Uo5vU/Z9flfUbHoL8YRHq8R9IfIMYPeoG/P3HTSCeO0rDx5F3wti/
         piQ8gWy4bjf5j8pxF+DI7d+ryo285usiwqGJRHMlH9JG4To92aMgSueoejE7XGb9Lqzr
         2V1uXDVN0rFFh2W7I+7AbBePff+7HLhODuLaX28pPabqkPl9NFTuPG4yDJUgqsYNR73H
         US+9Sp6W3crjhmwz1AjYHLJp2tmFt348JSIdE3HJhsXCiiarzmclFNOkTLH/tcs+r6pl
         bdzxearUnzvOaTizabF5r5P1LFmJAudst/SRQctFIHxDgIkMvcobW8mtaUFTNe8wUZMb
         DSDg==
X-Forwarded-Encrypted: i=3; AJvYcCWunfawqC/XSr8qFTf/gu3p7souOI7/CW2/sB2bXJUVQwPtLy0nmkCvC6oWV25ST3Ga/a5Nuw==@lfdr.de
X-Gm-Message-State: AOJu0YzzYaMyjxyFaUAnj+eeW6L/Ds3+8+I0mz+ohzTe1P7r4d1Do0Zm
	yQ70Qsj2AhcYoXHZDuqqy2LQ1YxsLY2H3Vct6abSQk+U26p0nWBOxZPS
X-Google-Smtp-Source: AGHT+IHwflpoK0S6P/6tp0aPyy8Qyi2rHGYgxeTPfsX/ooQCGfr6fz+2k37OGqWAeM9WR3kQEfIj9Q==
X-Received: by 2002:a05:6870:d85:b0:2ff:9905:134 with SMTP id 586e51a60fabf-30c211ca847mr3561460fac.39.1754746502303;
        Sat, 09 Aug 2025 06:35:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1flkA3IZQD6bIH9RzFc76DyLVJ6WVKiSUL0EeY56oPw==
Received: by 2002:a05:6870:7057:b0:30b:85bc:4baf with SMTP id
 586e51a60fabf-30bfe40e974ls938916fac.0.-pod-prod-07-us; Sat, 09 Aug 2025
 06:35:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUaNfl1jI6B427ptdnrEkWmi7vyyqxTe5fCeizS7BnMhfMiA+vzhawWV4E3nBMQsxLxO6IlVu5lsSg=@googlegroups.com
X-Received: by 2002:a05:6820:811:b0:619:866f:76b1 with SMTP id 006d021491bc7-61b7c41e3a3mr3664715eaf.4.1754746501513;
        Sat, 09 Aug 2025 06:35:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754746501; cv=pass;
        d=google.com; s=arc-20240605;
        b=HqyZqym/Xb43Hxp9TOnE+yS9APKs7zCeTfeZ4NFNyRAZEumSjqbX88c49UjwTYLUmj
         xBWi/hEirn0Bq7Fg1Q1WANQEWWNRuJ6egldvATCd/ULC1u9wPpX7j4FCqZ4GBzLy3zn4
         OdspsuwaUKb26BfmnDb0fpB3u2uouRohDiX45iQa2zodjd2HLM6YEunzRa2/ZgU2dQYz
         9SI+td/L5iiToOOBaZ5n2pFz0ZFsLAAPdDIDYtA1yjP7gWLuFo3ximFL0D0phGxqmyaX
         OyQW0sfW3ZIF56QVShk2VL6zPwCil0J9IEhi4SXe87ur+ZdN4LI040UV8h0LLiUo2uZT
         ixDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=5hQwFjXQOmqNPj4Z17V9pB+cg3fmuvcbi4cPAiVbgUQ=;
        fh=V2v2wOTK7B95biDmlomC5DJQVb68W8dDVMwTi5I+Rf4=;
        b=VJuU0TspSghhKj0ZqZOIEIcyjPBCt/+hqSmDqvCZ9z5qxSwU5Xv78pLkg88LTQS3Os
         o7nkdxQoW94PxsTvOEJHB4eePKXyMsEloSayVs3Nnbz78L3BGUJPZgiLa45ZstwjWRUP
         6I8eqEWgTJLc19R2RzFdl6DGcuP5IvA5lgBZKu4q2Vfup7Eh8U7Vv5kf8AGnYDidKXmh
         NHKZs2LGlP1jxhk0ctjt7IYhvtegPq8DDly8/z7eSC/x9Kks1MVnUa8LYXRBj9tpHYc+
         YGlW/ZuaYRzWrehiGa8BI8+CzkubhlkFH3CnJeyaEJ4+RgoWgDY7vwrXYTR5SdMwWJS6
         fysg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=ixJwxTcm;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20611.outbound.protection.outlook.com. [2a01:111:f403:200a::611])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61b7c9a44e6si237033eaf.2.2025.08.09.06.35.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Aug 2025 06:35:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::611 as permitted sender) client-ip=2a01:111:f403:200a::611;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=LVWxGMpQHc+QFX0/tTrsQ+8oHoHhaaBptiFL16N9lUZjafg2Vwxo83jWrmIx0ys15EM9iLwa74lxSiyNk5ftshFT+e1Eta7JIqCOTCrW5byLiQBsfKVaCVBBzPup2XaTOnikWBB7vgKTU+z4zXiTNeng/jCqYBe2h2PYH2fwzQ3PKP8NSselMu8jizZmYlls+PHYCRS2pHfeAG3XPYxZzpJWN8N4qmR31PJItd4uPx4olthfFjDZ02xGEMNGj13mDybVgBPs2TerV0xYuzIS54FH+0SOXfMTRaQBcIHb+RSZ1q23RYtpQ+AgpWmPR1O+sGDFqziTlb5ldPoq5gKYOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5hQwFjXQOmqNPj4Z17V9pB+cg3fmuvcbi4cPAiVbgUQ=;
 b=S0eeE5f0L2EE2VBH3feGr3RpQeI9Jf7XwUukXfSWpH0rHI4Cbbq4k8XxHRnzfC3h7A9scNhTRHpB7NPASDxxAvsF2uVw8haHpy80o4tFiNNNIUw1ZrWJjHDZ1HkWrvT4659y433RL1/B32AmUWgHSAbFI2tU2kxcPmRuXX7k97ZcM1BUQ4rRwzn/DGDFShh03rW4LPHeitwa11rKRDFgk34lLSqUk2yOrJhN0A6/HuISK79BDAUQ9Ggyj1furszHvdXn3ecKKQh2Rkhx62Vk0/hAZ8KMsrpAQdp6sLgJo3ysePjx/XPBGuO1iqY+XpwavZOZCbPSJLUiTUCrjYqJXA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH2PR12MB4120.namprd12.prod.outlook.com (2603:10b6:610:7b::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.16; Sat, 9 Aug
 2025 13:34:56 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.018; Sat, 9 Aug 2025
 13:34:56 +0000
Date: Sat, 9 Aug 2025 10:34:54 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leon@kernel.org>,
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
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250809133454.GP184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <CGME20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1@eucas1p2.samsung.com>
 <20250807141929.GN184255@nvidia.com>
 <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
X-ClientProxiedBy: YT1PR01CA0136.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2f::15) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH2PR12MB4120:EE_
X-MS-Office365-Filtering-Correlation-Id: ea51f777-dd35-4f45-4aa8-08ddd7498728
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?U3E5Z09lcGdXblFaVVFad0VLYzdKWGJzZTU5V0ZwN1c2SEJ2cVpwV1YxZm1q?=
 =?utf-8?B?Y0hBSTNKb3ViWGVZL1lyNmRaVUFOelhBelJEdnQvbDQvTWpXTHhURENMOEZj?=
 =?utf-8?B?R1grOXQ0ZG5Ma3hGU2NwZ0xJamIyaVhwRjcwSXJoa1ZuaDhqRXRPMGs5dE1v?=
 =?utf-8?B?T2wzK0huNCtXUnNlME81dW1pak5ySno4TTZyYzJaNFBVbHF0RWhmZ0ttZnRM?=
 =?utf-8?B?RnBpQWozaWRMak9BZjBaRlRGdW1rd3JtTDVIVFFhUHBETEZ5R3UvTjkzdFRl?=
 =?utf-8?B?d1FYYkZ2aUJxU3BpWVNZUVlSdW9yYU1GbTBHVFp5MXVoSXZIbFE3WE1yUW1G?=
 =?utf-8?B?N0YwaU9OTEVnaXZKeklrYk1OTVFJclVVZ25xRTk4VE9HMkJQR0tRZjBMblRO?=
 =?utf-8?B?YW41b3pnd2wyNDY0U05hQVMvY1N0SVVQT3JUMmFZcXVLbmxDdkhsZ0NKK0Fw?=
 =?utf-8?B?bTBlUVMxRlpoWWRDYUJIOU5vZzlSTDVvZTk5Y2E1eVZaZFdrUC9rN0F0L0Vk?=
 =?utf-8?B?WVdEOThFelpDdzJXeVlFcWVCZjMwMHpXQVB6YTlKSFdsMlBWRndwV29JaGpJ?=
 =?utf-8?B?b2ErNVRtY3VjTUIyMDZtc1d3THJxKzBYNlg3eFBxSmFwbzlJOW04Ni9GeFk3?=
 =?utf-8?B?eVlaVW1iakpKN2ZMQ3dDTTBJelFINVF0Z3djWndaK0U4MjdYaXR6eCtaZVJq?=
 =?utf-8?B?N3h6VndrZnhFYVBrQ2I3OC93eVVXRzVWUFlXbk4rU2RyQ2ZnU0JPU09nUXEz?=
 =?utf-8?B?MUNvNjIyeWZqWDZhdDFSK0M3NHYxTkRNRkovZzl2cTd3RGhBZThpSkFWK09J?=
 =?utf-8?B?UVkrMkhTWkgvanpUcTcwMFRieVB6NGk1VTU3NjFxTVZlbXVqMWkzYVhxb3Ji?=
 =?utf-8?B?YlFxcFRHUUZBNTdPc3FxVlJkVkhMbTlKZ2ZRUDNVOHZsMzFrS094TStiRUNu?=
 =?utf-8?B?Snk2S3ZZRThpdXFOQXZRb25jQ2orZHdtNllFY0xSUnM2LzdyYm5FYXdWT0tO?=
 =?utf-8?B?NUptdVFQU25WKzNBQ0Ezc3pqd0VSMzlIejNJSVJDY1VHTE5IUzhGamRBTExt?=
 =?utf-8?B?NFIwMnh5bkxBb1BoeDUxdWtlUnhKZTBKS2NwT2MweDI0eklrSDl1WUo1TG9P?=
 =?utf-8?B?bFpROTRGcU9MK2dabXpiUThLZ0NHc0tScUgrK2hSUFFJaDVRV01hN2xMZVBI?=
 =?utf-8?B?SWZQSUE2cnFmTC9aMHJzREE3YjhLNG5IcW9XZzc5K0RiRTh4Wmk0bENHbUtp?=
 =?utf-8?B?NVRZRElsZjhLOFZJbkJ2OWQzeUVIOVU5SUZLMWlSaUtFTG1HZWF3RVVJQ09u?=
 =?utf-8?B?N1c4SkxOV0N1SDIzcWQvdmNzSGtqbGtMOTdRWVB1NGp3S294enNqY1Njai8v?=
 =?utf-8?B?RTNod2U2N3F4QzZDVitscFN1K3h2VjNIcHFKNDY5WXJmQTd5eUI3aWRZaEFE?=
 =?utf-8?B?RHRuY3lLcXZKa3pkMEhkQXk2OEFicE1EdisyMEt1ZXJxTElVNXNYZWRseGV6?=
 =?utf-8?B?WC9IRHV2MlVLZ3YrZk5EdmdPTDNSNkRPeVpKMi9xdW15RGsvYzNadlV0eUor?=
 =?utf-8?B?UjBMdmNxMC9yNkp1MDNGc2RSODU3NzVTTytySmNkcXJ4TmJCSWNHdDdLRmpy?=
 =?utf-8?B?WGpHVEFkL1FvdzlNRkk4bjlXMCtCbDR2UWw3NmpUMnl3QzUydFJTOGVxd2w0?=
 =?utf-8?B?UktRRUN5M1NoMjlEWThpQVpuTURCM2Jvaml6Q2pmbkZzUkF1MnlaUlRNNHFK?=
 =?utf-8?B?aURCd1lxT09UNU83bC9yaGlNNDRnTDZZUVhrVktweEJxcXdLSUc5MTM0TDFn?=
 =?utf-8?B?Ym9kU0VLLzc4UnI4YVFEUUU0QUVIemVnSzA4ZkNPdWFMME11YUpjOGtsbndE?=
 =?utf-8?B?MGkrN1ZHNFRaZDhoS21ER1U1U0RTNnhWNVBzVUdkOUljOWk3ZnJBSWFNRjFq?=
 =?utf-8?Q?clzIDg9uv2o=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cUlPQ3Q2bW1obUhaZnE4MTdVVlpBcVlKSkc3OWdGMHE2N2prNk1JQjRwTVMy?=
 =?utf-8?B?M0RZd1VqN1RIK1VLMVN2emZaRzNkSk9iSjZ0bUZYcU8wczFkRGtKeTRqNmJ4?=
 =?utf-8?B?Sjg5OUZVanMzM0o1U1RkVysvcWFVSTRwV2d3UDUwVUhGaGhoYmNjT1BwWThm?=
 =?utf-8?B?VXlsMGlidi8wZmc4MDQ1T21FYWwxa2dpbHlESEM1SGhIM1JFeDNFQ1NZL2JC?=
 =?utf-8?B?cGhFekdyTnlZdlpCVUhwOTdhYVI5WHJKVm9SaURENHlWNUVxSzlRL1V0Y2tr?=
 =?utf-8?B?cHhsY2lHSFN2WFgzSjlUVXo3T1g1cWlocEFZMG9maDBSS1ZuckVrVXVySDJn?=
 =?utf-8?B?NFpnZnZycnY5dU1ra3RNd0g0Q0JKY2hNVWRrRTFaMDh2b29zdGlneE9DOTdi?=
 =?utf-8?B?WlNjK1pHbFppekFqSWR4M3p1dGxwbGwvalU4aS81Sm1VdkVwSmR3RlVOcjFF?=
 =?utf-8?B?RUhjYm1WNVlxaCs0dThjOVRnZk9mOXdxWWk1S3M5eTVVcWphQ294VnFaNDF1?=
 =?utf-8?B?T01OYktuQzR3QWlnQlFoRG90dkJpbFB4K05jZnBDUnVBRHMwdURWVi9VRjhZ?=
 =?utf-8?B?OTduOG5Ra3JLeHI0aWMrNExRaWhWK0kxM0pQZDUxam1PMFhSTG9DanFiMTZO?=
 =?utf-8?B?YzhTb3B3d1FQVEd3MzdzUUh3RXFNS2dnMkdrdUUyc3laWjhaQkVDWUFxTUt4?=
 =?utf-8?B?WVIxUkdoUW80NVUwZldDZVIzZXB4TXZ0Q3pjQjhNOHNOK3hBYndrNkZQelNr?=
 =?utf-8?B?NTdkdGpYSzhjMDJMZEw4TjREeFg5cFlsV3pmUTlieU1oYW5ZSzF5MDJGTzlp?=
 =?utf-8?B?SC8vTTBuRTlHTytOQTdvWmNjaHdvYnNsYzN5aGI2Wk9ld3NjN1NGemxjRysx?=
 =?utf-8?B?bEl2NERCQndsTUF0emNaYXVKUHU5TFR3dzAwOXFCczVxYnNxeEVHK2F2Njkr?=
 =?utf-8?B?MlFxSU1FdzB6K3FCeE9Wb3RiZkVUMXhCMHVKMDRIMVZ5ZWhqelZZbWhsY0Nq?=
 =?utf-8?B?TDF4bmV6ckVCSWc2aVZicGZna0ptTFpmVGZ4WWVheGhuZjhxQVFZNnBqdkc3?=
 =?utf-8?B?ci8yWE1RRjhWR1MyMEpHWC84eFZWZmJJa0ZhM0RzR0ZnWVM5SnE4UERZTnRH?=
 =?utf-8?B?WEdDalhKd0JoVW9iU0RqNXRLNlFDZ2NiVTdhcW5PV3VaL2JFNkVCT1pLWlFR?=
 =?utf-8?B?eUxzSW1kcG9CblNOQVRMZWcwdk5jMURrZk51MTFFWXg1ZlBFc0Y3U3MydGo5?=
 =?utf-8?B?b1B6ODJkaDVCVVV0VUgwNlFvbU5WUEQ1b2FvK0F6Y1NweUhnblErWkpmbXcv?=
 =?utf-8?B?UDZYUUVCSzk2RHVzSWx0V3gyZ3RGTDU3cTBIblhEbWJtVVFsRGxCVk0yZEZk?=
 =?utf-8?B?RTFzQjJ2MTNKa3drczcvZGNtNUE0b0lPMmVON0pPL2pIaG14OTdLZExtQzk2?=
 =?utf-8?B?eXFCbWkrNlVIdDM5eEJLWmNtUithY1pqVFVZWGRVeExXMldhNjlVTXBNSzAr?=
 =?utf-8?B?aUVHZDZsaDJSdXo4dzJ4Yk9KOHRyaEJHS0luL01uNG82bllEaWhETmhRNjhQ?=
 =?utf-8?B?OCs2U2dlUWhyeFZGbVd3TElrWnNaR1RLTkRQVEhBb0xvT05IZjJQVWhZSVBx?=
 =?utf-8?B?eU5RNkZFanYvODZEaWNEK1VBdlRRcmRwcitHNGJxbU9UdUo1eHlTempVaVZU?=
 =?utf-8?B?cDFsbnY0QXE2TCtFMlorSVJSWWZaVEl4OEZZUzFnWGV2ZjlQZkxTZy9Nd1R3?=
 =?utf-8?B?cFBHWmRnb2FHZmZZejNKZHlobFhaNTJsV2Jyb2lkK0Rxdzk4SFFabFJjSjFt?=
 =?utf-8?B?MC9OZ2d3dmdrUVBJK1hkZHIwODFPdThwei8rUXJ6NlJCOW9UY1VMOWhjZjN4?=
 =?utf-8?B?QWRZMFJOVkN3YlFPN004U2I2aWI3OWhpUU1CaFUvSmVnOUdEK3Q2cGVRQmh2?=
 =?utf-8?B?djI4Mk5vZDBxbElxMVowc1hXTys0cWgzbjRQK0dEc1duMmhxc3FjM3dXZTlr?=
 =?utf-8?B?WEt2SmQ0Z3prcEdtRjJ2TldKMEowYUN6ZkRNVnZ6azkwdm40U29selB1ZzdX?=
 =?utf-8?B?bGM4MHJUbzdsdW5Kamc0VkJHaDh3d3plRVVOdVFYMmcyMVBpVkZtaXdodnho?=
 =?utf-8?Q?MjQ4=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ea51f777-dd35-4f45-4aa8-08ddd7498728
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Aug 2025 13:34:55.9153
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 6Ly2R1iyYEFH7E0g275dSDdE+KiUwr3rSanp+t+S8WiLKTigRjsg+luIZBAobiS3
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR12MB4120
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=ixJwxTcm;       arc=pass
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

On Fri, Aug 08, 2025 at 08:51:08PM +0200, Marek Szyprowski wrote:
> First - basing the=C2=A0API on the phys_addr_t.
>=20
> Page based API had the advantage that it was really hard to abuse it and=
=20
> call for something that is not 'a normal RAM'.=20

This is not true anymore. Today we have ZONE_DEVICE as a struct page
type with a whole bunch of non-dram sub-types:

enum memory_type {
	/* 0 is reserved to catch uninitialized type fields */
	MEMORY_DEVICE_PRIVATE =3D 1,
	MEMORY_DEVICE_COHERENT,
	MEMORY_DEVICE_FS_DAX,
	MEMORY_DEVICE_GENERIC,
	MEMORY_DEVICE_PCI_P2PDMA,
};

Few of which are kmappable/page_to_virtable() in a way that is useful
for the DMA API.

DMA API sort of ignores all of this and relies on the caller to not
pass in an incorrect struct page. eg we rely on things like the block
stack to do the right stuff when a MEMORY_DEVICE_PCI_P2PDMA is present
in a bio_vec.

Which is not really fundamentally different from just using
phys_addr_t in the first place.

Sure, this was a stronger argument when this stuff was originally
written, before ZONE_DEVICE was invented.

> I initially though that phys_addr_t based API will somehow simplify
> arch specific implementation, as some of them indeed rely on
> phys_addr_t internally, but I missed other things pointed by
> Robin. Do we have here any alternative?

I think it is less of a code simplification, more as a reduction in
conceptual load. When we can say directly there is no struct page type
anyhwere in the DMA API layers then we only have to reason about
kmap/phys_to_virt compatibly.

This is also a weaker overall requirement than needing an actual
struct page which allows optimizing other parts of the kernel. Like we
aren't forced to create MEMORY_DEVICE_PCI_P2PDMA stuct pages just to
use the dma api.

Again, any place in the kernel we can get rid of struct page the
smoother the road will be for the MM side struct page restructuring.

For example one of the bigger eventual goes here is to make a bio_vec
store phys_addr_t, not struct page pointers.

DMA API is not alone here, we have been de-struct-paging the kernel
for a long time now:

netdev: https://lore.kernel.org/linux-mm/20250609043225.77229-1-byungchul@s=
k.com/
slab: https://lore.kernel.org/linux-mm/20211201181510.18784-1-vbabka@suse.c=
z/
iommmu: https://lore.kernel.org/all/0-v4-c8663abbb606+3f7-iommu_pages_jgg@n=
vidia.com/
page tables: https://lore.kernel.org/linux-mm/20230731170332.69404-1-vishal=
.moola@gmail.com/
zswap: https://lore.kernel.org/all/20241216150450.1228021-1-42.hyeyoo@gmail=
.com/

With a long term goal that struct page only exists for legacy code,
and is maybe entirely compiled out of modern server kernels.

> Second - making dma_map_phys() a single API to handle all cases.
>=20
> Do we really need such single function to handle all cases?=20

If we accept the direction to remove struct page then it makes little
sense to have a dma_map_ram(phys_addr) and dma_map_resource(phys_addr)
and force key callers (like block) to have more ifs - especially if
the conditional could become "free" inside the dma API (see below).

Plus if we keep the callchain split then adding a
"dma_link_resource"/etc are now needed as well.

> DMA_ATTR_MMIO for every typical DMA user? I know that branching is=20
> cheap, but this will probably increase code size for most of the typical=
=20
> users for no reason.

Well, having two call chains will increase the code size much more,
and 'resource' can't be compiled out. Arguably this unification should
reduce the .text size since many of the resource only functions go
away.

There are some branches, and I think the push toward re-using
DMA_ATTR_SKIP_CPU_SYNC was directly to try to reduce that branch
cost.

However, I think we should be looking for a design here that is "free"
on the fast no-swiotlb and non-cache-flush path. I think this can be
achieved by checking ATTR_MMIO only after seeing swiotlb is needed
(like today's is p2p check). And we can probably freely fold it into
the existing sync check:

	if ((attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)) =3D=3D 0)

I saw Leon hasn't done these micro optimizations, but it seems like it
could work out.

Regards,
Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250809133454.GP184255%40nvidia.com.
