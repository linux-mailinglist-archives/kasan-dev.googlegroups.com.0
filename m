Return-Path: <kasan-dev+bncBCN77QHK3UIBBGX6UHCQMGQENHCTEHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4A7B31B95
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 16:30:53 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7e870623cdasf504435085a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 07:30:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755873052; cv=pass;
        d=google.com; s=arc-20240605;
        b=EvHxcI4H+ppIygkaKPk/smd3gNn7koJz1hhfh/suI7f0+n0Of6aoKTsge4j0/M2FpQ
         CXeCwYeCa5pc/ZCFCK1KRAXz3XISIPeegDapvbGEYuEaZMuYnVa54NmbpoE7SqK9K+IE
         RkSTQZTskLCUX40Of97cwGc/cm8Jhq58Drs6Yi+0UMJKpgWCjPPI+1BqnpgYmjKw5Z7P
         ccOOdJ9yWC2NPiXWEMYLxvwiDsbZkSJFa26wY6UAGUhuhNitxuYerRi5zeLySBY6VUMu
         Diu1OOfQ1SbOj3iR4IJSfVieTEXYpKgkIuYEOWS+bkqBfACmfSveOSenXAZCnvVnm31T
         6wVw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zapeKZIKsPpclQoqgP0vZyO2ADlYcgkAz41taECUl6Q=;
        fh=QmvPhhzzJDK8ifcXfqMiMpobwt5GqbxzRfN6QECbw90=;
        b=NHkoc7M3TvvWwBPpEzC2xjvs3NsuUmDJn3t6tnwxqfuY0PBaSpzpbIcJZMGNBI8kYk
         9luL1HGwesnyrkMDbulqtIQAQcmdonwfoz36RU8R1hyC1tCVdiWd4+ceBVq8eC1jM+BQ
         hfYc8JEavx/dseuzDpcWRW43mMcOQbrGIoiOIpfJtmwEM2eitVzyN+W/IjM3qXNe/2Xq
         5Rt5o6zLTrsstxeimcF41Xi6WwW/q/69AwZ0r/xxVeSDGZTY1nGwfJQtvC9b7917VwY2
         Ty2nML+mb4AUXl4tdo4JJ7+FDU48rkCoGkJ07hraVSlx+vP7fzVdvAWu92EdiRBjtBTQ
         Ss1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=uhOaTwj2;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755873052; x=1756477852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zapeKZIKsPpclQoqgP0vZyO2ADlYcgkAz41taECUl6Q=;
        b=rLqZfZGMv3ynD/h3nu71VnCZW2HmnXfHWD+mfYsnfTTiIiM6ILuZHQpTT4uFpq6LJD
         G6k9gAE0NK4ezht11zXvDsw6tgb91vXMVo2WOjvY1NQXFvMQUoJofRewoXA+/UaEk9Xo
         UMdj+4gm1GMw3go3/lOvWhM3SC0lQrEl4151bB6sSclJvFo3pa8E4EstVEo16r9R6xUl
         tuSut32W12modYl0kvyJseEx5KA4tB3+L5x47aEQ8dtgJ4h6BsBnPpKCXFumOuI+Lb75
         +K2SpY5YZLixP3Pa5sy0QsjeO1YCJYd25LqB0LtIfSAn0KriZMjxbzgEgzLvIx45Msov
         Pbqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755873052; x=1756477852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zapeKZIKsPpclQoqgP0vZyO2ADlYcgkAz41taECUl6Q=;
        b=SXTtVOATXJrK3VqaTypjtJ9KxXrc9qLKOntyKO7/KHy42YeUNY79UDxKi9ydHcgCPp
         G6Zrnt/o+If7OV/+tU4G4b4vnKfwyslJUTnnaD0K1tM/2K7amPTNv4VaRWgGkENkPhqW
         ZczFJduuO7gCh6BpqVbiy2OwKfqISbFXu6JIdOwQnNQlWXFdQnMYd7oJTPk06hldpdCL
         9rzRC4vOO6gjy0/6LfwIwABk0Ak3qQzH747hgqDdn68afK3fWtcgQy3TcX0x1PtK+/yJ
         OB+/ARPFVVDcarTVY8zKywdDjyvuCOiPNYxJ1GSrRi2TDIP3vVx4BY8d6GrIyYGMfKIr
         hASA==
X-Forwarded-Encrypted: i=3; AJvYcCW3zNemlcWhqeEjFhdwjB4K5gG0oPkEbRfpXRzWml/sjlXUIwEoevVSkGuR2KKvaj5Hinppbg==@lfdr.de
X-Gm-Message-State: AOJu0Yz1xSnrBwwIHJe+2EqaCCrFCVym7BT9VclJDO1FUwqO5evVxkYZ
	otcIjHb2v3WEJzeEWNtOjk7juCB5Flta0UopR/Zn6ylyXYOKTJ1S7xKD
X-Google-Smtp-Source: AGHT+IHIphpuqJxe4/jcjInC00bxereYHmTyzst35cG9LSW1ktSJVkkp1qN2M2TrmNUFvZnGomH00g==
X-Received: by 2002:ac8:5d48:0:b0:4b0:7d7c:7ae2 with SMTP id d75a77b69052e-4b2aaa7ffcfmr36521931cf.20.1755873051157;
        Fri, 22 Aug 2025 07:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcb7Xj0IrNJddgRJ0cWWcy/YnwuBettZwjyV+91VQ11ew==
Received: by 2002:a05:622a:1445:b0:4b0:7bac:ac35 with SMTP id
 d75a77b69052e-4b29daa4c0als36142221cf.1.-pod-prod-05-us; Fri, 22 Aug 2025
 07:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVtgbU6uuvSKDEaq431aRGoD6OC0ubDdG3+7rPM2FSMlU8U1itYZ/Qhk0n/37d+vqOKgAFenb8nTGE=@googlegroups.com
X-Received: by 2002:ac8:6f1a:0:b0:4af:15e5:e84 with SMTP id d75a77b69052e-4b2aab3b2bemr35225921cf.42.1755873050101;
        Fri, 22 Aug 2025 07:30:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755873050; cv=pass;
        d=google.com; s=arc-20240605;
        b=EI6j2rcFzDOE69u/m2SGC/2vpl1V3D8AySpkibOj4HM/tKK1YUePZ38vQ8K8ylucZd
         bEHpKh6o8RQZqMj82KBxit3WFkY8usUpVQXdaQNB5ErVEf9zvKdd+7WcjXjDsANHrDdH
         XE34Aae0HleAwjXB9LrGkAkgWsH0ql8wXGSWWQw5z21/NQ/X4+IUjkFrGh/TqQsxqENz
         QZZQU08Qf+VnTDAzWnQUe5l35LbzjvfVDqBlN8qW+UeSeioGfR5CGDnvPXtE1CS6CS74
         GJNCskuRETB3kX+eNq6jPZRzwUhouxYngIVDmph3O3CnK5Wb3ymExtuCSMS2hgVY3Lk6
         jwkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ACOf1O1PLD4ZSCVgv3MS4fsXCYCqkOYdums6O1hrUrY=;
        fh=UBgNx/Egx3cnuBexSBEJYqcN4QiD+KRMYC2Iqtu0Qi8=;
        b=WoPd8kQw0ok63VRugTLMPjJpTXbcFXCDSSVlh/ZyipfwAVPRDAdH3SqMPLPqq/dQdt
         URiaXI96oZFwlw8NI7w7QVL/RcEZ4+COLRcvILpnjJfJw/JQyKhZU18bcdIuw6T0O93i
         jFNMKXOt2VSpm5ZNAOG0fm7cCdB2/i7JLZvKiZgIBZpDidWQRoWE73tKC6uTbSM8ijx2
         n+Sl8sq4pHTk2u6odSOOYqL4cnHhOe8lsI8tDS/1ZAzfGgWshrSKJ0Szi6Kyo6D2ECwt
         eg2I6ksTpagGw91K3EKzPUF6V3hdzattHIK+93rLDQvD6bPMbp0WiPpv2Zglr+yCDpDZ
         5cyA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=uhOaTwj2;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2060d.outbound.protection.outlook.com. [2a01:111:f403:2415::60d])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8d774f3si55491cf.3.2025.08.22.07.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 07:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) client-ip=2a01:111:f403:2415::60d;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EpHCemWmGaJPOCO0fywXNNlXtT8gkDIzfWloxU9oFpXbEBiImI/1hxOEI+yoOQkkk8ArWwoY2nS0Bs1DDvJ4wD34j7EW0rp5YJK6dHDbvVbWo1Fl7ki4RfhZxA41Vob/rJXUpsU9NshMxeBF7/1zDPHJw5UD3aPqV2qpkSr1MxmIGP3CRJxUiYlZPEvXmF2ulY0A22uoDpp6944htt/QYVxdRS1EBbiMGeIlOccRF1EeprX4+5QgP+WnECtx0PaZIngbSHNpYWuh1JsVnqnJK5y0hwa+UFZCs+ZLAL83dqXGrYaGD968JHGRKkXO/vEO/mq90ton4Y12evgdDDJoHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ACOf1O1PLD4ZSCVgv3MS4fsXCYCqkOYdums6O1hrUrY=;
 b=RR4Rep2Ibzmq0uRyXFyzbn9KdLkutEAHnkWNZ53MV8A1El2BkrU4y2GE3dswjLuGLfclWd6C/ur2z80xZQUiwBBxIN3E56vyjVT0wddNcj38rIGaYWEDTAT4f8aepSAzxdjFBApVX/MVvHFS4n0rd6skoYgXypull4yfPtGCGNlSuKct0mRzQhcTf8pZgFtoIFmEeOiX38K8sEcMdphWUK7YN/m/T7i/xeI8MRnUaH0ZKt7BbDmZ585vFntfuj9xh9mLUJKnKBuhdUxktznB1lcI2Ouzo4Cawa5rNGxJFunQfRALdtBdaLnbvJp7a5MoE2KIvegGo3r6ka3g9+C3IA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by DM4PR12MB6591.namprd12.prod.outlook.com (2603:10b6:8:8e::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Fri, 22 Aug
 2025 14:30:46 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9052.014; Fri, 22 Aug 2025
 14:30:45 +0000
Date: Fri, 22 Aug 2025 11:30:43 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Jens Axboe <axboe@kernel.dk>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Hubbard <jhubbard@nvidia.com>, Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Brendan Jackman <jackmanb@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@gentwo.org>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>, x86@kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org, intel-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, linux-mmc@vger.kernel.org,
	linux-arm-kernel@axis.com, linux-scsi@vger.kernel.org,
	kvm@vger.kernel.org, virtualization@lists.linux.dev,
	linux-mm@kvack.org, io-uring@vger.kernel.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, wireguard@lists.zx2c4.com,
	netdev@vger.kernel.org, linux-kselftest@vger.kernel.org,
	linux-riscv@lists.infradead.org, Albert Ou <aou@eecs.berkeley.edu>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Alexandre Ghiti <alex@ghiti.fr>, Alex Dubov <oakad@yahoo.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Andreas Larsson <andreas@gaisler.com>,
	Borislav Petkov <bp@alien8.de>,
	Brett Creeley <brett.creeley@amd.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Damien Le Moal <dlemoal@kernel.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@gmail.com>,
	"David S. Miller" <davem@davemloft.net>,
	Doug Gilbert <dgilbert@interlog.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
	Jani Nikula <jani.nikula@linux.intel.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jesper Nilsson <jesper.nilsson@axis.com>,
	Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Lars Persson <lars.persson@axis.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Niklas Cassel <cassel@kernel.org>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Rodrigo Vivi <rodrigo.vivi@intel.com>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Shuah Khan <shuah@kernel.org>, Simona Vetter <simona@ffwll.ch>,
	Sven Schnelle <svens@linux.ibm.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Tvrtko Ursulin <tursulin@ursulin.net>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vasily Gorbik <gor@linux.ibm.com>, WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>, Yishai Hadas <yishaih@nvidia.com>
Subject: Re: [PATCH RFC 00/35] mm: remove nth_page()
Message-ID: <20250822143043.GG1311579@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
X-ClientProxiedBy: BN0PR04CA0184.namprd04.prod.outlook.com
 (2603:10b6:408:e9::9) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|DM4PR12MB6591:EE_
X-MS-Office365-Filtering-Correlation-Id: d3ddd353-fedc-4b8c-944f-08dde1887b1f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?DdkQ1n08o6MwOJbucunbwqZv1Lt9Bxc/J40IJFQH9OUi8FHycBEvpJSyEHGI?=
 =?us-ascii?Q?SNBeMGD3R96YLB+KSVcOKZF8wkL8hzquftLr36iMaPjh4RXmGB24FdvVAOs7?=
 =?us-ascii?Q?w9Cl9kbXNZWAbrhF/YP/fsYoPsc/5+ydhR6Oos1F0eIohWBk20g/MuI2Folv?=
 =?us-ascii?Q?TcPDxaquS+GqqQ/lI8iwoTPaeDHDAVie0FNGWKgGOiUHmpzAl+4oVfageQxa?=
 =?us-ascii?Q?v8vjgO7uoB/DyS1NKywLY5O6ImQJICZTCDWKPH2BceBmdp+gTH+FmQ+dGtFW?=
 =?us-ascii?Q?YLfj3Nb38v5RvhqeNeIzQ2ajqCv/7ALh90D8Q+6fL3yPB0R5RtNTVFpnraPc?=
 =?us-ascii?Q?ZgmWPm7P9DZAKs00Nws4VXuzUxIR3qfc5hEZjiEt054RuW/LkUYzs5qnh05J?=
 =?us-ascii?Q?VqJtL7OC0enzfOZHexNLxo2BKNq7Bb49mL182hd4eoYuUAf8WnntkdA3Np2P?=
 =?us-ascii?Q?5RCF6F4crNzpsPWzSq3jel9Pvl/TaRBv79PJ18s86KDusUepBt+ByaQrA55S?=
 =?us-ascii?Q?xEl7LYM4axrSyLxItnO6Q1up/EkoxpiNON5LaW8755cV+CjHdmVWrQbhTgvm?=
 =?us-ascii?Q?2dtvlPCO7pNdHB+If9iX5c5ZuvJkrrZ/D+j19Xh8EZyJinO7SRQieitUNB4V?=
 =?us-ascii?Q?FOUITKSVddPppo+w7jJDl479aQ2y/ktaq1bF/orNHknEHq3E/iGBZR0uKjxy?=
 =?us-ascii?Q?2/aD2VVcXFR7f8gGIxqAntXZbq6nlSmK1g+hBrccG+XLZnedOPY3fBWAaiqD?=
 =?us-ascii?Q?K9/hYE8ZKNPVhZ2dMymvKmh4p76vhQP8P6NvtPVFnK+uK48lux0i/7sLjtbS?=
 =?us-ascii?Q?2Yaa07LyakI+P3FZWtC7Hj/1pjaQmY+6Kex8qWc88iEJ9gtCpLNflD6+FqJU?=
 =?us-ascii?Q?g7oMliTYjv4NphFxoiLyTqv6h6IM5FVIBDxYks8hBDTHqUwFsQpxF1c+clF2?=
 =?us-ascii?Q?NT/XJS9/5RgdyRBxMdvQA4rPNv+WpFBwVt/7S6dELmz9etf3n52laspmp/qO?=
 =?us-ascii?Q?yi4VnDG4+k9YSlpuD56eNwgikq0Fj1X9aP6cCoApB4HoexltCh2x+GfbE66G?=
 =?us-ascii?Q?wD8DbP9GMAATAA2C+yWG8omlcIADkQ82VMNDJm/IQEqNnpW5kDTCcLImIHA6?=
 =?us-ascii?Q?oDbwinZXUYbqmyUHzo8Ha3MrTwPnlO81aMAZ41cPavJQm6YsxHj34peTZg+O?=
 =?us-ascii?Q?mANFCb3Px0IpmZKulMWhUIussglyTd5wZmyIHTu7eMkxRXBLn1tqREUmcSua?=
 =?us-ascii?Q?CzNq0Z8DKCEksCBDhUFxb6CfVA+q99arZ0MSWkT3e96oPY1ofdO0Tfj6bOTP?=
 =?us-ascii?Q?Bs0Y5njDVElFsS7VI4366nTxyqvk/dc3/XpHjFicET/4lXBP0DbF9q/h51C/?=
 =?us-ascii?Q?tQFz6Z8fLz1vLNW/dM94pH8bwEN5kojzyYZwxaMR+IPkoBtC6V79aFtRC9HR?=
 =?us-ascii?Q?QRgxTj29Dhk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xsmiQxApSOK4Oh/idsdA7WuEOm+1DXmH25mMSNxi7dcpWvKf4jssrz+7bcZL?=
 =?us-ascii?Q?x+rdJVjeEChZHdfVt2a4cx4iyENuSUcgI2y5hg57xigoM+lcTQMZ9GYWMvZP?=
 =?us-ascii?Q?wdohwx9jpz5bbmMS6y5EZOfSJlGXNTboPWSs9qOitXXq5BwmrwpAAQdqCoWm?=
 =?us-ascii?Q?CTZvmg2erApEuGo8D9UYQaGLMpsAtjBRZfqsyeD13HOWEM7ja+NiCTrdfO9/?=
 =?us-ascii?Q?Fjj1VbZkZtEd9YTZQ3tGEbl89+X99EWOAjxS/QDvE+WUNLc1pl9lvKK2PiLV?=
 =?us-ascii?Q?NjHz7PvcLiGP+XXAA1AwAL10EgxkazPVOlErLFc4j4i3Gxher3zLRlbepAWB?=
 =?us-ascii?Q?3bKK/vZJuPtMRhjCh3pAl6KvXoWXAb6i38Nyw36AlzjvrjOZ3YFH4qKbzjsZ?=
 =?us-ascii?Q?ZHt9Ld/oOaR4J5wrhQRYZWFSZCXp1sNw09+VMTXsycX+GbzDaBNhVU86e0v0?=
 =?us-ascii?Q?Vf7FPKTEBfXgymnt7U2aEQGjHjC9WFt4Vy4TXpNPYuMEfHfvpHWNikbxuMcc?=
 =?us-ascii?Q?Qv0hCGIpryIyox2sLFMS4ybWTixCsmwFPTRzQN1CswK1CaPseFThZl02azWE?=
 =?us-ascii?Q?WVslweXg4JDEvmXU0gsMaVZA+uYCDpPiNO8hzx4WuN1kBe7+4JP4KgeLG4bi?=
 =?us-ascii?Q?y/c69gYSECaiKxhzUOLYbsZvZE8dqMOrKRTxXoluHU4/bSBCN5oo93cPWX1W?=
 =?us-ascii?Q?Nzw+D11qOJb8n4oqCbTq7nXKMOqxpZgNL4KI2/QF4y90NvWMRRXkNxJNq+fu?=
 =?us-ascii?Q?RGjGZWVJ2Sp0J4qyspZRL0h8kwm5p+dSnCAH1uptWx646s3iMTDKATOXRPR/?=
 =?us-ascii?Q?p195PaTdb3U0qFCmzkajtl92Qlyx9SuE8jrVrb4y+eTYsT7SPQtfBC7Umr50?=
 =?us-ascii?Q?LzzvteYDH3ET2rzIDCqd9wwFhBfPdn6NjcJ8GL+99cnLswXrG/qfvmVVlOgR?=
 =?us-ascii?Q?j6gWF81tqKjAejC+UwQCze8SiK0sJg/ctaLsj1mnpde90672ONRsatw32jsx?=
 =?us-ascii?Q?bF1m0IUNRiqoq5bZ/h6BsXNUQXFapFEepJjVyn+YF23bife9YzkCHBMVIPLy?=
 =?us-ascii?Q?ga6qhGMz0jEekA51Kuur9heYC3IrzWw6dk3MA/wXU1rA3VOI5U+mGbYsuRNa?=
 =?us-ascii?Q?Z2QoURa4itA3Hb29reyvswAPz5915GgA/3z84OdyE4yHBhDnyVvzh0Lpvuwe?=
 =?us-ascii?Q?h7ODJJ0E9H41cNzPeQLlugohIrbiEuhI3YerwZjJnWnjJLIy56V7WuvXHZXZ?=
 =?us-ascii?Q?gMNKV5jyqwnav29TIRsHyX0S7BTcQ0CLkKTdhtS1uSni+71S0L1+AHD3X0sR?=
 =?us-ascii?Q?EadQQpIo/RhnlZ/EsEZUPhmZKH9zbIgP0NUzyFNlyPZ3RcMhXvIWt0iy2seB?=
 =?us-ascii?Q?T77nJtogXXrEdpwCN1PY4Z4wJytJQOoAdA7yt3zP50ipO/3AyPiZPT49lj/N?=
 =?us-ascii?Q?rU4EfnV/ZxQ5csyQ6jAtcw6m9mrJ9i9+nlxcEsPPQTtz2AuFQewM6CaIbX93?=
 =?us-ascii?Q?s0pPhVO187W+n6nLNCJAiXcSEW7pOXvYeFpvoOi9+Cx6R8pQTEkO1sb83Bin?=
 =?us-ascii?Q?XZEjZ3YUgj/kMQRDaT5fACiJff7I2KQFIZATedbE?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d3ddd353-fedc-4b8c-944f-08dde1887b1f
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Aug 2025 14:30:45.7354
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EVsHixaNqI9KMqq+rfkiyi0QDX3x7XzlS5itLRgPsnc/YXDOqjJAhWngclDt8gvH
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR12MB6591
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=uhOaTwj2;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 21, 2025 at 10:06:26PM +0200, David Hildenbrand wrote:
> As discussed recently with Linus, nth_page() is just nasty and we would
> like to remove it.
> 
> To recap, the reason we currently need nth_page() within a folio is because
> on some kernel configs (SPARSEMEM without SPARSEMEM_VMEMMAP), the
> memmap is allocated per memory section.
> 
> While buddy allocations cannot cross memory section boundaries, hugetlb
> and dax folios can.
> 
> So crossing a memory section means that "page++" could do the wrong thing.
> Instead, nth_page() on these problematic configs always goes from
> page->pfn, to the go from (++pfn)->page, which is rather nasty.
> 
> Likely, many people have no idea when nth_page() is required and when
> it might be dropped.
> 
> We refer to such problematic PFN ranges and "non-contiguous pages".
> If we only deal with "contiguous pages", there is not need for nth_page().
>
> Besides that "obvious" folio case, we might end up using nth_page()
> within CMA allocations (again, could span memory sections), and in
> one corner case (kfence) when processing memblock allocations (again,
> could span memory sections).

I browsed the patches and it looks great to me, thanks for doing this

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250822143043.GG1311579%40nvidia.com.
