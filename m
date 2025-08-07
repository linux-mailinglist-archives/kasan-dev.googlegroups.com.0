Return-Path: <kasan-dev+bncBCN77QHK3UIBBWON2LCAMGQEJ6SV72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E21D5B1D8B7
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 15:15:06 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-23fd831def4sf9051145ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 06:15:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754572505; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ik+tfbi3CNdBmfQAVcznPdVvqBi4lpuTWNDsRkHria4+OIzZJIBAby6GcZAeuEKxdS
         TTvBrHFn+Gb902lr5Tur1Zgmr57U8Ky77EzOSPody5b9RcdYhIdx3CAR780kZnDp+vnf
         QKmqzwyboRn3fWrP929/6faW82qBp4FqgYgP1xBh7KNCOMPNziC9Ss/lFexFJNF2YAsR
         cXQAUvtau77Wk7zbrfPRxSDv+HAxOejlpAHQEJ19rvl4Lz4dQ9Vhxb8il3FHBLoICfhL
         xxdkUJPLUviERCZ6/yaOg2vkbWcm3fJQcOVTK8U+H5CTwmk9pJ6Q6czHNWHci//tOJM4
         /oJg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MmnW0zfzCf8PlbYONv+cJexBDxGQWqrNzdOYSVmkb70=;
        fh=R8i65JFCTRPH6fiAjQxLdFUPYr0zO/RpDTEAgduRuoQ=;
        b=MUPcOLg8Kk6pEjFtMiRAi3+9TuCvzJshePNyMsiAgR7MPgljYTh69OvzyINfK+SDi4
         4lLi6puUEgPLTmssn2bGeG2ybhJmNRoezH4o/LL5lUKjllQzb9kOBlA1cvhykXROC2ZK
         Edmifbpkk7B3i3/41ddQ5GLY+g1gmxkDWkhif84h5mFpt3SvF4c2v6XXrbUBPWGzZtbw
         bPAzE756OFxWikGJ57GzsaHJn2wEqTXbtuPdesEke5BmJ0wgmP0Kna6GkmLRathvghbT
         EIDJo8AYTiX5QwyDd1BURL2ZdRlM+W4OpBy9Pzec+CyE33siTcB5NBgJn5Ut+fewFAJQ
         PDgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=hRuZURXL;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2413::613 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754572505; x=1755177305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MmnW0zfzCf8PlbYONv+cJexBDxGQWqrNzdOYSVmkb70=;
        b=tibeU3281V+lzeKNInG0RgLQgeHQO5mr362C2ZwTAlG5Hrd4fJnz9Zu2QVF2ovr9Cj
         TFgMYkHdZxg2iI5Ji9bGE6Z8s2OzorDw7JTJwniksN67EgpVSzAgtX8mHzrZ7pyxQ5lD
         5XxgOeKvTOFKCpQt4FQAJ3qUbAtf9t2ucYYeqbQc42IqBIWQi3rjoZvL3jGfjQkCMOU1
         UtLq9f8vyxy8XKZDF9m8IWwJOCtOB4+kRtbS2sFs06DLwb9A6ofmjEQs5hFX10m4LT3F
         upOoXOttuNZW68MTqcDpasDxLew/PVNh65A9pryDnbXcuT+SXSmgrrUo4i7+V2olL/hJ
         FDKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754572505; x=1755177305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MmnW0zfzCf8PlbYONv+cJexBDxGQWqrNzdOYSVmkb70=;
        b=iRzG+YJMT/FC3lYEoj2c17ptDR2wxF8CmvXN5YKEI7x+NDvKG97hI0TEbBa+2FzxdV
         VxFKJFd7OxUDMhkFl3gcdj9cs3WWfIvKHfjuIOcraCOoVXc+b4xU2RHLIkCdi8Y82XKb
         4LX+AYzl7aaUop40KxRiD8KhrABpFnZEDjEq0zeQWn7NtvEQGnO4mwFuX7465FK0ajDb
         NM3yXG8n05UPT5mAxX8H0q3c0ijOqJ5XMQm+G5OpI+LpzURqQSsDQNp7BZjMRPoFvFNQ
         fsmfQV3v0HCTAyLEp1UHJidlHPkJDCfrZkj+3dv7UCbXlbFjvtLpEPfJiQ2yDAXtiADb
         KhAg==
X-Forwarded-Encrypted: i=3; AJvYcCUoiM31eMN4Mci+dRCqn0SbAlc+4L1BhL5fZKGLWik4saXxIq1buFo4ga8fS9WgwblxKqHcng==@lfdr.de
X-Gm-Message-State: AOJu0YxYK3W/C3fft4pLNrP+AXfgDLzTldUEHIP3+ePdaTPA0rztGREE
	4KWIrxDYyTxlp40kM3NrhY4BZztp2yf/eoK9ImiwZZLpgfFbFyYdV51v
X-Google-Smtp-Source: AGHT+IEEQ3dbdlJjQjhyqwgq7PK/6Hf9YbK+r5yTuurduis3EtupRszmf8/bcqNoDhggC+z28LQtvA==
X-Received: by 2002:a17:903:2cf:b0:240:71ad:a454 with SMTP id d9443c01a7336-2429f2d9e92mr116413085ad.1.1754572505330;
        Thu, 07 Aug 2025 06:15:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZelsjNroIdBODzfjWWAQCZzAMe423eqkWMOvw/av0xF9w==
Received: by 2002:a17:90b:3143:b0:30e:8102:9f57 with SMTP id
 98e67ed59e1d1-321750850d3ls1163830a91.2.-pod-prod-04-us; Thu, 07 Aug 2025
 06:15:04 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUpICAjTrfGLL1kFwpIDJbbXOeSq+kfdPE0HBYdR36kYVX4Pi82pXpX+m4oNgfLMTNkkMfHbSj61vo=@googlegroups.com
X-Received: by 2002:a17:90a:d60f:b0:321:7a2f:985e with SMTP id 98e67ed59e1d1-3217a2f9c30mr3288251a91.12.1754572503936;
        Thu, 07 Aug 2025 06:15:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754572503; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vzt3+JVhXpjTcmceu9ogE+rCxwk7SUvMEVmFpjznQsor/TKgAjHGPkIEf0D8EI1fQE
         Fj+1WMKEjHJQ/Sgjpu7TgAEC5PQqBTxqMxY3noNfj0VdrRSDPlkvIjO+Vv+vYS1z93ay
         Cj6bEcEwQ1e5L2opr/mLqeozw2EPPAeht5HgGXztSVsF4PwkE049OqBjYFmL/tZtKjSf
         f88a7Lfxu1eVY+JBknnle8fGFMiXEUAzerkDyq9FAc+KaznSkYPLZTGT0h2vEDGwCk47
         Dqqx7nD1DyvFTR/ryabxdBrnFxsU7+gSaFDYMboTt0reZZZ/ffqA6JHs5ncldY7MICTW
         jj9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fhrpJXFQJ413bVBg/dYiA6Su59FLs9ca9I3Q/eQtjEk=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=M+xFNMMeGIOo90s74kYtrOYNZvw62KCwIffkfdqa2BZ4kcXsBjy7On+FGU+fGDh8e/
         SyVpYywEcsAyz7QTwVgEOMfoQIYDtTfHrvcW2u3SicHWGq076jpCbsDlDODHcpXGX/xP
         REpyLM0Dl8OvkZjN/1BrKLWY3Z8ZrCUZHsX8eWP71ROubFeod8/UMPqxYbXXhaR2/cJT
         UfBXI+LXX8wrKkNIvqTv/bxaMqJ7961AouKi/X55PQp8RP41GMODE0IKZ64f7N/u9YXw
         VBXbAcnSQq+Gc848KVSYz47L9pBHsla81C/MHgyFjfq3mApNvTMSPpchkZgZusdWtTAs
         EPew==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=hRuZURXL;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2413::613 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (mail-dm6nam10on20613.outbound.protection.outlook.com. [2a01:111:f403:2413::613])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31f63d9e126si1055695a91.1.2025.08.07.06.15.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 06:15:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2413::613 as permitted sender) client-ip=2a01:111:f403:2413::613;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wo7k/uTJcp855ED3LJ2trHqYOTev4jBcYYE5YCzT2lh6ZrTAiSZnK6310k5CwU2DX10KGyyyMZKZBU8RMc5vPnCUrXZ75/vrnILosqT52b0KVH5q9zE8A4M5Rwvmz9MtWNd7qxKnJ2PJbQaEVj+yzxHyEJ8kCvuCefO9Ww9d5NaSKaNRQaLHCygKxRzuBAmOGUT8kuX4N6Lm5YS5EXO+L8UOfUGCf7+tmb/xnK/rzrG+vjOLVIThtuO4YGYEYXs+xyfjnuuOFbK3vRkOaoziwWcicM0MdtajbyNIgdgnQ9B895Gx2eXja2Jdm23RboMkhF3jUyeex9YxhdtqrEmCoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=fhrpJXFQJ413bVBg/dYiA6Su59FLs9ca9I3Q/eQtjEk=;
 b=EHGeulZn/cEjtXGORzllVslfrrFvgrgMnl/ePhrHnBOHldTAU8S8irht6EJwWSYJKvMe1oo3TlyGX7HHg89opsTeE9+b/k5ud81AEpmH4nGwg6JRWUHwXbHjisHW4FLEvfXhT+2gWLCYc9LS1Zep8h6WJa134oN59w6WfAzyDVPGU5EKTIYoLEOhmEscKKmBs/1eHdLnbaJ/4RKp5qM+xm9RJuhwkIXsK9OnATvBAdfkKdp0FvwkVOsEo3pEzyEaqwKhuKj6a2ct20xIOkVenCjiCIZcP//vJOlO1JkbQIZk32YdvShMWKBhXz+Bw25fXOrSXffAm5e7mG7YvvXQag==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by SJ2PR12MB7848.namprd12.prod.outlook.com (2603:10b6:a03:4ca::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.15; Thu, 7 Aug
 2025 13:14:59 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 13:14:59 +0000
Date: Thu, 7 Aug 2025 10:14:58 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
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
Subject: Re: [PATCH v1 12/16] mm/hmm: migrate to physical address-based DMA
 mapping API
Message-ID: <20250807131458.GK184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <6d5896c3c1eb4d481b7d49f1eb661f61353bcfdb.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6d5896c3c1eb4d481b7d49f1eb661f61353bcfdb.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0453.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10d::14) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|SJ2PR12MB7848:EE_
X-MS-Office365-Filtering-Correlation-Id: 1a07515f-ddaa-4ac5-b3a8-08ddd5b46965
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?GSImJahfz0YNnt1fwDp+mBc8ssN50vC6AfMAVhkIOcvn/O3sKKoVm/4ksk+C?=
 =?us-ascii?Q?ocO/j51p/V7ugnNBtvoABaUqHrSIHA9Hm3UvgFM8lP6vQxcc6ItyQVS8sL+1?=
 =?us-ascii?Q?AFJZ2QOJt7mdJGm1fDtTNPXa0+l/bFsl4GGBxccS/ZBCMRWwW6kOnrInWdhN?=
 =?us-ascii?Q?83XGe+RKzaNtVWcHVBFBaBo56C/aGBb5C+9EM6ZUTolx2BRnrpu86JJU/wly?=
 =?us-ascii?Q?9szly7j+qUXn/j4XVZcOHY5lDECADNx528PGUctcbByhNzn1Nb1j9ruTOZq+?=
 =?us-ascii?Q?mS0giz6+NtlYc7Sj5f39bXIjYeyXMDM+3/5HOLSrKpEO7nkBUtlg7hVlfYKB?=
 =?us-ascii?Q?0XwxqyC+ToKBhD4XgCtw+Iq+U8Mo0KraoFrBPq+1wyov3kpH0c8gjn5r6K3W?=
 =?us-ascii?Q?j3BHaQxj+rE9iX6vsQJDexzC1wmVL/mrIxtKjiFoM5HcDocs3VBn2jPVMLJ3?=
 =?us-ascii?Q?BdwIUdxEwiEfV0GpNoRxxguI0E0FYCcuf/MKIAW3891CA5OFHWqirQlpsgDY?=
 =?us-ascii?Q?XkURAwqUb0dWLrOxoL5l1X1/NqGr0QT4Suj4DNnf4ohQmbMpToCrPb2zl8EB?=
 =?us-ascii?Q?q1viVoNJz8xho2ph51Tdx9z+bDtkvRC1kXGyv7sI8UEgJt/f99Cxpgtx7g77?=
 =?us-ascii?Q?vnX2EJLvSGKe3KSusQvb55iJieU6kCocSj/sIXxsDZq3RKVn8Ne04l+MHgU6?=
 =?us-ascii?Q?CMmGigO1sUjkKIYoUiZeOYP4AlwB1yCIMR3GAr/99Nuoc370O35GK1mGVfuY?=
 =?us-ascii?Q?e5Wiv3u/K9vUiSL2kX+g43gTTZAdICuCcJz204KRJttcQl79pgkqkxi/EIvA?=
 =?us-ascii?Q?sTFGuLo4MafZMKHhqgEtiJxm/b5gtT+nRMhxgVUSObDw3JIp2bvXm75dYN/w?=
 =?us-ascii?Q?6l5nyT/xIRGSEitQu/Lr2FHKQKHn9MHFRQNRWp0DSTUG+3qXMxQad5hJvV5n?=
 =?us-ascii?Q?dWqC71GofP4YKjxsIZ0c/H3MDQ8nkezQjLX/dCrCvLwkNlzb6m0AgT7K2jqx?=
 =?us-ascii?Q?9R6bD2ZfdnvuXjOGyJ6fhlN4SLJQbtPufxDLKQTfQB05olRPoAUqIBiCO5bW?=
 =?us-ascii?Q?yH7Pe2lbyALqgNdWAIp/EqvK6E4Thye+lVnh6zwiLrDMa65lu8lekZ4aiXIi?=
 =?us-ascii?Q?c/b6ljhCYqJfdsScF1CbUScdoN0Ap1gfOL7Vuu8zQoVZqupoIt/yxUbtfQ4A?=
 =?us-ascii?Q?tZaSCbtFmaRduYZYpoPmB5tyb6mpkhRYiwdd6eaAJU0ybvtQ0OKqyLXxeiQv?=
 =?us-ascii?Q?OWjcSpaA7rvKBbgiXM0giidUJTWnVU6jrP6WmyNtYgMrKTzflx6Tgz6pe/l7?=
 =?us-ascii?Q?4AvALcXlgU4yOMOFDaKMZS5SK/bTKr96s0QiJhGb3mzDbYBU3EgfkOp0Jxr3?=
 =?us-ascii?Q?pFlomqRCIkf/qHucrTbTlGSNMnPQq8DSC6J2iHHFV4+igvw8ctO77QccHuvG?=
 =?us-ascii?Q?BSNvcvV7iDM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uVQwG2u0CVNbXDDS+5ZdwxowmLZ5OHkQuEUxGqmleC+7gjjEVrPza8qdCu2H?=
 =?us-ascii?Q?DqmgrtbTEojW6zJDsVFIcNi1mJtxn/lW5SIBCCh4cx4QK6iHT6bCoistEIsr?=
 =?us-ascii?Q?V81Ce1X6q1kOGhUq4wgeXBtDhahFfmTQ5ljjrt1UI+qnmP4Ilj/Zcc7yLrts?=
 =?us-ascii?Q?4iDSIZoTfHlAI5W7hlopIAm7a4w63jWe4fKj71k1Qumik5Nh6xIYj7zfpR3r?=
 =?us-ascii?Q?i5uOwuhZ3HvtWgwSuJhT1aS7m5u41Ag2I2lrRUwqL0AVtiIjLPjwX/qK6Zrq?=
 =?us-ascii?Q?KO41KlW1eTh02FnnoO1GT/Ib+kl0sV39jUP4abkPVRba2S63iWWmInlZ+xzW?=
 =?us-ascii?Q?ujOMQ9ef4P240ZAM4NRcuIMcQRURHa1gE+rjuzIMMEDO4pLl7/pzjlZdn6lq?=
 =?us-ascii?Q?MznwkkeNxk6uvq487o4jFJpPpsUdZz2nEzvUuBx/rPzAaCFQNNNC0RQN7svm?=
 =?us-ascii?Q?dhMy0qzKzFQXhQh65YVbx6AzQmkyN5Uk2APUSFJjGWZY4Az3xQTMtf2NXZnB?=
 =?us-ascii?Q?nzR8e0xSr3JS3DKhLaWw530AwSv4hpYooUcrB0NnM8F6A+0woOQdR0VaT+iC?=
 =?us-ascii?Q?Vadjw9RX4KbqHbKVGsoKSjkTk+bA57fulc3p/bWQIHlEn8Kyxi1eGatWiFK/?=
 =?us-ascii?Q?jHdn0+a3csJUb5cBRLs+rVWoY+1AqrvRqbg+U08UNpCurQBWF6i5J087gACH?=
 =?us-ascii?Q?LW2aYjif9bGLKfmDzee3sqwJ5AJkGUmbB6UKRJFW1+HCxZBnOqUwx+HsA7EB?=
 =?us-ascii?Q?zOLqpjCMVfm49rgIfbh8WSfJPplF9WKE0FZWXrSxYOofC7kDOSj/W5e0Y3Dr?=
 =?us-ascii?Q?6GJ+XRM0WEAXZQzPzSWJ+jLw7tbuNqCuEDn7e8h5uCpfXo2ppikWX2hZbwW3?=
 =?us-ascii?Q?xgrQ3DesCQzZLLs2caRCHXivsYaNx938WILpK9WWFsgmSoyhc8MGyNESDvJb?=
 =?us-ascii?Q?4qvLGxLu4SfHFaPcYHm209mQY6xpelBXVSXJA442Yp+hJm7e3p9IMFi8RoBP?=
 =?us-ascii?Q?MmAZ4EjmfuSqZXz/PL11o/ynTW1D1jHmnKn3HIqrahsFm4/JoYyOlQZP4UHq?=
 =?us-ascii?Q?YfregCimSaNIXwVWh108NkwU5pbdz3yPazMSYvuL45kMcHa/70fUn0/9tjkZ?=
 =?us-ascii?Q?/fJSdzrrdW9cUHpkHtiOQXTckFjVfNpxgXDuS4tvv6cLaDbscTAfeiW8RVgf?=
 =?us-ascii?Q?HRFm5YF4KRqmY4ZEgrsyGu7clCF7UXAFWGnbmM11qCj7cImhrJAYXMDQ2b0Z?=
 =?us-ascii?Q?4UkpZKzb552akcXznmWtJe5aSm9v5fj7+ipUL1EuxH3aI0Bg6mF3EUzbLH9A?=
 =?us-ascii?Q?umBxh3cGpH+Mdf0Uka6xf4IPU5USIcPJWKiyNaQXVSAXsm9PlUfTLQdcc/ld?=
 =?us-ascii?Q?WhI2SVYFqbI/1QXzwljSHsxSi8jYAMow6c0+uff7K5biL+6kvgE5khgWhjcO?=
 =?us-ascii?Q?FX/WHQsGoZXDDdOGj3cexmCiGtYwnzdnHV/f0WHDVT6/xj7SB1e5mL5hFpTQ?=
 =?us-ascii?Q?1AltKpMuPum0qbcYABG//OJr8UX1BsZ8/wiz2T/B2maxJTItHhJS/pj5YFQq?=
 =?us-ascii?Q?xY1T4eXY8Gl9xBE6JQM=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1a07515f-ddaa-4ac5-b3a8-08ddd5b46965
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 13:14:59.7997
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aRilX0OJKybLQvXrxDL1luTg64hyjr54mJCIoCxuOa64E1WkO3f40ZTT12LJxHyK
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR12MB7848
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=hRuZURXL;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2413::613 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:46PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Convert HMM DMA operations from the legacy page-based API to the new
> physical address-based dma_map_phys() and dma_unmap_phys() functions.
> This demonstrates the preferred approach for new code that should use
> physical addresses directly rather than page+offset parameters.
> 
> The change replaces dma_map_page() and dma_unmap_page() calls with
> dma_map_phys() and dma_unmap_phys() respectively, using the physical
> address that was already available in the code. This eliminates the
> redundant page-to-physical address conversion and aligns with the
> DMA subsystem's move toward physical address-centric interfaces.
> 
> This serves as an example of how new code should be written to leverage
> the more efficient physical address API, which provides cleaner interfaces
> for drivers that already have access to physical addresses.
> 
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  mm/hmm.c | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Maybe the next patch should be squished into here too if it is going
to be a full example

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807131458.GK184255%40nvidia.com.
