Return-Path: <kasan-dev+bncBCN77QHK3UIBBQFC7PCQMGQESZNV7WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C062B48E19
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 14:51:14 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-71ff3e1256csf110307846d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 05:51:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757335873; cv=pass;
        d=google.com; s=arc-20240605;
        b=P0i63CfcgIttaoj8kI8R5ZHwKhIRA9EgkmODbR+p8zfMCewsLcsrfd1Y9ZLoJotLIb
         Pkw/7oTxEOCocpPzZ+gJz7RWYdBT5nXDuxQmj9sBBpZJGI6+7kcAVwZ8ZpsohRU8CX2I
         VC6rDvOdW3KtyMYjkRhfdclOeBF0AzSflXfFl5sLlWFR8ACObx1nkWpb+1CxwgFCEG69
         MUOMWFvxp+5USNCSqOLzgW/T8kxOb4tNVA43maFjZS5G0KfAjxFOCKAiiBBQhfhf5x2o
         ScrWNIhwN6kH+HvFbOZNetGK8n1dZW9ZZE4nDJoDaLM98BhPx8H0vRUTlwUnd1A8cext
         2Q7A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Z7yo7b1b6Roa17dqykI1EgfEIaLiN1bBijfiZUUG5XU=;
        fh=uM1qg26voHDtFdrf4drGtkESyivVjqF3m3re7sRD8Fc=;
        b=MObKDOz54AMesJkafqzTrhllDsUKVRg1BiF39C0/q4jT9a3VJiCd5CIBjqRPBcGqtD
         8epR37aBq/zYbVwlcpa6QBTfVN5WyEpUweZzDPIcnO7cpLxZntyhDNg+ez9aE36qnWXc
         DZfShqKd395+JRlvvcmaIiksNEfqC/Irtf2bSUqGJRCYa1AqTvp+LQemzK93O9q3sIr8
         nWqbwfk3NeUIm72n68aBbh3TJ1yudF7OhqJeY19GDRF1Tn1tweAWhgyKBAsddqXqzJ/G
         1Z8pyeLBlbJrPaROXvex4l1YAEatxFaNaNHLDiwKSwmIZXVx083urUnRjziiNvy3J+NI
         NhzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Q04TGYks;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757335873; x=1757940673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Z7yo7b1b6Roa17dqykI1EgfEIaLiN1bBijfiZUUG5XU=;
        b=wF50lt5eeBMCdchEQGQHzdpC+9dbKEgQUIxe+5NDbNFHD4IPnORl+VExkUJ/CrCyFY
         A05LNRDZz6zWvmmeYwZ/F5mLzig+TsmVEA2xAzX5V71BaZspOWH17H4ujjumiLAM2wk/
         TsO5LkM7Dx8Q3waSgxMeT5w8R2Vgv7kUEYlxvZxPrQNeYDWU4m4lkn9ag2ObBf/aQtnW
         aFSRa6gkVUHO1Xshhy5zP6oE+hX1qFcOPNEP6XIaiU/mIzWU5DJR8zDS02j7snxQdiy2
         1xLm9ypzjCdAPFBSDZI7DlMBdqXiNfJnKKqA3jHqv7H+WJDNfD3Bc6USUIl0hQddTtXA
         IKcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757335873; x=1757940673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z7yo7b1b6Roa17dqykI1EgfEIaLiN1bBijfiZUUG5XU=;
        b=mM9s23tCPNHFcYN1HMmquO6PzbcSOL0pikttjvKV9Mr9LfpPWgJabd6ZxztZUeLciS
         Xg41eXJppyLlarMYBkRYO0vH6NZOXCbEGFFKSRL4G7Z5yMTiyVnrOILI6m9/ZuJOZX2w
         EsE5BUwOHpsf3dGbLBrZcGcB1b0L3DWcd8KxIBS42/CCx/p/nlBtm9Nl/tIg4MXVMWUH
         SeLiBvu7l+OxQ1rzM+UAQbPl4hXLwF48KgQ22ckVuQVfHTFMDkyMtqyKhZ3VMvGitNi5
         neCcO55lo6d/7O3gyaCaN+5rTijZ9JwXa+ZErixwpTX3fhAF6YYnIQ+BI7Pj4IQxoF1s
         cPew==
X-Forwarded-Encrypted: i=3; AJvYcCXniiUccFgNTlhOlkF1yOh+I15hAfAnEmgL3uIH0HhUhr6kSupzLtdpW8h+cJ3cfNhKmtcAvQ==@lfdr.de
X-Gm-Message-State: AOJu0YzvSrNxnhZ7/+ZnJKN3vnpqpPKfJhc6Z2JwE4ts+luL+MCnYByW
	EjzNb73SnEgbZp34dy03cbNK50+whNB0WiQWdNgDzAUk0r0+9xyKdDtj
X-Google-Smtp-Source: AGHT+IHXYt6t9PfUbaanlud3wyHl7b+g1UEuQKl8CwFmUtcjThTg3vDzgsQh1Wq785iwe7p/UcQmWg==
X-Received: by 2002:a05:6214:2624:b0:72c:cc04:c3a4 with SMTP id 6a1803df08f44-7391bf48d19mr79850916d6.8.1757335872766;
        Mon, 08 Sep 2025 05:51:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5NdczV10BddfoFOd9QykW8SCwJ6RpJs+7vjdFvqrHrgg==
Received: by 2002:a05:6214:ac8:b0:709:ad61:71b0 with SMTP id
 6a1803df08f44-72d3c128912ls47814216d6.1.-pod-prod-02-us; Mon, 08 Sep 2025
 05:51:11 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXduSzpMfl6Vw6eJ/k5z8K7ApmkuFNlY8Y0t+SwAcxmoFcYMYBGuw2TZJGcpepZiOAhBRpx4nJFdV8=@googlegroups.com
X-Received: by 2002:a05:6214:246e:b0:70f:4ee6:ebc7 with SMTP id 6a1803df08f44-739397ec383mr92389696d6.40.1757335871126;
        Mon, 08 Sep 2025 05:51:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757335871; cv=pass;
        d=google.com; s=arc-20240605;
        b=hTrLdLvvXcpXvkHwoUpTtwcWQXf1Vk0jKkRZWsZVt2F19265UDhGMRVCO5cOouLN8V
         DcVI7gGdQyeCwCIpl6JnmYfYnR01KZzmoWuRZOF+tiCRUkSxDx8KThR+xx0RzhDPcY8z
         9yx/rGfEjO3u0FxGzreNJrCLyWcoCvsQRJhXnlTHJPxYDHRVel4PKvcCG/8SiqsaW9Ow
         ULym6DdftUdkXiUp7PySSsTSUWxfsDuBH4Cmk/cUYNF/bqdvTVeDw3oNB8pcBUMPdpmW
         0OShq0V50l3Ft81RVNdaQ2INoY8Om6al+yuE6U1BVjp5QwyHHfj/24923mLBQ1GmmY1N
         qdOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3OSHuO/Vc5BKJ5cHo5+Vst34M23kDq4EdFQN0zPkUWU=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=f+J5KblLqX3905dwIpimvaGUeRUIYRYRVtn9VUHvI0F2C9n4b/VMAEINmQUkwCtbH7
         CQjpn/cLNBH51UHGMTBybdVq2rCaXLj4W4wQ6ZddbKon7XcQOTHMPH56uNArdyqmM5Ou
         GuOyC37T/U3H6izL7bHp9pDPEyxMGKrnmz18GhkTWnQ1ttnOTTJDx6FQPkyLypfQej7f
         Fwd9VfE6q4rCMOOoxyleDGTuXUkV6xhOWh6Y4yIfFkMBi/LqVBvNKpONB7LCnZ++q5U1
         Ql54HBbY8ecEOJv1HoVuLHeyUPbTGAHAFhgCvQ2JL/CldrxI/vlkjuKLFMe6Vw3LGPwp
         iRnw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Q04TGYks;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on20603.outbound.protection.outlook.com. [2a01:111:f403:2418::603])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b14464absi7534156d6.4.2025.09.08.05.51.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 05:51:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::603 as permitted sender) client-ip=2a01:111:f403:2418::603;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kMvaxhUHleRxntZGYNAQ6oYMMU1JbeUP44toucYGKbizGwaVMRXKNbkyUFUPdd0e5Cx1IPl7vdp6NNOfeScVoPrEkHkhyxvyg4Z3WGpwprovcRWpUbAKPj3LpU3yLKYEGI4N/IBMz8V4RdV88lY/2ZC6Xue21KFvFMzNVqI//cN0BaviWdnunZkApyGcUGQYPnAfZT2SAd0F2w5Bh3reSRHld3eTwjTzhHpyuc9FBQOxUCbwFN4OtNc3B1ZiAyEbVcyqhEP5hi8KOmS/QIwrn/1kwgtzi/wnDJRZhlfqlp2fv4jY8SPduKV85cq+NgFbmtVBMuxznJWsv+Kl/L4G8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3OSHuO/Vc5BKJ5cHo5+Vst34M23kDq4EdFQN0zPkUWU=;
 b=mAunikoQejeLXAvW4UoM/ycWFNsazJgGlsg2fFTcvhHr61/n9tobPBooHxj3TwWiuVwbSxm+AGM9klT5+AuulVxt82iMD+bqYOPay2LMN6Ls/xLRH5tMO6XW6R8SCwTGnLOYkS786s5iFd8HhFP8FgGqQK1nu/tRrY3hs+ZxLXc1GPyp0jAO9I2FD22OG0sVxSlQz+Cui+g2Oh0RartMJkUtDClkC0e1hCGEwoGk+bGiYer6erlnkqX2KXhpOBAKk6XGemXPUeOSV94gPD5qIE4/4g139jRdQ5kWOa+kqk26RabCHPWwcwiGEbQK6CJe/dcp4u4ZP4nWHjEKIfUt+g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW5PR12MB5623.namprd12.prod.outlook.com (2603:10b6:303:199::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 12:51:03 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 12:51:03 +0000
Date: Mon, 8 Sep 2025 09:51:01 -0300
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
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <20250908125101.GX616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0026.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:fe::11) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW5PR12MB5623:EE_
X-MS-Office365-Filtering-Correlation-Id: 4535ed58-2ad9-4ee8-9dcc-08ddeed65ea1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?RK/YBv5RNmNrwTy3JLCS1Y1nfiWysNq4+ETCGrZ4WZi0XuFOccD62zIDAlil?=
 =?us-ascii?Q?nUIP8RZbII+RXqNS05kjw5UbPaF/PQU6Be88QsX5mxma/KsXEZF7cvvkHZO2?=
 =?us-ascii?Q?rdqeSeZr5YraoB+Cr/Qk+akQ3NZ2HayLh/VudWRzntdZ0xpxUPq6FIO8Kile?=
 =?us-ascii?Q?s5FE9Qjp0kv25LidB6vAS9HybJ3yEyF9t2rnW2VpddB1fNKdEZe56IS6eX6E?=
 =?us-ascii?Q?CNOT3HxG3Wn988IPGJ4oKmmJ773At2GItnm/lEMmWSvBJ/UlzQfVoKODwdLA?=
 =?us-ascii?Q?YHPKlBwJG72E7OotPbX9Y7qXLKi5smIS/C06uKbhWECr8idy/CU122C7Yl2b?=
 =?us-ascii?Q?XD/RcFNqYQKzWVGzR8QrSIdDPn2FcmtrBcApFeOEdixuVlIm4s42RCtTm/g2?=
 =?us-ascii?Q?xoVhUsJ/N9dBbVIisQWF5AllOd5e1+XYYdxIR5Kt1QkwioLJ0KyTEDeCTFGy?=
 =?us-ascii?Q?lUQSASAg7/1Hj0swNb0t1Ed25d3dBPWK42qlFjWUlSpl7P7+on6HWCSw7J+e?=
 =?us-ascii?Q?4evEH2DAzAcbmbaUfUXVlalDx8ckqV5vjEcDB8DUEZGowI4ViyWSEC9K3W1q?=
 =?us-ascii?Q?IS3Qx84Oi7NAkm+WfOV8kYFaOogHkT0ts40/8aEY31D0fzCIK1ELHnrHzNkm?=
 =?us-ascii?Q?pUho4uxM3CqCKWfugqZ0JFUHkK8PnIcJR8ya3hxr125S1jpyIiFAGA216uw9?=
 =?us-ascii?Q?t8xdXPAmkOsIbHGh4QhvB/xbPrYwie4HqCCIIRIZxW2paXWxmBgo1PR1RU8e?=
 =?us-ascii?Q?MWbad7VZbjodBwhrL8xGFZd2vvOuHcfbJQGo5q0Ep4zMsQgxP+kQ4LiLCE0j?=
 =?us-ascii?Q?IuGz+MOgY6XXyZuwzp/P1xdHoTpT8M2XwdxuYR8BxH1N5m8PW/HS2dH4TVco?=
 =?us-ascii?Q?VNUc83r6YFKFeighj5ALqEIsRZ17wUbCbYZ2ri2+pDTwKh0bubzc86Tu+9LG?=
 =?us-ascii?Q?kVTyxhhlS/kRr6ASBt0DKNl17jpla7l+MAXu0TOJiDcBvGx/UdnF7JJ+GwSv?=
 =?us-ascii?Q?v4MDkLqydrts2aOb+01r6FIi55aETunKug+Es4+4nRMT4ptW5icztTsEv6W9?=
 =?us-ascii?Q?24ZT6eRRiIikbgND645qTHgusuaJ3aoQh4Ls6apYRamNS8yax+yeynAo4jZ4?=
 =?us-ascii?Q?rO1fa2RoFM25adezfrSsYLS5lRFOWPfVW5iNIrUfNnVpCiJONDJJ968TLeaP?=
 =?us-ascii?Q?IiBCfqG4Exa36ZYdyC06vfK50GLf2FK7OjtjYkKdqOwC4QoRwoTlcPawz03o?=
 =?us-ascii?Q?gYAmipXzZVQ6otp2+Rnr+DIPRziuykb3ofJH6c20nxZlHmIqaapEiH8V2hXG?=
 =?us-ascii?Q?mNf5NZQncmdcuZ4E2h/txc7MswUwwwhSNPG/zJXwB169zPSwpKTXduIf8wCL?=
 =?us-ascii?Q?zO5m8DSRVMxSCZNcagD8yJrV5fMymM7BQeMJQLjj47O/uoc4a4qBg/ug4B/Y?=
 =?us-ascii?Q?xFwDFI1zPwo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?YOgrbUOulWOusbdk/vwY/I6Z0hEnYRMIwKYZWRYlkMsXhv0unFY8GITjYHEW?=
 =?us-ascii?Q?FnoYUxSTvZfH+MbxKuG8wvPbmhco82reC6g7tADJQk/Ne/1S81ZpK1+qlZfD?=
 =?us-ascii?Q?6r1tXru1+1lkTFks5IiZU5uNdIkDtH3gKk1cMyhFPNNlLcaTSUxy3wHKtOIT?=
 =?us-ascii?Q?ONWrZmv0N8y5ZrAEe0bjSPpBkRWfA9gLXs8aoL/+fqWNNTsF7Ytv6yiDWEL3?=
 =?us-ascii?Q?c8JBkZgNXWp33U1/D8XCrMtNxeGGECxEQklzrNYwXQv5Zfm3WcjN//xwIWIz?=
 =?us-ascii?Q?6YTjg9IEV5hfrKr+uvzpsMEMT0ws5155Z0dJkdyoQ02LwQ5AQACKhh2hcUNs?=
 =?us-ascii?Q?OkYpZIu1LiG3M6bi1ezhol1hGrg29Tn8OdoZVPRrItimWlN5V+r6tmE58NfD?=
 =?us-ascii?Q?ooDp9ZT7dklMIKGRsL0PPbxXJ+8qQ9BETZNakHq/EQWunHRDuCbz0G/bIH41?=
 =?us-ascii?Q?/klUb/zRAKYQoU22ga5sIoPqi/OzPKt+d0um5OobjK6BIN9r/XzddQEa+TsZ?=
 =?us-ascii?Q?a/GVUuzPC87G/4dV36GMj7j6f0C8DQEuLUNbs83zQ0T+E9wvun1/sEwJUuiG?=
 =?us-ascii?Q?gvfijF6fhL8wNQoD/lYo1kzQRrWRfsDzI/ywhPEUANQyo1rTcYEccgEqaiFs?=
 =?us-ascii?Q?lbWpTI2agTB3i3XmPyJw7KG6SzrN4OIIeslybDy7xA826vEstw8ro+gQDXO+?=
 =?us-ascii?Q?2sjqodoscdkfv3a8x+X9zgEisXkTTwhqO0eayayzehCwNKZs1GTxBzWucVJK?=
 =?us-ascii?Q?s22no0ChtnK24gCSESJApYtZAn5D/go5ATo3i3OtAc1Oi2YxRIuWr6Nkm0q4?=
 =?us-ascii?Q?eDxkbPA5lehfuCPidPixQoghqmDqqPIo6vvQBkK9DuqhTjrYlFDNaYdfj6D/?=
 =?us-ascii?Q?AfDc+aROynD+8LQScdbXCy6FrRqr/YarM8tKdVJjK+UMotbYGicjMHd95UFW?=
 =?us-ascii?Q?h501mXq1jmhhQZ2R/IW3LQTNdszvKZV9hg9WuFBEidHEkT5RSUGrgp6bosAX?=
 =?us-ascii?Q?/cgE4rtBChfs8qOWdd/RrwfdBT0fE6so+0nSI4GeOb57wwtKAxWqAShaHLF1?=
 =?us-ascii?Q?f0GsySe1WFciFtdY7OQSwzK2T7Z8T/SZNoGEqngNSQ0Yr+iXN3OcuORMBHbw?=
 =?us-ascii?Q?GXO3y8XI4U2Ab6laC8IbG4E9dZu8fDBBoEdkaAGrNZ7s+UfP3GFDy0j19FWR?=
 =?us-ascii?Q?VyNR59v23zZ6ZVdtMoYTT9cNJHloAZ9jPdrUYDTGVesEoYxEBtlHBYc6yOgG?=
 =?us-ascii?Q?QM3OCOxzWNSqbgFfZOHkyeSBwUDkgr1r+7+9bW6GX6+r6g7n7BBeTZBCsrJO?=
 =?us-ascii?Q?hr5cc0JW2YZetLCZ+OEWv5beZ8ksNlcnDTuu0Lydd4Opj8sUASzCLaaYqFt7?=
 =?us-ascii?Q?ZC2yXeFf8vUhJ6m4qv33HWVMd1wBmOqtDgU7i/DWmD/LSLrbmUoJYUmOkf7F?=
 =?us-ascii?Q?kOJZ0vqoxjg47Gt/Y4il4nlQioOgNhdhsCq4ojUuORoHXL4spuE2y4YSRggx?=
 =?us-ascii?Q?CnAhL7Ev9UBO1vyGa6isplhSj+Ke/CpF8hqBx4gCEqS+gAUqGYr+06lH3PP2?=
 =?us-ascii?Q?ZdmjeAbLBE+QQVTIYYE=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4535ed58-2ad9-4ee8-9dcc-08ddeed65ea1
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 12:51:03.6211
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hPSYzFEjHMyzJ4cZEzUHXo0bko3ctFNuaC/vuTYRitLPN1OBS4RYznmP/7soLPCh
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW5PR12MB5623
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Q04TGYks;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2418::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:34PM +0100, Lorenzo Stoakes wrote:
>  static int secretmem_mmap_prepare(struct vm_area_desc *desc)
>  {
> -	const unsigned long len = desc->end - desc->start;
> +	const unsigned long len = vma_desc_size(desc);
>  
>  	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
>  		return -EINVAL;

I wonder if we should have some helper for this shared check too, it
is a bit tricky with the two flags. Forced-shared checks are pretty
common.

vma_desc_must_be_shared(desc) ?

Also 'must not be exec' is common too.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908125101.GX616306%40nvidia.com.
