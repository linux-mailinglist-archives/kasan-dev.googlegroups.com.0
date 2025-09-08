Return-Path: <kasan-dev+bncBCN77QHK3UIBBL5X7PCQMGQESUJI5CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E076B48FB4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:35:45 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b47b4d296esf112986241cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:35:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757338544; cv=pass;
        d=google.com; s=arc-20240605;
        b=lyY8wXmxbbRzRQ1ku2CNY/6UBXkXY5nzBbJg7rrlmtDXskFfNBCwXcX63I/To4YBFB
         cuxge1N7+Le6ZocXwceWaoNcqfGhlCmDWTtMHs6t4x8ZVGB4uc6LEair5dVZKMhK+/Xh
         2YDYMD4vGzncT7x4o+4Xbe03ewORxUOtfv/aEo5M1in79Ly1Cpmo29uY9Rfy7yTBrcJW
         pYap5ag/qkZcO10FwkLRb3JHZGaWnuuQsHRnJYeJzbFRqKhwJpCWjSI1w8XoAnJA6g9a
         iNt/vcz+VlmhSkNA4rHkusM/XhlKrBzO3ESgsKtQ89aid7Nt881Jth7vScQSk3U54DGg
         9RsA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=fy1dRt9SpUwcvw+6oIZ1aRAh4mXVull5Y7isa5pic4E=;
        fh=YDo5hpJjiOeH2YDR7jYY6aedP84Y/w/FpJ+PoYJzkRQ=;
        b=DAc94NBgLemooAYYyGoSPMQeBWTcoUA7qwvXhOb6A8/1Up2oYOy+LxylKM3SDzzHCG
         fIJgfnU0GVvHoeOlIETI0mj/EQ8r4gDSsDsa7G3PLfOiAHdHQ7uWlP4wdnXqgkv616g3
         6dOGKvBrjVTDPDZw5taed03rQR4M9ShMpYZXwLhpTzIivVP2/TsoXkMU20PmhJpX6Cdt
         quOrNCImAfaE7LJSwPr0Rcc5aiwpJIE6sXMRvEmxHjhQqdhMFC7mVwxu5s/nfBndHyAC
         2L3O2LF2C06do+ieDfGTxoB3e1C/f8RgnCgkbuwaSoHz5p0QYuuUavKzGzECv9slRvfY
         1G0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YJjLy7lc;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::61b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338544; x=1757943344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fy1dRt9SpUwcvw+6oIZ1aRAh4mXVull5Y7isa5pic4E=;
        b=DEeZevoqWqL1twA/5qU/8qHSMRzyW3D32oyU2hI9VNiW7TKewO/ZjWVfA5Og48r2fz
         UZKAWu76ia9hZLGLdvHJPkSmEJvfoUeKoGJ5iSnFk7SYFkFTnXgTh4owCTyDZTZ0L2Q5
         G3QMtsnFwfGdzlQFSqIeVMFnSHq1FIw4HslbT3CQ2c2M2BbolgLukheayfKWf1QQOqDs
         rS8SeIv8QV6DHLqlTjFsSN6H1/5JUJtTo9zPxq8cbtVp4RcNeKN/xrSrgfQHlmvlNXtA
         eqUCqA0s18o9yQiqO+ZMr4nX/iKLuleTqkPgtl4mQymS4pXuR/EL4wvQ4alhVj4b/cvj
         IfFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338544; x=1757943344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fy1dRt9SpUwcvw+6oIZ1aRAh4mXVull5Y7isa5pic4E=;
        b=jAlDD/m5TYRh1qMoSkwmcYHWF666YcbtmrZomwjZhid0VhomfG21s+z8rPbaxFTk3Y
         VZTBPEwvlnK+DJbgwm56SMnVc0rWMpOA2DkVKFF9Q58Jsj7stYi8N5nj7vRk+06gQkc8
         ll51AlUpyM1+n8DzyA4LxpYwY5Tp/aEYLeQcwEt9xfdZ7upl040yN/9DjdGqgAiYGC2C
         gENMRQ/LgOS1SJp3bkYdhk8z/yhETj7bZYsklMAtH/aYviAXqwTBC5r1OApUxtyQRKtc
         4sjEQajMiplmvBqucpaHo5jVKE6JRkYhjcjZtEGdBvCpva4v8zPJjUVlMMJNEfqyrVnW
         VZvw==
X-Forwarded-Encrypted: i=3; AJvYcCWhdAGp2LF96u9qxBotV0gJNcK7Oe3bB8wd78XU3zZioAaT0qxXHn3PnwkGoF9qy17kWEv9yg==@lfdr.de
X-Gm-Message-State: AOJu0YyXmEF1RyXvYb4FtLP+aP3PxxkCDpC1qB3Q/2J3GnhxXgw6NvO7
	klAcFjmPuIQdaAXnULQQ+BlHENAAbiq0F7nDAC2aYrrKoBNl3w4VPUdy
X-Google-Smtp-Source: AGHT+IFR1Scbereozm8ykWd9C1QVNjY2cOM1puwH/5uhKLBcbCu8aT+mmUzCOkx4pjnIVOWoGF6qpg==
X-Received: by 2002:a05:622a:5c16:b0:4af:1f06:6b41 with SMTP id d75a77b69052e-4b5f8469f3bmr92089881cf.59.1757338543908;
        Mon, 08 Sep 2025 06:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfceRjnJ16cxNqLvS6Jb1uq3H1TzicRJQIc0OAVdLXbQw==
Received: by 2002:ac8:58d3:0:b0:4b3:aacd:5c80 with SMTP id d75a77b69052e-4b5ea97519els53171231cf.1.-pod-prod-02-us;
 Mon, 08 Sep 2025 06:35:43 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXhDhSlwYGbWFod034VKDrPJstDBLbSU+PH2wKzNfDZ8qZLGOPH+fdrzYOtKRbaOnYXO0Lo1RIIHMc=@googlegroups.com
X-Received: by 2002:a05:622a:5ce:b0:4b5:e868:ffec with SMTP id d75a77b69052e-4b5f837d530mr79863931cf.8.1757338542960;
        Mon, 08 Sep 2025 06:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338542; cv=pass;
        d=google.com; s=arc-20240605;
        b=ak3c1KeqKDCOKUF1M2n3mS8/LCFz+WGKh272nqPKvFuS69UMPEteTluF3Kb88aHXzm
         kOmPsLuhUCr9IJ/Vb1yNQEkmzetUzoBKDSEzeiMo2buz22ZUpwPjx3544JW0j9/Mb7Rt
         NTTQcSA+LMHCdzlyXzEk2Jlxexz7oIG+csP34pEZwBvyb0vzjdQU99O1Hlq6K2w/ULaN
         LBzpTyOoa/tAg32KMtqdOTdH40ZUdALi6EoL/S6enm7JOZgFBSrnjHqQD/LOOtHOobCX
         E7z06IXBDhlalIor/9jZZYxJBGLcrMBBrz0FHatm7/PvJSvVGDeZ+0CE17P5SuiDgIKD
         SCRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4kKs0ULVrmsp0q9pUjSjwYRoJS6dVCpdN8WM8V3+MSg=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=Joa1yKoyGMsDeWOuplnP/E0elUWtkbyrlqBxNuUWLpW6a3RnJo+Az4AdbKXdoalT7w
         tvFTaoEJSuvA+EOzWADOGpwXbENfWomoB4Gjrmvyv4WI+emaBgAE4alX5vyoOtpN8mP0
         hMpZ416gUieFF9e+PbLo/yPIlsGisd0UZLYTlLwIM//kWNJ/87EWZ0jovpEZBKHF3bd5
         D/jy+DiIy6ZjYWKYkcT6vo75iFmgh4Ks8iSgb9y3UeIFxo0B6gtK1ozmKeziv7ugPKcy
         KevytsEBnbwAB+iTP+VLwM6vAFcHudU+LbOMAfvi2P+LPG6lVtU4UtU3IOgSTCHMYn6+
         2REQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YJjLy7lc;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::61b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (mail-co1nam11on2061b.outbound.protection.outlook.com. [2a01:111:f403:2416::61b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-816b6edd4fbsi15668985a.7.2025.09.08.06.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::61b as permitted sender) client-ip=2a01:111:f403:2416::61b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Fm/QNG5CWPQm0vheGQPQ43eTSlWS5GAI/KK9xDOZ5eVgVk0Iu04rmGMrVyGhdiq6FjAjXPmz0zlJyl/jPbPOaKqIbjN+P+AedYQJKzDI21XGkXUNSfS/9CtPWNcuY+DnUS2F1RCaPwbiOGyvGw56Z+4hfYaPxj1hpt25cv/66QOIlVngsyF3iPduuOsCmxKlXCNGeKaXAEAOAuyG/L+CkKYjuxdMuxEWsIhX73Aibg7QqmwQJEWY9d92w++TzWTe/6TrvrdoknTQOrwl9Td9+L6qy4oMxHvPP2//vQSXw7HpWTV/qJKuszav31BPGPNC334UPsQFNHKcI2LMpNkpCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4kKs0ULVrmsp0q9pUjSjwYRoJS6dVCpdN8WM8V3+MSg=;
 b=DxeKHxWI4eQHO3LKQO4CR9zpe0f2MnrLLN98sNl6qZ5+3dEV4CMpp/1C9acYBQttZ/JHdoqFLROLE5eaOD9tLXGcRNQr4D35HgdBZGFrn8sIAgtUThZjJSypsYpwERBqL/Fx4FYM1djlRB4vDhaBk+z+VF8ful+Sdl3ewqLKyJQbjYNFmV+96/zTS6KG60RuzvL4ovJByOy1ReMGb8cYNVMUieLcw7JL/Il1xtbUC/SomgrgBqGOaZjyouvlN9sVGXfCqOqyAvrgkj3+Z520AgomKdmHUjupHi+92bqKVibO45Z01unxya6tS2UxRSAldz4rYKeZEN7RnvIAbHZMSQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH1PPFC8B3B7859.namprd12.prod.outlook.com (2603:10b6:61f:fc00::622) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.30; Mon, 8 Sep
 2025 13:35:40 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:35:39 +0000
Date: Mon, 8 Sep 2025 10:35:38 -0300
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
Subject: Re: [PATCH 08/16] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <20250908133538.GF616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908130015.GZ616306@nvidia.com>
 <f819a3b8-7040-44fd-b1ae-f273d702eb5b@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f819a3b8-7040-44fd-b1ae-f273d702eb5b@lucifer.local>
X-ClientProxiedBy: YT4PR01CA0235.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:eb::23) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH1PPFC8B3B7859:EE_
X-MS-Office365-Filtering-Correlation-Id: 2b1abce0-3b27-4a91-4505-08ddeedc99ad
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?q5Sc4kxW2Htk7RIituyQkliTWEMFyz0aoHo7O5B93rDmRzoomgRYwui9DXX6?=
 =?us-ascii?Q?GAK5kpXqzhClfYVzGYGgsAwW7c1BFkvzCJCchI1XGWuwWwdBvzawEUmhcEmV?=
 =?us-ascii?Q?+CzfQ4wCJhM/69WPS5Bq2BbNvsrNMHUhrCgp4ouuEEewl08EDVuYsaPLVxPw?=
 =?us-ascii?Q?Rm8mc6eitT28ULRMQ+mYafg0CamBYszp5+qaCOWwkovBLEqnddi/fI8QAKM0?=
 =?us-ascii?Q?VfrJuYLl2bIR9ZrsxrUa6mvjVJ1PhM9Borsyb/0Q0kRthnLWjjt2zn5J5EVc?=
 =?us-ascii?Q?yvecmnkeaeRNXX8kIiJCugijr9+pmPZKcBkrpdzsGC3nekD5uWm+kJoEPFMI?=
 =?us-ascii?Q?f8De5swF0Iz3MlYyuPBy0r1ZzBtm6EgpRVfTn99wcvflf3RNtPq89w5gZ4EB?=
 =?us-ascii?Q?lmB1y4bpq5htTDCjxHCskxpFwcwkiYFEpp9eCCuSKMHGBCIgh1Mzu7/JnWNp?=
 =?us-ascii?Q?qwGJprSn+rS12xUZMZAcy28KlUhLJJlkq8jSL+hrPTgEy8yaZ8ysfLa3wqye?=
 =?us-ascii?Q?7NVyOV/7zQAavetS8eDJerD9zMU0yE5XWsOSEoop8MIrAaAsRMVpgIagA+bZ?=
 =?us-ascii?Q?Orqv1uWqLwGR7QR+HOSoNXp/GeZ0YknOvVOg6dV27cjEtNlUu+kyPnDA2EEy?=
 =?us-ascii?Q?Cas+rIVSflT5pKXoqzxCGMoaQpmGldKw4i6qZEfqcSBzIF/F50pJ7G/IWv1z?=
 =?us-ascii?Q?Hlleid9xZ7475EJOdGbNfS+H6rPcRYvzdXgzx1usZ5hYnvaqhoZdlriwlBKG?=
 =?us-ascii?Q?DfTUnR1j1vhx0HBcOG+hgf2aOTdHp23NM9EjIh4n4Ixbn21TBjcEwT6jWAsh?=
 =?us-ascii?Q?nlBC0cwmoh8suWxojiMywSC/jHredzMw3y5I2eb5LDokeaESr9ABapujz8v+?=
 =?us-ascii?Q?Bp5gIFf0+gKb/sLGAK+9iTwHnnuf6klwCrHnbSF5kIjceYpnZdUPl+ljpeWh?=
 =?us-ascii?Q?t+3mskVkq06wqXjyhi1PHdbF88mklwZOzcE9c8wyFbzvh6QZZ+K0w1KvapRc?=
 =?us-ascii?Q?M44UJqOZMDrH+DXoEMwHrllZTvN7Op5SHFeR9or0FgGtUu2og6F0ci4Zkd7n?=
 =?us-ascii?Q?WEkrGlaCxdgVFu5/jaGj66ouq9MQMh/KN2FyMvZuLQwT7sOP6NVv1Mk/QH1g?=
 =?us-ascii?Q?yVBw498spv30urE6zaduZOnWUDt68yHPMjTMl9m0yqJ8oWFHcAg541cKSa1O?=
 =?us-ascii?Q?nCE5tZFA8oLyxTEZ4dufj9GMwRZX3tcvlvlFW8HxEsOE2eOU06/2ThPXo8T0?=
 =?us-ascii?Q?uxcOtIlO+lWmoE64HtUdOtqFr/BXOu84LkXOILusVHSU5lPPULIOjxUH8abi?=
 =?us-ascii?Q?dwUXVPqKZEqBskzCnMExyRTgkcsIVJs3qX003Nb3cYMC8DzjCy96j4cVom7/?=
 =?us-ascii?Q?In+C5cZOI7252KlG0R5zfBF4WVjWZtR0/OfHvss+zLY/QcAtTA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XoSFbBmQ/CennDI8oGI0MESDwwJX8yEwaHfHkpFzoNPSkfzfCDLpJgtLTrI0?=
 =?us-ascii?Q?SUpq83zu7SxOXaU+/wiNK014JpLYDaKvfTdbUYX2Ye+0+ytFyeT67llbsWJ/?=
 =?us-ascii?Q?bU8WHlxGrTd/eQ1LSF1LZiNzUB9wIluTBs33OCAJyp8rgDBnHxg3vo/8jIoC?=
 =?us-ascii?Q?6J0AL32mUTblgy5BaelXuS1eaWbaIW5MG4YiVEadeqrVevgfByWLS1hsKqDz?=
 =?us-ascii?Q?5J4oUYF7LTBAANzNZDBxoU+L/64ddHSo3bKBvnNwoT+/hvW58W4XYU0vbVi6?=
 =?us-ascii?Q?LznekYaA4157apt1Z4sBrC5AjXojFR/K5SWsGpL5n7EG/duNHMRS9z8IJLH0?=
 =?us-ascii?Q?yb9MNom4HdZs23t8nEhLy4zTV5hSUv/ezS+vu8bNKBPmuqHPhKajLbdu+NYL?=
 =?us-ascii?Q?XFNq6FCYdzZfHBViB9h32hMZl5Za7PJ6Ux0nI6ngfUuQ4HH3KoauI0KDqh3h?=
 =?us-ascii?Q?bRWZQYh9k5xhnh4ncGaCeXerBnmE3GLaHsGT3t2cGI5y3TPsl19PNs9fwXtw?=
 =?us-ascii?Q?MGW9mz8KEoWpj3dA3YTTM7R/jvXow20E7MogxHij7kjL477kylqJYn1frt1y?=
 =?us-ascii?Q?jRVV5HdchogiipTpKEU1xKHxpsXdrvZ5WC6ZRqAEiFqaVDTg+d75efEq03A4?=
 =?us-ascii?Q?HUel/xTJN9UdPUitqyJcnupLu/Nvo90cF/stAC2Ixm9AwTeUnf3/rPiFmmpL?=
 =?us-ascii?Q?hUnb9kYvxOVslrUT0boTzxcvvih1yEvm5hUmFUbSbLOAvct0jHiGlwwsqTEd?=
 =?us-ascii?Q?zIR4k2JA+OibLbooYWuMDWyEUf6NswxR5eTne2gExobaEm1e9Zcxo8OSAaxV?=
 =?us-ascii?Q?tvUQXZ9+1+YVzftXOs/Pnh9boONC5y14i0wDVWzs1IW5a72z0A5ribvDwb5M?=
 =?us-ascii?Q?0G9TijqNGBjsZtCj+Flzcs3zVqIWlLagQ0wfbjjsWbRemHOgmkA9w+v/rw1S?=
 =?us-ascii?Q?BbzaEvA1/bfTpNoU+qXVu/oHkeEtzEyyXCyF+HXqmprCux+RuyAqjxTuSqxc?=
 =?us-ascii?Q?o603eA8jGFqDyMB4wMyzWmv2C5rstnentmJVWEhSAok4EWFMi5ZpvTAgoj8t?=
 =?us-ascii?Q?jLHaKXPkCmAnsoeyBUPfBx53Og5Fg4YchUI8iq9sZ5li5m0VhOrizP/6tTgy?=
 =?us-ascii?Q?oxhmRGajUcPCEaYJELT2L4FwzSq6SGoz6LudOOJVGFSWxepbuHKzZsFu6xmp?=
 =?us-ascii?Q?knvYA+tHJAGMSgKQNucWWyd/d9PPWNYbQviMILNzikJMrVc1Hvk4Snw7U3Aw?=
 =?us-ascii?Q?ZdsZwb5zTE95ogb4FQNlwtzsVbaetS68NbFJYi/JhoefmlgoYz8YiQ8EkM+1?=
 =?us-ascii?Q?xmOEFMnQYxM29LdRSbwq5aOGgQPQAbDvp4hhGnEmivNdfHhcZS+8IR9ANwuo?=
 =?us-ascii?Q?ww3UcqjR8PM78X5AaI1/IlvnIBz4+N8rFSC7rv6NCIwxY9VOFNFQgynE55ib?=
 =?us-ascii?Q?0UqYtT44c8jXInkvlUFLzHNZN9RWAYdncMIZ+kF9saqBrTZnIk2gEQzxHdlQ?=
 =?us-ascii?Q?eSl4eCwkfjyYgGZ0BUM4yVr+VLO8/eoSnIGiXTku+Ym/nYJI3u3pdAvF9dr8?=
 =?us-ascii?Q?HP/e7HFEWsuUurH1XDM=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2b1abce0-3b27-4a91-4505-08ddeedc99ad
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:35:39.6548
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ywhab8dI4tMuB18SbSNhlK0aNKx8mOn9NqG+l3MsmIb9xJnhpEG9w9k3jzdq7/6h
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH1PPFC8B3B7859
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=YJjLy7lc;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2416::61b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 02:27:12PM +0100, Lorenzo Stoakes wrote:

> It's not only remap that is a concern here, people do all kinds of weird
> and wonderful things in .mmap(), sometimes in combination with remap.

So it should really not be split this way, complete is a badly name
prepopulate and it should only fill the PTEs, which shouldn't need
more locking.

The only example in this series didn't actually need to hold the lock.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908133538.GF616306%40nvidia.com.
