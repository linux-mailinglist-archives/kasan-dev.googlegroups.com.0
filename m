Return-Path: <kasan-dev+bncBCN77QHK3UIBB4E77PCQMGQE25TNAYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id F07D7B48DE6
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 14:45:37 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-72631c2c2f7sf99393886d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 05:45:37 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757335537; cv=pass;
        d=google.com; s=arc-20240605;
        b=BfHfLwljCsLUrZUt1OE6QOsPIdS/G2g9NfbHWfIBElw7OdzHXRjK5lEY5rgVPs/jhn
         1DlM/14OHq3IURBqXZeZ+aXS1n+VnfvOOgLNU7hh6tquZlzRlsReEvQMu2zrBYqWnwqD
         mLL7JzKYp0ADhiF4COuqHtp/mmScS6z7Kqxhsf5cFhgcL3gnfTPaeagpN8Z/peUn8jiy
         lFxGIdOGDviGuQsyVYgbwefSBKgvKyLB2phG7/XXuldf1IVzKMQmes+8i1kEGg+yvnaC
         zn/sBSGBCc2Fa9A5tvUazcKNrKyzAj2wyw7ihASnnGVmlL2ObZ4q6jJ8fG+h0mt6hCSb
         DU9A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:to:from:date
         :dkim-signature;
        bh=pswcK4e/F7XWSl2a5swmxlTRK1lfZfhyQbxwy56zAak=;
        fh=BfzWHhLomhxXRvwH11LUPM5YwvFzwudUztki0tDSlJ4=;
        b=WjWGc/JpogB4ovST/hZU/c3IcsVdRFjSS15WyBnVZbUZkbplI+XmlhYRdxT9oObIaf
         PmcKIE5HDmw72+kiGgiAWFq5aI4qYi4ocKY2Z0a0VL8PchPNsTpvgfUKTmhB2xrHONvw
         epsoY3oKsbUAxC49pxcZiL8Hg857pvtoW4bIcpSW3TfYAl6m49I6YAO1q3TPbQMJ9qpV
         DlBKGzIGptHWUDE/blAh/daAF5U9cUs2cxhmTarzq6A4hTRdZ38tHKD/oIt4hQeLJUXK
         D2UF0vvjqdiDcGaGaat2r3lhxMka/bs++ugnaUaET3xV31EhkjrU8yvobyxyfJ8wrEdR
         JWWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=TTXRCLKb;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::610 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757335536; x=1757940336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pswcK4e/F7XWSl2a5swmxlTRK1lfZfhyQbxwy56zAak=;
        b=WZWguwmPdSQudd6xv5AOXT/zuy4zUL6jaIyFJreRtoS+4TJ2ZviUkxC0Xo5FejPZnx
         KvRFL7d7a9VMMRMlYGF8dZDj6zWOHFZ7FZorIRtp8s/Dx3HujLxeGAEzeaLiUqK71Hu1
         1mrz0OtXbeFQeMlQV+gwtyoeld8D5YVlHEVNGMZtN1cYFabt6vH+qikPuipwNfwco1h6
         fioGYjXYzrvUnyml6Hx5Jid66soLmaTjDruq8tjZR8h3/JTMZkXcf+ehFBQ9PhPyKArB
         T7j5nTgC9PRL8AeQVru6wrwZW1EiX5vso5x0ZR9PeRBs6UWNPByzFJSwQZchCrApRdqh
         XDGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757335536; x=1757940336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pswcK4e/F7XWSl2a5swmxlTRK1lfZfhyQbxwy56zAak=;
        b=kA+3k0UTykBIx/n+jmxGZn4EZtpoPXbiNrS5RC2p1gyWZ+LS1d9v41PWI5x+J4KlqJ
         IIyzYo6UNK0jO9b6xShtGdOH7Gon5mG4kK+dRxA27QzJTeuKRv8yi8xzLwI36S7C0lsE
         iwrmYBGF7VY8s5LZIP00EzsaQj7p9HXSkniH3gAlOW1oKab5CGTMP+k2AKVeeDbv+hlp
         dCMPWpHkn2tnAVvWuMy//aUqIaKtypbkfxqpM8SzvhnCttN+uRSO/ldZ9xQiLsXBbOz5
         R5dxQNIG4Gl2/mefHbdqO6VHWBN7xpChxUctpz3qMHJX7loZPRtQ8zO2k7LDUCnOYHdS
         lM8A==
X-Forwarded-Encrypted: i=3; AJvYcCXYoJR38+xW03JsssD5NRPQNMpdtxZdzXxzmSh4CglHzCBK+sI3o0dX90DvEBIqBY3pR1ZtPw==@lfdr.de
X-Gm-Message-State: AOJu0YwVbbwumnEbybjCqsIgBiSztzFw2qkz5Pn6UYtLqy0GGzjNOj9g
	7UhKxpjBNqoxXWm8zwo6il+eizVaxkywixV0TbRLwBARtaTBytkZ0fcV
X-Google-Smtp-Source: AGHT+IH90BWeJ46J+cP+0iQ8G9gwhbMaVrDyNUFXP+VZlhn7RcQOTrzmkTU0NWGUrZnGXjOE6xfiHA==
X-Received: by 2002:a05:6214:906:b0:73a:9990:86db with SMTP id 6a1803df08f44-73a99908866mr61919826d6.54.1757335536608;
        Mon, 08 Sep 2025 05:45:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5bwulG9vhIBhayPww/9VvxIFSeaUCy0h+b8AGehDzsyQ==
Received: by 2002:a05:6214:c82:b0:70d:bc98:89ea with SMTP id
 6a1803df08f44-72d3cbab092ls37667126d6.2.-pod-prod-09-us; Mon, 08 Sep 2025
 05:45:35 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUbVBgbe+MzZqzDBE2YxWV7emlmJH40omS3BVJKJbDkwwOaVoK93EP6yINhQP8rLYq+N9iMqogMmjk=@googlegroups.com
X-Received: by 2002:a05:6122:7c9:b0:544:79bd:f937 with SMTP id 71dfb90a1353d-5473d2900e3mr2021929e0c.15.1757335535542;
        Mon, 08 Sep 2025 05:45:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757335535; cv=pass;
        d=google.com; s=arc-20240605;
        b=iU8QjpgOZKGh2XVVBBM2e3LUz9qMpecOEstI+TArVtJc7zeOVZnt3+5hbylBkWuGpG
         BU7FnJSkmU3XSIPRcSgYskA4UTibCtD5wSXcpkBnT7I5imm8ovOmDusLyjGRvdXV6czw
         AqT+qb3dH8wmSqRBTZINg1GxPdXe7y7Rtw1C8L6vdeJZSgkMR8dxl9yi/oTN92rQbRw+
         f0Tv0sOg8H/9Jow+Z9/HBxhm2/C7dr53Yfnw9bok/e1E0ozmZmjZ3yJDhf2xDlwLxZzj
         RaRt3J+7PJ3h4WELjWzfQrFnw5goj290oXlZxIPwoT8uW5Zal6QS5GnQk1SnhWvmEDGJ
         259g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:to:from:date:dkim-signature;
        bh=kVtJy3VxH0BzMR5kUXXhlP/z9wRsHc79lEhpuG67Dec=;
        fh=rd0+OxCEIZZkd/pDZasX1IOErtc/wBY6s+620wtrsro=;
        b=Sd61HHfrn2gvUJraxIZGEHzj14rbl9K0Q1uKNPI5WeeDk2ebnjUuPie9gDjKNg8wrj
         TJutAzWcYyo4TnJ+A9n47A4KlYSe1QiB9aD4n3FzUqUoz4hC7riEi4r5cU6flzoypAeu
         pyDNztsuGehQdbto0Jup6sh18zCJm0iLBMyt8D4BzO6t66TALj1Dpr21nODDezaW4VZ9
         1toHZHWQmikb6PIpP7WxODfHd41yS5hwZWZ0/jXRglusRnRGzGqgA8aMVwdJF+QeZRiy
         VIhapbiXpuMNCOow+XfLCXtsDrLOdCcNgaJ2tKS5A3r6a6ae1BEaTqIaf8Jg0txHvqJW
         O7EQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=TTXRCLKb;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::610 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20610.outbound.protection.outlook.com. [2a01:111:f403:200a::610])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914fe552si1094971e0c.5.2025.09.08.05.45.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 05:45:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::610 as permitted sender) client-ip=2a01:111:f403:200a::610;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RdxQVyLbcPIzsM6sX7q8x7QmTn6cnd1lfXvY+FyzL1eEYsJhq9FOb6iapvK1Vz5owlYgWdY9IcbGDYG8U3EX3/aLA0nDcCYTJC7wHenAsnAO4Czyl77gaCg7SpKYxFc8vCEpuna490IbfIxsgf/ViI+4fzVEemqsS3aVW9Y2MZhLbVZX/uF/wNgSpbNCUvPBsT3kU7vL621wcjdrvJSbzaGGNtfbB6NLqSbDi0YipLdWfMOWLkamlIDFiHR9w25kDbwO3pu7Wt69fsWct0/Y9gw6jnJwFKcl+JSZ7v3pWCEiKmz6+YXiu/WBXR8/4CyQC2eB+n0kBVADV5jrPd0Tzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kVtJy3VxH0BzMR5kUXXhlP/z9wRsHc79lEhpuG67Dec=;
 b=o3stciIRY0cSJ/aOoKNOmkPUysvopr5Wx/viD+gEzJmMnFkak7IdVhQbwrw7tsvA6T0FYwu2yQ5Nwoyj9qlnzkWKTaMRsALckATri7XTNhou0MLIyx2PuHCYXgCae/ZCpiwvzum50SCvDdvYJ4RAuY+eym69GzWs317bloT3QfKrPljCpgtlwN9FbC+UElJQ9nliFQDE2C/dHiswGGaVahPyeZI/oP7dvf56EbFJdVUZTHCqKDWGl3FY8GPa0201Ebw/riZkCBLrxZ0fJZQfdLnHV7BMPixp9lP7coa48gsTnOOWWAkA9bdBVWwItKKN47qeov3W/7ZsaJHd45YQhQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by BN7PPF915F74166.namprd12.prod.outlook.com (2603:10b6:40f:fc02::6d9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 12:45:29 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 12:45:29 +0000
Date: Mon, 8 Sep 2025 09:45:26 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250908124526.GW616306@nvidia.com>
References: <20250905174324.GI616306@nvidia.com>
 <20250907142509.GA507575@workstation.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250907142509.GA507575@workstation.local>
X-ClientProxiedBy: YT4PR01CA0305.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10e::13) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|BN7PPF915F74166:EE_
X-MS-Office365-Filtering-Correlation-Id: a297ed27-88a7-4d5b-a32b-08ddeed59743
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|921020;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?+6uZKrS/rFG7MRbc+Kg/J4Ot96foh2BlZEiEN1Gc4OuIi39qI6yHkY4PEkfG?=
 =?us-ascii?Q?jA/PRoUyT1q+EIGXzX7t0ApHKIxeYDeEAl20/rgmrNPntcmc8Iivg+AMC3Lw?=
 =?us-ascii?Q?WOAXYZ1L6evCFL9T/bmJmFODQWdI2MH4oHxaX1HopkzRh91IxyGj+9peL8RV?=
 =?us-ascii?Q?9fSFLbno4AmTJ1fSiEIyyohEE064gEroDSm8XNq/MB8OEEMKSIj0TriT3Ssw?=
 =?us-ascii?Q?VortqCOKPGT2hv8cT1JPF44pejI0n1LsWAyFLR1gutdbrehx8vokd3u6KVqI?=
 =?us-ascii?Q?GgPqNSiI3YrCnTVCk+Tz3GPC0uJ5ZIw2yNL/us3HAvbtqxm100PlHVaPKdYe?=
 =?us-ascii?Q?2V7O9MKWWOQeDozXhmfBSqmAUYFqt1oH5vl0hq4APA24BfIXU+HWhyrEsuz+?=
 =?us-ascii?Q?wq0KXWfVrz0k82RLqVQZ/J4eKXhnTPDrOA7AaaickgYp0gQu1EwhU7ifJqHV?=
 =?us-ascii?Q?rqQ23Oqz9AD/ntgir855KqvA3s5THBgyckszj+V270BVldG2vBOQkZhkBQia?=
 =?us-ascii?Q?e/Tr7EoOPpmzkqHbtsiw0H68hrG0eqMTcuE6RCl6X8SmIa+hl/4V2lg41ndB?=
 =?us-ascii?Q?EuqxZyKqlPaSw2MjBw8QvvlvhUWWiUpC97XjmiGOrmU5+WoChm8Zts5NOuVt?=
 =?us-ascii?Q?A8Ki/8+2p7ahT+pimvRT2prrUpAQcHs5cA/Fx4PDgspNgL/FwIU7g7Hccb+H?=
 =?us-ascii?Q?aqiEjctDv2j+q294LXOSulq2fbOjnK1RZtOSSVSPy1WhZZ1Alz3sTuPF99tO?=
 =?us-ascii?Q?udZXTc4yis+0F+KaFGNDjVCDRJc+lOAocmfLdbmKFPwbbIjX3mPFE7zajQd5?=
 =?us-ascii?Q?qfo7G1Gfvl2ydc15Lpk0AS5qoTk9zwU54HbX9pg74pg8KTlE5hRf+Pa5ocmO?=
 =?us-ascii?Q?cHlGOnwIcdwg2nys8IcpbhTR9gkPhnBbid/BFf6fcWoN3cpUWYOylZPFUk03?=
 =?us-ascii?Q?HywyUTCqV/tnz1EUkeEfa291hPquovP6yvS2pL9GrerxVbQaXpVgzcTJLbIg?=
 =?us-ascii?Q?+8EYx0FmnXIPtYM4tFEY3dbme+u69ebfrxAQIKIQVCNwN+nDWv0FHN5t7hbf?=
 =?us-ascii?Q?RzY9nK7LKxC9CAhWPmtD/3kHWAlIPWMC61O7+alpounDIUmQRJl3h+RGct+y?=
 =?us-ascii?Q?6eCVWNGJZe+TjhGMDjxpT33n6ZSxSyUd84vSC8czzPWG4JS/IhDOzsvQ7yDq?=
 =?us-ascii?Q?56yBS+5JjbfIywsP/qiEAV728XS198lNNAFaAmKvHE9QknNxJQTLoX29Kgl8?=
 =?us-ascii?Q?5WqbAaDpYtAJhHDkND5bkNY455cdXsjt0XTjDWEbD9A1p/r6J4Yf7kIXShZF?=
 =?us-ascii?Q?/IouUBTbEb9MU4sDMEZz8eKXYjmBhmh/Da085uGm9qmpvGAmnhn/4G5G2r+R?=
 =?us-ascii?Q?jOMfKZc3Z1rR6MN+r7VxpOBLd+Th1pqOiT7cDdD8m9TfkRZoSjdxvivtFHft?=
 =?us-ascii?Q?YZW6miCbA+sYYRu1iRXK+Yn5tSAnkNiRV8QX/Ztjw3FUI5xRUysfEA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(921020);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VaRDYGzlyPZ446X9cUFcoyBn4ZNwDpZl+Wn1SszX+e8axirqjy+8nBXqF20N?=
 =?us-ascii?Q?9aKtqeEbs0Jq8B7NCS/khSfonEox/eWnFHb6kOf966QYkVg/ET8FoUvKKqBs?=
 =?us-ascii?Q?V3SUQYRMwHo9y8uXX3e/RdmPF/pmvKhvdm0Spa61mTHuGNXRojfrkkKuaOSU?=
 =?us-ascii?Q?h8XBNpQ8CHYvnI0fJHnJc2RyhrnvyE/7KZ1ah9zOSyDw2D6SqGFiMN5S454N?=
 =?us-ascii?Q?9CUDie0XpqHCbhArrhnYqWk5yEPecvZDL/ADhpHbKH+XYubEnKJZraeW4uor?=
 =?us-ascii?Q?8lEdL7JGpHDvrxXJ2JFAXFwbTCLSVPFx+xVqa1N1ByLX1AIjkCTQXU9th90X?=
 =?us-ascii?Q?Z2YrgDTc9Lq2tLjCMN6A6a08AckBGfEaFnPnABhrWuGD6Dx/DUECxnxL4Smm?=
 =?us-ascii?Q?j180nsWWH0EKFvhP/fwJuixzWKoj1gQL4jWDtJBormM/nSEDvS2OKF+4SVZ9?=
 =?us-ascii?Q?zxK2/RCBGAAdzl8uV0xrBNNFkpkRAnlez7v2PCxpTEzfAuollRpheC1xqfht?=
 =?us-ascii?Q?3HjN8M0xDa4a0wr8CW65uMdG1gwwRt9qrU5jnaWgT2n5gicGXcRSAdrRhx2a?=
 =?us-ascii?Q?/XmGx/189f0TGjStS02vZHAtQ3L5vtToX4bGwAKFAUq479985fhUESmNttMA?=
 =?us-ascii?Q?6Q2vmD6vLFaWZGjjpAY3kTV5LVzOtcFf7w16oM+Hddu70x29LoG42kbaNSGm?=
 =?us-ascii?Q?1lJm3SXmb2ykDFOcSeYoT/GONUv2ewDZqf7gh4rs8oA1HHXhs5UqzY2r3QJQ?=
 =?us-ascii?Q?/VOjHqme64F4KM8eT/nGkZeryj3tBQZ00Om5sH++YOs4GxP4TthE7mjG9o1/?=
 =?us-ascii?Q?+NREwv4TdTRck4CFdchOtToNAVaFsdjRNTXm6iC4oYgvGhvrKLBErUBPlCJI?=
 =?us-ascii?Q?wM6BKktsOqabF1AcVFQDveUBB2ClsKavMm1QNxk7j1UDVX6t0mZUvW8c0AWL?=
 =?us-ascii?Q?WLBJfWnMeOHkFjgkxv8t8rAbh6zXRa4kufED8fRgRu6RJ8Q0rg4V81zwsWQT?=
 =?us-ascii?Q?MwbMgIvsOD+RH4YMG85gaI87L8e4duL2bwy3WNN0OLmdqp33FDZ/e4D97/GJ?=
 =?us-ascii?Q?0CXch8MTyrNJvUgn3Ngw98JmGAOCsAAcutZbuaLFNbdfEBQVicuoUpHDnIyg?=
 =?us-ascii?Q?QGZFX8AolMrtqoIKanyrjxkT9NbIT+G0mDhu5k2puPxH+HKCAAqSUi7cmpiC?=
 =?us-ascii?Q?0yMmruH1U6FSi9mmYUfHUd5wY9LGYJGPiGtc2LQZx6wYSmVeVdp8bWT04woR?=
 =?us-ascii?Q?Y2RtqT6jhSLWiIxIAfZJE+xzPzLHyCBCRVL1/0s1ZJyqd54qkpczi5Ee4MhE?=
 =?us-ascii?Q?EhR+5d9FZQG6oAWosn95jIuApoA/2+iVxkRbpYQMoQJDUzegBmVqovtmhCbS?=
 =?us-ascii?Q?G9bErnrTylhfFf0su/qLKauImRiYfpG2bv15tp1wxP6EIrokn7NqJBrpF2fV?=
 =?us-ascii?Q?dsytqeOyByJ1NKoQ3EBtGBe2ts4yIFdPjYbAd7U5CCARf9OsQF01liBQECFV?=
 =?us-ascii?Q?lmxnQJL/+8WPn4LrX61pDLzje5ZofXzt0MPyPqqFj6keh/m1o8Rf/X29YzX7?=
 =?us-ascii?Q?pyTTDKVvBwcaN+fjkt4=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a297ed27-88a7-4d5b-a32b-08ddeed59743
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 12:45:29.4369
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: MpjeEYUBSzxhLqO+CFbT2nbSUFImadVFjjLPJK1baSpu1/pO2lfM5uOGwpCMQBKu
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN7PPF915F74166
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=TTXRCLKb;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:200a::610 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Sun, Sep 07, 2025 at 11:25:09PM +0900, Takashi Sakamoto wrote:
> Hi,
> 
> I'm a present maintainer of Linux FireWire subsystem, and recent years
> have been working to modernize the subsystem.
> 
> On Fri, Sep 05, 2025 at 14:43:24PM -0300, Jason Gunthorpe wrote:
> > There is only one user I found of alloc_pages:
> >
> > drivers/firewire/ohci.c:                ctx->pages[i] = dma_alloc_pages(dev, PAGE_SIZE, &dma_addr,
> >
> > And it deliberately uses page->private:
> >
> >		set_page_private(ctx->pages[i], dma_addr);
> >
> > So it is correct to use the struct page API.
> 
> I've already realized it, and it is in my TODO list to use modern
> alternative APIs to replace it (but not yet). If you know some
> candidates for this purpose, it is really helpful to accomplish it.

I think for now it is probably OKish, but in the medium/longer term
this probably wants to have its own memdesc like other cases.

Ie instead of using page->private you'd have a

struct ohci_desc {
	unsigned long __page_flags;
	dma_addr_t dma_addr;
[..]
};

And instead of using page->private you'd use ohci_desc::dma_addr.

This would require changing dma_alloc_pages() to be able to allocate
the frozen memdescs..

Which we are not quite there yet, but maybe come back to this in 2026?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908124526.GW616306%40nvidia.com.
