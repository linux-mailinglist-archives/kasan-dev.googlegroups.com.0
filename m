Return-Path: <kasan-dev+bncBCN77QHK3UIBBLG6YHCQMGQETLDB5OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B8262B3A331
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:01:02 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70d709a78d4sf2127276d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 08:01:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756393261; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ype3itEE/xi8XXealfWX/cHvjsG30bBNfhjTdPE/RBpTo9sgsDvOdjkUZG53ZDhMj1
         j9n54uUN8m17boCsuo2bgKYvnM3Gm+SDFv3aeR/kxgYJN3SeFFR7IkKEsW2CS8BMCY8k
         mk472725sNMf8s2cZJafF0Uv8k4atHJ8Rl/DRr+O5HvJ+imy0LSTW+ViRGrYFvhLiCjt
         R5tvWfeopPSu3mwn8HmF0GZfeqdYE0VKqLIxlrN7Q3ov/fYw7BXxuTdOGVXs5W9DdZVN
         Wgd6Avw4CpBUc1kKR6Z/U/k1xkA/ppgHYIWYLt+iQmojGEgjW0dNVD1eHCKvN75xDtHp
         HTXQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=CRRSKqSAnoamu/ShK1wx2SQY8XamlhmXuYWgvmFbGY4=;
        fh=Wm8Pv31YjHibbnX6Ct/IZx1pPL8wrnSfhYQr0WoYJb4=;
        b=ATi7w1ZiELqs2f4tOV1Wb5V79oOrC29TGF4w9NoVsbRNZuctPS0Pps4UEM3FsG4I+C
         JH+glmNR+gssgg2qH+x2UERLPWJfD1trtyXeZ7891zRXHcmpp4aWtnixc2G7nL+dbX0M
         0su2ZBs/7vm3xV2V99tRGqGBOvD4/h3Ht7TrZMxGaJZX+rWAv3vaXQVmj2sbpMA/bixo
         HLWyE/gOWrElIqh6MEZqWR5xTPo7Sv/KShBpHX7zdY5E37iHbjSbvQxEQOO4Yfsxcfgi
         pe3A1zsTM/KnEsfoT3Vlte/aMojzD+NwALIBiB/W87iYWSbELxQ9swqhPsUwTuLDEdsD
         0krg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=qkezqVMz;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756393261; x=1756998061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=CRRSKqSAnoamu/ShK1wx2SQY8XamlhmXuYWgvmFbGY4=;
        b=Kvj3Rn5ZPMzYsudOAq4LAKkF59WvwqU49t3Iea3Hze53MlVj6mAG2rBHj7hYlMsVJA
         wmSKhH432d7qRd9LNvyvFuqEfU2s+byqco31jrdJeIbZh1eIO0RyDZo6QTqVUtbAhDUt
         +e5oiszmkW7lN31ll4h5x61hKlnLaZFGnHhhAHGkMSl0Qhgjvze81e5hNqi9LUr0tt1P
         C+UDtJZiZEAvxXuS7UKqhNIlmXQ4b6WupccPj1GkTfMZtDpMp7LqGO6nO4Bl7rqKxv2s
         kOx4HT72joL/3zJspazQw3G74XpVN9wSnIPyU+ii/q77CeWZAFUsucMbE/egcrFWiiel
         3OCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756393261; x=1756998061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CRRSKqSAnoamu/ShK1wx2SQY8XamlhmXuYWgvmFbGY4=;
        b=Ke0mODsVjrPmQqpE9v9LUkQ1NJ9PZS09zbJVRL5lAfasBWSSuJlFizdOUYqa/kWxdm
         cVjIEnUq8D4Ad2ySMkAeRGT1FYPFwUVPj9IY4PDkZk7q+uh2JrFzp+Cc/tpdKwbQcImL
         eFx9OlHWTWsywJIAA4UAJYM4QaRPT2QboFkp0QP7iOJuAOIOpbUUeqssSB8MoMl14rrJ
         LbkzJPRUoQ2csaHo8Z7MBn5A0Yy3bskoVi0RUex489R/0Hm7zQiRnFrOLGa7krNOLK1y
         MdZOWqKOOdiarj2h5dsY8iwR4pWjouZKNSH+fCvmcxZyUUYaJ7uJRXKyx8VEMkrCZxa6
         c2nA==
X-Forwarded-Encrypted: i=3; AJvYcCWWCEJy9NiTToSkXQ5T5Fm+7ZZjcz65pSYagXCCMmwjxWgVqpSojPzRbHW924cNOnTy88bpmg==@lfdr.de
X-Gm-Message-State: AOJu0YyN/HjSxtgEOET9DyPX32SOfreNhKqIqwoospaKdsCA5lrnfvno
	4IrNb4jLR/GocNIC17CPI3iNmgOs0N9rTt36lrP41ToSWyouQLwLz+es
X-Google-Smtp-Source: AGHT+IHmIc8gi0XoTDJfKfjjqWQwEJLlRci2kxg0XDP2l5FaDBsFHyMMvx4os3tKHSyf9UHd424dyg==
X-Received: by 2002:a05:6214:268a:b0:70b:a0c5:5687 with SMTP id 6a1803df08f44-70d973ab53dmr176693836d6.7.1756393260852;
        Thu, 28 Aug 2025 08:01:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc8InnIYs1Mo2Wm8oPmVJ1LykOYIvtAvOeltsXvsOD04Q==
Received: by 2002:ad4:5963:0:b0:70d:a451:c7c6 with SMTP id 6a1803df08f44-70df000898bls12176926d6.0.-pod-prod-02-us;
 Thu, 28 Aug 2025 08:00:58 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUOvBtiNkSVPQ7oWUDOv5uyckwZe1xhlhR7iRIOl1V6oxWqcC3fCQXijXfa25RoJncMcXf8DTzAhJ4=@googlegroups.com
X-Received: by 2002:a05:6122:4f84:b0:543:8c04:43f4 with SMTP id 71dfb90a1353d-5438c044754mr3979087e0c.14.1756393258508;
        Thu, 28 Aug 2025 08:00:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756393258; cv=pass;
        d=google.com; s=arc-20240605;
        b=IK9tFjMuOQjsSSy6Tdzea/3DYjaAMauNizN0qb3J6resRFBMbjuJLikbAzFQOAwQm5
         vYbm2bOJgAs0ZBpvJDoPMkwKyzVE2WlYT1O/z2uhGhqPMUU3RspWXDshLpxSp/S2Sy/n
         bdooKwwqrlYcw3azovL4c/pEdS7apNPrc/eWDCqsqA11HK6zy1ZJqe/UKfYwb4/ur0fB
         DzGVWIt+WmQnVHEO9SlHlZh1puuUY2MSnYL47BnGdCu3DmQ9Q9XpN0g+DhALf4gVLx39
         6bnFYYdsQj4TFdqOrKqPvB0lpV0feWbKx3CqgwPk0whN8rFJaXzoCRH2LuNXCzxJ8Ews
         kBHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YhYgIuXMPDyneIixgb3ayDngq33diPvUwzKhingnZUs=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=Jb1P8OjK0TQsXShY/TNpCf2OdDLxQ4MtcOZzEwRt3z2rZaSM3o1fl8uerYRcLAKtCq
         wM7jWYnjZTWEx9H6SMRb1bS+nnrKlSsqmfC7j/1YCNVhFjq7lUZxo61s+yCz2akIiVGB
         GPBIf0uBX1EPSbxQ/jNTz+Mpj80P1BN01AfnlPYosQ/20BJkkvS41imzuFhIpJuwaFAD
         SfwAT9xOKJPlWI0qubsbEUunNxQUSMYaOTyjZ9g++XnY0jC7MmFQfCOEbExHpfM1/RGC
         T4dfSYYgQ8847yT7Ej9vjmDAohyGpSJ9DvlcKQdrnnjOJ7eEtQW1LHfEsBY80cedcf+M
         bSDw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=qkezqVMz;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20600.outbound.protection.outlook.com. [2a01:111:f403:2415::600])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5443064e3ebsi237238e0c.5.2025.08.28.08.00.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 08:00:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::600 as permitted sender) client-ip=2a01:111:f403:2415::600;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=NS6QF9PmkhPSetggaII5CehTlNqOJP7vlZ3U1FhtbEJxV7OqYGAMEImFhkSEkVt8p4tMk12Kq+qkyt9hkXaA3hNTw0Q/M8JsOk89YCE34YUJMbwpcSbThpcPNb8wLgyaPwW6ZGVpAgcGi41Oc/cey8aZQgz7mbUCOQ7tc/sczz3afaA2QRRBbuXquufQAmJf9sL/A6SD/TF4rdhqnMo48S2K6UzD9pSyjxqV2sqNVzD6z6Ip+oi/OabsECcItshuq8tNhBlbjP1tEj2lLzx0DCeMCiupm+JXR4h6uE9VaT/OtZ88vfpoUxv15tHzMBQ9qGXmW0QvuV+wNoRl6Z0AFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YhYgIuXMPDyneIixgb3ayDngq33diPvUwzKhingnZUs=;
 b=L6kKIA+cyA334TB+HD6KAb0poZQRgfS+mi0YyYxUih9dP8c8uDGCwry1fq5E3IAs3r0+l134PJ+M+RHZ/x8HD7Yt+f0tP6ddNZ2aQLxcz/QkPJ+dRs7igP+u5glEEt8uY2/L+weMU5UCN+OPkEvsRWXhb/OIZ9rh4KubDEOvFUoAIj1k+4YBSjFfvNJLXgwILa1QnbgC65cHcHmZFKcKirSMgnxZcz9ybBWbtd1/tFdgT4E9kgmr5rYCWQyGWRJD+FZmq1hKglllDlaj100v7wtivgG8yRUcVXZh49dztnslaMANyvHcOUx+C7KrcwIl/VaOfumTn7GnMsKKVVxsHg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH2PR12MB4312.namprd12.prod.outlook.com (2603:10b6:610:af::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.16; Thu, 28 Aug
 2025 15:00:51 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 15:00:51 +0000
Date: Thu, 28 Aug 2025 12:00:49 -0300
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
Subject: Re: [PATCH v4 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250828150049.GG9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <f52ab055c9ffa4da854afe47232c7d06d109d8ce.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f52ab055c9ffa4da854afe47232c7d06d109d8ce.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT3PR01CA0138.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:83::25) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH2PR12MB4312:EE_
X-MS-Office365-Filtering-Correlation-Id: cd324a99-7b50-48f0-b0b3-08dde643ad87
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?F3t8pjxGuYiqQXVRHHoABfhe3+nJCLYfL6dfMX6OVHmrSntXdCx5WtVVMFHz?=
 =?us-ascii?Q?yIevAB0p9919JudsrpMU6LZXPwxOeB9F3UoThU3jOmE7GG9uxOE5qnMerxlg?=
 =?us-ascii?Q?AN/UIs/2Eg+OivcbbHEpPHCi39auQu/YZ8nvFxeTPjZk3Ada64JLqqgnkSht?=
 =?us-ascii?Q?543bGq64xQ4iKEYNxa2ok61AsVkpvnT+Uw7NMsRGYJRPYMAsP5PBjypPdUBf?=
 =?us-ascii?Q?81RH4ul4DOiq5i+njO8K39Sfezmnlh6jHSbM73vKdx78Kp2e/lXKQOCqkfKk?=
 =?us-ascii?Q?GqW+8ek12Sua17KiSbBLTYD6OHXBdB/KEbLwIUYy46n4iVYEXrek8Peoq5/7?=
 =?us-ascii?Q?K+OpIeuHCsarMY09f/7Ske6UqL3X2966rZkUOyW8bBJeXZF/5QntDeEXO5H4?=
 =?us-ascii?Q?XSu/AU+Smc0Gu9vuwbA7xN8mb7/fUJw4zfSDUaI1WXJhnh4aqcraj1hcO4O+?=
 =?us-ascii?Q?EDIwkRaibNorWjRo2KD1Xm308/+ExCCE+H5o+9DL6CvUSuvGuEjPZWHGWh1L?=
 =?us-ascii?Q?Qk88DLWsKxzmwnorlRypDjuSrRJbB5gLNQthol57IcMc3Cup1IIXsKyPmYSk?=
 =?us-ascii?Q?IWH2yF8gaH0SdOuca7KzzBqW+S4YE/EC12HojfMnvk09W6nqqb4fF7aaQ/Zu?=
 =?us-ascii?Q?Orj1BFeugwUPXkm2LQeGmgm0hEB3oh/qLZnJS4cA1KO9cp3oYLx+FJayhERl?=
 =?us-ascii?Q?sjLXgnd1db4hPQgzuFmeXwoGL7Iy+wcTnr2oP90fVeq+t38aAtCMB/BRHQjs?=
 =?us-ascii?Q?x9O83XsAWqorEs0kwmGsD/wWNCY3rfNgCxM3Jg6wm7FkAkUfXd8ZQV52+779?=
 =?us-ascii?Q?a5jofWus3cV8yAr4swvRu8HqzElhF00CvUSewWnDVPEETGebx85qNIZFxgS2?=
 =?us-ascii?Q?KYtd1Vqd+kAd8m/rG/y21hHXjwA8HyOBgkLV1oW/H3l+Q5F9Zj358PhlumsN?=
 =?us-ascii?Q?ZBkEOrfZg0VQFTj0dry4OGp4HYTN4KEMh+yianvgfkREmfLiYJNy0xLGrvfP?=
 =?us-ascii?Q?zRNYmHb1BhypYX+XMP4ZqHYhe5wqD9omzX6FhepSaws2mnbL6V/h0843bI7f?=
 =?us-ascii?Q?9J/g7OWg2AkezlH5prpTFen+dMQMWjPHAXqZuMW/hT5Bz4/etFPDwTgv/L7X?=
 =?us-ascii?Q?1NCwRIzvfKHFkhIYGOBODZrs8NLb5i8KHZ0YEMreb3KDZuZNRvRHMXnP2Il0?=
 =?us-ascii?Q?pGtu9m8/4F1vowQ4SUYg8H+QpznU8ztibiwxlnVAl9Y6dbfkoYvwnTb2kVxl?=
 =?us-ascii?Q?CGBs07j5ssRf0PygNTBsuIRc+MoGCDkoaxHNF41xLXDg1HMby8oaNi/d+Z+F?=
 =?us-ascii?Q?/jiqKkjDyWZSULX/+ZIfD5k5Z3aNv7sQTvoozJTNKQf+hutgN9PNPqMM3aps?=
 =?us-ascii?Q?QY+hwbAR76MfSkDtNGbY8H+YtiEZvOwrF73u/2Lko0T85eWLr9f3kbMsUy8S?=
 =?us-ascii?Q?1FKnLopyHwI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uvpwli8oU8wOvJLyl3NwVP+TQsbxubD0QEkBmRvQ2Jh4ZZJP5qipOjZamH69?=
 =?us-ascii?Q?B+PbjhWcvbtpGKlhIxRiDqqYfHFPEPCBZqhYcM3T3ZJCwQw82zG9G2Rke9q4?=
 =?us-ascii?Q?CHgav7pRRa8j+o2jKanzZWaj+WSOMGZy5DY+0AHtPYJI0nJ5hOZvUn3SDpkt?=
 =?us-ascii?Q?0Lj6tDEn2MUr7dn/mRi5s+tS4G54SGWL1gmMMjbn3782+tcgUScunIc00GN0?=
 =?us-ascii?Q?3pRE8QnZ3QHE9tNZwhIa7y+X0nMffa4WSZUKiKe5KdNA8VOOl+TOtsOWaCd1?=
 =?us-ascii?Q?jcHChVqL0T/rslHr4WXAO0p+c3Z1RyNIMo03ObYJYsT182PvejTMDMYVcPW2?=
 =?us-ascii?Q?TxkEmh8HQJHQ4C1zp5n+5QiKUrbxiqY9ujbKvp0SZsFyrXRl0y9aGhqFKY7c?=
 =?us-ascii?Q?s4JSDoQbvQ6HGj3v7qDJDWH0FLS7fYF1+N6yLGUyrTyqzOSuJuDY+7aUoI2N?=
 =?us-ascii?Q?rOZahLnSaGGsH9jYN/jH2gyt3RIa/wpjbTeaGNfIaNMmv4ypGsc7LxZ4a5i4?=
 =?us-ascii?Q?qPt6RFV0Ln+5onDrvs+VTLORC18S6Tu2yzJcwprZV/lJEtiCP5kZ0uWmoXqs?=
 =?us-ascii?Q?Zu+lwyG4f1mD8rOfNV+DnPl4KlKRekyau5weSSnPlOVlVYPg/gRl8KLZCEJ4?=
 =?us-ascii?Q?qIbh1Rs8xBJ8wOG1jy8byWrqFGCUVvzZZROHHnuwjFw0P5z3CDGu9b1s1NRa?=
 =?us-ascii?Q?l0Hj1TmoiopLBTq6x8wbyh2ilDgffTBbrmu+042g58KDcRxv7nui3UD/+nJI?=
 =?us-ascii?Q?yOM9GnMdDPLDOgrfrL7iMO5SEjt83MxpwQoxdnZ0851+375n+sQrnKKouUza?=
 =?us-ascii?Q?5tdZqUIRyEgSx00YK7nwXErvHKgJfWsAsz0+vEnKoOPzwQuo/j+3VMvxzvLE?=
 =?us-ascii?Q?COndN5Wm1bXxccaF9kAf/g40DSjFJPH67o4ODthM9e12YFPj/IxsCaJUDVZg?=
 =?us-ascii?Q?GQhSbzT1xXF2YdalACMmlmSTrucAzSSmwfbiNfM6aElZNJ6NWZgO6ORB0u37?=
 =?us-ascii?Q?G9RgeLWXQ1bv9FUe0PmKyv4Q9COG32CMNhjHgqSML+tgId1eianjVIc3N0HU?=
 =?us-ascii?Q?dcf5rlhw0KvJ/WcSFLUrcXS4Hq10eLpBr9YnU3iGxkE/Z6mqccKBwxjAHxku?=
 =?us-ascii?Q?GTufKt69kT3PxhVdyKrwpZOER+7hmU7Tb6AOxxFAmRiGqOM9Y5JoMuQtA+gQ?=
 =?us-ascii?Q?TQs8oD7Ni9Msd5adVQqHsRdc0ni8RZkTR+IrDWPZiBkkABiDKLMRbpQR9dA5?=
 =?us-ascii?Q?7BSW1ESHp3r7W789bDbU8cdpRR5rKVroZ3TE3SsFAHi/jckiLl3IbxxKZt/d?=
 =?us-ascii?Q?IaISd75BGpc4lxeH8Achj5wt8e/8Q8Qxttl9cgpN9M0ijzLoSIx07nLAJkTy?=
 =?us-ascii?Q?FNG58ONb0+qKUHcGPeSkaO9cE8SCYUNrtCPXl6/aDaEFD2ZIhouLTLWqXE+3?=
 =?us-ascii?Q?cYw6VCnPhOlZhYR/jfb4PjNOvSOX6aokxBVUQa86yqNxMH4vzfOMMQZLHTUc?=
 =?us-ascii?Q?sV4Yc109BXOL/IFth93oiQUr8pcDxVyh5M3fp7VE3fHzDVMUx2C49eAGfDzY?=
 =?us-ascii?Q?u6BMG3n/8GgM7hjb++E=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cd324a99-7b50-48f0-b0b3-08dde643ad87
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 15:00:50.9010
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Z15O0VvpBrGAOGITkb5/Y05ckWmkWXcBfnra5oKm94y8bsDpfspUxCq/SnlW4BPn
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR12MB4312
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=qkezqVMz;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::600 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:52PM +0300, Leon Romanovsky wrote:
>  /* Helper function to handle DMA data transfers. */
> -void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
> +void kmsan_handle_dma(phys_addr_t phys, size_t size,
>  		      enum dma_data_direction dir)
>  {
> +	struct page *page = phys_to_page(phys);
>  	u64 page_offset, to_go, addr;
>  
>  	if (PageHighMem(page))
>  		return;
> -	addr = (u64)page_address(page) + offset;
> +	addr = (u64)page_address(page) + offset_in_page(phys);

addr = phys_to_virt(phys);

And make addr a void *

Otherwise looks fine

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828150049.GG9469%40nvidia.com.
