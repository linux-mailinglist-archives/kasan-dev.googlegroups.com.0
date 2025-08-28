Return-Path: <kasan-dev+bncBCN77QHK3UIBBGHGYHCQMGQETPOW6QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DCC6B3A3F4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:17:46 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-327ceb05e9dsf286143a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 08:17:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756394265; cv=pass;
        d=google.com; s=arc-20240605;
        b=QY4Fq746yEFopgbCNk+IAj5ncUItPNunW9yHsLCqCU3109yz8P2rQd0Trdg0GQbuh0
         2zrRqDayg8awcYtaYIDeUwQOQ3sVoh+LYF1LfrCYlJFq9iN3G7d80m7pqKeU54OOLE7J
         Xin8gBm2hPAyKkcr8226gi/510LPz0neor7jkn5REpxPxCuexEpCMK2LBgnbf057U67E
         xGjlbaiYfT61CgEePZWDu8cvbr89EP49G4PGm5BzNmPx8sG0oNyXKV2K+3lHhZb7rDE0
         oIBTAdtEJCeQZiF4dvB8STHvtG5YxX3hIoXaCdq2NxvGuCoquLL8gD82na6MWl5LkJPB
         aLMQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=EktOAH4XLW3RkXV6LT8ZnWprPKG/Z/DPMBHL9aUtOww=;
        fh=UZNBQoqIDSmnC1daoGIJlgIE+e8V1wMfiHGM0Or5GAs=;
        b=CGqSVP8dNYoIqElaXB/Exu3Kj8PabTqaUOEXnLTSZOk9LBxIVTZysV0Xz1WhkEd7Ln
         F4yACSUAsisGMBHQqgVTZfiMTF9lG98+68GQ0j1dK/i/qg2JS27XVZOcLx+2qEdral/t
         jjHpZtUyYqYXL2rxgIhwiMCy4MukmK5XRpt66cIXjAj16KEClgySqLjpyamotv4g1FOz
         vBxHZ+5XpQWZYWite1F1KnHnJkO69b3ES5Hpy6QA45/SLnnz6MDDBD7ie5KcsnzABMj0
         73VkHKJ2+ZCKb6Yiynwhuqm12f9oWn+uy2byDAkejLDg9IOqkOOXu2WA4PsAgRJr+X0C
         CSVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UIZ0GZxL;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::625 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756394265; x=1756999065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EktOAH4XLW3RkXV6LT8ZnWprPKG/Z/DPMBHL9aUtOww=;
        b=sewS8zI4YOF9v74+7Aw63cL9+h68KQI3s/ys9AX/UUBc0PiXyA3G3Beyfg5mZSYa4c
         ShaYxLUN279loE+fa6dhjL5htcI6ROvrd8aRWaKXOMg9UGUs+HjojR/GpMBBxG8Wd/Q3
         cdXxuoO4ZNybbGsz8V9vqtPLaBIrBQkiuVDkEZaCYJhg0oebwIa2TGEAMrObPSUw3Njs
         3pcNO8G+BAi/D/HXgm14py3ZkkmdxQ0xufhbDxFB/2O1qf0Xe5oEf5tERsFkJ7VrFx++
         6plDMpC26qwzZY9Hh1Jrqqyh42B8GmH+no1nCq2m4JjowVtE+d97pFuPyodlMGG7uTGS
         nO0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756394265; x=1756999065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EktOAH4XLW3RkXV6LT8ZnWprPKG/Z/DPMBHL9aUtOww=;
        b=rvSOUNnaFDeE0OJoFPQD8sKc7JejygWFagwgV76Gavzs3mfpnb2uPZ2eFQTO4ZKFax
         F3NTA02iFyN0Ge6c4t9txtARdoEIo+lTa3py4OblPRuYzl0V/QeaGTvW/tn8Xmrhvdd9
         HqRDVrjUjqOIh6fJSPDLbi4fvPFji1yTIq/0gQ9t3jXFN8aJbdwvHSYQE6M+Tqe03a+4
         48kA45c9voW8XFqOCymV/4t4TVnf736NMiyH/JJbOjBzVCML8eLl9SR/ISPmkPxrIFZ1
         b58j5FvsMSBeNQTlGhgM/wLRtH4SgK8g7FKFjkTmDovE+TIMOMxQkIPEWNKEHvZAuHrJ
         9XZw==
X-Forwarded-Encrypted: i=3; AJvYcCUNPyRWyIZtY7zMm4FdDhMq40RSr0F0j0akhbZLU+qqlrBwbWPlV8YGm6cRVibv3b39r0m3WA==@lfdr.de
X-Gm-Message-State: AOJu0YzRnFhptFB8964HIFw0QO3UoTx1JN20AN0l7yWcxBMStDHCgFe8
	gvUhMsbwggtu/D7waEVN5Q3ULapc46sDe07CYJq/RESUoI5aq3/6vKb/
X-Google-Smtp-Source: AGHT+IGFeVJXOlaODSloRi1zUvA4sqPi68024gnRXO8BPOJCAUva6UjGukY+q7oZnD8t1SHz3ONtDw==
X-Received: by 2002:a17:90b:1344:b0:327:78ec:7bb3 with SMTP id 98e67ed59e1d1-32778ec7c71mr7764982a91.27.1756394264896;
        Thu, 28 Aug 2025 08:17:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcLp8AZsMrn+nCthaggf2fK8klQIccmLf+QG8MO7IgzsA==
Received: by 2002:a17:90b:4c8e:b0:327:d8f0:e20b with SMTP id
 98e67ed59e1d1-327d8f0e3e6ls18512a91.1.-pod-prod-09-us; Thu, 28 Aug 2025
 08:17:43 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVX0BN/AYlK2iFfsv1G0Yx6lGXbLQHGUGhh5oLsoAP642+yK9JOW0kYHwD9hv4/oasFscZvGN1nEtc=@googlegroups.com
X-Received: by 2002:a17:90b:2f87:b0:31e:fac5:5d3f with SMTP id 98e67ed59e1d1-32515e37453mr35596822a91.16.1756394263171;
        Thu, 28 Aug 2025 08:17:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756394263; cv=pass;
        d=google.com; s=arc-20240605;
        b=AO/OHeeMULm1+E8lq19TA2i8IjJ1btVl5HS8ol7r5qMmG/oN+dQRnKuFgUakQKi+5+
         1z06lsvtAFRkULCr6eD+pGRz6ivpmCAfBGTIAzaPau+1gFjuXg9EEN8RL3sAcUZWypYO
         VRH31xQG0Gl5MUksmSlWox7XSJ87KbDvnBN6DmmxRmnJQC7fxyMNnjaFw/7TKAmtKWFl
         biOq4EEWJzoOKxtjQdhwqkbFq/WFHqW9Z7MVPOLaH8vAXYFz+EwI7WbTqwzEU/BD3t8X
         Ca7Rlkod5cO9WbL5MlrLuF1Ep7BCvL91dVEdwB3se8do6hX/qcZe6sdkLAYikjRMlzX4
         uOSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9Gj2EZNRr0DPgaVxIhfrzZTloYAFkHlRSLQ88RnkN/Y=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=i6eDzhv2k3P21PJMfBmN3lMLuf8WpPa9+reJ17XzUqUb1glFckUZhzkIZDGWIo+2dG
         Psp6ddJA2JwJed3Ae4n/MJ6G25yq9GSuTg2g4gd0v3P8D/04KY7PE9wgtAPge2/KUQD3
         IRMDL19DN4GO06wjJgGTDHZMWyFeRp3xLBgApnqSPdM6t8y6Dt3wih9/Oe1oz0sacbfo
         dv+rOj7rsAuMn2247FEoI4LxKlTOlf4mfKvRZaqGyG7TPMjD4UNknT1ee72j2t2NAzsq
         rxHZA2O6EqVOTjUSh5/gaxMGe//yQAXqvr4tN+vnNcA4bfD0Tx4aWwyAaypo1/sIBKqY
         dQLw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UIZ0GZxL;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::625 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20625.outbound.protection.outlook.com. [2a01:111:f403:200a::625])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327d9331daesi1341a91.1.2025.08.28.08.17.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 08:17:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::625 as permitted sender) client-ip=2a01:111:f403:200a::625;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=DeFisRlfdtskQJuokSZMY5Xg0kP2ri832SWOoOxZmFyfr1hQfzKObwTm+dZ/jmzAp7YiYKcameskckoFkgeqeKsJxR2M86hxVxefTFJbbHlbo89kJvMWfHWDSwK/7Xbo0GP+iu1sr0X8F7X9m2WKLIg4t6QznLNFOH/MxS6vCOK3IPW3oyYLUg9yK0etWTT2a+s/dKUyjQ88tELxataJ7E5iLzNbugrf5kkulSCJGU/EvDMBusPgZ8cjI4kdKgZrWBT8VeRErl8D8Ri5s/0qX+BTGAQoUlsRXJ/0BnVyew7Z3j3iM+QlgZObIGJGnjVP1RNDkbX2v1H7YIjLyIISSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9Gj2EZNRr0DPgaVxIhfrzZTloYAFkHlRSLQ88RnkN/Y=;
 b=dJXQVVIKxoWlQmbSqqZra4WL6Kz2zfSDPLs05lcSjOU93g6u6C66YMMC8Lt3Gk8wFzCpFvCT5ecVUr69Yz9PvqCgt8QZlH+B83dzj16RIDYQMsoCT04lKTgWQTCPY1rNP6GnD9WyIvwDUgafnL0bPZdm8DCw5ABjQBMBINbCBaiLuf7hCYi52ryeathkd22iFVq6j6zhCh3E5CMa04us5TUS23R+FIpNb8rlNq78JyS1RQyYFtZ99/2WNmCca3aanZ1jIYmPQ/OkZg+Wvu8mWT96SktYVKQjqsH52wQNa9gpzJz/G0n/q5JG6ysHSnvUGNNYmzoeUJKVqVuN27ktMw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH3PR12MB9342.namprd12.prod.outlook.com (2603:10b6:610:1cb::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 15:17:31 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 15:17:31 +0000
Date: Thu, 28 Aug 2025 12:17:30 -0300
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
Subject: Re: [PATCH v4 09/16] dma-mapping: handle MMIO flow in
 dma_map|unmap_page
Message-ID: <20250828151730.GH9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <ba5b6525bb8d49ca356a299aa63b0a495d3c74ca.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ba5b6525bb8d49ca356a299aa63b0a495d3c74ca.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0001.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:d1::11) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH3PR12MB9342:EE_
X-MS-Office365-Filtering-Correlation-Id: ac16ca3a-0c04-4c85-d3ef-08dde64601de
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?njO48yMTkw5FBTMUHcU9RfdwduyPEqfYr5sDmRvb6M70ofOoeXEHGdq1KNf4?=
 =?us-ascii?Q?QnOK8yoCKTiN54zd+3Ivy4vhFI07qsRdXAtVykVph5TO913t+GGI3xiUDVb+?=
 =?us-ascii?Q?jdnd66i9zxJkY2od5xp8XaKem47dhOkzbyqZTg0QSTIE1Kl+JtwAQuGucH+T?=
 =?us-ascii?Q?WjnqVfoyqNqJyAXe7F4pk/eGqkOCR+KiacAhMEjzezrQL3MBdzW1NdVzexOQ?=
 =?us-ascii?Q?4JoB0upSpmTOokwwxt2bakEPV0ltEhyRe9dYQxfuSK2Ni5IBHIpgyw9/GjgO?=
 =?us-ascii?Q?rNdkK/h3qoZxtMvYY2QtRdUSkPrc4Xxm4GIfjB32jEXKmfR0gmsX86ipkdSl?=
 =?us-ascii?Q?+ImevhWLNt2q31YwRfzliMD7KZSG0HsQjlY1SSVnmAUUf82tnmqrimbEPDLg?=
 =?us-ascii?Q?eSdVfVKj7cOEAAq1+leLcYkCxGBZl12n84VymHT0KYsqW8wleBoLujozvOqc?=
 =?us-ascii?Q?zmgLDEGRinBrPJDXwZuGq2f9BT4fJm0zdrIJfns1LtxKDEMqVmDAWNh8/SgO?=
 =?us-ascii?Q?9V2fUyO5leN0oa/4AVwYmWXV3aV4V2gUOzu1EVUlutMPRpfmeGz2vW1gub/D?=
 =?us-ascii?Q?ki9V01NbOn8YGcJiX8wDYnKzaK4aqlnnVuZH9YRSeCaaRm1Muo77Uhd5L3LH?=
 =?us-ascii?Q?INl61YEAVQO0z56Kjz68QZSheFaG3KDVD5f5BEn1oRj0PzThcoCsU2k9tWIq?=
 =?us-ascii?Q?UxNTSR+Pb4sW53wbVO7DgnW1qURzXATYaVpNa00mg1Yy1LSGgkQQCjRYGBHq?=
 =?us-ascii?Q?27O1T4Jx5AHYP3cBB6ymsreMfcb/Ta+gxBBQAtwbjxMsJVU7jz88CVvQn7/z?=
 =?us-ascii?Q?+WKSsy1NKee+3h6bbDYWAOH4FdM2Y7eQx41AvGBe13AgWiTDC0b+ZD+eRZWx?=
 =?us-ascii?Q?ZwsdUsxeIZx+zEvtrxiMU5OhJJlwBlTPBOjO5wSkKX3WqPUSpjaxR8BDV2VU?=
 =?us-ascii?Q?1wx3mUKsBiRWWhdj7HUjQN53bDZFnAWV7CUSCUt1EO/Y/VTP3xsRgujjSe/+?=
 =?us-ascii?Q?BSLh/DT/4OCuihxSMkTch9BW7a3YK/5gJJyPDDblqNZ0pcDTobHcfz8DTYJn?=
 =?us-ascii?Q?Ck8DUdWdRnBvLdNHEaGz8HiqeczuoebVoyqnxnVuNzA+nxR3ymb+d0uKw4uZ?=
 =?us-ascii?Q?iKR+taHPMsQ2WzJ7cabBlBYVSqX63f6H5dMGHIn9K44bU/MW0BOeJY4BhkwA?=
 =?us-ascii?Q?QHSqhhpxargIpwGhK1abMW0zmR+qJVJuDoXc3rIZSpt8N3mkfHnb0ikI8p48?=
 =?us-ascii?Q?CwJzWANXRtAbCp8qfDMvPDcUQuWlZvAVE8yRoHDUNhguvACqUuTu6nDAg/vQ?=
 =?us-ascii?Q?t5GGhsyS4K6VUdYb16hY8nIS2UJkrMLqTASPdhZdqWPT/P3qqDThBqsezU7w?=
 =?us-ascii?Q?ckjS0OwVRy8YboJ9/UkMDTqTRY5Q2TSeLuYkVmRNbBTZUYbRAwnlOakGXQWO?=
 =?us-ascii?Q?xKNTVNVhIIc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?jdNZg78XP2T9TUtHO4FrQOYHXwTm5pXMXy4+gH+6XrSX7+gSRUdR6SOGtYEH?=
 =?us-ascii?Q?HBth39Oc9aLRJBNWgk7O8lPEICHVy+pfoNIpyct5Rj3WezAlVOXAvl4iRCzg?=
 =?us-ascii?Q?VRcyxl9TvcvDq4wWiG56ZTJlx7IDlObxlQ9JuyPvdbibioMEpVIfgfJGHkB/?=
 =?us-ascii?Q?B5MPYLJACoNIJH3MHSn0DW2KwM+6yeEyfC9LQ4PqD9PeN7fmLX3u/JSRbXIy?=
 =?us-ascii?Q?NAXdRpAs3wuONAvSTzn+75geHNCvqxmuFmZLoEz/AqX61KOtRvg93Ee78uND?=
 =?us-ascii?Q?peUCkwk8Oy09PptlLWkstUOcVdOS4my9pSfWso3H/0IROqZIFLkKoDoNkwcv?=
 =?us-ascii?Q?kILYeC7kNf+VH6z19s6jkr1t2zH4PtxftHk+sUqKCeX4wQV7ZJ8w6+ko2CqB?=
 =?us-ascii?Q?iEXLEDSYPg85+Njc5Kaw6p7ej/9nB5LQvS3L9gSNVGzPX7fiPT0jfn+sbDwA?=
 =?us-ascii?Q?zDo1NrvIGE8yJgrURQyQGI8NGl/gmac6MSrfKEyE2wYOwuihBg+52zpOsKDT?=
 =?us-ascii?Q?zVPQGuknFn6xhw0ULIhgilBdsMTevgwlb8qik+1gJ43vwHxDHCa2Anp9iHQk?=
 =?us-ascii?Q?TJLSt9NQ1qSa8R2ssZqykd9si9z9ihI5/MiAuuMbmYKUqklCS2wrGtcSAl9t?=
 =?us-ascii?Q?f7B56uwj1x2ObZAI4STPBh9GoCG0cjFA0CDbaCzesWcfTbERSpM84j599A3A?=
 =?us-ascii?Q?7/pOpboO/5AzqdZXmgN3iusPK4ZsGs3PawOZNUKRjdOoMirfvjsNjGaAu3e9?=
 =?us-ascii?Q?mHR5nsa+ehX36f5u+5vBZKoaCd7cliPg1DxHMnaRcEKCzF/+WOoA7I23qLG9?=
 =?us-ascii?Q?WWME2fMxQsO5zwF5c0bzvTXVO6Hi2XAQfd98biDYJK17A7m5+17+VtkU5337?=
 =?us-ascii?Q?YjFKF/V5Pq6THGrsvVlUSNoNyIG/X0vgCedtyw+iebNuNTKeWWOyklAbORXt?=
 =?us-ascii?Q?2JUO+pW6trCpPpIAfhnlNn4EQ8nX8WAiUMIdLmvdkP5pQpAQ2ATG30U5vkJI?=
 =?us-ascii?Q?MhRMHPJ1FVQgx7yYaRYurqh8qUxc8NDRXR1mXSAO19NQo+k9y1rbWR+JlkLG?=
 =?us-ascii?Q?FuzY4iQ4QiaZwAIKT2jv0ZXztWs+nnlZ2aIG7UdiTK++Sl77Fx1AvE65Amt+?=
 =?us-ascii?Q?Y1875MWrBCt+Wn7UE95WSo+fXxDYboAE+E8BZ++FSd91hEpKBaTazy5qHd5F?=
 =?us-ascii?Q?GvYxoLDevzvJgY7AqRGDY6RqRTMaSAgYOTnWAXVJEqiXjStCFQ2xk2mhoZ/9?=
 =?us-ascii?Q?4O3blNpfVskby8PNMgxF4LDXhmAmGIZ97qQgKAQhEvx9H7K+lpUR9d5i4ctY?=
 =?us-ascii?Q?UMUIVKh1YqIgWJ7ftzcTNKMbIvuAu44IA5qQLDK357xwY6CzE+ywzliWXGJm?=
 =?us-ascii?Q?L6KnQLr6kD1VXrLjSmlzT9MhabxD2MryJs7/a9RtUr/RmwVnntoTXxdp1NJG?=
 =?us-ascii?Q?IZzy0C2fDKu4I01dJA/qvtIZRvPDzy/WptVch3Jg08J+u7E1GsZKopGv3DLM?=
 =?us-ascii?Q?lCw0VQ+/cSQbw0BhTD4bvNTf8wfDSAMKWNhgcNrXutwByTrAMqSyv26wVxme?=
 =?us-ascii?Q?1DqU5O6tlVCU/VrZBMg=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ac16ca3a-0c04-4c85-d3ef-08dde64601de
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 15:17:31.2708
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: PZwuEXlW337UFGaRmTgrOOZ86hQJ0hssTlhNBI9xQ+44PM8OwEdLJrn8oa/w6/tN
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB9342
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=UIZ0GZxL;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:200a::625 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:53PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Extend base DMA page API to handle MMIO flow and follow
> existing dma_map_resource() implementation to rely on dma_map_direct()
> only to take DMA direct path.

I would reword this a little bit too

dma-mapping: implement DMA_ATTR_MMIO for dma_(un)map_page_attrs()

Make dma_map_page_attrs() and dma_map_page_attrs() respect
DMA_ATTR_MMIO.

DMA_ATR_MMIO makes the functions behave the same as dma_(un)map_resource():
 - No swiotlb is possible
 - Legacy dma_ops arches use ops->map_resource()
 - No kmsan
 - No arch_dma_map_phys_direct()

The prior patches have made the internl funtions called here support
DMA_ATTR_MMIO.

This is also preparation for turning dma_map_resource() into an inline
calling dma_map_phys(DMA_ATTR_MMIO) to consolidate the flows.

> @@ -166,14 +167,25 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>  		return DMA_MAPPING_ERROR;
>  
>  	if (dma_map_direct(dev, ops) ||
> -	    arch_dma_map_phys_direct(dev, phys + size))
> +	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
>  		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);

PPC is the only user of arch_dma_map_phys_direct() and it looks like
it should be called on MMIO memory. Seems like another inconsistency
with map_resource. I'd leave it like the above though for this series.

>  	else if (use_dma_iommu(dev))
>  		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
> -	else
> +	else if (is_mmio) {
> +		if (!ops->map_resource)
> +			return DMA_MAPPING_ERROR;

Probably written like:

		if (ops->map_resource)
			addr = ops->map_resource(dev, phys, size, dir, attrs);
		else
			addr = DMA_MAPPING_ERROR;

As I think some of the design here is to run the trace even on the
failure path?

Otherwise looks OK

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828151730.GH9469%40nvidia.com.
