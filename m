Return-Path: <kasan-dev+bncBCN77QHK3UIBBV6FYLCQMGQETWHQPAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF2D4B3AA24
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:41:28 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b2f9e8dca6sf27830541cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:41:28 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756406488; cv=pass;
        d=google.com; s=arc-20240605;
        b=UgHjLzoavC9zFGrsIIcugDiL6NbvcgZ9oA7KcEF/1WSr8ePZQxh0X1kb3iXYVCaaXf
         ahB+dqryive7vu1+d2SV7TF2zKDtZPpW9pLzPPgwIE0LNsvA8pV9EiYIUnsfhq+NBwWB
         /DyrIW3yj5UqCz7I1sev+X7cpX9fzXKlCttQYBZ64nL1r4E1uIK4iBvqVSHCdqLl8fyh
         OVf2G/h5SZwrW1Hgba9Xz4GoAfGMO6Rq5BF2HF10thbJyv9QKd6Fh48OjR/TyZSMQ/o/
         sJtEZEtJR/Wa4hc52c8qbPj7S21akI+ZoUX2M3B51x0+M5nMq9CaVoo0lwpt4aG1APQK
         GmdQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lfd5QhokhOFiPqECZvWIdsby15b1oMX5tVlhy7WEzM0=;
        fh=/bsxMRfOCBXfYw+3iKVUp5btcH+R/Wy0cbKEwqtdUUc=;
        b=WlCmeyYEaG7kDcNgpLRfo99jBW8ZQC4h3ApaDGIohgT+H7Gp5xOZGvoeZsXoXXYKRd
         NB/ynhYitKFOWpL0ezDvxNLB54Gy8sQhSHsGiclitx29UapiMEv5TGWy+kLTsCYlwUsP
         uGGB+uOp/yRVOxIvhPQVDpGRnrKAXvqQd+C9fQGHCv+aecWIxlQe/e9EdqXyzpxaXP13
         GtejkRlsYSJbuOuXSa/IKksCVMBkJDXYVUc5NnStooOHmEDbKek7Pw9yN79dx78PoT9J
         ul/39ja2WcgDBAnIEBEYxS6jfMfK/cK469suoR3iOQ5TBnVbamQXhr3Nr5aPsd1/sGUc
         bKqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=siB2nADh;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::61f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756406488; x=1757011288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lfd5QhokhOFiPqECZvWIdsby15b1oMX5tVlhy7WEzM0=;
        b=DBdAgbGYfBZngeYi6XUWCztHgJYQlcoDIwtyr2E6nfmdmdXjVT9Qu9or5+jbR2lXmz
         HTPypOnU4z94ZAQnLj6w3mnqyshGcDxnVBsnkG4+80+PiHUAW02d3tG50FZDFAqtAca6
         rUcGAe16sD1FHdSbRCKfYWnM9AhD5vmuOtgfKS0e1u65cOQb9Y/ZX4dS3yHez8Ar9fIY
         1zNi72ESGSE1w551t/Fq1BD4eO28q1sngKZC1tRDo9Y9X34PRnsjRavkOkNf8lpK67yM
         IiFCP34/fHY5tb4963DinpuFq3dy/RdE2wjgRWpueok/ZuDoqaeETBYgN8aJDOcRFf+H
         b3gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756406488; x=1757011288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lfd5QhokhOFiPqECZvWIdsby15b1oMX5tVlhy7WEzM0=;
        b=w6YfiwlITdXZ5n2mXd4TvR2ikHPEoHuiycBtq1fG7n4CXgoeTIT7AGqUPwGo+Exp2i
         bvXs3UfI+5s4T22d9VIZ7KE/IkXog6RzQmSwm+7si5qoAq6T0IBnA20BfL5Zx6ZlGUxF
         4bHdnaJMTF7vsYbLUNY8j2zcBbHRQ5okREkEEuPZiZ9kuzUCCvQxa+wCqrjlfFcI2hTf
         sPBJAj2dDc7+xKnVPwfZm57JJ//kan97QlwdrZJqkWrcFhGtee4B1pzSdBsNVWTs33/U
         MOIqj7Y10bgQrJx1ldPzJPFbO859dH0Y50rPfdaoRrAH5JTL4FXaJOmnt27x0gdEcir/
         bEhg==
X-Forwarded-Encrypted: i=3; AJvYcCU1qelQJZJoQH96SQ6oJetMif5y3rbaZfZlDWKT8edx5A+P0AH5ZoLsvU//zNkRfiP7DIEkvg==@lfdr.de
X-Gm-Message-State: AOJu0YwJaqXP9qoXdi0Eq+zT05w4ch5ji+Xr2rvH27NKpl3zT7YQRO6x
	YLzI179mIarF/r3eBd+VJOU5a6v/mNKgE2ewcEWXnR8eqkQ8gelMAAre
X-Google-Smtp-Source: AGHT+IGgnWTVvmDP0YmMC8hyKRkrRqPRgJdWGKenSzfF1iWDmdP0BctT+fmnDBw4eEhOv+x13ZiXlw==
X-Received: by 2002:a05:622a:288:b0:4b0:6d72:58da with SMTP id d75a77b69052e-4b2aab05a46mr253450461cf.40.1756406487557;
        Thu, 28 Aug 2025 11:41:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeY7vi4iNXAZx3bmEnYv2AfteSunvutaVBu4BD0WTpxUw==
Received: by 2002:ac8:5741:0:b0:4b0:889b:5698 with SMTP id d75a77b69052e-4b2fe667756ls17830881cf.0.-pod-prod-03-us;
 Thu, 28 Aug 2025 11:41:26 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU85u6USsqavTnNGPh5usWPTTvEBAvwjDRMneTMUv19P5aveDDljnUIBgznpcbfXj+uM7K1a/Qd+f8=@googlegroups.com
X-Received: by 2002:a05:622a:288:b0:4b0:6d72:58da with SMTP id d75a77b69052e-4b2aab05a46mr253449881cf.40.1756406486498;
        Thu, 28 Aug 2025 11:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756406486; cv=pass;
        d=google.com; s=arc-20240605;
        b=D2KdVJbcWgYoG/Or5miDtYCjvMWyWepFCWk7QeVWpwsSb/Qa3PhF09ifm3LdCWc3/c
         kG1erPNL5eGI8t5vXbypgef1ZMEf0yszHb6wf3+odGjlSp40iLwB0U/pVGYGX/A4uAhw
         WkAG+HyfYiH4/iJmOy8x0hgnFpmmF0OTlleyDb4g2MWPjMKKTnw/XKVx44DkBucq8Tjc
         6z19BGll8XTyv50hHfsLjbRytRswZSuNIUvNpiDGU4PiOQz/JvawUzrf6kID2XvTuWNA
         xkLu1jhDMXKPbwrL7mWQOd1fzp+yy9nXd1StILHC0Q/HO+xliyCbEOIrXFS/ECgHUVr5
         VJcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IH4p1Ynk9S0qsGZQOi2m3kXmB/gc/sOBxCVzanZxDJg=;
        fh=KNrcxmkEXOCGvlInKu/iFbEeiPtFjj53/K2rpPyAzag=;
        b=RQMUBHgJbvNqQPxIRaifY+3ugvMn0KixqwA9QqW+m05WIRmLc6SFrUVjiObfcl6HI6
         w7nBoTncvHVl+esOQQlpu5gguz+Jr75iOlXsllFoZMpGpFcmyGorlN8Gg8McGREmecXa
         fvvSTlR7BZ8cWG1+luSEInwzHhVAJlPHTp0COhc6FbCi48ifHB1CCNS4u/ZHD82tv0CK
         zxyCy0aHN9YctA5Lz4rEmC6xBj/QUGcM8V95I3TeFnrF6klsz6DbSyLb6U/jfAe/iMRO
         mCef/i/SvA6YaqcpmsXsKLBjJw+ColtJtVAsNoMJ/TXYDQcZqaupfWdJdq0/eek0h5ix
         QROA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=siB2nADh;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::61f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on2061f.outbound.protection.outlook.com. [2a01:111:f403:200a::61f])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc1105c4e0si1865085a.6.2025.08.28.11.41.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 11:41:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::61f as permitted sender) client-ip=2a01:111:f403:200a::61f;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bR+CIVlRgwV9tDETEuGzlP8ip4aFPHzJBGzDvHbjKfYz/rc2zF3tORBCBM/DoT1VJ3kbD4t4G+PGxVI4K+Hv3xXztY6kMjJyXifQ+gKYlp63yZ1+dPBrxwaadi/B4V/N5dgFEZQiQNAyHSQygRIl8C/i4Ky9g4kyBBUNPkLJ4FDNwXrHBkmgTrtl230i641/7HjsAixjeqHS1dT2v4GaPIzWzGMfqZJNAl4HTT6oc+J2l9XVujdJhdi2sLyJksV5iQMMCKfkQvcR7F6xKF+/i4GTbH5hrATvfBpI0iZqsAeCuvSZ/MRCl6EmMZQYxeoAqnwmkwEgT7rOtKKEVDJjlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IH4p1Ynk9S0qsGZQOi2m3kXmB/gc/sOBxCVzanZxDJg=;
 b=KeH+UnNB4zg15YJvU7ADMo84nKVAI71Q6ibHzwd9vdo2H1LN7XQdt0ZPdKdaqZq3LGyiI32QGbJixU2ERNMizdR3mq7W5UJy8QnZhUO55FM3UQzEhm+kUN2J6hWwg5qax6JEYdn5ZOr0s71DKfO7wES7I247L1KyvjtV9dGWW1MnxWceNx1PExB+eKfP8eZClx2+jyoyYs0mQ/lfXtd6YUmuyy8QYF/wLWVWfdaVCGS26CnxjAW9X+DxKv8Zl2cLlb+/IWr4zWRuOXVfu6dU7Kl20kiRxfBkV6wMoyZ6vvI2fzSQlEy6dVbffA51/SgK/mBSlZ0MAPRur/6iEJ3kbA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH3PR12MB8306.namprd12.prod.outlook.com (2603:10b6:610:12c::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.20; Thu, 28 Aug
 2025 18:41:18 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 18:41:17 +0000
Date: Thu, 28 Aug 2025 15:41:15 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <20250828184115.GE7333@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aLCOqIaoaKUEOdeh@kbusch-mbp>
X-ClientProxiedBy: YT1PR01CA0137.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2f::16) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH3PR12MB8306:EE_
X-MS-Office365-Filtering-Correlation-Id: 6e3a885c-158c-45b2-6f52-08dde6627977
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?nV1kIOb9VP48Ge+qYZehwA9eGeoxeOZdlL6tbqFCaZF7sX7c4XZQ+EeTEXV1?=
 =?us-ascii?Q?jeOHpXDpN9jTsr0aNY6rvxAEZT563BNdWHjY39m6D+rbkoJCxDyVhpMAKzT4?=
 =?us-ascii?Q?ZiDMILlnK4rP2lqQl4aAw8OQMeKljsP6XMW5lTTWivG2xK3dEy6PZXJSCovR?=
 =?us-ascii?Q?BIANh2Q1CfCf5pFWKroPAu96gx3gMN5vwEGdtNRAoKx8xtulXV3TFsmTS2xJ?=
 =?us-ascii?Q?nwU/Ja5/QcJxHQVAICa5K5arovbYb6RJ56hG5XnmQmqRnORnaDBGTzumViRg?=
 =?us-ascii?Q?DkMxQtBopzV2/gFJShioAb//97O4/pd0ohUYfqUBK75vpTzqiANsRQRk/ouP?=
 =?us-ascii?Q?Fv6CwYSYIuOhJmzdhhMxA2fCTtjH/j8sneQs/z26EmdguwM7eCODjWsqyxXb?=
 =?us-ascii?Q?krd1yEy7/9eXMuHFA+8/BQLpYwNCSdZnDKnf2GHOr/r+sIORslv0r6llJ/W5?=
 =?us-ascii?Q?lYuGM6Jl0iL0lTz1xPBKnEQLL0PNl1q3EoXkp1zkdVHWTqa7YjQAM3LY4xnq?=
 =?us-ascii?Q?+xyXr5leJisKW4ybbGmqcLY4dFG9memB49yY0V2DqdyiwLRQTofGh+srQ7j6?=
 =?us-ascii?Q?SLzI9ufkZixUXU32tsskxXeMjyixZ7Jv9y9mzfLg2gLveR89VBCORXPfbZ4I?=
 =?us-ascii?Q?Rz3RK65W2EFd1bY/g6b7/BJ1lRFVs0gKzpkjgAPeLQQZ4w2i+yquliXEg5cW?=
 =?us-ascii?Q?UpnplUqsnF2sJhmOW69n1N3suCJj7k1RtNz6Fc9v3x+vy+D0AjDK2NeXZfYY?=
 =?us-ascii?Q?ggNou7iwS3eUP3mmT/UbZbJr/c80mQn9aRBz90zkq1YJDX6B4AUMg/V/mBWE?=
 =?us-ascii?Q?dLhhDvkJ6qJVwo6PgMuMIAVd209YsjIh3LBoHhKFIBqoykFmePWfa8wShv+E?=
 =?us-ascii?Q?woIROJMSoD4mqx8s82XZTfSfaBQQDM4rI1DHz7EWZ6aJss4VpQy3hjZ3DXnL?=
 =?us-ascii?Q?yunNIYOHlbwaao8eE8/8Q0enL72WtWHCREdigrSCso/t0Ymxj658JJetd6am?=
 =?us-ascii?Q?r4eWmL98TVTrU3oE1js1kLGYugu8BtiG5c/LhyWENYYwGg4L38kePJ1hQsQb?=
 =?us-ascii?Q?ga63IImaDX1Ke8gVjOdBzhF5Mdk3jECr5JTReym6u2vnytQTGD1Aw5K2FcxE?=
 =?us-ascii?Q?HYtNc6zV429goAnwbIgzIr9oAlHAQyoxWi9ij3k0yJnxyCpmDprAMycojbAk?=
 =?us-ascii?Q?EzwY9beQEtM6o7DjAGgBbH2YAIZfDijNcOgmC/kbeI7ihRarV5UV0eqZkU3I?=
 =?us-ascii?Q?ENsaIqLh/Xo3CLt7Ol6vEm9ZzGFxM2epqD02bjJJftP3gVu6nchYBPmU6pRo?=
 =?us-ascii?Q?IxKRYL76ez6f9Lzhx5rNGhXWpHnx6dn+V1v2qE1skWJ/GY9tOIOZHLxIvdrU?=
 =?us-ascii?Q?BoyC9ifHd9gN/BQpHESbI1RbRWrS4N5nGYzhVWQItOCmuQrpFt+xS7I69mrx?=
 =?us-ascii?Q?josnzQcDqpM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?612nRiCny2xtHW95HDZvqIOsNAcX7knc6GaUA1ENwQSUEyWYRrxQ6LgHZM9V?=
 =?us-ascii?Q?gxIbVEIlCpkc5dpljNzBkZka3iIL1//txK42jVrfAO5Mxfz6nm05pHR9RU74?=
 =?us-ascii?Q?sViC+p9O0c+HVw9saEBM8mb1QG0kiimXnK3LSHrb8aFfVfgc2Iq5QjfL/uht?=
 =?us-ascii?Q?Lf+lkIg1ZOhhihb2SlUFSulu8mpGU3jOgcDvl3HM2XP7nfTVOKBThqogue+W?=
 =?us-ascii?Q?1CJhUPa4eY1szS76IWXTgIIhXYHrBCbuTjs7sCxbDLihH8wqXAtDa/Rg/g71?=
 =?us-ascii?Q?ljua2SF7XuiXfvtQ1CY7cw4MFCoteno4FC79mVzvNFpEvK7R78LNuMMHUwVA?=
 =?us-ascii?Q?VzwzEx0KDGcJ3Rv1a3vKSH827Z3cN938T+JI07+/ngE+rJUeyI6So7kts8QB?=
 =?us-ascii?Q?fvuLgamOpucTIP9glxRVgHF7gtRr255/n2zDW9qUI2H0Cmgb9w3KxTApeXU3?=
 =?us-ascii?Q?OeRGzdCkiVzHYuuOMyytk3IPu3txt7oLyoPYLaGMJPkNz44EwgDtVYjPhEkm?=
 =?us-ascii?Q?GmlE526wdzwFHyqNV+QnfquwtCZ5mo03XalIrWWNqwQC17yUsL/h438i4O71?=
 =?us-ascii?Q?VwO8L+Lg/Chss9IRqQJTn1FuJxTD2YwoEsgICmYx6lXkT5Aosba6lTJaRim7?=
 =?us-ascii?Q?p0Zml7Ro9ze8oOuftM60T72mE0P7GFFajmaTP4qNiv1s4J/9AUyZqZh7PRpJ?=
 =?us-ascii?Q?Y0GAAIAFHYaWvPSjqTXlZMEXOjQv6tHu0j0/eTcjURhe3Tnb2CVH/gk4TH18?=
 =?us-ascii?Q?QDOjQ3lXkELM0HB1w/fllOjPldc1Hu1NRLasvOJeQDkWHfAgYdhxQk9lgtV0?=
 =?us-ascii?Q?AyoS7yExGHLto2dq4Zn4tdoi6ZzgbXkCWE9wvFVi3Tpks693wdZ9eU/Ytrm+?=
 =?us-ascii?Q?89V7owK29lgAAaY4FispQ9SCR1zjVzVxEP/mawel7Lngn5evc/516bQOh3uo?=
 =?us-ascii?Q?yNefhsv1nYoIiiqGFvJd46fgazIZmU8k2I3NU/aeew5e4w5UOmCfT0yFfzUh?=
 =?us-ascii?Q?zhQHGytPL1/5XlM65i58JQWBt2sVBd3V7sXbx/7QBWmMWZ4JnanEQznV1xEJ?=
 =?us-ascii?Q?/MRtt7aKWupeCMt939zVdJ47rTdTQMF3P/kpyLZj8RKd6yrEf9HBiedJJJj5?=
 =?us-ascii?Q?b/Es6Dcd9GqF58vO/AL225W6jecBZYHyOjUQVTslycoqPKmk+nBKaIiPD6bz?=
 =?us-ascii?Q?OzjLSXXmyt2z2pmr08AyKLDljujpBwKFcArblI+6yefY5/Zdzgpv/RVKIvwm?=
 =?us-ascii?Q?xXrKKWUGFnz6l2UBXl7oMms4tGvgbabzhDyP83M21Ku9t/34OEp5sfoDFLDO?=
 =?us-ascii?Q?pg9sDLqwgjuxlf1NJ1JeVlZE8S8lZUluNK3wtdYVHq5vdfSBZ6UKLJgUPbZX?=
 =?us-ascii?Q?t4Rn4C3mi4obUpy77vBnFcDjUzSoiY39nc6esrK6NLhI3nmAiULLgvdZbusK?=
 =?us-ascii?Q?WkpOM8JbpDrGzaCuR8ogZpOLnjMis6ZKv2WE4KguqS+kU5EmVp3Rqbz540to?=
 =?us-ascii?Q?6dX741hkL2oiFucdvhQXK1tK3/5CIz7Z9lq/W3yBJcYxMAGwVK+poT+JPUTS?=
 =?us-ascii?Q?dFmRbRG5orn6BsJ5VfU=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6e3a885c-158c-45b2-6f52-08dde6627977
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 18:41:17.7869
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CDSLv6OFkm+aZOnW74Ehofn0ul6m7JzKm/hB2lXjK1SkGQPpQAYH91pJpVyw9xjg
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8306
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=siB2nADh;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:200a::61f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 28, 2025 at 11:15:20AM -0600, Keith Busch wrote:
> On Thu, Aug 28, 2025 at 07:54:27PM +0300, Leon Romanovsky wrote:
> > On Thu, Aug 28, 2025 at 09:19:20AM -0600, Keith Busch wrote:
> > > On Tue, Aug 19, 2025 at 08:36:59PM +0300, Leon Romanovsky wrote:
> > > > diff --git a/include/linux/blk_types.h b/include/linux/blk_types.h
> > > > index 09b99d52fd36..283058bcb5b1 100644
> > > > --- a/include/linux/blk_types.h
> > > > +++ b/include/linux/blk_types.h
> > > > @@ -387,6 +387,7 @@ enum req_flag_bits {
> > > >  	__REQ_FS_PRIVATE,	/* for file system (submitter) use */
> > > >  	__REQ_ATOMIC,		/* for atomic write operations */
> > > >  	__REQ_P2PDMA,		/* contains P2P DMA pages */
> > > > +	__REQ_MMIO,		/* contains MMIO memory */
> > > >  	/*
> > > >  	 * Command specific flags, keep last:
> > > >  	 */
> > > > @@ -420,6 +421,7 @@ enum req_flag_bits {
> > > >  #define REQ_FS_PRIVATE	(__force blk_opf_t)(1ULL << __REQ_FS_PRIVATE)
> > > >  #define REQ_ATOMIC	(__force blk_opf_t)(1ULL << __REQ_ATOMIC)
> > > >  #define REQ_P2PDMA	(__force blk_opf_t)(1ULL << __REQ_P2PDMA)
> > > > +#define REQ_MMIO	(__force blk_opf_t)(1ULL << __REQ_MMIO)
> > > 
> > > Now that my integrity metadata DMA series is staged, I don't think we
> > > can use REQ flags like this because data and metadata may have different
> > > mapping types. I think we should add a flags field to the dma_iova_state
> > > instead.
> > 
> > Before integrity metadata code was merged, the assumption was that request is
> > only one type or p2p or host. Is it still holding now?
> 
> I don't think that was ever the case. Metadata is allocated
> independently of the data payload, usually by the kernel in
> bio_integrity_prep() just before dispatching the request. The bio may
> have a p2p data payload, but the integrity metadata is just a kmalloc
> buf in that path.

Then you should do two dma mapping operations today, that is how the
API was built. You shouldn't mix P2P and non P2P within a single
operation right now..

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828184115.GE7333%40nvidia.com.
