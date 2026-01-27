Return-Path: <kasan-dev+bncBCYIJU5JTINRB7HM4PFQMGQERSQPG2A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CLTnOH/2eGnYuAEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRB7HM4PFQMGQERSQPG2A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 18:31:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B16F98782
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 18:31:43 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-34c7d0c5ed2sf4947562a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 09:31:43 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769535101; cv=pass;
        d=google.com; s=arc-20240605;
        b=knyId/EmTsa6cd2lTROPjgTAVSf7qNsBwACMvuh3pzf0XbRa7ZiO4ECvtGmbMAsiMD
         Tt0Tcu5tkOooiIdPjZhGfz7MqP4MVssEi9iCi9O0JBi6VuqHkCGUOsiBzaXIaKz5aM1P
         vy2xCG4DAgbbo4S7bLSqCEuIz2IDiEbrUv8bT6Rdkn/n4F9FD/m71Qz2rz/3y2/DZCgE
         JEljigiQy2VlLQ5pxeyymBSCKkGxP4MAFIOgnLx2i+GQcfoc6hzUhJKm8SP08rKvcmrw
         qAe6w7haBj40Ecx2mmRYqxsOelf9dsEIwih7TNaLi6UFn2YVMYqwZ5AgLdAMP3YPORcr
         ozMg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UhyRRYJGDw/bIoGHzIbO0wgpznSSIar2lrZXztEBV7o=;
        fh=/A8E2DpAwCAccD7A40zxtdiY/rdYe8sdVaRVrd0D2Tw=;
        b=X4Ze0Mecf3OejTLniEOImAwziW7hC5w6MdhlDu2+AiYdIwNk0EJl6Ue9nCD10IhSgN
         R7+LezLkhQVTfqZjWts8flKaPqryNXkAop+jauv7gIDfUV2zrirHOOjxpMqjJRLoZyGD
         6AGL5S3gk4I++P+W/f6oOD1Wzv6KFfhHdsJJ9XnxSBcOHDQG787Gs7LHn1wkjnogusEY
         fYonMH13ebaiUN7ijn3z2BIOAp2nuN6HIHcgiD6DmvL0Bf8C1qQFJa8LHNV3h6eINUZV
         SIhujPvrv4A86On9NxAyjPi+X49SieCsZc4gRaI+8XtqfXkurorOioDPpaAbG6nZhZNF
         JZiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XtNXojkI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eiRaVYsf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769535101; x=1770139901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UhyRRYJGDw/bIoGHzIbO0wgpznSSIar2lrZXztEBV7o=;
        b=nSl2F97i06ZPOVivzt6hdDnvqBFDpb/GKGzUeIdCFwk4c6Am26TmG4AURNcpJTOR5u
         GOwCa9sn7cdmzFLmaUOnbNtUfDVc50aCHz+o6r2Uz0YxCYhSQ7WzyDN6o461/XzuvJol
         2iPPKNpxIIeePt5pfzXtc7VO2DsMx8MrgmVUNpQcxLGEtNDjH/6H7OATqgsX3cFtqRzw
         xH1kNwflu7fs835AbmBoz33egix02pKKaQpOxgue7WadUQzpoA7YwyTxczOD08qTCiXh
         IZvGPqi57S4aXZbLpG92zt3jeIZJEaO+lxVikbspWlTV0zrxMe4K6egaU+ZNdLUDeJ0p
         RIRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769535101; x=1770139901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UhyRRYJGDw/bIoGHzIbO0wgpznSSIar2lrZXztEBV7o=;
        b=SUHkK+0qSWZNwu0mdJgifNH/tfKxmMxGPQn+bHS3aEXe3at4hE/XvDUcv6kiPEh9+v
         vAzhSgZz6TEuvu9awbC9D8T6ImKARCsqrgfQwoMY9pmcIwnNbxy1z5V/lJjw+SfihlNR
         rOw3SUWcJc9kn9mkRuPp2nulfOibXDnBW/mJpR5w0TVIDjPNnITKsX39LLseveDWLhDu
         sMRWyxk0gbG1/JKc1z0+5NPjCU9FQHBHhHpeWOppHHrKao/Vw8xA9WZCGjHdaoJBSkDL
         nrqsbwDXKqJ7qoXY95n5bgYZYdWY5tuLBeD6WUSd2Ygx0yOV73FXPvsR13E3w23FhQdO
         9dBg==
X-Forwarded-Encrypted: i=3; AJvYcCXEudADTXPjN+nC/roOVDu9NNeSw9ecx4KxakYK3BfgePOIgJRvnvp1hJyX469CQ5H/H7dvLg==@lfdr.de
X-Gm-Message-State: AOJu0YzNVViWV0rd+NuDSra0lJunxOxl2D9R2h/vHcJ9ZyzUBXyAzHT6
	6Vwpfp1cEN4ZZCnkWmqm3kcsSU5HNZ/6IgpZDrt6RWmDTTCllw/QFwZp
X-Received: by 2002:a17:90b:538f:b0:34c:6108:bf32 with SMTP id 98e67ed59e1d1-353fedb94b1mr2463746a91.34.1769535101065;
        Tue, 27 Jan 2026 09:31:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HhSlepcDA3YmsZdi7oKyy2DQDiloD6DLrRgOI1tH1Uow=="
Received: by 2002:a17:90b:20c:b0:341:8ac7:48b8 with SMTP id
 98e67ed59e1d1-35335989e26ls3873553a91.0.-pod-prod-09-us; Tue, 27 Jan 2026
 09:31:39 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXNnf0xas7UoUcP0beLZA/TNuWbikgBY3XboXQe4BsGaA/dFYRIlkX7XN1BraafxPIxOU8Oe7IX1mg=@googlegroups.com
X-Received: by 2002:a17:90a:e7d0:b0:341:3ea2:b625 with SMTP id 98e67ed59e1d1-353fecf48d8mr2376528a91.12.1769535099485;
        Tue, 27 Jan 2026 09:31:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769535099; cv=pass;
        d=google.com; s=arc-20240605;
        b=WOIzaDBOFHLG3kBTesQv30qzqOfeFAljBWFcjBmm6Nq2UQfKbBWeSd9gVCBG9BG1yY
         kI7krEFEt2hGWqqeM5Q0ejjxtjVWjDQOxw5NHjke3svNPdxRfynDpwJ58M9ByzIqgutZ
         T1H8dRra66UQBlBjNuKJgicqLEMY2TAIeRFQ9/DuQarV/ZVTQdZAoOV9HVlKk5AdzI1j
         LwyhqHQzRAA5vgkk7Gv4gLgL87/Ts4qGqJYAkL273cNByvfQKXQkEZTGCekfCjTe/vRE
         9yAL3+qlf/DN8o9vCZhkXWG24Wd7eCKa3OLr2l6e0wpfQTAKoFfj9rKWLAY6La26rm4R
         EvHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=RsviRwB6GoLMRBWD6fxGcQGEWBFvmyKp5z2JdQrzqHo=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=WIEIN5t0QCbzdH/XQW5uZ5+Yia/GzHiO0QFmYs9NCB/9MqEsXaSBRIm8k+Qjzt+oeX
         xGbOr9gbSc31JTNkgKFTDnr6NFdlxhqiR/VLFCJvpxwcDnsmjFXbrA/t9ts+q5EwZGLU
         jlT/FFe/Hg00dxK1l3ysFpiCZ47abOZ235ErkBs+0m3JPplqD7DDEW6CS8ItLd4h0aZX
         +mXJ1PIDmeOwhjslXEW30/qjvxx7P52E1E79EBGIcXXj71gM3zgfTfSX5qj+w7P6cqo4
         u7Nwuosxro/W3Gxk3v8KaDuDzROwu/dKgUeX/wc0oP2rjywK0+K85TE2/l/O9bzJLeWG
         mxAA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XtNXojkI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eiRaVYsf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3540f5fefa9si501a91.0.2026.01.27.09.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 09:31:39 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBEH9K454905;
	Tue, 27 Jan 2026 17:31:36 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvp4bvgnj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 17:31:35 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RFxg7f020098;
	Tue, 27 Jan 2026 17:31:35 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010015.outbound.protection.outlook.com [40.93.198.15])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhf1dxe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 17:31:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tJy56oHUsHgUMAYNUAyFKkUfZg8J3z4TYZc9lAF6LMopKD/LDb2qDFGNDoiqjll3kNVG2f7yp4Ue4WJuv3+ceCknmcixERfH3tA/rQGGuNpZ4I2qqgY0U+clXP2rcyabqFRmi5PzIzwwgQVbNuJ4boW+Uo8m4gEgj/CtDkZfevHbDqgq1O/EQMx+GnHUCd1nmgzaBhvGOLbIjPxEA76hxgEZnBwJNLWT1XvCh4osdzHDFUPlWkTzShGrFJIYNNSYPY+YLa/x6hdWSSbESA6gxwRDcFYqkxS/cJWjGnmqaEpjvwQI6BrC+wxkzw4NXX/EKBUFi6Il0K7nfT6kWU8pwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=RsviRwB6GoLMRBWD6fxGcQGEWBFvmyKp5z2JdQrzqHo=;
 b=hWMz3maGLMxiKIgk78SbmxZU9V847Ndcv7VQx+TQIOKDZ/4CvZMtcHiph7OK+8DH6fEHcgKn0YJ48i0DIkT3Z7u4QTQ3+5Ctoop//GjcLhEQVHhuvajdUwSXZBAfkHehGMES6VBCrZA8B4jToDrImB0s2daOIusVwE/BrgpxPzokT3rPseUirpo6FqUMqMckIx5wMKj5BRzo4St43Osq33LI9vg21jFxEJ8WRvAJzmd81XHou5udDQaA4UK7BaS6apjHkp5Gc8DM8P/V1cfhjlz2a/0ReujZwu3/FG+Oxl47Tytmbc60bjP8XRWyx7GKIeaWoUTv7HP4oONLJcn+wA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by PH0PR10MB4421.namprd10.prod.outlook.com (2603:10b6:510:33::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.16; Tue, 27 Jan
 2026 17:31:30 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 17:31:30 +0000
Date: Tue, 27 Jan 2026 12:31:27 -0500
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 07/22] slab: introduce percpu sheaves bootstrap
Message-ID: <dk5mggvowqulzlbv7o2n7ha5p4adq5uzh5i4d473jjwsyivi7l@lvlqxz4si37f>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4PR01CA0449.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10d::21) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|PH0PR10MB4421:EE_
X-MS-Office365-Filtering-Correlation-Id: d58c1a1b-b45b-4961-9792-08de5dc9e8a9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?pwX3QpS/R5iSOF5A76mGS+p+4ysykxLDs0XRfgetbENF35pEPeheStWLFD2o?=
 =?us-ascii?Q?ezuCIxuvUpSlB1/Nwj2Y0FHjeZxXlfwvNziUFz622wXS9GGxkN3x6rfSjuMj?=
 =?us-ascii?Q?/dSSl8P8pXxdZY67K0Ip1+Gd/+YNSEdZ1kMvGM/KSTOVgZzHsCB1WMRI4i8f?=
 =?us-ascii?Q?LLRSjn2UR8Teq3NxzA5VaLwR1Pz3kPKpNE7cWi6kb3HroDjK2xPil4kjPO7r?=
 =?us-ascii?Q?dZ67LyUbB2j/8xS7Qq/0zGz06J1ERmsEWjgwWoAI2ERkLGOjSFZHt4J7cCay?=
 =?us-ascii?Q?pJ2sxqoBkSJ7RL4fdXgqIV+GxmJCjHuq7CM1FK56qZ8m+37QgBWohuge5Ti5?=
 =?us-ascii?Q?AnVVBs6av3WMkmPEmrlg3HTu8pVAAAWlWfJ6VAUycRpOB9vHtD+P2bPgzvcU?=
 =?us-ascii?Q?TYMJ0kYlOUGMKUBmyyv6P0unKpCfz9t/EPfa6+R4UgI1pO08YYvka2by5EA6?=
 =?us-ascii?Q?A2j8p7hcbvvbLxPjpF0M/0yjyagySg9Tq6GRj+W4BHxDFQv9DBaOB5AJusll?=
 =?us-ascii?Q?kW+BniXoRwML6c6dfmyMjyz3mZfKi9X7JSxdesZs18kkWJAsHfUk0oKpRHCE?=
 =?us-ascii?Q?XzW0uQJ93ciyBrIdRb4k2mrWIiG1pn8xdqRJpt1AMdMxd9iBTY7fwyqbH+5Y?=
 =?us-ascii?Q?ZmtoHQ/yIt3N3arlVjhfWb9gdpZn5A3fMZuAFXTaURJ28zNzt7CUlkuaRvh8?=
 =?us-ascii?Q?0zuyInG3Za9+t83RX9F8VGVUphq9iGH6SQ6W2zznhCuf7ddthOvtbbS2nzsJ?=
 =?us-ascii?Q?SYMgotYBzJzUTd3hJ+NuooSLYo0qpXoGkBC3gGdTSAankdnY05Xk0Bcty+80?=
 =?us-ascii?Q?uX+rvsP/yqrA8w8ITuOYOM5H6LAK4gya4sqFIff8DtMG7BV/9himWMvMlKLR?=
 =?us-ascii?Q?/LHzY2+TIp4vFyZdqSRMn42ZerV0YQB4aeOrED/Ht6krTJMM5ac4u7BQcHnb?=
 =?us-ascii?Q?LOv6BsIRsa3se98uCn4UGW23L7Au4gQ5cQARQ5KcgPTemFEDzUdxkpcSGOdD?=
 =?us-ascii?Q?TiUnL/C6EyAsIk+oDMjkNt7HS1MZr8rdyZuBRCa7ulsB9P5rAHzu2ePrjO8D?=
 =?us-ascii?Q?mTfnMtroz07JP5fcQsEoAaxIbAPwNcAiXS+Qb0ybPfQG99ytCqSKWoxjolla?=
 =?us-ascii?Q?xa/6DaTjtkyqul5ScGsHRpKWfWnwIzakp1T09aaSnE1dNxxg0d15//CcQl7Q?=
 =?us-ascii?Q?KALeRp0g+CmrfnqsQhLdn8RYz4pCbUzAkNW8osTPi9asddJ45IIzMChnf4N4?=
 =?us-ascii?Q?IpB2Kqg7WXGyzckY+U83WY9ZPzmVR92Y6N97/zeQxxhJUEwfL5hjEsc06TkD?=
 =?us-ascii?Q?niaJmXrzm3cdDmw7LAHXmbRhIdzNaVMBBDuXyxxLXR9WjKq+T9yRAOL9CFG7?=
 =?us-ascii?Q?GGoJU+BGiSE/dQa6V11I1tyebnfm2ME+WrnW9xJKMkmipxv4Ly3CJeqnDm6a?=
 =?us-ascii?Q?2afg7TwNobbqrx+h6tFR0gdJB85kYJl2BGMAwSJgaCviE+slpZuVBybEwGMv?=
 =?us-ascii?Q?P/7imkphCH5vhiCCd57pCDqVoSbKxcH4u7H/UOpv94wnTgtvRVDFsvJ2Yiy3?=
 =?us-ascii?Q?uZCP8Z0WizBafNv4q0g=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ehWNEnNhODc7mGnWsaPCYRMIpFVP5YiGG3nZxQkG4r4wN0fKM1uJUV0gN/nV?=
 =?us-ascii?Q?O9BCeQK1remOWYKGmihceknExEnDNFrEHh8rknSI/ImoXNYgzV+o973A0QmH?=
 =?us-ascii?Q?DhBaCWjj1Pwn+XrFGQSSsJIGxQ0AGmZMrlbhi2qQ68UddmM1OQAiF+Idkmn6?=
 =?us-ascii?Q?2SPqWOcQZQyRJzZYxzHdtPWfAlzNWKkl284wK4Jsmo2fesiuHak/NOTXwKvL?=
 =?us-ascii?Q?iUH7u77HrOsFbnlOnOMNHRehmwWP/JNqxP2RDnLyozazYOIrDOR1GgaRDwiH?=
 =?us-ascii?Q?DEyp/k5RUxdmPwsklMlPfdeinwnzwKErsQaXuPuL72b+849NASrEchi5i6u0?=
 =?us-ascii?Q?18Dl74WOe2VGWjFpuB7f9mCc6WwtqIMZNTAXBSOnIeHQXghqscO9ScIbSb/P?=
 =?us-ascii?Q?BSISmhB8KJS9kU6R776GcrN+RWIO4JgOhNWIHFDSk/BRHoudxCFIAuv0GQo0?=
 =?us-ascii?Q?mZsPw+P95iXLdIh/8LnnNTP2TVfFa/D8dwHSXX4sJ5RqbhCP69vIVqvwnDnl?=
 =?us-ascii?Q?mA5YJWC/mwHWVoJefiX0JVZmKeW1PrK/6swnLLm6ZNZYlZ/GLu+Dm9qp0sh3?=
 =?us-ascii?Q?IADmydvP4nhMqu67zA8MXFXTyUP/TfhrbCcD3k4DdGIjk3Mt/MczfoKRBl1c?=
 =?us-ascii?Q?16WKm7pt15vwTWRjvtmclVkHSARqYCeleIEWI0kKtYPpxHOWTKsX6ipLhLZu?=
 =?us-ascii?Q?GPsPqB1dhOMV4Z8z3hFqFi0TJkd5FnTOzrqayDYM3qf9A/BsjmEtJX6YDzR5?=
 =?us-ascii?Q?3HHGUfqS52g1AhlePM4sskDX4G2VfSQRHatE5yyhPFe0meuuFZZhwePzfjcM?=
 =?us-ascii?Q?phNYC5SDuHn1u0vmyrMDzdlT6bHHSolOqS2KR2lFkGJzdwcrBEQw60Gla6PJ?=
 =?us-ascii?Q?3XOI2u89SqbBOWTwsCYJPO4ug807mEy/6ms8ruuwIarSDn/AWZxVqNIncMD/?=
 =?us-ascii?Q?N2Ac0kph8Y71cX1qYGEOu8BHDLelJFYDpwKYDb9uwbr4LV/Ve3rcwm1tp4vs?=
 =?us-ascii?Q?gTHooY0XWr/eYrj3TKUcgfC57zZ2FCC9M0IIMlSf06GOycvBp9YnvCPw5KDQ?=
 =?us-ascii?Q?0UuojphNhfIL9QDo2alqv4KikO6TsmSpaAzhZBQInhIA9ESHL7gDK3wDtze2?=
 =?us-ascii?Q?Xivzivb+9th0/b/sktculYXzj4qhFAFJmHt9KyDv+8JUcwKTLz+E2cwr+2xP?=
 =?us-ascii?Q?Gu2EBdTNB8NncKB/j/m9HeXtv8tzmfdzjkN4rRuiORZYH57XTyj6mdBdk5bN?=
 =?us-ascii?Q?8b00BVWp0QYRM+qJpLfwv/Fa3p2hc6eCeFllPA6Gngrnq7Pt2RUrCSbjt0wS?=
 =?us-ascii?Q?226frSgSZCC1C08HD3s2qfQVMQV7lUK+T7bjCd/+FG6iqyC8OQ2lTq9A7HJQ?=
 =?us-ascii?Q?6FXtNgH+d/bpdsF+iFY/l2ei2yU6p3i3QgUVumdMm+DpY5X9qXCMjx40XHzH?=
 =?us-ascii?Q?W44nSlliPbwF87tpvXvOVI6Zr4SdQm/Vz1NoZwhtwKx6ZucOK8jyy3OG8B9C?=
 =?us-ascii?Q?OdlBq1HTSbb00O+b6r/GjyMaia+B8z6UEK1f8cqqmDNJtvm7vv9fcB2PPjVX?=
 =?us-ascii?Q?3jfeUAw8lzH0ZfKz+fr60XesGo4N2gF4/J/hOhK3QY7gAoLiLC9hQWC+ZE5a?=
 =?us-ascii?Q?aCZeq1We75zkMG0Q9OBYXB4KrRl10ylQy0RtYD4MjDZxY3q6AMF9voomUtPD?=
 =?us-ascii?Q?w6+NSmttQ2s35rUaI8sYzyjGVZEX2rACM/tjcjaNtgqtc/zCsDJTpXVe1L8D?=
 =?us-ascii?Q?4tyW3SJtcQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: dW+8kAY57URflg9d8qZ6uBCClr19vz0u35HEur9Btbv5QGhAj5D0bfPTwfI7XWpMM/1PUwzYhiQNdjWGQQe7n1Xf27CVifcjkxeWH2J1WDy8D73m4clZD97Yl/1QILXtITmqde4mVC4tEk3HVovUVTGHrDDqmGIFJcqIWYaS0MA7BMCFtaBiGQBA3U8sKxtQN3BDeMq60zNM067GgBR8gX8aAzfMAYRyTRv4T41xm0rEXEjMdQ0Gb+jHEzDDxEsVBVepbe+WoyA794tvVwQ3Ge3c1p4X5S4zFbgI0eji3PWSZzXf3kZqyAMyL5fkPvuVUKxvibCuN1xMx+5/q5rDflocXft6s3Og6PKOuRnFwdj/TAxeyZFzAwxx5Wmk860l0x3D1f35dS+4IHCO5idCJiP/y+JqyPBjLmfbhUCoUB96zEQ9MFuIx+8b6vHLrlYWjFW34lWfFzai7S20HLCEieNPyHA3+ykKI9R1ojrpHI4M2gn3zgI/Fnimbhb1xXtn4JuEBUY3gHeTPaM15olzog1xxJD8t+rHKRYfCoNv8L38jiQyKfSe8BayNDDaviOMyhvrO7la0ebyHQyyMbCMZGpPhbls8ZxNT//Q6Qbp0k4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d58c1a1b-b45b-4961-9792-08de5dc9e8a9
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 17:31:30.7525
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 91ZF7VgiZwhhoPNnxY83JF2SNidmIbCgEOeJYi1I9VgkXLLzi+wZ4p1cvoRuZe9e7LgnoGg1YKN3opiQSp0OeQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4421
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_04,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270142
X-Proofpoint-ORIG-GUID: aTadYn4Q2GOLd2OCKrlDvLBWMA-pPnih
X-Authority-Analysis: v=2.4 cv=StidKfO0 c=1 sm=1 tr=0 ts=6978f677 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=Ttaf_5FmjKx-C6-eRbQA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12103
X-Proofpoint-GUID: aTadYn4Q2GOLd2OCKrlDvLBWMA-pPnih
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDE0MyBTYWx0ZWRfX6nefJP7Y/UVD
 GnDrcqYRtCuOgR/k7BPSEcFXbzpPOcKm6WAAdbWnmGWEbAVfNr9Zf+dFYSge355iMCcQMGt+AuW
 g9tn/5X336H9fwCILKmcKQ14Hyq9igAIzMV7z4g9DEsfOiyHwIsxDl4VTgiO5da2sw7/+MnFlsZ
 Ap4wtfirwpYKUZbfmslKnkl2Ja3XwFpX9HFeSkeriGxmmL5v7/XwtJXRlriRJnc2N9AshfygQFH
 KGUO9P0gHv1Qf1m5RCDs7p8+1WQWPNChA52tlXOuGC9yFEtYOjPdFrgBD5E0zken6b/XoH5ng5s
 IkQj/stti0Q4xY7fIRhy94DVJwUSXWkb2YODvaUPq503xzv9dW6x3LNwyO7RH2mEBo85z6BpGLx
 ABSV5Nf1/Hb1vPYqKN+x8wo52XRuPwSCBVCiMcdkIDtoNRNiLAbkrWsVaptQc37eBEtB3J/Rpui
 4JDPVo+tTMMpPURUMitqembGVtQYbEJdOCXLJGq4=
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=XtNXojkI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=eiRaVYsf;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Reply-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRB7HM4PFQMGQERSQPG2A];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:replyto,oracle.com:email,mail-pj1-x1040.google.com:helo,mail-pj1-x1040.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[Liam.Howlett@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 5B16F98782
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed, using a new
> cache_has_sheaves() helper.
> 
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
> 
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we use cache_has_sheaves() to
> recognize that the cache doesn't (yet) have real sheaves, and fall back.
> Thus sharing the single bootstrap sheaf like this for multiple caches
> and cpus is safe.
> 
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/slab.h        |  12 ++++++
>  mm/slab_common.c |   2 +-
>  mm/slub.c        | 123 ++++++++++++++++++++++++++++++++++++-------------------
>  3 files changed, 95 insertions(+), 42 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index cb48ce5014ba..a20a6af6e0ef 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -277,6 +277,18 @@ struct kmem_cache {
>  	struct kmem_cache_node *node[MAX_NUMNODES];
>  };
>  
> +/*
> + * Every cache has !NULL s->cpu_sheaves but they may point to the
> + * bootstrap_sheaf temporarily during init, or permanently for the boot caches
> + * and caches with debugging enabled, or all caches with CONFIG_SLUB_TINY. This
> + * helper distinguishes whether cache has real non-bootstrap sheaves.
> + */
> +static inline bool cache_has_sheaves(struct kmem_cache *s)
> +{
> +	/* Test CONFIG_SLUB_TINY for code elimination purposes */
> +	return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
> +}
> +
>  #if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
>  #define SLAB_SUPPORTS_SYSFS 1
>  void sysfs_slab_unlink(struct kmem_cache *s);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 5c15a4ce5743..8d0d6b0cb896 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -2163,7 +2163,7 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
>   */
>  void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
>  {
> -	if (s->cpu_sheaves) {
> +	if (cache_has_sheaves(s)) {
>  		flush_rcu_sheaves_on_cache(s);
>  		rcu_barrier();
>  	}
> diff --git a/mm/slub.c b/mm/slub.c
> index 594f5fac39b3..41e1bf35707c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2846,12 +2846,23 @@ static void pcs_destroy(struct kmem_cache *s)
>  {
>  	int cpu;
>  
> +	/*
> +	 * We may be unwinding cache creation that failed before or during the
> +	 * allocation of this.
> +	 */
> +	if (!s->cpu_sheaves)
> +		return;
> +
> +	/* pcs->main can only point to the bootstrap sheaf, nothing to free */
> +	if (!cache_has_sheaves(s))
> +		goto free_pcs;
> +
>  	for_each_possible_cpu(cpu) {
>  		struct slub_percpu_sheaves *pcs;
>  
>  		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
>  
> -		/* can happen when unwinding failed create */
> +		/* This can happen when unwinding failed cache creation. */
>  		if (!pcs->main)
>  			continue;
>  
> @@ -2873,6 +2884,7 @@ static void pcs_destroy(struct kmem_cache *s)
>  		}
>  	}
>  
> +free_pcs:
>  	free_percpu(s->cpu_sheaves);
>  	s->cpu_sheaves = NULL;
>  }
> @@ -4030,7 +4042,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  
> -	if (!s->cpu_sheaves)
> +	if (!cache_has_sheaves(s))
>  		return false;
>  
>  	pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
> @@ -4052,7 +4064,7 @@ static void flush_cpu_slab(struct work_struct *w)
>  
>  	s = sfw->s;
>  
> -	if (s->cpu_sheaves)
> +	if (cache_has_sheaves(s))
>  		pcs_flush_all(s);
>  
>  	flush_this_cpu_slab(s);
> @@ -4157,7 +4169,7 @@ void flush_all_rcu_sheaves(void)
>  	mutex_lock(&slab_mutex);
>  
>  	list_for_each_entry(s, &slab_caches, list) {
> -		if (!s->cpu_sheaves)
> +		if (!cache_has_sheaves(s))
>  			continue;
>  		flush_rcu_sheaves_on_cache(s);
>  	}
> @@ -4179,7 +4191,7 @@ static int slub_cpu_dead(unsigned int cpu)
>  	mutex_lock(&slab_mutex);
>  	list_for_each_entry(s, &slab_caches, list) {
>  		__flush_cpu_slab(s, cpu);
> -		if (s->cpu_sheaves)
> +		if (cache_has_sheaves(s))
>  			__pcs_flush_all_cpu(s, cpu);
>  	}
>  	mutex_unlock(&slab_mutex);
> @@ -4979,6 +4991,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  
>  	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>  
> +	/* Bootstrap or debug cache, back off */
> +	if (unlikely(!cache_has_sheaves(s))) {
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}
> +
>  	if (pcs->spare && pcs->spare->size > 0) {
>  		swap(pcs->main, pcs->spare);
>  		return pcs;
> @@ -5165,6 +5183,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		struct slab_sheaf *full;
>  		struct node_barn *barn;
>  
> +		if (unlikely(!cache_has_sheaves(s))) {
> +			local_unlock(&s->cpu_sheaves->lock);
> +			return allocated;
> +		}
> +
>  		if (pcs->spare && pcs->spare->size > 0) {
>  			swap(pcs->main, pcs->spare);
>  			goto do_alloc;
> @@ -5244,8 +5267,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
>  	if (unlikely(object))
>  		goto out;
>  
> -	if (s->cpu_sheaves)
> -		object = alloc_from_pcs(s, gfpflags, node);
> +	object = alloc_from_pcs(s, gfpflags, node);
>  
>  	if (!object)
>  		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
> @@ -5353,18 +5375,10 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t gfp, unsigned int size)
>  	struct slab_sheaf *sheaf = NULL;
>  	struct node_barn *barn;
>  
> -	if (unlikely(size > s->sheaf_capacity)) {
> +	if (unlikely(!size))
> +		return NULL;
>  
> -		/*
> -		 * slab_debug disables cpu sheaves intentionally so all
> -		 * prefilled sheaves become "oversize" and we give up on
> -		 * performance for the debugging. Same with SLUB_TINY.
> -		 * Creating a cache without sheaves and then requesting a
> -		 * prefilled sheaf is however not expected, so warn.
> -		 */
> -		WARN_ON_ONCE(s->sheaf_capacity == 0 &&
> -			     !IS_ENABLED(CONFIG_SLUB_TINY) &&
> -			     !(s->flags & SLAB_DEBUG_FLAGS));
> +	if (unlikely(size > s->sheaf_capacity)) {
>  
>  		sheaf = kzalloc(struct_size(sheaf, objects, size), gfp);
>  		if (!sheaf)
> @@ -6082,6 +6096,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  restart:
>  	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>  
> +	/* Bootstrap or debug cache, back off */
> +	if (unlikely(!cache_has_sheaves(s))) {
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}
> +
>  	barn = get_barn(s);
>  	if (!barn) {
>  		local_unlock(&s->cpu_sheaves->lock);
> @@ -6295,6 +6315,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>  		struct slab_sheaf *empty;
>  		struct node_barn *barn;
>  
> +		/* Bootstrap or debug cache, fall back */
> +		if (unlikely(!cache_has_sheaves(s))) {
> +			local_unlock(&s->cpu_sheaves->lock);
> +			goto fail;
> +		}
> +
>  		if (pcs->spare && pcs->spare->size == 0) {
>  			pcs->rcu_free = pcs->spare;
>  			pcs->spare = NULL;
> @@ -6691,9 +6717,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>  		return;
>  
> -	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
> -				     slab_nid(slab) == numa_mem_id())
> -			   && likely(!slab_test_pfmemalloc(slab))) {
> +	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
> +	    && likely(!slab_test_pfmemalloc(slab))) {
>  		if (likely(free_to_pcs(s, object)))
>  			return;
>  	}
> @@ -7396,7 +7421,7 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  	 * freeing to sheaves is so incompatible with the detached freelist so
>  	 * once we go that way, we have to do everything differently
>  	 */
> -	if (s && s->cpu_sheaves) {
> +	if (s && cache_has_sheaves(s)) {
>  		free_to_pcs_bulk(s, size, p);
>  		return;
>  	}
> @@ -7507,8 +7532,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	if (s->cpu_sheaves)
> -		i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, size, p);
>  
>  	if (i < size) {
>  		/*
> @@ -7719,6 +7743,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
>  
>  static int init_percpu_sheaves(struct kmem_cache *s)
>  {
> +	static struct slab_sheaf bootstrap_sheaf = {};
>  	int cpu;
>  
>  	for_each_possible_cpu(cpu) {
> @@ -7728,7 +7753,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
>  
>  		local_trylock_init(&pcs->lock);
>  
> -		pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
> +		/*
> +		 * Bootstrap sheaf has zero size so fast-path allocation fails.
> +		 * It has also size == s->sheaf_capacity, so fast-path free
> +		 * fails. In the slow paths we recognize the situation by
> +		 * checking s->sheaf_capacity. This allows fast paths to assume
> +		 * s->cpu_sheaves and pcs->main always exists and are valid.
> +		 * It's also safe to share the single static bootstrap_sheaf
> +		 * with zero-sized objects array as it's never modified.
> +		 *
> +		 * Bootstrap_sheaf also has NULL pointer to kmem_cache so we
> +		 * recognize it and not attempt to free it when destroying the
> +		 * cache.
> +		 *
> +		 * We keep bootstrap_sheaf for kmem_cache and kmem_cache_node,
> +		 * caches with debug enabled, and all caches with SLUB_TINY.
> +		 * For kmalloc caches it's used temporarily during the initial
> +		 * bootstrap.
> +		 */
> +		if (!s->sheaf_capacity)
> +			pcs->main = &bootstrap_sheaf;
> +		else
> +			pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
>  
>  		if (!pcs->main)
>  			return -ENOMEM;
> @@ -7803,8 +7849,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *s)
>  void __kmem_cache_release(struct kmem_cache *s)
>  {
>  	cache_random_seq_destroy(s);
> -	if (s->cpu_sheaves)
> -		pcs_destroy(s);
> +	pcs_destroy(s);
>  #ifdef CONFIG_PREEMPT_RT
>  	if (s->cpu_slab)
>  		lockdep_unregister_key(&s->lock_key);
> @@ -7826,7 +7871,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
>  			continue;
>  		}
>  
> -		if (s->cpu_sheaves) {
> +		if (cache_has_sheaves(s)) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
>  
>  			if (!barn)
> @@ -8149,7 +8194,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>  	flush_all_cpus_locked(s);
>  
>  	/* we might have rcu sheaves in flight */
> -	if (s->cpu_sheaves)
> +	if (cache_has_sheaves(s))
>  		rcu_barrier();
>  
>  	/* Attempt to free all objects */
> @@ -8461,7 +8506,7 @@ static int slab_mem_going_online_callback(int nid)
>  		if (get_node(s, nid))
>  			continue;
>  
> -		if (s->cpu_sheaves) {
> +		if (cache_has_sheaves(s)) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
>  
>  			if (!barn) {
> @@ -8669,12 +8714,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  
>  	set_cpu_partial(s);
>  
> -	if (s->sheaf_capacity) {
> -		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> -		if (!s->cpu_sheaves) {
> -			err = -ENOMEM;
> -			goto out;
> -		}
> +	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> +	if (!s->cpu_sheaves) {
> +		err = -ENOMEM;
> +		goto out;
>  	}
>  
>  #ifdef CONFIG_NUMA
> @@ -8693,11 +8736,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  	if (!alloc_kmem_cache_cpus(s))
>  		goto out;
>  
> -	if (s->cpu_sheaves) {
> -		err = init_percpu_sheaves(s);
> -		if (err)
> -			goto out;
> -	}
> +	err = init_percpu_sheaves(s);
> +	if (err)
> +		goto out;
>  
>  	err = 0;
>  
> 
> -- 
> 2.52.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dk5mggvowqulzlbv7o2n7ha5p4adq5uzh5i4d473jjwsyivi7l%40lvlqxz4si37f.
