Return-Path: <kasan-dev+bncBCYIJU5JTINRBFOK4PFQMGQETVN3JMY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yHxMFBjleGlftwEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRBFOK4PFQMGQETVN3JMY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:17:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id CCBD597972
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:17:27 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-662c9283415sf17535540eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 08:17:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769530646; cv=pass;
        d=google.com; s=arc-20240605;
        b=PLDyDHfMr5rzU2RO1K10xjf2ntfp3ToevzZw19eyXvbiS+dEf4tlPVAsWgI2+YFImp
         vTIJQMtF8ZmhvU8XOkFP+KTqYNvhpMIIA7h9WWLJc2eFKfukDPUhvOlJz2LIpgZEkWz+
         GWA4yIDMz/MiUougA18slktX7krT1MhBSCzCESlj+xyErE33F0Yyl7E7MeJRALM3/6aV
         Emu30swiL7dfrsCmUS59JHsENIp2P+/cr+Gd/iILeBxY/HTf+Va9/jukvVOMWdym3qyX
         el2t3SROnKVQ9Dr7FnV/RV/EueOyoGRwSfXRAKR0EfOZ+X41LH1yvKPegOSeZx4q+HHW
         Dm4w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wPC6wRHlZYbnDDfoCsnBRxeTxuYgk1+QZnqA8RA3oI4=;
        fh=4m13tajVLho/LsppowVVjtyk0/YtErZEbAfKd39gfVc=;
        b=BHjZA7/uWkAgrqjXU9/YgsYbJtGapu/EVUOUwHvh0k8gO5gEJReDKGAoCR8OtMBern
         +RciN4jP9UoKMoSjatDQi5gcNF86c7yRsWiFJh4mo5oBffCtNUnUBPiowSCTWupVd4gh
         OTN07/+b6WQdvVNDWinoOqzzQFyrU5kzwzJEApZvL8LUVKhR4lUhv7b9GWwJJ1cjt7zd
         TYyrrz/YIFosIg/hG23xbnItpMreAdnfcgoCZWAKv0cA/LI4Bd+cj8Wz1cnIV2MApSK0
         ITrhqQD9Ky9Ejk/sn65zbWgG2lQEhAOI+9WCpaWRtj2N51CQ+xrYEfU4SaG8t2SE2q8x
         Gj8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TXOmsv3l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=opTNLmen;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769530646; x=1770135446; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wPC6wRHlZYbnDDfoCsnBRxeTxuYgk1+QZnqA8RA3oI4=;
        b=jA1TiQ28+kkibCj9JYCy4DCuZ/ViGkukRi1w/0OG2zRw3NoT/mZrvYkfQZ1zq3ImjS
         94YnVFC+Ww8LS4fz+iNFGaJeg7q5NNhtbK+1RLAIsUTZUEbmHwRab+qCpKFuTT28YJ/j
         2AmE9Z46qXjzO/skIPfAR1Wz3nLUbjnI1zsDT3KsLTf04iiRE3YtHfHyFogcz0QOGzuT
         3qgWLf1Ap48+DAJuodQotr41K4xTJYPTzynbjpUppl57NFMP2bzBXgmsryaEytM6KmKv
         muiCJGEOk0l5Xzz9+yB2w5wC3BpOVxw8gmq1534roJl83QpwzVRACF5tOaNdIFKRwkUP
         GYNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769530646; x=1770135446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wPC6wRHlZYbnDDfoCsnBRxeTxuYgk1+QZnqA8RA3oI4=;
        b=Flny3P/qT96rMhdCbxb4c6LVFMEB/DW6r/JxkgJVgC3oGoBEiak6QG+ceZM/bjLVk3
         IV0jFEaI3+n35GF0FWga4OcIQnU6wnx8Z3fYmxYCm7UY47DH/h6yFwYTAiJ8gn09NJ94
         55ZcBepHKTcmQ4BIdCLFmhGYLCZoecZNJXktLqyCU0bZl1Ej7zd0TGZudylglN8GAYlB
         rGrLjZh5iMMSpzLk9WL148M6SmT9f3g7Eh72ZR54hlJP/jp2nkrvWdfdObC7fBsDVDMz
         Y/luu8m9IdawvHUq3lPZq4Z8lTnYO+7cZ53YPiALOGqVWviU9BpUzid+GLHdNnmvvJ1M
         J7WQ==
X-Forwarded-Encrypted: i=3; AJvYcCUDjFjOqYjlUeArai0u0e10tvmbRToQLOEEGxuuqCwAPE49zRYgGdMcLCS7KekQjx9DOwqaSg==@lfdr.de
X-Gm-Message-State: AOJu0YyHXQ4XwEfV2ciqYWR7Wv6Mqqqi6NhlZXu/mzpkjx5g3w0aGXC8
	WU1DywDbsNUJFINBLz7Gbj66YLOMoj8StvWNstBuZTNXtlS6/8RoOA7B
X-Received: by 2002:a05:6820:1609:b0:660:ffbe:e351 with SMTP id 006d021491bc7-662f20fc93amr1304904eaf.71.1769530645858;
        Tue, 27 Jan 2026 08:17:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ESJfUn50OUeU3gfd3kQUG11aM+IU4kV5JIfAjbECy+Og=="
Received: by 2002:a05:6820:2208:b0:65b:243c:21 with SMTP id
 006d021491bc7-662f8fdd738ls41225eaf.1.-pod-prod-03-us; Tue, 27 Jan 2026
 08:17:24 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVb4lVpDlrAjBNjhRQrrvGYPqsZOXqxJrYREjkSF1TyzgE899C+Kc1gRNgle0GgSWZgkQ17y6iVlqM=@googlegroups.com
X-Received: by 2002:a05:6830:2696:b0:7cf:db30:bb5f with SMTP id 46e09a7af769-7d18511de97mr1046112a34.33.1769530644390;
        Tue, 27 Jan 2026 08:17:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769530644; cv=pass;
        d=google.com; s=arc-20240605;
        b=e02GSJs2F/9dwmUW77Kw5rTktHo+lEmXK1izgsbTgZZZN9gqZjBTYDoGPfKUb13tUE
         0jAE+2mN5Q3TuvSqj5vdeCm1HuKbEf4gkIQY9O4yxIRSq96unSFboc/N56KShXNv48Gb
         K4oGH/lacEhakUmrpYWT7o/ARB/HPF0S9zWbwymFxMiosGskrB0FLh9Cba3D1slRN/KF
         h96Ur/x11v5vQA0eUNhbXGaA2j4xx3uMuTuJVs+C5Cv8kIpjpqImIm6f49b4S/r0lF7e
         LKIZFK+vcjp0eZs9vSz8ggnz0abLahvgYUPZjBz85K5RoLNeacgTcTOchTb/kmnID1J9
         WUow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=OKHSLDxRoTP0O21CGrHG30PQSZORZgUK3s69kGq/Nq8=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=FC2EmmcxxanIjynC75QdlC3IYpDTk6Ynpj6JkNzIwH5sjPZX/Yp1z1b3vQMYQvE0Km
         UMkECqgQvW4ZZ5wDW83eFkcsBUvk2uyXC4cwwvCyzIDlYwyKu682+scJiwdVIwnJqL0r
         y5Nl/V3DiP851PbdWg1YatdvDpj6qWOVsnUwP0egWp2u/6IFFlL2Y8fv94USqu3acXId
         KtUvBNyMXXQWR9DQ8XAqMhw5IIRj8YbVgaJbskPWF+K7zJknCAPG+IZn2cSAp2enVqki
         x2yl97sniO/naV/ErZmEubNk8IiMWzuz0z6dtDc90KtqfyZITcy7dQzSe+Q9QTk2/wiG
         TU+A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TXOmsv3l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=opTNLmen;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d18c7517e1si5628a34.5.2026.01.27.08.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 08:17:24 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBELSw3280520;
	Tue, 27 Jan 2026 16:17:20 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvpmrc9vs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:17:20 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RExua7036177;
	Tue, 27 Jan 2026 16:17:18 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010063.outbound.protection.outlook.com [52.101.193.63])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhnwgde-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:17:18 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=YawpJ07oEZ8w4HQLCIh2LJGHr+EGQK5YHUKU3UjpKV4U1GM/H0bZpWOb/Dj7yWEIyxKCCC43D7a14i5WcS+bLLMyYNoLRJAkbuT3HpjhY5GTAVXAnEBrnNwumw3hcWTtVXIHETPmwCf24hhigbDyvEX2vMPjgEbCxXYQZGILNyOGqDHhUxS/7c+1vWMdeoMn9hk/fsWfHri2zGqVRB9aACEs8myPARVUOuuPxiJqUkxeMQaRg5U1awpn5iidDbobgSPqD8JGx+Lk6HQWi/cHZvBCg4yF8XNgGzBcmQY+Nu7N1Dg0+Raf/sw2AzidllOsiwehMD7nRANw8ZCYHie0+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OKHSLDxRoTP0O21CGrHG30PQSZORZgUK3s69kGq/Nq8=;
 b=Lk25NjNaFfDOYdHFQldPIwXm83WwATULBV2NK8cFZOVzCfCBo3UHkREblIenqJzB3M9m7yLquaP6E0fnnXsnHnbyBkp+kfLNGWmh+fELolCZetdKJHu9dNvXbwrSNaRKVR4J/STH1rDJSBF5KxytvubUGJs0xr7jtu/qH/8wMEXiH0+r4UIyXAxOoyMiEt3wpS/nv35/fAMCtUtAm0Ol6qLI7/x3wR4CSBKn27fcKPRcJlwRtse8Q30wt0j4grCF79o5eLPjdVoTi5NWdvEFKj15LaLvCgUSFTexn0w1VfbFopN24cP1EL803LrlCQ2Zg/zotr+Z4xAQp1+x6dTKsg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by IA3PR10MB8300.namprd10.prod.outlook.com (2603:10b6:208:582::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.15; Tue, 27 Jan
 2026 16:17:15 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 16:17:14 +0000
Date: Tue, 27 Jan 2026 11:17:11 -0500
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
Subject: Re: [PATCH v4 04/22] mm/slab: move and refactor __kmem_cache_alias()
Message-ID: <xvdhietnpfl6ait3kjwxu3nrrzdpwvt3zp5ui4l6o7t7yps55g@wygbtepochfg>
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
 <20260123-sheaves-for-all-v4-4-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-4-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT1PR01CA0140.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2f::19) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|IA3PR10MB8300:EE_
X-MS-Office365-Filtering-Correlation-Id: b904aac4-cdf7-4ecd-54d0-08de5dbf88be
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007|27256017;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?CLSm88rvjDbI8AFOM0VzqMW63wzQOouBYfEXFt5YxHMT9mrdtb2Vq2grXDJq?=
 =?us-ascii?Q?Adb/YSB6jpP7S+1nJLsIkXILETD5ubxDb/Sybi+FVHaScALTdHpUWon4eac9?=
 =?us-ascii?Q?ntEKlKzOsPzhJyy/+KKE1p7p/v/BtHakQWO+unpJuwtcMg0Oy+X1MDcKM4rp?=
 =?us-ascii?Q?Cj1Gxqni0iDCeaVBZ//WohTeP5Z6Wsu3kx/9pFp0mNF2en0kvZa8patWTO9N?=
 =?us-ascii?Q?2w4qqCfR1M08MJaxFjqKaBHsPeLGhiQRHpfH1JAhbdYrnSASxjNurj8uVnlt?=
 =?us-ascii?Q?D9wVZC94QOZrIw3d+OqqWRtrL9kMLItZLzc6j3ncu+sknsuwm8DEi1lxxA7t?=
 =?us-ascii?Q?YpVq7cZeqX+Q1+zQYITQWx8FCr7JMl/iJ5BAbWl6Ib6IL2ekCfTptEz2qwxs?=
 =?us-ascii?Q?GbkvBTZTA3ELRK6XRAoGKhcebz8eMaL9evEOHdV18DDikkgxXmYeZd/zBFtS?=
 =?us-ascii?Q?l0Jtu5yhUiwmAj8sdKkGR/fh6MLVbl1E/BXsaR2rNjNEhbWl2JcL8+bymnrv?=
 =?us-ascii?Q?DsiDLZse5wp24G+ljncCwUYtUSRay42k1exyKgVeVDJi9eoB5IyHPknz7KFF?=
 =?us-ascii?Q?+u7lzE/vGtnOM39hQnMeYGvV2kE+NmL3Xra6BfS0hCtxo641Fhm+f7FuKWYO?=
 =?us-ascii?Q?NNaDLpcWhtbW83MNC9qm6oiFLtkWWbJaHzHZinIXYaipcXdsvlVu6sE5XqtW?=
 =?us-ascii?Q?+U601R3yi4bRDQNB6NL98Y342NS0etSCCYSckPAdf2G4hBeB4ZWBvf7PyVWc?=
 =?us-ascii?Q?JfrAdkSInREh/D8ZMzMQDzRqllXCf5L5+18XrUkSbe06ZXI7T5wQI6/yzvAz?=
 =?us-ascii?Q?+i7XDiyQ/9adsdt0KhMiSL4UXWkwCOW3YmjOvVgXK3AhbSCLY4UoQVPQR/sh?=
 =?us-ascii?Q?iZ0bZwfThTEYLYB3CimGgCkP6Uf0K7RNB0qOygvOCLWJ1neu4PZ1WgSf1v96?=
 =?us-ascii?Q?v3qHbC/oqMO3gxHExbEKl8Uik42VTVfKvmumilFGA3GT5DYTwAgdk9mkZH2Q?=
 =?us-ascii?Q?V+Al1w0BbfJj7HOxtmthEQWF1kIsQUYQxJiVOgop/Y8dQm/x/+tQwc6IJ/xa?=
 =?us-ascii?Q?tbsLWxk4XjSjG5fn2mkKKvNRDNVmWXqZqv+89vezB2Z5QYY7LbBG1BbOPx+T?=
 =?us-ascii?Q?IhG1wrI/HdPnLSGJhEyOTEB4a54VttY/gBqjXNR+pa30ZrTPZjEZxzBGfJcW?=
 =?us-ascii?Q?Ra0QCiS6m7cV3yD32qQ5mm3/ehBF8gvpCiLop3y3stwCEcVRZPIANzH9vhqX?=
 =?us-ascii?Q?c89e4XK1h1fPHWnh50UOn/i41D+RExY+JsgjnyYcsiuknLWYZKWn11Pw7dM/?=
 =?us-ascii?Q?Ct9ElXqJV7S0VqKisbWJomCFq5ke4Iafnuo80vXoW/5kY4ZYIEeI70ZvDz58?=
 =?us-ascii?Q?gFGy5b+tuxxQ+yG3sXPB8Yw1rYwmbU6fCbuDr5+MaOwqc+df0TkkClHE6S8k?=
 =?us-ascii?Q?X4mHkCi6+1LbLX/AqIVwiGmks1Q8X/fwq85Ej+DbQQF56T7SrtvCD+ucFLI0?=
 =?us-ascii?Q?ejiqC2eCK8FvvJeIOwy1vwceq28WbQPq4IkvSebYyj5NPYm4t/bJSW0dRifW?=
 =?us-ascii?Q?tzIVwxCLIVwuuHifC0eLff2gYxkUB5hLaHL+WvErkMlpaJt7V74LgZrpy5DK?=
 =?us-ascii?Q?Pk33ZijlWrVRw0R/FxMBMHg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007)(27256017);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?X1DIaSVUmv7JaTRLD24gJKabYAzTwIotewX+s8R4CY+R/8z3WkLORvyDhwuz?=
 =?us-ascii?Q?M/LRGebkOpu4p2ENPq7CCtkLsgwOCfb+O+sPoDBuxpkME0+5YPOMg6D4lZc8?=
 =?us-ascii?Q?7gMsM/z+rXbqU69BsgPcLt+t7YQRr4IyRwlU4/rYNqCwAABhkGbKWe/2+7hc?=
 =?us-ascii?Q?6umT+lU6p+yy4p51Xn+oU+csxCiFoiIf1baZecU1TXSyQLNuFxHzBGKU/83Q?=
 =?us-ascii?Q?eMbrKQV5IwMiE3P+ip/4SevrLSlMuJMuDIJNucnrTlfzO83e3Qoa9CbQCMF5?=
 =?us-ascii?Q?VSPhtjJh6Cip4nmFo1FjQ7G3L+jw3dXziVUyM/arMv6as192ggPgZjWypS5k?=
 =?us-ascii?Q?8cPawipWOVkx7yMAs37KiY1Oo7GD/H1MiCkWh3W1iPhP8BfZaqv5KSQGUh+g?=
 =?us-ascii?Q?LNkskiz+TLD0gm6/g1dxSJob0OdPQo6qUeQXK1nAEqAYJxadDXhP6Zj6a6Kt?=
 =?us-ascii?Q?MzGF0kEnrt16OCV0qz4RDABJ3qlimkhE8PipuQdzTbyHs/xjknE/LlFcykli?=
 =?us-ascii?Q?rX8w5vsh8ke6luE/Yim9wZHz8PiJmKrY6ZdEjCNvx7OFRfsVym5mLlRiUz2K?=
 =?us-ascii?Q?7wqRKCcnU0idATfNHB7LMFX68oV+U2W4eCuqEvZOyjjD/cXEyUkqPrlyY5Wg?=
 =?us-ascii?Q?sUtRuIjO57fVZsAam+9RgdkPgDeTjw5WOGeMj08t0EUfjznVpDnQwQGJpAyV?=
 =?us-ascii?Q?tT65KC2cQYqb7JmCX6ByLNqcJXw3Wsr0ONOjRHxZNlgDT115HYzDeXAlLzgA?=
 =?us-ascii?Q?KsVz5XIhxFCo+/kj48LbShI2kg5zgT/f/Sw5QXjO0BGDyLxY0V6VZtS+bVEO?=
 =?us-ascii?Q?VolgQyob/7uS4dDO9Z8da4xSg7N+CkN9LeV/CYyvdENav7/SbcF/Ks07o2Q0?=
 =?us-ascii?Q?zcPc9Yq8G61dM+rssyC+xZTBYNrxzEMtMMmMH4p2JVOgiWZJPpVRTGYVFYcs?=
 =?us-ascii?Q?CT3rHfxCtogMw0K9CqlMeVrR7GkzaDgnJPnG98IGOl5alZ5XKRhAQci4P/OT?=
 =?us-ascii?Q?25rNxeW6q2Gi+/xIt9V1bvx4fMsO8OpBE9qZQwpwz1elSwXez6UMmGe9uIqt?=
 =?us-ascii?Q?swWjXTS5ac3jun+LoGCV81V8AmVPeXfIaxEN+C9xyExjmEIAKYtBUlZqclHK?=
 =?us-ascii?Q?zE9Xxe7YWJ5XvP2D3an7FxqtAv43LVNk9as0WIZ7sCn3H8WGjAmXYskTMLqv?=
 =?us-ascii?Q?8WmeqLNfNshwfmQnIY7wA7cEWBUJLjjLlP82B7DaV97UnHeXUu+Md7A+p2xQ?=
 =?us-ascii?Q?yZRSjyEVHcdPngV06PdE1Y/YoNGpgeiFnMNyYMDnpVT9YEAFwKx+VMEJYgEC?=
 =?us-ascii?Q?iBrymvHG3cOXeMcvBbYQDYPVkMcv7tojkvmK/6q8RBOBRiN6zUX0k2z5HEgm?=
 =?us-ascii?Q?SRzJ1YTWmgC1ISFh/8yqNFTLxPXYkFeBFp6jhOCPtggcMrvHKkIZsZI9oJvF?=
 =?us-ascii?Q?NdGednQlVoP+HCvsBrUAxcgF+TqvtMl76+0jhLydwmznExECGyYGlKkfPLY2?=
 =?us-ascii?Q?B/HKeJnirW9S215bsEKORDarJ/gxdWNceD13LX97RvxIfSh0gOdMWbSUrXI3?=
 =?us-ascii?Q?0D/b/t4nenuBTMKZ/UzHBttdu8J1zZ+Ytq+XpgeE4cIP3OW3L36DakPqLnwZ?=
 =?us-ascii?Q?dl/AZaUC4+94hHIMKMEkkfaI4xplZaNpGxruOdb2WMSKfpGIx7B99poTEPKt?=
 =?us-ascii?Q?farINXQgG40mik1r41L8OZZBhSiG9QA+hIfZEBvWlbEc/PTo87cU0l8hPh4p?=
 =?us-ascii?Q?kfzZXmO8zA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 79E2T0mM17ycWCBlF0Xo0nUyvC1BkoldEZUc26/JapnMghSE4BwzXein76GT03DM57pP0FK8XfiFZmXTlKf9wULU2NqO8PPo/egNu6bGJUOEr5zY4P13uxLFNNLoMNQDjuN5PWQFzpuVZaGxUxHnX7UiNRb+M2teHkjju19bHHQ6Sm/LER6HUTRbWfB2nwf+RON4UvEL+pnJyT9oVFBkqKwbDlgoNsMKv6eDD98+PZsa0RmKJj4Ik3H04ssM97PuD0uP3Y0lT4sUsSxcRqtbndF1DX/1w6lEhKq76PdMCWxbfp3FSQ0jVJ5GdcJq5P03uWYgNR0TUfS10YDT/eYJHMF2WOIHohztrG749JWZHfwfNQ8Hycq13ZvpE0v6MBkW0WKFMquyJAV8+3HeBz7tt+/mYisfKicT2Aja1NvAJcfNUCA034Tqt3NnlMRcKBQJZ7cgdGeHf3X0lGpPFzuSp9Q0yY29NfSL29RiQRzXoQpnkdH9yj6VRwPGnFEebLzxuNsw6Tw3SDb+6f8F7Sdh5DxZdIZYKeIOlKyMRcgQDMKltss2PUx3SW4LaG9HMVmTwVLFuXfbCx9q5LYHMJkpYPRb+9efmYXmKVcH4Vy/YJA=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b904aac4-cdf7-4ecd-54d0-08de5dbf88be
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 16:17:14.9336
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8hVZiDPtViPjN1GvBat+NZIBCeHviwCGPxmXAyRI9KM3f8vpEh1vihz9x5XS76S4GiYT6ChFpTUNZabm78Fxsw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8300
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_03,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270132
X-Authority-Analysis: v=2.4 cv=Q//fIo2a c=1 sm=1 tr=0 ts=6978e510 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=1XWaLZrsAAAA:8 a=vatuI3SuysR0fGYlY6kA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12104
X-Proofpoint-ORIG-GUID: HnipPC-KP78po4qnQT616jaAQ50kq0R8
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDEzMyBTYWx0ZWRfX6koh6F11Aai4
 8UjWztBHQ0oUzszz+nIKgKUGPJhrWNDcRvZIFcJiMTA39owXPW2v0pVkv2NtVvS41/uDeFxKaOO
 VjSK9QwElWLUjcA/3NZIh/rnBB0vJATKj+uCbdDUcXvLEogVfBxFeuDipUHeJK5qtxJpzU63uKn
 FWrhOqU0z60OHX5pwtot9C0IAEsyPrfWeve+wFLAnj+bZ3xMOeorLXyF58+yDTWr4IFrkV6dspY
 G7wkHhiI4VpREdQuhoMh975/qN3R4Fy1TVnuNj9tb7i8NbBYsBnR+zsU9ZRlsMF1Yi6swlUb4h1
 2VKy4mf3BpFEKvh0ecT7FYI2Tlglv23eWukrv1eT5M31NuDkF4YNT3A8O+AYN/4mDy9P5+6hC3B
 QyVgyswmCq8pEcGe5IvGI/C1uJ1t38zFMRb73BYSp/cPDnsklhjT77HMgJxc1jZzakQclhiCZk7
 OeRBnki1KPzKEIImxMAtGDGelgL2jdXPF5cUgWyA=
X-Proofpoint-GUID: HnipPC-KP78po4qnQT616jaAQ50kq0R8
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=TXOmsv3l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=opTNLmen;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRBFOK4PFQMGQETVN3JMY];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,oracle.com:replyto,oracle.com:email,mail-oo1-xc40.google.com:helo,mail-oo1-xc40.google.com:rdns];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[Liam.Howlett@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: CCBD597972
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> Move __kmem_cache_alias() to slab_common.c since it's called by
> __kmem_cache_create_args() and calls find_mergeable() that both
> are in this file. We can remove two slab.h declarations and make
> them static. Instead declare sysfs_slab_alias() from slub.c so
> that __kmem_cache_alias() can keep calling it.
> 
> Add args parameter to __kmem_cache_alias() and find_mergeable() instead
> of align and ctor. With that we can also move the checks for usersize
> and sheaf_capacity there from __kmem_cache_create_args() and make the
> result more symmetric with slab_unmergeable().
> 
> No functional changes intended.
> 
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

One nit.

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/slab.h        |  8 +++-----
>  mm/slab_common.c | 44 +++++++++++++++++++++++++++++++++++++-------
>  mm/slub.c        | 30 +-----------------------------
>  3 files changed, 41 insertions(+), 41 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index e767aa7e91b0..cb48ce5014ba 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -281,9 +281,12 @@ struct kmem_cache {
>  #define SLAB_SUPPORTS_SYSFS 1
>  void sysfs_slab_unlink(struct kmem_cache *s);
>  void sysfs_slab_release(struct kmem_cache *s);
> +int sysfs_slab_alias(struct kmem_cache *, const char *);

nit: the names of the variables are missing.  I guess because they were
missing before.  *s and *name,  I guess, although they are *s and *p
in the other declaration.

>  #else
>  static inline void sysfs_slab_unlink(struct kmem_cache *s) { }
>  static inline void sysfs_slab_release(struct kmem_cache *s) { }
> +static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
> +							{ return 0; }
>  #endif
>  
>  void *fixup_red_left(struct kmem_cache *s, void *p);
> @@ -400,11 +403,6 @@ extern void create_boot_cache(struct kmem_cache *, const char *name,
>  			unsigned int useroffset, unsigned int usersize);
>  
>  int slab_unmergeable(struct kmem_cache *s);
> -struct kmem_cache *find_mergeable(unsigned size, unsigned align,
> -		slab_flags_t flags, const char *name, void (*ctor)(void *));
> -struct kmem_cache *
> -__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
> -		   slab_flags_t flags, void (*ctor)(void *));
>  
>  slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name);
>  
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index e691ede0e6a8..ee245a880603 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -174,15 +174,22 @@ int slab_unmergeable(struct kmem_cache *s)
>  	return 0;
>  }
>  
> -struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
> -		slab_flags_t flags, const char *name, void (*ctor)(void *))
> +static struct kmem_cache *find_mergeable(unsigned int size, slab_flags_t flags,
> +		const char *name, struct kmem_cache_args *args)
>  {
>  	struct kmem_cache *s;
> +	unsigned int align;
>  
>  	if (slab_nomerge)
>  		return NULL;
>  
> -	if (ctor)
> +	if (args->ctor)
> +		return NULL;
> +
> +	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
> +		return NULL;
> +
> +	if (args->sheaf_capacity)
>  		return NULL;
>  
>  	flags = kmem_cache_flags(flags, name);
> @@ -191,7 +198,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
>  		return NULL;
>  
>  	size = ALIGN(size, sizeof(void *));
> -	align = calculate_alignment(flags, align, size);
> +	align = calculate_alignment(flags, args->align, size);
>  	size = ALIGN(size, align);
>  
>  	list_for_each_entry_reverse(s, &slab_caches, list) {
> @@ -252,6 +259,31 @@ static struct kmem_cache *create_cache(const char *name,
>  	return ERR_PTR(err);
>  }
>  
> +static struct kmem_cache *
> +__kmem_cache_alias(const char *name, unsigned int size, slab_flags_t flags,
> +		   struct kmem_cache_args *args)
> +{
> +	struct kmem_cache *s;
> +
> +	s = find_mergeable(size, flags, name, args);
> +	if (s) {
> +		if (sysfs_slab_alias(s, name))
> +			pr_err("SLUB: Unable to add cache alias %s to sysfs\n",
> +			       name);
> +
> +		s->refcount++;
> +
> +		/*
> +		 * Adjust the object sizes so that we clear
> +		 * the complete object on kzalloc.
> +		 */
> +		s->object_size = max(s->object_size, size);
> +		s->inuse = max(s->inuse, ALIGN(size, sizeof(void *)));
> +	}
> +
> +	return s;
> +}
> +
>  /**
>   * __kmem_cache_create_args - Create a kmem cache.
>   * @name: A string which is used in /proc/slabinfo to identify this cache.
> @@ -323,9 +355,7 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
>  		    object_size - args->usersize < args->useroffset))
>  		args->usersize = args->useroffset = 0;
>  
> -	if (!args->usersize && !args->sheaf_capacity)
> -		s = __kmem_cache_alias(name, object_size, args->align, flags,
> -				       args->ctor);
> +	s = __kmem_cache_alias(name, object_size, flags, args);
>  	if (s)
>  		goto out_unlock;
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 4eb60e99abd7..9d86c0505dcd 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -350,11 +350,8 @@ enum track_item { TRACK_ALLOC, TRACK_FREE };
>  
>  #ifdef SLAB_SUPPORTS_SYSFS
>  static int sysfs_slab_add(struct kmem_cache *);
> -static int sysfs_slab_alias(struct kmem_cache *, const char *);
>  #else
>  static inline int sysfs_slab_add(struct kmem_cache *s) { return 0; }
> -static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
> -							{ return 0; }
>  #endif
>  
>  #if defined(CONFIG_DEBUG_FS) && defined(CONFIG_SLUB_DEBUG)
> @@ -8570,31 +8567,6 @@ void __init kmem_cache_init_late(void)
>  	WARN_ON(!flushwq);
>  }
>  
> -struct kmem_cache *
> -__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
> -		   slab_flags_t flags, void (*ctor)(void *))
> -{
> -	struct kmem_cache *s;
> -
> -	s = find_mergeable(size, align, flags, name, ctor);
> -	if (s) {
> -		if (sysfs_slab_alias(s, name))
> -			pr_err("SLUB: Unable to add cache alias %s to sysfs\n",
> -			       name);
> -
> -		s->refcount++;
> -
> -		/*
> -		 * Adjust the object sizes so that we clear
> -		 * the complete object on kzalloc.
> -		 */
> -		s->object_size = max(s->object_size, size);
> -		s->inuse = max(s->inuse, ALIGN(size, sizeof(void *)));
> -	}
> -
> -	return s;
> -}
> -
>  int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  			 unsigned int size, struct kmem_cache_args *args,
>  			 slab_flags_t flags)
> @@ -9827,7 +9799,7 @@ struct saved_alias {
>  
>  static struct saved_alias *alias_list;
>  
> -static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
> +int sysfs_slab_alias(struct kmem_cache *s, const char *name)
>  {
>  	struct saved_alias *al;
>  
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/xvdhietnpfl6ait3kjwxu3nrrzdpwvt3zp5ui4l6o7t7yps55g%40wygbtepochfg.
