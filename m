Return-Path: <kasan-dev+bncBC37BC7E2QERB5U55TFQMGQEKPNL2RQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8FkiFvgOe2nqAwIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERB5U55TFQMGQEKPNL2RQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:40:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id D4E85ACD76
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:40:39 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-8c5e166fb75sf210363985a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 23:40:39 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769672438; cv=pass;
        d=google.com; s=arc-20240605;
        b=cXoN1Y33VSX1h5NbvuAdqksukcCZc+qFUj1PhQ+hN0e2tnVPC3yLpVaoBx1kVqQpws
         kED3gKY8aWGdMSvtM1I4E5xBUbXc14Lgiq6/KWLqXzdSeAFFoO1Y3CeCcgS0Jtz6ZJeH
         w3H+yNZEolCVIhW2oYRNoGSYnKx1ICHrPSYSEBCbVNswk6zA556DAm4YFwDqPoOvvjNl
         U66gSZvwcuhdazqB/5kG4FeYHCNiSG6g5oDjO3EJ3VQ/FsOZEo2T6EK9jHpp3vw3tLL2
         sw6Kkk7C/gdatx4ecnZn69VSsnAkP7/6lfzIOC/KuS7IiMVL+ZhfHD0yYYKJ99y1kK6T
         NIgQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bwj2r9516uFNTja+Gh92Yj0NqhC4Irpgy+94ObJHTY4=;
        fh=hI198Os8RcmUACF7kBWVyJC1xR2jvP0IEE/7+9HYWZY=;
        b=iQi/LgYKj4OCgbqsH7CB3Blyknxfbi7PUJXQrbvahOM7/oigs1oD6M0RL6abnt/gl/
         Xz/8+MDzT6zbJ4et9ExvxZCiFtoZa9OrEMF0kOeHb0MwSnVrmAjrPGHYn5D7AEaqxZzQ
         BSA8A3alzxcrm3hGDUB4jA3aLqPHCOaB85auNtWS4BYwNlmzSu278jpF1mKWfIxd0f/8
         enXWYPXor4wflqvyVKAV36WreAhzOEwyYwba7Q6TmZpvwkeNiYVmEjuGBa/PdEkn9ge+
         LOHX8ygFOdcUSfcIqiHtsNSkQfPh1je+BB4LktwHv42g5RnZMiMdE5bLz6JrQUK4DMie
         fhvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gcnVJM7e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OaCv1X0H;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769672438; x=1770277238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bwj2r9516uFNTja+Gh92Yj0NqhC4Irpgy+94ObJHTY4=;
        b=RVj6QYQWRiEgXp5fj59vcuoq+pgHm8mzrkZ/CxqFVjecFvAFsafYHS5Bf3Ut1DVGh0
         8DUrKw5QWnEdkTBq6gzqEVdNiXrRlMl3J/bVbtVM8u0bPhj5PIYYj6xcMy7/0FJzKBnr
         zy86kDn8mfVsa5KXDBLK78Xg8aeCn2YAGpfsuaW4zJ5+szK5XN6KakfU+8Z78QXdInML
         p2axw0dBpNwDWireGJcaJPi/uWkdASemo28NFjL+ZjH3bXRKt1fQQkHpna5rCWNkB39C
         7ctOeLeKKfvKwd1DxwyDi7KpSCBFbK9x5NwKUQhlK2BmnrN8fs5sWlW832gFJmZC1QHs
         fZxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769672438; x=1770277238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bwj2r9516uFNTja+Gh92Yj0NqhC4Irpgy+94ObJHTY4=;
        b=qaYv1LzjlrJ1nXyeAhvByAl5KNq1+7PMuQhXBEDLtajJcUUIVns2knfJCwTEyWedy6
         ypCvnfMcyIsGaA4RUrtV1QBQv/V393eRjTyQyHvxjE5rLpSDsk794NSgBQ4LR8zd639y
         GFvhx1lf8ElSwxcDTHPT1Em5vi2niSR5cPMaWvqOSQ7cMqEZbogjUWQgKzpdEUVXwUe2
         geb9bjIub55OJR+yVSBSO3SLw7pMIFA6aT0aW8XFWF//ZMTocgy3ycOHkcYKG08cQ2C1
         lQD3qEPxtN60nz3m31BrjiVZngggT2M5kdqbJ0AgfWE6SYSl8+aCdnDAogVMlkxPA5TW
         XxsQ==
X-Forwarded-Encrypted: i=3; AJvYcCWgssCtItLiVWSsgUZrAz8FYkyhO9ZxX9vuWEGmaaAA9BtsIo4sNBaUViIbQroHOK3L7K3PaA==@lfdr.de
X-Gm-Message-State: AOJu0Yzc7OE9F9mT9lt44Ru/6KSympUHGYCERyhM+Ejs6uAxHuzRdaDK
	AQxJ8wQtU+XIsXV/EmsQBnytgD2DbYfJfEhbqClIFv5ZyPGshWCtPEM0
X-Received: by 2002:a05:620a:4692:b0:8bb:a960:a6fd with SMTP id af79cd13be357-8c70b821995mr1002743085a.10.1769672438335;
        Wed, 28 Jan 2026 23:40:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GilUbTq0I87IyVjPvlhO2FIUcqQTStS6R8V4w2xEphfg=="
Received: by 2002:ad4:5ba6:0:b0:880:57b3:cd12 with SMTP id 6a1803df08f44-894e0c0532cls9381416d6.1.-pod-prod-03-us;
 Wed, 28 Jan 2026 23:40:37 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV+/qpUpdgGQ3+qBJhZEi0OMGeiwv6tXkXIXhx0MWlHUtg6qMYMT7gPMgPhKIEibwSZy+TqZUf5BjQ=@googlegroups.com
X-Received: by 2002:a05:6122:2a0a:b0:54a:1e96:e958 with SMTP id 71dfb90a1353d-56679342fcdmr2328195e0c.0.1769672437436;
        Wed, 28 Jan 2026 23:40:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769672437; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hr7UKS1E1rBzn9HuVNdWYsP29ooGGih41CfHix9DP7esU3SjM/k8G3A4OMy18cqP5D
         QYSFclQ8RQxPBeCadYKMoFW92CIGmaRd/ngKT05E9jUmIPNGgUlg13W0IknL+oNch56a
         lyodndnmREe70Gjwd+mXfHtN2d6EOG19Rs7L1STp8yqSIOF2modQaZJN51MEu3MvykHp
         VI/M/dVs9er2eadZy2jUeAd7lzPL7c3PKapTylbKS1Z0CgXlAN9FowoN9owAVULvqHbs
         2o+vjHo5NYwA3use4E19gFQSJIAdMnTRDa+VXOhH9Tq/pCt0/hV8brF7Z6UAjicLbOBJ
         lh0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=u9jfUclw+yvPmVIZjheNtO73+AAMxSJHVeZcsaPYEQo=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=Oe4D4x0JA3utnIgQaEZGgRN3TpXY4j5cPc5eyovrMDrnba3nxc8Rl3OBVAbfpGQKGU
         S41LLtsKurNPYxFunNRLYO+XRoqSKAuwsYyHgU0NLVpY0wF1h8u92ztMPF8fy6xBqlO5
         v9wILYV3Xrb8F9xzI6PCaM8dkvkg9+HvVFKqbveIwWREoE96oUqjOMoEqsaplpI1w5+6
         Wdv00HvRlandddq2Fa/ecY8K5Hj06QVCjP9dy0igQwgS25aZ4u3d5qp75c213zP2Ms5J
         ZGBEKs2vgs6PTw88WYe0+C814MKiFP+ZwyGxyyOJAqhRCZtjiVxx6qwfXbh4GC1ZxwAK
         +JnA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gcnVJM7e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OaCv1X0H;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56685ae438asi150543e0c.1.2026.01.28.23.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Jan 2026 23:40:37 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T6RXDs1431695;
	Thu, 29 Jan 2026 07:40:35 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4by5dj2em7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:40:34 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T6YS7S036021;
	Thu, 29 Jan 2026 07:40:34 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011006.outbound.protection.outlook.com [52.101.62.6])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhr9ddd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:40:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=WXJUjhEFV11m3XjURaJxWDaF73dfP4J2ABwwn/E4M5Lng8xY/YYqyKKPQhImHsZ4tfxsKwzLygGN0tKQbCiZAfK999XEE+EQ8pNgBrYCTRy8IgKJUGQ3SbhWnU23ddvH3QxgvjKfJqmOB2juVg5+ke5nD71fSAeOxB490Yd2CzHAmSxRwpeICF1dq+kpgoQNStNK+2myU+i0ekZRLByZjFekN5AtF+OFH+Y8pixmnWlfGTm5+PmM8tXn+L5aEkgaLMMbri8tVyvNLIlbq9bGpsY0BNxEBCkghc5BOIOkPifC2hpYML+wSElb8raXN7DCuwzDym0A4W3VvUX0YhrAnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=u9jfUclw+yvPmVIZjheNtO73+AAMxSJHVeZcsaPYEQo=;
 b=RTckxcy1SRusOx7Zx+9VQlKUkhGpIEA75iRZ0xZRpZUnfceWet6HNBqTzA1UP9D3ZO/Vdv5pYuFDF0AsPszUnWZkQGZPCs6W1YuOCTaBFTP4J/ffnN91lISsHdYow3eS1mhL+zk0kBvYwzUcRzfXDK9/Xbe/Bu2TeYZc8eA043c3yEP5htdoea+Kc/RBMifm2RYBSUwa7VKi84suSr4YnV/RiE7helsvHjWek0yTdgv4Tt1U1vnZABONakANEIBnshTBByHyQEShnx6bpqMF0sGEPlvix64T/Fr78rkkZ4+sp6LWNCLvTmXfVOs3LfK5KAR2dkAUbSiLZJrADldPcA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB4623.namprd10.prod.outlook.com (2603:10b6:a03:2dc::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9564.10; Thu, 29 Jan
 2026 07:40:31 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 07:40:31 +0000
Date: Thu, 29 Jan 2026 16:40:21 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 22/22] mm/slub: cleanup and repurpose some stat items
Message-ID: <aXsO5ROLtJ5jH0dh@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-22-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-22-041323d506f7@suse.cz>
X-ClientProxiedBy: SL2P216CA0191.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:1a::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB4623:EE_
X-MS-Office365-Filtering-Correlation-Id: 282e14f5-679e-4e61-455f-08de5f09adf3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?IaZ6PDuUK+NvP4lWqVvY8iqj79ZouNeK9i3SdaUW2VHYlVJA+PRTKaZGETCO?=
 =?us-ascii?Q?wbaR2t8kbQjY4p/NnJ/TNNz6YG6q1xEBTPb1FTtKs92TiHA5HBYsuewRZ8bn?=
 =?us-ascii?Q?eWUG/EuTecYZg0aao4W2ALjEPfYwuDTLDUfZgI24/3KT4RuiKwuR7N4CpLUM?=
 =?us-ascii?Q?1b9M9Kx5gktgoSF/tcI9gXDiDkDlf3A3jwVhiMJ8Jbvd8xfvHsLO4BqHUZK1?=
 =?us-ascii?Q?Z89l0n5shGkeGHOD5f2qizfcjKY5YZCDeWylWugUCOfGQXo0e+wxE9CaXzdW?=
 =?us-ascii?Q?SZCiJamlBZmzW/KsUQ1aaEtFGoFPFr5QmPJjak4odTVerQzyAxVrGQkqyU5K?=
 =?us-ascii?Q?G6jodRst7CoM7W3UoEdV5FZtruXtEwgSW4yXv6aELlny7FnEI747AtIvfOOe?=
 =?us-ascii?Q?4j7Qs+8NiTr6+qsvOcG2gWJMYtOkG6B54m00wbZNoKfILuu/fXC10hnYFUMm?=
 =?us-ascii?Q?Nac6uesJqy4+NMu8k0C3M8D8MmMMaJIjl7rz48ShTSklUl/rnxcL/ESQoo2m?=
 =?us-ascii?Q?dXNU1nPlqlFDzk7AZu0aHBanYNC3gRUAb3H7IkhBtxWDhu1S5p6+MN6qPGYX?=
 =?us-ascii?Q?PtP5VSVe+pxTVTD2/iAm0ELxeXYOjeDfq5q/pQTawnjZR8HXL9YKlNiDLDGR?=
 =?us-ascii?Q?rR93r4XhdgOM0ZKR1tNTqnmx4AbnOaEuhgr4qgX29FISKEiMxIU0JwiLdWn8?=
 =?us-ascii?Q?TecUcjYj9Gri6miHQZOYxD39w1YpryQAxwkw5/2q/sf4LZXj3r7FRDgjTw9K?=
 =?us-ascii?Q?+2kc3P0O8rMPHiHE8jf8Zy1IKOebTxNTiY/PTt7wy1miaGfoqkZ9L9m42fZz?=
 =?us-ascii?Q?3P2+I08ye76n77VfYQPRMwUIZhvS8HOJeyOBqCTY+IJTfEFkIn3GQATE2Yfv?=
 =?us-ascii?Q?PBtNmvLSf/qt3aJBXSg+tSBpC8htj4WkFmEk1pg+B/p5CY/Y2cmCHoHpyQCT?=
 =?us-ascii?Q?RY+JtrttpTl9tVM7hgNmAyuAWFHtSnwscqI2Chb7bnIdH4HsNKJlBZPod9RF?=
 =?us-ascii?Q?ag+jdIVFGW2i0fZt05/Xi1kiVkrY6RBLeKXAAyttpc5+uVVggsvw6ALmlayJ?=
 =?us-ascii?Q?FHFamlr4fwDT8ELIQwmocp44NLgBs9rOXg5hSyw6m2xrDlXFLJGBUga6H0TG?=
 =?us-ascii?Q?hGAr72jY9gicIEM5homXZbzSfUj6NrV27nkWuWBzA5EkIy1Gng7uOC7UFNXv?=
 =?us-ascii?Q?eCxbhiIRt4O76ycjfzvIHouKJePgnvA3Q5J9qcRRn8hV5sTU/9avkyzt2WX8?=
 =?us-ascii?Q?sxt5U+2vKVzrjALWmNZyDcua+C2nj8U3BaWexPqMXQwfgty2nz7rxs6Wcg/B?=
 =?us-ascii?Q?d4qT38GUeQmkJGPrQeNXVkKwhvBDxC+9Z+p4otXkMSSsat5MCGsrn+lLjgBk?=
 =?us-ascii?Q?KTdmUo/f0JrtWwUNypM4Z+YRPdpBXNWnuWjn+fZHLWlCscc3Ab0taccJanFg?=
 =?us-ascii?Q?3Mj4KU+nH/DOiYwd6BgC94mpaVaPBXSRVYXhY6OvFbWQ/+CeGyMv8sErXfAI?=
 =?us-ascii?Q?2thvAKjeV3glhhcZgh/XAqiaN/sCyfTXNkMqUiscVWxcTR1+wswCCWSGB7HG?=
 =?us-ascii?Q?+dvK7T7+OTPCWEBkddE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?3BRgP3xtif/bQF6gCxiCy69Tq/QcEPwggHeuRMozKMluJhEKY5TjNOPvbfot?=
 =?us-ascii?Q?p7noMbDQ3F1q3r0Lx2Uz8B1kEbIC20v0hBdKBlZ5vmb62caQyY5HxGTbg/KV?=
 =?us-ascii?Q?PGfYIUMCwC7s4jXQjvQrZLSTtmdxaVg66V9MoK8nXkuO59XYorJCi+iN3cAX?=
 =?us-ascii?Q?j4RO3SsrL9Wvc8uurMDZYNYKUBaH6oUoPo3Mzez8/F8v3k3/Z0o7vsTeFIaw?=
 =?us-ascii?Q?bFLJnlpNz7xR+Ae9aByBLlLGoQllclmVMcB+ejS5hpArA4YrsLbY2qsk2Nz3?=
 =?us-ascii?Q?1MbHBXZ1gHfIJfNlRAurgvjITCUcrhK1MPTJYfpCMhNBuLrIpPlfSEfVU9rz?=
 =?us-ascii?Q?iytHej2fmlt8FmnXeAXddCbiW439IkKOdWKSRHXiLJMQ0RfHobSFBNKKg/XE?=
 =?us-ascii?Q?JD+Rb+yJeZuggEdD6x7AUIOx9+1b+Kuf2z+SOyhiCnqJYTPXjw5rANHX/Ev1?=
 =?us-ascii?Q?Tmm5LQtVPfM0I/Xo0O+McxBz8zcEQ3QTih7g8or2Q65PkNISx1+TNFM5kGXv?=
 =?us-ascii?Q?xlxMUXoHU//d5hwgPBaYmHecoR+RUwBU5JPRkD9K8Uj6wAMIPA0wuptM1G58?=
 =?us-ascii?Q?OV6JqhQw/1wWQQ+J2kRUFjur7PnWcuehOGERRnrXLmom65/ntMFZZ0RFRUBi?=
 =?us-ascii?Q?MlWZBTUxpS0I+CyAGy33bDuXuAClFR4YN03LKnF3ZJCeyNOXhANHKFtXr47o?=
 =?us-ascii?Q?eEgtJq2jx2aKIw+yXQaKNaUDxxbhYY6iQcMECZWqJhOj1j+ZIOT7or6/MBbA?=
 =?us-ascii?Q?MTt1bMqe27KWUarEYm020dxsBPUc5/+UuWxMeDTLfY/vbClZ0IHBnDWy6ZAv?=
 =?us-ascii?Q?+0Hd7waRPCKDrHGsrsRZBhCUzYQX5EoYjiMKba+bUdQExM9pRO9oXzW4/MQy?=
 =?us-ascii?Q?0zuwt2YalSkMHzSpau3MeSYx+mLlKSQ4Ph3RG23b4t9xt0buiicgO5bCyFg8?=
 =?us-ascii?Q?MjIMYbtwG4RuOUGMq8sepSLeDhYeYZ/igOtNjZppR42BbrKiMpQYs2BQIcXQ?=
 =?us-ascii?Q?PBJATkLVKKwj5510VfSUvAIwFkddLR7pSxAjmRF0uzaQea5aDpgkDaDgN8rG?=
 =?us-ascii?Q?9z0WefUguYNdfSfq8QxU8zYZ+3kH1v9GMqC92ZrsDUKRb3Ytmkbds5JNKtFl?=
 =?us-ascii?Q?iC8GRlkj4ToxNysxJVjv2a6OkvH2aG5kZE3o8ag/GDTWHVB5lPl5TM+UqqOh?=
 =?us-ascii?Q?VQJYeVya2FjBWpJBIVJUyexUaGksEqUOXms9xsKQHnXuvEZ49SC/nYrYQyMS?=
 =?us-ascii?Q?qFMeS+xD7K5HFDfnpFbvhUh575gnSTtxGFMlO0Lr3dJ0qevWIb3DBlC9AjWs?=
 =?us-ascii?Q?e61Ci/746mPSuqxWiSZZ5oFGYvJuA3wTmdb4c4dQX9NzeTql7Y/9gl+cWnjy?=
 =?us-ascii?Q?p3u//zIixpEUQg3mxzZMe1FXg3wCNjYlPnN+CbdBItYR041RnlnbhpoKakNb?=
 =?us-ascii?Q?yuht18s30LzdvOvdKlyJRxOXeBw6jcDYzFpPB1AR7ahTdQcC881asp8JmH+r?=
 =?us-ascii?Q?lsMVISyUz03MPndCCem7rjI348a/ZfY61q+uWj2lx7AVBG+oydyQ7udASoi5?=
 =?us-ascii?Q?3KKpdaRkItFzIb+rJvLma365Onugbo2PzbdqJEZRevF5tKQJy/0PMzlSbMMq?=
 =?us-ascii?Q?3YPSd4/SzoGwCwzN/fwkel8fqBUEREPijnnYCuexH/Rj3vNlnn+XgeZq4ief?=
 =?us-ascii?Q?oJTW1Pbni+jCrh/DGJlOk0JQlXJEwxlDPGfc26r1vk3y5K50x1sUbuTNqn6G?=
 =?us-ascii?Q?O9iUF7vLjg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: w18hyy4nbx1KeOd+dkxI2ocvVSJLGUuoXfSW0l/ekNXFAPWRbeblrWDDAXreeBa2HgAIKd+DpzXlNriYQbO+PbaFVxn5hLbcecOaXomGVhwoBGtR+NvW5/gmYAVM67835DPDnhfidIaMMCGax/BGE5bdFEbhOQ2xgolHnSz+ox0dKDWWLcBaGlKRZ9sBDKSM7Hem0IY2uDpa/NhMqWNRuE+nqoXu58C+NL2KqhD+yIElwD+jT1cuBTss0XuS4NhEbysMRHq7JWBnFMKMdEkpLvaUHEjjoZtQudIx25DgLlNYoJnnl5jkLCXsUWbF68B2qDqWeRQGe/z6SESYBSSNYLlfbUvKw5LcuuOvdL0PUu6XughnUp5EMCSJ98otnBcgWaw4rvgDpTxWgRma3lO33ugIUGf51dmOa93Wxc51r7W88YBsNjYMatwe1IW4hShwbU+WGM0HV/Dmf/bw5kU0In+B7PT2RtljNrbu9prd2XPW3L3GKNXao2t0yKDWHloqp8Pui4bSsd82w7Cm+vPhNmv8ZcSo6CV8SPO4V3ND+/xVanu4LLq8SOfuEKdNjxwKt0vse+01cbw982pCtady3ubOFPEqNrTebGoOEVrU2FU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 282e14f5-679e-4e61-455f-08de5f09adf3
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 07:40:31.2181
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: o8pxqvEjGKMJqTs1gWc8u8pzl8udnOaZ7avAIsMVoVA9UTcUKNUbwqGdCIm2xka9wFSwnNy08hi+619iwvHWrg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4623
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601290044
X-Proofpoint-ORIG-GUID: 13_wVBGG-jHl8bltQtiZwg_6svQuPy9w
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA0NSBTYWx0ZWRfX8IiqiL+DcdK5
 1baTZGvUdPQ7K6irCjqgIhD9qGmv+AhkwnOgGDGeq85DChLDcr8EO6smOdvzp1dA0xbcCh1CG2v
 3ouplfcAV2SjB8rmEwDFXBW0h7r5Q2AXmLTEkyVRt/lI5c342W2xD5sOuIn96CzSIYMx1e1lEpZ
 c0lXKaKTJjFkXwbiQ5fn1udkwke1w/bQ2fsX9cA48iTaTB0p4ZYiuDugVuVYWaLOLVNFCxouwz0
 wFRGx5RmY8hFAdzEoSosYwiHboFfdrcNt+ep7CD29aA2ziV6RKDdnj1yZTkHeWY/+xQvMeIqosQ
 F7yuny2+nmIfdtaC41kMNmG3+MAVpnjTJnQssbI0LyGkNgs+f4tj3Yf2pEqIuPJhdRFP8/tzJGp
 EIr4Pg9qVUdtlwVlRx9jUrkJQiPuu88CiWbYj4eobjOUmPtbG2aE8kAOSpncRoWXcvwmRqeIacY
 Y7vKMkYhyyIrc1sdk95BD+lj+b1+EMSbN7rLvdyk=
X-Authority-Analysis: v=2.4 cv=IrsTsb/g c=1 sm=1 tr=0 ts=697b0ef2 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=3XPRvzdtEcMrkblgAfAA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12104
X-Proofpoint-GUID: 13_wVBGG-jHl8bltQtiZwg_6svQuPy9w
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gcnVJM7e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=OaCv1X0H;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERB5U55TFQMGQEKPNL2RQ];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: D4E85ACD76
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:53:00AM +0100, Vlastimil Babka wrote:
> A number of stat items related to cpu slabs became unused, remove them.
> 
> Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
> removing those, use them instead of ALLOC_PCS and FREE_PCS, since
> sheaves are the new (and only) fastpaths, Remove the recently added
> _PCS variants instead.
> 
> Change where FREE_SLOWPATH is counted so that it only counts freeing of
> objects by slab users that (for whatever reason) do not go to a percpu
> sheaf, and not all (including internal) callers of __slab_free(). Thus
> sheaf flushing (already counted by SHEAF_FLUSH) does not affect
> FREE_SLOWPATH anymore. This matches how ALLOC_SLOWPATH doesn't count
> sheaf refills (counted by SHEAF_REFILL).
> 
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsO5ROLtJ5jH0dh%40hyeyoo.
