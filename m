Return-Path: <kasan-dev+bncBC37BC7E2QERB66SXPFQMGQEJ3PYUOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F59CD3BD87
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 03:33:33 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-40805ab764fsf3691153fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 18:33:33 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768876411; cv=pass;
        d=google.com; s=arc-20240605;
        b=cusuiGusxeXFej2SvFBXN/kQQD+EwgnsjGbvKwEipXzrVAfYv/hTrsXqIMh9VOecYY
         yi4Eikw3p8kspQNki/j0W+PlLLe6I4nePRcOFUZEVKl80cnUb8m3FGRUbGXFut4dwvcb
         QfEMcUZVWlV51hE/1XxcGkMDnlkDQBAwFxcBWuHHGdhK9gy1x63htdPjXl3ovA539G2r
         lJq1p5BoMNBdrHPnVW6RHxud51c3G4bANpwE6J2d3JfYLMH6dWUomw4p4YaTSEbJvYfL
         iuqCzFdUTzBLxXfINkDwpr9mbfq2aRXwk8I5GMfPvcVkIav8LpdJXRZDuiRJ9JEd2Sr6
         zxUA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ChHdqO5TWylsHr2Dx6GXZvk6z7qd56w0e9OfR/dV7EM=;
        fh=218kVTtIwTy9WrF8IxBQ4mRgvNZqfy0m76+MAYZlA5E=;
        b=OCmTm8uI8cJ5ne0/kfSoM3Wc5yBcjWz5jtDJ4PYH7RPhGH1U7OE7MawitUz2mRiKwF
         U5C8R+XQKb6x2v0cfBDbJNtk7KzvI9Dj9z8xhAiKd2UFfYzfpQv5/H0iXM4cAiEL1+mc
         jHtJW66wjuzUU7x85AW9dtVmUlKogVNPv3sSB3vdSe4e6ob/z28HI5M36tJjLPI79Dyk
         KJWW539caQaRqtCAWSK5xAb6ITDdZ+wsJaRyq4pvRrwaUzAWFAdB/0ZwJVOnt+D2boPZ
         IFjos3mIUR3RhisqRiXJ7xGD1HB+Xd+TBYTOFUMlrqabpxJyi1SWaoU6AaCpnnYzjnGS
         aRXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=VkjKgvSg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Q7FHoR3t;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768876411; x=1769481211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ChHdqO5TWylsHr2Dx6GXZvk6z7qd56w0e9OfR/dV7EM=;
        b=Fj8z3ctuBH+8KBflGngbWlQ1wrFWIlrWv2cNDp3lUUZzgxJ7neRNnhMOCzJJBeZSRU
         /4d1nsYlUzHtmaS3jiLYcF06J2DJDK9cp71Z5ty5xAD0384pvpQdyGT9YxaOdwRs0r2b
         8WHaLeZQJ9gESvgsUgGiiWn7pxYDgtlUwXBGGXzAVanKhRufF08VSYHVqCox0yW5lvcB
         xIn005dMPRAjVMho0T19iP8mK/xStBkn7t/61dmItZpZF0LaWQxENGX9QYZh4D09DRno
         ZGBlUk+aoMQXsAIz3l/JoRILhYJo8Xq9Qz5QXQ8jSZ4LSXAyWe/lOKAszyHgcIqi+Ds0
         1x1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768876411; x=1769481211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ChHdqO5TWylsHr2Dx6GXZvk6z7qd56w0e9OfR/dV7EM=;
        b=TK03Q2DeHO//qT7aPadAiTqO7axdGYJJadU97D7wJyUt2MoUzBnCVlV0qsyTGMhVu1
         F9/lt94iKWC+MkygtpNwaObO+iKN7A/0JXLOZv4XWAJoZ5CMHrhysAW8qonl3jRlbznt
         V/qsC/hkfLBptbhA0pzxXohqlxF7cxqVnfgh6KDXs5THf5v8FUrFhRkvI8hKFLg+l5Q0
         5Qp7Rm8tAGllRWFFd9N1YaJPwqlCJe8actHYgwBYKTzpdqOMJbsddg107ztZNgIBsXD5
         BEY1aDN45CrnJ9WZMDTwxmuulrcifPYTi6haEgmS/jrNt4NIyKGsahq9AOUC6te6wNG+
         j+Wg==
X-Forwarded-Encrypted: i=3; AJvYcCXd0KtKX3/ivl57ttsd2+V6AiOTT44zR/5HmMVy/Ti4ZgCkGbCa3tnP9lxTi+l3x9ibnJFCSw==@lfdr.de
X-Gm-Message-State: AOJu0YxqVY9xFJrNf8IGA9zZJuXhaHlfRxA9399R/nP0uuQaMMUB3fIU
	yT87fjGlCj7//GVqblvhX/55TAIYZiJ6m5p9Ve6RYE7jc92rMs9n8pFL
X-Received: by 2002:a05:6820:160a:b0:659:9a49:8f54 with SMTP id 006d021491bc7-6611796e7d4mr5513172eaf.25.1768876411366;
        Mon, 19 Jan 2026 18:33:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FjCz37QCAS/BN2BS//ymqmQEuhKOXH86uygt+WNgmbwA=="
Received: by 2002:a4a:c316:0:b0:661:4cb:572a with SMTP id 006d021491bc7-6610e4ea61bls2541298eaf.2.-pod-prod-01-us;
 Mon, 19 Jan 2026 18:33:30 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXhPkVJoioMu9/anvmcse++djaWUfSJZXwfAlY27n/AGpd4RufSAdAJm4Pj/ujLRcfG8kzJ5yb/gM8=@googlegroups.com
X-Received: by 2002:a05:6830:7107:b0:7cf:d88d:5dd5 with SMTP id 46e09a7af769-7cfded1f1c3mr5752553a34.5.1768876410255;
        Mon, 19 Jan 2026 18:33:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768876410; cv=pass;
        d=google.com; s=arc-20240605;
        b=gKFfibTSoHW4+MuseoeMOqudEbP4WisLzANhRhCPTPsR8kMYJLgu+vgUL34oq8IwhY
         hjbJlaxt5HbQk5V9EsE6s8YVA43olNkTsvVlWkBAufljeDi3/UlP+1DbQj8gSOvQKF8V
         sOoRLMhoHUtEQqn2sjGEpktSLIbqFdHR2IORoNXiJfulXKH50JIeNEfVJw9D6UoFlx+u
         Qu+9b2qu2xljGuSzfveGfzn5DpBiWbyW/pzUBmKuYFuWeadWmU6Sd0f9d596ltiMonII
         YbCZrJ4QLKpm/mQ7+eIqeEvYFKVmCVwgPaj/9PUvJRYJty0BUipggpVDmgBDz/cviOXY
         D5+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=LVB7e7j5UDzigZd+NgUFwsZdhjany1imc0CkeHFTCBw=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=QObfsHi+NiMUTMJJhrlrQYtukO/hovLbkIAcGiX5nXa4js4imw9zo2nKDZauZQULgL
         lX1J+r7ew47hS4jkw7Jrg42wuGmnjAQaSOtEBUJdmiMPec/mHnWMkM/929n79UkRK6Qi
         TlIClbBZ+QP4N/vYR/vSncH/arPwXdBeuzHGgol+fldoKysg8MKMKFpmBmOLTzMTelo2
         hvWqNxtAYNt6Yf8rZA+wraCFE8BTDHClo98S0MkHSLmADAMdbMr71wOChSdkMUDBOxyw
         QrtrOIPz3+uVo8RXbBeVIQoE17Kf8q2lp7/1LuVjkpdjkd0Gt7fTKFjT5B7HiKo7FltM
         6NMQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=VkjKgvSg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Q7FHoR3t;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cfdf0cd0b1si347031a34.2.2026.01.19.18.33.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 18:33:30 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60JBDRJ51037505;
	Tue, 20 Jan 2026 02:33:26 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br2yptvfm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 02:33:25 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60JNFeTC022107;
	Tue, 20 Jan 2026 02:33:24 GMT
Received: from bl2pr02cu003.outbound.protection.outlook.com (mail-eastusazon11011047.outbound.protection.outlook.com [52.101.52.47])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vcr6yv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 02:33:23 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=U1h83CDBHZ8rs2rtevDwrKsDi+rk79ZAp9aYEdRfGW5JR95sWcJBPrWO/bzAr4V776IsF6XFTPpA4UyPVbMR4oozQuG8x9jiZirMjXvujtJFo3ytPgsncMAjTkA6PBdzH7oc/VTQEHARepkRC4QjZpeRerKYMUtzUL35mKbjcpxmrizP6GJm9vhdJAPHdp/wl4gF3Kmb8iswu+vpb8qM50yDLl7+50Xr/nUpTUCPECJP06qHNJ+kFFWnLf2WRX5wKBBvJhNWaHDh8oDWH0o8EhTYAEZblbRviYe3Yx2SwNX62WQMcNfPRg8nY5AHTTmsc4GEp643Plu9bkjo8MfPcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LVB7e7j5UDzigZd+NgUFwsZdhjany1imc0CkeHFTCBw=;
 b=LfZA3hnt9vcC42+lUmOW1A+hQ0EXujup9upPtq0ecmbSSa5YaGF8/AUowDecJ5PFlCZkUG7XrIc74ygPOPgUdq5NNOXp39M+JKjeisK+XQYN5DOjGNC1inXXE6eDWERdhDCy3GsLuvDeDcmC0sMhB9uxJL+Y8Dst7rjCGZBVaMfkYoNkUJbIaSVZ0KgvvEqRQDoIb3z0f/ktJJEteXsFk8XBOeOD4/+v/WTMJhfG3T9KceVMKF82dyJq2q59tmwC5i6i/jl6sfjfpNW7jX/jmD9209lUjH5Se3rVK+eLHN3HrXjfaITKDGSe+s0UMHDX8su2rkyQGxARLt69PCRPyw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SA1PR10MB6470.namprd10.prod.outlook.com (2603:10b6:806:29f::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 02:32:52 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.011; Tue, 20 Jan 2026
 02:32:52 +0000
Date: Tue, 20 Jan 2026 11:32:43 +0900
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
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <aW7pSzVPvLLbQGxn@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2PR03CA0013.apcprd03.prod.outlook.com
 (2603:1096:100:55::25) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SA1PR10MB6470:EE_
X-MS-Office365-Filtering-Correlation-Id: fb5e4d28-d213-4cb8-31a1-08de57cc3603
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rL48u25JVMkWsfhoSaxTyMyyK1t5p611SWBV9UOQ7zWhjOTLtBNS27Pq8H4I?=
 =?us-ascii?Q?M8R2VJXfqxtzrE66Fzmn5NIhP6MgGksjRLELHni+g3QxwuyN6ZOTre0okUaf?=
 =?us-ascii?Q?EfW9t8vLT3BQZaSup8oSBowo9nEnaastAvxZj0M2z8w6R0p5DetMjh2WAJgg?=
 =?us-ascii?Q?GBEX27Y2cAVl/g+sznH6QcCI+owoQjS7ekCHnY54svBYlNhzJ6gG/FP+f4lg?=
 =?us-ascii?Q?7zjx09MRBC/WuL0VtvG10ZNK1TeOuWj6vyCzBe518YW2qCvbpXV7T7NkJH0N?=
 =?us-ascii?Q?l/buSIBK3TJdHl3h5FM+vjiyHCTLq3mceuLyOmrvSyeA1z7cHnj5gHf+TXwc?=
 =?us-ascii?Q?dfwVsGpSUEevYMPo8luVdTBlop9JJEKoJ35IiHoH+apPVBmcDfioHdcdplOd?=
 =?us-ascii?Q?x1qSBKRr92XOFk1SrrDB48jgp9LthCw5kpf8O1O4xv8LOiN/iREOZohpzYPz?=
 =?us-ascii?Q?hdkYO6cFZ5PyFUQ4J/6iPYBQYacUtvTZVOrd0I5ivgs8ju8OBZw96FPZ6867?=
 =?us-ascii?Q?IvDPw8c5HUSquYCXEFbg50WbLIkbnpWoehB2RreJPzbYb8yqJn4TMCqeTjOz?=
 =?us-ascii?Q?gVdCmrJ/3JxtGG7cLhPh3UYtMDZF2eV95ougIgO04yKqFdcUYe4XIYX/9Br3?=
 =?us-ascii?Q?wOnd/pc7aoxn3PJOoN+UVFQcd/6+4+E4QKySb4DKk9vQb6yOVUQgxvpU6aSG?=
 =?us-ascii?Q?H4BB3KvRit3OuoPpf+78c7Ax4MpMqe60r+fSnEXs3LaEzTbAwCgkLrVk3rAE?=
 =?us-ascii?Q?sasjJ8no4kUS9Eferz7OZ8p852yukNfGXbVDgxWrJz+whXlGQSGx8hWV+aOo?=
 =?us-ascii?Q?3Mhzcq+0Z8l3jr3vO+y6qLi9Az+Da0lvztrnEV6oOY1X2Lj8Wy/3PcvDh7YV?=
 =?us-ascii?Q?qcNzeSoAmRlmigW+FiMyVAlMzaFYlpU66BS90omiOzBChUgR2NzOls4tXXCB?=
 =?us-ascii?Q?4PbZTV3rlRTInhvcWLwAg+3I8dB042PeA9hNl/IU6wcImsyhWWQUG/kvsCsh?=
 =?us-ascii?Q?5vesfhu1CllicIf7fEjZQLcWk4SOvlTwgZPUROxvAJOM2lO3LRBwh7D2rdD1?=
 =?us-ascii?Q?98roVJ2G4VxjkMWpb1XJTX9bkgHS0Z7hRgdQWyBuCw9m//bs8A+Hboskcx/t?=
 =?us-ascii?Q?vzhN+/plcQDmZMfbp7YqqL8hFjdat0yd9BLQbwhGm/HuEi6uwOncnvfaDTsZ?=
 =?us-ascii?Q?ImRFii9ZdzGDmDqKpWWVbNPRiwxPwTMBsniZ8DBef87AI1FxwQokDsxF9sHI?=
 =?us-ascii?Q?H3SgYF/sOEIDxrcB1k4O7vfN9xej/Hvj4152WPyhxlrs8TG8N/MbRnHI21hS?=
 =?us-ascii?Q?klD0J6Jm8qnkVYha+aCdz7v8zUjvC7MDetVfTU0SqsXEEOuNsUbFKnWqh284?=
 =?us-ascii?Q?5kn2GAjY+wdiRPIZYFhyZoa1UKSO6Oc4kUUGyyJa3RbzjDxvnlBEHyTfrG7p?=
 =?us-ascii?Q?8poYB4AOGDfDcOIaIsHVPegQUH7s2k4Z5VLJNoRxC6PMJEwe56i/LyFhAKTZ?=
 =?us-ascii?Q?+IBHPu6NR8J+JbV5qisfy9EmU22KFnj7REX8dyz9QuCao6/D8xskC0RYjJke?=
 =?us-ascii?Q?SmCjhQBMJ028lEGo+w8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?fpM+90P9hMFFytZW8CZfP3n8/wMno2wWm2YLf1D0e03YkN7yx+6Vk9WYO8+w?=
 =?us-ascii?Q?OrUnEWn1ohlbbyPycWF/cZrJKg7DX6nMiiySCRVV7GeDflLDUn6C8oc+j9n6?=
 =?us-ascii?Q?HTouPDcL1Ygtkr9TAXNsWcHRSDp1WjPM3QdlHuCApHFeFFBYkend/TZ5y3KA?=
 =?us-ascii?Q?FWjJ6dcDyyHiZdE8t35lOamEezBNuWSHgSqwFPQL5Y9aRtrBq4ZIyESI2d0K?=
 =?us-ascii?Q?TNsXpXfHVWlt1c/7OqvelZDLHaxnkqKP7J+fZ69PVWvSdB2hMoqlC3OaT9Lz?=
 =?us-ascii?Q?DfXzSJIB0NsuqbfMaHI4cdFLLoPEHSu4Yq/mf3bevwwQTXywDvNQAHyacOYN?=
 =?us-ascii?Q?DFCdSWmIlirncxcRrzJWfSbhsrQheArzXCudHyxQwHFJTHWBQgQ/UX5hUbIP?=
 =?us-ascii?Q?8aVSOb9ZwuiOcSEwO5k3VLenr0Kupv7VmpO72iorhm/CUKN6zgkxgk+W2rmG?=
 =?us-ascii?Q?p4YORL3o7vOL5kIGE7T9D/rNmWQb+hLHPD/VCpcl4E8+7ZRzDvmrsd4gbSVW?=
 =?us-ascii?Q?BCP4a6eyZMNgWaQwNkMkn/8/AxBn1KhU12gVulkNzt1W9xETxVyt6lQm+fBq?=
 =?us-ascii?Q?pL7IMbBjlOkf6nzLTXHBSI8GnEN1XytUWrfWAAbdONbLytsgVNKq+8eRREx/?=
 =?us-ascii?Q?i4b3U07G0glZy/uVlpSxStK6uT0apR/lYVDiTMt9sD3gOqLkV6StVpCTtsk5?=
 =?us-ascii?Q?vhoYZII0dKe9JJrTXdZI72fTjH/95thQkh9dHHQ8gTvPTL4JKP7wTgir7JEo?=
 =?us-ascii?Q?O313xw8N5SasH1lbPdoCJgH7y3rZevf7xJifUpBeHMbZXMGj6xW3Rv4800lB?=
 =?us-ascii?Q?OSJCt9RyTHnlJKDHD6nhQWoPPNt1TAuvrmbEbKynzWYi2dCmgkruMeN1Ju8P?=
 =?us-ascii?Q?K9gJ1JaU6c/QYtm2D0MhD2qSuL19Lr19gquIl8NTT5y0c0p9w+h3hIcsPMJE?=
 =?us-ascii?Q?YRQptKI1XyE0J0R2XW6czNTZVqeCoaF6At6eGgGYb5ItF+rc+oVsZlmklGz8?=
 =?us-ascii?Q?0PEqq48skyNMw7/X/aqEYz8bG9PzBZMgau9EtBwCTw+0lzmJK5L+YhqwFAfU?=
 =?us-ascii?Q?iwbWpQghCHkHlOD9J2YAVOsL9i3tBNL33os9Bb4em45ScW0DMAf/4wDaQZ+Q?=
 =?us-ascii?Q?Be2UjXXOLq/u5ulHwmJMKTUrnIVH1eYKF+l47CfDXWjneQ/3EKE/gnsz2/ht?=
 =?us-ascii?Q?nun1LgDEh66L/TFFpuSaw2fxPNCdKHkIFmmazKWpCIjCKRaS5aLLgWxXOYVA?=
 =?us-ascii?Q?tHtHPqqPemdEV2nvCIlEqNJXw4a3ybk4Z4TVIfgLySEDFD8MNgD1vT0GwoII?=
 =?us-ascii?Q?7XdhV8BPhPh027f0mif1eIB6ujQoTe9lhGV1pmEljjzOErA2Fapa914svFAa?=
 =?us-ascii?Q?GEgPVQ6pKdxTxb5fWfO3mUSFwtYa3Vq5m44RivtzavJmXAjedSgvvV6PuzKH?=
 =?us-ascii?Q?TsVd+9Wlc12gJKH2TitqzuIB7JtLrsAT82Z0L9Ha9xBowpEGazHHXynoQep2?=
 =?us-ascii?Q?6zonLpXE0ehxCNNuUDKr3GR81hE+o7X5jJ5fXF+nQ7Nv48FazHCUxvaDA//O?=
 =?us-ascii?Q?NJ+WQUjivIqyDPaC1KRjghakwjGQbURwD/WTJv1tMLULYKB3Z57JYeS8mFvY?=
 =?us-ascii?Q?bmmUK/DJRSpT6pxTHv3gCCQRvFC2JqPI9xZWQnoCK6X6DGQnRNXL7/yc3Spf?=
 =?us-ascii?Q?FnMhlHoiKrh5frLCpsuA+ovkrCcICwBTz9rDO+n2Bu2CHspv07T6sspaRCiD?=
 =?us-ascii?Q?OQF65bXmrA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: c4DIC/N4Cg3jp+E/AeW7zj0GYL416DFOiPuTG4owhgIWS6PdTCfL74jS2INiQl6t42cpuk3PYOrcYEYBl4VtcXNcKaTi7aY/HfTcE1wG2lriWO4ECJGanhXrtrrFDw27eYwhNJZjb+i0ERi7y5VSxx+Kkpyl+P+AILVzOmjhLeoPGEHYGto922+DoZKSgDS0DG3WIyJiSLrifd60Jz3uaCiKpnyawHjgWt3m5X2w4bRgq4s1tYZr1bDgIXYCMQi1MaFfzQ8BGW7cfF9LHOMoBO2CPwtt24wUNBBQQNwvc29vL7Slnff8c/9vJmZNFHwHTLONzJkcAcut1/1GBcTS7x7ZHnBBBZBu20zYp+iwDg989gPkMnz5Rls2qj8Qpks4zgezPzIqQo5LbJHO8j3yQvAjzAQQrzJuVsU6yaU+YNHsLzdvGLCQcuycGbvfq5Ghwk2NtCy3uzrpaPV50H4YyiH6nE5lnDG8HGNiuY+PXUgtegM8QLr718yZS6aiAEH/t0wMQr/Ho9kTqEfXE5pFM56o45QmVktQd6/Z232IThric2IkWff26MBkjNWXStNCB8CcvwcXxWF+fGJcF5fzvTdr8+sLhld3P9artbUjsjY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fb5e4d28-d213-4cb8-31a1-08de57cc3603
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 02:32:52.6322
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /eOj4hgflZjnsixFyyZI0sfUjEqTl81HPfTUaFeeM8JblxVJeaCKv2cDf0hhQwaFJj1QJuofEAkS1NnC+F8Uzg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR10MB6470
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-20_01,2026-01-19_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 phishscore=0 mlxlogscore=919 mlxscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601200020
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIwMDAyMCBTYWx0ZWRfX13d8j37mMrio
 2DWOLrHhO7wbeOB+yy0vjhOSxDma/aSa+wb38KI1LaQDc4nr/V8iuiMGrInNbQJYyfxATKQxmga
 DG+CgJOnoR273XD4V0CJ43wwqhjkWS32ZY2Tn8mp0wrxfkRfsrpkYVD70vECRBCGLZdvXSkhZtY
 5KbZlRUxS0P+Mozp2NAsOBXjOBf1d+wYtqc4DLuKv6EymFeLOjSb298n5IsZv2Y7oss4NKHBFsv
 kf95bybU2uxjd2f+OA+ED9Qp4noKAzlh1I2Gdk45lt05SnRSeblmurXPjpGLfi1+sAXoFPudkY+
 pJq2NHWwNRvTJQb7yQoqMYtrNn601gN+s3LpQwvSYbh9U52CjpP4BWLCwSvqCzMAVnkAIxPoS2T
 VO6ItDqfUELRojXjt9vE1eiWykZv+X0i0OCWDifvDlIuC5yq0ek8LRRtO6Oe6RWM8q4TzzEPgj+
 qFiBOWN7IewFTwjDRZZ9slltxUoZTbZd5vFuvtMU=
X-Authority-Analysis: v=2.4 cv=de6NHHXe c=1 sm=1 tr=0 ts=696ee975 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=u1qovP0KQFmDFdSvR1oA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12109
X-Proofpoint-ORIG-GUID: grcBseRyVw3gGOjjsqyeJEa-YoGHU3mE
X-Proofpoint-GUID: grcBseRyVw3gGOjjsqyeJEa-YoGHU3mE
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=VkjKgvSg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Q7FHoR3t;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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

On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Extend struct partial_context so it can return a list of slabs from the
> partial list with the sum of free objects in them within the requested
> min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 264 insertions(+), 20 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 9bea8a65e510..dce80463f92c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -246,6 +246,9 @@ struct partial_context {
>  	gfp_t flags;
>  	unsigned int orig_size;
>  	void *object;
> +	unsigned int min_objects;
> +	unsigned int max_objects;
> +	struct list_head slabs;
>  };
>  
>  static inline bool kmem_cache_debug(struct kmem_cache *s)
> @@ -2663,8 +2666,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>  	if (!to_fill)
>  		return 0;
>  
> -	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
> -					 &sheaf->objects[sheaf->size]);
> +	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
> +			to_fill, to_fill);

nit: perhaps handling min and max separately is unnecessary
if it's always min == max? we could have simply one 'count' or 'size'?

Otherwise LGTM!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW7pSzVPvLLbQGxn%40hyeyoo.
