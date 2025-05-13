Return-Path: <kasan-dev+bncBAABBIFFRLAQMGQEXI6B6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56335AB4872
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 02:30:26 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-6049e1c6629sf4455951eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 17:30:26 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1747096224; cv=pass;
        d=google.com; s=arc-20240605;
        b=SbnUiba/vHnK1unCxfOjogaFg1df3jVoGkhg4W2U6PIhkXMtJ1nlKKkonaTKn/QVmT
         XLlWhnPKUrMaUlY5PTIgcO2mTJfzJpI5wiAWCjBvNxX3tZM7gHb19Eeg+P90f5O18Tp6
         4eZX9lRQJBtsGWWBgq317eFOD7EJ4gg0Z8xe+TL5H0JhYV4LfJiAAcessTONA5W4rhUe
         jNRfOGXwqS9K3b44jIcfMylTdNznkX5Otkz77goD3oCosrIF8co4bqYcR4vze1KG6mz6
         017tSOCIsc0va/PajehMUreAQnYENgyj7jzbGfX/1rsTO1HJegMT8EajfCU/+NtlmISy
         D+hw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=IJV+LUvdT2a5aXHiga6Mv5LumcllfKrZ+Fhp2IRueo4=;
        fh=T45eD8L6I5L3lUg/k3kcS9i2mJ8m72yfAO1bff6gOik=;
        b=SBEAwJwnQABtaDnAYQf92YRYFVAkXwrhjmAeIcXPCJejHeIn5oh46g6JP2ND9fvluE
         48/EohcJ4QJ1Xp1Ia4dkkHHXZQYOpxr87vialjW74iAvUcSiBLmwVrANtMxLj+4g66ua
         39oPNQWf1OCzbKMFGIrgKii4RzUcYrBrmCBwzrcfh81P7XZWt3QS7NrUqOy5CumdgiGw
         HYpOmLLhIVFmC+8ZzxtH1tdmr9lyeZpdoo8/7XP2Pp/8Wq626iA38GOzSvyXEjlHyFsX
         XzwyvEBabkNJk+kgkEGD10sAjJEZJS1JPuZyl/K+v14xbeIc/QQ8FxtTl0Fk+iR9rpmX
         JZjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AlgujIEc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=K3Zj6Z58;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747096224; x=1747701024; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=IJV+LUvdT2a5aXHiga6Mv5LumcllfKrZ+Fhp2IRueo4=;
        b=cOlRgsDPlVY4gH65jKL3JqR9IwxjbAcfzwwK+rgXcMBElFtrWrltPVZZk7W5Ei+eSJ
         q0fJjn9z9nVVwOeQq9g7hQpqPBHGLaxaCe9OjOkA6Xqs9478bnucRzij6BwbZf/ztBZn
         3Ww0KeSEtftDnw/REYS/zVft0ikgfG/UPL9GItng6w0377YisVkhO7o4rIB1AZEs0HAz
         cvWxcN0+yTL1d5Shk7sNBI3ARPSBxUuh1l7fNgemiestdGwFxSBWNoe2M0V0iKFizrFg
         4cIg18kgyK9PEwcdOWFPJxmXts/IYIQC32HSXuI0Z7bklxdMzWPXGt5GSdkG0UfmwRnR
         YgHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747096224; x=1747701024;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IJV+LUvdT2a5aXHiga6Mv5LumcllfKrZ+Fhp2IRueo4=;
        b=h0/UR6bHchxPD3p6rUKv85m81N34L8Run6l5NLo/UuOFPjGyuJj0ubBgq3kU8xn7mC
         f+YPiygvdhhWgwn7I67B5sSdC5/qiIZaLtJrg2OGbDsu8j4K5dJlQT3OWzgnitiR2eDa
         mqCOt1LVB6grIScSAupSmOjyX3UvEa7gNlDaH9vJNvqnX5frZ/7XaSPJPEPQ2Ey+X8i+
         FfuGKXPaHzOPLoBajJmP3UTnXDFUsSq67vEm0rN2Y7ZubbZMJSsB8BARMS/lv6FlhSzE
         fmXBx/s+nvIvHrjv2YRjsaaXpt15mnvMDAbuoWyW3S1oHRP94Ygjkw3HU17jicK2RkPy
         36Uw==
X-Forwarded-Encrypted: i=3; AJvYcCUK8Anb0AxBkZfj9j0A9o5WRibFT5lxSyDUcfwoo6W33puzTE77DIFf0VIvB0XAXT/Gs1qAHg==@lfdr.de
X-Gm-Message-State: AOJu0Yxohzfy4/JUG9cfGAWugWetlJ9Ba76M0/77FzdrlOiUH1Ikd3T3
	8mWlcBQJYo6aA7eb/TB7CvzHu4R7V6KDC8qtNc4HmvR0KLUP43zg
X-Google-Smtp-Source: AGHT+IHwPhszUp3+F1fvrGF9+QjSA9wS48H5viAbjT83iR969OF+ImyojFFbSGzSG12LwxG9J6bbdQ==
X-Received: by 2002:a05:6870:2487:b0:2b3:55b3:e38 with SMTP id 586e51a60fabf-2dba4343dc8mr7904811fac.21.1747096224681;
        Mon, 12 May 2025 17:30:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFrePsykbJVUVfzb81UugVqWmxkotw26yxGFz4Z7EwlKQ==
Received: by 2002:a05:6871:6088:b0:2c2:586d:6480 with SMTP id
 586e51a60fabf-2db80644bf2ls1516180fac.2.-pod-prod-01-us; Mon, 12 May 2025
 17:30:24 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWmn2icHCgexs04QenwjdAd5APdBLnNHM+Vs6s9atam+QXd2iks0lNh9CCNc7yWC1YwXSrXm2S/DKA=@googlegroups.com
X-Received: by 2002:a05:6870:960d:b0:2d4:d07c:7cb6 with SMTP id 586e51a60fabf-2dba4204e0fmr8690495fac.1.1747096223984;
        Mon, 12 May 2025 17:30:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747096223; cv=pass;
        d=google.com; s=arc-20240605;
        b=DgOgsyfX8+miffd8aJDtj3a7Z1YgE89+Bm9jqiYAUccMW+ql1L4RCZc+2zNPc5iUPj
         Qy+R0rBTLVWvpHbSklquQIYtkxI1CQlkuneZd85yLbUmKLHUvRiL6Cx8v6XovbqDZljo
         HoNAHaFK6/mExSLbPnk/inAOszubQwaHYzxPLoSvLUlcVj0qw4qTCmWnBJvcmLiNSAU5
         3TiSIp2eDWKY3wvC0JO13AqjqiyEuZ93Izg7YwD00QEZhuVjUkwxG2TQUCYEUW9NSwG2
         EvBf9oB7UHcci7Ko4Gy4811mKW3o6XE+oyzw486tSfzxTa7iLGK+RcM8w4wj7bQm+6AY
         hZ6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=5nu07v2jjWQnv6aeX9byVkSi85cE+spiyMYRTa5kogQ=;
        fh=vZDVMGuAHVstcoxpR37bje4wUcDtpbOa5BfyS9r5Fok=;
        b=X7JBMpDncnBhWVD2pY6KRNzVP5jtY4yKaq8wWUohr1eRG5gfwcgCTza+aNcfx7TnJu
         uOzcqwU4yPxIxoNLrF4cJibSJQgUAj0TEQfxrjxSini6AXJY4Cg1XU08ofafk/O5ADM5
         ye7xvRn/nQNnD/1rg3FE5aQDAw9f5+Q60ia1Y1QZPMAgXap4OnLPWTkaEfbPeHIX6DEz
         bjEurDVx+qyiL/VgxHwjxt4M6DOjMwpgv+fz4yVyudpU2byBpp2Fzkdl4KSoufIb4q8Q
         +xngLBYNrWE0w62SERJ6WiCYhaomqg8T0nbRVOMJ3YaxjTUPCQzccteCIR73Owf7M2iw
         GSdQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AlgujIEc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=K3Zj6Z58;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2dba0a86ecesi46097fac.4.2025.05.12.17.30.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 May 2025 17:30:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54CK6sT8017916;
	Tue, 13 May 2025 00:30:21 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 46j1663r4v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 May 2025 00:30:21 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 54D0G1JU001944;
	Tue, 13 May 2025 00:30:20 GMT
Received: from bl2pr02cu003.outbound.protection.outlook.com (mail-eastusazlp17010007.outbound.protection.outlook.com [40.93.11.7])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 46hw8ehx82-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 May 2025 00:30:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=C71fVK36xILMr6lsnW0ANkqR6wLxCLnLWqR12U7SRYGAr4KxK2elU+v7JsjdyYr64yrZ070Z8t8VbbT4CEqtO7fSwMWwNfXXYzSAOllDggm9/4FpeKNYrCPK9fKUJEhEUhizjQDGVAbDzC7sSbCEXLF2XFYwkVqrvgBTCGnwkWdqy9NiwFBbhYdEDX856PXa9GRi3N6+qD01IPPQXraeLBPtq9XCQgEMUiXPAO/YpcFDDfQDT6zGevqGF07W7FFszPi2qlDoyBU9Qk7YNQ/kuP6/zXPwFWrRTcuRSBMLVJkThp1h6hIeDy4whJnVk/VILaMBU3giSIw7zjw6REt4Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5nu07v2jjWQnv6aeX9byVkSi85cE+spiyMYRTa5kogQ=;
 b=etvA/EJa+S4O7vgS5P2XzbQ1bPG4a333MoP+5AXRcVhkYgL5DxcX/lVs1lOB49lZBvbMcuhtcCS0+0z3Hbl2ABmj6RPKmK3Y98/voghXZc/JxxtfdUPjIrL6SFkg4N4wVHKjvuPQuu4rs+1y2c7/51zy0ZwTePxJFd5Afb0VqQ76sIekFzuLwOUNLTQVePaYSAeM1C26zEwB1hjQhqp6Bkm2vR5isoz65SnwNQcpW9HHHWvpuB8UIbgrhWQTXfdkd46in9ZONq6Xo/8k9VUP6zKyzxhiTEH4lY8XgIvDFkNVPCtIpwNTlPnzN140KkhyO7rcAjOtQQ5IBcJiZ6pnhg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA4PR10MB8399.namprd10.prod.outlook.com (2603:10b6:208:56b::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8699.25; Tue, 13 May
 2025 00:30:16 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%4]) with mapi id 15.20.8722.027; Tue, 13 May 2025
 00:30:16 +0000
Date: Tue, 13 May 2025 09:30:06 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v7 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aCKSjnQdzaRvgZzo@harry>
References: <cover.1747059374.git.agordeev@linux.ibm.com>
 <c8eeeb146382bcadabce5b5dcf92e6176ba4fb04.1747059374.git.agordeev@linux.ibm.com>
 <aCIUz3_9WoSFH9Hp@harry>
 <aCIiYgeQcvO+VQzy@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aCIiYgeQcvO+VQzy@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
X-ClientProxiedBy: SEWP216CA0037.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b5::17) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA4PR10MB8399:EE_
X-MS-Office365-Filtering-Correlation-Id: b40bc458-72e2-4a94-ef96-08dd91b554dd
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?csw1Z1mAJLWdzja6AJ/wlyZ9jU16v/L7OHVYoInHs/n6nivfgZydqQm1glBr?=
 =?us-ascii?Q?RusjEtCoAmJRJ5kB+4dndRyf+Q+V4+Ywrs2L5h+O740tZntCF2Vi2yXHw0tz?=
 =?us-ascii?Q?sUCIcgep8hLX03JsrF7RF2XObc7qoB/yVVBMwJX0orlUiAEmKKcxmHOc9z8K?=
 =?us-ascii?Q?mTzfnLTknN8iw7bSD/tep67JmPpctOro7fHpVv7V1o3v3qogTvzR1sR1m3F3?=
 =?us-ascii?Q?KLQa8AbB/AZx04HUyQBQd7Ni/WwSZYPlUOTQdSurKd2JOpqM8W0+CpQu+vzF?=
 =?us-ascii?Q?N/UTeho4wO3NQXoKWeDvbNsngP75CeIg2/jPDTeeWB3OOrRn9YyZYpsU3RIE?=
 =?us-ascii?Q?td9IGM9ZtNd0lNC6kCbK0QMOdhU/U3wABBhNQk3vsoq5n2o0/6Hr5a1on/nF?=
 =?us-ascii?Q?mL3lxqkNIQtKbsHf+FjjXVokhRBXVNtAqrwK5LikwnrUZJzCi8W9D8RDqyYg?=
 =?us-ascii?Q?NgK+m4GrRRouCKZE1EjnrG030avCYfQm/FmWHFMGhJasqsZLkW3NFqoIYVrE?=
 =?us-ascii?Q?zPQyirMzXt5YOw6da+0WqV6qamVmHSSJ+Riu3tBLxksGpBe9jvqNzUCXAp4s?=
 =?us-ascii?Q?VeMcuAVadZori6nxdEdL76RQCib6GD0STqSIdZ2l47nWXZ/dFGH8QufnXArU?=
 =?us-ascii?Q?Q/jXVHf51W2QKknNdKXvvDDjaiousafkRRKj8keh/v49x4mY8fDpqWpI20DE?=
 =?us-ascii?Q?9rU/EyJDSkD7bvb1K2Jx8p6+XAeN4IggRz9+7YpBRK02Dnsmjk+e0MLcGi1+?=
 =?us-ascii?Q?NA97fYpO0mP0nJ8yCGMhd1AstF2093Q/r8D5JpkBi5uO2N4HIQI8lzggmqfj?=
 =?us-ascii?Q?fmLx88+rrN3ANGSxEvhAIAuvp4IwKCkhxGf8QCeQY86V9lg2ma8ZSarIbAZT?=
 =?us-ascii?Q?r01Nt2mwNFZFtHDadedemCZWzPdGTR3OpBMhGjLDt3tzb/c9KKk5t9NjP+kN?=
 =?us-ascii?Q?g6bw4i8EBtCb4DLphwXS1IE+C42SfODGwZVsKK+OUw+DOiOfJOQrfGcWWB6S?=
 =?us-ascii?Q?narUzlTnSQ+bhVa87437DI5ygAR1h9GJXIGOgzESQuGri2d11OlgpKdOH960?=
 =?us-ascii?Q?NU5Ch+U2pA/VsGcCfee8peLdhonz1TnE1/rN8/pPfC1vpOfVvOymkOndO53l?=
 =?us-ascii?Q?LFhTWTdYMk3ELH+rQfih4IZdcnHi7CvfYj3UvXsNZRqHFrIx9z9OMPoHlJmp?=
 =?us-ascii?Q?Z4SiyJOcIWx75mUO/jZ4spPQTaPmOLRXXYNQEuIByIaLfEXEwga6lUj1/zwQ?=
 =?us-ascii?Q?lc8f7xHFY5Tu6CWMUX9bytlL4oGq15XxCIpT66v+0i5ey252XeM5eyhwiit9?=
 =?us-ascii?Q?JR9q6kN/wrMufaueZwjSJxXdq07fbFkhRcUYQOXDUMvObDb2ri9eIG8Raq1T?=
 =?us-ascii?Q?TK15tSh+ydH2yKhwfdCxWC1K+TjWAnzITDeySBJUNTeQARIFFFVrewupgneg?=
 =?us-ascii?Q?AlzWxI6fglg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?vToVpjLPi/ZZ3ezgEblZRifR2HbCwvLndUBFP7obsgP2ojoUHmeqWotbesc6?=
 =?us-ascii?Q?+M25DJBI6wV0DSr0St0CRejZ1LThyLUcaZtBvenrrtvd/SvK5laSNDmcaYy8?=
 =?us-ascii?Q?RNS3oRsSmNSCC/RahTGr8nNZEuCl0/UssS6mdlW0v+nUKAwtsE4eQ9KXiK9l?=
 =?us-ascii?Q?PbIF48QrAF4PFlCdYVznIUaEsU72GGHTUs7dJkcMyRBQbt8alK64jxns1A16?=
 =?us-ascii?Q?LvB7o2ItTD+RaF38D6w2oCRLltFg1lqNJ6Y3wYQ3V/k1/M8OPwresNUWrhFB?=
 =?us-ascii?Q?9vVwpjP027OGY/b9tb1CP1uOE9+i8RaRkNq6xl2XjiDHYgrtDQ/VI6fH2rdo?=
 =?us-ascii?Q?FWL+1Idld2e6eJiQKz99nv774uSrTZpOoI960PAGrA37Xmn64Ui+eIsjF/Ql?=
 =?us-ascii?Q?A3qJ/dJPQtPoonmpdYVMXIkekUN0Vqfbb+yrAe4w3uWE5aNkRpxsvi1UdEb3?=
 =?us-ascii?Q?BLB4mfK4fhxq+F+3s1f4X0JL2108NZ8iSG4lMnWXR8NwZv1bV9g2P4oQZ0Dy?=
 =?us-ascii?Q?WpRDpZ/vN4WM/GQYYYQblY6h8g0xK5OSXAk+xTgzU9TXR5oxtRps5r7XrAwX?=
 =?us-ascii?Q?58hvVf7sg9Ub/nofIskJKuCzHsH40bZHES+BoFSuLFegAzmhCBXLvpHqX9w4?=
 =?us-ascii?Q?Y9it/UUXbmydcT2TkfBmgTnaniwgLcBDXbTrjv/tQxP3UzUHRK436s2gq3eR?=
 =?us-ascii?Q?mk00p2r4NfL/O+RSIYfDFEuLD+QPKVaCFLMnNB0owyv+geylWDnes97Y8FKb?=
 =?us-ascii?Q?mEa3HqM2VEl0bygg9Hjg9CjmgIi2j/K3MhMA2esGZkhXk8snFRDM48p9Jk+C?=
 =?us-ascii?Q?yyx2fLMc9Dkf11jAfMot+m34fUZSDRe/HjtZ5gBOhV0y6jeW78A/CNOIYief?=
 =?us-ascii?Q?TXzSwQH/VvOPhudE+9wXzhIGAqDly7WWSd/PMnwY+ogoXX4W+pyMSe6hHczY?=
 =?us-ascii?Q?RPEsXxCtLB2JpCfffy6hLF9hKvNZEmWCIOXxPrL2yhlUbYkDsoKYzN19qRYZ?=
 =?us-ascii?Q?JRgSBf3l6o1tE8Cxfz8El9nPuyAy7yQAFZeb0F7YCwXSddOkrzjbSlS8rk2V?=
 =?us-ascii?Q?jd0yLn5upocfsq9AjPmhe+8I4oiptzmmWpVW1RUd2kox6tmHLk4UMtXRWlNU?=
 =?us-ascii?Q?iJNnR68/r7LKSAANCgOC1Hew3JOXsyjoFmCeBx0n0WMX2J7EQLkfanxiFyp7?=
 =?us-ascii?Q?kR7Cq//F0iJf8/sBaPCarOqjNu7SPz0+DIdnKk52Af5rK6XfFKmWRvl4y9EL?=
 =?us-ascii?Q?rFNPQ3BxOaFioDYMMQvwgMzeOQoCrYmGP2kObJsiU8kSEJX095Ti1W26iJSs?=
 =?us-ascii?Q?4Isb0mUQlIf2+pugKEcgLYfRBCrI6phyUrTKdKDOFwQN6AZljmJqVhdp9g8/?=
 =?us-ascii?Q?8Z3/a4Gh9Mn8/4QhAAFa6w7lL8C9/XewYIVU65KwXajWSX6Y17rCzbNSH66Y?=
 =?us-ascii?Q?ItSQOJbk3bYT/i8luGVgxMd//OlF+aTU4ZYHmYRNcfh9ollZH+BK9wpcOGf5?=
 =?us-ascii?Q?7ozh2L135Vrme68YqcV56GjGoS7gr6yETNAdUBO7LD74nNUKSrsk1ClbU+GL?=
 =?us-ascii?Q?aDj1apxfduRpAg8S7lZW5YwTvs5tycc3Rt8sdXDc?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: liQihTcW3Sd2J5+X81Z6/Y8FtttGzDkvtYrC4Tzbl0Pir05D9z+GjucVUOfb2RsbE4CsIuS5ncG1SSrbo5BjP1U5bjRwjlU61AUTyKLooxppEIkZHRWlqWmFZje+MRmZTSi9z96yMWkQwVHFbUPtCm/ln518SH/pkcbLNztaaiUMxh1GSskwTktCGefLnuMU4JDPGSFcGmxSfMCB5mlhUvN8pONvW7bFm+G5PaePQDVpJyTqYiZ6vPDXZf+G+593W9vnpOCdaEuqeJ8+9rSoeyqIgJF+h3yWQ7Uig107jmeqVW/riPNGgXnqULnBnVeYW844DChbiD/bP7ojHYxgB/FB+xYU08ji57eUqpiu6RM/aKUZXkWn7+fdFXIkn1tgf+Vw51sDcws/t+Ru+4N3T6UyZ1Oloo/WXM7scKnLimwLNxK2od6w/rRdWChIBoBaKwWcMdPTR0aw2OWgs8Nmcr56d+eKIw/QIlUVp1Kh6kXyVfG5HXvVnthyMn4Zu0Dv5wNwA6hURGN5epon9H2GSVpf2Kpdkj0QoOaDT9dzwm5dvEWAsrU3Snc3YrI4+h7tqTxFQxzPuLmWyw/rI5KAB6WSpQg3Nd/bz3O/rsdpFBo=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b40bc458-72e2-4a94-ef96-08dd91b554dd
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 May 2025 00:30:15.9642
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hM3/QBdYXajUSVPpw+xxEdmnI48kzN6fIQndvQDxwpjG+dG54nalPg7Omh/7oo6Q45i0lG6+Z25VEx6PykMwDA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA4PR10MB8399
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-12_07,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 adultscore=0 bulkscore=0 mlxlogscore=982 mlxscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2504070000
 definitions=main-2505130002
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEzMDAwMiBTYWx0ZWRfX94dcU3WzLesK shlTeLyWydrDvwXsN0y6s/TplCck09iqfU7X2PUGi9YMepqS3qgt3wU+WyhXL912VlipMYx+vG2 vhWliWO1OVnu7TSx37r02NBanpYwF84CopsrLxzySh0HU6XlvJShgWyzvej4DEwI5nOQK7QqLqy
 jxdFskDIPvEHt8C4NNh3Bba062AKUZk0PwTpiiKpbkPd3fpQxiTC5FqFKGu2z55Rj37QjYOOpS/ CbmnfZQf6xtiMvcVRVDywjgvDkzzUFFpAzmC4PE5tZD9SQtDVdPxxEGmxIHsIxFLTzVBkowQZFn r/olV3dZIx1Sq34AUOuwBAoWQWUZX3dW3EgS+gf9xUmDnnzMzNuMFApq10MMeLw/qC1sFpJaI7G
 fWbE20jeJdmhY8AtH4S9OOwOx7YI4leG0nrTUteQdZXrjdtCs3g132Xy9G8NCkuOVHyViKPx
X-Authority-Analysis: v=2.4 cv=VMDdn8PX c=1 sm=1 tr=0 ts=6822929d b=1 cx=c_pps a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19
 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=8spYyqAcjxGn2WIhPwQA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13185
X-Proofpoint-ORIG-GUID: H3z0oSeVPG_fqM_8cuaS6SmfrBW9R4ek
X-Proofpoint-GUID: H3z0oSeVPG_fqM_8cuaS6SmfrBW9R4ek
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=AlgujIEc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=K3Zj6Z58;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, May 12, 2025 at 06:31:30PM +0200, Alexander Gordeev wrote:
> On Tue, May 13, 2025 at 12:33:35AM +0900, Harry Yoo wrote:
> > Thanks for the update, but I don't think nr_populated is sufficient
> > here. If nr_populated in the last iteration is smaller than its value
> > in any previous iteration, it could lead to a memory leak.
> > 
> > That's why I suggested (PAGE_SIZE / sizeof(data.pages[0])).
> > ...but on second thought maybe touching the whole array is not
> > efficient either.
> 
> Yes, I did not like it and wanted to limit the number of pages,
> but did not realize that using nr_populated still could produce
> leaks. In addition I could simply do:
> 
> 	max_populted = max(max_populted, nr_populated);
> 	...
> 	free_pages_bulk(data.pages, max_populated);

Yeah that could work, but given that it already confused you,
I think we should focus on fixing the bug and defer further
improvements later, since it will be backported to -stable.

> > If this ends up making things complicated probably we should just
> > merge v6 instead (v6 looks good)? micro-optimizing vmalloc shadow memory
> > population doesn't seem worth it if it comes at the cost of complexity :)
> 
> v6 is okay, except that in v7 I use break instead of return:
> 
> 	ret = apply_to_page_range(...);
> 	if (ret)
> 		break;
> 
> and as result can call the final:
> 
> 	free_page((unsigned long)data.pages);

Uh, I didn't realize that while reviewing.

I think at this stage (-rc6) Andrew will prefer a fixup patch on top of
v6. I think this [1] could fix it, but could you please verify it's
correct and send a fixup patch (as a reply to v6)?

[1] https://lore.kernel.org/mm-commits/aCKJYHPL_3xAewUB@hyeyoo

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aCKSjnQdzaRvgZzo%40harry.
