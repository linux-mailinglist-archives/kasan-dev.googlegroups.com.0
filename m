Return-Path: <kasan-dev+bncBCJNVUGE34MBBK5NUO2QMGQEXOLZYXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C046941175
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 14:03:57 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e0ba463c970sf705279276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 05:03:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1722341036; cv=pass;
        d=google.com; s=arc-20160816;
        b=pz+XeRTe29laRmbv9oKWCiymX9BjlpL/3LQFjDyqgD4D8XjzbjMAu6C7Ila2irehPp
         YgKvdNwSUhGoQGfwA5Q+FIeV0/bxxpFaXhCH6kSrnpI/+qC4mPFQe1lro7HNV5Coo0Bj
         4V0KX+DCXmPWXGaJr+mldwgMLFp/8Eph5V7Kh0d3HDEmhmqGbyX5ktVHHXTSsOD7VsSm
         3YXKMXM7SAP7UmdkTtcrwE4j57eXTkz+vtpSN5s+pNQhg7hDokyF7g5xOK3usYIMtaUu
         jaGjiw7y7E9ShySVz7O78EixME+QA8EJ0cEa5fF+OPNkOfg6vXqupjSjyTNjYgUfEnqN
         YSew==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=kx7xmwwS3jBerinF2Hu8wQNWRPYvPuhkk0NlvUFYWxc=;
        fh=wJvSDye/U1Tjf8zcxSKuWCuK0er1Fpy5OdliwbqmUY4=;
        b=ieZsWeZ4CmHaXaiogfCbwFx5hlZMsEWy8x9pIbnPyN4v70YY7Zq6iDETKxmvg84uV5
         0RKagRQybfKpdUejal8MnzFZRde40dNNoQ3dwmIRMTO+LQjT2+eBs3E2PgTkabzug3nC
         QlVX9YDJLm3NWOU/xknEFRTZjFR0ifYxlDoLtKtyjE36FJilrQshq2jC+X+S/+6Z8iPV
         rBNmsjwXnJqWAdqOkBYGUgBKtIgAllwOcTx3MZjankV2+sFZ7NJ6JaQeDr74ZLNuZUHq
         Wj7sxM78KUkgATOnHRLO9t/xKs3+BgUWzfJaqDZt2z8udUhrQq3OXlzoa1d7tz9veF8e
         tdoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2021-q4 header.b=YvjOxh6Q;
       arc=pass (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass fromdomain=meta.com);
       spf=pass (google.com: domain of prvs=3941bde6b2=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=3941bde6b2=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722341036; x=1722945836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kx7xmwwS3jBerinF2Hu8wQNWRPYvPuhkk0NlvUFYWxc=;
        b=lwQSzrNUE2ZbOlzCHjgBozebxZmqRyTrq7c0+6fFBQCRusPQsiRue8dS8dH+gjlMW5
         tFiGoteC1CSuez/w3yD89sOmnPqRUyCh/mVxthmChXI9rXPpZdmJRWlk85hbvh+jSGc/
         BvY45k1deSE5VC62LfonrUSA7ZXixpC7HdglmLb77+X7/NMrGkxOsPGCQnXC2EJ261+h
         T7p+uKscmdInslbXFV4VoBjXeXj81gE8ldt8gVgyy1vvr7h6Hds54WiAzKVi6EP4SGMB
         t2jgOGAVazL8LKhNgh6e/05G9Xt2o9GTqTt0IpwjmEP/2EL4rAGyCouWnyQXawzSyykN
         8anw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722341036; x=1722945836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kx7xmwwS3jBerinF2Hu8wQNWRPYvPuhkk0NlvUFYWxc=;
        b=giKgd/dyycf1eB5m/yUq7uDdZtnjXg+Kyxabqpo0kblq+CtnxDd456epJRl8PqbHrJ
         /WFEB55FqM0WhI1JCJrVMKVajWolIQKV/7trx08olD1lkTF7y2+2ysWsvOWS1RyzqL67
         3Leb7qz8wQuVceucARU8GctRdVw/5O9J+Oki18TzDPXN3A4kzbu601Av7pGfo6G2KAQe
         Fy+l+54Jsg2zjHzOd6nbjbuHH2hs+tZlExo8/h4SYvED2nyZkEX9/bwSXNndAa9qKqRJ
         BVrJIYPN2sv/IW9Cua0hNdRQuesYhxMSensBGq9Oc4GE4XuBnXi/jHL9aYuVniopUvoR
         ge+g==
X-Forwarded-Encrypted: i=3; AJvYcCUUcTNhEr82jXpXaRf62ROTsTrX3zOiYKxPMftIg0YIE6qxUn8zHosyIFIl3ITMhMB4v1zWt2n2OFN1Bl4IXnJVEgwKPL2kFg==
X-Gm-Message-State: AOJu0YyRgBran49XSqiFWf68iXNDcFNV9h+3Ny5jnqDyIwcEP+Me4Dxc
	DugBE5pbBrmYZmZQnBcRL1k4u4a8OQveEiyhdVkyLk8iIS41rQGF
X-Google-Smtp-Source: AGHT+IFvmJy9PUhzAjcXBMgqe72AXKcbQGxzIS8352huk1niOGUi2djIMIdws74xNZI5YAL4GCi0eQ==
X-Received: by 2002:a25:9187:0:b0:dff:91e:56ed with SMTP id 3f1490d57ef6-e0b5449e17dmr11362887276.1.1722341035974;
        Tue, 30 Jul 2024 05:03:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:70f:b0:dfa:77ba:dc1f with SMTP id
 3f1490d57ef6-e0b2290d919ls8411890276.2.-pod-prod-06-us; Tue, 30 Jul 2024
 05:03:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUC0nueYIJtAb4/4sqVmsQnYCzqJuBk1TJBiiArCi8LNQ7rqx8GGpollkjeFxvp2xPy/JBTgtSwTgNFXIeaUijcHd8egR/l+dX/Cw==
X-Received: by 2002:a05:690c:3587:b0:646:5f95:9c7d with SMTP id 00721157ae682-67a0a135d8bmr100178487b3.36.1722341034873;
        Tue, 30 Jul 2024 05:03:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722341034; cv=pass;
        d=google.com; s=arc-20160816;
        b=x6vyVNxmtppUEO7VL8879Y2/Jxcjb3enBYAG6ZvwXsoJfWNkXe+vFrqz/Sgq7rwzve
         uqME6fDuNlOnw+ucrCDEkQXPm6QuAURG1hGd9WWUNa8ZsPgcx5+y0W7kAp8YqsGlfNCp
         58paLskPh0TBPvSaDJUfKN4FdcWDsbK/f68IazYZ0xIazJioHuIuTVoro2LmLRSGx9ci
         O9Xt1xkEszgBGrGxjmbxC5Bv7uMxniMfYLipLtk1h08INXjupiC1B7SiM3YHiTSEovWt
         I22lC6DTTM/Pf0a73fOg+eQCSways/7TLM1s8OTEQqZQkzNUYnrjf7FrLy+ddZzjFPLL
         qaCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=uFlWW77NdiD9akTZKY2wQTKEkDJ+sQrki6MeBorxxDU=;
        fh=ftCtwZuMmN5BFyU5hHcoCBR8KrxF+LXnZ2khBWjEiFM=;
        b=SSpfCb+x02w7VIgvXB5fzdPH921rHh5mCjSiKn9Penk7u2eUeUTwA3/WrEfwmxkb+A
         pDRePu8ev7jql748eMu/hdqfYyj2GuzdgzTwzLJrj7VnB+GWCQv638Ac+xnMBjq8mkBi
         yoqXs0Vm/TKRz16fckkxNoGZE61vxZai+HqjYbGMJmWUiOB3obeOfNUKPJGIjyW2+jQe
         G0/2y5Ezwlmfm8eqrlVTcpnUa7GC643YA6P0y+as0QB8VJTyHnzRejla+FRIaDJffocB
         R+MR51Hu5a0JWZtMCNtj4WZKYfhbz426BrvNMy10X4d/QAms4UkTNfL9l37d6rBHNBVH
         B2wA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2021-q4 header.b=YvjOxh6Q;
       arc=pass (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass fromdomain=meta.com);
       spf=pass (google.com: domain of prvs=3941bde6b2=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=3941bde6b2=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6756302689fsi6791967b3.0.2024.07.30.05.03.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jul 2024 05:03:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=3941bde6b2=clm@meta.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0001303.ppops.net [127.0.0.1])
	by m0001303.ppops.net (8.18.1.2/8.18.1.2) with ESMTP id 46UBjYLB017602;
	Tue, 30 Jul 2024 05:03:53 -0700
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11lp2169.outbound.protection.outlook.com [104.47.56.169])
	by m0001303.ppops.net (PPS) with ESMTPS id 40pnh837ty-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 30 Jul 2024 05:03:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=C+52BLSbJ8EyTWqli4Xauk01lCHfrwHOfGp19kHss+59WA4OF4lFtN9qfizXG+mfnZ0LdQlVTS6SSQwxrsAOiBjIIH5zmJy0f8RC9na+ZRWC62szwo4Ltk5xMmINNTYSxSU4o4kRNZe81MXG/97FRkZfzFt+7VPxMdCUh7wetjqBMlerW617s4o81oBoza9Q8YIlIFdQFqMJHrOTv2fUPzd1Q/80IN15Lm69TJZNDmMZIxxffFMP0IBJfVlgsKG18MuI0jTPYfdxMMqoqGVyEFcv0rLUCoDo7KBo2Y4BRxmS8RPazpzFVuOnP24kJAVAL6/q0V4Dnj+dnZRonSblXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uFlWW77NdiD9akTZKY2wQTKEkDJ+sQrki6MeBorxxDU=;
 b=zJrIqDmYSfN7QZCJCexgPHJw0TAtY5Mp5Ri0NgfQaArOXfVnAnRYEciWEAcvvbMx3cQ/5MuNgiG6xBPhnK6JOJ6LjVbmeelz+digGKH0GYMxUqaMo4kZTDdAQaiNwldwR95URr2Wn081OI5YF9eQzMqXfpZWko8Mh9p0r7aBASM7r8GakvxMMsApMK+urNVHuWGjj2rAwS4Lq3o6lkf45T46PU3T4KLr7EpYGdi8a9CNKpdD/q+U0HQeOESGwUYGXB5QgCG4U0gfsxjjy1IRs49d7A4tBhBKqmInbIpMB9arsaRsdqZ8M8XFMuXLmZloOskYamPl1lwPdq4K3n240w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=meta.com; dmarc=pass action=none header.from=meta.com;
 dkim=pass header.d=meta.com; arc=none
Received: from LV3PR15MB6455.namprd15.prod.outlook.com (2603:10b6:408:1ad::10)
 by CH3PR15MB6479.namprd15.prod.outlook.com (2603:10b6:610:1b5::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7807.28; Tue, 30 Jul
 2024 12:03:49 +0000
Received: from LV3PR15MB6455.namprd15.prod.outlook.com
 ([fe80::4f47:a1b2:2ff9:3af5]) by LV3PR15MB6455.namprd15.prod.outlook.com
 ([fe80::4f47:a1b2:2ff9:3af5%7]) with mapi id 15.20.7807.026; Tue, 30 Jul 2024
 12:03:49 +0000
Message-ID: <7a347d75-4df0-4591-b040-a832d3860a30@meta.com>
Date: Tue, 30 Jul 2024 08:03:36 -0400
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] mm,slub: do not call do_slab_free for kfence object
To: Vlastimil Babka <vbabka@suse.cz>, Rik van Riel <riel@surriel.com>
Cc: Pekka Enberg <penberg@kernel.org>, Christoph Lameter <cl@linux.com>,
        Andrew Morton <akpm@linux-foundation.org>, kernel-team@meta.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        David Rientjes <rientjes@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>, Jann Horn <jannh@google.com>
References: <20240729141928.4545a093@imladris.surriel.com>
 <044edc48-f597-46dd-8dc8-524697e50848@meta.com>
 <0d6e8252-de39-4414-b4e7-b6c22a427b0d@suse.cz>
Content-Language: en-US
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <0d6e8252-de39-4414-b4e7-b6c22a427b0d@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: BL1PR13CA0179.namprd13.prod.outlook.com
 (2603:10b6:208:2bd::34) To LV3PR15MB6455.namprd15.prod.outlook.com
 (2603:10b6:408:1ad::10)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR15MB6455:EE_|CH3PR15MB6479:EE_
X-MS-Office365-Filtering-Correlation-Id: ce990fb2-d66f-415a-3449-08dcb08fabcf
X-FB-Source: Internal
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?OVc5dmVtN2hjYjZjdmxBUTU1T0RDZzhIWUxMZHFMRk5mWnZUQVlORGdiUzJR?=
 =?utf-8?B?R2lwcktnTU1OUEVoaXhlYUlEeHBRQXdFK3JuSlFDUWxNTmpYY0p2OTl2MTdP?=
 =?utf-8?B?VUhjWWRrQnNXbU4vNzJMS2R4S1puSkxoQ2pSb1JyVExEMmIrT3pXQ1VjNWNn?=
 =?utf-8?B?WlppUzR0UTZEMjNQYkpCclNqeFhzVTBGZ3ROUUFEdXNpNVR2Q1E3VjEwYlBG?=
 =?utf-8?B?RTkwNG5HSDJjSTFyZWkyOU5VM1VlbDFEb0M0dU5JdEFjNlVCbjFqZ3dCSmR5?=
 =?utf-8?B?ZDNBNlZKVDdYTVljaEY2Y1VjcEFSdTBuWmhjWVF4UWtCZXpmN2tlV3FtbmJq?=
 =?utf-8?B?R3NQSmVVMjNOQmVEVjhJKyt5K0MvaW1xTStCQmprVEhOQUlJTlJ4bXozSUEy?=
 =?utf-8?B?MTl2dFNLSERlclphbTIzL0FtQk1CaTlMT1M0a1pHUlUyZGEwdGhlQ3d1eXJl?=
 =?utf-8?B?S1Y4QmpuT2JVQ3pVbEZBWmhOaGY5RUl1eWk4bHZCN1hReUxUU0hDOHB0N3lQ?=
 =?utf-8?B?eDhFekhUd3lVcTFGbzl3aldOTWhubHNuOTZSYnNObFpuRXYzWEJKeG9YTUFy?=
 =?utf-8?B?aGRzM1J3VlJhNisvZ3lsVkpjQ0VJNy84L2NMUlhmTzArdG5vZS9LLzd4L1FQ?=
 =?utf-8?B?UTJ2V0ZmeEErL1R3MXNHK3lMNTFiNCtOQkw2a1lUMjVoM2tpSEwzOE9wckZJ?=
 =?utf-8?B?NG5wNUxiK3ZxSFhyT1FPTC9Yc0ZzMXdXWit3QXRFYmFRT0xOWWh1cTBhSmd0?=
 =?utf-8?B?RDM4cnRQQkdRakovYTF0RXdkRTlqYWpGVW50UnY5aVFtblEzYU5ueW5hSitU?=
 =?utf-8?B?SjhmQ0F0V3RMd25RK3k2c2g0eVVRemFWenhjM2hZcjVKOVhPbzFjd3hRcnlw?=
 =?utf-8?B?cjZjT2VpdGdNNG9VbzV4UkxkME9ZTlpSU2lXY0NuSzJHQUwvdTdyS0liVkFC?=
 =?utf-8?B?OVhKOE93TjNHTzVJekVEWmkrakNkeDNZRUM1KzNxVjkwaUYxWUFhamJVUGdV?=
 =?utf-8?B?Z2hTVDRRUGcvWmZjazY2L2VaeDZ5NEdOUzI5ZTNBUWpLekltMFFwZ2pVTFpr?=
 =?utf-8?B?NHd0Y28vVGNqUjhDUDBtZDdOQ01yeTdYUWRIMzJlN3RkQmd1ZzZ4WVhQaDNw?=
 =?utf-8?B?YmNFcWZRVGtSTVJlZjBaM3dDY0k5S3Fqdm91bitXbE0vZ3Jtc2FQYkRPVjFN?=
 =?utf-8?B?V1c4M2NtUWlEcTkyMDFNZUpLTndrb1BZUU5qUzE1WTRBTHRyRTJadDkva0lF?=
 =?utf-8?B?MFdpc3ZIMEF6ZDNybzBNSE16aDY4UENFMytPd2lndTh1d1p0aEJybERqa3Zm?=
 =?utf-8?B?SjFDcWtyay9TcFJwZHBoaC9EampQS1hOZUpEK0ZMK1lycFR2ZTNMalJLYy9E?=
 =?utf-8?B?dHJ4ajA2YnZRbjlrc0lrdjVYb1NPWGRKMHk0bnFNR2J5Myt3TWhTRjVTVURk?=
 =?utf-8?B?MVM1dUFLZ0NKNm1rbjdBMVpYVkRhaktmemdsV0lOQlRZSnR3WUdLeTJSODZy?=
 =?utf-8?B?bFJqVysvUW00VXBSTWJhMHk3eHVXMU8wbVM5dGxRNUJtdE5MN2Rydm4vSDk1?=
 =?utf-8?B?SkpxL2R4K1hjaWNvRXU0bU9LaDhSeVNlcnBpYVYwRWYxQTlUaDNEWDdneUlW?=
 =?utf-8?B?NDA3V0pHWmVkS1VkSEtkN0xaLzcwak9jRk1SZjNhU2JybVo3NlBsZTE5eFlM?=
 =?utf-8?B?SXczNXZGc3RacSs5VDY1emMvTkZJcjhTTHFLK0FXb2Q5ZVlQUVVOL1k3TzVD?=
 =?utf-8?B?bmdyUUQ2OThkRzFoYnU3SFJiZkpPcnRyMnN2UVFFanE5TGFDM1M1ck9QMzNL?=
 =?utf-8?B?Zjcwb043VjJudzRkSCtxZz09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR15MB6455.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?V3NHTjdZUjNUL094c3YrK3lMbm01cXFtQlJldVJJblNydXI4b05KV1B0TkV3?=
 =?utf-8?B?bnJvSjgxTGl3aEZKM0lIQmhZY3llRTFUN3ZNNytYL3phTFNuenQrcUp4d1cy?=
 =?utf-8?B?NC9FcU01ZjE0cHFrZjZIWTB6KzlYS29pemxZTEg0TGt4UkZrdzJ5UURSOFA4?=
 =?utf-8?B?Ni92ZmJGcTdHTHkxMTJvRWxqNm5qcVZ2ZE0wRVBqOFFlMVdjelhOSXdFUVNs?=
 =?utf-8?B?aHpuV3JlT1MxMnliaXFrNkdVaVlzSXFGNUdML0c4Z0h2c0U2emNCM1JPWnRl?=
 =?utf-8?B?YVdSZS9sQzJxMUxsd0RPaU5MeWZNaUV3L0ZXWnVXekkwOVdrQTFuNUlqUS9z?=
 =?utf-8?B?WFlXcVdlaEduUkRIK2tIa1lrVFJ3NFM3aTc1OVdSK3M1QVR1aEZlYjQ2VU83?=
 =?utf-8?B?SmZ5L25HNWVhOGhWZjY0QStGdWZJYzJhRFRRUnVscDVoaEg0K1F4aFFjUXo0?=
 =?utf-8?B?L0poWUs1bTZNMjRjQS8rTE9zTHRQVm1udklqcUtmaVYwRGxBTlVjc2d1OUE1?=
 =?utf-8?B?bnVhMUswcXVZNSsxR3h2VzJoOE9FeW9oVTlsUzlMaGhEOWw4bTVoTGljRXY5?=
 =?utf-8?B?VU9wR3I1NWdvdTVBc1J4OW42empJc1ZFUXJqcVlPeWN6VFJxTGFPeDJnSkFV?=
 =?utf-8?B?djRyNEVpNm9GSGU2QW5WanN5RkJzSFR0SGYzMmwwRWpqeHloaGxZeldTYUp2?=
 =?utf-8?B?U0lJM3lsakZxSjVyVGJaREpFcG1EVXpqTHlXNFZUalFxc3dKekVXakdGMzBS?=
 =?utf-8?B?MUNmWTFzRDNuSjdFcTZaaEtlQ2RFZDJZNE1jQnhDUlBEaGlkNWFONXB6V0dX?=
 =?utf-8?B?R09zVDFQMlpMT3ZldU50RWtqMVJ4ZlN2eG4xSkdiNE1NeUpuaHpWNXN2RkRw?=
 =?utf-8?B?VzNraS96RWw5L1ZRdE41c3JXN0FQN2RxUDl1cjdOMENLTE1QRzJ2MzcyVU42?=
 =?utf-8?B?dk1aVFo2dHJQYUZEL3dsTXlTZEg1NmJQU1BjRGRhQXRiUU5ETXlFbTZvYzU2?=
 =?utf-8?B?c1NlTU1LVDNhY3F5ZlVkL0lVUHJ1SWxNYkw5RUhmeVdOUktKOWF3ekhiSUgw?=
 =?utf-8?B?VThvemRoeC82d2xsdTNCM20wUDZQMUVBNzBKdWhvRnhVbGhrT09mQ2ZsZTNa?=
 =?utf-8?B?K1VsRHRKZDkxZTBWaTlLdW8rdU5nUktleThiRDZNU2VwNkZtNlUwVXhNNmtt?=
 =?utf-8?B?a3pGelVHSVN1QVc3SHdwSEk3cVE2WkF5blJFdWl1Q1pldUE4QWlDZWlMUEVt?=
 =?utf-8?B?QnF4NnhQaE5RM29RQUpJNTBjS00vWlFpcVdYTTlmdnhxSEpIaTZHK21pQVI2?=
 =?utf-8?B?SiszUCtLNkorN0Q0TEZyL2lSaHdlRVJSeGpROFRMNlJuY0JkV3pmcCtFQ1BH?=
 =?utf-8?B?SDBmNDZNbkVlbmhOWklvQnVVaHo0OGY4RzVZekFnQmc5b3FFK1pGV0lpVElO?=
 =?utf-8?B?SjNDeFhiRno3VmVSWndhejM3OW1WOFAzM1Y3NFB6Wnd1eW1nVXJPY3IwSkhP?=
 =?utf-8?B?TFZVM1lRSUZUR0EyVG8zU3h0Y1BQRk9ZR3BQOEhyZnh5U1B0MFFSelQ0bk1n?=
 =?utf-8?B?dEphdHM0YUJRY2dla1F3em4xK0R1Sll1UFBvSGlPdS9MdUxGVWJzMTl2cXUx?=
 =?utf-8?B?SVBxUGk4RXhXbU1MbmZqcDluK2xXcDlueTBHTHZuU2U4eGFtc013MnVYNzVh?=
 =?utf-8?B?ekFzVXc0dS9zQlczZzhlY3ZidDhKL0NMbHU0c0JzbHhxUE0ybGtvcE1ydTRo?=
 =?utf-8?B?ckpRaHh6V0krOGx2VlZJT2k1a0ZEcktsZEo4eDl0R0dTRDZlbCs3dGdvdita?=
 =?utf-8?B?Nk9hVmxNK2tWVGY0M3gxR3V6NFlUWjR6Yk1LVDkwaFVWaWZNV1Vqa1dtZFhR?=
 =?utf-8?B?bCtTQkNIUDFrRlhXT0VHVTZ4R2QwQ011eHJhbFZZbFZ2Unp6WEJCUENsL3lW?=
 =?utf-8?B?TGRsS0VWam5Xa2pKdlV4S0N6ZllVd2Q2VFlNTHpqQmtLU0tZV3g1Z1lZakRD?=
 =?utf-8?B?dGdIR0FNcFhnRENYUENlWWxnNTJERkZvNFE0bExKM2ZGbFFsUEtKT3NOWGYx?=
 =?utf-8?B?dVBiZHFHd3ZkQ2MybTBINzZabk9GY2ZlNzZWQUV5RzhadjV6QmJ3dW81NTEz?=
 =?utf-8?Q?sLas=3D?=
X-OriginatorOrg: meta.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ce990fb2-d66f-415a-3449-08dcb08fabcf
X-MS-Exchange-CrossTenant-AuthSource: LV3PR15MB6455.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Jul 2024 12:03:48.9976
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vxZKVJ+js5IK8JcZqtAmJWH75eLc9ymf4vDuQ2rNssroOiG9C5OYj9mVhtffaL0f
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR15MB6479
X-Proofpoint-GUID: FSHC8QWQzoFOSvvj6pgxmLdO_YpvEiz4
X-Proofpoint-ORIG-GUID: FSHC8QWQzoFOSvvj6pgxmLdO_YpvEiz4
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-07-30_11,2024-07-30_01,2024-05-17_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2021-q4 header.b=YvjOxh6Q;       arc=pass
 (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass
 fromdomain=meta.com);       spf=pass (google.com: domain of
 prvs=3941bde6b2=clm@meta.com designates 67.231.153.30 as permitted sender)
 smtp.mailfrom="prvs=3941bde6b2=clm@meta.com";       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On 7/30/24 6:01 AM, Vlastimil Babka wrote:
> On 7/29/24 8:46 PM, Chris Mason wrote:
>>
>>
>> On 7/29/24 2:19 PM, Rik van Riel wrote:
>>> Reported-by: Chris Mason <clm@meta.com>
>>> Fixes: 782f8906f805 ("mm/slub: free KFENCE objects in slab_free_hook()")
>>> Cc: stable@kernel.org
>>> Signed-off-by: Rik van Riel <riel@surriel.com>
>>
>> We found this after bisecting a slab corruption down to the kfence
>> patch, and with this patch applied we're no longer falling over.  So
>> thanks Rik!
> 
> Indeed thanks and sorry for the trouble! Given that
> __kmem_cache_free_bulk is currently only used to unwind a
> kmem_cache_bulk_alloc() that runs out of memory in the middle of the
> operation, I'm surprised you saw this happen reliably enough to bisect it.
> 
The repro was just forcing two sequential OOMs during iperf load on top
of mlx5 ethernet:

Test machine:
- iperf -s -V

Load generator:
- iperf -c test_machine -P 10 -w 1k -l 1k -V --time 900

Test machine:
- hog all memory until OOM
- Do it one more time

Since we didn't have memory corruptions on other nics, I was pretty sure
the bisect had gone wrong when all the remaining commits were in MM.
Nothing against our friends in networking, but MM bugs are usually
easier to fix, so I was pretty happy after confirming kfence as the cause.

> Added to slab/for-6.11-rc1/fixes

Thanks!

-chris

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7a347d75-4df0-4591-b040-a832d3860a30%40meta.com.
