Return-Path: <kasan-dev+bncBDOJT7EVXMDBBCNU3CXAMGQEDZRFLUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BE9985E19E
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:43:07 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2990e2d497fsf6102020a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 07:43:07 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708530186; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfw2reE2S6ed8U+NKDj0ZVcAyp96FuIZSqbLl7vf41CJTxoMf/Q+PU695n8nN0L5AT
         T1mVAu0WtxVgk7JJt7HVVXpxcXBeae7o6AcQMyK7fL/dnycqWq1X19KCVWJpW2CHczgQ
         wiNbokAZeNuxsT1/a4tCU6TsYV3DfKfqCWIUHo3EXdYyQDrHFEYI5CG+0kwpCWfCchYF
         5vYZbiv7U56STvCd5O2ener3gbhS2zpEq6iJB83l+cF0H/B1TBGymPa9PMFOBRVPBwzN
         sLVENSNSPGJAzgF4SvcxllNy3Izkjzw7PhSRTxU1LnPaQ6n7dfeixWAbkwctQRZkySIi
         XVsw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=7X7SsuNfqp2GI/YrBL4R8MzP4Jpby7W/R8v+GKd9CUI=;
        fh=vRTYDVI/mNI9AEeyv/1jcJRkp36R3UsrM8QcDOGHw4o=;
        b=Li3NtG7oAFfVkYbflRasRFNFv6dCW0JZlqIFqkL/FxFJ/OfuJ2bu73O4zPspHboDhj
         htDC2qW1H8gii4sW3s1LrXubAHX0smeM5MXOZveqpLUnv5CUGao/sNIv98tEfrcjPxnz
         mIC+NxzA2ulQDrtcjcK73yLtxvV1UMwbqgXUt0eyj6JEAitIXYkj/T6PQdlX2jvYiZVA
         gQ5AFkWh3+/xfiF6m80285dg3nKP7hH/j8lO4bo71PcTpwFZDETPlkzBkjCnOe4GypE2
         fNrTeP+++Vh4v99l9hV7bIAlkOGWE/Sc3IwZDlKZ/8j6VK4wBajtQmV7twR217NoulfG
         N4mg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=hKq+HNNu;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708530186; x=1709134986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7X7SsuNfqp2GI/YrBL4R8MzP4Jpby7W/R8v+GKd9CUI=;
        b=qjDK7j7eaXrwlcYYj0fXJnfWc8dUhF/SF3ylX3NKaIinDMhNMKBF89yNajKeSeieA5
         P6DvMwzqsGXFhMC4BgnzBRpD+eauZ4v1z/p6iO04d4LdhLT4HDnFOKU/948bYgTrKQ5j
         Rndp9vxdutLLBo85byKKmdKi/UcpIGZrUjaX0anqufDL0HXSwYflKlZqRcK7SGuOAIAR
         MqrpB5Ai/Y5QpOT3S2TrgYxKBixYWlvjA58FGs1xGIALD7hIxLYULDJ+w6VlTVr9sOGZ
         wloIdLAWA1mpxtappSr/Yvh5npwItCZymSssMrwxvlVE0CphowA/LoS7WFip1m2djWIx
         sKfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708530186; x=1709134986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7X7SsuNfqp2GI/YrBL4R8MzP4Jpby7W/R8v+GKd9CUI=;
        b=jbuilM+7h7+h/hyq4Qxcqby/+unEIpm915YBI88MoWRnA50a3BzjWNSuOki2gGEjnY
         ndaeS8f589XPA3bFJmMmUQ7hPd1vM5p0B925JTeUScG3ZpNKZoqM4egvrklwN8pZuSTP
         FqZccmPiRkijGlwYUNSwOXDbgS0NPXWOj5toTUk/epShiIyO5akJ3S7FKD2r8Ymc8RJE
         /F/29cc6kYpiGQU5dMqviXt9UNGbUKgFQpcvQpxiNHDkLaA81JYzYxKAsiaHaOYrfoD7
         B40uunS7n4ojVyMwhnHIns/qTUtBS2Yj9kkcDnfu0UmaX+w8xfbjOPJyq4goeXhCcgB1
         TA9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVyG6bX+1EbrdXaiibboK7GwYKuoeDNB3lpmfogVR3xxI3+yMRo9siLQWDv1urJJOI1oNthHJD7NKAr3Lh1x6uTBgh/2H1QXw==
X-Gm-Message-State: AOJu0YxVRKA7cBRE1OqOhR1NkwXr8uJBxEKqnHNE3hxK/u+NRfsnWU5B
	CG4ovEItlufzzgyOfFLp43J6A1SdCjnfWUSmyjUKD5Ap3PPEY3Fg
X-Google-Smtp-Source: AGHT+IGFHh/5dmfatf7cKlPafwWbvLVAP61hMOG20bVdf5DlNA+2fOftKw9TGVXX6iIroL9PbAIX5w==
X-Received: by 2002:a17:90a:7e11:b0:299:bf10:b559 with SMTP id i17-20020a17090a7e1100b00299bf10b559mr6168681pjl.30.1708530185719;
        Wed, 21 Feb 2024 07:43:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:8a:b0:299:6e5f:3d49 with SMTP id bb10-20020a17090b008a00b002996e5f3d49ls2796570pjb.2.-pod-prod-08-us;
 Wed, 21 Feb 2024 07:43:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWjpB+ddfhPps3vg/GTyv4HVBuTc3tkdh5kp8+y4rag/B04W4DbyVtq7FEhqtrNkATP7sq7+evHWT9+GVOrcbG9xuQ9G8BeZiQoMg==
X-Received: by 2002:a17:90a:c50:b0:299:906b:488e with SMTP id u16-20020a17090a0c5000b00299906b488emr8409588pje.18.1708530184663;
        Wed, 21 Feb 2024 07:43:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708530184; cv=pass;
        d=google.com; s=arc-20160816;
        b=K99ascD0aQcSdAcxcKKx8xozE3SjIAikFINdveH0VTBhijl2SfsZt+Xd57LhkT6dzz
         N5TdX8Z7bOzzRd0GG7XGdsa4mDsSzrkgegnjElQil+CXKiBP8T5HgZ1YoWhtDQJfLXgS
         PcJ7wDc5lrWSYSN1+/glTzSLkA5+XZ2RnMT6PhKBwxBU/dXPsEUA6fueQzlpjcnGM83j
         lRzHfe1L/oLAUj1bwrSHjNurgUDwI2983mbaS1II11eQepnLVaSLIBhmT3Ivx9Ty7XVV
         fl0gxnsAQg0mK43HTTQ65gO+fB4hzkT/+u7XeaXmPF1wQt3RirMYIsxgRnRvS8txc7EL
         +6Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=001nv3w1nCax1VFqAppcvmEoIQEaObOZ6q27qzGokMU=;
        fh=cVX3+QH4GL+zTKeOAoHRs7cEA//ih1w83qRPk9bfNWs=;
        b=02SWwrwxUlgbXcXN8kWkU31vLVVcm6vcM5MqiwEtSBqM2VpVV/iuBIK6i3pQu++5ea
         6G+zO+0N2638JTpnUJBe1fnlmrgbM/U4gWHGRNAuuiTw91ld4j3Utn+WJ111j/JtO3hn
         mFLECsBc4JWzGaH3u7gm+sTjdNd5MnLmoSO3xPju8y6MQD0XUyoHk1NtVDknZXe6V5Jo
         SV8T7uePaAOfllZ9uzHiByTCSWDfcXCKwoX6pSHc2uGmorkp+Y7uZglpzeQU5w/9RkkU
         QhEqT7GLGNV6TaFiL/Io6cZXx8G3+TnvpiKprPTHsV4ZFuILjTX04DrNrcunEVn2Ml/f
         vV5g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=hKq+HNNu;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0a-00823401.pphosted.com (mx0a-00823401.pphosted.com. [148.163.148.104])
        by gmr-mx.google.com with ESMTPS id y3-20020a17090a86c300b002998ff3a008si138311pjv.1.2024.02.21.07.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 07:43:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) client-ip=148.163.148.104;
Received: from pps.filterd (m0355088.ppops.net [127.0.0.1])
	by m0355088.ppops.net (8.17.1.24/8.17.1.24) with ESMTP id 41LCfC8i003869;
	Wed, 21 Feb 2024 15:42:35 GMT
Received: from apc01-sg2-obe.outbound.protection.outlook.com (mail-sgaapc01lp2104.outbound.protection.outlook.com [104.47.26.104])
	by m0355088.ppops.net (PPS) with ESMTPS id 3wd21x2sy2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 15:42:35 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Y6OWsc1itzUuLyeWVeTIB8Rf92jJtaEN7tq3WOEm3cmySd9/qFPZivY7H9jG/aTB2iuJ+GoSTyOR7r2YXsO1/AbnG5LyB99mZW59KlOmT+3uIiMJBPGsIaKrZ+v4zVffWPi8FdZvNfnKcMl9yFhSDbfuApYRQjkEk45hhVxJMWV7t+1LOCBQg9/qSFCq3Qw6qa3+nksLpTecXNz1q5ox/48q7euyXg+QchUYB46/k2P3zq3+Tx+r42mXcjLaFjfW8W6gzD0rFkUH1rFfR+wzGAxPpSVFnXNJ1bqR20bOSzjpVbDwUaQ7OybAHumLLZPp6YdAfDwhwyxV+u6wse9nyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=001nv3w1nCax1VFqAppcvmEoIQEaObOZ6q27qzGokMU=;
 b=LXxfoNZqwRHRhBxiz1Gs1+KpTp56b+Nt+rPK0rdrNKycCd8EjntUchj89UnmhHHtlmLz81971TBiUOO//L7bxOXSeFn4kaP1O/EV/oTsu6f50FDiZ705WrgCx8mvDWW9tvNmQ5+bexPm0Vu6xCcdpslSlyNsGuGTHlmduwY5+Qtdl8lwbuR9UJP1qkSy3XiZODGuMwTq3UROLteCpkqXrNlQ0qL3MHNjTwrXoDvXc9zp1F1UbrajlGqXUBlkOx6/cNX2td/HoTdYsBA3IQw7ESa29qMRAnJ/jjqp5PluWS1DqbSeX7Oylgnnps6kYyjyJP+gQFyN5BriG8Z+P2LkHg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=motorola.com; dmarc=pass action=none header.from=motorola.com;
 dkim=pass header.d=motorola.com; arc=none
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com (2603:1096:101:66::5)
 by KL1PR03MB7106.apcprd03.prod.outlook.com (2603:1096:820:d0::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.32; Wed, 21 Feb
 2024 15:42:31 +0000
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74]) by SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74%6]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 15:42:31 +0000
From: Maxwell Bland <mbland@motorola.com>
To: Conor Dooley <conor@kernel.org>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>,
        "gregkh@linuxfoundation.org"
	<gregkh@linuxfoundation.org>,
        "agordeev@linux.ibm.com"
	<agordeev@linux.ibm.com>,
        "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>,
        "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
        "andrii@kernel.org" <andrii@kernel.org>,
        "aneesh.kumar@kernel.org"
	<aneesh.kumar@kernel.org>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "ardb@kernel.org" <ardb@kernel.org>, "arnd@arndb.de" <arnd@arndb.de>,
        "ast@kernel.org" <ast@kernel.org>,
        "borntraeger@linux.ibm.com"
	<borntraeger@linux.ibm.com>,
        "bpf@vger.kernel.org" <bpf@vger.kernel.org>,
        "brauner@kernel.org" <brauner@kernel.org>,
        "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>,
        "christophe.leroy@csgroup.eu"
	<christophe.leroy@csgroup.eu>,
        "cl@linux.com" <cl@linux.com>,
        "daniel@iogearbox.net" <daniel@iogearbox.net>,
        "dave.hansen@linux.intel.com"
	<dave.hansen@linux.intel.com>,
        "david@redhat.com" <david@redhat.com>,
        "dennis@kernel.org" <dennis@kernel.org>,
        "dvyukov@google.com"
	<dvyukov@google.com>,
        "glider@google.com" <glider@google.com>,
        "gor@linux.ibm.com" <gor@linux.ibm.com>,
        "guoren@kernel.org"
	<guoren@kernel.org>,
        "haoluo@google.com" <haoluo@google.com>,
        "hca@linux.ibm.com" <hca@linux.ibm.com>,
        "hch@infradead.org"
	<hch@infradead.org>,
        "john.fastabend@gmail.com" <john.fastabend@gmail.com>,
        "jolsa@kernel.org" <jolsa@kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "kpsingh@kernel.org" <kpsingh@kernel.org>,
        "linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
        "linux@armlinux.org.uk" <linux@armlinux.org.uk>,
        "linux-efi@vger.kernel.org"
	<linux-efi@vger.kernel.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
        "linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
        "lstoakes@gmail.com" <lstoakes@gmail.com>,
        "mark.rutland@arm.com"
	<mark.rutland@arm.com>,
        "martin.lau@linux.dev" <martin.lau@linux.dev>,
        "meted@linux.ibm.com" <meted@linux.ibm.com>,
        "michael.christie@oracle.com"
	<michael.christie@oracle.com>,
        "mjguzik@gmail.com" <mjguzik@gmail.com>,
        "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
        "mst@redhat.com" <mst@redhat.com>,
        "muchun.song@linux.dev" <muchun.song@linux.dev>,
        "naveen.n.rao@linux.ibm.com"
	<naveen.n.rao@linux.ibm.com>,
        "npiggin@gmail.com" <npiggin@gmail.com>,
        "palmer@dabbelt.com" <palmer@dabbelt.com>,
        "paul.walmsley@sifive.com"
	<paul.walmsley@sifive.com>,
        "quic_nprakash@quicinc.com"
	<quic_nprakash@quicinc.com>,
        "quic_pkondeti@quicinc.com"
	<quic_pkondeti@quicinc.com>,
        "rick.p.edgecombe@intel.com"
	<rick.p.edgecombe@intel.com>,
        "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>,
        "ryan.roberts@arm.com" <ryan.roberts@arm.com>,
        "samitolvanen@google.com" <samitolvanen@google.com>,
        "sdf@google.com"
	<sdf@google.com>,
        "song@kernel.org" <song@kernel.org>,
        "surenb@google.com"
	<surenb@google.com>,
        "svens@linux.ibm.com" <svens@linux.ibm.com>,
        "tj@kernel.org" <tj@kernel.org>, "urezki@gmail.com" <urezki@gmail.com>,
        "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
        "will@kernel.org"
	<will@kernel.org>,
        "wuqiang.matt@bytedance.com" <wuqiang.matt@bytedance.com>,
        "yonghong.song@linux.dev" <yonghong.song@linux.dev>,
        "zlim.lnx@gmail.com"
	<zlim.lnx@gmail.com>,
        Andrew Wheeler <awheeler@motorola.com>
Subject: RE: [External] Re: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd
 configuration
Thread-Topic: [External] Re: [PATCH 0/4] arm64: mm: support dynamic
 vmalloc/pmd configuration
Thread-Index: AQHaZDwWYaEUphdXfk6h1XMsSOUd1LEU4kGAgAAM4XA=
Date: Wed, 21 Feb 2024 15:42:31 +0000
Message-ID: <SEZPR03MB6786CCB9C8071EAA143C246EB4572@SEZPR03MB6786.apcprd03.prod.outlook.com>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240221-ipod-uneaten-4da8b229f4a4@spud>
In-Reply-To: <20240221-ipod-uneaten-4da8b229f4a4@spud>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SEZPR03MB6786:EE_|KL1PR03MB7106:EE_
x-ms-office365-filtering-correlation-id: af590ce6-111e-4bd4-9e7d-08dc32f3b776
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: /Yv06vKHWKs7wI49yiVin9RGAI1xBkhgNCULBiL+rIQxhVgPi1k2b6jvXOUqwJpl1oNt8zr2whqYj6bUGlhhXy+6cEAhTaAYrlcyUsCatlLk99z/n7D0oFO666gHQ7KakIjmA4qUhy1/Edx5t65WjgmzbBgsdbUd/mBTrQFdJoowjGKHkP+fWscznT0dOBD2zmbMHG/+hTop4Wphhtq6n4Wpi9nvjEQN7dxLYF5x8mQdx/HO4hznXFiObdepwvhtqlAX/Se0gHVFQi4zem5Rzf8gFJ3xf9f4m3nao6eYZdrTj35tOSjQ+xfki7f7apHdBwpqbu1IX2EiDIjNE6dHVhmhimjzSguwX6XHMZPEoTl8fYb88OsmbCT8G0RNZ2Z08GE30ApkgUQ8uhfgVuUQzePGym4FFA2azvsBnCRV+cZKhbBmtw7r5b0nIvdingSWqsX07O8GpYWC40wDgITdXfQaeRXIIvI5HvLUdS4HETJWdCVImpNlzUVjglwzMwbZRkLczJtXZE1vs56/fwAXFqgsf8wt+0MXCAkkkAFYgGhD+37WrnWdr6aby1WojTUPaJXwWxAX/LSw4Ykix9aZLIoF83WONvWXukDL2kachHFHpeSfI8TOtW3BWCuIo7lS
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SEZPR03MB6786.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?Qm01eTRFOVNxQUZiQWQ1UGV0WnVsWlZKcnpqdUJJSXhuR1RONWJKeVNDcVFX?=
 =?utf-8?B?dXFHMnVoeENTQms5RS9nSUZlZ3cxa3VPbmxYYWRvc1FtaEh4R1MrWHVNVk5V?=
 =?utf-8?B?dzhESkg1RGxuMWlqWFkxaDY1RjNTSFVkemhmblZaT0dxWjA2YXdmMWJWWnlE?=
 =?utf-8?B?Q1kxYTFzbmdMeUExRGdlWGdySjZOM2tHWFhhYklGbmNnMFdQTGdsRldTY3Q3?=
 =?utf-8?B?eE5haTZwK1NJVDdZSnpTaEdaMVVVNXN0MlNvUUxBdUZiWTQ2Q2VJbndjdnBj?=
 =?utf-8?B?STM3ZnoyWkk2cldmczB5bXRhS1M0TW1UcjVRTTZudExYUlpxckxyL1cwQ3JW?=
 =?utf-8?B?L0N1MWluZzVKQ3NmM2phYmRoNVFGUVphOWRlb2lRNUxkMGZoYXYyb0c1bjVY?=
 =?utf-8?B?bUFQQyt1RHhsNXAwUnJtVy9IenJVUmtBSHBsYXZoQmpycXN3QUFmQU03K3Ev?=
 =?utf-8?B?a0sxUWE3QUE5YXdqQWJRT1N3NmZWR3FJbXFSQTZVMElGUTVwUnA3Y0t0eFV3?=
 =?utf-8?B?NHQ2VFd3a3VERTZrM3hVZkJzMTZWT25JQUFFU05tYU5NUXFFUkgwKzFPZUlM?=
 =?utf-8?B?WUo3TXVTdEs0YWtrNVNvVlhTcWVaQUxmc0N1aTZmU1hLT0lBNWR5YXlNRlU4?=
 =?utf-8?B?aGdKK0l0RUJmQjB1dTh6VDlHR0VNV0c3VlRLbFJLTWNIN1lTemtvNTM5dWNx?=
 =?utf-8?B?bGZjUVljWXdsaDgxamdTWDRUL3ZrbEdSTDAyTlJpQS9wTHRqd21TYlBwOE1O?=
 =?utf-8?B?OS9Dd1c2a1Q1OUNBWEltSmd5dU13Zm1WdU51QzhMaVhtOGpUKzIyT09JMlp4?=
 =?utf-8?B?am9WRStUR2I0Snc3TFlqRUloR2duTzhKc2RrOHBldm1EMmsyVWJJUW9aWE80?=
 =?utf-8?B?eUZoWHpKbVRGZTFDQmI1aThGaktsRUpNMVVZa0J5QWxXTUhQVGZMSkJtLzBK?=
 =?utf-8?B?UkE0QVFqR1VwWTdGNnBDM0MvUnFNRHhNZGNRak8vazRET2QvUjVMVUc0ODdB?=
 =?utf-8?B?aEZiZlNsaFdieEQ2NnA4UjFjSWFuZFZWOUNnYjlMMFdxVlU5OWVrcXBxYUV3?=
 =?utf-8?B?aHpqWlNGZThzclRnTkE1RjB4UUFCd1NTYnNDSGJIb3hwQ3FnTnRYeTczbTRL?=
 =?utf-8?B?WW4wcXNQY0hVVWRIbUx1Szh1UjBQOTBLbEo2QmV6UXVzNTVJcWxLQ2d3QThp?=
 =?utf-8?B?QTF4eUlESUVtendLZXEwdkpMZDlEQ0pIcEcyamsvazVCV3Q5YlRqekxBdE5X?=
 =?utf-8?B?RlpPWkl6OGQ3bHUrbDNXQXl4SXZweEl1SmsyYkJLM2g2R0JCWDVBVkwyaW0z?=
 =?utf-8?B?WStHQlBxekJrcERUcFQ2TkhlbHNPSFhBeUdFVnJidmI5RUVabUE0M0gzSE1x?=
 =?utf-8?B?NFpZdlA5VitTMGQ5cTBzQjNRRHdnR29NNzFTNzNDT3cydk1RNjVSOGQ0d0FH?=
 =?utf-8?B?ajhHZG9RdHYyQi9zYkpsZHBadjBmTFRLb2RvUy9TbHplOFJnNFhYY3ArbWNv?=
 =?utf-8?B?d2U4WXZnQ2Z2ZnVwUkh2aE9LQ0hFWGE0SkNjNTUrNjR0MVhVemRsNitTYkxD?=
 =?utf-8?B?eXAxL012ejREaXBpT3Z3dnVUNDBOeCtWaVhwYXBEemlkeStCQjY0a1lBU1c1?=
 =?utf-8?B?MnhiQzBHRHZFTkJYeitPOHFLR2F3WjZYOGdVcXJBY2RSZms2dmJvcG9wMGpH?=
 =?utf-8?B?dVlVeEJKendFaGJpeS9KbjFyKytjNmxTejV5N1lac1RsYlpTdnZ3NWtSeldk?=
 =?utf-8?B?K29FNUExUmsyMFRodTBtMFpJTGJGank0NXMyRFV5THZBeXFJNitzUC9kSG1I?=
 =?utf-8?B?WjN5a3pGYXpaeDJBazR1b0xIbjBDV1Q5b0dhcjJxcXIzbCtJNUljMUxFMGFB?=
 =?utf-8?B?NDJLcTlkaS9IelNDbVdzbFJNZE52RThqT1RNYXhOVnY3R01VYnZUeFJTSjVs?=
 =?utf-8?B?LzMzNnZzUHloL08xZlp2V1dwSDMrdHZ0WGFjaHRSeVFpNlR1Q1N4QXYzSk1z?=
 =?utf-8?B?SEFjYitWOENCS2JtNDdRQUNtT1dHS0NJTlhoRnRMbHFMYlYxWFg2VFVPello?=
 =?utf-8?B?cjBBNEh6U2VnZWRuQWs0UXQwdWlPaHcxRVpKNmhUMlVYcVV4TWZVM1JmVEhU?=
 =?utf-8?Q?/mZQ=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: motorola.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SEZPR03MB6786.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: af590ce6-111e-4bd4-9e7d-08dc32f3b776
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 15:42:31.5953
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 5c7d0b28-bdf8-410c-aa93-4df372b16203
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: I02FLoE/179LVLp7WiDF/PAC1nWUqGpbW6SrnF6b19HYGX+T7Qv+ZCNNLeRMR9rJHtpzjIS7ceaSbXo6dp3mzw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: KL1PR03MB7106
X-Proofpoint-ORIG-GUID: 8e7kxaKy7R84tzDdYam3XybMEgvXrbl2
X-Proofpoint-GUID: 8e7kxaKy7R84tzDdYam3XybMEgvXrbl2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-21_02,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 mlxlogscore=751 clxscore=1011 suspectscore=0 phishscore=0 mlxscore=0
 malwarescore=0 adultscore=0 bulkscore=0 impostorscore=0 spamscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210120
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=hKq+HNNu;       arc=pass
 (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com
 dmarc=pass fromdomain=motorola.com);       spf=pass (google.com: domain of
 mbland@motorola.com designates 148.163.148.104 as permitted sender)
 smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
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

> From: Conor Dooley <conor@kernel.org>
> FYI:
> 
> >   mm/vmalloc: allow arch-specific vmalloc_node overrides
> >   mm: pgalloc: support address-conditional pmd allocation
> 
> With these two arch/riscv/configs/* are broken with calls to undeclared
> functions.

Will fix, thanks! I will also figure out how to make sure this doesn't happen again for some other architecture.

> >   arm64: separate code and data virtual memory allocation
> >   arm64: dynamic enforcement of pmd-level PXNTable
> 
> And with these two the 32-bit and nommu builds are broken.

Was not aware there was a dependency here. I will see what I can do.

Thank you,
Maxwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/SEZPR03MB6786CCB9C8071EAA143C246EB4572%40SEZPR03MB6786.apcprd03.prod.outlook.com.
