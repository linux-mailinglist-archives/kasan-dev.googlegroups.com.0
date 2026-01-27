Return-Path: <kasan-dev+bncBCYIJU5JTINRB2MI4TFQMGQEH4BWNKA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UJJpHWwEeWk3ugEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRB2MI4TFQMGQEH4BWNKA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 19:31:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id D1E5B99159
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 19:31:07 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-894766748f9sf277210446d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 10:31:07 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769538666; cv=pass;
        d=google.com; s=arc-20240605;
        b=i8oNtvjzf8Gwbrm9OUhJWOUSswL6IQ1rmfcqJU0M+scmgEIhWg3Thq/5Hp6yuqXOwU
         DEz4GOptlvcAEoAzC9NrsH5KTAGMNW2BOEGxy04WSFzTmJkgIePLwRvclfXaPrWd34VM
         Y7P+1DsOWZATZGmEYL13AJ8oZCF5hlkqm+PTdAe535YHpGyqFQlg8iKiXFk5cJHooXWy
         IGrGhHDpFJ5DKuPHCuRWHnCAmOcutTvbuEfdQlvgKfo23/fO8Zh5NXaF1mJRlJU7mDZx
         Z7Dp58KTN3Bj9FSJXcfekDXg2f5McsBQgEdFzJWjvsPlF4TkKe1TV1DeMHdqE9s/8AfR
         6/AQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QqPbdFkvBmYku53WRnSxOqQwxS5wqLIeRr3Nh1YOxdE=;
        fh=xGyQphkbUaLnWKG3GB37rjZLPMjjCvtdbAkTBk9tQbI=;
        b=TV2bx09wLJrsP4SwuuiY0K+xIeUG6bN7t4U57JNqSSPqGlObUz+l2adQgokfVJAhAU
         11lXdPFHnqTS6wh+1Eux92waMRokFuAH2Org6uMVRmjnInIq1Ybg3skYkmZKXYLXlj9m
         jHIRNenMGAMGzcZxlsIg8jLpTyTRHI8BZ6QNEc1BD37smWIkLtxmC3cLMQksmnRozysM
         eUDcW+aOcNkaeP9oDnUqxffYkzlVlH8Sh7bcMoDMytvqgJvKsCiGocGjOwX7Pl7ZD4pG
         CaKBjJAeYyeTqBuhj6aGRFpT9hw4JLkOUTnWpRHlFrrcTsvJ1LNi31nEwaeSYTJdb23o
         CcuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zq4xDYE2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bzn7YJpv;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769538666; x=1770143466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QqPbdFkvBmYku53WRnSxOqQwxS5wqLIeRr3Nh1YOxdE=;
        b=d1UtYRRpWPwvE8t/0k1wLBwTGFWJC9hFr6hPL2l6/Ad89ldyy3VnIFd3WnvACW7muC
         sAN0ioyqsy17ke7V2POzw3ARXdc3RSge+taPWk4vGPEchF85SZslS4l+4j+o1Lxo4s0H
         X6sLVA9Vx9VszTorlMkUp1WG8DqBnNahh3yJQWdpABt0qg23GCHP6K572xEIkaCGYlb3
         9xJDB7in4eS1vlOfUof3VVsWYo5fzM+E+ZKwSeQLEg2RwXCjafde3iT6G7W6Y2cvPTUx
         yjLDVZ0rKhDL3dIVJszl+xpHr693Gctes+8FY4VppGO5A6l2YKFJA3+8rWACoL5HvqeR
         zRpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769538666; x=1770143466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=QqPbdFkvBmYku53WRnSxOqQwxS5wqLIeRr3Nh1YOxdE=;
        b=tovW3JT1VDbgL775wQ/w9y/dNdW1JNfLTpV6kIWEZqP0W1zVgQQe0p6Q+x8zy+OJ/1
         S00UACOlSHSUTFKrv+zJkEXKptMS8T1w6MuL153zgZpn5WGGIDGrUJfBbTEvcFkrQxsr
         TaYe8Ohk2y3IQ/HS6HxK91QcTE7O1DxlGordrqt/Ekzdq5tLObrd5UyxSx4ShauTA9xM
         d8obYBHvWf2apT6bg+1/cUcsMfIeK2Ad9cXneyasTPhuLqwDGMzAN70uvF7akE/Sjz2D
         y2bg/a3i1qp3ZDKfOD2M6QBSja/7o0qUADxX1XKWbK/udho+EC0rM4c/XbGCff0iHLnD
         60Iw==
X-Forwarded-Encrypted: i=3; AJvYcCU38JnESB79f+5JZnaMkOw1JN3fxCEiORd2PAvTZTsZ6CzwgmsAI6Qh2eKf6Ji9gbRzNpfcrw==@lfdr.de
X-Gm-Message-State: AOJu0YxiUmEqwbEarrBrS2dlvv4rlXe00r4CP/jOX4rC6m5P597jrXfo
	ov6q1CU9BK9sgSQMp2LYLxjkeRctDn2Pu8D+hr00B3vTNovE/JA3Kvzm
X-Received: by 2002:a05:6214:2505:b0:880:5bff:74b6 with SMTP id 6a1803df08f44-894cc7d03cdmr38388146d6.7.1769538666093;
        Tue, 27 Jan 2026 10:31:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EJSqaEXApfs3Sy8/iM9yX675pNYuc+nh8Oa1OKZxhRmw=="
Received: by 2002:a05:6214:e8a:b0:880:44a5:3f53 with SMTP id
 6a1803df08f44-8947deca870ls125652436d6.1.-pod-prod-06-us; Tue, 27 Jan 2026
 10:31:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXlaBAGGpEP0rXBBnw5GxM7IH6gOZ5Mf5AVsr78oWcsOCXnx3FaZlUIMCwfrJSo70KdnfE0m0ktplA=@googlegroups.com
X-Received: by 2002:a05:6214:19c9:b0:894:72a9:68ee with SMTP id 6a1803df08f44-894cc7d0142mr38318006d6.11.1769538665023;
        Tue, 27 Jan 2026 10:31:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769538665; cv=pass;
        d=google.com; s=arc-20240605;
        b=VfRleGQVQHhl3i+CC3fFjZbr4SkbGhG+du9C7WsP8N/FYsJ2D1ZIYlZ3twqSclgEs7
         sLGFahE+cMOL8KyhJOxnyaKQd04abie8aW+n5JBJ2q++lKwukLJJwht/cSK0W51z2D7V
         GAdVfUKOAq/KYGaqTI+g93ymlKV7eYZj6EQrD2rFNH7UyZBko4fJjpRoLj2NYeKGeKkz
         eAJfzxk0zgYhfRrNHaYlHd1pqNPzAPz9pXGlsouLm3G6BOQnNL4Fo5nJat4h5Yj9ZBwo
         /I6aBHXKHX7lVUpoWirTNVZ8Ekzg1ytD+zJoJKP1V0gxBvHNM56vwbA1oWAMiA993aWz
         RIkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=2/8dm5W9FrtsuLbIC5/UKPy4boFvXMPqDEXBuUp24PI=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=C8Kb5TCL+YVt/zorvpncttpq5IVE9+9Rj2pXubbP75JVCJi6rt29hyuh/CuKOTyNpF
         dnmz01bPFMZupbSzOtpHky2X3Vidkir+9NSic8Cw2SNMRW46YGCSIOJ1fctaxNA5Zdc0
         fKdrO7HcDwoUNnKPVlhknkwT4mywy9RfoIu5Cq1NTr9Kctak4q0d2y3IGWqAoSj2IJL1
         VpmceUzwJurabtaFjhmD509kEjJXT+VW0ckiF0aNtKhlFwo6oE3g4n12Qe6aSyfKHUKX
         vKJAOmeJnneioDh3rIu34sh6ixft4nycgy/wH9zl0bTvM9PWE3r29pjtRCtG6w5UYEA9
         ZjoA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zq4xDYE2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bzn7YJpv;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-894d3781747si107926d6.9.2026.01.27.10.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 10:31:05 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBIHK73545592;
	Tue, 27 Jan 2026 18:31:01 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvn09mkub-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 18:31:00 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RI2gKo036020;
	Tue, 27 Jan 2026 18:30:59 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010010.outbound.protection.outlook.com [40.93.198.10])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhp393c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 18:30:59 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JuTLExDZPzw53oqNZUrFzskGmDdJxT7SGCNWOcB6Ok26v1U+d2iUbbpOjVRV4uNfQAjuXcpqZlzpyGJSikh0voz2gl1NcUM2ud1AHr03CDJUIsKc0Bop+LQXbbjH13337GHExJHOgNeeYCpotwQMPz/8I3LEjxOCUJmndG0E/rhmi8lDcp0qsJOXFHYa7ETMzjaMDZhdwwhLGqFMlhanBCl6K2ADWc2qnRb176zA6QLDlm/K4hwv6H9pKKgMZXSBteHoGtPA4JMI1EUzWjEKr4QledZdbP7ZyYWH8IfGZBeOYw5Y8cqfSXKGW5+z9Ly91i51nUBd0b8wR6gPwyWvlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2/8dm5W9FrtsuLbIC5/UKPy4boFvXMPqDEXBuUp24PI=;
 b=ih6zZu1oH/Fe5Ba1gF2SA/6oRF6LD9OD3wPGyathfSLjfOsC4UwyOCY5GcHIwh+phv5SIGcmcNtenT+zjDWeiykPxFZMsiRB7Ak+iA7253NemnUglk2GL169pEzjMO572dVrEAU/fq66ltuavC+RSEb17ZiimqEz30MztIqcV8VTkPzhpwQ9lJRPaXPPisA31jqxgyEFhvDZpn0Mknp0jVMTKBty4ISuKryu4ZhhjufT5iuW6wVLgnuflIJ82IyqDBDMepQy39t4G2wOCrk/BB1dckpgl/pO2J/gKRHwry9MMU0UF13nyfEbjFdDXacmRMsZg6VMsAsOOUQhJeLiPw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by CH4PR10MB8172.namprd10.prod.outlook.com (2603:10b6:610:239::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.15; Tue, 27 Jan
 2026 18:30:56 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 18:30:56 +0000
Date: Tue, 27 Jan 2026 13:30:52 -0500
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
Subject: Re: [PATCH v4 09/22] slab: handle kmalloc sheaves bootstrap
Message-ID: <tm7yjp4phbf24quv5vdjw3juhusvzk7dyassrtrejqyhbieie7@ml5okfvozh6j>
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
 <20260123-sheaves-for-all-v4-9-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-9-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4PR01CA0234.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:eb::6) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|CH4PR10MB8172:EE_
X-MS-Office365-Filtering-Correlation-Id: 8a06c56b-8148-48f9-12d6-08de5dd235c8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?OJufz3IDmjNYb3PGA3P7OaHMlfEDST+/7o9qIOBjYjl9cVnBvxntD6c3xD6T?=
 =?us-ascii?Q?rZ9+PH9yCfCxOnb5mhTdz4W44W/d8WZeopQuVBpPjIGlSM1Mbdm69HCF6d9d?=
 =?us-ascii?Q?iwPdiA7aGCgJNR+3v44TVrM4aKV+Z0CAiyBJNVT58aetRU6W5wCn2yJJ1THp?=
 =?us-ascii?Q?6wVDoqD8ratArKP6ZnYhhgxHkbqD70IcgJQRTcD2SiFZQPTDREVjZobJIvdm?=
 =?us-ascii?Q?4KmCaOarnHrPAx06ko7zAUeAfrhLd6oMGtI++icO8SaF5yFpnE+t6fnRljPB?=
 =?us-ascii?Q?zAPpxMZqSk7JKnRAyhAdmXbjxJUQE6BtFkz/KoM/C8wjqqdovnVgJZReQUxl?=
 =?us-ascii?Q?nT3NlsOxyLjjItrK8MBEDjfR/nCnO1m/j1epf8tVrAKQ0b3Q5DxtQXJ4YvSV?=
 =?us-ascii?Q?0czXTbZoJDY6G9RtwkJ8Zrkn7Q8lFtNm8X/2Hpkh161IpoZ6RMloGfrfPzvP?=
 =?us-ascii?Q?IfIFGcJl2z9fLfFnAFnysqB0kF7sMQCJXLQIJF2Mxjw5rsquZwdkm75bClhn?=
 =?us-ascii?Q?cTHhmDYxaL1bVpBX3BPWu0GAiDsORrgnjrap/UGRzK77mWZFQZc0hEwAqLfw?=
 =?us-ascii?Q?0juB/U+zo81vgpueauSDoqyRPXXe/q/ws6t5UZPSyMrX2QgLRcQzT3UmrU9M?=
 =?us-ascii?Q?XO7PPkXVPV7U5ckGmmQVzBVz67QPfE6n0hlA5SGX77nROjykl86mcgf1+LLq?=
 =?us-ascii?Q?pSV0IU95GkiVNogTj+zhRsd/DwKYbaKDiOfyCp3nIZhJn5H1Ihif4sihxv8B?=
 =?us-ascii?Q?eM82jLpZXKvE8OcDoidt8mmTyGuNHJduwePzdlHPMK/wgmbg9L1JdSGPkL4+?=
 =?us-ascii?Q?pTXAmYnxrBdGeoUpUnrrpiCF1QtCHgztPECT2tdNpIxSzHOpKU/ZqZwndteq?=
 =?us-ascii?Q?ESQLLeCihpfhZxQmdOHaavoENxeUk6osZL9+GnQQtQDT8EMxrJ10fuGXrH1v?=
 =?us-ascii?Q?XMxXd+Xr8Wn4a1tw3oi/MoxsAmtZZkwPhsjxlKOiUMHuP0ihzqVm/Du1da94?=
 =?us-ascii?Q?Wj7MjyFyOAmsAc3Ee0/L3bmlv8iWfnHAFHd9VT6VRnuk5KWNKKvGDV5+8sIp?=
 =?us-ascii?Q?qQsBlnN4RfW+UjBUHo4+dquTy5XouE+rDAhB1ID9KvB6CW+M+79U6dUwd0ty?=
 =?us-ascii?Q?eHMWeKT9KHB3ZzKG9AAV8mxcRALiofBUNQ+wtVrU6GFpAoZELDRd9ZnB6Qf3?=
 =?us-ascii?Q?cnZ84aYGKGVNr+cPLX8xY4le2pZo66JAQZ25u3HD48dC4+KF4/UNS7pl5w2h?=
 =?us-ascii?Q?arO4HLJ3qJCZKYdEW65DIA+NHawjqQwePrNOKcA/6k+aCrVbiv1ExZcWxz0X?=
 =?us-ascii?Q?VnIl9edu6l06t2mlk1oSTWW46AiiPd5s2UrmsVyEBur+klynDV14v2BYw9jZ?=
 =?us-ascii?Q?TwI2R/8zo0lQfOKPGqfNLJREoEGT8oZ9KkV2hMJIp5uX5UEDu+hPS1fUkmSQ?=
 =?us-ascii?Q?r0Sk8OgMOHaBLGBSyzPHIbzNCcsRTrHewj4ZXE0TG2mBSV2Y2lUJ0wnZktB6?=
 =?us-ascii?Q?XqukILvRc73AX+VoQuBmiXinRqem6jqFn0Gyi6gd7EPOMRZItEahY2/4ILCk?=
 =?us-ascii?Q?GaRcaGceN9oS8JaBMWw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Uz+5Ktj9Xo/3+VuDG3T+4QndCCrbnfsvwh0tgpXBqil2aU38KdcZKEwJ5/tD?=
 =?us-ascii?Q?JHqG7DgMGx/t8tFnBWSEH2uDiYGB8sU+1HKZEmm26tIvA4MJhOz+bK/UrGsC?=
 =?us-ascii?Q?WMxn4sF4hi0FDJ0ZPu3WcBGtXjw49W1Ix/jEDTZomATEAONxDElY/QANq6bB?=
 =?us-ascii?Q?45IUQBMt0FFbZ9l3mr8+pylW85NGoxqbFLfnldrc3l0X2BS3TpCf3Sgfpx50?=
 =?us-ascii?Q?kpP1+Hrj6TUqvnBOfWG4AFpg1AOdma0tn+vK1bjWsPQNX1hN2rJT8GnqBM+R?=
 =?us-ascii?Q?1gPrzQlGICeaNZlLaGT5oaAfotFVAlG6ny0xUeLZ/D/qK67o21riXWGA/RLe?=
 =?us-ascii?Q?Ywi8+WKgJeKxfhm1tbvZzGCBciRvC4b6YvH9zFfh9ouz6a0fsbA3wpOGbdT0?=
 =?us-ascii?Q?E/rj38DlQbf8AU3yauh/xeoid7kwrQkOJA/AsW5J4D2SexdksfogX30UEB5k?=
 =?us-ascii?Q?mHngnvhGiVRA/dPQ1FKcMqkd9rx2Pd8EjmdfBbf2S+rVZmQ5jMA5YzNKxutM?=
 =?us-ascii?Q?cbZzH4V+HxKSQmbUyrE0YSmS1e3iZZ+rpUWgUOOwXbYqONJ4C5JcpjRnyRyv?=
 =?us-ascii?Q?I56KsYQ+HF9wWXCU4353gIKS56FV2IknraBxskZTYovrj+3KK708RqhJPZfm?=
 =?us-ascii?Q?Gnci2+yMM2OLkLJuWUqF+XEtjCIPRhOiXgpQyZ8W6iJIqklR+iZgHBq2c/qf?=
 =?us-ascii?Q?+GgbQNj1cEx/UaP6R6W6fz/MjdGw98HS/nM4NsX/jcKQ4YJvkWCIOPUyO3Qc?=
 =?us-ascii?Q?IGtE4f4M7/GZMTt6BdzuN3JqQaBHjw2wE2JGwl6oOqZIRPk0vxlgBvdr+qYr?=
 =?us-ascii?Q?b0U9h3cSlkSpm2woYWSERJxdIYR6+m2NNmBXSjihScpvMCv9Nh6zHtWmjZy/?=
 =?us-ascii?Q?aUo1HQLpg6L8JoDNTyVuslsMM5KFV4QXn20FmsGA1jhwv/xBwGK9dUu+GZL3?=
 =?us-ascii?Q?EpcUEmUAG3TpswNYR7w9Ur04irGl6aEVbhLPQ/khgcE90s61oLXsSdzHCyL/?=
 =?us-ascii?Q?wm1qrEtBdXWu51/u4c6PDSARqrAbscWY/xua2RWV89n+kMZEaCJFaZ8mJ0T4?=
 =?us-ascii?Q?CcyNo/q1s0gn3O8MVj+ehuB/A/TE2y4+LsZfRfBbTKhwhT1oc2cjPkc+l9ZF?=
 =?us-ascii?Q?XDP958RyS8fMAEMYHRxu0ykXj+jO7HopXB8iVK+j0MpNa7jRez/VE0IU6lgv?=
 =?us-ascii?Q?+8x5aXBRdSi2oIq0LevEu4E+4gf/uLUKrE4qxXxtOUHTx5VTJIA2cEOzgB+4?=
 =?us-ascii?Q?gA/dEsdxAdOqEhD9/98M+8DwBa9xp8l1swYp5uRAhE8OAOnvAKZzRr3RH09R?=
 =?us-ascii?Q?0XEbWP6hW/RLcDOSVurw1nHTDHW2QwjbrKvweqjHM4/yo353etkffwyI1vZ0?=
 =?us-ascii?Q?p4fNtTO/pQoc3d7LRXYra02w0LROSibseverdbEYX3RzNziVknjw4y3+sfSl?=
 =?us-ascii?Q?oM3vMsSXx743hfldIAn2HzlC0ThO/XtxCi8gfdaqxRmIr/LsQcC15+v+6zWS?=
 =?us-ascii?Q?/7S3FhEiPv3cJeBhvLbWQo6zyoBqd5hTmW8BSTb9y9CKgYU6t97oRpC4CQkB?=
 =?us-ascii?Q?hl97QTqFKp/1o/rjv686OXyVOf8Rg0NxM1yPrWrquacJQmFtM3gU5LZBBqIx?=
 =?us-ascii?Q?V/UiEunmkRMan/jkILMd5CsDOcHVsTqMxCTVqeWGrAemFfGzb0/AF0lPhg85?=
 =?us-ascii?Q?/cgyKEpVKPShxgPaCwrqO2xEtbANxvqrQt7nSysEjdyxIgNiXJa0whd9gXJ+?=
 =?us-ascii?Q?Gfuah6aiLw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Xb8sLvUSPiN8HFMk/Y7Wq7SrA+hp3WEHvs/TZF79xJscqJZtAGDkgnysbDmNf41CWTU+2Oj4rUcQSHKXF3DKmw9JMjEoZVGu3TDzZS16uV2JzwoiOnt9oazD1SDkdVSOfdTpAzU7wOGnJRdtyNojEpti75xZeN0AwB8YxAoiqQsu4VJ/tIwiXU0iJjbHb2RdzJo29o2CQVrXUY+J+HxJYWncSyl8iyl3vKh6jpUTKyZPZQ9kjhi9XZ2PmT7apZKF9WbQuI1CS7PWGyL42eFeNANqWuGYEHN+8wvqI1Ampd6CU5uNM+Uu+o/mu5EyV+NXHZT9BO8BZkmY7Pt53+sS56e8GmYfAgtfjW1kcOoDWzhtxDIcXPdsu7DTcgW9C30B9fVuGr+NUvRzbKq4aXfTYuG3IifCRcSSOvgEoBQ5l5x4X14/K2JwKYDfn93HxLra0J+FsewBXb/B0gIXJl7uqikgYhestz6cKAZvR6W6Gp6MoY8ovkvt+gJqNFlLkLjvju4o4zkYGha6co9XaOYe3VVxdEOqyRScCruPuFmAgjKSeGsDK1Hyg6obcZXYMU7BKEaE5P7D7sjJIZlQsE4rWDKyD2TrWx3DVQv7sIYA4cI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8a06c56b-8148-48f9-12d6-08de5dd235c8
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 18:30:56.1283
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ou/SK34sTrUK/LQ10mzFEXEDhDqU3uyC8OPiylWuqzqTwyWC2GHEAdZgel7SsgtAtKlNCWaTtZ8u8E1zUloMUA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH4PR10MB8172
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_04,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270150
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDE1MSBTYWx0ZWRfXxpsE2lwQPc3D
 DPJOg0/ePLjPuw9wv+UCoOgCllMovcGOkvxKLqtdly10wdvp3iITmQpvETSs5+bcdeVYoDEfexy
 WAJw5K0Oc67cfEB4JMIScBYKcRIilfdXKEkarwhzXwbpaY+oySmd2Mjzb4gaj068DKbFgOHxq4a
 Q7KqJl1xPs9hiNEDBcy0sp1ZDdz/j5nYQJq63mgTivx3dDUYbsvKECg0UKDQw6CYWiHoiFbBazA
 3HTbI500Qn/PA1DhMC1N/egVoR4B6Ji28V8avd6amIASmw6UTZPs6l5vIADwl/kcq0E11h7B5FE
 jrR0+vpGba75TKMIQa+WsKRDzw1Ts5VeuY5roEOglJ1Z0Yhufk6h+HA3GggMCXzCV9M65rxReme
 58U4PQCWrfstXx8wH63pEdb+ZWf80Q5FTI05pYooTFPtZj8R9Gq1jNACKofdmAIVI+64admPUj/
 DXqxypvS/1/4boCI+ydOQo6cIUHyWykXCXFmy3Fg=
X-Proofpoint-ORIG-GUID: bq9MMIxTlz4wuLNKnBGZE86XYthXMhb9
X-Authority-Analysis: v=2.4 cv=Rp7I7SmK c=1 sm=1 tr=0 ts=69790464 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=dcaMh4N4r9lwndKBsE4A:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12104
X-Proofpoint-GUID: bq9MMIxTlz4wuLNKnBGZE86XYthXMhb9
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zq4xDYE2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=bzn7YJpv;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRB2MI4TFQMGQEH4BWNKA];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email];
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
X-Rspamd-Queue-Id: D1E5B99159
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
> we can simply allow them in calculate_sizes() as they are created later
> than KMALLOC_NORMAL caches and can allocate sheaves and barns from
> those.
> 
> For KMALLOC_NORMAL caches we perform additional step after first
> creating them without sheaves. Then bootstrap_cache_sheaves() simply
> allocates and initializes barns and sheaves and finally sets
> s->sheaf_capacity to make them actually used.
> 
> Afterwards the only caches left without sheaves (unless SLUB_TINY or
> debugging is enabled) are kmem_cache and kmem_cache_node. These are only
> used when creating or destroying other kmem_caches. Thus they are not
> performance critical and we can simply leave it that way.
> 
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
>  1 file changed, 84 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 4ca6bd944854..22acc249f9c0 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2593,7 +2593,8 @@ static void *setup_object(struct kmem_cache *s, void *object)
>  	return object;
>  }
>  
> -static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
> +static struct slab_sheaf *__alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp,
> +					      unsigned int capacity)
>  {
>  	struct slab_sheaf *sheaf;
>  	size_t sheaf_size;
> @@ -2611,7 +2612,7 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
>  	if (s->flags & SLAB_KMALLOC)
>  		gfp |= __GFP_NO_OBJ_EXT;
>  
> -	sheaf_size = struct_size(sheaf, objects, s->sheaf_capacity);
> +	sheaf_size = struct_size(sheaf, objects, capacity);
>  	sheaf = kzalloc(sheaf_size, gfp);
>  
>  	if (unlikely(!sheaf))
> @@ -2624,6 +2625,12 @@ static struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s, gfp_t gfp)
>  	return sheaf;
>  }
>  
> +static inline struct slab_sheaf *alloc_empty_sheaf(struct kmem_cache *s,
> +						   gfp_t gfp)
> +{
> +	return __alloc_empty_sheaf(s, gfp, s->sheaf_capacity);
> +}
> +
>  static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
>  {
>  	kfree(sheaf);
> @@ -8144,8 +8151,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
>  	if (s->flags & SLAB_RECLAIM_ACCOUNT)
>  		s->allocflags |= __GFP_RECLAIMABLE;
>  
> -	/* kmalloc caches need extra care to support sheaves */
> -	if (!is_kmalloc_cache(s))
> +	/*
> +	 * For KMALLOC_NORMAL caches we enable sheaves later by
> +	 * bootstrap_kmalloc_sheaves() to avoid recursion
> +	 */
> +	if (!is_kmalloc_normal(s))
>  		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
>  
>  	/*
> @@ -8640,6 +8650,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
>  	return s;
>  }
>  
> +/*
> + * Finish the sheaves initialization done normally by init_percpu_sheaves() and
> + * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
> + * since sheaves and barns are allocated by kmalloc.
> + */
> +static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
> +{
> +	struct kmem_cache_args empty_args = {};
> +	unsigned int capacity;
> +	bool failed = false;
> +	int node, cpu;
> +
> +	capacity = calculate_sheaf_capacity(s, &empty_args);
> +
> +	/* capacity can be 0 due to debugging or SLUB_TINY */
> +	if (!capacity)
> +		return;
> +
> +	for_each_node_mask(node, slab_nodes) {
> +		struct node_barn *barn;
> +
> +		barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
> +
> +		if (!barn) {
> +			failed = true;
> +			goto out;
> +		}
> +
> +		barn_init(barn);
> +		get_node(s, node)->barn = barn;
> +	}
> +
> +	for_each_possible_cpu(cpu) {
> +		struct slub_percpu_sheaves *pcs;
> +
> +		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
> +
> +		pcs->main = __alloc_empty_sheaf(s, GFP_KERNEL, capacity);
> +
> +		if (!pcs->main) {
> +			failed = true;
> +			break;
> +		}
> +	}
> +
> +out:
> +	/*
> +	 * It's still early in boot so treat this like same as a failure to
> +	 * create the kmalloc cache in the first place
> +	 */
> +	if (failed)
> +		panic("Out of memory when creating kmem_cache %s\n", s->name);
> +
> +	s->sheaf_capacity = capacity;
> +}
> +
> +static void __init bootstrap_kmalloc_sheaves(void)
> +{
> +	enum kmalloc_cache_type type;
> +
> +	for (type = KMALLOC_NORMAL; type <= KMALLOC_RANDOM_END; type++) {
> +		for (int idx = 0; idx < KMALLOC_SHIFT_HIGH + 1; idx++) {
> +			if (kmalloc_caches[type][idx])
> +				bootstrap_cache_sheaves(kmalloc_caches[type][idx]);
> +		}
> +	}
> +}
> +
>  void __init kmem_cache_init(void)
>  {
>  	static __initdata struct kmem_cache boot_kmem_cache,
> @@ -8683,6 +8761,8 @@ void __init kmem_cache_init(void)
>  	setup_kmalloc_cache_index_table();
>  	create_kmalloc_caches();
>  
> +	bootstrap_kmalloc_sheaves();
> +
>  	/* Setup random freelists for each cache */
>  	init_freelist_randomization();
>  
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/tm7yjp4phbf24quv5vdjw3juhusvzk7dyassrtrejqyhbieie7%40ml5okfvozh6j.
