Return-Path: <kasan-dev+bncBCYIJU5JTINRBMPQY3CQMGQENOGZXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1EBB3BD73
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:24:51 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-327b00af618sf2076270a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:24:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756477489; cv=pass;
        d=google.com; s=arc-20240605;
        b=MO50+c36tVvQ1DdfORvH04oAhRI9R5V/NXLvIF2kTNBavn7SF7cRHTj78CZpCZi2ij
         6kdFvSthWoZNk0/ZVwwJuoepOEExq5NDaM+fhUhvc7aLKnOjzIgG7ydVb7Nh8Uv6mW3+
         2xoQdttpH9sVoQ3BTH6UOgy8SnB99cE55dEFt6SkSk6vEAHjZVZELbHXub4kbNskQyL3
         74GDEO2aHA1AFpRwqbIw7KiWlHh7r5XIbJghlAGpjcJHzRbamEGQVm3kcF+TLTIOJ9cy
         7x7PgVvFB6WHxvFcd7L9ZlNBxUXX7zxZsZKpj+Ud4nNq7c1zTacynbzFrPPJrmvprzc5
         pv2w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4owZWkmj7wqlxTbxtBe8F/fqzBZbUoYV5QXP2GCeTgA=;
        fh=gHSbgnWmJVGTcr+HWK31gIVD3kPRcA04LKG4iZNEmyE=;
        b=kYeUkWaNo8FXj/xjJnSrpeHrbkDxdg+NgJWoM0wJE4/KwWkKHtg/RQVR4H95kxhcB8
         /lEOO0HCCi84nupVARsRkMCpsqsYEXiwo0n67emN7o6Xw1rY/GMwxY0AmQAxZjmK0qVG
         iK0Nt++VcppByPH63FT/xxwRAOche//A8eya5IDjKF42/1BwS6w/c7R7oYQmuev5mu4h
         T2kNJFPcw4IoLbpvJ5624iBjHMVp0d/IK9OKkQ8kE99g3IXHfQd3S9TBXbOFbjJir1xG
         kP7mDOZ8NtixxNhyBIBTsnEoawEVQdMmoBC5mUgxOdYXn9PD1pNeG8dwH4toUh/WPk9i
         z/yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=l3p29884;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SiMfdLO5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756477489; x=1757082289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4owZWkmj7wqlxTbxtBe8F/fqzBZbUoYV5QXP2GCeTgA=;
        b=EriV1KHUjWcL+/28NkxbXOCsgi3EMBtVI9bOc6aIC7Lu+UbQbHKMcmy1JVW3GPwnkM
         jMYCqXL0XESs+s1c16nPsX22bGxEUtZLWA5l1I7s7x7yQDBuo2wJXYR3gcyrEsjN0Dka
         kosFDjHzP8eDglcpP4VRqt9LLAh6+UWL6m3slUXpk30nXT0szPaaK19Gxy7HLRuOrwc2
         157fHrMvE9cwojT7TvzGXEiXA3E4FDap7pNshGZM/g9TByJSYmQ4nWLaLRBfFZGZfywm
         /OeECMvwUBOyImxHUpua9ZlT9+UnkWw3zZmsWWywgUFl4PChzrjNzEtBBdEBcO4taf60
         uCQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756477489; x=1757082289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4owZWkmj7wqlxTbxtBe8F/fqzBZbUoYV5QXP2GCeTgA=;
        b=nlJDbD2mGNwPWr/+UfWfygBBVw1OqALBEr0lcyYTEo2vTz8y4p715jbxiOvTNH+wH5
         Bw2u3awhlzaW6J/8sKSN6Sf2QxycWFoCSI4YejrzbWDDrMVUFHAE50daJJDVbTBjWoOZ
         O6ZpdfdKkOWi9RmA3VEiLwVeHbhh8MrwKT7+QmncbnEBhNnUpNNmHrwffsXJV7yy3NWa
         aypimaZVpclEdDYUP0ytyaaiZY3ikm7ThI++IaMovbf9mTxaHFiChyKCgBNp/qOeEZqa
         M0M+XMuriOWxIXynnw8dLn/LmXWDe+kDHwbuOOCAlMw+dwF9aKAsOymr1sH6tMs0YKJo
         tQug==
X-Forwarded-Encrypted: i=3; AJvYcCXQ5lqAfmALMJkGDjSHM9/iU3wayi6omi3zCciZogMLVUaUQJKYGO8+IHiF6BPH2O0EwZANOg==@lfdr.de
X-Gm-Message-State: AOJu0Yx4mlhXQNSL93xJgkdhvaVgXHIE6YRQBeX9x9/Km9K6bKIPBJz8
	lJuA8ECq9BdhrQjzFoBfCGJTz0OumFDnSckiJGMtFmbIWlfQEFze76EI
X-Google-Smtp-Source: AGHT+IHKTliirknzWhHCHRPCWx3RsCDp8O1Ta8u4TfI1U132D4alnL7gJ2bUnqUGVz08T3jX9ZKXbA==
X-Received: by 2002:a17:90b:2ccd:b0:324:eac4:2968 with SMTP id 98e67ed59e1d1-32515ee13cdmr37423951a91.33.1756477489419;
        Fri, 29 Aug 2025 07:24:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfbuPEwfrhWu36ZGQprsiTPFdUPbzrmLOKeC8mwdg4b9Q==
Received: by 2002:a05:6a00:4882:b0:772:27f9:fd3a with SMTP id
 d2e1a72fcca58-77227fa08fels1099415b3a.2.-pod-prod-05-us; Fri, 29 Aug 2025
 07:24:48 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUJobfP2Ok3586Tlpg/jVkc+GGjlrhmZxwS2Qb9J52B2RJn5/M9vlSDqGHl+6wMO3OUrpxufQ+4hhI=@googlegroups.com
X-Received: by 2002:a05:6a00:420d:b0:770:34eb:1d38 with SMTP id d2e1a72fcca58-77034eb2007mr32130524b3a.3.1756477487832;
        Fri, 29 Aug 2025 07:24:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756477487; cv=pass;
        d=google.com; s=arc-20240605;
        b=aNPbj+qvhKuuhpXimcY7UtLHCsy2GtNyIOsXJDv2k9vPbmAbMMRqT3dfsQxrYEQ7lp
         bwXGpvhUyu9rrJwRHMDeqSYbw+iEZA5tloRUDKW73qF0l0FlSblBHaZK9XeDMH2JjDF1
         OAvNtduzotZjMJb15ciFUncS4dCh0JtSUmSJTIGK78Y95xub3AHo2nr6IStvk7REUAiR
         2YOs2ku3Mi9sKxHKo+Jwm188cLEuSH+epqIgZr9S1gBFKQKF9L8zHZtY1JtiPo/AbbjB
         Rar+uOOs06SC2wprUdOzWNYVcpe1Pw40Sra9a7w7ICt+GrxTqd74UJTyusVBengQNMe2
         Wlyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=gZGfXDjbyb+OGF3VAjezv30Z9Vthn/0XzhQZTeuKsS0=;
        fh=Ob8eTtE71MCOthAzNORoVza58vWJMrZ9tpIAIK2RYWg=;
        b=E3bKfWH9YPXk/0ETnIbAsD+yIYkhqQpd3lTX9JoputSBX/eVEtRJhZt1AhjfjkTmDI
         kP5/ShzlQnPiKs2fuiKOrvtSi6flAxm9OHhEhLwjeiOdTWWeLoUBQNmfuR2OS0LBhsIO
         211LfE9ehu0+4dUYYNYpKxvDJdAGcO6DXAGjEoS+oJfDr3NyuagrRxjdflGo+yftsEHd
         2NeQ983XsgGmloY+HbGDrI8gSvAghULq+2ndgG6RnMg/3eRLtTt+aHV1uRki7a5O+dmC
         7AsWAOhWNDxo6P4ui1AL+JnRlS33MmLP34H0io5y4heYhsxe1+yKYm6ccK2oACOpZxLd
         QZAA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=l3p29884;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SiMfdLO5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7722a298a49si86174b3a.2.2025.08.29.07.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCtksT014769;
	Fri, 29 Aug 2025 14:24:39 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4e2aqus-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:24:39 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCY1xm004977;
	Fri, 29 Aug 2025 14:24:38 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02on2064.outbound.protection.outlook.com [40.107.96.64])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43dacuc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:24:38 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=o2Sw2zVb0Meb+WiQuUojbg21yXN6CAoNmRy3Onc/Dt5leXuauReVCUSoTEuDqE+KlyRTRfgmO8swTCy++i4DWzyR0Le6bVFEZgFbslBOUfQMo65Onag9t2kp2TyVl8d+nGQxl2PMqykr/8HJE7XMvuQKSLazu6QYVu40kek/0m7uDO1ruWIKOHBACrV414MMHtROkZ2v6lurCvzGeOHO42x4wrIErWLjaGCaTWqMbyLvq660xGraYxpj2BzCmNJhxXMkniC/1Yy2tpFy6Bg5jnXktVf2onoZxSZO5IsJkStWRqJZh2ZKqj1syk3BsX+QLZgtMKFamkd3rLOs275zxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gZGfXDjbyb+OGF3VAjezv30Z9Vthn/0XzhQZTeuKsS0=;
 b=ozewxpmTo8KK3episWScMRMswbDAXZHDkB0N15ktkAGfK9YUyPXeXjYQYaB53UBUI6oVs64XE8Tux1Q87KB8rsA2svGdvyD4/saPH82cZaRedIEBggFxIvcAQRmnfQphunnpAqlzH09BduacPH2DgmBhcd02L8x97qJaDhKhpq76ExA7sqoBqz9ucQaybfOUYf++PqSn4/cX9PNORbar1rmEwKTK5vvrSBlS0GCLcvMlwXUEI7ZbjOy5KeN4yU2Z219gmM8h2SQQFChrCvJQRj9KKujbqJbkiPQHBd9Mmahsv92f/lUnhpI1kSkFFlKBghR3ZuTpYcY4IyBgcmS5kQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by DM3PR10MB7970.namprd10.prod.outlook.com (2603:10b6:0:40::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.16; Fri, 29 Aug
 2025 14:24:30 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 14:24:30 +0000
Date: Fri, 29 Aug 2025 10:24:10 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 10/36] mm: sanity-check maximum folio size in
 folio_set_order()
Message-ID: <fbfswjohgqohj32ibefqp22rz5xvbwiry6nxusgtjoxm6waqal@4mo4gske35eu>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, 
	Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev, 
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, 
	Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, 
	kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Marco Elver <elver@google.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, 
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, 
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-11-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-11-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: MW4PR02CA0024.namprd02.prod.outlook.com
 (2603:10b6:303:16d::9) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|DM3PR10MB7970:EE_
X-MS-Office365-Filtering-Correlation-Id: 52d091dc-a522-4740-ff5f-08dde707c46e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4wectUMaFmYqYWV+o1aiRksy3eIZ8zl56VzHcOsdfZmkM//I81/dN3a/dGNg?=
 =?us-ascii?Q?JoInkDJBHbyZg7Nut7egzdNdFErfc0LAec5ufzy2IBMa+T5SpCdMPqOLtURw?=
 =?us-ascii?Q?5zR01a6yApX7LRIxBWqvKwaCkA7TnFVmHJYiKiSEf+7tgdvRNsLBZwgoYibu?=
 =?us-ascii?Q?gh71rjQl0FHCPCVPOtFeRIaq3S5fnY4ltIw+A/QSgAA9Z53/EnaPVmBR7nEV?=
 =?us-ascii?Q?pCitbA2msNY4hAqmpSwsN2RPD1VT64qMUuqeex8TdkPJhck4ydQ+E8BTOEy6?=
 =?us-ascii?Q?iiQFM0Mv2inp5nIbi1/FoMIFXRrMjhX69A7D+y4bcJfWn0Jdt1jXsxq8HjUf?=
 =?us-ascii?Q?iLYW6FAckZiVUe7RTppZMZp1WioWtnJyPNwzfqt5SIqwYwEmuwQXMuNmFTI9?=
 =?us-ascii?Q?mpnWpRuTV9NIUBHu2RLlaIPRKZlVcvS7sJsYLlxKP7M6NwPd2mC/dnikC/3l?=
 =?us-ascii?Q?RAhjLVOx2YiupHMS3AXz8gkVVEo+EzQncHQqulW4iUqNh7gwEw+EKZP6Ugyd?=
 =?us-ascii?Q?9K6o+sTriY4t2wsEzzseW17gxZDhQgOurlaVW1Od4prL438Io+jwR/7iWLGa?=
 =?us-ascii?Q?hPkIcpw+RcC/pE3Ianvnk/5fXPjmVAdY8LHOjSg7Sl32DRZ+VTkqhyheoKY+?=
 =?us-ascii?Q?q5eix4EKUr3vNcrFwC7lYEmkeRZF/T/hykB9hrt+VjFQnAYzOcTqKGRTsY0L?=
 =?us-ascii?Q?twZu1apAmyOgbAz9bIOSykZthCWXFDxS9WSRQhvvH97sZOJNvltEQ03E/+5u?=
 =?us-ascii?Q?6ooUkzQYo2kE51I38Z6WEHq6+JqMAva9tl0aKZfVJ0ukIfqdzT3OWm4QGtN1?=
 =?us-ascii?Q?UqEuyFW5NxYIFVtbtfph/xPqRYGWvbvAqDe/y+YiBqYY/NsQgh67dPSn/dA/?=
 =?us-ascii?Q?N1auCk5kpzOWgFr/u4VqSAnkm6ObuR0IwnoKFwGzJP6zDTBuKNmKLwFgiK7k?=
 =?us-ascii?Q?s3CUKJOTcj0aLyTn23VScQoS2Db7wxi53+K/W3bEs/S6BYgh5sJMyA10lz86?=
 =?us-ascii?Q?Gp82M142mM9aEkOMAd7nc6LgvEli+HxA5mwulGXzo9vQO+dDNGit+WWOf36o?=
 =?us-ascii?Q?YLgMpvQyQ6FUxRHdVxUShvjG8PzWNOwp1Cs6fYuuLdRw+RknZDoG98MMi0t7?=
 =?us-ascii?Q?javnxRC3IOsUlFYBZLWe036kjPdUOWe+rjdzYtHCcltdEbV/37lNZP13D/UE?=
 =?us-ascii?Q?hsZE0lpqX9nw+d5xcoonqMp9q2E0z0PSDzITD+eZbhNHVfwfrynuGO6CzIbi?=
 =?us-ascii?Q?a2+irtuaTvSq9B/vHG5dby66bwq5r7NqoWPISME0p/V+Aap654lCYVZfZqNn?=
 =?us-ascii?Q?Hr2QZd3C8sEVBtG4uyrIAZ73uJid92I31gsU6l9jO3GqOap1isxrKEGpPXn/?=
 =?us-ascii?Q?2Z0t494ZKBwprGrF2MoUrJ1KH4byRPVtJxzOEvsiBwpSdouzdn3VzyYbs31/?=
 =?us-ascii?Q?toJK+jiCq44=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?sdcCm/2E+uwce1L6BovuRZrZslHBsLQYyDlzqHgk+bhzschxXtWTe0S9bTl0?=
 =?us-ascii?Q?Vq9sl/hVQFlJxOufSbnGzTdXb/W2MP3xweLP9cTjDmyx9Kft09/caboC2Edn?=
 =?us-ascii?Q?lq9RUOJBYz+vxYP+GzN34sqkUMnsy8g3b64t++gguBbhBr0t+oj5r5sPZ3QK?=
 =?us-ascii?Q?z70dimOAmFUBTOsLr7PHUXLOdQ7QrcrbjK0tLV8YwQnrLxM+nIGA+9PSuL86?=
 =?us-ascii?Q?O5OR39ti6gCk6ffAyFjWDUieh8KilV/tUC/0yoebH6Lc9Cg7B5mnL4oKR+Vz?=
 =?us-ascii?Q?g71LlUrcVQ1+1LnkQT8e0Mj02iQSsBmSHCIPSeMCLz6iI+URcP164w68Wo+q?=
 =?us-ascii?Q?FyE91OEZI6Iga1sN8RG/BVOikwWgcplHyAjCatm+fdb5exmyFMiPYVOkwRsq?=
 =?us-ascii?Q?dDrove8aKAy8O1aAfClBYsBAxo/CmyHRHIvFM392DcGeuwFzOPdlummnXgkk?=
 =?us-ascii?Q?B0kAlwNdXCwQ1LD2MQ4ZsK7ayt7LdnZ9nZNz6DZXYoYuxbseSfx19R7Hby0E?=
 =?us-ascii?Q?RWlxyUGrWZ7tkd8Y5rx9/WJoMi063Dtsj+SjZpFyYY/AEvVOfyBVJnkkeVSI?=
 =?us-ascii?Q?djxn1sjnEup4KSEHGSAFWbJNoz91aVEnAoEW2WfHfOYDYPfBLw+1r74o/xQu?=
 =?us-ascii?Q?mxw0irhdpOE+ioLtwfqyQWSk7SPBaUqDdTdQzmaJDmpuqBUZfC+VwHRDOL6c?=
 =?us-ascii?Q?TiZQMH4SEoNDlY42UY8jnShl8kEO//zhHPC0FNSQS4FVGFPDvQB9/R7n75YX?=
 =?us-ascii?Q?U2prIEj/+mbbU5ve99hK7iMVLMnkANHF7TlF3+YdGIcx46CIO89OXbFnciQj?=
 =?us-ascii?Q?RynPJky1Lkbg8OWl6aXYOBuNGKjSPwCdLpcMkgCLqOPuLWJdVCkCq2WrpshR?=
 =?us-ascii?Q?Coqr4LGt1gucg7kt1MHLB4dKSG6aAOVOxJM5LBwdlPImFTxFAM48fHSkEmzl?=
 =?us-ascii?Q?wI/Yff4IHSV8BH7VkNRNOc/98lnv70vz8qAkjYG1qMcYRVkp6VgH9gFItX3J?=
 =?us-ascii?Q?Evnn/grhM0LoJnO/kp5NXgiJSB/kmOsMmkyf7S+HtHGuqsGO6uHwUH6Zvljm?=
 =?us-ascii?Q?CtNo8r6ivX9OqIdSeHmgk5s4/eLEgDdbhwLKsTAH3XhwwMa/wsq3gBVJNVcC?=
 =?us-ascii?Q?SiqT+Nx1TOPDZ+3E3hGYDcM64xcZdkpYTgChz4973mVWFlHf5HmajSFhZKcs?=
 =?us-ascii?Q?UT08KVGaCF1tYPNU7mbzztNmGj3LpNLfxKRFeuoRBu8spJWJ+DUs3f0a6JlC?=
 =?us-ascii?Q?bFbsqDQXfRFgtWSp/AShwCFC66tdsTDHi2f703x6aLJlsyFsBlMjznz4rclJ?=
 =?us-ascii?Q?5uUpJ/95X7KiUJiK/Kutmdx/jJ92446iMixe3YjeT9I0LvCE9pGE950qGAsw?=
 =?us-ascii?Q?wrNv16pjNT75E7hnhKbxvSTTZmPkr8EI7cD68stISvaoCn0LOTNaCP4m/u8V?=
 =?us-ascii?Q?ulsdUEVh0tR/ZL+7I0pajiIlmZHbTAb4XGqSV9qyysrjeN6EEomhLR65QgRk?=
 =?us-ascii?Q?ChVh70Vbrr7goiDcxItG4H5jiqsABl2UJXGg0iuq8QkBbZzrK5LIoXgCCxMu?=
 =?us-ascii?Q?UmSpmK+JMtSc3kRs6krZUxaIgSKB3xskHErLHl48dtBDgyLoEDeSXkZ5T8At?=
 =?us-ascii?Q?RQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YBa8ZvktNmaxKQkTgGwQGQq1pr3JI8CoI3B6YDnR1oaupgeU6qzodXmOR+hawRlQRkgYcRUajBt8geNkyuC7ZlXiYwU+AuE1uJ7p3c1m5PFeg2MYbokPtL6Y/g/qXlmr00EBtVBUlyQ5ftVor9mlHFQ4LnMqBG4YKg4dDUlTYsXExEzibDR8gQn3W9h1Fw0Eem5nu4a3BzMr8cKJ0YrQkxUrTSZWzCzX9xPN1pe9MSMqeW6S9CXM9P/BWXJ4uMG5IoBqshZczVrjMmEdsLkt6NG+wne8cZAX3N9I17gkBpRf0dgxNhj+sDoCh8n3dmS9PqgyyCmIc/6kCjDkrMYhbW2T+ZM2vJunMT7La0rk+b9fIryxK8dO1G4Il4T9pAOypKYXemCUeiAW1xi6NFYObzHCloLUb6IYYeUMs6bF7xsOAX8/OMY2fO2qLzf5uzQReCU7Cwq3y0JyzMYJ15o3CxcuyfKSq29rfBuV4WiRwNyjScVS2WBCnz3EkputRNtihwRJOKDJVe4jmC7yJBJPhJfmkaz8hI4dpeXzym8mI8CoUqwRne7FUJGVZXjE1UZ8rp98jMMi6UKnryax3BoySr0pBjIpQEPyrGz8ptTcbZU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 52d091dc-a522-4740-ff5f-08dde707c46e
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 14:24:30.4571
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: LhZm1Iaek/a1MhLPzRXX5DlST8hrcFJdugqmzsj2cMZ5q5LnswYFMo9JoVjBOOjd5+EnuebgURU36lwlCCL22Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PR10MB7970
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_05,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290121
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNyBTYWx0ZWRfX6fyMu0StlB9j
 AVpkjLHIDVwe186EyDOTuv9VWa611XjG2z9qCA2jYQm5fyXRCEru/XoUCKGoiIps5Yirfd+3WlO
 hhbqE7Y2jKTwQZoM0duQeFgja/0oMdMf99gt0quDnWCFADihZ5cQJmQVoCVlMcmT+xvx7lab/QO
 jO4XIPPlxjvxE/37nxnOG0hmtEA2af5pJ3ogD50t2ideAsuE/NqfRPYFbs95k4Unsk7/7GoSmUX
 6NJ66C7NPWPIGmT6Vz7M6ED2RRiBeecCi1yg/TWRJ5hS/c8qVutVuIzUcTS7MAjm5gMm/DfvMGT
 E09aWcLdKmX8CoZ7t0u+YFBOmYFtF5ISgam30b2WQVDonzEj7omJzrY6nI28vnFRrhnmjO2ccBI
 FLtNiono
X-Proofpoint-ORIG-GUID: 9SMIN6-sVjjCbHbjwd4dIYLLyTe0Whk7
X-Proofpoint-GUID: 9SMIN6-sVjjCbHbjwd4dIYLLyTe0Whk7
X-Authority-Analysis: v=2.4 cv=IauHWXqa c=1 sm=1 tr=0 ts=68b1b827 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=yPCof4ZbAAAA:8 a=SJHYMh_qAkJed6OffD8A:9 a=CjuIK1q_8ugA:10
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=l3p29884;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=SiMfdLO5;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

* David Hildenbrand <david@redhat.com> [250827 18:05]:
> Let's sanity-check in folio_set_order() whether we would be trying to
> create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
> 
> This will enable the check whenever a folio/compound page is initialized
> through prepare_compound_head() / prepare_compound_page().
> 
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/internal.h | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index 45da9ff5694f6..9b0129531d004 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
>  {
>  	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
>  		return;
> +	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);
>  
>  	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
>  #ifdef NR_PAGES_IN_LARGE_FOLIO
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fbfswjohgqohj32ibefqp22rz5xvbwiry6nxusgtjoxm6waqal%404mo4gske35eu.
