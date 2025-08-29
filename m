Return-Path: <kasan-dev+bncBCYIJU5JTINRBGHSY3CQMGQERFMJSFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44447B3BDA9
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:28:42 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3eca67caa2bsf23301195ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:28:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756477721; cv=pass;
        d=google.com; s=arc-20240605;
        b=gdN50IeXiQi98dD8IjLveFp0jznYssJoimkp32QsZuBMEUAHWMbDr5rbjEnt41A6bg
         DJwpTMm9heeuIrNiyrEoBfjExSMRrYkZjRwd3y3OBE3yv/f5Ye2Zek6THHb5gtzK/Xu5
         L3+ZhzC56xYkZ5Pp8VAL3qhrASlQb2W29sE/KlucmQhc5c/n167qzZrQ1T9zvoPzWYd3
         D7TNSzaOxmHvMAsCNGEAgtM7/2ncJ3MlzafXBiyrRIM7nZFB4JItQlurJAMde4fU+/Jx
         SX/f1Z/tIucKyQQWVQ8sAIGncZ0MyrplcKwV/yNJ5Zpg5vYIbYktx3QsGt2MWJkIj6CC
         qnjQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BGpn8glPlkRoXPFVkvoIkfGOjTzfWz23XSbhXNhQK60=;
        fh=hAd5sdyipEzMSKhJXeQ7tdcC67DIMSMlKM7mXKHAedA=;
        b=Tw4g6te591iKghYmM6/+jpwEgkagQBXrxhtwLYkr2pYe8I6OOV1Z0N5mJVbQt4tElr
         dUepG43uCFLYTHyyVNXicz3w0a7X8IaJU8vcvyci3zNqGYDYJDvi/UCGpo8xSex0cnl2
         DR1eUtO1TDny85nkYngmTIZD7K/bRabF7d4uUvn5bJktajWF1DhfEcmn0uS/oQ60fWFY
         51dtEEoUgncIsCKmBq8i1jOd+O+CEaQD0BvR4yqVyNXzgGS3DsrxZy63uMlzANr/5Ebp
         zoZGkDxZAv+1eXrXroUFPVF3zyTXPC7pg4ydhC9OD35yr1/VSjNg91LfK0N/BHsUq3TB
         Fp/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nds0xCUV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=B6BJxGGf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756477721; x=1757082521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BGpn8glPlkRoXPFVkvoIkfGOjTzfWz23XSbhXNhQK60=;
        b=ENk+9CKGnTOcb3CXHmk+hsVL2Ybro3XTHJuvpFHlZbuhAQjzxy9dXv+HVVJTvPvmwA
         TvGupIMQnB883klx2QeQ0uvv1/ifOLEk7qd4gssTapfK5867ghyBtOKB9z8JlUuOgnqt
         nYO6eRxWjEnzCcHOSgBKs6Q5ShsC+j+mTCYqioQDBMwykQ2SvZc17TrPO5KZtG9+TBP3
         AKosRWF0HilSmzbgtQP2WFP5nQKXQBEvl08PE/M4MY0qsTXq4IhzkQTbSmkHE5e/8RVK
         g89i92D9rTOsYhxibEHDTb7pTo1eXS8DYcYbyMWz9S4eU3eAB5BPgzwnJ+JBOvwEXZ35
         nPZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756477721; x=1757082521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BGpn8glPlkRoXPFVkvoIkfGOjTzfWz23XSbhXNhQK60=;
        b=pVdaHip/mbfv4mAdQxtRGvezQ0PJ5N9rjgaT5J0HYlC6cYnmQw2LgNOyc53mcuzTAL
         1iKv9E+GoxYpyrnz9WYB8hehNz2XbcD+KS0NGjvRpnn721rOH4ANNSx2Drgx6k9cZOAj
         mEFt31taUvCAvDbOHBjOh6BT7JW8Ir7rKMzMGlLxDqsSmdTPr68YSDPbeOmYejBd6LhA
         v2Ecrwy/0cETJqDzt/aGL/YFK4CJuZYdKufCgBbcAUYheYiSSX700knyNNtVmU+ZPLWb
         cwro3o8CVj2uNR5nKLrTK/NYoFISGlKHbJDMVUecKuEb95k+LyfTk0r+XajfQqCJri0N
         38kA==
X-Forwarded-Encrypted: i=3; AJvYcCV3cRQVCfsbwqDq9F9zYcVZkTUL9b2Bvs/SzTtn5Wz269WF4z0ZuVR8WCN3VUfDgxaKVuRjlA==@lfdr.de
X-Gm-Message-State: AOJu0YzCnjDK3DIM+ImhVpHtZjnbT95M1F5Cme8Z3ccvdMLdar3zi5WJ
	sHfXUh1aK2xvov13fEFTWvgyZ5DgVb4KdzzMxPCPWWrb09htmhYn4mfI
X-Google-Smtp-Source: AGHT+IF/gOS7dpDf8arrosnsNdA2/jOPSjr3Q7j51W3e9rzQULzJiCF1bWay27noEJseXNSMxf0gGQ==
X-Received: by 2002:a05:6e02:2483:b0:3f0:62bf:f1a with SMTP id e9e14a558f8ab-3f062bf10b0mr163490435ab.29.1756477720672;
        Fri, 29 Aug 2025 07:28:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZclahUcqWrtjpGevRUnKdev+sNg5A0cvw2CsLkCaRFNXg==
Received: by 2002:a05:6e02:198d:b0:3f1:219f:f51e with SMTP id
 e9e14a558f8ab-3f136fb421bls14141315ab.0.-pod-prod-07-us; Fri, 29 Aug 2025
 07:28:39 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWF5ifbkEVazb7dwbrkxcHNcyJWGtt/Idv8g8eJGmktasIuEgfEWUoOn5Ya3DAcNDHpZDN3B5/4WUA=@googlegroups.com
X-Received: by 2002:a05:6e02:154e:b0:3ec:1da2:9d9c with SMTP id e9e14a558f8ab-3ec1db1e109mr245393315ab.17.1756477719552;
        Fri, 29 Aug 2025 07:28:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756477719; cv=pass;
        d=google.com; s=arc-20240605;
        b=SHs0HK5I3XBwxF4o0D01zBIzOdUgilN6aPoT7xorVt7iH3+2xQ2vhJHEVje1GG9/9U
         nXzQeK6guNaJ/z9KkI8eNFGapzcWI/bU2/Sy1JMIau4BbQodqJYMMxJ0ZBFfhSSLLi+R
         rM3pokpmQDY7Ta6iXkmN9qql8BYymPPhmSJalZx4EsNoZu22TVtom/jrvIfaUXotf84B
         /7VktgRCzSUh9JpbhvLrsBPsvNWa8HZ/HNzY4mr3HbY7L5QCjhvlLdzIgKeX1NgqGqyM
         tipPoOLF+ZF/o7JMZb+MrZaer4Pf38y0hAQUwKeR2MJlBD9efg6K+7KJvGcjYEZIwtDS
         yACQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=y/Wfj+DqHyE+g9KzLPvXttB1erXuztGJeeF0e9b4zJ8=;
        fh=FA4alcIjt2gh18fEEkEgh7kVV7tk0kU/Lhs9ToYTHQg=;
        b=RrugXSJoQ4+6rA9y3PetpYtxFbQW7cO0Vm5sluB2ZViZXqCAhMutqDO1JHIFjLviG7
         cy3CV8GLSC1dFQ3Ull/cBJzDSMCKiBf9TBqDgFkhmiJy7NGkDVaWvI0oHc9iWlc0ivVd
         bI21u7x0kxvnSleFfv10FGWwR4WsXKpd2HZY3ZgbMfeK2OJeR68GG0p23VLyX48Cotgq
         +EcKdRLDe2fm8Ehr8S3Pgu1wiGtrz1Le9dTcOWVxX/3cMxkiW5y/1mYEflA/oiFSLzVF
         n/zrCUlmHJihK5oUX8BVNpwEETcChU8nGSoVxipEa8CV3ezuKjCdNpepxyn+JiSdYrW4
         nQtA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nds0xCUV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=B6BJxGGf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f2a1f53ba6si966705ab.5.2025.08.29.07.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:28:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCuGPf023146;
	Fri, 29 Aug 2025 14:28:29 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4jatmmq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:28:29 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCp7tq005063;
	Fri, 29 Aug 2025 14:28:28 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2074.outbound.protection.outlook.com [40.107.243.74])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43dag76-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:28:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Pfd3vEsL4viNEO22ImXle4lKhZ6KsYPUByq4Hbz2jDXjVLPPhpj9scPmi4rJZ3lO+IHWxT0Lq5GMFL0YLeW533FgGbgwO/TGv+Bgy3VzuzHylUonLf53niI6vHwastyaiD62FoTJd0p2+0CEc0yj7yTmDnR0u7AqINwgaCwke0K/D9zcAsnHrRA6xf/wCwQ9ytTrR4DWTJvF61pRKuLv9badTEH/877ydUwNBIaJta/FQ+Ra09MSmC085SPqJ0JC5F6mSWu9qVtfPSZ0n2F5agYWmVpdIQWJg9NZ2K5XCLrWgzSPYCnK4yV/SZ70rE3tEfbH5hgQu1dGhygRlULxcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=y/Wfj+DqHyE+g9KzLPvXttB1erXuztGJeeF0e9b4zJ8=;
 b=mYIBAmp1ZxMo7/iH0ERBW9LEgqs6IBG9LDFiF4BUtQK0392tUan/TgpxPBrW2y7y7VzP905al2kZBgQbOIjpNtynG5bRcK5YHvEur4HCQjBWQMSdWGRGIehYjq69p9MCkLSWOWS0uR1iimFxhpF4nYdB0YV+AJc51YbETwJ5SoroGu32CB7/fSbWVqpPItSgfbBKi7VMELr2qkD6TNy1+tev+hWOtXVVbCuiH7NHi4vG/yKOcJKEXxd76wDSdKcWTNV+FFOdtkhxTPuURGZQHMc+vRYh08U29fIYALUqwEni+JBHggyPadFjtk8Hoc21swj+iMMh54fVlwACQruAeQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by PH7PR10MB5877.namprd10.prod.outlook.com (2603:10b6:510:126::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.21; Fri, 29 Aug
 2025 14:27:52 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 14:27:52 +0000
Date: Fri, 29 Aug 2025 10:27:46 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
        Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
        netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
        Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 11/36] mm: limit folio/compound page sizes in
 problematic kernel configs
Message-ID: <le23yqshxkwqzdoj3pgv3kt6epxtshfu5omxcr4egkhuhh3wyb@afauanocxw34>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>, 
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>, 
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, 
	iommu@lists.linux.dev, io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, 
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org, 
	Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Marco Elver <elver@google.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, 
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, 
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-12-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-12-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: YT4PR01CA0405.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:108::18) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|PH7PR10MB5877:EE_
X-MS-Office365-Filtering-Correlation-Id: f920132e-b2b7-403d-5915-08dde7083cc8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?77iYJeh+lHITMhQo0FuLWjWfdeJksPMAB2i2Bc6NapuPom2SENqXbygVGGae?=
 =?us-ascii?Q?4SI55wE5NVQ/8IH4TbFTOttSbM6PsX5iW1I839xKHr82bHzP7cAe0F0sgdtI?=
 =?us-ascii?Q?CGP7yWZx1mlN03llNGA31A+88WIcwhb+4NHmPiyJo0K3HkZuxhccQ+sCRS92?=
 =?us-ascii?Q?ilyWtBJeqtflgnshBJJl6qY46yyJLzmcxbHVweEn038BhrZbeJodgPPwRTiv?=
 =?us-ascii?Q?dXQpnadivR+bmQ/LpApkPHC7/8NCXQmtOin9O1CGXincSIa0XvkPgcVSfXQq?=
 =?us-ascii?Q?4RFx/assL8kyBMfG0te5Q94vI+QOY+eL9nPRaQA32Y6PKFJaEKqMupuR/HXr?=
 =?us-ascii?Q?mXp/ZQf/8PskP/CW4eB4MGeuOtCBIcL6qDk1pmM76qRIF00dccgU1/9GT/Ma?=
 =?us-ascii?Q?PRokHOYSLf5RaTVvioDl1Xcv4/+oEVQnmGwrnEFNKqkDRs387onr32hWoPAE?=
 =?us-ascii?Q?qJ7ADWHMzVkJmltA0Xu0hsxesbnzcdmobSrERNkUv2NxxXDSbX4GjPGkQ3yC?=
 =?us-ascii?Q?CmspXRk9Xm7RKn/PLxWZ9lA/eRVRhRtb65DLhhZUkqpTCEcxpV1tC95ZMJBD?=
 =?us-ascii?Q?jD3r1kawXXoALKxR7clwe9p+8tCt+AMj6xyadvwFPL0kGv/KHOMpi2nGF9lv?=
 =?us-ascii?Q?2/xhi6EmaS4zZYHWmZ+KmcUxI1evP9ZuYE3L711yYFbji7+N7AtkWpJVGr68?=
 =?us-ascii?Q?1Z/PDEPyR7WLCNB+MApTNQKolXtrVfm21Mgnp7LW5u8GNQ82eUhZv2Ty1hBf?=
 =?us-ascii?Q?xDN1rncQSDcoGoam/Fo5KZcNlTyxpJ4MeHBtHvBhz3HraetX2mSaruGQnGY+?=
 =?us-ascii?Q?atLmVtXeP6j6MIqNWtFw7mA14Huc/wiWfWQLptCS4jrtAt2DHZZbqfgijpiM?=
 =?us-ascii?Q?zgqisMxF6mV9UQA5l+7PxoZJQZ0netNTcef0JHYq6LffUepa4xRIg2kIh8yF?=
 =?us-ascii?Q?BPQEBxHIl/rdGjfmbIYizaKysDrMVuyeKYIFLXwv16wH26Y3sgqIrLsZWUP/?=
 =?us-ascii?Q?Jn/oTsaT6Mp+0MUEtHOGoZEYeszI5B5Z7oVIwHnFCRmPj/G7ZdyCEjjlFX4J?=
 =?us-ascii?Q?xD0/j7tHjXN7q7b9MlBAikitc4rN/9fcr+U0Mw78tFyb+lrH7MrDNLDnZovW?=
 =?us-ascii?Q?pPYppjUmQKRVY5ELaO3NQyC7rbonA/jyu08NkjIQ24Yn9WPKwh6HsD7lksFL?=
 =?us-ascii?Q?mz/YBZiv5unrTB1V+ODAbqOi1SWkqpD3hcDCnAWbWdK84Xvocpe+EfNd3wPQ?=
 =?us-ascii?Q?mfNnH7v0UHIUbLkwZvjkk9Dg4CzX7UMaUApJXkzEnEZixAHbF6RcOt0qgfc+?=
 =?us-ascii?Q?L4wDQ/S3p9lUvQVyK3fiLeWWv1vm1itp6ZntBhPe2ePhrTBNZoXiLI7t/cmO?=
 =?us-ascii?Q?tUAUJRtWiTKkjc0v9ENqq/O25RK7xLP66C2QUy+tI89iY4mVo4+pNHygnoPn?=
 =?us-ascii?Q?gIIXCem+Ajk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?hzK33oZVfT7z5cMuNgwmco2IANa1iZRBD55DlmW6Hd7YQ6nmkHMF6kcjvZyJ?=
 =?us-ascii?Q?GODhVt67wEklC3F6z5pBG84mhJ9ViHj7ioKb5QgNYyK7v0z5X+ftStmWUhIm?=
 =?us-ascii?Q?B57ZJRQ/kUMoKM2X5nOdKOYCYf0ixj82Xf3EM75IH1PiYBsj+4cPcfdJZ64s?=
 =?us-ascii?Q?SOO2yUGkgnQwdQNauDHogFRWgQAMSFsiGkBOvOhXNwnOcLMlicakVvVhYfo4?=
 =?us-ascii?Q?ZzJFSF3MG2MVcW7oWumCfCl7EKp5hDwJVKwI2bW/wwuhp9c2nL9GhiQqP8oj?=
 =?us-ascii?Q?wrwUfwpyPjq0GkY35FLL4dklfmREwr5EUS4kqqZcFJXlgUhJEXiy1fpyK3na?=
 =?us-ascii?Q?zyRU9aRPVhAGH64HQMOleJ+lzcOaoq7zEs6qk3SwJnWcIDIng0xDIpyxVFxT?=
 =?us-ascii?Q?9EPXZ2AcWYOZHGaPkPspUnOzLwyQfsHfECd0YYuSk9ABK1aqv7BZcZz3K5UA?=
 =?us-ascii?Q?h6wcJsDvhKczPJu1RyBmsXTMbl1srUxZU5QNNXMi+ZUNjmmhvDKvoS9mINhr?=
 =?us-ascii?Q?vHL5S6Eu50hqKq7oWhAQedqjtubHxC0Jo1oI218HXFuz/7SxIY1y1mI0OvJ+?=
 =?us-ascii?Q?nFn3+2TYERYiLg2B19DANgwUB0B0HpKvbvErpRtaONaLLuZkUTXW7uDCRazK?=
 =?us-ascii?Q?+63CD2+I4NusIz9qF3OhdgauTPMkYYRojjqsH6Gd+PBzWufKcXjkt1LxETiS?=
 =?us-ascii?Q?R1BvOr2GJI86q3eZa2dZp1FUGIS0J4VXZirGG7+/1brV71xpWWS0Inwe4ls+?=
 =?us-ascii?Q?5l7nQuBLIzRdWnx0pCVkBEwoJm6CoFEI9f4Yura6JlcGyTNU7SjQpmAgHFFq?=
 =?us-ascii?Q?frEmiEKNXfKmVEs+iN09SG4JADM9IC9i64R2i6SoqWUFQebVX/dLbcj+t1Cf?=
 =?us-ascii?Q?vuAJe/1Yq+FCnvTnxVdViXa3erlBDCIdch625nintxJX9P21rawyC2hJP/6m?=
 =?us-ascii?Q?3WZ7PTlOxBNJXUPddq++terOR5E2lfD/o6VOkPzLq/2CAdpLmSlcbrXA/+eT?=
 =?us-ascii?Q?XRhucwsNohF/T9wpkZvp5JEgajh8FztUPnfwu5dzAOUHjdZwsVrDaLLL0+Ko?=
 =?us-ascii?Q?lYzZB0Ydki/msO8qMVKWvVyv9zZblfltHAPgtzNp1L59OYIzOBgMHgkLsfeE?=
 =?us-ascii?Q?pgdvhyhyFL8YmBxOReWI0Vp0L4g2NXgtqXfk7XRnLmY+HY5vP73Y701uclMl?=
 =?us-ascii?Q?ZiXY2QIE01bu/MEj07iKva16F9q+1V6nQDtF9iOC2V4ioGeYme0/BkdGT4HL?=
 =?us-ascii?Q?sUEZLMbKUxYq8yoD1jJvZx1vtyc5Jk377bOBBOmUnePJ3hMyUYWaamrFBgEy?=
 =?us-ascii?Q?tzNwpV6/YEokbgab2KVVobSviq85oSLTDZzF96JNVtwR4dtrEUDUytXgBv/c?=
 =?us-ascii?Q?lRYYH8ynYG55arg+xkuZjkj7ZIYmrxO3g0iBP6ia2pfWAhuAo6MIqNcPXkDX?=
 =?us-ascii?Q?Z6n1CT/GnJ3GGuCXFbfWcp4Rs8iNWVqmvd1DmkyLbexb81JeManSGvzrUP6h?=
 =?us-ascii?Q?dlVZGo2eb2lMKDbzuz/C9y2D0s6hqzSIdE989CfN+Y+ImzjdFJwCz3VvciCm?=
 =?us-ascii?Q?k8JMJBRFHOB2QFOqk0I84mkbKuCCHUCMBHl3sIW8jtrLk0HnirzP98nW8McA?=
 =?us-ascii?Q?Kw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: CM9+eeAmsHCrjgdrpQoqJxRhFjPIUHx46sE8vXOiWOKCHrxl9cp0LoqyhAZR4z9HB0cIisKxWeLojNf22iEk+jH4PSHDBcLEnJLhEsJOKWJyMNmC0iNnAxAnwduma7NysBartUxUERk+nvGwELV30BV/3veOus9c94+llSeR1nkuCcnUzhSrD0g2A+oQOIdIvIylCvSMUALBqZO8Pr3LoJTGhje1l8dn8mYpy3HykKEWyGRysEmbCagqLQu/PhRwHYB1CRgsC5zzgFjGTVqRGlz+KQgruH/TrmR3JycKdSysLiYYgxLgV1WXXynWnbXBCkQJhoiewD0NCibnlkAweNe/1lrg0gILJgiGz4r3fMCcCZMSUOi1l3+WjNyjeM9F/XsB1s0F3MtgpPesS68iIKq3QnaogpC7nZn+JWYFl4yWom1Le1sgyN7SJRmK7+BLqA5nxSwAXKxcuczaunho5VEb5gl0my/hG9gimo0dRe2h6FKNSqVWf5wtcb+AexhCj3VDPWlsKzgsnEk3yB+7ftXs1LtLWpVA0Ts+lQQPE1nlQn9lTTjpsSAj8TdxUlhid3O10TdkX7FiisKOneAzh2bLCAKLMNT967gLVREQMXQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f920132e-b2b7-403d-5915-08dde7083cc8
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 14:27:52.4488
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: WBFwAHM2aFI/RuisfwnVC/KHoP9Ls02Ew+mRytRE0n3ODpUdN+hgL5AkRIMRh/qi1/Mx3mjUuai0oCrLOqZCxw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB5877
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_05,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290122
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxOCBTYWx0ZWRfX0kGIo2LINChF
 jttR8BCcoxS4HBdNElwUZ9wc9y4GfL5DO+YUF6drwMZyasyW0KOL0j2AhpeS+4nXei5t+XBZB91
 s7BKqH6zDWXV1eZmsvghG0Qz9D1+i9bBwGGHh2HBzTWCxGbMjb0EFltCqvLgRt2C82GYmuyRmB1
 tKpw3NFGxJgpwvqCU35UWH1S0dRSbgFAy/W9WpLZwh0jK4DlNqosQy+73xK7uC3517aTYbsV/44
 doIy1h6Jo1YWgLfIeUY8JtRLyjWskB8Gi39I/0W3r/yQsTP3pxzNKrQln9ChEfzKThRvu606NLR
 vngWVG59+tJ1hhSJOEmb0h0PARA63+d6L7oPvm+Cq8tNWuqGtUn4+rY3gTbtPxwPoC93UTMvBQN
 yV2d3l0O
X-Proofpoint-GUID: 1t32yqI8iiw3TUyJC_y4AtEWXZiUd87R
X-Authority-Analysis: v=2.4 cv=IZWHWXqa c=1 sm=1 tr=0 ts=68b1b90d b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8 a=r2OVo3NODdYC9qRF9NoA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 1t32yqI8iiw3TUyJC_y4AtEWXZiUd87R
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=nds0xCUV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=B6BJxGGf;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

* David Hildenbrand <david@redhat.com> [250827 18:05]:
> Let's limit the maximum folio size in problematic kernel config where
> the memmap is allocated per memory section (SPARSEMEM without
> SPARSEMEM_VMEMMAP) to a single memory section.
> 
> Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
> but not SPARSEMEM_VMEMMAP: sh.
> 
> Fortunately, the biggest hugetlb size sh supports is 64 MiB
> (HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
> (SECTION_SIZE_BITS == 26), so their use case is not degraded.
> 
> As folios and memory sections are naturally aligned to their order-2 size
> in memory, consequently a single folio can no longer span multiple memory
> sections on these problematic kernel configs.
> 
> nth_page() is no longer required when operating within a single compound
> page / folio.
> 
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>


Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  include/linux/mm.h | 22 ++++++++++++++++++----
>  1 file changed, 18 insertions(+), 4 deletions(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 77737cbf2216a..2dee79fa2efcf 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct folio *folio)
>  	return folio_large_nr_pages(folio);
>  }
>  
> -/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
> -#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
> -#define MAX_FOLIO_ORDER		PUD_ORDER
> -#else
> +#if !defined(CONFIG_ARCH_HAS_GIGANTIC_PAGE)
> +/*
> + * We don't expect any folios that exceed buddy sizes (and consequently
> + * memory sections).
> + */
>  #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
> +#elif defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +/*
> + * Only pages within a single memory section are guaranteed to be
> + * contiguous. By limiting folios to a single memory section, all folio
> + * pages are guaranteed to be contiguous.
> + */
> +#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
> +#else
> +/*
> + * There is no real limit on the folio size. We limit them to the maximum we
> + * currently expect (e.g., hugetlb, dax).
> + */
> +#define MAX_FOLIO_ORDER		PUD_ORDER
>  #endif
>  
>  #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
> -- 
> 2.50.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/le23yqshxkwqzdoj3pgv3kt6epxtshfu5omxcr4egkhuhh3wyb%40afauanocxw34.
