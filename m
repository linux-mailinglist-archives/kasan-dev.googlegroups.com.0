Return-Path: <kasan-dev+bncBCYIJU5JTINRBKPYY3CQMGQEHYJ5LHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id A674BB3BE1B
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:41:47 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-3278bb34a68sf2144627a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:41:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756478506; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ddb8PJYD983dtZe8IbDhvUpgSlm2MCRODFTqzPJkzxhIOKtCZKTFggwk66mDrg/+mi
         Z+8rO+Hgvp44r4p7Ot9c9f3/eLIVhv+DtTu0fI0Fpl9erNk7EXRfFW6NkjVovT8KwLU+
         mvppZLdKsSzJz4Wzn8dU3j0b3rVys13l1ToSBFsa6sheEyLf2ayS3RXQpvpu8n8/jiaj
         YUQraCEEXM1etRKpI/BDwXqSp+nu55ladMc72CYOmLYhIW9wlG9zO1ioB8QqCbC8CJCL
         iJl6OTxRXDG5LDhaInQQxoFUSKB/azVyhsDLLBRJpr+nngGbsHMrJuOpsEO9GbYX9lNy
         M7hw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NA7QcB5qW53zSDt6sq7QXtYqr4XQcsQyefltJ7XM5kE=;
        fh=PJTZhPVSc/DebGObOVeuRkmUIo7lZBmT1zVJftCy19U=;
        b=O9mQVe8IH8rUhJg9xYgIXdAnelbtOTg+Lz3AO0DEY5Aqf/WsgI0BMVDmxa+8qWc4Hl
         eK4OcIRIjSrGZ+gc/6WFoIDjFKj8hiNSWnORqit2J5wPXsjztw+fmu4hBFGl0tYO48A9
         B33+vWTM16dDFIWLWOKU5XKY59toe0i20Ki+zc+WP21RY/lyBVYU4LT+GDMFteX3LsIw
         LYG6EZII0dGhwfzxC4iwH6UB4z1yREBZBVc5IDhw00yTPZlIRr5c3TxiWx41E97lukVF
         Bang5ldzlBLt5MxudoxwF4yxuh9KbsLkvIG4I9d4zhYclld35eZssNceE1Q7HAy7Y+Mm
         +yEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ZhRBgO9L;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AQzInVdn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478506; x=1757083306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NA7QcB5qW53zSDt6sq7QXtYqr4XQcsQyefltJ7XM5kE=;
        b=ubw4tQeiLrkJvfZVcefx1bYY4TSqJbYhbmjHDaiiNuihHBRAWXm9Eet6ii+ytTBWMm
         fN3aYT1SjVYRE5uGv6kncvoBt+8Ip6PFBPB1y5EDHn9GY7UmTcMxY2JswWFH21f7heKa
         KSWR23eXKKlga2WW802IiQwsNdhP8vqG9EBFLSgbuWW7kPb+e5v1VXU3Sza5Ydby55Y4
         I8ciPKmeRI4e1WQ6U+h7ZY4IBaxWcIXkDmaeY/Y2+MSvVQMxMw00pigfk+Hb4/r5Hffc
         6U9CBtEtY3ZwddW3X/TrxegEP+xC/X4o/9Hz3D0ykw67GmnjMACuqZoTb/DkoEBVD0g3
         uv7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478506; x=1757083306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=NA7QcB5qW53zSDt6sq7QXtYqr4XQcsQyefltJ7XM5kE=;
        b=Ede+eTuSc9eUhlqRVJDBsRG5nwnpT3v3Gb0SIQQgGKenDZBPT2Jzg8ek1DNPVfJSzz
         Gk4vvUs0eUaFk7qKFPBWAavXi2dtk4Abmvvpnbn+1+5TTGQogI+Hfr8ktZSNE+TPFjOA
         UurZSYSBTvnYRL9yjWqjdJRaYG92V0UbihATSJCwOCZEPrI1k0C8HwxfFLnNAGVChOsS
         N8brG/DKsXaogk6Jvq6DnhHg6Ixnbr7Kr/U3Kl7/Z5fBk+sSBX18IVcqJW6UMgqsw91n
         e04FKjKDPS8Nu7pdPlYR9TfGb6q3dNFpTWrUyUt4nniOx7fBQCH0YI1KONfQU7LnTndU
         W0mQ==
X-Forwarded-Encrypted: i=3; AJvYcCWpcpuOtSdBf5V7FUpoNUeUdtu4NDtnfVr74uSMCB1KDCcOVi82rmWUmPo4OuvUjdP1cW0plw==@lfdr.de
X-Gm-Message-State: AOJu0YzmrOVMH8mmGKLjFQGcsw2zhFbz+XuWeNEXSXbfb/WgYHLL3fMU
	hu5HCEktkn7kQabtdzJ0pvm2Z4GOqtBO6aW0+cVqfEUF5F+KDWb1PtLb
X-Google-Smtp-Source: AGHT+IGT7salb/CqoshRfXtivWm86R+aIKLkWJOvCEv6/ljIsb44/0NW84Rgc57PS2kQk0MweUgIQA==
X-Received: by 2002:a17:90b:1c0b:b0:327:f050:cc6f with SMTP id 98e67ed59e1d1-327f050d3cemr2730028a91.20.1756478505841;
        Fri, 29 Aug 2025 07:41:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdpF6/Itm1Zidebcf32rZcSP6m/uKm1Yqt1oGbBEJ/PNQ==
Received: by 2002:a17:90b:5082:b0:325:7c02:d093 with SMTP id
 98e67ed59e1d1-327aac6d100ls1832675a91.1.-pod-prod-04-us; Fri, 29 Aug 2025
 07:41:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVuma4SRpgAVXxx2sj3XWxUK96oymBdjBH26Ej5z1I93t4yZeS6LY9WQ/iOsz3qRrb3lkxMTvk2hlY=@googlegroups.com
X-Received: by 2002:a05:6a20:258d:b0:243:c171:4774 with SMTP id adf61e73a8af0-243c1714c99mr5057662637.33.1756478504214;
        Fri, 29 Aug 2025 07:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478504; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZtHDyzHHlGQmi9r4d6Rd+56hJFqoBX3pktw9JVjx8F/iIRKaqUJbOPojgHMABGrShi
         o0Lma8KKXSPrmv4cAvZydw21+8p6VRCmWhe3bKcln0LQ95FGpwxCNiHlpthqGECdWCDs
         dzSehty6JcnFatW9g1ZtvgjEIDb+VXScQuMQb3VdLPJommGT2LJvYfUOrUoUBQvQFxju
         bcDZyG2mc0RCI5f0IRRim4i6ld2ApGNpO48Ix04Lm0QTDYKy+sjkM3pNrPoZMX6khXZH
         30wivNMcMV/d2a5GMRnugdo/BqWu2ri/fXmV+ilylRAiFw4RV5A0d3KEQ8QuhZWwZ1o4
         KGlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=CHBK/yCd2y9Udi776witkoyMBgpaQNnNAyTnYZGtC+w=;
        fh=Ob8eTtE71MCOthAzNORoVza58vWJMrZ9tpIAIK2RYWg=;
        b=jLJ32mE5dDccrsWTp4TTy+JmEgsRUrdHl2i7UurJwhdB0Vs/5/te8goVg6e60Ed3IP
         A295ITR+9XNg0G3/KFUzW4VbnK7hVRUCMGzKSA5LQ/WE7wAZaOKtgPmXW8nSIGzmCd11
         q6PK6udPQVjZ9CUGx+sC0Ex2SZL98nbbcl5x92zfMoVrP+uV/2D7cXBzTsHMG++DjIsH
         TuZnbFqJf7JMZF/n1IcpCsTmefB2l9zVS5KO9rrS+3TDfKyk9H99M9SsEipmB5YD9fZO
         qTBmBDvntSRLptzG3ALHB9aLXGjRpkRWhIFGg9aHoeiv29v1thUINchHdFcQ+m634Hv9
         Bvmg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ZhRBgO9L;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AQzInVdn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-328027692f6si16895a91.1.2025.08.29.07.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:41:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCuDFY023080;
	Fri, 29 Aug 2025 14:41:33 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4jatnbu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:41:32 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TDD6iQ018993;
	Fri, 29 Aug 2025 14:41:32 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10on2055.outbound.protection.outlook.com [40.107.93.55])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43dabpk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:41:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=i12ZsvQcHat6JWmW6NbzA0nEZCvK8WaY19xRM9xW/qAV91RJJ5DGdFTCTgiQsVRCGY5xkNgWUS1nOZdJ/x0K42D1+HSXW/FUFZEnLfkfwlLv59TecMaMI7CgBHPzF9mRRxez5LYjVP3eQMGu7u7+8YGBhbR2Z+fWBQCQwjcXO3o9FqRuU3CBFFpb4yfzDBrmIxOhcdP/2TSglKw5kQG18zQbQtd9YL1Z5rlLTcHX2p6geSyuu6OdZJxPKcRC52SAHjev2yiET13Ghv2SYZnhsjC7804WIE3p+KIwzBnvhUjP2ei2PgEzIQhal5YQ9i2XM1qLACGRPmD67KVMcLolEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=CHBK/yCd2y9Udi776witkoyMBgpaQNnNAyTnYZGtC+w=;
 b=jvH292nK9gK5RlI018Cr7e0rpa1qrha52Kj/yLtNvZ4AC0G1BoP5rKkQpQullRtq06yEX+ims68M853mUNJFv8juSisESbxeQ1KgQ1iIsHvlzcwczFU06xl3tcaGktEGPl0vqvbULxXGWZNTWsW4dRtWvJXt4k+6McCVCgcqwed8WvoIg4oD914ki0G6ebTkoMGSftjcwgwseYmGU04vW9hF7pqo1HFeHvI4v7odyQxRRtMtcpZLM/8s82UVzQySC+9kZfQ6+1K5cnt5DbTOgkRf1a8dB/VqyQiE842jn13FunE7FIVcjrpCHOy/71fu691crscFXJve0t4ZNraT4w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by DS7PR10MB4928.namprd10.prod.outlook.com (2603:10b6:5:3a1::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Fri, 29 Aug
 2025 14:41:24 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 14:41:23 +0000
Date: Fri, 29 Aug 2025 10:41:16 -0400
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
Subject: Re: [PATCH v1 12/36] mm: simplify folio_page() and folio_page_idx()
Message-ID: <oinnsfpimax75klq74eb3orjaoipl6szcjlfhfes6gvnmyvb4m@xdpb7l3igqt3>
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
 <20250827220141.262669-13-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-13-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: YT3PR01CA0089.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:84::20) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|DS7PR10MB4928:EE_
X-MS-Office365-Filtering-Correlation-Id: e0169503-5758-4f9a-60c8-08dde70a1fea
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?N/wuaz7jp/N1IXtIg41SSxEOZIl2Jsi4hG199GMn3DuVopZybGA/g6G6npU4?=
 =?us-ascii?Q?T5+AW0iLm8xEuiSfhGvcRs18LzjB7jFad650At5UtGw7zPOgxTsqdDb4NkyV?=
 =?us-ascii?Q?2bLSs0zTHDAuyuOl6LIydQq8yFMQvkgReA9MglLZhqRb2miruSZU0zLn+NhD?=
 =?us-ascii?Q?RcQYJIabkVPPphiEE9/xzQgDXSudqhNG+9tF4m1j2FwiWJ/Md3ATB7jPg3mt?=
 =?us-ascii?Q?KxNUbGvnLzmQOdxjeFOJri+9gw79BkmB+FLS41z41O/ah3KK2bSoc/l9OrgS?=
 =?us-ascii?Q?r70qW7QToEMrl6iYnigVj+6/CxIn3duLp/FSG1sIgLp5wlPsr39fz5GBVZ6a?=
 =?us-ascii?Q?AJFIfXWoTivknkk8S8ZjF5HzkwGYEd/LKWgvS+hJaWF1JCukeRY4qaOrXldP?=
 =?us-ascii?Q?KD/ZoMDBdRVGSmp0p4X70NcVZA16v6ugrFgz2KNNswZXN3wpD8kvCf3YpDBP?=
 =?us-ascii?Q?Uj6WjO3UJ34GOLqZclIUrSf+VJi6GijXNkqkrwk8WZWlG+dfyxwYXS+HlhZw?=
 =?us-ascii?Q?FWioXssObwBnztduIFp3EOTTET5ZTk2fKuJs2iMHsp9gjiGgfq1S4LyEW0lg?=
 =?us-ascii?Q?ryA0Lq5H7qAGO5azoj+f0cNZ/OkJYl68UyD2v9guMQE04I73Hl8umrSyHIFx?=
 =?us-ascii?Q?ikgZYvwjngRHpxfNuu4dHaTB0UJcNP5ltgU69W2+1nqKLCM7LwJjN3TTPiLU?=
 =?us-ascii?Q?Im7UzNZ/V1uw0B/ADcMOENRdml97JD05s5ycoO23/FpK6tnt8owGK29hlIvw?=
 =?us-ascii?Q?hqguq/lVFRJGZAhflF9vqbckJBC8CtIjSbNXnNvnZ+gdhsuEmjZzE+mWnxEW?=
 =?us-ascii?Q?0doE3h4cckQ43wHtcsacs5WKutIyq9vh4POYjQEhsHZeWCHbgs0V1bTVUV9S?=
 =?us-ascii?Q?aHCWq6mPUIAy5YTeynPXUzoT8Km0sCkTWY0DLdsfyHMB5g0xmeN+uQdtiKD0?=
 =?us-ascii?Q?n3TAdlt4BvqAK/ExE6+SoKg033AU5gdbkmEKVB61ZPlZ6pNOzqAsJhgCL/IL?=
 =?us-ascii?Q?bwtio5G2mn6aL9/cQKJwYRPDj/j1WFT7EkoOqVOJ8Tp3ACSGcNQDym8GoWOF?=
 =?us-ascii?Q?ec9Z4taxAuxPufrPaDQtl59hiqMnKoKn6Cskk1BEO67AcJuSRP7vDH6Z7liH?=
 =?us-ascii?Q?fnHvU/6rTm1OiRzlZQRApHLsgue08sibH/+Tlmrt2O78bgT5WZohLH64dRWw?=
 =?us-ascii?Q?fPmFjHeVNwDf2U4MUfihzDyTjJaxKuNNe90vV4mwM3Kj5nvXmolZX+RD/9IA?=
 =?us-ascii?Q?6tPjT3I55gBfrPmTsncNhreBfQ9ekGo4Ba1kk4vDWMU2JiwozTkUcaATLKNy?=
 =?us-ascii?Q?QVpMgY7BGQlTWG1O2jnyZvaSZpWuVLUSptLToaVoKfbLr/8FPmP6eTaXmbQt?=
 =?us-ascii?Q?dx1plocNWS2Gx23A4+Vmqr1nib+0SHcA/jc8iVaRTzh+4EJikpHLcRgTpEzv?=
 =?us-ascii?Q?NRNji/o2vDk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?dNxd3tP1q3UBS2PB2/5qjKXvPWH3Y5YXoeC3b3HNm5UMdlmh3+nMfmBXHEAG?=
 =?us-ascii?Q?cWzLRD7/0WFqitzFr84xEFoGsCmmtcOgXVv3ZwyCO6SdVvgIofnKUHE+xY+8?=
 =?us-ascii?Q?Z+cDrwA8my60IYGQRZeY0MDGOCXLUcwwmQEYkNN5YCIgKDK3i+mIVQw2vC3A?=
 =?us-ascii?Q?dhSTpytX5UI30D+TKy1VbXiOY4LHnNrnIaeimtJD/2aLAFSg5RDghD5hvoLD?=
 =?us-ascii?Q?DWwkmkiptSCYrUDUu7m+6OQLMdEAl3NSTPFwJ90S5hxGKdxq3AhlxROYIPTj?=
 =?us-ascii?Q?y7+Q6tsZcz+XlJFeZXH93vjAsGcflJhAIuSlR685Mzd4kieu1AM5PBTL+NmU?=
 =?us-ascii?Q?Dri1xRmD0Oot39kubsFeswVlrFPBm3mGa3SkJXhYqwk76p7QIhGfqdtvqngx?=
 =?us-ascii?Q?3XQfWOkw2KoQo3Gqel5kBw20/Arq53TI/1nX56TNDr8Dt7rZpexijitgTPgm?=
 =?us-ascii?Q?dPmi5BgFa1x+XynBsR42NBUsJusc4lFl0XHZmRPbDYuInnmcvyVqwMKt5E4R?=
 =?us-ascii?Q?HqLVVuKUdeam0PMO5qAEP++swYDCPeO10X5KFXhvztsQadIbSsZPz9V/hihd?=
 =?us-ascii?Q?18c3cX6cdwrsHo60YBYDoIFvo9lgCu0TG82V4+X7domZ62GnTq70tWR4mLx+?=
 =?us-ascii?Q?3VsP4bnI8ZdDidwLm16aCGCBGff+r1+9v/YeT3Uquvq4uC9i6Exa9YBiWAe5?=
 =?us-ascii?Q?djx7NbCykd/mJDog3Clb4IAG8tGUa2ssVN3W1VJFMzew3SiUcswQvrCMwGs2?=
 =?us-ascii?Q?U/IFE02wb3jcsvRqoMHGoOTsU0yBD6c9iPi4iWaPG2Pss7LO6+jHrC237s1C?=
 =?us-ascii?Q?unrlq3b/xN6vwionb5VLxCLQuy+ovodE6TqLB+4xOTYRPMUCYFFVXrLPD7s5?=
 =?us-ascii?Q?RTSWxW/hRo3G4Krq/zUo3AA3/TopghEmGJFf8Ip2c1bsNTiLCfLy8yAUGX6r?=
 =?us-ascii?Q?5mLNd+urP2fx1mtcWzODg2+yO/nCgFyxGNgnvIfSOq5E/IApVjaTzlLxx00S?=
 =?us-ascii?Q?yFT8Gnz10yoIw3fkvoOdxB9l+o0ZKy8JRq+CxX87pt4Jr3kqqQOvbr8ekLPf?=
 =?us-ascii?Q?vRis0YvLkUk2SyZYh+JvTg+xSvODj9JxKtNyGN1QQqHTner+5yfhfpe1ctnw?=
 =?us-ascii?Q?IzTgJ2ILKT6d5AFv3gaplIuZtp0tKEZmzENtpQdTGgAO17YhpY/QWYPBADdx?=
 =?us-ascii?Q?JvXgnVRwGjOv16XOJz10x9X/gmxqOHaIoNfnvShcBO079sHKSZwyfucpU9dW?=
 =?us-ascii?Q?tPGoE6cK7Itw2AplS22cetJr4Q4o3ialEbTNzicu08crJGSMW0k17VIAtMtB?=
 =?us-ascii?Q?bmfl9oy2PjMtyl/Uywrj+Kq3qYe2lptdzVovCgAYrsrizL9Hs9IqXVGt6L/8?=
 =?us-ascii?Q?0E+jnsI7CfrbtE6sv8FyJKUWdFJI5KtcscPmEGFp5K3lZgaDEmd2U05xwvb/?=
 =?us-ascii?Q?blT3kJbHxlvwY8ENbkhRhc9Qw1+dD75Yx/0S5KIazdOIPyLrL8nU94JnzDKW?=
 =?us-ascii?Q?7IfxBpGS1/DHvNd9hH3Gqj5m0GhHp+ZdSRupT47p1Hghwy6yj3anZqZCtsnn?=
 =?us-ascii?Q?I15i88YQ7n5tBGkaLfEt7luBHxDcFXa0Vcx1BkZC4MUdM8+D9iPvsz0Qfm0L?=
 =?us-ascii?Q?WQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6GiuuMB13CUwzIm0LYJIs9umdinpazr9oTzAOH2w+PS6OMaBHt2UX4mXWAIpmRamETf5662MI8q4msAJRpd0I3Va0q2HH5elAudxaM13rNcrfb/FzFJRmwJPBD9KBvGjTkvq4of6H6Cl2PrFkeRnMr/LDiFgLWq3Vkr/eSXyX0OklSyNMCwyOK3mG97hUUfhkcjuHqCZnAC//MqirXYx6/mrlAd5ANcs0FsnKs3ykXLMBtl/ZbwJgaKFNKOjt4avbQvIUpDyF+9q0g7q/dCxgM3TDN5yFb6OCRRp981WN1t/iTqFJ9V6jKQaBoN+mstBOl7FGAQjN9BmZa9jjblVEDeKEkX/rPJufPSC1K3CYGI35EqrLgYv7H5fe9avX6+/Qt88PyqCm/px8qIJODjVIhl/rTfPGjk8IPm8P2JKBwSgfMDTYmIaxXdu0cd/YHtijYSlF5IZnO9zAZodWdi1EEvxZf5JnuNsq2m6cEwThRMIveJqduwaiaX8fRxt3Hu4UNwUBn36+xLaE+lDYhYsK1lf3lhkdaiFYaGZui5BwELtycuGsy2qnGf8E1BdOztCPS0mNuFMNtI7UHCvnErl2sHycRCcYbwy+suHpv+Dufc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e0169503-5758-4f9a-60c8-08dde70a1fea
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 14:41:22.9856
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: sE185fl/rrcNYjNJ2YBR+wuAF6OEfLr+9fcS6SeKOQg/N9ATV/iSLBfs9GgWWvVkP+p306AMGEFkt2DILb/cnQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB4928
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_05,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 suspectscore=0
 mlxscore=0 phishscore=0 bulkscore=0 malwarescore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290123
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxOCBTYWx0ZWRfXxWdzdUe2K2Uf
 jCfcu+ZfuSc56wZ5YeDqiD1pUfhYsuEJmdvJkN0K1000M0L+bact4dxkNRrW3S0RkBsiAR4sljP
 qnj09p44RVwRd6Cy68B7RerUkz0pb5mI78/F5U9wi2mgrg/46rmYhEbyVEoKPCmXRRCRPh0/yeE
 V+xZoz/BCJeCLUZ1AhNimZuImBze80JobeLHWAynegJ9Hw/Py18XXTi6h0MkJzyoSyhSqGqQWzw
 Ehj+K97caxMsYgBhzUpmoF53E5GYQYKmBBWyBp5/UwBJdiGX84UnlW0riLCDYgGXohLnvyiSblf
 SHgAhaBcMUrrxuFFc3ohV76UReV/1CwMc4VXeIz/xOn6PEQCTBh0mENtxZnLmw1tP2K3uMtoP37
 lg8gOAYh
X-Proofpoint-GUID: cKFhcsBQfgh6ud7DwqlZobdMJMRfsl69
X-Authority-Analysis: v=2.4 cv=IZWHWXqa c=1 sm=1 tr=0 ts=68b1bc1c cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=yPCof4ZbAAAA:8 a=0J61nuS8Vg-Uhu75psoA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: cKFhcsBQfgh6ud7DwqlZobdMJMRfsl69
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ZhRBgO9L;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=AQzInVdn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

* David Hildenbrand <david@redhat.com> [250827 18:06]:
> Now that a single folio/compound page can no longer span memory sections
> in problematic kernel configurations, we can stop using nth_page().

..but only in a subset of nth_page uses, considering mm.h still has the
define.


> 
> While at it, turn both macros into static inline functions and add
> kernel doc for folio_page_idx().
> 
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  include/linux/mm.h         | 16 ++++++++++++++--
>  include/linux/page-flags.h |  5 ++++-
>  2 files changed, 18 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 2dee79fa2efcf..f6880e3225c5c 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -210,10 +210,8 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>  
>  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>  #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
> -#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
>  #else
>  #define nth_page(page,n) ((page) + (n))
> -#define folio_page_idx(folio, p)	((p) - &(folio)->page)
>  #endif
>  
>  /* to align the pointer to the (next) page boundary */
> @@ -225,6 +223,20 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>  /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
>  #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
>  
> +/**
> + * folio_page_idx - Return the number of a page in a folio.
> + * @folio: The folio.
> + * @page: The folio page.
> + *
> + * This function expects that the page is actually part of the folio.
> + * The returned number is relative to the start of the folio.
> + */
> +static inline unsigned long folio_page_idx(const struct folio *folio,
> +		const struct page *page)
> +{
> +	return page - &folio->page;
> +}
> +
>  static inline struct folio *lru_to_folio(struct list_head *head)
>  {
>  	return list_entry((head)->prev, struct folio, lru);
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index 5ee6ffbdbf831..faf17ca211b4f 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
>   * check that the page number lies within @folio; the caller is presumed
>   * to have a reference to the page.
>   */
> -#define folio_page(folio, n)	nth_page(&(folio)->page, n)
> +static inline struct page *folio_page(struct folio *folio, unsigned long n)
> +{
> +	return &folio->page + n;
> +}
>  
>  static __always_inline int PageTail(const struct page *page)
>  {
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/oinnsfpimax75klq74eb3orjaoipl6szcjlfhfes6gvnmyvb4m%40xdpb7l3igqt3.
