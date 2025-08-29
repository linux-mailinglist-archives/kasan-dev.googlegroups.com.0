Return-Path: <kasan-dev+bncBCYIJU5JTINRBV7HYPCQMGQEBGJEYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E017CB3AF1E
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 02:27:04 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70dd6d2560asf36701706d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:27:04 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756427223; cv=pass;
        d=google.com; s=arc-20240605;
        b=JwKoCjUU2DHkaKVnOMCyrrAt0NCHQbfFZX7Yo4IP2621LMKENlVIoLm1MqZZlJeQt9
         hW6ReJ4on+1aOnf+IlWU7fWz6aFCBcy5GiRh0TCbQjTkyQ7Pc8X6RMkAnDjg1iJvcEF3
         6IAp7qVsBUo4f6+KXTg7MZWV2P3YhlXhHHfGFiLVukkljUKFdRCUgoCzIjzNLbVCuHCN
         eogFTaaCxAcLaNgP5zf9cCPuH4eRdvvB41eeEHFFr1BuY2te1/ZJB4nfYtx8aL4fZukY
         wGkEBNVRvGD5EUo7gXbiK4CceMBawv84qaL1J4gefsGS0q7Z/L1VpN0ubYc3yj1RByz3
         dtUQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DdNzqoMAkq22Dy8R0vEbVYjrR4XoAbOARWZ6EYwVZDg=;
        fh=mYU4RWVIvIzu0auBW4MmsIBJM4nku9Fc7T2p69kGj9Q=;
        b=lxLYGo3XVkGkmcZwpwVPcgPDbSCe5Wi5bN4b35mBg5ZKFeQgWOyusMfVgtFUXYHYte
         HS5dEzX/qxomt5xe3sgtgRPzLlz4dc2lI7xGQhq3cExZPWNqQhpy7ysYj6UXk+hPWEMt
         DdAAuyEAqXQ2vK0kW7AdeJye6cIZV0Y6wcfcIYHOYzJmQS/uUPdm/zzdpbWDIIcMNWHK
         2yKm8qihypbJPK6lo8W08nLTntVbyGAnF4cur1IgFoHo0+ylQiJ7/SwLvdt8cwda4c1y
         117N/CfkLmuCFRRZ+ZAkRxYMz80JmsPe4m+MqHAxy1ZsVG9YtYc1YyAKcRMwiemvuhTT
         ZfhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Ly9Hd7B/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Lu1yLvL1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756427223; x=1757032023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DdNzqoMAkq22Dy8R0vEbVYjrR4XoAbOARWZ6EYwVZDg=;
        b=c7QIT0G3XmSUuD/hURVGwf2S0rNfOrP/CdDRZjTI+MR16LUaa3XHj9Djx+iV86/sRc
         TpxvuKHpNgPnVgLlUjRFrFJTG11a4PCrAnb/RCC4MtPuZ5izDYJw+hVPNkdk5dPy8HqF
         yrwZoYxpEHn+0RM5UU6u2IfLatwltTOlzE7qUkvdYKijh80JQLxl0bNWE2TXgeevkZh6
         l/z3TF0J0DUC1PQQwuzliWf00Se43FmiP4YCHQdGF8Et1lHLYJkDGVxSFZLJgfhlf/G0
         /lFuLh3xGXTy/VQpuV0EghCYkvLI9YXvNmm57F1xhu1p/JN2i8aPClnXTf39l1USKrD1
         ZX7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756427223; x=1757032023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DdNzqoMAkq22Dy8R0vEbVYjrR4XoAbOARWZ6EYwVZDg=;
        b=U3BMh0I3Ai40MKLh4CblAXZ7vXcNOmy7hTIKQP52iRSvlaN3HbkdOeepYOyUlNCuVZ
         GyqZoaZvcBpBV3Zgo4OKQtXiq6HQChPXjf/dE6dRTuvBErwms15D5V38gIYqZTKLp+pB
         FVabuwoCfl8punNCmIDIRuqab+g+QMjeNV9nRO4kWvxakABy0zPfl8Bjmwj9pegvnDNZ
         HaSsEdUhqXgQ9AvlNC2+0zZfkmWqzWQhzus9gIGc718/DtW3EisD9SREDxP3tT4UCz66
         pbtaQ3QZiZ5X9ffy6FizkqIysrTn5TO/i+cM/t0MzPRBpugzE2ar8pySaajhWYjFH6or
         ktsA==
X-Forwarded-Encrypted: i=3; AJvYcCWDRGCt2q3WMy4b/S12NlmwveyzciOpkrP0ac+IK7hJTsd5gd6hPcaM+tF3gwC5MbS3EDywNA==@lfdr.de
X-Gm-Message-State: AOJu0Ywdn/7PzfkoXWTJCC+RRDKggpw3HjKADi4mQ2sNtly6NEA8VSHE
	3seEAt02eY9r+h+/MXHW+9d1XHrFBVD9prUo2fEkODiDRi1MZBKUGwsa
X-Google-Smtp-Source: AGHT+IFL6GQmgissXGFNml4yZvBMXBGGP+YYKZCpvzGmhlN94cL3JvOKDHK0BpkF6bV/d0sYpUCAyg==
X-Received: by 2002:a05:6214:c65:b0:709:f328:8ec5 with SMTP id 6a1803df08f44-70d971e42b9mr326921316d6.39.1756427223600;
        Thu, 28 Aug 2025 17:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdu1tXxqrGG4rNN9mx7NXe1k72qhAlqaaGA7aJOfrLBJA==
Received: by 2002:a05:6214:5298:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70df04e85a8ls20142146d6.1.-pod-prod-01-us; Thu, 28 Aug 2025
 17:27:02 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVHxxGIbUnvjJhHvlxNzlCIHBnT3jExsH704LziprwiCC53DD5zFL8MHmqQ1zSHmlxOsx50hRiPu20=@googlegroups.com
X-Received: by 2002:a05:6122:318b:b0:544:6eb7:d7c4 with SMTP id 71dfb90a1353d-5446eb7dd23mr2670047e0c.12.1756427222708;
        Thu, 28 Aug 2025 17:27:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756427222; cv=pass;
        d=google.com; s=arc-20240605;
        b=LDZsMnlfrhiJlvnxprM/FF5z3jZQm1xM38omyq8B8BpwXNeAXOjRpNo5vj2and+uEu
         m5Srp0/pG+pj6/udP1EOF3X0/hKZRd6d5Q0BVXTrRcVNLx7UKuT2uAMzmc6rqntC6b78
         /VkUttXGvYuwtttZ51g/Ce+z74qyJ3r87H4utISRrNnJ38zOvSXUurf/zbr0YluI0s7W
         woC8KByb99c+lUs9pJxlMQwVkD7b6ZJvO+zZ6q2cEQ+36JEPSfD6D4GsZXzXKc6MKCjH
         CSnJn0lWA20lm33Vq+gmasu+eM4pNCOCKy5cdUMvMVfOqDQwEdR27LVh3BI6HaRofJvJ
         lr4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=7WzTD6ZWd9axqxJvOi/47IKvcT0TJ7Bxqohox481SGY=;
        fh=K4IQFEAV3eJIooQ1P7F3K4p+EaThPcTKx9Yfl7lMyng=;
        b=iKwJRz2Siz/yyYSfgYR+ZRWwc3zBBds4LYTQfXQbKUgnzK4Y61qb+93DBkfVwSeJC7
         7tX+hoL4IqbN6fu4/noigwW6k34lNGV1ZRkhIhx7ZLK6UQz6ZmsqBkchGQK2hNXOZqfE
         tp0F8QUEu8V24ARnBZ9pGfJmTP/VqyNR6lk/+wXXZoeoBIdEHucDOGuD5FxMEsTsuvU0
         yyuTYfXUyQpCIkQyPWQr2UC8nc04tuRrcf3KqHVwCEsrcz3AI2IaalIQr1C+pRxIi2Gq
         RmQUZmSeTJ0VinQtL9HOT04SAoty74O8Yitr7q4rKqVnhTZl0UMrs8N3zFayUQSoZjwt
         +7OQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Ly9Hd7B/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Lu1yLvL1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54491322008si10248e0c.2.2025.08.28.17.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 17:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SLUx6u015369;
	Fri, 29 Aug 2025 00:26:39 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q58s9jwr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:26:38 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SMIcsa014593;
	Fri, 29 Aug 2025 00:26:38 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12on2082.outbound.protection.outlook.com [40.107.237.82])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43chyd3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:26:38 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=t6dygJFWSxpawEWzxdVpehp46DlWBjl8+Imxp3jRT6zFcGxmUhcsR7hbxYjDWkN14IpzXwQrwmul9Gnl/L4jSD45NXZocU0GXaZz1qmP0ZOLJjBbQ0Bp7CTEFSggWVfz4XBAr4BUSO5au64P5it3y6elBm1taxwoTtBwwNAV5bcsxNcxKURPN2QZdrgSZeLJ2XocdO6o2nDvq+svteBuRHMoPrCkcvtZ/bN9dDYolDsl10GGUEBOLedLyqieBFtXTsjXE3MdzyWbWyjrE3+roejKOyiU8XzE0KhXsfT0sJZftqjid4PmdIjXYSZx5+h6mLPs9FJm/GlkbBWUHCX8hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7WzTD6ZWd9axqxJvOi/47IKvcT0TJ7Bxqohox481SGY=;
 b=jpGSW8pTGvjdHOnteT5WUr7Kd8HfwGjqSba55Lu5A1SqNEIus2StTp/sPMXfMIopwdjKXq7+4ml27FIbCPqdDlpWJWneVsDUuR0XRrCjzMEGXqHs7ykiPXkLLfuu8AnbIkfJNfnegrFGKA94ngNkR3pf9aThZjc2fF8dQ3mh3Tw3GBiKaDGdkTlzDc//kHmeraAtHqqjq2xWElBGP2aqsYPdOVpwTGD3q98kdjLWmLkLyAb550gPRherTGiuXcWqOglT7QbUdLM+QfZ2ZaTFzF3MWCFZs0ncMXGILq3G2YpczUBWVbopcqTg0LWSPcG8LYA7lsqYQ8kQjP53odB0dA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by PH7PR10MB6481.namprd10.prod.outlook.com (2603:10b6:510:1ec::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.17; Fri, 29 Aug
 2025 00:26:30 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 00:26:30 +0000
Date: Thu, 28 Aug 2025 20:26:22 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        SeongJae Park <sj@kernel.org>, Huacai Chen <chenhuacai@kernel.org>,
        WANG Xuerui <kernel@xen0n.name>,
        Madhavan Srinivasan <maddy@linux.ibm.com>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Nicholas Piggin <npiggin@gmail.com>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Paul Walmsley <paul.walmsley@sifive.com>,
        Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
        Alexandre Ghiti <alex@ghiti.fr>,
        "David S. Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>,
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
Subject: Re: [PATCH v1 01/36] mm: stop making SPARSEMEM_VMEMMAP
 user-selectable
Message-ID: <imcmdidialtrylnkj4sjqmciwwgbpzsplavazyxkdlebrc7mey@jnm7wh6bjk3p>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>, 
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>, SeongJae Park <sj@kernel.org>, 
	Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>, 
	Madhavan Srinivasan <maddy@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>, 
	Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, 
	"David S. Miller" <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>, 
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
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, 
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, 
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-2-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-2-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: YQXP288CA0015.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:c00:41::31) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|PH7PR10MB6481:EE_
X-MS-Office365-Filtering-Correlation-Id: 337fe588-fdfe-40b1-d678-08dde692b357
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?7PdM898Jd3u4PTlJM5FPal/V/unlSYcLlusdxt7aCDBJPRsyiVRNISQHmLdU?=
 =?us-ascii?Q?Rh/W7WSB6rVSFmfY3ziwBzbUISlsk/BPIiZod1dan3xQWQ0jTlaPFORTIA7V?=
 =?us-ascii?Q?4RiEdp/0z9EbErlyebNyabzv8un6VpMaICQmdGmxwr2OTt/hBzZfrPjSKJTw?=
 =?us-ascii?Q?N6i9fnGU5y8wTLN5Dp5RQuMsB0FKwvOwIUpFv5XeueG5lCeIYBurDlUlI3pn?=
 =?us-ascii?Q?7SDtOXJdLL8VW9XYYGH0DDAG6i5ZgyLMze4UoeHtsf+Rt0/SFZlOSo8zmKQR?=
 =?us-ascii?Q?34Lll/hvHlLsOEYDxFrcWT/JRpFi6zYvQAzqKUPMWF9cz5nIF8Trg+VU6vOC?=
 =?us-ascii?Q?E3e1VjhP4BSeiOdaoC9+eS9RIgP8sCsRXdsug8hQJDD2dsjAmLxi2q7kr5Ug?=
 =?us-ascii?Q?jY3MwG67DIMCkicNjrLYJ9kNyQWL5NdcFOGrTZYoTKk/xwMGLgtFNF0XIU0x?=
 =?us-ascii?Q?RzVfMcOzmIdc5r9L9FrDv9YPmahjukcppXW29Uo3FA1uPjgYvHyZ624+YCY7?=
 =?us-ascii?Q?8Z436fMAdH/+tCL8Z3al1y7GcPxe/pzm9j+np4i8fix3q21wQS9lyMyUbfBt?=
 =?us-ascii?Q?rrqYENzTmk818O9mvdRVxntQTUSfLZUTwXxcCRIFYGsZSAUWZudyeY/uI0OZ?=
 =?us-ascii?Q?n52b+YnIlyaX/A7/yoM0clchknJ+s+4Q71AZPvUeGPGOQBFWBr8tUBMxC0rl?=
 =?us-ascii?Q?CkW67+7qmEORHr9wDRDwgc0B2bjxVKr11Tj94Sq1H/go2IWE53MItTjFTIlR?=
 =?us-ascii?Q?8FUP5LAOP43HBNFog6a/rDfc+Wed9KG2GdpsI/jN70NHXuVtt2KRJpNaBPkG?=
 =?us-ascii?Q?LFz/QCzkjr8R1Tm15H3tl3LEOklLVwlkKZX8A5IFelVrt/QXcvjk/dNzg706?=
 =?us-ascii?Q?XC3+Is+uvqkYrm6DS88d0k4h560xTxb7AKMXZxjkk5wsuux1uzT3SadsIbym?=
 =?us-ascii?Q?9NOtuTgF1U3eDr4xBo+AIpazV2CoyHoblN0O7OaaXka1b6ZetcIWMae3rHD7?=
 =?us-ascii?Q?aQoICvXb3F1zQw3VIoCH8vqpACT+cPaLK1YpKHrxjoo9y68bQw8dV6AfznX5?=
 =?us-ascii?Q?Hv+fjdInIFSW/wafJVh6KTj0i+HZKHPXIIgKH+/qoEaXLdYcHWUErjl5QlCS?=
 =?us-ascii?Q?ft3OXaDfM8vQdavYrzk+p1TFgxjz1gYqMhjzlCp3/hWC5NUF4vCRCeJbnRka?=
 =?us-ascii?Q?OXDkBARXSfqD04pyn7OX1r6TFkReFvskOJyh1MswJnIyXsMOEpzrZafuyrze?=
 =?us-ascii?Q?kwlME9gYSYdjSj/ChuUGnhNSGiPsWWyhdnCxxyam1I0C1NH/Ry8gwx89vJcY?=
 =?us-ascii?Q?X4uUlEwprDdmqA5/K00waNgdXlck2tvsPiydgLU1TYu160x4ukqh6XyN3Y3f?=
 =?us-ascii?Q?0FfqOC6ZtYZyHMa4ZGNRLhYlLl8hxMaUEDWLlaAxGx/0REFwLYDF019bdni6?=
 =?us-ascii?Q?kmr+6Y1kbE0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?b3FDyHmZEm4Oowh3gHKp/axtPWPkN5DAogkN06CYLJu8pT1Zfg+5DMGddkU7?=
 =?us-ascii?Q?9GrCLP7fhFWEZv/ZUEEy3FE5UuND1IQeOcUqX3YFsW7fr23drBvdQXigUB60?=
 =?us-ascii?Q?FuNgpRYsNK1b6OCbdGP+gVlV2q3mQY6SI42fJaqLnqH55hjfku9ZAhbzVgYB?=
 =?us-ascii?Q?O3VdKQsDNdPnoPpdoNfpVLbSOgjsZI9A3aD69m+U12jX3ThsyomUVejte3Uz?=
 =?us-ascii?Q?hKZeZN/sw/HNJdLXuJHtJOEpx70N1A7ffVG7dsdNr/6I4Fci5DqtD2Nu54U+?=
 =?us-ascii?Q?noQNkmL9lfcldQc/ABjIOq0WCKahAOUK0Y99eWua9rlgTMmBvcbB2wveDCes?=
 =?us-ascii?Q?/TNwWGa3P6zxtk/BfFgBt06CRK5e+8wiOgrJStm46TCeZ1Jf7vQOCAcaSJmG?=
 =?us-ascii?Q?s1rd6N597AqjqjXn8UqtpilyxQz9jNwGd5ON2yajHhNElXXjuwH4vONmeK/T?=
 =?us-ascii?Q?SzFgUM84MX5R0zR+qYD7u24XOGj0VD+OXaqiUKVNGEp2LYXfk+mIbEnzd/fi?=
 =?us-ascii?Q?tdMXukb4VMBC3VQVECSitME7bVspUHx0NLsaeeQ30Gk8qquhMuIp5shXZyY8?=
 =?us-ascii?Q?YmkQXmPhaSZiDN4UbwfhVou41OTQQH3ZtTZu3En4PPp3X6d4OCJPuZzt0Ytk?=
 =?us-ascii?Q?j/os6kBk+rsYuifuqe+5+QeCcsNa1KQGyZvtuoUViWe4z9Fs89Hnb0CiBftM?=
 =?us-ascii?Q?9RVOMUlfubLv8a0s7/xmya/50ZnjhW3KHuVqUCVc3dpMVstLssTMgyz4npel?=
 =?us-ascii?Q?XtLhg9/HS32Ax3zkGRLeXGZ9XlizulJEwn8Sg+eIhi0HhKDU0B64jUXJMGzD?=
 =?us-ascii?Q?uGKXGcJ6PlzSmKv78cXB6oHILMhpX/5rW3vAOZUkGCq2Ls8ZHL3QPqkF0d2Q?=
 =?us-ascii?Q?MMb+xk2cSBzjGmw5JkBZZTeR6qh7IIGZRjeo3FDa8I3YYGCjLIXmOWDPE+Rf?=
 =?us-ascii?Q?1LIye5REsZcWw/rOHgsUdvnNN2/uAwtXpkeejdnay+YM40cs6fupCamy8ALy?=
 =?us-ascii?Q?cqOt0xL2NUQsGD1h7yEIzgpaM+qetm/25YhiHFvF2Vt0rxa+V9IaVYLAZz51?=
 =?us-ascii?Q?Yg+IHtSmgJmn729aF14rrwWGHNongo4Jgi2++XR47ChJqege8WxQPHdK4gs8?=
 =?us-ascii?Q?cfuaGD26CHKWPkBUepv05hIC19v290jBMcEj3W+hKo2RBp2FodiQbSICA5v0?=
 =?us-ascii?Q?8n3Dm2dAZbJRrJxYAsv7+f84YuzkqfXkFa8odSD8hFMCxyJ35IeNiI04aoIa?=
 =?us-ascii?Q?MzPJPBMOUvPg7fHgfpucD8MDREnJOrEXLWfeRzgQayj8HJC8uvyrUJXWbZa6?=
 =?us-ascii?Q?k4KdbNxHXSnvyxf3NZSzQ6jU3LfN0eWqEtfdM8oVRyDnhD03K/NDfD/HaFUB?=
 =?us-ascii?Q?rvTYSLQK8IqLXRhwjHX1Q23vjK87v45P2e5sb74+UQIiDulCY1cDqlqJbIjX?=
 =?us-ascii?Q?VgOc3ltx9t8SYH5m9AgIE1iYR73FtiZQTPu6PiSmiVUUE4DXuManaq/BAxIo?=
 =?us-ascii?Q?gdCBI6LlozWvtKJ+duVc+L6tOoqxNyf1tzWQ1cOANWpBGcsymkhRK/4hcyq9?=
 =?us-ascii?Q?VN6lkZKV1kb71iHK4BTzUPxpQEPRbPlpohSrKsbdh3Q597kOOg0OwAKXStVA?=
 =?us-ascii?Q?qw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EEVfXIvSvw+jnauws45hnF2tbxeNJ6cnRmv81PWW2uanoc9QiaWFD1UZR6Sjz79OhEKTjo23XYPwdIogExkQwKpaSdvYcI7X9P2yKbN59lozxTHeKZNhhariGbiFYmm8BDPmwLncHsPi9Scy84DcOhVe+qPsaffjjL51msTXCDtMg7X64myiAd2U6n1MuIpc6LZSEOJgqzPSEVUb8ZrrY+XhbamO0YhQAOMURtAaRWkn8c/UxfLGiTJLRa3PXhkORGddCzCqaTbf28YBjVqxpUTFgDWiCVcKWPGkOwTYjyo7+lWs1R7nt573t9KSOg1FuC+8HVv2QSvnKgO8b7pDTvQF4PTsRSd//v2q6OQhM6LdYuT47epXonFOh4GG12oREJ+c76PdMwcUuJxXzcT3vhCcDpG5SCxQuieAYgwlR3YSu0/D2who1S/i/RFDPrTjDOCBYBBRJVJps6+ZD7tURisC3+dSG6hVQKuEc0CzrxCEGYlH7So3f6L2GqWZ3KeNaPwdHCZS6+TsoDkBOIXzocUdGr7KUoBiod3cRPmmihRwP8QX7Rko3gZicnYkz2Dt8ulczZjrCzL2djS/F7Cl3xe5H5PrfVl15tgRgoOP+oI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 337fe588-fdfe-40b1-d678-08dde692b357
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 00:26:30.6784
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VwdVTNhN/b8RTlQvwoAkc0KBGjsllb8bvRp29OAstWP/++DcLmavzIsQSo+sEVLzDiYkmozIAnBndBVb56UNrg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6481
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 phishscore=0 adultscore=0 spamscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290001
X-Authority-Analysis: v=2.4 cv=J6mq7BnS c=1 sm=1 tr=0 ts=68b0f3be b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=pGLkceISAAAA:8 a=1UX6Do5GAAAA:8
 a=pFyQfRViAAAA:8 a=_O3DOGVWAAAA:8 a=J1Y8HTJGAAAA:8 a=ebG-ZW-8AAAA:8
 a=yPCof4ZbAAAA:8 a=3kAz48_qQRIM5rfxVM0A:9 a=CjuIK1q_8ugA:10
 a=Et2XPkok5AAZYJIKzHr1:22 a=oJz5jJLG1JtSoe7EL652:22 a=2TKV-7w1aU1AVAwN0oqT:22
 a=y1Q9-5lHfBjTkpIzbSAN:22 a=Bj2TwAA_C77lQ_X2_dkp:22 cc=ntf awl=host:13602
X-Proofpoint-GUID: gUJ0MDkluHsVVrgEE3WqwkuCNFAM-xYG
X-Proofpoint-ORIG-GUID: gUJ0MDkluHsVVrgEE3WqwkuCNFAM-xYG
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAyNyBTYWx0ZWRfX39KpAFosgaI+
 6AxJ+Drns8ZQq3DKNpTTI7tfjYyjbPqsKEDy1MvT1fzSFVRUn4Sbnaebbe+QlnWqNTvSyZTbaNA
 AtJJvc1CJyJm240qbvZ4NobTKTOSLbw7m9T74CuNpPqC58mp8DulC6AbgBfwbFoOd0wzuUlTitX
 CVkLcVEkTHUl9rcnpMWap/LtQTOtEg/KSdasZlFPHDcpsRu40z7OKoo2Gr3mxo5ftHw5YA1sXX8
 NGiBgSplH58wNB7P9cnaNS0HijoX9gp2b38u+E7V/9JTM+Ta8khspDU4YH4gKMTJ8ETOEoDC9jq
 hoTdwFZUPfV5+akDXk4WJ373Vt+kwzPqpsJ/IShFET6DffgL/XvCTe2xPr3h7abdjHAQBVC+akJ
 4kQYUMaIt9UgEXeUabNaf72CL4erBQ==
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Ly9Hd7B/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Lu1yLvL1;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

* David Hildenbrand <david@redhat.com> [250827 18:03]:
> In an ideal world, we wouldn't have to deal with SPARSEMEM without
> SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
> considered too costly and consequently not supported.
> 
> However, if an architecture does support SPARSEMEM with
> SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
> like we already do for arm64, s390 and x86.
> 
> So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
> SPARSEMEM_VMEMMAP.
> 
> This implies that the option to not use SPARSEMEM_VMEMMAP will now be
> gone for loongarch, powerpc, riscv and sparc. All architectures only
> enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
> be a big downside to using the VMEMMAP (quite the contrary).
> 
> This is a preparation for not supporting
> 
> (1) folio sizes that exceed a single memory section
> (2) CMA allocations of non-contiguous page ranges
> 
> in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
> want to limit possible impact as much as possible (e.g., gigantic hugetlb
> page allocations suddenly fails).
> 
> Acked-by: Zi Yan <ziy@nvidia.com>
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Acked-by: SeongJae Park <sj@kernel.org>
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Paul Walmsley <paul.walmsley@sifive.com>
> Cc: Palmer Dabbelt <palmer@dabbelt.com>
> Cc: Albert Ou <aou@eecs.berkeley.edu>
> Cc: Alexandre Ghiti <alex@ghiti.fr>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Andreas Larsson <andreas@gaisler.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>


> ---
>  mm/Kconfig | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
> 
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 4108bcd967848..330d0e698ef96 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -439,9 +439,8 @@ config SPARSEMEM_VMEMMAP_ENABLE
>  	bool
>  
>  config SPARSEMEM_VMEMMAP
> -	bool "Sparse Memory virtual memmap"
> +	def_bool y
>  	depends on SPARSEMEM && SPARSEMEM_VMEMMAP_ENABLE
> -	default y
>  	help
>  	  SPARSEMEM_VMEMMAP uses a virtually mapped memmap to optimise
>  	  pfn_to_page and page_to_pfn operations.  This is the most
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/imcmdidialtrylnkj4sjqmciwwgbpzsplavazyxkdlebrc7mey%40jnm7wh6bjk3p.
