Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPF3YLCQMGQETOQU45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 77B1CB3A9C4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:19:42 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e94dfb23622sf1528667276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:19:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756405181; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uk8Vaw6fvxsbApS2mDdx7ZPGsSsrhWL083VKyZFT+9xHVVDABHe0nm68TJJ6EfCQ3o
         DSKDr/YbGfgfzySU1nRXJhK6cFKFh0gdsGabUpx3O5pr0wEnBbbpY5danKq5wJIDlGB1
         Nw2fhN9rk30eXjoppIo8tXO04LV73SQmr+Eo+Fv8qYICMwTmGKy4ZqLPVQh4QwJjMPjj
         R1J9zJlZx/XCKdslN3+bh5KviUZiqHpuRU/dyHqXfRdYbEr63O9EVA8/i2BIJNdJEukQ
         /6urgCicBl2Ref/Cw4rPOYG/kVaJmN3Bsixx82SLwM520Sb52WcKB7LHF7KilBR+mwWB
         QeOw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YPW07lhPSkAYtlFWCuvqpr2Vc2sbQ6uXUzVDlqHWDJg=;
        fh=dncbe6jx0nZ1AxAM2PwDErV//JPRmrAnGMcanfFE24Q=;
        b=O7aLUhY98Vo6MYXfVJZex2LHFLyQG1ufHOC4gzRaLJSak+kxZvzCvAarxF/wFQjbmp
         KkfOqcptAQamjSVegZqNP/2Y5yqCZV/rc8V7xC5hDfubM6mrX0HGdW7Dsdwk5nrFbjLu
         L4BzHtPrrQywGkjhsTn+2r6/Sfz9jr2h4KR090RhS9HeYCMz1jVYxD3XvhEcIsg3Hrsk
         VKxK432ynL8LqzFHPyYdLVnTobx6f+LNtDfQnPV9/hvuNsbeTllQh1ClbVip6E/rZ/hN
         reHLMcAfNKucoKypXdY39kYpdU/a+sr5nQxp8oqpatVQfs/l6grcHq5L7vhMeQqupuqN
         hQCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oBhMt8j3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=H2j7Bp2F;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756405181; x=1757009981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YPW07lhPSkAYtlFWCuvqpr2Vc2sbQ6uXUzVDlqHWDJg=;
        b=ddL9PQrMvoyJEX8zgIJ47vteKBVM74VN4Q/OAbj6PsGmodQVmGEyuMGMyxrKZZNxw/
         qvQnFpIdoN0fIgksXprwgFtnQbgcpGr4Zlcnam0N0uvNONWLi71z1VLW/Kp3JlX+s1xy
         jhimJOEt0gnMIVARcf5dqMxWkY0ljMdySx1tEGEJ+gBlOGcH1HXNU01VUf57g+E3ySg5
         FtDTUiyb9DZEsugSgzHbjCQGREd8GeI5RgVujbsgTFodv0y2/fgP9jIPei5dL1pMZEJ6
         VlTKcP3lzaSTDdQnAmJzXjqR0Uxz+uz/P0NK3UrdadbRgldMAK/pbkXI/tNgzRdOBh+z
         9fQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756405181; x=1757009981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YPW07lhPSkAYtlFWCuvqpr2Vc2sbQ6uXUzVDlqHWDJg=;
        b=WOV9gJucRw4UkirTu26ruGn0mmmSVVewCsy/H9lVM962I9aN8XUBKe9zwEoTFKgAlC
         Y51J3cn272m34iwPA1tf4hSGREsBXI9O9idDOuvDZCVQ4FSL1hClriI0YuxMoeHOoNgs
         GuU8X2Y+5rOLY68aOzlFwD3rjR5UFIPLJtOn6DazerDELigTyxvSkzQtFuw/4KhCObn1
         yG9M+Zt2W50z+UlrMqUdGD7RvyezJhCu/aXxdXXtLR9ptK7o/ZkBLx065JVpXczbs4/1
         UU7yyZ+lnKz+4SHIjovYQXhFkz6j/6UFMDGovT569oedrLGuBYuTY66GngcHlGb/79x2
         vbAg==
X-Forwarded-Encrypted: i=3; AJvYcCXeloXRXyeiDJf1VYgDw2LLmMtYodHsbDCOeD+ODyuTEdWAdzCRfIs4lSG3bgP2fOpPfMF0uA==@lfdr.de
X-Gm-Message-State: AOJu0Yyt4ZpxsC8+COiY51fT4CDUK5lvS+Anjk2gkP3m7+WspPCAB8/t
	IUSmTVdmqO0AwzLcDMWYWaAInFgRO0gS1DYko/mnFCF3WuKi8hC/Jz0E
X-Google-Smtp-Source: AGHT+IFbyWN1Fh/1TmOHzzbEeyvSN6S1uPsRy8v6hKeyxDocyyDvVBwHMrEtYsXxEhpqAQaegnhpHg==
X-Received: by 2002:a05:6902:1006:b0:e96:c77b:8c43 with SMTP id 3f1490d57ef6-e96c77b8dc2mr15290766276.4.1756405181105;
        Thu, 28 Aug 2025 11:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9WL6CAa15ubqXWM0C/ZHXbSiB11JYRL4YUODYwWgSyg==
Received: by 2002:a25:b1a6:0:b0:e95:3946:b54 with SMTP id 3f1490d57ef6-e9700f4df2fls1215025276.2.-pod-prod-04-us;
 Thu, 28 Aug 2025 11:19:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXLbKWRZ8h3mqyT+emHz6WTGuWqCY67o1ZLAGWXlzUCQokotTjJmLRr3x80t7YEIs0NL/0FSJc11Gw=@googlegroups.com
X-Received: by 2002:a05:690c:6104:b0:71f:c6c7:e238 with SMTP id 00721157ae682-71fdc40714dmr287158167b3.37.1756405180152;
        Thu, 28 Aug 2025 11:19:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756405180; cv=pass;
        d=google.com; s=arc-20240605;
        b=kvlo26auh7xa+oUGoPyNdYm0Z/1fnMRLOxzDWqI6oM7o/3LetT41NHsgTVpEUmpgJy
         sTF9e3Z2T7d56yVSa4wtDCx1+HcBqD37vHtnGQDiaHbCmyjV/libKrrFiZ/ZqkZyXoJA
         OdmnT6C1B3PJjonLQ3YUWA8bE6klD3TUsAkrnjjrrIVlKaza4/r+FBY9RTYR5AMmEW0r
         /M7fkNXjxZrjMnRKcczC2nJeaz3Lbt5A6E/pKxSW7M4AEot8aiN2bY/jMlakFRM0QzVg
         W0yTKfG6in8OEwui3EhOIPK28BMdoTwrnEtl/aUyY5Bc7CV1fygnfxQdUq1PyqKwAMhE
         yX8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=N+mZkfZTLMtwBxeI/7+WrcodtVCJZHK5OJOkLv53PHU=;
        fh=bXlj/mCBeHmZqEcGPnSqEI9he7oyG9fANadYACVpSlo=;
        b=EV3WT5jMqFCt1/3oS+EafPNBy0409f23mA8KUF7ZMbJLqgL/fdJC3g0MD8R7zAmcwR
         Gj9kjJDBk7Ov/UZALT2y/7fGD4ha95OjOfDCwAAKeqQOsUS5DsUGO69/kaQEE05ju8Hg
         H8QAk1e9vHqQ+lWJzUZx/fKbupDQ1Wi0WsyIHfyaplNCjdKMyrI96M3QON7QwZxNvBu/
         nHIw+eEmQU8C5KBl7jQYj6bM/w59c9kHjcJCgogh1T4CC3+Nsehd7EFMA32mJfIx6BpS
         xhfzQHxsoyrHe625GfreLS9kZUi7Hii5jqiXKq0cwO+fyJu3QFD/5/XXrMtk46tDvT60
         +x7g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oBhMt8j3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=H2j7Bp2F;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5ff85b37094si16382d50.1.2025.08.28.11.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 11:19:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHNXNv019192;
	Thu, 28 Aug 2025 18:19:29 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4jas59x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:19:29 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SH4aBN027290;
	Thu, 28 Aug 2025 18:19:28 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010028.outbound.protection.outlook.com [52.101.85.28])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c3vbk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:19:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QllXEEEQnj0YNUg1ijz5q99TjA1+Muw1ztnRFrsbGvGMMpXMEy5gz/9gqyOKatgOcXmWoPaKpWui0tpx2Wk+lfaqP9e7EBeCHr/K2iEVaFLvj79IZSE7CZlKQgTOYkQeJfX0/esNmSGW7yTh5w2cAOvE284J53BhvNOtBzDLJFPeZFWwuRRXR+0E3srOlthS8482stfyRIuXRLAjFvHRvKtOFQe+6ul8ULDvfwDfFrBiElJpdEBEJY5mt06SaYVs7AKQDTz/NI/QqFR9Vn/HsmiIL2hN+y1LZ8srC/mxn1WjM4+oVuhzzx5eNbfHm5YSOtBYRI/7dfKD+SGIU1/X1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=N+mZkfZTLMtwBxeI/7+WrcodtVCJZHK5OJOkLv53PHU=;
 b=A2+72MGtlNSRKujo4v+jke3qiCjz+3fZ6up2N2aILzmuQ5jlPbvpfZ62mSguVTYj3LJNoaLHqATRfkzJAYuACB+EkZxNQHkxJmTPlvrDpziurc4o4qPpi+vX9VcM3WgDAyn9F0qXkZaMAe/suuscVbaH/D0hb3ZWi3pAlkMEvFfwdIw3xia08QBbXMeR+XrN61ZOGQOWc8fgCOtvauItto6zIC3javo2pmDHNJiz/53/j6uzcB5PYetVkMoCTxuWxz4dt3+7/hanAJnNqgCUM769uYUH7b1gz74C6b8jiLorweDoPTyhT6Z/1Lwz2NpIUg8aww1s+zg7urFflYSSow==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6873.namprd10.prod.outlook.com (2603:10b6:930:84::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.17; Thu, 28 Aug
 2025 18:19:20 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 18:19:20 +0000
Date: Thu, 28 Aug 2025 19:19:12 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
        iommu@lists.linux.dev, io-uring@vger.kernel.org,
        Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
        Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 34/36] kfence: drop nth_page() usage
Message-ID: <dd50511e-7fc8-41b0-bcd9-fe43ca107a54@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-35-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-35-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0512.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:272::18) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6873:EE_
X-MS-Office365-Filtering-Correlation-Id: 2466e27b-02b8-4582-f3a0-08dde65f6825
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|366016|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?EeKxciEqmIgFvQJTbPI9Kg5rZOhmnU6YHD6uvUK0ez+DPTDiAiOEX2Xuhc+f?=
 =?us-ascii?Q?C45H5CqbSFTj19CAerC9MI4JKDLGiZvggJNRdwjXQcooBhTUb+lY45UPOq/u?=
 =?us-ascii?Q?M7zJhrwpG9UwIgjCh4ee+OJa24Z+XJL9RH8t+v81pXG3VnOpUxWKuUHpUtH+?=
 =?us-ascii?Q?5vdltJZI8AHfI9BtBqH0mTDMzahfXrO+oUKf8qx0J64o7kVJLd/+JsC0qiFg?=
 =?us-ascii?Q?7BDqmO5U+174iIq4Fri79s3IlBh2FFerOm9TjLEGAP8r5kp6BjY6W4cnUIJM?=
 =?us-ascii?Q?w4pbU8X5Wi2hyg+79QOI2Vv2W6ZAtSDys2A5qj9xATPtABEAmVULbDY4uNUU?=
 =?us-ascii?Q?qLcS/kT0ElmIi63skR7tq+oWzRV7VrShFvPA1PLJrIS47r3JSdCz3rUIccGb?=
 =?us-ascii?Q?fcQHof+n4nd7wj/P61O3QIOiHzgu4FlyaysMQ79/0a5XevI/hbL/vTxq+yrJ?=
 =?us-ascii?Q?D5d15LNF3eMikJZE7EVIAAdGqqAnZDLXCYw43lXxyp3GDPX2awT9iH+7yMYV?=
 =?us-ascii?Q?gaBYl7NJqC7Q+VrHnTVbd1v1m/XfT2CIsl/KRf9dZTZwQZe+HiXD5NMtYnFL?=
 =?us-ascii?Q?3KAWTzCEneJ5OMKTFeiAM3s0yhnQgQ6ZhxB6ZDvGJUF0hiCxLIOA+PkUGDbx?=
 =?us-ascii?Q?3B9AcFf9J7mPRB0BOdegUbpPEhzcIaKtsTShI5jvsA4nsQ36ocM1Yl8M9sKb?=
 =?us-ascii?Q?DYxMdQNcU9WTcrr6/87PhDYU7h6FQF2nzVywqR07HyjUHF/2159RS+b48RrN?=
 =?us-ascii?Q?RsDs+MCf/0Rdm7HfFeE2EbLkZf73tNOtRs4W745EplZynUTGXEK8ae5SZTJh?=
 =?us-ascii?Q?mAJCZamxTRWcJ307JZgCniyHsy0qMfGw6O6bHzY9xz8uUNPP7VFoyf8a/bYn?=
 =?us-ascii?Q?S422nqwN21bllV/j5+yJfIY45CVRdBtfRVNwjUZmWT7UikqcADSYhp7+iDkH?=
 =?us-ascii?Q?DETTXHcuXqdc5sw8oPcA5XR39iV7iX6APbtQEYyW4gdcM2RXbINRJdT2pC6l?=
 =?us-ascii?Q?Q/l9XLM3zIQNnEtfhpOun6Z7StgaLEJUe4S/Rto0FKy+jMtlza35gaEpeU2P?=
 =?us-ascii?Q?Pg+rKhYxOViSmZYezxdwd59tJ8hThesAt5DTTrxLvCt6tL6yzIcF71XL+o0N?=
 =?us-ascii?Q?OFS+S/0ga3UPpCy0zCjqmG0Hn9WT69ogZTLgU4JBpXqHE5mtLQxgWNxkc3JE?=
 =?us-ascii?Q?09ZsjxsmhSjGLBCALXE5NjCNUjlwscOxrUtT1dOXMWbD1UQjcdOtMDWmX4Gv?=
 =?us-ascii?Q?B03vRLy3fvDH6qkidPQ8jwJpeYilV1OW2cWabOmcYX+6iOSJGupQTYDJVzBK?=
 =?us-ascii?Q?iNvGDd4dOkJDVFEtximv2IiILBfwPAFEE4KoUSNcTuUA0cVNicBT5SOmDerf?=
 =?us-ascii?Q?LmZOXFEkROMnTcyQsbpOnzmq4/SBC5VDgDxRkWZXjQXbl6NqPj7s7n4jrnbd?=
 =?us-ascii?Q?KqjMzfSk7EI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(366016)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5YibZq3a6ChVbDWI3XVAX+/oCVwVei0vAiaJid0Ob3oYPdMxnuBIbf1KjCQ2?=
 =?us-ascii?Q?ZpeM7BSk4hW1KynunvWpIaEUHLqv8s+VNszJg9iNblrs9+i0TTRdjx/OfyZz?=
 =?us-ascii?Q?GqAjaAoikkgxxzSrHSb7Pw93xUclo4gGoeX6u3YXCYE+R6BgnWR3btItpd8S?=
 =?us-ascii?Q?wglHvvRspMDOzAUNpdGsaZCeyQ/QpPTePkFZ9gnFOwoyx4YJmYMBDr2Rwyqq?=
 =?us-ascii?Q?hkcd0b4kK0axIuMmOkbZf1rgwocJKGF1bl//rXl62pD5qG1WxAeO814vkTJe?=
 =?us-ascii?Q?ZdEsn0H7bQb6CpmU2dhBugHJRZ96NwGAbtaleSG85UjY8ZQGISdJur6m305H?=
 =?us-ascii?Q?aFENkzdgcwwV6aw7+QWQLA0zAweyYZuTqN3BjcNzl4VIBOOGBnbi88rlgNga?=
 =?us-ascii?Q?E1OzDvWdCjWTl2LBrkHbyOsGIS8dnc3HkuLL460CkGL12ic5KOrbGfdYDgVS?=
 =?us-ascii?Q?YHfiviNmmmHYjeui40VkXtKj7Oeq7tB6BPlD0/JYR5fHFtNxY7v/VDC+2vVA?=
 =?us-ascii?Q?UASivi+37MXzgcx35v0nqmAoUOygdlk+/CStt7gpHw0QgC4PMNmrmUXyj6mg?=
 =?us-ascii?Q?m0hxGjIqHKYTdFM1GtGJ4bbOqeTVbhEjDmkYs1q4Ec5INMaH4oS+W4OhuLyj?=
 =?us-ascii?Q?D8hXZFxM++eYm81dRQt+/kGQeVdHdfU3/TzClWEhnG5LkuyW4A5gOmI6aQho?=
 =?us-ascii?Q?D3qPYnDw0eugOTNpkHMD69QEhJCamwrOfgxX9Brw+Pw0tltx+CfGYchMoxIc?=
 =?us-ascii?Q?diA8PEWl5e+6A3hTjvAvDSPRUJd15CQGYiqRdkzUq7YCeQ360sdf9Cs8QfQq?=
 =?us-ascii?Q?3KN47jcBHsC4eu9JEMWFCHv4VskWD13eL17t5TXZl6lx7k+arZtW1/EHLaai?=
 =?us-ascii?Q?C+8NLjarlewA9gte6k9BWgHBlsjBi6Z8Z+r8kPaZKvIP2R3VqBZsjVMNTZeW?=
 =?us-ascii?Q?/8fRVJ6bFF1SEGYMOt+QwHPxL0ORbd1Wui8+HaUF8vVUyDJkee0pVnywcCP1?=
 =?us-ascii?Q?ohhoGq/LUxp4qiMlbbU62mmSHMrrGG4hEyZUIxN0/1AgoFGg4D/hhnfs1YYz?=
 =?us-ascii?Q?tG9mS3UKHyTnqTwTpY8sHom4ZVEhud594uP82uKcAV+9kVwbCqDRQPrgqGkt?=
 =?us-ascii?Q?0ObYh/Ol4NSy3ChCjrtOIMG1M8iwvZZGzrfQUQDZwdK4smNnqXzs4Btnq3s1?=
 =?us-ascii?Q?IXYoiaMthdF3RlHsB+ZcV8QcmRXd2CK9olhnzPrXNi2IJCSEL1Q3ohdhTLI9?=
 =?us-ascii?Q?kaK8FXz44d+mJPX28ldRXENUIrtNlV/FnQ9by2lAWFBRWhUA51zThM9POps6?=
 =?us-ascii?Q?CZotLEq5XhkgpSEKBE4E/A45enMa1fE/mcs4vzDtj0XfONs2qoNPozUrS6A8?=
 =?us-ascii?Q?AH2n54yjcA9J9xmyh6hHnR6wu8mwuzFnwe0hL22xdZ1XC4KxShc3GgjYoVry?=
 =?us-ascii?Q?kq4fOG7MH9Fc52psqsV26NOBx8Grxwezp2bq5NcD2eCYuWWzBu/3rcpYe5Tu?=
 =?us-ascii?Q?jSD6xM4vDxXDH06r9ZBy/hT5cGh9GfyPjaxvjZlFNobKzHC972WYHSwOotFw?=
 =?us-ascii?Q?Ewcarf4SwnGqCc1TqtAL0s0erbUTamO1o0wVoKHPo+4Msgy0AvV8dWUToSvU?=
 =?us-ascii?Q?8g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: qPPcDbLXdLSK/LTylvFp720qMCkIK6HR1vyInFC+mPafPdGulZIrY5uf5QIdUH8RJLdEmXbjbe/31gk05d/KcjGBdkq2W/WgvDk0SVQ7N4EuVnIYRMifA6X9jZK7suAxGRiNHuLTG1ukQJt0G55ICCJ1cuephBfTWtHxfA+c+fFH35/e5FO+EuYRPRfqMtnfMcdCWbXK+GUOY5X7pdobdY4UZ8Fbn2egjMVs72gcYySIIcJF/x8jyYLsKjqwDn423IMG5Qst1TgGwtkcES7XkDixzqrU6gmidESgCVKrXbqxayXYP5rawW1QFx1YlUs/uoq2PeGlhbAZ++w14Ty5jvjgmVimGmNi63wuYkMD0pigWScIJLmPuun6gOfGI6tuniwmmDYXgcLYeQ2K/2LDIBqPK7LKbqv53NGsR21fpOib2kXxZEi2wGgNyLpIHCb77lUNktHmIemS50TpweFdH0ZIY+8wU0zn5LeYXZEzc9UZ3+uu6G7F4b6W20yJMF9NiBz5clGNZp7qFik4WcOrNhL78J1Sg0/GFEYONJK63Qr7BqsqqUPyHhi42LN1wiJPjUq7Fj2kCk3T1tH+pVBXovK5zoQesYbfYx6hNEXXWMs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2466e27b-02b8-4582-f3a0-08dde65f6825
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 18:19:20.0803
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UHSrZZ7IRsSQ7jCL+mgZDUr6WBeOqrd4d9/mv02Hwc0yLykPhxLuzw3pYfhgohqpG6JSm1wJfBCbz53qKdyJ/NwoPsQn4+jVb2MKnUSogD4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6873
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 bulkscore=0 malwarescore=0
 adultscore=0 phishscore=0 suspectscore=0 mlxlogscore=999 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280153
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxOCBTYWx0ZWRfX5ddWEAXI5elz
 CHUIX7PX11nTt1Z0ZOyl9KCJmmDptYLKNbLGKX7EyYpzQmGAU5UekIkZPfsyQPZAcjekNOtRPSJ
 kik60GU+txpCZ08A48NpiJksLvaYwgSH4CPpnA7MZQXFyq/zDlgGwVWX6db9Zh3KaJHT3v0HRcl
 z2J8X+DDfpPEOFtBFUs8RR2i6Z8hgr73Bt3bKVSj52cjvqsafBcABw7dujcH3J48vDZ23pYyTx1
 QrZGNXHHpXixoILZZinOAz4ITDgYcHiM6GeBROuQPBj6ij9tLYFLWNE6iSlGcbLKIvBQEm2SXik
 +uUrDjDcXkarEZcnnd9xaifxzz20AZJkg8+avICdXPqeoTZjQbKeyDj2d+xhnHIYhigkl334W4w
 3KCNAVng
X-Proofpoint-GUID: DhOcddl-9psiX1dCHRTL3X9Se839U3wV
X-Authority-Analysis: v=2.4 cv=IZWHWXqa c=1 sm=1 tr=0 ts=68b09db1 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=1XWaLZrsAAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=2XVGN-VCC70hLb22CjUA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: DhOcddl-9psiX1dCHRTL3X9Se839U3wV
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=oBhMt8j3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=H2j7Bp2F;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Aug 28, 2025 at 12:01:38AM +0200, David Hildenbrand wrote:
> We want to get rid of nth_page(), and kfence init code is the last user.
>
> Unfortunately, we might actually walk a PFN range where the pages are
> not contiguous, because we might be allocating an area from memblock
> that could span memory sections in problematic kernel configs (SPARSEMEM
> without SPARSEMEM_VMEMMAP).

Sad.

>
> We could check whether the page range is contiguous
> using page_range_contiguous() and failing kfence init, or making kfence
> incompatible these problemtic kernel configs.

Sounds iffy though.

>
> Let's keep it simple and simply use pfn_to_page() by iterating PFNs.

Yes.

>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Stared at this and can't see anything wrong, so - LGTM and:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/kfence/core.c | 12 +++++++-----
>  1 file changed, 7 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 0ed3be100963a..727c20c94ac59 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -594,15 +594,14 @@ static void rcu_guarded_free(struct rcu_head *h)
>   */
>  static unsigned long kfence_init_pool(void)
>  {
> -	unsigned long addr;
> -	struct page *pages;
> +	unsigned long addr, start_pfn;
>  	int i;
>
>  	if (!arch_kfence_init_pool())
>  		return (unsigned long)__kfence_pool;
>
>  	addr = (unsigned long)__kfence_pool;
> -	pages = virt_to_page(__kfence_pool);
> +	start_pfn = PHYS_PFN(virt_to_phys(__kfence_pool));
>
>  	/*
>  	 * Set up object pages: they must have PGTY_slab set to avoid freeing
> @@ -613,11 +612,12 @@ static unsigned long kfence_init_pool(void)
>  	 * enters __slab_free() slow-path.
>  	 */
>  	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -		struct slab *slab = page_slab(nth_page(pages, i));
> +		struct slab *slab;
>
>  		if (!i || (i % 2))
>  			continue;
>
> +		slab = page_slab(pfn_to_page(start_pfn + i));
>  		__folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
>  		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
> @@ -665,10 +665,12 @@ static unsigned long kfence_init_pool(void)
>
>  reset_slab:
>  	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -		struct slab *slab = page_slab(nth_page(pages, i));
> +		struct slab *slab;
>
>  		if (!i || (i % 2))
>  			continue;
> +
> +		slab = page_slab(pfn_to_page(start_pfn + i));
>  #ifdef CONFIG_MEMCG
>  		slab->obj_exts = 0;
>  #endif
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dd50511e-7fc8-41b0-bcd9-fe43ca107a54%40lucifer.local.
