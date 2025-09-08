Return-Path: <kasan-dev+bncBCZLJOMFV4FRB2M47TCQMGQEJG3DXOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D491B496A2
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 19:12:11 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-722693d5a44sf60728047b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 10:12:11 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757351530; cv=pass;
        d=google.com; s=arc-20240605;
        b=BcqPvm7Ru5g3bLFfYV2iveNdV9TtcMGjyBWaecg0vXMLc+0gzMYjLuYzMLlKH+X8uM
         MTlYO6rCp3wWYCHIgrZpO1JTo41L4SbDnwNpfjR1HU0s4rvgA84zOhi4hTd6jkCFa1br
         OOG6aMQyTPJRAz+5CHXSRxb+Vr6gr3Wwc6QESVswENUmsBncOtuowVcPMhsC1Y0i6Ko9
         An136W0S8C5gAjTiu+A3aMPUSbOG6dsQBY6C88dvSBE1TDDukapa1gl7lVtyNjkqIJNv
         5Zg0+GjWV6h406DroGJDPjWenAYFz5BXo0jr7SG7w13EM9012Zce6+LFTje/2m8i+HG7
         GsSg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=4yhneIQ7IgwttSdnKjpKmsYqes0OiBTqyfQY+ncKy1c=;
        fh=CmrSYBayMJriLfQROKbp6BHg1fgbMJBoUvT89p3TljM=;
        b=jGc72O+6aAjcdIHFzXoWDrD5apS3hU/vrikGe19S4WBeJpEcVMCEkKqVD7+2HuTrAR
         0s1J4bMY9uqGj9BH+64NDRAvtbj4CvZJ7z5KoTe9hYu7+SPUdFmOG41FAAg2Hrrag8FI
         49SC682M/60rMbuVi7Hu8sENXy2xHDtEsYRAPl0fr3D+aRRrpOHSAzXkEBxNqLnVFInn
         qmcWq/DjpLCvkbpZGP+FDPLhMLMGDTSENnkXEJ9/BoBlVYKJEjSMMxzcP84rmzRLAvYu
         pZqTFHPpnjabnL4iiBWNBrfRWZ41e3mEH+exJIeT8YMxMxCt6grN9OOWse6CGHW6GDfB
         j3AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="L4Y6i/Ow";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2412::605 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757351530; x=1757956330; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4yhneIQ7IgwttSdnKjpKmsYqes0OiBTqyfQY+ncKy1c=;
        b=FvW6oiYbsLNofMcI7c0clgwzTSYuFvOAcSm64SshZRhov9yn2Rh/f7tsg1KlcCzkNY
         ycH+5bfzVgrg2m/15d5FgbsxBz7Vn6qltE9+evrg/YoCPXRf9+Lwxzlq60PnvVyWuzKS
         VYJXPqiSrzYYPFbLCWmiGdsDZPjy3rXDqA/0fhHyOsHyjnpljGwT46VS+WYWumPItlIi
         idBBZAOhAlOmFUwoTInmmL6aPdl/XE+4M4JR5Gsk20Iv6alLAd/7xZckueli95m8mmBx
         1k09ONEL+Svgau+D6ZlG5fZ7TWUNQd4WQLY2Tq/Ynj1IOehkoWB3r8io+7XbXJvtqv6i
         +UIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757351530; x=1757956330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4yhneIQ7IgwttSdnKjpKmsYqes0OiBTqyfQY+ncKy1c=;
        b=lVleBBCfqyefktsR6xwjy0TQ6soU4Dn6YMmysvtrtL7/AaSw5XuL/+WAHZbimLUDKX
         w92gmJCAXLUeEbVqxAi9hc/rvLI0COVyObvveRPbSNDEt0ohKNyJ/Tb4ce2vyuvgfoNW
         KP5ePkSRp37A3SxhbFpnAjCpMXYyjdw5orLcz94DbZMFoJv21f1n0xcxk5YT1Trdb15g
         LDWcnLTSfS0o5uuQkYZxI+mcQ+MdalBeWsBemoJkDl9/iO7cFX2ZBApV4492qoW+7JOU
         c0MVH8sQO1utNFprubECtZjiQbjlBwxm4mzaiJ9vuYCV26/Zm17QmokUvK/NXy1VO3nF
         /6Uw==
X-Forwarded-Encrypted: i=3; AJvYcCWYSv0EnfIjDL1OKuV+j8hsISFAQ9x41NUQ9CDrXFIjB8Uk9yXa27huqktD7Jw2vW9OHccLmg==@lfdr.de
X-Gm-Message-State: AOJu0Ywa4r7lrXzR2XMC4e9+bTD8eXOXf6/ictnAr/5SxAYGX0uVEmCr
	o4r/UcGi5Z9BgENzZbU6SOf+0DNNUboMcChgbTz9DNDGF06apTRQ1IZF
X-Google-Smtp-Source: AGHT+IHKMMbKyUU41BbgLgUreFhQp+YNLei8JvriTW+ZxsMiqS9YfPPD4zQmByXGU51fvKxyfnN8Rg==
X-Received: by 2002:a05:690c:6301:b0:721:562c:381e with SMTP id 00721157ae682-727f28e7b23mr68650907b3.3.1757351529969;
        Mon, 08 Sep 2025 10:12:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Qz2uI4nGxYg0KEMTArvQopKNWaAl+4xhnmlDGHTFUaQ==
Received: by 2002:a05:690e:d51:b0:5f3:b6f7:98fb with SMTP id
 956f58d0204a3-60c77e84991ls1656084d50.2.-pod-prod-09-us; Mon, 08 Sep 2025
 10:12:09 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWoWUraonpUUJRkR9vjf61o0ozQs2a2+yOpDG4UkMRQfqw21cACngxEKq+N9zA4aYDlbcDY15xtf00=@googlegroups.com
X-Received: by 2002:a05:690c:30a:b0:723:8ccd:6898 with SMTP id 00721157ae682-727f28e47c9mr96194157b3.10.1757351528841;
        Mon, 08 Sep 2025 10:12:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757351528; cv=pass;
        d=google.com; s=arc-20240605;
        b=QuWXOiYzJmly7xcWvK3Pbwk2yB1cHn/QuEyB3IJtYwrBs5dMA22ycYAk12sZxAyiMH
         GamXILa4L//grLF9HDxqEo2TNuF60vOR6cPxfyFxpVw/KxhHfXWZMf7OfdqTo7nlGAUA
         j1jUpWUKErFLasaAHkwofC8XfkIMyYbBojVjxbJe4QX5oIVv7PvM2Adlk3zbVO44DlCk
         +vn8JeMkqy901f+tuU7zsVVir14BhbA7tQjnmS4CH4hLXASSBtx+HFVmMosu6LOdsLgN
         xeV+4dvCtrnF0mct8iSodVJrJ0MGtXyoD+6XqM87D14PeulVWYEg6r/EuUwHItjUFV67
         3ALw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:from:content-language:references:cc:to
         :subject:user-agent:date:message-id:dkim-signature;
        bh=cCHhtKAYH71OaRqtwumrUC6VgHGSSo5HrlbF86pIJBw=;
        fh=V/WSg9Bj2b8dJbvkwy3KeUsM/M6IbGex5H+LfBkBuFI=;
        b=Q8hFjMH4XpNqAH9vuU1n8ZWXikDxHsZrfchh7v1p7Z45pqwvXHOuv7UVOEqSEWYoKg
         BemcRvF9mzUUtW1H1yIKhvm+P3/zz9E9K7LRLH5WtsM0FxjJzutw7HVHfc7TcwL01Ll4
         O9r3puLPmTXDn2uajGMJ/++MpybTr03B1bW9S5wT0pVChMFYZu2E/To1zKTQK0ZOUZoc
         WntvuGvBQkAi4oNGoNZoAlE0s3/B9FY3i1V2dSLakrBw/JfSP821K0eu47qeUeG2vbrh
         ZAVj1ZYwdMS40Gj8agEb0vMHKI1y2qoFjHm8WKX1/ur8Y2OBju9GT03fc8rRZiSt8y7K
         WgsQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="L4Y6i/Ow";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2412::605 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on20605.outbound.protection.outlook.com. [2a01:111:f403:2412::605])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-723a7eab3c7si7062057b3.0.2025.09.08.10.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 10:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2412::605 as permitted sender) client-ip=2a01:111:f403:2412::605;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=qjGMso32SDE7tJAwprNfSj0WioVRegxAQDvd80g5Az33fnSzJszM90NlFPTSkt3FfltOMvJ2seqnIfLrtPIuQYdbXBK+W/MlVfTzYY+iMnumUkzssbdtR5BczkwG7L2Ilb7cz93MdpaUrMD31PDT+/2eo4Zmr4B7sjO4OYe+ZzdzNib0WArx+DGH7rekVlgvtDVgjjYYSICadYPwGcpYB/SQM80NtPTpX0kTJZT33zsSz2zOjlj0afx0ULH/31Cap99pWkJsjEOLdcyLDEg19Cc8FYjHxVr5RtrgDQ1Z9aVUXrbEzuhilZzHICRt3FGuPGV+pE8n/7HDc1Kw4em+IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cCHhtKAYH71OaRqtwumrUC6VgHGSSo5HrlbF86pIJBw=;
 b=MPRoYwQJCONGKkVtoV8NTG8bixNkGojivjX1QfiB3EFA7UyK9GfBlYCK7pZ3yMuMz7LnAJlTayE2kK6TjlZyONCfFu27perWYr7UKf330i4C/NJKwFfGt6bzJ/CQY7UA+DhRcAN0Ni4MvKi0H1bi1t4QolY3FB3a81Wt555rMe1JJ6+X/0Zu5hN7YGQjDyVnb5+GvvZUVfA0AkfgrHCckomVxyxKfMYfcbU0N34COF6Odlm1cH4Tv6LwuSRG+cS9VHMfgMk8X3jvidiXnconlf3Z2Dj1DZSHYquqL0SZDp4W7FWSVMo08+7IZVnNJ6Y68qbr6dF8XM/PHSkg8xYJBQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from MN2PR12MB4127.namprd12.prod.outlook.com (2603:10b6:208:1d1::24)
 by MW3PR12MB4460.namprd12.prod.outlook.com (2603:10b6:303:2f::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 17:12:05 +0000
Received: from MN2PR12MB4127.namprd12.prod.outlook.com
 ([fe80::a0ad:4e23:765e:7cb6]) by MN2PR12MB4127.namprd12.prod.outlook.com
 ([fe80::a0ad:4e23:765e:7cb6%7]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 17:12:05 +0000
Content-Type: multipart/mixed; boundary="------------rzrR4BY03xbhW3M4NQgwG8lR"
Message-ID: <cc49661d-c3ea-44c6-9af5-cda4bd102d25@nvidia.com>
Date: Mon, 8 Sep 2025 10:12:00 -0700
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: David Hildenbrand <david@redhat.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
 <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
 <727cabec-5ee8-4793-926b-8d78febcd623@lucifer.local>
 <7ee0b58a-8fe4-46fe-bfef-f04f900f3040@redhat.com>
Content-Language: en-US
From: "'John Hubbard' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <7ee0b58a-8fe4-46fe-bfef-f04f900f3040@redhat.com>
X-ClientProxiedBy: BY5PR20CA0022.namprd20.prod.outlook.com
 (2603:10b6:a03:1f4::35) To MN2PR12MB4127.namprd12.prod.outlook.com
 (2603:10b6:208:1d1::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR12MB4127:EE_|MW3PR12MB4460:EE_
X-MS-Office365-Filtering-Correlation-Id: 4dfe6367-6971-421b-1057-08ddeefad596
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|366016|1800799024|376014|7416014|4053099003;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?czFGSzQydEYzaHBCV05IMWtORTJDRXIra0FQaG5IUkI0YlI1dVVYZzFaS2N2?=
 =?utf-8?B?V1BGajFZRktpNVhlWmd3YjdibkVPU1hJczJjdVljajhRWTdBWlBheUh2ZTBQ?=
 =?utf-8?B?emhaTEY5cDNZWWwzWVRqMU5iUktzd3paMzJQemlqekpBSHN1aGpLOENRVURS?=
 =?utf-8?B?eTZIdERyNXRmUEQ1L3RlQWMvVlo1LzA4N3JTclJDREEvUUZMckhuWkk0cVho?=
 =?utf-8?B?TDZOQTZLQ1RJM1VabzNVV1Q5STZKclRnM0ZQbVVoeDE1QWVKWFd1MHpHMEhU?=
 =?utf-8?B?d2xld3VZdTZKVzFxeDhUUkY4RGNIa2tCN1dhL3Zqd1JjaFRNK010S1dTWHZi?=
 =?utf-8?B?WFk3Z1MzdzduRUtFRXRzZ0lLazRKdVM3R2dVT2VnSHlmOWxWUUh4NmNIbFY3?=
 =?utf-8?B?MWN3NkdyM0Y5ZDNQSVhPTkFiR0xRbk1BSEM1QVBrRHJycS9TZVY1QTJENjJx?=
 =?utf-8?B?Y0Z5dElHOEQrWUhLeWw2MHRNUFlsOW4zejVxWlFVbjlHUWNzT21nbWNkOXQz?=
 =?utf-8?B?TWRCdjYzSmZFZ2FITkVQUHFJKyt5SVQ0ZU91M2tMVzN3akpoYXdjUHRYR2c0?=
 =?utf-8?B?QjJRbTFBeGUyNHdScE9UMGR0bWZGbUN6VHRyUUgwbHA1QnJhNHFGVG83STF2?=
 =?utf-8?B?WkUvZWJHREpWWFpIdjUwS0plWDQrTTBwdU05R2NmZjR6ckpoQXF0b3Q0cW5y?=
 =?utf-8?B?Y01HREs1by9Qc3N0alB6eGQrbThKVVZrWE5NMUI0Wmd3UUVXcFo1Vk9CVUIr?=
 =?utf-8?B?TVhTQmY4MmlGbkxCVGJJN1VxbDFzNmRYaTNLb21WaXFBcy8zS1dPNDAwVVc3?=
 =?utf-8?B?SlRFa1owRTJJNG96cVdvV0o5eGdTaUMvcUhqUnNOQkRWYWNBVFQ5cVBGTFRK?=
 =?utf-8?B?ak8yZDNyeE9LSit5TiszQmRJeEVXZWpWRmJEWmJOenBIRkZrQUp3R1cxMjdu?=
 =?utf-8?B?RXRXZXB0L2JCdm9OL1BHdWw3L1hzVzZmbHZOcC9CVkpwNDJpZFNKNkx3QnZR?=
 =?utf-8?B?S2EwRUdYRSsvdzBjcDBxVHUvcFJnbFRyeEl0RVVLQStmenZoNkE5NHRFQkxR?=
 =?utf-8?B?VHhGaHVGS0I0RWo5dStET0dwT1dSNEdubDhzWnhyeW8wUUhOKzlNN3ZXQUdK?=
 =?utf-8?B?OVZpc3hiRTJ6dG5nQkpNd3d6T3JmVzFFSHNhbzhXRnFaMnJVQlUzZVZpeVF4?=
 =?utf-8?B?R2lhL3duN1lUY0dGV2xKRUM3Rmo3RkZmNWQ4cEw1L3JNZDJ5c09LUTNSWnZh?=
 =?utf-8?B?bHV0M0RLYUt3ZlliZFc2V3VGeEowOE1BYkY5QWRnK2ozU0F0dVNiMEJ6Zi9E?=
 =?utf-8?B?dXFzTmpNWXpYai8zekhQUXRBQ2lHLzJjUWtTYzY4OUorYjd1VHQ2cmo1U2do?=
 =?utf-8?B?cGV6K3Roc253SGJPNklyR1lydjhYNmVmd1pGa01CTXZ6TWduNHVSREFka2Mw?=
 =?utf-8?B?ZmhjMytFMzIvalBsUlBJclBDZU5SVWs0Mk9kWEFUUmZKY1QxRkZlQ3NTQlNJ?=
 =?utf-8?B?SUcrU0JPbExGTDBPeGZ3SUtvUGMyVVZRcHZldGdhUlZ5T2tJZkZuQ1pqaUJD?=
 =?utf-8?B?dExVL1h2V29UeFREUFpBaFpqeW5VL2YyZDR1Wnl3c0pGbFdBN1NDTGViV1Bn?=
 =?utf-8?B?b0RFNWN0Q0twU09KR09lYUIxR3ZxSXlySmNaSGhZMFdabFREQng2bkh3bEM5?=
 =?utf-8?B?SHBtblBUb1NVakVJY0EvT1lHQlJOU2orQ0oveG5kTWI0dStZVWd6aTcrUWJV?=
 =?utf-8?B?ZG1lMDM4eVZsaHRrTHhtMGVzYWNvbncyY09pekRDWmFWZWdOcXdpV24xTXZk?=
 =?utf-8?B?T0psanNSSFVqYWFsd3lBMjYrUGxtRzZZN1VUOTE1VXVlSDNWazI5M2F5NUx0?=
 =?utf-8?B?RGN5NXkwVEp2RTJ1UXFCSVR2R0tXYTFsMFNlM00yMlRZUDMxWmI5RFVXN2hP?=
 =?utf-8?Q?2Y/7ft6Y8Po=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR12MB4127.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(366016)(1800799024)(376014)(7416014)(4053099003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cks3TlUvZ0FIN2Q5MXYyc29NVHI1N3Q5TEJpQm10Q3pmb3VLcmlnaEkwQ2h2?=
 =?utf-8?B?NlErZFduYzhPVnZLZU92YTdSa0tzdmtmb3o1TVNWYlpQdG01RlovQmhQcEpL?=
 =?utf-8?B?MGlJd3kvN3J4WGNkOWJMZXBXS0VhTVlKT1doY3NxTFJiMkdNaWg4WGpPKytJ?=
 =?utf-8?B?cGRMZCtMeTloeDhGZUVRZ1NiQ0dqVjZRMGUwYVhsQ0hEdkJ6cER6MkFOL3A0?=
 =?utf-8?B?L3RGTWlmM3BJcHJyUUlxc3BreWc2dEtsWWVJZ3oyU1pTQ3FWUVB6UVpMRC9C?=
 =?utf-8?B?dGpNcGltV2hCVVFhbjV0MVhwZDdBb0p2eU9KVnRXVDdPV1djc2RoWm1RNk8x?=
 =?utf-8?B?eWNrcitmbTIrbWZVN043Tk11V3hyRmlhL3I4UUpHSWZtUXpleUw1eUNKOVF1?=
 =?utf-8?B?bC9sZmFkL29rZTNFRXpvYmRBcVlROVZELzdQcG56RlcwM3ZSaTBHRk8zUFFz?=
 =?utf-8?B?bUxBY0QvOElsemZpanAzbUZPV1JRMEZJWktldjczYXAzRnlGVURzUlFWSSt1?=
 =?utf-8?B?enJJbnA4ZlNqZ21GU1Rwbk5LVW9RelJNTk42VlVoVCtuSzVqcG4xZEVGZHk4?=
 =?utf-8?B?TURrOGtpdmliUXpTamdCV25wS3hSUnNlWXRTTzBQbjEvMjFLUENMQlVyQlM1?=
 =?utf-8?B?QWtCR2JwbmdobEt4M0QxSlhOd1NEZ283VExZckNBL1JsU2YveExSTlBiOFFU?=
 =?utf-8?B?NUg1NXdaV1VjYms4TnJKeERtaHdPZFBQbjB3UEladklTSXBNV3l2OFllWFRC?=
 =?utf-8?B?Wk56QkpncW1NOC9jamNaaUpoSWhFUEIxb0RFcW9ZOW8zUndlMjBxMklURTFj?=
 =?utf-8?B?WmlVSE9wSDAxd1BIZmpULzdWaHlDQU1mRWZHcjF3OTZrZnJLbTFHMTE0dHFi?=
 =?utf-8?B?Y3k0NHU5ZW54aWlEelgvUXZRVWpYbXdJWit1bWZrMFhmT0tNcUhYUjBveXA0?=
 =?utf-8?B?QVBnTHpKU1EvQTZZbkd2YktWQXJEMFNVQzg5TCtsd0JVMjUzMTZneWFwVjJX?=
 =?utf-8?B?alZWeEVKVlhhMEpsNWU5OFFDYzZ3TlMxdWFVN2UwRzdNbFhadVo4NjVoK2xo?=
 =?utf-8?B?SlNvR2dIUGp6QXFvWVpYa3cvTlBDNEk2TGhGbmpiUURaNzc0WmpoWExxTGEz?=
 =?utf-8?B?aWF1ZFVOaldDdktjU0gwTmJoQVNBTjJTdWdqYmNpRTlQWEVnT3hqbFVrUjFZ?=
 =?utf-8?B?b21tbktHWllPMUZ4ZzFCUWxZT1M1WUxtazhlSGlSTWNKRkhLK1c0OU9TUUZC?=
 =?utf-8?B?U0tIQVNIMENDWk5aTVdQR3VPbXZQTHE0dUJrek9xOStLb3JEaE5rcXBqeWNx?=
 =?utf-8?B?UkNXaWc3OGk4dUQwY0ptL0lHbEZpdVVqUmNwMmdEUGJxa3FaN01GSGJ2VXB0?=
 =?utf-8?B?cmlBNzlXcTlXMm9IK3lwdGtxUzBXL0Z3R0VPZ1VidlRpeUNObjhNUlE5S2Rt?=
 =?utf-8?B?K1MxaXk0NkpGQ1NKeFE0bXVYSVZxdVJWQUZyK2JUaFpxdHZZTFllTGwyQ2VU?=
 =?utf-8?B?alV4cjhZMmRGWFJVTWZmWXVHNmhsTEhYYU1yVG5Nb1hWd0FTalN1TE9oVXU5?=
 =?utf-8?B?R1R5Y3pjek0xbGU3aVJxc3M1SUpIcU16ZDY2WnlwSVNNb1EwSnJGMlBSSWlX?=
 =?utf-8?B?U2pCUUJld0ZMRVlUNlQ3NGlyRGp5N3RwUlNaNkprSDc4cDhKbFVBR251Qmdj?=
 =?utf-8?B?OTNFT1ZuWHhyZld4Y2FhVEJvS3BudWRUTmJQNTc3UFIzaVI1K3JVRm5PSGQz?=
 =?utf-8?B?eHZ2QVZwTGFlREFTYS8yRE9LYjI0aW90dFJYTHdmVGhYbm9hMEE3U1dvQ1d5?=
 =?utf-8?B?LzV5VFU0Y1RuUWNtWWVmMHRVVTBMaU10YXlBQWc1U3ZySGtndVJYbGJBeFhq?=
 =?utf-8?B?M29DWDBPc3BjWm8vM25sTERqTnJ0Y3VEQW5UOUY1R0ZxbFZEQk04d2l2OHps?=
 =?utf-8?B?cEplOUwxSEhvR3FxcDJXR2pYM281MHhGdVF0R1RWeDhxdW8wMlgzanRldElh?=
 =?utf-8?B?VnpNenBoT2R0TUsyOGliY3RuU0xqOU5adnd1QnBpbk1ZRFo1TGFpV2pRYk94?=
 =?utf-8?B?dVYwRm1VSHE5a3U2ZTM4aWRRL1FRNmJFSXRhVVRtd2kwMDhtclR3c0xRNmh2?=
 =?utf-8?B?OUM4b05ZMXJDVk55RjI4bVdKc0dTd3pxN2NJRWM4TWZuRjhmUTJ5bmwvckF1?=
 =?utf-8?B?UkE9PQ==?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4dfe6367-6971-421b-1057-08ddeefad596
X-MS-Exchange-CrossTenant-AuthSource: MN2PR12MB4127.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 17:12:05.2791
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: fsEWO9zucFmDF/W1gtYaz1/irOZlFpaiXuf3YnAC+CEmK3EYeKr8QougyKFoynPq37VI4N6lkK2JnP/ZgUJbnA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW3PR12MB4460
X-Original-Sender: jhubbard@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="L4Y6i/Ow";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 jhubbard@nvidia.com designates 2a01:111:f403:2412::605 as permitted sender)
 smtp.mailfrom=jhubbard@nvidia.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=nvidia.com
X-Original-From: John Hubbard <jhubbard@nvidia.com>
Reply-To: John Hubbard <jhubbard@nvidia.com>
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

--------------rzrR4BY03xbhW3M4NQgwG8lR
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 9/8/25 5:53 AM, David Hildenbrand wrote:
> On 08.09.25 14:25, Lorenzo Stoakes wrote:
>> On Sat, Sep 06, 2025 at 08:56:48AM +0200, David Hildenbrand wrote:
>>> On 06.09.25 03:05, John Hubbard wrote:
...
>>> Roughly, what I am thinking (limiting it to pte+pmd case) about is 
>>> the following:
>>
>> I cannot get the below to apply even with the original patch here 
>> applied + fix.
>>
>> It looks like (in mm-new :) commit e73f43a66d5f ("mm/gup: remove dead 
>> pgmap
>> refcounting code") by Alastair has conflicted here, but even then I 
>> can't make
>> it apply, with/without your fix...!

I eventually resorted to telling the local AI to read the diffs and
apply them on top of the nth_page series locally. :) Attaching the
resulting patch, which worked well enough to at least see the proposal
clearly.

> 
> To be clear: it was never intended to be applied, because it wouldn't 
> even compile in the current form.
> 
> It was based on this nth_page submission + fix.
> 
> thanks,
-- 
John Hubbard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cc49661d-c3ea-44c6-9af5-cda4bd102d25%40nvidia.com.

--------------rzrR4BY03xbhW3M4NQgwG8lR
Content-Type: text/x-patch; charset=UTF-8;
 name="0001-David-Hildenbrand-s-fix-for-record_subpages.patch"
Content-Disposition: attachment;
 filename="0001-David-Hildenbrand-s-fix-for-record_subpages.patch"
Content-Transfer-Encoding: base64

RnJvbSA2MTQwMTQ3NzVjNmQzYzkyYWJkMGE1M2FlNDdhMGVmYjA1ZTE5MWIyIE1vbiBTZXAgMTcg
MDA6MDA6MDAgMjAwMQpGcm9tOiBKb2huIEh1YmJhcmQgPGpodWJiYXJkQG52aWRpYS5jb20+CkRh
dGU6IFNhdCwgNiBTZXAgMjAyNSAxNDoyMTozOCAtMDcwMApTdWJqZWN0OiBbUEFUQ0hdIERhdmlk
IEhpbGRlbmJyYW5kJ3MgZml4IGZvciByZWNvcmRfc3VicGFnZXMoKQpYLU5WQ29uZmlkZW50aWFs
aXR5OiBwdWJsaWMKQ2M6IEpvaG4gSHViYmFyZCA8amh1YmJhcmRAbnZpZGlhLmNvbT4KCi0tLQog
bW0vZ3VwLmMgfCA3OCArKysrKysrKysrKysrKysrKysrKysrKysrKy0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLQogMSBmaWxlIGNoYW5nZWQsIDM2IGluc2VydGlvbnMoKyksIDQyIGRlbGV0
aW9ucygtKQoKZGlmZiAtLWdpdCBhL21tL2d1cC5jIGIvbW0vZ3VwLmMKaW5kZXggZDFlYWJhOTFk
NjgwLi5hODhlZmYxYjE1ZjEgMTAwNjQ0Ci0tLSBhL21tL2d1cC5jCisrKyBiL21tL2d1cC5jCkBA
IC0yODQxLDEyICsyODQxLDExIEBAIHN0YXRpYyB2b2lkIF9fbWF5YmVfdW51c2VkIGd1cF9mYXN0
X3VuZG9fZGV2X3BhZ2VtYXAoaW50ICpuciwgaW50IG5yX3N0YXJ0LAogICogYWxzbyBjaGVjayBw
bWQgaGVyZSB0byBtYWtlIHN1cmUgcG1kIGRvZXNuJ3QgY2hhbmdlIChjb3JyZXNwb25kcyB0bwog
ICogcG1kcF9jb2xsYXBzZV9mbHVzaCgpIGluIHRoZSBUSFAgY29sbGFwc2UgY29kZSBwYXRoKS4K
ICAqLwotc3RhdGljIGludCBndXBfZmFzdF9wdGVfcmFuZ2UocG1kX3QgcG1kLCBwbWRfdCAqcG1k
cCwgdW5zaWduZWQgbG9uZyBhZGRyLAotCQl1bnNpZ25lZCBsb25nIGVuZCwgdW5zaWduZWQgaW50
IGZsYWdzLCBzdHJ1Y3QgcGFnZSAqKnBhZ2VzLAotCQlpbnQgKm5yKQorc3RhdGljIHVuc2lnbmVk
IGxvbmcgZ3VwX2Zhc3RfcHRlX3JhbmdlKHBtZF90IHBtZCwgcG1kX3QgKnBtZHAsIHVuc2lnbmVk
IGxvbmcgYWRkciwKKwkJdW5zaWduZWQgbG9uZyBlbmQsIHVuc2lnbmVkIGludCBmbGFncywgc3Ry
dWN0IHBhZ2UgKipwYWdlcykKIHsKIAlzdHJ1Y3QgZGV2X3BhZ2VtYXAgKnBnbWFwID0gTlVMTDsK
LQlpbnQgcmV0ID0gMDsKKwl1bnNpZ25lZCBsb25nIG5yX3BhZ2VzID0gMDsKIAlwdGVfdCAqcHRl
cCwgKnB0ZW07CiAKIAlwdGVtID0gcHRlcCA9IHB0ZV9vZmZzZXRfbWFwKCZwbWQsIGFkZHIpOwpA
QCAtMjkwNCwyNCArMjkwMywyMCBAQCBzdGF0aWMgaW50IGd1cF9mYXN0X3B0ZV9yYW5nZShwbWRf
dCBwbWQsIHBtZF90ICpwbWRwLCB1bnNpZ25lZCBsb25nIGFkZHIsCiAJCSAqIGRldGFpbHMuCiAJ
CSAqLwogCQlpZiAoZmxhZ3MgJiBGT0xMX1BJTikgewotCQkJcmV0ID0gYXJjaF9tYWtlX2ZvbGlv
X2FjY2Vzc2libGUoZm9saW8pOwotCQkJaWYgKHJldCkgeworCQkJaWYgKGFyY2hfbWFrZV9mb2xp
b19hY2Nlc3NpYmxlKGZvbGlvKSkgewogCQkJCWd1cF9wdXRfZm9saW8oZm9saW8sIDEsIGZsYWdz
KTsKIAkJCQlnb3RvIHB0ZV91bm1hcDsKIAkJCX0KIAkJfQogCQlmb2xpb19zZXRfcmVmZXJlbmNl
ZChmb2xpbyk7Ci0JCXBhZ2VzWypucl0gPSBwYWdlOwotCQkoKm5yKSsrOworCQlwYWdlc1tucl9w
YWdlcysrXSA9IHBhZ2U7CiAJfSB3aGlsZSAocHRlcCsrLCBhZGRyICs9IFBBR0VfU0laRSwgYWRk
ciAhPSBlbmQpOwogCi0JcmV0ID0gMTsKLQogcHRlX3VubWFwOgogCWlmIChwZ21hcCkKIAkJcHV0
X2Rldl9wYWdlbWFwKHBnbWFwKTsKIAlwdGVfdW5tYXAocHRlbSk7Ci0JcmV0dXJuIHJldDsKKwly
ZXR1cm4gbnJfcGFnZXM7CiB9CiAjZWxzZQogCkBAIC0yOTM0LDIxICsyOTI5LDI0IEBAIHN0YXRp
YyBpbnQgZ3VwX2Zhc3RfcHRlX3JhbmdlKHBtZF90IHBtZCwgcG1kX3QgKnBtZHAsIHVuc2lnbmVk
IGxvbmcgYWRkciwKICAqIGdldF91c2VyX3BhZ2VzX2Zhc3Rfb25seSBpbXBsZW1lbnRhdGlvbiB0
aGF0IGNhbiBwaW4gcGFnZXMuIFRodXMgaXQncyBzdGlsbAogICogdXNlZnVsIHRvIGhhdmUgZ3Vw
X2Zhc3RfcG1kX2xlYWYgZXZlbiBpZiB3ZSBjYW4ndCBvcGVyYXRlIG9uIHB0ZXMuCiAgKi8KLXN0
YXRpYyBpbnQgZ3VwX2Zhc3RfcHRlX3JhbmdlKHBtZF90IHBtZCwgcG1kX3QgKnBtZHAsIHVuc2ln
bmVkIGxvbmcgYWRkciwKLQkJdW5zaWduZWQgbG9uZyBlbmQsIHVuc2lnbmVkIGludCBmbGFncywg
c3RydWN0IHBhZ2UgKipwYWdlcywKLQkJaW50ICpucikKK3N0YXRpYyB1bnNpZ25lZCBsb25nIGd1
cF9mYXN0X3B0ZV9yYW5nZShwbWRfdCBwbWQsIHBtZF90ICpwbWRwLCB1bnNpZ25lZCBsb25nIGFk
ZHIsCisJCXVuc2lnbmVkIGxvbmcgZW5kLCB1bnNpZ25lZCBpbnQgZmxhZ3MsIHN0cnVjdCBwYWdl
ICoqcGFnZXMpCiB7CiAJcmV0dXJuIDA7CiB9CiAjZW5kaWYgLyogQ09ORklHX0FSQ0hfSEFTX1BU
RV9TUEVDSUFMICovCiAKLXN0YXRpYyBpbnQgZ3VwX2Zhc3RfcG1kX2xlYWYocG1kX3Qgb3JpZywg
cG1kX3QgKnBtZHAsIHVuc2lnbmVkIGxvbmcgYWRkciwKLQkJdW5zaWduZWQgbG9uZyBlbmQsIHVu
c2lnbmVkIGludCBmbGFncywgc3RydWN0IHBhZ2UgKipwYWdlcywKLQkJaW50ICpucikKK3N0YXRp
YyB1bnNpZ25lZCBsb25nIGd1cF9mYXN0X3BtZF9sZWFmKHBtZF90IG9yaWcsIHBtZF90ICpwbWRw
LCB1bnNpZ25lZCBsb25nIGFkZHIsCisJCXVuc2lnbmVkIGxvbmcgZW5kLCB1bnNpZ25lZCBpbnQg
ZmxhZ3MsIHN0cnVjdCBwYWdlICoqcGFnZXMpCiB7CisJY29uc3QgdW5zaWduZWQgbG9uZyBucl9w
YWdlcyA9IChlbmQgLSBhZGRyKSA+PiBQQUdFX1NISUZUOwogCXN0cnVjdCBwYWdlICpwYWdlOwog
CXN0cnVjdCBmb2xpbyAqZm9saW87Ci0JaW50IHJlZnM7CisJdW5zaWduZWQgbG9uZyBpOworCisJ
LyogU2VlIGd1cF9mYXN0X3B0ZV9yYW5nZSgpICovCisJaWYgKHBtZF9wcm90bm9uZShvcmlnKSkK
KwkJcmV0dXJuIDA7CiAKIAlpZiAoIXBtZF9hY2Nlc3NfcGVybWl0dGVkKG9yaWcsIGZsYWdzICYg
Rk9MTF9XUklURSkpCiAJCXJldHVybiAwOwpAQCAtMjk1NiwzMiArMjk1NCwzMCBAQCBzdGF0aWMg
aW50IGd1cF9mYXN0X3BtZF9sZWFmKHBtZF90IG9yaWcsIHBtZF90ICpwbWRwLCB1bnNpZ25lZCBs
b25nIGFkZHIsCiAJaWYgKHBtZF9zcGVjaWFsKG9yaWcpKQogCQlyZXR1cm4gMDsKIAotCXJlZnMg
PSAoZW5kIC0gYWRkcikgPj4gUEFHRV9TSElGVDsKIAlwYWdlID0gcG1kX3BhZ2Uob3JpZykgKyAo
KGFkZHIgJiB+UE1EX01BU0spID4+IFBBR0VfU0hJRlQpOwogCi0JZm9saW8gPSB0cnlfZ3JhYl9m
b2xpb19mYXN0KHBhZ2UsIHJlZnMsIGZsYWdzKTsKKwlmb2xpbyA9IHRyeV9ncmFiX2ZvbGlvX2Zh
c3QocGFnZSwgbnJfcGFnZXMsIGZsYWdzKTsKIAlpZiAoIWZvbGlvKQogCQlyZXR1cm4gMDsKIAog
CWlmICh1bmxpa2VseShwbWRfdmFsKG9yaWcpICE9IHBtZF92YWwoKnBtZHApKSkgewotCQlndXBf
cHV0X2ZvbGlvKGZvbGlvLCByZWZzLCBmbGFncyk7CisJCWd1cF9wdXRfZm9saW8oZm9saW8sIG5y
X3BhZ2VzLCBmbGFncyk7CiAJCXJldHVybiAwOwogCX0KIAogCWlmICghZ3VwX2Zhc3RfZm9saW9f
YWxsb3dlZChmb2xpbywgZmxhZ3MpKSB7Ci0JCWd1cF9wdXRfZm9saW8oZm9saW8sIHJlZnMsIGZs
YWdzKTsKKwkJZ3VwX3B1dF9mb2xpbyhmb2xpbywgbnJfcGFnZXMsIGZsYWdzKTsKIAkJcmV0dXJu
IDA7CiAJfQogCWlmICghcG1kX3dyaXRlKG9yaWcpICYmIGd1cF9tdXN0X3Vuc2hhcmUoTlVMTCwg
ZmxhZ3MsICZmb2xpby0+cGFnZSkpIHsKLQkJZ3VwX3B1dF9mb2xpbyhmb2xpbywgcmVmcywgZmxh
Z3MpOworCQlndXBfcHV0X2ZvbGlvKGZvbGlvLCBucl9wYWdlcywgZmxhZ3MpOwogCQlyZXR1cm4g
MDsKIAl9CiAKLQkqbnIgKz0gcmVmczsKLQlmb3IgKDsgcmVmczsgcmVmcy0tKQorCWZvciAoaSA9
IDA7IGkgPCBucl9wYWdlczsgaSsrKQogCQkqKHBhZ2VzKyspID0gcGFnZSsrOwogCWZvbGlvX3Nl
dF9yZWZlcmVuY2VkKGZvbGlvKTsKLQlyZXR1cm4gMTsKKwlyZXR1cm4gbnJfcGFnZXM7CiB9CiAK
IHN0YXRpYyBpbnQgZ3VwX2Zhc3RfcHVkX2xlYWYocHVkX3Qgb3JpZywgcHVkX3QgKnB1ZHAsIHVu
c2lnbmVkIGxvbmcgYWRkciwKQEAgLTMwMjcsMTEgKzMwMjMsMTEgQEAgc3RhdGljIGludCBndXBf
ZmFzdF9wdWRfbGVhZihwdWRfdCBvcmlnLCBwdWRfdCAqcHVkcCwgdW5zaWduZWQgbG9uZyBhZGRy
LAogCXJldHVybiAxOwogfQogCi1zdGF0aWMgaW50IGd1cF9mYXN0X3BtZF9yYW5nZShwdWRfdCAq
cHVkcCwgcHVkX3QgcHVkLCB1bnNpZ25lZCBsb25nIGFkZHIsCi0JCXVuc2lnbmVkIGxvbmcgZW5k
LCB1bnNpZ25lZCBpbnQgZmxhZ3MsIHN0cnVjdCBwYWdlICoqcGFnZXMsCi0JCWludCAqbnIpCitz
dGF0aWMgdW5zaWduZWQgbG9uZyBndXBfZmFzdF9wbWRfcmFuZ2UocHVkX3QgKnB1ZHAsIHB1ZF90
IHB1ZCwgdW5zaWduZWQgbG9uZyBhZGRyLAorCQl1bnNpZ25lZCBsb25nIGVuZCwgdW5zaWduZWQg
aW50IGZsYWdzLCBzdHJ1Y3QgcGFnZSAqKnBhZ2VzKQogewotCXVuc2lnbmVkIGxvbmcgbmV4dDsK
Kwl1bnNpZ25lZCBsb25nIGN1cl9ucl9wYWdlcywgbmV4dDsKKwl1bnNpZ25lZCBsb25nIG5yX3Bh
Z2VzID0gMDsKIAlwbWRfdCAqcG1kcDsKIAogCXBtZHAgPSBwbWRfb2Zmc2V0X2xvY2tsZXNzKHB1
ZHAsIHB1ZCwgYWRkcik7CkBAIC0zMDQwLDIzICszMDM2LDIxIEBAIHN0YXRpYyBpbnQgZ3VwX2Zh
c3RfcG1kX3JhbmdlKHB1ZF90ICpwdWRwLCBwdWRfdCBwdWQsIHVuc2lnbmVkIGxvbmcgYWRkciwK
IAogCQluZXh0ID0gcG1kX2FkZHJfZW5kKGFkZHIsIGVuZCk7CiAJCWlmICghcG1kX3ByZXNlbnQo
cG1kKSkKLQkJCXJldHVybiAwOworCQkJYnJlYWs7CiAKLQkJaWYgKHVubGlrZWx5KHBtZF9sZWFm
KHBtZCkpKSB7Ci0JCQkvKiBTZWUgZ3VwX2Zhc3RfcHRlX3JhbmdlKCkgKi8KLQkJCWlmIChwbWRf
cHJvdG5vbmUocG1kKSkKLQkJCQlyZXR1cm4gMDsKKwkJaWYgKHVubGlrZWx5KHBtZF9sZWFmKHBt
ZCkpKQorCQkJY3VyX25yX3BhZ2VzID0gZ3VwX2Zhc3RfcG1kX2xlYWYocG1kLCBwbWRwLCBhZGRy
LCBuZXh0LCBmbGFncywgcGFnZXMpOworCQllbHNlCisJCQljdXJfbnJfcGFnZXMgPSBndXBfZmFz
dF9wdGVfcmFuZ2UocG1kLCBwbWRwLCBhZGRyLCBuZXh0LCBmbGFncywgcGFnZXMpOwogCi0JCQlp
ZiAoIWd1cF9mYXN0X3BtZF9sZWFmKHBtZCwgcG1kcCwgYWRkciwgbmV4dCwgZmxhZ3MsCi0JCQkJ
cGFnZXMsIG5yKSkKLQkJCQlyZXR1cm4gMDsKKwkJbnJfcGFnZXMgKz0gY3VyX25yX3BhZ2VzOwor
CQlwYWdlcyArPSBjdXJfbnJfcGFnZXM7CiAKLQkJfSBlbHNlIGlmICghZ3VwX2Zhc3RfcHRlX3Jh
bmdlKHBtZCwgcG1kcCwgYWRkciwgbmV4dCwgZmxhZ3MsCi0JCQkJCSAgICAgICBwYWdlcywgbnIp
KQotCQkJcmV0dXJuIDA7CisJCWlmIChucl9wYWdlcyAhPSAobmV4dCAtIGFkZHIpID4+IFBBR0Vf
U0laRSkKKwkJCWJyZWFrOwogCX0gd2hpbGUgKHBtZHArKywgYWRkciA9IG5leHQsIGFkZHIgIT0g
ZW5kKTsKIAotCXJldHVybiAxOworCXJldHVybiBucl9wYWdlczsKIH0KIAogc3RhdGljIGludCBn
dXBfZmFzdF9wdWRfcmFuZ2UocDRkX3QgKnA0ZHAsIHA0ZF90IHA0ZCwgdW5zaWduZWQgbG9uZyBh
ZGRyLAotLSAKMi41MS4wCgo=

--------------rzrR4BY03xbhW3M4NQgwG8lR--
