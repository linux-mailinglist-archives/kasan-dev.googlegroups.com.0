Return-Path: <kasan-dev+bncBAABB7XRYLCQMGQEN36LMBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E32D3B3AB5E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 22:15:59 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70d9acd91e3sf2774566d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:15:59 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756412159; cv=pass;
        d=google.com; s=arc-20240605;
        b=Np4JMJSYw8GyQRv5wfQHFS0IFv7u7Elxh3s68OU0AaCMJhjUlebXUZY54KMbB4NMa/
         by7O1tzO5qKNatT7+nVQG8kLpw3cporyeVWkqRcgBAg2PIe+ysLpfK8CwylR6cOcdxGh
         zcvZxHCaomWu+MEbKhAgxh4j9uBjM2JO3w7xyFpM8jXTKY9astYhiJMCfU0lHmRZq+1w
         CaiO3PzIi+lONMc6rXUq/3D7E6Hbb69di/DkArD8Pq+hoBXKP+jN38bSnkVmXw2VQCV4
         47IEajaeNro8UUqqeFbvPdu1XBTB2PmyUNTLS74qDT4Iz+Hqr226viUbNs2TT8jmf0HH
         KYow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=ZTVvrTfrDvYUQGWRWVOP9PKAtMCXUkbLYQXFCURQd+w=;
        fh=PHOuVr1vocCch14iCPiyso426six2iJ06E4SoDSMQSI=;
        b=ZZlMkyPdzC/RD5SkDRs2/3LNI2gP3B0SBK9vZ7nrgV8wNdJRlHqPvfc0hz+mzhvxkw
         bMIeAPruLlIA1izGC41hzLEQCg6nGyR749OMDtIzWAWUw+G2KlPU1VLyYgqIgbnL1/Gw
         oXhn4YTqCPLN/y0xiH8e8xlizOT+BIryOdOwtFVPYoB1Ej8sw8Jfpfkh75kIu0rjhOlE
         Xhsiv56rcZW8fhOpHw3SED6MLEjMOEo2oW4gkUBAleHDavQ58pg8icPdFxjg0HdB0fOv
         lp1r4w2wfznQJtUqde4hR2Ci3nl7akwMmPPPa1Yj0+ObytYLLYEuv0G/4FnBuKuIs6Of
         Rb1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=CiIsbdFf;
       arc=pass (i=1 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of brett.creeley@amd.com designates 2a01:111:f403:2413::612 as permitted sender) smtp.mailfrom=Brett.Creeley@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756412159; x=1757016959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZTVvrTfrDvYUQGWRWVOP9PKAtMCXUkbLYQXFCURQd+w=;
        b=IRNuhmHUCSHVZPOXuu9aEsCphZUSZflG2mI8ujcOGJI7teX4vZPr1/WuMzQsotrzAe
         RMkNjO0ZAvd/iuz2dj0StmXy+n4icn+f8rJia+mmL8acdr/XQUVMcNGsiyxkk9JxGBzL
         vf1bpYRE6I5ZZeo0DjhBMOWbUfj4JR1n9H6mCX2ps+cP2JBwFkh32iqaobu05JxplQ3T
         bnx6KmP/tS7z0nQBWkOa0p3lSY1kW5/DxOIwA6Z31e9Ghif5/4QPAC/Zpiy+RGoO3k0p
         N7+SH/Cd7ZwSpeE9XhpWcMKYz+i1BMYDyKwKGWDWG5oSEM7cCDtLoYehnWfHsugz7++A
         4+bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756412159; x=1757016959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZTVvrTfrDvYUQGWRWVOP9PKAtMCXUkbLYQXFCURQd+w=;
        b=B0FOQkBWHjXSJa9IKcOqkswJ4ev9scZ6/9eUsxOnVsrJoMfPwoRPAMihhh7y883C7c
         BwGpRQfgt/IhfrKMdn9YS7T2g9569prS0HKbSejfa13TtujbYj/JecWd54e1CjLF/LoT
         Tcxyrs6hBxs7/v9DYwU+KhHUrCzTd6aR/t5lcthmrQuvU9xedvww8+yiMPZF0rOL14f2
         OPRvyMGN6xmy0/XUpHqdo4M/hmQqcdDqJs62ha34o0SdZjiO6dgAbcrT+HamBO0QJfWT
         Z91UEqeioshTQXD81sbaYk7slGDZCDYhSmx+DB1dXwwPpmj0EXAiEG9IuMhNWMDoSl3h
         2Uew==
X-Forwarded-Encrypted: i=3; AJvYcCVpBs80Abit3FxDkLgecNfu2sE8IjhevxxcGF9JiR5jFYztHEjKmmx/saw5MPF4szuuEDaLaw==@lfdr.de
X-Gm-Message-State: AOJu0Yw6DUIbdnDKAvyplUvs9tscbgKXIyJ0GXTXjwi8oyzpqS5J9+US
	yMF/9bxQUzXfGGf+lBlh9JtN7DnrZ+qiLtF9CIM2wVinLGByFw6eyWRd
X-Google-Smtp-Source: AGHT+IHONaJSX0egNgs0jIaNecyKkxEt5dOhVuYVWn8YUArmZ65LCpAU77szl/8zkoe+0S9ddpAYqQ==
X-Received: by 2002:ac8:58d2:0:b0:4ae:6af4:3908 with SMTP id d75a77b69052e-4b2aab1c099mr210225721cf.9.1756412158601;
        Thu, 28 Aug 2025 13:15:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdj1BeOthyeu+maAwia0Rsq0t5jR2O1MbN1M+RxsLEfJQ==
Received: by 2002:a05:6214:daf:b0:70d:9fb7:756b with SMTP id
 6a1803df08f44-70df03db7eals16834866d6.2.-pod-prod-03-us; Thu, 28 Aug 2025
 13:15:57 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXMRCFmWlclrrD08MHndV2KoeCt2lIsa1wlRaqdibE0skONn/q6h6cpuJp+rZoc4llOA7ffcRThi80=@googlegroups.com
X-Received: by 2002:ad4:5cad:0:b0:70d:6de2:50d1 with SMTP id 6a1803df08f44-70d9720ec57mr286589246d6.62.1756412157096;
        Thu, 28 Aug 2025 13:15:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756412157; cv=pass;
        d=google.com; s=arc-20240605;
        b=AEzidjir87Q/GNFNQ7yVMdcYbYlCxZs2IcfwbZV4ihHVKRK3w6i8DIAXS/CrOSvzXS
         w9WTwbDKSdZoti0caW+X9Ghp0BNZLE8xGVneZu4yu0NFvk2mUObSQGXhILgZFsIJ0Arr
         isEHZuC/ntf4yjQBPdUboFW6hVIagYdgXr+1E6TLOUjLM7l7ESQ0O721V84n0jBkiAJ/
         5HnuXnUC7Js31G0/ZzuaKWjE7btcH9FPeWEcvkxE3nYbiwvmgCL0I734nZOjZW1XU+6D
         iWL5jeRg70zKWyUXX87jInwyR7Wm6AOKtdOjWATmqkbLQUKhp55JOrIPiIe7HmUHWA8u
         qJDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=5NCZxsh7hXIhQTc+nlvlpEE5dDol9DLzOeRAAkojles=;
        fh=7qcUnJR/mbZTPM3G1gkqaWVPXSnaLmG+mWEIAD0TFqY=;
        b=DA6xFJ/PwCpKdiggubTZrd4oIDxHr+FxTyHKUxvBJq07eNCeHVGQaUQxb1Wsz+tzsf
         mhgboC/g5Nl29NKA/NWy8bTyhVijrIikuS9Y6dtoEln/Ax9mGoxLr1LCb5/WBe/jGwtd
         VNikSivF8IwFPcfUZ2VCEHkKE7beu9HmDVQ9hBl9SF2LsMBGxs95YdYnPR8nB9kZPwmX
         SPRBbWsyQFPRvnHCITAkva8/kgAX3jKxGhuyJ9WG6fYCB5UnHcbcJ824LMBBaq2Vu/Zw
         u9wfcxaDDWUlkwy8iJ4degCV9jPCIOxkuUiWj5yxiBJWLrAS7qwKVOFXIctSter6CH0F
         +seg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=CiIsbdFf;
       arc=pass (i=1 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of brett.creeley@amd.com designates 2a01:111:f403:2413::612 as permitted sender) smtp.mailfrom=Brett.Creeley@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (mail-dm6nam10on20612.outbound.protection.outlook.com. [2a01:111:f403:2413::612])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e624c1dbcsi120036d6.7.2025.08.28.13.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 13:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of brett.creeley@amd.com designates 2a01:111:f403:2413::612 as permitted sender) client-ip=2a01:111:f403:2413::612;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Y5w/cjZY9/rFmSnQwyDNR+TIt2kdjif7oOjMr4MmDwu0Rucbdu1dXLf/cc45tTiFEQcSr+DxHu8SW59PsyG48YK6hqeW+HNibYfboSpO4de0XTtTpszD/pJZ4+FYsy9Hn4oAs6YDzkKKUHl03sQ1y5DAS3yz0JpREXj2FIbMwdE8T4Lox5w1KnixqZqD6zExzeTvuARf2AjjqMr77gm6VTHCEswAQ5lNR0wxw+AGoTPVd6BC/G8bnjcsgpZKnX0Ue0WX8a9x9zS4jeWYYn+2YvV8/orh0HbyuQ3SLpktjWxU351b/g+TS6GedstH+vK+ULm6NoGIpwGhTYOGtrIMQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5NCZxsh7hXIhQTc+nlvlpEE5dDol9DLzOeRAAkojles=;
 b=ZGMz/RQ/HP5lAPiaFKrtnQ5+uBz/rKFoG5gRPgwfpEz/oz+D/pH9NAk+Hyz8XXqUbSx5WfISt2t3t/MPjzMBHFbmybn2WTIASweMhGEcp8VBG01TKwIjXRy2hyOKKaRhEDeHTBbUsBGXV/DmAS7BClZDq0KvXzgTbE0QCOcte7jmxP9H/ivx6/5A/pklQ5qvCA1a1ZBVr5lsbdzmMmWMG4SrF0o/NeV3mVoHw7Z6rxGR7LU+p3E4wHQCiHpxN7ex4rHM3iuZbi4diuZfoXvNW4FEa4LOkBr8GHzVQ/zG736fX1PDAR6tfHp8lBaC6MszQHZXO8LLjX8/TueAGtqXEA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=amd.com; dmarc=pass action=none header.from=amd.com; dkim=pass
 header.d=amd.com; arc=none
Received: from PH0PR12MB7982.namprd12.prod.outlook.com (2603:10b6:510:28d::5)
 by SA1PR12MB6994.namprd12.prod.outlook.com (2603:10b6:806:24d::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.17; Thu, 28 Aug
 2025 20:15:49 +0000
Received: from PH0PR12MB7982.namprd12.prod.outlook.com
 ([fe80::bfd5:ffcf:f153:636a]) by PH0PR12MB7982.namprd12.prod.outlook.com
 ([fe80::bfd5:ffcf:f153:636a%5]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 20:15:49 +0000
Message-ID: <de02027e-964a-4510-b988-c93c87d132e9@amd.com>
Date: Thu, 28 Aug 2025 13:15:42 -0700
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 31/36] vfio/pci: drop nth_page() usage within SG entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Brett Creeley <brett.creeley@amd.com>, Jason Gunthorpe <jgg@ziepe.ca>,
 Yishai Hadas <yishaih@nvidia.com>,
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
 Kevin Tian <kevin.tian@intel.com>,
 Alex Williamson <alex.williamson@redhat.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-32-david@redhat.com>
Content-Language: en-US
From: "'Brett Creeley' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250827220141.262669-32-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-ClientProxiedBy: SJ0PR13CA0191.namprd13.prod.outlook.com
 (2603:10b6:a03:2c3::16) To PH0PR12MB7982.namprd12.prod.outlook.com
 (2603:10b6:510:28d::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR12MB7982:EE_|SA1PR12MB6994:EE_
X-MS-Office365-Filtering-Correlation-Id: a67faebf-c655-4d24-4bb6-08dde66fae0c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?U292QldXcXZkSW03TkcxYVE1d05tOGpMamZQOEtzWWdmMGw1STlIaUsrT2Np?=
 =?utf-8?B?NExhT3NLVmkzZFJWZ1JLSlhHaEFOQ2pZWTREN3B0K3gyWGZ4SVFYa21ZQUlU?=
 =?utf-8?B?NDlMZFVpQkZLTlo1TDVQVFBjTkFIcFp4QUZMRXl6UC81ak44T0RYd3dpeUxH?=
 =?utf-8?B?QUIrb3c3STFRQUl0dS8rRkxwUHc0eWZJa1ZNdFcxR1JMVlQwNmF3bGxVNDRN?=
 =?utf-8?B?cElVcHJNQW8zOEl6eG8zY0JxaTRCQ2ovdmorMjhHU0VkWi8zWEJ3S3RrMUdC?=
 =?utf-8?B?OTFPOGI3K3VEL1FxUWZDT1R0SUp4R0EvSVpadGlNWVY4NGV5WmMydzBhZUpV?=
 =?utf-8?B?NWZJMVE4S1F0NXY4SzRQVzFudUVRcmxuaWNpdU9nWlFXSFk1RXFvaUlGMXpM?=
 =?utf-8?B?TTRZNnVQeC9oRTNGeURob3UwOXNQSDJqNnpmZG9aVEZXRW9PODUvZk1RM3ZW?=
 =?utf-8?B?dkQ0OTNYWFJ3Q09INk1hRmlFZmtDalZzNWNrbitHSk1zSEZsb2NUdUR0S0ZW?=
 =?utf-8?B?VlBoWk55MEdFTGJpbTdmLzlhTzlJVDVOOFM3V0o2Zk5XZVNYN1J0TDNqTHY1?=
 =?utf-8?B?VC8vbERFV1pDd1JGdnhlS0RsUXVHU3RJdDNwdmdwYlliRWtLdGZPeGg0N2Vq?=
 =?utf-8?B?ZU1jcHcwUzFVTnlXVjVra1ZUMDhDZzhLTjB0a2d1UnIzUEVGNnRXaGJWTlFs?=
 =?utf-8?B?QUJUazNlL3ZpcXZCVkNzTUg2UUxqVWZvZUZXeVhOcXMvOFVFdUl0YVRNV0Jq?=
 =?utf-8?B?ZHNacE45ZjBQblNCbXRvNkFTSDE5anIyaURkV0VOYmluVEszWW05MUIzaCtw?=
 =?utf-8?B?cVFKMUluNlQ5SGdPemtGM3VOMEtVRzdzT3dpRlpQdTl3SVdWcGxYdThNbWJT?=
 =?utf-8?B?VFFBbk1jMkNqdDNqRTBqMnJhT3UzaDlDY1RlRElEY09SNDdYeGQ1SHRyc0Rz?=
 =?utf-8?B?eGlKNVJEcXJ3eTRsdWtrdVcrMTd5UXBuY2NCelpHK2UzTjc0Njlsa25DWGQ0?=
 =?utf-8?B?cmFvKzcwWUpESkJLZlJ6dUFDZE9tUi9QeU1FeGNRUE9pMGlsVXlXTkZoT0tv?=
 =?utf-8?B?Z2FzazViU0djcFVyRitVSDNuU05CY1BLNlFhSFRPazYxcDdIdW96UnFQanBY?=
 =?utf-8?B?ZEIwdmpCQWR1NUZUQ2FRaTdybUlNMzdGNkNNVW9UYURLNXFsVk8vWEJtWUg3?=
 =?utf-8?B?YzZVODh1RmdCaitBeFhxNERBR2xmRWc4MnZnVTg0WFJVbTBRWjdqRkxET09K?=
 =?utf-8?B?RWJFdDZEVCs4bmY0aFNKY1JRWnEzU3VENkJsSnBLMVN0TXpwSlNFd0ZyQnJB?=
 =?utf-8?B?citiYzM3QUZHRGxIUG1EM2RlajVhelB2OGpiZTJkZjFRZ3ZuUWh0RlBuSGJt?=
 =?utf-8?B?OUgwR1Z6aWdPOUV1cFZhTXNoamViWmU3aDVhbDN4NUhEallLS2tSbWwramFP?=
 =?utf-8?B?VGk0Lzlxdk4rRXZkZURueWU1Z3RXR1R0dExHSndlSityQXBtQmlGZU41Z3Fv?=
 =?utf-8?B?TWxLMTRQNG80eEFXYyt5eWphQVk2RFdYeUR3Rzh5cGZMZmFkZ2dvTVZNdkFp?=
 =?utf-8?B?OHhDYndEbTNrL3FReGxMN05KK0FJcTZ6Z0ZlWW5VbDdaUTdScmRFS1pSMjA1?=
 =?utf-8?B?M0tMYmc2QVJmcEg3b1lsYzJLQytVdzZreHo2MkJZdjFEa1Y1RVk2NkhwOE1x?=
 =?utf-8?B?VkFBdERMc2k4WW9MdkhOemdiZ2ZyVUdvc2o0Und5TkxZbjZhUFpOSi9SQm1y?=
 =?utf-8?B?MFY5WlFKNU1haFZkTzFIMmFhSXp0STFUUHlvTDlwejd4blVSbU1iRHIrdWpN?=
 =?utf-8?B?c2x5VzJvZ3U3Z3hBY08zM3RqTENvTFJaaHB6M2J3a1h6M1FPTEo5WDBZWXJO?=
 =?utf-8?B?Zkc2M3I0blV1Y0h1MWhQbHpPSVA1RytkSStEWFUyQm55UCtsZzhDTElBT1Zn?=
 =?utf-8?Q?7Kh2L1I3SCI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR12MB7982.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?dXJvWEZoQVpacGxzWi9iM0JmSzBwZzMvM09qUDlzRnd4SzR1QnJ0SXJDQkVx?=
 =?utf-8?B?SkJpcDBBUnZCVDc5a040eWJjZEFaZ29QMmdTUVZVOHhZQjBXNk96bVFxL3B0?=
 =?utf-8?B?SXV1ZmVsb1R1aHdWWUpVd21Nd3hYa0RXenc2dDdBQ3FERVFNY1ZRKzFHY1pq?=
 =?utf-8?B?akhHUTJocC84dFc4MExTWmszbG50NFMyVi9mMnkrMC9RN1hkRUd0cml4SFRU?=
 =?utf-8?B?YWhrZEFrUzdWN3gwWkVsOG54MmRseUlndURUN2lielhRQUxmT2UzZnk2dEha?=
 =?utf-8?B?MU1mS0k2ZGp3bzUzZE9iYjRDeFFDTDgraUxXdnhkTll1cWllbGVSMWFwRm50?=
 =?utf-8?B?cW1OL2lSK2htNlM5cENHSlp1NFFxb21FT0NhVGtOVU9yYmJZZEZmSXZ5Umhs?=
 =?utf-8?B?Zlc0SisvT1llMFlrS0FPNHh5V2JtSm9waExDUW5XZEtyYWJGSW5ZbnlONHZz?=
 =?utf-8?B?aHpmcHM4SUpXaENYMlY4UUNWYzhtMkFxOTd1RGN1VG55UjRTSDhMWWkva0kx?=
 =?utf-8?B?K0draFJhbm1JZnB1bnpveDhRSGFQRFUyL0hhSVBjVU5zdDFYRHFuSzZneGp6?=
 =?utf-8?B?czNmSDVrbHVKaGtEM3N0QUhtRmZHUE1iSXNsdHNYa0JqNzMvRE5xTERndysx?=
 =?utf-8?B?Y1ZEVldzL3ZLUmFaNG1oZUpKRHNkbDBpT2lJdzZERHBHem5nOTBKQWZuWUFM?=
 =?utf-8?B?WTRVem5DZk8wKzMzVXRLVitNN1ltdE0ySjZEVHowUitwb3R0OGVWL1prdWR6?=
 =?utf-8?B?ZndJUmpPdXV1cW9CSDFBa2dkQ0VjeXo5cTUvbGFGUGhvMVo3dFlGRExhVEVq?=
 =?utf-8?B?SHE4VEVtM3ZOTUQzZDg5SERJeUh2c0w5WWVMQVVpY3JRYjBrdHBORUh6blln?=
 =?utf-8?B?MDdjV3JFMmNZT012azFnTmczbTkvOFIzUXFseHdlTFpoZEc3TlZRN2tSWGtk?=
 =?utf-8?B?dXRscGhUMFJOditLL081dTRxT2VHeC9NdG9KczNRVHhydmNxb1hyYmNJYkJH?=
 =?utf-8?B?cVRKWmY3MlE4bWNwL1BQWUY0U1RsYm9NS0preW9HV0JQNHN0Q1JXYWpTaE1a?=
 =?utf-8?B?eGsrR1FoWTN2YjJnVURTWDU1bzBXYng5bWlwRFUydkxQSXB1VnhZVXFDVExP?=
 =?utf-8?B?d3A1dko2YUMzTllPMmJkMFRyamlobTFSWnZGTHRoSU1uSGYzUEVoaEMwSXVr?=
 =?utf-8?B?YldzU0EvSkVaQmtwenZEbDczUjFXN2oxaHkyZmRMSkxoU3VIN0VHZ0IwRE1O?=
 =?utf-8?B?YXpqWDNlQlZuKzJCdk1Qd2hCNlB3NEZKU3FQR1JwdGFMN29zTnErUjRucUdM?=
 =?utf-8?B?ZFQxTWozY3ZQbkxXMHFPb0Jwa1BBTU9jdTdZdkkxSTNUb1BCZ0R0ZzA0Mk1Y?=
 =?utf-8?B?eEF6YWhNNE16UUxOMldQeEhheEJUYkFtbUFtOHc5VXNtUnhKN3RpeFZxV3cv?=
 =?utf-8?B?OS9aWVp6M01PbmJMbTVKc0NhNGhSbmFvb1dOT0lhY0hVeCtpa1A3dTh0dFk2?=
 =?utf-8?B?WFZlb0dxUjY4ZlhFSHRnR3FkblR5dzdkRWJFOEJQaFFnLzFoWlFyL0JBeXRE?=
 =?utf-8?B?ZGxxQXpMcEhRS1kwS3hReENiRWJCMzd1bDNjZlB0bFN1dnB4Y0xiQms4aS9z?=
 =?utf-8?B?UmFUa2pKeEpCRk1mdXZzVS9Db2I0TEp0L3J0K290MHhPTFlScGtlSUwydFRP?=
 =?utf-8?B?TEFVaDBWK1FWL0svNm9wQ0k2blhHWDZjTGJkTzE2MnE4RFhvTXVYR3NjbVlX?=
 =?utf-8?B?STN2a1lIK1FQT2lKdkhza0ZZTllacnVHQzRzWlhrOC9tUkthemIzNm9TbXdl?=
 =?utf-8?B?bHRCb1dKZUVYRnVjWVEvSUYvZWdIc0YxRWhzc3hOZ2F6d05rWWw0NWV1UzZi?=
 =?utf-8?B?Rk5xV05aYlAzV3hZRERLbG1GV2tJeXpHcGlrSmtnVDRaekVtek5xWnhrUU9X?=
 =?utf-8?B?bk41T0lHejRqdU1HTFozRUZ4RTZRME1RQUhHWXNZUWlwOVpFMXRCNFcvT2l3?=
 =?utf-8?B?UTB1dE9pYkFnZ0Fwc0daTjRKZDVNRitYczJUbWxLajkybXpuUVRMMmE4bDBB?=
 =?utf-8?B?K2lpLzg3d2E0UVA3eTRYNW9YdGVtdndsK2lXVHhzQnFMRUkrbXA4ZXlTVExS?=
 =?utf-8?Q?ABGgS8baU4PzLH7BG9JBiJhRX?=
X-OriginatorOrg: amd.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a67faebf-c655-4d24-4bb6-08dde66fae0c
X-MS-Exchange-CrossTenant-AuthSource: PH0PR12MB7982.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 20:15:49.4373
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 3dd8961f-e488-4e60-8e11-a82d994e183d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZWX72iSnzux1BBrPn1OlvuZ2nBV/HdxLjzylCF38ic/JnLsa9JlrvX3VFwuAFVMRx1w1QnuVMnscn+Q3pEYazQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR12MB6994
X-Original-Sender: bcreeley@amd.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amd.com header.s=selector1 header.b=CiIsbdFf;       arc=pass (i=1
 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass
 fromdomain=amd.com);       spf=pass (google.com: domain of
 brett.creeley@amd.com designates 2a01:111:f403:2413::612 as permitted sender)
 smtp.mailfrom=Brett.Creeley@amd.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=amd.com
X-Original-From: Brett Creeley <bcreeley@amd.com>
Reply-To: Brett Creeley <bcreeley@amd.com>
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



On 8/27/2025 3:01 PM, David Hildenbrand wrote:
> Caution: This message originated from an External Source. Use proper caution when opening attachments, clicking links, or responding.
> 
> 
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Cc: Brett Creeley <brett.creeley@amd.com>
> Cc: Jason Gunthorpe <jgg@ziepe.ca>
> Cc: Yishai Hadas <yishaih@nvidia.com>
> Cc: Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>
> Cc: Kevin Tian <kevin.tian@intel.com>
> Cc: Alex Williamson <alex.williamson@redhat.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>   drivers/vfio/pci/pds/lm.c         | 3 +--
>   drivers/vfio/pci/virtio/migrate.c | 3 +--
>   2 files changed, 2 insertions(+), 4 deletions(-)
> 
> diff --git a/drivers/vfio/pci/pds/lm.c b/drivers/vfio/pci/pds/lm.c
> index f2673d395236a..4d70c833fa32e 100644
> --- a/drivers/vfio/pci/pds/lm.c
> +++ b/drivers/vfio/pci/pds/lm.c
> @@ -151,8 +151,7 @@ static struct page *pds_vfio_get_file_page(struct pds_vfio_lm_file *lm_file,
>                          lm_file->last_offset_sg = sg;
>                          lm_file->sg_last_entry += i;
>                          lm_file->last_offset = cur_offset;
> -                       return nth_page(sg_page(sg),
> -                                       (offset - cur_offset) / PAGE_SIZE);
> +                       return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
>                  }
>                  cur_offset += sg->length;
>          }
> diff --git a/drivers/vfio/pci/virtio/migrate.c b/drivers/vfio/pci/virtio/migrate.c
> index ba92bb4e9af94..7dd0ac866461d 100644
> --- a/drivers/vfio/pci/virtio/migrate.c
> +++ b/drivers/vfio/pci/virtio/migrate.c
> @@ -53,8 +53,7 @@ virtiovf_get_migration_page(struct virtiovf_data_buffer *buf,
>                          buf->last_offset_sg = sg;
>                          buf->sg_last_entry += i;
>                          buf->last_offset = cur_offset;
> -                       return nth_page(sg_page(sg),
> -                                       (offset - cur_offset) / PAGE_SIZE);
> +                       return sg_page(sg) + (offset - cur_offset) / PAGE_SIZE;
>                  }
>                  cur_offset += sg->length;
>          }

LGTM. Thanks.

Reviewed-by: Brett Creeley <brett.creeley@amd.com>

> --
> 2.50.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/de02027e-964a-4510-b988-c93c87d132e9%40amd.com.
