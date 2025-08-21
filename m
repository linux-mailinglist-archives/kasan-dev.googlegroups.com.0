Return-Path: <kasan-dev+bncBDWMT3UBYINRBMULT3CQMGQETX5RTEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FD8CB30664
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:46:44 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e94dfb23622sf2048358276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:46:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755809203; cv=pass;
        d=google.com; s=arc-20240605;
        b=KCrTOkwz+MJGC5taZlvKWUJ13cYPJiOIGscVkUdKlptutDR8Y4iWjxVqgKuNaA82QF
         HUGHWCAa0aWIdBf3eRJCNXIntHZ3H+WZ8QmKcCqFrDyw4oat9PucmuYXx7IV870CwWTN
         6whEI+p+avHpr3g3YMvV29h/R6uvdjN8V1ov+e1xxH3kW/Da/SUmqLUvloQOMUQjz5Bu
         6n0qPCicf33lpLeMu3c8UWzX1wstePw4oAl7z3D3fZTYeOyEUY0HMd7XOc1hYcuSs5Pu
         equKS2LlldY1mqEjIzAIADKrftrqXextKqNkr4C8v2keJuME6WiS3sF2u5MSKS5YA6uD
         2WJA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:cc:to:from:dkim-signature;
        bh=RfOfYYf+c/6+YjUWD7LvZbYta03r3cbcKvsi69QtBGM=;
        fh=2q6RDI1WdLQfR6azW3kxLnAuYQ9Vs82WqIbuMqiBRSg=;
        b=H6gNe+fF7TphHbrffl8FzcGpawjE2k1JLejoO8nvosTHLwLHi1qC4GwcuH3oIwFErt
         UN1mtbrNKIVNFh0kELXyha0EQuux8SIRGgjoJUDpLRHsja9Uxhqs0khZU4omqQ9BpWTw
         nNdzC56W2gqSsQFAgyknu8awwL3gQnmez0mINaw95sB34idn3QIs3gzxFHuA46t6dDnK
         9pEUj2O5BmNnN+zJB/8TBlj4fQ26PptoAEYhfvzP2aMKHnNME//XbVLjFQAgEq2Y1QDu
         CKO5spRyJcC5UkDP+bGaU6Pin0HY3V8SI6PKYMRM9C0CJXQ8Y0nVTg0I6Th3OwSKsbzD
         /agg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=svFEWHWH;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::620 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755809203; x=1756414003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RfOfYYf+c/6+YjUWD7LvZbYta03r3cbcKvsi69QtBGM=;
        b=t2gSX7tIX2ucWndpio/+4NiSZJx0Y7Oo4vYr0H2OGc73XaNC7VqXrxF5rDRCkuSVjM
         Hcb4+IsvQUvoj3TIib9mNs/asBSPb/BzVwZVJ4LaAx/ZTWHHXTAuXBxWgoxfmQW5hhNT
         s+yaXIaOu76RotdRjWMhz6LWTCIeIq+G8jlMdaWJbd8DpWzSPheGb8P2oj9ANEhkzf37
         1fEhWBGcHaHuL2regCEtG2nQuxVJPjE7tLWPc92+Vt0NO+hgM4SAtBg4TpehKXKLo7uc
         E5RXcd3fpSNuGGV6yoSonaavtCh/jsIwNAsRY5yD1BWv2QI4ZOJygcANYDIT7XYhRqC3
         mbNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755809203; x=1756414003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RfOfYYf+c/6+YjUWD7LvZbYta03r3cbcKvsi69QtBGM=;
        b=NFDZ0Zej+lYHy8Y8AIJSvtAyFPHFUaU8fQ525rSAdqzMeZ4Zn3oo/JL9TCkkgAQZ/C
         X6Wqo7SBIdDC3e4YCBKx/tlrL8Fw6PFjUwivJ+rK05FBqTV5agaTyeK0jdSoExfwoS8q
         dZ1Hfe2SmvQ4RO6f4lURAvQjUxdUQa6kFqHvGa9hXMVCAIV731cW9oug9zG0AMUDO7fN
         6+T9a5wX+YGJCjEXysvp77MZTAv8kpllb0CV/gOW+W5mAUk4xmUtAEcz/2sN6IGF5S+7
         gZOkgooieLco9+y63yGw7Wrptzw4JzHQTg/77sKUgENHKZHJlIGCYCH8caGaOWk9uL4g
         h4GQ==
X-Forwarded-Encrypted: i=3; AJvYcCW6csZUyTxwEMliby9BqsxqbodKJM8Rav7nIvOxf4WpFGGgrhtfx2QYiEDCi/q8Miw/2XI+gg==@lfdr.de
X-Gm-Message-State: AOJu0YyXoPcO9bx+fede9o81hYgKgl4ZCLu/lCtoR2f3GGsUgmbTsoh4
	uGPi4RYId1ofxLqOXs7d009CLJifk3daaJfPU8bAJZB8++iI6xpqV5fX
X-Google-Smtp-Source: AGHT+IGFUUN84mdR5W7rfYzzcHVjlTCHl+9TNPp6ZTZQM8WEHkt5FOpnOl28cnw9MftAsW33vWjkfw==
X-Received: by 2002:a05:6902:1148:b0:e93:451f:93ad with SMTP id 3f1490d57ef6-e951c2984acmr1084555276.33.1755809202877;
        Thu, 21 Aug 2025 13:46:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcj+yhzySxutlOeXBcZhYCkGrSHWtaMlPekGGbPQVWUQA==
Received: by 2002:a25:c147:0:b0:e94:e82f:67ac with SMTP id 3f1490d57ef6-e950456842fls1206413276.0.-pod-prod-04-us;
 Thu, 21 Aug 2025 13:46:41 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWzVNonego76GFzKWH5R0raGWegFPKrpDB5NqLkWFlN0FoZSYVRjKMylTq6OKUcY7tC8j+H8KDgyaQ=@googlegroups.com
X-Received: by 2002:a05:690c:6104:b0:71f:c6c7:e238 with SMTP id 00721157ae682-71fdc40714dmr7160737b3.37.1755809201167;
        Thu, 21 Aug 2025 13:46:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755809201; cv=pass;
        d=google.com; s=arc-20240605;
        b=WnEtYJyF6q79Z1iEIbnJy7JATR3dGb8U3/+O35kTa3pEMrdlRnKCSpGUzbkj9MAhDj
         +vBgkqn3yvwMDhQR5rcP0yYU+7Zvv1Cuh7Dpjbjcwf+KVvfHsOJebm61sOO8MXf2XZ+B
         Kp6KT2KDbf07t3/VwvORky5B0sEau/hF8C0hPb7RBCkS3GODO0gZLRLZpCm8icVzQ2vU
         LMujg6v6zsXiwjM0t6jxVSH2VntLdujgfQ+U6r+KF9zkhr977vkYx8Yg89CZ46EcAo7H
         7kufpkgzLHM7YUtFnqFUSUC8H1H0s6DXtCaQq7e/rkD+6/70++InPbfpg3lIk3bvH4YZ
         E+lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4zV4M8m3AKmKwHhJ/SUSqW+gzDWqxJUe6URDNOe6HNg=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=XFvFOlf7S/vdLvb2c/xtpWMeF9x/PV8OJLDQRE3iArvJQdTE+G28VpInmgV1JcBKRv
         aZx7I5LTmSsMxihRpzgJ04rFMMw5UCb65aSHmsFYzBZds9qJI8CkXzC40ZZAVJ2yy3MW
         iGPSHH3YvwrJcIstCKMloc5TJD/GQNltvcnk4h2Oo6/k0vAEMxwUV1GFwNwfGJvizjdg
         jkavVSeYU0x8tGvTKVXPp6zCOj8Dy2HFUCMtKCBnRVvXkZyx695qf+e77eNcOmuSRfI2
         wTmT6x/9dAwUQc9I2QCZuD4qqKGsEZ6551aVeYKgjEBcrIimbxPXe1ISu0MUXqkoI5Lh
         iD2w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=svFEWHWH;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::620 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on20620.outbound.protection.outlook.com. [2a01:111:f403:2417::620])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71fd9211753si444547b3.1.2025.08.21.13.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:46:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::620 as permitted sender) client-ip=2a01:111:f403:2417::620;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=D7n8Z7XOVuaGW3/8muWolwOxvE3k9c4reLFr8ladj3oIAxjNWAzplfEqql2MVHjX5lz8ePRZRn3Yd9A9Zi1U7bMfNUjTJC4JWAqARfcilaU/VKLd0i4FPk5KQjKNn54McdWF5ek1+yZH63JlW1cxDDTEjRzcrQMcLzfG9Sj3IacE9M86/KeS+mPptkkWCLyVaK4m/UV+58C8E2VYdyFpBQP8hFDnOIjxx7q2EEVrKU3oJt1teH5TLwxTyXY6KNGXNP+K7bQ1m2JkBIXbxskgc8CJXthtRPKrFE1NfEgjMsBg6mc62XDQUc1fYp2s6Dhw9h9ewuiYQS3KsGn3TYAs+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4zV4M8m3AKmKwHhJ/SUSqW+gzDWqxJUe6URDNOe6HNg=;
 b=eHkFQBui4f1aOqxE73ULCkaM0E64XeXA3dMoPbUumA1SCpOj1yY1Y6o5u99oxuMVGMLcfGYVQ8Go0cuj5sm67vJEXDOdb70qhO7zybq/RKA6UkDduT0qOpZiSstu5c3++xcaG22bOIbu+4b0uY8lm73pDa3xDjxjYiMfNtQxMs0DMwqvF86y10gBZChAS0Gl0w2yxvB0LQi9SpNsyIioh/S6tCWOHoUoYZsu/fBGxiPbyiJjmKHcTqt2Vzv9Tlu4/wGqGXXr4YV3SJT8XO7B1hc94y8sdvtufxU8BhqbQI12eLRm2ABDZvsv2z9Vkh1YPQ9jlCHHjpHkT4HSryZNFg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 CY5PR12MB6576.namprd12.prod.outlook.com (2603:10b6:930:40::12) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9031.13; Thu, 21 Aug 2025 20:46:38 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.013; Thu, 21 Aug 2025
 20:46:38 +0000
From: "'Zi Yan' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH RFC 12/35] mm: limit folio/compound page sizes in
 problematic kernel configs
Date: Thu, 21 Aug 2025 16:46:34 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <FFF22E91-6CA5-4C8F-92DE-89C22DB3EAD7@nvidia.com>
In-Reply-To: <20250821200701.1329277-13-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-13-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: MN2PR07CA0030.namprd07.prod.outlook.com
 (2603:10b6:208:1a0::40) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|CY5PR12MB6576:EE_
X-MS-Office365-Filtering-Correlation-Id: f97d9f8a-d383-4ed4-3ac0-08dde0f3d36a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?SkI4MUd1MnFwSm5GZlcxL3UyT1dpaW1UaXNqczgvSENZR1h3a0VYMjB5TGFC?=
 =?utf-8?B?YnNaaFFiRUtnZnlFUjRCZ2hycjd4L21CUVZPUU94VTJHaFpVS2FJd3dyZlRB?=
 =?utf-8?B?ekJUZ0hxWXVIL0hOZytqTlBWK2UxdkIwRXp2N2kxUWQ2RjlTNkoxdkVIazVv?=
 =?utf-8?B?aUtXa1hZTlhyY0M0UllNNzdFQ2pzM1BxTCszRkIrTzcwM3FhZkp6SVV2bElX?=
 =?utf-8?B?SjA3cVRNc1VnYkh2Z1d3NkduZlVZUEFHMnlZaGoxd3lnTCtBKzFMQzM1TSs2?=
 =?utf-8?B?QWVrOW5Zd2dWajdmSG5KNVdUWU4rNVZKZkhzaXAxTzlCWlJoN3ZsMXA4V2pQ?=
 =?utf-8?B?WEVlZlBZY2ZYL1c5ZEticmduamsxTGZEalNWRlRJS1ZFWXlYZmNlejBJNzdR?=
 =?utf-8?B?MEx4c011aU05Vi9BN2dBdFJwZGRidldKRlN6RjJtWk9saC9nMGg0cFRodmhL?=
 =?utf-8?B?Um5mS1VKMVFZRTFnU1dsSWt2UjJ6NkM4NTRzT2R2amo5OXBQRXZVOEpxWTJn?=
 =?utf-8?B?Q0dmdURPYlA3d28yanFvd1AwenEzZUtiOTNRc3lvWVZDMWc0NVE4VG9MUHZJ?=
 =?utf-8?B?WGRUMTlLNVpVa3VPZ0l2cXBRRklYQVlERStoc285Ny85bGpod2JPWEVHNmFO?=
 =?utf-8?B?M01hc1NnZEFNSXZwbGVncWlPOFZlQW55bzdSMXlxSlRua0VqQVhtUllvZHNB?=
 =?utf-8?B?d2RsK0tTbmlIdUMwYzNpZ2RiR3dQcHJJdFFGZlFEZU42ZFFYTUZhR3pkUGx4?=
 =?utf-8?B?dG1ubGtmazJhOXFPdjZFTVpKd0VreWkybE5Mc0FQZmZXL2Vzbk40WTdnQjh6?=
 =?utf-8?B?WHNVSitLMDhqNXV6Y1FhM0QrNmU1MWd0a1ZsWkNsZ3pCUXdTUFVsVysxVVRl?=
 =?utf-8?B?dXVHdUFObUxaMkxOR3NjUnpMdGplUTVCb0dnS1VSak0zbWdpN0V2RXZodGxQ?=
 =?utf-8?B?Yk5XVGk0SkxPenlMeTJaWjRIei9acGVHSVczVk14TlBHQ21MdnNObTVBY3hi?=
 =?utf-8?B?bkphZG9GTWNTN0Y3Y2sxMW13a0pVRjIwOXlHNWhaMFQrUnZjc2JZOGhXNzRa?=
 =?utf-8?B?Yyt3QjVrZDZIbmtYM3NKdmVBSzNxMXl1RTNpcnVTYjJCMVo5Yi9yaTdOMVF6?=
 =?utf-8?B?dTVWOTIrMC91cEpxM0NUejVNa3llK3ZuMnFJbTFQc3Bwa2cwTExKU0hrYkZz?=
 =?utf-8?B?VkM3SVZPek5zYVM3T2hUZm5PMEVKbk85WEg5TGJaN3J0RU4vNXg5SGZjR3o4?=
 =?utf-8?B?QnU0a1ZscmRUNzdab2NXaUc4NHV6N2M5a2x0ZnhBNjZkVkZnWHkydCt4UXhJ?=
 =?utf-8?B?TzBhaUpxenE4S3J3cElMQ2ZyREhWdStxSkdmdWNsRzdZRGlIbXNkcHgwWGg0?=
 =?utf-8?B?K2h5THJHeU5JbjlIeHNuQmxHZG1UNW9MVElNWUJ2LzlHazg1M1V1WEFDeVpw?=
 =?utf-8?B?TWpDOVZtQ2N1M3kySU40Y3Q3MWV2dC8wUWw0QUFJTkRPN3NmZmNBUXo4ekR6?=
 =?utf-8?B?V0ZncGtjQzQ2WGV5RUV5M3N1eWk4cDNubXFGMkoyZWpNY1c2SXJ5QTd4ZXRQ?=
 =?utf-8?B?b2h4TkZSTEZFTkczKzdzT21yZkVzK3pOMDlKV3NITDE1Q2VBQ0tVdWdDcE1i?=
 =?utf-8?B?Ykd6SlBPZVQ2YlZFUWFRS2o1K29yNlhUdnV5NEVGUWpqQUU1Q1ZyUGFMN0Vj?=
 =?utf-8?B?MjA5SFNnVTNVc1prMEw1LzhxS2hZZFpYTm9TamxOdlNCS3pCUnJxRTNmWUp5?=
 =?utf-8?B?SG1Pc1B4cUw5Y3VMN2U3OU02bVhCdUFJVGhzQzlUN3EvdVNYc2phMHFoSDdG?=
 =?utf-8?B?NFRnKzJDRW5ONmdGblRrUmRRa2U5N3lSODJTY0lNWHFLWlFkMWp0aHQ3R2dv?=
 =?utf-8?B?cXdIY2xNQ2JlQVZoc2VNL2ptMy8xT3FXdTkwN1ordXZtNFc0bStDVXBDcGVH?=
 =?utf-8?Q?f4dW6tbCcB8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?M1U5Nzg5L2lSWjNqemEyeitmR2VINUtlSU85UzVROVJpZTdocVZMYWhaS0JV?=
 =?utf-8?B?blB3M3pXNUowMGZ2WUl0OGloUFF3QXk2RnVHemg5RFJTRzRWYUpwSmdoUGlL?=
 =?utf-8?B?SzFYRCtoVG5seXlpcm02ajN1TnpyenBXUTlNUSt3ZTFqb2FoS1pCUVJNYmVJ?=
 =?utf-8?B?amRERXkrWkRoZzh6V21YbldBUzBqVjFONlZFdGVsTWdGb2hncG1SMk1xUUU0?=
 =?utf-8?B?UWxNVWN3bnhBTFNPZHNXZGM2ZVFoTmJsMi9QU0UrendSaWxYK29mZENCOGlu?=
 =?utf-8?B?aC9nS2Fma2xOSHJLdzRuZ2F0cUNuUGxQK0F3STh6ZG9VVDBtOXZPTkgzdmJF?=
 =?utf-8?B?VWJvM1hYYnJaSVBuVXdtdnJ2UXJXUEcySm9lWG9kSnNmSzdaTnJGTkR4eUcx?=
 =?utf-8?B?OGt3QXdEMTBmcmwrMjJNRnVLdDdnOG9wVjUvWHRyQVFpM0MzN3h4MXJaS1VD?=
 =?utf-8?B?N0N3WTBKK0xuYmhySUpUK2djYzFodmwwNHBWdklScjhMc0s3Z29XQ1BjN3dD?=
 =?utf-8?B?MG0xNnlUOHYvSzFFb2I4SklpRjlKSVZKM2lYK1pPWVcyRHRhOHF1czVCZEVF?=
 =?utf-8?B?R2IyRjNzVVE4bHorbFBhdmRSd1NvOTVJMzZlN1hhSk1XaDBBL3hLai9IMUdQ?=
 =?utf-8?B?MlRhM0NENDBLV2hLQ1ZvY0hoVEhTb3ZBTmorQlVoNUUrQnU0ZWtRMXQ1b2J2?=
 =?utf-8?B?eGpxaFhCOG1KV1pqZnJZNTRsUFRvR2lVdE8yMHBUQjEzZ1ZLSGtsMjdTSkRT?=
 =?utf-8?B?SDI3MER5S1B5eTNvaHZNU3R3VXV0bWVRVEJSUVNFRW5rY2FFaVlpeFZ5ZkZr?=
 =?utf-8?B?d0xXdzJEb2U4cCs3eDF3ODdNVHRFaERsdVdoSnZnd2k0U1E4ZStaWGNpSUZr?=
 =?utf-8?B?K2drT3FCZXNzbks5c25Idks3Ym16dEpqclVCbVRVaXMzWWlFUWVRcm5GbVlt?=
 =?utf-8?B?YmFMR3lBQ3M1WEJLWU42aEpIaEZvb3MrSkdsRFByaDNPejkzQnZQUjNEK2Y5?=
 =?utf-8?B?Mzl5ZE1XUEZPNDM1RlptNC9HU1JQSGFQMU1pUnBUWlA4MDE3UzV6dHVOQUtp?=
 =?utf-8?B?QVpQSUs4b1djVjN2QjYzdjYxVXJJQk01Tnhic3doemFDWFIvSy85THM5eTUx?=
 =?utf-8?B?MU1NUE45aWg1L3lSb01rdDk5TjE3bXJaV2VEQU1XT1hISlJLMnlqaEJUejZJ?=
 =?utf-8?B?cFowbGNoSm40b2dEMkFUQ1REZ21aQ1RSaktSVzhoTEg1aUdUYXgzTk1UcVdq?=
 =?utf-8?B?ZXVWSWxqS0lwYzdwUHJQWGY0Ylk5QkVnZmZqM2hscTJ5ZzlzYWZMOTNvNUcv?=
 =?utf-8?B?Y3I0eCtmV3lUZTVXZm82akxJZGR5ejFkdEdRWVBLSlUwbFFZSTYzK2hQbTF3?=
 =?utf-8?B?TjRjU2dWdVlPRDBFVnR3aEYyQnRtUGlRTldMUXQvVnZhbjZrWVlqdWQ0cVBX?=
 =?utf-8?B?a0hpd1RxRk9SY0ZUaVJJRWZWTGs3RkJzWmtZUmJUMFl6dU9ML1BKczZtRmxD?=
 =?utf-8?B?R0JJVlRMaHFEU0NhZDdhdFVqbGs0WWFsOE1nK0h5WEtneXBPam9Fa3g2NGww?=
 =?utf-8?B?MTBxUGh5elp4UGQwZ0FKdWJvdXFkR3B4eGkvQ1VYUHFacWhZVE55U2llNy9i?=
 =?utf-8?B?bnBadllEa3d2TkNYSDlMSjZRMFhoVVFidjRvUU1PNGhkeW1wVms4Z0xZeWV2?=
 =?utf-8?B?cjJSME45TGFQSXFzdkJYK3k5U05kNGgyWWRkb09lU3F5d2UwRmVYeTZtUzJP?=
 =?utf-8?B?UHJsZTFPSTI2N0xUcVpaQ1RsZEtpQ1puTWpSMldweVdTQVVpY3NjdGljd1R6?=
 =?utf-8?B?ZlhBc05hbE9hU0cwc0Fma3dwdjlIU3RYMFJLMnRqaW1rbGQwKzZhYmdOeTd4?=
 =?utf-8?B?Mkx6elM3b2ZyTm5nOGpYWitubnZGK0crUzZLNEFaVkg2ZEZMWm02QXZJcGxQ?=
 =?utf-8?B?Y05zN0VKL1lpVk5VSnlJVk5vMVpVdHQ4bW04amtxS3JlY3c0cEdueXRPZ1NQ?=
 =?utf-8?B?Wm0zVXpiVUU1eTFiZUxldmNZNitPR242T3g1WDFxNEpkMWRKZ1N0VmM2TVFF?=
 =?utf-8?B?OEtrRzdGOHY5SG56TlJwc25TdXhBWkZRclIxd0JGeDMwZzZYWDZwMkVMdzI5?=
 =?utf-8?Q?iGSEfvKbOqJjhZOwyafJMnQlm?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f97d9f8a-d383-4ed4-3ac0-08dde0f3d36a
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 20:46:38.6244
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RSGSzTIr7NyGNE6H/rambemJg2q/cUNnow64qllaMHUBPoVY1W9d6OWZBuLELSR0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR12MB6576
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=svFEWHWH;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2417::620 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Zi Yan <ziy@nvidia.com>
Reply-To: Zi Yan <ziy@nvidia.com>
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

On 21 Aug 2025, at 16:06, David Hildenbrand wrote:

> Let's limit the maximum folio size in problematic kernel config where
> the memmap is allocated per memory section (SPARSEMEM without
> SPARSEMEM_VMEMMAP) to a single memory section.
>
> Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
> but not SPARSEMEM_VMEMMAP: sh.
>
> Fortunately, the biggest hugetlb size sh supports is 64 MiB
> (HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
> (SECTION_SIZE_BITS =3D=3D 26), so their use case is not degraded.
>
> As folios and memory sections are naturally aligned to their order-2 size
> in memory, consequently a single folio can no longer span multiple memory
> sections on these problematic kernel configs.
>
> nth_page() is no longer required when operating within a single compound
> page / folio.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  include/linux/mm.h | 22 ++++++++++++++++++----
>  1 file changed, 18 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 77737cbf2216a..48a985e17ef4e 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct fo=
lio *folio)
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
> + * There is no real limit on the folio size. We limit them to the maximu=
m we
> + * currently expect.

The comment about hugetlbfs is helpful here, since the other folios are sti=
ll
limited by buddy allocator=E2=80=99s MAX_ORDER.

> + */
> +#define MAX_FOLIO_ORDER		PUD_ORDER
>  #endif
>
>  #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
> --=20
> 2.50.1

Otherwise, Reviewed-by: Zi Yan <ziy@nvidia.com>

Best Regards,
Yan, Zi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/F=
FF22E91-6CA5-4C8F-92DE-89C22DB3EAD7%40nvidia.com.
