Return-Path: <kasan-dev+bncBD6LBUWO5UMBBLNRYLCQMGQEADG2O7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E78CB3A910
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:58:07 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-77220823fefsf612871b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:58:07 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756403885; cv=pass;
        d=google.com; s=arc-20240605;
        b=aFjrJwF/8W8D8/UAOSHY3bMrTdhQDSfIFyTkzoCoxjLdr+9mUWMKU9PTihFIps4Q4U
         F6QSRM1rzFZlcw+K9i5Scji5ZI8FFlcPsIELX6/RB2+jTT2yb17n3jZGg5EwWdVZoDts
         IyCpIHBVuGO0bjNhk4SItquxxThtNaRqKWPq6TQEKAAESQ003n3pL8CyQmSUEB5zm/DE
         x/ehTCTv50KONvwnAmnZ9q3oECEh0//1o0rBFBOT69+Stgz1IT5AIPWc4Gj5nni+W7+Q
         J/DKSJDlvesf/0lN0YkLGUXwWbZzHHJfi6s04prB+S+kaz1Lr2X6bGDhh2muY7cGwLzc
         d8dA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ErImlNqDXWWPiNJs6XYSqRN22fV1mnfulJPLZ2Pm2bE=;
        fh=Wr0DYmTxzmJAEcgHOP0k3wTRSMMxZCyHJ0oRJXaoE18=;
        b=VyekNROw2dgFKAx2tNbf5A8glOG5Zy+hOTIZC0WcUiFPGw8D8Vis8I7ObrEM8HxfPn
         SGoINlwV4Z/mt4GLRaihevTfgPViTwsISj7KaQLnCUlwKToqyj9eEjHApyj5jbt2BDHb
         Rb+Q/A3TzC1JddB+9dUfHALh46HdOs/Va77Mp/D7uIfWGXbn2xiTMvr02LuSL6bNInQA
         n7VQ7TC4m4wpk8lJz1H6sfnFevlr8cUUU5cBPSe/f7S0yEEPbeKcxPYxQfIazF8ewAzk
         p3qSS1PK+4MhXbY9eC10/HMXdpZ0p8IKCElrxirN0qr+RvCeHOLQa1RIvjv9bHIPjUjD
         fiew==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fF3JHBLp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KCjkhwdK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756403885; x=1757008685; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ErImlNqDXWWPiNJs6XYSqRN22fV1mnfulJPLZ2Pm2bE=;
        b=S5O5Zj+PxL9E52E3fCvZy+uRi0RdN5mv5hUIcZeMrbMHLVKIExcp0+nB3eCKvxVMCJ
         BckjGriSisRVUwqulWB9Osxf6xzEzSJ6BF0l21bEmlvek3hwbdWAoaUA7LXXcMgIM3DA
         G6b5RlCelkdWXxRoj6JzDZUVLw59z4MYv7QlBkN3G2FEEVP6r+7bGMeefZwTJDdm64QQ
         gLLh5S60asQbOFPs69MbBVzqzLeNtKqjImVXANz3G9R0oVIYqY0cum+2jah5U/NUjzyh
         tDB86QQT3G8vsGkNZ4fjBGw/s7ysDyYArY02NJMZVlBFzDZfaCJmAxaLTervIBY9dxV8
         3Nzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756403885; x=1757008685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ErImlNqDXWWPiNJs6XYSqRN22fV1mnfulJPLZ2Pm2bE=;
        b=Gxj+TpTY/T5/dCNJ1v57/w5/7MOz9QF2lsvlIpXV2YPZhhjIdiBRe2TBZphuMPrGig
         zTffLXKq9Twwu8xyAmPYoZq24ETewSbFKtU+clHa4JqiMRH9r1YCWi7ovYzrVZuy4Y9a
         VdB9LwTz4TmmF2NccJ9n99M3QVxzZ2XzLiUqGyd4ptLAStykTBLuJJJfKeiZfG7hxMLa
         nqDGazLPTLAgf2imDTr2r1BmNJPLBepaIEGXO3PVMJPe5lPLEiaW/9YYBcx/xALnrTdT
         NpMYlCJDPdjYyE4D523FtObVd5R3wBlVwRH/Bcw2gZbhqckVHZeO5hb4eepBPz8wXzpO
         Fx6w==
X-Forwarded-Encrypted: i=3; AJvYcCVkSsOMSAgxv1o4Y+uQdljxnn/ca4MiiyQkEvEsDenP0Y8NNZwHu94cl8JH/itGu8q6f8gMeg==@lfdr.de
X-Gm-Message-State: AOJu0Yz30sB3VoGIw3EWSKxZhXtzdKOWW9fwCQs+C8Q36r4UlgGQWaDQ
	M6vNIyCicMOoRsqBthsZd1XV9I7QTFiueooXZff8auQKZEy+ciklY9fQ
X-Google-Smtp-Source: AGHT+IHH0ps17w7fROUdCd+FtMzxYTRR+ViDvHsu5W3e5YagFT481906f6bw8jPgK5w+U49x2kNqmA==
X-Received: by 2002:a05:6a20:734f:b0:231:acae:1977 with SMTP id adf61e73a8af0-24340c0faebmr35795848637.15.1756403885452;
        Thu, 28 Aug 2025 10:58:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmne/Eo8zM7ReYP0tDmOPIbf9RoKJW0P7oL0flEe4zSg==
Received: by 2002:a05:6a00:f8a:b0:730:940f:4fa5 with SMTP id
 d2e1a72fcca58-772181dbd7cls1194879b3a.1.-pod-prod-04-us; Thu, 28 Aug 2025
 10:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXquiYEleLwalh9oTr1+PP+T9aXP3Fl9Rgl2qMMznIOQDCenJ8b/Ml3Bbfrc2e10SNzPMHxeEW0bNI=@googlegroups.com
X-Received: by 2002:a05:6a21:6d8f:b0:238:e08:f283 with SMTP id adf61e73a8af0-24340c0fad3mr35963023637.13.1756403884129;
        Thu, 28 Aug 2025 10:58:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756403884; cv=pass;
        d=google.com; s=arc-20240605;
        b=KZyPkfiNOcf3UeFC+f0+M/JsUTW2bxC98VLGDhuYHeMFfaxNlcu6duTyblnK5G0rD3
         qMw4YFnIPLaD0sFz5JKSbcUQ69XTWAaMSW3IEcJvzxuQU9GUoUw3oJyXmOnIX6bW4mnv
         gkxbIH9Z0ut9nnqcAC6G6eJ9DK27mQb62+tWo4Hd8B7FzzY+2mEMgQ7lagIOd1qQKtQh
         wRNNZExHSmpVk/uXjN498ghGlC2U4x/4b2vuJF0xD4zVfu6xMwW3+Bw/qCJ7IoXw/y3L
         XsBV2LGWdZK0Es5MMqM8ROv1jouYunLNn+RtZFp0x6vleyoR/JQg+9qQBQzNVT98SMta
         bWTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=9cZrz3QvCmIxE0hfAptkXfPVqLUI6aLgQLEHim68YPY=;
        fh=qs/zKwwDi8oVegNZDqpRCQxzkKyAGJIAfQ1wor2K85I=;
        b=X8bqLFYMFJZCkil3ylAPQFACJ4u72UvPB5iSPjeV+obfChKyRlaU0y5qiVUqsGqTK4
         FcDkt3iA+hbC8QbDSw8mZNU3yJlRAWYGOdGGLnZRdufIZOQ0cAAxPZaL3aB9Bb8jXbqS
         idd257IYJ4KfpSnjk3hAFswPP9ZUBZv4MtmEgFdACc1iRSeq9Mxfpf82EnZXv9W1OXne
         fE+3eQFZFYLxsQ5NW79jArxrLBRl4PrQmyyupS0zWaI5RYyPabTGGepyNWuNgf+5xhHg
         407z+YkkN5rc4BrAKltEz8XIOvS5rmqQ5UzXlPqUCDDbxKk107z5HWazb8quC0G59Fjd
         NXKg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fF3JHBLp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KCjkhwdK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4cd3f3b0e3si1705a12.5.2025.08.28.10.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:58:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMqSp006543;
	Thu, 28 Aug 2025 17:57:56 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42t8xgk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:57:55 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHHdQQ014629;
	Thu, 28 Aug 2025 17:57:55 GMT
Received: from nam02-dm3-obe.outbound.protection.outlook.com (mail-dm3nam02on2077.outbound.protection.outlook.com [40.107.95.77])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c71av-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:57:54 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yQlvnE9y2Tpj6h2H/uz85ZgHvkN3OeF2hKR7WdcOYdzzyO2x23C5ogmTsvfoSB/A0Amqg7KITbKJgu4/GoJr+Adw2rNdO+NElkDB7zeQHNeZcg3UUYNTuUvY13i2dIMhrYHuChm2wNSZpARYQt/itXGedSITDa2lq9iKijol/YJsv2q1i2jtRFGwdyyAku9qE1Jrpa1XoFJ2LePgvOuKy5szOH1RyQreW1SoJTXB/uJEW8k6ZXXvIFJIiHH//0svIlTU2qxbTwHZ7JGQSEkP6h2SAwtWmkLbfOzhO3OLikP9yc7RKTQgdLN3jdks5takjp/dZHZEYPKnUwYP034q1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9cZrz3QvCmIxE0hfAptkXfPVqLUI6aLgQLEHim68YPY=;
 b=TJAp0z+onAKoHgwyZ33EqwOYW4r9/L+0+vy6c8lLFtz9lX5fKRIMrPWQR5w7cU6M5v1Ro+JxXoaAGLjXIUQa3BE1nhroEcQAcRHZZLKKHzH06Qs/U5de6iK/YKHdBWckmKzUiqyt/a+bcX/DzvNOFAUtmKXU7rz/BhtcxCIMR5qKrPZV1I0eD0GdFHbMGhhdm94WX2R2kOCEVw/FV6j+QQtlbghkFtWvnJGvtNbFSi4TzeezoqVBrucxilabHwZ/XVI6VT+tI4xoht/qZKhnHEQE+5OMqNX5VB++WkRYtONW+YjLlLIvLlhDZsVfIDjTUL+zXn9huhePyGwhuXZ7WQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB4573.namprd10.prod.outlook.com (2603:10b6:a03:2ac::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.19; Thu, 28 Aug
 2025 17:57:46 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:57:46 +0000
Date: Thu, 28 Aug 2025 18:57:37 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Ulf Hansson <ulf.hansson@linaro.org>,
        Maxim Levitsky <maximlevitsky@gmail.com>, Alex Dubov <oakad@yahoo.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 27/36] memstick: drop nth_page() usage within SG entry
Message-ID: <b86e6769-18e1-4bb5-b9b3-cd11a72e3f2e@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-28-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-28-david@redhat.com>
X-ClientProxiedBy: LO2P123CA0045.GBRP123.PROD.OUTLOOK.COM (2603:10a6:600::33)
 To DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB4573:EE_
X-MS-Office365-Filtering-Correlation-Id: 3d6536ce-176c-4285-81d7-08dde65c650c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?WaM5wlBTDp+s7i+OTEIyAvluZZo9SB443jpRt+pUW7wc4usiRya4Yfa+IhtI?=
 =?us-ascii?Q?1kyS1m4Ikte7GjuWPGZZXojWNIpdAOdRFRuG6atXDuNfVQrZvpnSPlhT7XSG?=
 =?us-ascii?Q?2Lm8Zjys6Q7Iu1vaQx7rgdeeSO90bikvoo5qES67J5WvCvdY/HLRKxqHXH54?=
 =?us-ascii?Q?yKNMJR/gptu0J/zZL7dsjLYrw3NpFJ5zAEGda0hMbEZbBpqoYDGe/OzZ6sm8?=
 =?us-ascii?Q?NTmrkPGQb8OxID2kbhypRSTrhhI4GhKNtU9L2Cx57iSf2OPJ6Uh/LAsz/cEA?=
 =?us-ascii?Q?r0+JBgie9hikO4KHpxSwzlli9p/sGnxJva4+VWX/JiTqvQzWOIbQ5abWTJ+6?=
 =?us-ascii?Q?P0p2VST0tjm/lKlCvyVAQ7QG0Hh+eSuDt9ZR7pVHSruwserxDDcKjM7ThJDL?=
 =?us-ascii?Q?9ta0+FoRyANBZcuwO73yVBYqm07Anfo6Qgbshshz347H0f3/gprskZfg8fkR?=
 =?us-ascii?Q?WEgrivfgXO6ku9EwKrI4KQeU2Z88UgwfeSaGQCgusLqWxK0lOH4A2XnzXJ/z?=
 =?us-ascii?Q?LhxtRAhLVKZYAE1o30UEXAUedhcvW0ldehJC4d7DH00Gb/epPMPV8VT8irs0?=
 =?us-ascii?Q?/EwI/DqiIiDE5LNQvPSi4qHXJmb9wNcX70KKS4om+u9jvsVUWNjnIzqjhdBY?=
 =?us-ascii?Q?SnCFZASnJsa4My4f7/B/I1NULcexrf7WBOxmtZV0FH+YV3hpg+choDpqpqas?=
 =?us-ascii?Q?++Q7Lt1j4rDVtIiel8XRpDLTtGOHwi4xEfPgxvkl1+KdETusD8Hk0n3Charo?=
 =?us-ascii?Q?ZkPxxIw3qQJYF8ketP0yiZTWJrgyoq51m4myJx8mgB1q+4NLJ0uQuML/ELfA?=
 =?us-ascii?Q?2VI9KpmQoIT51Wr4+2pKWG32IbCze8OAN4a914AMY92g/xo8mywLktu5sSPV?=
 =?us-ascii?Q?nz1x+ZoGFOx3rorEoVYFGZJFFz5mg6NLMSXiyj22fv6x/+mwNcX/FPATntUT?=
 =?us-ascii?Q?t2F8jj8jyt+qj/BIOmPSCyCCDCBkZtS/P2Pli/KDTpGgvd2VgJFN7kmOBLgC?=
 =?us-ascii?Q?QFW34Mi6O+3BuXJE2Aa1m4ZyLKtzhGXrOsvkM2LvEwlsTG58eJZv9juhVIkP?=
 =?us-ascii?Q?XnyMmNSM5BWjNRCe2UTMv8K+fIlIHFCgB+x6sGtu/JfYMhMkh+5X7TbltrYT?=
 =?us-ascii?Q?sz2r+zz8NQR8yrrDYL41Jwdfw9cDTk61+SBsAEj1pvbEw8jvPvD3lZZAp5Bf?=
 =?us-ascii?Q?KrYDuFgiZXggUi6NqfJA7LyytY3ArkGu2qocs9XKVmVuMewG6tFMfNUQDV1W?=
 =?us-ascii?Q?pCc07ypN/sJKBtVuZwYy/R/CFKwELu+V4kb9RMReGq2oCPKeJUBq6c6jyiJF?=
 =?us-ascii?Q?Qxr95D3m0h6ctFdRq0VC+GygLE9XjRWFVvLt37q2fFFl0FmQZguXVhhU6MyA?=
 =?us-ascii?Q?d9+5bu9s0foGkW03D+N8tFxka23eAl1EbMmsd7Mafz0Q0DMMUJOc4s649Vdu?=
 =?us-ascii?Q?VyFf7VdXzjs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?pdamH6iUfxgFH1js9efUYp61jt150pJKqjVi//S9E87hPTRpJv/sOP8Sgzlw?=
 =?us-ascii?Q?MK1AYbxFBsEdvEouHjqEBJWeHxZdjCDULAYPLbpYBnv9rxVsxMTagaJhcdfa?=
 =?us-ascii?Q?6UQPpmWyOnN/EHvb2GJPHd6L2Bdr6YL1lKmozaNNgB2isCh8xbFzVktR4+nQ?=
 =?us-ascii?Q?dnYCQWjL/IBiaE7+CrUXxcXE7x/oSfDnOq5W7qzUjvmD5v8tMCcTRXVEBk96?=
 =?us-ascii?Q?/KDL+yrIlgzaDP1YdRZ+SaratSIncEPtJ27OO2OBmmlBCunsNFXUlS2uJuLD?=
 =?us-ascii?Q?62SkJhw4E9f8IVpcIlAzKBWV1xlnfsDijAf0UYW1RrUATQO7DACOhZt9VOXd?=
 =?us-ascii?Q?L1tIYs+vU9B2236Vjvh4ehNj7QiL9yAB+HSYyOEp1qQDK3kYtgFbWlETiGIi?=
 =?us-ascii?Q?MXRepf4B9c+aBkNnS8pQB9fsCSm85ezqUr41Enj1ZP5efdnOlUnyTvpV8At7?=
 =?us-ascii?Q?XiqNpCWWGJt6Ud7Mp6eQvQ3iOy2+aHcAV7WzVeYoyRsZgxpeWD6Wzp9rIB1w?=
 =?us-ascii?Q?/Vb5+kDAcq5/HnSlOQjdTN866KlBAQuz+Mpsr55HfKPfO7/Tj+d8IdkvWZ7F?=
 =?us-ascii?Q?LWBqG5p3yAXjw58BAwSMK+84JcitjYZy9FVx+tfQtxj5ePAJ8NSphMltvNmU?=
 =?us-ascii?Q?ECWaerH63C4la39sZ3l8GYV18Rr88Vw1GnR8jIGvRvohpvILRH8ZCBN3bwIg?=
 =?us-ascii?Q?1sKFIMNVEwcgXWRS+jBnYpVFVi4ve01MArYX7EGl4JVCjRN2nTdZ5T/ffRtq?=
 =?us-ascii?Q?ZHTFbC7XHRTFiOiZHBSlDSfxboPJLaOmYWtJeDuFhXw0sx72XKxKd6e45SLd?=
 =?us-ascii?Q?zxIgMNnspZiyDdZw5XoH96R+dV32lzi1FYtgCvwK4BhAA4Jh9pIWbdqHYwyi?=
 =?us-ascii?Q?HBwn8Ly+wVoO82gtlS+e9ltSLH8wz1h/vn2aDyhz14melp2eoLSYjqbPLhzc?=
 =?us-ascii?Q?LU9HRGjmTyx/LnMqFF9qGN+MyZdaRIR/gRXWhI99D/vdQXeB/pYw88EgQt6J?=
 =?us-ascii?Q?8GM/Bktft54InqQo4A/TqjTZtvxNWC+IYKqisNEAkB3RhmKBgodCUA0/7ia0?=
 =?us-ascii?Q?0r9rBbRlrRiGHOXQWd16Rk6J3n2Nh8Fwre+d4vJ+PzqWcGgBnGfgiGGeQ7m+?=
 =?us-ascii?Q?hQY7FGm5HWZG/Y/zr5judAwfe6dZH2haOmUC7q3YiCtU3g9zEX3MVXxKC0bE?=
 =?us-ascii?Q?rSy2Iy/5k5YttoxchzuyWv6rz8y/vCra3/wnrffjc9zPgRY6Pa15TK9TrxQv?=
 =?us-ascii?Q?pDmMfBqZHFcn4/VuVNlzkgRi2QUx74bzx7qcoDt3T+/4T0IuIbkTjudxBr8O?=
 =?us-ascii?Q?xtTPYgwFA6v4ywWUUVkuJQg/CvOJmvakUH4WcZj1owF1ksKvO4rPTQbLgMv/?=
 =?us-ascii?Q?u7oLUTzjQewRvsA3F5KmnrVweXpvBI4bzvjWn2lmX4KxJBnZmiQoCv5Tf6gd?=
 =?us-ascii?Q?0Lliw4Uu9lWNzkeru2Jc9Wl/QAJuUoTdE6+ys4ud7E1JxZ50Qpx405NIWsvM?=
 =?us-ascii?Q?nbgve01qwlsLNxQUvVhXGXQBHnP7Ak+VMqrnb3Do7jShVt5CVemPH/VChjFE?=
 =?us-ascii?Q?VuYh6Yu/ElehWaXfTwq3h5HhVyXvA8aa7kQrpbf902+bdqc8M0srK6QmeOs9?=
 =?us-ascii?Q?iQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: VR2OgddmozllL5PJlKtaBAC5z4YoP4pB7dFj3tCKTgOZqZzSXkrhSOCcE8iFWeC38O8FlDjv0THF00TdhRlmd5CL6h9TC9mL5Zc9jfUMlP/Wjqs54rzGvhx5GpWbbtrb+QsKVuC7kG0vBHwxppHfw9W9tlpXXHt/v8r0USK/4Bh4Ez2hPR8/VIWxjubjWAVAQuXM61nwJfUA6N3k2ZQRZbd8HVYcylLPcZXoumZhx/xIF8L8UHtTa7Y0PiKSrkmcz6ofDFekKHr26X97uCVXaZ/SxFxh18M3QIl/gkX26UcITVohWyObbrdLdSOl+MMD3AVTzV3VFLtT5SgYpeNiLAAW6Hhwihv7c7N7HpC4mlZHcEn5WrwGdyOL2+f3yisDHhhxfqZ3sb6kDN4IhzobgFY0c5H1Sp/TN7z/VNI0vnTZ863WgcE1pISUW0u+5kp7L4SCFG2OBjaKv4mpFhRbKXMn6ZWiUcHwRsJnfH6XUQCj1NgQORHp+fXQICF38OuuIZSG33U/eOktuQFISheqWHU06lfwmBFojYCKa/eKZRHvTo9vT8QFCkmPGc6sCwpsebKMKbusLx7Fy5WG1mp0vaMZp3slpp5l/bNsbE7I+KY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3d6536ce-176c-4285-81d7-08dde65c650c
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:57:46.3867
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: oyzNSG/kmQUyXNkZKL5BaNMcb+lmS4t4goSzlQYYCaRArqJ81mXV7LQUwgXO4NjE09Oce7JTTTwwBNyTb05hXeWb8e4Xxr1zbwdO+qluaAM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4573
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 phishscore=0 adultscore=0 spamscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280150
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfXzi7lE6e6xBEr
 14BPdHueeigaJzvE9Eg62I+AHaMPJCgNCwASbwbXMQhyl2QIykh4c3n2yciZKUntj0U02d8KrcR
 1AnhweCS4m4XA6SRTm3CiGQPwr4njGZyS5dwjlXRhGerYAeCFT2LCMnEp015kuw6GpQdV1p7BdX
 Ndgi6M8/dw9GeA/YslFXQAU4yDsNckgp0yHZHzn8qJiAoZtX9H3o5QIz388enXcut40A7TCdi/o
 payKNAn921fxj95qYX1pBC7ncIRSwb96snSncYNkLHUIRl4SveRwLdKl3pUxv5OF7IVbSaFPjQe
 7Tb1tlnBoWoeZS2lW+4gpxBpbWdXNlqfRtPuUrw34dsLIFBvQpykAbR5mDIFUtYe5hvvvsN1to4
 97sYA+kYKinGjhE+quf7npz/uMH/4w==
X-Proofpoint-ORIG-GUID: 49VPKPdu7WFsfaTDL8lydvjguw7SHGas
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b098a3 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=KKAkSRfTAAAA:8 a=pGLkceISAAAA:8
 a=CjxXgO3LAAAA:8 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=0XKWupS24O7JAqhbPLcA:9
 a=CjuIK1q_8ugA:10 a=cvBusfyB2V15izCimMoJ:22 cc=ntf awl=host:13602
X-Proofpoint-GUID: 49VPKPdu7WFsfaTDL8lydvjguw7SHGas
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=fF3JHBLp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=KCjkhwdK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

On Thu, Aug 28, 2025 at 12:01:31AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
> Cc: Maxim Levitsky <maximlevitsky@gmail.com>
> Cc: Alex Dubov <oakad@yahoo.com>
> Cc: Ulf Hansson <ulf.hansson@linaro.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/memstick/host/jmb38x_ms.c | 3 +--
>  drivers/memstick/host/tifm_ms.c   | 3 +--
>  2 files changed, 2 insertions(+), 4 deletions(-)
>
> diff --git a/drivers/memstick/host/jmb38x_ms.c b/drivers/memstick/host/jmb38x_ms.c
> index cddddb3a5a27f..79e66e30417c1 100644
> --- a/drivers/memstick/host/jmb38x_ms.c
> +++ b/drivers/memstick/host/jmb38x_ms.c
> @@ -317,8 +317,7 @@ static int jmb38x_ms_transfer_data(struct jmb38x_ms_host *host)
>  		unsigned int p_off;
>
>  		if (host->req->long_data) {
> -			pg = nth_page(sg_page(&host->req->sg),
> -				      off >> PAGE_SHIFT);
> +			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
>  			p_off = offset_in_page(off);
>  			p_cnt = PAGE_SIZE - p_off;
>  			p_cnt = min(p_cnt, length);
> diff --git a/drivers/memstick/host/tifm_ms.c b/drivers/memstick/host/tifm_ms.c
> index db7f3a088fb09..0b6a90661eee5 100644
> --- a/drivers/memstick/host/tifm_ms.c
> +++ b/drivers/memstick/host/tifm_ms.c
> @@ -201,8 +201,7 @@ static unsigned int tifm_ms_transfer_data(struct tifm_ms *host)
>  		unsigned int p_off;
>
>  		if (host->req->long_data) {
> -			pg = nth_page(sg_page(&host->req->sg),
> -				      off >> PAGE_SHIFT);
> +			pg = sg_page(&host->req->sg) + (off >> PAGE_SHIFT);
>  			p_off = offset_in_page(off);
>  			p_cnt = PAGE_SIZE - p_off;
>  			p_cnt = min(p_cnt, length);
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b86e6769-18e1-4bb5-b9b3-cd11a72e3f2e%40lucifer.local.
