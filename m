Return-Path: <kasan-dev+bncBD6LBUWO5UMBBH56YLCQMGQEPENROJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BE0EB3A9EF
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:25:57 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70dd4405514sf38531196d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:25:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756405536; cv=pass;
        d=google.com; s=arc-20240605;
        b=D+FZPSIdcDuNGqG2TzzSjzz3anTPYXjNteSmSOtzbbXEnUIpIRXzo+6EBjVsUnDabO
         p5rYarD/oTedZLu5LQVecEzlV/ymJaW2CeijyBSpslsp3NjP6e2BbWBx6qZIgYzLrVLG
         euKZxKKgeAKuLxUSHYdLyGmjqQTuYPl/DzYaiMmIR0SloVrY0yxMz/u/JPnDHn5cLljb
         Goc5eVG8e9oNvuVfTXxSDuHAPWb8++/x/dUNq1JRKwosyujXoJ1grNMiMCZxSqq3JGq8
         xqPmk081Y/qai1D8J2nKY6yOwPMNz4AM2kk2WJp1yCZDUJvjxFAUOgQYHtID4XSmYQ6m
         Qadg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Iyp/hbmHguqzp8wWYXUsFYrPr0msW+DaLZvpb0VsUb0=;
        fh=gXNx+T+ONVt1PKa7FheihLN1XRmIqSjjXkR+NNsal2k=;
        b=a8HFBdB/AOQ3bpGm+nR7DctzMPh3d/5+/JFEJ25qN9ARNsmhrIWOAW9EyJtnm+Mjxf
         we7AKZoJXojK1KTBSpJWjVrflYd0A+xUCVv0xq/n+yEEr0xvSqu0npApftnOTKd7CmHU
         zApbWGmLjncvGkyOxuT9MmcmUvhZw5UhA3dSRsosNcbEPhcDIecHAHeagPAY+O2xfeIj
         J9t6yjtSFNxEeh4dO9FgEe8EfOeQg21FvWnjR8EEG4oqrV+L/SOAYxcKMK9J14JaBhE2
         HKewVdagptpqaSaF8RQl92zj6hjLr+JlT0SlJsfEgJ66wMgK3VgXATU8ijVwqVD2raE1
         xbpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="M2xCNDW/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HB4NuIDy;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756405536; x=1757010336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Iyp/hbmHguqzp8wWYXUsFYrPr0msW+DaLZvpb0VsUb0=;
        b=BQ68TqqqyXheOaIfBi03wKQl+mmomSNR8nyxAUkUO3a5hd+/qdBXv3hKr4GcUnch0D
         Pz4Fk9O5mNhfzdruz0SxHdHHzW/ECTN0EElm1jclIJ2XEnI3+La1VLA0YPFTqfEyFwCd
         X9hAuUMDWjVkAp3NtWgXfeSXuHs5Y1hSQxgA1SDekN0q3xaWmJFTvUXl07431BzaGmRH
         UIvBC/pofHyh4cJLfX1udsFu2VvvLxzmxDekH6tnK3SWKL4BofwhoHOeGWJBSL9Z9rwG
         53FkXB5/xblMNfXhl6+qRkrin/SpTXIACMvd53NOPHGYHTQToQctIj7sq6o5Tsus5Wzz
         IdEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756405536; x=1757010336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Iyp/hbmHguqzp8wWYXUsFYrPr0msW+DaLZvpb0VsUb0=;
        b=dB3zPAGVy7R3QqFTi3p3zLP9aI0Vpu+ekxZy8RTaFdEpDBdIyVJHxopHJ8IASRUz35
         tUoG3ReI7nFXumYSsqrZ38dQLLkW9iRxV5bzhnrXaOU0HJxCRcQSTmLLoFWRIQzw/ykc
         LJFF9h4vq5qiGOZtAKaesESZW3/zLKj4YNSiRtKGqbtux+WayjeQ4aUOkgduum25Etx4
         oQB3UngdNcXQk26hUZ8Qn4eMaS+OT0ADcOdAxLOxEeCp0RfgLvu4s7iuFrejXLo8Lq2a
         J96Erm7olbGoR8UeUoiAex148CXatYzFYmRboTlDuRBbK4ved6k3/ronkFFug9IsFmqe
         MXUA==
X-Forwarded-Encrypted: i=3; AJvYcCXf9G6ObquCAu0XcMdKjGdlC2hhOaqRZcPVVCZT1D693pgnt/A+Su2U4wxj3I8IQqa+7vR/HQ==@lfdr.de
X-Gm-Message-State: AOJu0YwO0MOakEPPnw9zUemECmq7oOOmWlmeRmPP+4b8Wasl6oHthQ09
	Q5F5WjjClzyMB4MbMQFFqvU1SItqmA/G318yKkw0n9RQNQifnch2/BUz
X-Google-Smtp-Source: AGHT+IHjxj1NvM3AWF3iOANcR4W04XYuOsU1ldXrnX4xhz5/YaZeWeBHLUyxDsn/PMJXBVWInQLBgg==
X-Received: by 2002:a05:6214:21ee:b0:70d:a712:617e with SMTP id 6a1803df08f44-70da7126252mr230767866d6.66.1756405535967;
        Thu, 28 Aug 2025 11:25:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeaG8yCFpfzgh6+PQHtWF5Oaf41q2R8h2TYeUsbvd6mRw==
Received: by 2002:a05:6214:5086:b0:70d:ac70:48d7 with SMTP id
 6a1803df08f44-70df04c3d06ls17363286d6.1.-pod-prod-06-us; Thu, 28 Aug 2025
 11:25:35 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV/GhmsFrKPmzthr+4OkcXgdzAG+/CEzSPHo0UedwrxqtxPxPLwGyzYqCyGD84T1/qT4LkPWxNLGOs=@googlegroups.com
X-Received: by 2002:a05:6122:1686:b0:537:7606:2544 with SMTP id 71dfb90a1353d-53c8a2814bcmr7184330e0c.2.1756405534991;
        Thu, 28 Aug 2025 11:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756405534; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xv1zQfdBEOcNArYmXLq9lH+nDqD1e+XJW3lTZ4NOMqKjWY9eURjo5Qma0hYGCHVFnv
         99EC1AEbz4NZxHgI5uP1qhQ4Ra/3tltAF1aRzIT0NaM4XIE3Yln+FgZDWTvHPQl3N0sl
         zerrN7pPwMvIPHygQ7ZNIL84f6mpijoKRpcz6G6VJX0MDnxEKlSyyEJ1Uz6GcNufwvzk
         hB95DZQk8ADXOl7trYaEgDY97ySUVgzuzVL38lAaD6nQb1qA7SpZ20wci43Z4blz2ZI2
         drAm3+9vkmniIuI2J+WHjl/clFhGxnFuL76Q7UUU0Vv4ju7nebO5GCIhBKd8Hoe4ttsb
         Grxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=5Wzj7I6omxHBLPSuBf5OyOAftJjkQzQ3dAldM03YV9Y=;
        fh=nDVLMfpnt16dAvQHlJ/+ZWR3WaZCA+P2x3XNdYCnLhM=;
        b=UGT1OUHHfukYJr0nYX6+l2/0V9yNBeEpLmZ9UvN2ivbCuhiWQmYG2NbXS+GElHEdYo
         X0D0dW1d2ZtqcZO6K1cvBNFqvoCwV+MzFl8UGj4ZVy1wuGbTZIfdArbumCw6DuSO36Pn
         9DAhgcgdY1CN5qGseUfix11VtTxyqyJ56Okf/weGUlby7V643j0hFZU3dheiKt4xHBWZ
         rrCm1o+ItKOfAw7WcQbqsC25vSRpGQaYehQ8JR4mYjUS2y+CJZItcsX4BdH8lJwr5+Bo
         KgPlaGmdBkJMM0lZoy6a15c5XhglCjNwNO6HK+dGIPuDDeGlm9LVuzVk8DbmfZMF1QsQ
         wHdg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="M2xCNDW/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HB4NuIDy;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943890b28fsi11606241.1.2025.08.28.11.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 11:25:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMqiH030390;
	Thu, 28 Aug 2025 18:25:28 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q58s94mu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:25:28 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SI1Wuh012167;
	Thu, 28 Aug 2025 18:25:27 GMT
Received: from nam10-mw2-obe.outbound.protection.outlook.com (mail-mw2nam10on2066.outbound.protection.outlook.com [40.107.94.66])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c7fke-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:25:27 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=DIjqqBrvUMfVYKnDBxMYLTCloE9zainXgXIpx+hidF7+d5EXacyJS1gcJkEAbl+dZ9QGwmH1eLr4pzC3Fop9g+o3eFHFMqLQ5PY4hZ9NnR+Q7kWIbTeCvr8ZtpSA/wviR3oW8i6RopJN7N+AQn4tz7oVfFn55RUQ95YwOJmQUVREsr/VV6qpYvYtH+QFmgiS/CzY8ByqMNzZzAB/sV+/8v9H+1QrVFj07oaxsR9HF0JEe3wGQsDMd51RMjcvZoGEk0m3Nx6dClnBV2mrVJpZ6dusW/WC+ns9jK2uZDwpwCv2s1nw/N8flAw+BjRSYIQ5lSVkUu46uoutz0X4cbxlvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5Wzj7I6omxHBLPSuBf5OyOAftJjkQzQ3dAldM03YV9Y=;
 b=sNOhkrq/iriiSkhcfTY/2Fu4hIWt33a2dLmYQXIYbG/ilSmtc0sOgS/tjYFE2kkJFds/tWe1colInRUzWHrjrF9wFMdFZk95fHe4lTaK2kB15wJUrbtwx/gNtsi00PDPUvFQXydZV14YKRLG89n8RnROXOfs/aBQnvjsWOHTcJ5RBMznp74vYbJkDQuQOOTvWjeZIfJ7EJSbMf+LOnY9+NnqYgMACORn2wLu8/eS/QnR91ery6M47HiRmEDm15p4/qmYG/z/V7TsxZtt54y/TM4xH7KhVSKs//tZ9FRwX6y4C7HtA1bu3Qmdu7XNAlabnSaE3me3oIyJTPu+xwXWIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB4621.namprd10.prod.outlook.com (2603:10b6:a03:2d1::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.16; Thu, 28 Aug
 2025 18:25:20 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 18:25:20 +0000
Date: Thu, 28 Aug 2025 19:25:12 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH v1 36/36] mm: remove nth_page()
Message-ID: <18c6a175-507f-464c-b776-67d346863ddf@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-37-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-37-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0380.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18f::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB4621:EE_
X-MS-Office365-Filtering-Correlation-Id: 31387df9-81e8-401a-e121-08dde6603eed
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1EJmPwV/EbfWaaoErR0D+4FYLifVyZqPVqz2aFCycHpsDWif73B9rcds74tK?=
 =?us-ascii?Q?BYQI7XzQpgw3UqtbG5XQ6zsn4o69Qw4OdtZ6SQCyfiplLw65Im4OaFb2L68j?=
 =?us-ascii?Q?5+NXpr7DPczCMwYOEN90Tls1zkIEJCVnkykrL1U8sTQXje1exGjXO9wf2d3n?=
 =?us-ascii?Q?MVaoqhalC4JHhlKkiTlCpOmlh5QR+WHYKefGdJxyh4hFxsP3V9C2PutC/6VO?=
 =?us-ascii?Q?1sMWFlWJDl+cAyX96M17bRuQC155DXa6HYGC8Nu2J8Oz0PbuE3go42rsC7ap?=
 =?us-ascii?Q?GL/VXqQ9qwaC0rgt/gZvpFbgPTvnGcYcKd2QdPW1rw7PLZ09CSMT2u1UkPbj?=
 =?us-ascii?Q?tHZiKRglYptfzz1SrUtxOjl+XdUZ8WWzBLWANkiHKybXKV9r+yrvIbZACYNd?=
 =?us-ascii?Q?oFTDNy7ILgC6B5Wd1zba6YyC3H5/UlVEIbUR3SndSfLD6a1j7zItY8QNeHyT?=
 =?us-ascii?Q?f3LyGu3cQHbinjKNwZfOxfNde+eliTfPoBtu2BvPkRb0qStlmV213Wq2xvp8?=
 =?us-ascii?Q?ukX3SDESibPGz53LXACyY+568dm0cUYUXQJFHbF+Bvf0p0wfjEPXb9CxhzJU?=
 =?us-ascii?Q?BEMRQrvmObIkCGEgmT1ersxVbTOEFiEWLHV4rsMAbh0VVXC2GJ3UXabhH6vU?=
 =?us-ascii?Q?LKeggWDQrxb23Gy6YLO35drVXM8GAgODM5VkbSTOm6tYNGEez982VNtLRdyD?=
 =?us-ascii?Q?zIF2uOorU2WJmqEoEAuvni6poXjJY86LzLUsd5TkLc5V0clYxX4Vn8ikN/Uz?=
 =?us-ascii?Q?EkUBrBv3B9rxom1sI0/raxy0LiO5nhty1uGd2Wh+Rsj0BM/Wp/iAfWmKG6s1?=
 =?us-ascii?Q?MHuJB8A4qHWULvzSRZzvbACbVmBk/zpjn/fQwbM3onI09N+EvkP009LBRwH4?=
 =?us-ascii?Q?lTO3ciDfi1X5gbFya/eda8GIRKH9FBEIdn3TsFSaAYNMbvjz6fpkBxHf0oy3?=
 =?us-ascii?Q?+/6LvMazE9rWImBwEGRa64JUsLpt0X5O3nLwhWHwb/cnwtnFOCfHf+4atnQy?=
 =?us-ascii?Q?rwptC/ZO1lAbTmBOxfrKXsanmkVO0CNE7maRXLvZhueIIMChwwISfr+0JvLZ?=
 =?us-ascii?Q?72vnRLZzQhLz7mBOdRhjeJQp2qv1w+MoC1nCQqtCcPMGZztlxGducSIeuiPn?=
 =?us-ascii?Q?uVSZC+KK3K/Dp4bKHYgCV+QTUBoOGlGcLH7wdybJFlb0Dkpc+9TAYp12O1jt?=
 =?us-ascii?Q?TR7ySNboqmcUgG0Dc1LOiCWjSdv4P74AOjYybC1vZz1XsVVUyLhB8/UupUt+?=
 =?us-ascii?Q?uL3D8JE/4D2ZbkdtX8nQITv+HtO98/tbbxLqsJ7ev+wwb8CKr4NWtynoVRQZ?=
 =?us-ascii?Q?tCpFd40SFGBtWRF3R3taaOX7uDRzothQsxL4Uo7weJuJSHZLodFuoiZkyS/0?=
 =?us-ascii?Q?96TzOMory52x3pxgpw/tikxz1byEKunysKqCBHhyyFAAnf0QsistDk6sBJHx?=
 =?us-ascii?Q?ZdSJv0rtiAo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1pLSc7vL82gALLDAkkRYwEJKqZJmghG+iymABWPDKcJaGqacLOiLSlPLWMyE?=
 =?us-ascii?Q?+0qDC8135Rmta+rp/UnQU6LVbZB1CSHDMiQ6jQtaoMZF4qpLc5iWTuJzHK9I?=
 =?us-ascii?Q?h+g6Ak+XBSTB29KpoyyX5zMpvuNhF/Od6iw6Ah8j573n6b5HAX4wUVfC837z?=
 =?us-ascii?Q?iVL9VwEnC1jiVVz1aRA1S9dgu02t9Y955Pn117sfztibPrBFCYOB3ghop/pa?=
 =?us-ascii?Q?AzeACYkHJjCPCMQj4+Fdth1/uxbfE+S4Di4Q+vl3iVyHRnjVJAJVY6fR2sjM?=
 =?us-ascii?Q?eQApaEMwqj0+AVrd0PKtyuvsiW28Lj8uFJX18VTFwxdspnBTu5X9i9gNZomS?=
 =?us-ascii?Q?lzG1z+a2CsN1VrVNQ3F2BZcb5X+hcqonDgE2CZRyCM4DWQqthjmY5P7dbKNm?=
 =?us-ascii?Q?YetavIOq3d6E2SVsjInfvp6lf4m+cnhtPQT7yYtPjwj/v0+VI4qW4uK1uBdU?=
 =?us-ascii?Q?dZ/a+YVBGpN8MXInDJNF33RZV8tgdYelE7vmAW8e/2MQrMAfUFcrV7JyNttY?=
 =?us-ascii?Q?svqEjuZBc+ynrRFLpWnQzTgsLhv5s7FmRjyiDw7/EV5CtD/OHKS+OROw9l4K?=
 =?us-ascii?Q?wQL7HDDwi+SQsnir3VoK3xRMNrRR4U7po56fliKDMnmOwZHXIm70d9OnMIuI?=
 =?us-ascii?Q?7g5eS/UltH4Bi80IoyJWLTFLkPxDq0nrRZTXHyhN+kX03j4qmozrgiRAxVBc?=
 =?us-ascii?Q?9CJvl8guKSZBMFyNxFo8ucOY1LqrhZXT2qsk1sGHNn9/8VF0UV9ZmMBzqYUc?=
 =?us-ascii?Q?aljfVLaUto/KEan3FJ4/T4G/bSWBXBxufDW3KN6kAnfBWmBWaslDzCk+DPpn?=
 =?us-ascii?Q?UgbFIF5ZsA1YouzI+FLTdEmYBKzEvR88jtXXekJLIx4Y1LEV7aVxj1gl6OXG?=
 =?us-ascii?Q?i0z3ZzQ1HqoLKOvVLZ6eF32ZSDyijyI2qraWfSXb62W2/6giNmJajyzNaXYh?=
 =?us-ascii?Q?iX8bQ5c+1tVJlF2gowozhiWKr4immpAnaEuXqNmP1vLif+3w8ksz71RUmO7L?=
 =?us-ascii?Q?cJlkKBjIsPfuZIBFuF3TKvGSEBhpt5/J9smcRXT87JmiDA/kIP8/1Wd2lVga?=
 =?us-ascii?Q?tM7Xb7YdHDhVMTxM7zv08dFtDKf6uVegRLIZAmalncOvbd3+woj65Vc9B0gP?=
 =?us-ascii?Q?PkDwKCsNPqaW/hB+EhMdYbY7WoUsytkpRnJMfsuQjwcrK5pEJW5vP9NubUYI?=
 =?us-ascii?Q?Y1nCxzaCioA0kWFKeuh0nYezjmjLsOX/sB99ODiOnbVwub912QaB6rmTniXG?=
 =?us-ascii?Q?LoHFO955jHkjH2EFXb0Ha1jLXH9jme1aNVH4A8Kf0jzZ3xdOM5LGdyjWrau1?=
 =?us-ascii?Q?aYV121BaQHrDbHkXRR87Ve09NmAKVVVHlLfnxt7uLcl5XsG5/t/0PF0/mH28?=
 =?us-ascii?Q?BTzIj+u8GJxFxhzOZ5aIWeSTCLLZRl2ssfgi2YSM9FiOwjuiwLTOMXQbNy0u?=
 =?us-ascii?Q?q+JU1BC3YpFyKtRF1QbQeWN/s3VqI0m29rSOqQwnENWbL5+5BKGMUdhapxGk?=
 =?us-ascii?Q?sIxybevKhk4ES9Fp7aMBxNc1osW7S+InLsZez7LMgBl+ZqHjtJU6BpV207Et?=
 =?us-ascii?Q?tpoUfz+d/UfNnYTr96fvdylb+tzNRcz3REn0Qhq+iWOuliJDHcgPmMmzpLeC?=
 =?us-ascii?Q?CQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: y+eEmb6IYTQM2uWwtJWs00QOxhFqJd4nJ5ZSNuRSPZFjIOanlVnUzJsG8Nyf6h0MN83hYx3Q+ewpeuAaDvLM/scIDnYFW+bGuF1ukkvQk01Eb3g6qzBLGr6TR9E4zsyHHVwxiLWusiYd7hPpb7k//Oj/v/o+J5vtfZ8SfdR1ARBcpPwvZV+1e6jH6MzEhZynGXalkTDMgNskNU7sf9VkofsJbfATxKWjomHsfd4hFF+8w85LejzVEYDBPShdRmKaIfn87/PiumPdJW67JQJikDZkB3AS3N+nq2xxk6pQkK1EeyqhPsy+MjO6Qvt+UqWUekzNTRtH0pqL9WIaH+fgyJgCg2PTPo6kdUHm9w1s4lM4tY+rkyO6mnTvhenjg6VJF0SmvyqEKyMyCoI0C7WDWoVkKvxeZ1DmXQrqcpmkE4yHEh6OwAs/TyRq8aozETfeat1gyXG/ysAY2xqyOv4LaTru8L3hncKSVA/oFQen1tIo6SxLiD/OXViFX5Lk5cFLq0JgMqOKDlq4qsENO5cksdhOLIHtQ+v6Aa14gRydkbJG6zzR9ePvJdBEmcl07efAFJwprdAiutXLzg6fbUy6dWctz1OD7jaA7hF43O/pYbY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 31387df9-81e8-401a-e121-08dde6603eed
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 18:25:20.4366
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0O5qaH+do0+1IWmRXgKK5GoFj3OQET+hlp4IZ8kLgtYtMJbv080YLPP5WTVbQOg5QjK5pFVBZLaxk91iTwATfJYvG5zsTa3r4Okmzn6JkUo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4621
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280154
X-Authority-Analysis: v=2.4 cv=J6mq7BnS c=1 sm=1 tr=0 ts=68b09f18 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8
 a=m2c6sf9u4xuizvxJlxgA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Proofpoint-GUID: 1AIOKZ7DiS7gajcwdpv0Ucz-0iIAbDNd
X-Proofpoint-ORIG-GUID: 1AIOKZ7DiS7gajcwdpv0Ucz-0iIAbDNd
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAyNyBTYWx0ZWRfX8c2JsYrZabso
 z4fEVpPiU6/wALxsXeQAWIB5TCOqMhaD/4QgO0GLe5rSsvBzdjUMCLAh3GuYtMm0OzM3wIXobgo
 ebhrX1TqO/dsbBbRJVIYnZZHNoodXIdTWTFEq7mlXqhD74wnmYmkQIT/3I/y9ZPyPO9GKvVlRTk
 zbVS+7Yo/PxoKZU/Suq2o8Q64xceWdQrwkXXY4Tkz5OUq9Zi2jmegTw3u8FhUmQfOyjto+eoKUi
 2HBQzM0L9bC/JkZhF4gQUb4wHJawMvzkrpML6ZokOe4mhK06D3cY0ZoYri1dh5WyvSGJb7oaB8z
 NU/elzeyiXLqQ+konRrfK8kusqz6LRuSqPOTEhbS2FocxiOMQ1J+8tYPuvLg1U6A8xMuB9D1rV2
 S0WOp4Yg14L8Ss43c6WfviVGa2FQMg==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="M2xCNDW/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=HB4NuIDy;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:40AM +0200, David Hildenbrand wrote:
> Now that all users are gone, let's remove it.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>

HAPPY DAYYS!!!!

Happy to have reached this bit, great work! :)

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  include/linux/mm.h                   | 2 --
>  tools/testing/scatterlist/linux/mm.h | 1 -
>  2 files changed, 3 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 2ca1eb2db63ec..b26ca8b2162d9 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -210,9 +210,7 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>
>  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>  bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
> -#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>  #else
> -#define nth_page(page,n) ((page) + (n))
>  static inline bool page_range_contiguous(const struct page *page,
>  		unsigned long nr_pages)
>  {
> diff --git a/tools/testing/scatterlist/linux/mm.h b/tools/testing/scatterlist/linux/mm.h
> index 5bd9e6e806254..121ae78d6e885 100644
> --- a/tools/testing/scatterlist/linux/mm.h
> +++ b/tools/testing/scatterlist/linux/mm.h
> @@ -51,7 +51,6 @@ static inline unsigned long page_to_phys(struct page *page)
>
>  #define page_to_pfn(page) ((unsigned long)(page) / PAGE_SIZE)
>  #define pfn_to_page(pfn) (void *)((pfn) * PAGE_SIZE)
> -#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>
>  #define __min(t1, t2, min1, min2, x, y) ({              \
>  	t1 min1 = (x);                                  \
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/18c6a175-507f-464c-b776-67d346863ddf%40lucifer.local.
