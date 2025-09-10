Return-Path: <kasan-dev+bncBD6LBUWO5UMBBT54Q7DAMGQE7WWVCAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1040CB521CB
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:45 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-4111411b387sf30503935ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535823; cv=pass;
        d=google.com; s=arc-20240605;
        b=WM2BA4cM2t0F3u2mfgXHf/mtRIu4qFf7MrD1Auq5hOiCkOu7U5oIzTUuXQCY/O2UJS
         +Rl2bcGJ9hkgED+yCCHzndy44OB7P4Z4MkucLjHh6k7bc/TAhbStq+QR4AwqNSrRnMNy
         fUe6KdPGAyA/60lq9N3f7OlWeHIqd5BBccCIGi4nQxlbBPim/hUMaC4BcEOl/0qVh5AY
         0SRpyFJiiovhD1d/kJ4LhxF6yG+v9r9us8rAHP9X1tN6RKhdKvNtUpZb/aZQwzGbqLWO
         Kq0QrInd3jhXSOlrt2D/eWHsAxNE799INXz0QD7csuR2YPPRXoo3BvP9w+sAe3Rfguea
         mBwQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=X7NuVtPSXTjrzNBH3y+UWOSXlf+hAGmjTCv0mLcldPo=;
        fh=+GkdtWGaHI5GgIglFzyexuVgmR338JCB2T5KtlPukSU=;
        b=TH8rqGytSKt7X+Z9iwMI7wgP49Ohi1GR8SPIxqk13b6EuYvX8tn4ANdBF7AmxOqJrM
         liVxkkTg0/lKNQqm9TF09rbghwlG+XcSZewQ5nlpxeXuqjGVgBlNVxxsGEXdDwXRDaFU
         t1UMfUz27s2kAUR3or1KY0lsXFntqx477vVzubA+onTN29NymLL6f0U0ueU6ykeRvD4w
         UPOGpzDvG/Hr5KT86Z6t4TO8bWjpxoffGdm/TjTSK4/3KkSH/t0cI+8tW4AwTJ2Wf8ku
         m+TBdWyA0mrv0V2k8+4qvS9NcB2AHATu5ByRRmSIwDwExaQh9ARU1GgCrH2y3Rb1NrSK
         h6dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Crjq4f7B;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CYP6rE3h;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535823; x=1758140623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=X7NuVtPSXTjrzNBH3y+UWOSXlf+hAGmjTCv0mLcldPo=;
        b=h7nd+r4yRVao8HlmUOkGJf/tiWkIkrw0TIZFhrwgXv6EkixXhTbUakG+D93JejA7hQ
         P5+bJw3+zlBPT3IYgI1oPD3bVJRVcXZ1XGNE6KXeMpXuQ461JH8v5V/QdLIlBQajDsG/
         mlD7gI4m/GfSAj4eNrp1oZv1uU3+7kH/juf+xdE2n52fHMseuFKl0o5I3ZVbmtSXr0Un
         uRtL7p96ls/Wq6aATRA7d4E7BwxRIQlfgMWM1IUGxsNDNmQm+Lc/2Hc0XAFRzMUuYAPk
         AyLcziA1AD9i8IpVVNc6Dz7jA5hSCnrfnWNBNlI2DQ5tegJotU73vN2/xJ3v/0UM5t5+
         dABQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535823; x=1758140623;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X7NuVtPSXTjrzNBH3y+UWOSXlf+hAGmjTCv0mLcldPo=;
        b=Ez1wl78GqgMFLelBGZ/z/Fr9uVkdxGrIkxUS2/FQkHoBmEnXNkAD7MZAbb+9uLpzzX
         zlFr6x9jsitiqPJfC1TuLS0KCkV9TFxMKp1JnUb/ldYkSqZ0XAmgKAo/clLl8Ox7lQOE
         nLihhYFclhBRflHNRcbuLkGHWzCEaBZKnEF+9yKSRUEYp3uczZiiagBnlNeIlHbRySeB
         O5C07PqWtufux54SEO7mZeaDORGf8txPEJ/HwyjX/H3gru9rRsUsc8YgFg3veASdozTc
         0wHmUydCf/NfMRdqWxl8YXOB52N2OgIQv+RE7ZTHGJzM+zUwV5qUrUXl32lSYgFNt4qX
         BIXw==
X-Forwarded-Encrypted: i=3; AJvYcCW+tPTj/IH7f4wmupwrtntHjpyVHVu7oKzFnjD42hqo5KZZZgdKx7PRvEsEE1mwKcTrNNtCBQ==@lfdr.de
X-Gm-Message-State: AOJu0YzIMfXiZT5VEFdObpw6hjtN8ob9bb41cEEsMCb7vnhO89xsaUVo
	KePK/QS9MB/m8pPTw/H1oB2Us3OCleO3LjY/JhdMZif9dU8MsckFuPAp
X-Google-Smtp-Source: AGHT+IGl2h55mDW8t+asvtlcM7vh6/mx9Rukq3JNOLxlrd7TpvAnq6gflI/UM5iP41JfurXCH5A0+w==
X-Received: by 2002:a05:6e02:228a:b0:408:1ec5:ddd7 with SMTP id e9e14a558f8ab-4081ec5dee5mr168465365ab.20.1757535823482;
        Wed, 10 Sep 2025 13:23:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeO1EK2J6aSSahwJIFntLwxDDrl49zrvWNybOr1QjFOVQ==
Received: by 2002:a05:6e02:4604:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-41cd5ab6765ls293325ab.2.-pod-prod-06-us; Wed, 10 Sep 2025
 13:23:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXTGIhbBCo7CA2VLo52ID6Fxb+R+N8QEodiEbNbF825ZTSiByrMmcP4+zuTcMHVyHX7/sz4zgZT0J4=@googlegroups.com
X-Received: by 2002:a05:6e02:178c:b0:40f:3015:239f with SMTP id e9e14a558f8ab-40f301523a9mr122311155ab.6.1757535822481;
        Wed, 10 Sep 2025 13:23:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535822; cv=pass;
        d=google.com; s=arc-20240605;
        b=dLy0EHuwTxTPULz6OdSaZxRuJKpoHBm8LpBT1vMwJzenUffSTzLOFQJciHJkvrADuT
         oE4C80UplCgSzIn4hMisruvJLL1dOZB5Kw5qSXQqzjbEC5ym5LgSamfDiuSEzrHAelTc
         zjo35SBdr8BgRINQUcZcGRb0Wm9fvfHpDAEUaiAcrcHqTGH8sEQBkcNcPf2xUSFo1Mhc
         GXOHb8GIkK3eZZYKsI+VShgeaycKeR/43s98admSn4jqE0b1TWsFNfkNOHAvMoNnJ2EN
         85uYnolMjJJlH5ZccM/PCTJmoHLmsZIE9zhYL8KHdP9CQZYYd85JwqBiI1n65p2LFFTl
         R7lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=OuBj8M9Fa+IBLDa0PJiJfcoR2DELHVDDJqpa6D9XAig=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=R2U9dE+WzKSiVT6gT6lr5RgGoV3W6pyKEguAcc0cltIHh41zo1jsN4U/Paw+IC1ppH
         +Uh6qX/pz+N7zsDIqFzGm6xt3m39x2zhnTYGza71YZ3bQr25uKRbxgrZPVTsWzWdqW/9
         3vF5LBmXBpGz1VcsSdmo1CGAN3aoyboIy0v+zkajbYpLdgPmEuX9Vzhz8gkNlmPEfCaN
         CcbIhQxVEfhU2HF62SZCe/yubB3UHe38hKM4kJ6YX+KgwTp90uteHWl6j1hdMCWtwvTB
         tM4/bESsg+8UCGANzBcDk14Wq51Jf30zAjgFOvhHX5FM/jlYrdu3WPmhSn+8iCjh0kuO
         9+PQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Crjq4f7B;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CYP6rE3h;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-41c7eb3b67dsi127045ab.0.2025.09.10.13.23.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:23:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfpW1009838;
	Wed, 10 Sep 2025 20:23:33 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgvy4w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:33 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJfi4U002816;
	Wed, 10 Sep 2025 20:23:32 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010005.outbound.protection.outlook.com [52.101.56.5])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdj1cg6-5
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZonWXkTZ3VrlOZLPav0a7WmKfMKG7vVaeiSW5TVYyhoEP3+roFFJqu+O/2j/mfyrXFAEBggPNKS5piPQpPses69UYAL8gypU+V7vwabTTEujwHyAqv0L6BRmPG5ofK6ghGI9z7vYOfEEao1Jq2S3KMvZH/gJlwDrW20CNVEqXAoHr1wdeC6sRs7UAoJaigm+lIVGwJOo1PY1KgrEtP7roSgCOr2t69Uydhp6tMAyt7NRyCC5KNo/63NKcgb44nRemLEMUvaTihoE4frd8f/L6gVtsWa4ZAOyHQx7/+9Hp2mLf+YU6e2AfUsmrDF/VRayopJZBfCEC2laS2h/Xu+dPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OuBj8M9Fa+IBLDa0PJiJfcoR2DELHVDDJqpa6D9XAig=;
 b=ctQtJV+sUqjDQ9wGQ7HJn+b9nrj1UA7LeLLWt9zJX3EAaO63JTqUWVoE6BfLC2yzuK6mzL7FNaZG7lGUEvOCmltkNb+2j2AKiOA265b/R/4y2JlkHqD586ng8W7X5lv38BdNb15nZ1+KKHthm3XRSqf9HcuKYwU8tfUcLXZ2NjbmCkaZSOZh4wWyKBFEMxzQ5WNaDHOBSQD/Pf4CWnV6W+iHx7TeOPrpXYk4v1csDrNzJBeJ3R0enyICY/qD5tn+WB3b3X4udFX7dclg3br+WCMCtecKrEEjNS9+/0VgZktENBQJm0SnCgfN+GbTmScyp97eXXYjXP4lYPMuQKvr6Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:23:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:23:13 +0000
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre <reinette.chatre@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Date: Wed, 10 Sep 2025 21:22:11 +0100
Message-ID: <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVZP280CA0052.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:271::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: bece5537-e9f8-455a-c22c-08ddf0a7de5d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/bbcUiuSdSQ8uP8/kwt04z7ErqJnR85izqT683dT/FFwAUnnzp6C9FinVVHU?=
 =?us-ascii?Q?hzJpC3h5f8MBwXbTXISrsXnoM5CrXPx4cwzd56g0vRtMxBuMzMX21ojC0RzF?=
 =?us-ascii?Q?aciMdVNCvT39ITZcn4Tqr7CAVPobgL6uLFdhz59DYNfDWQlPcWx/JJE+2jpJ?=
 =?us-ascii?Q?BrWioOTaWwqcxSS7hv8InSiW13n9inGIs0fWBVYC0qjxQ1X7KUtdga074ktw?=
 =?us-ascii?Q?HpC6VKH+evXytDWiNRIy/BfZso+YHzIGb180nBld84C05JAzLnVsBVkbFQmK?=
 =?us-ascii?Q?9ymrSYwfN4boMA53nmZnGZfpfW2ATbuiFA4V0I/hEaGEx7RfABBu1fG+BcBL?=
 =?us-ascii?Q?NHJ9CNM4yBqlzQxMQcu4QqmqtRAzmUjkocPnFyiMaywv3YbHv0+P1FTa+xOc?=
 =?us-ascii?Q?YcJFB1ELLB+f+EeEJ0WL2SnKF7E93H5T5Q29xIbj4jmAcdSi/+Lg5znpJp96?=
 =?us-ascii?Q?mkzGO6/9ZALBRhF8AUTFjazx/JrJolgz/o2N/vnNjrxfKX/XHJuvLoJ2CYNe?=
 =?us-ascii?Q?TUHxtBSq+FlE23l0j50K5q6ugwIiOeGvUaYzYqNmLSDm5hlc/U1GTFsN2ooJ?=
 =?us-ascii?Q?ajOD5pQOxmbs3SgY238aD/rL0f42BpTH1B1a6oOzTs6QZQrW9c4TRf9EprkG?=
 =?us-ascii?Q?6fAYWmvp/gcD7oFaxNLu2q5iAYWRiKnLO7DaIBNlFcvBSDZ6hgp+inc5LXBf?=
 =?us-ascii?Q?2wmqiCrYuEedPcb7pfB46LyM5ry7l10MF6Os99M7Otq1cS/3To9DzD+kAMmL?=
 =?us-ascii?Q?euWpRPYtz8/AWAJjdgvZ42/oKjJw+3zCfP5CuQJ3jPfxqOlDw0akyDX2FQoc?=
 =?us-ascii?Q?ucg+5qBuYYWXtVCouxASYMyv4+jlo+ypDtjEZnCcLei6UmKB1PFOKfBJaH3S?=
 =?us-ascii?Q?1kU50Dh1Wb7IWR49yFbtwKnk4DWS0GVLwgvQlKPN7OfeGBhzo0rXEGWlCYb7?=
 =?us-ascii?Q?SSSHkXVPN7kjvmvkmARjuVZqog9XgrnN1v8H/Ib0uxs4mptbuKD5+UlqRfjS?=
 =?us-ascii?Q?xel/g/thM+FbWVUmEWS0/4JPHRu5EqOIbCfwBR1NjMKCtHnFL9zdlLkBIWWg?=
 =?us-ascii?Q?ltpm7JudviYHADhG5iODS7S/CXAFfsuG83Kdh9uLxMHTrh8eExZnwzREKy4T?=
 =?us-ascii?Q?08epDV17xU7vrupEse/PVsDUuePsKDX4NW3TNJ5UX17yXq2CAFFSL/2wKTnW?=
 =?us-ascii?Q?xWaL5Y8SoXbEEWRK3VmBtTzbvCEqye+NXjZH3HP0aAfsO0FgURj4mQsWhCGs?=
 =?us-ascii?Q?TAFFGLg+LLNUG0i/EdTO7kaiievBWEpY+cbfs5GOAUjkLsC3Sprq5IzOB8iA?=
 =?us-ascii?Q?4M/AOUukdRbZiFgjth/rtvT8Qy52KErHqIeX02bA6/oIL3YscHbr7G4/Odao?=
 =?us-ascii?Q?qwgFjuUUCrdidlHxPk9lon9PCtcqm/Mcu8Hs3O8/FQ3ceaKmN0T38doGt2Yk?=
 =?us-ascii?Q?CSVhyjkg/dM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BYDNSXKidrZzZGgXL/yT709cMSdHZ31fPXWmzuQxzYvo79NQwMhUX5s3fVMK?=
 =?us-ascii?Q?tayIoRsSsm7+5jGQacxzCPYwdkh7eAAKqtMtsxfCbVX9X2DpLtiLuWw7vi/c?=
 =?us-ascii?Q?D3hX1y6qR7FSCpzdh2k0zX66nkXYf9Fxzfd1J8ERv7i+52yb2kLUeeZGlPWY?=
 =?us-ascii?Q?BrQtZE091BrOM4/aThkAz2yrvkSPJJY+eYOxhxbLZuDQLi6/JKn4qZ8KqsOI?=
 =?us-ascii?Q?giOV/Sit6rs/afJAGrxKP54Vvl83Ulie1EijwCFStmTuZCyvDrfwGValS6aU?=
 =?us-ascii?Q?TpcF4F5Y1MbjzRzTG4QCKb6RzOqGXRRCRUs+zDBdcfRENgUjwQePsXOmxDNU?=
 =?us-ascii?Q?CZXd183if7OWf6fReQ9Si8T64r5JpT7zO/DDNWMXEyN3KOrFD4V71bn/8A9U?=
 =?us-ascii?Q?sPL+OgKMyrl5l8q3Gf6KgTW/PTPmfBPFGSPOyrlNTbBMoPwgK0qjvKHAiLAC?=
 =?us-ascii?Q?CL0R7OYRQpXA9j55BkXA04ZuV6I6AdJXx+SLWu2GwYoTjt8jyYHYsJgO8gGD?=
 =?us-ascii?Q?Z5/NKTMW8i0IiD810Emdp0S8mnatYVX/g4sOLMzSpg3NtDZbN2RGUwB2AVyg?=
 =?us-ascii?Q?7hpZNCOEAr8NXijTLgzi0qiRxJq1s3Oo4/eIQC868Nnfi3mkafCVN9TvFEQl?=
 =?us-ascii?Q?8UvkmCYhC7I0b3HD8fz1MvO/JfLUAO+Khm/LMSiydcGFFA5MQRlV9/BHn2At?=
 =?us-ascii?Q?ZxgL8oWHtkxco/py3xhKRkWqH2C5cENDL4j342vdXc/bSdTRhOzhBPjjwtVH?=
 =?us-ascii?Q?w1Mmbb5JStHnFuiNSAhXm/NgqznZatwjiZBTimqwV8PuSXwIuy+vxZlCrnaP?=
 =?us-ascii?Q?mdbWEhcyglfbBxrPMGG4DcQC89M1XUQdOqVML7nokEwxNPrsi1uzpZ03EqCU?=
 =?us-ascii?Q?W6zyFim0QpROFYN+Abcz0ueGUIr/cOOzcRVWgCYHpmLsHn5gEG8J+BMCteCU?=
 =?us-ascii?Q?SlpKw8DytUiTHLbr9spZnY7sZiFqRglO/l9Lp9dh//S+MwSRoVOt20NkBBxl?=
 =?us-ascii?Q?dPaRUCLEPjUbf5CyQdONxHaJ8kAzRZd51qoCZ1G15AR5zqQ5mWXiGZpneCrZ?=
 =?us-ascii?Q?GfZzMguBDv6vabQQymAW5crdF69m+kJSG/kQ6AZOPR1xS5b7lk+zpco8OriX?=
 =?us-ascii?Q?/vkL+vlRkkYRcwwm3kvl+DQgX+EkTHRY6xXCcAxbrKwQ+UoOVdw6huRoI8aX?=
 =?us-ascii?Q?8qvHSKIJ3OQFrfM631jR+pRb5Nhl9UFvRd9UJYtdAwpXgUYuk7EtKWEpWqaF?=
 =?us-ascii?Q?vfRcuHra1ZSitPzVwIRPfXc8dpb0hroyC2kggFRjA7ZzhFkLzLYqsI/BZOUd?=
 =?us-ascii?Q?MwQRT7+F9JlG3kqQG5XqdSbGaYeEGqF1pv2cE+VMFnBkZ93bo8iQ9M+z/naI?=
 =?us-ascii?Q?Malmr3ep0iJK27TfNHTT59pjM8oulTaRfsVW/5oAdRLVTkXQhwa+82YvgADH?=
 =?us-ascii?Q?XrzQYla/6HjSKERohWJkG5UrCCnlN4VAdH62ffw/g4VxQKF+CVfgJrKVF+K3?=
 =?us-ascii?Q?O/vUkEsTnxdhSkNpW4c67/ELNABzVRXdvOUZjyTpIWnSKnyz0NYwHozRkFVJ?=
 =?us-ascii?Q?zrA2PrKRa3uZTsJSzCmEEor3AoWDWyl2mVGG/T6jeHxxQfdn3SfQ9QB5vZjv?=
 =?us-ascii?Q?UQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6h/3YwwIG+fCWtEdJHhBXqEo4zXSXm79+xOVJ+QF+A2XfzRXFtXIE+IQrRifjHmDNESlg9SnShGeDuL2WhDFybkX2MwwtdyJIZecgxlfZ0AXCm5f6MjTD2bPmnO++JS4NR8XyZoht7dwCTYrxhDoBszTZ3sDplYmYTVktxPQ5RJPQW9fw8eg78X2QsjFtfNcDRwEhiZ5w0pcdAfOJLddasikvKEI5o3hVhez2n9U30bHx6J3KxbPk5fkuCcP10UYl7lNZvUVP9gALRx7nQ3yMS47EeOyvDfUS4VoaRDbMjizLxYOWjKbTB+UmU+/7plDFBVZzMZc8JjBHjckl+MdXbIVsowaQKocYdjDuNECzFH66qIznWIhpiLB0UHSc8Koh0gKhkVvSQaZaWIGY1RNBXxe3+LLZPd1qX1qXjL2IsIUQNPB80e3cWwTQZygN+svUxMgr1V17Nw5lyQIcUW6AkyvtzKxx9xE1CdFYc9P7DCwPZ5qANuXELMCsQqFrdGekSok168huHukelZysiQhAksALrJscnI84Ybsw7k7DI5/idfMaS6JQCf/VSYQSfF/xWXHFMHaS5AFQ0sC9+MV5+z9Zkn9N4SMHUmOvCUHvo4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bece5537-e9f8-455a-c22c-08ddf0a7de5d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:23:13.9396
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8sHBeGcrz06BAaqxWHn44XoRNewcqOP0cLpKG7zeFhw071msETi1VB0HkcdAu3GMJ/q3Atjo8i7+plOmJ+LqCvhRq7F7MvxYGmcb0l8PKps=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100190
X-Proofpoint-ORIG-GUID: TRQUnQ-xRkryZD128SitOB895Mo1JVom
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68c1de45 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=obMSAg19tZQ7Rrc9VVEA:9 cc=ntf
 awl=host:12084
X-Proofpoint-GUID: TRQUnQ-xRkryZD128SitOB895Mo1JVom
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfXyjNRfq12RVpJ
 sNwiotSkCUvTO3Wx61x3HhmNMlz3O/v1/bd6QGdjOJsWbCz+Chb6+j9+kDfEwfb1a7zf025SsnL
 qIg02cmN/bxic8dR4xZgslgUYKZcmfnfD29F/qnC+PYcygYmTep4/NCxEAk4gmwm38KqQ7chk15
 eZUNwmATR+AOWn2oIlfz0HMC5jbv4u9iE/VlymHGm1oMlpUDn4vLkWw7dWDZNUotoCSQsa0yJt0
 mglwU7fZ0/q3P+qZ2UelNoHcASVOzn9S1cd5SUzANi4oucMKyJZwQ6AdJVHY9Er/yxMxUL3NbOn
 Q6+d1nv6THIUcn3y4E4wUoAUQDGwKnqRApA1ta61F6NSaJb0tHIazeKI/og0fE0L53EahAF/Iig
 d95kgG7mDOzN1y8gaZskadGBYLeU7A==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Crjq4f7B;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=CYP6rE3h;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

We can use the mmap insert pages functionality provided for use in
mmap_prepare to insert the kcov pages as required.

This does necessitate an allocation, but since it's in the mmap path this
doesn't seem egregious. The allocation/freeing of the pages array is
handled automatically by vma_desc_set_mixedmap_pages() and the mapping
logic.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 kernel/kcov.c | 42 ++++++++++++++++++++++++++----------------
 1 file changed, 26 insertions(+), 16 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 1d85597057e1..2bcf403e5f6f 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -484,31 +484,41 @@ void kcov_task_exit(struct task_struct *t)
 	kcov_put(kcov);
 }
 
-static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
+static int kcov_mmap_error(int err)
+{
+	pr_warn_once("kcov: vm_insert_page() failed\n");
+	return err;
+}
+
+static int kcov_mmap_prepare(struct vm_area_desc *desc)
 {
 	int res = 0;
-	struct kcov *kcov = vma->vm_file->private_data;
-	unsigned long size, off;
-	struct page *page;
+	struct kcov *kcov = desc->file->private_data;
+	unsigned long size, nr_pages, i;
+	struct page **pages;
 	unsigned long flags;
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
-	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
-	    vma->vm_end - vma->vm_start != size) {
+	if (kcov->area == NULL || desc->pgoff != 0 ||
+	    vma_desc_size(desc) != size) {
 		res = -EINVAL;
 		goto exit;
 	}
 	spin_unlock_irqrestore(&kcov->lock, flags);
-	vm_flags_set(vma, VM_DONTEXPAND);
-	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
-		res = vm_insert_page(vma, vma->vm_start + off, page);
-		if (res) {
-			pr_warn_once("kcov: vm_insert_page() failed\n");
-			return res;
-		}
-	}
+
+	desc->vm_flags |= VM_DONTEXPAND;
+	nr_pages = size >> PAGE_SHIFT;
+
+	pages = mmap_action_mixedmap_pages(&desc->action, desc->start,
+					   nr_pages);
+	if (!pages)
+		return -ENOMEM;
+
+	for (i = 0; i < nr_pages; i++)
+		pages[i] = vmalloc_to_page(kcov->area + i * PAGE_SIZE);
+	desc->action.error_hook = kcov_mmap_error;
+
 	return 0;
 exit:
 	spin_unlock_irqrestore(&kcov->lock, flags);
@@ -761,7 +771,7 @@ static const struct file_operations kcov_fops = {
 	.open		= kcov_open,
 	.unlocked_ioctl	= kcov_ioctl,
 	.compat_ioctl	= kcov_ioctl,
-	.mmap		= kcov_mmap,
+	.mmap_prepare	= kcov_mmap_prepare,
 	.release        = kcov_close,
 };
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes%40oracle.com.
