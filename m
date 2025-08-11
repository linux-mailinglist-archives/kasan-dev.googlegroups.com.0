Return-Path: <kasan-dev+bncBD6LBUWO5UMBBRPH43CAMGQEKQD6MMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 53903B202CC
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 11:11:50 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-31ea6231678sf4530127a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 02:11:50 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754903494; cv=pass;
        d=google.com; s=arc-20240605;
        b=TwpQBxpTXcYCp+1XHdm1rGlw84DLGhnLYi0DfNhTrLjqC+DCdo6R8FGclFRWuL3M6i
         U7r3k2ZOoTD4r3Q6r69SVhzAUuHb4SPyfx+AaTeIQoaamytIBgVLBlSzCYJNM3sbNKph
         KdEHFI5C8V1HZwUO+BKQtQXyLh4sTFStwSJL8PYQD0VneC1nAe/sPXGCM3i8YoLGHNpd
         d6iN1anDFMGGcyUq9lo76jIxr+QshW5/ykT6eBeyPA2UPzSjB/dOjCoxtIv+Yl/6HNMI
         a1XgSu7q178fuu8bxNxHUVW5TiKrNHlM5N9MofjKejfUSEkRRv5qfKZcHwbGx02MPtH9
         zj9Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=V7hi1nOI4UTAlym8x+OsmoxGpuXaA8Cw7Ho8GNZy3V4=;
        fh=YgQ+SLOQ/6dII33MiPALnHpaMCo/0AO02kWLGwHLqIA=;
        b=KbHCMxyPFToO+ircYI1h/2Hh63drqtAEQeWsWwBcqR2VcpDL633S+lnsMM46h1bwVb
         IMMWzM+6tDhlHoKtcXRYqZfMJEw95XZHTfjKk+7NhSlGlHZRjbo++QoL892rLSh4HAaP
         ohUvTOhKUslsc+PIrwIlIqkiOlkxM+1rm8b94+GTpLKcerh3ltzE3dRCYv27UTcVcKDt
         RqcEzhkMGjGceBEVT4HR4kcGC9essniH8Bhb5yCwu6WK5flejQDDvW0mmcRS/qvcCQsD
         LP4FvmCCh966XESop1LSlry5KzMm5B7HSYs67zqaIxth39rO6RnzPPj5Fa4OffhUWQyS
         46yA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rMBjP9L8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="QKBOa/Nj";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754903494; x=1755508294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=V7hi1nOI4UTAlym8x+OsmoxGpuXaA8Cw7Ho8GNZy3V4=;
        b=u41fBNZd7g0rkIbUwDx4lITW8mi94W8Enw/11Vqr+uVqiaKfy1pgDa+xhB0hzrqZVN
         3sDWp+l8f9QOuP56qZwC2jYoEPejaKF2cfXdoEK/Wf0LVJ18fnC6cCY0z32wwwGPT2lm
         OwRjCVi4520h1xzDA36jXfOjKAFGTFyNNX+giWzXH52k9Ci78K7zrQ4AP/gQGN1B7tNN
         33PH+iKX3qR+YlvXHHZqDVEJeuFzRAnXDVBvbTCRe1RTcC5w8oOUbjREkXm7FkQVVQ46
         qEqDCPjVY+P9XG1FkuhsRVaQ8kRip3dy3sKU6HLnp+SLOa6KOWZlMWeguM23/6JNFl7d
         JuMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754903494; x=1755508294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=V7hi1nOI4UTAlym8x+OsmoxGpuXaA8Cw7Ho8GNZy3V4=;
        b=IRc5ZTIibfCdznMtkbUzRnjjHKsptEqLAev+dSP7JQsTw1AyLnTaThQFWmyXUK4pfW
         PkY+mE24bz1TC19sc7z+mLKp/ax07vlaDGkHPO7855qC4x2pfAHjb5z0m+hrAvKV1Tfn
         Cgm7RM+zRXSA8CpC2nczTwC5dkff5wJH5ymx5Fv7tM1IpdxUneO6b9XerkxsTgIPWnQf
         TE0jclu3BVVLcdRSpkBBxMwEThcS5MoRnw4qGefA+Yd7LZtpx/0bF4ppRNXbL6511Q86
         IggRUn07TzeH894qNhbBK6S6YSCAcf61j/wpXWpIDA9J3osWIpW06SwJJzOySQY6jgGA
         qPvQ==
X-Forwarded-Encrypted: i=3; AJvYcCV1zi+tlqVdQS5Gt1OHPBSmQbYG7cbUF3n6hSJX3/nypT/r3ZynZ8a/qfme4bZxCXnie76Aag==@lfdr.de
X-Gm-Message-State: AOJu0YwjgWlxTz1NQ6ZVsYbCkVsH7plPQ51/84W/eAR3QSrHNZzZMulz
	t8I5E5CcDwsMesprwDcWbYAR1m7IvXVQ+jP9NjgfEjxIDwW4Xbdr28Vg
X-Google-Smtp-Source: AGHT+IHctqAO+nfOEgGwnVxiIVhEJ/ZAY1yAozhIHa2IHfVQiA0FE8WxEMjwXE8XTE+C1T7Q19nZKg==
X-Received: by 2002:a17:902:d505:b0:234:9fe1:8fc6 with SMTP id d9443c01a7336-242b072bbb4mr246397745ad.18.1754903493725;
        Mon, 11 Aug 2025 02:11:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwu8CO5nzBlqCDFMhtFjH62iTrYm5p4++Mg/tGeQ8YWA==
Received: by 2002:a17:903:3c6f:b0:240:3cf2:c3d9 with SMTP id
 d9443c01a7336-242afcb962cls23233135ad.1.-pod-prod-00-us; Mon, 11 Aug 2025
 02:11:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUfhGwyWC7FjRNclUub8QB4ik6QgjpmIJN20Am9sv3HV0UWu9Tq4X0MjOBklnTpjZkxklgBU27GcrE=@googlegroups.com
X-Received: by 2002:a17:902:e74e:b0:23e:3911:433e with SMTP id d9443c01a7336-242c29cd6a5mr181162615ad.5.1754903492364;
        Mon, 11 Aug 2025 02:11:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754903492; cv=pass;
        d=google.com; s=arc-20240605;
        b=h13TvAmukOdM7LfNBJuKYEk7RPBSGPt7luKwH0ANDo7OM8da6AQ7BlH2cbHR7+e1Oz
         yD/22/fsvuA9Cw9sdRBQl09UL6NbQaXKbkclOSLcxD+FspmzG7Qudz1jHP84EgT8gpVh
         nmCLfNBhFUvFscwHdbFhSWvFocIY/HK24lZomqwyyZ6pE3Q1e8mfcUD3dzRfHDvVerYN
         ubRguX5ryccnqeN9q7WaiUYIEfgl8aX0X4WpNuAdovaeImPc4jV99J2udUChBNKKg20B
         DLJHSfLVfs3PlRvF3j1VjWhGUtXNhvgiSqgxPxK2hEoQtdCH/D5BCpM3xIMSTLLahtW4
         X38g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=GazEp2Unr/pH4TG/HiBdoLnCaVnKBWnQUTOARKFYIBY=;
        fh=PLQgFxTRLyhcg3N9pmSi1Fg/j2fHtLGfM3ZloGi4B4Q=;
        b=aCUduZrdF8N5dGVA1B87dy8rsZPohZLVubZDGk2mLUBjetlk5+VpHW9m836y8BhZ8S
         zh8hJSOftW9jG4oIaYioYPccc0i16ztk0NxDxzEqSfiyUI07os35HrrMJUE7ijtriRz7
         KmqgLJb78qxBN/J+k1qziJ7TMbPlUD92bEwBBgfBcFQGqwcQ2K5/jceXfdn0b4O6Dpp4
         Mi4atioGBq91z9kvgywFCldjuAfxTP8iWyKFXVg0ilAfYYMAA9sFx1o8Lm3e1Xuf9Cuz
         Uet7K1HjBUInoC4ZZ7LrdIFX7ocRprT1QwVCghN0kWQs5w/zRmNvAosh9L0FkUklVHB3
         Hwjw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rMBjP9L8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="QKBOa/Nj";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cec02f6csi4222295ad.2.2025.08.11.02.11.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Aug 2025 02:11:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B5uA7v015015;
	Mon, 11 Aug 2025 09:11:14 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw44t3hy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 09:11:14 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B8d17F006475;
	Mon, 11 Aug 2025 09:11:13 GMT
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11on2043.outbound.protection.outlook.com [40.107.220.43])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs85g2u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 09:11:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gaKIPG7EG89KL6J+gf5ldJhzsjWuGdxaIrfq0vTWBf0sgZVUFdN0brUb5Vl6vSV1vXQ9P+5+ygWAIzAGXXkhTuVlrcZc+UiFb49vmyQk6fuVQ9xmxI8THVFppYIVLFLDsicw4KjLVwYaj0TvGhA02yYtu4YMLFYmlxpvbwXhh3t7DbdIIMInU4q961bnt2f6tah8g9zAIe7DanEvGEDO89XmcmM5vfEC1FSSA+gKfXJRiPFEJIT082r6MuT8YqcbayOrpNxsCEfRkYDnkr+GD8YUqxsTudHa1jXGSpx2CXlwXu4kOetYarNOCN5LchkwD3yoL9xj8NPZmcj4lMK6TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GazEp2Unr/pH4TG/HiBdoLnCaVnKBWnQUTOARKFYIBY=;
 b=rpfL+6V0HgyRj66Or51H906ms9XvF3FN19f9ZrMZN+gruZN8EWrRtzJdZ7tOSDiBQGYz7BIBJjLxvfh8tO0+WTqiHzDdADR9CxaGYAYyqgQcHw4JKmpq0GkiVFrF/SWCpE2DrEc1n5S6Z0EewNK6rTZ2MXHOOCX+YMEUiczyUxwywmGH6uSsBuTi46OIFZwuY9HmoCqx16p16FYQjvjDP1CC708Fzw8fjFSVuF7TUDmxpNUyMmp6v2EgmbU/kTeeziouNloNFmlDe17qrqlXbZYVdLp09ATvvpw8pGjdvJzfoUy57VZzesTxCnMtPWzY8VXT+YOTB+oUpZsXruB1oA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM6PR10MB4281.namprd10.prod.outlook.com (2603:10b6:5:216::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.18; Mon, 11 Aug
 2025 09:11:10 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 09:11:10 +0000
Date: Mon, 11 Aug 2025 10:10:58 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>, Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <1e8ca159-bf4a-47ab-b965-c7e30ad51b28@lucifer.local>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-3-harry.yoo@oracle.com>
X-ClientProxiedBy: MM0P280CA0043.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:190:b::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM6PR10MB4281:EE_
X-MS-Office365-Filtering-Correlation-Id: 3ac84b8f-45b0-4999-4e85-08ddd8b70317
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Cgv7Fh3/Cth5fiAUOPYCZtp/WnJ+dtFd0GVMP8cjp8qCi02MSq62OEWpiXnc?=
 =?us-ascii?Q?tVh8BOckqT7I81b0lIjI/DhWxV6jMrY5BdSeHXjbzvuDOkDB+3hkuj3wKmHg?=
 =?us-ascii?Q?iX/aQZrnNRAKMxyjzqsr+MKJUZNruZpt7DQICYhgJr0z0fZ3HHPNvHHlJltK?=
 =?us-ascii?Q?84fx15HxJxbe9XnLp5chREHciJ0zRj1lbH46JBe0afjnth2idjptRibVnxe3?=
 =?us-ascii?Q?8M018bW7HvwaAQTmNiboHO6OAXVBCG2rwMy0nFS7bj+p3lZs8yxSGlMULnRi?=
 =?us-ascii?Q?PQFCn/N04rSk4mbSmXfXZI7pdf6epLkPwF+gEy8WGA+vN1vcXuXKBOySI6gT?=
 =?us-ascii?Q?+AnZaj9yTDAeURZIztnKwhD2jP6EXDrdkU8V8GdhJAVd/DgczW1yLw+ODjiH?=
 =?us-ascii?Q?CevLEuiBX09lcqNgnuTy0D+2aSbiLo885oVmjB9AcFhJScjVocOa1E4ddxo+?=
 =?us-ascii?Q?T/8mVKOdIQHVnqwi+93fJXYBJvWk8KoBrGtnswkeHDryCJC3Q3nxx+Txf3Rv?=
 =?us-ascii?Q?fLe5VTtQaqyGcuisaym4uG4qabzJMChMk2ASrcD7XEBtnVrXYByfHPLUxINh?=
 =?us-ascii?Q?yJkzaLzaB67tye76GdAynzKtRATDIxGlNVw0gh19/YGpMGl3k7Wq+mZTjpq9?=
 =?us-ascii?Q?pyAMKdPRG8gtt8KVRGX268n0ckR+3HQnD9C2QnegrXysHSJ/mpV18hwhUPb6?=
 =?us-ascii?Q?mTHqVOVzl8ndglRYpBCMg8ATzk2+qYjFXeDV3IbNMhE0iOOrQVnm2evpBt1i?=
 =?us-ascii?Q?y9MRx6SlCnEDR7lQ/g9n8rQ2zc2sJ4sYkareCNT930f9nmaObXHlUs/37UK0?=
 =?us-ascii?Q?rrwBdv3dOt9yKaFYdJCjLBAkMgQqOLSfLfaRXVUz+hNAHBJx4TlJXMQAlpzt?=
 =?us-ascii?Q?Eu58mgcaZ0AcMEkwi2xkpTQgpq6cDumhbEmnij2OItszcuADd2yKFSESQrf2?=
 =?us-ascii?Q?b50vgwd9ESjv5UQIF6aVnxfPDwKdIZ5o+aX40tcjpAUQL6P98602ua1dhoGO?=
 =?us-ascii?Q?bjoWYeUO8ylpRlX/IGVIZn5kIoiS8skChS8RPf7kG4OORFrAOY2GjbzTF7wV?=
 =?us-ascii?Q?s+w2snxwxWZ1xZjG21XP+bgGw2Kx12j9XJj9G7BmdXrsfrlpXDqcUM2UG19x?=
 =?us-ascii?Q?wIx2LDz8BOXkZ7JKxEMypLTqsSElX1BFDUKh4QYKFCCSjGXffzGV9pXPrAL5?=
 =?us-ascii?Q?PCwrfUY54mLZ3yBtcBkrx1Mzn06g2WcPg2WZGKNcyPrtI/qzQbBfq75aPROi?=
 =?us-ascii?Q?/EN9tqTTI9qwuKQ4uLrBiYNgjCk99HxASWDE/5t1oVfphH8Tg6yLqjnYF/zL?=
 =?us-ascii?Q?iKOSvOtkOwUdM1bJpF/zRQebhglLtGuEwo6JZLSAfgCk3gGNBk4rpcG5losv?=
 =?us-ascii?Q?K0I45ZoY/PcVZNT6jv3EIEjhBUGjy68Er9sZb2QIw/UL/FltQzwuvAAGvfQk?=
 =?us-ascii?Q?yZWfI1aLXKc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?YcQuPGzpZVaZdRM8TcnX2/yNTxO74sGMnHShF4M5O6E62sjO/slnw8XuZ28l?=
 =?us-ascii?Q?liTz29W7wzrtVj7g6Qdbl7d7Ja8t6Dz50CqyegnJA2g8LdTHGpLIv+xP6Q9J?=
 =?us-ascii?Q?6wnz8qNpG31Ngu2HqXgJleiDmuieIzzRsi5vJWZpBB6qt1oHJWONUpSoIUEk?=
 =?us-ascii?Q?fRIz55YPqQsq8JbYCj9zKheyOF9g4Oxq+MyhbIsRBVinNHFDY8ADL3wEiNnG?=
 =?us-ascii?Q?zQn62N1TY+Ra1DvCGNE+iJMjEd7MekxdaF2zxCFbWNrefOALPc1VfmAF8ElZ?=
 =?us-ascii?Q?7a4ORYclnPjmN6ovmVNUkptGyxROFW0atXF4EJaE4TqEFldlgwUrPsXE1xE9?=
 =?us-ascii?Q?lH9zW9m57DrVBgWeeH4FZ05j0sXJ0gKK+C2mvR9IcodUKaFfdXyDBhrP0ji5?=
 =?us-ascii?Q?zhyzUCokGuXCaP7Wwj7RWObBLa2GEIzVl1JI7+Cf5sseEWQtbJPPwoSECBcJ?=
 =?us-ascii?Q?qBiwci1D5k5KDuuvHSF1caOdEQ2IrCJi1xgUO/i8kPp42U5UjCjJ0yML49iF?=
 =?us-ascii?Q?BxWB4wmBEQFZNRz3kCm33ya5DHRQxvhK2FQxm4rYipDo/MWyo4zqzri4NrTf?=
 =?us-ascii?Q?MIXzb9bn/UyI2qmrZImYqnqu7Nf/8YjvaSz8cP3Y09g4GIAixTPTGUiPxKj1?=
 =?us-ascii?Q?jawgz8rWT/42VS9pb/D7Crc7yMckGlJ+/JpZXg3cSNJhs1042nPFFI5hVbsO?=
 =?us-ascii?Q?xN3lKAb9AGT+LS43u7SpKAijCd+IzYTkuOpvWRRADyMoF9mzAzf1invyA3Ht?=
 =?us-ascii?Q?Qmcn4HALm/HYe8U/xKPi2SjfBn2+M+lxMpXhYe0qXe0aeFrQyE6fhHBk2fYc?=
 =?us-ascii?Q?UPwRjQFpWK24plzcBQEQ+oUWDwXdO6YPW3BT2lmqKjZeXK2bqrzVSeumZVYC?=
 =?us-ascii?Q?GQaZ6zA6ifg9ANhlhDeDb4T5nMe1lBQSCacZbQ5pInol538jHKQypMjcY8G1?=
 =?us-ascii?Q?jZGC/SnSy37IMoIjCXxNiyy25WXjcy3wcWyHdMQam2/iQv2FtsVy5I4Fa0x9?=
 =?us-ascii?Q?CgxUeKA7vpaD9iZqnuKEwBdmMkEcFKn4RwFuJHaFJpmXO+taGBzHBjdp7Zmt?=
 =?us-ascii?Q?eZZ45JVZIFV/nTdq5tb03uWZALZmlhtTg+LLw7nkuBuuX6b7mWGUN2Q0mhj5?=
 =?us-ascii?Q?3u7I533VGEj3NIXh+PZl4ALJTx7gGrqO8x+mYaIY2gD5Bu161AQIV+YaiXN7?=
 =?us-ascii?Q?CsQ3VtLevVxfgIpX0GobkQA30ZUw2KI7BT8X61Qb6ZaO8AIX9gF4a2k439/z?=
 =?us-ascii?Q?EgM3RRmQmdigiHgBr5YpAFzJxcM4B0SYFQe5K7mt9Y3M23i96bTudqay5gRh?=
 =?us-ascii?Q?nvG1uEl7/LxEL9/nMefmkzQbbJKGelTprloW4Qv6QfKN/DPniNlTR61+VXVC?=
 =?us-ascii?Q?MjmPSMiTwinhdtCTlROeYcemdo9YVBvoJICCDGIFqyhilV5epsdXGbFaZe85?=
 =?us-ascii?Q?zZxa05/JxXghQ3OL1BH8vQe+iM4FHn8G8iLbLJou7losQ50MBV9xolEPAGV8?=
 =?us-ascii?Q?jM8pm/URa26FDBLr6EzhLeUgyBrw3WqNhumrm8P/Ew+6I65ei4daKVwKKoMu?=
 =?us-ascii?Q?BaDFMeGrdIun3bPOgVN9IIMBOynkz8A/zksNrh6u4s09OZRXALwaOoIIzN5y?=
 =?us-ascii?Q?aQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: jq/ZgIvxY6LmVaWZmnh/7bh4LzB/jT/OelT+7Av+4CfU+51dd+xZsbH27rIUrM6sPZ1l6SUase8J16UMguUK9RGyQahv0CjXTk3h4mJJQFXIvyrULMUmHfe6ZIObbwsCDXhOrGObTZW8QVtRhceckFoev7vz9UgTtAweTxKY1/ZZxIFlsi9s2WMpajr//7MiMP5cBrBv4eptw0ajxBia+t0uIvNrqoIyWxfLSRvsgGzLwOa7UEtaQc8W7/R0P2wLTgD6N6Z7JeKjr4VaKgPcSAa8mn6165zYcXpuGSB/zL0QTwrtvK9z3pqDmxAz6+I1pzuXtUDhqHOmT0vQUlsIwV21/5fgk1PI1TbAvFCGzxjKf6u6hoLusSNnLMWyP7rgDlLYcwqcX1BVIceUsjAjOyDp6Tc/IxoD58oOvDCy8pxUwRGuSvV0NgVe2yoW8WXR3yBrCYSWHObYunAGVHZKF7fxtaDad6riPtQsS7aM14r3XnKei2Iqs8fFxJiTczR7iPgBk0maJm+u39a4gPl1rBstxHnRigbuhU2yJv6fUbVJjNdUDzaZL+joZpHLM/tnG6Ui0pTdu1R1xK9TbqrZpmOklMQ6A03gAL8xJmtHtTU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3ac84b8f-45b0-4999-4e85-08ddd8b70317
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 09:11:10.0756
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4ZstwEZRRnc3hjUgTp/UZ/qSz6tY0orKWgd36iMNaoUnkJFXERd8ZMOJKTjHzvgvI32eGqilbxkVJewSyktjA47DgPCunYbFqSZ5jK6HgK4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB4281
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-11_01,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 adultscore=0 malwarescore=0
 spamscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508110060
X-Proofpoint-ORIG-GUID: jwxE_B392GQfOucNP_8IB4jkLjFZigM0
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDA2MSBTYWx0ZWRfX27lLTy36X2Vc
 gFyYJV/uvR6iulD161q3f0wbaIoPZe27hnktZG7I9cXM+CvILxq7Kx4NzHfBCp8iEKXixPVtMDL
 Uy9q1yoqWvYCiMwNyrBNhvUMqg3dF7E07t/NOcBqUQXVybrTUWed3Ij1Wm6GaqJ4uJTIKhMjtbg
 CKqc5WqAGuW4zbmk1EIOKjpm7hiBXCAJTWmGP4eDSS4ADYjVh8xA4LaHi6jRpbSA3karDTw2Vl5
 ycqnMTIFK/A8HfjpSFMHsYEA4yZNwD2Dlv0Evb59uMEIH5P10sU27gSjLfpWHNWOvhILM5ufl6t
 99vvlEAXf8a7kzLJFo4Fx9Prd1G7JGy6U4L30oAehFiodLVuUNHl9Y+2n00QVOrtGTLhD+MhrPp
 vJ4mtPiOTTaomkU+DUOynTwbDOh0A0SlU+B0vlEOrmcqr3olugxJPk6aYBi71ym+7SWz61sy
X-Authority-Analysis: v=2.4 cv=X9FSKHTe c=1 sm=1 tr=0 ts=6899b3b2 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=yPCof4ZbAAAA:8 a=UsRtJFEanIWlDYqK5fwA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:13600
X-Proofpoint-GUID: jwxE_B392GQfOucNP_8IB4jkLjFZigM0
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=rMBjP9L8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="QKBOa/Nj";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 11, 2025 at 02:34:19PM +0900, Harry Yoo wrote:
> Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> populating PGD and P4D entries for the kernel address space.
> These helpers ensure proper synchronization of page tables when
> updating the kernel portion of top-level page tables.
>
> Until now, the kernel has relied on each architecture to handle
> synchronization of top-level page tables in an ad-hoc manner.
> For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> direct mapping and vmemmap mapping changes").
>
> However, this approach has proven fragile for following reasons:
>
>   1) It is easy to forget to perform the necessary page table
>      synchronization when introducing new changes.
>      For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memory
>      savings for compound devmaps") overlooked the need to synchronize
>      page tables for the vmemmap area.
>
>   2) It is also easy to overlook that the vmemmap and direct mapping areas
>      must not be accessed before explicit page table synchronization.
>      For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
>      sub-pmd ranges")) caused crashes by accessing the vmemmap area
>      before calling sync_global_pgds().
>
> To address this, as suggested by Dave Hansen, introduce _kernel() variants
> of the page table population helpers, which invoke architecture-specific
> hooks to properly synchronize page tables. These are introduced in a new
> header file, include/linux/pgalloc.h, so they can be called from common code.
>
> They reuse existing infrastructure for vmalloc and ioremap.
> Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
> and the actual synchronization is performed by arch_sync_kernel_mappings().
>
> This change currently targets only x86_64, so only PGD and P4D level
> helpers are introduced. In theory, PUD and PMD level helpers can be added
> later if needed by other architectures.
>
> Currently this is a no-op, since no architecture sets
> PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.
>
> Cc: <stable@vger.kernel.org>
> Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> ---
>  include/linux/pgalloc.h | 24 ++++++++++++++++++++++++

Could we put this in the correct place in MAINTAINERS please? I think
MEMORY MANAGEMENT - CORE is correct, given the below file is there.

>  include/linux/pgtable.h |  4 ++--

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1e8ca159-bf4a-47ab-b965-c7e30ad51b28%40lucifer.local.
