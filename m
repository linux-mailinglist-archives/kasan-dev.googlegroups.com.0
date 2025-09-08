Return-Path: <kasan-dev+bncBD6LBUWO5UMBB37T7LCQMGQEVRV46XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A1B0AB48B30
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:45 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-31d6bf5796esf1345727fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329904; cv=pass;
        d=google.com; s=arc-20240605;
        b=XhlvGHFcyyeyvNgOMr43wQVzCronuTUNcsULDBjIoy/JP45K/qAWIDiLuvJhiR3wj9
         v9x93iwQsmP/wsTc7kdnRenOoacMQI7w0HigoQK4384KsxHPMkRs4kRXlXm80I0t/cYf
         pCIRGZX0MnmczAUyFN13ISX0M6Wo3y8tJ+8dEu6eVWc9G1OvJhwYDV/1vPJmIlCG28+s
         Fqp3ZqcO1ngHn8BNVg1rb7wEhyr1UviS5++WEIzAn3mAuF7UZC3rYJ/8NnR0Zgs/loNP
         jEIMZc5LINmKEaEP8+mbe6BbVfNi5bB1qmQvnQA7XyKu5MMafdDl1LiiP1ZxBxtrNQtO
         D3xQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=oQDY/HUXxOfCNuc4lfG4gx7FVg/GY5nmXZwqqhZ6YdI=;
        fh=thN0qJMOW1jFkFpga+yM9Lq2qDCY2OOa1Ai24jYg3So=;
        b=imFYYZqqzyb6dsnI++1OrW5oscuQF5t27oari0sQxxEkPpX8sGYvn+AKLEnt7Cr5oE
         2niOEz6uMu+7mH1ICkGtASCvC1BOsUeqMlngleoIBI3nuodFMsN1io2ITXm7QRdhyAqG
         Pjgtx2mEgM6MLMsM3XHj/b1I7HgobNEYKCEnt8SQ6016a0w6CXVTha1nFAMgnKaC8XDG
         IVyHDCI2i2hZ5wP15ujAfZpcKsh/g8qWF4NIuxnQYOwcEW4hq+M7tmEFH3KLzcXbeAz9
         Nh2AcHxHOyDFb21ReXTtVgZuLob4Jl3gnmFcjFhKUx7s5USKL6b1nXFYgaywUL8wF9c4
         Wgew==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fDuJDT+n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZawzBEQz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329904; x=1757934704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oQDY/HUXxOfCNuc4lfG4gx7FVg/GY5nmXZwqqhZ6YdI=;
        b=pUdUcwQwHYYLrn5jpgzT0O5b4lj4GIipQNpz85SBi4fRWhIwBrR/YGtsAk715xxYAz
         /i+m0On59bVndUb6UDopV8EaMz+tvqFqw0k2lhzeNysAj0I14TR5cI1/ofSwAF4O0rb8
         SxAbe+49/5YacL1fXh3ne03E4WMdK5WfJkV+Rxbx76rTIkZAv+8SFhxGZGDcy9g+odaS
         AcBvwfw29PMJXxb3gIwNglrdzpMpg/gj9ynpav4MeNaCWtuwF5AB7hpDglgPestLEQFH
         Eq7KD1a4plvDh2T0Z7u1qB/f0nmtfdCVpFuNPnZfXNMWXwigiAnlYcCX0LAZb+W7ypQ5
         zTAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329904; x=1757934704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oQDY/HUXxOfCNuc4lfG4gx7FVg/GY5nmXZwqqhZ6YdI=;
        b=ZBQTtdrNSo9PdHg0h51+jbfi738aJiHJgEct6UN4+ETGRnI7FlawYE9OEwzCySmvws
         gahc7J3bVfv3Q5MrF+uC5LxpsbI9zHyJH5/pKcEmJVpJ8HPQ6rHB9F5M1kUkXmaKWCMj
         aqNTKrKwYMOM1leG+61wgeFRn4CTSO2pb2ZdO+PSbEsp1qNMdbGg4qsaUhZFm38ye16T
         nRAVRh9G7C9JWpTU0y6/GYiGei4YWnyzLsY9UpYYiBNhlNHIkNO8lQCRwDIE1K0LuWZ+
         KWiM3Xu3fSNYIUgFB3/WxTLETHzn3HjWSqMor8iz8zat9KstyLNvCBwnY8MpNF49zg/G
         2qrw==
X-Forwarded-Encrypted: i=3; AJvYcCX+EJZiElpQM/0hxmB2NwCET/d7rlv75XEmFImtOfJqiiQqfyLR8g1JaLivUeF9g5vrIZ1mjg==@lfdr.de
X-Gm-Message-State: AOJu0YxYtCcizPMfA52Ocj6FTuqgq8Bd35kx3oRSg+xYP02YjR3Vr1Dl
	V4oqVMUJ8czVqjWph+GYQ5o8d7X7nrtEYMdkx39C8z/Rur6JmfPEO/vF
X-Google-Smtp-Source: AGHT+IH+NnAqs4RmgmXMjYFmsuwOIkL4RDmMvs1JrkqfN4wMJtW1zieyYTT7uqpTuaRyyvGBtBK1AA==
X-Received: by 2002:a05:6871:6a5:b0:319:be1e:9de2 with SMTP id 586e51a60fabf-3226552e545mr2964189fac.46.1757329903848;
        Mon, 08 Sep 2025 04:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6oTS5t2x6Qo3H4nxLUC1zf+UQmMui/Avw0UZobRoA6Rw==
Received: by 2002:a05:6871:81d1:10b0:31d:8b8a:ce6e with SMTP id
 586e51a60fabf-32126bc4120ls799057fac.0.-pod-prod-04-us; Mon, 08 Sep 2025
 04:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXr0BnsUeK5pHPXISXdM124IuLfI5+hvzVZ8OSZlH6M1oMX3Vav1zc3W1kpMy6Pnr2kP7Ze67fJDCs=@googlegroups.com
X-Received: by 2002:a05:6871:521e:b0:319:c5fd:44de with SMTP id 586e51a60fabf-3226480d739mr3832813fac.26.1757329902439;
        Mon, 08 Sep 2025 04:11:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329902; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q0mtItPT8A/YKvOR+ze0slqYQUBbiOPK5wFxNkgqTeNNUXs0xQLGo3HaMhN77K60MG
         gyjd/yeohhRrPwcKgzreZ6+XbnjGlplp3CO8AC99xsZTDkrUMFVfv1Jh/HFuPQDN3kMT
         JCk3Q5KZc3P5nZBffu3coSGk0XrvpROflffQLNdmwpM0XhYXTBsMdjPh0t8d1mGHPLuV
         4CDmTkOglYJjCTgKR+qjwNuR5WnuVYR7rwxw4LfFgydRXKUYIGORXtHJSEstVxzYilL9
         aY59W3exFN2QDLUwb1wLU3DknCG/Vm41U+6D9wiKNrT2+JidLtlMDkVFTvJqWCcy98W3
         Dvow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=gz57yfJVYY55pJ8jX/B7xvolXutyen8mtTxHeZc/2Gk=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=IjTqmmrAgtSbiSXnvWfpKZBqBGMpHpIDFetVdjPXFQABOwF+oUpc7BP45Sp1MwCpLV
         fNqhMpc+OKkjRCXWGQkrgzFuJ5EP/6Pl6mWaQfG1mKRP8mfBgGq0hCm59YfSUlJXxMi0
         ih5z4bm/UK0xY2vpCL+DCXEr+2Yn3URePkoDayK94Def71IXoeUsiNIrk6YbeXKYdByu
         gwq0E99IC9vsB1yFZYspbEL1py9VuGI5sAUS7IeT7ZFwiIbmJfK8hhpMfZABvvRQa9PV
         WxmvJe6rQBCtTG1+DFagXdKTG9oTkiBl5P3yA2elrcZ9JW3xk+wEGtRMpxigOp0408+b
         VDXw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fDuJDT+n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZawzBEQz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745a106144bsi526970a34.5.2025.09.08.04.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588B4rqf011813;
	Mon, 8 Sep 2025 11:11:30 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wxvg07b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:29 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5889YAKq030737;
	Mon, 8 Sep 2025 11:11:29 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2042.outbound.protection.outlook.com [40.107.244.42])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd819u7-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:29 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JMrYllM/A166ZcyRvZMqjT1V+2L3KnAWQQs5Uxc5zvFbN+VxRwGdDXHdfcuCsgL+ZYIbfG22aA4Obnhmctq2xzKDZtdrq7wEN2dhE+L+7m3C+UIcPymK4rF4s/9peFUpQmHAFs8aZb0Lcx91YuyRo9ShRaAUeJwyqQ0La0084ertC9M1sNIXKjllyv34NxepF0IhzCUCJvZKNbTBpWbCfYlEZKtRkYwtDjnpvkjwY1KpyAALg2pmTciqXNVP1QbkbYurEuRuRCQ42F2W5ShDEdX/3QBKJNNAb8QsBv8WmbjX9P516C9JD2sKd6kC4ZWcybEtJWmbDmalyFD3I3sWBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gz57yfJVYY55pJ8jX/B7xvolXutyen8mtTxHeZc/2Gk=;
 b=JC6Wy2jwbOBwD5JR+F2fMyqvqQHAIJ77IW3G9AIbsNlbRqnqT49w2nuApkrt/R1gI8trN5MeFWpe1vY0s2wvqicvCgqfQ7zZ2l9fA8wQItXquLEu0HhHE2NAyLrxzgtBUEDAuaBwzH60T8zy83fVvXSjMOyrw7rEEW96dB5Kn0eYUjJ8/g6DU4zm3d6kxyKv8NiHt6xOBGmdUAQGkZeUxkOdSg1njYMt0Y+LNpzdCuHuT2LYUBRCrFdkEyQenkpnN8pX0lgoMYEDkoxKtQnRHBfBID+HrBqWPLPI+o8H5vRPjKVFc51GrIMw1AE0hhbpzLFi4Yej6xxzUCGzNcLK+Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7155.namprd10.prod.outlook.com (2603:10b6:8:e0::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:23 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:23 +0000
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
Subject: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort hooks
Date: Mon,  8 Sep 2025 12:10:37 +0100
Message-ID: <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3P280CA0109.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:8::12) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7155:EE_
X-MS-Office365-Filtering-Correlation-Id: 74baa32d-14b9-4652-2874-08ddeec8720f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?PapI3ih3wfP/hwTk7s3JRJlxQhA5lIreStn38Tr6jtkbBkrBmA+I3BhG24PY?=
 =?us-ascii?Q?hlyN6im5qtfIAoEHdYPallM7qmBwnT6DyI/d/ISSaVK8suafxGKpgj8kij8Q?=
 =?us-ascii?Q?ePPhSpBFla1gRVWL1+9qXGgAo8lJt2RzxUSWDYPX57MJOnOf+hfGIkHminCl?=
 =?us-ascii?Q?LPJVwILriZ3kLYZOx6bmKBzaYWC3+eilcPPmK0g++RVA+D/F9DN5qOwmJGjm?=
 =?us-ascii?Q?nfiVky5OAiUg2YoRD059lS6YSoIjWj5r0gYgsERRcptHAhXv3YpEfRBm6zNn?=
 =?us-ascii?Q?j8U4KzbAYzPKFOCPAWj5rv4v/OjktZ0BMG/0NzMCa9DHL0F93aRiNZo3gIm7?=
 =?us-ascii?Q?RxHpghtQbuhIrr9evj+yWTKTHIHyn+LYOETXwPFv36ltJcIyoriyfPmGBipt?=
 =?us-ascii?Q?F1Vzh8SAQd26MaktQYw40Q88SzLGl+kvSZcd9G1OEwu0lWO0wOYw5+i0fKq2?=
 =?us-ascii?Q?VLd2x8WOJl6vMO1C8QgK7iI4RxKNhcqspRGR+Jj/RlmEFZzlp97SpOM+Q0q1?=
 =?us-ascii?Q?6bDQ1ThhFgejKIOPVg/QEhxc55lldqZRIWK6E3XdgL9IVHieRmc/F2T+WVkw?=
 =?us-ascii?Q?cGbCV19yoFrad0xBVNr+mNrb3diQYDUuuxY62EZ8iAm0otYsMq9+alNEnRgD?=
 =?us-ascii?Q?SJ9HMwZRLzid61OaHMQRpK/JIxlm7rD4DFcJXSpeDdzSaSelOtlq57nV5UFd?=
 =?us-ascii?Q?uTWcRbdXHr4ap0EJVWx5x7yF9NVKnvyrPhODUt7HjRk5Cn7vCcx4ho3Vte7M?=
 =?us-ascii?Q?hwV5v8UJPih0XjN7Hw+9NdWW78oWQzBKD2cNsU/QiONpN3kMlSQEOrLsg9zw?=
 =?us-ascii?Q?SgDKwe/QWmk/3xYkrjDWCLdabIcamwWtaSMYBgivA3xG2yvJJhBmOwz9UzsC?=
 =?us-ascii?Q?x/76NseTGv3qMdwr7NR3CzTOw+HJSPVsEqnA/yU5eIz+wStZif0K99zl2tj3?=
 =?us-ascii?Q?1mz8u7lr/lVX7gsami7ceMlCO8wVpTy1+fMIm5+/jV4lZX6ImEANif0yMAsk?=
 =?us-ascii?Q?xKef+pRvV4PnbwpIvhVF7U91k/RtXKTejzdtGvbpw86B0oayQihIdGY600/w?=
 =?us-ascii?Q?kNcgWUTYPkw1YUHk2Vu+XTfRf26I79ARpLtZoC569g4Ycm9naB2D9snvurRh?=
 =?us-ascii?Q?yri211Zf3NbW6YBzeU5poXyZlC0diWbPAlnt85NPQa62txJOA7Axm7NLpQLa?=
 =?us-ascii?Q?7kFVIRIqnYFkXjtNVt9JArMncXFmjf/fonLVdd/c/+cVMa1un1OA70T6en3C?=
 =?us-ascii?Q?lv0CW1ISnlyQxYY38W6JHG36zaxW1XVPBc2nqLPJ1wOTHuzI8fLvt68XAGaK?=
 =?us-ascii?Q?c9KfwFwKQV9VfnJH8+4G4DeHQpnazPW/B43Y9OP59DM3vm5+UqnCVi+2o5Wi?=
 =?us-ascii?Q?N/Tepa0N4FsAcNs6qv5LKOSgbN+pwSHarvPljF30k/2K4oBDbZlE9Ro4ZwHr?=
 =?us-ascii?Q?BkkAO3VOsZ4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?FxU5UYO7kXrfnI3hOgTgwgkbsueVDESCUfWbtlG7qn1BgUlMHnTQ7N/0wBY7?=
 =?us-ascii?Q?xVXK5eXHr4iyQBzVzIECH1xyq6EBQv1GkpiJbdTaE7cxgK+ibew0Xa1CFhmG?=
 =?us-ascii?Q?QsHYK8pPWaccHqmQVLL0G/W/n5SrXm+0ZmG/I9tVQDgaQ4H274MnShHqtx7a?=
 =?us-ascii?Q?KqDNCyKRXaouvveP+0JjCf+/0eDZzwjUx/aGwlicnSLJYDlIO7LMnho2BUPw?=
 =?us-ascii?Q?KNrUvygp5zAHZXO/3I+/gmmTgAPXIdL5zIGuodnz82bpqgOi8qvfB/os8fCP?=
 =?us-ascii?Q?jvpkJUvqvQ3UCLtZFkEuhqmIqb39NwXpFEAapEDWWhtNN2Zqyr/DObYzexeh?=
 =?us-ascii?Q?J+yRCAflY4tfBsd4ZGaFQVsKoYiayhoyplASW4fHzzzWoMEhan87CGy3zJ7P?=
 =?us-ascii?Q?UfH126nLEzNLaIdFzmldxHqJz1CCWXRhoynUusMxun4dWxmhMaBgXDLhS0Lp?=
 =?us-ascii?Q?42d22ndCdZlaMD9PVF3Ci/V63SkF+t3Fw6hL//SbZ4VwuC4einwhNBIuqWT+?=
 =?us-ascii?Q?uADtgkJt2YEHvGLGcTmfQHB6iPO7gWCAtKSTYS3IRrLCa8YZpNQxBEXDMBst?=
 =?us-ascii?Q?W6co3fXCMVkUIj+iUmiIdJ9t1Z1zcvuoc91MjvzVSb3ybOqwt3tA06DV1Pdy?=
 =?us-ascii?Q?BfeLH03WzYmLAVMAPLs2fppc7/cOyfIzU9ah8dml5cFJBoxcWKPBPjhRfzrc?=
 =?us-ascii?Q?BHXHCof59doEOPc6veQ7KANtLWeLkCtSGUPSubhoiyVodjkxwi1xq6dgarg9?=
 =?us-ascii?Q?crfPpzdJOpom1uIXqTFYi8DywstsHDFu3iVJPvRJTE/skdWCsP8ZsuYByt4P?=
 =?us-ascii?Q?YsabMiI+bOwuPlu4SbsbcGTHgEJ7fBcn597uSPU8+mmE733K8Kq+rN2Dn1hx?=
 =?us-ascii?Q?i3YKEGKk0BH1JLn2lEiTcpZoVRKOZIP8AOHNYWYuqft5qPjbXCympf+dbESP?=
 =?us-ascii?Q?scySfQ+KIUh9AlOa/Oce0ozR6u/iw632U0cAvhGoKN+xRLMjxHocJsrDXjtC?=
 =?us-ascii?Q?vh4keXoO/Oki7jAUTsKb7goTVP4qKaZGkdhrUdzmxXEcRztuqBUcMwn0DuL1?=
 =?us-ascii?Q?MEMIMaBx2cS6hq3TLf5JxtonVQv2zZwtfxJhEjDpMw4gL9S76lkY8+puEdfZ?=
 =?us-ascii?Q?CSJIDb1m+xXRkYawIALMcHGm9ZQs+Du99yD8VLbwTXW4HZpZkuqjMXTQaK3d?=
 =?us-ascii?Q?2pzeUILrWXbMfYh2h2Alu0wcHeJ4MSKRFsQR9N02bupPMYLq6woL+00vnBSW?=
 =?us-ascii?Q?Q1EIDTM00ICoKtPZ7iJ4AuQvT5aT1xWq9KdzgZ3VFie1ckufwdojz41+mn34?=
 =?us-ascii?Q?VM9/NZSE6vFWCgw7i8KAtG+03jFJ/z0ECmlHNhHuOPPunI7UOZFuv9rUwefo?=
 =?us-ascii?Q?X599zwi+4ZZzrCQ+5M82v96hjBxDzgQXKNcIaWCoXV8WRG1s1LmY+lvP1eIl?=
 =?us-ascii?Q?2DiW8JvQNFQbxB2l9D1VGsvWZnaA71gOA/sQxI8y4CVhCl5oWsbpj7ZZtTT7?=
 =?us-ascii?Q?Yq6DqSnQWlK9XbLiv5InL/UqdB9ONO28wtst+6n/60+WHK6J3xDlAPbcLT+i?=
 =?us-ascii?Q?ZLEKLuNvJj/jQ199t/LFRCa7m6Au3tRn5e+1ynlNqNDUbaiSc8I66eLBkDXt?=
 =?us-ascii?Q?Zw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: WnrOlYLz/f+X6tlwZZe9Xbx1ljZ8UF5HA053hMUxHwbavlaAiB0yvTZ6iWRv3eDhjvMpBGxkdwNHouSAoNqRImjfsz1gJePAEw4IJGrld5pEevNKPnKNalv+AZk4A1XMj7hi3K2Tx6veYejB2rlS0omGTwqxIBYGvUAog5zfCG8kR6qRYwiU8QSyMibs/aEqh5Dd/vsAFlOOrn3vrWhV3K8kfYn7nC5pGwsCZxsgBuh3SEMKnTFt1Pk2f3ZYvBjgBYg35Qxr1H5GJ1Ve05WyiFD9YcFcp/1NmdpJZtj1N89JrN102CSKMJpxDK3rA00g1VsxMge7BnpK2XjYfEZvn9Pf6Dl88hOyok7zV3KbMiGoMz+tLTaFXRT+ktQLY/+X7bLLcXFQ51J/+KI05BxxfK4b0ibLC3hUyomzJmZ1aUeitR61dKG1VKruM/eipkMGboIMPU6bU/OKAfsgicwiDvtBF4Jh2nZiXOamDjoWUj2vAa5I7LF3dIVe5KSu5SeZU8qE1HPOIfGXW2FCcp3huA9NiO7M3az34yYOjpR4EaUSqqLhrlkr/bLVPg8MiOdaB1aAuTKPZEBlFWuRwCEykBu2hEULA/Thv6GkElW5Pbw=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 74baa32d-14b9-4652-2874-08ddeec8720f
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:23.1969
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: HEfUt+WLT6K830b4BPLo5FFlXo/xY+utzfEXkzFVJVqYPqpLJ6lM6Z9dRu3gEscgqdsCwTP24CJBeEFEKs4DfMO/tSFVggVOr0rLqTOnLqs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7155
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509080113
X-Proofpoint-ORIG-GUID: mIuJGnVRsnBd8VCQcrLcHpOnvb_4QPFS
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMiBTYWx0ZWRfX9DcKhCnnoTH6
 TD3TSn6lmASdwnVKxrIiUTNsIbeiAh062HBKf+oHbkUM2kHTQVaKeX5omrX7H3FSqkl886O9DBL
 Ej7A3nVf9gKRAOXMhUrubPJPu5EgGDznV3gKncc3VQB4g27qj5GrNchCTyelXEv0kZk/s4+mWHu
 Jj/ngn+5AshATyKaVCllspaKYF6bX90y9mBV9Bs+ez6ikC9vfcTUrA11H+oYFiVr/OBUnzQUEKO
 k+d3Ais8E8agIO8DWtz0raYzZE/41afeHtre1kzBv/mox6enLA2G6WyycbxpOxkrUTqEG1hhcXp
 Ocxg58NEXl2Pm8WSQFwjbrEgRyHIdeuMqC/tgTzzZkRmwnDN9A49eqDkdZFHdskrpm5ISSyRTan
 r+AByrq1
X-Authority-Analysis: v=2.4 cv=MIFgmNZl c=1 sm=1 tr=0 ts=68beb9e2 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=ADFhEmSlnIQLkT-ZH0EA:9
X-Proofpoint-GUID: mIuJGnVRsnBd8VCQcrLcHpOnvb_4QPFS
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=fDuJDT+n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ZawzBEQz;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

We have introduced the f_op->mmap_prepare hook to allow for setting up a
VMA far earlier in the process of mapping memory, reducing problematic
error handling paths, but this does not provide what all
drivers/filesystems need.

In order to supply this, and to be able to move forward with removing
f_op->mmap altogether, introduce f_op->mmap_complete.

This hook is called once the VMA is fully mapped and everything is done,
however with the mmap write lock and VMA write locks held.

The hook is then provided with a fully initialised VMA which it can do what
it needs with, though the mmap and VMA write locks must remain held
throughout.

It is not intended that the VMA be modified at this point, attempts to do
so will end in tears.

This allows for operations such as pre-population typically via a remap, or
really anything that requires access to the VMA once initialised.

In addition, a caller may need to take a lock in mmap_prepare, when it is
possible to modify the VMA, and release it on mmap_complete. In order to
handle errors which may arise between the two operations, f_op->mmap_abort
is provided.

This hook should be used to drop any lock and clean up anything before the
VMA mapping operation is aborted. After this point the VMA will not be
added to any mapping and will not exist.

We also add a new mmap_context field to the vm_area_desc type which can be
used to pass information pertinent to any locks which are held or any state
which is required for mmap_complete, abort to operate correctly.

We also update the compatibility layer for nested filesystems which
currently still only specify an f_op->mmap() handler so that it correctly
invokes f_op->mmap_complete as necessary (note that no error can occur
between mmap_prepare and mmap_complete so mmap_abort will never be called
in this case).

Also update the VMA tests to account for the changes.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 include/linux/fs.h               |  4 ++
 include/linux/mm_types.h         |  5 ++
 mm/util.c                        | 18 +++++--
 mm/vma.c                         | 82 ++++++++++++++++++++++++++++++--
 tools/testing/vma/vma_internal.h | 31 ++++++++++--
 5 files changed, 129 insertions(+), 11 deletions(-)

diff --git a/include/linux/fs.h b/include/linux/fs.h
index 594bd4d0521e..bb432924993a 100644
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -2195,6 +2195,10 @@ struct file_operations {
 	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *,
 				unsigned int poll_flags);
 	int (*mmap_prepare)(struct vm_area_desc *);
+	int (*mmap_complete)(struct file *, struct vm_area_struct *,
+			     const void *context);
+	void (*mmap_abort)(const struct file *, const void *vm_private_data,
+			   const void *context);
 } __randomize_layout;
 
 /* Supports async buffered reads */
diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
index cf759fe08bb3..052db1f31fb3 100644
--- a/include/linux/mm_types.h
+++ b/include/linux/mm_types.h
@@ -793,6 +793,11 @@ struct vm_area_desc {
 	/* Write-only fields. */
 	const struct vm_operations_struct *vm_ops;
 	void *private_data;
+	/*
+	 * A user-defined field, value will be passed to mmap_complete,
+	 * mmap_abort.
+	 */
+	void *mmap_context;
 };
 
 /*
diff --git a/mm/util.c b/mm/util.c
index 248f877f629b..f5bcac140cb9 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1161,17 +1161,26 @@ int __compat_vma_mmap_prepare(const struct file_operations *f_op,
 	err = f_op->mmap_prepare(&desc);
 	if (err)
 		return err;
+
 	set_vma_from_desc(vma, &desc);
 
-	return 0;
+	/*
+	 * No error can occur between mmap_prepare() and mmap_complete so no
+	 * need to invoke mmap_abort().
+	 */
+
+	if (f_op->mmap_complete)
+		err = f_op->mmap_complete(file, vma, desc.mmap_context);
+
+	return err;
 }
 EXPORT_SYMBOL(__compat_vma_mmap_prepare);
 
 /**
  * compat_vma_mmap_prepare() - Apply the file's .mmap_prepare() hook to an
- * existing VMA.
+ * existing VMA and invoke .mmap_complete() if provided.
  * @file: The file which possesss an f_op->mmap_prepare() hook.
- * @vma: The VMA to apply the .mmap_prepare() hook to.
+ * @vma: The VMA to apply the hooks to.
  *
  * Ordinarily, .mmap_prepare() is invoked directly upon mmap(). However, certain
  * stacked filesystems invoke a nested mmap hook of an underlying file.
@@ -1188,6 +1197,9 @@ EXPORT_SYMBOL(__compat_vma_mmap_prepare);
  * establishes a struct vm_area_desc descriptor, passes to the underlying
  * .mmap_prepare() hook and applies any changes performed by it.
  *
+ * If the relevant hooks are provided, it also invokes .mmap_complete() upon
+ * successful completion.
+ *
  * Once the conversion of filesystems is complete this function will no longer
  * be required and will be removed.
  *
diff --git a/mm/vma.c b/mm/vma.c
index 0efa4288570e..a0b568fe9e8d 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -22,6 +22,7 @@ struct mmap_state {
 	/* User-defined fields, perhaps updated by .mmap_prepare(). */
 	const struct vm_operations_struct *vm_ops;
 	void *vm_private_data;
+	void *mmap_context;
 
 	unsigned long charged;
 
@@ -2343,6 +2344,23 @@ static int __mmap_prelude(struct mmap_state *map, struct list_head *uf)
 	int error;
 	struct vma_iterator *vmi = map->vmi;
 	struct vma_munmap_struct *vms = &map->vms;
+	struct file *file = map->file;
+
+	if (file) {
+		/* f_op->mmap_complete requires f_op->mmap_prepare. */
+		if (file->f_op->mmap_complete && !file->f_op->mmap_prepare)
+			return -EINVAL;
+
+		/*
+		 * It's not valid to provide an f_op->mmap_abort hook without also
+		 * providing the f_op->mmap_prepare and f_op->mmap_complete hooks it is
+		 * used with.
+		 */
+		if (file->f_op->mmap_abort &&
+		     (!file->f_op->mmap_prepare ||
+		      !file->f_op->mmap_complete))
+			return -EINVAL;
+	}
 
 	/* Find the first overlapping VMA and initialise unmap state. */
 	vms->vma = vma_find(vmi, map->end);
@@ -2595,6 +2613,7 @@ static int call_mmap_prepare(struct mmap_state *map)
 	/* User-defined fields. */
 	map->vm_ops = desc.vm_ops;
 	map->vm_private_data = desc.private_data;
+	map->mmap_context = desc.mmap_context;
 
 	return 0;
 }
@@ -2636,16 +2655,61 @@ static bool can_set_ksm_flags_early(struct mmap_state *map)
 	return false;
 }
 
+/*
+ * Invoke the f_op->mmap_complete hook, providing it with a fully initialised
+ * VMA to operate upon.
+ *
+ * The mmap and VMA write locks must be held prior to and after the hook has
+ * been invoked.
+ */
+static int call_mmap_complete(struct mmap_state *map, struct vm_area_struct *vma)
+{
+	struct file *file = map->file;
+	void *context = map->mmap_context;
+	int error;
+	size_t len;
+
+	if (!file || !file->f_op->mmap_complete)
+		return 0;
+
+	error = file->f_op->mmap_complete(file, vma, context);
+	/* The hook must NOT drop the write locks. */
+	vma_assert_write_locked(vma);
+	mmap_assert_write_locked(current->mm);
+	if (!error)
+		return 0;
+
+	/*
+	 * If an error occurs, unmap the VMA altogether and return an error. We
+	 * only clear the newly allocated VMA, since this function is only
+	 * invoked if we do NOT merge, so we only clean up the VMA we created.
+	 */
+	len = vma_pages(vma) << PAGE_SHIFT;
+	do_munmap(current->mm, vma->vm_start, len, NULL);
+	return error;
+}
+
+static void call_mmap_abort(struct mmap_state *map)
+{
+	struct file *file = map->file;
+	void *vm_private_data = map->vm_private_data;
+
+	VM_WARN_ON_ONCE(!file || !file->f_op);
+	file->f_op->mmap_abort(file, vm_private_data, map->mmap_context);
+}
+
 static unsigned long __mmap_region(struct file *file, unsigned long addr,
 		unsigned long len, vm_flags_t vm_flags, unsigned long pgoff,
 		struct list_head *uf)
 {
-	struct mm_struct *mm = current->mm;
-	struct vm_area_struct *vma = NULL;
-	int error;
 	bool have_mmap_prepare = file && file->f_op->mmap_prepare;
+	bool have_mmap_abort = file && file->f_op->mmap_abort;
+	struct mm_struct *mm = current->mm;
 	VMA_ITERATOR(vmi, mm, addr);
 	MMAP_STATE(map, mm, &vmi, addr, len, pgoff, vm_flags, file);
+	struct vm_area_struct *vma = NULL;
+	bool allocated_new = false;
+	int error;
 
 	map.check_ksm_early = can_set_ksm_flags_early(&map);
 
@@ -2668,8 +2732,12 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 	/* ...but if we can't, allocate a new VMA. */
 	if (!vma) {
 		error = __mmap_new_vma(&map, &vma);
-		if (error)
+		if (error) {
+			if (have_mmap_abort)
+				call_mmap_abort(&map);
 			goto unacct_error;
+		}
+		allocated_new = true;
 	}
 
 	if (have_mmap_prepare)
@@ -2677,6 +2745,12 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
 	__mmap_epilogue(&map, vma);
 
+	if (allocated_new) {
+		error = call_mmap_complete(&map, vma);
+		if (error)
+			return error;
+	}
+
 	return addr;
 
 	/* Accounting was done by __mmap_prelude(). */
diff --git a/tools/testing/vma/vma_internal.h b/tools/testing/vma/vma_internal.h
index 07167446dcf4..566cef1c0e0b 100644
--- a/tools/testing/vma/vma_internal.h
+++ b/tools/testing/vma/vma_internal.h
@@ -297,11 +297,20 @@ struct vm_area_desc {
 	/* Write-only fields. */
 	const struct vm_operations_struct *vm_ops;
 	void *private_data;
+	/*
+	 * A user-defined field, value will be passed to mmap_complete,
+	 * mmap_abort.
+	 */
+	void *mmap_context;
 };
 
 struct file_operations {
 	int (*mmap)(struct file *, struct vm_area_struct *);
 	int (*mmap_prepare)(struct vm_area_desc *);
+	void (*mmap_abort)(const struct file *, const void *vm_private_data,
+			   const void *context);
+	int (*mmap_complete)(struct file *, struct vm_area_struct *,
+			     const void *context);
 };
 
 struct file {
@@ -1471,7 +1480,7 @@ static inline int __compat_vma_mmap_prepare(const struct file_operations *f_op,
 {
 	struct vm_area_desc desc = {
 		.mm = vma->vm_mm,
-		.file = vma->vm_file,
+		.file = file,
 		.start = vma->vm_start,
 		.end = vma->vm_end,
 
@@ -1485,13 +1494,21 @@ static inline int __compat_vma_mmap_prepare(const struct file_operations *f_op,
 	err = f_op->mmap_prepare(&desc);
 	if (err)
 		return err;
+
 	set_vma_from_desc(vma, &desc);
 
-	return 0;
+	/*
+	 * No error can occur between mmap_prepare() and mmap_complete so no
+	 * need to invoke mmap_abort().
+	 */
+
+	if (f_op->mmap_complete)
+		err = f_op->mmap_complete(file, vma, desc.mmap_context);
+
+	return err;
 }
 
-static inline int compat_vma_mmap_prepare(struct file *file,
-		struct vm_area_struct *vma)
+static inline int compat_vma_mmap_prepare(struct file *file, struct vm_area_struct *vma)
 {
 	return __compat_vma_mmap_prepare(file->f_op, file, vma);
 }
@@ -1548,4 +1565,10 @@ static inline vm_flags_t ksm_vma_flags(const struct mm_struct *, const struct fi
 	return vm_flags;
 }
 
+static inline int do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
+	      struct list_head *uf)
+{
+	return 0;
+}
+
 #endif	/* __MM_VMA_INTERNAL_H */
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes%40oracle.com.
