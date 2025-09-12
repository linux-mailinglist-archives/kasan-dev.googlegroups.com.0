Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPXKR7DAMGQECVUCXNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5904DB549B3
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:26:08 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b4fb59a89acsf1268489a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:26:08 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672767; cv=pass;
        d=google.com; s=arc-20240605;
        b=a6zFqrpFa3isgDGlsf4QZ3JryscqgTzZHEcEgwV1k5At9LudU0UdPe4CAmd1EPUALm
         vw9+CVEDVw77/Vpm20Jm1rlM6bQIRUujR86PPo+1gD6Ev15LK1uI/b5X5qQLwBURg26s
         E2k0kkAyS3mkOmHWliXd4DRNd1MKiNNA2GJN4Y9mvhzhF+iEM30BBmNCt6TL1My295tR
         Zo1CXJ2Gb/yrrvNQdzM3qwGP3kCz8QLI8teN4Bb5ye02U7BkYV5EXMYgZOiolzUDdi+j
         MLD0CCgZP95tAnxoLB4XKYW+uE8sqoXOi1j1yWyZw8bfLI2DWDhMIvMSWsVWTLINEroe
         p4yg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=voRfpyXylUTzW7Z7LlLO1reX4sm28Xx9dNJKUvESDA0=;
        fh=nskemd67OWpCEp8Gm6jhu8V0QC55GHG59gulf/RNndo=;
        b=Mezkz6IFlueqfRYgfeaHxFyp6PLItEPwrWcMcbCmSra6sri7FIj7V7WalA4dNyyeQW
         qayB7UqqrY+SbomTxEqqdHxuvDD7t8y2TJ3wmPK6785fHwCW/9b+2kUtj4TOf8W7roAN
         EPCLwYAsHSEGrcxxhHwHNL/OB8CrxQsDfn63uveQSl69EWC/q1eQS5IbNiTaQgzS1Vdm
         HSBu3p2r+3UjaiJbczLb/bhxgyh8RAxcMxQ9mJvZXVQjZ+WOrdsKE+AGG+RhrPnHg15r
         8cuh1hyA9A7zYCctunA5eDbT+SWlxyVRAo58qx1FCRGuKHyLWsZpubZqKlMW6fe0doP5
         khzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="imMmYnD/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=jOZFjdcr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672767; x=1758277567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=voRfpyXylUTzW7Z7LlLO1reX4sm28Xx9dNJKUvESDA0=;
        b=NoIJSR11nsmIJnmE28Ma8wHQys4K5E3DCCeKX8dewjIqZ4AgexX5lqzuQ5qnzcfZ6K
         hZsKE0CN3u3A9KC0YxUw7PjOZZwrZq+HUemenh2e5rQkuKpPtg9JslP3/So3UYwLLSMU
         WQVLhkBBb+y5fFzJgQ2l+m/dIOw94ogj8Y8Mccj9Nnzlah6FowMHbVXMVHkaZ8n1g9en
         o5x6Md41AfuXaTPm5C9Ih/1cNGsP3Lqn4AnD52xIbmms5leFA8XvGYhaJtm1Sq//jDXg
         j8MB9hWD+DDhPjBaEb7wDRF9iMf1SkJxMYRCHHZiHYjQnC2eyyOx54VoPBS9FZHcEEqz
         5qEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672767; x=1758277567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=voRfpyXylUTzW7Z7LlLO1reX4sm28Xx9dNJKUvESDA0=;
        b=SOFHHQgZmiria+DMrfDmEOZyMsPTKvHrgkNKHiPFCRhlJY4HOjr+uWpBnKUFX2uMpw
         hwqGoi64kJVpia6GT7F5fWFs3rHVB8faauxexr7JYbmcvtZiD/fzSM/geM7IY2g5Ov3P
         cadbMg+Iay4hCoYUZV6l5rxoGA61oYcbjYeIwXEgMwYrPwkeOBewj7RdeKWGttGaAz3N
         U7ziwsJUI2bRdzlYv6c6HJ4QwNH45JuaaFZbb36lbqQALhEyZUEkQVBJWJqx1SyfWv2W
         uw6LvtI7ToUAjSMdZsG0YKdZK4Gq+lDYwKUM1kabKUT5nmy7UzTMaLdtmiiMm4AA3Q9/
         PZFw==
X-Forwarded-Encrypted: i=3; AJvYcCUpFsBYjOIMOgJVzefoVbS9nqwcMnuNEwHuoWl8aIrMVdLPMcrS5YwLT39Wm4v+RDHCH5/cfg==@lfdr.de
X-Gm-Message-State: AOJu0YxOdu9gyZVmgQLIpSfxDHf8Z2TinOgpVknZ+Q5T09ERjD0umg+a
	o9RYs30UsduEIp/T4QQRtaevbkpchzDHOkd8c7RD2DHl+otk2QB7g8yi
X-Google-Smtp-Source: AGHT+IE6OLh2EJLMYyIg18fVaE16sbWT00FZReO9/bBKZ2Eff/cBSzry0Ee8Byv2DlcsdvJ3GoP/qw==
X-Received: by 2002:a05:6a20:6a10:b0:248:e0f7:1331 with SMTP id adf61e73a8af0-2602a49b119mr3166064637.3.1757672766721;
        Fri, 12 Sep 2025 03:26:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd72lUHAcd1QxIvnHxZIWQo7TXqaX9mFvQ7HMz2RW8eIHg==
Received: by 2002:a05:6a00:17a4:b0:772:4235:4c0d with SMTP id
 d2e1a72fcca58-77604e13bbcls1622238b3a.0.-pod-prod-05-us; Fri, 12 Sep 2025
 03:26:05 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVlNhxSiCQa8rdxlCkJ7+P15V66DuDE90I+mL/M5DWo4kIc0QzIT/GD3ctM2kS7wXDu21D2PRkXKk4=@googlegroups.com
X-Received: by 2002:a05:6a20:6a11:b0:248:92f6:b5ac with SMTP id adf61e73a8af0-2602c43326dmr3134431637.32.1757672765038;
        Fri, 12 Sep 2025 03:26:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672765; cv=pass;
        d=google.com; s=arc-20240605;
        b=SMaYr/05vdEIqGIq/5eEgNrFzY+RGbrKxq04SDtLHg9GM8CGniK/bN6M7d887vqrhK
         XHwqAIbA7cowpnTB2rEy7leLp6g9EFwMbGXJ0AAWfkSq7CHTJpooxtrSLLMv7dAihV/s
         qoOeyL8Egi5a36Oys4xGEcOGSB66LuXn2C5gahfrTorpVWNS7BL6NI3mkeob0wrth6LL
         Ik/HKcJiDnEFrwl24ST80Vp2JMGzkXSzQkWbs3j/Lor4uAXJDmVGR40BVx+0e9JuLkR6
         7NoOKK2aBlEpO34xzAXlRKNaloYnOtFsKgi4aFWjz/mLSrKaYNSZM9SjsxfB/XD2s41h
         ZcTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=incJwCIYorm8M7FpmmTc0A8Xy986UI3fv+7VhTuyXHg=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=TaDcuBcd/5RPFN1vNKer+x/gan7pTrYgWk+GS1s38PWLad6tTtXq6e9hjE0BVmz2Ky
         3lWh1eYO5NQ0nxPYeUKV5B3n/3I25vzZpxF5zw5WzehiTJgk7NY5fmVrcE6bSSZJ0pYj
         g33+hKYayp4nxhqYwQTt7EQ2MWIWTMstmju7Zbbc2bCi8KEG4sUlXVLDiyW2XRuAeKd8
         98JN+4QRlPKJCwDbLQlRLnR56ZtvuWJH9KVOO2y9cHmbletbs+Hjfe1shgCG+e+7x7pn
         E8CWBkkaDK8tUTwAcDVBY09PMzFrZu2vAh3I0LvAEaXnHI651WQhoMlFf3AMQcYRqj+n
         n1Zg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="imMmYnD/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=jOZFjdcr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77607b2b236si171004b3a.4.2025.09.12.03.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:26:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1uMVa009829;
	Fri, 12 Sep 2025 10:25:52 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921d1r3ce-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:25:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58C8l7bG030633;
	Fri, 12 Sep 2025 10:25:51 GMT
Received: from sn4pr0501cu005.outbound.protection.outlook.com (mail-southcentralusazon11011057.outbound.protection.outlook.com [40.93.194.57])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bddn0w2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:25:50 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tgr5qb9upQD9/+QR/LCgB1fvEiovVagdXpKXp5Y+hEpXEOcCoXBJaFFU1XGL6vGgsdkdBt4rt8GzEYP809QAkYS7FDHsEuUi5xoCJXko+g29aO91YhENh3kuF97S7zctvwqb55obVS1pCgOXWo1vzfncrRFKR+8xsQghlXArYqukY905Ewsum7vhLTuzQrjM2YqByJyPohwyi/JHxIEXWvKOKFCrfOGFLw3rumcgE07o4xR1kalsANJ0WR1hTPbrFmXZ7dWaMwYR+dVWrSdn1EtN7JUrZf6qPSZhznrQGOafSd17IoF1GoJv6Csv/FNHTnl9cqht3BGm2vaN5ZFneQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=incJwCIYorm8M7FpmmTc0A8Xy986UI3fv+7VhTuyXHg=;
 b=bhExYOwmLgvwKpB/+NJ5tqiNcNAx2GNqxneeKDwyg9ix95OvOF/mxIfWvq98aa+VAPsJNxb4xmRszcVPQNRN5bJOA198GWy0djEyp9l9Av4Hzq+a1akmSC/8A22SOWiWMXrisHm0n06qKljeG9SxaElWAD16M7VSXQMqQvgmJx72Kx8Go/2z9n+qr7Dp8e17SqZhQYWae1HCOhiLuRjYAdB/i/fF7DqLLYTOY6FnJQQOF5Up+2Ue6Hf3ZWHGVGMpixQGcXA5U7As2lg37b1y2qCgiwbvWrhow2uDdJ+GXgowFkBpNDdwJRujKOswzNo36L4E0ZqZ1ONQ9IX784CTxg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA1PR10MB7216.namprd10.prod.outlook.com (2603:10b6:208:3f0::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:25:46 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:25:45 +0000
Date: Fri, 12 Sep 2025 11:25:43 +0100
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
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <3f7a0972-50da-453c-a0cf-73001e9ba835@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO3P123CA0025.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:388::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA1PR10MB7216:EE_
X-MS-Office365-Filtering-Correlation-Id: 2866920b-85f6-411e-c57a-08ddf1e6bb94
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BBItLnBhYywEfBn0SapPjUHRTHHnXzorhGNuMzBPG9JUJ0KbHmjgmU3w26ge?=
 =?us-ascii?Q?AxiElFe63j7robv8mZSz0ctMuxL3BP139YxBpeDTTul7ZN9WUeUMsCHCSW7b?=
 =?us-ascii?Q?iP4VR2CAe3v6OcoQZUGDuP/6TL5L87MHis7RbYTzQxeztq7+HRDBvP890LaT?=
 =?us-ascii?Q?FCrt/UCN3sU4cIDHArK+DcID1a0Isar0Bdx0BdPBAByICRN9PWre5fRyifn3?=
 =?us-ascii?Q?aEv6Sp+w9+NsbO7An0Olug8MpI24nZLBS3dXXqdY9GcMb+f/Irs/hKp38/6E?=
 =?us-ascii?Q?dWtw9TUzwpHrBXDAgm2joYOclQnhGaHFUsTgJcBj+zganwAbjUJrqwQW/vGo?=
 =?us-ascii?Q?e0spyCHBcjLMNR/Mxn/T85gJa1lFW2eGwlP6OTffQ3RhWdZIuewNhKgEVGM5?=
 =?us-ascii?Q?fvJfX6GBipeHH7elDMyvZDWCIe1kyoXpZko+ITqKhgHP+ihQaf0KhDs30Z9z?=
 =?us-ascii?Q?+u1HQZIN9hTtJslWB5VlflnMZS5hAbGwHJ6QoHtRxKcWmund6nsIHIrZC+6i?=
 =?us-ascii?Q?+VonpfOGwAjmEFGk5nukb6NxqcA5e9UMYfPacyO8tQx5yCCdLaBrK83YcNO6?=
 =?us-ascii?Q?rD0ILoykmEH3PrLJHs5S8np/QKBefprxmoMgz21GAhisZhdhGgKc/awLVvAV?=
 =?us-ascii?Q?HSL/pj3nOl50UCTFDzeNeQimFtr9e2uktaRfJzUdAbKbi9AcautnQeRoUOww?=
 =?us-ascii?Q?DhDehd8kSPKoJBkf6ySddyT/drQH5p5H7R4DCWm7TuJ6R8M6Zm4QLwRaBjdr?=
 =?us-ascii?Q?m85h6hYCogZSitrb593fNHNVJWXEqtn56p3TY84rfq0efY3ZPIbin7bHDnxk?=
 =?us-ascii?Q?HTiFUf5zUov+hPh4ake9uXoxKMOkgZEqU/TjOru5eur1+IQtpM3DwQlVhFnQ?=
 =?us-ascii?Q?jfRbEQNsPLsHy6AYkcRTmDdH3xsDEFpgKcrNcfuhhMP0w4pYsoJi6wCHprC2?=
 =?us-ascii?Q?Cmm4ft1IFFZfdxlELXIe5hGMdceB62HDHhufmlnJERitk0PMs1E2oTkI4YCo?=
 =?us-ascii?Q?V3hsyRjVtj4xsoXH2bWRlV/BNW93lEVO+36u/9NgvlXUBkU/ZF8lrrlArj4e?=
 =?us-ascii?Q?bEKkBK9oSFCjpvXMGRzDT5ynF16NBrWLZjLEzqGqKcOycTbB2uc6VPJIs2OH?=
 =?us-ascii?Q?EMZLOS7rbI+/ISnRdFt2KryelVGN8r9D/rwnbn0SWPurUkSlyzZQohCG4IC7?=
 =?us-ascii?Q?IKxTr4h1E9KmX39cmUEy3lRQSKO/JWYNzz2SOB5BBsYpBd2EJGw5tWcQF3gO?=
 =?us-ascii?Q?yrLVWdXNoPHlSABlP29ulKdYnDXy27z/XqIGiRiJmrFOFLtWg3iaifpY8x8Y?=
 =?us-ascii?Q?N7BQW6hWo9a8UDzebsTb2O4HGz5iOQYLbl1IcAu78cH98mRwD/O4j/Tq5Dna?=
 =?us-ascii?Q?lBU/KuHDviOdsflhSrzAbLkbd0BaAaS7VLDKx3vCPgY21QfrZRMZPFTP6NqV?=
 =?us-ascii?Q?asjJIuKYYGA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?wz609W1lCC8XdF1vwqTsWnWUrrUtiy2uSoTFb57ZMUHEwsvFxHWVxo0Pmazj?=
 =?us-ascii?Q?ALAu4VHuet4I4uqpesBDv36jqQh3DYk07ps57ozguLtX0aB7vqMQsXf/ykB7?=
 =?us-ascii?Q?rEvYarj9TN88IphkUeEInLsyd6yGnWyAYxOjIwm0NhF8i722x0YyC7Xp7fGa?=
 =?us-ascii?Q?TSp3PXQcg3mR+85H7X64xBb3NR6BdzqUF6pjJblHhZD/D+n/0T7w9NUCRdnz?=
 =?us-ascii?Q?cLvbvXCa+lJmvF3nwl2SETDJ6svb85SM5KsL5o98Xv9gGW7Xv6ThVa+qkCzP?=
 =?us-ascii?Q?FtM/frbWnG5wPHYSp2P7z1hlmbBfFbnEtqOnu2G/1l2yDRCuCNUI8BxJmCzq?=
 =?us-ascii?Q?bidMZY5VPSYyUKl0fw6CnEVUlrDrcetZtWLadhHjUzHdQMOCOCtcPBifO1mm?=
 =?us-ascii?Q?aYsbtjhKB6uwuU4oXB8L+fJMJJ/VwRCvNTVjXG3Z/CilBdHiG6ZYMBZlwkD+?=
 =?us-ascii?Q?tHVbBbuG1ckQPLBUInUSD0fCCa6q3jzplCyJ+70Nro1bQPwZX5c3eD+7InHy?=
 =?us-ascii?Q?hD5QyEvwfGvr2BPv+eMlUFRdYlsN3MN3JUuS5LqF+Lo6Ak5dBeLUhKHNy6yl?=
 =?us-ascii?Q?BNF+cpnziKRfxa97xVXPCUsRmfi7oqxFtbTZ91wNJP2kPY15UrtE1K1PviUl?=
 =?us-ascii?Q?/O95gH20RAcEQYkpjrjO6NpMI+JqO0nB5NnsoUT0/Lqe/Dj9EaRfk5ipUwOu?=
 =?us-ascii?Q?QqOYdlBHp30krJ77oQ0bK7o13DWueIH83vpwLYTNpyW8BIbW+Njmd0OYmHbA?=
 =?us-ascii?Q?gU4J+7dhaEIKL9p5OUJuiwCG0iDs6tqY08Q6HlwvlH4VKUScv+NkMZQEN0/1?=
 =?us-ascii?Q?Be288OocO9eZ3rswa18oGgVXxetmuKOpr8Roao1t2ZtsymhN07EXAibk4JRu?=
 =?us-ascii?Q?WoxMMv6G3SVf3EI+pk9M3MRXMNH8ZQ9b245wYChcKLDoiANCBpgrmSicy+4c?=
 =?us-ascii?Q?cW8ffnFgX1aIxTFRQg/vONeV+NmillO4IZpcJRdTN/9x8o48PXoz6Xdyuo3W?=
 =?us-ascii?Q?u66m51JlOR5ICSimCPd7Vt/x3ZHZMN+hykCl5Tjx/W4h9L/MHtaqKUgEEjXD?=
 =?us-ascii?Q?Q7zphX2E0v92fvgrDNsimdCPLtOPOAymTcu3WvEgJ8NUeIJ6n11RIgZKJBwg?=
 =?us-ascii?Q?scQUri7p8USruzUvfjybR7Hp7a6nED3PGK+RJb3XUcdW7KOv7ddChOMMjnbx?=
 =?us-ascii?Q?jICHVcjKHfSoa63o8isJCi62tCtOeeLzr1X/i/soqfppfkerd4m01s6r1VY/?=
 =?us-ascii?Q?C7nrXKrzToCv1RqbLq8R8DgXKiwMU1OLBmHBk+5cmZp3B9t02Icz4bxiHbr3?=
 =?us-ascii?Q?0XAi2O8hrYLtId9wU+qqPRBSiqk6jYPrs2gVWEU/n6cY249FyraVJVP41Jum?=
 =?us-ascii?Q?VgAh+o2ttzRxTYYZOE+CRMNi8gFzTFUbt5zzgj+jdl9xovISdVLA5779e9do?=
 =?us-ascii?Q?uSH+pKi5hJVG595Ir0/boXNQD1MzlEfHGWy/Ote95JB9crcXaE0FP6bOR3NJ?=
 =?us-ascii?Q?Z5kqWHuYRqTWkwfzIJyNH0HNjPoEI6bwbuFmbKKd1aDj02cYckhq/GIdJx8R?=
 =?us-ascii?Q?zlBKM9RG2HjjXknS+n7u+xPHGY7sVq/cZC/UTVsyXbaJzCaZWPJdxUQ96l3E?=
 =?us-ascii?Q?Lg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6bF5qBhYAelGPtamrSatvkR5lq0EgBKd/miOiVS9nY+pkq2JpIs7MNC8LR9Vmcyagr2G8FcyjHYoHg4S8/zsvlvrOkSyj8nzXFCnFKKl8j3LOQPt48McVcdWKu5m2sz+rRIBxrKpEIk3PxDUKoK6jyEydTVEAwEuV1luQIB4FI7jZCLi846ByV7JmDHi1O5XRGgvOuvjwErs7LhbL3ue0f8xq5fBqg8rjEa9/xixoAdXXc6lmWHGrreUuLrs0SNZuKHAv4gXKRrmGabbhkUw8wmV87Tg1kcgbRzXPs6elDYKO8zC/Wwpr7/nyQMP3hQLqOCv4bF4xA76mj2k216Kva6TW2sZelZQrIF5qXVoteiv3FSkouX9rnN2aUqKCXTpVCRTYsbhaHxYpTqbE2cNlnz8L7h8Gu2kOYKPnPdYMjnZODIKE1Xbr3NDwHbCp7DA76LS6A4tySONBegR8GlG6AkcI16I0jAa+cpHcW1ZIGM/cIIuKiZjrAgnKM9/HDpdif0ekJ/UTfAwecfMBQ+lIJmns0/oG/8m7YUNRATdIhKDCh9NDto329ytTSgWN8nxGJt9cTJhJfYD9KPiC9pWgQCdmdlh7xsDwtIlaOr9NoM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2866920b-85f6-411e-c57a-08ddf1e6bb94
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:25:44.9940
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZTP4GC9QYGmWT6TIbnkIZjCizvS87KGY0fDEZKDrT0/9MpCbTdUurg4GTclK8xZviQhN5xxkwi7lwaAohhg+HPxMSS4O0ipnTwujIcUUCQE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB7216
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509120098
X-Proofpoint-ORIG-GUID: _Q-aF0R_on2GMZpG-_PrXWqsIDnFgg1S
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MCBTYWx0ZWRfX9ZWcDupAcYBF
 599Sqhc1WQmOZyYLnYu4bx0kLuXVS/ByS0qsW878t8fUql4gHt01zlZ/FMDgfUGMPmo4Fg3osXv
 lqTJVggz86gAMizL5qLx2Ozv58Pyx713n7lr4R7kuV3YpAgo1lC/jueJ8r4Ya5+2key8p1CVIle
 ABLBt4OjwKK+zmESNJ64XHOkXBC1pvTzbbI87tynQ9VO1j5XyjmCOUciuNnKI3lT4Wc2eUkIWwl
 uZJqFtJfd0ucq/4vGq8lSFaW9E/PWW1Bg/upvPP4Ejg98Css4EjiLIttaqC/UPqzziXTycwdOWN
 sR/X2fTTbCAAMS2jEp+/03aLDqAwtl3RAPs2764BEo3tyhKZuN8SSfPksV/TjTSmv3DIK+lRNkk
 98EFxokM
X-Authority-Analysis: v=2.4 cv=d6P1yQjE c=1 sm=1 tr=0 ts=68c3f52f cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=vyXzzD44dxrMwQyxdGUA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: _Q-aF0R_on2GMZpG-_PrXWqsIDnFgg1S
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="imMmYnD/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=jOZFjdcr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Could you apply the below fix-patch to make nommu happy? It also has a couple
trivial whitespace fixes in it.

Thanks, Lorenzo

----8<----
From 94d0d29ab23b48bd301eb7e4e9abe88546565d7a Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Fri, 12 Sep 2025 10:56:39 +0100
Subject: [PATCH] nommu fix

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/util.c | 68 +++++++++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 66 insertions(+), 2 deletions(-)

diff --git a/mm/util.c b/mm/util.c
index 11752d67b89c..f0730efd34eb 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1302,6 +1302,7 @@ struct page **mmap_action_mixedmap_pages(struct mmap_action *action,
 }
 EXPORT_SYMBOL(mmap_action_mixedmap_pages);

+#ifdef CONFIG_MMU
 /**
  * mmap_action_prepare - Perform preparatory setup for an VMA descriptor
  * action which need to be performed.
@@ -1313,7 +1314,7 @@ EXPORT_SYMBOL(mmap_action_mixedmap_pages);
  * it wishes to perform.
  */
 void mmap_action_prepare(struct mmap_action *action,
-			    struct vm_area_desc *desc)
+			struct vm_area_desc *desc)
 {
 	switch (action->type) {
 	case MMAP_NOTHING:
@@ -1342,7 +1343,7 @@ EXPORT_SYMBOL(mmap_action_prepare);
  * Return: 0 on success, or error, at which point the VMA will be unmapped.
  */
 int mmap_action_complete(struct mmap_action *action,
-			    struct vm_area_struct *vma)
+			struct vm_area_struct *vma)
 {
 	int err = 0;

@@ -1424,6 +1425,69 @@ int mmap_action_complete(struct mmap_action *action,
 	return 0;
 }
 EXPORT_SYMBOL(mmap_action_complete);
+#else
+void mmap_action_prepare(struct mmap_action *action,
+			struct vm_area_desc *desc)
+{
+	switch (action->type) {
+	case MMAP_NOTHING:
+	case MMAP_CUSTOM_ACTION:
+		break;
+	case MMAP_REMAP_PFN:
+	case MMAP_INSERT_MIXED:
+	case MMAP_INSERT_MIXED_PAGES:
+		WARN_ON_ONCE(1); /* nommu cannot handle these. */
+		break;
+	}
+}
+EXPORT_SYMBOL(mmap_action_prepare);
+
+int mmap_action_complete(struct mmap_action *action,
+			struct vm_area_struct *vma)
+{
+	int err = 0;
+
+	switch (action->type) {
+	case MMAP_NOTHING:
+		break;
+	case MMAP_REMAP_PFN:
+	case MMAP_INSERT_MIXED:
+	case MMAP_INSERT_MIXED_PAGES:
+		WARN_ON_ONCE(1); /* nommu cannot handle these. */
+
+		break;
+	case MMAP_CUSTOM_ACTION:
+		err = action->custom.action_hook(vma);
+		break;
+	}
+
+	/*
+	* If an error occurs, unmap the VMA altogether and return an error. We
+	* only clear the newly allocated VMA, since this function is only
+	* invoked if we do NOT merge, so we only clean up the VMA we created.
+	*/
+	if (err) {
+		const size_t len = vma_pages(vma) << PAGE_SHIFT;
+
+		do_munmap(current->mm, vma->vm_start, len, NULL);
+
+		if (action->error_hook) {
+			/* We may want to filter the error. */
+			err = action->error_hook(err);
+
+			/* The caller should not clear the error. */
+			VM_WARN_ON_ONCE(!err);
+		}
+		return err;
+	}
+
+	if (action->success_hook)
+		err = action->success_hook(vma);
+
+	return 0;
+}
+EXPORT_SYMBOL(mmap_action_complete);
+#endif

 #ifdef CONFIG_MMU
 /**
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3f7a0972-50da-453c-a0cf-73001e9ba835%40lucifer.local.
