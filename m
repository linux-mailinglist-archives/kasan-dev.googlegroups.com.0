Return-Path: <kasan-dev+bncBCN77QHK3UIBBQP47PCQMGQENIBKDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A486B494A5
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 18:03:15 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-745a0d69fb2sf6828624a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 09:03:15 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757347394; cv=pass;
        d=google.com; s=arc-20240605;
        b=LlOc9Qyoz+txiNVCcfPuFssm0YR1dJiOFosW8AUvIblvYZaFpHzEf7FpzYkSMOWs0o
         Mv6Xc80rop5rzfDNoWsmupfo1MOtSLz/Td/Tm7Z3sGmRGsoUWMgCNkGwv570nIWN2BoE
         vVVPn/f5JNUes9FPWQWEaW+e/CAoN850eaeeUw/GzjzmzpOSlPw0AnBL2HaOcZ4dF7Ns
         MbC/qJqFXd666/QDPsZvMeAU+/eKPI+IPZd7JPaJIaN1DPUUoqEStyWJ6YEonfaSRXgO
         YiDsQ6H1c5GamDM7tmK5lDizCZgDWOQaHVFbWjkN+mZMu/29iyUl6wxA+iNgwq91rjvF
         AFPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=E955exvbCHBUYIhmMVhuaJ2/iGMKxCki0yBEoDjC5Xo=;
        fh=hSq2st96YbrC6wVoahjo1gANrRNH70HZI0la8xoDDBk=;
        b=KjfP+bBaXunVVaa8DmhjNpfIGeEGy4J0C8rxssjnjMqvd8YWCaOAifSxzjXATlVPHF
         N5hd7XeMSpGM4FLhk2Vf9Xht97HUvi6MM9OmV5OT+QuIgJdsPhBnNVrCzBPrQbM/W2iu
         riEal0GxSXFhDGpqxw1neEiqeb127c5S4SMXDo/a4oxGLD0/vimVQRCBTMSKhbhUuecB
         /6BLsAyS0VXo7e5Zbw3rqTOiAoQSCWp1/ZIZx9gq5r4GLarqwBNHkmadyLQfzf3wicXs
         XeCaCEEMtuPCDu/JWFh0WW5f7FDz9QkM4pKI3ioDIG3l+KONuOuTDC29If2umr3uWwmc
         verQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=pHEY7zKD;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757347394; x=1757952194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=E955exvbCHBUYIhmMVhuaJ2/iGMKxCki0yBEoDjC5Xo=;
        b=PgxCCiVdQu50ZIZYvS9RnWwJfEFGOzy9vv+7zFC7yVsFTHwolD0MHps7ks56a7cE+g
         WKqqy7AKBGVw/Z46d2gG+YTb6a9g0RRerFgFAaH53sBZhDXLv5tm+uClpLw+my4eKYsH
         TwrN/dUC2KioMsxGsz6wYWl79RJnT8Ul+CPpIwQLj34zcGoRgTDKKeEQG08rsqpBZX2D
         wPuc/vgTUalVJG8gPMTjCCiKwLViuN8sF2228rnsczZ9xQJ0VJ3gtTCFt5muCbCD/va6
         TLfh6sitlyjZnNl7KycP0I2JxSmWY68xzM72UBm+wvrCUNIYDuGaov0dk66jJraFSwbo
         lJJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757347394; x=1757952194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E955exvbCHBUYIhmMVhuaJ2/iGMKxCki0yBEoDjC5Xo=;
        b=wywlCsUTgWAfO3KnHBmOkEgWyuTpCebhZ07APoc/GttrvEOSVTVkm9x4PQCJ6m3Whs
         Zt2f86ofmBGbM0yYuZI3msRRj95DHTM5dR0AdxUAviGBruSF7ETfpEguXHne3H7bxJc1
         REw+92vWuzkTH5UH9lqkbnvtea1Q4d04YCr359i9Nn2bFsq+Rne/BM4YKjpPqySPJ77V
         eK7ddnotgMSEvaJM33F6bs8lyYXyI0ZJt7XYNMc7sKRB0bO35jnZn5nX0saMqIP3AZ4Y
         KVZS4NfkR1WhGLcnkNQQbsKLKq+wjwpbqoNG5b37llwA+mO6K4BYupamhmdYQCjjKc9+
         HYtg==
X-Forwarded-Encrypted: i=3; AJvYcCWQHldR3U3uSDaXs1HzjwBYpMd6AMo6b5ehO2Oe9L6VaQE0+7pRH/2ZGzo2r1IikGXGfEqjWg==@lfdr.de
X-Gm-Message-State: AOJu0YzP7SlD2YCmaisF24xXEn6h7Pc5jmmtWe0/V2wcF5M8jU+zzjMe
	kd/95rPq/DA6AWsf8C8VSTUPEdrJmPk1JGDm+7rs7tQmMAUXBvoN+cP5
X-Google-Smtp-Source: AGHT+IFVek73qetDxslcEeUxvSn20UWxKkt2FKK+DTmY66qSAclfzLydDBHG0OCNuKuQbH6MoB9iKg==
X-Received: by 2002:a05:6830:43a3:b0:743:2cc:d533 with SMTP id 46e09a7af769-74c7851b7c9mr4168306a34.26.1757347393689;
        Mon, 08 Sep 2025 09:03:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfK1UcdRMyupKEQqU+2MuFbzTjmBYgqPZ3nDLEkHcugOQ==
Received: by 2002:a05:6820:4602:b0:61d:f8d4:b321 with SMTP id
 006d021491bc7-6202592fb31ls929002eaf.1.-pod-prod-01-us; Mon, 08 Sep 2025
 09:03:12 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU1fjYKX2RoZU0YZl7wt4PNisV+kSMTToVWqCJsF24pN51IFNl8fNaQf8/mlOh430wq3z/U/Ui9DoY=@googlegroups.com
X-Received: by 2002:a05:6808:1a1c:b0:438:2a49:52a6 with SMTP id 5614622812f47-43b29a133e6mr4082686b6e.12.1757347392546;
        Mon, 08 Sep 2025 09:03:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757347392; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fy04dC6SH1hfPn0hfEkcVRlSi4mpMhLV+E7FQXVo8n6uP1/5OGvYwwueXu4pfdn4Uh
         rSsbRXH3JJ4oj6d7J2u16pJwiHJNbIxa6S8b0q/AkykIFv+L1N0qxaSFx3O+08Tcgr3W
         iTySvBIMVk1yOH/P1aeJmhfO8FywIwg4xwjKLL6Bsg0aQGNfDh2K3wRMFJhdlOhpg2AR
         vuJg9Qz4AhLyb4hY2vuRj8MJD6HbzJ8lYRxInXOeg1zcdB+iswYiD7Bzs3Wdzrmn3Aun
         VmHiFYfXiI+ot8geCUab1aoBcNDyvLu0AF5NAoikcr0CwcJSfpkBbPemuFrZrnDRqCsu
         BKww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dt9aTliZZuhRAufB663nCCMSTejhkiKkCRfqIGP2850=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=GjjUPaoq7bK0wVpjWsDzSUN7eseUNcOU4Vm3+zxRISJVabLu+ISeEevViH1ZCu6BNv
         0ZXpgycmPX1CLgZXj7uPzLLtLX1v6T5eEMBvSFb7hjrYtzFVJmjLP0ccyeOI7EWlHWx+
         XOn9r2KgfDMOMAMhkNm3PDb5THh0qbpAyBNOOccijghRa/q7RlkizNn9/8sF1w9mhPbG
         YvSI1Cgpa784yKXgkPnvDLmXLOwOV5R2HoVMqtJkojF2VxKiZZpw4Vb/um4xpksQWBKF
         ZMOtAErFjhhRQZhwvVhahLsvCS6A639T4BpLeVJ7lsy/w2hLh3dOx/NMsQNXX926LX72
         Z3pg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=pHEY7zKD;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on2060d.outbound.protection.outlook.com. [2a01:111:f403:2418::60d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437ffe894acsi749813b6e.1.2025.09.08.09.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 09:03:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::60d as permitted sender) client-ip=2a01:111:f403:2418::60d;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Q00R0vvdxZ0D8Fhbc+CvT0111kr+RW98NYlUbHYS5vQaGqLHoWzXvkL5yW1kVoZiUQG0U6qE73y8HTcR/gf60UDKPcnEk3UqtbkjYY73S14ErvHf3ceHk/3nsD8hi9fu5u9YjkzcPaTt/Lu8chssk0AvgE4COd/XgCcnnxyYlYQvAAnb7+Ccdd0wkjm/WP3RGn1b/QgoANCXhUE6UkpjFM74Kfw6PjREh6lqyGmuJ9YLrmPJtnbye/udkyyTP/PtFTZDCo7QSd9d58Df2gzHMJoD02uQOy15e2BsQW/QbbndOqlqyyq7RjXIqFPyC+eITb/obMPxfyabMzfHtFnP+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dt9aTliZZuhRAufB663nCCMSTejhkiKkCRfqIGP2850=;
 b=DuASmmh6gvaUqLkCWws861uUKneJ4YVNhvg/Afmn41h2x+Ntjzm1EYtrzI7458zieeoPqPkLryi6s8jM/kBxeCF9j/PTtI7EIyDFFvHOLHWgJMNxrY6liKwG74vrlDzw1btCMIh5LHmoF0fpY1/SkhsiU5wTGk+Z6oc6e3lhMwsnxLxsK7cx8ufJlZdzYcuniT/NhCPSwEm/s6niLTJi5tZyOrPt4qS7otolzB7ogjC7ysI7gmg7/r0gRI9GZRDFRiHKZb+A5Go6EDQ90gkAzHVuqkQdyEfFoc/eeXYuEQYYUuN1zf0+LeEiFetVphKm63lv1srmv9YsOwLQ4AVJbQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from BL1PR12MB5753.namprd12.prod.outlook.com (2603:10b6:208:390::15)
 by CY5PR12MB6574.namprd12.prod.outlook.com (2603:10b6:930:42::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 16:03:07 +0000
Received: from BL1PR12MB5753.namprd12.prod.outlook.com
 ([fe80::81e6:908a:a59b:87e2]) by BL1PR12MB5753.namprd12.prod.outlook.com
 ([fe80::81e6:908a:a59b:87e2%6]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 16:03:07 +0000
Date: Mon, 8 Sep 2025 13:03:06 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
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
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 08/16] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <20250908160306.GF789684@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908130015.GZ616306@nvidia.com>
 <f819a3b8-7040-44fd-b1ae-f273d702eb5b@lucifer.local>
 <20250908133538.GF616306@nvidia.com>
 <34d93f7f-8bb8-4ffc-a6b9-05b68e876766@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <34d93f7f-8bb8-4ffc-a6b9-05b68e876766@lucifer.local>
X-ClientProxiedBy: YT1PR01CA0085.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2d::24) To BL1PR12MB5753.namprd12.prod.outlook.com
 (2603:10b6:208:390::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL1PR12MB5753:EE_|CY5PR12MB6574:EE_
X-MS-Office365-Filtering-Correlation-Id: 811f0150-4e55-4e79-a8ad-08ddeef13323
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?KKh8P+a9TrV9/bNZP3bmGQUYmu/tVxXfQkL3mUdrFuZxJ88zVPRZJmiC7CQ9?=
 =?us-ascii?Q?SI/J+ad6uBVjJtw6GaFTWv+DjDM1z0sgH6/9kW0y50w3ecvJyfruv2oZD8hS?=
 =?us-ascii?Q?FcHgKoL/DlmrmPxd4EB7XcOGOi0edlaJQxALx19rjQ2RPmEbuwaS3eROMaMQ?=
 =?us-ascii?Q?XcwxvfnH26cuK8dRGfF00N0LDORNQHVRz9/1LVbUN1L72N/S3l/q/dfrnYJ6?=
 =?us-ascii?Q?/iA5s5IQftPfBaRZIoGDXcXgUtowbr/fv9FgM+s8SZ/y/r/sib8BFPMKfML+?=
 =?us-ascii?Q?rn1Mq51Yo0T0HslDDDtyQDJuWIfb8azAQOM865XUXEFlYgb6GGrrx4ZJm6IE?=
 =?us-ascii?Q?WL+NHFgncmGZNK2IQn69Uw4JSa6T0lGTBBTRNyMiXk0pwNtGq5AU4Q3EaInG?=
 =?us-ascii?Q?URWwsyoOazZuFerSJikZnhn+DATT+asI2D5t86lqlgDzJuqYw085NKYaOzcu?=
 =?us-ascii?Q?HWdsaVycWVnk3PpAXyRPUlLg1eZKVI+c04nTfO0U9sJaE4XeW+AUUc4ysPoq?=
 =?us-ascii?Q?YS14+4La4oUJ9uSVLUAh1bsLN85E5rLkOlFU4IaBIRtg++gPFDiEncv5euFf?=
 =?us-ascii?Q?YqhsK0A7QvVK3SocGJcNg7gUCmRpL827WqoF4LwrZP2xFEo8p07PrmsFPaOI?=
 =?us-ascii?Q?efMse+MAMUxt/UqGsA2VduYGQSnhSXa86jK9mXTrXeG+cFaqy5v4dtUPUmzZ?=
 =?us-ascii?Q?rNeoYI5yLGOc16/pVKPVtEV4wTB7ers/62hMANj27/zPDMCgyyDxvlUkP97x?=
 =?us-ascii?Q?L3UE3CZX6CeTsj7dhNsSglFYMQMKxziVst6sSSzpL/vCH97b4OoHJ9Mi1jYn?=
 =?us-ascii?Q?C5JVTVeHi8Parf4rCLLw1HUVbIKBnXwJsiNJGjaxNp3FvUqenje1ZYeij/uj?=
 =?us-ascii?Q?KnRsXjzdpOjpIjt+wcevtIo3P4Dh4tzjk3+xp1i26QDepxbZKxV+2jK1JDuw?=
 =?us-ascii?Q?GeUIKyzskhpWIBHpWV1oRXp46hAiZMiCkFt9B0Dnwat1h5OVTPfRTqeCkEht?=
 =?us-ascii?Q?Nb1m+salO5yRmykN0s6QG5h/GSscd8ebpat4hafg/f+/QJg//Th2aHItXwDi?=
 =?us-ascii?Q?w+u7FLLbjMwZ9wGh5P24Q9G70nMseTerExnxc4vqeCqRRhbzT9P4FW8/p02M?=
 =?us-ascii?Q?WACdGbBWHkOheh/GFxFFBO6NksJ5zjSwNA8huuzhoG0TDzSuCVboT3l7SaxX?=
 =?us-ascii?Q?JcPRMz9yBaI53gAWLbSWbGLYWjEj9ChWfScveqPSyEpIxEhC/7xtheUTUfjE?=
 =?us-ascii?Q?fNXh5FIJ10epuMDgN4pnpbT+SjVAgOmqqiSHTd12UEaomQUbdBEWvZKrktjL?=
 =?us-ascii?Q?VcupuiGY22ukog4VdyIsUnuKsx8KXH+1kpq+7FyfjXqQfJDW7R1SLzcvehBb?=
 =?us-ascii?Q?hUI8LyUMgr2X8fdqzlZM4XFPyASZTJrg2ZSaYV849Wt+E8Fiz6sS+65ohs7V?=
 =?us-ascii?Q?4K/zF/azRFM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL1PR12MB5753.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Di7+HYoZhHLGiOzcljW44OE/k8IMzE5L8NHJubYEvzqECa0m0qTN+LvvCoPQ?=
 =?us-ascii?Q?DJGzrKTLiJAQNTFAaewrBdrushviRZyIIeUJgGuJvc1qlJGAfkJ1PFi8gEvQ?=
 =?us-ascii?Q?OwP2/fIFoHpg8dg1TqXQL8FoQ3iw45uPHX4NmfuArBkiiLojgNQ3s2IGNxCI?=
 =?us-ascii?Q?8cwzoqZiyQ46/UCx98uR8jht+oJVaQbjovpHtp0k/4Iut61meU1zRuDztHta?=
 =?us-ascii?Q?pGxxlQv/vxuqkmCIdXt8Evso6MiXxxTFURpzmrX5AfCpISGuYWihD/l7CuTI?=
 =?us-ascii?Q?kUn//E/McDsvF0EYlwxGrA/ExyWx4KAjhH65O6rqwvkvKfOjyjLfH28PDjyV?=
 =?us-ascii?Q?a2cKSsLPAXXDB3PDunAbZJ1gPz0uJ7vYbCHbhUBVn31W6teyIo+Q+z56VvAr?=
 =?us-ascii?Q?Wik+O92ECIfiusR312tm95/0qtkvV4zwd8272XCyVFB1mR1Hgt3Oj0BMb2yP?=
 =?us-ascii?Q?ZjculdsL6uvKG4VBLkonpeAPK7tgf3Fand49i3tVwwxJtZGAS8Hkw194RJHd?=
 =?us-ascii?Q?OkMsW2axpbSDc1ogGaG7I/9irWJ7SuultRqIyyXbWnxjaQzQLn6/C4JjJQ7p?=
 =?us-ascii?Q?Zt7RNmjMgRcePy2CW2N22+/A8wQazIx0pmCJDc0BbNRFiqW3dgk6/TOjSyvE?=
 =?us-ascii?Q?TGnjynoJNdO1yWWCN0XY1cwCrZSl2y5HXCgfDS/MMpZ9MWfABlv3IjkAv/77?=
 =?us-ascii?Q?MnaSo34ndYk1Y2o9iS/d3S3jqC0EvfSqj6LH2RMjmezMksLp7b7URmR16TD/?=
 =?us-ascii?Q?6JU7U4ecSpsZKeUeHroXjumhyhOOwDy7SFwpfShhZNItsa/VTsn/1WrC4JLn?=
 =?us-ascii?Q?kD91iuKCdBiZfsFRNAT9G1QUYfn6jMztlBUPFHiLKyvActrRMp5+T9W9X9L7?=
 =?us-ascii?Q?qP5maWnsbwZgf2jWu42C7EW1gAu+8qYkpAIU61wMdy37YDx3Jph+Tz7WEJXY?=
 =?us-ascii?Q?Wt0Wo4Xq7o+SFHH9sHzEhDwFrshv1zYM2S7Fre0eIi2HD7d7Xz+3yo8B0BrW?=
 =?us-ascii?Q?prd1SJ/3qxKkZOUqrxpQn6lMbzwlHnc9HRss9yzRq3AeBfOfD6CNtrjAcwbC?=
 =?us-ascii?Q?gNgJRFXteSgMQZdO3BM9DsLh7/l9yqCAXo7T68+WOJFqcelCas6HeCn6U9CX?=
 =?us-ascii?Q?j407Bb15QBzHNDd3Pvbm3v0fWjbxauaNxqXCxRDWeGHE0pdvmYegQY8x3cvu?=
 =?us-ascii?Q?XTaMFhpUUP9cmwuoTH/vul662VRuCszhow3DHgQZTU6W1yWHAGj3KcK9RMVf?=
 =?us-ascii?Q?FjHcXr4zFRs+1rRtisju7KL6/TgI9Pf/80fpSY3PIpx/eqZw3qtLWP1C81Eq?=
 =?us-ascii?Q?xIJ4mjMECxjMuLQNsLjvbUsRKizQ1VCrApu59PwJfnZn/tog76CtxaphBqR3?=
 =?us-ascii?Q?4db+cBpmROKQsoIQ/mF5qsGxbJ2cLZolnVauvwTKhHjlSD76evWpZwIjTKl9?=
 =?us-ascii?Q?U9IOQTBSa08vB/d6uhCBCGmP/dRRvK1UD2xhJeBZuPn+g90INMNGjs4Ez8Kf?=
 =?us-ascii?Q?s+xR+vxp2EK8fmfbwfLlDRIhMc4Ajz1hNgqysZVOA0tF9tcva8kvbxYtQipe?=
 =?us-ascii?Q?MCNOWtLBGUL1PhJxBhI=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 811f0150-4e55-4e79-a8ad-08ddeef13323
X-MS-Exchange-CrossTenant-AuthSource: BL1PR12MB5753.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 16:03:07.1689
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: oskmkHeAse2jgaCJUs2Yfl8HL0NEQXj+7yIdF/4uJciqoXgC3qRiBgsqz9TIjNS+
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR12MB6574
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=pHEY7zKD;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2418::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Mon, Sep 08, 2025 at 03:18:46PM +0100, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 10:35:38AM -0300, Jason Gunthorpe wrote:
> > On Mon, Sep 08, 2025 at 02:27:12PM +0100, Lorenzo Stoakes wrote:
> >
> > > It's not only remap that is a concern here, people do all kinds of weird
> > > and wonderful things in .mmap(), sometimes in combination with remap.
> >
> > So it should really not be split this way, complete is a badly name
> 
> I don't understand, you think we can avoid splitting this in two? If so, I
> disagree.

I'm saying to the greatest extent possible complete should only
populate PTEs.

We should refrain from trying to use it for other things, because it
shouldn't need to be there.

> > The only example in this series didn't actually need to hold the lock.
> 
> There's ~250 more mmap callbacks to work through. Do you provide a guarantee
> that:

I'd be happy if only a small few need something weird and everything
else was aligned.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908160306.GF789684%40nvidia.com.
