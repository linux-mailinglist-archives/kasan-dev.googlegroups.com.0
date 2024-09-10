Return-Path: <kasan-dev+bncBDN7L7O25EIBB2OZ723AMGQE2JXABZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4008A972711
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 04:20:27 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4581b5172a6sf69494831cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2024 19:20:27 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725934826; x=1726539626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KZYP802mjcVyH8OFfFCLkGVDUgBR2ac0TrEbLPeTI14=;
        b=WemKs/M9afJk30bSQpgsHK1MdiGiPy+wAkQDCa+VznzyIgp0ACWDHYmwiHNYlHNhWz
         8UdC/1WVtEeOmQNolVhyz4HmFZeiEg4SZpgk+QyDMQ/WyqSBkBp6BuI4WjbpRcAfAekv
         6h23QQarAAXzPFriFwUVqJt0MJ+7ThRHM53ljA1gw8D04Fxuvllk9Y+Fgy1jesBVe1Hl
         T2ZYg3O+nlPJUGuNK71Np9XRz70mv2yhxb/kck9rmIXcpA2EsQXCnv1Kc/9dKnuKqnAL
         BE1/MxjNb4GMpEuoMkGvk3/k1y+sudORrAK88YHAvV175A4KHdp5QdMBZH3YhOJmKtXM
         DXPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725934826; x=1726539626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=KZYP802mjcVyH8OFfFCLkGVDUgBR2ac0TrEbLPeTI14=;
        b=bOwSmhYmNO0Xqr8whhNO/0RxnNtK3rv7vGgvhNzPNjAogvMWxABguPVSetYekBV8x3
         +Ahw0Do5q/OK3s46yX3RKrOdj3WUoO4P5d19ErqqQBkTLiKpADZ9hZs5SBGS2h+11Hn7
         WlVvheqL6GLpKvBX0+NRED6y4T1D45hqKaL8I2/Ryq33/m+uTtDulIK3xgUFd9s8yEw4
         LbtqQOYAf2tVwSZoXnS5Y4xgkSl9eh5P2GWuLVqJ7/WD8FYN/ffQirzZaj9RTxMj3IHz
         9CvhAXQPo+qh0TDd+C+2scwWaCRgZE394gHYM5xT7qGgS1ucpfL1X4hhwngzlT5DGo5y
         BHhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsHiLtUNCOGjTR4iFBXBP/FBbLEgqRfTnq2Y5nbHlQ8MaqImFckjpHFAhlntwZVXvYanARjg==@lfdr.de
X-Gm-Message-State: AOJu0Yy1xWucNe6pqCrTK2I8RjHRWBNAvNM2+oH9RlJhbEWwIEZR6ssu
	CuoUbgQFe7YezvFmjRv+WyLOnXxIXvyNBvJefS8N1FhnXNEP0CP8
X-Google-Smtp-Source: AGHT+IHwdHfqTHKtGvuSzJm0lBf0gpVTWVwyTfldiVYU7Ym8coAXN+pN+Yr6+RacJocn5X9w0GzyBQ==
X-Received: by 2002:ac8:5742:0:b0:456:802c:a67e with SMTP id d75a77b69052e-458200cde45mr168649601cf.3.1725934825831;
        Mon, 09 Sep 2024 19:20:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1994:b0:449:2608:3035 with SMTP id
 d75a77b69052e-4582cfdb5e9ls41025681cf.1.-pod-prod-01-us; Mon, 09 Sep 2024
 19:20:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUs0Z1/KGu/mmFxCpshPwuyZgxWWxdQ3EI9m0bMu5TINCihkz2P05U8o8VMbytwunfmmRPaHCcQ23g=@googlegroups.com
X-Received: by 2002:ac8:5742:0:b0:456:802c:a67e with SMTP id d75a77b69052e-458200cde45mr168649251cf.3.1725934825100;
        Mon, 09 Sep 2024 19:20:25 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-45822eb9ce4si2385641cf.1.2024.09.09.19.20.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 Sep 2024 19:20:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: Yb485aPVTt2tbLeIM7oOzg==
X-CSE-MsgGUID: igz8YWAwRwuA5HPpCEUJzQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11190"; a="35327227"
X-IronPort-AV: E=Sophos;i="6.10,215,1719903600"; 
   d="scan'208";a="35327227"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2024 19:20:24 -0700
X-CSE-ConnectionGUID: 6l/uB7ICQu2ciNKAZsoaFA==
X-CSE-MsgGUID: spaOKUCdTy+eIja84VGD/g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,215,1719903600"; 
   d="scan'208";a="71837569"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by orviesa004.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 09 Sep 2024 19:20:24 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 9 Sep 2024 19:20:23 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Mon, 9 Sep 2024 19:20:23 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.172)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Mon, 9 Sep 2024 19:20:22 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=T4acKEh0+asrtOf5iINE1Vl5XnnhobfyZ14Yn8M+aQQPGBntoQNSU6+O7pbh/7L8X3UyhEAsBfYWEgNRf7lNRiLjg8RUnq3Qcfg9Sw1VnCgR1RTOLjPQjH38W6cHq7guL5tM4B2NdFYYwjQQp6g7HvuP/Stt2RSIcpt6/J9GGwdZSdj4qh0xy6yKA4Acgwmb1EdsMk1+e9l+0yOCS51j0Z1D+VNko/l4FlkvBgWeOEC6vdjUlnw/PeduXfelkbI6M9WKyJ7/cTwyefK779Py2v6Zqvwpwr5d7QhI22DshZ8kFXDhCOI2otemknE3kqj9lqvhOotpTveMi3O2uhyKPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ybNxLYB6lun2oidHqYglPQBpDDUEjVegsqL9Ua9iXeI=;
 b=n8DJor2I/dDA3t9O4xAROFfA8lnzApMLzZAv3fXIqkvK+ysDPWXdSFP3v+aTM97jV1OU1eTIZMBnFwKv6Jdm3sFCwYjsu1+JGU/s0ez3YpIw0uXF9uWhpiW4q+WD6d3dToi+FWRdiNpul9O9WMzY4kx0pGpE+tw6Z3pE2Mp6EIju7ljc98l0K7wWpP9JKf8GZ7c01dwzwS1R8dyvvx1p7mW5/UaXN4MvBcS4jxRIoByCit1qvb1aCV7+AzGs2Q/C9ovnk1rLaqU1I7rSzPil4+E7NhTQls4UGn3TLUyU70TVBHxZ+xT9zFIxKqjdVSyx5lYPG2GH9V593JIVm+TZFw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DS0PR11MB6397.namprd11.prod.outlook.com (2603:10b6:8:ca::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7918.28; Tue, 10 Sep
 2024 02:20:21 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%5]) with mapi id 15.20.7939.017; Tue, 10 Sep 2024
 02:20:21 +0000
Date: Tue, 10 Sep 2024 10:20:08 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, Shuah Khan
	<skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, "Danilo
 Krummrich" <dakr@kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Message-ID: <Zt+s2J87hZ7CZjl9@feng-clx.sh.intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
 <edd4e139-363b-4a8a-a4bb-b5625acac33f@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <edd4e139-363b-4a8a-a4bb-b5625acac33f@suse.cz>
X-ClientProxiedBy: SI2PR01CA0032.apcprd01.prod.exchangelabs.com
 (2603:1096:4:192::18) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|DS0PR11MB6397:EE_
X-MS-Office365-Filtering-Correlation-Id: 8c5d8396-c7dd-4497-b7f0-08dcd13f1ec5
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?uMzPxlrvrRYKSOs+YrFPNX6kn3JFtcHRuR1lY4/d32MUKhjJhbdGJ1S3YBG1?=
 =?us-ascii?Q?RWiEcYJom6airg/4hqn34X8yOEw1c2jxkRCzUTBLWx5dLF4J22AuQlCl4AX+?=
 =?us-ascii?Q?3PTMDQ9FcyRbBbF7b2H2AoOONnkpSZhkJal05CxOM2/kyCRSLaoDXkMY3NND?=
 =?us-ascii?Q?bZ/Ri3yG71Glw7K/LGGLdVVxsYTFYiRlGLu6HUnInufsRTSmNOCkIP1ZpUzR?=
 =?us-ascii?Q?CHvyyYO1pBHSjyBbsqovgYnyPZ3lp14k/PwOYK0wObjkJdyeG2zNl0NGv3t6?=
 =?us-ascii?Q?mHg2qMw1kimiYv+/SsKgTCAygVjcokQqelHX2UzABz+zjJhp9Lc54drN+khx?=
 =?us-ascii?Q?nQifsO28Jl6vIob9+F/HDsRcAYDolInreSZj8eElJKfJ8x+rHg0/LhiOUQ0l?=
 =?us-ascii?Q?x67aJqT+jXACgLuInw9FDohze9vnna23cHUTIA9u4RtAXvQVieqdPk6VK3BD?=
 =?us-ascii?Q?sW4hEfU+pUOpA2fWSHPiEyBP3FsXg4BnbQ4eaivdz2uF5FdzTLI96i2tNmBI?=
 =?us-ascii?Q?HUVJzqgqpMvNyGDO+2HIIuYKluGB1pwCYtpxjLeSQRThYGl1QCt5LGwmH7j+?=
 =?us-ascii?Q?Vzo366LZGH2Pt5W6f5DMIgr26NrXiPJHBFeyusm1vRtamZqrhqGq1vzhPeC4?=
 =?us-ascii?Q?0yXFoYyACNonmbibNlFS6vKZ+2V8KtcqlmyIsFvQOLbNp6DaS0R2+yKVWBre?=
 =?us-ascii?Q?vk/CwFNvrahPM/P2W19I+8XZ6ra/AhgVWaCOywIMXXlaX2oeyTOHI+xBoyy2?=
 =?us-ascii?Q?3/y+IacxoHNBPCAuJw2ta4JgXKTS+z32TUVBfON17lGP6FRrKp/0SeFEDZVZ?=
 =?us-ascii?Q?C6oAVoNLj+T3jHT5TwmZNvi5ygWEH+mJ8PsqT7Z0Q154AY0/jMKPOiO51tjw?=
 =?us-ascii?Q?0C536fXPNGtejQmFFbTECdXAVtZr0pGyZEpIiviREHPoukqcWc6HULTZJH0p?=
 =?us-ascii?Q?xLXm8IIJZgaIZOqtVxAtMymxJYyg+0LiaCRf7hjcDSNDlzrFkgj9DrST+wRu?=
 =?us-ascii?Q?RIeAbLfx1xWLF0j8bglDj1CGEsA8b1WlHsy9Ryrzm4BYq3XjFv0spzw3Ebkl?=
 =?us-ascii?Q?K7TmRjBsGv8nvR+6iq01hiLWjscPxyOkgWxwru7g6DO3aXv3pNpdXfkpXq8u?=
 =?us-ascii?Q?yEHqvbPKmnlHT4aoSidWgBP29RgRmIGkKJrxgEbwRHC42eQECC2MBiKa7YIR?=
 =?us-ascii?Q?rcpgtQihZsjqc9sSOx4YLoopYYeFwVRXZIjgQniIRTuZqb6iJeAI2Gz2n39/?=
 =?us-ascii?Q?ljt7Y0JPnGQiPNl3PbBZpXmM8Rr2sX5++sBbdqSYTayVHdzFvpxktepFXNQc?=
 =?us-ascii?Q?F9B0exMgcTdtxHfQ8AuKFBUTyUZeCq7hLea4ueN7FmNG0g=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zWG+ErP+WGjFpXNGtb9z7WEwB7sKeDUoaqXkqSkya/MVqwWQycF9E24yIphf?=
 =?us-ascii?Q?vBqq7CEaw2imylx/zAu0VGLfBujXiJCAhjBp3i+mNhcPZ9IyBW0iW/sUDX4N?=
 =?us-ascii?Q?JKPmtvIWwva6dLJ17PC5Ezdbq5YhdtwTliOhQ2QLVuG3Vc1+baxeextw3gPB?=
 =?us-ascii?Q?Ubi01UYAKDraikyGxepegrfKxGEFAf7OK8iQw6zE/ZqOKvVrx2hR5q7TWNfi?=
 =?us-ascii?Q?2TVB1mFJ+fQVFriZqWrxKd+0mMgoHyKbKiaoPY9U08hTJUmXuPbEBC5YItGr?=
 =?us-ascii?Q?lR792GOTljkhIiMyB2dCC/TEOdy6u/cy10udeyNr3DPJNY2ITEjAqAH2mko/?=
 =?us-ascii?Q?DAMPZUZhPFRDyx9dCadTgWyAkt6ZR/l2RY9rQnH1rbqC29R88fOr8SU/Dutl?=
 =?us-ascii?Q?WT8a58eFyKkXKeg10pjqjZLssOXkRpySOeAlgZqmYIVLsDzXZT3qe8rJXon5?=
 =?us-ascii?Q?dsePEOfMX8B9cnwmKDoU07VzK5WOxaoi4I87XlokK2hHvDEmjNInChfLz/9N?=
 =?us-ascii?Q?iSix0gHbdXWt0mMYEYijrueWq5i5b7KU1R1x305bDZkJufnDMNwNrtKfEEur?=
 =?us-ascii?Q?HpgdDiC2wV3EjfaxgPjYZa+HgibjSOiH/LPeuauhTWtsp2DRTOoMp+O/EhGy?=
 =?us-ascii?Q?dMNX2HA2sUCG3eeQK6EK8qVWxmkmcii7FmZx9NMZld4cj4h4e4w09sKL8TB2?=
 =?us-ascii?Q?WQ9tdRCA2eMRDw+N3+S/cNYVgZbtpF0QO77edoTwkls1FwGXMz++AUu1v+/2?=
 =?us-ascii?Q?579eq2jfDin/4U+UPsoI3L+b4BE+kDvI96b7b0+rvIuwSE7g42ZIiRMqv+/R?=
 =?us-ascii?Q?qhLWM425jgjfDcSQBBiTiU4rZ0hXVhZ6f1gzOeUeu2g+kL3DOfaM0ozPPRYU?=
 =?us-ascii?Q?R+RC7iZ887MI6IEfbJ1YXXvrrAoYGLlJJD9I50XOEvfyyt3tUlkdqLf/0SSk?=
 =?us-ascii?Q?rQrizDd7wvxJ618XKmlQTnQ5R3TJcGQf2vUFPhWoH8uXsfILjds+FnXPsMH7?=
 =?us-ascii?Q?M7Sa8yw8jZG+rLi+dLYGGFD81EtlLoH2bp8ZqfCTrupCnZKlChZNMIRHeX3+?=
 =?us-ascii?Q?28p8mL9AO8bduysZ73IzeeeBFlVAkuCoe4WJczzTjgvK1SZxrcYvgKUcRCvL?=
 =?us-ascii?Q?9n8x/mFNl5fyQ1kt7+3Bxii63/yoL15EoAHE1CtwiQRshnPyPFOqiPTx8zIT?=
 =?us-ascii?Q?V+mLY47cIqQxWS7REN52foEQoZ+XXuh1x0dHXjnYGd27j+ZI35SRcC5focro?=
 =?us-ascii?Q?Tkzw4/rcHrofj8k9fqNxMbDt5WIJCzQEB0T9bufLHiPnLSZ6h3hm5lV6keUM?=
 =?us-ascii?Q?4QiXMf+6+LMOPS+8Tj4yCQS2oGAM8PxW087FcM29RZykw4+Sa26jKgQiQ9ei?=
 =?us-ascii?Q?IzPLzMkpfdBxLwrXoM9IHYr+5HvSU/1mD68/scapvf6ensR/8ywkCvOhqK2h?=
 =?us-ascii?Q?LhXknHyw1GRAtDqKyB1rmCImir4AJp2ac4wMT/ZKCSt8hbD90cM5bgqsQa6Q?=
 =?us-ascii?Q?qciYE5S6Z1qfF2bJoOGJBAt9zTNo+2ole20Nv3VBFLcLr5lPt50sIgONG1DZ?=
 =?us-ascii?Q?qEfvbKN7XbDphfXkrDXcl3LQeYZRDHW1rznXDVON?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 8c5d8396-c7dd-4497-b7f0-08dcd13f1ec5
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2024 02:20:21.0343
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VrkGVWnRBLwR9qW8I0kPLZ4BPszaQdujEq4jlj33kBNVwSX7lAwh+CkHrPthA8p65kgx+IrPdyfuS5CydoS2Qw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB6397
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JWEzfhpx;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.198.163.9 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Sep 09, 2024 at 07:12:31PM +0200, Vlastimil Babka wrote:
> On 9/9/24 03:29, Feng Tang wrote:
> > Danilo Krummrich's patch [1] raised one problem about krealloc() that
> > its caller doesn't know what's the actual request size, say the object
> > is 64 bytes kmalloc one, but the original caller may only requested 48
> > bytes. And when krealloc() shrinks or grows in the same object, or
> > allocate a new bigger object, it lacks this 'original size' information
> > to do accurate data preserving or zeroing (when __GFP_ZERO is set).
> > 
> > And when some slub debug option is enabled, kmalloc caches do have this
> > 'orig_size' feature. As suggested by Vlastimil, utilize it to do more
> > accurate data handling, as well as enforce the kmalloc-redzone sanity check.
> > 
> > To make the 'orig_size' accurate, we adjust some kasan/slub meta data
> > handling. Also add a slub kunit test case for krealloc().
> > 
> > This patchset has dependency over patches in both -mm tree and -slab
> > trees, so it is written based on linux-next tree '20240905' version.
> 
> Thanks, given the timing with merge window opening soon, I would take this
> into the slab tree after the merge window, when the current -next becomes
> 6.12-rc1.
 
Sounds good to me. Thanks for the review!

- Feng

> > 
> > [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
> > 
> > Thanks,
> > Feng
> > 
> > Feng Tang (5):
> >   mm/kasan: Don't store metadata inside kmalloc object when
> >     slub_debug_orig_size is on
> >   mm/slub: Consider kfence case for get_orig_size()
> >   mm/slub: Improve redzone check and zeroing for krealloc()
> >   kunit: kfence: Make KFENCE_TEST_REQUIRES macro available for all kunit
> >     case
> >   mm/slub, kunit: Add testcase for krealloc redzone and zeroing
> > 
> >  include/kunit/test.h    |   6 ++
> >  lib/slub_kunit.c        |  46 +++++++++++++++
> >  mm/kasan/generic.c      |   5 +-
> >  mm/kfence/kfence_test.c |   9 +--
> >  mm/slab.h               |   6 ++
> >  mm/slab_common.c        |  84 ---------------------------
> >  mm/slub.c               | 125 ++++++++++++++++++++++++++++++++++------
> >  7 files changed, 171 insertions(+), 110 deletions(-)
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zt%2Bs2J87hZ7CZjl9%40feng-clx.sh.intel.com.
