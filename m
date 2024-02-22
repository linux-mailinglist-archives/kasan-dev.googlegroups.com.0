Return-Path: <kasan-dev+bncBAABBUPX3KXAMGQEJURQ4WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 280ED85EFB8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 04:13:23 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1dbcbffd853sf46422155ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 19:13:23 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708571601; cv=pass;
        d=google.com; s=arc-20160816;
        b=LzwA/nD+YXKeeEIx2sdi/abyInsy7YFoL4/9e7UUfCGe72VGvOPmxRSHJTZfkyOEB6
         uS1U70uRvioXjO3tod+wpXDEji2hQmZk/hNSyRyjhrhNs2z+Gs42gY8z8ogWjKDVvmrx
         eCKow4fFGwLciY6jDUfLbifJAXJLwJuK5CeZWnXZSAFnCKCVlY6q7wLEydrcKMvpbJrF
         TKVuGNdRo3HkZ8nyGWzv095SECSltaO5wVOl8jG6eEHtH1bJm1nQk04xHIa3Sg2Ty+g0
         qhEr7QZq6gBqzVFQrEfG/aLVdH8NCpSG2EIGhre1ZaAX1aEmTOFxcgztSoWPmTQqXbw4
         I72Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=ocq13Qe8vOCc1IAFLqnAl/2mCuTSTruud4rE/jUwCsA=;
        fh=5rwNJNyUoP3fzmTlOGU94AfkM+k43Cblg4GnWHuB9FE=;
        b=vfE8pprKfSP46OP0ZOwJoAm9J0vNiYoJrljjtjrgSZzW4037OeW8V8LAXBcBADRs1P
         ui/isvZl5FWM8NXEY3UBz3Q6GZklrTE8+Gpz7qj95qyxch5ycNwFj0u9THL9yY6++w+j
         7C4RKPKv6cwn7UaXTEr3FAiH5+mWX7i+s1HrFkHm5bt62z9YOzMWozQb7/b28fD8K54A
         YN62M/r2kDf/NQujAQf1JAh8iVsb1s10mLg3cqJ2OwbmNPi0OH6MZNu4z6tDdqlHRcJn
         ts4ED4SDbl8G9TN4MKzRLS/r8+ZxJcf5HXbTYTwCxwhGxuusgAj8G5QciibYSoUvWtsm
         gHpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=CgCuFdJW;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708571601; x=1709176401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ocq13Qe8vOCc1IAFLqnAl/2mCuTSTruud4rE/jUwCsA=;
        b=bWVM0dcrpUugA/lmubr7gXT4RHTZCQozAJHbztekMIAm8osQu+1lP8tCBLxts4Jc/W
         jULv39GoKQJe1WuZC3I1f5KhXxoP/I+cOJBVj1ZJOW8bclSJuIKYSfNuOu3mUEpvPJkh
         mbAXSFnrsC8kAqZ7y3279dbuh0a4T2BS7QlbhJabZyioveYjhbijL3VBgV/OqtHT20jl
         UjNtH9hnsyPSUQaAXkHF9G+NFSUSwQCb7LlATzN0GNj1OrL5oXIPJYwbIHyjbzCxTEGI
         Ixupl8gzzIrBNYtj4bnetaa8L5XtLIW6FsGnQEBZ+79SA2RMp01B1vV8syftFa2FuGa2
         iVnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708571601; x=1709176401;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ocq13Qe8vOCc1IAFLqnAl/2mCuTSTruud4rE/jUwCsA=;
        b=P+lgb6D81yWcbLd15rdlHCl1FZv3LUbJtIDCcLfSb9JuZOt4L4OPpRHq5SveCILeBi
         gqP/WgcLT+Wxk3t05L2+nAJe2PUHV4j2XzFZV65LzpQkiXdE1Fq2PUsPL5tcEhs4AfD1
         Ca6q/RnGpIkLXq31MGUSc7lGIbr4I0/55KwZdEr98Yxo/vzEiDORW364JiXqkDwLwC5o
         ONX6IPWMveUbhQDZRhQTV9tImXL8B2Bn7Lj0Xmk+JFvQl5RUTLMphT8DRnMBRn3jM0wL
         dWXIcxedZJ183BqXPHSSoI34+2bSkAVa+PNoJnoOc5NB8wN/Y3LHnnE7aOzUVA/VBK+V
         hraw==
X-Forwarded-Encrypted: i=3; AJvYcCV0jLapCL5tAvtpJ1BO3hI1Rsb/X3R7+q5hjB8pyRkGj2ViQey92PBEJ/Mhi90JlvzkkUE/qBw+3578DDrryT/h5nBhAPIq6A==
X-Gm-Message-State: AOJu0YzqjlA6inOdCSPYjtkSuhzVxGBAaixG/lV2Ka9Fl/vUq03N+hf/
	cmYraZCVxdg2zzhcHupVe1G2KYfGbJxBKKyjtXfT8ANLuMuXi6YO
X-Google-Smtp-Source: AGHT+IEIUHpaIR+6875MuCerS4LSunCXDFvFavgyYmoNVMELGxXH9PcxKQG8YWICQ/qJF+DBmigICg==
X-Received: by 2002:a17:902:ec91:b0:1db:f6b0:92d with SMTP id x17-20020a170902ec9100b001dbf6b0092dmr11252541plg.6.1708571601393;
        Wed, 21 Feb 2024 19:13:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:3295:b0:1db:2ca9:b5b8 with SMTP id
 jh21-20020a170903329500b001db2ca9b5b8ls2152053plb.1.-pod-prod-07-us; Wed, 21
 Feb 2024 19:13:20 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVJ81qSgGJRnWWWCEWTY6U5McI4ggWzWNrQPUFYFjQcwP9qmSa6tavmn1e9rdE4+pynItJsfF+0dwhik7eDEetKVUicBqzQc9qbIg==
X-Received: by 2002:a17:902:db11:b0:1db:f049:6315 with SMTP id m17-20020a170902db1100b001dbf0496315mr12580997plx.51.1708571600371;
        Wed, 21 Feb 2024 19:13:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708571600; cv=pass;
        d=google.com; s=arc-20160816;
        b=LBXLbYF5YnsB9lq6IVD6v/nf19Bs4F2vp/C+94fOybur4tmK1zb+ntzMOGN2+Q5r/S
         W/UMzGySIimSelxLO0aevL0FNWjep/SiKGSY/SMdi4CDmZ36aDcqllaXHM/6sV8f+49z
         eLgHxu9FWk/VSdxWC7k29JISHKstgmCJJpdoNK2Gd6jqfd6US8Wvb8vXkvqsIZmMpFQD
         qhi9whxYVbnUX3igTT8KrO4KW72W3arx0NqsjJR4VcZ5jIqkbh4srDAUSNmUE88utjNz
         I10kEvGF7m2F89HDlEi3BDDSy+HkRuVSsCgkBKQJMTbb2lTOAYTbjeB5p6dAAZiuWfUm
         0CJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=GAp8bMM+fO0rGx8i7CXxmYBLcWjDTZpGb2xv+4zg/aU=;
        fh=rZPYQuyUa0CTc5AAksktWNL4iHWYY8GZV+7iGCQxBq4=;
        b=SqjEA9aE1e6Bf/PT0UoGhsDfj5CE/5/Wbg5C/K8JwRxhF2yvryfiWz5BOHYipvmHM2
         VQAYKkc+2QWGN8BnqTdpWeoKLXTkmpDxFhy6RY4nwh3DkQo8LRAPivprn0pG1zjlzKAw
         jTEp/5HcJI9N2hAVFbFU3XPtZBxCgcVyKKAjwql5y1sz1pIZrgJRjA++Rcb1q2aPPzDv
         D0RS2MqSfsbtnrdxbgtOWGveM1zAl1fc3eqiIFahssI2o+9uDZf80wr1SGcGwzzbZIwd
         tdVCe0IygdhwZBm1nZtNl+8+B5FrPLz7hKN4aG7Qcgd/9oiSXPHFki24ONPAXxuuzzpP
         sGWA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=CgCuFdJW;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
Received: from mx0a-0064b401.pphosted.com (mx0a-0064b401.pphosted.com. [205.220.166.238])
        by gmr-mx.google.com with ESMTPS id y10-20020a170903010a00b001db4cf35983si690673plc.10.2024.02.21.19.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 19:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) client-ip=205.220.166.238;
Received: from pps.filterd (m0250810.ppops.net [127.0.0.1])
	by mx0a-0064b401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41M3DBia002597;
	Wed, 21 Feb 2024 19:13:11 -0800
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11lp2168.outbound.protection.outlook.com [104.47.57.168])
	by mx0a-0064b401.pphosted.com (PPS) with ESMTPS id 3wd20chj5d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 19:13:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Z9P2JknbeBnD3o9mTN9KSf0pnWclWAMDB4noePFJvUi5m9dTGN1MruyvEO7BvMKZrvfdRBNJ+yrjiuRRsT540WuFIsMCDHBrbzLmtmiAgq/Q0A5Ne076orq0VAfjTxYhrMywfWFHs/LSaEGp18G/dSzkzOLQJTQqgZnhO3j/3UZPDN7+VC76SLm5Ne3ynSfpUhFOXt4oBFbKYg0R5afmsqiKuKElBob3FnHcueqrteFv1rfyletWc7ZeDu6OJuZ0lAEh5EJEMFsadSNf/8h0X/s7uxTAUff78Sz8UrmhI40cvYz0OZyFJrFiVP6A5JocF5Myf+52Q0sD88ZrZqgMLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GAp8bMM+fO0rGx8i7CXxmYBLcWjDTZpGb2xv+4zg/aU=;
 b=hu1m3UBrbTIz9oyBpGSWgfJPVF2DfPEVpflIsOmSHCQrCVzrOFQT51CHYIb6YI5oTY3boi56AkDopx3KVmabi9s3x8OmL95YXb+xNtLBCGAeL/IaeFbjpHTR7bG7whs+lV8hNFbfxTSV74euJJyTPO92XYkmefyBRx3IhsT8rz+7kf6680nLabxsmBJqbD4HxxLPPsnd0vjeqOg/wat+0mBGauVPVDAKgaHb8eJHZr6JgaKZj6OiTKWw5GRxgxRk/6eDqmWNhf18YaCJCmLqNiodFE/6tEUGDlkuyZq+DFRNvzUGALawYBz9rhY677C0hNIw/ro2oYcrqwgfMT3O4g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from PH0PR11MB5192.namprd11.prod.outlook.com (2603:10b6:510:3b::9)
 by PH0PR11MB4968.namprd11.prod.outlook.com (2603:10b6:510:39::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Thu, 22 Feb
 2024 03:13:07 +0000
Received: from PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3]) by PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3%3]) with mapi id 15.20.7339.009; Thu, 22 Feb 2024
 03:13:06 +0000
From: "'Song, Xiongwei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Chengming Zhou <chengming.zhou@linux.dev>,
        Roman Gushchin
	<roman.gushchin@linux.dev>,
        Vlastimil Babka <vbabka@suse.cz>
CC: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
        David
 Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Andrew
 Morton <akpm@linux-foundation.org>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko
	<glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov
	<dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Zheng
 Yejian <zhengyejian1@huawei.com>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        Steven Rostedt
	<rostedt@goodmis.org>
Subject: RE: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Topic: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Index: AQHaZB4V5G9cauwLMUeerVHZZ0FHGbEVH8qAgABvR8CAABeVAIAACOdA
Date: Thu, 22 Feb 2024 03:13:06 +0000
Message-ID: <PH0PR11MB519245317F026FD9C6A6AC23EC562@PH0PR11MB5192.namprd11.prod.outlook.com>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
 <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
 <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
 <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
In-Reply-To: <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PH0PR11MB5192:EE_|PH0PR11MB4968:EE_
x-ms-office365-filtering-correlation-id: 10fe0838-b683-42ab-675f-08dc335430ab
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: OH1X6II8+jY/wdX2X8Brq6z15BXC/0HP1LuO4k74nV7xYR1zgI/g/jE/98Mk8hLPvXqpvBpkkdG9ZgKOyMsD6Nr2Do1ejbn0u8SWm63M3P8+LkmJgnOBioHScGTRtL5mW9ZLZh/biXEoDjQZxIfY7g4iKHteDC7gKDvZlOoww4zyVSI8QxE56rkpu2BZXvOhl4eabq5ai0krZczGMDRUZcHHXJk5E3OHDeadXcTvDYHbfuqdBqZzLk4Rd136NMAbkhou83g/+p6AkoVcBuvK4NGlafH7XVuc32mkr+nDE6yzEN16E40S6acih6n4qc7rcmoyB8MnWfPK06L8g1CtpXeSWYzoaiJhWGhQz0uruynQgol6hNI/NyI1Ld1tHAAlu0YFWB7fDK7o6k/k3s004s49uJjetE0VzIdC5hwIB1Ox/wFK9PVoY6Nau/vYVtMkMIU9BtofWiEFXfcmr5bZdbpJ6022lF39gBol7WJSpLLggDhck5SZjO1HunB5zQFlSGGjdHwPXkV+wQL/cNrBy22JiM6+Da5HCS71ZXPJwqZoQm30xUVZsFOTV3361PYs9KtYMOD+63GPANdDLjsuD0cxf09mYEoRI2GSVBWEQgQ=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5192.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?alhGaGFtYUd2U0FQd0RZdG1DZTd0Sld1K084dis5K1E3U3NNeG9sQzljUWc0?=
 =?utf-8?B?RDVFdktQSys5dklua0tWUWt5WE1hR0JjMzY5c1BjUkd6M2dBOCsrYkxhT0JW?=
 =?utf-8?B?RVhQOVBwTEJZWVBoU2M0WFUxRVRmMW5QdTY4Z3djSm5pNG5pZEN2bWlyNHZn?=
 =?utf-8?B?eUFKdEtUWVZIbXJnTHEvWFk0R3QvT29remdLWllsUFlHUm1tZDI2NzRJSDhh?=
 =?utf-8?B?OW03TndlTSs5R2hGMVBaLytpVExXbU8rNG9KRTA3dDFCMURQNEsvRm96Qnpo?=
 =?utf-8?B?MXBCUkFhd2FzaW4zRkhWZEVQS0N1V05HT1VReVFvZ3hQVVNSR2ptYnJ4a0JK?=
 =?utf-8?B?LzVaU0ZQWWw1ekZRL2YvQXpOZUZ1Y09TREJWbGI4c2tRRHFiaitxVnVzbkh5?=
 =?utf-8?B?dnVHSTMxRW0vQXJrRStZQk9BNERSN2ZKclVDOWsrenRRdHZsSFVUeUY5T2FT?=
 =?utf-8?B?ZWhmSUsvYmpWY1JkbFUyUmc1ak50QllpMzc2Qm5hQmFYc3IrYTQ2VGJtT3lX?=
 =?utf-8?B?ZXB2ZUNDY1haR3NjdnNCWk85L0RORlVyRnBpQ2c4U2x0cjZXZ241TVdRM1My?=
 =?utf-8?B?cWJ0cWQyTXhGSGwveFd3NDhFSFlZSHVyc2xsQUdoYUtKNTcwaVptUTNkRU9U?=
 =?utf-8?B?TzVpZWsyZ2JlbkdQNVl6MDdHdGxuMGZEdXd5NGo5cy9TTGFsajVIT1lmV2N2?=
 =?utf-8?B?dzl6NFFwc3BXZzlKTDBWTlBXK2V5TzZQMXpHQVllT3lKU1NMM2tSSXBUL0ZR?=
 =?utf-8?B?WFhpRkFRWHN6V3d3ZnVJVkoyUFRZOUdTZXZGeVFrVSs5cUxMcy9jcGErZm9S?=
 =?utf-8?B?eUEzTEFtdElkTnNkcGpRSlpwcTVOY2RBVUxlbkYrYnllQXIwQ011VzVxVG5I?=
 =?utf-8?B?dDRjeWJBZmRjSnlicmk1cVU2d1Avb2pkdGlGMzBKMXhGb3ord2RlVW9PSjhN?=
 =?utf-8?B?dW5kaGd2T1dkZkxiWTlnN0phNTNEZFUxaG1Tak5GV3NxbjVSTC9GdnUzd3Mx?=
 =?utf-8?B?dTlJbUZtdFFXbGRicFFQcUFQYUZHUThWMkhNaE5pRmtHbDZOTTFEU3VVUzEz?=
 =?utf-8?B?dEYvRk1ZT1UyUWo5NEJxR3AxZXJUemhVTTBBWFlxMDRCNG5NcEc3RjZwT0tv?=
 =?utf-8?B?TU5QNlB6SXdTU1VSc0c0cGtLVk5ZK05uVGY3UElldkZsYjNKVzh6bU1WemVk?=
 =?utf-8?B?S1M5RjlaUGRSaGFXNTI0YkdVdkVuQkxWOHR0RWM5bzBrVTdIckhvbExtQkJZ?=
 =?utf-8?B?Wkl0TnFkdGpkS2VsdlBaT1lKOFhCT1JwMTNNS3BTeko3aEN1eHdudlUxa2xU?=
 =?utf-8?B?OXpGaTUyQWM4cXNpd051dXNrWDc4R254K0VTYnpNWk11SjAvY3Z1RGZ5RHJt?=
 =?utf-8?B?T2hTUmhBUkY3N05JTWlDWU1rUk1xLy94cDQySUMwN0FpaG5VS1VsSnZ5clZB?=
 =?utf-8?B?YVNkTE5GSEZCbTU3OEw3T2VYbFk5RkFMYlRIb3ZoVjRoSmZRUW9FMlJlcHFn?=
 =?utf-8?B?NiszalF3aWo4MTh2STBEWjZEUC9DdnVnVjJ0YUVNN0tJWTQxcjl3dFNheHNn?=
 =?utf-8?B?MW5BL2JmekxQOW1rbWZ3N1VEcTJmN0hlWGdrK2Z3SGZTUkNWZzQ5bmlrd2dD?=
 =?utf-8?B?ZTlzTTZhTTF6Y2pZcmZBQWFVQ1drNzdNQmYyYksxTEtRSld3eW1oR1JtSFVn?=
 =?utf-8?B?aGtJOEZiaHdYMTloQThRUE1yT0JiZkdlOHVzQUVNbjZhcVcraitsT3lGVWhT?=
 =?utf-8?B?R0JzdkF6ak9lY3dhanNnWlR1c1c0R2p4V1ZjQkdUMW1oWFZlaC9LU3llb3Vv?=
 =?utf-8?B?UDFPalFOUGN1ZjdRK0FNMWFPdDJ5UW5yMnIvU1A5MnhtSXB0djI3Rjd0SzFi?=
 =?utf-8?B?Y3IrRzFQTExhd3docEJlNXc3Z2ZPV3BIRDIyVlFEMVdHTW4xR0dsOE5HVkc3?=
 =?utf-8?B?RGh4VTVSNUc3eW5FMDltei8weEpEV1UyaHdJVUozeTRBakhDVDBwYlJpOFE5?=
 =?utf-8?B?YU1HMzBPenhkQXVTV0pjOVdLUlVKV0JBNzZVT0oxVXlKQ1lObkw5WGI3dmNF?=
 =?utf-8?B?b0hLbER6anpUWittZDcvVk5EZCtTUkdDdm0zb2h1SUdoK3Zjdno4Q0FNUG5G?=
 =?utf-8?B?b2U5ajBnaUFvRVlXcDd5b2xQQTRZaHZ2aDNrNFlycVlmYmYvbzM0TW5iQkx4?=
 =?utf-8?B?Qnc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5192.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 10fe0838-b683-42ab-675f-08dc335430ab
X-MS-Exchange-CrossTenant-originalarrivaltime: 22 Feb 2024 03:13:06.5954
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 50IN8ZrZrjPyCHKHcuUtM/7L8cwZiMrIUESgolKZEVCKrIIyZoiycqVQm0X0b4oYuIlDHDCpyib98tkzcM7JvaPQvQgFXITnTRaGcDIXyFo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR11MB4968
X-Proofpoint-GUID: C7CiAq9NKO_GUTSNtpWym9dERM5q0rZe
X-Proofpoint-ORIG-GUID: C7CiAq9NKO_GUTSNtpWym9dERM5q0rZe
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-22_01,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 priorityscore=1501 lowpriorityscore=0 mlxlogscore=757 malwarescore=0
 clxscore=1015 impostorscore=0 phishscore=0 spamscore=0 suspectscore=0
 mlxscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402220024
X-Original-Sender: xiongwei.song@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriver.com header.s=PPS06212021 header.b=CgCuFdJW;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass
 dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);       spf=pass
 (google.com: domain of prvs=278288f4cd=xiongwei.song@windriver.com designates
 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=278288f4cd=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
X-Original-From: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
Reply-To: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
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

> On 2024/2/22 09:10, Song, Xiongwei wrote:
> > Hi Vlastimil,
> >
> >> On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
> >> 0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> >>> removed.  SLUB instead relies on the page allocator's NUMA policies.
> >>> Change the flag's value to 0 to free up the value it had, and mark it
> >>> for full removal once all users are gone.
> >>>
> >>> Reported-by: Steven Rostedt <rostedt@goodmis.org>
> >>> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> >>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>
> >> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
> >>
> >> Do you plan to follow up with a patch series removing all usages?
> >
> > If you are not available with it, I can do.
> 
> Actually, I have done it yesterday. Sorry, I just forgot this task. :)

Ok, that's fine.

I remember you said you wanted to do it. But it's been for a long time.
I thinks that's why Vlastimil sent the series out. 

You could've said what you've done or your any update when you reviewed
this series yesterday, which wouldn't make others confused. So keeping 
update would be better.

Thanks.

> 
> I plan to send out it after this series merged in the slab branch. And
> I'm wondering is it better to put all diffs in one huge patch or split
> every diff to each patch?
> 
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB519245317F026FD9C6A6AC23EC562%40PH0PR11MB5192.namprd11.prod.outlook.com.
