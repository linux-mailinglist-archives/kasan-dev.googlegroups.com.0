Return-Path: <kasan-dev+bncBAABBZ522WXAMGQEEOCJN2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 976C385CDD4
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 03:18:16 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-68f9e713a1csf1878316d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:18:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708481895; cv=pass;
        d=google.com; s=arc-20160816;
        b=tWhXL9BvyVX02RT7Nw9HYayKiMOYy63PHGejUA9tvPq0yg8MvvXlkeO14DLRs4nz4M
         EgWNHTXF50I/XOYqkEHC1C4yoXDH60jxbXrJZbbF4CBEZFjmy9g6jyMMmwIKsoMe3XSj
         clqRGzy08OSO0emBGRDYeLklOa7glPAdffHe9wnET+hwk6xibXT5DYyUtEx5N0rm4JGs
         Qdy2rFLBvDEhzuLLZoQ9e7AOQ+h6qpOUd43ZxLoHo74XH+6by3dBM3YedCUpwPfCh6y9
         jS+TVeMA+8tngZnbq63CntbJnvVWySHTbKfduLcfvzlxzHyA2wYJkWju/W/HYh1QuD6a
         ZuuA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=LkVZh1dAFY0hJwimxAzs8k+sNv+qV6Zil9Kf4u4B3p4=;
        fh=A5hhkMyGASQT58bYVpY3UlbhpoxJPfqbtC8SHyqpVsw=;
        b=FWvubo9CDENjeQac5rMC1B+HMlToG+SYVmcUYsIFXjy2zRBMf5XjMXI7VFldxWO0Gz
         Guqp/jVhDmb1N4ly4UuP2johvtGdkEcFvQxblr27nzHQZqWU0GEKmpiqMZNopB3v/i3/
         GzBzR61i8Ofwv0qXaX9IVFBG6k6NsOpUmNppW+rTyXRGdFO0OhkE56i6X8PtvvRIzj7q
         FYwDgLVpLCOQIvrdVOodGa4ndSPX3cec+OiwKAwIpuluEqoBJKQj0PTxGOhj5gUqM7uS
         6m3rFuOaz/HWHGpnq8t+YxBtGoOZ8c+6UgcVPivf9GxNBMO2fzE/FpB369PuPeVLPoum
         5GHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=nKSdqE6N;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708481895; x=1709086695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LkVZh1dAFY0hJwimxAzs8k+sNv+qV6Zil9Kf4u4B3p4=;
        b=dPAJal22U7YuZV0KBseP31bHDuUmVkTsZsiGs8zCDatxSnUg6Rtu3J2di7dDdHiXY4
         4bwzrXslZUbqfXJ/b8IoZ9AHBTXBXNrCmQTVGFa+4ghKk89ubUUW7itARQxUvcsGxAJw
         J8vv+QN1aSyDX8V43RY6khjBEY3qpj6Kv+48wH5WFLxDiA8s9YsdFh3QUjOyaXocPLzo
         nhT6aniDBNrej7XHPwzDge8GkT2ItZ2qZgGvqc8K3igH8SZEsndk7asHW7rKtGEdQOjR
         oA4wLVtPrUmbCarzsNAsK6ckJdkIZmBTEZ8i3wNc9PeUFY/wvcd8573zw0qcfPtjumvY
         OrZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708481895; x=1709086695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LkVZh1dAFY0hJwimxAzs8k+sNv+qV6Zil9Kf4u4B3p4=;
        b=hTM39erhNYXTsUF1gctoEzSvUEsTgDAwvI5BH6EqvRSilntPM7D8ylvYhZmfK5kZYk
         jeAYOxa+JyQXRExkHOL4HbMuh3YFyiy9cR6CZ/+DAbm+EEkCIQGWZznPRBDqymo09OQL
         kx6cdyZqAjTwc/+v0tV9N+S8jQjRo+NsEDEf3c7xpERYK/P3bWkWRE4ztyL41pgR+KcB
         jgFVYbZmkoxVEw2K5VhBxch7MSFskcFE9lW4U2hICB4Xx3iGN/Oig7IlcZhPoE3weeXr
         c+sXpVsbpwO5e2ZOb6QShnDLAX82ONBRbdbww7iBnJMydmXY00hdUdF3EJt7Wo5QBsXE
         Cmdg==
X-Forwarded-Encrypted: i=3; AJvYcCU2tlCAPOJNhAX5NJGh12wBpqfuTbC6joIzyBRlV8pHWtXuWwGR8yjJtT634jeIxkjzHzfu/KYg/zMMiQ8P9bADC1H+K74nKA==
X-Gm-Message-State: AOJu0YzqxLD2JqqggdjHK/O+zCuEqX1hp8efQt3ltPM/8XzCT5Qi7NNz
	dNCPlQIDI86HQjN26XSbIvbuIlf7HxS/I4znEa1zXjubUpGq76e3
X-Google-Smtp-Source: AGHT+IGB0FxVkfSOI4gKmRk3EVSZTR9ClxGF3Gzeb8XzT8VRZZUoczrejx2qCpIV1rt/dDDTpgTYGA==
X-Received: by 2002:a05:6214:27c8:b0:68f:8921:6924 with SMTP id ge8-20020a05621427c800b0068f89216924mr7594230qvb.12.1708481895123;
        Tue, 20 Feb 2024 18:18:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:519e:b0:68c:5c2d:cae9 with SMTP id
 kl30-20020a056214519e00b0068c5c2dcae9ls7276767qvb.2.-pod-prod-05-us; Tue, 20
 Feb 2024 18:18:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWE2Gp7eM6iYBjO2t3J++308sFHT8V8GkyxcxgdhkFBKmt4V6m0cnqHyYwp1u/kxbn2zpwbbp8Cv5DO2UKCOllxJxk9ZHlxXlCefw==
X-Received: by 2002:a05:6214:27c8:b0:68f:8921:6924 with SMTP id ge8-20020a05621427c800b0068f89216924mr7594178qvb.12.1708481894207;
        Tue, 20 Feb 2024 18:18:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708481894; cv=pass;
        d=google.com; s=arc-20160816;
        b=dUMEIihE/zQj++SoH82HTpNDUWRBRyqdnBV6sxXGP+IUReBqfsS+mcMj6Oxw7PbPPz
         wBqb4ZlCfKfGKJ8C+1JYZbnFj1YQBb6fCTNtgBLvq/YJFhZ+P56VIwj3czZOFy7QJJz7
         uGzPIQCXpAXr+0Vf9oS1JcUYlXJjIIHqgUjgwGDGhCN1IHc/aOZWxiPYR7hKc+/pbYCv
         YQxsrY19CEHpSbRQkX37FNv7PZHsSVL4HOHeiIaIwtqWlG014C2oFxyeZuXe8EtrcDqK
         gudlsPzO4V4HyHSYiWB47a1g6HLo6IXkBk55SLuY9HduEzF8FBL+kw2XVD0YIwTeozcI
         ZgbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=0eR6U8TW8my7HwTmWwJC3CONe6WJvFBnFHL061pVyLc=;
        fh=BIJnpBMmU/gy6/h3tyf5L++c4ILYNuT3ZG9aiU1Zr3I=;
        b=WO+xEjdRmW0AoOtGauSHoZyFOl2vo+So2s60s3F0WvZ7bJUSKKNAleBNDGFge5Jkfh
         YZvNRbUaqZxmUluxFscZoUGdMgI9q7HXJsvFEN1kugV/WEaQWCTpf5ntja+CNJjxl81W
         Kcfz53vs+VNZjb1JcS95S7Nwr8OG5ROXVBqP3p06zqH6lSzZmvT0PPCzyQetWXCw7Phl
         +dZSMrsba4fdmTacu2k8GkHGRTPoGDcktqlYgH3CJtAQtJEQXPluGjCjOWgsNErj674o
         YivsgmsIsQIKqWRyDWOZ50cn0IdsT8KL/MhbeRG04hhHbaHE4cCMcenRSwrDnOWEzGlL
         27EA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=nKSdqE6N;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
Received: from mx0a-0064b401.pphosted.com (mx0a-0064b401.pphosted.com. [205.220.166.238])
        by gmr-mx.google.com with ESMTPS id i4-20020a0cd844000000b0068f015fceadsi679749qvj.8.2024.02.20.18.18.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 18:18:13 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.166.238 as permitted sender) client-ip=205.220.166.238;
Received: from pps.filterd (m0250810.ppops.net [127.0.0.1])
	by mx0a-0064b401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41L19VSW021647;
	Tue, 20 Feb 2024 18:18:04 -0800
Received: from nam02-dm3-obe.outbound.protection.outlook.com (mail-dm3nam02lp2041.outbound.protection.outlook.com [104.47.56.41])
	by mx0a-0064b401.pphosted.com (PPS) with ESMTPS id 3wd20cgand-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 18:18:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=h5c1ee3Z3xjscmLyv+EtahvFoNAEixkwcAOTz+GAs9nfj7ubC4lLCVWqFnFFozqeXUpdTjkDjApKxDQ/1ERBpryb14Yxvpmt/tlBPfAjPL7yf6pTy7tZqT0SQa3BwT30DOa9+AgOlChR3f/DI1xwjhLC8DhOTTwwUAzka+kWRXVbjEEB88MPCo2jlLPi8hRUQ2h3wRE1KMguRKSfbGZ1tqWyw/zUXBEhEfuyp0f1KfqkHhOLXiyckx41VePGZMVMuIrSCO8125VcX5oHOJgeVux3DXtxCFzJTArIb3POFmZlUlTu6dvoSNP2TnC9051hki6BL9ehZzCwIBIOBLJ2Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0eR6U8TW8my7HwTmWwJC3CONe6WJvFBnFHL061pVyLc=;
 b=lyI8edmkE92hsSxuOr/76RBd1sa054tSAtxv8mbQd+CvFHzms2xQU8Pvegh4hhvIYTxJsPFdeEp+HVO8QoAJ2Uw9U/lXYZL2/zaPGns7kSYn8BG2hikvPzqpopjDXWpp0EUIZE93Zear2m5yMrK3WP5A5fvgXoVkYr1oWCbSTw1gEmHS94TUjG8Olrcqykr8u73E3DnSxiuqHbSenwYR6papCNwZmHD/4b4VZ9ZfIYpq1sF+C6KoaKRf2OWJ6pv/9D14h7fe0421nAt8pOA8PpD+oEr0BnXETyrihWNkH9EbpmWS+UTnIfkhvRnBOUTft4MZmE6pbP2IyDzObIb73g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from PH0PR11MB5192.namprd11.prod.outlook.com (2603:10b6:510:3b::9)
 by SJ2PR11MB8538.namprd11.prod.outlook.com (2603:10b6:a03:578::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 02:17:59 +0000
Received: from PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3]) by PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3%3]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 02:17:59 +0000
From: "'Song, Xiongwei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
        Pekka
 Enberg <penberg@kernel.org>,
        David Rientjes <rientjes@google.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Hyeonggon Yoo
	<42.hyeyoo@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>
CC: Zheng Yejian <zhengyejian1@huawei.com>,
        Chengming Zhou
	<chengming.zhou@linux.dev>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        Steven Rostedt
	<rostedt@goodmis.org>
Subject: RE: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Topic: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Thread-Index: AQHaZB4V5G9cauwLMUeerVHZZ0FHGbEUAXtQ
Date: Wed, 21 Feb 2024 02:17:59 +0000
Message-ID: <PH0PR11MB51927A728EA0776433CD66AAEC572@PH0PR11MB5192.namprd11.prod.outlook.com>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PH0PR11MB5192:EE_|SJ2PR11MB8538:EE_
x-ms-office365-filtering-correlation-id: 5acc7f52-6f8c-427f-f89f-08dc328352fe
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: plgx5vvSXRDXglsjts6lLcsFIBTwm3Mu9S0RZmTQrb0zJFWVTGNH7GKaKyEsyFfSl9X7hLlmE/5sn1cxmCtJDIz03NRnynVevaO4txyH0VzPvcntzRNoLt7rHO0xpbRg4tohQhoHUB2VosFjJGP/9aU0bwPssmKcc2gANYkGTuIlUlH79kRQ4fdmLm4XO7+U2+r2eh+cbBWS12Ox5BauXlfYGlv0HafSA5QGb0bVETKqlN0WqoQeNkDdD59mU7SkZ0e1CTuTwhbGqICX5fHTbS4EDD1TGltlHK8ZlyV377yVZHgz5V35g4ZjpFZtEHG6/kkBjWO/LxcYTCZyyUxOIx8/JUxdGk4Qko3YvFnRMLl3U00ME5ownIXP2Q+o9DEpm3mv01JEdsAyQszmROFrPnPUije6kUKDALDLpZSYHG0YcdtpX4Y1b4gGhvfnmcXRrrbj0uC/O+qwCCz3Rg+Y+Ty0ZexNj4Q+q14hL1ARKgftpDK8S/UMpB85SKFMUD13mTWwZ5TjSueJPKJHEqYcgLUnY9IzB98vCt93x1st5rA3NWj8q5TDPIQ6oxwsGlzCeveGQOAkZDJoxcFj+yD0RnqSBILG7lxafb+310GAKIGD/h/q6equZtebq6vFVfXr
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5192.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(921011)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?TlFzbUdSWXhIeS90WDBDdWsyaDk1aU0vb1FkU0VvblFyYzdnejEyQWg0d3lx?=
 =?utf-8?B?ZGR5VkM4TFNoeUZpeWIzUEpVY3d6YUlTRG4xU0t2bHZ3UU1wNUhIOENrSW1k?=
 =?utf-8?B?WFAvaUFXYTdnUlBNSFhQSjZab1BsUytFRTFlNTBqdmpKSmsrZnVJdXNpay8x?=
 =?utf-8?B?Mml4RzZXVG9lTlQ4anl4Q3VRZ2ZFUlg2UWtzS2N3OW5YWFI3SmFzbElZMExW?=
 =?utf-8?B?cTBGWitWNlpXVXBYU2FNWkYvRWhOUlJSTnlVcDgrc2d4QzFUNUNvek1OeUxn?=
 =?utf-8?B?MVdHTk5SRUpsaTU2b0VNUnhBVnlyMmtJYUthUTNibS9kYTBzaTkzWmtiS2FF?=
 =?utf-8?B?aU5CTEtkUGFoZVlZeXo3aGFTQXBuR0oxN0xLWm5VbWpBQ3FBeW5tc09JeXJR?=
 =?utf-8?B?cEtnUjduTnRhbVpNMThzQXNhb3h6cGpUUU15dHhsWSs3TXcwTEZUN3V3V3U0?=
 =?utf-8?B?bEs4UlhXR0Y0S0QzWnNQMTBKWEsyRGgrMXpuN3NLNDM3Q1F5cFdVZFhESWFn?=
 =?utf-8?B?Q0E4QjN3eGpDZmRBNWZmaCtlVmZwTlhGa3pweHRpQkwzbGxCSGxudkI2d2ZC?=
 =?utf-8?B?OEg2T2xza3J2TlNEb2Izcy90NFhXMWxHd2REa2F0d25taGhhVEFOYVAzbkxG?=
 =?utf-8?B?cVdkbkxQdzFzZGJrdUkyei96SHQxbFFnTGNTS2s3SjA4UWNWYlgxa2V1MnJQ?=
 =?utf-8?B?UGNNQ2lIb0xLSldXS3RsVnVXS3VyT2Njc3ovUHAxWVAvSWlnMHZCdnV2NW9p?=
 =?utf-8?B?cnFxMTZwT3BnaW5zeTdzNVBsM3J2WEVzUkZCZXRIeFhVN0l6UHpnSmJHOWE4?=
 =?utf-8?B?Y0xzRXJQSFFCY201R0IzMTFGaGZxRVBNN1FaZks5YWdRNDJTSTNvS1RNdFRs?=
 =?utf-8?B?NzMzRHEwYXozdkhuK2YySFlQRlVOdUE2N1Y2OTV0RXJjc0lvck9QNlRkKzMw?=
 =?utf-8?B?Z1VlVTkyMm14eGNKOTBmSTdWV2RPU0NvNmp0SkwwNVdtVFVrSHE3aFc4d2dj?=
 =?utf-8?B?UHo5OWhvaXFWWHRWWVp0OTRZN0pMTVBBTVFJOFZzSEpXZm9iT2FMVXNFTXdm?=
 =?utf-8?B?QVlvdTlsZ0NFRGhUak9hZ25KbnY2aVZKYlJhbk9NT3BPVWlZUzljbnpFelU4?=
 =?utf-8?B?dzhzUjZTVnM5bUpuUnZ1NHpmUk1ZNThHZ1N6aklhZzdYaDdiZXV4eVFyQnR4?=
 =?utf-8?B?dkZPNjhxem4rdVk2Y0dVRE9wZE1icm80aU8wRTJOUHIrT2xDM0VxbUdaWGFS?=
 =?utf-8?B?eHU4OGtMVWdLQTkvdkxNS2R0OEh3WUc5Y2lVTk8rL0NTQmthZGxnWnh6ZEZG?=
 =?utf-8?B?dTNLZDhxeU9scVlGcFRYdXBvWFZhUlhoMnR6SEJQYlo4QkY4Y2dnekIwbUVV?=
 =?utf-8?B?RWdZYlZnQ0VnSXFmbThlU01aWDFZQkdZalAzSVluTkJ2YXM1SENTelpXaTNq?=
 =?utf-8?B?ZTNXOUw2WUdTOHBwWWRmVmlZUG51T2J6a1ZOWVZFVzNrcTBJT0FpMCt1WkJ3?=
 =?utf-8?B?Z0dzUGIrQkxrcDVWOXhZS0JVMy8vT3A0dmpRUVRxOUZkZG9FYWFSMVFSd3Rj?=
 =?utf-8?B?UlpjWUZ1MW81d3J1eCtIMXdjTEdZdkV4WEUwYU1SYWJ3SEljK3hhRHoxVlJn?=
 =?utf-8?B?aE5JMG9Wb1ZUVEI1Z3ZkNWJWNGlUY01KNEtPb0paT1g5N1JvU0dlTjhBZUg3?=
 =?utf-8?B?ejBrb0dtOUVxZVp3bmVacVFvTXoxeVl4OStvNkg4Q01uL0IxYTVNNGNIenNx?=
 =?utf-8?B?clJreFUzdm9ENDdKb3BHZHdsbU4xOE5LZXlHbGhSNTM1aUZRWEMzS3ZvTGFa?=
 =?utf-8?B?U1IvbTh0RW9oMld1Q1U4eWdkc0IyOEU4TEZ2M2NPY1JJL0lPOEJFamgvTjQ5?=
 =?utf-8?B?WXVlMVEwMHAyczE4K1ZSSU9paHVIUnRCQVJYOXVnSmQzVDQ0alkxMXpCdEtC?=
 =?utf-8?B?clRrWjQwOHBzc1owTDN3KytxcW1RbldHQ1EwYndjQ2RkbWZtNXR3NXVTWitX?=
 =?utf-8?B?RVpvdHBwdEVmcUY5QkJzbXNOU3JtaUZzSVRwY2NOODVUVWlzUVlQOWt3ZTRk?=
 =?utf-8?B?THo4SEQvcmw4Z0ZMdEtPanoreDFoVW5Rc2FBMGRIeVFjVGs2OFBhbnh5c1ZK?=
 =?utf-8?B?REFsTTF6ZU1tN2FQV3dZZU81Z3ZsdkdqaEF4UEJueVJNWDh3TERWRVlkQ0VD?=
 =?utf-8?B?RVE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5192.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5acc7f52-6f8c-427f-f89f-08dc328352fe
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 02:17:59.3782
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: sdFv6yZ3JySV+IWVTPOiW/bgdegxxrURViwsZipP+De5T4mlNdsB2F8syCtapcVbOt2gCIkoTzlfpWd4P57PFOz9ely9DgofhixMnD4/IGg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB8538
X-Proofpoint-GUID: F19HJeW5U28aiZeK5kJv5fHBtyrqFGkG
X-Proofpoint-ORIG-GUID: F19HJeW5U28aiZeK5kJv5fHBtyrqFGkG
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 priorityscore=1501 lowpriorityscore=0 mlxlogscore=589 malwarescore=0
 clxscore=1011 impostorscore=0 phishscore=0 spamscore=0 suspectscore=0
 mlxscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210014
X-Original-Sender: xiongwei.song@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriver.com header.s=PPS06212021 header.b=nKSdqE6N;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass
 dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);       spf=pass
 (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates
 205.220.166.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
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

> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> removed.  SLUB instead relies on the page allocator's NUMA policies.
> Change the flag's value to 0 to free up the value it had, and mark it
> for full removal once all users are gone.
> 
> Reported-by: Steven Rostedt <rostedt@goodmis.org>
> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Ran a rough test with build and bootup, feel free to add

Tested-by: Xiongwei Song <xiongwei.song@windriver.com>
Reviewed-by: Xiongwei Song <xiongwei.song@windriver.com>

> ---
>  include/linux/slab.h | 5 +++--
>  mm/slab.h            | 1 -
>  2 files changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index b5f5ee8308d0..6252f44115c2 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -96,8 +96,6 @@
>   */
>  /* Defer freeing slabs to RCU */
>  #define SLAB_TYPESAFE_BY_RCU   ((slab_flags_t __force)0x00080000U)
> -/* Spread some memory over cpuset */
> -#define SLAB_MEM_SPREAD                ((slab_flags_t __force)0x00100000U)
>  /* Trace allocations and frees */
>  #define SLAB_TRACE             ((slab_flags_t __force)0x00200000U)
> 
> @@ -164,6 +162,9 @@
>  #endif
>  #define SLAB_TEMPORARY         SLAB_RECLAIM_ACCOUNT    /* Objects are short-lived */
> 
> +/* Obsolete unused flag, to be removed */
> +#define SLAB_MEM_SPREAD                0
> +
>  /*
>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
>   *
> diff --git a/mm/slab.h b/mm/slab.h
> index 54deeb0428c6..f4534eefb35d 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -469,7 +469,6 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>                               SLAB_STORE_USER | \
>                               SLAB_TRACE | \
>                               SLAB_CONSISTENCY_CHECKS | \
> -                             SLAB_MEM_SPREAD | \
>                               SLAB_NOLEAKTRACE | \
>                               SLAB_RECLAIM_ACCOUNT | \
>                               SLAB_TEMPORARY | \
> 
> --
> 2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB51927A728EA0776433CD66AAEC572%40PH0PR11MB5192.namprd11.prod.outlook.com.
