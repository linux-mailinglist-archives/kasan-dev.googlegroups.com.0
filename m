Return-Path: <kasan-dev+bncBDLKPY4HVQKBBC6F22XAMGQE4HD2UHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8696885D0F6
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:13:16 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5129e5b5556sf262780e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:13:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708499596; cv=pass;
        d=google.com; s=arc-20160816;
        b=qyA+ZScSiWUxx5LfmqfwagD54QytXz6GD+IiIrLvyKh6spce1qEJC5ORB2gA08ltqw
         WhI+/6iY29Nvc4dkm+EwZIFUVHMhLwoCyljAkSuMGl+bPmCV+1HQet2cF68TJ0LwphAF
         z1KtOdpAmj/lUBkg9Oh21OyMhazUHL1ktTS8cQtmvVGb+tQRwFgPRe5k2xp2aw90TxAH
         iCH4F/g6ZYL0QPi+O9yYv+KtNzofHGPRwQx7gemkkNs+A0AQGGuiun7+K3lEPgdvf8Np
         Fg3FWTYpKwX7o+HZ8aFNawHXMP6aaSPuEGvbUmaB0H+wxeQEx4Z17EhYFkwXHhsrERSK
         RVLg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=elUqxgDuhQBakUeFK55dpH+ZgQHJ6YTJTcgV6b7lE70=;
        fh=DxK7l/Hm+WklTsxCVGabKBjWpbn2RW4hMxROIR4lxEQ=;
        b=Pv2gxPsnup0NcsNjt7YMJ4uuokJ9WInVyUDQspWzvBM8WrbcmSW03emlrXpqK2BYLG
         RIwLi3RVkjQF4lk9NK7W0D4UEHNLOU+ezBFN0kWGROfv0KsW9RX1CEB6PTXn5APsSEwB
         0o0KoYAj18CBW6ln6Aj+lFZWV8ETU35jvSvJfj3WGFR492MBCIUSDlbvMjlUCejw629D
         Mw1SaUS1tbQ2YvWuIpiz21IcmAC3paWD9cRFyQYj81Q3INRzxtW+s+G9ju5CA65sbKpJ
         +OYWPUmlgP+u6URlvD3RjXVXQDU1+gqroqcGmRKaVLLb+T3SCY+U3XoZYXgD8HuVoPm8
         2yUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=aUpfz4J7;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708499596; x=1709104396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=elUqxgDuhQBakUeFK55dpH+ZgQHJ6YTJTcgV6b7lE70=;
        b=Tut0IxRW5AveH4HU4DT1p6FsYJ1Z1Bo74wLJzd/bCTSvQtOISgHRqi+kjHaawOtnsb
         3F2qX4HvxbGj/AfCcPl0eQuEPnGlIQL7doV6dV5eNWfGO024E8Jyg/9tkVnW+KJxBcXP
         fHCk5gQZSTlceeCFZV97x4nSpGA72RNf7aAfA6dMk847Ce0Bfkt6xAWVte6YH01g6w2v
         pY5PXNj0v+A2rY3i0u8LdsUCTG8nPglS5kGAz9lZ/89kxoWFMI7ikmjBkvPQbUNfXAOC
         yIWSiCGe0bHBVMlHDNjNL6cXOXdK4A8qNwJ2TignQjeBMl+QG/+LLDkXZXj/ed7226jE
         /u6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708499596; x=1709104396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=elUqxgDuhQBakUeFK55dpH+ZgQHJ6YTJTcgV6b7lE70=;
        b=a3lraEC1ifqyQdgyeB7BYIm7zQIXnIykWgkA2+ETvFealoOeMm/MUzSyB+XNS8WHL4
         TK5MwtxkFHFohnMzdJ9C64iE5eNElgAd1nLUU6qHwWH7Kzs0V7FpRrvvkNEnbSvo94rj
         4Es9cuvYPIUQeg3XsLuIevYsNG78+Aw7P9XBt0maNHxEeWk8ZN+i58KL1ByDi17Wd3cS
         uYaOYXFKJqjlUOrn1q3OcBgYlwcPD44boSoS94GOjzcYPG3owqGTSqP8PeobB/ShdLv1
         qIu26SHfrd6Z7WscURRsodoEVIFmTP1kgnYUuYLDO4LZ4yt4Jm0plQoh26bEYkCkGkQz
         iVIQ==
X-Forwarded-Encrypted: i=3; AJvYcCU+zROdMkCAtfa/4BWXzVuZcQ5h/cJyvnx5MKEbbWHWVDZjgJcMggbBQpt8xvB+A6d4TuCn7j6fQuv2w8pfTUZQ8N514ecKkw==
X-Gm-Message-State: AOJu0YyZUgNUskRwt6qhPLKPUR21mPJltsiQ6iBrA0nXrRhPekx9Y0FX
	XRPC+WB2NqBFrtu2PJn1sVvoQiEyguk2rZT0og/ue5DS0tXi89X6
X-Google-Smtp-Source: AGHT+IFgTVF3SanUq2zmvtSlDCmW5z25ttnvA1fzib+1GshoGxquAh1OtyKfbt5UzV+d0LmOE6eDUA==
X-Received: by 2002:ac2:4304:0:b0:512:ab73:d2d3 with SMTP id l4-20020ac24304000000b00512ab73d2d3mr5794079lfh.47.1708499595310;
        Tue, 20 Feb 2024 23:13:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d5:b0:512:d6d6:5ec4 with SMTP id
 k21-20020a05651210d500b00512d6d65ec4ls23714lfg.2.-pod-prod-05-eu; Tue, 20 Feb
 2024 23:13:13 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVR9aHWby9FPKFEWO4eH5+RiaZDB4O6D/W2RkJXW/4UV/MV34wLj7aaSRRyi+0JqqEGy+ErF2JTjdn+B8vDVELNxOiS5ZdNPJI1mw==
X-Received: by 2002:ac2:4e06:0:b0:512:b369:15cf with SMTP id e6-20020ac24e06000000b00512b36915cfmr6246858lfr.17.1708499593417;
        Tue, 20 Feb 2024 23:13:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708499593; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLW1RvRQVlBZb/Kowm5ZC/jTtxpXIqNxYfpXJrdPqZK1H16taCQ/81EiwPdgpGSK6b
         IKn0MbNI+nBt1uHKCcP+4XmTjsyB6BDeRTTOczZrp6yK5BPUfWdJE1DChFtjPz3VKZPd
         PO74071q/0gJNUiNQYpCFlwiJYqTasMLClhl0wzYG/RP0tqWSTa228vjwRan1MfIBvOc
         BKUiM36+CXrBM+4hnYlR3kKlU0yU51OIUqlIQgYUy7BoBsI1fKYViWXsD2qS94PiU8xS
         5tAji7fCtLwg4hYgIUPuUgtQGknuR0pkO0x8onVIC2sFu8mBy3WZfuC/2ZHhY6FUoUyi
         V1JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=nOnAkzumuBIFcwP1MxkHbuOI/mwVodiON58mzESTZDE=;
        fh=0/nJWjGjUDnfJAXO9tPU9tkn3rnQs7SlLqPGDpCOlAE=;
        b=fMpTMriKKoDQ3eQp3fHol5vGo19IrJ1fb5jjF//U64YPQe3YILWen9Ew9UEJlPWEG9
         D5iWTRRV/CxuxhS7N1X/u5PcV3ozmnU/krmqmpXKUJZJCX9o/J2EAbt301sXE+ILKiCC
         XK1JBWUdre6UnlAVxhmnHga0SoKAA4z1SBhP/ahqu1DU9bzS+QuOZK0CoIIe0j723kcz
         HvjpGWjT/oCER3NTHFp4SS34wWtceuGFH52DjnwlVjRXVbKQHtFRGVTqCJn8Anh9mb9T
         HwsmkFumDJOKMijNCn4g7iAgiCik0sJgtpNi4JUE4Hdp8XUGNCyrKhlCU3PnxQX39DE/
         ZQNA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=aUpfz4J7;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20700.outbound.protection.outlook.com. [2a01:111:f403:261d::700])
        by gmr-mx.google.com with ESMTPS id b7-20020a0565120b8700b00511495618fdsi401723lfv.7.2024.02.20.23.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 23:13:13 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) client-ip=2a01:111:f403:261d::700;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=cszV+5VJw3oxLqo/wwCEr5Htg3bFotgi9x5IK/qsGUts6gJIshjizkCFNmy3MBiO4RAT6k0IZVhVxpPlojiKFxcw/1AxsYBuud0Z3PaPhUcbo2mutl0Ge9efojBJloddumxp0PA3gP9f6sEu2y6ImYiBWzKmXFcdEi5K0z5zfv9VLv4KXWDFrTua34+RpQX6GExel8advQgEYaBFimcbQNkv60S3FVWl4tFs3a9srGSF9X7VV2b+DyDXa8n/lDc3BKA+KZITrn4dtOeuH9SXMGk9dagKsbsDY6sYGaqiRxlyPRuPzTzFZ2hyUgB/t+n4sNu4VIvtY772vYrERsvo4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=nOnAkzumuBIFcwP1MxkHbuOI/mwVodiON58mzESTZDE=;
 b=KGNoYirOROXzX33GqYrehu6ZMq2PZki7M8CDAC5uiuoJ0+OHTOp7nQM5USU/gTddY4AuZauLqaoYG2x/57wIcaX2bSs7CstSQxHUDJ3at/ZTHIfXvWbpjiZVKnVdgnPtyeYWgVWdohTdR0lMBd9tABb07+69m1XfYJd0Kury1MqJbJ9blYgCnA3h9ppjdiqvIPovbgMLes3m3csuO+S+TTz90lW3Bpu6hKG/OPC39iyViMSv9qX1apj0uBd0AMGJldr6Jjudqu77oD009ePW65NmDf3ikYANbdEo0kS1ow3Gg2dRQ1syaOeUrSqvAitXRsIVkTHfb/a6hBeNeV4jAQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB3537.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:23::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 07:13:11 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 07:13:11 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maxwell Bland <mbland@motorola.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
CC: "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	"agordeev@linux.ibm.com" <agordeev@linux.ibm.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, "andrii@kernel.org"
	<andrii@kernel.org>, "aneesh.kumar@kernel.org" <aneesh.kumar@kernel.org>,
	"aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>, "ardb@kernel.org"
	<ardb@kernel.org>, "arnd@arndb.de" <arnd@arndb.de>, "ast@kernel.org"
	<ast@kernel.org>, "borntraeger@linux.ibm.com" <borntraeger@linux.ibm.com>,
	"bpf@vger.kernel.org" <bpf@vger.kernel.org>, "brauner@kernel.org"
	<brauner@kernel.org>, "catalin.marinas@arm.com" <catalin.marinas@arm.com>,
	"cl@linux.com" <cl@linux.com>, "daniel@iogearbox.net" <daniel@iogearbox.net>,
	"dave.hansen@linux.intel.com" <dave.hansen@linux.intel.com>,
	"david@redhat.com" <david@redhat.com>, "dennis@kernel.org"
	<dennis@kernel.org>, "dvyukov@google.com" <dvyukov@google.com>,
	"glider@google.com" <glider@google.com>, "gor@linux.ibm.com"
	<gor@linux.ibm.com>, "guoren@kernel.org" <guoren@kernel.org>,
	"haoluo@google.com" <haoluo@google.com>, "hca@linux.ibm.com"
	<hca@linux.ibm.com>, "hch@infradead.org" <hch@infradead.org>,
	"john.fastabend@gmail.com" <john.fastabend@gmail.com>, "jolsa@kernel.org"
	<jolsa@kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "kpsingh@kernel.org" <kpsingh@kernel.org>,
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
	"linux@armlinux.org.uk" <linux@armlinux.org.uk>, "linux-efi@vger.kernel.org"
	<linux-efi@vger.kernel.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
	"lstoakes@gmail.com" <lstoakes@gmail.com>, "mark.rutland@arm.com"
	<mark.rutland@arm.com>, "martin.lau@linux.dev" <martin.lau@linux.dev>,
	"meted@linux.ibm.com" <meted@linux.ibm.com>, "michael.christie@oracle.com"
	<michael.christie@oracle.com>, "mjguzik@gmail.com" <mjguzik@gmail.com>,
	"mpe@ellerman.id.au" <mpe@ellerman.id.au>, "mst@redhat.com" <mst@redhat.com>,
	"muchun.song@linux.dev" <muchun.song@linux.dev>, "naveen.n.rao@linux.ibm.com"
	<naveen.n.rao@linux.ibm.com>, "npiggin@gmail.com" <npiggin@gmail.com>,
	"palmer@dabbelt.com" <palmer@dabbelt.com>, "paul.walmsley@sifive.com"
	<paul.walmsley@sifive.com>, "quic_nprakash@quicinc.com"
	<quic_nprakash@quicinc.com>, "quic_pkondeti@quicinc.com"
	<quic_pkondeti@quicinc.com>, "rick.p.edgecombe@intel.com"
	<rick.p.edgecombe@intel.com>, "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>, "ryan.roberts@arm.com" <ryan.roberts@arm.com>,
	"samitolvanen@google.com" <samitolvanen@google.com>, "sdf@google.com"
	<sdf@google.com>, "song@kernel.org" <song@kernel.org>, "surenb@google.com"
	<surenb@google.com>, "svens@linux.ibm.com" <svens@linux.ibm.com>,
	"tj@kernel.org" <tj@kernel.org>, "urezki@gmail.com" <urezki@gmail.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org"
	<will@kernel.org>, "wuqiang.matt@bytedance.com" <wuqiang.matt@bytedance.com>,
	"yonghong.song@linux.dev" <yonghong.song@linux.dev>, "zlim.lnx@gmail.com"
	<zlim.lnx@gmail.com>, "awheeler@motorola.com" <awheeler@motorola.com>
Subject: Re: [PATCH 2/4] mm: pgalloc: support address-conditional pmd
 allocation
Thread-Topic: [PATCH 2/4] mm: pgalloc: support address-conditional pmd
 allocation
Thread-Index: AQHaZDwW93UMB1leek+pWpos6TxTxLEUYmEA
Date: Wed, 21 Feb 2024 07:13:11 +0000
Message-ID: <838a05f0-568d-481d-b826-d2bb61908ace@csgroup.eu>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-3-mbland@motorola.com>
In-Reply-To: <20240220203256.31153-3-mbland@motorola.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB3537:EE_
x-ms-office365-filtering-correlation-id: e02f172d-bafe-43d3-7b32-08dc32ac9003
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: mqjDbMMeFWS4w5ziBtUy/MaPwTyexgL+HBLG2OjyBjRpqu9wdMWtYmT1Jd+hqZ4aDvryivArysylycvo0SfuawhNDhU8Gp7SZ+HSlCoyjvdueFcPBBG3qZYMy1TD0GEmtRG+z5yLwdG730YiKqqeuKhIEsdDb8iJJqHLoGDnpXF9wiOVuRkStOQLedQrc15eQghF8wfHC66wldBPNXNoruvmg2Fz5SsTbbu8cZB+fLhaYwQkVisvEaf+D9VOGxrTHOf7b/A6aE0uThoCZtM/BxIFpCDjNGc8vP7iMaSKtdN5SSbhwjac/QExfSlWSo465lxqArm609TsDy6sno0jm0GT8ddWGPp382AWsWc7eUkfluRXztRIVLR8gEn4tDAnI/LKQAoRbas8jNc3Mgjrpb0WoByj7Fs9UXpXG6vVMal/WUtXx+/5kvBUAS2VjvyQ1sRIXNEzqjCPPDi6aqrhgIEHTEBaNya8u4Qa6NDo268/dPKAHgbmpXkUzO5fI3XNJYMQldc1pNMQ2w7mJ2aPFsFktFDYPMyzP4t+04wk34kpI8anw5tYSAgxzTogEPk8CVkCVzvZ96SghUQIaUngWABzTuneWnaxkzUlzS+phtvb7L+9TAj3xEQmI1FOCfod
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MzJNc1YxeVJoS2o0YXY1b0p2TmNadHpsa2JYZ3ZESDJYU3B4aXdMeXZDblZx?=
 =?utf-8?B?eExKck1YWUNBQWpBSEFLbW55UkJKbEFHZkFybGM3VGxnRkJSdHJEbWRpWW4y?=
 =?utf-8?B?eDE3RWpVcFlOdDJUVDJiZW92d2h6L25CdnRoVmRRMS9rZThraGF4c2V1NXpK?=
 =?utf-8?B?THlzUzVIUnhaTXZTR0FqLzF6cDhuOS9ZWTc1emZqU0hiZFlRQkgrSmVyMFBs?=
 =?utf-8?B?Z2dRZHA0MVVnNXZTdGw2QW53QUx5OTlTRTZsb01qQThQcjR1MUhEWTNFWXJh?=
 =?utf-8?B?aUtqWmxpQ25zVEFRazhITXNEUHdpeHJYMUNjRHA4TlpqREMxRXNhb3k3M29y?=
 =?utf-8?B?Mmx4QUNidEJtNStRUzdjTU5DSEFFT3JQSGg2Ulp1UTRONVcwS3ZOSjV4VVgv?=
 =?utf-8?B?NHFySTE1T1AvQ1kvRGJ6VjAyNXFDRUJYT3BNdzVMd3FOb04valArR2NYWHda?=
 =?utf-8?B?UU9wckhvejRqV0l4WnlOd2txK2F0eFU1Nk1IbXNNQnA3MHFWY3hSbkhBT3RE?=
 =?utf-8?B?RjlPdFdCaGFmR1lKK0RuVXhCc1crZTZneEZONENRNEZiQnRLMEk0T25ReWJP?=
 =?utf-8?B?L2NFU3ZGVmNBMzVTdkJIQUJTODFWWkl4S29WVHQrYkNHTWgvVTFTSDRPWEwz?=
 =?utf-8?B?UUMvWkNSdzYwK09uWFI3RXFwZ09Cdm5abTB1ZmtyaEZzaTZnREphUjhQMEN3?=
 =?utf-8?B?YnRrMDBoekR2d2t3My9NcXNpcjNPZ2lSbHlVejhCaTB0aTh3NUNoc0p3NVNI?=
 =?utf-8?B?bjM4U2RZckpSbEZiZG9BZ3BaTUxaWCs3aVc3a3NKV0JWMUJNZXdYRldPcWdp?=
 =?utf-8?B?TzBxYms1ZWtnU2x6TGlkVHlMN0NXNk95MzRJckFFRDZWeDBHbENDOGU1K2pF?=
 =?utf-8?B?V0RaN05sSTM1UkVOcG42ZFFwdnZvRHozd2x3NEVmT1JONml6Y1ZYREJaNmUv?=
 =?utf-8?B?TmU5TGxUUXdIaGVKR1RPLzg3YTBYNS84SFBablhBVys3bGRXR0pQYjgvSnha?=
 =?utf-8?B?MXNmUjhScFcvODJsVmRFYXNKWEV3ZUZyWkIwei84NHY3bEZpS29iZVkrZlRl?=
 =?utf-8?B?L1hnUlJldzRRUlJpUG5UeFBFZjlPT21rVDRmVFZ0VmVFWkhYMlRKVmUxWUw1?=
 =?utf-8?B?TXNHK0gzT1Y2U2Z6a2dxTUJlSWdXVXFmcm5paThkTFVRS2dhbjBXZUtzaHhn?=
 =?utf-8?B?S0N5QXpoQ3JCdFVXOWJFTUxDaFBLcEtHTWRrWFhEK1QvZDh4Q2JqN0JEemtl?=
 =?utf-8?B?SnAvMVlEWU9tSkNOV3lFRFQ2K3dPQmQ2aHR3eTZ3MlZGNEl3NnBFYUYvQ04v?=
 =?utf-8?B?M2owUEdONXZqN3FvQjhIelI0K2xWUjhLbGV2NDZUbVExdVdha2dURmhzQ096?=
 =?utf-8?B?YW5jbnJlNnRDYWdVN2ZBL0M1QkVsVG1XWXEvSFlENFE0VHV2NkJlNy9xbXNx?=
 =?utf-8?B?S1hYUit5MThsbmNvQjJnWWJ1Y0JiOWFyRTJpTVFrblR6Rm1CTzhYbU44R3dl?=
 =?utf-8?B?Y2E0dUhIUVBqaUFMWjR6am9QR1NVS1JnMGtLZHB6a0FFc1FBNTJDMTkrYjZL?=
 =?utf-8?B?RzY3emxQM1FNZXJFOFgvOG1mQzlPbCtEWlFhZ0RaZ3prdXQyQUJNRXFEWHEz?=
 =?utf-8?B?dnBBcDlDZW5EeWxXWVJqaVo2L2JlaGNKcUZkU3MxRzZUSDQvbmFOQXFCU28x?=
 =?utf-8?B?bUllcHErb2xtMG1ma1p0Vk11d1BaTVE4aHNkR0xrL0lYeW5XRnBXaGhtTElm?=
 =?utf-8?B?dVV4b0FPTXRMdURObXhFbXFzNTl0dlQxMy9nblZNNzRkMklOYmMyMFYzL2gw?=
 =?utf-8?B?NHMweU1DeXRud3Y0UCt3eXZkM1dTRDBaU0NsYTQ3UHpxV2ZOL2lxd3M0WERW?=
 =?utf-8?B?N3NtdTV0U2lrU3JzREhRVlBiYnBrQ3MvVTBFbTlSYUJyS3ZScDVwcThOU0Er?=
 =?utf-8?B?ajNWTVNYVHNjTWl2eWs4QU9EMkgxRXI1U1BLZGVzaHVYUVgzOFV6WXJ5VndL?=
 =?utf-8?B?cHAweVppTS9nQkR0QWdsZHkwT0RzRFREM2pSbXF1MjVZeDBzdUdWTGk4c2Nm?=
 =?utf-8?B?aTBaaDNNbzR0cXdid3Q2dVN5VVZVNDVYMWlPVjdUYUI3Zy9Qb0piS2NaUHRq?=
 =?utf-8?Q?u/QeXgsMiI3r5YYaWS3qkf6W7?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <125461FB77418F46AE8C6E8B2BEA809E@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: e02f172d-bafe-43d3-7b32-08dc32ac9003
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 07:13:11.1296
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: yJfb6cutQTPCyzf85tiXIZidyjv7HiEbrZntqFSykrwPQu0mFVjHzhbgdsHQm0iSzyoxMX4opLCJpSCyJKskdksfsJKu+PLieDnF+nyg7lQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB3537
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=aUpfz4J7;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted
 sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 20/02/2024 =C3=A0 21:32, Maxwell Bland a =C3=A9crit=C2=A0:
> [Vous ne recevez pas souvent de courriers de mbland@motorola.com. D=C3=A9=
couvrez pourquoi ceci est important =C3=A0 https://aka.ms/LearnAboutSenderI=
dentification ]
>=20
> While other descriptors (e.g. pud) allow allocations conditional on
> which virtual address is allocated, pmd descriptor allocations do not.
> However, adding support for this is straightforward and is beneficial to
> future kernel development targeting the PMD memory granularity.
>=20
> As many architectures already implement pmd_populate_kernel in an
> address-generic manner, it is necessary to roll out support
> incrementally. For this purpose a preprocessor flag,

Is it really worth it ? It is only 48 call sites that need to be=20
updated. It would avoid that processor flag and avoid introducing that=20
pmd_populate_kernel_at() in kernel core.

$ git grep -l pmd_populate_kernel -- arch/ | wc -l
48


> __HAVE_ARCH_ADDR_COND_PMD is introduced to capture whether the
> architecture supports some feature requiring PMD allocation conditional
> on virtual address. Some microarchitectures (e.g. arm64) support
> configurations for table descriptors, for example to enforce Privilege
> eXecute Never, which benefit from knowing the virtual memory addresses
> referenced by PMDs.
>=20
> Thus two major arguments in favor of this change are (1) unformity of
> allocation between PMD and other table descriptor types and (2) the
> capability of address-specific PMD allocation.

Can you give more details on that uniformity ? I can't find any function=20
called pud_populate_kernel().

Previously, pmd_populate_kernel() had same arguments as pmd_populate().=20
Why not also updating pmd_populate() to keep consistancy ? (can be done=20
in a follow-up patch, not in this patch).

>=20
> Signed-off-by: Maxwell Bland <mbland@motorola.com>
> ---
>   include/asm-generic/pgalloc.h | 18 ++++++++++++++++++
>   include/linux/mm.h            |  4 ++--
>   mm/hugetlb_vmemmap.c          |  4 ++--
>   mm/kasan/init.c               | 22 +++++++++++++---------
>   mm/memory.c                   |  4 ++--
>   mm/percpu.c                   |  2 +-
>   mm/pgalloc-track.h            |  3 ++-
>   mm/sparse-vmemmap.c           |  2 +-
>   8 files changed, 41 insertions(+), 18 deletions(-)
>=20
> diff --git a/include/asm-generic/pgalloc.h b/include/asm-generic/pgalloc.=
h
> index 879e5f8aa5e9..e5cdce77c6e4 100644
> --- a/include/asm-generic/pgalloc.h
> +++ b/include/asm-generic/pgalloc.h
> @@ -142,6 +142,24 @@ static inline pmd_t *pmd_alloc_one(struct mm_struct =
*mm, unsigned long addr)
>   }
>   #endif
>=20
> +#ifdef __HAVE_ARCH_ADDR_COND_PMD
> +static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp=
,
> +                       pte_t *ptep, unsigned long address);
> +#else
> +static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp=
,
> +                       pte_t *ptep);
> +#endif
> +
> +static inline void pmd_populate_kernel_at(struct mm_struct *mm, pmd_t *p=
mdp,
> +                       pte_t *ptep, unsigned long address)
> +{
> +#ifdef __HAVE_ARCH_ADDR_COND_PMD
> +       pmd_populate_kernel(mm, pmdp, ptep, address);
> +#else
> +       pmd_populate_kernel(mm, pmdp, ptep);
> +#endif
> +}
> +
>   #ifndef __HAVE_ARCH_PMD_FREE
>   static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
>   {
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index f5a97dec5169..6a9d5ded428d 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2782,7 +2782,7 @@ static inline void mm_dec_nr_ptes(struct mm_struct =
*mm) {}
>   #endif
>=20
>   int __pte_alloc(struct mm_struct *mm, pmd_t *pmd);
> -int __pte_alloc_kernel(pmd_t *pmd);
> +int __pte_alloc_kernel(pmd_t *pmd, unsigned long address);
>=20
>   #if defined(CONFIG_MMU)
>=20
> @@ -2977,7 +2977,7 @@ pte_t *pte_offset_map_nolock(struct mm_struct *mm, =
pmd_t *pmd,
>                   NULL : pte_offset_map_lock(mm, pmd, address, ptlp))
>=20
>   #define pte_alloc_kernel(pmd, address)                 \
> -       ((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
> +       ((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address))=
 ? \
>                  NULL: pte_offset_kernel(pmd, address))
>=20
>   #if USE_SPLIT_PMD_PTLOCKS
> diff --git a/mm/hugetlb_vmemmap.c b/mm/hugetlb_vmemmap.c
> index da177e49d956..1f5664b656f1 100644
> --- a/mm/hugetlb_vmemmap.c
> +++ b/mm/hugetlb_vmemmap.c
> @@ -58,7 +58,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *h=
ead, unsigned long start,
>          if (!pgtable)
>                  return -ENOMEM;
>=20
> -       pmd_populate_kernel(&init_mm, &__pmd, pgtable);
> +       pmd_populate_kernel_at(&init_mm, &__pmd, pgtable, addr);
>=20
>          for (i =3D 0; i < PTRS_PER_PTE; i++, addr +=3D PAGE_SIZE) {
>                  pte_t entry, *pte;
> @@ -81,7 +81,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *h=
ead, unsigned long start,
>=20
>                  /* Make pte visible before pmd. See comment in pmd_insta=
ll(). */
>                  smp_wmb();
> -               pmd_populate_kernel(&init_mm, pmd, pgtable);
> +               pmd_populate_kernel_at(&init_mm, pmd, pgtable, addr);
>                  if (!(walk->flags & VMEMMAP_SPLIT_NO_TLB_FLUSH))
>                          flush_tlb_kernel_range(start, start + PMD_SIZE);
>          } else {
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 89895f38f722..1e31d965a14e 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -116,8 +116,9 @@ static int __ref zero_pmd_populate(pud_t *pud, unsign=
ed long addr,
>                  next =3D pmd_addr_end(addr, end);
>=20
>                  if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >=3D PMD_SI=
ZE) {
> -                       pmd_populate_kernel(&init_mm, pmd,
> -                                       lm_alias(kasan_early_shadow_pte))=
;
> +                       pmd_populate_kernel_at(&init_mm, pmd,
> +                                       lm_alias(kasan_early_shadow_pte),
> +                                       addr);
>                          continue;
>                  }
>=20
> @@ -131,7 +132,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsign=
ed long addr,
>                          if (!p)
>                                  return -ENOMEM;
>=20
> -                       pmd_populate_kernel(&init_mm, pmd, p);
> +                       pmd_populate_kernel_at(&init_mm, pmd, p, addr);
>                  }
>                  zero_pte_populate(pmd, addr, next);
>          } while (pmd++, addr =3D next, addr !=3D end);
> @@ -157,8 +158,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsign=
ed long addr,
>                          pud_populate(&init_mm, pud,
>                                          lm_alias(kasan_early_shadow_pmd)=
);
>                          pmd =3D pmd_offset(pud, addr);
> -                       pmd_populate_kernel(&init_mm, pmd,
> -                                       lm_alias(kasan_early_shadow_pte))=
;
> +                       pmd_populate_kernel_at(&init_mm, pmd,
> +                                       lm_alias(kasan_early_shadow_pte),
> +                                       addr);
>                          continue;
>                  }
>=20
> @@ -203,8 +205,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsign=
ed long addr,
>                          pud_populate(&init_mm, pud,
>                                          lm_alias(kasan_early_shadow_pmd)=
);
>                          pmd =3D pmd_offset(pud, addr);
> -                       pmd_populate_kernel(&init_mm, pmd,
> -                                       lm_alias(kasan_early_shadow_pte))=
;
> +                       pmd_populate_kernel_at(&init_mm, pmd,
> +                                       lm_alias(kasan_early_shadow_pte),
> +                                       addr);
>                          continue;
>                  }
>=20
> @@ -266,8 +269,9 @@ int __ref kasan_populate_early_shadow(const void *sha=
dow_start,
>                          pud_populate(&init_mm, pud,
>                                          lm_alias(kasan_early_shadow_pmd)=
);
>                          pmd =3D pmd_offset(pud, addr);
> -                       pmd_populate_kernel(&init_mm, pmd,
> -                                       lm_alias(kasan_early_shadow_pte))=
;
> +                       pmd_populate_kernel_at(&init_mm, pmd,
> +                                       lm_alias(kasan_early_shadow_pte),
> +                                       addr);
>                          continue;
>                  }
>=20
> diff --git a/mm/memory.c b/mm/memory.c
> index 15f8b10ea17c..15702822d904 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -447,7 +447,7 @@ int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
>          return 0;
>   }
>=20
> -int __pte_alloc_kernel(pmd_t *pmd)
> +int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
>   {
>          pte_t *new =3D pte_alloc_one_kernel(&init_mm);
>          if (!new)
> @@ -456,7 +456,7 @@ int __pte_alloc_kernel(pmd_t *pmd)
>          spin_lock(&init_mm.page_table_lock);
>          if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
>                  smp_wmb(); /* See comment in pmd_install() */
> -               pmd_populate_kernel(&init_mm, pmd, new);
> +               pmd_populate_kernel_at(&init_mm, pmd, new, address);
>                  new =3D NULL;
>          }
>          spin_unlock(&init_mm.page_table_lock);
> diff --git a/mm/percpu.c b/mm/percpu.c
> index 4e11fc1e6def..7312e584c1b5 100644
> --- a/mm/percpu.c
> +++ b/mm/percpu.c
> @@ -3238,7 +3238,7 @@ void __init __weak pcpu_populate_pte(unsigned long =
addr)
>                  new =3D memblock_alloc(PTE_TABLE_SIZE, PTE_TABLE_SIZE);
>                  if (!new)
>                          goto err_alloc;
> -               pmd_populate_kernel(&init_mm, pmd, new);
> +               pmd_populate_kernel_at(&init_mm, pmd, new, addr);
>          }
>=20
>          return;
> diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
> index e9e879de8649..0984681c03d4 100644
> --- a/mm/pgalloc-track.h
> +++ b/mm/pgalloc-track.h
> @@ -45,7 +45,8 @@ static inline pmd_t *pmd_alloc_track(struct mm_struct *=
mm, pud_t *pud,
>=20
>   #define pte_alloc_kernel_track(pmd, address, mask)                     =
\
>          ((unlikely(pmd_none(*(pmd))) &&                                 =
\
> -         (__pte_alloc_kernel(pmd) || ({*(mask)|=3DPGTBL_PMD_MODIFIED;0;}=
)))?\
> +         (__pte_alloc_kernel(pmd, address) ||                          \
> +               ({*(mask) |=3D PGTBL_PMD_MODIFIED; 0; }))) ?             =
 \
>                  NULL: pte_offset_kernel(pmd, address))
>=20
>   #endif /* _LINUX_PGALLOC_TRACK_H */
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index a2cbe44c48e1..d876cc4dc700 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -191,7 +191,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, un=
signed long addr, int node)
>                  void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
>                  if (!p)
>                          return NULL;
> -               pmd_populate_kernel(&init_mm, pmd, p);
> +               pmd_populate_kernel_at(&init_mm, pmd, p, addr);
>          }
>          return pmd;
>   }
> --
> 2.39.2
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/838a05f0-568d-481d-b826-d2bb61908ace%40csgroup.eu.
