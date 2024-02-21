Return-Path: <kasan-dev+bncBDLKPY4HVQKBB7ON22XAMGQEODTVV7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 81CB385D167
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:32:14 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4126c262040sf9224245e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:32:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708500734; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4717jsXe7bM1fldYNcomcv+g+7U7Zyb76hkm7TILfYdeC76LYISGFVzcrD3LNmHXy
         rDP5u/boEphu2d92fdtvKpFxNA2FwuqVG/KhZKe0ALxUiYu2Gkhp2zNKybH37RiE564s
         b275mOmhVgWYL1/z9UyeVLB2Vry2Pw5yPJ+L1FWkCRW9rqL4t8Y0vBlO0fKDqQAUYOoJ
         SRtSxqmw751ZmTJ858Zre2q0XI9KFvrhWhY1Uo5jKjZPz+CiE8n3B8OVPDgmT8bweOSW
         umCL/mUTgkB09uaj4hDXpEwEU2MdPxFrIDlSzC2SIisIUMtzYbr1nvWx/+ch9bsEEAAg
         dORQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=myjqoFUnBY/xH3qvphFpZCCaa0jPiMDghIsc9veXqR0=;
        fh=qEtMAR7m7m4fHoeEdUmahzLi3eu6YeAi8LfvugVDqOI=;
        b=Fd55SVjYbh9MwGhcR1B4qt2Q88Px9Q/GX5BhQG9bMwiJb5JHH5E+rXcibYLJmckvsz
         Bn0DZqO99LR6LhEM9aTRPIW3/aPb/5+wQWRjGFEZ8GUmJAFIeIg+cUYW8QrYC1ygh2ZU
         turVkfjFxMJuNIesAzLKBoU1Ex8LFn6OcSjSLLfgX7648kUW94GtbfcS42GMA79l7W8z
         lrIyzmHg90Qj4aM6eZ7EKiD48PVWfuTbgT2XEcJyf8/UdcG++4w09ydQuJvvISJILAXn
         GWJX3WaiZ7qrMP2pRGGqG6Tj7tkLnAzNJWGxLA2DssAJcN2S5vXX2OBkKV6o+uqRJVq7
         omJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=H3mXfIOs;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708500734; x=1709105534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=myjqoFUnBY/xH3qvphFpZCCaa0jPiMDghIsc9veXqR0=;
        b=NUc6kOiBrLiumEwTaz3at1GzK+n+E7O3DSRaoPM0rB6s6Xiobnkp5A6tHF2Wolz+3K
         WYx4zwuxz7Nfaf1aCqGcaKGEfxD97Ph1ToiHsNhPz+U8uzG49GBtYYP1r0qvWl1/EBeI
         wuz6P8ht15S5rDi2oCeLSky6sBY9vzdmdPXIYj2JheCi8mNU9KmMbLzqOJA2apfWAc01
         aWd3yk+C1YdPpqRz789Dc77n9UvCxfu63UyL2a+RaEkhc/vgfH0IOmh1pO+YlrdHlkvX
         P3EfhjWafmNshyni4ForgiBGoVqDVfqYStMlxNIcgpwY/ZephlJkr6G0cxLjwqMnaYl/
         cY8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708500734; x=1709105534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=myjqoFUnBY/xH3qvphFpZCCaa0jPiMDghIsc9veXqR0=;
        b=qVA+q0M9OfFhEIL4JPNdT0P3JIatqZaFAGnDy8/ATg2zj4sC50db/BK3UJmKBGT7hx
         IpfJoVei949Yebr2trkgTGsKZnsSPZggX4dS4yONRahK1QrqGmfovG+AyKUmJJiH4wzK
         DGUj1DHYI4GwQTRb+X4Q/okncB3JV8Aiio3nvjyGEJkhVIEnPaBlxhTrnE2AcfEthrE3
         lLzol3dtcJIA0l8NZh3xYl5Qs8bZmJAlwZw93uK5gZ8DwJuBmjGMpxcpvyhMoGAabCtV
         xxkCy3REqKYy73ZMrAUqz/xtPvC52AgnIspgvDhZzFjtoSc7SoLh8U8cC/8tEkieoL+6
         48iA==
X-Forwarded-Encrypted: i=3; AJvYcCVk8NsOb/JtIwIpFU+2oip3qi2fEMABHgBb4NMJVBIwVVsHY+Y7jX7QTlMKjS2Jo3raXQi64Zuipy4gTikxvMnYS4Qcdvad1g==
X-Gm-Message-State: AOJu0YzP/4Jb0kW7ptAT2No1TpJnZ6LFuuhjzWQf3XTfaX7lmO4Gey18
	uHWR1IgACcvltAPAvm7WJul6DLTX7T2vb0wOHeh1+OKd64ce4HQ2
X-Google-Smtp-Source: AGHT+IFEwZDZ5B4hHPvthhEWWbj35mHAaiPfcSOSMxAtq+Cphfvzfdgbs6BXsoJiRqBlodOV5GHwKQ==
X-Received: by 2002:a5d:6d8e:0:b0:33d:4868:273d with SMTP id l14-20020a5d6d8e000000b0033d4868273dmr9489455wrs.19.1708500733679;
        Tue, 20 Feb 2024 23:32:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e23:b0:412:7878:6231 with SMTP id
 ay35-20020a05600c1e2300b0041278786231ls21935wmb.0.-pod-prod-00-eu; Tue, 20
 Feb 2024 23:32:12 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXgWrDGR9l3SvT6vZsxk5atFbCI1J57rfFpgdDeIbvQqVcOTarF1HK6IM+kNcYR0AYk/jLgzdw4J5K54ip/iw0DY+Pvtpa+9jr2rw==
X-Received: by 2002:a05:600c:19c9:b0:412:5eba:c155 with SMTP id u9-20020a05600c19c900b004125ebac155mr9676618wmq.11.1708500731981;
        Tue, 20 Feb 2024 23:32:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708500731; cv=pass;
        d=google.com; s=arc-20160816;
        b=h57Wg9XUBR3xe56qCOyc/UBRYuglMk9yFfbUCHZ+uXSZ7t0u2hUSKxxaArRWSBUm1p
         p0Ib9VY+mG0R5wf2FZONxaTO8OnIfdol6gLUvKpAZfrk03OMZ1If2C0Bx/ptNh5Km3UW
         XSHrugDacZytEEpjpy9MDV8EbexU+AtYaBk9YD50eW7DM44ykhs5RXyZPIwm30pKZpuW
         4Yqg3kn5GWp1G8YuP1B6IYwx1qq1XqjMLKDjYYEfVjVMPZzws/CjpjB4n5UjOH0Bj4zK
         rJPcRFZ6EHMTodGftfEgnQQMbMb2EfSldB2UTh+/IWpGN2ihD4MhxKKu+/FUW9q5n0oQ
         xEhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=myopBb3edsQIuwuiK+u4DVa5+NjagIv+wRUsTqlc9ao=;
        fh=0/nJWjGjUDnfJAXO9tPU9tkn3rnQs7SlLqPGDpCOlAE=;
        b=j35DxXqqVL+IvJvjVaZGYK8OAHZGDtxXcujahBizZtClKfwIkFYiJIsh8M9VmPu1uX
         QE7oESkUXskDgEQVi/jm1pt/VG/p3DBre6RoXQ/tmSeJQ7Q9/Fn18jbDblcF8aCaq6o5
         OQvKuAD7LSiZq0o2BHeq8EavuATeOk8h2r8cGSskmFCkB019OLr9QZjJptA9VVJjuZo7
         c+PIJU9CIxJaHhxP6dKwIPL8MK8wQ8rDoAdioVox7Aa2ngfWVw1PGM/NxoxIDY2cyqTs
         5X2OXN4/h7Mzru4bmtKaFrjytzuRX1Sopfibi9Qv6ELR973yR1bwlD1WADACHy7NTiw+
         Hkrg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=H3mXfIOs;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20701.outbound.protection.outlook.com. [2a01:111:f403:261d::701])
        by gmr-mx.google.com with ESMTPS id j14-20020a05600c1c0e00b00411e6461fa7si40914wms.1.2024.02.20.23.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 23:32:11 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) client-ip=2a01:111:f403:261d::701;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=I1bmX8Ce+l4FjBwbLlCCEJkdj8Svm7S8o0wmYD2l0YbBgLoe5PKedatp+CP0lEtlULOVzXSDQKozXZ3Cy6B/7/gI83bkXvbI29dFM1a6iqQcsJyFzRpfcO53t7f1yW1p8+xAQoiS1frsEt1jiOh6xOG86uza+l88xsQbKqpDoCghGUcJfRIWe4Mh4h9w32yfboZEZImU0yatzExMOERASXzx45XVhRdtEQ6hbEan2n2ilYadWG1bfkF5PHQWPaL8T87tBtxXztZkosmsvOmF7+lGaO1ItkhX5NyiO5qsLFCeqP7DpKDhChLj9ox/JAp0rezKnIEf8/iKClPQsXjnBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=myopBb3edsQIuwuiK+u4DVa5+NjagIv+wRUsTqlc9ao=;
 b=HbajcpleRD/j39bvBgXNfoO8AhKUqaSCW/pw6xtN/xweg2fDHoOh7gipxgRITsqqogozE7swRHL0ZsRyli2YXwo7rq9cDc6kbdmPAHDWb1CLILJymRroLEv/4PclalGlBwj1y/4G1B0E8CZfAEwiD4l2czxhvbTfOVg3hBJdRkuuwLlcPFn9p5G9ZCwHtFff3CeY19vZsH5RPRSHoTuqRJPlPec68YKKuUkbevM53c0ItcoWxFlPTgRy+ARRK4AU6TEcHrfzqsQG881twT/bQPJVdLsflVz6gav9q9CKA9b+vxWzoj/eU8Sb64OS+pFocxw2gBkYjkBjakFd4Z16aA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR1P264MB2109.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1b1::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 07:32:09 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 07:32:09 +0000
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
Subject: Re: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Thread-Topic: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Thread-Index: AQHaZDwS5UJxmu/gN0awDwkY2kCoDLEUZ6+A
Date: Wed, 21 Feb 2024 07:32:09 +0000
Message-ID: <4368e86f-d6aa-4db8-b4cf-42174191dcf9@csgroup.eu>
References: <20240220203256.31153-1-mbland@motorola.com>
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR1P264MB2109:EE_
x-ms-office365-filtering-correlation-id: f23273f4-db2e-4c88-e1a9-08dc32af36ad
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: k7+ekNLSaNiCmwoc9C+wCy19voCsyW0XgV1aYjzRxQA8Orsm3U9dpesJUzhZdK7sha8CuJvG0vZsDLVHsO7eJzAiS+y4gB3y7r/63RiKqmfzRUnxgwU/4uOmPFXuR4rKkL/atQwzhwg3zFLvUS7JJsFTW6wXhNJAu0/1pFAe2GaclidoIVjYOBOrZS57IfDBSgfUtkilBGLUDlw5+KpD9wzlJPRiBs+sBxSwj34Z3MfdaEjOnyiyu7v1VH4liSSrU1Yq9/wxcEd0riTjVb/+rYblEy/GjP+5NfVPzsrVbwoZI1Fk6rf1y6Zs7bB4/q3cOBDYSwQKIyyhoJw4JiPwc+JVPOdv49Jojd4qOQX98RVJoX8/vvQ1xr2TozIPjRcwIx6PCura5bpqQKVfOp4D1ZMKrJXUxHxsADi1l7xs7zATWyVQaALvx5ECunGvzT30MiYxqZpueltiyYxgmUBFnUqQuTwLwIuKR5xk+rWSv1FTNqnB8ChEjDSf1Pr4cKVqVypKBuTp8heyFI1yptuy1q/U/BGOcvRRVio7QmBzbMQYPxv9229Gaso8Thf/upsalL2X0G6dYb03fxpE5WlEga00M0mVSiwQCJ4+frok6QkGv9IFSqb76crkpZU0cjk9
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?a3daQWQ1bWdFc3BySmpEZ21yVFlTRUcrYTFmOGpFMVJpUGxpWDBuaXNjUHNF?=
 =?utf-8?B?MU1PSnJMWHFZbnVGc1JYbm1odDZLdTVOaFQvWWY4RHVKRkhlTk1PV0xBQ1Zi?=
 =?utf-8?B?aWtUbmkrQmpoQUxBVVo2V1lwU096L1lWNUtuWmh5MlNZYnkvZ1k4WlpYZGR4?=
 =?utf-8?B?V3VOTmp5SEF2TDZVTnRweU05RXFlZDF0TFc0Z3dxZW42Q0lOVWV2ZE1WY3Iz?=
 =?utf-8?B?cnVSdXJRTWRNdytFeGtkMEdTSW5Ua0F1ZmwwTWdOeFBTQThkYm84cHRMczJ4?=
 =?utf-8?B?dDRhcUppQmFyb2I2NlBXRWdHZkc2UXgveUhmSktuVytGczVEd09DSzA0Q3dN?=
 =?utf-8?B?Q0k5amh1RDBjaDNGMHFmWUU1Z21pRUtUOFRNUkxYUkFjTzdqVXAxN3ZBMjdi?=
 =?utf-8?B?akV0MW5aMXh3WWN5dDZDRHN2YnFXNzlzWTJWMnJZQzVOWFE0Qmx1b3ZUd3Qx?=
 =?utf-8?B?eE9kdTdxUWplbWlTanR6Z0Q3WEVzOGhNVmVEVjRIdVA3TURadE01RGZlTkpQ?=
 =?utf-8?B?ZFdrUnp3blF4b3NVNytJalBMZUNrZXhFNTRUSEZaWXpKZjMwV3Q3OE9XLzRJ?=
 =?utf-8?B?cTZLbDdHWUxMQXZ6YUJPYW1hYnYvMXc5Y3lzZENDVDBDU2pUSXkrZEhyMU41?=
 =?utf-8?B?MkhnYkxKdmdQczJZS0NRZ3ZheUdzUHBBMjdkV1Ftak5acUc3Yjd5Y0J4Wmt5?=
 =?utf-8?B?VVVRZ3c1K3NOQjBLQXRsSUZzSHBzVVc3NzZQaUN6S2tnUFZINDMwL0lBbk1P?=
 =?utf-8?B?aUVhd3JhclAvTVFsMHhMUXNDb3M0OFlhQ3c0OXRZRS9VUWJnWFJGUzBXdEx6?=
 =?utf-8?B?aTBJM3h1V0h4U0orL3dGRUhHT0lOQytkQWM5UGY5UVdtM0JvelYxR3RqUU9V?=
 =?utf-8?B?WXhmdTVkQm8yQk90ZWx5eG9EVlVEbitndHpDOGhiZDhFRjNvTHZLRGRWaitQ?=
 =?utf-8?B?REM5RVBrQXMySFp2SVFpS054Q0hXbVZRWkwrQWxEMG5LSmxvWndNd0hNWVN3?=
 =?utf-8?B?aitGOGI4Z1ZmNHp4blRKWmhSeHVTWVBlTUZMK0pUZStmbXN4Qi9ENEYxNVlR?=
 =?utf-8?B?NWlXTjYxRjI0aFVpeFg0OTVmSlo2Zk15NlZ2a3Q5WC91Tm42d0NITWVwcVgr?=
 =?utf-8?B?WkNkNldnWnZhT09LM1ZId09LOUJ6L2dBc2pwWkhzV2pyNllhMzQzKzlGTWx0?=
 =?utf-8?B?UDRCVTU1SlNVb0dUS3F5UWZPcmJZK2pZMXkvSjhzV0dSSDE5RmJGYlJISklz?=
 =?utf-8?B?US9saXRxRWNqUGhuQURXS0UxNEdxT2h1dXFaekZiZXdRY3RXV0JSbDJkdjNL?=
 =?utf-8?B?WVV2WHNQc2M3M3JtN0RVY2JFYmdNTHdHK2dwRkZhdHNCN1QvVDlxbE5OOFJN?=
 =?utf-8?B?MjdKTGZXYlNaNHNya3NDdVFNdG9nN09qbEhmMHU5bzRBK3l2dmIxRDBUS3NS?=
 =?utf-8?B?VHVvU3hhVHdiWVhseWZkOW5hQzlvSEdUbzYzd3NuaUFMNHlwQmcwaEZhd3FT?=
 =?utf-8?B?a0VNdllXZGgzZjhneXRtTU5YRmw1MVZJQnZWZlRjUmMzUitpTlFMWHllL2c2?=
 =?utf-8?B?dzlST1BMb0czZUVHc2V6emlVOVNpeTBUVE5rcy9PbW9tQTBGTWlyZHhUem1V?=
 =?utf-8?B?ZndDejcrK2hYcndZS2FTVTNlODFUckoyVFpjQUlxdmRFKzN2dnZMTjJNMDh1?=
 =?utf-8?B?VEVDSlNsbjdEbkRoSHZPQTNSdThMb0lGWEIyZ2JsRHBtTzBTdUs2dnl1em5S?=
 =?utf-8?B?bmJYeEVCeXo2REwzM203bFJLM1J4NVIzcVZHbktzbmFFTU83VkU5UDRSV2h4?=
 =?utf-8?B?U0N4NGF0SjFZT1BoNVQxcVVpc0NuOW5PaDNHbjh6ZExVMTB3R25SU2NIUldk?=
 =?utf-8?B?SUFIU2RGbWcwV1dKQVg1UzlXRWhUMzgwZ3IvbExvdHp1dCtjdVpId21rbFVo?=
 =?utf-8?B?RkJTUWdRc2hQTlU0K3plMDF0YzJ4NDNSNzRvYlFJNGNMUVJTSzFGU0dEbXlh?=
 =?utf-8?B?MC82Si9OL2JibEhjV2ZNeis2dlFYZitqRTBUZ2hHVDFZcGxqdTBTTzlTaGdo?=
 =?utf-8?B?bVIxeHJuMzdtTHFNaTV6UlZwWFhuWFRHVVFFYXJaeUNUR1FUaFowZ0hwb2Za?=
 =?utf-8?Q?WLXugoi8kZUVnyiCLBXuAPOox?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A4CF3C4C5DAEB14EB9859660BADFDF9C@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: f23273f4-db2e-4c88-e1a9-08dc32af36ad
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 07:32:09.7438
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: tci4GFI2Jf1hiYyW1khtOKki2yqiS6g4KMOybofoZ9UHzgk3uoxxse/khcOJFfKMPZadFaEV11P3p/ziFDYqFhCfdyblUCIT2lbcUvj+oUQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR1P264MB2109
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=H3mXfIOs;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted
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
> Reworks ARM's virtual memory allocation infrastructure to support
> dynamic enforcement of page middle directory PXNTable restrictions
> rather than only during the initial memory mapping. Runtime enforcement
> of this bit prevents write-then-execute attacks, where malicious code is
> staged in vmalloc'd data regions, and later the page table is changed to
> make this code executable.
>=20
> Previously the entire region from VMALLOC_START to VMALLOC_END was
> vulnerable, but now the vulnerable region is restricted to the 2GB
> reserved by module_alloc, a region which is generally read-only and more
> difficult to inject staging code into, e.g., data must pass the BPF
> verifier. These changes also set the stage for other systems, such as
> KVM-level (EL2) changes to mark page tables immutable and code page
> verification changes, forging a path toward complete mitigation of
> kernel exploits on ARM.
>=20
> Implementing this required minimal changes to the generic vmalloc
> interface in the kernel to allow architecture overrides of some vmalloc
> wrapper functions, refactoring vmalloc calls to use a standard interface
> in the generic kernel, and passing the address parameter already passed
> into PTE allocation to the pte_allocate child function call.
>=20
> The new arm64 vmalloc wrapper functions ensure vmalloc data is not
> allocated into the region reserved for module_alloc. arm64 BPF and
> kprobe code also see a two-line-change ensuring their allocations abide
> by the segmentation of code from data. Finally, arm64's pmd_populate
> function is modified to set the PXNTable bit appropriately.

On powerpc (book3s/32) we have more or less the same although it is not=20
directly linked to PMDs: the virtual 4G address space is split in=20
segments of 256M. On each segment there's a bit called NX to forbit=20
execution. Vmalloc space is allocated in a segment with NX bit set while=20
Module spare is allocated in a segment with NX bit unset. We never have=20
to override vmalloc wrappers. All consumers of exec memory allocate it=20
using module_alloc() while vmalloc() provides non-exec memory.

For modules, all you have to do is select=20
ARCH_WANTS_MODULES_DATA_IN_VMALLOC and module data will be allocated=20
using vmalloc() hence non-exec memory in our case.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4368e86f-d6aa-4db8-b4cf-42174191dcf9%40csgroup.eu.
