Return-Path: <kasan-dev+bncBDLKPY4HVQKBBO5622XAMGQEFBOYHOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E70885D0C7
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 07:59:09 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2d230281e63sf27293541fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 22:59:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708498748; cv=pass;
        d=google.com; s=arc-20160816;
        b=jTni+BGIeWNCjpcsGDUnaznw3kqnxtRkUt6evyjxVqXsHbdnmTjDl+Ac8Q6cOahnKN
         A7hkPjiVTuefXnQdE+QfM4uch5YsOm1RE35IiVUzqfFtpqfGS4ZDTDcsnfFu7aMkPuCr
         ZdSNCEBgXiwzVx9eLten+yUNEeybC6ATJZMRRDOR3Z82HEMv4AQQXMxdlRyPrN1FCYYb
         AOmrbjhR243wFjE0BA7iu0ZpLoZDSAmIviy73yjjN1KAeCxhDZltcojE1+kdaR6zJx8b
         0ltMbtk2YEG8eefDYcWPOxWAu1kSnLErvDvGZrcbb35SFG/xBhB/lywZYKuTLlHfzeYm
         crug==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=nWndnf/Xb1neFKmk4haUyPWzrtv9bQIbQkTJT57z/jI=;
        fh=B/y6AQSa7cSojPqD6+kuxgnV8L0D4vNgdmWllujRE4g=;
        b=HC8LJEIE1Zi4w7JwJtO3yDjc6KxJhnLtziio7U6sYAEPmE1DAsmWVRHXDpr7vSHwUF
         vQAhwoxI8vWnYdZyB0haZarfXOKvTsMhxLfA3PrlP4GlRNfeyVnyRyh3KsmGUwU7et0+
         j4mBdC5tGgYGluI/k1Ku88ZiUNN5M7wxyYB+UXciSLnHEbHiXH/cgJv9x/VZhO7MNdI2
         j7VpYgpuK+mVXGxChYwC8S3OIFxisT3JReSBvYoIBhuy3bh69pz0BNCgyHjs2BTL8MBI
         2U9cL5ljJAfsBcDSjlqxlZyPYGVd9pF21LFoBe5wjeavS4ebp8lHZLxUWWQjBTNvk4Ka
         w5vA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XqqDLxQb;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708498748; x=1709103548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nWndnf/Xb1neFKmk4haUyPWzrtv9bQIbQkTJT57z/jI=;
        b=sm/iBE21aG4pVy+E8cFb3RL1DTOvk5wjr5frKxHeKDQCzLTGx1qB7EDEas04Q5YGhe
         G+uTNPVtF2jDkQgh7n2mqIz2lP1TVxdDheji0D0bNhpyYxJ/NAVXUy2XzdA/TEkvCH42
         b7hP4nErmtBqpjJ1gKRllTnilbDVxlLdJtIck8EwthgCiWIig2Y1yOOvJlcG/fAO0Jvc
         iifgQW46elFXJZzvbZu+XTjdZt6BO8URDHreZ2UZ0K1RAAJMIEKGZN+FzgH7ZNuVYFGh
         A+oxXSW4KVtBq4qRuanyzQFn+MwAzTbS3xT/8LFVyadW5bCWkPq1lY/jRnMxYcoCDrMZ
         x7dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708498748; x=1709103548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=nWndnf/Xb1neFKmk4haUyPWzrtv9bQIbQkTJT57z/jI=;
        b=wbRlVAwHPksqJU4nHPTBH9Gbwi4/QpFVV2yCkZPAZz/xk9F52LpGNHqD0y0YbI/Xwj
         I/HHyrW3Tg7YOQ225WBltN/6Px+MZPxhYbXqJy8oW6oIxGx925GoQ0OBB7ia5u7RbSRa
         HlS9EaU2j5xD5REPrT+r35Xa/RH35TZRNxcPDctdsxSizApQvtr3WlwjZfiuaHrwWtpE
         yqYOkaF7p7AlRydLK7aG3amec4dEAtIcjY7EsYH3sGlZqPXj8K1iRIaQf6YhSiwOi8dz
         8nzrMyM+hfXrnusYYPsFCi9rHzQgJK6CPmL+BGgZ6BQVV1k8L6/y7XxkJrmMBq9IjzXq
         aDvg==
X-Forwarded-Encrypted: i=3; AJvYcCWL++3a1/U5Eiy/lgLbPBndNnvuULbcCV0+fICoQi1LCMhGgbx2inJ49rxrbj2E1QZ4JeRvd9PB85fYJuHXALza29u1lEoejA==
X-Gm-Message-State: AOJu0Yxj0DO+6Vu3aiO+ABSucaeFYsFrBuWU5U+IsqzB0Ey/cwnSsdjs
	5T2M0y/Ap680K1QXvogeNI6lBwFjU7oUdgeieU6gQJxgXFUzPUAl
X-Google-Smtp-Source: AGHT+IE9uiNHnpqTYLyMnYPwTZHMoKo7ay99yc30B+2cghmXVruAjTeodqlZBAkv1INkjTscP/QeQA==
X-Received: by 2002:a2e:3a16:0:b0:2d2:4391:484e with SMTP id h22-20020a2e3a16000000b002d24391484emr3431111lja.15.1708498747995;
        Tue, 20 Feb 2024 22:59:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a442:0:b0:2d2:509e:a90e with SMTP id v2-20020a2ea442000000b002d2509ea90els7139ljn.0.-pod-prod-02-eu;
 Tue, 20 Feb 2024 22:59:06 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWGzF0Hkq5ycCGVk8L6Uxv50w3dfiA18jtQ5DgCQ6mfS37B7Y6YsrtuU7BUi47iUROwxUPi9e1yJERGTsNFEXlB5sRtUPpkdUJDBQ==
X-Received: by 2002:a05:6512:280d:b0:512:a2fb:4a7a with SMTP id cf13-20020a056512280d00b00512a2fb4a7amr8164476lfb.68.1708498746007;
        Tue, 20 Feb 2024 22:59:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708498745; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gk5phqDuLtgFLEQ2C5MD7hjNK+ydvikvpOlOfVFuMalhu+tS6vFGuJyco++erMB2VR
         HlbG51GQQzBk1ohVU6c2zuEO6BH7HAOo9PsivXzRCleI37NvLbzA4m3gpA6lH50hTouc
         Vi3iqWEuH9VNYDgxVFlFqS9PlqpaiwlwEAI85KF5Cvx0z3UBN7m2esySeQd1Rt44kGE4
         coB5FtwGLXraNXyDjGbC8nEL5yMvcmFltVsTynbMBh9fZM4WMxlth0nbccy+9fhVJ1G4
         DkL7aW9KX11PloDDGfAjI2eE1W4eXWO1I8nEH5YS44Uojz524AF3EpQMSvdoLMb6LJc1
         naeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=NZh/o3+ui/KR67Kpif2Y2cLLTahL2J4AlYhkq5tZjXc=;
        fh=0/nJWjGjUDnfJAXO9tPU9tkn3rnQs7SlLqPGDpCOlAE=;
        b=KOJkaOr7xWiXf1mXAaIJfi4vVDRme99jQJ5BuDaJ7ZL1bO5sMNNnddARcaZa4tNcAz
         W7QeqOQ/pd92syTlPVsZceEWMGODj+S2fpbDOEQ1hmXPt0TGlpOFaRwfRKKFOLYKQenZ
         0yLYT6l6L+mhhHJ7nYVqDSwhG5+7zGvIqAJ8vBkHZhAxVq7eHRKW3N1/eZG/5TyzhRn5
         pvV6YwZHsN8l1lmV+1g1p1l7e2cOtTmEW8NKpugR9HbD8GGrEMt2jRPITo8jACIEYZlR
         qt9uhBIMLQWhkq2Si7/a09q5J5TefxXGOld5Q/4sF5ry5qgNKsAMHC7c/v6NHaHcGG7a
         0F5g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XqqDLxQb;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20701.outbound.protection.outlook.com. [2a01:111:f403:261d::701])
        by gmr-mx.google.com with ESMTPS id bp15-20020a056512158f00b00511539e222esi441959lfb.5.2024.02.20.22.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 22:59:05 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::701 as permitted sender) client-ip=2a01:111:f403:261d::701;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=MJx0i13yAqn5iCLJmw6SWsXcY7mJLsoZXcrK1h2d4IFevdtzZK0YLtCRcyQOeaHF6z0sS8l8oDCDcY2jna3YGT9scmXFPWrqvpdkRa0QhZsF/zS0FPg9wm0RPR8F3roPsJoGUlzIpLbaxg7nX6WmAq6lQ695ivbKOESAKGzIMEtZwTZW3Fl66XI1QnnkB9PWCNXFRgNQnQzczR0YkdScSiMH39gCKKQ3B74SLnU31keabzYctT4KzKQclqKOd0SOGwCdtZvoomZTWc7GNBbolbhcwqIXhN8DhdN0UCWgU/odKIfuJAmx0g+JUfizZ1EefM8G+8jzhk7CpOfKekdn5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NZh/o3+ui/KR67Kpif2Y2cLLTahL2J4AlYhkq5tZjXc=;
 b=cdodFNTXoKq9agxRrB1db/LuVYOw/4jLR2NhEc+X69Tna52XRp9cFJWGCVYAoMwAicd6JXMpmc6+/8cQaTHkWbWtwvHLRz/1YK7hVenXwD6/mhLMsJbKKK1qEEYW3aOW+hmUlvC9LEZqnxvzs/U0bAEqS5WiV/tRP9jbgWsNOF+znqdKU4iyrzdhGbsyt3SYS+njPhPXh1EIYTcgt0GzfnxHRz3fIyYuXTPV+48s3y4k/ZGfi62UFt1H/OrJSrujHR809Plk2Txpqh5cnN9Er0lqTd3puJJKQByRqg9aPTMd/UyPSYwRvK97r87RHqy5WkrpaqEmT7uDEaqeg1Vqzw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB3076.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:3d::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7316.21; Wed, 21 Feb
 2024 06:59:01 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 06:59:01 +0000
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
Subject: Re: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node
 overrides
Thread-Topic: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node
 overrides
Thread-Index: AQHaZDwS6FkPILIvP0qdTgNTWVgWnbEUXmwA
Date: Wed, 21 Feb 2024 06:59:01 +0000
Message-ID: <4026e0f4-f0f3-4386-b9e9-62834c823fc9@csgroup.eu>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-2-mbland@motorola.com>
In-Reply-To: <20240220203256.31153-2-mbland@motorola.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB3076:EE_
x-ms-office365-filtering-correlation-id: 66b64f21-cb34-4ac9-9ec7-08dc32aa958b
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: GLvBbtbz2pjCp3+xnGU/zvlOULtfi+T/ZwmErPr1nE2wu1XKC2j21vhlgVDNOsHroNo109P3sDLcuPxl8BCeE2Py9CL1Aso4S39shb8hq9TxzuEKtscjMnXZwBkro3xEnGSGH9qYZ9q7+FGVmfQsN4InNBXWNPhsmuRtmotj7UbzqxWEnn1BZZLKC8kEH2W8ljDy89efnWIU5ysnDg7AYZmtI73iob31O1Z3CvkzV0QKgRqedLZIdwape2L71IZU/wkuH4qaqDGItJWpUZ6AQx4R3O9MmACJukh7Ns23CKheeJpJEzUuE/p9u95MrhCT4zJnerhP4aVF0Bb0EGSP24v5I36VNP/pJq9awR2e8rkJkGdiuc7manrH0/qqkhKqnpbhJgBsNj08L38WVhKD6WwcEc5ZsKe+YNUYI9EJS98xgmu6UIcuChC5oQ0XlfkQ0LrXCJ3RQsUESV7tbszkKQ+6rP/hHjB3XM9FLhyhzZ+vlMYaAU3x/uC0/A4ITHNDTZHa+nSRa8eYinRwIW9ehXYytOjFqoo+P27gMnmi9zJxVNrypkCT3s12EZw99U2HyEXUsk2q5eP1+u70Cf9bga2goBZo46leMQXKxcnVAqwni9kdfHzS7N/UMn7d7xoK
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MW5iUXE1eGF2SGFiVzFtcFlEc2ZyUGtsS1NsenZvL0tybjl5dndPVCtzSzc1?=
 =?utf-8?B?a0k1MmE3VGN3WHhXRXdTaGdHZ29DemhraWpqb0F3K3JrZGgzNDlSWmNmbFdI?=
 =?utf-8?B?WmNrV0tmSVlqeUppbnJtd2hoVU9xaXB6Y0JtSG1ac0tERUtrY2hhVEVROTVm?=
 =?utf-8?B?R2hxdko3WWUrVHZPZUg3NHdWbVE2R1I5dEI4cE5HZUdrdFJzbzR4V2pSVWR6?=
 =?utf-8?B?K0JmZGhEMGRLNDA5cmQzSkdPZFpEMUwrc3dUbHJ3d0tTZDZjQW9sUlZhcmJp?=
 =?utf-8?B?cnVLYVdiMkVMaHkxM2IzTEdNTTF5Y2RYWUlnQzcyTGdWa29Mbm9qd0tjSmJa?=
 =?utf-8?B?Vmd1V1V6dlRJVFdPYUJwazhiaEVmZG9KTTRHNmI3U0VobmxWSExwaENjNUha?=
 =?utf-8?B?TFVLa1dscFNtaTh1cUl6YUc4QThFbjZ5SnJkRXVxRjFtT0FHM25kYzRDYitU?=
 =?utf-8?B?RGo5R3MrS1g0RXQ1Q0o5dGVPNDJSVVU2cXppWmo5Wjl4dTNxb29JTFFDQXNB?=
 =?utf-8?B?UFNmUHBOSUJUZ2l2Z0hMZEZkRUE3Kys5bDFlTkhOaVpPdklJWFZEeCtTR3ZT?=
 =?utf-8?B?eDhxaXduRVgrM2QveDQ1QjB2bjVPVnBwTEVsWjNGZkZnWmt2ZFRSNHhkQkha?=
 =?utf-8?B?UEt6SW84bWV2aDhRelJ2bE04TmhQUllzV2h3WXJVZlhERU5OeGc1VzhVTDVI?=
 =?utf-8?B?TFFoZEcvLzFiMlM3N3kwSW5QY1craUhnWFJ5eEZPRVRWSXpITjRZVXJJNWdX?=
 =?utf-8?B?SU81dGFQbmxWSFFwTEgwcC9KblRRTmNCMkJlWEttdXRnNjIrUHNaeFA2dUdH?=
 =?utf-8?B?eFJCbkRkQWZZeEd4RVMxMkZCSmsxZGdjQkRIcWVpSDR1MnF0WnBWS0NxbGJj?=
 =?utf-8?B?Mm5KQXZGVTJxT0NGcW9nMlFoSENSS0Vjb2EySGdtNEorVll0TzRkOUZCMzV2?=
 =?utf-8?B?ZUVKVVJpRkJNa1BYallTZzlUQXkwOUlGU3BHc3Y3OXdwMUowZ3p2NE9USUh5?=
 =?utf-8?B?d0duSyt2eGRlS3RHUnBlUk9XKzhkb0UxdWorakcraWFONlJXZ0Y4YnM4ZWhu?=
 =?utf-8?B?SlE3UmZZUWl2THFzcVh1cVVCdTAyODNPRms2ZWx2VzM1M3JaSjJWdGp3RHRH?=
 =?utf-8?B?UjhzelJITVdwRGkyb2VnbEN0bXQ0TklPSWcreUtvblNCYVhreFl5WUxYS1ZS?=
 =?utf-8?B?UStUYVMra24zcjFyS0ZvOW1zeVNsOXBCYkUrRmpVNjd6VHY3UVR1L1U0OFZO?=
 =?utf-8?B?dEc5YitPNUxZR3NMaUF2K2t1U2hGVElPVlNtWTlLak9BMjBiYkoxVDJicTNX?=
 =?utf-8?B?MzNGNXhwd2FDWWlmSkZMZUM5Lys3em9HWURXK3Z4ZmtuV0ZxM3cyeHBQcXJw?=
 =?utf-8?B?YlFUZGlwQVZnS1NJeVRkL09yTkFBbW1EeGQxS3MxYlFCeTRQaFVBUnJaOExE?=
 =?utf-8?B?UHhsOGNrdzBnaUZqN0N1TlVHWFUrQmhVT0dYQU5pRm03N3ZLVkRHei82M0E2?=
 =?utf-8?B?ZnE5TnpaWmZ6T1pWd1pRWkI0VmxBZ05uV3N5V2tCQ2hNb2lvS3hwdU0vUE1F?=
 =?utf-8?B?Y1RKa21WYTBhbUFhQ0ErUFF4SmNDTFRhMVhHSWxpLzBVU2ZZNk9IZjVOcU9a?=
 =?utf-8?B?Q0tOekRTempxYlJEa3phSm9PZEZsL1NmUDg4QjhvdXRQQ09sSmtMTkRBMVpE?=
 =?utf-8?B?NE12b0hNdWdISnBwa2xYWGJLbHc1Q1luWnJkMStBK3pmQ3Z1c09LMExxKzdT?=
 =?utf-8?B?amplVG04OGNZWDlCOEMrOFEwdWNDNFNPSlRLYkh2amZ4dDRDbzBhRzNmTVl2?=
 =?utf-8?B?Z24ydVFhQW4rVjEzTXNLV1NzcWtCNnJDY3hBcEJBQnV5c1lDSHdyL1FRZDR6?=
 =?utf-8?B?aWxDSExiWWNBRlBxWWNreW1yaWM2dll6MWlLS2lod3BWUFFEWDVSQUFSSS9r?=
 =?utf-8?B?T2thTHhPQmVtdXNxYXlzd3kvUUlMcmZqcUg5TG5sNlJSU1c1MWhUcjczUGRO?=
 =?utf-8?B?bGJmWDJMM1RCSlZnWHJJSlppQUdQbUVkSEk4QlB0VDNWcEVjUFZId0VkWXBu?=
 =?utf-8?B?cGdnRnArOEVXclBHckI5MUJrN29GbUZKR3RHNVNDT25rYW0vR0IrQWwyTGk3?=
 =?utf-8?Q?sTE+ogap5VBSh3fRT6zlURyEk?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <58C10DCF67DC9D429B875C322586089B@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 66b64f21-cb34-4ac9-9ec7-08dc32aa958b
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 06:59:01.4379
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: qYjoTbkPqVMyOC3HrSZ9P/dFzqn2QIEsWmID8i7rlxiy3zp/ayfZx+ZkwC8bMZdqIjxyYO1t6xJ/lhBQI3VXUa+HL9JmkSVIZfn3ghAP1VY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB3076
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=XqqDLxQb;       arc=pass
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
> Present non-uniform use of __vmalloc_node and __vmalloc_node_range makes
> enforcing appropriate code and data seperation untenable on certain
> microarchitectures, as VMALLOC_START and VMALLOC_END are monolithic
> while the use of the vmalloc interface is non-monolithic: in particular,
> appropriate randomness in ASLR makes it such that code regions must fall
> in some region between VMALLOC_START and VMALLOC_end, but this
> necessitates that code pages are intermingled with data pages, meaning
> code-specific protections, such as arm64's PXNTable, cannot be
> performantly runtime enforced.
>=20
> The solution to this problem allows architectures to override the
> vmalloc wrapper functions by enforcing that the rest of the kernel does
> not reimplement __vmalloc_node by using __vmalloc_node_range with the
> same parameters as __vmalloc_node or provides a __weak tag to those
> functions using __vmalloc_node_range with parameters repeating those of
> __vmalloc_node.
>=20
> Two benefits of this approach are (1) greater flexibility to each
> architecture for handling of virtual memory while not compromising the
> kernel's vmalloc logic and (2) more uniform use of the __vmalloc_node
> interface, reserving the more specialized __vmalloc_node_range for more
> specialized cases, such as kasan's shadow memory.

I'm not sure I understand the message. What I understand is that you=20
allow architectures to override vmalloc_node().

In the code you add __weak for that. But you also add the flags to the=20
parameters and I can't understand why when reading the above description.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4026e0f4-f0f3-4386-b9e9-62834c823fc9%40csgroup.eu.
