Return-Path: <kasan-dev+bncBDLKPY4HVQKBB7OQ22XAMGQETZGQG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF85C85D18E
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:38:38 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-a3f3c382ba9sf18594066b.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:38:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708501118; cv=pass;
        d=google.com; s=arc-20160816;
        b=UbbDvVtlHjNQtsjuzoUB117SLveR5lfAT5MCmi25z0t6xbzrDnAsyO94YX8EbEb97A
         lGXHW+xK2k38ZVHGuv0/QvODOFRJ50bAEKv3NxCft6HIwu8OnTlm25K3A10XM+hfReTz
         GJo661wLYM2SDXZ+1awq6d4gd2ssvL7MwUPTfvvhAipZCifMPqYskoqplCFGrUCc5h3p
         epoMya49QtktDU55HvnEBncfERUTREKSmLEJqRqaD4+xqWnMrndYOgrCNu/ZAhyxU2Wu
         wSogsz2QW2F9mOk+uPv4fuPPEorlqy9DOZi3fOl0bsc+fet4or1mTAbr9n9hClTMoYok
         j6jQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=OAu0Z8dvyKJG4iTsAGew6GcEFDH/miYKiZH/SzoMWHY=;
        fh=lwJBJClIr6CsJJILDpPOChkwrFf3bsiMqCOSomARVs0=;
        b=w28cKbaJXpq46KrVMcp641JOu5vBqbRiCa/qrV04yMieUru1yeFfyZqwqhODShG5EX
         qL9YsM1sRGXj232bQWL1BYQ8pQnYkQLbmBpz17p5oF7RKMen9KKedpanoFXyZpoO8qjB
         /S3vSA3cAaPNjDb7qVdbuLc6zhlWFP6Y7x5xJnfqCNL09BcB5amoAXlr8oe+meSml9iK
         1zYMOd3aPWQNbSBPR5TKByNc15mzfYmMUFPvEkl8BywfhpuqwbsaE2tRbRIeKGbKiUck
         9IYRYoZb1PCtY9uNoQQ9cWwAi9fS9lU+kOZDVbksvXqR7ZNInu6BBJhdncgA1kd4EuZK
         C/GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XYc+SGek;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708501118; x=1709105918; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OAu0Z8dvyKJG4iTsAGew6GcEFDH/miYKiZH/SzoMWHY=;
        b=qpCV4cd6v1SX07pCMZ/RYBKS86e+c8Wf6VhIKph+Gk8rHjJqyj9EVi9TtFFXV5IY1J
         sVfGcyE5bEa5QnZytbbXVs088ZKEhHjEMyaxPHaARBgjEhuwd0UAWJosy+BkyCmYLCJN
         nHUYmw/V7TDM4T+31OQXFT5fwHU7ffuRCsjUFVJeQvQe3N/32WnyXGAgQSU9Edaxt6JB
         JXOqvhE4W3noM0Ihy9QADi4JBRbcJJl4rLB4/kSo+7Cb0XiZrt/KXHKaDOoeBTyoyyS/
         keJganqeACOottFALu+Ojf9VIAnYc0k6BfOT/MXGzup1fhEI/kEg7wD4tQpoaHl4awOD
         S/LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708501118; x=1709105918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=OAu0Z8dvyKJG4iTsAGew6GcEFDH/miYKiZH/SzoMWHY=;
        b=I3q0ay3UiKUKi5PstI2+3r3SYu8EYKWWp/1v5pzhcVHLMIoOArUaHs69I7qMKZA8i6
         G0UA3+MqwwYQmkhp/uFy1ufrJCOxX6A8/UilJRjmBObt8oXH5z/+Tc+l1mlJb2mFKciG
         a31v1M1prhb7bFIrVR4VDmcP/UPkho6pPi90W495bQh6AM5D0V0iFDTwnevZwfTlyIDP
         kJjZakGDxsdjza77oJOG4z/DemBeG5RhWIh9WZGxRmgUZwGL5d//2xQQNQlDhCeauCin
         fDYQFXEjtEVgpIBtOgME661MlgIyaS2hWeb7jI7p0rpox8fcjBfvutARCgEaMW9x/9kF
         Zzkw==
X-Forwarded-Encrypted: i=3; AJvYcCUkU/LGchjPz2xCoM3JlBb+w/s5Q4LzK2fSwehhpyppGHRb7bLQzvn5ii5KBBO0H/RmP0Ik+4j6DS+09Stf8/b7Av043h7hDA==
X-Gm-Message-State: AOJu0YyVPaJfCqptRfl9fByJIbvhGKaLs6IGgM3v6FSrlrt6rmBwwEbM
	PghhwRqnBquv1QD9dtzosF16IZvMmnDAv+i0UVwjyxDnK8yVXzHs
X-Google-Smtp-Source: AGHT+IHhUOZoYp/GEYzZhXdXu0oI1Z8/GQSJgjke3ubzEL8XdR2SIsahvbFwYFVMIk2/PW1x3/GxiA==
X-Received: by 2002:aa7:c58a:0:b0:564:b822:91f4 with SMTP id g10-20020aa7c58a000000b00564b82291f4mr3093736edq.21.1708501117946;
        Tue, 20 Feb 2024 23:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:322a:b0:562:c01:5808 with SMTP id
 g42-20020a056402322a00b005620c015808ls105017eda.2.-pod-prod-06-eu; Tue, 20
 Feb 2024 23:38:36 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXPmnuS8eKd10vm2N9qoKBk5B1oLcQ9Wdja3T8VbzAnLGDgiOnYZf20PGKHQYZuLE8XeYWldYFZ7wGF6g46D9MkMhIW5pHfSjHq8w==
X-Received: by 2002:a05:6402:12c7:b0:564:67d0:2381 with SMTP id k7-20020a05640212c700b0056467d02381mr4227720edx.40.1708501115890;
        Tue, 20 Feb 2024 23:38:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708501115; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECeI0dF+/OkYGlYlPkB34voElF1jyxNuYN5io9ZnkGtYJ0GojXFX1gXVzwpjdrbseQ
         krbbZ0JJNygo8QtoBuvskcTkjh7VH39lnV95XmI/pZNihZSGSE/u6y8qPZlXEKfwBLxI
         K0ol1cqqCffLJpDkJi62rgd2VVwh8nt45seNr/UDDC45E71hHfCYOOQaxG3ZrnzSaCFx
         DDNq3JQdukDpZrhTU8xEwVoLc2yofgn1Yn5kbc+vLjmDuaTJXh/5GtqLhcaca3AJ9JQ+
         oC+jZ1DOE/9r/NtZxmnrsEmCjcvSantTUi58HCI41TjOAPNz0Sj/mK4a8V1/BBZ4DwIW
         7h+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=MXZLuJtNgTm52IXo2S8naIieT83ZW1InPsP2+L/39lY=;
        fh=fI0dK30fAndNJl5+CgK8Mtkt/rBng7Yi9+gCtsNA0dY=;
        b=NCOJVWSrtyYqSJP7TPxU4TyAv3Ijvc+D6uxWNhu6mgqLsJMbzlvYe5NYRYpnrVjDw/
         CkV5KTHB5HotKIXIOfzinSXEC6JA/in2U8x2SrqjpLi1HFIfeUrTHMze3eCHTapYdgS0
         lUXmIY365AukILWS6SjokLVbnVT6oVmWb52ccDBXTwnpKrWe7WP3DRiI1EgvjuHwPdrf
         P8CZx1U0cOx/HIefLffoPjaxRxKUbDzg58Q03cbr7lxv59SPYoxDvav9dtdBIUDyr5Cw
         Qx5PCt7PnNNghH+6alYH3J64oUT7msEdrJS4OkPR7MDYUKnuIy2CUi3h980o51GXl88A
         CDBg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XYc+SGek;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on20701.outbound.protection.outlook.com. [2a01:111:f403:261c::701])
        by gmr-mx.google.com with ESMTPS id a11-20020a509b4b000000b00564caddf28bsi229329edj.3.2024.02.20.23.38.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 23:38:35 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) client-ip=2a01:111:f403:261c::701;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=m0HWueNXSvinZgZ6KPRNtraBkLlCJ5UMQVYYnxqL89EOM0Bk+vlePeDmIwQPMedg7YyzlgjKtitov8q23Q125aUTz27ZVGtVpaFFEF+6uJHNPZUD9N8bCIM8tmCZJlJEU0Ih5VIyDv0R4OpzxZERq3j8vb4JI91UUi29+XHAdxn0weGPZACq0zCktUZkMZCzU8hwUrfYVqkg4QW3sZ0RScBWg16w0xKJN/rhnvDaW4jgszZBSW/1rsU8dMa2HxAnHDVFUWayKn2dJquMoELTMIWl+SPWTLEEfqyjbFpwdSo712qEzrWmcZ21IiWc2NffN8LPHeBVtHSgjN/cidX+pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=MXZLuJtNgTm52IXo2S8naIieT83ZW1InPsP2+L/39lY=;
 b=ZQAW/FqBWABgMsS4pxIYtl67jg0DLJu+A2hRy2jFilApmvVcExnsyEgM5toCGajS3Eu2GRFeoE2WenciRkVkqFb3PD7Ftmr2vjUancEl+d0KiQS6t1gfvOsgEe4MWRSvOhteEuT7k1zqvAOli5s+AWx4Y32aZZV3BXz02NMEmU0/zRmdxOz+XCXXvmplpYLSdYtM1t6uJ2KyE6psEePuCn6GT4XVdw3LjszY4TSc34XEPjbC5kX0ZuV7pyo3fyS0L+tWi6abGwW6ZEVN3tWP96idtH6I+brazF5OldWm2iiIVBFitAbEED0RK4ad3yxC7xRtcrZ2aophIxjFLhiphg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB3660.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:162::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7316.22; Wed, 21 Feb
 2024 07:38:32 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 07:38:32 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@infradead.org>, Maxwell Bland <mbland@motorola.com>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "gregkh@linuxfoundation.org"
	<gregkh@linuxfoundation.org>, "agordeev@linux.ibm.com"
	<agordeev@linux.ibm.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"andrii@kernel.org" <andrii@kernel.org>, "aneesh.kumar@kernel.org"
	<aneesh.kumar@kernel.org>, "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
	"ardb@kernel.org" <ardb@kernel.org>, "arnd@arndb.de" <arnd@arndb.de>,
	"ast@kernel.org" <ast@kernel.org>, "borntraeger@linux.ibm.com"
	<borntraeger@linux.ibm.com>, "bpf@vger.kernel.org" <bpf@vger.kernel.org>,
	"brauner@kernel.org" <brauner@kernel.org>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "cl@linux.com" <cl@linux.com>,
	"daniel@iogearbox.net" <daniel@iogearbox.net>, "dave.hansen@linux.intel.com"
	<dave.hansen@linux.intel.com>, "david@redhat.com" <david@redhat.com>,
	"dennis@kernel.org" <dennis@kernel.org>, "dvyukov@google.com"
	<dvyukov@google.com>, "glider@google.com" <glider@google.com>,
	"gor@linux.ibm.com" <gor@linux.ibm.com>, "guoren@kernel.org"
	<guoren@kernel.org>, "haoluo@google.com" <haoluo@google.com>,
	"hca@linux.ibm.com" <hca@linux.ibm.com>, "john.fastabend@gmail.com"
	<john.fastabend@gmail.com>, "jolsa@kernel.org" <jolsa@kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"kpsingh@kernel.org" <kpsingh@kernel.org>, "linux-arch@vger.kernel.org"
	<linux-arch@vger.kernel.org>, "linux@armlinux.org.uk"
	<linux@armlinux.org.uk>, "linux-efi@vger.kernel.org"
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
Thread-Index: AQHaZDwS6FkPILIvP0qdTgNTWVgWnbEUSTcAgAAgP4A=
Date: Wed, 21 Feb 2024 07:38:32 +0000
Message-ID: <e508c3e0-8644-40f1-aee2-90625237b01c@csgroup.eu>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-2-mbland@motorola.com> <ZdWNalbmABYDuFHE@infradead.org>
In-Reply-To: <ZdWNalbmABYDuFHE@infradead.org>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB3660:EE_
x-ms-office365-filtering-correlation-id: 0ad90097-84ff-4286-924b-08dc32b01ad2
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: /ye+NiC8jyBUKD38/Q5eOx6zLGvyGGkiJNjR7VDR2ZVxFydv5FebhevuJCUBTHfgZ8XjblfnGOa7I6+9CrT5/0S7XqYi0GdXF5BRGgjPUXxg0KpLLfDjmrRaxZO3ystievjwyF3wkCrxjevjA8SM5lY4V1IMbQlKxWJoT9owF5LBDXPuQ4B+47GtqYoX6HdGS2SqFEBThQ8KGKrUpKpJf2DTeAqGaj0pzTLjVbkKRmNgkaF2wi+lAeZq+bU5Csn0+YGc5J7j30rfQYbyhGu2/DsXQYMl9twDp/5mT/41TzYMKqINaF4oIdz3pi7MbEtJxRgVZNL7VsivR7s4LYV0pPVqv//+h6Y6zjnUwXxONLc1p2rSel4UtCtBnA+9RvZWZUVKZjDQo+2gT9f6Ib5ztPfhAVg4oUb6Xr9+9cmdx+eguV6ckIJdyDfcIXfU/H10GdN9p3JuU+tRPOd2fkPzp2cIYdR2t9a/Re6P7Jx/VimI0HQnqsuXFtsVuwNAxhYkThPQxSIEDGNIOpKmatoSMUPpb8CjVyZ9dmFamS6vixPBrwZmyXSGKqW+4sZQdUzNGLbPLtoVfJi8612XSuPawBiE90AfkQfiKewcWWwwgT1n1fQkjm3EEnxdYs8hqqO5
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?NU9pRFE2d1pab0hMa0c0b0dqeU1vNFQwbGgyY2w0ekFFYUVONHNzNmw1TWlM?=
 =?utf-8?B?MDB3WDlZR0pqUEdueWlvN1BBY1Z2bjhTeGpIQlM2c0pmV1AwekJ0V1BBRkFv?=
 =?utf-8?B?ZjdaSDlNVHoycHVYTFBFYi9lZmxhSE1hRjVjVFJSdHdGZ2RXL1U5L3FxS2FU?=
 =?utf-8?B?WUpOM1VNUGF5VmhYRUovK1REeTBpSis0MS9vOEdTWG0rendBcUNBeDRiYVhN?=
 =?utf-8?B?Sld5Q3Iva2g1M2tIVmpQYitVcFQvSHJiYVp1OE1iU1Bja2ZrbkRLNXpESlJj?=
 =?utf-8?B?REdxMXJEaUpIRzRDN1hpazBxbDFiTUt6Z1BqYm9yRmVoQzFLN1B3QWo4dUJy?=
 =?utf-8?B?SksvaWdyTXJpY3lKeldmZUZoNnNXUGIwQ0VsZlBnZ0Y5VEViNDhjMDllN2x5?=
 =?utf-8?B?YXR2SmZQcXFDbUFYSWRjUUF6aS9yOTZSK2tBWWdhV0NpbHV2Uit6YlVsS1NH?=
 =?utf-8?B?bld2VVdWdms0YWFUSDlsUE1GL1QrTmUvaTNTR3puN1J4SmdENnIvRnRib05B?=
 =?utf-8?B?eEtCRUZGTE9FUnJKblFsYjF4czFKZE1OR0JXd2t4N2xyQ0hpOUFsR0k4ZWpO?=
 =?utf-8?B?NzlhYngyL3cyWTdVdlpqdUI2bkZNUklwTy9tdmd3VTJvYUpIWXN3TStQV00z?=
 =?utf-8?B?TDFMT2xabjloVlhUbFRUTzlDRlcwUHhJamJpRjBuUFlNVkVUVTlOQTR4VmR2?=
 =?utf-8?B?R0prM0x4U3o2VVNpM2x3aTBSSEsxd1pwbGpjSGozQmJjYkg1akRTakhFM3JQ?=
 =?utf-8?B?KzhFeDFjREExM2l6dlBOQ1ByUHhqQmJaQVRqY1JCL2pnNVhlWjlKV2VIMXZ5?=
 =?utf-8?B?a3lrS2xuNlFERGJDUm1XREQ2cGpWekFtUHhhSXI1MDh3d08xeWZHSHE1ZXgw?=
 =?utf-8?B?eUM5RkNKNExPblBiOFllaklzZlg1RUZqSmZ1UjRwY1RvMVA3dm9Benh0MGhE?=
 =?utf-8?B?NVpIY3ZDVXBmVzdMNzBFU3BRai9TWnd1RXJFTEFkNmpYNGFnRlJPc2FMY3cx?=
 =?utf-8?B?a2w5SmVuKzV5Z3NURGNXekJvZ1dEdTVPdFpaTnVJd0txRU5ISkJLYy9aVmZI?=
 =?utf-8?B?M0VqK2RaRXhZYXk0aU9kVGJCWWtuUnhrMTl3VlBQVndWQmpkbXRUNjZoYW1k?=
 =?utf-8?B?VWxFc3Q2Z0hoTDRndzBTeFQ4eklzbmdkdjk0U25PUC84cU1HTDFrZVFLMWEz?=
 =?utf-8?B?UVhiZHd6OEZYaldmMTZkd1lCK21IZDVTMEVkTFloV2RkSENFZmViR1dDUVdY?=
 =?utf-8?B?TGJUaFlJRWllSjdsc1NUUFM1VnNvcHhDQXlWako5aFFiVElRRmk1cTJ1M1h6?=
 =?utf-8?B?VDJCb04xQlhGOFRUVWh3M1VZeFhZdVFtNytIeXVFMEp3bERMbFlPSmorTFlm?=
 =?utf-8?B?NHFKaHJ3aTFiVlh2QVBPTHVCV240Qjg5c0w4cTVWZ2lEQWxpdW81TU1HZGZR?=
 =?utf-8?B?Sk5oUmNsYXA1dWs3ZEcwdytmekpJSE55NThDc2xGUVBsYTRiWWlWUWVORHNS?=
 =?utf-8?B?ajJCdS9aY2xoaXFPMGFBU2NMOUNTWUc0NGdueDBqSFRXcFN6bkZ4ZHNabUVZ?=
 =?utf-8?B?MFBaQzRyaU5QZHdpTHdMdEtYL09kOFhUcGFoZ1VHM3pYNHg0RVBOZW1seVZB?=
 =?utf-8?B?Zk16V090WkptVFJJMFJiWk1oRndGWVNOM1hIMjQ5Vm9xakliaUI4OEV4TnE0?=
 =?utf-8?B?RHUyZWlDMzErRnlhNzVvQVIxU3R1eFlQN2Q4YndTNW9rR05BdUh6cVhNek8w?=
 =?utf-8?B?c0lSR0xHWURNcnRTYm1CVHdjQTFid1BSa3NvYXBEbUlwVFVISCsyUGJRZHpL?=
 =?utf-8?B?anp2SjRQYXpvZSthL1NUaUFYTXFaTkNIOGhPT1RjeDJCbG9Rd2hlTWpuRWxt?=
 =?utf-8?B?MEZuUHk2KzNQV25LZGpKdVdDdGYxcDRNUHFVZE9sYVNwNXo4YW9acVFSMzNV?=
 =?utf-8?B?SW5hemdycU9mUWZTVytsYXgxSk41MVhQeXlvM0VKdTNKeTMvM3I5QjJIaFli?=
 =?utf-8?B?ZGxDUUM4QWxkMURPRXdxWmNTUzZ6Yjh5eElKcXZHc0dQRjZVWEhFTDVIeVh6?=
 =?utf-8?B?NnR6ME5ZREpJbHVHbnFUZ05oSDF5QUVCUUtEaDBJUGFnTHBEMmRJUzJFNWhZ?=
 =?utf-8?Q?P8FL5k9l3JMP9mcURlctrXEg1?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <6302266E3F2ADF4B9219C990578BC0A5@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 0ad90097-84ff-4286-924b-08dc32b01ad2
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 07:38:32.5128
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: OCAT1sYyjWBizOWOz5o72xlfzVAm6cj/PsVud6+IRWc20HYzILTVwNr9S3EI1MtezxNC60gA5/79pJoFCdQZNmK2R1x5SV2Z6yR7gejkfSQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB3660
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=XYc+SGek;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted
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



Le 21/02/2024 =C3=A0 06:43, Christoph Hellwig a =C3=A9crit=C2=A0:
> On Tue, Feb 20, 2024 at 02:32:53PM -0600, Maxwell Bland wrote:
>> Present non-uniform use of __vmalloc_node and __vmalloc_node_range makes
>> enforcing appropriate code and data seperation untenable on certain
>> microarchitectures, as VMALLOC_START and VMALLOC_END are monolithic
>> while the use of the vmalloc interface is non-monolithic: in particular,
>> appropriate randomness in ASLR makes it such that code regions must fall
>> in some region between VMALLOC_START and VMALLOC_end, but this
>> necessitates that code pages are intermingled with data pages, meaning
>> code-specific protections, such as arm64's PXNTable, cannot be
>> performantly runtime enforced.
>=20
> That's not actually true.  We have MODULE_START/END to separate them,
> which is used by mips only for now.

We have MODULES_VADDR and MODULES_END that are used by arm, arm64,=20
loongarcg, powerpc, riscv, s390, sparc, x86_64

is_vmalloc_or_module_addr() is using MODULES_VADDR so I guess this=20
function fails on mips ?

>=20
>>
>> The solution to this problem allows architectures to override the
>> vmalloc wrapper functions by enforcing that the rest of the kernel does
>> not reimplement __vmalloc_node by using __vmalloc_node_range with the
>> same parameters as __vmalloc_node or provides a __weak tag to those
>> functions using __vmalloc_node_range with parameters repeating those of
>> __vmalloc_node.
>=20
> I'm really not too happy about overriding the functions.  Especially
> as the separation is a generally good idea and it would be good to
> move everyone (or at least all modern architectures) over to a scheme
> like this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e508c3e0-8644-40f1-aee2-90625237b01c%40csgroup.eu.
