Return-Path: <kasan-dev+bncBDLKPY4HVQKBBLWI22XAMGQEGVAUHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B915985D123
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:20:15 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d243ef274esf20880291fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:20:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708500015; cv=pass;
        d=google.com; s=arc-20160816;
        b=bsJ+aacMFQMHA1TQ5WTJ01dMOMvqY9X4Vr/1fGsS4Vz+JKIZW4YcO2pabYDWh0zaCG
         YsUNS6wZi++7EOXT3WppCTUSiD3Bx9R/ic54iJmrzj/Nf7fBKl3D2MNPJBS1h+PK+S1j
         Q/zdFtt44eN6SoBDO9Kqcn5xvs3RqDDpBDMLaZ8Yf3qYXoGB7nOmQmgIR3X9LD9gzm9o
         DnBD51/Y/XqSJEL8W2zqfI/UIzIzcSPacZ8WiREnH5Hx+B+biZkAizWpkFrdsfmucinA
         mbS6fJPgT/jqw3yXbBiu5j8z+HbWGMPoSHASM4UBPWlWYFCIdamluOZHwGter2c3A/NU
         1fZw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=eoxfW/6lfDO/f+4Pe72Ch7z82ff7zZTzL/ikstbbd+E=;
        fh=f8v6XZE+ARoU54IXmz73PB51o7vBOwFwlAoGHlov2gM=;
        b=tw5P686ZfUxfNIkCAVNmw7Xh2PJY4h/TJbK5kIy3pcpug3kXw5RtsiJnKv7UtnfQV5
         jsRoBP3mrdq06PsA91Djp2sOUwHN8RQih7FYXj6FDxTmTablSxOlduBmF45FFdMHeP/T
         VgrzkfbKxQWfc7NjZLAWQm31G7DH+jD3jNcfNIuqCdZsRKgL3buaA0W0IRe7kbcjktyH
         2y/nm771yloHPvCQoJsWiIdcGT4ktUr0Ufhl9gdhuYV5eDuzRna1YH/QXtJG61/BPhh/
         uRpQvy2nmz2QZx5YGh3YDLZdhM64qn3YZiBA7/YzF9VGZYt53BU1D/jEes73uF6vSK0A
         JFTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=livul2WI;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708500015; x=1709104815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eoxfW/6lfDO/f+4Pe72Ch7z82ff7zZTzL/ikstbbd+E=;
        b=f27Knn0AqGql1HL7F4kn85kpP6f5RwuYoCtRKIx298l/XXfbdBwWxFX+gkvx4JPe3U
         4MDFfIIqNRLvIzAL8s4ycptN028TTLjU33b8E851pd3x5PbNK4RBNwS9uCFmDs7EA4Op
         6SlMjVKNW8+VD3XMXiGbMqn/p+e/psG4S9v2T+8ZicpsqSAyM2GDz7P+9kBTohTXO1TX
         xQjKMAPwHHMnS3Xb0vx7uGvqXx3GGGkyMVpDtUMskguVvaio1VXt14RgBDmFCzgOriO/
         huBh4YyvPXlye0UD89H4LiUAtK7kB2lD5C7BS5Obcta1f5pLUhQ7cNN+H/6LCCaZjrrh
         bl8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708500015; x=1709104815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=eoxfW/6lfDO/f+4Pe72Ch7z82ff7zZTzL/ikstbbd+E=;
        b=qtlJ2b8ItymFy0vuI41Z5qM0ATE93cADLxXUvqMX9l6VbPze6ZlfU1rifsAeVLvhqp
         hp5bBKqEyhMUvZ+7mJtkhOQsjNVsQEE9iZeSyrCQUAtdVpcLhxogOJP8RKmmjvQuh0L4
         4C69Z37a92g38MpCspnJJRUXP212NtbkMMAmptQ1mn12Oes0Bwb3QbP8FTJ6g8pcQ7oE
         csE1Yx99Cs6WkE8VRaSQlkAvvtwIRg53ThlIdLegwUdYqYK+PWglzFQrow88ZLEO9znx
         2LmSt2BEj3j+RP2KTAB+S63xDXOds+P3a11YN1g8HYg3UWeywXMTwf108hF+MJ4YOiio
         D+wA==
X-Forwarded-Encrypted: i=3; AJvYcCWuGggxhkbOUXw8HdCi10gq3kv8b90SvZYiZvdeVSQlEmkMitYTyerpKvIAI+aXQnkxPVeJnSwbqpbp42UHef0azWfRKNS1eQ==
X-Gm-Message-State: AOJu0YyW3xi5WbVnrO/EsoBR+thY7yxeZoQmYJhoSIXl6Ans7LrCdVr4
	XPXcRQUdxQPt/g2ncur03PhMc0Gxk8tzQ3wwd+QWaVZVX2hKN/cj
X-Google-Smtp-Source: AGHT+IFgkAx2k9p3ESBqoHCXhOX6F4DszynOu26tWzuswCci7uiSXtkOtT2r+P7IvkBZBSaXZO5Ldg==
X-Received: by 2002:a05:651c:220b:b0:2d2:3a8c:e510 with SMTP id y11-20020a05651c220b00b002d23a8ce510mr5925447ljq.43.1708500014705;
        Tue, 20 Feb 2024 23:20:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4af:0:b0:2d2:47f5:7e27 with SMTP id g15-20020a2ea4af000000b002d247f57e27ls717624ljm.0.-pod-prod-08-eu;
 Tue, 20 Feb 2024 23:20:13 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW0YXCeelgKny7NuhOPxff5ujDpkZEiiBhux7Bpv0tg0Ci2HmZOnss8ONjAi5uUE6uh/B3dApZ9UF99zBdUb3KOLU0+kxkllhMn2Q==
X-Received: by 2002:a05:651c:1a08:b0:2d2:2ada:9260 with SMTP id by8-20020a05651c1a0800b002d22ada9260mr8317430ljb.4.1708500012808;
        Tue, 20 Feb 2024 23:20:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708500012; cv=pass;
        d=google.com; s=arc-20160816;
        b=VXES71GjXjlM3tZpNc13tmToS7AsuP3c94jcvBOaFsylqIepWRrw7mo/RFtjZni3bC
         FcLRgpnCROfrHskfDoV37Okc6E5vPuzPFtAQI4elfTsyq8z9Ft0Et+YOeM3aT2RAnH5A
         9VxpwWV+6hI90tQCECRk8AWsa67mWRdV5Qhdx+t7itKCzery3mNdgkLitTRTlvqNBS+T
         E0ZACxUZ5KAyqOQspRKhou3YBaQpuoh3+mFSHvjiZ4KnZhCsFc8HxfaxgojNpz3Ow2cX
         qoc7RRbBRG0BW8Iv0bvi82QljuBY6MZYsB+jcq1raGs4KvthYnepV/7LUrZAqvf/9CKG
         J+2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=Vugcc3CJbj52FMPSPQwTUzb2Vi4gpJyifr0eyPS8gV4=;
        fh=0/nJWjGjUDnfJAXO9tPU9tkn3rnQs7SlLqPGDpCOlAE=;
        b=T5geUiNbdXJKIHGpnmKx7EYi5wpl8gQA8JFL1HRGCZuN5deuSQcCK7c48/AvrhZ9VY
         GO0ex+e2+AES1ITzswi5uVY3uIMmwodq0IXp+fRE2t2Gp0lPvxNmmCB/+WU8wqBEw2PR
         uE/LqyaOn1K5mbNShuFr0470HcoOh3kVbRrPHtsDW9MCdQgeMNS9lAAY/SRmw5jKEA8+
         H+ZsQuN0FCGJUqLBiINzjLwNSr1ZTIF5aRl6ITLRLn0hv61BGBqmud4IEeSh/Y8txPsZ
         /2E9T64KCqanYJCZtY7/uHv6xRzhSetRuksE4mRy1a1qA0JvnZJkz71jssc3lqwxuBDM
         0Vdw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=livul2WI;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on20701.outbound.protection.outlook.com. [2a01:111:f403:261c::701])
        by gmr-mx.google.com with ESMTPS id x33-20020a2ea9a1000000b002d11e45bbbesi338096ljq.6.2024.02.20.23.20.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 23:20:12 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) client-ip=2a01:111:f403:261c::701;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=WyifqikZvGPYio/WU/2hcROEGJoogl5NxWciKVlRZGdUbjLyQOIAVBLaDIQ15q6fcLE3X6FuQk6ULwwWcWvndao3A45NQcgls/c05Q8AlyFnc/TmRIQqyU744+L1OEX4S5vJT2NsvUHh4t0McnWxlTincPfMILZhQQ1HmO6/EVXo8+KsonDQE5PupnlxjOZmv6E4nFqg9hIjzISwZBR13hutKT8OqWCbla17x28910aQID+i+IOw1KiDZ/elD2Dukz5CEJHrtUwwcpveyQVSRB+o8AtVh6UemdNYTEQUpzz0LJQJXApKQPFw6Q80HwqMafgKpbQls2yqQGWneW+yDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Vugcc3CJbj52FMPSPQwTUzb2Vi4gpJyifr0eyPS8gV4=;
 b=Iw6CjLtsE2HpcXGcCOawlTWEryhznt5BFw/dv63T6cGFN54K8jEMnAzNR6Gl0OnTAA0ZhBk0spb9CZ6BxAAA0fKDOwVP2jBSTXBK/B/IGX9AGw7U/eXb9pvfES8yijzyx0uuJQxo276AQ0uCkDIoGQgNUjDlpglEZR6s4xf8R18J6FrSSkka4aL+d8Y6LCUzRtMxiJTd4bmJwiuGd6kBfq1qqjPN8yH74mbyiHdAjSOBO5zbgIa4mdCzXwqAlf7J+/gtiXxHKQwjB61lUB6siO6Xl9nE4yp2oo78p0VNGAU0QatxfQPIyNaH9CI16Vxt5u9ezLr3lkSVxQNUfz7/uA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR1P264MB1567.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1b2::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 07:20:10 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 07:20:09 +0000
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
Subject: Re: [PATCH 3/4] arm64: separate code and data virtual memory
 allocation
Thread-Topic: [PATCH 3/4] arm64: separate code and data virtual memory
 allocation
Thread-Index: AQHaZDwTLzm6aukIxEyL5imV7Y1QlLEUZFWA
Date: Wed, 21 Feb 2024 07:20:09 +0000
Message-ID: <dc1ebba5-c4a4-496d-8a46-1e58a796e4ad@csgroup.eu>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-4-mbland@motorola.com>
In-Reply-To: <20240220203256.31153-4-mbland@motorola.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR1P264MB1567:EE_
x-ms-office365-filtering-correlation-id: 36ac0533-bcbd-42cd-a326-08dc32ad8985
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 537c8LDPSfW2V4lXJYHzDWvqG1y2+9FXpqVUesuaB+xLFF7ecjn/Y84r6ThpVU94c2mQ2thtilZr6idmgG2UgcEbYsYFFn/atEqd1MFlRM1NCIscWQ27/M/GwFc8XP35vgG0HCMA3WM1QhDuVz9kuYwGIJcmPWcCdcVbshZjn7wcq8wt00dXF3hdobqQ4H4K7OPBb5G1m1NHXbicQKMBIC4jM5Cmy3SxTAE6Jngklp7giHSoiuG2EjcwXIXZ2eeLViFV1n7c9ysw++2AfbQFFLX1UcftulQQdN/vcjP9brXnnnW2PawhNr3BB2ZlkRBXI3L398vJuIK3fR370vX4SUxzZL9WPBO2ipcwg+OXVtfPMaW5AwQXU3imMHiXbSOkygjcocwpLwWrw7QkHVOaLyN0U/4mZ2xOtFvXIvA76uAdHT+KvwYuA/AYFjgaX+XH2RcZeqA8kV8cr9miykmDmH9sQeN73wYv1h+8B6qPproxdTrLdRvhY8eNEliZNBNdOvUJLm8W2MkBy4c/u7Ot32MEFortsdEUYGysYcHP9R0JCxhQVbWKlZ9x6mq6OM+OI1orQvodqcbyKJ643Uf6pGzekn8OxFbGvSPrxWTn15Vfl/lRD/8EA/n4WSG3SSkQ
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?WkpsR2lhcGhucExPYXBqeUVPbEUwYjVBZUtMOFlmYmRseWJjUk5hUFBYcmJw?=
 =?utf-8?B?Yno0STlVM1BHRkdmb1ZXNFpnYnJJbkpWQlY4R2JGaldPeDQrUXUwVUVYTjlS?=
 =?utf-8?B?S0tId01VV2lIQUF0bHJ2bGw3eWpDc1FmRzl0U0dQdzJDZ3BPU1dJU1YyS1FB?=
 =?utf-8?B?MHUzeWxveGpzeUZQWDkwR0Z0UHlHN1BzNzd0NUx3VnVzUW5vTXRaMGR6djU2?=
 =?utf-8?B?UElmOEdPSy9NcHNIYXlzU0FyVFZZODNZQVJ0V0JnMFhYK1NiOFRIV2s0bnNj?=
 =?utf-8?B?Qlp5bkFydEd5YktEL1VhendDUnJaVXJMUisxWEFUY3Q2dldoeVhkcit4bzlr?=
 =?utf-8?B?UHFWV3NmRVcrUEd1SUdRZk1kTVlVVko1d1IwdDRpWkIxV2txcTQ4dXJoZncy?=
 =?utf-8?B?RnlOMWpyM3dkcnQrVnkvM250TEZCL3ZGTldkclRtN0dqSm94OUdIUzIrZ1hy?=
 =?utf-8?B?SnVpRWhTVkk3ZkVCZk01WGtoaXVuK0RFb2lxNmVHNkxKYTNCV3FxWTE4cDcz?=
 =?utf-8?B?eWJDbGFQMDN3TXhFYkk4STF0U1MxbEhKMHFTdEdxczZrRzY0MmpwMXdDbGJW?=
 =?utf-8?B?QmdIdmZ4NEs1bFdvQk9YODRZeE13SHlTaUhBUHNJaldkemJJTit6dGJXcjNr?=
 =?utf-8?B?RmhtTmJmZkZLMjdRMzR2cmUxZU1mY253eFpCazQrMFY4VUw4ekdGYnpwOWF5?=
 =?utf-8?B?REEvWnJVNWFlWUNIODg1YnpZbmVyb0plSG1BTlVmU1VFNFRNdkgyLzcrSXpz?=
 =?utf-8?B?aE9EMVI4ZXROOGdIYjFWMTVQMGhjV1gzZFFuMTFXeHBueWJMV2lQeklDazBi?=
 =?utf-8?B?UXNUOWpndyt2bEF6UTFkSU5zdng0WkMxWjFFVG5DZXdJUlltN3NRUlFvSXkv?=
 =?utf-8?B?cXdRM0tFVDFPVHpoTjF6VHZHejJuZTBnTXB3MElYREM0T0JLdG5paElkdlgx?=
 =?utf-8?B?aXRxelB3VlIxeDlyci9QQ0VoNkxJY0hkUkJ0WWNnUmNrNDErTXlkYUdnTkFZ?=
 =?utf-8?B?Z2pDWldYTS9VL1NJd2JIZG1DUS8yNzd1T3BHMldmRXhYS2FxQ3pZelZpcTRa?=
 =?utf-8?B?MC9wYWIxdTh0aUkvWEMxV1IvM0c5K3RVZlBOZ1lsQlpkV09FTE42U2N1cEN6?=
 =?utf-8?B?MmErZ0J4WGJUVHVYM0xsTXcvUC84UHNWMDFlYlk5RWE5OW1pMDVmMW43QjZK?=
 =?utf-8?B?MGdwbnd3Wm1NVDBuZUhRR0JjYTZkcm1UUkhyYm1CV28rSW54UndpdGQ3ckVn?=
 =?utf-8?B?YzZoVXZwNElyVW8rckZBNm9uSFlpNk4zN2JmbjQzd2NRV0wrSEZjWFJRWjNq?=
 =?utf-8?B?UjhWMkxLYXlRRWhiUnpueXZIdENYK0J6OUJaUlR4b245T1Q3Z201Y2kzcmUw?=
 =?utf-8?B?aWpWTUlnMklKWktvWkZMVmtOZ0xMaUxPVE1XVmZPcTVhN1Y3enNSR0NmVnVR?=
 =?utf-8?B?VlBkV3g3TGxLa1B5ZDFuaE0xVHpYNDRtYlNad1hqSzErbW16UmQxYUhqUmdm?=
 =?utf-8?B?VEJWMEhkUml1Qk5oaTlTSG42WG9DYjI5Q2kzaGpLL1VVL0RveXpEZzh2TEUv?=
 =?utf-8?B?OVNmakZjZ1R1aG5MRXZoTTgyRVo4Vm1zYkdRbmVZNngvOGdmQ3V4VFBVUzI3?=
 =?utf-8?B?dzZFalZIY1l5dGdFelJzT3h2c0Q5bVUzWm4wa2V1dVhXQ3QrS3JNZTFWWWdu?=
 =?utf-8?B?bXJsbkxkYmw3djRzandvVHREam9kVXJLYnlkbzd5NjAveWZtSmZidUJsbE9G?=
 =?utf-8?B?NEVBRlJUZWE4RHlWaUwvUE91ZEMwVmtBYlpqOUNaNHFtdm9pOFF4QjFHdUZh?=
 =?utf-8?B?UlNPYTVjY0dRZWtLZE0zK3VWNDNNYmNGWWlCS0JXZFpsSzlCVU5sdSs4R0lm?=
 =?utf-8?B?NEJGbmZ4NmhjUmFkNTVybzRoSXZoR2t3dWZhM3FXTStpTDYxM2hJNnRueno2?=
 =?utf-8?B?dG1keHRidTU0VkZsczBTZStzRzNJR3FMTUZNL2VGMi96UlRjZ0VyQzkzMFgy?=
 =?utf-8?B?L1lkdTk1SkI1d1hqRE5PZVE3eExaRjJGZU01LzYvR0JPRXpka0lPN09CclNB?=
 =?utf-8?B?WVJjR1F1YVpLV1V0K1k3bGNZWTREYmF2bmRtZS8xaHZ5elNtaEFnM3g0dzQ1?=
 =?utf-8?Q?eDK/oNAkakp6bTFWRZVSc70bv?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <FE918AA4F859F04F9DB4BE5CE3EEA3AA@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 36ac0533-bcbd-42cd-a326-08dc32ad8985
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 07:20:09.7397
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: OA76lf9T5Au5Q+oa7AhhnrGXk55/UMLPwJ4Y1VKRCQlLTbbDTimDaqjRLtsoOJIvZFqnsB3A564ApyS6vtGfO/ELIoWfbZvX5DL5lB4Kia4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR1P264MB1567
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=livul2WI;       arc=pass
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



Le 20/02/2024 =C3=A0 21:32, Maxwell Bland a =C3=A9crit=C2=A0:
> [Vous ne recevez pas souvent de courriers de mbland@motorola.com. D=C3=A9=
couvrez pourquoi ceci est important =C3=A0 https://aka.ms/LearnAboutSenderI=
dentification ]
>=20
> Current BPF and kprobe instruction allocation interfaces do not match
> the base kernel and intermingle code and data pages within the same
> sections. In the case of BPF, this appears to be a result of code
> duplication between the kernel's JIT compiler and arm64's JIT.  However,
> This is no longer necessary given the possibility of overriding vmalloc
> wrapper functions.

Why do you need to override vmalloc wrapper functions for that ?

See powerpc, for kprobes, alloc_insn_page() uses module_alloc().
On powerpc, the approach is that vmalloc() provides non-exec memory=20
while module_alloc() provides executable memory.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dc1ebba5-c4a4-496d-8a46-1e58a796e4ad%40csgroup.eu.
