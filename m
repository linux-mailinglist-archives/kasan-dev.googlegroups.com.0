Return-Path: <kasan-dev+bncBDOJT7EVXMDBBDXT3CXAMGQE2RU2UAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C59685E50B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 18:57:36 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-29935a0ecbbsf661287a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 09:57:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708538254; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGQkxxkIomKDX9yl2Y3Z43X79S9m2EAnNmPY9tzAns7OOl9B5LdIyrkyeTALKyb3W8
         ek6SZ0/QwGxmGgoBUbud95x0EShugZMVuusfI4AnxlnwLADfdV/bGROppkbhrcyLAcTK
         BEPQcz7rY3Y3By8BPGhjxW9TMvW6YxI+YbMWfE6k4FEjvbtJsWsB7Rfa2BkgsWmPiIbC
         utkwfPVHqi5nypzvPq5F9q6h+PX65hclFBQixw18j/Ay1qz/sW8OGy0ePmLjfDaVf6T4
         hCg6O0CgGhQHtbPfv3W/ip5063hfZj7blec2rPzMbQb+upZye57wa4jHvsyutCIO9KjT
         Zmvg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=nphm0AmnrkpXlNUt0osyYcWEitZ2WhYk4MTka5J6z6Y=;
        fh=a4UiCp74d/BEMwrlfSHrNkKyCDsuw7DmC6HDqd5aHS4=;
        b=g4Va1FKfka9hXLc5eRz5Ed6TmVYuzdHuN8rXAQU2xhmv2wjjfEhDVrkLQs8eNrf+NO
         gi6HOg3YiSZWsJdZe2g1ENF/SRfnUI1amy9MKObEi9SVCAa3Q0xeFEnc4PdAaYeW3XDG
         hcVd+ct8DE8HLF8bWR+WLYPWC/jurUUbrKiQ7KlkEq47br8l11CQWabIPuuFByzhpE9U
         YWGGUrav4uYjAitfa3QEmj/IzbkpxX0F6YpRbqg+OQoMRGaEvJJkJM7erTOUcH2Eo63l
         GYhe2dtWgsJ9kH7xXf82FqJevjXJsWWSj7LN4+M/+Lw0x7tDTHFcsbMprxjq87nKFHSS
         qCJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=fdTtH0q3;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708538254; x=1709143054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nphm0AmnrkpXlNUt0osyYcWEitZ2WhYk4MTka5J6z6Y=;
        b=oY9xUUMZVQETQqZ7p1n+jcvdF2isADpx6xLC1rlINaHr+xrzaK4Y3WzODXVicyaUjL
         mZIadRwIze81F3BcXQLAFRPs/38fuIUY/ZM7RyW4NuCQO4sgwSym8Bq4sK0ijS4F6Agl
         7uHTIuXCxc09HVvdsZNkHJx/M/rEQqEZ7Y0vfzQg/0xd23TbG5LAKyA3SGQEyQ7gOgCL
         +2vyl5VZiUfnWGymUXaRUeFuyIMP/aDGo8iBMfdLTX6Ofj+UlkG/ChqPZYZAcJOHBYwa
         33PFC0UJfZW2W5gHRsLRH8PgyMxMo7DM+aO2PoKYnmKbFi0c3koMQbMOvF/jYkKOj3P5
         iBpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708538254; x=1709143054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nphm0AmnrkpXlNUt0osyYcWEitZ2WhYk4MTka5J6z6Y=;
        b=OTltDvlLb9LXn9xOb2ZByzhmiwUYnXhEzniU5f7R9pVI8w4q8TLcA66BED/w7HJv1q
         EirmTLofeWH8CX1Z+H7CwwfW4eygloLF6zZqPjTLU3YI31ZIh44zi1RQD5Td7grJZzIh
         cXu9plp3dCDJzLHFoonl9Kro6e9piFQOUL16hxBIGGVBdbsD3FEVMqK6N88yel/lKA+k
         9KOSTnA+63ZTjnfQBOoOK7qmPFqezd0Jofhii11bS2msqH4v4hVeYyzBuZ6xp5ozH9bX
         Gx1LGkl+pOQw3N/Sy1fDeDSXf9Z84J44qASlkBbH1S93wbZ9RbKFBupeZ7x0w0Ua7RMh
         B0/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWDoUYDn1f+OaoaEFgHtyKwCaYehbqbbwdkcsDdK6qVSJD3Ll79pcOeVJQv9Cgzl1nXgil0uH/pb/aSiosvxU8hJnH/DgQVIw==
X-Gm-Message-State: AOJu0Ywejh5HXavLHDY5lBIe7gJencyldJG88Q+39RypzE8mVvCpsbuT
	hZXK7EagN0YPFwCNQpFxP/IrC4xrxvWEVJaStNT278lS3SaM0E6X
X-Google-Smtp-Source: AGHT+IEgI81+K/mBDmaM8dIWP4A+48OoEtNUh2loMCD47XeUwLFN20tbx8B/Aw4VL6jcRNdvWaZStA==
X-Received: by 2002:a17:90a:c205:b0:299:6389:2961 with SMTP id e5-20020a17090ac20500b0029963892961mr10501346pjt.13.1708538254605;
        Wed, 21 Feb 2024 09:57:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4fca:b0:297:2abc:75 with SMTP id qa10-20020a17090b4fca00b002972abc0075ls4209323pjb.0.-pod-prod-06-us;
 Wed, 21 Feb 2024 09:57:32 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXiRlsgjD3Az0vrFEGwhZoD3mETFcLCbSY9pahg9HE3UDnK3vQJzHG7jQg5vy4p9gTN+Guzv3WbyWUSoc0CF4qkwX4YlPlnpLf3jw==
X-Received: by 2002:a17:90a:d181:b0:299:96fe:1135 with SMTP id fu1-20020a17090ad18100b0029996fe1135mr8638621pjb.44.1708538251711;
        Wed, 21 Feb 2024 09:57:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708538251; cv=pass;
        d=google.com; s=arc-20160816;
        b=zuYsJ4WC/uz06I+AOBqVIhgtDCYkCRSaQc4RMSTjLVtzpr73xTXNHRZhA1dFhd9x8k
         HS2tZY4niYpYow2kWVQ8pejd43ZnX4HuvFYJHH8uNP+BLgodnF9ucW+TfiwnusEDnA/g
         hLYFO00I8FWY/UitSBP/Ov9eqh+Gfj4QwbdXqf8ipvjXYwTSk0AN/TExvDsXlD4/zPU/
         J6Cea/Bibj2i7EUw+bEInvys/nxXLuLpgcClDkFj9K1ZgEyqf7DjJeLKMiTgqGAq1iFS
         3AaVtoxoqP8njQ2KEneTJqSvCbwKOg5TOGSNe+QfENbDgt1G7pqvKodr1psVhSad0q1b
         rt7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=ohdBdAmRjzn/ur1B1BUK4Ux1Xy+rpyuKbSwdnqUhuWg=;
        fh=26WDJvrZTUBXr7OgJfLXCVa6QZ//IQ/MBN7wOTBCeuU=;
        b=T2sf5P4D/ggWAcOIS3vT5bJR/OplOIujZFKgubEmbi3SDWFJwGMkQQdGMinxigIRrJ
         DMiEWh2WdK0QnR3Z1tyXCFvzIn5BPadfe1HPm+Goxuqqzv5mCsDhwq6+Q6177dVfiMQi
         I2ZpsEZVlqqVXnceQYYdVfbzAJVU3mSfzViu9kJtzdAbisEmanPD5aAK/zbIAsntDtVU
         LVKLY0fSThlBtgOVD87BtQjioQSPlea2xEmcjaMA9Be9IDDUkRyW2WvMT1FZknJMN54e
         2Dw51nZHJHNd3Dm/B2uzON36JaBH86z8KOfhKP7SukOXi3yrf4lP+bfXZ3F5tvIXIW9e
         vDIw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=fdTtH0q3;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id y6-20020a17090aca8600b002994aca6132si806449pjt.1.2024.02.21.09.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 09:57:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355091.ppops.net [127.0.0.1])
	by mx0b-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41LEiEDV020144;
	Wed, 21 Feb 2024 17:57:09 GMT
Received: from apc01-psa-obe.outbound.protection.outlook.com (mail-psaapc01lp2040.outbound.protection.outlook.com [104.47.26.40])
	by mx0b-00823401.pphosted.com (PPS) with ESMTPS id 3wda6dt3hf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 17:57:09 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=FJAqPp7I2/x0U7z/WH+JEVKGhZw21OoDA5H70BsaDTOh/XQk7lRx0S0CljPBqDKkvTT9R0zU+gXOemIayv6/Nf+mgNIeeWXU9EXu0c9cxK0/qZnbkSaTt9R44ApQesSFbe5AxMUicwj93kfj2lDvAT62qUZ3XYYS/qV+Kptw9Xn9su0XnMBy1N9SipzgVI117OZfJSuoe5WGTRvh179C+0/tBV7W4xgRHi/TJwwChejeNo8Hwkm4QP55AyXH1HFgpPuBF174ogisfXCF41Y2PQfuSc6EHFCQprKKr4lwRhNcc/4lutGfAXCHfThiBqwcg7Kf6H3aQt+mnGbhtpzBfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ohdBdAmRjzn/ur1B1BUK4Ux1Xy+rpyuKbSwdnqUhuWg=;
 b=TfIzPVOLga6zuLvOhHK5d2HTkHgVFYQE/Buuwy31BV4y6I3C111MRnhRRwwnNZ/gRuyzbcgVMcL69fxfY86Iwt6BDYrzar+1830HS/cuJULcHGJmlV4X3D2jVumNqmWrv0esiyWWrR9mBgziO6iHzSgZ5GHK5Gm0X2i2E9RBnWRJdsay6C4If4+Ji6ZrYAfvpHfUYxoYaUjnpFB5763efQLgM9PH1Hbw5gfnMEKBfhisHJhfw4Z3WAWeKbhyCqDa6wK5BCpZD5tqC37RIFXP9X/Pi87AUzmnZBVLhD7fQUWbxA2+1Sl1Mwpx4VoAdjhWuThutveyCKS9frhvu0vcog==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=motorola.com; dmarc=pass action=none header.from=motorola.com;
 dkim=pass header.d=motorola.com; arc=none
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com (2603:1096:101:66::5)
 by PUZPR03MB6101.apcprd03.prod.outlook.com (2603:1096:301:b8::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7316.21; Wed, 21 Feb
 2024 17:57:05 +0000
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74]) by SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74%6]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 17:57:05 +0000
From: Maxwell Bland <mbland@motorola.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
        "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
CC: "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
        "agordeev@linux.ibm.com" <agordeev@linux.ibm.com>,
        "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
        "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
        "andrii@kernel.org"
	<andrii@kernel.org>,
        "aneesh.kumar@kernel.org" <aneesh.kumar@kernel.org>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "ardb@kernel.org"
	<ardb@kernel.org>, "arnd@arndb.de" <arnd@arndb.de>,
        "ast@kernel.org"
	<ast@kernel.org>,
        "borntraeger@linux.ibm.com" <borntraeger@linux.ibm.com>,
        "bpf@vger.kernel.org" <bpf@vger.kernel.org>,
        "brauner@kernel.org"
	<brauner@kernel.org>,
        "catalin.marinas@arm.com" <catalin.marinas@arm.com>,
        "cl@linux.com" <cl@linux.com>,
        "daniel@iogearbox.net" <daniel@iogearbox.net>,
        "dave.hansen@linux.intel.com" <dave.hansen@linux.intel.com>,
        "david@redhat.com" <david@redhat.com>,
        "dennis@kernel.org"
	<dennis@kernel.org>,
        "dvyukov@google.com" <dvyukov@google.com>,
        "glider@google.com" <glider@google.com>,
        "gor@linux.ibm.com"
	<gor@linux.ibm.com>,
        "guoren@kernel.org" <guoren@kernel.org>,
        "haoluo@google.com" <haoluo@google.com>,
        "hca@linux.ibm.com"
	<hca@linux.ibm.com>,
        "hch@infradead.org" <hch@infradead.org>,
        "john.fastabend@gmail.com" <john.fastabend@gmail.com>,
        "jolsa@kernel.org"
	<jolsa@kernel.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "kpsingh@kernel.org" <kpsingh@kernel.org>,
        "linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
        "linux@armlinux.org.uk" <linux@armlinux.org.uk>,
        "linux-efi@vger.kernel.org"
	<linux-efi@vger.kernel.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
        "linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
        "lstoakes@gmail.com" <lstoakes@gmail.com>,
        "mark.rutland@arm.com"
	<mark.rutland@arm.com>,
        "martin.lau@linux.dev" <martin.lau@linux.dev>,
        "meted@linux.ibm.com" <meted@linux.ibm.com>,
        "michael.christie@oracle.com"
	<michael.christie@oracle.com>,
        "mjguzik@gmail.com" <mjguzik@gmail.com>,
        "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
        "mst@redhat.com" <mst@redhat.com>,
        "muchun.song@linux.dev" <muchun.song@linux.dev>,
        "naveen.n.rao@linux.ibm.com"
	<naveen.n.rao@linux.ibm.com>,
        "npiggin@gmail.com" <npiggin@gmail.com>,
        "palmer@dabbelt.com" <palmer@dabbelt.com>,
        "paul.walmsley@sifive.com"
	<paul.walmsley@sifive.com>,
        "quic_nprakash@quicinc.com"
	<quic_nprakash@quicinc.com>,
        "quic_pkondeti@quicinc.com"
	<quic_pkondeti@quicinc.com>,
        "rick.p.edgecombe@intel.com"
	<rick.p.edgecombe@intel.com>,
        "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>,
        "ryan.roberts@arm.com" <ryan.roberts@arm.com>,
        "samitolvanen@google.com" <samitolvanen@google.com>,
        "sdf@google.com"
	<sdf@google.com>,
        "song@kernel.org" <song@kernel.org>,
        "surenb@google.com"
	<surenb@google.com>,
        "svens@linux.ibm.com" <svens@linux.ibm.com>,
        "tj@kernel.org" <tj@kernel.org>, "urezki@gmail.com" <urezki@gmail.com>,
        "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
        "will@kernel.org"
	<will@kernel.org>,
        "wuqiang.matt@bytedance.com" <wuqiang.matt@bytedance.com>,
        "yonghong.song@linux.dev" <yonghong.song@linux.dev>,
        "zlim.lnx@gmail.com"
	<zlim.lnx@gmail.com>,
        Andrew Wheeler <awheeler@motorola.com>
Subject: Re: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Thread-Topic: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Thread-Index: AQHaZO9h6psKGO7SGk25OSRe9qGB2A==
Date: Wed, 21 Feb 2024 17:57:05 +0000
Message-ID: <SEZPR03MB6786142493B476B96F46081BB4572@SEZPR03MB6786.apcprd03.prod.outlook.com>
References: <20240220203256.31153-1-mbland@motorola.com>
 <4368e86f-d6aa-4db8-b4cf-42174191dcf9@csgroup.eu>
In-Reply-To: <4368e86f-d6aa-4db8-b4cf-42174191dcf9@csgroup.eu>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SEZPR03MB6786:EE_|PUZPR03MB6101:EE_
x-ms-office365-filtering-correlation-id: 9d9aa498-b3b2-4238-42ef-08dc330683e8
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: EHZlv0SDyyBCswKHz8QhE6+fKjEQfTEOEOnsfEw8WEdafdcTxkcxZBO2/vj6FFUY2v9/9trYiQ6ovPZrHiLJRt0AYlbyDtvArwJM8Pfm8CQ5jYEjeE1tZwtXD05V5CIw5SHjSlz1Yy3e9xCLSCB0AXbwDq6ZJEdTY2XRxV9DwabpXTcJTE6s9SM3szosTeRI4kH/l9HiEoPpq6l3XOMqylPfo1GnRoNxPyb03Amwn2a8RlHgbQUG694iehl8XtHLPjP7S6BVy6mVilX7MgyDk+u47GjmaC4xNnCbrLfAG5p9MKDnXYsFXuej2a69o4viRvs2xDrjQ3z+uSAfX8hG43l/7pT5F9UQ+oNptrSSiJgD9KQFRV4Z+/Be/hcwGm0dgXQ7AIj4DzbYdms/ea+d58bFLMg5QDMT993ljeu9kyj+EBq/ycwVZSpMx9aU2wPkYtQzAcaeot9XMivuQSmQPoDjEnZj1IANgS91tY27ATWnzHCaESeO8t6Z7Cag88jsqB3Wvb0ZswuW9YMal2BkUKTfkZARtarjcU8/Fj56yIBqDDmAMxNmZjwqTHo/TvqPbvCPRMSp2P47w3npSvC4MkqC5aKgl3+sYOSY+Bro06Q=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SEZPR03MB6786.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?RDJlSTlhVzdGcnRNVC9PdWlqSTl1R2JlQi9BcW5LTW9sME51VG94SmtpdkdF?=
 =?utf-8?B?azRDOHRvSHI5VS96b1Jld1lEcTZRZitZTndxaUZDS29ueFk5RWg1SEFleU9K?=
 =?utf-8?B?WE9MZUVBTGdDZm9qSDdSUHV5QnhDeGgrTDM5STRyR1JzSGFURm8wN0lOYnpM?=
 =?utf-8?B?SEZCSGIrZUJtS2dUaHhYZ0JqVk40ZnNrcTRUd29CQUNpckY2TmpTdHJTTkh1?=
 =?utf-8?B?YzlyU1AzdnZaUGlaMXdXTllEc0xOWE5laUM2aDZPVDYxOThlM1hmbFJ0NWIw?=
 =?utf-8?B?Y3JCU000NkZBMTVnM0FHaWIzVDd4aUtqRWxKdFJsWmN1cWV0Q1BYQlFBOUth?=
 =?utf-8?B?M29iaFFQbUhKYnh3c04rK20xc1I2U3BFdXdvbUIrYU1oV3I1akU0eW1odFQ2?=
 =?utf-8?B?Q3F0dEZERk44M2xjQ0FoN0hxeFc2YUE4ZkFKOG9IYnNBUll5bVBRNVZVTmN6?=
 =?utf-8?B?Tkh1UW5XRUVXZkF3Y3hwZkd3MjNUOWJHdldDUG13Q3lmZy9aL2tkSEdOb2tK?=
 =?utf-8?B?M3U5bnpZNnRyZVRadzY3c29TT2lCTU9HYjA1OWxRS0lUZFpHM2dvVE9ZSklH?=
 =?utf-8?B?eTBPd21EQ0xjZC9IQkpPUVZ5elduZVpnejFIUFJKNXlFQ2xmRW5YclBtN09N?=
 =?utf-8?B?aDRxdGlzMzZ0MVZERU1tZzVFTERnMXhQbVNoODRocU05cEZZbXBXcDJXTi8x?=
 =?utf-8?B?dnJuZFQzYmNBb3J2U0c0S3lBeG4wMEhmNzM5ZThlYmNscVR4eUF0aVh4M3hV?=
 =?utf-8?B?M0cvUExwZmp1eE55VEJ4NUlsTWpqcjB5U1M1V1NVZ2V2dHpVb3NBMjlXQTh5?=
 =?utf-8?B?NkxvOUdjK280Z2pYakF3VE5jL3JxYUJjNTF4U0dickhwM3JRRjcxVktkTUFW?=
 =?utf-8?B?R1MyTU53T0E3MFdUeXRRaWxMNXR6ekRhNnBLVHZVZ1pkMG0wNXlURnk5YnJq?=
 =?utf-8?B?N0hlM1YzNEVNNTUyNDM3N1NZV2hUNlNTaS90eE5EZXdBNVRIY043aFgwQTBk?=
 =?utf-8?B?VkhkRVV0cnJZcm8wQkZuMTZnWE5aUzJjZmhwcjUyRm9EMDFwQ2N0QUFMc2dv?=
 =?utf-8?B?bUhvNHZkc2N3OXR6VXFkVnFRZ1k0YlR6SnFEZzF3WkVYU1N1WTk4U3B0U2Zk?=
 =?utf-8?B?aW9kdjB4RGFqd1pPTVJkeDVmSmJiVnR1UTl3UWY1WmpOZGNSQ0cvNW9xUzJ3?=
 =?utf-8?B?S0FrZmJVUko1UHdaTXBCZUY0ZDlPS2M5eVB0Q2hQdDZnNGhOcTUwTDdHcEkr?=
 =?utf-8?B?NlVkMll6QTQwTk83TWU3QVk0SE9nTjByWk52c0FUQmVZcURuYTh5MXptODda?=
 =?utf-8?B?WkRFd3JsdkFUQ3FkQmlUSkpsUGRYSU5RODNoM29pQmFLUDNaTS9xY3hlSEJK?=
 =?utf-8?B?NUR5U2lVU1ZHVU5tZTBITGp2WWlINTNnTnpoY0dqODRhSHlHcGVBMERQQ3R1?=
 =?utf-8?B?UEthYWpVRmZxMkI5MXhJNWlMZHYyd0VSMldmeGNlOXd4ZUFjQk5DUkVGNmUy?=
 =?utf-8?B?THpkL1FLU29VOEpPMmlralQ2VUdGTkl4R0JvK3Yva20rLzltWmtnbFdyZFdI?=
 =?utf-8?B?WXFLRElwMkZRKzI4TDZITjU4UWh2MnhOWmVSNkNMZ1UwNXlCNjdYRXdmb3Zl?=
 =?utf-8?B?cnVxaUtJbk45WlVVcm14N2paQlN4VHZxbWFCTzFpbncxRE1USzgxVWFNNHZt?=
 =?utf-8?B?VDdjaXl6Q1lQbzJqMWF2Z0dBdmxDcVY5eUdGTHdlZW1GWlZBNHVoMFlvcU45?=
 =?utf-8?B?Wm5wRjVLSFZ3VkxaeDZuOGwxOHBVK3pyTjBZL2NMYjdXUWFzT1F3OWtiWjJT?=
 =?utf-8?B?ZDgrbWNlWmZ3OWlmOTdmS29vcG5kS2UxTlV6SUpvMzBBN05TRlRIQ1loZjBz?=
 =?utf-8?B?SGw2cmE0LzFnMCtTcXVRZjlTYWJIK0lZZlBvbnM1aGNDN2d1aXRIT3hwMy8x?=
 =?utf-8?B?NFlkN202b25UQjFINm1qckJpQitZMS9zb2dhUzhNUlcrTXg0RXFnSE9pUjZO?=
 =?utf-8?B?WTFaazdVR29zSkJXMTRqSER0MVhQZ1l5Slg3dEs1Vk9yek16Zlh5OElxLy9l?=
 =?utf-8?B?amZ0UHJlSWlyYmtMQkdVeGhWSTBSSElzcmt1Z1UyMmFnQnc0a0Z1bUR3eEJk?=
 =?utf-8?Q?KjjA=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: motorola.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SEZPR03MB6786.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9d9aa498-b3b2-4238-42ef-08dc330683e8
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 17:57:05.5478
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 5c7d0b28-bdf8-410c-aa93-4df372b16203
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: YPFU8MGPpDCKjjZb95ddjheCAP3uJp6GUxYh1ARNI5BJGmk2nK4mXgKhdZbUBsjkzKFz3ru8xaW7USi2mSF6QA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PUZPR03MB6101
X-Proofpoint-GUID: t_vz-c102zLvZ-9DS63pGkPli8NM-ato
X-Proofpoint-ORIG-GUID: t_vz-c102zLvZ-9DS63pGkPli8NM-ato
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-21_05,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 phishscore=0 spamscore=0 clxscore=1015 bulkscore=0
 mlxscore=0 priorityscore=1501 adultscore=0 impostorscore=0 mlxlogscore=999
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210139
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=fdTtH0q3;       arc=pass
 (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com
 dmarc=pass fromdomain=motorola.com);       spf=pass (google.com: domain of
 mbland@motorola.com designates 148.163.152.46 as permitted sender)
 smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
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

> On Wednesday, February 21, 2024 at 1:32 AM, Christophe Leroy wrote:
> 
> On powerpc (book3s/32) we have more or less the same although it is not
> directly linked to PMDs: the virtual 4G address space is split in
> segments of 256M. On each segment there's a bit called NX to forbit
> execution. Vmalloc space is allocated in a segment with NX bit set while
> Module spare is allocated in a segment with NX bit unset. We never have
> to override vmalloc wrappers. All consumers of exec memory allocate it
> using module_alloc() while vmalloc() provides non-exec memory.
> 
> For modules, all you have to do is select
> ARCH_WANTS_MODULES_DATA_IN_VMALLOC and module data will be allocated
> using vmalloc() hence non-exec memory in our case.

This critique has led me to some valuable ideas, and I can definitely find a simpler
approach without overrides.

I do want to mention changes to how VMALLOC_* and MODULE_* constants
are used on arm64 may introduce other issues. See discussion/code on the patch
that motivated this patch at:

https://lore.kernel.org/all/CAP5Mv+ydhk=Ob4b40ZahGMgT-5+-VEHxtmA=-LkJiEOOU+K6hw@mail.gmail.com/

In short, maybe the issue of code/data intermixing requires a rework of arm64
memory infrastructure, but I see a potentially elegant solution here based on the
comments given on this patch.

Thanks,
Maxwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/SEZPR03MB6786142493B476B96F46081BB4572%40SEZPR03MB6786.apcprd03.prod.outlook.com.
