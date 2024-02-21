Return-Path: <kasan-dev+bncBDOJT7EVXMDBBW5Z3CXAMGQE77A3CAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D62185E207
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:55:09 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-29988382913sf2235517a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 07:55:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708530907; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZDSDRg+me61fb+PLlLhpG+2rzzT+9ZUUdSWZ7rj7r7xL+EWp5U1qpZe6TOHLuUV/YP
         9oFdPs06ffXJnNYMVBD8l6DbWzYOTbaKmSj52ezUX2T4Ve6ZRivHqNy8PMabYpBTtsHM
         koNeh88S6uSmNPlgrZjRl4WRv+DxGTslt2wTc1N0rdvGNI0a6Z7KkjOIon9KN88H2vPR
         Z2y/+ELG3sfYEoKjzIGK1Df4+JnXuUKt5WZDJK7DghBTY+fl5A3hrGLHuHZdh25gdpmO
         hKJfMm4Fco6UPhJcbpsh1C+Wolw5snMlLurPoHZg0GtdRcW/0VuAx0iPuyHWW/ecB3nf
         r3+A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=tHOXCFZ4Vz4Y5eKpgsFBOemWkQemuBRn/E1QvP+9+Ww=;
        fh=1HJqejrubSsP5yy41Z2Z03dMagTm8au4FmoATshlQPw=;
        b=Q36qnUpbTP15s6/m+qT+mhGc+vbbG3wURm4uGc03zSWurF4tFvc4BBYHljYsHquzU2
         Ac5C6FBySV7KeBD+P8Tzdo//hTHL89hrITUn1f81kStc/KjB1kC9chkdxpYD41/P5KQJ
         Wbg+ecM1v82sgZSMQcuKudgGV/bfLOGadcCYePFvva3LPhfjaUdCVyNfPF15tzA0oLwB
         0qcNuo/oKfBjDMzWZEBS5WM+WIjNXZfwEkiap1BvefiYXtnmSE4feZqM3HV37RqELdrS
         ZVWM64Mcl0Z0Nk0gziLJ30m+FiFeOotj883i4HOz2vX9FjAtjZbnufOLkjb/ONrL+6ih
         p7uQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b="V4Vmcbb/";
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708530907; x=1709135707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tHOXCFZ4Vz4Y5eKpgsFBOemWkQemuBRn/E1QvP+9+Ww=;
        b=ZBwSYmo4TM6u2+fzmXOoS8pCNOtxCB/5g9Iwlt01M7j4sp/l+WSy3ae/a3d4+7JJRT
         EijH0YDOLgXecEiSjr1IkoLrD2cdmDf5hdDxIiQjVisa8UMRZvAc5FyIPK6vhMcxuJya
         iBTKn2UNJ+SfNhTyXdlBU5ylDdosAHHo69gf9yg/EwmDNR8LkMsTu1R/wCB+fzuCf/hn
         XSccA7cK/KU0Eh9FCvSMQqUvpYe+DdNwYKCptL2v6nBPYtGzXJh+nGXGJQJDMu+496Vh
         oGDePv2IGODFS38vQCBHrpvLutj+bQojUfbIj5rk6wiz2hK8Hnosf9RuXovH+RaN6nJg
         CMfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708530907; x=1709135707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tHOXCFZ4Vz4Y5eKpgsFBOemWkQemuBRn/E1QvP+9+Ww=;
        b=e27AmPwv+E/hAMDro/iKpQRTEzkTXPO8O29bW69LWQPRAC1n2xoC8GhtdDuD5loIqZ
         YWAm2QmB+y8qDnNxNZ2PyYmB6tyJSQkgnauPDTE4q5m0l3nkyKHBX8DOkGjr6Gu4VlCE
         EdXooHsZ2h1wYpGGQRT1UMjca96R+BxADW7/G9D/O7FzFbxg39d/YGlk0mG3XYh5lVwM
         ajMHo2gfFD76jWI46CSdPMNi6bhwxCXxkUKx/neU5fEhvoivrKJ9Y9MtjXXBqjpP++y9
         ItImHRWb0jQ5sdLMf7S+Atqdbaq2ILtJkoO0wMXXxGm3Se71mTupDvmShqrN+8sS3hyb
         FL5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXtP1fZv8c+kO1xy2qvY7dLadu/Pe3iqLDdqLxlzIOzya31xCqmNRZ8flkF/7Oq4ea4/a32ZdMCIKu8ezttbWerRRuVbxBRzA==
X-Gm-Message-State: AOJu0YxxAKuTKt0VJB7qhMiii5uPqfNHQ1Yx0V0qtQbtBoLg7aG+alHO
	1ecgCaOlDHdTNauFEaxWiq+Jw1SaEhXmAZYKZxDXSTpbngmU/qch
X-Google-Smtp-Source: AGHT+IFPMhVgo/hqj+sCALN3a8ey3ez+e5uzuhRykmBG8UzGPgGdyJh3D0ey1XR3m5hW4EYyH8TFXA==
X-Received: by 2002:a17:90b:90:b0:299:5ebb:1ee0 with SMTP id bb16-20020a17090b009000b002995ebb1ee0mr7781256pjb.28.1708530907525;
        Wed, 21 Feb 2024 07:55:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:5111:b0:299:7c4f:efe8 with SMTP id
 sc17-20020a17090b511100b002997c4fefe8ls2113494pjb.2.-pod-prod-01-us; Wed, 21
 Feb 2024 07:55:06 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUay5gKxUqdoIQ0Qj/7nVYw9FMrHKJT9O2isHcYmLkAWyJM+iwSkIH+vgZWZ0N2uFr7xponLoG08sQVJoF0u3vRf/m7tr3myKhWdg==
X-Received: by 2002:a05:6a20:d806:b0:1a0:94a8:400f with SMTP id iv6-20020a056a20d80600b001a094a8400fmr12059787pzb.18.1708530906443;
        Wed, 21 Feb 2024 07:55:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708530906; cv=pass;
        d=google.com; s=arc-20160816;
        b=yS6A0/j/kfkOwpPAP9oQkGD5QcW784K9Dpo3bTjTP3Rgfr5HnkiETUhUmWNrWybCJ4
         026wJQ0qlRtkfm+PomYulLGvky6IGCfunJL4LVUl6JJ5EkQDMc8gRoPTppmSkYCrmWDJ
         KHC5HPO6PC3jNvfIpEJnpnS/YNw5ar6L21n8GxxEKs+PP/cQmLG8lOaEI6PQsPjlXuvd
         xthBde55Ln1vdRJIn9M4MHYiRvcyamDEQffsR1V1hU59qR7slAHPV9PF5xYIBxN60kml
         el2eLvQh3iwOuZlNURSy1OBoDiEcom9+NJs7eyg28A4qzRB8Z5PMzpBqFz5nz03pidw8
         fFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=Ndv5CT0ope3GRC9NxF40lrKqbTEAg7f/d+wP18JLdi4=;
        fh=dghTBoit9Kn+3xePKPvSdvKekQ2OQyVIxKnX/hj8XDA=;
        b=tRlBxczpOKUaPjmcjX2hp1bCvJQSr25L55M/vlF+4T819SnsQH9cpP0qMX41nHEsvW
         QY3YolORSXwMZZac+sqtVLhw4rcBX4DlJ72D8f4v9WIIfDE5f5E7B41koxeZkwhcsVM4
         kLxmWYdafkpEIFiFdu/MAJIiF9WlZrxlv9TBpY/+LxDnTI7vXWJ55NF712l/59cEf50C
         fjgobhtzLJkZT+TA865wIG18UUKI6thaN3J0Kd/TRyD8CU8nCeFktVyLHnUuK5RDMEDF
         amU3K3yRseQ7hS6MouPWVpoF590KLBIS34Txsix3qRuK6uKcIesA3POsGBjs7RLhqFSG
         g6/Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b="V4Vmcbb/";
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0a-00823401.pphosted.com (mx0a-00823401.pphosted.com. [148.163.148.104])
        by gmr-mx.google.com with ESMTPS id hw10-20020a056a00890a00b006e460350a5esi579265pfb.4.2024.02.21.07.55.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 07:55:06 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) client-ip=148.163.148.104;
Received: from pps.filterd (m0355087.ppops.net [127.0.0.1])
	by mx0a-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41LBv8ea005111;
	Wed, 21 Feb 2024 15:54:42 GMT
Received: from apc01-psa-obe.outbound.protection.outlook.com (mail-psaapc01lp2041.outbound.protection.outlook.com [104.47.26.41])
	by mx0a-00823401.pphosted.com (PPS) with ESMTPS id 3wd764t05s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 15:54:41 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=UII3ZAwmlHdDEq3K7JkHbO7U70o4b74Z3VGFinEac9Po1gaXITmBbL/B3AtVuT/z5nh2YKF/3XmK9T9z+diiqmuYHMbF1qN/UDtHcnqPGQfegTnv4ZP3YJEmHDP1z1wD/VwkzXj+9iu3mlXIB4baVvU/C1cs918NYd8QJgbMdXBkGb5jg0EGy3zxMbk94mt5WS9X3kH672irrV3FMtO+vmSEthEKV/AqL2rYEnPbQwMk8rYCoKjS4EySo1nlZ951UKQut1l9TCZJ/upp0MRiI6bP5vYkJUtnKMo7MJ3rREFZwgHzyPSv858HGBGt06gAlPNzneHIsXr/3q2WZDjwTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ndv5CT0ope3GRC9NxF40lrKqbTEAg7f/d+wP18JLdi4=;
 b=RtrPGxwHnG5Z2VBqJ0M+tmTRlvTp0CozH7cke2N1jijHQ+SL0GfYIuXu7xxpI58S3tRCNB8EojTeWKiTwOQ7PVNV8ITL+t2m5/C6scxhBFAn02KvV/fpWnS6rDwoGU4XjYtw9bVpbWyNvXSzR0HxN7nr03gxAhmTXWbiWU42XLBHQH0gnziYNU365fTDAN2apj11tZK6NQwDdp/z/77kb3pdQcS2lQPXrwswZ/n5Bq3jWCl5sGvXS7YVA3voDi+Y2+EQITt4ovwst50C8L/tZCW2mGQP19YWQFr1KQRlTMPY6zXxfTvJPcDvHzMSpV7Dppuq4x2686q+101poD/EDg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=motorola.com; dmarc=pass action=none header.from=motorola.com;
 dkim=pass header.d=motorola.com; arc=none
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com (2603:1096:101:66::5)
 by PSAPR03MB5558.apcprd03.prod.outlook.com (2603:1096:301:74::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 15:54:38 +0000
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74]) by SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74%6]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 15:54:38 +0000
From: Maxwell Bland <mbland@motorola.com>
To: David Hildenbrand <david@redhat.com>,
        Christophe Leroy
	<christophe.leroy@csgroup.eu>,
        "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>
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
        "dennis@kernel.org" <dennis@kernel.org>,
        "dvyukov@google.com"
	<dvyukov@google.com>,
        "glider@google.com" <glider@google.com>,
        "gor@linux.ibm.com" <gor@linux.ibm.com>,
        "guoren@kernel.org"
	<guoren@kernel.org>,
        "haoluo@google.com" <haoluo@google.com>,
        "hca@linux.ibm.com" <hca@linux.ibm.com>,
        "hch@infradead.org"
	<hch@infradead.org>,
        "john.fastabend@gmail.com" <john.fastabend@gmail.com>,
        "jolsa@kernel.org" <jolsa@kernel.org>,
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
Subject: RE: [External] Re: [PATCH 2/4] mm: pgalloc: support
 address-conditional pmd allocation
Thread-Topic: [External] Re: [PATCH 2/4] mm: pgalloc: support
 address-conditional pmd allocation
Thread-Index: AQHaZDwOaIoKplpm30WfPRJTeTXuwrEUYmKAgAAlawCAAGuRkA==
Date: Wed, 21 Feb 2024 15:54:38 +0000
Message-ID: <SEZPR03MB6786F9F84DBC9B5DD952C70AB4572@SEZPR03MB6786.apcprd03.prod.outlook.com>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-3-mbland@motorola.com>
 <838a05f0-568d-481d-b826-d2bb61908ace@csgroup.eu>
 <cf5409c3-254a-459b-8969-429db2ec6439@redhat.com>
In-Reply-To: <cf5409c3-254a-459b-8969-429db2ec6439@redhat.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SEZPR03MB6786:EE_|PSAPR03MB5558:EE_
x-ms-office365-filtering-correlation-id: 50a5abcd-fbf8-499f-ebf3-08dc32f56897
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: RB/tgIT3MafxK91gE1//hiiBG4JGFcf1CIoZ/s6O2aHLrM8qKGc6UU3BvOSst8ITwn5bGwqda4HlbjMjIbaRL9aTotmUqdqsiZpiyFTeqTKB/mpDDbvrHCGhNId5MixUfds1wtMvqFiPNdy0Cu1rI6zL6Sl3A5YGYxXzXdom1rRIcFLkTkoR24PeyIXLkj581meJelJiap5WNzet52ocGw+J+n+bvqtySH+lisEySJLSzwLHViyRcJijsY9XkLCCg6VJv1qw7eqoUtY8uLPxhY3fhQ6Vkvut6pQU0eJbkh0WpV309UYu0UtxWKmSx9VlKs2cBcbfWAregoIFnP9JnNvFdoTBM52pWvmeI8wAJWOrK6Z24uS9Hcb+GjRBi4uxwsL0qRT2wMtk+oWWehdLZt2qMF1He697ZOehdCryMKLc3OMhMs2owRZr3jhabS421HHRuMmKFt/s0WzOw5FoiUz4i84UVIfidpT90NCwmvTYkHyJba2nbW+R1777E6nkLFBNeRYlQI6NyupPt8T1Zqgr2CUvp3x4sExFKOF8WMXKcXp+tasHpvo3vgTjySQ0zl3ro59YaCPkXKlf84UfjZAbSVRsh+UFfpoIWijEUJ45pe5fkucXVBnFXfOVeSjU
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SEZPR03MB6786.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?d1FHK3hBZXdzM1RXbVlON01iSDRLdzV4ZkFoUnpVcy93NnF5QTE4YnY2Uzc0?=
 =?utf-8?B?bm56cUNZTUxpekFqN0tWT1hicU1QaGpxcUVKMGFQeURkN04zNVRUQkxCbmFr?=
 =?utf-8?B?ZjZpQ1lmYndURjVWMnRHRTl6VWErT1BnQ0taYUZkSkxmYk9NMExBWDc2OGdo?=
 =?utf-8?B?WFU4UHBEdXVVcUFpa2hnYmFGeUErcEgxdXhPUGRKQVFBczBld05GWWpwTEQ3?=
 =?utf-8?B?NDZhS3lYT0EyZGpETmdCUnNObitVV1pZdjk0MFIyOVNwaDlEZ2VlcXRydE1T?=
 =?utf-8?B?OFcrQ3FqNllKNjdsZ3ZDK0N1NVlmdVR2NFY3Vi8wYUM1ZCttRGd6bDVRNk14?=
 =?utf-8?B?c3MxcVM5V3haUXhKMTIwN1B4WndsYlo3WmpFL2s1dVhDSHZ4cTRPemdtWWlq?=
 =?utf-8?B?bjJOcW1IaUtGWnh5QS81dUkyZjllVDVvanlDRUhCZTJ0WGpwOVppSFVZZ0la?=
 =?utf-8?B?cGZsVFdLU01ab3FZUm9MaFlDa1crMXlReTRBLzlDbjV1VTZqKzUyUStMMDIv?=
 =?utf-8?B?bVoxODRKNmxJVkFEcTRNcGxqd04veFAwZ0xGWUFMZm1WRXd6Z3ZvMit0UExv?=
 =?utf-8?B?ZXprbkRKUzNWTVRtU3V4TVEyME1KaDl2WE5wMndkWFlINXlxUVZZU1JCYkFm?=
 =?utf-8?B?SVQ2VE9zWTRtSTBsY0RLa2RrNjZ1a29rd1Jld2dnRUdEejdyMUdzdHNmZGV5?=
 =?utf-8?B?aFFxSmFJY01zRzRuYUE2STNVeDRBRExMZlEreFN1ajRvV0dGWlFrRGpuUlJp?=
 =?utf-8?B?Y3RzRUdqdUJLdGw1WHdPNUZtT1Y1Q3lsekliWmVScmdzeDRVQ3YveFdBNTN5?=
 =?utf-8?B?WWhMc2xjdmFlYnpzTi9lMGxESll0am05aU1DVzZzUGxsbE1UL0lSSEtyTjlo?=
 =?utf-8?B?aG4rN1MxSm9hOGk0THVuV0k3RmxNY054MDhlNkdaWmxUOE4xTkxUU21WTnF5?=
 =?utf-8?B?N3V4TTBTOHZyR3MxOEo3cTZkQkYwWXQrdHNMWm8zbStOcjg5Q0ZrQWFxZTRD?=
 =?utf-8?B?OGI0U3FDcm83NXovTFdaQ0FXVzhnRHhhekowUmU0S3NNVkVXWWxtMWMwTSs2?=
 =?utf-8?B?cXUwb3JzZEVXUk0rR2JsT0ZMbU5qMlRZMHgrSWdkakNBQ241d3phTjQ0dUxt?=
 =?utf-8?B?UmY2OUhPOFZOY2V3Y2Zibk9BQStlUGQ1VGJRd2JVZG9wOTBsRWIrNk1KYW9u?=
 =?utf-8?B?Y2NMU0tFeUMxeVVFMFo1ZjZtaXo0R0JiQkJzemZkOE0xdDZQRUxIUC9ZMTlN?=
 =?utf-8?B?aVltMjVmd0p5ajh1UVF5MTBHT20yR1BKcDV4UDd5SWN4NWdkYjdOOFdvMjUz?=
 =?utf-8?B?ZmJNVElLSXlEVWx0ZktTemhIU1Fld1lieXlVREJ4dmhrc2ZSUEFXQ2laWU15?=
 =?utf-8?B?UlUzNEdEYmt5RWZNWUJEUnlUbW83eXJuZFZBdmNpcGdXZlkrbDdUNWhndnVF?=
 =?utf-8?B?VS9hN2VESW81N3IrNklsZEhBUkVKQnJiMk1qTUJYeDh4YXE1Q0k5M3FuQzRT?=
 =?utf-8?B?N2NRbiswczdSTnU0NUpSQVoxVFN6MElTSzBzQ01SQWZnYUlpb09lZERpZDBq?=
 =?utf-8?B?cW95RnAvVWFpNDd0SVNtVnRPZkRHVXk2VlJYbGFjNGhPWUlhcTc3Q1N1L3hJ?=
 =?utf-8?B?QW5pb0VLclpKZzU1VkNoS0VqRHBXSXIwR2hud0Fxa2lJR09PUVpISzFEdEhY?=
 =?utf-8?B?K3lqcVQ2aE5WNTJsVjV6K1hhSnJHVjNBN3E2ckpEcDRDanhMSTdhOTNxZUNp?=
 =?utf-8?B?VTFGbE5jcXNlVmhSRTQ4VEJFZFBINFJmaXRMNjdKMXpBb0NudWJHY3R4bGZY?=
 =?utf-8?B?amIya0cwYUhxZ2lseXNlaG5xUmJEYVBXajdVcXBwMjF2MW8xTnJZcWRSMmh6?=
 =?utf-8?B?YWVCdWd6amJwWHl1dDhCSjkyd0RVVE5hNUtYMDRiS3hTMXRaNjdEaHNYVVF4?=
 =?utf-8?B?bXNaM3AxSEk1VHhra3dDY1RJQ1VwWXZveFA5bWVHKy9mZlNvOGxkOEUrclF1?=
 =?utf-8?B?QkVmS2E0YlhpSFhMeC9EWlFoOUhvQkpJU3pSemNCK1dDbjV2N0pVbmg2MlNI?=
 =?utf-8?B?dnNiMXFPSjhNSGtxMndFc1pXWTg4SURib0QyY2c3SUJveGpOVFY1SDlDRjc5?=
 =?utf-8?Q?SMmk=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: motorola.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SEZPR03MB6786.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 50a5abcd-fbf8-499f-ebf3-08dc32f56897
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 15:54:38.2323
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 5c7d0b28-bdf8-410c-aa93-4df372b16203
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 6ZO63d4wdasEh+ilKMHhwVd+IuhRMTs+U8pfg1HPGCYEIeSkWmfrZafrs3mJoPzT/yOxhTCGJsa6Q7FaMrgkcA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PSAPR03MB5558
X-Proofpoint-GUID: 4noMEdWesuHzJEjFJ2n8AjKVuCDcOQaC
X-Proofpoint-ORIG-GUID: 4noMEdWesuHzJEjFJ2n8AjKVuCDcOQaC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-21_03,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 malwarescore=0
 priorityscore=1501 impostorscore=0 bulkscore=0 clxscore=1015 adultscore=0
 mlxlogscore=849 spamscore=0 lowpriorityscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2402120000
 definitions=main-2402210122
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b="V4Vmcbb/";
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass
 dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);       spf=pass
 (google.com: domain of mbland@motorola.com designates 148.163.148.104 as
 permitted sender) smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=motorola.com
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

> On February 21, 2024 3:27 AM David Hildenbrand wrote
> On 21.02.24 08:13, Christophe Leroy wrote:
> > Le 20/02/2024 =C3=A0 21:32, Maxwell Bland a =C3=A9crit=C2=A0:
> >>
> >> While other descriptors (e.g. pud) allow allocations conditional on
> >> which virtual address is allocated, pmd descriptor allocations do not.
> >> However, adding support for this is straightforward and is beneficial =
to
> >> future kernel development targeting the PMD memory granularity.
> >>
> >> As many architectures already implement pmd_populate_kernel in an
> >> address-generic manner, it is necessary to roll out support
> >> incrementally. For this purpose a preprocessor flag,
> >
> > Is it really worth it ? It is only 48 call sites that need to be
> > updated. It would avoid that processor flag and avoid introducing that
> > pmd_populate_kernel_at() in kernel core.
>=20
> +1, let's avoid that if possible.

Will fix, thank you!

Maxwell

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/SEZPR03MB6786F9F84DBC9B5DD952C70AB4572%40SEZPR03MB6786.apcprd03.p=
rod.outlook.com.
