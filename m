Return-Path: <kasan-dev+bncBDOJT7EVXMDBBV7B3CXAMGQEUINCZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id BA3BF85E46C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 18:20:24 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42c6fb437b9sf418041cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 09:20:24 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708536023; cv=pass;
        d=google.com; s=arc-20160816;
        b=aBs1bf2b17s8kZCiziYkZRiuOQq1JV9bIMv/Tq6nWB9mMPOPF875sxyNm7jG0odp3c
         mFo+AcSSukDhu0FYoe691Ud9z+MBzrfHOlmoTYEfhG6y3nESQN6S9AIGq3v27d226TJw
         A8lX3kMG1UZN4O1OsysPJintWR+j5lRstUv8+0KdQZuXmdqolbshyD5Bo3dZF5gn72go
         7ASA5mC78FLSgQ4m5yYuRFGKHHZ2HZu6NCIywfwtqsbt3Mikc2sK3l4wNh3qiennhyjC
         t2OPCkBxE5giqdHKFufc+LR9D5KWnwEY7cY8IWe8CBwZBD1OIvyVQVBWuIitUJoQGlEC
         yqpQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=R2t66Z4spjgK7oBQjwkbSyFl+6IgWcumIBORbhsArP8=;
        fh=YMY6ZiiG1ivK4uSARefGlZdpjjAIl4CxuJ5U7pGJnXw=;
        b=tvc3gy9QsVjPVpGup1J86p9Z36z5zfgsl/FV0yh8rrxTpdn3uCBeStahumLBkisLqi
         h2JJOX7WAmiPiaG1odDR5qFQwcmEGQwxRMYD0/eg0/y5cnYVXctbeDpJr+t5kAUchYhG
         qTFLXAKxIJpsmI7t8/S/oKhPMRokPhNsOuh9makQVlbyD3cVdwdURj0UhFH/7t5lbPOK
         Upr6LVlTlq87AoJP9sK+gcueCeXqvGg01aU6ii+YXf9w8pjH0IZ75R25zVyImftNLx2Z
         zKwVtuPAR0tchTP8cjoisXzEgphxpJY+W/BpfFldpfLFsxUa93j7pk3LH9Xh5HSqupt/
         Pe+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=YRjAyTGp;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708536023; x=1709140823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R2t66Z4spjgK7oBQjwkbSyFl+6IgWcumIBORbhsArP8=;
        b=N8EybhixP2QLdiesztBvw3FBhO2lsYv4OuTKfa0R5D1mAcALXJGI5mE/uxaHO9xEpG
         QxsIElWQGs8hOd/X/EsNuP+IiSylsmMbfptpnyB8QwUcnGtHnCylr87RzhdJy9XuDUrZ
         NOZoZ8MxTPwByMdXwSD17hL5/S+pXWikSzVtVFJb7/JRMDh3xWZ9Chke25cRSmc0jIcv
         BqxtKOnIbjCEre94CAckwEZIvZ1ppEdiGs1yFZS6dWsBVQeccBeCt3ugX8Nv9KyrIs8L
         WkAxHJuH2KPenKRKtGojbyIBL36L1I1fM9Gbel20PHI6pWjw6yMO+95tDei8jYZ8kpnI
         rtcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708536023; x=1709140823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R2t66Z4spjgK7oBQjwkbSyFl+6IgWcumIBORbhsArP8=;
        b=Ob7tY3FzD85vHm7hBIcJGmpG358z0Il/6rDaSVyiYZG33SBj1j/eF+qSLPbb8X9EBF
         T+Llo9R2Lf9kWOGzPsLzHk5VM7n1TFheu7STnCSsEpXiSP7MnFIoKGUKXZVkJNk/o7b5
         3nyuSGmCjCwX7Vi5/iZKqE42Loa2g+10FL6leJn+83OPvN5AbkB2GWU2YZiiWzv1n2pp
         QjfzFPnubIAMtK+jm5sRDM2BXGEhTPFAhzuuRDrGRdeW4u2lmb99PgCmQNqM/9MB143l
         aeeL5BM5itxvBRnSfh7dsiv8rWnBGeDn6R8grnhiPnJ73YsoRD4FtgwABZpCciV5bMsY
         GQyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCX0Qf6oZLBhm+Nzi3n7XQ4n//d++s498GbUanMxROXDj9mT6kiCQ5PfqK66D6hYC4p6VtaQ6+eUT4saz7m8m93Sj6OjvJIDzQ==
X-Gm-Message-State: AOJu0Yw240GvEyZvXkK+GtCpforNEvV/1MzcvntvjRIjiZMtpCzdJt1c
	CPnMl/uwxv62gLqGsIQBBXksAxrnTgIAIfM7vNN/6quXRosY9vxV
X-Google-Smtp-Source: AGHT+IHn4SvZkMLlxjbceHwIFyPGTfecqq06K1HsSRdMVLGw/J6dCKlwnkoeydPk78i72gwVQJNoqA==
X-Received: by 2002:a05:622a:134a:b0:42e:2898:2e3 with SMTP id w10-20020a05622a134a00b0042e289802e3mr318513qtk.23.1708536023565;
        Wed, 21 Feb 2024 09:20:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e89:0:b0:42e:3234:6afc with SMTP id 9-20020ac84e89000000b0042e32346afcls779751qtp.2.-pod-prod-02-us;
 Wed, 21 Feb 2024 09:20:23 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV6fvYoH6NDTaNLn36K5KSeluoRpOMm6BTiMhyuA17Cew/TXl0IPXiWoxt6/2/Ij9FAdVL+mtCKx/fuM8jA0vpQjngEWP30dxR6wg==
X-Received: by 2002:a05:622a:14c6:b0:42d:344d:9b with SMTP id u6-20020a05622a14c600b0042d344d009bmr24664498qtx.10.1708536022746;
        Wed, 21 Feb 2024 09:20:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708536022; cv=pass;
        d=google.com; s=arc-20160816;
        b=OzMMPpL3v3+tDl+hZttP+UK7B7Pe0Bqq+9gGdbqsShI/CnSGl5EdvV6CgY8G5GEnic
         cl+Xjtw//lA2LDRKfazf79/yQ1XCezNIeeC0xSmLq92pI2rqtMbG6jLCBWAF4Q8yATiN
         hUtLClbCq7EY2NAWi1f2kTtF7rttgRckI02yr99x3pJ4GFdg8YYIMrLaFmQqXIMxzN5Z
         7UbVrm4/4Irk17wesf27EzxOsl3b3arMZwz3OqJnoQnljjHXuf5NHd98QDabS8K3IMfY
         HywzXYRK3BNhFiWjsEOs9WcS1eDcGSaEtEZRPdKgjleN/kvgKCUZcKssypwR+xDBYcVn
         T6Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=A16FWm2ylqNOU3f2uziRcCTYLkAP3hC2xgtH7xfVk8I=;
        fh=26WDJvrZTUBXr7OgJfLXCVa6QZ//IQ/MBN7wOTBCeuU=;
        b=b+A3M+sNbJhWtt/enCUDEvj+Xv6txaa1WuNcjEDaiIHPO7/K9GMUnwiFCtW2plkgFh
         NeyGbjffLO8ef1XEEpoyPvpBqyJV3CD1ylDsY0xvWngLFAx61d26ZRrLEeW9LrvceA+6
         tnHoNf8TFQdLflMKbkHDjCfgGwJjzLqaKtDsPQcU9LrYRa+s23VF8uUa1nQHa0XHcRph
         2NN0TcvmrTlW6YexCZb+r6cvmqTa+FNvJ/EH5xZyWmGfF2rW5ZP35bXmU7QjSFgs0sHN
         +unSgETb3Cwz9INKRBkhKDobmTBPHQyUKtmTmfS8uTunDR9YU040hGGP+DM2ALa+bXSH
         388Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=YRjAyTGp;
       arc=pass (i=1 spf=pass spfdomain=motorola.com dkim=pass dkdomain=motorola.com dmarc=pass fromdomain=motorola.com);
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0b-00823401.pphosted.com (mx0b-00823401.pphosted.com. [148.163.152.46])
        by gmr-mx.google.com with ESMTPS id r13-20020ac867cd000000b0042aa4e99da3si425016qtp.5.2024.02.21.09.20.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Feb 2024 09:20:22 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.152.46 as permitted sender) client-ip=148.163.152.46;
Received: from pps.filterd (m0355091.ppops.net [127.0.0.1])
	by mx0b-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41LH8G9C020266;
	Wed, 21 Feb 2024 17:19:58 GMT
Received: from apc01-sg2-obe.outbound.protection.outlook.com (mail-sgaapc01lp2105.outbound.protection.outlook.com [104.47.26.105])
	by mx0b-00823401.pphosted.com (PPS) with ESMTPS id 3wda6dt1tu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 17:19:57 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=W6KWxvvHlU0jWj2vbiDwmEfEaFfZRsKV9SZcAAA/oaQFwTXKGX5YAXpH1kikXwDKZi46NF3Cb8siyLfT+agJWylkT23iCls2CVSZmgORiCOqsP8U8ueAOO1v/i+WjJxr9PYirjWjgW+zcQvd/e1W3cJmkzwMSTV2L40DpiBAdWAGhLDmjXAgntmLOwzb8d9A6wF5McbqxR6utG2COo2aVuWMFSzTesHrkIlBzl0lkNb5cY0DTIT2m9763Cx8FLe+0LNA/zmg+Y+AuRdvjKkIl+H8YZEXFZ3atyOSVx3EX4++acGcymlnvNekcTedR42wlpcLlHZYd0QMNXwCASnmWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=A16FWm2ylqNOU3f2uziRcCTYLkAP3hC2xgtH7xfVk8I=;
 b=MGTcODYIFmAuCAI49fvDrL4NXE0Ie+i7tOMKoWFATIXd8slCTzRQnj+tTMp69quoqr6TpkwqgkdaW4mOmKDY229XP86B75nj/dofZ54cYkt/9sLVGREYTutUM9eA2k7jwbQ4bz7m2kHzwRCUUpGyWK4IQOIUwRTDHUBhQP5kqKbcm40OVuk6lk4cRpDtwGMgsYUnn8FY3P0v85pHQopRmgR0d2P/kWszyG6oEL1kqWXQ5G6JtTTMpX+DbQnfogxfTffWE6IeSwV29VAnIhxSHu+ixFyJBgG/6+tDzuIYvSw/We3m9Wv+2ZHpeUIhASG3aKR4lqegCHhf9pGA4baHhw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=motorola.com; dmarc=pass action=none header.from=motorola.com;
 dkim=pass header.d=motorola.com; arc=none
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com (2603:1096:101:66::5)
 by SI6PR03MB9032.apcprd03.prod.outlook.com (2603:1096:4:23a::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 17:19:53 +0000
Received: from SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74]) by SEZPR03MB6786.apcprd03.prod.outlook.com
 ([fe80::dbc8:b80e:efaf:2d74%6]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 17:19:53 +0000
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
Subject: Re: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node
 overrides
Thread-Topic: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node
 overrides
Thread-Index: AQHaZOovDm6xvxRBMUiuzkOVo5kMqw==
Date: Wed, 21 Feb 2024 17:19:53 +0000
Message-ID: <SEZPR03MB67867ACC0D9AAD3A3AB19EBAB4572@SEZPR03MB6786.apcprd03.prod.outlook.com>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-2-mbland@motorola.com>
 <4026e0f4-f0f3-4386-b9e9-62834c823fc9@csgroup.eu>
In-Reply-To: <4026e0f4-f0f3-4386-b9e9-62834c823fc9@csgroup.eu>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SEZPR03MB6786:EE_|SI6PR03MB9032:EE_
x-ms-office365-filtering-correlation-id: 93a026fc-7063-4f6b-da50-08dc330151a6
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: jNK41NW185C9Av48J6JIwOOAcGYr1P7xl/03poGw09xEkYOlInmAhZA2h1ZyikrYsnZUl/MTbtoCkOvAcA4U+/4zLDeur5RC91agxgm8/w08HH1XAaNFuiGz0vkWJKw7gUohL6InCSSr4RliC86cQiPkgFAFVWUO8++Ziv8OgwiSF4/rypBMu0PBcoRN6MGp48ZAWxIVz9+GeevU3ZERXuDEWUiy7cUJAoP4IhNlY/f91AjBbMYHHUyGT+DIa16mDz4nIXX/adGsShcTS30Xx0EHTA1aJ/Xp+SHvcSxlczFCeCObwG34tkYIL7Hzeq8x87nvl8NIvNL8c3ZnxrieXOuc7H0/uoWQv0N8dPGjrnTxQhYpHCrVp22W+XuRxrdcO+XfTAluKF+qJcM7PU9FdCnrZ6NV014YA7U9Qa0faQnhNLPC1F+r4NmAqcuZqxWNDdcyBY9yeB+Jjza0vGecBWDZgSof1Dul3B/1izDnlW4UqQyzPjak8edYUTro2y/kYapUtWYP9w7VsiEbVI5G7f4zvp46u6gQZycMTK2H3C8BQg+7tZtbHQVFKhGMB5Z3n26fKhS6lZ76SyhpRlFIR6yiboCn5ixyydobYcZqKrb1G1LuQ14xodrQbkaerdRH
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SEZPR03MB6786.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MStISkhsOVo1YmpraXFUaDFmdHZXV1RUMUdyUXZ3WTRmbHhjMW5jVnBER2hq?=
 =?utf-8?B?cFhBK0doTUcyYUZvcXJWRWlPNVZ4QU1NQ0xDc1VucEhlaGNlTVFCcDFxb0lq?=
 =?utf-8?B?R1VhODFvNzRRQUZnaWFjc1J4VUFBdkJTMVBrZzN2Mnp0QngzNno3SU5qN2pW?=
 =?utf-8?B?ZWpuUlNiMXU0SDNuNDhBUGwwTWo4ZXB6WmZ6REV1eG5BQUJvNVpubW0zT2Rm?=
 =?utf-8?B?dC9LTzFFS3RScE16eGU3QUQvdzNYbEZUTE1mdlRLQnFzQm12TDVjMXc4Tklr?=
 =?utf-8?B?Vzd2aFBlTytoVGhlZkN0SG81MkVCN3Z5YzZabFVEMUhzUWxIZzRQcmVub0N3?=
 =?utf-8?B?OTRtQzZFbE1VYzBSU2thNjRMbnl6MzhDT1RFbUJqSVhBa1ZyNzJ0cFdJSjho?=
 =?utf-8?B?UEIvRm9Ca3RiMTdFNFpEcjNIMUpjSTdTV09HL1pLTERnTFBpQmxxdDdFVkpZ?=
 =?utf-8?B?ZFFQRlFMTTV1U2J0Q1VWNVRXT3Vzb29vMlFycjMxNDhYcGhDODFVdHYwZ2M1?=
 =?utf-8?B?ejdtQXN3Q1ZCTUN4eE5sS01YQzlSbWkrOGFxRHNSREIwQlFCMHpRUXZiZHhR?=
 =?utf-8?B?Z0VYVHV3SWRxMXhRNFlzY0tHYTFpOTBNZFRTRDBBcWc4OWJVL1VmZDMyT2Fr?=
 =?utf-8?B?RHVkSWxKSW1lbzJscUFBMEE5Z016YjRGV2I4YTRrZldDUVBwd3FuM1FaZUht?=
 =?utf-8?B?aUpZcUR1NHU4UmQwVVF5UzZVYmQvSjRwaTFCTzkyN0VucHQ1V0ZhRXNUUXBF?=
 =?utf-8?B?VDBXSGsrTFRVYTdYQVAzZ2czOXpLNXNWcUMzU0luYkp4ZXNsb1VVT01ZbG0y?=
 =?utf-8?B?STZ6RDQwYXFJWE5oVXhicklBSEVGVG9LenhVd1JYV3E3VmhXeDdSckdZQ3B5?=
 =?utf-8?B?LzNHWkJQT1lHYWlkTEluaGpYU3dDMlRJYXpnQkgzOWtweW56eCszQ3ZzcDFJ?=
 =?utf-8?B?T3lHM2R6S1dPWUVsM2dWZi9EVGZ3UW4ybUNobzFqZE4xc29rVFdUQllpakFT?=
 =?utf-8?B?cUkrb2xaMnhHTTJ5azRzbW5VSjJMR0cvNzFlT2FsS21HelcwcjA1MmxJZEE4?=
 =?utf-8?B?VGtocVNUeG9KOERFYXVnRjV6QlZSaVQvejFsNXpoVEN4VVoyVE9YQkg2dlJV?=
 =?utf-8?B?VUN6SXRNYUI3NHE5R1hQSXZ3VVI2c213bkZHelFBZWRxRjJMSFBxSWtLSkJp?=
 =?utf-8?B?d3lVWnB2ZkNFcHJWczlnM2EreG8rWURDQnV6Z2s0WkZTSXRLQnJRS3NwQVpK?=
 =?utf-8?B?Z25YUy9CcUJELzlLNkhRVGVsMi9uQThqNHlMcFZ6RjhKYVRReWplRXhCeXlu?=
 =?utf-8?B?c0c3SjZ6TzRyeU5IRnNLZ3pXSHZwdDNZRFVjT1gyS3pxdGdFSHU2WFhneWxV?=
 =?utf-8?B?K3BXaU1FYVM2cCtWL0Nwait5V3NhOHBiUGJJY0gwZE8wSVBGQmM0bjh0dVVS?=
 =?utf-8?B?djlXczAzMHh2YS8rV1ptM3BmVURFbWxxQUdKV1dNZFJhOW1PaklYWC9pUVNQ?=
 =?utf-8?B?L2pGOTYvNVdSd3N1UWt6b2k1S1Q5QzRUU1VkZGtITUxURFhGdFlFKzJTdVBE?=
 =?utf-8?B?RVJHRDJTVnNHUUI0VWI5eUlpWGhLb0lNbEQwV2xHN1pEMUNBMUpkQVVnN21T?=
 =?utf-8?B?WThNOU45S2VKQkIrcjAxU0VmNGt3WmVTTjNhQmhldjdTYVk5QkhwTit1MXc4?=
 =?utf-8?B?MHF3cjNlc1ZJekhTQXNXUWkveHAvb3ZIMC9vSVpHcGpQODkwUFkrdUtRM3Mr?=
 =?utf-8?B?a0xQOWQ4Um4wUVZoM2l2TFh5bWVYUS9iNTVRYkFpaE5Xeldwa3lxc3Jzcmpp?=
 =?utf-8?B?UlFrVEpua25vVmR0QUdLbDNBUnhsWkh3WS9LVW9FRzdLcENpQU9EaHVMRVpG?=
 =?utf-8?B?UDhSTEdQekh4NWh4QURTZ1BEaWQxbU44NXZrNGxUU056OEx5TVF0NXo1c0xJ?=
 =?utf-8?B?K1AySGM4c1l5ME1IY2VPTnpYVFROV2xYaE5BdGJDbmF3UENtcHBwQlFGNjhB?=
 =?utf-8?B?cDdDUExTZ2VpMThZYWFKNEowY29GSVR4dG1oazRVZlBKQnpneDYra2lwMGgr?=
 =?utf-8?B?eVpaQXZTODlnRlJUaHczTnNxd1gwK0N1VVpSTmJnZE53TlB4azNVUFU1ZERv?=
 =?utf-8?Q?eW+Q=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: motorola.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SEZPR03MB6786.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 93a026fc-7063-4f6b-da50-08dc330151a6
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 17:19:53.7262
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 5c7d0b28-bdf8-410c-aa93-4df372b16203
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 72jIbILg8ZqP+TZn2CsrTBc3gBzdYzltZg5je2/0ag/Zwdz4+hXoD0wAqB33nEOinpWX1M0nk6VwDjXNVVJRxQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SI6PR03MB9032
X-Proofpoint-GUID: Anrb8UwrX8w3BZK-gnzrdoMgiKxQTAsp
X-Proofpoint-ORIG-GUID: Anrb8UwrX8w3BZK-gnzrdoMgiKxQTAsp
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-21_04,2024-02-21_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 phishscore=0 spamscore=0 clxscore=1015 bulkscore=0
 mlxscore=0 priorityscore=1501 adultscore=0 impostorscore=0 mlxlogscore=924
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210134
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=YRjAyTGp;       arc=pass
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

> On Wednesday, February 21, 2024 12:59 AM, Christophe Leroy wrote:
> 
> In the code you add __weak for that. But you also add the flags to the
> parameters and I can't understand why when reading the above description.

This  change was made to allow most kernel interfaces use vmalloc_node and
enable the overrides to work. It also reduces the number of kernel locations
which would need to be change if there was ever a change to the
vmalloc_node_range interface.

However, there is a pushback to overriding the vmalloc interface, so this change
will likely not show up in my final patch.

Regards,
Maxwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/SEZPR03MB67867ACC0D9AAD3A3AB19EBAB4572%40SEZPR03MB6786.apcprd03.prod.outlook.com.
