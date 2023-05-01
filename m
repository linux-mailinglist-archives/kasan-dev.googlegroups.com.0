Return-Path: <kasan-dev+bncBCYIJU5JTINRB4XAYCRAMGQEFCZGPZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BAAC6F39D2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 23:34:44 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1a6ce2cdb92sf31335765ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 14:34:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1682976883; cv=pass;
        d=google.com; s=arc-20160816;
        b=v2LVtYK+UHvxliIu2ni1F5OI6t7OvbAoSZ8z2YeajL8XpkMN7NZG5BOOF173dJC2Ax
         ms6ePRZ1+co5ZkBKoJIDhPNs2MG+3+OzjN5o+JkFiWCgXK2lIEVV32ZCJ8j9KyvG2kdD
         aA5MyUpIkJePnasVtE7QWMfaQ5KBMlRjx8GpYfjhe2c8vDaYUG55dB0filtZGaWMWIbY
         OhMMD6T7QfLPbGp/rxUF4OMamTX0noBN0XV7zrMfcszecmU/kyIIQAawtoOri9+AdUKI
         dDdGQp//PyA2OkHVoxjFktobqEY03z/uU9l784wPJ+wl2C/2H5/v/8Pb/g6ie8eKrf/E
         A67g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=j/i5lozuuIj/320psZohJcmgoZ+32jhy446pjQhhIKo=;
        b=OnmH1AcskhNGewod8N6HXrqK856DNB41d5tIwH/2IuxXyl2ECJA0bTnbmBRwrQO8qB
         Uaas7kULeyarlxcIzIQN9CWQtQr9XVuo2SCR7hNucYJj9pd9x2r50JY6Qm+P9l/TxhW8
         DmTVdo0dwGkY5f4tpR8MbNgcKDn8NbwxUt6NL7U6R61wFu4vTddV59dEe9Vmtq0lCy9D
         quet5Csv6EKePXV72mo4I773UAn+Wz1eXPv9SYuSg+DEJjm7Vtrq0eae4UlpuyzI3O6Q
         L7OraugRWiRwEOx1AzmUCfZUnHqz6lROjDpi24WMbXrX3SFYTgR4p//LNddTp1vFSvgf
         oWdg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b="ZtSqL/rw";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="O5/4W4m0";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682976883; x=1685568883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j/i5lozuuIj/320psZohJcmgoZ+32jhy446pjQhhIKo=;
        b=iq8glFIdgHDTvsPpNrfzN3ldKI1O1fhxDf5slgjAx6catPva6F6ADsx1e67i6+1Kit
         q5o/gqx3r3hPY17wGnOSgoCBZzpplmKJ7r4PWbs73C6U3uLyt/qUzVp5CQCOz3aAeLaY
         3cc2tT/FExRqchbSp10QVRuGgUxS1doJ5f+H6xfnoVKx+4SGPqOX3HveqYbCSz8jLdie
         4c0RLp/4wWEENOo4/v0OnIgI9qGC1yz6gUfeVy2bcuE2RORA+VvdPbpsWlV2gtpiXTaa
         05roQaKgAZRns7cg5eXED/eaK1LaP5XsKnD48URrmZcXlWxPAX5Yy6O7hHHhFANT1Yzz
         DCMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682976883; x=1685568883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j/i5lozuuIj/320psZohJcmgoZ+32jhy446pjQhhIKo=;
        b=Ah7TOC0tvAm43uLWIzLk51Q63kFmAx/r77FhugL0FUDDIZh96DSvSFbQVrMhJByQh0
         YmcG5OKeRtHKa/E0xKAq83KSG5lTxhOad3cgDwSE0ZMQ9I+Mh+paPc9qlasDc4KvXJcE
         TeOIcxaJNcfBrhHBhn7tEI5cb9soIuSik9KuEmD814Ba7/g5+kuooSjOGB1Bm6+y5ExL
         U+Bu9Fk+SICiefk3v6tOXaMjEJ1icPygqkWJe6vICjomS9zDJ7ukzTS54Q5OBPZUHDXG
         VMX8bX3/Z55wrJS69a9PSk5cJfrg+G2XppmTO2RueXpl7q02bE1l5I8ZaRZ/yLxHJmUX
         297w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwVl0rofkN/x8ehGJ3i1ZNYriv6p5Ymr6++vEGFUvoSg+f1SpkN
	LK3VlkfEp+6spv4wooSEEYE=
X-Google-Smtp-Source: ACHHUZ7E5LvhAAnuaxdz5a9MLL/b0YFNS77lxhVrUuJAzyUlp78wuh71XsjJtOEJWrpjJBfFFWJp7g==
X-Received: by 2002:a17:902:ecca:b0:1a6:9363:163a with SMTP id a10-20020a170902ecca00b001a69363163amr5179223plh.10.1682976882868;
        Mon, 01 May 2023 14:34:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2888:0:b0:509:e5e7:5f57 with SMTP id bs130-20020a632888000000b00509e5e75f57ls2487944pgb.5.-pod-prod-gmail;
 Mon, 01 May 2023 14:34:42 -0700 (PDT)
X-Received: by 2002:a05:6a00:248a:b0:641:3bf8:bed0 with SMTP id c10-20020a056a00248a00b006413bf8bed0mr14790423pfv.4.1682976881939;
        Mon, 01 May 2023 14:34:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682976881; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqiPhu/ExnSqu76UIlw8dAAlHIg+Hr5YgGocV2rXxVixdSn9xGlMn9YUQaHmAg2jnP
         X4IHv+FwqE5qaMAmFwqOPdSuP998DPrtCUUP2EsJmsMEJRXwQllMz0uxC8jZ+Qp/Wr9j
         3671l08jYaivJSaoAS0ejuPvaOKBTNeXscjc7S0f2TFrDTAqAZbWSnUbdkjjh3ThWufA
         rs3R0zgkxxNOfeP9QElMg6BN+oLGJgE4KgMaJFe7fcXFfkyUuq3DsBHfYqpCF1hB5fDM
         Hc3J9/QYtuujHMEbZUGxok4Ic/DWxQo/6Xf4ZC9OPfpojA3ZKTom+vTN0CLJ1piTNc/i
         p3hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:dkim-signature:dkim-signature;
        bh=oIqIKkV+mXN+M+KlVC9soascZOdeXUNT3GbUh7j2yUQ=;
        b=WnpZo4FbaSsijee5iSmqtmaUuJJfaAzPZ4+tg96Pl5TIxhlmCf5C2A1cxDZTcKvZyK
         1JqT/3+ffshfE86b4W8LmQfEZRlRUI6KYG33H7i1Cz0rbZepvAHKE0QvZg9K3s9FcY4B
         F4qkFwGIbbY8q3QlTj6eEzomHBAJfOQ74j35Zpb1gPidMyrt77NgKb12vEFy6UOoyIFJ
         nIo4DFgZkBG27/nVFmQtoQfVfMWY3GNdUL4lL0ZXRWk5sJoMq5+3JOA4eg71czH5aNMM
         Uc9XTkxhOT76WnXY5flc6iExe55bngQLfmyj0YtW+N0n84UyNo2i2X7YTKf2YpZqOmWg
         8duA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b="ZtSqL/rw";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="O5/4W4m0";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id fa36-20020a056a002d2400b0063b7b261fa0si1648154pfb.0.2023.05.01.14.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 May 2023 14:34:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 341LOcBT007311;
	Mon, 1 May 2023 21:34:03 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3q8t5fkase-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 01 May 2023 21:34:03 +0000
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 341KvSnE002397;
	Mon, 1 May 2023 21:34:01 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10lp2103.outbound.protection.outlook.com [104.47.70.103])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3q8spb5yu1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 01 May 2023 21:34:01 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ieS3/qLEp45A5eZ4zZ4DEJitNcRZLUywWzL00wmZ3VmTRSwaXXMRpyk2IJnFBH8mQZXaf0+afmqIlDZ4q5j7gWOslGQ69zEiXoidl0a5AdyYYalQIcJItX0YORaevCS/d/kZWMFURJ15TPIQ3W77gy0AFcqAfIpH48LuXIc3VqRxnxEw1PSeJGn7Xwt2ZpyceurqbhqAORFlhkYexOLHt7NfitqB07hs7QF/mFm4P/cnhzYMmbZWnAwKGNhdL6b2uKDlOOS6bpsfZl2nEnG+MgpZJQ3+qWCnBQD//FjzJh3uK35UDVuaSypFrW2myPkR163+nRERXXJs4GUNLWqFbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=oIqIKkV+mXN+M+KlVC9soascZOdeXUNT3GbUh7j2yUQ=;
 b=UF2+Ps/Lx3pgdWcshWpqAIISXQ7DbDfVSKLJkttU9+0vBiteMCwFgDgdBaBqzliGLYLEYvw/YqEiqmLiHsbkTKwWVQo6w3fRDquGVaVczjyR4jYhkJE8Nj4FfWWR9d/hR1GGxDrmvwrhVTbfiYcc90bOL0bnWlJNOVnrtVKEY9y+VXfWhYcaDVZQCyuMenud6VBYBe6dQfYvXMbbkPzCUt3B8Cd8QApir1IaXJFbxN/cyHLWp1p+YQ7MTuABJ7g0qFKvj3zCIPhMCF4aLR42Wp2oSuWlfT1qw3e9Jc4iHAjL+97YGQ5u90lH10Z9Lu0jxYSgYi32Jt95E4uMfQLFjQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from SN6PR10MB3022.namprd10.prod.outlook.com (2603:10b6:805:d8::25)
 by CH2PR10MB4294.namprd10.prod.outlook.com (2603:10b6:610:a7::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6340.30; Mon, 1 May
 2023 21:33:58 +0000
Received: from SN6PR10MB3022.namprd10.prod.outlook.com
 ([fe80::8bb9:2bb7:3930:b5da]) by SN6PR10MB3022.namprd10.prod.outlook.com
 ([fe80::8bb9:2bb7:3930:b5da%7]) with mapi id 15.20.6340.030; Mon, 1 May 2023
 21:33:58 +0000
Date: Mon, 1 May 2023 17:33:49 -0400
From: "Liam R. Howlett" <Liam.Howlett@Oracle.com>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
        Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
        mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
        roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
        corbet@lwn.net, void@manifault.com, peterz@infradead.org,
        juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
        will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
        dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
        david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
        masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
        tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
        paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
        yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
        andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
        gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
        vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
        rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
        vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
        iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
        elver@google.com, dvyukov@google.com, shakeelb@google.com,
        songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
        minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
        linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        iommu@lists.linux.dev, linux-arch@vger.kernel.org,
        linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
        linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
        cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Benjamin Herrenschmidt <benh@kernel.crashing.org>,
        Paul Mackerras <paulus@samba.org>,
        "Michael S. Tsirkin" <mst@redhat.com>,
        Jason Wang <jasowang@redhat.com>,
        Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <20230501213349.bvbf6i72eepcd56m@revolver>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@Oracle.com>,
	Andy Shevchenko <andy.shevchenko@gmail.com>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75VeJ_a6j3uweLN5-woSQUtN5u36c2gkoiXhnJa1HXJdoyQ@mail.gmail.com>
User-Agent: NeoMutt/20220429
X-ClientProxiedBy: YT4PR01CA0067.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:111::22) To SN6PR10MB3022.namprd10.prod.outlook.com
 (2603:10b6:805:d8::25)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SN6PR10MB3022:EE_|CH2PR10MB4294:EE_
X-MS-Office365-Filtering-Correlation-Id: 09397e23-aff0-4b3f-96a9-08db4a8bc57a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 94ahiiDAzmUW4VzF0dHmA5kCHDmvhp791Gc8U/ISV/33d8DfVoyHQuONpy9HjUqyNHaNztp3ewHY4vzI0cSxKijqm2l+iIt7nwh+xi/J6lKiCWrcc3ZEzXbB3fNs0TIuAg50Far0b8FGRiAb7px54BkySfwUcaP8kFqoW6T1X54mlM8S5hyVicOafoHP10w1leals3HbTF30sX1UUMYFpA1fyyGmn8yCq3d75n+JVnBMTd6bwXQMnobYmNVNxJ54Ya9O2MGOSaBejEgNLh5NDs8AEV00CVZI+Jukv1p90vTMyMzbfu/ZmxfynzF/zX1aiGnbEEQywXekE0J4I0Sf7gynIYsLcJMIq6Iy2R2pyN5UgKgDl6b85l6nyi2br411vdTBdgZbUCsfBAlB35jdmsRrOtUzU/ClpSRi+tBQhV9KGIWsMZYMW+2mvH5Mpa8tZU1FAyXbBu8NeoY6TzHIWUnPgXmlYB1hFD7nCpOvPDh7X+7+Pzqnp7vSz8arc4SeFfMzibyZ0hkGxYQ8TFjk/+VxA51WUUXy6NVyzSkapWo=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SN6PR10MB3022.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(7916004)(346002)(396003)(39860400002)(376002)(136003)(366004)(451199021)(86362001)(6666004)(6486002)(966005)(53546011)(1076003)(26005)(6512007)(6506007)(9686003)(186003)(33716001)(38100700002)(5660300002)(7416002)(7336002)(7366002)(8936002)(8676002)(2906002)(478600001)(7406005)(66556008)(66946007)(66476007)(41300700001)(316002)(6916009)(4326008)(54906003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?RkNTdVRvTHNVbHpEdTB1SU10dTh5Und5SkRoamNvTVdzbEdNamw3d3NiVFgy?=
 =?utf-8?B?dmFiZDlRTkVCQ3JyT2pjemdrTlBvOHpOWnE3QjdXUmxPWVJXVjYrdlYrYXJn?=
 =?utf-8?B?Z3FJOTFUWUFkZFhxcEtxc044cnNLVkZFN1N1Ny9mZDdtb21ZU1VXQUkvT21M?=
 =?utf-8?B?aXQ2Z1FMNUlUMGoxUVBMTFdnczJrTU03VHROZVZxMlRiUWpZWmlzL0x0R0lH?=
 =?utf-8?B?VVJHNXdjODVVRktUL01RdlhaUHJrTHViSGxNaVRmTE1ISjJ5Yy9lMXZqUjRE?=
 =?utf-8?B?cTV6Y1I0Z2lFU3FTb0R1UnJod2M4QkowdFMrKzVvcTRkNEJPQVdKeW52eGRB?=
 =?utf-8?B?Rk5PenlBWCswZTEzNkpNcEE0bEJjM2R4NzhTanJwUWdDS1E2UWZGWlprSU9T?=
 =?utf-8?B?cnhYd0VsU0NHM2duSTN1RG9EV1ZjN24yMTJYL0V0eVE2VXlXb1BXckhyZEt1?=
 =?utf-8?B?K2Y5ejQ1T25JL0UxcnhqWW94Qk9HYkVUTDZjSVQ4WWRRVTZ3aGFRZUlaNkxG?=
 =?utf-8?B?d0R4V1JXNjkyVmtVaDBjVE0vazgrQ1k4QlFxOVFid0pHN1JIUjZIQ2JYYnVZ?=
 =?utf-8?B?SVh2UHBsZHZQcTdoR2RRRjdTaTgzQUo1bEdFNmtldWxha0UwQ0JVV1A0L2NO?=
 =?utf-8?B?VlNyNVpsMGlrSnZXRTVKTWpzaWcvUHQ2cHk3eFgvcHp0dERyQnlWem00RDg2?=
 =?utf-8?B?eEVpcUNreEltd2R4WU1Gc0FDbjgvL1pyNjVubTB6OURkY2tvWFhFQUpwQ0Uz?=
 =?utf-8?B?OUlqcmlwQStmOUVOV1gwOWN6T0dBMkw0bnRyRkdZLysreXhkc0tYdWc1cmR4?=
 =?utf-8?B?QWtFVFpFYUs5cVI4NllnWFJ1djlPWWxXWE1NbkNnbGpUTThMNzg4Ry82MWlw?=
 =?utf-8?B?V0k0WDJGdnhldFBIa3FQbGJqQjYvb2ZpMzh5bWdnQnNXWnRGdUh2WHY4Ri9C?=
 =?utf-8?B?Wk9TZnEvRjJnbSszTy81VFM2VUd1QURLSXFrQlFOSDBkbVI3bTRpbmVzUk9S?=
 =?utf-8?B?VzI0SkxQOXZSTHozS0VMdnBORU1pK1pwTldVTzE0Unk5QjI3MU1ubGJIbWdq?=
 =?utf-8?B?MmZxNUlyKzcrdjNwbnNkTjJoY3pVUDFWeEtHbU44Y1pucGVaWnVmeDVPRmRS?=
 =?utf-8?B?RXhSb0RCT3FHM2VSVktVU2pKSGtoUDBCNzBQaTlTZktoWU1YUGRBcGM4WmRL?=
 =?utf-8?B?N2NoMDB3UU51YnA3R3FoWUhyL3RrVzJUYnp3Z3Iyd1duNW5uWXhGaG4yMDZx?=
 =?utf-8?B?bmRObkVYc0tUU1VxeXp1aitCT1hCN0R2cFR5SXZpRjI2WllGZVF1Yzd2NnZz?=
 =?utf-8?B?NHRIRmZFaE1JMUlleDJPSnRiNXZ3TkZ6RlQzTkZxK1lZcm9xTHphTk5sY1pY?=
 =?utf-8?B?MFk5NFkva1pMNFVUWk90TVQ0MzVQOFdCN25qM3BhRWFzdGc3cVhuVXovZksz?=
 =?utf-8?B?clZ3cnlPOEhQM2hxV3JSR3B5WDNxR0NnRGR4Y2pENTVDQWt6WE5jcEVkbk1V?=
 =?utf-8?B?UXBaOE1FeVNCdlFyc0g5UEgwY1lkT0pJcXdNWi9PVVd3OHVJNEY4QVFqQ2lK?=
 =?utf-8?B?UVViMGV0TlRhOGVIYktnbkVXSkZZcldnalZPcVhzSU13VnZOdlJ1eHJPdGpv?=
 =?utf-8?B?WWloZzVRMGp5ZkNiSmkvWFd1UEs0aVZIS1h6L1gxY08wQTU5MERvb1djMTRt?=
 =?utf-8?B?bFY0cmRKc2NHRkxpaXhVNEdOR1Q2OEhlUnRGUlBYSDlLQTRrYk5BaGxuc1pr?=
 =?utf-8?B?S2tzL1dEajUyYVQxSUFWc25DVGxBb1JjWmMwQ0pkRU82TVBjREltNUE2T01M?=
 =?utf-8?B?MGhjSVZySS9CVEp2QlgxTWgzaDh2eTlqTGtxOFVydUpDNXJ6cXBSU3JFQ25r?=
 =?utf-8?B?MGY5a2lFbVVyUWY5N2RTQ0oyQ2RQNWZxMGIvOGljNkVZaHpYcEI1bE5mZ0lF?=
 =?utf-8?B?YnQzQUdBZUpaZGlzZFpULzI5WmJneU5HcXBPK3lYSmJoakVKVXI0QWlPRDFR?=
 =?utf-8?B?elJndm9pdE85SEpOSnplRzJyS1Z2MEJwU2t4VTJZQnNRaVVMWndsa3RHdWM4?=
 =?utf-8?B?b3J4U3lqNzhwMWx2MCtocEFyZThOcEU3WWRqZ0Z4NXhjcTFWdVlib25TZVpG?=
 =?utf-8?Q?deQ84EOGxod3sYWkP38+OXS88?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 2
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?utf-8?B?SGNrUnZwZ3g4RUpJdm84dVpDTmVHRTBkdzlNc3Vkb3pTZ1VNNlI1ZUdvbWUr?=
 =?utf-8?B?aTNFUTJ3WnhmN0tqUktQN05JZWRsbnJVaGJWaDBSNlkyMkllN1l0UzRnYXpn?=
 =?utf-8?B?WXVKWUJPRGdpNFJNMElwMnJFMzluOG9pSU0zNEhoNTFvNW1GdkI3Q1M3c1Vj?=
 =?utf-8?B?ZFVFV1N4d3ZVUnNZU1pjb3RLMzhvMXJTUnpzeUdNYzk5ZmdEdTFOZU9rMzRj?=
 =?utf-8?B?LzlsVXJ6NlBGN3g1UEp6MGRzVFE5VGVpNVBJZ1JWSlBYckg3dnNIaE9Fb1d6?=
 =?utf-8?B?ZXhMNU02bDFLcGI1MmRXUGdibDlQUkxJaE0vVHBBcEhSN0JJbU40akYydFl5?=
 =?utf-8?B?dGl0M2Irb1BGTGhxVm9aVDY5Y2JFRmJYbXNUdVluenZzckRtRVBGOEo4bzhz?=
 =?utf-8?B?emEzaFE5T1FCVk1vQ0JNTmNLK2VrV0E2R1o4b24yQUV0dmxGR2M1eVl2ZTlD?=
 =?utf-8?B?RVA1MlZzQmJpRVRoWDFYaXdGWjRrR0Jpc3FxUDBUcFNIZFFCRnNEbHFSNmxF?=
 =?utf-8?B?MW1yL1NuQTNOeHB6ZEtFMWtIckVpamxlRU5BMGthUk16cjFSWk93aERvOHNJ?=
 =?utf-8?B?WkhXSmJSdlZBQVpRNVhialNHcWVqNThYU0xQSmk2SWJqMWEvSWd4bW8xU21S?=
 =?utf-8?B?RlZEL0ZnWmdCZE1yV0lGckdXSytsRkxaYWg1Y25Benh0d2x2YVlSUGRtampR?=
 =?utf-8?B?cDJ5bmpPN2NPUE1KZHc3c2FGNXVvWVN3aTc5SHA1cGhYYXFuWi9mdGQ0ODZq?=
 =?utf-8?B?emdjcngrSis2WVgxMm14M043WjM2M1l5d2VGaVJPTlBGUVVjcmQwR2xsVlVN?=
 =?utf-8?B?bFZGQkI5bFljYTNJWDBLclFSQUQ3RkFIVUNqclZyWW00SzI1VjlNRE1VbmtI?=
 =?utf-8?B?ampBUVRYaGJtVjh3dHByT1pZN1hHMTZOWDhSUzdoM0xGanI2SktrSmg1cFRN?=
 =?utf-8?B?dUpEaENvS0puTmppdWcxMFBUOU82dk8xT1JrbWc3ODhEY0drczNyTHA5OGJV?=
 =?utf-8?B?RThTazd6Z0YrSVJrWWg5S1U0QlRMTjBlckF6MGVWMUNKOWRMYTN1TWpJM1pO?=
 =?utf-8?B?dUs5NmNuVzJabnBac1ZteTFBcU5uTTBFUyt0bCtiSml1MzJ1MjYxaFlhb3ls?=
 =?utf-8?B?ODd3eU5peVZkbnU0ZWgyQXg1YXRqQlNJWlJEWnBmU0wxMGlLTjRZeWVDYUNL?=
 =?utf-8?B?ZFhqdHRzYU53UjFCQW55QlJNRnlDd2xxT0xTQ0NJMzBVTzBTUXJCekJPWnZN?=
 =?utf-8?B?NWYreE5VeHpBcFNRbmY0d3psaXpxMzdnQmwwR1NJMFFiYXlJWXRhUGY3cUQ3?=
 =?utf-8?B?V3owN1IwcHJsME9IMnJvVG8yOU15QnpwR3Y3VXgrWTNRM0I3d1EzWElXMXVa?=
 =?utf-8?B?RUJ3QjRON0FvejBOalNVb09ZK3MxSjd4aUoxM01Zbm5nOTVBa2k3S3Z4Wmhv?=
 =?utf-8?B?cnJ4Sks2ZmpFN2xyS3BJSjlpcmxubi9hY0k0bzlOUUNJNFhrOHRpVTB5eWcv?=
 =?utf-8?B?ZmIrU0Yzd29ZdnhSeWxsMFByUFBXWHcwR29KbG4zNHZWOTcrajRTbTBVa0ZL?=
 =?utf-8?B?bE4rSVZqUXJBYWpTNGtPTjYzSVpGcEsvZitBQklTN2RBbjVNTi9ndGVUcG1i?=
 =?utf-8?B?S05HN3NDM29Zc3h6VHF6QjZDSERpS1VOaTNOUmtaUElneHptdlU0VGhZbWZV?=
 =?utf-8?B?ZDhhUmluWUdMVDJnRVdLQ0srUWVabVJPZFFPZU5TRk1mSUp5eU1WbmFBMkFY?=
 =?utf-8?B?aExkV2ZLcWY4clpQVUUrc2hVTTJNZ1ZLYXkya294ODV4emFQZTkxS3E5cEEr?=
 =?utf-8?B?VGJFcXRVYnNGQTZoNVhyTUlITEJoSDhBbGV1T00rTU80MStkUGFYdUJjZk9N?=
 =?utf-8?B?V25pWXVDVlNBVFVGQWVNZGZWVDNMdnVLWDVrK0R5S2dDYm05Z2hDby85VVU1?=
 =?utf-8?B?MjB1SjRzV3NEcVk5RUJNbUVzd1pZM2tlWUdHTkowS3ZZSWVRZGJvTXJzaW5i?=
 =?utf-8?B?bDBiS0tsbHMycXp5US9VV2JFZnVRelBCaCtDNU5yWkh0cjZPbE1NY3JhK1BC?=
 =?utf-8?B?bFpkdEd6SEhveUZ5YzJzVUdoNmtuNzY3ZHdkT3ZuQjJkNDgyWlN4clptKzB0?=
 =?utf-8?B?UGs3NzFVcE53MzhXRWVSanNIZU9JMStkd1JaQ0hJMmtKL3RFU2RUaHJFYjl2?=
 =?utf-8?B?SlBtT2E0aE1jYWh6R3JOd0hDL1F0MGtVRG8zd2FuaFRuQWRuYk5WNUFlcDEv?=
 =?utf-8?B?VWI3b2hqNFlrUkJlTHVTQnZTRTBnSWV4T0xsZWcwN280ZVBQM2YybXpLRGNh?=
 =?utf-8?B?RzJVU0p1Z3hmaTZ1M1RvKzNGYUpJOUZFYUErNHB4SlVSYXlRTFNsNlpyLzE3?=
 =?utf-8?Q?knNwpkah2BnktmjyeVFq6jhKzHAFFGqU6o4rT96P8uxeT?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-1: bMa7cwkunDYtYEZBLGPyYKSHuFQspFWVTiWduGLJoCVkHnyPQbAuh1NxtDZAS2rnUnbyDS8goOwF/F8pX/eMTKh3Oq+Olw8aGWXsdntY2ofpxqJtKci8aI8h3NfTgIAobbZz4mehpRAHQLQeAWyLW00OxzXShDVRriQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 09397e23-aff0-4b3f-96a9-08db4a8bc57a
X-MS-Exchange-CrossTenant-AuthSource: SN6PR10MB3022.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 May 2023 21:33:58.1011
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UMXLqazwLyhrVjCOmh/YJCkG2AEmNdpgakpN9kM0d0sgdNVhGOgoH4B9FAvAjTGOPfUMc8XpRDUA/EOr1CZr9w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR10MB4294
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-05-01_13,2023-04-27_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 bulkscore=0 spamscore=0
 mlxlogscore=999 mlxscore=0 adultscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2303200000
 definitions=main-2305010173
X-Proofpoint-GUID: dBg5ZStizV16Btz8PAwRs1Y5vGXrl_Tc
X-Proofpoint-ORIG-GUID: dBg5ZStizV16Btz8PAwRs1Y5vGXrl_Tc
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-03-30 header.b="ZtSqL/rw";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="O5/4W4m0";       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

* Andy Shevchenko <andy.shevchenko@gmail.com> [230501 15:57]:
> On Mon, May 1, 2023 at 10:36=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Mon, May 01, 2023 at 11:13:15AM -0700, Davidlohr Bueso wrote:
> > > On Mon, 01 May 2023, Suren Baghdasaryan wrote:
> > >
> > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > >
> > > > Previously, string_get_size() outputted a space between the number =
and
> > > > the units, i.e.
> > > >  9.88 MiB
> > > >
> > > > This changes it to
> > > >  9.88MiB
> > > >
> > > > which allows it to be parsed correctly by the 'sort -h' command.
>=20
> But why do we need that? What's the use case?
>=20
> > > Wouldn't this break users that already parse it the current way?
> >
> > It's not impossible - but it's not used in very many places and we
> > wouldn't be printing in human-readable units if it was meant to be
> > parsed - it's mainly used for debug output currently.
> >
> > If someone raises a specific objection we'll do something different,
> > otherwise I think standardizing on what userspace tooling already parse=
s
> > is a good idea.
>=20
> Yes, I NAK this on the basis of
> https://english.stackexchange.com/a/2911/153144

This fixes the output to be better aligned with:
the output of ls -sh
the input expected by find -size

Are there counter-examples of commands that follow the SI Brochure?

Thanks,
Liam

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230501213349.bvbf6i72eepcd56m%40revolver.
