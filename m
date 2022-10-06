Return-Path: <kasan-dev+bncBCY3HBU5WEJBB4HP7OMQMGQEQ2DGYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F9695F6AEC
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 17:44:49 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-3521c1a01b5sf20669867b3.23
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 08:44:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665071088; cv=pass;
        d=google.com; s=arc-20160816;
        b=PfEQ0x8/uKGrEGxJLxuCLV2G+oubTYgYHOPakGH/jze3RLg5rKvGQi/I0XinERCRkP
         2SWYCJDXPJcsyLPIcmMY013EP9uQXhHrZpkypR4uRwhosgO30Tn43ZYxxMIw2PFS0iMk
         WvSxGeAKp50wZP75OBc7Lt/t9SSu3OGEufvkLbw4Xq7MfxORpSHPuEL925nwhPvyRSlu
         BB8SDPB/ae9WJWGsApm8OUi7gD6PO7RWUNokhg+FyIW1VrrGNNQzLz1a/LBn6vRmkCH4
         G9XSibXqHtfnREvsfNu1/iy6wfeXRMrscJXSY48SCwSjw2qZjPw0QHAVw43oM0d2FmKZ
         DvqA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=7fNygVxQs79cDdbaYUDIQNms5aCHUv2Xqb4TUtLbOyM=;
        b=Bn41akh2N12YcX05NvG9UxO2Jq13dip+WQFxek7l9irU7n2Q34HY7hW0vhqqf4GEwm
         bavkGTGhyV5eIH4jlqf57feQVmZcMbe0vPALoD+V8zd/ITN4+5nX740GxK12lYlDTmN4
         De8BQKMH7higlgbG6EpkWUqaG7CZVNCdEsiv51rVfBTF8Rl0J3ztDMsWqHKcCdNlIsVs
         0vg1k72iooC5yDb8ktWv0Ec8TfYrtoznQonN9b30HmQfUA3YwOE1LTmoADLfQds4zihD
         ziH0dRHnA21Y47v/h4yEPT/4Qa0wP84P0PI+abTShi+Us049/o95an9CAdW3VPKMdY0R
         yhdQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=tJZ7pulU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SAQtX80y;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7fNygVxQs79cDdbaYUDIQNms5aCHUv2Xqb4TUtLbOyM=;
        b=KB6EuyI42wwdVudJD4t5GylEY+5KLR+NlBCO/SeOvI1uAQdtjkGIFGrUu8/ZEvypVH
         vxN3LTXMzUfVG7V7t2+4YP8tJ8mu4Rhk/f9M8pLdd4qntgFO9bYveGFySstGf43dl1vB
         Bx0MkPkAX0yOPMOSqhuOmBi8vR+j6L9lvBclt4e7HWzIZ+HgK8i7PfOiu5ppdMCOKrZr
         ioU3wW0JU3uXsB4+dPHntPrhbgLTT5b3n50wk1WJbffNTYUmQc0yecQ4EWDnJlmg9HAR
         vNQl7Y5srrDa2Y+dh/DAMiFgBWgQSpPaDTFDI3BFOmf7ZdjsQ5wJ3MfrDHVBLurOzbpE
         Vl5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7fNygVxQs79cDdbaYUDIQNms5aCHUv2Xqb4TUtLbOyM=;
        b=YhSsj86f2hGJcSzJXoBtLjnRaVia1TiZ0RDFyxAN3exTFx2DF5b0KwZfY3SNJtLI6Q
         IxMmzbD4EQ5C/71KBdAMxgC50c89sKeZ6/qcWqqamYmEozuJ5i2/l4hpHahK+g36tXFr
         s6KDJrxyOs32tQxhIhNC/potZmcuWpL5zG5cL5d6Sr5xSz/11Ge1jKYY7MHVS8DmUzs+
         iE5UW6afmtQ1nJzCW3Y5PkmfIMWCBbDglrUUrOJeabwQjuh8B2H3Xd2znVt2iMQMCqgl
         RWrPHNwmpOEsPD2BtvlwyedMj1Abnc4/k1ZqdYMFJc0YDyi8t9+HRBqoCBYVYVhQKXpj
         pnPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2+oQTkmUdQZrQfBpYhFnupoTBVO8GoWRofQPj8xm01wZ51RhAy
	yf+eTLykfKtBtogdo5p7+5o=
X-Google-Smtp-Source: AMsMyM5m4WeeRQ0iUT25plZUKbupO2KVazYrJg4HxBmO9IAa7oFTT4BlkrbwLPKAroBiOlkYhYU/ng==
X-Received: by 2002:a25:7b06:0:b0:6a9:5f43:bd62 with SMTP id w6-20020a257b06000000b006a95f43bd62mr311109ybc.357.1665071088126;
        Thu, 06 Oct 2022 08:44:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6851:0:b0:6bd:2495:653f with SMTP id d78-20020a256851000000b006bd2495653fls1237517ybc.5.-pod-prod-gmail;
 Thu, 06 Oct 2022 08:44:47 -0700 (PDT)
X-Received: by 2002:a25:cfd2:0:b0:6bc:b591:6b2a with SMTP id f201-20020a25cfd2000000b006bcb5916b2amr292860ybg.463.1665071087582;
        Thu, 06 Oct 2022 08:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665071087; cv=pass;
        d=google.com; s=arc-20160816;
        b=qnX+ylUDb+NtMrk6pZRMxdMyy5JWAcipRVgyGQ3BzW+E8tcNU02AkNqsdJyDh/20f9
         0IBlTWQxjErOkYRliiFM2l86i3jRrcvK4+JoJEp2qSND98YMoxMJxjvyU7BbIcBtsTVw
         5SSzPyFi/Bj/6IL6nl33Qq6v48a1au0GApgo8yTkSvneiNizjXuisrPOjsrTp5A4IkZg
         vFjA//5IAftvMVQXvATLiiu1YNXGAoFBPQYGfiqim/MJuNK3zb3Nj49ITzH6JVVD3M95
         1CprVMM6eTBNf4tmeUW4ZHwG2iPxbrSe+3cia1VRtdMyMPW8CmEFkU2F6JQoxBvr4gIL
         6MhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=T4aQH8jmIdGMUMGA3JS51KNvM/ee2gXMTejsiZsls/Q=;
        b=mpkHFD0v6J+0wsRP6XOityEQDalj76x32Dvl7sDogZZFyriepwyW4KyJbsXOuLb0QH
         CRT1OjAA9k5WwB5zC69E205qwr4evU8autiuOkvIC1jymunaGqwapZpvZUuxFFULDJu+
         /wVU4xfBZESUGdUQeRrcq1WpcsRjky/VRlV1xXt8CdMT5TWTmtqUWIGv0DT1Th7XCW89
         RM9PmYxZs5hTDfex2+rJfomgO0CH7x+F8Wb2eN62KaMUHzn+o7XMeTvHYmrlwwdFG7L/
         DmW6/kM0rAGSG0FDTTSz6BrxuSgGBg815w3lgDO9iOAwrkvLlumx0zNbRo9gMoQ1vnJS
         8q/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=tJZ7pulU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SAQtX80y;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 68-20020a250747000000b0069015ac7716si1211459ybh.0.2022.10.06.08.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 08:44:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 296Fhv1f011296;
	Thu, 6 Oct 2022 15:44:12 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3jxe3tvx04-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 06 Oct 2022 15:44:11 +0000
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 296FAapT020924;
	Thu, 6 Oct 2022 15:44:09 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10lp2101.outbound.protection.outlook.com [104.47.70.101])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3jxc068sws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 06 Oct 2022 15:44:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=WX1LrQjaXRtUINc6WjUzss8PTNEl6exShEoXqHqg4oOD7vCqtxbQ4ne9A0VwKPcz4ZhbQhjFqv9KZup0FBLBrNpEcx0d4gbWnPQOj15Bhc96j+aXGRCh0VOlPhQ4IPkBpk3qfyN41+VXh+H00O+p4wc+8mw/aCcakg7pSRo7Cn1ESWiW5YCu/png8YYIfXXEb8WEyex1NKh3MDWidtTrz+f+Ep6klbvffIBuZi6WOB8OIIPpmLk7DiLvhyP2/6+qY0tzgbjJDt9RsZ3WS7G+fe4VrfeOSw2VtKg8GTB6+ZcqOl5fLVR5vr22g9Qc12rxp2tmOTTOgBD/gaJgttwWrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=T4aQH8jmIdGMUMGA3JS51KNvM/ee2gXMTejsiZsls/Q=;
 b=Ud5wX4bY7PB6emxHbcrNfKqt6Z1C7fhmOlQgZu8DsVrQy2Ihv7q80+kkG2Hd/32v0/F/iNseNCv1XlFnlJULOENhHksKZzce5g5tXiSB57RIaDpG9K6OdWb8QkQ+1YOvT2KnotEG8l/kfk3kOGEsq3w74P4fQYAuS/kE+y8qdl5HThAgXNwkH7yN7MEBKikPtjFzFRR6+f1T8YTZ0DDyHmrudUG9Ljz7UNVZ1Pit438i/XURZ4n4/Va5U8rp2JwDxcGyaZNqjFUaPIyeTRcccpVLgtM/mhpgl9E/mphJNviYLXIHGfY3PYo44RumMDKwa/G29yqri80TcMP7RdicIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BN0PR10MB5128.namprd10.prod.outlook.com (2603:10b6:408:117::24)
 by CY5PR10MB6011.namprd10.prod.outlook.com (2603:10b6:930:28::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.23; Thu, 6 Oct
 2022 15:44:06 +0000
Received: from BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::5403:3164:f6c3:d48a]) by BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::5403:3164:f6c3:d48a%3]) with mapi id 15.20.5676.031; Thu, 6 Oct 2022
 15:44:06 +0000
From: Chuck Lever III <chuck.lever@oracle.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
CC: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        "patches@lists.linux.dev" <patches@lists.linux.dev>,
        Andreas Noever
	<andreas.noever@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andy
 Shevchenko <andriy.shevchenko@linux.intel.com>,
        Borislav Petkov
	<bp@alien8.de>,
        =?iso-8859-1?Q?Christoph_B=F6hmwalder?=
	<christoph.boehmwalder@linbit.com>,
        Christoph Hellwig <hch@lst.de>,
        Daniel
 Borkmann <daniel@iogearbox.net>,
        Dave Airlie <airlied@redhat.com>,
        Dave
 Hansen <dave.hansen@linux.intel.com>,
        "David S . Miller"
	<davem@davemloft.net>,
        Eric Dumazet <edumazet@google.com>, Florian Westphal
	<fw@strlen.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        "H. Peter
 Anvin" <hpa@zytor.com>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Hugh
 Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
        "James E . J .
 Bottomley" <jejb@linux.ibm.com>,
        Jan Kara <jack@suse.com>, Jason Gunthorpe
	<jgg@ziepe.ca>,
        Jens Axboe <axboe@kernel.dk>,
        Johannes Berg
	<johannes@sipsolutions.net>,
        Jonathan Corbet <corbet@lwn.net>,
        Jozsef
 Kadlecsik <kadlec@netfilter.org>,
        KP Singh <kpsingh@kernel.org>, Kees Cook
	<keescook@chromium.org>,
        Marco Elver <elver@google.com>,
        Mauro Carvalho
 Chehab <mchehab@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>,
        Pablo
 Neira Ayuso <pablo@netfilter.org>,
        Paolo Abeni <pabeni@redhat.com>, Theodore
 Ts'o <tytso@mit.edu>,
        Thomas Gleixner <tglx@linutronix.de>, Thomas Graf
	<tgraf@suug.ch>,
        Ulf Hansson <ulf.hansson@linaro.org>,
        Vignesh Raghavendra
	<vigneshr@ti.com>,
        Yury Norov <yury.norov@gmail.com>,
        dri-devel
	<dri-devel@lists.freedesktop.org>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
        "kernel-janitors@vger.kernel.org"
	<kernel-janitors@vger.kernel.org>,
        "linux-block@vger.kernel.org"
	<linux-block@vger.kernel.org>,
        "linux-crypto@vger.kernel.org"
	<linux-crypto@vger.kernel.org>,
        "linux-doc@vger.kernel.org"
	<linux-doc@vger.kernel.org>,
        linux-fsdevel <linux-fsdevel@vger.kernel.org>,
        "linux-media@vger.kernel.org" <linux-media@vger.kernel.org>,
        Linux Memory
 Management List <linux-mm@kvack.org>,
        "linux-mmc@vger.kernel.org"
	<linux-mmc@vger.kernel.org>,
        "linux-mtd@lists.infradead.org"
	<linux-mtd@lists.infradead.org>,
        "linux-nvme@lists.infradead.org"
	<linux-nvme@lists.infradead.org>,
        linux-rdma <linux-rdma@vger.kernel.org>,
        "linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
        "linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
        netdev
	<netdev@vger.kernel.org>
Subject: Re: [PATCH v2 3/5] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v2 3/5] treewide: use get_random_u32() when possible
Thread-Index: AQHY2Yd8Db0GqFZoz0aeW8dLRbUzW64Bgd6A
Date: Thu, 6 Oct 2022 15:44:06 +0000
Message-ID: <E057FAB4-C522-4CE7-ADFE-BDEC7C207A0C@oracle.com>
References: <20221006132510.23374-1-Jason@zx2c4.com>
 <20221006132510.23374-4-Jason@zx2c4.com>
In-Reply-To: <20221006132510.23374-4-Jason@zx2c4.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Apple Mail (2.3696.120.41.1.1)
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: BN0PR10MB5128:EE_|CY5PR10MB6011:EE_
x-ms-office365-filtering-correlation-id: 1cde40ea-87f9-48fe-68ce-08daa7b19a45
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 0j6PvztKaQy+244EOq6vGpbddCol4ZOZ4NH2/CccJ1utlXNwGqzKL3XKs6GupRO1hFjuu39nQRL0I2IPPyVXahFDn+dLErEr04H47baz29sidsIAPBD5096MQTMtCFeYKrSAS3T6cbURTM1qWKV4MGWWwHRIV2RhECTbHbWcxoYcFrKmT4fK4jupzteDwhkzaT3dxhKw/O/YlTuparCdB+avBVTIfQ4Vg/mzTK6guezE5fphKYr2UTXyl16+88Se0VsAjW90ouWUB8avkNy4ohXAeGAu9O6IO2EuV+IXOct8AMwAPVsVzoDdc2vtTEWsQPPk8rK9/SGyYs5NNdu8FQb1Hyb6WVAxRRs7rpZ2ajEZOcPIZav24rvrci3urmetdDI2Qn/V599PcvHfP5sJaZmoWNvV2/0QWPdYoXmnyUnrK2zzUzxyGa7q1lWfdsTtGq+rae+1bGffXlduK3UIdlG+9vHYaBIfZs/YJTEDd6PbEb8+v7rcX4to/105kdp41V/yevECQroEXTeK6sIyVOyVol72AK1CXY+Z1xiabGC0giORBlDMxAvKJK6YFsSQFpisJzCDi5BusqBOr1xtzen+Jbk01zHElfK6HvV3BKK4abI4vIiGA7/QKlS5u2TQ9/pGFqlfV1+6XQ22AsUxZrlAfxyQVlqD4QusM81xgP4nU060eTXuebw3snhJcj+UKxB4pWCg7njiDf1RvLp2Gq85FKIMwvfbLLbI3YTSr5fHAODC7MrAqBreE8rqxtwPieuaMgZOR85MBnhNNsMWsibrHV7hn0hmId8Klx83yuc=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN0PR10MB5128.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(396003)(136003)(376002)(366004)(346002)(39860400002)(451199015)(71200400001)(2906002)(36756003)(41300700001)(38070700005)(5660300002)(6916009)(316002)(76116006)(66556008)(91956017)(478600001)(33656002)(64756008)(8676002)(54906003)(66476007)(66446008)(66946007)(6486002)(4326008)(86362001)(6506007)(6512007)(26005)(122000001)(2616005)(38100700002)(7366002)(7406005)(7416002)(8936002)(186003)(53546011)(83380400001)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?xmVibhsdI4faUH7zLt6h3stvia4us5mtNQnW3Z+88CbHZsTxbPUZwojsWg?=
 =?iso-8859-1?Q?AmweSuqPGRUQtAzGmukjBgH5ntsZUjPZtrlTtZDv+rIxZD31EcPG9ppiHW?=
 =?iso-8859-1?Q?Z9vyaOJ3OK4NjT8xM4GvA9kzvvdPXejhaNNQYfWYfQ/5UzzvKmeb4xlnpq?=
 =?iso-8859-1?Q?ijke7T7vyt7Lnx4TSmnUWi06tyHpLKrJFj38KqNxGmWEJY2eWBi8Qr5s9p?=
 =?iso-8859-1?Q?0iQJ7AcHKXbtLiQRBWpNx8WD+gk0Pbj5nf9KSVDDNMbyuGrIf6qmqO1hBW?=
 =?iso-8859-1?Q?PRv6GTx966T0o/b/yPdOKRT59w1tBQZTP9LWMG3uJ6qzC5MkOCbOgZWVXo?=
 =?iso-8859-1?Q?KTptclkcp5RrVrRFyh6pe9md61w/Ogk8VgwMfg6BTvmpkO204zL1PpvOOh?=
 =?iso-8859-1?Q?QnSQsmnpflalk0qfng+Gyi0kTw9apDFAEP/d2Rxe3sZs3chDHN88VuFF/A?=
 =?iso-8859-1?Q?xa0fs1vXowpyGTJSEhJCkyVUi/wrC5p4kdyykGcfqBRw3zY/vZCqB/uIiu?=
 =?iso-8859-1?Q?KpYIWVydBdCxwQwSqcj/tJ/hx3eaFG+LH8LdQveikfo/eGnHKngspH6Urt?=
 =?iso-8859-1?Q?mtMcZGFj3S2Dy3sAP48tjqDO94T9KfEIHiyiPmlGmLE8cn7tGpwPE6qsRq?=
 =?iso-8859-1?Q?BOyxIg+1zOT5sKO8CnhZcH5Yp3zm9YiVHu51kTnEIPNAYQ2FDDeQjbSs02?=
 =?iso-8859-1?Q?N4Hp+8FifjiVmVC0F1QXtqnzW1Ich40GmHQ1ctGlB7PbaVZhvItL9g8GUc?=
 =?iso-8859-1?Q?6adB2ESxDXt8bJkOM1D7mZ60nEIhRZOF9mgPWVGnzKXHpSZrHQsddEnZHg?=
 =?iso-8859-1?Q?nxJ2VC4jVVGIqmMmXS99XuphGjfsCDnKC79WBxcB0LpFSpv8LdZqhqo3ar?=
 =?iso-8859-1?Q?z85FhPfVdamzGqAj5bZA7kjqlibV1qbqbQ4rTy9v27YkaLP7PegenW84H4?=
 =?iso-8859-1?Q?6SQRNDHITqQhJwfKQn2aHC9URPxCk2afzlvxCo7Gm3x1LktJUd1soJxNkg?=
 =?iso-8859-1?Q?de71G0XYNEBrmz3SmHAxtBCsu2pbPnhUznvYs1H01UdIxXjVFWEAV8HNrV?=
 =?iso-8859-1?Q?uKueIDGlc2HsSXME1NdN37nJexh++LSHa8R2faG4JSZzGTyoHKvCUGNtZW?=
 =?iso-8859-1?Q?jRoEDRLicv/QoFcz7qhx6Z4a66n9zsvbuyFZTAfGcD7Kp2zgU3upxYYdZ+?=
 =?iso-8859-1?Q?ygI9fxfm2ptCP+bC/dwxsEA6CHoDoqbk+5sH5RQuQDgktpFbVt+O8vegct?=
 =?iso-8859-1?Q?fy+hpOYndjRry8xWU8oANhFHgsnBYhcDyYKQ0rpRayduGeXp60UuXYc9en?=
 =?iso-8859-1?Q?ieYhbaIYqdkvvJN4OlVc3UWw2o8xL1Sf5MR6Bi2TXZAlT/AUCqXwJhdWYX?=
 =?iso-8859-1?Q?uNSLW1tBj88+4o4h/wPcbLj3bq3MIiM3kNzu6PeLsYLztILnNL2QFXJGSp?=
 =?iso-8859-1?Q?efLs8EGnmEFqrKuUxTPghi1Qg1At7fRpF25U3V7di6a3BzeVn4PbQnCav8?=
 =?iso-8859-1?Q?3+OpLV8Uj4h4OB0geez8BKz94zoaQwbN/O/NeD+G+YOT3u/NOItdIou+UD?=
 =?iso-8859-1?Q?ZmoNQ0ZMsTm7TeKix3WQSx+AxdlTdL6JA10n0WAQko3SAUcnqHaHfUtoap?=
 =?iso-8859-1?Q?fetdx4kkNvEKEsGTalH28pqs72BnBJijHoDSDp4iy9c6Jn8F5sNtLWwQ?=
 =?iso-8859-1?Q?=3D=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <91704363A059AB4F8A642E0F6C318C0F@namprd10.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 2
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?iso-8859-1?Q?TUDAGMQm7tMsfJYKXs2m+SysadPDJYaxZ+2Zsy+ORvQ3nIXXpqduzSRWIg?=
 =?iso-8859-1?Q?MneSAi6h7FP/hdopm0CUoO6YTS+F52yPMIeRv9DzwHNdFP4DSGUJbKgoc5?=
 =?iso-8859-1?Q?kdDpnps/DcfKSZqxTRzVAqRmWCwTmjzQYOUnmY68APbwSF/5syuopp7Jv4?=
 =?iso-8859-1?Q?LCGwzIiMI/N/2gMWHaLtgUCVwH3DCzQ2EmRToEZyFdMzNc1Wyx7kKkDUeP?=
 =?iso-8859-1?Q?zbJOr/RTlMOF6AzRJTAV6Jg1PaYFzgKgyC6ptnpqwGwjUeJ1g0UDLvrSCV?=
 =?iso-8859-1?Q?hhoCt5daCQKm7kfiXHyQ46GrJWTYrl3xYirP8/9ZRmD2NICEga4I8tXjrd?=
 =?iso-8859-1?Q?Y+b5kp9dGNsNdqN2vkx0vn1BnSr6JqX6AWq7cTRDL3BTbqvkw/ksvlwJpZ?=
 =?iso-8859-1?Q?crityc1D+8lY2VNq680NGB22wpAz8AC4d4SCPRDGmlIlUZ+t9jgHE99FcN?=
 =?iso-8859-1?Q?SZEzS5smoiOgbukHLuOqv9y7apPQtU6nDIVSm4UkzX5AueVMNI2Ha4DcDx?=
 =?iso-8859-1?Q?waB8d18UEuwzxh3qOxYMMmGcs5VhVQG5QefDdr3h7NRrJygQ+bjnykKiIW?=
 =?iso-8859-1?Q?g6+B7xFl+BE/DL99O6vImdDyWo77jxuStzntdCHwKwNgBK8gDEgf6vAmk5?=
 =?iso-8859-1?Q?tZoIbPoMNWe3W2dNIsoWMVJSmRWiiSXUDFCFc347UGzRjaPEt4fWDLlKm5?=
 =?iso-8859-1?Q?bHti6BMXbpy7GoSbna+7j0YlMKLvGCcdpQoaTclWg6XBl5MuTMUbLOof3X?=
 =?iso-8859-1?Q?LRK4/ydXKRvTKpLqwZGGkO7RrwRNusVMfq7oJYIY4F9MJvuqI20bp8oMSI?=
 =?iso-8859-1?Q?XQR/oRuXbCI12ZKP/bzJ2aMimHgOLujZHpBpxqYHfx0yll1JdP2aasAJ8v?=
 =?iso-8859-1?Q?yIBHkypFStZhcVCLBNDGo2y/KwINiNuDRfx2vSln1yf/4QIsEO69sFOPgQ?=
 =?iso-8859-1?Q?ZASekJZmCfAAycO0lBgtn8r3KWrsdn9d8CkKde20KB67Fgz7rjMvjAG8w2?=
 =?iso-8859-1?Q?gZ94qjBkQsP1CNT1JNLIkFRCHuxOirwWoArYrpXyTy9N8cAGB4aB3Q7Fd6?=
 =?iso-8859-1?Q?werMaOovbZ9/ve0FTnq9tcnvUL8s2h4wW6yOd/b0AYqo9i5Y9LVckfczf2?=
 =?iso-8859-1?Q?UZe6KbLWdLD8p45KdXvGc1StUuA9CoeAUPrXtxqShYmF7Su4V+53TS8UH5?=
 =?iso-8859-1?Q?DBDXhE/12Zll8vtuFyr6jn9Cr7Y5BtTZN7UajeV1v0NHzDfE4+G6bjGypp?=
 =?iso-8859-1?Q?uz9YgYYIjrdWw8mcfNY0dv+zDvHCFQpdQS8uogeHPzhTQRjngYpPBtYJM5?=
 =?iso-8859-1?Q?+xbjVVr4bT5U/1rlSl/pUE90Ku1WTpB57PNeiFUAJumYGqounBwE7DuWpm?=
 =?iso-8859-1?Q?Jyi6PqLRe9AhrV6Omi6ygUFn2A4mSv4iKq3UxtCn9wwWJoWDQbhlNeYgCs?=
 =?iso-8859-1?Q?WOGfHc1OuwZN6AnSP163RkOacsfSO5Br0SZcJQ4Xr8ur70zTNLHeKOfqvl?=
 =?iso-8859-1?Q?4HIE71GeIw1w13Xz+cqzQGzQixvTTEQomAbUl0slzXMSd9sbcCGqXGYamT?=
 =?iso-8859-1?Q?th0hV0FnpSbGN7w0d2nkwTapbv0CJEvKB2EIlCVCH7E5HDNNJt4WEmu9rr?=
 =?iso-8859-1?Q?bIBzccqYlBzXNzMMejpFDBddMhC8Zkl6/bOeMT77DNTP7bR7wJY0M/52Ls?=
 =?iso-8859-1?Q?refzs/FW0lYN75e+CAMagTZ3lmxc9bMU2BjYI6IkAHTtVZtQkNpGRn+4Mh?=
 =?iso-8859-1?Q?l+0u8AbEDIR39ZgMjrj/4PrBGcdoOeX1RuHj8ATX2LIEhqFoD+7s3fPuMC?=
 =?iso-8859-1?Q?doBGQI3Vs36T1X4mi1j6pfe8GSmuYd82gzLBymn7ODnPRA1lVreos6eMwj?=
 =?iso-8859-1?Q?Aj?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-1: =?iso-8859-1?Q?PcFssm7iFlICr6EDk0asnX9+N6TWMFrG72OwFUDER+QdJqBsFeN6bb3ctj?=
 =?iso-8859-1?Q?rfmImIYJpEwccPF9ABx2/p+OoCNDgMKaV3QRDXoG2dhiQzZg6sYj/Kqbpu?=
 =?iso-8859-1?Q?BMctdWXIrVXP9sfbEExSginPHkSl1P4voLY/TIidzZOaPGTN2sv1FmbDh4?=
 =?iso-8859-1?Q?QNdKNNWySmjKXKetU/a1TgRl8GqNlf4f2G+u7Tjs/RHS6y/ArUWCI6l2ae?=
 =?iso-8859-1?Q?whk3V5zWGFg8a7qishQkLgJcQ8ZPEgDgdqyRIYpeLTs8uGnRlcV77dSVWk?=
 =?iso-8859-1?Q?OAD5c2RRjvwI035aRX083t/3H0c/iJfCzSVpBdb/JdE74qMcaHO2sCgwCy?=
 =?iso-8859-1?Q?FuSqdy2jNNeeCneT7l/xq6KtLfSATVXoWFO9PyNfPQkno9s3R9qDAXOtT/?=
 =?iso-8859-1?Q?96RgpTAIrLER/182Ah3nDzYN/swi0ledKiFTH7dYzG0+Ybcx34ldsLk8+Z?=
 =?iso-8859-1?Q?HgTfDQBKKVnwgZJrJ+CFxno7lpMznmJjd+P61PrmuyjV6Ss9Xm3BmNINTL?=
 =?iso-8859-1?Q?FIbFheG6cKy7UEOMX2WYfgaijb5azqi4XDrbRl3KihXJTShW/jn0YSqxlg?=
 =?iso-8859-1?Q?cGu8AMOIgLSDNgTULAbik+meqLGhsNTeA4vigUkX8dOKSqV1rWFOJz97nK?=
 =?iso-8859-1?Q?bntFSIF/TUQTy9hxXHnJ07etdtVVgPUi1gSnnJxzNfpkCdkNnUFzm1Or1q?=
 =?iso-8859-1?Q?Ayd74Jjv8Zh2oUN2RljiJO7eSGaYcThIbfYBPMGv4dxRvrMWq13klDHKvM?=
 =?iso-8859-1?Q?aBfxycmPtOUhgg1Ku98jFiriJOUgJzzBLtMJN2Vr8gXZ+6RS1dSWL2XDf5?=
 =?iso-8859-1?Q?g2ASLyIRTL2jQhVjNXvPETISdJyEyEx245OKD7rCQOmZAz9FtbXD9djB7e?=
 =?iso-8859-1?Q?YLc3+QXeJMggo2a2y5vsPKhUd9K+sAwWZWuFqfuv+Qu83mMT/7f6jf2r4Q?=
 =?iso-8859-1?Q?++2Lu1bPFmkuOE5h4TUpFeMQ?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BN0PR10MB5128.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1cde40ea-87f9-48fe-68ce-08daa7b19a45
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Oct 2022 15:44:06.5167
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: JMHnOqirbM26igqkeHpx8JoaHuuyhUVauvml8OWkN+ZePGqopCZnBUzaDEaxlzkKVSVVaBlVPKT8KjJuGucbDA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR10MB6011
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-06_04,2022-10-06_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0 bulkscore=0
 suspectscore=0 mlxlogscore=999 mlxscore=0 spamscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2209130000
 definitions=main-2210060091
X-Proofpoint-ORIG-GUID: XAlRFAtKNWz7xkwQAyQpJBDlwwbqph4Z
X-Proofpoint-GUID: XAlRFAtKNWz7xkwQAyQpJBDlwwbqph4Z
X-Original-Sender: chuck.lever@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=tJZ7pulU;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=SAQtX80y;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
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



> On Oct 6, 2022, at 9:25 AM, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> 
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
> Documentation/networking/filter.rst            |  2 +-
> drivers/infiniband/hw/cxgb4/cm.c               |  4 ++--
> drivers/infiniband/hw/hfi1/tid_rdma.c          |  2 +-
> drivers/infiniband/hw/mlx4/mad.c               |  2 +-
> drivers/infiniband/ulp/ipoib/ipoib_cm.c        |  2 +-
> drivers/md/raid5-cache.c                       |  2 +-
> drivers/mtd/nand/raw/nandsim.c                 |  2 +-
> drivers/net/bonding/bond_main.c                |  2 +-
> drivers/net/ethernet/broadcom/cnic.c           |  2 +-
> .../chelsio/inline_crypto/chtls/chtls_cm.c     |  2 +-
> drivers/net/ethernet/rocker/rocker_main.c      |  6 +++---
> .../net/wireless/marvell/mwifiex/cfg80211.c    |  4 ++--
> .../net/wireless/microchip/wilc1000/cfg80211.c |  2 +-
> .../net/wireless/quantenna/qtnfmac/cfg80211.c  |  2 +-
> drivers/nvme/common/auth.c                     |  2 +-
> drivers/scsi/cxgbi/cxgb4i/cxgb4i.c             |  4 ++--
> drivers/target/iscsi/cxgbit/cxgbit_cm.c        |  2 +-
> drivers/thunderbolt/xdomain.c                  |  2 +-
> drivers/video/fbdev/uvesafb.c                  |  2 +-
> fs/exfat/inode.c                               |  2 +-
> fs/ext4/ialloc.c                               |  2 +-
> fs/ext4/ioctl.c                                |  4 ++--
> fs/ext4/mmp.c                                  |  2 +-
> fs/f2fs/namei.c                                |  2 +-
> fs/fat/inode.c                                 |  2 +-
> fs/nfsd/nfs4state.c                            |  4 ++--
> fs/ubifs/journal.c                             |  2 +-
> fs/xfs/libxfs/xfs_ialloc.c                     |  2 +-
> fs/xfs/xfs_icache.c                            |  2 +-
> fs/xfs/xfs_log.c                               |  2 +-
> include/net/netfilter/nf_queue.h               |  2 +-
> include/net/red.h                              |  2 +-
> include/net/sock.h                             |  2 +-
> kernel/kcsan/selftest.c                        |  2 +-
> lib/random32.c                                 |  2 +-
> lib/reed_solomon/test_rslib.c                  |  6 +++---
> lib/test_fprobe.c                              |  2 +-
> lib/test_kprobes.c                             |  2 +-
> lib/test_rhashtable.c                          |  6 +++---
> mm/shmem.c                                     |  2 +-
> net/802/garp.c                                 |  2 +-
> net/802/mrp.c                                  |  2 +-
> net/core/pktgen.c                              |  4 ++--
> net/ipv4/tcp_cdg.c                             |  2 +-
> net/ipv4/udp.c                                 |  2 +-
> net/ipv6/ip6_flowlabel.c                       |  2 +-
> net/ipv6/output_core.c                         |  2 +-
> net/netfilter/ipvs/ip_vs_conn.c                |  2 +-
> net/netfilter/xt_statistic.c                   |  2 +-
> net/openvswitch/actions.c                      |  2 +-
> net/rds/bind.c                                 |  2 +-
> net/sched/sch_cake.c                           |  2 +-
> net/sched/sch_netem.c                          | 18 +++++++++---------
> net/sunrpc/auth_gss/gss_krb5_wrap.c            |  4 ++--
> net/sunrpc/xprt.c                              |  2 +-
> net/unix/af_unix.c                             |  2 +-
> 56 files changed, 77 insertions(+), 77 deletions(-)

 ...


> diff --git a/fs/nfsd/nfs4state.c b/fs/nfsd/nfs4state.c
> index c5d199d7e6b4..e10c16cd7881 100644
> --- a/fs/nfsd/nfs4state.c
> +++ b/fs/nfsd/nfs4state.c
> @@ -4346,8 +4346,8 @@ void nfsd4_init_leases_net(struct nfsd_net *nn)
> 	nn->nfsd4_grace = 90;
> 	nn->somebody_reclaimed = false;
> 	nn->track_reclaim_completes = false;
> -	nn->clverifier_counter = prandom_u32();
> -	nn->clientid_base = prandom_u32();
> +	nn->clverifier_counter = get_random_u32();
> +	nn->clientid_base = get_random_u32();
> 	nn->clientid_counter = nn->clientid_base + 1;
> 	nn->s2s_cp_cl_id = nn->clientid_counter++;
> 

For the NFSD hunk:

Acked-by: Chuck Lever <chuck.lever@oracle.com>

--
Chuck Lever



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/E057FAB4-C522-4CE7-ADFE-BDEC7C207A0C%40oracle.com.
