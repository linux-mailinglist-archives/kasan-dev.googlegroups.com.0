Return-Path: <kasan-dev+bncBCX7RK77SEDBBIUHTOAQMGQEEGJKIXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 527EC31A434
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 19:06:27 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id p25sf205524vso.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 10:06:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1613153186; cv=pass;
        d=google.com; s=arc-20160816;
        b=XmHUAFuIb6nAF+WjvaOD6LjPT44U0DO1aIPuPz1TnYgMXgYr3PNZB6YK06IMvX2Eet
         Vukt0JMn0bmSIgx4LWTsYSi6vteP7/WNo2G368TXinv68bXwe3h/XAHlebyEWmatqOZj
         uueUho/a/J5kWMVpMCMdbChO5u3dJZcWB+pHCkT/LeEcGOEahTsD7MXVcZ+qX/YRkYEs
         o7xzqyB71R6OXLGvIvYc9fAdyZKFzUoYA3LtMKLyZU59Hnl5Xyxj4KU2ETaZqIdnKIwF
         r1jVkdsuBDsl+mJb/tUOw/tUZyF9Ab1os/APNgoEY7Fh0+YY5Q5WQ2JzOWYIW6yoJDM+
         4VdA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=osx+gtP6Y1Xp9bPpBLfI313T8UBicx7fyxVzg8YHuJ4=;
        b=qqcLOkm9GQJRsrgbaJAcgfIZ8Nw58ePJ7lIRw1HH25hgWrxn8N7DCGedqRoqyrbdi0
         pPMcolozuGs0+IE/pSuStrewmkCcv5oylCADaRSm206q5WjJoltamBSHDZchFPl61ls0
         lySTqCzX0slfbNE8gh8O28Ba6XA5K/JYGWXzkWAH7RwBUCkdDmYbM/d2SXNIkXjoEAPk
         oyEszYd1qVn374Fsef2DGxKowGSNwq33wPiikGWZKAx3GzoQLPs89Vuw/vqCE/XcdSse
         BpEyRwjZ0ic2Gf8V5hmgGh6sI96WtKJs/N71rzNF3nVXXMUa7k/NziLSpxzUnCEWoQFn
         aQKA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=J20DwUL+;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Ayuzq6uf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=osx+gtP6Y1Xp9bPpBLfI313T8UBicx7fyxVzg8YHuJ4=;
        b=rULswMM29ybFs6a8iwOBITFcFFdmiG3b0+R9PcJ9bzIi666rRt5VMhJNftwspwMVvO
         4htcGjCccNTT2svDj4+69wqklwh+KqgJSwS2ZQ7dJRjqtxhyxuquump4430ockJ6a4Ec
         IueAcnO7aYMuC1xHC4gGslVidadFTii3YpEoxomlr9rLMgPh4vSt1uHK3LGNiJFaDjsX
         ksQlcIpAWBdWDFxwsrX0n3Ph/hgBRB5wlazfDGWeEdHfgp1pTv7Fbm7maWLEPgOWJp7L
         dsJwRNEl1Fiz1zHs1j4T/TWfIk3CGCbE8sEYt3Fpc7UuJoyXPin1yHOYbWiLEuR/YejX
         2EtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=osx+gtP6Y1Xp9bPpBLfI313T8UBicx7fyxVzg8YHuJ4=;
        b=SRcow26sR7SvhWHB30c5nENYUCXluC7CIoETSc0E4nJPv/mywHXAxijEfe5Z9WOT1u
         /MU94809OfU9A9F8eiImFXUQilgE8TFg15J8+lbru9PqOw4T2khOKqJwaQwWQVrC15jk
         HyU4WPwiQZYiLB8gSJYaJlDR67d4j2KXs2DNJj5u9TB438TG7xzyQKq4M3dRrTuYCN64
         B1RHJj3YxSPKEzmK7fQqya8Y+/ZZKnW+O3b03Q55LVLjo+HD8Fqa+PR27IfeUSIc5E3m
         c++47JKFLb6UEGUQGVtrXHivaa+D7bNdAoSRiK6jqkj0wJvP5oYPxWuz2C2vGjncl9aC
         lNMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314Q0yVy6we16ocP45gQTgeM7TZDv2wicILxXZfX/Eprhlv2y5x
	maTdeCW5t7sOibTe9sNhxBk=
X-Google-Smtp-Source: ABdhPJx2AGQS4O2qFbyCL2P5TimuTiMUmzZdXEJcxm4sfSU2aU8wCblBltCDFHaZEuoW+9dUhayqZA==
X-Received: by 2002:ab0:22d5:: with SMTP id z21mr2689141uam.81.1613153186326;
        Fri, 12 Feb 2021 10:06:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3d86:: with SMTP id k128ls517389vka.0.gmail; Fri, 12 Feb
 2021 10:06:25 -0800 (PST)
X-Received: by 2002:a1f:3101:: with SMTP id x1mr2563421vkx.16.1613153185797;
        Fri, 12 Feb 2021 10:06:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613153185; cv=pass;
        d=google.com; s=arc-20160816;
        b=B/pTR8SVi4GKgomKe964pfLFpiRYseI4JTNA/g3Z8KnjAsavfR11EVUTpk6uaLLkBn
         kTFplUhmaLq64TjXLGB7q7kDGSJYojJe38lGbG+fIS1+OyrskXGsCYTdNYHTHktNdSOs
         xU1ockZQqLlgOYP1z5xZJGzJbmrcnvC+qjBZCwA3kusbdlO81KDH8QtegwNyJ4GlTCWy
         SFrBxNaEEeA60JHaFuiR3rexH7kseP3hFUoxfs4CceKCwLk1Th0RGQ80urvvw0ZB08je
         uGQuAjZOYaVt7kTz+8rtJDanSUrYnJHFJd9QO+ddzNEGB6eMWg7fP77Kbmr0ZesWyusM
         Ot+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=Xgdwr+OSOa/ocU0qw/OVvwr0KWMwPuNMluzNMW7z3C0=;
        b=pp35l0zMydPlsDoT+FOErrgkbXB1bynKvla/F6XdYmQ/NahT0Hb+OLr/1rWStnHPX6
         Fpex7bgicOqlo/LvrAaEpBkyYKj02kHYMzQYgFhUzQNEQ/E1G3YzsGm+ZdRENvG/9Zlf
         cL5qksy6bw/Vj9S4YiLXXcAqz9AJM6xY17n6IQ1asZeXHZ9tguyZRvSTBe+Kd1+8XIsv
         fbrE2brMRC5SA1TtklCy1HMDwv+S9byueeDyQ1BaDgzPWsfzOQsuHXnLYsZOKNxoia/a
         X2RCSTUwEAoBmJvqh9YNg+VP79vpVKftcdLSxpd99wdhyuLXzqF4p7G/9ufAO990nnhK
         ncFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=J20DwUL+;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Ayuzq6uf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id q1si557735vsn.1.2021.02.12.10.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 10:06:25 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11CI3r8O115719;
	Fri, 12 Feb 2021 18:06:11 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by userp2120.oracle.com with ESMTP id 36hkrnc3wq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Feb 2021 18:06:10 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11CI69C1126078;
	Fri, 12 Feb 2021 18:06:10 GMT
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11lp2168.outbound.protection.outlook.com [104.47.56.168])
	by aserp3030.oracle.com with ESMTP id 36j4pt9nt5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Feb 2021 18:06:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=W59iLMQUo4nl+2yfannTa1uj8VWs5u/kzYpJzAcHEEWJKlZr1Jd2ZpbHEzE4mhWXvPe5xdGSjS0NNPu577wnjyozZ0pF3VHJGWDXZm9dfeOsAeSYEScJFxsrFqVtcNkheTsvibsm6k91PIAHOMjKKBZPPsi6RV5ix64w0lEoRTggazZx6Ht+RzW+l+Bjmfm94giZRCmLq85HZb/fAa3f6CuDeeL8I0G3H0quxcOiMs2htqqJeIX8nz02MTaEON98aTWqauaqcKbRNoxD+fppFk5Nbv3JGlFXpOAhP/dABhBdIURSL7zXfZThAOvD2a0/kpDcn6zMlVQcKw1FotkEkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Xgdwr+OSOa/ocU0qw/OVvwr0KWMwPuNMluzNMW7z3C0=;
 b=bgtc2pXUGrMAFAiPVy0k6AolgVIfHtzoN0tWuQrk1WfGZRc5S2JOQzp6DcqmGT/tPCYL4czaZEFr33rg9M3ji5eVusB/jxi4AvppwcEzD9KEV4ECkDtvzIXwgArq0XJONv9clW7HRPOHiDCw8JyyYocCQIPDJy9Q7jWl/96IUlvO34qbIOuiK8/T/Homnq1VDht7Yvlq3chaWXPeO62iWaiFmbY6PaFhP3j0PmHuXtRo8tQHR6UtTfOBXXiK4UvJqKG6SZ90TcsemYAZtGyGIWEi9e+UnWS5L8bxs4xo0jvPPI5Fn9so2K52o4NBaG8tmD0uAnIcD77i0ceCMEGLWQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB3116.namprd10.prod.outlook.com (2603:10b6:5:1ab::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3846.25; Fri, 12 Feb
 2021 18:05:54 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3846.027; Fri, 12 Feb 2021
 18:05:54 +0000
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
To: David Hildenbrand <david@redhat.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: Konrad Rzeszutek Wilk <konrad@darnok.org>,
        "Rafael J. Wysocki" <rjw@rjwysocki.net>,
        Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com,
        konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>,
        Dan Carpenter <dan.carpenter@oracle.com>,
        Dhaval Giani <dhaval.giani@oracle.com>
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
 <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com>
 <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
 <20210203192856.GA324708@fedora>
 <CACT4Y+bscZGpMK-UXXzeFDeJtGYt-royR_=iTzTmBrwe3wOmTw@mail.gmail.com>
 <14124734-326e-87b3-a04a-b7190f1e1282@oracle.com>
 <bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com>
 <CACT4Y+Ze3J5L7vBt7hmqbMrxhRg=k1hZkPTJpCG83Gc=Wr-Fsg@mail.gmail.com>
 <b2399990-0464-4041-5dd1-d2828ee0c910@redhat.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <39fc8ef9-94ff-3d43-cde4-0e65d1ca187d@oracle.com>
Date: Fri, 12 Feb 2021 13:05:48 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <b2399990-0464-4041-5dd1-d2828ee0c910@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: SJ0PR13CA0042.namprd13.prod.outlook.com
 (2603:10b6:a03:2c2::17) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by SJ0PR13CA0042.namprd13.prod.outlook.com (2603:10b6:a03:2c2::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.11 via Frontend Transport; Fri, 12 Feb 2021 18:05:52 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: b9a2dd11-5676-401c-0697-08d8cf80d6e6
X-MS-TrafficTypeDiagnostic: DM6PR10MB3116:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB3116A89EC63549CD236C8DD3E68B9@DM6PR10MB3116.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: QZKmuGedt8sXcv9BMg+8SWSavyUVIEhCYSt8SxE6wRfHkuXyGJTf3hTLP/Lc34723TJsUlle6jfVD16pzq9Og6sHGihdAmWK9Wt/jSRY9Q+HPYuZaQ4DNsYVePuvzWZcFgU2Kbbi8GRKkgAVytxGuffGYpkt8eR+dqoGrUbItV/y5/gKiMMk4+Cjz/pGTgJmZgf3SXeyHrC6HMwhRB32pvD1oKRazXR3P+7EpjMWA3OXC3ye9A0Npz+XLhpD223Uw4oF3E6iGeQA5C7y2j2v+HxWWOgY0ta0og60mgxcJGDyYpjYZmbZeFu8FNmflnqV93wTJYXzqj0Rvid+TY1AyklU7KQJ+SPNUH6yMZUqr+XLftusKG4iVSiJUKuF4TRfhbAjaOKLqipLjuVH6ACFJY6FXQ4xAwZ9QHnK07ZGlIv7X+PKz7P3S/p1wUg1rJRtPZi6o5Xh1EaAnPvia+Qz9jfH+irj4MzbSvqjrmd0jGzoatX9GuzZUx3n1OryOqK14CFkqtepCDjn0bUXG0DmTePLoOOfZ9jaI0UHWtbJUDIyVyFnXbWRRV8vSEhnpfiS602w3OF3sBNGPSEMhIwUIfcaZSwXsJxRDGkwSRgwLtg9UxwzyuZbiHaWisqqtycFJaJPFE+Sk1mLviDVDPTARfydCWdhYptN2av6u+f+LmTfSSNYelKuLc0qujGdnqDC
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(376002)(39860400002)(136003)(396003)(366004)(31686004)(2906002)(53546011)(4326008)(8676002)(83380400001)(66476007)(4001150100001)(44832011)(7416002)(54906003)(6666004)(110136005)(16526019)(107886003)(186003)(956004)(2616005)(36916002)(26005)(5660300002)(86362001)(478600001)(66946007)(30864003)(16576012)(66556008)(8936002)(966005)(316002)(31696002)(6486002)(36756003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?SENpNFVseGJ5cG9TN1l0VlBQK0ZJRWdNN3lYVjA4dG5WYmV1ekJtU3NBWWRr?=
 =?utf-8?B?OStZRk8vSUlOMFUrVFNzQ29FeW55Wjl5MnhiTFEyYWdCZ1FYNFZoM2YwbDU2?=
 =?utf-8?B?aCtjc0ptVmRTK0J3M2p2cWMwVWxrV3RTcGNpbjRId0NZSDM5N0h1djFUb3R1?=
 =?utf-8?B?bHZqajRkUHoxUllsbTlMbyt0RVkxaWRNNWhKSStVTmx4bm1IUC9WOWEzWHM4?=
 =?utf-8?B?WlVuMzNuUy81cVQvUjhGY2lFUmpFZ3Mza25iRmZXSGphalllRzNuSUQ1Q1da?=
 =?utf-8?B?c1B2Wnl0SEpKM0daV1ljU1NaWnBWNEVyc3dRWGZDU0JtdHpXZFh2dDlwdTRQ?=
 =?utf-8?B?RkoyTlVYVmZ4cTcySUNsaGZpMndrc3RRNUx4MEw1WGRwMTNqYjQ4bTMyelhs?=
 =?utf-8?B?L0lkcHZ4K3o1ZllMYzVVQWNUZjBOdlcrZVl3UFFicTVQdXR3M0hlb1o5L2pw?=
 =?utf-8?B?dXF6QytCYnd1UFRETURPWmJqd0xhU28xUy9KVWRmaHhiR3JzbEhpdUlCR1lr?=
 =?utf-8?B?clBUWnZRejl5cytzNVVYVW5OeG55QWQrZ3FaWEFjNnhvMldjdjIrT2t3UmFs?=
 =?utf-8?B?YlJ4UEVZMkFQYllRSXF5S3ZtdkcvUVl0SmNwL2YrLzZxanNhTWc3TnQ0RGt5?=
 =?utf-8?B?SUtobXB6UHFyNGM0VFU5dXk2dENCdE80SFVuMWh5MExyN01ReGx4dEU3MHd2?=
 =?utf-8?B?L3NPbENpRlo0TnV3R2FZL3pPeUZrYTRiWkE1MjNQVXVaNjlrV0doWUhuUHlE?=
 =?utf-8?B?S2trZzRoMVJlSUlhbEpqYVhnUWhtY1MyZ3JVZ1VtTFd0L3l5NW9pRXkrU25h?=
 =?utf-8?B?ZitHOEFKV2lFN0Q2VVdGOWRhSXQ0WFNsZWowZFJYbkhxQVNZWUxhT3VUSWJB?=
 =?utf-8?B?LzZBVUtxanNPc0ZJcmJQN2ZnUzFiNjdoc2pUdUVqMVVEVUp3QVFIZW8xbC94?=
 =?utf-8?B?d25hOGRTTmtZUDQyeXREN1RaMWxBVStVa3BndXQ5OWE4a1dhK1UyQkNEeUxC?=
 =?utf-8?B?L0FrbUV6RWsweG1CeUQ1VXhJZDk4cDhLaHE4K1JvZ2pkVmwzYlM1aFIyOU1p?=
 =?utf-8?B?b3YrWWF0b2dReXdhcUl4N3BnV3RMUjhjK0ExbkZIVTl5bnM2MDlTRjI0VEUy?=
 =?utf-8?B?OEFHR0U5UUNzejA1MnB2ZDB4NTVVcVc3U1ZSRHRvREZ6SktUYnE2d1JjMTJR?=
 =?utf-8?B?K2U0OUsySUFzRmZTZE1yaTlHWnhDOGdxZ2x3Q3ZmLzg0V1Eza25ncUVQMWdl?=
 =?utf-8?B?R1gzZmpVa2Frbmt5ZEpPaUp4dGFjK0J1VWtRd3Z5a1VSZzRnR1ZKcXlOeWNT?=
 =?utf-8?B?TXA5QUYvUGg1cWYwd1I2cG4zVldnODFYQU1uWVV6WWVURmdyZjV0cEpDZE9M?=
 =?utf-8?B?OWRiSXVVNE1iZ2JEcVpCOWdldmtPQlRTSjlZaDFlSTBsOUlTdnEwaXlDdXRx?=
 =?utf-8?B?NHp2MTgwK2t2QlZhQVN2dzAwYmRscU1ld0dRTk1Hb0V3elNHRWpDSTIveXBa?=
 =?utf-8?B?SGRYU3NpY0RDc2FSOVYrU0o5YVIrbUNXMTl4V2hGSXVHQU1sYUJ0VDhkaEpu?=
 =?utf-8?B?L1hyV2JUSmRycU5FQldZSkErK0R6d1MvNWhLTFhjZWZsaWk2bGJkYmg5YWFU?=
 =?utf-8?B?M2IzRTZYa0k1a0pMbW9WYjFrVUVYQVMzV2dnN0pqMFNsdThuSGJ0UkNtTTJJ?=
 =?utf-8?B?bkRjMU0rZWFGaUdmL05sZ05yRlZQNkhZb0xBQmlIakM0b3E3MUQwUTBxcE44?=
 =?utf-8?Q?Su8/oqWbApIjtzafiGyF4W2RyYniCoI1h5YoZRp?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b9a2dd11-5676-401c-0697-08d8cf80d6e6
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Feb 2021 18:05:54.2876
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: U3lMPEB0/aIV8YyrLgB8Yzj7g9viXo6fJcR7ZsSlO62u3iVsvcCLtBVhwQRs2MO9eyVfzfH/W9/mFNSJk331fPiBT/ZYq8+LBsOSBDkLQXQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3116
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9893 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 adultscore=0
 mlxlogscore=999 malwarescore=0 bulkscore=0 phishscore=0 spamscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102120133
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9893 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 malwarescore=0
 priorityscore=1501 bulkscore=0 spamscore=0 impostorscore=0 mlxscore=0
 suspectscore=0 mlxlogscore=999 adultscore=0 clxscore=1015
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102120133
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=J20DwUL+;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Ayuzq6uf;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/12/2021 10:36 AM, David Hildenbrand wrote:
> On 12.02.21 14:51, Dmitry Vyukov wrote:
>> On Fri, Feb 12, 2021 at 2:31 PM George Kennedy
>> <george.kennedy@oracle.com> wrote:
>>> On 2/10/2021 4:51 PM, George Kennedy wrote:
>>>> On 2/3/2021 2:35 PM, Dmitry Vyukov wrote:
>>>>> On Wed, Feb 3, 2021 at 8:29 PM Konrad Rzeszutek Wilk
>>>>> <konrad@darnok.org> wrote:
>>>>>> Hey Dmitry, Rafael, George, please see below..
>>>>>>
>>>>>> On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
>>>>>>> On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
>>>>>>> <george.kennedy@oracle.com> wrote:
>>>>>>>> Hi Dmitry,
>>>>>>>>
>>>>>>>> On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
>>>>>>>>
>>>>>>>> On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
>>>>>>>> <konrad.wilk@oracle.com> wrote:
>>>>>>>>
>>>>>>>> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
>>>>>>>>
>>>>>>>> During boot of kernel with CONFIG_KASAN the following KASAN false
>>>>>>>> positive failure will occur when ibft_init() reads the
>>>>>>>> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
>>>>>>>>
>>>>>>>> The ACPI iBFT table is not allocated, and the iscsi driver uses
>>>>>>>> a pointer to it to calculate checksum, etc. KASAN complains
>>>>>>>> about this pointer with use-after-free, which this is not.
>>>>>>>>
>>>>>>>> Andrey, Alexander, Dmitry,
>>>>>>>>
>>>>>>>> I think this is the right way for this, but was wondering if=20
>>>>>>>> you have
>>>>>>>> other suggestions?
>>>>>>>>
>>>>>>>> Thanks!
>>>>>>>>
>>>>>>>> Hi George, Konrad,
>>>>>>>>
>>>>>>>> Please provide a sample KASAN report and kernel version to match
>>>>>>>> line numbers.
>>>>>>>>
>>>>>>>> 5.4.17-2102.200.0.0.20210106_0000
>>>>>>>>
>>>>>>>> [=C2=A0=C2=A0 24.413536] iBFT detected.
>>>>>>>> [=C2=A0=C2=A0 24.414074]
>>>>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>>>>> [=C2=A0=C2=A0 24.407342] BUG: KASAN: use-after-free in ibft_init+0=
x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342] Read of size 4 at addr ffff8880be452004 b=
y task
>>>>>>>> swapper/0/1
>>>>>>>> [=C2=A0=C2=A0 24.407342]
>>>>>>>> [=C2=A0=C2=A0 24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted
>>>>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>>>>> [=C2=A0=C2=A0 24.407342] Hardware name: QEMU Standard PC (i440FX +=
 PIIX,
>>>>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>>>>> [=C2=A0=C2=A0 24.407342] Call Trace:
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 dump_stack+0xd4/0x119
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342] print_address_description.constprop.6+0x2=
0/0x220
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 __kasan_report.cold.9+0x37/0x77
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kasan_report+0x14/0x1b
>>>>>>>> [=C2=A0=C2=A0 24.407342] __asan_report_load_n_noabort+0xf/0x11
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? dmi_sysfs_init+0x1a5/0x1a5
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? dmi_walk+0x72/0x89
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_check_initiator_for+0x159/0x=
159
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rvt_init_port+0x110/0x101
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_check_initiator_for+0x159/0x=
159
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 do_one_initcall+0xc3/0x44d
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? perf_trace_initcall_level+0x410/0=
x405
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kernel_init_freeable+0x551/0x673
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? start_kernel+0x94b/0x94b
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? __sanitizer_cov_trace_const_cmp1+=
0x1a/0x1c
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? __kasan_check_write+0x14/0x16
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rest_init+0xe6/0xe6
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kernel_init+0x16/0x1bd
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rest_init+0xe6/0xe6
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ret_from_fork+0x2b/0x36
>>>>>>>> [=C2=A0=C2=A0 24.407342]
>>>>>>>> [=C2=A0=C2=A0 24.407342] The buggy address belongs to the page:
>>>>>>>> [=C2=A0=C2=A0 24.407342] page:ffffea0002f91480 refcount:0 mapcount=
:0
>>>>>>>> mapping:0000000000000000 index:0x1
>>>>>>>> [=C2=A0=C2=A0 24.407342] flags: 0xfffffc0000000()
>>>>>>>> [=C2=A0=C2=A0 24.407342] raw: 000fffffc0000000 ffffea0002fca588
>>>>>>>> ffffea0002fb1a88 0000000000000000
>>>>>>>> [=C2=A0=C2=A0 24.407342] raw: 0000000000000001 0000000000000000
>>>>>>>> 00000000ffffffff 0000000000000000
>>>>>>>> [=C2=A0=C2=A0 24.407342] page dumped because: kasan: bad access de=
tected
>>>>>>>> [=C2=A0=C2=A0 24.407342]
>>>>>>>> [=C2=A0=C2=A0 24.407342] Memory state around the buggy address:
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be451f00: ff ff ff ff ff ff=
 ff ff ff ff ff
>>>>>>>> ff ff ff ff ff
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be451f80: ff ff ff ff ff ff=
 ff ff ff ff ff
>>>>>>>> ff ff ff ff ff
>>>>>>>> [=C2=A0=C2=A0 24.407342] >ffff8880be452000: ff ff ff ff ff ff ff f=
f ff ff ff
>>>>>>>> ff ff ff ff ff
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be452080: ff ff ff ff ff ff=
 ff ff ff ff ff
>>>>>>>> ff ff ff ff ff
>>>>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be452100: ff ff ff ff ff ff=
 ff ff ff ff ff
>>>>>>>> ff ff ff ff ff
>>>>>>>> [=C2=A0=C2=A0 24.407342]
>>>>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>>>>> [=C2=A0=C2=A0 24.407342] Disabling lock debugging due to kernel ta=
int
>>>>>>>> [=C2=A0=C2=A0 24.451021] Kernel panic - not syncing: panic_on_warn=
 set ...
>>>>>>>> [=C2=A0=C2=A0 24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G =
B
>>>>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>>>>> [=C2=A0=C2=A0 24.452002] Hardware name: QEMU Standard PC (i440FX +=
 PIIX,
>>>>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>>>>> [=C2=A0=C2=A0 24.452002] Call Trace:
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 dump_stack+0xd4/0x119
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x102/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 panic+0x28f/0x6e0
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __warn_printk+0xe0/0xe0
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? add_taint+0x68/0xb3
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? add_taint+0x68/0xb3
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 end_report+0x4c/0x54
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 __kasan_report.cold.9+0x55/0x77
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kasan_report+0x14/0x1b
>>>>>>>> [=C2=A0=C2=A0 24.452002] __asan_report_load_n_noabort+0xf/0x11
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ibft_init+0x134/0xb8b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? dmi_sysfs_init+0x1a5/0x1a5
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? dmi_walk+0x72/0x89
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_check_initiator_for+0x159/0x=
159
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rvt_init_port+0x110/0x101
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_check_initiator_for+0x159/0x=
159
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 do_one_initcall+0xc3/0x44d
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? perf_trace_initcall_level+0x410/0=
x405
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kernel_init_freeable+0x551/0x673
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? start_kernel+0x94b/0x94b
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __sanitizer_cov_trace_const_cmp1+=
0x1a/0x1c
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __kasan_check_write+0x14/0x16
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rest_init+0xe6/0xe6
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kernel_init+0x16/0x1bd
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rest_init+0xe6/0xe6
>>>>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ret_from_fork+0x2b/0x36
>>>>>>>> [=C2=A0=C2=A0 24.452002] Dumping ftrace buffer:
>>>>>>>> [=C2=A0=C2=A0 24.452002] ---------------------------------
>>>>>>>> [=C2=A0=C2=A0 24.452002] swapper/-1=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 1.... 24564337us : rdmaip_init:
>>>>>>>> 2924: rdmaip_init: Active Bonding is DISABLED
>>>>>>>> [=C2=A0=C2=A0 24.452002] ---------------------------------
>>>>>>>> [=C2=A0=C2=A0 24.452002] Kernel Offset: disabled
>>>>>>>> [=C2=A0=C2=A0 24.452002] Rebooting in 1 seconds..
>>>>>>>>
>>>>>>>> Why does KASAN think the address is freed? For that to happen that
>>>>>>>> memory should have been freed. I don't remember any similar false
>>>>>>>> positives from KASAN, so this looks a bit suspicious.
>>>>>>>>
>>>>>>>> I'm not sure why KASAN thinks the address is freed. There are
>>>>>>>> other modules where KASAN/KCOV is disabled on boot.
>>>>>>>> Could this be for a similar reason?
>>>>>>> Most of these files are disabled because they cause recursion in
>>>>>>> instrumentation, or execute too early in bootstrap process (before
>>>>>>> kasan_init).
>>>>>>>
>>>>>>> Somehow the table pointer in ibft_init points to a freed page. I
>>>>>>> tracked it down to here:
>>>>>>> https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica=
/tbutils.c#L399=20
>>>>>>>
>>>>>>>
>>>>>>> but I can't find where this table_desc->pointer comes from.=20
>>>>>>> Perhaps it
>>>>>> It is what the BIOS generated. It usually points to some memory
>>>>>> location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
>>>>>> other tables in there.
>>>>>>
>>>>>>> uses some allocation method that's not supported by KASAN? However,
>>>>>>> it's the only such case that I've seen, so it's a bit weird.=20
>>>>>>> Could it
>>>>>>> use something like memblock_alloc? Or maybe that page was in fact
>>>>>>> freed?... Too bad KASAN does not print free stack for pages, maybe
>>>>>>> it's not too hard to do if CONFIG_PAGE_OWNER is enabled...
>>>>>> Hm, there is a comment in the acpi_get_table speaking about the
>>>>>> requirement of having a acpi_put_table and:
>>>>>>
>>>>>>
>>>>>> =C2=A0=C2=A0 * DESCRIPTION: Finds and verifies an ACPI table. Table =
must be=20
>>>>>> in the
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 RSDT/XSDT.
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 Note that an early stage acpi_get_table() call=20
>>>>>> must
>>>>>> be paired
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 with an early stage acpi_put_table() call.
>>>>>> otherwise the table
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 pointer mapped by the early stage mapping
>>>>>> implementation may be
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 erroneously unmapped by the late stage unmapping
>>>>>> implementation
>>>>>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 in an acpi_put_table() invoked during the late=20
>>>>>> stage.
>>>>>> =C2=A0=C2=A0 *
>>>>>>
>>>>>> Which would imply that I should use acpi_put_table in the error path
>>>>>> (see below a patch), but also copy the structure instead of=20
>>>>>> depending
>>>>>> on ACPI keeping it mapped for me. I think.
>>>>> Hi Konrad,
>>>>>
>>>>> Thanks for looking into this.
>>>>> If ACPI unmaps this page, that would perfectly explain the KASAN=20
>>>>> report.
>>>>>
>>>>> George, does this patch eliminate the KASAN report for you?
>>>>
>>>> Hi Dmitry,
>>>>
>>>> No luck with the patch. Tried high level bisect instead. Here are the
>>>> results:
>>>>
>>>> BUG: KASAN: use-after-free in ibft_init+0x134/0xc49
>>>>
>>>> Bisect status:
>>>> v5.11-rc6 Sun Jan 31 13:50:09 2021 -0800=C2=A0=C2=A0=C2=A0=C2=A0 Faile=
d
>>>> v5.11-rc1 Sun Dec 27 15:30:22 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
>>>> v5.10 Sun Dec 13 14:41:30 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 Failed
>>>> v5.10-rc6 Sun Nov 29 15:50:50 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
>>>> v5.10-rc5 Sun Nov 22 15:36:08 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
>>>> v5.10-rc4 Sun Nov 15 16:44:31 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
>>>> v5.10-rc3 Sun Nov 8 16:10:16 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
Failed
>>>> v5.10-rc2 Sun Nov 1 14:43:52 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
Failed
>>>> v5.10-rc1 Sun Oct 25 15:14:11 2020 -0700=C2=A0=C2=A0=C2=A0=C2=A0 Faile=
d
>>>> v5.9 Sun Oct 11 14:15:50 2020 -0700=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 OK - 10 reboots so
>>>> far w/o kasan failure
>>>>
>>>> So, will look at what changed between v5.9 and v5.10-rc1
>>>
>>> git bisect has identified the following as the offending commit:
>>>
>>> 2020-10-16 torvalds@linux-foundation.org - 7fef431 2020-10-15 David
>>> Hildenbrand mm/page_alloc: place pages to tail in __free_pages_core()
>>
>> I think this suggests that this is a real use-after-free and the
>> page_alloc change just exposed a latent bug.
>
> That commit is ridiculously good at finding latent BUGs. Memory gets=20
> allocated and used in the reverse order. So could be that this is=20
> exposing yet another latent bug.
>
> For example:=20
> https://lkml.kernel.org/r/20201213225517.3838501-1-linus.walleij@linaro.o=
rg
>
> Or a longer discussion at:=20
> https://lkml.kernel.org/r/87361onphy.fsf_-_@codeaurora.org
>
>
> Anyhow, let me know in case it looks like this time it's actually my=20
> commit that broke something (although somewhat unlikely I have to say).

Thank you Dmitry & David,

Good read and agree - great smoke test for latent bugs.

Continuing to search for the real bug.

George

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/39fc8ef9-94ff-3d43-cde4-0e65d1ca187d%40oracle.com.
