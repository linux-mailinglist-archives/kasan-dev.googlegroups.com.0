Return-Path: <kasan-dev+bncBDRYTJUOSUERBAMU72FAMGQEBFRW7FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E12274260D2
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 02:00:01 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id p12-20020adfc38c000000b00160d6a7e293sf3419951wrf.18
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 17:00:01 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1633651201; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhbD4wBS5Vr8mCIf/ZCXzJO4KEiPhS2bXMkJJJVujx/V4+2P3175zj34KYyBVG7HzV
         H/WMqS+VkpwO43KTxMef/zgtL+uJSLSOY7gYQ5QsUyF/TeVEcseiOAcbWU6gdAWmSjFY
         qxcUnypzhm8axug+yIaDSbh5BTtscR1ccFmwDj1J1arAmni4grNBPEuvnzxMJCyKtdDF
         KVVUK1f9PxYrZcUqiteF5RzIRZJGeXuH/oMFHlINp5FvUoS29260INYF91d4d2+SLEfS
         SavPARlFxU8jf4b/o/fIP7GhWcT3ZiMcm3eAYQU6sRGdK8TnwxhaLCoKWUtwswJG5AR5
         cBxA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dxsd+4AJearsGqOoyqCNrAlmvm3kn4wmdVAreHJHOko=;
        b=NarKxwvdIyvQD75gRUOQUgBsGa7JYC7rdVe1KqoUw7fhKYNvJuiRZZRg12JZSB7Ms7
         ylVVgpkzGIsT87G5h06/cx2d1WJmDV1vSlJ6VYv65Xrd1zlS3GAVRsiAzWLwYlaIRWGN
         FZVfRUP9PhPrBUAbov5ibIDets9SZyrT1Ml/kshRlquoyitsMU06nMLB7nEwXLboAaUX
         xGrJPJH7cEb4d6wxDL3UfH4kh5QYREcwwmFKqj0grQ88YkLXlPZsnFPU0MZcyC97G9Hh
         brllyocGd3V5rtUegBEC0veA3lpjqKxulsL6Ne2l59Nx799HUyfbSC4MDntU4YSTSTQ5
         welA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=Ard5ZRx7;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.10.132 as permitted sender) smtp.mailfrom=gary@garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dxsd+4AJearsGqOoyqCNrAlmvm3kn4wmdVAreHJHOko=;
        b=fAZfwxys3SOpszkifx5vBqmGzoB0zPO3mNvL0y3jdRsi6yB/gWMifpCxC36W7HpbWN
         CEIi0dAoAGxpZrSFfJRzc3lX+ThVCNdWHjSfJUWdcVrRt91ENKDd2nqG2YzI5ElNrZXu
         n1OB2+3VjBu4y4thz/epOo0rNL0byxlpaJG7RQboKuzNhvMhyXUDvKIKZcgxvReLHzUQ
         ju8EKID7h3dfbHCTzUxEJgntkCAAfiP3qvEBlFv72ff/lzQexkq1k8BM4ucNOnbMp57H
         TWvDYIx4c+knKocAYmM7wk7kKGfAR9y1exnUBGks4QP63Y+Yo2gNueqX9D2AdYnwdrnc
         5kQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dxsd+4AJearsGqOoyqCNrAlmvm3kn4wmdVAreHJHOko=;
        b=oCggxENH0t+e+GKDjzCzM8eawNL0jW7F26Foyg6jK5P/0/I8sQaC4alII3yFNsJ3YF
         c7jahPOdmvxCgEMGiSjpF2UMWFSm+Nbi89owANSGwESEoNun8Fp4LCEnwF5nay9xYChE
         zZE9B58PEgWCiE0W04nKqKJLwaGtsofInVjzC/kWCHj7driAjcW+G8Eu16CfD0kLlIZ5
         PmwIPrkDnBBSzkJRQ3D4GAEkereiNt4y0qXtDcA5YIMg9EDHTCNZURA/SzuNrsCPZj5I
         OAOdUyOZqZufD4qczZqC4sHjVjOonY+JreigbKXIcGUj97eTzXOVormeabOfGUXS0p0D
         s6Ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NBR8JFs+RPPoUHYiI4ioKN8BxgLUUnHuYJ0E6GB3cNjVjLNwP
	gpa0eh+tZZUDPESYeszUgAs=
X-Google-Smtp-Source: ABdhPJw4J4d8+FMkzSPZrGX8bWstmSIYsksOTdH1qaQyTE9WbzmLXOIibUDL9QevftKSXfOiqLM5Pw==
X-Received: by 2002:adf:8b9a:: with SMTP id o26mr9235659wra.109.1633651201700;
        Thu, 07 Oct 2021 17:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:364f:: with SMTP id y15ls738367wmq.3.gmail; Thu, 07
 Oct 2021 17:00:00 -0700 (PDT)
X-Received: by 2002:a1c:9d50:: with SMTP id g77mr27565wme.58.1633651200721;
        Thu, 07 Oct 2021 17:00:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633651200; cv=pass;
        d=google.com; s=arc-20160816;
        b=LhUa7poQ9KE0crjUibZrcaUgW6kWJgBosR11U7YN0tceIelXbk9WE6Vxn9p7M5gQwG
         dyFKNTwVR4V+FGPNgNGDJbgTvaYh3pdDh5nOudpIsozHdx9a/wM2IM5MQuW5tDSvZN7V
         gnlRU71h4HKTtpI1GKHparF7W/iZR2RzEIyvPEJkAJCgGPgV1R+fvrIhAUHrBfnmwVrV
         bR1F4xLPjg+inL6Jqh2y0DW18a76ltGVAKNoDed49HHF5bm/SfG3t+YgCOWRJt3+2t7d
         i3XLgwoeV9Sn1lwSsOmdbwRGfz3iv9iYds38WjYM2Y4CXEAHq2HYK4LyOPS/h4zmoGV4
         mUjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0IQPYDDHu3jt+U4rEPg9YzNj/aBL+MyWi9LpZI4khpU=;
        b=ZKuDWQ44cHZ72bUWXMjqKfVi/pwjAM/9WvquG3yJuUTlbSl39g8PtXsXjkaiWjsQng
         +mZN30D0YMabA9x57XtKsl02aE0L8zRRdNWB4uV+LbgGFGqylX45XwBPtRBbG7iklG8z
         9VZTZECt0U1i2yxvg0MOtRUh9V4xLohxX7UU2btQUsp6b21HChz6Iepxdv1wdAF4G9vv
         z/lLNxdCCdfJ0zxt9GrutyiyS0aEUlGkOhIr8NrUzUibi2VUZ695+GsH+RxM2lH3VbB/
         3T/pnoIQqfpCsoMsstHl5wR6+9RGQGDrqwFZ3OX3jOtF17/uAIE12w0397xeAFujMdZc
         9uBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=Ard5ZRx7;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.10.132 as permitted sender) smtp.mailfrom=gary@garyguo.net
Received: from GBR01-LO2-obe.outbound.protection.outlook.com (mail-eopbgr100132.outbound.protection.outlook.com. [40.107.10.132])
        by gmr-mx.google.com with ESMTPS id b72si336138wmd.1.2021.10.07.17.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 17:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 40.107.10.132 as permitted sender) client-ip=40.107.10.132;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=UFnO2esuuinMou/3a4lVVd+gNHuTy6Doxx7z5REgHaRmIs/FMA7VQFMlGg0N60ZTak1JodmSj7FeX7tO+/RvkAab7jL8m5jGX/YDn9yL6yzkynV97ZCj3um/pehFLu25sTtPlU38X7bdIDPgjL9LJGrxPeUUoXLMj0sDatUE/QL8EohJOoFCwi/seEVkmdPzXG3Sqqh1Fjc6AgEdt5zt6Hr1/74C55ddHcQjL3uwQN6BuqCzxiAjGhQObEM/S0IEZWbgviNNevZSTBvwLipWscQllT/eMGKt9OOrt/GS0R6vhKYYKjVFTAJtUqCPRcSjPF3YabOKo97dOCae/wtsjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0IQPYDDHu3jt+U4rEPg9YzNj/aBL+MyWi9LpZI4khpU=;
 b=XnsCc7B2M3Y/HiZi6f6dUd+fmIEioeYcJYOaRTFfjpKwTdpjTayGhtQVjEJnfoCwAkddR8rbGRQDMxGMckjpJXFKP4v/6KLbvhiSYT+GGHjfy0PDe0pNs2UrsbGvn7m57qB5p7SS1vNnJ00N5TatldJoG6kO2RQI4mIasD7SCPNQGgDSAG55JqNvEUs3O6HOLePpdG/ZbOs4AcuF6UdwYVMtMx3C23dkzeCcPBpEthR2Z9zY4T6FIMRcQpxlIuUO+RmZx+U/pKmaaBKaq7lzMI2u+Yh27TC38CfHGTwUX5edRgnEQU2M7ZhHJOOxcfYQd8NNdyqsmdJNdrPTzO6U2A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:253::10)
 by LO2P265MB4792.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:232::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4587.18; Fri, 8 Oct
 2021 00:00:00 +0000
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89]) by LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89%5]) with mapi id 15.20.4587.020; Fri, 8 Oct 2021
 00:00:00 +0000
Date: Fri, 8 Oct 2021 00:59:58 +0100
From: Gary Guo <gary@garyguo.net>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco Elver
 <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, rust-for-linux
 <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211008005958.0000125d@garyguo.net>
In-Reply-To: <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
	<YV8A5iQczHApZlD6@boqun-archlinux>
	<CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
	<CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
	<20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
	<20211007224247.000073c5@garyguo.net>
	<20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
	<20211008000601.00000ba1@garyguo.net>
	<20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; i686-w64-mingw32)
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0156.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:188::17) To LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:253::10)
MIME-Version: 1.0
Received: from localhost (2001:470:6972:501:7558:fc3c:561c:bc74) by LO4P123CA0156.GBRP123.PROD.OUTLOOK.COM (2603:10a6:600:188::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4566.17 via Frontend Transport; Thu, 7 Oct 2021 23:59:59 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: c1839974-7d38-424b-c060-08d989ee923f
X-MS-TrafficTypeDiagnostic: LO2P265MB4792:
X-Microsoft-Antispam-PRVS: <LO2P265MB4792A79B5488728708914F6BD6B29@LO2P265MB4792.GBRP265.PROD.OUTLOOK.COM>
X-MS-Oob-TLC-OOBClassifiers: OLM:8882;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 24iJIVZM3PAhSFmvk5A0eoCXgSrEx6R2NHnjSn6/krc72UaxdCn/W/lCkmGhARyevcexDAEK7Cgd1CRAXm9tLa1ZcrFBh+UotPw+zmdXZQvesJ3O8LNRqFIHlC4tngad4R92oHxsArBTJ/+gm26c+UAaghhwNlm33tK4IfAfz6/v/eSLmwg+VoxHDv4BVtAkbe+NhU2RCPTZTB57NOYy55qCN+GcGfncn6abPA89x2cHBws4iZtI3u/NkyWdP8jH/yMz97ZG4TZuUzz7BBWIDsQcaDRlZ5FD1qsfzyCw8KKzaPMTmp6KvZlS9bAmLf4cUzxE5kIO9rAvPtjNg3tPivdd0OahBW0UvsekHC/fYRtRuaRtCAers4GvhbyBhHkrHb0WwV+KotgVbV1m9jQgcaEadbbsE6mj5uyh1Fzc89WsJHuCjGivl4TRnCxhlAMVHvP9Uq2k45JUyjT2jKjOaLi2JZchz9mRUDS13ars8PWHRVVWHTLD/TeFCQl3zYT+l3hViMc4pCNTfXxqL9U9rqGVekW03JMpwYvbVXwnRErzfDvoiRgygPtnb/B3caj/zCoJnQB2jSiviHeEeTAEeTGr1ztAZDhMm3h4ygpComsYXGFd+Kx2Qgdsb+xfhfnCkCNufAlIvByMNfT0ad+F2rUSx5a+od0rvagnxrbyAU3yyb0ZSlVgH4vYw5wzhuInY/xw64AbiBgHw3X67UmGvpZYNKrrnDQUm1l1yigqY+0=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(39830400003)(376002)(366004)(136003)(346002)(396003)(8936002)(316002)(8676002)(54906003)(38100700002)(2906002)(508600001)(1076003)(6916009)(6496006)(52116002)(2616005)(66946007)(5660300002)(83380400001)(6486002)(186003)(4326008)(36756003)(86362001)(66476007)(66556008);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5H45tDJnwKXCTz5oq8LjglgSCqAITdXj52ZFvp+OyDAl3cV8g5fdJvNVIgHo?=
 =?us-ascii?Q?sPc8znAod87NzvBpANv666Q+cJyQbW0Gy9iCOFe5Fs6bbtO1U2WWZoxwFOGE?=
 =?us-ascii?Q?440d9pPN8+pzImgso8/5Tbpw7K6asgOGbmn6owBrB/RXHWl/GuvGLDy+baGe?=
 =?us-ascii?Q?f+aX+Qohpfg3TfLwy0lNsXWhDZgqZpr043b7EULQ27E5aNRvDcs/YCj6DC6+?=
 =?us-ascii?Q?FFrlem4jSDiK6FOlxS5Ux8DHTtouUaQEHyOzExNUZv27ZWMcVTV6q6wc0s0b?=
 =?us-ascii?Q?I1Q5wq2vj6ozAO+R1h1rsW1qRNj5BPDkUt3MJe7rh0IVrCx6B+LPu1VqimwD?=
 =?us-ascii?Q?rR+94bpmLY3H8ToKDYScMj6OfUXLwVMLvT3zH31+c3jxHUdDq+zOn0N+Nca/?=
 =?us-ascii?Q?Ey8NuaRgp1REjN+QQoHc1Rm6En+dHXs8g1wZl+ZNwDaIZZlTTVI2nuGJlJga?=
 =?us-ascii?Q?i6PvAh11LDYO5S4Yei4pbRjMQSyIafKNjti+lYnct4L5X5p09WLeiY8BhMQ3?=
 =?us-ascii?Q?3oo2uil6lN1Wc8LdGNefRpiGCQM0qaiDP+FnbwW+FIHoUt5RyGTr7trql9Li?=
 =?us-ascii?Q?9r8yTmIi1A5d/+5oAiST7zfMVkY1Ct0fiVXIqgQoDISzTpz0faeJfPn0iNjM?=
 =?us-ascii?Q?df+vGPaCWrBkRdnOkZGSt1nPryag2GKs17+djzjVjZi6TLenYm6zQ9cu68pk?=
 =?us-ascii?Q?cBsQkWtkL5c3YeJPlpAQHtBJN9ah/qxOnwuSdUbhAsJd6Iy+h7T2JB6tehbz?=
 =?us-ascii?Q?ZP7nA3VF5eirywVPwzBm0J8lfl7l0OXRVZeT7y6NvWvV/wr5IWWZhZJa4eLg?=
 =?us-ascii?Q?BPqsB/EdumKlEfDunzgP9UKhovX7YngT2Wjb7FVWSlDHzbRACQN+5tSere18?=
 =?us-ascii?Q?GMH9jOE0/0inTcMDiJ+dKxB53anFa14HfNi533/L6a8f2K7NSmU3IV/Guz4Z?=
 =?us-ascii?Q?DeQZ19JzOkUCuw36JWslweFWJV8ILlbRVfUNEDKct0kE2gM9jrEVjynvJHdb?=
 =?us-ascii?Q?MN8ifasxzltCsKzu2EEVDyH4h3/sSDsj4eOJgKWA16NGlayobycITxk5F1xN?=
 =?us-ascii?Q?WP69Vln63ZlGCKQgYkSbTMLAF719pHpJAF0fl4kgJAHLNq4NpdEzrF+9SIxB?=
 =?us-ascii?Q?xHv730uyDUVTgXS/P0FsZ1T+suX/YboOh96OoUOLWbLUZ3eKlpZxF97j+RvI?=
 =?us-ascii?Q?7+TluBYRVLyTt2i2KBxkrPWxUPDHJcDzZX4vxleRGbh7tlkVIkYxKhq+LYPN?=
 =?us-ascii?Q?tk37I3QFVYODijMKukivyLPpRETDu/+fNmYqpKhtGxtQZE5RcEJlEYl7R8dc?=
 =?us-ascii?Q?npG9HcSSmPmBdHCKj71nlqI/zhWqZjxyM1JZXGy2K2j6o8qoyGWd46Cbve7f?=
 =?us-ascii?Q?ULjKxPhKlO+5RqAajv6tD3jD8ogN?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: c1839974-7d38-424b-c060-08d989ee923f
X-MS-Exchange-CrossTenant-AuthSource: LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Oct 2021 23:59:59.9564
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: gX5/+3VuLNNSMec1hOKenkQpWU23LpHtrNnCrowbG/dh6zLiYglCWbK76vW3L6EzuZ7VNHRhEo2/ilqEXSvQwg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO2P265MB4792
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=Ard5ZRx7;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 40.107.10.132 as permitted sender) smtp.mailfrom=gary@garyguo.net
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

On Thu, 7 Oct 2021 16:42:47 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> > I don't see why LTO is significant in the argument. Doing LTO or not
> > wouldn't change the number of bugs. It could make a bug more or less
> > visible, but buggy code remains buggy and bug-free code remains
> > bug-free.
> > 
> > If I have expose a safe `invoke_ub` function in a translation unit
> > that internally causes UB using unsafe code, and have another
> > all-safe-code crate calling it, then the whole program has UB
> > regardless LTO is enabled or not.  
> 
> Here is the problem we face.  The least buggy project I know of was a
> single-threaded safety-critical project that was subjected to
> stringent code-style constraints and heavy-duty formal verification.
> There was also a testing phase at the end of the validation process,
> but any failure detected by the test was considered to be a critical
> bug not only against the software under test, but also against the
> formal verification phase.
> 
> The results were impressive, coming in at about 0.04 bugs per thousand
> lines of code (KLoC), that is, about one bug per 25,000 lines of code.
> 
> But that is still way more than zero bugs.  And I seriously doubt that
> Rust will be anywhere near this level.
> 
> A more typical bug rate is about 1-3 bugs per KLoC.
> 
> Suppose Rust geometrically splits the difference between the better
> end of typical experience (1 bug per KLoC) and that safety-critical
> project (again, 0.04 bugs per KLoC), that is to say 0.2 bugs per KLoC.
> (The arithmetic mean would give 0.52 bugs per KLoC, so I am being
> Rust-optimistic here.)
> 
> In a project the size of the Linux kernel, that still works out to
> some thousands of bugs.
> 
> So in the context of the Linux kernel, the propagation of bugs will
> still be important, even if the entire kernel were to be converted to
> Rust.

There is a distinction between what is considered safe in Rust and what
is considered safe in safety-critical systems. Miguel's LPC talk
(https://youtu.be/ORwYx5_zmZo?t=1749) summarizes this really well. A
large Rust program would no doubt contain bugs, but it is quite
possible that it's UB-free.

I should probably say that doing LTO or not wouldn't make a UB-free
program exhibit UB (assuming LLVM doesn't introduce any during LTO).

- Gary

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211008005958.0000125d%40garyguo.net.
