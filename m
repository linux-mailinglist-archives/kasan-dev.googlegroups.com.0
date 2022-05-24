Return-Path: <kasan-dev+bncBCWJVL6L2QLBBMEZWGKAMGQET4O57CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 67A5E532179
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 05:10:41 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id z14-20020a056512308e00b004786d7fde66sf2373803lfd.18
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 20:10:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1653361841; cv=pass;
        d=google.com; s=arc-20160816;
        b=kX/8t3kiQDHp2GJ3h2MofNxt6JlWIaSfx6KXDzMlfzLk3eGOOIEpN0wHBmTUMT2cQt
         zxeohcLYKeQdZFNflB00PYhdM8NnnJUpCAIZkDUv8gocpklXOSN0Lme8XPiQWgWmGQjT
         BjYhqE7RJGDi+VZcxlpwOFkU545ijWnTIjjI1BkJtSLwn2OGCBfnJOX6YuL2YYG/uJzc
         W9t0ELaXVmuqwuiHLQnCfhePDy94fJvuxqTjLymts3sg99HgawnudqqyZ6lv1Qoeu7X3
         pSewprXQ054oW9DkiG5DAxZ4drHLWXYGXZfRq9q5rXfwEWNmE0kM99SttRjM0u4QOqgt
         owxw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=re1mdp4lV4VVTauGUitgEUGK1h2BINv4dlbjvee1rII=;
        b=nvghARiMXCQjavYWTnJQvjUtIAR4zVhV5/MMr2D8zwU/T7Aaz556SiKD+CcKYJSP9Y
         Peo8QdHtPb1LoKBDxiCDEiHQByripUmMeM8K4E4CrBa7qTkB7Kl1q2+Rv/gkSTK1f6FV
         TTo6bkclM6hmgK4o9SZ71RNDhlSBP3rJsljDThQr0p/OaOZP21uXqwyNm89FlmtNZZ6W
         A1je/Jeeo2Zby9qONpXhy8Z3Y4gVNSNb5UhCsSv4C93fGwoVGAnGaWtxyU2iDzlmdQHi
         bKrxb3/XNZWlRKPIwymfWAw44mRI63CKy/r0qDtOCElyMK/Jx0DlQZfpnHn4qpWjrDcn
         1Q2Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=fMvcC0Ka;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::706 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :suggested_attachment_session_id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=re1mdp4lV4VVTauGUitgEUGK1h2BINv4dlbjvee1rII=;
        b=Am2YrJrUKo1gbg7lmicFA2Oe64ALCvQj+XNtcfc3hvkIox3D3/HcIyuXdEndChMhOR
         wv17QJa6A9O25ngC3CY/mhSP4KLaVe8DoPa97yUBEsZ2OLiOOdJh3jAzZAb56/XUNUrc
         oRgvIuhp8je74h2+IjM3mCey/S2Hd6e5oN96uCQvR8o7Aj+39pLOMWc9CWd2yni9QSxK
         f1MoZPcNBXqven/2GimDZv25ZGOVoJy1URiwbHZuvNhtfV/inYJVL6mvRL3toQGa8oo0
         F9zmDpYw03jYmNsyv0kqukI4kih3yuA7i5NqrNNWEiZyMmF9ql3uN66o5e37fES46b6d
         1agQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:suggested_attachment_session_id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=re1mdp4lV4VVTauGUitgEUGK1h2BINv4dlbjvee1rII=;
        b=cyaEmMaD/EmKCpYKM0PnHVSy2RIe42iV1FMTzF4J87KG/gEz12CjH9jsJx+HLg9bNB
         tlDScA4DmaCdGyjZ/AnRepzdILSA4wvojc65oDCa3nEQ4qVUHSDKmlVKeE2gnxEdikFU
         iyld2hlAoywHqjUPjgPIa5sLF+vgR+wmE98gTdT/3TA06w8FSZU//OV30/F1WqyGnPOt
         RAghntXqU8huS3s0BVD+gGmxCk8pwkyFddG9dYiCOnJbcDwSvG5zFs5ntQ5NOUls/yI6
         z78Vo9OpWMGg2eiBo0B/bKMFXbryR0IIJCP++6pLnipbemORVud971mIX8pP7CiVevDP
         wOcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yID3LtKLOloLa7RdPcvhxL0mxBgW2zs5m81kDTXgjvRmhbHBk
	LQcSSpq4Vlr0xJU77RSOdis=
X-Google-Smtp-Source: ABdhPJzCUeDbXza+lc6ZoWBhIyEM2Qa5Vk4Yuv0x4Cf2Lc6KC5wwiU/NeXk+FtqP8ga32oapFMD6jA==
X-Received: by 2002:ac2:5a07:0:b0:478:8433:30c1 with SMTP id q7-20020ac25a07000000b00478843330c1mr2022512lfn.377.1653361840824;
        Mon, 23 May 2022 20:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1603:b0:253:9ae0:be3b with SMTP id
 f3-20020a05651c160300b002539ae0be3bls2563054ljq.10.gmail; Mon, 23 May 2022
 20:10:39 -0700 (PDT)
X-Received: by 2002:a2e:a3d8:0:b0:253:e5ed:8d6b with SMTP id w24-20020a2ea3d8000000b00253e5ed8d6bmr6975024lje.438.1653361839716;
        Mon, 23 May 2022 20:10:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653361839; cv=pass;
        d=google.com; s=arc-20160816;
        b=bExvqhfBANTyjoXV3ZaxoXuIYYFaPWFI+dxtsyXefPfCNUn3bc37Rm66plIHIVNVRA
         wREz+ysYQRhFqzAMtmn1vvmXWK36k1V3r6l8APhPj0AcI3xLmEE5HabdEHc58cVQPeI6
         pBioGY8Ljjs5Cs7oCkMoSXAYuYJabm4AxL5I3j7v0QxvSNIcVAl5R89/h+gccvj7Lxeu
         5SNyxL+PvqRdWLT0WNzJFCPzh2iZVsNxWxGcoVy8zg1hxv63FkEP3v0cHr3W4UY/rL3e
         gSuiRezCFwn5rESc4Nu8r3HSwEC+635IS3VN4l5FpDS54CZVFm2TLzktBljV4d9e6OOk
         UvJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=Vj7bL6AP1PWyEUXKIktvcMSfTddRQqYiL/oOYGLTxsE=;
        b=J26CEdcLg+hnVd0dbiWT4K6QEPcSQnm+/Uw69rpCkCSZ+rSbLUSXsq8jF6iUMmZfHt
         Hg4syHQs14ROvLC9mIrdo0keJYuFV06dSPnE+jGEnIrAyYElGlytvQASdjTD4nmLmrtQ
         Nf4a8s/C1AvGzoc8t5zD/MH1HVmQESDb0f+ZlooN7HudhKlWId3tv2PglO5lhjiEuBl0
         01Of6ce+y1Mtw1QRFD/VM/qjDcPg+NfBGv96r8/aBqqVJmjKB4fnzxEd41blxQC2npLE
         W4XtzhtEp/m9ROSZN+Y2fMoQNsndGggsKQsOnVC1r5wJrVTB4+B3Q+1fmFF4f/1abjnM
         RZPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=fMvcC0Ka;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::706 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (mail-dm3nam07on20706.outbound.protection.outlook.com. [2a01:111:f400:7e83::706])
        by gmr-mx.google.com with ESMTPS id p8-20020a2e9ac8000000b0024c7f087105si483886ljj.8.2022.05.23.20.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 May 2022 20:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::706 as permitted sender) client-ip=2a01:111:f400:7e83::706;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aTN/kBHn45rZ283IWMrT+ANXZIevdP8wsTLwihPie0sQXz3PMa9JwmpiQhGZRaft7i2b1NCKAgdml7XltTHv4gMxaClzvcZ1s45SO6cAPObOoxeYr33C2W+Slh5qa8ALUNwAqXTA/5ceooyhBsrSe/00Ogi9I1N1pKnmlGu6Rbm+4lE0kdawPmxDZqutFh6qglimvYUFzdP7xHnr2kuRXKZ/AsVT6bvijuhuBcsSnJ3xaMvDQQs5Ab7SXIe9JIBPjPLB9OkkI0nNIBJQKhk0u02YVoqAwVRYuDYfqTrRobDHLR5lGshC4VvejMsePvIt0sG02xF+qqWZKaJFQypRUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Vj7bL6AP1PWyEUXKIktvcMSfTddRQqYiL/oOYGLTxsE=;
 b=REm1O6GDPOgSEKyiyYa99DeAa7c7jlAkS4ZGiGjmnJiMo0V50LsUC4VwEJa1mDGLlLl40usKJfs2T9GYqSZ0ZK2FSF5NuXmCiWhWBwpznPCMgMHWPHs/5v8WBe1imVeb1vdFCZCJ2bDPVPindlN85cTi4oosBbbTCvkkxpiV9IMzkWQrDjU4A+VYDKDCrp1v82M8MaL4oe7P6LVXoEhl/3EeCd2GtK0oVwfzyVT8RDIrYFi/2Z5XESjgje+g/0NxujEPCmQkinDc3SZTZZFCfQnOTzgolhw2Z8eXWgFOZDQvf4U3zfL71GeNbePJd4hCzkPBa/z6Ow2Iw1eOBFEMNw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=purdue.edu; dmarc=pass action=none header.from=purdue.edu;
 dkim=pass header.d=purdue.edu; arc=none
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 (2603:10b6:301:33::18) by BYAPR22MB2375.namprd22.prod.outlook.com
 (2603:10b6:a02:c1::23) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5273.23; Tue, 24 May
 2022 03:10:37 +0000
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa]) by MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa%3]) with mapi id 15.20.5273.023; Tue, 24 May 2022
 03:10:37 +0000
From: "Liu, Congyu" <liu3101@purdue.edu>
To: Dmitry Vyukov <dvyukov@google.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function
Thread-Topic: [PATCH v2] kcov: update pos before writing pc in trace function
Thread-Index: AQHYbmb5ybW7rPmroUCLD053biTbk60sJDKAgAEv7peAAAZIxA==
Date: Tue, 24 May 2022 03:10:37 +0000
Message-ID: <MWHPR2201MB10723DDEE1492EA0BB6AEE8CD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
References: <20220523053531.1572793-1-liu3101@purdue.edu>
 <CACT4Y+Y9bx0Yrn=kntwcRwdrZh+O7xMKvPWgg=aMjyXb9P4dLw@mail.gmail.com>
 <MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
In-Reply-To: <MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
Accept-Language: en-US, zh-CN
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
suggested_attachment_session_id: 97fb9dcb-d055-7325-928e-eb7bd94ddc9c
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 00d8d8e5-ee7b-4817-0058-08da3d32f9a1
x-ms-traffictypediagnostic: BYAPR22MB2375:EE_
x-microsoft-antispam-prvs: <BYAPR22MB23754928B9A2354A971E0CCCD0D79@BYAPR22MB2375.namprd22.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 4p2zDJ2Z1uANXRQ/ZSi0a0OHCegO8g11E8M0+ID8pjlR1Kc2xDlT70MNqx71iArjBD6NqyY+pnDBwWEpv2O415TVkGrfEWB/cchE91zt+CWsdbe2nVJFZDrBosMX8S2hJ/d332oFEzYj8IemLeY2WLNKJ8MjLtRCtd2jUqukSptZQM+vLaLvtWXVYpBB9lwPe02qhmgBan0iVB0Gxw8nj5AEIvpxbeiLs1RgSv+4WBkhsjPt9zHge7NQnpFUEnObP5NB3oL19UGadzR7LkpzrAbgkdz9LCns1rA2fxf4CEJXtoovIkH4XhYIAijFFBA3W5aseuzZqSUHlusgWlTwzyfszwTuPFgI93nI1d6q4fkC1FbuNI9EiQfn7oDftasaOjIyZ97TAKRTpm7PhEDpBbCJhZL0g8IJxsCdxtxyz81nN0LN+1H0VmUGYDfQX50fYdqA9/1UKX+XbT92BzdxjWUNTwVlcP22sMuD7UQQWzWX6ycJn5hBIDhiWhFXrzyksS63IdGHKZdfM+TJuXmV2l8t2IQLMihdetLsO9NRcR2PQBKW7vfEz5uziJp/rklXi1DZKKfsPCzAFdi8vKGNI0WQnOyjJD24Qzc+ZoOJ8MMWflO2vwaoDXRlVVzKeTWxBXhCFVzl90JoxGnnDvNhnqoKr4SUJ34KK3HHla3RgAh6obs6j1D91iYBqfpnLjOVmii7YOhOkPEsymb1Tej8BaFvUKfKK6UfDmm2OldFBTsvOU3Tv9meGuHwh08bdhzc4nuvpRnJ89rgl1k47rQB0bECf9hbZWK8zKtu/T0uH1M=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MWHPR2201MB1072.namprd22.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(966005)(52536014)(8936002)(55016003)(2940100002)(83380400001)(186003)(5660300002)(6506007)(7696005)(53546011)(66476007)(64756008)(86362001)(26005)(15650500001)(9686003)(33656002)(66556008)(2906002)(508600001)(6916009)(8676002)(54906003)(38100700002)(316002)(786003)(122000001)(66946007)(66446008)(76116006)(38070700005)(4326008)(75432002)(91956017)(71200400001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?Ojpk4XugF7WdlAYKdidJBr1bABZAR4e+0iy5IxTvHrAq3AGdYhh17X6N5/Kp?=
 =?us-ascii?Q?UtN383bdKkawfZeOKCIsffQknpaTY8C2xwe7SjLfuqSXjrIXw5NdUYMzeIDj?=
 =?us-ascii?Q?sRVYwp3WMBhEbgaE2ZWkUwXuU50tlLS6vxa2lKw3XGWl6TnlqitBbyXEueoA?=
 =?us-ascii?Q?/ZUrxqbUBTwiAWVwYU73GdLBOB3O7fj4gkUMovDiguICd58KfbybOxYYiJfq?=
 =?us-ascii?Q?S+HB7c0lDJVUUDUDrDqcgoOfYz5L/1eTDqjfC3bW0+g0yBmCBQJv/lu0gJoy?=
 =?us-ascii?Q?onygDqEUb4aqySq21nciHfpW80st/Tv2tZid2sO8bNSdwIOfnuYWKBEcEqOp?=
 =?us-ascii?Q?JutZw8e5TwBNlTp9tU6NIN1slTBHnEPSKbQUKQqtSylTR2nIUKf1KiFpVWYh?=
 =?us-ascii?Q?PqHKThljMh35+0a1Pprov9BepqzD1vO9LUnV3lDIbkVFzMataXC4WADK+KnO?=
 =?us-ascii?Q?pP2Gl57+HthX7CLnGxAzKn3f/bLpyp1l0icnUexo9S579DdIkObirAVNr/Yc?=
 =?us-ascii?Q?SDHoBZjFCx4p7ltrJfi2roiDoIv7APdi4VJsp0M4SCedt9nYmlFa1hGJkuZJ?=
 =?us-ascii?Q?VxstO2exAVPfMNSE/iy3WPGaqQSDi7u834Wf2A0NLP4oK5OiSQxnIldC4E0O?=
 =?us-ascii?Q?MagzHgGk7YnUvk+hE1e3hIRSCKKUL8fUsohlzL2uOVvQQa/ezFvDwCoM21jJ?=
 =?us-ascii?Q?ebGLxcXeH8V9BMWVQFWTIV5MDgObfEArNvUdblh2zEGe9ntl5se4rsA7k6ei?=
 =?us-ascii?Q?Cn9NyafUBQdoaR1myuQUtB3wkWvt4v/GOtTvzMSq4hJovZNCv0Fy910e3MHQ?=
 =?us-ascii?Q?2KFYP5PeJ27NGYsykJ5uYknq9hkdo5jsCsi0YU4OVoqvcs0nMEWig3iC4YQE?=
 =?us-ascii?Q?2OCk23DeU7+kOFvAg1wNWZ70ERDwC/aHFkG6oQJRIe5hw8ATiujlbfQUdehO?=
 =?us-ascii?Q?kaFZMBAL5EBYDHVGadLddOU5loruJTz87CBQ+cskw3rICiRWKlc4pVmtHRdU?=
 =?us-ascii?Q?gnfXBqvFnks3w7U7/NkPfJrAGnMEyG5ds19B3uoEbkagfXaORPD8FiYJrRs1?=
 =?us-ascii?Q?TPcoFNaH3Jm307Hq45mhysZto6YvHxJkgSDGVgAX8wSjQDDWuaAr81dSc8ZL?=
 =?us-ascii?Q?rkGLNowyIJ3N3PWGwrGV60WwCSMaQ7YIehCXpZYpjqP3ZQsE8HuQOGXuRt/g?=
 =?us-ascii?Q?q8miYqUWs6yt7V2wqmTTFXMill/vAI8rtA0nC+evHC4groTpCmOfmYssKapL?=
 =?us-ascii?Q?PcPMVRtfbL/WbRig22qj/+if+Y8ZNQdIS5o7K03QoF+oZL+OGk4CuNgA01oW?=
 =?us-ascii?Q?fCkwdBK2L/eOtHZycYzvYyq6F1Xz/Wh55Q4hi5JcN6KJi8AHlg9BrLmtNGnk?=
 =?us-ascii?Q?j+VwIFlDu0RmahOR2ByQpkxL4C7/CeNmvncELHeyY1wHJfWvLRT8OnQtiIbJ?=
 =?us-ascii?Q?SV1ZsAdYkpNUD1qxGQcVa1GLYwQLs+ZtHrNFBn0k0JjakXrAlneroJBDBCgp?=
 =?us-ascii?Q?HuFuIlne6Fe491RPhoFFHt3N2+l15XGQGHObzXkbbXKn6MLlZuDzfCFvN3Nj?=
 =?us-ascii?Q?tJpe4RLvf9si2gMMZYImVNrxgMTTI9IerdUcDsOvW8Wx8oma/8dvtFqTh+sC?=
 =?us-ascii?Q?+IjjAZD9E4AfWIQITd3hifv4e99GfmQGKfB15JAoDIH/eBEopW3Ynz8257bu?=
 =?us-ascii?Q?KBvNEsMnBKcFLKaqj/XPlgliFlIZwHZpgWpJoFDMKo62ZXNjnnvvo/CMJw5W?=
 =?us-ascii?Q?P79QvxmMXA=3D=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: purdue.edu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MWHPR2201MB1072.namprd22.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 00d8d8e5-ee7b-4817-0058-08da3d32f9a1
X-MS-Exchange-CrossTenant-originalarrivaltime: 24 May 2022 03:10:37.1771
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4130bd39-7c53-419c-b1e5-8758d6d63f21
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: wFPgrzgXBZWrlAI0AEzWN9X9mmH5zvc93/nyw4oJgsl4NhGhkFjzC46p7oqZv33J7mwVWYCclLUZJlNhxgLX9A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR22MB2375
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com
 header.b=fMvcC0Ka;       arc=pass (i=1 spf=pass spfdomain=purdue.edu
 dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates
 2a01:111:f400:7e83::706 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
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

+Andrew Morton

________________________________________
From: Liu, Congyu <liu3101@purdue.edu>
Sent: Monday, May 23, 2022 23:08
To: Dmitry Vyukov
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function

It was actually first found in the kernel trace module I wrote for my research
project. For each call instruction I instrumented one trace function before it
and one trace function after it, then expected traces generated from
them would match since I only instrumented calls that return. But it turns
out that it didn't match from time to time in a non-deterministic manner.
Eventually I figured out it was actually caused by the overwritten issue
from interrupt. I then referred to kcov for a solution but it also suffered from
the same issue...so here's this patch :).

________________________________________
From: Dmitry Vyukov <dvyukov@google.com>
Sent: Monday, May 23, 2022 4:38
To: Liu, Congyu
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function

On Mon, 23 May 2022 at 07:35, Congyu Liu <liu3101@purdue.edu> wrote:
>
> In __sanitizer_cov_trace_pc(), previously we write pc before updating pos.
> However, some early interrupt code could bypass check_kcov_mode()
> check and invoke __sanitizer_cov_trace_pc(). If such interrupt is raised
> between writing pc and updating pos, the pc could be overitten by the
> recursive __sanitizer_cov_trace_pc().
>
> As suggested by Dmitry, we cold update pos before writing pc to avoid
> such interleaving.
>
> Apply the same change to write_comp_data().
>
> Signed-off-by: Congyu Liu <liu3101@purdue.edu>

This version looks good to me.
I wonder how you encountered this? Do you mind sharing a bit about
what you are doing with kcov?

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks

> ---
> PATCH v2:
> * Update pos before writing pc as suggested by Dmitry.
>
> PATCH v1:
> https://lore.kernel.org/lkml/20220517210532.1506591-1-liu3101@purdue.edu/
> ---
>  kernel/kcov.c | 14 ++++++++++++--
>  1 file changed, 12 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index b3732b210593..e19c84b02452 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -204,8 +204,16 @@ void notrace __sanitizer_cov_trace_pc(void)
>         /* The first 64-bit word is the number of subsequent PCs. */
>         pos = READ_ONCE(area[0]) + 1;
>         if (likely(pos < t->kcov_size)) {
> -               area[pos] = ip;
> +               /* Previously we write pc before updating pos. However, some
> +                * early interrupt code could bypass check_kcov_mode() check
> +                * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> +                * raised between writing pc and updating pos, the pc could be
> +                * overitten by the recursive __sanitizer_cov_trace_pc().
> +                * Update pos before writing pc to avoid such interleaving.
> +                */
>                 WRITE_ONCE(area[0], pos);
> +               barrier();
> +               area[pos] = ip;
>         }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> @@ -236,11 +244,13 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
> +               /* See comment in __sanitizer_cov_trace_pc(). */
> +               WRITE_ONCE(area[0], count + 1);
> +               barrier();
>                 area[start_index] = type;
>                 area[start_index + 1] = arg1;
>                 area[start_index + 2] = arg2;
>                 area[start_index + 3] = ip;
> -               WRITE_ONCE(area[0], count + 1);
>         }
>  }
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/MWHPR2201MB10723DDEE1492EA0BB6AEE8CD0D79%40MWHPR2201MB1072.namprd22.prod.outlook.com.
