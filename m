Return-Path: <kasan-dev+bncBCWJVL6L2QLBBOMYWGKAMGQEO7BVQJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 41981532174
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 05:08:42 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id bi27-20020a0565120e9b00b004786caccc7dsf2486804lfb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 20:08:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1653361721; cv=pass;
        d=google.com; s=arc-20160816;
        b=vp6UGmCFlKlEhSDEOmIJBB46NW561JB3uXNbFDaYLkbhXGoKRQ/scJAX4ZA0Cpi40T
         C0O1ZKKtWRuVqvdAgg1bN41VKCaVzl6IK2SbhqvqXQShp4RmevVd/jAuufvHZBbIJ52I
         rqboYmVjdWMNbG3mMK8imbGu/V6Xgf7EzXEAhL089VHMq5vkhxJJcDPz1FZJg2pulRZB
         9tZkc1824CUozKSCO1nsTMQkBMCCnyeBdj2ZLB9N61B0qTftpL+F9nonOoyPslUUzZj7
         uQlLDe6M2/nwPB38iHq7v1bhXvdMJni262odGK5qm44B9PyYBIpH12bA5lajQR9vnbVF
         CyXw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=fSy5w8DUIS9geO72DoPTEIrCty2tdSxggHGLXB8VMLs=;
        b=ZDRbTMnmauia4Zv67OjcGKgXeJ7Mup4ytN+8ewoR5WaXxrTGaibvghc+Fa1HjHbYaD
         vIJR6O6G33DlnMnZIEXp2oX0pbfTdGZL5gdDFwMx3e7sQK5OvZ/xpHlZ17ixHN8lBvFx
         qKpTUwjbu1i/VoLgM0lmFVcFZs/pfrxD54qotqjfNvr3HJuntZrRyUuVsDND8svRDtLL
         PvF58qHr8QNdctC7iRrDC6Ri0uXsY7+GR9VLq+DPrSyT0nK7nCej6D8atCa8Ct3H3mgV
         ah0ZvKHJ/O0SWPvOdwvBA4DcfUpL/GoeNnAwOb1NqhYKUN/4pbIFywWodMK5JkWCm+uk
         VpkA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=VHlmX95K;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::718 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :suggested_attachment_session_id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fSy5w8DUIS9geO72DoPTEIrCty2tdSxggHGLXB8VMLs=;
        b=TkWAcEFNmmbyMMUFJF+u/UPXjRpWHxezbkcZDKjxwj5IVz0IX6HvB8I9k7Iow0ZpSB
         jj3Ya1NN549gjqJ0AqnEIvlhUlkTDktSM4I138eWleD66UvkJXUlQqO80e+TSBVAgZZ0
         zC/s70BUQ8VTAlNj0O/hKVOoOj6w5bvkQHc3ObBxB8G8Ax3Y59hsnGxWqIQCOzfRFVYg
         HUqEzqbXGEEK/Mt1a/4zj2N4pGGWik3kqmzaAldoPRpVwfEuszH21SUOX5lHxsz60dQU
         UDRKzy99UKMF+4Bxvqu2UErTxUOWEWKKd3Up2KyST+OrqOQz2R/fo4kJVxpqrs96nBgR
         amaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:suggested_attachment_session_id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fSy5w8DUIS9geO72DoPTEIrCty2tdSxggHGLXB8VMLs=;
        b=z/PK5yhVa7badXdwIM19rvHHxH+fUIaw5I5vN3hbmaah0btfLWTFeAFuA16Zd5QfBr
         QOXyf0TpNkxcZMRIVOspnTRSqF6YO8rQ9Hz3u3CB4e0HD2ujIT5D5pX6hEfNQBrCFXHb
         Uh0yUZTHWvkXsE9FZx7a7vul2BckUikJcjp5RnRJohGS28c0K/aB2J82IgaUrmM/q8vr
         Ikc8BoBQtv6lNpIBP2sNCizTwF7HwJhzw2+JzcmLnDYL1WK3WW+5FqCSpHqoZUGJE+yZ
         8gcTLVd9DiOiioHj/y6MmUqqzk3ei9oEIPngKf74OY7hVa1EbnY4pI7F+w6L2uk4AoGB
         B3XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eeXPgF4WPc1Oy34MKA7qh2EDScJ6f/7iQ3m4983WV5or+4aoE
	sbyYGJjCkb8hRrg015VQYjg=
X-Google-Smtp-Source: ABdhPJxctYTelvj4rurOz+vICgfZLfDqKcyCQETMxgiyHTN1RZO6M+IrZgv5x5QUVETkuk0SK4+AZA==
X-Received: by 2002:a05:651c:98d:b0:250:976b:4a0e with SMTP id b13-20020a05651c098d00b00250976b4a0emr14599028ljq.494.1653361721647;
        Mon, 23 May 2022 20:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls178657lfu.0.gmail; Mon, 23 May 2022
 20:08:40 -0700 (PDT)
X-Received: by 2002:a05:6512:2526:b0:478:62b7:3591 with SMTP id be38-20020a056512252600b0047862b73591mr9104121lfb.472.1653361720456;
        Mon, 23 May 2022 20:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653361720; cv=pass;
        d=google.com; s=arc-20160816;
        b=uzxu85VeJM5TBtnts35KMCHLIRkWRFDyJNRC14RJekFtiXzqulUW2v0QG5+353Tu3b
         siMkg0Z5UryH1M4jCH6HAmQb5EYQ047a9bZTgy2Yud7lxa8HkJxefWFITJ15LE3oOSMi
         8p2dnVarYyheyAS/aQPSWTdJ3A3FPw9987YFtpkNdDpSe6tx3H2vnUiCcigwr+kIM0MM
         5orDR9l5zMDgBNq20Le1V9X+QKIQj0WFnfTUvMwJ4Z9aLtgZzclpc/23HV6peeSchQyf
         R3F6yCxGG7/qqpDU9Cti/c/PsrBuRAk8/1VeHOQj4b11X5n+aHQqO50WVmcwdz0UIm/9
         Xwtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=kSBBU8wtFL5CoRnOO+r66WKfxM3/Gso/TM0pC0uVE/w=;
        b=ORr9BRNIOjnqyZ5o6lJ3HblhlQPwp8xpv2Cg9cIPaepUyTcBSFTovhcipXLpowuL5e
         SjOd7s4I7bqQMZZAzJuyvAztF1RI9avccn9gM8qep8l3jThBqKI7OGLhcHB3WKrhNh5i
         mJtqjJyEqoAAIU9nN9ATDnPl9AjNEoMuhWSI+T+z2su4cenoJTuCObVjpPi6XUhdVvC+
         Qv4ZPpx2189qN9nh+10K+2c31iNEUyzPF3+JuAOuuEWl58CbI4Dbf9Qk9GzB93j/LGn5
         WEys7dvArVxQshgYYHl2geYi9vhWBloBlLm0RIxjz9+sgbDclRp16KbyQ1dedz6i7Z81
         yXDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=VHlmX95K;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::718 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (mail-dm3nam07on20718.outbound.protection.outlook.com. [2a01:111:f400:7e83::718])
        by gmr-mx.google.com with ESMTPS id q4-20020a2e9144000000b0024f0dcb32f8si468609ljg.5.2022.05.23.20.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 May 2022 20:08:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e83::718 as permitted sender) client-ip=2a01:111:f400:7e83::718;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=f/UlJf+R3AP6qWBXKELd3l65hO6GuBuTicLNRTuUeLENXKFXhlb2fqrLg72Ihgf76wVohA+2Y9s6RI6p/HzEx4Te9N3IAsEAlhtFiUGDGB9TxE4K3VDuwmGnXhsRXsmMIVjKXOPXj3Ye39yVazYSFFRUhXRsmyGF7rC0zowkmo4vWJfWP8YXRuROLyStx21d4D/l5Uhfkxk0echJjiyjNcoQiWpJRI9uiHjslfq4xFab1QVSDyKFJb5dChtLwR1RdBxN3e5WNZidh/WA7bTIESykbLgLbXnA6q+wgRFEvL0vesIpZWqaApb8I52L74fmYHgaHbdhO1CzaeSwTSMD2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kSBBU8wtFL5CoRnOO+r66WKfxM3/Gso/TM0pC0uVE/w=;
 b=gqwxxKZzIBKV9wI/isFT13qUBAOCuQNAPaBGe/ZeTJlT54POo68UUomQL1eNDZz09wPykLXfRVu6WzM5dkaioIg8TRRDgIp1vvVWNll18rzZEa5k7YwMaFbmb1tPG/aemG1ZokXwy+tVUL+kevQwab75pgoOhrcCH5cwvBPDOegYB63JnaiMpyxtK7PhYfwg6CSNUCxxMJkPiBBcEHLTEOLSPLZf9b9VcSA4K2aGrqSrKZVK9PatCqiDDrnKM9Y/ujhiDuTRRdJzZzE2sqxuu0S3efJtzG+jy3s9sbai3WRGMpsZGDzWrNT5bDaLfyyjLv5Evii7hTxFLckAZiHd7w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=purdue.edu; dmarc=pass action=none header.from=purdue.edu;
 dkim=pass header.d=purdue.edu; arc=none
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 (2603:10b6:301:33::18) by BYAPR22MB2375.namprd22.prod.outlook.com
 (2603:10b6:a02:c1::23) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5273.23; Tue, 24 May
 2022 03:08:35 +0000
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa]) by MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa%3]) with mapi id 15.20.5273.023; Tue, 24 May 2022
 03:08:35 +0000
From: "Liu, Congyu" <liu3101@purdue.edu>
To: Dmitry Vyukov <dvyukov@google.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function
Thread-Topic: [PATCH v2] kcov: update pos before writing pc in trace function
Thread-Index: AQHYbmb5ybW7rPmroUCLD053biTbk60sJDKAgAEv7pc=
Date: Tue, 24 May 2022 03:08:35 +0000
Message-ID: <MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79@MWHPR2201MB1072.namprd22.prod.outlook.com>
References: <20220523053531.1572793-1-liu3101@purdue.edu>
 <CACT4Y+Y9bx0Yrn=kntwcRwdrZh+O7xMKvPWgg=aMjyXb9P4dLw@mail.gmail.com>
In-Reply-To: <CACT4Y+Y9bx0Yrn=kntwcRwdrZh+O7xMKvPWgg=aMjyXb9P4dLw@mail.gmail.com>
Accept-Language: en-US, zh-CN
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
suggested_attachment_session_id: eb43b202-168b-5b93-d60f-f1d8b95159f7
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 7b13280c-acba-473c-b3e6-08da3d32b11c
x-ms-traffictypediagnostic: BYAPR22MB2375:EE_
x-microsoft-antispam-prvs: <BYAPR22MB23750C2D5DFCCE15A73E9258D0D79@BYAPR22MB2375.namprd22.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: wkTW56Qdkhup26N6j1nDwkPwfuFoYqKhMx3BJMHK3zYS1jkoE9V2nE/dt8rKDah8eU+cQjzfT1yEHwnI3L6kvpyg+l4oL89ty7E1GZPDvimavXx+pUDcWgSpuzpUketrDvsP+RiWJh8p34NObsMVoJp/zWEz6C454NqYgLM6bqacNsGO7AO0KJWCwDgwWZCOFzBumS24v/gIHAc1e5wcoN3od4grRgQ7IWO/hY8qDeAw3LcHXyX74CuFZ75mrWOffteW7Psq/6KRcSoEEKr+CJCrDujnKOSminoSpyc0aMrM2+8AFZ1d5SC/6CfdmmGWTbtFftwlVQ3NsaJmAxIny3keCI5xhHA4DaYlfgGHt5e8WtdoUC5Fj9iK+g2dAGqnyrO6JbbbIrw/5BCSHrDaJyzlbgbYWEutnAr15PG9yibaYjh06ijLzKne7MLy89CZWDQzOgQwELoKNOM1Om8j4UKXukmLR+ijt6dUu4p+HNmVZWlfb+Kh4UGILPHctX+xLnQYwxzASaQErFOW/GNKB62Y1YVU1Zhh8PSfpzPJsCiDaIXOyFo4hz7fMf2qkYtYO+rebalXi4nbpMD4g0Mwr7vAeioQx3uLXr1my+8HEZcjHKmttnzW85K5CV72q2SQBaSwZgZQljHKUOX+MF3XgJZpxkiRPtKKgSBXPZlYqYfvZKuBE+G4IKC2FHv283Y8YNdWQRI0a9TPIeHwGHxClDDPg01Wlk1jL4OAlK37nXqGYuVx05gn8/dXGfjUV8C5WQ9KPULNXhg85EPENdjIo5ykWZg6LA2KJTtQ4tB6I5U=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MWHPR2201MB1072.namprd22.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(966005)(52536014)(8936002)(55016003)(83380400001)(186003)(5660300002)(6506007)(7696005)(53546011)(66476007)(64756008)(86362001)(26005)(15650500001)(9686003)(33656002)(66556008)(2906002)(508600001)(6916009)(8676002)(54906003)(38100700002)(316002)(786003)(122000001)(66946007)(66446008)(76116006)(38070700005)(4326008)(75432002)(91956017)(71200400001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?9mu3UxyPg8Bl89tkt5xOofAJK9o/ZgGrsVkZ9XD06EBfDJ40f1JRBpvdFqUd?=
 =?us-ascii?Q?6SP1u0yBLjy8e5qluVtqc6V0+oHqDxJunvtOr7T5fCn9Jzdu0o5b006qb/O+?=
 =?us-ascii?Q?y3wqMLgQCTqTMyrwx5C7DiNgaKJpXdpZxjYiM/gZU73eumDxvq0bWaeQ6pIG?=
 =?us-ascii?Q?aF4YjtkhByQFnp/BNE7uUfmLqD0wfp9i6x1orAiB9DzeC2P1b2We3fk4DPKB?=
 =?us-ascii?Q?leizepZ5i3Unt5RpWUrqp20IJN5tPNE+lSKdZtDZ+oB6AjFGMs9OutXv1+WF?=
 =?us-ascii?Q?bQqIV0KSIyA1ZmoHvGCp3UaPb14FT744Bf87qoFv+fY7VU2DliAT3RDtcTab?=
 =?us-ascii?Q?2okxL8UPOKOVrTgiqdKOhorveiJjYM/fU2rPl4K3l6JM2XVvNPtShgFXq8+z?=
 =?us-ascii?Q?AVYUaJlcOvheKRFF7TC1fmdOfCDYnRoaVKDFSw1JtTt2d6DUeTvmNoR1MxN8?=
 =?us-ascii?Q?QWme2bfbfJWRnEqxb+myoG2YOacEm7wG1F7FfFIpklKcm1O6i7ooUrowsoI0?=
 =?us-ascii?Q?+rv6axkXpwvPgAZ09BhjuKejY5ore360K3Q0i2puiutHBIQZXPmxofdE+lwo?=
 =?us-ascii?Q?szYyU5o+Qkjl2yJXKHo0c+c6gdNVXwFobPWwjNpm67TvtBlpprAc2IqFthm6?=
 =?us-ascii?Q?/H2VdVEjG853DvoWsITcjWi0cVKqfxmO/y8uVWjuVpswAkMM50zeFD/Pz9+c?=
 =?us-ascii?Q?6XYeS4bBMBY6zrV5fRDYPZvfIy2X8oj9ydhH/wnVADbQwQmU/KGDY9+kxl6u?=
 =?us-ascii?Q?Iv/cPBl5U85gEj7Q2V6j6I5X0rZpWRArMZkXAe+yZ7j2gBeirJT4XsFp8N10?=
 =?us-ascii?Q?9fvILoTSiHRoH5Z0wAgkwR9cOHcuicZjPPMlsqeBLGZnDomwlDBTZAB/WyIk?=
 =?us-ascii?Q?2+bmwbii0XbOywP7Q7BTrgREialnTk0BWFciBazL7EZsFH/+73JUiYcx1U8T?=
 =?us-ascii?Q?QlLDyisDI/xDWS6C8rSP4kFGgIO11ec2ui8dawTnlCkM6tkEk4SjeRpU2KdC?=
 =?us-ascii?Q?C4WEs8sFlgYDKdY1CTRj344Og1qpwBfHIHnQeJAMWFPEDxdYt6TWwvOXPb/O?=
 =?us-ascii?Q?X1aml+KfasEQFaTKqubDGG/wIoztimgQsGQXvq4cJfz2CnyQUI7fUFaJfSEF?=
 =?us-ascii?Q?RqcgKVKahxFhAx6GH2TST+zfvA+wVR0V36dJ9bIglXo+w3DdK8tlFQowxlN8?=
 =?us-ascii?Q?/1RlEPAXir/Hnzb+uCqgASSMJMQovSZSXJD4Ug0iQTnIFd05yosJ/Qw5kybc?=
 =?us-ascii?Q?T9t+GFw9XFhRl5+qeNx1kBa3R2/Rn4XlkU7GdjX8rZs+NJifO4nR68tmNUu9?=
 =?us-ascii?Q?eM/f0K0qdAr0giyC9URye0BnzWh5R+n6qlf7QHeYmXtCDV/YWyme6oGCnaWt?=
 =?us-ascii?Q?bwDUSCWlQ1UncHC1xtekjXkb7+0tCcRPAmbsRo5mMYxJ7mnakU1orKQH2jAv?=
 =?us-ascii?Q?oQrm4joVTK8jywYJF86DlzS9KLmcOIZZ1hwI3yYcYtMANdZSyGpPv7PfvXaO?=
 =?us-ascii?Q?MjcjDUdIgypPMocICETOZiqrk7izLk6kA7rn06ocW/c4Scf1wWQhMr5+iV5n?=
 =?us-ascii?Q?qmfCPO2jFCeWPKFEjYe7nWl/2stpGxM4d9kNbd/dPkNQhulM5Da1jDh+SkHb?=
 =?us-ascii?Q?81BHfuGFICBPcttQtitTSZWnIaP7kpmNeYCWnuYFtvaNA9fDGb76U7gNZaQa?=
 =?us-ascii?Q?irJtSK1glzXxY6TL5Gd1Fs09iKs6Qfaewh06d9IaYKzMwMzw?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: purdue.edu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MWHPR2201MB1072.namprd22.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7b13280c-acba-473c-b3e6-08da3d32b11c
X-MS-Exchange-CrossTenant-originalarrivaltime: 24 May 2022 03:08:35.5297
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4130bd39-7c53-419c-b1e5-8758d6d63f21
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: c8Kc7mH7mWRpr81gwZAj6GmC2+6Wss4poTFPLnHulBD2UmAefJk0v4GIj+1EcoDcYgcT1MRiJC8wbyObkxW7TA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR22MB2375
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com
 header.b=VHlmX95K;       arc=pass (i=1 spf=pass spfdomain=purdue.edu
 dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates
 2a01:111:f400:7e83::718 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/MWHPR2201MB1072A5D51631B60BF02E2F3DD0D79%40MWHPR2201MB1072.namprd22.prod.outlook.com.
