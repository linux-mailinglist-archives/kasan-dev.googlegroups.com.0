Return-Path: <kasan-dev+bncBCYL7PHBVABBBOVDROEAMGQEPLS3QSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D22A3DA863
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 18:05:16 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id z1-20020a1709030181b029012c775d35e1sf2179616plg.20
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 09:05:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627574714; cv=pass;
        d=google.com; s=arc-20160816;
        b=H0YhQFh2G1FmYK/EfhnBeg7iMNgH8qC56eonwsULQHZ7iAQRWePEuSnT3F4uIDo1mW
         vjliV9BU15iTdeOXM8XxcyE/2x2sE4jGH1ZuhWgrKsbbd2rkx4ndjZRY2kEy5zgV6xlw
         ZVTsYoE9tIbQy8jdb/ACY1zVTR6VLKz/+3qKL/W4RygDFFmbTE2jdo+9qY86X+luj2mn
         RFXMTirOuvWr37nEO9Kzt5wzX3ddc/IDaZt5TlS7/r3kSffe3oU7qGB2j45pv2kbMkT2
         dJ+GwQbDOLO2xAfhXeRyBfMr5ArPJn4xdP5DfpYvOj8m2lbFk+Wr4zKEUaVXoB5hVeFU
         zYxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/OqsOmftXnQFSp3Uqu0W/aIARi+K+1cvhSbdY+hcbu4=;
        b=eG3DSdJQUkdQXMw17ma4/R5ff7JIoXBWVCM8W3vzIBqkanxiuGJFj8AtK7ni5PhaEc
         bmD9y+f1N+Xtm/gOmznmvzmqzEbNb/cfghcppLLzUS/3SkXLKuCQM5fuKkX6Ciwcpc3/
         5GbXQwWfXHPdDdStFMnTUI2V+mouPiApdE14bFxeVkfzShKluIXzPU3ttO0+XJksRzCY
         3ve8hqGtLHCb/qXvWT1/PFElV/pniPfyhCTR7lntjFxd9PKoHmDYzOSReXV6mqwNz39D
         F3nVfJvJMe3koCDwJIvaejX/+8aa808+qJTzeNRg0kzoevG/7SbsZ7U5nCpHnB6634ec
         RUIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Tprljk8G;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/OqsOmftXnQFSp3Uqu0W/aIARi+K+1cvhSbdY+hcbu4=;
        b=bH2pifkn/OvmsFhExWFpzzrFiDkYQoiNYHH/EGLQhxqWoTw7dC/jcitZgL6ofXxO95
         cnOnouYtoYjryYVsy7bV8+FQv+AbbroDoV5m9CneF2ePnE5+5L8oJyOgLTXBCkFmqLhB
         n718v63+dtpUV7+oewoyVeFEHSLC584PGFBsr9J806CTWFZ221x74x38rnnQ3T01upnn
         bg9GZtjaQ89rOan6+txhG5eBsbub72xvn2LsRXNRL1A7xt059M5bNqQpp5IpZbyesB7l
         h4/qjJCpwN5XBpJPfrduOFoXoluE/RFJq7U0/TXZKD1pp+dm8LKQcTfS7X3X1inYA4yB
         bUEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/OqsOmftXnQFSp3Uqu0W/aIARi+K+1cvhSbdY+hcbu4=;
        b=Rt9nfMj2tk4EK0f+lWOkilH8lzXaRBrnYqtNeEIOr36DPPUOvYNrb3P54fLsddVHzR
         +V6VKEbRPZgd81uQ0Mo6rFDfU27XApnHI1zyotr1CToxKuQQYSCwa3bfh8dP1CdfqkWc
         wT78wccGgI/TGD2X5Ip04TOgymQ2bM5X7kz35fiiEx3RkHdHEWr/qbmAAj8FVcZZC3pd
         QA+Ttniz6orQenkdIdokcbPXV3AmdepC2+UniIU3D2g/INpViFCK53o1MtUi8MP9gQQS
         N7503HdS+FrgfVLhVv4JFKM3vDZjs5ecgQ+wEyWX7HOYzy3u+zpAAfubOXlG+fMEIzNj
         FbDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53104+PWqPIwx5Tlm/mA1Ov2MgbvXXbQMd1zv7LBxwyDF7vk8VNK
	QSwhl19gkI9lWwEba4LU7D8=
X-Google-Smtp-Source: ABdhPJz0TWfJNpS21UdoQGRbTFgxd+a7IbLO2JaJYa154/lotpp3M20X/Sz9VaNgMnhejIRNf3cXPg==
X-Received: by 2002:a17:902:8507:b029:12b:533e:5e9d with SMTP id bj7-20020a1709028507b029012b533e5e9dmr5271423plb.53.1627574714550;
        Thu, 29 Jul 2021 09:05:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c96:: with SMTP id a22ls2503372pfv.4.gmail; Thu, 29
 Jul 2021 09:05:13 -0700 (PDT)
X-Received: by 2002:aa7:8757:0:b029:39e:4765:20c6 with SMTP id g23-20020aa787570000b029039e476520c6mr5751387pfo.58.1627574713815;
        Thu, 29 Jul 2021 09:05:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627574713; cv=none;
        d=google.com; s=arc-20160816;
        b=RKcDAoxOE3tqzZFD/FN5MSW4xsC2iS5MiEsH7ZQL0U5Trlc8LUPliL7V0SX6dDLMMv
         Msn1pZHJlszxca6X5H430NLZk+rT2s8hD0fG0hyRQvMTvkRWbCqBf3N8Erm6Uibd8hhb
         BvgRBO/C3O+YhZNlOznVLzu41G9cph6XiFP56hL1LaYHWwA6jS0K7C2oDVsuyF22Njwj
         ZtFZoCM4PgdNHrTszLBFDQ0mm3HC86/7AhxOlcGkNNDssZ4wuahhAMlt6kA8ZFB0SiPW
         dFyr9Ngxpv2m3fxsDDdWnbIN6XbWAd4q+nCsYhrhUSmP7TxBPHdnOx4we9ofnnZMDDJR
         rdOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+hvYv+gTA03BfCESrF6+SKmI0tlkNnXdZDWckobVI8M=;
        b=tKBCwSDh4Lh7wQC9Wln/kPTs1g9BhoXeqy3Tn3+5PF2fnQNqBSlLaubLGFB1iS5Nu9
         vs8IM1EYVFvzAYhUwlm9oNzk9BEWpSd8HYpCy1iDjaGo3JdDzJInfo5wCFpNpGHkoIuB
         nNEEIIWuvh/knSBAD/XIRgbB/0d/utpkiGodu0vtc2E7rwCLsEH2Z104/AZ0bzpKJp2Q
         6V2vEnvqZZ9kMavShMS9Q0xkkCIAvME6dFU61hWxkfDigfrE3bmORXjyAGX7CuiVs/X/
         mdoKznzMVtMJszbXZtR4YafJwD1+MdFiW2x6Kinpbh4lmJI4KR4KKpYzR9lWnf7fNZBl
         Bzqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Tprljk8G;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id c9si232393pfr.5.2021.07.29.09.05.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jul 2021 09:05:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098420.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16TG43E9006711;
	Thu, 29 Jul 2021 12:05:12 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3a3shafnqw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 12:05:12 -0400
Received: from m0098420.ppops.net (m0098420.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16TG4Jg9011471;
	Thu, 29 Jul 2021 12:05:12 -0400
Received: from ppma02fra.de.ibm.com (47.49.7a9f.ip4.static.sl-reverse.com [159.122.73.71])
	by mx0b-001b2d01.pphosted.com with ESMTP id 3a3shafnpq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 12:05:11 -0400
Received: from pps.filterd (ppma02fra.de.ibm.com [127.0.0.1])
	by ppma02fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16TG0BOM018534;
	Thu, 29 Jul 2021 16:05:10 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma02fra.de.ibm.com with ESMTP id 3a235xs9c2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 16:05:09 +0000
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16TG56Uj22151634
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jul 2021 16:05:06 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 296BFA4075;
	Thu, 29 Jul 2021 16:05:06 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CBEB9A4066;
	Thu, 29 Jul 2021 16:05:05 +0000 (GMT)
Received: from osiris (unknown [9.145.0.186])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 29 Jul 2021 16:05:05 +0000 (GMT)
Date: Thu, 29 Jul 2021 18:05:04 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: Re: [PATCH] kcsan: use u64 instead of cycles_t
Message-ID: <YQLRsNjn/lQwiIcl@osiris>
References: <20210729142811.1309391-1-hca@linux.ibm.com>
 <CANpmjNM=rSFwmJCEq6gxHZBdYKVZas4rbnd2gk8GCAEjiJ_5UQ@mail.gmail.com>
 <20210729155834.GX4397@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210729155834.GX4397@paulmck-ThinkPad-P17-Gen-1>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qTIWVnuHtf-8duyggWgGst_ghBh7F0Sj
X-Proofpoint-GUID: 7OxKO8CAHGaWRanJ6MkPTxV7gmUbu9bW
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-29_12:2021-07-29,2021-07-29 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 adultscore=0
 impostorscore=0 mlxlogscore=939 phishscore=0 priorityscore=1501
 suspectscore=0 mlxscore=0 spamscore=0 clxscore=1011 bulkscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107290101
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Tprljk8G;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Jul 29, 2021 at 08:58:34AM -0700, Paul E. McKenney wrote:
> On Thu, Jul 29, 2021 at 04:53:10PM +0200, Marco Elver wrote:
> > +Cc: Paul
> >=20
> > On Thu, 29 Jul 2021 at 16:28, Heiko Carstens <hca@linux.ibm.com> wrote:
> > >
> > > cycles_t has a different type across architectures: unsigned int,
> > > unsinged long, or unsigned long long. Depending on architecture this
> > > will generate this warning:
> > >
> > > kernel/kcsan/debugfs.c: In function =E2=80=98microbenchmark=E2=80=99:
> > > ./include/linux/kern_levels.h:5:25: warning: format =E2=80=98%llu=E2=
=80=99 expects argument of type =E2=80=98long long unsigned int=E2=80=99, b=
ut argument 3 has type =E2=80=98cycles_t=E2=80=99 {aka =E2=80=98long unsign=
ed int=E2=80=99} [-Wformat=3D]
> > >
> > > To avoid this simple change the type of cycle to u64 in
> > > microbenchmark(), since u64 is of type unsigned long long for all
> > > architectures.
> > >
> > > Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> >=20
> > Acked-by: Marco Elver <elver@google.com>
> >=20
> > Do you have a series adding KCSAN support for s390, i.e. would you
> > like to keep it together with those changes?
> >=20
> > Otherwise this would go the usual route through Paul's -rcu tree.
>=20
> Either way, please let me know!

We will enable KCSAN support for s390 with the next merge window, so
I'll queue this patch also on the s390 tree.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YQLRsNjn/lQwiIcl%40osiris.
