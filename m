Return-Path: <kasan-dev+bncBCLMXXWM5YBBBB5IRWUQMGQENFBMMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 38DC67BD1B9
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 03:14:49 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1dd8e6a7a86sf6633613fac.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Oct 2023 18:14:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696814088; cv=pass;
        d=google.com; s=arc-20160816;
        b=b8dMLAK626J8FLqNYLNVS4MlqlKTiY5c7yaxiLc4GHhDjN04CBmiSMqG1NVPTdGgQH
         4W2JXTVGVxTzPx+lRfDDpJbYWrQlmFkDGnB816mseQn5RZp2Au7pvZRp2tJJy7hL98Dj
         pGIcVov542wlzBnIBphxjL/FzElO5ets89QzcqxO5yVNwlagT3o/jEJmnV6u3mhmIqCp
         5MeVnWccLIbi/HrWfF4HoGCr6Vn1TXqhqkxsNvOm9kqiwXsUh9fzMJerlAHWrgT/E+c5
         nZIUxqsgM/4l5s3f/vtecYpCLpyli8TEL/SzazIr0AUCQbabiiG9w9wNVuoYG790IZcY
         ruqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=HkpKy9g7R/CZDvDXz8yrWUvfTeaW5O+feAxhI0vFG18=;
        fh=nt0pL45EiiHCjIus20cjE4TV+BsNg5sejWxgaGKQXOI=;
        b=LGwcLFMNuvR8Syq+PfD141yKHfJRR0Zeh1iDc8xOQ3X45kSqYgIWvNF70aY39ZrnFn
         sajq9FsbKJFERK+DZ6XkpKL8bY6PNSjAI9z476bpSqbeCsmiOESGD5szyGLrc1VOZFYa
         aM9Z5Hxnzxt/nWh/U0QInq+h1gG0hSh9je2LAIQwXXxqZHrvPk0eKlwQAz6VOO9ffFSV
         7NquNNJOBgApH80IfzHqjZHd1R/caavTejakbcdgfs9XLHG8HdCn1ReRQOk5U6PnIru5
         Vw2pnbBuX5K8TPT9knTH1kFCI8gNK/ElvOBfcG97I4Q5F+EZ4m2xYzhmqZLJbXkuYDhy
         Oi5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Zi1FKHca;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696814088; x=1697418888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HkpKy9g7R/CZDvDXz8yrWUvfTeaW5O+feAxhI0vFG18=;
        b=U7m8VlheVi2vLRwc9hkV7Qh7VLCtar3dTUTB1NCaSYEb9cjBAiXb1Ri1G/Htz3lobP
         Sh0Xky5HRO6LZdUnlJhkX+1O6uLGUU/VuuoQdkuRqLMjI3JYFWa0VIkXw4Zzt1JiZJ7X
         7Tv6EKl5Zml6WbJv82s9q0UlPETvFjEleIS7kzaCM6A+7Yskdoa3nmyQGfHPtTC4AV5I
         iylu+nDUoNxmYVAtoIiQ+f1QsF7sJPUvPjvtwtDs8L7dV82gNsLRorIhhk5JK+ABONqt
         DSJiNRHSJhAxrLuLnmvht3Pvt9zCu7Y26Pmp/73O2Vwslv3ZmehPtaMwgZOjupJ+qTAq
         FHIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696814088; x=1697418888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HkpKy9g7R/CZDvDXz8yrWUvfTeaW5O+feAxhI0vFG18=;
        b=RHfrIc3NMh2kaA+suZK3k4wWad8S05AP+Z8G2K+117uUBJYYcjz24RmGTJjdIarGxF
         8gvOeaovXWi8vWIfD4NgpBwjJNyjbwia2Lc24xiNSS29d7syqnmQYd/305HDIiIKIeN7
         kkEt2LuMe90nHuwx4xNWz7yk1IGAxLIZhSno2EQmP+8Z2ZVigtDoyu/uHyIK3Rcx0uHk
         FJo/8ZaBPnajGz8OTilrCGGIW38urQZCff5/2VpreHyDeu9+32hreKhzktSxS0MqPOl4
         6T2lKEFqI6JGg0VBhXGStcC4/s6DAiRdQfP4Z8pbAkIOSQ40giHI8e+JjearX3rxf9pR
         yF6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwUNhmac8BVkXW/tT7u+At7gewaFwl/McscV2e6zAFqbhXPVe7M
	ayGQm24VgMIK18uQPKrHDcc=
X-Google-Smtp-Source: AGHT+IF1vN6Z/5G4IAxQF4h8Xya/CD+TycvYiqdRfAYr/xqruXJQky/yZ0MDvdsCm+tGyfRQGF8Njw==
X-Received: by 2002:a05:6870:9602:b0:1dd:443c:57a8 with SMTP id d2-20020a056870960200b001dd443c57a8mr18736694oaq.26.1696814087618;
        Sun, 08 Oct 2023 18:14:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:209:b0:1dd:6b48:3e25 with SMTP id
 t9-20020a056871020900b001dd6b483e25ls2724358oad.1.-pod-prod-01-us; Sun, 08
 Oct 2023 18:14:47 -0700 (PDT)
X-Received: by 2002:a05:6870:e416:b0:1d4:cb38:f19e with SMTP id n22-20020a056870e41600b001d4cb38f19emr18366940oag.9.1696814087014;
        Sun, 08 Oct 2023 18:14:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696814087; cv=none;
        d=google.com; s=arc-20160816;
        b=m/0v3PrNXWYALTexlubvp5+3KwLJT1E2jYarQz3LZJCaozwPY5DPM57EfDc5mG5eoC
         bNrbi9ANAmNWGXWwaxvVttLjQjjG6bZ/349sthbwyx/uGB0Xvd+Rojeyj//7/KT890KJ
         QI/+iLPIF5ULrKAE+5VWGSt2ljwHExTlSg3CF3P4L/XZtZizkQsCe40p8AYqbX5Pj09m
         z1UIHGx/DYh7vQTgb0dJlxUstBYJ/YygvhgXhr+erk0lp2GmaDHHlvfNzk7e/eHT7NaE
         sNozAA2enfaLR9r9tNHKOnZ7XAA0N+OEzoK343HfNsCkU5liiP1gFdcc9KwuCu7SaFPx
         /opQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=bqKwEEDSZeu3XWsBzxAeh+cU4hhpiMZzmCfjh4Tm36c=;
        fh=nt0pL45EiiHCjIus20cjE4TV+BsNg5sejWxgaGKQXOI=;
        b=ChVZgvK8Ph0wB+uT/jURFMu/b/1MKPeo3h98PakUkY8Gu/TuGCy5sAASmCqllJM51s
         15D5CHTHZL9IwynhuwXEIzpBb4RVo2hrQWqM7fNr7PV0Nj2tO4VKiFpWosJdL4bkSkW4
         rYW9/bmXFgA3ju4qEYag3uwvFipDeCE/IhlrcajsvZkRHuoyLSI3Di76QrjTlTq5yjsn
         i/hVgUPkgGU32VqSzIRSBj/GUUwQ/VI6W0UbKNZl7lComMZcYa5cF0qcHVeos7aLWbV+
         X3FHNaSJ4qAFHSLDa1EpEYhO5LFEeEIpJXzs9awkSfnHW9jgjrHw6sb8lnqfvQRSt8GP
         Slvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Zi1FKHca;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id lh8-20020a0568700b0800b001d6edf0fa0esi554872oab.2.2023.10.08.18.14.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Oct 2023 18:14:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279870.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3991BwBe027666;
	Mon, 9 Oct 2023 01:14:33 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3tkh6g19m9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 09 Oct 2023 01:14:32 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 3991EVDw002833
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 9 Oct 2023 01:14:31 GMT
Received: from nalasex01c.na.qualcomm.com (10.47.97.35) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.36; Sun, 8 Oct 2023 18:14:31 -0700
Received: from nalasex01c.na.qualcomm.com ([fe80::6c73:4982:d918:fc9e]) by
 nalasex01c.na.qualcomm.com ([fe80::6c73:4982:d918:fc9e%11]) with mapi id
 15.02.1118.030; Sun, 8 Oct 2023 18:14:31 -0700
From: "Joey Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: Masahiro Yamada <masahiroy@kernel.org>,
        Alexander Potapenko
	<glider@google.com>
CC: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        "Kevin Ding
 (QUIC)" <quic_likaid@quicinc.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Nathan Chancellor
	<nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        "Nicolas
 Schier" <nicolas@fjasle.eu>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "linux-kbuild@vger.kernel.org"
	<linux-kbuild@vger.kernel.org>,
        "Changmin Liu (QUIC)"
	<quic_changmil@quicinc.com>
Subject: RE: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
Thread-Topic: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode
Thread-Index: AQHZ8cKGhLNei3YqKk6uH8pD4/r18bAyTeQAgAFRKACADRj7EA==
Date: Mon, 9 Oct 2023 01:14:31 +0000
Message-ID: <11e5eafbf8ac42fd90491e09e96d8eea@quicinc.com>
References: <20230928041600.15982-1-quic_jiangenj@quicinc.com>
 <CAG_fn=V9FXGpqceojn0UGiPi7gFbDbRnObc-N5a55Qk=XQy=kg@mail.gmail.com>
 <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
In-Reply-To: <CAK7LNASfdQYy7ON011jQxqd4Bz98CJuvDNCUp2NRrHcK29x3zA@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.239.132.37]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: rrhB8qCbGW6xgOd3duwbO0qi0XsUyDXW
X-Proofpoint-ORIG-GUID: rrhB8qCbGW6xgOd3duwbO0qi0XsUyDXW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.980,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-10-09_01,2023-10-06_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 spamscore=0
 clxscore=1015 mlxlogscore=883 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxscore=0 adultscore=0 priorityscore=1501 malwarescore=0 impostorscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2309180000
 definitions=main-2310090009
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Zi1FKHca;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Right, it will be only useful for low memory kernel where 'KASAN_SANITIZE :=
=3Dy' has to be added explicitly in local as hotfix.

-----Original Message-----
From: Masahiro Yamada <masahiroy@kernel.org>=20
Sent: Saturday, September 30, 2023 6:12 PM
To: Alexander Potapenko <glider@google.com>
Cc: Joey Jiao (QUIC) <quic_jiangenj@quicinc.com>; kasan-dev@googlegroups.co=
m; Kevin Ding (QUIC) <quic_likaid@quicinc.com>; Andrey Ryabinin <ryabinin.a=
.a@gmail.com>; Andrey Konovalov <andreyknvl@gmail.com>; Dmitry Vyukov <dvyu=
kov@google.com>; Vincenzo Frascino <vincenzo.frascino@arm.com>; Nathan Chan=
cellor <nathan@kernel.org>; Nick Desaulniers <ndesaulniers@google.com>; Nic=
olas Schier <nicolas@fjasle.eu>; linux-kernel@vger.kernel.org; linux-kbuild=
@vger.kernel.org
Subject: Re: [PATCH] kasan: Add CONFIG_KASAN_WHITELIST_ONLY mode

On Fri, Sep 29, 2023 at 11:06=E2=80=AFPM Alexander Potapenko <glider@google=
.com> wrote:
>
> (CC Masahiro Yamada)
>
> On Thu, Sep 28, 2023 at 6:16=E2=80=AFAM Joey Jiao <quic_jiangenj@quicinc.=
com> wrote:
> >
> > Fow low memory device, full enabled kasan just not work.
> > Set KASAN_SANITIZE to n when CONFIG_KASAN_WHITELIST_ONLY=3Dy.
> > So we can enable kasan for single file or module.
>
> I don't have technical objections here, but it bothers me a bit that=20
> we are adding support for KASAN_SANITIZE:=3Dy, although nobody will be=20
> adding KASAN_SANITIZE:=3Dy to upstream Makefiles - only development=20
> kernels when debugging on low-end devices.
>
> Masahiro, is this something worth having in upstream Kconfig code?


Even if we apply this patch to the upstream, you will end up with adding 'K=
ASAN_SANITIZE :=3Dy'
to the single file/Makefile.

I am not convinced with this patch
since this nod is not so useful standalone.



> > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>



--
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/11e5eafbf8ac42fd90491e09e96d8eea%40quicinc.com.
