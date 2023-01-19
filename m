Return-Path: <kasan-dev+bncBCOJBN4V7QMBBIMAU6PAMGQEM3SHUYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 987A0674590
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 23:11:46 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id b24-20020a0565120b9800b004d593e1d644sf1545506lfv.8
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 14:11:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674166306; cv=pass;
        d=google.com; s=arc-20160816;
        b=awBuojNSpqjvApNxUSzyOtFylw7kQkZEV+DDOTpaPA1NX56uFgsJDV1wAHvYGUKhty
         f/oKTg5CzP2yb4PwhRrMobWwen8Fhm6y8Jq6yps2KwzGIC8RTkIEaibK9rcQ3wSt5a92
         C7Yp7wtxgeBIvAxsUJ8FaepGAEfAKnjHkTdX7zhTyO1idz9gfzIWC3I55+j5KrQeAea5
         K0iz/I69zQGor6qCAqueUiFU7FVLpy7KzRJPp9w9+tYLJrSzRH1YXq3jquTIO65qcFIi
         qdU9gOJ+1PTlAz7PfDvTt/i+x8mZWibBgCaw8YM+6NqD+ktLit33P5nqyyLVuSe5Wt93
         TA6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:subject:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=xtnC2XNnv+XVAwPETDZt6guwFcusMQE10hBk0GLfHTo=;
        b=k1dceAmsok7qqV/nG4CjmttzQl12AlCWQPqiF2DojAnoC/cEYZuBPV3KcYZMkKIloC
         +oTRyOD+C/WWfffd9bI+DVO4F8yxfu8+9p9+perAPppSXLRsILHNVo3qbG+lHY4HFMbN
         lF17okPgdNi37lo0QCzB0FmrQEyScb8NOxc++l72TDIBZjngc6pP7nYxMAOIViphrHbT
         8f1oKLRRVFUSmkOyoMKEAggdSTdB+qcj0477FPPC9Nqo8lc286iyOst7iIdVd/rjU6TG
         x1v6UA+noHzimqAOHLgoSOxpeVnHr8R8LnGlvrugl4yVmsUYRVVihswXYMusjBU2OqjA
         SpMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mkarcher@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=mkarcher@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:subject
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xtnC2XNnv+XVAwPETDZt6guwFcusMQE10hBk0GLfHTo=;
        b=XXJsfHNAYz1x02RhnARXxaQJgyCNIgZWgTPcfIx/vvdtH5Ea5POlg7LsNoRL43/9r0
         d9aLrWImkXYTZiLzIPOQ1QEocGRacjfExXkzsQTDMjCFr6VyTTlg1SszyILisrXtu8Qd
         L+WEUdrhEtedoR6zrDOdLTMgHg6AA3pT0saZ8KVKESghAj7n+y/LjLQyXB7JasL1CQXU
         Wel3HXN0kOGEvJKqbw73WE8bPjizQFn5ZnOKicIlk8qcXR6aNtdJtSOoOdvEQtpaxaD8
         J31luSYP/F3hIaQhYRcFh+0b1SiW3ft15xKRVIDDgPKM1z3q3jAsduVg5HpoC7QDcqEd
         MJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :user-agent:mime-version:date:message-id:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xtnC2XNnv+XVAwPETDZt6guwFcusMQE10hBk0GLfHTo=;
        b=LZIBy1KC1Ihm4yxL3TYilfU8mEGRaWnLBmbzvuCN/Lv4auk0cFHrWOqmi/Yrt/21YR
         C5gquJc+Meg5hIuvdv3UssyMiKLmL7XmBt5RiQmvylx77xlr86aOQbeTuZ7Li5mQlKqT
         bKyC3CXqU1B5gDemt3zyyyImo5rwgpxFMix4kIB8dK2Rz16mpfgvu1cARoxw9PDTSfNJ
         tFEi9Txaby5XbacKu8XYHSlbMYpV0oqvUZR52nbTTPjAtxbdWWUsurQM4axEE/toi/vu
         frG1ce6jzc4AF6b2XDJTrPc1OBdfJZMLWaeA1pR9k5eU8naXrP5btBf2QoDNXYmGlX7j
         auUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kozCbIm2GCKcx3/zimy+hoQ0mmC8T5aceMoX02iE4JgBzqKYqo7
	ZvJV8S2mt+LuTPgds3aKcGU=
X-Google-Smtp-Source: AMrXdXtqT3vACndF/YqZN2fTn+Q0A3ZMxWCazBq+BGySnm80TxiIpRPpRJ3OE0dh5o4E37dhtqtl9w==
X-Received: by 2002:ac2:5443:0:b0:4cc:534f:beef with SMTP id d3-20020ac25443000000b004cc534fbeefmr743747lfn.524.1674166305642;
        Thu, 19 Jan 2023 14:11:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2082:b0:4d1:8575:2d31 with SMTP id
 t2-20020a056512208200b004d185752d31ls2198039lfr.0.-pod-prod-gmail; Thu, 19
 Jan 2023 14:11:44 -0800 (PST)
X-Received: by 2002:a05:6512:2822:b0:4b4:e4a1:2fc6 with SMTP id cf34-20020a056512282200b004b4e4a12fc6mr4543160lfb.68.1674166304402;
        Thu, 19 Jan 2023 14:11:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674166304; cv=none;
        d=google.com; s=arc-20160816;
        b=WKJmLDKyg9gYerQ40M1Hi8y4Oe4SInSS6eFMBJAev2i1dgyc0Wyb4PVu5lnfXXXvz9
         wekCQCB734tyRdDUh6di13PMWKNQtw7mGP/dlCIpOmIGbyl4wPNEeXHYPlbjy/HQF0Z5
         j/sgHk/dAzyR6Gj0V8MhXqr+rBagi/eAoYa+haCrSQTOtR+sj6Si/JMNDlFMHZPFDfmH
         SOZKY0HMCrtp1WmcDHRRsH+RBIGfjRieRt3/Wqz6QgfuSKjw1km25Uk5vCnIAFAoyX+k
         WbDLPB6FryHsd/T7G22sumvopxDclHGrM5fAsqDCHzrg9vlIxN2ZILxxxHFXorIvDId2
         JSGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :user-agent:mime-version:date:message-id;
        bh=99u4QbRJmltszSmEfDBmEyKbNIgB3K7LFPI1t4QDyBM=;
        b=hFLFJIGUQrO9Y8W82Qndxp0CGk9IyFPkIa6UknVIqic5FsbGUf9gJNUS22vIYZPYKS
         V6Lgb8jdMAbXNf3VLq6Uy7xO4UmQZRi5aihs1SmK3CuG3lpKMep8hh6sop/vdPYVjPMV
         gwBfkg0iBfAInSM6LsyBYt6oZOsn0Va8YJNjhBgDbgQo72XpBghGmE0r0nhWFkrBykNj
         6h1wj14/PS+5EBOlH4+vgmMS8to/iJ/wMi6cG3hngLBAvw/16zMzxSHdsF/lqXl+5j+U
         +iIE17nb5KlUvNPLAEpKmQuM97jKAOdwc1J+UQyhG9EgzjuZ07BHlLuNitLpCxKdmIxC
         1Bcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mkarcher@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=mkarcher@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id o10-20020a05651205ca00b004ce3ceb0e80si985079lfo.5.2023.01.19.14.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jan 2023 14:11:44 -0800 (PST)
Received-SPF: pass (google.com: domain of mkarcher@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <mkarcher@zedat.fu-berlin.de>)
          id 1pId7s-000ES9-TO; Thu, 19 Jan 2023 23:11:16 +0100
Received: from pd9f631ca.dip0.t-ipconnect.de ([217.246.49.202] helo=[192.168.144.87])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <Michael.Karcher@fu-berlin.de>)
          id 1pId7s-002cf1-Mu; Thu, 19 Jan 2023 23:11:16 +0100
Message-ID: <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
Date: Thu, 19 Jan 2023 23:11:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
To: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
 Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org,
 Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
 Arnd Bergmann <arnd@arndb.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
 <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
From: "Michael.Karcher" <Michael.Karcher@fu-berlin.de>
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
In-Reply-To: <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: 217.246.49.202
X-Original-Sender: michael.karcher@fu-berlin.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mkarcher@zedat.fu-berlin.de designates 130.133.4.66 as
 permitted sender) smtp.mailfrom=mkarcher@zedat.fu-berlin.de
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

Isn't this supposed to be caught by this check:
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 a, __same_type(a, NULL=
)
>>>
>>> ?
>>
>> Yeah, but gcc thinks it is smarter than us...
>> Probably it drops the test, assuming UB cannot happen.
> Hmm, sounds like a GGC bug to me then. Not sure how to fix this then.


I don't see a clear bug at this point. We are talking about the C expressio=
n

 =C2=A0 __same_type((void*)0, (void*)0)? 0 : sizeof((void*)0)/sizeof(*((voi=
d*0))

This expression is valid (assuming __same_type works, which is a GCC=20
extension), and should return 0. As of now, I have no indication that=20
this expression does not return 0. Also, it is true that this expression=20
contains the suspicious pattern "sizeof(void*)/sizeof(void)", which is=20
does not calculate the size of any array. GCC is free to emit as much=20
warnings is it wants for any kind of expressions. From a C standard=20
point of view, it's just a "quality of implementation" issue, and an=20
implementation that emits useless warnings is of low quality, but not=20
non-conforming.

In this case, we requested that gcc refuses to compile if it emits any=20
kind of warning, which instructs gcc to reject programs that would be=20
valid according to the C standard, but are deemed to be "likely incorrect".

I suggest to file a bug against gcc complaining about a "spurious=20
warning", and using "-Werror -Wno-error-sizeof-pointer-div" until gcc is=20
adapted to not emit the warning about the pointer division if the result=20
is not used.


Regards,
 =C2=A0 Michael Karcher

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1732342f-49fe-c20e-b877-bc0a340e1a50%40fu-berlin.de.
