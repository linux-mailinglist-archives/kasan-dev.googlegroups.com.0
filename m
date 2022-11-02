Return-Path: <kasan-dev+bncBCP3NC7J64FRBZGERGNQMGQETHIRVRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EFF26162B4
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 13:28:21 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 1-20020a05600c028100b003cf7833293csf1025456wmk.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 05:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667392101; cv=pass;
        d=google.com; s=arc-20160816;
        b=A0wf3tzvIA8XbGIGfVC9KNVHw1MLGeNVfibp4Wr4To2SotYexmg6F3S0QBIY5qSmDI
         9WpDx6Q9dEYkjXkXdeQCsK+zAS6RHEinulb0T5h7riCLpg5690lXkl5Z++7j9X7nZLFn
         FVEZ8z6URgO7uMrlzB3AuFH3hQHge1HqhZ2/Pmn8JPhUiXcOa8a87DWTRiYDrRLhIDKP
         YiB1XtBGNtvdDLZJJ4rdbUUmONFHKmc0Lf82nJbyV9Ff9xB4Zw+1Dw/ysUuSnkF1TU6Q
         WiAYkAJPcA2/psWbe/5HcDY2K5aAyQm6sD0Ajt3E8xltR6a1r4Da4qrN0Ov2SkMgvogY
         suRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=dDelkDm9G2ZKIhDVkDeFGKxltHebk7m5c09WOAh1LTQ=;
        b=hDVkXcuC4fQNcgA1ah+Y0AK1VJIRsNltaAqzgLFmDzVJ1Y2HqmF7Xt7mpDfdftzgbZ
         xN0a/sbO884la8AahBYGGnYrfgDbpweB7XtiNcFhZubN/VDimcLYZaU4qB+QQ8eYSqRr
         vz/R1rUgdctSl0PT2liTnryyCZLqPhnnNDoRoXVnlhJCez61EvI2+6sNh+dqxYd5Z2Un
         zUf2wt/Ar1lz4KdaKpjL3M+sPavjraRUrmtcYgPTraoBxXRvtCeSt1V7K2ZUztEdSNZI
         mPpebm2P4cZ63dmYX4XYs5R/9VK7T0X4MQHFUU5uW2vEPUtzv8XnBwWBu/Mo3Agkvn1G
         L3VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WExcMboC;
       spf=pass (google.com: domain of mistraciaw0@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=mistraciaw0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dDelkDm9G2ZKIhDVkDeFGKxltHebk7m5c09WOAh1LTQ=;
        b=jtqYCyRzIpuM5KrhZJJh2yapCf5XLcDCz/uoIRs+rZGesdf7tjWO+C0bntgWSyCocd
         6wWkBAO6W+VW30KynXPrzLzlOtLfWIKMLs6V2iUeu0SuIgxRfSRhZ53NBA8qgPb4aEc0
         7DfOm4EbHpc7SfoGWnvOWI2o3S/XevK1VYt02+HuC2YqSXM6sNu/uew1mrjUOHjT88s2
         KCqFbr6r7ySc/3IfrwDY+A/e0xpmeaRpXuA8KV3wacXMZWxRdLBmAe/mTCS/C+ENKxSK
         exyTIp2W/Y4WolZDK2rPOXPpfimzAfkcNyQXjqT1sGMfPmOQB48jaM0fNhUH7OMuBbm8
         t9HA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dDelkDm9G2ZKIhDVkDeFGKxltHebk7m5c09WOAh1LTQ=;
        b=YKaH6sN/eycQBJ/wzXZD/3BqPhAJPzpw7A8YSCAcvFhLysqfiug1KJQZaU3wiul0Eu
         mcPnBsY/NKiH6fS5ruwspyW+zWce1TT3bimpZo7zDGy/I/o3xx4u9EMD1yOAQhbXKI0i
         KiQfCY347x4/ow8M06IgKcHeZqbOTwKt9eYJKWJ126FZwqO6xWSY/dU1TnxrvgdGy2eB
         4inFkXpbtf83nfCI/h+1a4sZTonm+UEamJg638yeV5d/8kX2bpmqdJz7AHOTg5Yp5G4a
         QWiUkIOpQK9/3oJPTq6DFF1xs2/od2+AAS2pfd3dnJQ4A/iOzYDbVETel8PLMMZN5PUJ
         wshA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dDelkDm9G2ZKIhDVkDeFGKxltHebk7m5c09WOAh1LTQ=;
        b=Q3DOcPi9VgKkMJfuObbLswfgnmdQs8Ee60/c/W86UmXY2fHUrCcXr8zoHlJrCxnsYD
         NEjVOgLiccpW/GodV5Be4mqUNS1zEI/3tvkNDOKV2nkU0YGDxK7twSOAcmTJGM7GnMmL
         ObdoAkl+c2FxHZ2o10kAGsbj3u8xK0/7vP8eSzLKlOTzu/aqjPQ2VoeA3MyZ/cro51eb
         fmLgCwKZKHm0aTVbDiL9/19qGthdcIFjijrf4QO05K8iV3nxyD+GQJ6uMjmrDrwY5/7o
         aBRAy1x/gzsh8p0SdK73KLaIVue/s84oP+Ip0hgd/b7ZDFtXxgQmHgDefKzdS2lLPFE8
         8YuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Y4TqPDVO3v5CPUGQXix+VgDBR3vzJLHeuUNnWQ+f0Qv9TZ+RF
	2gs39GLHtezjkP+Thg+T454=
X-Google-Smtp-Source: AMsMyM7+XjsofuD+ESXzF/M4fisjyr8poysZaKM+1y2QCqTrp2dVXaMqHALAyB+7lryMi5JeJxbWNA==
X-Received: by 2002:a7b:c048:0:b0:3b4:fb26:f0f3 with SMTP id u8-20020a7bc048000000b003b4fb26f0f3mr26579009wmc.115.1667392101018;
        Wed, 02 Nov 2022 05:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d205:0:b0:228:ddd7:f40e with SMTP id j5-20020adfd205000000b00228ddd7f40els8247993wrh.3.-pod-prod-gmail;
 Wed, 02 Nov 2022 05:28:19 -0700 (PDT)
X-Received: by 2002:adf:cc92:0:b0:236:77f0:ef5f with SMTP id p18-20020adfcc92000000b0023677f0ef5fmr15251243wrj.198.1667392099790;
        Wed, 02 Nov 2022 05:28:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667392099; cv=none;
        d=google.com; s=arc-20160816;
        b=xFrMR7+GReJsllGgWt7OIDN4/UUxALOxY0jJw1FmtfP4sx3gQnf8vGum2Nwv6HAcVP
         GpGsOL3RcJmnTdwc8jomyosAk4lE45HuJBJHaz5C4b8S0i02PrsjdTKptD9sUT5XjtIE
         Vqu44sN4o+lUFKV4UWqbc8Gt+DJF/MF7VO3oGC45zl4VEul1iFFFEQYSL2GbF2Owra38
         FF8TZ+wXLRzKl63pWmu7o3TLlV7dIzOg8QMHbPyALLqwzNXVEkLR7tQaB8N20WE6QW01
         7SMtUe/GTooLOf3dFgVptRz9v9u67IF01jun3hTzNwFwjf8EvegLP+tP07/O4ZYm+oA8
         qdqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Ij9RuvNXBdqYNNQVilL0lDhT/mtl+xBPfqcxgJWA3ds=;
        b=sCnJT2L8OAzTT2IEntYJKM0bD/IQg4xS5yjpemFEXlKHysjmXnMP5hkWqznbOjJH3j
         QCI/ajbJpF/ENlZpeSO3acYpd+M85Vycs7M4eOZbH2AltztidVjahkQOA8E28vTboKi9
         v+RK5DmtXEMGzg7Qm/aGD6VUEnSDp4mabU8ZjWLVIE19MNQucuFe8msqNvyHTAeU5lPh
         YaVY1zh7S65qsy1gN8QRcJNOcZCcTNnggvCcKbuiRt0PH8VixSap3zABvrzsjAls3KOu
         4xi0dDuxrb9+gszmlyVMG/sN9ALae8B8lNuNNDe8Aqdxwiyg0x9uhl39iiYwKfNr9tgT
         ZnIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WExcMboC;
       spf=pass (google.com: domain of mistraciaw0@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=mistraciaw0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id ba24-20020a0560001c1800b0023677081f0esi418450wrb.7.2022.11.02.05.28.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Nov 2022 05:28:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mistraciaw0@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id s24so24863155ljs.11
        for <kasan-dev@googlegroups.com>; Wed, 02 Nov 2022 05:28:19 -0700 (PDT)
X-Received: by 2002:a2e:bd8b:0:b0:26d:e6a1:9a41 with SMTP id
 o11-20020a2ebd8b000000b0026de6a19a41mr8809174ljq.204.1667392099368; Wed, 02
 Nov 2022 05:28:19 -0700 (PDT)
MIME-Version: 1.0
From: "Mrs. Johanna Maaly Bob" <johannamaalybob01@gmail.com>
Date: Wed, 2 Nov 2022 12:28:02 +0000
Message-ID: <CAEmyYRkk8YGRxG9G84Q8+oXG9qALByHwTCHdE-6qY3cVLXLRyA@mail.gmail.com>
Subject: Hello Dear,
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000c8c3bb05ec7bf9a4"
X-Original-Sender: johannamaalybob01@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WExcMboC;       spf=pass
 (google.com: domain of mistraciaw0@gmail.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=mistraciaw0@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000c8c3bb05ec7bf9a4
Content-Type: text/plain; charset="UTF-8"

Hello Dear, I was wondering if you received my email a couple of Days ago?
I would like to have a personal discussion with you. Please give me a quick
reply.
Yours sincerely,
Mrs. Johanna Maaly Bob,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAEmyYRkk8YGRxG9G84Q8%2BoXG9qALByHwTCHdE-6qY3cVLXLRyA%40mail.gmail.com.

--000000000000c8c3bb05ec7bf9a4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello Dear, I was wondering if you received my email a cou=
ple of Days ago?=C2=A0 I would like to have a personal discussion with you.=
 Please give me a quick reply.<br>Yours sincerely,<br>Mrs. Johanna Maaly Bo=
b,<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAEmyYRkk8YGRxG9G84Q8%2BoXG9qALByHwTCHdE-6qY3cVLXLRyA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAEmyYRkk8YGRxG9G84Q8%2BoXG9qALByHwTCHdE-6qY3cVLX=
LRyA%40mail.gmail.com</a>.<br />

--000000000000c8c3bb05ec7bf9a4--
