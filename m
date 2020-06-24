Return-Path: <kasan-dev+bncBDPINV4F24ORBK7SZL3QKGQENLRY7RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 63603206A15
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 04:23:40 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id f5sf1593519wrv.22
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 19:23:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592965420; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ne1k8IIz2ftdBxTTCfHm2JgwKaUprVgfs51GgqmMgrYHufoZoaIwpAc3Feil65fjdG
         y078IJB53OnZp+cU36c6plAadEimXzhgYkyXmljzOSeRfkpDyvkPJpvF4HiqUG7Ro1TG
         rhAg0fSRqogg/RQFpyg7mKfnkv0mnICpSQDCBEdAQlRSKKAkDs8ONXVAduZx4hX+hVAh
         4FRCvEW69jYch5OxGLriAal2nVqOckD60J4aIJR/6jg/4auSgSYgSqsQoLVK/Bl3j3Zu
         WdMAi1ajI74P2BQtrHcol4T2aFRBw4VESPAqhTqqnxUTrkkS9G3QqrMHRDNnFgu09DZi
         HehA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:reply-to
         :mime-version:to:subject:from:sender:dkim-signature;
        bh=ZJ/sdJH94bTozUHzvz3zZfK6kSVTtwArmSxT9/EHC7A=;
        b=meflCX9HkjZboY7CEKj7Tph6dUD/i4Xk7MHcLA1/AIgDQZjKSv+OrEZfPjtXODXU1T
         d19g/5tO3lOYPUMLPmjWUK7++V5ZEoveLm0Bd9uOV6sMEbmJ6u8oAGQZ8rxObYJccPVR
         8Ti10Ik/mJU4sXxae8qkWx52q4lVPEqy73/XytLUafLmsCEFx2ToOdiJanvVGj70cDZB
         L7bNygZYgR0CimR/9j0G2MuohZfchMKw9hQSIId+2Tsye77y26y1UtxociJry3Zs1MeF
         khsF6n3RCC85eqHUlLORmNdzF96nOO1SherwJtVZAYXkfytQgrQBFCXToWftQushgCJ2
         VKpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning karen@pei.com does not designate 80.12.242.135 as permitted sender) smtp.mailfrom=karen@pei.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=pei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:mime-version:reply-to:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZJ/sdJH94bTozUHzvz3zZfK6kSVTtwArmSxT9/EHC7A=;
        b=AEop1uFrJZ+YY8IoWtSJyTJw1Jl2YqJH3SvzS5JE/3Sf57Qm/3scg91RlgApcwZXha
         XBT9EZGhUndKaL3JxIsRdes/hwREcKVcb4x8GAnUmRwk5mQ0WyygO6i2jzeWMB+UD1XC
         2H/IuzzZnanyqL8wgYJUoKUQr/P2EzMhgWdFTEQC8AwLEFAElFzEnoQx/0KvVW69e2G/
         wuR2fMoaBrz+RsqCPj831lWZhehPyzs6CPwEG1YfFQ7izzObG7aQ2Ty5T0m56WmtHyXg
         rySyBcCJ1CBiqxzsDilR5p972iM3gh4a5uhXeAZpnARJPqdnBgb00u8HEUtqXFALy3ra
         kIOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:mime-version:reply-to
         :date:message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZJ/sdJH94bTozUHzvz3zZfK6kSVTtwArmSxT9/EHC7A=;
        b=Vm6As46Cyp9zIiUkSIN6vKGVv/qWLuceT7H6vG4CkF2ISeRbGEiP4XFjLF5F8z8FPo
         Yy1f/nponBiI+6Axg8EwXGEHoEo34Ew4nZtPIPwGVxQ3MPe8h/QkhOwPtfVu1G75to8N
         8pDW8hdBgfkMne//zkvpvnn5quJ/d575FBzy5wbPE22JMZrJ0Cvz6ZCC5V/mMqB5Vqxj
         jyDpYY37180VETx0/Hk5YKwK7f11sJiqrprSNBCvOr2i59hvmh7i5m7jQBNfUg0RJc3T
         UkBackrA+uX7J8jBJ0t4kwLvDCe1yElm44lT4yV9ckwcof8C2sqFVbR0gI3sWBG8SmWP
         s4ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532S/v+aaKsG+a8DebwmojPwy3i+5EVkB+AMKvVOOCWRDuG4+9Vp
	d86oeFMYXJoL4eyxaG/72fM=
X-Google-Smtp-Source: ABdhPJxPhVfeLPAr2Pb4K50HudtXV1G087jpxjqu6XKPKHB+lYR7P2lO2tA2II3h96HDb3HZDgfZZw==
X-Received: by 2002:a7b:c090:: with SMTP id r16mr28493083wmh.105.1592965420038;
        Tue, 23 Jun 2020 19:23:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls321717wmd.1.gmail; Tue, 23 Jun
 2020 19:23:39 -0700 (PDT)
X-Received: by 2002:a1c:ed17:: with SMTP id l23mr28657987wmh.73.1592965419570;
        Tue, 23 Jun 2020 19:23:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592965419; cv=none;
        d=google.com; s=arc-20160816;
        b=xRDMN8000KCUdMu8X7Aj04/45lKU+bTLIdlUBT7/kO7B/FCOARD65Zsx7MVm8HiEf5
         JmZf1QFnWsbh/hu27XOW0C1QdTCIbgUf6RxauMlz6kRqPJ0/Ln1chfHPQyzBHhdmSdEk
         68sIP22FG1hQkSC8Txo+7Nj3Mfy1gbMM+CRdI5Ln3A/I2xqLRr0lwEhF3VpFcO6lV954
         MazWpKChM76p2pIocQo6FvzEnRb1vA2qdnI5p6hy4MrXUCWluzCaAMiQQM4gwSrSqV+a
         G8pHd+vaax5olgwkj5Wa/ZTQ9HeFU1HjHUdBzUrkDHQ7MFJOhDq/COtk6mTI/2S/h8mo
         p1ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:reply-to:mime-version:to:subject:from;
        bh=q9RX3tFbp9ucdcWO0RK9efoACfY6L0sm+6B9mIScKa4=;
        b=aSXmZvSodDvNTtobH/j1MBUI0WLCEpLtyQCcO2Jr30dovtha2wihYiE6otnX3Zv2nD
         WtBVB/cajovSfMPBv1e1jpSJaKnLRgTVhhzGkA8aKcSylK9sxtQbd/X4Oxouo7LmVp/i
         zJDNQWB7RyMIN+LAvSTv19QwHcbpKkl3BC6xurqZr9QVmMiuznxCQaDKQrOtt3zdwTWI
         JK299GHVO+1jXEC2lYe01T1tg3JHkEWSXV3L1inrQmepQLK5YaSI8OFygYxEFePEWUFA
         xUM/GKA9DD/oWpr3VbSGpBpqmwr6iB0dvR1Tq8xfljhoji2z4LDnvFq2jYk+sY/yf+0g
         NSgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning karen@pei.com does not designate 80.12.242.135 as permitted sender) smtp.mailfrom=karen@pei.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=pei.com
Received: from smtp.smtpout.orange.fr (smtp13.smtpout.orange.fr. [80.12.242.135])
        by gmr-mx.google.com with ESMTPS id s130si195577wme.2.2020.06.23.19.23.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1 cipher=AES128-SHA bits=128/128);
        Tue, 23 Jun 2020 19:23:39 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning karen@pei.com does not designate 80.12.242.135 as permitted sender) client-ip=80.12.242.135;
Received: from DESKTOP-Q5JCF6G ([90.3.146.230])
	by mwinf5d71 with ME
	id uqBE220044yUvma03qPefx; Wed, 24 Jun 2020 04:23:39 +0200
X-ME-Helo: DESKTOP-Q5JCF6G
X-ME-Date: Wed, 24 Jun 2020 04:23:39 +0200
X-ME-IP: 90.3.146.230
From: "Ms Karen Ngui" <karen@pei.com>
Subject: To ~~~ kasan-dev@googlegroups.com
To: <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="D712aoV3QpKmaCsvfYI=_ZXgktejymc9FD"
MIME-Version: 1.0
Reply-To: <invoicekngui054@gmail.com>
Date: Tue, 23 Jun 2020 19:23:38 -0700
Message-Id: <23372020062319C059EC1710$ADCB1603B8@DESKTOPQJCFG>
X-Original-Sender: karen@pei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning karen@pei.com does not designate
 80.12.242.135 as permitted sender) smtp.mailfrom=karen@pei.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=pei.com
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

This is a multi-part message in MIME format

--D712aoV3QpKmaCsvfYI=_ZXgktejymc9FD
Content-Type: text/plain; charset="UTF-8"


Kindly confirm if you got my business collaboration In-mail sent to you via LinkedIn.

Thanks. Mrs. Ngui

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23372020062319C059EC1710%24ADCB1603B8%40DESKTOPQJCFG.

--D712aoV3QpKmaCsvfYI=_ZXgktejymc9FD
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


<html><head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
  <META name=3DGenerator content=3D10.90> <META name=3Dviewport content=3D"=
width=3Ddevice-width, initial-scale=3D1"> <META name=3Dformat-detection con=
tent=3Dtelephone=3Dno><title>To ~~~ kasan-dev@googlegroups.com</title>
 </head>
 <body style=3D"BACKGROUND-COLOR: #ffffff" bgColor=3D#ffffff> <P align=3Dce=
nter><FONT size=3D3 face=3DArial><STRONG><FONT size=3D3 face=3DArial><STRON=
G>Kindly check through email,&nbsp; I sent you a proposal via LinkedIn on t=
he 20th of last month...did you get the message?</STRONG></FONT></P></STRON=
G></FONT> <P align=3Dleft><FONT size=3D3 face=3DArial></FONT>&nbsp;</P></bo=
dy>
 </html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/23372020062319C059EC1710%24ADCB1603B8%40DESKTOPQJCFG?u=
tm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/ka=
san-dev/23372020062319C059EC1710%24ADCB1603B8%40DESKTOPQJCFG</a>.<br />

--D712aoV3QpKmaCsvfYI=_ZXgktejymc9FD--

