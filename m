Return-Path: <kasan-dev+bncBCHLP47IUYKRBAH3U2GQMGQE3ATUWNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EBD2467234
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 07:47:29 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id bm9-20020a05620a198900b004629c6f44c4sf2310769qkb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 22:47:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638514048; cv=pass;
        d=google.com; s=arc-20160816;
        b=DV2WqiH7Fpy17QornFM9qySKddbu1kHFH9anU/hZL78cNw/Dsu62ChvlLbgb8/BkoX
         bUsAqHUSPofICserRb2YuPubiWhynVyXHdZN5SbHNDr28kVuAxW3EXEpy3zluM4dMCWD
         AtXaNMl/NiX1aQt6vB4KtSy08qEV6IGFtdeH9C6gE7UvSbTNfI/KGzUkL/gXHL/Y1q+b
         X+ZdLXdG3U3jjLa7nx4Lwdi785aEe1rSUyB1Gp56uyGyc1VTL9Ul4PSaoExsQSkfgXzU
         0YO+PPoe+GJGkKG3h4gpngnlMPQAWBlhatvzHLsvSFoxEM0L/aXc6o/gm6s1ZfXNv7kN
         PEqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:to
         :subject:message-id:date:from:reply-to:mime-version:sender
         :dkim-signature:dkim-signature;
        bh=jAPJsXX9JhEmfoAwbfwiz5xFrcCg4TOYN9/ZtAQ4tGk=;
        b=Q32kyxrivCOdatqTESgJdX69e+RJRV9cU67csha4ODet9on/qxSXAF8fEobn1Y7BQ5
         mJiEmKeWjTICEAizegeemC+O44L461bfgoxoZpEt13GvZCXYasnzbl53PX7JWclwKqOz
         FGTkH9VXktNGFDbj5cUd4svmN5T3y2hlGFnpukK8AkODdFpFH4zAOM3CQFS95Ud2B35N
         J7WMq8YVPo5CQU9mhWKDoEPOylXBvgUK+YVqQ3mDis3M2O4+q5PsuHAseZclRv6iDfdK
         Ty2Lbbtg0infkwFnwpXTFlQGw/3CaxEMnCYFHeQjQkHHi5WXcIKeSSp4Ecras2L761x7
         nS+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZTJpxeGb;
       spf=pass (google.com: domain of ericofili5@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=ericofili5@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jAPJsXX9JhEmfoAwbfwiz5xFrcCg4TOYN9/ZtAQ4tGk=;
        b=Q8BZIRQV1gbPCJWJle2f7fqK4Je0Dd0C9tmI6N5mGjB7XcJbT3J6C7/eFp6+P0jgwD
         Pp+hkLvQrER2ybp9WTMT4sCAE9Wz5PhyyP9EdkpZu2Y/1wm8DqUePPrlTDaOeEx3L5LB
         /fuQmJOlsdY6gI4KvszJsGeA7vnkSeTshmyu3FFppenlYoe1oru2teG7Qth9AMZrgmm5
         lgIjH/TFhaYGk5giyJpBiwXu94h0h0tUFoIJCKuOXIh2EBoqdhW+3s8XsN5VD3CywRGg
         FuptmUN9JDnKWLxeYY/NpVwaLvNc680Xq0gcVkRV3FAbDR+UGbygQsMN8TTo+dMVReIZ
         N0iA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jAPJsXX9JhEmfoAwbfwiz5xFrcCg4TOYN9/ZtAQ4tGk=;
        b=iqns10NuMxeuVm6EGRGMXl6TK3AvIqq4TKr6SEg3dOFD1EoilQ4yIXvy5g5RvGASq8
         5GT26srXFfg6Zu/4SGqcjyfLT4YNGRy1p5wXqDPLBMQ/HABlrNVy21baEbFYN+FzQWmC
         N/228mzEmVnA5wePBgFEWJZ1zoeLpwaQy6CBNvUSkaHt1m1WBmk3q2AAsOcLvwn8FXIj
         osg94yn+5KqfjoiIyvNNElIsH0RNPdtzarxao6uPpWPmXehKVdnbJj9e8vNKPqKEF6B+
         gCWQ1/Y5JuTaqWOCcZHaRSulzGbD76bQabekgslojpERE6/AQ8TsIpaNdNm4ld625Nan
         2FXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAPJsXX9JhEmfoAwbfwiz5xFrcCg4TOYN9/ZtAQ4tGk=;
        b=ptACWIC+aaQII0+Xz0RFgZCmq10/nT6o78rblQHxgE3qZJ/zmRlOIon0QoSkhSPneM
         lf2EErPN1waI/S+TTMtLtcnjow7yY5XAfqLjMfS5ye5qWPMG98nUyoeVmYS74ftC89UD
         JXH8H0BgbCTeVVWzkgXgtYQsiaCl58jB9+rJV1znyAg0WatHdbPNgZ4BzghJeJdnlEyU
         Wjycm89XWhll9OpNkFfcoV0KwfAwfJKG9cN4HZxnQOPyqAwyH1q3wdDyiEDwY9jhidzk
         hd9mGbHbj7POZRY3xFrJ/yaehC6U1N1kLX8w18wt+DRgAZ+89nH1kkEHxlxAr8lih2sn
         YarQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rGbFFBp/Z7JakE1Xoby1ogEzzkmAGlL8Uw4N4ECRLjvudSmNM
	fWSxQIPJ0NIwGe24sfeDEaE=
X-Google-Smtp-Source: ABdhPJzchsC+GN0mKTdKnEb18Ckc6aFqkuN852vbaKFTGMYxkTbCCXzz2wL0GOyfu/gSYQw5ZGuTHA==
X-Received: by 2002:ac8:20f:: with SMTP id k15mr18622905qtg.173.1638514048222;
        Thu, 02 Dec 2021 22:47:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f83:: with SMTP id z3ls5896802qtj.1.gmail; Thu, 02 Dec
 2021 22:47:27 -0800 (PST)
X-Received: by 2002:a05:622a:48f:: with SMTP id p15mr18880841qtx.246.1638514047746;
        Thu, 02 Dec 2021 22:47:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638514047; cv=none;
        d=google.com; s=arc-20160816;
        b=Xp9Qyi9tF06v14JlfaivoUprBl9ne8F0WrpfXl9MWVI2P0TbzYCuPlG8snvDPw/lx9
         yXNFbVtZ8IfVsqjyx5RqdPhWgO3+uB2Dwde2Y/92AKwV1JCVv2NkPzyvGG/75/ftBMj3
         tQeRMRqw3Y73yFNjyMiVttuyjXxn1Tf4J+Ws5VpgskuYc9Qcvb1afBwhXxpc6J7m2mXH
         Dc8/mY3arSNscngcTw9ZlS2lbAZUnb92QHiJCOjZIGfExmL4q3aS5YIemn1HEJRcwLWr
         ELrOdVMaXrxDd9VnMbTRqIRN7i5V7YCu+KsT6LMKry1Ghld9/bMyMKUxbaPIlkZU6hZK
         splA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from:reply-to
         :mime-version:dkim-signature;
        bh=2Mv9jrqjT3MhcoaOxxXoXpTQsXNDwfELgjBdMyKMz0g=;
        b=sC0VzDIk8qn15LosKFkaPRmgzKdnllD1G3Nmn+NpdCOIbVKheOSQ2CiHsVh37wZhVm
         t7IVjltH81OionDvDYdohyw4NrJpSH2Pjge9O3ZOwF0i1u3T1UVrZb6xpxSCKwNcAiih
         b/ahyBB6QdTj8wJKN89zklao9qZJcd7/NBR79ZwE+6KcJMY7RHAaLiVvVMBCIU8dgTm0
         /jGoRONp8bAIFExwAkS0a+wZgQUbltyfL/RpsyuaRrwlLZs/4uqtGamEIvDXoIhbFaYq
         vKJ+T61oeTIyHKFvVqzZemzkoMvDZzPdTqlBsxd1SRwHWmiMxKenst7mYXf4pa7Lo3RR
         uIAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZTJpxeGb;
       spf=pass (google.com: domain of ericofili5@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=ericofili5@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id n20si289867qtl.1.2021.12.02.22.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 22:47:27 -0800 (PST)
Received-SPF: pass (google.com: domain of ericofili5@gmail.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id y5so3626311ual.7
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 22:47:27 -0800 (PST)
X-Received: by 2002:a05:6102:292c:: with SMTP id cz44mr19768992vsb.9.1638514047132;
 Thu, 02 Dec 2021 22:47:27 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a59:8852:0:b0:262:687d:8d8f with HTTP; Thu, 2 Dec 2021
 22:47:26 -0800 (PST)
Reply-To: jeffery1@jefferylambertesq.co.uk
From: Jeffery Lambert ESQ <ericofili5@gmail.com>
Date: Thu, 2 Dec 2021 22:47:26 -0800
Message-ID: <CANNckNuGNJjNPd7H16teCaqqqY4UcuiUsrQLdoskFbAvCFwdog@mail.gmail.com>
Subject: Can i trust you?
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ericofili5@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZTJpxeGb;       spf=pass
 (google.com: domain of ericofili5@gmail.com designates 2607:f8b0:4864:20::92a
 as permitted sender) smtp.mailfrom=ericofili5@gmail.com;       dmarc=pass
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

Good day,

This is a personal email directed to you and I request that it=E2=80=99s be=
en
treated as such. I got your email from online directory; I would need
your assistance in re-profiling funds belonging to my late client who
shares similar surnames with you. Contact me for more detailed
information.

Regards,

Jeffery Lambert ESQ

____________________________________________________________________
This e-mail contains legally privileged and confidential information
intended for the individual or entity named in the message. If the
reader of this message is not the intended recipient, or the agent
responsible to deliver it to the intended recipient, you are hereby
notified that any review, disseminating or copying of this
communication is strictly prohibited

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANNckNuGNJjNPd7H16teCaqqqY4UcuiUsrQLdoskFbAvCFwdog%40mail.gmail.=
com.
