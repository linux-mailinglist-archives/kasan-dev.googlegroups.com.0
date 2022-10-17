Return-Path: <kasan-dev+bncBCLI747UVAFRBUNAW2NAMGQEZKLXQYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id CB7E960152B
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 19:26:43 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id n56-20020a056a000d7800b00562b27194d1sf6425047pfv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 10:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666027602; cv=pass;
        d=google.com; s=arc-20160816;
        b=K9pbKf2uVFQCPJyeC4PEBv7EydPR3JPZ3L1fuIBDOEedGmSrIAvc+hIvIgYBTutm4r
         qke0EhlQPRCaINIDqX4fA77lYdzM3olh335jXlrufRk8zfMkSJzBIk84rtTE80oSFDpR
         fXzxjVbim5C7OybDNKCvwgZZ1IwOgUCpesdbwr/GvlGYzjsIxfpRPpoZChhet3wV2AWQ
         hXoUoWLJRtQc3InZYxM6ky9iJ62QMlkgEiWjmLmnR+CfRrmrKcDL91n15JLa1LpbgLEh
         wYDtC93+6wEwzV2JHDDQqreZIau6Xu1Ncgan4edxT+xqmJs9B15EJ3rzDtpFPRt68pYM
         dhLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bvTo5717uP1UxFkqE10M0skDJaVfvsDKuKPrnEmShkY=;
        b=jGq5pS57uwntctRcBYZ+KWCDyDcHCuWmZ2M1mGQf9dabNS9sQ2TZD2131Bb19zW48f
         nJT90TQMvourK6XSGEzg5X5f2G38nEdV1DyxLH/iEMEGFVVasv5LckdhnJUw/yLobI/H
         6zqzhUEBNWyQFQWJx48UhmpXzMMDf11QyeysdbxPwFppEkCn1Ce8zCzGZEgb12KiyELo
         SXK5nrrSxO0zG9Mbe2jxKWqFygAGQtw2ViphqewXaiNx6FZcs+hstRsdk1b/aF0Cj6VK
         SmWY7sN9YdqqPhVEug1ybhh84+M2/wF01WyPrztsx24YPHXjbdewMwdvSbhLZQx9Qa81
         7EVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=C17OfLTV;
       spf=pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bvTo5717uP1UxFkqE10M0skDJaVfvsDKuKPrnEmShkY=;
        b=ethT5RH61adraipkQgJ3h219AKfCvxD0GUKoH5xCjhfBSxJsaMleAGXJv9x7vXs89N
         YxKbhrd6nzEZVkXc1MBwiScaDNQ6DA8oHHVByOBj/bNKlGG6AgbJH8v6CPW3XhtBd6nc
         1zjRdyjV7eMkSXWNlA5qEwnL1VKGceThbEqlB9kqHpWYFCeotPaawlcqEIDAEP1Iwa9c
         JbQIt9lXuP30eEDUW0f3Lv0jFPXuvTvdTlaSm8efzne4uU2EuQWSPWbKGo71H6aMA3Lj
         W7tFDgImrSt2pWcojWqfzioWUlKkLDFZL3JeE93J9vJdNnbTVvpWfxL2IebfUSmojqvG
         xWkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bvTo5717uP1UxFkqE10M0skDJaVfvsDKuKPrnEmShkY=;
        b=e+6QUkmK+aOCPjYuvB2r0VKiVcrPjPFB7VjToywZ8+i/uCDdmBiwQgwRJlR+YH0RbL
         GboM1hEHPfK4KknSwPs4n7Syxtk4Bb40ZkR5A3oXXciCJ6WBn3TvWax2vFaz/M/g1SsO
         iaAgG7Y5w0kxbsw8PPNLk0AiKPAe0+Y5lcZqigHALmz5/klpRzHfHSCgGIt9kwLTGLJN
         WHB4JfDiiPvPP+AJv9aF7PfTcuU2Mwbffyov28xvdkkE89W6hV6w3ZUTDEMTQGct9vWi
         eLD2qpgc/F9Rf4MJztXLUJSbcNmGiMjCccRYwdYxdD0aSGWN90aKp7de7Z1mnOay1Yoi
         i8cg==
X-Gm-Message-State: ACrzQf1skVGWpUCJSq01UhFbIgxiB0Qgna4KI7ZGzoMlXoClZkbqJqeM
	xri3XnPL8R0Lpw7jmrF5U5c=
X-Google-Smtp-Source: AMsMyM5nSbH06dqtVzOjQ7oKpB3KqDQHJLsI8wZ3WZJOvbT1WsVQKBkHr/74X8T5mFJ5buwFspHEFw==
X-Received: by 2002:a17:902:e848:b0:180:c732:1e52 with SMTP id t8-20020a170902e84800b00180c7321e52mr13242796plg.83.1666027602156;
        Mon, 17 Oct 2022 10:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1d45:b0:20a:3bee:9aa4 with SMTP id
 u5-20020a17090a1d4500b0020a3bee9aa4ls12676350pju.3.-pod-canary-gmail; Mon, 17
 Oct 2022 10:26:41 -0700 (PDT)
X-Received: by 2002:a17:902:7792:b0:182:9404:f226 with SMTP id o18-20020a170902779200b001829404f226mr13262728pll.76.1666027601419;
        Mon, 17 Oct 2022 10:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666027601; cv=none;
        d=google.com; s=arc-20160816;
        b=dTTc6bp5YdPk0VDud/VZwLUpxvOd9nxatnCg8sAMDzyD5wB4wrrpbT/WLvRpDQmFy0
         oqSAzukt7ZICfJe1YOM3RYtOylNBtMdu3vLwTC/TzdrbprImE5oHLKlEIuMVQQlR0p3t
         FR7u7liKnVBjuc9fCvNNv4YB9HAeH1ZbfynE4fN2pT4y8RTzSIicHqp952+5wOV+10/i
         vTiU3+uuFFtVmHJOQ8IRJuUhReumEYJ/M6+pCyDrEnghNfu1Np5kfFOAumGBUkB1GkmG
         nqST1T7AjUfhLwVD84GfuDsoKBMwCtBJcHh8zNuZ1iqGAyriSgrA87S86ahTbl4LTRsa
         XDCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IUidW8NItaDXNEWCUfPFKo7TadH14Rb3mgSUQBIql2o=;
        b=rHR5q1Hcn+N82IOzfCUHat/SmzcvVQt34ltA0mi+L/TGGgjwtAK3IR6tW4VHGZgKtm
         cJkILT3TC659djHERdqNWK20w/dvtDqbjNvqhhRAEvBF9Anpv6Q/8yx23cG8ieSWRB+y
         Q+bV1fKG6PmalQtldIZTShqLlAUcaAjJvXdf8vGGayivokaiSznpMCZymzaDwh3oPxdt
         an0+0AkkbN90atPhSi1bdtsoYGZjKn5c88Z53OdUdOvso36uHt4eFhYLk0+JXymQ7K1s
         UqhZcEruT1F4vhfddRbosdD2/uhsjllxShCznxHlOy+njEFqnBASMEJhdp5lZHaa/KAS
         Eb/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=C17OfLTV;
       spf=pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b0020d43c5c99csi590449pjb.0.2022.10.17.10.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Oct 2022 10:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B281E611D8
	for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 17:26:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E58CDC433D6
	for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 17:26:39 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id d7c1d7b7 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 17 Oct 2022 17:26:37 +0000 (UTC)
Received: by mail-vs1-f51.google.com with SMTP id h3so12209744vsa.4
        for <kasan-dev@googlegroups.com>; Mon, 17 Oct 2022 10:26:37 -0700 (PDT)
X-Received: by 2002:a67:ed9a:0:b0:3a7:718a:7321 with SMTP id
 d26-20020a67ed9a000000b003a7718a7321mr4013100vsp.55.1666027596776; Mon, 17
 Oct 2022 10:26:36 -0700 (PDT)
MIME-Version: 1.0
References: <20221017044345.15496-1-Jason@zx2c4.com> <CANpmjNM7Sca3YJQ7RK14e_pzB5Wq3_-VokLum6MpqKXq7ixzSQ@mail.gmail.com>
 <CANpmjNO0hu7OHmckU7kAVu+C6Jy_M_yMxe41YmcF2oePxh7Rnw@mail.gmail.com>
In-Reply-To: <CANpmjNO0hu7OHmckU7kAVu+C6Jy_M_yMxe41YmcF2oePxh7Rnw@mail.gmail.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Oct 2022 11:26:25 -0600
X-Gmail-Original-Message-ID: <CAHmME9rTwugD49-0VRbAu72fZ8nHBQbXicSct6CPq529fWCs6g@mail.gmail.com>
Message-ID: <CAHmME9rTwugD49-0VRbAu72fZ8nHBQbXicSct6CPq529fWCs6g@mail.gmail.com>
Subject: Re: [PATCH] kcsan: remove rng selftest
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=C17OfLTV;       spf=pass
 (google.com: domain of srs0=knoz=2s=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kNOZ=2S=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Sun, Oct 16, 2022 at 11:09 PM Marco Elver <elver@google.com> wrote:
>
> On Sun, 16 Oct 2022 at 22:07, Marco Elver <elver@google.com> wrote:
> >
> > On Sun, 16 Oct 2022 at 21:43, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > >
> > > The first test of the kcsan selftest appears to test if get_random_u32()
> > > returns two zeros in a row, and requires that it doesn't. This seems
> > > like a bogus critera. Remove it.
> > >
> > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> >
> > Acked-by: Marco Elver <elver@google.com>
> >
> > Looks pretty redundant at this point (I think some early version had
> > it because somehow I managed to run the test too early and wanted to
> > avoid that accidentally happening again).
> >
>
> And kindly queue it in your tree with all the rng related changes. Thanks!

Okay sure, will do.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9rTwugD49-0VRbAu72fZ8nHBQbXicSct6CPq529fWCs6g%40mail.gmail.com.
