Return-Path: <kasan-dev+bncBDW2JDUY5AORBBE4SOGQMGQE62HAL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BA65461597
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 13:56:37 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id d9-20020a251d09000000b005c208092922sf22761506ybd.20
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 04:56:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638190596; cv=pass;
        d=google.com; s=arc-20160816;
        b=bbYXnAQdFeUWut5e2iTjzM/eo2Qs9McA73E3VO0THWKqYE8VKVwCV0ofE1QXWG4256
         zFJ3Ra8sJ0N2KuNdaXLgpQfVrtbQkWQCN03Qtx5OfKZxGju/HxVi5BDT1ZJ7Z/0vrbga
         bzpm99K+qckgnRr4FviDfir/QCJVqVGN7Zr5R9JiyMbcjXrga7XTmR2Jhjh/RA1UdkeS
         fbiPIa2DCohawHmZCd07LPlfHN8dEPuSaiLmFfXBeIwAjBBc8th9sYwxpGFa3ZUgIy8H
         ti+VvWpGo1jgYkE+KZlKbjj8iABcMzpZutqhrY4N1h81S+zPIVr3/o2HTJnnMZA7Pq2b
         68Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=8zRIl+NFv4pxlirjV8qHwJuqX2jbVk59gBNegVD5DmU=;
        b=oWTH/aZQVcyguYKg/mpDUDO8gZrk7JpHhybyagESD3NjUDFkXKtg89gGkCvCD1wKtq
         Du0nMivV5ZH/5wMIw1gqW/hMNmtJakfKu/cQV+Y/Z9jDn1tkwooddstK4VXr/vjIOIt/
         OheJ1umlDSf7gX7FYCJSEK6Vd+Nf4aXbTadkYspP42iI3v0ht1KwXoejeA9cFaa2X0Ay
         /M1edD5zr49vjcnbXeeiNLB+h/I47EvambINM1Y4MeAHn8Krk0mD2RZCRcq946rmAJGc
         +IGSa3Pb8qfh5Ah2RlT3DOdXtO2kVs/US8v2Fwz3yZzwPijvqqKkeX7CrTpL9L25DglJ
         qZ6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BPmA997o;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8zRIl+NFv4pxlirjV8qHwJuqX2jbVk59gBNegVD5DmU=;
        b=HGAU+wQSJicDoaYqIDp+/sq4Hg58250bxVgqIww4Vulmw7wp3nG9cnlhBYISd17TjK
         OzHNEUKh+tvayDovc53hP39rs5qZNzxsQ4uJZWpMGRPhCicGXJamyo/NHNTU+nYl7Ze9
         gsxzZguG6FyX+mbFZbmlIAuZnuWBeK97qYde8Jf9WL4j+8lcUx2VnnjzeGzREfzjF2oo
         eAa4Z1Leuw1OpK9K31py9McIAeTdEQ1fwQoI6z36WvPeSAsRlTzUqrsAxmf6+OQenWrM
         VlyP8lsAr0DmZQiEhcr14TCzxZ0DBZ27CVd1Jf5Jbdg4UzTMCTIyOgIPO47tzN5AeKhs
         C7AA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8zRIl+NFv4pxlirjV8qHwJuqX2jbVk59gBNegVD5DmU=;
        b=c8oqHpb4yHSMC1WP+pdKrorvr/ohV+Qe0vduBB9Vn4A11/nouXKGw9VsvCDDTgjT3s
         p2PnUfavlHlJ6sEjzAxQx9rUpP6UeQi82ZAHTmVa6cdg0AoUBp6oeJ1C2GMS0tljKqoZ
         a91BtMip38B84ivF/p+AjpA+WQ1VBE8jVgLp89clNPruDUkH3EckmBq2AtG/7LrLVHcY
         8tjjaYwA5AD+of0Lw3aXlXBXIDOKPdSkvp6oYYG+YvFSG6MeE3+FQqltjg3VRFXNYOxy
         TRg15FYPhki8Rv7zGmZ576gsw5W0VC67UFma4rpu/wyIPqu9PvhGRr4i8ew+CYDzt056
         3uXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8zRIl+NFv4pxlirjV8qHwJuqX2jbVk59gBNegVD5DmU=;
        b=fO+IHxzLhZGSv3Wbejp8eM9dcyXvpe9jIixeQJkYdvNcsfbrGsjABlUcrvY+CF7UyB
         jls8EpZPR4CksNQhkJ+Fkr2mJ07KYfrjIMMVfApRrF+8H2aezyawYaSUxQ8jw8sisFj2
         2CAohC2Jy/KSD4XafsfPOhKgj4MOLd+njc9uCXP+Sz0tXnsJlzhLDY+P2+sxYBg6kfTS
         RVSCH7nTEMI1W97fvoZ86NUhy3asmUqztvGBtv7vbQ475ZAPROImuiLWVlawS9w5MT/Y
         MxLKvRbCwbk9EDwmnpZtBPnDwWZnyfajY49fC/iPQ5uRdAhSwU/twaIjY5hZR0arfgY+
         ckww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532N2bmCp1WD23DuVExcW83YHfl4MOxElUK5oulQAVifRcqWfF4W
	sA5/cftwyugEX7x/LkZMyRM=
X-Google-Smtp-Source: ABdhPJwjWYAcCq+wU6rUY8K6b8m7o5M8L7c3w65SndIles24rkBPapYkvm6oRXThOvxBIs8wJlnrOA==
X-Received: by 2002:a25:38cf:: with SMTP id f198mr32836921yba.438.1638190596492;
        Mon, 29 Nov 2021 04:56:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:25d0:: with SMTP id l199ls448611ybl.6.gmail; Mon, 29 Nov
 2021 04:56:35 -0800 (PST)
X-Received: by 2002:a25:4cc5:: with SMTP id z188mr31913039yba.248.1638190595922;
        Mon, 29 Nov 2021 04:56:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638190595; cv=none;
        d=google.com; s=arc-20160816;
        b=q7VeuPT01CynXzbNfgmiFr9kdqz2WXM8QmlCxAGxopaxK8Q04PwjTbrvgd7WZw9ZwH
         +2a383cdPP8UapipFCsYQm/FKixtcxpLRKfKccBoFbIvNSQfodPn3f7H0Z5WdBhHOqeo
         mnJsA3Um9Pts65y5aqLxRmt1SwHnwznTx0n8YLMeVouwkAQLbnpBNPOJnfwAIzdiOs+O
         GS3Dca2qAZjF4h6CNhW9ku16xTeC1OJu47JSL//fzzSDq1LEyRFezUBG63TGSw7O3Lzp
         uDP9J3a/fWQAQm97kVxYaowjm/AOtHU43v63U1/Ye5BeqCiwZDhUvr7hKjsIowcgsMgh
         uAXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CKtqbicwgTdzcfDDVJ9s3/qtMRbUgp3KQEuBry1DrH0=;
        b=ZiSTs4FW9eR2IsyUsliVjJw/e5IPdOMN1WaIi7KyuOtdLi3LT31oPXDJijcKNNhW3T
         W0XxrB+Z7kfm1mSxWxTb67qlls8kkhjlFqcUrv4tacSsTcXIxRgraNEc91TMKtF8y5vp
         C1X5tukw/9L9F8Psqpul3rtEq1KzthhjaqDn1CdFkZjJjtc8tJebf41tP8NWsx21HKpi
         /ehXcjK4o42Hg/cwvfWgu+gHi9/qtDUGSMEbEarD4HgiZwfVbyTASrp728hJEUx4iniz
         eWJC2kpkfr8R0K/aGdSSN+r1dS+sKsfgf/Z7Kh/bss8VqAeSS4AmFwFYlcssNH6iRY0C
         2Z/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BPmA997o;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id k1si657233ybp.1.2021.11.29.04.56.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Nov 2021 04:56:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id m9so21405613iop.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 04:56:35 -0800 (PST)
X-Received: by 2002:a5e:9b0e:: with SMTP id j14mr59665497iok.127.1638190595204;
 Mon, 29 Nov 2021 04:56:35 -0800 (PST)
MIME-Version: 1.0
References: <CANiq72kGS0JzFkuUS9oN2_HU9f_stm1gA8v79o2pUCb7bNSe0A@mail.gmail.com>
 <CACT4Y+Z7bD62SkYGQH2tXV0Zx2MFojYoZzA2R+4J-CrXa6siMw@mail.gmail.com>
In-Reply-To: <CACT4Y+Z7bD62SkYGQH2tXV0Zx2MFojYoZzA2R+4J-CrXa6siMw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 29 Nov 2021 13:56:24 +0100
Message-ID: <CA+fCnZcUEVDWZTUvD+mbe2OrnrpJCC_OB66YMvbZYak8sKg7cw@mail.gmail.com>
Subject: Re: KASAN Arm: global-out-of-bounds in load_module
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-kernel <linux-kernel@vger.kernel.org>, 
	Linus Walleij <linus.walleij@linaro.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Florian Fainelli <f.fainelli@gmail.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=BPmA997o;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d30
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Nov 29, 2021 at 7:37 AM 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Sun, 28 Nov 2021 at 01:43, Miguel Ojeda
> <miguel.ojeda.sandonis@gmail.com> wrote:
> >
> > Hi KASAN / Arm folks,
> >
> > I noticed in our CI that inserting and removing a module, and then
> > inserting it again, e.g.:
> >
> >     insmod bcm2835_thermal.ko
> >     rmmod bcm2835_thermal.ko
> >     insmod bcm2835_thermal.ko
> >
> > deterministically triggers the report below in v5.16-rc2. I also tried
> > it on v5.12 to see if it was a recent thing, but same story.
> >
> > I could find this other report from May, which may be related:
> > https://lore.kernel.org/lkml/20210510202653.gjvqsxacw3hcxfvr@pengutronix.de/
> >
> > Cheers,
> > Miguel
>
> HI Miguel,
>
> 0xf9 is redzone for global variables:
> #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
>
> I would assume this is caused by not clearing shadow of unloaded
> modules, so that the next module loaded hits these leftover redzones.

Hi Miguel,

Adding to what Dmitry mentioned:

The code that's responsible for allocating&clearing/freeing shadow for
modules is at the very end of mm/kasan/shadow.c. It's only required
when CONFIG_KASAN_VMALLOC is not supported/enabled.

As 32-bit arm doesn't select HAVE_ARCH_KASAN_VMALLOC, perhaps it needs
something along the lines of what kasan_module_alloc() does with
regards to clearing shadow? I assume arm doesn't call that function
directly due to a different shadow allocation scheme.

Just a guess.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcUEVDWZTUvD%2Bmbe2OrnrpJCC_OB66YMvbZYak8sKg7cw%40mail.gmail.com.
