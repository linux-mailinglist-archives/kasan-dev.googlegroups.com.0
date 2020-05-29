Return-Path: <kasan-dev+bncBDE6RCFOWIARBDM7Y33AKGQEV3ZRQWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 91DED1E8B77
	for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 00:41:17 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id f19sf347094ejx.7
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 15:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590792077; cv=pass;
        d=google.com; s=arc-20160816;
        b=FdR+Wb5PMggUKQI4ZskIYhBJOO+x8rHY2flQPfdtvbknP/ppUodoMLgCqiYyWLXk4b
         hwh4uK6PTgPvN3ijJQyVz2hixVf8oKL4K4iq26o2J5tN2nzYMwNQCv6Fohv8c5Cfy356
         OonWqCGPO0aacVv3PgpNp63xILb2MdV71+USAaqi8AcxD/lwsOj30HpNY7NV/T4sB3Ur
         mJadEtT++7MEgZBrrXLIPl1FWWavFkSZeHTdszHgYxaqKxjISdVuyM5knXGfoPmHafjs
         PZs+rKxPIphAro7MNEQC7EoMlkTBasuuV2bcQhoCLboWumDWDTdCIRgbVQbjKiRBosKT
         nlIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=s2ZzdY06M/Q7cggaXvO4yzJ6SfLRXKrzPCfd/TeFhQQ=;
        b=bQbBBbltdPCuSqC0tZmRweYQJ7oAcBpbPUqt7XvpiK3TJl5TnboQYo2NHGwMuv3ZVL
         nco9Ce2gfl+0FXNpjnnSwjI9B/mu6hiHa3xoNySbUXo44s5zgd6qorfBc5RFwhHFLn4V
         u3PW3Kn2V+pwk2p5rW3/V5v6J6YLSJstF26IlwkFuZXA3QuDCdesMGKoOgUzyV+HPWBe
         593JhpwbVw4g48dMh0NZmZx32xduE2L6GUrca22E/dqs8ytIrpc7AFBaOyq2esyBqZuT
         /T+6YtUydWrRsxlRtWQAYjWdXmsRssHRyA3pggBza1Bf9iKGZ9jh+tjG8Bbdsq3jHFQT
         0yAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="vep/vTK6";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s2ZzdY06M/Q7cggaXvO4yzJ6SfLRXKrzPCfd/TeFhQQ=;
        b=X87mXvpvAq0Dst2Tu8HkvRlJsi/kV4QeoPjpgRF4UqgXY6PhH7ArXxMqQSaEzqhUG+
         3o2B5/0ESj8Ez+bA+kDBVS/TutBFUaeIlxx6Xff5Zdpe5hZXnWi62oVudMuPA2ft1xdk
         vxTsK+h69s29X3vDQmdE1xCpmq2A8yorOJT0cJAkBVWJPmzIVdB5O6JlrOp0GxzzKasY
         o/IbxKrt3NmU9ymQkWfnDXu4WlD31eUSaMDp4VBbvBk3gSU0vekkolF9V9UDM4t2/QBB
         ucMHc1uOcENq2L6yQ4Ow9/Q74B/CZXz8os3kjaF6ozSzQkLrSb/ROV2miHmkNe6J9TIx
         bQJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s2ZzdY06M/Q7cggaXvO4yzJ6SfLRXKrzPCfd/TeFhQQ=;
        b=V8dzjpattFTalezryK/yYd1FnhoaCRXzvCneTjlcRKhb9TxdXV/D955PJcRDtdZJut
         zi91OhS5DRz5WqcPRwev/LioVHbxXOnA+U9Ep2Lbc/2HnrSLj0yrpUsuloEBA/lgr2bP
         Bbc9PNW7MjRPqcb26GIPrSdNq282a5cSSbyeMKb+QHIGmuT6Y2dATJlyPR/dUgprfACQ
         pbqFf7m1JVdICV9FJiCd9qWeAH9P1lFJ+10HRZpgZWgA7mwQJclSmcCOi3ExoPY8971G
         7V7jE2QCba8hLcnAknGE3C/wU3r/0Qmze2aTnLniS+BqtTYyuv4ArikM2v47CSLJHyjw
         OxKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339uVmU9MRD4gvCKKwZojotGSI8K1p1k3wM3uJfN7yj4yDwhkBQ
	cknL/S6kZelJ1qYfQfxpc/8=
X-Google-Smtp-Source: ABdhPJzZPtLjXHVKmXP9hL0jl8LwhCi+i8s+gQE1FRlRGvEi1yZCe4SPJ0sFzYoP5yzwaq/wqfJOXg==
X-Received: by 2002:a17:906:4886:: with SMTP id v6mr9988862ejq.11.1590792077276;
        Fri, 29 May 2020 15:41:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1004:: with SMTP id c4ls610520edu.0.gmail; Fri, 29
 May 2020 15:41:16 -0700 (PDT)
X-Received: by 2002:aa7:d84e:: with SMTP id f14mr10832228eds.195.1590792076759;
        Fri, 29 May 2020 15:41:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590792076; cv=none;
        d=google.com; s=arc-20160816;
        b=GustLPKQv8BV2Wmg1qkSzHC37bZxF86mDsDB/Be/LISt1mYHnc+8fFnp5IytsG4jn7
         Ah8+nLhgYLTO1aEwNC98xVVXtwwtVwxZx7eNWlJeQJbSCTiO6bKX9XUzCjAWfBmUm8U1
         picQYirEj8qEZIVGV76tVGv4RuZfwXr70qmloTd+Ukt683B0Wr50zh9AxUOUQg2DpMqh
         lFeuq9KpD8kENa6dxegv/yHeBTwpvps71Na4ixSpw4+Hyglgmy+t9BYjLI+rO5AOZemU
         8Hs2fQMZMdCdJ5pLenXAZaF7CNF/9teMLFAie57WBJvugw++vs0xQIBH0NcnUIxSKIx6
         hORg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X5nGTm95lYY81sEpJ+H/eeZOC54JCxUcaG6tww/QNbQ=;
        b=ShZxZedMDjqrBCXd6sGAOidvtsymi9QIWSLl2FfVXOIO2FIMIvvrk0+toqjuH1hnSb
         Bd3NWSaK36dvhQ4lvFqYVmcRHMiaC4nX3sMLwFCsoagBkUDyF6CgkxBYPbwHmuDjPRZ9
         ObUOgoYaKwforv7L5s2HJSP8Wiv29ipDcTIanJlgBUV4Z3O71Q9ZTvifEGHIPZv5+dGO
         84ijEh/0kkZtF/E4B1wxL4uVBxlxCGi3jH0n8uCiysJ2Au2CkIKASETqtT04QgjfVkKt
         Lg/uLt6ncyJAJlYAsp++0R5nEtCdnzmm9R84vK1uqtgFNgg8Wh2XZsWelBN4NZypJDPO
         zqVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="vep/vTK6";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id m17si474083eda.1.2020.05.29.15.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 15:41:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id c11so1210886ljn.2
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 15:41:16 -0700 (PDT)
X-Received: by 2002:a2e:b5b0:: with SMTP id f16mr5418396ljn.100.1590792076101;
 Fri, 29 May 2020 15:41:16 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sat, 30 May 2020 00:41:04 +0200
Message-ID: <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Raju Sana <venkat.rajuece@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="vep/vTK6";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Raju, Dmitry,

On Fri, May 29, 2020 at 9:59 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Fri, May 29, 2020 at 5:39 PM Raju Sana <venkat.rajuece@gmail.com> wrote:
> >
> > Hello All,
> >
> > I started   porting https://github.com/torvalds/linux/compare/master...ffainelli:kasan-v7?expand=1
> >
> > to one out target , compilation seems fine but  target is not booting ,
> >
> > Any help can be greatly appreciated
> >
> > Thanks,
> > Venkat Sana
>
> Hi Venkat,
>
> +Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).
>
> However, you need to provide more details. There is not much
> information to act on.

Different parts were written by different people over time,
Andrey, Abbot and Florian, and some by myself as well.

I am trying to finish the job and it is starting to look good :)

I need to rebase it for v5.7 but then it should be in mergeable
state.

Please try the latest v9 patch set:
https://lore.kernel.org/linux-arm-kernel/20200515114028.135674-1-linus.walleij@linaro.org/

You also need this patch:
https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/

You have it all in a branch in my git here:
https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=kasan

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZzj6MRJk3sFN%2Bihw8ZksZ-WF%3DCJNsxuazkAYPmd%3DKi_Q%40mail.gmail.com.
