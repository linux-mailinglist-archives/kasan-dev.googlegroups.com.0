Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBMNGSSKAMGQEQS4EYEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 142FF52BEC9
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 17:39:30 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id r15-20020a2e994f000000b00253c43c5b20sf577315ljj.21
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 08:39:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652888369; cv=pass;
        d=google.com; s=arc-20160816;
        b=MxVFCW9A+9dJ6UdLlY+9A6lw73Fc2l6dT4kXrN6m4mWiqRWhPARocACTubrKtCXSlo
         eoirOGNKkU27OxPLTzrj1INSR/GKCPdOpt/9Q9zUJuHMpQn/AOcy8TTI1mFbmIKv4TX7
         JKG29G3MONf5RVe6lsxAp51RMRAmCCOVdBxhkQ20FgM/zscjuP1DnCfPv0ZZ7xU7NqYP
         8NogStmTfURUGbvYgLNnSv5RF3KgZ6Qe3yfy6Glu4vOpv3qLGRNpGo64cUqwLuzyhaaI
         gToDMZz99198rFQOwifJNwSdkZRev5nsPe9dljgpHatbqMZhC5HXwncSlHwJ98B6wOcU
         i+ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4v+g1eVKwh+N/dIzG0mkLiP4sndQmerBuns6w+KowQQ=;
        b=fQ4iIxrugd2z908USd6YCUTt7XRlIHmrw+lZIgs3sCmjaHkalsQo1S629/9UUwNbIp
         f/R72UeYCqcVBjgULjfqjV0CYbYXH6P6Dz8sjsIn1dE+fOwy8ISMyRAlqHhHxd7cpbrE
         TRP/Ar3I/Uv4fJ492+urBi7dNjy6HvgUN3EZnOJddIk0rUqVcoU8s5dfbPg0ffxX0Y4r
         4ncXlCpI8kGxXY8rylchioWoALgfWq+uiwyqryVhCK3G9EVcVlwJsxK96y0HXZ0tKE6v
         pRyc2LBZokJhtJqp6a3qauLh59B+r9U+sRq79loYSE9N6mEE8msaihLEn7ZHUu3HrBiT
         QdCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WHvW2VBA;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4v+g1eVKwh+N/dIzG0mkLiP4sndQmerBuns6w+KowQQ=;
        b=r28qQr9+fawg0YOS3O/F1czAzH0eT1HdEsGJ201RhqvRLL9PCmKPIR6en8ahN9xmU8
         XC9s9BIOXZyU08zuHOjFWCg1L88XzFhA94X18Sy9YUG9O65qi3NLGbTP+dM5JGGiFU1X
         0zyilBuLH6cwwezEWV474g0auSYiSgobaAMpmsULVc0o3c2tnh2Wa48GSaUo6LFBS4NU
         lqbwe3eh6/YWDbfdxYJLxFm2MHJNB7wn1gez38U/wJgJcZqBs4kjdLTlV1k00uYHxUbV
         AyL0awHmqv4Z8AkL5mWvyyUlowtnjHWTMRD8b7tHbPC3kKv5re8MvnzFB9bWiIEPXTYE
         Qu3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4v+g1eVKwh+N/dIzG0mkLiP4sndQmerBuns6w+KowQQ=;
        b=5UE82l1PcSBhJUiaX8ki4nFhsSU0msSBl79+OUMn0p7FKwfBXusat6CIifRfCnODbj
         wJg0WOqw2MInKjhgestLP6VoQeYy4mkSxpLXK764s+OUI2jyaePPwxyn3PcfOOoQ3mCD
         hNKM7HkmAsLeWApOr4tH6C2sks90j1U8abULDWPHV1GVniUDfpfTs0HEbrfd17/8UfIZ
         TnD8rcvRcltU8Y7oC7gkGFbMIoo62B3hUzDLaTtvApCvss+ao4hc7NiCtBrymlTbRxQy
         spGLKbaG2ioA0pc5uDWyzgtWDMboe/embt2Nz8DXCQtjfRE3l+XzfCOOJlbt+5d6L2yG
         ofWA==
X-Gm-Message-State: AOAM533pyAbC0IoUN90TpO3U3MKAdcKsRUKU8cLfyyoOZm+6m62uLxEx
	ToOyGL/uHueofL5MAHXIy8c=
X-Google-Smtp-Source: ABdhPJwjhPF+rRIXwjZhX+hK4lj9TnB7tfy70xXZtWeSXA0CyFKLZSXjSDQLisZ39rEXueFNbS8RxA==
X-Received: by 2002:a2e:a90d:0:b0:250:8444:2681 with SMTP id j13-20020a2ea90d000000b0025084442681mr981ljq.342.1652888369671;
        Wed, 18 May 2022 08:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls115988lfv.3.gmail; Wed, 18 May 2022
 08:39:28 -0700 (PDT)
X-Received: by 2002:a05:6512:228e:b0:473:bb91:33f3 with SMTP id f14-20020a056512228e00b00473bb9133f3mr67118lfu.101.1652888368696;
        Wed, 18 May 2022 08:39:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652888368; cv=none;
        d=google.com; s=arc-20160816;
        b=K8esN6m+1XSvighIXTVyLXIdZsLpBfddpNyivsYQL6d7P+/cUWtoW7yy/nfYuEb7Jx
         sH06NUfN0M3IwK4+Y/4+qYSyVeaGNH24AAs1lNoddwoRBZJ0B4t5dPJpJfaLZaS075Qy
         Km2A3lMe+MyGxgeSDfLdJ8bjadz530V0FZW7u4hzdUB080l7m9+hIZpaWJ9jIlwcc1dp
         kPEhYI5YNrH5LeGVeB4vup/cTEh7lVa1msjQGMvCkAIIID9aUdx/v9+4kT9e4Cd6iBNq
         f2Gaw+8fNTiT2E/B8yFb0maLPKpX1c+TReDYppU8NTlv5CgwHRQeKiR/eI2kSCJ9u+WT
         X9nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mZSb0554f2n8IO9cffG87Gnp2j/skjs0bnuEFWLNgIY=;
        b=b64fm9uDlJ18n2JJFfvi52vhcMhFS4rKR0d8s8ls8Jq/LoK5DsKgUkCBCPut+Vcps4
         WQw8iE4GtmtX46HJSUypw+OtkYOHmLf7nRYsZnp+E6tnavqDkoVm7TF6kJEpvGVsVj63
         RHKD5y/F9pwU5DXgXMxNgM7qa4SiOl46N9FbY59hsWlm6Kuw33CvvViXX1D37fUwv/WQ
         SgBRk8IPSKwDwa8zpFAqVPAMIGq94sGVapzbgg3eK0NkVsX1se4nhcdNhfVRpiINKKPE
         YuHOSRLZdiwBUKLQ4JkGicW0Gv1QUWHLYtG+7lyUZGbJ03r4/HhQKl/azy5oHEUvCPM8
         3xJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WHvW2VBA;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id b30-20020a0565120b9e00b0046bbea539dasi118930lfv.10.2022.05.18.08.39.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 08:39:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id wh22so4451850ejb.7
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 08:39:28 -0700 (PDT)
X-Received: by 2002:a17:907:1c06:b0:6df:b257:cbb3 with SMTP id
 nc6-20020a1709071c0600b006dfb257cbb3mr139397ejc.631.1652888367981; Wed, 18
 May 2022 08:39:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
 <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
In-Reply-To: <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 08:39:16 -0700
Message-ID: <CAGS_qxr4vTSEtcGGFyoZibga2Q_Avp9pFD78GOA3W9o6F9RVRQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WHvW2VBA;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62a
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, May 18, 2022 at 8:36 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, 18 May 2022 at 17:31, Daniel Latypov <dlatypov@google.com> wrote:
> >
> > On Wed, May 18, 2022 at 12:32 AM 'David Gow' via KUnit Development
> > <kunit-dev@googlegroups.com> wrote:
> > >
> > > Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> > > 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> > > setup, so this is the best bet for testing things like KCSAN, which
> > > require a multicore/multi-cpu system.
> > >
> > > The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> > > KCSAN to run with a nontrivial number of worker threads, while still
> > > working relatively quickly on older machines.
> > >
> >
> > Since it's arbitrary, I somewhat prefer the idea of leaving up
> > entirely to the caller
> > i.e.
> > $ kunit.py run --kconfig_add=CONFIG_SMP=y --qemu_args '-smp 8'
> >
> > We could add CONFIG_SMP=y to the default qemu_configs/*.py and do
> > $ kunit.py run --qemu_args '-smp 8'
> > but I'd prefer the first, even if it is more verbose.
> >
> > Marco, does this seem reasonable from your perspective?
>
> Either way works. But I wouldn't mind a sane default though, where
> that default can be overridden with custom number of CPUs.
>

Ack.
Let me clean up what I have for --qemu_args and send it out for discussion.

One downside I see to adding more qemu_configs is that --arch now
becomes more kunit-specific.
Before, a user could assume "oh, it's just what I pass in to make ARCH=...".
This new "--arch=x86_64-smp" violates that. I don't personally see it
being that confusing, but I still worry.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxr4vTSEtcGGFyoZibga2Q_Avp9pFD78GOA3W9o6F9RVRQ%40mail.gmail.com.
