Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVJ22JAMGQEO4Y6DBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FDBB4FE44C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 17:02:56 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id d11-20020a17090a628b00b001ca8fc92b9esf10073231pjj.9
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 08:02:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649775775; cv=pass;
        d=google.com; s=arc-20160816;
        b=AP7nzbevwtvopHk4QGaJdvhtTj+pvaJJC8adORUZhud7GmsQQMhXbTMYjmBZvqwj+1
         4FqlQZB4RYNFETghu7DohJ1YbTAUkGPzfTc9PLtsIq9n3vTSWtLY4M11OmEQbNdCFBak
         sNMb8ud1Zh6oCnAK+vOEensMgPu8yXqTxVI+1E/KXsBr6ILKH5Lo+z7lq/3J+1ppTuKz
         bC1vH23+hLtKbvCyH8meIhbQCZ80hlxUVvOXxYDjTBYsGj323GoISxyiRVDv3Wtfjawh
         QukS3MV+qt7B2bj0Nvmjb+NeUbrit6QZ8/O14tJd3roYvyJVj483b9zKut43At5tghva
         kMLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AtiPlKKPZ3aPlG83Nytrg4aeL3R0o15nl0w5qr7NP/w=;
        b=hLvqNz2B+4TnbjsFk+wWjuNXCNe2PxaGr69AD+ogErMdIaL+NQx5205vdF3mtlg7zn
         +lolJxUJ5nX+izUvdycIMowIS5Uxa0QmAXPsiw3j9T7txd6xoXgF+PcOs8E/+qWhof9v
         asQFX3g8T2b6AJSPu0TzNJ1td+aSfV1Xv8MulKn3va7P/rVnieWEXTQxiBUMywYrsRvN
         AW/JbHprER2gP3wqzT0xa7DhtaNE28PkNTpi0fFSskXHc/ErKkeJ9CBITMh7FFjaB2bJ
         h8k38jz40pX6okz858aQMMvNDrxOXJK4ImY7yIoSkjD3W8fHLkmu2D4Ezujap0ExrUv8
         JJlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kqj7qkJt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtiPlKKPZ3aPlG83Nytrg4aeL3R0o15nl0w5qr7NP/w=;
        b=TzXmc+KsTI8kOZZx+kIWdaBHuW/uWujeVpWorCKS+zAC5+vHRBVrHdp033reMztpMh
         M2GOCm+vlQ58ovogOaShxJTnRCBHquGsgxP5vMZ3y6yIpmLlgqOycFmCUEFTIiZFt3Gq
         UJkIv3tZfETaZtUiHJoxqPwL4cEVMBX0Mnjui2hM0IYM6MhV8K/nzWyO8mCcm1rEDUwh
         d5E294aMtvtEJpyIXBZ/qAvlX1cv/Y1ucPeG5jmSDkxhdnibGNt1M++hzyZOgDkkfoSk
         k6NWcBZHyVez0Wywc4+VondbvY0E+yKZvVr580qb4qRTiMciYlc8ruwKo2gY9pZ2KL0c
         Vzig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtiPlKKPZ3aPlG83Nytrg4aeL3R0o15nl0w5qr7NP/w=;
        b=b4mBd14nUwSSpCYmX1STI6m7n/3Up062+3pTIGDvc7f9tFho+9UAbmrTiYxQ/eqd1E
         P6kbfeEJHwqXzAht/gDM3OASe7LwDQKNepSD8Ypjeg1lxwQPdgsIaHmd5sGe2W/Xvmfk
         T5f17A6zyL8EHVkn6CJKb5AExxGak5npsetwuWGqGeNI/LQlpTTVCI7vUW5nhZVWuvee
         AiI/weoPsTBopX3dlWpqtFxCIJSWx7IY4KqvOMf9MKfNDCYtajWycy3Tu8g0MZQQ+MEu
         0wxLDxA1ePubuqWMdOQNIDm3DJk/aseq6DOirZJeDuwUUWYTgZ2NcmpBeXRWUdB9caf3
         AtDg==
X-Gm-Message-State: AOAM53290mLU1jECOQv4mCwClsPFje3SvYoNy8qpD/uMgNT0SZsZDL4B
	DdSdu+YyQUJUDUzmbTeBKJ4=
X-Google-Smtp-Source: ABdhPJx0yZNNE5QW0enTBFyvgs7Q362FubV/w5GCh15E1YiInGyBgv9gXHTMu76MALI1ffL1hi9tXA==
X-Received: by 2002:a17:903:41c2:b0:158:83f7:f8a9 with SMTP id u2-20020a17090341c200b0015883f7f8a9mr4976243ple.146.1649775775060;
        Tue, 12 Apr 2022 08:02:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2287:b0:505:70be:6fee with SMTP id
 f7-20020a056a00228700b0050570be6feels12288742pfe.3.gmail; Tue, 12 Apr 2022
 08:02:54 -0700 (PDT)
X-Received: by 2002:a63:6fc4:0:b0:393:9567:16dc with SMTP id k187-20020a636fc4000000b00393956716dcmr30617927pgc.593.1649775774156;
        Tue, 12 Apr 2022 08:02:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649775774; cv=none;
        d=google.com; s=arc-20160816;
        b=qvgVZmHt/re1gIgjxzqYrtTWpCMMQGaFee5PcNke1oRIsnVg4TifK8PDv+Hjp7g0kO
         YaRY0wXjp5QiNZN+lxFkG1UOZugQwyuzhpGPVffRPTE4xX1LpfVW08LtZxofpZgNQf7+
         h0Cms3eo5T5eW6aQII2kAplY9dl+6XJyh6BI099cg+Uo3v38kKnmCO12XdEF7NINMh0m
         OimdlFMUr4di6TVxfD+lxt6R0DiZi/FFeqMUdUgoVWsgVOthvFtSyV6q4VMjSUPIvMLD
         iZoAdO2ZmoqQ1Zx8zpr0hAkCrlQXb6RY7WKrd030xYGZZ5oIL0ujdiE7AluCZ335hpfJ
         YB2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LIbAv5l0ZDXFk0gGIWaCaLe3jbR9/lI410ENmUvMqQM=;
        b=nE1bybe2NkrZVUOtzgGN7SPHlmhwX1N5FhM+XiNG/8c+acxtawzD14tdZ5cTPDAJX5
         SMB+pA1ndhLqaGmcnbvImjl5hsS70QzM4yVzfOMyYoQ8aN0oPbgfSAGbOQYdcnixfSJq
         8VkrFr424s97+RItc3wxfpPQdKSVF6urkLS12cMygA2rzC8XAd5OVPVnPlGtvFO6JBLh
         l+FeqohvDxRNmlSvGjWflVgzvjewu8sYAPgx3luXBt5pPgJLHCGyym2Tfw0+xfdBunyG
         peIu9vp1cDukrYXaHs6JbSpRd6mComXeBqSTryu53yaKYuNIQf06fu2qlH6Si/xIxpmV
         L6sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kqj7qkJt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id f85-20020a623858000000b0050604acd127si172081pfa.3.2022.04.12.08.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Apr 2022 08:02:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-2eafabbc80aso203788247b3.11
        for <kasan-dev@googlegroups.com>; Tue, 12 Apr 2022 08:02:54 -0700 (PDT)
X-Received: by 2002:a81:4e58:0:b0:2eb:5da0:e706 with SMTP id
 c85-20020a814e58000000b002eb5da0e706mr30458489ywb.412.1649775773341; Tue, 12
 Apr 2022 08:02:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220412062942.022903016@linuxfoundation.org> <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
In-Reply-To: <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Apr 2022 17:02:17 +0200
Message-ID: <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
Subject: Re: [PATCH 5.15 000/277] 5.15.34-rc1 review
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, linux-kernel@vger.kernel.org, 
	stable@vger.kernel.org, torvalds@linux-foundation.org, 
	akpm@linux-foundation.org, linux@roeck-us.net, shuah@kernel.org, 
	patches@kernelci.org, lkft-triage@lists.linaro.org, pavel@denx.de, 
	jonathanh@nvidia.com, f.fainelli@gmail.com, sudipm.mukherjee@gmail.com, 
	slade@sladewatkins.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kqj7qkJt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> <gregkh@linuxfoundation.org> wrote:
> >
> > This is the start of the stable review cycle for the 5.15.34 release.
> > There are 277 patches in this series, all will be posted as a response
> > to this one.  If anyone has any issues with these being applied, please
> > let me know.
> >
> > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > Anything received after that time might be too late.
> >
> > The whole patch series can be found in one patch at:
> >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > or in the git tree and branch at:
> >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > and the diffstat can be found below.
> >
> > thanks,
> >
> > greg k-h
>
>
> On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> with config [2].
>
> The finding is when kunit config is enabled the builds pass.
> CONFIG_KUNIT=y
>
> But with CONFIG_KUNIT not set the builds failed.
>
> x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>
> I see these three commits, I will bisect and get back to you
>
> 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> e25487912879 kfence: move saving stack trace of allocations into
> __kfence_alloc()
> d99355395380 kfence: count unexpectedly skipped allocations

My guess is that this commit is missing:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4-jG%3DkW8FoQpmt4X64en5G%3DGd-3zaBebPL7xDFFOHmA%40mail.gmail.com.
