Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5N622JAMGQEK3Q3EPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id E12534FE51E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 17:49:10 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id ay14-20020a05620a178e00b0069a9c319c64sf7995807qkb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 08:49:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649778550; cv=pass;
        d=google.com; s=arc-20160816;
        b=puiz+BueVxa4kXRN1406tYbt05sHjchP30PRxsXhe6jUV0miDGreoOwwBpxmKwS1jG
         ELpCZi3C5Mvk9a6DmuSt81jyElVFVRvZqbtjyAEgaXxlkff0xZmFJqxTqoRvRXEfhhFw
         fBO4dT6VTza09yjAXo6SrtldYIPFVjiFAwhqUZt1GV+aOd8D6aMkKk63uPEJVUgufYVp
         sYPVvZERUaa8LQqE6PTSFa3dbg1ZmnWuxStJmFGbitpzym4o2r3u6q6IsHM0laiWEizX
         cdBtyfClAytzia5FezDEzd2ClXmMbkwOV1yBHdBPTuoiqssfNQJ7rJmcNmRos2Fw5e9b
         D8Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3JPGMOwtES5oj3imGpgLrYbVr0VKyvIX2TBVSL845Z8=;
        b=GdYUitrspRjaMiwyIoWReyGNIchvefp8Bxv51pMMCdUDE6EnPa5PGyQ3iKgrMaIDyZ
         H308ncI39uKOtRFwC4yrYQYl3euHs0PnOWHrAou8Ssrh2Dgb05+RBmqqPqAG7maP0n98
         lXPG2uKTKIEpvxVismQJHAGZsM3Y2dgiqoyYe91fPRvBFcInCreSRVWa/xA4h1xvdbdA
         uG42jilTeCINXN8kdfCAGlaZvBh2ea0l8+T8Kt2wMk6gytfbL6a66z6uwebc8kJDhqNA
         B7RuNR5MTwzYBEh2u9ohHy6xdiLLe4nKY2lHq4D3YKXC92KPM9eFamAorBmlnKW4Jvj5
         pPew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QX626BjZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3JPGMOwtES5oj3imGpgLrYbVr0VKyvIX2TBVSL845Z8=;
        b=GCQ8fm47XeU+Yf0tkIF8Jb7CbxrRNcFZnGNQhW8KgMhaiv29f1yKx1JAew8KbdypMJ
         CupYN4Q6c9zv9UvShtdHpxNedmYnia0fon91F7bvyjJ/2OUtQQMpYowBQ9LvK9YxiFHl
         mddeeVKtHjqyMw4521az8tiN3ShIFIBdOS/lQsUywzSGp3Fspe/8DGRhakF75jKx2P8c
         pqnQb+Ta8ivle75Kd6gczx/p9xOQhao0ei7S0M/Op2etB0RzOMsTjZuVImf3gOcC1LXR
         AOAhcEXE/gp0z7Dl9dpNMFjIxIwVJFWZMiTSiEqIZgczct7kGqQAmsO/B0ihl1Z2KDZ8
         DUVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3JPGMOwtES5oj3imGpgLrYbVr0VKyvIX2TBVSL845Z8=;
        b=Wh1g4ZiLtJqQAyT1XqrtxjYALo0Xycah9XP8zhib+/IAypRRW/h1utHIvoyYOHqbDs
         q3HbkMCeBlJKixQS7UZAEQjivyrj+3AmOBQm+bZU0i8iOfzAXbQkwidRNxjeUw+IBBgO
         MXyNn7loxltCM+537iWeGNhK2OpDFo4XzfXMMjMN70h1cQTUTkpe6j8S9JNnbErKKqJv
         KJ0P76ezYJ5l7DXKYq40u8FML9xIovfcDsCitSIWSiaYriibIj6Nid0muVbuPETIurCm
         /3EcXgB9ZHZ4nAO3DPlkP0mZV61hAqrTO+q7TeZmTYGttDoBZMsKTI9+EWyr0weKbtbC
         udzw==
X-Gm-Message-State: AOAM530P2AVVb7AxFG0Zey4pq0I68G0d62RhlAwfGk8x9jSAxWcyqkNa
	vAf6LNYB7Es+Vsbm53JlNVU=
X-Google-Smtp-Source: ABdhPJzniZvlg+Gy3XV9pMoDBQ2L3X7WNa7jOGz7Nnszhg7vgFXjqkgwn5w8K6N7QwUpmnC0XsUKqA==
X-Received: by 2002:a05:620a:4442:b0:67d:b94a:8c6a with SMTP id w2-20020a05620a444200b0067db94a8c6amr3568957qkp.569.1649778549915;
        Tue, 12 Apr 2022 08:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4312:b0:699:fda3:7819 with SMTP id
 u18-20020a05620a431200b00699fda37819ls12541999qko.1.gmail; Tue, 12 Apr 2022
 08:49:09 -0700 (PDT)
X-Received: by 2002:a05:620a:1373:b0:69b:fbcf:5fc5 with SMTP id d19-20020a05620a137300b0069bfbcf5fc5mr3456235qkl.275.1649778549198;
        Tue, 12 Apr 2022 08:49:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649778549; cv=none;
        d=google.com; s=arc-20160816;
        b=BbGAvLv+uIowbaFwPhZ3pbardcN/30SS4XIqjiFqtyPZEnJieWyEyp8r04bYkBTte6
         jHMWnvyr2KrlpHnbj1IlJ/vysQX3EyyClSrcyI9C3AkWx27Ii45g1DPKjEffXdz1HUqg
         Iu7eRZOk5TVoEtWUlze0/UYySug4kvpOw8rCBj0TxaKTFirmgMXbBtifzUeOloRCU3EK
         j4PbGlp1LcC5qKXg9NpMJZkyClYJIWy4sDLtqKpyJv8VXKPAU6iA7LE3gI4ZX4ndnpX7
         K0G5Iizet7KmQ/rD2XtOUu0uHcVHrBUvKGIu+/8aOk3gfNTHR0ma1SB0bTeZqyfmsAhJ
         Jm1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UTyzDghl6HrL3ZR/fFistubqxpKJRCJIoqi5QoNRA9Y=;
        b=KglSBIBN2349T932w4XouHNTEkGegOLZSiN9C3r/oF11iUwSs52wadauLQEYWmGmiC
         HUvmiuDlaPYJS01aoJvH8BH9nsncSBMKdAuDnTPWzfQc7Lem9ML+R0oWQw1dOXQ8AErw
         q/RaVhUMNOdhfBHeLmnFQ8nL5NRy3piRZmr93N9rr8bhxY+DiN5E7vxwSoHkTTFyBYIQ
         mqetV8EUil/zqUESOjkid9HbwuLogKlApcHjFdfPC/N4zoVCyna+jeJTzGfpgiBoj7FD
         Hdw/CV2cufRlBBc8UmN2oktir5lMBJlak2dQK50rmzzWI0DJ6UovpcKBj1HFdac7Ds7i
         VxVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QX626BjZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id p5-20020ac84085000000b002edb5d721efsi1305904qtl.3.2022.04.12.08.49.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Apr 2022 08:49:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id g34so13874468ybj.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Apr 2022 08:49:09 -0700 (PDT)
X-Received: by 2002:a25:f50e:0:b0:641:303c:782c with SMTP id
 a14-20020a25f50e000000b00641303c782cmr10373094ybe.625.1649778548714; Tue, 12
 Apr 2022 08:49:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220412062942.022903016@linuxfoundation.org> <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
 <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com> <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
In-Reply-To: <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Apr 2022 17:48:32 +0200
Message-ID: <CANpmjNPMd_HRPEqxQR0XXdp91QfqoYJxhoTjVMZLLDSTgyyTYA@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=QX626BjZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2c as
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

On Tue, 12 Apr 2022 at 17:44, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> Hi Marco
>
> On Tue, 12 Apr 2022 at 20:32, Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> > >
> > > On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> > > <gregkh@linuxfoundation.org> wrote:
> > > >
> > > > This is the start of the stable review cycle for the 5.15.34 release.
> > > > There are 277 patches in this series, all will be posted as a response
> > > > to this one.  If anyone has any issues with these being applied, please
> > > > let me know.
> > > >
> > > > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > > > Anything received after that time might be too late.
> > > >
> > > > The whole patch series can be found in one patch at:
> > > >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > > > or in the git tree and branch at:
> > > >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > > > and the diffstat can be found below.
> > > >
> > > > thanks,
> > > >
> > > > greg k-h
> > >
> > >
> > > On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> > > with config [2].
> > >
> > > The finding is when kunit config is enabled the builds pass.
> > > CONFIG_KUNIT=y
> > >
> > > But with CONFIG_KUNIT not set the builds failed.
> > >
> > > x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> > > core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> > > make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
> > >
> > > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > >
> > > I see these three commits, I will bisect and get back to you
> > >
> > > 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> > > e25487912879 kfence: move saving stack trace of allocations into
> > > __kfence_alloc()
> > > d99355395380 kfence: count unexpectedly skipped allocations
> >
> > My guess is that this commit is missing:
>
> This patch is missing Fixes: tag.

No it's not - it was patch 1/N in this series:
https://lore.kernel.org/all/20210923104803.2620285-1-elver@google.com/

> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPMd_HRPEqxQR0XXdp91QfqoYJxhoTjVMZLLDSTgyyTYA%40mail.gmail.com.
