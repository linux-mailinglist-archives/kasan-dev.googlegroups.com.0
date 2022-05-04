Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMNZKJQMGQEVYE25WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A78C51A1A7
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 15:59:06 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id t12-20020ab0688c000000b0036274f5d6a4sf579185uar.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 06:59:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651672745; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fn0TfUoF1d6hIpZ3SvQD4BFsfzasQ30j/IJsaYWk3LjnzpjAMVLQUDYqrKYTskR9ZT
         mN6/AplLlgebTxEv8uLmwygMHVdxA0pdr0+AJ2Lc8KnOJq465I87X8bvQDQQXCJiSqaN
         aZaTbcbZJj9g10lRIjuqoIcDGk8axzw8R+B0S0BbYqb9BVo4yReSckFdXFqISfr68JiK
         9/Bkty1LU/nE0lbaBSno5jUymjhm+deUQVcvw2Nf2hmTZIVj9VHA0G0fUfaiWGBQNmbS
         Q8oq58XKiHZAiLIQl/4fUpzXPIgu5MZ5Sz7WxMFnil65gaofBYU+3dBz3s9rUZ1mOcI6
         u99g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xhg3MCBgmCEBdIetQqWEcR3TVNAgOfM/6ZtSgXY+zkE=;
        b=sUHjZTQnCPHjUBrnROcTc0/FlLh7/+Zt5gaXmL/9u9P75Rf7mUgtYtI9vvsoGOMmHD
         H/1q9J9Yn5/3gMG4Q0xUyFk37jydhvvtDTSznlffDeOCQMFkIJeUmTXYRlHOV9UT3Ex1
         Ytgzkr/hvyW++NId1co9C3RUoFHbZEOPAkKwbXE2Hal40OxeNlluyEOxwqZpx9fx/0XL
         WvFxT7PedYu5OZesuDq3yEC5d8+IqUSm1Us7Qj/EnxM/fCYvpxdBRWkP3dzxaYklh+vg
         HshccQlXRKsM/FAml1ZX4QmrdC2Mle91K/+0D4tlLe1QAqK5PVpgOT+tpfZ738pbG+In
         gpdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRu+SOgp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xhg3MCBgmCEBdIetQqWEcR3TVNAgOfM/6ZtSgXY+zkE=;
        b=FnTclpGxu3DdQHD5ktEw9IRMLUgobfIKSVU/DHJ+kf0MMgzr7Y9DDAd7sfnJE/yUz0
         vOgE3HDUqZTQqZQ6R7uRFCbe7wU6CVuh8v26K6YAsEfKlogvz/N/6sEvWPinpfFrPARm
         LUxFdHxuuxk3uU9mjJnES65byJ6EGj5qp0jLDo7dQiJMVYmLMXKrhxP0v4TQn0N0cakk
         4aC7tHwqzG335DP3cTUUILchb1ZjCYf0/jgN0T4J4q7pUK5tl+eiVNX9lSvzvtAISCy6
         xEbjjUHy+Kwkruipiv/aUIxC5B24hvlinlUu3ZqSujdtBRJF4QX7ny2LOJsFZqSZO8gp
         LSnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xhg3MCBgmCEBdIetQqWEcR3TVNAgOfM/6ZtSgXY+zkE=;
        b=JLZcyCwLga8cyz5ONVqBvlmPwSRVK1D4PZbmZVdJlMk6GSgrJDooSrH8FG86CT1dU3
         mrexpZiN9s2O8y47BiLcpzfi7T+xrQoDE/TysPOZurnm3Szi8crhPY8ZBcZ+gRwgdZKC
         F1PkHiXIkGOqzmugYcrJ/eHbImxFOSSKD6jyys7jaMEYvVfHUuz/fIVDPaPAVposzw4C
         4nLu/DYtIwyypB08IJdVolKaSrnu8fcfqW4DDW8Z34ATX79Ya8E+odG5zhESoJuUxxEm
         GU/74o6Hkz3a+N3HETbSZA4GTjAiIwX/ur+lAUsmgtZkg7nJ0m8mz//vhY7gwgqqldX5
         vl4A==
X-Gm-Message-State: AOAM530Mzt7LSb36nozSIwKq2RewD+avPvgwMC5TIxkJ5TTD8KuvZwKM
	LSr5Wfu3MVX7l2qhfFNm6E0=
X-Google-Smtp-Source: ABdhPJyXMQbpNkllUVSsul7r2PJpMToPJsdvnhf4iFW3UruWzjiAYO7YPde2cQfWDIM0TBK7DM3f3A==
X-Received: by 2002:a67:c905:0:b0:32c:69bd:18a3 with SMTP id w5-20020a67c905000000b0032c69bd18a3mr7077288vsk.5.1651672745284;
        Wed, 04 May 2022 06:59:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1945:0:b0:328:1375:9d3f with SMTP id 66-20020a671945000000b0032813759d3fls371865vsz.9.gmail;
 Wed, 04 May 2022 06:59:04 -0700 (PDT)
X-Received: by 2002:a05:6102:1629:b0:32d:33c3:d815 with SMTP id cu41-20020a056102162900b0032d33c3d815mr5477418vsb.15.1651672744537;
        Wed, 04 May 2022 06:59:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651672744; cv=none;
        d=google.com; s=arc-20160816;
        b=DVt67IAy6VuVR0thXzYlsXhaabGmZQ3QFSgQ6mnLgruDA7Z7Splsi15chCGxkvjfzD
         fBH9lunmaKzGBT78M4GKFJ6JucIf3d5FHwdrQ26E2BOu9aqtxnK6cCOkP0m4UwC3Mg+a
         wZA04OYGOqH+pCKaPYb9ahRRo/Jls+AEtNScQNoAGwSxlUTU7i9InM+j+hYEdyl1zGmY
         VM2/eg83dcN/dlF5vNamqA6Vws02+xKUm1OoBfjHNxCrJe0RhLfZ/tCABqOuMLEmlzjo
         VGY+QQVknvpHhD4+VrTnlGBIxlottE9fXJEn7SMJbZNvX2M2B8FlPG/Mp1VwuZfVjVdU
         P9IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SPZZPIZ3tMBmU2J1+dZLu8mQ0Ktfd9UqnJWzWh7GFsY=;
        b=xkJp5rDig3CqnT/w+2+D6kmYqk+5gMsmdU1GvWZtJmTpXVkYaHRadgJDg1n/ufMdPj
         hluMaCmLl8MNEUcpzcgpQ5ScvuKDoaEMtxPlwAgvgGXVZNWY+hog22D/CAq1z5yn5Ylu
         lQXZJDyYflHEozII1kGCdK5YOPjA2qsTckfeb2ilfI46nQ60MgCRsFnSCyag9uRc3Tv5
         wu6809eaX86XSI/IUopZZdu/JKhIh/5E5ITKnBJC02SyVRBeQfGTiQY74FVQExFcdP8c
         ix9j9mbJJy7hHOuj6KaMaVAH8I6Ua78sXgQlmvEG1/+CZnu1nTp0to3vkwivKO5V5+h8
         y1Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRu+SOgp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id q25-20020a056122117900b00344e7df6461si2380085vko.5.2022.05.04.06.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 06:59:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id g28so2483076ybj.10
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 06:59:04 -0700 (PDT)
X-Received: by 2002:a25:c1c3:0:b0:648:e9af:111f with SMTP id
 r186-20020a25c1c3000000b00648e9af111fmr19203938ybf.168.1651672743992; Wed, 04
 May 2022 06:59:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com> <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
 <CANpmjNPKyGUV4fXui5hEwc9+4y70kP_XgSnHbPObWBGyDeccYA@mail.gmail.com> <CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx+yC9J+4FYQpn2bpQ@mail.gmail.com>
In-Reply-To: <CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx+yC9J+4FYQpn2bpQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 15:58:27 +0200
Message-ID: <CANpmjNNHwpmVnrbRcibyu7F7r3cU9p_+ZHGTx=GGB7Y8LfVxGg@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: David Gow <davidgow@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LRu+SOgp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as
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

On Wed, 4 May 2022 at 15:54, David Gow <davidgow@google.com> wrote:
>
> On Wed, May 4, 2022 at 9:48 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 4 May 2022 at 15:43, David Gow <davidgow@google.com> wrote:
> > >
> > > On Wed, May 4, 2022 at 3:09 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > Use the newly added suite_{init,exit} support for suite-wide init and
> > > > cleanup. This avoids the unsupported method by which the test used to do
> > > > suite-wide init and cleanup (avoiding issues such as missing TAP
> > > > headers, and possible future conflicts).
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > > This patch should go on the -kselftest/kunit branch, where this new
> > > > support currently lives, including a similar change to the KFENCE test.
> > > > ---
> > >
> > > Thanks! This is working for me. I ran it as a builtin using kunit_tool
> > > under (I had to add an x86_64-smp architecture), then use:
> > > ./tools/testing/kunit/kunit.py run --arch=x86_64-smp
> > > --kconfig_add=CONFIG_KCSAN=y --kconfig_add=CONFIG_DEBUG_KERNEL=y
> > > --timeout 900 'kcsan'
> > >
> > > To add the x86_64 smp architecture, I added a file
> > > ./tools/testing/kunit/qemu_configs/x86_64-smp.py, which was a copy of
> > > x86_64.py but with 'CONFIG_SMP=y' added to XXXX and '-smp 16' added to
> > > YYYY.
>
> (Whoops, forgot to copy this in properly: XXXX was 'kconfig' and YYYY
> was 'extra_qemu_params'.)
>
> The x86_64-smp.py file ends up looking like this:
> ---8<---
> from ..qemu_config import QemuArchParams
>
> QEMU_ARCH = QemuArchParams(linux_arch='x86_64',
>                           kconfig='''
> CONFIG_SERIAL_8250=y
> CONFIG_SERIAL_8250_CONSOLE=y
> CONFIG_SMP=y
>                           ''',
>                           qemu_arch='x86_64',
>                           kernel_path='arch/x86/boot/bzImage',
>                           kernel_command_line='console=ttyS0',
>                           extra_qemu_params=['-smp 16'])
> ---8<---
> > > It took about 10 minutes on my system, so the default 5 minute timeout
> > > definitely wasn't enough.
> >
> > The trick to reduce the KCSAN test time is to set
> > CONFIG_KCSAN_REPORT_ONCE_IN_MS=100 or lower. So should you consider a
> > special KUnit config, I'd add that.
> >
>
> Ah: it might be worth adding a dedicated kcsan .kunitconfig, in which
> case this would be helpful. It'd also need the SMP qemu config above
> before it's particularly useful, and 16 was a randomly-picked number
> of CPUs -- not sure if there's a better default.
>
> If you're likely to use it, though, we can definitely add it in. I'm
> sure there'll eventually be other uses for an SMP config under
> kunit_tool, too.

I currently have some other frankenscript to run it, but I wouldn't
mind just using kunit_tool to do so. So having real SMP support there
would be very useful.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNHwpmVnrbRcibyu7F7r3cU9p_%2BZHGTx%3DGGB7Y8LfVxGg%40mail.gmail.com.
