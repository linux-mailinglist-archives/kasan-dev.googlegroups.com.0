Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBTGEZKJQMGQEE64GBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B34351A4B2
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 17:57:01 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id br16-20020a056512401000b004739cf51722sf795006lfb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 08:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651679821; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2wssZWdVd0q3napd2+AVrmSJVPl9A0n5GshXbweW5/fBoyq0ggLYM4GS9uwZalfJm
         1YlKACBsppCuUrDoyydFBTDV3ya4lv27DQwUWVKFDObDfMMPwp+4XK2smOK0Vy/m/8nH
         GQuur4OCLIcLL3R+UhhewKqZZmnqjurflLgPIy8hdBoRjO/BhxAMDPeQfc2L/rdqu5fE
         qi5fU521omtnZ5IPCAH7UhVfUWROa3qHVFy7oGvmKs4JFCIgO+UOR3E1Bmm5lqPs0LuD
         AnZKkB86ofW7zMOzgd2WLyaSZMojcPiw9ARt/iV8KL56Juzv9VtinUUldY9M4tZWhCaW
         nAgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DQKnBNvVilojFYI0aYWN5fCWjq3udq7MarU0Kki9htI=;
        b=tRnRTY9VVRSxf4qyIzfJszxMyBixYCMoJUosVJjB8y26G5tliHcpgodMTYoKRBGTR8
         qfFprt6nYDYp5kA1b9msMQ5yOY3B+k2FVDMbSwUGxQPmkRdxEGzw3OUyXe70rbJplnVR
         uuwn0ECLqM24iMa2seGDZr1rMfnFR7k81ImdBXyRmHYVdT3Fy2aBAFpynZxp9+W6PDFn
         Ks+QN6sqoP0WjFPuenbD28IoR8d2B1iHI7TbNNGLPskim1EYKqvpHC1tUrcQaYsqo5r8
         cwzbY1TCwa2kX7fyN4ILzVG2PgRK888K/7eb5SJu+Qq6ZtrjXAGXmT41vGh4CqAhpiqY
         zWsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qxlyl1Tn;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DQKnBNvVilojFYI0aYWN5fCWjq3udq7MarU0Kki9htI=;
        b=q4EG3vD9UflCHnScxN/YRDmKSsh6GPesz0KWJ9uEP8sdSHCTk4Nkc90GY5eUhNwxKi
         n2kYZjyH8QhiV+BVpcI2Nc9obYuPRg6EILkVTaQEyf8C6Oz9Aytf7ho6jHEpafq9NrWd
         dFg024ZdKpVUhNKj0eSOapjQDhdFhQGwAzBv8WzauDWiFg+RvdblrrMSOZiRxhuApgrV
         T+fWPfCjK2aZUrie6S4cHuwC8DHpt0jGQTdW83xi805sYV3e8p3XTaCH/PkG9WlKtvte
         yDgAD5gJhRT954DekN7ToFDCpsKvpoD6WvuPu9uhp8FqLIYAqWh0SbS+70yaa5jyBDyx
         S+tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DQKnBNvVilojFYI0aYWN5fCWjq3udq7MarU0Kki9htI=;
        b=O8Oy8y5kpfMMVnY8vRjkTv36gup+jm00ervq1XGx7M0HKyq4jr61v82fTYUcF+yFT+
         RYNYYZJA/D3BOY4e8bsejTSmK/iyOTQQu0o9V2vhB0NGA+E+CavdCjKCDD1WD5kpeqSf
         0ni1sDs98KxFfgwcgO+ZBLs3vgDIT/AOU6jULvhVIigF6C0OwITtRbwus59CcX8mY8w6
         rm+kgJnTVFLtB6jHtmq1F+qi/0s5svNNZVr6Z99vttPTNnArmXtf/mXLQtEykLfEuMjt
         L8Nny5fhdroIfYEJ/Ql92iyYTId1qTFXGBW9xJ9evCjec+zf0DSg7uSji4I2t8iwtrNi
         xZwQ==
X-Gm-Message-State: AOAM5322RV7rvToBXCDU0oHFY/G7tNY7Khl/4NAX5IZ5G5kF9+hvicUe
	ANJHXnDkhzP7mUe23Ajo1ds=
X-Google-Smtp-Source: ABdhPJwXDqco9wDBYarvhSOkvOxsvQJE//fvJIVa6AZRHNYLQrBGFhPx+A3W7ZtaQLSW9FpSVpLazg==
X-Received: by 2002:a2e:b001:0:b0:24f:ece:15d2 with SMTP id y1-20020a2eb001000000b0024f0ece15d2mr12729270ljk.20.1651679820869;
        Wed, 04 May 2022 08:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:4ca:b0:24f:f52e:16e0 with SMTP id
 e10-20020a05651c04ca00b0024ff52e16e0ls520522lji.3.gmail; Wed, 04 May 2022
 08:56:59 -0700 (PDT)
X-Received: by 2002:a2e:9b06:0:b0:24f:155f:9045 with SMTP id u6-20020a2e9b06000000b0024f155f9045mr12567967lji.174.1651679819681;
        Wed, 04 May 2022 08:56:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651679819; cv=none;
        d=google.com; s=arc-20160816;
        b=TFIEG1AenS7gYaxTFSgsBqYJfkIFxNMR9C1ITJT755+03UWCaRsQjK+NDajFktl9iP
         87Gc3gX98p0eqkEEpFlHo+bDNxcpgD8Io93V5I/5z3Spbxt9NWDoZCheZFHg9PLvmGXp
         YyfLy/j0JcuCFUCwM1KouIGp91hKagwI9b5B4xK9VcVRMiSQMQxfeuHCjaUFlmPJB3E7
         8/ZRxQVfaogMpK39UppdG6o7gHdyrH9dYrXOM9BAdGRj9r0MPb9EBq4Hhn0224JbjRaH
         Q449ZOJQBSUmPm2Qex+eYT4TRXwYnXhmJRg8olHbc/WmBSAiS+gQUnFPkBHsaW2GWw7Y
         aYrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5/V8aOCPUs9sOYmfOrlEFkCOFP4EK6WXgi3jd0LGRss=;
        b=LxqItKSFYKj0ZNIXLvFXFuHqANSbBigbzWYAODfvbiqNEw9afvpfyxHw41QakeFgu0
         D5hnXiGXZnfHI2L58JNgAkjmvUYgeXTzlGCN+tOsIMYKJAe/T7OkF41SrZaZ8S42Rbhz
         x/M0wNBwcVLbwKUdQkkDg4TOr49vIg2VAyp+hcmh3XCTwY7TepUAc6zqW1ifV6Irc75Y
         fczxemuaIZn8zHWUYIddW1LDdkAKZAG0Vmg3rCjop5d/yJBEiAb+kYYRS08E4cUOlPe9
         FsEXt3B2cJn77DEDYRStCKJIXnCbpYZtwNjyhtp6DrlJvm7N0Y0Oiagpm2vkjxF2sIgZ
         n3vA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qxlyl1Tn;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id u3-20020ac25bc3000000b00473a659879csi285331lfn.13.2022.05.04.08.56.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 08:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id z19so2191975edx.9
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 08:56:59 -0700 (PDT)
X-Received: by 2002:a05:6402:3490:b0:427:b471:9e1e with SMTP id
 v16-20020a056402349000b00427b4719e1emr19515336edc.36.1651679819093; Wed, 04
 May 2022 08:56:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com> <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
 <CANpmjNPKyGUV4fXui5hEwc9+4y70kP_XgSnHbPObWBGyDeccYA@mail.gmail.com> <CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx+yC9J+4FYQpn2bpQ@mail.gmail.com>
In-Reply-To: <CABVgOSkLGryZeWVXdfBDkQKWvSkYTk2LWx+yC9J+4FYQpn2bpQ@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 10:56:48 -0500
Message-ID: <CAGS_qxqY89wOweJwzGB83_mHsFBzzbvbtRyY2qT69Dbrm1ZZkQ@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: David Gow <davidgow@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Qxlyl1Tn;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::532
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

On Wed, May 4, 2022 at 8:54 AM David Gow <davidgow@google.com> wrote:
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

You'd want ['-smp', '16'].
Otherwise this config will be broken by
https://lore.kernel.org/linux-kselftest/20220420203020.1412886-1-dlatypov@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxqY89wOweJwzGB83_mHsFBzzbvbtRyY2qT69Dbrm1ZZkQ%40mail.gmail.com.
