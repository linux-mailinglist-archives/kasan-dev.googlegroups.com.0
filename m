Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBQGVYKLAMGQEMKVJ5HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B05FE575823
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 01:46:08 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id g7-20020a056402424700b0043ac55ccf15sf2357986edb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 16:46:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657842368; cv=pass;
        d=google.com; s=arc-20160816;
        b=UBCDUOsS6HptSX/zwCYrboPcGP+h6dI3Te9zsb0VX61M5P1BWEYBEt75ms2uSquzQk
         QF9uVvKgRmtpqCqT2nvv5n5ZC8Gcu/kf3mSsrB4y1oDjZD3yaltJNgIBILHrCZjra+8I
         xJJyeBNsgl2qVny2JhmgPSmMarecWM1cQHn8Zv07Geylodp5L4mCjUY0hQqJxPtehvlp
         UNJerySK0BMbedqACn35Bcnk15lPwoXMkk10GIrAmg+EoK631jb151DVLu2kzrq3JiHD
         F4JWCdzchhGctpheNP33Ogv0NU+Mr1reZLdNFMGZWUE+LxFRct+iu84iS03KhLfj+20E
         ZrZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NWq6phSoNTpTQLgswQEWfErjZQ7pJAAqHTT/FcaAWYQ=;
        b=YV0s2SClHb8QdqMFp7dQPEVJsM7oEkHa98Wvead6AzK+bEo5PNQa87DAMpISMhkw22
         LGuVvhKJA3pgDIWYZvN0jLG7B97lbLd4Pdlgb3bicCjtN4J+x2EQzAHCYeq/2XP8ggMM
         0PbIoTiQeOcMMX1M7B9g7oZelAKZ48NiDQDUAazjBlhob46qrdWu7BTzopcpoQlXzTbK
         bGNSiFyPi7SJgx5i8XLZNTwuqqBTMtJtLT9OALloolsz2eJaFxaRIiMBNfBtrN614vi0
         dwQz5HG3Q4wUjYhc8QSlpYJkx2tqDKuDajKFO6fvO0XOALCrTJMk9r45/rjUY6mHn4zT
         MnHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dACUMMrT;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NWq6phSoNTpTQLgswQEWfErjZQ7pJAAqHTT/FcaAWYQ=;
        b=ojh3OZLRkxImq3IKQe4CnvJ3JqoU3gCVR834vb6K1BxVuyOooOvvAgL2VkWzU8YhXm
         +FrxNvqnJqMaYyaxhvHF8795R5Re0AUkj9bxkovxcfJJfqpBhOCMGyha1ESHmv7zG0Xs
         i34r6N+hZACqcLKB9lcOKXn01LFDbTC0QfJstTaw1nkpQQXQDGE4i0lNU3x7US44arMG
         2QwpUbBzUQpF2rr0BfgqYVulEJYpgH+3+GgxUyrc2hgJ9+EIcDE+sISMyeqLmvIsGGJW
         ckZtKXPDPioSmDv0t4/3Y6p7gQ6So8MkgHWmZENPiYFl6FGivwnyxHmuFFGb1W2c61ZY
         XJvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NWq6phSoNTpTQLgswQEWfErjZQ7pJAAqHTT/FcaAWYQ=;
        b=TOD4HdsKUlZM8DJ/JDUxe6WJa4baeGOqRLxqv/S4IWpf4RvjsT2VrjQaD3SrZh7BuP
         sLl74n0oWxGx4W1vtKRnDykKxBKbX6D6OyhdUlcV2y4lRleXpsEfeOKCLmuc+nyu4qay
         z2EWEfuhDlObj29uxcrinuYP5x0ScPs4VpV2MfINI0g9K4CN71E6HQgVp4Vu8DJL++WA
         tepxMV0RQV+Sf7rkxkPntbm8Pivdo8nUm75UnYT15YxGu7XZwNktrBlKeoaUcs6zTtSx
         XW9D9/gPBzJOy7JaxY4Nnu81TrxbhRB7DflCuN53YFZNmQjwV7rOF6UbLtmxQmDiVezw
         c8ug==
X-Gm-Message-State: AJIora82fLEOmj0TvF0cJWmtVTmmy+qNj0x1YOfq0l0rR9MolDQz71Ud
	8muflU6t5PhYfh9O5Gt2hkQ=
X-Google-Smtp-Source: AGRyM1sxXHoyiU+eb8vYC2IJwhWvwWpSO3aHyUv3hBIG7GivIGTspBLqap+e9Gm6f+wCOckc06+Rvw==
X-Received: by 2002:a17:907:9621:b0:72e:d9a3:3f7a with SMTP id gb33-20020a170907962100b0072ed9a33f7amr6712015ejc.260.1657842368284;
        Thu, 14 Jul 2022 16:46:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:274e:b0:43a:6e16:5059 with SMTP id
 z14-20020a056402274e00b0043a6e165059ls45726edd.2.-pod-prod-gmail; Thu, 14 Jul
 2022 16:46:07 -0700 (PDT)
X-Received: by 2002:a05:6402:d57:b0:43a:f611:fe40 with SMTP id ec23-20020a0564020d5700b0043af611fe40mr15374284edb.392.1657842367261;
        Thu, 14 Jul 2022 16:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657842367; cv=none;
        d=google.com; s=arc-20160816;
        b=EEuyrY78G+v/zvsC74E55jtqMRnymy5H1+cNq3dJlKuPAZ6GVjqbTpPy33l05rhsoU
         ZG//sLC4OxsrLskJFoZy5igzX0irnV3RP4UHBkFmsvdsYN3qvDZGId++bz56zsYz/00T
         /8yYjjMbwDYO59vNQx3BYtLXGC7fv4Ig6SUJsmmEZm1CiJxvXhU7kowDnr+wNELhBn75
         VEtCLjH3eGG+Rm7zDbLrKtx426KBBwETSCV+NEHQFvCGQKpE3U4p7rJ7owmOG07sfnoW
         jvf406YHiumhQUnz/urekdnlLELLcifRuoTT2vJdJW//Sb7tQAx3r53bV+3AlVX5s+VW
         NWRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IyIlDk4W3kNLsc6EwzwzX2HL8L0b3ZfiT6dB513UuYM=;
        b=exhn2edWqotT6csOH5rw7pbpshXIRxWZH2rQqNDU+lSwMH94JXVet/mFV7KHR10M/h
         en9yW3mjceW5/ksaSX4i0svDj9SD3shUm5xcxYgGoaD4f+l/UlT3PUAYGkc6b8OduiqV
         Y/oP7NIMDKFVxRNFOpa6vLCdAgd49iM48GdGPN1EYt6N98nYKXO3JKMfsylHNuy0BDkb
         KHg1ICI7/HyQsGFv381buDuh293Uf0it2xxlH1ZBSLfor4UbrgofnzI1VDvXtzb4NA6S
         8FVS1RBLP4bEaHeLY0hAd55FddcXBGyXytHcxyKCsoj7W8Z9ybymKB+rgc0x1FVbv46K
         mVsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dACUMMrT;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id h22-20020a1709070b1600b0072695cb14f9si112986ejl.0.2022.07.14.16.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 16:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id l23so6177396ejr.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 16:46:07 -0700 (PDT)
X-Received: by 2002:a17:907:2856:b0:72b:54bd:40eb with SMTP id
 el22-20020a170907285600b0072b54bd40ebmr10726416ejc.542.1657842366888; Thu, 14
 Jul 2022 16:46:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
 <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
 <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com> <CANpmjNP-YYB05skVuJkk9CRB=KVvS+5Yd+yTAzXC7MAkKAe4jw@mail.gmail.com>
In-Reply-To: <CANpmjNP-YYB05skVuJkk9CRB=KVvS+5Yd+yTAzXC7MAkKAe4jw@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jul 2022 16:45:55 -0700
Message-ID: <CAGS_qxq5AAe0vB8N5Eq+WKKNBchEW++Cap2UDo=2hqGzjAekCg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dACUMMrT;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634
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

On Thu, Jul 14, 2022 at 2:41 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 14 Jul 2022 at 22:23, Daniel Latypov <dlatypov@google.com> wrote:
> >
> > On Thu, May 19, 2022 at 6:24 AM Marco Elver <elver@google.com> wrote:
> > > I'd keep it simple for now, and remove both lines i.e. make non-strict
> > > the default. It's easy to just run with --kconfig_add
> > > CONFIG_KCSAN_STRICT=y, along with other variations. I know that
> > > rcutoruture uses KCSAN_STRICT=y by default, so it's already getting
> > > coverage there. ;-)
> >
> > David decided to drop the parent patch (the new QEMU config) now
> > --qemu_args was merged into the kunit tree.
> > Did we want a standalone v2 of this patch?
> >
> > Based on Marco's comments, we'd change:
> > * drop CONFIG_KCSAN_STRICT=y per this comment [1]
> > * drop CONFIG_KCSAN_WEAK_MEMORY per previous comments
> > Then for --qemu_args changes:
> > * add CONFIG_SMP=y explicitly to this file
> > * update the comment to show to include --qemu_args="-smp 8"
> >
> > Does this sound right?
>
> Yes, sounds good to me, and thanks for remembering this. I'd prefer a
> close-to-default config.
>
> > [1] Note: there's also patches in kunit now so you could do
> > --kconfig_add=CONFIG_KCSAN_STRICT=n to explicitly disable it. This
> > wasn't possible before. Does that change what we want for the default?
>
> I'd just have KCSAN_STRICT=n by default, and if desired it can be
> added per kconfig_add just the same way.

Ack.
So concretely, so then a final result like this?

$ cat kernel/kcsan/.kunitconfig
# Note that the KCSAN tests need to run on an SMP setup.
# Under kunit_tool, this can be done by using the x86_64-smp
# qemu-based architecture:
# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
--arch=x86_64 --qemu_args='-smp 8'

CONFIG_KUNIT=y

CONFIG_DEBUG_KERNEL=y

CONFIG_KCSAN=y
CONFIG_KCSAN_KUNIT_TEST=y

# Need some level of concurrency to test a concurrency sanitizer.
CONFIG_SMP=y

# This prevents the test from timing out on many setups. Feel free to remove
# (or alter) this, in conjunction with setting a different test timeout with,
# for example, the --timeout kunit_tool option.
CONFIG_KCSAN_REPORT_ONCE_IN_MS=100

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxq5AAe0vB8N5Eq%2BWKKNBchEW%2B%2BCap2UDo%3D2hqGzjAekCg%40mail.gmail.com.
