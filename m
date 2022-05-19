Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBNXUTGKAMGQEHK2LRHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CB43A52DAD6
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 19:11:19 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id u6-20020a2e91c6000000b00253d94dddecsf394370ljg.16
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 10:11:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652980279; cv=pass;
        d=google.com; s=arc-20160816;
        b=vJ1MBbpdAsNCImbYj1eVQ5NKd5QGw81JPBLaQiI31YY0LBC531nbUrm0uRXZacDxZj
         F3I14SUovSBakIj3hmX0NyvylpRL5DcMne4MhfhftLluu1U2RghJHtHxdSzXZ23W4sWy
         2jCbUzYepv7sSOs0VspOxv9lxv1NKRusCAI+kLjZtd15jx962HRR2NDiX9yiqGPquhSB
         bjF+Z42AzxMqMalmKu2ukkoSIkv/+pktANjFcWWshOqbMC2iDldtFBv/alLWUHVQfSf2
         e14HTu3KiJmlo916QD2yIQ/vJ9R6AaO2ZZpshcVgMoAz5D2KDefdxTlQq1Nuv1OOVWZB
         3k6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UL0FqekNK2hD+XLTwjCklr1uOF8PVlqsi1BllR0h8yE=;
        b=ud9i+kQjzhieLfkQ4hUsAIjKcM8ecN0wIGVKhAeZ/GvKmgR1FjXOfveCRG6pK9DjOL
         2bnhZRr6fZK+OZ1fp1jWCtYFvPeWvcjILR5cY59y4E1+QiUT1CwDu/X+f0ur5eHOOg/R
         mSouuoiT0o0UFbrxycE6XIPKwNlacK/FfEvV57p14sVVORW/+hvx7cUFRFciTgMLpLYg
         SdHaLDH2+/Xtth+G3oG/2JfEsACZ190hpu3PP63hq69g8aM/oQcvTko6Onfpu5tKdzIx
         +wDXh2plHjswoaz0nqfGs0jdTr7jAGwVC4tEN+8I1XtPzw/ShF0WZC8AlvDZn6dm4yrI
         IyYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TUnSopuT;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UL0FqekNK2hD+XLTwjCklr1uOF8PVlqsi1BllR0h8yE=;
        b=GBqtgoWl7mb7Nw4YTbTm09ZsLLbbNm8ZwXRFAzfa+N9+S2ItFio7GNgwgnpn8g6qTK
         LorB3KTrXCAT5gnsD9eucz4Ey56/Ofb1EpuHPqvyRicbtoNbA0/Fkxkx6GYZs9/koSV8
         I0PsMHDNRh/n5yjMNkMaI7Ltg0uAyhM63NkeuKK3Wx7t6c5Y60t2PxDeNm8HWgSaTw5Z
         QeqLzKOqaUgAsUsJEbagooKGWyCgoxLdTH3Gb0d37fIl1dKjfLmiSYlAk0RRekKNlddD
         RPMWAZb7W+gt0ePnckxs4cG7BzU1b6mrfqAXs3GFQkwZ9a9JwhioJuq1AAyBR9lYqlh6
         AwLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UL0FqekNK2hD+XLTwjCklr1uOF8PVlqsi1BllR0h8yE=;
        b=lYfvhUonjpGgEVZMRfzDDU2mopGoEPO8SU8FkEZ9HQDrLspHNlCUK0aQNXodRie/Ub
         gFciqEyRDzUwnCIzi2YbGeQugFGLKpDRFihAUS2mFNK7W2jmV86XIwVKkGbTOkqwCkDo
         H+cj4uCnmRu1CuTMvj9MCDGXc5jNBIuJacp+p09a2ZuEEnyy5/hvPJrs9zRSqdtK+4Fc
         ELmJNKgNvC9LJCaJTB42fL0HEAl3V0kxAR0fMGLfy/hHH1aPuEbQat1/qi3h7UIEE/4A
         edZk33SJ2NHVlASo3bN5kYngbIKjMWLZt/fbSoqMvEOogYlKDf8pkRPDLwi4yP/nyUu4
         bndg==
X-Gm-Message-State: AOAM532ULP14u+vqznuGVmoS9/GRuDcqjtK+8HU7JXqh05efJ/v/jqnH
	pnfqdWLkOqJ4hkR5WwwENNU=
X-Google-Smtp-Source: ABdhPJyk26AAycwHkdqKj4zbP9GxWzLBoC0Zo/uuFepNVMLhvdKHCoYx4JYlp+CedfzjpPX7zmB5oQ==
X-Received: by 2002:a05:6512:1692:b0:477:a14d:1eae with SMTP id bu18-20020a056512169200b00477a14d1eaemr3996954lfb.176.1652980279209;
        Thu, 19 May 2022 10:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2967654lfb.1.gmail; Thu, 19 May 2022
 10:11:17 -0700 (PDT)
X-Received: by 2002:a19:7702:0:b0:477:c134:bdbd with SMTP id s2-20020a197702000000b00477c134bdbdmr4111435lfc.317.1652980277801;
        Thu, 19 May 2022 10:11:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652980277; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWcBSN1jVhYd/c1XPW5uW/fkhCPR28SZQJlQIi3AacRCXjXHULy2uHJgprhq19iGUb
         4XU80N/UmzfDnONeVHiel87K0ep4I2nGh2n+cI1A5OaPGV1qWH4U8XIwZZ+uuYRqeAXv
         TPXnKFQuYjsOIDnw2eGrD+jTpnd15WN5pzfdjGgR/m9eTrsmh46OtqY5VulRrKLRM8g5
         twjunTqWLH0NtgDKXU8JouSOJYxGFHarqOWxk+FII5NJTQyCfp3EzZZeAI5c5vluAkXb
         9J1Wq2a//oWb/+N4ATsJgFzuwGEMpKSSaeSX64Hgye7KSjKIwsXB91Emx+LSCAeIXAtp
         w3gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ctr4gplq7tIvfpEzcReXp2Tbx4VBOJ0VA7nTlFJ97VA=;
        b=QZB/T9gehhuqDRMSVnBd5FX0LFYyUcYNuPrU+nyUqfCHI1vw6Lytdc9j4hk1By361A
         qo7BaryNkG9y4V1RBblqtjse+z9MQJfFI0L/CSjOkjaEfZ1qBDEJ6BzLL2mUk94ccbiV
         PNLIq11rkzNAG5yMq0fu9ECk3blkQu/zh30+E+llumVstZUO17S+Uu5XXix7cr4nqx2m
         axfgMQlIJd8Ncox+FHDRKneL8UtWjLoo2Elkccyx5Ap3ODziB9U8Eu4ArBW4tmWdIkU0
         jaJcmVvYgHDKkIAhf6tDWo/pO1Fz60tDI+6JfOP/3lQ1nU1WI6wT622mf0Q8W4LvxMIS
         Pbbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TUnSopuT;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id bp22-20020a056512159600b004720a623d80si163855lfb.7.2022.05.19.10.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 10:11:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id s3so7762057edr.9
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 10:11:17 -0700 (PDT)
X-Received: by 2002:a05:6402:84a:b0:426:262d:967e with SMTP id
 b10-20020a056402084a00b00426262d967emr6618652edz.286.1652980276934; Thu, 19
 May 2022 10:11:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
 <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com> <CABVgOS=X51T_=hwTumnzL2yECgcshWBp1RT0F3GiT3+Fe_vang@mail.gmail.com>
In-Reply-To: <CABVgOS=X51T_=hwTumnzL2yECgcshWBp1RT0F3GiT3+Fe_vang@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 10:11:06 -0700
Message-ID: <CAGS_qxqsF-soqSM7-cO+tRD1Rg5fqrA07TGLRruxPE4i_rLdJw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: David Gow <davidgow@google.com>
Cc: Marco Elver <elver@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TUnSopuT;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::533
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

On Thu, May 19, 2022 at 6:15 AM David Gow <davidgow@google.com> wrote:
>
> I tend to agree that having both would be nice: I think there are
> enough useful "machine configs" that trying to maintain, e.g, a 1:1
> mapping with kernel architectures is going to leave a bunch of things
> on the table, particularly as we add more tests for, e.g., drivers and
> specific CPU models.

I agree that we don't necessarily need to maintain a 1:1 mapping.
But I feel like we should have a pretty convincing reason for doing
so, e.g. support for a CPU that requires we add in a bunch of
kconfigs.

This particular one feels simple enough to me.
Given we already have to put specific instructions in the
kcsan/.kunitconfig, I don't know if there's much of a difference in
cost between these two commands

$ ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
--arch=x86_64-smp
$ ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
--arch=x86_64 --kconfig_add CONFIG_SMP=y --qemu_args "-smp 8"

I've generally learned to prefer more explicit commands like the
second, even if they're quite a bit longer.
But I have the following biases
* I use FZF heavily, so I don't re-type long commands much
* I'm the person who proposed --kconfig_add and --qemu_args, so of
course I'd think the longer form is easy to understand.
so I'm not in a position to object to this change.


Changing topics:
Users can overwrite the '-smp 8' here via --qemu_args [1], so I'm much
less worried about hard-coding any specific value in this file
anymore.
And given that, I think a more "natural" value for this file would be "-smp 2".
I think anything that needs more than that should explicitly should --qemu_args.

Thoughts?

[1] tested with --qemu_args='-smp 4' --qemu_args='-smp 8'
and I see the following in the test.log
 smpboot: Allowing 8 CPUs, 0 hotplug CPUs
so QEMU respects the last value passed in, as expected.

>
> The problem, of course, is that the --kconfig_add flags don't allow us
> to override anything explicitly stated in either the kunitconfig or
> qemu_config (and I imagine there could be problems with --qemu_config,
> too).

This patch would fix that.
https://lore.kernel.org/linux-kselftest/20220519164512.3180360-1-dlatypov@google.com

It introduces an overwriting priority of
* --kconfig_add
* kunitconfig / --kunitconfig
* qemu_config

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxqsF-soqSM7-cO%2BtRD1Rg5fqrA07TGLRruxPE4i_rLdJw%40mail.gmail.com.
