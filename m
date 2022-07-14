Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBJ7WYGLAMGQEBLQEP2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B2CF575649
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 22:23:05 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id g19-20020ac25393000000b00489cc6219fcsf1200824lfh.18
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 13:23:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657830184; cv=pass;
        d=google.com; s=arc-20160816;
        b=HcTS3iG+/qMHmE03t7g/LhkSi1clLTW5NZYzBXLsC0SlXGH8idFgrBISQ1tBhD1CFR
         y6eqesOQhqwJeOxmOiNF6mIoxrGpkXidiybvAVhc2JUGjxfuu2OEKS8dOMjlI+OnJudg
         js4wIWunYvcZG8TNvofTmwGIZSd2h4HeUVS27ZLtqI7VZYh2dv946QcxKyaz6WU9kLEe
         Ie5ujIuH+6YD4bDehQ/gre3vVnFoupZlM/heMRzIJ6ASforGoyUz2VjqGHys+dgJaaAk
         KAEs3tyL0KGA9C33gF8IuKWVl0y+3VnjHVfc07nLQ6Gi2QFHUZ1OFIr1Cm8Rl+wgUe1n
         kjEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AK5wZIrYYnEWGS9AxGcGWoLJqnRHBI9jq4gcfrC88bQ=;
        b=cUE29fm6RRhyalJVRI0cz+7FfTuAvMktttFbgGynNcRtr5HRG90XOrqHuFt8Vch5c2
         qsDXIej6FVRI7BlzWnzSI5Z9rPjBunLdViq64OgqhElbDBPPO+4zLWZaIZzmoIRb0M24
         LLH9dN+bcx7oxV3kWvmBNdA1SVdt878Cxjnl3xUsAErGEFuzmevnGqxqyINCPD0dHZYc
         NlDWt38wBC0ii/o4VGwMtqlY0cmpK4a8Rd6RskD3DQimxCodZXco0sMdZVxeUIvAHeVb
         A04li5qpQMDh1gKKq95WqXuhdn+xN5Lba2ciFVs18/vHx0XpK2jHKFuJ6OgNdWjsq7Az
         LnPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M14PGsSK;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AK5wZIrYYnEWGS9AxGcGWoLJqnRHBI9jq4gcfrC88bQ=;
        b=eiIMhqMEMoklIKgPgV50Qs+nV1AlcHDCfx/nvMKDqj4kAULOaMMUeCoHRFzGruI8GM
         JFLuC/5IQBvC/OWTi0/E0gLnrI8q9xuS49nQCmE/Shcil1F/N3wxv3v+WDU38F0N9wqY
         6IhcxPXK9g9YqBCKEOM13yHiuECYoTjP3QaZoXzuZEgWhKOqdTmdYCn5tX1ra8p/zYng
         fTfWABbhwgezxuwaY6GAypLMYp5vvGIwXSqnxqOXVXGGrQW2cKZi7Xe9DZD5agm8eQf+
         gLNPvUTCQJX+F7gu1NeQDI1enZH4wQEEZ/0RIBEruGn9w4c3izvoe1mU75XNWf6MF+wg
         UhBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AK5wZIrYYnEWGS9AxGcGWoLJqnRHBI9jq4gcfrC88bQ=;
        b=0sowH/Wcna/SKyvfQ1el7GjSTrr4M5Mzh9NTOB+KKPdiEr/MZtODHoiCXuXt5X9cbF
         nYigKm51f5lnKpDuTi58eWvh8ID3OELj9iiHv/svvj8s9GBclznHw+QAk1yQhW70HjzG
         RCPW4mPIS8AOoKGj0SUTGJl00FIXTWYPkeATYbRTBaiskNitL8EtkAX9WPMwLUY7b9Ha
         5IwY8H849DvdsgrMplQxN0H97k5LM2o0C6vG+M6QO9c4RgsGqwvLx2C+JU+Yu4AhYoyR
         Rp/RG3juVB9kBcAhkgqqLQiPmCv6DAT2woMbgNG+UseO6Xtn77RgDY9jKp7PVBpOgYAz
         A1UA==
X-Gm-Message-State: AJIora9eAwkOPDA5BZZXS1tAGKCMXlHp4PFKYWXjAu7SE16EDhwpU1Zd
	iXMRDWIr/2z8kEPrOmUms1o=
X-Google-Smtp-Source: AGRyM1s9rRuNrxqHhPgepCcbYZGldLCjuo6tJGrUvB88W2PDQNS6pm5Tctz9R3wzqgSG200NV+A2gw==
X-Received: by 2002:a2e:a4a5:0:b0:25d:980f:8ba7 with SMTP id g5-20020a2ea4a5000000b0025d980f8ba7mr2985336ljm.513.1657830184180;
        Thu, 14 Jul 2022 13:23:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a05:0:b0:25d:5514:2fc3 with SMTP id h5-20020a2e3a05000000b0025d55142fc3ls1809131lja.4.gmail;
 Thu, 14 Jul 2022 13:23:02 -0700 (PDT)
X-Received: by 2002:a2e:9b0e:0:b0:25d:9ded:7b4f with SMTP id u14-20020a2e9b0e000000b0025d9ded7b4fmr1653805lji.4.1657830182022;
        Thu, 14 Jul 2022 13:23:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657830182; cv=none;
        d=google.com; s=arc-20160816;
        b=OnVMLahhN0yRSt17i3EN1Ojuk8X+tGs5opXpREA9wrXwWoIobWgIbkHq/AWnO7HJCN
         NnnkvaeGAA0sHr+joOL7bSdm5QotEB3Hn2kjZbqovHO5x8S92NL4VA7hjFfi0SvDnCtM
         zJkp7VsaUNiM62zN7zLmkTEDRAr7lq+g67FSXY2YTbP9RxzhsBclAYCQnKx84FslULsQ
         rWcDn94MuMQZYcoKh1MLEZ/ecV5TQFUaRvQGw6csxJgFZjvMJ2l//qo19fCsJ5ZHkOSS
         rLPkZClrBc91JJ2iS2JNZ1L+SlOBsJvxFtZ3IiP8JHgn34UmURdToe39lRpCJgooM8d9
         1ieA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DJyqb0gXwX9toDZcdJ0Ejs1ECxk9NdxpXaz6/AftgKg=;
        b=l/E3KVlnB371UExtcW67OTQRNivTJqmRE9SCEslNFWq2xzZ1pR/aXcBCsXvc/VDOhb
         2seHUKPF5HrbWKV2axvrdYG03W65W1Gm2TzSOwTP+yOa2JKPbXG2h7/FPMNCqe0Ec0VU
         +N94DH0yzdaDRt3X0+pLmk//0I+vrTF3dWPmZL+Kt2ZEs1AwHGZ4cjzFfCU0kS4/R9TV
         99wtYTmexJDpviRV80Ih530DY08Lu5Z1bSGpK5NlOusV09CKJ7TwYJ6ycKcfcoLOW3GZ
         vViAjPpDBMv+IITqpJoBKlyni/d9cbjgFqDsxyFJY4TrD/SE6kASd5QAyVAzsLbA58/r
         5wlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M14PGsSK;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id k18-20020a05651c10b200b0025a70508721si89212ljn.7.2022.07.14.13.23.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 13:23:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id va17so5507674ejb.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 13:23:01 -0700 (PDT)
X-Received: by 2002:a17:907:a06e:b0:72b:2cba:da35 with SMTP id
 ia14-20020a170907a06e00b0072b2cbada35mr10407054ejc.358.1657830181392; Thu, 14
 Jul 2022 13:23:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
 <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
In-Reply-To: <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jul 2022 13:22:50 -0700
Message-ID: <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=M14PGsSK;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::632
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

On Thu, May 19, 2022 at 6:24 AM Marco Elver <elver@google.com> wrote:
> I'd keep it simple for now, and remove both lines i.e. make non-strict
> the default. It's easy to just run with --kconfig_add
> CONFIG_KCSAN_STRICT=y, along with other variations. I know that
> rcutoruture uses KCSAN_STRICT=y by default, so it's already getting
> coverage there. ;-)

David decided to drop the parent patch (the new QEMU config) now
--qemu_args was merged into the kunit tree.
Did we want a standalone v2 of this patch?

Based on Marco's comments, we'd change:
* drop CONFIG_KCSAN_STRICT=y per this comment [1]
* drop CONFIG_KCSAN_WEAK_MEMORY per previous comments
Then for --qemu_args changes:
* add CONFIG_SMP=y explicitly to this file
* update the comment to show to include --qemu_args="-smp 8"

Does this sound right?

[1] Note: there's also patches in kunit now so you could do
--kconfig_add=CONFIG_KCSAN_STRICT=n to explicitly disable it. This
wasn't possible before. Does that change what we want for the default?

Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxr_%2BKgqXRG-f9XMWsZ%2BASOxSHFy9_4OZKnvS5eZAaAT7g%40mail.gmail.com.
