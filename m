Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNJQODAMGQEXYOFJAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DD76F3A17D4
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 16:48:46 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id r5-20020a5448850000b02901f4271c7d03sf3859731oic.4
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 07:48:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623250126; cv=pass;
        d=google.com; s=arc-20160816;
        b=cqpsgvg8pXVjGiCl2Pf5a9DoBZMQeIsmi9ei5hoHXj9F3nyfAFFiBC4IHfHHsSfchq
         E0gUGwcdmd+l6MDsZObYmUsUrSp3nyb1xc1gpIvQ5gbdHXMt3GzYf9/5ldO7vUzITdt4
         4t3V3SSyRJXjLGK+MlKin+8NI2QToSwH3yA3jtw1Za5taTJD5i745nF3mSPFiotcBIC/
         G6xb3txHH8WSHQ5pkAZ6jKooycT4ZnQHOAazeH/p6CHkPOvoZmRIJr378ax8gqPYXs83
         KFkcKtqXXD4t6I0yK0WP0oJeZpCexxYQ5wfipd6uG0GEhX3q7NhoVRH9HmgYdr02XAOx
         06Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x4KPtlo/7gDiuqR1+JQ9fDq5+d4/o1zZIZZZaPfMrg8=;
        b=BVEigHmxDXbIUyHFtBREOH2cFTIwN8hhVygfUqG4gDHHHVe9KCAXVNMrmLKAqxtAtG
         qAqGDQ42x2rCJuDbb/klZffBiX3PhnhFjWMPXtphn2V3QphqbpQf8Nvcxdl9wH715cxF
         XFkgg8p+cPPZJ2CcZwQwX/pnV4jkBy2FKOe8QejlJiWPIHnvNsb9G25bWyDuWCsP3kps
         im5RuK9m5DOOLuuEnzbfT8ea37uj4D+Mk3GbKdpvUhTK+lNresF5Ix2CYA7ThouI4SzR
         /2wL2SosnwbJpKex2EdpjzOYp74vbZDTUjJN4GRcchwmhX/ERlBFJ/FyUilihzNOfQF7
         Bcrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FPzO9ihE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4KPtlo/7gDiuqR1+JQ9fDq5+d4/o1zZIZZZaPfMrg8=;
        b=ZhSmBe3X3pzcNP9x0Gx/pz/QPrOeCBfmfurUYq/ACeRIvly2WPFIYsnUsJoPNuW0nW
         Y11XlHAbmqo1uLRxXLdvW6zoT0+bRxtTB1Sim9Cbga9OaICEIsg6vOY93IqlPa3wsTMC
         EZjw8BpvJ2oR+KrTpAnpggXE7Ndbruo32VO7dk/kCTc2ea0Kn1I4foPTUqpnrZF+/C0R
         d4HO2JzFruA42kotxdX0BrtEFJiO8s0m270AP1lkYN78p1EePAevEHZVIeeKZlQS9H98
         0sfYd5Q1BH8OdaA5rLqGdMMlK+U3f/YBD1ZZ8n3lRjcsQ2GsIJNrUl8nLLYPqiYJTxJ6
         VNEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4KPtlo/7gDiuqR1+JQ9fDq5+d4/o1zZIZZZaPfMrg8=;
        b=Z64kC68I6HXpH1qypdl/SnyyHtai5Q90YAeinJuZHslyR21v8DPPryVKN7Kx6NNRfc
         1GWpv/LasUqDL5QMvA5WAeIriZBAIuIel6alH56kguOxTH7WbuLrMiRZT3pwOWY+rLoo
         THvtPOBHLAV+H37ArSW/Qau+rE/VMA0OtleBGDMJXRz94S2vtPQi+vJBtKQ7nTmZIMMB
         TyHhSQFk1xt+lbBTKTPLkHy66R51bLNC5JFPhEFhQVUTMrBhPsYYE6FJG4tDfPemCEQ9
         u6pisjdgdrLCGn/lXC03jfL8thLqsuQHRxqvkicqcEox/UBP7XBXtaSbVZnCQva3rk2T
         ogdQ==
X-Gm-Message-State: AOAM531sBu3ZwwUJhtLbfwMXWaNB4hNo0mnTDyxiDozolSbXsOD1/Q+T
	S4eBRLyh/1mNBTIvd6H9f5s=
X-Google-Smtp-Source: ABdhPJwkkRpKEaN18rf/4Tvhig72loTj52ZzGUWZJOm6bNjNdnA7n0oB9dPxD8e7MGldzwKi5KTQxA==
X-Received: by 2002:aca:f488:: with SMTP id s130mr21324oih.5.1623250125908;
        Wed, 09 Jun 2021 07:48:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e45:: with SMTP id e5ls896971otj.6.gmail; Wed, 09
 Jun 2021 07:48:45 -0700 (PDT)
X-Received: by 2002:a9d:27a4:: with SMTP id c33mr23673402otb.281.1623250125545;
        Wed, 09 Jun 2021 07:48:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623250125; cv=none;
        d=google.com; s=arc-20160816;
        b=iGZPhd3Tb+gs0xmG7inqcmIuaitHCyvIDSUHCV4wk3BO4WK2GjWQ013/oTKlhJurw9
         iuU3KZRqTkGvi6wICmD5dqhIMFrA8XhYrpCCsM95WIcTrPgYs6sMHD8NX+NwHaqn3XdB
         WzL10OtwspD6MCFz/Xcw3diMXgs2Ocxr/7vIpLXB4oqftCIbAgFH5lifn6WGTQy0EhBX
         8QPrYG3hq2gNZ9ZjFOHiwBbGoWZZurEF9iMAdqe6wCmeqfoe08MMj7/Mfr0E+r1/Ss5M
         48zUt7x1/k2weVCrKK1rsupGh0NdpMIMBdA7qlWIBs4d7Lrz5OeRsMATPrRHjX4nz9Fz
         mHTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RTh8R/SkvzXRGPhrTpf9c7cGy1PDb0Bu2dMrsT+Lr58=;
        b=yoQAvwQOBHp8nUMx0XMr4iKx82KYCg/gzFYzTAnoDBNfipSDzWdW57bR6SOQhLdwDX
         OIfS1TDLVEvXyqq282KXXFFaX2RHyhflLqU52gpkISBHwgG2BaCUcuWK5zPjfwtLy2XT
         iMDluWIFa30ElQel8L8GvqPCRo8BeC1QVMIq2t+lJYXJU90mdvmm/R2Rm20n079RAdFM
         1BgPFd2Vpe4LWH3b6tdYhE5TpHtoIwKVutluKFAob1h54FL4e3fbyOTOc/G/ALH5XfWt
         KtWUgZIbCIRwoz/iWpZEtc3piSuDsanAsuPRGQNpxXRXK+1ZeYny6czemncP0BRMEBPE
         Nzjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FPzO9ihE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id e17si3253ote.2.2021.06.09.07.48.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jun 2021 07:48:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id l15-20020a05683016cfb02903fca0eacd15so259140otr.7
        for <kasan-dev@googlegroups.com>; Wed, 09 Jun 2021 07:48:45 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr8740513oto.17.1623250125090;
 Wed, 09 Jun 2021 07:48:45 -0700 (PDT)
MIME-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com> <20210609123810.GA37375@C02TD0UTHF1T.local>
In-Reply-To: <20210609123810.GA37375@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jun 2021 16:48:33 +0200
Message-ID: <CANpmjNMvvdaBsN4QFVQ2CW7mB0yW2J0EF9aMd7RFg-K8BMkdgw@mail.gmail.com>
Subject: Re: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
To: Mark Rutland <mark.rutland@arm.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FPzO9ihE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Wed, 9 Jun 2021 at 14:38, Mark Rutland <mark.rutland@arm.com> wrote:
> Hi Marco,
>
> On Mon, Jun 07, 2021 at 02:56:46PM +0200, Marco Elver wrote:
> > While investigating a number of data races, we've encountered data-racy
> > accesses on flags variables to be very common. The typical pattern is a
> > reader masking all but one bit, and the writer setting/clearing only 1
> > bit (current->flags being a frequently encountered case; mm/sl[au]b.c
> > disables KCSAN for this reason currently).
>
> As a heads up, I just sent out the series I promised for
> thread_info::flags, at:
>
>   https://lore.kernel.org/lkml/20210609122001.18277-1-mark.rutland@arm.com/T/#t
>
> ... which I think is complementary to this (IIUC it should help with the
> multi-bit cases you mention below), and may help to make the checks more
> stringent in future.

Nice, glad to see this.

And yes, this series isn't a permission to let the 'flags' variables
be forgotten, but perhaps not every subsystem wants to go through this
now. So seeing any progress on this front helps and we can also use it
to give concrete suggestions how to approach it (e.g. your accessors).

> FWIW, for this series:
>
> Acked-by: Mark Rutland <mark.rutland@arm.com>

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvvdaBsN4QFVQ2CW7mB0yW2J0EF9aMd7RFg-K8BMkdgw%40mail.gmail.com.
