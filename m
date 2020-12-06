Return-Path: <kasan-dev+bncBD63B2HX4EPBBTHVWT7AKGQE5BRU3IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF1A12D070F
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 21:10:56 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 5sf5058274otd.13
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 12:10:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607285453; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZNwpar+Mpq3sK8grESCB4ELnQFjTlZm+2mCowLEL3bJ8g3amcKa2PUGVlieSnxdUJ
         hgUD9GGOw1eF0cdK5ANRgq7ruYaZHKDEV72SRqG1+v1NVWxmtaIoUsfT0q1ZpgvX9aJy
         YEu+P1LfGWaysXNGMaF/t2uPIIONB1wj2D2JXkymyCESMaXEgrBXnkN1wgeLGCBkV3Dd
         zIpbtMxH5rh6EujrXhF3f0pZQ3kzzfLJkB5JkVQvHC9jFUiRlBqJ3bQ//dyXjMXfklCJ
         oYiknyYyhsHb3XXgw5luJEQS2uAYE2K5Q51q4dv7uu7ikzKN4c4f1QTTgvAx+KinhsIf
         Dd9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=JaY9lRanrqXASfK7vC+9rgtuqUkuOYU+MqGSe9eTt04=;
        b=GuSoLEV4m4l11vFNae649EY4srB73Km2mffSzzxbDWCfsthEEOKtIYFRdS6PjrCcUC
         CIFgNbrV+YgIFNBws9S4f9dcQiqT4LgbqeJl/Bau+ekRlNGnpGBptrNgx6VEq4gN1Jop
         4kXN0ppcF2spm7ZxeM4egwcdJvXDRPqtKG8eLyIS0BP1lbEA/BiEZbUHjqCi6SfzDvyi
         taujTyffg1ilvrPQZsWiGed47+i88PtjW0goLRRwRE/FtlhahTRHSB+2Pu4uTA3rB+TJ
         ZE1rrCZgVgIml0ju/7LBRnhJirEXzOszb+0WiI4SPDTN0UqQtWgron4qiy2qHFA0XOJ+
         M7rA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=mepdYmt7;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JaY9lRanrqXASfK7vC+9rgtuqUkuOYU+MqGSe9eTt04=;
        b=pGsLY5MeYEE2v+i9M17OLkrmLFHq7G15vNixBt1+DOGSEmBrIR0awkRikWqj6Gvajg
         DA8lFuyHehWQWBS7NdlcTsscSkc1iR3v3Mtpj4WFBJ8g1lTGgGbL1znlzO1RGLHoA4CQ
         zHkMBr6QLgnuQO2PdU3EV6i50YcsOtgTqZt90YMb3m5ZpWPYBGXw+U+/15qimft3gYch
         R+5RCMzqQY5nF/f8cGkgPBfCfOEF3LOGAzS9gbEwz9a9/BzPEUuNjH/JxhNCTpJk8QdE
         SzLnyTZYuD5lN4BhsLsB7LcurBZvsxdReEr/pRX7CdHTt0Ur3m3HVLr0mXycxRD7RSnD
         jmEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JaY9lRanrqXASfK7vC+9rgtuqUkuOYU+MqGSe9eTt04=;
        b=s4R6Ys9HH03di9Vi2sgI0/mdZMT6io60cXb9oV2e9owzqFAVE5L1KjKJcm5ttALC5W
         do8hxAHYtEcO/nkG8b5Q6m7YQhIq3KM8cdptffh7MAbQpw7ygz/IrJYtzPljwnthgW9N
         Kodpfckle5a1avx1Ened+MDc5xr9bztzA2oNy262+LLBgO5CDj84s/snrVY/UfV4m422
         mjuAkNccZ2sL3dR0dI7R2uO1DdJaVl6KtkZexlI6qo92t/ORoW7QRpnEoStphA5uxipb
         4ABeCTEM7v/ZyClKLFmzDbhQLfMwDtaF//zudBacmhHaVIMibsGzHJlJbmrLV0OwBvDy
         BtOw==
X-Gm-Message-State: AOAM531ZdvxbHK4VvFDMFLogGk39qasDZntSj2XRjr4C9+1vEhJUVRKm
	/RAL8DMdr0AVcQ6L9zGypWo=
X-Google-Smtp-Source: ABdhPJxTpd9N8oQkEX7jkJ7jWOlD8TNfLWfMJJj+kXzBV9ZnKl4FAFwfI1Jmq9Hftvrb3ydC5N0vyA==
X-Received: by 2002:aca:3cc5:: with SMTP id j188mr9248995oia.100.1607285452535;
        Sun, 06 Dec 2020 12:10:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4c0e:: with SMTP id l14ls3675841otf.11.gmail; Sun, 06
 Dec 2020 12:10:52 -0800 (PST)
X-Received: by 2002:a9d:3b36:: with SMTP id z51mr3333641otb.272.1607285452194;
        Sun, 06 Dec 2020 12:10:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607285452; cv=none;
        d=google.com; s=arc-20160816;
        b=UG3aJfZX/3rjQT3h0YN9IQuCm8qF22DzYdzzpwCIJJUCtiveyTu6V0OKwEflm6raML
         6lAgwPmpUIrABN9nTetz7rPzfKjEVgA7swbU2mGDjtNxN+WmOKEKSFOQd38nVvHq12gu
         C3v00y8WDbWLW84/pzhsUCjPWCQoGMnN/Dujzoya4K9ozIFYvpYjBjuF5YdO5wkouSu6
         p4zOdhtRM3E5XonYMllyglFNUk6VPsDi+AOmEVOBsCBBykEGWHx1pgxoDv52IRN6j3CO
         Z9tv0lS3DYdrDorvs6UK3/9ZdZm5BgyWXYmXQsB2XS6YWfWIt9ub1BEnJRsJU5MUoRk4
         ASEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SaI33A/iSBFxHOGg2cUK/lRbMARvVBB1/YoexE+aIbo=;
        b=e8Oc3QqR1TCVX6KPeueGS2batTFJFCo9D0EGcuGIwImBorL2BnQTOKjkZz3McF7Nwx
         OLb+GEvgzhLliBC6K9Xvv5FQ2G0LGB++D0kPS+714JSRric33fbLUzMf7jboIuY4DKwt
         k3xF513Kk9plGWThXTw2wr3H9NJdBa758VQ483Lj9KbdKYMtBQILeuTF5CdUvgsDUvLl
         3lCZ3ccs7Np6zoMpHDzvyr60QKKQ28/3YsIhURUyXsLEXD9n7clqMJyqTYItxrPqaHMl
         v7SkzYPvnaAH2UZsCH0UAV9/M+pYQwfeGAdV8Khb5KsxVzK+BId4Oko/QoGvTi2Lu3dL
         7PGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=mepdYmt7;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id l23si429897oil.2.2020.12.06.12.10.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Dec 2020 12:10:52 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id f9so7048648pfc.11
        for <kasan-dev@googlegroups.com>; Sun, 06 Dec 2020 12:10:52 -0800 (PST)
X-Received: by 2002:a63:4184:: with SMTP id o126mr13135526pga.362.1607285451501;
        Sun, 06 Dec 2020 12:10:51 -0800 (PST)
Received: from cork (dyndsl-085-016-208-233.ewe-ip-backbone.de. [85.16.208.233])
        by smtp.gmail.com with ESMTPSA id g34sm9953056pgb.33.2020.12.06.12.10.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 12:10:50 -0800 (PST)
Date: Sun, 6 Dec 2020 12:10:45 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201206201045.GI1228220@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=mepdYmt7;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Sun, Dec 06, 2020 at 06:38:45PM +0100, Marco Elver wrote:
>=20
> Toggling the static key is expensive, because it has to patch the code
> and flip the static branch (involves IPIs etc.).

I see.

> At that point, you'd need 1) a very large KFENCE pool to not exhaust
> it immediately, and 2) maybe think about replacing the static key with
> simply a boolean that is checked. However, this is explicitly not what
> we wanted to design KFENCE for, because a non-static branch in the
> SL*B fast path is not acceptable if we want to retain ~zero overhead.

On x86 the difference between a trivially-predicted branch and a NOP
(assuming that's what a static branch turns into) it about half a cycle.
I haven't measured slab/slub, but my allocator takes ~40 cycles if the
thread cache hits and ~110 cycles on a miss.  Presumably slab/slub is
closer to the 110 cycles figure.  Therefore a regular branch would add
about .5% overhead to the allocator.

In profiles I typically see the allocator consume 1% of overall CPU,
sometimes 5% in particularly allocation-heavy workloads.  So overall
overhead would be 50-250ppm.

Static keys use text_poke_bp().  The do_sync_core() looks fairly cheap,
I cannot find it in profiles.  Most of the cost is in the generic
interrupt processing, but let's assume that to not matter either.  That
leaves the text_poke_bp(), which appears to consume 90% of a single CPU
with We use CONFIG_KFENCE_SAMPLE_INTERVAL=3D1.  Or .9% with the default
value.  To match the 50-250ppm cost, you need 36-180 CPUs.

Please check my calculation, but it appears that static keys are bad for
performance even with your default config.

> And KFENCE is not designed for something like 10=C2=B5s, because the
> resulting overhead (in terms of memory for the pool and performance)
> just are no longer acceptable. At that point, please just use KASAN.
> Presumably you're trying to run this in some canary environment, and
> having a few KASAN canaries will yield better results than a few
> KFENCE canaries. However, if you have >10000s machines, and you want
> something in production, then KFENCE is your friend (at reasonable
> sample intervals!) -- this is what we designed KFENCE for.

My impression is that KASAN has noticeable performance implications.
And that's basically a binary decision, you either enable it or you
don't.  KFENCE is attractive because the overhead is low enough that
people don't notice.  And I can move a slider to adjust overhead to some
value I'm comfortable with.  Am I wrong?

> My feeling is that you'd also like MTE-based KASAN:
> https://lkml.org/lkml/2020/11/10/1187 -- but, like anything, there are
> trade-offs. The biggest one right now is that it requires unreleased
> Arm64 silicon, and early silicon won't be ~zero overhead. One can hope
> that we'll see it for x86 one day...

I'm very impressed by both Arm and Apple on the CPU front.  When I saw
"new security features", Intel had trained be to expect a trainwreck.
But Arm has created something very beautiful and afaics solid.

J=C3=B6rn

--
Money can buy bandwidth, but latency is forever.
-- John R. Mashey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201206201045.GI1228220%40cork.
