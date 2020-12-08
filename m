Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRF6X37AKGQEBMXJ77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 81C4A2D2E83
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:44:05 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id h2sf3511526plt.11
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:44:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607442244; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxQAtPrii2m0a7RhdL7mhb8xL+71Qk8wG4qXGe647KkCKB2GEM8EFWzEeeqqoTGve2
         9Vgthrfw6DRkWXQ5YG0b0IpfFuuFL2xhH6MriF3Bc5ItIY4BXv6CPbNURwyYvAtsQ2dR
         alqR64wcxuPWqLhXkVo8Zk7pycgCOE6KcP2LemvJfqEm6Xw5/LUSwL3gp2I7N+L+typt
         kuFfCqVdt3HC6dWIlXupXlM2AEJitCWTIconK26eF7wTS/reZCHQl4f4cNHipZ2vYHDI
         sTd1lMaHN/Uasn8iZQtCwAXp1nkhaCis2wqVfievavjQRIaChz51pOmUhFou88KmsMJr
         GY5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U5V/A6Is5XnHC0gTs/6lHzIudRe5fkvFQW/EP7G/ayI=;
        b=Z/h8/HdkRBpUslQSEB5OVqRs0OHnXnVQrCYdqusBjDt+SZ5de86Usj3Qgo0rxp2Zs/
         DjzP0vnH9SBph3RGw0WBntQTQMPGa6Ep8kiHlXLTi2CxkVOdARa0eE/9JUrOBL2JNZEG
         r1tJKYyn6igjvjsQ8FPQRXs6wxqjjlSz3ediQ2qJYzv2Ka9eobt4ijVHayHvQtHpV58T
         lUNzVU48Txt02MSd2vLaIZ6i0d5sThEWoKZ1F5P7/sWskTgBTLx7N9c1dqiqjqPxkyBz
         jfp/a8b1sDUlVbLOUjz6s98HadwS+Z7MR4iCk+qMHQhclCDujaW+Qa3vV+Xae2APrrXa
         UGww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eb2Honi7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U5V/A6Is5XnHC0gTs/6lHzIudRe5fkvFQW/EP7G/ayI=;
        b=dfuZlgeUQN2KAfJYd/k3QkEUTl9Rq5Kheg+L7hZhQX94RWtBWWAqkg8DaQUE43hAad
         JHmdLbtIGAZWRIQv9oh1uzjnAVUm8x4+DFiQUCEGrbu9n+RMVwN8S5e/ZlTXBbIOPwAS
         FKUn7OPP0UvY/ml7+aDJOb8Czr4fo2Yc8tGOk2LXUdQNO346rETcNyOTNeUNCMTTY7Yi
         Cy67FupXByql+/vFnDcWYkrL7J0VMX8Fkozpsq8molh7KhyvbxrN5pV7di9Y33+hxA5C
         a/ASF5Dv57JfBkFm9xL9F7Vaczq9w2DpcqFEdgMdRnuzDVKPm9bDiGhrPaxSBUk2xdEx
         xHeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U5V/A6Is5XnHC0gTs/6lHzIudRe5fkvFQW/EP7G/ayI=;
        b=FAIXdd//WrGB9OLLgZxS1tGXJlXswm8I8B3YZN921L1MlVnZ2sGz6mcOii10CLQU43
         wkLT4k6aXofRzprM1OJKEw5L9Bp4eRPC3taoFU6Py8f42aZq3ASjlKwZkqxbWkZgwMXr
         Rmmepi2UqrFWBR+QhSxB8gXbt0hYP2GdHxQ5agmRoLu9FC6lnT2tRNM+oA38tRuUAHVf
         vNPiBDHhmwW45QsLEphaQhebLLSlBtFyMo0OncH44omZAdBD4hxsG10pEv+t3BybguAy
         vDzVhwieV1p0HzP2S97OG7te57uqFGjRTCGgJgzVQr1px42UHE5cN2haJqs6ll1XHtEa
         OX1A==
X-Gm-Message-State: AOAM532/hWWrxsBmLeHopEJhQAVDCwqxW3mVuVgzwDtpVe9NWm5Y5iuq
	CtzsK/xsnmFPKvhEKWX5g68=
X-Google-Smtp-Source: ABdhPJz9V7GUwBZyf28lTzeReYD0UluAJm0NG16+nz4OV+4dn138AjZX9MFlZq2JVZmgaM3Q4LRLlQ==
X-Received: by 2002:a05:6a00:882:b029:19c:5287:4a1e with SMTP id q2-20020a056a000882b029019c52874a1emr20786890pfj.44.1607442244206;
        Tue, 08 Dec 2020 07:44:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:174c:: with SMTP id 12ls1614419pgx.2.gmail; Tue, 08 Dec
 2020 07:44:03 -0800 (PST)
X-Received: by 2002:a63:1107:: with SMTP id g7mr22643322pgl.432.1607442243571;
        Tue, 08 Dec 2020 07:44:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607442243; cv=none;
        d=google.com; s=arc-20160816;
        b=qreS8Tc1FXW/nmTGsz7iAxt6oLHCfeWMeisO6/I8acFjHAY3fHG4dPcFZIJEY22mvg
         x5IBuf4LHzM86MlsZEy7U/El3NZi9fSzlwOJnY0vxR9fJ0kq4HRWhDBFMz11Me2D6xG/
         dGAptiU3/wnoZOjNoeLahw2wgdO5PTMgheEKLXr4JiHtqhruue1jcVNdVh9I7SCYGORh
         hlZ2XIugIbfumz6vQjsF5522p7no3mkJnaCqqJ9o0nxPJFoPXbEEt0dxozXR9FhylyeO
         jL7w3yWbBtug+LM0ZOGnP0hdGJtKWILa0dVIXR3+CuVeuG8SlmxU1LRs2d/7jqU8VXDt
         /PYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SxpPcDOjuHpsVF8u4wqhK0tfdVqdvg621jordwmRhdk=;
        b=tPwx8xtTR6M0LQa0B53HomVCGiNxzwsNm3d2mR3ri12AfCCSPgA1QalgMi7Psh27mF
         jA+tbedk/puqJmXI31GzNezBi4f9lmTBms5z1cCFZGHiVIQXcUsukZPeImUkMTFq/5x6
         QxERTEPtEBH3rCYsuyXf+hqHVjvNTZ8qErxIzq7/2gpa2gFmGKcMcWrVJDT4Xe4CvvUw
         hTVs8JgdBNx8Clf5iR2N5UI/nGYrueKiwQDM6vG1yImrVXpuUf8uX6pWYN5190TTLxYN
         eA6VBunOD2xhJpuEbpWjD1shwkzj8kBedELMN7KAo6OoL0jrItmJ76+XydwLl5QAGYmd
         sR2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eb2Honi7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id il4si171080pjb.0.2020.12.08.07.44.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:44:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id q25so4372372otn.10
        for <kasan-dev@googlegroups.com>; Tue, 08 Dec 2020 07:44:03 -0800 (PST)
X-Received: by 2002:a9d:6317:: with SMTP id q23mr17582237otk.251.1607442242735;
 Tue, 08 Dec 2020 07:44:02 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork> <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork> <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork> <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork> <X83nnTV62M/ZXFDR@elver.google.com>
 <X83y/etcPKUnPxeD@elver.google.com> <20201208153632.GB2140704@cork>
In-Reply-To: <20201208153632.GB2140704@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Dec 2020 16:43:51 +0100
Message-ID: <CANpmjNPvRg6UfjX0=hW2LabqpNY6o8FGANex4yFtkvikDJvR_w@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Eb2Honi7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Tue, 8 Dec 2020 at 16:36, 'J=C3=B6rn Engel' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Mon, Dec 07, 2020 at 10:16:45AM +0100, Marco Elver wrote:
> > On Mon, Dec 07, 2020 at 09:28AM +0100, Marco Elver wrote:
> > [...]
> > > Please try the patch below and let us know if this improves your
> > > 1ms-sample-interval setup (of course set CONFIG_KFENCE_STATIC_KEYS=3D=
n).
> > > If that works better for you, let's send it for inclusion in mainline=
.
> >
> > Patch can be optimized a little further (no more wake_up()
> > wait_event() calls). See new version below.
>
> I went one step further.  Not sure how to measure the overhead of
> interrupt vs. schedule(), but I suspect they are pretty close.  At any
> rate, hrtimers are needed to go faster than 1ms and are more precise in
> environments with high scheduler latency.

Cool, do share some perf numbers if you have them.

> Patch is a mess, you definitely don't want it as-is.  But it allows me
> to go more extreme and test the limits of kfence.  If it works for me at
> 10kHz, it should work for you at 10Hz. :)

Fair enough, of course it's fine if you keep this in your tree if it
suits your needs. But the hrtimer won't work with static keys, because
the IPIs can't run from interrupt context. And I imagine your KFENCE
pool must be huge, otherwise you'll exhaust it immediately (this is
another non-starter for us).

To bridge the gap, does it make sense to send the
KFENCE_STATIC_KEYS=3D[yn] patch at all, or would you just not bother,
given that you're running with hrtimers anyway?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPvRg6UfjX0%3DhW2LabqpNY6o8FGANex4yFtkvikDJvR_w%40mail.gmai=
l.com.
