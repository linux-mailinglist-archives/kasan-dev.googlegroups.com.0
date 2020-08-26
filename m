Return-Path: <kasan-dev+bncBC7OBJGL2MHBBANGTH5AKGQEGHG553Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B9EE252E92
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 14:18:11 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id y190sf573609vsc.19
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Aug 2020 05:18:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598444290; cv=pass;
        d=google.com; s=arc-20160816;
        b=S2h97IneHzNd5NmnKs37cUt0ZAcDv0mEOaruozcpUQ1N6voGUxM+xvlb8JcOV3XJCI
         U8jULOhr7beZe5WZcl/VeavQs4KTejOnQS6Xd42x96KIsuWXjX4IdW9kNGzFxkZRwiPL
         g0L8+YaK8u667+yzwdFI1vRpXQ/bwh4xozHPyJal0dPUdh+SWRD9D6/IJ9GgABGUQUQN
         nUA8irJxPtXWDY7c3WtaV21vDW49ok5T8lNRWTbK8WhVKkpMSTGLgufYYezj0SU2fgYy
         JGssZ1hLCUqlRdUlVpx+VR0DFWg87cEfhXMOHT8i049N3tkPR5JvWvfrqoGoWHnuE78C
         yD7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0S/w+9HL7YUMBbdVzNawwPZ+zquP8RIXgRGSg0sg4N0=;
        b=bCe9XG628hJF/x6rxEFUbDZ2E9gRrG+dZyGQmp8wKxT0pplO19iiS2Z5A8Bbf7vJ2g
         ud+hklsdYtTA2LHajz4cSe+mg0xjBLaZ7ANJ3XXXCsIIUsOwtiazDX60SWyQw3aAmB5P
         yTp/iP73wpq/oEINDu+ZX6O4tw1wATvtVVNI3VNuU9ZaRZedpruUZQzCPpiRTtwXgz6W
         /YL9vR5VlHuizctxK/wDAZ6TzGOUJ44QK0bXN8O1sDlUFMqhr9yG4xPeOU3CQogNA+bd
         ++38IslNAU6QeLf+NcIDJ8AdG5/6Ax//Il0PmV8gf4Q2AUplNxKCjSaMtp+k0HVnUz92
         nFsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cUFP7Oiw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0S/w+9HL7YUMBbdVzNawwPZ+zquP8RIXgRGSg0sg4N0=;
        b=JrfwZxwWBsg82W0QDCPYPnr5Cm5GnlA3uFd56GDqfDwHX1+FDKUphHrVZWJlHt3Qa5
         Sn+/qaKPeQY4ryxrPqFgIsxpNhiIMiaAtxw8sgQPcfvpBjt4nEmYTW3hBbX6w3vgxp04
         VBjDFT7VWVLgSuhvmNVCH1y3pYbigeMCCYlOD4jWW0EA6i7y8z8lyvffaM2PFlnpD0rO
         pJsAthQTe/7yHvVUtcq5YaoF9KVSBvhZkGTi2lxF8Vi6sz/mcE9AtcuEU+/zVAo9b1dE
         4Aydk6GW8KjOCnEChWtAgrZ0YHktprS9De3M4dNm46MiOsXO+FT9rtHQbnWsle3nNznG
         xA6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0S/w+9HL7YUMBbdVzNawwPZ+zquP8RIXgRGSg0sg4N0=;
        b=DrRRzlACIUXaGID7qjonEwI/YIQV54/PGvAOaAq5e4Lna2DjRQRYK7H5KpgebH/z7z
         63oKbalK4mnwT8bczt5+0AMapHQ9BxUX/B2tVfrhaFJiTzTHEn8bUSqStWvBbUHnd93A
         qpT7BQRG36rfwe7MTRZG/8kMf7mimBiUGeViTD7QENzUlYr8+nAEpyO5Xw2Uwf/C1Z21
         FiQqAg/BYJ6KX0nwOObHDrGIKzVD20yVtQ9hX9zAQWzn8oXAATel3dN44+fDG5NMNCSW
         CalcpOLV3sem0u2fySHe3RJxMqEfuUARoU8Rxfch0aAK5r0ukVHKCG9QAzYA2wsaQ6wg
         kobQ==
X-Gm-Message-State: AOAM533Kpn6PEavOyXfqT1JBlk5osiVF8KYfWOKjIx+ncEZywevpEQTE
	FslyDKbylbK5Teko68otJWk=
X-Google-Smtp-Source: ABdhPJwW9j85a6U25OROUwdBbylSLsTjVEV0NLnj93i0JzyAa3TEyNRDR2r2EtgA44Ff3rDiuzGa5w==
X-Received: by 2002:a1f:7d49:: with SMTP id y70mr3764246vkc.12.1598444290064;
        Wed, 26 Aug 2020 05:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:704b:: with SMTP id v11ls148364ual.6.gmail; Wed, 26 Aug
 2020 05:18:09 -0700 (PDT)
X-Received: by 2002:ab0:116c:: with SMTP id g44mr8679518uac.137.1598444289668;
        Wed, 26 Aug 2020 05:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598444289; cv=none;
        d=google.com; s=arc-20160816;
        b=UHVXvmHK8ye5nSWdzjf+keCiUU1Vot87fDzeIkeVnsgcTpECv4UHeMYW/hESnrazfu
         fiuX5RCqBOvsAryIIDGCZD4W54kVYMLHdvRa1vsFR+/cZKVsr5ffCaZOXJrnV+NNOB9I
         AWcnkRDNYON78Q72eYykhl7IHJ0HOt7pfA4pLMMZFPMRdzjlNtN52WLb/BWoYtjzY/qt
         M7ReTdWnsjYV+3SFn1IWAhXkwGeAI6bg/tbB6a3C7MmHGyKQ+52sXEF8D5mkg5UAs+qc
         TbTa0h+P6hN3GGJ9x4IjkgvJEnkwxUN2Ix1vcTLLfl070ny+J/QfAtn7mTfHXMW5oESe
         /LWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7/q8ddA2FVVePJulVHbf1w2DVxs+k2gCtz8r5i1ccF8=;
        b=qaqvSS5awzQKyuGJJ2x56F/jBwwAJG+zVVQPyfdsd7jj4iGR92M+6ojHwTm7fsRiQB
         l2xaxDqvt/o36oAg7EyaU4qP9j7DLz4qYEpPqVH3PfGJ4lcoOrcvcHXYhI3pdUWghRy3
         1q1KBvruoMVXp0AIS8KDbbOWaqKJmgX3NauxXB6aW1tZizYJH2gHG6tupa2Qr4CkNUAK
         gV12dddK2WtRt0sZq7ng+y6sfEGa5+5qxeYyZd+rQWMISQ1Zf2m5BsyHgwkfCbDOaSIr
         2KmbAfUzanNPVkYND52TN+VNyvcrLoRTtf2AGsLnGVV2heNFPeTaJFyu8dvMAVeQ7UQ+
         Ua0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cUFP7Oiw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q1si142617ual.0.2020.08.26.05.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Aug 2020 05:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id r8so1289217ota.6
        for <kasan-dev@googlegroups.com>; Wed, 26 Aug 2020 05:18:09 -0700 (PDT)
X-Received: by 2002:a9d:739a:: with SMTP id j26mr10379141otk.17.1598444288848;
 Wed, 26 Aug 2020 05:18:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200821123126.3121494-1-elver@google.com>
In-Reply-To: <20200821123126.3121494-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Aug 2020 14:17:57 +0200
Message-ID: <CANpmjNMLL+Xqg0MQrtBMxLunUGXVP-mAXKqRH5s0xNSfAUhrzg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Use tracing-safe version of prandom
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cUFP7Oiw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 21 Aug 2020 at 14:31, Marco Elver <elver@google.com> wrote:
> In the core runtime, we must minimize any calls to external library
> functions to avoid any kind of recursion. This can happen even though
> instrumentation is disabled for called functions, but tracing is
> enabled.
>
> Most recently, prandom_u32() added a tracepoint, which can cause
> problems for KCSAN even if the rcuidle variant is used. For example:
>         kcsan -> prandom_u32() -> trace_prandom_u32_rcuidle ->
>         srcu_read_lock_notrace -> __srcu_read_lock -> kcsan ...
>
> While we could disable KCSAN in kcsan_setup_watchpoint(), this does not
> solve other unexpected behaviour we may get due recursing into functions
> that may not be tolerant to such recursion:
>         __srcu_read_lock -> kcsan -> ... -> __srcu_read_lock
>
> Therefore, switch to using prandom_u32_state(), which is uninstrumented,
> and does not have a tracepoint.
>
> Link: https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com
> Link: https://lkml.kernel.org/r/20200820172046.GA177701@elver.google.com
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Applies to latest -rcu/dev only.
>
> Let's wait a bit to see what happens with
>   https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com,
> just in case there's a better solution that might make this patch redundant.

Paul, feel free to pick this up.

I wanted to wait until after plumbers to see what happens, but maybe
it's better to give the heads-up now, so this is in time for the next
pull-request. It seems that prandom_u32() will keep its tracepoint,
which means we definitely need this to make KCSAN compatible with
tracing again.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMLL%2BXqg0MQrtBMxLunUGXVP-mAXKqRH5s0xNSfAUhrzg%40mail.gmail.com.
