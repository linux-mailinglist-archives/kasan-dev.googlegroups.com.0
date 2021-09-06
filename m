Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI743CEQMGQEW2GUOZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AE76C401E17
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 18:13:24 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id h8-20020a056e021b8800b0022b466f3373sf2742308ili.20
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Sep 2021 09:13:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630944803; cv=pass;
        d=google.com; s=arc-20160816;
        b=rOWQsa2V5sIKcDsegKgsvgcnBU+CW1vU5BAwqMnw57ds3SkKrWncVW69X8T17v2E9U
         43COZDQ+GzoFTfewhhqSnc3DOp3d35OWRMCDM8ttQzqBsKV5tIBHKYMLnBf+w1o3zGaQ
         g/Levx6pINkVBWjDp1WTk3CfAKJVX2F3qnWvAThYBtdriJZacIG6FjY7bFnuaCOkOSUl
         WJU4xmqq8XemSicHu+jvaWHDimHzZnqCvGKadz5jKl18S4IblnK77SPaR3IDjAJOktUD
         7XTk3c25THY3b5Of0D7n/VmQGKxmKMDQ1rZ8jFKAnFCN5Q2VX/+wwDSlKPSz6fidSOlp
         2pMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E7GMAImN+Fg/hIJH9VZOwyH0Y1UxM1wEt7kzJDVx/IM=;
        b=KQzW/ex7FSrVPdYiVLHxwc054U6XvraksduvW35DaqA4IDtvKlaNOZ9vZh5N5HReZb
         1EycRHYcFsT+t3s59HYIUlj5MEoBB/P3SIF7ZY+fJ03pYbvmvhgD3nQb9HakGvAZe+Pj
         DU86D5ljTCG3+AmOK8kgeQiMuL6J7wR4EnFHRXO1J/PZr+neSd9B8+V8bF7wWtXpQ7R+
         Va1Nz2siF885R5hmJbz19wD/aU2gPPI+NA39yoq9MXmnRQ7X9plM9FNZpMv9V+Oa3VO7
         4PnWZnjUD6Z+AkzKpVsm3a+m7zyLptur7ICU5AzXVVNS8WI1eSh2LgpiMdMQbfz+7+Y4
         W5iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IxYvyvZz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7GMAImN+Fg/hIJH9VZOwyH0Y1UxM1wEt7kzJDVx/IM=;
        b=drXiFFu7rX8uFpf1otIPbwQKoHFF3GiN/rwORQonjfk8jlgAbEEtD2eBIrC3dCONb4
         7lOG6ugeprZnTwQRiMF/t6H1ujJ3IbVrX1kOddHrsdZJ833CHfsP4Kq4Ai5a2Aks2GOT
         KivkA8u0m6lecKqh5YjhxUWiskIduJArRdISan/VLE0et95Vy9cX+xHYrCyrBno7Vb2c
         4Cd7KWxv61oDKabCj+/sPnKhNcw+5+5lM8ITuH9bNew6N5l01qHxqoskEqD66R8KUI7z
         iIPuaDEJfayRHAOqElIbg8oYKiMwtknwBppTZ1HzmqRmiqsIoQuLPKN+Osh3QBQJXiyt
         YT6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7GMAImN+Fg/hIJH9VZOwyH0Y1UxM1wEt7kzJDVx/IM=;
        b=i9TonIA4B+N37tXFxbdZ9A5VeifbUTHIOGyL7ckeeLuComVh4MbfPTBxf0w0fA0eRP
         nSKZsuwqAUujk00DCvkH517qYTn/pU5XrFxzUjer5DmqW/jfNqT4t4CKTMGep49dPRpi
         xF29mMFtTJyz3TKS6rfO12x8HQpzSbuKWKFixl+knLbUZdWc+OYWomJomZbsdkJ14p0b
         je0bD93aNh/KDt2dfEYFjNlvXitSH7jHlKrHhyfNAHr0r9m0KBOTFmHOqrZBCiYEiXFP
         gHHdrNbhGkTBvRBbyE/RFJJVD4gCzFwXfaK+9lBLND7su3dL7eqijO3g6ukXdJ3zDL5W
         dXfw==
X-Gm-Message-State: AOAM533o9TyN4klgRCx2Sk/FmjN4GZpfph663pn1VM3g6+D8g6rmFjdk
	5mcJwaM+io3DJFayOKrh/2o=
X-Google-Smtp-Source: ABdhPJyMAKBv8V9nOqOAs2lzgFIfDZAAPTXpf58NNBVzWmIFgwZ3vQpAjw6v2sMBYpqNAxTvQhRmgQ==
X-Received: by 2002:a5d:8715:: with SMTP id u21mr10582072iom.1.1630944803774;
        Mon, 06 Sep 2021 09:13:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9499:: with SMTP id v25ls28634ioj.7.gmail; Mon, 06 Sep
 2021 09:13:23 -0700 (PDT)
X-Received: by 2002:a5e:dd42:: with SMTP id u2mr10229341iop.157.1630944803375;
        Mon, 06 Sep 2021 09:13:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630944803; cv=none;
        d=google.com; s=arc-20160816;
        b=Y7H1bxUqNFjOBk57C90jO+fZ8JnHK8UmB78CuiGotIgoIjrEmAWmRjwUMunGpJAkj+
         XKlhLV7PvEG1SjPTypKGRQQ3bhk7yYbZ7hyb6CVHXr1FMa/aGLjaw5GX+hb2FKBzTJ1q
         yXAinjM/G77YEjGOYavMqFCsn+pfU1PcvX1mcmbtvOLS4NNyjKUr7kDyeBZRaHs+TWm2
         8VeGN5atv+s2KRd0vDkvPq24guxt/3rwZPbcSRRoYwVRWLv82qMOIyM9jOAjcs7ljviP
         UpcQt9qiM/isRgOqApfMcAcxMsj8gUbZg9TFA2ttGw6Qqo/CcRSMkebjlO9/R4HKp7uI
         uU7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sSHWLdRniClMLbNX/vMWN1xbfEPKJ8OMc5qP3DmQu0A=;
        b=IHvi7U73jo+aWoWRIWNW2/Dt+zLOnXHPfq6fJLH0rSxvdf0Nf5gsnGcfWFMsrQzZog
         l1F3LkKrL/tNsvGMYNHJFF2hih7ttUEU8fhDmPiT+ttI4SQVGlp66c75NFe94ACK7YPz
         MeQXO4tlrdyjnkQGsdlQQGUsBXjRen6EoDb1nrV9mz9E2aaq5Qp0sbt0e2Vo1ufviJb7
         xZNwdzgnYJWoJTvJ9lY/QVJLHXSFan+mXqr6ih7Er4AFvFtfe5dwY2yVsOBJ/cikSHFB
         23qK4ilExYfs343wrjtPEoh2ex1s2ZO5GStQUaJ7le7w0dUpb0QSuxDwkATk3iJ2FYQs
         ouRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IxYvyvZz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id o21si373305iov.2.2021.09.06.09.13.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Sep 2021 09:13:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id bi4so9330546oib.9
        for <kasan-dev@googlegroups.com>; Mon, 06 Sep 2021 09:13:23 -0700 (PDT)
X-Received: by 2002:aca:4344:: with SMTP id q65mr9355069oia.70.1630944802829;
 Mon, 06 Sep 2021 09:13:22 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Sep 2021 18:13:11 +0200
Message-ID: <CANpmjNPZMVkr5BpywHTY_m+ndLTeWrMLTog=yGG=VLg_miqUvQ@mail.gmail.com>
Subject: Re: [PATCH 0/5] kcov: PREEMPT_RT fixup + misc
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Steven Rostedt <rostedt@goodmis.org>, 
	Clark Williams <williams@redhat.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IxYvyvZz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
> The last patch in series is follow-up to address the PREEMPT_RT issue
> within in kcov reported by Clark [0].
> Patches 1-3 are smaller things that I noticed while staring at it.
> Patch 4 is small change which makes replacement in #5 simpler / more
> obvious.
> I tested this with the three examples in the documentation folder and I
> didn't notice higher latency with kcov enabled. Debug or not, I don't
> see a reason to make the lock a raw_spin_lock_t annd it would complicate
> memory allocation as mentioned in #5.

Thanks for sorting this out. Given syzkaller is exercising all of
KCOV's feature, I let syzkaller run for a few hours with PROVE_LOCKING
(and PROVE_RAW_LOCK_NESTING) on, and looks fine:

    Acked-by: Marco Elver <elver@google.com>
    Tested-by: Marco Elver <elver@google.com>

> One thing I noticed and have no idea if this is right or not:
> The code seems to mix long and uint64_t for the reported instruction
> pointer / position in the buffer. For instance
> __sanitizer_cov_trace_pc() refers to a 64bit pointer (in the comment)
> while the area pointer itself is (long *). The problematic part is that
> a 32bit application on a 64bit pointer will expect a four byte pointer
> while kernel uses an eight byte pointer.

I think the code is consistent in using 'unsigned long' for writing
regular pos/IP (except write_comp_data(), which has a comment about
it). The mentions of 64-bit in comments might be inaccurate though.
But I think it's working as expected:

- on 64-bit kernels, pos/IP can be up to 64-bit;
- on 32-bit kernels, pos/IP can only be up to 32-bit.

User space necessarily has to know about the bit-ness of its kernel,
because the coverage information is entirely dependent on the kernel
image. I think the examples in documentation weren't exhaustive in
this regard. At least that's my take -- Dmitry or Andrey would know
for sure (Dmitry is currently on vacation, but hopefully can clarify
next week).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZMVkr5BpywHTY_m%2BndLTeWrMLTog%3DyGG%3DVLg_miqUvQ%40mail.gmail.com.
