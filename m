Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTWFWKCAMGQER4IJQYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id EF18137047B
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 02:37:35 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id h7-20020a5d9e070000b029041a1f6bccc8sf799844ioh.18
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 17:37:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619829454; cv=pass;
        d=google.com; s=arc-20160816;
        b=mw1fBwi3Zh2+LTCW3rwVO8IKy2c1xHCUudc2IS9qT+i1FFhjttIULwwB+c0USGlP6a
         wY2ri7MqC61E3QVgLhV1vhizd7cHWR0pR8GEoaI+Iv/boAc2QeAGXtzMlOaHNBkw2/zr
         64JmLIK3yH+Nx/2WFf6ge/LcKk7mA4G9ompZkRp0nLt5j7HCIHZrc/K7jwVEdv9zNRPa
         69s8Oynvuwl4FDUX/Q+wnz29RssioAcyTNSWM8M/kdjDRajTq4zeDft2gvlDk5aWuPqa
         UpwbmWWSuoyIxY65mKNrcwDSh/JZ0q3S0fu075OsNZ2w7yBcD+M+cMNGUTJeQHt/xBQd
         49hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=74MaToCsv9qIQT0aLoAfuxFzKKDRKJFaux6fxIbGYG0=;
        b=fbmywc02paZgXc/6Iwm/0hR1u4myiDssar6xzYezFiMNVjBTJz1pxLwGssbQwsY5jT
         fauywZXi/bxJ9CmLN/3z9kckT+lEw+cSoDhVWV1ERWLEhZXDwiCId3u0pnATamer21xj
         3dIsS+hY8B0ZP7Pgs8XyryMT4WUHNMllwLZ6xrzskdJLf/QqwMITTz9WTHZ5v92U+ay6
         q2wWl/YiMoAanNJqOHEY2s1cwKhQwbttNawdM3VY+M8N81n5aU+oML0iTSJWQPoNmDCR
         G5/XeIdN9bPjtWkUwFJYuKYVI69wLAStXjdrzQFI4Ar8sgefPbqsXBgro42iNKyjE4Oy
         1VBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BePQGXKe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=74MaToCsv9qIQT0aLoAfuxFzKKDRKJFaux6fxIbGYG0=;
        b=NtC9P53MYYHPkD7Ne5jaDtf65OZ+dIZ0Mh1X03K3inKAARxKqQ9qX4ODnsqU5GeqVZ
         YeG372Zvph3+ttxyg3wbT/XqR43hzV7VdmNgkHgAci58ek53d28NQfY1iR8dvCBtWUK0
         4VGLCcjLJym9oVPY7rJZQVLrNtVnXa6x0MbunP88+nD6GWVXRjixeQ+IF8lFYoVPV8+9
         V+RckmoHTddyn/JpjMPlAnuDB7O8ZUJZEVLXg+QkAIsQ7Hc3QEcW6i4BO30VZFZlQKao
         MMJ98Y1UxS0FipWByJFJb3e/zvdTdnhbe/FFjJp7ICA81rdqOOseahMoUiWUPLWQ3OAd
         suUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=74MaToCsv9qIQT0aLoAfuxFzKKDRKJFaux6fxIbGYG0=;
        b=JqSSBng/yWF651p6iLMY5WmNRI2eNFB0ebpJGA3rZy+wvjTnel9lTzhbQLmIyjx66v
         sYqiQgjybj0SYU3xsmxrw4LtcPaGyB0RhA55AfEZGTUCvXPCBi6XhQblIB2W/H+QS+e6
         LJ2maXCk7pwQY0Ccg90QRW5BruYhq975NZ9EXusfaNRyVT9NR8mhTFoqYIyjffM+lKZZ
         862aR74BH5j/Z+J1rlmsjOPzlcZiC6lxpv96u/rEwxOEJ954pcPmaj8YZKYWYTN8Zu69
         2FETjoF1fbTY62iFH5Bdnq2hwwc1DcVrd/6ytgcPSBf2RmKJHU0ti1b8HV2edPLBCRL/
         XhQA==
X-Gm-Message-State: AOAM531gcIhU/wrdRGUzADo7uk9ztGOtllvH6sOYCqGOKxnGCdn0v/iq
	xBKsXMcqgKOszQ7Hzt2L8Ns=
X-Google-Smtp-Source: ABdhPJyYoiA3uIo2MsFGm9W0Ix9oAeSeRY1L1kRaYHpyxtyPVNDB7LuOpp/Lnw74Dqn8raB1Px9vxQ==
X-Received: by 2002:a05:6e02:120e:: with SMTP id a14mr6179107ilq.273.1619829454649;
        Fri, 30 Apr 2021 17:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2811:: with SMTP id l17ls1747803ilf.2.gmail; Fri, 30 Apr
 2021 17:37:34 -0700 (PDT)
X-Received: by 2002:a05:6e02:48b:: with SMTP id b11mr6217056ils.245.1619829454177;
        Fri, 30 Apr 2021 17:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619829454; cv=none;
        d=google.com; s=arc-20160816;
        b=m+3+paOajiPobZE+7Bt/B2AqnNoy0UI3b6ZAY5RCtIIX4sWaK2odXB7zWSuO8yTnjX
         5KkFHyNaCjs6gocGfRiDfdQv42M1bQ+4bl/0ghV8aOAXuMsnhap71WxR10RxgZtfPd6X
         GyuX57XaaTWM/mlYU9uc7rzKVXCIufzyVmO6nK2ChcB2Y8iyswKdS1p/jRwW7tfy1Mc9
         BabsP+93m0umWKqbN19sv9jkWYUaOx6664FuaKiLY8a+epZdichPe6kKJPMofRaMojVL
         8gLcgSXtkmXsu4Ue6x7jwebQcThDdC+Mv0c1S16mxlebuI7soq9k+WxqQRHl/1pVvCTY
         98Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iYQeAScJs1TpMXononV3fp1ygIDD0T/s8VaH8jvt3Xw=;
        b=g90G1LeOJiMaa5Fnq/XfiThZ7nN597Z2vzWgPK/XjSg2qPB7/uJE7VfVnANFtmK/Vy
         4PRDf2vbmpUpdY/oI1wYdyiKgMad8Fr2UnhoEL4Z68axNf9LRS6akhxKfmJ5l6rHPFbB
         HLR36AxXZ61Xj494xQanS2cbaoI3ybUQwJUDonKtDvJCadFmnHwrlesNdJvl20qSTGZk
         7GXI0bC8yV7o7vnqsKE5RXnoWYpt8LavTsrtTXv/U9yS1ziW9ehJCb02l95bIROSamyp
         HTac3M5TilWMyJmiG1JhHdxBxNdwixGlyoY4CNgGvCJSJpTyIjAetD0brmvyvMHicAS9
         qNbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BePQGXKe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id a13si578432ioc.1.2021.04.30.17.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Apr 2021 17:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id d25so34237070oij.5
        for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 17:37:34 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr6087597oia.70.1619829453704;
 Fri, 30 Apr 2021 17:37:33 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
In-Reply-To: <m1r1irpc5v.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 02:37:22 +0200
Message-ID: <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
Subject: Re: [RFC][PATCH 0/3] signal: Move si_trapno into the _si_fault union
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BePQGXKe;       spf=pass
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

On Sat, 1 May 2021 at 01:48, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Well with 7 patches instead of 3 that was a little more than I thought
> I was going to send.
>
> However that does demonstrate what I am thinking, and I think most of
> the changes are reasonable at this point.
>
> I am very curious how synchronous this all is, because if this code
> is truly synchronous updating signalfd to handle this class of signal
> doesn't really make sense.
>
> If the code is not synchronous using force_sig is questionable.
>
> Eric W. Biederman (7):
>       siginfo: Move si_trapno inside the union inside _si_fault
>       signal: Implement SIL_FAULT_TRAPNO
>       signal: Use dedicated helpers to send signals with si_trapno set
>       signal: Remove __ARCH_SI_TRAPNO
>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
>       signal: Factor force_sig_perf out of perf_sigtrap
>       signal: Deliver all of the perf_data in si_perf

Thank you for doing this so quickly -- it looks much cleaner. I'll
have a more detailed look next week and also run some tests myself.

At a first glance, you've broken our tests in
tools/testing/selftests/perf_events/ -- needs a
s/si_perf/si_perf.data/, s/si_errno/si_perf.type/

Thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ%40mail.gmail.com.
