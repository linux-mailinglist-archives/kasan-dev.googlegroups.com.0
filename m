Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT5JYGCAMGQEYNSGUNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C1EA03720FB
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 21:53:52 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 75-20020a9d08d10000b02902a5bd8ddf7bsf4708600otf.20
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 12:53:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620071631; cv=pass;
        d=google.com; s=arc-20160816;
        b=QDQMcODTT9QlxIR/ROxJYDYIZlolxLz8w6v+X1mtO2TTQFClufHY54tN6MjiVCfck0
         2mEKBtkoXyprwsWhRpCuUsOkYfYU6Zm+PY6DqwSyahh8xYRnIjUnIxICs3YUVQ1mNWM7
         Scu+LrmXHzr+xUv74343Pl8W3DTgsB2FI7rM1mtUxCta+0zEUeN7gmnPJcxX+SgjZgkq
         NU79pk9Gw5LkO3BLU4j4DhsnBh9NTo5T4/QD0DNAIfF+OZcgQ73EhF6BxsLmYYtJsgEu
         SBGk1irSYDvIVPLbVdIjjSW9Hy77KZkZBH7Wa+XMPQTI34AXJAZ7USrk2TgXZbEpEWbH
         AT5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WH+OQ23axa6Egus6l2hkd+iDez/NCYBDi+L4UclqYBk=;
        b=UKOzTAP2wK7rLUCMhD/s/xYJKeuRoieps6owRToV/w6nZ3jUCQ4cpn8dsj4WjfZ3hT
         v668+RYInV7gFpeE+irJFfBz1akhR9Dd8PraD5iglWM9KIi0QP3c+i8W3jy+A7L19IRp
         HQFAG+0JkCSZHdXagVFvQBOMqG0Jl/+o2H2+05cKOK54GZ4ygd6R5EojTUSlOiVURFMj
         bVSy00w0BQg8NM6EhdLoPKe8cE87mvltrz4kI2yYG+i6+DgkNokIkipi3lXgK5hB4Q5u
         MUK5BUu8OgJKI1S16ZMc/H2AuwNEn7MUvEAS6uXXWp2i2az8noOlhdLG3s01M8s5hQIj
         7n+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CRqyGcRJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WH+OQ23axa6Egus6l2hkd+iDez/NCYBDi+L4UclqYBk=;
        b=UyP6RqCBj45gLXTY3fa3Ny7Qssg4/BnBpIEo4EO3HAPupXvpgs/9p3CG5ETvDnye8w
         zWQoR9f9Up1i4h6LIQyeQXwoudvaVQhV4kMx254LmUgqfo3cqvdzmngowj22GvpIN4mg
         zZmYKqcYi/kZvVaQnD9Jh4nRDVx8o3CLR0l8r8e6DoFYGy2W4FWfBtgMXz4m5WOCdniG
         BFOD/ULH/tVSZ88IS9sbIAMCverHOk4JtlgtZaxPLcWc4zH6VttyPHkxP+bGN9QtN2ue
         8Bb/YDUoTD8+2oAN88ZGF2twBUXjKrO3k2EyZSKWkKySlSbDpP/ST5eioYeWrm6p5bSN
         sdyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WH+OQ23axa6Egus6l2hkd+iDez/NCYBDi+L4UclqYBk=;
        b=j3z7Cah6oglV6ZdVkbfKGGfPlepEjSq8kWViWQT7wUYM5z7kEEGA5WaC4C9SkOpzCx
         cVytN1BVmQEw5b++pWmpp5wIj6X8heazNR9/1E5YtV9cRYBgzSfcxu3pXKi2SMtWCglQ
         OfOja2TSaHA3QVrqTfW3oEi+uq89dQ1kCpczwzpNxLTxmSR6y3unKOLc6Z3xOCHd+N5w
         1zxwjV0Zmuh/G9cHYOyrpGi6sHCDBUpEC0FPF7GMFaVP/AbXPeP4P4LfuRwUzxNSgN2D
         Ycnl7/R1NVY762BUUFPSX+Ai+VoAs4O/hmk1+3lKXxVtFy/w8QCP1I49tof8kxrULlza
         bKHg==
X-Gm-Message-State: AOAM532Ve+EES83wvdenb2Ms8r3Z4xvbLrMY4+eTnYXExIfRmECs8j21
	yq2Y4RfkcfRaI8FU0+DldFE=
X-Google-Smtp-Source: ABdhPJytN6y2eMIDtWd4pRnZMSmRp6YkQup3hkRbjom9fmV73UEQAMDTrzmbZAU5hG8HADe+H8seHw==
X-Received: by 2002:a05:6830:14d3:: with SMTP id t19mr15298508otq.95.1620071631791;
        Mon, 03 May 2021 12:53:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:605:: with SMTP id w5ls4119630oti.8.gmail; Mon, 03
 May 2021 12:53:51 -0700 (PDT)
X-Received: by 2002:a05:6830:210a:: with SMTP id i10mr15822484otc.302.1620071631422;
        Mon, 03 May 2021 12:53:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620071631; cv=none;
        d=google.com; s=arc-20160816;
        b=LMm8gbT7DqSBkxZntKHdkk77o3vn6TLOcO241MGXZ3w5F3SJw20sq8OERq2R34k12K
         d3nOSOL/hGDC1oFuouqhM7mOl61JKv83WcchpRu5NXv+G89UwKS4zYo1ynmp1QFSTzoH
         ZR+0moYl+qCAXGJVDVMo+kLrONAkvAhLQClzn9HwANheiGmnl7yDSkYMFkwmpFpsh5Lg
         3hbWO28u8bXI1FTEYyhcMAoPHVn5eWe2A8RfHwIGuZncoyTPCmeTJznc79NiA/GuK8Pv
         tc3HZ6VgzdOhgHFeT6JIiDxatJUYY1AlRMKSpa3GJ3sflNvMk+t2Av1nt46CD0+MJiJZ
         lfdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sL1cfgAwusROayggatCngmy+CDfZipZ8K0S97Q3yq6Q=;
        b=0z+qNWJTKvU1ug6QNMkKNMO6KV/m6XT8TG5GMLkNkKW16swDY4CsjIU3ZMpaUEb1ej
         aouxjrWcP0QZZKP11U1Xxtss1UwGDc+BEmco19aUq09VBce+MAD3a4KYTOVR5/AMJiss
         XFeuJ+bHwarZfuDvyheV/bXMpl7vWHAgDBGdOu3ip5k8XXnyFRj5jGz3cjKFMcTv1QM/
         A+onmHsMBn/s4/Jxcydi6OpX6mODjLMMLx6X9Xe90ubivHF3nRiij9O0Z9BvxaNNi4/z
         vqX55HH6jNonu3bxjanmOFcz7shPzvpxZG6K5EaVyP+KkU78ax1B522R0NLnATlzMXwU
         alXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CRqyGcRJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id c4si52201oto.0.2021.05.03.12.53.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 May 2021 12:53:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id m13so6511811oiw.13
        for <kasan-dev@googlegroups.com>; Mon, 03 May 2021 12:53:51 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr14657198oif.121.1620071630990;
 Mon, 03 May 2021 12:53:50 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m11rarqqx2.fsf_-_@fess.ebiederm.org>
 <CANpmjNNJ_MnNyD4R2+9i24E=9xPHKnwTh6zwWtBYkuAq1Xo6-w@mail.gmail.com>
 <m1wnshm14b.fsf@fess.ebiederm.org> <YI/wJSwQitisM8Xf@hirez.programming.kicks-ass.net>
 <m1sg33ip4w.fsf@fess.ebiederm.org>
In-Reply-To: <m1sg33ip4w.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 May 2021 21:53:39 +0200
Message-ID: <CANpmjNNyvOFyEDLPKuGn-pjFTMfLCOBHOQrMocLVpdEG47Ge3A@mail.gmail.com>
Subject: Re: [PATCH 7/3] signal: Deliver all of the perf_data in si_perf
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Arnd Bergmann <arnd@arndb.de>, 
	Florian Weimer <fweimer@redhat.com>, "David S. Miller" <davem@davemloft.net>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CRqyGcRJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Mon, 3 May 2021 at 21:38, Eric W. Biederman <ebiederm@xmission.com> wrote:
> Peter Zijlstra <peterz@infradead.org> writes:
>
> > On Sun, May 02, 2021 at 01:39:16PM -0500, Eric W. Biederman wrote:
> >
> >> The one thing that this doesn't do is give you a 64bit field
> >> on 32bit architectures.
> >>
> >> On 32bit builds the layout is:
> >>
> >>      int si_signo;
> >>      int si_errno;
> >>      int si_code;
> >>      void __user *_addr;
> >>
> >> So I believe if the first 3 fields were moved into the _sifields union
> >> si_perf could define a 64bit field as it's first member and it would not
> >> break anything else.
> >>
> >> Given that the data field is 64bit that seems desirable.
> >
> > The data field is fundamentally an address, it is internally a u64
> > because the perf ring buffer has u64 alignment and it saves on compat
> > crap etc.
> >
> > So for the 32bit/compat case the high bits will always be 0 and
> > truncating into an unsigned long is fine.
>
> I see why it is fine to truncate the data field into an unsigned long.
>
> Other than technical difficulties in extending siginfo_t is there any
> reason not to define data as a __u64?

No -- like I pointed at earlier, si_perf used to be __u64, but we
can't because of the siginfo_t limitation. What we have now is fine,
and not worth dwelling over given siginfo limitations.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyvOFyEDLPKuGn-pjFTMfLCOBHOQrMocLVpdEG47Ge3A%40mail.gmail.com.
