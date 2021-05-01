Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNMCW2CAMGQEST3KKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A76C3707DB
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 18:26:30 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id w6-20020a0568300786b0290297fb946e1asf1239372ots.4
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 09:26:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619886389; cv=pass;
        d=google.com; s=arc-20160816;
        b=SgXiqD1Bk+OB+nb8TVGKsFGPhEvyWPiIZ1C00BL+Vi7n4WPTusFV4QbX1tuVLk7EMj
         tagfUnMy5jDq4Tco+Z+N7qHg8N/QF/M7PfSb4wrcmXujLng7CCrIddEA1QyIw7O5P6Uj
         I9LXGu476acFt4oHpp9YjcmEN1np1e8LN9MiYJj1WryyLGYwNZRgcH50lqIS+k+s8ZLj
         t+Xg2Z2ng8qfJO2xF9c9inMuEy5FPPV6nmQDQozTUHdd3gz1Lu+o2y1eZk4pvBFQScE7
         lEBFw8HT1NP1r3RIvQQCe4zZtal8HveC34OYobDJOG/4JrciUBuvbpTDBmwbFas+N057
         vOWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=z3EeY3ClJMvh+DdA5S/Dk3gRXBbX8F1C4qIFyyyI1Hs=;
        b=uczZ1Os/mYklCxPDLf8bSlB/JlBMraKloqP6xMepab9UYJnmX+sY2jHfQJFjIIP1M3
         WnXHFDxrXBfWFr8ofY8R7SrzIuJ38cWOlDVAHjgk2s1Vauuw5Pk7c3/mz3NIp7qDpZen
         JLPsWccLTWqegDF0MIoRYzuBZ3oLdsiIIGry1VGtlrNuEIgRhfn5qC9KOoezkBnoeziL
         e8an31n4zUQsJuJAfpcDpKg9bKv+L6wpN+9UHRhla6M/SCLzqyrXPfjUrbOCvMohu34L
         cT6vULaDIoAMRaNNhpEtnsffMTKOH62MjHiNZJEsBhTbo7TwHZVEzEzaxnQRDMV4NjJq
         /yBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZOy4ilx8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z3EeY3ClJMvh+DdA5S/Dk3gRXBbX8F1C4qIFyyyI1Hs=;
        b=lf8CuE1qcPDjMVVXwhNosLIcJolzSQy9xlBdh9bHWl7KeSYopX0bGOzTI5F+6DFWAe
         iU+Djh4sq3zFUgQbvVG4n60OlERkz49vwHCWYeNaZ6f7vZJv8s/XDApPTQpxFGsuXyDN
         VNrlbfMb/mom6ZGPQNfDXUCp5RrbO0qT6AkkSH6Jh8enX7Wgwi0ryEjxN1huVMiTe0dF
         79RTqOXb4EnyIQwkE83o7mAvqaqQ4t7bQAAFPqyA98MOeDqGBx6O2T9v1agN7r1vxw+9
         3e/WAf37tzD70i/4docxfdmxU3UN8xKrMkL2Ya/oa/mr0NKC4uVKXyAeTGEWCa2zzhdl
         JkhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z3EeY3ClJMvh+DdA5S/Dk3gRXBbX8F1C4qIFyyyI1Hs=;
        b=XPP9qVjLjyhRkGuA7GgqYbw+THogsUME+FNnfknUO4Fxw3VGY4PaWBZWkpUzx5mll5
         +lcSWtyLSE3Rrax/6FPwd5YbHMCIBiyf+QZBgIJvj8u1AGLE43Q+imlH0zCZRk6WItWG
         +7n7hxpa7FLDA9DEHxw3NE0gFR3CbmaucVzczvAKeXvRhFIttKnGeONBwPq5M0kkyZ3Y
         WpkZERBZi4pJPHphfDxek0hgoZGyQa0mU3TyppXk7YhZCApBqGqyZ2cmu2RFwavNa/HV
         hOfQUPR1mpkDPoi+DooYXFeuD5fiZyh0qxSdqlGy4ORcFrdft6QS8eb6FM9eAITh7eNe
         DyXw==
X-Gm-Message-State: AOAM532Do+dlNnlT0Q8exvrTCqc3i0JpAKwKZqOQgDAOBqxVT5Mg7ad7
	/ThrP9Z6mj0VZdbG0Vmml/0=
X-Google-Smtp-Source: ABdhPJxhTVPI8m2NPXcPM+jigRGaYMBscVSIZMumz+XlSo8Opx0gTuJDdivvrJqFnpVS//gsPqjX5w==
X-Received: by 2002:aca:1e16:: with SMTP id m22mr8150300oic.153.1619886389407;
        Sat, 01 May 2021 09:26:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3488:: with SMTP id c8ls2615800otu.10.gmail; Sat,
 01 May 2021 09:26:29 -0700 (PDT)
X-Received: by 2002:a05:6830:1398:: with SMTP id d24mr8114130otq.281.1619886389019;
        Sat, 01 May 2021 09:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619886389; cv=none;
        d=google.com; s=arc-20160816;
        b=fJOZH1Pdo0uy6Vz8bKf2Y9PVNgKsj3aajRQvksUuzP0IsUMnqmWwBJbD5nPlw4JDVK
         mkOoOcSwbOkjUTzmJ1tizbNW5QcSJwC9TO8n1em4h0uvA5d5dxGJzYyu+i1fLKh/wMnu
         FbZgHdnCbJexLzgFmrkM3ZwKxOv/0iRw0BFu3YtIytKTs5v8BISTQWhHc6/dBDZGxHKV
         PAJEvs4YDbsmqTteAJhL1wouDAhqh38koc/u1djgtti7OKoE0GCnzTcyoruQCm2CRHgC
         +3C9fqIOG7ulZ4e3+syyaIM3coxJ1bchgy06SxLERKBlIkENMgoxPSJNNnW+O5ED4Ozs
         2LoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=64NGINXN7ynqOlzs0BXPYhgqQOU3tvwvuitkM9gE7fk=;
        b=NsSrLEL2dGIJcd2CIeSaNjTdyOSeNgL1Ia8ajQecvxKFjtMQZU3jM+x8GWwRt/grq+
         kSrYMvXFz529vx/awUZrcYw6JSNS/nHw5iYANFTjlwXwXG664A4O3853phreGpXHo62b
         CF36fEma/7OpIQMpqUKJ6opRvlECfzJFMHvO1e7ydkntqjQyObjuLkjDZVU+LkftMDdS
         zkWf+zorzT+cEyoqB4vjfWJUKz7Ow/tu/SzsVJcLCroMoPhytg6+uVXabuGrNu0koqla
         XjN71l/imdKfl4FNwSA6NvU/LIWPyNCqJxFvbRTUqswA4K9RRRDL09dPdXObOH0ilIWI
         7m5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZOy4ilx8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id f4si1081088otc.2.2021.05.01.09.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 09:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id i81so1264675oif.6
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 09:26:29 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr8271992oia.70.1619886388654;
 Sat, 01 May 2021 09:26:28 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org> <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
In-Reply-To: <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 18:26:17 +0200
Message-ID: <CANpmjNMtM7JyxTiA-QpEmqd0MuQ+uZTjfZ3+_r4D=rrGpFU8RA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=ZOy4ilx8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Sat, 1 May 2021 at 02:37, Marco Elver <elver@google.com> wrote:
> On Sat, 1 May 2021 at 01:48, Eric W. Biederman <ebiederm@xmission.com> wrote:
> >
> > Well with 7 patches instead of 3 that was a little more than I thought
> > I was going to send.
> >
> > However that does demonstrate what I am thinking, and I think most of
> > the changes are reasonable at this point.
> >
> > I am very curious how synchronous this all is, because if this code
> > is truly synchronous updating signalfd to handle this class of signal
> > doesn't really make sense.

Just a note on this: the reason for adding signalfd support was based
on the comment at SIL_FAULT_PKUERR:

>                 /*
>                   * Fall through to the SIL_FAULT case.  Both SIL_FAULT_BNDERR
>                   * and SIL_FAULT_PKUERR are only generated by faults that
>                   * deliver them synchronously to userspace.  In case someone
>                   * injects one of these signals and signalfd catches it treat
>                   * it as SIL_FAULT.
>                   */

The same would hold for SIL_FAULT_PERF_EVENT, where somebody injects
(re-injects perhaps?) such an event. But otherwise, yes,
non-synchronous handling of SIGTRAP/TRAP_PERF is pretty useless for
almost all usecases I can think of.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMtM7JyxTiA-QpEmqd0MuQ%2BuZTjfZ3%2B_r4D%3DrrGpFU8RA%40mail.gmail.com.
