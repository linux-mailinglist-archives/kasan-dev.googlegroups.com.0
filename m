Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP6ERWCQMGQECIWAR3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 996A8387260
	for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 08:44:16 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id f7-20020a9d5e870000b02902f479dba730sf6381576otl.21
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 23:44:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621320255; cv=pass;
        d=google.com; s=arc-20160816;
        b=D7Cq6D11tH0cE+eToULfMYbW+DgfUTfBtAPTlWUcvFJpEtrqdRxHnxBZhSPnUzOc4j
         ZtDL3yMu3KRmrbtWM/o8r0evGKRAlJ9AjrPjdo3/1fjdzeJZ6hWtIcQaVbRsNSLtcFxQ
         IWNdaINeickW0Y53haieXSjzbmfWfsGN2exLyhE8dVaV/sOdvMX6OUx0Dq6O8hD+mwyA
         HlQrWoSXteA/8jXIoTE1tNgE3vc5CDoMAFK0g6sHaFbJ7tu0ji/n2+xK+uNAvY8Fby4n
         QDIDCvx0k4l3D4QIHh/COcE5Hytvt0RLgGnIRH/WcvELOcMjTkx8IOtGhp6oJtLaYD+l
         ZCDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G9eCX0C7lFhA4vBhN9xOQfe0aD4zcKowD0etzNEym0Y=;
        b=TzuRUHd2111vxdBnA0Mz64rvkjKvZOI0xEGJcqU4vG0fI6TYS5PoJd5RhwUnDyIXc6
         squKjcc33PEZ96Rdjyxb3Xk+H2AceiRviJerl1+GhAWHpYgVIhcS1b1nqoZV3JXsFnm2
         q7TtEAHhhx0SOpum1Iudg1rNA9zcnigzk54/Xze0zwYEOCC2JSfr+lafPOlYQgmN5EgP
         /93l1kAUHMyqZxtuZ2GZZGkxgzYaU/iUdP9v0X7mDEk5xgEIFfcsoYI+9rM0fjS9tioz
         MfCpni/PLC5Kl9W0bHhYIK/7s9DlIPMdCKTYH76/rmwpCOdr9BJ+L2j8QO9JffmDf6Zw
         /cfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XDBwjWcK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G9eCX0C7lFhA4vBhN9xOQfe0aD4zcKowD0etzNEym0Y=;
        b=pQqEzkcs4oSD8DmxGbaGu9MWYllVsNSRKQwog5nUenCDwf4rmLu9glxWuuqhoD4wQE
         +YY4XofdOnuCKKJZ0i72hCJWC9yCKYSZK2ou3m0+y5ehkAZQ3AmZv3FDyeXCw68wuSjj
         0GoM1AtOILKz11J+0A1YUKCESv4f6Aide+gAQjBcFNIGxB2fdbC1mdxSA/lreEDYrgnf
         j9De7YfFiHVYZt2Uqew8FaecH3ZA9/t+d9wwuG9YiDHRDStpqFPydr/UTMjt4Jg3JwRq
         70hIGxfmDrkqSMKCwKvm7kx20FI6f6AyeOy12zu1fkudECn3haaFPUsE0hYXvGZIToY5
         Ykhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G9eCX0C7lFhA4vBhN9xOQfe0aD4zcKowD0etzNEym0Y=;
        b=mP1hwQgqLpS0epZ5J8ABJO5oUsCQ0NtpNAoHYPzS6JqZ/1CEP72HTjsXLkRJLYFN1w
         1Ji94VWngtgwWdNuEd2Lh8MBYhOuQAubqpx8fXVlufQNdcSRPd9GOUJaABu5R/5YFnGN
         eOYC7pKZqGvSBPpOVY7XYaoq5ui0oXINoklItnbru8Oeqt+3qSunSbifuehXWJXSSwky
         fDcJdo5hWLHe2Q+vdqVYOfKq0uXZgcaaluopZoteeJieqxdUFs2rJvK22Ju7S7YKL2x9
         owMx7w2OKE3+BO3ZmpOo0l/bx0LofsGgjuL517vnJU+hGkyhmoewVRlSDh7t2ALeJpbs
         viEg==
X-Gm-Message-State: AOAM531mJeeSPHm3+kGEUF/WGwlZh2bIqks7N4rtNMVdlzs6mIBZNft/
	61mG5rdjqbJFRPUq3138MEY=
X-Google-Smtp-Source: ABdhPJxBB+kQr9EouqNUosSMic8siJd6s82OP5jJSlf03/Yvz17dZ7D//GbcHugSIAdcJL1PnC9yvg==
X-Received: by 2002:a05:6830:1404:: with SMTP id v4mr2967792otp.209.1621320255362;
        Mon, 17 May 2021 23:44:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d487:: with SMTP id l129ls5077224oig.11.gmail; Mon, 17
 May 2021 23:44:15 -0700 (PDT)
X-Received: by 2002:a05:6808:3ae:: with SMTP id n14mr2282909oie.153.1621320254996;
        Mon, 17 May 2021 23:44:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621320254; cv=none;
        d=google.com; s=arc-20160816;
        b=TDM9rBKSVPzOqdcfnPRSjFkudytV1i7Ff7BPpKmnJKBubDqDN9eCR7tQA8f1iv/9jR
         gDtloiG2GVmZDESvkaKRJh4oBfPg/KUGkWNdGf8h9yAb7O2mP8piH25D/NVlph2J1wjJ
         M46Bq91ONXMzXwfCWH+7wHiilBVT17iU7GY1B7k4Vw9KgMV5cHZoUh2eqwQiIZXwXZfa
         dUyojm34lPqnt9ZgdqbbWJlzs0zJlqnSPuhH7lK6hEAtuTh94dOKaqldL1a3fmCZ5QcK
         H2dJgOs2H80YNin9cQKMvC/iUBpdBdd7lgVB/HdDs/Ry3BaWowo1UqSbC8HoM8xl/aJM
         FFmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bcn5fb5DZjb4YtyFgvoiwHqnuY6hbdNmIIbEt5dAaVo=;
        b=CsoeHovKfR1FifUoluC+sGcqvJGSCWIc9eBdrzQqwO5PBrsSlLJRMNfnIcaRnkotAY
         E6jgwBM1M2F8bjKJbsQO8NMCygSFuB+p89xkDprcHwSvJWUg2YGqXN9IsEQUyozeMao4
         eDXEBi3qIabF4lRHF59or7xkEncssIorKaidvXdcYsncz0T3q9wvm8kMKsPG8kxeP0Rr
         8LOTFIg4OiJ9M06BSLX9F7iRwAvkiojKCnS7BJc7uGH4wsvadRvhz3JFDn1qKnh8QYQn
         imXIDEHfeu1SArDr2opkVkArW0SYsvIy9rgtBDBOikHnTcztz7qWMYYe7F3yx4denHsH
         lX5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XDBwjWcK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id a10si80982oiw.5.2021.05.17.23.44.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 23:44:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id v22so8832942oic.2
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 23:44:14 -0700 (PDT)
X-Received: by 2002:a05:6808:144f:: with SMTP id x15mr2779174oiv.172.1621320254598;
 Mon, 17 May 2021 23:44:14 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <m1a6ot5e2h.fsf_-_@fess.ebiederm.org> <CANpmjNM6rzyTp_+myecf8_773HLWDyJDbxFM6rWvzfKTLkXbhQ@mail.gmail.com>
 <m1lf8c4sc4.fsf@fess.ebiederm.org>
In-Reply-To: <m1lf8c4sc4.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 May 2021 08:44:03 +0200
Message-ID: <CANpmjNOcZkC3YDSK8rA7yagRNBLCxyNRcUSKNbx69sR9PSW-2w@mail.gmail.com>
Subject: Re: [PATCH v4 0/5] siginfo: ABI fixes for TRAP_PERF
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
 header.i=@google.com header.s=20161025 header.b=XDBwjWcK;       spf=pass
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

On Tue, 18 May 2021 at 05:47, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> > On Mon, 17 May 2021 at 21:58, Eric W. Biederman <ebiederm@xmission.com> wrote:
> >>
> >> During the merge window an issue with si_perf and the siginfo ABI came
> >> up.  The alpha and sparc siginfo structure layout had changed with the
> >> addition of SIGTRAP TRAP_PERF and the new field si_perf.
> >>
> >> The reason only alpha and sparc were affected is that they are the
> >> only architectures that use si_trapno.
> >>
> >> Looking deeper it was discovered that si_trapno is used for only
> >> a few select signals on alpha and sparc, and that none of the
> >> other _sigfault fields past si_addr are used at all.  Which means
> >> technically no regression on alpha and sparc.
> >>
> >> While the alignment concerns might be dismissed the abuse of
> >> si_errno by SIGTRAP TRAP_PERF does have the potential to cause
> >> regressions in existing userspace.
> >>
> >> While we still have time before userspace starts using and depending on
> >> the new definition siginfo for SIGTRAP TRAP_PERF this set of changes
> >> cleans up siginfo_t.
> >>
> >> - The si_trapno field is demoted from magic alpha and sparc status and
> >>   made an ordinary union member of the _sigfault member of siginfo_t.
> >>   Without moving it of course.
> >>
> >> - si_perf is replaced with si_perf_data and si_perf_type ending the
> >>   abuse of si_errno.
> >>
> >> - Unnecessary additions to signalfd_siginfo are removed.
> >>
> >> v3: https://lkml.kernel.org/r/m1tuni8ano.fsf_-_@fess.ebiederm.org
> >> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
> >> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
> >>
> >> This version drops the tests and fine grained handling of si_trapno
> >> on alpha and sparc (replaced assuming si_trapno is valid for
> >> all but the faults that defined different data).
> >
> > And just to clarify, the rest of the series (including static-asserts)
> > for the next merge-window will be sent once this series is all sorted,
> > correct?
>
> That is the plan.
>
> I really wonder about alphas use of si_trapno, and alphas use send_sig
> instead of force_sig.  It could be worth looking into those as it
> has the potential to simplify the code.
>
> >> Eric W. Biederman (5):
> >>       siginfo: Move si_trapno inside the union inside _si_fault
> >>       signal: Implement SIL_FAULT_TRAPNO
> >>       signal: Factor force_sig_perf out of perf_sigtrap
> >>       signal: Deliver all of the siginfo perf data in _perf
> >>       signalfd: Remove SIL_PERF_EVENT fields from signalfd_siginfo
> >
> > Looks good, thank you! I build-tested (defconfig -- x86_64, i386, arm,
> > arm64, m68k, sparc, alpha) this series together with a local patch to
> > pull in the static asserts from v3. Also re-ran perf_events kselftests
> > on x86_64 (native and 32bit compat).
>
> Thanks,
>
> Can I have your Tested-by?

Of course,

  Tested-by: Marco Elver <elver@google.com>

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcZkC3YDSK8rA7yagRNBLCxyNRcUSKNbx69sR9PSW-2w%40mail.gmail.com.
