Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEKY6CAMGQEAJTAZ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DC455373231
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 00:05:14 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id z2-20020a9d62c20000b02902a51ba083a5sf7145918otk.21
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 15:05:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620165913; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kt2lC7yQ81EyEPkcjH66d+QWZV+zu0xHl361m9U8V73koYEoM4zRG76ahvWHFwMYZU
         KgJc18sioZ+FqKqD4y0QQNZOsphvUyn9nTz2Jb4EuGNYQ7a1uaLWRZbCpSPn8psfh+qO
         vhEP9zvmICzGvqcDQkexpXxr/KZB33F/O85pu/jZurQ+78J1J0FLHh4Vqvnr6p79DcXe
         IPMqcEKOh/EbAi20h5/GUOVff3ePjxvoV16X3qo/Mhy6f0NYvF1U1wn3rrNfZ2OHddmw
         Hk4pD7iidCgs7JXVeqSxJ1ox3I9azq4ZFt3XanK55sx5LbJ0exO0MI54zsdordE4J6ct
         lY7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eVY0LlEbL2QcTWbZVKk47REv6S1dDUHCZN7bHH6ZC20=;
        b=Mp9ql+aVmm7BesA88LFO1aDEGyQEvhU4llvTNH2kbWK5V8/2WOLhDNwuSz4FI/xjCB
         d/EGGpYDIUUSSX+sbhJ4H9ROUXdE02IdGW0FjUEwljOMniX9OzcxFK4qpK1eXqgGC56K
         9azpkG/2PuCepDfiNsI/0gPqJlQ9U3wBumrHceMLKp4BiKZ9/I25V0KIDkk88GCKJzdT
         8mo2Z1oVE1AhkUWiB+xM7DSNajAeRRrT7A8ArO1bp5lhgFsABmWBGesBd8/g8TPkbWir
         P2ltltz6F2rIX86AR7ynFqYr5nEimBPhTSYXnrB1mcDWVC7+ER/XnWG2zcjj2R6JNqWQ
         gXDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rbZN4R3L;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eVY0LlEbL2QcTWbZVKk47REv6S1dDUHCZN7bHH6ZC20=;
        b=td2WIVoMDTpsqNs3wsP2n78hdGGJEbCq6Ea3bUJKnrdWDXTXgtzDto3aF+lau5MjJ/
         VCeB1g1a8Fr9GYAjmMwRlG1zcoD05FUSq4HtmfIbMF+1bEE+/uCnjaIfbT2J/e9/s3hF
         k6XjUdAFeTHCtu9A9bAMMHdachvtcf7VaN7jj6UurPmF6hWtjBtjCvXzXYEjTumtP20p
         jXygBYiw3m8KiA7K4zliVRzpZ/KLhsdY0cvLbqyNvhKoM6Me8U45wRmP7eog+zqGYMEU
         695dERkHNi8bDKU2Jdazy1DkaDwPkW9qs+L30qzVoyKPXBvLjzxTacLlyJxXTn5Yw/VW
         n8dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eVY0LlEbL2QcTWbZVKk47REv6S1dDUHCZN7bHH6ZC20=;
        b=ADOJthDmMOzPiutSilU4WD6+6NUW0kmpBJQ4An4E0Y7KWRK7S/H3eunBbe3wI1K3OZ
         +T9Cg+bX1ru02tJcXlkcD3Fng+XOQIsxeC2nrQrBL3HWrahI75y3piT2RNiJwgiFcnx0
         ZdICI3LdawpI8F/7Frgghd91bhZ2M68akyZWXTlpuhHW1ensypZIm/INLMTH6R9/3fYq
         HNFTnQ16QqUJivLLsSWrPFvjd+MhN941ICB79PAYIt//jk6/Q+GHGr/OoJ0ayaJAYjCe
         S0c0m3/G/sUoyGJZdvzCmKaK3RgxRlV9AxvrQ/f4Z3DP9T+4LrA+3vCUpHhKyF5JpPgM
         /YMQ==
X-Gm-Message-State: AOAM533lfrnE31Aq1/Q3nJld8S+VdZtrMDsZ5+KB75EqzCDBduJGz29G
	Ag1XZogXOlSV1m7huUy9IlQ=
X-Google-Smtp-Source: ABdhPJxcc5jHY1LjOqk+e+urU7G1SqKRv5j01u8DWDVOPvzU90a2iFfMxhBES6jyhxTvB2Nnp7tObA==
X-Received: by 2002:a05:6808:315:: with SMTP id i21mr4585321oie.119.1620165912496;
        Tue, 04 May 2021 15:05:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1711:: with SMTP id i17ls206753ota.11.gmail; Tue, 04 May
 2021 15:05:12 -0700 (PDT)
X-Received: by 2002:a05:6830:13c4:: with SMTP id e4mr6685535otq.315.1620165912082;
        Tue, 04 May 2021 15:05:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620165912; cv=none;
        d=google.com; s=arc-20160816;
        b=p7Qrsr0pGsogPSNwSzHMi9NGODQRzq0jlOavv18QLdX8k4B/d99DPpdYM1ZZTKIjzG
         rGZKS2bIWVSxerstBjIZeSuBnsrv/ofkwGp9cQdKx8yupF6YEu7ENAO0q/IB4OuewiXh
         +DQQI0VNw4pK8r4yL5XUSyb9QQmXSpfXGLaPSkgNMqcyJStwgGe3ykuKhpjiLuxW/4RX
         0qjXuYEPNmE14mn3sFfCvIk/fgrr7NCbPAvaHmG1AWy5reyTHZgX6QLqKSq5Q2j1xXqT
         FZWpo9PVgjfmRTT26644LzWHD3dvuWi8+tIx1CPEu9a/6v7HPln4YdjySgbmwLQs8gvv
         Tqcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bUX+fmvBWZ7MZX/eB50i8/ErJ0LDxPwc8AG9r8drP3E=;
        b=yL34GeRrMXnukeXQ/nQgAUlCWtInuB1zflY98LLKpm/irJiQQ61AVqQ09C0Rsz5Z55
         gDh6bg2+72w/IrCGQ/788Bc8bDL7sd/OG89DZ6L4RERmHgzYCn4FbAgmj0+/X3i5FFDF
         VPuI+nLcNRKHzqyH1mhlBtJ0PsaZucgmTadPrD1uuRGZvVNUjnfgUQwabkzL0Gyj4qit
         KgK3RFU4j6vvk+9wUn0TTr4Lp1fam3Mp90fsfWVoCcVIfW1uJlZA7CIB+Y/fKgPvyXMA
         xCddaZIW86vZqMRAAgX0lfD+6+5x+K0Rv7Xy9RfDBu6lyvelObdtghX6OwpweO5Wis9C
         xkPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rbZN4R3L;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id a5si358778oiw.0.2021.05.04.15.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 May 2021 15:05:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id b5-20020a9d5d050000b02902a5883b0f4bso9693997oti.2
        for <kasan-dev@googlegroups.com>; Tue, 04 May 2021 15:05:12 -0700 (PDT)
X-Received: by 2002:a9d:60c8:: with SMTP id b8mr21322801otk.17.1620165911656;
 Tue, 04 May 2021 15:05:11 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 00:05:00 +0200
Message-ID: <CANpmjNM5sYihM_9P5YHx06BooqLDhK96cMHGKaf61nCcoDJBdw@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
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
 header.i=@google.com header.s=20161025 header.b=rbZN4R3L;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 4 May 2021 at 23:13, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> This set of changes sorts out the ABI issues with SIGTRAP TRAP_PERF, and
> hopefully will can get merged before any userspace code starts using the
> new ABI.
>
> The big ideas are:
> - Placing the asserts first to prevent unexpected ABI changes
> - si_trapno becomming ordinary fault subfield.
> - struct signalfd_siginfo is almost full
>
> This set of changes starts out with Marco's static_assert changes and
> additional one of my own that enforces the fact that the alignment of
> siginfo_t is also part of the ABI.  Together these build time
> checks verify there are no unexpected ABI changes in the changes
> that follow.
>
> The field si_trapno is changed to become an ordinary extension of the
> _sigfault member of siginfo.
>
> The code is refactored a bit and then si_perf_type is added along side
> si_perf_data in the _perf subfield of _sigfault of siginfo_t.
>
> Finally the signalfd_siginfo fields are removed as they appear to be
> filling up the structure without userspace actually being able to use
> them.
>
> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
>
> Eric W. Biederman (9):
>       signal: Verify the alignment and size of siginfo_t
>       siginfo: Move si_trapno inside the union inside _si_fault
>       signal: Implement SIL_FAULT_TRAPNO
>       signal: Use dedicated helpers to send signals with si_trapno set
>       signal: Remove __ARCH_SI_TRAPNO
>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
>       signal: Factor force_sig_perf out of perf_sigtrap
>       signal: Deliver all of the siginfo perf data in _perf
>       signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo
>
> Marco Elver (3):
>       sparc64: Add compile-time asserts for siginfo_t offsets
>       arm: Add compile-time asserts for siginfo_t offsets
>       arm64: Add compile-time asserts for siginfo_t offsets

I can't seem to see the rest of them in my inbox. LKML also is missing
them: https://lore.kernel.org/linux-api/m1tuni8ano.fsf_-_@fess.ebiederm.org/

Something must have swallowed them. Could you resend?
I'll then test in the morning.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM5sYihM_9P5YHx06BooqLDhK96cMHGKaf61nCcoDJBdw%40mail.gmail.com.
