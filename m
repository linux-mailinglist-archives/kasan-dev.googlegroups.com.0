Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFPROCQMGQE2CEVYZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C208E386BB9
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 22:53:33 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id l1-20020a5441010000b02901ecd2ee1861sf2028865oic.13
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 13:53:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621284812; cv=pass;
        d=google.com; s=arc-20160816;
        b=q29PqNH3xbOHiuOz2cgojF8/gpG/RGtC7jJDGwKeo6tkQwY6w58H+w4Pt+kUTOSR2g
         78wypaUTaDdC3tZv1GFaeLJtzwvGtXnW2sWXDbjcUEQDQxDUeiIU+2FC1bV/t9i8UzA0
         p1DfIZPqLbWzDFHYNKczJg76TjuHPEvdB2jEmK38UkcbtqfXB6ktU10V0TFq/q7dda4W
         WyHdh98jJH49+dd5Jzl147KQFLihPyd7FadZGhsw47M7sktEDCxZikw7XZ0xkadnb0Py
         3aPuwcywUZ2QVbP3viS55hsgDz438UXZxd+tHNUTNIsbDUCyzI+CU6Jn/2kPSmGzw5Of
         SxYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k73NhJeTlaJ8r4kQyJFO4GF1Hs9vDH91X3xzNHAtF40=;
        b=BqRkFq9PyWeUGaA5PMT2OOHaE7dEjocBBN2IMHIR0CPQzoOdn+shbDikdwta0M6csp
         hUF7TwbLhemaTJgW9rei6xj36o2inAKEfmP7NhMggz8gT78ZUuRSWboOpioZMR7BezId
         kkw1Mz2/dPDc1cNEhM53I0ikwhoPnu6fqjxxsPIxHd06BbbbDtzD2Vq7ry7r4+MxFViM
         laoMzwjRYPgqLihVTpzylljo/sR1ZWi337aCGKxrI4ycsVokjUK4iKMcCQtD/HNpANcG
         K/H23MacMkxuGDzgX1ecf7iA7ZkZVSeYaPgySEl8gHcYdTQ2p1NNhNnmc9HjB0obIgQu
         LDGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E4IYESmD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k73NhJeTlaJ8r4kQyJFO4GF1Hs9vDH91X3xzNHAtF40=;
        b=tcZnIL9jCenSuMXTs8WVJqZWTyKWCGdvMwjBdUOKCSoJjz2cas5aGPh343iNmFF8d3
         y15KL3k/dKcBegRZYXjlZIRGICDB4PVGv3no+K22XJ2HjbFfLoRg3grXV9su+I/xtw+2
         NE00gWmyNiWgHFvbqxi1xRvw8iAEOKJKrbhCAE1ye3g6I56ThrZXf6E1zYJ+fYe8Rkct
         zwL9Ukjoz6gZ2wCocURW7oLLO4B4EgNjd2Dz8dset1DT60zmHsuucq+6xH1lTrQRC03v
         enSD8YfRyGcarzfUCI0k7hynnBo/ozI6a/VRzZqI2IK/CNUaOYUtiiduWKOkDUUpiJnP
         yHMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k73NhJeTlaJ8r4kQyJFO4GF1Hs9vDH91X3xzNHAtF40=;
        b=eoHJueXsg3RHAB5jFfmPwAsHDHR1o04DhWA4t0juZl4UTXHnjSl1cycmqnpFNJl2Hd
         05FjJQsu1NkTcArj/V+Pv+3qja/SHvahYdjbVpVNJFc9xpgihRXUSSf4KRGemHSVv+RX
         M3PxmTi5I5930q8lfylLP4ce4mKpN57FL4M+4F0r3pr7KtshOb9bDxUHqYB54G/EuGQR
         qG+sntcYEYlLnFdUbBCyL2SDEEaV4J7v2UFZirMDSei/FV9Mtu5mMD3BGxIHbEIjFCRb
         bVueBt6gxIFCMkdE9WOVGCuy2YQZTRx+BlXqLKAgw+IEhko9T8SuHdMPf6rXrDlQl0kP
         0B/w==
X-Gm-Message-State: AOAM531nvsyVkau0sORLHIp7uYo+lJyXl2KrOnUXl67jXaRtdDq4jEbT
	d86j05D0KQYuNL66J8IW3Pk=
X-Google-Smtp-Source: ABdhPJySYkaHjlYY/Fe6zwkOish4s6iu02ZPEyppvzirzX/AzLAAcRQKi5DrjKi98N9be6hxRcMFeA==
X-Received: by 2002:a9d:6117:: with SMTP id i23mr1234572otj.28.1621284812780;
        Mon, 17 May 2021 13:53:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:68ca:: with SMTP id i10ls1851765oto.8.gmail; Mon, 17 May
 2021 13:53:32 -0700 (PDT)
X-Received: by 2002:a9d:7a44:: with SMTP id z4mr1213825otm.196.1621284812426;
        Mon, 17 May 2021 13:53:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621284812; cv=none;
        d=google.com; s=arc-20160816;
        b=nypXncFdgUsnMYBLT1x7bkGxpcX5lrQp0RNSKCltEmeOlcQdql/TLp7VLJf9KdVh+N
         6WBxaedNnMXdFiosnAaboxU/alGQr9vyGqAQ2K/gbm014L9KILLOgq0DQxaL2W0zTAzj
         eLI1zWqAj7uGJ1xcflS56+OI7QXXIlzvE2+Cvh2XGWzjhHvvFv7jZ+tjQzNOwMZhVBPC
         hfqkxPVhhAuoD6Ws16/CYuJwhx9j+NvTNSJFFdfl9AdKoD7jJx0UwETkSP0hmvpqUojn
         GJhQYfNmV5NHa+wrfoqtvQ5Sn+PaI3ffHIA3lvKVvgdz+Hw0cnTMNTPA0C+LM/f2sMDJ
         AAiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tYiKNumB/sG3g6UoDTpwUaKhoLR3TJj2KrtveF22its=;
        b=r3FWAf0GmH+jLdG39NVvG7adF1bwgzgCFlwWE2cm5nEVTDUXzf7OPA5dN9PXbNiWFS
         q6HPBw05UFE4/Xo9G7NIXZ0ofBqTYB+HMy5kAN0+apghW9oAdTNQSuEXYZ+D9CBy/ebN
         MSSOUT8Lha4Et6hN19U01hcKgg0zHgBvG7mNYpSZbxYR3bFywB1/roewyndIfXdzNawx
         K/vRVV8c/PDBJI3Q+oomEPNgwChAe0RFmFh08iRJIUe4JphJO0BpKQy4eqOTGK6mvlP8
         CJizI63KI01UJZ8dATodkRj873pV1pznuDR8qpLBDPmKWktqMII3Z8xSjWGWHKTvAIX+
         qBAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E4IYESmD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id f4si2150101otc.2.2021.05.17.13.53.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 May 2021 13:53:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id b25so7785053oic.0
        for <kasan-dev@googlegroups.com>; Mon, 17 May 2021 13:53:32 -0700 (PDT)
X-Received: by 2002:a05:6808:f94:: with SMTP id o20mr1223000oiw.121.1621284811977;
 Mon, 17 May 2021 13:53:31 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org> <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1a6ot5e2h.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 May 2021 22:53:20 +0200
Message-ID: <CANpmjNM6rzyTp_+myecf8_773HLWDyJDbxFM6rWvzfKTLkXbhQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=E4IYESmD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Mon, 17 May 2021 at 21:58, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> During the merge window an issue with si_perf and the siginfo ABI came
> up.  The alpha and sparc siginfo structure layout had changed with the
> addition of SIGTRAP TRAP_PERF and the new field si_perf.
>
> The reason only alpha and sparc were affected is that they are the
> only architectures that use si_trapno.
>
> Looking deeper it was discovered that si_trapno is used for only
> a few select signals on alpha and sparc, and that none of the
> other _sigfault fields past si_addr are used at all.  Which means
> technically no regression on alpha and sparc.
>
> While the alignment concerns might be dismissed the abuse of
> si_errno by SIGTRAP TRAP_PERF does have the potential to cause
> regressions in existing userspace.
>
> While we still have time before userspace starts using and depending on
> the new definition siginfo for SIGTRAP TRAP_PERF this set of changes
> cleans up siginfo_t.
>
> - The si_trapno field is demoted from magic alpha and sparc status and
>   made an ordinary union member of the _sigfault member of siginfo_t.
>   Without moving it of course.
>
> - si_perf is replaced with si_perf_data and si_perf_type ending the
>   abuse of si_errno.
>
> - Unnecessary additions to signalfd_siginfo are removed.
>
> v3: https://lkml.kernel.org/r/m1tuni8ano.fsf_-_@fess.ebiederm.org
> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
>
> This version drops the tests and fine grained handling of si_trapno
> on alpha and sparc (replaced assuming si_trapno is valid for
> all but the faults that defined different data).

And just to clarify, the rest of the series (including static-asserts)
for the next merge-window will be sent once this series is all sorted,
correct?

> Eric W. Biederman (5):
>       siginfo: Move si_trapno inside the union inside _si_fault
>       signal: Implement SIL_FAULT_TRAPNO
>       signal: Factor force_sig_perf out of perf_sigtrap
>       signal: Deliver all of the siginfo perf data in _perf
>       signalfd: Remove SIL_PERF_EVENT fields from signalfd_siginfo

Looks good, thank you! I build-tested (defconfig -- x86_64, i386, arm,
arm64, m68k, sparc, alpha) this series together with a local patch to
pull in the static asserts from v3. Also re-ran perf_events kselftests
on x86_64 (native and 32bit compat).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM6rzyTp_%2Bmyecf8_773HLWDyJDbxFM6rWvzfKTLkXbhQ%40mail.gmail.com.
