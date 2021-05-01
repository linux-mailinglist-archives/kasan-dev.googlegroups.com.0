Return-Path: <kasan-dev+bncBC7OBJGL2MHBBREBW2CAMGQEGJ7KEMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AC9A3707D5
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 18:24:37 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id s26-20020a67c39a0000b02902274964b0a0sf672144vsj.19
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 09:24:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619886276; cv=pass;
        d=google.com; s=arc-20160816;
        b=RzjDACIevlzt0N4j3Es9RNxOBipH1DvMzTnPAq6aFcKPXJT9pwYIg56CLk1mmfdvsU
         4FlSpLCkWj6L6ri7Rq1qcFKyitQuPoxEMkdfvD+uHU1YdFAo1frinhkXR6j0mfko5ZmR
         cd1S1Sa9ETRgCMsz7tMzYIGwsh3qzJkJcwp6SSQqjyjl+wek480NDA9ezbSyGEqkIjGf
         r9Z2+KwLBKMqQSOoEIlAvprGnA3lC4gOczST10zKJXpYy0cgzWP2aj9K73irrFRIbvTU
         sFY54BPf3KzJdRLiUUsJpVZfDPzWJze3UeRyEH75vLAcLncwE2nJ0pl5zuO1YLYrankp
         SSSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OZE4QD9nUQyss5SrsmyZH55CKQbhSGXol52o9xS2PnU=;
        b=kfOQii1ENjKshdEjI5IVMwQ3vdvRUOhqHxqxoBF7IEVzcPLUSXD4dNHdGzC69GhcSA
         AMf38NB4bKztl4u+uqh3v6MxQMaWeX5/cbZ7OfqpttpdlVDbto9SE/Ypf7ZyHQiKjA1x
         Wiqi0dZaOJrshmQ0fI17ISUv/4PfSTVqhWvvAVDD68C3VFC6vOXn4aykaSRoPtsMJxn6
         dedOTAzS+glCsl46jv6IDFddTnJJYfSXUvKPUaGPtNgX3jHPBlrcyq6xWXxN0NZ4pd06
         cPVoVUGyLSAnlX80hnWLtQ8xSZ4ejx1OxBXFyBYujnoM4d7g00bVoEXIJLD1hqVWpDe6
         co8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eF/f5QKw";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OZE4QD9nUQyss5SrsmyZH55CKQbhSGXol52o9xS2PnU=;
        b=Gt3qbtPxideB6w8r8f7Y+VFcPvYLRYTSD6pfIJWvd4ZLjLjwtV+cMZdVhHcAQo+Fdb
         /bZgPwTxrIlCryxs6tjXR4vF2oQfGPj8T9IN0VOfEejNj0fnacfnzcUquivAEGh6ImgI
         z5A2p47Py257Kj5kQtKK2/srOgTkHzpIJ0t4gXEZdI5nOzGuQHZYK4Fi7JDJAMHfwPjT
         hrMa++5KZod1caTT7OHqZURAeN7lCYg72fZv/I7qQ+Klf2zRCLkfmd5bHF5XHQgozIBZ
         0DsFL6lmMhNKIWYC+FUmI4Yzg8Q0L5T/JZY5TU24cjDd4lvQMBud/YgA2muQa7+iRgI5
         qSxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OZE4QD9nUQyss5SrsmyZH55CKQbhSGXol52o9xS2PnU=;
        b=eb+kbOqT4NVCWoJm8qAKRK0n61SxDcNHJPiA/HWGlQuxxLzjnUu42l6R5y8tXRmp/w
         97pp5WfmhCFCVXxHNgQnSi6WCa8zE4RbHSLdZkf+ph1zAvntDRF6dDQC4N/BcH4Dl3oE
         /pn7yPUd5yqP3ikR6VzrnByCYZ+oNMUKZIdUJH35Opzos3genbhi7DYv4jJBE6Lev7ht
         aV/885YhHJY6+nSyuDgqxEvpOu8svPI7Zqxo6w4ZFWxwqKjHhJlZtm7+pKNecNybodaj
         vmbZ6a1SRk6XJ6wO+usgT0g3jgqQiqrIoByfL0zMJEd3Ybo+E/i0TZREtgpjF6kfd7/R
         Nn+w==
X-Gm-Message-State: AOAM5311KWP5WvwTHP19hvUEa56FAuxdXT41fyIKomEOUDy8IMBA9P/L
	K0KeY6jfMdtF1qLkhsxrunI=
X-Google-Smtp-Source: ABdhPJy6oPleZHBFXdep66fbUUzi7Mi6bHMLqmax+jO2BS9WVni27LY3RDAfjYc7IE9ogwc/2CGZZQ==
X-Received: by 2002:a67:8745:: with SMTP id j66mr11721450vsd.18.1619886276595;
        Sat, 01 May 2021 09:24:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:de96:: with SMTP id r22ls275114vsk.7.gmail; Sat, 01 May
 2021 09:24:36 -0700 (PDT)
X-Received: by 2002:a67:7045:: with SMTP id l66mr7234157vsc.47.1619886276027;
        Sat, 01 May 2021 09:24:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619886276; cv=none;
        d=google.com; s=arc-20160816;
        b=D8OG85wPISVu1eD5KJGhe52HUY4PXqdSppxgD3hBzGsUzBvZi4PGp3pJe4l4p+b7ou
         btK02az1FlJSYKskr/0SlcBvCXvOdc94a1w7fceV76lS3wuIkcDDx/EEkNK6y+L8K1wh
         oeFQGafUOtwofJNCxmoS/XyOSnrKDbm9vBBjqqnqA8Ic9xwpJIJiavdKUqShS/3tJ9Me
         DK1bqAsVGl2p7pOuz1KvYlsGVVw6yTrIS2Qq+EUCRkv6dsoM5xny9WtnM1Ny/5nEKqac
         8/CsBTChtrpcgOqkkWpnHfDSbaaO8cFYSoCWDE2c0GTqV/5qV1qNf1gmlSSfVjVG7gXy
         sKdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CyRw8Tn64/8GQf/qvRpik9Jpd4CoRgx2tUKy0Z4v2kk=;
        b=liIono0Z8Z/qqvyq6CQ6xsK1HWYK67jRpqNMWepDlYdL2VdsjgMXAdIzxLihauXXGW
         z1zV+oqH6Th7hSHmMg94TekVCpwsAWzL+bQ6e3MQ/9X/TMtBUu54zscuczc3YcDibEpY
         V1uBHOElsRKlynZQF6MBYh8TOglGzb+ugZpEfE0wa6HNodcS17+Wqosg3zf4g9EE/gRr
         VFD6IafysrOFm5ZO8/2UOJz9p3FVHVlljERiZI9WtoRh053XP+mH2DbAf7Y3L+YdUxX+
         8tACPUx0sjlQy/O5vwAd6XLoiLwwoA/mHGuJ1rOhXH5go90wM8VO6dY4ArGswXJe7zW0
         NDag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eF/f5QKw";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id h7si760386uad.1.2021.05.01.09.24.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 09:24:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id n32-20020a9d1ea30000b02902a53d6ad4bdso1308193otn.3
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 09:24:35 -0700 (PDT)
X-Received: by 2002:a9d:60c8:: with SMTP id b8mr8272179otk.17.1619886275343;
 Sat, 01 May 2021 09:24:35 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com> <m1czuapjpx.fsf@fess.ebiederm.org>
In-Reply-To: <m1czuapjpx.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 18:24:24 +0200
Message-ID: <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="eF/f5QKw";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Sat, 1 May 2021 at 17:17, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> > On Sat, 1 May 2021 at 01:48, Eric W. Biederman <ebiederm@xmission.com> wrote:
> >>
> >> Well with 7 patches instead of 3 that was a little more than I thought
> >> I was going to send.
> >>
> >> However that does demonstrate what I am thinking, and I think most of
> >> the changes are reasonable at this point.
> >>
> >> I am very curious how synchronous this all is, because if this code
> >> is truly synchronous updating signalfd to handle this class of signal
> >> doesn't really make sense.
> >>
> >> If the code is not synchronous using force_sig is questionable.
> >>
> >> Eric W. Biederman (7):
> >>       siginfo: Move si_trapno inside the union inside _si_fault
> >>       signal: Implement SIL_FAULT_TRAPNO
> >>       signal: Use dedicated helpers to send signals with si_trapno set
> >>       signal: Remove __ARCH_SI_TRAPNO
> >>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
> >>       signal: Factor force_sig_perf out of perf_sigtrap
> >>       signal: Deliver all of the perf_data in si_perf
> >
> > Thank you for doing this so quickly -- it looks much cleaner. I'll
> > have a more detailed look next week and also run some tests myself.
> >
> > At a first glance, you've broken our tests in
> > tools/testing/selftests/perf_events/ -- needs a
> > s/si_perf/si_perf.data/, s/si_errno/si_perf.type/
>
> Yeah.  I figured I did, but I couldn't figure out where the tests were
> and I didn't have a lot of time.  I just wanted to get this out so we
> can do as much as reasonable before the ABI starts being actively used
> by userspace and we can't change it.

No worries, and agreed. I've run tools/testing/selftests/perf_events
tests on x86-64 (native + 32-bit compat), and compile-tested x86-32,
arm64, arm (with my static asserts), m68k, and sparc64. Some trivial
breakages, note comments in other patches.

With the trivial fixes this looks good to me. I'll happily retest v2
when you send it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyifBNdpejc6ofT6%2Bn6FtUw-Cap_z9Z9YCevd7Wf3JYQ%40mail.gmail.com.
