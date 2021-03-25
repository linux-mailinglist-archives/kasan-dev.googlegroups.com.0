Return-Path: <kasan-dev+bncBD7LZ45K3ECBBNNX6KBAMGQEFV43YKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 230E63493DC
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 15:18:30 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id g187sf222154wme.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 07:18:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616681909; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtajHIiCSw+pmfhMaXxHHqEOmoHW2PllF0LfO+q1dkk/3TFHd8+a6b9EA3pYdOGWkK
         BIotejgOuYBTZLWD2ZS63/UAo02u78fD10iPAaaJWlFVgMlTvNB9382tn8Fem4n+MTZ1
         vyncUeQA7ELOkwFvkwkwYAVJW9wT05yjW2cys1TJrvYT04ovVoR2zftT34bAWJrGt6zx
         q1l7n0mG045myCqFm4GG56QBjKGsu7q7PJdHCX/ScV+WbOj98k/QGwOBAGnto9vqAz/A
         d19yelIb9Oxw0iMbCpVb2XJmggLqdNMfSY9hScRTB3x+Q10Vmi75iJChUOvCQWKRokSH
         t8XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PcU210be4E5YpvEM0XIfNfJMNWNhU9hrqgTKEZfZvuY=;
        b=N1ypaM0Z0fQiw2TUl/B7O7Q+9u/mDWH8J8ovFCoMRrjMwHVKBeeqInqg3FbICjHcCv
         7t7rPCJPCCwbCSMZKCN31zFf56EUKZbi368WQIEX2zfmyMvUH4bm9qf6hpIdFdzZgvwZ
         DfOr9CV7wXI8scKJXyxiQEra1b7DF8k7y2cllNsHj32NQZKU3ftnLZUUT9pl+7mU/+xh
         5z65VlRfWR0o6Y892STitefl8ie7fqEdjV68VCpyuqB1NNjHMCKQnn3ITu0yiRRRcgr/
         E69n14+VQe3d+6nMzMyTCwwjkb0m96l65sKDzALEP9j5cfBOrPrK3NzrXeuOfsUoyiQa
         o3YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RbjSEQfq;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PcU210be4E5YpvEM0XIfNfJMNWNhU9hrqgTKEZfZvuY=;
        b=Xdd0OTAerYW5m326J2/wmSABYfaLoNks/Ea4HE224NlzqZpN8qwzgC2NPuxvcqVe0U
         GsAQMD13rFD8180BLySwOQEqMG22PvKbfKv/he6Dko+TUBogfg5Y7qQdYJagv8pJ3e7d
         +Jc4zdCSlYMjq/XRfrsP+wgacAK6Tu7RGbpGAjQd2MmFzkyvK4sAcEvKivMbijMIeds2
         kU22diatNMy8vV0ZJ1vTHj1pWX7YFKLz00BIHXg7skNJVV0o3mnkJja7YjNU/mHbsbfB
         2aEtFlf/hc4BeFegXGwZoN/Y4pD52dYI7bm7G5Z+joK13e6XCY4QsAoOof15it6sN/DG
         lOMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PcU210be4E5YpvEM0XIfNfJMNWNhU9hrqgTKEZfZvuY=;
        b=m3+vxNABo75zrdaQLUmxze9ZBTEO6L2Ed+B5gJznJA1NC6iTaafZWai5mfXEx/fc2c
         4Dzzc2ZFJBEbv/KDwzryUuDDY4nomYEsGyR/8Rwf+UVAr3cwq0NWYf3hKKQsaWV8n88x
         c4wGmiW2TD5qU8M/aU9yfmpYSphQfnAgsizPfWZQVQ5WC1wmdu7O6gGLnLC8u+bhM9qt
         yzQc/BKxs+nD0OyXN+1dFFvVgxhEuix2Ia++Rx2nNh7VmJXMXHv3KC/G4AW/2pDDUMgB
         1WqHalizLn0OGc5/i2+c3VHxbuugmuvVZMapaWmiy1ECMac+fWIN1aRXJJaXvGlInZcT
         sf9A==
X-Gm-Message-State: AOAM5323/L+4YaxsyBgyNH0z7WY5Ku/NCn5a8VYIuTelDk/oV+KR5OfC
	sawk4P0z8HWDlzAY6Fk3GQA=
X-Google-Smtp-Source: ABdhPJwm8jMFZ/WeuPrT+LeOSuAeraYUbWvxHpzTveVF8csTux7ac0nQrFxqCINkmRMjOBd1HqhkJA==
X-Received: by 2002:a5d:684d:: with SMTP id o13mr9578997wrw.235.1616681909844;
        Thu, 25 Mar 2021 07:18:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls4614823wrd.0.gmail; Thu, 25 Mar
 2021 07:18:28 -0700 (PDT)
X-Received: by 2002:a5d:4b0e:: with SMTP id v14mr8712538wrq.61.1616681908763;
        Thu, 25 Mar 2021 07:18:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616681908; cv=none;
        d=google.com; s=arc-20160816;
        b=SRRRC8nbxRMh963AOBl1nuo9iNaqTauR/5Zp0s2zoaBbCGE8bP6BKxFkG4NwmWnBdO
         M9Q8iXBay80iFyHkh0sFcS0RkFAMRn7gc7gRy7vr0Ulmh6sbtLLQ0e1mckgOtixq7yEq
         wMDU3DhWF4q8UlaYPzS9seh+ErjQTv8KXvFY/PeOsKspiGqJu2nuAj1QN9XbcrVDgJIg
         nKzZJmXGGmxMVMHkZYUfzlTSz2kGUCGAQtb6XsBf3s4dzKtRVip8qLbmckhX3nGuRsqw
         XhZoGIAyrfvVD/IVGtXOSlK1QtaoO7r3+jSWj334O1xt60NnDMoPrAb743maF8cgaA77
         Pw+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=lMu1u0tgdpKUYdK0Y2edV56h3EG24/y18/fAyUCWVWo=;
        b=U0sYMGHXDnWWkQUkCPsVnVbr8mF7oafyeyZLMu/NRRhF5ELl6YEPC4nTqfIGuH2axG
         lelobPnMncR7pgJyqoRvia0psweGSWrZ6Jf5/mgjpVAdh2EV3222bPJ0v1oqaH7Es8ds
         Cryp7noEyixfyJhBfcKMwX/b4/luvby3XwmEj0zjzrPXzJn9+U52iGho8KT610lztHLf
         W58MCWFl7YotK0DSc6eeuWy0wXCGPs3JheRtxZrg4zCuMqHUKlrBYD9wp3xUIGAujxwU
         KbUHY6Ql1rGi08+FszAWtuVjev3fIeDYjlTCP3K5ZmMHBbOi0Qw6aAv/Fkrw4j12Wjp0
         dxlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RbjSEQfq;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id s8si238221wrn.5.2021.03.25.07.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 07:18:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id w3so3191560ejc.4
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 07:18:28 -0700 (PDT)
X-Received: by 2002:a17:907:e8f:: with SMTP id ho15mr9886768ejc.541.1616681908525;
        Thu, 25 Mar 2021 07:18:28 -0700 (PDT)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id p19sm2793453edr.57.2021.03.25.07.18.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 07:18:28 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Thu, 25 Mar 2021 15:18:20 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Namhyung Kim <namhyung@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
	Christian Brauner <christian@brauner.io>,
	Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>,
	Matt Morehouse <mascasa@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Ian Rogers <irogers@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on
 SIGTRAP
Message-ID: <20210325141820.GA1456211@gmail.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
 <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
 <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net>
 <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
 <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=RbjSEQfq;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Dmitry Vyukov <dvyukov@google.com> wrote:

> On Wed, Mar 24, 2021 at 3:05 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 24 Mar 2021 at 15:01, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > One last try, I'll leave it alone now, I promise :-)
> >
> > This looks like it does what you suggested, thanks! :-)
> >
> > I'll still need to think about it, because of the potential problem
> > with modify-signal-races and what the user's synchronization story
> > would look like then.
> 
> I agree that this looks inherently racy. The attr can't be allocated
> on stack, user synchronization may be tricky and expensive. The API
> may provoke bugs and some users may not even realize the race problem.

Yeah, so why cannot we allocate enough space from the signal handler 
user-space stack and put the attr there, and point to it from 
sig_info?

The idea would be to create a stable, per-signal snapshot of whatever 
the perf_attr state is at the moment the event happens and the signal 
is generated - which is roughly what user-space wants, right?

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210325141820.GA1456211%40gmail.com.
