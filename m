Return-Path: <kasan-dev+bncBDPPFIEASMFBBLFY4WBAMGQEQVVQPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D34BE3455F2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 04:10:36 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id p4sf626121ljj.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 20:10:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616469036; cv=pass;
        d=google.com; s=arc-20160816;
        b=HIYNMnvvs4QDEnmhJjmsztYHH/LM55rtAoUFbuhMgWA8vGiWMsMCXMDAePUH4E+TS2
         +WZ/3couFKtAbnbL0BQeqJZ7ACuvisrF5GArgLrWwsKiXt6nkJhdsiwu4w8m71GtbPon
         v1I8xVGcq5f14kf9PkcY3eGFseaRuQ/LWarHFnyDXbcj2+I0OJIiRe+/uC1UQVL0iReg
         CQNX2DmFHvAoQkgxkUmtwZ8g28sCQIWwrjhTJKhfz23RSjz1DZaI7N00EV1vtpoArlEu
         8ush4jYDcEnz+aXl2AUrBFDvoLkTgV7V7/ZxWF2h5A1zJStvD6qbmfltPpwN2A3b1WSr
         ozgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6rYKbhfT8ATEZE0Vva/6ttS85IPU0OJYnF/g11M3DW8=;
        b=Y24gJ1pHTqS9yZ1f1ljyRBm0hxHO1TPRdxSACttMsmKn12q02kSnLbmLiJD4sBwElK
         y9GLQU8389wUu4hULOiw0T8LbNPaIjTgQTrWZ9WyxGJf4Twwp3wzath13PDUXBST9FAZ
         0kqedFVCE9LCSuMIbi5rCVchkrW/rk+61UbN55gsJAyaZVIw49CDI42757L8OHesvQ8q
         ZQcFboRttZhN8R1YaYMMuLv5hMVyfm0WcDXzy61dbG4hkjETZp/IkXq8BQqopQtZWhdy
         Txq407gzPogFJe2vJ0YMXtOS+i5+lc/0yary6V6fR65vdIkj+RSYh/w7nchn9DZgMBs8
         0Zpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+uMOdSR;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6rYKbhfT8ATEZE0Vva/6ttS85IPU0OJYnF/g11M3DW8=;
        b=FDxf/Nq+x0EP44+2D0d/aO3ZhPxSTWp3WGktY9SBdzk6MXiriKglcp65Jf/axrKD0i
         xxFWukK02fgHRN39EA5njK5d7yTFuegpDopvjSgShraHEp9KeJvQEADoA+jeXdd4Dno4
         OR0wgc1SSiGWGh5yOIgSGP5fbrwgigL18gbnmkUhuSdffjunq9CfBT4jLZTVX9s7TtOq
         iCH8aubdC4StYK58T7/WPZ2f0IAPQ7kJeHG96bkHxppTEZXkkwPF1Za6rmbySck68LGw
         pEbuoNOzyqwvPnrtHyoUeIFsyLcz9rMQ0kNApq4wvWwbuzsmwBeJpiRgUMwBB4cHzw4a
         d6Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6rYKbhfT8ATEZE0Vva/6ttS85IPU0OJYnF/g11M3DW8=;
        b=E60+daHmVFXn8J3XBLiWRiaUvAv5zn1OuYUJfa7qk+hGRoM0KaNSApsC9fJ+kWB/lc
         8QFsD4rcf3u87s2NfoAg+iNuQxsovE1kyxZ4qvzrH0xsx7qG+pM1XYmcuwnyad8caaqN
         zbPckep6QpLxXLofrQtFJGRUzx/wvHIFhHCELJZh+QlOk2B7rIi1B/p+wQFVMLGPboZp
         mSxGDt1KA9u7Q7APheZilyomdW+ZaN3QYmPphw2kxoFJTydu6vFtmPKhR75jAvS8ToUp
         Ib5yx/XviGCjDR5Xh8ahi6UFfpcHo9tTLD3wU6poQ1FNXDrvXTP1nHaFW/g2roZqEFwS
         PQ0g==
X-Gm-Message-State: AOAM531qOmXLtgf4jSBykZ0eBdHUKsIZZh3nxjNIN0+7yJuxHfJFJfkW
	55JLsvxTfpEhnI6/ZVt3l0w=
X-Google-Smtp-Source: ABdhPJwwUpl/Tk06ZrQiXhq+O98k4YY0GuWbpgykPELZv5RAI1oV4DBTUwYUsJ/XdzcpaPZM1Fj6Pg==
X-Received: by 2002:a2e:a54b:: with SMTP id e11mr1561313ljn.458.1616469036387;
        Mon, 22 Mar 2021 20:10:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f8:: with SMTP id v24ls4111002lfo.2.gmail; Mon, 22 Mar
 2021 20:10:35 -0700 (PDT)
X-Received: by 2002:ac2:5444:: with SMTP id d4mr1387762lfn.126.1616469035377;
        Mon, 22 Mar 2021 20:10:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616469035; cv=none;
        d=google.com; s=arc-20160816;
        b=muNGpVrEoN5/4/1VX4QE3AmLjXpSuCNDnjLtSs90SJ4YnlLDOwjiwjj2nT35iZpHE+
         JPJxunUfIR+usnV/cv3ZY7BD75PLKgsAyyhGEdHmnLjoKyEkG69zztoUcueqL8WnXxt/
         ulqP5ZjgiOq+NW2i08vvORLJ0pbNosEqNBlxX1yalZEtm19fuyuE2NbdYx93QbDaHr8c
         Zk2cGKGdFo8Yhc5tDFV5uktMSlfYTP5XKQMyjDYbNat6NYXkjuqGg2I8tdFDbu5rF/NB
         OjX850cnPn65dBk/oomDkI6AvAOMgtQY2ii+bpxfu1roqWalglKoLaKJoFyP138wCI30
         Sxwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ij2qTAkV9onciaXLQh2fELQAThocPd0dv9MVIWIx7vM=;
        b=v2q2dgnr+Wmx+zzmhOGk+ZqhrxwVeTweWk1EIyuPoZbdh2pCMhcEb8NEjyBG6wj1kQ
         7p81Qra4/V+8HYb32XicUmQtwW2sxr2FAOS2V/Gxk1KVmBJsuE5TGsNtOC0pozr+NHvk
         Pi1JOpeY5kCrjPDPKIUjygkkyCY20Q471z+GOnltGmUCtFl0kooKYHJOXAEE5RuE/bnC
         gCCBXM/i0nKEhxWqkB4jGszdt21mbp5HJRpvqjYO8gN/GCI/VZu62crmmEpObwywRvRb
         +0Rw+Aiphmdex5048R2f93JZvEvvBISko7ALtRu/3uVxiwSg3cCA1IIEfEHQALiaR2uD
         36Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+uMOdSR;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id f21si608105ljg.6.2021.03.22.20.10.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 20:10:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id 61so19198078wrm.12
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 20:10:35 -0700 (PDT)
X-Received: by 2002:a05:6000:1acd:: with SMTP id i13mr1545621wry.48.1616469034674;
 Mon, 22 Mar 2021 20:10:34 -0700 (PDT)
MIME-Version: 1.0
References: <20210310104139.679618-1-elver@google.com> <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
In-Reply-To: <YFiamKX+xYH2HJ4E@elver.google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Mar 2021 20:10:22 -0700
Message-ID: <CAP-5=fW8NnLFbnK8UwLuYFzkwk6Yjvxv=LdOpE8qgXbyL6=CCg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for remove_on_exec
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, viro@zeniv.linux.org.uk, 
	Arnd Bergmann <arnd@arndb.de>, christian@brauner.io, Dmitry Vyukov <dvyukov@google.com>, 
	jannh@google.com, axboe@kernel.dk, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>, 
	x86 <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Vince Weaver <vincent.weaver@maine.edu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r+uMOdSR;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Mar 22, 2021 at 6:24 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, Mar 10, 2021 at 11:41AM +0100, Marco Elver wrote:
> > Add kselftest to test that remove_on_exec removes inherited events from
> > child tasks.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> To make compatible with more recent libc, we'll need to fixup the tests
> with the below.
>
> Also, I've seen that tools/perf/tests exists, however it seems to be
> primarily about perf-tool related tests. Is this correct?
>
> I'd propose to keep these purely kernel ABI related tests separate, and
> that way we can also make use of the kselftests framework which will
> also integrate into various CI systems such as kernelci.org.

Perhaps there is a way to have both? Having the perf tool spot an
errant kernel feels like a feature. There are also
tools/lib/perf/tests and Vince Weaver's tests [1]. It is possible to
run standalone tests from within perf test by having them be executed
by a shell test.

Thanks,
Ian

[1] https://github.com/deater/perf_event_tests

> Thanks,
> -- Marco
>
> ------ >8 ------
>
> diff --git a/tools/testing/selftests/perf_events/remove_on_exec.c b/tools/testing/selftests/perf_events/remove_on_exec.c
> index e176b3a74d55..f89d0cfdb81e 100644
> --- a/tools/testing/selftests/perf_events/remove_on_exec.c
> +++ b/tools/testing/selftests/perf_events/remove_on_exec.c
> @@ -13,6 +13,11 @@
>  #define __have_siginfo_t 1
>  #define __have_sigval_t 1
>  #define __have_sigevent_t 1
> +#define __siginfo_t_defined
> +#define __sigval_t_defined
> +#define __sigevent_t_defined
> +#define _BITS_SIGINFO_CONSTS_H 1
> +#define _BITS_SIGEVENT_CONSTS_H 1
>
>  #include <linux/perf_event.h>
>  #include <pthread.h>
> diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
> index 7ebb9bb34c2e..b9a7d4b64b3c 100644
> --- a/tools/testing/selftests/perf_events/sigtrap_threads.c
> +++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
> @@ -13,6 +13,11 @@
>  #define __have_siginfo_t 1
>  #define __have_sigval_t 1
>  #define __have_sigevent_t 1
> +#define __siginfo_t_defined
> +#define __sigval_t_defined
> +#define __sigevent_t_defined
> +#define _BITS_SIGINFO_CONSTS_H 1
> +#define _BITS_SIGEVENT_CONSTS_H 1
>
>  #include <linux/hw_breakpoint.h>
>  #include <linux/perf_event.h>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfW8NnLFbnK8UwLuYFzkwk6Yjvxv%3DLdOpE8qgXbyL6%3DCCg%40mail.gmail.com.
