Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55VRCBQMGQELIPK6TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D395E34D6EC
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:22:48 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 8sf10060140otj.11
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:22:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042167; cv=pass;
        d=google.com; s=arc-20160816;
        b=dM7S9zHEfsJq/s7tJUjCirszVsRbtqB1XiG2DcpLZYKhGXf4wKZPGLw/Ci/rHoeJYL
         dLArfUBof0iD8Ir2iw2y9MCdIafZnCJxbiO6quw3j0YaUHshaVCNRez/7z1EXXZ0XqBy
         n0cB8hdizJbW+uEvOb/vu0h/NJLWjIOKqgxM05VrcOqTsnlBvjZF1JJOUmeTqMAbUjuN
         xDR+XjQsc6KITK3CIX3nqBF8biA9ASI6EF0uQjbF7Duqcbh0BfAwiNlijWNOfs/c/pxC
         Gu6/xnbePQYWfUZ/CA/wvkgEvuLG3E+GBUibVB5CAGmaUUq2e+ijc/k9vS7HwBEBt2ox
         8Q0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CDhsDzyUmTRJRp8tcGUMdDQedlAmVuPxYw4qvPiKfus=;
        b=hL4O+yfqJvK1RpJQ5wWTxOc5NI9HcpjsKm0vU1YyWY7uGvuZnCpF/zXahkPuORyrVJ
         Nz93vXhbyRxP/2GuBWG32M3V20MCZN9N76hRJmdZUf3q4qSnxofLFYrtDHZj+YAhbKab
         RQXEc5n3ipE0Sq438Hxg/AqWNHoLwX9RU39tmNz70UGmMIasU4dzRCOgnWFGMPN/P1e0
         fhRkDMMcMbE72Up/xHuiRqTkau5HBhOaRCNNtEnOBVgGhn7+RqvNLZnLnMtISCapFEhT
         j57KiEqA90gZiPIoxOGyUYuAylRddTxWKKdVwoTXfbzhVI3NhdMN9967HeVutjwmb6qr
         LrrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ihmdOem+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CDhsDzyUmTRJRp8tcGUMdDQedlAmVuPxYw4qvPiKfus=;
        b=UvMjsxfxoA6jYhYTABh+Lg/hdhCjJBy+uebIyo77JYNFS0pQYrPoJ5DhII4UOgVxSE
         cpaNwTHZmFU8s6eU60rj6NoAHQcS6bgpbbMaq/u72uZRH2ZBW5lpAQsiIzVlRJh1zsHD
         NXaLB6y38ReLfe4/mRJ+leFGWNAuISj8ChzWv8eV8hFupJmGukex+7ZOTvpiBs6O24VC
         kHttJfrM1q3Jc6odvmZFnMpGsd1dkSxVPojuKh6XsXnd+yCmaLn+fKHnwMpeZm8x/0c8
         yi9H3u21spkRqGfni4Q3QsyJbGETDiQIibvMNumobcL6OBVPBApXntBxl70ILv9V3zQD
         MrwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CDhsDzyUmTRJRp8tcGUMdDQedlAmVuPxYw4qvPiKfus=;
        b=GBo6TuG65waKxO/iMcWWxCTrR//jhF6a+rCSkifMhUO9TtkcxV4KXlPAfVkpOQmHwn
         kDU1c4+5cB8Rb00LSwaI+D55yAci4j+TUPVw+86JMo6nwq2bj6nM+Mfz8vY7w1EVD42l
         27LiNjdxLg+PLD1ykbXEvpRiCwf6k+BSOo75OPIpg301J+NYz0HYNtlPVXQuDtAScsZU
         oL8nl5fwM+xEfXTksB4ze2VPcB+Ry3t02yVcmUa3VKg/PtNLed86HILkZQLlTcWU5FeE
         jcF8+AAo6ZcmY7yF29BWORJz2L0QOjnWlQet6Y0SJ1eaF2l2dyeuhV+Lpv0WjdaoY+lk
         tKeA==
X-Gm-Message-State: AOAM530Hc9mnfp355WWo30lyFV1HL7WGxLdGKjlduSXbf8tZQ3g4D7r2
	dX/EGhCNLjYRhB/aVGgz1pc=
X-Google-Smtp-Source: ABdhPJy/H0CNJRIEeQImR9NvK1+UbrsboLGnXytXS/fNR1TQUlKP0UPUOInZJggUHeJV2gAMfH8Jlw==
X-Received: by 2002:a9d:2f24:: with SMTP id h33mr24744169otb.128.1617042167560;
        Mon, 29 Mar 2021 11:22:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d54d:: with SMTP id m74ls3959657oig.11.gmail; Mon, 29
 Mar 2021 11:22:47 -0700 (PDT)
X-Received: by 2002:aca:5fc2:: with SMTP id t185mr338961oib.64.1617042167196;
        Mon, 29 Mar 2021 11:22:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042167; cv=none;
        d=google.com; s=arc-20160816;
        b=kQBhhhwMZmjaVw/u5ndrSWE6xteaKmqjnVJSWJtJ2S9WrNfQl3o9A0qqzVptQaC7Cb
         8nQ0bWJJfUAskKiRemr9TKGe2d0Dvf/ARbpmSzoZK/Xoj86r52J/tXGj/WusLJDoMsAR
         vVmMlptJJvO2CTTlzUltISV8ySO2gTv6V8gavnUQqDhySD/pr45NuydnXTp5I1W/Lefz
         SPNOahTv8688i8ga3Gh/gaR5DPHY0kOv+HbA5Yh3EsOkAUqbshSLpj/nCklT/z9cW64G
         gxsxM1Iq9Ba+VqRAh1IrzPuzT/C4JV3I5XgT8U3P4lOb5862buhVWVt/JEMzILFP0sPB
         bNxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P+4V7kdgmOSoM2q5m0q378E9m02rDEI4zRk0CO5JIEk=;
        b=0esZ8Pj4USspQoLb6U7l4p1eXX2KHYA8z7BohrFxM7O2h59TVLK28VGZ5zWPXAVPaU
         otoc/UYr3XwLGkZp4CCSAN4eIuEC0B8QJTO3w0MNf+hrUO4kT9ummNueMOkZfygKeDS1
         OiR6+2cWAMIqckc++/BDYF0u6HKX8foBBP1uB/UrtCw1uVT8lI4yGMQzxQ53E+fltzyX
         JSV4uzlJqK75K/j626w3TogzhWL64CIvXMg+/6gACb62VFGFiHJsaJzGL9u4MqOr1SOr
         D+BwmGcE9KnUM4X9OGXf4YFkkou8MtgS6Ae/tyAPmbUE0VXl6Yk+9RGXCuJRu801Cxza
         czAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ihmdOem+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id w16si1721748oov.0.2021.03.29.11.22.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 11:22:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id 31-20020a9d00220000b02901b64b9b50b1so13159442ota.9
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 11:22:47 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr24623928otq.251.1617042166749;
 Mon, 29 Mar 2021 11:22:46 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com> <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <20210329142705.GA24849@redhat.com>
In-Reply-To: <20210329142705.GA24849@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 20:22:34 +0200
Message-ID: <CANpmjNN=dpMmanU1mzigUscZQ6_Bx6u4u5mS4Ukhy0PTiexgDA@mail.gmail.com>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
To: Oleg Nesterov <oleg@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Jiri Olsa <jolsa@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ihmdOem+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Mon, 29 Mar 2021 at 16:27, Oleg Nesterov <oleg@redhat.com> wrote:
> On 03/29, Peter Zijlstra wrote:
> >
> > On Thu, Mar 25, 2021 at 09:14:39AM +0100, Marco Elver wrote:
> > > @@ -6395,6 +6395,13 @@ static void perf_sigtrap(struct perf_event *event)
> > >  {
> > >     struct kernel_siginfo info;
> > >
> > > +   /*
> > > +    * This irq_work can race with an exiting task; bail out if sighand has
> > > +    * already been released in release_task().
> > > +    */
> > > +   if (!current->sighand)
> > > +           return;
>
> This is racy. If "current" has already passed exit_notify(), current->parent
> can do release_task() and destroy current->sighand right after the check.
>
> > Urgh.. I'm not entirely sure that check is correct, but I always forget
> > the rules with signal. It could be we ought to be testing PF_EXISTING
> > instead.
>
> Agreed, PF_EXISTING check makes more sense in any case, the exiting task
> can't receive the signal anyway.

So, per off-list discussion, it appears that I should ask to clarify:
PF_EXISTING or PF_EXITING?

It appears that PF_EXISTING is what's being suggested, whereas it has
not been mentioned anywhere, nor are its semantics clear. If it is not
simply the negation of PF_EXITING, what are its semantics? And why do
we need it in the case here (instead of something else that already
exists)?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%3DdpMmanU1mzigUscZQ6_Bx6u4u5mS4Ukhy0PTiexgDA%40mail.gmail.com.
