Return-Path: <kasan-dev+bncBD7LZ45K3ECBBUG36KBAMGQECCV3E5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF8633495B1
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 16:35:44 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id s17sf3211323ljs.19
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 08:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616686544; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfSdyFJXJHwyZ2yjhwIccXwNYDTbDO6CUPy6OUtYfqtl+Om0alr/9/3wja+4dCG6lo
         X0XesNBP1waUCxT66uH4tAMlZSNDg1ktC3RRH7hJGHnYAPVlZGzbriUGJqRAwnf+lKen
         0EAn5FlvkbfB9AaMUKv5sx84NTMtV4+ci5YZ/IVx53V7tQUocEYensE2tn+oN0Z+b9h0
         AsP6WqTQ3l1/HFLMfsvbdOSNzifiuQn+/msP5Tjz25pZUSSZCDEawM5QN8PvqUMYjrcL
         VDtbxkJGewkQonZa0kyZPaDiW9hj4S441qQQkC/06UbpeVY99AtsZUXSsnFlbZQU4aA6
         uHug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qFQs5fVHPz80O6NYz6IMgcge3rZjiKt2OeZL4U5srQc=;
        b=LoaKv+4JzulAFH2a/lJ68/+Ot3+pinM2cYGIn96DZk8xx05ZWNu6s4axPb5vmG736t
         wOLo5nOiQMAUOhpIbPEMnhmGtElR85rk/CYwwmPvVVWfMqlfP9yOAxL13d5fWoi6d3Gr
         bPNNN4sbHJMLlvd5crnS7+kNEGLuYefk2Rpe2o5cpDL23ZClJmFIfE3b7YytFSBa4Ule
         ej8RFgL5ezakZYb6qtCp/KQvLUmh75n3PNk/yHNTLEuFMyV18H1E5uDfdJaUIoyq0Aqd
         vMxAsTxMdJzGhD5TZCHqw+7motwqkDipJBtmlCYAT5EqHVL1k2YlE2LsdFT0gVDZRUfe
         hTgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vReFbpzU;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qFQs5fVHPz80O6NYz6IMgcge3rZjiKt2OeZL4U5srQc=;
        b=Oh3V6GhBcL9PJuEOYvJWlg01I5NCLM4xggTbUNPRNNMR4O6ib9h3zBE4DqJbdWpXgw
         cW4CT8nopXkpATnArktVHf2IzNpiWo20CbTfkCihaqeHAxDVStxCnlRY9ZomoQKtu0I6
         p6vIsdmfX8skIn2W++JG9DUm84N8n8OXUwIn8S4vbyYy5r/rtwxgnW8USC8Jo4k7JQT3
         O92FT9nKpHfLo5PxTgRGC5qWJgfItda1Et0D+1VTA72AyrRtXm23em+Z2yWn3kONTJR0
         cVsJ9rkLMVUnq/APc6kjQexip0+dUMyutZ3j59Typ0tc7tVG+Rr4lImElUGPLI26DuwS
         TbwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qFQs5fVHPz80O6NYz6IMgcge3rZjiKt2OeZL4U5srQc=;
        b=pDsrmUHnPbFQF2xu0eT22G6sVBDQtn4JrjbGyR1J0NqBrK6eMp+hxvryNoS/FfpwmJ
         Y1T+PxPAsXBtoxw3zGoX7ig+ToGWmXwnyIG0NHqROTCE2+QU/UpUHDKpV8DHGRxLG+b9
         JtGYlxYB4tqZHI4GiKVV2c4Ffz+aR4YMHFhntcPkwb8FbvnKS5EVQy4L9x+1+RN46+SA
         tvAXsvUxAW6qOa6zYlEgZbBkIW7EglLpSAbOpV6Barc5XbBRrg79FiiLmu4TozSGYsvg
         FzpWiBp+Sv4mJUzuK4ouCPIB2QruNQCgflC8wwCi53RkLk0POnxBY7yA/+o0BSpZnr1g
         Ha1Q==
X-Gm-Message-State: AOAM530Co9waAaWXKGCysBxK7rGr7ocQwmssqVNLFGT6yuJsjvVtFE2q
	KrhGgIycyUIKWrnvQMtWY/o=
X-Google-Smtp-Source: ABdhPJwgZnGB9rVzhz2ErZH8B+Bt6o9Hs2iRtX64Vni3y/LFG8kSEOSr+1ZVZbalvhzLk9edEjPcHQ==
X-Received: by 2002:a2e:9908:: with SMTP id v8mr6273602lji.460.1616686544310;
        Thu, 25 Mar 2021 08:35:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a48:: with SMTP id k8ls1367266ljj.10.gmail; Thu, 25 Mar
 2021 08:35:43 -0700 (PDT)
X-Received: by 2002:a2e:730b:: with SMTP id o11mr6018515ljc.221.1616686543021;
        Thu, 25 Mar 2021 08:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616686543; cv=none;
        d=google.com; s=arc-20160816;
        b=rj9IhXgOBcjfu13QE8LyXC7TbRAcrD8tlLr2SfCij9/gp3omJSIbjCvZGaqgT2z9jK
         KgK6Ur8axX1AeCGC3wmchT8Pv+q9TiidEwm8RQS+z95FnROBfN6frAhSB9UDTMpfSkEI
         jNiAoEboFhj4yxlKX7/HP8XoJYl0ibDJbxtk+0pLukWOa74vpvdhZD3eGbizZxezs1Jf
         PGdNSOKKCT8O2qQVyWtJR7Vx2cEzGAeIVLmMvGamdeUZ9Z05ydOX8F2164nGHxB4hTqN
         4C5hdhh27xIL70Ssielx1vwiQ3lbHTYYmdUsFFiZWY6rQMRdOIBzrKa4KoPrDuKvcqo8
         puaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=1QKElLhOfCduB4W2ZnttsXzaaUpOx3i5hzbEvc+SfaM=;
        b=q9v+/r+k1MKERNHOIijrs9Ss3lSht+9JVWJLtQToq3zip1Z954yE/uNUngZJGnq4kL
         +e3r51XGgCNreVtdJXkVikDfDmrbJXrjjRmOuN+uYt+Rd3z3HFehD8xmJsetduzrBr1I
         nn+UE289AHXHRtKVN8L4Eq0Mg9RnUcITujfQ/WZT8zmv3s558KW5+RWjTdE0RhvwYiR8
         5C+f8/CGgq/6/eV4WlUJE+qZSBWKCJps5pIgeatgB7VHANWOttZCUdMYOXaCjidsjh6z
         JvgvV9l3kGQ/H4LmhrM4uuwB3XqeAbAnGcFZ/B9A738EVJKkCxJIGYcAMWEM0qQewFvG
         0+Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vReFbpzU;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 63si214763lfd.1.2021.03.25.08.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 08:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id dm8so2921431edb.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 08:35:42 -0700 (PDT)
X-Received: by 2002:a05:6402:17d5:: with SMTP id s21mr9755769edy.65.1616686542501;
        Thu, 25 Mar 2021 08:35:42 -0700 (PDT)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id r19sm2868681edp.52.2021.03.25.08.35.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 08:35:41 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Thu, 25 Mar 2021 16:35:33 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <20210325153056.GA1895212@gmail.com>
References: <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
 <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net>
 <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net>
 <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
 <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com>
 <20210325141820.GA1456211@gmail.com>
 <CANpmjNNcYSGCC7587YzMzX1UpDvTA8ewAJRsKFdzQRdmWEO7Yw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNcYSGCC7587YzMzX1UpDvTA8ewAJRsKFdzQRdmWEO7Yw@mail.gmail.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vReFbpzU;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
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


* Marco Elver <elver@google.com> wrote:

> > Yeah, so why cannot we allocate enough space from the signal 
> > handler user-space stack and put the attr there, and point to it 
> > from sig_info?
> >
> > The idea would be to create a stable, per-signal snapshot of 
> > whatever the perf_attr state is at the moment the event happens 
> > and the signal is generated - which is roughly what user-space 
> > wants, right?
> 
> I certainly couldn't say how feasible this is. Is there 
> infrastructure in place to do this? Or do we have to introduce 
> support for stashing things on the signal stack?
> 
> From what we can tell, the most flexible option though appears to be 
> just some user settable opaque data in perf_event_attr, that is 
> copied to siginfo. It'd allow user space to store a pointer or a 
> hash/key, or just encode the relevant information it wants; but 
> could also go further, and add information beyond perf_event_attr, 
> such as things like a signal receiver filter (e.g. task ID or set of 
> threads which should process the signal etc.).
> 
> So if there's no strong objection to the additional field in 
> perf_event_attr, I think it'll give us the simplest and most 
> flexible option.

Sounds good to me - it's also probably measurably faster than copying 
the not-so-small-anymore perf_attr structure.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210325153056.GA1895212%40gmail.com.
