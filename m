Return-Path: <kasan-dev+bncBC7OBJGL2MHBB76JQ6BQMGQEIRTDVGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C3FB34D268
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 16:32:32 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id t1sf19344320ybq.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 07:32:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617028351; cv=pass;
        d=google.com; s=arc-20160816;
        b=PMdBnpuwFcx449T4wzIH4wen/mAbtnY49BVt6GpbHPJPOq6zXmInHcGZ91Pj4BnU8r
         g6H6uDfUUQyNvoNi617FZ0uUOnCIuNWys4OQdawDdLBaxFis4iumFzOMHVaHMYBPAlpM
         ae0aogQ9tN7nuQVs1AbdS7wVPF3coPozaepV8cGowidqqI92/Kx7/CUiEi1Oluov/gCO
         V9TePekgqgpmWsfiamL2izK6m634rjWUy7ZjdMMAuwJeNs9fZCclh2lC5/FG8J2AWhm1
         /2Q+Ad21ZLVAkndf81Oy1IQrE7qk5nsCxafX3T5SjZk2nkodTTiliFYpFcoQi3jBn0Jh
         DyAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IG4A9iH3dbx06cNHA29oPyLzuP7mORD/O0UvGjuLeqo=;
        b=QeGGaWGANH/cVmgEt2IvCQtn89/nao6CtzTk1nSBuU7UllksOI49Ldq7x/W1kVQyqU
         Zxb95HF4kkHkrs0qhrIHnU2aLDwMMx74CXZIed0V02Wp5gTMzuqgM2z0eRJJAyHi8NDE
         kBkWJfM5DvLXvAh2RT+oP9xNy0sO/fSiyZNrMznSiIEFLVbaoioBUEbXVN3doUixyj6q
         9diob/5o1I3XkYDifQXEKyXArWgOsEGQHnX61GWKdVkFO2A5rXqbyPbP8hjRGrMIDL6r
         Zaekein6XmuTFv8cM3GkgHJjfRubWsRndsqMRWkPzgJTXTwICZi7rfAHZ85iPj2Jdm6Z
         pv+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WOGPfNiB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IG4A9iH3dbx06cNHA29oPyLzuP7mORD/O0UvGjuLeqo=;
        b=WJ5NmXVH8yE/XXj1CwDfg27XG+BaMy8M7YcwIuSxZ/LqigtDHgs/WtxURiTI4EKzA3
         q03G7xzkYL2FILMdd0dMiZJ8T4C8VR7H79QXPnjKbrJIIsMuakF/dNBwPm9/Hy8zCgmw
         d0fIKxHfTxPcvVeTxIuB6+XLqui8OXsQLjKq0tODOce5HeQuHgd8uQgcNPouBEsjvqc+
         Sca9MZ+O3OoQK67kO6iztghfR51N2bnhh4LQQC5J7XFxTfH6wFiLF8RJ24EgvOnM8KRt
         Z3GH9GV7kDRJpTNAUWbQ/5XmVhvJTNtZFzaK3fU3h4zYcRpJrpMvcgpOm3MRTmwzShHU
         AB5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IG4A9iH3dbx06cNHA29oPyLzuP7mORD/O0UvGjuLeqo=;
        b=hhxgsnxY3fRW5hwpWs8Z0bLAHRw/rbzf/o8BCYvtoBMmj7l9lpqVoMHbqM/683eCO9
         9oYP8oDr0iYJSnwv5rPdzSNtUbYxiVQ2qRUsyy3XwgCzG0JLp3MQemtPayQbsndXHj9z
         n+zoEGSg2+UL82g3ffgSYbxsK/A/eIEqF030PAk6QvhpXRKtm0ANMGZD0UVHMe8Iiqi5
         9ahMUrrgVrzvOUcY+FimXWKhW9Gad6mv52MR+OrVwqg6xbDZUVEQirTvhmppQWnwZW97
         /2x7sSihO2ce2YqtcaZSpv9vUZKRZIO7torbpY9aAV6emZWHj9OBK9tfeXzxME9Ad8FY
         rirA==
X-Gm-Message-State: AOAM532COb4fdDHBn8Zk43BEBVu+4NhDtUAvKCTi2K5eMFJYAFnanSox
	+OLehLY+8HY3N90aHb0NUEw=
X-Google-Smtp-Source: ABdhPJwF+OflslE6KjF8CesBjAKVUHxZHgKLuXMcXhm1pfLiuJRh2GObqLqtCQ5T8NM93Ykx5zSlSQ==
X-Received: by 2002:a25:4c89:: with SMTP id z131mr40147987yba.40.1617028351423;
        Mon, 29 Mar 2021 07:32:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:fc23:: with SMTP id v35ls5086502ybd.4.gmail; Mon, 29 Mar
 2021 07:32:31 -0700 (PDT)
X-Received: by 2002:a25:2682:: with SMTP id m124mr40398503ybm.410.1617028350988;
        Mon, 29 Mar 2021 07:32:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617028350; cv=none;
        d=google.com; s=arc-20160816;
        b=qE7IbrA53Rk1BNSBrbQh70mDMmUbYHvLuBBSD1JQeAdmV+2Rya9NNr33ffCv7IhR4V
         ZvLtn1rm3ZyPn8ZLAUAXmdSLTA+tZnUXRN75/TU/1cQBfFOzx36P6jAJKDi3jY/zP60N
         ksKu7f8mTxZCOuu/C3kNWI3inYxYdrF01ggYGEeG8X2fAPtgTz0h3F6E49BADD8Cyyxb
         8lYt/1XNLnnCiF9rxx0Rno0NvZxpVMDwgnbh3oyAdegwJeJIdSZuunsQnxzeUP96NnbN
         W1SDvcMQNJxbjquHroSCKTWKV+YiqoZpZAAhkJ1z3UOnigJd7UkCRwVUEVj+rFFm4os1
         9ufg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6pd5+1lyxF0IpfUFm+C/Q0BotbJ7mj/8xSGsdykFryU=;
        b=pq/Z0qGOUD2UfFGm1ngSWrgttfO7OkTbbARlG7FRHENmukF6BCUn4SCa0W2E2EJTkc
         eNcmaGa0ZqcYoxFoGMRjdvwy8He9K4hYA6UoUMfOIuu7fw+KZUF8VDRljcCYE5l5wBwR
         sVkEZvL+DvDImtHJZEGoFIHQ6vrX0fAqquM5D3dBGUJk05UlJWs+U0R1kpgqf6yp4Pn5
         uWAFEOFAYwNc1Hq8D6TBtUcSoL+FQzB9+yR3V3iOPl0aR7Sdh5HowyB42yviBlPHfOKL
         gQU95OjDD05O4EkeMzmwl+TY2h4TizfwNlNyOn0qewIdc2L4VWNFQi1PuFEj5JSXkBNp
         HXyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WOGPfNiB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id s18si908284ybk.5.2021.03.29.07.32.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 07:32:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id 31-20020a9d00220000b02901b64b9b50b1so12438608ota.9
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 07:32:30 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr23773028otq.251.1617028350375;
 Mon, 29 Mar 2021 07:32:30 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com> <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
 <20210329142705.GA24849@redhat.com>
In-Reply-To: <20210329142705.GA24849@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 16:32:18 +0200
Message-ID: <CANpmjNN4kiGiuSSm2g0empgKo3DW-UJ=eNDB6sv1bpypD13vqQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=WOGPfNiB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

Thanks for confirming. I'll switch to just checking PF_EXITING
(PF_EXISTING does not exist :-)).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4kiGiuSSm2g0empgKo3DW-UJ%3DeNDB6sv1bpypD13vqQ%40mail.gmail.com.
