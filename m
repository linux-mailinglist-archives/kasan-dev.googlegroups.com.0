Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDOCWO4QMGQE3EEAHVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E8589C0A53
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:47:27 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e293150c2c6sf2206604276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:47:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730994446; cv=pass;
        d=google.com; s=arc-20240605;
        b=a7+3Q4n3TWBUYf+Of+GZPJUIAY3qIS7hltimj3qveHBmywS8vzz+9gvDjVeC0iRBcB
         BLNzUi7EmVesrKh/lzLEpJ9uPL95//T1jZ9mFFgm+FYniwFA6aSgMV5A1rIqKRsm4Ll7
         94K8btyKm2xd+5npvqchq+fmJMB/Wpy1TooW+L45+FnnVmxHbEqF0pETrmV2PPwvhmww
         Xf0qj2rmEeOKjon0CJkusn1rP2x3M6TMfsWdQIM6O8vR4T/8EHIUU0p9hqE8TK0HYH7L
         vvOO9pLtrLtfx3OXDUEhouCTLI93KzCla2Or0EZLK+9FY+wuksNTjo2ECZCs2XLAg1J7
         T2Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xIlFbU1M52o/e/sxG2yElOrGDVr5OkmyGct6oqOrA9Q=;
        fh=GFGLICC1vmEl4JWTpVR806YtGcFbQmP7ovfezDR2jo0=;
        b=eZSCYscZtkijRqpbmAnvZC6yEjehnS9IZlTB7DYiGNHrJL8ujqFdqqRDvbFGy+xA+w
         4hrAggtr08irmAkqfxg2kBF3/vQgM/n3LhygTo1php/6PwEfJER6PRqPoU/gBfIrziKG
         hg92keZBNvcg/aQlNhCEAn37hS85IiSaDwRLVv94zPa8U9X8dFoBxfvHl8xuXkuqM5Nc
         wbTHVsNyI3TE83ISzghdseLsMnVINwbXEctw2Dp9pebsKHFSawlzC8jz4ZpEjvxKy/R9
         pqEa07dws3kt2Wa4j9Hq69Y5oDo8JHSU2zzuJPmWJJ4Pq8z0+6nL+3KtSK8Wqb5wfVSy
         4ynQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ELCLjKg5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730994446; x=1731599246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xIlFbU1M52o/e/sxG2yElOrGDVr5OkmyGct6oqOrA9Q=;
        b=W4g8u9x5QRt3EfGYocVg5WWZXGVkne6VbICo5ZKDgFdS6EUIdVZPRsuczNkAJ+AplE
         fO9adhvynoZnkt3oM3xwnmPtfA2oHOm0no0C7D8O7WOxgtVd0YuDn++ZprBIIP6OG1zv
         s43/1UJG3V16TbziWF4McE+gOntzaAUCyL6NXcVXQlELc7/eOnaUtob7FbbYWVN5tcBJ
         Cdx2wL5W9uAtSwbGkWQtyuncQdL/WB/VaLMeN/2m8gkQmV2+qSyXZYqQr9wtOGEZXF9K
         5Y6VkMpsRNHpke19+nB6tzYprWzmME4IqDasYrNtjC21yHRkGnfbLeyDZ7taLOROiv+r
         /JDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730994446; x=1731599246;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xIlFbU1M52o/e/sxG2yElOrGDVr5OkmyGct6oqOrA9Q=;
        b=n5VwoLgrPo8pkGr1Zzzs14x017jcHMo427AMH2It+lEflkObrQpkGjhJtyhx4XsgER
         DvZXpb2oBsXK33Ue0rtkOHb7RHBCFR3fENRKG46nk0bpiew5h3HFFeTw8dTTMuKBvAQj
         AZe54hZdTHeNd58kQfGSikf9suUu3InF/4E4C/ghgdFHCs7DVK4YiwlqHF9jPm21GzK3
         43ELIN4Cgw0wQzKAVBalH3kq3QmilnzIUAcYYE02aI3oJ8GV3zJbiXVzwwAED3FZ8Kz7
         ivpDJw/W6k4vFG/0TPrkLDa+osgd4UBzsbrWatfiWQGEgd/BNQekCKFeZBriyJP+9cK1
         DEvA==
X-Forwarded-Encrypted: i=2; AJvYcCUeFQi9VS7wixcYlNMJ7oMZ0RKMBduCqd6WixJuMZypl0PRWI9uy1/0RP3wW/iSpM/JzdfhKg==@lfdr.de
X-Gm-Message-State: AOJu0YxNFYAKhROy52sL9Acac9R5LVL74WonIUcx8sfltHplApEmd5ge
	K0YDegieTZtBktISxCjvghSIownBZ39IFi1oCde0j74WmrIPe7Kx
X-Google-Smtp-Source: AGHT+IG/rHJsx12zHBRfLVBM8AlJXilOc4dRBKk5kJ6krHKA6UOUMM5ZACazKt08OgtLUb+28cBuQQ==
X-Received: by 2002:a05:6902:168a:b0:e2b:dcb6:ffa1 with SMTP id 3f1490d57ef6-e337d16731cmr483224276.40.1730994446150;
        Thu, 07 Nov 2024 07:47:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:181e:b0:e30:84f1:999f with SMTP id
 3f1490d57ef6-e336800eb33ls1422091276.0.-pod-prod-02-us; Thu, 07 Nov 2024
 07:47:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHQUKmkJvdloZ2V1176wWh0zOMmomoAvZuUh7HY1Gr3Tx/ZGJ/Cre0JHKRKxfOF8Qxfzc1DAR1vi4=@googlegroups.com
X-Received: by 2002:a05:690c:6d0a:b0:6e3:d97e:848 with SMTP id 00721157ae682-6eadae3082bmr6734157b3.10.1730994445303;
        Thu, 07 Nov 2024 07:47:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730994445; cv=none;
        d=google.com; s=arc-20240605;
        b=i2KpRNXc88Vl0cL36qNvOpbA36ARb7uHRYXOBMfS4NDLSucgwb4vVBZAkYEbZCssCr
         6dCPs9KSoo02utamsLVu8WTFYqRkT0kkWHaTs0EmEDyolIU1LXJL4f5NtWeIGEgFqmck
         tdITHms1SUVQX04S9D/eXIUMm3yk3Ok+sObFQmppKXlgfnPzGI/gOjhCrVzEv3BGwl+1
         NYkm2Ve/T8Iu8EjQKRXsHPlKiD+J/RMzKTASIrxEE1JdukX291Aar3L7tWVLb+4HbFAN
         Ky+w3yl7iwkT1AYeDr+LWVMUPcmigMl3TAt/RMS9JNsiNHg6btlZQ56r8rSHMvVFsH+6
         GbOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TKCS6QZhEemyijFYjDdqN6Pf7qMYs//016N4dS3FzLY=;
        fh=JLCmWsWNc8MPQFPGGjzpZfLNAmc6fjOg/Uq0bFXbXi4=;
        b=ADLcSOsGO7KJjzME0PwPWV/AWGcTftfTg6MO0uiQdBt8fASno7U2NUd1RjRDgaYKvG
         YaPzVcAa3Ze0xeoru8muRHa/rdNoprbsAIYoRAT9iLJrFrer4cXKUNlLo1kc39BQgzZD
         rvoXWmzsF5Z7xBpcdtCoLL+Tefoqf9aYlKv0afM27kcw+tM4HCjnze0S87bNxny+vdZk
         pzRJOhFM6JiQjjzB4ZpyHUjOQ8XDlWelLzLCp5IOJ8mTyl4cS7x4hOYLLL3evGzY1YL8
         pOjPKG+n4Uza0ciGaA5wz8W3P3kpIWfIwX6IQYqZ98jdzLOGlVfF/BKqUPtmxJmwo3Um
         OXUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ELCLjKg5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6eace7a5e39si1001927b3.0.2024.11.07.07.47.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Nov 2024 07:47:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2e2a999b287so919823a91.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Nov 2024 07:47:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXWpJqjd9Xwr6dwK2JlFbpEwPlBwO/zQA9Zw27oCIusFuHZwD6kBSpMOPBaOE1YjF1Rz4Rb9U5BYCo=@googlegroups.com
X-Received: by 2002:a17:90a:e7cb:b0:2e2:d239:84be with SMTP id
 98e67ed59e1d1-2e9afbd3c7cmr532113a91.5.1730994444041; Thu, 07 Nov 2024
 07:47:24 -0800 (PST)
MIME-Version: 1.0
References: <20241107122648.2504368-1-elver@google.com> <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
In-Reply-To: <5b7defe4-09db-491e-b2fb-3fb6379dc452@efficios.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Nov 2024 16:46:47 +0100
Message-ID: <CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] tracing: Add task_prctl_unknown tracepoint
To: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Kees Cook <keescook@chromium.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Oleg Nesterov <oleg@redhat.com>, linux-kernel@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ELCLjKg5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 7 Nov 2024 at 16:45, Mathieu Desnoyers
<mathieu.desnoyers@efficios.com> wrote:
>
> On 2024-11-07 07:25, Marco Elver wrote:
> > prctl() is a complex syscall which multiplexes its functionality based
> > on a large set of PR_* options. Currently we count 64 such options. The
> > return value of unknown options is -EINVAL, and doesn't distinguish from
> > known options that were passed invalid args that also return -EINVAL.
> >
> > To understand if programs are attempting to use prctl() options not yet
> > available on the running kernel, provide the task_prctl_unknown
> > tracepoint.
> >
> > Note, this tracepoint is in an unlikely cold path, and would therefore
> > be suitable for continuous monitoring (e.g. via perf_event_open).
> >
> > While the above is likely the simplest usecase, additionally this
> > tracepoint can help unlock some testing scenarios (where probing
> > sys_enter or sys_exit causes undesirable performance overheads):
> >
> >    a. unprivileged triggering of a test module: test modules may register a
> >       probe to be called back on task_prctl_unknown, and pick a very large
> >       unknown prctl() option upon which they perform a test function for an
> >       unprivileged user;
> >
> >    b. unprivileged triggering of an eBPF program function: similar
> >       as idea (a).
> >
> > Example trace_pipe output:
> >
> >    test-484     [000] .....   631.748104: task_prctl_unknown: comm=test option=1234 arg2=101 arg3=102 arg4=103 arg5=104
> >
>
> My concern is that we start adding tons of special-case
> tracepoints to the implementation of system calls which
> are redundant with the sys_enter/exit tracepoints.
>
> Why favor this approach rather than hooking on sys_enter/exit ?

It's __extremely__ expensive when deployed at scale. See note in
commit description above.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPWLOfXBMYV0_Eon6NgKPyDorTxwS4b67ZKz7hyz5i13A%40mail.gmail.com.
