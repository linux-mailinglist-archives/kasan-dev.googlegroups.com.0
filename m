Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WV3WPAMGQEI7IU26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 35EF5680651
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 08:00:08 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id c2-20020a25a2c2000000b008016611ca77sf11895339ybn.9
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Jan 2023 23:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675062007; cv=pass;
        d=google.com; s=arc-20160816;
        b=WYfZi0smLjTxsOhZdcTJzWlov1OJ93yTnZCx4TAVlAxLDUHb/LtNyZpZVRYPf8j/Ot
         i5oKIhJ0d1HOQxTdYpxemtFls3gNprxumoKmAIE8KD2/jpyzNaTUV9FTSEDRULXoTh86
         cxmcGnpdq6yhCTxkJvpJB6k5aPUCt1zbMEfSsExkl4e/QATJCSSWD8zM9AaMMdrd23P6
         R+ori6l+NXp7ZkKYWawRNIT5qrM4g7kOKc78tIz68nWKuQL9sKQbX9ojppw4SIRsJA3x
         JxL5H7L0Iv8bzEGVnw/c56k4GFLNyXA2UeNNksyAJPU+iNck8DHFkN8eqf2Y9RnkUeYz
         Yp4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9FDFIiGP/0C0dhOgcdUz6nE/OpBAfX5Zh2DPyLz6ADQ=;
        b=RZEqty4jdn95yUJgbOCTi25h1CUrFTpfFy2JIRmyzirn3l/kOTqbT8s7zVWof3+VUA
         IOdO6HBXLaJP4Gh0Sf2I+yI339NQQJJQBj63N+BteXD4s6Apy9ga4ms43IEA+qifbvpn
         xYXSfLbqEN8X9DXtc5Egdd69ebkT4pgKmyEkg2f8tATm55HLGSpqDp5efYS23qg37yr9
         r4KMjcNzopnZGTixWvqGybIgAO+NkTmPMzIWiKP7uDpldHzOln7T0fV906L63KY8vmsM
         M8Tq0Y2MDVxuXYfIsIOWJbnmCjzndaOPkt3IMsAUvZwCQJqwu8MB9A2K+Rxc1ndi+zlK
         k+jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HL6O2If/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9FDFIiGP/0C0dhOgcdUz6nE/OpBAfX5Zh2DPyLz6ADQ=;
        b=HbC2r09bOPBh8DOWf9AzO2DJXKXrBWm5eTlibkSBtrbhbUpsPqbjNuVjex3dsdoEj/
         hsn68eJXhV5LA0nztJI76BYmw/yQLfjtsc1yl/FsgqTRdgZHsah54i0usufD8AX9GhUI
         U+n7FYekjcrJ3nGo5Npt/LuhKgmhRtYdORKnWGvQAjYJsGoddByinbULr0nApoMXKWWC
         WWdGvdVu+zCdLHOux1/+c1mTvLUJGopc4GgF3O+GPsHTD3a+CeS1/Eac2agNx0ShSa0v
         DlFXE4AFrqwNeRGsPr/pDazTutXDpP6OoQ68iyn9dkFr9Oh+rAwr6UhZpRmhnX4ryvky
         W/PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9FDFIiGP/0C0dhOgcdUz6nE/OpBAfX5Zh2DPyLz6ADQ=;
        b=SU+er1qwl0f0rwHMQsLIz1p0T6+cYFv09PTAbzRA5HSPiLOxpVg4Nn3vvVNO96hFRe
         MvEnTRVt5/X7jxikNpBitVIHYSJIjVskslM9Lk1BNrkXPUjIbM7fmXDi8YOWWQC33QSu
         GlDKN9W7i1+QfmCCHpsHkm8RKouVeDEia+bKWujpur4ZkZt1/IwlxHGKGIivANDJjHIG
         1v55QzgPIOurUoFQuxwJkz5TtQalBIPsZ5YVerjSgzjuGQjERyKI4kNbuFUIIlHuo3mR
         Qgliv+64jg8n+jWY8D8gbMPLXQDV3vjBYKHXrCXl4Kfiso6cvq30+UEN0ESKdVBHjMGZ
         PoXA==
X-Gm-Message-State: AO0yUKWloFp+5sgFHRzZqF/0XQfzF5K09wsxPw3V0GLYgsaI0Q9WlCG2
	F8lLO0qXH1HjqXM+ERiFWok=
X-Google-Smtp-Source: AK7set/FZ1LVt1AMXJX3dzw1NtmNIEEYTGmGqaZ6NqmziWqmCh8eaIQQAo39UGGea0fnZ3bG5NJbJg==
X-Received: by 2002:a25:3784:0:b0:80b:8514:e7c1 with SMTP id e126-20020a253784000000b0080b8514e7c1mr1767648yba.603.1675062006850;
        Sun, 29 Jan 2023 23:00:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:f541:0:b0:3fe:c52c:dd9a with SMTP id e62-20020a0df541000000b003fec52cdd9als7454123ywf.4.-pod-prod-gmail;
 Sun, 29 Jan 2023 23:00:06 -0800 (PST)
X-Received: by 2002:a0d:c507:0:b0:4ff:9dbf:35d0 with SMTP id h7-20020a0dc507000000b004ff9dbf35d0mr3797723ywd.12.1675062006097;
        Sun, 29 Jan 2023 23:00:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675062006; cv=none;
        d=google.com; s=arc-20160816;
        b=S9T0bIEQH8HN1e8picsM6F5zECkZXPe9RR6i4j4kuWZPWwS3MBVVlhMOULTTplT+R5
         VKxMAnfaaTJxB7JMljkA4edhq5RnrJipzzQFnONWsOtfujEkxpi2wRTUMu3seK3Atzw0
         zin/WOg3L2nDeLnodRcfBeOvCh20bPRNNAqHzbmSA8Vwg4X38HxfY85J5daD12aFV9Ui
         odLTe1mu13zpcqxdJSdjXvWBIU2A8DSLLsGt3vzXl7vByADaKqvFpKkGi/Ehgus1Cnao
         bMS/A+0J9CnIYnGKE0pMNJAdSGacFV0NkYRdUuXG9QgkJWCBCh4brnVLd2xTH4IDZx4m
         ediA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YevmuFxSkxWTJZuYLK3auP/ln6gsEkZmPuZuK5JXHz4=;
        b=bEw5ZDWsSErU2a0YkIC7o50XQ3yu7CJKg9IGuHgElihzh4bk6CCze/Ngz8TyIOOhww
         hJX1fNRifjRsmn8/ucUb7VvRDmUr8qVzJgfZ9daz6ALceZjvzPFQOMiMHFZHZQspHWsX
         iTSuD157dJ42czo8NfnjkxPBNLtFLFf6sIjJValm+ILb5Eu+kMqofC44LmLMag2YSzbS
         rgi27Uv9CscaN5Al3Et/wq8TBalEz/sJlfxe/GYwubJ5E6+c7kYMOd6nyN9K8ySvDkXY
         S7qpsVtFgNHqtvuyXcboTHo8zoxApGByGERoD8KYLT0sMYCuzATLJgWfn30/rENI1Dvc
         TyAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HL6O2If/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id g137-20020a81528f000000b004e0c0549c53si2437394ywb.2.2023.01.29.23.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Jan 2023 23:00:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id a9so12827305ybb.3
        for <kasan-dev@googlegroups.com>; Sun, 29 Jan 2023 23:00:06 -0800 (PST)
X-Received: by 2002:a5b:92:0:b0:80b:d161:ace9 with SMTP id b18-20020a5b0092000000b0080bd161ace9mr1690523ybp.143.1675062005661;
 Sun, 29 Jan 2023 23:00:05 -0800 (PST)
MIME-Version: 1.0
References: <20230127162409.2505312-1-elver@google.com> <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
In-Reply-To: <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Jan 2023 08:00:00 +0100
Message-ID: <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user addresses
To: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="HL6O2If/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Fri, 27 Jan 2023 at 19:14, Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Marco,
>
> Apologies for having not replies on v1...
>
> On Fri, Jan 27, 2023 at 05:24:09PM +0100, Marco Elver wrote:
> > Allow the creation of restricted breakpoint perf events that also fire
> > in the kernel (perf_event_attr::exclude_kernel=0), if:
> >
> >   1. No sample information is requested; samples may contain IPs,
> >      registers, or other information that may disclose kernel addresses.
> >
> >   2. The breakpoint (viz. data watchpoint) is on a user address.
>
> I think there's a potential problem here w.r.t. what constitutes a "user
> address". Below, the patch assumes that any address which access_ok() is happy
> with is a user address, but that's not always the case, and it's not
> necessarily always safe to allow watchpoints on such addresses.

Isn't that a deficiency with access_ok()?

https://www.kernel.org/doc/html/latest/core-api/mm-api.html#c.access_ok
"Checks if a pointer to a block of memory in user space is valid. [...]"

> For example, UEFI runtime services may live in low adddresses below
> TASK_SIZE_MAX, and there are times when we run code in an idmap (or other
> low-half mapping) when we cannot safely take an exception for things like idle,
> suspend, kexec, pagetable rewriting on arm64, etc.
>
> So I think this may introduce functional issues (e.g. a mechanism to crash the
> kernel) in addition to any potential information disclosure, and I would not
> want this to be generally available to unprivileged users.
>
> Most of those happen in kernel threads, but they can also happen in the context
> of user threads (e.g. if triggering suspend/idle via sysfs), so special care
> will be needed, as above.

These are good points.

> > The rules constrain the allowable perf events such that no sensitive
> > kernel information can be disclosed.
> >
> > Despite no explicit kernel information disclosure, the following
> > questions may need answers:
> >
> >  1. Q: Is obtaining information that the kernel accessed a particular
> >     user's known memory location revealing new information?
> >
> >     A: Given the kernel's user space ABI, there should be no "surprise
> >     accesses" to user space memory in the first place.
>
> I think that may be true for userspace, but not true for other transient
> mappings in the low half of the address space. Ignoring the functional concern
> above, for idmap'd code this would at least provide a mechanism to probe for
> the phyiscal address of that code (and by extension, reveal the phyiscal
> location of the entire kernel).

This again feels like a deficiency with access_ok(). Is there a better
primitive than access_ok(), or can we have something that gives us the
guarantee that whatever it says is "ok" is a userspace address?

> >  2. Q: Does causing breakpoints on user memory accesses by the kernel
> >     potentially impact timing in a sensitive way?
> >
> >     A: Since hardware breakpoints trigger regardless of the state of
> >     perf_event_attr::exclude_kernel, but are filtered in the perf
> >     subsystem, this possibility already exists independent of the
> >     proposed change.
>
> Hmm... arm64's HW breakpoints and watchpoints have HW privilege filters, so I'm
> not sure the above statement is generally/necessarily true.

Right, I can see this being a valid concern on those architectures
that do support HW privilege filters.

> > Motivation:  Data breakpoints on user addresses that also fire in the
> > kernel provide complete coverage to track and debug accesses, not just
> > in user space but also through the kernel. For example, tracking where
> > user space invokes syscalls with pointers to specific memory.
> >
> > Breakpoints can be used for more complex dynamic analysis, such as race
> > detection, memory-safety error detection, or data-flow analysis. Larger
> > deployment by linking such dynamic analysis into binaries in production
> > only becomes possible when no additional capabilities are required by
> > unprivileged users. To improve coverage, it should then also be possible
> > to enable breakpoints on user addresses that fire in the kernel with no
> > additional capabilities.
>
> I can understand the argument for watchpoints (modulo my concerns above), but
> there's no need to support instruction breakpoints, right? i.e. there's no
> legitimate reason for a user to want to monitor a given user address
> system-wide, regardless of what's running?
>
> IIUC this only makes sense for watchpoints, and only in the context of a given
> task.

Right, there shouldn't be a need for instruction breakpoints, the
kernel shouldn't be executing user code.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNGCf_NqS96iB%2BYLU1M%2BJSFy2tRRbuLfarkUchfesk2%3DA%40mail.gmail.com.
