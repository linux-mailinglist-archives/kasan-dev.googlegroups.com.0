Return-Path: <kasan-dev+bncBDV37XP3XYDRB6F732PAMGQECHS5FQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 27616680B28
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 11:46:17 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id l23-20020a7bc457000000b003db0cb8e543sf4182612wmi.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 02:46:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675075576; cv=pass;
        d=google.com; s=arc-20160816;
        b=E36GU3YKF/3Nar0aF9cYjSdbZi4IF/zdd1KLCqltapGZARR66zxzmiH4y3tn2xLlDh
         c+Vt66OcwHO0qh/PqJRTL/vAIHIFPSkv4euF2ev9J/Irvowa9dZN4Aq92rkQLF2BO4AS
         ZvTCsxo8fdTeVM6P3Y04TlvtfH+ATLXjfuKF4MrkXo9P8p+U5Vpwde7iTs5gFimjLkWp
         X/+cyPdiehqoyTCi0k5TzlcR3M2GobF73MkDhdn8f1WKVhw0hK3BA25hafydLznwcdLP
         3VXI5oz/CvUaZDaflZbcGBQONRFow8HmHLgt9b7q244ew0RJ2k//1Vo/fAvVfCb1+YQN
         iU7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+CmRtrUDMjvlwKzA4rrqZ/kLB14RTVxYwtsz90fnDpM=;
        b=BbZOnU2scxpAhIyqrX4a45htfBbUanQczTw6Vos3Awhay9+1GUHj91mdcCcNCKNzxU
         qjk5pEIS6MF7X3Q3v2lEn6UyHiXr8C7hCGEmBO5N91oOd2S0U7zyN0SUlyyPpXZ3kw/P
         SUySLQ9QKFc43ZkBM6ikHjjwGioe7G5hUo2rAgvK+H5bYYWmkxv9FdNcz7napXta2ASG
         Ri/6JihAQzsEfKSt2z5fALoYc1N1kdM59YJuWfJk0b+LqOXEqUy+805K+Rra+lwtho+I
         0cQkLHr2uN+hp8SDL7jbN8JVVVbxvE9Ntnz1q6MC+iXK1nkwUbVn8dm9UaAQlek2tM8M
         ZrNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+CmRtrUDMjvlwKzA4rrqZ/kLB14RTVxYwtsz90fnDpM=;
        b=Wjn7fP76fTp0E3lRPcNAC9rUEaxSLyR3jRfg3MegNY9mIDn5Mw82RweeoiP/tFbi3a
         dUQe1fKRvoiMnucIwGMqEGbfLRUzO3xEtYnH0NCLAmSKN3NCkZu/SvB+L77kLLAuTZTl
         J0U52l3FOk1A0igHWqjVbwlPlYCLr++L/elJHt1mFSoiMFAen801psh09TlA3qBrDTWO
         RSBlg6lD2YZaWQH+c8T6h5uazFYz0jMpz1/LEWYbiqH/Y6N1OLrRT2LleCJvqIBoobRI
         TJHsYNO1ISNlwlld2bm9p9hej8SpBYPoYEd+MRtnmUNkxrv0x30UN8Zfd9SKrGxPyR5O
         iUJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+CmRtrUDMjvlwKzA4rrqZ/kLB14RTVxYwtsz90fnDpM=;
        b=wQzNh8XnpjCReF1gF153y7w4Tu8Ua11x7aKMl778XcCJjKo32wyigXSfRwCsIf4JJl
         /ROsOClEuelVm99aLcPLMDgQWWHjIdOCtKIn4dFy1xGKHgeVrjRaBRKYc8TsrrbiPyRz
         aJDO3/i9Jb4jP7E8uGEQNCdOilje2HnTLAGd77gcF+qf9pfrcvvcmKD8VdBdi3Xr8k7n
         qHiuboxGh90ukhMxW+sPJi6M4FG8662pRMflY2XvHVMFBUv5x3rv5BQIS18JRh2/3Wbg
         mDQ7RfdoMym9ZwxymMnTbC88beG2oET+Muq+q9c0tKllSStyB0R0TkeFHogf3VNQyxhP
         p8yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVgFQUKjRaDy8CrxQe9/gfd0slcUI7V8+mgpUpcKFOtXu9ar6FS
	pKwX+nRAG7xemZAlgxqydhk=
X-Google-Smtp-Source: AK7set9o2VR00hhX5gL63ihYXenLf/ZFZ9Ew1ZapBWyD/GNk7t8kMtEnE5MDt8OxfUuLRMmwAa82/g==
X-Received: by 2002:a1c:2bc3:0:b0:3dc:2af8:83bc with SMTP id r186-20020a1c2bc3000000b003dc2af883bcmr813142wmr.144.1675075576541;
        Mon, 30 Jan 2023 02:46:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ce90:0:b0:2bf:ae0c:669b with SMTP id r16-20020adfce90000000b002bfae0c669bls945177wrn.2.-pod-prod-gmail;
 Mon, 30 Jan 2023 02:46:15 -0800 (PST)
X-Received: by 2002:a5d:6f0e:0:b0:2bf:dcbc:c442 with SMTP id ay14-20020a5d6f0e000000b002bfdcbcc442mr7015089wrb.24.1675075575073;
        Mon, 30 Jan 2023 02:46:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675075575; cv=none;
        d=google.com; s=arc-20160816;
        b=VUfg6VB//18khTUg969JE+e9sYSnSlDwzHLXLamISUB9GK/AoVD/b5y//eFQd+F+cr
         +l76dcudO1TJmzpwbqGeL5Eq/lfFk2Qei7SaeRKonpT12xBEGdd0QCuLRDJ5+K7x0w70
         UVToZ9dK0Qh0kBJ9nMOIIKIeidgl9yvRR6gnEBOXbUGyqlDTVhEPpwbR0SaBO7es8hRw
         yT/nMAPSecl1+kCg8Z3r9L7UFvAQQa8W2Jlbi/2BLKyxhGMpBMKjXyrA3p/OPl/QCTe1
         jd0upg1vOk1duCEpe3IiCEM5prz8Qr+qf1OK5hJmahjZo5Ju3Tp5WpAzV8GpVKAixOWD
         xCmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=xwrNlBydazc5t639iFN6aprL3WGemATs/tO8X4a/07Q=;
        b=wnfSIkHIZNR9U0nwLQ5PmAFUQgjmUekGbOT0o6FGHGPY1XclOQVHfJHVPjDNBYkfDZ
         DufVKHAg7JQYycdEEkGlvCk0KmQLGka2asJkmCwrigoX0Xq9yTavYxI6vL5MGDEmU8Cv
         9zVwCXhFu5mktls9cBHXTSAI0mC2A/kamtvFVkXe3l/Mg0qnUcKEFp13xirzN/v0mveM
         c8fvrQP6eBwJvj844wVYDFWFijpD5VtF3LhjB/QwSXF9e2fIL+rPdS9UZw1C9sSpJ17Y
         FgIuyt0Gnmv1WyS/vyNEMEtsgn0FmJj0zhxQ8WC+JS9d5KflGFMH3zc3lxJmx+8VRfN7
         krlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bt1-20020a056000080100b0024222ed1370si591387wrb.3.2023.01.30.02.46.14
        for <kasan-dev@googlegroups.com>;
        Mon, 30 Jan 2023 02:46:15 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 460BD16A3;
	Mon, 30 Jan 2023 02:46:56 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.13.128])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DDCED3F71E;
	Mon, 30 Jan 2023 02:46:11 -0800 (PST)
Date: Mon, 30 Jan 2023 10:46:09 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Andrey Konovalov <andreyknvl@gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user
 addresses
Message-ID: <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N>
References: <20230127162409.2505312-1-elver@google.com>
 <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 30, 2023 at 08:00:00AM +0100, Marco Elver wrote:
> On Fri, 27 Jan 2023 at 19:14, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > Hi Marco,
> >
> > Apologies for having not replies on v1...
> >
> > On Fri, Jan 27, 2023 at 05:24:09PM +0100, Marco Elver wrote:
> > > Allow the creation of restricted breakpoint perf events that also fire
> > > in the kernel (perf_event_attr::exclude_kernel=0), if:
> > >
> > >   1. No sample information is requested; samples may contain IPs,
> > >      registers, or other information that may disclose kernel addresses.
> > >
> > >   2. The breakpoint (viz. data watchpoint) is on a user address.
> >
> > I think there's a potential problem here w.r.t. what constitutes a "user
> > address". Below, the patch assumes that any address which access_ok() is happy
> > with is a user address, but that's not always the case, and it's not
> > necessarily always safe to allow watchpoints on such addresses.
> 
> Isn't that a deficiency with access_ok()?
> 
> https://www.kernel.org/doc/html/latest/core-api/mm-api.html#c.access_ok
> "Checks if a pointer to a block of memory in user space is valid. [...]"

Arguably yes, but it's not really solvable in the current API design.

One issue is that this is contextual, and access_ok() is implicitly limited to
some scenarios but not others. It's not meant to work for arbitrarty pointers
in arbitrary contexts (as e.g. it has no way of distinguishing an idmap from
userspace).

We largely don't take implicit context into account in access_ok(), other than
the tag removal stuff we do on arm64 (and on x86 for LAM), and I don't think
anyone was all that happy about extending it for that.

> > For example, UEFI runtime services may live in low adddresses below
> > TASK_SIZE_MAX, and there are times when we run code in an idmap (or other
> > low-half mapping) when we cannot safely take an exception for things like idle,
> > suspend, kexec, pagetable rewriting on arm64, etc.
> >
> > So I think this may introduce functional issues (e.g. a mechanism to crash the
> > kernel) in addition to any potential information disclosure, and I would not
> > want this to be generally available to unprivileged users.
> >
> > Most of those happen in kernel threads, but they can also happen in the context
> > of user threads (e.g. if triggering suspend/idle via sysfs), so special care
> > will be needed, as above.
> 
> These are good points.
> 
> > > The rules constrain the allowable perf events such that no sensitive
> > > kernel information can be disclosed.
> > >
> > > Despite no explicit kernel information disclosure, the following
> > > questions may need answers:
> > >
> > >  1. Q: Is obtaining information that the kernel accessed a particular
> > >     user's known memory location revealing new information?
> > >
> > >     A: Given the kernel's user space ABI, there should be no "surprise
> > >     accesses" to user space memory in the first place.
> >
> > I think that may be true for userspace, but not true for other transient
> > mappings in the low half of the address space. Ignoring the functional concern
> > above, for idmap'd code this would at least provide a mechanism to probe for
> > the phyiscal address of that code (and by extension, reveal the phyiscal
> > location of the entire kernel).
> 
> This again feels like a deficiency with access_ok(). Is there a better
> primitive than access_ok(), or can we have something that gives us the
> guarantee that whatever it says is "ok" is a userspace address?

I don't think so, since this is contextual and temporal -- a helper can't give
a single correct answert in all cases because it could change.

In the cases we switch to another mapping, we could try to ensure that we
enable/disable potentially unsafe watchpoints/breakpoints.

Taking a look at arm64, our idmap code might actually be ok, since we usually
mask all the DAIF bits (and the 'D' or 'Debug' bit masks HW
breakpoints/watchpoints). For EFI we largely switch to another thread (but not
always), so that would need some auditing.

So if this only needs to work in per-task mode rather than system-wide mode, I
reckon we can have some save/restore logic around those special cases where we
transiently install a mapping, which would protect us.

For the threads that run with special mappings in the low half, I'm not sure
what to do. If we've ruled out system-wide monitoring I believe those would be
protected from unprivileged users.

Thanks,
Mark.

> > >  2. Q: Does causing breakpoints on user memory accesses by the kernel
> > >     potentially impact timing in a sensitive way?
> > >
> > >     A: Since hardware breakpoints trigger regardless of the state of
> > >     perf_event_attr::exclude_kernel, but are filtered in the perf
> > >     subsystem, this possibility already exists independent of the
> > >     proposed change.
> >
> > Hmm... arm64's HW breakpoints and watchpoints have HW privilege filters, so I'm
> > not sure the above statement is generally/necessarily true.
> 
> Right, I can see this being a valid concern on those architectures
> that do support HW privilege filters.
> 
> > > Motivation:  Data breakpoints on user addresses that also fire in the
> > > kernel provide complete coverage to track and debug accesses, not just
> > > in user space but also through the kernel. For example, tracking where
> > > user space invokes syscalls with pointers to specific memory.
> > >
> > > Breakpoints can be used for more complex dynamic analysis, such as race
> > > detection, memory-safety error detection, or data-flow analysis. Larger
> > > deployment by linking such dynamic analysis into binaries in production
> > > only becomes possible when no additional capabilities are required by
> > > unprivileged users. To improve coverage, it should then also be possible
> > > to enable breakpoints on user addresses that fire in the kernel with no
> > > additional capabilities.
> >
> > I can understand the argument for watchpoints (modulo my concerns above), but
> > there's no need to support instruction breakpoints, right? i.e. there's no
> > legitimate reason for a user to want to monitor a given user address
> > system-wide, regardless of what's running?
> >
> > IIUC this only makes sense for watchpoints, and only in the context of a given
> > task.
> 
> Right, there shouldn't be a need for instruction breakpoints, the
> kernel shouldn't be executing user code.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9ef8cKrE4RJsrO%2B%40FVFF77S0Q05N.
