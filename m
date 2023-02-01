Return-Path: <kasan-dev+bncBDV37XP3XYDRBBVC5GPAMGQE4CWJRWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B9F7686588
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 12:46:15 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id r15-20020a05600c35cf00b003d9a14517b2sf942650wmq.2
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 03:46:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675251974; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hs+bvno8ZzmtKOvPKwYj3G+9z/PBc21vAKcArO/keYzaf53YmpmtLmHON8+0FBhKFY
         AO3UprQ2jhFw/GvT7ywLU9ZnAPkLRzk3vBU+OB1ecY1VQ45Jioj/GEtz6Hfn2tUlmYgQ
         YY+F5qw81s2Hno/dX3pjb5l70eoomHg1bjFZ0NHHfHggXAVZMr3yU659+sJI1YLIamUL
         MibcHFR40DFYPxwuD8BHATvIp+mxKBe4DBHPpa0YbxyrwLvRK1R8Tjx08AFhkSuZCOyU
         V2BD4qRY1WDXFn9pMQbUe0kMlIBantZswuED5UT40z5m18XCMuJ1+p9EJG3NrDQvgnWy
         5PUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=djcHy3dTfJB5suByUwNefwCsJPsmkc+SJwvw7Y82/Lc=;
        b=08PZkRhMOsDiA+FnNlSJabYPyCej0LJEclTLoiWosytwxATmZfEwphDp1J8NggA0Z1
         Okz5z1NmOQqWo9nXd9OaX/pdIbQmGmcHCPlO1QWXDzze+PbHeaylZjgnEW151YTeRoEQ
         MMELhuyf7HXseXOimvS6P7ZbzxYlAADNwa8u21VSoiMXH8Yh86UJGpvYX2iydgNYeXxn
         jqjnkSf/ryR3SrI/gi4QeoNK4QKoayZ4+nBT8PFVoSb1IN/umOycLjdTMdMJgAR9KK61
         QCl6bZiq98i5kBLXViCIaXzenpjSWY42zJvLV9EFvBHnS2gGrOZl7oij46iMVh3sANhU
         SG1A==
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
        bh=djcHy3dTfJB5suByUwNefwCsJPsmkc+SJwvw7Y82/Lc=;
        b=AfzolF4F3pd1Pr/Wwc3CP9yghA/I4KEM71SEmTOh2Lo/gEQIeThInTgfPpIeCql/Mj
         zcf4E70EzpeUQ/+qwcw5W3otN4S8JGM8e18OpwUf+22i13PkWwESxpj3mYnNnnOkO313
         Ckz/MrASawOFeY7PLKQhym2WHB+3Pzo4dqR+mfc0BDCYcFHOyybY8e70gPnMyJ4GbBWP
         UFmVMF9rBkYnNnWNRehXu9GuoxJkEjhEZfSiUB6uarxsU9Z+1D0ph2T94PuWykY+fDPi
         8Aiis0xcnvkadSeagkJeMLD27w0Cz1CTH9rFf+TXvgkv6fiiYI8LfQGP5TcAFAi6Kif4
         UUZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=djcHy3dTfJB5suByUwNefwCsJPsmkc+SJwvw7Y82/Lc=;
        b=Ket8lYe+hno6H53awxvrJvbKPVTVVu4eixLzgM3pfo5DVqiHo6xaxegJxxpWMF3uXI
         qP323grO9xagTXR/i+s+sBmCWAH7uIzkr7yPP/NMvpdDDhBa9Qb0HiwYkFGV5AZPcTZK
         5uFL22JMGzmjEeaKRfQg8TFGt9rrVPXJo5WbJzcHOaVfQoChv3X9xR0qjx5UZ8H0G2zC
         0AqdEuWtfPuamR8T3aPrbTmPwSMyw4GAt0x/1jomSCXe7Uq/qo2S/cHtv6aGTEGAWAhp
         mIyXocRF3/QclPSpdY4NIVbZEvsq3DSNUic5YBPFlxDpSTAAZQ1/XMbpiRwRxtbkWxsM
         OlgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXWyO2b9LEdgxIxU/4uvA5b415U/odQjeNeIQc4HOeDKssBdIOs
	A0LvdBypokNoYNBFdaLnVls=
X-Google-Smtp-Source: AK7set/PVsc+OqMNNMVCgQe+f/0A99zEJfCPJhp14YJtLGLGJsrXQ/DgRXO+ekfEcyWKs6RRytY5mA==
X-Received: by 2002:a05:600c:4f51:b0:3db:1838:3ee6 with SMTP id m17-20020a05600c4f5100b003db18383ee6mr131000wmq.168.1675251974551;
        Wed, 01 Feb 2023 03:46:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3caa:b0:3cf:72dc:df8 with SMTP id
 bg42-20020a05600c3caa00b003cf72dc0df8ls896811wmb.0.-pod-canary-gmail; Wed, 01
 Feb 2023 03:46:13 -0800 (PST)
X-Received: by 2002:a05:600c:310b:b0:3dc:5bdc:a9e9 with SMTP id g11-20020a05600c310b00b003dc5bdca9e9mr1771255wmo.33.1675251973076;
        Wed, 01 Feb 2023 03:46:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675251973; cv=none;
        d=google.com; s=arc-20160816;
        b=YClCRJQZUT3RYiPM+VNfLu/MW805XU1WPfyN7VWNEhg6ZKVYOaDiFSkF6u8ypSYBSm
         /z51kbdF/FCqoL+rsKn7XE8j3Msb/wUPkEWwRxAud/iFUbRw+arYX4JdbXvwx+fi15ui
         r+LPb64W6Rq51KBxPpF+C62QJDhwE0YnUK9phSR6hwvJYQsCHjlazlS0A2y2+2ILOL6l
         bq2ZfgxAeALoE6vKFoiPlhajOhtjBQjz7T3ajcw5dYHpIsccBhkn0f/dF/vAPuGpGhhq
         2KVAzDYnVrzd3fL7vfruZP8cDIUd+SrDMN+aAA3JRdYYdD6LtvbJdqekdmt2Pej2C8ES
         WyDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=rqWgXxqqwp4Ql9UNC6Tqgtq44UdEHBaHnj3RXN3rx5g=;
        b=TDcJcc476IbzPEDAqi+rpqpR0oD39pGAXdzasGZfFt941Hu9ArU9NQNplbOF3XGgls
         wx+iMOTbHRftG3Md694Of5skN4SmHxV0xIg2d5xF2vL7/iJrdl0rVTC7f2p6RhJjhL6z
         +5/gkprtu5jVmoHZuI9+f2V9Hjvf90EmQW1OgAqonjETKhVCwnRgQqzxKJjTIIQ/oA4v
         LlGOdAYftUzsysAJDhPB9AScXoeyBcjrAV5nT4x+Zm2VJ/m1PSVuDk2mJPM4FRrwV632
         qafnz3O28R7uz4NWJuPz2Q7m2lCiDtCKDOJ5mW7srJr3H35e7fe2oZHD1SwwXaESdsv2
         LiAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n23-20020a7bc5d7000000b003db0d2c3d6esi76294wmk.0.2023.02.01.03.46.12
        for <kasan-dev@googlegroups.com>;
        Wed, 01 Feb 2023 03:46:13 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 586DE4B3;
	Wed,  1 Feb 2023 03:46:54 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.12.10])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0F0963F882;
	Wed,  1 Feb 2023 03:46:09 -0800 (PST)
Date: Wed, 1 Feb 2023 11:46:07 +0000
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
Message-ID: <Y9pQ/939u9O6teX0@FVFF77S0Q05N>
References: <20230127162409.2505312-1-elver@google.com>
 <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
 <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N>
 <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
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

On Wed, Feb 01, 2023 at 10:33:40AM +0100, Marco Elver wrote:
> On Mon, 30 Jan 2023 at 11:46, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > > This again feels like a deficiency with access_ok(). Is there a better
> > > primitive than access_ok(), or can we have something that gives us the
> > > guarantee that whatever it says is "ok" is a userspace address?
> >
> > I don't think so, since this is contextual and temporal -- a helper can't give
> > a single correct answert in all cases because it could change.
 
One thing I just realised to note -- these mappings are installed in a distinct
set of page tables that the kernel transiently switches to within the context
of a task, they're not inside the same page tables as userspace associated with
that task. So you can have distinct mappings at the same VA at different times.

> That's fair, but unfortunate.

Yup. :)

> Just curious: would copy_from_user_nofault() reliably fail if it tries to
> access one of those mappings but where access_ok() said "ok"?

Generally, no. Most architectures don't have special instructions for accessing
user memory specifically and are reliant on people not making uaccesses while
such mappings are installed. That's generally enforced by mutual exclusion;
userspace can't issue any new syscalls within the context of that task since it
isn't executing while the special mappings are installed, and usually IRQs
would be disabled, preventing IPIs and such. There *might* be a latent issue
with interruptible EFI runtime services.

On arm64, yes. Our uacccess routines including copy_from_user_nofault() use out
`LDTR` and `STTR` instructions, which use the same permissions as accesses from
userspace, and we create the special mappings without user access permissions,
so any uaccess to those will fault. There are some special cases (e.g. the
futex code), but those are never invoked in a context where the special
mappings are in place.

> Though that would probably restrict us to only creating watchpoints
> for addresses that are actually mapped in the task.

As above, since this is contextual and temporal, that wouldn't actually protect
us.

Consider a user task with something mapped at 0xCAFEF00D:

* access_ok(0xCAFEF00D, 1) is true

* copy_from_user_nofault(dst, 0xCAFEF00D, 1) succeeds without faulting.

... so we would be able to install a watchpoint.

However, after this the task might *transiently* use a different mapping (e.g.
the idmap), which could have an unrelated mapping at 0xCAFEF00D (for which
copy_from_user_nofault() would fault).

> > In the cases we switch to another mapping, we could try to ensure that we
> > enable/disable potentially unsafe watchpoints/breakpoints.
> 
> That seems it'd be too hard to reason that it's 100% safe, everywhere,
> on every arch. I'm still convinced we can prohibit creation of such
> watchpoints in the first place, but need something other than
> access_ok().

As above, I don't think that can be an ahead-of-time check. If we want the
watchpoints to fire on kernel-mode accesses to user memory, we need a temporal
boundary around when userspace mappings are transiently switched with other
mappings.

While that's arch specific, there are relatively few places that do that
switch.

> > Taking a look at arm64, our idmap code might actually be ok, since we usually
> > mask all the DAIF bits (and the 'D' or 'Debug' bit masks HW
> > breakpoints/watchpoints). For EFI we largely switch to another thread (but not
> > always), so that would need some auditing.
> >
> > So if this only needs to work in per-task mode rather than system-wide mode, I
> > reckon we can have some save/restore logic around those special cases where we
> > transiently install a mapping, which would protect us.
> 
> It should only work in per-task mode.

Ok, that makes the problem much simpler; with that in mind arm64 might already
be safe today.

That rules out a user task trying to monitor a kthread, which is the common
case (e.g. most EFI RTS calls or use of the idmap for idle).

There are a few rare cases where we do this within the context of a user task.
In those cases we're already doing a bunch of work to transiently switch page
tables and other state, so we could add some hooks to transiently disable
watchpoints and call those at the same time.

> > For the threads that run with special mappings in the low half, I'm not sure
> > what to do. If we've ruled out system-wide monitoring I believe those would be
> > protected from unprivileged users.
> 
> Can the task actually access those special mappings, or is it only
> accessible by the kernel?

They're only accessible by the kernel, and are not accessible by a uaccess or
actual userspace access.

As above, they're in a distinct set of page tables (so not accessible from
other threads within the same process), and they're mapped with kernel
permissions, so the uaccess routines should fault.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9pQ/939u9O6teX0%40FVFF77S0Q05N.
