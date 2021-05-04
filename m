Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VSYSCAMGQE3AWIDCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF76D372852
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 11:53:02 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id v4-20020a2e96040000b02900ce9d1504b5sf3549445ljh.16
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 02:53:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620121982; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qo7fw3mwtC3XuFO8SkNyCe27msNhJfx0Z4y/i7fMkxwKRz6VqgwtCTQy7avMEzypmU
         7dF+i8fCjK5VM1KZba0xsd2IehHTGHx9IcTS7oLdocbiBBKU9LsVEVMA1BVR6hQNAJa1
         6pGThlEippYJgKk4OFBb0iphJg6Mru2Y+Xb+N81YbufPsu5fMlfj21pHvc6gp3N+Xjn3
         IwB16F9ocUv6wZ+SaDieObRLAwzVP1C2c5jOhHAqVkoarC1BjhQPc/9pjAZiybXovokk
         vIGApKEV3ByiZ9UNG3Q8iH+o+LBqGdE0oXJo9dvdNH1Bi+H0UHNThbsvWYT8xMpfQXUa
         tE1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xyirRCAHSuv1y6dT1U4THXHKLOFNYIIMpSxVE9bjkJc=;
        b=ZZA3jS28tkx7lgR8N/1NjWV/9pWrpgpzpLwdJsrdvQ9teXYHTTHVHHFTDuzh2mT9g8
         YOOybXUA0xSu+ka+shpSErKi731iXoNnoFAjUl6cX0EZbCD2RsocabpLV9sjvN7SQQir
         FMP+XzAFPayQrw8r42uTNoLzoxNrnC+G7bnocl719WCUO+B+3pwbsBnyy+u7MsYdiJGn
         SLOfACM4umLBywyn44R/NWn+JFbCD9GuT5subxjllncqd3BCoeXLXtioF/u3+TMMVqTJ
         FWDwqMrss2WNXkhdA4mEOAtQf3RjHGcSpeohpmqxSrXTq1H0FbVUo0THyCkmLyXl65F5
         C2bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FjfNrm6c;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xyirRCAHSuv1y6dT1U4THXHKLOFNYIIMpSxVE9bjkJc=;
        b=JCGcVJqpPv4R2QTV4f06/c4HlIHkaTwohVT6nZKfBWQEHT0esra7BGY3MdMIoM5UQR
         12DRClJPdBt8wmliENOps4SGsKE2ivHpY1zj5nV4JOrtNenZPX7crML31NW5W49Q+Ydt
         FXbxAf5bsZ/tM7VQNrjaH0PA503gkQRSFhzjpiSLB5YsEP2/qzxFk3lwBJb3TpN0P863
         8zpw6yEKuHt+g9eoHVfE6KJKoKAfnWVht90jkgXt8GhmlhkMN+LGB4/b4vmvMZ9ITEd7
         PEgNb8cvPdIQdhABRMRZEcjjqKhJ4cMMjbkiNSqKHzeXdbeDiQ5BeyVUin4xhCKxJgT+
         FNRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xyirRCAHSuv1y6dT1U4THXHKLOFNYIIMpSxVE9bjkJc=;
        b=VZL9mazGsz2SDUYbvbK27DTgmnYuu0VB27CZAx2RknydxOu+ypzdiPcjnjFcup6vsT
         PGmRGg/6d3bKn5xJdLZQv9SzG6pVLsYuXFRzVB1QVcmEUCarL+tC6xMYSdyQWlLiM7Bv
         qvFaCDzEnhIUBRM+Fm7DygA9oAW8R1BjDh3ocQEakIhl0ofdfdh012aYf7dmyMXx4Xv6
         BLPXXEhxPoHMAEf/4XyaN0qOjDhZgVtWlEe9i3wvZQARU9fEPhFEO59d7k6zN7ND3K1h
         O/EFx97Hgm9JRIXrU9JXqUba3d6UeuMIGougd9n5KDt5e+SPiJzNkyRykhkDLCeXpkcE
         abvg==
X-Gm-Message-State: AOAM531Xv/nnQYkisYuoflm+bXlPprfX1Cqcrzf78hG/s8tELn5UjW4f
	8a/IPYjcXZT9wb/vGS9NaWc=
X-Google-Smtp-Source: ABdhPJzCAbHkcZ0AzXakBzIds0+yXOW51U7aTi2xi+95Dyh3KUw6wzzDqYu6i0ZqlvxO0YtrKTv9bw==
X-Received: by 2002:a05:6512:1192:: with SMTP id g18mr10764516lfr.659.1620121982313;
        Tue, 04 May 2021 02:53:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc14:: with SMTP id b20ls2928004ljf.10.gmail; Tue, 04
 May 2021 02:53:01 -0700 (PDT)
X-Received: by 2002:a05:651c:33a:: with SMTP id b26mr16731120ljp.220.1620121981171;
        Tue, 04 May 2021 02:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620121981; cv=none;
        d=google.com; s=arc-20160816;
        b=YiWXldXxO0f+fl0/kcp0seyybU0lHSDxzVWzJTav01OpYgFXyrrMHTfu3P+TQKpjd6
         Bftd/za+12cv8gMF0aOnz4kQBklTCbFt/0fcPRiGra20Yx5C+Xi1IKVBhm0jBZZwqufU
         C8kIfINy+x/gyU4OihXZFN/TAN0+3v67TM+kw6eacHS0Jiy5/DZg2IIXAQVf6YJaI5rk
         u/pr/EVgJ2GtJBwGxGZ7b1xr6dPeoHdTKruMU4wkBfVi5ykToVhic0HRF0E0bk+cRXQ/
         tbiCjAjQ3mo/MRT7mMblPZgrSCNR7QpxpknTVUm0mKdc/Cthu28YJZdC/hvFcXSXH88v
         bBxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=nbYaFoj0a2opBaBQYBBRmlSUUXl+1Qvyp4TrOePSvwA=;
        b=E6vcujFKJSKZTFRtGC+/WrystzTwnFDeZzt3fKd3VQFceNesPYwRjOue4BHR1WNi3n
         OT1r19d4q9g89Uz6wKAkyCM0ebFSRdHNkt0reWMaSnelqdin7X/9o2AjGXfsKVVFcVQ8
         DTNQ6uPsXaGd0bdPO2MgF37W4WDDqMXBW0pv5999opDykPGOKCipNr1b7hqP8QAUWAjQ
         yWXoU8GIBchC5HNxEN3zHXepfZjxHU9DzgHaJ6molx3eNVnxE5q7/JSi0D/q+n2Cg7DQ
         8gP6GEQm0DNh3uJP+s7Gc8LM2NhM3MASTJzX5DAwdyoeOfSfteIryJ7nQJRoKn2+tcmu
         lO7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FjfNrm6c;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id j7si174228ljc.6.2021.05.04.02.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 May 2021 02:53:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id s5-20020a7bc0c50000b0290147d0c21c51so939310wmh.4
        for <kasan-dev@googlegroups.com>; Tue, 04 May 2021 02:53:01 -0700 (PDT)
X-Received: by 2002:a1c:b087:: with SMTP id z129mr2922551wme.67.1620121980472;
        Tue, 04 May 2021 02:53:00 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:fd3e:f300:5aa9:4169])
        by smtp.gmail.com with ESMTPSA id p5sm2107257wma.45.2021.05.04.02.52.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 May 2021 02:52:59 -0700 (PDT)
Date: Tue, 4 May 2021 11:52:54 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Eric W. Biederman" <ebiederm@xmission.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are
 possible
Message-ID: <YJEZdhe6JGFNYlum@elver.google.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
 <20210503203814.25487-10-ebiederm@xmission.com>
 <m1o8drfs1m.fsf@fess.ebiederm.org>
 <CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com>
 <m1lf8vb1w8.fsf@fess.ebiederm.org>
 <CAMn1gO7+wMzHoGtp2t3=jJxRmPAGEbhnUDFLQQ0vFXZ2NP8stg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO7+wMzHoGtp2t3=jJxRmPAGEbhnUDFLQQ0vFXZ2NP8stg@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FjfNrm6c;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Mon, May 03, 2021 at 09:03PM -0700, Peter Collingbourne wrote:
> On Mon, May 3, 2021 at 8:42 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
> > Marco Elver <elver@google.com> writes:
> > > On Mon, 3 May 2021 at 23:04, Eric W. Biederman <ebiederm@xmission.com> wrote:
> > >> "Eric W. Beiderman" <ebiederm@xmission.com> writes:
> > >> > From: "Eric W. Biederman" <ebiederm@xmission.com>
> > >> >
> > >> > The si_perf code really wants to add a u64 field.  This change enables
> > >> > that by reorganizing the definition of siginfo_t, so that a 64bit
> > >> > field can be added without increasing the alignment of other fields.
> > >
> > > If you can, it'd be good to have an explanation for this, because it's
> > > not at all obvious -- some future archeologist will wonder how we ever
> > > came up with this definition of siginfo...
> > >
> > > (I see the trick here is that before the union would have changed
> > > alignment, introducing padding after the 3 ints -- but now because the
> > > 3 ints are inside the union the union's padding no longer adds padding
> > > for these ints.  Perhaps you can explain it better than I can. Also
> > > see below.)
> >
> > Yes.  The big idea is adding a 64bit field into the second union
> > in the _sigfault case will increase the alignment of that second
> > union to 64bit.
> >
> > In the 64bit case the alignment is already 64bit so it is not an
> > issue.
> >
> > In the 32bit case there are 3 ints followed by a pointer.  When the
> > 64bit member is added the alignment of _segfault becomes 64bit.  That
> > 64bit alignment after 3 ints changes the location of the 32bit pointer.
> >
> > By moving the 3 preceding ints into _segfault that does not happen.
> >
> >
> >
> > There remains one very subtle issue that I think isn't a problem
> > but I would appreciate someone else double checking me.
> >
> >
> > The old definition of siginfo_t on 32bit almost certainly had 32bit
> > alignment.  With the addition of a 64bit member siginfo_t gains 64bit
> > alignment.  This difference only matters if the 64bit field is accessed.
> > Accessing a 64bit field with 32bit alignment will cause unaligned access
> > exceptions on some (most?) architectures.
> >
> > For the 64bit field to be accessed the code needs to be recompiled with
> > the new headers.  Which implies that when everything is recompiled
> > siginfo_t will become 64bit aligned.
> >
> >
> > So the change should be safe unless someone is casting something with
> > 32bit alignment into siginfo_t.
> 
> How about if someone has a field of type siginfo_t as an element of a
> struct? For example:
> 
> struct foo {
>   int x;
>   siginfo_t y;
> };
> 
> With this change wouldn't the y field move from offset 4 to offset 8?

This is a problem if such a struct is part of the ABI -- in the kernel I
found these that might be problematic:

| arch/csky/kernel/signal.c:struct rt_sigframe {
| arch/csky/kernel/signal.c-	/*
| arch/csky/kernel/signal.c-	 * pad[3] is compatible with the same struct defined in
| arch/csky/kernel/signal.c-	 * gcc/libgcc/config/csky/linux-unwind.h
| arch/csky/kernel/signal.c-	 */
| arch/csky/kernel/signal.c-	int pad[3];
| arch/csky/kernel/signal.c-	struct siginfo info;
| arch/csky/kernel/signal.c-	struct ucontext uc;
| arch/csky/kernel/signal.c-};
| [...]
| arch/parisc/include/asm/rt_sigframe.h-#define SIGRETURN_TRAMP 4
| arch/parisc/include/asm/rt_sigframe.h-#define SIGRESTARTBLOCK_TRAMP 5 
| arch/parisc/include/asm/rt_sigframe.h-#define TRAMP_SIZE (SIGRETURN_TRAMP + SIGRESTARTBLOCK_TRAMP)
| arch/parisc/include/asm/rt_sigframe.h-
| arch/parisc/include/asm/rt_sigframe.h:struct rt_sigframe {
| arch/parisc/include/asm/rt_sigframe.h-	/* XXX: Must match trampoline size in arch/parisc/kernel/signal.c 
| arch/parisc/include/asm/rt_sigframe.h-	        Secondary to that it must protect the ERESTART_RESTARTBLOCK
| arch/parisc/include/asm/rt_sigframe.h-		trampoline we left on the stack (we were bad and didn't 
| arch/parisc/include/asm/rt_sigframe.h-		change sp so we could run really fast.) */
| arch/parisc/include/asm/rt_sigframe.h-	unsigned int tramp[TRAMP_SIZE];
| arch/parisc/include/asm/rt_sigframe.h-	struct siginfo info;
| [..]
| arch/parisc/kernel/signal32.h-#define COMPAT_SIGRETURN_TRAMP 4
| arch/parisc/kernel/signal32.h-#define COMPAT_SIGRESTARTBLOCK_TRAMP 5
| arch/parisc/kernel/signal32.h-#define COMPAT_TRAMP_SIZE (COMPAT_SIGRETURN_TRAMP + \
| arch/parisc/kernel/signal32.h-				COMPAT_SIGRESTARTBLOCK_TRAMP)
| arch/parisc/kernel/signal32.h-
| arch/parisc/kernel/signal32.h:struct compat_rt_sigframe {
| arch/parisc/kernel/signal32.h-        /* XXX: Must match trampoline size in arch/parisc/kernel/signal.c
| arch/parisc/kernel/signal32.h-                Secondary to that it must protect the ERESTART_RESTARTBLOCK
| arch/parisc/kernel/signal32.h-                trampoline we left on the stack (we were bad and didn't
| arch/parisc/kernel/signal32.h-                change sp so we could run really fast.) */
| arch/parisc/kernel/signal32.h-        compat_uint_t tramp[COMPAT_TRAMP_SIZE];
| arch/parisc/kernel/signal32.h-        compat_siginfo_t info;

Adding these static asserts to parisc shows the problem:

| diff --git a/arch/parisc/kernel/signal.c b/arch/parisc/kernel/signal.c
| index fb1e94a3982b..0be582fb81be 100644
| --- a/arch/parisc/kernel/signal.c
| +++ b/arch/parisc/kernel/signal.c
| @@ -610,3 +610,6 @@ void do_notify_resume(struct pt_regs *regs, long in_syscall)
|  	if (test_thread_flag(TIF_NOTIFY_RESUME))
|  		tracehook_notify_resume(regs);
|  }
| +
| +static_assert(sizeof(unsigned long) == 4); // 32 bit build
| +static_assert(offsetof(struct rt_sigframe, info) == 9 * 4);

This passes without the siginfo rework in this patch. With it:

| ./include/linux/build_bug.h:78:41: error: static assertion failed: "offsetof(struct rt_sigframe, info) == 9 * 4"

As sad as it is, I don't think we can have our cake and eat it, too. :-(

Unless you see why this is fine, I think we need to drop this patch and
go back to the simpler version you had.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJEZdhe6JGFNYlum%40elver.google.com.
