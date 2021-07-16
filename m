Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWH5Y2DQMGQEK2IOGBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id C02CA3CBAFD
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 19:16:09 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id r10-20020ab0330a0000b02902a1547abcd1sf3990873uao.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 10:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626455768; cv=pass;
        d=google.com; s=arc-20160816;
        b=i03Q+DobDFLCo5aN3145NC7iPvyNTr8m4Ndi+5f4kHFB/i6VQn59qdGD7XKmr4tYSo
         QKi1PJPj9/9KZfkqGEqlKzsg2pQks3z28rePE+uU2G+1yGbJCmhHCkDs77LWx21L07Ad
         XBCSYHhL5Fed0r3CDcjUCw1tNflCZoadbGQPNRoCdvCkN3LrpK/Ubz/fFrGKELajxdhC
         UItj5cQfFGbiN2CcgOS90Yt4Bm5rltPhHpbfpDbIhg3ZZ+CsSH6hLR8ymeJsLxSZ3Qfr
         37dvgW5ws96M4tFvEbhPlJadiKr6P78QeMkp8FZln010hv4PQ+v+OP0GIa3gSV8q5YXM
         J+vA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v/viO0sEyKSynoFJ+ydPhx0eE1Xv1yw+XPPWOz2dcFY=;
        b=ISeRJEOfhBxodOjuY62kUPYi8QaoEoViW8nfVW5ArZKdwwjO/SH58wmQI1mHryFJwu
         +iY+z8gIuucXZfHWOZatgLRAAV9ZhUoBXBeU2IBXZeUxHtNCIk3TCqWP9QLbF2IfPN9J
         eKsybC60dQfUMxPFZ+FP4gjllMdiubS0iCbWpIr3zKFCrUFDBfJijp7moMrjAKtH60i6
         WdMLGgljBy6JjjXV4eQ/DrLk7ofqsKe7t8MlYjJTGsQnbvxtYqfvEOZ1zf674MqnGkBH
         69PaUm29iF4Le8lYYsUt55pPILVw8i4gysAf1foRwpfTQ7c2A5qtLZFGTBhLM1sXADI9
         L7WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kycsT8OT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v/viO0sEyKSynoFJ+ydPhx0eE1Xv1yw+XPPWOz2dcFY=;
        b=pcLFj1qy4nZ13dniIJ1adDngY7SO/iQJUZhZydVvazz+VmiQkPZuZ+s37gcpApknvo
         AHP9PG0DZU6GIaigkvif8v63mROU8lnOEcGIRqCxRI1eITS2guyzFbdcOCp5LU/c8NW6
         sJ+tQC6UkZP7k3cpDcRd2xcVhPkbPA0Gg2TNnZ6vao4htCDYLPdBQ3A8E4FSpFupFK07
         /OnhHE82uNGi+cH1vSx17UTiNeG+/90V2adkR/9M/2RxBRrFRQ6KLZ4tdiEbczolqEit
         XRZQvMfGv5LgM7TmbESPV8qdPNMKiLDtXAvowGIF4R6KQ4xzlWlJP26cS3/w7tO3o/K/
         ZlAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v/viO0sEyKSynoFJ+ydPhx0eE1Xv1yw+XPPWOz2dcFY=;
        b=am+cy0n8gOyQmPcxkJqHHFZnWa3UrQyGkkXIAtwobDQhkv9sqN9x4bTwnk5NTU0Lcr
         GZszOAa0yedVffadY/oPWq7sExZj2C9TDuS1IeoyYoF2hqasF3r/bxZ2DxQoaQZJ3c18
         ZuhQogEvTTWZ6Nwe4Ky91FZMqPXf+cPets95xveUO7fQFaSi4Aha1efAobHPe0KpgxyN
         MJG+WciiHFuzviWhr04pwQCypz/CfL5tHbuzd8PifPYZ8T5LXxDs3viEW4PJCRTVybib
         SfYul2IulhFQ9uDTAVbAbQx2vZq1riC0Zvjpfa4Qt6V73RnHnfRSu1myaVNofvOJ/NPw
         RQMg==
X-Gm-Message-State: AOAM530eeLus1wjYPvMa8RshwmzOrZWnFru/su/xcnyPEj4e08HfkATo
	i7pkbXu0qwSC4MXaZipcczo=
X-Google-Smtp-Source: ABdhPJxDvVJ9oR8/PTAVQ+hOgevELQXHtC1mbJsoCYYNALJ78p6E/E38hpotUrSEgxDDX/FRRlZ4Ug==
X-Received: by 2002:a67:7d8b:: with SMTP id y133mr13897039vsc.60.1626455768574;
        Fri, 16 Jul 2021 10:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:ec5:: with SMTP id m5ls3167979vst.11.gmail; Fri, 16
 Jul 2021 10:16:07 -0700 (PDT)
X-Received: by 2002:a67:ea50:: with SMTP id r16mr13678772vso.11.1626455767834;
        Fri, 16 Jul 2021 10:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626455767; cv=none;
        d=google.com; s=arc-20160816;
        b=tSafY00jfKPkQy2dFc70LBvqeAhKYptTZLAL+H8WaC5jWr/5MfclxLf4p6E5Z2SqB3
         R+KwI33FdNJvmaIjcnskKu2/kB6zQMQwgZnP1HgwqLDStx19GDuIr76hDaDPdgKZENaL
         1zrE/F0F1Z5FOFWq2NDyZNQSOBkwt8hSWKYAmPaJ/3YLN9GL4DmHy/fz1V//eHAwyAiH
         XuWBRTDly+VJURUTbyfrP3ivXThchYmEqVYgrizueGrrFXoU63wFMI63xjKmHU7Qmpbx
         rKBVgkRGyC3IDSc9vTwMYREGn8jh1a32+MrA/0hzPBsadVILDDtEJX+1wddubit9MDgi
         oekQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jWbVndvTFPt8BOcGSAnZdQeZBgwQ39VLXMDadBgw6kk=;
        b=uHRNVhUYNh/Ai/1MhfFX8TBkrZG/uClFGlX3W/TElqU/WxucVnLMr3Z45hBbtZOW3b
         gEulbhkTjNPI5xtQlydSW+MkQygif6U1oXMNAZVxjSBR6ZdKZwUmG0oF1GQ1GFLTpfY4
         hPDE5mEQI/ivUGNOFGj3Rmz1JDJi66lUODNRK8bJzjLbbNT7/PryFCZpGkK5Vvrdv0Ke
         dQJYPnJMJi+mcsoq0mVbpWNrYvd4RI60xQ62C6+zTaq+DSuZuowWp80TbtC80Rg6grfa
         kn+z9IpSAuCLVNEdlMObbQwt4FRfIHztIwUQl99CWUdtxAPe0rHsSNLsEmJCJuQOl9IF
         ihXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kycsT8OT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id s7si792126vsm.0.2021.07.16.10.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 10:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id 128-20020a4a11860000b029024b19a4d98eso2602980ooc.5
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 10:16:07 -0700 (PDT)
X-Received: by 2002:a4a:956f:: with SMTP id n44mr8396820ooi.54.1626455767094;
 Fri, 16 Jul 2021 10:16:07 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
 <YPFybJQ7eviet341@elver.google.com> <87tukuw8a3.fsf@disp2133>
In-Reply-To: <87tukuw8a3.fsf@disp2133>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jul 2021 19:15:55 +0200
Message-ID: <CANpmjNMAxk5--iAmL3fL8XpPuDDFdufu1T=r0USnO+6Rn-A95A@mail.gmail.com>
Subject: Re: [PATCH 0/6] Final si_trapno bits
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kycsT8OT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as
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

On Fri, 16 Jul 2021 at 18:09, Eric W. Biederman <ebiederm@xmission.com> wrote:
> Marco Elver <elver@google.com> writes:
> > On Thu, Jul 15, 2021 at 01:09PM -0500, Eric W. Biederman wrote:
> >> As a part of a fix for the ABI of the newly added SIGTRAP TRAP_PERF a
> >> si_trapno was reduced to an ordinary extention of the _sigfault case
> >> of struct siginfo.
> >>
> >> When Linus saw the complete set of changes come in as a fix he requested
> >> that the set of changes be trimmed down to just what was necessary to
> >> fix the SIGTRAP TRAP_PERF ABI.
> >>
> >> I had intended to get the rest of the changes into the merge window for
> >> v5.14 but I dropped the ball.
> >>
> >> I have made the changes to stop using __ARCH_SI_TRAPNO be per
> >> architecture so they are easier to review.  In doing so I found one
> >> place on alpha where I used send_sig_fault instead of
> >> send_sig_fault_trapno(... si_trapno = 0).  That would not have changed
> >> the userspace behavior but it did make the kernel code less clear.
> >>
> >> My rule in these patches is everywhere that siginfo layout calls
> >> for SIL_FAULT_TRAPNO the code uses either force_sig_fault_trapno
> >> or send_sig_fault_trapno.
> >>
> >> And of course I have rebased and compile tested Marco's compile time
> >> assert patches.
> >>
> >> Eric
> >>
> >>
> >> Eric W. Biederman (3):
> >>       signal/sparc: si_trapno is only used with SIGILL ILL_ILLTRP
> >>       signal/alpha: si_trapno is only used with SIGFPE and SIGTRAP TRAP_UNK
> >>       signal: Remove the generic __ARCH_SI_TRAPNO support
> >>
> >> Marco Elver (3):
> >>       sparc64: Add compile-time asserts for siginfo_t offsets
> >>       arm: Add compile-time asserts for siginfo_t offsets
> >>       arm64: Add compile-time asserts for siginfo_t offsets
> >
> > Nice, thanks for the respin. If I diffed it right, I see this is almost
> > (modulo what you mentioned above) equivalent to:
> >   https://lore.kernel.org/linux-api/m1tuni8ano.fsf_-_@fess.ebiederm.org/
> > + what's already in mainline. It's only missing:
> >
> >       signal: Verify the alignment and size of siginfo_t
> >       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
> >
> > Would this be appropriate for this series, or rather separately, or
> > dropped completely?
>
> Appropriate I just overlooked them.

Full series with the 2 patches just sent looks good to me.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAxk5--iAmL3fL8XpPuDDFdufu1T%3Dr0USnO%2B6Rn-A95A%40mail.gmail.com.
