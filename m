Return-Path: <kasan-dev+bncBCJZXCHARQJRBH4MUD5AKGQEZXWN6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id D1684254E0D
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 21:14:40 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id f18sf5117321pgl.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598555679; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkD9L2eMpxsDJfMBJWivtd6b+Yn7YAYF3ucN8YE3zFWsnZgDNuStqvgHkHrD0s180s
         BWNt9G26Q9BnCF7MMSmAdZ3OTcV1uOAbO+xydl+cRAuMnIoezs69RdFk/rx11rJob4ZH
         VF4nF3eSOKZqtlBtPuFcffeEZWPy10Iy0wLobQeW0uhGrke4cIjdmi1E6VCXpWb343fp
         d6gMUyeDLj4KOZOuy/AgFETf0ajfy04i1NFA0QV+SYXrAzAnh3T3W6XuEbnSEwLC8pXY
         ffXgsWAi7uxWx79qRyh7Z/R2+1juG1N3L496cI02CQpENeoj2HnKnhMaNhcqHGDur90+
         Sfyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8fxZIPvbaWTA4LTDRO3yf3UHUdrFA72dVuabGehvQug=;
        b=d0YD+Oi3H0z/1x+6w0rW93nWYFot3Zx+LoAZUfCqDqcr7H23NGHSgrDMUwe9Y2DMBV
         zMq5QRMoJK81AcjO96b/2b4reorkKzOMd9WYvKZuLyNc++VHacEj5TIktOln1abIOlyb
         LA3gEu1zHLtoy3D9zkGKpcq/eyilnD5e+/1qD/TfBEPpZUsg58Li/jjvrVnCdem7S/aG
         +FbGYwLqcKvQ8fHREwaIXR/J96vtGhpPEiktmFDP2aGAlxZRp/9/TdsVAGKHcwQPn8Go
         /T+CZwdazCoGJBiFjZTB+tgz/3tV2ycOgj/Uwd6Oci0NCl14GrOEUx1JHiJGkAwPCrC4
         ep4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CzK5MevC;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8fxZIPvbaWTA4LTDRO3yf3UHUdrFA72dVuabGehvQug=;
        b=Anhy1CXffkiiHVZmZ3Q7ZdL3Y9S853YvPXmV4WKyXYTkTw4qx3Iaks4ujoLV0b81ug
         fTN9S3WWTW9h3H4+QZi6n6Ftp+5JeNagKXClKd000sktwaJQquXDoSwWcG9vpXNSOgPw
         2eWrO6FqGGgg7Aa3v1F0duCLKo3zcJl0hU7IOwLM+VG6+Dd6NbV6Ok2FIabi7OTd3hMk
         8hUIuOwH6C4Gc6YCdnTcov7vbhmSkhOY76Q+mMC6g19+tduqb7g/fupMtFOcnE/veTC+
         oc5HNXzb1zyUdAjEZ8IzqyPuKA9na8IiqIOnvMyvsI85nQH/PB8AKrq/+lFzGevo0/0R
         vT4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8fxZIPvbaWTA4LTDRO3yf3UHUdrFA72dVuabGehvQug=;
        b=hDltqwhdw96FGqSMy37dv1vbBauyWEqDanKB4sqxXWMy5vYsvifeMi9tFuamXqmCsR
         3d8xzTeFvIU0D3PPNyn32crYui5SD1oyL/87vXAVT0ezQpCtnzzNMox4btSGUS4hnXNL
         m/+00Cicwxf6oSWmaaNB5PhfEMDGLw/XnbV5LdaSBC8CkxZAUt8gOvHYF70nfeeGQrgF
         DZukVREkcM7Fl7c7PoV/STx9SBNzAY2oJuJ5/Nh/J8Y6JxYH3HrHWsbf53lcTkqAc2VR
         5RoJO/1X3Ys8N+YAxWcd/8I+hPrilt6NHFi1iu++TyFRtMqs+2E03gn4IqWATTKjPmOC
         1sKA==
X-Gm-Message-State: AOAM530yvpBNJKxHumJqJFH7XHUaIHstUMh1wfyoWV2b6rhSSBam/35q
	njpOLhb+w/D72BAu+PBM5lM=
X-Google-Smtp-Source: ABdhPJx7tJ5oAXtoOExM6JN5d3vnhW3rZ/GNqgX8u34oACTv+AGTStM59eSY02Calf2M2+iZewT9vQ==
X-Received: by 2002:a17:90a:d901:: with SMTP id c1mr316421pjv.60.1598555679517;
        Thu, 27 Aug 2020 12:14:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:720b:: with SMTP id ba11ls1677057plb.0.gmail; Thu,
 27 Aug 2020 12:14:39 -0700 (PDT)
X-Received: by 2002:a17:902:6b45:: with SMTP id g5mr17401060plt.262.1598555679077;
        Thu, 27 Aug 2020 12:14:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598555679; cv=none;
        d=google.com; s=arc-20160816;
        b=PtQdc+5JnIi/lh/C3m1jkqmO6+nPwVd6GrgqxMA7dy0T8oPcanIVk85cDu4fwEZ/gK
         HFbMZqH+YK+96lKdoPs82GCVQnwpS92WmAXhGyr/5LeE7HAdqCFVXHNsBrPpyuFG7lMb
         kp5CzGKH+b60xNoEQk/b40x18q40E5FeZXWWlzrcvBlx5/Iv982g8nSYxDZDaIHvMkId
         D1OHsSyReh+dUtao0wgozRO9rz6Cvpwg4CCLggYeEstoFunL8azgVfmIXhsMIumgYJZe
         DsLInX5/CT0GcYRC1NsOj2m9bNjjPJ/dgaK6Eq8ylUQWdtsFAHbNjASKYnikXs8xMfYu
         2KvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8EbCOeZ1KrDUva8Qo9ruBWoAtdzcTodwXUPT6QjLJgQ=;
        b=WJmEuMxpsKTt2rjghX/Pfa7SW9uE4hK9t76DkoqESaXT+evJHIA+zjrJNDc1MLDyS4
         19C/Sg+SE0y+ORuw30CVsXbCiSTgFAEKoxV6IbZ8EJsb0dlnKYHtUJTPqFL/rP0NEAVe
         ejkljwD0YZGm7OHe2tAfNg2wS57lEd0nDd33mHPS9ejmSfpacUIiZSyxnxJX2kDkNpzB
         L7ROwDc63aH7DXs/Ebrx8gSJkmN9J/K4/FzOguXCezH0F5R4SLbs3u92PSn5fqxfv1yk
         T3aMW9f7P8uQNbp9ch2nCMVdBVJmfYUm6cJ99zORDYwviDpbw6mH0fSOeVX7nvuBkSLY
         tK2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CzK5MevC;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b41 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb41.google.com (mail-yb1-xb41.google.com. [2607:f8b0:4864:20::b41])
        by gmr-mx.google.com with ESMTPS id u204si213157pfc.1.2020.08.27.12.14.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 12:14:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b41 as permitted sender) client-ip=2607:f8b0:4864:20::b41;
Received: by mail-yb1-xb41.google.com with SMTP id p191so3574690ybg.0
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 12:14:39 -0700 (PDT)
X-Received: by 2002:a5b:744:: with SMTP id s4mr32088872ybq.26.1598555678461;
 Thu, 27 Aug 2020 12:14:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia> <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
 <20200827131045.GM29264@gaia> <CAAeHK+xraz7E41b4LW6VW9xOH51UoZ+odNEDrDGtaJ71n=bQ3A@mail.gmail.com>
 <20200827145642.GO29264@gaia>
In-Reply-To: <20200827145642.GO29264@gaia>
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 12:14:26 -0700
Message-ID: <CAFKCwrhAPrognS7WtKXV-nJN-9k6BW+RWmM56z-urvbWepTAKg@mail.gmail.com>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CzK5MevC;       spf=pass
 (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b41
 as permitted sender) smtp.mailfrom=eugenis@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

On Thu, Aug 27, 2020 at 7:56 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Aug 27, 2020 at 03:34:42PM +0200, Andrey Konovalov wrote:
> > On Thu, Aug 27, 2020 at 3:10 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > On Thu, Aug 27, 2020 at 02:31:23PM +0200, Andrey Konovalov wrote:
> > > > On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
> > > > <catalin.marinas@arm.com> wrote:
> > > > > On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > > > > > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > > > +                        struct pt_regs *regs)
> > > > > > +{
> > > > > > +     report_tag_fault(addr, esr, regs);
> > > > > > +
> > > > > > +     /* Skip over the faulting instruction and continue: */
> > > > > > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> > > > >
> > > > > Ooooh, do we expect the kernel to still behave correctly after this? I
> > > > > thought the recovery means disabling tag checking altogether and
> > > > > restarting the instruction rather than skipping over it.
> [...]
> > > > Can we disable MTE, reexecute the instruction, and then reenable MTE,
> > > > or something like that?
> > >
> > > If you want to preserve the MTE enabled, you could single-step the
> > > instruction or execute it out of line, though it's a bit more convoluted
> > > (we have a similar mechanism for kprobes/uprobes).
> > >
> > > Another option would be to attempt to set the matching tag in memory,
> > > under the assumption that it is writable (if it's not, maybe it's fine
> > > to panic). Not sure how this interacts with the slub allocator since,
> > > presumably, the logical tag in the pointer is wrong rather than the
> > > allocation one.
> > >
> > > Yet another option would be to change the tag in the register and
> > > re-execute but this may confuse the compiler.
> >
> > Which one of these would be simpler to implement?
>
> Either 2 or 3 would be simpler (re-tag the memory location or the
> pointer) with the caveats I mentioned. Also, does the slab allocator
> need to touch the memory on free with a tagged pointer? Otherwise slab
> may hit an MTE fault itself.

Changing the memory tag can cause faults in other threads, and that
could be very confusing.
Probably the safest thing is to retag the register, single step and
then retag it back, but be careful with the instructions that change
the address register (like ldr x0, [x0]).

>
> > Perhaps we could somehow only skip faulting instructions that happen
> > in the KASAN test module?.. Decoding stack trace would be an option,
> > but that's a bit weird.
>
> If you want to restrict this to the KASAN tests, just add some
> MTE-specific accessors with a fixup entry similar to get_user/put_user.
> __do_kernel_fault() (if actually called) will invoke the fixup code
> which skips the access and returns an error. This way KASAN tests can
> actually verify that tag checking works, I'd find this a lot more
> useful.
>
> --
> Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFKCwrhAPrognS7WtKXV-nJN-9k6BW%2BRWmM56z-urvbWepTAKg%40mail.gmail.com.
