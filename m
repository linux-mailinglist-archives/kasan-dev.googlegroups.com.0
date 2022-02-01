Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFO4SHQMGQEYSYNG4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id C1EB24A5B04
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 12:18:33 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id n8-20020a4abd08000000b002eabaaab571sf6422240oop.11
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Feb 2022 03:18:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643714312; cv=pass;
        d=google.com; s=arc-20160816;
        b=OBI88oahWE60bYwHS/OApvj+8EiD/1fI+vCH3L91oGMjXfpkA7nJXKsuJIfsailnD8
         3TfkkXqe6MK0RA+YKuwCiyeThiFqKiQRs4jTAjh7cU73PzZTWPvy6W07PHL2vqnrOQ0Z
         ZD+Zqrp01ixHcm6toGxavApZlVKaRwm+pvu0HGQPanV9sz3Fu9hpW8vMXJkOwixFf4ML
         eTXI+XhpqMmuTocOZhz+qjo2XqH1/Q3XxiYQCOgnDTX2FSZdJGsb4PnUp8uB1Vf60m/I
         yqRafKnH8CI1zHcWMuVEZrCb2+N0m0uaZJoxtZKtgKYI8hQo7iz+Fcj9AJl8/6c8SZzv
         2Qhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=56kkwoQ6SeRSJ3Pf/1g+gY1ZJ6fCcLlopYbxgqEMuQg=;
        b=oPFpdzsmzCdEyLp7oVYw9xHmHoLplE3iSnoxrClyiCXyPB1H855o3MQPGQFssk9Fk1
         9St5ubPXixiiy5rabGIu1J+gxhMx4CQ9ijkYFN1ETFiWQcCwGNgy1EgUjF2ch4bmYPfX
         6PTVzrVMK7zsxxEPkZlCotr41YXpLf05p6x95wCdgLFLYNzkFdwxg7TIqe3YZe2C+U4+
         mSENWoRaJESRonHSnuPJjEbKcOoK/+PNeAF3pwz5AIZqsNbgdtXd1SzvHc3JRTWjFBL9
         Sfz43B381YqLCtja7E9tUVSSUXlqY7r0raOBqb0ljs8hKAGYSV2cNm9hUTZiOevKAMt3
         tEdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hKzVGBGb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56kkwoQ6SeRSJ3Pf/1g+gY1ZJ6fCcLlopYbxgqEMuQg=;
        b=f95LGHRfC+kgOvOmHV0fgH9etMVA4kYTyi0TFbMgrKUfpeX5YjfLbcijatyKulodr1
         x9roL0qvS6zhiwu5ySmmcQhjzg3LYof7N9iuKHv9jNwBNRa+KuFqtoGi+b08SJT148LF
         UqDWt0Z1qSU7SqRETRO+we0D6s4FyNX/CDtgvFkHdAygXPp735B2Ji5mV8Z3u5L305Kr
         pXXx8gWbKOwQfHSeP9TzIUwp1ygWj+dJRdGd+I3LTB2vwMrl2SUPRc2xGLdD5PbRnhpj
         fecehCJBhBw2ii+NtiDVEzX4epdvAFWB28SjsOciycp9+gmnEvIcOLFJqXp4FTg90ZND
         9PHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=56kkwoQ6SeRSJ3Pf/1g+gY1ZJ6fCcLlopYbxgqEMuQg=;
        b=cH2vKjnEU3igb8fLC0OsT9ysTCuQzpkMSCwxgvkUZyBi4VYj77h+xCcRwZAO/2j1C5
         IZLKqfpSXw0S7DZ3qGnyfsJddb0JUAz/3VG+j5ykjUfrfCY6XhaFz7PCukrmFpuzqPMj
         B7BjrcGa+RfHp2DiqrkE1I0jBWoLJHMFIafz/w8V5pxTDOsjP/KF+Agda20KKvcRvGvu
         NLe+FMAazxkaGKJjxvxgTfW+p47oS7/TvutkXVySoNle6C9kHPMnt2is172r35ecBNYW
         RvOL5cx0WSuf61UkkmNUqIUS2UBx3a3WmtuREIcFGaFRhKJWVHw+R+lNPGMfqAyj6X2n
         a6pw==
X-Gm-Message-State: AOAM532+dUqC/82ykClCo6TnCIxMwkXqp4xRWaAeQZnSG9ZxB7XMQRy2
	D/zW1ztSpSGNqTCvzJi4gRA=
X-Google-Smtp-Source: ABdhPJyfJw5huUIp599Pwz93yVjM3fk2lzUkqXZkJ27STkKTkEN5qyXybWSB9GoqAY/Ry3MWJPqFAg==
X-Received: by 2002:aca:e003:: with SMTP id x3mr777025oig.155.1643714312417;
        Tue, 01 Feb 2022 03:18:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:128b:: with SMTP id a11ls7849179oiw.0.gmail; Tue,
 01 Feb 2022 03:18:32 -0800 (PST)
X-Received: by 2002:a05:6808:15a1:: with SMTP id t33mr812887oiw.254.1643714312081;
        Tue, 01 Feb 2022 03:18:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643714312; cv=none;
        d=google.com; s=arc-20160816;
        b=yhXag5rmtrNovcO6/XzcnOE+lp61Ud54H7Oo/lncYsBfOr+0hQCOEy3WOnNYVna0GJ
         AKOlRBCyu+yRH3ceeomCeXbGpUvYwXhPaxfziL7QVa8T2hKaIkh6jsXyTL/I1qVCSt8P
         1VsGE0LnCq/MWWzczF/pr8qhmZjTCx4iMfAF+fR3RKH3u2hUMMWwEvW/Ii1g6SbDYDxL
         Q926dRygXEZ46OT4a799wlDcRsEPWBsjnYDpwEUQ3jtPF4E492vgeAJ+9vH2ETz4Yjr2
         /CiVqnq4ViWlVQl3OaLjl5v1A+7rRf/KY3T1x2Xxis//EfByxVEP0lzsIUS3DLQIC3fM
         xwqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pcT8Frn0n3Hw9SbN/loP8iSe8IeaLdSI0AOmRzA0azM=;
        b=NHWYHSEM/ikZSOEmhfh6KbFXoDq4GOuvJdXdN0CqO/UUP+vUsHCwhzdt1PwdVKrZHL
         8v0ZDIa4oOySUe6hZp7pMjcPrkoI48oQtOcD5d/bDhpc/+mPcTExfBbWKjRxihqGKaf5
         iB09Q9JvwElWNmLzht3Q8g73bEd0mKctVMjcbKxeR6sBU07PkBUhr+Q/y1mkj07gxSnx
         awDFAQlY94qIjRDPdk46ISfTcGijG3DY/igEPeGpVbAvFJhP+cLuzShsk5FkVDwRgeg+
         8piupdZ+wp8aa9PI3I6Cj2dNToem0COIJet46xH1YqTha32T5+vZvmCaAstrdALGxnbF
         GyKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hKzVGBGb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id u43si2232524oiw.2.2022.02.01.03.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Feb 2022 03:18:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id m9so32493289oia.12
        for <kasan-dev@googlegroups.com>; Tue, 01 Feb 2022 03:18:32 -0800 (PST)
X-Received: by 2002:aca:2b16:: with SMTP id i22mr746926oik.128.1643714311558;
 Tue, 01 Feb 2022 03:18:31 -0800 (PST)
MIME-Version: 1.0
References: <20220131090521.1947110-1-elver@google.com> <20220131090521.1947110-2-elver@google.com>
 <202201311315.B9FDD0A@keescook>
In-Reply-To: <202201311315.B9FDD0A@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Feb 2022 12:18:19 +0100
Message-ID: <CANpmjNPvyKF2LiZAzTOz0mvbxPvJW_a7ysJ3n_kcHYvHXxpw+g@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] stack: Constrain and fix stack offset
 randomization with Clang builds
To: Kees Cook <keescook@chromium.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Elena Reshetova <elena.reshetova@intel.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hKzVGBGb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Mon, 31 Jan 2022 at 22:15, Kees Cook <keescook@chromium.org> wrote:
> On Mon, Jan 31, 2022 at 10:05:21AM +0100, Marco Elver wrote:
> > All supported versions of Clang perform auto-init of __builtin_alloca()
> > when stack auto-init is on (CONFIG_INIT_STACK_ALL_{ZERO,PATTERN}).
> >
> > add_random_kstack_offset() uses __builtin_alloca() to add a stack
> > offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> > enabled, add_random_kstack_offset() will auto-init that unused portion
> > of the stack used to add an offset.
> >
> > There are several problems with this:
> >
> >       1. These offsets can be as large as 1023 bytes. Performing
> >          memset() on them isn't exactly cheap, and this is done on
> >          every syscall entry.
> >
> >       2. Architectures adding add_random_kstack_offset() to syscall
> >          entry implemented in C require them to be 'noinstr' (e.g. see
> >          x86 and s390). The potential problem here is that a call to
> >          memset may occur, which is not noinstr.
> >
> > A x86_64 defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> >
> >  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> >
> > Clang 14 (unreleased) will introduce a way to skip alloca initialization
> > via __builtin_alloca_uninitialized() (https://reviews.llvm.org/D115440).
> >
> > Constrain RANDOMIZE_KSTACK_OFFSET to only be enabled if no stack
> > auto-init is enabled, the compiler is GCC, or Clang is version 14+. Use
> > __builtin_alloca_uninitialized() if the compiler provides it, as is done
> > by Clang 14.
> >
> > Link: https://lkml.kernel.org/r/YbHTKUjEejZCLyhX@elver.google.com
> > Fixes: 39218ff4c625 ("stack: Optionally randomize kernel stack offset each syscall")
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Thanks for the tweaks; this looks good to me now.
>
> Acked-by: Kees Cook <keescook@chromium.org>

Kees, which tree do randomize_kstack changes go through these days?
I've seen previous patches went through -tip via Thomas.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvyKF2LiZAzTOz0mvbxPvJW_a7ysJ3n_kcHYvHXxpw%2Bg%40mail.gmail.com.
