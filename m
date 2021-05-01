Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA65WSCAMGQEGHU5NNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD3E93706DA
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:33:40 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id w10-20020a056830144ab02902a5baf885d0sf356744otp.15
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:33:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619865219; cv=pass;
        d=google.com; s=arc-20160816;
        b=hqk4ziVhqvEu1sb6L3iHRZYAHCUyOXkqjrmhJ7CfutfxiIdVDnJcxxmbzjLZuT+cb0
         InST9Qh1xOLTQ+Ti5IdThMO2sVuQUV/GiWVPbVExtcS4a9aJWM/43awOPJbEH8w07xhC
         NHzcaGztySH6958/aFsLQOGXJj7pjol8OH4ORKpgYVB79Mem3xfBOJ740Y+UKJF6+IKP
         gDtrmNqvmI3wloaNYqvn0tCzQ9U0fz6qi++ahDTQr1YvNu8bnUgquC2UXJyJXvRhqE3U
         CQ5dKaGVuQV1qwmv47YBKLFEMeBe8zjBNmFvDsHSnalbA8inUut2ZBFw89y5w0murAb3
         v7+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M+6T6zbXSkQlwecvV+gcDajMm+xFBJnqxn6sVMBCpCE=;
        b=VfRWjHYTGKlGhhTl3WI2b/TIkzZnU5jNWilR0xiZmL7xjNfE+2br7xNs7NON1smT4F
         T2W890zccUTyolH3PzgTK4e/lFACb5vrMO0G1aDwgPu5v7TOhLuSTWuFURGzlbYjO7Ka
         YraBe+tWBvLT9BllXHyGHXXlb4PNARLbnuMUfbC/mPyw/FZ5SSpRI19bsz8tlhvRBS72
         27ksUNar3GJpsd9+LrF6W7ll8eQBp7OmJMiSq1+YNqYaxOLqu073hWPaglORs83gcbP2
         8IOX9+VlYCp91zObPD4vOcAE9VtSgN0sCQd7VCNefuoLUbncvltH7A2JrvCsDYiHpOe4
         WRLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q3Ci9b94;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M+6T6zbXSkQlwecvV+gcDajMm+xFBJnqxn6sVMBCpCE=;
        b=ksupp1tQ3rfa8CSr42JQd+Chnrodad582NMPC+8L8fr4+6aL+f6tXq52WRLlcQGh+Z
         iQXvO8FDWW6L+vNUnQ1lR/IB7W6BezUQqBJcjgKVuJoTYlf+FszzcbqfAoXqjZTXCGyU
         UsVnEKmmN5BTfonIv0faRj2g3sFzlL9FYRmVzB1+o9OlQFh2fknpuwgpN+jzyOwUzwhR
         5KQr5y82RCnVbGMfo7BPB+H6mQDYJmzUlooLrVkAWZcfmH15VAtV1dGrzm0V11lVHazK
         ygF2Dxxl6ze8fxhHI15aU9i0BmSXQzbCS2ZZeikNINcRpeN97fW8Iln0FXEszg4cV4hx
         /0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M+6T6zbXSkQlwecvV+gcDajMm+xFBJnqxn6sVMBCpCE=;
        b=g+ewdBJyuXz1EVmWFO0tgtplPVKSy987jEsRIgScNHw7D6HXIwRHnbeYU9GjHG4Yl7
         9kUnnlGmLVxaUcnVK/JLxej+UtWdH0rTVuq3zzatfMuAOSPXmS2qsNu7cFkZMVvGk63n
         dvVKeSVxjjKqZnoi59S4WII6obPZfekN6xllpLAt5WuK5C5JOux7yUcRCn//+LZjanAr
         QZrwgHPcELqJPReAQZ+sdc0MNf4nO//JYKfanqwcbzS++Q1y451s0bV9AngxCq9dGv7q
         ye5/mPwrkUyW7kUR+smVXR1a2PgFY7RIpvnFqNEIZjgV6QVlXSbjiREAYEt54EYrYhJg
         UinQ==
X-Gm-Message-State: AOAM531jCH1Q+aaYOu0eU+YHd4pRlnPZHVo8F6C3A0FPujtHhTE7zZFR
	Or5Ai0Xp4lFPR0JXIkg1Gnw=
X-Google-Smtp-Source: ABdhPJyZl7me5LzCdK9C4S5XrJQ3mCTgi/JfRYNxtKVC5rBhf5m07TwoKOrrzPSI/xbmVzm372WLVg==
X-Received: by 2002:a4a:a223:: with SMTP id m35mr8027642ool.39.1619865219515;
        Sat, 01 May 2021 03:33:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:f0d:: with SMTP id m13ls2546549oiw.4.gmail; Sat, 01
 May 2021 03:33:39 -0700 (PDT)
X-Received: by 2002:aca:af8d:: with SMTP id y135mr14179760oie.66.1619865219135;
        Sat, 01 May 2021 03:33:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619865219; cv=none;
        d=google.com; s=arc-20160816;
        b=uGC/gGZT5VqI2AXE3DlTcVfXNuIINEmV1IyjYnjzU9k8BDAlw088IKYxxUfBrRrXwa
         9m4EXcLi0FgRYtcF53/iHHbtEeetHRRUl3nadLgWELCkB4NiRrpwnymQca4dupmZJbr7
         HU6UgraIjhTCh7sPUCTxiJP54Z7rDkJMhdheuM4sibJPfi1wVRP0dp/9aKUBn5qaGRFL
         bWOOr+trcxPG4QGqnRDhe9kCDvvoO9oujI23Ig2CCdy+iU+DmEn2nH3KfNnGPg6/PV+A
         d5o32v+HjnwiHsCwW+AK1F6N2a8nc05SZA+m+rITiRk2ykx13cgmfaC+sd2dBi3kDpzy
         0ixA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hdaqve5YvScbUJtoSM3sAOiUvwbsjnuFfVlCkD3R0H0=;
        b=ImNNnJ1A3SAT0Eqh8UZgB165KaVbzGIIVTGjR/fEyxBGaCAEz/hcUgbtvTUXCPX7Ob
         BXSvsssrRglqkYvggX7ZSIGmtebTzk39JbkoiERa+3KIwDZhpBaDFzWOn16XXQBarK1X
         cJpyXbUErM/FICXPqrGDHxqLP8e1kWtkCe2fCHlab7Du4ZEmBBKKNd0udVnsTs2gA8Ub
         jgh1oXB/zZKzYIbFhqMld2buRYkAkM6FrCDifSQJ+yTmo88B1tEBIFWiVRacIl82B8vr
         Q9F9EG8bDjK7eDUfQkoDcqkCKSX8ddeS0mSW3uIi/DkSP+bQtlC44VKznXVFnR/OzHfT
         vDpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q3Ci9b94;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id w16si927501oov.0.2021.05.01.03.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:33:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id c36-20020a05683034a4b02902a5b84b1d12so433600otu.8
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:33:39 -0700 (PDT)
X-Received: by 2002:a05:6830:410e:: with SMTP id w14mr5442391ott.251.1619865218745;
 Sat, 01 May 2021 03:33:38 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1o8dvs7s7.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1o8dvs7s7.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:33:27 +0200
Message-ID: <CANpmjNNhd+qAy7tPSu=08_y-BZiowKigVkOh6HnXsxhWYuFpJA@mail.gmail.com>
Subject: Re: [PATCH 2/3] signal: Implement SIL_FAULT_TRAPNO
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
 header.i=@google.com header.s=20161025 header.b=q3Ci9b94;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Sat, 1 May 2021 at 00:54, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Now that si_trapno is part of the union in _si_fault and available on
> all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
> return SIL_FAULT_TRAPNO when si_trapno is actually used.
>
> Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
> and have the same code ignore si_trapno in in all other cases.
>
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---
>  fs/signalfd.c          |  7 ++-----
>  include/linux/signal.h |  1 +
>  kernel/signal.c        | 36 ++++++++++++++----------------------
>  3 files changed, 17 insertions(+), 27 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 040a1142915f..126c681a30e7 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -123,15 +123,12 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                  */
>         case SIL_FAULT:
>                 new.ssi_addr = (long) kinfo->si_addr;
> -#ifdef __ARCH_SI_TRAPNO
> +       case SIL_FAULT_TRAPNO:
> +               new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_trapno = kinfo->si_trapno;
> -#endif
>                 break;
>         case SIL_FAULT_MCEERR:
>                 new.ssi_addr = (long) kinfo->si_addr;
> -#ifdef __ARCH_SI_TRAPNO
> -               new.ssi_trapno = kinfo->si_trapno;
> -#endif
>                 new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>                 break;
>         case SIL_PERF_EVENT:
> diff --git a/include/linux/signal.h b/include/linux/signal.h
> index 1e98548d7cf6..5160fd45e5ca 100644
> --- a/include/linux/signal.h
> +++ b/include/linux/signal.h
> @@ -40,6 +40,7 @@ enum siginfo_layout {
>         SIL_TIMER,
>         SIL_POLL,
>         SIL_FAULT,
> +       SIL_FAULT_TRAPNO,
>         SIL_FAULT_MCEERR,
>         SIL_FAULT_BNDERR,
>         SIL_FAULT_PKUERR,
> diff --git a/kernel/signal.c b/kernel/signal.c
> index c3017aa8024a..7b2d61cb7411 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1194,6 +1194,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
>         case SIL_TIMER:
>         case SIL_POLL:
>         case SIL_FAULT:
> +       case SIL_FAULT_TRAPNO:
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> @@ -2527,6 +2528,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
>  {
>         switch (siginfo_layout(ksig->sig, ksig->info.si_code)) {
>         case SIL_FAULT:
> +       case SIL_FAULT_TRAPNO:
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> @@ -3206,6 +3208,12 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                         if ((sig == SIGBUS) &&
>                             (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
>                                 layout = SIL_FAULT_MCEERR;
> +                       else if (IS_ENABLED(ALPHA) &&
> +                                ((sig == SIGFPE) ||
> +                                 ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
> +                               layout = SIL_FAULT_TRAPNO;
> +                       else if (IS_ENABLED(SPARC) && (sig == SIGILL) && (si_code == ILL_ILLTRP))
> +                               layout = SIL_FAULT_TRAPNO;

The breakage isn't apparent here, but in later patches. These need to
become CONFIG_SPARC and CONFIG_ALPHA.


>                         else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
>                                 layout = SIL_FAULT_BNDERR;
>  #ifdef SEGV_PKUERR
> @@ -3317,30 +3325,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 break;
>         case SIL_FAULT:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> +               break;
> +       case SIL_FAULT_TRAPNO:
> +               to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_trapno = from->si_trapno;
> -#endif
>                 break;
>         case SIL_FAULT_MCEERR:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_addr_lsb = from->si_addr_lsb;
>                 break;
>         case SIL_FAULT_BNDERR:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_lower = ptr_to_compat(from->si_lower);
>                 to->si_upper = ptr_to_compat(from->si_upper);
>                 break;
>         case SIL_FAULT_PKUERR:
>                 to->si_addr = ptr_to_compat(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_pkey = from->si_pkey;
>                 break;
>         case SIL_PERF_EVENT:
> @@ -3401,30 +3401,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 break;
>         case SIL_FAULT:
>                 to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> +               break;
> +       case SIL_FAULT_TRAPNO:
> +               to->si_addr = compat_ptr(from->si_addr);
>                 to->si_trapno = from->si_trapno;
> -#endif
>                 break;
>         case SIL_FAULT_MCEERR:
>                 to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_addr_lsb = from->si_addr_lsb;
>                 break;
>         case SIL_FAULT_BNDERR:
>                 to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_lower = compat_ptr(from->si_lower);
>                 to->si_upper = compat_ptr(from->si_upper);
>                 break;
>         case SIL_FAULT_PKUERR:
>                 to->si_addr = compat_ptr(from->si_addr);
> -#ifdef __ARCH_SI_TRAPNO
> -               to->si_trapno = from->si_trapno;
> -#endif
>                 to->si_pkey = from->si_pkey;
>                 break;
>         case SIL_PERF_EVENT:
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNhd%2BqAy7tPSu%3D08_y-BZiowKigVkOh6HnXsxhWYuFpJA%40mail.gmail.com.
