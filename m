Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYVKZOCAMGQEBDMCZ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E46DE374378
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:26:59 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id n22-20020a4ad4160000b02901e94af54f75sf1490967oos.17
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235618; cv=pass;
        d=google.com; s=arc-20160816;
        b=txf4YwOOiyIZH9z72XAEnaLofgzbNDBO7N1lvBQS/4TxwGCoiydiUb6p8NOqvD3DoN
         yJXJKO4ifD8JwooGe1xw0CQ5w7wVTGjqFr6osiLy2kkRc+Kyk8/QiXv3CjKcUCmckKfq
         QkDHb88ecNrSJftvwzEUD4Di7MvTOQDmWgV72jUkXSMCwfIs/QqPyaC+h3slErTh8cFf
         eQwVp6kotYWGFD9Dz3wvXILe6VfFjFskQ9EErsU6j1LLA8Bd1L9zS3cqvhYXHxpRaWdw
         ZmMuw34K3NUtzx0uOtR1q6Z+Z0JS7dq8rLDLj1LFvCWRJqzd9ieot7O2eZ4PT5Q0hWs5
         ueMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GsHIj2wGfzzFa3Z6tAL3SJNZP/Z3KxAVyvZXqJl9anI=;
        b=Wlod2hGKst9fNxru4RGCeKPKsW1smql/iVKp5uq6dL75QLGml9Z4WZSQvOktmro7x7
         4Yg4cUztR5NHON6QhJ6VyzbMFnoqpTn4zzPVBKc9eya5k5RLQk3+wMDPkCh5YO+vPP8a
         gIJBV5hIW7Pxtyp0Yry/QurtDJGEw4u8PqufFlAdnhS3AiWhO4fPpK5Q6sg2MWJKlUNU
         VgYx2RWga5WOc5JTSMttCK126TItVJygR6/VxP6jtaH87P5vnYkRYV4K5nzWmI2gtk24
         corluzgJdJvfaR5X3zatITmA6cuB6suNbk9YlQLhK4AQFct2JNwGmwGzzY8sVPaBY2LS
         AtNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ICjc38Q5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GsHIj2wGfzzFa3Z6tAL3SJNZP/Z3KxAVyvZXqJl9anI=;
        b=IMNNJ7JoeMI20okksGxoTOl8/pXegANkDeGl7Ndz2V0W7qBd1t5Nq2hk2AjGwvYIz9
         QOiHbShqpBiW9XiLo59QbEBlUJAv9P/X/yPc91q5L9cDqlOIDDMMJETorf1bORo9v6s0
         GSxfzDwMwjZIrFA/sT+NtThIlbELX7idoEnRJpblSqMk7FNUuG1Atofzcgz0+gubKeAX
         9HdeyNbTyZ8pEu6uG0akFVphsatiLGa3GtsbgtuH2JQ4CxJR0xAODnPxk5m7mSJtjJjy
         umqj8HKl+HQttN6dC/wVeks198/YY7kzxgfGAnoWhQMR84ryvLJcv3z8cCFHHLCAIek/
         uKHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GsHIj2wGfzzFa3Z6tAL3SJNZP/Z3KxAVyvZXqJl9anI=;
        b=SrPsymZ+IUaBHFd63Q7bKa8mjwcDAvHivgxcExSbDNidW0GqOafULLN9bObaVzuiG2
         Vq1ew5Q0LqD27HGvdKTJMl2WuidDN0AdaCtgULcA/xLgnwZLdag077qijhix2VQcsaTq
         puWGJMWgaAWGrpJjsUUOAg4piOeIahvwP+l5cKKMlmTMM4a06WF0CMsvkTsLINTHbuNf
         ptafBhFGIzCutgt4ibTB7U2Uac1teJj4EAKWrbwl7J1orFBv4+5hA8bN5uUzNxCtohN1
         Dyh28XIxhTd81ThAWF4HTVcsat74p5X4vP9zEvhmHaohORvJSJc+MnKoLiCZF/99KvEO
         XmHQ==
X-Gm-Message-State: AOAM532CdaLaAVBPZ1X69blRx5EyLAxK8WnapghTtopcSuMk9lHMaUUc
	tOEgyN2VkG0FVNn1ZoHamKI=
X-Google-Smtp-Source: ABdhPJyRgueGqQf/Y9ZFqB6GF2FdZczBRWiNDszmc912UEkvz1ekMrCymZ53ZTeBWCA+cAXkmwQC5Q==
X-Received: by 2002:a9d:4b0e:: with SMTP id q14mr16564002otf.254.1620235618709;
        Wed, 05 May 2021 10:26:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:200d:: with SMTP id e13ls3277137otp.4.gmail; Wed,
 05 May 2021 10:26:58 -0700 (PDT)
X-Received: by 2002:a05:6830:90b:: with SMTP id v11mr23626183ott.110.1620235618147;
        Wed, 05 May 2021 10:26:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235618; cv=none;
        d=google.com; s=arc-20160816;
        b=avx1NghraZio/t7rgXTBVvb7c9KvrcOKSnouJwNbXAV35Gw37kRCDVvb5KyUq4Vum0
         d1Z0kE7Q1goFrHh5qXh4OdPflFHmaHYbGEQjM0EUHTtpe0TQ/jbah6owOB3ayLPJLjC2
         jg+q0HGzibXX+uN6aKAWufufeTaKRDGHH27gkp93q1v18JizPym3zPD8fAaQnw/zRJjH
         w8gqJsPV+jQsFVV3Bftr6hFLgclD0LbyKgxvqzu6SEGCzJy5AnIeQtlQEd+Wnkck9k+t
         yAtTSUpFJhMfs6PMklvgJ+iLgIG8EqMbApdhli+QJGd+xM7iH/cnnsDNAd2WD8W2sq2q
         7JXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yGF+UlpouxsTqR+y6ELaKPFA13FXOGSdqkaJj7UR80I=;
        b=MjbnZOfTnW2aL/EPS7hml60TY/RgWKzlM7H03/BWj/eSP4Oc/xS37cYsrZk9CIkQy5
         zB7fEY9wYz79yPWxNSaMA0cv0CgxIvVIHVTiBsylFZ4nOlNgQAIcyOmmaSTjzJzJFa7M
         kSowVwiAuIKls85XgUFsDAGTG9C3ein01VsNX2SSY/G5OCxR79awKAWATvK4zG9coHY5
         gCEfw23a6sJ3WL0HdoEEE5ttQbvuolQ1MlLdAGOIiS7/GOBiilGvPntd2ejcaDWoYUsb
         umI75DEP0vmNQVGd7OmFQkhQqqIX2Qzje3YM/g7PyZFmtTVJaMtL9PHpUE1P84PmnaP7
         YabA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ICjc38Q5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id a5si587319oiw.0.2021.05.05.10.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id d21so2852020oic.11
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:26:58 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr11265oia.172.1620235617658;
 Wed, 05 May 2021 10:26:57 -0700 (PDT)
MIME-Version: 1.0
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org> <20210505141101.11519-1-ebiederm@xmission.com>
 <20210505141101.11519-6-ebiederm@xmission.com>
In-Reply-To: <20210505141101.11519-6-ebiederm@xmission.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:25:00 +0200
Message-ID: <CANpmjNOVC1ExjUaGkN1xFKZSeJSweN7tJmapc5QLUXemYnQbaQ@mail.gmail.com>
Subject: Re: [PATCH v3 06/12] signal: Implement SIL_FAULT_TRAPNO
To: "Eric W. Beiderman" <ebiederm@xmission.com>
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
 header.i=@google.com header.s=20161025 header.b=ICjc38Q5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Wed, 5 May 2021 at 16:11, Eric W. Beiderman <ebiederm@xmission.com> wrote:
> From: "Eric W. Biederman" <ebiederm@xmission.com>
>
> Now that si_trapno is part of the union in _si_fault and available on
> all architectures, add SIL_FAULT_TRAPNO and update siginfo_layout to
> return SIL_FAULT_TRAPNO when si_trapno is actually used.
>
> Update the code that uses siginfo_layout to deal with SIL_FAULT_TRAPNO
> and have the same code ignore si_trapno in in all other cases.
>
> v1: https://lkml.kernel.org/r/m1o8dvs7s7.fsf_-_@fess.ebiederm.org
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  fs/signalfd.c          |  8 +++-----
>  include/linux/signal.h |  1 +
>  kernel/signal.c        | 37 +++++++++++++++----------------------
>  3 files changed, 19 insertions(+), 27 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index 040a1142915f..e87e59581653 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -123,15 +123,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                  */
>         case SIL_FAULT:
>                 new.ssi_addr = (long) kinfo->si_addr;
> -#ifdef __ARCH_SI_TRAPNO
> +               break;
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
> index 65888aec65a0..3d3ba7949788 100644
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
> @@ -3206,6 +3208,13 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                         if ((sig == SIGBUS) &&
>                             (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
>                                 layout = SIL_FAULT_MCEERR;
> +                       else if (IS_ENABLED(CONFIG_ALPHA) &&
> +                                ((sig == SIGFPE) ||
> +                                 ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
> +                               layout = SIL_FAULT_TRAPNO;
> +                       else if (IS_ENABLED(CONFIG_SPARC) &&
> +                                (sig == SIGILL) && (si_code == ILL_ILLTRP))
> +                               layout = SIL_FAULT_TRAPNO;
>                         else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
>                                 layout = SIL_FAULT_BNDERR;
>  #ifdef SEGV_PKUERR
> @@ -3317,30 +3326,22 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
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
> @@ -3401,30 +3402,22 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOVC1ExjUaGkN1xFKZSeJSweN7tJmapc5QLUXemYnQbaQ%40mail.gmail.com.
