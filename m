Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7O5WSCAMGQE4XRDSRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id E41DB3706E5
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:35:42 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id i10-20020a17090a650ab0290155f6f011a9sf914227pjj.0
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619865341; cv=pass;
        d=google.com; s=arc-20160816;
        b=RRJcABHG5MJhqMbZ62H9MoQ7Lnc4shildZ1BM968O0F6FHjKUFsOj+uOA7z4ewJeF1
         YoEwfy1QO6LvpuwayNAZ5ZXVIg/h5litC5D83Njoi9VAQMGdqnt5s72jbCYvZcvfGn+R
         0cbo4LPbmod5OxsS/zMyhgDo3B/mr83DG2+45Y1Xo+4gT0KZREV1VWCbK5zCxDh4pKuX
         LMuf+Mvg4XwaN3aRL07m60mTA4t7cbO1mnbK6NOMpNsRcAakurGD22uZ1lr5sKsyLLc7
         hXtmqxRrAvOJqlBvGQXGTGOdWgD66iSBXMiTLw9SSQk2cf0PW75QSvswo9SEx3UJJ6/V
         8uIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UBeyUiqw040Nw99uCUjsnBv2KlGu/trdNPoChXa3s0M=;
        b=osItfGXfa/L8+/zSuWwgDvJtEdpVk49cEoDCCgBgS6sVx8nwkPWyxgHZzoiOYIpPnf
         xJ5zBgeNsHPd5cnbjew5TEOWv4MsMilHmTG4mO8vYeS80mmsN7fOHVHEj2N8b4HUz0z+
         BEPE1kYGL0QCHojGSQiFp5DOog/Xi442GDYQA9VQfxZ+WubLeUJOqIbeWjNenEvordoj
         H4Ei21Uup737JSappBdxL6HBkhD7YrcIRU3IEHnjWT438KSO0cakBLYfrxzlZEpiOkRp
         hFoRh/BqLE9+deERsUFOBVZmWgrCtxFJ5uvXdDFfxQqouMAtA+tJXVbOZtXfKf7xhNIL
         cf6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Fi/veP+r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UBeyUiqw040Nw99uCUjsnBv2KlGu/trdNPoChXa3s0M=;
        b=rrO8gT8igC/ZhX4+XamHijDxYT401K3xO3TXO2KSsJuk7cRBJ9pYiDw3Yuj5D1AYq5
         XOM9cSJ7xCF8nfWUM26fWjYzDIYRpvCb9NqLbbJcuetecEHzdAAkQ0/DLU1d0bzdtK4q
         ufka73Qj2epN9JX9pxz+xGp3/d2T8N5XOTJGZdUQw8wSTQQ9q8guVLfs1pbVPzST9D5f
         W5BBCwwVThBOxfv93L09sJZ9OBRXF4mpUl3iRvlQvShrdPB7qpKMXRmkAt4rovZE8LuH
         ETb92WRKpKS4jaH4XH2QzKLlMbudVyko0WUmRrQQQoRgr/71su+qzxJH/CSJJgHkh0WD
         mqUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UBeyUiqw040Nw99uCUjsnBv2KlGu/trdNPoChXa3s0M=;
        b=qpuhpPnXg4A6S3wxE1jKARQPzMYlY57IP06AFbcTeVVLflefcqcKBjhvnmIb/WDd2k
         ivv3cCyC0YbkFN8JMiIQ5kFEotN903dnrgZbrYWpLo6ShFf56nHPkzRKytIN/NfzR+p8
         RR4BOUQofSHIZ/6igphRR24ZucxGsCMn2ksZDsGfZRUNiEpYZzrJii2Yhdhd+MF5fE3C
         6seeA4FiIJJmOS2spAMtxdz4kB6gr6ODHePkr1lwFsDGDJ4+Mb5qYAXRiKzKUeXEtm/X
         bekEuwE8KN1jeAUWEfz9Ipy7QWUuHBeis0FtRv8AxWEHfrMZIVkKhFEA6341ilD0mHbb
         i1Wg==
X-Gm-Message-State: AOAM530jUDSU8w+Ic9oZ3esyDUsHZXo8SDvyT72/fyqDzG+hFDwYNgYC
	OVbIgMsGl16CeqlauKpMLC0=
X-Google-Smtp-Source: ABdhPJw4LrVBqnqIUxu9wrVAphP47VLXXxg50qxKLPbvXu/8nWCWKr4E5K+363GkaL+Jqu5yo/UkRg==
X-Received: by 2002:a63:da0a:: with SMTP id c10mr8913387pgh.255.1619865341441;
        Sat, 01 May 2021 03:35:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e84a:: with SMTP id t10ls2967905plg.9.gmail; Sat, 01
 May 2021 03:35:40 -0700 (PDT)
X-Received: by 2002:a17:902:dac2:b029:ec:7fcb:1088 with SMTP id q2-20020a170902dac2b02900ec7fcb1088mr9824305plx.65.1619865340797;
        Sat, 01 May 2021 03:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619865340; cv=none;
        d=google.com; s=arc-20160816;
        b=sQMG9Yiub3+D1AWLnrhIHFyK6Aoq6VjGJFq5YPbh/rvkzxbcle7xOOnjY3ayYbzbgE
         zGCL6tv/ghYDTUs398VY4DVJv3Rz9zV7+yVmlyRUXuZ7hj/FKsM7xhydeIhmdsDGa+eu
         gqimUvLvTVF0EVLQZ7OfxXvdIljDb5g4015H+dPjbGneV38WMJbFiIftpgG374HELmqw
         6cb0e/oVHUY5VfHDH1ZkEAhhVsalc6Nww4tEGDUHZiBjoeuGuz+5QH1chtgulM5jbkDI
         IPnmeQsg1hT4MsJdTMD5cLOXr8bjc6GgPlyhe1Ew/BuoMRS1uG8294mMOGjsWeSZ+heI
         6yvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bTlI6z8vmo0ApTJAefLbFgioHKc+K8OTZdLV1HoxLWY=;
        b=r29xA/dxwvzjEdf5ltkWV8uETASJVlWVra66rhjqpunq/v/JeYzGo6Sh3IYwzfKRYH
         fpi+CWYAK/xY2Fco/nS/jeXN35eQ21Hc7qpSCH9jwIbGch+GGRtYc5jiLbY6Yj3erSG9
         T+Q34juNfO07kQwgpfmLYkqL+WsrMoc3WDUpmLABsIVrjBL3b9nGBnIcTaAZy17/ogHG
         bK+w+EoOP6KaqlVdjM4WGP7RsajmKk1pCPJH3xAEnh4dgtlXMejeIteMDnlLfC9b80w7
         S5peXEW+41c7hhnFRnE/fuO78b9892t+eLMQxTiMIx9kBPbBgaMoIAYnmEX4ca5Ua+zR
         uhyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Fi/veP+r";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id i17si1405347pjl.0.2021.05.01.03.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id n184so671743oia.12
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:35:40 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr7103289oif.121.1619865339999;
 Sat, 01 May 2021 03:35:39 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1czubqqz0.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1czubqqz0.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:35:28 +0200
Message-ID: <CANpmjNP_FSvVEWjoW3y5ihgnA2swisSXXiH5E2tOUmwoKFeSsg@mail.gmail.com>
Subject: Re: [PATCH 5/3] signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT
 for consistency
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
 header.i=@google.com header.s=20161025 header.b="Fi/veP+r";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Sat, 1 May 2021 at 01:43, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> It helps to know which part of the siginfo structure the siginfo_layout
> value is talking about.

Your Signed-off-by seems to be missing.

Otherwise,

Acked-by: Marco Elver <elver@google.com>


> ---
>  fs/signalfd.c          |  2 +-
>  include/linux/signal.h |  2 +-
>  kernel/signal.c        | 10 +++++-----
>  3 files changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/fs/signalfd.c b/fs/signalfd.c
> index e87e59581653..83130244f653 100644
> --- a/fs/signalfd.c
> +++ b/fs/signalfd.c
> @@ -132,7 +132,7 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
>                 new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 new.ssi_addr = (long) kinfo->si_addr;
>                 new.ssi_perf = kinfo->si_perf;
>                 break;
> diff --git a/include/linux/signal.h b/include/linux/signal.h
> index 5160fd45e5ca..ed896d790e46 100644
> --- a/include/linux/signal.h
> +++ b/include/linux/signal.h
> @@ -44,7 +44,7 @@ enum siginfo_layout {
>         SIL_FAULT_MCEERR,
>         SIL_FAULT_BNDERR,
>         SIL_FAULT_PKUERR,
> -       SIL_PERF_EVENT,
> +       SIL_FAULT_PERF_EVENT,
>         SIL_CHLD,
>         SIL_RT,
>         SIL_SYS,
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 0517ff950d38..690921960d8b 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1198,7 +1198,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>         case SIL_SYS:
>                 ret = false;
>                 break;
> @@ -2553,7 +2553,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
>         case SIL_FAULT_MCEERR:
>         case SIL_FAULT_BNDERR:
>         case SIL_FAULT_PKUERR:
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 ksig->info.si_addr = arch_untagged_si_addr(
>                         ksig->info.si_addr, ksig->sig, ksig->info.si_code);
>                 break;
> @@ -3242,7 +3242,7 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
>                                 layout = SIL_FAULT_PKUERR;
>  #endif
>                         else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
> -                               layout = SIL_PERF_EVENT;
> +                               layout = SIL_FAULT_PERF_EVENT;
>                 }
>                 else if (si_code <= NSIGPOLL)
>                         layout = SIL_POLL;
> @@ -3364,7 +3364,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_pkey = from->si_pkey;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_perf = from->si_perf;
>                 break;
> @@ -3440,7 +3440,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 to->si_addr = compat_ptr(from->si_addr);
>                 to->si_pkey = from->si_pkey;
>                 break;
> -       case SIL_PERF_EVENT:
> +       case SIL_FAULT_PERF_EVENT:
>                 to->si_addr = compat_ptr(from->si_addr);
>                 to->si_perf = from->si_perf;
>                 break;
> --
> 2.30.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_FSvVEWjoW3y5ihgnA2swisSXXiH5E2tOUmwoKFeSsg%40mail.gmail.com.
