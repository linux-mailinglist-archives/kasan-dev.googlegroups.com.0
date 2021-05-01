Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHW5WSCAMGQEZY4QQ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 47FCD3706DF
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:34:08 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id o129-20020a6292870000b0290241fe341603sf867656pfd.14
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:34:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619865246; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYU58Hbs9JbZQ0mg74LxwPNDTQZQl6vZWQ4dy2eYwvnnGEfpv3GTI73MqqceW/DQu2
         seLauP3rzoNTkXllXsFiHvgzm5aG5RKmz6/XmVG4k7PolmE4qPVFWEAFG7ho/eik37JD
         oK3KRhyiipVYcRbFIJoaDhQxIPG2PUljaallwF3RjW3GZwUdmF1IwjrlCvv7ooxZ5lfy
         8cBv+0Fqt0QeBNCnO16QzyiR+nIRRybhN5DdmI4Fs+9xttE6vCw/0MAvXyAdxf+vrjx9
         sOlDftlVbLlUqt0+9BXLe6WLqsWAfoPrRnrHS62ICvZBHOeIjW4KTwtNZjtdSATNkfTV
         y9Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8QFJdxHPF3CHVy1LLaAmtyloW4+eCzcKVQpAxKjgzB8=;
        b=z2ktU6CI5nc9Nu7tE/h2I84HQcScZuzpri23nsUrTsH3LgpSH40TpEJxZhJSc0xTHp
         CqyR0rMEbakXdNn4d6ogACdJUUCLbSUCdwrlv42SXNj1x0eT7Yt8eD9mqqrKHfiEwikl
         J1e1oZ+H/EIuYrev2yenOJB0WBDRovmcAHivXaDvzOkTlFqEWEbHW3pnIvbzGt9YWIRP
         mNJbr5Dgf+HqUk3MTEO0Fp+6wCXacisw+4SP2tcDhOTM2qFqiC+jy0KGVwzCZ/NRJOdf
         WSCfn8tQq3HvOYI5XwyxkHeB5X6YsSqIZL5H7oNFRuzrBBZpWTJ45Ir25y5JAXECGmZU
         Ibvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="UWGMH/nV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8QFJdxHPF3CHVy1LLaAmtyloW4+eCzcKVQpAxKjgzB8=;
        b=AiAcglKCdqD5urco7DfJUv/YdWXXKX04iVKwyl3PLG/+9bp40gVtU2tVP1CI1W9zKR
         0avd6WzR2WlCXBWTaYVqv2FPGTSN/OGOJzYaP/D2NNUKOwVj0uZ4LYo1e5FaEYSkj1CO
         s7rpfnz+b4Y3x5kezJ8akWRZeFq4Z/3T94DMlDdg3BLptVC+PHm3It2mBbXAHVNG+11W
         Kn+4OyZtnnfbWMab8fBaCLLhngGCG48mdoEI084D2qCH45nPcXT6JEnEMujpCQLqsJ2a
         LUVGMGOc4yq/5bEaYcVcTsjgf6p3OIXubtaUMeujAvLRJF5636ILgUDgw9lbeWqe0lMB
         cuxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8QFJdxHPF3CHVy1LLaAmtyloW4+eCzcKVQpAxKjgzB8=;
        b=ocRLyV5KDZg/43qMk6Oyji+V3ZnNlKaNAJGiw7P61t0ERnV6QEEdcgfpxgURZu22gb
         aVV7VhK6yy9Dij6id4LDelk7AyC2dgxAYnhV4sZouuf8cdpF7DR2B9Ka2mRctdQglsi0
         PxQq8xYhgNtS2mlWYsixFEQEpHAQtpF7qghtXrrV+wt0IzakcmZzmtZpGsg/+YJBFGUt
         7ptsD9d4GnYq0mVkXiJn1dJRl8xTzMZQDq3kyqkfetsi5pecmG7pW6hW/QHuxoUFJ1YB
         WXuSR2+Ph8JsMKcAIm/uGgNWAWNjeR/VSujOup15lbuqUWOrANG4MxHJJRFTU/hJj584
         3YMA==
X-Gm-Message-State: AOAM531XHyPZpDO5hZF4+RcVP543s42XFPaJsrrtVEeAuYNqRD2z5W4C
	QqjW4FpWjJku8x7LKKdSGzU=
X-Google-Smtp-Source: ABdhPJzPxqGgmlrMQ9h65JwcyMhWxLTgqy860dVqhGykCreek15i2R5wp+nVgfSxMINXbvfYVI/72Q==
X-Received: by 2002:a17:90a:8c8b:: with SMTP id b11mr10019347pjo.236.1619865246625;
        Sat, 01 May 2021 03:34:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:df0d:: with SMTP id u13ls2932658pgg.2.gmail; Sat, 01 May
 2021 03:34:05 -0700 (PDT)
X-Received: by 2002:a05:6a00:c8:b029:260:f25a:f2ef with SMTP id e8-20020a056a0000c8b0290260f25af2efmr9043032pfj.78.1619865245434;
        Sat, 01 May 2021 03:34:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619865245; cv=none;
        d=google.com; s=arc-20160816;
        b=ED4maqMXAfZFlD+9VQqxaq+r86VMPJ+YQgwSVNcqLfRCDlyvKJ16Cqp4GqjPrM2/s2
         E7GRa9muMohvYGGS8sFfh66eVtrK/Gf/9oen06r7cEs8CFrFBHw5eoZv+Njyld+p2/R9
         W8LysaNgK/HUzMW2Y5wt6zbpKNVCPYhiBHT6moS3w0sv/PRW3a5ebvR4erpZfp7SxrKo
         xKZyINinyYI3R+ZPhtn892HNBR9TaHs8rExfjxbQm7I2TQrnOeggZB4ulbq1Gtv1S7TI
         IVADgNTpqWDVvQu5EA/frARnAa8Xou1Sv2tBrstQf0vmnEEwhriagS+9W7Xv6nEswZ4b
         9e/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jCan+6xptMFqGkbIIPn1nwIIm9+SRi9i6mWKGsgGhAU=;
        b=F/eGl2OUuwN1HdOJ2s/uhq7phPub2uND2QsjiOVMZ/xiC8N4fnJDSk5pvsSPGx8+Tu
         0sCZ8JjhsGRd/RN2vTDI+P3fTCd03z5HxMJmgpZ5oSCkj297qT8JXRHESvh55kbzV6HV
         j+ep56euOZLukWFT+bvQ892E6rnNf7RCsa21iSFbFRwqspwh6X7eX+yojn/ThptQLJqR
         K80SMtzFJkIaF/zUlI/9Ya88fpjWHvabgr/tXXlCn1WvfQDlJE4BJtqWYYExnKBv4kzb
         DWRumSoCpH6JgHHDG7rSYRORCx2j434Lwwle9t1YMBmsrAiH+6WmrD9wCBR65FFrSEzP
         tzjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="UWGMH/nV";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id e10si814884pfc.0.2021.05.01.03.34.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:34:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id g4-20020a9d6b040000b029029debbbb3ecso804622otp.7
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:34:05 -0700 (PDT)
X-Received: by 2002:a9d:60c8:: with SMTP id b8mr7228167otk.17.1619865244678;
 Sat, 01 May 2021 03:34:04 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1eeers7q7.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1eeers7q7.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:33:53 +0200
Message-ID: <CANpmjNPztuttUqN3=Z4r7GPCyGu76CWNK-oYhxtByAx5OP_2rg@mail.gmail.com>
Subject: Re: [PATCH 3/3] signal: Use dedicated helpers to send signals with
 si_trapno set
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
 header.i=@google.com header.s=20161025 header.b="UWGMH/nV";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Sat, 1 May 2021 at 00:55, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Now that si_trapno is no longer expected to be present for every fault
> reported using siginfo on alpha and sparc remove the trapno parameter
> from force_sig_fault, force_sig_fault_to_task and send_sig_fault.
>
> Add two new helpers force_sig_fault_trapno and send_sig_fault_trapno
> for those signals where trapno is expected to be set.
>
> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
> ---
>  arch/alpha/kernel/osf_sys.c      |  2 +-
>  arch/alpha/kernel/signal.c       |  4 +--
>  arch/alpha/kernel/traps.c        | 24 ++++++++---------
>  arch/alpha/mm/fault.c            |  4 +--
>  arch/sparc/kernel/process_64.c   |  2 +-
>  arch/sparc/kernel/sys_sparc_32.c |  2 +-
>  arch/sparc/kernel/sys_sparc_64.c |  2 +-
>  arch/sparc/kernel/traps_32.c     | 22 ++++++++--------
>  arch/sparc/kernel/traps_64.c     | 44 ++++++++++++++------------------
>  arch/sparc/kernel/unaligned_32.c |  2 +-
>  arch/sparc/mm/fault_32.c         |  2 +-
>  arch/sparc/mm/fault_64.c         |  2 +-
>  include/linux/sched/signal.h     | 12 +++------
>  kernel/signal.c                  | 41 +++++++++++++++++++++--------
>  14 files changed, 88 insertions(+), 77 deletions(-)

This still breaks sparc64:

> sparc64-linux-gnu-ld: arch/sparc/kernel/traps_64.o: in function `bad_trap':
> (.text+0x2a4): undefined reference to `force_sig_fault_trapno'

[...]
> +#if IS_ENABLED(SPARC)

This should be 'IS_ENABLED(CONFIG_SPARC)'.

> +int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = sig;
> +       info.si_errno = 0;
> +       info.si_code  = code;
> +       info.si_addr  = addr;
> +       info.si_trapno = trapno;
> +       return force_sig_info(&info);
> +}
> +#endif
> +
> +#if IS_ENABLED(ALPHA)

CONFIG_ALPHA


> +int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
> +                         struct task_struct *t)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = sig;
> +       info.si_errno = 0;
> +       info.si_code  = code;
> +       info.si_addr  = addr;
> +       info.si_trapno = trapno;
> +       return send_sig_info(info.si_signo, &info, t);
> +}
> +#endif
> +
>  /* For the crazy architectures that include trap information in
>   * the errno field, instead of an actual errno value.
>   */
> --
> 2.30.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPztuttUqN3%3DZ4r7GPCyGu76CWNK-oYhxtByAx5OP_2rg%40mail.gmail.com.
