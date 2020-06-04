Return-Path: <kasan-dev+bncBDYJPJO25UGBBTGT4T3AKGQE2VQJ3PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 832041EE917
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 19:05:17 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id x68sf5205522qkd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 10:05:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591290316; cv=pass;
        d=google.com; s=arc-20160816;
        b=J2iD2yQvctz3DN9JDpaKS25s1M1Le5AYFKPyiAJLR6y1MqxvIsRhHkMA+uGpj1iolJ
         NgKgM3nfYUu0UkW/bblD+TV/y4su4N/3uiZ55xALiV4QwaYPiucaFPaXLDYU9mR0ktQc
         Fh87n0jMc7iQRjdhhT6Ooos5MfQ/2/daU9XyJEjn2iZ1QTKM4WQpAqAQncgocUotmJ7M
         DiNmOINdFy2l9YRwj+bnOwFAKnHGA/HNIVaBuXjCNYZJC+yFtPf9j7uw5Om5oLoXzArr
         /3xnkobjdPXT4ldpdafD52yg1IPczLJ9W2daP7c563u5kSSfLxivUXAsdVm0kbrrh2HI
         Eeag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JFwaEZCJjGoMD48WKXsR/Vzzs9Lg8NQDxOUuXQtbfPY=;
        b=M5tJcwpvWCDI4L+SMwpCarGzCpvlD83y+Cem7GVGwm8IcfRnWNKuwX12Sym5xL6anI
         K1WJfc7gZV7XvTwbQyRePIYmCcmOetn2pT4nZTCzxQrRj2wib9G0mzyiTwiat5WFhrHN
         RiYKYKbqWJ4nMuMaAATMOswKje44kMcXz+6jcj1Rn2yCOhgyUkEkIHOCQErXYxYWrnZ3
         HMkl4e9/WdMrOnsIsEScuUAZyH/TVgE+2Xx1dVX0SWI3mgoXBMDd4Hjpa6qXCWEA/DIq
         MtLkTpiJr7aRXLKss5+YKo7NjlPJ47i17RodZk1niaCencIN2ogJVW+NiQjMD62cKDeO
         vA4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3DoQg0w;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JFwaEZCJjGoMD48WKXsR/Vzzs9Lg8NQDxOUuXQtbfPY=;
        b=lz3WovrQ8RlcFCOdViVscciOVs+RJDGFut2gM5T8OLnl0cXDSXUXwp1+fjgmLzHFk0
         mWzk4+IHwJcIZIXnI/WrmpL8beisUa51D8btZ25BC5X7UVmGnKy1EIimgSPw+c+wf3t9
         FZHLtq67kt2iJ6Esq+Jgeg+BhY5uRCysHWnUZHg+kbrlOabgRaMB23xm76TPxle7Xmh7
         QDnEK7E19Mrh5TmYQlWYBBLvY7pbJbsV6XpP7IETml4aueju0h9R4NTMD6ulm9O/ostc
         gtDPGZFt/3+NLRuaZqhTWJe4yfP27VPVtBYZR0QjRVd2b+H5BtxCo0RtO1+EyyYF3VDl
         jd8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JFwaEZCJjGoMD48WKXsR/Vzzs9Lg8NQDxOUuXQtbfPY=;
        b=P4t9xls/e4rKLZ6ynRNkJO1SWPumtN5XCAHrdVJRQ9iAgYDU5PcIkui4Mp28buMdFd
         iO9mQ5WZoPTVXqWXPuyo9pfXqDuBV512dO13DRg0m42YcEQkLIKLEfJjpOPF36u372Jq
         dGlnKIqhfTVaCM552ZNLAmjYmn+nX5dGMCcWYBwqOr3UuaTCowhDq6nstNoHCDQsqPpl
         isKbDLDCPyCWiDXRfmLxSYVBEgv6mmHqX+VWpddZ/eWXCtBNuGh66ePxg0IM8F4lDxI8
         62pdLfA7qu+xf78Y/Kpj9s9kpL/YXIz8rGMC1yiQGQQN8EbqE6em6hT2EQ6dYKMmdV8G
         ROvg==
X-Gm-Message-State: AOAM531IzKREHpIuugnyvjAIaPv2YaqRFghTVcVQfptYBXeBDHp9NPAi
	4NP9611Ox46XafFQ5T/lQzI=
X-Google-Smtp-Source: ABdhPJwUC12AzoZQc2aY1/PzMpezoe5amwPSYNuN/vmgx8eTzqtvstlZHO9nADUSX91qbGwEV0JwGQ==
X-Received: by 2002:ac8:6bc6:: with SMTP id b6mr5637313qtt.101.1591290316566;
        Thu, 04 Jun 2020 10:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e293:: with SMTP id r19ls349846qvl.1.gmail; Thu, 04 Jun
 2020 10:05:16 -0700 (PDT)
X-Received: by 2002:a05:6214:922:: with SMTP id dk2mr5849085qvb.87.1591290316253;
        Thu, 04 Jun 2020 10:05:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591290316; cv=none;
        d=google.com; s=arc-20160816;
        b=hdyP5IiL1nfdEJ1Onj3VdG2r9XpcMBzK34VhuR3GgkERwz1rAyen8xpc1xxwaJYS0D
         gLUFhDmdzkksY5CwyZON4gvdetN3PGFrYNKli3HJhqcwgwKpg0h6vfqis5bieKTxVWzf
         Lan4mQj5Rq6coEk0siSDwlTk9JNYsDhrkeI7eAqP2LrruiR6z/4/6CROMoNE1nYI++rz
         Cj7q+CQGiAl6R5ruzsdrAGQmdHSPmRZE+rxdjg7XgivaiamCJdkFooYED4zHY06D58t+
         sTa4BFns8+CF8oThWLkRgnrVjYq5KhmUBhNEtvdPd/lFa6euJXfAlPhsWSQ9XZm+wl5Z
         +KqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lISUp6znJVR2B4ykX8SGIADCyXExJUwiZFK3+UkXhn4=;
        b=jbCDatrcuI2s18KjlJEsduy6e7lW/Fpl42j24QpHFIC1P/ejCRBbduNdeY0qv3zZlC
         5AvFtF5ljbcu4hayvi5Hb0w6MOUfRZmJQUnoxdb6M7225q+EehMnEUOruYrZVL3TeoDx
         OdhOfZ/I5s2YVusFS5YNPnJhqsQNlBgLPaxr8qDn1VMTYCQc7g7mYJKZEtZOW91XeJQ4
         ZMgSFa5hZ4t81TIgv6QlujeYzF8v4Thq2sTDhpWXJGjoebtPo85FYLEHiVsOm6H5r0uT
         M1xiQG6vYdTs8qkJCCq+usI3kxNKFl3rn612mUmAagE1p6bTSOu7XZlTgbRx1nIbYfqt
         cLkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3DoQg0w;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id d3si393033qtg.0.2020.06.04.10.05.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 10:05:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id h95so1464913pje.4
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 10:05:16 -0700 (PDT)
X-Received: by 2002:a17:90b:4c47:: with SMTP id np7mr7304224pjb.101.1591290315538;
 Thu, 04 Jun 2020 10:05:15 -0700 (PDT)
MIME-Version: 1.0
References: <20200604145635.21565-1-elver@google.com> <20200604145635.21565-2-elver@google.com>
In-Reply-To: <20200604145635.21565-2-elver@google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 10:05:04 -0700
Message-ID: <CAKwvOdnxqzMgs_CNd5xQgXBOt5GmirfCjKYk7d+cxEBEeKgLrg@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kcov: Pass -fno-stack-protector with Clang
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F3DoQg0w;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, Jun 4, 2020 at 7:56 AM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
>
> For Clang, correctly pass -fno-stack-protector via a separate cc-option,
> as -fno-conserve-stack does not exist with Clang.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  kernel/Makefile | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index ce8716a04d0e..82153c47d2a6 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
>  KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
> -CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) $(call cc-option, -fno-stack-protector)

All supported compiler versions understand -fno-stack-protector.
Please unwrap it from cc-option.  That's one less compiler invocation
at build time.

>
>  # cond_syscall is currently not LTO compatible
>  CFLAGS_sys_ni.o = $(DISABLE_LTO)
> --
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdnxqzMgs_CNd5xQgXBOt5GmirfCjKYk7d%2BcxEBEeKgLrg%40mail.gmail.com.
