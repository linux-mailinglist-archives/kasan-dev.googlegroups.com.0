Return-Path: <kasan-dev+bncBCMIZB7QWENRB46RQTZQKGQEQQ2SK7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 8402D17AA7E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 17:29:40 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id o13sf1367422uad.7
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 08:29:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583425779; cv=pass;
        d=google.com; s=arc-20160816;
        b=t0luBAqZXOIuFde0TJNWKOWYQw9GaId48iv5wGIvbW/MBoEf4+2Nh50RYrceSSgwtv
         iZKZpzLvbS10TJ7jk3iklB2qi7sOOc25F8vjShP++oYmzmEKneA3OFlzld1rrMy0tstO
         FdPry5iP5ofOeyI5tSzFOUuUZWt1lo6eHQWtGQh6firyFrfqXko8nZGhN1v5+eRs9Zoy
         vuC7LpExUylPjp+j9BfR3wAU+AXeHxpdOZWyiPLNoOJRYPGBWQRc+7+eL/03LmFO77A7
         vK0By869yDJQapGWtTqOYQ56mbNt5XjubcxapwVRc71vnQ7RNGVutAhe5BYAI/GfY4N7
         ZxFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2KsGmrFQG1hRnL0sr2NgjydvpcOi3osAjCHlKPsEgpc=;
        b=B6DrJa4vo+TWtWV/9IRWme1p68ajcF4pd9vQy7ajQOOuvsUh3ZlM5xpJkkKvK1QPzV
         6HRp/0uuu2Szhp3YwRnHP++WgjgoVg+uU1rKVizdG+DG90nw+PwjHUSBtSw2GXHAv2HW
         5v+WwfS2p1OYBuZoEccu63d1DRTVNZkzqWG9eqQBLx+ffv+p7XW/Q8MPgNlj3PZY6wY0
         RVK0KDCOsdGd8KPPM0JJZ51thy3DQ02ngpGcd6VPXIJfUVPrKfk7u786DPHr73b+juM2
         VzlaKhuneJMjpRoslmyRin7f9ZMT6tgv0jqOpZcNkSjwSm3lN3UkcNtyD6erD50kA2qS
         cOuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJ55u5NK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2KsGmrFQG1hRnL0sr2NgjydvpcOi3osAjCHlKPsEgpc=;
        b=ch/p7BppkCW0oqNUWXbnfSYsFMMCbXRbSpavDeTo+k7MEyG4JHy3uopCXKhCzVCYcF
         k93Cuma6RCQBpnieKZxESP0VNhjcHSfKMIq/TZNA5aEevHHdD3jI1s+QFr9/CaISuHKA
         nXhyihuxhb/wNcdjZO9vrefLCNxDWCbKKuG+/7RWO7IjrZmEYmADDunBpqPsRbNQsGKW
         kNiU/CjtYtuEnFVQ1JtJrXTPyUCqhSCTEafN2wT13/MUYBsvfqdpqS9Zt7+6AVl/+IU5
         oTCy5O2D4lUZTJAvTVQCS3lpXT13zwr8Qx4P//z7/KEZAspiiz/eyFL0GglJPBPYzJk/
         9Unw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2KsGmrFQG1hRnL0sr2NgjydvpcOi3osAjCHlKPsEgpc=;
        b=lPuP155hSiAIeMPT1QTQhdJMMhB6NKxy7KyzXAFcZXSj875UXfRAeCxCjILiBKGwnH
         6BqVnXL4CF6rBgKtvU401xUUk7YbbRXoHjwa6Cn1QfBGALg22YXLvisdsVavlXULReAZ
         oXUTJiIYorAowgKgtCuAqDyc8lZpJM72iO8kqrmTkRJlhoHjr+08jXabrbcXytCLUcb5
         VOLE0X3oMQlWO4vtm0BTeWqJiKRSJhp/hHdC3xFN6zbTFS/4BmO4XRY1ol6dDE/dZ8aP
         FiGJT1UK2/voDCe1Uf59hOXrCbbEBkr6A+oXKwICHvgbLdXwqS4MqIlVupokhUlJSEc8
         qkig==
X-Gm-Message-State: ANhLgQ1DoYd4J3fVYEMRNXTEK5YBM2KOLdOv7mX1zPWivJSs+RSNrG13
	Sz9dFql0F7RHi1fdE7MJwUM=
X-Google-Smtp-Source: ADFU+vt/jbdf4Ja5cciQnveeuw5Z7gvz8MRdqJmInjNHI3c30J9U3p+W4QUUD+8MYL+6PmOIECtIhw==
X-Received: by 2002:a9f:230d:: with SMTP id 13mr5307751uae.3.1583425779567;
        Thu, 05 Mar 2020 08:29:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:168e:: with SMTP id e14ls80161uaf.4.gmail; Thu, 05 Mar
 2020 08:29:39 -0800 (PST)
X-Received: by 2002:a9f:3046:: with SMTP id i6mr5093586uab.15.1583425779232;
        Thu, 05 Mar 2020 08:29:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583425779; cv=none;
        d=google.com; s=arc-20160816;
        b=Rl3BBP6nTwdT5C5OumSVdzXTITb5eu6J61wMiCQUfps+LlkRsU/09k/wIbPDVCxwvj
         B+td6+UTDuKalDKVrsrSzadRYZB+pPHH6zdQxJqJg3v+c9EN/AAXrXb2ZFKdJEmsKuwS
         AzpJ84HFc4HSMicNEfclUBvpwqVL30eq3C7XNZEbfiHux1gRWlI5fJgRXznjYvESO51I
         wAMBvubSlhflXnQ/QfUn6HiKz5KLySTyrgCEbt33Bw9DPus2Q+xd8plyvFqAfuYY7m1J
         D1IZCCCusIgcAUGaDRoB/hmcZt2cRaBDCDf1u0OCqzX/ma+42mJ5dZ/TFS3t1n4ufhWb
         hXNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E3g6+orjBjzo+QwYTR0lxbE5uzupz2BUTuK1TDzoMIE=;
        b=o5SVLXOzjSn1U41AtB3w8fKuG6lHE0kKbSJ2A30OvqhGVDDr0tfPauOAqZ7aHqgBYB
         aCLjDI1teQjCzjzaUt3/zaP/aPozhJdPTMHYT7lrrOcQqYVqOBu85G2hn5ZaJwcLs4EQ
         qqX3TYMCA65M7qL/itxT5+7HTR7jgeKf33XlizOBN7NPvTIaq/gAk6tMVYFCM5CSlfMf
         +2b+KoUaBEWE24fIh7Ulv0sqrCQG3jdz5kdpqB/VemX/q6iUEzdb3dNMgQTspi3ANlfn
         EcebEhRQNSnNvwRCWDKZih6NUAd20mYuUWwWDLcAyyXtB1AddKwAlNZUox8nC4U1rVqT
         dfLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJ55u5NK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id w69si339622vkh.4.2020.03.05.08.29.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 08:29:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b5so5860813qkh.8
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 08:29:39 -0800 (PST)
X-Received: by 2002:a37:7c47:: with SMTP id x68mr9032036qkc.8.1583425778497;
 Thu, 05 Mar 2020 08:29:38 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com> <20200305155539.GA12561@hirez.programming.kicks-ass.net>
In-Reply-To: <20200305155539.GA12561@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 17:29:27 +0100
Message-ID: <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nJ55u5NK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Mar 5, 2020 at 4:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Mar 05, 2020 at 04:23:11PM +0100, Dmitry Vyukov wrote:
> > Compilers just don't allow this: asking to inline sanitized function
> > into a non-sanitized function. But I don't know the ptrace/alternative
> > code good enough to suggest the right alternative (don't call
> > user_mode, copy user_mode, or something else).
>
> Does it work if we inline into a .c file and build it with:
>
>   KASAN_SANITIZE := n
>   UBSAN_SANITIZE := n
>   KCOV_INSTRUMENT := n
>
> Which would be effectively the very same, just more cumbersome.

I think it should work, because then user_mode will also not be instrumented.

> > Maybe we could replace no_sanitize with calls to
> > kasan_disable_current/kasan_enable_current around the section of code
> > where you don't want to see kasan reports.
>
> It's not that we don't want to see the reports, the problem is that the
> execution context is too fragile to call into random code. We've not yet
> completely set up a normal C environment, even though we're more or less
> running C.
>
> This is very early exception entry where we still need to frob hardware
> state and set up things.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZBE%3DFDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3%3DA%40mail.gmail.com.
