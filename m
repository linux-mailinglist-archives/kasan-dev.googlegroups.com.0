Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBHHGW3XAKGQEN7SB7GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05AFCFCF0C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 21:03:42 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id z1sf4968546ioh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 12:03:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573761820; cv=pass;
        d=google.com; s=arc-20160816;
        b=i406tGq6zDBhEP9lDOzWqsaJRkCmkeMz7vjJcvlWbQrQEaFCcpUPVl3IeAGQp+UwM0
         QCtiMfKw0myEpWVztJ8wyGD9vi9wAqnOMc9fP1yxw7pDptE7LkYcz8ys09MHmVSMC25h
         KM4aNgDhC3MP1z6nKGCQJUnZN1zUF6iUL17fml/qPaWkEmK+UuKxlJR8DTApYSWIojqA
         ZmeLFI3ZEuKkUsB25rzkXXgC1KzkiLOs3JF1yMwbqRMDfCQwO7B866No2Dr0JxGjI5CK
         KXyP+zJfAYTACCc3dRzaKiO0QRkHDhIxP3Q9VRQQm5aIjgiAnPQPY16SaVvbodGCoeN5
         D/Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iGKqRlHDUZ8HOnfg/xawRgonvfY4VJRy35bBpnXl+NQ=;
        b=0rPxNXJJ/XejHw5lV4QjnsYO5ZDQIo51m4tuRw81La2YPzY2Yo+qfL1luxUGSKd/XG
         S5rqxKeDDKmjieGZAuqh9L47C0Pw7+VoY+xWdLpuPEJE4KMhR57B+PuWd/STQdNsr5E3
         mjy++j9DtsuwK97X/sSOUxjn4q0p/zKiMVMLDdnJHsAwpnHLPdHiM2fxtq6nicZZlob4
         DRW1z04U2wrDPDSrH7WEJgVA51pTEc5VXVqVx9XNsf/OgtKQfix8PrB3csvJWA9I0J42
         DnITds1Y6Z2kJq7Ut2iBiC69zlvwXKpDV3rFLkr9Q5p0HWA1x0u0+n4YVsUIuoeT3bAe
         Gewg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="g1DQ6a/b";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGKqRlHDUZ8HOnfg/xawRgonvfY4VJRy35bBpnXl+NQ=;
        b=qpgOlIXnZSrm+f0O5TGxgFl4V4H8DTtqZIUmjzTFyeLXzT9tp4gPUKifPHU+8opbxS
         zcyt1ZPm8S0rXHkmLLWQg09h99szJcnoBJfJevT7ypsfO4TVgRKbuIbS0ZT9NPTckNd7
         YkEmkbrR4JdUfVj1bi49/54Iv4mtDeVACLi7LXCdJ2ZzwnnqLZOIw2BRL0hyvX08/ZDR
         M9Ltp1eIbS478DOVWGWflMcZNOUa86/eNxwkLZVJktkVVZVmrwTn75aDvKszRMqAfkCw
         OQTWRR9FE5T17FOLnyDNA0TLAALlAOMpGvBYHWJ5V3XsiabWD6w+XyuXj+dcQZZsTu7Z
         OqKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iGKqRlHDUZ8HOnfg/xawRgonvfY4VJRy35bBpnXl+NQ=;
        b=is43NzjvwXI/9/WkHRMlpIfHDWEIvvx49IWbIyylrlDzRKhNEs6DlN0dqMchWumDus
         tbUvIZkyq65mDPEZ5fzYNFa/s1UBmj/2GLihneAwhY9S8lTfkbPW4KKOWiqG9dUdV2lA
         8nqR7pqDjRrxeZi/kFU2I5CnE9LaM80k5z6JKx6f+AAMrePkaTjmoSl0bDBEy707PbAo
         dfcgY6EdrGgWb5mzxmfTmI2fYLxpAWIXhZSPs4ACntZx73kaTUYnmcqUZ9l/2DKx2xOq
         UMYSPpkP+0TdjDzzPKo+aYqfU1WbsoXlWh1O7xBaP2pRVLWaKh5luAhkBp4Cb41eRIb2
         oCmg==
X-Gm-Message-State: APjAAAUf1tgoBQisHH+E0xIyDsMhOFgKDsJzGNVCBkZQL5qldJCryniA
	1QsnqEaPMoRMqPr6EUIhwPA=
X-Google-Smtp-Source: APXvYqx79Zea740zSchoze7wB1UVLTryrk01wJu6UUPXRmEvLb4SKErwkf5NSCM/tqGccnG6ZCJx9g==
X-Received: by 2002:a92:4944:: with SMTP id w65mr12795579ila.102.1573761820550;
        Thu, 14 Nov 2019 12:03:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a0d:: with SMTP id t13ls1373225ili.0.gmail; Thu, 14 Nov
 2019 12:03:40 -0800 (PST)
X-Received: by 2002:a92:8581:: with SMTP id f123mr12082789ilh.8.1573761820214;
        Thu, 14 Nov 2019 12:03:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573761820; cv=none;
        d=google.com; s=arc-20160816;
        b=0KIGhEf2w13Xs25NpcfldApoqTf4iLHKOMMAWnzEe6TzTJ0iju2tMMD+BAM3XvhRpK
         tYF1kAOJckafHb0qqwIHzooGlmtVboveCSBhgXSgbQqFUxBReNCuTTJCezsKL6zyHSbH
         UiWcg8eGAurg+e7BdzhyG5qZrLePl0X5rv3xJgcknWlreThtRXQFadakA1sc6PmBu9OP
         goaP6JgHUeLc0irjThjmc5z/h6Z3CddB1zysWCfhuuUsgvMnIjMwUzClIZB/SLn4FBjy
         KbA5oP5tigZew78OitbIEhA3d6mMcQyjJJ3a0pphbowPfPFoY/vyoeFqRUO8dPzjrdoY
         qITQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=De12QG3/ymw5hWl2Jg59C4M8muYieV0byC9HL46vsws=;
        b=xqF7qF78dBcj0ekRA3W5gtfClWtNJTSTKqyCIdHZBUxnkJmjS7TVS+Fv0TYiwF7e9/
         k4TG9ImEVAbugSNSS8VajEmlqUZQ4UH0tcS6Cpy30W8oCrSrQR66vbNsCyENqV+M0eHB
         m+6mZQKl7LqEPsULKLS9ejUIzHK+wojhEjdefHESFcJEI5haJYxESTwxRZRbfFvjWOhs
         0tSxJPvW8cubmL+MN0YZKUjQe9eH7Mi9/iJaDF5mdhnEFR5Y8u3JqyFGsrg6LacuqPBn
         pqArZK48Fpbi35UdYSQlynqFMiNuSdhQX1naL1xObFMd3hwQkcnryVD1+GN52sxStuih
         Qk8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="g1DQ6a/b";
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j74si386064ilf.0.2019.11.14.12.03.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 12:03:40 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id w24so5503385otk.6
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 12:03:40 -0800 (PST)
X-Received: by 2002:a9d:4801:: with SMTP id c1mr8756763otf.32.1573761819399;
 Thu, 14 Nov 2019 12:03:39 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com> <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
In-Reply-To: <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 21:03:13 +0100
Message-ID: <CAG48ez3fzJ_GP42XEPvXEiUmBtEc1zVtXaGRMavr==sSgF772w@mail.gmail.com>
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
To: Andy Lutomirski <luto@kernel.org>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, 
	X86 ML <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="g1DQ6a/b";       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Nov 14, 2019 at 7:00 PM Andy Lutomirski <luto@kernel.org> wrote:
> On Thu, Nov 14, 2019 at 9:46 AM Sean Christopherson
> <sean.j.christopherson@intel.com> wrote:
> > On Tue, Nov 12, 2019 at 10:10:01PM +0100, Jann Horn wrote:
> > > A frequent cause of #GP exceptions are memory accesses to non-canonical
> > > addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> > > the kernel doesn't currently print the fault address for #GP.
> > > Luckily, we already have the necessary infrastructure for decoding X86
> > > instructions and computing the memory address that is being accessed;
> > > hook it up to the #GP handler so that we can figure out whether the #GP
> > > looks like it was caused by a non-canonical address, and if so, print
> > > that address.
[...]
> > > +     /*
> > > +      * If insn_get_addr_ref() failed or we got a canonical address in the
> > > +      * kernel half, bail out.
> > > +      */
> > > +     if ((addr_ref | __VIRTUAL_MASK) == ~0UL)
> > > +             return;
> > > +     /*
> > > +      * For the user half, check against TASK_SIZE_MAX; this way, if the
> > > +      * access crosses the canonical address boundary, we don't miss it.
> > > +      */
> > > +     if (addr_ref <= TASK_SIZE_MAX)
> >
> > Any objection to open coding the upper bound instead of using
> > TASK_SIZE_MASK to make the threshold more obvious?
> >
> > > +             return;
> > > +
> > > +     pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> >
> > Printing the raw address will confuse users in the case where the access
> > straddles the lower canonical boundary.  Maybe combine this with open
> > coding the straddle case?  With a rough heuristic to hedge a bit for
> > instructions whose operand size isn't accurately reflected in opnd_bytes.
> >
> >         if (addr_ref > __VIRTUAL_MASK)
> >                 pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> >         else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
> >                 pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> >                          addr_ref, addr_ref + insn->opnd_bytes - 1);
> >         else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
> >                 pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> >                          addr_ref, addr_ref + PAGE_SIZE - 1);
>
> This is unnecessarily complicated, and I suspect that Jann had the
> right idea but just didn't quite explain it enough.  The secret here
> is that TASK_SIZE_MAX is a full page below the canonical boundary
> (thanks, Intel, for screwing up SYSRET), so, if we get #GP for an
> address above TASK_SIZE_MAX, then it's either a #GP for a different
> reason or it's a genuine non-canonical access.
>
> So I think that just a comment about this would be enough.

Ah, I didn't realize that insn->opnd_bytes exists. Since I already
have that available, I guess using that is cleaner than being clever
with TASK_SIZE_MAX.

> *However*, the printout should at least hedge a bit and say something
> like "probably dereferencing non-canonical address", since there are
> plenty of ways to get #GP with an operand that is nominally
> non-canonical but where the actual cause of #GP is different.

Ah, yeah, I'll change that.

> And I think this code should be skipped entirely if error_code != 0.

Makes sense. As Borislav suggested, I'll add some code to
do_general_protection() to instead print a hint about it being a
segment-related problem.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3fzJ_GP42XEPvXEiUmBtEc1zVtXaGRMavr%3D%3DsSgF772w%40mail.gmail.com.
