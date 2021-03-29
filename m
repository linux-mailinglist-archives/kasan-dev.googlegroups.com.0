Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUPRGBQMGQEDRMWCGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 20D8734D997
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:34:32 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id v7sf10013399ilh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:34:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617053671; cv=pass;
        d=google.com; s=arc-20160816;
        b=0sherkinve64/hm8N6/Td3lPk0+55c4zoBv/c4dt13eYIEjE4cOlPHt7NBpkUasG8U
         a4r//BdYtkdd5Y7keC88j7BN6q8nm7J+q/TcW3EMMb4TC3fIXgN9xk8PYcxg6u7Uk3w3
         XKCO+/Kj4Vg6gEjV/fIKV9ZeFFyNEt+ji5sSR6VtgehrFCFPWXWjVh8pJekfT98nMcoc
         cgb5ua2UZxvCODnz3Ksw81bzCGubxSVpO5ajMZayj6DGqNZW1gJ2jpyOYexjgVp8HN51
         SuvlsWEUWy3G/SoQ1d3dT8/LOdSyHsO9dE3YW3s7YVwYVFsBujoO0ggiF/psnpDfJCyg
         R7LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=idPqPTp/l/dFuRXso5qxeBA853ujnIDWy6dQ4pl0b18=;
        b=IYR28EN7OicQzoB0YkdRH2mNdKmLsl+F4srRwjdBGdfgIDKDzBnV3jutrdAZ0kCDXN
         JKBbFg6LrkLN/bR1Rv6HGYSZZ8OOLiFL+AZW7mSfxQypJvbGjhFDIXQpQA9Mh2vQcnOA
         smKi61SHAYRUwUAnz7Y/j46B9TyOIXPjZ4rbwSYcX7LYhka3gLkMwMhWbAqrzYX0PvcB
         PNWsyrGRdrcvJOVEN470/F83WmQStSS272Lx6InZ/cvgg2rGTmjxT1doYSvMnsIs7dCk
         UtZ7vAMgad9KeznX7ksfvl4JE7Z6tyZc+W6NXJPSG5kbmB9l8/5xb3z47vzUQGJuMnw4
         nmrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z2ZWtI8d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=idPqPTp/l/dFuRXso5qxeBA853ujnIDWy6dQ4pl0b18=;
        b=UztlUypRZzNpID7xCd26LauWi5TlNZy/u2aptKSO/J8hHczihSiJwt+fd2+2b3ww92
         DdR73O9iqT8htmCflMWeVEPEcd6Knc1snwk78FDKWQID+qPCUiCpM22Hq54Q4koSurOA
         gv9CBvKUXe8sPRXMZ72Mx+R09cWPow6JBKhDurf9icO1202M1a92b1RJeZNpefMGQLTB
         NzfhuRlR03Sj5SGoUCDH8iwE19WX/53wPrbLWF1zldRDfueIDDrurO9cQovP9G/6oR+8
         HOYrMI0djXkCM/+vR1KSv7RkQhqYqxcMLDRaYtJmnTjFPvWSdneNwvwVdx+szSwYlTLU
         nzwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=idPqPTp/l/dFuRXso5qxeBA853ujnIDWy6dQ4pl0b18=;
        b=VB2MsRC3Pe9pCfOmtt6VlMB7dUkd+ZvXrqzffj2jXnsaC9uCRzjC+yvHM1ByaZH+XK
         OxEQOrlGunNkEN4r7ud+sa7RsSweyA3vgaBqfVUcm1v+ZLJiZTsiUO9R3cfYjJlKz0dw
         IGiuqlwBOY4nmvg/Vof4PuV9CB0rcWR0ab7PzRS7FKKwBhUgRZVmcPYac3Ee50w0RMxY
         NQUVmI8J2QpjE65bw9oq/Cmf/uuxH1sbebarw0I11j/AW4HRnAbRWuYW92r82Ljk395Q
         OBcBGwy9sh+z5IHTA2NDAcxZLTJygznFn9S7WmIxI3Ejhjwp7StWYOoDwS1ZqQPXDPGX
         PRkA==
X-Gm-Message-State: AOAM533wawHseVCXI4Bc31JfzqAPoq2itygL85ahtAk2YV8MDiLaWixn
	XBhEu+siHSmmtjarF3FXK+4=
X-Google-Smtp-Source: ABdhPJwvc2+FCc+UwFTkwpqLz+vgn1te3EHxu+yz5HLbyd9whmGrMxh0CxGCspXOBzGR0Sm00utJCw==
X-Received: by 2002:a5e:cb4c:: with SMTP id h12mr21065942iok.183.1617053671010;
        Mon, 29 Mar 2021 14:34:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c85:: with SMTP id w5ls1238744ill.10.gmail; Mon,
 29 Mar 2021 14:34:30 -0700 (PDT)
X-Received: by 2002:a92:cf10:: with SMTP id c16mr21110076ilo.92.1617053670712;
        Mon, 29 Mar 2021 14:34:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617053670; cv=none;
        d=google.com; s=arc-20160816;
        b=rvultWNup610mmRMYNjhw2m8deeOvjB8de/jgo98vvXz5JE8TQby/AZAdvUOkQ7oAZ
         VDguVCBK6aLT5An4JaVRbxTSSqRahtqfYHtMY/i+IwqcTRKnbc6gF6Cs8MyFG0uktU4C
         QG6qPcBJwa+AWvWEiUbpdYlaOjSfmF7Dc6HtGKIEboCh93CCJIbbv+Nc/jlBimhVmVPk
         RTyYtaw2C52ngCmz2T8F+7ZGZGXPBh10kyLyhdxygU1XUAQ3BFw/oSH0Vjczg1vIGzQ7
         R+f6GbBvW0buzEX8HSKShvVO0vazjoianKiLQBkP4JAH2SR6I2eNaQGUB3XUUrppK8RL
         l3BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k966H/wfqQRlWoFUGdKZeCOesHebiaByi4u25Efyrqc=;
        b=WibACx9XTteMwqti6RvM+O676xN4FCEuLdMMo8SHE4/+i9Kw+LZT3RnttnXZgDYO7J
         FaQLukN8tBRUxeQNV3FcNSBeCBk1LyFT5QNxvfD5DDetcwnE/r4BugEgrHV8YiBs6cpw
         O2Chd+jiNW/mBJr2iNyxwZlM4wC5RUgEVpqvXUGJ6XOmNqeiPg8rqEbBBzOS04ixw1yn
         1uh4/mrs8Bbu+4HO/RSicuQ/1hTe1KXi+4b9E69n9Y0xLI6BTWUqkLqmZ2tPjB4Aka4g
         QPmzy8iEbUF8hIaVm6pKRxu8nQdn4TbwEc2nUmy8XZvMVpRyT4+8kllPkqKU759ZogwQ
         YI/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z2ZWtI8d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id u17si1171445ilk.5.2021.03.29.14.34.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 14:34:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id c16so14480439oib.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 14:34:30 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr781868oif.121.1617053670246;
 Mon, 29 Mar 2021 14:34:30 -0700 (PDT)
MIME-Version: 1.0
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com> <66f453a79f2541d4b05bcd933204f1c9@intel.com>
 <YGIDBAboELGgMgXy@elver.google.com> <796ff05e-c137-cbd4-252b-7b114abaced9@intel.com>
 <CANpmjNP4Jjo2W2K_2nVv3UmOGB8c5k9Z0iOFRFD9bQpeWr+8mA@mail.gmail.com> <ef4956a3-c14b-f56a-3527-23fcecf7e1a3@intel.com>
In-Reply-To: <ef4956a3-c14b-f56a-3527-23fcecf7e1a3@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 23:34:18 +0200
Message-ID: <CANpmjNPjj7ocn6rf-9LkwJrYdVw3AuKfuF7FzwMu=hwe7qrEUw@mail.gmail.com>
Subject: Re: I915 CI-run with kfence enabled, issues found
To: Dave Hansen <dave.hansen@intel.com>
Cc: "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z2ZWtI8d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Mon, 29 Mar 2021 at 23:03, Dave Hansen <dave.hansen@intel.com> wrote:
> On 3/29/21 10:45 AM, Marco Elver wrote:
> > On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wrote:
> > Doing it to all CPUs is too expensive, and we can tolerate this being
> > approximate (nothing bad will happen, KFENCE might just miss a bug and
> > that's ok).
> ...
> >> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on KPTI
> >> being enabled.  That's probably why you don't see this everywhere.  We
> >> should probably have unconditional preempt checks in there.
> >
> > In which case I'll add a preempt_disable/enable() pair to
> > kfence_protect_page() in arch/x86/include/asm/kfence.h.
>
> That sounds sane to me.  I'd just plead that the special situation (not
> needing deterministic TLB flushes) is obvious.  We don't want any folks
> copying this code.
>
> BTW, I know you want to avoid the cost of IPIs, but have you considered
> any other low-cost ways to get quicker TLB flushes?  For instance, you
> could loop over all CPUs and set cpu_tlbstate.invalidate_other=1.  That
> would induce a context switch at the next context switch without needing
> an IPI.

This is interesting. And it seems like it would work well for our
usecase. Ideally we should only flush entries related to the page we
changed. But it seems invalidate_other would flush the entire TLB.

With PTI, flush_tlb_one_kernel() already does that for the current
CPU, but now we'd flush entire TLBs for all CPUs and even if PTI is
off.

Do you have an intuition for how much this would affect large
multi-socket systems? I currently can't quite say, and would err on
the side of caution.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPjj7ocn6rf-9LkwJrYdVw3AuKfuF7FzwMu%3Dhwe7qrEUw%40mail.gmail.com.
