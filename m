Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBRFY7PXAKGQEFGUU47Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7F5410B768
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 21:27:49 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id f15sf1239295iol.21
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 12:27:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574886468; cv=pass;
        d=google.com; s=arc-20160816;
        b=FS8Ktoz3DGY4wDZvj9NcdRkxbQe79ZuP+vc8UCjJgnO1DXGKMOBSOqYZ9FY/NZd+fu
         kAxfvO6W3uZiPc3hnfxHBilNpb0nkfPAwsv3ccUr2RDoUzf7LSwsImrXGOnKTxJRiqqB
         VYV7pnFYybC+/J3TquZqje18VEuY6AvVEky7FuZYfv6BHNTBrgwukvGyb8mwX1f6B4+D
         jJqo0wIUybjnQdZeZxRl4II8vyrPaIsXgBKuByMMJzizfNOE89FcltOyq0e1ZgVb8+JB
         hLF1o3GRONQEOuxxd9wTdTQ29BCUW0U2O9f5WVLI4bcjNsNv68g66F2mwuNItfycNJuR
         7k4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jMsPz/j9py8fwDzHCRzHRwEVjCjYaxR2slyVDYPLSqM=;
        b=O35friqpq4qWZaBYxtUZ/yxklBjlS+pqTC1hmpHfBqtjC13dhmTfFRaJ8lDuAMeEeX
         jj0O3Ksvw00hjEfn4Kyfmtrfhy0y7jpQ3MafwWs2BiY8tKWsZRCilWoko4qtf8Tf8drR
         vTi9veYZHCi4FywvPgYFiHY0FA6k/3ynIlxynMCbB9iVKINit4km5wxZ9f9RRfJkiD7R
         7sIPF2wbcB19RdEKxtVBw//gPcXFy0V9pArF5Wz+v94p302Bp5o5TF1yLDo0WgDbhtRv
         8dDJ5KgmJRuISQXpH/G81foNahjxQVG9UFc0CBeeGr5PfbXROjG5uQCxSwNWQpU8fxAM
         +JfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UkHiWpu5;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jMsPz/j9py8fwDzHCRzHRwEVjCjYaxR2slyVDYPLSqM=;
        b=WkIgiJgZvu7XyjtuJBlmcUp39+n4qBfBdD8/fRy9r2gAQ29rOAe5GYTL5Iphrua1QW
         69zFet3wAJkAmPgx1urgO7GdHWII/Mpx4A+teDOz91dT/0ZUl0BCIxdZe9Y2Fk3wVEcI
         A93ckqOo9++OGA7IRA7EjDsC7cUtzhrrtuzQf1R89u6f0Jj7ZEoGkKfztW6BoGJY64br
         Crxyto7L4YVz4/9/xwCqs+JYXaZlICahIs2axXetUPlA3Dkazz0LB2AYmCISKg/Fn0Ci
         Z0Kh+qSBm5QqEUvIIjM5jsvxVCJYfcrDG0ObjW0a7pkUOvGI9bt08EQ27TPtYHDIwHGy
         2OCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jMsPz/j9py8fwDzHCRzHRwEVjCjYaxR2slyVDYPLSqM=;
        b=Ll8iVOacqS7yUKddvv2NByzjkggeeHdJF2K+NH08mFcfAeijbSV/cjtIzgicSMz3+y
         BmnqV1CZT6KQR5nO+qbwhKORyGR2SzjUD8R9Z1QyATaQ6Q5DgELXAA2aKrUYcIFmlB80
         Q1ecS5G+KTBizw0wb1sjbDRnQXEMcJjwBwNBh0cu5z3HBNWxrU1sl7NdTDqgOg27QebZ
         KYJ98sFWyvLm6ZqTPU3C7hGz2/wwIei+Wussrrv1ABwbAxd1Udm8pTKNb0pSlDYl26XR
         pQpucaulllWC5Md7uveTOEcU+AfbL+qmyEX6RoM3L+NmYYzBMx1Q5z4lE1wLZJ4riQtK
         yMbQ==
X-Gm-Message-State: APjAAAXigLsbxGfksX+idJ2Gqezs0NwJd/M8vFBPrn1ZAmlHIE7vJd/o
	hzYEJZb+GvG1IugJLPM4hxc=
X-Google-Smtp-Source: APXvYqyEJkgk3kxO5aeZPnWcvaEJGp/IdOQbGssu6zj8HVy1Vu5U7JM6sNI/u50/VpUKz27DX0h1gw==
X-Received: by 2002:a02:7708:: with SMTP id g8mr6486452jac.9.1574886468451;
        Wed, 27 Nov 2019 12:27:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:81d4:: with SMTP id t20ls3756057iol.16.gmail; Wed, 27
 Nov 2019 12:27:48 -0800 (PST)
X-Received: by 2002:a5d:8a06:: with SMTP id w6mr1729957iod.216.1574886468104;
        Wed, 27 Nov 2019 12:27:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574886468; cv=none;
        d=google.com; s=arc-20160816;
        b=yjhkIkKqE+mRON9uwLRr4pE+YbFq4Xc0n+EF39uj1kPyhvkwktVnJ9Q1z6kefuAmWf
         oGQSOzKu18Do82/GXhBN0yKzF6chOD5oavpuD6qkAwWBpJs2pbxi7IKnSQMmk23OUoj9
         6oFwJK/IFMW4IboUJUkiLZ5AXePPLge6fHsvf0YeciG0Gs6iRoEfB1OfvKfp1rB+FEFE
         KKBbTFMdQW70YL3XdYrkOJ5+i5lWlCgFhHH/c/fMFc1BzJzq5xoi2rMn6qvt5HlMzHcB
         GYZqO/kxd4xpOV4JaRIhGRxwhCPjenoJK+gCH72qE46XjgKEvNJejeTcVguntQdidsp8
         bYmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/9xP2Kq0ECGwvZPzuAJ5O0ZAlQ2V/eOMBzNaTBOLe2M=;
        b=CSR9Q7kyZzPGiE+IFdO59IP2Bgeh7NPFaJvXsdg1LY+yREKyU19b7UgtNsWiZCQP5Z
         wOupWKEWS3kS42P/kJgRWybih/iFZZNPuKfSxNNXfOybofu2yV7nS7xGocOa+zKIBEC+
         g2HFox13/UgM0sjw8dykIRBOWUQpN6pWapxaWCjG28n+nNJLQR++421t9yHR/2Mwp8iL
         hzGhpb19Au+8cni023w8pHFjJ1dKh+gNm2ElSeEmnnkqUxiIMUFCqqXF3Qdb3UA/X2st
         n7dhw+h2e31I6T1oTg68S8are0ODsKj6MXhI/64OpUM4B33vQ807hdV6VCqHsA5nyG+8
         1ORA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UkHiWpu5;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id k25si651853iog.5.2019.11.27.12.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 12:27:48 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id d7so3362546otq.3
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 12:27:48 -0800 (PST)
X-Received: by 2002:a9d:328:: with SMTP id 37mr4826013otv.228.1574886467145;
 Wed, 27 Nov 2019 12:27:47 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A@mail.gmail.com>
In-Reply-To: <CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Nov 2019 21:27:20 +0100
Message-ID: <CAG48ez2z8i1nosA1nGrVdXx1cXXwHBqe7CC5kMB2W=uxbsvkjg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Andy Lutomirski <luto@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UkHiWpu5;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::342 as
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

On Sun, Nov 24, 2019 at 12:08 AM Andy Lutomirski <luto@kernel.org> wrote:
> On Fri, Nov 15, 2019 at 11:17 AM Jann Horn <jannh@google.com> wrote:
> > A frequent cause of #GP exceptions are memory accesses to non-canonical
> > addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> > the kernel doesn't currently print the fault address for #GP.
> > Luckily, we already have the necessary infrastructure for decoding X86
> > instructions and computing the memory address that is being accessed;
> > hook it up to the #GP handler so that we can figure out whether the #GP
> > looks like it was caused by a non-canonical address, and if so, print
> > that address.
[...]
> > +static void print_kernel_gp_address(struct pt_regs *regs)
> > +{
> > +#ifdef CONFIG_X86_64
> > +       u8 insn_bytes[MAX_INSN_SIZE];
> > +       struct insn insn;
> > +       unsigned long addr_ref;
> > +
> > +       if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> > +               return;
> > +
> > +       kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> > +       insn_get_modrm(&insn);
> > +       insn_get_sib(&insn);
> > +       addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
[...]
> > +}
>
> Could you refactor this a little bit so that we end up with a helper
> that does the computation?  Something like:
>
> int probe_insn_get_memory_ref(void **addr, size_t *len, void *insn_addr);
>
> returns 1 if there was a memory operand and fills in addr and len,
> returns 0 if there was no memory operand, and returns a negative error
> on error.
>
> I think we're going to want this for #AC handling, too :)

Mmmh... the instruction decoder doesn't currently give us a reliable
access size though. (I know, I'm using it here regardless, but it
doesn't really matter here if the decoded size is too big from time to
time... whereas I imagine that that'd matter quite a bit for #AC
handling.) IIRC e.g. a MOVZX that loads 1 byte into a 4-byte register
is decoded as having .opnd_bytes==4; and if you look through
arch/x86/lib/insn.c, there isn't even anything that would ever set
->opnd_bytes to 1. You'd have to add some plumbing to get reliable
access sizes. I don't want to add a helper for this before the
underlying infrastructure actually works properly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2z8i1nosA1nGrVdXx1cXXwHBqe7CC5kMB2W%3Duxbsvkjg%40mail.gmail.com.
