Return-Path: <kasan-dev+bncBDEPT3NHSUCBBUF7W3XAKGQEXFSEYXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 56367FCDF2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:41:22 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id k7sf5183659pgq.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:41:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573756881; cv=pass;
        d=google.com; s=arc-20160816;
        b=dnbl1ad2wucC4+987jO+K5+p5xeVEpKBJ+nTbhimVRlIuKkOv33HQItgmFXXyAkm05
         u5XGEDNv+jNRlMNHNILZJfBTYRdjomLyRvHFMPOGC7qjv/AA4F3tESRuhpkii9Ff6ldU
         FVOLwJqRjzp0E9xwxxkcLDESwsj9DMdm2RbR3UmALOMOzZjn6qYOAb142mIQ5g9i3wGO
         aDtudR3skSbLWvZ1nYSHeEBY9KyzAMM9hP0+gMOnN3/PdG6aryRDlQwaq3zuJ/hyG401
         LenzYKpK82RqobaBupO09OcVH+y/O38cXF1UQOkjzqGXwLF5Y+tLs2COp5MkHl2LKD/9
         7JYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=W3peracX3uX8SxwZSjZFBvwgCViGvp+SdHQsb4KDF/Q=;
        b=iYY7IKX1CQB3SLxHNZrpiok4ikkiYTiKi1aC2PMp0/LxzCCRjQxie2qfePhtY57Ozg
         4tT/wH3SCVxbc8/NzwTMZEGBqySVOyyGP0SwK9E0C0b0+Y9yikka0NTDnprXLPL+P+cP
         Vfn0JJnRzjZOXGxpuMd/6udCRS93PLClEB3feULSxRWxmwLHSNkIH3jKWgWCzOay/o1M
         nfqjnHG61EkIio/Sv7shAFU1YUN4lFmoydXbxb6ISU7DY1mhog2hPTElDmqF4aSJzgiO
         MmjBsBNvbNsSG38VCPrMTCwrD7EcYuYk/mXVfRbe2TYkwYPLK7w/+dH/QYX4/DoYb5JF
         J6+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Aov+8BbS;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W3peracX3uX8SxwZSjZFBvwgCViGvp+SdHQsb4KDF/Q=;
        b=MnTkGMt+kKt4riTJwEaKWNqVjbOslTKEQ1ZvJj1mCASozkJQBcvwI13s/Q56waqTkO
         4qcRH6TQRQqy+7J5bioG6hyPLEYCEulCNItetcBdhJP5yspiZs/CC4qmMC2K7FVwc2LQ
         gKWt5C1tJAyYIMbrrsB6A6sEySv7BON+X9qYp7cyxXa1qhuESn2lj/cHhHQiBag2cVxz
         i/+juKT/ccQZtf01J73oC/dihgPrNsPqkE+L2Y2Z3R4FfxDY/XO6/3X+HGA3h/ZxPEjx
         S6/C0IyYaFGExTkcDt+zETV00FxsjnYIYZm06kcwEC4at3MHEEGQuXZfiwXwZbzKG/Qa
         4gYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W3peracX3uX8SxwZSjZFBvwgCViGvp+SdHQsb4KDF/Q=;
        b=aTxnnP7Qx6ZZq+lszvhJirxarAEaAkpSeA2LCYyxBUlSiAh0fX1+HK8tCqn6vWW5k7
         DUQqTeSqJHx9+A45ozdQKIw/mLZClGGzdnIW05M/goJGMu23HQUFLpAznlh7zdi4jZST
         A3QreqJWXvoGwKvb4MRECTwwW33blTka/KSOBlNBbjXMUBPIMfZ0WWuHB4/5q5VG0HXu
         Sc8Hfp1tJ2vknlg9TTq6DqSZPAZws0SEhbUfuh99XfVwZV50MW+2PNka9fhXjH2rSYN6
         z5j6i73yUPRS9iy8MYNqDnbH0Fy2Zeyg/dgdQEUnrRh8N72REDgjEyx+fNJSB/C+c4Rk
         xmhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXSnBSmJFwoDmDgWyfYSP04lnVh3PPgFXps59quroJ1olB7g63K
	zVeONvgf5MNMDQJmhjsRuGU=
X-Google-Smtp-Source: APXvYqzuOrmbYvygky6aF2r9CeawgWsPBb2TRuJf1sOJX7Hpys/P8BD+1BDtL7NdJvFee2Q1Su+d8w==
X-Received: by 2002:a17:902:904c:: with SMTP id w12mr11119641plz.144.1573756880992;
        Thu, 14 Nov 2019 10:41:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:a50f:: with SMTP id v15ls919508pfm.14.gmail; Thu, 14 Nov
 2019 10:41:20 -0800 (PST)
X-Received: by 2002:a63:91c1:: with SMTP id l184mr9866631pge.57.1573756880589;
        Thu, 14 Nov 2019 10:41:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573756880; cv=none;
        d=google.com; s=arc-20160816;
        b=R5RHjp8evx1hIyTxnoTNJ6sELKU5A/tkSHtz5a2lK7wdF2XeiuiuMVpx+9+54nEa2T
         bkE0yvX8101ZlmDFdeRxtPqEsSCQbht++aJwnlWTLmgiFtQ4136tkhiy/e09qIPb/eOU
         XQgVMfS08DMGRRXumuNPt5IsDecoqqrFY2jia6BjAIxiZb+tig3/PbSXiYMTGOMccLS3
         YPZ0U1UBD118iaRjGU8zfmC3aMh73MqIUeJ0f3D4VsFPAherO2KO/syzMTZCrXfrax4P
         kXtGewG+/o5cwnz++Ej5XijQrSLcyMTSDIaEVFAIvfclJnWFMWe19+uueIMloe126ZSm
         hnaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YlfxgaVenhSJAWAQse27vMQOL6nd8/BRzLqyo+P+J2g=;
        b=U3HEhyetshmCLWOHkrKBzSZyadgVKnkK6gGJx+rH6QPiEf6lt0MBfrH3Xm8d2EEJKT
         anXmmIfgCuA0B4l7hfsVkQUfQ33DVEe/IgKir5JaAUIwi082PiZlQB4W+cSsjp5Lc74+
         66C9iEDcFK1NiMLq+H8Re102qlmHjoK4F1jTpGNGdSkFLjSL8dCwsse0TrL0Opjkr6e1
         PQxPCaYyayUiunkJJTPltpxFtG1PHpG3tGMp8wNuoOXptGyUwe2xQuufvTCiAb6naAnR
         vd59a/eyNdlvZslCStjQoEVEjkU05HUKQDb4tc4WsofxnNLxXUpE+7qkvSOhtsofUjIN
         Y5JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Aov+8BbS;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g10si259741plp.4.2019.11.14.10.41.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:41:20 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f44.google.com (mail-wr1-f44.google.com [209.85.221.44])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0ED6020727
	for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 18:41:20 +0000 (UTC)
Received: by mail-wr1-f44.google.com with SMTP id t1so7722223wrv.4
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:41:19 -0800 (PST)
X-Received: by 2002:a5d:640b:: with SMTP id z11mr9414430wru.195.1573756877389;
 Thu, 14 Nov 2019 10:41:17 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com> <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
 <20191114182043.GG24045@linux.intel.com>
In-Reply-To: <20191114182043.GG24045@linux.intel.com>
From: Andy Lutomirski <luto@kernel.org>
Date: Thu, 14 Nov 2019 10:41:06 -0800
X-Gmail-Original-Message-ID: <CALCETrVOPT5Np9=4ypEipu5YtXyTRZhiYBQ1XZoDd2=_Q4s=yw@mail.gmail.com>
Message-ID: <CALCETrVOPT5Np9=4ypEipu5YtXyTRZhiYBQ1XZoDd2=_Q4s=yw@mail.gmail.com>
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Andy Lutomirski <luto@kernel.org>, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Aov+8BbS;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Nov 14, 2019 at 10:20 AM Sean Christopherson
<sean.j.christopherson@intel.com> wrote:
>
> On Thu, Nov 14, 2019 at 10:00:35AM -0800, Andy Lutomirski wrote:
> > On Thu, Nov 14, 2019 at 9:46 AM Sean Christopherson
> > <sean.j.christopherson@intel.com> wrote:
> > > > +     /*
> > > > +      * For the user half, check against TASK_SIZE_MAX; this way, if the
> > > > +      * access crosses the canonical address boundary, we don't miss it.
> > > > +      */
> > > > +     if (addr_ref <= TASK_SIZE_MAX)
> > >
> > > Any objection to open coding the upper bound instead of using
> > > TASK_SIZE_MASK to make the threshold more obvious?
> > >
> > > > +             return;
> > > > +
> > > > +     pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > >
> > > Printing the raw address will confuse users in the case where the access
> > > straddles the lower canonical boundary.  Maybe combine this with open
> > > coding the straddle case?  With a rough heuristic to hedge a bit for
> > > instructions whose operand size isn't accurately reflected in opnd_bytes.
> > >
> > >         if (addr_ref > __VIRTUAL_MASK)
> > >                 pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > >         else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
> > >                 pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> > >                          addr_ref, addr_ref + insn->opnd_bytes - 1);
> > >         else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
> > >                 pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> > >                          addr_ref, addr_ref + PAGE_SIZE - 1);
> >
> > This is unnecessarily complicated, and I suspect that Jann had the
> > right idea but just didn't quite explain it enough.  The secret here
> > is that TASK_SIZE_MAX is a full page below the canonical boundary
> > (thanks, Intel, for screwing up SYSRET), so, if we get #GP for an
> > address above TASK_SIZE_MAX,
>
> Ya, I followed all that.  My point is that if "addr_ref + insn->opnd_bytes"
> straddles the boundary then it's extremely likely the #GP is due to a
> non-canonical access, i.e. the pr_alert() doesn't have to hedge (as much).

I suppose.  But I don't think we have a real epidemic of failed
accesses to user memory between TASK_SIZE_MAX and the actual boundary
that get #GP instead of #PF but fail for a reason other than
non-canonicality :)

I think we should just go back in time and fix x86_64 to either give
#PF or at least give some useful page fault for a non-canonical
address. The only difficulties I'm aware of is that Intel CPUs would
either need to be redesigned better or would have slightly odd
semantics for jumps to non-canonical addresses -- #PF in Intel's model
of "RIP literally *can't* have a non-canonical value" would be a bit
strange.  Also, my time machine is out of commission.

--Andy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrVOPT5Np9%3D4ypEipu5YtXyTRZhiYBQ1XZoDd2%3D_Q4s%3Dyw%40mail.gmail.com.
