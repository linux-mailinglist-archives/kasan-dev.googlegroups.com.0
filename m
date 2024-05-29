Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZHI3WZAMGQEG66D4TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B7998D3E58
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 20:31:02 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-43faa4d2080sf20438101cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 11:31:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717007461; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xe8SMqhl1/pHxJKmVcEbpH9O1Q7j4sACJzZlaI34BvbCzHdS8m2moGIzIePqxB1n5y
         Zyq+5/qQ+yKaxbE2Ww0ANJW0ZOf2HRDzXE7sUSFcLftoF3xNiY3i9xgJGBeC09Xav5vl
         y5AgGuZONkj1DmCG2WwAUdJsOdAbsEpSTiRlL4dJKrhNFyOUQIebL4FrDqGZfLVMQkZJ
         FGEkmSjHdIAoPBoirQBuvPnlr4Ub6pE12SVNOvtDSiM66ncbdG/H00BUJKNGcNJMMZ89
         hamiEmUIkwDThm3aBPPEeRE3PsYViGBlcKTRQgSHeF7ZM/kFqT06qPXeuRRagIKxWShK
         1WaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cg0aWoIz270Ya8HkB6dpOVNSOdShah7DrAtLdjc/+Gc=;
        fh=3r1K2Eb/gGoo0A/FzPjmgCH9X2Cgzsy4HdmfZmnT+f0=;
        b=n+KG8JlBTRaBEEpeQfxe6fiRYOtqOIqqJ778Vpw5ovp9hGb4tslRpKrsnhNs7tTom7
         616BEWCzERxonWy6XyU8DY5LqmgOUAl8oMTbP8DUJE6F+DVYnEt5kx4XLyhxR+YLoZSc
         VOkS3QKHQJmPKuA8kItBsexyp52cwhdTX7KnMmjhvA/6Q1Qsm3XyWqBS+6qb0z5WJhQX
         Dtk/xVxpbxjwZL14Uc6RcqEZuwMWp5KcfMEEZP08FdFGk57hjcm3XMEXiAIGbL4hoS79
         xzuVXmSY5fwu8DUCkwJ86QXXaHZyofQ5utXqzcFLcCpVJYOuxhHbEA7dpgetMTFa4b9w
         GrOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gTd4vGFK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717007461; x=1717612261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cg0aWoIz270Ya8HkB6dpOVNSOdShah7DrAtLdjc/+Gc=;
        b=vj8h3CbKSZhLBWPlzwa/3o+ir4UlwG9X76SeJpyLGeuZLlfvrLJkxrE7WdHEXDLDMC
         VlYTY1eCj2qNT5GBNjjPaj9DUiwmBap1VRHjkK0cuLSqqhZzllOihUAS0jF4hMiGKJYd
         tjofJ3hyI4ol+Sbgpoli7l+CtcEuTuZEdtozIS1xMphhgVJ+7FU6xmJuJMENUC1ZZDkT
         62WclJao/utdPCE952ndqtlMYj5eMmDDa7AeGCJoc9YpIT7Fab96JPPj3+tJ7DZL9T5d
         NbRRUg0HyXQgnwhZ5ACXTNSHlQLHv7Koi+UPyUK7sukuUenGiqpWU4FZ/Tl+gEzTgwk4
         HOVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717007461; x=1717612261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cg0aWoIz270Ya8HkB6dpOVNSOdShah7DrAtLdjc/+Gc=;
        b=Mn0F5WrASx3ntGbRTvsoqBdDxe9Ll8wf97DY50I2e47Sz0VI6WelhpXsaifp0e771S
         IXSoHW3huqQyB0bmEObXyb8h/443Wr22V/mkRGobdWFNCClqV3X65SCACdRkYe2M3XLa
         KeEmJvpmsjLGaX7qlv2yYwrJiKUeTnVZ6//6VZKqJ1fFFzUuUEmBsy518HsZC4FyinAD
         G/DHXn6IVCvpgqHqHxE+vBAVOUpMg9w2fGK8zV3EJM3Oj7BCa6UjDvu87N2X9mV1NKc3
         kphfYJXTtqnqZ/5TC2lR1rwVCufXQHIFd30jq5CtocwOaFK42OHkJN76SyJkcWTav0ib
         7Q5A==
X-Forwarded-Encrypted: i=2; AJvYcCVOPUSopX6Z9VG7+13QcAabe20p9wyGXNqt4IDptUG9p2GOtGHKnOk7ttbcjZeTkkWz3FvlbHrWfUtrJNVrjV0M/i3Uf1183g==
X-Gm-Message-State: AOJu0YxhbKrHrH9/0u+bRdBgmp0B7V9cMDqV3S5ep5038plajujF1TZj
	bkWV4o1vUJqRhfgug5hoiz3HGY1VZAe0eqTS3UDzMlKkIVqVdbhf
X-Google-Smtp-Source: AGHT+IFPY/PQywOQJNI52zTmZV2LpuHgAFSQ1gSPg35Qb352mzzikXtLnLpWxez7uCzkc/VDYoDbbg==
X-Received: by 2002:ac8:5dcb:0:b0:43d:f0e4:65ef with SMTP id d75a77b69052e-43fe92ab507mr594791cf.4.1717007461076;
        Wed, 29 May 2024 11:31:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e89:0:b0:43f:e7c7:a4d0 with SMTP id d75a77b69052e-43fe915b540ls454831cf.1.-pod-prod-03-us;
 Wed, 29 May 2024 11:31:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbrn1AN6Q1usGb3cxXEnfLbnTtlgxt25y0xIDEVbF5BJgsr433+hT1Kxmjf1/LB5uIJyU1oj+y1WZGl9YWlMh7WOMGbZQyXWNHqw==
X-Received: by 2002:ac8:5f14:0:b0:43a:fa90:edb6 with SMTP id d75a77b69052e-43fe933a649mr243311cf.60.1717007459989;
        Wed, 29 May 2024 11:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717007459; cv=none;
        d=google.com; s=arc-20160816;
        b=jFNKmlgxIPJRezt5uMplLEHayl1q+avjduhzorsYxq8KWuxQNrsaBRDqaBFi53BRrT
         liYcA6ygNCxIa6Q3OAIqvo9XVpT5cQiSXrwk21RaXXpbc/K8+w2O5ZFhYn+54ROVl198
         0kDqugxpI/Wex1YL49JYSfLn9aqFDM85cNBIY9DuH3p5EGKWzvySrpUmZM+zrz/yCYkw
         6LbAbGIBa2fazaNM6y4s1ljVZBVHDBNPkgsrQ0m0P49jsW2PvQTmJRaxrR4nHt3qtHpj
         9S2jAXk9Db+sSY9zag0HKus73fEK+yPbtIv28lk3dm73eTwpuEAbaT/cPTsl9tngtTWZ
         8bUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RbCogX4lIMiJS1kYrrISzNNe/fzp3T/RrkQJx2fP6us=;
        fh=8DP16s2yak6XIPVHoov+Hn4+kWOORx0klmrEKa6a1J0=;
        b=SMFMzBZZMdLVIfzOaE4WxnDlSQ6PUOqvPEOmye7qSzsopDXYl4OFWOc14migovwnIb
         TLOg23HhcNNBckwvth17dyFly57VQMsYgcjOlcaCudQ50MTJlU0ShgWqRDk3hHhOhGjL
         6lw0Ijn/Rzpaz2BHEa2lQIu4pTdYywLf0weSeBuoo8nHWX/m41MmKkY147EDQFyK/g9M
         PoxiedWUaKxsMQM6aorwydyBAfdf2zuq5hNDDhtgb9V/7/tQlxfDODLQPzXRUBgbfbtX
         dVwTG8ZxG3aF8C81jnuCsPL8ahmu1+rOO0o7dCEfbZkRQHWaOFbVTv/mh2QyqVqAmfAT
         9O6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gTd4vGFK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa31.google.com (mail-vk1-xa31.google.com. [2607:f8b0:4864:20::a31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-43fb18b26e9si8366201cf.4.2024.05.29.11.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 11:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) client-ip=2607:f8b0:4864:20::a31;
Received: by mail-vk1-xa31.google.com with SMTP id 71dfb90a1353d-4eaef863a08so21181e0c.1
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 11:30:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWILT5W/itmCkWMGE89ojC3RTPRONl73GQpJ3ZiBOzSW6XwcyXlGsHCJoYnXzQVv1ImQ0XCHmG9cSptV6Ov5D10I1Hs2L8LyvKCSQ==
X-Received: by 2002:a05:6122:168e:b0:4df:261c:fc0c with SMTP id
 71dfb90a1353d-4e4f02e650cmr15206852e0c.13.1717007459290; Wed, 29 May 2024
 11:30:59 -0700 (PDT)
MIME-Version: 1.0
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
 <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com> <2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh@fi53ovwjjl3w>
In-Reply-To: <2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh@fi53ovwjjl3w>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2024 20:30:20 +0200
Message-ID: <CANpmjNM4pFHYRqmBLi0qUm8K2SroYWg7NFjreHffHvk0WW95kA@mail.gmail.com>
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>, 
	Rick Edgecombe <rick.p.edgecombe@intel.com>, Changbin Du <changbin.du@huawei.com>, 
	Pengfei Xu <pengfei.xu@intel.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gTd4vGFK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as
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

On Wed, 29 May 2024 at 20:17, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
>
> On Wed, May 29, 2024 at 09:25:21AM UTC, Marco Elver wrote:
> > On Wed, 29 May 2024 at 04:20, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> > [...]
> > >         if (regs->flags & X86_EFLAGS_IF)
> > >                 raw_local_irq_enable();
> > > -       if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > -           handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > -               regs->ip += LEN_UD2;
> > > -               handled = true;
> > > +
> > > +       if (insn == INSN_UD2) {
> > > +               if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > +               handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > +                       regs->ip += LEN_UD2;
> > > +                       handled = true;
> > > +               }
> > > +       } else {
> > > +               if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> >
> > handle_ubsan_failure currently only returns BUG_TRAP_TYPE_NONE?
> >
> > > +                       if (insn == INSN_REX)
> > > +                               regs->ip += LEN_REX;
> > > +                       regs->ip += LEN_UD1;
> > > +                       handled = true;
> > > +               }
> > >         }
> > >         if (regs->flags & X86_EFLAGS_IF)
> > >                 raw_local_irq_disable();
> > > diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> > > new file mode 100644
> > > index 000000000000..6cae11f4fe23
> > > --- /dev/null
> > > +++ b/arch/x86/kernel/ubsan.c
> > > @@ -0,0 +1,32 @@
> > > +// SPDX-License-Identifier: GPL-2.0
> > > +/*
> > > + * Clang Undefined Behavior Sanitizer trap mode support.
> > > + */
> > > +#include <linux/bug.h>
> > > +#include <linux/string.h>
> > > +#include <linux/printk.h>
> > > +#include <linux/ubsan.h>
> > > +#include <asm/ptrace.h>
> > > +#include <asm/ubsan.h>
> > > +
> > > +/*
> > > + * Checks for the information embedded in the UD1 trap instruction
> > > + * for the UB Sanitizer in order to pass along debugging output.
> > > + */
> > > +enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
> > > +{
> > > +       u32 type = 0;
> > > +
> > > +       if (insn == INSN_REX) {
> > > +               type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
> > > +               if ((type & 0xFF) == 0x40)
> > > +                       type = (type >> 8) & 0xFF;
> > > +       } else {
> > > +               type = (*(u16 *)(regs->ip + LEN_UD1));
> > > +               if ((type & 0xFF) == 0x40)
> > > +                       type = (type >> 8) & 0xFF;
> > > +       }
> > > +       pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> > > +
> > > +       return BUG_TRAP_TYPE_NONE;
> > > +}
> >
> > Shouldn't this return BUG_TRAP_TYPE_WARN?
>
> So as far as I understand, UBSAN trap mode never warns. Perhaps it does on
> arm64, although it calls die() so I am unsure. Maybe the condition in
> handle_bug() should be rewritten in the case of UBSAN ud1s? Do you have any
> suggestions?

AFAIK on arm64 it's basically a kernel OOPS.

The main thing I just wanted to point out though is that your newly added branch

> if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {

will never be taken, because I don't see where handle_ubsan_failure()
returns BUG_TRAP_TYPE_WARN.

That means 'handled' will be false, and the code in exc_invalid_op
will proceed to call handle_invalid_op() which is probably not what
you intended - i.e. it's definitely not BUG_TRAP_TYPE_NONE, but one of
TYPE_WARN of TYPE_BUG.

Did you test it and you got the behaviour you expected?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM4pFHYRqmBLi0qUm8K2SroYWg7NFjreHffHvk0WW95kA%40mail.gmail.com.
