Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBXFD32ZAMGQEHPQ6NDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 38D408D3FB5
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 22:36:46 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3d1c4410a80sf80918b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 13:36:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717015004; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGAmH2cSPc6cwlyPyZLRGIaPQAe9sukEW27GjjEzgYhvmNF5qETuAbR0xOFE2eYQIC
         oONWZoJpm0BglZT4gkGF4Bhi/djLP89bVR8rHN6cZJQpHilcA4Uu7Srky2Xh7iD/JqwF
         bKMAV8yuC/V0tkwQ3P170hjuEJvdwY4MQw/H2HS9zd4a1WBZlYTOOH6HM/DFKKtF+OVL
         gB1xe9sb2/+jJdz6dGl2gPXPOI/ij8Qwr4kVk7nhpg+/LtbtnUCDHTx6GPdO4lZyX4qN
         duV+Q4S1zXlZsUPorRwLGAzuA0wFpNTJcX4fxPtR2yjlU+WB41EiphjDiWg4R59uFW0p
         i7MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=yiikHfQjsXNDMbF+EHRsUJgtrSwvpZjIf/HdMSkJviQ=;
        fh=gCc6N0g3xthgWTWchXL5SBRNhqmPDBQp6TGKLe6gcg0=;
        b=mIfjfuUfkrrVMeJ3UVU84X3blIy7HoMWKQwoVYGecR01kZnNoL3tTtCQ+QUX4PCi7n
         1EITsh1uPi2tM9FWbJcynb4MLmxY234PgQHbCu+/y368t4SLcbkVLecX6EbbDFSuK5bv
         3iMk+j0yeCPcOjFimhOI7dAeTHYWoUaHUBk2NTWgWYcvR7qY6Q/2dFMoH4OCpTFDBvms
         x16WzXtnmcOlJJJL5XoxlCJteFQl02VwXMPUpzYVViBCrfakRbug71a6vtZr7pTMptik
         iA6tF/eUrQyF2UQ2nrGlaWF11UM/BKgTJg4+0m6eHWv0ioQ5h4/jfV5Dgmp9Y4ymv/Be
         IYCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OgsTfjRO;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717015004; x=1717619804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yiikHfQjsXNDMbF+EHRsUJgtrSwvpZjIf/HdMSkJviQ=;
        b=BtTcHf+52pr3RWCW3FA6r6SPCM6fFZ5LMlRMJsajKXVh/xKmDQG8kRvxZCk8jXA8/l
         3o+Y1C3D5KEHoajBbahZC9gjbGUGBsiHIlD+kse9Iiwt8Og1Y3kKyiQUjskXD30IO229
         jPszMlxguu7JnC7UOoFhCRkTbi0pUZBCH94Z0EXoQ0a+b7t1m74KqOy0VYfCgZeCkSay
         BiqqZ9IS0HVx/Laka94cCoxHDSvCDhvaM+uqKTSa1V0+6ZxnxT3e5OLaUib1ldnVkxOY
         MHBlYGMYFpJCxZMpz4EcQ+Jw0xxfhBFIserhIqbswcCxbXyhwrLatvMEyFJ/7rXa5VcD
         WWnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1717015004; x=1717619804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yiikHfQjsXNDMbF+EHRsUJgtrSwvpZjIf/HdMSkJviQ=;
        b=UEiFWtHl5n6LmeLx5mB9kJE+Nu4LZPY30SPi4qdnppR68g8Yw6IqqLE0OMlHpi/M20
         0mWP9vtsGxnE5miskJLyMc+nMNHWnk0YeFQadaLUmeF5zbLtMZXI/rP2ZlL6PYEDdb5Z
         SJatDkgK3o8D2mX5pvjQAq3ZtJ52qgQ8MPnXCzE5iuZKO8JPEvtFmCtSvmlT4+s9pPdi
         /q6k+DedcPzWHhVlw7olwzPg/Jxd0PocEpy4TU0/B+Y7jz1HKSqxNIayhjs1meJF05gi
         jOQNlIyEZY8Km+YFX7NNVzIqMXlVBDgyrdnm49IvWLBSXC5T9xv8j3FxwcGds/JQ3OUk
         cE8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717015004; x=1717619804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yiikHfQjsXNDMbF+EHRsUJgtrSwvpZjIf/HdMSkJviQ=;
        b=jwOZdVb63any6+DvJEX6Sl/kaXfyjaVKWMlXvN9oLop95hNb06NFvDeedFQlp0wJ6n
         qGOg1s+VcJAaVt+ftiwUvOpJc47B7HbHdO5/69qy0+S1XAw5mSjR8m124wx1fu/pne6Y
         1HATZn8LdlhX5KAF9S/Pux2bZOZCM/DcwpOPKkXIXxe5frC7TbLO3wOct4wKnqJ1RY6/
         BkSxS+6ldooczF9PAU4uemPaPrR4oxocnjIjO13j8w61ImNc9QbPAchNFVTyh2JwW6MU
         dC8LM5bwM/LA2HI0BLcNPfvwqPAqy1nn3vdAmhIyrH0kxpZBiJ7dksF6Xt3nRjHu8dAj
         cq1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6o5a7ucVWMRRxeOmP9eLhPVE8Pgavu+fFaQ+NxU2MZaUWYiQAbVECN4HciyqQPhsevMK9sISd5tMXoG10oE5a1xfK3gOzfg==
X-Gm-Message-State: AOJu0YzU2lgACWwmozaG0aMW4BRl/0qM8f063ZPCBLgEUgonMheZxP77
	DxMgLZ1PeZlwx3QOfR47zwPTOrD/8AtYAvpdj6v2uAORKkhFxhRZ
X-Google-Smtp-Source: AGHT+IFf9479wifX8ByaXgOIsrZ4MWhBnL1BFbRuKJ4/RqniTd9rYduVnUX25CYHD97eRwvR+PIpbA==
X-Received: by 2002:a05:6808:15a0:b0:3c9:68bd:5786 with SMTP id 5614622812f47-3d1dcd13c6dmr175236b6e.45.1717015004558;
        Wed, 29 May 2024 13:36:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:242b:b0:6ad:78c0:24fd with SMTP id
 6a1803df08f44-6ae0befba8cls2253686d6.1.-pod-prod-08-us; Wed, 29 May 2024
 13:36:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVW39jkXn9MIBmWGwe771Fnq4iFdtHyWwSIVQUC2QGtSuHE22ugJsbvWaYHVXAa9WzZWA/vstNIxxRDQ3WuBFBifeSC146Zff9q7g==
X-Received: by 2002:a05:6102:9ab:b0:47c:549c:d6a3 with SMTP id ada2fe7eead31-48bae9ac61emr349360137.2.1717015003188;
        Wed, 29 May 2024 13:36:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717015003; cv=none;
        d=google.com; s=arc-20160816;
        b=CHPwKGLP586NxpGf+QQUnH3QnwdjqXH4igK1p1Y5Mp9+6h4xM7z7i2ZFVQwQFSCReF
         F94L5Licwzd3IXtEIMGqJyuhaaN7Uw8Ddr1k23EZlinEaHZn8iKq2YmKT1Kl3gerOVMr
         /YugHmx3e2IW0yRrsTXSrZvIjh3fgXM3DqyHJPLTQa7tgK9BMNSM/dWdGR5pbvKivqKH
         bdGaqS9iCNkDZRMBrXI3EwTG9RhbX2AH31dmpTJnWcPOR4xxlDwzG0MCBbq1xdzEZwtS
         3LBbKgoqyBfrBatRzOeNLzsZIlw45dTzUWfJm4fBwxKYx1ua0inxrbMD88ctXSZIiAN4
         ibIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JsDD1NAPFioHO4gLv1AtQFDU2NR/QOFSQPXZbsUyXIQ=;
        fh=3rei658ie94vatLQHvxO8AMrwTlyV9QYmEm95lMFHw0=;
        b=dRamcw3dVkYbLJBFXmy2VKuEz3Y9c0kuc5pDghk4lOnP20UNC5QKRTr09V9KfEDzo9
         Ovgeli/CB5zgZ6QCm49GJFGUEKRp27sU/NVziGV0hEkPcCiKsLq/dJ8Sbi/blGWdaWYe
         5+DG8j5cw0SlopcLCvK3JKyHgg3malwmdn8WTd1ztBzdT1BWQGnKUuSsyC2X7VZvLIEW
         DngILnuVC09l+c+2G5P16VgUiaYbswojqtjwHYgg/kPPe5hqPjcnqFN5TDUl13ovZ1eO
         nFQ9ZtbSiwCxsNmLeBq464KqVzcB2843kU2oV4ywcV1yH4Mb4jNiqorDQKe1HleL/xm6
         Pptg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OgsTfjRO;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48baf364be0si4980137.2.2024.05.29.13.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 13:36:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1f32b1b5429so1373265ad.2
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 13:36:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVxQyZtsItx0SwSIC0Yotka44YLw9Gq0w/1Zl3GFv8bOvKjYmzXKhs7yN74RAcQdrfMnT1aF8xhYACxCiswh62E0fLcEzpQQZSdsw==
X-Received: by 2002:a17:903:8c3:b0:1f2:f986:595d with SMTP id d9443c01a7336-1f61a4dd759mr1743215ad.66.1717015001980;
        Wed, 29 May 2024 13:36:41 -0700 (PDT)
Received: from Gatlins-MacBook-Pro.local ([131.252.143.197])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f44c75e579sm103603725ad.35.2024.05.29.13.36.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 May 2024 13:36:41 -0700 (PDT)
Date: Wed, 29 May 2024 13:36:39 -0700
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>, 
	Rick Edgecombe <rick.p.edgecombe@intel.com>, Changbin Du <changbin.du@huawei.com>, 
	Pengfei Xu <pengfei.xu@intel.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	llvm@lists.linux.dev
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
Message-ID: <57vgoje4bmrckwqtwnletukcnlvjpj2yp3cjlkym4bfw66a57a@w35yjzcurcis>
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
 <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com>
 <2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh@fi53ovwjjl3w>
 <CANpmjNM4pFHYRqmBLi0qUm8K2SroYWg7NFjreHffHvk0WW95kA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM4pFHYRqmBLi0qUm8K2SroYWg7NFjreHffHvk0WW95kA@mail.gmail.com>
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OgsTfjRO;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 29, 2024 at 08:30:20PM UTC, Marco Elver wrote:
> On Wed, 29 May 2024 at 20:17, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> >
> > On Wed, May 29, 2024 at 09:25:21AM UTC, Marco Elver wrote:
> > > On Wed, 29 May 2024 at 04:20, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> > > [...]
> > > >         if (regs->flags & X86_EFLAGS_IF)
> > > >                 raw_local_irq_enable();
> > > > -       if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > > -           handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > > -               regs->ip += LEN_UD2;
> > > > -               handled = true;
> > > > +
> > > > +       if (insn == INSN_UD2) {
> > > > +               if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > > +               handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > > +                       regs->ip += LEN_UD2;
> > > > +                       handled = true;
> > > > +               }
> > > > +       } else {
> > > > +               if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> > >
> > > handle_ubsan_failure currently only returns BUG_TRAP_TYPE_NONE?
> > >
> > > > +                       if (insn == INSN_REX)
> > > > +                               regs->ip += LEN_REX;
> > > > +                       regs->ip += LEN_UD1;
> > > > +                       handled = true;
> > > > +               }
> > > >         }
> > > >         if (regs->flags & X86_EFLAGS_IF)
> > > >                 raw_local_irq_disable();
> > > > diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> > > > new file mode 100644
> > > > index 000000000000..6cae11f4fe23
> > > > --- /dev/null
> > > > +++ b/arch/x86/kernel/ubsan.c
> > > > @@ -0,0 +1,32 @@
> > > > +// SPDX-License-Identifier: GPL-2.0
> > > > +/*
> > > > + * Clang Undefined Behavior Sanitizer trap mode support.
> > > > + */
> > > > +#include <linux/bug.h>
> > > > +#include <linux/string.h>
> > > > +#include <linux/printk.h>
> > > > +#include <linux/ubsan.h>
> > > > +#include <asm/ptrace.h>
> > > > +#include <asm/ubsan.h>
> > > > +
> > > > +/*
> > > > + * Checks for the information embedded in the UD1 trap instruction
> > > > + * for the UB Sanitizer in order to pass along debugging output.
> > > > + */
> > > > +enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
> > > > +{
> > > > +       u32 type = 0;
> > > > +
> > > > +       if (insn == INSN_REX) {
> > > > +               type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
> > > > +               if ((type & 0xFF) == 0x40)
> > > > +                       type = (type >> 8) & 0xFF;
> > > > +       } else {
> > > > +               type = (*(u16 *)(regs->ip + LEN_UD1));
> > > > +               if ((type & 0xFF) == 0x40)
> > > > +                       type = (type >> 8) & 0xFF;
> > > > +       }
> > > > +       pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> > > > +
> > > > +       return BUG_TRAP_TYPE_NONE;
> > > > +}
> > >
> > > Shouldn't this return BUG_TRAP_TYPE_WARN?
> >
> > So as far as I understand, UBSAN trap mode never warns. Perhaps it does on
> > arm64, although it calls die() so I am unsure. Maybe the condition in
> > handle_bug() should be rewritten in the case of UBSAN ud1s? Do you have any
> > suggestions?
> 
> AFAIK on arm64 it's basically a kernel OOPS.
> 
> The main thing I just wanted to point out though is that your newly added branch
> 
> > if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> 
> will never be taken, because I don't see where handle_ubsan_failure()
> returns BUG_TRAP_TYPE_WARN.
>

Initially I wrote this with some symmetry to the KCFI checks nearby, but I
was unsure if this would be considered handled or not.

> 
> That means 'handled' will be false, and the code in exc_invalid_op
> will proceed to call handle_invalid_op() which is probably not what
> you intended - i.e. it's definitely not BUG_TRAP_TYPE_NONE, but one of
> TYPE_WARN of TYPE_BUG.
>

This remains a question to me as to whether it should be considered handled
or not. Which is why I'm happy to change this branch which is never taken to
something else that still outputs the UBSAN type information before calling
handle_invalid_op().

> 
> Did you test it and you got the behaviour you expected?
>

Testing with LKDTM provided the output I expected. The UBSAN type information
along with file and offsets are output before an illegal op and trace.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/57vgoje4bmrckwqtwnletukcnlvjpj2yp3cjlkym4bfw66a57a%40w35yjzcurcis.
