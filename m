Return-Path: <kasan-dev+bncBCF5XGNWYQBRBF7W32ZAMGQE76LKKJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 78EDB8D41FB
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 01:32:44 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f34737c989sf3273205ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 16:32:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717025563; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbavJTBrRVQYyUmDJuKwJKLlCa6iMkFZDcrAzd9+ufkCh/VOkEMnAn3bRd2Fn7PDAu
         gA9ee31zDhTm6iIvTs49PmibFc+5VIQk8W5m82WmL2itE4zbHYUQ2y1xTeG4HS/YLUHw
         RvN1QN4h6zezLKUKIrWSlmUN9saIo2eASaN5Ed0Dyb06EgddtYktjdGpWZg3R+oGo/A8
         hwNac5gESsBo/AuEfNtyDH+Mwep/o/NpKMmQXV5vqhjOZ/yNd1YuUncZ+sRzER1OfT0Q
         6fiqrWRjemDySICr8jsEdF2FXzmpjyL3XnT7B1o2PgA6ITllOXbtp+WjDTkLYC83obLj
         EXZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NJSLLMjhbr3gIkHyshcZJqG6JuQ0jmXZ6KK9ojdJlyY=;
        fh=7q+zYUFUaQm2emDP0jWnUhfnSYP1HKsQeKWeKQA92YU=;
        b=eVpDhM2czhHZtFazj+JcXO6gYprgQ7Ps2fTPPLfX1kAgyw3/KqUzKgTdCsr7vrgl37
         ZZZ/wgLgLAeV3Xa4PwkV5Cf/5joJQ9txBUD50Hcu1xv0kbix+jr5W3TPzhrUwPPaC8LB
         LNAthJYP8PWEEAqBtwDjk20CRfjJMozFe0PPunpE+IRS75z7YdE4RAbhB5A5rgDu3gUK
         MVG20RgZx3q8yeCC7YWjiq02Hl9I/Kqi7+U6D2y+/89dFN1mSjwMzAVxoY9gWz0/x6Q9
         U9v7CklTCVVXF/nyNJ8Zee1vM6HllrhABO1mf6TjZph3wAZ2mlVW3AmBSLvfevfnkqW0
         sPZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HDmXuwiK;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717025563; x=1717630363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NJSLLMjhbr3gIkHyshcZJqG6JuQ0jmXZ6KK9ojdJlyY=;
        b=JNfexALigD//Mf2wNnR+2zYo45C8dHHb3R2bQy658GxIrTdYMum0BHln3YrWWwcA8e
         P7tn4yjgCn9yZVR0yagu9PaixwExcHr7YfeK9p7pKGNGYrP8+91fhLj1b8H8oBDB5ufe
         +psahbpj1BU+LoHXY6ia0WyF4/74vI4fpX2aE6G0wrNhAOMKH61RqigQ9InBXvN7t0FS
         l7MyvfRsaJgDz+aruMiu86evFexo4slZgeVJeY5b5net1p2fYpda3NrB/oS0+REn3pnR
         W1A2kzUqiV+z3OShqydiJFxRnu8k4zWPH4jTN6IFdhGSL/9dTVjPfoPhGdyt56VEgzW1
         t4dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717025563; x=1717630363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NJSLLMjhbr3gIkHyshcZJqG6JuQ0jmXZ6KK9ojdJlyY=;
        b=iE92K6K4cPpkCl6rDGlEZeXkkJN6Nyb7D5N8wcjGEz1xWBN/YCYyyA9tbGW99BBEcV
         StmSPxEYS5yBaKqSdD3I25h8NlZZ/8oXkGzluQKvToiPcVhkwqpss5CjOFjlAUT8BaEJ
         Jbu68iRNIH2wJ4aYMOVIrYncmp47KyXg+yAxDUTMcEKeQcE8Np1xWCLWfXByhBX9LRnr
         nOU8S6pH7pYUGmhWKblz1dBr+PO7ogvEc7ocOq6F2u0G6fbVuEvUdhvN3Vc/kLbHo7fC
         EO/fb2gvysDG0pATOZXi+IFgekFqXAJlrEcr51zUa1xt8o9RcFx2tdqG/rSVfj4COVGD
         7n4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkMS/4KxDhgnV3bnhGKhdE93tZ7sVC3+b+Ob/zKo6blG9z8ktMtaSiXQI/CRKuqx/qzZEgbEskToE/Fenk/n5bQUIGYVTyCg==
X-Gm-Message-State: AOJu0YyQU7L9pDpqvi84rq8ZTm4VpQ/r9VeRvg/ZW63c9JxCygQH8Pmp
	8wmi/t2OFPALMI1lGYNnUDigww+VgPJKm9Fk6aztqqBLh5sLugDD
X-Google-Smtp-Source: AGHT+IGbMClDMR7UaqBL6LUQZ5jKjIta3LbZa/52MEOg72pYsSOl6ZZa5X9+ue5ul9Qsgv1b0Ar7JA==
X-Received: by 2002:a17:902:e84a:b0:1f3:35d9:432b with SMTP id d9443c01a7336-1f6192ed34fmr4970285ad.10.1717025562881;
        Wed, 29 May 2024 16:32:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d1:b0:1f3:604:4b1e with SMTP id
 d9443c01a7336-1f61747c092ls2021475ad.2.-pod-prod-01-us; Wed, 29 May 2024
 16:32:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSxmnaCjGMpD4F2z1t/OJ20Dtn4DkJAYJ9377OHCFccQmCo0wbWBCjse9z4N25lt2RPY1CP7dAAc7EXLvDpDVcJVylrAuWE9OT4w==
X-Received: by 2002:a17:902:cecc:b0:1f6:62c:96df with SMTP id d9443c01a7336-1f619f0d733mr4928915ad.69.1717025558775;
        Wed, 29 May 2024 16:32:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717025558; cv=none;
        d=google.com; s=arc-20160816;
        b=dS0d2acEr1IMEEXcMg17niZ+OhqZHWoMCU6QaLQRKOpHB2F6lmJbS2ub+HCl2xbA0U
         vL59X9paM/mk1IqSBv9d6zvns1vAphLKWExV8kQqHwS1CtbaC++lFOBl/Nj6I92VTanC
         BDB+YFZmaKkiWv2ka+CqtZqN779uz1PLlDV0p1trxpEV9ooKXbwjwrxTFznE9EXC0Fe5
         WmaMfCs2Crv+ea5EBi2zuwsBmv7IULcA3mvGalLocPocHTeu+aUtYcsETKThKG6mlkL0
         VxYfN5KwcgxXppNJi5IX6TUwsd4EWvqaEpbkilxhsi0YA/cROYZc7q8W4l0M2rUnGxla
         At5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cucV7qOoOPIUrj3G8eYL6EQD/QmFAva7FNUzBgHa+iQ=;
        fh=xAfzT3V+C3a4Mlc6Cp1XKskk0t6uWIWdvYH3TrhyeaA=;
        b=MOLEhaqtIec/G3ZUc/gxQaq+GEZahjdTN/wYVTZeOXdb+4GzVH1mJN3iGy9tuZ5WhA
         58p1KgQG2u8aVOI3sQ9AYGuTYt+QzLfi2I7n2i+eP7g+YoM3T+7VCjF/qZSExoh9BtdA
         PMgYc4KOz3usIH7zbD1zoe+U8JUydD+IBYCl8Gc5JINAa9v6QLFHiMVpRQH5+JENmyVE
         ETSfAmj+nw21JGXyyKY7ncvQZVn788pfZtHjzK8oW/gV3E5HULrHCdasUBau5DidyKkI
         5nUSwRqv3vptqtiXyJv5gkFt9An6CX6+E4CA27+/4HB5epbvsWEoBhhOR+7rrIw93dHN
         UKpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HDmXuwiK;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f44c941c91si5413605ad.9.2024.05.29.16.32.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 16:32:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1f47f07aceaso2997435ad.0
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 16:32:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUXuMR42P3TzltcrFnePyTIRApoS8sRIEolre80TWHCx0YPZ6PCsLZGhnIhbUTJCr2Sn1+1m8Mf4rxURDwS2fXbq8T/bxertGO2Sg==
X-Received: by 2002:a17:902:d2c1:b0:1f3:903:5c9a with SMTP id d9443c01a7336-1f619936a85mr5241125ad.58.1717025558317;
        Wed, 29 May 2024 16:32:38 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f44c99d23asm108088905ad.208.2024.05.29.16.32.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 May 2024 16:32:37 -0700 (PDT)
Date: Wed, 29 May 2024 16:32:37 -0700
From: Kees Cook <keescook@chromium.org>
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Marco Elver <elver@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baoquan He <bhe@redhat.com>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
Message-ID: <202405291631.79BB8BF@keescook>
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
 <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com>
 <2j6nkzn2tfdwdqhoal5o56ds2hqg2sqk5diolv23l5nzteypzh@fi53ovwjjl3w>
 <CANpmjNM4pFHYRqmBLi0qUm8K2SroYWg7NFjreHffHvk0WW95kA@mail.gmail.com>
 <57vgoje4bmrckwqtwnletukcnlvjpj2yp3cjlkym4bfw66a57a@w35yjzcurcis>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <57vgoje4bmrckwqtwnletukcnlvjpj2yp3cjlkym4bfw66a57a@w35yjzcurcis>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=HDmXuwiK;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, May 29, 2024 at 01:36:39PM -0700, Gatlin Newhouse wrote:
> On Wed, May 29, 2024 at 08:30:20PM UTC, Marco Elver wrote:
> > On Wed, 29 May 2024 at 20:17, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> > >
> > > On Wed, May 29, 2024 at 09:25:21AM UTC, Marco Elver wrote:
> > > > On Wed, 29 May 2024 at 04:20, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
> > > > [...]
> > > > >         if (regs->flags & X86_EFLAGS_IF)
> > > > >                 raw_local_irq_enable();
> > > > > -       if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > > > -           handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > > > -               regs->ip += LEN_UD2;
> > > > > -               handled = true;
> > > > > +
> > > > > +       if (insn == INSN_UD2) {
> > > > > +               if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > > > > +               handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > > > > +                       regs->ip += LEN_UD2;
> > > > > +                       handled = true;
> > > > > +               }
> > > > > +       } else {
> > > > > +               if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> > > >
> > > > handle_ubsan_failure currently only returns BUG_TRAP_TYPE_NONE?
> > > >
> > > > > +                       if (insn == INSN_REX)
> > > > > +                               regs->ip += LEN_REX;
> > > > > +                       regs->ip += LEN_UD1;
> > > > > +                       handled = true;
> > > > > +               }
> > > > >         }
> > > > >         if (regs->flags & X86_EFLAGS_IF)
> > > > >                 raw_local_irq_disable();
> > > > > diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> > > > > new file mode 100644
> > > > > index 000000000000..6cae11f4fe23
> > > > > --- /dev/null
> > > > > +++ b/arch/x86/kernel/ubsan.c
> > > > > @@ -0,0 +1,32 @@
> > > > > +// SPDX-License-Identifier: GPL-2.0
> > > > > +/*
> > > > > + * Clang Undefined Behavior Sanitizer trap mode support.
> > > > > + */
> > > > > +#include <linux/bug.h>
> > > > > +#include <linux/string.h>
> > > > > +#include <linux/printk.h>
> > > > > +#include <linux/ubsan.h>
> > > > > +#include <asm/ptrace.h>
> > > > > +#include <asm/ubsan.h>
> > > > > +
> > > > > +/*
> > > > > + * Checks for the information embedded in the UD1 trap instruction
> > > > > + * for the UB Sanitizer in order to pass along debugging output.
> > > > > + */
> > > > > +enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
> > > > > +{
> > > > > +       u32 type = 0;
> > > > > +
> > > > > +       if (insn == INSN_REX) {
> > > > > +               type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
> > > > > +               if ((type & 0xFF) == 0x40)
> > > > > +                       type = (type >> 8) & 0xFF;
> > > > > +       } else {
> > > > > +               type = (*(u16 *)(regs->ip + LEN_UD1));
> > > > > +               if ((type & 0xFF) == 0x40)
> > > > > +                       type = (type >> 8) & 0xFF;
> > > > > +       }
> > > > > +       pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> > > > > +
> > > > > +       return BUG_TRAP_TYPE_NONE;
> > > > > +}
> > > >
> > > > Shouldn't this return BUG_TRAP_TYPE_WARN?
> > >
> > > So as far as I understand, UBSAN trap mode never warns. Perhaps it does on
> > > arm64, although it calls die() so I am unsure. Maybe the condition in
> > > handle_bug() should be rewritten in the case of UBSAN ud1s? Do you have any
> > > suggestions?
> > 
> > AFAIK on arm64 it's basically a kernel OOPS.
> > 
> > The main thing I just wanted to point out though is that your newly added branch
> > 
> > > if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {
> > 
> > will never be taken, because I don't see where handle_ubsan_failure()
> > returns BUG_TRAP_TYPE_WARN.
> >
> 
> Initially I wrote this with some symmetry to the KCFI checks nearby, but I
> was unsure if this would be considered handled or not.

Yeah, that seemed like the right "style" to me too. Perhaps, since it
can never warn, we could just rewrite it so it's a void function avoid
the checking, etc.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202405291631.79BB8BF%40keescook.
