Return-Path: <kasan-dev+bncBDBK55H2UQKRBSOSYC2AMGQEEIF2TDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 44D2C92EF26
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 20:49:47 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ee848b2fedsf10363431fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 11:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720723786; cv=pass;
        d=google.com; s=arc-20160816;
        b=SQw0bhRJyMl6cPWp3FpqkyRaSRKH+Q1FtzGkeQZAX9HmFqf3xASEYeT4FK+dhJtbdK
         eVFYXy59baeZcGsvPQBXwrrlYDgRQAdcyzd6HsAiwCit/K1xI0DmpKcYKbUpRTORipQ7
         2zG213Lzd3C3/rXt0tLSHyyUugZsQ6NTOZUWwICdJvWgpQbOO8Mo/81IT8cy0NcXeIOI
         2xmhwq5K+ke9QnEHi9w9hLJfdrloGgf3fRPhq55D7RO7H48NdeygvuXosejcXfeWnSZC
         v8AiQB9mKEdVgT7BoB0gGoUP1uRHz/w4qs5e4PNRS46MMlm/CRWScEXHPiMWVFZiRq57
         R/JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WWA6LSZeElU9Bx1z4UwmuYUU3RRzcD4rTXeebTBDE7U=;
        fh=ARC/eb6TCcGoLCe+WSp69eaS0hrtEhcKOFu4mzk+eyE=;
        b=Kj5UCBOaFmnWXR1yLc0RBJaG2RsxLkNenOCZZjApeDu2zV2Yw6gxkl+2JTrsLx1HLg
         otZvGlQaJpbtnPAn1eKOQO1l7EwbJz55tqMvCIXPvfo/d6wJhIw6QrOIEHGzRoYLQrWJ
         QwJGdtvCqEckljJHLXDsIl6AHF7Vn5aN3UImooBKMyExq3JEe9aoZ104i/eXiZvI0g7a
         Jb6IQFiq5kKXClbDUcwlg/hzdEOdNqKSGfAY1ctWTE4pdsQb2BMrXlHErvTfkGARWEp8
         dhwcvJtEfInnWn+MVd4TcyjWOk+sV5qbv3gFPTxEGtlKtMVWCiLj38Pm20GqbLpM4MPy
         EoVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=By5aYvAq;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720723786; x=1721328586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WWA6LSZeElU9Bx1z4UwmuYUU3RRzcD4rTXeebTBDE7U=;
        b=kGEJbx3kZOMehNRZsUdM100xn4jec99QeEoar3nV7Yy+Bag/pkt3F5MbcYzzZmm5Bn
         is6iHAGWC3QdAxWi6OBbl+pnyJ9yqDNepk1CZQAhWVMZKWfarU0LJmbbe8cpy60tV5o6
         qhwOKkBJ+UVjzeijCYyS/8ANy3Qw5CfztBLyZbVIfg3HPWwLP0h/UfVQK/Xnqt7Kjzbr
         LUmmuhrMYPFctiJar8AyG9GdNltMlMe84hcdSBoacB/8/3+s9xky/wyK3WlJXRAa6+LC
         7+T9G8HUrwPBBDZg0IiwbzfOghTTBFFyF2mZPyI0UXuQtFkNREAn8pNy0R9Is/xIksj4
         eqnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720723786; x=1721328586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WWA6LSZeElU9Bx1z4UwmuYUU3RRzcD4rTXeebTBDE7U=;
        b=usKxyxr4oDmag01d8jgSYYttq/9gwR5AP3WNcPtdw3e2WJbdfaZO6msdroG2QnMhOU
         ZkZnoRO+2Ef/Iv0iUTFyIeZ9bgvzJr0XhNaQYRlQGgHLNO7neQjCwsrwYazPlNkFoJkK
         cA4u+mGuN1nIRjcHRsFSYxoTpOZwuyck2vH04EJrqg2yen19lj+dHXAUao6Wr2djH8V9
         JUjl8WFhXfYP+mqTvleeAioNn/82wXsKUw5D9mMtEc0SZQW9ltAyPQ74S5gGhkVLQBcD
         /bheE/bWYjbPP8ArmkNNU7TRJ2vzsXsuFdLakGy4CE8R41FJ5thm23TSCL+xeO6nc07n
         mLvw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8xbS/y3bVRgfrRj8sYZw+hJk9IPxSkoPqgFKIhDLtHNqkEg/2x0Sddi6pRWuvILCmtrNj0ZQKd6qQ1bXGmtBlZQxbRfNNcA==
X-Gm-Message-State: AOJu0YzvI6npknlpGGt2/trbtYx6sOeDr3/5QunamcpRrd8eOuvBtSxz
	WLcX7hI0ATVQPJj+wB5zQhiiTz32zo4WuWtqtyEobhwp/Y6e0kep
X-Google-Smtp-Source: AGHT+IFvnwiJQA+zDqPP1AoSyzoaqvroVUu2qCa3HnPcXFj5l8hwOOUVXRmGeCXtw03SBqZh2hKoFA==
X-Received: by 2002:a2e:3c06:0:b0:2ee:5b97:ebce with SMTP id 38308e7fff4ca-2eeb31022dfmr55508001fa.24.1720723785920;
        Thu, 11 Jul 2024 11:49:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9d49:0:b0:2ec:5d3e:a6d3 with SMTP id 38308e7fff4ca-2eec93b3299ls6928911fa.2.-pod-prod-07-eu;
 Thu, 11 Jul 2024 11:49:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6Q+X0gp4oHBsocbc3Mw10T3CME1w1NljyCAebzqWIL6u9qP6Y70EKuGg/efik53/5ZZOxqNgAQOYEn+a2yOYYB7uGVQmASEFIcQ==
X-Received: by 2002:a2e:8712:0:b0:2ec:5a25:16e9 with SMTP id 38308e7fff4ca-2eeb318a2e7mr56741651fa.34.1720723783442;
        Thu, 11 Jul 2024 11:49:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720723783; cv=none;
        d=google.com; s=arc-20160816;
        b=IA3TZHB45IjgTLMmXDokRgb/MtEuHd2TeSiks8eTycvbImjZ6SqwSRAQ4ilEtppI0U
         fBcR4VbJhrRaIozekBJ7dgE55tcRUJiQy9TZkQQxIbZ4XU4Vo+pS5iHHB9PTgJIjPgaI
         vsMQVXcsSNCcbc9xzQ6NDqk+GkrCeelYWa6sUJOdbMN6bbYXIOPqLuGBl88ekqwdsW0C
         2HM6BcGACM40inb2fNOPcGDOg2cYNUO1P9lN++IFjm6wkydOrm+5ZR1vGQfSX1bES8/K
         5DuUswoAM3awdUCmzOnMqXIk+tHgLmzLCKdr+XZHwOTcmKforW1qLa+nzW0GlZ9l4DyW
         jusw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=o/IW2cCwLwJEDMO66z3r5dlrUmlAEsjcwslEcQLO45s=;
        fh=dh1bgqotY4wALKP6HaRE4d7euBkKlolFqMNu5lqllw4=;
        b=WA9NDnhlz7RbDa4XFVWF3QsRrMBejnE5wlt+MbjZ8viwIeq2z8D0ZLO15/+6UCEnNC
         8iujoUw1wkbD9/q6MiRLuTtdGN/pAuwjtC26v6RpC/VZ8HYUNeDCUbVjWMd3nQvZk9fO
         IMr5Kb5II2rA9rn/a8+nAnT3Sp+OPsFlivXNGv3Eod/gm4HvPHhRg2XU5aMKeE9E75Pz
         yJ1fxBOHtxEpLGOvOJApXzIx9+t36+sOutE2nHAt5drB2TyuYphTuSzqe+n/x/AitqXm
         vcj3LsbJOlDiPyGwKCAZthIZuMZrm9brZE5eZsbJcEoYIRZofjcOrqR2YWbgYlA3dbTo
         Ei7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=By5aYvAq;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-426725584d2si1861595e9.0.2024.07.11.11.49.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jul 2024 11:49:43 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1sRyrJ-000000018ze-3Fdq;
	Thu, 11 Jul 2024 18:49:37 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4636630050D; Thu, 11 Jul 2024 20:49:37 +0200 (CEST)
Date: Thu, 11 Jul 2024 20:49:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kees Cook <kees@kernel.org>
Cc: Marco Elver <elver@google.com>,
	Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
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
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Changbin Du <changbin.du@huawei.com>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Arnd Bergmann <arnd@arndb.de>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev,
	t.p.northover@gmail.com, Fangrui Song <maskray@google.com>
Subject: Re: [PATCH v4] x86/traps: Enable UBSAN traps on x86
Message-ID: <20240711184937.GE27299@noisy.programming.kicks-ass.net>
References: <20240710203250.238782-1-gatlin.newhouse@gmail.com>
 <20240711081031.GB4587@noisy.programming.kicks-ass.net>
 <CANpmjNObEzShHvw19EAntPvCYJbqezKBq+pB=mkd7j3sXDEE7A@mail.gmail.com>
 <202407110924.81A08DD4D@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202407110924.81A08DD4D@keescook>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=By5aYvAq;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jul 11, 2024 at 09:35:24AM -0700, Kees Cook wrote:
> On Thu, Jul 11, 2024 at 11:06:12AM +0200, Marco Elver wrote:
> > On Thu, 11 Jul 2024 at 10:10, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Wed, Jul 10, 2024 at 08:32:38PM +0000, Gatlin Newhouse wrote:
> > > > Currently ARM architectures extract which specific sanitizer
> > > > has caused a trap via encoded data in the trap instruction.
> > > > Clang on x86 currently encodes the same data in ud1 instructions
> > > > but the x86 handle_bug() and is_valid_bugaddr() functions
> > > > currently only look at ud2s.
> > > >
> > > > Bring x86 to parity with arm64, similar to commit 25b84002afb9
> > > > ("arm64: Support Clang UBSAN trap codes for better reporting").
> > > > Enable the reporting of UBSAN sanitizer detail on x86 architectures
> > > > compiled with clang when CONFIG_UBSAN_TRAP=y.
> > >
> > > Can we please get some actual words on what code clang will generate for
> > > this? This doesn't even refer to the clang commit.
> > >
> > > How am I supposed to know if the below patch matches what clang will
> > > generate etc..
> > 
> > I got curious what the history of this is - I think it was introduced
> > in https://github.com/llvm/llvm-project/commit/c5978f42ec8e9, which
> > was reviewed here: https://reviews.llvm.org/D89959
> 
> Sorry, I should have suggested this commit be mentioned in the commit
> log. The details are in llvm/lib/Target/X86/X86MCInstLower.cpp:
> https://github.com/llvm/llvm-project/commit/c5978f42ec8e9#diff-bb68d7cd885f41cfc35843998b0f9f534adb60b415f647109e597ce448e92d9f
> 
>   case X86::UBSAN_UD1:
>     EmitAndCountInstruction(MCInstBuilder(X86::UD1Lm)
>                                 .addReg(X86::EAX)
>                                 .addReg(X86::EAX)
>                                 .addImm(1)
>                                 .addReg(X86::NoRegister)
>                                 .addImm(MI->getOperand(0).getImm())
>                                 .addReg(X86::NoRegister));
> 
> Which is using the UD1Lm template from
> https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86InstrSystem.td#L27
> 
>   def UD1Lm   : I<0xB9, MRMSrcMem, (outs), (ins GR32:$src1, i32mem:$src2),
>                   "ud1{l}\t{$src2, $src1|$src1, $src2}", []>, TB, OpSize32;
> 
> It uses OpSize32, distinct from UD1Wm (16) and UD1Qm (64).
> 
> > But besides that, there's very little documentation. Either Gatlin or
> > one of the other LLVM folks might have more background, but we might
> > be out of luck if that 1 commit is all there is.
> > 
> > [+Cc Tim, author of the LLVM commit]
> > 
> > > > diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> > > > index a3ec87d198ac..ccd573d58edb 100644
> > > > --- a/arch/x86/include/asm/bug.h
> > > > +++ b/arch/x86/include/asm/bug.h
> > > > @@ -13,6 +13,17 @@
> > > >  #define INSN_UD2     0x0b0f
> > > >  #define LEN_UD2              2
> > > >
> > > > +/*
> > > > + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> > > > + */
> > > > +#define INSN_ASOP    0x67
> > >
> > > I asked, but did not receive answer, *WHY* does clang add this silly
> > > prefix? AFAICT this is entirely spurious and things would be simpler if
> > > we don't have to deal with it.
> 
> Even if we change LLVM, I'd still like to support the older versions, so
> we'll need to handle this regardless.

Is it (LLVM) allowed to do prefix stuffing for 'random' instructions in
order to achieve alignment goals? That is, are we ever expecting more
prefixes here?

Anyway, as proposed the 'decoder' also accepts ASOP UD2, should we be
complete and also return an instruction length? Just in case we want to
be non fatal (WARN like) and skip over the instruction.

> > >
> > > > +#define OPCODE_PREFIX        0x0f
> > >
> > > This is *NOT* a prefix, it is an escape, please see the SDM Vol 2
> > > Chapter 'Instruction Format'. That ASOP thing above is a prefix.
> > >
> > > > +#define OPCODE_UD1   0xb9
> > > > +#define OPCODE_UD2   0x0b
> > >
> > > These are second byte opcodes. The actual (single byte opcodes) of those
> > > value exist and are something entirely different (0xB0+r is MOV, and
> > > 0x0B is OR).
> 
> What would be your preferred names for all of these defines?

SDM calls 0x0f the escape opcode and these others secondary opcode
bytes, so something along those lines would be clear I suppose.	

Vol2 2.1.2 (todays edition)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240711184937.GE27299%40noisy.programming.kicks-ass.net.
