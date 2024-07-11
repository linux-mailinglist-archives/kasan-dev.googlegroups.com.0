Return-Path: <kasan-dev+bncBDCPL7WX3MKBBT4TYC2AMGQEL7N6ZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E952192ECD3
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 18:35:28 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5c44c86c4a8sf786671eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 09:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720715727; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5YUh4vGcWzcTLiYT8lSEKM7szBsyi5BBPzwUgFUy6ji9ukXNUQ5enA1ELTYouhbfu
         89FPd9X2VRSRnHKVkJinS9K1Um3gNBNvcBXPL4ni2EWkj+zZRwXz0NqolusMOhfWAk0Y
         0gXa7uztnYI4Mre2BJGY+aIoH9o0Zkx/drD1QAsMK1HYVrWw7zQGucHb7uiMAsNmuVpx
         bHhB8GVNgEkwrdqCRSoSS/kDRuoFYZ0ozzqBQh1y9NiRjETuDvgEK1v8pHgZ3lvv3/pH
         JqlbDenOoLxaJ7S0fyoFW0Xw5D1+GCbnDA3LkbJHZ/T1T3YWwZcbzuI4DuLzG0SQQPC5
         iRQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nSI8ZFroWcVZEWkgoBGQmHPhlbAHI7IO3yiikZHVLEI=;
        fh=mqdKM9/UpbtAwzJvEG5FqM7L9svSsFpB0GO3HWsCxfE=;
        b=eDzRSddyKMuK5Dv7kxgNXbwiaiIhTL0wFcwM864hFnNEKHAH6PQ7W229tF0fexb+Z8
         /AxdLk+Q4umnjZASFgcRvR0X8u0uexXLbOlDOpn5TpJy8iRuv8+c1dndVu8A3lDsSgqD
         O62lcI3iEkmAIu80JhWcy6GJbhsMIh6F/nf4L/Ggk7JVzxRLy371IX3jOiSH5J1N5ohZ
         TrvwwvNd53ZK5QeZ1VaDarvSOi131u7WB67xFdDJHKICjTbvgRN04B86WjjplPLwRkNw
         SHKNtVv7ERNdAL7w5BE4Zvlh0TI1bxUwX1lUEj81ltG/x3FFA0+JahKOIW454Rxg6fFN
         N88g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kty32UDH;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720715727; x=1721320527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nSI8ZFroWcVZEWkgoBGQmHPhlbAHI7IO3yiikZHVLEI=;
        b=VTsIz9YAzx8vg0FqHej+9kprkI3LnZBthfQu0nce2QblAsg8SXUkrWVnDxe1y1JNub
         TCuiOW3h4Sy1RzU1VfsX1yl6QAcB9kfHv5EsX1GUHBK8od1N51xAszVvxQJ42lKNaBh/
         TqvgdRPQIKsXD208lR2V+BfiIdvKLWE81gDqqEqOpVhZKD1N/VRYbiokrMCtyb2V7GAX
         NelkR7b/jEX0absG93Yj3mfrevbDv2WF+4mN0jSNP62whC5bmWNX37Dtbq/LVFqM2js1
         t4v+UPEQY1833NzSTlb1lD+iUGFzmGaV2AsMIWDSRL+kKB32BkWlZ0TocSS1Hmc4//tD
         tgSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720715727; x=1721320527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nSI8ZFroWcVZEWkgoBGQmHPhlbAHI7IO3yiikZHVLEI=;
        b=PfD2bsibCmGhxLMDh/KO/C5WnH/rUXysivXuObvYc/NKiwTMFHnXmYSF1iqtDtcORU
         sg0Rt/t/Sl1CB6S6poD3GAb0cWNsJ+CHJQmqSC8gPRgAm9kIDa8D54QRyg2p1fnFcpJh
         wOYyFYihA73Bdos2x/9PWN9oGSfBiiD/XWK7GBlq8lBgIQJIyPcprSxIWJcfKNbDDeT6
         y9YCkiOv7MD7claleBPHBjAeuaM2tlJ7odAyORbTBP1ovm5f4l4149YfOZ+qBLfEqn1q
         gZO8KmqKbQ+wLtwS4sxKyl9xaGQA52+ixaHcZVfOPKMs3UPoc2384Usn9ZtOXHHJcO3D
         1znw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKGtbk+75EayeU/KIEwxWJsArldG/wtFWO3hP0iH1PHOuRW4IxcHBb9spJps6/O6ZUOgwiZUns/OqYoVmgklyoORLWaM63xw==
X-Gm-Message-State: AOJu0YzPW4nnrCIjKQOBX0SuYaYlKCQkcLG4NZzqKsIGC6IX3g8oKP+Z
	KVTw5HDW9Ew6iltHkyRYzuSCdxYqIIpGSeiMiQK0PEAXpMSzFwFU
X-Google-Smtp-Source: AGHT+IEGHdfj1AiBrmtrV7RcKsN3NJzlMhD+7S3Zmmda4stFaREtRx7587iPGRN9TsehMSqk9OOXlQ==
X-Received: by 2002:a05:6820:8c2:b0:5c7:ae9d:7894 with SMTP id 006d021491bc7-5c7ae9d79d4mr9160000eaf.5.1720715727129;
        Thu, 11 Jul 2024 09:35:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dfb5:0:b0:5c4:2c4d:b67 with SMTP id 006d021491bc7-5caad7fe2aals1010839eaf.0.-pod-prod-02-us;
 Thu, 11 Jul 2024 09:35:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrCYtNebu18PSRvTcymqiPFKWwWajwug0NeNVZR9KYljQRgX1GGu6qHERQg/9rK7xoOJcYIkUiyCLvllDhi5S4TjFV5PFCQ41nyg==
X-Received: by 2002:a05:6808:274b:b0:3da:a97d:3579 with SMTP id 5614622812f47-3daa97d4a2bmr140775b6e.16.1720715726122;
        Thu, 11 Jul 2024 09:35:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720715726; cv=none;
        d=google.com; s=arc-20160816;
        b=fb2EY2zidUF7OXxrgktq969KVyNbxEK+3ebkD/seRCMj17iwE8FSJExNLIth1SJ5Oq
         fM9cYxCUTCLazxF1bISJz5NAC8lYyHPKBM4o3YnGYTn6ayj9SUU1zdnnAgg6vKBI1txu
         3MUVFqCsdJUQcm3vMBo4V95iLlpkRh51IXjSzwr1iNzhCw4l2ZpT93lobHUjKU/SKV5s
         9ztg7Dpgfy1ZbaXtY+FabzumBg99mTq7zttBK2bJVOZjt1soK3/qRXFCU1y6NK9PqDIR
         0oLjm6QAaoRrfDrVfTM49bJW7+Jo68BQhgu/ETWi+gJkGSWDUlLWaUZnNaGfgvT5GHpr
         dBbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iG53baZ18GMDi9YXMC4xJR3Pixolumk6VvI6cKokJWk=;
        fh=0usZ/D/H0yciGAU7rPbWQGtELZuCfxOB+nWItzrQQow=;
        b=lZvuLU98Y8YeDiweVS1lcbQKxLgiSOzYaNEe7lVeFXvpqR2qYbMK0IVT+0mb79c2Hn
         CNF9Zy5KAXABXpz/v5uZXP7m96VLx+616uKNONHvZ9d6NuSkPKEM5Z5kQrmzgnVoejLv
         0PUG60A0fs+nOY3xv4dsEWc92P7WKcliTPtRzJy+kcbf5NBkAuDD8bH3dv81VFQoYXGc
         18tM21+MbJnTOVNA2xvM499WP4M6CkJLvyVwyEHgqUYU4CB+xPFhddvdb5n//CHtthJR
         U+y29voU9l2fMNKeMU8QwaPweP6L5zXQD6A37CV7LFoGtRWJHTA4kcBQMEeUY+J8x59d
         I8/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kty32UDH;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-447f9bc3cd6si2715471cf.4.2024.07.11.09.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jul 2024 09:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A252961CC4;
	Thu, 11 Jul 2024 16:35:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 49893C116B1;
	Thu, 11 Jul 2024 16:35:25 +0000 (UTC)
Date: Thu, 11 Jul 2024 09:35:24 -0700
From: Kees Cook <kees@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <202407110924.81A08DD4D@keescook>
References: <20240710203250.238782-1-gatlin.newhouse@gmail.com>
 <20240711081031.GB4587@noisy.programming.kicks-ass.net>
 <CANpmjNObEzShHvw19EAntPvCYJbqezKBq+pB=mkd7j3sXDEE7A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNObEzShHvw19EAntPvCYJbqezKBq+pB=mkd7j3sXDEE7A@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kty32UDH;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Thu, Jul 11, 2024 at 11:06:12AM +0200, Marco Elver wrote:
> On Thu, 11 Jul 2024 at 10:10, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, Jul 10, 2024 at 08:32:38PM +0000, Gatlin Newhouse wrote:
> > > Currently ARM architectures extract which specific sanitizer
> > > has caused a trap via encoded data in the trap instruction.
> > > Clang on x86 currently encodes the same data in ud1 instructions
> > > but the x86 handle_bug() and is_valid_bugaddr() functions
> > > currently only look at ud2s.
> > >
> > > Bring x86 to parity with arm64, similar to commit 25b84002afb9
> > > ("arm64: Support Clang UBSAN trap codes for better reporting").
> > > Enable the reporting of UBSAN sanitizer detail on x86 architectures
> > > compiled with clang when CONFIG_UBSAN_TRAP=y.
> >
> > Can we please get some actual words on what code clang will generate for
> > this? This doesn't even refer to the clang commit.
> >
> > How am I supposed to know if the below patch matches what clang will
> > generate etc..
> 
> I got curious what the history of this is - I think it was introduced
> in https://github.com/llvm/llvm-project/commit/c5978f42ec8e9, which
> was reviewed here: https://reviews.llvm.org/D89959

Sorry, I should have suggested this commit be mentioned in the commit
log. The details are in llvm/lib/Target/X86/X86MCInstLower.cpp:
https://github.com/llvm/llvm-project/commit/c5978f42ec8e9#diff-bb68d7cd885f41cfc35843998b0f9f534adb60b415f647109e597ce448e92d9f

  case X86::UBSAN_UD1:
    EmitAndCountInstruction(MCInstBuilder(X86::UD1Lm)
                                .addReg(X86::EAX)
                                .addReg(X86::EAX)
                                .addImm(1)
                                .addReg(X86::NoRegister)
                                .addImm(MI->getOperand(0).getImm())
                                .addReg(X86::NoRegister));

Which is using the UD1Lm template from
https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/X86/X86InstrSystem.td#L27

  def UD1Lm   : I<0xB9, MRMSrcMem, (outs), (ins GR32:$src1, i32mem:$src2),
                  "ud1{l}\t{$src2, $src1|$src1, $src2}", []>, TB, OpSize32;

It uses OpSize32, distinct from UD1Wm (16) and UD1Qm (64).

> But besides that, there's very little documentation. Either Gatlin or
> one of the other LLVM folks might have more background, but we might
> be out of luck if that 1 commit is all there is.
> 
> [+Cc Tim, author of the LLVM commit]
> 
> > > diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> > > index a3ec87d198ac..ccd573d58edb 100644
> > > --- a/arch/x86/include/asm/bug.h
> > > +++ b/arch/x86/include/asm/bug.h
> > > @@ -13,6 +13,17 @@
> > >  #define INSN_UD2     0x0b0f
> > >  #define LEN_UD2              2
> > >
> > > +/*
> > > + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> > > + */
> > > +#define INSN_ASOP    0x67
> >
> > I asked, but did not receive answer, *WHY* does clang add this silly
> > prefix? AFAICT this is entirely spurious and things would be simpler if
> > we don't have to deal with it.

Even if we change LLVM, I'd still like to support the older versions, so
we'll need to handle this regardless.

> >
> > > +#define OPCODE_PREFIX        0x0f
> >
> > This is *NOT* a prefix, it is an escape, please see the SDM Vol 2
> > Chapter 'Instruction Format'. That ASOP thing above is a prefix.
> >
> > > +#define OPCODE_UD1   0xb9
> > > +#define OPCODE_UD2   0x0b
> >
> > These are second byte opcodes. The actual (single byte opcodes) of those
> > value exist and are something entirely different (0xB0+r is MOV, and
> > 0x0B is OR).

What would be your preferred names for all of these defines?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202407110924.81A08DD4D%40keescook.
