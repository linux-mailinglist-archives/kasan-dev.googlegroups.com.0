Return-Path: <kasan-dev+bncBDCPL7WX3MKBB7OXU6ZQMGQEWIWVYBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E0311905B40
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 20:42:06 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f6fcfaed57sf199655ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 11:42:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718217725; cv=pass;
        d=google.com; s=arc-20160816;
        b=TyIFrrKCFUYH09A/2ZlMUAqckPUBrEEuwjzNZxcGk5W6Eh7rLk5zog7Fw9OGuNb8JT
         0iBwf7DRDREHVmCQBQmpGV8QJqakADT6yTIssaqe1QHs3Itr1W4konDfON4RMeEb93W/
         SQL9bFK52Bi60ZhtmEy/sjU905/Ov42uTtaQMLhtrh+gjUB1s3WP5/B+K2swgjKoITaH
         kRwfr4BH0JGyuQx+1EnIipOajC/yI44NTqMNUOm2AqU7TLOEkkstbOICfOdShZcUECLd
         H2zqBdrHZcK3UhG1+wH/mIkwBZc6O371qPLHTnqTpf4KZYUNr886BNUTObz5z02FLIKN
         nq6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Q0RS3ZvuYRICTwU4Rzb8Rrouzh/Cy68qCc7BGhK5zVo=;
        fh=BTLkUyPK0XUM+qXuRUoEOsg7H5cbUlqPzhErpi7JJUc=;
        b=tgAqpTQjGQOXeJNRWTZuFaN2W3dItxfeNW0D4u0LEO5mDcBikUnCoB0tAD58NONtbp
         jJPSgbJotifRya1Iu2gqKvdXwpA6vqYCPDfu5yzh/e+ISQ7ssRunllCZ5RcCS40o4xF3
         7F+XnCAAoTzFu7cq3ythxHs91OHj2ge/rf3K4KsrGWAP/5654k59C6C+8Oqb94gRZKZ4
         J06U/FxYK6xEY992bdqfbnQR4KT6qWe4pp74WU4yb4C0AwDoktZdiNt63VjLK3azW4SX
         w51D0Na4FyYMKnUDQMyp9D5DPwTvLRNYIf4zrBJmF7G3IVD+gr8zbLwO8dCNRysawEEl
         akfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FU4Pmgqd;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718217725; x=1718822525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q0RS3ZvuYRICTwU4Rzb8Rrouzh/Cy68qCc7BGhK5zVo=;
        b=aOIHGL+Jpgys30hFgsaByrOBWf9AZjg0j5Pm70Tj4Ixq7UIcaToS7DZejOPcQtWKIB
         kfPaS9XqjagihaTsvsOMe82cA8pG3TGZTlPDTFK0nfP/pFQxov7gcUXbAPUJXtPs48Wz
         575gv32KeBhXYgf6Z84dzEgtSNHLSS72+LdczYI0dIqOUibDCbnHtYKNZ4eTHdqbGE8J
         9Xw8UVeIXyZHxddCyB9uRYG3pmBxBtVSgGYpTTA/KLXxFp7Lkch9ty8yvsw7mpUv/ds1
         aiZfHmNYveB2wpf52GjmJZyuFO8vo8Wjh9/JRJ7B883AaTqYVh1MXg30ZFSEUPRqu37X
         LTtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718217725; x=1718822525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q0RS3ZvuYRICTwU4Rzb8Rrouzh/Cy68qCc7BGhK5zVo=;
        b=aDblddVl+Ljd+4i59X8ok6LQAXsjmNe/KP/ULCW+pHWTY7wr7PLwMIEQ0mWY5T+muh
         nq+JHpbhw300/LYPP9xIjfoWrJbXLTxwuvLWzJcph2Mnuf7q5DbWjxf61CrJYKcDpjRQ
         3dFZo971RAByKXSFcxqWMYUZWKtrYbZ5C8wEfCyWnSGuyLIRXWg3aYIwVVuuUbRDWXE/
         WNls8+Of6lRoRvJvAJzNhdOeBIp4BGFnelr2x1mEJjsKaxeeerg2SIvl8NXfLgnHRs0c
         SfoPlhSupNU3/D3WIY0T5eozZGe1OiTRMoRvXbiXK7GmENtdMehLf4by628FB2abVD6S
         UgNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3TPfnGZrgnHjBqRYMu+M0vRAv1VrOdznR7Oq/WyRNgJGC6+SYDMcgVJFfkisXSKzH70MFXIdraXYHg/1WefcVDBe3CaH+LQ==
X-Gm-Message-State: AOJu0YzMma0oO4Z1HXTrtmJ9cJ2Z6roXbJxZHCR1wubI0H2eLy+JBHuj
	sjwNepi5j2+McVI/LgyeyRDDc6NunjQB3OCSXlmAFUti6aXHyrK2
X-Google-Smtp-Source: AGHT+IHqiZ48/B52X1SU/EnIP5yQXp++lGTYiNwA69IOOAKbRY2NdsyCm0tsFLYB2JGVphwL6fHccw==
X-Received: by 2002:a17:903:3344:b0:1f6:3891:7950 with SMTP id d9443c01a7336-1f84fe2a30dmr283625ad.1.1718217725257;
        Wed, 12 Jun 2024 11:42:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ad87:0:b0:5a4:5fe2:2211 with SMTP id 006d021491bc7-5bcc3ce23ffls105548eaf.1.-pod-prod-07-us;
 Wed, 12 Jun 2024 11:42:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2Cbhzwchq3sEkVAiy7KfCUjJ4A4nkpYJHu0JjeovAsFj53kyEHGybmB8o+VlYAai4nfgExsiOLSrhDGeGzvCIVBs/xr/DMcwyDg==
X-Received: by 2002:a05:6830:1d58:b0:6f9:6518:27d9 with SMTP id 46e09a7af769-6fa1be31d3fmr2941227a34.3.1718217724054;
        Wed, 12 Jun 2024 11:42:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718217724; cv=none;
        d=google.com; s=arc-20160816;
        b=NntI8l2wYTaOOLRZpEl0hy5sUPCJVp1oaNOkM5atnr4/C3HXxL8xt0UrmQ3GaLOFke
         wnatNXHr868qkKCt440GFOfem3fJ3iY/hOT0LXnmP3EUBcADBAzhvBTYjC9/wTASS5RH
         vtxwXpYVV8AmpHIE3d03NbDtLKlvyJ9Wk5SgYyMOgX5iyycnEyP+8kbqkgTsbbBGi7CC
         k8J5hfy8J+UHaQVPYn93KZsnR3hZHE9jPHaTc9nL4i9Ciaw0gLVnYpqkhOaaUK8Ha5/E
         UbGIUJIWijQyJXou9lIsAz9Cn6l2lr5UY3CRwYxh0zGOmcvEWq170lLD3glZOI4S0VNf
         SMVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=A7bWTlReaeJ0vy3KwKWv/9m10n1zGklnYGYgXpk2SE4=;
        fh=kSEd0C/TZD87ZP5jXeo62GhHy1VmrIzGlKPBHEpnbUU=;
        b=T29K8or1FKY7x1Xd93URT7CSpuFdKFHhYocn+L9DwxGNwoGQa0Q/mxkaTkHNowS5cb
         WBSWrr/7YCTxPdRDO3omz9UsA4s8OIpEmYYUcK1ZdLDL/zuXso6c0x/IfYnC7Alzz7Pk
         MLSUIUyUFlrw6Mru72D0Sxu/aRBZjDHVsuAhZsMF+Ys5Pgm5d/h/bqhH+Gq64eG6uHNR
         /bfHf9rVYOFM8A5xAXbAYODFeAbp0iVisSso4XmjWuucXjVmPy0xJWainYv6dfZcQF3P
         KPwxaPTTWS6X+6/rsIf5r/C28R4tsaXzQ5y+jzrSQgo2tI3ank+ubX7S35GFPrtPmqEn
         rFYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FU4Pmgqd;
       spf=pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fa0f7b18b7si121635a34.1.2024.06.12.11.42.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Jun 2024 11:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 585DDCE21FD;
	Wed, 12 Jun 2024 18:42:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8C059C32786;
	Wed, 12 Jun 2024 18:42:00 +0000 (UTC)
Date: Wed, 12 Jun 2024 11:42:00 -0700
From: Kees Cook <kees@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Gatlin Newhouse <gatlin.newhouse@gmail.com>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Rick Edgecombe <rick.p.edgecombe@intel.com>,
	Baoquan He <bhe@redhat.com>, Changbin Du <changbin.du@huawei.com>,
	Pengfei Xu <pengfei.xu@intel.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>,
	Jason Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>,
	Uros Bizjak <ubizjak@gmail.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
Message-ID: <202406121139.5E793B4F3E@keescook>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
 <878qzm6m2m.ffs@tglx>
 <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FU4Pmgqd;       spf=pass
 (google.com: domain of kees@kernel.org designates 145.40.73.55 as permitted
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

On Tue, Jun 11, 2024 at 01:26:09PM -0700, Gatlin Newhouse wrote:
> On Mon, Jun 03, 2024 at 06:13:53PM UTC, Thomas Gleixner wrote:
> > On Sat, Jun 01 2024 at 03:10, Gatlin Newhouse wrote:
> > 
> > > Bring x86 to parity with arm64, similar to commit 25b84002afb9
> > > ("arm64: Support Clang UBSAN trap codes for better reporting").
> > > Enable the output of UBSAN type information on x86 architectures
> > > compiled with clang when CONFIG_UBSAN_TRAP=y. Currently ARM
> > > architectures output which specific sanitizer caused the trap,
> > > via the encoded data in the trap instruction. Clang on x86
> > > currently encodes the same data in ud1 instructions but the x86
> > > handle_bug() and is_valid_bugaddr() functions currently only look
> > > at ud2s.
> > 
> > Please structure your change log properly instead of one paragraph of
> > unstructured word salad. See:
> > 
> >   https://www.kernel.org/doc/html/latest/process/maintainer-tip.html#changelog
> >   
> > > +/*
> > > + * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
> > > + */
> > >  __always_inline int is_valid_bugaddr(unsigned long addr)
> > >  {
> > >  	if (addr < TASK_SIZE_MAX)
> > > @@ -88,7 +92,13 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
> > >  	 * We got #UD, if the text isn't readable we'd have gotten
> > >  	 * a different exception.
> > >  	 */
> > > -	return *(unsigned short *)addr == INSN_UD2;
> > > +	if (*(u16 *)addr == INSN_UD2)
> > > +		return INSN_UD2;
> > > +	if (*(u16 *)addr == INSN_UD1)
> > > +		return INSN_UD1;
> > > +	if (*(u8 *)addr == INSN_ASOP && *(u16 *)(addr + 1) == INSN_UD1)
> > 
> > 	s/1/LEN_ASOP/ ?
> > 
> > > +		return INSN_ASOP;
> > > +	return 0;
> > 
> > I'm not really a fan of the reuse of the INSN defines here. Especially
> > not about INSN_ASOP. Also 0 is just lame.
> > 
> > Neither does the function name make sense anymore. is_valid_bugaddr() is
> > clearly telling that it's a boolean check (despite the return value
> > being int for hysterical raisins). But now you turn it into a
> > non-boolean integer which returns a instruction encoding. That's
> > hideous. Programming should result in obvious code and that should be
> > pretty obvious to people who create tools to validate code.
> > 
> > Also all UBSAN cares about is the actual failure type and not the
> > instruction itself:
> > 
> > #define INSN_UD_MASK		0xFFFF
> > #define INSN_ASOP_MASK		0x00FF
> > 
> > #define BUG_UD_NONE		0xFFFF
> > #define BUG_UD2			0xFFFE
> > 
> > __always_inline u16 get_ud_type(unsigned long addr)
> > {
> > 	u16 insn;
> > 
> > 	if (addr < TASK_SIZE_MAX)
> >         	return BUD_UD_NONE;
> > 
> >         insn = *(u16 *)addr;
> >         if ((insn & INSN_UD_MASK) == INSN_UD2)
> >         	return BUG_UD2;
> > 
> > 	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
> >         	insn = *(u16 *)(++addr);
> > 
> > 	// UBSAN encodes the failure type in the two bytes after UD1
> >         if ((insn & INSN_UD_MASK) == INSN_UD1)
> >         	return *(u16 *)(addr + LEN_UD1);
> > 
> > 	return BUG_UD_NONE;
> > }
> > 
> > No?
> 
> Thanks for the feedback.
> 
> It seems that is_valid_bugaddr() needs to be implemented on all architectures
> and the function get_ud_type() replaces it here. So how should the patch handle
> is_valid_bugaddr()? Should the function remain as-is in traps.c despite no
> longer being used?

Yeah, this is why I'd suggested to Gatlin in early designs to reuse
is_valid_bugaddr()'s int value. It's a required function, so it seemed
sensible to just repurpose it from yes/no to no/type1/type2/type3/etc.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202406121139.5E793B4F3E%40keescook.
