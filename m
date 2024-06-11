Return-Path: <kasan-dev+bncBDZIZ2OL6IIRBZXFUKZQMGQEBICZOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id D61C49045B5
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 22:26:15 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-62a0827391asf112967987b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 13:26:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718137574; cv=pass;
        d=google.com; s=arc-20160816;
        b=dG+L6+QlaGKlS6U9368H7Epd5Md88vWhv6BNAGoQdwFFbfIOqrDu+umw/9eSNdEbb2
         09DzdVzoIhu1b5a/ON9MxCR43LIN1EelCltcQLIy74FuFB9bEU3WGVWh7mPEB5ppdoJA
         4QCt2yZGnD5S5q3gDEFfQukjjZJJTuzEzbS1rNuZ07cHiwEJ/S0k8qxAqL/XfOWSosr7
         wMZDSeatbVtAfw6z3w2aFosbQ6R1iv/T/kVgq53IlO3JtW6lV+ZYdWCSpdepX4/ul/l5
         8dtTu4AakMSsHHthXEZcltYnhs38Yn9tRCIk3l3FV0/pmBOHFSsNNxpYC02BmNtGGlQz
         9B7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=27o2tlXEPQZCiT2MkmpUV0Msnb+ObwWvC6Bb6rJFKOA=;
        fh=JOyqKINyZyk/cWInGnRkI0fQXW5taDcY7sykGGffnqk=;
        b=mQ44XJ0hstDtHLxQEuYQYPnL0GYX2HIFZcvZVWAezcrjAU2VEXt8tXuhdNp4t6FTNf
         KaMd7aqUtbDXjVxDv29TMmDvfFywztsKODJP6o9DEBuzsdWaARSeGJVKvQro+Tk+MydT
         1xsyG4sjmzA1Q6/eJWpGpPLvQqJRXteV64f4h8s+O9irEjjw6gaeBbR3/3mZOVFdFPYb
         qy2id8VMw4PedFD5PqK7Us9V0KpT+RtlaDtbyFm+xF5CGBdIkMok0mRuB4K3WHNxyHCZ
         OTEq66xQQAJwOzrdmWgsoug3xGDQab15aYoca8OMBxD/eCrQZDdMpG2KBkn7FzAOxBdy
         WKMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S+7c4XRi;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718137574; x=1718742374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=27o2tlXEPQZCiT2MkmpUV0Msnb+ObwWvC6Bb6rJFKOA=;
        b=Rfhi10CpVLpMMQluZ3hl6tC1P67DbDlg6qHLcPjA49Z1pIdZKXi4MtBzPh8QJlD0r7
         SXi0rSul2adE6rjLypno+I71Q4QWweosA4/NkDBnOwvuX4ZzAt+rG5AzVEC1mAsdJeEW
         rH4KNeU8xsJnXFKLpp4H2fbIaJC2mUaKbAPGdD6CAW+0jwh0eUM2EZIdOhk0ghB+VH3k
         zI8U5F19X1U/HWPr4n2cH0/xli8RwKebly4npUFG7QCipVZOdxaQIoz/UeZ1z+82Wiil
         RnCUEqQwFv5kIwufPo+ZmokpMn9ysEwWNejD6pN0aMd93unRqG/ZuXo6Ma0ViHOr2w2M
         Zk0g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718137574; x=1718742374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=27o2tlXEPQZCiT2MkmpUV0Msnb+ObwWvC6Bb6rJFKOA=;
        b=TWapwny+648RsiU3X/YrxDyA2YNB+YF6UBczyHd73IJO3YYpnMQ08Zn20Hxrt9vwom
         OTse0ELNmtCZhOvFhdJvDi6ufx6GoLEg0wn8FW92yjknfGaaqnXNyfTL/6iynp9W778H
         hZlCs40pZNfFD1bPUxvVFtsX3YbU2oc07TiwXvEBYD2GRFqyxcP7ePkE3i/jUtXnQgrp
         SKGBo/7KuIdsU4tqs2OAhutUujmvoBv4D/LzyXCUcnF1Jz0wLfd8H8/cDzpTTLzjniVw
         DBYIiSxWVgGYrT3yJa2iFexjZudqryOSTEwU6OE0HRUq8A0Gnu/D699zbYyn8CJo73eB
         XoIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718137574; x=1718742374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=27o2tlXEPQZCiT2MkmpUV0Msnb+ObwWvC6Bb6rJFKOA=;
        b=hiIbth7kie0U155N8mqnwOFzHuAIL0IDBCPYKJeEuOGyXo3VnpM+LcTj2M5pt62vv9
         gtMaot/032ku361zEVMM59aFmDWeBiBc6kiTzTYCmSEMdfCFygbqCXVQ8oAIdBZWvp3w
         z8f5WIzVkAr4euYHdX4cifeQTZdsTClxPzw7uQZo4pz0zDbOlyEYRK62DMJdZ5jhc55+
         EmWp11hiccRsIN6FTTxqQfaIOD9UZxYmVJFGEwiP8xSb22vIKpDZFEkp0506LLOL7s/c
         MOpOcUx5sQkftm6d/juRLLGxh3dP3wqYzo8fJgIhzf+eaamamfi1glZ8eZtsWdJbqtXT
         OrYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRy8yIlhOeYIu/Rs6NN8be2RD0ytmBZ34lAsW+4a97gcVda2aeZe53CK77W+2XGtx9RnhkzWttsG5X0tRl2JgEie74jlmvHA==
X-Gm-Message-State: AOJu0YxsHYnC98ae6PFgNtPYzWWNHJAID+DdfBZcr9pfsEz7yW1ZuneY
	5VtNgVsaPxAGRSajC94DZYPdX4jPSzukTfTJWoy4ZrXD7HMqpbaJ
X-Google-Smtp-Source: AGHT+IFz/8hshEGSqBFc9A0GWLjAT1ECJ6BUvGSPGEmYkEkI7NELdOAS2B9kxcKyVcGw/l0TnxGzaw==
X-Received: by 2002:a25:b204:0:b0:df4:dfee:3572 with SMTP id 3f1490d57ef6-dfaf663ca80mr12768755276.38.1718137574385;
        Tue, 11 Jun 2024 13:26:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6807:0:b0:dfb:14a0:3d5f with SMTP id 3f1490d57ef6-dfb14a03ee7ls1856472276.1.-pod-prod-05-us;
 Tue, 11 Jun 2024 13:26:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8OUj6Dwqi4V9rzo6u92JL2FiNzNzmQVFAIDxzagIlW3kkKCTVNTu4tZutdtBOThYL7Bvts2ZJsPB0bAKOWwFlNWzfKmIYYhbl/Q==
X-Received: by 2002:a25:6cc2:0:b0:dfa:6bfb:e19a with SMTP id 3f1490d57ef6-dfaf6649029mr12717586276.39.1718137571951;
        Tue, 11 Jun 2024 13:26:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718137571; cv=none;
        d=google.com; s=arc-20160816;
        b=Fc0yDID81cMBz6xwGYJtjf7d/6b0n30qCiRg19Fxr5HblUy8K9AbKAauJfD0bg7KfM
         h4Fk0wMxMpeWM2Qq6/luEn2K4mRO5irrrNL6+739Akfznp0ATOBljxtDPvv3YvWhHouC
         Tqbke3tR77PYqEx3IjMUz03UtHnGIWqOlljNGBJoWXukNchmBhTls2nR1OIGGVGV5T1K
         LuQir+G3uz7Ti32NyZFiKn0yLm1vM42g0D1gyTOJt7ZyuK1WwHyC/Cnm5RIwqRwCr4aK
         OEvjwKCwGjqI8xGFryGiQ4ky6FxpcJUzxnfxLBYnf3HqgQbdAUONEnT+Pzss7Q3hCX4U
         ZybA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LiuNTA4whcExw8Dugs1FyNFiaWA9GU3jWb1r5NfBRAE=;
        fh=HQt+4EXz+j96lo3tdQCz+3swZXUfLkk3CfbI5Kxkptk=;
        b=v9EM4kEFsV7BI67L3bOsKC09A8lptGI0ndWoJtqT6zmqiDWSKLxuZLTfbW4nUfxa1y
         yj9xFgd6bKJ1SRZYUfWXg4SeEPfmzGilg+7n3cC1eLsOWQzFeARc+JBcbLr7jZrpLyG5
         Me8mn5O82nmc6ax710qkjO8yKrva+49aEE5R2op7MvO+raz1AbSbhwnYDT3jkTfHi3du
         BGFxRX8MwHGlV3zo4E/Jn0A9mG/bqyUUJcbuU6ekwg1MkFLo1MMkfdkbNNNvzWBbQuuH
         jyCDbjx1nmAI0Aj9JYMXNCzqNMYI0O/M0uVEnHiSJOeq+TBoro4Tz6Ut0DYUIC6A4kQv
         mMWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S+7c4XRi;
       spf=pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-dfdb4bf899asi90878276.2.2024.06.11.13.26.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 13:26:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of gatlin.newhouse@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1f44b594deeso51305335ad.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 13:26:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXVLctFOdTy5+M0EOsf+aBNX7jpqf4+aY+VIYJpqFTvemODcVK+gRPUzbrGAGLDT7GIUeGgk9J54U5LU6/uy6SkL9ioUI7xukBJrw==
X-Received: by 2002:a17:903:1212:b0:1f6:6dc9:615c with SMTP id d9443c01a7336-1f6d02f4e65mr152389785ad.35.1718137571295;
        Tue, 11 Jun 2024 13:26:11 -0700 (PDT)
Received: from Gatlins-MacBook-Pro.local ([131.252.49.243])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f72d450697sm20488005ad.168.2024.06.11.13.26.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 13:26:10 -0700 (PDT)
Date: Tue, 11 Jun 2024 13:26:09 -0700
From: Gatlin Newhouse <gatlin.newhouse@gmail.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Rick Edgecombe <rick.p.edgecombe@intel.com>, 
	Baoquan He <bhe@redhat.com>, Changbin Du <changbin.du@huawei.com>, 
	Pengfei Xu <pengfei.xu@intel.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>, 
	Uros Bizjak <ubizjak@gmail.com>, "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
Message-ID: <7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq@ihpax3jffuz6>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
 <878qzm6m2m.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <878qzm6m2m.ffs@tglx>
X-Original-Sender: gatlin.newhouse@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S+7c4XRi;       spf=pass
 (google.com: domain of gatlin.newhouse@gmail.com designates
 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=gatlin.newhouse@gmail.com;
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

On Mon, Jun 03, 2024 at 06:13:53PM UTC, Thomas Gleixner wrote:
> On Sat, Jun 01 2024 at 03:10, Gatlin Newhouse wrote:
> 
> > Bring x86 to parity with arm64, similar to commit 25b84002afb9
> > ("arm64: Support Clang UBSAN trap codes for better reporting").
> > Enable the output of UBSAN type information on x86 architectures
> > compiled with clang when CONFIG_UBSAN_TRAP=y. Currently ARM
> > architectures output which specific sanitizer caused the trap,
> > via the encoded data in the trap instruction. Clang on x86
> > currently encodes the same data in ud1 instructions but the x86
> > handle_bug() and is_valid_bugaddr() functions currently only look
> > at ud2s.
> 
> Please structure your change log properly instead of one paragraph of
> unstructured word salad. See:
> 
>   https://www.kernel.org/doc/html/latest/process/maintainer-tip.html#changelog
>   
> > +/*
> > + * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
> > + */
> >  __always_inline int is_valid_bugaddr(unsigned long addr)
> >  {
> >  	if (addr < TASK_SIZE_MAX)
> > @@ -88,7 +92,13 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
> >  	 * We got #UD, if the text isn't readable we'd have gotten
> >  	 * a different exception.
> >  	 */
> > -	return *(unsigned short *)addr == INSN_UD2;
> > +	if (*(u16 *)addr == INSN_UD2)
> > +		return INSN_UD2;
> > +	if (*(u16 *)addr == INSN_UD1)
> > +		return INSN_UD1;
> > +	if (*(u8 *)addr == INSN_ASOP && *(u16 *)(addr + 1) == INSN_UD1)
> 
> 	s/1/LEN_ASOP/ ?
> 
> > +		return INSN_ASOP;
> > +	return 0;
> 
> I'm not really a fan of the reuse of the INSN defines here. Especially
> not about INSN_ASOP. Also 0 is just lame.
> 
> Neither does the function name make sense anymore. is_valid_bugaddr() is
> clearly telling that it's a boolean check (despite the return value
> being int for hysterical raisins). But now you turn it into a
> non-boolean integer which returns a instruction encoding. That's
> hideous. Programming should result in obvious code and that should be
> pretty obvious to people who create tools to validate code.
> 
> Also all UBSAN cares about is the actual failure type and not the
> instruction itself:
> 
> #define INSN_UD_MASK		0xFFFF
> #define INSN_ASOP_MASK		0x00FF
> 
> #define BUG_UD_NONE		0xFFFF
> #define BUG_UD2			0xFFFE
> 
> __always_inline u16 get_ud_type(unsigned long addr)
> {
> 	u16 insn;
> 
> 	if (addr < TASK_SIZE_MAX)
>         	return BUD_UD_NONE;
> 
>         insn = *(u16 *)addr;
>         if ((insn & INSN_UD_MASK) == INSN_UD2)
>         	return BUG_UD2;
> 
> 	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
>         	insn = *(u16 *)(++addr);
> 
> 	// UBSAN encodes the failure type in the two bytes after UD1
>         if ((insn & INSN_UD_MASK) == INSN_UD1)
>         	return *(u16 *)(addr + LEN_UD1);
> 
> 	return BUG_UD_NONE;
> }
> 
> No?

Thanks for the feedback.

It seems that is_valid_bugaddr() needs to be implemented on all architectures
and the function get_ud_type() replaces it here. So how should the patch handle
is_valid_bugaddr()? Should the function remain as-is in traps.c despite no
longer being used?

> 
> >  static nokprobe_inline int
> > @@ -216,6 +226,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
> >  static noinstr bool handle_bug(struct pt_regs *regs)
> >  {
> >  	bool handled = false;
> > +	int insn;
> >  
> >  	/*
> >  	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
> > @@ -223,7 +234,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
> >  	 * irqentry_enter().
> >  	 */
> >  	kmsan_unpoison_entry_regs(regs);
> > -	if (!is_valid_bugaddr(regs->ip))
> > +	insn = is_valid_bugaddr(regs->ip);
> > +	if (insn == 0)
> 
> Sigh.
> 
> But with the above sanitized (pun intended) this becomes obvious by
> itself:
> 
>         ud_type = get_ud_type(regs->ip);
>         if (ud_type == BUG_UD_NONE)
>         	return false;
> 
> See?
> 
> >  		return handled;
> >  
> >  	/*
> > @@ -236,10 +248,15 @@ static noinstr bool handle_bug(struct pt_regs *regs)
> >  	 */
> >  	if (regs->flags & X86_EFLAGS_IF)
> >  		raw_local_irq_enable();
> > -	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > -	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> > -		regs->ip += LEN_UD2;
> > -		handled = true;
> > +
> > +	if (insn == INSN_UD2) {
> > +		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> > +		handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> 
> Please indent the second condition properly:
> 
>        if (a ||
>            b) {
> 
> I know you just added another tab, but when touching code, then please
> do it right.
> 
> > +			regs->ip += LEN_UD2;
> > +			handled = true;
> 
> > +/*
> > + * Checks for the information embedded in the UD1 trap instruction
> > + * for the UB Sanitizer in order to pass along debugging output.
> > + */
> > +void handle_ubsan_failure(struct pt_regs *regs, int insn)
> > +{
> > +	u32 type = 0;
> 
> Pointless initialization.
> 
> > +	if (insn == INSN_ASOP) {
> > +		type = (*(u16 *)(regs->ip + LEN_ASOP + LEN_UD1));
> > +		if ((type & 0xFF) == 0x40)
> 
> No magic constants please. What does 0x40 mean?
> 
> > +			type = (type >> 8) & 0xFF;
> 
> That mask is pointless as u16 is zero extended when assigned to u32, but
> why not using u16 in the first place to make it clear?
> 
> > +	} else {
> > +		type = (*(u16 *)(regs->ip + LEN_UD1));
> > +		if ((type & 0xFF) == 0x40)
> > +			type = (type >> 8) & 0xFF;
> > +	}
> 
> Copy & pasta rules!
> 
> 	unsigned long addr = regs->ip + LEN_UD1;
> 	u16 type;
> 
>         type = insn == INSN_UD1 ? *(u16 *)addr : *(u16 *)(addr + LEN_ASOP);
> 
> 	if ((type & 0xFF) == UBSAN_MAGICALLY_USE_2ND_BYTE)
> 		type >>= 8;
> 	pr_crit("%s\n", report_ubsan_failure(regs, type));
> 
> I don't see the point for printing regs->ip as this is followed by a
> stack trace anyway, but I don't have a strong opinion about it either.
> 
> Though with the above get_ud_type() variant this becomes even simpler:
> 
> void handle_ubsan_failure(struct pt_regs *regs, u16 type)
> {
> 	if ((type & 0xFF) == UBSAN_MAGICALLY_USE_2ND_BYTE)
> 		type >>= 8;
> 	pr_crit("%s\n", report_ubsan_failure(regs, type));
> }
> 
> Thanks,
> 
>         tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7bthvkp3kitmmxwdywyeyexajedlxxf6rqx4zxwco6bzuyx5eq%40ihpax3jffuz6.
