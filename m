Return-Path: <kasan-dev+bncBDAMN6NI5EERBQ6X66ZAMGQEFZRAG4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D75388D86F6
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2024 18:13:59 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42138d5d766sf59525e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2024 09:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717431237; cv=pass;
        d=google.com; s=arc-20160816;
        b=jY/gaZtRly3qhF2x+KB4vkD0jrWns1jfSw136DxX9QMzoI8EYxCeA9yXzaBobDEC4H
         g3kcD0ZwDV2ICm4NNWO9CvNHNXe4qrHMz1Bjb+E5btNqonkJTBDo3ftFYFdbyOQNn3Kl
         pxvZS8ED6wulLLalmljThlaQ/nurCgh8zje+QrsBE6goGcjE0j07UIC7e/2Cdvv3WGaa
         0zbnu7JasIODcFKb5Bqln6CQet2yd2rX7eWBxDyp2E7TrbhLwCpDBZ28N+kyRPtwm/jP
         KRYnMLUPeecsP/ablzML3cZLKNJcxM/5lITZx4+jYNtsp8j5zRC3+eXrpL2KWL2tDtZO
         IhVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=lSFXfbaM0wK8MSbXhE1+8YyYpMz5QzblxLeR2XQOyIQ=;
        fh=oHiYp/au/YXZ08p04gwerBTKJI+S5K6l4CuANwo4xgc=;
        b=xhKFtD1H1QuyDhCL6uwXI0ITMlWdAKg15r6AzYebH59AOamRhCYalj8urgCItN2Grv
         xhxIvKCcaI+i67G26WQ0Rfmf06bCIxafjcZnRzuV0JuETjOO/1ae9D8c/Y64PywCEBX3
         ENhFRaGmQwell0nXFt2BbUQdMRxHIcAB6dhv0jX2f32w7TTlXFcYNNN0zgX6OxCtMmQT
         wvOtXZ35CepsdDO17OpCaMS6yJR0p9Jl0pCa0ZZCCcd5F4PhQGPJPShzYIrAWKlskfme
         32KJWeTNvlHb2tAQ8VStVtA6QuXdKFMj4jXJqmGqf2LZMWwejQmFshxvs8fhGnGovcab
         h0lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=jtIS63tC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717431237; x=1718036037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lSFXfbaM0wK8MSbXhE1+8YyYpMz5QzblxLeR2XQOyIQ=;
        b=DULzgGZThH6b34BseZgiAASr759sEGwzxS1vIS8C8jg14u4UGCdBxDS7vwCCxpV3rc
         OyQonaRXxWqgyM2K6BxihlJ11xuv1rINQq6sXt+VywuQJItT+r2MvXBSnOjwBC5NC26Q
         RZXJ/7bv9IuzmZiI4hq9w8rJsDXcUh5kLc3YyWUI2N2hP7nRoBZKN1INcvfKgzxxdSWP
         qOONaLTSU0TkMhT0RHZd0VO2U6FCwSNLenCJoK47rAPKLsC+D9Z05FadI5GDial/pUdO
         VF/bXrEQE9e9wkfkQcZVqWb9Rw9w3/rWJwkA0x577P7LkCN3KJ/Jn/kcCUjOZvsKxQ9P
         eNuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717431237; x=1718036037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lSFXfbaM0wK8MSbXhE1+8YyYpMz5QzblxLeR2XQOyIQ=;
        b=I0ZCZv6PwEaKqPTWlvtk/9kNLmbRu+hC3DSHJteTmE0P5Yz/P/UqXFPVwWCp7LNdNA
         AdsERGRWtxCOSVoNKLv22jNF5WuM7KlLFLrOpjWKyg1WX5fvbd8nJtyWigu1NPMBc3cx
         sswyW7vazfyAo5RvCjqzYuf/Y/mRxutxl52uqt8m7ee5eM7Jh103NouztrxLda4Cewa4
         85dRhxSYlmspgvXPDT2GAIGDs5ti17nEmCwbnqOuyRNHRI8xhphKRKaNI4P08mS98bkQ
         7AK+1arOGCW1QJrW5nay/HoLrBv9y055hfVHobbF60G2BOOQE8e4vZUeqpoES/XniRo+
         1+tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdHg+SN5tLS2EmD9JZ/ceqHFmN595AWAMjo2UUdB07lTqVmWfwS07FfOZErxgoYUMz+jgi5WUF1dCcPAudmLzA0KohXXioGw==
X-Gm-Message-State: AOJu0Ywk3N55ITs5k1c9vR6/Xo3R+V9vmxtvXHP1x7cE7twLT7xHhTbb
	3gT/V/5NYUw6umcEdRLG9UXds7Bc7xMk5ZGekiCHloPU4aONVTNK
X-Google-Smtp-Source: AGHT+IEQUMNdCa7r6+jNzL85EWflh1TjTvdeCaG4vj7yrPjCyrmVMXvkWUAkcVmM9gKswKUHAaNK/g==
X-Received: by 2002:a05:600c:4347:b0:41c:3e1:9db9 with SMTP id 5b1f17b1804b1-4212e09ccfcmr73854855e9.27.1717431236060;
        Mon, 03 Jun 2024 09:13:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4449:b0:421:3948:6fc9 with SMTP id
 5b1f17b1804b1-42144db55a7ls635935e9.1.-pod-prod-02-eu; Mon, 03 Jun 2024
 09:13:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlZi/Dw5WPIda6YtLQxlT9Cy5Y2B5Ktaxj5s8czgNaDCwzdxGemVlwPzw4ZqbPiNV0fPBqSlhrJceSR89DkyxVPqAWFQCQm22Diw==
X-Received: by 2002:a05:600c:450b:b0:421:2990:7f8b with SMTP id 5b1f17b1804b1-4212e044c39mr77809515e9.3.1717431234206;
        Mon, 03 Jun 2024 09:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717431234; cv=none;
        d=google.com; s=arc-20160816;
        b=nxbdRYRuN0T12KRu12+NC9FsbtgsQcBDYrnUCmDGicpDAALhhD4VM3vVOgdN3KtlIV
         8mjLy/TymNy4MD0ssWZy4iLHKrng9ODJSwZLHpS4znsQAf6dUTpVQvA2lXHbhSVda3+x
         c/SU6b2eNP82Big0bYHxPebgFWjiNEPoGba3lne5213D3+lYiBntjPotdntxKFytA2D4
         VebJ/zV90TYRGR2r7kSmYTUoF/Giw6Co2Ht0COT3rXyHiS3gRmmTJhwgnnj5z/a3t78I
         mYDyR0ZC8QF391x0fER8wrRyJ2hdUoiNrcBJdjvS5wbKLNd7eblUxHCUD8/5m12xyfgA
         QBtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to
         :dkim-signature:dkim-signature:from;
        bh=QCBBZJLHh7XXomoDX6GxiwpPupsy6ADT629bR0qasGs=;
        fh=t3xc+VipxTgakH/eJ8ttfHL9Uc6rv0is+WNcGlxnnM0=;
        b=E30QR4UThu3jmydWgJBmiHSUuSng6hW8ZvsR/WClF1TVEIIUCkwEv9Z5qsuiLwXPJk
         mC/1QUxNbmKlVlDMOzJeb+BeQxHFz4FUo803pf7E82i5Ykpb1GJl19vgU4FxG0rpXBTC
         c7fXibM29++dSJRozyudPVwIuUw5lpXsxcaMUUUW309rQPpmEwa/010fHgBq1YvbK31/
         MD9c8FiQRaCG0xkUGVDSvx1FcV7yCzN5QtLlzO/O3f6mjThvfKl5pScCHTBZ6ksTCaLv
         PtuOuni1er/mhOjUhGgavKraFu0Yza1THFB3vMYwPD6x5A5QIsMaQm6L8+fx2W9r/Xca
         dOkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=jtIS63tC;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4212b892ec0si1550355e9.1.2024.06.03.09.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jun 2024 09:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>, Ingo Molnar
 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling
 <morbo@google.com>, Justin Stitt <justinstitt@google.com>, Gatlin Newhouse
 <gatlin.newhouse@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Rick Edgecombe <rick.p.edgecombe@intel.com>, Baoquan He <bhe@redhat.com>,
 Changbin Du <changbin.du@huawei.com>, Pengfei Xu <pengfei.xu@intel.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, Jason
 Gunthorpe <jgg@ziepe.ca>, Tina Zhang <tina.zhang@intel.com>, Uros Bizjak
 <ubizjak@gmail.com>, "Kirill A. Shutemov"
 <kirill.shutemov@linux.intel.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH v2] x86/traps: Enable UBSAN traps on x86
In-Reply-To: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
References: <20240601031019.3708758-1-gatlin.newhouse@gmail.com>
Date: Mon, 03 Jun 2024 18:13:53 +0200
Message-ID: <878qzm6m2m.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=jtIS63tC;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Sat, Jun 01 2024 at 03:10, Gatlin Newhouse wrote:

> Bring x86 to parity with arm64, similar to commit 25b84002afb9
> ("arm64: Support Clang UBSAN trap codes for better reporting").
> Enable the output of UBSAN type information on x86 architectures
> compiled with clang when CONFIG_UBSAN_TRAP=y. Currently ARM
> architectures output which specific sanitizer caused the trap,
> via the encoded data in the trap instruction. Clang on x86
> currently encodes the same data in ud1 instructions but the x86
> handle_bug() and is_valid_bugaddr() functions currently only look
> at ud2s.

Please structure your change log properly instead of one paragraph of
unstructured word salad. See:

  https://www.kernel.org/doc/html/latest/process/maintainer-tip.html#changelog
  
> +/*
> + * Check for UD1, UD2, with or without Address Size Override Prefixes instructions.
> + */
>  __always_inline int is_valid_bugaddr(unsigned long addr)
>  {
>  	if (addr < TASK_SIZE_MAX)
> @@ -88,7 +92,13 @@ __always_inline int is_valid_bugaddr(unsigned long addr)
>  	 * We got #UD, if the text isn't readable we'd have gotten
>  	 * a different exception.
>  	 */
> -	return *(unsigned short *)addr == INSN_UD2;
> +	if (*(u16 *)addr == INSN_UD2)
> +		return INSN_UD2;
> +	if (*(u16 *)addr == INSN_UD1)
> +		return INSN_UD1;
> +	if (*(u8 *)addr == INSN_ASOP && *(u16 *)(addr + 1) == INSN_UD1)

	s/1/LEN_ASOP/ ?

> +		return INSN_ASOP;
> +	return 0;

I'm not really a fan of the reuse of the INSN defines here. Especially
not about INSN_ASOP. Also 0 is just lame.

Neither does the function name make sense anymore. is_valid_bugaddr() is
clearly telling that it's a boolean check (despite the return value
being int for hysterical raisins). But now you turn it into a
non-boolean integer which returns a instruction encoding. That's
hideous. Programming should result in obvious code and that should be
pretty obvious to people who create tools to validate code.

Also all UBSAN cares about is the actual failure type and not the
instruction itself:

#define INSN_UD_MASK		0xFFFF
#define INSN_ASOP_MASK		0x00FF

#define BUG_UD_NONE		0xFFFF
#define BUG_UD2			0xFFFE

__always_inline u16 get_ud_type(unsigned long addr)
{
	u16 insn;

	if (addr < TASK_SIZE_MAX)
        	return BUD_UD_NONE;

        insn = *(u16 *)addr;
        if ((insn & INSN_UD_MASK) == INSN_UD2)
        	return BUG_UD2;

	if ((insn & INSN_ASOP_MASK) == INSN_ASOP)
        	insn = *(u16 *)(++addr);

	// UBSAN encodes the failure type in the two bytes after UD1
        if ((insn & INSN_UD_MASK) == INSN_UD1)
        	return *(u16 *)(addr + LEN_UD1);

	return BUG_UD_NONE;
}

No?

>  static nokprobe_inline int
> @@ -216,6 +226,7 @@ static inline void handle_invalid_op(struct pt_regs *regs)
>  static noinstr bool handle_bug(struct pt_regs *regs)
>  {
>  	bool handled = false;
> +	int insn;
>  
>  	/*
>  	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
> @@ -223,7 +234,8 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>  	 * irqentry_enter().
>  	 */
>  	kmsan_unpoison_entry_regs(regs);
> -	if (!is_valid_bugaddr(regs->ip))
> +	insn = is_valid_bugaddr(regs->ip);
> +	if (insn == 0)

Sigh.

But with the above sanitized (pun intended) this becomes obvious by
itself:

        ud_type = get_ud_type(regs->ip);
        if (ud_type == BUG_UD_NONE)
        	return false;

See?

>  		return handled;
>  
>  	/*
> @@ -236,10 +248,15 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>  	 */
>  	if (regs->flags & X86_EFLAGS_IF)
>  		raw_local_irq_enable();
> -	if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> -	    handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> -		regs->ip += LEN_UD2;
> -		handled = true;
> +
> +	if (insn == INSN_UD2) {
> +		if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> +		handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {

Please indent the second condition properly:

       if (a ||
           b) {

I know you just added another tab, but when touching code, then please
do it right.

> +			regs->ip += LEN_UD2;
> +			handled = true;

> +/*
> + * Checks for the information embedded in the UD1 trap instruction
> + * for the UB Sanitizer in order to pass along debugging output.
> + */
> +void handle_ubsan_failure(struct pt_regs *regs, int insn)
> +{
> +	u32 type = 0;

Pointless initialization.

> +	if (insn == INSN_ASOP) {
> +		type = (*(u16 *)(regs->ip + LEN_ASOP + LEN_UD1));
> +		if ((type & 0xFF) == 0x40)

No magic constants please. What does 0x40 mean?

> +			type = (type >> 8) & 0xFF;

That mask is pointless as u16 is zero extended when assigned to u32, but
why not using u16 in the first place to make it clear?

> +	} else {
> +		type = (*(u16 *)(regs->ip + LEN_UD1));
> +		if ((type & 0xFF) == 0x40)
> +			type = (type >> 8) & 0xFF;
> +	}

Copy & pasta rules!

	unsigned long addr = regs->ip + LEN_UD1;
	u16 type;

        type = insn == INSN_UD1 ? *(u16 *)addr : *(u16 *)(addr + LEN_ASOP);

	if ((type & 0xFF) == UBSAN_MAGICALLY_USE_2ND_BYTE)
		type >>= 8;
	pr_crit("%s\n", report_ubsan_failure(regs, type));

I don't see the point for printing regs->ip as this is followed by a
stack trace anyway, but I don't have a strong opinion about it either.

Though with the above get_ud_type() variant this becomes even simpler:

void handle_ubsan_failure(struct pt_regs *regs, u16 type)
{
	if ((type & 0xFF) == UBSAN_MAGICALLY_USE_2ND_BYTE)
		type >>= 8;
	pr_crit("%s\n", report_ubsan_failure(regs, type));
}

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878qzm6m2m.ffs%40tglx.
