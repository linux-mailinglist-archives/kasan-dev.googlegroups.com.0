Return-Path: <kasan-dev+bncBDV37XP3XYDRBWWH36WQMGQEUCUU7FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C2E8D841105
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 18:43:56 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6de0fc90a93sf983500b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 09:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706550235; cv=pass;
        d=google.com; s=arc-20160816;
        b=EpzIryzsIH1VVvEJ2J1FxESFtyN+IBk2Ti9W561oALmHDiFoB7Q9Ymnh10pik75dDY
         L+2iv5wZXBzLzmq64vbiB5jeyqre8q1pteDkWV+W82gs6EkMpqZypsZ1BOHBN1qgA9oH
         7KUVNgsu4+9NB6gzdRToLd9a59pSx3S0GScFullKyk+cMaLCy/rlEf62b7BvIxM8D2qr
         xkzQyvJ2Ujcg1Qt73MGZ+I4SQEiPTK4ETIit6iDuYNUzr3t3/s9ko9p5orh05AO14ZbH
         Ls9V4Xfh8Z/W6cjMvhCJKt/vg+l9MK5EHtNDmpYzPEnCBEo8y/VstuUyzaHuEamqceLf
         KrGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b1O/WK3dO3AoYyg0JQNsYcX7Acm7iUuhrh6UA1b9eLU=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=GewUgm97FSOavnMMnV/sUjGDvrjB8fOVb2Fa6HRM2ug4TPLHgNJmW7dl+CnFm2CFBu
         qjNizzmNtvzQXWY8KCkj3KHJ9Dh1epz6ygSUyJwIRytL2CBewSXmbl6o7KbfgFzd4PsP
         3csLzFUrt29OP+mM6MxIZJMT3QTCYy/d60cvnY7n1d85xlcHVZh5nIpiEvj88I/gQFxx
         xEYf9hP94OLO94Hzuv3Qm7inX8BY26AuNDADw+CQvRIj2izg2J5P9jeiNQhG8/ognytU
         E8sDRQWW3CK6zy7vuoJKG4k1cFDWJoUbgGU6kg/Lh2+97jfOo7G0mdGO0Fk9gXD7P24G
         oLXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706550235; x=1707155035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b1O/WK3dO3AoYyg0JQNsYcX7Acm7iUuhrh6UA1b9eLU=;
        b=iFFYvyRrYoMZan5yOLChajX2nOZ4qLncvBpHll/HygSRddINaVR+sJjoj2JnzmhXqs
         1yx1hGAWG+i2EJa1ZVHvTMcs8+Ayh1p8U0QWhAsRb9zxJNdBJW0zzKktXaoPsSHKLS0W
         LQP2UWzQhklpXFdmC1eg4Ybt4ZM/C3MTNxIFSVLVzybAQScACtlARrY+6HIjLosxb0ua
         0vC/kXSsjDNMZSK7C3UfO89AoQMsuT5ioXCJu6v83dp4nIlS4n/zY7OG0i4K42xOfxJd
         2bUEZNhwhjKt/miQOD3FwloKDHuvU9RvMLDk5aTfHyX/geyLX2DsxlbVZWIuH0Luaqqq
         mkmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706550235; x=1707155035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b1O/WK3dO3AoYyg0JQNsYcX7Acm7iUuhrh6UA1b9eLU=;
        b=RVBGZzAuMuFYo17xqavgZ2ehSgd+rLyhIyi6x69TrmlFjrWZ/Hb4dN+0snMMBtzp3S
         j64abFucXLu2AcBkggoWgpuIuY4ZXsPMx584xBuVJyDcR6zV1lAgHdBg1unD3Fc2vu0F
         st+HZNC3c4SHyMSHHN21uQkqc3toddhWgkvIS2S6mcKop2fQ+g5yiqU/jse+kUY2EPKm
         n6xEmh71xGTgAnMIb3ooVscvDKHy2nZNoJ8u7Exz96maZlJKc3bAHtZFtypxMGuc2apR
         WCumPWeDc33Aw8JS/F7JlmWOLRg4xWx26KBRsSGSjAGBKfbM1OkBFIcDmcof/PG5XZiU
         RJQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhLAxfmgrrJO+w/DkY92Rndoa1iOtiYdgvYRzgaI6VSoVgfMXX
	GSvYrJC1SCNjzhr3BTBf5WZGfXTxizbI/Rwd/kF3c2K5E3MNPmrC
X-Google-Smtp-Source: AGHT+IEsOXpWwu6PQoxCCTHBO676CDOij4Dhzvjz67XrPWto3LDri73Wc/mNO8/AYQ8YRpXmqschiQ==
X-Received: by 2002:a05:6a00:22cb:b0:6dd:6caa:aecc with SMTP id f11-20020a056a0022cb00b006dd6caaaeccmr3061121pfj.31.1706550234940;
        Mon, 29 Jan 2024 09:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:92aa:b0:6dd:739f:ec26 with SMTP id
 jw42-20020a056a0092aa00b006dd739fec26ls1246457pfb.0.-pod-prod-04-us; Mon, 29
 Jan 2024 09:43:53 -0800 (PST)
X-Received: by 2002:a05:6a20:c407:b0:19c:23f6:861b with SMTP id en7-20020a056a20c40700b0019c23f6861bmr2430393pzb.57.1706550233663;
        Mon, 29 Jan 2024 09:43:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706550233; cv=none;
        d=google.com; s=arc-20160816;
        b=DTcdt/q+BoPylrIOm2q7ThlbFzt/uSEfb5C/z1qE5Iu0aEP7XZ9aiociHwXGTAPEQK
         nhqqa7PzWu1Rch0b42OpWaHK9KLYdPID2GiCg5mZR5zqeM7cmrnsy8tdzB91eXO7DD/n
         repFo8kE6+ZNpXyoE4/C8lpT422USmoPEBp3+zEQOiTjb2d/rxqfAQzhh3NoEzJGKuIU
         HvWZrlKY7WEurI4HiPTG99gmzc0p898/0jg7zOqzEEDcJbAzzQVe0jXBkDmTrLD1wqE2
         qGB/MI6FpUuFWrc7Lu4344moezsPOupSiOcz2Ya31LwYAbEwH1QX/BQS6SXF32hjoVii
         Stlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=SWYBLvZfUt2cLhO8iTZgbrxGUftGYF8K8yBDbQbJxm4=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=u5lLPlNw008vUzyLuZsutp76DxXcJqhg0LF6/AeWR938wLO1VFMVZ0eBPOy6JLv1FE
         7KdFlQQDMrTisNycuSgQ29IluMvplio7Jg0gyLfAlkuJcgJl7k7zWxbqJU83/zg0A4Y8
         fVdWj9NTQ5DVuwFYspQDKb/0rId01zIW2uG4CKDB73II8rPdvOK9QqSiCyQMXqI7ClV8
         ozAlxKzMLLt+JG+hkydyk9psfJR+Wq461sZwwwg3f/xKuJNc/XqfaAROgazbpuFbHHmU
         Kc4LAxGYwy6pnzBDOG18i7NRYQhRu41tm5cflzUCVsJLVhN783HOXkWsGp4OkP+9s0gl
         hUww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id jc13-20020a17090325cd00b001d8d1a697bdsi216261plb.9.2024.01.29.09.43.53
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Jan 2024 09:43:53 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 719E5DA7;
	Mon, 29 Jan 2024 09:44:36 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.128])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6A2B13F738;
	Mon, 29 Jan 2024 09:43:48 -0800 (PST)
Date: Mon, 29 Jan 2024 17:43:24 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 3/6] arm64: add uaccess to machine check safe
Message-ID: <ZbfjvD1_yKK6IVVY@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-4-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240129134652.4004931-4-tongtiangen@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 29, 2024 at 09:46:49PM +0800, Tong Tiangen wrote:
> If user process access memory fails due to hardware memory error, only the
> relevant processes are affected, so it is more reasonable to kill the user
> process and isolate the corrupt page than to panic the kernel.
> 
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>  arch/arm64/lib/copy_from_user.S | 10 +++++-----
>  arch/arm64/lib/copy_to_user.S   | 10 +++++-----
>  arch/arm64/mm/extable.c         |  8 ++++----
>  3 files changed, 14 insertions(+), 14 deletions(-)
> 
> diff --git a/arch/arm64/lib/copy_from_user.S b/arch/arm64/lib/copy_from_user.S
> index 34e317907524..1bf676e9201d 100644
> --- a/arch/arm64/lib/copy_from_user.S
> +++ b/arch/arm64/lib/copy_from_user.S
> @@ -25,7 +25,7 @@
>  	.endm
>  
>  	.macro strb1 reg, ptr, val
> -	strb \reg, [\ptr], \val
> +	USER(9998f, strb \reg, [\ptr], \val)
>  	.endm

This is a store to *kernel* memory, not user memory. It should not be marked
with USER().

I understand that you *might* want to handle memory errors on these stores, but
the commit message doesn't describe that and the associated trade-off. For
example, consider that when a copy_form_user fails we'll try to zero the
remaining buffer via memset(); so if a STR* instruction in copy_to_user
faulted, upon handling the fault we'll immediately try to fix that up with some
more stores which will also fault, but won't get fixed up, leading to a panic()
anyway...

Further, this change will also silently fixup unexpected kernel faults if we
pass bad kernel pointers to copy_{to,from}_user, which will hide real bugs.

So NAK to this change as-is; likewise for the addition of USER() to other ldr*
macros in copy_from_user.S and the addition of USER() str* macros in
copy_to_user.S.

If we want to handle memory errors on some kaccesses, we need a new EX_TYPE_*
separate from the usual EX_TYPE_KACESS_ERR_ZERO that means "handle memory
errors, but treat other faults as fatal". That should come with a rationale and
explanation of why it's actually useful.

[...]

> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> index 478e639f8680..28ec35e3d210 100644
> --- a/arch/arm64/mm/extable.c
> +++ b/arch/arm64/mm/extable.c
> @@ -85,10 +85,10 @@ bool fixup_exception_mc(struct pt_regs *regs)
>  	if (!ex)
>  		return false;
>  
> -	/*
> -	 * This is not complete, More Machine check safe extable type can
> -	 * be processed here.
> -	 */
> +	switch (ex->type) {
> +	case EX_TYPE_UACCESS_ERR_ZERO:
> +		return ex_handler_uaccess_err_zero(ex, regs);
> +	}

Please fold this part into the prior patch, and start ogf with *only* handling
errors on accesses already marked with EX_TYPE_UACCESS_ERR_ZERO. I think that
change would be relatively uncontroversial, and it would be much easier to
build atop that.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbfjvD1_yKK6IVVY%40FVFF77S0Q05N.
