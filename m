Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ6WX64AMGQEIUMHMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 448049A0FCB
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 18:34:49 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5eb61a5d117sf60270eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 09:34:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729096488; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xjr4jFDc3Gg/ireGIOtXctTPtD7lEWHJLI2IPv+3MZE1MFxg0A1qXex8MCVQNA6yqi
         2c5bzVvVCgx6mASyKQiTjA/q1d03SqGDLQP8DhiyC9WcaqPnTNUAVlrdR1QOu7k75EvF
         hzcIV75dw3xdfaZwHzzbOcznM8SoXNu37ooEtAIz/NhuYjjZ+8sMRdIUAGZ6MfijT0XZ
         qNjR9ud6l6g3mIVBKLiDvb0Fjr80pkEm6Nm3gkw1BWWixZfKmAL4WRZJkWt3sWrnae11
         YpLA956jO1Mt1QOE9/PBErRIDD4micTggZ5QBzpTQ5q1xuklU4KHPGbh8kNke4vBexok
         +C9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cH3bh7KBYe1rn7VYyZT2ZlYmDJ9sRDH2Pv0odbHKqNQ=;
        fh=LVmIMOZEtu9EyesWArEKKxIHIijH/iFcDOWvmhkEE2w=;
        b=E9jkVgWVeBINhN9IqCDyzsZWkNHirvYJLy/SEGTBqywt+kqC3EDEn8/qjUpB/K/JCj
         IuZprNAFwBksUXT8sWXR5sS5B8TbRhO7gsSVP6LROxcwz80meYjRmdA+Llv55ugqFtJ2
         bHO7UOzgjJTCZF9d1GYO3FEWAHSaaE6n86ls9t20WDAPL7iVgHKnjyQG0WkgzhnuMjsD
         6ELNoYzLC6+fl3Sv54CmaczUdZ65rR1G8SDI+NlvqYzvqmM2Nk7rjCXslguKSN+2vQBm
         RXoSyTwRkO1zuQcKlNgV2fye+vSCTbT4p5mUyf/Sk/GQuHkmiwNfOaIUG+9jkxTvXKAO
         Yk2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UXm+ppi0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729096488; x=1729701288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cH3bh7KBYe1rn7VYyZT2ZlYmDJ9sRDH2Pv0odbHKqNQ=;
        b=Vzh7WzZc2rc1wI8cyAnQbOZKMxoe2pTIsbD2fPvNIJK12KHCJH5fRApV/hWDXOU3CA
         a0ohOZet2igXAbmhLknRZZihzwJC9cQIazc7WOK3QDQVgGJEjpzzu+9cAOYCpVN/CXuK
         TBYMw8Ypg23k6D/Zx+94Cs6aDj6vCcvnKZ0s4aQbaNJQ4Vof7ExAkzMI8s34fnMbZpzL
         CgjCx0e4T7Yvb/yRKPJTBQvskKxE0hduGoIuAHsZuVmzHv8dP4ZW6GlEwi8A1tZ+oJIU
         8VB/pHAkjPmG7bxy3bib1R7cTPe4GVWztUx83kp+MyP0j41FkCm+I6idZqE1C2iA572I
         8c0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729096488; x=1729701288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cH3bh7KBYe1rn7VYyZT2ZlYmDJ9sRDH2Pv0odbHKqNQ=;
        b=spJkvJEVxYC4CpM8O+HqiMDe1A9ttfP7DgLSX+hrf5cZBn2VLcUKjoOUJEtPwjGL7j
         /BeXyFgjv/cwxQpa3mJbu6SaHSgIKjKOCffACCQTCccS9GGB6AYveYBGTTHQ8L/QfiIZ
         Di8RsrMVFIMfymexDDv1J2J+7hPqkPMOPVI+ghs0diuVdjGRcwNyT5+0MzsmIJUOSiYl
         qkG68mCnncH5KclUeN5JBsCRXODl+45p+ZaKJotzs35IFP/gwOK+j2QjnMJ7XwXI2Gvx
         oEBX6H6KpX6I2siFDM14m0Hr58zHB5+USiQmfvMNiHdUwnBgnbo5R2ztnBhjNDxhD0tv
         vlQQ==
X-Forwarded-Encrypted: i=2; AJvYcCUElR5bBhcRZ+vAgxMi9NA8kTLeOkXcUnKfsHh83M6JucR7dN4K1EG6DuUu2xHnvljJtXYQ5g==@lfdr.de
X-Gm-Message-State: AOJu0YxR/+4G1HwzGWz5UY9MIGcEecnRorS7qTpQZxLXIbLa7v/yLzcD
	q6S6T3tVhedHknsa0gegQiW/E+No9cfxQTiTnkLtWQPHE3HuYLTJ
X-Google-Smtp-Source: AGHT+IHX8EyHLp0Uu5LtcXpYQHysfvySNhnwo+POky+8Zq1Tr9rlDgaTVHnWCnrDHRFm7tKqZc/udA==
X-Received: by 2002:a05:6820:2215:b0:5e1:d741:6f04 with SMTP id 006d021491bc7-5eb1a19d225mr9722077eaf.3.1729096487819;
        Wed, 16 Oct 2024 09:34:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b813:0:b0:5eb:636b:1b4b with SMTP id 006d021491bc7-5eb6bbc9559ls67924eaf.2.-pod-prod-01-us;
 Wed, 16 Oct 2024 09:34:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWb47GZvQoCmZi9OSJOQDHbS+c0Yp6pG8mJ/skBi2O0R3apWYZhRmg2MYQBkOTkNgTbiRegYf75z1U=@googlegroups.com
X-Received: by 2002:a05:6830:3509:b0:70f:716c:7d4a with SMTP id 46e09a7af769-717d65bc340mr18700167a34.27.1729096486619;
        Wed, 16 Oct 2024 09:34:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729096486; cv=none;
        d=google.com; s=arc-20240605;
        b=eY7EE9IIvYA7mM/d54KNKMQj4XSaShdv3rbJUiSjjz2GUCB53K01RhRDh1adJjUYZl
         yb3yfrJ8KymR32W/pPZ88v0LQi5+M7zTIqIF+AtMwukGCdBP+9TltYgn4wxL9cBaWD01
         CrqeOUtN4Vwg71gmOfhiV15WLmXogAufaoz/s3Cak/ePpivEqQ2RgbBI3kV2OyCluO/B
         Gz3uxmImXsxFF1nlZCYRRk8cPzSePnqQQQezK+Vx1leDOR302vjxhyEb+MjvlI9aXzT1
         fmEq/AzWYal5BNZut8yy6yeaXQn1UbfrByngjlpXd7An32Wfz7twBTf5+Z9RtguGNy5W
         clGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0rshs8JSwkn4JoxD+NjTq/04DsnCWL9TnPBUKxzKlyQ=;
        fh=5Q+nZMF8BrO0iYpmPEdv/Zpd8FS6l+8prD4LaAWgYc4=;
        b=GwL3IfqRyH2dtkyySZTDs96Fu3KOwU4PiBjhLYXhDBjKmTr3fQOVuQirFUsxB7+RWK
         WLC9UAYkgi/OrS0V2ljmFl+iyktdLLoqpoOwpObYzBAzCmvxlECw7zvD5x8dRh87D7B7
         P10FR4d8PM4CpFvZ0Mn5qGX+oKgmPncPMcw3VZQ7wu4cOm20M74Y5U1mGujBYFW4Ar4K
         SL6tMr6xRa74QbvxiDbKH5GzW2hl3vzt4BJvAQeYG52/LDdNAFM4DO/4tgzQL14V+gdv
         ym/aenuQNdg01sig3nRn1kWy2uc69R07lBjL9rqXSSE6jEi9Pw9kyX/wZp3FhbOaKGht
         71Gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UXm+ppi0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7180722e200si77461a34.0.2024.10.16.09.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 09:34:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 46e09a7af769-7180120a78dso1153190a34.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 09:34:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXT8d+v4zBPyHT6EUO8t7mCcI5tEx6Dgm9x7hEqGE9MZApnNL/Xj7so8reBPnokZgHyBxjqDH/RYnU=@googlegroups.com
X-Received: by 2002:a05:6830:4890:b0:715:4cb1:4409 with SMTP id
 46e09a7af769-717d65d8bc4mr13549998a34.31.1729096486089; Wed, 16 Oct 2024
 09:34:46 -0700 (PDT)
MIME-Version: 1.0
References: <20241016152407.3149001-1-snovitoll@gmail.com>
In-Reply-To: <20241016152407.3149001-1-snovitoll@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2024 18:34:05 +0200
Message-ID: <CAG_fn=WTUXdGH+1oKx8LSwDXrFFMz3Fy1XZUAcbw3TmFmpopFg@mail.gmail.com>
Subject: Re: [PATCH] x86/traps: move kmsan check after instrumentation_begin
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, x86@kernel.org, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UXm+ppi0;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Oct 16, 2024 at 5:23=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> During x86_64 kernel build with CONFIG_KMSAN, the objtool warns
> following:
>
>   AR      built-in.a
>   AR      vmlinux.a
>   LD      vmlinux.o
> vmlinux.o: warning: objtool: handle_bug+0x4: call to
>     kmsan_unpoison_entry_regs() leaves .noinstr.text section
>   OBJCOPY modules.builtin.modinfo
>   GEN     modules.builtin
>   MODPOST Module.symvers
>   CC      .vmlinux.export.o
>
> Moving kmsan_unpoison_entry_regs() _after_ instrumentation_begin() fixes
> the warning.

Thanks for taking care of this!

> There is decode_bug(regs->ip, &imm) is left before KMSAN unpoisoining,

(side note: decode_bug itself is inlined into handle_bug(), so it is
not instrumented, and no bugs are reported in it)

> but it has the return condition and if we include it after
> instrumentation_begin() it results the warning
> "return with instrumentation enabled", hence, I'm concerned that regs
> will not be KMSAN unpoisoned if `ud_type =3D=3D BUG_NONE` is true.

So far the only caller of handle_bug() passes regs to
irqentry_enter(), which unpoisons them anyway.
I think this is fine, adding an extra instrumentation region around
kmsan_unpoison_entry_regs() in handle_bug() would be an overkill.

>
> Fixes: ba54d194f8da ("x86/traps: avoid KMSAN bugs originating from handle=
_bug()")
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWTUXdGH%2B1oKx8LSwDXrFFMz3Fy1XZUAcbw3TmFmpopFg%40mail.gm=
ail.com.
