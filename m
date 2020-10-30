Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUX65X6AKGQE73LVLZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B11A529FBA6
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:49:54 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id r19sf679805wmh.9
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026194; cv=pass;
        d=google.com; s=arc-20160816;
        b=G5wxhG7niWrOupCfDAWZWvgrKFZvCsKih2xTYsVdd0XJtZ1Zz3FGsGNnhz1G2naJk5
         MznM0aLLnH0k0/z4m2XYqp2ibDibTkrgtxTgZYu7ThlsiXRmFVUY3ARjHBUnPL4yBag4
         FdxiCU76pRuZyzxEnptj+ybhKO+chIouEq5Kiq/gXM6USK17d8huGqdulMIvtRfAX7pl
         OKrBtJXLC4SQ+4Q2yGUDiAXqP9gslB0onlisnNXhH80Nt9ZeKGX5CQgG5uxvro5xsjx2
         E9h9sHgAwDOS4AGEBxXZMdeE6/MVa5XEARa3TRmj4kzNvJ8k87Go1SmIo2bpl+8g7uGv
         00aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=88o2GA7WL0oswN0iz60s/9g+0vRrJUK+zQfG/DpZzsI=;
        b=bcVX/ufsngKkZp9t25S/MCJlxgkk3EGnl9qQIbhh+/SLrj+F5+LJ51+USUMoQTtUgf
         J5JH7kff9NvAeiaQ9hJIIF8JjE5fJJoLI1G4G8YGh1ZbWyh2xsQQwj2v1EoaSALNAfjg
         VkLLG/BlTdT7CPls6rmlYh0En9NTURuT8d1vQnGs1Qcc7PmMBJpOkYCc5h1GLBBVmf+q
         C91HVxWnnX5cFumnJW9TFKSXOSEmd6zGwPsiOksVU8rfw6ybe8oGrQS+EOeZvaU0a+r+
         wMpb81+BwPRNM328yWapGMpDeD7OaghNaixhNUlyqMpHvKtAsX2TNAUVJ3F+7FOdFDOH
         We3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hvIenZ/1";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=88o2GA7WL0oswN0iz60s/9g+0vRrJUK+zQfG/DpZzsI=;
        b=ONIQCldVxlohpr7jcS+igznX6mE9CAYAVuRhBLCSAawr2s+zihacvKk8/5eue++sWV
         ALdmxmpGRuqEMCXdakSdF7IGGrJ7JLbAgwJA1l3q9+9TTH4daFaFtqEbaVEsc8gNHCyz
         fSME43K46IATXQpvcWmxih/1kPujBFM9kxED+c8wncEaJo04etk40YZOwErwA8r0/msc
         Zedx+7CIgSInEgtTTzYi69TY+Jn7Cp82VLl1g6UAPwdUrcBA7ufXDsC/5huJ9npTH3DI
         Qxd33FT+dpnO+5slLj65amzfyYlLSOew4/uHJZ4Z1FQDTQBPWh5vhbyzFA6YfLCgfWNi
         cYIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=88o2GA7WL0oswN0iz60s/9g+0vRrJUK+zQfG/DpZzsI=;
        b=uX4APsvgPizWIp4Ew1CYmIn7w4l6B17XYlzuTgQHVy/95zViRttcIz5muAkyCybGCm
         TCdY/t9DWnlm8DNSCkZvCN9rGjN7J8sCEa/CnxfGlq+zUQwL1aqkYidUqNz8FYCHH47Z
         93Mi1WOXBVXcOGGu+SVsfuajh9iPLYlzMAeGTnwD2qZya4Uj/R0180QsMduvJGKBoNmJ
         e62XtW0U5Liu4fL24PZukghlfk33sZ33obJbxJ2vax5zLBX+RkO+ZVagI/mqFsBp0Z7h
         Vy4W1j+odeM4mCqmpU/mKggQfl1zU2Md4ERgq9akq8OFd/6OIFsg8laPXBYzJWpTadrV
         91/Q==
X-Gm-Message-State: AOAM5320TRd7KzG61IoFrAltlERGHDeA238UyLB2wZ45SXsbYSw6zFvE
	ioq4C2vyDhQaI88QFWkgujQ=
X-Google-Smtp-Source: ABdhPJyte4uNBa5LpuVUagD0L8YWEb4JzF1Go9mLqxkc5ryg+h2THAImwr2zEC80KMm5NkXXH77J9g==
X-Received: by 2002:a7b:c1ce:: with SMTP id a14mr75602wmj.126.1604026194503;
        Thu, 29 Oct 2020 19:49:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c794:: with SMTP id l20ls3607491wrg.2.gmail; Thu, 29 Oct
 2020 19:49:53 -0700 (PDT)
X-Received: by 2002:a5d:40c3:: with SMTP id b3mr167840wrq.157.1604026193667;
        Thu, 29 Oct 2020 19:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026193; cv=none;
        d=google.com; s=arc-20160816;
        b=WC0qAhSgU/u96uvThLT9MdgUC68qavoSOqv9wMxahf/1jCd/ivr8gWanBieDKgkfIC
         4IolAAHJub9YYiTPSsO9Jv/JQS4v/WRpAd121qjDz3FiphiQRKidgmsoehpbGvEcJrRy
         Q1eqHqJ6ZikI2lQLtzBIhaWO2LmDYjVkPzXXM2ejtbFjylRSE+OkiSE/a9zPIcg8/ayq
         fldosTtpa4piiNT7veGClFbSa+/Y6/FdOpcQHPvCFPNhV9XJAizT8LxhaNz4Mclt4wLf
         a3OqhB6tAuqRIRogEBUNfspqS/n19RPK+v8bycThREIXtUfL7nS7sDY6qfYTRCy8o9y+
         JhuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U5VSV5EOvuuPrA9xNEsowWeAohxv+a7+9KVx3Owvda8=;
        b=amd8/HA7X/34PsdtVWsSFAP6rQtDTPBcVa2D8HRp6JIhv3pV9ajRLEngh8tJ2YuZoc
         mI5LPYbDZ7MYcKjTLnS9u72RbgE5bdwlgWvRdCv8jvir7Ka7VX0yjSLNzstPtWqdH4+M
         Mkkn6/KH9aohCZFqiWkVgKNDVf8yX8pZ858/1j207Jgxxjit00A+rdq0nhJ0cfUrMwy+
         gsgPioBjUNUWfuFjpcRFYCdDOBKd1ciT40wdN9S5OUXEzQDFT6llX50Ao8x/k4d3zJW4
         jZG/2RYZB6CP7kBoC0Vc2auAtnPOisa5elzbCdPjI0Stny04hPP4ZhuBDYYRfq7hdVwm
         JQwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hvIenZ/1";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id y14si162739wrq.0.2020.10.29.19.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id x16so5386244ljh.2
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:49:53 -0700 (PDT)
X-Received: by 2002:a2e:8816:: with SMTP id x22mr82450ljh.377.1604026192956;
 Thu, 29 Oct 2020 19:49:52 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-4-elver@google.com>
In-Reply-To: <20201029131649.182037-4-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:26 +0100
Message-ID: <CAG48ez11T4gXHkhgnM7eWc1EJQ5u7NQup4ADy75c1uUVPeWGSg@mail.gmail.com>
Subject: Re: [PATCH v6 3/9] arm64, kfence: enable KFENCE for ARM64
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="hvIenZ/1";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the entire linear map to be mapped
> at page granularity. Doing so may result in extra memory allocated for
> page tables in case rodata=full is not set; however, currently
> CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> is therefore not affected by this change.
[...]
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
[...]
> +       select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)

"if ARM64_4K_PAGES"?

[...]
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
[...]
> @@ -312,6 +313,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>             "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
>                 return;
>
> +       if (kfence_handle_page_fault(addr))
> +               return;

As in the X86 case, we may want to ensure that this doesn't run for
permission faults, only for non-present pages. Maybe move this down
into the third branch of the "if" block below (neither permission
fault nor NULL deref)?



> +
>         if (is_el1_permission_fault(addr, esr, regs)) {
>                 if (esr & ESR_ELx_WNR)
>                         msg = "write to read-only memory";

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez11T4gXHkhgnM7eWc1EJQ5u7NQup4ADy75c1uUVPeWGSg%40mail.gmail.com.
