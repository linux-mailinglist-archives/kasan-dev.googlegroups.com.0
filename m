Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBTH65X6AKGQES5ZJS5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C563129FBA5
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:49:48 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id d13sf1928170ejz.6
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026188; cv=pass;
        d=google.com; s=arc-20160816;
        b=oWh0dX2htO1zUIQIO2J20MJ62uev3vwxY4lLBwodFpo0OLQWd4dMRKzBWY94EI4c4V
         XndcWtrFExpUZu3OQPQUKsY1MUYvrIxClhbr5fWbHpW6rUj7SttjBHEthFAX5jDcvx12
         IrSJA0GhZttxcfGtqRgw6UM4LDskTF6JBc/vQkp+BVAXToKgDe31CQy4WCnnxdvsxwTr
         V9ihS0FKJGuXf6Yglod7dhMG0SxiK1VyvfYHSTofm2qf3HZbzATGmvy66KpHOKmF+37+
         BJG0pnFjUzWq1nnfBQPYY5N2AdN5lekSKTkWzeHKVzNE6qWzIwgtfNVD2DCydN4YRMKr
         bvvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=++5Jn343xZemZqMMRGsvBcsWJhMkHd4ySWAZLI7GaA4=;
        b=VsmA3r0Zqe8FV+o+aFQdSNqrlP+4JbTZwWQQ+2T47lci1hMmKvBajb1X4OYbOnLuCB
         3+uZrHABi25KKdFBxf+kEF3HchvXydCeVKDEUJMHq/7cBLexq/W463XHQXo0MsL+upNi
         x3kwYdCpxdLIr1WMYsqGCP8zcB/8uA4rbVytI6mYpVl63fqRoExRgJcR9Hsy95WNwMVj
         ERYnoSwPlIRpm/rBo2/ZJRMCiRU/DL83odFPEWbEwqAeetWzLIoJ1LOWN5O1UjWqaLVZ
         XUwqMEZoM4vBvnl1vvKJH8OBkpdkItL2xs8gVkGOUQuEuRAoulJp9G69D+UuvFY9Zjnc
         iRdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SUW+4c/G";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=++5Jn343xZemZqMMRGsvBcsWJhMkHd4ySWAZLI7GaA4=;
        b=pncmgFvrLprmBbfgPhKpXZUgBuBBDQBw/UrzSXbjn7QBDH4wyYET8/gfo0JCjFb9we
         G2L3o+4MhMxeQs0SJqBXrJyZyuoqfgM/9nBFxl8yP5ehTH0lo/htLJ7nKBU3mw5bPv6c
         xyF5hN/fYDRwdmZyEcnlcqvUfMktBO/5ebBEbae4Jbl1GOuuMNLfOK3XTcqAqq7wxwmt
         ztZMH5oIWwjZHkErMUJx1xx7WehP37vybFlleax3BtY13z3zvjMrNaQLLS4UtdqXswrz
         6lNMXF+IJd+KgB3vardcMv6Vtfru7l9nz74w/iXR1ebjRYB5blH6agNadV37FwRqELrl
         uM8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=++5Jn343xZemZqMMRGsvBcsWJhMkHd4ySWAZLI7GaA4=;
        b=RzNI+PViivQwfW+82qGrAdg7VnbLan52QbCFIzPUM7iE/w0YceGxbLYlaSe74MB/58
         Nh7M6rN8BjtEJqENYxfmSpsgBSoESfNGcth+SXGfhErrWLqYlpLadeQRRjZkmmi5Qjd3
         kb9LjLcU519ourI933exskaTFmDSZUjOHVJ27MiHAz2aKEPBHfi5jIcWryq6eBYs7uhb
         Wr6HsyzqRB0pbi6ip6bwTkjac/jeIhPtSGaRlI4DCcfKplAllT0Pmsia80lTbz5+vpK5
         6PEfPg+hxuD7BGw/kkIsfVRTxM2hVUWyIglxDmxviCxTWw3CW6NUmE8ivikWhTvTqnJY
         HhrQ==
X-Gm-Message-State: AOAM532XjwHEGObNMiT5k+Zh5pqCzYqkoVNpr3mmUKF88gRnNgBoqfBh
	kSUjaJQbf1bynHceDOJ3K7Q=
X-Google-Smtp-Source: ABdhPJzBWQMkqAFzMsC5/b2K9HqEPqSB5otGZFjAlmBetdAtpY4xWJvb1rmc4LdVvzFhuMGgy3rQLg==
X-Received: by 2002:a50:e087:: with SMTP id f7mr70197edl.96.1604026188565;
        Thu, 29 Oct 2020 19:49:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3189:: with SMTP id 9ls2514635ejy.10.gmail; Thu, 29
 Oct 2020 19:49:47 -0700 (PDT)
X-Received: by 2002:a17:906:4816:: with SMTP id w22mr412279ejq.458.1604026187602;
        Thu, 29 Oct 2020 19:49:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026187; cv=none;
        d=google.com; s=arc-20160816;
        b=lCOR1mjWRFkzQBIpnsXzNGljeg/WLD8KebdVfglyAGbZuL1VDGF080qugdKtieb124
         c0GRjnP1TWyS8GVRUDt7n1hlSjqmZFp1H8PXXI7r4y1sfNS5bjgJSrNhZWggEzZPiCiC
         o8AMnNNC77FBDMude88ErtynlnrWs4zGwHReJWPIOMEPtbCdTAmcadWxgV3JiEmWyURl
         2mMPCweWGXjYbceVTJJMLSYuy/UCA7Ow6IXIifTvCL8KqXWpkhg26bd48RlDwUHiUvkS
         qrlBqqWFhnN/KqWRaa761Iv8dU2KMEn/uE4SrtQC3K2ULvKHdHSK7aZIfEUoSwK6FVKn
         XFeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iyTdtZ1FYlfsFiUutt0GVS7r1yGxXmwfsMwCFfiA6Mo=;
        b=UQ5j3P/jklISUoCNdVvXPF9iRnxXWqTDzNnxXMxSI4dTPbNNjS5L2yvnrIY5x5JJ0I
         GooNLF2on6qasEgmK7NgldaI5iAWlWSIm/UhY+gRWoeHxAMeQPNE8sHnhq1RSNvi6HCn
         5nQUvU9B8O7rfgx11qbTMSySKUy3mm41uU67DJnhn5giABII5ZRiG7fmgWgrAf9YRkRF
         HKZiQr3SY9Y70NhW38Cmrrp5h3+PB3fiXMu/Hc2k1eRVVKKKfSWoZo9tTJHPFp4oBbQg
         YE1ejn54MXaiwMRt1D11OIcxEwu4zdVE6ReZJzwBZDZIZJmtw//l0Jk0LVhNOauHSmhj
         PysQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SUW+4c/G";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id n7si113939edy.3.2020.10.29.19.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:49:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id h6so5987732lfj.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:49:47 -0700 (PDT)
X-Received: by 2002:a19:ef07:: with SMTP id n7mr22380lfh.482.1604026186911;
 Thu, 29 Oct 2020 19:49:46 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-3-elver@google.com>
In-Reply-To: <20201029131649.182037-3-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:19 +0100
Message-ID: <CAG48ez1n7FrRA8Djq5685KcUJp1YgW0qijtBYNm2c9ZqQ1M4rw@mail.gmail.com>
Subject: Re: [PATCH v6 2/9] x86, kfence: enable KFENCE for x86
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
 header.i=@google.com header.s=20161025 header.b="SUW+4c/G";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as
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
> KFENCE for the x86 architecture. In particular, this implements the
> required interface in <asm/kfence.h> for setting up the pool and
> providing helper functions for protecting and unprotecting pages.
>
> For x86, we need to ensure that the pool uses 4K pages, which is done
> using the set_memory_4k() helper function.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
[...]
> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
[...]
> @@ -725,6 +726,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
>         if (IS_ENABLED(CONFIG_EFI))
>                 efi_recover_from_page_fault(address);
>
> +       if (kfence_handle_page_fault(address))
> +               return;

We can also get to this point due to an attempt to execute a data
page. That's very unlikely (given that the same thing would also crash
if you tried to do it with normal heap memory, and KFENCE allocations
are extremely rare); but we might want to try to avoid handling such
faults as KFENCE faults, since KFENCE will assume that it has resolved
the fault and retry execution of the faulting instruction. Once kernel
protection keys are introduced, those might cause the same kind of
trouble.

So we might want to gate this on a check like "if ((error_code &
X86_PF_PROT) == 0)" (meaning "only handle the fault if the fault was
caused by no page being present", see enum x86_pf_error_code).


Unrelated sidenote: Since we're hooking after exception fixup
handling, the debug-only KFENCE_STRESS_TEST_FAULTS can probably still
cause some behavioral differences through spurious faults in places
like copy_user_enhanced_fast_string (where the exception table entries
are used even if the *kernel* pointer, not the user pointer, causes a
fault). But since KFENCE_STRESS_TEST_FAULTS is exclusively for KFENCE
development, the difference might not matter. And ordering them the
other way around definitely isn't possible, because the kernel relies
on being able to fixup OOB reads. So there probably isn't really
anything we can do better here; it's just something to keep in mind.
Maybe you can add a little warning to the help text for that Kconfig
entry that warns people about this?



> +
>  oops:
>         /*
>          * Oops. The kernel tried to access some bad page. We'll have to
> --
> 2.29.1.341.ge80a0c044ae-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1n7FrRA8Djq5685KcUJp1YgW0qijtBYNm2c9ZqQ1M4rw%40mail.gmail.com.
