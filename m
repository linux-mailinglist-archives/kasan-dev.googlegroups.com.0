Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBZ765X6AKGQEUJHNUGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E512629FBA9
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:15 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id d19sf791416lfl.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026215; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKKsb3pmZAq0+OTbJHJ3BIciw2Cn0spiwbH1+ApZ71oDJg5Nz6hAx6b8dCtS7KBIsr
         ZH5Laml6+MJmEf1m+gIktG6wQUWbfdUq1AR5Qosd0TyuNeQ8f9iX2jfWx0B7AM/ZEGsQ
         3NRRJrAEHXSl9mFCBr8W6aHzAzNI2Ss48/o/gXK4VHpMxi1OK4QSBJmcdRWxFR+EI8l3
         egk7PENjN1GzhnmtQI2GQE1vKBBrMbeJOFaeW3J0fwaaOwlHndnBwGFst7q71HFKw4SD
         PlO0WX6eDi37lZ3EcJVI62dCfl28RMU3V/a+ftcdPYe11GffAam4p5+RO+cSkXTmp+0Q
         W4qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=08JtrWDhUAU13RuLwm7eNsBYS2bvJP3Z17sBPR75gJc=;
        b=hL7sWB2qrf6wsLLckZzig/kaZGOG97YnNDD8BQIbgepnzNjoWSRVIw9rALTy3geqYp
         hGvWsO4L1iUyfjUYzicTgX7MpxtYuRFf08oSEhtQusi3PfVzB4ZbopkBGx8h6JPf51pz
         tI6ml5p0XPVfXQv4+98UFowHkZ7fNpJZfKucYjAHqaHtp1VTR0KeL3e/0aTmfMUgiMl3
         0VkY5ll2qx8cV5FOAMDkzKhOa/kwioIVb+3OGxjgKG0s8qcWaPG/ffeIvmvFiL7IY69T
         84c5i8YKlqbbYBBL9Sztv+jLScG00Axji1PGhFufeD/wBz9Mdjw+0fdzWLxiHs5rf5Z1
         rPXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=faQ03KFX;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=08JtrWDhUAU13RuLwm7eNsBYS2bvJP3Z17sBPR75gJc=;
        b=eBUtTPE+OxZjirbrIGxTC9R45HEAo3+fcf2wQX2qgFyxUF7ncfltFrX4CYqnhf6Op5
         62LWkSzRaLhHrEzntno6G4Jk/HvcswUp34muPh5mGxFyEq1vRngFJotuAlkjygB1fsHH
         Ce/D8gu7Ttq1F2oOH6DDmkkDt43WjACMxNoNPguXLQz1EJoLYIbrTfK5GNAXFnL3k3xd
         JbU/EWnxOh8pULFxTRPRj/iZfwG1SImDZJL/IAx5t3yZltOO/mG4/9TdQBOT4YmJOVfK
         /o88eBUGoIIIO+nuDsbmTk8W89eSRGtOrZvMtVu7NQIP4wqTrcaF5h6HW7Z5zCnTSZtI
         88+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=08JtrWDhUAU13RuLwm7eNsBYS2bvJP3Z17sBPR75gJc=;
        b=flIr4cIRUB1kWmqvPE/L9TbO+EcrKm7nTeejRAv8wA+oBhxXZHK45d+sCIXIP8oRnA
         HyGsjpfJdrJO8arUPIsUm6eFMDiUZBgeH4T/xwaSjkl2ljly5vFYJmVpT0XAm1nPB1Qj
         OM2U7djmQceHgUWWw7mVPbpu66uzItjwMxX4nyTMzlarI4Y9qiRmqai8a/P9lc2rGAWr
         EFwUhV8iCV2NrADfL75YQ9NMH+dIUxM7DYQBIit366FzWuUjgzYOrr45BoEs1HnHFzxx
         /kvRGDyLQJkIieroQovJ2N/SO7yRhLlsC2HKRb8XD1I9AHDh8wyjpRWkDlJB4ESdYcZT
         mquQ==
X-Gm-Message-State: AOAM531kGJBiANeDbcsdBiEC24InQoy0XdDXJRPlSLCXg/uOwRwL138S
	Ebo7lFzSmU0B5u5w8YuasWQ=
X-Google-Smtp-Source: ABdhPJypUjKMP9Fzairp4pIEspvf5AT2fxGIIR1Hvlf+UFjlLmHi/AZGrOgh3YRQheeX0zBp5Vi48Q==
X-Received: by 2002:a2e:9951:: with SMTP id r17mr101338ljj.37.1604026215486;
        Thu, 29 Oct 2020 19:50:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2919492lff.1.gmail; Thu, 29 Oct
 2020 19:50:14 -0700 (PDT)
X-Received: by 2002:ac2:495e:: with SMTP id o30mr32051lfi.76.1604026214479;
        Thu, 29 Oct 2020 19:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026214; cv=none;
        d=google.com; s=arc-20160816;
        b=lBecuif1OR/70NlJaAykbkbGwaEOEWZFvJkPPw3FEhoFgs8n1pvD8pa6LVXgWkBjex
         q5d6w55y6XYDPoDt/zttaE7NZPcpWvl160g7rLXsGhNFRv/g8gryiRXmiKkmJlI7tJlL
         KlRH0rytXknpetYUawR+M78OJLpbmi6xL1bRGJwnVdsIlYjHUNuER0Dt/X5G2o3Da1gI
         D+89s3cwBuVj4+zGscmVQCIH27ODPglRtLbekcWD+C8uMbzw8EPqoE4TiP273DHsVxYi
         z0rCwN9LuulcU3dvSoE7ug3CEAz7Kd38VGLRF5jz1DuE3YKY4yHHAqSyxHxmt3MCPmAC
         ypRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=29/mvfnx5ijMJBRqUvdSEy/Y/vTbwUpvdNL7Ey86vSQ=;
        b=vVPISgVUhzBLa9HudFsmPf0Y0yG7pnvrygVHsoX47+kPzMiverhySHIzgIbRI/e6sE
         vMWYSAJ2NKGJAqLE9hz7TLlA/5fALIwx85oBp/xAdh2JG1YDD0ggtMHTJTuduzI3rslz
         tow+DWU45Umgz16VyNSx7ta5UX1UCYv+1aQpHXFt986R0383uPuJXS+5+BR+WRW62m+h
         NQZ3xd4/nkivfiXa/AQRFEG/nBndEoAfFA3duJ/a0Ay+ns8W6sS0WrgPBIaxkCMWo4Nm
         oMyu4kDG9Rsiq1LSSCGPNWRMRbI7zenkTfSPW0iwQB8UuwSX5bMLA1p3ZChI1cNBRDh1
         g8xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=faQ03KFX;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k63si118436lfd.0.2020.10.29.19.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id i2so5361182ljg.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:50:14 -0700 (PDT)
X-Received: by 2002:a2e:9f13:: with SMTP id u19mr101336ljk.160.1604026214056;
 Thu, 29 Oct 2020 19:50:14 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-7-elver@google.com>
In-Reply-To: <20201029131649.182037-7-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:47 +0100
Message-ID: <CAG48ez0N5iKCmg-JEwZ2oKw3zUA=5EdsL0CMi6biwLbtqFXqCA@mail.gmail.com>
Subject: Re: [PATCH v6 6/9] kfence, kasan: make KFENCE compatible with KASAN
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
 header.i=@google.com header.s=20161025 header.b=faQ03KFX;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as
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
> We make KFENCE compatible with KASAN for testing KFENCE itself. In
> particular, KASAN helps to catch any potential corruptions to KFENCE
> state, or other corruptions that may be a result of freepointer
> corruptions in the main allocators.
>
> To indicate that the combination of the two is generally discouraged,
> CONFIG_EXPERT=y should be set. It also gives us the nice property that
> KFENCE will be build-tested by allyesconfig builds.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

with one nit:

[...]
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
[...]
> @@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
>          */
>         address = reset_tag(address);
>
> +       /*
> +        * We may be called from SL*B internals, such as ksize(): with a size
> +        * not a multiple of machine-word size, avoid poisoning the invalid
> +        * portion of the word for KFENCE memory.
> +        */
> +       if (is_kfence_address(address))
> +               return;

It might be helpful if you could add a comment that explains that
kasan_poison_object_data() does not need a similar guard because
kasan_poison_object_data() is always paired with
kasan_unpoison_object_data() - that threw me off a bit at first.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0N5iKCmg-JEwZ2oKw3zUA%3D5EdsL0CMi6biwLbtqFXqCA%40mail.gmail.com.
