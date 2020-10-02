Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBOM23P5QKGQESMM3LUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F453280D9E
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 08:48:26 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id v12sf190795wrm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 23:48:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601621305; cv=pass;
        d=google.com; s=arc-20160816;
        b=PBIWA8qIIAZJX711Tfh09NWeNBznCNfBBc89s3lIQflf9RbLstXPEfyGw3eLa/9O6q
         5hZw8GnJSf3mScM9BBfvJc3G0jbViVC16NjwM4xmn67CNCkJraD4CNsq3fiU3W3+mZWP
         8TWIA4cKNM0MsPiJnp5zQS8ABjp01lAjf0iLOHXQAyVlJRMMFxbOmCVw4lBZnA21fFxR
         Iuz65mZBGlEUVqSQtQoRm2pJvWGvr2tlzt6LJpMppotw0dLIn8C3ZHfzdknwH9rybVH3
         7Ki376tfvY6diR1vaL8jPaMqxhm06dmB8Ij86FQcAhCskBA9WktF3hQ5Ly70VWS5fup3
         moyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f8MvkLPXZhhlhHH4kFmQLEIQeleQi87/wDVYSQSetGE=;
        b=m22OVZ55JwM3hj8P0lDsfrvG4jn+261jG2m3uij+kA4mcFqv9NhbUGPGAIu8ax7nxd
         8iX+x6uFBZdQqbSaD9isNR0Bp+dFiWZfhZn6+JQeK9jW3+b/kohokY4pUKTbREwk9anv
         iWBTYuT3ukiHTUcyY7PXlTga9dyCn1wxj+zUr5O+tBilcapTG6j4lx6VuayzQSIlNZOU
         m3Y5K5VxEwKng5XoFDbWFdoivWQe3lx+rT3YGYlC2J/o8VX9gBZEj1ZIWFIZxO5m8Pp4
         PBBFkSIGuou2Op0ACRZebGByAQD2buhfbdokJMOJ0SEFDzvpHDrm3/VrrJ7N6glIumBt
         Hmqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFZ4SnEx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f8MvkLPXZhhlhHH4kFmQLEIQeleQi87/wDVYSQSetGE=;
        b=QJ38ukdwu/irA/sVroeXcMdXZNjqgX8r6fv9dqt384Qivcb5Y05ECr9W0Rx+l6ZGmF
         wb211rrscDCibvb/hYVIJn5n1nI6+99bv1fdnEcK4wnmOWqavtQqby1nQVRL9mW2rkKo
         kAQ1md/NAnMsgLIPI2HI6+rXeAPYQ7oW1bJVdYvp9l2UAK0xStL4vmOt+MerXObNOGzw
         i12CE8sUTABHOufyqL2jutTWPX65rHOy1qQl4x/L8gI90ogQFaISek7ZAC2TvLf42M1S
         6boumUgIJ2a43jQk+bziGK1cjyXDEBQxTLrFuhvgR6lR9WfWQSNPoiAIk9V59ldQRGs+
         IIZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f8MvkLPXZhhlhHH4kFmQLEIQeleQi87/wDVYSQSetGE=;
        b=aqeR/R+LY7WvVj9jr4nDMd+5xCw4NfchN9pJQP9+ODLADqRguoc0KKojGWfgkM5EZz
         UoQknOljkVr68rOBLRaMHWPlHIkYnVnVO8ObjsRE57xzNL8Ti1+uHmgo1QIN8KLKm5bp
         0GfEh6Ow8gxVrNPpeD+VcoSew57+gPdaX/6epOZJZpyzYwWr4ucYagLRfNzOLH1QfqhE
         0en+SB0r7QaCxeFu8ZSMooNlnWhff3FC9h6oQu730APfG7QEFTpywxU46zZSN+HvjV0Y
         gsXM300cKVA6EngL+1K8/GKOZJ1ceLQ9lVVuic1zL42jKtxWJh2/gbLRYo6u60i4dBsB
         hSug==
X-Gm-Message-State: AOAM532wiHCeFAPCj5ObNllvAM5GA/woR3VjPsZx+KNkow0+QkQUbruU
	je/SX4Z67bGKHAv5KIXjgoI=
X-Google-Smtp-Source: ABdhPJwyp65U0lGBabYDYHMRKg2VHeYt6qQFVBdPvmd/4p/A4aBUvGSQ2C5yrb3PJXc+pa5kRqJD8g==
X-Received: by 2002:adf:9504:: with SMTP id 4mr1225652wrs.27.1601621305835;
        Thu, 01 Oct 2020 23:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls279755wmi.3.gmail; Thu, 01 Oct
 2020 23:48:24 -0700 (PDT)
X-Received: by 2002:a1c:28a:: with SMTP id 132mr1132783wmc.144.1601621304894;
        Thu, 01 Oct 2020 23:48:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601621304; cv=none;
        d=google.com; s=arc-20160816;
        b=bRQ9tnDrWh0I1mjF4AttNIDwaFW4PsQd1p3j0dR40Cm8InGV0pTwInvf3ggQOUWKx2
         AsnfZjEuaWzMFteatq3MGRO/9Q2vY44/oWn260RuMTM/MkVLhEj88Jh1z5VUoB0ZUeoE
         SIuWzJpUTRZ8dSVnXs0bkdHYmKXlxe6ZHnbVIbe90FykwdXP+7X33K4+sedLrvhaZf9V
         oyVHopGNXvBJsJk4hsL+4MIFkoE5fPzv1S4WFP/dYvWNocgYBaR5mUPMF0IxFoGZ3CBp
         v5Adj/QgSRM92W1SY+IUmhccNnHkkRyohQH+01I8+2UeK7/JMp2sE0mUBvk+epcko2kl
         rc2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J8AL8yHl5XUf+oARcqfxDLAGYCbuXqngBj+IQF3uLUQ=;
        b=RPWwQZjwiRVd3CprcFaV3i34T0Mz3aP5fVkh5Vcsjw87pn/g9zIkdbF4SJn71gmP2U
         NFGqFIBbXmI5sPcE1a11p3X3tkBsSgXJFJaQ25TQBXFRtNfaPslcPjTVyNng7ZQ+xIf1
         yQaFHoGOoNe7HMJt8aE/FisDQhIj/ZIkzEAk2Z57FBLAXiegZBdYdU7ZhxaRIt412xLq
         WA9F53O8pzjmuHwUJo4OnYgU8eq28qGZeZ0ARYlddAxd3se3rrmlFGldP9o0LugVagJ8
         MHbkERYMIScryqiTN2K9HXVDCNJSVHbQ2/Cd66cakq4y1vj+24WKlwmiLJ9h2gP4gtb/
         7wxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFZ4SnEx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id b1si11616wmj.1.2020.10.01.23.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 23:48:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id lo4so422105ejb.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 23:48:24 -0700 (PDT)
X-Received: by 2002:a17:906:394:: with SMTP id b20mr727889eja.513.1601621304442;
 Thu, 01 Oct 2020 23:48:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-4-elver@google.com>
In-Reply-To: <20200929133814.2834621-4-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 08:47:57 +0200
Message-ID: <CAG48ez1VNQo2HZSDDxUqtM4w63MmQsDc4SH0xLw92E6vXaPWrg@mail.gmail.com>
Subject: Re: [PATCH v4 03/11] arm64, kfence: enable KFENCE for ARM64
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GFZ4SnEx;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as
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

On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>. Currently, the arm64 version does
> not yet use a statically allocated memory pool, at the cost of a pointer
> load for each is_kfence_address().
[...]
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
[...]
> +static inline bool arch_kfence_initialize_pool(void)
> +{
> +       const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
> +       struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
> +
> +       if (!pages)
> +               return false;
> +
> +       __kfence_pool = page_address(pages);
> +       return true;
> +}

If you're going to do "virt_to_page(meta->addr)->slab_cache = cache;"
on these pages in kfence_guarded_alloc(), and pass them into kfree(),
you'd better mark these pages as non-compound - something like
alloc_pages_exact() or split_page() may help. Otherwise, I think when
SLUB's kfree() does virt_to_head_page() right at the start, that will
return a pointer to the first page of the entire __kfence_pool, and
then when it loads page->slab_cache, it gets some random cache and
stuff blows up. Kinda surprising that you haven't run into that during
your testing, maybe I'm missing something...

Also, this kinda feels like it should be the "generic" version of
arch_kfence_initialize_pool() and live in mm/kfence/core.c ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1VNQo2HZSDDxUqtM4w63MmQsDc4SH0xLw92E6vXaPWrg%40mail.gmail.com.
