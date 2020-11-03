Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBH5OQ76QKGQERMNIIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 59F652A59EA
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 23:18:08 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id f28sf3032994lfq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 14:18:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604441888; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q7Z+gcLQWu4pn883ECEAZEEXpgw3O6e1beIoURF0jMJNx2NpV0j/qvJ+KoYrG+oJuT
         AoxNjgB1AmpIrHBLZbshdttF8LNDcW7nojBNYQhJWyL+NN1WO2Ebk+VnB37TUvPbGxgR
         EvT0EIFa7rHuloArL5ku0kIa/kcESclerZLcTJPreUsIMNxwwgMcPXmTt3wdA48bOQar
         B4DfSbV5H45MOYo2rZzhwZODf7+wU5iky15hr4WHexis+MtISguuFftbG8VKCxf1V2UN
         L65rQljNrppm4J55KzIGtwicPpYRXxoRFpIddh0PK85Pv13yozAcAySuzTSUweqvtFpL
         CTqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bWRsRWvaP0tjQxyhjXcLQGROlRoCnlOiuchJg6YSrlc=;
        b=n3jCntly7khavyD+BQrtZxitVI/kOLGcBg7iD2hw+HG1+YnUmPwc3CgRNVQccMpW2I
         4M8LxOxyEi5sU83E8mS/V87Q2XN2TG8M9dOqdBaooMbAeureAhv4uUT2k/YFfYaVvUpL
         PDrAP3Vvb+HgtCsmqEbjdT8NK/UsMOaOXIEyc9ST4QdzHi5ASgHemPUCtejJpJ3ylAcC
         7D1h3XKooUEi/2Rg7jGMM8QOOT5EXhj4U5QLpTa7LRHKhoSEr84FBCVIrKyla8Lwa23y
         Cg/s10gvNb7Y4jEx2k3M8qEQIJweg04Xpg648JfrmNarGteZZJIFK7Z8fec6BynBrili
         tEBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e64Bz7BE;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bWRsRWvaP0tjQxyhjXcLQGROlRoCnlOiuchJg6YSrlc=;
        b=Qw5m+jue96XTPUMmVC+yoqq3RB247LhzF8BPPXXU/WdbKVmyXL3U66Y2ITH+njtICm
         yami37bdhkgfTQKy72wP6Pwaq7S6mARieVBWnsjLO9jiGLeuPqLp9YMSSclW7ELoydy6
         jGZG7GS7sGvHoW6iM8ex3nVPzrWTRpxxNkCviQjGh/dIJOZ25oihs5CZt5xGuoHFoyYk
         1LSkC3vH3dBxxXYI85yl/5RgRMwIUqrU8OciEFo9rIWHE7Va+A5T8Wae1r2d++Z8YM3v
         Xc2ju8SHuHgjtXuYuUNQ/0u+MLKvAmW5NQE167Rw2qNqsSi5tb2xYT9/3fM8ekpFIx/Q
         sM+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bWRsRWvaP0tjQxyhjXcLQGROlRoCnlOiuchJg6YSrlc=;
        b=QMY1S8dINU5sf4Dcye6m6RAl6KbqA/QDWQC3zTx1PBj8WcKhJwVFi6dyHgDItkW0Ek
         trQvOPQjg2yy3ot9XVcJMwtLwK64EO9Wfjd44fbz/2ipaZ9EC56mfSHuoFunjDU9qJgC
         B17yX5VYgcdAvqnlFjK3bzMrqnNgzjR7exNMbw5FabFzljezm7UhEa5HKX/vQNTsRWM8
         ntVlRq+HtxpWZeq1OyszdVIsrbYsx+ynuENsQMqCCA96mmS53OncWdJAnStDreqfpg3c
         xrsKAnuwfk1JSEbq2q1gipNQT+PeGfVGeSfLHvyw6X6g+Sz9vMKEHi3Rhce6obf02Sie
         gGmA==
X-Gm-Message-State: AOAM530bVP0qa19QfY5n82lIKlVvF1EbZiNxM70kbmxijjxhZCl7QfwH
	qmoN1QTCb7RzlFHoyY8Maj0=
X-Google-Smtp-Source: ABdhPJzr7+TNuP0CdArarYJ6IAA4s43gbrJuBd16kb/IftrdJJ840m8JWPu3qvg7bqlI82kgSujFrw==
X-Received: by 2002:ac2:58d8:: with SMTP id u24mr8122456lfo.415.1604441887960;
        Tue, 03 Nov 2020 14:18:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f48:: with SMTP id v8ls46304ljk.9.gmail; Tue, 03 Nov
 2020 14:18:07 -0800 (PST)
X-Received: by 2002:a2e:9747:: with SMTP id f7mr10167560ljj.81.1604441886916;
        Tue, 03 Nov 2020 14:18:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604441886; cv=none;
        d=google.com; s=arc-20160816;
        b=x8Y0QnV+867sMThdMDwKZDH5olIzOITrGXk/9gtlspJ1/w+v1DQGQZtSn+jkdxKWQg
         ZeBdjzlXbTAFRm3XCG6cur6YlE3kIynNvicS3Uqjwkhovurg/lgo+CeflnExEZjD4TQr
         N/1cseuUZSNCxnOq/J+GxdziUP2O8ANq7/Rn/gENxm8g0669cgf6MLPwXgDYzaEXgwkn
         uSxL7scmCDezuo0TMoKeIihgIG1rFoaMUiVnAqyo2UvXS4lGUaNeiunm+v5tZusq4GTJ
         6jntwQrkk2bfz2ScXtE4MFvUUEevDJ+sLBP292IUEJuMjyLT2Jfib7rpqnvhnn16iPC5
         YTRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ZRbguQ1x9dT0hAvOuP/VOG3YF2apB5kK77xWV7GZj8=;
        b=OYyq0q1Qe6tL+qHef1kkLbbsKwBdp5mnRUybfJ8S6lZVIthYWM93mz++4I2lpw9zsp
         iNQFnbXBNoBUMFqpLYtcpprnlPWr9NzBW0i+8YSTp9T4U6PR/A6e+ItaTPKD7ldZjbk2
         o7zTUqxbj9k89QU19DJ/MuJpaRL6ybG3fxmR/whnHHGvt8ZwOk9vm/1eirgSVwnW0AOx
         TAhSX4fyfK9IA9CaGL1y6/h6CQeGheDpvwEqyHpGNqJpLH9Oh1Cgv04axgOFUxFCZlzn
         5SP8CN7Erze/ydLs02BD9vLpbdTZ/Wf1q+ggCANtVDDRb9wZCZmR+EAdvlxc7O1gF/mD
         eJnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e64Bz7BE;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id n5si5731lji.5.2020.11.03.14.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 14:18:06 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id i6so24427595lfd.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 14:18:06 -0800 (PST)
X-Received: by 2002:a19:83c1:: with SMTP id f184mr7817703lfd.97.1604441886422;
 Tue, 03 Nov 2020 14:18:06 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-9-elver@google.com>
In-Reply-To: <20201103175841.3495947-9-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 23:17:39 +0100
Message-ID: <CAG48ez0040+=Grn6nELgPfV4VntStm8iXTC62+ouiF29=9K_rg@mail.gmail.com>
Subject: Re: [PATCH v7 8/9] kfence: add test suite
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
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
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
 header.i=@google.com header.s=20161025 header.b=e64Bz7BE;       spf=pass
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

On Tue, Nov 3, 2020 at 6:59 PM Marco Elver <elver@google.com> wrote:
> Add KFENCE test suite, testing various error detection scenarios. Makes
> use of KUnit for test organization. Since KFENCE's interface to obtain
> error reports is via the console, the test verifies that KFENCE outputs
> expected reports to the console.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0040%2B%3DGrn6nELgPfV4VntStm8iXTC62%2BouiF29%3D9K_rg%40mail.gmail.com.
