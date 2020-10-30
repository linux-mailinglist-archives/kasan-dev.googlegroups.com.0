Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZU46D6AKGQEQ3DXZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D9AF2A0614
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 14:00:25 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id d5sf3785144qkg.16
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 06:00:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604062823; cv=pass;
        d=google.com; s=arc-20160816;
        b=gkyaMrqNO+7aPuVOIwhl9z2dn+P8PMAQcd40qYKF/y7CDyGKw9ctkZQWZtMhqQcjcA
         iSXFTuMKDLOQ8+VJqLTrs8Wsihe/4AgLwJXjXDgqF2pLucyDQAduP37VOsfcr2q87eT2
         H1xGYHm0GDfXt67bgW62EcLPZtYkJFovpNXrOqummMlbNjSL2bhxXB7IN0r2TuS/AvmS
         wTp4ZoFPGCSSsZ9elPMoNTKXUdmCjqUURBvSSYjmH8DtLbOk5juIIXBMsl2gVTWhGUQ2
         yqa55M40ZjOP2osQZHfpRqklq3Zg5kOJKuvN3yShiXi/4kVieQYZOPAuHnukr19gqyLx
         9zpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AHJg77v9KBIZJY+Bo/wAyxfMG3tXaYPgO7zVuNih6vI=;
        b=TI0lcuGQswEIIOWgE6eOmK9yVuBphwnS9RdcY12s9HbN+Zjnq2fRNeppsHbG7VmrJC
         xb/l9LyXoGY/QR/9T7jl4C6TvLpHzRtIizH8KG6LXtV/vqzOBlvU71NQQR/Tx04d+UOV
         Jp/u5qtJPKeHpcku3N/qCcjcJqJE6OX/+GhJzoYXe7sl2gLxuErmWzXOmVYTH9Xht4fC
         CPH/WIX0247mm3Vh5jISnTd3hmEyjLeDdzbCV66PHLpbCbcl8Bc7NWde74SkP5EVIGAL
         7gfgcV5wc5SBS0fR5LRP4xtWpl7heot3k7RNk6vZ9zq8iMgVBtiAMHCrDFxKBQNwudmx
         9xkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EcnjjxiP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHJg77v9KBIZJY+Bo/wAyxfMG3tXaYPgO7zVuNih6vI=;
        b=jDxGkCKB1XymC46K2qaMdfDm8TQZOh7h78KToJv7ySBJSLxcPbZWSU5OJPm/GvkIlD
         /6NYBgKPxgegsPrzkwjKaOHlGA/fzrUNkCeG+tgm1aVNkdxEEqAGoX3VICMjmIg9NhmK
         brgpt8xOIE3kbTX9uiU197tlKN+1mSyjqW4rZRj5l+77RBKlMeC7OLTxtpi21K7nCatl
         h2UQlOnofcV5rF9VmMtZra1aMqMv+Xf5TvKMvQjhjj43SNlMGTLTLKjSRvVTu9OqXSwE
         r/EawPcO7YH9ETSBVTSxchn/ejqeQ4kFClZaQY5FDEoWt2LwpwieJXg2GntVIHZjiLCF
         7j8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHJg77v9KBIZJY+Bo/wAyxfMG3tXaYPgO7zVuNih6vI=;
        b=FIqWnE/hCVktyjeyfrP2koCK0YNxe1J0AnjqlJmqAYFAm3mWRyacib89T/9gGxPsvt
         XUmmObgstpIMMAlXiL+Q2/4oBL9F3jGqyWF2HQQrCekf9pbIK2r1AIocdnIeBh+eyC2J
         dkUJN9ftFIcvpUS1UMCskSwWZqux6TzSZbkFqpiq1IPALBJTm+KGX7iEXGR0abygBJnF
         /SYpKPoFjuukYAuGj90+yXQvDz5Vbh39c+svGZ2kAG3PFVmCc5Eo9GarH8hLdO4Q9saq
         Fhu3SBqrQBr7HTH3v3tU5Cg04fc1fJcTLXXeNvo03/h9MnpQJziKTOWDWxNJBIRPeuFx
         Rebg==
X-Gm-Message-State: AOAM531PuRu7G6gbeM46qaZXhc/wzchLZdUN6vmqyzuQIixDZqDSfZ+1
	ZPWMIZUwP514SO+6NDL0Ai0=
X-Google-Smtp-Source: ABdhPJzD1/O5bJFrdA4dtBJRZDTkVViD1um3DQkCk2UNlz7sSVorPpr2yXqJi8/TzMY6viReXiLmEQ==
X-Received: by 2002:a37:2795:: with SMTP id n143mr2010168qkn.321.1604062823042;
        Fri, 30 Oct 2020 06:00:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:34b:: with SMTP id t11ls3068137qkm.4.gmail; Fri, 30
 Oct 2020 06:00:22 -0700 (PDT)
X-Received: by 2002:ae9:e314:: with SMTP id v20mr2000651qkf.93.1604062822574;
        Fri, 30 Oct 2020 06:00:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604062822; cv=none;
        d=google.com; s=arc-20160816;
        b=AHfLuHUom77QxHMRrcoMbZ6VzoMGLkMOmg2iu2iyE4CAN1t7GzXHJ2FsLMVrixaP5o
         6tWXLY/n1+/mthP4erweR+T7ZLvaxKA2pgG00B/gDO6itz0TltYr0QcGJrZfOR59x0DI
         IiyzUkHBiN7PvAQ6xNOmQFhO0AMoBaNuWPQuRDC5ZcSgD3ax+kN0jGwd34l4wOL3bah+
         sTu7ILXL9Ai4civJlrQWaqjW/6x4MxMXAL4HWWFvQuqKf0+PtVlqCzbzIV0PDNzixvUa
         rfy1k+2xrydqx/nDypcB+m9TLCB4cePvALGtEX1Au0zkkbk2qsUYskEcA/e9LZ0U7Vid
         /OYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6fvLoA2ACGsw9h6fUs2eRqYp5Vxv5mvJOqpZ7bS2dDQ=;
        b=a/ft8Zfg4G4EtO28+ImcFbLywqR6YgI0S26L+exaYsagpFNk+S7Y/CEA2RScLMokOw
         KQcU2ClpfH+k1VUipQ+i4SEcLts8sMrww4u0yTZCxYiW1F+j+64xfDGR6K9REtwVPrUv
         0L4Sg6FzgDjcaVtKWcvu8GD4zCjy4P6y1mW1uWoynZutiD+TyhEGeUOFUqXLf6da2nFq
         JD5mviAolRffPmlgSPx0FxA/w7sPfvHYoty6lKIb/+1X3efPVweS4usiSbKGL07JBCSG
         wlxXlIhvuBOQuOS8MW4PnE5YVh1N8/ZUP9+WUbvWrCO9RNceeS3ISM4epshd7EbehOA1
         1y9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EcnjjxiP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id z205si400165qkb.1.2020.10.30.06.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 06:00:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 32so5467579otm.3
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 06:00:22 -0700 (PDT)
X-Received: by 2002:a9d:34d:: with SMTP id 71mr1421371otv.251.1604062821578;
 Fri, 30 Oct 2020 06:00:21 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-3-elver@google.com>
 <CAG48ez1n7FrRA8Djq5685KcUJp1YgW0qijtBYNm2c9ZqQ1M4rw@mail.gmail.com>
In-Reply-To: <CAG48ez1n7FrRA8Djq5685KcUJp1YgW0qijtBYNm2c9ZqQ1M4rw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 14:00:09 +0100
Message-ID: <CANpmjNNBoiL2=JDD=vC5dB_TPW1Ybe5k7SqqhvUE2B7GmzRLyg@mail.gmail.com>
Subject: Re: [PATCH v6 2/9] x86, kfence: enable KFENCE for x86
To: Jann Horn <jannh@google.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EcnjjxiP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 30 Oct 2020 at 03:49, Jann Horn <jannh@google.com> wrote:
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the x86 architecture. In particular, this implements the
> > required interface in <asm/kfence.h> for setting up the pool and
> > providing helper functions for protecting and unprotecting pages.
> >
> > For x86, we need to ensure that the pool uses 4K pages, which is done
> > using the set_memory_4k() helper function.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> [...]
> > diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
> [...]
> > @@ -725,6 +726,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
> >         if (IS_ENABLED(CONFIG_EFI))
> >                 efi_recover_from_page_fault(address);
> >
> > +       if (kfence_handle_page_fault(address))
> > +               return;
>
> We can also get to this point due to an attempt to execute a data
> page. That's very unlikely (given that the same thing would also crash
> if you tried to do it with normal heap memory, and KFENCE allocations
> are extremely rare); but we might want to try to avoid handling such
> faults as KFENCE faults, since KFENCE will assume that it has resolved
> the fault and retry execution of the faulting instruction. Once kernel
> protection keys are introduced, those might cause the same kind of
> trouble.
>
> So we might want to gate this on a check like "if ((error_code &
> X86_PF_PROT) == 0)" (meaning "only handle the fault if the fault was
> caused by no page being present", see enum x86_pf_error_code).

Good point. Will fix in v7.

> Unrelated sidenote: Since we're hooking after exception fixup
> handling, the debug-only KFENCE_STRESS_TEST_FAULTS can probably still
> cause some behavioral differences through spurious faults in places
> like copy_user_enhanced_fast_string (where the exception table entries
> are used even if the *kernel* pointer, not the user pointer, causes a
> fault). But since KFENCE_STRESS_TEST_FAULTS is exclusively for KFENCE
> development, the difference might not matter. And ordering them the
> other way around definitely isn't possible, because the kernel relies
> on being able to fixup OOB reads. So there probably isn't really
> anything we can do better here; it's just something to keep in mind.
> Maybe you can add a little warning to the help text for that Kconfig
> entry that warns people about this?

Thanks for pointing it out, but that option really is *only* to stress
kfence with concurrent allocations/frees/page faults. If anybody
enables this option for anything other than testing kfence, it's their
own fault. ;-)
I'll try to add a generic note to the Kconfig entry, but what you
mention here seems quite x86-specific.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBoiL2%3DJDD%3DvC5dB_TPW1Ybe5k7SqqhvUE2B7GmzRLyg%40mail.gmail.com.
