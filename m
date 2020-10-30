Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBTG76D6AKGQETCGMOHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B0BA2A09A6
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:22:53 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id v5sf2809443wrr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:22:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604071373; cv=pass;
        d=google.com; s=arc-20160816;
        b=YKt+SzgS/kDneQHCiI2WsXaekJHGF/4+nWEU6AzmdRmyNY9oUOheL0Cs/Mgxa90PDs
         fwAnVfg5MQGrEIrXmbJHZOQ806pQVVWJwLewRVixLBiWOi2XjNKT5faFlOLuVhOnOcap
         GrtwwwwxwNiFHHEYNAPYvEUQFdYYGh00sV7+hFBRcFxwtV370kX4Auv/o5fU58bBC11T
         2caNut099yg9Uhb97e5mAMh4X0pTAEoClwqPmudH0597UhiCxJ6l86ORCEe6nU5B6r79
         q/P0Wj0AbciQKjkd75MCjh1LcjtZt4GRUSMkmclMYvRJ5eemNDoFcKOXLvnYlIB9Av/m
         ejlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6F4haVsgUW3ChG2j2E0uyj6S02a5vH5m1QRQ0iRF4Ig=;
        b=P6C7mVxwwXPDXk6djZ5FjZoOUdSlyo8sEIe3cigm9l+evGgUYrpUvTweno3TyPlmwa
         Sm+0+itEEB0PFkUeA1JX+p58QMW2QGwKJpfOtBU6iHycSDJZjaAoaZIgNkOyf62xxgXx
         tpe4XYgZMzRQ1QJ3tKCnaqhOKIr7tsoJzxxy63v8uveP99YXZ0d32zjpwIC3NL47W+6A
         MD345Vq34oDfts9+FbLLZ738h3S9JD1ewTwMZ1tDqIvpAinIpTOMf+CUa3NcxPRDmvHr
         9U1jnbPmCGa9dQq3V2nIOxlPibf2pdMwBRbbkNSTEIMYqFhUluVAy9Sm8rVXPXdOdgYp
         OvzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU+xx2bx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6F4haVsgUW3ChG2j2E0uyj6S02a5vH5m1QRQ0iRF4Ig=;
        b=YzUdeyvfffm9zxo8hmIzZMfexk4ppIQqo2sElOkfHtKQoswO1v2GddEf2P4ek0tvZN
         m3zEvV66InZJ50AyRVGNKzeXSsn6+JN4N9ZnmZExRqHiWklGnNjQGinYiR99sl9CH+cw
         b/3iVvOCoAF+Bhkkh2Y0eC+8++y/eLEpgZulPfMV52mf6aNM5o9XPAStPHviWe91MZ37
         z/vSBRoovNVkrMmgKwDk4UjiDIQb4Apf5ObLEoj/q/iTYcDrnNETN8GYEIC7DtU7rlm4
         a46eoUq2jLhLso2llv3x0pc+XuL2/M1hc1ukSb7OWvXwbwDDtIV6q6VHYw6YS+dRcNN5
         uYgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6F4haVsgUW3ChG2j2E0uyj6S02a5vH5m1QRQ0iRF4Ig=;
        b=P6no9UUnARAfZlNJZ4ObaR/RS1FcRYEVljH7ZoCqPEWEJObR+Mnk0seHCoypWiyJi4
         UHGanAID6RRwQ6yw/qzHBQzk1fLqhy9iRjHzKd8rqmWQkxyYICVo9lExWEiBllDsgSSS
         vTcLgwd+9A9bicSZSh110BtDUKGYmiFO19aUJq08am+y0pIHs/5gP+6PfnakvoZlE0dl
         1YpJ9OAQ5npcZncdkyR0ot31YZWzQGEQiwbrneyyaRmRB5v2DT52a0JbIKCYClH9s+UQ
         8WDureJLdownjm7BdUcDYTddD0MoebFWebmI1coprm//dPhHm6Rl6QZbQ2K++u38r9pj
         r8Cg==
X-Gm-Message-State: AOAM53263pFkwWBWvqQPt6m4ChAPVINez1VsAm9Kz8z2G5A+FJQeZhYq
	XN0XjU+c+q8qzkmhTrB+zbU=
X-Google-Smtp-Source: ABdhPJzCLebhbUupcr5v6OPDMwLCnMlzwnwkye/JFRp2X7vZal9X9NOOy8G5z6xzOxeDVmxxx7HBFw==
X-Received: by 2002:a1c:f20d:: with SMTP id s13mr3429335wmc.156.1604071372858;
        Fri, 30 Oct 2020 08:22:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls2194457wrj.0.gmail; Fri, 30 Oct
 2020 08:22:52 -0700 (PDT)
X-Received: by 2002:adf:9502:: with SMTP id 2mr1705111wrs.5.1604071371983;
        Fri, 30 Oct 2020 08:22:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604071371; cv=none;
        d=google.com; s=arc-20160816;
        b=gy/kE7omh2dgeNCV/opdZhbuWtuXJibnmpaiipLsVEgglpiWRFgQBycOeVJe5kxb39
         JCrAOB+BMRultpetgbwvlEXCjmdlzfQw/zOXt+Wn5A2QmfeDfjjL9GFAmeqRNPn1GR7l
         UkI7MuTm+E6Vy2Vl4LqeI8a9PSYo15iTSyf4JEW6IFO7EPYVrHiq4TWgE0APktqv5iv2
         GkgBAzWBPTAepKP7IRHYyzQSsxf/qT6QqGkCLk2/tBYX3tI5ubYe2x/OdeVwuvs6TdbX
         ShxfX2v0j2922kpYNFxVKD+7SKbnZIRYN2rHvcGzQgWbb9P+vFx7ZX2sc+whvVkcHxtA
         FvMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5sSkbnbDNPQyj7tIyOHf0OZ0EnyY+U+Tr7Q/pQTsliQ=;
        b=of1JndLCf+cdHLC+T8Vqz/nbraYdVRkjro1UMSCFEq6EYR1LRYHCPJq7Sv3rBNGvB2
         Z2vVS76B/ZqZFPFUauSTaIREpahrNArcY4A1E2sqOvty15D/byIxalgG6PstQpW3+kjC
         B4pJcUskeUuB9eXQaKh/DSf4UvVm2ER4bZlqWb9uaba3muPKOEgxaRFPeapWsY6bkmMC
         DP8Nri/u0kvij0Q3LhVPR+lWioatmrImB+mI3dxr44I/LRMKhGzFo3TT0AuyQszrvUWn
         UFC9Yxytsv7rmcFmndsz+MVLpFufes7r+Y5JqY1fZftUK/Kwiqz8h//LMRse9j/6oX8S
         dL8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wU+xx2bx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id 14si138784wmf.4.2020.10.30.08.22.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:22:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id b1so8314932lfp.11
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:22:51 -0700 (PDT)
X-Received: by 2002:a05:6512:51a:: with SMTP id o26mr1098326lfb.381.1604071371166;
 Fri, 30 Oct 2020 08:22:51 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-3-elver@google.com>
 <CAG48ez1n7FrRA8Djq5685KcUJp1YgW0qijtBYNm2c9ZqQ1M4rw@mail.gmail.com> <CANpmjNNBoiL2=JDD=vC5dB_TPW1Ybe5k7SqqhvUE2B7GmzRLyg@mail.gmail.com>
In-Reply-To: <CANpmjNNBoiL2=JDD=vC5dB_TPW1Ybe5k7SqqhvUE2B7GmzRLyg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:22:24 +0100
Message-ID: <CAG48ez1=uad2yMeffArw7Nem3Hea3pnL9rqAFsB7fFzBd+4Hcw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=wU+xx2bx;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as
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

On Fri, Oct 30, 2020 at 2:00 PM Marco Elver <elver@google.com> wrote:
> On Fri, 30 Oct 2020 at 03:49, Jann Horn <jannh@google.com> wrote:
> > On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > > Add architecture specific implementation details for KFENCE and enable
> > > KFENCE for the x86 architecture. In particular, this implements the
> > > required interface in <asm/kfence.h> for setting up the pool and
> > > providing helper functions for protecting and unprotecting pages.
> > >
> > > For x86, we need to ensure that the pool uses 4K pages, which is done
> > > using the set_memory_4k() helper function.
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > Co-developed-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > [...]
> > > diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
> > [...]
> > > @@ -725,6 +726,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
> > >         if (IS_ENABLED(CONFIG_EFI))
> > >                 efi_recover_from_page_fault(address);
> > >
> > > +       if (kfence_handle_page_fault(address))
> > > +               return;
[...]
> > Unrelated sidenote: Since we're hooking after exception fixup
> > handling, the debug-only KFENCE_STRESS_TEST_FAULTS can probably still
> > cause some behavioral differences through spurious faults in places
> > like copy_user_enhanced_fast_string (where the exception table entries
> > are used even if the *kernel* pointer, not the user pointer, causes a
> > fault). But since KFENCE_STRESS_TEST_FAULTS is exclusively for KFENCE
> > development, the difference might not matter. And ordering them the
> > other way around definitely isn't possible, because the kernel relies
> > on being able to fixup OOB reads. So there probably isn't really
> > anything we can do better here; it's just something to keep in mind.
> > Maybe you can add a little warning to the help text for that Kconfig
> > entry that warns people about this?
>
> Thanks for pointing it out, but that option really is *only* to stress
> kfence with concurrent allocations/frees/page faults. If anybody
> enables this option for anything other than testing kfence, it's their
> own fault. ;-)

Sounds fair. :P

> I'll try to add a generic note to the Kconfig entry, but what you
> mention here seems quite x86-specific.

(FWIW, I think it could currently also happen on arm64 in the rare
cases where KERNEL_DS is used. But luckily Christoph Hellwig has
already gotten rid of most places that did that.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1%3Duad2yMeffArw7Nem3Hea3pnL9rqAFsB7fFzBd%2B4Hcw%40mail.gmail.com.
