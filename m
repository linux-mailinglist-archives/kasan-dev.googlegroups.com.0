Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV7O6D6AKGQEIDQXMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D81792A0A75
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:55:04 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id c16sf4952323pgn.3
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:55:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604073303; cv=pass;
        d=google.com; s=arc-20160816;
        b=exVW857iVxL0OkvfNDvF73x0DxaEhSXXn+ByvWOtWnsFwulBdwPPJ/1cSMZUEBlF2A
         Gd3uezDH53BGM9J07Jq9ruIeljLl/cXK/PyhUiPgT8vhuaa9lH/4FAIHlBhyodwG30NN
         lkIW5TgqHsWZOvimQ6wQhiVE50e+2pa+NvV4hv4gVc8D44Ectt5mfUrWpl8K3RY6u9rv
         9YwHRLtfJLDDHpSyPp4E31DU+IT29hYBNBXJw0RauBR8XAfdBXzRIXjlPgOcl4fPZ8xx
         DKuuSQIURdOMcokgcmV9FYQQMLXt4bzOiLugY4IzTOdSVADZpZExbG2NDl6HrpY/6Gpn
         VmQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QW+ZjCu600sMuJHXEDDmAGiRSa4W36MlHENLiobuM/Q=;
        b=TeMqJ1m/NbLmdlmPUyIfewfTFomw6gG7vCim9rLR5T2dGm4ptFW5/M4jgR9zRPd5jC
         rAH6SqXPoz2KSgkukN9PpFLhK204L/MOb9COqbfP+9NdHppIN3HLQRg3W8VRv+g3kTbq
         1eGhKUcgQfdyCnH6A8aRQBPmivJonJp5CgYJ0cHbvNi+QUb+cGt3BVBRhw8qAPNgwtqR
         zcm/0Dwdda5FF/siXnRHFBznAw2y79AZR+54aAaL6HkvjG3OtD/eRtxAXyLwW+v+xDZq
         gvlPTm4WUER+JldpCFkTUaonVvp8QJ2hU7aoX00AV5RrPD7haWcBzJoHGzx5I05uZG9y
         WH5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K0Bt4tbR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW+ZjCu600sMuJHXEDDmAGiRSa4W36MlHENLiobuM/Q=;
        b=LCeCd5q+w5F55O3XJE8GjhdfpoG/SoErtt3t2yTIXjJf3f28WY5tLAnRgVlHet9zLu
         1tci8X3gxcDxdvugSOmMg/9PTlyvJr4KV556CDTTcvDblULKmyhXIZWAq31glWfe0AdU
         F6/HRFppKKwGX6WU5T9D+6GjZbzJCbLnqv6c4St30PP4J2gy7E5cjd9tLafz3Ji0iJgM
         IF17b5nNzCZZg7Q9izU3ZuVYJPIhCShtkKk6fbiLjlyZjiEqzDaRLJGN5bHe9M1RnB01
         ELJew+atl0TC7AzJ6Y2l5jr7EEXD2ia9lz+cV28tFhJxIydWWULD8SR6vF1Vt7LkWvSQ
         AgTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW+ZjCu600sMuJHXEDDmAGiRSa4W36MlHENLiobuM/Q=;
        b=IfR9U4wJ+OBeqKbN3IV/ED8WJaYmetbwNMPNfyix7p0uW/Z0AS2fYIBqyTXV8+g3Rg
         JRueMCp/d1R44wgXEA/RVN7b0+PGB0dd5qoBLAFd6cVxpUIfiDHoipBBceyBox5GKE4a
         zVMC450EJtSib82PwHf8He8jpmg0er6RdbwzZmBfrRp/uE7MTGwq4tCjngPNNEXgs5Cd
         Xgq1Mnkh9rIGzSo86de6zm6UygvdwvVE6kcqggV+lqErf1IbprdbR9XABP7aci9QKrWX
         fVOp4XWfBLLCb8/P8hYFgsfC9xgDfdMfWFMoYJRJH/1Vmg5nJXyBHtmRBXipmWBQvOyn
         j4/w==
X-Gm-Message-State: AOAM530/hoavOSPO/44kWq8Lo+qG+CKtClUavhiYznC89MF4vzf4WMnI
	9Sv3+WpgpFHixvghc/J69oo=
X-Google-Smtp-Source: ABdhPJz1sx128U+B/b635vGKDHnfT9zYrQppXbSfvQwsKZY6j3lmgvI5kBXKomwmQiIZycD5fA4Ahg==
X-Received: by 2002:a17:902:7004:b029:d6:489b:6657 with SMTP id y4-20020a1709027004b02900d6489b6657mr9547255plk.20.1604073303615;
        Fri, 30 Oct 2020 08:55:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:d4:: with SMTP id 203ls2455090pfa.7.gmail; Fri, 30 Oct
 2020 08:55:03 -0700 (PDT)
X-Received: by 2002:aa7:83c2:0:b029:156:5ece:98b6 with SMTP id j2-20020aa783c20000b02901565ece98b6mr9729719pfn.4.1604073303006;
        Fri, 30 Oct 2020 08:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604073303; cv=none;
        d=google.com; s=arc-20160816;
        b=BoUBKCCPuorQkd5LjXovwx50lf6smxZ7S52qslHrD2LUULVoaxWZVQxZlvF4fLAi2V
         XlK4xf8V0vcpYm/y89TxT96KQStpeiY7aJB28Z3ZEWG8xwDjA/t+0u7ObPudem1MuMfa
         C+bD9MtBMcxsEl7oboCPmnTKv2+bT3H0jIMzSry4NKpIGM/gkyC34hyB3h+JXF8slw1X
         dd0InxmnjfkihzFWIdxW9QRXVOLCmbb9sJW1ptdeXuabYqiHsTh6PIwHLbTTTrmWTncM
         NGRM3wWXTiHAULWLfoVfXkZ6wuEbr1eCdcLngi+wtj+F1FUVKldpIbzaKiip50j1nvGt
         F6vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sCugon9AoPEJ8csYK/QZPsPZOpWR2wJLxLfUDJUrNWA=;
        b=VEGXH/eKuC+/1+lhsx1yagcmU0BvglLTcmoFxDH7V+tdvWrZ57CDzQzsHDpA9fLCsd
         64Vax05ULnVvDHx9E85w52zMNhv0xf+63zLVAAhw+ignrasytCIh7SaPmV//2JqJkFd1
         2hUGB2+OMcilKckY6FeVGzF+TowCaa1664jmms9YPXpSqH+4cIZx+qckQDXJRg8sozxc
         ocEJoi2fNGbDbE4wm4TDV9c3xQXwlUqW+zGsKP0Dyv0t2f9+QplaRT9ouKXlk+INwS82
         5c3uE+1GjU4AksoAqDWgXYRRXj2jvFvPSdorkzsACtRagKSiLjIuCeFzm5veUmL3Zcny
         fz1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K0Bt4tbR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id m62si530604pgm.2.2020.10.30.08.55.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:55:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id m26so5918705otk.11
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:55:02 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr2236333otn.233.1604073302210;
 Fri, 30 Oct 2020 08:55:02 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-4-elver@google.com>
 <20201030154745.GD50718@C02TD0UTHF1T.local>
In-Reply-To: <20201030154745.GD50718@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:54:50 +0100
Message-ID: <CANpmjNNko4pYa3zrzWOVROZF8RGsaH4tNffZrDOaNpVa2ZkNRA@mail.gmail.com>
Subject: Re: [PATCH v6 3/9] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K0Bt4tbR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Fri, 30 Oct 2020 at 16:47, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Oct 29, 2020 at 02:16:43PM +0100, Marco Elver wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>.
> >
> > KFENCE requires that attributes for pages from its memory pool can
> > individually be set. Therefore, force the entire linear map to be mapped
> > at page granularity. Doing so may result in extra memory allocated for
> > page tables in case rodata=full is not set; however, currently
> > CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> > is therefore not affected by this change.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v5:
> > * Move generic page allocation code to core.c [suggested by Jann Horn].
> > * Remove comment about HAVE_ARCH_KFENCE_STATIC_POOL, since we no longer
> >   support static pools.
> > * Force page granularity for the linear map [suggested by Mark Rutland].
> > ---
> >  arch/arm64/Kconfig              |  1 +
> >  arch/arm64/include/asm/kfence.h | 19 +++++++++++++++++++
> >  arch/arm64/mm/fault.c           |  4 ++++
> >  arch/arm64/mm/mmu.c             |  7 ++++++-
> >  4 files changed, 30 insertions(+), 1 deletion(-)
> >  create mode 100644 arch/arm64/include/asm/kfence.h
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index f858c352f72a..2f8b32dddd8b 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -135,6 +135,7 @@ config ARM64
> >       select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >       select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> >       select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> > +     select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
>
> Why does this depend on the page size?
>
> If this is functional, but has a larger overhead on 16K or 64K, I'd
> suggest removing the dependency, and just updating the Kconfig help text
> to explain that.

Good point, I don't think anything is requiring us to force 4K pages.
Let's remove it.

Thanks,
-- Marco

> Otherwise, this patch looks fine to me.
>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNko4pYa3zrzWOVROZF8RGsaH4tNffZrDOaNpVa2ZkNRA%40mail.gmail.com.
