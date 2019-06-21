Return-Path: <kasan-dev+bncBDYNJBOFRECBBF6BWPUAKGQEZWA7KBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E83634E9E5
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 15:50:15 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id a11sf2214800vso.9
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 06:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561125015; cv=pass;
        d=google.com; s=arc-20160816;
        b=tYXEe+8iXIFM9sLwT34/FhS8dHy3tSAi3A15tpj6zvHE2LqilHesVaHvNsvJCr4VTi
         enpoPwE+cRvUveXJPAIWKE9txqv+BhEwbQGfMn1MbYRB1wgrOuV3wM8FQPM8jsDs5wMc
         pVO2/vRXzCBrS82xFkCavV6h7TpyxjV+vArvZV4AlnULPXMGIiXp7Zz7QPZxCNR7V44x
         gh96oeMXK/rixbMTe7bd2VWCDzPO2gPULX2MG+GidA6MSs5LdLzmhyQBGoC6Ff7MBk+e
         huvZY8FmGgnKl3f39Dro9hUizQftw6Qokb4Z/ocoGSvCRWLVFOcf+CS2xFGuHJGdQ95n
         M4Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=D5K2qkpj0ZyvlmIuxwyesvPG/bwlvc3vxO2ZUpYhGEA=;
        b=xl8g4zYV3eiSIyb0OxOCTtVZ19rxgfyX8IySgWDiMP/2GEBDpLulcT5ZuYunOhPaEf
         rp7nao2VrXwH5rdLVLoeVjwkSZn0an5QItsMfofHe0uIRM+v8dkJbg16+wR3mzc/sl3P
         /V+NN3iTG5tshjLqczvdj361s5WsZlDMrC0DWOpzCxiW4ciSQfPbNsFVjS2On3FvLHCQ
         9jF8TwOAMj2RAK2SVZlCZIOy1wvcqOW/uPCW54TmhDY/PcM9la7bk+cdp/49Sxz6nlfM
         NwckT+U6vsYQ0ci4goKS3mgilKHo8reRFXAVWn9m572atmJnVV+3Tir8LMa8V36E9oJh
         oe2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=KXjBo31V;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D5K2qkpj0ZyvlmIuxwyesvPG/bwlvc3vxO2ZUpYhGEA=;
        b=OVx4kRcBVd/iVIb/gZzVRxksOIFh2TbLhiEyJfNRQPm0Q9Ueos+RR0pvRu9baVqVWN
         S0SZliWqC+VN1Dvhqvi3M0uII1hPGjKXufJJlL7gQiSBm7hmcxQFMbMYzc3DraM5dvWz
         1sLWR5S7Ty9TbQd4PyDEAAiwg/7Oi9iojEDIj4dJ6+idvJU0VHT9qrm7G4y+8E5zTlhp
         7Ggdl5qjokDhOhga5yWxvdZdg7WmEPkwdRflK0QskILVO0lTwY4J1uRzuvgQxNlHS7A1
         xeDlbX/cZCliHKjnXF5DNcdxcWhZ1tA0UlwG4oXa5+dIsICwPRO5QjOP15+rM08FeceF
         YnZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D5K2qkpj0ZyvlmIuxwyesvPG/bwlvc3vxO2ZUpYhGEA=;
        b=FSydX59cFAh6DxXi2eWAh2NSWNFoKJVZYnAUSYqOy0o5wQm+XAPzktjwgGG8o2Qsy9
         eIL3rntH0GqnFzkjHPCmQ7Pk7kjiEUdj2NC/Q9CAgcai/PKIQ/dEF4j6rdhQqnhSjbL1
         YaFXcYaEnxJRO1D4ZXOhXR8C+hYq15NbJip+vEF6zU1l3NKPmJ5/zjQ62ARMzDnfy+l7
         u2Cl35jGjP1vOvjUwRyHq5nNB+ehIYIlqJlNBvyhHSRXCfwnQbB0P/n7LiBK1L+4hr0P
         fXm6s0FP0wxMyIWyNmr7oZWRuzxysyW+axC2SKRa6d/Qy9Di9D/8ZzxpTEX5FPumk2/v
         qcvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWSpssLuVk6KFF7tv46NrztwoBrT4mRjbNqehrP5PBptrh5azvt
	bfV6A9eUZsrI8IFVxhj7vGc=
X-Google-Smtp-Source: APXvYqz7rrQTE0xsMwLxlzej+yGDr4OO6yXN3zIV1SROicI4UpNzCscWN6T1PJEBJDWX8umHNEn+7w==
X-Received: by 2002:a05:6102:18e:: with SMTP id r14mr20217627vsq.2.1561125015064;
        Fri, 21 Jun 2019 06:50:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:698f:: with SMTP id e137ls966751vsc.12.gmail; Fri, 21
 Jun 2019 06:50:14 -0700 (PDT)
X-Received: by 2002:a67:cd9a:: with SMTP id r26mr6534075vsl.152.1561125014788;
        Fri, 21 Jun 2019 06:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561125014; cv=none;
        d=google.com; s=arc-20160816;
        b=EYxV/jofCPbHRqn1nIud1vMBJR85yo4BZNX9UDZ3a3q4OrRYchPO/I3OEi3dsnfmIB
         nSNay8GzPCqWXUpikzWnYbWDoVnbK/rJzpKU2TVxRQspZ0265XbvnSMIWZsIKJ/jVL+u
         UhY6YViqvcrCQJdH3ULyDWVh63PPnqmPq8WnUH1Zs7frQRXhxWiAQ3SHCTT4VCbh1oCi
         b1zDYV06PI3QHug376hbW5aq3DQK4ldySMlieFP+CF17eYrGQ0MeJwtNJFys0om6cgIg
         09HcHn3NDV2KgAlMthIrY1sCjyoELMGPGSI0yYOpbdNBlJNN37dfn+DWDCW8+p/SbgQE
         A/1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cw2DVVVaW1JthaIStHyVWKFyGjZO7Go63aSJmpzaddY=;
        b=Pkybl7+K3de8Qk4gjsdBKs2t+28PBb3aF0gOwZHYMUjlwEWRuAC3bgN5OI+q7+4Ck4
         8fAVgt+gCMdywEYhMMUZn/5FfIi1fzgcOOoK1vVlWHa+wLBRNX1nZj8ZMwC2Q5/r6ouf
         6E33gH0LzEfNFjPyiZF+N0euzyOycuFfn5Ig1V5ytdhHOxX2u3jnHMZy+4THlF4bKIoc
         f9JLX8cBhpZpN+4VKx86Z18j77nCoKJJQ1dT8ntGrZGjHVVjnE1Lz5xhIgpr7WiXTuOV
         ZPPNIT4jgmBEYXzxp1f6MVKYdiVac65gyqbLj8tvzGppfYLcT1qhpBBWFcrZKGouRBiv
         XP+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=KXjBo31V;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id w4si197407vkd.1.2019.06.21.06.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 06:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id r185so639673iod.6
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 06:50:14 -0700 (PDT)
X-Received: by 2002:a5e:820a:: with SMTP id l10mr23290864iom.283.1561125013996;
 Fri, 21 Jun 2019 06:50:13 -0700 (PDT)
MIME-Version: 1.0
References: <20190618094731.3677294-1-arnd@arndb.de> <201906201034.9E44D8A2A8@keescook>
 <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
 <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com> <CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg@mail.gmail.com>
In-Reply-To: <CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg@mail.gmail.com>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Fri, 21 Jun 2019 15:50:02 +0200
Message-ID: <CAKv+Gu9p017iPva85dPMdnKW_MSOUcthqcy7KDhGEYCN7=C_SA@mail.gmail.com>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <keescook@chromium.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Popov <alex.popov@linux.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, 
	LSM List <linux-security-module@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=KXjBo31V;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, 21 Jun 2019 at 15:44, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Fri, Jun 21, 2019 at 3:32 PM Ard Biesheuvel
> <ard.biesheuvel@linaro.org> wrote:
> > On Fri, 21 Jun 2019 at 11:44, Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Thu, Jun 20, 2019 at 7:36 PM Kees Cook <keescook@chromium.org> wrote:
> > > > On Tue, Jun 18, 2019 at 11:47:13AM +0200, Arnd Bergmann wrote:
> > > > > The combination of KASAN_STACK and GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> > > > > leads to much larger kernel stack usage, as seen from the warnings
> > > > > about functions that now exceed the 2048 byte limit:
> > > >
> > > > Is the preference that this go into v5.2 (there's not much time left),
> > > > or should this be v5.3? (You didn't mark it as Cc: stable?)
> > >
> > > Having it in 5.2 would be great. I had not done much build testing in the last
> > > months, so I didn't actually realize that your patch was merged a while ago
> > > rather than only in linux-next.
> > >
> > > BTW, I have now run into a small number of files that are still affected
> > > by a stack overflow warning from STRUCTLEAK_BYREF_ALL. I'm trying
> > > to come up with patches for those as well, we can probably do it in a way
> > > that also improves the affected drivers. I'll put you on Cc when I
> > > find another one.
> > >
> >
> > There is something fundamentally wrong here, though. BYREF_ALL only
> > initializes variables that have their address taken, which does not
> > explain why the size of the stack frame should increase (since in
> > order to have an address in the first place, the variable must already
> > have a stack slot assigned)
> >
> > So I suspect that BYREF_ALL is defeating some optimizations where.
> > e.g., the call involving the address of the variable is optimized
> > away, but the the initialization remains, thus forcing the variable to
> > be allocated in the stack frame even though the initializer is the
> > only thing that references it.
>
> One pattern I have seen here is temporary variables from macros or
> inline functions whose lifetime now extends over the entire function
> rather than just the basic block in which they are defined, see e.g.
> lpfc_debug_dump_qe() being inlined multiple times into
> lpfc_debug_dump_all_queues(). Each instance of the local
> "char line_buf[LPFC_LBUF_SZ];" seems to add on to the previous
> one now, where the behavior without the structleak plugin is that
> they don't.
>

Right, that seems to be due to the fact that this code

/* split the first bb where we can put the forced initializers */
gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
if (!single_pred_p(bb)) {
    split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
    gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
}

puts all the initializers at the beginning of the function rather than
inside the scope of the definition.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu9p017iPva85dPMdnKW_MSOUcthqcy7KDhGEYCN7%3DC_SA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
