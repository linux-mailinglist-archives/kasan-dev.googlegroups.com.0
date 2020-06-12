Return-Path: <kasan-dev+bncBCMIZB7QWENRBR75RP3QKGQEXQBGKXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD761F72A9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 06:04:24 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id o23sf5847753pjs.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jun 2020 21:04:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591934663; cv=pass;
        d=google.com; s=arc-20160816;
        b=fcuATru50SKG1wlPer9vS8j8HX3/7awlcEjTNvV6KLlwV0Vm3GDFZrb1waHaP/P5yD
         wTsM7S8FQYZyFncAy9yvAQwYfEurjpFPyK3pfGkYpadhnz9AyXQ708oVdRetDpSo0IS5
         AvoWTP0dyrHxxDRsqGrY6vnb/X4BxsNFWTK0C5oELFppEsmHQTUGgVGe0jjdw/igDZFQ
         r9IMuLoVznbdIKGc1JZFz7wqXy/4tJwPkwYisqN1GePHrvlrDOK9Bzi09c9VEd167Xyg
         d5hvZeQnTXq31eyoQlsSkDw+b+UDIloklnZqC1v0X6bjGmVxxkE2DddmqzVyIk8dbKE8
         mhGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SLOK1GSlsgWItgXUBBmDYu+mVnyR/+mTdWOPkc1eWyk=;
        b=mKTNw8rdkNdK2NMviLazNvkokw2Xqs9z5DK3aTOp2gIfeolLjIACXw73tRIeK+NPpE
         i0jORIPwERx5Y+cZ96Ny0141CQyFmR8fdtViT8NdIZdRq0A8SATPhCylBJcoCqZO6N4+
         zk2zAxWA6ZbYvq4InARIuWF0Vv3J1EbNGjuEVOgJk1MJC5mkFhpFMsaVZFbqOvq9FkQK
         VS30RA3ks1M0C5ydezFOK73PT6dI2NNBpURhBKcftVNK8GrlmCPRfD+OLpv56lT6Z5EZ
         bm+U57QaZivMjC2Iyok5YXNAeY/+TU0TXzD/kq5cSYIfnpI0fx7UOE7oGemecM2+0C+9
         102Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R6cpDsvT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SLOK1GSlsgWItgXUBBmDYu+mVnyR/+mTdWOPkc1eWyk=;
        b=FVCsiGyFIRslst+UxaC9Xucg+B5f3vHkJfG95W+LdbhdDBCMVdfxs58NY+1fAx9EYq
         01vESAg/9YGsNIahI25U39NH/oPpFCfUJdXnVzLeY3DEyfTZr7ZYC8nIe2x7m+XBUvCj
         YeMiPDdINgM0vTR7+xO+xOfrnZMClVg5YNAJYkZiM4zhtxtSDgyQLxS1Sp2g5xgsYv6M
         i9pU4VqySy6kuT0Y8ISPWVDtKb+MRf/oAKsO28qciIt/DVVdBp519h1ecso6TC8TQ6LE
         yeoy1tu8j7jdPop5PtrE8KKi6ku7ijxR9EohvRoOWy+Hu2t01/bPoXacXqL7CKIetim/
         159Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SLOK1GSlsgWItgXUBBmDYu+mVnyR/+mTdWOPkc1eWyk=;
        b=I4bKUX+IUWe03AoGEJsVo6SmUMJC9LPzlHZeiMMqAWz9aintwmElKVcQO1Tk/MOkRc
         ajcI1GZ4YJyjNvzkv47Lg6jVQdaFbSe7xjdQqeiJSY20I8MMNyRRwm3kVqN5axg6gt5z
         4IgmbPQM3BtCfHUEfKx7JixLFLc3vEHAfvNs4g0+GuBy0CWcARvFXAwn5kVcY9qAD+WR
         V1m/udaPUlUL4LHiPY0/TLpmDuQpk0lVQBAJBw34QOaaepfO/4mgQkeNzcG5xvGvGn3V
         pXWco1xzNAHL+7XSITp8KYjHppIRMY5W7zvu3fMgugqquNs6nmF2KrzvRztcZRWuAFCG
         DT8w==
X-Gm-Message-State: AOAM533YxP7Qz1x815pr63/nRkU7kzeEhQWqXIhg00P8BOxNcp2nmfK5
	LbsLaZuzvcrmdAsR/4xzI/k=
X-Google-Smtp-Source: ABdhPJziAr+gjs4fKtbU3KDX9BQqKpHQS+AG1w6tVOk3U0ICH28y3h3krju2r9d86jWiig3hKX7flw==
X-Received: by 2002:a17:90a:a08d:: with SMTP id r13mr10702398pjp.96.1591934663227;
        Thu, 11 Jun 2020 21:04:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c910:: with SMTP id o16ls1150635pgg.4.gmail; Thu, 11 Jun
 2020 21:04:22 -0700 (PDT)
X-Received: by 2002:a63:5b0e:: with SMTP id p14mr9564243pgb.43.1591934662750;
        Thu, 11 Jun 2020 21:04:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591934662; cv=none;
        d=google.com; s=arc-20160816;
        b=CDMsGX6hWrbd5GsiuRO30/q2ypA6MM6KKOzwu6o6v+6aOBVvVZWbHQNSFVQv1h92XC
         WE/tD36WQ4niLswLL7p0P3XrDKFRMRdQgvTHv68Wbxu2MiFacfRw3sbK8Ni978uFmEz5
         KSS5ZJQU64xvv6S9nqLiS8vDCHa2ICTlkqTawHoV9D2CXyyhYGf+Opvk5MlO7qH62dEY
         KgpMDXbxf1RYrtYzF8N4GrN9gJ5i19PBEfoI43IX31v1iiOvPiCSZn0xbKgRLhSe5mN/
         4KfQWdjtN1D6pRA9fpHz6J+JtYG6tyGuwym5tNdemeGUp2tkJL65C48t4wePFDfbfuAX
         LVXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tk4oPlKcNdHHWRnpa3/f3nYi5KMB00ccTNvWIrQryOY=;
        b=BmtPEQfMgevyXmIT7mPizPTMgUouIONapYhjOBhuSkT12gvsuifzz/wHy8rYxktaSc
         nMYVGoYSu8QASwDFNV+Xl2XDoZCBWBGMSqerKr1RHDcZVGNNyaYVGbsRvazX9PixM9Nk
         vlS8YFzRdid1Ps3c/QmFTLZCzFqn6Mekc1rvsQQe4Xs8xw2V+BoxmzkoeoyWW7z6ki5X
         ckBbKJCH6cUd0UhFlKEuCe8Uu3qDxdxTh1SGmmpcL5HRQCIVe1QamXfaOAxeV564yifP
         hsF/aTiSJCunwjvGpMI7b01z2eIedxjOUWH7YMhiUA9WrnHGXw+BYBz/4lQHuLsKgWjL
         SCVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R6cpDsvT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id q194si417557pfq.4.2020.06.11.21.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jun 2020 21:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id c12so7795858qkk.13
        for <kasan-dev@googlegroups.com>; Thu, 11 Jun 2020 21:04:22 -0700 (PDT)
X-Received: by 2002:a37:a0c6:: with SMTP id j189mr1147710qke.256.1591934661563;
 Thu, 11 Jun 2020 21:04:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net> <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net> <20200611215538.GE4496@worktop.programming.kicks-ass.net>
In-Reply-To: <20200611215538.GE4496@worktop.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Jun 2020 06:04:09 +0200
Message-ID: <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=R6cpDsvT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jun 11, 2020 at 11:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Jun 08, 2020 at 01:01:08PM +0200, Peter Zijlstra wrote:
> > On Mon, Jun 08, 2020 at 09:57:39AM +0200, Dmitry Vyukov wrote:
> >
> > > As a crazy idea: is it possible to employ objtool (linker script?) to
> > > rewrite all coverage calls to nops in the noinstr section? Or relocate
> > > to nop function?
> > > What we are trying to do is very static, it _should_ have been done
> > > during build. We don't have means in existing _compilers_ to do this,
> > > but maybe we could do it elsewhere during build?...
> >
> > Let me try and figure out how to make objtool actually rewrite code.
>
> The below is quite horrific but seems to sorta work.
>
> It turns this:
>
>   12:   e8 00 00 00 00          callq  17 <lockdep_hardirqs_on+0x17>
>                         13: R_X86_64_PLT32      __sanitizer_cov_trace_pc-0x4
>
> Into this:
>
>   12:   90                      nop
>   13:   90                      nop
>                         13: R_X86_64_NONE       __sanitizer_cov_trace_pc-0x4
>   14:   90                      nop
>   15:   90                      nop
>   16:   90                      nop
>
>
> I'll have to dig around a little more to see if I can't get rid of the
> relocation entirely. Also, I need to steal better arch_nop_insn() from
> the kernel :-)

Wow! Cool!
Thanks for resolving this. I guess this can be used to wipe more
unwanted things in future :)

Marco double checked and his patch did not actually fix the existing
crash under KCSAN. The call itself was the problem or something,
returning early did not really help. This should hopefully fix it.
Marco, please double check.

Re better nop insn, I don't know how much work it is (or how much you
are striving for perfection :)). But from KCOV point of view, I think
we can live with more or less any nop insn. The main thing was
removing overhead from all other (not noinstr) cases, I would assume
the noinstr cases where we use nops are very rare. I mean don't spend
too much time on it, if it's not needed for something else.

Thanks again!


> ---
>  tools/objtool/arch.h            |  2 ++
>  tools/objtool/arch/x86/decode.c | 24 ++++++++++++++++++++++
>  tools/objtool/check.c           | 15 +++++++++++++-
>  tools/objtool/elf.c             | 45 ++++++++++++++++++++++++++++++++++++++++-
>  tools/objtool/elf.h             | 11 ++++++++--
>  5 files changed, 93 insertions(+), 4 deletions(-)
>
> diff --git a/tools/objtool/arch.h b/tools/objtool/arch.h
> index eda15a5a285e..3c5967748abb 100644
> --- a/tools/objtool/arch.h
> +++ b/tools/objtool/arch.h
> @@ -84,4 +84,6 @@ unsigned long arch_jump_destination(struct instruction *insn);
>
>  unsigned long arch_dest_rela_offset(int addend);
>
> +const char *arch_nop_insn(int len);
> +
>  #endif /* _ARCH_H */
> diff --git a/tools/objtool/arch/x86/decode.c b/tools/objtool/arch/x86/decode.c
> index 4b504fc90bbb..b615c32e21db 100644
> --- a/tools/objtool/arch/x86/decode.c
> +++ b/tools/objtool/arch/x86/decode.c
> @@ -565,3 +565,27 @@ void arch_initial_func_cfi_state(struct cfi_init_state *state)
>         state->regs[16].base = CFI_CFA;
>         state->regs[16].offset = -8;
>  }
> +
> +const char *arch_nop_insn(int len)
> +{
> +       static const char insn[16] = {
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +               0x90,
> +       };
> +
> +       return insn;
> +}
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 5fbb90a80d23..487b4dc3d122 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -765,6 +765,17 @@ static int add_call_destinations(struct objtool_file *file)
>                 } else
>                         insn->call_dest = rela->sym;
>
> +               if (insn->sec->noinstr &&
> +                   !strncmp(insn->call_dest->name, "__sanitizer_cov_", 16)) {
> +                       if (rela)
> +                               elf_write_rela(file->elf, rela);
> +
> +                       elf_write_insn(file->elf, insn->sec,
> +                                      insn->offset, insn->len,
> +                                      arch_nop_insn(insn->len));
> +                       insn->type = INSN_NOP;
> +               }
> +
>                 /*
>                  * Whatever stack impact regular CALLs have, should be undone
>                  * by the RETURN of the called function.
> @@ -2802,11 +2813,13 @@ int check(const char *_objname, bool orc)
>                 if (ret < 0)
>                         goto out;
>
> +       }
> +
> +       if (file.elf->changed) {
>                 ret = elf_write(file.elf);
>                 if (ret < 0)
>                         goto out;
>         }
> -
>  out:
>         if (ret < 0) {
>                 /*
> diff --git a/tools/objtool/elf.c b/tools/objtool/elf.c
> index 84225679f96d..705582729374 100644
> --- a/tools/objtool/elf.c
> +++ b/tools/objtool/elf.c
> @@ -525,6 +525,7 @@ static int read_relas(struct elf *elf)
>                                 return -1;
>                         }
>
> +                       rela->idx = i;
>                         rela->type = GELF_R_TYPE(rela->rela.r_info);
>                         rela->addend = rela->rela.r_addend;
>                         rela->offset = rela->rela.r_offset;
> @@ -713,6 +714,8 @@ struct section *elf_create_section(struct elf *elf, const char *name,
>         elf_hash_add(elf->section_hash, &sec->hash, sec->idx);
>         elf_hash_add(elf->section_name_hash, &sec->name_hash, str_hash(sec->name));
>
> +       elf->changed = true;
> +
>         return sec;
>  }
>
> @@ -779,7 +782,43 @@ int elf_rebuild_rela_section(struct section *sec)
>         return 0;
>  }
>
> -int elf_write(const struct elf *elf)
> +int elf_write_insn(struct elf *elf, struct section *sec,
> +                  unsigned long offset, unsigned int len,
> +                  const char *insn)
> +{
> +       Elf_Data *data = sec->data;
> +
> +       if (data->d_type != ELF_T_BYTE || data->d_off) {
> +               printf("ponies\n");
> +               return -1;
> +       }
> +
> +       memcpy(sec->data->d_buf + offset, insn, len);
> +
> +       elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
> +
> +       sec->changed = true;
> +       elf->changed = true;
> +
> +       return 0;
> +}
> +
> +int elf_write_rela(struct elf *elf, struct rela *rela)
> +{
> +       struct section *sec = rela->sec;
> +
> +       rela->rela.r_info = 0;
> +       rela->rela.r_addend = 0;
> +
> +       gelf_update_rela(sec->data, rela->idx, &rela->rela);
> +
> +       sec->changed = true;
> +       elf->changed = true;
> +
> +       return 0;
> +}
> +
> +int elf_write(struct elf *elf)
>  {
>         struct section *sec;
>         Elf_Scn *s;
> @@ -796,6 +835,8 @@ int elf_write(const struct elf *elf)
>                                 WARN_ELF("gelf_update_shdr");
>                                 return -1;
>                         }
> +
> +                       sec->changed = false;
>                 }
>         }
>
> @@ -808,6 +849,8 @@ int elf_write(const struct elf *elf)
>                 return -1;
>         }
>
> +       elf->changed = false;
> +
>         return 0;
>  }
>
> diff --git a/tools/objtool/elf.h b/tools/objtool/elf.h
> index f4fe1d6ea392..4a3fe4f455c5 100644
> --- a/tools/objtool/elf.h
> +++ b/tools/objtool/elf.h
> @@ -64,9 +64,10 @@ struct rela {
>         GElf_Rela rela;
>         struct section *sec;
>         struct symbol *sym;
> -       unsigned int type;
>         unsigned long offset;
> +       unsigned int type;
>         int addend;
> +       int idx;
>         bool jump_table_start;
>  };
>
> @@ -76,6 +77,7 @@ struct elf {
>         Elf *elf;
>         GElf_Ehdr ehdr;
>         int fd;
> +       bool changed;
>         char *name;
>         struct list_head sections;
>         DECLARE_HASHTABLE(symbol_hash, ELF_HASH_BITS);
> @@ -118,7 +120,7 @@ struct elf *elf_open_read(const char *name, int flags);
>  struct section *elf_create_section(struct elf *elf, const char *name, size_t entsize, int nr);
>  struct section *elf_create_rela_section(struct elf *elf, struct section *base);
>  void elf_add_rela(struct elf *elf, struct rela *rela);
> -int elf_write(const struct elf *elf);
> +int elf_write(struct elf *elf);
>  void elf_close(struct elf *elf);
>
>  struct section *find_section_by_name(const struct elf *elf, const char *name);
> @@ -132,6 +134,11 @@ struct rela *find_rela_by_dest_range(const struct elf *elf, struct section *sec,
>  struct symbol *find_func_containing(struct section *sec, unsigned long offset);
>  int elf_rebuild_rela_section(struct section *sec);
>
> +int elf_write_rela(struct elf *elf, struct rela *rela);
> +int elf_write_insn(struct elf *elf, struct section *sec,
> +                  unsigned long offset, unsigned int len,
> +                  const char *insn);
> +
>  #define for_each_sec(file, sec)                                                \
>         list_for_each_entry(sec, &file->elf->sections, list)
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh%3DjgX0ZvLw%40mail.gmail.com.
