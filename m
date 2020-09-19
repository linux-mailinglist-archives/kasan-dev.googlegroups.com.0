Return-Path: <kasan-dev+bncBDHYDDNWVUNRBYGKS75QKGQE5O7RG5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 47B3D270D5F
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Sep 2020 13:02:58 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id c126sf3875271oib.8
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Sep 2020 04:02:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600513377; cv=pass;
        d=google.com; s=arc-20160816;
        b=h1AXDz2iYaaKm0b15NpYqSU9HrP9OjQUjb5k+EEc8dBuJnYYQifXAukkb32DbTvrDi
         7ShdCQjFd6lP/ilhvCzj1hX4x2GqjfnO4AOyLiSeqI8+geO3A5FhLkzqvHl0PY3oMFjv
         LlBF+1siIppmDbmeCMBScACRsaCqHXOWuEXBPuWdQ6fyMBMhpLRxpo63zId/ZBbDOIkV
         3aGz3g/wLMRtnmrfwyHPkC+++oFCC9UY4WV+/lJf1e9QHdtBPr8lPPUuiM1JLZ7NrNb5
         FQyT3P4eANn11cKzD4mys/fR6JpvGUj1rqDlzwM6Q756zZor9oxh2DVF1fzsl4J+7CVV
         y6jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=AjyvKclhK1zPx98wXwllRuLkueW7hwlbx+FNBDg5a8o=;
        b=FGUlbOy3k6tqqAcaHEOKhvTmcK6n0jTmGO2i3KUZ1v7pHml5JRePftoT9+OkPsqMFd
         kobsmBxJlixmptN4M5T4x5Ybw+a04Z63wX82ylVs0I6kW5/OOefH1mPLTIM2aK77MOmW
         jtzjmchZdjYR36WCirr+nGnav+hPS5qjBuSPXgi4jOQZIqm/gSOZr7TAyDkJthB+K4fh
         mVYd2HvVKPlerAy5+FXpaDWqNjpgGTacLte3v6VhL5tiO5fgdf1Ntwjgg3e1a5VNPlxw
         gUs3Xj84aNUUlrpKv9oDw7od0gTJyOhb3M5aH5RRKn8prRmHPm5STiNfFjNnxaOR5qpM
         o1yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MCIFkzn4;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AjyvKclhK1zPx98wXwllRuLkueW7hwlbx+FNBDg5a8o=;
        b=P8QvK+Wo+jsdGjq95Ljp9hww2lGwpZypiYaXIPYIAeNwSxEbDUcYkQJpmYG1VVFoYS
         l5eBlSg2rot5o0CVaUu4/by/+i19rhfikRsHK1+4yK810UOT/2RdTJCRjVgjpOSYhMDD
         qSiUcKqSoc2cF3BheM2C+Rir/SI2Ur+vMG36lKFXSGSg+TM8Z2rJFCaLlb5ccuC9i+T4
         asKa6R1NfE0Za9I6sVhrBVCGwSjjjtt59a8EVL0kJJuBCiP2KSXzkHe3Pyp7+uoPtI9+
         PFiMYyJyql7hW+qjDIsCQipQpbLziD4nyejXOz88jOpEx7uLUxtm9eFexDYBi+uMMtYp
         aw8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AjyvKclhK1zPx98wXwllRuLkueW7hwlbx+FNBDg5a8o=;
        b=NySQQ/5bWXnJWWZFcQs1BcQqKjP3d1SVVuCsdkf6ZDfgAfe+gyPmEA8D4yh/9zAoan
         zh8i5CxMsSWIi29JQ0rxanZiLjtaNHFTqPQsiUY1oxp2cXz7/0yGTL7IzDwFNavwH6Lo
         7Xn7TAVw1UsigatYMZNolekYxlXGHV6nFOicfcvj+oALxZb2MR+VjrkbbAwFolCKOU1P
         04Z1cScNhkZQNHWHssS1HiuZH81vJQoNm6hB9dwa5GPA45JpUO4rRm3P8cErqnPJPvrI
         w/dX2pYudmpzKBytdutEiV6u1HdgCzTT6D7Ifj4mUMFTuziDpuYz6BkrxcAITwikOZxV
         3i2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AjyvKclhK1zPx98wXwllRuLkueW7hwlbx+FNBDg5a8o=;
        b=BWkP3Kst2l3x4iAu2nlc79aPRvxY5yRk/0B16O76gh/jiIpWcebm72OEa5fvyBu+6+
         wvytdfs3SsrBKD1IuV3V/5O/eb2n0++yV3WfC45ZeifE+JjY+efb+m+m6ql8BFX3qZwc
         SopCeiVAw/Cofl+E91MtbzEqlnRlwQ+5gwnXwTvsv+V5OcWED8eoG2DfN08sOwc/XKXt
         pkxx0kYjttk0s53KoTaF17Bn6dfBXTz+STSB43RDzzimAyhd5V6QSkhBq450MdwcBQ/G
         jsIfmo4y9A1sHoliW5HpUPydyLsYn056PGwiL+KDjzQydnkO6gju+mtLhKPHUw6ItfgA
         Adjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531us5Pe6FaEz56oH3A6Qej5cgnGxOd1hwlFU76wB5G+6IwOVSx6
	Cpx8bN0M/eG7FUAn4Xh0Kww=
X-Google-Smtp-Source: ABdhPJzM2CB3XJxUpnuQ7OmGy6MuzRUm/8Wc483cCvtD4+WqjU0gzamt726Sm1EeBwUjyZwYm6PBsw==
X-Received: by 2002:a9d:185:: with SMTP id e5mr26708535ote.135.1600513376703;
        Sat, 19 Sep 2020 04:02:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d803:: with SMTP id f3ls485746oov.1.gmail; Sat, 19 Sep
 2020 04:02:56 -0700 (PDT)
X-Received: by 2002:a4a:e862:: with SMTP id m2mr27286656oom.33.1600513376363;
        Sat, 19 Sep 2020 04:02:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600513376; cv=none;
        d=google.com; s=arc-20160816;
        b=VbDfuS5bnac0Q6ZGncDLw80J70dQW7/X4adhUmdm8qP0kocEtmDLfg3Srv4Epx8EKk
         14OZ31k8WTT2TErHSKhXlcbKvdHNEA5oN2LuH4UBt8bbTgvNYWx3hImM1nmA7ZBXuJff
         LrjCK4Hes04PaCNmrLiM0pYZc05COYiDcUvcVoIHQAjKL9XREwP3yVvdTa0p5pdzm+Yb
         x4eVNMXyPB+ZouHPn5yYk7knD/bDNies1AbFxje2suScLv2m0ld48GgJjPslrWKKzIQZ
         Nw9PfRqNO9tqqUtu/qW6/DhgcuWdEWJwEh/rZQ9STir5DF9mRmebv6DDk5BgRPbF5Ckf
         MnjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3h23YiWPGuupu0L7W8TUBUUA4TL4R9nY/LN+gBcZbe0=;
        b=S48611ob6aDC/FLs03s710C6EDvO5rtFZG297wlWXBD2kbIiFhFO0Is91vpRodiQEo
         no3cWowhM6TX5FlOlsioy6B3zyfx9k4o9nAinGj0ZAVHpQOvqCYWNEkZH8CN/nS25Jbf
         88BZxQAHwk/ilPgDesyiy8S3/QEF+UjEvoP6VP/o112yCpewOK5wMQ6FBvjLxwTvOQ/z
         b3vl0DH8nuQwBZFtew2Fus4EpG8jr3BYW3RtPO1+yYuwTcRe5iu2EpvX96Qvlt2goJ9e
         qvf9cyzOdyW6K+OCFCLoXKAGDNvWF+GLwMifSKCSyY828Pljh854et5aVfDD18LEmmrE
         0f2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MCIFkzn4;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id u27si429763otg.5.2020.09.19.04.02.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 19 Sep 2020 04:02:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id u25so7883248otq.6;
        Sat, 19 Sep 2020 04:02:56 -0700 (PDT)
X-Received: by 2002:a05:6830:110b:: with SMTP id w11mr24254895otq.109.1600513376087;
 Sat, 19 Sep 2020 04:02:56 -0700 (PDT)
MIME-Version: 1.0
References: <20200918154840.h3xbspb5jq7zw755@treble> <20200919064118.1899325-1-ilie.halip@gmail.com>
In-Reply-To: <20200919064118.1899325-1-ilie.halip@gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Sat, 19 Sep 2020 13:02:44 +0200
Message-ID: <CA+icZUVxsXXocAkiLM_Avv3vmFn=Gzm6B3s6aRrE+ycQB2Bxng@mail.gmail.com>
Subject: Re: [PATCH v2] objtool: ignore unreachable trap after call to
 noreturn functions
To: Ilie Halip <ilie.halip@gmail.com>
Cc: linux-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>, 
	Rong Chen <rong.a.chen@intel.com>, Marco Elver <elver@google.com>, 
	Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>, kasan-dev@googlegroups.com, 
	x86@kernel.org, Clang-Built-Linux ML <clang-built-linux@googlegroups.com>, 
	kbuild test robot <lkp@intel.com>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Nathan Chancellor <natechancellor@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=MCIFkzn4;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::343
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Sep 19, 2020 at 8:41 AM Ilie Halip <ilie.halip@gmail.com> wrote:
>
> With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap instruction
> after a call to a noreturn function. In this case, objtool warns that the
> ud2 instruction is unreachable.
>
> This is a behavior seen with clang, from the oldest version capable of
> building the mainline x64_64 kernel (9.0), to the latest experimental
> version (12.0).
>
> objtool silences similar warnings (trap after dead end instructions), so
> so expand that check to include dead end functions.
>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Rong Chen <rong.a.chen@intel.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Philip Li <philip.li@intel.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: kasan-dev@googlegroups.com
> Cc: x86@kernel.org
> Cc: clang-built-linux@googlegroups.com
> BugLink: https://github.com/ClangBuiltLinux/linux/issues/1148
> Link: https://lore.kernel.org/lkml/CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com
> Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> Tested-by: Nick Desaulniers <ndesaulniers@google.com>
> Reported-by: kbuild test robot <lkp@intel.com>
> Signed-off-by: Ilie Halip <ilie.halip@gmail.com>
> ---

Tested-by: Sedat Dilek <sedat.dilek@gmail.com>

- Sedat -

>
> Changed in v2:
>  - added a mention that this is a clang issue across all versions
>  - added Nick's Reviewed-by, Tested-by
>  - added Reported-by
>
>  tools/objtool/check.c | 10 +++++++---
>  1 file changed, 7 insertions(+), 3 deletions(-)
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index e034a8f24f46..eddf8bf16b05 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -2612,9 +2612,10 @@ static bool is_ubsan_insn(struct instruction *insn)
>                         "__ubsan_handle_builtin_unreachable"));
>  }
>
> -static bool ignore_unreachable_insn(struct instruction *insn)
> +static bool ignore_unreachable_insn(struct objtool_file *file, struct instruction *insn)
>  {
>         int i;
> +       struct instruction *prev_insn;
>
>         if (insn->ignore || insn->type == INSN_NOP)
>                 return true;
> @@ -2639,8 +2640,11 @@ static bool ignore_unreachable_insn(struct instruction *insn)
>          * __builtin_unreachable().  The BUG() macro has an unreachable() after
>          * the UD2, which causes GCC's undefined trap logic to emit another UD2
>          * (or occasionally a JMP to UD2).
> +        * CONFIG_UBSAN_TRAP may also insert a UD2 after calling a __noreturn
> +        * function.
>          */
> -       if (list_prev_entry(insn, list)->dead_end &&
> +       prev_insn = list_prev_entry(insn, list);
> +       if ((prev_insn->dead_end || dead_end_function(file, prev_insn->call_dest)) &&
>             (insn->type == INSN_BUG ||
>              (insn->type == INSN_JUMP_UNCONDITIONAL &&
>               insn->jump_dest && insn->jump_dest->type == INSN_BUG)))
> @@ -2767,7 +2771,7 @@ static int validate_reachable_instructions(struct objtool_file *file)
>                 return 0;
>
>         for_each_insn(file, insn) {
> -               if (insn->visited || ignore_unreachable_insn(insn))
> +               if (insn->visited || ignore_unreachable_insn(file, insn))
>                         continue;
>
>                 WARN_FUNC("unreachable instruction", insn->sec, insn->offset);
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "Clang Built Linux" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to clang-built-linux+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/clang-built-linux/20200919064118.1899325-1-ilie.halip%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUVxsXXocAkiLM_Avv3vmFn%3DGzm6B3s6aRrE%2BycQB2Bxng%40mail.gmail.com.
