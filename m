Return-Path: <kasan-dev+bncBDYJPJO25UGBBZWPR35QKGQE7OOSILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 528EA26E35B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 20:16:08 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 6sf1353283oix.6
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 11:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600366567; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYm3RueJl4a5HGjf69wQg9lzgDQvTNENv+4ZkgC6OPkLkYRvyOAlsiFgpbItwleFIs
         WsZ7xDFeTjPA1WDJ1uc66eCKC1MAZKMzcUWQM6w9sFJUww3aGuysucT0Mg4ov4YoMxOV
         xEC1ot7CoJjEvan+667PfIRmjEhxZHgOopKe/xDJ5rBfN3Ckih/WW3B26/vBjDUc56nN
         Qf6o/PVd4/pg9Ljd39OSIYi99aLGD6Os1WW8zmgXMqsZtGcCAGZWxIhU9+hfOXNI7YE/
         m33mokUSe//uuBMmPxNuA8Oyutm+hcLXSexWOEK1VvAA8jhe0H5xMNIdw6oScmOnGr0Q
         Is+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bE60PMKJZ0LeVrFz4UggEEKfJroRdtEMURSa/HGv8FM=;
        b=oPyzFv5m4S2OJYHWLJkDwZ4cJpAHyHfDINrYBvoC5xBpiORPwH2zXaUrFtFKRuLUFf
         0nqnxcQZg2vo+mM8jBRi5muetB4eQLWf+diBFBckOrzd4tbOyL+WzsRqco4npqNyQPm0
         XDNKiBwkhwIQfOVmKiFkEXefmLoCSgXjJKXLsY87gk38RwfIW/aUlsZ2u58jOgPDp7mu
         IhMiuZK+Wk7WatOtJTlyUYmCa9rHfSP9+zwDww/NW5BIgaI/jtP4lNCTlgw0uu+0UTZt
         gWaEOEv4ia7o3h1bKn6fUZtS8XloI/IysxN5UvVoVeGQqw7u1J/gjPdgDL9RbpmznLiw
         4mfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vxxCO7Jr;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bE60PMKJZ0LeVrFz4UggEEKfJroRdtEMURSa/HGv8FM=;
        b=tglNMvk2iCoOTZqngNX92kRybBSgp5dqLyAXZvTKfnh0WkGa1P6IACRvoW2+5MxL5x
         CqW9B3P3sAyDxJHLsnHmhQK9OqugrdWcg+JTPjhVm47DUwBvqmIlD2RLKq+b1bZxHW5D
         jB9cjzFJ3dfXm+w+y1NnO848jOOvFD7jkRkycx9aiJ0AOhx06Hi67dzdyo/4aj70WvlA
         5+1bhA4xtv09csAXyOx4/wO7JeAX9Pt/LFxmkGQvsqOyIy4ZnU6/mtec+1UHG7Wd2MJ5
         vY51y+0F/cSLCl8MqnY0MWlsYCtD1svY2pATEF6dRVrJe3bWPSmWN8LSNAHiVZVZPmur
         y3sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bE60PMKJZ0LeVrFz4UggEEKfJroRdtEMURSa/HGv8FM=;
        b=HTOHMa0JLMQShTksZVsX2Ru6jByL0xI/4JYoWSOLpMMPdLxVO2HQdGxxiHnZdImJZW
         SiMECjp6gcB7DDTPNaUXqA3kCGbDn++A4r0oiR2JvpymHKLPQjTbzIoiz6yzPederhhA
         BXE3QWr0P7kxHk22v79FTwVa0GLYoAK/2VZe0c3WycQeGhaugAS0OEM/+dxHrmDB6hU9
         z7bMr6UKc1WJivYkJ5YE75BbzsTUUdrZclGGedeWM3BrsDSRyXFtd03QTaVEub01m4Ph
         YXkDZI4ky9ub3pQg7s5yByP2bovoC8uMQsjVr6ic3odMzsJ97qj8s6AWRBt3n9Sl9A9h
         nVLw==
X-Gm-Message-State: AOAM530aMqOrpUWDS8Cc1NKSazHbhkn3MOLWghjGTnHczsbmv721v49+
	Cdh/22+9l0AXYmL30wIXNnI=
X-Google-Smtp-Source: ABdhPJxClpQIxhuIHS+1pgeF/D5kUsrwiUNvFFVV2YKRju8Ij5zHrHVfqrlWXuIyMokLeRyIZ/ug8A==
X-Received: by 2002:a4a:dc99:: with SMTP id g25mr21531053oou.64.1600366567007;
        Thu, 17 Sep 2020 11:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e547:: with SMTP id s7ls174466oot.11.gmail; Thu, 17 Sep
 2020 11:16:06 -0700 (PDT)
X-Received: by 2002:a4a:d04c:: with SMTP id x12mr21570472oor.61.1600366566599;
        Thu, 17 Sep 2020 11:16:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600366566; cv=none;
        d=google.com; s=arc-20160816;
        b=H6wW9QrAWopitcc3OEb+Sjy//Du6DmwLALIJS77pHhY/xqSoC00/v1olcSO5PdZNkW
         GxcuxticJC/ZJxRaikXnLSAn8u/vvayZUjh/SD9rteQqtPhyfDXXVai2PSVDU0XCZRji
         teqUAaB/yZ8Pv3Lp1A7l18ZrKxWKb1jEvAGSymPRX6X+krY9oh6Ivtl2F7EBWiBa47mA
         w0LDGTpicBDfbpiU2v7/3zddKNls+sGZzG9K2lRYXXdS+oUVt79T2ikkRzlsOG2OBwbR
         wY9nCc7GgWHx8Xn2tR19WS3NtLE/7rjNEvwNSnoMlnEM9x8zHHAHouxFUKbQeSdxySlN
         DwCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pJlz1lyl7aTxHeTmVzs1SzNTrj8gWqaynH0CCR1cE3c=;
        b=jVJzLIE0McEl3rmpKLFAT0bYpqlikF7/STqyK5mlzHhVXD9BfKsFpOaoW0zzB8vbyF
         em1aN4s/ZsUmB8vFYNEvPI65KzIh+iZJUsu6M5RCpjxmfbYJmQt5gwzIn/EmZrmGAK9K
         yqTE5vsTFjz7tMK/olf0AnfthtWq7Nb7NM17rb1kwOJ7804/tKARejUAti+jciRArupd
         YW6OzBDp/zOqdqTRd6YXRGckdsr19dHAhoBQONf3fEa0+//YzwoUVmUMMaRxCITby8CW
         NuGxj+bkfHdKCO+zHceSjwP4vEWimQP2/Pw8fWrbxALnxXVLmpWpajmLmc8po66j9eKz
         Qp1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vxxCO7Jr;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id k144si48335oih.5.2020.09.17.11.16.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 11:16:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id q12so1546553plr.12
        for <kasan-dev@googlegroups.com>; Thu, 17 Sep 2020 11:16:06 -0700 (PDT)
X-Received: by 2002:a17:90a:e517:: with SMTP id t23mr9138243pjy.25.1600366565663;
 Thu, 17 Sep 2020 11:16:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200917084905.1647262-1-ilie.halip@gmail.com>
In-Reply-To: <20200917084905.1647262-1-ilie.halip@gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Sep 2020 11:15:54 -0700
Message-ID: <CAKwvOdkBPrdekTsMnhvN2OH-vk1eLU+ZC-1MJ5jgA2FDq7Ja3A@mail.gmail.com>
Subject: Re: [PATCH] objtool: ignore unreachable trap after call to noreturn functions
To: Ilie Halip <ilie.halip@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Rong Chen <rong.a.chen@intel.com>, 
	Marco Elver <elver@google.com>, Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>, clang-built-linux <clang-built-linux@googlegroups.com>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Nathan Chancellor <natechancellor@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vxxCO7Jr;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::642
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, Sep 17, 2020 at 1:49 AM Ilie Halip <ilie.halip@gmail.com> wrote:
>
> With CONFIG_UBSAN_TRAP enabled, the compiler may insert a trap instruction
> after a call to a noreturn function. In this case, objtool warns that the
> ud2 instruction is unreachable.
>
> objtool silences similar warnings (trap after dead end instructions), so
> expand that check to include dead end functions.

Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Tested-by: Nick Desaulniers <ndesaulniers@google.com>
Reported-by: kbuild test robot <lkp@intel.com>

Thanks for the patch, Ilie!  With this, a
defconfig+CONFIG_UBSAN+CONFIG_UBSAN_TRAP goes from 82 unreachable
instruction warnings from objtool to 0.

$ make LLVM=1 -j71 defconfig
$ make LLVM=1 -j71 menuconfig
<enable UBSAN and UBSAN_TRAP>
$ make LLVM=1 -j71 2> log.txt
$ grep warning: log.txt | cut -d ' ' -f 2- | sort | uniq -c | wc -l
82
$ b4 am https://lore.kernel.org/lkml/20200917084905.1647262-1-ilie.halip@gmail.com/
-o - | git am
$ make LLVM=1 -j71 clean
$ make LLVM=1 -j71 2> log.txt
$ grep warning: log.txt | cut -d ' ' -f 2- | sort | uniq -c | wc -l
0

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
> Signed-off-by: Ilie Halip <ilie.halip@gmail.com>
> ---
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


-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdkBPrdekTsMnhvN2OH-vk1eLU%2BZC-1MJ5jgA2FDq7Ja3A%40mail.gmail.com.
