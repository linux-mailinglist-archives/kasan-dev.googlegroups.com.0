Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5EMQSDAMGQEOU5PHVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 556913A1C9E
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 20:20:39 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id x22-20020a1709028216b0290112042155c8sf6235728pln.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 11:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623262836; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1ikCaTZxD/mhT4d6DB0XuPq7CPkfBjI54klOujwV202S4gr/C/tdmnY0iqsTYyJKA
         kD9ocszM0IDCIVbSg9u+cflr++3zEjaa4/vtIwfchA3CNp3Cy/f9Mw1F0H0j1ZZy61oA
         m37c5q2J7jF5W7aleL3t2sYrT39qtRI4Y5tBI/01mIWLEU/91AN0nUJzYDJhQy6+O91c
         yDhHlrXPE9a3hDx1W05PbXn9eWQvHre/9Sg0PR+roJUCO7GLOYXlsF5GWe0uUJHdbduE
         awpwRUp47nS24w3LaIvBvcSF643LCAoXyMzVQaoDvEr25/LE1AgmCJ6UYnAZsjC7xmAy
         xEAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ujKTjpDufUskWCLGe6CeSm249oIJQEgOP3bCT9uZLe0=;
        b=cHEaNrDqwrykd4Ps3s2BdQ9DexSCrXBfIU2GmhG8EL3eJfXAbW7Dgd6fLdexy0ZTpM
         qhrRI8mwE67d90lGTJBMDQPm4Oemeta1zL1zmTF66Ca/BuFun51Pow8qeiHj/V4vSWOl
         fesnZ1S0RfrP+tQ9MHvLT3KA/CnUbim8KqRstxN08vOfAL7Hv/Q3HIyk4h6lEnpgIzAg
         VyECi9tYh2b9IxCuboLnDTqkI2VEMRXgDb9YQ+/CwO2MBL4lokPwmpRM48ARPgf84/QT
         EN3fi6M9P3Q04Mpfbfw0ZRlkz/qrDyQUFu61O2TPhfElr/jXO6tG9BNXbGNBwAoASH3v
         X0wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PazdJpi7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ujKTjpDufUskWCLGe6CeSm249oIJQEgOP3bCT9uZLe0=;
        b=gLMohomjhSf+TKGXjZ/4AtYFoLVV6jo4sBmE3kPEh4VlloGpYeAntEOaMEV8C10BYa
         IUMGHz3lWREkBNLHfsJ+92/bk5XURWn9QSDN5W46KvVIk7Zi9jn7UP8rzDSn39PvcTbd
         e61EErf3LANuUBgtIQ3xyJP2k041BXLSGhSCp8FZB5Na3zaWU06jao5KRknyCv7aGndK
         2cK6/8/zyBf6T6j9+jLVOVNbb6QHkQ8EbnLXJH/cNCrTDev0e491HmmpAzURfOmbeymM
         Z5Mne4hXDtoCacfZ4CzhMzBZCygrDMwG14rND4wYdW1Bd9zYfhS0WvgSvHNtUiDcRT8v
         /h+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ujKTjpDufUskWCLGe6CeSm249oIJQEgOP3bCT9uZLe0=;
        b=nguWmB4mnRGtkj3VgosEPFw27GBHEJrI82YEOL8U51n/9VAj9bOgoZjFaJ+O61Jree
         oAu+SLiLtA7ppRqUBZKUAtoop6td1X4isysjxM8oq0ner1TQdlZpRMTNojUXO6dH2I+0
         3DN90LfwEqEI9enuSyR1vu+O7J0c952bDWFrSqQsIB/7nnnw5zL5W8dz14mWCoazy2YC
         SIDtf2N9JRbXM+/9iTJ6zphJkiqPSThgX1WyrDpxpNk6o7Kc5w2BGkYBU0DXf2kefuoV
         8x8IVdJqds66DKgK6+Nx5JsIszaOXQ2YFOWnh5leZIUseXqWE/1huBQ+sLvc83JNi783
         UM6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JeZHsCKeKznE4s3bQl+Lgo2KX3TBD7hCH2sgNbI6dkKHvDYUB
	DdepFYRg3nfXGt5HVa2xMrc=
X-Google-Smtp-Source: ABdhPJxr4DJ3G0uaEaM/1IuOOclE0j0f8e9Mcii3L/VDel+9Fm57PL2kkPfkie5Imo77MJVUVV4Sng==
X-Received: by 2002:a17:90b:1197:: with SMTP id gk23mr834809pjb.71.1623262836595;
        Wed, 09 Jun 2021 11:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd47:: with SMTP id a7ls1587351pgj.1.gmail; Wed, 09 Jun
 2021 11:20:36 -0700 (PDT)
X-Received: by 2002:a63:cd16:: with SMTP id i22mr944767pgg.251.1623262836002;
        Wed, 09 Jun 2021 11:20:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623262835; cv=none;
        d=google.com; s=arc-20160816;
        b=gXVjgQhdEcfV+4zv8RWwP7tBuVwsKqcXcvOiDCyEZPwm4p8l46x8y74/SBwIIbj1a0
         cJUi2wrI92STcvFqSioVEjA/1bjVy2SK8AmkP7+V2tAbP6A6xl5HPoAPoDzDeqwwvHkk
         IheskhyXx4soeBe/HTTdZPByI150RQ/o80XjfOLtjhoMAVRZmM89I6foh2sADQ6VwOE4
         FKFsB36Spm6dXwrgCph8W6T7jeZXMIvOkqzu71NFJ4XzwEvFbjolxVIKo9LyHcG01WdB
         mq0/1fBBFdlxvUxmgbTDOm2jojfxJYxuUPOIfyxlZmQdhuJHCEozOSjnD5+v+H245VPM
         9SGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pMNtPdB4yeaOaJg4oKXM0D8sPt6m955IeGjoIXPrk70=;
        b=cZ6qgaSDBbFKgbOHafv90I0cIyb2LbH8/n7LQknvh0pbj4FXtIEFMExQTrERp9KW1t
         jYYeGceNVpIhYTu07RXvKH643NzErNAmgoweiBqnzuSxsRNd4fB15cfLZagVaZBTkVCQ
         fdBLNYEecPkRvFe7inqnEVU4/7Xnvz6hKqyYHRTEMoxeyOnxu4UeZd8SEOYM1dx05C2k
         JOm4dS1GcQxuDjHY50WAql2uKMyu+PtApdlCcryw93U9wL6b9cz6fWwDKuJ4a74gXxQB
         OUepdcD/8QzKljs108wgVbOhc+XYP0FTs7DtFtdHNSs9D8MX8r7oWY2cLEaoq6zv/9W/
         LSAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PazdJpi7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id n5si93904pgf.5.2021.06.09.11.20.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jun 2021 11:20:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id s14so18189326pfd.9
        for <kasan-dev@googlegroups.com>; Wed, 09 Jun 2021 11:20:35 -0700 (PDT)
X-Received: by 2002:a62:3444:0:b029:2ec:9658:a755 with SMTP id b65-20020a6234440000b02902ec9658a755mr1010418pfa.71.1623262835683;
        Wed, 09 Jun 2021 11:20:35 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id p14sm445214pgk.6.2021.06.09.11.20.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jun 2021 11:20:34 -0700 (PDT)
Date: Wed, 9 Jun 2021 11:20:33 -0700
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
	Yonghong Song <yhs@fb.com>,
	Kurt Manucredo <fuzzybritches0@gmail.com>,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
	Andrii Nakryiko <andrii@kernel.org>,
	Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	"David S. Miller" <davem@davemloft.net>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	Martin KaFai Lau <kafai@fb.com>, KP Singh <kpsingh@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Network Development <netdev@vger.kernel.org>,
	Song Liu <songliubraving@fb.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, nathan@kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Clang-Built-Linux ML <clang-built-linux@googlegroups.com>,
	linux-kernel-mentees@lists.linuxfoundation.org,
	Shuah Khan <skhan@linuxfoundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Kernel Hardening <kernel-hardening@lists.openwall.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Message-ID: <202106091119.84A88B6FE7@keescook>
References: <000000000000c2987605be907e41@google.com>
 <20210602212726.7-1-fuzzybritches0@gmail.com>
 <YLhd8BL3HGItbXmx@kroah.com>
 <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com>
 <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=PazdJpi7;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Jun 07, 2021 at 09:38:43AM +0200, 'Dmitry Vyukov' via Clang Built Linux wrote:
> On Sat, Jun 5, 2021 at 9:10 PM Alexei Starovoitov
> <alexei.starovoitov@gmail.com> wrote:
> > On Sat, Jun 5, 2021 at 10:55 AM Yonghong Song <yhs@fb.com> wrote:
> > > On 6/5/21 8:01 AM, Kurt Manucredo wrote:
> > > > Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
> > > > kernel/bpf/core.c:1414:2.
> > >
> > > This is not enough. We need more information on why this happens
> > > so we can judge whether the patch indeed fixed the issue.
> > >
> > > >
> > > > I propose: In adjust_scalar_min_max_vals() move boundary check up to avoid
> > > > missing them and return with error when detected.
> > > >
> > > > Reported-and-tested-by: syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
> > > > Signed-off-by: Kurt Manucredo <fuzzybritches0@gmail.com>
> > > > ---
> > > >
> > > > https://syzkaller.appspot.com/bug?id=edb51be4c9a320186328893287bb30d5eed09231
> > > >
> > > > Changelog:
> > > > ----------
> > > > v4 - Fix shift-out-of-bounds in adjust_scalar_min_max_vals.
> > > >       Fix commit message.
> > > > v3 - Make it clearer what the fix is for.
> > > > v2 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> > > >       check in check_alu_op() in verifier.c.
> > > > v1 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> > > >       check in ___bpf_prog_run().
> > > >
> > > > thanks
> > > >
> > > > kind regards
> > > >
> > > > Kurt
> > > >
> > > >   kernel/bpf/verifier.c | 30 +++++++++---------------------
> > > >   1 file changed, 9 insertions(+), 21 deletions(-)
> > > >
> > > > diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
> > > > index 94ba5163d4c5..ed0eecf20de5 100644
> > > > --- a/kernel/bpf/verifier.c
> > > > +++ b/kernel/bpf/verifier.c
> > > > @@ -7510,6 +7510,15 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> > > >       u32_min_val = src_reg.u32_min_value;
> > > >       u32_max_val = src_reg.u32_max_value;
> > > >
> > > > +     if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) &&
> > > > +                     umax_val >= insn_bitness) {
> > > > +             /* Shifts greater than 31 or 63 are undefined.
> > > > +              * This includes shifts by a negative number.
> > > > +              */
> > > > +             verbose(env, "invalid shift %lld\n", umax_val);
> > > > +             return -EINVAL;
> > > > +     }
> > >
> > > I think your fix is good. I would like to move after
> >
> > I suspect such change will break valid programs that do shift by register.
> >
> > > the following code though:
> > >
> > >          if (!src_known &&
> > >              opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
> > >                  __mark_reg_unknown(env, dst_reg);
> > >                  return 0;
> > >          }
> > >
> > > > +
> > > >       if (alu32) {
> > > >               src_known = tnum_subreg_is_const(src_reg.var_off);
> > > >               if ((src_known &&
> > > > @@ -7592,39 +7601,18 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> > > >               scalar_min_max_xor(dst_reg, &src_reg);
> > > >               break;
> > > >       case BPF_LSH:
> > > > -             if (umax_val >= insn_bitness) {
> > > > -                     /* Shifts greater than 31 or 63 are undefined.
> > > > -                      * This includes shifts by a negative number.
> > > > -                      */
> > > > -                     mark_reg_unknown(env, regs, insn->dst_reg);
> > > > -                     break;
> > > > -             }
> > >
> > > I think this is what happens. For the above case, we simply
> > > marks the dst reg as unknown and didn't fail verification.
> > > So later on at runtime, the shift optimization will have wrong
> > > shift value (> 31/64). Please correct me if this is not right
> > > analysis. As I mentioned in the early please write detailed
> > > analysis in commit log.
> >
> > The large shift is not wrong. It's just undefined.
> > syzbot has to ignore such cases.
> 
> Hi Alexei,
> 
> The report is produced by KUBSAN. I thought there was an agreement on
> cleaning up KUBSAN reports from the kernel (the subset enabled on
> syzbot at least).
> What exactly cases should KUBSAN ignore?
> +linux-hardening/kasan-dev for KUBSAN false positive

Can check_shl_overflow() be used at all? Best to just make things
readable and compiler-happy, whatever the implementation. :)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202106091119.84A88B6FE7%40keescook.
