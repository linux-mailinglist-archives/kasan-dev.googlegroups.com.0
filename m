Return-Path: <kasan-dev+bncBCMIZB7QWENRBEE266CQMGQEZQN4HMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 56DC839D629
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 09:38:57 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id z8-20020a5e92480000b02904ae394676efsf7925165iop.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 00:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623051536; cv=pass;
        d=google.com; s=arc-20160816;
        b=rgX8kKtA5uE+xdymP1Xx22YN6W4Y1vIfZGIHLkAGbxu9gmNb4SfvoU4UC1WWRvs3U1
         7GiAZ+ziIF05rwnqQAC30TZq5H8eP99nGIC0bN1aPdgLHa+Ni9medjIDWRwpV+sEel+J
         UAvnZL4kjECtttci6zsvsjU60EBxbVqwdTb1nVQdk67wxYNawM21lcI6vigvsUG7OhJj
         +CdAR3PFwBYHxBSuM30Q6c47cbLYAGb/v9CQ8MwM0hiTCwZGohU4afMEpSus0RpF4dYo
         /bBonbL/665IJkAgTN6aGzmp/dZe2vj3Fh9rJC6tMDjyK+Izs/fGF4GAKGoR/jrcz/IY
         TXZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5l4isBzuGB87NRz6amxw4/vAf8WzuLUuq4giduhu4uc=;
        b=FT5lm0+AxJj9Wz4bQLFqjG9VsTymp7akhE7ulN+YR1egNomLLts5gn3i+Qab/rXLYR
         hjX4b+a25moCcigHbwXxhcCgjbwwlDcPPw0cVXP3Fp377MlxrqN2e/zXOdxD1hLC/nxe
         IjseL85hw48gsj2orx0msaIROgn2wqlVFzeJGw8P/OJcdjZYdZ3K5EZgSefFwYRu5Umr
         FaGufd6iRBm3t5fSJ6KSM+yLOQsUaxyT7yjHENdRI5tj970tHQaKIrZ4REtFUlLms0An
         vNLm3NQRPRMzWwKCl594ubcBPn8zoaDbcJrn44tvAlXRnbRCKJa31hWDdC5lXV5x/I+M
         1Uxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nHm4WK6c;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5l4isBzuGB87NRz6amxw4/vAf8WzuLUuq4giduhu4uc=;
        b=LkPYxyzVU8ShNBtXzhuNefgldt/9ZUVNmRyk0yVb01Hqexglfe0aSb1ymWFuUisbgj
         iRbYBSfgST7mJWY76mqkE7FCwwokK6S4jSucItwW+s564QScFRXNan2vGgVGBuSWyEyF
         obGiDzCAJlMwB/SQJSOEWapYeiQpq4vWxlZcRwTytW+THq1Zf3GZ7Er7LY4ESvBlCwrM
         J9kznitVQLAgBrSuCKxxgB7h8AGki5nFN23ZM0o70zm8gDFnd3K+fXb1XptCknpvEZRP
         bHSt+SHcuc7KcwXeuLOcA1uM2gWptBTD98eUWi1ZWksx6VlhplqTRjQCvUStL0sGKIJH
         zonw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5l4isBzuGB87NRz6amxw4/vAf8WzuLUuq4giduhu4uc=;
        b=LCCc2pI21bH3AjlABzZpA4Jo9xLiJpJy4P85V5Uxe4ipuI9JjySomBlBOC9qxuMYjM
         Zw2uPmNKEX3kSRoVKXG++7o2yVFMmqhyefd8/Suslo5wNf3X7RvFDvuPloUY1HgNVK7Q
         iXsRH8ia9S8fZh9zSvldLIIvk7OnaGZtXC4VpJc9nM3xFQ0yYJKGgXrFUhR+PUwth51q
         rupbei3tM/k7UDq2EtmbFyW/des9XIqWD5nwf5A2PB9oMI3nnntoXymzB5T9mLLSSyrY
         GwSfb/KcjxnbS0hOhbiXpQaUWTTR7ykg8/TJ31AIbzyul48BEEm8IbanSC7mASbj0Tgn
         tevQ==
X-Gm-Message-State: AOAM531qxF3hs/T6q2n5VaOv0A4EFBoK1XWf81grHtgWWRIpNHpuQVbW
	v/+5gKk/0oJTh5+9C5/biAE=
X-Google-Smtp-Source: ABdhPJzkw05hAdGnVe5q2pjiFcNT6mAJYFGO1EM2+CU6mrO2kDN0N2NivbkhXpjEA5bAxvUF7AtGNA==
X-Received: by 2002:a05:6e02:525:: with SMTP id h5mr5145035ils.212.1623051536178;
        Mon, 07 Jun 2021 00:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce87:: with SMTP id r7ls152087ilo.6.gmail; Mon, 07 Jun
 2021 00:38:55 -0700 (PDT)
X-Received: by 2002:a92:7b0f:: with SMTP id w15mr14143513ilc.150.1623051535903;
        Mon, 07 Jun 2021 00:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623051535; cv=none;
        d=google.com; s=arc-20160816;
        b=PAwYcMaFHXTMMF3IE+nRjAkhjdKqMgA2zubWpUyHw0a4pVyXN1m8vKyhUq57Y07CG6
         0G+lf0adLdKjHJ3w7ylesSCc5y91H3OBj4a/mksCVrWHn4mqEAS3opfLLhblQb9bF6+L
         7NQ42TICXif2qyxaA6076dVNMj1GgB4HXpZohB1iMDagetZx7N+PkOOiPzLnuYnXNQNo
         8S7oa/AAEnYB/ktsqtZBdv/UgUdz+Zw6FUGgL/Yy1zZiJBl8/did6tQBG01mlPl1ipu4
         QR4AKueN9DDfUPH3XVz5jR4WgkYkIhlB00yfPkC+Pbi9sDhkYl89aZ8NGwYCEODIYCJg
         QU+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FkDnZkLm7S26Fub+7GJQrbQgH8zlz9fkqHVVt8EUVII=;
        b=NJ0WAKQjLT0Li12CQmNNXQxU1819ZiTpFSj3WUFpiDAgk2J+Izp/9W8UyOIu+CMqBW
         wVerlJfC7vbTCw1Fu451PpF3sRfhWFci0VWCc3RLGTXRSHBsSPvwdRcvr9AajwLD4Q0A
         5gZKnjWdrJq5i8MZYSbEDQVKFVvjDGnAIMSxZdB+9zMmYMKRvyso3BDU40bYF94vHE76
         uO9n9g7qWjiK4u/nEFhGzoKTsL9jV5C7XD3tmjSUr2a5jEoLPJDlqi1pjcpDS4ue4eR4
         i2uVl7vNyRkYr983CyfXCb7hcUqvEUmE8pOMWlc3EGAmEncjpIaCwK2e0xWw3JLF5zmy
         zvGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nHm4WK6c;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id f9si1303718iop.1.2021.06.07.00.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 00:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id u20so3694752qtx.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 00:38:55 -0700 (PDT)
X-Received: by 2002:ac8:7c4e:: with SMTP id o14mr14825948qtv.290.1623051534847;
 Mon, 07 Jun 2021 00:38:54 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000c2987605be907e41@google.com> <20210602212726.7-1-fuzzybritches0@gmail.com>
 <YLhd8BL3HGItbXmx@kroah.com> <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com> <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
In-Reply-To: <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jun 2021 09:38:43 +0200
Message-ID: <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Yonghong Song <yhs@fb.com>, Kurt Manucredo <fuzzybritches0@gmail.com>, 
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com, 
	Andrii Nakryiko <andrii@kernel.org>, Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, "David S. Miller" <davem@davemloft.net>, 
	Jesper Dangaard Brouer <hawk@kernel.org>, John Fastabend <john.fastabend@gmail.com>, 
	Martin KaFai Lau <kafai@fb.com>, KP Singh <kpsingh@kernel.org>, Jakub Kicinski <kuba@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Network Development <netdev@vger.kernel.org>, 
	Song Liu <songliubraving@fb.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	nathan@kernel.org, Nick Desaulniers <ndesaulniers@google.com>, 
	Clang-Built-Linux ML <clang-built-linux@googlegroups.com>, 
	linux-kernel-mentees@lists.linuxfoundation.org, 
	Shuah Khan <skhan@linuxfoundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nHm4WK6c;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832
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

On Sat, Jun 5, 2021 at 9:10 PM Alexei Starovoitov
<alexei.starovoitov@gmail.com> wrote:
> On Sat, Jun 5, 2021 at 10:55 AM Yonghong Song <yhs@fb.com> wrote:
> > On 6/5/21 8:01 AM, Kurt Manucredo wrote:
> > > Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
> > > kernel/bpf/core.c:1414:2.
> >
> > This is not enough. We need more information on why this happens
> > so we can judge whether the patch indeed fixed the issue.
> >
> > >
> > > I propose: In adjust_scalar_min_max_vals() move boundary check up to avoid
> > > missing them and return with error when detected.
> > >
> > > Reported-and-tested-by: syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
> > > Signed-off-by: Kurt Manucredo <fuzzybritches0@gmail.com>
> > > ---
> > >
> > > https://syzkaller.appspot.com/bug?id=edb51be4c9a320186328893287bb30d5eed09231
> > >
> > > Changelog:
> > > ----------
> > > v4 - Fix shift-out-of-bounds in adjust_scalar_min_max_vals.
> > >       Fix commit message.
> > > v3 - Make it clearer what the fix is for.
> > > v2 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> > >       check in check_alu_op() in verifier.c.
> > > v1 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> > >       check in ___bpf_prog_run().
> > >
> > > thanks
> > >
> > > kind regards
> > >
> > > Kurt
> > >
> > >   kernel/bpf/verifier.c | 30 +++++++++---------------------
> > >   1 file changed, 9 insertions(+), 21 deletions(-)
> > >
> > > diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
> > > index 94ba5163d4c5..ed0eecf20de5 100644
> > > --- a/kernel/bpf/verifier.c
> > > +++ b/kernel/bpf/verifier.c
> > > @@ -7510,6 +7510,15 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> > >       u32_min_val = src_reg.u32_min_value;
> > >       u32_max_val = src_reg.u32_max_value;
> > >
> > > +     if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) &&
> > > +                     umax_val >= insn_bitness) {
> > > +             /* Shifts greater than 31 or 63 are undefined.
> > > +              * This includes shifts by a negative number.
> > > +              */
> > > +             verbose(env, "invalid shift %lld\n", umax_val);
> > > +             return -EINVAL;
> > > +     }
> >
> > I think your fix is good. I would like to move after
>
> I suspect such change will break valid programs that do shift by register.
>
> > the following code though:
> >
> >          if (!src_known &&
> >              opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
> >                  __mark_reg_unknown(env, dst_reg);
> >                  return 0;
> >          }
> >
> > > +
> > >       if (alu32) {
> > >               src_known = tnum_subreg_is_const(src_reg.var_off);
> > >               if ((src_known &&
> > > @@ -7592,39 +7601,18 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> > >               scalar_min_max_xor(dst_reg, &src_reg);
> > >               break;
> > >       case BPF_LSH:
> > > -             if (umax_val >= insn_bitness) {
> > > -                     /* Shifts greater than 31 or 63 are undefined.
> > > -                      * This includes shifts by a negative number.
> > > -                      */
> > > -                     mark_reg_unknown(env, regs, insn->dst_reg);
> > > -                     break;
> > > -             }
> >
> > I think this is what happens. For the above case, we simply
> > marks the dst reg as unknown and didn't fail verification.
> > So later on at runtime, the shift optimization will have wrong
> > shift value (> 31/64). Please correct me if this is not right
> > analysis. As I mentioned in the early please write detailed
> > analysis in commit log.
>
> The large shift is not wrong. It's just undefined.
> syzbot has to ignore such cases.

Hi Alexei,

The report is produced by KUBSAN. I thought there was an agreement on
cleaning up KUBSAN reports from the kernel (the subset enabled on
syzbot at least).
What exactly cases should KUBSAN ignore?
+linux-hardening/kasan-dev for KUBSAN false positive

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb%3Dsi6NCx%3DnRHKm_pziXnVMmLo-eSuRajsxmx5%2BHy_ycg%40mail.gmail.com.
