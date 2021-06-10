Return-Path: <kasan-dev+bncBCMIZB7QWENRB5OHQ2DAMGQE2FWKZBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E92AF3A2404
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 07:32:38 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id j9-20020a056e020149b02901ece9afab6bsf568999ilr.10
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 22:32:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623303157; cv=pass;
        d=google.com; s=arc-20160816;
        b=owZfsTuK30rirssMOuvTqcj/Olkvbmeq+iMcfeAX+R5vbazGURBR5Qv+1ArCrFuzY3
         mmV97sTBvh3TxskLGXxbiWlbv04e+O4mLeI5z1jCgyM/YJVg9x9Zl4zsffVGIIACrFjM
         PL7R2uRkgxCM/bXXkY1vUHO2fH6cm9a+2cUBYnkaZNCVsohRCk3/rJkYJJtyZVCcwVCh
         2XPPYy++un5uQbaZDS8RUZCl6obtdtSjPhhqXxw4xgCb7mG/9Z6XFaHjqhTD/3kNSuFp
         uug91V1mNZmBgHW93NljVlmlMv5RQh8XCmNzWyJYoBJpiJuJAaRBREKo0mXE/nL701Es
         GdIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5ecArVIE2kmx09rujF049kSamoF879A9UEiK+UE6T7U=;
        b=DJQtpSg5fa7tLorBIACJjrNHGnHleX8R0Dl+yVs3GCIYCdh6/5I+8BNbX7Z6BiB+LH
         SGwdFz+5/JEorUPw+BMUrtGZkZ3m4dVsDxtmflKdLjKidMqYHgW/ITI0rKP2LXkgO6aL
         kC2qKYECMUac74uBKuK8GHTE4PvUlbiy527nvitsdeQTn4tTLp75BiLqx+8QPFI1dNcG
         HBo991dAVVsfb3Rz/1GrIgGLHtw16WaKGwBuYF55jSOqv128c92jsK8ujKstrbJrJRSZ
         lVPw5yz1pobHCLX+fz4J+BIvfFpZsf78DuON6SXcPtsuy5KFtFdC4iUL31p7yDvcdNwB
         tWCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVuckSqO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5ecArVIE2kmx09rujF049kSamoF879A9UEiK+UE6T7U=;
        b=cGTT5T+Fp8Zobec7MoGHLXm5gyPDySgQIcgF9CezJnEP/8Qf/lADq/uDSVro3NVUsL
         27wskUFDuiAdc/rl9IfBWWw9Sf0YNrRVWVakf1Gi4jEIgbbJ/m/dejGRqnRapoT985VV
         Vy1r9bEjhdF53g3O4eQtexq7B+Hli+1kMMsgq6WdjDoia06GarAacgkJQsevsTvhZKWi
         FkCGiep1cWUIa8eABUc0rAVw8TEWJXuKFBQgqe7Vxh0dbRw0LXlbHu9t1wxDoSkZb+t+
         QfgaNV3RV+aXUoP3pIKaDqcWVyS3svuUyktE3V6xX0536wtU7RMaJEjSytU6iO+P60t7
         tc7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5ecArVIE2kmx09rujF049kSamoF879A9UEiK+UE6T7U=;
        b=hY7PyRDRxR27bo/eYxc18ZoJ8P0kmJDdp4H2Abyogs/sLCjJwDeAk/Ce+qiqkZtAVO
         aR205m3gza0XOw9yvxs/inMtH6lGu4Kdl3hq8OpFAb81ukb9LE31bGxPbAfya8PXWxFD
         k6LmiMXcjILogub8mJEY1f9tWNP8mN9LE8vrgCbtPRkveDdr5JLMcLWhbFvui/FJF3v7
         C7EfUGbhrtiGtYcG/upNUCjt/N25mvItiSNkTVdpbCU0XGwxrO5GR+UZOQL1fpMIiib5
         c6xXxX46UHDey5ID0/p4nozvob9jCZl9RPK6Z7vHwSDBMTVPTwl5AUkXr8iZ1iXkfQka
         n/zQ==
X-Gm-Message-State: AOAM533W9qSt2wfnZHyO3boPRKubSE7zMmx8ud0wl+GymcJfciwc7YbC
	GjNGX02TnLIN90pM1wnytGI=
X-Google-Smtp-Source: ABdhPJxDto3gPsgeZtLjJbhKepiqW2eJih1xIIujMMLP7cp8aMQfyiPLpe/VtinUQKuKw/LIwoSgBw==
X-Received: by 2002:a92:364f:: with SMTP id d15mr2641796ilf.26.1623303157696;
        Wed, 09 Jun 2021 22:32:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d902:: with SMTP id s2ls1368595iln.1.gmail; Wed, 09 Jun
 2021 22:32:37 -0700 (PDT)
X-Received: by 2002:a05:6e02:12af:: with SMTP id f15mr2662316ilr.266.1623303157389;
        Wed, 09 Jun 2021 22:32:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623303157; cv=none;
        d=google.com; s=arc-20160816;
        b=H32qOfjoN8uEkkoC/DXwwOe0pZfkoBH23MOBYvC/GiBxVl5vjrWAz/cGQeu1Ecr9Hq
         L/DDeYqB/h9pQ29naRBEkvm8/UBPOsGmLXQGX0ce/mMsu8gILQvc7V6SlShnBVRTsjv/
         uUb2NiEbNZao8FGF0aWGM1/fNMSW0QFdfiyByJ+13+5T+QF/2phh1Dkdbl8tJFQ15KW7
         SssN38QPkkjI3cpbGHGpeMrcgV58jxjwVvOtSnoxksCv1cuzCNrs6zy/afA9P0RmTfgy
         pvHMLwRjJ6C72UON8S7cNZkfGpnZceN6C9YxccVq0p2kitKHkGF25tjIP2IUdDZd/eSz
         qwOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OaVwnGtK9jh2uHt5Ipx2vrWPn+KDUOXrS2y79saIzrk=;
        b=HstnVloujLb1ZIpqg1MmqgMxrX535+SLSRJO3CTcYkYKMzhEDXosfI1/xkyGfvCY27
         SFxpSz6v9hYUiXQYMJeK7l/vCC1VG9fgN1KbtOMaSSQU5ZDoKc6mo7PNDAZDNqwQdro/
         97RO1DdXbgdeSAM4xt5tkdGA2di1PlnvYHE4sOOZ/H7Cs60/h0LQvs+UcaFKedOLiVv5
         er9nx5YqKvdoM9vxiiPSioKSiyyHMzhJms/i8zv3ITyZPE57U13Z0mbbhO+Z/e+f6TNe
         O08WPr4temkQ0M9vmRGjgNJTXdugRUIojkpICmlCFH83JfJvFiWGPD+LZq2JNVAXtcTq
         4oVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVuckSqO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id v124si230692iof.2.2021.06.09.22.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jun 2021 22:32:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id l3so7068633qvl.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Jun 2021 22:32:37 -0700 (PDT)
X-Received: by 2002:a0c:d610:: with SMTP id c16mr3488166qvj.13.1623303156474;
 Wed, 09 Jun 2021 22:32:36 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000c2987605be907e41@google.com> <20210602212726.7-1-fuzzybritches0@gmail.com>
 <YLhd8BL3HGItbXmx@kroah.com> <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com> <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook> <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
In-Reply-To: <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Jun 2021 07:32:24 +0200
Message-ID: <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Yonghong Song <yhs@fb.com>
Cc: Kees Cook <keescook@chromium.org>, 
	Alexei Starovoitov <alexei.starovoitov@gmail.com>, Kurt Manucredo <fuzzybritches0@gmail.com>, 
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
 header.i=@google.com header.s=20161025 header.b=LVuckSqO;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f30
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

On Thu, Jun 10, 2021 at 1:40 AM Yonghong Song <yhs@fb.com> wrote:
> On 6/9/21 11:20 AM, Kees Cook wrote:
> > On Mon, Jun 07, 2021 at 09:38:43AM +0200, 'Dmitry Vyukov' via Clang Built Linux wrote:
> >> On Sat, Jun 5, 2021 at 9:10 PM Alexei Starovoitov
> >> <alexei.starovoitov@gmail.com> wrote:
> >>> On Sat, Jun 5, 2021 at 10:55 AM Yonghong Song <yhs@fb.com> wrote:
> >>>> On 6/5/21 8:01 AM, Kurt Manucredo wrote:
> >>>>> Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
> >>>>> kernel/bpf/core.c:1414:2.
> >>>>
> >>>> This is not enough. We need more information on why this happens
> >>>> so we can judge whether the patch indeed fixed the issue.
> >>>>
> >>>>>
> >>>>> I propose: In adjust_scalar_min_max_vals() move boundary check up to avoid
> >>>>> missing them and return with error when detected.
> >>>>>
> >>>>> Reported-and-tested-by: syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
> >>>>> Signed-off-by: Kurt Manucredo <fuzzybritches0@gmail.com>
> >>>>> ---
> >>>>>
> >>>>> https://syzkaller.appspot.com/bug?id=edb51be4c9a320186328893287bb30d5eed09231
> >>>>>
> >>>>> Changelog:
> >>>>> ----------
> >>>>> v4 - Fix shift-out-of-bounds in adjust_scalar_min_max_vals.
> >>>>>        Fix commit message.
> >>>>> v3 - Make it clearer what the fix is for.
> >>>>> v2 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> >>>>>        check in check_alu_op() in verifier.c.
> >>>>> v1 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
> >>>>>        check in ___bpf_prog_run().
> >>>>>
> >>>>> thanks
> >>>>>
> >>>>> kind regards
> >>>>>
> >>>>> Kurt
> >>>>>
> >>>>>    kernel/bpf/verifier.c | 30 +++++++++---------------------
> >>>>>    1 file changed, 9 insertions(+), 21 deletions(-)
> >>>>>
> >>>>> diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
> >>>>> index 94ba5163d4c5..ed0eecf20de5 100644
> >>>>> --- a/kernel/bpf/verifier.c
> >>>>> +++ b/kernel/bpf/verifier.c
> >>>>> @@ -7510,6 +7510,15 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> >>>>>        u32_min_val = src_reg.u32_min_value;
> >>>>>        u32_max_val = src_reg.u32_max_value;
> >>>>>
> >>>>> +     if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) &&
> >>>>> +                     umax_val >= insn_bitness) {
> >>>>> +             /* Shifts greater than 31 or 63 are undefined.
> >>>>> +              * This includes shifts by a negative number.
> >>>>> +              */
> >>>>> +             verbose(env, "invalid shift %lld\n", umax_val);
> >>>>> +             return -EINVAL;
> >>>>> +     }
> >>>>
> >>>> I think your fix is good. I would like to move after
> >>>
> >>> I suspect such change will break valid programs that do shift by register.
> >>>
> >>>> the following code though:
> >>>>
> >>>>           if (!src_known &&
> >>>>               opcode != BPF_ADD && opcode != BPF_SUB && opcode != BPF_AND) {
> >>>>                   __mark_reg_unknown(env, dst_reg);
> >>>>                   return 0;
> >>>>           }
> >>>>
> >>>>> +
> >>>>>        if (alu32) {
> >>>>>                src_known = tnum_subreg_is_const(src_reg.var_off);
> >>>>>                if ((src_known &&
> >>>>> @@ -7592,39 +7601,18 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
> >>>>>                scalar_min_max_xor(dst_reg, &src_reg);
> >>>>>                break;
> >>>>>        case BPF_LSH:
> >>>>> -             if (umax_val >= insn_bitness) {
> >>>>> -                     /* Shifts greater than 31 or 63 are undefined.
> >>>>> -                      * This includes shifts by a negative number.
> >>>>> -                      */
> >>>>> -                     mark_reg_unknown(env, regs, insn->dst_reg);
> >>>>> -                     break;
> >>>>> -             }
> >>>>
> >>>> I think this is what happens. For the above case, we simply
> >>>> marks the dst reg as unknown and didn't fail verification.
> >>>> So later on at runtime, the shift optimization will have wrong
> >>>> shift value (> 31/64). Please correct me if this is not right
> >>>> analysis. As I mentioned in the early please write detailed
> >>>> analysis in commit log.
> >>>
> >>> The large shift is not wrong. It's just undefined.
> >>> syzbot has to ignore such cases.
> >>
> >> Hi Alexei,
> >>
> >> The report is produced by KUBSAN. I thought there was an agreement on
> >> cleaning up KUBSAN reports from the kernel (the subset enabled on
> >> syzbot at least).
> >> What exactly cases should KUBSAN ignore?
> >> +linux-hardening/kasan-dev for KUBSAN false positive
> >
> > Can check_shl_overflow() be used at all? Best to just make things
> > readable and compiler-happy, whatever the implementation. :)
>
> This is not a compile issue. If the shift amount is a constant,
> compiler should have warned and user should fix the warning.
>
> This is because user code has
> something like
>      a << s;
> where s is a unknown variable and
> verifier just marked the result of a << s as unknown value.
> Verifier may not reject the code depending on how a << s result
> is used.
>
> If bpf program writer uses check_shl_overflow() or some kind
> of checking for shift value and won't do shifting if the
> shifting may cause an undefined result, there should not
> be any kubsan warning.

I guess the main question: what should happen if a bpf program writer
does _not_ use compiler nor check_shl_overflow()?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc%3DoA%40mail.gmail.com.
