Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ6I2D2AKGQEWW4KICA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 532F11A642C
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 10:35:53 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id l1sf6378475pld.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 01:35:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586766952; cv=pass;
        d=google.com; s=arc-20160816;
        b=UpvoN2FDMUnAntAfm9uJO5RfcQqXsmpR01ja14kjnuxbapoyVeIBlDa+H0gKoGMLCt
         pOrh7KqHxDnw+p9ztY1M2gpJEGu9CrjB9TsKFHkQ5ZzhEMvgQtnsQboN1gNTuHFwDcUY
         KMsBVYIkDO2k6hxUHydfT4xATOM8awmMpcXbqQOGKFFbgueRRHtuvxGIc3Otk0/vM53B
         BVRIdcip0l8HAhcFSRMlvn2Eden8pVSg7Z5mlbY9NXxwHXqVdhDcWGFFlQomwzleThpj
         e6HTF/7rVBIg6+z1Ke7Gw6n9Kdl2w9jHR1BSds0gqu25pldNndOpvIs15wSzk/cZm1lP
         BQRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WWl1qoIE4nGrmkNDd0xavowmNgtq86eaCF+mRpl9WOs=;
        b=juFVUcf/5qaibhjhuQ9HXBiOLWFBDr3rJ9qGPaQEyLZV29P/qb7Sfa9jxxcPps/85w
         yjAH7+BKQJezNEZ/kefw+T0aS0meMk5Dt2PpCbacW2zTaWBsdNzNGKmwhv91EE4k7vus
         fJqQAqqzG1058yIWuG3kfsV5r510aQVeRRcBUGupZueZxXqvVIjauCA9jkhYWMoD+SYi
         HjchWJLB+Qn2VHOxA/dhjyWtMwSrFVueNz85GkjHsWzZjAkMMLnkyLwUVk9zRRyywfmz
         bjG4xjXbQA6Eb96bMCFhteqDax1gNZ1JkjoBt1CCmMQViNcUOxs2CHC4e5oRZ2gu8NnO
         JbVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uD8A8qgO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=WWl1qoIE4nGrmkNDd0xavowmNgtq86eaCF+mRpl9WOs=;
        b=UfS1mS0eBbEr9M+Ol6qHa7Lc9hb81HHAfjf8NinBtEyOHZFMrnHRXrMKozFlTvm/CW
         zlj0HG2Z+uY9wytxMSeibuSOr0txQd0YS47XIVTLjKklGbdGRdzY4jBa9pn1GAwZ0RQx
         hH+NRYYveeWyMJweS6L6gx3DXXu5XWugialVO3indmmPaBw5cUP9b62cbigqJARUrjzm
         nHThh4qKJvB2jwnKKyn2jEjhkgKsXw6Fcru47dljHsHO0ljQEHcM/naUzD3i4YDupLYn
         nSms3BqXd1YH2X8f3851imHSJcJJw75dEiFdt2q+QrQ/RSfKWOgB4Ufyk44gyFyyYRx9
         9mMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WWl1qoIE4nGrmkNDd0xavowmNgtq86eaCF+mRpl9WOs=;
        b=Vu30hzyOTP00FrH0FQLwT9SFEsg04yzxr77f8amZCT3G064PUqUPDo9mMCOeMnE7WJ
         7ttywgN4e+0DzSpDpMpNps4ED4HYGDlLohjsHp2CMf9BYps1SNhmpRWR9O+wgnMHtxXo
         SfG7GSpEYDpH8jzFWv29Ndezo2tTbRMzkTFW2rWqQngLk6plqrTcEJMWYlA+uVIfwC70
         9jJygbUsEZroBfef8MvRglVw6HLb5YH7JKaM22GwngHsh5L/Az9E9WJEjU2abCzOl/O3
         f9OSHKl7ukKRI0PfsP9VlALopwpTNEhqcnV7Zf/CuH9STbJQlkkZblkHXfTDX2KWP5LZ
         dALg==
X-Gm-Message-State: AGi0PuYze8yTgDT2pBmAlIi6/NJOnUvjmLY+veX20bQfrvmfU4Qt7D5k
	Ju5zPt/up3RGeiJurxx7MTA=
X-Google-Smtp-Source: APiQypJkJFU/9kP5UIc94TbEOveazn7K/uh8c+mve29Icmj3bVPG6o+LWqx41DHtIxpqL1vmI292ag==
X-Received: by 2002:a17:90a:fa17:: with SMTP id cm23mr20945312pjb.121.1586766951727;
        Mon, 13 Apr 2020 01:35:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5f58:: with SMTP id t85ls13458808pgb.2.gmail; Mon, 13
 Apr 2020 01:35:51 -0700 (PDT)
X-Received: by 2002:a63:f151:: with SMTP id o17mr13244992pgk.221.1586766951253;
        Mon, 13 Apr 2020 01:35:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586766951; cv=none;
        d=google.com; s=arc-20160816;
        b=nT1zFQQyTGL3Gh4ozLAqgxzxoDfNDY0SYzVlGTZLKi6Jyk3XcOzCNs1a++2K1Y1rSN
         t3j+FyqHF6H8nIPNgOLV7u3LJOh+/4kBk5Gusv33kZBeat8vRgeybKMmjFP1FHTB82D5
         71/CApGpZD9upMvG7OfJAbbIoQgKBKNXckeRMoAtEuVmNehtPTSxrF04hHseCshOkmi5
         vVb/0OYCK6eXxXLJdtulkCv6vFgSgMZsnYeLWC8UaWe4mrziH8suuLKIgc6fbsWuPAiQ
         k/UlTpj8O0ueOqCjbWxvud86aTowXOVTx56t1M1dcTzbI+D+kg6UtXa5p7sEDnqZBNYX
         tDbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AvGw2BENomW5mAjLN7te1eswf7XokhztvBZamCcaYj0=;
        b=JlUvRLO02V/ydpUecFESheXbBXlU7gD90EggvENfCsJu/a4nyAtE4v/ItMpl5cMggI
         IwdhwnGFLScsb/47zMvsKlRIdtizyuVAarXv4ydo+LidrxuEJwLMDyNCjMeWidneYI2/
         mqxM6AaSdSIEfl9q+cqepYPXB0PNTBvZhjCteGALP/5pq9PdIPxFaHcXuL4eUynXNC1p
         zA2ID8bVveH517WVx5tqYUyWoS1LfTSObOoBxkUiaB02gaELiWoI2+PeMOMl0rJkTIvv
         klchharIN3YQbUFOOswCMC1BEYYKHo/JMLI1M/5DrHa1+hAOxObEWDWegpUmMCAI7xyq
         Z06g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uD8A8qgO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id 138si674018pfa.6.2020.04.13.01.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 01:35:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id j4so1775843otr.11
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 01:35:51 -0700 (PDT)
X-Received: by 2002:a9d:4b84:: with SMTP id k4mr3987928otf.233.1586766950301;
 Mon, 13 Apr 2020 01:35:50 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw> <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
 <C4FED226-E3DE-44AE-BBED-2B56B9F5B12F@lca.pw>
In-Reply-To: <C4FED226-E3DE-44AE-BBED-2B56B9F5B12F@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Apr 2020 10:35:38 +0200
Message-ID: <CANpmjNPSLkiEer3xQHHxJm_4o5Em0i3bvM7TMmNO46Vzv2cwWQ@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uD8A8qgO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Fri, 10 Apr 2020 at 21:57, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 10, 2020, at 7:35 AM, Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 10 Apr 2020 at 13:25, Qian Cai <cai@lca.pw> wrote:
> >>
> >>
> >>
> >>> On Apr 10, 2020, at 5:47 AM, Marco Elver <elver@google.com> wrote:
> >>>
> >>> That would contradict what you said about it working if KCSAN is
> >>> "off". What kernel are you attempting to use in the VM?
> >
> > Ah, sorry this was a typo,
> >  s/working if KCSAN/not working if KCSAN/
> >
> >> Well, I said set KCSAN debugfs to =E2=80=9Coff=E2=80=9D did not help, =
i.e., it will reset the host running kvm.sh. It is the vanilla ubuntu 18.04=
 kernel in VM.
> >>
> >> github.com/cailca/linux-mm/blob/master/kvm.sh
> >
> > So, if you say that CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn works, that
> > contradicts it not working when KCSAN is "off". Because if KCSAN is
> > off, it never sets up any watchpoints, and whether or not
> > KCSAN_INTERRUPT_WATCHER is selected or not shouldn't matter. Does that
> > make more sense?
>
> Yes, you are right. CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn does not
> make it work. It was a mistake when I tested it because there was a stale=
 svm.o
> leftover from the previous run, and then it will not trigger a rebuild (a=
 bug?) when
> only modify the Makefile to remove KCSAN_SANITIZE :=3D n. Sorry for the m=
isleading
> information. I should be checking if svm.o was really recompiled in the f=
irst place.
>
> Anyway, I=E2=80=99ll send a patch to add __no_kcsan for svm_vcpu_run() be=
cause I tried
> to narrow down more with a kcsan_[disable|enable]_current() pair, but it =
does NOT
> work even by enclosing the almost whole function below until Marcro has m=
ore ideas?

This is expected. Instrumentation is not removed if you add
kcsan_{disable,enable}_current() (it has the same effect as a
localized "off"). Since it seems just the instrumentation and
associated calls before every memory access is enough, this won't
work. The attribute __no_kcsan removes instrumentation entirely from
the function. If the non-instrumented code should be reduced, it is
conceivable to take the problematic portion of code and factor it into
a function that has attribute '__no_kcsan_or_inline'.

Thanks,
-- Marco

> diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
> index 2be5bbae3a40..e58b2d5a575c 100644
> --- a/arch/x86/kvm/svm/svm.c
> +++ b/arch/x86/kvm/svm/svm.c
> @@ -3286,6 +3286,7 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
>         svm->vmcb->save.rsp =3D vcpu->arch.regs[VCPU_REGS_RSP];
>         svm->vmcb->save.rip =3D vcpu->arch.regs[VCPU_REGS_RIP];
>
> +       kcsan_disable_current();
>         /*
>          * A vmexit emulation is required before the vcpu can be executed
>          * again.
> @@ -3410,6 +3411,7 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
>                 svm_handle_mce(svm);
>
>         mark_all_clean(svm->vmcb);
> +       kcsan_enable_current();
>  }
>  STACK_FRAME_NON_STANDARD(svm_vcpu_run);
>
>
>
>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPSLkiEer3xQHHxJm_4o5Em0i3bvM7TMmNO46Vzv2cwWQ%40mail.gmail.=
com.
