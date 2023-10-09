Return-Path: <kasan-dev+bncBD5N3VM65EKRBK47SCUQMGQESI4PGDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A3277BE2F2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 16:35:26 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2bfe9ed93easf37148841fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 07:35:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696862125; cv=pass;
        d=google.com; s=arc-20160816;
        b=XT2f1Jo8Fl5r/ZjgF/yIKYaPCIH1Tn6iyldtJo3MzEnuG3RkhUdRRltc05B/7/golV
         DUmgVg0qXmeEQ+IDCsdZLNKYsUiXh/txm3xZlbNXIEMKQj1VK/9AtZBn51boV0jkWKpE
         qtfSscyCsanMMKwxwqGSVZkuajXreR5jmDeqEGXe8TomxnR3k1b8nGUT7JHtKZBPNKH1
         LSatxQPvltu50cPNzgv8cLDkHMYtUaNTDc9U/5FMzdgaeZDf9CpYN78pMLE5shpt5+Ks
         aOrybUo2Q16O3CI0BSG3U07PUDMlaPF1nC9wdvtHK2mM2Ys8RuNVUGnJmZmZybhAMkP5
         KklA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=oSvpaGquCPPVMzRn0PZQ2DdEg3UxSWmTTIYjUNnctvk=;
        fh=ipa6FZjW80JJ+zjVaBa7Ytd/cuQaea4wbq9a/8Bo9EM=;
        b=jaFAxbsRZ3DaY+PhD7EZAGchh7Ahb9St09uYY95GVj5gijAgXl0b0/5spWV2Dej0d/
         t64aPHcfknSeB/7m1cnIUIBmoQAL4OwvA1gc6MkAmi1bFwLFSCiLSGs4sYv6Ijdcah1H
         4cEGJ13XyFkm0COsvqJsegzsqWxhr0VgrQXmr3ozDhffP/Wed39/Hh/ZuXXa3sIFhX01
         YupW0Q2bnOB6y09aaEbwmPZNPquNdM+NU1eVS8fMdY5a80O3wu2QKtzQNEKLIocYd7NJ
         1MfdyKM4QiljhfiAhttyb6ehghXD3Qygp4FwCrOcQZUvtqd4Sqsb3rJQleQM2m6znFyc
         Nqjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WXpBAh4a;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696862125; x=1697466925; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oSvpaGquCPPVMzRn0PZQ2DdEg3UxSWmTTIYjUNnctvk=;
        b=rMgMbZ4Tqj+AVaMpYwxSXFdiNInhCnOXfAQVMd+SroMgQmbLq78EsoiggV8jpdZ7h2
         UuAXv6zWxJDul9uAIoGIW4tKmiD5SJshK0TmbgMXmptTlyVLbOscrqmWawmwrTkkLoXQ
         qkKSi5C57HitCvfPLpc3d8oiiuCSxcTvI25wf5uAYaHod5Tbq06z/FNcPNhgme1Av+CG
         vX4AnLHpzGkzyJWcCrzfWUNLV4mLb9/xxLHkI3QcE4hHKmA/4qDYpCWCMAoZxdu/+7Mf
         KTA8EPdsmfy4VTNjwo4k0JV8Hxgl+hvPn7Mky5IoHDfdawxu6LXz30uxuT0/+R9avcA7
         EbGQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696862125; x=1697466925; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oSvpaGquCPPVMzRn0PZQ2DdEg3UxSWmTTIYjUNnctvk=;
        b=JeoPXbSRMdX2rZ/0vuNDFpfS5bybOBOmrqrlGn/kEPkcE1MwqdqZrzYTZwCh9YgzTe
         yg/2klYCNFU/u3Mh++0rkjNPB9/oRuWwqcHVL2IbsbBnRRmFsivI7bQvWXqU2h7crOU3
         rJFdx0eiSEWR6BR6iQ3nTN7yacZk3vwzDsJEa8RCR4vbx7ld82bl9zzh1ZqXSqL5ncJe
         ZKdYP2U1CV237S0y+L8ZIVzLtozdpIu5mGX4s/Vn3inKx/Kte5S3T4iqA9cMtccwZIg+
         3NB0D5uJJiJukjx17fJsjKFD8KwprJoLFml5plXlHpzv/JQuh0qhmtmZpmQtacdkYm57
         yuCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696862125; x=1697466925;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oSvpaGquCPPVMzRn0PZQ2DdEg3UxSWmTTIYjUNnctvk=;
        b=M2RoonVDRgtFwUbL0Sg3FSiJg6YoDx7VJ1HwFF4L35BRfk+K52Mkxcmim76MzGsXqj
         VstMXwhAhJsac+5GhwfJDRaDX8Y+GjGeJ1rnASRZfsgLFYQjLKtSDUIk3ud45hEW6RcN
         tASN7KoaLodThfoE3IYuQxrrOmSDRfHS81eLPpzR1OqxmGpwr0PfS+nXkBVGYq2+Ax3J
         35sYJXnnDQBysrLb3yhKR4B3voqbyoujljuJElQQ1CDVFDmwxgPVp2CFsQd91pdZ3pc0
         FszuSCMEoYPD42sUg2mhRCP8B04rlysMl2wmar8MfVF+9klwNMzxRnY9UX+CPM6LYFtT
         CUiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyqpLs4WsVTfp6ErCLTAvBcqg+sjI6Midi2iZC1f/Czm3oKVfGa
	gro6ExR1sQz7sscS0HgcVRc=
X-Google-Smtp-Source: AGHT+IFEGsFduAYV7Mkbp2GOWn19/e+hxRHOv/QMWSmANbpMSac9Ey65SHPNdwH6H1ReYMuJVyYQ9Q==
X-Received: by 2002:a2e:3509:0:b0:2c1:7df1:14b1 with SMTP id z9-20020a2e3509000000b002c17df114b1mr10260871ljz.15.1696862124013;
        Mon, 09 Oct 2023 07:35:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9397:0:b0:2c1:261b:7353 with SMTP id g23-20020a2e9397000000b002c1261b7353ls208568ljh.0.-pod-prod-00-eu;
 Mon, 09 Oct 2023 07:35:22 -0700 (PDT)
X-Received: by 2002:a05:6512:3f03:b0:4fe:2815:8ba7 with SMTP id y3-20020a0565123f0300b004fe28158ba7mr8259493lfa.25.1696862122179;
        Mon, 09 Oct 2023 07:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696862122; cv=none;
        d=google.com; s=arc-20160816;
        b=Yl5pYCD+hDO9yKoBpOquow3C67LW/OtsjIheiU0rsQ/DXNVGFN2ex/G2JO8A8iDbz4
         hn2OtY06SFb6ModdGQD+DezPvClcg4ObX8Ctwi8X8KvBASRBP6/ywCIm1iXpdhcrY7Hq
         g6YAkPHTWOZvSicPuQgCXq40gb1cHPaRfgmN3x1er4f7Kbka1p55Yw1oHs2vMlRx3o2+
         0I68uKHPyVMIEyetJ5BrTlYDYk1L01JnpzvtXSugfxAvUcGvggbfsU8mcV1BpWzYn2yN
         5oeS1fNwmk9YZVem7mVS/EVMmMCIf2sFg+f7cFBYbonU5IaQ1IKtD2irnW54Y6gNr3U0
         PzXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VVuzGRM0+235Dw/cvpufLU0wqCwQ31kVmAzdeU61ySM=;
        fh=ipa6FZjW80JJ+zjVaBa7Ytd/cuQaea4wbq9a/8Bo9EM=;
        b=K8PKhef35DA8p+GWH3usO7AYUs+XZx8+veEcqVSVhGY5MoR7EHsB1hyjaF6eV8aFBM
         McZentKtKbVFPBhLLaY4ArmWhxB1ZvB1PjI3m0/FquorWH1Zwo9mq6636trW3bYgeqMb
         OjDRC80xNLM6NclTP/EHey3phomha+0ufY//kBGaz3Mcgu1BzsteekGdDAB37TXtfo7+
         K0dbBGG76YXp/YDQIcCHEnztsUOoxCXBIvxcbCrXxfmYw3A4/wH9bW498NX7lZjE7F6M
         MOh8OMSfPL++4xzIpLqMe2lFQnem5/U920Xi++w/OBkrVmOKll0pm3QUep7FPpXHPw/w
         OpDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WXpBAh4a;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id v3-20020a056512348300b005042ae499b9si402437lfr.7.2023.10.09.07.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 07:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-536071e79deso10074413a12.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 07:35:22 -0700 (PDT)
X-Received: by 2002:a05:6402:5114:b0:522:405f:a7 with SMTP id
 m20-20020a056402511400b00522405f00a7mr11091090edd.16.1696862121276; Mon, 09
 Oct 2023 07:35:21 -0700 (PDT)
MIME-Version: 1.0
References: <20231004145137.86537-1-ubizjak@gmail.com> <20231004145137.86537-5-ubizjak@gmail.com>
 <CAHk-=wgepFm=jGodFQYPAaEvcBhR3-f_h1BLBYiVQsutCwCnUQ@mail.gmail.com>
 <CAFULd4YWjxoSTyCtMN0OzKgHtshMQOuMH1Z0n_OaWKVnUjy2iA@mail.gmail.com>
 <CAHk-=whq=+LNHmsde8LaF4pdvKxqKt5GxW+Tq+U35_aDcV0ADg@mail.gmail.com>
 <CAHk-=wi6U-O1wdPOESuCE6QO2OaPu0hEzaig0uDOU4L5CREhug@mail.gmail.com>
 <CAFULd4Z3C771u8Y==8h6hi=mhGmy=7RJRAEBGfNZ0SmynxF41g@mail.gmail.com> <ZSPm6Z/lTK1ZlO8m@gmail.com>
In-Reply-To: <ZSPm6Z/lTK1ZlO8m@gmail.com>
From: Uros Bizjak <ubizjak@gmail.com>
Date: Mon, 9 Oct 2023 16:35:09 +0200
Message-ID: <CAFULd4Z=S+GyvtWCpQi=_mkkYvj8xb_m0b0t1exDe5NPyAHyAA@mail.gmail.com>
Subject: Re: [PATCH 4/4] x86/percpu: Use C for percpu read/write accessors
To: Ingo Molnar <mingo@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, Andy Lutomirski <luto@kernel.org>, 
	Nadav Amit <namit@vmware.com>, Brian Gerst <brgerst@gmail.com>, 
	Denys Vlasenko <dvlasenk@redhat.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ubizjak@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WXpBAh4a;       spf=pass
 (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::535 as
 permitted sender) smtp.mailfrom=ubizjak@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Oct 9, 2023 at 1:41=E2=80=AFPM Ingo Molnar <mingo@kernel.org> wrote=
:
>
>
> * Uros Bizjak <ubizjak@gmail.com> wrote:
>
> > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > index ecb256954351..1edf4a5b93ca 100644
> > --- a/arch/x86/Kconfig
> > +++ b/arch/x86/Kconfig
> > @@ -2393,7 +2393,7 @@ config CC_HAS_NAMED_AS
> >
> >  config USE_X86_SEG_SUPPORT
> >       def_bool y
> > -     depends on CC_HAS_NAMED_AS && SMP
> > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
> > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
>
> So I'd rather express this as a Kconfig quirk line, and explain each quir=
k.
>
> Something like:
>
>         depends on CC_HAS_NAMED_AS
>         depends on SMP
>         #
>         # -fsanitize=3Dkernel-address (KASAN) is at the moment incompatib=
le
>         # with named address spaces - see GCC bug #12345.
>         #
>         depends on !KASAN

This is now PR sanitizer/111736 [1], but perhaps KASAN people [CC'd]
also want to be notified about this problem.

[1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D111736

Thanks,
Uros.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFULd4Z%3DS%2BGyvtWCpQi%3D_mkkYvj8xb_m0b0t1exDe5NPyAHyAA%40mail.=
gmail.com.
