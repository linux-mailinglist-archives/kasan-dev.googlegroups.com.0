Return-Path: <kasan-dev+bncBDFJHU6GRMBBBD5GQSKAMGQE37X5J4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B1D152783A
	for <lists+kasan-dev@lfdr.de>; Sun, 15 May 2022 16:49:52 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z20-20020a50f154000000b0042815e3008csf8103815edl.15
        for <lists+kasan-dev@lfdr.de>; Sun, 15 May 2022 07:49:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652626191; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ocsxi44lBlQur04UfBlGKBNINM6tr/QeJE0jkNK5t1pZpZ3BN7ojflxQn5xqxnGs3F
         ilvbj6bo/HF0u1o4GVQBGOq20jW5/rZIh2oYeNa5i1kVxhswyubugAYAEQGIfEPa6xOu
         9FBDtOKcvCi8r4XZxB8Z1JyICP/LIcnTJG8tpZniE7Lmd5K+yJjPyTcymu2wTUbQiE6Z
         pRLir2WC+GpksHBKP0EOR4oxl604zSG1z9dc6qlPLbYrNGKNIwMUIWV08Lqi1qp5y/Zo
         KqleVVnWlpuX7WsSNFW1HODtf/t8z0abHa1dMvLowXiYgVBlfRx82cstyxKaJ3M2KOVW
         Razg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=S0+Foh6lv2lsiPi6y9pcjLoqyKqSANWMwVyal8opTY8=;
        b=u0ExZmIbNC9AAkrmODLOi97F62QSNZH8/oKexQ4VI7UNBB33QywCITe0myVczme61E
         ZiYSR16gMux3Wdqo9Q5CtBkdb6LOlrVjaTtzAsMFaZdPC6VNy4JeeAabzbLrdzMF2wXk
         +1HT0mpPKg/IlW1y6xqZm6em3SPdCGH8ik9EhqPSPoITo0aqBjGiLkViQSuOW4bduiYU
         vxIAx6/b3sYgNuLhTj2xJSdj1HgmOHJ71q43dafdAEFD4WyO5ZbATjN7cKGyr50rk4yr
         LtfglGyEorn1wtwVxwVkiW7tX+GwdnHklDHB9hrT1IeczuAsjQBLLLEfk1vAxNDp2xPy
         c4Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=C+eq1A7H;
       spf=neutral (google.com: 2a00:1450:4864:20::42e is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S0+Foh6lv2lsiPi6y9pcjLoqyKqSANWMwVyal8opTY8=;
        b=NNpIIlV+/cySdV+XM9zUiXbFTeMDHbIThBV0gytCeRi1omMYYGgVrlnlc4+KjoP01n
         jW/n4mvgMbIHxQAx1vaEfg2lkvGzj9Cf1j6gH5PyfdjPLtqes1h0nM9gg01YO/2qqWlF
         xT6di5Ni37xgovVtfHF15Ja4qgTy6fWeQEpWHhCxloWpem1qDwj+Ss3JoGgFwtayKFvo
         t0er7GcRomHFe1KCYXitL2vt6K/4L54vUXHlNde1YL7EWVgac9UmzZuGgyty0QwGIrpw
         03c9E+xgxy6/argGprDy8uioklMNjPT7Mx+ydMd/ylH+qk4krYziN5kimgkvvvWYMNIW
         cn/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S0+Foh6lv2lsiPi6y9pcjLoqyKqSANWMwVyal8opTY8=;
        b=sXIShBhTcxxBRiIB0I/qya5c2gRxHsuom6JdkNWeKQHepKGTY7ZRY6G4YE7Cx4jnP6
         uDuGeLdCrTPVrlJREPUg+W3mIRlfr4PEtuVVFSP1QfbuSKJm4K5AXvcWPOh0Ct8TF9b+
         dH0piSZeGqT11COtOOnH6H7aIUhxDiX+Ueo1U5ONarDuW+IutaRRZGECXmQSaSXa5xLR
         DlSSZJqqu2WGzPGJesLqd/jUe2r9YgLluWXYEfsW7p4Wti8U3soAosuP5FLTTzxfJm5t
         y8EHqFoyO/jL8W8m3sHKYUlymSp5Z8g8Bg7PgNwK78OBeYDrzSw+O2Cfi6e0DtXHVFLB
         Xz3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bmFTzAKW5tkyKmG4Uz7acd6mYvwAbUDzE/+SzAj5e/pJ5SCba
	Nc2y8AgPe1eZDeB1lu46H+0=
X-Google-Smtp-Source: ABdhPJyb5HuSK1KleeJxzcdTmURnrAtB0XgJpeXpcYjlSPhx3bZQQ7B4esH82ElXBGHksn+aUVlIww==
X-Received: by 2002:a17:906:29c2:b0:6f3:da29:8304 with SMTP id y2-20020a17090629c200b006f3da298304mr11819105eje.569.1652626191533;
        Sun, 15 May 2022 07:49:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e11:b0:6f5:1321:37ec with SMTP id
 hp17-20020a1709073e1100b006f5132137ecls6133991ejc.11.gmail; Sun, 15 May 2022
 07:49:50 -0700 (PDT)
X-Received: by 2002:a17:907:6089:b0:6f8:5933:7062 with SMTP id ht9-20020a170907608900b006f859337062mr11573814ejc.169.1652626190524;
        Sun, 15 May 2022 07:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652626190; cv=none;
        d=google.com; s=arc-20160816;
        b=rJONPHopSm7um0O6RhTjmgr6jeNvlY9JxEDLWuSz6EY65euj5aIVYP7Gxj2IlOUJ62
         5d6JvLU4ePjvqx4Ks83ffTXePPtoFj0PLS5MCKZ+k7VGe+4ZNpeLAgJk1vX3vZlgYF9s
         N5+ShA6KeEWqcsOUoPR5ut3qlwMYwpkc8WduCq3yhB1EedJzxVRbUHpikagJSQH5hGq4
         a30Rj5XQYu+fI3XvbhDtXTq3uNI8ICQCP57fmshhqr0eliKWwANnVEe9wGxRyTug+sYY
         3NwKdr/W5jT+kSagvjYM9VUNsUF92KgXYLgnsX0oytd/USKSfQ/b9kEGeF09ZC4TKQF1
         3lhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zVVOCTvJRX3Olou6oLL+JZw4cMsITWwHrp/zHjilPa0=;
        b=M7vrJAuuJ2Ws2tnk4FzbzkMdaW2v8zzzF+3QEcMYVJsqdnonA6vW6qhTuVqnhGEFCG
         IUzoYIYLI3Vl0VPuFLttoIFzEcHtFB04KBUVQU8sl8Vc6X4mdF+V27CzEF6TO12Nzqjc
         QZiMSl6FikN+DZIxXq8DlHm/Zhw98n9tCqoNkgC9gXBYbcBQ2oe8xXWan4sMIlKadawc
         10Vz08+f/7q8ORcTd2OVsZKTL+BAvpKuK4p65npvLGP0/ad5F8gcz6DaLR2pcJt36uzT
         PPruPs8sA8o+UzLV3kOg0rzy/f/EKtN2MXWq9i8ERzLnLGx1s+GUJY6bDCiA8fZqRh+u
         yFLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=C+eq1A7H;
       spf=neutral (google.com: 2a00:1450:4864:20::42e is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id g9-20020a50d5c9000000b00425adbac75dsi373361edj.2.2022.05.15.07.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 15 May 2022 07:49:50 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::42e is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id j25so16402216wrc.9
        for <kasan-dev@googlegroups.com>; Sun, 15 May 2022 07:49:50 -0700 (PDT)
X-Received: by 2002:adf:f001:0:b0:20d:22b:183c with SMTP id
 j1-20020adff001000000b0020d022b183cmr4176252wro.313.1652626190014; Sun, 15
 May 2022 07:49:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
 <YnkoKxaPbrTnZPQv@xhacker> <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
 <YoCollqhS93NJZjL@xhacker>
In-Reply-To: <YoCollqhS93NJZjL@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Sun, 15 May 2022 20:19:37 +0530
Message-ID: <CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD+pGLA@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Atish Patra <atishp@atishpatra.org>, Anup Patel <apatel@ventanamicro.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=C+eq1A7H;       spf=neutral (google.com: 2a00:1450:4864:20::42e is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sun, May 15, 2022 at 12:54 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> On Wed, May 11, 2022 at 11:29:32PM -0700, Atish Patra wrote:
> > On Mon, May 9, 2022 at 7:50 AM Jisheng Zhang <jszhang@kernel.org> wrote:
> > >
> > > On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> > > > On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > > >
> > > > > Currently, riscv has several features why may not be supported on all
> > > > > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > > > > kernel Image style, we need to check whether the feature is suportted
> > > > > or not. If the check sits at hot code path, then performance will be
> > > > > impacted a lot. static key can be used to solve the issue. In the past
> > > > > FPU support has been converted to use static key mechanism. I believe
> > > > > we will have similar cases in the future.
> > > >
> > > > It's not just FPU and Sv48. There are several others such as Svinval,
> > > > Vector, Svnapot, Svpbmt, and many many others.
> > > >
> > > > Overall, I agree with the approach of using static key array but I
> > > > disagree with the semantics and the duplicate stuff being added.
> > > >
> > > > Please see more comments below ..
> > > >
> > > > >
> > > > > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > > > > patch tries to add an unified mechanism to use static keys for all
> > > > > the cpu features by implementing an array of default-false static keys
> > > > > and enabling them when detected. The cpus_have_*_cap() check uses the
> > > > > static keys if riscv_const_caps_ready is finalized, otherwise the
> > > > > compiler generates the bitmap test.
> > > >
> > > > First of all, we should stop calling this a feature (like ARM does). Rather,
> > > > we should call these as isa extensions ("isaext") to align with the RISC-V
> > > > priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> > > > not have distinct extension name, the RISC-V profiles spec is assigning
> > > > names to all such optionalities.
> > >
> > > Same as the reply a few minutes ago, the key problem here is do all
> > > CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
> > > I agree with Atish's comments here:
> > >
> > > "I think the cpu feature is a superset of the ISA extension.
> > > cpu feature != ISA extension"
> > >
> >
> > It seems to be accurate at that point in time. However, the latest
> > profile spec seems to
> > define everything as an extension including sv48.
> >
> > https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#623-rva22s64-supported-optional-extensions
> >
> > It may be a redundant effort and confusing to create two sets i.e.
> > feature and extension in this case.
> > But this specification is not frozen yet and may change in the future.
> > We at least know that that is the current intention.
> >
> > Array of static keys is definitely useful and should be used for all
> > well defined ISA extensions by the ratified priv spec.
> > This will simplify this patch as well. For any feature/extensions
> > (i.e. sv48/sv57) which was never defined as an extension
> > in the priv spec but profile seems to define it now, I would leave it
> > alone for the time being. Converting the existing code
> > to static key probably has value but please do not include it in the
> > static key array setup.
> >
> > Once the profile spec is frozen, we can decide which direction the
> > Linux kernel should go.
> >
>
> Hi Atish, Anup,
>
> I see your points and thanks for the information of the profile
> spec. Now, I have other two points about isa VS features:
>
> 1. Not all isa extenstions need static key mechanism, so if we
> make a static key array with 1:1 riscv_isa <-> static key relationship
> there may be waste.
>
> For example, the 'a', 'c', 'i', 'm' and so on don't have static
> key usage.

Not all isa extensions but a large number of them will need a static
key. It's better to always have one static key per ISA extension
defined in cpufeatures.c

For example, F, D, V, Sstc, Svinval, Ssofpmt, Zb*, AIA, etc.

>
> 2.We may need riscv architecture static keys for non-isa, this is
> usually related with the linux os itself, for example
> a static key for "unmap kernelspace at userspace".
> static keys for "spectre CVE mitigations"
> etc.

These things look more like errata or workarounds so better
to use that framework instead of ISA extensions (or features).

Some of these things might even use ALTERNATIVEs instead
of static keys.

>
> In summary, I can see riscv_isa doesn't cover features which need static
> keys, and vice vesa.
>
> Could you please comment?
>
> Thanks in advance,
> Jisheng

Regards,
Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD%2BpGLA%40mail.gmail.com.
