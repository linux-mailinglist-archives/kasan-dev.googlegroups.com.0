Return-Path: <kasan-dev+bncBD5L3BOATYFRB5F4RSKAMGQE42UKDVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 72B6F529879
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 06:03:02 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id bp17-20020a056512159100b00472631eb445sf7358463lfb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 21:03:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652760181; cv=pass;
        d=google.com; s=arc-20160816;
        b=VaLleYfr8IjmE8l2wOpHKVG1DvOHN9fUn2f2pSCZMHRhq5bJxlX4oTHg8gNqoCwkzy
         LvvA1KRQxVhSVGoaesnwp+LjI9lnqOTHLae3Z2Tr2kkSnkUVXCMCJg5Lblc5yJzJdXA2
         YnPe8wVIEmjy61iNZqMlHPKqy7X6AMSm+Q33rH+v46D0xWUNgURKtDCjo6NpA82G1HvI
         54lHlg/e1/2/FGcvY+RwI02V/T8dkj9XCaPN52tS4QgARk3TRx+7nuYY7gl1dafWxC+V
         Gu2fnFuEgTV31Fhb5482M3/JFpTqBMk48ToT2r4eIRkqEi6/MKn5ljPNOOP7DCuKz5Og
         amDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ra9TcRhkYSq0cGgF01CMcfEJmbUrTs15ioYBWnv0ENI=;
        b=BCh84DzNyj7zefqfGzFcdESRHjTniis8ajgrGX0LP/XxMIngfZTskAus+wQ4Z6gyld
         LBmhj/Ajj/PotUtQWGO0GUNBlhVREPRFZNhKgOxo49HYAeAHaTCNp2oF7X7h8KFOJ8Pd
         U/KmqXKa7B2QWH7c90vzgkWOLPTDrBdkV+cCoFDNjgh8rQgruKFFhK4NNHxLWiPZlNUa
         Y+YOHUVZ/K1QkHL78qMyUaA28bJgOcyvjWyEqWdOsUJlRldAikBrztLrEXLLAibLevc2
         MADT0AIbbeOXQcivVjvJrV1QqrxJAJwCx5OgV3k0OqYPN8t4p5+aF/YYePGU5Ne2ozxD
         5c0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b="h/uB1SJQ";
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ra9TcRhkYSq0cGgF01CMcfEJmbUrTs15ioYBWnv0ENI=;
        b=gN3gW1iCTfq6O3GrZjoazCIW+ATQ3Zz1q2v8mQnD43N1/JnJBopvQs2wDlkmfkeehH
         va5zWk8fWes5nVrSzjEnpLi2kVGDg0P09aCNRJm1f+cYTRdz4IBIWGAsro5Zw6jI06ju
         wjXoxReG9uKkQ5C3SQ/z7G1naHDXCJQ5aXB/mqI8kSbTJMx6kfTi3edfGjVOvDLpa6Zc
         lSUrlOEqdY+n2ot0dV7ls9PFSyH/8ZYpRePqumsd7Lnitf94kWqX7Oy4ApdAMoikhcSh
         TxFHQORyYCr73/bLUZp4K2kqFqnnPCq0DqAIwoJ6V6AvLvoaMK38pJKV6biFDMthccSl
         OCTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ra9TcRhkYSq0cGgF01CMcfEJmbUrTs15ioYBWnv0ENI=;
        b=jwRyR3StgP6B0+RIj78FjFnsxYY4DaPWolZCfwXeP01QZsinoEStK6JoNmmN2AqO96
         han2HD/uphMzXSelXu9G/UuvcJ1RdWgiPF1rA1NM+aGZoCUxvtwnuo9VSVC+kEyhNbZC
         0xjPtgNseBO95EUO2QPdz16Jn0P/QyvTvOkh2oTuetzF/qqFjUWvDq19eaNMN8HvYMqE
         WdeQny3jFWIpMmmccU7C8X2ilFaUNeqGlmkDJ6wQXzuGM4qp1L7d1UKePFJmt8GqKhnW
         3aCfk7xQj75Uj/zmuUOmEtuR4XFrycR1k+7PYPrC0c7GymNzF8FiLcS+tPYvumKtP2wv
         82jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303RI2fl7tKWXoSfF4wNFnpkZYZrbUkQgS5vKBr19UnxE4S47Cx
	2TdwPfjuabh4cZr3HTK5iZE=
X-Google-Smtp-Source: ABdhPJymBFAbfu1xFW0aC9USlF2Xf8SJK0TV0mkQZyaVByGQ0tBiQCGQijj5MuVKcaHX/hKXK71PGQ==
X-Received: by 2002:a2e:bc10:0:b0:250:59ed:405a with SMTP id b16-20020a2ebc10000000b0025059ed405amr12733428ljf.301.1652760181139;
        Mon, 16 May 2022 21:03:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls10370085lfu.0.gmail; Mon, 16 May 2022
 21:03:00 -0700 (PDT)
X-Received: by 2002:ac2:4d14:0:b0:472:90d:d008 with SMTP id r20-20020ac24d14000000b00472090dd008mr15394215lfi.240.1652760179999;
        Mon, 16 May 2022 21:02:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652760179; cv=none;
        d=google.com; s=arc-20160816;
        b=I3sb94KBKU5NT7DA2Tp6Xmn5ohTsD/F7siaB3p0TedmMSfSbSoi4kaX4BL49ecpM8E
         KhgmJ1gONAlg+fuXmZUavt2roNyegN+kmiCq2K6oEzLC5nvVZ0Gmtj/tNJ6krVxsuRXM
         lCNKPMuc5Tk0cKTaBNMS2V7JM7OEgSShyllybboBwh6f69VfsrZW8Pt+Aye9TUOF2sVT
         2H2PwUgrcLTuptGMQjjJT2VEpXLmVOOxSlnpMCzkxYWinHZtDeBlL9GkfmqI5DDPVxX2
         CnD4NzVy5+t9yov/IIlvMT77U4DEcgQnfo7UkZxyKG6BbhLjlPTr5INw1RIA6Cyf/SGE
         WpFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HLuh6iim4/H/XbPkV7FBYvTzbDgx426YXgEZpo+wCs8=;
        b=XMfUTvxjjj05d4gMAr+HKc2qPx3psbhSesWQQaMqqFbxVvbWdRkntDisTg1Gl4+/PV
         QXss7KqNRM4fHVP0yGlLDPSDXo4wkTqP/ZiW8DQqtVHH5OzwUVdkP1742sfF3idp/vEi
         oqoUD/XAxQglVY/gn3q9nn8trKoqwt/qnqf6t38Rd4T+RCn1mebEWP9SGgrHD32ToExy
         tXsPpUuo5XXjYCT/M1rvgHAyiizr6wocALb7FS6/tlmPB0KGyVRCAoyDxhnQ1LImbUIk
         Xqf5PjWrokxFj2YaPXNU+hhueCxVQkJTUDUEipPMQEw3VuVtIMOlfnD0GK+3L0Z/hOBX
         919Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b="h/uB1SJQ";
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id u11-20020a2e91cb000000b0024f304af5b0si589442ljg.7.2022.05.16.21.02.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 May 2022 21:02:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id bq30so29169272lfb.3
        for <kasan-dev@googlegroups.com>; Mon, 16 May 2022 21:02:59 -0700 (PDT)
X-Received: by 2002:a05:6512:309:b0:477:a8c7:96d8 with SMTP id
 t9-20020a056512030900b00477a8c796d8mr142603lfp.41.1652760179523; Mon, 16 May
 2022 21:02:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
 <YnkoKxaPbrTnZPQv@xhacker> <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
 <YoCollqhS93NJZjL@xhacker> <CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD+pGLA@mail.gmail.com>
 <YoKIv2ATRdQfYbBf@xhacker>
In-Reply-To: <YoKIv2ATRdQfYbBf@xhacker>
From: Anup Patel <apatel@ventanamicro.com>
Date: Tue, 17 May 2022 09:31:50 +0530
Message-ID: <CAK9=C2VJ-+bu20+QOfKrq6cEBE93Yi21U=zU9AKOSQi1GGHWiA@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Anup Patel <anup@brainfault.org>, Atish Patra <atishp@atishpatra.org>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: apatel@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b="h/uB1SJQ";
       spf=pass (google.com: domain of apatel@ventanamicro.com designates
 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=apatel@ventanamicro.com
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

On Mon, May 16, 2022 at 11:02 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> On Sun, May 15, 2022 at 08:19:37PM +0530, Anup Patel wrote:
> > On Sun, May 15, 2022 at 12:54 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > >
> > > On Wed, May 11, 2022 at 11:29:32PM -0700, Atish Patra wrote:
> > > > On Mon, May 9, 2022 at 7:50 AM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > > >
> > > > > On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> > > > > > On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > > > > >
> > > > > > > Currently, riscv has several features why may not be supported on all
> > > > > > > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > > > > > > kernel Image style, we need to check whether the feature is suportted
> > > > > > > or not. If the check sits at hot code path, then performance will be
> > > > > > > impacted a lot. static key can be used to solve the issue. In the past
> > > > > > > FPU support has been converted to use static key mechanism. I believe
> > > > > > > we will have similar cases in the future.
> > > > > >
> > > > > > It's not just FPU and Sv48. There are several others such as Svinval,
> > > > > > Vector, Svnapot, Svpbmt, and many many others.
> > > > > >
> > > > > > Overall, I agree with the approach of using static key array but I
> > > > > > disagree with the semantics and the duplicate stuff being added.
> > > > > >
> > > > > > Please see more comments below ..
> > > > > >
> > > > > > >
> > > > > > > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > > > > > > patch tries to add an unified mechanism to use static keys for all
> > > > > > > the cpu features by implementing an array of default-false static keys
> > > > > > > and enabling them when detected. The cpus_have_*_cap() check uses the
> > > > > > > static keys if riscv_const_caps_ready is finalized, otherwise the
> > > > > > > compiler generates the bitmap test.
> > > > > >
> > > > > > First of all, we should stop calling this a feature (like ARM does). Rather,
> > > > > > we should call these as isa extensions ("isaext") to align with the RISC-V
> > > > > > priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> > > > > > not have distinct extension name, the RISC-V profiles spec is assigning
> > > > > > names to all such optionalities.
> > > > >
> > > > > Same as the reply a few minutes ago, the key problem here is do all
> > > > > CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
> > > > > I agree with Atish's comments here:
> > > > >
> > > > > "I think the cpu feature is a superset of the ISA extension.
> > > > > cpu feature != ISA extension"
> > > > >
> > > >
> > > > It seems to be accurate at that point in time. However, the latest
> > > > profile spec seems to
> > > > define everything as an extension including sv48.
> > > >
> > > > https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#623-rva22s64-supported-optional-extensions
> > > >
> > > > It may be a redundant effort and confusing to create two sets i.e.
> > > > feature and extension in this case.
> > > > But this specification is not frozen yet and may change in the future.
> > > > We at least know that that is the current intention.
> > > >
> > > > Array of static keys is definitely useful and should be used for all
> > > > well defined ISA extensions by the ratified priv spec.
> > > > This will simplify this patch as well. For any feature/extensions
> > > > (i.e. sv48/sv57) which was never defined as an extension
> > > > in the priv spec but profile seems to define it now, I would leave it
> > > > alone for the time being. Converting the existing code
> > > > to static key probably has value but please do not include it in the
> > > > static key array setup.
> > > >
> > > > Once the profile spec is frozen, we can decide which direction the
> > > > Linux kernel should go.
> > > >
> > >
> > > Hi Atish, Anup,
> > >
> > > I see your points and thanks for the information of the profile
> > > spec. Now, I have other two points about isa VS features:
> > >
> > > 1. Not all isa extenstions need static key mechanism, so if we
> > > make a static key array with 1:1 riscv_isa <-> static key relationship
> > > there may be waste.
> > >
> > > For example, the 'a', 'c', 'i', 'm' and so on don't have static
> > > key usage.
> >
> > Not all isa extensions but a large number of them will need a static
> > key. It's better to always have one static key per ISA extension
> > defined in cpufeatures.c
>
> Currently, RISCV_ISA_EXT_MAX equals to 64 while the base ID is 26.
> In those 26 base IDs, only F/D and V need static key, it means
> we waste at least 24 static keys.

If you want to save space of unused static keys then there are other
ways.

For example, you can create a small static key array which has
many-to-one relation with the ISA extension numbers. For ISA extension
which are always ON or always OFF, we can use fixed FALSE and
TRUE keys. Something like below.

enum riscv_isa_ext_key {
    RISCV_ISA_EXT_KEY_FALSE = 0,
    RISCV_ISA_EXT_KEY_TRUE,
    RISCV_ISA_EXT_KEY_FLOAD, /* For 'F' and 'D' */
    RISCV_ISA_EXT_KEY_VECTOR, /* For all vector extensions */
    RISCV_ISA_EXT_KEY_SVINVAL,
    RISCV_ISA_EXT_KEY_SSCOFPMT,
    RISCV_ISA_EXT_KEY_MAX,
};

extern unsigned char __riscv_isa_ext_id2key[RISCV_ISA_EXT_ID_MAX];
extern struct static_key_false __riscv_isa_ext_keys[RISCV_ISA_EXT_KEY_MAX];

static __always_inline bool __riscv_isa_extension_keycheck(unsigned int ext)
{
    if (RISCV_ISA_EXT_ID_MAX <= ext)
        return false;
    return static_branch_unlikely(&__riscv_isa_ext_keys[__riscv_isa_ext_id2key[ext]]);
}
#define riscv_isa_extension_keycheck(ext)    \
    __riscv_isa_extension_keycheck(RISCV_ISA_EXT_##ext)

>
> >
> > For example, F, D, V, Sstc, Svinval, Ssofpmt, Zb*, AIA, etc.
> >
> > >
> > > 2.We may need riscv architecture static keys for non-isa, this is
> > > usually related with the linux os itself, for example
> > > a static key for "unmap kernelspace at userspace".
> > > static keys for "spectre CVE mitigations"
> > > etc.
> >
> > These things look more like errata or workarounds so better
> > to use that framework instead of ISA extensions (or features).
>
> Currently, the errata workarounds are implemented with ALTERNATIVEs
> but I believe sometime we may need static key to implement the
> workarounds. However this can be checked later. Now I worried about
> the static key waste above.

That's a separate topic and for now what we need is a simple
and extensible approach to have static keys for ISA extensions.

Regards,
Anup

>
> Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK9%3DC2VJ-%2Bbu20%2BQOfKrq6cEBE93Yi21U%3DzU9AKOSQi1GGHWiA%40mail.gmail.com.
