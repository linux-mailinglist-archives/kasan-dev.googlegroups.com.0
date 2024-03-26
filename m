Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMWGRSYAMGQENFCI5XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FDF888CD4B
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 20:34:11 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id ada2fe7eead31-478325274a4sf65974137.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 12:34:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711481650; cv=pass;
        d=google.com; s=arc-20160816;
        b=fiKchAvUXd4aIuusKCav4kz0f/tZiYkNJY3abg5qmy5320IytX3ilrbTrmmksrR+65
         LL9rv2IqJaialJ+FQHjb5VaMAftN2nGvek5tyzpaR1pP77RYILzLsDuzdQuOYCpx/gXg
         XiLJeLeHTgfE2nj1xk78+HXB8O7NcxEm0Yx3vphzZcErJXUB9w69dUh7PPCZpI4YkYgD
         hPYMqbx6KMTCNlc8xXJ4tNH7rytjcNYV1WPEF4yCkSedQEpAXUOa+hZ5zBxphuJRatVW
         zh+dbu3e1qxGT5EMKiE+hBUFmxP6rrjNAj9BrDAsQEYQpocBTcRyZx4q0+Q0QTENUowG
         TCvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I5b8ix7cBH7YVPimiVw/AYjEB//d56F72Fa4usqMdvQ=;
        fh=qwyoUw7aJtG88JdbmKtIFiNJvbGkeglEi1RUwHqu7lc=;
        b=WgH85bPET9ANw5k1rwk/W94g/TDTBVTxYdeJI2dT0LAs9lAir49wiQhiFa65Xc0ouu
         bCi7GEMZaqIg+FrJqois7IzuBSVEeCwQj5lTcMrRjtEuzo6QUPQsZOCN03RvrseONZoE
         eCRr6jlZWWTMHhI187iphqtTuBRzts/kkqBjIdovfc1YKH+ty0fKrFHFOr5/f/0Zvsoy
         DGuTy5apJ6bgMseceog+7JLOYv13aZJ0Ljla62ndTFXF9y2MWKv4OilcJlYIkpaYCEup
         sVk2Y1LVZ6ytrTOesMNVWQxWXZ26NAYaT9QPF0ZQMcNOShw6ISQH/WQaUhbOeXUlhKqC
         l9+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EjDSXVsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711481650; x=1712086450; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I5b8ix7cBH7YVPimiVw/AYjEB//d56F72Fa4usqMdvQ=;
        b=sKQnN4c3WTf3rMUpgRiza+4lap1Mefx0YfUN/go2uggAcHABS1tpOzYA08aL/7lEwk
         rhmcuDFzUFOqqV6MqSoffr4Mkujma90H5Q5l1EqauKkJSiVWWY3F4ersQCG/bz4AMG/h
         QmjTeaD2l/zrC/5UAEasIiPeMrHkT+A3yL/+gQPwmBFuRSMCJaWF1iU3kl0r08yehDb9
         EMFjyi6EdptH0Nm7bZtWyHId7X3R9wL/lonfiqual9cL5cQ80Im/Xaa5f/kPNCHS+JE5
         cc4K3tl/9swf14dHk7Q5tnDi1wxCER23ljwtiArkZfQIoMaJazRq0W31/2nLdix2+6I2
         rrSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711481650; x=1712086450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I5b8ix7cBH7YVPimiVw/AYjEB//d56F72Fa4usqMdvQ=;
        b=OXpE2yZEpz3HwZv6iVfkBhlSLCcbAcIj9GLhuEJz9Dgw9X4Eb3CEvXdKIO5MRyLJrA
         D/xCYDo2NOFLqbCfmqD0lEO8cUvPp93eq0Cg6khd6W+gLwqV1bNYSci7MRBY9bF5zV39
         vGhiYB44n19Rq6EvusLa82YtKlRooETPOTKprpNRQ4HOmM0nlYxws43N0gwvlTDoEMw7
         AavkGUhlNX/diHxzYy5Z4oLdfJYPIRaD2laWKzJisBodfP99cbbrV+2Zhet6+jq38r4d
         umVISEqUxh+YFPIyXJjcXIQ3kqHYUSGuquKETFf0z62B6GFvbywPiSxVQrE+nmpGRC2S
         uCkQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1cceHvuYf3Xcu2rJTsEeNA5QXVaW9r1Wa+ytKmW5o9grHYj1X2L4TvnJZOtwfC6yrimo4YCkpxHmMqKD4pp3cux/z9M684g==
X-Gm-Message-State: AOJu0YygTStgB1szC2tbrhB8QBOO/z9w6L+EeggKn2Ppq8DRNnhqTgvf
	Vt8SVpD5Xwdz8UILQ2ydTzUIy2odlFgZ11B8vU1FWUpuyirs0yaV
X-Google-Smtp-Source: AGHT+IGJVTmpq9y1xv0B66cNmYgjcA3qhT5Egx4mfk0cO9NR/JmWgHne0zJcKUSoTxHv1x6SNXjlFg==
X-Received: by 2002:a05:6102:151a:b0:476:e7bb:8783 with SMTP id f26-20020a056102151a00b00476e7bb8783mr9733836vsv.25.1711481650132;
        Tue, 26 Mar 2024 12:34:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5ceb:0:b0:690:c950:c414 with SMTP id iv11-20020ad45ceb000000b00690c950c414ls8569940qvb.2.-pod-prod-09-us;
 Tue, 26 Mar 2024 12:34:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvueqOuj7Xdv63lNfpBlvrSA3LpHHlHlbonvIr8fEfXnNKHyFXAt4EMKa/82//1Hg68p6wA4jjrSVwxpU/KxZaIil+cDbnCsev5Q==
X-Received: by 2002:a05:6122:449b:b0:4d4:20cb:8c0 with SMTP id cz27-20020a056122449b00b004d420cb08c0mr8592128vkb.8.1711481649041;
        Tue, 26 Mar 2024 12:34:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711481649; cv=none;
        d=google.com; s=arc-20160816;
        b=pO5CQ9T1c3uxOYEmEWDuybe/V0y/ooj/XsY3O8P5ICxcjMB5YiEqJHvfQ93w3OtCJu
         2iC1cmkVlIq8N4JIpaeO75VK7UO7+dimD7VdmHpkJ9DGhYSmzGDessFy94OAMW30p0JT
         Xls3ZaYM9CTZHfGIw+GmztZC7OGigCEb21pjn26jRV6R2sD0lFfstgIVA2w/7E7L8C1v
         XTT3Ep93L5R53LVoD2+D3Oha+FghAvviNQNONOD8CMqOWxjrMS4v5UCR0UdLougXO0+z
         wjdU9ncFBT7Kls4kSCQDdGBvPLeRYJgH1+ucMZoM8cyaUQHqHMVNZE/sfwsqQ9tN9fml
         Cv3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B6sTqJ0aPnz4xq/ZZGbsUBdM/hjOugrKakCuozLiqI4=;
        fh=Vv4giNqh/zpRoXP3CA2XVlqhc+C2FSrSCF80IcETM7I=;
        b=N3mpKsqDuSOjVI0FZi/YKl2/4q6lMd9MUVx9sH8DvihLPW619YNxEH/rpbtoXXmj6Y
         yejmvVqYQFzlBRydwUIqRqWe1KanKUF9gSl9SKtXITbErZQsqzYBdkcDlMOcmehjV0zq
         DRw+3YODG1AC0pzBxPVSUGyW3IHE7r/o2dr+V5qYHLD4qANiDdv6dsN8trDhtiHnltOW
         p8MUkUy4MycVWRwqSIjSxHgrBQI9cKD4A3AMKXpeeGr2ZvxN8zqP2+9tjc62EwdMY4Xd
         P7XvpnNF0eQ/PgrKGZJiltkS0zPucc7iGQXzbk4gq2SOv2YAN2xTA8gL5NHLdKKwA6Bj
         Pdwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EjDSXVsu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe32.google.com (mail-vs1-xe32.google.com. [2607:f8b0:4864:20::e32])
        by gmr-mx.google.com with ESMTPS id i7-20020ac5cbe7000000b004d88e05895asi189327vkn.1.2024.03.26.12.34.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 12:34:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e32 as permitted sender) client-ip=2607:f8b0:4864:20::e32;
Received: by mail-vs1-xe32.google.com with SMTP id ada2fe7eead31-4765792fc76so1209380137.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 12:34:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5TGayPS/WMRoNoB2DMocoM+HHqOi1ukbuQDgJFKNG/Rf0imCkn5GD8QOOIkMcmSarwfQSvSGo2kmuc48ZkId2e9FhvZ4TOd973Q==
X-Received: by 2002:a05:6102:24b8:b0:476:9ac0:e8c4 with SMTP id
 s24-20020a05610224b800b004769ac0e8c4mr10157730vse.34.1711481648508; Tue, 26
 Mar 2024 12:34:08 -0700 (PDT)
MIME-Version: 1.0
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com> <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com> <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
In-Reply-To: <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Mar 2024 20:33:31 +0100
Message-ID: <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
Subject: Re: Unpatched return thunk in use. This should not happen!
To: Borislav Petkov <bp@alien8.de>
Cc: Nikolay Borisov <nik.borisov@suse.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Paul Menzel <pmenzel@molgen.mpg.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	David Kaplan <David.Kaplan@amd.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EjDSXVsu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e32 as
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

On Tue, 26 Mar 2024 at 20:12, Borislav Petkov <bp@alien8.de> wrote:
>
> On Tue, Mar 26, 2024 at 06:04:26PM +0200, Nikolay Borisov wrote:
> > So this       _sub_I_00099_0 is the compiler generated ctors that is likely
> > not patched. What's strange is that when adding debugging code I see that 2
> > ctors are being executed and only the 2nd one fires:
> >
> > [    7.635418] in do_mod_ctors
> > [    7.635425] calling 0 ctor 00000000aa7a443a
> > [    7.635430] called 0 ctor
> > [    7.635433] calling 1 ctor 00000000fe9d0d54
> > [    7.635437] ------------[ cut here ]------------
> > [    7.635441] Unpatched return thunk in use. This should not happen!
>
> ... and this is just the beginning of the rabbit hole. David and I went
> all the way down.
>
> Turns out that objtool runs on the .o files and creates the
> .return_sites just fine but then the module building dance creates an
> intermediary *.mod.c file and when that thing is built, KCSAN would
> cause the addition of *another* constructor to .text.startup in the
> module.
>
> The .o file has one:
>
> -------------------
> Disassembly of section .text.startup:
>
> ...
>
> 0000000000000010 <_sub_I_00099_0>:
>   10:   f3 0f 1e fa             endbr64
>   14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                         15: R_X86_64_PLT32      __tsan_init-0x4
>   19:   e9 00 00 00 00          jmp    1e <__UNIQUE_ID___addressable_cryptd_alloc_aead349+0x6>
>                         1a: R_X86_64_PLT32      __x86_return_thunk-0x4
> -------------------
>
>
> while the .ko file has two:
>
> -------------------
> Disassembly of section .text.startup:
>
> 0000000000000010 <_sub_I_00099_0>:
>   10:   f3 0f 1e fa             endbr64
>   14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                         15: R_X86_64_PLT32      __tsan_init-0x4
>   19:   e9 00 00 00 00          jmp    1e <_sub_I_00099_0+0xe>
>                         1a: R_X86_64_PLT32      __x86_return_thunk-0x4
>
> ...
>
> 0000000000000030 <_sub_I_00099_0>:
>   30:   f3 0f 1e fa             endbr64
>   34:   e8 00 00 00 00          call   39 <_sub_I_00099_0+0x9>
>                         35: R_X86_64_PLT32      __tsan_init-0x4
>   39:   e9 00 00 00 00          jmp    3e <__ksymtab_cryptd_alloc_ahash+0x2>
>                         3a: R_X86_64_PLT32      __x86_return_thunk-0x4
> -------------------
>
> Once we've figured that out, finding a fix is easy:

Thanks for figuring this one out!

> diff --git a/scripts/Makefile.modfinal b/scripts/Makefile.modfinal
> index 8568d256d6fb..79fcf2731686 100644
> --- a/scripts/Makefile.modfinal
> +++ b/scripts/Makefile.modfinal
> @@ -23,7 +23,7 @@ modname = $(notdir $(@:.mod.o=))
>  part-of-module = y
>
>  quiet_cmd_cc_o_c = CC [M]  $@
> -      cmd_cc_o_c = $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV), $(c_flags)) -c -o $@ $<
> +      cmd_cc_o_c = $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV) $(CFLAGS_KCSAN), $(c_flags)) -c -o $@ $<

This looks reasonable.

>  %.mod.o: %.mod.c FORCE
>         $(call if_changed_dep,cc_o_c)
>
> However, I'm not sure.
>
> I wanna say that since those are constructors then we don't care about
> dynamic races there so we could exclude them from KCSAN.

Yeah, we can just exclude all the code from the auto-generated mod.c
files from KCSAN instrumentation. It looks like they just contain
global metadata for the module, and no other code. The auto-generated
constructors don't contain much interesting code (unlikely they'd
contain data races we'd ever care about).

> If not, I could disable the warning on KCSAN. I'm thinking no one would
> run KCSAN in production...
>
> A third option would be to make objtool run on .ko files. Yeah, that
> would be fun for Josh. :-P
>
> I'd look into the direction of melver for suggestions here.

I think just removing instrumentation from the mod.c files is very reasonable.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA%40mail.gmail.com.
