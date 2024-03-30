Return-Path: <kasan-dev+bncBDT2NE7U5UFRBKNGUKYAMGQEBN3YKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 52E72892DA6
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 23:33:15 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5a55fb94ab0sf4087754eaf.1
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 15:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711837994; cv=pass;
        d=google.com; s=arc-20160816;
        b=mOP51bk4PSBA2w88FzN6mZIuhfuSD5eBQ8If5UyPq8tizSl3bl+9zjJ6O2AIEAoigS
         xrGX0ndoAPymJgRowWIY1TIBPnF9kTLDl8oRbFjdQd28k93zRr9SWMknyaw5HpZU7GS6
         x4yyt9YUPq3aR/FniVLJ+pYrvz9jSIH0eW/L0ydW2bKHpSYSi0vdhglVSTqdl54t+vAC
         f7wzlf5GwnQFvQOpBnoullPaiHdDqh/2H3J64LZuuSR4eo1KXuhYRXX8MsbuRULOV0en
         6lpz2EOL6HRZS+GUr1n7r/PWz1IQQT9ebg0rdlfPYhKpqQWmhlKQdLsm693zktKdpSL4
         oo5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=+8EwgtrG94oY58QGzvJgMPm1+64UyjWZdtYfNRSUDJQ=;
        fh=Kp2j8vHlaPUVx2mYqTWnxwkq+9z56R3Tq6vqDK2j/wc=;
        b=K3iJQZnC/DzwUPmUIwIn8g0p2w8KL2TwY4Do3i94wySRhCl1/4y1SrU/buRRpDUmZO
         AQ+KHbnp9JgPt0GVLfaCrBlmdFVj1D6bnyiJtb6Hsiv7IZwMxkvzcS5hDAONh9BKqZ3X
         xyGSQd52HwhjPtJB0EUFHPEHtyKYe04C0d/HMWKg7z1qgjvaviatjVnZIOy/VL7+JdNl
         MPERH4wcFBCz6xsss8NGvy89ri3Z6tj+h8aOPa0mWf2YYxzZubNtHjYZZgpLYXwegJ6C
         NIJt0TbfEpVJ7XI10LdrOI3jd9Rbw7m2dO8qTrrw3p53DG7zP9z/ce2zbaBfwK3ACRTO
         spgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bxcemWO2;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711837994; x=1712442794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+8EwgtrG94oY58QGzvJgMPm1+64UyjWZdtYfNRSUDJQ=;
        b=VPVLCJWZyCz4+SlifXyQHAdLS6DVTduYVSyZCwjNL39Gv5R8TFGHEvnZtoVio7Xctf
         7IRfndkz2u7OocKk6OjUJhCMbvu3R4SLN0L2sl0Jww+CiJhINvvzaJi/1DJz9kyoCr9y
         VnlKVNtEj7gxw5FCQsq/egZsipgmlxa0JLvA/MRziIHXQdbXtOR+Lw0yUA+8wYxnNNfj
         VcU27ufXq9C4cJkNFSUVhlu/DCSzy0Rgm4NsH+jhn/WPea9R7mSj9XzyqR9IC/gayw1m
         oJ6NvgJOANBg055gWh4bx9I8AD37RxI6tvgCPSKRKXJOOcsuRG0CC5YQgFUEbP5V8hkH
         nd2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711837994; x=1712442794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+8EwgtrG94oY58QGzvJgMPm1+64UyjWZdtYfNRSUDJQ=;
        b=a9uC9UUdxzp6iN00FIKdwhuxRhGKN0hMjLX3HHYna8jiR4c3swQuwU631enBaf3PFh
         58PZ51ySJMNDcVEyNtQeWszxBmyodpkX1JlLI3kB1K/ziHrbxLOlfKX/MpiFdukYmJ+J
         SB9Nu3qE9XRsJrt6sFXM/OJZ8qjqnSp12JkaDgDwqDMUIzUNSRATwBhFjY2taHjTwd3K
         fUbXVPcyDCGbWJbgAI7AcyemBwA5U+pTNhlZpsAbBcjJvMHjE/gpcVHhoerAWqM1OM1J
         sZwy6U5FLfqRuu3srPdo0LSyc4LPGlgUwq6J7letFIpuQLUq/c8HeeBDLoMTcstS3Ilq
         iwxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMbvd1L0rmcn53euj5tFsCpGIrrjXKvmiH7HParuA3R9PgbBohjUHrcBPC2sXkqPhim5lN4tJWV1EOMplFfgzcFw5rxrmtnA==
X-Gm-Message-State: AOJu0Yy7KPs/kgcgx/diveXgu+UTAQXpsuVjMGIxA96l5c9EL/cYnMwm
	0oikzbKU8TB2OVkdQj+AS++PuFE4NuBNLRB5mJ//jzLYmi92RX6a
X-Google-Smtp-Source: AGHT+IFvO87ahQTj6eeODzuQzhL9Nk1z8cFI/7jJ0MtWt8Ex9ahl6gOOAAZzb5L4AmMebJ6GWDkOwA==
X-Received: by 2002:a05:6820:217:b0:5a4:77f2:1c9f with SMTP id bw23-20020a056820021700b005a477f21c9fmr5677973oob.6.1711837993732;
        Sat, 30 Mar 2024 15:33:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c85:b0:5a4:6d5d:8a6 with SMTP id
 ct5-20020a0568201c8500b005a46d5d08a6ls2995935oob.0.-pod-prod-07-us; Sat, 30
 Mar 2024 15:33:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwnd4n5MGQZEjVq09BYi+nkOfR7Z7BMqmtpHdRi6khgX9iL9yTInFVVOe+b7fusbNA5NUYiLG6EYK4dGFeU9L+bIjDztV7D1WX4g==
X-Received: by 2002:a05:6820:3082:b0:5a4:97f0:ca44 with SMTP id eu2-20020a056820308200b005a497f0ca44mr5573952oob.5.1711837991846;
        Sat, 30 Mar 2024 15:33:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711837991; cv=none;
        d=google.com; s=arc-20160816;
        b=XMOjCZ8PExZv1fyYCL90f6rAIGYFMZGZsVlAKGe8Kl/fCfUw/hsW4ariPH/fbuhTh2
         GYA6cUGhVi34X+oxGAObWk+as6nwVwo35g3luNMoyOZUi5qNGG59dy3E7pXiBVd/y0Pm
         rEtS5G3uXBvIJh31wM5Jt6Tp1qgsrabMKGIaMsu30ePlb8lHb68R2Sa4d1BXCWb5tjZY
         g8tMZH31959pGu2uxpifaJud9r3Q2cV9Yh/AsgRCmwn+/Y7U7fdpfPxx0Pfwpr14+Onf
         Jy4GKJr+z9eOWvR9obde5haCIE0PHjowxi0w/pbNHf0CU127BMOz1uGn01/PYFMIHaSH
         L5VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CjRZqXH4O9NIrKGuArot+5i7bibdSXDsEAYiGs/Hmz8=;
        fh=6cfet2yImcAezdi/1jyrgq14vJuOZUHxgja5to4nfZc=;
        b=jTRNimENz+WmCGPYsz9LHF3fVMNN3s4ZvFb0A5AnFOm6Nmh99psZ2WKU1xcJEBCbyT
         54cB6vEotVANV59oKM7FTqnnq4n0bajd9t6yV/DXaUIbfuYn8CniCYiJ8rhwKSFMzXwA
         ps3JeWmotGMYpxonT2lJy+1rh9cviqerZ+xHjOzyhGtu28H3dgNBYNVhoSrpzik3eKOJ
         zi1CHySc3xnXGmCHcx7DZE5NVrQdRCmIcbpgHXoLYUMsoAf5N6fPhnEhYlelY7CU5Svu
         RvmryMI8iG31qD6FopNL9ssUuRUUwIUrDwudmgB0/VQRZP+nAimeQLUBwe05QUfDu8Kr
         WL+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bxcemWO2;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id k22-20020a4a8516000000b005a4965efccbsi717229ooh.1.2024.03.30.15.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Mar 2024 15:33:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 84D8DCE0AC9
	for <kasan-dev@googlegroups.com>; Sat, 30 Mar 2024 22:33:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6C772C433B2
	for <kasan-dev@googlegroups.com>; Sat, 30 Mar 2024 22:33:08 +0000 (UTC)
Received: by mail-lf1-f53.google.com with SMTP id 2adb3069b0e04-515ac73c516so3177175e87.0
        for <kasan-dev@googlegroups.com>; Sat, 30 Mar 2024 15:33:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMJf6/vqVgkIKFIZTbpLGqci2jjJTbsKjk2h+qyp6Vl14YOrvsYTmJUASdn5MmkW4aiEFPQnM8dGkD/KuvOJ31Bs4xh8Udi9eXkA==
X-Received: by 2002:ac2:5a4b:0:b0:513:d234:e8c1 with SMTP id
 r11-20020ac25a4b000000b00513d234e8c1mr2020997lfn.28.1711837987085; Sat, 30
 Mar 2024 15:33:07 -0700 (PDT)
MIME-Version: 1.0
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com> <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com> <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com> <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
In-Reply-To: <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
From: Masahiro Yamada <masahiroy@kernel.org>
Date: Sun, 31 Mar 2024 07:32:30 +0900
X-Gmail-Original-Message-ID: <CAK7LNASkpxRQHn2HqRbc01CCFK=U0DV607Bbr9QA9xDYhjcwyA@mail.gmail.com>
Message-ID: <CAK7LNASkpxRQHn2HqRbc01CCFK=U0DV607Bbr9QA9xDYhjcwyA@mail.gmail.com>
Subject: Re: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c intermediaries
To: Borislav Petkov <bp@alien8.de>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	Marco Elver <elver@google.com>, Nikolay Borisov <nik.borisov@suse.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Paul Menzel <pmenzel@molgen.mpg.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	David Kaplan <David.Kaplan@amd.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bxcemWO2;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Mar 27, 2024 at 5:26=E2=80=AFAM Borislav Petkov <bp@alien8.de> wrot=
e:
>
> On Tue, Mar 26, 2024 at 08:33:31PM +0100, Marco Elver wrote:
> > I think just removing instrumentation from the mod.c files is very reas=
onable.
>
> Thanks!
>
> @Masahiro: pls send this to Linus now as the commit which adds the
> warning is in 6.9 so we should make sure we release it with all issues
> fixed.
>
> Thx.
>
> ---
> From: "Borislav Petkov (AMD)" <bp@alien8.de>
> Date: Tue, 26 Mar 2024 21:11:01 +0100
>
> When KCSAN and CONSTRUCTORS are enabled, one can trigger the
>
>   "Unpatched return thunk in use. This should not happen!"
>
> catch-all warning.
>
> Usually, when objtool runs on the .o objects, it does generate a section
> .return_sites which contains all offsets in the objects to the return
> thunks of the functions present there. Those return thunks then get
> patched at runtime by the alternatives.
>
> KCSAN and CONSTRUCTORS add this to the the object file's .text.startup
> section:
>
>   -------------------
>   Disassembly of section .text.startup:
>
>   ...
>
>   0000000000000010 <_sub_I_00099_0>:
>     10:   f3 0f 1e fa             endbr64
>     14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                           15: R_X86_64_PLT32      __tsan_init-0x4
>     19:   e9 00 00 00 00          jmp    1e <__UNIQUE_ID___addressable_cr=
yptd_alloc_aead349+0x6>
>                           1a: R_X86_64_PLT32      __x86_return_thunk-0x4
>   -------------------
>
> which, if it is built as a module goes through the intermediary stage of
> creating a <module>.mod.c file which, when translated, receives a second
> constructor:
>
>   -------------------
>   Disassembly of section .text.startup:
>
>   0000000000000010 <_sub_I_00099_0>:
>     10:   f3 0f 1e fa             endbr64
>     14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                           15: R_X86_64_PLT32      __tsan_init-0x4
>     19:   e9 00 00 00 00          jmp    1e <_sub_I_00099_0+0xe>
>                           1a: R_X86_64_PLT32      __x86_return_thunk-0x4
>
>   ...
>
>   0000000000000030 <_sub_I_00099_0>:
>     30:   f3 0f 1e fa             endbr64
>     34:   e8 00 00 00 00          call   39 <_sub_I_00099_0+0x9>
>                           35: R_X86_64_PLT32      __tsan_init-0x4
>     39:   e9 00 00 00 00          jmp    3e <__ksymtab_cryptd_alloc_ahash=
+0x2>
>                           3a: R_X86_64_PLT32      __x86_return_thunk-0x4
>   -------------------
>
> in the .ko file.
>
> Objtool has run already so that second constructor's return thunk cannot
> be added to the .return_sites section and thus the return thunk remains
> unpatched and the warning rightfully fires.
>
> Drop KCSAN flags from the mod.c generation stage as those constructors
> do not contain data races one would be interested about.
>
> Debugged together with David Kaplan <David.Kaplan@amd.com> and Nikolay
> Borisov <nik.borisov@suse.com>.
>
> Reported-by: Paul Menzel <pmenzel@molgen.mpg.de>
> Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>
> Link: https://lore.kernel.org/r/0851a207-7143-417e-be31-8bf2b3afb57d@molg=
en.mpg.de
> ---
>  scripts/Makefile.modfinal | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/scripts/Makefile.modfinal b/scripts/Makefile.modfinal
> index 8568d256d6fb..79fcf2731686 100644
> --- a/scripts/Makefile.modfinal
> +++ b/scripts/Makefile.modfinal
> @@ -23,7 +23,7 @@ modname =3D $(notdir $(@:.mod.o=3D))
>  part-of-module =3D y
>
>  quiet_cmd_cc_o_c =3D CC [M]  $@
> -      cmd_cc_o_c =3D $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV), =
$(c_flags)) -c -o $@ $<
> +      cmd_cc_o_c =3D $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV) $=
(CFLAGS_KCSAN), $(c_flags)) -c -o $@ $<
>
>  %.mod.o: %.mod.c FORCE
>         $(call if_changed_dep,cc_o_c)
> --
> 2.43.0
>
>
>
> --
> Regards/Gruss,
>     Boris.
>
> https://people.kernel.org/tglx/notes-about-netiquette



I applied.

I fixed the typo "the the" and replaced Link: with Closes:
to address the following checkpatch warnings:





WARNING: Possible repeated word: 'the'
#18:
KCSAN and CONSTRUCTORS add this to the the object file's .text.startup



WARNING: Reported-by: should be immediately followed by Closes: with a
URL to the report
#70:
Reported-by: Paul Menzel <pmenzel@molgen.mpg.de>
Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>






Instead of filter-out, you could add
KCSAN_SANITIZE :=3D n
to scripts/Makefile.modfinal because
it is the reason why KCSAN_SANITIZE exists.

But, that is not a big deal.
GCOV flag is also filtered away instead of
GCOV_PROFILE :=3D n


I will probably use a different approach later.



--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK7LNASkpxRQHn2HqRbc01CCFK%3DU0DV607Bbr9QA9xDYhjcwyA%40mail.gmai=
l.com.
