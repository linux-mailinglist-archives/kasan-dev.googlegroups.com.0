Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXGRSYAMGQEKAMHGXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D15D88CF2A
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 21:42:31 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-696429af0efsf3703746d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 13:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711485750; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uj6X5LgxDSXlZG4bDmNQ/NfJRrbJ+rNZb5cPvyRUE/E0k6+FgtNzMIGfAGH2AD+oAc
         NiHSyrD4I8ZExVwk66FXdgq/gd66jn6suqGLdglBPzF/0AWgk0EHNNRqUtL+7GCbaQdv
         oyhCHoksJ6ffAi4B3USF6j7/UqSbijYWpJUzC93LmWSJIIO/Vgr9Q3fPSgsQsigYdOdP
         Jg5W9XA7QPvbZSJ4ssE8pCF46wom6XE8bxSvuTaT8Xta8aVRKYc/1KqRab0clB/61wsC
         dEAkHii5gPvNK4TW+1nOteyFyOMeZq31ZzqGEmSNQe69+JjyvuiVEv4zXoadq/J8xeYA
         pbEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Oy8lm/YF4VcKWVITQgFz7JS5GWUUKltbwc7094IreKA=;
        fh=FXMwJVsCj4xf61cSmVdZCsbsO3Hr0XTwliqL+r7+YHU=;
        b=A7Qv1iHNXtEZgiB7otAO4iKGHYrCCkRQWmwLz7E4oK4jGmlxf4ab3UpxXvbsl9lt77
         jlC3mRFpt7benZRgzr1lf0xWxjzPxYqnvzsfpga4oDz5LIdHwS8gYREtC58P5qvgELqP
         LYQaRs2sVwvYHuHfFBCxqdd6gHID7AMcQAuzJJCJANg8ZYeT6fkhiooVWRiJwSZY50BI
         pIkCYT/CHNA7mu6Ne8MqcbUqiVio3sS1/vN8iRna32eSrl54fyvuNG44MYgsGbADKuei
         uxBCa+XmTgnI007VrQe1XzqL2Pme9Wh2WHdQGLsefEm0OTazBzoEGXLgcg30a22xc4BT
         Fk8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=icb7FHV+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711485750; x=1712090550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Oy8lm/YF4VcKWVITQgFz7JS5GWUUKltbwc7094IreKA=;
        b=Cy84p3FhPxzDjIho4jk5qgPVQVAo5h2QHYdhZqYcmCEO+LGDcWSfkDW1hQCTWg+m+V
         zh4Z5/KGk65w9o18aZgjTH9Ht3Lug2+1TFEIGWI1qD4Ed0iscoq6/V58lieCB+5VRYmZ
         3aY6g40THeokW4rvmwdsiFovwFhpCD+M4UJoqSUoc0xKNBb3IoRpqgrktR/3Kk8+C1Fq
         ho6dwKA8X6Mh7yLLFeEzYAgZd9PswsoV0Y85cUG0NGYCH6wtABvsrr7/Fie1ppCs/UY5
         MCRoAK54wIl6SqbYJtQUgf4G4Dwc33z7DjatJYXxVRgx2f265S2p0tlNwdpOMuBvSVdt
         NpRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711485750; x=1712090550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Oy8lm/YF4VcKWVITQgFz7JS5GWUUKltbwc7094IreKA=;
        b=Xi177/9+kzkWt4NL4xHeDTk5Ul48NLyKlAkpKXjaJh/kn/nI7L3oO5wZFCFNZEzz8L
         6d1uNeCq6OquDCwoyZTr9YZOLDMNX+nVKClwZXKSn4c+mVbfklOMF9H31RatvOf11Be+
         L2+PXlFQIYgiJgF2SEQiGnkk/EJXZnbD5YteEvLktPS5aspyxJxiiG1BEaiDnoSO0hkz
         3rm3NuHQalCE/R53iV5YpsrmPuVd8n0vic9/Gll2kX8rqQ2dTiQQdmHQnivrIMMvAFbk
         X3XOxJcklA9VccVDJQ/JbgQTo765deqsiKlxXyzBZc7gipVwNQjW1ybMKEaWbn0A6DAN
         wIRQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUAIv7s2hX12KKjwTK9l7u5xHuhKZ2jI6LeliO9xySHh+UD4+cKJ8h/xyAF/8fgnuZ1swqNn/iajSGyRLuL4QNb2XeaC5lQw==
X-Gm-Message-State: AOJu0YwTcCbWyxpPZpLUXm0FmI7XXyM2wA/Dtd1rkekVF3rb/BUmHixo
	RPRNm3xMFwAZMyPZ8GZINtR7yUwUI/gMtijrS5+XsZtrk8RAzjFT
X-Google-Smtp-Source: AGHT+IEs5SI0vO5XR2wH/6fCctN6W22LTyiOZZekte3VSwqSweRGgrC5UhqAavcESdaZbFvtnR8c5Q==
X-Received: by 2002:a05:6214:1928:b0:696:a2ea:7c71 with SMTP id es8-20020a056214192800b00696a2ea7c71mr2559117qvb.9.1711485750227;
        Tue, 26 Mar 2024 13:42:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2aa5:b0:68f:2ba3:a9d7 with SMTP id
 js5-20020a0562142aa500b0068f2ba3a9d7ls1970638qvb.2.-pod-prod-00-us; Tue, 26
 Mar 2024 13:42:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUr8fNdS2llp65RSscyM+rtqTvq6xdh8VMNKvYtfZmpOK5f32y6YrJnVgfFTLX2Vonx7pMnqimUMLJrMXcVpjMRvH2PCy2D+O0skg==
X-Received: by 2002:a05:6102:ca:b0:476:e1b2:c9d2 with SMTP id u10-20020a05610200ca00b00476e1b2c9d2mr1999263vsp.14.1711485749411;
        Tue, 26 Mar 2024 13:42:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711485749; cv=none;
        d=google.com; s=arc-20160816;
        b=kgoom+wGlFFWyaD9tpg4KIh4lvDiRGk7AXuInjb3aTkPCudxyuX/w4TjMT/rKu5pJv
         hEweEroaoLDDZzr9VPsIwC5Cn9QbqRbuyRc2Q27fLY4fzBiY9DTnGvEDL0OfwTnq+/g9
         hPci6RzT7GXbTEFkdE550tnqzyx9jo6cdU5i14iRG2tWKnCQs2z5uc1ghzYGBgw2RnG+
         jm2GYWuk0Udb6dP9O+hMZgksFo4MRomUfiJmCol2kGR471X/vqSbAc9+kaY4vPHbV22S
         0jybQmWrYXbfhygi+iLuP9qEth3MYPxUtvnFri+WICbDgpQduAvR+hBHQOshlYwHB0RO
         uVWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WXbMV//iCVDcmmeY0RArWtkZ2QeUzFh9TWNfWy7C9Pk=;
        fh=iPctFYuUVtPNuPPLqz1XWw8DQ3LZ/0KHCnRK20QjEMs=;
        b=rB6XrS1iC3pNqoy6rFKGBplm8uT2uCYn7AdJVvg8LS4AVhFC8Au9MHW3aHI/NPEEaD
         1hxa80p9wv0HAy5D8h5N/KAeR0wufqNgh2MoXVnGWHkrTllqB0kIdLK0wh7cLS+2LiPR
         zu/ogEhA8uFjE2wpXnJ3maLHhSWwEAcLkR6xe5IXLx0h5JyEeWD2xULSXQ7kFtqoacAy
         futf5M/Br0X9QowjXJepFngEVVW5qI88xSQyGlr+Oo/5GPVNPyeuDbwtpCIMImrfe6pq
         K3UNxnggKo3vxun6YuqKVZbOrOZxJgpyOH0jkiwz19/SyILmXp6DF7EPKmEYFq5UtXWn
         VQeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=icb7FHV+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id dt2-20020a056130140200b007e113310243si394264uab.0.2024.03.26.13.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 13:42:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id 71dfb90a1353d-4d438e141d5so111913e0c.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 13:42:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXpD421g9k9TgH0EDL0VRvbpisVL4lBKV1qwK3uG62X+F6kpOdJz4pyhJoT+stDHIAySTv8HVho6m9iOQHojGiIpl7cfBQzFxxPpA==
X-Received: by 2002:a05:6122:181c:b0:4d4:4ff8:c367 with SMTP id
 ay28-20020a056122181c00b004d44ff8c367mr2307752vkb.6.1711485748894; Tue, 26
 Mar 2024 13:42:28 -0700 (PDT)
MIME-Version: 1.0
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com> <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com> <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com> <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
In-Reply-To: <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Mar 2024 21:41:50 +0100
Message-ID: <CANpmjNM0fnqDJHZYxvy6dfTHE3jeCv-rXmaJiD5XXx+bodF1-A@mail.gmail.com>
Subject: Re: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c intermediaries
To: Borislav Petkov <bp@alien8.de>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org, 
	Nikolay Borisov <nik.borisov@suse.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Paul Menzel <pmenzel@molgen.mpg.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	David Kaplan <David.Kaplan@amd.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=icb7FHV+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as
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

On Tue, 26 Mar 2024 at 21:26, Borislav Petkov <bp@alien8.de> wrote:
>
> On Tue, Mar 26, 2024 at 08:33:31PM +0100, Marco Elver wrote:
> > I think just removing instrumentation from the mod.c files is very reasonable.
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
>     19:   e9 00 00 00 00          jmp    1e <__UNIQUE_ID___addressable_cryptd_alloc_aead349+0x6>
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
>     39:   e9 00 00 00 00          jmp    3e <__ksymtab_cryptd_alloc_ahash+0x2>
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
> Link: https://lore.kernel.org/r/0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> ---
>  scripts/Makefile.modfinal | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM0fnqDJHZYxvy6dfTHE3jeCv-rXmaJiD5XXx%2BbodF1-A%40mail.gmail.com.
