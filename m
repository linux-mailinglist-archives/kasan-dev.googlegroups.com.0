Return-Path: <kasan-dev+bncBC6L3EFVX4NRBDXEROYAMGQEDARODCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6009688C872
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 17:04:32 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2d496045d19sf52001121fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 09:04:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711469072; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpVxJ9xk2XEhfjSyti73glr4g7QK0TfNXucwFiwcHjU3QqCOBvImgK7++LlNQP/lvM
         ABekSqzn6UGzb78jVuwQf66S4ZvYjZT7VBDr2zFfbibOUqOYF/XUJ9HR4RRKl7Fctj3Q
         PJGufmUmJKvbKalu3Ltr3jCstGe8DP6wzC37sgrQWUdN+/VCvEvYRVVfhp254NNbLE8G
         PlFlgUoeyunefKt4jcQPwHToTlpKI74Y1YDKxCqHXhO/5Pk/niyk2pEQfdKvjbx/JBeP
         /hHzCp2PFnEk7s/EAQ9JyYRG8HpXx1XxiNPmK/R6QoGarTMULMmvXx3S3ew6VbENWtsO
         zCkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=996L7w+RZsELmemTMYx9pdI3NNbmWs7brTJlYyPo32A=;
        fh=C+H9XD3ZwatB1snzetlh5Zhb/s/cgKLtJbH/ywM5hUk=;
        b=RYrQhy4I0JLBm/UUSjmVGMxklheN0aE7hKsdschkBAdLfkFl0Mm1BkDWlyVunkiZtT
         ahStbnNXF22tK15drFeMmNkt6k4azbGol+g3W56HrnS0lSCj++CHPVswTavQvgo8/AHE
         hCMMJrnLmtIWlfHHWhrQOz9HkAGunaL7HLyGaLcMllEtYCfVd7RXtV4k4t47kVKqweC/
         538n70/c3CYkM/sur1X6lqyQHyzofASi6cOVsrBMPhSuMWF0WM47S+Vw43eTGdhQ+7C6
         uN0UCVbJpmFau7VG68n5kfsE93tuuHhnFWKUFcZeWOBM96PkDVZWs0Vvf48yYzC9p6/C
         V4DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=cEICiqhg;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711469072; x=1712073872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=996L7w+RZsELmemTMYx9pdI3NNbmWs7brTJlYyPo32A=;
        b=pgKc/xK3EmPxKFuD5NIVQ6hwj2FRa9NymOPmmh7LaBqC+9sIzSUquhzZ2Ot2Z2cgva
         Y6VITND4qPyT4GIiS6sX5TBfxR9okxH2nin66dRUAwox4pYMFSDNO0yxW9tzizDy/789
         UD269Cm3j+tHT57tql44siVxkVcpKAk2n1ii65sZbKklz4peGDNQWYdyAE0OvqEiHsZy
         jb6SPcioMe4EC+GvcxCp7z8Lfjj3lKpBeH4EEQ/w6Dwp9EIR9JZi2MjGK/9O7INvE1N1
         4MaGaDuQ6YcXTtCIc/a59KdT46n/l+5ArhCELY3Ko80/O6rsjKM1TUGelgoOCAnT4wlb
         B40Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711469072; x=1712073872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=996L7w+RZsELmemTMYx9pdI3NNbmWs7brTJlYyPo32A=;
        b=kDGLdefrD9o+8/H9ZGnGf05+DUQAzbtYo+D/VD0HTmZSVg/bvUclLc9t2lKOA5TqbA
         GydK1vMedbA3n2k1NxSvOyboaU08rMxe6bbM7UpVzs/rQKw/Bv++IrfeRhvCPpxO84di
         IH9TLxmoUte9HF6w+qHtGXgknrja35/6RgRjWVQ38tReHEfnJ5+nkZ9bb0BVzUMzRH8g
         MUSA4RPb5x3EWupsCxpw5Q9r1UGFM8q/F7OhzKJwWBWQfHPP2zEo1BN3yhcNddaO+69I
         pqLDLCRmIuKc1PnhIu2m2+ix4kBwBVmyoRhwTvW3Ft0kN0zneg5cYdPmInsRkeILzGi1
         8XsA==
X-Forwarded-Encrypted: i=2; AJvYcCXBaOXxQZE+ajrC8FrdWl8fhPOlP7kn7LUz0bCQtETyWMbGfkNPwoVtx61tefA/tlvKpzpFcCFG+RKCOC6uAMoAicbpRN+4dg==
X-Gm-Message-State: AOJu0YwAfJ2K/nZnBLtsGNB4WPj6jDvHbG0PEzAI2u5Z64mqfwt04s6m
	LbHUOO/1uF6gIH+S5NdkLKUOGk7VJNRplZS74yh4IhnFERc4xDdP
X-Google-Smtp-Source: AGHT+IGqJ1XnT81B811bwZWcbP0NM0zKilYXt4Wr6UTXxFx+WPS/NcO5TTQttOTsid6pRzdaA+sbeQ==
X-Received: by 2002:a2e:b6ce:0:b0:2d4:6c08:5f94 with SMTP id m14-20020a2eb6ce000000b002d46c085f94mr2363629ljo.37.1711469070606;
        Tue, 26 Mar 2024 09:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8397:0:b0:2d4:122c:9578 with SMTP id x23-20020a2e8397000000b002d4122c9578ls722776ljg.2.-pod-prod-01-eu;
 Tue, 26 Mar 2024 09:04:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjyChppglBd6PLTedF+fnluGr9TFh0qfSoW8n9cUHtxIkVCKaAiLuaGUBFIEbeKt/0tlQ50KaC1Xirqei4XaKqIw9Oeu0fHqWzxg==
X-Received: by 2002:a2e:a9a4:0:b0:2d4:9333:8e38 with SMTP id x36-20020a2ea9a4000000b002d493338e38mr2826344ljq.38.1711469068477;
        Tue, 26 Mar 2024 09:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711469068; cv=none;
        d=google.com; s=arc-20160816;
        b=Whre6ZVaa/4eHBDtpTsAM1A3rLRZUKW6qxeagpEIcOwjygC6YtIx7vOj9jJh1Fom2p
         6fvdfHc9AJxiXb+qQQyrdxro7oGUc8czRXJSR0WGAEPq7waTjZ+DokC3E2tGfMwfHG8q
         g0XMJ09hU2WDIFhsamUP7w6HvbtDbD+10zqjDHz+0iJp3ffm6mVVt/eVig7a2/NA1XJt
         pBBZ998nOB0cEzQueaXC+ds1SFb52uspAUobbJ0cBfjjxgnNbyKnY13hOlbr+Bvltsli
         92LGovfsSSEHfPnPM+6pnsiS2TM1YF81dJ8i8fFTubZt+cOPpZ2DXSoWbqUHqlt/pMEw
         hgVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=VHaAJ4RnYHJ8KX34kKTxzTaqVnfDqn1/9DcdAoyFrhw=;
        fh=pAylO0Age3ExUGrYbIuJ2A2b7a8GAlwCsxNg0CizBPc=;
        b=01YcBCNqm19hut0pDjyBeUrEIOa3SYL1NYS65WWoiQBYtasPe3YRV/TCo92c6g97r5
         /xozPO8Oa2aHW1JFRp1bqpS2YDgHoKtJJlUQGe1Oa+wAFb7kffGGAHSRK6+s9jWd2j0v
         sY3xxO33LPYHGTeeLFTFEiIme8cVaJ1lQYD3qBgFnVQjvXhE1lPrIgY1McnmDdkVkZ1A
         4KvYQyUWgZmz0w6daf+d+ZZRxwdULvTUU0rkjinwvGWitCCIgHKrYb7l8O7L4O2WMUep
         wBCDVRz/lj70s0ixcumh4Sv8hO3fZtF76iC0XyLbcqpY4A4YFbWN7JdfpVfdXErBSfD2
         DtTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=cEICiqhg;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id e25-20020a2e9859000000b002d46764b564si312061ljj.6.2024.03.26.09.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 09:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-41490d05b2cso2786675e9.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 09:04:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLbKgV2lmpm2Db6DLqdc7v82tzBQwwldOTVoz5Tx8bT+RHNiDH5GWhoqSgeHrrad5DNFW0YxWCjO951JtA2vigMyHvZXDYLRaciQ==
X-Received: by 2002:a05:600c:3c9c:b0:414:22b5:c33a with SMTP id bg28-20020a05600c3c9c00b0041422b5c33amr2466458wmb.1.1711469067629;
        Tue, 26 Mar 2024 09:04:27 -0700 (PDT)
Received: from ?IPV6:2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a? ([2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a])
        by smtp.gmail.com with ESMTPSA id j19-20020a05600c191300b00414610d9223sm11999819wmq.14.2024.03.26.09.04.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 09:04:27 -0700 (PDT)
Message-ID: <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
Date: Tue, 26 Mar 2024 18:04:26 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Unpatched return thunk in use. This should not happen!
Content-Language: en-US
To: Borislav Petkov <bp@alien8.de>
Cc: Paul Menzel <pmenzel@molgen.mpg.de>, Thomas Gleixner
 <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
 kasan-dev@googlegroups.com
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
From: "'Nikolay Borisov' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nik.borisov@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=cEICiqhg;       spf=pass
 (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32b
 as permitted sender) smtp.mailfrom=nik.borisov@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Nikolay Borisov <nik.borisov@suse.com>
Reply-To: Nikolay Borisov <nik.borisov@suse.com>
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



On 26.03.24 =D0=B3. 17:52 =D1=87., Borislav Petkov wrote:
> On Tue, Mar 26, 2024 at 04:08:32PM +0200, Nikolay Borisov wrote:
>> So the problem happens when KCSAN=3Dy CONFIG_CONSTRUCTORS is also enable=
d and
>> this results in an indirect call in do_mod_ctors():
>>
>>     mod->ctors[i]();
>>
>>
>> When KCSAN is disabled, do_mod_ctors is empty, hence the warning is not
>> printed.
>=20
> Yeah, KCSAN is doing something weird. I was able to stop the guest when
> the warning fires. Here's what I see:
>=20
> The callstack when it fires:
>=20
> #0  warn_thunk_thunk () at arch/x86/entry/entry.S:48
> #1  0xffffffff811a98f9 in do_mod_ctors (mod=3D0xffffffffa00052c0) at kern=
el/module/main.c:2462
> #2  do_init_module (mod=3Dmod@entry=3D0xffffffffa00052c0) at kernel/modul=
e/main.c:2535
> #3  0xffffffff811ad2e1 in load_module (info=3Dinfo@entry=3D0xffffc900004c=
7dd0, uargs=3Duargs@entry=3D0x564c103dd4a0 "", flags=3Dflags@entry=3D0) at =
kernel/module/main.c:3001
> #4  0xffffffff811ad8ef in init_module_from_file (f=3Df@entry=3D0xffff8880=
151c5d00, uargs=3Duargs@entry=3D0x564c103dd4a0 "", flags=3Dflags@entry=3D0)=
 at kernel/module/main.c:3168
> #5  0xffffffff811adade in idempotent_init_module (f=3Df@entry=3D0xffff888=
0151c5d00, uargs=3Duargs@entry=3D0x564c103dd4a0 "", flags=3Dflags@entry=3D0=
) at kernel/module/main.c:3185
> #6  0xffffffff811adec9 in __do_sys_finit_module (flags=3D0, uargs=3D0x564=
c103dd4a0 "", fd=3D3) at kernel/module/main.c:3206
> #7  __se_sys_finit_module (flags=3D<optimized out>, uargs=3D9488468999081=
6, fd=3D3) at kernel/module/main.c:3189
> #8  __x64_sys_finit_module (regs=3D<optimized out>) at kernel/module/main=
.c:3189
> #9  0xffffffff81fccdff in do_syscall_x64 (nr=3D<optimized out>, regs=3D0x=
ffffc900004c7f58) at arch/x86/entry/common.c:52
> #10 do_syscall_64 (regs=3D0xffffc900004c7f58, nr=3D<optimized out>) at ar=
ch/x86/entry/common.c:83
> #11 0xffffffff82000126 in entry_SYSCALL_64 () at arch/x86/entry/entry_64.=
S:120
> #12 0x0000000000000000 in ?? ()
>=20
> Now, when we look at frame #1:
>=20
> ffffffff811a9800 <do_init_module>:
> ffffffff811a9800:       e8 bb 36 ee ff          call   ffffffff8108cec0 <=
__fentry__>
> ffffffff811a9805:       41 57                   push   %r15
> ffffffff811a9807:       41 56                   push   %r14
> ffffffff811a9809:       41 55                   push   %r13
> ffffffff811a980b:       41 54                   push   %r12
> ffffffff811a980d:       55                      push   %rbp
> ffffffff811a980e:       53                      push   %rbx
> ffffffff811a980f:       48 89 fb                mov    %rdi,%rbx
> ffffffff811a9812:       48 c7 c7 c8 9f 6a 82    mov    $0xffffffff826a9fc=
8,%rdi
> ffffffff811a9819:       48 83 ec 08             sub    $0x8,%rsp
> ffffffff811a981d:       e8 5e 51 0d 00          call   ffffffff8127e980 <=
__tsan_read8>
> ffffffff811a9822:       48 8b 3d 9f 07 50 01    mov    0x150079f(%rip),%r=
di        # ffffffff826a9fc8 <kmalloc_caches+0x28>
>=20
> ...
>=20
> ffffffff811a98ec:       e8 8f 50 0d 00          call   ffffffff8127e980 <=
__tsan_read8>
> ffffffff811a98f1:       49 8b 07                mov    (%r15),%rax
> ffffffff811a98f4:       e8 27 d1 e3 00          call   ffffffff81fe6a20 <=
__x86_indirect_thunk_array>
> ffffffff811a98f9:       4c 89 ef                mov    %r13,%rdi
>=20
> there's that call to the indirect array. Which is in the static kernel im=
age:
>=20
> ffffffff81fe6a20 <__x86_indirect_thunk_array>:
> ffffffff81fe6a20:       e8 01 00 00 00          call   ffffffff81fe6a26 <=
__x86_indirect_thunk_array+0x6>
> ffffffff81fe6a25:       cc                      int3
> ffffffff81fe6a26:       48 89 04 24             mov    %rax,(%rsp)
> ffffffff81fe6a2a:       e9 b1 07 00 00          jmp    ffffffff81fe71e0 <=
__x86_return_thunk>
>=20
> where you'd think, ah, yes, that's why it fires.
>=20
> BUT! The live kernel image in gdb looks like this:
>=20
> Dump of assembler code for function __x86_indirect_thunk_array:
>     0xffffffff81fe6a20 <+0>:     call   0xffffffff81fe6a26 <__x86_indirec=
t_thunk_array+6>
>     0xffffffff81fe6a25 <+5>:     int3
>     0xffffffff81fe6a26 <+6>:     mov    %rax,(%rsp)
>     0xffffffff81fe6a2a <+10>:    jmp    0xffffffff81fe70a0 <srso_return_t=
hunk>
>=20
> so the right thunk is already there!
>=20
> And yet, the warning still fired.

But you eventually call the address that was in %RAX from within=20
srso_return_thunk, so it's likely that's where the warning is triggered.=20
As far as I managed to see that address is supposed to be some compiler=20
generated constructors that calls tsan_init. Dumping the .init_array=20
contains:


      .type   _sub_I_00099_0, @function=20

   25 _sub_I_00099_0:=20

   24         endbr64=20

   23         call    __tsan_init     #=20

   22         jmp     __x86_return_thunk=20

   21         .size   _sub_I_00099_0, .-_sub_I_00099_0=20

   20         .section        .init_array.00099,"aw"=20

   19         .align 8=20

   18         .quad   _sub_I_00099_0=20

   17         .ident  "GCC: (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0"=20

   16         .section        .note.GNU-stack,"",@progbits=20

   15         .section        .note.gnu.property,"a"=20

   14         .align 8=20

   13         .long   1f - 0f=20

   12         .long   4f - 1f=20

   11         .long   5=20

   10 0:=20

    9         .string "GNU"=20

    8 1:=20

    7         .align 8=20

    6         .long   0xc0000002=20

    5         .long   3f - 2f=20

    4 2:=20

    3         .long   0x1=20

    2 3:=20

    1         .align 8=20

    0 4:


So this       _sub_I_00099_0 is the compiler generated ctors that is=20
likely not patched. What's strange is that when adding debugging code I=20
see that 2 ctors are being executed and only the 2nd one fires:

[    7.635418] in do_mod_ctors
[    7.635425] calling 0 ctor 00000000aa7a443a
[    7.635430] called 0 ctor
[    7.635433] calling 1 ctor 00000000fe9d0d54
[    7.635437] ------------[ cut here ]------------
[    7.635441] Unpatched return thunk in use. This should not happen!


>=20
> I need to singlestep this whole loading bit more carefully.
>=20
> Thx.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/80582244-8c1c-4eb4-8881-db68a1428817%40suse.com.
