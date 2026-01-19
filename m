Return-Path: <kasan-dev+bncBAABBY4SXLFQMGQEEAVXNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id B1735D3B778
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 20:43:33 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-50143b67424sf119083221cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 11:43:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768851812; cv=pass;
        d=google.com; s=arc-20240605;
        b=KEhz8dGKVDBKPuOZfdip5AlwVRo2U4E/r59CdUSJogtgdeLLG/D/EDMs+kf3WnxG6l
         ydpkYyaQWUWTuewZUE71Yt86+LG4nQqnV8Dt8Z6eHGtNASc1FHFpXg94BN+RUvu+DA1H
         /SUhi7HaPSPKb9wcbK4zHET5u/oNVP04neNu6wacq6YM5McHiE32zSTJc6GRDho/dlYN
         gbnqeg9Askns2jv//EksMPS2J0o3Fl/+74DE+XJus2v/uB4cWwcHErsbG3/ncGDr/dAY
         9Pw607/2s0F9RDxP4SgGwsF1xsDLQ+pU0yYinTBgaSw/wA0nqv5CzuPmjtCgNwTBYEH4
         WdxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=tbDTfPdiHTFti0oRJ3PMkZEoJf88HYqwcvD9to0r9kE=;
        fh=Bn/VT7Tuv7Wo7ehAD4SdWiMju1PellH4MLrNg/1ln8s=;
        b=CgoGDsfj+GOT4ix/H+04Ez4LxgQygH7cOzRszGqyWZgbSj4voiSC0wxM+GufedRbWZ
         J5qA3I95dziwOKeCT/NNi9Vla95YGE/ob3CNAvsXuZ60J/vRcmrS6IFc9dpEhmLviyMR
         rCtaF85bbu/BjB6LhySzWK9M4GuO2Q4QBmyq0e8rYVmdieC5rV9WiaVbCZu18DApg9WB
         9jiNWh/XqKkdus43KKCbdQ9zYMNxAFWBbiVBCw/YuiKnBHXU7uiwRrVOgnnq++5D5+c+
         9Eu/QU5Ml3gRdsdr+Ic69FvuPa/6oWfeh2kc5xF+JYjHiokgL3Oh/vtq7P9ajxDZUS++
         Ti7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mmSiMYG6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768851812; x=1769456612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tbDTfPdiHTFti0oRJ3PMkZEoJf88HYqwcvD9to0r9kE=;
        b=W9GEfw4xhQk16owPJ/kBMU5xp1pFBS50sNdJ14t0UgqtKGatVG7zTLDUcpQ1+IDQxE
         JmvQL0vIJ/k3CrBPmkCYeo9WF3P3Yv6vxQNnkcJlOdBCWEJcK1czbt9oxY0SMVOoYZQO
         hGi+iuF3o0Uy2bdwuN7jDe3m7g0O8Lk9Gm2p8F6iItoUyXHzsnzMsW/WD8/wwYKQBo8q
         RvQ8Am39EgfE3R5IsbajSqBEL2yEa2OGuEfHsZmmJlM+Ruy2m60h5IdD2CXO0SnKhBAE
         /iV79QZvbLDHyP9HmvVpenTviXa2wHSQb6/es4lBe9Zs6n0Y6ct0F/iu9weDDLhiZkiU
         Kufw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768851812; x=1769456612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tbDTfPdiHTFti0oRJ3PMkZEoJf88HYqwcvD9to0r9kE=;
        b=fCIy9a8WOXv7NOKxw+sNjjXwB90m9kZkld7qMMQIrUMeA99exkIp3jiaJOu/ELFvIj
         iJP8klV6agM7okZlpo8D6hDSQDwiHvNLB/eMVNoB+ybscHy901vrinj/dMsSGyb1dn58
         Rxtk7in65Y/v5z3lpcp9kRFNv43uD3/UANTnckq2nF37ivZ9aepM5Os9z4e7bjKjaHMf
         jZS8vIO7bU6hyEb7U5BItAEDCm51+ByMVO/+8ZbMjcaUqo5CajL0zrMoswL0rwwTIths
         22xV+EEaf5znNbk4Dcga9pInrOwNCSuLrHHV+KdtXv8MiydxqB1LDQdKNtr8z0dttFkP
         jHoA==
X-Forwarded-Encrypted: i=2; AJvYcCUza+mmv6STFrUUS+2HwIcy5DG+1UAjsuC3vXhPZwqA+LNBmcBAMiZgTb3wGuSoBuDUZ3Kd8Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx5rnnbtYrwD3q2zquY6ALuxYepwVAi6UkhG7E+zHm3scSdW8F2
	EvzUEHVgmtW2UYKVu/YOikVNGdA6H2K4ac/tx93XbMpK/C6riBThYwGR
X-Received: by 2002:ac8:5884:0:b0:501:47e5:cbf8 with SMTP id d75a77b69052e-502a177b98cmr177455471cf.57.1768851812020;
        Mon, 19 Jan 2026 11:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HZIchF4zc3XMQ0D1RPR1nllZ+hmo3LG0/Hax1ywk45sQ=="
Received: by 2002:a05:622a:91:b0:4ec:f039:2eda with SMTP id
 d75a77b69052e-50214a17de4ls80349221cf.2.-pod-prod-09-us; Mon, 19 Jan 2026
 11:43:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWa0ByXuirepj/bdqVZsMHrP4aOPk0xQj9kxe0l1M7qEBNpFyOKlekmBfWMI9/oRFkPpCgmOIvYRE=@googlegroups.com
X-Received: by 2002:a05:620a:191e:b0:8b2:ec00:7840 with SMTP id af79cd13be357-8c6a6704482mr1714063185a.27.1768851811379;
        Mon, 19 Jan 2026 11:43:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768851811; cv=none;
        d=google.com; s=arc-20240605;
        b=VqtlpfRDkw3StF9aMhXH3EilVJiXiT2xlSp9Xa77EHN4NPKQV/6EYMDtvD7t+Oc6XX
         qGiCh1fL+aqB8oGWUpsVRcXhh1leQs2bf4rPuWvyOSW+imdbQyJjQUyWMXLfpd8g4/Q+
         5IkdPYX81WvxpRo0IP7slVIxCaClyZap0Wk4vYW07LlPwKewcLsgkYYOQ4hdHTXxirx/
         PJjUePAgN1f+6GR7Hlvjk3NYE3LLJbISdfurJXrC6t9HD1Qk1LUlDoucGcI/kVXLfEPP
         1Jhj7FpBphiIqVPNKDZhM+B16/wmBN7I/vv926evVH09w0Twqn8Kxdq1Oy87aPKLIyST
         9dlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=s9GRY0FJY6iHKv2Hjum9gopPHHwQIkfpO/pEZWZdRvM=;
        fh=+kRqYKgG1RpI5Un75VzKYkGz29LvUbdEZenL9IVSUd0=;
        b=LMHTC+QtFZIIqz48wY/6Ugpvno1033Sz6HInOgCUeXaB+sJseJaYTNhTiiD9MdcCYc
         Lj6qnC7tHOLjCcxYkpaJfBFuo8rVHz3QIAON40NvObFRT3jvjDUBbCynchK1NLp1Y9lx
         EfLEUO10kOOko4E88G375wGIpof5I97SfgUJEvdJGUi6gIk5aPKainDXGW5FtnVxDkVH
         S71MLCxExCywCkCpZejnrPkukPAkJWvrMdLrOO7n8KZedTfp9/+7Y4gx9tIgK3rNXHW+
         0lBTncKm0Sc3k5IjZi1YCYb6ZXK6NwXOeCqQn20IxfRzjUZbk3SEoT83jbQFK+U2jbFD
         shwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mmSiMYG6;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244122.protonmail.ch (mail-244122.protonmail.ch. [109.224.244.122])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8942e65c5fbsi3736876d6.5.2026.01.19.11.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 11:43:31 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) client-ip=109.224.244.122;
Date: Mon, 19 Jan 2026 19:43:23 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, akpm@linux-foundation.org, Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org, bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com, urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com, andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com, samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com, surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
	yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com, kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org, bp@alien8.de, ardb@kernel.org, justinstitt@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <aW6HcGjkAZ3lITeA@wieczorr-mobl1.localdomain>
In-Reply-To: <e273571e-ab8f-46d6-a44e-c1d0d06d3cbf@gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <e273571e-ab8f-46d6-a44e-c1d0d06d3cbf@gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 85c5e72275bf1238c6f06b30c2b28981083b1095
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=mmSiMYG6;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-19 at 17:33:35 +0100, Andrey Ryabinin wrote:
>On 1/12/26 6:26 PM, Maciej Wieczor-Retman wrote:
>
>> =3D=3D=3D=3D=3D=3D=3D Compilation
>> Clang was used to compile the series (make LLVM=3D1) since gcc doesn't
>> seem to have support for KASAN tag-based compiler instrumentation on
>> x86.
>>
>
>It appears that GCC nominally supports this, but in practice it does not w=
ork.
>Here is a minimal reproducer: https://godbolt.org/z/s85e11T5r
>
>As far as I understand, calling a function through a tagged pointer is not
>supported by the hardware, so GCC attempts to clear the tag before the cal=
l.
>This behavior seems to be inherited from the userspace implementation of H=
WASan (-fsanitize=3Dhwaddress).
>
>I have filed a GCC bug report: https://gcc.gnu.org/bugzilla/show_bug.cgi?i=
d=3D123696
>
>For the kernel, we probably do not want this masking at all, as effectivel=
y 99.9=E2=80=93100%
>of function pointer calls are expected to be untagged anyway.
>
>Clang does not appear to do this, not even for userspace.

Cool, thanks, nice to know why the kernel didn't start with gcc.

I'm going to check in on the bug report every now and then and once it gets
resolved I'll test if everything works as expected on both compilers.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
W6HcGjkAZ3lITeA%40wieczorr-mobl1.localdomain.
