Return-Path: <kasan-dev+bncBCP35GGZRMDRBZW2USDAMGQEV2ZPI2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DC073A8BFA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 00:44:55 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id j2-20020a2e6e020000b02900f2f75a122asf346023ljc.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 15:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623797094; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxfNuVp5GD0Wv4lRoFTsM+WrtXoQNQ3mMV44+0wyXqgciJ3MfgAtHklYEi545lzRjE
         NUkUUXnmVk3yylcNBRSBWgZNVlnM6w5MZtdiwoAIYVI3N/kveKmt3P/Q+LuUPj1l2vlP
         /fJRcOvPOEeFJRtReLzj3rX108Oaz1ItSj4lwFL9HBJvBDpY0OzcvDMIP36+fGP2IfYq
         VVnqUYNWeiLxdDW8gk2RbDsuUwKZeseb5Z6aAkdB1GoTrQVZsd+9YsMspz6Bfw3tXlUq
         yByeASIpiFKJkjUkzu5iT0HMfNm1Nqy3QUuDRKrqCW3cNY5fk81JbyqH4k3tMSNaUiVc
         oojg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :date:references:in-reply-to:message-id:from:to:cc:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=f3V1GHYLYdme+VtCIFnuem9y1TXlqMab6R7YhpMAhwc=;
        b=WpMHev1QBCxFutVwPpnPoMDk6k96rK73HK4CqYB1CnlhPgEn1NLZqHYVHjeENzPpn2
         LeNaqQt60FJe2jtTUvbQh5lRJa6Rg+bhhEGtg2xEH89+kM/cGQ4OjvHm3GLtJkDrxo4H
         h2zyHsZ6tclKhhbflXIjoFxzRx23VglVrNpxKvAIjOfEdHW7qXBbMVcoeRbpm4Kdknm3
         OUfVjcDEvfvU38WJZISE3tSSqOz5gKP20pgztMFAzpbIrT722NIEMOrhaxj9RjQvALft
         W0Rdx6ANg4huBfFOp7UxWma1dbb79SFOhrJ+kn3HS3BNQKdbbZrpS8nW97zPDrD9c5sL
         rGMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HS0GT+xp;
       spf=pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:cc:to:from:message-id:in-reply-to:references
         :date:subject:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f3V1GHYLYdme+VtCIFnuem9y1TXlqMab6R7YhpMAhwc=;
        b=enblPAAZCqOBFwQn3CnA1dB/XF5QdMT3g+byvHt27tvMSkwYfZAi6f2lkhrOAj6tmN
         zTEKFPO15MfqCfDuo0uPgMQI/nmDOHDFACmjcDNWrae2qUmj0AMcjJ3fjmgYkfQaqPSW
         ZKA+InVnvNm8Zesce8jVKKLVW+XGmVhDRaPISr54JvqKwAvmoETAlq1NC8Iv8OIxfxtg
         OVihzAuRxxyCN8PYEbYHeBYxTxZZG0lA07zspg+lUmz/6Erabfx5KUFOMsVt5wgbuiLK
         tnZP3au9OtAAj7Y4BbVOEK8JYCnMWAFsdmhPM3hq41ZfyUfIILtsZVGjfXPJq+Ca2tAK
         pwcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:cc:to:from:message-id:in-reply-to:references:date
         :subject:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f3V1GHYLYdme+VtCIFnuem9y1TXlqMab6R7YhpMAhwc=;
        b=mcC6ExMC6+3O9MUa4WHqo4y7kvPnk5nOGwR1fLUNxAu0bWW2X6Oz8JCnZqT2Gy/WRS
         3IYMgeAD06qm5yHPgPuJ9UFAzjPpBjClNkX6V/zdGCUOywMQ6C8OHNKvuqRgAlsAYJU5
         YxGMf8Cp75AaegmSrp25hM1Pbkjf4jbKrJhtmBv+tJzB+neBOvYc057gzaMLzJ6eFo8Z
         CS72cJqHDj7nsnfrMfeWs/N+gwptuD2hALjuOX6axuvpdcBhSRAk+FRgnlq7bN1gbzFG
         oeLQL//kmUY0Fdu8+eMxYhGL5sGBf/w8o0kh86jtWh1eI0Ov8MR2MgSkToi27I9iapnm
         5wkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:cc:to:from:message-id
         :in-reply-to:references:date:subject:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f3V1GHYLYdme+VtCIFnuem9y1TXlqMab6R7YhpMAhwc=;
        b=Fo2G9zbKBArQ49zJnRuxtlhwkJdsOTWxQ0Jl7PGuQeEMok9bCLcyfQjjqtUBYfgf5/
         7CdyzzLOysrD9mblByS0te8jSS/IpmU2BPAvcWlLamZIwWrt7jqT6S7mnFnfT02IzVS9
         1m+/70CWJq6Fa5x/sImtJtERPKfH7B0ULTmxbefvrHRZZYsAufjUGLOrR5BpGNQ6CmBx
         knQlvkj64pgyLCkPf9TAnnQcztkswDoSQGvzrdj0239VCdMegL0tBJ9ycIGvH0SFa9nC
         hsjVzDC2dNjSErCnBxwjQMT1znQPfoVpLUpA1UP10h1hpjNe8xE9OixBuQNXOMneCBsV
         FHww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Zc0xUs+VHXvVVzq7TLFotkdUhU+/rtRgk0VhdKSk6QynDpY1h
	vp07n6Adw8c7oQg59Hzpn8A=
X-Google-Smtp-Source: ABdhPJxPgyra2fQO54C+1bWNWxhNRouTPpU1igYCSL5Nvp7zI1SK7dlMX986xWDmDPK5kduW++0PbQ==
X-Received: by 2002:ac2:4c0a:: with SMTP id t10mr1166974lfq.401.1623797094775;
        Tue, 15 Jun 2021 15:44:54 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86c7:: with SMTP id n7ls86563ljj.4.gmail; Tue, 15 Jun
 2021 15:44:53 -0700 (PDT)
X-Received: by 2002:a05:651c:50c:: with SMTP id o12mr1688257ljp.364.1623797093697;
        Tue, 15 Jun 2021 15:44:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623797093; cv=none;
        d=google.com; s=arc-20160816;
        b=X4PBx4uvtAeqzz6/wWXsTYWEHPERIcW4rZZFXT8Ja8sFv68KeGT8kUQBMlGEVV9q22
         AsxNyYQ3lZKRUfeqrunO6rx7CEZys3FPXJ+mX0nLnVTONWCVw8lBpTvydWiRvwPEZuE3
         poq5BbcQRB/wWJJ0gQ+QOaEGYhgKYxLsixYgk8vH5ggPbf/lzD4IZEv/hUotYYvUoJEm
         K8qMnV56UU/xS4xwfLM2susRXwiAxMpFhPj4mMyVxSce3+eyGtAjuIu9rMpcL+kEjK/Y
         BSuEFFNWdE6onl2Fzb3+fG2qG7wXTflaChQhRNYvog4aUmrLxbrRD9UlZCiATmaAU0Mn
         nLOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:date:references:in-reply-to:message-id:from:to:cc
         :dkim-signature;
        bh=yAsKDxu4OsJzll8QC5S0Yfmf14kqjw1ys0j1yn9M9SA=;
        b=sDAWDOR9jT8RlqcHcGTuPQAmiVMbHPrpC4rIy99/Vqmt12gSMfPUJOyq+8kuE1mnXg
         Ho4XG7zEMgdqoy8x/oqzXZmB0EuP/sTPugMku7jAJpN1MyReuHlBtQOpq1PGqR15WeNV
         p0MKWY4RVY/fTAXA7MArTq9dDz8tOqxvkHAi6DdWy5woj21FF21JpXXqRvgvWSsAlsVd
         Vhu6TyOmaspOU7Vc+HNv4fj0DzooHMTugU8M4H/0ZEjPpg69YAA/dBIe550qfNkLIVBQ
         MlpCBKJYa6nFe8LGxOzl+C4Fn0Red5fciy+EJKEovXcgoe+YL8VzjqTe5rphHBgLX1y8
         Rogw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HS0GT+xp;
       spf=pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id j2si8652lfe.8.2021.06.15.15.44.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 15:44:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id q5so356929wrm.1;
        Tue, 15 Jun 2021 15:44:53 -0700 (PDT)
X-Received: by 2002:a5d:5585:: with SMTP id i5mr1483433wrv.371.1623797093202;
        Tue, 15 Jun 2021 15:44:53 -0700 (PDT)
Received: from localhost ([185.199.80.151])
        by smtp.gmail.com with ESMTPSA id t82sm139726wmf.22.2021.06.15.15.44.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 15:44:52 -0700 (PDT)
Cc: ecree.xilinx@gmail.com,
    syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
    keescook@chromium.org,
    yhs@fb.com,
    dvyukov@google.com,
    andrii@kernel.org,
    ast@kernel.org,
    bpf@vger.kernel.org,
    davem@davemloft.net,
    hawk@kernel.org,
    john.fastabend@gmail.com,
    kafai@fb.com,
    kpsingh@kernel.org,
    kuba@kernel.org,
    linux-kernel@vger.kernel.org,
    netdev@vger.kernel.org,
    songliubraving@fb.com,
    syzkaller-bugs@googlegroups.com,
    nathan@kernel.org,
    ndesaulniers@google.com,
    clang-built-linux@googlegroups.com,
    kernel-hardening@lists.openwall.com,
    kasan-dev@googlegroups.com
To: ebiggers@kernel.org,
    daniel@iogearbox.net
From: "Kurt Manucredo" <fuzzybritches0@gmail.com>
Message-ID: <31138-26823-curtm@phaethon>
In-Reply-To: <YMkkr5G6E8lcFymG@gmail.com>
References: <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
 <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com>
 <YMkAbNQiIBbhD7+P@gmail.com>
 <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
 <YMkcYn4dyZBY/ze+@gmail.com>
 <YMkdx1VB0i+fhjAY@gmail.com>
 <4713f6e9-2cfb-e2a6-c42d-b2a62f035bf2@iogearbox.net>
 <YMkkr5G6E8lcFymG@gmail.com>
Date: Wed, 16 Jun 2021 00:31:49 +0200
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
X-Original-Sender: fuzzybritches0@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=HS0GT+xp;       spf=pass
 (google.com: domain of fuzzybritches0@gmail.com designates
 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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

On Tue, 15 Jun 2021 15:07:43 -0700, Eric Biggers <ebiggers@kernel.org> wrot=
e:
>=20
> On Tue, Jun 15, 2021 at 11:54:41PM +0200, Daniel Borkmann wrote:
> > On 6/15/21 11:38 PM, Eric Biggers wrote:
> > > On Tue, Jun 15, 2021 at 02:32:18PM -0700, Eric Biggers wrote:
> > > > On Tue, Jun 15, 2021 at 11:08:18PM +0200, Daniel Borkmann wrote:
> > > > > On 6/15/21 9:33 PM, Eric Biggers wrote:
> > > > > > On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
> > > > > > >=20
> > > > > > > As I understand it, the UBSAN report is coming from the eBPF =
interpreter,
> > > > > > >    which is the *slow path* and indeed on many production sys=
tems is
> > > > > > >    compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_=
ON).
> > > > > > > Perhaps a better approach to the fix would be to change the i=
nterpreter
> > > > > > >    to compute "DST =3D DST << (SRC & 63);" (and similar for o=
ther shifts and
> > > > > > >    bitnesses), thus matching the behaviour of most chips' shi=
ft opcodes.
> > > > > > > This would shut up UBSAN, without affecting JIT code generati=
on.
> > > > > >=20
> > > > > > Yes, I suggested that last week
> > > > > > (https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  T=
he AND will even
> > > > > > get optimized out when compiling for most CPUs.
> > > > >=20
> > > > > Did you check if the generated interpreter code for e.g. x86 is t=
he same
> > > > > before/after with that?
> > > >=20
> > > > Yes, on x86_64 with gcc 10.2.1, the disassembly of ___bpf_prog_run(=
) is the same
> > > > both before and after (with UBSAN disabled).  Here is the patch I u=
sed:
> > > >=20
> > > > diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
> > > > index 5e31ee9f7512..996db8a1bbfb 100644
> > > > --- a/kernel/bpf/core.c
> > > > +++ b/kernel/bpf/core.c
> > > > @@ -1407,12 +1407,30 @@ static u64 ___bpf_prog_run(u64 *regs, const=
 struct bpf_insn *insn)
> > > >   		DST =3D (u32) DST OP (u32) IMM;	> > >   		CONT;
> > > > +	/*
> > > > +	 * Explicitly mask the shift amounts with 63 or 31 to avoid undef=
ined
> > > > +	 * behavior.  Normally this won't affect the generated code.
> >=20
> > The last one should probably be more specific in terms of 'normally', e=
.g. that
> > it is expected that the compiler is optimizing this away for archs like=
 x86. Is
> > arm64 also covered by this ... do you happen to know on which archs thi=
s won't
> > be the case?
> >=20
> > Additionally, I think such comment should probably be more clear in tha=
t it also
> > needs to give proper guidance to JIT authors that look at the interpret=
er code to
> > see what they need to implement, in other words, that they don't end up=
 copying
> > an explicit AND instruction emission if not needed there.
>=20
> Same result on arm64 with gcc 10.2.0.
>=20
> On arm32 it is different, probably because the 64-bit shifts aren't nativ=
e in
> that case.  I don't know about other architectures.  But there aren't man=
y ways
> to implement shifts, and using just the low bits of the shift amount is t=
he most
> logical way.
>=20
> Please feel free to send out a patch with whatever comment you want.  The=
 diff I
> gave was just an example and I am not an expert in BPF.
>=20
> >=20
> > > > +	 */
> > > > +#define ALU_SHIFT(OPCODE, OP)		> > > +	ALU64_##OPCODE##_X:		> > > =
+		DST =3D DST OP (SRC & 63);> > > +		CONT;			> > > +	ALU_##OPCODE##_X:		> =
> > +		DST =3D (u32) DST OP ((u32)SRC & 31);	> > > +		CONT;			> > > +	ALU64=
_##OPCODE##_K:		> > > +		DST =3D DST OP (IMM & 63);	> > > +		CONT;			> > > =
+	ALU_##OPCODE##_K:		> > > +		DST =3D (u32) DST OP ((u32)IMM & 31);	> > > +=
		CONT;
> >=20
> > For the *_K cases these are explicitly rejected by the verifier already=
. Is this
> > required here nevertheless to suppress UBSAN false positive?
> >=20
>=20
> No, I just didn't know that these constants are never out of range.  Plea=
se feel
> free to send out a patch that does this properly.
>=20
The shift-out-of-bounds on syzbot happens in ALU_##OPCODE##_X only. To
pass the syzbot test, only ALU_##OPCODE##_X needs to be guarded.

This old patch I tested on syzbot puts a check in all four.
https://syzkaller.appspot.com/text?tag=3DPatch&x=3D11f8cacbd00000

https://syzkaller.appspot.com/bug?id=3Dedb51be4c9a320186328893287bb30d5eed0=
9231

thanks,

kind regards

Kurt Manucredo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/31138-26823-curtm%40phaethon.
