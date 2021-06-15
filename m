Return-Path: <kasan-dev+bncBDEZDPVRZMARBZVYUSDAMGQEJMSRSGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 502C33A8B1F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 23:32:23 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 67-20020a2514460000b029053a9edba2a6sf21959955ybu.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 14:32:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623792742; cv=pass;
        d=google.com; s=arc-20160816;
        b=VHgCjFw6VTPFonLR2/GilpafJOn5yoJw3H5hgLJ3v57i41ZpE90X/zGXhNUDD2Vqc3
         RSJJlIUXQ2gePuzO2Ft4A9xus7WHxb6NZifADqXGASZEbHVrHAhA2m6Fv7URMoXuKk2b
         nNfLVxR78C+f+OPZblZO6lmFMt+XMOu65IV5rdAo38f3q1rLbFIPqym2TEvVPGdYZKcO
         O0BcLOpb3SvSBk7F6fpmcnm8xcQh5nNSfJZaXHOI9IwukP8Pqkj25KPfLJldH8IRfFYN
         iHYarhWAl1N1JEMGuWmWextEY2EI9qXTfqnSYHr9kQks8c5am5UyQvS4GGUfan5g15F4
         oNDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0UjXpa04cbchzeR4eA3guJZwDcVfSXY13L0GoOnV0Og=;
        b=v5fwPMablg9vH+IWmJHg1IKRE+i8QUOrQVz8tydCUHAjIOU6UNaWt9f5j59o+VwFc2
         EPLwRmCQAm+TL3WzGFC3T4/CdvKv0whHAjU8CCzD/00TQhhSe84ycCox4LhG463MXrXM
         ctels4HGKIs8/W2zdvaioguA+G80/i0K4G32sNRNeb/Tx9Nacinxyt9Lodx8jtvwInPK
         TBUEcu+T8dkUi/UkXCvkl5w+SupYsdjbf23EOW1hLf6Z0iq22dVVz1nwnlw5egnNm0oK
         3dePRFbnNOmFlr3akBaCMd3awAZ17+4phhPHJMhcmrtUZEXAqa/BzSjGLA2Y8wSONSvO
         y3Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dlg4FUfR;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0UjXpa04cbchzeR4eA3guJZwDcVfSXY13L0GoOnV0Og=;
        b=iL6V/2WOteUq7iUIJ+WRd4TUSYzGL53ykpefTYo5fNiVHdW4lQ6ay6EwzlYpXM2vbA
         cQQ629TFrzn0cAhZGMjP2HvLWtfeTAYCZi8d6NxBcTjw8jyWd9Jhp1I5wJF/zkjScWws
         bfZscWcFUMQMrCEEdalsxWJVu6Xf2DsjgdAEdNGA401wVRUxgsoRPMNx7Z4GVCu3zXfq
         O3CQxGezASC3KQrZPRSkW9gFdfx3MWFSVk9wL5H3GvEQk1nuw+J6pfRefkeeXeqxJoTn
         SVxNlsuxIJRr8eDqWvPzimPHqiY/ZiVWGtIQkf6jxQ1+QpT71AyXaQrrHUc67aqCCcX9
         Bbmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0UjXpa04cbchzeR4eA3guJZwDcVfSXY13L0GoOnV0Og=;
        b=Wq8EUoaDVRpxFlsA4zv1pPtoLKbYetTrprQ2tJ3Ms+BwUMlNJXdyY5bcxjej8nSRBe
         Th2GQVxpfNBLUq8LYu/qlVcaAkhwzx8fsbfAsALtAlw8AsiowPBepjPsRXNk1Psj2nEF
         4GGcGBCvSpUpbRxJJrHxVRGEwCr/LXdP+2e6FR5lPkk69X0GMemxy9JP4MCuTR4yK7pv
         7+yyPtIb7T+UT+4VVCwl/jQ01v22kqZM2J0u5TU2L2ZRaw7lRmiEKqVpJ9UHLiFtVnTO
         7xsOS8dPIzt8JD3m/VUX+oxiMC1zwkvNVuwSJOJxyXC9ebTr5mWXEITW4vXcyA8eB+mX
         dxXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eSCuOkmOUljn7lpG/LZyBN1zfTybVfShxVDVwocrmJca6o8eC
	a6RTl2yfi30Y480Ufenazxo=
X-Google-Smtp-Source: ABdhPJwTnFqOStXyJfoRnCs1M/RZrcJFv4HuVA4MJq6ZK0SFra+aR2ZPrTdMrhb40myrFp/ynhFiCA==
X-Received: by 2002:a25:ad41:: with SMTP id l1mr1755462ybe.380.1623792742225;
        Tue, 15 Jun 2021 14:32:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:544:: with SMTP id z4ls220757ybs.3.gmail; Tue, 15
 Jun 2021 14:32:21 -0700 (PDT)
X-Received: by 2002:a25:18c3:: with SMTP id 186mr1819367yby.0.1623792741812;
        Tue, 15 Jun 2021 14:32:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623792741; cv=none;
        d=google.com; s=arc-20160816;
        b=AKwnFXdQQLjH7qpfrws1OuTR1R4zFLD950xPdLQhJqPHS011u+3A80X67d2IgxHDUY
         3yVT8XJ9NSSdT9lV6c7Z6fBrvMZTP5oFeJi6vvSnyW2c4fnRdxY8Ru+5ce/D+Z8M/4F9
         CffQ7shVN080IRgo0uXULkQkRkcUcm1Sl2r3vvISJ1GbO33JEVCwDhlp3YqXfDZCONv6
         /QgZ9+ot+l/gacslrOFxidpeehfQ983i59KIbfVjQfy5lnxCocVrExT2MEXYoG7ydkIW
         Pl7df71O8J9sJoeyWwSz5yYrhtHz/0m+rvQ/IiRLTFR+KMAgDZWbQnFr2Jxyl8YkpjIT
         acEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vBn1Kq8SJGcxfnaOZmYoqEOirrBNr6M7PkXW/RMINCM=;
        b=jsleEjv/lKaryOdylkhhhpfyou2I9rLXfAkGIJmjuu0OjtQQ92nLcgTzI7+UBQA8yx
         IUQQy8eRZlpkxsqAiWRy8mvI49bjj/oIey+iYXrMU/Q5LvevdjC1GokPzcGBFwoK6HJV
         bxgJ1c/goRiao+v8JJ0RbzDPcBmx93lyL+fiuGv1pGxgtpwoW2TC19anAwzl9HlNM/KR
         aRC99Tw/UxTwTjOXHE9zu4+zb6knBfDu1Yjxkj3/bIUs9PvlHkzlkC69eVvW3HLHWggU
         yUabQwLeU68uZqlGAbP7gO5OjsHOr+4+zQaIkyvLUVj1QDsBUK3z8SrqJ5xzgfABXyej
         EEuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dlg4FUfR;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q62si10633ybc.4.2021.06.15.14.32.21
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Jun 2021 14:32:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2820A610C8;
	Tue, 15 Jun 2021 21:32:20 +0000 (UTC)
Date: Tue, 15 Jun 2021 14:32:18 -0700
From: Eric Biggers <ebiggers@kernel.org>
To: Daniel Borkmann <daniel@iogearbox.net>
Cc: Edward Cree <ecree.xilinx@gmail.com>,
	Kurt Manucredo <fuzzybritches0@gmail.com>,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
	keescook@chromium.org, yhs@fb.com, dvyukov@google.com,
	andrii@kernel.org, ast@kernel.org, bpf@vger.kernel.org,
	davem@davemloft.net, hawk@kernel.org, john.fastabend@gmail.com,
	kafai@fb.com, kpsingh@kernel.org, kuba@kernel.org,
	linux-kernel@vger.kernel.org, netdev@vger.kernel.org,
	songliubraving@fb.com, syzkaller-bugs@googlegroups.com,
	nathan@kernel.org, ndesaulniers@google.com,
	clang-built-linux@googlegroups.com,
	kernel-hardening@lists.openwall.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Message-ID: <YMkcYn4dyZBY/ze+@gmail.com>
References: <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
 <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com>
 <YMkAbNQiIBbhD7+P@gmail.com>
 <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dbcfb2d3-0054-3ee6-6e76-5bd78023a4f2@iogearbox.net>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Dlg4FUfR;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 15, 2021 at 11:08:18PM +0200, Daniel Borkmann wrote:
> On 6/15/21 9:33 PM, Eric Biggers wrote:
> > On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
> > > 
> > > As I understand it, the UBSAN report is coming from the eBPF interpreter,
> > >   which is the *slow path* and indeed on many production systems is
> > >   compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
> > > Perhaps a better approach to the fix would be to change the interpreter
> > >   to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
> > >   bitnesses), thus matching the behaviour of most chips' shift opcodes.
> > > This would shut up UBSAN, without affecting JIT code generation.
> > 
> > Yes, I suggested that last week
> > (https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  The AND will even
> > get optimized out when compiling for most CPUs.
> 
> Did you check if the generated interpreter code for e.g. x86 is the same
> before/after with that?

Yes, on x86_64 with gcc 10.2.1, the disassembly of ___bpf_prog_run() is the same
both before and after (with UBSAN disabled).  Here is the patch I used:

diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index 5e31ee9f7512..996db8a1bbfb 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -1407,12 +1407,30 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
 		DST = (u32) DST OP (u32) IMM;	\
 		CONT;
 
+	/*
+	 * Explicitly mask the shift amounts with 63 or 31 to avoid undefined
+	 * behavior.  Normally this won't affect the generated code.
+	 */
+#define ALU_SHIFT(OPCODE, OP)		\
+	ALU64_##OPCODE##_X:		\
+		DST = DST OP (SRC & 63);\
+		CONT;			\
+	ALU_##OPCODE##_X:		\
+		DST = (u32) DST OP ((u32)SRC & 31);	\
+		CONT;			\
+	ALU64_##OPCODE##_K:		\
+		DST = DST OP (IMM & 63);	\
+		CONT;			\
+	ALU_##OPCODE##_K:		\
+		DST = (u32) DST OP ((u32)IMM & 31);	\
+		CONT;
+
 	ALU(ADD,  +)
 	ALU(SUB,  -)
 	ALU(AND,  &)
 	ALU(OR,   |)
-	ALU(LSH, <<)
-	ALU(RSH, >>)
+	ALU_SHIFT(LSH, <<)
+	ALU_SHIFT(RSH, >>)
 	ALU(XOR,  ^)
 	ALU(MUL,  *)
 #undef ALU

> 
> How does UBSAN detect this in general? I would assume generated code for
> interpreter wrt DST = DST << SRC would not really change as otherwise all
> valid cases would be broken as well, given compiler has not really room
> to optimize or make any assumptions here, in other words, it's only
> propagating potential quirks under such cases from underlying arch.

UBSAN inserts code that checks that shift amounts are in range.

In theory there are cases where the undefined behavior of out-of-range shift
amounts could cause problems.  For example, a compiler could make the following
function always return true, as it can assume that 'b' is in the range [0, 31].

	bool foo(int a, int b, int *c)
	{
		*c = a << b;
		return b < 32;
	}

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMkcYn4dyZBY/ze%2B%40gmail.com.
