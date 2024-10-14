Return-Path: <kasan-dev+bncBDW2JDUY5AORBSGGWW4AMGQEAGUPKHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3156299D67B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 20:30:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2fb4e2da8basf7084271fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 11:30:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728930634; cv=pass;
        d=google.com; s=arc-20240605;
        b=UPEPSAwt488J3lYpDWtn99/2QYBAroVqJPAXL3ZypmWnl1iCUPs6Rb6uy2aDfLQTIK
         sNZSIuEIrYZwgwS10uexou7K9OTb/Dxzo6tVYHxi7k0q+jvF+BpOtPGVHSEcxgxZplLN
         aqxf4dbQ7GynYuwXXvRtS4xSfwLJ69Big6M1ai7bq5HNdY1p8NqZN/UlXdmNofCCXmqf
         nQ17/4H4T/K/4M2eoDeZOnaRiExbOPPeXnIFp74OlP28SRoyu4mJRqM0Ns7WBUGpBTJO
         NLlGQYohO0lrZS0yTVTF6npbezqTlE/lkHjvoWW3TURKnrHJJeLwO4ogncryfyb/aBRP
         SD0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=yHXFCMXD4W19CN2ddwpD0Guw1ddChAkOle0N9065N5A=;
        fh=n6gfhwRBqoz2vAmDruwziz4aMN8PWhkJXgcpN6mMc9g=;
        b=JoaKLyfp2UbVIy3OPKZY0YA5nzhUeVnhthkiIHTbwnHCjaVcjpNJw1HXqFMkX4E5BP
         7y0Jm/R9Rm3WOYSdxWWMD0IgSfo15DoqYBjcdxh7jeV97+OiQ51lSXkKqIfmb+QeRHS0
         bD8q31ALB+KLViSrDrlZvQu6b1UxhqnghzN+QSuR1ZLDIhbF5h9g3i43gfBAacJuvdNZ
         QmAfGSuOLf1X/RdTq0ajoZOZcJX0qLoB4jjspc61Ozn173yCtWAlG2UvP8wZr2JTWsP7
         f1r8bVW+JLAE6CkhkVAPtwuWRxWLWBuTpKw897eqBerWFkYlJ2WHn0BSpLWfpQe1Hzx/
         CraA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TOC3nFzs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728930634; x=1729535434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yHXFCMXD4W19CN2ddwpD0Guw1ddChAkOle0N9065N5A=;
        b=UAwwIO1IjT97cPhWUJBEKzOJVLxYecBsxJ7t6JeBfe8OpqUXlCduz/vmc77klSVuWN
         2CM/p1Y437wib4rXXT8d56SqHsdFfv0hRDKv36N4FE9NG+eFioT+O636roPNTtla9RhT
         lK7UhZKnjXCNVpvEzMDLBIBZdiSsyqOM7MDYtQ3zrEsNW05489GGYZpDHqN9lVAGAIUH
         FAzkEcr95vpHlpNuZJHCQqcPkt1qIgcQr0RrV0KnNwhofAEe/RwXZ/oru9lMftc5EmoU
         jESYQpuJleRA/VHELdgz84rs/bt2QQezQAG6BLzidVYf4VgDO8i1uQKgpQ0fFIT0pmuC
         4ppQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728930634; x=1729535434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yHXFCMXD4W19CN2ddwpD0Guw1ddChAkOle0N9065N5A=;
        b=D5O1tBVIjEX8LtHJOrEDqCwI/aKnuMG5bYUI1wne8SieCppY8Td5TEEDBsTiosSb1v
         9C4+He2+dhbCpbd5kPKLQgdbLphhByQKnMGipOC85tKV8XTp1Ak/VsGI1+NdhfXF2j4Y
         mQdWjErY+jFSGRdIhAbNxwJFh72IuLNCi0Z4iNWY0geyhyCpBy/X0gKRqeBLSmkkVGOA
         GODDQBBTythOvwOivYNupmdunr5ZMdJxMEAvDxtl2mezGI1Frv5yEVLDkJKLVi4uhCpH
         4ceU4T3w5bYGnRFIF8v8QQoTUsCVctjd5uPy88HuDXf5Sl329owe3uF249ptC9mpbAFa
         1GSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728930634; x=1729535434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yHXFCMXD4W19CN2ddwpD0Guw1ddChAkOle0N9065N5A=;
        b=ht4J18fNPvr83Tj2NiaoAyq27brSE1R2brfwEJfhD1w2hL+BzCejNTNN1mXLivMgMq
         Qke1Lp0tDq8nFUBUkrWvWmRCtQ3Qloup01DgPrpdnujSSu66n0evKRYjt/D9SQeyTyNi
         LaF/y9+QwOba1KzocWfIDDO6QAVnAXtxMtjDijsmwso8VO/bFfg8yWnqnQxZYKi2WGsN
         32OmNZsVpPSCIxSLSr6uuE1cm52lic7HM99IDgH9swhZiYstkgIdAxetqW65nnHbHPTB
         B+hq0BvEblSi0IT50I9oSxV8wT6Uw3qBAm1erhiItDpQZ1faZ5IflrajkqPy52ogWzhS
         BcIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFIJf0VNU0lQODuuLvxH/D1H1NrULZyUDaGeG2TkbtFcERz3EZXonLFB/HVDqMpkzEwfrSdA==@lfdr.de
X-Gm-Message-State: AOJu0YxSrKBNVu8n2VaTk+1i2Ozqv8N3lDvBHkYOhAt8REWY6Ft8igRC
	DdbUmFF8p9hxp5WH5Q2o0hmxiM3LXbucblCHoIV32iN+2n3N8/GT
X-Google-Smtp-Source: AGHT+IFxy2dW2PFjDXI+FNxZ4RghGaXoNqtY2S6gBxdkwTQznlhZw6fnTLQZlfjQ0CLW6p14Y2Pg4Q==
X-Received: by 2002:a05:651c:198a:b0:2fb:5504:7966 with SMTP id 38308e7fff4ca-2fb55047d41mr17376951fa.30.1728930632899;
        Mon, 14 Oct 2024 11:30:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34c2:b0:5bf:bf:efe4 with SMTP id
 4fb4d7f45d1cf-5c933d3e336ls350931a12.2.-pod-prod-08-eu; Mon, 14 Oct 2024
 11:30:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnhVIgucgkvjzVJNOPKV2AYj5A3gV10JqAWJyhdwAsTKnxYV/+6AO5WPlRLlez2SPkT+wi2KRX+lw=@googlegroups.com
X-Received: by 2002:a17:907:3d9f:b0:a99:f29a:bc9a with SMTP id a640c23a62f3a-a99f29abecfmr618623266b.7.1728930630823;
        Mon, 14 Oct 2024 11:30:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728930630; cv=none;
        d=google.com; s=arc-20240605;
        b=F4a5RZ8D0WsZHV3ETH9jKei42l4Zm6R4q7PiDo3CjZ4N8CZGidajHewwD06JGRPM3v
         F3653PobuaRMX63P5mN/0o+uhOIoqtsBNslHj1zK9kf9IgdS9PxEhyj5HcKiu/llCAzx
         YDwJ4sSqa1OX5zpqkh+raY6jJ+GVJO4z3oQqwAf6Au7xO0EfOAQiRAXLhFksDvV6Ntm6
         uAN1XuLUP+Wehnkoy+GoMRqLxovYpes33Wjkiu+bo3ca06FieAiidq9ODbZ+KiyMj1Oe
         6f0IMN4l49pAZMJIt//gYdK6MprbNgLJDRwRWU/yqNTTrY+ghHYgryAeMrYRD8s1i8us
         zifg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8p/i+4MpEi91Z7jAUbGFY6UVGM+tdrsPn8RyPX05x+Q=;
        fh=xkT8NC9bnk9yxp5TCp0+CWasC81M/JMMnYX75e1KoGk=;
        b=gHbxkqK6lnraKbzflyZDIZA6G9oOwyUtR5dUPV6IsOQwffvJg9B9WC4d6Ypnw78Gea
         ilLRaxyjWhDPCg7olQXyG/od6ddaDTuCLSmcOjga7lMDZU7mOCIz5F9l3UfX1KvQ+Is5
         zRS4mFtcdOH1l/Jlv/M/ufklmZLW6bDGXv4OB4RsLTuR/RHzBeglrs94BSZ+0io5xwGv
         BJLyKnyFlMyZYK/02nYvVWznOKoaWS0syZRSs7Z21gZRpEka0y+9xLJz2nkqdE8wilj2
         IJe6xvmWWufAxfOHyLJvPm2FZDUSzBuwmqEN4yJS9sn3MEkcTVak1+BNDXnZvr2v13ya
         BUBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TOC3nFzs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a99e7f339cfsi10405366b.1.2024.10.14.11.30.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 11:30:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-539f72c913aso1439405e87.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 11:30:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVkE0aDpLKgld0iPzrpbgzGzM91S1v8d1vvnFIl3BKTmKKWMmiSutkp5EOHRWQ4wDg1o0Rpsq+3O1g=@googlegroups.com
X-Received: by 2002:a05:6512:1393:b0:539:ebe5:298e with SMTP id
 2adb3069b0e04-539ebe52c0fmr2823532e87.59.1728930629680; Mon, 14 Oct 2024
 11:30:29 -0700 (PDT)
MIME-Version: 1.0
References: <20241014161100.18034-1-will@kernel.org>
In-Reply-To: <20241014161100.18034-1-will@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 14 Oct 2024 20:30:18 +0200
Message-ID: <CA+fCnZccUHpgAYZ3prRBg5y+481CeUi4EuDPHMGBBE5dyRzPQA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
To: Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	ryabinin.a.a@gmail.com, glider@google.com, kasan-dev@googlegroups.com, 
	Mark Rutland <mark.rutland@arm.com>, 
	syzbot+908886656a02769af987@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TOC3nFzs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 14, 2024 at 6:11=E2=80=AFPM Will Deacon <will@kernel.org> wrote=
:
>
> Syzbot reports a KASAN failure early during boot on arm64 when building
> with GCC 12.2.0 and using the Software Tag-Based KASAN mode:
>
>   | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/=
setup.c:133 [inline]
>   | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kerne=
l/setup.c:356
>   | Write of size 4 at addr 03ff800086867e00 by task swapper/0
>   | Pointer tag: [03], memory tag: [fe]
>
> Initial triage indicates that the report is a false positive and a
> thorough investigation of the crash by Mark Rutland revealed the root
> cause to be a bug in GCC:
>
>   > When GCC is passed `-fsanitize=3Dhwaddress` or
>   > `-fsanitize=3Dkernel-hwaddress` it ignores
>   > `__attribute__((no_sanitize_address))`, and instruments functions
>   > we require are not instrumented.
>   >
>   > [...]
>   >
>   > All versions [of GCC] I tried were broken, from 11.3.0 to 14.2.0
>   > inclusive.
>   >
>   > I think we have to disable KASAN_SW_TAGS with GCC until this is
>   > fixed
>
> Disable Software Tag-Based KASAN when building with GCC by making
> CC_HAS_KASAN_SW_TAGS depend on !CC_IS_GCC.
>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> Signed-off-by: Will Deacon <will@kernel.org>
> ---
>  lib/Kconfig.kasan | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
>
> While sweeping up pending fixes and open bug reports, I noticed this one
> had slipped through the cracks...
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 98016e137b7f..233ab2096924 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -22,8 +22,11 @@ config ARCH_DISABLE_KASAN_INLINE
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=3Dkernel-address)
>
> +# GCC appears to ignore no_sanitize_address when -fsanitize=3Dkernel-hwa=
ddress
> +# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=3D218854 (a=
nd
> +# the linked LKML thread) for more details.
>  config CC_HAS_KASAN_SW_TAGS
> -       def_bool $(cc-option, -fsanitize=3Dkernel-hwaddress)
> +       def_bool !CC_IS_GCC && $(cc-option, -fsanitize=3Dkernel-hwaddress=
)
>
>  # This option is only required for software KASAN modes.
>  # Old GCC versions do not have proper support for no_sanitize_address.
> @@ -98,7 +101,7 @@ config KASAN_SW_TAGS
>         help
>           Enables Software Tag-Based KASAN.
>
> -         Requires GCC 11+ or Clang.
> +         Requires Clang.
>
>           Supported only on arm64 CPUs and relies on Top Byte Ignore.
>
> --
> 2.47.0.rc1.288.g06298d1525-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZccUHpgAYZ3prRBg5y%2B481CeUi4EuDPHMGBBE5dyRzPQA%40mail.gm=
ail.com.
