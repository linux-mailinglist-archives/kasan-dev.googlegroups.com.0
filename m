Return-Path: <kasan-dev+bncBDAOJ6534YNBBBGTVW4AMGQEVHYSTRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89C4C99B899
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 08:32:38 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-53997e2fe14sf2911098e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 23:32:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728801158; cv=pass;
        d=google.com; s=arc-20240605;
        b=TpdPEUF+/VMJPfp6FlGoaDCC2Ynqs10N9EzLSm1FzB4QBqqUZFPl2cRSJd5ysTpBM9
         ELmOobnP+dZwHdBBgqDYHPWXiTsOfWmOlsaO8Xs05UiLiUFPCW4AWLace4PztbE8kg9t
         5rhQGftmDk1HatNZLV1mTiQkiQ/M1mXYrXq6Uq+5lJaYfqrqTRhyRLExMY1xxkv09+Ah
         INVr9AjuczRld7X3s/VxMrUiR9vOAGFcI1BpdrhO/SqLI2mlq0FxmKSyHIgtg/kJkCG3
         q+h1+PEpyk8y9+ILRRo9xE3987agxUzxhxB241BRSDz+cN4u35EoLDNG9KXoDx1o/kMC
         LdQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=yhFaSbDiIMQ+WOU3zJiRTNzU8k6Tbln9pC6nlJtOY6k=;
        fh=+xD92kP+fWYElO5midJXxuEkQDytmM+AMkBNHKdd0Bg=;
        b=Niu9CeC2PSnFWeWR4pSPbzs2uYizduQcwEQxvEIDuey92upDeha4VwSvqLR2TwksVI
         U+PHd+13nWVTeRYZq7vUAnnZfhx6t58QHeJZepx73WgSQmNlUuS7RRpLKBXrh8zdgwkP
         RKb5oIeiM3hsXK+3+24AV2Fs4IaapbdOstshEXga8/X2TgaGFtwcc9WdHp9X2wZBWOLV
         RdK/1TAhzgUzDPmVdHruCjco1bSm8r27k8ottn/gNuFCkfgUmi2JHP5xnyz11mgveqCh
         z7jIjUSmiUcZZu/tpghL6p2iAUA7O4AR2XhOXI18q7/Ie2TnftrGNJbrRwNSwjanQLDP
         gIcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SkcSbbLE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728801158; x=1729405958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yhFaSbDiIMQ+WOU3zJiRTNzU8k6Tbln9pC6nlJtOY6k=;
        b=UBFkDWswG+19UVj7ZSvjAxVSD3aedourEDB+EFUc6lQl2XIQ/K36xMhfUBAbQArd2R
         kKMD4j7Z41Vzr+uI8nyekMn8v6emgvODhDCI8kSTlxYFPzdEg1cla/KMOT9pcFPupOPF
         V0WzzjVyyM/DAd1ryn3t9VBFyqPWwFGXstrZRE41EUMZj5B2Fjl5/tz5IeDz8z8ZbY9c
         3WdBHXwJvmDj538RMR655RO0p2cqQRLGd+Ovcs7EkvG3WHNoVRQGyeyYr0lH7DR5Kv0i
         6p/AbSPynavLSk5Dx2eqiw8+Up8FXmMm6FnIoUfU7RguJkwEP0P1m8cLFLLTzrY/37p3
         Sjig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728801158; x=1729405958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yhFaSbDiIMQ+WOU3zJiRTNzU8k6Tbln9pC6nlJtOY6k=;
        b=EpwNJWzfRdql5KDTSyJThAOTioOGkbzgQCtZCiDVo122FyaZAEPw6c4+tB9v7t0EVP
         uUH5FY+eCTcjTGQ2L8oqPAy/o92eyxnG7AvDMmlkyBWMUD+hBouMq9cY65uoha3VpDwL
         CgHmY/PCLMA0aKkDWFu1PQMA2cfwxGLQfEjA0yi58qD2kHcZnS2gFod3OORsHbMy9X78
         TqXnxbgyAMy7GoHb6cxQ2okl9ApYVP1z6eQkvrZA30cdLYVPlnGw/gLDSjdfOAdr2+JK
         SoOdoTJYoUO8PvMEd5uIkLS3Fm2XJVgcfNEBBsDdZga7BlpjsmGCDCVNOvI02vqDwdxs
         CxJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728801158; x=1729405958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yhFaSbDiIMQ+WOU3zJiRTNzU8k6Tbln9pC6nlJtOY6k=;
        b=i7YK7zsNP/cD16OiN8NuGsDcAkbwEdp7Mbhy8TjZroWiGwhKOB996Sei8kTW9/BvNP
         WlSXHodGMthYrCx/uqwKqOP20QBxjdtPGUwbYmDUHxggaMY9PncMIvNQkwC+bcJi6woZ
         RnlkJowd+JMOthOVAb6scGHYQgTfY1NDMTodNwhGL1euDs9qL0TNcKuDLIXcP+pjBvTp
         VFM7MXSnbsmF3KEI0PvMR1HcggEMvlaMCOmqWaxLDt0TQv31YGuADR1DoA+gesuL6jY3
         ogMu+HCR3uUlanvNVFyQoWjsiddWT4629zw6J/xzZpWCLefqvR1JQ8muloA96SS0e6S9
         wB5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCEefw/VkTxCwlkuBuW0PTnfkPWcTA3PQBkIX7cAZJGA0xSrTGp5VD9nxDfmlmQf+49FxzCw==@lfdr.de
X-Gm-Message-State: AOJu0YyXFbeVqaAUm+Q93C6+cpcTKeFqFE21Umyzdxa8hvj27ANf89vE
	bsyk7CFi7soqmXNevYUt230TMcg7GZiNFeaHsVH2HCUz476Qw6XA
X-Google-Smtp-Source: AGHT+IHzvFLlPxRAmST/SRqxmJSJONbYqHxcLTLrqHn5tgwnFXsAe2hO3HV5PpAQLnOEKbsZUcw/0w==
X-Received: by 2002:a05:6512:1594:b0:52e:987f:cfc6 with SMTP id 2adb3069b0e04-539e5741a2cmr1495274e87.51.1728801157104;
        Sat, 12 Oct 2024 23:32:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d0e:b0:539:944b:cb5a with SMTP id
 2adb3069b0e04-539c9b66acals1669434e87.0.-pod-prod-04-eu; Sat, 12 Oct 2024
 23:32:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxWTXKKhUpDZRj4UHbaIzthfDDZhAwDCQav25i5yPNSKD1btKgHqQ8aA8fr1D2ZzNZWtU+mCPYk6s=@googlegroups.com
X-Received: by 2002:a05:6512:1108:b0:535:6cde:5c4d with SMTP id 2adb3069b0e04-539e54d829bmr1870372e87.3.1728801154928;
        Sat, 12 Oct 2024 23:32:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728801154; cv=none;
        d=google.com; s=arc-20240605;
        b=XjI+A+7UKg6bCuaF1UjNVs62Q0mttaPRiFtSNRsZtXVIgTz7rQxjGM7fYiYDAOoKOC
         oD1OErGokGe/CJwchHIx9YcOuVr49yRuuQMMHzA1rjG7Nhk3zLambDOltvzUP4ImELF1
         5BYf8sS+Y5230yM1WhORbnAaM+55XcOjnZQRjUJdJUx3HN2CAuXAF0GZpYssg8XKYT/l
         rrhdP/vV2234MoyJ9XnyUR92jIpNJyDJAHLUwS39ouUKDypQW+d6WkPoOD/4WczF8MxQ
         yvD4BORi2j4n+hjATz/iKjxKLOC3FFMI2KrsqmdBcGVSZnq0qSvWmf+cBc93ykBa+I06
         Wl0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Elf4ApeyMulrVrUDxJM8t7aAJNFW1jcBJ7/MTw4NMUo=;
        fh=yEGhLg3b+pSAsJSnXa8A6Wl598/vH5IFQs6+GpV0gQ8=;
        b=IyFJ5PnEsTwnhK6K60zaehV+vIcY0sF/SbBscs5MhwRuWUn6NLAmdDQU3UGTppD6DR
         B50QeJmI8EXo/aY4Cm71rhWyNwWlncZlyhw5S19skhri6kP5H3hh78EpyLJqL8friYyE
         RCnxCQW6nuXOAAxM8tZ62G2q8B5aJZtM/ATbeVZX1W3o/6W20rs5Rwu5wFKkIyYxEEXT
         qoq6FYuh2m6Cu5fy9/dVk5yJWBzhVe/P6Nlo/KFBIZTBafw3YsxeCjyumoutnSLAJV/4
         sbShRSjCqifKlrB61tbsah8MKDD+r7QpsiLdwUwEj++jpMmEs+foG0z3TCMduVVzxQyE
         P2Wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SkcSbbLE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539cb8dbf59si116876e87.9.2024.10.12.23.32.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Oct 2024 23:32:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5c9454f3bfaso2976773a12.2
        for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 23:32:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUkInYv/0Qkou2lS4ES0y6pVto2h3XMe2WoQM6YrC6zde5RP5mxSaLp2xe/Drj/NVbxGLCKPQp1fLk=@googlegroups.com
X-Received: by 2002:a05:6402:27c7:b0:5c8:8610:98b0 with SMTP id
 4fb4d7f45d1cf-5c95ac4dcfcmr2923431a12.27.1728801153900; Sat, 12 Oct 2024
 23:32:33 -0700 (PDT)
MIME-Version: 1.0
References: <20241011071657.3032690-1-snovitoll@gmail.com> <CACzwLxj21h7nCcS2-KA_q7ybe+5pxH0uCDwu64q_9pPsydneWQ@mail.gmail.com>
 <CA+fCnZdasETx78HOLViEQHDZV1JS7ibzTbmfPzCb--3uN+tLiQ@mail.gmail.com>
In-Reply-To: <CA+fCnZdasETx78HOLViEQHDZV1JS7ibzTbmfPzCb--3uN+tLiQ@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Sun, 13 Oct 2024 11:33:27 +0500
Message-ID: <CACzwLxiWzNqPBp4C1VkaXZ2wDwvY3yZeetCi1TLGFipKW77drA@mail.gmail.com>
Subject: Re: [PATCH] kasan: migrate copy_user_test to kunit
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SkcSbbLE;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Sun, Oct 13, 2024 at 3:49=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Oct 11, 2024 at 11:12=E2=80=AFAM Sabyrzhan Tasbolatov
> <snovitoll@gmail.com> wrote:
> >
> > This has been tested on:
> > - x86_64 with CONFIG_KASAN_GENERIC
> > - arm64 with CONFIG_KASAN_SW_TAGS
> > - arm64 with CONFIG_KASAN_HW_TAGS
> >
> > - arm64 SW_TAGS has 1 failing test which is in the mainline,
> > will try to address it in different patch, not related to changes in th=
is PR:
> > [    9.480716]     # vmalloc_percpu: EXPECTATION FAILED at
> > mm/kasan/kasan_test_c.c:1830
> > [    9.480716]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, =
but
> > [    9.480716]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
> > [    9.480716]         (u8)0xFF =3D=3D 255 (0xff)
> > [    9.481936]     # vmalloc_percpu: EXPECTATION FAILED at
> > mm/kasan/kasan_test_c.c:1830
> > [    9.481936]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, =
but
> > [    9.481936]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
> > [    9.481936]         (u8)0xFF =3D=3D 255 (0xff)
>
> Could you share the kernel config that you use to get this failure?
> This test works for me with my config...
>

Here is config for arm64 with SW_TAGS:
https://gist.githubusercontent.com/novitoll/7ab93edca1f7d71925735075e84fc2e=
c/raw/7da07ae3c06009ad80dba87a0ba188934e31b8af/config-arm64-sw
, config for arm64 with HW_TAGS:
https://gist.githubusercontent.com/novitoll/7ab93edca1f7d71925735075e84fc2e=
c/raw/7da07ae3c06009ad80dba87a0ba188934e31b8af/config-arm64-hw

I've built them with defconfig, then chose in menuconfig KASAN,
enabled KUnit tests.

$ make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-strip
OBJCOPY=3Dllvm-objcopy \
 OBJDUMP=3Dllvm-objdump READELF=3Dllvm-readelf   HOSTCC=3Dclang HOSTCXX=3Dc=
lang++ \
 HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld ARCH=3Darm64 defconfig
$ clang --version
ClangBuiltLinux clang version 14.0.6
(https://github.com/llvm/llvm-project.git
f28c006a5895fc0e329fe15fead81e37457cb1d1)
Target: x86_64-unknown-linux-gnu
Thread model: posix
$ qemu-system-aarch64 \
  -machine virt,mte=3Don \
  -cpu max \
  -smp 2 \
  -m 2048 \
  -hda $IMAGE \
  -kernel $KERNEL/arch/arm64/boot/Image \
  -append "console=3DttyAMA0 root=3D/dev/vda debug earlyprintk=3Dserial
net.iframes=3D0 slub_debug=3DUZ oops=3Dpanic panic_on_warn=3D1 panic=3D-1
ftrace_dump_on_oops=3Dorig_cpu" \
  -net user,hostfwd=3Dtcp::10023-:22 -net nic \
  -nographic \
  -pidfile vm.pid \
  2>&1

> > Here is my full console log of arm64-sw.log:
> > https://gist.githubusercontent.com/novitoll/7ab93edca1f7d71925735075e84=
fc2ec/raw/6ef05758bcc396cd2f5796a5bcb5e41a091224cf/arm64-sw.log
> >
> > - arm64 HW_TAGS has 1 failing test related to new changes
> > and AFAIU, it's known issue related to HW_TAGS:
> >
> > [ 11.167324] # copy_user_test_oob: EXPECTATION FAILED at
> > mm/kasan/kasan_test_c.c:1992
> > [ 11.167324] KASAN failure expected in "unused =3D
> > strncpy_from_user(kmem, usermem, size + 1)", but none occurred
> >
> > Here is the console log of arm64-hw.log:
> > https://gist.github.com/novitoll/7ab93edca1f7d71925735075e84fc2ec#file-=
arm64-hw-log-L11208
>
> I don't remember seeing this issue before, did you manage to figure
> out why this happens?
>

I haven't figured it out yet. All I've understood that for HW_TAGS,
KASAN_GRANULE_SIZE is MTE_GRANULE_SIZE (16),
and I've tried to tweak the buffer size in kunit test, where it's 128
- KASAN_GRANULE_SIZE,
I've also tried to understand the if branches in:

#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do { \
...
      if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) && \

, haven't made any progress on it.

I've faced a similar issue with HW_TAGS in:
https://lore.kernel.org/all/20241011035310.2982017-1-snovitoll@gmail.com/

and also see the comment from you (perhaps, not related):
https://bugzilla.kernel.org/show_bug.cgi?id=3D212205#c2

> Thank you for working on this!

Thanks, I'll address your comments in another reply.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxiWzNqPBp4C1VkaXZ2wDwvY3yZeetCi1TLGFipKW77drA%40mail.gmail.=
com.
