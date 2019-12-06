Return-Path: <kasan-dev+bncBCR5PSMFZYORBH43VHXQKGQEBT3PKNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 994C011508E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 13:46:24 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id x11sf3670543otk.6
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 04:46:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575636383; cv=pass;
        d=google.com; s=arc-20160816;
        b=j5T7sF1/XtP0H7TcE3syfn59aWVme4nkuKxxQ7d88WLR/BzP4mG3eBc/qwvhSqGBak
         dM0Eg2y4WUYp5+Be+gSz8tm8pO0BlezzlxpWV7wG67iW/i040y4zF17xGDsi3M1AQ7Ui
         fasaFLhBCa1F5KGGBilLY3Rfaw7IKuXFxNCChvbnWKCToViqSxuo+L4AvyHYdBLWUu3F
         4pBn6gjbQ5j2PaWUPLAk2xACltdumOESxXd5Z8b+sZ/y8tRzdw8iVmriG70DdrG080/n
         SFU03aKaV9FwIc97REnsS2MZqqPXtAHzAeojAifFVsuttoorqP+R2n5annYsezlsFf7f
         Emtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SPlm3XPHvT5OaA2z+8v3DwxT4qgGaZzf9+SF3ViPno0=;
        b=kxQoGOdMMwsa/FeDmz4QfS1nDZipsy2dVarns1u1K9JHi+KZ8HGowhIhCh2CuqiyZh
         ZJlOgB6q5YZHXyDn2FpN/9doCgde6DtPCczv349MhVS87lytqqxdej7FoBDfrj9kq4Lc
         1Atm/dN4/Cxg04tLsjGyP36MQl5p2TfztLydPlVruH5/BPSfHYDu8X/C5MK3/B/6hp9O
         6kTm4M3tPqOOSFPU0vPYiHd18n8Zh8SO+QGtCA8aVKUydGm795Y2S0MHS/8zL7QXxbUY
         xxCHmH9/4TP4+PD2AA0+F4cdswJhcjRGEXOSmy+nu7InonV/k9RSvQKi6c3qA2LjZm6M
         VprA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=LDjqbEKi;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SPlm3XPHvT5OaA2z+8v3DwxT4qgGaZzf9+SF3ViPno0=;
        b=PrqlUz/69Oi/nBaVHfeEp5jrD88VOeQv7/4JUFk5/bPI6LjRy4GANEQqVAU2zjkNm3
         AIIUWDvE4YXAlK5TOmT+rrKusHcUNEZ1KrJTW15c3WOO8Wf7AHqfv+luhuL+z7bZgz3M
         K08QTwYUVOUQXNYHv6SpbIAjmD9Lw45qJG2Fl0pDxxN1TAOgxtTaFTKAReE+tvYwp6No
         0AIXjvwmrDCtLmrNiZaw/DV+XSShFCEKben74kTYBnFR9a0iOQDaoKsjyoZKa/xs5ybS
         An9wI6EBNbEMWCBR8u94f+uqT12Gx/0KrfTiI6PnaNLB/Tu2oWCwmaVsMW3wDmwPvoqO
         ewPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SPlm3XPHvT5OaA2z+8v3DwxT4qgGaZzf9+SF3ViPno0=;
        b=myQtSCW8tNGeib7tiPRcwoLVyWnPIzUrVwrGvqAL67otXTRM9QUruqmbAhiqfrECso
         BUzViBueEjjMICaisZQcsj2CJHNX8Lg2sRvXF5KqXiYTRrlqOi8a9vy3jg2bAwsIz2NU
         TW4V2MLvhEIzovABwiahECTY+QoCkIklaW9O7tpUUY6KpFbJvQung2QqYajpEvklXr23
         4gSZ1qn4+CXFbLZUGdVQ0NkyJcBP+3qHKz5iHh2BfF3r0q1dOwLhwQjK91XHEFYciBCN
         BJAM6m+5KATfyeXzYc+TuwzlsfBr0yWA9BRE7ACy18ZUgfjGZJ0lLspjaaOf/8jqz7WF
         80qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXkbguzKrM+ExOHUD7JKC/h+RDAhyyOFla5lii3hE1PiPUE5jcS
	hsms6hImVVX+WySywpfgKXQ=
X-Google-Smtp-Source: APXvYqzbgapdCQe0vp22adEb8VdM5XS65a8uQNj5QAVpGDzK9B1cZK7qwLmq4opTktSk2u+VBi1l8A==
X-Received: by 2002:a9d:5c13:: with SMTP id o19mr10133665otk.366.1575636383420;
        Fri, 06 Dec 2019 04:46:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:784:: with SMTP id 126ls1249501oih.8.gmail; Fri, 06 Dec
 2019 04:46:23 -0800 (PST)
X-Received: by 2002:aca:4fcd:: with SMTP id d196mr12157540oib.89.1575636383092;
        Fri, 06 Dec 2019 04:46:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575636383; cv=none;
        d=google.com; s=arc-20160816;
        b=SvoMjZI3L7nV+Iudlhoowb2EBVnBtKPSm2a5Cp0e6A5D1GOY8RLIEQo74wZZUfRL1f
         ep579kJcoR6Cufk9pSxWqFZu8RjVriCVWR3tUIBHX1vGotpEK3HUlxqxfaMZuOiuEMqZ
         Arwk9VYNEV/J3QeDX4TqP+QWQMbn//QMb2AYU6xS6J9O2Cn+0CxNQpdp7zi9Uhc1iCZ+
         IHswN3qaJyW/dn+dUZwcq5cCIP2Rs+qV1cdmgaFtaFp2hlC382IAVQmuytGRFelkEc20
         +Dz4Xa7YErX5FJotv4bOIcubrxBSkWDfnRS4J2m7X2i8Uft8oNfpqH7hb7Xd6TkQOxro
         yJow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qjaq4CifbB0jjf07bIL3hqxv9Tz6WZK/5he1KlEq23Q=;
        b=rIlrZnn5SKNgp93I1Tyx6XWBYs/SElgURZKodW8YFADT4WycFc4Bkajps8my3ftnrE
         ktPmkyyWq9V7CLCpHrt2cpOc4gzuRXp3vn1/rYZJp+EKWj8gAW6M0T4F9CxtVpfQdES6
         cX2lQ/z8JcUButAlCLlWD+JcL6GnGokmjlHAQjDi+3mHPru2cf9qxMo09au8ZzN6vGdB
         ro0FNlIUlYcuB+y0Q40aZyzTimd8MJYuWIz17mdQkMvZTg1nSwQ+d79TqhPNP9r11TOi
         p3MP+gDGFq5Rnho4BDpQcFRIxivzPyJp7HlQfIWOiSyFswN1KYYKKmCBv7mSOqB1s0Mr
         4fWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=LDjqbEKi;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id o26si69893otk.2.2019.12.06.04.46.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2019 04:46:22 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 47TslW10tCz9s4Y;
	Fri,  6 Dec 2019 23:46:14 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: dja@axtens.net, elver@google.com, linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com
Subject: [GIT PULL] Please pull powerpc/linux.git powerpc-5.5-2 tag (topic/kasan-bitops)
Date: Fri, 06 Dec 2019 23:46:11 +1100
Message-ID: <87blslei5o.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=LDjqbEKi;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hi Linus,

Please pull another powerpc update for 5.5.

As you'll see from the diffstat this is mostly not powerpc code. In order to do
KASAN instrumentation of bitops we needed to juggle some of the generic bitops
headers.

Because those changes potentially affect several architectures I wasn't
confident putting them directly into my tree, so I've had them sitting in a
topic branch. That branch (topic/kasan-bitops) has been in linux-next for a
month, and I've not had any feedback that it's caused any problems.

So I think this is good to merge, but it's a standalone pull so if anyone does
object it's not a problem.

cheers


The following changes since commit da0c9ea146cbe92b832f1b0f694840ea8eb33cce:

  Linux 5.4-rc2 (2019-10-06 14:27:30 -0700)

are available in the git repository at:

  https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git tags/powerpc-5.5-2

for you to fetch changes up to 4f4afc2c9599520300b3f2b3666d2034fca03df3:

  docs/core-api: Remove possibly confusing sub-headings from Bit Operations (2019-12-04 21:20:28 +1100)

- ------------------------------------------------------------------
powerpc updates for 5.5 #2

A few commits splitting the KASAN instrumented bitops header in
three, to match the split of the asm-generic bitops headers.

This is needed on powerpc because we use asm-generic/bitops/non-atomic.h,
for the non-atomic bitops, whereas the existing KASAN instrumented
bitops assume all the underlying operations are provided by the arch
as arch_foo() versions.

Thanks to:
  Daniel Axtens & Christophe Leroy.

- ------------------------------------------------------------------
Daniel Axtens (2):
      kasan: support instrumented bitops combined with generic bitops
      powerpc: support KASAN instrumentation of bitops

Michael Ellerman (1):
      docs/core-api: Remove possibly confusing sub-headings from Bit Operations


 Documentation/core-api/kernel-api.rst                |   8 +-
 arch/powerpc/include/asm/bitops.h                    |  51 ++--
 arch/s390/include/asm/bitops.h                       |   4 +-
 arch/x86/include/asm/bitops.h                        |   4 +-
 include/asm-generic/bitops-instrumented.h            | 263 --------------------
 include/asm-generic/bitops/instrumented-atomic.h     | 100 ++++++++
 include/asm-generic/bitops/instrumented-lock.h       |  81 ++++++
 include/asm-generic/bitops/instrumented-non-atomic.h | 114 +++++++++
 8 files changed, 337 insertions(+), 288 deletions(-)
 delete mode 100644 include/asm-generic/bitops-instrumented.h
 create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
 create mode 100644 include/asm-generic/bitops/instrumented-lock.h
 create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEJFGtCPCthwEv2Y/bUevqPMjhpYAFAl3qSS4ACgkQUevqPMjh
pYCp1Q//TrG2tPMDPHpWqCzNdWoh96zpIo2UsauDcc8l+XT7shkwHcGnpoECgCfK
NjhP77qqXI61E+5qUCfO16/j5g6PbvvG/E/xlQEdgX7lIxBeGs4IkoRU8QjkJ9w5
wAjG/XwaMJ21CQY2F51dn9NPQUvFxKV0o6QJ+/pIFBnv0eeYCtRWno7+tZGIiMhk
ExfJhR0rnBdBc6oonNOTAfWn5u51FRRqUeICeo4iFoICu5v4cTbPiU3/8bZYzhSb
wM9WdG+/IUs02PffIQF4GDyMmzi/Qm3Ujl3tUIEaFHlfN9pF6X7Yog7Co26CShJj
No4wJK5rS3ECXmwo7Yd69sV9FZrMZZvGY9x7p7bEE7mqk1fHMaM3DMXvR8Gx6UGM
NCXX2QIIigz3RUTbj3CW2iZa9R/FTSFXs3Ih4YDDJdPNanYpcX3/wE6mpwsco8do
lxWcN1AMGXLiaNdQ8IkRZ6hOLH/Po34RvDo1P1mS06NzfyyTZW7JNiUtU2HSqPRs
vjIkHDM7585ika6jeDHU4cJaLy7bsCNV2fLsHWDE3Xno43g7qcKGOx+PtO25XubZ
iP1vojR4Qml+e3ySf6dDiOIDltSWZwjCGtbi2gmdErHiLdLeJX2XGjC36Qnep6u6
15HIWzX41tg8y4QRJDmPyeDm3Ccbabz+m4LaccbdObgGWVwxwgA=
=06Wr
-----END PGP SIGNATURE-----

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blslei5o.fsf%40mpe.ellerman.id.au.
