Return-Path: <kasan-dev+bncBDCPL7WX3MKBBPGV7C2QMGQEUNUHFQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id AA405953821
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 18:20:13 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-39b3a9f9f5bsf11222645ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 09:20:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723738812; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXRgpHwgXAywmWvHjv+z95YJdRRQJQx+zdeACZm85Ph1+sVkgcqPEFNi6RrE2bn8Mh
         3qezPSN1lGaWAbe6eq9lLVxOU2cV1AQJSjzKMqaUHyTXNvMA0qsC07bOFZQEchoiFAYi
         apLjVN5yGwrfwwtQYIYDlY4UjvestkXxxrfsnUcmX747UsqeWE8JszWKGY6j6CQS7gvi
         0gs0ICzA9/oiWmih/gA4VnG8EVEWaYxM1qOArMNZ3UTlD/vjQGUkp/Szdjkg90cCE//4
         CRaTuwGnlM/3yH1pja8kGSZSwt4F2RS8kPl2SUq28xs8+WFS3MDitETiN7/U/QoFv8dh
         0ozQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/ycd98hkNtAkSxhDTzbXXBOrP/1dqwj5r8e7i3RWT58=;
        fh=39ieNkckxW1j0q0hvPYNnCBwt8Z5RjBLpJQRIYXn7vg=;
        b=WRUAlkS5EtxnX8ifRQ21BwHM9nJVQqxpZDlz38JZuEoJTClmhYzcudYi0Dtr8d3wEc
         2xuDvYbwertQfu4jmDPAsShVgMem2aXF923Pbu1YJFhG3vTStAhXClD075Y21XOJd7bB
         Imvf5rmpqhi4a5yn2+O7ugFy3GvRg80FI3yFkW5GlucxVcE7IILUY6w6Zo1/bT++QPjq
         +g2fyHwCoxG+HwMdGDN4Irnxc2eJANftcJAiJsd3VzDteiFaKLqlgifeqXhA/N7Q9pys
         njKG+JCT0tpdFAZy+p/L1ymlGwbxij9MGZ7YAPQ6O0eMP+PtquQq+x3hzvBhXO+nexF3
         Hvgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V+4zvyf7;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723738812; x=1724343612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/ycd98hkNtAkSxhDTzbXXBOrP/1dqwj5r8e7i3RWT58=;
        b=Thi4qLNJ3CBaIs/o8mz3i0nBPlMa2Vhgg6UW+53tkFD2l3GWs7svkQle1QGeFVu0mX
         HiM5SBf+ADc8b/HWRgw68Rl6VojR+X1lFn7GcrChAzB+r4lArFGPKa/p5VHVjIEXFcjK
         aElE+jZ7MpZQQZ+j572wSLWEcZRgAUkfLjkCXdaWLYlSEL4Afs/BWKDsBjpkZ4rXxib4
         Hefy3qTWR3Vxa8a3Kt/hhMhq/7AtRabh4BfNFKSvjM6ovU/w9+5/OrgPDsK3ukyqCUBG
         z6WgH6MEMS+iCeUsTsEy7G7mRGDJw+Zn6KVVAprCqOMnfNR2f7GAI3lDa2y3wzQ7wUh9
         Tp2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723738812; x=1724343612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/ycd98hkNtAkSxhDTzbXXBOrP/1dqwj5r8e7i3RWT58=;
        b=EKesmwSXGNtN+Hr/VIZg1jCvUOE/vkW3fjqdvipIP4iDj6LfxAOUzklXi9LWJmIhsV
         Q3bsuwXiiC0IAQ3VwMG7QETKjaNtfyX5XUDach27/vyJt48Fwghfj5IS3vTSGF9yK11v
         pmuJDfgfAgUx2jgsG9/33WMBj2vPzsMgjkfB77G9ojN6hfdpn2XUSRRpVyb89gLcdHp/
         r9CvtslAN1qNuC95B9utE61SxKAOqZErpsbNKc4MY5UgFEne+IyfYVkDMUHhkp/kxpvL
         Od9KsNR4v2wGz9W1+ta3oB2zji680vQkoZ2X7bRh+KEcwWIA5jPKCCaWuRKjKBSv6Fa3
         oXrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKunhXNvFTx1xXtoYhRhmmpCeSewekMOB+GdSynyWxgCnkifLsaOZi570Cw44ePRZ3+/Sn8+JKP2Yq9UOEbQ2jghbaVeoSCQ==
X-Gm-Message-State: AOJu0YzTkejqHZZEigB5gWRtTX58Dbh/HKOw0CD8uQ16FmpAxL3AcG2w
	TTa/2TUHcYUX+4w/QzoJwmDyCjIk5PtDeJZSU6HcgKn2NzprFDSK
X-Google-Smtp-Source: AGHT+IGDQF4sa4QFdGiYuCmV13QkV77GxV7SvlVHVkotVE1d6LYYsskhNQgbHkqbPNIamEv7V1KR7w==
X-Received: by 2002:a05:6e02:1ca3:b0:375:e04f:55ac with SMTP id e9e14a558f8ab-39d26d0c7fdmr4548635ab.16.1723738812391;
        Thu, 15 Aug 2024 09:20:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a69:b0:39b:35ad:1cbe with SMTP id
 e9e14a558f8ab-39d1bbec481ls8532295ab.0.-pod-prod-03-us; Thu, 15 Aug 2024
 09:20:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyGl1XwR7hZ//T4kECxJRlwpzSFkIrGDap3vRA7wEGMS3IjZ2H2PjEEWsctpziFRjyZS5IEFGJubOcJpUJlzGUNHQqRZJdwIRHdw==
X-Received: by 2002:a05:6602:1586:b0:81f:8f5d:6e19 with SMTP id ca18e2360f4ac-824f25f70e0mr41145139f.2.1723738811480;
        Thu, 15 Aug 2024 09:20:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723738811; cv=none;
        d=google.com; s=arc-20160816;
        b=y99l8vxUQ3tuMrFqp3aP3yAgWJ91a7FZ7zCxFCs5z0wxRKwoFvi16d2Iq0YLWPu32C
         CBSzDCk4oLr4kKlz2XmfUS97/7YwBp3ZKBrfrF+8qBZmrnLBsGYbLTwFQn6+dLPo5Vr6
         QG9kYuWt1gBdDQ9S2zviyr5MEB7/bRi0CbweWPvr5szG7aWXd8pxavz+PCcsXPmQ2S16
         SbJ2YQETufcINppzVAuFRR6naydODW5AQamox3WTdGQC6LZSxKUam48Bwfh4ybh6c/H9
         4dR8Yax7yDQ6/njo5ErMmSHsJjPAodN6tJ936GBOVXX1AJiDdFWCy9ZIwppl39SV+JjU
         6EyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=p5bWyzbLss5oQkJdeTU4rQMAg5jXosCLlTKgD7jMXBc=;
        fh=ruEydNv/CCGeYH3oEY7mFm9Gd8mOKvBCtzgXW2n02q4=;
        b=wjb1RUzojrg2pgdP6ZBJMlcRcZyxcJ9NnjCJuRQdbuPO5ck84nM8jIelsNj0AYhG0+
         JVobpvuFxcbg1A0lRIDaqV33+VqFQYr9ODzh406IKty6gXEk0UHRgzLmgUd13eSiEz2p
         y6pzVSEs7EDhzSrc+X2/bID7K/SWRZIY93muDBtmT84bcRWlbHVLQEGVF3K57yI+fyIt
         FN95sp7nwWMsZPAApZH7+m62n+uogg71T6Xvip0L7yPBAO3/aKnJe8nUVBIsMl9jWKCb
         VkEnUaLyUqKcFST+oNkNn20n8Q9uxFWtmY3b1fUVz8L9rlv3ZJggF2KAa65ninn0JClG
         CKHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V+4zvyf7;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ccd6f4cbb2si69386173.5.2024.08.15.09.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2024 09:20:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id BFA29CE1BE3;
	Thu, 15 Aug 2024 16:20:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C473FC32786;
	Thu, 15 Aug 2024 16:20:07 +0000 (UTC)
Date: Thu, 15 Aug 2024 09:20:07 -0700
From: Kees Cook <kees@kernel.org>
To: Justin Stitt <justinstitt@google.com>
Cc: Breno Leitao <leitao@debian.org>, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	axboe@kernel.dk, asml.silence@gmail.com, netdev@vger.kernel.org
Subject: Re: UBSAN: annotation to skip sanitization in variable that will wrap
Message-ID: <202408150915.150AC9A3E@keescook>
References: <Zrzk8hilADAj+QTg@gmail.com>
 <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAFhGd8oowe7TwS88SU1ETJ1qvBP++MOL1iz3GrqNs+CDUhKbzg@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V+4zvyf7;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE
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

On Wed, Aug 14, 2024 at 02:05:49PM -0700, Justin Stitt wrote:
> Hi,
>=20
> On Wed, Aug 14, 2024 at 10:10=E2=80=AFAM Breno Leitao <leitao@debian.org>=
 wrote:
> >
> > Hello,
> >
> > I am seeing some signed-integer-overflow in percpu reference counters.
>=20
> it is brave of you to enable this sanitizer :>)
>=20
> >
> >         UBSAN: signed-integer-overflow in ./arch/arm64/include/asm/atom=
ic_lse.h:204:1
> >         -9223372036854775808 - 1 cannot be represented in type 's64' (a=
ka 'long long')
> >         Call trace:
> >
> >          handle_overflow
> >          __ubsan_handle_sub_overflow
> >          percpu_ref_put_many
> >          css_put
> >          cgroup_sk_free
> >          __sk_destruct
> >          __sk_free
> >          sk_free
> >          unix_release_sock
> >          unix_release
> >          sock_close
> >
> > This overflow is probably happening in percpu_ref->percpu_ref_data->cou=
nt.
> >
> > Looking at the code documentation, it seems that overflows are fine in
> > per-cpu values. The lib/percpu-refcount.c code comment says:
> >
> >  * Note that the counter on a particular cpu can (and will) wrap - this
> >  * is fine, when we go to shutdown the percpu counters will all sum to
> >  * the correct value
> >
> > Is there a way to annotate the code to tell UBSAN that this overflow is
> > expected and it shouldn't be reported?
>=20
> Great question.
>=20
> 1) There exists some new-ish macros in overflow.h that perform
> wrapping arithmetic without triggering sanitizer splats -- check out
> the wrapping_* suite of macros.
>=20
> 2) I have a Clang attribute in the works [1] that would enable you to
> annotate expressions or types that are expected to wrap and will
> therefore silence arithmetic overflow/truncation sanitizers. If you
> think this could help make the kernel better then I'd appreciate a +1
> on that PR so it can get some more review from compiler people! Kees
> and I have some other Clang features in the works that will allow for
> better mitigation strategies for intended overflow in the kernel.
>=20
> 3) Kees can probably chime in with some other methods of getting the
> sanitizer to shush -- we've been doing some work together in this
> space. Also check out [2]

I haven't checked closely yet, but I *think* top 4 patches here[1]
(proposed here[2]) fix the atomics issues. The haven't landed due to
atomics maintainers wanting differing behavior from the compiler that
Justin is still working on (the "wraps" attribute alluded to above[3]).

-Kees

[1] https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git/log/?h=
=3Ddev/v6.8-rc2/signed-overflow-sanitizer
[2] https://lore.kernel.org/linux-hardening/20240424191225.work.780-kees@ke=
rnel.org/
[3] https://github.com/llvm/llvm-project/pull/86618

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202408150915.150AC9A3E%40keescook.
