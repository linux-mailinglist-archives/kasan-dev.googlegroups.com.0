Return-Path: <kasan-dev+bncBDEZDPVRZMARBO52RTDAMGQELCRQP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 32BCFB53C14
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 21:04:29 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-75e974f3f7dsf31038106d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 12:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757617468; cv=pass;
        d=google.com; s=arc-20240605;
        b=dMfOBN+/x0fk1fhFDPZpZVnfnvRqdbs4mX5yUxmV75pZF6M5hMIfAjjtYQedCKqXaC
         gUXo7xtAH+9+ZSv6ZhogGMf30O+nJrfJRzlxodwwUTpmS3LAWSkVevJWRPtVyoSMwAZm
         tmwwO+zd9/SWpvJc7DPAxfILsiOhY7Cc98F3UoL3Q97nc5z8YnbFSQkwkATucK8Hu71x
         Pg4vCzLI7nCue/ovErvR3XaFbMKJciDrghxAO8eJClqciC4VQ3ZgU3BN8tVHNArBw/25
         g8UfU/qKteEe9A+zyKV/KfLKrTrCAsk/oChb96eIMonimwagXQ39XHMddRBIbsFKmssT
         Wh7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UbMafyCqrEdCfPM6QMowMEELF1aU53MnLh0H1gEvzcs=;
        fh=aCa3iNVeK/Y7fB1R8guo85b+KmwMPDMXyFrnoh0LSX4=;
        b=UjqzkOXwf5GaYTvBytGKokWGBboqJucI8dcVkF2EiyaVD0xS546vOibszcZ5udYpSs
         JMFjEMSQcZBaVufGbdlWXPSCZzz4qCsKXkTp8TYWcQiojXtZiOke53PuSzTN0Bz9OX+O
         NipzEdMw8OqqryLSvkxX6jwtnn03QpbICkM27HlV5yzdE3YVOmaAzGs95yU2x3HSzmRw
         2XgxIqn0mWVR9fIUWkiGT5H2r6xNVnKx7mhyB5mFKZlwZPD8PwrQ9VVkBPuskL6eWLpq
         V6X7FGUOtVulMQT8Vq46+6QlBo3o4isIU2bH2MF3fnFXCPvWo/HC+EorHda61DYclB6B
         xIEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NgJmdhFv;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757617468; x=1758222268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=UbMafyCqrEdCfPM6QMowMEELF1aU53MnLh0H1gEvzcs=;
        b=FUU7tgS5o6x1iLFNCgOP9FYmhMSCbX2DXbeV3Anip0UzInWTO78EO4BUjX7HAafe/m
         WBn8hrYp4OA9hYdl/DyeJYejy74bjjDOUhcf23TUcJfWngiITSGgO9bIIJ/sRiv+Ty4u
         6DIaEEKFY+Zxm8OBMd5aiCl+7tRSrr7LA402IQ+579Tkja1dM65rXmmL0sYBARWmuXEt
         9sSQSu7QsrcWmlA8yLOM2sjEeKfGe4Y2PeHMr9VREtFrT/TjIGqgHPqZ8SAVyGPbQGO1
         F7m/+8RulFRm9et0E8SddH9RxXC0k3As3RnM8JCo2H/O/da5XrQcY6F/tn1PEdSyp7HX
         S9hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757617468; x=1758222268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UbMafyCqrEdCfPM6QMowMEELF1aU53MnLh0H1gEvzcs=;
        b=u0e+fTG3DYz7xJo8AQA+XTIkXw+Mc7Og/DBEHt7dA1Z1lnJdJNeRREYcGQP5iF8QVW
         iUi7CjF7MXDAkQ8NGL+Gu9vbE47pABU+LGbgOSOcjAw+oG9hx7lCWoKWPgcMj52lIeCh
         pBaaNvuAoTUUmanS58Pv/ZgCcSJNNSs8z8aKRwaJrBXKJtslS/4A7I7DrFxdc+/Vi4XT
         sFoP7qMK2/YBwqI8RpVcl+AS5+YsmkQBw3FaD4Unis4hZWZjwIOhqjAUyBBnkJuBHFHN
         dAKmfi9Xbc5XpsNs0b2iu++PiEOOCBMK5NSC+gzK5jeW7lvpwsDis1QGZkrf7sZZRYbM
         nBaw==
X-Forwarded-Encrypted: i=2; AJvYcCVGNuICXEGWIaubcP95btIP0ZS+4pJBFdJAndMiLikQ8yhDMUMOSCrCzauDCng/A7tcdeIuRA==@lfdr.de
X-Gm-Message-State: AOJu0YwqTDH7nFlmfInVjUL6rQZFod2FzQrNKFqXGvt59XDEYxS53EtB
	9eS+LZuzdoiEKqP93EimBAEMrNNjvccGOZXnTH4TTV3auLkfX7fhudbk
X-Google-Smtp-Source: AGHT+IEae1Zy8udbke23GzdRiCabRikFg8YVpWj1euEjXmo5mjBUfJhb3w+3Ne6jEqwQpQJR3UFdnw==
X-Received: by 2002:a05:6214:19c6:b0:722:1db2:f8df with SMTP id 6a1803df08f44-767c5436ffcmr7370806d6.67.1757617467891;
        Thu, 11 Sep 2025 12:04:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7mM5OCuCFswAGu7B/+S9fkShO3cPxVAmxnTjfNa5LRvw==
Received: by 2002:a05:6214:262c:b0:70f:abbb:a05c with SMTP id
 6a1803df08f44-762e43d7a92ls23935266d6.1.-pod-prod-04-us; Thu, 11 Sep 2025
 12:04:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXNcj7S266VDMmHoEmN2tZIk57lOoivFzrsolRJvblVaSgZNgIi0pEis9wgGjeEulmpHly7lupRVU=@googlegroups.com
X-Received: by 2002:a05:620a:1a12:b0:811:936a:d0b5 with SMTP id af79cd13be357-824001882f2mr71668185a.65.1757617465624;
        Thu, 11 Sep 2025 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757617465; cv=none;
        d=google.com; s=arc-20240605;
        b=OhXtwK0nP07X59Av0lPgD+sh34x9rIZVShtT+R5uCnsjjVvHnFM+9EbY6b/w/XmRTt
         LnM9dB6SB42C2aR8r5igf5nwoOYIzMPrnhQKqXuUKban8Dx8xWxsJ17qrJoJ6CVE0wAr
         TMYTvcouL/9/tJMau/yE5Puvck1EBiYeqjBtTlfclobRhRqhCn2ZGt1OFvMQ7rvagqp+
         fAhf4VFrrNZA9ThGnf1pOdA7FUEIxXTAgnxPRYOKdE8iip0xzwgZIPWwcmVn7MIPRmjS
         xGB0v8nqZiCOHU8m6IsO2GGNykB7Bqv7tBVfBsHB0wJ5uoFGkLbz3Hlw2q7PStaAzR0y
         QUYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KS/GQZvKohxF2dXOoetjc+Srv9VGnubroIDx6lMqSUI=;
        fh=KHT2kymW7tjxt6FznQi1j79NKfOkVh21sCLzL2GzzK0=;
        b=L7aYs2pBIdyPAOOhNs4LoiqrZkPgXUVFrUrWpXQdZH3WoOeyR6fLBBD+KVT+QTRbyO
         z+Sk69dVDL7oh8AdVnksAg+Sd20Z2QloDeyjOry6E4WIgk/1t/G55iZCZa7r4GXG8LGN
         xDcsrKE2NoCNWQj9M+6umS6dsrAl14t1IXxD37ZmN7zW15qs9wZ09gRYeHyDT9KguKIa
         7SmJrtyt5JXrEJNUxmDoCd4FL9LKeZlTvTmgjv/kPCa01lpRDc1tglZHxqNz/XeGewr3
         nVs6srPXLG2B4QE4IuTnZvvOSNOmzu0mkbu83C8kPe08SOXLkhLhnzfS1iPZcyLkNW30
         U6kg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NgJmdhFv;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820c303eaf1si8852085a.0.2025.09.11.12.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 12:04:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B91394177A;
	Thu, 11 Sep 2025 19:04:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5C146C4CEF0;
	Thu, 11 Sep 2025 19:04:23 +0000 (UTC)
Date: Thu, 11 Sep 2025 12:03:02 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-crypto@vger.kernel.org,
	stable@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
Message-ID: <20250911190302.GF1376@sol>
References: <20250829164500.324329-1-ebiggers@kernel.org>
 <20250910194921.GA3153735@google.com>
 <CAG_fn=W_7o6ANs94GwoYjyjvY5kSFYHB6DwfE+oXM7TP1eP5dw@mail.gmail.com>
 <20250911175145.GA1376@sol>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250911175145.GA1376@sol>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NgJmdhFv;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Thu, Sep 11, 2025 at 10:51:45AM -0700, Eric Biggers wrote:
> On Thu, Sep 11, 2025 at 11:09:17AM +0200, Alexander Potapenko wrote:
> > On Wed, Sep 10, 2025 at 9:49=E2=80=AFPM Eric Biggers <ebiggers@kernel.o=
rg> wrote:
> > >
> > > On Fri, Aug 29, 2025 at 09:45:00AM -0700, Eric Biggers wrote:
> > > > Running sha224_kunit on a KMSAN-enabled kernel results in a crash i=
n
> > > > kmsan_internal_set_shadow_origin():
> > > >
> > > >     BUG: unable to handle page fault for address: ffffbc3840291000
> > > >     #PF: supervisor read access in kernel mode
> > > >     #PF: error_code(0x0000) - not-present page
> > > >     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
> > > >     Oops: 0000 [#1] SMP NOPTI
> > > >     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G         =
        N  6.17.0-rc3 #10 PREEMPT(voluntary)
> > > >     Tainted: [N]=3DTEST
> > > >     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel=
-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
> > > >     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
> > > >     [...]
> > > >     Call Trace:
> > > >     <TASK>
> > > >     __msan_memset+0xee/0x1a0
> > > >     sha224_final+0x9e/0x350
> > > >     test_hash_buffer_overruns+0x46f/0x5f0
> > > >     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
> > > >     ? __pfx_test_hash_buffer_overruns+0x10/0x10
> > > >     kunit_try_run_case+0x198/0xa00
> > >
> > > Any thoughts on this patch from the KMSAN folks?  I'd love to add
> > > CONFIG_KMSAN=3Dy to my crypto subsystem testing, but unfortunately th=
e
> > > kernel crashes due to this bug :-(
> > >
> > > - Eric
> >=20
> > Sorry, I was out in August and missed this email when digging through m=
y inbox.
> >=20
> > Curiously, I couldn't find any relevant crashes on the KMSAN syzbot
> > instance, but the issue is legit.
> > Thank you so much for fixing this!
> >=20
> > Any chance you can add a test case for it to mm/kmsan/kmsan_test.c?
>=20
> Unfortunately most of the KMSAN test cases already fail on upstream,
> which makes it difficult to develop new ones:

The KMSAN test failures bisect to the following commit:

    commit f90b474a35744b5d43009e4fab232e74a3024cae
    Author: Vlastimil Babka <vbabka@suse.cz>
    Date:   Mon Mar 10 13:40:17 2025 +0100

        mm: Fix the flipped condition in gfpflags_allow_spinning()

I'm not sure why.  Apparently something related to lib/stackdepot.c.

Reverting that commit on top of upstream fixes the KMSAN tests.

- Eric

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250911190302.GF1376%40sol.
