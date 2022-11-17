Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXHW3CNQMGQE7D4KH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B41262DD19
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 14:47:10 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id l13-20020a17090a4d4d00b002187d994e82sf13975pjh.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 05:47:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668692828; cv=pass;
        d=google.com; s=arc-20160816;
        b=dslb88B96cym31LMAAvRCrz+cpUhALdkhSlkqZfM5QqfO5ujJGzN53QQdn/CraLRg2
         iNrWyfdbtN0yKWMw9Tgj3T8wVmJFHeZevC7rxPJEqMFGRbFXBXVOTJ4fpi+qRfBqBc3H
         29Hj20RH21IsdrB6HUchJtpB935dzk37GDUEE47OGUJHbbGJYd7U4AP+yL6dQZagegDC
         /MXCEGZqz1HvRoq+rF2VAaBvHT++g4iL0Fx2GvMoJkzyeyA1S4mtr7QagydsH4/TVHMA
         VVjm1F5L35FywQ5TWtm3yrk44Y/04M+geKuU3Q7ADMqtwfZrFuQ/qNuUv3zFTKFj3WrX
         smyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=56Fx5RDW6p6Grbv9xfM8UmV4ZMzNBMvRv1jVCgRID+Q=;
        b=AlTicwdgDjYr6OGPyC8D+C3GCjH9KNBXztvxmsw24j49J2dmBoNoELR32v/C+Syy9y
         oY6KxwgwbLOpvhsqRrBIbufVEr6YhGBQk7ODh3HRWHckezEHFGZRUH2wMkslJcC7/GKJ
         T6yMZ6vcAwz7BJFhzuO2sbljNBGaSF7liFYvvkHkVjlnmrQ5T2rH1+P+rS0FPwhi0lyI
         tuc5w7j0pGlog31M74sVhLRTKke7vCqZiwQasE1+pxM6d3vKeCrKl0uFz4vXeudqwavE
         QkbO7JMbRR2au4FsnAeIiKFFQ5908ufYDZsHfRDKee7B875/4MfAhniyQzVPLR6dgXlY
         hT0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="c8vO+LU/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=56Fx5RDW6p6Grbv9xfM8UmV4ZMzNBMvRv1jVCgRID+Q=;
        b=tyPJsIlQpUaQLW0/7PVacJvaFDllMj7qOuZKLxFaHMMd2vl+eIdo/GNn3QuBs86I9R
         UtR/CLbUVbEilH5k5ME0edm5XXsSi0kQgJD6/2/d4x62o95u2uInYt0O+4Lemmp7tV+1
         B3P6hv34hzt8TohROskiUG2w7KYni34HDhImfqTfikrM2adVDrLVPni3L/X/25fXxyey
         V21HKecqsV6+VT2Frb80a/zrq50uIlTZalbRTPDLw6r+kiLcqvsbBj4qCSp3H6a6J5px
         YPcXBb0Ja/943AAI4012td+rsRkITuXcEfQQW0016ok8ZIzAojcDCX8imnN0gkCDJa0Z
         PkZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=56Fx5RDW6p6Grbv9xfM8UmV4ZMzNBMvRv1jVCgRID+Q=;
        b=b1dzCmZ9G4+nyD3pgrNQq32oQn90O6jbdLbRSTFHyrG2UC6O/qdhLNQv6T0TobAqMr
         YlV4EZxiqbad0V5hV0sTCTFgyngXsBFgcK1QztUhHXuJyyMbBuQXA3xHnJ+y2+7wGPeT
         14gLq7JbKIrwgJDdXhFZyNG5+xN1W9AT9hOFpw824XRXTlemiMI0o88rDprthbzFl6Z3
         VihajVn/4X0i/yKAAe74U8yIPV56/giawNOmx5I0H6+zjSBCNVhXOV/HmaXhlYQ9hW/E
         arJGDV5dWShbVDCkLf0ScFjLhDCI995k4rTLE/zfl36NSoVBAsyUhRVS4a+DHWfqVFkV
         gqXA==
X-Gm-Message-State: ANoB5plb8WRUV0sM1KrzHX+6QWD2c81rrv4T5ceinlDcaaELtBa55DD0
	ZHqwCQzvJRE/zJ+ULKm1In4=
X-Google-Smtp-Source: AA0mqf7w0XkJp1BP1BnoSsIMf72yF4LwGKrwJ4jIvwRUWEBD+1b3wUiXBBv7psI9D5EHaNWr/POebA==
X-Received: by 2002:a63:d712:0:b0:470:4522:f317 with SMTP id d18-20020a63d712000000b004704522f317mr2126980pgg.129.1668692828547;
        Thu, 17 Nov 2022 05:47:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1c6:0:b0:43c:2618:9c3f with SMTP id 189-20020a6301c6000000b0043c26189c3fls1144176pgb.9.-pod-prod-gmail;
 Thu, 17 Nov 2022 05:47:07 -0800 (PST)
X-Received: by 2002:a63:1025:0:b0:476:8f1c:d095 with SMTP id f37-20020a631025000000b004768f1cd095mr2114393pgl.412.1668692827829;
        Thu, 17 Nov 2022 05:47:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668692827; cv=none;
        d=google.com; s=arc-20160816;
        b=uzqb6yunmdqp7Ntx/t7XiTE0X3hU782Mzp3vyNjtiQRG85Dfwlg+zmswL0xjkHLVh8
         LrPym19oIF/Q0wYRVLyLyG76GpchjTIAmk+DzcW/1M9sF5WGm66QKhXTifBXRBU419lv
         jHIZyF+XILPWvZ0AKF4SeFn4ZWiuoiIn4W/GV6+NdFUuxGhXtVFnY9D9eFqelwkLCMXM
         JPDeLMacC+UNRXBujEURLOkth/3FUOvliSZUp9Ow/M3w4CubD0Hb/tObGz/lIFvz30xd
         07ND2cJz1kwjMGJePcm+CQc6NV/j3DrxP54Y/QNqw5yAVEL2eNj/fRkCY+edRVP8J6av
         +p3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NBgn5FfavxoeQ10DPy6H31rWSKaucrVJq2p8zFcWxKg=;
        b=kdzPAejAdWmkESDGZQeSvTu7thvA1P9OGT7/IrLNDwakn00attFJvTGTFrA0JyxljU
         um43hID3p+W5hebwVfm4zjSu0Mkj05fX3l06k5Jjv2OvbbFU9ubps36UDutCwG6JjdNL
         UjF8rNRRi/UdV7UPgEV7Q1sIlWkFJPABpxk08QAyj5NaraLzm2nwRLmcP8n2Mi7gIYiu
         MqBi6SlXFHN4/NdX1HMJbpZTl0yIbAiiAqXyrZktl0nAjXv3CQp6clHn6hGA86YVHT5p
         uO2aQfOf4HLE5Ck2v6BBVg0Z9kESdXWfnyDF4wvdA/eL7yr2kM9OatFAUYI/rXRgZqLZ
         4OhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="c8vO+LU/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id o11-20020a170902d4cb00b00186b3b9870fsi70256plg.11.2022.11.17.05.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 05:47:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 63so1914756ybq.4
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 05:47:07 -0800 (PST)
X-Received: by 2002:a25:8390:0:b0:6de:5b33:4a29 with SMTP id
 t16-20020a258390000000b006de5b334a29mr2076908ybk.485.1668692825505; Thu, 17
 Nov 2022 05:47:05 -0800 (PST)
MIME-Version: 1.0
References: <Y3VEL0P0M3uSCxdk@sol.localdomain>
In-Reply-To: <Y3VEL0P0M3uSCxdk@sol.localdomain>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Nov 2022 14:46:29 +0100
Message-ID: <CAG_fn=XwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA@mail.gmail.com>
Subject: Re: KMSAN broken with lockdep again?
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="c8vO+LU/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 16, 2022 at 9:12 PM Eric Biggers <ebiggers@kernel.org> wrote:
>
> Hi,
>
> I'm trying v6.1-rc5 with CONFIG_KMSAN, but the kernel continuously spams
> "BUG: KMSAN: uninit-value in __init_waitqueue_head".
>
> I tracked it down to lockdep (CONFIG_PROVE_LOCKING=3Dy).  The problem goe=
s away if
> I disable that.
>
> I don't see any obvious use of uninitialized memory in __init_waitqueue_h=
ead().
>
> The compiler I'm using is tip-of-tree clang (LLVM commit 4155be339ba80fef=
).
>
> Is this a known issue?
>
> - Eric

Thanks for flagging this!

The reason behind that is that under lockdep we're accessing the
contents of wq_head->lock->dep_map, which KMSAN considers
uninitialized.
The initialization of dep_map happens inside kernel/locking/lockdep.c,
for which KMSAN is deliberately disabled, because lockep used to
deadlock in the past.

As far as I can tell, removing `KMSAN_SANITIZE_lockdep.o :=3D n` does
not actually break anything now (although the kernel becomes quite
slow with both lockdep and KMSAN). Let me experiment a bit and send a
patch.
If this won't work out, we'll need an explicit call to
kmsan_unpoison_memory() somewhere in lockdep_init_map_type() to
suppress these reports.


--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA%40mail.gmai=
l.com.
