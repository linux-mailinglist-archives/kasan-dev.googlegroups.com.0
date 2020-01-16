Return-Path: <kasan-dev+bncBCMIZB7QWENRBZGEQDYQKGQEDX2FAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D08213D611
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:44:21 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id n9sf15601162ilm.19
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:44:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579164260; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMAro38bOMdwb+zLinjIPdwfT5SkSx1DiKchboN9Zc6bfp5oMPBE8truF72bzDZ3u0
         LwPnLJT/sD6ChdqQjk2xQIQUq8+epvtQeM0I5XwrHMa+We7PFC8zKnbEqjAZ+yxC2dIl
         +4+kkPmu4FsRjrTFu1Uu2TFyVHOd3qj6JT6rqvD9fjC40fb+5pUQYuCmx6I+d0ihYvib
         Ql846awTgcGKsPolayI6NJc8vouvvsYJcnqfTK0GO6A44V7b6zwzdxddpFe1so7sJ7w3
         291l3NnIxfM8DJXjSHClLSpr65UP0C72tNPS15fTDP7t7XU6yqSGqgRSsnyNA2RrVDxE
         2JzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lqsqDnCM/xsfSQZWTnNYumlJrc+vYM08DkkxFI7UgOI=;
        b=g2M5NLqJWoGscX4HkmLcbfguoup0HxbgxEoN9lndBcS5CdHq4fIa1SdohuDz0pA2Ax
         gHUYZJWWxZaVX8DwLYjLkpGg6N/Dh6/kFITgWWp2oGN8B5l1/H63SVJWYLtTRzp0x+Bf
         H/C3FkBRSg+h3qGDiaTWRJkvojnjJtFSOAtF8uwaDdQ7GAKUOM/+a/8bUwr0piPhTn55
         z6dpKJghhqYZ8MjV5ADypagNK4DgmuGIsXH/XiFj8F5RdRIIfyUFauTHXXG3BBOChkfU
         5Z4n7ELQo8kAnmypYHX0XkwvB5nSyRpaRcJsxdAKr89NrzRH3QSPDx5eXkjqIUGpMC1m
         7grQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G12enqTe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqsqDnCM/xsfSQZWTnNYumlJrc+vYM08DkkxFI7UgOI=;
        b=StLRP+hQEIXdq7uNCG8fTxZBB/efSP/AIr/epFSWX6vyQweprJHuu1eYN1BQ9HZpR8
         VJS4RT7Twmb7qThs79mF0Xp0mYMobKoewSZZ2czrS4XEag038Zoe6j3iwWDwDZjSWP4Q
         2ixXTBtf6AL0Bx0tz2KuAe/TLIHDHlvDK0xfI/htQKCA2DKg3Jt8dkZE8ZptQvofd4yb
         uukt3+9VXP4OgI5VU/VDrQVMCLqC8+sSRLET67yI54UmVV/dh+NowwoSag+5fqOweZCD
         3al1UtqqLjTNEuokiu3ifexgKBWqM7PB4xMjBadYGVHHAOdh+kRUDfvVntGY9uu92FNT
         9gCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqsqDnCM/xsfSQZWTnNYumlJrc+vYM08DkkxFI7UgOI=;
        b=NDJ7+XH/6FmcQgt0TLzy9gKHG9UMRdE6L0tPHkm4TS9s5ETw9JofT0/wzeU8U3i4Zr
         +xJulvhclY7LIfrgRvA6eM0wyNXR66OikVPpmrmAZgctkTDEblxGyZtekR2+iQuFKq22
         YE9St62icYlppysjPfVbB3xJSdps+xbbJ3qxuAoUO5+b5hGnb9QKfIq0wSsMzGHuRbIh
         iFC3FZay6Kj43mEUqY9K8QUJYTfstfRWu2lSd1OlULDVmcWolmHZulsuUkBPMd8i81mN
         0Aw1DR1G/QRJIzeYkCFNSvaJrqptVNi4nPEsDYhA7A/BNYBs9Syq8F2bwosnaGel2U/M
         0ykA==
X-Gm-Message-State: APjAAAUHW/l7qIEKKDtvW+tZDiQ6IUFCgE/H2G/V2Dcw2DititkDWFAz
	jHeuxXX9HQW2+Nl7Um8OzL4=
X-Google-Smtp-Source: APXvYqzXdaMskKe4L0GPDfdRCmgwVXC9ycqKEjjr7swF/3h7vWSEcTh8dBAD8BohnNEwgLdRX+tIRw==
X-Received: by 2002:a5e:9814:: with SMTP id s20mr23298915ioj.96.1579164260258;
        Thu, 16 Jan 2020 00:44:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:93d3:: with SMTP id j19ls2226306ioo.16.gmail; Thu, 16
 Jan 2020 00:44:19 -0800 (PST)
X-Received: by 2002:a5e:9246:: with SMTP id z6mr26673160iop.232.1579164259881;
        Thu, 16 Jan 2020 00:44:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579164259; cv=none;
        d=google.com; s=arc-20160816;
        b=A1zHkuOgfzxoBjHcC0OpAha2H27EXzou9/UL8OOH6zX0gP/1bMMrNl6lXKV5uLTRWt
         V4eza4N16bSTP4WsLaGn6PmcJXEaJG+Cm1OB+MoPWVTpNCDe14k7s/ktOC9ou/tZLi7B
         hpqpSsTqaH27rw0Ok3il8w36oswtizez9q+UZCnP12B1uuF5bcHTIKN+QFqQCyqTW2KR
         nFaZ1eBPucqPTpGjWgm7EPzwCbhUUY+G35KlZqJSnvRREHRXBIz2RyNrA5To2CwJgXYI
         g76PcTr30rgp1pkQfUDbpWiH52QFpzt4Sv10zROqFKlMwjybq4ldUumNGFrYmU2F9azZ
         pZOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gJg5ZRxNcTyn3n/fup2Ib0eaCQR42k4DrKQJxK1gJxw=;
        b=orf5cGCiJCHi0Ri+Tf9AXT8MVYJdFMiqQDliSbboXXL93uXZEIrumLWENa/2Jq1s2H
         0ZTVZgY8U82XagNTXPztA0p/tjzZGPX2iirWOnKz9J8Mkg0YbjuN+x5nXt0gGqJDdrxt
         TpP8JDFhLgEZzoCVYWqrHyXK5XqfOhVw4dn12BHI2iQai/wqgJ4WGjQF6jG+AvX45sno
         QQY5nnpCuJx6hWOSDgWrr8VU/0S69IGwuB3lM4jfjJvBoTA0xCj/xiOjF8Ur10Bhu5N9
         rHbli7ECmZ79hDaLJd6kmw5swwhJIZsYqzT0Vxix+OT2zaiQ7Y58lFW0WEI5PSPn3RB1
         +1kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G12enqTe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id z7si1120554ilz.1.2020.01.16.00.44.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:44:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id j9so18423027qkk.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:44:19 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr32326765qki.250.1579164259120;
 Thu, 16 Jan 2020 00:44:19 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
In-Reply-To: <20200115182816.33892-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:44:08 +0100
Message-ID: <CACT4Y+bPzRbWw-dPQkLVENPKy_DBdjrbSce0f6XE3=W7RhfhBA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G12enqTe;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Jan 15, 2020 at 7:28 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x100000000000
> +       help
> +         This is the offset at which the ~2.25TB of shadow memory is
> +         initialized and used by KASAN for memory debugging. The default
> +         is 0x100000000000.

What are restrictions on this value?
In user-space we use 0x7fff8000 as a base (just below 2GB) and it's
extremely profitable wrt codegen since it fits into immediate of most
instructions.
We can load and add the base with a short instruction:
    2d8c: 48 81 c2 00 80 ff 7f    add    $0x7fff8000,%rdx
Or even add base, load shadow and check it with a single 7-byte instruction:
     1e4: 80 b8 00 80 ff 7f 00    cmpb   $0x0,0x7fff8000(%rax)

While with the large base, it takes 10 bytes just to load the const
into a register (current x86 KASAN codegen):
ffffffff81001571: 48 b8 00 00 00 00 00 fc ff df    movabs
$0xdffffc0000000000,%rax
Most instructions don't have 8-byte immediates, so then we separately
need to add/load/check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbPzRbWw-dPQkLVENPKy_DBdjrbSce0f6XE3%3DW7RhfhBA%40mail.gmail.com.
