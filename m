Return-Path: <kasan-dev+bncBC447XVYUEMRBW4KWKBAMGQEXOU4NOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 628B4339D39
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 10:26:52 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id j15sf8912317lfe.2
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 01:26:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615627612; cv=pass;
        d=google.com; s=arc-20160816;
        b=pTo90Y7Vxeqc+lIoqRSOx980Ql/VMTOFl1f+AfYmEIl22lTTDrzU+JVxwjpQViUmgD
         fzVYU4LFkfHjV2HtaD46o9hrwb1jpmUa1KR9Rtn7Wmw/WssxuCmbwfIL+HzLpPvlfa+x
         AhnxGwYjwnaHqBw6cxSWPieNvJQ4a3FvEKKjoNGJLb0MyBew2SIwYVh0QfIPn7rBwOdc
         vCHvrpZLDwStYFDq0VBYofin8xH1WbwXruJdsoGXIYCIP5eHdmrSPR2/BUUp/DdKn8GB
         2TqSU9w8TMusF9cVa6NjZe7rHmbHPh8J2f6/skBwkMiPDazhDBZLQ6BDQOvXtITiw8jG
         /1EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=43nwpGIcsaRCYl2dRyd/0W+sjEAh+4rNBN3mf+ccbkw=;
        b=s80oKrDRtBOfDrrWsKR/+4u9pLRZDt47hqyfHFeXGESwY0CTi4gUnlp9L55g0alUe5
         eFQk7mQEF1BhwnQDrVECv9D+uFPYjgScCqJcdTbpl3FhaqOWHTgU8RaXmESMP7k0j7II
         qxiJs1uKQapzJ1cFXq5EnF/5omdvssmiTtenF+hbhuHkL3Sl7YyeXk1VnNhAaG2U3N2L
         MWy8fI7ghO3ib7JfHw2B7+3dTbR+JJV1As2yaLVPbWFt4GQHSy9Nt9Dir7leEr6SFecY
         R+jW+BISoFw2UyuvQtOhgFgFQsnhX34MIDiF+gXRecHWYGeBpuNs1bWu8yrp8P9mrdO/
         CrPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=43nwpGIcsaRCYl2dRyd/0W+sjEAh+4rNBN3mf+ccbkw=;
        b=fsgDtTzR7tyL+YtGBkbQveETkMYxBmUXDSGg+PN7f9LPx7z4co1NqAcTKRqpKTdLTk
         YWvgAD2vd/d2046f0FZgFwWDVsiillX6jQ+9ItBfQRXLzBP3u7PXKEc4PG4HNkdvHGf1
         xEZu6DgxVPUelWUqOlKGRB/0vbo5ZIbr0FFd9k3qtPklzwxCkj7rEerFX4z4skfIsELq
         iP3aLz1HP8onc+7g7ImCLmGktPdxf2a9PXxR/BUVqIIffQfxOe01gjK1fVyT26ZOU3s9
         0fKejq/cc5nWwscBQ7ZClElo4S67AlDsqCaBRWdXgm0EyNepy4/cazlFhNsHgBO686Dn
         RSBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=43nwpGIcsaRCYl2dRyd/0W+sjEAh+4rNBN3mf+ccbkw=;
        b=fzHhfcvUEOX50NUgkHrJUnLrjNmht3woCsrheIgdIuxpBK1ZqVYzWhikdyyoDKMweN
         IHft02fIBlLrEKdsevdzs2p9UgUcW9xmkP+3Nes5DiCdLorpK7jFbNzcbsnDWC7V4df5
         nLO7D61iyY+HZh1UxJA47tQ4kzXp0laTQYN5TXDuI458fuWL3mn4DP6b3l6oDsxCLkwL
         WKBXO8ayPLS0L7+OzaWs/vhYsH4YGoXeDyAHDZqkTk/lUxYS9Vcdafc9gtFr4pa53bU8
         8OU9jYatgfxB/ICDuJwI/e5c3uFawq9Ing/gULymjS9/kMDDAgwENlnhcvtOkNSRvpwa
         /xEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DA5yeaJ22VCK1mnrFRotQ8ow7yeIAsGJxOMYEdbGjS8jAkf2Q
	bWHFFa2b/CwEf35weqz6UCE=
X-Google-Smtp-Source: ABdhPJy2bn+4EBAjxMFoLxOgSWz1atXfSQXJexfn9LrX+Wy7XYub7+h1sD7FLJlhgiLzfglPFxBwnw==
X-Received: by 2002:ac2:5052:: with SMTP id a18mr2035221lfm.55.1615627611976;
        Sat, 13 Mar 2021 01:26:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:391a:: with SMTP id g26ls2455980lja.4.gmail; Sat, 13 Mar
 2021 01:26:51 -0800 (PST)
X-Received: by 2002:a2e:9595:: with SMTP id w21mr4929606ljh.72.1615627610999;
        Sat, 13 Mar 2021 01:26:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615627610; cv=none;
        d=google.com; s=arc-20160816;
        b=B1MSSkrVegA+t33CRgAkgRs7m2t/Jz78pEhXlUpbKqkbcUoWqgLoM086oLLHz0YhPJ
         L1Qa6v+Pqr48YLQVFFKvGKqn8ruK7biamfdEg3LRwGuGgwX8KU+Rwk3vUgsMgwaB4pjl
         uyNPd7u70CKvpU0G5/KzRZqU7lNj6iewoB6Jb7aGB40hpa84v7cwRpEIEZQX4mLoF0LG
         G4clWwU93r+cxVgdHyCq1iJ6nMBGWxEwQOMckgNEN5oEfMsGTOK83snWQySidlXGg+v7
         h05FJHcErzHa7uqTpdVJUqEnRho3/ThbqJAyB0SDCY/v7vSf0lHNJWwQkP5QpneJYEdq
         XRhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=qqlTGHUosnIjdHU1tHTgi9L71ROrKWCZOiIP5ugXxns=;
        b=SL3++r5dCGy4+Nbv71cJNjitFH2+oLMyYcKae5BgxhNZ5jgmngsye0E2a6tSele/lb
         4FREo7+79dhgzYkWJJop1HYdfzXKwzjCE6RourHxYbxkbc3umFA6elLoDwApMiI8+TIY
         UKhnNbnj6X7E1PtCr5MPcFqBvMpSO8Ty4iI+WpMPnFk2Itj2/UL68078lPNWsncZwrHU
         FcrXTdPv56w4eKo4EX7yua2UQF7SCax08Nr4LcmQZx2+Gh14nDnYLJYZtQ0EKXGGmahd
         nI/5NY8VJ4tZCyG9dRJD2kuavtLOsuHJ0O0K/r06ll1yaOkr2VzZizHd7BvcJ8BKWbf7
         Ddog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [217.70.183.197])
        by gmr-mx.google.com with ESMTPS id i30si337779lfj.6.2021.03.13.01.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 01:26:50 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.197;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.100] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay5-d.mail.gandi.net (Postfix) with ESMTPSA id 8C6861C0008;
	Sat, 13 Mar 2021 09:26:47 +0000 (UTC)
Subject: Re: [PATCH 0/3] Move kernel mapping outside the linear mapping
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
 aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <mhng-cf5d29ec-e941-4579-8c42-2c11799a8f2f@penguin>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <0bb85388-c4e1-523a-9bf3-0ccec6c4041e@ghiti.fr>
Date: Sat, 13 Mar 2021 04:26:47 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-cf5d29ec-e941-4579-8c42-2c11799a8f2f@penguin>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.197 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Palmer,

Le 3/9/21 =C3=A0 9:54 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Thu, 25 Feb 2021 00:04:50 PST (-0800), alex@ghiti.fr wrote:
>> I decided to split sv48 support in small series to ease the review.
>>
>> This patchset pushes the kernel mapping (modules and BPF too) to the las=
t
>> 4GB of the 64bit address space, this allows to:
>> - implement relocatable kernel (that will come later in another
>> =C2=A0 patchset) that requires to move the kernel mapping out of the lin=
ear
>> =C2=A0 mapping to avoid to copy the kernel at a different physical addre=
ss.
>> - have a single kernel that is not relocatable (and then that avoids the
>> =C2=A0 performance penalty imposed by PIC kernel) for both sv39 and sv48=
.
>>
>> The first patch implements this behaviour, the second patch introduces a
>> documentation that describes the virtual address space layout of the=20
>> 64bit
>> kernel and the last patch is taken from my sv48 series where I simply=20
>> added
>> the dump of the modules/kernel/BPF mapping.
>>
>> I removed the Reviewed-by on the first patch since it changed enough fro=
m
>> last time and deserves a second look.
>>
>> Alexandre Ghiti (3):
>> =C2=A0 riscv: Move kernel mapping outside of linear mapping
>> =C2=A0 Documentation: riscv: Add documentation that describes the VM lay=
out
>> =C2=A0 riscv: Prepare ptdump for vm layout dynamic addresses
>>
>> =C2=A0Documentation/riscv/index.rst=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
|=C2=A0 1 +
>> =C2=A0Documentation/riscv/vm-layout.rst=C2=A0=C2=A0 | 61 +++++++++++++++=
+++++++
>> =C2=A0arch/riscv/boot/loader.lds.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 3 +-
>> =C2=A0arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
| 18 ++++++-
>> =C2=A0arch/riscv/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0 | 37 +++++++++-=
---
>> =C2=A0arch/riscv/include/asm/set_memory.h |=C2=A0 1 +
>> =C2=A0arch/riscv/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 +-
>> =C2=A0arch/riscv/kernel/module.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 6 +--
>> =C2=A0arch/riscv/kernel/setup.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 ++
>> =C2=A0arch/riscv/kernel/vmlinux.lds.S=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 =
+-
>> =C2=A0arch/riscv/mm/fault.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 13 +++++
>> =C2=A0arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 81 +++++++++++++++++++++++-=
-----
>> =C2=A0arch/riscv/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 9 ++++
>> =C2=A0arch/riscv/mm/physaddr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 2 +-
>> =C2=A0arch/riscv/mm/ptdump.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 67 +++++++++++++++++++-----
>> =C2=A015 files changed, 258 insertions(+), 50 deletions(-)
>> =C2=A0create mode 100644 Documentation/riscv/vm-layout.rst
>=20
> This generally looks good, but I'm getting a bunch of checkpatch=20
> warnings and some conflicts, do you mind fixing those up (and including=
=20
> your other kasan patch, as that's likely to conflict)?


I fixed a few checkpatch warnings and rebased on top of for-next but had=20
not conflicts.

I have just sent the v2.

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0bb85388-c4e1-523a-9bf3-0ccec6c4041e%40ghiti.fr.
