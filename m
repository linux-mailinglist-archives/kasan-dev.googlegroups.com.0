Return-Path: <kasan-dev+bncBC447XVYUEMRBVPN22BAMGQEL4XSXXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DE33342B56
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 09:48:22 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id w18sf21372614edu.5
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Mar 2021 01:48:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616230101; cv=pass;
        d=google.com; s=arc-20160816;
        b=A8xWmUc6QsjFL1Go6+QNwFXc/G8f7FonqOJ30AKiz2866spNc/nhr3HU4z3zDXwSVL
         ek8HkcsAMdiDPP5ISpJEWP7aniu6mHDkqj6Jll9r/4vtRBBcI0YpVF7s7z/wLvwIG8iF
         9rcsgCioPNh8p72H6Oc/fXIOybd8ljAJTlJF0njNNzNxfZqHSC2oC9qX8KO7PqHjskhR
         aWdSxoMm6t/kwvEE7FkpHkNNU7tsBPgKbo3BeEITBgBTPNSZKuZa3DafxlbZePaWE+Fd
         uusKe/f9rnIq3RcKLR4lQbXTYwWSK+49yanyE6PxJILuJU+0ObSGirzUjZ0maT/UCf3O
         4eYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=B8ZrWcNekaDFKHEfRfZC/xDxtxWC7ESARJnwdsVPHmA=;
        b=BZ6KGQyjw4ZDNE9r3GzW1xhNagg8oU94+ZLjbqudQDWap7yipoi3n6RLFfcaU/CT/0
         8KtzdeF6EEN33WFzumxPnJDIb2Xxd2+Hj4g5mBvxyrAOeorxqVqC6AX/NHFyi6dBtK2L
         152Ii4jNKXAHqZk3uQZhIpNlk6ikzu+y0s2q4byxR+ZlE9FAex5rsbGxXCjUSKqAPyUO
         9cB2E4Z9rJX27R8+2yfLFnVHTaJFEZNH2lHiKYsSM9ZT4MUuFzMGGxsfEl4IWhCUrbNN
         Ne7/16rrrxnFV9HVRGiVBBc5ghn02DnWstUp8vHJvS9UYyLW+WPaEx4s90jqASPiGdBy
         ZSnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B8ZrWcNekaDFKHEfRfZC/xDxtxWC7ESARJnwdsVPHmA=;
        b=gRejmP1NCwucmgeH7jehHId7luolFg9cBY5uKDwktiYCCA1d9eNZpCUOfBwLSS3xaA
         BKo7ZYFxSRosGjrvVhvpOZglljzv8TSAhbA7rva/RYshPS1kpHkagVmbjhinYrrOh4SA
         kcM+ZZSmahON+qaVK2SL+dNOwSRjG2tZrecpeaEWEY+vYZf/XQLYtBfWBeuc7/wqN2FH
         DPhDrIsXJ3dAYYX1U1xL4uBN6j6VfrJuve29rvRkKjq8vGJpWOzopNigGV2mFUnUhQZb
         5uf2LkERXqVGVFxCRFJ+QBStEtX2/UAFohLybbS3g0WP23KNRbKiP60S2MHkJbw2GBbN
         XMJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B8ZrWcNekaDFKHEfRfZC/xDxtxWC7ESARJnwdsVPHmA=;
        b=g0FKOyOYoMPQxomoTZpTGJwdUz0LQKUoz4o2QkdwhTjd/8c6FJrVR/ZHv37pbduxcL
         8i65y2GeTUNWDmL1S78C2zdYRX6yaR3fSq/bfU8lN5JaSyDRLFBAG99oSz/EOBAtzGDX
         zEP2kSXGXv1SU7DGA9ZveRIpNeP2GXcE1KATtklv7kqtU7r3zkyRuxbOHiz08g/0Z+1k
         00dlqHW0Z92v3b6aWK7Vw34BciufED7sz37o7HOp9qJI0YfcPZlYk5DGuogxXr+Q/Fi9
         tS5J8YAx0WLC7+rEEMg9MpXGIYWVcusd6bVdQ2QKSNReH6UpstB5Nry1Jl8lbOICAUdq
         I98Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l3H5hVF9kD6qQefC1ytWR6JIxLhYckyXl4UKl1SVmJFESHq/Y
	WkDRfIqCsnQDpK3LfqAEfnY=
X-Google-Smtp-Source: ABdhPJxg+tAq2wSYGayPtkxsON4v8XIcofp/tHlUYFAjLR2ALspM+6VLVQgRwVeY+TZZuTSCmGq/6g==
X-Received: by 2002:a17:906:1f93:: with SMTP id t19mr8930383ejr.443.1616230101712;
        Sat, 20 Mar 2021 01:48:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls8325157edr.2.gmail; Sat, 20 Mar
 2021 01:48:20 -0700 (PDT)
X-Received: by 2002:a05:6402:b41:: with SMTP id bx1mr14539115edb.69.1616230100903;
        Sat, 20 Mar 2021 01:48:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616230100; cv=none;
        d=google.com; s=arc-20160816;
        b=EYX6lw+8YDR76kogI+Bi82LT9obVcXsvG81Gl9jjgsIjTteicr5KCl6ctd62V5PbB6
         E/SeOllNwmVKNOHb5FfVM2XQWsFQeSi+Vyq1DC8A52AJeKTiXtdllBiPFPIop0/cQ/Zg
         xj0YIZqAhzaP9VsCn68voHklwjQthVJ7rynXY85zU0BjhwBAV9tSOZZrAoxdLVeqm75M
         YnC0VxiouQsbrzW/bGpdHk8QClo74qYOlZg4Gk3sggczJCfLxg7h+9qgr0XE8fiWOwm5
         RNxj135ANoSydtT4yLx6ZW+wd9GzxmZfhxejhSZV5U6rM0qLaKnLgukOXTlvcfv2lrPj
         H2RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=lN9plnuKkpbJzQLXMCLzC6M7ry/HHd2YVAkTMHBXoC8=;
        b=RGqy6G/T1iWlbdYYjKwAbJXhTxuEIDHouTB42D5m9rPhBHcgbpaWym+PcUBQ005Q14
         4a2w5bGRyOPR0LceGMVl43Jvgno5ClCoDLZRxbvmn3i7iZnqB0MF5F/bJ9lttaFkVcKs
         NgD11V8FrguirgeY4tEglDbTAApDktL2Q1UW5MtCf0RrZnLuqkfpcmFQHH8X2feaLIj8
         WfuqJYTpxiRo3Mna9FL4Cg1MAs1w9eFHnZz97hTZLq3GXvmf3sr5Fnnv9nVHDk9nhHwy
         n4J+JUroL+P7zNIk4uGBc/RyGaIV+FaM+7/ymp65DmgZzUeeD710R3xv2FVWvbT2vGIr
         jVhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay2-d.mail.gandi.net (relay2-d.mail.gandi.net. [217.70.183.194])
        by gmr-mx.google.com with ESMTPS id sd27si219246ejb.1.2021.03.20.01.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 20 Mar 2021 01:48:20 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.194 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.194;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay2-d.mail.gandi.net (Postfix) with ESMTPSA id 39AEC40003;
	Sat, 20 Mar 2021 08:48:14 +0000 (UTC)
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
Message-ID: <fdc52c40-3324-fc9a-ffda-926ced856a80@ghiti.fr>
Date: Sat, 20 Mar 2021 04:48:14 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <mhng-cf5d29ec-e941-4579-8c42-2c11799a8f2f@penguin>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.194 is neither permitted nor denied by best guess
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

I have just tried to rebase this on for-next, and that quite conflicts=20
with Vitaly's XIP patch, I'm fixing this and post a v3.

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fdc52c40-3324-fc9a-ffda-926ced856a80%40ghiti.fr.
