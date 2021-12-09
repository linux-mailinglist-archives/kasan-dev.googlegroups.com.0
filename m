Return-Path: <kasan-dev+bncBAABBBUOY2GQMGQEBQOA6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CBFF746E178
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 05:33:11 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id ay10-20020a5d9d8a000000b005e238eaeaa9sf5820260iob.12
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Dec 2021 20:33:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639024390; cv=pass;
        d=google.com; s=arc-20160816;
        b=x84VuGPjZxUCHMv95s5keqO33633ah3D1bNRsC2N8dhW1d6aguNn6Fv9V1+t7tGx/4
         WAgbUNtLmu/hLHZDhZG/p0Pe10FKqEmg1biCSsKtx8CgSorNaehDqZhtN+aEs8DkKUCO
         zSe6PldBpDMlQDyZl1Wbr15C8p+wYhvMDHLw9jdALUk1jYBc1DDZqPv+SX7JIL+CbWV7
         5mHkiNrqi17sWCxnFv/xRucgVkJptUkJJ1oIAKaaO+P+Aee9GlevwpdhDq+u2rJJBh6Z
         L/6y1/yaEEzpgI7zzSoSjlW2llSM+cgv6mc48gc4aRxQkc63wqS+okpm5K8Sd43wP6Ad
         6jIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:to:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=PyFK8KqNnAFlLcuA0EPfVceRFS7LNG3QdhlCivYAANc=;
        b=jRxEP5ydPoETTJ7GknLoK9+SQQrur1I4Us37HoYhTCuq4CFSkZ40giz3F7IR6wKChj
         GlTEz/nJANrwUwpstsvCw4+eHlWBngOrrMC4AqWzLdbyrdrLXAe02O0xUB6Un0CeybEz
         RPjdocUcgHns8G3K5ew1lVNL//wWYHk6dO3ABM+lSWjfXyCUpfCaDGUlGeWTW8W4+afb
         QBHtwx9TKn9K3NnVSZHb7moeU8SZnoKzsFVPZhmmndFf87V1bE3ZB76ZIvvXsJ8wgK7j
         GJCymhoHwjZq9AGhz1ImdQZ4i87EWJtC5Kd9sdNLvcXEFmejgJE4S6aYD/s391Shn7Ps
         ht8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of panqinglin2020@iscas.ac.cn designates 159.226.251.21 as permitted sender) smtp.mailfrom=panqinglin2020@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject:to
         :references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PyFK8KqNnAFlLcuA0EPfVceRFS7LNG3QdhlCivYAANc=;
        b=o9bGKxzkjk2lrgqIVnt6kFveDzmoCOuxgkeagAY+FX8gQsX8MKCp6mdF+mlywTAi2G
         2NMIlcGMz2vGBwUWRV1103gVGl3HEz8DRNmowxuDmA26OOdg7pg4x6qk2+c9Mp8s0DS/
         LnQ8WscUX3k7RaX8oiIn+ACrDi5K3F6f1CRurOESOw6FuSfRM+eM9Uzsm90NOQTkC+Pv
         106BMRDMJNnp1ByuWsAQYmBD8mLYt+t3TuqlldIxJs/jMLDKRjOPGqztab3D4LHPKAD3
         Ch4ws368Q4n6Irabu0OLVYgSMKR50LxuJjMf6qKw4KRYq6ofArpOITPG3vWQ0rPih1My
         zLnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:to:references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PyFK8KqNnAFlLcuA0EPfVceRFS7LNG3QdhlCivYAANc=;
        b=CHko5vugTxvwnGI3bH0Mg+IihClxiWwiJAlaFQnmMGTPGve5WC2Qxu6pcNpSQiui12
         1yM5EsTMUWDnaSkjBvxzMxpImI9n2SAXl9yiwMAg1qrebOr8y222MOSY7BSnSDuhX7eS
         usNS6blSaSzZh3BIv94tDEZ53a4xwHZxTcLH9z7Q51n4QYV5Z0IItOcj3uvDGecSNkDd
         k24dKK1/mcZPkoe+APPasV/2aHSkOK2tKAXLneP9Z6Ow9qhYyex91Uf/pZWFfBiP1yvi
         SE6F6E5ky9mFzKftetY//7Pp/Cnrf0YB0fitsgcvLOaZv7jJPmnAYi4Tdd8+jHZbVgsf
         mbhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O2GbjIeKCO1ObvS9QdHfhhJHc5S8vYETDARPhRLEJ14Bgjj3w
	zxZ+LUeY9adc0wwfgIIXvZc=
X-Google-Smtp-Source: ABdhPJy0tCZUr5Tu5iwzxTvU8ZiC5t4nHRuLOBdY3hvGGg8QNPS9LOQdlRqDNhdVIALnSQPOMxurAA==
X-Received: by 2002:a05:6638:16d6:: with SMTP id g22mr5819620jat.140.1639024390186;
        Wed, 08 Dec 2021 20:33:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a67:: with SMTP id w7ls592533ilv.8.gmail; Wed, 08
 Dec 2021 20:33:09 -0800 (PST)
X-Received: by 2002:a05:6e02:b45:: with SMTP id f5mr10250861ilu.283.1639024389688;
        Wed, 08 Dec 2021 20:33:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639024389; cv=none;
        d=google.com; s=arc-20160816;
        b=FSZ3PQ+Ld/GU1X4ZsG/O5lAnhogZooEmQo4R07MR6bDfQ6wEbjlc4vdZYI4rO1yDh1
         rJlCrBS6sb+bdx7TqLEZOWDYXPyaPTs6WCJB33iEa0PzkRaI9fuEZ++lTIyhIO+vqWW7
         vAVIDr+CYDg/NeKEQhTrAGNvxSDgd2ifKVM2svxvT9WwEC5HROWq1/khz9xmpQMx/zjv
         N4Wq9tIND6BW9Ou6WC28OZCC0tQTv3VHVNTiZ1Kz9ckZ2Gu2zsKQxsaJ6R5RsobdG2Ne
         aIEKKSqQhuQvfuXmVpkM/pW+EEGbF2KAISR0oE1LO5AU6+6wpK30RMfDkDTKzsYL/9LA
         RhMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to:subject
         :user-agent:mime-version:date:message-id;
        bh=EWmUHmdYROigW7AIQLLMLBBdb+vjoB8Q4m57jm/HBiw=;
        b=r9N/gJfy5tc0bzsl7J6Gfpu2IGFztsi8Hkqqrx04L/wMvbjK2r7LUczq/tjhUwEhzb
         BW4Zrd89XItxFxZ6itAEd1peelFNRU1S/qIml2OZUjWhm5nETHf9b6BD/l4/KQhV4ExG
         76ybg+vP39yuKaoUYswUBNeTF3QmCt4vF2gnKqJForuhrUtbDRmV42RuXtYc2uvU77Om
         rBiBn8tTYUn/KajU+PNkUflrcrkrE0/bw898azgya8ZPvBTOJjUFN4HMnzzr8e/T+BVK
         2GMxk7yvU2YljZbWGWqfxNKrkprbw62gvoWRwcdoFTYmwVjW0GqG7p72IWCaghYwm1EC
         QqtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of panqinglin2020@iscas.ac.cn designates 159.226.251.21 as permitted sender) smtp.mailfrom=panqinglin2020@iscas.ac.cn
Received: from cstnet.cn (smtp21.cstnet.cn. [159.226.251.21])
        by gmr-mx.google.com with ESMTP id y14si903526ill.0.2021.12.08.20.33.08
        for <kasan-dev@googlegroups.com>;
        Wed, 08 Dec 2021 20:33:09 -0800 (PST)
Received-SPF: pass (google.com: domain of panqinglin2020@iscas.ac.cn designates 159.226.251.21 as permitted sender) client-ip=159.226.251.21;
Received: from [192.168.31.60] (unknown [124.16.141.241])
	by APP-01 (Coremail) with SMTP id qwCowACnrZ3ahrFh4W_oAQ--.15063S3;
	Thu, 09 Dec 2021 12:32:27 +0800 (CST)
Message-ID: <b3040494-a0b7-a9e8-1690-af395af3626c@iscas.ac.cn>
Date: Thu, 9 Dec 2021 12:32:26 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH v3 07/13] riscv: Implement sv48 support
To: Alexandre ghiti <alex@ghiti.fr>,
 Alexandre Ghiti <alexandre.ghiti@canonical.com>,
 Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>,
 Atish Patra <Atish.Patra@rivosinc.com>, Christoph Hellwig <hch@lst.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>,
 Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
 Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
 linux-arch@vger.kernel.org
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-8-alexandre.ghiti@canonical.com>
 <73b65a52-3b52-f1aa-333b-aeb1e7daa002@ghiti.fr>
From: =?UTF-8?B?5r2Y5bqG6ZyW?= <panqinglin2020@iscas.ac.cn>
In-Reply-To: <73b65a52-3b52-f1aa-333b-aeb1e7daa002@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qwCowACnrZ3ahrFh4W_oAQ--.15063S3
X-Coremail-Antispam: 1UD129KBjvAXoWDCrWDuF1Dtr4rWF15XrW3GFg_yoWrZFW5uo
	WUKr1fGw1fXr1UKr17Gr1UXr15JF1UJrnrtr1UGrW3JF1xAF1UG3y8JrWjq3yUJr18Kr1U
	JF1UJ34jyFyDArn5n29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73VFW2AGmfu7bjvjm3
	AaLaJ3UjIYCTnIWjp_UUUYi7k0a2IF6w4kM7kC6x804xWl14x267AKxVWrJVCq3wAFc2x0
	x2IEx4CE42xK8VAvwI8IcIk0rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2ocxC64kIII0Yj4
	1l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r1j6r1xM28EF7xvwVC0
	I7IYx2IY6xkF7I0E14v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwV
	C2z280aVCY1x0267AKxVWxJr0_GcWlnxkEFVAIw20F6cxK64vIFxWle2I262IYc4CY6c8I
	j28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JrI_Jr
	ylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwAC
	I402YVCY1x02628vn2kIc2xKxwCYjI0SjxkI62AI1cAE67vIY487MxkIecxEwVAFwVW8Xw
	CF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j
	6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64
	vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Gr0_
	Cr1lIxAIcVCF04k26cxKx2IYs7xG6rWUJVWrZr1UMIIF0xvEx4A2jsIE14v26r1j6r4UMI
	IF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07brNtsUUUUU
	=
X-Originating-IP: [124.16.141.241]
X-CM-SenderInfo: 5sdq1xpqjox0asqsiq5lvft2wodfhubq/
X-Original-Sender: panqinglin2020@iscas.ac.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of panqinglin2020@iscas.ac.cn designates 159.226.251.21
 as permitted sender) smtp.mailfrom=panqinglin2020@iscas.ac.cn
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

Hi Alex,

On 2021/12/6 19:05, Alexandre ghiti wrote:
 > On 12/6/21 11:46, Alexandre Ghiti wrote:
 >> By adding a new 4th level of page table, give the possibility to 64bit
 >> kernel to address 2^48 bytes of virtual address: in practice, that=20
offers
 >> 128TB of virtual address space to userspace and allows up to 64TB of
 >> physical memory.
 >>
 >> If the underlying hardware does not support sv48, we will automatically
 >> fallback to a standard 3-level page table by folding the new PUD=20
level into
 >> PGDIR level. In order to detect HW capabilities at runtime, we
 >> use SATP feature that ignores writes with an unsupported mode.
 >>
 >> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
 >> ---
 >>=C2=A0=C2=A0 arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0=C2=A0 4 +-
 >>=C2=A0=C2=A0 arch/riscv/include/asm/csr.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 3 +-
 >>=C2=A0=C2=A0 arch/riscv/include/asm/fixmap.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 1 +
 >>=C2=A0=C2=A0 arch/riscv/include/asm/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 6 +-
 >>=C2=A0=C2=A0 arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 14 ++
 >>=C2=A0=C2=A0 arch/riscv/include/asm/pgalloc.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 40 +++++
 >>=C2=A0=C2=A0 arch/riscv/include/asm/pgtable-64.h=C2=A0=C2=A0=C2=A0=C2=A0=
 | 108 +++++++++++-
 >>=C2=A0=C2=A0 arch/riscv/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 24 ++-
 >>=C2=A0=C2=A0 arch/riscv/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 3 +=
-
 >>=C2=A0=C2=A0 arch/riscv/mm/context.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 =
4 +-
 >>=C2=A0=C2=A0 arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 212 +++++++++++++++++++++---
 >>=C2=A0=C2=A0 arch/riscv/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 137 ++++++++++++++-
 >>=C2=A0=C2=A0 drivers/firmware/efi/libstub/efi-stub.c |=C2=A0=C2=A0 2 +
 >>=C2=A0=C2=A0 13 files changed, 514 insertions(+), 44 deletions(-)
 >>
 >> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
 >> index ac6c0cd9bc29..d28fe0148e13 100644
 >> --- a/arch/riscv/Kconfig
 >> +++ b/arch/riscv/Kconfig
 >> @@ -150,7 +150,7 @@ config PAGE_OFFSET
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 hex
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 default 0xC0000000 if 32BIT
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 default 0x80000000 if 64BIT && !MMU
 >> -=C2=A0=C2=A0=C2=A0 default 0xffffffd800000000 if 64BIT
 >> +=C2=A0=C2=A0=C2=A0 default 0xffffaf8000000000 if 64BIT
 >>=C2=A0=C2=A0=C2=A0=C2=A0 config KASAN_SHADOW_OFFSET
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 hex
 >> @@ -201,7 +201,7 @@ config FIX_EARLYCON_MEM
 >>=C2=A0=C2=A0=C2=A0=C2=A0 config PGTABLE_LEVELS
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int
 >> -=C2=A0=C2=A0=C2=A0 default 3 if 64BIT
 >> +=C2=A0=C2=A0=C2=A0 default 4 if 64BIT
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 default 2
 >>=C2=A0=C2=A0=C2=A0=C2=A0 config LOCKDEP_SUPPORT
 >> diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.=
h
 >> index 87ac65696871..3fdb971c7896 100644
 >> --- a/arch/riscv/include/asm/csr.h
 >> +++ b/arch/riscv/include/asm/csr.h
 >> @@ -40,14 +40,13 @@
 >>=C2=A0=C2=A0 #ifndef CONFIG_64BIT
 >>=C2=A0=C2=A0 #define SATP_PPN=C2=A0=C2=A0=C2=A0 _AC(0x003FFFFF, UL)
 >>=C2=A0=C2=A0 #define SATP_MODE_32=C2=A0=C2=A0=C2=A0 _AC(0x80000000, UL)
 >> -#define SATP_MODE=C2=A0=C2=A0=C2=A0 SATP_MODE_32
 >>=C2=A0=C2=A0 #define SATP_ASID_BITS=C2=A0=C2=A0=C2=A0 9
 >>=C2=A0=C2=A0 #define SATP_ASID_SHIFT=C2=A0=C2=A0=C2=A0 22
 >>=C2=A0=C2=A0 #define SATP_ASID_MASK=C2=A0=C2=A0=C2=A0 _AC(0x1FF, UL)
 >>=C2=A0=C2=A0 #else
 >>=C2=A0=C2=A0 #define SATP_PPN=C2=A0=C2=A0=C2=A0 _AC(0x00000FFFFFFFFFFF, =
UL)
 >>=C2=A0=C2=A0 #define SATP_MODE_39=C2=A0=C2=A0=C2=A0 _AC(0x80000000000000=
00, UL)
 >> -#define SATP_MODE=C2=A0=C2=A0=C2=A0 SATP_MODE_39
 >> +#define SATP_MODE_48=C2=A0=C2=A0=C2=A0 _AC(0x9000000000000000, UL)
 >>=C2=A0=C2=A0 #define SATP_ASID_BITS=C2=A0=C2=A0=C2=A0 16
 >>=C2=A0=C2=A0 #define SATP_ASID_SHIFT=C2=A0=C2=A0=C2=A0 44
 >>=C2=A0=C2=A0 #define SATP_ASID_MASK=C2=A0=C2=A0=C2=A0 _AC(0xFFFF, UL)
 >> diff --git a/arch/riscv/include/asm/fixmap.h=20
b/arch/riscv/include/asm/fixmap.h
 >> index 54cbf07fb4e9..58a718573ad6 100644
 >> --- a/arch/riscv/include/asm/fixmap.h
 >> +++ b/arch/riscv/include/asm/fixmap.h
 >> @@ -24,6 +24,7 @@ enum fixed_addresses {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_HOLE,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_PTE,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_PMD,
 >> +=C2=A0=C2=A0=C2=A0 FIX_PUD,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_TEXT_POKE1,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_TEXT_POKE0,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 FIX_EARLYCON_MEM_BASE,
 >> diff --git a/arch/riscv/include/asm/kasan.h=20
b/arch/riscv/include/asm/kasan.h
 >> index 743e6ff57996..0b85e363e778 100644
 >> --- a/arch/riscv/include/asm/kasan.h
 >> +++ b/arch/riscv/include/asm/kasan.h
 >> @@ -28,7 +28,11 @@
 >>=C2=A0=C2=A0 #define KASAN_SHADOW_SCALE_SHIFT=C2=A0=C2=A0=C2=A0 3
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #define KASAN_SHADOW_SIZE=C2=A0=C2=A0=C2=A0 (UL=
(1) << ((VA_BITS - 1) -=20
KASAN_SHADOW_SCALE_SHIFT))
 >> -#define KASAN_SHADOW_START=C2=A0=C2=A0=C2=A0 (KASAN_SHADOW_END - KASAN=
_SHADOW_SIZE)
 >> +/*
 >> + * Depending on the size of the virtual address space, the region=20
may not be
 >> + * aligned on PGDIR_SIZE, so force its alignment to ease its=20
population.
 >> + */
 >> +#define KASAN_SHADOW_START=C2=A0=C2=A0=C2=A0 ((KASAN_SHADOW_END -=20
KASAN_SHADOW_SIZE) & PGDIR_MASK)
 >>=C2=A0=C2=A0 #define KASAN_SHADOW_END=C2=A0=C2=A0=C2=A0 MODULES_LOWEST_V=
ADDR
 >>=C2=A0=C2=A0 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET,=
 UL)
 >>=C2=A0=C2=A0 diff --git a/arch/riscv/include/asm/page.h=20
b/arch/riscv/include/asm/page.h
 >> index e03559f9b35e..d089fe46f7d8 100644
 >> --- a/arch/riscv/include/asm/page.h
 >> +++ b/arch/riscv/include/asm/page.h
 >> @@ -31,7 +31,20 @@
 >>=C2=A0=C2=A0=C2=A0 * When not using MMU this corresponds to the first fr=
ee page in
 >>=C2=A0=C2=A0=C2=A0 * physical memory (aligned on a page boundary).
 >>=C2=A0=C2=A0=C2=A0 */
 >> +#ifdef CONFIG_64BIT
 >> +#ifdef CONFIG_MMU
 >> +#define PAGE_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_m=
ap.page_offset
 >> +#else
 >> +#define PAGE_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 _AC(CONF=
IG_PAGE_OFFSET, UL)
 >> +#endif
 >> +/*
 >> + * By default, CONFIG_PAGE_OFFSET value corresponds to SV48 address=20
space so
 >> + * define the PAGE_OFFSET value for SV39.
 >> + */
 >> +#define PAGE_OFFSET_L3=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 _AC(0=
xffffffd800000000, UL)
 >> +#else
 >>=C2=A0=C2=A0 #define PAGE_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 _AC(CONFIG_PAGE_OFFSET, UL)
 >> +#endif /* CONFIG_64BIT */
 >>=C2=A0=C2=A0=C2=A0=C2=A0 /*
 >>=C2=A0=C2=A0=C2=A0 * Half of the kernel address space (half of the entri=
es of the=20
page global
 >> @@ -90,6 +103,7 @@ extern unsigned long riscv_pfn_base;
 >>=C2=A0=C2=A0 #endif /* CONFIG_MMU */
 >>=C2=A0=C2=A0=C2=A0=C2=A0 struct kernel_mapping {
 >> +=C2=A0=C2=A0=C2=A0 unsigned long page_offset;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long virt_addr;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t phys_addr;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t size;
 >> diff --git a/arch/riscv/include/asm/pgalloc.h=20
b/arch/riscv/include/asm/pgalloc.h
 >> index 0af6933a7100..11823004b87a 100644
 >> --- a/arch/riscv/include/asm/pgalloc.h
 >> +++ b/arch/riscv/include/asm/pgalloc.h
 >> @@ -11,6 +11,8 @@
 >>=C2=A0=C2=A0 #include <asm/tlb.h>
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_MMU
 >> +#define __HAVE_ARCH_PUD_ALLOC_ONE
 >> +#define __HAVE_ARCH_PUD_FREE
 >>=C2=A0=C2=A0 #include <asm-generic/pgalloc.h>
 >>=C2=A0=C2=A0=C2=A0=C2=A0 static inline void pmd_populate_kernel(struct m=
m_struct *mm,
 >> @@ -36,6 +38,44 @@ static inline void pud_populate(struct mm_struct=20
*mm, pud_t *pud, pmd_t *pmd)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pud(pud, __pud((pfn=
 << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
 >>=C2=A0=C2=A0 }
 >> +
 >> +static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d,=20
pud_t *pud)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn =3D virt_=
to_pfn(pud);
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_p4d(p4d, __p4d((pfn << =
_PAGE_PFN_SHIFT) | _PAGE_TABLE));
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +}
 >> +
 >> +static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_t *pud)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn =3D virt_=
to_pfn(pud);
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_p4d_safe(p4d,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +}
 >> +
 >> +#define pud_alloc_one pud_alloc_one
 >> +static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned=20
long addr)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return __pud_alloc_one(mm, =
addr);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return NULL;
 >> +}
 >> +
 >> +#define pud_free pud_free
 >> +static inline void pud_free(struct mm_struct *mm, pud_t *pud)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pud_free(mm, pud);
 >> +}
 >> +
 >> +#define __pud_free_tlb(tlb, pud, addr) pud_free((tlb)->mm, pud)
 >>=C2=A0=C2=A0 #endif /* __PAGETABLE_PMD_FOLDED */
 >>=C2=A0=C2=A0=C2=A0=C2=A0 static inline pgd_t *pgd_alloc(struct mm_struct=
 *mm)
 >> diff --git a/arch/riscv/include/asm/pgtable-64.h=20
b/arch/riscv/include/asm/pgtable-64.h
 >> index 228261aa9628..bbbdd66e5e2f 100644
 >> --- a/arch/riscv/include/asm/pgtable-64.h
 >> +++ b/arch/riscv/include/asm/pgtable-64.h
 >> @@ -8,16 +8,36 @@
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #include <linux/const.h>
 >>=C2=A0=C2=A0 -#define PGDIR_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0 30
 >> +extern bool pgtable_l4_enabled;
 >> +
 >> +#define PGDIR_SHIFT_L3=C2=A0 30
 >> +#define PGDIR_SHIFT_L4=C2=A0 39
 >> +#define PGDIR_SIZE_L3=C2=A0=C2=A0 (_AC(1, UL) << PGDIR_SHIFT_L3)
 >> +
 >> +#define PGDIR_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ? PGDI=
R_SHIFT_L4 :=20
PGDIR_SHIFT_L3)
 >>=C2=A0=C2=A0 /* Size of region mapped by a page global directory */
 >>=C2=A0=C2=A0 #define PGDIR_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (_AC(1, UL=
) << PGDIR_SHIFT)
 >>=C2=A0=C2=A0 #define PGDIR_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (~(PGDIR_S=
IZE - 1))
 >>=C2=A0=C2=A0 +/* pud is folded into pgd in case of 3-level page table */
 >> +#define PUD_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 30
 >> +#define PUD_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (_AC(1, UL) << PU=
D_SHIFT)
 >> +#define PUD_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (~(PUD_SIZE - 1))
 >> +
 >>=C2=A0=C2=A0 #define PMD_SHIFT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 21
 >>=C2=A0=C2=A0 /* Size of region mapped by a page middle directory */
 >>=C2=A0=C2=A0 #define PMD_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
(_AC(1, UL) << PMD_SHIFT)
 >>=C2=A0=C2=A0 #define PMD_MASK=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
(~(PMD_SIZE - 1))
 >>=C2=A0=C2=A0 +/* Page Upper Directory entry */
 >> +typedef struct {
 >> +=C2=A0=C2=A0=C2=A0 unsigned long pud;
 >> +} pud_t;
 >> +
 >> +#define pud_val(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((x).pud)
 >> +#define __pud(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pud_t) { =
(x) })
 >> +#define PTRS_PER_PUD=C2=A0=C2=A0=C2=A0 (PAGE_SIZE / sizeof(pud_t))
 >> +
 >>=C2=A0=C2=A0 /* Page Middle Directory entry */
 >>=C2=A0=C2=A0 typedef struct {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pmd;
 >> @@ -59,6 +79,16 @@ static inline void pud_clear(pud_t *pudp)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pud(pudp, __pud(0));
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 +static inline pud_t pfn_pud(unsigned long pfn, pgprot_t pr=
ot)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return __pud((pfn << _PAGE_PFN_SHIFT) | pgprot_val(=
prot));
 >> +}
 >> +
 >> +static inline unsigned long _pud_pfn(pud_t pud)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return pud_val(pud) >> _PAGE_PFN_SHIFT;
 >> +}
 >> +
 >>=C2=A0=C2=A0 static inline pmd_t *pud_pgtable(pud_t pud)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (pmd_t *)pfn_to_virt(pud_val=
(pud) >> _PAGE_PFN_SHIFT);
 >> @@ -69,6 +99,17 @@ static inline struct page *pud_page(pud_t pud)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return pfn_to_page(pud_val(pud) >> =
_PAGE_PFN_SHIFT);
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 +#define mm_pud_folded=C2=A0 mm_pud_folded
 >> +static inline bool mm_pud_folded(struct mm_struct *mm)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return false;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return true;
 >> +}
 >> +
 >> +#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
 >> +
 >>=C2=A0=C2=A0 static inline pmd_t pfn_pmd(unsigned long pfn, pgprot_t pro=
t)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return __pmd((pfn << _PAGE_PFN_SHIF=
T) | pgprot_val(prot));
 >> @@ -84,4 +125,69 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 >>=C2=A0=C2=A0 #define pmd_ERROR(e) \
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("%s:%d: bad pmd %016lx.\n", =
__FILE__, __LINE__, pmd_val(e))
 >>=C2=A0=C2=A0 +#define pud_ERROR(e)=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0 pr_err("%s:%d: bad pud %016lx.\n", __FILE__, __LINE=
__, pud_val(e))
 >> +
 >> +static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *p4dp =3D p4d;
 >> +=C2=A0=C2=A0=C2=A0 else
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pud((pud_t *)p4dp, (pud=
_t){ p4d_val(p4d) });
 >> +}
 >> +
 >> +static inline int p4d_none(p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (p4d_val(p4d) =3D=3D=
 0);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return 0;
 >> +}
 >> +
 >> +static inline int p4d_present(p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (p4d_val(p4d) & _PAG=
E_PRESENT);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return 1;
 >> +}
 >> +
 >> +static inline int p4d_bad(p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return !p4d_present(p4d);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return 0;
 >> +}
 >> +
 >> +static inline void p4d_clear(p4d_t *p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_p4d(p4d, __p4d(0));
 >> +}
 >> +
 >> +static inline pud_t *p4d_pgtable(p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (pud_t *)pfn_to_virt=
(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) =
});
 >> +}
 >> +
 >> +static inline struct page *p4d_page(p4d_t p4d)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return pfn_to_page(p4d_val(p4d) >> _PAGE_PFN_SHIFT)=
;
 >> +}
 >> +
 >> +#define pud_index(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
 >> +
 >> +#define pud_offset pud_offset
 >> +static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return p4d_pgtable(*p4d) + =
pud_index(address);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return (pud_t *)p4d;
 >> +}
 >> +
 >>=C2=A0=C2=A0 #endif /* _ASM_RISCV_PGTABLE_64_H */
 >> diff --git a/arch/riscv/include/asm/pgtable.h=20
b/arch/riscv/include/asm/pgtable.h
 >> index e1a52e22ad7e..e1c74ef4ead2 100644
 >> --- a/arch/riscv/include/asm/pgtable.h
 >> +++ b/arch/riscv/include/asm/pgtable.h
 >> @@ -51,7 +51,7 @@
 >>=C2=A0=C2=A0=C2=A0 * position vmemmap directly below the VMALLOC region.
 >>=C2=A0=C2=A0=C2=A0 */
 >>=C2=A0=C2=A0 #ifdef CONFIG_64BIT
 >> -#define VA_BITS=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 39
 >> +#define VA_BITS=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (pgtable_l4_=
enabled ? 48 : 39)
 >>=C2=A0=C2=A0 #else
 >>=C2=A0=C2=A0 #define VA_BITS=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 3=
2
 >>=C2=A0=C2=A0 #endif
 >> @@ -90,8 +90,7 @@
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifndef __ASSEMBLY__
 >>=C2=A0=C2=A0 -/* Page Upper Directory not used in RISC-V */
 >> -#include <asm-generic/pgtable-nopud.h>
 >> +#include <asm-generic/pgtable-nop4d.h>
 >>=C2=A0=C2=A0 #include <asm/page.h>
 >>=C2=A0=C2=A0 #include <asm/tlbflush.h>
 >>=C2=A0=C2=A0 #include <linux/mm_types.h>
 >> @@ -113,6 +112,17 @@
 >>=C2=A0=C2=A0 #define XIP_FIXUP(addr)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 (addr)
 >>=C2=A0=C2=A0 #endif /* CONFIG_XIP_KERNEL */
 >>=C2=A0=C2=A0 +struct pt_alloc_ops {
 >> +=C2=A0=C2=A0=C2=A0 pte_t *(*get_pte_virt)(phys_addr_t pa);
 >> +=C2=A0=C2=A0=C2=A0 phys_addr_t (*alloc_pte)(uintptr_t va);
 >> +#ifndef __PAGETABLE_PMD_FOLDED
 >> +=C2=A0=C2=A0=C2=A0 pmd_t *(*get_pmd_virt)(phys_addr_t pa);
 >> +=C2=A0=C2=A0=C2=A0 phys_addr_t (*alloc_pmd)(uintptr_t va);
 >> +=C2=A0=C2=A0=C2=A0 pud_t *(*get_pud_virt)(phys_addr_t pa);
 >> +=C2=A0=C2=A0=C2=A0 phys_addr_t (*alloc_pud)(uintptr_t va);
 >> +#endif
 >> +};
 >> +
 >>=C2=A0=C2=A0 #ifdef CONFIG_MMU
 >>=C2=A0=C2=A0 /* Number of entries in the page global directory */
 >>=C2=A0=C2=A0 #define PTRS_PER_PGD=C2=A0=C2=A0=C2=A0 (PAGE_SIZE / sizeof(=
pgd_t))
 >> @@ -669,9 +679,11 @@ static inline pmd_t pmdp_establish(struct=20
vm_area_struct *vma,
 >>=C2=A0=C2=A0=C2=A0 * Note that PGDIR_SIZE must evenly divide TASK_SIZE.
 >>=C2=A0=C2=A0=C2=A0 */
 >>=C2=A0=C2=A0 #ifdef CONFIG_64BIT
 >> -#define TASK_SIZE (PGDIR_SIZE * PTRS_PER_PGD / 2)
 >> +#define TASK_SIZE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PGDIR_SIZE * PTRS_PER=
_PGD / 2)
 >> +#define TASK_SIZE_MIN=C2=A0 (PGDIR_SIZE_L3 * PTRS_PER_PGD / 2)
 >>=C2=A0=C2=A0 #else
 >> -#define TASK_SIZE FIXADDR_START
 >> +#define TASK_SIZE=C2=A0=C2=A0=C2=A0 FIXADDR_START
 >> +#define TASK_SIZE_MIN=C2=A0=C2=A0=C2=A0 TASK_SIZE
 >>=C2=A0=C2=A0 #endif
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #else /* CONFIG_MMU */
 >> @@ -697,6 +709,8 @@ extern uintptr_t _dtb_early_pa;
 >>=C2=A0=C2=A0 #define dtb_early_va=C2=A0=C2=A0=C2=A0 _dtb_early_va
 >>=C2=A0=C2=A0 #define dtb_early_pa=C2=A0=C2=A0=C2=A0 _dtb_early_pa
 >>=C2=A0=C2=A0 #endif /* CONFIG_XIP_KERNEL */
 >> +extern u64 satp_mode;
 >> +extern bool pgtable_l4_enabled;
 >>=C2=A0=C2=A0=C2=A0=C2=A0 void paging_init(void);
 >>=C2=A0=C2=A0 void misc_mem_init(void);
 >> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
 >> index 52c5ff9804c5..c3c0ed559770 100644
 >> --- a/arch/riscv/kernel/head.S
 >> +++ b/arch/riscv/kernel/head.S
 >> @@ -95,7 +95,8 @@ relocate:
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Compute satp for ker=
nel page tables, but don't load it yet */
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 srl a2, a0, PAGE_SHIFT
 >> -=C2=A0=C2=A0=C2=A0 li a1, SATP_MODE
 >> +=C2=A0=C2=A0=C2=A0 la a1, satp_mode
 >> +=C2=A0=C2=A0=C2=A0 REG_L a1, 0(a1)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 or a2, a2, a1
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
 >> diff --git a/arch/riscv/mm/context.c b/arch/riscv/mm/context.c
 >> index ee3459cb6750..a7246872bd30 100644
 >> --- a/arch/riscv/mm/context.c
 >> +++ b/arch/riscv/mm/context.c
 >> @@ -192,7 +192,7 @@ static void set_mm_asid(struct mm_struct *mm,=20
unsigned int cpu)
 >>=C2=A0=C2=A0 switch_mm_fast:
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, virt_to_pfn(mm-=
>pgd) |
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 ((cntx & asid_mask) << SATP_ASID_SHIFT) |
 >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 SATP_MODE);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 satp_mode);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (need_flush_tlb)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush=
_tlb_all();
 >> @@ -201,7 +201,7 @@ static void set_mm_asid(struct mm_struct *mm,=20
unsigned int cpu)
 >>=C2=A0=C2=A0 static void set_mm_noasid(struct mm_struct *mm)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Switch the page table and blindl=
y nuke entire local TLB */
 >> -=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, virt_to_pfn(mm->pgd) | SATP_MOD=
E);
 >> +=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, virt_to_pfn(mm->pgd) | satp_mod=
e);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
 >> index 1552226fb6bd..6a19a1b1caf8 100644
 >> --- a/arch/riscv/mm/init.c
 >> +++ b/arch/riscv/mm/init.c
 >> @@ -37,6 +37,17 @@ EXPORT_SYMBOL(kernel_map);
 >>=C2=A0=C2=A0 #define kernel_map=C2=A0=C2=A0=C2=A0 (*(struct kernel_mappi=
ng=20
*)XIP_FIXUP(&kernel_map))
 >>=C2=A0=C2=A0 #endif
 >>=C2=A0=C2=A0 +#ifdef CONFIG_64BIT
 >> +u64 satp_mode =3D !IS_ENABLED(CONFIG_XIP_KERNEL) ? SATP_MODE_48 :=20
SATP_MODE_39;
 >> +#else
 >> +u64 satp_mode =3D SATP_MODE_32;
 >> +#endif
 >> +EXPORT_SYMBOL(satp_mode);
 >> +
 >> +bool pgtable_l4_enabled =3D IS_ENABLED(CONFIG_64BIT) &&=20
!IS_ENABLED(CONFIG_XIP_KERNEL) ?
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 true : false;
 >> +EXPORT_SYMBOL(pgtable_l4_enabled);
 >> +
 >>=C2=A0=C2=A0 phys_addr_t phys_ram_base __ro_after_init;
 >>=C2=A0=C2=A0 EXPORT_SYMBOL(phys_ram_base);
 >>=C2=A0=C2=A0 @@ -53,15 +64,6 @@ extern char _start[];
 >>=C2=A0=C2=A0 void *_dtb_early_va __initdata;
 >>=C2=A0=C2=A0 uintptr_t _dtb_early_pa __initdata;
 >>=C2=A0=C2=A0 -struct pt_alloc_ops {
 >> -=C2=A0=C2=A0=C2=A0 pte_t *(*get_pte_virt)(phys_addr_t pa);
 >> -=C2=A0=C2=A0=C2=A0 phys_addr_t (*alloc_pte)(uintptr_t va);
 >> -#ifndef __PAGETABLE_PMD_FOLDED
 >> -=C2=A0=C2=A0=C2=A0 pmd_t *(*get_pmd_virt)(phys_addr_t pa);
 >> -=C2=A0=C2=A0=C2=A0 phys_addr_t (*alloc_pmd)(uintptr_t va);
 >> -#endif
 >> -};
 >> -
 >>=C2=A0=C2=A0 static phys_addr_t dma32_phys_limit __initdata;
 >>=C2=A0=C2=A0=C2=A0=C2=A0 static void __init zone_sizes_init(void)
 >> @@ -222,7 +224,7 @@ static void __init setup_bootmem(void)
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_MMU
 >> -static struct pt_alloc_ops _pt_ops __initdata;
 >> +struct pt_alloc_ops _pt_ops __initdata;
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_XIP_KERNEL
 >>=C2=A0=C2=A0 #define pt_ops (*(struct pt_alloc_ops *)XIP_FIXUP(&_pt_ops)=
)
 >> @@ -238,6 +240,7 @@ pgd_t trampoline_pg_dir[PTRS_PER_PGD]=20
__page_aligned_bss;
 >>=C2=A0=C2=A0 static pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;
 >>=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __a=
ligned(PAGE_SIZE);
 >> +static pud_t __maybe_unused early_dtb_pud[PTRS_PER_PUD] __initdata=20
__aligned(PAGE_SIZE);
 >>=C2=A0=C2=A0 static pmd_t __maybe_unused early_dtb_pmd[PTRS_PER_PMD] __i=
nitdata=20
__aligned(PAGE_SIZE);
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_XIP_KERNEL
 >> @@ -326,6 +329,16 @@ static pmd_t early_pmd[PTRS_PER_PMD] __initdata=20
__aligned(PAGE_SIZE);
 >>=C2=A0=C2=A0 #define early_pmd=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pmd_t *)X=
IP_FIXUP(early_pmd))
 >>=C2=A0=C2=A0 #endif /* CONFIG_XIP_KERNEL */
 >>=C2=A0=C2=A0 +static pud_t trampoline_pud[PTRS_PER_PUD] __page_aligned_b=
ss;
 >> +static pud_t fixmap_pud[PTRS_PER_PUD] __page_aligned_bss;
 >> +static pud_t early_pud[PTRS_PER_PUD] __initdata __aligned(PAGE_SIZE);
 >> +
 >> +#ifdef CONFIG_XIP_KERNEL
 >> +#define trampoline_pud ((pud_t *)XIP_FIXUP(trampoline_pud))
 >> +#define fixmap_pud=C2=A0=C2=A0=C2=A0=C2=A0 ((pud_t *)XIP_FIXUP(fixmap_=
pud))
 >> +#define early_pud=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pud_t *)XIP_FIXUP(ea=
rly_pud))
 >> +#endif /* CONFIG_XIP_KERNEL */
 >> +
 >>=C2=A0=C2=A0 static pmd_t *__init get_pmd_virt_early(phys_addr_t pa)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Before MMU is enabled */
 >> @@ -345,7 +358,7 @@ static pmd_t *__init=20
get_pmd_virt_late(phys_addr_t pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0 static phys_addr_t __init alloc_pmd_early(uintp=
tr_t va)
 >>=C2=A0=C2=A0 {
 >> -=C2=A0=C2=A0=C2=A0 BUG_ON((va - kernel_map.virt_addr) >> PGDIR_SHIFT);
 >> +=C2=A0=C2=A0=C2=A0 BUG_ON((va - kernel_map.virt_addr) >> PUD_SHIFT);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (uintptr_t)early=
_pmd;
 >>=C2=A0=C2=A0 }
 >> @@ -391,21 +404,97 @@ static void __init create_pmd_mapping(pmd_t *pmdp=
,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pte_mapping(ptep, va, pa, sz=
, prot);
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 -#define pgd_next_t=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 pmd_t
 >> -#define alloc_pgd_next(__va)=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pmd(__va)
 >> -#define get_pgd_next_virt(__pa) pt_ops.get_pmd_virt(__pa)
 >> +static pud_t *__init get_pud_virt_early(phys_addr_t pa)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return (pud_t *)((uintptr_t)pa);
 >> +}
 >> +
 >> +static pud_t *__init get_pud_virt_fixmap(phys_addr_t pa)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PUD);
 >> +=C2=A0=C2=A0=C2=A0 return (pud_t *)set_fixmap_offset(FIX_PUD, pa);
 >> +}
 >> +
 >> +static pud_t *__init get_pud_virt_late(phys_addr_t pa)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return (pud_t *)__va(pa);
 >> +}
 >> +
 >> +static phys_addr_t __init alloc_pud_early(uintptr_t va)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 /* Only one PUD is available for early mapping */
 >> +=C2=A0=C2=A0=C2=A0 BUG_ON((va - kernel_map.virt_addr) >> PGDIR_SHIFT);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 return (uintptr_t)early_pud;
 >> +}
 >> +
 >> +static phys_addr_t __init alloc_pud_fixmap(uintptr_t va)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
 >> +}
 >> +
 >> +static phys_addr_t alloc_pud_late(uintptr_t va)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 vaddr =3D __get_free_page(GFP_KERNEL);
 >> +=C2=A0=C2=A0=C2=A0 BUG_ON(!vaddr);
 >> +=C2=A0=C2=A0=C2=A0 return __pa(vaddr);
 >> +}
 >> +
 >> +static void __init create_pud_mapping(pud_t *pudp,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t va, phy=
s_addr_t pa,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t sz, p=
gprot_t prot)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 pmd_t *nextp;
 >> +=C2=A0=C2=A0=C2=A0 phys_addr_t next_phys;
 >> +=C2=A0=C2=A0=C2=A0 uintptr_t pud_index =3D pud_index(va);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 if (sz =3D=3D PUD_SIZE) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_val(pudp[pud_index]=
) =3D=3D 0)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud=
p[pud_index] =3D pfn_pud(PFN_DOWN(pa), prot);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +
 >> +=C2=A0=C2=A0=C2=A0 if (pud_val(pudp[pud_index]) =3D=3D 0) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next_phys =3D pt_ops.alloc_=
pmd(va);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pudp[pud_index] =3D pfn_pud=
(PFN_DOWN(next_phys), PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 nextp =3D pt_ops.get_pmd_vi=
rt(next_phys);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(nextp, 0, PAGE_SIZE)=
;
 >> +=C2=A0=C2=A0=C2=A0 } else {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next_phys =3D PFN_PHYS(_pud=
_pfn(pudp[pud_index]));
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 nextp =3D pt_ops.get_pmd_vi=
rt(next_phys);
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +
 >> +=C2=A0=C2=A0=C2=A0 create_pmd_mapping(nextp, va, pa, sz, prot);
 >> +}
 >> +
 >> +#define pgd_next_t=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_t
 >> +#define alloc_pgd_next(__va)=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ?=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pud(__va) : pt=
_ops.alloc_pmd(__va))
 >> +#define get_pgd_next_virt(__pa)=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled =
?=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.get_pud_virt(__pa) :=
 (pgd_next_t=20
*)pt_ops.get_pmd_virt(__pa))
 >>=C2=A0=C2=A0 #define create_pgd_next_mapping(__nextp, __va, __pa, __sz,=
=20
__prot)=C2=A0=C2=A0=C2=A0 \
 >> -=C2=A0=C2=A0=C2=A0 create_pmd_mapping(__nextp, __va, __pa, __sz, __pro=
t)
 >> -#define fixmap_pgd_next=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 fixm=
ap_pmd
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ?=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pud_mapping(__nextp,=
 __va, __pa, __sz, __prot) :=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_mapping((pmd_t *=
)__nextp, __va, __pa, __sz, __prot))
 >> +#define fixmap_pgd_next=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (pgt=
able_l4_enabled ?=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pud : (ui=
ntptr_t)fixmap_pmd)
 >> +#define trampoline_pgd_next=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ?=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)trampoline_pud :=
 (uintptr_t)trampoline_pmd)
 >> +#define early_dtb_pgd_next=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ?=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)early_dtb_pud : =
(uintptr_t)early_dtb_pmd)
 >>=C2=A0=C2=A0 #else
 >>=C2=A0=C2=A0 #define pgd_next_t=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 pte_t
 >>=C2=A0=C2=A0 #define alloc_pgd_next(__va)=C2=A0=C2=A0=C2=A0 pt_ops.alloc=
_pte(__va)
 >>=C2=A0=C2=A0 #define get_pgd_next_virt(__pa) pt_ops.get_pte_virt(__pa)
 >>=C2=A0=C2=A0 #define create_pgd_next_mapping(__nextp, __va, __pa, __sz,=
=20
__prot)=C2=A0=C2=A0=C2=A0 \
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pte_mapping(__nextp, __va, _=
_pa, __sz, __prot)
 >> -#define fixmap_pgd_next=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 fixm=
ap_pte
 >> +#define fixmap_pgd_next=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((ui=
ntptr_t)fixmap_pte)
 >> +#define early_dtb_pgd_next=C2=A0=C2=A0=C2=A0 ((uintptr_t)early_dtb_pmd=
)
 >> +#define create_pud_mapping(__pmdp, __va, __pa, __sz, __prot)
 >>=C2=A0=C2=A0 #define create_pmd_mapping(__pmdp, __va, __pa, __sz, __prot=
)
 >> -#endif
 >> +#endif /* __PAGETABLE_PMD_FOLDED */
 >>=C2=A0=C2=A0=C2=A0=C2=A0 void __init create_pgd_mapping(pgd_t *pgdp,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ui=
ntptr_t va, phys_addr_t pa,
 >> @@ -493,6 +582,57 @@ static __init pgprot_t pgprot_from_va(uintptr_t va=
)
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 #endif /* CONFIG_STRICT_KERNEL_RWX */
 >>=C2=A0=C2=A0 +#ifdef CONFIG_64BIT
 >> +static void __init disable_pgtable_l4(void)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 pgtable_l4_enabled =3D false;
 >> +=C2=A0=C2=A0=C2=A0 kernel_map.page_offset =3D PAGE_OFFSET_L3;
 >> +=C2=A0=C2=A0=C2=A0 satp_mode =3D SATP_MODE_39;
 >> +}
 >> +
 >> +/*
 >> + * There is a simple way to determine if 4-level is supported by the
 >> + * underlying hardware: establish 1:1 mapping in 4-level page table=20
mode
 >> + * then read SATP to see if the configuration was taken into account
 >> + * meaning sv48 is supported.
 >> + */
 >> +static __init void set_satp_mode(void)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 u64 identity_satp, hw_satp;
 >> +=C2=A0=C2=A0=C2=A0 uintptr_t set_satp_mode_pmd;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 set_satp_mode_pmd =3D ((unsigned long)set_satp_mode=
) & PMD_MASK;
 >> +=C2=A0=C2=A0=C2=A0 create_pgd_mapping(early_pg_dir,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 set_satp_mode_pmd, (uintptr_t)early_pud,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 PGDIR_SIZE, PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0 create_pud_mapping(early_pud,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 set_satp_mode_pmd, (uintptr_t)early_pmd,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 PUD_SIZE, PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0 /* Handle the case where set_satp_mode straddles 2 =
PMDs */
 >> +=C2=A0=C2=A0=C2=A0 create_pmd_mapping(early_pmd,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 set_satp_mode_pmd, set_satp_mode_pmd,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 PMD_SIZE, PAGE_KERNEL_EXEC);
 >> +=C2=A0=C2=A0=C2=A0 create_pmd_mapping(early_pmd,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 set_satp_mode_pmd + PMD_SIZE,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 set_satp_mode_pmd + PMD_SIZE,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 PMD_SIZE, PAGE_KERNEL_EXEC);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 identity_satp =3D PFN_DOWN((uintptr_t)&early_pg_dir=
) | satp_mode;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
 >> +=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, identity_satp);
 >> +=C2=A0=C2=A0=C2=A0 hw_satp =3D csr_swap(CSR_SATP, 0ULL);
 >> +=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
 >> +
 >> +=C2=A0=C2=A0=C2=A0 if (hw_satp !=3D identity_satp)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 disable_pgtable_l4();
 >> +
 >> +=C2=A0=C2=A0=C2=A0 memset(early_pg_dir, 0, PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0 memset(early_pud, 0, PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0 memset(early_pmd, 0, PAGE_SIZE);
 >> +}
 >> +#endif
 >> +
 >>=C2=A0=C2=A0 /*
 >>=C2=A0=C2=A0=C2=A0 * setup_vm() is called from head.S with MMU-off.
 >>=C2=A0=C2=A0=C2=A0 *
 >> @@ -557,10 +697,15 @@ static void __init=20
create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 uintptr_t pa =3D dtb_pa & ~(PMD_SIZ=
E - 1);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(earl=
y_pg_dir, DTB_EARLY_BASE_VA,
 >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_64BIT) ? (uintptr_t)early_dtb_pmd=20
: pa,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_64BIT) ? early_dtb_pgd_next : pa,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PGDIR_SIZE,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE=
_KERNEL);
 >>=C2=A0=C2=A0 +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pud_mapping(early_dt=
b_pud, DTB_EARLY_BASE_VA,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)early_dtb_pmd, PUD_SIZE,=
 PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_64BIT)) {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_=
mapping(early_dtb_pmd, DTB_EARLY_BASE_VA,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pa, PMD_SIZE, PAGE_K=
ERNEL);
 >> @@ -593,6 +738,8 @@ void pt_ops_set_early(void)
 >>=C2=A0=C2=A0 #ifndef __PAGETABLE_PMD_FOLDED
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pmd =3D alloc_pmd_earl=
y;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.get_pmd_virt =3D get_pmd_vir=
t_early;
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pud =3D alloc_pud_early;
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.get_pud_virt =3D get_pud_virt_early;
 >>=C2=A0=C2=A0 #endif
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 @@ -611,6 +758,8 @@ void pt_ops_set_fixmap(void)
 >>=C2=A0=C2=A0 #ifndef __PAGETABLE_PMD_FOLDED
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pmd =3D=20
kernel_mapping_pa_to_va((uintptr_t)alloc_pmd_fixmap);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.get_pmd_virt =3D=20
kernel_mapping_pa_to_va((uintptr_t)get_pmd_virt_fixmap);
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pud =3D=20
kernel_mapping_pa_to_va((uintptr_t)alloc_pud_fixmap);
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.get_pud_virt =3D=20
kernel_mapping_pa_to_va((uintptr_t)get_pud_virt_fixmap);
 >>=C2=A0=C2=A0 #endif
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 @@ -625,6 +774,8 @@ void pt_ops_set_late(void)
 >>=C2=A0=C2=A0 #ifndef __PAGETABLE_PMD_FOLDED
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pmd =3D alloc_pmd_late=
;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops.get_pmd_virt =3D get_pmd_vir=
t_late;
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.alloc_pud =3D alloc_pud_late;
 >> +=C2=A0=C2=A0=C2=A0 pt_ops.get_pud_virt =3D get_pud_virt_late;
 >>=C2=A0=C2=A0 #endif
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 @@ -633,6 +784,7 @@ asmlinkage void __init setup_vm(uintptr=
_t dtb_pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmd_t __maybe_unused fix_bmap_spmd,=
 fix_bmap_epmd;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.virt_addr =
=3D KERNEL_LINK_ADDR;
 >> +=C2=A0=C2=A0=C2=A0 kernel_map.page_offset =3D _AC(CONFIG_PAGE_OFFSET, =
UL);
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_XIP_KERNEL
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.xiprom =3D (uintptr_t)CO=
NFIG_XIP_PHYS_ADDR;
 >> @@ -647,6 +799,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.phys_addr =3D (uintptr_t=
)(&_start);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.size =3D (uintptr_t)(&_e=
nd) - kernel_map.phys_addr;
 >>=C2=A0=C2=A0 #endif
 >> +
 >> +#if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
 >> +=C2=A0=C2=A0=C2=A0 set_satp_mode();
 >> +#endif
 >> +
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.va_pa_offset =3D PAGE_OF=
FSET - kernel_map.phys_addr;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.va_kernel_pa_offset =3D =
kernel_map.virt_addr -=20
kernel_map.phys_addr;
 >>=C2=A0=C2=A0 @@ -676,15 +833,21 @@ asmlinkage void __init setup_vm(uintp=
tr_t=20
dtb_pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Setup early PGD for =
fixmap */
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(early_pg_dir, FI=
XADDR_START,
 >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifndef __PAGETABLE_PMD_FOLDED
 >> -=C2=A0=C2=A0=C2=A0 /* Setup fixmap PMD */
 >> +=C2=A0=C2=A0=C2=A0 /* Setup fixmap PUD and PMD */
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pud_mapping(fixmap_p=
ud, FIXADDR_START,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pmd, PUD_SIZE, PA=
GE_TABLE);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_mapping(fixmap_pmd, FIXA=
DDR_START,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE)=
;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Setup trampoline PGD and PMD */
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pgd_mapping(trampoline_pg_di=
r, kernel_map.virt_addr,
 >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
 >> +=C2=A0=C2=A0=C2=A0 if (pgtable_l4_enabled)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pud_mapping(trampoli=
ne_pud, kernel_map.virt_addr,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)trampoline_pmd, PUD_SIZE=
, PAGE_TABLE);
 >>=C2=A0=C2=A0 #ifdef CONFIG_XIP_KERNEL
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_pmd_mapping(trampoline_pmd, =
kernel_map.virt_addr,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kernel_map.xiprom, PMD_SIZE, PAGE_KERNEL_EXE=
C);
 >> @@ -712,7 +875,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Bootime fixmap only can han=
dle PMD_SIZE mapping. Thus,=20
boot-ioremap
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * range can not span multiple=
 pmds.
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
 >> -=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD=
_SHIFT)
 >> +=C2=A0=C2=A0=C2=A0 BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT=
)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 !=3D (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifndef __PAGETABLE_PMD_FOLDED
 >> @@ -783,9 +946,10 @@ static void __init setup_vm_final(void)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Clear fixmap PTE and PMD mapping=
s */
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PTE);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PMD);
 >> +=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PUD);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Move to swapper page=
 table */
 >> -=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg=
_dir)) |=20
SATP_MODE);
 >> +=C2=A0=C2=A0=C2=A0 csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg=
_dir)) |=20
satp_mode);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 local_flush_tlb_all();
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pt_ops_set_late();
 >> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
 >> index 1434a0225140..993f50571a3b 100644
 >> --- a/arch/riscv/mm/kasan_init.c
 >> +++ b/arch/riscv/mm/kasan_init.c
 >> @@ -11,7 +11,29 @@
 >>=C2=A0=C2=A0 #include <asm/fixmap.h>
 >>=C2=A0=C2=A0 #include <asm/pgalloc.h>
 >>=C2=A0=C2=A0 +/*
 >> + * Kasan shadow region must lie at a fixed address across sv39,=20
sv48 and sv57
 >> + * which is right before the kernel.
 >> + *
 >> + * For sv39, the region is aligned on PGDIR_SIZE so we only need to=20
populate
 >> + * the page global directory with kasan_early_shadow_pmd.
 >> + *
 >> + * For sv48 and sv57, the region is not aligned on PGDIR_SIZE so=20
the mapping
 >> + * must be divided as follows:
 >> + * - the first PGD entry, although incomplete, is populated with
 >> + *=C2=A0=C2=A0 kasan_early_shadow_pud/p4d
 >> + * - the PGD entries in the middle are populated with=20
kasan_early_shadow_pud/p4d
 >> + * - the last PGD entry is shared with the kernel mapping so=20
populated at the
 >> + *=C2=A0=C2=A0 lower levels pud/p4d
 >> + *
 >> + * In addition, when shallow populating a kasan region (for example=20
vmalloc),
 >> + * this region may also not be aligned on PGDIR size, so we must go=20
down to the
 >> + * pud level too.
 >> + */
 >> +
 >>=C2=A0=C2=A0 extern pgd_t early_pg_dir[PTRS_PER_PGD];
 >> +extern struct pt_alloc_ops _pt_ops __initdata;
 >> +#define pt_ops=C2=A0=C2=A0=C2=A0 _pt_ops
 >>=C2=A0=C2=A0=C2=A0=C2=A0 static void __init kasan_populate_pte(pmd_t *pm=
d, unsigned long=20
vaddr, unsigned long end)
 >>=C2=A0=C2=A0 {
 >> @@ -35,15 +57,19 @@ static void __init kasan_populate_pte(pmd_t=20
*pmd, unsigned long vaddr, unsigned
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(=
base_pte)), PAGE_TABLE));
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 -static void __init kasan_populate_pmd(pgd_t *pgd, unsigned=
 long=20
vaddr, unsigned long end)
 >> +static void __init kasan_populate_pmd(pud_t *pud, unsigned long=20
vaddr, unsigned long end)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t phys_addr;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmd_t *pmdp, *base_pmd;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
 >>=C2=A0=C2=A0 -=C2=A0=C2=A0=C2=A0 base_pmd =3D (pmd_t *)pgd_page_vaddr(*p=
gd);
 >> -=C2=A0=C2=A0=C2=A0 if (base_pmd =3D=3D lm_alias(kasan_early_shadow_pmd=
))
 >> +=C2=A0=C2=A0=C2=A0 if (pud_none(*pud)) {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 base_pmd =
=3D memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t),=20
PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0 } else {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 base_pmd =3D (pmd_t *)pud_p=
gtable(*pud);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (base_pmd =3D=3D lm_alia=
s(kasan_early_shadow_pmd))
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bas=
e_pmd =3D memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t),=20
PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pmdp =3D base_pmd + pmd=
_index(vaddr);
 >>=C2=A0=C2=A0 @@ -67,9 +93,72 @@ static void __init kasan_populate_pmd(pg=
d_t=20
*pgd, unsigned long vaddr, unsigned
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * it entirely, memblock could=
 allocate a page at a physical=20
address
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * where KASAN is not populate=
d yet and then we'd get a page=20
fault.
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
 >> -=C2=A0=C2=A0=C2=A0 set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pmd)), PAGE=
_TABLE));
 >> +=C2=A0=C2=A0=C2=A0 set_pud(pud, pfn_pud(PFN_DOWN(__pa(base_pmd)), PAGE=
_TABLE));
 >> +}
 >> +
 >> +static void __init kasan_populate_pud(pgd_t *pgd,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long vad=
dr, unsigned long end,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool early)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 phys_addr_t phys_addr;
 >> +=C2=A0=C2=A0=C2=A0 pud_t *pudp, *base_pud;
 >> +=C2=A0=C2=A0=C2=A0 unsigned long next;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 if (early) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * We can't use pgd_pa=
ge_vaddr here as it would return a linear
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * mapping address but=
 it is not mapped yet, but when=20
populating
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * early_pg_dir, we ne=
ed the physical address and when=20
populating
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * swapper_pg_dir, we =
need the kernel virtual address so use
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * pt_ops facility.
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 base_pud =3D pt_ops.get_pud=
_virt(pfn_to_phys(_pgd_pfn(*pgd)));
 >> +=C2=A0=C2=A0=C2=A0 } else {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 base_pud =3D (pud_t *)pgd_p=
age_vaddr(*pgd);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (base_pud =3D=3D lm_alia=
s(kasan_early_shadow_pud))
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bas=
e_pud =3D memblock_alloc(PTRS_PER_PUD * sizeof(pud_t),=20
PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0 }
 >> +
 >> +=C2=A0=C2=A0=C2=A0 pudp =3D base_pud + pud_index(vaddr);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 do {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pud_addr_end(vaddr=
, end);
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_none(*pudp) && IS_A=
LIGNED(vaddr, PUD_SIZE) && (next=20
- vaddr) >=3D PUD_SIZE) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if =
(early) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 phys_addr =3D __pa(((uintptr_t)kasan_early_shadow_pmd=
));
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 set_pud(pudp, pfn_pud(PFN_DOWN(phys_addr),=20
PAGE_TABLE));
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 continue;
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } e=
lse {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 phys_addr =3D memblock_phys_alloc(PUD_SIZE, PUD_SIZE)=
;
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 if (phys_addr) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pud(pudp, pfn_pud(PFN_DOW=
N(phys_addr),=20
PAGE_KERNEL));
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 continue;
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 }
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_pmd(pudp, va=
ddr, next);
 >> +=C2=A0=C2=A0=C2=A0 } while (pudp++, vaddr =3D next, vaddr !=3D end);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 /*
 >> +=C2=A0=C2=A0=C2=A0=C2=A0 * Wait for the whole PGD to be populated befo=
re setting the PGD in
 >> +=C2=A0=C2=A0=C2=A0=C2=A0 * the page table, otherwise, if we did set th=
e PGD before=20
populating
 >> +=C2=A0=C2=A0=C2=A0=C2=A0 * it entirely, memblock could allocate a page=
 at a physical=20
address
 >> +=C2=A0=C2=A0=C2=A0=C2=A0 * where KASAN is not populated yet and then w=
e'd get a page fault.
 >> +=C2=A0=C2=A0=C2=A0=C2=A0 */
 >> +=C2=A0=C2=A0=C2=A0 if (!early)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd, pfn_pgd(PFN_DO=
WN(__pa(base_pud)), PAGE_TABLE));
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 +#define kasan_early_shadow_pgd_next (pgtable_l4_enabled ?=
=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)kasan_early_shadow_pud : \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 (uintptr_t)kasan_early_shadow_pmd)
 >> +#define kasan_populate_pgd_next(pgdp, vaddr, next, early)=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (pgtable_l4_enabled ?=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kas=
an_populate_pud(pgdp, vaddr, next, early) :=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 \
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kas=
an_populate_pmd((pud_t *)pgdp, vaddr, next))
 >> +
 >>=C2=A0=C2=A0 static void __init kasan_populate_pgd(pgd_t *pgdp,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 un=
signed long vaddr, unsigned long end,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bo=
ol early)
 >> @@ -102,7 +191,7 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_=
pmd(pgdp, vaddr, next);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_pgd_next(pgd=
p, vaddr, next, early);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgdp++, vaddr =3D next, va=
ddr !=3D end);
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 @@ -157,18 +246,54 @@ static void __init kasan_populate(voi=
d=20
*start, void *end)
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memset(start, KASAN_SHADOW_INIT, en=
d - start);
 >>=C2=A0=C2=A0 }
 >>=C2=A0=C2=A0 +static void __init kasan_shallow_populate_pud(pgd_t *pgdp,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 unsigned long vaddr, unsigned long end,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 bool kasan_populate)
 >> +{
 >> +=C2=A0=C2=A0=C2=A0 unsigned long next;
 >> +=C2=A0=C2=A0=C2=A0 pud_t *pudp, *base_pud;
 >> +=C2=A0=C2=A0=C2=A0 pmd_t *base_pmd;
 >> +=C2=A0=C2=A0=C2=A0 bool is_kasan_pmd;
 >> +
 >> +=C2=A0=C2=A0=C2=A0 base_pud =3D (pud_t *)pgd_page_vaddr(*pgdp);
 >> +=C2=A0=C2=A0=C2=A0 pudp =3D base_pud + pud_index(vaddr);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 if (kasan_populate)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memcpy(base_pud, (void *)ka=
san_early_shadow_pgd_next,
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 sizeof(pud_t) * PTRS_PER_PUD);
 >> +
 >> +=C2=A0=C2=A0=C2=A0 do {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pud_addr_end(vaddr=
, end);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 is_kasan_pmd =3D (pud_pgtab=
le(*pudp) =3D=3D=20
lm_alias(kasan_early_shadow_pmd));
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_kasan_pmd) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bas=
e_pmd =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set=
_pud(pudp, pfn_pud(PFN_DOWN(__pa(base_pmd)),=20
PAGE_TABLE));
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 >> +=C2=A0=C2=A0=C2=A0 } while (pudp++, vaddr =3D next, vaddr !=3D end);
 >> +}
 >> +
 >>=C2=A0=C2=A0 static void __init kasan_shallow_populate_pgd(unsigned long=
 vaddr,=20
unsigned long end)
 >>=C2=A0=C2=A0 {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long next;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *p;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_t *pgd_k =3D pgd_offset_k(vaddr=
);
 >> +=C2=A0=C2=A0=C2=A0 bool is_kasan_pgd_next;
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 do {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pg=
d_addr_end(vaddr, end);
 >> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pgd_page_vaddr(*pgd_k) =
=3D=3D (unsigned=20
long)lm_alias(kasan_early_shadow_pmd)) {
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 is_kasan_pgd_next =3D (pgd_=
page_vaddr(*pgd_k) =3D=3D
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned=20
long)lm_alias(kasan_early_shadow_pgd_next));
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_kasan_pgd_next) {
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 p =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (IS_ALIGNED(vaddr, PGDIR=
_SIZE) && (next - vaddr) >=3D=20
PGDIR_SIZE)
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 con=
tinue;
 >> +
 >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate_pud(=
pgd_k, vaddr, next,=20
is_kasan_pgd_next);
 >>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } while (pgd_k++, vaddr =3D next, v=
addr !=3D end);
 >>=C2=A0=C2=A0 }
 >
 >
 > @Qinglin: I can deal with sv57 kasan population if needs be as it is=20
a bit tricky and I think it would save you quite some time :)

Thanks so much for you suggestion! And I want to give it a try firstly=20
as I am now making new Sv57 patchset :) I will ask for your help when I=20
meet any trouble, and thanks again!

Yours,
Qinglin

 >
 >
 >>=C2=A0=C2=A0 diff --git a/drivers/firmware/efi/libstub/efi-stub.c=20
b/drivers/firmware/efi/libstub/efi-stub.c
 >> index 26e69788f27a..b3db5d91ed38 100644
 >> --- a/drivers/firmware/efi/libstub/efi-stub.c
 >> +++ b/drivers/firmware/efi/libstub/efi-stub.c
 >> @@ -40,6 +40,8 @@
 >>=C2=A0=C2=A0=C2=A0=C2=A0 #ifdef CONFIG_ARM64
 >>=C2=A0=C2=A0 # define EFI_RT_VIRTUAL_LIMIT=C2=A0=C2=A0=C2=A0 DEFAULT_MAP=
_WINDOW_64
 >> +#elif defined(CONFIG_RISCV)
 >> +# define EFI_RT_VIRTUAL_LIMIT=C2=A0=C2=A0=C2=A0 TASK_SIZE_MIN
 >>=C2=A0=C2=A0 #else
 >>=C2=A0=C2=A0 # define EFI_RT_VIRTUAL_LIMIT=C2=A0=C2=A0=C2=A0 TASK_SIZE
 >>=C2=A0=C2=A0 #endif

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b3040494-a0b7-a9e8-1690-af395af3626c%40iscas.ac.cn.
