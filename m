Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB2P3SCFAMGQEVMWD5PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 524CE40F2DD
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 09:04:10 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id b15-20020a05622a020f00b0029e28300d94sf86781362qtx.16
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 00:04:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631862249; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMsKooidPvPcI4tZlG5XlejlgjjY0P7jbvrjWOcJAwl5I7E59v/Z5UAdRL4ALFAfJg
         Vew5A6M5JCxFBxc+K/LVxiSLTabs2iFA0Wb14BRA0F2Is/+9ry5npojy+2pOyi+cRrHE
         +3GihYEyFvoZnG0e8hXXD8bqKg3RPU2hiPP7dxyvvCKS0PVR0sixShYE4bOIpAevPEjv
         GbmXmyUg++G9E5Xi3et65eWS8fHTDbuBwKFegmwF8xBl0S9E1LP346WyiWIYcoJIBB+b
         8RWdiZd+M/AKPrwwu6bek1j/ryCzYAjCe8ftn7A41O3brQiuMYfpMwGEoVwCxt8smGuA
         bQNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0nIox7HgsbJJZMFXToaT/OthAYGZNUHgTMZg/UJB2nk=;
        b=YiEwTT8x2yWcUv0JUbHwk3hhk1eit4t9LVA7KYHKv9uYAyxSc3phfgVkpBPgGsbRJn
         Oq0wR8lX7XR6CdCJVCrq6VgI+eQZcyaUzJrHY0J0zBTXAYgc6Bb8mrJdI7oyHz6dILm7
         AOiTfk5xNrQGkuNpkLmZJkVrtJMSP9PbBrGZrIKSfGKayDEZWf6RteZZfhJGSnjlS5QV
         dH+JpfjV177xiemLgHU2FMfJJdURmpDM0evlYUCGUg7jNGOUi82BigGhcosALAYcW5O4
         6mwyROEkR6oqd/cxm3rlYN6Bm3EJa0i9l/XWSILbCcldhlT/qz467A3VDtYWM/igzBlX
         aSsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=m83sWZky;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nIox7HgsbJJZMFXToaT/OthAYGZNUHgTMZg/UJB2nk=;
        b=hVnVryzlB/ITaHIc1gCsg18IkXbEgNSqdijElrQIgIWh2XqY54M3zBj38CvSaVtMAm
         u1JYtxYa9u2BoSoxH52zgovAhxnrtsSItfHSusO/UPu/bXnFBmRoWNQGsWfuidzAN94N
         mZU2fCS0QBteHhaJVEfnmVJONaYP7+f698L8Pi+gHdPCRpwLj3YNmQTMQGGfQbN0rSS9
         n9sIWcmu3kQvnLs2BoC60/FRHVwlD1g9Cqy/G9nKewb2MHa+X+W/qafcMdarWDqEgYsc
         smtawAt7CZgHl2ozmg58A+qlNoxNkU+gCwPbvdwjfF5bReyzNOop/mX+ViThfKU+XDFa
         Wrig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nIox7HgsbJJZMFXToaT/OthAYGZNUHgTMZg/UJB2nk=;
        b=C11i3NRzQ0ZOzdu7ZC0LLG1SWtffgk6kIPbtaIXN1xTdTtS5JEtMRanLQNzmFKlxTE
         Ww5X1Q4DZYFQDCf3Y+EBA5CrICbgogkmFHAR+qmECPN5f8OryHD3ufQGxcWRSvl1qX85
         t7M4FHuKpurCYKJlJEjTv0s72I/JjZx1qe+mOBxh5xpzi1bmJ/jHwaF5cMa13sJDUEWQ
         323/4kM8kTQGoJvlAY6TWwMPr6yhz6sFNzyU2k2XI+p2zLpLrcXNGEqMyt1zRvC6rPbc
         a4TqGgL56FFRcBELjSEQZZ1NAb/DU3kYrRQqxGm2n1HWetAwKl0KIvysi6z8FvYXxzF/
         odpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xUbS75VttuvZE3OvbuueSCPiGSGWlKxhM4ta6L1Fwfp2bM41V
	d+5J2FkWKXInG0a6Hl2CKcw=
X-Google-Smtp-Source: ABdhPJyNvPgYq9BwOSZcf/vQNqulVQ2aRFoEKpcarPf89+SIkZr0GhGlOIYJAQW5o2BqaP5O1V/CfA==
X-Received: by 2002:a05:620a:228c:: with SMTP id o12mr8861811qkh.367.1631862249314;
        Fri, 17 Sep 2021 00:04:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a9d3:: with SMTP id c19ls2320567qvb.5.gmail; Fri, 17 Sep
 2021 00:04:08 -0700 (PDT)
X-Received: by 2002:ad4:560b:: with SMTP id ca11mr9563160qvb.10.1631862248841;
        Fri, 17 Sep 2021 00:04:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631862248; cv=none;
        d=google.com; s=arc-20160816;
        b=ORQY3a9rNoNYQr0Xr0HnD0phaN8wIEnKIBdNsCCJ8D7rgHhSM69FkbgakvapRP+aDf
         BcVlMo1PHMKgEwmckNO7GDJIAnMfz0IeI55RuGxyR473JNlmoN/rTw4wUU/cFoNQwAAY
         QI91FT8EthUSmZJyUufcpPWVrvi+QnUKni6erZtCOWleU/b6H6MR5u09+ZF4UVe7VANe
         q6oCIZunPJgGL0Ekk721bKfrfegc/xX6CYKrZX7rHXVOLypkfjCcOCCBOVVkLmF/8bvr
         e7lV6CkRTb0UBURvoL6Cjzoqngwlgbk79OD154opdd5jZhxOMumPVDFUXWLYWtbrTqGx
         BzPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=CAgMLL/mS5tRa+YAdakaLdZrfmqf1huUSxYmkon5MLo=;
        b=oJHe06rN5TcCziZQBQ49HCLMfB3Zc72mQrggPmSRKAdyYkqLcN9TNNdl/d1rsTnNBK
         q7oxUxcser4a7rTKaaslgwxwexdTKN5v4kfMEjQ+eZnqKscKP3i4SWaB6YNB6ICsvAPw
         NqInJ5cPAvJ4nqv8Qe1mCR6FsMUg7daguJtdvNCaJRoqHzN9SLkg9QBvmgpEY+DvA9UZ
         79AA5d+KVXggP30hbr4ocrGI2945B56dpgrwlGa1N1B+lUJSWulnP8WB+RGUg4CEPSGU
         16J28V4I3iekWPL3x/62TsZ7AAoM5t+FsG4OBJdhCtY+tRrj9RlMXz7muFjZ0P5oWBnF
         sVbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=m83sWZky;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 11si925546qtu.5.2021.09.17.00.04.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Sep 2021 00:04:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2D7C760ED7;
	Fri, 17 Sep 2021 07:04:07 +0000 (UTC)
Date: Fri, 17 Sep 2021 09:04:04 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, catalin.marinas@arm.com, ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com, dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, elver@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 2/3] arm64: Support page mapping percpu first chunk
 allocator
Message-ID: <YUQ95HuATcgtOgsy@kroah.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-3-wangkefeng.wang@huawei.com>
 <YUQ0lvldA+wGpr0G@kroah.com>
 <9b2e89c4-a821-8657-0ffb-d822aa51936c@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9b2e89c4-a821-8657-0ffb-d822aa51936c@huawei.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=m83sWZky;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Sep 17, 2021 at 02:55:18PM +0800, Kefeng Wang wrote:
>=20
> On 2021/9/17 14:24, Greg KH wrote:
> > On Fri, Sep 10, 2021 at 01:33:53PM +0800, Kefeng Wang wrote:
> > > Percpu embedded first chunk allocator is the firstly option, but it
> > > could fails on ARM64, eg,
> > >    "percpu: max_distance=3D0x5fcfdc640000 too large for vmalloc space=
 0x781fefff0000"
> > >    "percpu: max_distance=3D0x600000540000 too large for vmalloc space=
 0x7dffb7ff0000"
> > >    "percpu: max_distance=3D0x5fff9adb0000 too large for vmalloc space=
 0x5dffb7ff0000"
> > > then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_=
get_vm_areas+0x488/0x838",
> > > even the system could not boot successfully.
> > >=20
> > > Let's implement page mapping percpu first chunk allocator as a fallba=
ck
> > > to the embedding allocator to increase the robustness of the system.
> > >=20
> > > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> > > Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> > > ---
> > >   arch/arm64/Kconfig       |  4 ++
> > >   drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++--=
---
> > >   2 files changed, 76 insertions(+), 10 deletions(-)
> > >=20
> > > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > > index 077f2ec4eeb2..04cfe1b4e98b 100644
> > > --- a/arch/arm64/Kconfig
> > > +++ b/arch/arm64/Kconfig
> > > @@ -1042,6 +1042,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
> > >   	def_bool y
> > >   	depends on NUMA
> > > +config NEED_PER_CPU_PAGE_FIRST_CHUNK
> > > +	def_bool y
> > > +	depends on NUMA
> > Why is this a config option at all?
>=20
> The config is introduced from
>=20
> commit 08fc45806103e59a37418e84719b878f9bb32540
> Author: Tejun Heo <tj@kernel.org>
> Date:=C2=A0=C2=A0 Fri Aug 14 15:00:49 2009 +0900
>=20
> =C2=A0=C2=A0=C2=A0 percpu: build first chunk allocators selectively
>=20
> =C2=A0=C2=A0=C2=A0 There's no need to build unused first chunk allocators=
 in. Define
> =C2=A0=C2=A0=C2=A0 CONFIG_NEED_PER_CPU_*_FIRST_CHUNK and let archs enable=
 them
> =C2=A0=C2=A0=C2=A0 selectively.
>=20
> For now, there are three ARCHs support both PER_CPU_EMBED_FIRST_CHUNK
>=20
> and PER_CPU_PAGE_FIRST_CHUNK.
>=20
> =C2=A0 arch/powerpc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
> =C2=A0 arch/sparc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
> =C2=A0 arch/x86/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
>=20
> and we have a cmdline to choose a alloctor.
>=20
> =C2=A0=C2=A0 percpu_alloc=3D=C2=A0=C2=A0 Select which percpu first chunk =
allocator to use.
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Currently supported values are "embed"=
 and "page".
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Archs may support subset or none of th=
e selections.
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 See comments in mm/percpu.c for detail=
s on each
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 allocator.=C2=A0 This parameter is pri=
marily for debugging
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 and performance comparison.
>=20
> embed percpu first chunk allocator is the first choice, but it could fail=
s
> due to some
>=20
> memory layout(it does occurs on ARM64 too.), so page mapping percpu first
> chunk
>=20
> allocator is as a fallback, that is what this patch does.
>=20
> >=20
> > > +
> > >   source "kernel/Kconfig.hz"
> > >   config ARCH_SPARSEMEM_ENABLE
> > > diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
> > > index 46c503486e96..995dca9f3254 100644
> > > --- a/drivers/base/arch_numa.c
> > > +++ b/drivers/base/arch_numa.c
> > > @@ -14,6 +14,7 @@
> > >   #include <linux/of.h>
> > >   #include <asm/sections.h>
> > > +#include <asm/pgalloc.h>
> > >   struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
> > >   EXPORT_SYMBOL(node_data);
> > > @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size=
_t size)
> > >   	memblock_free_early(__pa(ptr), size);
> > >   }
> > > +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> > Ick, no #ifdef in .c files if at all possible please.
>=20
> The drivers/base/arch_numa.c is shared by RISCV/ARM64, so I add this conf=
ig
> to
>=20
> no need to build this part on RISCV.

Ok, then you need to get reviews from the mm people as I know nothing
about this at all, sorry.  This file ended up in drivers/base/ for some
reason to make it easier for others to use cross-arches, not that it had
much to do with the driver core :(

thanks,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YUQ95HuATcgtOgsy%40kroah.com.
