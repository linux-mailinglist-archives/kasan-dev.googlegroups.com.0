Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7VWKCQMGQEGGCHTPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 129EC38FD32
	for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 10:52:37 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id r3-20020a92cd830000b02901c085bc9f5esf19142728ilb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 01:52:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621932756; cv=pass;
        d=google.com; s=arc-20160816;
        b=q0btsHCWFx5kbNUrFlLLgLSPabXKP4E//qe3A88P4Nit4UbO5KI7ZWQ7A8Hx645INB
         yW19BJCYPFKizoOZd3xPg6p0kghaN4ZKGfeJ0XBJD1kOfUaplni35353fUEOF2XLDttb
         yOREgTKrI7b0s0Vx6klnrv8oSHVV4cRw0pijW9oA5vr6k/YOiEBYM6CAw9rz1HSILbXN
         f+c+c9QMwNPeos4uV03LRt6iyok9EeWqg4+gP0fIFKJFH5SZakZ6iQRsk995vNV+gz6R
         HOc1h9mRo96Q9UZOZASNLWYu2b3lokv5AYJ0SBKP8L7LHyjWEk9IeV+PNNHthfTLgotX
         ik0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vcUh88FKzY3qi/kNCxhttdXXo7ZBYKXK544CxAlWwi0=;
        b=JTnxc3FF2N3/B5JRNHmb9HoWmWBDxLqej+Wxi785Ts9w5tfMiQB4dTF+kdbiTU/Unl
         Uv5Kys9mGZr4eIi7zKBXxiLrIi+w7P4yV7pLkpWWTGgEkkwbMflv81OD+IT4C7k133D8
         /eTzniSLsvTvkq8rntNvLa0b+pSG+7p00S20cX+CuHHjiEFD+d+FA8bzNcrvRC+5SWzZ
         iUT97YefFfZkZZR5RHDSbMymJN/td7Qs8CaKUKXdR/vNuYa/01zoJn83ynh0Gr6k2xi4
         XoJENBNIg3IYu0B5rGMXcRCcdOgrFuKF3GoyGxSdyrlGyp/Gd/fgPutxK84Xr2IDaIi3
         c0+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DbQN+qgl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vcUh88FKzY3qi/kNCxhttdXXo7ZBYKXK544CxAlWwi0=;
        b=jSxLOawcXc1q04zHAHwGjclU8OmPJW1/YPAU/E8lbmfuISompPuye6gCa0e92NgH+K
         iIRiOwxHmj/k4wq1Vwi0DHecT3buiUEaErOi93ckJzo+PaydaJlxHcwv08XXrlaDF5ay
         MO3YOWV2ZIEIrlOZW0PyDyhxwYyq7hncGL9fBzKuq2dXYZGH3e65Kq4YfVnpAvQGeUEF
         Hdz6N2c0enrbOdzINVL6vDctjsQmB53ZSdIUhBq5TgjmTAw3dHCJ09q01gezEnoB8f5C
         Y3eDv3ktEKPfRpyQxffPpOsdu12ibdcTlIj+fDUGJgb3Qo2llLL6HrcgBOz40d0mFdJK
         hOhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vcUh88FKzY3qi/kNCxhttdXXo7ZBYKXK544CxAlWwi0=;
        b=BV46uFpksx3vgtdEDwbtwN5WcXqofUe4t0PSIpt4IQbNqhD7a9wBiDQkXORZa8Qh8A
         OpnBZXlw/M2mNvVXMorLXZg1YzwkLDhNhGebZ/BCUzIIHT4ypjydL2GDhMhX+zo4iInC
         XbJARcT66p1J2t+7tKF+wgSy6Ifs8pM82+ZJTuDyT9jj5C7z/IVqHM2VFx0/E7DWdBS+
         B+ChHnlVSdgpJHAlfXft7ZL494ehMREQYc7S4rRa4EBwIvFPT02SSu59OhKBzxtoADjr
         du1o4jjHK9noOpJPMhOJ/rJx1FsY2EmhIW3i9GEgsVZloAQ7EdqSJ483BAuG2/eJM+s8
         THFg==
X-Gm-Message-State: AOAM533dZVGD4VJbT2c07UPvU2mMclIqNz4xglKZgy2ZCYocvCU1SkHc
	2QpyTgjKEiQBWgMjv72AEVM=
X-Google-Smtp-Source: ABdhPJwUVOPUQ/vnKnaNUvYBUEQ7BGMhn7H7LLzrHv9HIF/cDuc/l7b4toUyXauhqdCmNM3CmfbOYg==
X-Received: by 2002:a05:6e02:216b:: with SMTP id s11mr11454623ilv.267.1621932755785;
        Tue, 25 May 2021 01:52:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2cd1:: with SMTP id j17ls2541599iow.8.gmail; Tue,
 25 May 2021 01:52:35 -0700 (PDT)
X-Received: by 2002:a5e:a912:: with SMTP id c18mr11818891iod.74.1621932755438;
        Tue, 25 May 2021 01:52:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621932755; cv=none;
        d=google.com; s=arc-20160816;
        b=rUxXUJwGe6ejgnqyRnxVaZJEt2gbC3Tzqm53copz71RoYk/aV9nV825MarLPrlxXnz
         BPNyq2J31msMjUHL+LIDRuc0MKI7rsrkLt0sOu7mOSFvZU5Z+fSnM/qA8Ddzx9w99nf3
         fVjXRpdhEaN9s1Pm6TdQUBcd1idiF6Esc2T3lBYfRviPYwxOeA0H7EUfkXoeijn585lj
         F4E5smQGoZOt99yHW5rJFSBC2bH/jrXRyXGHV1aODEtcqYsf40GIUw6PMcm/jwXHsbhK
         BYIcle41q8iUapwsFoAjnNlanBKVgILFu0UIKROBAhtMvo3yUJMO/WBV+YG4nqqqNcN8
         VUJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S983RmEN+zCzGygvTomJowV0VqiLAFWLutr88hzTzxw=;
        b=dHFcnRGQiuDz4oxg11DW7kVkNuHaBMONK22ahUHn3BdnG1e2G/co3nYKZVBhI/fA9b
         RUutXVEDb2eoZOnwiYnvRzDDui1EThJUEN5NYmsQ1vU9+yYytQ2xDm63mBhRD+ov4g+l
         z3LQOJtOLyXzrA5k5b2OFfajZC6vtk4HOeiM12OebfROXjK+DId7XxxukQdZjs8SGWp6
         qvpHkg5VG3E5lcwOjvGMw4y0Mm0H5Uwl5DfPcqRMd+dAp/lhaUf4vWPJK6RmdLfyXdPm
         RnZdZazm4ZwD4uxSp0lBOTTfEZXSW2NSDvMNrmmN1BEaebH/EpUeMqzzwqdsrO1+KJ0l
         2OcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DbQN+qgl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id p5si2846079ilm.4.2021.05.25.01.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 May 2021 01:52:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id h24-20020a9d64180000b029036edcf8f9a6so3606612otl.3
        for <kasan-dev@googlegroups.com>; Tue, 25 May 2021 01:52:35 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr23119899otu.251.1621932754928;
 Tue, 25 May 2021 01:52:34 -0700 (PDT)
MIME-Version: 1.0
References: <mhng-f2825fd1-15e0-403d-b972-d327494525e6@palmerdabbelt-glaptop> <0b584a85-79e2-fcdd-2adf-5b63f56cc591@huawei.com>
In-Reply-To: <0b584a85-79e2-fcdd-2adf-5b63f56cc591@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 May 2021 10:52:23 +0200
Message-ID: <CANpmjNPuhUVMdVYNMaQc1NARzp2w+A8A6F16L=WmzWpJOWz_sg@mail.gmail.com>
Subject: Re: [PATCH RFC v2] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DbQN+qgl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 24 May 2021 at 03:56, Liu Shixin <liushixin2@huawei.com> wrote:
> On 2021/5/23 10:38, Palmer Dabbelt wrote:
> > On Fri, 14 May 2021 08:20:10 PDT (-0700), elver@google.com wrote:
> >> On Fri, 14 May 2021 at 05:11, Liu Shixin <liushixin2@huawei.com> wrote=
:
> >>> Add architecture specific implementation details for KFENCE and enabl=
e
> >>> KFENCE for the riscv64 architecture. In particular, this implements t=
he
> >>> required interface in <asm/kfence.h>.
> >>>
> >>> KFENCE requires that attributes for pages from its memory pool can
> >>> individually be set. Therefore, force the kfence pool to be mapped at
> >>> page granularity.
> >>>
> >>> I tested this patch using the testcases in kfence_test.c and all pass=
ed.
> >>>
> >>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
> >>
> >> Acked-by: Marco Elver <elver@google.com>
> >>
> >>
> >>> ---
> >>> v1->v2: Change kmalloc() to pte_alloc_one_kernel() for allocating pte=
.
> >>>
> >>>  arch/riscv/Kconfig              |  1 +
> >>>  arch/riscv/include/asm/kfence.h | 51 +++++++++++++++++++++++++++++++=
++
> >>>  arch/riscv/mm/fault.c           | 11 ++++++-
> >>>  3 files changed, 62 insertions(+), 1 deletion(-)
> >>>  create mode 100644 arch/riscv/include/asm/kfence.h
> >>>
> >>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> >>> index c426e7d20907..000d8aba1030 100644
> >>> --- a/arch/riscv/Kconfig
> >>> +++ b/arch/riscv/Kconfig
> >>> @@ -64,6 +64,7 @@ config RISCV
> >>>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >>>         select HAVE_ARCH_KASAN if MMU && 64BIT
> >>>         select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
> >>> +       select HAVE_ARCH_KFENCE if MMU && 64BIT
> >>>         select HAVE_ARCH_KGDB
> >>>         select HAVE_ARCH_KGDB_QXFER_PKT
> >>>         select HAVE_ARCH_MMAP_RND_BITS if MMU
> >>> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm=
/kfence.h
> >>> new file mode 100644
> >>> index 000000000000..c25d67e0b8ba
> >>> --- /dev/null
> >>> +++ b/arch/riscv/include/asm/kfence.h
> >>> @@ -0,0 +1,51 @@
> >>> +/* SPDX-License-Identifier: GPL-2.0 */
> >>> +
> >>> +#ifndef _ASM_RISCV_KFENCE_H
> >>> +#define _ASM_RISCV_KFENCE_H
> >>> +
> >>> +#include <linux/kfence.h>
> >>> +#include <linux/pfn.h>
> >>> +#include <asm-generic/pgalloc.h>
> >>> +#include <asm/pgtable.h>
> >>> +
> >>> +static inline bool arch_kfence_init_pool(void)
> >>> +{
> >>> +       int i;
> >>> +       unsigned long addr;
> >>> +       pte_t *pte;
> >>> +       pmd_t *pmd;
> >>> +
> >>> +       for (addr =3D (unsigned long)__kfence_pool; is_kfence_address=
((void *)addr);
> >>> +            addr +=3D PAGE_SIZE) {
> >>> +               pte =3D virt_to_kpte(addr);
> >>> +               pmd =3D pmd_off_k(addr);
> >>> +
> >>> +               if (!pmd_leaf(*pmd) && pte_present(*pte))
> >>> +                       continue;
> >>> +
> >>> +               pte =3D pte_alloc_one_kernel(&init_mm);
> >>> +               for (i =3D 0; i < PTRS_PER_PTE; i++)
> >>> +                       set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr =
& PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
> >>> +
> >>> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE)=
);
> >>> +               flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> >>> +       }
> >>> +
> >>> +       return true;
> >>> +}
> >
> > I'm not fundamentally opposed to this, but the arm64 approach where pag=
es are split at runtime when they have mis-matched permissions seems cleane=
r to me.  I'm not sure why x86 is doing it during init, though, as IIUC set=
_memory_4k() will work for both.
> >
> > Upgrading our __set_memory() with the ability to split pages (like arm6=
4 has) seems generally useful, and would let us trivially implement the dyn=
amic version of this.  We'll probably end up with the ability to split page=
s anyway, so that would be the least code in the long run.
> >
> > If there's some reason to prefer statically allocating the pages I'm fi=
ne with this, though.
> >
> As I understand=EF=BC=8Cthe arm64 approach does not implement dynamic spl=
itting.
> If kfence is enabled in arch arm64, the linear map need to be forcibly ma=
pped
> at page granularity. But x86 does not have such constraints as it only sp=
lit pages
> in the kfence pool, so I think the x86 approach is better as it has less =
influence
> on the whole.

Correct.

I think either riscv gains set_memory_4k(), like x86, or we go with
the approach in this patch. Unless you see this is trivially
implementable, I wouldn't want to block this patch. It's better to
have something working, and then incrementally improve later if riscv
ever gets set_memory_4k().

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPuhUVMdVYNMaQc1NARzp2w%2BA8A6F16L%3DWmzWpJOWz_sg%40mail.gm=
ail.com.
