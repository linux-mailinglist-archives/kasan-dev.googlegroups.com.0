Return-Path: <kasan-dev+bncBCU4TIPXUUFRBMMUQGHAMGQE62OB37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D07D47A6B6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 10:17:38 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id cf27-20020a056512281b00b004259e7fce67sf650063lfb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 01:17:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639991858; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPOLgVOL0cZ2+3+PGVEDvaDgk4RjisDZYo+IsnDQZac714Jenef8+msls9WrZOzwYE
         3PthlKXVZUnkhIN0vRG+nVL5tQkrGaIEFs//tJYXon/u5BMQYDF0e3EXBT5Tdqw76nbu
         6GWw+zV2mtgJ17i5SmTgnWnwlkvslsb0bVPUk63IZWIs3XNH6KQ7oqOYcUy2T7wYHqwd
         p5wdDADWpeKqPr0r/GaPQPps+FqHEKmtVac3c4ue1uj8G/Twh+n55rFAG9x27cp6eZjL
         DbIH/V42rom7YH3dfNThx3KFOVz8jPr30rYT48Y3J46fsPdHdBrEm5As7uWOG5hzRZd0
         dbTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=t4RElw3O/j+xJ7AGaHORKlxW7ckhtNzan+c6k+WecT8=;
        b=r9p6yzFRi/E5ZDLwStqOCqgs97RFyDknW/CP4/GgivODt9yVXjzDJXrGo2AJx9tpO6
         XMDQ/UI3DBP2vqJ6T2fnwHRzHkyovXINq4Mu+EbsGFb2tn83wvbSeu/bU3Zt65e7D6FS
         Msechp+T38I2KiQJ+3Zlhlpo8tLEzpSEYXLKdrI/3n3Z+hnsuZKBlbfk3X+C0gh1SO4N
         fL3lZupy47QsPtnOQIjtQ4qWpbXy6p/npsEDi64n1bC68gy1ZjsUGZa+GVHS1SPSiKl5
         p5nY4svm7hTV4jLwbnhDzawpceFNk9hTh6WkAW6TOWBMTSvdFBJDFQY89U2rj1k+9+6J
         lLOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RORZ8FOw;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4RElw3O/j+xJ7AGaHORKlxW7ckhtNzan+c6k+WecT8=;
        b=c2jn6IBT5F8svfPPt/mHkrBVSEo1yxs/9aYtIEVVXjMDssYhT+nkUg4xHLPIPpJwfF
         JxGbVfApgtqx9gjp2CBr5k1uGTPKtBtNC4LL22B5REJrElI1POf6Sxjzn02qIu6fnkVT
         7daTFIKx6pkvDY9XWYSZs7dRZ0t7DfWp3ZkS3gY38FNXbTmbKlHiacMlVmEQnQfJOGOC
         66QLMEfVPRA7/BAp5SKFRPh2p3VyFRIxYjmdEaQi+uf1rlUMy7DIOqK5c4Y9iReppqgv
         lKY9i/vhI+qOxjeiP8m5LsiPQWfFGt8nQiv6qE7594pyU2sbCwYLWvOVcS8b9lpTBdrW
         lo3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4RElw3O/j+xJ7AGaHORKlxW7ckhtNzan+c6k+WecT8=;
        b=eRnPK/TVucM7012P4Kh2SjOBJpJ/kDCm5f9od4RtBi4ixGK7RxPYLd2WvoSFYFOTvH
         6CGbvxc+0O3YrAK2T1GZyWUDqcL4ieH5Oi7kWZ1dL2jr6UJl7Rzoa+oexMAZw7W+UzG/
         JS3CThEHzqraZO4RjgOubJ57w5cuxKl7IUH/cJIfQ8BaUVlpjmtKMrmV1l5CxPxf2YdJ
         QFQFRO+eBTtw9s3wxacMSWuZ9TJsGzKtdnr0Y7sn99s+Y+VirwCB0SYklfjOp4UvSlOY
         nOmdVrsdhWP1kp2byOCkve7IuBo/rrdj5ucoJW2QhN/SIk4VmAdXkBY1BUeLL6NcZsPW
         BgxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327mk+HYviUr9tLDaD4VAuQ7c53MFDrKhV+Hqqx0/Qm9pl3RHBj
	agAZjeo5aUpGn4UB21Wij8A=
X-Google-Smtp-Source: ABdhPJz2j7/CtHoTVbmnwqWt3JkT0hvvb7ducY3OcvNoLnkv3SNn10bcsjMBzjZ5rN4TSdrGoV55Fg==
X-Received: by 2002:a05:6512:2305:: with SMTP id o5mr14965093lfu.294.1639991857778;
        Mon, 20 Dec 2021 01:17:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a222:: with SMTP id i2ls2368307ljm.9.gmail; Mon, 20 Dec
 2021 01:17:36 -0800 (PST)
X-Received: by 2002:a2e:a4aa:: with SMTP id g10mr13787946ljm.529.1639991856649;
        Mon, 20 Dec 2021 01:17:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639991856; cv=none;
        d=google.com; s=arc-20160816;
        b=VHskeDwVZjDyq1R1CRQh9Ei+0eLf7EilR1qrY4OirhDthoaB0T6M+afYHrgWfueWLP
         RE6as0BqUgASAc9JBYxA4YlDgAhYEBJmI40ULSrFNtk3A2wqjMGZ12RH+cbqmT1ex8TA
         aIsJIC/n7Yw7EizSPSKZP1NoM/ZUhn9jMJeFp3M3tGHY7YuN1kfBStVghiccaXci6sOI
         2sr+Ve+CSaR05CyReQeKcpE0WRc5A8TcwL0NNAwKtIpeFeT7E5AKXJE2sUsiOR8r/b/l
         98cr9AtR7MKxeY616JjCTdAB8CILUKC1G0h9WsVkr3kCY3OToK29JtK1CiM4G9XpjKUW
         i5dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PURodPzHaRYVBlGs2ZC+2E85Ok/SFvSvhHTOhnrmT58=;
        b=Ku4VqPOnP5Kq1yEcdHIofunY3O5psCEGKxekM1I4WcvTn9FZlgH+Aq6f9sbPwaYAki
         K1/42FVClKtbhmFqp4axAEHTmxcIhEqy4BSJSqC6O6qxmHisyssy60kngeauvupZ87ee
         PlhLkz+God63svN2VTVLsYP2gzZ/sot7yxd4GenBFfKxhi+tr4ke+a0qRHvIroxanmIm
         w1STDwNTTn4Uo4vC3oT9FTigx8yZ15uu7NIoci4Hu76UtI+pKCbe6xI2JOICs/B15+aC
         TlA8yjeLmr4DdXFc56/wfw/u4EiCInuK4laWHi62h4aCwQvxvc8gXSbN3/K7YzGK953e
         hfKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RORZ8FOw;
       spf=pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d34si230380lfv.13.2021.12.20.01.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Dec 2021 01:17:36 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E702360F57
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:17:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96A23C36AF6
	for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 09:17:33 +0000 (UTC)
Received: by mail-wm1-f45.google.com with SMTP id p27-20020a05600c1d9b00b0033bf8532855so6185001wms.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 01:17:33 -0800 (PST)
X-Received: by 2002:a1c:1f93:: with SMTP id f141mr4145000wmf.56.1639991851853;
 Mon, 20 Dec 2021 01:17:31 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-13-alexandre.ghiti@canonical.com> <CAJF2gTQEHv1dVzv=JNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ@mail.gmail.com>
In-Reply-To: <CAJF2gTQEHv1dVzv=JNCYSzD8oh6UxYOFRTdBOp-FFeeeOhSJrQ@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 20 Dec 2021 10:17:20 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHmdDKFozkoAfM-mxsxxfanhVq5HcA1qKTrkp=vAt=Umg@mail.gmail.com>
Message-ID: <CAMj1kXHmdDKFozkoAfM-mxsxxfanhVq5HcA1qKTrkp=vAt=Umg@mail.gmail.com>
Subject: Re: [PATCH v3 12/13] riscv: Initialize thread pointer before calling
 C functions
To: Guo Ren <guoren@kernel.org>
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>, Jonathan Corbet <corbet@lwn.net>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@rivosinc.com>, 
	Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, 
	Guo Ren <guoren@linux.alibaba.com>, 
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, 
	Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, linux-riscv <linux-riscv@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-efi <linux-efi@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RORZ8FOw;       spf=pass
 (google.com: domain of ardb@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE
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

On Mon, 20 Dec 2021 at 10:11, Guo Ren <guoren@kernel.org> wrote:
>
> On Tue, Dec 7, 2021 at 11:55 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > Because of the stack canary feature that reads from the current task
> > structure the stack canary value, the thread pointer register "tp" must
> > be set before calling any C function from head.S: by chance, setup_vm
> Shall we disable -fstack-protector for setup_vm() with __attribute__?

Don't use __attribute__((optimize())) for that: it is known to be
broken, and documented as debug purposes only in the GCC info pages:

https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html




> Actually, we've already init tp later.
>
> > and all the functions that it calls does not seem to be part of the
> > functions where the canary check is done, but in the following commits,
> > some functions will.
> >
> > Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > ---
> >  arch/riscv/kernel/head.S | 1 +
> >  1 file changed, 1 insertion(+)
> >
> > diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> > index c3c0ed559770..86f7ee3d210d 100644
> > --- a/arch/riscv/kernel/head.S
> > +++ b/arch/riscv/kernel/head.S
> > @@ -302,6 +302,7 @@ clear_bss_done:
> >         REG_S a0, (a2)
> >
> >         /* Initialize page tables and relocate to virtual addresses */
> > +       la tp, init_task
> >         la sp, init_thread_union + THREAD_SIZE
> >         XIP_FIXUP_OFFSET sp
> >  #ifdef CONFIG_BUILTIN_DTB
> > --
> > 2.32.0
> >
>
>
> --
> Best Regards
>  Guo Ren
>
> ML: https://lore.kernel.org/linux-csky/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHmdDKFozkoAfM-mxsxxfanhVq5HcA1qKTrkp%3DvAt%3DUmg%40mail.gmail.com.
