Return-Path: <kasan-dev+bncBCMIZB7QWENRBM4DZPWAKGQEYLBFBZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 79269C2C22
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 05:02:12 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id z14sf11084284ywz.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 20:02:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569898931; cv=pass;
        d=google.com; s=arc-20160816;
        b=dCVBQ9oxNnbFkb2YQAX8D1asJfsQlmwWZ2j0IeIDI0WwKI6k64XaP2b5yT7/41riKx
         82zev757OL95ugoAS4aDESdWq6J73J8qZ/MEc6Jh94bkAdpjhe7O+4bjfhLdWCrknf+n
         Me1hHmH5Bm2dMoXxw8ERGP7PRoxyvmZZ5P9JEfF7B867ru9yVOYzAvWm/X0dj7Ia8beu
         tHIroENEj3/v08dMYQC+2BsbJwWX0FP1yvIEgYqO8PgxfNUHybNrSBz+a90GYuRWoBXi
         nFy6HStQcvLR+Yr7mSB2DhiL99XhVxDWEbsBSf4cFlZHIgjNRIYad6/8S4oEcQvI4r+G
         h5Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YoCBiBWQ/uPJq5CMNZyDeITWkA9sJiTWjmhVlXpSpMs=;
        b=v/kKZRW532sI4IuASfeuSr+d1/gvKB9HqBsMLLalQJz9yBHC0WZlAc2W7zWjTvdP4y
         pKSiiJRFFBEuDYPwdkhb831wdC9HidoVw12IyZO5S+vuZb9pApNu2M5JyuRUXv0jlkOu
         DRkLU8s+/2BtnT5Osga+D9ac8FDh8Hh/1zjXIGu59tsuznfLqspuKvSkxWMoe6XzNzL5
         OQFyh1RKw/b74yQ43x3zfB3EjnnyfRVziCEQf7FnX6CYBeblBnf3ZDQEi2+Tyf96XxZb
         +VRgQCUzGCPJJERjpF/P+w6LOEoMipX6b7hXjYjXbQg3NEXsso4YKhidigX8aStA1q6V
         3SRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j8TZ3XWt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YoCBiBWQ/uPJq5CMNZyDeITWkA9sJiTWjmhVlXpSpMs=;
        b=YFLeZmLhE0wvbY2xTOxY25byHRGyGB1MtFeuA9hs1zBsXsAz1jWwYq5SX4lffivORP
         XHclcMtJsVLED9gRY/JI5y1LeAXI2bozOkXUYIPasta4gdCXZK4VmtpVFXzaxRMFOPui
         R6eQco3cO8FQ1I8HJJCFo6AvapB31+y7O3LLICeIyJDD5CD9vSo3yycojmrYTuglD/lB
         Q/Sf1CH8yDHcvJs9CAdu2fT/PA05pRW1VY9lgsLUG5m9LSYTJcrLaWNYWnRzeOpVzQjx
         U+NGp6AD7FZLSaXC+x/7tmStgCIQacmhho7yO06H+KI6y60HSu5h1NMowVT4FhyljbLx
         ig1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YoCBiBWQ/uPJq5CMNZyDeITWkA9sJiTWjmhVlXpSpMs=;
        b=KHU8eJZPNhO0tO7UTz6FoP8vJYOM3IFSv1Ex0FsSYgZqWsbnI3Bth1yeQJWYs88M20
         NkPlrv6I3c0kpPbkR99AWR7Lt3xqkDVcDa/mhoOTaUbNgyrWWvijmEe2DhVTd04F8tPl
         a28WvZfBPjfmpamzdVFt3yjQnQRR5bB+yoFIeRWRoKeLZaw2J+aI7BuQ8hl6w76ais6J
         RH8zt59RG74o5gk1UdQULQFx0HNRsIjn4i1bD7DOuGBm5pwLwZ8g4uVC8NCYV6GPBgO+
         +pq41a+txgv1JyLS7e4T2LqB3wkh1He8TqXptAn58OTgfdZYji9F7LGBK7kASvof7YTU
         bGVA==
X-Gm-Message-State: APjAAAXGkpAWK+FdUZMwSV5E0SmRAxjQmQBwqZv4UeekThCQltvgD8ac
	Lpvn5S3I6Lz0sVfK56J4z9Q=
X-Google-Smtp-Source: APXvYqx2n4Ts2zWNyt7i2XBOdNaGd6Q/OUyiSa1XyjLkzWfD/rAtbrf07pfnHcNuDgvDV7nh/10cwQ==
X-Received: by 2002:a81:431d:: with SMTP id q29mr14261226ywa.205.1569898931539;
        Mon, 30 Sep 2019 20:02:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8008:: with SMTP id m8ls2482233ybk.5.gmail; Mon, 30 Sep
 2019 20:02:11 -0700 (PDT)
X-Received: by 2002:a25:2e44:: with SMTP id b4mr18282295ybn.9.1569898931231;
        Mon, 30 Sep 2019 20:02:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569898931; cv=none;
        d=google.com; s=arc-20160816;
        b=NgIBOZS3eKMXDWxNnTl2Tm0teNkmmVRHpG6ov3dVeH424CHnLSd6Qhp28panlrYYMs
         3Ny7Vb5XcNVdPd95geXF1bGGK5afqKUnkdOb+ftKp2hulIvwdNcwgVI1Y+wV0X1nn8PA
         URCp51ENezn/8729dGpuN1WQdqyxbfXMLV4nIBm7xCSWsefAYzzNJUNUh4LmTrH0VCL8
         d9uvIBvKprgQ+ZLqvKKF7aw2rI1EKzifbIA3qdFdu8L4mLhJR7SvGUfDhZeDiaarFyLc
         quTbcPkHWPxU3lWNKuCmkOkiHEWwtKUu7XRednaBMSOiSM+7tW8LzQ7RVJJlrsLN0nB3
         NxxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NhU6yRd8rVi5W+b69famc3Wf+MRe5kZVRUYy3CZ04Qw=;
        b=sWcCkPHeNsZNhyNhFzIxk8dqHdbnl7kHXlYZOXpNczqR6Cd5pxN5e6vt/qLfdhJpBA
         ZRZokljNvw7Mol0aYVJZ2tMPURnEijUmWpeW2sIWrgox7Q1+QcFRb5kyK6RbRdly4xmx
         DHfRUZSebg/uCU5cScy4oIjuKeGpLOZ/tmYP+Dj/wJ8pdHL0moflUtvVafS/jzZfvC/b
         n0EONoYkHajbeJ630vmdRB4KU6LzE8NmbHOuHGNTepb4vzcd+pLAPcvfIyJjBZ6IR6Dt
         lCcnGQLKP3siY/GFTCoaCEfEvOxeX6RkvSd7gmGnMmGoVDG05fnU+p4o+8wpw0p+C7cE
         1shw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j8TZ3XWt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h83si946863ybg.3.2019.09.30.20.02.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 20:02:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id f16so9798745qkl.9
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 20:02:11 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr3460614qkn.407.1569898930461;
 Mon, 30 Sep 2019 20:02:10 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <a3a5e118-e6da-8d6d-5073-931653fa2808@free.fr>
 <1569897400.17361.27.camel@mtksdccf07>
In-Reply-To: <1569897400.17361.27.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Oct 2019 05:01:58 +0200
Message-ID: <CACT4Y+b3NPemYwJJsD_oC0vde5Ybz1qDNWb=cFu2HpOTMrGSnQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Marc Gonzalez <marc.w.gonzalez@free.fr>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j8TZ3XWt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Tue, Oct 1, 2019 at 4:36 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2019-09-30 at 10:57 +0200, Marc Gonzalez wrote:
> > On 30/09/2019 06:36, Walter Wu wrote:
> >
> > >  bool check_memory_region(unsigned long addr, size_t size, bool write,
> > >                                 unsigned long ret_ip)
> > >  {
> > > +       if (long(size) < 0) {
> > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > > +               return false;
> > > +       }
> > > +
> > >         return check_memory_region_inline(addr, size, write, ret_ip);
> > >  }
> >
> > Is it expected that memcpy/memmove may sometimes (incorrectly) be passed
> > a negative value? (It would indeed turn up as a "large" size_t)
> >
> > IMO, casting to long is suspicious.
> >
> > There seem to be some two implicit assumptions.
> >
> > 1) size >= ULONG_MAX/2 is invalid input
> > 2) casting a size >= ULONG_MAX/2 to long yields a negative value
> >
> > 1) seems reasonable because we can't copy more than half of memory to
> > the other half of memory. I suppose the constraint could be even tighter,
> > but it's not clear where to draw the line, especially when considering
> > 32b vs 64b arches.
> >
> > 2) is implementation-defined, and gcc works "as expected" (clang too
> > probably) https://gcc.gnu.org/onlinedocs/gcc/Integers-implementation.html
> >
> > A comment might be warranted to explain the rationale.
> > Regards.
>
> Thanks for your suggestion.
> Yes, It is passed a negative value issue in memcpy/memmove/memset.
> Our current idea should be assumption 1 and only consider 64b arch,
> because KASAN only supports 64b. In fact, we really can't use so much
> memory in 64b arch. so assumption 1 make sense.

Note there are arm KASAN patches floating around, so we should not
make assumptions about 64-bit arch.

But there seems to be a number of such casts already:

$ find -name "*.c" -exec egrep "\(long\).* < 0" {} \; -print
    } else if ((long) delta < 0) {
./kernel/time/timer.c
    if ((long)state < 0)
./drivers/thermal/thermal_sysfs.c
    if ((long)delay < 0)
./drivers/infiniband/core/addr.c
    if ((long)tmo < 0)
./drivers/net/wireless/st/cw1200/pm.c
    if (pos < 0 || (long) pos != pos || (ssize_t) count < 0)
./sound/core/info.c
        if ((long)hwrpb->sys_type < 0) {
./arch/alpha/kernel/setup.c
    if ((long)m->driver_data < 0)
./arch/x86/kernel/apic/apic.c
            if ((long) size < 0L)
    if ((long)addr < 0L) {
./arch/sparc/mm/init_64.c
    if ((long)lpid < 0)
./arch/powerpc/kvm/book3s_hv.c
            if ((long)regs->regs[insn.mm_i_format.rs] < 0)
            if ((long)regs->regs[insn.i_format.rs] < 0) {
            if ((long)regs->regs[insn.i_format.rs] < 0) {
./arch/mips/kernel/branch.c
            if ((long)arch->gprs[insn.i_format.rs] < 0)
            if ((long)arch->gprs[insn.i_format.rs] < 0)
./arch/mips/kvm/emulate.c
            if ((long)regs->regs[insn.i_format.rs] < 0)
./arch/mips/math-emu/cp1emu.c
        if ((int32_t)(long)prom_vec < 0) {
./arch/mips/sibyte/common/cfe.c
    if (msgsz > ns->msg_ctlmax || (long) msgsz < 0 || msqid < 0)
    if (msqid < 0 || (long) bufsz < 0)
./ipc/msg.c
    if ((long)x < 0)
./mm/page-writeback.c
    if ((long)(next - val) < 0) {
./mm/memcontrol.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb3NPemYwJJsD_oC0vde5Ybz1qDNWb%3DcFu2HpOTMrGSnQ%40mail.gmail.com.
