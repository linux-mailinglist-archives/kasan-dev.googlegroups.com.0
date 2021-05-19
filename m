Return-Path: <kasan-dev+bncBCJZXCHARQJRBEWZSWCQMGQE6IXRIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 14EF3389712
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 21:52:52 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id h23-20020a67c1970000b029022a88436f30sf34107vsj.11
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 12:52:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621453971; cv=pass;
        d=google.com; s=arc-20160816;
        b=yPF5LgLiITYE7b3FhMw/pQwDoBw8/1Mnh0NVHFDoTiEli2FkcncrC1pxu1VF5T1Ran
         QVk/XPnhPliCOOlzgf1D/sRbM/+m+ZXNJycuAS/Bdzefk3vy68vukaxtF2dHsHEDvvg+
         QJzIAeYOw0ROgtk/7Db5coa7xgbfsxk/mBaaHD1eJzetPBG9te8g+wp77W1DkFawLuyL
         DGhlVc6KgbHpByULjQqJ2SRsYADb+wWpd9iNs4gjXXDiEqb46TygFJX+n0VKLLrCfDs+
         Y3Km1lJEcCIJ4NUxbLSfoes/9GoxfjNguEeyhMSoVsTaqBsdvKH/RG+VTXS29mum+OG/
         G9wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vGhkceyR/OP+oMgTZzaU6nFHrTzMO8DHWVdRVWELX2s=;
        b=eu6KyLiUPnrxw256Kb0HpNEPZ4SDJabJYL60vAERb0oelIRzZUjFqtOpSICii0NvKg
         vWKRLZQt/YzPzYhAS8xPlC3K6nytCeJod2QfVOXDi97AGsoKa9QVKtN3Fi/wqkWpwYxj
         IMtxu3erk7UbF7LnX9nslKi178K5hwBoYt0mvBB9jH9nWz6OQKvnEhQncup5+iiy+e6M
         7jLWAnAIyIAYB2qFz0BDWvK1ZAg9Llvng6DYFv78ErdjqH0eDnuXTOplCRvVJtoyPyIv
         apCUlv54foYtjPumITmx7sSsUsxvwTW+N0XtZD5n14DVLck+VKGvfMCQcka467ltE6PN
         oMiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j02T5iH/";
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vGhkceyR/OP+oMgTZzaU6nFHrTzMO8DHWVdRVWELX2s=;
        b=XSOwnbgw8Ujvbz8gsxmPyC3QpFAgj48J6FVz/YJUPUrHfwTkEpyl6moAslQZ5CAe56
         Da4VtTeybkSBgeWmWs5HlLGBypvubkd9r3zurlXZdFnlkPmiRCIFuVUIFYxxQWAqvAcN
         I5NbisAZin19c5T/CkRnBHKhKvrXCGjn2puUW10oby9v7X4Xsy1ObOjIStCgJR5+5qWs
         S9yRi4YVA0txr6HDEQWMaQElso7adbmiGe/719MTmYD8a8NQlS1j/5pLjZKkSiMBI+T9
         59VSVxCdCG0+BbWvwBXA08+Muz0rsX87LzW84r8g3EYTRdopzA5+Tf5ee6nXHEu+JWpB
         eyfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vGhkceyR/OP+oMgTZzaU6nFHrTzMO8DHWVdRVWELX2s=;
        b=GCPKvozQPSp7O67jHof1/U+5pEyXWaxDpRQFuWFSNLN9xK4lotv9nNfgHwG+io9UYL
         e/cLThKTiyG8q+C0wItdHpiQNRmGi8hbuu9eJP5et9LIo/H6onVCVi1LvGL4t32GzVq3
         eyOTl2SseVIQiDsNn1EyKxnNFC3w0LPRzjmShaA8h2SiSd1PIrM2fjb3zAJCkhBO+l98
         dL+x2KAxbQ7eNAjP/IK8ySpz6TKxXSD48I8gdBYyvp2/TF/E+7vvdwv3QL/+CGvJLA27
         s9KUlaOLWmpt5Ik0mnHts9Hm1f9KnJxvU2orOXBnm2EEnupoSppURcH+D49om2zcjnXh
         lI7g==
X-Gm-Message-State: AOAM532lrFMN/+I3D0D56HAKZA1F09DxgKxfnaxZyyUCwvoqJTEsVmEW
	UfpQb5vme1PF6oIDADutNRU=
X-Google-Smtp-Source: ABdhPJyn4yRJzBhaPdwjZUgppv68mR1O3Ju3ZwVjIJC6ISvoAa9VQZKCQXX5UFJhc4WN40vAgrjxfw==
X-Received: by 2002:a9f:2c84:: with SMTP id w4mr1409285uaj.99.1621453971071;
        Wed, 19 May 2021 12:52:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:725a:: with SMTP id d26ls93025uap.5.gmail; Wed, 19 May
 2021 12:52:50 -0700 (PDT)
X-Received: by 2002:a9f:368f:: with SMTP id p15mr1476433uap.14.1621453970602;
        Wed, 19 May 2021 12:52:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621453970; cv=none;
        d=google.com; s=arc-20160816;
        b=Gp9oIlYwpRtNw57Xd5TilthnZYkyQmgujkEZjBkfVa9Eh4XEg3DIqHQ8YHM94B0DrG
         3rnOwjhGoxVhC8Elq250qkURQvHSlI8CWuDBIHrrl1mpO4hPFobvzwTXGonc+wYZ2OYW
         TeltG/KZVPkpBA4AyHPsqUTxCC7LRRdeG1bDbQ8ZeawXaAMibRter5WYTjfej9CuFg14
         DdTwsSfjqY+r8AxGZ+K0qzzb2dYL9W/dpYiHhaBmSn19fzOFwIs5m/NHMqvG/xjIsMG9
         idL/AXW3qSd3aU04MfwjOP0gase4IimEnxw1z81v3YI7U9j3b2DE5ORx9M5HUNk/fyIa
         F2wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SVSoUhFkNVU1wGDCrOEIUWeMZbbqgNel6ArZ5B6BHME=;
        b=CvwhMXqmIFQ+Ywruh3X3H0ZTYa+oZ1mbrP8ftkJViYEYwnEeeIL99/933BRIwkH8Xi
         mfW3WdtLNEGNrR3dX3o1BJn5XDhmryi81QNp65jNZeBzXNVh4w5XutgBV4od7NGziWF1
         90dixoRyjc8kxB1ntdy+UI60wYRe3bwLx0ABHaKOSgAmu/O4mcyTRHPV7yJFgBAx1lvy
         Oj2GMtjVKqtRgI80Wztd3zmUfzAYxq5gdLXg3eJm4ZLVLx3TP2Mhb2zzWnIJTiKqRpXc
         lRG6kS+LQ3FWCwwKuLfNaLlmcUUEhYhLt+ZN7YsYxA1J7zkYhHHP8Y+jWIXh0nTDzDvW
         8XnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j02T5iH/";
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id y4si43093vsl.1.2021.05.19.12.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 12:52:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id e18so5168759vsk.5
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 12:52:50 -0700 (PDT)
X-Received: by 2002:a05:6102:7d8:: with SMTP id y24mr935834vsg.2.1621453968723;
 Wed, 19 May 2021 12:52:48 -0700 (PDT)
MIME-Version: 1.0
References: <20210517235546.3038875-1-eugenis@google.com> <20210518174439.GA28491@arm.com>
 <CAMn1gO5TmJZ4M4EyQ60VMc2-acUZSYkaB9M0C9kOv_dXQe54Ug@mail.gmail.com> <20210519181225.GF21619@arm.com>
In-Reply-To: <20210519181225.GF21619@arm.com>
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 May 2021 12:52:36 -0700
Message-ID: <CAFKCwrjH1FEKqeQyKxXacQVk_034NCtsF+rAwTvb4jZwK7a+nA@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: speed up mte_set_mem_tag_range
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will@kernel.org>, 
	Steven Price <steven.price@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="j02T5iH/";       spf=pass
 (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::e34
 as permitted sender) smtp.mailfrom=eugenis@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

On Wed, May 19, 2021 at 11:13 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Tue, May 18, 2021 at 11:11:52AM -0700, Peter Collingbourne wrote:
> > On Tue, May 18, 2021 at 10:44 AM Catalin Marinas
> > <catalin.marinas@arm.com> wrote:
> > > If we want to get the best performance out of this, we should look at
> > > the memset implementation and do something similar. In principle it's
> > > not that far from a memzero, though depending on the microarchitecture
> > > it may behave slightly differently.
> >
> > For Scudo I compared our storeTags implementation linked above against
> > __mtag_tag_zero_region from the arm-optimized-routines repository
> > (which I think is basically an improved version of that memset
> > implementation rewritten to use STG and DC GZVA), and our
> > implementation performed better on the hardware that we have access
> > to.
>
> That's the advantage of having hardware early ;).
>
> > > Anyway, before that I wonder if we wrote all this in C + inline asm
> > > (three while loops or maybe two and some goto), what's the performance
> > > difference? It has the advantage of being easier to maintain even if we
> > > used some C macros to generate gva/gzva variants.
> >
> > I'm not sure I agree that it will be easier to maintain. Due to the
> > number of "unusual" instructions required here it seems more readable
> > to have the code in pure assembly than to require readers to switch
> > contexts between C and asm. If we did move it to inline asm then I
> > think it should basically be a large blob of asm like the Scudo code
> > that I linked.
>
> I was definitely not thinking of a big asm block, that's even less
> readable than separate .S file. It's more like adding dedicated macros
> for single STG or DC GVA uses and using them in while loops.

I've got a C version with 4 single-instruction asm blocks, and it
looks pretty nice. The assembly is almost identical to the hand
written variant, and performance is 3% better, presumably because of
the inlining. Also, the C version allows more potential optimizations,
like specialization on the value of "init" - which is not happening
right now because it is not constant in any of the callers.

I'll upload a v4 shortly.

>
> Anyway, let's see a better commented .S implementation first. Given that
> tagging is very sensitive to the performance of this function, we'd
> probably benefit from a (few percent I suspect) perf improvement with
> the hand-coded assembly.
>
> --
> Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFKCwrjH1FEKqeQyKxXacQVk_034NCtsF%2BrAwTvb4jZwK7a%2BnA%40mail.gmail.com.
