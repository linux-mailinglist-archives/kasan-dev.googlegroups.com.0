Return-Path: <kasan-dev+bncBD4NDKWHQYDRB66BUGFQMGQEDGWMP2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9F4142DFBE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 18:55:24 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id c19-20020ac81e93000000b002a71180fd3dsf4970575qtm.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 09:55:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634230523; cv=pass;
        d=google.com; s=arc-20160816;
        b=ob4mZPUizagcBgfn7U7e7fhJKmgGLV7HXi7F0ui7GTLVZYHj6vawjL6IzQ6qqZhEHU
         yXmBW6XBGSNRxxSel9DFMhSL8zuGlo791Y+rqZQeO2zJeOnbgi5rcgLmQ2C4kdI0zZKP
         ehaYvPxgg0rPa/Q9x5mAuM+8zWUpTXZF82TuRPCePffMFhOHTnW/+K+AMeEEN3suTGDP
         0y4F6dQHcn4lRyb5boxPk9hDgfLlR0g8cl91S03gSgfl5spFqo5F9QnA6K6PgANLTDg2
         VeAjgdim9okbJ86R9TLp7PcIYVkSMkxvI12HH+82+gH4TwAwMtEHx0/mcY0WJAO3yzn/
         Z/aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=VQlDB0wlRBidaqSQAtbSF76QDJcT70wjP4I7NGUMFiU=;
        b=WwGnfIdhItNWEmRa8+Y3YJd+RXfupQJt8Jge9mj5fGh6Dof4KBzdJB8fCypLtakDKC
         KMJqk/ovXOuxSCMt6v6EQ8nOn2huKuCJ+XTW2XVLOqgQpTCEX6xwitgXKQmIaxDH5uTp
         B2mCV8BYZrYR5l8a0XWMrkOp0juA1rUXq4O1MED1ztjcsM0mQBeYpNQ9VXKTHw82tIda
         Y7MS73DPJpPE+KKNWEcBzQmUogpU5FBbyzTdELAzoSiVZdmtL2eua7OCuo6LcrxiSP1o
         UHEQT+0Es6ZU9lgLPkO+5i+73f5kyq06/bIX09ogeON4YgAFAm6AgVLm/rSv+tFuFQOn
         yRIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=URMDQCzg;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VQlDB0wlRBidaqSQAtbSF76QDJcT70wjP4I7NGUMFiU=;
        b=tYcpNtfrUAET9GwNDQO6abdU/6Me2QZzXuaEmmMrMaR4k8U2VAnGbxSrVdq7KC6toj
         Slw2zwKa1Jd0xmqC87fHKq3mLkuaDcSNFVs1yKN1m5/1LB12gG9MutuS6vLzbe2ogsDh
         UrUJqXPHwGDAVPZ5ZToTWdAsYHZR45/Pjlo36coyy3cpNxY7FJIQbXkmmApnnk/dzMEI
         BmgBKkq0Q624xXALdY3HdvfP1Zjgki843SYLehfKw9x1pr5fewFyqyv3kXwOfyZlRamv
         o7ocUz4Uryy6swUIFQtEhpnYtaaDRTz6FipnMN2Mvkn4yTPaDYUGjX9dkpZHvZm9R79Z
         G8qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VQlDB0wlRBidaqSQAtbSF76QDJcT70wjP4I7NGUMFiU=;
        b=YqBbztaoOJnKjMd4Odj9dNtQJrMgLmD+Pvyu8x0tu66jhCOmEfqwoFU9uqZtVlbOr4
         T7GwDQXzcPhTj6LAGY1d+qJjiWDR++I4ogb9kNtDrBHkoWt+e0PMcypt/EQ9UUt5UFFc
         Pc/KVn9WQkdhJpX6nBtpCDwjcYUJBcet5ZSwu8O8fKp3PUEbHHTKAdxFdCuFc3qE9/TD
         /6GoWpB7Mss+mbojzbFuAXYw7jKTOyMTPR7PFejwWpUuzW6sPaaFR4Vze0qkZNu8H+S4
         uY4rc8xc0H5tjouxwwl32KjbD6rmPRLSap00qjXs/EfFBC33IFwS+rUANoO7NizW0TrL
         fn3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531A4zz2+qydzFbSB37W+nPW7/GQEX6tN8XV119O8WPFRwwKhEo4
	5xtucGY4Ea6Ozcx0FyB4dGQ=
X-Google-Smtp-Source: ABdhPJypoaSdLCnu7Of95TrLkbLxK7LYDn+/rxFw9sgNR2holWPWN9bm5eEXfGhFV9yHJQ+i3d5CAg==
X-Received: by 2002:a0c:b412:: with SMTP id u18mr6683482qve.14.1634230523529;
        Thu, 14 Oct 2021 09:55:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ef45:: with SMTP id d66ls3445036qkg.5.gmail; Thu, 14 Oct
 2021 09:55:23 -0700 (PDT)
X-Received: by 2002:a05:620a:31a2:: with SMTP id bi34mr5769032qkb.331.1634230522931;
        Thu, 14 Oct 2021 09:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634230522; cv=none;
        d=google.com; s=arc-20160816;
        b=q04Q3F/4EBgGx3yOwOjxfPymiD11UPMwXN7cTRnDbt4xz7psbTC0tY+OIUdqnQeh+T
         78W8bLLM94DU6aQC228Nsj0lSrzSfNu5seivs9mH+5ZSUNGKfwSuLkefntsWov1zpazt
         lf8tDJhsUMHQMWki9YRvjxbQ9kbFHsXPPcGZhfvxtctRUehw6LBLianlg8Zj6GkRv7Ma
         0DipkVel69xxuE04BDNWXD9owSU9Z+IHXejwI+WupQe+7UBoG+dHOxrtlTaA82qFuKET
         O47242Bmy6BIhro2uH4+/i6oke1OHNop3bxP7q0SHJcNbCc2uCsHCGtaCDw8rU270Jsr
         Z6ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=kfnjzImLxwA49HPu8KOqjvVjbB6jAaFVPu+h2ZxRhXY=;
        b=At5P2qbjBTkAE/FZJtF0/WvKCNEp9IDyOFqzsCidi4aD+wagfZex7DgC4ka8M6KDfT
         6FFxQ+d1+f0a1SJVmuCpvnxbR56mf4eztKvrLXCTk62YHJhdhcUD1oxbRtAdwi42IOx+
         LMT7ByjEv5PufSsNcqY4V4BF7TuYR6duGRRT7DEPswRs8d0L4TrbyZnjIsnaW6e4mNIP
         KE/Zzq7tO0/Zm1FPp3U/X1DKwZI61hfXNG2jp1p+VWRZRerh9wjhH4zLM3qVa4qG7BwN
         uxAgDIdF+q+Acgia4IrpA3v5Lox6Stg2YWzbja+4EmFHLywyQhvbe8KgrgV0hWFcxRwI
         lzeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=URMDQCzg;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s15si292314qkp.3.2021.10.14.09.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Oct 2021 09:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2DB9D6101D;
	Thu, 14 Oct 2021 16:55:19 +0000 (UTC)
Date: Thu, 14 Oct 2021 09:55:15 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: elver@google.com, akpm@linux-foundation.org, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	ndesaulniers@google.com, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-riscv@lists.infradead.org,
	Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	linux-mm@kvack.org
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
Message-ID: <YWhg8/UzjJsB51Gd@archlinux-ax161>
References: <YUyWYpDl2Dmegz0a@archlinux-ax161>
 <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=URMDQCzg;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
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

On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
> > On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
> > > On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> =
wrote:
> > > > Currently, the asan-stack parameter is only passed along if
> > > > CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSE=
T to
> > > > be defined in Kconfig so that the value can be checked. In RISC-V's
> > > > case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means th=
at
> > > > asan-stack does not get disabled with clang even when CONFIG_KASAN_=
STACK
> > > > is disabled, resulting in large stack warnings with allmodconfig:
> > > >
> > > > drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.=
c:117:12:
> > > > error: stack frame size (14400) exceeds limit (2048) in function
> > > > 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> > > > static int lb035q02_connect(struct omap_dss_device *dssdev)
> > > >            ^
> > > > 1 error generated.
> > > >
> > > > Ensure that the value of CONFIG_KASAN_STACK is always passed along =
to
> > > > the compiler so that these warnings do not happen when
> > > > CONFIG_KASAN_STACK is disabled.
> > > >
> > > > Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> > > > References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 a=
nd earlier")
> > > > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > >=20
> > > Reviewed-by: Marco Elver <elver@google.com>
> >=20
> > Thanks!
> >=20
> > > [ Which tree are you planning to take it through? ]
> >=20
> > Gah, I was intending for it to go through -mm, then I cc'd neither
> > Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
> > grab it from LKML?
>=20
> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
>=20
> (assuming you still want it through somewhere else)

Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
respect CONFIG_KASAN_STACK").

> > > Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
> > > comment (copied from arm64). Did RISC-V just forget to copy over the
> > > Kconfig option?
> >=20
> > I do see it defined in that file as well but you are right that they di=
d
> > not copy the Kconfig logic, even though it was present in the tree when
> > RISC-V KASAN was implemented. Perhaps they should so that they get
> > access to the other flags in the "else" branch?
>=20
> Ya, looks like we just screwed this up.  I'm seeing some warnings like
>=20
>    cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 with stack=
 protection is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=
=99 for this target

Hmmm, I thought I did a GCC build with this change but I must not have
:/=20

> which is how I ended up here, I'm assuming that's what you're talking abo=
ut
> here?  LMK if you were planning on sending along a fix or if you want me =
to
> go figure it out.

I took a look at moving the logic into Kconfig like arm64 before sending
this change and I did not really understand it well enough to do so. I
think it would be best if you were able to do that so that nothing gets
messed up.

Cheers,
Nathan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YWhg8/UzjJsB51Gd%40archlinux-ax161.
