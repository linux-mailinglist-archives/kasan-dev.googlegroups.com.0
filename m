Return-Path: <kasan-dev+bncBD4NDKWHQYDRB2NMWKFAMGQEZMWUWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ED6E416194
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 16:59:54 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 1-20020a630e41000000b002528846c9f2sf4019054pgo.12
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 07:59:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632409193; cv=pass;
        d=google.com; s=arc-20160816;
        b=LLBY0FMezxPwJlrV/6YK5ZCkq3CfwI99bLHJBuhYtSje8iDssGMwjVunr6pr+lc3Nj
         a8iPEvQQOjr/EWElGKKEJQstRvZnBjKi7mJdBE3BUMFefgnPw187PJnkDVRa1wTwqcCl
         7X9H2Acve/jhrZ3A2WWc7hLlVoxoPHbu/JHb7a4zG29g0I6sTuSPu30llguR9usQ2g/a
         g+jW9Khc1UursPdceX9DJodwIGDQqeeQlJ5EBWmCx6lpRRbigtFFg7vKyNuHArahgRbe
         CKsOVDJDsqft4QiSbhtC4Ci4+t1cvdd5ARdCcw65OD/iy68r5p86qvAitnfxvv7INADs
         qEgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3Ox1wzJr5bX68NipzK0zjwaW10sQhI4rZPu7brVD1UY=;
        b=l7BQpC4rPV0AJZoi4z7jETOUFi11F3d7VnoHF1pDnefvEAZEzuuaksp6YAcWSMr+Wk
         k/aZmq6NdIYPlIHHHWk6hiYeO21UsZQvJYnaI05/nkdi3TSPz3sUaZsercrdtwRCESck
         /QV4/mIQHcfA6pEhdEYdNStzGqz9yupqGuJQyypuZRPb3C8NBBwg9OwllKcND5fKzDZi
         oQy0Qj2NuB55LreT8AFqvZOCTPuhQ9aPfewUX7As0I0kbMEjGeSTGleSG6BedOUUCFQ4
         v9FdjOSlyzDoFd6p1zggxEyRlA9TQPEl6Altl+z5kmLokLdDnBztpB5o2SeFM1IpKxic
         m1OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NHICIs3c;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Ox1wzJr5bX68NipzK0zjwaW10sQhI4rZPu7brVD1UY=;
        b=YSDPbXpU5F55gFGWfByDntn+kG9xDqHkSZuvlwaigNhgMOAlIcv/dBTIJH0lg7+4Sv
         fcAZp73DaJtIt1bD6F9qvBpot5MOE9coEId8rm0e/DCPg35AtYxFA7EBmmU9pELtbYf6
         c0EB1U/bU5TPP+sLuLe+25WiLugY3oXZTPYgNPilj/tb3iNwqYRDGlquHVd/k3Sh1n+4
         3ERl2MkaVn3V1Sq0f0AZvLfhUfW1h20XSR7C8EerkfE9g6jd2ze5R6Op4p+/3s3IzdRM
         ewUx9+F+tD2XUtqrcFYZe6D98PEXYpqq7LGcYd80kjCQ4OR2ktcFKXTfOpKs1RM9FIqd
         /2Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Ox1wzJr5bX68NipzK0zjwaW10sQhI4rZPu7brVD1UY=;
        b=6BgZ+isJkPZll/URsiRkxdhoTL7QL+R8tJ6taVmEMZzM6zrdY6HXZOaFNKpZOlAWvm
         B2DMxXi49rR2JPXoOTAn9vd97WQ5k6q0nHhiusknBOfettys9Zn4X60PsA8snTRT5zQi
         71w2bSA3z+qexQWedQQq3a6+GYFosCb2Pvb/NssuCM+L3hR0cFIeRlfpdDLRcFkwT8Pb
         F4yM0Lv8LPb4H3UPd5ed6r94MtfZ3phUxomZbrmKWkMjMrJdeR5e5zIM3y78r6tZkwJw
         F6gS9LHbXlXF+6G1QpTntstQtBjqxG84XVhp/C16pkTlZBljWcIfGmmiLe61E7H8JMrN
         PTiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532V/9Gtb/xWuTRHCDUVjv/6XHfFP1CEJk522zEVx2hfXiu0mV6X
	3/clE3j+BYeNXqAd/0HE1rs=
X-Google-Smtp-Source: ABdhPJwkUESNF2e8MEN/GkKJFukW2cQA0Y1IhE6OwnoLwMBL+HzMO00RO2yepmTbGLr2QwGCKdyCpw==
X-Received: by 2002:a63:aa06:: with SMTP id e6mr4666675pgf.66.1632409193232;
        Thu, 23 Sep 2021 07:59:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls2433913pgv.7.gmail; Thu, 23 Sep
 2021 07:59:52 -0700 (PDT)
X-Received: by 2002:a62:5a86:0:b0:445:4b23:9fe5 with SMTP id o128-20020a625a86000000b004454b239fe5mr4627234pfb.65.1632409192705;
        Thu, 23 Sep 2021 07:59:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632409192; cv=none;
        d=google.com; s=arc-20160816;
        b=g9IzBTcT+V1dIJ0k8PLND15US+t4kE/Q96znwOXXOB2pqKU08gXAhTQ0sxJXvhwDW4
         SxNhtv+8Wb+RnrWHO+jxD9ULt1qJLpN98twzvPnnKZLtFqAGPuAKEIou3IDzAQqr/OE5
         j0C2/rL0tr+6jw8tf3OPH7UpXr1HXVO36KGwFKilEn85LxRIfiGZ7kgoh3ZWP96udyjQ
         8VW0lQhN8Xzg9LnmRyjhAkPXr9lB9PJcdPLQxA2ZqVqN92azsMKh8twH7AccdXfX0SBj
         pbZF3TkUNNdD2Yz2vfiL3ciNrGW4+5wqzqBUQqQa4UkCzDruqZWUVRMj5t+MEf/pVTZn
         B1Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1Bm69zIOCyX2o9ZI+FreHVvqZswAGtnW++Y+vtuwEAo=;
        b=cnhUEk9i4TBd4lYU1RCUEa4UCLDwvtL13DDHYInHRvWDUQzvMvvHPZiBx8qQOXsqB5
         jRmZhna8Z3c5ZhB1lkkziL3PMHcLwT3BcoilZx7fzs7UwZ+IRCxbspZpYKJm8iQ6mgE+
         Z1nwg64RRdT9uO634fgqlXp29bBFfjeNtFa2FbZyekvK/v5E/N6MbMJddjgAKEsQhHww
         0hZ1y4eI/h9lLlcK7kGrqijZ5rX3KLM+lB2NsA13w82AFauh8/pFD7JOph9fMnZ9oC34
         BnozHZlDXoHF41RKbYTgtnT9XBW4UoacWV/QRU12pgqnmP9/ENTVt+8JK6rK4yYuWEkq
         y1fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NHICIs3c;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j12si341264pgk.2.2021.09.23.07.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 07:59:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7F03A60FC1;
	Thu, 23 Sep 2021 14:59:49 +0000 (UTC)
Date: Thu, 23 Sep 2021 07:59:46 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	linux-riscv <linux-riscv@lists.infradead.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, linux-mm@kvack.org
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
Message-ID: <YUyWYpDl2Dmegz0a@archlinux-ax161>
References: <20210922205525.570068-1-nathan@kernel.org>
 <CANpmjNNqgUSbiPHOpD8z5JAv2aiujxAMiO4siymYdU6zpid_2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNqgUSbiPHOpD8z5JAv2aiujxAMiO4siymYdU6zpid_2g@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NHICIs3c;       spf=pass
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

On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> wrote:
> > Currently, the asan-stack parameter is only passed along if
> > CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET to
> > be defined in Kconfig so that the value can be checked. In RISC-V's
> > case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means that
> > asan-stack does not get disabled with clang even when CONFIG_KASAN_STACK
> > is disabled, resulting in large stack warnings with allmodconfig:
> >
> > drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c:117:12:
> > error: stack frame size (14400) exceeds limit (2048) in function
> > 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> > static int lb035q02_connect(struct omap_dss_device *dssdev)
> >            ^
> > 1 error generated.
> >
> > Ensure that the value of CONFIG_KASAN_STACK is always passed along to
> > the compiler so that these warnings do not happen when
> > CONFIG_KASAN_STACK is disabled.
> >
> > Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> > References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 and earlier")
> > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> 
> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> [ Which tree are you planning to take it through? ]

Gah, I was intending for it to go through -mm, then I cc'd neither
Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
grab it from LKML?

> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
> comment (copied from arm64). Did RISC-V just forget to copy over the
> Kconfig option?

I do see it defined in that file as well but you are right that they did
not copy the Kconfig logic, even though it was present in the tree when
RISC-V KASAN was implemented. Perhaps they should so that they get
access to the other flags in the "else" branch?

> > ---
> >  scripts/Makefile.kasan | 3 ++-
> >  1 file changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index 801c415bac59..b9e94c5e7097 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -33,10 +33,11 @@ else
> >         CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
> >          $(call cc-param,asan-globals=1) \
> >          $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> > -        $(call cc-param,asan-stack=$(stack_enable)) \
> >          $(call cc-param,asan-instrument-allocas=1)
> >  endif
> >
> > +CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
> > +
> >  endif # CONFIG_KASAN_GENERIC
> >
> >  ifdef CONFIG_KASAN_SW_TAGS
> >
> > base-commit: 4057525736b159bd456732d11270af2cc49ec21f
> > --
> > 2.33.0.514.g99c99ed825
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUyWYpDl2Dmegz0a%40archlinux-ax161.
