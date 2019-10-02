Return-Path: <kasan-dev+bncBCD3PVFVQENBBYWXZ7WAKGQE5FSD45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id EDD0CC44CF
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 02:14:27 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id w13sf12261422pge.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 17:14:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569975266; cv=pass;
        d=google.com; s=arc-20160816;
        b=kC9mJAF50Y4wJoUre5wzSRPwmChq970G1FPatBjXykx2lY0/MyF7G12nH1HCVyZfYm
         reChuSL2sPlq6EUrFanG+Eyau+0ABV96Jx4YwUoDkKG1TUzI0ZbLz0w1JHG+F55iFh6U
         BOPdwCUSSfFCGJpPp6duTqs6Guc71VzArcZENccov5EfTMaCpmHV1S7AJosGu1bif/uw
         wfGstaJsdHQ8OyWMqDlsn1aPjdXSw97w69KNkxhM/PN58LrhsgislGKNv7NWmrkJGCzR
         /bH6eP45JZ/tieFbpFPXUVW4Vk/emMmCPSRdKnWko4NdnX6Q2wOkKtyqCwTnOgGSi3mC
         Rm/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kQw+Yj4m89r8nJ39V+Ct1F6LFh9+OWfvBQ8qnYzkptM=;
        b=CB4vhWcpNTMK7kmBKXA06u1JIYt8S/A3WztQaI/GaAF3+gRr4+fpZvD+KzYVPQkNo6
         T0y46eJUkHUYPQG9GxWDoncfOvnOF05J4BCO7kFaUzJj2nNp4B0Q8PfaCvTxrQh2+z6f
         cyafJci/AV7pi6oaOtsaj9VmXljXbInA067TVq6NbCCQYQ0vUF6cbKHOMZiGtQVOvpuM
         nWlgq0bptURYn1amel/2Aks7zSZvU2NOhdyeBZjMgK8fxEwLEymjsKhYIxUwoKnVPtkm
         w8Z1RVXR3dQciWYF8ixsI4WhCymkO9+jAMnucpPgM+l77gySJmwZ5OBLw76cbyYz7kFi
         Xy+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nJtPZChL;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kQw+Yj4m89r8nJ39V+Ct1F6LFh9+OWfvBQ8qnYzkptM=;
        b=W0tlCGVlgyDLtPQcQi9q424Sr7g2v5tphrIK5BGug8JnqIN8XFpdxx1i0f8aqVbVpz
         R8ktjizuuhCsuz+QhHQlPSx/yV3y6NKzeStPGPOiSyf0dOXybtvOaDIaEUbzV6i5X8Jc
         +FJworrnKQ+DCBrLsl5UcI1YXeqN1qsKv/bK9XWNAknWPfy79srYbEGD+4sIlU1OSBMt
         9rfxLP0sPJXe4L3uljhurNoV4Iv4D1+mCR/sOycLOy5gh5NCy7EZIFb3LtmZNYzKbj7W
         3+Qg4vmAQH24GnXIR0nOdgiGWk6z9cjhE7fSUBGMZL/0Iw3Idp0A+SgwGuNCz6iIdoVL
         fcTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kQw+Yj4m89r8nJ39V+Ct1F6LFh9+OWfvBQ8qnYzkptM=;
        b=TEeSUYF2DN7eSyduaafETI1gWddRH6bo9NNUMnA4AWywBXOxjEqT5Q4Cdkn2+4ydKj
         I4Iz8bEbcLZhmNsDTKAlEP3Z3nNMDtcy3/hKHA3AC6J5FPPNjoq4UV1R1tRj6UgAKafd
         h4mTRMFzrj5Xnuxpw16uEn8HByJDDG1Idar6Tfv2FiahiPkiLByMvvM0CL11JwS0iJyT
         c1ResRPA3HKR41k3IbrDItacrkbWzA1XkuefdrzswvmpNPDEL5BrWFeHSDbb+OhsBHpg
         3xB4SfGAgcvQVOg0YyQ8hx6JoK3rXbTENgXgGiXJVjEi2YGLuFLef1t5+TomS2FZR8cx
         zDww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kQw+Yj4m89r8nJ39V+Ct1F6LFh9+OWfvBQ8qnYzkptM=;
        b=lWbz2dDOYobgQJ6ti6nwaUE+wH+lC9ekKAtWqizwY3AY9B7u08jCsJ09TU+PHGBVRB
         ge5fCVKnqcCtXgHJcq7zlPj0QJh+qORUsPrWneiINEPjnE6cls8vclZL3c5E2D00GKfE
         HHtwLrVqhMJC8ZMtJ/8ojH0of9/2rmFdT84cN2aSFvIEyJ+kA5NEjH6U4bBbNAjOOT7S
         L0HUUFYH63D9V5UJISJG/hRPBFiJDrRVko976Q1cvd5S1QFhtkfodW39/MbphP3yQNUo
         2GeM9iVf3JO3CzjuYP+uWZSvkk9/KxeH59ZsZW3kNU5vRrjbPDM/6dgoORnxwbDtWakF
         eeMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTu/6LpMrmB/ZEuf6kEb+ejBVoWVS9UvgSHFkV36tKHBffireH
	lFfZB2HBK1kGUO+wm1oTtsU=
X-Google-Smtp-Source: APXvYqx6O5nnEHEGAdygIG9EOcOrkwCFCMOiy25x+Xi6Zy6ON/byFmoDMsFRveY/i/F6PWzVcMUUjA==
X-Received: by 2002:a17:902:7886:: with SMTP id q6mr533917pll.323.1569975266281;
        Tue, 01 Oct 2019 17:14:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5f90:: with SMTP id t138ls137314pgb.13.gmail; Tue, 01
 Oct 2019 17:14:25 -0700 (PDT)
X-Received: by 2002:a63:d80e:: with SMTP id b14mr596992pgh.423.1569975265841;
        Tue, 01 Oct 2019 17:14:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569975265; cv=none;
        d=google.com; s=arc-20160816;
        b=a97w2H385wuVPzFoWX98kdWyKNLrf5LdU+WkszvMYK6S0206+HH1YDreUfseDFFvmS
         dSD0b4IANeGmPKWWSrP7Z5nJ5noJ5tX5ouua3zNd9KbXz52LQcQi4lFcI68IHWte0AlZ
         8AEDt6aMxHSWoK0BzRAt/JDw37tMk/6EaX9dP/tDPVxHNmOcotS01CfxhK9cImburdi+
         boEJAwm2bTB2w9krxs2mg5wduqIcNpQELeBHR5I9Q8fHjBlR6Jlj1FeSGMhw5wrQdM9g
         fNEXeqPU6GdIrwCkKQFBiEYq1ze2yMwH9EXYhDbYXKeNssUGlieErKoXUUz5kVu19XsG
         qS+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qp6mpPjoJw8IpL230TwztYNGcdXtc2wRumjJPrYIsQE=;
        b=bBKRK6bBtHIDA5rz46y3rzYKsFoWvAG3hOkLBg0Br/GJKH0h+8FlLXp1xq6QcrCsQg
         J9vvnAPs3EemOE5v7NTzuXJLdSI1hTUftCV/2T6JhTjZzMK9oh1QjVEu1gLC+vfk+8Ih
         v50C+O0aPTs+zmmmUdREwqV783qoYo5L2feh0lm6xnAHuhHkBzff/h/VGwtgK17e4iRR
         yH3XUj+2bEJqoxj2Ym3ilGdzGQAFOvfbReHEZtMvREkCfoH9Ck+8OxtN8Vbyv49zbPp2
         pXTCXJy6iT0hyQ7lbBC+9k+b8G2cm1Xp66OgARbfkD/N1iVMgx2ps8ukqkcDkEKzIYAZ
         xqig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nJtPZChL;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id x197si15659pgx.5.2019.10.01.17.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 17:14:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id c25so52704121iot.12
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 17:14:25 -0700 (PDT)
X-Received: by 2002:a92:3314:: with SMTP id a20mr890351ilf.276.1569975265009;
 Tue, 01 Oct 2019 17:14:25 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
 <20190926160433.GD32311@linux.ibm.com> <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
 <20190928073331.GA5269@linux.ibm.com> <CAHCN7xJEvS2Si=M+BYtz+kY0M4NxmqDjiX9Nwq6_3GGBh3yg=w@mail.gmail.com>
In-Reply-To: <CAHCN7xJEvS2Si=M+BYtz+kY0M4NxmqDjiX9Nwq6_3GGBh3yg=w@mail.gmail.com>
From: Adam Ford <aford173@gmail.com>
Date: Tue, 1 Oct 2019 19:14:13 -0500
Message-ID: <CAHCN7xKLhWw4P9-sZKXQcfSfh2r3J_+rLxuxACW0UVgimCzyVw@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Fabio Estevam <festevam@gmail.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aford173@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nJtPZChL;       spf=pass
 (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d43
 as permitted sender) smtp.mailfrom=aford173@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Sep 29, 2019 at 8:33 AM Adam Ford <aford173@gmail.com> wrote:
>
> I am attaching two logs.  I now the mailing lists will be unhappy, but
>  don't want to try and spam a bunch of log through the mailing liast.
> The two logs show the differences between the working and non-working
> imx6q 3D accelerator when trying to run a simple glmark2-es2-drm demo.
>
> The only change between them is the 2 line code change you suggested.
>
> In both cases, I have cma=128M set in my bootargs.  Historically this
> has been sufficient, but cma=256M has not made a difference.
>

Mike any suggestions on how to move forward?
I was hoping to get the fixes tested and pushed before 5.4 is released
if at all possible

> adam
>
> On Sat, Sep 28, 2019 at 2:33 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> >
> > On Thu, Sep 26, 2019 at 02:35:53PM -0500, Adam Ford wrote:
> > > On Thu, Sep 26, 2019 at 11:04 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> > > >
> > > > Hi,
> > > >
> > > > On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> > > > > On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> > > > > >
> > > > > > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> > > > > >
> > > > > > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > > > > > change.  Do we need to setup a reserved-memory node like
> > > > > > > imx6ul-ccimx6ulsom.dtsi did?
> > > > > >
> > > > > > I don't think so.
> > > > > >
> > > > > > Were you able to identify what was the exact commit that caused such regression?
> > > > >
> > > > > I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> > > > > internal allocation functions") that caused the regression with
> > > > > Etnaviv.
> > > >
> > > >
> > > > Can you please test with this change:
> > > >
> > >
> > > That appears to have fixed my issue.  I am not sure what the impact
> > > is, but is this a safe option?
> >
> > It's not really a fix, I just wanted to see how exactly 92d12f9544b7 ("memblock:
> > refactor internal allocation functions") broke your setup.
> >
> > Can you share the dts you are using and the full kernel log?
> >
> > > adam
> > >
> > > > diff --git a/mm/memblock.c b/mm/memblock.c
> > > > index 7d4f61a..1f5a0eb 100644
> > > > --- a/mm/memblock.c
> > > > +++ b/mm/memblock.c
> > > > @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
> > > >                 align = SMP_CACHE_BYTES;
> > > >         }
> > > >
> > > > -       if (end > memblock.current_limit)
> > > > -               end = memblock.current_limit;
> > > > -
> > > >  again:
> > > >         found = memblock_find_in_range_node(size, align, start, end, nid,
> > > >                                             flags);
> > > >
> > > > > I also noticed that if I create a reserved memory node as was done one
> > > > > imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> > > > > was getting errors regardless of the 'cma=256M' or not.
> > > > > I don't have a problem using the reserved memory, but I guess I am not
> > > > > sure what the amount should be.  I know for the video decoding 1080p,
> > > > > I have historically used cma=128M, but with the 3D also needing some
> > > > > memory allocation, is that enough or should I use 256M?
> > > > >
> > > > > adam
> > > >
> > > > --
> > > > Sincerely yours,
> > > > Mike.
> > > >
> >
> > --
> > Sincerely yours,
> > Mike.
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHCN7xKLhWw4P9-sZKXQcfSfh2r3J_%2BrLxuxACW0UVgimCzyVw%40mail.gmail.com.
