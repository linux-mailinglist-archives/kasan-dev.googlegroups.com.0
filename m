Return-Path: <kasan-dev+bncBAABB6NO7KCAMGQEX6IKMHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC7C380D0E
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 17:30:02 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id n129-20020a2527870000b02904ed02e1aab5sf36576768ybn.21
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 08:30:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621006201; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cv+945aCFWz6I8cvYLilAmUk85aCMRuldQoQmYN3XayNN2B7LWs89xW2p8RUHRuyvg
         KlpyMuDzgp1Wws1HJKu0fKa6CDDvTpRYsPi7K19/UHANZMbm4jNk/rnXbsqDsLTeSprC
         x2gdCRrQ9KEz/koi9VoNeXqh3qUP6r7IPbGgRduJBapvxQ9bjf5CDi7EPfaEi6WqFABV
         d9fs7CXDBHuLEvHQPJOIKKnLEeWrFTYavsGv9tzR0qyfMfijK0oIB3Qz3pUt0Qv1d8iL
         M4i8yTWyGqqTqGd0garc97JjwxijY3PeD9mbZqONJ9JtATGRVApG/AjtioZx58GGiLhP
         e20Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=lGoLF7O4zJJAhy11DIwNpRDADOAxLJezkAxMnfc4csY=;
        b=gSwWa+hGG4ZYvEtvWv5xvl+Od5aB1vw1YhZYcqA1i1tw0cZG7Yepxh8HsBVJwpppPZ
         kHeCzVKWin1To040ENi+t22kpNCezVnjo+pEjk5uNLVk+2DrcgXS8OP6QpFzgu73ucN+
         5VV4SGKNKeJYYn2DGjDBD3sMpkFuAqYKLkxYK/EobHgfrTpEbhlNZ979IOslk+P1X05b
         UvgS14Lsg/BUHKrgQFSJB49w/LNQK3kiHzhcA/t7xS3Nbv42b/nFa9joK5/q7BGFWeVJ
         YgY0Qi6mw+jlHoXAmM0xxCuQDmJNM4AucDxDS6M1+vFEBGLiBqK4YHotIMXObm1H1L1G
         FGaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LxD8ghip;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lGoLF7O4zJJAhy11DIwNpRDADOAxLJezkAxMnfc4csY=;
        b=i1z9t5J+ZZ9Fjv8+qOxkzEwnEt65/uXm7cLcE4kknltAZBTet6L3y2MTWutcu6gjOI
         wmcJr2+wj3wmHDISEynZkOhPoquzJpLsTnJVxlYO6ifWaudplFg7Yqeg2Rtrw4FbXQ3q
         E/NsdoeWpddaP7Nk8OSv0DzbDJTZOC7rX3mDnUdfdKBl0aa1NyC4YNd7c83XsnfHsxGy
         3+BzHk4JVD6ZhOUvqeK2ifMxXvne9zssDxDKpqQZ3r+zIII8hZkOIJiUt84Wpu9Dw+mM
         wJjlXyZgnoNTfgzf1VrcDSJ6ErR+hDqPgrhqcPgynwGhlwD+RBElSfCuUSTB4A1fYxlX
         6TIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lGoLF7O4zJJAhy11DIwNpRDADOAxLJezkAxMnfc4csY=;
        b=Qb0TWfFlwlb/SiUsasNbIzwWWxvyTYsv85OizonFVb+/E6osgby5vB9PkSqyukm5XX
         b4NXcP4YnCKm8B8uTV6f4+fGLFJhPlRIJoKWVvC5x7WH4kfS0D3FgQY4TtaK1NKwDRpX
         5xy6r3rqrD+R1yV7DINM8gP+hstw5J9mIM6LQlGDdefz6Oc9ryhPFNE9hXOONri0x+DO
         4KxnlqhOxMKAplhbKB4YFWSjg7ihK5K1I13FN9VPGdFy79SVJFxlN66d+Pm9p0C80E7w
         LXW8MZKi8xKAN2C+AnQl94LNCnEI5VQ2fSF4t95ANAwh0rtiM5HZXsN/nptFmsqeA17U
         Rbog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530z+uFkhPWmGz6Gn0dT4Ew4skKTd8hxuH8elELe/uLwnf2QFkgR
	hLNWgHOpkZi3uprZfFI+8Kk=
X-Google-Smtp-Source: ABdhPJzG+6+BWF59x97vy5PYnvlohq5UnZjxxORSf9JyawYzP6fruYxtmusMcdK/QJVOw+2jtNBfmQ==
X-Received: by 2002:a25:2185:: with SMTP id h127mr36499017ybh.53.1621006201526;
        Fri, 14 May 2021 08:30:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9307:: with SMTP id f7ls4469586ybo.10.gmail; Fri, 14 May
 2021 08:30:01 -0700 (PDT)
X-Received: by 2002:a05:6902:72b:: with SMTP id l11mr21871425ybt.331.1621006201139;
        Fri, 14 May 2021 08:30:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621006201; cv=none;
        d=google.com; s=arc-20160816;
        b=A3gvp/5KiHV+xSGOVvb2dU0bFMDIQ1IxwDmml0Tni79IbJUN8deHMfP0EVxHdWyEfD
         JRzVgVX7FMfdSh/yq6FW17SOlcSP6z8RKEr4X3Fyzp5GiukaVi2t4706ExByJXnd0+lL
         WxYN9ZwGAJMAVTMssU5XYjh23V9cogdbNmpGEcgdlxQvSdswGf0hehPChU7SjXPcoS3J
         rDOpCou/untTDiR/cu5YwKCVqeHFjVXkA9dgLMdfs47jR3BIMtC2IOQHGe4W8+nV0DVF
         Cu4PfBkfO6OU/8uxa4adcseI8PjxwztCkY7gb3aZpQcO9y/w+CL2aBO1EmfJN+ROY6FU
         uVtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VaMJJCRuYq5WEvBzKIy/5zrvqnpQo5OhCoMNoRszLQs=;
        b=YJUDpDuF+W0zE+YeaB50DVhBskzQgavJs3pkVmmVjNJ0xKyQ/jAYZzRlzeJRHeLSkF
         4OT8G3D8K9nr1oHYZ+SVX9+p8hHDCgzkERY+Vry9lr2sW/HL1OpXEiJ9RFkhQKYFeL8g
         T8/J61z9ste5FV8TnEi7P7iBT8kNe5Th3oJAUZ2cKuRDVC6tRGM4DLtI5BGpLyyCNjcf
         kqre4TqLk2feO+jhoEuPQfYEYbxSo2ZJOVZQNhql+K9DzzOi+kCTFuJxzophaz1DhyQ3
         KB4CPiMWgn0iglQBKHI3bwXA+CNHFxzx0w1GCIJgzx+Bg87Fp/u6X4xilKzAnDHOqhn5
         CynQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LxD8ghip;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i15si459013ybk.2.2021.05.14.08.30.01
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 08:30:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1F93A6144C;
	Fri, 14 May 2021 15:30:00 +0000 (UTC)
Received: by mail-wr1-f49.google.com with SMTP id d11so30399464wrw.8;
        Fri, 14 May 2021 08:30:00 -0700 (PDT)
X-Received: by 2002:a05:6000:1b0b:: with SMTP id f11mr22232026wrz.165.1621006198659;
 Fri, 14 May 2021 08:29:58 -0700 (PDT)
MIME-Version: 1.0
References: <20210514140015.2944744-1-arnd@kernel.org> <YJ6E1scEoTATEJav@kroah.com>
 <CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA@mail.gmail.com>
In-Reply-To: <CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Fri, 14 May 2021 17:28:57 +0200
X-Gmail-Original-Message-ID: <CAK8P3a1bF1bLFGdD95OQ91GG0a2ZHWX+pp07N2px7RfCpWRUjg@mail.gmail.com>
Message-ID: <CAK8P3a1bF1bLFGdD95OQ91GG0a2ZHWX+pp07N2px7RfCpWRUjg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: Marco Elver <elver@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LxD8ghip;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, May 14, 2021 at 4:45 PM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
> On Fri, 14 May 2021 at 16:10, Greg Kroah-Hartman
> <gregkh@linuxfoundation.org> wrote:
> > On Fri, May 14, 2021 at 04:00:08PM +0200, Arnd Bergmann wrote:
> > > From: Arnd Bergmann <arnd@arndb.de>
> > >
> > > clang points out that an initcall funciton should return an 'int':
> > >
> > > kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> > > late_initcall(kcsan_debugfs_init);
> > > ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> > > include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
> > >  #define late_initcall(fn)               __define_initcall(fn, 7)
> > >
> > > Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> > > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> [...]
> > >
> > Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks for catching this -- it boggles my mind why gcc nor clang
> wouldn't warn about this by default...
> Is this a new clang?

It was clang-13, not sure if that made a difference.

         Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1bF1bLFGdD95OQ91GG0a2ZHWX%2Bpp07N2px7RfCpWRUjg%40mail.gmail.com.
