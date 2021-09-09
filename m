Return-Path: <kasan-dev+bncBCXO5E6EQQFBBR4I5CEQMGQEAW5RBZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EC4F4053B7
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 14:55:36 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 8-20020a9d0588000000b0051defe13038sf991980otd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 05:55:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631192135; cv=pass;
        d=google.com; s=arc-20160816;
        b=Re9amcBlBfwM3ztor6aG4fzvDHg9sFL1292cJmwAok8/DpnOPLQ5MG3wP2R0JCom5Z
         zYhSg/9pPqD25TR39GhhQeL0wubde9jN9wYquEPU/C7ex3u975/nkcN79VfPzClkeZL9
         mnL9cvVFZXnhf6BncHkFtnkN3qSA8/F+Cki2e6xt0BZEazgVO3xQkR+0YpfvuZ9Ka9bv
         RlYqkitEN2dT6qw+f4QHzIvtFWEZv4ZdcCtemxWSjkvgwnC1FVZcemdSezrH95toOCg/
         vg6j6pEBGR7e5xQ3W6MJstmwHGBTS9nA5abBXPJzGJ0SQvVldnexVM7yXjiD+D4O8aaA
         zCHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=6YsBDsgUSclcHt3ys9RjTqJ+AkXycpyEfAs06W9GMrg=;
        b=WLp0Var8/+n/3Rp/Mir988gDFGsl7P2dvkh0tidI4sbq93+LFkg+EJFuUovsOSBgqs
         itjs/EX/c9Y19vpPoHH8Q66YgpiTuoDvZ7eXjgg6ys8WNhkMnAT3Nl+DcMab0eQGVThL
         75g8yGvbbYEQeFFQFd1cPTrkjAsskUvvSc68tCyl0DmFS0ghkFWLvi2Y0mceincI5ez7
         yw2LsBcHA9dcR8I9/g/SVb4FzoLSVPjhdhVV7axLZJLi7PUZI0Ny5M4QhHQhRtysZKbJ
         mWaamaZNR0C30HvLnTjX4EVhtLxqVVFNUAdOSrGz69OcMpICdEvS1adNCurSg7UlWIQ8
         TWsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cB/PNnL/";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6YsBDsgUSclcHt3ys9RjTqJ+AkXycpyEfAs06W9GMrg=;
        b=m7xd4xfxOnFBKXs1+NZNZ5mJ5W+Sue4KkknXtO6fy117EaoNIL8fm+37FKRmj+tZaP
         909RhardJuFyc6fd6Oj6RyeKfxj2EERhaw2s8QKsNO0gu4gXR5phKOh1ZYd842WND0mi
         E5DQjRA3XeXXiVmiLvis4q94Q2VvpxM9ClbCc0yd+TMs3hjdKUOuxV9QZ/6mKN2BIbeN
         z4tonL+p0KPldYQ+M4rkdz7z8myjmO6KcC1FmlYPgk7YzH80wQ2eNu9rI+E031gTNaVA
         dtAmU/me6ccfw1lId4KjvIwdXTg7GXfu1m2xhmGB2uJjNa1/3uW/UY9TpOLIRnHN4HL4
         8n6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6YsBDsgUSclcHt3ys9RjTqJ+AkXycpyEfAs06W9GMrg=;
        b=U6yTWHApulwLn9STe2eFiU/2MeMcOgL4qABvRIJZvfm3+s1MBDlAQ8nmUwFAZ0w42l
         uIySeMwB6iog1CNdDRWHL42e4Z2RwvGAuSgQ0UpFcoNhUYPWCFutuqb/bpTFQB9VArHN
         wbPBOFCH19jjRcNwj6M1jGo0EVC6vylw8fXa6xNauN3ElX3nba1Sx+z5CxCYd66ZzRgt
         69PXq8vu8Ni8qkPxQreAcvLr5u8T15XWxWJ99gdci1Uc8OGXR7tt7spM1vUaORQ7zO3Q
         SoA7AGaIHOTlnzfwUVef7ukPJytT6sJSsatac2lcSW2Dl505LnkafTkun5OH6Kvy4GRS
         OXvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wWnH5lOobW4DGVGj4WGwXfl0Y/BJMjsDZJfRxUAeuWltwvzbH
	xLA2JxOSv+mEaQHLuPV2lEg=
X-Google-Smtp-Source: ABdhPJyk44j5ZmwoxcTHJcYQ5UIUtdpoeNmlXH2Y4vu1+jA+2bXFMLoxw/cvL6gGTWsnCI3LouHtdQ==
X-Received: by 2002:a9d:6359:: with SMTP id y25mr2338107otk.274.1631192135435;
        Thu, 09 Sep 2021 05:55:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66c4:: with SMTP id t4ls478023otm.5.gmail; Thu, 09 Sep
 2021 05:55:35 -0700 (PDT)
X-Received: by 2002:a9d:705d:: with SMTP id x29mr2374623otj.260.1631192135108;
        Thu, 09 Sep 2021 05:55:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631192135; cv=none;
        d=google.com; s=arc-20160816;
        b=G3feTMGQZSIZdBAr7pR7lvm9Dgxyt9UX1Aet9tAhvJaXUnZEQISSdeNKRRO8aChKuu
         FmsX77L9ETwWk67DZbq2V0sS+rCb1q1nB77D/ivQFbfrif6CZxvvZclhSwrXt2cMp6Sd
         WQMnsd5HGFjSQxbLRftbBi8L8HhgMDIf+RdKox9q6CQPV/gkPA+fKyD9h1W8Gffc6fNv
         le+DGj6ct5fBjU1ZpzPVyLIOvBeV17XEc+k6N5u5/wDXyzpDEhMh5QaQN3lhVgygo/KW
         2vfctogn2Y8MWQP88O0c+F2WkPItzO2n1AaoY4MvSy9+Bk9S5HIxNIUKe2b8RtXxjTVu
         UBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IeQvMSlBzO58HlO7lnDf7f77B8EHEWdhr0tsZ7BeMQg=;
        b=WpwKYktKQj4zVTFDEemYXlYu9phHSa9weruVyUGLI/+5xg3NvG643XhIgWm/9xEnPz
         w5k2uTNJdxbE8papXGrod9Xv2fcYz131AoiIZ1FkI0Go1LwPE+8U7ON4XXXkEyYTM9c2
         DXU4UGvKHGIRxA8X35TybAQLd3jUY3iOkUHdt8ClxX/uTMAmCn8Ax6ZGGJJFjO7Snl9i
         J8JtcqpivDTbPL7N1Dajy9WgW/PCNZ9/VGPfPlRKBpYuKNfRb520m/rILQKOfBUPdjOm
         StMeuYC+O6e2th00YzXRzGvF2icwEH0XZ5OosEXnOxjJcqdWS5TfKje2VZysPaNcL/99
         ExpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cB/PNnL/";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v21si137340oto.0.2021.09.09.05.55.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 05:55:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 58193611CC
	for <kasan-dev@googlegroups.com>; Thu,  9 Sep 2021 12:55:34 +0000 (UTC)
Received: by mail-wr1-f45.google.com with SMTP id q11so2413866wrr.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 05:55:34 -0700 (PDT)
X-Received: by 2002:adf:f884:: with SMTP id u4mr3278238wrp.411.1631192132894;
 Thu, 09 Sep 2021 05:55:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
 <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com>
 <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com> <CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com>
In-Reply-To: <CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Thu, 9 Sep 2021 14:55:16 +0200
X-Gmail-Original-Message-ID: <CAK8P3a2--kfvs-+qkZdpea94ccgcY6QpdHMfVFgY0F2Z=GBhyw@mail.gmail.com>
Message-ID: <CAK8P3a2--kfvs-+qkZdpea94ccgcY6QpdHMfVFgY0F2Z=GBhyw@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@infradead.org>, Guenter Roeck <linux@roeck-us.net>, 
	Nathan Chancellor <nathan@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv <linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx list <amd-gfx@lists.freedesktop.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cB/PNnL/";       spf=pass
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

On Thu, Sep 9, 2021 at 1:43 PM Marco Elver <elver@google.com> wrote:
> On Thu, 9 Sept 2021 at 13:00, Arnd Bergmann <arnd@kernel.org> wrote:
> > On Thu, Sep 9, 2021 at 12:54 PM Marco Elver <elver@google.com> wrote:
> > > On Thu, 9 Sept 2021 at 07:59, Christoph Hellwig <hch@infradead.org> wrote:
> > > > On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
> > > > > It'd be good to avoid. It has helped uncover build issues with KASAN in
> > > > > the past. Or at least make it dependent on the problematic architecture.
> > > > > For example if arm is a problem, something like this:
> > > >
> > > > I'm also seeing quite a few stack size warnings with KASAN on x86_64
> > > > without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
> > > > few warnings without KASAN, but with KASAN there are a lot more.
> > > > I'll try to find some time to dig into them.
> > >
> > > Right, this reminded me that we actually at least double the real
> > > stack size for KASAN builds, because it inherently requires more stack
> > > space. I think we need Wframe-larger-than to match that, otherwise
> > > we'll just keep having this problem:
> > >
> > > https://lkml.kernel.org/r/20210909104925.809674-1-elver@google.com
> >
> > The problem with this is that it completely defeats the point of the
> > stack size warnings in allmodconfig kernels when they have KASAN
> > enabled and end up missing obvious code bugs in drivers that put
> > large structures on the stack. Let's not go there.
>
> Sure, but the reality is that the real stack size is already doubled
> for KASAN. And that should be reflected in Wframe-larger-than.

I don't think "double" is an accurate description of what is going on,
it's much more complex than this. There are some functions
that completely explode with KASAN_STACK enabled on clang,
and many other functions instances that don't grow much at all.

I've been building randconfig kernels for a long time with KASAN_STACK
enabled on gcc, and the limit increased to 1440 bytes for 32-bit
and not increased beyond the normal 2048 bytes for 64-bit. I have
some patches to address the outliers and should go through and
resend some of those.

With the same limits and patches using clang, and KASAN=y but
KASAN_STACK=n I also get no warnings in randconfig builds,
but KASAN_STACK on clang doesn't really seem to have a good
limit that would make an allmodconfig kernel build with no warnings.

These are the worst offenders I see based on configuration, using
an 32-bit ARM allmodconfig with my fixups:

gcc-11, KASAN, no KASAN_STACK, FRAME_WARN=1024:
(nothing)

gcc-11, KASAN_STACK:
drivers/net/ethernet/hisilicon/hns3/hns3pf/hclge_debugfs.c:782:1:
warning: the frame size of 1416 bytes is larger than 1024 bytes
[-Wframe-larger-than=]
drivers/media/dvb-frontends/mxl5xx.c:1575:1: warning: the frame size
of 1240 bytes is larger than 1024 bytes [-Wframe-larger-than=]
drivers/mtd/nftlcore.c:468:1: warning: the frame size of 1232 bytes is
larger than 1024 bytes [-Wframe-larger-than=]
drivers/char/ipmi/ipmi_msghandler.c:4880:1: warning: the frame size of
1232 bytes is larger than 1024 bytes [-Wframe-larger-than=]
drivers/mtd/chips/cfi_cmdset_0001.c:1870:1: warning: the frame size of
1224 bytes is larger than 1024 bytes [-Wframe-larger-than=]
drivers/net/wireless/ath/ath9k/ar9003_paprd.c:749:1: warning: the
frame size of 1216 bytes is larger than 1024 bytes
[-Wframe-larger-than=]
drivers/net/ethernet/mellanox/mlx5/core/ipoib/ipoib.c:136:1: warning:
the frame size of 1216 bytes is larger than 1024 bytes
[-Wframe-larger-than=]
drivers/ntb/hw/idt/ntb_hw_idt.c:1116:1: warning: the frame size of
1200 bytes is larger than 1024 bytes [-Wframe-larger-than=]
net/dcb/dcbnl.c:1172:1: warning: the frame size of 1192 bytes is
larger than 1024 bytes [-Wframe-larger-than=]
fs/select.c:1042:1: warning: the frame size of 1192 bytes is larger
than 1024 bytes [-Wframe-larger-than=]

clang-12 KASAN, no KASAN_STACK, FRAME_WARN=1024:

kernel/trace/trace_events_hist.c:4601:13: error: stack frame size 1384
exceeds limit 1024 in function 'hist_trigger_print_key'
[-Werror,-Wframe-larger-than]
drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3045:6:
error: stack frame size 1384 exceeds limit 1024 in function 'bw_calcs'
[-Werror,-Wframe-larger-than]
drivers/staging/fbtft/fbtft-core.c:992:5: error: stack frame size 1208
exceeds limit 1024 in function 'fbtft_init_display'
[-Werror,-Wframe-larger-than]
crypto/wp512.c:782:13: error: stack frame size 1176 exceeds limit 1024
in function 'wp512_process_buffer' [-Werror,-Wframe-larger-than]
drivers/staging/fbtft/fbtft-core.c:902:12: error: stack frame size
1080 exceeds limit 1024 in function 'fbtft_init_display_from_property'
[-Werror,-Wframe-larger-than]
drivers/mtd/chips/cfi_cmdset_0001.c:1872:12: error: stack frame size
1064 exceeds limit 1024 in function 'cfi_intelext_writev'
[-Werror,-Wframe-larger-than]
drivers/staging/rtl8723bs/core/rtw_security.c:1288:5: error: stack
frame size 1040 exceeds limit 1024 in function 'rtw_aes_decrypt'
[-Werror,-Wframe-larger-than]
drivers/ntb/hw/idt/ntb_hw_idt.c:1041:27: error: stack frame size 1032
exceeds limit 1024 in function 'idt_scan_mws'
[-Werror,-Wframe-larger-than]

clang-12, KASAN_STACK:

drivers/infiniband/hw/ocrdma/ocrdma_stats.c:686:16: error: stack frame
size 20608 exceeds limit 1024 in function 'ocrdma_dbgfs_ops_read'
[-Werror,-Wframe-larger-than]
lib/bitfield_kunit.c:60:20: error: stack frame size 10336 exceeds
limit 10240 in function 'test_bitfields_constants'
[-Werror,-Wframe-larger-than]
drivers/net/wireless/ralink/rt2x00/rt2800lib.c:9012:13: error: stack
frame size 9952 exceeds limit 1024 in function 'rt2800_init_rfcsr'
[-Werror,-Wframe-larger-than]
drivers/net/usb/r8152.c:7486:13: error: stack frame size 8768 exceeds
limit 1024 in function 'r8156b_hw_phy_cfg'
[-Werror,-Wframe-larger-than]
drivers/media/dvb-frontends/nxt200x.c:915:12: error: stack frame size
8192 exceeds limit 1024 in function 'nxt2004_init'
[-Werror,-Wframe-larger-than]
drivers/net/wan/slic_ds26522.c:203:12: error: stack frame size 8064
exceeds limit 1024 in function 'slic_ds26522_probe'
[-Werror,-Wframe-larger-than]
drivers/firmware/broadcom/bcm47xx_sprom.c:188:13: error: stack frame
size 8064 exceeds limit 1024 in function 'bcm47xx_sprom_fill_auto'
[-Werror,-Wframe-larger-than]
drivers/media/dvb-frontends/drxd_hard.c:2857:12: error: stack frame
size 7584 exceeds limit 1024 in function 'drxd_set_frontend'
[-Werror,-Wframe-larger-than]
drivers/media/dvb-frontends/nxt200x.c:519:12: error: stack frame size
6848 exceeds limit 1024 in function
'nxt200x_setup_frontend_parameters' [-Werror,-Wframe-larger-than]
drivers/net/wireless/broadcom/brcm80211/brcmsmac/phy/phy_n.c:17019:13:
error: stack frame size 6560 exceeds limit 1024 in function
'wlc_phy_workarounds_nphy' [-Werror,-Wframe-larger-than]

> Either that, or we just have to live with the occasional warning (that
> is likely benign). But with WERROR we're now forced to make the
> defaults as sane as possible. If the worry is allmodconfig, maybe we
> do have to make KASAN dependent on !COMPILE_TEST, even though that's
> not great either because it has caught real issues in the past (it'll
> also mean doing the same for all other instrumentation-based tools,
> like KCSAN, UBSAN, etc.).

I would prefer going back to marking KASAN_STACK as broken on clang, it does
not seem like the warnings on the symbol were enough to stop people from
attempting to using it, and the remaining warnings seem fixable with a small
increase of the FRAME_WARN when using KASAN with clang but no KASAN_STACK,
or when using KASAN_STACK with gcc.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2--kfvs-%2BqkZdpea94ccgcY6QpdHMfVFgY0F2Z%3DGBhyw%40mail.gmail.com.
