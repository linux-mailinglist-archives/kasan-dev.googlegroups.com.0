Return-Path: <kasan-dev+bncBCLI747UVAFRBBFFU6OQMGQE36PLB7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C2CEE656443
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 17:57:41 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id bg25-20020a05600c3c9900b003cf3ed7e27bsf5810984wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 08:57:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672073861; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp0EOWnY2imXEfmCoo44deuhcAXTx2SqNlHwl2RDWF/XU586m/F5MlBYJmMdSKJuEo
         kkJlPX4/O1gZoW+Hu7ssIC2ON9Abk95uFwl76w8CaEYykUgWR6tkJcQ6nTBvzygHOhPj
         NRa5iU2wzX/15zjx7Ho7R68s2g0iU5hyEvk5cWykER9zpuBB70b2FkYN4z+no3IcsLO3
         YEQ0rcMwBbDrhSo+Ol0yIRwZRz6e73SZJto2XPrG1cObuprUOZ0KXOE6BelqvOKKTK8M
         dBQicT740gdzEAlQnbazwmP/W5/RAdSye3eBC1DGH33LEDUYKtCIypbaA/cCQhrLI3Kf
         5r7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=AsS4sMuOZL9g12F79PFHclpJDQxj7p/dkyI9QWBt7B8=;
        b=FbmGyuKNnIgLoJDlywIOeQifJ5T4XrmDFBGw8SI7lRUGjNNbAjXh52gpTc9buudwoO
         U+wgzIc3tGrSu7OQ3vvn0OHwLfVJIPSP6DNUpbvPTmpM4P18UhbpCMriw7AFb4iitawQ
         t7Q6Z2yp6uu3/i33/de0vD69U+DoWaqirbaP1fM32qMenWOZl+pxDHUApBsy2DCFU0nQ
         qhOKcs/Pqn3LoksAif6Br2mvBDbrduIUDYqksWjFMCm6M6hLgtZTZk7TJITRip/NWfjh
         xtnFNXHK6fj73UAtO01euZned2nEhlgu8YK2zF03cFQd4wvlmov9Nkt1Pb0pEE5okLnW
         9W4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=b6POVW8y;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=AsS4sMuOZL9g12F79PFHclpJDQxj7p/dkyI9QWBt7B8=;
        b=Uu0bu4vHkby94EJhfZDVDhA0v1TvaWdBtYBxg5VUn3nK+b3m0KOiRw/IIt0qK/ENcL
         H7luWhpGs+8BKOA/K4y65L4pxHV9Bv0oGJSnorUu3zQH9fCv1krewuTLNPU5Z9zBA0WL
         ajEUBNB52LkNPZ2MF7Vmkq58IV034yvQHMaE/tIuVc5hlIwm3lNLpQHFY+I8t/xfaiYJ
         X8vF3NzeAy33HZ6p2qrk9mq7U3SOTe10g/f3zctvEjVDqgcWrsXvHkT8xkar0VysvIx4
         kQPwGH/NeLMm3VvW5ZAcXTu/j3widAwLljgDAiDOr+0/uSRCFslZil3QEF7vwPOI6i/a
         DHmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AsS4sMuOZL9g12F79PFHclpJDQxj7p/dkyI9QWBt7B8=;
        b=X/JOIE4WMONCLhV7D1ku0VYsVeGhRzWmRVffikDHxzS8aV/2JNl/lXDnP9VKlyex8U
         d7F3KetBbvDUojswaSKyxAgMRtHJUHnLHfgl/hjeT60X2cy73WNSQ1ntxf1+xiQFxOBP
         ASuw2+dDwSj3zlfdpWz8pxTiTiDd2rEYWzk5uEOZkFwghYjNFJIWjsFXlXtlO3D33oz+
         NJhCDlL7reVwoliPBEXFP3CZrHI31iP75FdBzhK3wu5KFWIjsWeU8xjyGFlrt4sUQiuH
         UBvG8qp+46mOxeI9qexJDjPFPboUZCTmT7fIIad93r3DCM+0ggjkGHbxWQhSgMc5AsEz
         Jvwg==
X-Gm-Message-State: AFqh2koMqnY5Tr4zy8Q/6VAZEYKWbB9Ejvm6Nq7GwBj4AjbTystj+3E1
	Rot/LvciY0LJyts/HoGj/h4=
X-Google-Smtp-Source: AMrXdXuZHXxQoIzP+g8Z+Xerd4fjXbmtoIrxgOhEruO8eLx0SljUhZIbUOaWA3GdjkkppwIYE9cz/Q==
X-Received: by 2002:a1c:a486:0:b0:3d2:13cb:c562 with SMTP id n128-20020a1ca486000000b003d213cbc562mr1126901wme.91.1672073861130;
        Mon, 26 Dec 2022 08:57:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f548:0:b0:225:6559:3374 with SMTP id j8-20020adff548000000b0022565593374ls490210wrp.2.-pod-prod-gmail;
 Mon, 26 Dec 2022 08:57:40 -0800 (PST)
X-Received: by 2002:adf:e849:0:b0:24b:b74d:8011 with SMTP id d9-20020adfe849000000b0024bb74d8011mr11717693wrn.6.1672073860140;
        Mon, 26 Dec 2022 08:57:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672073860; cv=none;
        d=google.com; s=arc-20160816;
        b=GxHXwUhbhRBQ1u7fru0Xe0Vy7T2RA6puCXsRcf4zpmZdfKoWerzXCOWSRtBMc+sv69
         F8Bbe+0hto/6Owcwtfn4xQ1IAIxkX6P+1Pl/YIdTIPL9unDndnVNnQNTr/yqAKl5bvLx
         3NdydDbnvy8pnQywYviLqhdRLrEiG9M1HbIjuRA247xALcXXQrV6qqS68HvKipNaBAfo
         mSbtpOMkjnd9X2iK1ITq6c+ZH9IvuNpQhK0Fl96wFHnapuXaWwxcCnHsY5eUrss3tkQ9
         BR2jh2a0N+hr9XfpC6Me+hxXcyQurWGrnsoRQwwjfIwxUOMVeT/oy8vpjpvEv2yzGqU5
         FCRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=WIE3Z+cKtBnA8yyHSJ3TV6iPDq1ETA37GJq6ok6agec=;
        b=OaRGriWKV5bUaINAnsH0B9y/SwtTlA2+KC/WbeoXDIOs9CQ6lwBZQxLba1xXfqBKlR
         8gatxbY039JlaK1BWUo6d6QIUw5tcDsqgZkp7o/T3Nu76kpdx3Kg+fLj2w83VJX5jPuO
         4cvtUTeB4aUp573SJnsPPZ7U30x7ngauVDRanRbSB9+G7H3oucvm9Fx3hEUD44FA0gel
         ASAyrJErFx4sie2j2fnV3i2TkH6c7Sy+GupHEVBYfcb9QMCU0trFrb8UzYA98UI8LaqV
         ZTkxJyirhwFiXd8k61RCegViDufcW+EgHelrS02FRd69PbErUNxC/P6s6wMki7/w1jHu
         5etQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=b6POVW8y;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id h13-20020a05600016cd00b0025dd2434f36si392571wrf.2.2022.12.26.08.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Dec 2022 08:57:40 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id AEACEB80D68;
	Mon, 26 Dec 2022 16:57:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AD4B7C433EF;
	Mon, 26 Dec 2022 16:57:36 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id abdc5615 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Dec 2022 16:57:33 +0000 (UTC)
Date: Mon, 26 Dec 2022 17:57:30 +0100
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Eric Biggers <ebiggers@kernel.org>, x86@kernel.org, linux-mm@kvack.org
Cc: pbonzini@redhat.com, qemu-devel@nongnu.org,
	Laurent Vivier <laurent@vivier.eu>,
	"Michael S . Tsirkin" <mst@redhat.com>,
	Peter Maydell <peter.maydell@linaro.org>,
	Philippe =?utf-8?Q?Mathieu-Daud=C3=A9?= <f4bug@amsat.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Ard Biesheuvel <ardb@kernel.org>, Gerd Hoffmann <kraxel@redhat.com>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 4/4] x86: re-enable rng seeding via SetupData
Message-ID: <Y6nSel5/wdnoSFpk@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
 <Y6muh1E1fNOot+VZ@zx2c4.com>
 <Y6my+Oiz67G46snj@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6my+Oiz67G46snj@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=b6POVW8y;       spf=pass
 (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Mon, Dec 26, 2022 at 03:43:04PM +0100, Jason A. Donenfeld wrote:
> On Mon, Dec 26, 2022 at 03:24:07PM +0100, Jason A. Donenfeld wrote:
> > Hi,
> >=20
> > I'm currently stumped at the moment, so adding linux-mm@ and x86@. Stil=
l
> > working on it though. Details of where I'm at are below the quote below=
.
> >=20
> > On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrote:
> > > On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrote:
> > > > Hi Eric,
> > > >=20
> > > > Replying to you from my telephone, and I'm traveling the next two d=
ays,
> > > > but I thought I should mention some preliminary results right away =
from
> > > > doing some termux compiles:
> > > >=20
> > > > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > > > Hi Jason,
> > > > >=20
> > > > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld wrot=
e:
> > > > > > This reverts 3824e25db1 ("x86: disable rng seeding via setup_da=
ta"), but
> > > > > > for 7.2 rather than 7.1, now that modifying setup_data is safe =
to do.
> > > > > >=20
> > > > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > > > ---
> > > > > >  hw/i386/microvm.c | 2 +-
> > > > > >  hw/i386/pc_piix.c | 3 ++-
> > > > > >  hw/i386/pc_q35.c  | 3 ++-
> > > > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > > > >=20
> > > > >=20
> > > > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with some =
configs.  There
> > > > > is no output at all.  I bisected it to this commit, and I verifie=
d that the
> > > > > following change to QEMU's master branch makes the problem go awa=
y:
> > > > >=20
> > > > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > > > index b48047f50c..42f5b07d2f 100644
> > > > > --- a/hw/i386/pc_piix.c
> > > > > +++ b/hw/i386/pc_piix.c
> > > > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options(Mac=
hineClass *m)
> > > > >      pc_i440fx_machine_options(m);
> > > > >      m->alias =3D "pc";
> > > > >      m->is_default =3D true;
> > > > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > > > >  }
> > > > >=20
> > > > > I've attached the kernel config I am seeing the problem on.
> > > > >=20
> > > > > For some reason, the problem also goes away if I disable CONFIG_K=
ASAN.
> > > > >=20
> > > > > Any idea what is causing this?
> > > >=20
> > > > - Commenting out the call to parse_setup_data() doesn't fix the iss=
ue.
> > > >   So there's no KASAN issue with the actual parser.
> > > >=20
> > > > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> > > >=20
> > > > That makes me suspect that it's file size related, and QEMU or the =
BIOS
> > > > is placing setup data at an overlapping offset by accident, or some=
thing
> > > > similar.
> > >=20
> > > I removed the file systems from your config to bring the kernel size
> > > back down, and voila, it works, even with KASAN_INLINE. So perhaps I'=
m
> > > on the right track here...
> >=20
> > QEMU sticks setup_data after the kernel image, the same as kexec-tools
> > and everything else. Apparently, when the kernel image is large, the
> > call to early_memremap(boot_params.hdr.setup_data, ...) returns a value
> > that points some place bogus, and the system crashes or does something
> > weird. I haven't yet determined what this limit is, but in my current
> > test kernel, a value of 0x0000000001327650 is enough to make it point t=
o
> > rubbish.
> >=20
> > Is this expected? What's going on here?
>=20
> Attaching gdb to QEMU and switching it to physical memory mode
> (`maintenance packet Qqemu.PhyMemMode:1 `) indicates that it
> early_memremap is actually working fine and something *else* is at this
> address? That's kinda weird... Is KASAN populating physical addresses
> immediately after the kernel image extremely early in boot? I'm seeing
> the crash happen from early_reserve_memory()->
> memblock_x86_reserve_range_setup_data(), which should be before
> kasan_init() even runs. Is QEMU calculating kernel_size wrong, when it
> goes to determine where to put the setup_data data? But that's the same
> calculation as used everywhere else, so hmm...
>=20
> Jason

If bzImage is 15770544 bytes, it does not boot. If bzImage is 15641776
bytes, it does boot. So something is happening somewhat close to the
16MB mark?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6nSel5/wdnoSFpk%40zx2c4.com.
