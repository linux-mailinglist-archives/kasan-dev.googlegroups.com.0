Return-Path: <kasan-dev+bncBCLI747UVAFRBAHGU2OQMGQEP24DH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CD13656382
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 15:43:15 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id b17-20020a170903229100b00189da3b178bsf8311709plh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 06:43:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672065793; cv=pass;
        d=google.com; s=arc-20160816;
        b=Crb6GGLtZGNqOCONHMjSRQgkKF7SFI/vGVh9kBEmuhx1RaJOTlLhUtgZu+/w2KxN1f
         egobKHEkMNXSEXNKo6Tnbuie2Da1OoUxLWj997aRNQ2TgrY0hOPYiptwN+DztUawXSYH
         rSVbQZrihFi5BMSYNuAWSgdj5pTDtswAWZFAeJtAySMGpGPbcysldtG/3zriYkuCGKN0
         FM+K4iwyBla64Ud4vVJopyTW5oluBPzgEhhrdGLQuq+IVHMtAi8vTIzHak/iPIPT+akU
         Z0D1wTmfDYO9xOt0SDVy7J3YHkhoZgRvH2DcYsgH9l0ruqGp8ltw0/+nK2DxrPueg4tU
         nMsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=IicJ0GWnh8js4E8Cp/qDbjzB6neMlkybFvgArV1PXJM=;
        b=UM2+X6o4raytqq5agobXwdKcCXpIMqS4e48ZPzJXdLOWR/JcPHZmwETblHJP0xr/w2
         ocRTleEEpd3WZYwEoc5usSkVY9jf/YfsT8PR8erHo9Rw7CUaCk8UR3ABFyB6axzWTz8s
         Wz2DV7mK+WFA1/TUTWMfgaxin1MN6xNYDivR0Pn/49k8ac2YuNUX7vbUS6THKnaI9Pf4
         plS4vkKDaGzqZKWjpZqPq/vG0ojVnX4B55xYC6T9ucuvpHfA4EOcdPV9mzaqykkZaKTj
         oZ+qnWmoQewZvhK8er3hJdQOYgkVgfolHzBUfF3gKicq1BockoeHNnzDDZzFHfmIy50s
         LJMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZbIWQ+F1;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IicJ0GWnh8js4E8Cp/qDbjzB6neMlkybFvgArV1PXJM=;
        b=GIRw2v/PECu519gJV1+ipbZUBVzf44nFezYGLpDrZhhlWrqbABvYpwkMomrIRWY46W
         ZaOByNpSBJZWxdpEE4Xvn8QD3RU5DrfOQXPuIEJbGucBlwZbTTTj2aGXGVMkgixzm3H4
         NYUGq53N/LrnPhw6bIpoAIocPbSCTaXtXLoRg3/tfCUa07+xHxT0zfogjGGtz4KAHkAb
         A61lt2MMj4RP1EujCONltkh+ENU8E2emXGp4O/HYl4eO5tIAnM7SCTbyfjCbVKVi7hqV
         Q6W/wWgLiwyJUdUK6XWd+Jl5l71jZea9GvuC3o5guPa6+FjpHAJNzj6fx5Q/M0pk/QZX
         WM4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IicJ0GWnh8js4E8Cp/qDbjzB6neMlkybFvgArV1PXJM=;
        b=iy17F5CnN4HBA4GumV8jNvfDHgm3TPCRCmIGQ9J7gSbhyZ0KrPNV8KYZ9ju4Fbuhk3
         DWWug9Rhe4mKnUE6VMA94hLNj6AwHO1Yr3/KLyycT04angbGzZo7YP3PyJzl00k6Zyjp
         Z1cfAxf6hHYZsu3CF6S7KvBWxIkxXVpeGK2aYRn0bUTcStp9+t+BGl2Eii+WTq/l254P
         HrfySqH4cfPVu3ElXaH7cH9W5oQW+c1u8MHfy8ib5KDCRPRPNioNoc42Nx4OxIUApSb9
         9pGkjdtVQivOF+lR6C/5d4hS0r9ZNLPxiKZ9u1hBcv9GFifXIvWR6c0cIr0bkRkq0Uji
         Vg0A==
X-Gm-Message-State: AFqh2kqDAi1V05to2d/OhwcFbZQP45xJIMR7JEl7AsR7lDZEU7AM9CrU
	GseGe8sLnAshBIBVuqK4ylQ=
X-Google-Smtp-Source: AMrXdXuOLRy9vifaeli9+LaYzNtU8E1g+MjttyJ6PgeLv5S+uww3XTKx5ix6Rl6m+TuBzWoKWWnBJA==
X-Received: by 2002:a17:90a:a090:b0:225:ad17:2d34 with SMTP id r16-20020a17090aa09000b00225ad172d34mr1871187pjp.234.1672065793293;
        Mon, 26 Dec 2022 06:43:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f786:b0:178:3881:c7e3 with SMTP id
 q6-20020a170902f78600b001783881c7e3ls12248632pln.11.-pod-prod-gmail; Mon, 26
 Dec 2022 06:43:12 -0800 (PST)
X-Received: by 2002:a17:902:d051:b0:192:581b:25d3 with SMTP id l17-20020a170902d05100b00192581b25d3mr13773191pll.17.1672065792370;
        Mon, 26 Dec 2022 06:43:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672065792; cv=none;
        d=google.com; s=arc-20160816;
        b=d5/3gNbNYmHtqe7VXf09T3wYDjYCVQEFyo88xWdJlC0N6Jc+/7h0oeo0HfNlNxLzwM
         OPBmlkSBZrqdo8LbykBB73sUdrXKCAIjkRfaPWDSMiLVqW2opniGwUqVsTvKSb44Vb5j
         /OA2t/wIQObn45UpXXg/iz0/0VxDwsE2ZKDBMzh4GWopaW5n9vwsaWrke3KoH8qz76gZ
         ejzA8DwFWTNl36v+8Y1V3aQBpQ7knwmUnnbM2bM3/kWdTdfLmkgOff6Mot30tJuW442C
         RrTNGJ/PyagVOsfHElB/OHU4tCwLEIPh6DJpvS/kdv/D2SN/p/cEVx/P/iHTRMqz7iDK
         YTKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pnBVrkrJXTYl75Ql9lygETz8tLymjZhISCe1af4q/eI=;
        b=ZrYpkNJ14lUg9JIpNg5dmGLWTXu6453LIIS5YzN1Yvs1bPArcCA9tk6oeBlSsDe36X
         JFko7xVC3st9UKl6d6cmR0bFAqa8JqUV5atzxMu5WfFQ4t4S6b/ZBGvKezw5ol4bCKAH
         pYgWRSXQG66xux+NiuroeYvpgrAF1z8fnsd8CGyUbqYhsKyEKwA4c1P4tOh8S/hOLORc
         125EtMpngTA7UlYPv7nfluXszqEc1Z9lXUcw5t5fupIX58yYFxU1Ll+87WnAnRU7Ur7U
         JEYqWFhnm3DIjd+zSLm54ODPboLlILdH8s0OkUXROIzkqfMTwbOHRzFZfc6WK7FpN7sr
         rV2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZbIWQ+F1;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e16-20020a17090301d000b00186b3b9870fsi646392plh.11.2022.12.26.06.43.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Dec 2022 06:43:12 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D011160EA9;
	Mon, 26 Dec 2022 14:43:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9E0DCC433EF;
	Mon, 26 Dec 2022 14:43:09 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 2d986e2f (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Dec 2022 14:43:07 +0000 (UTC)
Date: Mon, 26 Dec 2022 15:43:04 +0100
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
Message-ID: <Y6my+Oiz67G46snj@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
 <Y6muh1E1fNOot+VZ@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6muh1E1fNOot+VZ@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=ZbIWQ+F1;       spf=pass
 (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
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

On Mon, Dec 26, 2022 at 03:24:07PM +0100, Jason A. Donenfeld wrote:
> Hi,
>=20
> I'm currently stumped at the moment, so adding linux-mm@ and x86@. Still
> working on it though. Details of where I'm at are below the quote below.
>=20
> On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrote:
> > On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrote:
> > > Hi Eric,
> > >=20
> > > Replying to you from my telephone, and I'm traveling the next two day=
s,
> > > but I thought I should mention some preliminary results right away fr=
om
> > > doing some termux compiles:
> > >=20
> > > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > > Hi Jason,
> > > >=20
> > > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld wrote:
> > > > > This reverts 3824e25db1 ("x86: disable rng seeding via setup_data=
"), but
> > > > > for 7.2 rather than 7.1, now that modifying setup_data is safe to=
 do.
> > > > >=20
> > > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > > ---
> > > > >  hw/i386/microvm.c | 2 +-
> > > > >  hw/i386/pc_piix.c | 3 ++-
> > > > >  hw/i386/pc_q35.c  | 3 ++-
> > > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > > >=20
> > > >=20
> > > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with some co=
nfigs.  There
> > > > is no output at all.  I bisected it to this commit, and I verified =
that the
> > > > following change to QEMU's master branch makes the problem go away:
> > > >=20
> > > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > > index b48047f50c..42f5b07d2f 100644
> > > > --- a/hw/i386/pc_piix.c
> > > > +++ b/hw/i386/pc_piix.c
> > > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options(Machi=
neClass *m)
> > > >      pc_i440fx_machine_options(m);
> > > >      m->alias =3D "pc";
> > > >      m->is_default =3D true;
> > > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > > >  }
> > > >=20
> > > > I've attached the kernel config I am seeing the problem on.
> > > >=20
> > > > For some reason, the problem also goes away if I disable CONFIG_KAS=
AN.
> > > >=20
> > > > Any idea what is causing this?
> > >=20
> > > - Commenting out the call to parse_setup_data() doesn't fix the issue=
.
> > >   So there's no KASAN issue with the actual parser.
> > >=20
> > > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> > >=20
> > > That makes me suspect that it's file size related, and QEMU or the BI=
OS
> > > is placing setup data at an overlapping offset by accident, or someth=
ing
> > > similar.
> >=20
> > I removed the file systems from your config to bring the kernel size
> > back down, and voila, it works, even with KASAN_INLINE. So perhaps I'm
> > on the right track here...
>=20
> QEMU sticks setup_data after the kernel image, the same as kexec-tools
> and everything else. Apparently, when the kernel image is large, the
> call to early_memremap(boot_params.hdr.setup_data, ...) returns a value
> that points some place bogus, and the system crashes or does something
> weird. I haven't yet determined what this limit is, but in my current
> test kernel, a value of 0x0000000001327650 is enough to make it point to
> rubbish.
>=20
> Is this expected? What's going on here?

Attaching gdb to QEMU and switching it to physical memory mode
(`maintenance packet Qqemu.PhyMemMode:1 `) indicates that it
early_memremap is actually working fine and something *else* is at this
address? That's kinda weird... Is KASAN populating physical addresses
immediately after the kernel image extremely early in boot? I'm seeing
the crash happen from early_reserve_memory()->
memblock_x86_reserve_range_setup_data(), which should be before
kasan_init() even runs. Is QEMU calculating kernel_size wrong, when it
goes to determine where to put the setup_data data? But that's the same
calculation as used everywhere else, so hmm...

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6my%2BOiz67G46snj%40zx2c4.com.
