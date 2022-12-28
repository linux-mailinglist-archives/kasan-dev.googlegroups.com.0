Return-Path: <kasan-dev+bncBCLI747UVAFRBG5KWGOQMGQEP3JA7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BDDD6577E6
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Dec 2022 15:39:24 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id b31-20020a05651c0b1f00b0027a003c5d43sf3760276ljr.7
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Dec 2022 06:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672238363; cv=pass;
        d=google.com; s=arc-20160816;
        b=0+tn8I7Gc3at4t9LDk6P7EMrzoaDL+d8o5lIo2/lSyPVvzwAjMR0W9TL0OupqojRxc
         HUWDmZ+OrlNgvJEcEhmT+OgaGv8XnNB9IWDPE+/iZvSpgBzQTAl5wULfOqi23fyZW847
         j+sTMNEDGaPLCxkGqrCchmkf22DcxJv5OW33owPU6DldbAIh73AOUzjLrEGFCgrKFl/E
         ro1eaOcqjTqxdcsM+bOMI+TPPEHe8EUXHXo2wEDNOlluFyub75bc+kMiwT3gj6yqskBg
         wzEEqJZknsqkBGkISr+7T17qY2A9J52ebqgWwGIIiicaJGTJdPHGcVPnQl2MBYXSQ+W7
         4eLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=5ATegTXg/iSj4EUoILUcH+7phZHPEo3T/iFVFV3cDm4=;
        b=VnA3T4g/oAgFgJl85NxHMZALck8a/x9fvg/e26no4KJJautnDEY6tMlqZdgm/FnWbI
         Ve1RRS02ZuIJn74ZsYj3UOXl+SUZnsJYgNFYthXDIRdO5lmfzdpookUM7KrUDCCbu371
         dazsbF2anw6Q/+HQJTWbu/JkyzNAleQzXT8Ga+XOPYWrdhM3flZn9yL3q3CiTAYlA6h4
         8iaWKZ2CA8jTeYfsf5u1MbXOA/FfrIZ2zKlRzpsde9G/fP6pfovq1E4C/IdYv1+uuWuP
         IAtcvwa07BdhVLGMIwkMakhMIm6lB2jCMVaxm7ENPW4+XIyY5CiRQLQ5vcwBQS9wvByK
         Eb5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=FmUMzWAF;
       spf=pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=5ATegTXg/iSj4EUoILUcH+7phZHPEo3T/iFVFV3cDm4=;
        b=jaIrebidrX+6Sd20AD0vo+w6dOhAKS0HqprLF9ohPRQ293MpGruHnrzJ55MaqgU/D0
         0aGNnqAq9kP0YffXK79RUV6X/4l5xjZIgfcq95QgJTV1FRPTAO3odb6TFlQdUcciSI9A
         kPfNzXl4q6vnECR66sztEPuO2cLJbeiSc/TsDx/TxSbLhC8mkZKH6Ah5M2vQBnxuu4B+
         T+nSZbvm8n7WLjXHYHrUg93qkd9MOcuUP2pyD7G3PJt4WI781wT0/hYiaM3005Oa0dUf
         ojoqUcOuAJKXbgwi0ZbZwEv3FXnCVIx9fevvOdB5j/95icis3rxKsr67PS24Z+FkzO20
         QWtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5ATegTXg/iSj4EUoILUcH+7phZHPEo3T/iFVFV3cDm4=;
        b=xZNbfhWWsviMrQX37ODd7NOuMmYuSBT0XO5APTZozulr948Z5BSMvzB/pDz0o5O1ZL
         Hq12WUiV85kI1pTSAWh4KIck/SZgxSja+LEqbiWVq/VWakcP29RlTS5otMQf9+L/eZjr
         1p0diFkNhirpOMzOWGTn6GRfPayqofmFKRSI9bcrREogU0ZZMU/xQdcraw2wFkHhmcXB
         13HlIqmSMZZefJOsAHqISyTap8retz/xrO3KBD9peT5MGj41kYrNfE6X5iG/3gU4/L13
         156k40/I4V7s2Xv9Re9aROe8TZqdw0ijssJ7SRCAHUyZ+U84cWkOBxYUKvXYdTaKnRUf
         mTpA==
X-Gm-Message-State: AFqh2kqJ9jHmwiuQ2vMbvAQ2klSCglb449NVDqs1ZuNnktNJ8YW4PqI8
	7InpPD5fJIhrhwQKCGtiJqE=
X-Google-Smtp-Source: AMrXdXuNfKjiuzLzE0R005zRXk2qTt4dRoSFp0B+ZV41uy0yglDCvwWSplUS3nvKWNdrC2MKofA5Vw==
X-Received: by 2002:a05:6512:ea0:b0:4ca:fff2:901c with SMTP id bi32-20020a0565120ea000b004cafff2901cmr1512351lfb.473.1672238363358;
        Wed, 28 Dec 2022 06:39:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e8a:0:b0:4c8:8384:83f3 with SMTP id o10-20020ac24e8a000000b004c8838483f3ls3403891lfr.3.-pod-prod-gmail;
 Wed, 28 Dec 2022 06:39:22 -0800 (PST)
X-Received: by 2002:a05:6512:3f85:b0:4b6:e19a:d1af with SMTP id x5-20020a0565123f8500b004b6e19ad1afmr8644263lfa.3.1672238362139;
        Wed, 28 Dec 2022 06:39:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672238362; cv=none;
        d=google.com; s=arc-20160816;
        b=gfmjhU7QaWqh46Zyre80wbdUGvfgiFssL9FRftRxYpn8IEiOjC2DD2+Zv+nZ5fvwND
         Gudg35dcKFcrmr52HA6pI55QEPO7IxHtRMAMUm/5TbVk1jDd7flhghGGfDiVCgkmKnrB
         vUCsHfAf446I/rjGeNBjAYkFvH/2+IHtok0iKdjBNSkftD6lhooE6A6QaSSWt38pF9L8
         ZlplaQfkZk7Ln6SL+N5Xnty2GtCgXEveQfU+NcZgax11OAaqzK/NCJBjlJogXrmxAlX4
         2/a6fOUU3p7HxPHf4gRl1l1m7b2Xs608PmwYF4SJl76aL0eDvCiNubKch6ZVkpP6UGW5
         4y/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Vq5HU2e0An2dJOWNwYu6KJi6n2DVTujSQj+JRa+gkDQ=;
        b=ZjXU6mxFK1TsCTWgPFOMn1mZcAbIASx9b53YDpwrSoPLXHJo8B5TScRZls5GIoV/WI
         SLHx3QVZaDdVXVziaUYNxx8Hg5R3dzciCkjpxqyFkihnwyHLtDeEdl5T63mJzlfawoOx
         sXm9h169Ux4WaG7CUO88tFYIH5M3y7t5IsLNqluW1Tfpxkg9GlXxORfRa8pfylwfgZOk
         P5JBrtgA/LqJmuxoq1d7UCewQXPCWD9ozEmKB5PnMZtzExwDdu99xCdxkHjA5xexhiiA
         RxDLeOa0TrB5cPQFc1cILVCzEQhJu3GNzuuRo5woZy6HX3yfTGV2O9eQLDUWJzsrZbev
         nRBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=FmUMzWAF;
       spf=pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id s15-20020a056512214f00b004b58f5274c1si547108lfr.1.2022.12.28.06.39.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Dec 2022 06:39:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6F671B8170E;
	Wed, 28 Dec 2022 14:39:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0D5AC433D2;
	Wed, 28 Dec 2022 14:39:18 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id d267fddd (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 28 Dec 2022 14:39:15 +0000 (UTC)
Date: Wed, 28 Dec 2022 15:39:12 +0100
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
Message-ID: <Y6xVELL0ZYNc5Bip@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
 <Y6muh1E1fNOot+VZ@zx2c4.com>
 <Y6my+Oiz67G46snj@zx2c4.com>
 <Y6nSel5/wdnoSFpk@zx2c4.com>
 <Y6r09pm68oI7GMe1@zx2c4.com>
 <Y6uy4b71GX0epQsu@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6uy4b71GX0epQsu@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=FmUMzWAF;       spf=pass
 (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
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

On Wed, Dec 28, 2022 at 04:07:13AM +0100, Jason A. Donenfeld wrote:
> On Tue, Dec 27, 2022 at 02:36:54PM +0100, Jason A. Donenfeld wrote:
> > On Mon, Dec 26, 2022 at 05:57:30PM +0100, Jason A. Donenfeld wrote:
> > > On Mon, Dec 26, 2022 at 03:43:04PM +0100, Jason A. Donenfeld wrote:
> > > > On Mon, Dec 26, 2022 at 03:24:07PM +0100, Jason A. Donenfeld wrote:
> > > > > Hi,
> > > > >=20
> > > > > I'm currently stumped at the moment, so adding linux-mm@ and x86@=
. Still
> > > > > working on it though. Details of where I'm at are below the quote=
 below.
> > > > >=20
> > > > > On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrot=
e:
> > > > > > On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wr=
ote:
> > > > > > > Hi Eric,
> > > > > > >=20
> > > > > > > Replying to you from my telephone, and I'm traveling the next=
 two days,
> > > > > > > but I thought I should mention some preliminary results right=
 away from
> > > > > > > doing some termux compiles:
> > > > > > >=20
> > > > > > > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > > > > > > Hi Jason,
> > > > > > > >=20
> > > > > > > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfel=
d wrote:
> > > > > > > > > This reverts 3824e25db1 ("x86: disable rng seeding via se=
tup_data"), but
> > > > > > > > > for 7.2 rather than 7.1, now that modifying setup_data is=
 safe to do.
> > > > > > > > >=20
> > > > > > > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > > > > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > > > > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > > > > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > > > > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > > > > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > > > > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > > > > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > > > > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > > > > > > ---
> > > > > > > > >  hw/i386/microvm.c | 2 +-
> > > > > > > > >  hw/i386/pc_piix.c | 3 ++-
> > > > > > > > >  hw/i386/pc_q35.c  | 3 ++-
> > > > > > > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > > > > > > >=20
> > > > > > > >=20
> > > > > > > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with=
 some configs.  There
> > > > > > > > is no output at all.  I bisected it to this commit, and I v=
erified that the
> > > > > > > > following change to QEMU's master branch makes the problem =
go away:
> > > > > > > >=20
> > > > > > > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > > > > > > index b48047f50c..42f5b07d2f 100644
> > > > > > > > --- a/hw/i386/pc_piix.c
> > > > > > > > +++ b/hw/i386/pc_piix.c
> > > > > > > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_optio=
ns(MachineClass *m)
> > > > > > > >      pc_i440fx_machine_options(m);
> > > > > > > >      m->alias =3D "pc";
> > > > > > > >      m->is_default =3D true;
> > > > > > > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > > > > > > >  }
> > > > > > > >=20
> > > > > > > > I've attached the kernel config I am seeing the problem on.
> > > > > > > >=20
> > > > > > > > For some reason, the problem also goes away if I disable CO=
NFIG_KASAN.
> > > > > > > >=20
> > > > > > > > Any idea what is causing this?
> > > > > > >=20
> > > > > > > - Commenting out the call to parse_setup_data() doesn't fix t=
he issue.
> > > > > > >   So there's no KASAN issue with the actual parser.
> > > > > > >=20
> > > > > > > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> > > > > > >=20
> > > > > > > That makes me suspect that it's file size related, and QEMU o=
r the BIOS
> > > > > > > is placing setup data at an overlapping offset by accident, o=
r something
> > > > > > > similar.
> > > > > >=20
> > > > > > I removed the file systems from your config to bring the kernel=
 size
> > > > > > back down, and voila, it works, even with KASAN_INLINE. So perh=
aps I'm
> > > > > > on the right track here...
> > > > >=20
> > > > > QEMU sticks setup_data after the kernel image, the same as kexec-=
tools
> > > > > and everything else. Apparently, when the kernel image is large, =
the
> > > > > call to early_memremap(boot_params.hdr.setup_data, ...) returns a=
 value
> > > > > that points some place bogus, and the system crashes or does some=
thing
> > > > > weird. I haven't yet determined what this limit is, but in my cur=
rent
> > > > > test kernel, a value of 0x0000000001327650 is enough to make it p=
oint to
> > > > > rubbish.
> > > > >=20
> > > > > Is this expected? What's going on here?
> > > >=20
> > > > Attaching gdb to QEMU and switching it to physical memory mode
> > > > (`maintenance packet Qqemu.PhyMemMode:1 `) indicates that it
> > > > early_memremap is actually working fine and something *else* is at =
this
> > > > address? That's kinda weird... Is KASAN populating physical address=
es
> > > > immediately after the kernel image extremely early in boot? I'm see=
ing
> > > > the crash happen from early_reserve_memory()->
> > > > memblock_x86_reserve_range_setup_data(), which should be before
> > > > kasan_init() even runs. Is QEMU calculating kernel_size wrong, when=
 it
> > > > goes to determine where to put the setup_data data? But that's the =
same
> > > > calculation as used everywhere else, so hmm...
> > > >=20
> > > > Jason
> > >=20
> > > If bzImage is 15770544 bytes, it does not boot. If bzImage is 1564177=
6
> > > bytes, it does boot. So something is happening somewhat close to the
> > > 16MB mark?
> > >=20
> >=20
> > Okay, the issue is that it's being decompressed to an area that overlap=
s
> > the source. So for example in my test kernel:
> >=20
> > input_addr: 0x3f112bf
> > output_addr: 0x1000000
> > output_len: 0x3a5d7d8
> >=20
> > Since 0x3a5d7d8 + 0x1000000 > 0x3f112bf, eventually this corrupts the
> > setup_data at the end there.
> >=20
> > Now digging into what can be done about it.
>=20
> Not quite. input_addr doesn't matter, since setup_data still points to
> the old mapping.
>=20
> So the actual issue is:
>=20
> compressed_size: 	0xf028d4
> decompressed_size:      0x3a5d7d8
> setup_data:      	0x100000 + compressed_size
> output_addr:    	0x1000000 (this is LOAD_PHYSICAL_ADDR)
>=20
> Since `output_addr + decompressed_size > setup_data && output_addr <
> setup_data`, then it means the decompressor will write over setup_data.
>=20
> Note that this is also a problem for SETUP_DTB, so it's a longstanding
> bug.
>=20
> I'm experimenting now with appending lots of zeros between the kernel
> image and setup_data, so that the decompressor doesn't overwrite
> setup_data, but so far it's not working.
>=20
> Another option would be to have the build system warn when this is going
> to happen, and suggest that the user increase the value of
> CONFIG_PHYSICAL_START. This might be the best option...

I posted a patch:
https://lore.kernel.org/qemu-devel/20221228143831.396245-1-Jason@zx2c4.com/

We can move discussion on the topic over to that thread now.

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6xVELL0ZYNc5Bip%40zx2c4.com.
