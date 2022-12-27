Return-Path: <kasan-dev+bncBCLI747UVAFRBAHKVOOQMGQEUE6XJFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BC60656B61
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Dec 2022 14:37:05 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id g3-20020a2e9cc3000000b0027760138bb9sf3088649ljj.23
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Dec 2022 05:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672148224; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpkPEox6ZdrQ8ndJtuVH/OD10o3Ga/iQ+ZC6+EmapnHXfLdIpp9qi3CGP8zdsb02ii
         y8t/xv0Dd8njA+8SjIAn8c88SkcD9WvOgSLBZquxE1Q+URxwRhBRHuKWOxI+GqyddqKs
         2JvvFYoGtNAuNaKuxeSoehQNUqTrhWeAfL1SMZR59pVMkbfEnqtbEB8x6O+M3X//jpjX
         uSMD5/+RWauThxpy3rS47F3GfTLKWg4jus/POpyMlJuZb2QDVYMEvBjsMXUGMitxCHCC
         8h7BUxLTN0/legWA6MbCvcozapIkwlVnd1u77U8rI+82e23/TVCHB7tJXbfO4q0am2NE
         ATkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=RJnTLRNSlsLybQtIK787RrEoPBP70QdH2FUvlBITwLk=;
        b=DmAViIOND7tYkV0YdZ8iHC630r4gt0uEFssMHLcYdYOylJtflOXVUh+E8yHheiGAHq
         CEtc0ZlfHp2WD35MfwBFjllj3THH+zsxHxJUNbYGiVPdD/Pm1rYm++qLu2E3sYe4msom
         5y1cdQcmkx5AKkh8qI/pL4fspKZ6TEu9m69alEwjHdV/OrJICQdMis66pK95x2xcft2I
         pF5zqUcyJRPJhBud1cE8hG/2yE9AEx7wWQLz2dQ7JSpLhxdb3d8pRIE9ik64zB85c8Ry
         0a2byqqib163fKuvsViWd44tUBHGfj2Ft9yxavCiqPgUDNWUNBHCLqOP82+KL4eM4x0x
         3Rsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=HsbP5xOE;
       spf=pass (google.com: domain of srs0=y2yx=4z=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=Y2YX=4Z=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=RJnTLRNSlsLybQtIK787RrEoPBP70QdH2FUvlBITwLk=;
        b=gk18UbAfOpP4ktU/aDc0aIpkQSR0qD4x9fTvgagUpOKt6q88wHwbh1hFiNvySc/K5L
         Dk8IQYYeexYtPUb4sy7SK34oESo8fAcXdgKlU3c9YnlwBvvG2m5srxSBTCP1wIJVtyhK
         s0gNe81r9Az7RRJYVSaVDlYdmCD/PhCEK+bGXu4uH0EUG2Lk/qkOe1uA7vjuR/BL5t2m
         CDKSzaiBmOde3csNy1OGNnNNqQwM3xPHwee10JGG+pynVuJqfCerWm8sYBJO/QfozCH4
         2wJQAMbZQnrEBx3kPZSttMSdn8ks1/s/BsbkScRh4yS/OcjY+4Wyn9YcR4/7E5zzPsaU
         y04g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RJnTLRNSlsLybQtIK787RrEoPBP70QdH2FUvlBITwLk=;
        b=GoI50NzpaVW8jiQofLkMCPloSiH0Z+Hdic/MISYMhBPISjTC6Ho2NycVSfAVPnDl3J
         0v4e2VSnTxAEaPQK6x7itUOAg86vGc5R9o+QcZmy91CfquFNJy4j80YKtvJx3vR38sTr
         hfqxIozIVVcGuAHZGjiMUgsq32L0/n896LogNN8JvOhb/C+VC3MXo6ICNRl71DAHEz77
         Bp48pOe8SKNobZmv8elJs+W25zLgF8Kt8V70h9RdvAv2z3iNfPICvr6yR5Cv50EWSg99
         PJ6zE/QNM5pJ9OWgy3qYRLYpdUe8UP1p5DzbzeiSwZYstp77nWYcKoYxqY56h9znVVea
         Z43Q==
X-Gm-Message-State: AFqh2kpsmmE2gu+zSvDEnzBjXbX9uhKPpM8ABV4DFU6Mx5QF78srOcD5
	BDacQT6uNqaVD9gD2GEs4x4=
X-Google-Smtp-Source: AMrXdXtt5vFAEGEbxz4HKZcOilLHtu+aVTyVT4S/mNECYA+qfQpIWStPbtcxy+nGOSl8Cnwbww8Jtg==
X-Received: by 2002:ac2:539c:0:b0:4cb:cbf:d2e3 with SMTP id g28-20020ac2539c000000b004cb0cbfd2e3mr217590lfh.42.1672148224539;
        Tue, 27 Dec 2022 05:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1570920lfr.2.-pod-prod-gmail; Tue, 27
 Dec 2022 05:37:03 -0800 (PST)
X-Received: by 2002:a05:6512:24e:b0:4b5:82f1:7f3d with SMTP id b14-20020a056512024e00b004b582f17f3dmr10898050lfo.58.1672148223365;
        Tue, 27 Dec 2022 05:37:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672148223; cv=none;
        d=google.com; s=arc-20160816;
        b=o637fwRsk8k9NgAM1loB++yuqWXo2Qz66j7MLnke9nQ7jJaLVBw9e37ZJ1u4fKk7vI
         jEp4pmMT5+Au/A+6gfvqTYLSn3r5yQS2iUXB31BUH7Tqmi8Iz2YZ4H2QvLeHlVtyPiOe
         Uid9r7AI0mIOktBEtMOWLt7aT+aMvmic7FAwD6BdZCiXhQKYLvVgqADa7VvGv80h6KBo
         UQxdCr94EZxMWD18I2qTXMgYtBad5UqmvCX3CFDp4op6QwqbMebXBM51Cj2kgGHF6ZL/
         JBI8cu3f7JrkN4c1kcLtHhHiq6ni5Fm3ZncnQ+wNObSpY9AvIYf6ZIQTJ/bxSlW7Ip0z
         dx7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=A6Tpz+0nHRofFNKNlRnj1MkH2P/4zYKJXoIQP8XxImY=;
        b=M6A/0kI5EQZpSrs9IyvJaRu58ppx3fnyESY52iXqwOxz4zLc+Znx7h6OTXMVDzI1nQ
         0w4IoWt+t/zjYu32V8Y/Fb79F5ZECCq5n/jtW6OgKBdUwG0KOPwpg2ow4G16S73odD6b
         3tu3OSJ04DeSdQnxwbZRlVD1ksBhcXIWOtqbfZ9XX7vAiWU7KiFmanEdETfxBvnqrhQI
         diFqfiZ9BUc/VTS0I8OAyk8g4nJNnxaxYGfA+7g0vTN2RPinokS4phu7pnNJltqIO2Ll
         9nyHnkg3Ee+jEj3e6umF6UJZeMhi+K7RKowK2SwFNBJwhNx9C1NpJvBdKKp3VvsOL/iw
         9xEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=HsbP5xOE;
       spf=pass (google.com: domain of srs0=y2yx=4z=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=Y2YX=4Z=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c17-20020ac25f71000000b004b4f4360405si447213lfc.12.2022.12.27.05.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Dec 2022 05:37:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y2yx=4z=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8FB8FB80FEA;
	Tue, 27 Dec 2022 13:37:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B5AE9C433D2;
	Tue, 27 Dec 2022 13:36:59 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 217de33c (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Tue, 27 Dec 2022 13:36:57 +0000 (UTC)
Date: Tue, 27 Dec 2022 14:36:54 +0100
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
Message-ID: <Y6r09pm68oI7GMe1@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
 <Y6muh1E1fNOot+VZ@zx2c4.com>
 <Y6my+Oiz67G46snj@zx2c4.com>
 <Y6nSel5/wdnoSFpk@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6nSel5/wdnoSFpk@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=HsbP5xOE;       spf=pass
 (google.com: domain of srs0=y2yx=4z=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=Y2YX=4Z=zx2c4.com=Jason@kernel.org";
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

On Mon, Dec 26, 2022 at 05:57:30PM +0100, Jason A. Donenfeld wrote:
> On Mon, Dec 26, 2022 at 03:43:04PM +0100, Jason A. Donenfeld wrote:
> > On Mon, Dec 26, 2022 at 03:24:07PM +0100, Jason A. Donenfeld wrote:
> > > Hi,
> > >=20
> > > I'm currently stumped at the moment, so adding linux-mm@ and x86@. St=
ill
> > > working on it though. Details of where I'm at are below the quote bel=
ow.
> > >=20
> > > On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrote:
> > > > On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrote:
> > > > > Hi Eric,
> > > > >=20
> > > > > Replying to you from my telephone, and I'm traveling the next two=
 days,
> > > > > but I thought I should mention some preliminary results right awa=
y from
> > > > > doing some termux compiles:
> > > > >=20
> > > > > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > > > > Hi Jason,
> > > > > >=20
> > > > > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld wr=
ote:
> > > > > > > This reverts 3824e25db1 ("x86: disable rng seeding via setup_=
data"), but
> > > > > > > for 7.2 rather than 7.1, now that modifying setup_data is saf=
e to do.
> > > > > > >=20
> > > > > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > > > > ---
> > > > > > >  hw/i386/microvm.c | 2 +-
> > > > > > >  hw/i386/pc_piix.c | 3 ++-
> > > > > > >  hw/i386/pc_q35.c  | 3 ++-
> > > > > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > > > > >=20
> > > > > >=20
> > > > > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with som=
e configs.  There
> > > > > > is no output at all.  I bisected it to this commit, and I verif=
ied that the
> > > > > > following change to QEMU's master branch makes the problem go a=
way:
> > > > > >=20
> > > > > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > > > > index b48047f50c..42f5b07d2f 100644
> > > > > > --- a/hw/i386/pc_piix.c
> > > > > > +++ b/hw/i386/pc_piix.c
> > > > > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options(M=
achineClass *m)
> > > > > >      pc_i440fx_machine_options(m);
> > > > > >      m->alias =3D "pc";
> > > > > >      m->is_default =3D true;
> > > > > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > > > > >  }
> > > > > >=20
> > > > > > I've attached the kernel config I am seeing the problem on.
> > > > > >=20
> > > > > > For some reason, the problem also goes away if I disable CONFIG=
_KASAN.
> > > > > >=20
> > > > > > Any idea what is causing this?
> > > > >=20
> > > > > - Commenting out the call to parse_setup_data() doesn't fix the i=
ssue.
> > > > >   So there's no KASAN issue with the actual parser.
> > > > >=20
> > > > > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> > > > >=20
> > > > > That makes me suspect that it's file size related, and QEMU or th=
e BIOS
> > > > > is placing setup data at an overlapping offset by accident, or so=
mething
> > > > > similar.
> > > >=20
> > > > I removed the file systems from your config to bring the kernel siz=
e
> > > > back down, and voila, it works, even with KASAN_INLINE. So perhaps =
I'm
> > > > on the right track here...
> > >=20
> > > QEMU sticks setup_data after the kernel image, the same as kexec-tool=
s
> > > and everything else. Apparently, when the kernel image is large, the
> > > call to early_memremap(boot_params.hdr.setup_data, ...) returns a val=
ue
> > > that points some place bogus, and the system crashes or does somethin=
g
> > > weird. I haven't yet determined what this limit is, but in my current
> > > test kernel, a value of 0x0000000001327650 is enough to make it point=
 to
> > > rubbish.
> > >=20
> > > Is this expected? What's going on here?
> >=20
> > Attaching gdb to QEMU and switching it to physical memory mode
> > (`maintenance packet Qqemu.PhyMemMode:1 `) indicates that it
> > early_memremap is actually working fine and something *else* is at this
> > address? That's kinda weird... Is KASAN populating physical addresses
> > immediately after the kernel image extremely early in boot? I'm seeing
> > the crash happen from early_reserve_memory()->
> > memblock_x86_reserve_range_setup_data(), which should be before
> > kasan_init() even runs. Is QEMU calculating kernel_size wrong, when it
> > goes to determine where to put the setup_data data? But that's the same
> > calculation as used everywhere else, so hmm...
> >=20
> > Jason
>=20
> If bzImage is 15770544 bytes, it does not boot. If bzImage is 15641776
> bytes, it does boot. So something is happening somewhat close to the
> 16MB mark?
>=20

Okay, the issue is that it's being decompressed to an area that overlaps
the source. So for example in my test kernel:

input_addr: 0x3f112bf
output_addr: 0x1000000
output_len: 0x3a5d7d8

Since 0x3a5d7d8 + 0x1000000 > 0x3f112bf, eventually this corrupts the
setup_data at the end there.

Now digging into what can be done about it.

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6r09pm68oI7GMe1%40zx2c4.com.
