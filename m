Return-Path: <kasan-dev+bncBCLI747UVAFRB3HFV2OQMGQE6WF35FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF29E65723E
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Dec 2022 04:07:25 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id bq2-20020a056830388200b00672e4a07168sf8408087otb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Dec 2022 19:07:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672196844; cv=pass;
        d=google.com; s=arc-20160816;
        b=X3LYSUsn5A6tgcp1hgL6uPDg4hB7ehCDhb/Gt/Q24WL3C/kPbRgXT6xY+E7hElOXIE
         ixbGi/ouTf8vWPZsqOXV1dquPeYGu9RiG1MjA0OhRe5lkWThCRRT0Ga+Tsr0d0OVH9rI
         Df0t53GroBhAwgLHOFRuOXchvvzLzLyN7eOZPift6FJ6rrCv4Nw2DPiZptesm0X2Jk37
         yexcy9sf+OTEvkxtoD8o+NL04okKmgHM47mP0Sp5kt+xcrSmf+8Btu6SZ5FPOAEiiR9s
         slEp+0TIh6ZW44n86HouDiP4C+Pgnjr3rR5qunNOAnOSd+Dbh1zYMjcenpxNP2NFil9a
         UPLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=n97/ndmMSYra1yxINd0WNwC42RZ4snta6IFp9nV65Vc=;
        b=jgGyVZvdOZKrliQXvMkEn2g2CY+LIykkotcqRgQIsYblfP/7crS06QlZWieQy5nAkO
         VGcNbJKO3icfLKNOJuUwSJuKqFvp166eD8fkuL2B2fIMn/DX2PPVD+RH7Dxie0lt3l2q
         syxZll+O7U6L9yZswl3VcfR1OYNJOtJKK3fso/jwfL0j7FTPkm5KZTMoVuAjkqM4hDyq
         ngFJc8+ZkeCNrfkadJuwKQTjgxqB+YqAJLGgWPyRFRtOuupmoVOdx2+CUeP83huuelLf
         VQt6IRexiFjIHfl2HyoADtYIuqH1EaB7sKGzl5rbBs/Glzh3SIxTm/kdIR6iJTO4lYlq
         Kqpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="Y/y+c61q";
       spf=pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=n97/ndmMSYra1yxINd0WNwC42RZ4snta6IFp9nV65Vc=;
        b=kbhwxgQZeDunYYRwiAdic4diYkxtToPG0Jz17qM1g6K6mfWkQr8Jlk6oTNSkJYEC56
         v14rZ6/yOdddVM0XGyyH266F0hGOup7CS4HydQmAv167sYGrbBk5DDecLF10afRA0F7Z
         2VjELwvzZ7NaiyHHl8klPZhjnCsMEQEjtnALELp9x65pVy0mfL6y80VU9K2VH0QVRcEI
         RfuhOKG08uh5RrtK/qdFSbCmhtF9Rrtp4MHaC9M8+5MlQAMX9IAwB99/h6NUV+jH7olm
         atpfq5sKBG7Q7CMNkDGUONmYTsKTAd1S5AxhKOKunZiYhG9c30GoEtiWsgtvoUSEw0wN
         7ufQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=n97/ndmMSYra1yxINd0WNwC42RZ4snta6IFp9nV65Vc=;
        b=Upm85IkrCLZqr6b+AINht0jWhJ1r9PY7D+HoeiU62DctARO4pUEhqL2+YA0grrk3dy
         wTze/KD5xrSPnDpxBoNU0+3kVd2y8jT1MuEsWwWDStTf8McEWu6z9UTf0nzBdnDVCHCw
         lp+5VP7tqJKLlFt8YxtHOFNJltUEwxuaeMxUEhmxILxApVhUDiDgSZg0belPloj75SqM
         kVPviGO0QjUmk4DfPHPaYtHCAj544D6BNQbHJxTtFGpyPTr6SCgH5a4n9vg4z6L/FmVY
         te9CHDXxAi2z1QwZsfpWrmuk1aeLWU1xRzvXo6Z5nGpxpZ/3PKGjbFM1MjxXkwZrv4Gl
         t9Ew==
X-Gm-Message-State: AFqh2kokK2u+tPnZdAfkwd5todQ+McSAJcdPay8o19zC/+9kRMA05afR
	mvchyyKHGKnrfQaNRyZ/NNE=
X-Google-Smtp-Source: AMrXdXuCMdgV5/tRjYxsfI4XcBkjpGBUxdyPDp2QFDHYtIJID8rQwFoOXZJ90oBuirCk/KEBoBsNLA==
X-Received: by 2002:a4a:bb86:0:b0:4c9:f4e1:afbf with SMTP id h6-20020a4abb86000000b004c9f4e1afbfmr838280oop.44.1672196844293;
        Tue, 27 Dec 2022 19:07:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:22fc:b0:668:d7a2:6181 with SMTP id
 t28-20020a05683022fc00b00668d7a26181ls2416093otc.11.-pod-prod-gmail; Tue, 27
 Dec 2022 19:07:24 -0800 (PST)
X-Received: by 2002:a9d:738e:0:b0:670:4588:f8c4 with SMTP id j14-20020a9d738e000000b006704588f8c4mr11671656otk.18.1672196843891;
        Tue, 27 Dec 2022 19:07:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672196843; cv=none;
        d=google.com; s=arc-20160816;
        b=jOuwWut2jcK8yrTu5KxGBEtyj6J7toK3Ik6/oXnNMyJMR9/IthPoJOtVg+/TNH2qfw
         HVgw52aZ19Qha+sAXs5T7Iy0kICToDUVMRPF7GhzZoBcAKKRQOZKsqKQmA0jco895ENr
         V3G5XMWw5e1Q/xsifuHvridOZWY7zASzt1iKUk+PaxBs9ZiCSUC2lax7H2jrpf1TxidO
         z/+luvHAVjmLp5Er5SK8rBkjcdFt4edodklmhIe6FKw/j1xrakJvoJ1XukUro+2Ot132
         lph9lbTntge8TevNA/hrpkv7cC1VtToO4AjyDvR8PEVr770bKjtecgu/zfFGfaFORk5u
         BpEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1jNWkU54yw6S78YLSE3k9v90RmAGeElEG1sJBoSd7sU=;
        b=z2mQsRE+G5kKPheoo4zbOWyvZPFOJ9RFtEf4125PyrxSA/uxnOTqXy8Zb7GDqAMwJ5
         z4s2j2kAnfeismnJW5sEQMOvz76cS9w7OKRwOJyuDkr8yFAjwvxL642opgPv+V1yXDpc
         IqZ4CC3/x4i/jPVOgkrYgOjML8vzVj5YcX4XZjGfu6iz3ZlxfWNpJ93cgr9FxpIwIBLD
         GgRe+9Pz6Qt6p2sp2d22bfbYAz4gQvF2HfdThZoUUoOoATB1GdbGCm75nCE1MprF/ipR
         TcB2B6RH00bV+37EaLvs3lyRlVex6kco1Te7SueRuLJ669N/AKRRm3B6ptyWLEmq5deD
         VjFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="Y/y+c61q";
       spf=pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 14-20020a9d010e000000b0067054a075b7si1497089otu.2.2022.12.27.19.07.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Dec 2022 19:07:23 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9189261274;
	Wed, 28 Dec 2022 03:07:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6FB95C433EF;
	Wed, 28 Dec 2022 03:07:21 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 9c2ced28 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 28 Dec 2022 03:07:18 +0000 (UTC)
Date: Wed, 28 Dec 2022 04:07:13 +0100
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
Message-ID: <Y6uy4b71GX0epQsu@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
 <Y6muh1E1fNOot+VZ@zx2c4.com>
 <Y6my+Oiz67G46snj@zx2c4.com>
 <Y6nSel5/wdnoSFpk@zx2c4.com>
 <Y6r09pm68oI7GMe1@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6r09pm68oI7GMe1@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b="Y/y+c61q";       spf=pass
 (google.com: domain of srs0=vu6c=42=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=vu6c=42=zx2c4.com=Jason@kernel.org";
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

On Tue, Dec 27, 2022 at 02:36:54PM +0100, Jason A. Donenfeld wrote:
> On Mon, Dec 26, 2022 at 05:57:30PM +0100, Jason A. Donenfeld wrote:
> > On Mon, Dec 26, 2022 at 03:43:04PM +0100, Jason A. Donenfeld wrote:
> > > On Mon, Dec 26, 2022 at 03:24:07PM +0100, Jason A. Donenfeld wrote:
> > > > Hi,
> > > >=20
> > > > I'm currently stumped at the moment, so adding linux-mm@ and x86@. =
Still
> > > > working on it though. Details of where I'm at are below the quote b=
elow.
> > > >=20
> > > > On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrote:
> > > > > On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrot=
e:
> > > > > > Hi Eric,
> > > > > >=20
> > > > > > Replying to you from my telephone, and I'm traveling the next t=
wo days,
> > > > > > but I thought I should mention some preliminary results right a=
way from
> > > > > > doing some termux compiles:
> > > > > >=20
> > > > > > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > > > > > Hi Jason,
> > > > > > >=20
> > > > > > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld =
wrote:
> > > > > > > > This reverts 3824e25db1 ("x86: disable rng seeding via setu=
p_data"), but
> > > > > > > > for 7.2 rather than 7.1, now that modifying setup_data is s=
afe to do.
> > > > > > > >=20
> > > > > > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > > > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > > > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > > > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > > > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > > > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > > > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > > > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > > > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > > > > > ---
> > > > > > > >  hw/i386/microvm.c | 2 +-
> > > > > > > >  hw/i386/pc_piix.c | 3 ++-
> > > > > > > >  hw/i386/pc_q35.c  | 3 ++-
> > > > > > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > > > > > >=20
> > > > > > >=20
> > > > > > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with s=
ome configs.  There
> > > > > > > is no output at all.  I bisected it to this commit, and I ver=
ified that the
> > > > > > > following change to QEMU's master branch makes the problem go=
 away:
> > > > > > >=20
> > > > > > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > > > > > index b48047f50c..42f5b07d2f 100644
> > > > > > > --- a/hw/i386/pc_piix.c
> > > > > > > +++ b/hw/i386/pc_piix.c
> > > > > > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options=
(MachineClass *m)
> > > > > > >      pc_i440fx_machine_options(m);
> > > > > > >      m->alias =3D "pc";
> > > > > > >      m->is_default =3D true;
> > > > > > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > > > > > >  }
> > > > > > >=20
> > > > > > > I've attached the kernel config I am seeing the problem on.
> > > > > > >=20
> > > > > > > For some reason, the problem also goes away if I disable CONF=
IG_KASAN.
> > > > > > >=20
> > > > > > > Any idea what is causing this?
> > > > > >=20
> > > > > > - Commenting out the call to parse_setup_data() doesn't fix the=
 issue.
> > > > > >   So there's no KASAN issue with the actual parser.
> > > > > >=20
> > > > > > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> > > > > >=20
> > > > > > That makes me suspect that it's file size related, and QEMU or =
the BIOS
> > > > > > is placing setup data at an overlapping offset by accident, or =
something
> > > > > > similar.
> > > > >=20
> > > > > I removed the file systems from your config to bring the kernel s=
ize
> > > > > back down, and voila, it works, even with KASAN_INLINE. So perhap=
s I'm
> > > > > on the right track here...
> > > >=20
> > > > QEMU sticks setup_data after the kernel image, the same as kexec-to=
ols
> > > > and everything else. Apparently, when the kernel image is large, th=
e
> > > > call to early_memremap(boot_params.hdr.setup_data, ...) returns a v=
alue
> > > > that points some place bogus, and the system crashes or does someth=
ing
> > > > weird. I haven't yet determined what this limit is, but in my curre=
nt
> > > > test kernel, a value of 0x0000000001327650 is enough to make it poi=
nt to
> > > > rubbish.
> > > >=20
> > > > Is this expected? What's going on here?
> > >=20
> > > Attaching gdb to QEMU and switching it to physical memory mode
> > > (`maintenance packet Qqemu.PhyMemMode:1 `) indicates that it
> > > early_memremap is actually working fine and something *else* is at th=
is
> > > address? That's kinda weird... Is KASAN populating physical addresses
> > > immediately after the kernel image extremely early in boot? I'm seein=
g
> > > the crash happen from early_reserve_memory()->
> > > memblock_x86_reserve_range_setup_data(), which should be before
> > > kasan_init() even runs. Is QEMU calculating kernel_size wrong, when i=
t
> > > goes to determine where to put the setup_data data? But that's the sa=
me
> > > calculation as used everywhere else, so hmm...
> > >=20
> > > Jason
> >=20
> > If bzImage is 15770544 bytes, it does not boot. If bzImage is 15641776
> > bytes, it does boot. So something is happening somewhat close to the
> > 16MB mark?
> >=20
>=20
> Okay, the issue is that it's being decompressed to an area that overlaps
> the source. So for example in my test kernel:
>=20
> input_addr: 0x3f112bf
> output_addr: 0x1000000
> output_len: 0x3a5d7d8
>=20
> Since 0x3a5d7d8 + 0x1000000 > 0x3f112bf, eventually this corrupts the
> setup_data at the end there.
>=20
> Now digging into what can be done about it.

Not quite. input_addr doesn't matter, since setup_data still points to
the old mapping.

So the actual issue is:

compressed_size: 	0xf028d4
decompressed_size:      0x3a5d7d8
setup_data:      	0x100000 + compressed_size
output_addr:    	0x1000000 (this is LOAD_PHYSICAL_ADDR)

Since `output_addr + decompressed_size > setup_data && output_addr <
setup_data`, then it means the decompressor will write over setup_data.

Note that this is also a problem for SETUP_DTB, so it's a longstanding
bug.

I'm experimenting now with appending lots of zeros between the kernel
image and setup_data, so that the decompressor doesn't overwrite
setup_data, but so far it's not working.

Another option would be to have the build system warn when this is going
to happen, and suggest that the user increase the value of
CONFIG_PHYSICAL_START. This might be the best option...

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6uy4b71GX0epQsu%40zx2c4.com.
