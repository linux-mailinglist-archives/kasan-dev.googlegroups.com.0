Return-Path: <kasan-dev+bncBCLI747UVAFRBEO5U2OQMGQESF7R3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 39763656357
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 15:24:19 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id t125-20020a1faa83000000b003d0e23c1210sf2814822vke.10
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 06:24:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672064658; cv=pass;
        d=google.com; s=arc-20160816;
        b=QEhCObuqNX0m1kQcAccpkkzqYOMaDsn7MScoVLt2AF811OGwoTJLKyI3Mqmf4vGQmZ
         QHjLA+R1RQCQ1IaBsz1HbmLVCekq92HjOnZhHRIaOo+IYcZFedEZVXpBBC83ccQP6rcb
         fOi1GNL6s64abK3W0YMYLEyxyIWs9/KLTtodgv9JxYQx292V/ViPgIwmW42fUb9gXkjX
         lKHm6czKWeD6IdYwBYSoA/oM1soosbKbNLziTVmy/G7EMCyEa0BkPnfrnCovUTsWFOJ6
         N0qd6ay9GriGftV1dtD0EzKHHSSwSZm14RUe1odaZ6gUcZRekZfYPQjfxxiRsIG+aeFJ
         Stzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KZKjUD6GOxu2+2abtOXbJ2BeBf5ANBgprAYctLVQxJU=;
        b=tnDQdyfcZMmpnX4j2GQB933lVJ/AKZkyFndQEQajoXIFUQW1sW+fx8xE+b7H6Cmlm+
         blXr+Bn+13sBpGMj8JZZmBuLX2oUU3pzcEPJb8fbH3dX+49UnnPwaxTRErixF8BIOd3Y
         eV9hyrFRWxh2LKk0IPUqSoU268lo+eD1+OUfroXbSZKJqMl/aJ9APr4/5WcLpf7BwpOV
         8O2xKFYh06agBzwZX2g2pzkH2+GxTwoykhb9uyYkUzNmPPXcBgoBj9frKJWl1JyGJ9En
         QG7M/+YfM1kkYv8vRDzA1TRP6uEXF+//A2CIupu/MikdGLUk2WQAS1cT2GVa6Wbz7JXr
         8GLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=TGvK9CV+;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=KZKjUD6GOxu2+2abtOXbJ2BeBf5ANBgprAYctLVQxJU=;
        b=t2uRumLE6aG6D7bkQ2myjc4MQ56VP2daJkymxxJYhffzQ6NzenSyC14v3WPLUxGIZH
         icVyYiVZgZo2GTfwo6/aFQuhezGF2LXY3CCqVHqsImfxbk+qw18nvxxb1q6jKBfKX8CM
         tY1Vt1Ca53SB//G6D3kTr5lrWV0RvQ3Kstg0IWSx2RjePeRXyk72j8JscNQQVynExpqX
         GvL86Eq0eaPApYaCYYW+GVdTT8E4xjZbSfR9Cr7eK5dR2u9L6FV+FPdbK5bphoaWKICT
         TAW9QioC4SaftksPUEhF5910yBZ1b2qpIPyyodxN1Rp1Ma/NKGpXP3n8FskaZrtsM5rd
         EHMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KZKjUD6GOxu2+2abtOXbJ2BeBf5ANBgprAYctLVQxJU=;
        b=ecPLoLGkOijiKEKjEjR5k5q6DWfB31eVxy2yV/I5IYBspZKJWWTNeb1JZUr1x4QAMJ
         6R+Skr7p9xv6FQbvwPPvBJcChqeSO5QUaOI0ao/ZVnsOwVPxKipObHuRqhN5N6rpHTXL
         4K1FvEjTpoBud2EBtS2vvMX0Yx0UtoTTkVSf8I1GkD+0H0205ZYKaZdZitjbciQ5+WxP
         b6woRJkkaME7JbOrMH5Db3BQ9nyDdRyaQs/Rb3JoRzm1tskeSmqAXgaVt2FBVZ7KBHc2
         qwz94+aLhHcXiaRm/5MYadupd16/EQ/0wYCr0SwnXBGXib5TxeIxnFlxy5diFOdqvmT1
         3DvQ==
X-Gm-Message-State: AFqh2kqzSWX7SaZUN/1r9XCebzK3QShHRC9qRePEUR7nzyS2+4h7S/YM
	HfrHs2tR6Vt37slbCd+pDhE=
X-Google-Smtp-Source: AMrXdXtw3R1vppVsja10cO2/DMw3bNNiKOFUCAQ7dxzZ55T1jb0RQPj/wlPPhYSV1wWu6afatPzDmQ==
X-Received: by 2002:ab0:1e86:0:b0:42f:555b:e4e0 with SMTP id o6-20020ab01e86000000b0042f555be4e0mr1610248uak.19.1672064657952;
        Mon, 26 Dec 2022 06:24:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d61b:0:b0:3b0:d6ec:8cdc with SMTP id n27-20020a67d61b000000b003b0d6ec8cdcls2646586vsj.2.-pod-prod-gmail;
 Mon, 26 Dec 2022 06:24:17 -0800 (PST)
X-Received: by 2002:a67:fe52:0:b0:3b1:2b5c:4e7a with SMTP id m18-20020a67fe52000000b003b12b5c4e7amr6834586vsr.32.1672064657357;
        Mon, 26 Dec 2022 06:24:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672064657; cv=none;
        d=google.com; s=arc-20160816;
        b=jRNcqvOzCRBillNBP5bk/Yj8UKe1VK0OM/yESqhWcV3u6bKZo1KJLqUWBIGjlCFmLw
         v+linuRJZno2lTMZg5z0TxRUfUqXCdtDkRz12TsFn8BmTkdw12ubKjdy/tr/J+JaTma8
         yg465Gq2sYlteZQLLMoqhI6xcefZTPXhJR7CwS23RkwR1cUVicaYb/xt1v+fvarSGQMx
         iAFTIwmL68bX/ntveDVfGFgQ2Yq0vlixWaDZmt0nYHKZcxu/BM5mbxSKuqFHyl5esg50
         EQ5aHSzvauv3vina6ybxzX7TZ84bxTZHXzlguSW/1mJINnbCxje95JNftTbB7HhN1P0D
         kTZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+PjVgheTmRbQKAuExj3xzO22Ben4VI5teURA2yxJhLo=;
        b=r0ZfhMh/5/yBc28mu7aAUUnSTGKixQx0q/sEWW7+yXkJoUlNTGWvb0Nk+l7d9ggI8J
         XVdSSzv7D5ggM1I1pNBlixaUG2nm1cHQwtU6LzjwcRLK2eWrh958ijZE+jpI4dkEANHV
         y4wNEM4O62YBhuZcIiFaWgQGHMh08Zv72VUs5To99G1V7+/4gB2wFfEZqGbXdjAclILg
         Em5x1zaG03i6LJMDGLmvBF0r9/DoOS599RD3ae1gOxppsUJ3xa8sUeb5F8gHrBvfBDoJ
         XzDqRP7OM9DwHEBYAHvLrZk1lJvZ2P5CXKHSAdvF4kdoqAC45ZhoAN03XDfAUHIiLZPD
         btlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=TGvK9CV+;
       spf=pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y15-20020a05620a0e0f00b007024a823e59si693413qkm.1.2022.12.26.06.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Dec 2022 06:24:17 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C499460EA7;
	Mon, 26 Dec 2022 14:24:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A2A3CC433D2;
	Mon, 26 Dec 2022 14:24:14 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 544c39fb (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Dec 2022 14:24:11 +0000 (UTC)
Date: Mon, 26 Dec 2022 15:24:07 +0100
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
Message-ID: <Y6muh1E1fNOot+VZ@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
 <Y6Z+WpqN59ZjIKkk@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6Z+WpqN59ZjIKkk@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=TGvK9CV+;       spf=pass
 (google.com: domain of srs0=dxcw=4y=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Dxcw=4Y=zx2c4.com=Jason@kernel.org";
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

Hi,

I'm currently stumped at the moment, so adding linux-mm@ and x86@. Still
working on it though. Details of where I'm at are below the quote below.

On Sat, Dec 24, 2022 at 05:21:46AM +0100, Jason A. Donenfeld wrote:
> On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrote:
> > Hi Eric,
> >=20
> > Replying to you from my telephone, and I'm traveling the next two days,
> > but I thought I should mention some preliminary results right away from
> > doing some termux compiles:
> >=20
> > On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > > Hi Jason,
> > >=20
> > > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld wrote:
> > > > This reverts 3824e25db1 ("x86: disable rng seeding via setup_data")=
, but
> > > > for 7.2 rather than 7.1, now that modifying setup_data is safe to d=
o.
> > > >=20
> > > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > > ---
> > > >  hw/i386/microvm.c | 2 +-
> > > >  hw/i386/pc_piix.c | 3 ++-
> > > >  hw/i386/pc_q35.c  | 3 ++-
> > > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > > >=20
> > >=20
> > > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with some conf=
igs.  There
> > > is no output at all.  I bisected it to this commit, and I verified th=
at the
> > > following change to QEMU's master branch makes the problem go away:
> > >=20
> > > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > > index b48047f50c..42f5b07d2f 100644
> > > --- a/hw/i386/pc_piix.c
> > > +++ b/hw/i386/pc_piix.c
> > > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options(Machine=
Class *m)
> > >      pc_i440fx_machine_options(m);
> > >      m->alias =3D "pc";
> > >      m->is_default =3D true;
> > > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> > >  }
> > >=20
> > > I've attached the kernel config I am seeing the problem on.
> > >=20
> > > For some reason, the problem also goes away if I disable CONFIG_KASAN=
.
> > >=20
> > > Any idea what is causing this?
> >=20
> > - Commenting out the call to parse_setup_data() doesn't fix the issue.
> >   So there's no KASAN issue with the actual parser.
> >=20
> > - Using KASAN_OUTLINE rather than INLINE does fix the issue!
> >=20
> > That makes me suspect that it's file size related, and QEMU or the BIOS
> > is placing setup data at an overlapping offset by accident, or somethin=
g
> > similar.
>=20
> I removed the file systems from your config to bring the kernel size
> back down, and voila, it works, even with KASAN_INLINE. So perhaps I'm
> on the right track here...

QEMU sticks setup_data after the kernel image, the same as kexec-tools
and everything else. Apparently, when the kernel image is large, the
call to early_memremap(boot_params.hdr.setup_data, ...) returns a value
that points some place bogus, and the system crashes or does something
weird. I haven't yet determined what this limit is, but in my current
test kernel, a value of 0x0000000001327650 is enough to make it point to
rubbish.

Is this expected? What's going on here?

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6muh1E1fNOot%2BVZ%40zx2c4.com.
