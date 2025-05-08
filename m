Return-Path: <kasan-dev+bncBDCPL7WX3MKBBQGE6PAAMGQEWBTF4KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B9B3AB00C5
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 18:56:34 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6f53d97079asf38765876d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 09:56:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746723393; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mr4cfuhlwd40Z9uQEC38Kf/nOBXe0oG7rOUCYWiO6MYufgermJt4+evOkAXW3t2STd
         Xmp1kY34tdFgHXJYkC0Sbudm2n1Kar/m9H0CCeDgfbPVYDA34Emi3wFNdlMWwTgeYjN5
         4W1bdy0D1peLFI4WMqLhil4qXScAnFom6z/+7BdlvhwJjQlCkO0OHX27gSuOFTfCnL2m
         nPD0bx2QnnBoxuiWEe65lTgcLLyCkTIPQIDjVEbKPr6V7Nv4qBBu/Mu0G2ItSTA+xZPL
         zmU4YfpiaJSdjQ/nB1BWBCzzVhOHeQUC7nGKUc6aeSeWzDZtRLkdkk1G4rcLJukGlYau
         bqqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TgSuoespREYVemriK+Ucnzwc0I2hvPpUrj26ZnUSeUI=;
        fh=WaQctjTx7IiUz14IUkjVly+dIzQ4J8+1CEHENufxon8=;
        b=OfXVMOaomrbNrlNcqEtU0dRLLV4A1TVinVV8nQH0hMFL/ou72+oWn/4zRoMZXrXgLj
         I4ajjRwo0ECjrjO2/K2mj+4ZHUv/kwg/nicRYS6G9KInzK04/pLW7YEPJIqr9KzPoQvQ
         uG5yPlwqSQWr7+jOtlXR6ztIUx7C8KATjWodM8OSMiLqjE/AGaqNJK3NXIXE6XqZZTWk
         d2v5N16P2RBDNn4ax/xobPjp4KaaeKyXAXK3RD2/gdvq1kWHJGB9XkbVT5JrlwHVQZ0M
         mS4NQ9ieARJyDzVOT8vzCwvc1bBl4irrWLhtY8zvAnxJbsZ4ajW/CM1+m/AF9dCiWgCn
         C/DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ChcionI4;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746723393; x=1747328193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TgSuoespREYVemriK+Ucnzwc0I2hvPpUrj26ZnUSeUI=;
        b=IfTf0YANGEakWzwwmvNd/Nb7uoqO/6HDYZ6shdfIz0jI4/GFjLfmaH57c6gDfyj4sh
         ZAXJY3YuqKbEV/89CkEcyBjjB79rbWOjZxRoYv6S2Y97pur+iaC/qKg/Fq44W/77ArCD
         p5T2DmHEBisZBymStTF3HT4+oVIzk+s+PuGEcoFOjonsLpbVulzaCSSjVfEm84GZ1Vmq
         KA2n523ER5VurGH4leiHeiJRj63QVOqyB7hDVV4FDGnOLpMClXBpLmP3sY9d6NirNljF
         D8G7ZqI8LzFmLbO5c8kGL8/hJsUBsslp4cJJH+ZyReo1gz66o/5HCHw4JPoETEebxzBl
         l68Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746723393; x=1747328193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=TgSuoespREYVemriK+Ucnzwc0I2hvPpUrj26ZnUSeUI=;
        b=QpHOxhQfCK7doDlv4+UE/F12scyH2VzR3qieFmolDHFWb/Friuz+Jrs3ps9UI1v8ss
         nm7hSrDkGWAIHu9edPiF43N9I1M+cwgaDy93YC1jQAyOh+xvUaZ8lLJ4XooZYco/RQ+I
         Ajru9H4tim9nBOlcWHhx0KPXR5938CI3233tisrZRTC8nOPphH+SXuVGYwe3vkSbK8yi
         RYOAPiTPDZQ1lyqXylLeAuUrx8djkLVnmu7pB+TsljI9rTErXjI+qzsiQaHEy8VwUtTI
         Ao7/TrAxEH1ka1pvlewXEPv5U0VEVZJ4u/jvTsiRsO72VIle1/qCar16+AO6AVwNga/E
         42VA==
X-Forwarded-Encrypted: i=2; AJvYcCUITq004CzwxSH77ysy9r0IbUw7Tz8KAE3kliY+/W+nMwv2UShX7lPjmQ0icL1V9QuwmPwdCw==@lfdr.de
X-Gm-Message-State: AOJu0Yz2R4hocp/DkFXyLq1RzXJUafdwNcTNciG7HzB9c9fc4iwS1ziS
	kdot8MSzFc3vyOBMHuEnQaXnrl8KFxGHtcAZXkh2nt1p2+ljc4fP
X-Google-Smtp-Source: AGHT+IHbmK8qQRC+cdRrE/GNg6xlPwXWuZdo5lXHs6djxg+HcCmiXyQ09nMadr4l/oXgIHS811KZJg==
X-Received: by 2002:a05:6214:5c9:b0:6f5:4508:fd84 with SMTP id 6a1803df08f44-6f54509024dmr99867776d6.35.1746723393136;
        Thu, 08 May 2025 09:56:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFph44OkHapqW8lX3GZOcX1y0SJPyW2iFw+SwviRgTXKA==
Received: by 2002:a05:6214:190e:b0:6f5:4843:dd89 with SMTP id
 6a1803df08f44-6f54b669558ls3647386d6.2.-pod-prod-04-us; Thu, 08 May 2025
 09:56:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtVu3Z3oWB3CsK2iTjAO17CZ8rnM3LG+78yrNhuiSoC40a1ndnfOuwjOSOrEalN59QRtD1Cw+Xzbs=@googlegroups.com
X-Received: by 2002:a05:6214:c46:b0:6e8:fbe2:2db0 with SMTP id 6a1803df08f44-6f542a9f77cmr111239756d6.30.1746723392165;
        Thu, 08 May 2025 09:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746723392; cv=none;
        d=google.com; s=arc-20240605;
        b=eY7YgJeoTYoSlijD6gZZtrA10R9PWq2ch+i/1kfOdhYc1XJQkAZz4iRMZwWoFdRPah
         lPo9yqeLlH8DYPSdw16g+x/VVuOQNJwd076w3yy1Uv6HvVLpzbiv7UBD06NBSC4CKOVo
         bMxKRatn5RMqhQvcLiddOTkSVMOm+3XB4s5Uk3asSD3SvIvDlt9FwE1p1BQB7yXqqbVr
         lDuV3BsN3CGNMTporoCUV0kP58DtkUHq4Tg7MVT9cyeeQFjVDrcjhYDaZ1mPgznDTmWT
         jDuAgYWPH3c5QwAfyEE0YfplSO3AxhPrT0MZNai5hP4FphlcSTuPSrsOjTh2NUlCztZN
         +QmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vMN+iMGvFhpjV0lE7tYmN8eikr2AxmfQ/1RJzjUb7HA=;
        fh=BxgzT0MZsSp477MtR51PGrPYIDC1oavm6ZTCuFIEh1E=;
        b=f9Bd0ikeVTtNqeIIup0N6uaiv7pk57ivO8I8uIjHQKJOh7sAuswvSUcsjKwwtQxu05
         tRbOcF7Cp8DDAN18MtB8S3+mWGF0sPNc07oaTGDKo/Jr6UZhSIyq9wj4yWhLxyPOv0em
         OX1XO/Ux1ytlhiSfb4PC0w5Z12Dq+fBrx3aEbR01VpsCk+AZigAiQLpv6rilxPE37DnC
         LEB9gZAv5207cs3dAX6Fnro2j6CK8MkGD5uZkxoaNiztSbrRE1mmWVrcGdy05zTLByxY
         eRwuAxIQotm5fOgKhW/dX9kqDvjFo65iEHFDpnIpJDcoVZziMnBf+ZBfz+rTpr+tOrKp
         KGzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ChcionI4;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f6e399a382si173366d6.7.2025.05.08.09.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 09:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id CEE79A4DF8D;
	Thu,  8 May 2025 16:56:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46EFAC4CEE7;
	Thu,  8 May 2025 16:56:31 +0000 (UTC)
Date: Thu, 8 May 2025 09:56:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: Re: [PATCH v2 0/3] Detect changed compiler dependencies for full
 rebuild
Message-ID: <202505080953.789B3381@keescook>
References: <20250502224512.it.706-kees@kernel.org>
 <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
 <202505031028.7022F10061@keescook>
 <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ChcionI4;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, May 09, 2025 at 01:44:09AM +0900, Masahiro Yamada wrote:
> On Sun, May 4, 2025 at 2:37=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
> >
> > On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> > > On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wr=
ote:
> > > >
> > > >  v2:
> > > >   - switch from -include to -I with a -D gated include compiler-ver=
sion.h
> > > >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kern=
el.org/
> > >
> > >
> > > What do you think of my patch as a prerequisite?
> > > https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-masahir=
oy@kernel.org/T/#u
> > > Perhaps, can you implement this series more simply?
> > >
> > > My idea is to touch a single include/generated/global-rebuild.h
> > > rather than multiple files such as gcc-plugins-deps.h, integer-wrap.h=
, etc.
> > >
> > > When the file is touched, the entire kernel source tree will be rebui=
lt.
> > > This may rebuild more than needed (e.g. vdso) but I do not think
> > > it is a big deal.
> >
> > This is roughly where I started when trying to implement this, but I
> > didn't like the ergonomics of needing to scatter "touch" calls all over=
,
> > which was especially difficult for targets that shared a build rule but
> > may not all need to trigger a global rebuild. But what ultimately pushe=
d
> > me away from it was when I needed to notice if a non-built source file
> > changed (the Clang .scl file), and I saw that I need to be dependency
> > driven rather than target driven. (Though perhaps there is a way to
> > address this with your global-rebuild.h?)
> >
> > As far as doing a full rebuild, if it had been available last week, I
> > probably would have used it, but now given the work that Nicolas, you,
> > and I have put into this, we have a viable way (I think) to make this
> > more specific. It does end up being a waste of time/resources to rebuil=
d
> > stuff that doesn't need to be (efi-stub, vdso, boot code, etc), and tha=
t
> > does add up when I'm iterating on something that keeps triggering a ful=
l
> > rebuild. We already have to do the argument filtering for targets that
> > don't want randstruct, etc, so why not capitalize on that and make the
> > rebuild avoid those files too?
>=20
>=20
> efi-stub, vdso are very small.
>=20
> Unless this turns out to be painful, I prefer
> a simpler implementation.
>=20
> You will see how .scl file is handled.
>=20
> See the below code:
>=20
>=20
> diff --git a/Kbuild b/Kbuild
> index f327ca86990c..85747239314c 100644
> --- a/Kbuild
> +++ b/Kbuild
> @@ -67,10 +67,20 @@ targets +=3D $(atomic-checks)
>  $(atomic-checks): $(obj)/.checked-%: include/linux/atomic/%  FORCE
>         $(call if_changed,check_sha1)
>=20
> +rebuild-$(CONFIG_GCC_PLUGINS)          +=3D $(addprefix
> scripts/gcc-plugins/, $(GCC_PLUGIN))
> +rebuild-$(CONFIG_RANDSTRUCT)           +=3D include/generated/randstruct=
_hash.h

These are in $(objtree)

> +rebuild-$(CONFIG_UBSAN_INTEGER_WRAP)   +=3D scripts/integer-wrap-ignore.=
scl

This is in $(srctree)

> +
> +quiet_cmd_touch =3D TOUCH   $@
> +      cmd_touch =3D touch $@
> +
> +include/generated/global-rebuild.h: $(rebuild-y)
> +       $(call cmd,touch)

Is this rule going to find the right versions of the dependencies?

> --- a/Makefile
> +++ b/Makefile
> @@ -558,7 +558,8 @@ USERINCLUDE    :=3D \
>                 -I$(srctree)/include/uapi \
>                 -I$(objtree)/include/generated/uapi \
>                  -include $(srctree)/include/linux/compiler-version.h \
> -                -include $(srctree)/include/linux/kconfig.h
> +                -include $(srctree)/include/linux/kconfig.h \
> +                -include $(objtree)/include/generated/global-rebuild.h

Instead of adding a new file, why not just touch compiler-version.h?

But whatever the case, sure, I can live with this. :)

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505080953.789B3381%40keescook.
