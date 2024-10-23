Return-Path: <kasan-dev+bncBDAZZCVNSYPBBYM44S4AMGQEMM36JAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B5BE39ACD85
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:55:31 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a3c90919a2sf67946305ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:55:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729695330; cv=pass;
        d=google.com; s=arc-20240605;
        b=CWOmW3QBmaEXs3nrh8E03cYSC5P2HJhvsWYXnWLP7Uog1/qK15clRrI+lPExpDOaIF
         AYK8B63Ig35TntCKQDMD8+ILXHHb3zCFZbGgbVwHz5Ent1HhY1kFW3dyd1eBWCBk48Jk
         QzKq0cMOBHoMsUppvKvMxTf1aettdtO7yIzzdSqoetuIFv5hl0fy+ORR3ySPp4/eg6Me
         KFgL+hG0kHp2pQD5Mugr0oD4QlERvA12D2NGPSTUPS+6nRIuZlwkXSWK5feKjTLyixvk
         2EgiPFE8MI+dWHLMjswe4vGXGDwqhh3Ydq5ttqq22DcASgBgvIvWH0kxHEs3ggI6HsyC
         9L0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WSxzQeULS7NgPzQG6Ow1ZHlxTNmsB6n9n7kAuNEDj5I=;
        fh=Kxpa6tRmqBCpla0K2S+5AFEz8smdHefl34nX7cSJR+w=;
        b=lsm3Ck2wbss8Wew8yEafpwi0Pn4Xo0Ld/1n2U23CBnq4ZO3ODtDn9iHheQj4HypNk/
         3wQ+kcwC4Y6/TUGsm0fZpZAnUWjyUfbAwULZuX/zfSk2t1Z64csfSZCUo5IKiYucP/sG
         TyAKuPl1iHEI6B1MpFt/sK7HEd9OxaEQwLtnPU50wrcJyb/lnLv9dxTboA2Rgg4c7aME
         BoP18BPHw/9l3+xEqL6lDheTD1v0Xg1QZ6z9oRn9wGk9ncTkGRCToAt6dnLHgs233ola
         WxXvTTKiNgO+uKZlRRg3KT+qG6tsM9qmAvyNTVvCYwcGOh1ITdDpXz/NnO1mhbWw6CLF
         kcrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C9LPmaL9;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729695330; x=1730300130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WSxzQeULS7NgPzQG6Ow1ZHlxTNmsB6n9n7kAuNEDj5I=;
        b=tvqYSM5Di1Jmv1/btRUa5V27qwpigypGHNVgSpGrwi8aKVys3KYUnEkgBIB4akapBj
         etB3AroEfxlEo1bijoeAgO2hHFohYQFR6tdxqSFD40Ng3TZDfp5QL+glp0o2TUIQW8Re
         SYOAJnCVKGXP8XMY6K0RPu85zWoslfznBWdvnVvUelGd0VPn4kkofu4S4ho+3TxyMqek
         2067/zYEpNan+wPSZaUICd4oJ05Lto5I892G5cdnCRTT790dpjSfrClfWONPBRZE4Rhs
         +WXrMC3MXxR6Uns9tYgrpjdysGJVx6MTz8aZNm/NTok4ToHLt3t7pWU/vVnsIuauaOWW
         0lAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729695330; x=1730300130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WSxzQeULS7NgPzQG6Ow1ZHlxTNmsB6n9n7kAuNEDj5I=;
        b=XXRetjUGPmsXMYVGKMjZGO/SBRrDxsJkdB+IrSixBBfAUwGDFyIlkVT3Up21yw5/H9
         1Vt7TU4PNEokePIUa2eOzG1VexPpOdW1NSPMeA3uKpdKIfQ14QODGcVPiPIJHEe+7Cfm
         vb4jYdYfO6OtDcc8iGYeT2JhgIRK4yRMfwpBcJuSMlU1rTlMgFx2Y36u0HwJPGvpubby
         R8VPhaE3HFzmv4TTiKojX0+998rmQIyx/jpsLoorXVjxrSOr+XYu9fUz9724MAlYwJip
         MT4Vl1uyuB4SceyQyjzWtJkxTTQJ9F3pTNi7zjfqGTWGn+2V1dJX1udcXWgqFkxfEPlR
         IA3w==
X-Forwarded-Encrypted: i=2; AJvYcCWgbiuxNta9yFr2QzkrOU52rWN/HpzHoGVSVFkj+Yji2RiPeUQFRdAa5OGVMgur62nPEIWp3w==@lfdr.de
X-Gm-Message-State: AOJu0Yw3NWHreE4Wg862IIn9K4dKRsfcXRHnRbB3XwVXUna2DmAiHfI7
	Aktnqlqk1aG1VwJZoBmjvECwzEAGZxFj7X+7JyWyPyRqvweoJPj2
X-Google-Smtp-Source: AGHT+IHU61dHXNa+YBlk3L5gWqIHE5IyWV3mDHW4m8uIza1raErXjP/VDx24MuI67Oo+R1uQQ9cYHA==
X-Received: by 2002:a05:6e02:1988:b0:39f:5d96:1fde with SMTP id e9e14a558f8ab-3a4d59304bcmr34999525ab.3.1729695329983;
        Wed, 23 Oct 2024 07:55:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b01:b0:3a2:6eaf:d929 with SMTP id
 e9e14a558f8ab-3a3e4b0383cls35207835ab.2.-pod-prod-08-us; Wed, 23 Oct 2024
 07:55:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYmICDGjWyFlmEN5RzdV9bfaDjfp3K+WaAVMKcLYX9PtpJVwHRpKiiklLAfg3+YEqU1uhCwgU3eAg=@googlegroups.com
X-Received: by 2002:a05:6e02:164e:b0:39b:330b:bb25 with SMTP id e9e14a558f8ab-3a4d5985ac4mr32251335ab.12.1729695328904;
        Wed, 23 Oct 2024 07:55:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729695328; cv=none;
        d=google.com; s=arc-20240605;
        b=AjZDpN6SBA8dJVa2FRQsF4bh/MTSdPgcCUAEmT4RhkBX12nTy3MOZvLegh3rwK5mjn
         FGxw2SwJ5Ag3shu7swB8nFfeR4HFlQU8wWYUy5xxQkX/k6KgRItCWupSstFiWawGvmir
         dwojc2uWndzWyg97lqh53hmb3FVFvPkqAKkWOKRcYquEmOP4byh/BBkgvDfYQhAryI49
         E+ynWEsi8ry78r/Bem5WDiyBzB73QXWmGNeQUSf306Uxd6IYmBmWVThmp3Bhb8QdwMiJ
         FX4yvgUN68z5iO6nyrn9soY3A1o8ban8Tcd9AVQX4J2vdD5HyoWAaD9KXbdD6ekV6n91
         1m6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7MTeTIVxX4OXNC5J0w9ckAUmAsWa3FUYOfK0b69BCZA=;
        fh=yZv+j7lW3dKqKob/Aw8KwHtx8lLy0XwgVvnD8VJl2EQ=;
        b=ghg6WTTcLRJlhYQ4gBs1Qf7s7o1AhElX9i9JePLtQhcGKqijpPV853ArZE/bxJNC8Z
         6k9TVXaZzC1+FXVorsYIteg3JEWwnApnwHoZTUP/lorDt4fyaVPX3+y7PXB9Btx2YPxj
         466jE//AmKJVH3wwxlyNPNVGc82WXYSw98KXMa+9H4YXsoTBMzy7MnnYiHAWq283Mf4T
         AaNFgi3+iZMyMhGnIZWehk5fVhrKBq/F1y7xfDOZMKlF9OKw2a3c6rW0iiTpBvjTlY3p
         EOtqMeqidIakZOFQ566IYehnlNiPo3lbQ6EU3rGV6Eqz9Uaod+TzQtluFhne9nosRYCV
         yJbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=C9LPmaL9;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a4009c2aaesi3633215ab.0.2024.10.23.07.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 07:55:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BD0E35C5E05;
	Wed, 23 Oct 2024 14:55:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9D6AC4CEE4;
	Wed, 23 Oct 2024 14:55:25 +0000 (UTC)
Date: Wed, 23 Oct 2024 15:55:22 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Pinski <pinskia@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	"Andrew Pinski (QUIC)" <quic_apinski@quicinc.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
Message-ID: <20241023145521.GA28800@willie-the-truck>
References: <20241021120013.3209481-1-elver@google.com>
 <20241021172058.GB26179@willie-the-truck>
 <CA+=Sn1m7KYkJHL3gis6+7M2-o9fuuzDtyUmycKnHK9KKEr2LtA@mail.gmail.com>
 <CANpmjNOf94nQL8YVr94L=9qXA6eHcm-AxbS+vz+Sm1aHJT2iAQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOf94nQL8YVr94L=9qXA6eHcm-AxbS+vz+Sm1aHJT2iAQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=C9LPmaL9;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Tue, Oct 22, 2024 at 11:42:40PM +0200, Marco Elver wrote:
> On Mon, 21 Oct 2024 at 19:29, Andrew Pinski <pinskia@gmail.com> wrote:
> >
> > On Mon, Oct 21, 2024 at 10:21=E2=80=AFAM Will Deacon <will@kernel.org> =
wrote:
> > >
> > > On Mon, Oct 21, 2024 at 02:00:10PM +0200, Marco Elver wrote:
> > > > Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not =
disable
> > > > instrumentation in functions with __attribute__((no_sanitize_addres=
s)).
> > > >
> > > > However, __attribute__((no_sanitize("hwaddress"))) does correctly
> > > > disable instrumentation. Use it instead.
> > > >
> > > > Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> > > > Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google=
.com
> > > > Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> > > > Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> > > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > > > Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
> > > > Cc: Andrew Pinski <pinskia@gmail.com>
> > > > Cc: Mark Rutland <mark.rutland@arm.com>
> > > > Cc: Will Deacon <will@kernel.org>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > >  include/linux/compiler-gcc.h | 4 ++++
> > > >  1 file changed, 4 insertions(+)
> > > >
> > > > diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-=
gcc.h
> > > > index f805adaa316e..cd6f9aae311f 100644
> > > > --- a/include/linux/compiler-gcc.h
> > > > +++ b/include/linux/compiler-gcc.h
> > > > @@ -80,7 +80,11 @@
> > > >  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack"=
)))
> > > >  #endif
> > > >
> > > > +#ifdef __SANITIZE_HWADDRESS__
> > > > +#define __no_sanitize_address __attribute__((__no_sanitize__("hwad=
dress")))
> > > > +#else
> > > >  #define __no_sanitize_address __attribute__((__no_sanitize_address=
__))
> > > > +#endif
> > >
> > > Does this work correctly for all versions of GCC that support
> > > -fsanitize=3Dkernel-hwaddress?
> >
> > Yes, tested from GCC 11+, kernel-hwaddress was added in GCC 11.
> > Also tested from clang 9.0+ and it works there too.
>=20
> +1 yes. From what I can tell GCC always supported
> no_sanitize("hwaddress") for -fsanitize=3Dkernel-hwaddress.

Thanks, both, for confirming this. I'll pick these up as fixes in the
arm64 tree.

> Even for Clang, we define __no_sanitize_address to include
> no_sanitize("hwaddress"):
> https://elixir.bootlin.com/linux/v6.11.4/source/include/linux/compiler-cl=
ang.h#L29
>=20
> So this has just been an oversight when GCC support for KASAN_SW_TAGS
> was introduced.
>=20
> Having a Fixes tag for this would be nice, but I don't think we
> explicitly added GCC support, and instead just relied on
> CC_HAS_KASAN_SW_TAGS with cc-option telling us if the flag is
> supported.
>=20
> But maybe we can use this:
>=20
> Fixes: 7b861a53e46b ("kasan: Bump required compiler version")

I can add that to patch 1.

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20241023145521.GA28800%40willie-the-truck.
