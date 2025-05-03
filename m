Return-Path: <kasan-dev+bncBDCPL7WX3MKBBTNI3HAAMGQESPJKWMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 52055AA81DB
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 19:37:19 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2241e7e3addsf28197235ad.1
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 10:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746293837; cv=pass;
        d=google.com; s=arc-20240605;
        b=IGGS6A2sVzIY56rmK5oJuNj7s7m0996SnHtunDllF9tYf640pcbnJjsbBltZzFSRDu
         z2dYImLiVyHF9uaZeZ7DGxvfFhnTDO8kds4obly2vazYFMivkz8tMIaKUEGzl4AtWXq/
         XPfIaMT2cCws/irXTLqxezlr6vI8Hl1MOdlNFPLqtF3cwy2AcLDSQ9TwqrYVdB8H4RAe
         VAcU6FRsl7L6hH5eJux1vhRmTPOzcw8KYLSxJjPs/Vowbv+gJk6ZBSZiLTsDssmwBgG3
         PTisEavH/kThybJNqpkta9B7osFZ7bkXDFH17jQ4FumebYhwgJfngSoGpJ5KErdDDpa8
         5BHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GZxNWnt+FZwE9f1hK3RDy8tidOLDipUa1UK0lc+oHpw=;
        fh=mBRug0s57hzz2AKkspb5pKD6PeGgMcm3bteADzvPYog=;
        b=X2bjIMxw8HzxVZGs0JhV+/7/tOHTTjEjyIV/CdOM1UKujZytdVMT7oIHo76WSjpgLc
         aiOu5Q05L/HxBKX0xQYvkVZpZRD5xDE5lQs+uuhY9SBiwDyDbP9DPS+BouTsOETYoDWx
         jxEpOYygj7/2sGSLWrpSwDxzGKIFKuxW73UWCTqVXxpGBCuc/t/um196DZZZ8utpOVsq
         I9RUOgLeWrJOfDgSy6qV/s3C97H0C/0k05z4uiJJ6VCePEjiJSL6HdRHp6BTSFnDf7fw
         SbflXYGOn8GG022EG1N4WOZygFxkbKD2ad+oAvDpGcywrPWz0CWrBtDpuMlm7jDp5CuD
         q5iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=roGI5vk0;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746293837; x=1746898637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=GZxNWnt+FZwE9f1hK3RDy8tidOLDipUa1UK0lc+oHpw=;
        b=PeDODrk2vUbxT22syrSzMfR07TeHsdBfVjRwIPmYIVA3+pFXx6zGuaUNPvmDthvCYW
         pt2lMynSs7wD5KT9kepeqXp1ZwwGrfHBsgJU9EBKAIEAl3N4pwfSDiYnKfsgg67nMTf6
         FWa6wea1acH3wP4Cj/p/gUNrmNCTmpxMQ7f0FPFNZVheP0cfUQSlGfsS0cBoL11Ay6rG
         XyIDyYwIDpRG6jMzNE7VSYwlEgGRhHBbIJHIU4BtvkIH0XWjDcmQEXaH3iCKJpyYKJoQ
         yKllCH9FmYrDrNe4NJCeMtmOan0TxKEASQ+EJj4yLJhLLswSfwbsOS/0G7UFdXmhU0rd
         mbPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746293837; x=1746898637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GZxNWnt+FZwE9f1hK3RDy8tidOLDipUa1UK0lc+oHpw=;
        b=G71hcgSjI/y+iZWfNYvYDYqYiXj8f20MQKyS4Fzt5NabNClSHfl5xgtpSM5zXtLaAe
         F2SKkUggymqogCbtwsPS1hfXwOtwqCphqzeRqX2PprFmK/OAVnebYs4ISc9cCg3fdDJo
         /btGeAXlWnjXW4BI74uW3A50NK8llDpvQYKa2zM2t+cyPl++sm3efQpXFZYeoLny96HP
         3sk7RjW2ffmFIktYHMYe1mFM3UNR9YqSdZEatZH9tkwhM8q2p1pgZrLR3KC9dEaI8bn4
         beTOqQhRWmdLz7vU9fUi7osWYhZ7ZyxBNZsTT/VtzH9P9is3UJizrtfQ3IzBv5Im8y+k
         rgig==
X-Forwarded-Encrypted: i=2; AJvYcCWnmPV3e1mDexqZ1v+eP9I29lcz8jX/1+W1TRJAd3N3WKnkeS1KbYGB91K9fZshkIFtVGc2MA==@lfdr.de
X-Gm-Message-State: AOJu0Yzs5/JqvnwTUPJrGRb8KpTTtlLB6F6H6OvtN1v2FwX3/Dtb7X/t
	GOrZPesq00hheYfT1g6V7kcNuc7DAqrmuM3dMYqDvd2JH+I8xQDt
X-Google-Smtp-Source: AGHT+IG4N6a8IRLvhRui20E9tSmnZPMoihUD5kTvn1kBVAwXmr2xO9ezoy9GELxUThS1B+TllWhqVg==
X-Received: by 2002:a17:902:f649:b0:22c:35c5:e30d with SMTP id d9443c01a7336-22e102cff7amr94024565ad.13.1746293837364;
        Sat, 03 May 2025 10:37:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEGgCXTeRuRv7vNOV6eYiC365MhU9nMY6cgEjYfWQZxxg==
Received: by 2002:a05:6a00:1747:b0:736:b289:bca6 with SMTP id
 d2e1a72fcca58-740459b649dls3086187b3a.1.-pod-prod-01-us; Sat, 03 May 2025
 10:37:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtpgodwRHpni7N/hzgiYiRYgJTwC3CnlRzIelGgqykr3sH9UKlc+Bef9IoNCAR1dyZLn218jJjHOI=@googlegroups.com
X-Received: by 2002:a05:6a20:c78e:b0:1ee:c8e7:203c with SMTP id adf61e73a8af0-20cded4694bmr11377846637.24.1746293836022;
        Sat, 03 May 2025 10:37:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746293836; cv=none;
        d=google.com; s=arc-20240605;
        b=Eb/o3x5tyo640fBX3tKoBSP+JgqsMAKelkIqFouOp4x/wE+b03Rvh84HuY9QYoF4s4
         aiMWMVtiU5g3LQEG4O2atjFBy0i9zRd2kBOznLnlViOlNChlYit/8Y3x2WmgoYpW+B5J
         ruqENa96WhTy2l8whHtb0Wk5AGWCvNfx25e/RaP9LflzeD5J8SK8u3ePITQ9wO+UNwJ+
         QWk/YXWLcgQyJycq0QPk9nZZwKc1EADkeGB6O2oEsq3+JJ2tQs1lmjaXs+Oc5HXgl3BN
         /diYdhElRCTuKQx8RpJCvBI289nkkP8H/XstycVDZV/mpcb0OygyDmBcA0Xnmj8sPaMp
         Gumw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wfYb0t5S/K+8zs2NzTzfRtfSNYBnzowq+ik5aTh7Vsg=;
        fh=BxgzT0MZsSp477MtR51PGrPYIDC1oavm6ZTCuFIEh1E=;
        b=i/fXMHircxu3kfH0b++aJT5NrehDJtjLFrO4ARNkf6gTai5SAAoPfYViPfSalLHeHA
         wFvSyuqMK4Ztdngr4lsU/fvRBeEdp6RXHFAsTYV8jJBuTESKGpcX5vf3wxC8p4k0U5Zr
         IYSUf+kDrl6oVVy3g4uvR1ESZqQJua8oJ9KTB3i8OYnmRJBshPT2pvsp4ZdHW4SbGv/X
         kRPAVIUoKlVetf2IWLWF+SkwdctdHmbtvY2TWD3lwaFsw1MmUDqfxx/8qF1gJNq3AGti
         3AhLSlOLw72tALmjSm+x0nX8kvw9KRe1ru9e1sk5NJODpXxFieGCscULkFH4oE4yJQNP
         uUIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=roGI5vk0;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b1fb3920d7asi138430a12.1.2025.05.03.10.37.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 10:37:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 61B5C6111F;
	Sat,  3 May 2025 17:36:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4F681C4CEE3;
	Sat,  3 May 2025 17:37:14 +0000 (UTC)
Date: Sat, 3 May 2025 10:37:11 -0700
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
Message-ID: <202505031028.7022F10061@keescook>
References: <20250502224512.it.706-kees@kernel.org>
 <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=roGI5vk0;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
> >
> >  v2:
> >   - switch from -include to -I with a -D gated include compiler-version=
.h
> >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.o=
rg/
>=20
>=20
> What do you think of my patch as a prerequisite?
> https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-masahiroy@k=
ernel.org/T/#u
> Perhaps, can you implement this series more simply?
>=20
> My idea is to touch a single include/generated/global-rebuild.h
> rather than multiple files such as gcc-plugins-deps.h, integer-wrap.h, et=
c.
>=20
> When the file is touched, the entire kernel source tree will be rebuilt.
> This may rebuild more than needed (e.g. vdso) but I do not think
> it is a big deal.

This is roughly where I started when trying to implement this, but I
didn't like the ergonomics of needing to scatter "touch" calls all over,
which was especially difficult for targets that shared a build rule but
may not all need to trigger a global rebuild. But what ultimately pushed
me away from it was when I needed to notice if a non-built source file
changed (the Clang .scl file), and I saw that I need to be dependency
driven rather than target driven. (Though perhaps there is a way to
address this with your global-rebuild.h?)

As far as doing a full rebuild, if it had been available last week, I
probably would have used it, but now given the work that Nicolas, you,
and I have put into this, we have a viable way (I think) to make this
more specific. It does end up being a waste of time/resources to rebuild
stuff that doesn't need to be (efi-stub, vdso, boot code, etc), and that
does add up when I'm iterating on something that keeps triggering a full
rebuild. We already have to do the argument filtering for targets that
don't want randstruct, etc, so why not capitalize on that and make the
rebuild avoid those files too?

So, I think the global-rebuild.h idea is a good one (though I think it
should maybe be included in compiler-version.h just to avoid yet more
compiler command line arguments), I'd really like to try to have the
specific dependency-based way to get it done.

I'll send a v3, and see what you think?

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505031028.7022F10061%40keescook.
