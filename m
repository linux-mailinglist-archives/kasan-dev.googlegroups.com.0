Return-Path: <kasan-dev+bncBDTMJ55N44FBBRWFTTEQMGQE2WQPPHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id EC252C8AC18
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 16:54:48 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-596a25b32edsf569569e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 07:54:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764172488; cv=pass;
        d=google.com; s=arc-20240605;
        b=DlM5FAJmi9ZsRD5Z8I41Prpj+TCi+zIx9eReCh0S0v7S15FSssP71iM59cbKLovJIV
         n9MYyFBLFmLR1CIIRznjLMrVoxWccBroDYrQ2takx8QakYr1PzkTG70WNU0pLEOD6AJF
         cAuhV1R7gCgSlnrRPrUOCRqJrVvp6U/SBmhaLENo68W1sPFRC7kZrgnVoirXgt+BPjw0
         AE6oifvO1H+lv78oTv7l0tlIyYu/ACBadPUNVxXymcHCLB4f5udGfAQ8BMJfcfifyHkC
         rleMiqKfD36+SsiPY9+mEuPZEwniQAMfxb0EeORzA+G5QpVtf4KDvOtH2ZyYlGb1p4hj
         J7SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4DDA5JHSMwMC/42oRvz7zZXohrcbI3tYChitFUAtDz8=;
        fh=o+/f8/y9jpHJ+vgRh5h0R8rwjLIhBdipHb1wonV6vEI=;
        b=QwMLlczWX4hrq8QdvfsYcVjoJO9LmlGSbQqFy/31LGVrp+TnH2w+WHN2gddCfxAZF2
         6wCfmf5NdP3AuVJ2w5j/qXs1ZGGisZ7jwPVSL5KNJuMsC+3LXWKfeVye5HdmpELZmEz8
         OtoaNu+NjlVL1h4+ycrAYH3oyJlA9kX7SzP1lU+M/j5MLpJ49aRIb3AEjvU/QmfWCFqL
         mKIlkRjbaxtBpQp3P+Z1j+ZO5HU9ay3fBepAd29Ipfwb/i/N33c3Q3YA2hmal1/+W4D3
         mGhszaeOD5RT1zXr0bGw6+kA9Ib7lyOvd6NC+6VZHjvhfKUNRXIHsHf+qKqQQ7hs5jIZ
         szww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=IVXFA76S;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764172488; x=1764777288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4DDA5JHSMwMC/42oRvz7zZXohrcbI3tYChitFUAtDz8=;
        b=Ik8t/urry2ZmbzO0nlknCGvSBa9/iZktQce3dfvFC6qi0XB67ykkdGW393vp/8y37/
         RH232oGTgvlIgk5RYvU20Vy/DLHjiu3XVci7twnpyxxvpvLgOq69SJwV55VseO35KX3g
         yduTQAYz5+4nTu8oTBaTHVIEWOtgw15DqjljsHTcMOn2TFW8ydDpmErkCP1tyDlSlAk7
         4IEQEJqHusfo/Ffpl+Dx8YM15BP2iwENY9jTGlIq9jL6ZUuhltNhGL+kiiCzMinecZxf
         TV16ENRQLzvDk7EIxaf6IlwSgLCW2Ptt5/nuqsAOYmhx/W/klbVlGv+Y0ZcmmBQKE0+s
         K4Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764172488; x=1764777288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4DDA5JHSMwMC/42oRvz7zZXohrcbI3tYChitFUAtDz8=;
        b=NWlbSZVy9SJPVD5+4ZizjucMkVgFKPW+9zfOrbJQr0Mp6ACBQmh9K+Fg2gue8E8CtU
         h3caAE7Y9nd3Nmmj5nMkTXxbY5lrab4LQcINSvsbG/6/GsDsK6eHdms8DUOM9CN2OFTp
         OZHbUlUTot1Gg6RhA8tR4WMktXVOHLOOK/+sUr1DkdW56gloEX1Zuutr1+Fwwbcu7PPc
         8KFLSGdUUZvlr1+D6WIT3DLnYFjFZ2VxgINVyysD1VnpoSS14qiD/Xo9EaGdVH0mm2g4
         TAUqI/kECmJR8naZ7caqXgL7ggQrK62/BWgKkmNrvNJSayeYyogj5c0Wa9Jp9od0pQt0
         a9Lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWn9l5MSX5RxNuTIqgVrmwuqMgWDiVOaAOR8pssRdCPRgIHwxwt04jCpzDBvZFJWmIz5bVGFg==@lfdr.de
X-Gm-Message-State: AOJu0Ywj0T912Ja9kOE8dfifSperNX5xibGt//CEg/cMAN1k6VYNsBN8
	i5kXCNBAm5PL/CcV0HTcj+EBb51ER61n0AtcquzSE4K1dMOMI2zysbiO
X-Google-Smtp-Source: AGHT+IFSfNQwJdsYKg8gv114lbW40mwwDGM/19V5KSJ7D79O5ph6Rx7MEqzvVTnfDz5aNHkUs2eMkA==
X-Received: by 2002:a05:6512:2311:b0:594:2f25:d491 with SMTP id 2adb3069b0e04-596a378a57emr6830447e87.16.1764172487486;
        Wed, 26 Nov 2025 07:54:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y4N/Ha+0w5hY3AiVa1B6btpmAVdfh3OJS703CQwgKiAw=="
Received: by 2002:a05:6512:32d5:b0:596:9ea9:d232 with SMTP id
 2adb3069b0e04-596b8dd28ffls288795e87.2.-pod-prod-00-eu; Wed, 26 Nov 2025
 07:54:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV7DRxo67sRSKd1GvCqxwE7FI9if/voW8vgzv7e0IZlba4vbwI04ZxvS0rT56Ugd3IkQuEHP6/9hg4=@googlegroups.com
X-Received: by 2002:a05:6512:31cf:b0:594:3b8f:b309 with SMTP id 2adb3069b0e04-596a377e6e6mr7149056e87.11.1764172484476;
        Wed, 26 Nov 2025 07:54:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764172484; cv=none;
        d=google.com; s=arc-20240605;
        b=l2L/lfnoK2gJ1/Yq3AGseX86yzQJlkIpx2jbJk7dInmJSb822c0XnjCkNHoPyBBUQo
         D+cE58tkZvIDMh/j7XS1bZIursSUhLLsiOQRM9CzybCeJW28zoVvJgKIzIeBjeUNJHXe
         ICfywvFXgND2+1+J+a0LCOc+WqrljYFBMSDiwmGGvlu+eb3Q82ahmDQE0x6Gt96Ox9J2
         b4t5r6hSwpxucxekcL64LQVxcyi1SbvavQGYk9vL2R2Fd9sqmLjkBwgkEg0TPEpFj9eq
         vmjnY+uonh8+KQE1iha2YguHOopStl0zMGyYBkG8mMLxY1QjxOxEhrTjWJ95s99Bu+I9
         JdKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bt8tp594VQ0MckrxY49wnixIx3cX7VkTNmuZLYckmos=;
        fh=yBvd/VNgtSTMPzz5CcDBmhQId+aAOonazZpNJ69BRXA=;
        b=cey8BvtVer755aOV3cJwhCXWKvwDsB0jaP/tepN8UyS3kZ5InT73z1ugmWaSR9yTs2
         +/4tuwVGSRqiv6FNZLF/Jfhfr5TI+CMd+mD4p51ctzX1Gf4CIa3Mwu2DCcX5Jb9x4tZd
         9wHOqPrCOErZJGToSSpaaFLrIHkgbYQS2R3KIZmDda5KV471VRbOxJukq7sQMiY73pfM
         jgGpBwHahjyMNQwUOWWVc2BblqYLnjopfq2hkJr4zdB5RwXdfT9fdHZ3butgmQ2jnmC3
         KdFHtI9Fs36pkXjOaNlxJFvRNtENRtFnOMhfXBO0TjmbZJ33zY2+0eTJG/InJgcgSw0I
         c5gA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=IVXFA76S;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dbb1a4bsi337358e87.7.2025.11.26.07.54.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Nov 2025 07:54:44 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vOHqh-004JzI-KN; Wed, 26 Nov 2025 15:54:32 +0000
Date: Wed, 26 Nov 2025 07:54:25 -0800
From: Breno Leitao <leitao@debian.org>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, usamaarif642@gmail.com, 
	leo.yan@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com, rmikey@meta.com, john.ogness@linutronix.de, 
	pmladek@suse.com, linux@armlinux.org.uk, paulmck@kernel.org, 
	kasan-dev@googlegroups.com
Subject: Re: CSD lockup during kexec due to unbounded busy-wait in
 pl011_console_write_atomic (arm64)
Message-ID: <l2tbxtfyjtu32wqv73hqc3loerzdshoq2mdkfpfnigtjjonrdc@3yacamzjcrti>
References: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu>
 <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
 <CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM=7QNJ02GMFG7BMeOGA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM=7QNJ02GMFG7BMeOGA@mail.gmail.com>
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=IVXFA76S;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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

Hello Marco,

On Wed, Nov 26, 2025 at 03:54:26PM +0100, Marco Elver wrote:
> On Wed, 26 Nov 2025 at 15:13, Breno Leitao <leitao@debian.org> wrote:
> >         +static int kfence_reboot_callback(struct notifier_block *nb,
> >         +                                 unsigned long action, void *d=
ata)
> >         +{
> >         +       /* Disable KFENCE to avoid IPI synchronization during s=
hutdown */
> >         +       WRITE_ONCE(kfence_enabled, false);
> >         +       /* Cancel any pending timer work */
> >         +       cancel_delayed_work_sync(&kfence_timer);
> >         +       return NOTIFY_OK;
> >         +}
> >         +
> >         +static struct notifier_block kfence_reboot_notifier =3D {
> >         +       .notifier_call =3D kfence_reboot_callback,
> >         +       .priority =3D INT_MAX, /* Run early to stop timers ASAP=
 */
> >         +};
>=20
> Just place it under the #ifdef CONFIG_KFENCE_STATIS_KEYS below, I do
> not think this is required if CONFIG_KFENCE_STATIC_KEYS is unset.

Ack. This is only needed for CONFIG_KFENCE_STATIC_KEYS, my bad.

> > Alexander, Marco and Kasan maintainers:
> >
> > What is the potential impact of disabling KFENCE during reboot
> > procedures?
>=20
> But only if CONFIG_KFENCE_STATIC_KEYS is enabled?
> That would be reasonable, given our recommendation has been to disable
> CONFIG_KFENCE_STATIC_KEYS since
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?id=3D4f612ed3f748962cbef1316ff3d323e2b9055b6e
> in most cases.
>=20
> I believe some low-CPU count systems are still benefiting from it, but
> in general, I'd advise against it.

Thanks for your review and guidance.

Just to confirm my understanding: You=E2=80=99re okay with me adding this
notifier specifically for CONFIG_KFENCE_STATIC_KEYS (which is what
I need), but you would not support adding it for the general case where
!CONFIG_KFENCE_STATIC_KEYS, correct?

Thanks again,
--breno

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/l=
2tbxtfyjtu32wqv73hqc3loerzdshoq2mdkfpfnigtjjonrdc%403yacamzjcrti.
