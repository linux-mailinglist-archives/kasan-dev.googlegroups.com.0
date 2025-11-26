Return-Path: <kasan-dev+bncBDTMJ55N44FBBXWZTTEQMGQEX7JCWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D8740C8B013
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 17:37:51 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-429cce847c4sf8403f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 08:37:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764175071; cv=pass;
        d=google.com; s=arc-20240605;
        b=KY4S1ztmLjQqGCs5wezkmOVtbewPqRT635zDvCw+LIwiaItjxl9keyQAPLCHcC7IIf
         1vDcdvIPOX+Gq2KAak70boiV8UJDnOISyJaqkHH14VtCLaI9K8Qs4iR2ESbF61Wsj8mW
         FWDcZVcy8t7JvNiyfhmyBuwolAGGwpzbW/6bjA0X542SBh9HCtp9ouRjPsqvYv5IOPVk
         MeO4br2LjJelRSHdeYetGCHpFDbzAtO7Vgv1Utyyk92TzZbcIoWYcp6evKD/siRZkYhY
         ykqggyin/Q+seunvQ4vmmja8E8GgPAKKz2yjkEpIqFXLnDjdt6md+XcIRv7AMydltAPl
         NULg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RZi3wRV9K+6okIxChLcZtwtzYnG/yDkGIxko7nnDKKQ=;
        fh=Pn9nD0JQjSTAij5dfEeYYJaMNfzEAYNxQpLSdJsl0DM=;
        b=NHHIDL7DDTYy173gdr0gdZVBAN2G2uC0FV843W1gg7YeIR3ME5vEPwfeTFPbRo3nJV
         BDC6EYkbQCfttib4A/J9vgve4Et5HnNmXbI84fNKF+Xi7xZJbl1X71j/+oxykZwysVWz
         PB9WL/pk/2y+MDBYd9Ffyjerwr7Dn3m3EgnJNhh5KLEsGZBD7qTlTh5zMaLwtPxYd4Zt
         aVCiSiOFp/oP8uKVjvmBPViSL27nY0j4wAaAc2h+HUXb+ubOZumwU9JtqojwP3a5jDLC
         JEL/M4R7qVREBJtV/zAplHgCVn1ufe+eDVLpCdeX04KebwXEhHsGwnJK0zWJGRtj7dfm
         HqLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b="jhl9ROt/";
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764175071; x=1764779871; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RZi3wRV9K+6okIxChLcZtwtzYnG/yDkGIxko7nnDKKQ=;
        b=ddNUsH79+C2pFBzxbrRYwyZYn/f3Feht2TsJxEmKWRMzDzOTD8S7IAzhQPJoZvxYx9
         c8ujseFg8+f4/uPyxIfzG49UoDnxZ1ebuKFJ1w2fCFquXV2erXJXtywRkcCRO7XtecsC
         zq5fQ3RRpoKEPwqarbLjJKMJEAm/I/bfbhzJQRsh4vWHsAkjDhXuQ/35kjcmgf5Bsg0q
         f0Cp2w9+oar7rYCmJn7q0/AqM/CgbWEkXWxlIrEEirp99bBkwoIsnOMSdPklU3RBKhqZ
         7OFhH1sEv1TWpRQwArWVxvUw9QXf4CsTCNqjDUMj2Kd5uXHHfV3D4DvhcnEQKtIam8uK
         +mCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764175071; x=1764779871;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RZi3wRV9K+6okIxChLcZtwtzYnG/yDkGIxko7nnDKKQ=;
        b=kQ7ETbL5LveOfqo5FTjKqRR3Hr3KN/O/YL8IEv8jmeHsvYjLuIX1oPdsgHDyNGGIpl
         PSrhQDqSFMt58G7dH8+l8/iasUzsvHvqP6rFz8FGE2dZmD7LaIaptHWyDQvNb1+MS/gy
         8MJmCI3WQc7mHPcyv29oLkg0CNS1CCG6TWVY3e2HVp47Hx1AjUjw8vF1oj3FevolMaVQ
         2b5ESd0aZPXeUTJ38UvMSht34wvsh2ZXIxKY5FXy03kD8rMHO227mHs8Hx8LPpYi2utY
         9eyjrVi5d1dFUZZd+tonfy+VtBBuN25DBWwNHjf7XM6gIFX4AnXtre6y767fWreGrbK6
         KxNg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVd+J9i0pUtwInHJWF8wk2juKLPFWOymtuYE+6qsQ534t+mEwl2ZUdYrUhckOntNjNYjfhXkA==@lfdr.de
X-Gm-Message-State: AOJu0YzRHsxFVTUtvdflz2NeujkZoUu9aVGmP648KHBLxJJG/SsWOddL
	mIoziTpntqqSA0ShaUdmEoh6IfNYBovjWVdfWPZSgzrUpKCdWEBTlw4T
X-Google-Smtp-Source: AGHT+IGYhVigUx0jGndAr3dqMh1wMWpcL/F2ofq45wahrHcxZxNRs5hta2oXh8AVFDRmVqzIQKg2ow==
X-Received: by 2002:a5d:5d10:0:b0:42b:496e:517c with SMTP id ffacd0b85a97d-42cc1ac9146mr21290196f8f.13.1764175070951;
        Wed, 26 Nov 2025 08:37:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Ydv1bpp5IFTx/LuPUrueaI9VJtpZFmzguQa7B/31+EgQ=="
Received: by 2002:a05:6000:2903:b0:429:d66b:509e with SMTP id
 ffacd0b85a97d-42cb8220d95ls4231923f8f.1.-pod-prod-03-eu; Wed, 26 Nov 2025
 08:37:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXT6OGeywJdXaALl8q0oGpAySgGv9FhVUCZTXEHvcvQHqpH0uYgMX9mWhG2QCUMYK6T73XMHRFJXSA=@googlegroups.com
X-Received: by 2002:a05:6000:2893:b0:42b:55f3:6196 with SMTP id ffacd0b85a97d-42cc1ab89b3mr22920791f8f.4.1764175066477;
        Wed, 26 Nov 2025 08:37:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764175066; cv=none;
        d=google.com; s=arc-20240605;
        b=du4443fR7vRj6gcblKuQR83oLUq4W9jJcmVD1f4/OnAvCCoSdlm8IHWCE2kbeZYlON
         W8f8JJT2nz/6/vYqZHnAcKaBWsk/EluhRp+nrqEAM3k5W/PVk7sAQy8se4Lr43I00Fs9
         256xXo243ePmdI/Q9z1jqJW8R0nUeNOYhloizZFeZqGGnNfbTidZVTHi59XB0CeOFMUz
         O7WZTDcG7LvnOXGnI+095ltzuGFev8n8uYZXIp2MAHWwtp2GP1Ca2EU7QSSm1yyqv1z0
         +4Wnx/MBwNqXORvA6kOMAtXQ5hW3XB0azExRn+l8m3rCoDSWPKOPK8iwZ/nRgoy6AwN7
         w8sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=UkehlKcCR1BYoMHCxU7xjsLfV9z4pwK9DmBr0352rSU=;
        fh=yBvd/VNgtSTMPzz5CcDBmhQId+aAOonazZpNJ69BRXA=;
        b=hxUkDaK+av+ZE2qzdaJQVTEsq4IpW7JRq9tHBrzncSuS1SD40k+9eRujI4Csn3ohhC
         Vxy2j5mmMSB2V7k1Y2pDzCudTzxzP8705nhYoD5zvtMB7MfRwWghCMi8U+LEc/OErD2j
         R2T5CjRTqZS0G+zwsJcFQnItMvhH6NzDx8jxHto0Wd2dFc3TbNtzDvKayTXryF86o3nX
         fhu6R4QCJwstpMbUn8gZmDsVA96LGdYwY+znVDuoe9q7ERe+eVCj4xC2nCe0i8ATdeNx
         YR1rabC3rhQMhbvpkJCCuWM/IF/2UwJW9neOR2ZVBseCnXHzOL1KaXAATf8fF5ypvFoP
         z89A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b="jhl9ROt/";
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42cb7f335f4si263596f8f.4.2025.11.26.08.37.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Nov 2025 08:37:46 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vOIWL-004LSp-E3; Wed, 26 Nov 2025 16:37:33 +0000
Date: Wed, 26 Nov 2025 08:37:28 -0800
From: Breno Leitao <leitao@debian.org>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, usamaarif642@gmail.com, 
	leo.yan@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com, rmikey@meta.com, john.ogness@linutronix.de, 
	pmladek@suse.com, linux@armlinux.org.uk, paulmck@kernel.org, 
	kasan-dev@googlegroups.com
Subject: Re: CSD lockup during kexec due to unbounded busy-wait in
 pl011_console_write_atomic (arm64)
Message-ID: <2qy6sn3zpe75q5fgasvr3amohtjbcckcjlsnln7pjf2kwk5i2a@2znsizshp6c6>
References: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu>
 <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
 <CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM=7QNJ02GMFG7BMeOGA@mail.gmail.com>
 <l2tbxtfyjtu32wqv73hqc3loerzdshoq2mdkfpfnigtjjonrdc@3yacamzjcrti>
 <CANpmjNMnKJGvneNDOCFRfC8xUWq-uuXVjLRQZsPYo86Xau5UHw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMnKJGvneNDOCFRfC8xUWq-uuXVjLRQZsPYo86Xau5UHw@mail.gmail.com>
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b="jhl9ROt/";
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

On Wed, Nov 26, 2025 at 05:08:59PM +0100, Marco Elver wrote:
> On Wed, 26 Nov 2025 at 16:54, Breno Leitao <leitao@debian.org> wrote:
> [..]
> > > > Alexander, Marco and Kasan maintainers:
> > > >
> > > > What is the potential impact of disabling KFENCE during reboot
> > > > procedures?
> > >
> > > But only if CONFIG_KFENCE_STATIC_KEYS is enabled?
> > > That would be reasonable, given our recommendation has been to disabl=
e
> > > CONFIG_KFENCE_STATIC_KEYS since
> > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/co=
mmit/?id=3D4f612ed3f748962cbef1316ff3d323e2b9055b6e
> > > in most cases.
> > >
> > > I believe some low-CPU count systems are still benefiting from it, bu=
t
> > > in general, I'd advise against it.
> >
> > Thanks for your review and guidance.
> >
> > Just to confirm my understanding: You=E2=80=99re okay with me adding th=
is
> > notifier specifically for CONFIG_KFENCE_STATIC_KEYS (which is what
> > I need), but you would not support adding it for the general case where
> > !CONFIG_KFENCE_STATIC_KEYS, correct?
>=20
> Yes, correct. If there's a real issue with CONFIG_KFENCE_STATIC_KEYS,
> it's worth fixing if there are still valid uses for it.

Thanks for clarifying. I'll submit the patch with changes limited to
CONFIG_KFENCE_STATIC_KEYS.

--breno

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
qy6sn3zpe75q5fgasvr3amohtjbcckcjlsnln7pjf2kwk5i2a%402znsizshp6c6.
