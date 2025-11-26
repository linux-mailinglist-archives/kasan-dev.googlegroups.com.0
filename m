Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQWMTTEQMGQEHJ2FBKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id ABBB4C8AD74
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 17:09:40 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-882380beb27sf214504076d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 08:09:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764173379; cv=pass;
        d=google.com; s=arc-20240605;
        b=P+AzE7r6eSYqU/ns26tEzoqO5bzPW2inldlrsy1V8LeYRCE/vdnoyWECdBbDiF2kR4
         8bWr+pyPOCoQtWQPFz6XGgAg+KUNqEdv0edehwc0sN6LxPViPTytTakaRGPpIkteYIik
         iXQBVd+gSW9GgUf7xos3oWzv/sZ8GJCacToVgYNzAU2y8JV4Oj+q8rz/DPUbISd2lVlQ
         pkDZLUxb6kG52sDJ5tydGNsuIRgqWK/rbxVYQ8dOLDMbBV36bgrYzPaDUxhe3jMHp0QY
         T7TNIc/9G/rkWrW3BRsnJJj+2GDym5rfwFtvpeGO9MdDfbwCb7/8BUpLBS/98iRrvAJ/
         LnxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ivcgVLeRJye9SoQqVslaj6HhNFdgadsdMGQ6fNxID3c=;
        fh=8cYWPu8NmXgHe1RUIOMD5uDpvoaqTr9N6aKKa9j5aVw=;
        b=J6yvpM3KaorVArEvuOsbdWGkTEvDg3JpTZ2pBERnpNnloJEER2/6arfGWNLRrowqGK
         X24+rcnwY5fxJWnwrHZHLxG+4a88+oN76djiU7TmXGwirXuaJwXY39MMEQbNhd4rjBE+
         ED5i1MOVzECQA6fz7Ur1NzlOhWQaJU7V3HvifPPi7GHFJDgC9eV20J+2xDVVr0NjsSUD
         PtIYLN7JvAZ+XQmFj2mrMWWIG4A46RMzE02sis9VTP+Q2aGxhmk/+bZow5z5BV4ujv5J
         mFwVifhjmDKZcEEHMpQPBLTQ8L7Ihz+y+MYfEU/QiKBv8ET7XG0Eo+du742gAfac5iRA
         uxkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rt96Kpok;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764173379; x=1764778179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ivcgVLeRJye9SoQqVslaj6HhNFdgadsdMGQ6fNxID3c=;
        b=oIcCfTszWhlApG8TKQ07qpdl6v0WOFk5B9GdtpBgHIgx/vyc2vRmpGmK0MAqlijY5R
         lbYvBToL5shA1O0flcI15U5skr5XQRJDCvzDsz9X6XzZuGHN6Pw4T8JAsrciJNM/MR5k
         +MqmhpUtrKRduzXzDQo33/XluQrsdA3E4zzhxgSAgv+T9s/ekixuVmVBQajLT19ug3mp
         lNhDntbR8sRc/Ll8vBqs7wcICOLLSVv4LweZM7R03ZeI9niPtq1ltHaeAxvDmSO2agWL
         QGbq+dUgz3aZ8f4oMFjm9YrE58UCKwED64SJK7JUTR9qdPMDABDAlnDa3u2yR9qq2oJj
         b4Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764173379; x=1764778179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ivcgVLeRJye9SoQqVslaj6HhNFdgadsdMGQ6fNxID3c=;
        b=XF17dcjWauWxuwfk2zFkwHwf3CjuAj+Ydm1DJocE7pR9pTqsHvFgcCZv8vBLss8Da/
         wcXE4RfkNT9QlA0xBXzn8SX4NKb0VetXdEn/PwUVz8wR4maS1GYMSXBo4+E8c7wm2H0F
         7iqh8RwFmYcya20waDRU3riDLf4U943JJg5D5rvl3QfX7zwOHS9+4XMokS1tQLEmckqd
         HHvqtAJTz9lrJBeCk59VhC+anLfZj9TEt0G29nEMRi5+mUyrlW/ujNVGuiVmhIj7c9Pv
         fDS4Ib1phm6dBXf9qcK5wh6HVanAH6ICHkoLyNwXtcCbnrS4M0HErJkdQfMEACOp1rng
         yc6A==
X-Forwarded-Encrypted: i=2; AJvYcCXObIEhMF+vYss5HWGQgmCdLRMFKW/xAF2JSb/OWxdnSseOrysS0tHS1+3SU2Dnk0YOwfgrDA==@lfdr.de
X-Gm-Message-State: AOJu0YwGBuf265LtpdSaOBiE20DDrTe6LeMB+iHJQqkrk5lScjhHGeDh
	buYas/BaPK1XhNJTZWeWAatsBb09L4TDdpfbdIP2/sC2xXPJuTue7uT4
X-Google-Smtp-Source: AGHT+IFIKrCqes75ybO8hynZAYHWt2529IjdTfXMpbnuLWMzdo3rT6gokXyUzO7J3og4RFHdf+yYvg==
X-Received: by 2002:a05:6214:5297:b0:880:486d:18dd with SMTP id 6a1803df08f44-8847c57d8ffmr257888826d6.65.1764173378890;
        Wed, 26 Nov 2025 08:09:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y3tV3PsK+BghJqLkCVTjcz/sO/B+V9zSUiNWRT3okdcQ=="
Received: by 2002:a05:6214:620f:b0:882:3d7d:3964 with SMTP id
 6a1803df08f44-8846da92130ls99636876d6.2.-pod-prod-02-us; Wed, 26 Nov 2025
 08:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUA+F08Y58C7/ef+RJzUY1/R5zjMM0dXzZy21O7eamFQAeuOKficQAj05D8QabrJMJw8z7PjVi1mKU=@googlegroups.com
X-Received: by 2002:ad4:5aab:0:b0:880:531a:a32d with SMTP id 6a1803df08f44-8847c5445a3mr306840936d6.41.1764173377574;
        Wed, 26 Nov 2025 08:09:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764173377; cv=none;
        d=google.com; s=arc-20240605;
        b=PXkIY5s3Y0SGF5FOJmUKa+Mo+OjUJjBFzaKdvcTqVTcBeWAWTHCcMuNtdqQjyc2adY
         CInjPAT39wZA6cZP87VesSH9fGjRhnepc7Kwyj3wSKArI2EZNiq6NA3ta9icRrqOz6WK
         G113OYXHTCoFRKQxNfocjhlGET1GUqR6IZIbAmZzKOvoIFFREfNL9pLzohoJhjy4EbFU
         4l0vNKc9WsZdVOpZM+WzYpxd9rsV3K4FHZNgc9T8t3gDtJKQn0BBIDTTCEBEGMTk8TLR
         utGfF0smcFuneiZuqm2qXXLPl1S/5XWEyc0TPFtySEaBH9vD4KZ6Mk7wv0viveZkfUsm
         PzpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0gcVBypLWbERJY8p8vcyLVaTMKTzyQc3bsZYqIHWRB8=;
        fh=ModvxTZHE57L6xhdVYo2bnb6jacDpMXoiCV6im1nk74=;
        b=k/UDN4L4QC+yvABh+PG3V50NXy1yx9I/6mnNVC2rvUIJrEufc2yTDSADOcbSheeiMR
         zKJUlgMCFFImHYqMPrbRSi4nVlYf/u1kJbNl0iXM8uU22ObZWA4zknwbBygubIHhK9Zd
         HKNmocoOIbzRgimo9Ctqr5D7PZg2Gb4hUcq7yP8+6lmnRmTSP0xU3Ph0xw0ZAGv20vAg
         m2Eqkzl0r5MqlA8S39Vd4UWruIbL/7rrzFlHGaf3C30pTj5BuEM9Al45GvXOQQ2p4avR
         1jS4vpvVKTviBPBG1hZbAk2FBdK4+poVW1voJ/ByNzdH6o20j0n7NL5pMfiFDgPjN6fN
         8Efw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Rt96Kpok;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8846e5446a3si6903706d6.6.2025.11.26.08.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Nov 2025 08:09:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7b80fed1505so7900301b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 26 Nov 2025 08:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU1vXC8r6MNq5ZPefN/zeZluuQQjG+7lI3qeFVJa71BTorJpKTeDtioCnqmiBX9YuijBvXSquA/zLw=@googlegroups.com
X-Gm-Gg: ASbGncuKZ09cxnmdgJ3e9oPToq1y33SCujxPWhHKbTuY4zM7YhlAUAVkJtMb/wNG8j3
	EoI+EYfT4XwEpfyixPu/Cb48l6QyOtFDUhZLI51jnv5bxEj06XsJ0KGyG89uWwzb4g9LHLAe7vw
	Bf3eBU8zx6Ot1gnosjrMDx7TQNAAut/PkWzicclfa5WEeGzL98EFccUAwyiFKV+uzxu+YBqxmOf
	SMwnCOGe8Ooruk0+MHwt0NsCLYT0s3T095cewn4u1gUeOFx/mmMi5pS2//IKxdOI/nMw0+wRXH4
	SbYQhddwnWmpkruXG0jSlLTaSLLn2ThDwC6D
X-Received: by 2002:a05:7022:4293:b0:11b:7f9a:9f00 with SMTP id
 a92af1059eb24-11c9d6128f8mr16441440c88.4.1764173376414; Wed, 26 Nov 2025
 08:09:36 -0800 (PST)
MIME-Version: 1.0
References: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu>
 <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
 <CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM=7QNJ02GMFG7BMeOGA@mail.gmail.com> <l2tbxtfyjtu32wqv73hqc3loerzdshoq2mdkfpfnigtjjonrdc@3yacamzjcrti>
In-Reply-To: <l2tbxtfyjtu32wqv73hqc3loerzdshoq2mdkfpfnigtjjonrdc@3yacamzjcrti>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Nov 2025 17:08:59 +0100
X-Gm-Features: AWmQ_bmhx5AyJc3aUebiyMdQ90XhVN16c7wvxxmC6w0jKeAhLXYecNNdM1Ixy_0
Message-ID: <CANpmjNMnKJGvneNDOCFRfC8xUWq-uuXVjLRQZsPYo86Xau5UHw@mail.gmail.com>
Subject: Re: CSD lockup during kexec due to unbounded busy-wait in
 pl011_console_write_atomic (arm64)
To: Breno Leitao <leitao@debian.org>
Cc: glider@google.com, dvyukov@google.com, usamaarif642@gmail.com, 
	leo.yan@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com, rmikey@meta.com, 
	john.ogness@linutronix.de, pmladek@suse.com, linux@armlinux.org.uk, 
	paulmck@kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Rt96Kpok;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 26 Nov 2025 at 16:54, Breno Leitao <leitao@debian.org> wrote:
[..]
> > > Alexander, Marco and Kasan maintainers:
> > >
> > > What is the potential impact of disabling KFENCE during reboot
> > > procedures?
> >
> > But only if CONFIG_KFENCE_STATIC_KEYS is enabled?
> > That would be reasonable, given our recommendation has been to disable
> > CONFIG_KFENCE_STATIC_KEYS since
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/comm=
it/?id=3D4f612ed3f748962cbef1316ff3d323e2b9055b6e
> > in most cases.
> >
> > I believe some low-CPU count systems are still benefiting from it, but
> > in general, I'd advise against it.
>
> Thanks for your review and guidance.
>
> Just to confirm my understanding: You=E2=80=99re okay with me adding this
> notifier specifically for CONFIG_KFENCE_STATIC_KEYS (which is what
> I need), but you would not support adding it for the general case where
> !CONFIG_KFENCE_STATIC_KEYS, correct?

Yes, correct. If there's a real issue with CONFIG_KFENCE_STATIC_KEYS,
it's worth fixing if there are still valid uses for it. But I wouldn't
pessimize the now default mode, which is !CONFIG_KFENCE_STATIC_KEYS,
as it doesn't appear to have this problem.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNMnKJGvneNDOCFRfC8xUWq-uuXVjLRQZsPYo86Xau5UHw%40mail.gmail.com.
