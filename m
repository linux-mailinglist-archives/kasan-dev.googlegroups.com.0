Return-Path: <kasan-dev+bncBDHMN6PCVUIRBYNJ7S6QMGQEDJFAWWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 611D4A46091
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 14:19:31 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30931bfee74sf28552721fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 05:19:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740575970; cv=pass;
        d=google.com; s=arc-20240605;
        b=PoERfxi3TMs47kBaZFaPe4gZNJl+7mHGucScXaEXAEUPFTGIonEeYXInDz1BVABLzq
         yi5+Vs0jyZ7CBZQXEdEResEWN7RRc8V8VuObWdiAEVNe//C/3IdFh6c28UPhU918ov1A
         uDuEauCo2HSySsWkuB8C6RUkWLew1m4f2u5uErt4XNrf+QNl9aQj1eE+ThKPB0MI0LPF
         D3ETK12LygK90ueJF6up9g+yu3iagMCJe9Vee0olU1NDLMvO8eCoxdLbLjfLB/hXo3L2
         +vucko4RRNTGWJMQdbEIYkPhcjhQEqeUmDlGTUfg5b0zWLijN5LSMF11cAmg8QH3mrwq
         oyxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=8ZWGflr9Y6ul219TD6pafSj22KveHxnCOxgIcdfeBU0=;
        fh=pXwBrhCU+6VBO2j7kP8S7uXDL+A8eaGJFRhq/wiMPWc=;
        b=E1XZKkAge3IZlPH3RCJzg0XqjlVtCQM+EvjdXQ1STxXHoZp6M4mVrVE75pXNas5hpb
         TaYjoChzZR1kClAh+0WfHhUhoFf5lRF2NNPSOfuCuf44k2ZqiOQddou47f6ifdhNe74b
         yFGBWF0zmijssaxhTN0IJI4TEV7RiC/LrCj/vIvugeoUn8nYj6QeSZht0jtsLYj0avqI
         5z0KAYzYBmOeNE4nPgz18/7xmFG+MZrJLEdgg4D0C2Ugv5JHyuYv31ZHLh3ThOBzXlFL
         TPeBGf4PCrlocnTom2I/XWlCeKExo1C0Wwx9lmAcZbRuTQRaMTrnGODzwz1ujNteHJ1Z
         +Vsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=fZ4bphJf;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740575970; x=1741180770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8ZWGflr9Y6ul219TD6pafSj22KveHxnCOxgIcdfeBU0=;
        b=WizlXGUSB9WD4/gsqhmJ7zDz2Eavn1UqEKEGV/X7co1m6JzQgb72nLgBYJnnmxsp6o
         4Y4zv4/4RtzFkXB5Id0reAEzFqKV4i2B84+RdvOEE/uV3rrP+qmfzKPMi3g5oPpHnTId
         tWbJzbcaVN771j5TOzLZog2UFGh1DHGbpM9XRdAotpl6ShAu86Mm6v4Sk6M8mcZaWvLo
         l9FC9G+5hcaLGicN8YPkJKwU/xixqP1o5SHLX2JZj2QHOxrKPE32hbo/zYOji/dovVjf
         JlC21DkyBb1ee6uS0FDOMZuIa8qS4w7EKnR9TJtZAAWuQrckqkOykOtOVHo82ma/uYFw
         CeDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740575970; x=1741180770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8ZWGflr9Y6ul219TD6pafSj22KveHxnCOxgIcdfeBU0=;
        b=loqr5KoZg0NW8aUouKHrcwHUK90yDvOhn+DFyRZbkMnSrdn13ZeUfhC3WajfikER5u
         NznynbxP9nAKhahRsIcN+aXljUEvaMDn04PZlnI9/OMjOeL+PZX5tdmQBLz0Tt04h8sd
         YTK5FGsFeJzSIcnf/ILY4imvmmit3JOU72lbv9OWYAIzvQLlkItFrGgftxGxH2hBaUIL
         XQOzkHms6rBvqFSh7ZDtoI3woB7UtVZyCJM7J19hi0FNOIFNkmmAUXRo6P1qbOmp5aW/
         sJ4ngpXMpwIiZ8CYktOaDKaMUW65jgwCXWLZcMntpxJh4nxwmuLQKHZB+DccygCO2Nv0
         QZ6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXT0fFHw87RjanfwoNnpPAPXWvolh6QbMIsUksuTaYZE1pZcAAuyrBHGs69risvzbKdLGPsWA==@lfdr.de
X-Gm-Message-State: AOJu0YxONyAg4fgzYYXVexNsYTvzfq44KOtCHTpuNbbFqS70ircB/fOm
	NwYPIaVEKFGjGBfTQO39SBYNt1cn4LnQ2lxu/uqw897C02K6g5Eb
X-Google-Smtp-Source: AGHT+IHAw2/xGaQUYLxEG4SdiVUlfFjOc2EYaa7osYoPWohMLPDE64ScjuF78ANmjTGe7504xl05gQ==
X-Received: by 2002:a05:6512:3e14:b0:545:1d13:c063 with SMTP id 2adb3069b0e04-548510d1bf0mr4691534e87.14.1740575969748;
        Wed, 26 Feb 2025 05:19:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH0thOpWSEeq74V2JDnFhBDVhpxVQt+XbfxAAirLR835w==
Received: by 2002:a05:6512:3f09:b0:546:1fe9:e806 with SMTP id
 2adb3069b0e04-548511331d7ls750980e87.1.-pod-prod-05-eu; Wed, 26 Feb 2025
 05:19:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVo8tVP27kM0PI+0vCq4s59ifWkf7OomLeViZSAnEfZa7YKgYX1f2gG50iwwBV04XrIjiy71Aw8Kfg=@googlegroups.com
X-Received: by 2002:a2e:9a98:0:b0:307:a2d6:45e9 with SMTP id 38308e7fff4ca-30a80c69371mr47572451fa.25.1740575967093;
        Wed, 26 Feb 2025 05:19:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740575967; cv=none;
        d=google.com; s=arc-20240605;
        b=Yfe7PsQIzxZlzHD27WWaaX60RAy9cD13uV5EKVgkiZDSrwTKkcX8t0pu95V6oMCCi/
         g180Y15TWjAw6FDtydfGDI1KwACkYzoWijBn4G2oXWSjSXq8W/MbAD2GV5ZHjJFNXBe3
         ry0PmbdsASIOeH48ebWsF3BCTnr2Dmlqnw5yxuAKTjpiEjnpa96SG//7FBU0DrT5w5+O
         XCHHww1ZBuE7tEeUhk0tHfF/OONSVAjF0IfqcL/GIb6SNq6uxKkCyo6b06g387XPVahh
         roqwKjGze8QGM2YSr47A2RVGHG8YBNoTNHw0GxUcUlOx2jMbkLpxY2MkiRwhNy7byzJB
         Kskg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=qJBErG/pSE3mwR2gO0Zf0GO3sxAtsZqzG79Fy9J4HfA=;
        fh=/wFa8qhS8YLUIYABCXYfQ0vtE/5nPLB2CKrOhiWAiWY=;
        b=JyH5aIIP0Dkv2Q+nFLlJeNqpDRwHxBSGRhoawXndnh3M/3i5fxnSUzeL+WACKbhR/A
         rHHRajDrxsgqko7AqFxh5PKkNCW++Y6fPoemcpCscOE3ppjPmP98dKzjMILPWNeCduLZ
         lwD+iNYR0x3ttVy736rYrZtFDutBKpqFdpnXevORQJyPHQJoJCkRzh6dqGx/G0FrthxT
         NHcoC9FitOqpCHbQC1otOpWaQ6bNhQZGf044kJjpdEwdxcWhBta4FP79btgMLddzX/mT
         buIsGb9FblqF8q/d7vl/DeSeZrwmRyQbFGjGVS+RbFUca11EiyPUYkytXC973HeQVgCD
         S+yA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=fZ4bphJf;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30a81a48959si1272631fa.7.2025.02.26.05.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 05:19:27 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tnHJs-0000000BUdH-0WaR;
	Wed, 26 Feb 2025 14:19:24 +0100
Message-ID: <159a83bf5457edbabcc1e88ee5ab98cf58ca6cb0.camel@sipsolutions.net>
Subject: Re: [PATCH 3/3] x86: avoid copying dynamic FP state from init_task
From: Benjamin Berg <benjamin@sipsolutions.net>
To: Ingo Molnar <mingo@kernel.org>
Cc: linux-arch@vger.kernel.org, linux-um@lists.infradead.org,
 x86@kernel.org, 	briannorris@chromium.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Date: Wed, 26 Feb 2025 14:19:19 +0100
In-Reply-To: <Z78SVdv5YKie-Mcp@gmail.com>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
	 <20241217202745.1402932-4-benjamin@sipsolutions.net>
	 <Z78SVdv5YKie-Mcp@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.54.3 (3.54.3-1.fc41)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=fZ4bphJf;       spf=pass
 (google.com: domain of benjamin@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2025-02-26 at 14:08 +0100, Ingo Molnar wrote:
>=20
> * Benjamin Berg <benjamin@sipsolutions.net> wrote:
>=20
> > From: Benjamin Berg <benjamin.berg@intel.com>
> >=20
> > The init_task instance of struct task_struct is statically allocated an=
d
> > may not contain the full FP state for userspace. As such, limit the cop=
y
> > to the valid area of init_task and fill the rest with zero.
> >=20
> > Note that the FP state is only needed for userspace, and as such it is
> > entirely reasonable for init_task to not contain parts of it.
> >=20
> > Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
> > Fixes: 5aaeb5c01c5b ("x86/fpu, sched: Introduce CONFIG_ARCH_WANTS_DYNAM=
IC_TASK_STRUCT and use it on x86")
> > ---
> > =C2=A0arch/x86/kernel/process.c | 10 +++++++++-
> > =C2=A01 file changed, 9 insertions(+), 1 deletion(-)
> >=20
> > diff --git a/arch/x86/kernel/process.c b/arch/x86/kernel/process.c
> > index f63f8fd00a91..1be45fe70cad 100644
> > --- a/arch/x86/kernel/process.c
> > +++ b/arch/x86/kernel/process.c
> > @@ -92,7 +92,15 @@ EXPORT_PER_CPU_SYMBOL_GPL(__tss_limit_invalid);
> > =C2=A0 */
> > =C2=A0int arch_dup_task_struct(struct task_struct *dst, struct task_str=
uct *src)
> > =C2=A0{
> > -	memcpy(dst, src, arch_task_struct_size);
> > +	/* init_task is not dynamically sized (incomplete FPU state) */
> > +	if (unlikely(src =3D=3D &init_task)) {
> > +		memcpy(dst, src, sizeof(init_task));
> > +		memset((void *)dst + sizeof(init_task), 0,
> > +		=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 arch_task_struct_size - sizeof(=
init_task));
> > +	} else {
> > +		memcpy(dst, src, arch_task_struct_size);
>=20
> Note that this patch, while it still applies cleanly, crashes/hangs the=
=20
> x86-64 defconfig kernel bootup in the early boot phase in a KVM guest
> bootup.

Oh, outch. It seems that arch_task_struct_size can actually become
smaller than sizeof(init_task) if the CPU does not have certain
features.

See fpu__init_task_struct_size, which does:

  int task_size =3D sizeof(struct task_struct);
  task_size -=3D sizeof(current->thread.fpu.__fpstate.regs);
  task_size +=3D fpu_kernel_cfg.default_size;

I'll submit a new version of the patch and then also switch to use
memcpy_and_pad.

Benjamin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
59a83bf5457edbabcc1e88ee5ab98cf58ca6cb0.camel%40sipsolutions.net.
