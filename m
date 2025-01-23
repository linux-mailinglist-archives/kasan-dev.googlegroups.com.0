Return-Path: <kasan-dev+bncBCO7L6ME2ELBBYNGZC6AMGQETTE3F7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 681C1A1A15B
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 11:01:07 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-53e1ee761d7sf341249e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 02:01:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737626466; cv=pass;
        d=google.com; s=arc-20240605;
        b=aObaw6i1nJPLO8wy08JPMUSh0Jpz1YpuvDU3AW8j5/JoVagJ/hld1Cxh4OLUFQSVR3
         xW3tyBaV4gXLWqx6me+86Mr0A0cnLTTlgzDHohGtQ9NsbIUhVxoxXnEx2WtQE2s2nYhT
         8wU56tLOOIs4HmIg3EPDNFRblPenM+AItVJ/QuMbMZ21nSrBtKWAhhSbAObzj7dg/czG
         JOOA/JY+f/Xiczl1tvBYuUOc1nQf4GrAyV/qJfNY0v1BN/L/9cBokKn38NZfvyj10bsR
         xLo+q4SPkigUIWpvxSetKk4trkwwnPVDjetGx6Pgsl1EQv2EyDiirtfXJMsIC/ewdQ2I
         /4bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=xVDwarb9rhCuEiThqnVhgsRcBUxhDkhlnAEPLHH2vIM=;
        fh=v5RmySBfZZrs34DZ+GihYfEJ905iH0NgsZp3S8F+rnw=;
        b=Ex0X3xEQ7KLgbJXTxvUBrehbl7qZpRd7n7F+Gx4E3VOIFdieYS491/debq9wy4iG1z
         X74kJdm9S/eAXrV2YBeXfMLO2WbyzO5ix2Yc+AmGAb4piSjX1lM11QOE+mINkoynFEGS
         6IKpb23ekWt7Pwj1+LtRsM8lHrfzwfZhBsYHdjlQ90xV0fO6lOOTkTU2/v0BWl0gXf5n
         9qzZwrg0Fd34bGIO5fpvdsrnFNeSm/1O+hjKKurp8chXy5YMuESj3Ix6vUSpkEUribVP
         ZX1h07uZkgmnt9dcSJHYQOihCuVVW2i6vWnNVfYgXSwuCNHeJoZYdz55gBlQqQ2lzKLo
         5ztw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=Viw2gDQe;
       spf=pass (google.com: domain of erhard_f@mailbox.org designates 80.241.56.151 as permitted sender) smtp.mailfrom=erhard_f@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737626466; x=1738231266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xVDwarb9rhCuEiThqnVhgsRcBUxhDkhlnAEPLHH2vIM=;
        b=Inh+EOGkAn+QP8wZnS2F9HPe9QpzAXZ5Xhkg4oiUa11zzUE1nxPRuPj9oNVliipM7j
         jUcDo/i70QAitmsUgq2uGYaCaafXMfLMphNE5ieSqseoBcpMz8eDwDlEbclJk7I2w/1F
         UA7MtjNHCDxsVrNQ7Qjtg5oIYHUCINmNS7mI2CcJJOZufv+PxapAITksjMzIxbgWINaP
         0fIlzppirYG1DRjVc1Aj58tScOfT4dm2PdFoFNFIM2TJUun0HP6nJ7izl7rQlSjP40vD
         9IxPxyfDBbehoQGnt6qOfb14yCoXuLcGH9i/F8a606i0LuCQ5vi23OxwfJHYD1FhzKBL
         SO8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737626466; x=1738231266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xVDwarb9rhCuEiThqnVhgsRcBUxhDkhlnAEPLHH2vIM=;
        b=YzzWIJwu3NCQVURKa/yhhW1V47YcNiJh6JX/e/rHkurQ8+9oHXCDZlKj8/Tr0p4JZE
         Z+RJCV0hdjI4yttcB5YWzWGybabXHIAwRTTJeDCIDolaZs+ybCMTD8EFRMuhHHprd+fc
         dK0hgvcrfS+gbsc3ysMPc7lQoJAm8RBVLCPA+HcN5KPrtcSDzAT/BxlTBZnXzVF4rvcq
         5cewAOHWwZYqav84dsNBHOsxAMfWoj996dcPZw+ZKQ9MzBRXP+rtlD6xG5rx+Bc93kP+
         p1Eed2lEAbK944RMzMAE092wxf5ja5KE7UNA+85OwOTMlOwULgt623gf/ykjaRu/2Tl+
         1hrw==
X-Forwarded-Encrypted: i=2; AJvYcCXPsqB1Q7NwNdtSjkFyXYV9H2Z4jacCi3PgEtn1/O5/Z+CN0yJKnSz+UxTCZJicBzxzf96Hjg==@lfdr.de
X-Gm-Message-State: AOJu0Yz68iqDMaBp025r4uRELErIwvgfEnIc/bv5+60ptV7y+z4miKLs
	IVXt7yLvGopOrWVvgK9KEizhE5VzIbxPXm77qMKT5BByfvJyDB9F
X-Google-Smtp-Source: AGHT+IHifyQTlXUseIyS8lG6KGGo3VFtbE8fxTkNa3zpZbsQDTHYsx8sqliliq8BksgrsoUXaOWBYA==
X-Received: by 2002:ac2:5211:0:b0:542:87c5:66da with SMTP id 2adb3069b0e04-5439c282b5amr7699944e87.37.1737626465836;
        Thu, 23 Jan 2025 02:01:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5e5a:0:b0:540:c34b:91f6 with SMTP id 2adb3069b0e04-543c24906bdls49185e87.1.-pod-prod-05-eu;
 Thu, 23 Jan 2025 02:01:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVObO8F9loNUXLJg8zhFmtr9KcOoXFf2IGQgMuTh92G9reNZ1AQ8C8+G6F1P3QPbkT8hgZvzK/L6o4=@googlegroups.com
X-Received: by 2002:a05:6512:ad5:b0:542:2190:9d99 with SMTP id 2adb3069b0e04-5439c22d7fcmr9242260e87.6.1737626461931;
        Thu, 23 Jan 2025 02:01:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737626461; cv=none;
        d=google.com; s=arc-20240605;
        b=RLudBHTzcojXeZTrrBqoA/jMF+b8SgLsXtrDSNE5H8o5wB7FD8JUqdJGvKyUhBbK03
         UNOyodWNoW9EJs2f6+IYZOuSNl3HgDVCb8yMezmP+EQlZWQFnHdIp6ZZfGiQYF61lvBn
         ReSmWjp/m4DasT8RmiusPEAzqWghWGWh8SsfE/ee6npz+OCEsgHuyzKK3D9vuSHS81sl
         qbRSbQKcRKGMVIe04k1MoqCuK8ojitYsu9A+lQRjO5HLhf6yAvyi75+oTtwa9W6B2BEo
         nq7P4FPhBIQWWzviwrQHG60RIM0SNbpL59eFVbFLbWQ881Y1ZQM0nxalMpRsdJ6cOi31
         Y0Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=g2pO6+QLNA6Mj2xw+ECoH+WU/EdmM/oG+IGjb8y/Gog=;
        fh=4r11t+ytE9B9MSvaMedC5UUZbxc6hJ0WzG47CJyeiiI=;
        b=Tz4cUrWnSdWF9jHLcRuULpQG6eZwfvCylGkTcuUmd2IUc7oLZLt4ZVAjXRI3Md/tcW
         +Yv9BOYGa2liUIkGIk0lzgv48qp3P5iLD+E6zMnqHrr5wzDTgi3g7Vtlgbrs4lREvq8G
         rw7W65y6Is3+uUyjNk4OAvXibu+/eeP8hIBseZkIEaXYg9TF+f9Z7q0tY+4cmQxzni+o
         RNIiY99lrT/qDzzSKBBl9fZbgndQ7lkQovuXM4Nps4JV9ypwgj5KjrWEf7Rd928mfoOz
         jjW0rKowIrAnx0QvKCsfmwxcLn8Tpe/4Qfnjq9kI6gJNbhaFxCOTPFfAOjG5A4wkrtaM
         PEbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=Viw2gDQe;
       spf=pass (google.com: domain of erhard_f@mailbox.org designates 80.241.56.151 as permitted sender) smtp.mailfrom=erhard_f@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
Received: from mout-p-101.mailbox.org (mout-p-101.mailbox.org. [80.241.56.151])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5439af64301si370218e87.7.2025.01.23.02.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Jan 2025 02:01:01 -0800 (PST)
Received-SPF: pass (google.com: domain of erhard_f@mailbox.org designates 80.241.56.151 as permitted sender) client-ip=80.241.56.151;
Received: from smtp102.mailbox.org (smtp102.mailbox.org [IPv6:2001:67c:2050:b231:465::102])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mout-p-101.mailbox.org (Postfix) with ESMTPS id 4YdxKQ5cxbz9sy3;
	Thu, 23 Jan 2025 11:00:58 +0100 (CET)
Date: Thu, 23 Jan 2025 11:00:51 +0100
From: "'Erhard Furtner' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, Balbir Singh
 <bsingharora@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
 linuxppc-dev@lists.ozlabs.org, torvalds@linux-foundation.org, kasan-dev
 <kasan-dev@googlegroups.com>
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in
 copy_to_kernel_nofault+0xd8/0x1c8 (v6.13-rc6, PowerMac G4)
Message-ID: <20250123110051.77591f69@yea>
In-Reply-To: <8acd6ef8-adf0-4694-a3e5-72ec3cf09bf1@csgroup.eu>
References: <20250112135832.57c92322@yea>
	<af04e91f-0f44-457e-9550-d1d49789158e@linux.ibm.com>
	<20250121220027.64b79bab@yea>
	<f06de018-34ae-4662-8a35-1c55dff1024a@csgroup.eu>
	<20250122002159.43b367f0@yea>
	<ca7568ef-5032-4a80-9350-a9648b87f0b5@csgroup.eu>
	<8acd6ef8-adf0-4694-a3e5-72ec3cf09bf1@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-MBO-RS-ID: fd40fbbe0cabfe8e5b5
X-MBO-RS-META: bz53gnnzceo19xeofg98yg7oixjnhbud
X-Original-Sender: erhard_f@mailbox.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mailbox.org header.s=mail20150812 header.b=Viw2gDQe;       spf=pass
 (google.com: domain of erhard_f@mailbox.org designates 80.241.56.151 as
 permitted sender) smtp.mailfrom=erhard_f@mailbox.org;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
X-Original-From: Erhard Furtner <erhard_f@mailbox.org>
Reply-To: Erhard Furtner <erhard_f@mailbox.org>
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

On Wed, 22 Jan 2025 19:23:00 +0100
Christophe Leroy <christophe.leroy@csgroup.eu> wrote:

> Le 22/01/2025 =C3=A0 16:32, Christophe Leroy a =C3=A9crit=C2=A0:
> >=20
> >=20
> > Le 22/01/2025 =C3=A0 00:21, Erhard Furtner a =C3=A9crit=C2=A0: =20
> >> On Tue, 21 Jan 2025 23:07:25 +0100
> >> Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
> >> =20
> >>>> Meanwhile I bisected the bug. Offending commit is:
> >>>>
> >>>> =C2=A0=C2=A0 # git bisect good
> >>>> 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d is the first bad commit
> >>>> commit 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d
> >>>> Author: Linus Torvalds <torvalds@linux-foundation.org>
> >>>> Date:=C2=A0=C2=A0 Mon Dec 9 10:00:25 2024 -0800
> >>>>
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 futex: fix user access on powerpc
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 The powerpc user access code is speci=
al, and unlike other=20
> >>>> architectures
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 distinguishes between user access for=
 reading and writing.
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 And commit 43a43faf5376 ("futex: impr=
ove user space accesses")=20
> >>>> messed
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 that up.=C2=A0 It went undetected els=
ewhere, but caused ppc32 to=20
> >>>> fail early
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 during boot, because the user access =
had been started with
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 user_read_access_begin(), but then fi=
nished off with just a plain
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 "user_access_end()".
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Note that the address-masking user ac=
cess helpers don't even=20
> >>>> have that
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 read-vs-write distinction, so if powe=
rpc ever wants to do address
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 masking tricks, we'll have to do some=
 extra work for it.
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 [ Make sure to also do it for the EFA=
ULT case, as pointed out by
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Christophe Leroy ]
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Reported-by: Andreas Schwab <schwab@l=
inux-m68k.org>
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Cc: Christophe Leroy <christophe.lero=
y@csgroup.eu>
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Link: https://eur01.safelinks.protect=
ion.outlook.com/?=20
> >>>> url=3Dhttps%3A%2F%2Flore.kernel.org%2Fall%2F87bjxl6b0i.fsf%40igel.ho=
me%2F&data=3D05%7C02%7Cchristophe.leroy%40csgroup.eu%7Cb4c1dc7184f54a410a0e=
08dd3a7270b6%7C8b87af7d86474dc78df45f69a2011bb5%7C0%7C0%7C63873098540790288=
1%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiO=
iJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DE5Yp9jopCP=
E1NFuBM8rs%2B1jXZ%2FXAaKvBGpcEP%2BaMyz0%3D&reserved=3D0
> >>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Signed-off-by: Linus Torvalds <torval=
ds@linux-foundation.org>
> >>>>
> >>>> =C2=A0=C2=A0 kernel/futex/futex.h | 4 ++--
> >>>> =C2=A0=C2=A0 1 file changed, 2 insertions(+), 2 deletions(-)
> >>>>
> >>>>
> >>>> Indeed, reverting 32913f348229c9f72dda45fc2c08c6d9dfcd3d6d on top of=
=20
> >>>> v6.13 makes the KASAN hit disappear. =20
> >>>
> >>> That looks terribly odd.
> >>>
> >>> On G4, user_read_access_begin() and user_read_access_end() are no-op
> >>> because book3s/32 can only protect user access by kernel against writ=
e.
> >>> Read is always granted.
> >>>
> >>> So the bug must be an indirect side effect of what user_access_end()
> >>> does. user_access_end() does a sync. Would the lack of sync (once
> >>> replaced user_access_end() by user_read_access_end() ) lead to some o=
dd
> >>> re-ordering ? Or another possibility is that user_access_end() is cal=
led
> >>> on some kernel address (I see in the description of commit 43a43faf53=
76
> >>> ("futex: improve user space accesses") that the replaced __get_user()
> >>> was expected to work on kernel adresses) ? Calling user_access_begin(=
)
> >>> and user_access_end() is unexpected and there is no guard so it could
> >>> lead to strange segment settings which hides a KASAN hit. But once th=
e
> >>> fix the issue the KASAN resurfaces ? Could this be the problem ?
> >>>
> >>> Do you have a way to reproduce the bug on QEMU ? It would enable me t=
o
> >>> investigate it further. =20
> >>
> >> Attached v6.13 .config plays nicely with qemu ttyS0 (forgot to disable=
=20
> >> SERIAL_8250 and set SERIAL_PMACZILOG + SERIAL_PMACZILOG_CONSOLE=20
> >> instead as I prefer the PCI Serial card in my G4).
> >>
> >> The KASAN hit also shows up on qemu 8.2.7 via via:
> >> qemu-system-ppc -machine mac99,via=3Dpmu -cpu 7450 -m 2G -nographic -=
=20
> >> append console=3DttyS0 -kernel vmlinux-6.13.0-PMacG4 -hda Debian-VM_g4=
.img
> >> =20
> >=20
> > I was able to reproduce it with v6.13 with QEMU when loading test_bpf=
=20
> > module.
> >=20
> > On my side, the problem doesn't disappear when reverting of commit=20
> > 32913f348229 ("futex: fix user access on powerpc")
> >=20
> > I bisected it to commit e4137f08816b ("mm, kasan, kmsan: instrument=20
> > copy_from/to_kernel_nofault"), which makes a lot more sense to me.
> >=20
> > It might be a problem in the way patch_instruction() is implemented on=
=20
> > powerpc, to be investigated. =20
>=20
> I think the problem is commit 37bc3e5fd764 ("powerpc/lib/code-patching:=
=20
> Use alternate map for patch_instruction()")
>=20
> Can you try the change below:
>=20
> diff --git a/arch/powerpc/lib/code-patching.c=20
> b/arch/powerpc/lib/code-patching.c
> index af97fbb3c257..8a378fc19074 100644
> --- a/arch/powerpc/lib/code-patching.c
> +++ b/arch/powerpc/lib/code-patching.c
> @@ -108,7 +108,7 @@ static int text_area_cpu_up(unsigned int cpu)
>   	unsigned long addr;
>   	int err;
>=20
> -	area =3D get_vm_area(PAGE_SIZE, VM_ALLOC);
> +	area =3D get_vm_area(PAGE_SIZE, 0);
>   	if (!area) {
>   		WARN_ONCE(1, "Failed to create text area for cpu %d\n",
>   			cpu);

Patch applies on v6.13 and fixes the KASAN hit on QEMU and on my PowerMac G=
4 DP. Thanks Christophe!

Regards,
Erhard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250123110051.77591f69%40yea.
