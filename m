Return-Path: <kasan-dev+bncBCKPFB7SXUERB34MZLEQMGQEURNHOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E9069CA6579
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 08:14:56 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4ed782d4c7dsf28992201cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 23:14:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764918895; cv=pass;
        d=google.com; s=arc-20240605;
        b=avZwLDGDYKgBbwqc2ucAGm47f4MqLrNqyaxD2fAHTxHhUzOPqrX4xMbporUu3HRjss
         JisKLeKhsCsokvS+qaEa1zD9wh5iM3OOAI7DQkkqYmswo8F9frx3ZXCZDNcH+MynlAzx
         1it+9NADCgAWP20FK28w/fn4B7IeS3w0XKiHT5UghrQeSv4Y3Jpx2vX3D2rppAI41V1f
         V7yr7TTnOuATIzcRTyVffgn9iGAijjzHJJ3lWiH2M972vq8bg0p341UXR35gt00iZJ+D
         kgvQuV5SxZXe9pndfhjdALOWP1mJMN1q+0rvlGIHLXN1t44A2GPWskbJeeFEud/5uqBZ
         lDRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+8xZgc6aDI9inu3MeYL9yhC8BZulIRvR8wlciLKAr/k=;
        fh=4ZAct/toMEIU8rqw65DVxm0Rs9JNp0dH8gx4xdpAM5o=;
        b=e++0x6oiOWqHLBG7jlKqajhC5xIn9cVMgPATLR9Pg/OoXG8kqSISBK/6j8/ujMkJAb
         j/F6Jpjj1f/qoB9VwbpeycJltkZnQjYNbOeIugGYAPq0ZTGvskMKjRaKP0awgoedQdDY
         SFE3/GofUa4St9VcXVDYjl/4EEVZtLSNFCR1g1DfYouRzanWEawqG8rzberWgqg7+TEs
         kfjCKbrUN/ft02vSJoY/NKzIEItZ0HoB0t/6DojkB7T5jqwjIqK3BtzTvQu6cX0JS6oa
         SfFzk9JAHLBtgJh1qBfNQ8oPQ4n49NwOSHjWsVCoYGxwx57QgsyLUXLKPAtH8cgiMouk
         V12A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fx8mSw2M;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764918895; x=1765523695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+8xZgc6aDI9inu3MeYL9yhC8BZulIRvR8wlciLKAr/k=;
        b=kTt7/oHCSH/TUVXpR/GfzojvlQ21+ujsrilKpvQeXfZIcWoD7oY/X+4asvchYG+Vfu
         8SoFYtFgWu/urjo9Xu2xWObPgkYSscXMbXArb8aot9ZzHdwUj4AaqbuduSY3HnaFrP7B
         7/PLT+pEyo1HQ/BdELKnN7sfRIt/7sMlkvqSELrDyBTzgNPBiBjRYL+MT5SYuHNqcpiv
         9KQPD1br944H8Icj0uVPDsOP8Wn5OZs3ONNT9e+yHnI8BgbDHbseUMzf5JrO4BMTlkw8
         YxHKIWHDu8L46sQ5h+YBQPJ9Vb+q0IouTJR0MQCZpsC8SDBFgn7fNjCJ4imMfVOj7Rov
         SSiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764918895; x=1765523695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+8xZgc6aDI9inu3MeYL9yhC8BZulIRvR8wlciLKAr/k=;
        b=Boh3IRfXJbfskH7jvl7PZpa5Eo+WSqo5vujSOk41HYuQ0BWbnCnTfwRJ72NmabPJ7/
         eXhGaPnJf3EPkKf/jmdw3wKLX7Q3gBQKOU//CFnBuvwlBCwdFqBoFUDoMAWGsBH7js5E
         JN4IyApz6aqTuVOeCVPskqVY5mg3SxfmVVmYNyT8uctglhg4HqZ4PcK7TMubcYuWJ/GI
         7z+EYQjgwtPawLi5h/cqDRMmBVq48UkXSLQnR2nylFz0QPH6Xo5NzTQrqZnppU5m1fqT
         Vc97LA3NA+m9I66x140YJV2soyoBq1CbFi0ygUOBnJbQDcn66g9CWuEhrmPmKoIG95Ys
         d2HA==
X-Forwarded-Encrypted: i=2; AJvYcCVdpJmBW518y5fZGtc/hcZhbQYJcPyNv44c3PsopNYZeMQkQEgt90D8SoOACLQsb2MWouOReg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5YanF3bUmb0S0ekO9PyF8KHJmjhWvGAqbGfktmVMLswR1rfpS
	fCr4tH5FAY096S4OC6Mj7/ARJ1qjr/a27XBd8YCPLfKKq1mxRgf2AQTe
X-Google-Smtp-Source: AGHT+IFKHq1UfmbYlerFhkh/sTEoqPoWY7ohUVN7nlhupq4kC0Bkz2nbKLy6F9W6sIT5SThaEwXmWA==
X-Received: by 2002:a05:622a:cf:b0:4e8:aa15:c96d with SMTP id d75a77b69052e-4f01767e963mr120492261cf.55.1764918895358;
        Thu, 04 Dec 2025 23:14:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+atAhNUDZ7OUWMuKP2Hyk5z3hB1x+Yy88z0NDwj0/xEvg=="
Received: by 2002:ac8:7d8d:0:b0:4ed:9424:fa31 with SMTP id d75a77b69052e-4f024c53e91ls35306161cf.2.-pod-prod-01-us;
 Thu, 04 Dec 2025 23:14:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUaZ4secX7Pb3RWaeTNs2PKRFObqNBG69dCb271r1swfCC2uSkiW55IZD2EwuO5z25VIJWJ0B4JGNI=@googlegroups.com
X-Received: by 2002:a05:622a:19a1:b0:4ec:f394:bc8e with SMTP id d75a77b69052e-4f01758cee7mr141693641cf.22.1764918894541;
        Thu, 04 Dec 2025 23:14:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764918894; cv=none;
        d=google.com; s=arc-20240605;
        b=B0ZVQva1GpDHCmD23dl43bH036WjTpoE+psdV0SpmGC3zlF6ZzPdFiw5kDdJs8wIvX
         H01AIdb2DHgVf/or9D/DoCEYLIdVijLyil5Kru+TL6FqQzcCtmWcmP/BRSNLydMyPCuJ
         QRKgHvBiHrY3apcFczX3bF6FlZQplHkG55bhlYIAzhJdwfUVMuJQTcYMG8jt5xp405Bs
         XYOoBANLux6+L9sm/7XP5530wzhTohkKA/m8ROfkRAS8Ab/TOIEce7gqHugCeRGZ9sPO
         fNyum/AkFYurt9WJ33yigO+Am73v7/fSex2CC/GdTfHnzgMpl+kLszVbdqLTQ87qe8iC
         iuZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NQFFwyyrbmSQDwjSydErzLovNjSAb4Pxxp/akbzvISk=;
        fh=bMZBJix3YMSVI/m5jYA+cZd5+5N920UloQTCzaIamYQ=;
        b=eiUb839TWkb82Hc/NIKfgJW5W26Dfv1ynYWm2Nyqn/CeQRvx1KbFKLwCN+CVj2QhSf
         jMR2ZSZYoFiea7uqQiV1v/8sDPHuVi55F6GC6Kpk5ZZ0Y8i2rv/dtOYX+ouUl2yUVtth
         R3Np/PBttRDbm0+ec83BND3WFovZRayu7uH2unP5p0bZOA17oZWtkHys86+gLkJF1NPf
         SIr1dZp0DRNfyL/iQDvmxyZGy1Zpz0ZH7HB3Gpi4+gLzwyAuJhKL+ol5Z/zNVGQiWxVF
         AHgnKNWyQ793eNkmdvaQ3AcnlbRGUSY4a+/YN4AKFLz9/WENaQVrY6XwF2eGUkdR2gzY
         bu8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fx8mSw2M;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88827ef5cbesi2030266d6.3.2025.12.04.23.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 23:14:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-159-U-7T_gsNNiuj00amjV2_Jg-1; Fri,
 05 Dec 2025 02:14:52 -0500
X-MC-Unique: U-7T_gsNNiuj00amjV2_Jg-1
X-Mimecast-MFC-AGG-ID: U-7T_gsNNiuj00amjV2_Jg_1764918890
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C2D2F1956095;
	Fri,  5 Dec 2025 07:14:49 +0000 (UTC)
Received: from localhost (unknown [10.72.112.128])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 988881800577;
	Fri,  5 Dec 2025 07:14:47 +0000 (UTC)
Date: Fri, 5 Dec 2025 15:14:43 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aTKGYzREbj/6Hwz6@fedora>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fx8mSw2M;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > Currently only hw_tags mode of kasan can be enabled or disabled with
> > kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> > sw_tags mode, there's no way to disable them once kernel is built.
> >
> > This is not convenient sometime, e.g in system kdump is configured.
> > When the 1st kernel has KASAN enabled and crash triggered to switch to
> > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > while in fact it's meaningless to have kasan in kdump kernel
> >
> > There are two parts of big amount of memory requiring for kasan enabed
> > kernel. One is the direct memory mapping shadow of kasan, which is 1/8
> > of system RAM in generic mode and 1/16 of system RAM in sw_tags mode;
> > the other is the shadow meomry for vmalloc which causes big meomry
> > usage in kdump kernel because of lazy vmap freeing. By introducing
> > "kasan=3Doff|on", if we specify 'kasan=3Doff', the former is avoided by=
 skipping
> > the kasan_init(), and the latter is avoided by not building the vmalloc
> > shadow for vmalloc.
> >
> > So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> > common code to make it visible in generic and sw_tags mode too. Then we
> > can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost =
for
> > kasan.
> >
> > Testing:
> > =3D=3D=3D=3D=3D=3D=3D=3D
> > - Testing on x86_64 and arm64 for generic mode passed when kasan=3Don o=
r
> >   kasan=3Doff.
> >
> > - Testing on arm64 with sw_tags mode passed when kasan=3Doff is set. Bu=
t
> >   when I tried to test sw_tags on arm64, the system bootup failed. It's
> >   not introduced by my patchset, the original code has the bug. I have
> >   reported it to upstream.
> >   - System is broken in KASAN sw_tags mode during bootup
> >     - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#u
>=20
> This will hopefully be fixed soon, so you'll be able to test.

Great news, thanks for telling. And thanks a lot for careful reviewing.

>=20
> >
> > - Haven't found hardware to test hw_tags. If anybody has the system,
> >   please help take a test.
>=20
> You don't need hardware to run the HW_TAGS mode, just pass -machine
> virt,mte=3Don to QEMU.

That's great, I will manage to test it in this way.

>=20
> I also wonder if we should keep this kasan=3Doff functionality
> conservative and limit it to x86 and arm64 (since these are the only
> two tested architectures).

We may not need to do that. I tested on arm64 because it has sw_tags and
hw_tags. And if x86_64 and arm64 works well with kasan=3Doff in generic
mode, it should be fine on other architectures. I am a little more
familiar with operations on x86/arm64 than others.  I can manage to get
power system to test kasan=3Doff in generic mode, if that is required.
From my side, I would like to see x86_64/arm64/s390/power to have
kasan=3Doff because RHEL support these architectures. I need consult people
to make clear how to change in s390. Will post patch later or ask other
people to help do that.

While there seems to be no reason we don't let other arch-es have this
benefit if the underlying code has paved the way, the arch side only needs
two lines of judgement code. Personal opinion.

> >
> > Changelog:
> > =3D=3D=3D=3D
> > v3->v4:
> > - Rebase code to the latest linux-next/master to make the whole patchse=
t
> >   set on top of
> >   [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
> >   [PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific =
implementations
>=20
> Note that are also:
>=20
> [PATCH 1/2] kasan: remove __kasan_save_free_info wrapper
> [PATCH 2/2] kasan: cleanup of kasan_enabled() checks

Right, I saw these two patches, and have rebased code to sit on top of
them. There are some conflicts, I have handled them manually. I only
mentioned the cover-letter one to state the whole patchset.

Sabyrzhan Tasbola [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
Sabyrzhan Tasbola =E2=94=9C=E2=94=80>[PATCH 2/2] kasan: cleanup of kasan_en=
abled() checks
Sabyrzhan Tasbola =E2=94=94=E2=94=80>[PATCH 1/2] kasan: remove __kasan_save=
_free_info wrapper

Thanks
Baoquan

>=20
> But I don't know if there will be any conflicts with these.
>=20
> >
> > v2->v3:
> > - Fix a building error on UML ARCH when CONFIG_KASAN is not set. The
> >   change of fixing is appended into patch patch 11. This is reported
> >   by LKP, thanks to them.
> >
> > v1->v2:
> > - Add __ro_after_init for kasan_arg_disabled, and remove redundant blan=
k
> >   lines in mm/kasan/common.c. Thanks to Marco.
> > - Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
> >   this is found out by SeongJae and Lorenzo, and also reported by LKP
> >   report, thanks to them.
> > - Add a missing kasan_enabled() checking in kasan_report(). This will
> >   cause below KASAN report info even though kasan=3Doff is set:
> >      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >      BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
> >      Read of size 4 at addr ffff00005f747778 by task swapper/0/1
> >
> >      CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMP=
T(voluntary)
> >      Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2=
.10.20220810) 09/30/2022
> >      Call trace:
> >       show_stack+0x30/0x90 (C)
> >       dump_stack_lvl+0x7c/0xa0
> >       print_address_description.constprop.0+0x90/0x310
> >       print_report+0x104/0x1f0
> >       kasan_report+0xc8/0x110
> >       __asan_report_load4_noabort+0x20/0x30
> >       tick_program_event+0x130/0x150
> >       ......snip...
> >      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >
> > - Add jump_label_init() calling before kasan_init() in setup_arch() in =
these
> >   architectures: xtensa, arm. Because they currenly rely on
> >   jump_label_init() in main() which is a little late. Then the early st=
atic
> >   key kasan_flag_enabled in kasan_init() won't work.
> >
> > - In UML architecture, change to enable kasan_flag_enabled in arch_mm_p=
reinit()
> >   because kasan_init() is enabled before main(), there's no chance to o=
perate
> >   on static key in kasan_init().
> >
> > Baoquan He (12):
> >   mm/kasan: add conditional checks in functions to return directly if
> >     kasan is disabled
> >   mm/kasan: move kasan=3D code to common place
> >   mm/kasan/sw_tags: don't initialize kasan if it's disabled
> >   arch/arm: don't initialize kasan if it's disabled
> >   arch/arm64: don't initialize kasan if it's disabled
> >   arch/loongarch: don't initialize kasan if it's disabled
> >   arch/powerpc: don't initialize kasan if it's disabled
> >   arch/riscv: don't initialize kasan if it's disabled
> >   arch/x86: don't initialize kasan if it's disabled
> >   arch/xtensa: don't initialize kasan if it's disabled
> >   arch/um: don't initialize kasan if it's disabled
> >   mm/kasan: make kasan=3Don|off take effect for all three modes
> >
> >  arch/arm/kernel/setup.c                |  6 ++++++
> >  arch/arm/mm/kasan_init.c               |  2 ++
> >  arch/arm64/mm/kasan_init.c             |  6 ++++++
> >  arch/loongarch/mm/kasan_init.c         |  2 ++
> >  arch/powerpc/mm/kasan/init_32.c        |  5 ++++-
> >  arch/powerpc/mm/kasan/init_book3e_64.c |  3 +++
> >  arch/powerpc/mm/kasan/init_book3s_64.c |  3 +++
> >  arch/riscv/mm/kasan_init.c             |  3 +++
> >  arch/um/kernel/mem.c                   |  5 ++++-
> >  arch/x86/mm/kasan_init_64.c            |  3 +++
> >  arch/xtensa/kernel/setup.c             |  1 +
> >  arch/xtensa/mm/kasan_init.c            |  3 +++
> >  include/linux/kasan-enabled.h          |  6 ++++--
> >  mm/kasan/common.c                      | 20 ++++++++++++++++--
> >  mm/kasan/generic.c                     | 17 ++++++++++++++--
> >  mm/kasan/hw_tags.c                     | 28 ++------------------------
> >  mm/kasan/init.c                        |  6 ++++++
> >  mm/kasan/quarantine.c                  |  3 +++
> >  mm/kasan/report.c                      |  4 +++-
> >  mm/kasan/shadow.c                      | 11 +++++++++-
> >  mm/kasan/sw_tags.c                     |  6 ++++++
> >  21 files changed, 107 insertions(+), 36 deletions(-)
>=20
> One part that's still missing is a Documentation change.
>=20
>=20
> >
> > --
> > 2.41.0
> >
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
TKGYzREbj/6Hwz6%40fedora.
