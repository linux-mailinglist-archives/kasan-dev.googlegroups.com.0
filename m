Return-Path: <kasan-dev+bncBCKPFB7SXUERBCPH6HCAMGQESBIO6WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 018C5B24825
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 13:14:19 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-88193bc4b09sf1371878339f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 04:14:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755083657; cv=pass;
        d=google.com; s=arc-20240605;
        b=fZIENDB3o7gywEXJyZi2G5xRTax/c3byZEx41pz5Svqmm2OX1t/HjCLj4Qv6DB1cUv
         ZeEx3zhlYEVHIXQ1ciOdGE7DGhW2YUAMug0+a9X5uQX9jYO+kOO44shSUUvptj76gu0I
         vENs0oMzcKzmEC+/bV6nSwMgiQ6M8L90yH4blYwk3cpsllxaLix1aig86+lty+Wa3UM6
         djbhfxUwAHMRkIFKanyEKvmsLquxMzliRhAd7/TcRAONHm1KGqjH3ylH9lY7dAU1xVnW
         OCg5oE6uENgGjD5xIMtiijNCu2tIUFqHgLgMCSWrfbFDC6sPe6SsMSgQexlZmtrpI9/V
         1pWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=R3WqfGoXk1cc+1TEj9zkN3E/MJdOvbWBEEWb2FiM5r4=;
        fh=XszB9VGSZX73JqYlu4YRZ/ZBSa1QN8qbZ9g1UItZ8KU=;
        b=ajAM00O+XylElIZET5gd1q7R116e/0m20tqJ1OXNFHOM1npxu0czNzTCAaOO8nr52u
         x3dNeb0KnTEfqsfDYbxfgdL7MGimtwFCk5DNIyMR5i1AsWJmdozhqVeNHuBIMrG1P1n4
         N04mNp0IvYfiJWK543dLQ2wLwflg6oaxkzde+/12xT1G+m6HoIsGiwcKBZT+d7FAgPtE
         bqP8ZOUPVDkjw8UUIdKLk6ea8YRL5zKP+lPSQo0csbdaePTpOvgo3irusEMfRL2IWAGC
         Oaa2I+J9mLuAHTn5WWmBMpSwp774MAunRyNir5MKW7DrQ+JBX7SF3lnPf/DRqUZ4hxnX
         Kl9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UmPGhcVK;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755083657; x=1755688457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=R3WqfGoXk1cc+1TEj9zkN3E/MJdOvbWBEEWb2FiM5r4=;
        b=Bkak1ec2UYfHyzg9nrTxCiP1+54NbVs5h9R/iouGXrmgasc2FfSzu/h3apVrwqHBU7
         l0g+YuGygK7G4I56vnA0xRD1AKVRm9/UBSryPCZtJcTuiJvLa+Ado2PE7QYWW+4zS7A8
         x8fqe8uBgmQvU5hBQM2X26HKSnEO9ygCA/ZgrMj0nSldM/5DoWmjzdY04D686gQl2dxG
         FqtQHzyyipOGem2g5cIpPKiRkYC/lVdKSNAa2et3YSOQtmh1zrdvE/489qO65XS09LgD
         IQqCV7R8Lli+tp59XxYzFyYj8fFki0+vSTR6SihOH0G1iFhZYqloHKbSx6zKdXlMHBUi
         DXEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755083657; x=1755688457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=R3WqfGoXk1cc+1TEj9zkN3E/MJdOvbWBEEWb2FiM5r4=;
        b=F19H1twWC4atcMA15XdahA/OZRYEuw7ZdcJlPXbBtG3bdO5fSw++oQLq0qIPUgrgRT
         5ng/0FcxpMBVs/H7RF8taoelVL6IuXvGod2mrX5gxQH/krqpFvUNZUbfPLyN3GHLFxY8
         jhpN49kl0P7vSqtE+U+VyUG+Bq0GfgiZ/rjrlNilQNqQLGAm2XUFt9Vp7Bi4UlSx+ick
         lMKaYtkvwBlhwKo8LTYWpJh5O9aARp42I8yjrVvLl2to+21EfOdi0vQ+s7GNjcB0nkC4
         PQJ5U7iMk13MeSDu4TSG/IvvvB7i2iMyYW+A1iQK3T/x6iG+dHJCXl2oBAe8EFVnsuwb
         /xaA==
X-Forwarded-Encrypted: i=2; AJvYcCWONonJZjFiQljQIlEuhtWNeWx05ml9BfnzABAFFaIjIQ1JXFxMk7dBB5roqO8Gh0e1dugTIA==@lfdr.de
X-Gm-Message-State: AOJu0YzOUhN4dJUGJ7KcT1S+k5dkkOwJXA3FUnQ4Wa2bla50h7LeokCi
	jJJuR5WYsq7NV86TxSt1l01TnAdCg88e7i07LPdIddNXEO5PUpiPoWDC
X-Google-Smtp-Source: AGHT+IH++PJRk8GilNAYpMVtvPCtift5dGX9qH0rK8NujZWXKqT9xE94pvCTJwOxSx31luSq8Nknsg==
X-Received: by 2002:a05:6e02:4904:b0:3e5:67a6:d41b with SMTP id e9e14a558f8ab-3e567a6d662mr42673335ab.12.1755083657519;
        Wed, 13 Aug 2025 04:14:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfERhNe4irt0khudNrcgFAoqWSRPMePN49g9TOyL3yTIw==
Received: by 2002:a05:6e02:3a09:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e56d695252ls1138225ab.2.-pod-prod-02-us; Wed, 13 Aug 2025
 04:14:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCDotOEwPvdzZSwbUl0wM3CcDOngpWwbNu14rC2WWCCeRoiAnSkwoCZAdm5JyvrksiZXdnRY4TkkA=@googlegroups.com
X-Received: by 2002:a05:6e02:1a4f:b0:3e5:3d13:5d8f with SMTP id e9e14a558f8ab-3e5673f6386mr41569465ab.9.1755083656466;
        Wed, 13 Aug 2025 04:14:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755083656; cv=none;
        d=google.com; s=arc-20240605;
        b=Hi9pCEo7DlbNOrjxSR6rGN4rsn1bZvhqalNcGrtTFWukMgJHBAd0t/TYQ1b9oDVpoH
         pNr4kEi+l1nJQXUM42dLYMWE/UU9gBr905AXuY55lfB+kjDyrGXWgNAalLZkBbPGcpHL
         R6Yg5CLZSPMhWGx07muhMn74wUUR1fxiJkwx38pqaIVmUliVZHfE6FSvJoR9qb2eedNq
         nFm9MOr+6FJUXgzyWe/jw2zWMay/gEAS9u8AZr3Ss7uevr5WfioPsKK6XPb9FTqir7XD
         iBHHlbqQsnzkai2r+wBUTcthyFHeaANYb27ejKejOfvW2emibzIYrrNoOAJ/P1WIHYTr
         emDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yNVE6wsMC8x7hacYqMkArJqlP3u73DUjInfZebo80YI=;
        fh=gOqAOsSLdoPOBJo0QozQvoXYivyuMTi1+Jbh8fKO3S4=;
        b=Yv1czdVkYqa/upUh7YO8gom4cNwGq8Fo7Yl3wuF40P/cQjcb671oc64eBp2vmAwTlz
         MiF/kW4GYOSzxIXtxsTlkv8vyFbMTVT/7Vas3ATxsJwirCCQGMlFmnQmQXZf0MLiR9aJ
         M2W1mlDlTEM94mZHZSHrk7gNrV/WRznxPG9B+CBadTLo+SF/BIW8uuVsGTst5RR413Tf
         8jtOvI+iQJaQiQMvMsxtIHRwaA1LIEvk6qMWoNOwUr5cz9uf7v9vjbtEHE3h0PBJDqnJ
         /KwnxcqfV7EvK29KfWQAJJzkicDbUdx+ZMLW3IMO/nxZbnllh4lKNYvWdhHKewrNCKky
         5IHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UmPGhcVK;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae99c28d4si593814173.1.2025.08.13.04.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 04:14:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-205-4Pp8IIsdO9WiKTWHKKqYIA-1; Wed,
 13 Aug 2025 07:14:12 -0400
X-MC-Unique: 4Pp8IIsdO9WiKTWHKKqYIA-1
X-Mimecast-MFC-AGG-ID: 4Pp8IIsdO9WiKTWHKKqYIA_1755083650
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F1FC61800291;
	Wed, 13 Aug 2025 11:14:09 +0000 (UTC)
Received: from localhost (unknown [10.72.112.177])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0043630001A1;
	Wed, 13 Aug 2025 11:14:07 +0000 (UTC)
Date: Wed, 13 Aug 2025 19:14:02 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com, elver@google.com,
	snovitoll@gmail.com
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv>
References: <20250812124941.69508-1-bhe@redhat.com>
 <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
 <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UmPGhcVK;
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

On 08/12/25 at 07:14pm, Andrey Konovalov wrote:
> On Tue, Aug 12, 2025 at 6:57=E2=80=AFPM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> >
> > On Tue, Aug 12, 2025 at 2:49=E2=80=AFPM Baoquan He <bhe@redhat.com> wro=
te:
> > >
> > > Currently only hw_tags mode of kasan can be enabled or disabled with
> > > kernel parameter kasan=3Don|off for built kernel. For kasan generic a=
nd
> > > sw_tags mode, there's no way to disable them once kernel is built.
> > > This is not convenient sometime, e.g in system kdump is configured.
> > > When the 1st kernel has KASAN enabled and crash triggered to switch t=
o
> > > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > > for kasan shadow while in fact it's meaningless to have kasan in kdum=
p
> > > kernel.
> > >
> > > So this patchset moves the kasan=3Don|off out of hw_tags scope and in=
to
> > > common code to make it visible in generic and sw_tags mode too. Then =
we
> > > can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cos=
t for
> > > kasan.
> >
> > Hi Baoquan,
> >
> > Could you clarify what are you trying to achieve by disabling
> > Generic/SW_TAGS KASAN via command-line? Do you want not to see any
> > KASAN reports produced? Or gain back the performance?
> >
> > Because for the no reports goal, it would be much easier to add a
> > command-line parameter to silent the reports.
> >
> > And the performance goal can only be partially achieved, as you cannot
> > remove the compiler instrumentation without rebuilding the kernel.
> > (What are the boot times for KASAN_GENERIC=3Dn vs KASAN_GENERIC=3Dy +
> > kasan=3Doff vs KASAN_GENERIC=3Dy btw?)
> >

Thanks a lot for checking this.

>=20
> Ah, you don't want the shadow memory for kdump, sorry, I somehow missed t=
hat.

Yeah, for kdump kernel, the shadow is a heavy burden, and most
importantly kasan is useless for kdump. We don't want to capture a
kernel memory bug through kdump kernel running becuase kdump is a
debugging mechanism.

>=20
> I'm not familiar with the internals of kdump, but would it be
> possible/reasonable to teach kdump to ignore the KASAN shadow region?

Yes, we can teach kdump to do that. Then people may hate those conditional
check "if (is_kdump_kernel())" being added in kasan code. E.g even
though we skip kasan_init(), we still need to check is_kdump_kernel()
in kasan_populate_vmalloc(), right?=20

Combined with the existing kasan_arch_is_ready(), it will make kasan code
ugly. I planned to add kasan_enabled() via static key
kasan_flag_enabled, then it can also easily remove kasan_arch_is_ready()
cleanly.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
JxzehJYKez5Q1v2%40MiWiFi-R3L-srv.
