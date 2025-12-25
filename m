Return-Path: <kasan-dev+bncBCKPFB7SXUERBXOBWLFAMGQE4AIWILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5446ACDD382
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Dec 2025 03:26:51 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88887611049sf192082646d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Dec 2025 18:26:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766629598; cv=pass;
        d=google.com; s=arc-20240605;
        b=WWL3PC4DXaSTX2HWT/GB7kBBbkKyyN5DaHPfcQCIkUATSmjPuKT4RIuHJnIvYW1m7i
         7tSJmDWhFkczjWHjMBjg16XvbL+E3jn7hmNKPRW0bzmO86yNiP5Dd9UhLuCebgu6sqnC
         bGEKNXih0U6wkVG7fe7FLG6LVB9VuOU3XbaRsfEnWMnU7rqhwJrbU111zONY+IpCTO4f
         ddb7dtcMzWxxDRWPyHYx4+Zp8D4R6n8kLtGUic+BRwgWIXg5FS2pkdHn+WNhpZH/f9xR
         AYWiGTcVJqxGqQn9n/8sLKVDoUe/MCw4nYlo+f7+TOe6NLPpYrztZH/+Q2OA6Jeuemhf
         nsMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=5qZ1FuN6N1wAHDCsVRTvX+Jj+zH8YTUkGmxJEEcPyi8=;
        fh=LnEM/3yew4DWTsxEZoPMUQgyNajLIhNX6MFrnW3aK+0=;
        b=WMmRM8dkMQ6yaQDR2KWoWY+wraJqThzGElG89VlWO8zkNM48Ze0PC2wO1dj29RwvYv
         SlEpZMGmpSPGW5+Sm07vMySHJXhtMnqPqELIOU7MeWZwYDgMNEfaIErTBDe4Im0hYsaJ
         Iba1BCR3uAnMxjoGDRyqUFg7ASjY1J7MnKiqYGqqlAh2h8gl7D2Fxp2X+lUS4QkkCXce
         OynYwS2+eGczyFGDhRzPpGI/yTovwMzIgAmdcBmDicDoZnh/s91CEdkPDKHZK3EuUQs0
         5qxUajtsG2jbIrXvBFz3O5eL4RYghKerW1BOMws+yOMMGx+l7+hT0e3FxddKefnDUFUG
         lMDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IUMbKaKj;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766629598; x=1767234398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=5qZ1FuN6N1wAHDCsVRTvX+Jj+zH8YTUkGmxJEEcPyi8=;
        b=Yk6cuUmGvtPhQuJFdvjD0yGlivj8W6UdBv3UOqYnvuIWZDJmX4NMRZHp0OahiA5BmU
         dOALz73b2WSOt0vXZ3ONGbX44BqilMO3x0K0f/eW5NNaXTVIcD+yCVL8AGU9I+GhjBeu
         9+F+wZJfQr4/gz5oM8LFWmRBE8BcwTCzvIK6fxKqLoWF/D8Zfp4IxQ1jcAVOVsaqvWGA
         LZm5gXdATPsfOF97AQGrdlDU7VzHZ9gPynUc8kGRpjgRpt6L6qDk2tp4l88/mX/Ajq2p
         3K5yz0IciUs3621TFsO7DHj4ZY4GwXdpdBYXpMMwNsV9ZESmj5P8xzuHHbJcT8BPHFcF
         UHYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766629598; x=1767234398;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5qZ1FuN6N1wAHDCsVRTvX+Jj+zH8YTUkGmxJEEcPyi8=;
        b=aEN6esaUvEtiqskYqG/TR3Jffp/VVRxFdYl9IN9l4oI8t55L5WSdw4fATUnLYwyWlL
         s5zR/14HvIrzZjk7xeRAumzpv267Yoe0jCNS0JqFMWhLrfwYpXEqkFA5IvP6CLaZm8s8
         fna9qgygRy92J7aik8h2aLIGImC6m0aaE9kjLkzC21/DTlP2ArTLSo7iB0Zd5zK6q/Ow
         JtHbur+mSjFRPJJAqP2bUTHz2xrmFQ47aR1oUNpwn4r/Dh8H+gyQSyJwFmQcu7eFLRwe
         iuzysd84dZh3j1BKjro1eXW/Q2PhpUfG0Bj9jfvJaMBHKbnyKf9bMM8yCEkAz6TlWZhq
         lwJg==
X-Forwarded-Encrypted: i=2; AJvYcCVWCZyDER/ZzHOba8jBvzqgK6HvIe4KLTfdl3Isur4upIWS+G5AKFHtKTlRiRr/7xy2XUDEYQ==@lfdr.de
X-Gm-Message-State: AOJu0YzBYjeQxEPsAjQC2E88LQHzX8FVuuvexNHhV2KX3JPWfUqTpsNf
	QLzE2dum8f3C7pZhMjSML8PyoeEV2FtvPqWtXqZKcViwpqwv6B4ESqb0
X-Google-Smtp-Source: AGHT+IFxPp5HZv3ZCCqaqMSX/YUerSxDuId5KgALCRtnVYxrvMwZvpkFxGOvxv3RnC+2lOzBIIxXAg==
X-Received: by 2002:a05:6214:3c87:b0:88a:2d09:abcf with SMTP id 6a1803df08f44-88d84c1a77dmr333663466d6.68.1766629597850;
        Wed, 24 Dec 2025 18:26:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbBlSliVkcEh1tdQPaOBveyyevNg0jhqZ9R0HHakc6Ptw=="
Received: by 2002:a05:6214:4105:b0:882:7510:5ec3 with SMTP id
 6a1803df08f44-8887cdb8cc1ls219698616d6.2.-pod-prod-04-us; Wed, 24 Dec 2025
 18:26:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXXQDvk4KOtupa7FSqpWuGssAkQclK8whkrfmQsuVGWvYi7HqYImDsGohUYg3X6q5L6ebJh0PX5t4=@googlegroups.com
X-Received: by 2002:a05:6102:dd2:b0:5db:f8aa:3a5f with SMTP id ada2fe7eead31-5eb1a85c32emr6634380137.38.1766629596694;
        Wed, 24 Dec 2025 18:26:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766629596; cv=none;
        d=google.com; s=arc-20240605;
        b=Z2r4XUcZZanvfwVVITlMdKWsK4KxcAeVzrFcv8qkE5DdOav9A0ePJmHwWqEy3J4yLB
         eo1uIx3/194NRiLf64yNtjoYQ3Xi1E9ipbUceTuBwdW4gh26lladIZagZq5t7YFKb/aP
         dN91aj1GdcbCjmJhZ5HHM0h3f2U8Q46wdjZqUvD+Z9cNtQquoqFWVVhY0nL7psp4lbYD
         TQK5T/2U2iFI1L1HQd5sfm5PPuVsR2hj8IK8eXVcrOaqFThecmNc+GuNnSmNAgwSekfw
         985/cRC/EQlHFqvr6mZnvkuBz/sOiSxWZWj+jpwVRdquqE09bLvZvwuDDP31/r57bZHC
         CK/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=0yhfpKa36z2S4e97UcvwglyoKQJoQuKZ4hzUKoJo5oQ=;
        fh=xFtr+XDHaB3peziTZkG3I7ds4PAaCmjJkD3n9joFmAo=;
        b=kqjahFQfQkmf9Dvl9uTg0yvQ49yp9yLKwPjmEn+vLSM9Ji6Ngr86Tm9+/9gcYjPfRS
         vWXI5Fyc2C+gRrEaPPq3Sew1ETxW6kimm90Om0RQovDadr4HP7/ntvZ8vIDwBJ3kSRbt
         aZrK77mbXPK1gBhaInsvRpLn7iXAAI7nzhKbsEBUQ//2EuIGqqrW11fr8tdgE8NEdVFl
         Aas2yV5zufySSEqMNAXEkDqT2VYJucpOuLpIcX5WteDdVzwFwnbo2TYrxSMVMdA/x77E
         TWNcGQz3p8glPbIACFO4PIMpCao6B+oXMuuA2B/5LlVz/sMmsWV3Aslcc4HIWpuFkNpi
         SZ7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IUMbKaKj;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-9434172effasi823929241.3.2025.12.24.18.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Dec 2025 18:26:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-284-XD3JdoSdMca2cw992Umbgg-1; Wed,
 24 Dec 2025 21:26:32 -0500
X-MC-Unique: XD3JdoSdMca2cw992Umbgg-1
X-Mimecast-MFC-AGG-ID: XD3JdoSdMca2cw992Umbgg_1766629590
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8A7461800365;
	Thu, 25 Dec 2025 02:26:29 +0000 (UTC)
Received: from localhost (unknown [10.72.112.137])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 9F37A30001B9;
	Thu, 25 Dec 2025 02:26:27 +0000 (UTC)
Date: Thu, 25 Dec 2025 10:26:23 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aUygzzVSqg52TANl@MiWiFi-R3L-srv>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
 <aUtd6es8UC0lNf/9@MiWiFi-R3L-srv>
 <edd6e350-5482-4551-aa94-e1ab8d2f9774@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <edd6e350-5482-4551-aa94-e1ab8d2f9774@gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IUMbKaKj;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

On 12/24/25 at 01:25pm, Andrey Ryabinin wrote:
>=20
>=20
> On 12/24/25 4:28 AM, Baoquan He wrote:
> > Hi Andrey,
> >=20
> > On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> >> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wr=
ote:
> >>>
> > ...snip...
> >>> Testing:
> >>> =3D=3D=3D=3D=3D=3D=3D=3D
> >>> - Testing on x86_64 and arm64 for generic mode passed when kasan=3Don=
 or
> >>>   kasan=3Doff.
> >>>
> >>> - Testing on arm64 with sw_tags mode passed when kasan=3Doff is set. =
But
> >>>   when I tried to test sw_tags on arm64, the system bootup failed. It=
's
> >>>   not introduced by my patchset, the original code has the bug. I hav=
e
> >>>   reported it to upstream.
> >>>   - System is broken in KASAN sw_tags mode during bootup
> >>>     - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#=
u
> >>
> >> This will hopefully be fixed soon, so you'll be able to test.
> >=20
> > Do you have the patch link of the fix on sw_tags breakage?
>=20
> I think this one  should fix it - https://lkml.kernel.org/r/cover.1765978=
969.git.m.wieczorretman@pm.me

Awesome, let me apply them and test. Many thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
UygzzVSqg52TANl%40MiWiFi-R3L-srv.
