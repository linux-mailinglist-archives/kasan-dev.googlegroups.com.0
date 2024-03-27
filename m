Return-Path: <kasan-dev+bncBAABB6HISGYAMGQEMGCEHSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id CB28588EF3A
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 20:33:14 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2d486c08c6esf1007221fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 12:33:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711567994; cv=pass;
        d=google.com; s=arc-20160816;
        b=HGww1+EOsEV/MQXTOBtLwD1Yh6tZjlEv3o77RRjTLd1+B8USuUCFYqMprjd8GLjFJI
         cfALf/uaqFW/zwKNEefFxkz3MIWZaVm+mwkkqD1PrqT60V97I9iKiNDRcKTsAIc1rbB0
         zitYqNPuYGQXn1hzGHKVbhXyk7RaFP/FkRKipUPyLUP+zRPuxCL+IEWo39dzmhxYCk4f
         eMY7wgxFWl0H0F9zcL5bBShlAQ7tYwhAY3wTvRwmZFfjFYcvvmA5yjQ8UTiBX/OEj2Jw
         X5Ul8VmoqwCst9n0mFfhNLcW6ZtBihbLBD8OEjTf7f1gW7wKmZ5rR1OBl3uSGdzb/fHl
         gqNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=9xBBv88lh6Fec1sbyrcniFMMGyxpeZbpl9mhdMClmSs=;
        fh=InMLl9M6ME++4zKW1U7igrvDb3nvx2e227Xy9C59JiI=;
        b=USFGf6IuxhzBtaxICQ3DTZq/bx5mpUyhdR1tIANNF7MpE/HtBvJ/+XwTxX5bM9Ni9T
         U6H8WsEbw36W891lX6qeafFGlKvdKbbKoqMlYxADzBiV7VY9n5y0jsa8fuiep4tLg0Eb
         XezboJXFKjuRwjKr/OERYCjtXEZBm5RTycxDHQbnlXO6TTW4yJmoM+L5N4SKPJjtzarP
         ns0UP2I6HVVa4LA3kL5tWTckquJ9ppwXV0qKC90F4Zvn3Q+05fsEY5sCH2SVU+sFMoz7
         ujcrDxIR/l0/OzvI0VXYxxI6kjkxAoJ/rmlhYtiHTFHjNWJ1QUI3wSJVpr7DktB/JOzu
         o6FA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=I7VDWqtE;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711567994; x=1712172794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9xBBv88lh6Fec1sbyrcniFMMGyxpeZbpl9mhdMClmSs=;
        b=eP5b0VMxvNpgyloFlEg0kYCH74zzoQespOLYnTqiRAFIBOp9Zq6TQWd7k+9bgoQjkf
         lej1RBohsIq94ga35ShQK5RMd4bbfTHQFu6C9vMztqwzf0cF631JFNDS4UyfAMyHVKXD
         +bhFzw2KXYvz8Eqs//sYwMn34+J6UDS4HDRdVkPfLhnXjeKj60r3cAFamzM/7YPYNh9t
         iQwwzSMM6Ms6yZUajNHohAIcpYjJnTBKDrNxx2rlxo1dcJp2vmrdZwOKO0jmd5p+RsKu
         VkthEgT0C9WXxQZQ+N3140LN0diIIhz6EeSkVcCA8TVGywotwa1Qx7ZRNmLAhESiFlc+
         lLyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711567994; x=1712172794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9xBBv88lh6Fec1sbyrcniFMMGyxpeZbpl9mhdMClmSs=;
        b=ZTVAzTHr9HoIhC9QqOELARmp1vO0ez5P5iR+pWnFDVLy8T58LdQa8gPUpVLJXoEiVL
         Q8MOvD0b7gFMsWCNnpYFK61P+zn/YK8yf6IK+J4glVNRGGvA1ilmKdOTC81SMqyOGt1M
         buuo1sMXrQtNLU4ECaNKZ51hxb0PVtAP7RXPb0UrCNqWJmsQRcicWYaVVeinJq9VZuYE
         iQi/qw0ZGfa36eRgpVxdM9GBfIi80Dkd2O4G0qE5T6i/X4o1KefjaS99Wx3L0mgyGAZh
         14GxVfR+iK1jiEfEWfqBKKzpfKfqa0Cr+8WSVGq7gZYdzhhza6JUdueAR2thetsEp4NG
         bpFA==
X-Forwarded-Encrypted: i=2; AJvYcCW/ZJyeZ6p0K7i3+ZsOZwrKxvPaydLvRdDsqiCG5diSKZUoNoWVm4AWXBLUJ62gelCpRoTFBeLvou7yaJA3/fgB6QT8t7gPLA==
X-Gm-Message-State: AOJu0YwGZZxLcpnxESSiBJucTi5eoMQqrdllKoRKAxJrgXPsX6WSVgdk
	qGnosx6qhtt5b3XPwf7hGMIeatoYBtKtsRr6WPVZPIdOVCU1zH/S
X-Google-Smtp-Source: AGHT+IGH+52S30EC4Wpk7hZSKhOEVC+SV7yWOQjunx0RPArLCiggn2CyvaNQnm6T2w14QNpiM4cu3g==
X-Received: by 2002:a19:ca0d:0:b0:515:a417:334 with SMTP id a13-20020a19ca0d000000b00515a4170334mr282099lfg.46.1711567993149;
        Wed, 27 Mar 2024 12:33:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1590:b0:513:b057:b10e with SMTP id
 bp16-20020a056512159000b00513b057b10els129599lfb.1.-pod-prod-09-eu; Wed, 27
 Mar 2024 12:33:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWba/QJEAG6Vy/loetTgfot8SWv26MGism9cls4x6zrkuC4/q+3VwVvofaV/degu8Yyk7i1yMAFWi07Ghjmb4cxO5p2ObsNaiB+jw==
X-Received: by 2002:a2e:9e08:0:b0:2d6:a5f6:c8d3 with SMTP id e8-20020a2e9e08000000b002d6a5f6c8d3mr670590ljk.27.1711567991424;
        Wed, 27 Mar 2024 12:33:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711567991; cv=none;
        d=google.com; s=arc-20160816;
        b=tAeqtBIKNho1ourAKJLU6SJ6iZ9NydT7byHiTJMB5CtsVkbiyIK0elRdbQ88TQDfBD
         Vikd8PfnlX/KkpDY+SHSkrW7Px+AKybEo8k45Ej0MSL87Xm8FGX3mTWiiyZ9q4J0mAWS
         yA04qG+0jml1rQoymu0U5CtGwVWqM+3U3R0dO2JToGtx5rkc7Gb65H3CxzbQCdglUgrj
         fnAaOp1JclCCivNe/DC95DVfdUYL009tBAb830WP7Vde22ne6L3hoy/TTegrly84KC75
         ZjPKDCgp/cyqqQ5RLurcWdwfw/5rvC4FVKMP66wc4b+kfUedIyQRnHUZ1IHaMk289wUB
         DFpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=dmSKRn1YP1sM5l4LbQabquMp3yhVxs4wEJRW8a/mfk8=;
        fh=hKQ4ffVvBhmhTdvE47DbnHt5MSmyCDq+XT2q7/x6Nss=;
        b=q7KV5hg6li+ecIxPZGVbPO3Ogs6mm3o79riLztB4Q8OGYIq4gzbt7iA6GLv7V4luUR
         /thR0S9IB9JmbJKFHuwKQ8Ju3HpulItJG07SJQRYksFsCtTFqeF/jFqRF8Aqqqjh+Pu7
         1ci7afs4EauStdGfVQn3Ig/C8nRYgmlumQcmVG6fuKCac6D5wKjOEhq3rtAIm4VGvXJp
         LlKhG8oQhMIyhKYXc4ztI9TQY1YYwK+VXPM8W16vmMnrNkLAdUVUNJrBxb57Wv2chn1F
         Dh/9Kndufy90csOyKrBRvL5rKzdxHRCYXl7ju/apQYDLH3PqlWZ3x/IEf3HkT5ZT9vLh
         86Tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=I7VDWqtE;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
Received: from xry111.site (xry111.site. [89.208.246.23])
        by gmr-mx.google.com with ESMTPS id d18-20020a05600c34d200b0041494c86cdfsi63047wmq.0.2024.03.27.12.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 12:33:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) client-ip=89.208.246.23;
Received: from [127.0.0.1] (unknown [IPv6:2001:470:683e::1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-384) server-digest SHA384)
	(Client did not present a certificate)
	(Authenticated sender: xry111@xry111.site)
	by xry111.site (Postfix) with ESMTPSA id E7547676A2;
	Wed, 27 Mar 2024 15:33:05 -0400 (EDT)
Message-ID: <4d2373e3f0694fd02137a72181d054ee2ebcca45.camel@xry111.site>
Subject: Re: Kernel BUG with loongarch and CONFIG_KFENCE and CONFIG_DEBUG_SG
From: "'Xi Ruoyao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Guenter Roeck <linux@roeck-us.net>, loongarch@lists.linux.dev
Cc: Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui <kernel@xen0n.name>, 
 Alexander Potapenko
	 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	 <dvyukov@google.com>, kasan-dev@googlegroups.com
Date: Thu, 28 Mar 2024 03:33:03 +0800
In-Reply-To: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
References: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.52.0
MIME-Version: 1.0
X-Original-Sender: xry111@xry111.site
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xry111.site header.s=default header.b=I7VDWqtE;       spf=pass
 (google.com: domain of xry111@xry111.site designates 89.208.246.23 as
 permitted sender) smtp.mailfrom=xry111@xry111.site;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
X-Original-From: Xi Ruoyao <xry111@xry111.site>
Reply-To: Xi Ruoyao <xry111@xry111.site>
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

On Wed, 2024-03-27 at 12:11 -0700, Guenter Roeck wrote:
> Hi,
>=20
> when enabling both CONFIG_KFENCE and CONFIG_DEBUG_SG, I get the following
> backtraces when running loongarch images in qemu.
>=20
> [=C2=A0=C2=A0=C2=A0 2.496257] kernel BUG at include/linux/scatterlist.h:1=
87!
> ...
> [=C2=A0=C2=A0=C2=A0 2.501925] Call Trace:
> [=C2=A0=C2=A0=C2=A0 2.501950] [<9000000004ad59c4>] sg_init_one+0xac/0xc0
> [=C2=A0=C2=A0=C2=A0 2.502204] [<9000000004a438f8>] do_test_kpp+0x278/0x6e=
4
> [=C2=A0=C2=A0=C2=A0 2.502353] [<9000000004a43dd4>] alg_test_kpp+0x70/0xf4
> [=C2=A0=C2=A0=C2=A0 2.502494] [<9000000004a41b48>] alg_test+0x128/0x690
> [=C2=A0=C2=A0=C2=A0 2.502631] [<9000000004a3d898>] cryptomgr_test+0x20/0x=
40
> [=C2=A0=C2=A0=C2=A0 2.502775] [<90000000041b4508>] kthread+0x138/0x158
> [=C2=A0=C2=A0=C2=A0 2.502912] [<9000000004161c48>] ret_from_kernel_thread=
+0xc/0xa4
>=20
> The backtrace is always similar but not exactly the same. It is always
> triggered from cryptomgr_test, but not always from the same test.
>=20
> Analysis shows that with CONFIG_KFENCE active, the address returned from
> kmalloc() and friends is not always below vm_map_base. It is allocated by
> kfence_alloc() which at least sometimes seems to get its memory from an
> address space above vm_map_base. This causes virt_addr_valid() to return
> false for the affected objects.

Oops, Xuerui has been haunted by some "random" kernel crashes only
occurring with CONFIG_KFENCE=3Dy for months but we weren't able to triage
the issue:

https://github.com/loongson-community/discussions/issues/34

Maybe the same issue or not.

> I have only seen this if CONFIG_DEBUG_SG is enabled because sg_set_buf()
> otherwise does not call virt_addr_valid(), but I found that many memory
> allocation calls return addresses above vm_map_base, making this a
> potential problem when running loongarch images with CONFIG_KFENCE enable=
d
> whenever some code calls virt_addr_valid().
>=20
> I don't know how to solve the problem, but I did notice that virt_to_page=
()
> does handle situations with addr >=3D vm_map_base. Maybe a similar soluti=
on
> would be possible for virt_addr_valid().
>=20
> Thanks,
> Guenter
>=20

--=20
Xi Ruoyao <xry111@xry111.site>
School of Aerospace Science and Technology, Xidian University

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4d2373e3f0694fd02137a72181d054ee2ebcca45.camel%40xry111.site.
