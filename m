Return-Path: <kasan-dev+bncBCW4XEU3YIIRBYUZ3GOAMGQE3DNDXFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DFC9649687
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 22:34:27 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id w15-20020a05640234cf00b0046d32d7b153sf3960990edc.0
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 13:34:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670794466; cv=pass;
        d=google.com; s=arc-20160816;
        b=qXI8m4IhkBQV5qc7V68sEcA9432/CaxuoAZPZT51NbN8+xZrhmnFsh3nJQUelopYXc
         F7opCvE5QNjL74LjY0IBXnam+0vk9PoK/srCuYzcXxAad92/pXOqjDJWIEqlpK7akDRd
         XPchsgwzKFo5lRNanlaqdp4VAE9YPfOm86STax9NTN3bLeXbnWA/+ONo0DqeWQ5MBuev
         W1XVXg5yYu7gvhos5d5Vvny6dzhKOcM9Pw4R5UB4p2IF9qSpwwC29fTdFOv28MJf5A0Z
         +5qZpS0+pYtWp1VaqPxePj4Ojk/2wcfRIYG/0Or7huXT8X5KbA0ZdGxrrdQoOHWGUepT
         JItg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:references
         :message-id:subject:cc:to:from:date:feedback-id:sender
         :dkim-signature;
        bh=h9Q1i4hIdU/E3nlQyNMODMHAvMDWZyrov34ZiWe5wMg=;
        b=xSQerWyq5QIHVcRCjhybPd+ehkTrp7wrXouKxDrrWly2nVkqmKEQUqYaiT+A6oPcY7
         A+Kz89eDXMR4oGJH8rcJTIaver21mr3DoKyA77PWzs2Ld3CelEu7+A3FQ/5yPh2OT6+s
         Np0AT06jNTv2SuTN/BFp17X7YaKyTc2rbZ+A8KmseGIKr565vNsZRwT3H50aHGKp5iGS
         +BR7CnbX57wannr2xWFH8YolcbunwVuBBDHwHCYA55io04ye0z9AxYSADh3fYuaMF2d0
         rOIdySGMJcy8l/Ytzc+hUgSus1qGaG57CRztpyzAEPIMPGGU3G8rsqEWkhxievgpNI4T
         kmGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@invisiblethingslab.com header.s=fm1 header.b=Q3EnF85w;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=ebyAHeuk;
       spf=neutral (google.com: 64.147.123.19 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h9Q1i4hIdU/E3nlQyNMODMHAvMDWZyrov34ZiWe5wMg=;
        b=Xytt5sccDYMvwB432sieola/OBTxcp0j/1y9yD37nqSFjRp0j9j5blelW9ig6zjPco
         YkblMR8AuHZE0dilSg852Kk6xCDc/H0qeCiKfQQ4FwveQW2a/wyHZCHi75gxzcis3+xB
         viQeo7o+AKNClhInsNGXC2tzi2hqyobHG349Grb5cx/N7rn45c7mtJ/URFo2Odt+GhRB
         M/ea1Tp6YcRY+EBj/kSREEkFNeuF82nPT/i69vrjbEchfuKo0GE1eOT9uupKZ5DADuo2
         BiuKUi2H3S09CHvNz/nxoraQsBao2XlhBXZwlty7/c1HEWfxIG/dRo1qqtIfcwD4cxTG
         HaRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h9Q1i4hIdU/E3nlQyNMODMHAvMDWZyrov34ZiWe5wMg=;
        b=rXxUyuKGemuId2Jm9Fb3GjegcP3buLqd4gTs6OwDJnYa+M7Bqg6pIGP9xHmDzCjIKr
         6yiDfKpO7ObeRuA2L5ledO2LdCrmckXn3ZJxMQujWJuFgIEpB+1ARtrQ0ZznOHtC3jvH
         1DyG07QiuwqH7lITmp5zFGIghNkOl5l/405GXjKI9YEoNJwFV3PEKgpgRmvejfXsCAVf
         efz4QINpmlkcdoYSJ8makGfvmR0o2E4DEdiGp7hKy4R5/g2gqEoFxAICtTe2wEoVjgmV
         LMJjlcubQnpUzXspRxJiT+bqQW75LcXjkOFnG+KuLK81TDJVLrW8O3t/Znp1LOqB3qMA
         lGYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkN6MyVgC8Ni/jmiLQn1b9F0bPddsnWte4Cs0Ph2LWEIZPj19W9
	6Kqw0FSd56ouGikCNlyVenM=
X-Google-Smtp-Source: AA0mqf5cSwqRDvW8gQs4LJW8/fxP5ysADF9/KmM8vUH5wKGNHJ0Yqbgrnz4kNbzEfH0Exkzb89YX3Q==
X-Received: by 2002:a17:906:3e5a:b0:7c1:19e1:50e6 with SMTP id t26-20020a1709063e5a00b007c119e150e6mr7030704eji.585.1670794466501;
        Sun, 11 Dec 2022 13:34:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:ce49:b0:791:9801:e4e4 with SMTP id
 se9-20020a170906ce4900b007919801e4e4ls6792244ejb.3.-pod-prod-gmail; Sun, 11
 Dec 2022 13:34:25 -0800 (PST)
X-Received: by 2002:a17:906:a0cc:b0:7ad:b791:6e37 with SMTP id bh12-20020a170906a0cc00b007adb7916e37mr16444198ejb.35.1670794465414;
        Sun, 11 Dec 2022 13:34:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670794465; cv=none;
        d=google.com; s=arc-20160816;
        b=LP69GyQh71VtKhJZAX/eFb4/4SeLZpKt2VXM9sJgT4stwVzLTYB/mK2sDksDR7UgbA
         O1NQFSWKnM5rZ9LzIzqYa/3sLSv5zA1L7WDrrQOfwP17s27XFcWelv+VZV72b9tRn2bk
         j2AcUlgHsfIFYoaGGRbiJfrF9QBMxCM5vA//J+Oql04Wi0Tb05gg6RTPX/lvQSl0lIE6
         aGiPoxAz1xgbJzVsqpUQgDLnTpaksGou6Uv9zV/XMQ7EC345w7ts+atsK/UHVaz7zGh9
         3z05YNCBAy3WZCKS7VVydnlS0zNrj0vMzOyAWzwRaKHLvq9500rMjmbV7HFSb2iHdUeB
         F9BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:feedback-id:dkim-signature:dkim-signature;
        bh=k3gy3L5U3kYrwCtls0KfuKnkSKMEo9j7w1C7soQ/tgQ=;
        b=StnVwhC8nYil/G09jtcc3U82Q/DZBosYQz+I6oQGFsOH8GykxXCE38gFf0SVGqHH+9
         h791JMYFhDsuHsqwUquLYGNvpNwOqvF+2HgtSRYtsdXBHu383I3GPUHYgsvRtI3c9P/r
         1U5WjCbTpwwUBEZQiQbcW7dtNL/fVuXPzoRttj718EsMHcbNr9nmq4GATncW7h/8aE+R
         lgO0zopzrGG8EZLMo5Uuxtab7qJ4O7ZdK4BZTeVdbP1KGXelHBd0YdyPMOSsrOCu/BqF
         6DkY7lv6wMbHS49gAnKyue/YArwVluFW/CPrvMkFRLr8X7mXUyL2/am9J1S1ZOR2pvpn
         aqAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@invisiblethingslab.com header.s=fm1 header.b=Q3EnF85w;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=ebyAHeuk;
       spf=neutral (google.com: 64.147.123.19 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
Received: from wout3-smtp.messagingengine.com (wout3-smtp.messagingengine.com. [64.147.123.19])
        by gmr-mx.google.com with ESMTPS id mm6-20020a170906cc4600b007c16d82962dsi90392ejb.0.2022.12.11.13.34.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Dec 2022 13:34:25 -0800 (PST)
Received-SPF: neutral (google.com: 64.147.123.19 is neither permitted nor denied by best guess record for domain of demi@invisiblethingslab.com) client-ip=64.147.123.19;
Received: from compute2.internal (compute2.nyi.internal [10.202.2.46])
	by mailout.west.internal (Postfix) with ESMTP id 0E78F32002B6;
	Sun, 11 Dec 2022 16:34:22 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute2.internal (MEProxy); Sun, 11 Dec 2022 16:34:23 -0500
X-ME-Sender: <xms:3kyWY1gJRSVBRCqCglQ6hilZn_kLVb1X5EwuGg__VT40dzcx0QSnxA>
    <xme:3kyWY6Am4BlmrU2VCY4sVfVvtuosxmx5aXNcNJkmMwMkdFj04QPBX2sbdqubMSnxh
    cqxtsaIwRRg-dI>
X-ME-Received: <xmr:3kyWY1GKBLoXlgobB0ziiHHTwrJHAeOXH1sQnAqlcmntvRTG8Yts9qBLS5lD>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrvdeigdduhedvucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvfevuffkfhggtggjsehttdertddttddvnecuhfhrohhmpeffvghmihcu
    ofgrrhhivgcuqfgsvghnohhurhcuoeguvghmihesihhnvhhishhisghlvghthhhinhhgsh
    hlrggsrdgtohhmqeenucggtffrrghtthgvrhhnpeegjeelleetfedufefgteetjeeghffg
    iedugeekffehfeekteeivddtteejffeuhfenucffohhmrghinhepghhithhhuhgsrdgtoh
    hmnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepuggv
    mhhisehinhhvihhsihgslhgvthhhihhnghhslhgrsgdrtghomh
X-ME-Proxy: <xmx:3kyWY6QWw021EUSdCqg6qZz9zSAGdSU_T_dV6XfX0efRNyGZ_vjTCA>
    <xmx:3kyWYyzA27Vom5Tk_-_A7JPv5FMJ3DAmhlZeGelSNuVORhomDmpjjw>
    <xmx:3kyWYw73rq4ly9VYAwiMdcBJkWBlNwzgMAJeSvi0jgdU1ElqWtVzig>
    <xmx:3kyWY2_wrXxY3i_YGrZ2K8YJEA-Q-Av1-cLMUZOiveaBBzdu89AEMw>
Feedback-ID: iac594737:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sun,
 11 Dec 2022 16:34:21 -0500 (EST)
Date: Sun, 11 Dec 2022 16:34:20 -0500
From: Demi Marie Obenour <demi@invisiblethingslab.com>
To: Juergen Gross <jgross@suse.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	"xen-devel@lists.xenproject.org" <xen-devel@lists.xenproject.org>,
	Marek =?utf-8?Q?Marczykowski-G=C3=B3recki?= <marmarek@invisiblethingslab.com>
Subject: Re: kfence_protect_page() writing L1TF vulnerable PTE
Message-ID: <Y5ZM3HCnTcLvP2vy@itl-email>
References: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; x-action=pgp-signed
In-Reply-To: <c18bc798-f484-ad66-fbb0-15192a74f8e3@suse.com>
X-Original-Sender: demi@invisiblethingslab.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@invisiblethingslab.com header.s=fm1 header.b=Q3EnF85w;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=ebyAHeuk;
       spf=neutral (google.com: 64.147.123.19 is neither permitted nor denied
 by best guess record for domain of demi@invisiblethingslab.com) smtp.mailfrom=demi@invisiblethingslab.com
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

-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

On Sun, Dec 11, 2022 at 01:15:06PM +0100, Juergen Gross wrote:
> During tests with QubesOS a problem was found which seemed to be related
> to kfence_protect_page() writing a L1TF vulnerable page table entry [1].
> 
> Looking into the function I'm seeing:
> 
> 	set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> 
> I don't think this can be correct, as keeping the PFN unmodified and
> just removing the _PAGE_PRESENT bit is wrong regarding L1TF.
> 
> There should be at least the highest PFN bit set in order to be L1TF
> safe.
> 
> 
> Juergen
> 
> [1]: https://github.com/QubesOS/qubes-issues/issues/7935

Does that mean that Linux with kfence enabled is vulnerable to L1TF?  Or
are these pages ones that are not in any userspace page tables?  If the
former, then this is a security vulnerability in Linux and must be
fixed.  If the latter, then the two options I can think of are to revert
whatever change caused kfence to produce L1TF-vulnerable PTEs, or to
disable kfence when running paravirtualized under Xen.
- -- 
Sincerely,
Demi Marie Obenour (she/her/hers)
Invisible Things Lab
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEdodNnxM2uiJZBxxxsoi1X/+cIsEFAmOWTNwACgkQsoi1X/+c
IsHgTA/9HGyx+vlFqwhx7sRHVbF3ZpBdZUY7WEDI6cZzIRx8Kvh2QT3ZfYXW/32t
9EUELEKDKqXMsjWozdFcs6leohZBbYozV/luoQUrm1AsavffwrxH+d84FnZFg2qh
VVh+Sd8NL15EZV9nXIqqS94uopqWKL79qmxVcSBVkfujtiI57uGFdshePGMP3I1D
RGPRB5my7A/JQFhuITiZcqbhj0h4Cm5QSQaARAOEr4XQuso+4SFPZVGSw/+vD1nG
XQ4YAvnFKy3+6oabroJ37cway7cimp6/qlEqS3YE1SaMa6q37mgsyGFobpQWbNy5
p4OkEuqlZ85p/C7g4XR+EvIJhfFovh0Wfj4fM0h78VvB8h2aHL2ckhi5vx0Snb8L
p5NLh8MFI0PDoUaUWFb4Y3tN/Ksne9MbTQSy03mnXdnT+/6LQEHFVgUC90K0N52D
R46brLZEfPsTVB+Ro3uynpbXaE7mw/IdzdAXgxRPcMQIiuRmUthWO4O9HC9DCoPz
IHgqZg8+oBn2DCqUomg8Fz/9DQzWKb24dPKyzNuOmbtL63Tk63Qy1Smxu829LtCv
5mkfNPXwT2A3PbdngNrIT9QgI7ziXwUxYBDJ7onlb8Ad6dsimQ6QHOOWilg8mY7E
jvNVYkqFD98wLeR4FuWdrA+20/0o1i2ab6afOFvyzN4lItC6mKU=
=lz1X
-----END PGP SIGNATURE-----

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y5ZM3HCnTcLvP2vy%40itl-email.
