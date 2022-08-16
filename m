Return-Path: <kasan-dev+bncBDAZZCVNSYPBBHOS52LQMGQEQ66WTBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C250595E51
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:26:38 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id m7-20020adfa3c7000000b002251ddd0e05sf289231wrb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 07:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660659998; cv=pass;
        d=google.com; s=arc-20160816;
        b=vOA2zYI2udJ4JGx8xr+GlgYoYikhlgMkZ7K4IUPzolsjcy94ITOESJdYbjWUeX+bRf
         y5XHhxvU/QGyQbIDCKMTaMZDEVKGMHkx+755nnT/NB0K3PmfoG7qGOJppWVrxi0Ec6r+
         yvBxPkUA/smbJunI5t5ma/WD21+I0KZuv1K87KpzxdSB5UtcqhT+We+KkPKcUeHoji1p
         lOp9ja2PgEWhTD7w/07Lj1/kocuGxHQRTa20QZgyYIU0GeAhkVVxjly+F/zu9vDEJX1o
         LcXv5JnPDL1z0TXbjJnZNQy3loKEcuDJvcUwFeb6gCJ/L2Kxx3cPfTq6o2UVMr9lTsts
         U4gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=AJm4Bah1evb+zPM1TsgIHKXsqpX2qekumNBDjKn7i8I=;
        b=yxHl6/2uOcAfIiJT31GnofTUtWyqa77CslWIFWeSvCfPmDstmmzCnWWugDhJKj90LN
         W+L6iHyv3EncOeqRlxowuYYE7xRCCnX+J18iXr9vIIQeZX/YBSoCFt9A5wcaGl0Swj9N
         DlOZnRqFfI+8DKSn+yqpNmlESpPwVyj7JP1yEOZldmFkwO/fTE3A+ZIL2GZ+dkpgT+dv
         0jlCVW3gkB9AFK6b6xozyW7vd5fN81Esv4EGd3xTSV6meGc2i8pehJJrngfegcEg7GOZ
         Mw+q5EnnHQ9HhAHh2AHcKOmjdQppohRdqdgFWOUmhf8WKo0WOuscwreOVPKZ6YohiB4K
         1B6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T2Sqwl6d;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=AJm4Bah1evb+zPM1TsgIHKXsqpX2qekumNBDjKn7i8I=;
        b=Rt+pC+qvcnvS5nC0tyNnXMkC+j5xnfS5gFngDhe4QDmXas//P7Bg41f488syIR2Zxh
         Jui61EGMYs+XmIbYwd3ryQMYrC26iHo9vai4ngWtt67ZOwfb0qB+5+Va1hHrLH4hhHcT
         P02x44gF9yujQrpeaL0oq6uhl05Z5VyANr48W8bqRFAp1aqc54VrJ79C7QevLzMHdj/n
         f0pp6XLxUjil7WAyNS1eBm+o1K+B84ZdZGJUAURUfZt5qye0Fk8cTMjIjYyDIGPjsp17
         mb04Wlre9Z7e/6+8XsaYCjm2Il1VTyXcyyVJo7key8klbX1yfMupFFXmzb8mrZNKGHN6
         FobA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc;
        bh=AJm4Bah1evb+zPM1TsgIHKXsqpX2qekumNBDjKn7i8I=;
        b=7/mKyegICU7+8q9H6cRee7pi5fzIDb0/O5r1hqaegjFzp8ETVWFYacEAomP9TC5U1Q
         dUSnaj/9WLC49GJ4ebq8P0WKRgGfN5gYNkTeQ86B4WTcZyJ4pTVWCCFeDeLOqTIyNzYX
         pOG0QN/QEyvLbPfkn+YJZ8h4Mnda8IZCOM+37mHGD55betfCeb54XhCS84/Z1mrMR4i6
         5ePb4oqqYk84izd49JOFS/OlZf5QZE0N6pd+W+/X6Ybe6i/TGQupCrOXFceug9pfpcaq
         rzxOQ0OG0LskKyBty7gvmKV3gaBvsSzAo26NI58iADoQcBtThEiDqTIP86CDDvriQTWa
         WB4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo29D/cUuFwnbPPWbKv65uCe+G4ipHIDe/8xjCpGLOSoKpkWWNjK
	OUFT+A1N6c/8uS/qpykGHAo=
X-Google-Smtp-Source: AA6agR577lYJfylhA9nPXCWVCULrf77UFzRlhhBk5Eu7QvLl65lxLb6QyCPGJBlX5iKKZcyxkq5+9Q==
X-Received: by 2002:a05:6000:1682:b0:221:599b:a41e with SMTP id y2-20020a056000168200b00221599ba41emr11688913wrd.522.1660659997759;
        Tue, 16 Aug 2022 07:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c1:b0:220:80cc:8add with SMTP id
 b1-20020a05600003c100b0022080cc8addls19798362wrg.2.-pod-prod-gmail; Tue, 16
 Aug 2022 07:26:36 -0700 (PDT)
X-Received: by 2002:a5d:494d:0:b0:225:1bfc:6820 with SMTP id r13-20020a5d494d000000b002251bfc6820mr1455695wrs.473.1660659996932;
        Tue, 16 Aug 2022 07:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660659996; cv=none;
        d=google.com; s=arc-20160816;
        b=CQzoFx3lEXHZ8QW5lpt+KB92NoNhLa55NJE+OFEQhmdCaxmJA+a4q2GyxEu/7rbnkN
         MOqHy3xb5aiFoLPAm7vr9BJ1rKKn6XFgsskWfuBwMgy/0gN1beC6MrRWIM8IGqpF5pmN
         vGIanPErKHUG5XYeuF5tfkAd2GwrarjynIDY2MdWxK8AKKs9w1etnHRgq94cuIMml4K3
         aBkCB/eN+XgNyZ9NsuBIqOeFB/pAzXWNAop/Rib6Bar5VNXUPPxQ5AWwgd7GFXKdakC5
         eFZtCwaTA0+v41NOkPiLLj07uaRsoUeW0j/rz0+0I2ZBwLxnYbkDCgyRtPLh8FuYjnje
         Q9DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qoDbxzkfxB5yzHZ4aIGuJ//j4H4ZdMk6h0R4+zdowMg=;
        b=nH6fLjQq0RAGgptRGvlLNgfhRp+Y7JiPPond3aHnKTrAcDXmRK2cWoeAQSJiwHHgyF
         r7ebPya0d5tHzL4nibIZefB62QVI4VTCzdCHXbe/2Qcfw09UrjR5IHUur/io2MyeDEop
         lqkGEqxzjbceqCwael7uRggAfSvq/PQNfKx6oPyPqsAqtXQKCYWNgGGCDJ1RZg5jS5iQ
         YbwcBU0g9g0ea3pshPDyTnYOWVT9QiBO0Tboy+EXXwKdlNmWiYz/U68AkWREcwqhU0io
         Nk0aQjM6JRHFBteHa85AAmUWawkPPSDVQBbSiGPHFrPwNeQ0ESb1RV1fJUqeB4J/+SEG
         Ksag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T2Sqwl6d;
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bo11-20020a056000068b00b0022068e0dba1si910686wrb.4.2022.08.16.07.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 07:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 91FBAB81A56;
	Tue, 16 Aug 2022 14:26:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7D472C433D6;
	Tue, 16 Aug 2022 14:26:33 +0000 (UTC)
Date: Tue, 16 Aug 2022 15:26:29 +0100
From: Will Deacon <will@kernel.org>
To: Yee Lee =?utf-8?B?KOadjuW7uuiqvCk=?= <Yee.Lee@mediatek.com>
Cc: Marco Elver <elver@google.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <20220816142628.GA11512@willie-the-truck>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=T2Sqwl6d;       spf=pass
 (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=E8=AA=
=BC) wrote:
> The kfence patch(07313a2b29ed) is based on the prior changes in
> kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earlier in
> v5.19.=20
>=20
> @akpm
> Andrew, sorry that the short fix tag caused confusing. Can we pull out th=
e
> patch(07313a2b29e) in v5.19.x?
>=20
> Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313a2b2=
9ed1079eaa7722624544b97b3ead84b
> Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c24e0=
61196c21d53328d60f4ad0e5a2b3183343

Hmm, so if I'm understanding correctly then:

 - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e061196c=
2)
   but the patches apply cleanly on their own.

 - The kmemleak change landed in the v6.0 merge window, but the kfence fix
   landed in 5.19 (and has a fixes tag)

So it sounds like we can either:

 1. Revert 07313a2b29ed in the stable trees which contain it and then fix
    the original issue some other way.

or,

 2. Backport 0c24e061196c2 everywhere that has 07313a2b29ed. Judging solely
    by the size of the patch, this doesn't look like a great idea.

Is that right?

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220816142628.GA11512%40willie-the-truck.
