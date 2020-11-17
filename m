Return-Path: <kasan-dev+bncBCQ4LP43XAMRB7NI2D6QKGQEBSNMKUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 076C82B6D28
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 19:20:47 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id z9sf301450oop.5
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 10:20:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605637246; cv=pass;
        d=google.com; s=arc-20160816;
        b=uaSmEsNjFmS7I61T/NOf+y/zSSx/XWudoLsppgD0FXs8+nE5WsvsFn6nl1FQszHgiS
         vlDT//m8ochiyTPGbYK/nku8QyBOoNDc6eG4t8PxRVVIT6PXlQbBBTyHEkzCLloYKL4S
         Kg6I5PgTmAWUhUbQZs4wxUluxuQzsxEApV5932jibksYk01z/R8kEOr2a2UvQiFDNKMA
         FxnsOrsU+56JTED67lTNCZ2SGFPAkM3+krQX6fr030Ac75yJ+BVXRNu8Onexn1YE3vH9
         ad+oLusrmgO55DrRRATvTgEnqRXLHggq86Z2fKy0irZRmSyU0oysgvMHyNiUeXVh0JH9
         pMlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:subject:reply-to:from:to:date:sender
         :dkim-signature;
        bh=oneCqZFfw8Gl13AiQuMqZqqIcG3kkPaKL0RCRLQH6S0=;
        b=CokHB3INLvLSGqHOxQ+GlN+gfXVf0CxqAYccuS4dClcgYwTCXXwOsU29R54efZJk/E
         VAm3hV6toqZwKkWzbCz/hAXmvUZEn/6+jUqFlIA3C1YLWn3d8qPE3euodpIWzJW2viL9
         dBb2mKmvRXL0OjuEDDqCD75MEEPCxVxOBbo9tBq0I4nmUL2Kx75kn1WplaGz7nHZOxOi
         +omK3innTXAVj/zfaQ3cJjq/UQBANOarxung1dUItRpG+ZaQYNiFkoW+Qw9E8iRNp28d
         Qlf1I0zU2hqV3iapokNBChD+BMd701m8V/tsKDzGaPyQ8ALnBiGNUuUfRGLrdNS2QnrY
         Qx8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@noelleneff.com header.s=default header.b=RTSIUbOo;
       spf=pass (google.com: domain of noelle@noelleneff.com designates 192.185.51.35 as permitted sender) smtp.mailfrom=noelle@noelleneff.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:to:from:reply-to:subject:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oneCqZFfw8Gl13AiQuMqZqqIcG3kkPaKL0RCRLQH6S0=;
        b=mQnpFMeiYdmiiDs3CKYl+DX3Znt4YbiHHllS6D4mQCuF+NGiW5CquUNASr2rd72HZB
         0K1sX+eTlm+oe7Nl8tUyFAgRpJT3DmUDVGwCKGGgPpixPy8ahg1QOwlOPHqPZ0CtpuMt
         GtAyKIVYXfWZPsSoejaeo+uvQq7WXwd3bm6Q6h7iLBeHapn2wtpGDKaSsgtO3n4vrjly
         rjTPoj+1clETKUciQy4kvSnYdWPdW2YUA7LXUaqmxZedtokcVLfeaEfqYC9qpO8vnabR
         sKPlwM3Gx+tM/28L3CjP09NNJWo+XTfyRVWJrn61RKpoTKJgkg6eADfMoLL6MU+IGtco
         PKHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:to:from:reply-to:subject:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oneCqZFfw8Gl13AiQuMqZqqIcG3kkPaKL0RCRLQH6S0=;
        b=SrIN54TVgAnb8681nR61Ce6muwT8AzZqAhgufyXI9ggFfKn4xS6Wl/emo60U3uMiN8
         7DL/6vbo3Zu9buXRk90myqYT2aFno3mU4jkm55R0IYh1MIxiLkjZkt51BFb9GD2Zxv0e
         MAXh3UYzQMJiQJgoomgfADWif3yJWbJG2qPHOBRLjKwwMou8QjR6St14SefkvvMn7kx8
         m01JnFY5AHJM13fKv/qctV7IkBHYUgEIphcp+3XHeTqd5V1hZuysq+mjkhlakZki85qL
         HpcNSmUH00bv43ROxdtLpFlAkkqp29M/fBOlS+jZ3IMyxPeRjsNGGBA661liMs7vBw/K
         HTJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SIcuvVfjXIrx9oag4n/noMj1O3WJdYciKaIwL0AXdodryEppW
	hOoQK1Jyc/4jguNdcukdmBE=
X-Google-Smtp-Source: ABdhPJzKgeO/+NhIQvy9V+q1D8wT8+xZ6H3MO/+Onx2mErkOh17iMkglGjuB+AK47YA04xOKRFSThA==
X-Received: by 2002:a05:6808:11a:: with SMTP id b26mr266681oie.59.1605637245706;
        Tue, 17 Nov 2020 10:20:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1ca0:: with SMTP id l32ls4393506ota.5.gmail; Tue, 17 Nov
 2020 10:20:45 -0800 (PST)
X-Received: by 2002:a9d:6c99:: with SMTP id c25mr4127274otr.327.1605637245294;
        Tue, 17 Nov 2020 10:20:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605637245; cv=none;
        d=google.com; s=arc-20160816;
        b=c15a8a/uxXpsz15JVLeTOYezvMPj2FUPn0LFwl57xKMc8lrLymKyF/UpwGjmW0eeLp
         v8tuUkB2j5wkbkAXR4VjGGvfvVkZ7RL6FEDvAevE05JAMTgG6BIORYDaPLsKs1OQW3KM
         kavuvjK0lnIbPoMNlbUc0xZgV7gDp3tWch2ftCGqm07i+1ODf/VmpXFc6HQP8bxpHxnf
         2PP1HRZBQJ+qwvh/OZmwC0+d0rHexKviNXBmTRL3/cf5bO1IBFk04eLRsqEyz3IlIidB
         L/AgpLk9ijRblpwQw/1WLnC45V4r6hX2eIHn5Xd4pcOuRnglP6+Ts3HfZyrA9BoiW5Db
         Y1dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:reply-to
         :from:to:date:dkim-signature;
        bh=QRkl0VPnuliCK5LVOW95S0HzK6dnH+e05SwPZnlJkIQ=;
        b=mThj5ZFncNhYl6hm5qUCGgM2fTM66YNHAk0fP0skmd094tlyIEtPawB3GQzGd2w0js
         M7nXl1fu+hXn+Nw8ZseyjbYxl/6OiC46ctCLuo4X95qd73H98OZ4TcrcRjQnMYN1uVCX
         B+I3sk7Aa7W0Yxo7a2+P6u6wgBNTZtGMy250hQgdSvtBm63OOlIiijCgWbV4luWu9kIa
         CP+pR+lGZOSBPgbNtNGvBuBZ9SwpRYB1btHadyySzJ46FR/n6PsRGbU0qGZxVNZ8apjG
         T6/XvlkC+WZWN1iFBWuuQaKvtDilqQRvSOMEdDoZul8vgMkhXu8gfXWMxtKn1K8bwkbO
         faxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@noelleneff.com header.s=default header.b=RTSIUbOo;
       spf=pass (google.com: domain of noelle@noelleneff.com designates 192.185.51.35 as permitted sender) smtp.mailfrom=noelle@noelleneff.com
Received: from gateway24.websitewelcome.com (gateway24.websitewelcome.com. [192.185.51.35])
        by gmr-mx.google.com with ESMTPS id f16si2112665otc.0.2020.11.17.10.20.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Nov 2020 10:20:45 -0800 (PST)
Received-SPF: pass (google.com: domain of noelle@noelleneff.com designates 192.185.51.35 as permitted sender) client-ip=192.185.51.35;
Received: from cm10.websitewelcome.com (cm10.websitewelcome.com [100.42.49.4])
	by gateway24.websitewelcome.com (Postfix) with ESMTP id 0551F56EB
	for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 12:20:36 -0600 (CST)
Received: from gator4102.hostgator.com ([192.185.4.114])
	by cmsmtp with SMTP
	id f5amk8PK9mi4Bf5amk7vyC; Tue, 17 Nov 2020 12:20:36 -0600
X-Authority-Reason: nr=8
Received: from ec2-52-71-138-247.compute-1.amazonaws.com ([52.71.138.247]:37934 helo=noelleneff.com)
	by gator4102.hostgator.com with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <noelle@noelleneff.com>)
	id 1kf5am-001gyV-7A
	for kasan-dev@googlegroups.com; Tue, 17 Nov 2020 12:20:36 -0600
Date: Tue, 17 Nov 2020 18:20:35 +0000
To: kasan-dev@googlegroups.com
From: Noelle Neff <noelle@noelleneff.com>
Reply-To: Noelle Neff <noelle@noelleneff.com>
Subject: iPhone 12 Post?
Message-ID: <56184529.or_mail@noelleneff.com>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="b1_KtF28a0ryeqDWXoGS21h68Abo3ufXDd2CDR0SNMyZ4"
Content-Transfer-Encoding: 8bit
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - gator4102.hostgator.com
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - noelleneff.com
X-BWhitelist: no
X-Source-IP: 52.71.138.247
X-Source-L: No
X-Exim-ID: 1kf5am-001gyV-7A
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Source-Sender: ec2-52-71-138-247.compute-1.amazonaws.com (noelleneff.com) [52.71.138.247]:37934
X-Source-Auth: noelle@noelleneff.com
X-Email-Count: 7
X-Source-Cap: YnJpYW5zcGVpZXI7YnJpYW5zcGVpZXI7Z2F0b3I0MTAyLmhvc3RnYXRvci5jb20=
X-Local-Domain: yes
X-Original-Sender: noelle@noelleneff.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@noelleneff.com header.s=default header.b=RTSIUbOo;       spf=pass
 (google.com: domain of noelle@noelleneff.com designates 192.185.51.35 as
 permitted sender) smtp.mailfrom=noelle@noelleneff.com
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

This is a multi-part message in MIME format.

--b1_KtF28a0ryeqDWXoGS21h68Abo3ufXDd2CDR0SNMyZ4
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi=C2=A0there,
My name is Noelle Neff, and I'm a featured journalist who has work publishe=
d on Chicago Tribune, Tech Acute, Independent Australia, and more.
I'd love to send over an article about the new iPhone 12. Any of these topi=
cs resonate with you?
iPhone 12 vs iPhone 12 Max - Buyers Guide
	Best iPhone 12 for Small Business Owners [with Quotes!]
	7 Best iOS 14 Apps for iPhone 12
	iPhone 12 - Is a Case Required? [Warranty Notes]
	11 New iPhone 12 Features You Might Have Missed

If you think you'd like to publish one of those articles, just let me know =
which one and I'll write it up and send it over for you to review!

		=09
						Noelle=C2=A0Neff

						Freelance Journalist
						& Photographer=C2=A0www.noelleneff.com
					=09
					=09
				=09
		=C2=A0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/56184529.or_mail%40noelleneff.com.

--b1_KtF28a0ryeqDWXoGS21h68Abo3ufXDd2CDR0SNMyZ4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi=C2=A0there,<br /><br />
My name is Noelle Neff, and I'm a featured journalist who has work publishe=
d on Chicago Tribune, Tech Acute, Independent Australia, and more.<br /><br=
 />
I'd love to send over an article about the new iPhone 12. Any of these topi=
cs resonate with you?
<ol><li><strong>iPhone 12 vs iPhone 12 Max - Buyers Guide</strong></li>
	<li><strong>Best iPhone 12 for Small Business Owners [with Quotes!]</stron=
g></li>
	<li><strong>7 Best iOS 14 Apps for iPhone 12</strong></li>
	<li><strong>iPhone 12 - Is a Case Required? [Warranty Notes]</strong></li>
	<li><strong>11 New iPhone 12 Features You Might Have Missed</strong></li>
</ol>
If you think you'd like to publish one of those articles, just let me know =
which one and I'll write it up and send it over for you to review!<br /><br=
 />
<table cellpadding=3D"0" cellspacing=3D"0"><tbody><tr><td>
			<table cellpadding=3D"0" cellspacing=3D"0"><tbody><tr><td>
						<h3><strong>Noelle=C2=A0Neff</strong></h3>

						<p>Freelance Journalist<br />
						& Photographer=C2=A0<br /><br /><a href=3D"https://www.noelleneff.com=
/">www.noelleneff.com</a></p>
						</td>
						<td><img alt=3D"uc?id=3D1A1BNiffC_TZ0fCQHbu58tGMeMj90nh3O" src=3D"htt=
ps://drive.google.com/uc?id=3D1A1BNiffC_TZ0fCQHbu58tGMeMj90nh3O" width=3D"1=
30" /></td>
					</tr></tbody></table></td>
		</tr><tr><td height=3D"30">=C2=A0</td>
		</tr></tbody></table>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/56184529.or_mail%40noelleneff.com?utm_medium=3Demail&u=
tm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/56184529.or=
_mail%40noelleneff.com</a>.<br />

--b1_KtF28a0ryeqDWXoGS21h68Abo3ufXDd2CDR0SNMyZ4--

