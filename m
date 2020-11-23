Return-Path: <kasan-dev+bncBCQ4LP43XAMRBQ7S576QKGQECJRWYZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 67F392C12CE
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 19:02:48 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id u37sf24303385ybi.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 10:02:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606154567; cv=pass;
        d=google.com; s=arc-20160816;
        b=RA8E+Duv+ao/UYDZslwb9GrrYVEKz2pl4ewvr7qTn21VpZ7dvUuE80Nm/a2pzSA0cU
         bLecVnldwnlc6iNBgikqOIT1e2J7JVZMHadh55+E5qDz3yZkWMeptO6Q1N8bu9yM1TJ7
         fQmwpjfho/ScsAXW/xpkfpXdCryHJ66uAqtByE4TC7p5dFqMOXbm60CbC0Yqw2tpZwbU
         BLR6pVCzy4LaYcrxMYZj55UmbgzpFmM09Z/vYBlUuWnRiEJQIv6Mgz17rVOzhJAx27nX
         yQ/pfBeVitiw9biqfLFTKW04rg+LRcL7kIK0gXIaO1kPlO7d47RwdJsRrpYU4IuwVwoI
         JbTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:subject:reply-to:from:to:date:sender
         :dkim-signature;
        bh=DK4lBi+7wWul+Rn0Athdrb5V9RVKy/+QYVkv45nuqps=;
        b=HccZOaNlnsTj3bONbdlk+lu4K6QBO7x6LvpP4vWBBBbhEP2904MsdC5jueF52BZ03b
         g3YifbsevE7yrIrfUuREgQ06eWwCZdn4CR4kaYQpd1aagrwqhk4dAEDA8bZyVevoVvgi
         TjCw3raN5SkXfC7/XHHv0GMHxMTbCrVYNARM3HJYEcJ/4VOTVfgqKCvTWPTDnc9DW6NS
         lDgywauRo8BMgBUkoLQIOjEe3yw50RC0C/+u88Djrp8bdvEgd3K1bWKmzfpsnBumn82N
         Ob/UWNu5eHoEwXF3QgVTyxSgZzACht0/kLKl0bVgZQvjiIFnh7/z0NTiL+Ycaq6tvxX1
         QDhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@noelleneff.com header.s=default header.b=euiHqX3h;
       spf=pass (google.com: domain of noelle@noelleneff.com designates 192.185.145.4 as permitted sender) smtp.mailfrom=noelle@noelleneff.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:to:from:reply-to:subject:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DK4lBi+7wWul+Rn0Athdrb5V9RVKy/+QYVkv45nuqps=;
        b=Oy2mnZUCm6nvrxnee4RhHMizuXuGwEo54pV/QFqnknHvVwuC6MnrTHzSnKywg9ADAp
         1CoTg7DSM4s5128BGE+hkYSzJ1X3qsd4KbRCpGosYN9d82mFAsmAr4wGIcNOTU+LY3Ak
         Om+ExrEfvHtgT/wL4y3/TwPAwhTjOc/nbNsyhA+T340IPGZfZ74q+v0mnzBwUos5bKYK
         /t+oui37ENoa/hQ2G21c4gQDgWN09ci5PCl4MtQqsslCL/KAX7BdbbquD6oA9tHYYCxt
         klvE0U9zWQjjOT1VJ2L06I5o9BMbGr5Oe8ZieWDEBwaPJoMFfad2zuben4LyFR+wHWBv
         XgHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:to:from:reply-to:subject:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DK4lBi+7wWul+Rn0Athdrb5V9RVKy/+QYVkv45nuqps=;
        b=t7HYY4zstw+G0cDbwIkJP1xfhsRPAW8RcM/wbpiOPKj8oPwY3bhmGdpEsolnvmTF9M
         sjR2uXL2vpNA3HUqYpAeXIwhXqdptffGvwYSI3oqXlq9grRfwJaXyBmo0Lehwyuaa+VO
         oEtvhW+wwNg48AGSwM99+qV+52Zzd4woDi7wLimYkxq8W72Uw40M4yNR34q2dhA5WJUj
         BvClT2yGn36q9GoKkUN4KsBqNL85uIueXKj0ll5j1q8U/sNDThH2rSv4MkW/vAZJEzyt
         FJFBMKu4HY1wGs/4pMrB86UnOigTbqhR3DSVgjMf923xncCJ9BpyfC20XThSutHFakRJ
         68Xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313QStiNBsW2PFIulAhM57lPgTc2yr+Ym8Np4JX4G0J9KQWt4pU
	DeQi8CUP5oGY+qUIRw9HxX0=
X-Google-Smtp-Source: ABdhPJzh9xll6ZaYXUvRUq6NF9fWmbNCzDohYQX6tEJJlG4S2Q2zAMXssY4dscimIHkxcurQnfZClg==
X-Received: by 2002:a25:b804:: with SMTP id v4mr1154324ybj.371.1606154563691;
        Mon, 23 Nov 2020 10:02:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c553:: with SMTP id v80ls371961ybe.2.gmail; Mon, 23 Nov
 2020 10:02:43 -0800 (PST)
X-Received: by 2002:a25:340c:: with SMTP id b12mr665519yba.417.1606154563007;
        Mon, 23 Nov 2020 10:02:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606154563; cv=none;
        d=google.com; s=arc-20160816;
        b=H3SNPQPY67CJeaEm1j6AmolMFXbLTxP2Kor5wozKnwT93W6sl2aX+ShSICWVduXH1b
         J9Cdr5VzhefKkZqwe/aEfvhVB/7xYkNaRoUp0hANdUkYpg2fp9zcxqtYMToQxP5bAmiQ
         wBQfe4grAwN2OS6B0aFeSyu/JTRinLXedhEnT9WM00gOrvdoArVKCVwKKO13qaKsy95g
         9zltTag9HCK4rS9kNcU1oR3TAYFjIt4IwwZb0PBcwqNJd2a4YVTmeeUGQ9/A50kYbA7G
         jwQFoC49e4myl8Z0juPG55YPefVEhTAj4SRx1CdlNZYwuMg6I93pYFkoox0bs8H6oOoQ
         hZGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:reply-to
         :from:to:date:dkim-signature;
        bh=FnlqGmd9phkHslJSh4yTKFWcM1QD0TL2MG9ViM5xwuI=;
        b=XimmcF2ZJp2Rjbp5zY6dXRxH9yAXkFr7J1KmGEFw7KfTy5TUfGTKY+rRBS763vJtcm
         3cpF8Zu+J10ILPSByE9YBQROjFYEJxm7lT3t4njSYnno8C5j2jAx8PWapOxWSissSJET
         S/5u++epVnpgjZt5cKe7sTSNt7AUvAIrj3/WrVildpxabUywikB5cxPpIIdhFGzp/dPv
         K87bNAIP2SQl94hyjdHHZLM3eNT3lSO/2Jc0nLbZ60msNs1pQ7oBOGK0gDJV8djxO3kN
         J+4/pOxwk+yMEnaRc+FcI3y5XnCds8nIYqRW1wigNR4G8yZHx50yDwuaJBSolFsHlTmf
         lkWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@noelleneff.com header.s=default header.b=euiHqX3h;
       spf=pass (google.com: domain of noelle@noelleneff.com designates 192.185.145.4 as permitted sender) smtp.mailfrom=noelle@noelleneff.com
Received: from gateway33.websitewelcome.com (gateway33.websitewelcome.com. [192.185.145.4])
        by gmr-mx.google.com with ESMTPS id y4si969566ybr.2.2020.11.23.10.02.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 10:02:42 -0800 (PST)
Received-SPF: pass (google.com: domain of noelle@noelleneff.com designates 192.185.145.4 as permitted sender) client-ip=192.185.145.4;
Received: from cm12.websitewelcome.com (cm12.websitewelcome.com [100.42.49.8])
	by gateway33.websitewelcome.com (Postfix) with ESMTP id 28169F276B
	for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:01:40 -0600 (CST)
Received: from gator4102.hostgator.com ([192.185.4.114])
	by cmsmtp with SMTP
	id hG9jkN19YiQiZhG9kk1fo8; Mon, 23 Nov 2020 12:01:40 -0600
X-Authority-Reason: nr=8
Received: from ec2-52-71-138-247.compute-1.amazonaws.com ([52.71.138.247]:40896 helo=noelleneff.com)
	by gator4102.hostgator.com with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <noelle@noelleneff.com>)
	id 1khG9j-001pn4-KA
	for kasan-dev@googlegroups.com; Mon, 23 Nov 2020 12:01:39 -0600
Date: Mon, 23 Nov 2020 18:01:39 +0000
To: kasan-dev@googlegroups.com
From: Noelle Neff <noelle@noelleneff.com>
Reply-To: Noelle Neff <noelle@noelleneff.com>
Subject: Bad ideas for googleprojectzero.blogspot.com?
Message-ID: <56471653.or_mail@noelleneff.com>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="b1_hqfJPSpyI0ppnXRuInh7JUXnJE4OhDUrzY2aH6Sws"
Content-Transfer-Encoding: 8bit
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - gator4102.hostgator.com
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - noelleneff.com
X-BWhitelist: no
X-Source-IP: 52.71.138.247
X-Source-L: No
X-Exim-ID: 1khG9j-001pn4-KA
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Source-Sender: ec2-52-71-138-247.compute-1.amazonaws.com (noelleneff.com) [52.71.138.247]:40896
X-Source-Auth: noelle@noelleneff.com
X-Email-Count: 1
X-Source-Cap: YnJpYW5zcGVpZXI7YnJpYW5zcGVpZXI7Z2F0b3I0MTAyLmhvc3RnYXRvci5jb20=
X-Local-Domain: yes
X-Original-Sender: noelle@noelleneff.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@noelleneff.com header.s=default header.b=euiHqX3h;       spf=pass
 (google.com: domain of noelle@noelleneff.com designates 192.185.145.4 as
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

--b1_hqfJPSpyI0ppnXRuInh7JUXnJE4OhDUrzY2aH6Sws
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello=C2=A0there!
Happy Monday!
I sent over some ideas about Apple's iPhone 12.
Did you NOT like any of my suggestions? I'll paste them again below. I don'=
t want to pester if you thought my ideas were bad.
Thank you,

		=09
						Noelle=C2=A0Neff

						Freelance Journalist
						& Photographer=C2=A0www.noelleneff.com
					=09
					=09
				=09
		=C2=A0
	=09
        On Tue, Nov 17, 2020 at 6:20 PM, Noelle Neff <noelle@noelleneff.com=
> wrote:
       =20
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
kasan-dev/56471653.or_mail%40noelleneff.com.

--b1_hqfJPSpyI0ppnXRuInh7JUXnJE4OhDUrzY2aH6Sws
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello=C2=A0there!<br /><br />
Happy Monday!<br /><br />
I sent over some ideas about Apple's iPhone 12.<br /><br />
Did you NOT like any of my suggestions? I'll paste them again below. I don'=
t want to pester if you thought my ideas were bad.<br /><br />
Thank you,<br /><br />
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
		</tr></tbody></table><br /><br />
        On Tue, Nov 17, 2020 at 6:20 PM, Noelle Neff &lt;noelle@noelleneff.=
com&gt; wrote:
        <blockquote>
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
		</tr></tbody></table>        </blockquote>
       =20

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/56471653.or_mail%40noelleneff.com?utm_medium=3Demail&u=
tm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/56471653.or=
_mail%40noelleneff.com</a>.<br />

--b1_hqfJPSpyI0ppnXRuInh7JUXnJE4OhDUrzY2aH6Sws--

