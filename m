Return-Path: <kasan-dev+bncBCS4V27AVMBBBOMK7OTQMGQEXADU5RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E6F7179A4DF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 09:43:54 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-4fe55c417fcsf4240576e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 00:43:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694418234; cv=pass;
        d=google.com; s=arc-20160816;
        b=bCSl0vqY3PZBpEvblIDCP3WCuvwAqT7Lc45RffJJSCHsf15twxrcYCfis/vZxW2YRJ
         A5okJz9je8JrYUUOKIf1VW+IwgQyv4zvxGeMWxG4+0OKruQtV4sAMKN97Gsf/6T08dQ0
         Cw+D3o6kq03AoQsIbHHSG3QgPHLalU0Yg9Nawu7jw+LiUwjaQeBQYtkZeW8g+elofN7L
         scGpxwAlM5noJSEc+6mDrJlk1yEVq+oeAhEPNOTXJ8JLVD2a1baPmvLKl2Ai9Imr5Wxk
         7Ll1xdjuvTOWvhSMgQs6HQ+sH/R/DYuZUolMuklTtc3vOCsSYPNYT7IVvG9ZG1o77v5n
         k4HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:thread-index:thread-topic
         :content-transfer-encoding:mime-version:subject:references
         :in-reply-to:message-id:cc:to:from:date:sender:dkim-signature;
        bh=kM2usxt+qSWoYA9l3VntYza7+Ldtz0DaRiJo/uTI07Y=;
        fh=6f+STlsjv072Nmmh+G7gpJ+wtI9hO4tmPSx56v+9T/I=;
        b=A20Bdg5FUAclNY/K4s/C2uoCfQ8IywwJHEhtATJQyuMrHIL5J89hASln2yFnTYLo+i
         uUBq114zIUhTlABvnEM1LMrfvWC0aKeO/IqeezOoiKCYyuoD9c7KMxcRDTt3tuNOwEmp
         3Dw6X87z4LcPNRPZi6+aoKXYYVQku5OLT0jfomWf/PGqVYeGPYbDOMk2E9PTS3GeifnP
         DHx8+KovBj7ICK2Z1QY8hRb/zLOAk3k7U1jBuiKFf3DndF2byCikvMXQZjfwCHhomLe5
         iVe0M0ajTjjsyvA7sZI/83jFrOvGA7utf1WG3PIxDqI00YYsmYQwAQ6EU29X+ua+Fm3/
         b7Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694418234; x=1695023034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:thread-index:thread-topic
         :content-transfer-encoding:mime-version:subject:references
         :in-reply-to:message-id:cc:to:from:date:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kM2usxt+qSWoYA9l3VntYza7+Ldtz0DaRiJo/uTI07Y=;
        b=Bb/+Noxb/6hrOGljFNgfTTIwa+WUaZ46oZ8tSfCcooJyRENba6HCVufNokKl/KS/H/
         Ba7d6FGAPrdWrdYHpwWMBdrHj1NN4FCnB3lpBl5mPzZvspbToW24mh8yr86KQn8PQrs9
         C1fL5rm0+ykZSZsxak5osHuAwbt/hV7WeXlf59vsoGrFUMR3MmD47aiqDikjMNs6013w
         86xBTp5yMRcrKv4Uxdvg4MxqO8nIHJilfsQIciPx0sg7msE1bMmpFtzhrWgedgBMJnB6
         d0FmmM9QBoc6kIZqUNkj/NF4IWvZQXCW97BxJyvlUme8PboIX0CXXzlH2WGirCVIZUXz
         epww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694418234; x=1695023034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:thread-index
         :thread-topic:content-transfer-encoding:mime-version:subject
         :references:in-reply-to:message-id:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kM2usxt+qSWoYA9l3VntYza7+Ldtz0DaRiJo/uTI07Y=;
        b=V9ZYzxy3o32j1yasKmvquI8eFMgRHjktoRnCw9WxnuY1Yoqd8JfZdvjqTBEi2gcGrd
         5S1Kpr9VPr1e29Aqsz1u0J7kahkNvyPik7Yl9/Y0XuLTXe7CGsFqvOyxDLmyj1CExzZT
         4vmqYwFWXN4qRkGz/gU02n14Bu3UCV+a4lcpTvAf+dUQHe0/lmcMpVXBCl+e9qI8zUPJ
         EzaHvpbX/ZkQBW8HGiY/9Xa0xFxVomdxtURRw4u5JAN+ykUEoWhSSj6ldX4HBKEB+j4Q
         CDdnce+pMutvdGChsE/c1rbDAmAewCD/0fcxAHNKolOc6QCh8bCf3sj/uVEnXS8ScmY4
         H4Vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwFy20H25/LJVGr3PeT3GH45wWRtUW+Mw4CKBOdfxccSqgs9Ao/
	xYyAainfY8ghDTkcIJ2meWA=
X-Google-Smtp-Source: AGHT+IEys/zVCClVvvLlXU0tkLdmGlQCoGYE9JVjapBGsXDCIwVjg4BcBGw5gGuvEZQmPD0tkjtG/A==
X-Received: by 2002:a05:6512:2344:b0:500:bb99:69a9 with SMTP id p4-20020a056512234400b00500bb9969a9mr9091762lfu.64.1694418233621;
        Mon, 11 Sep 2023 00:43:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2d48:0:b0:4f9:5662:5ef9 with SMTP id t8-20020a192d48000000b004f956625ef9ls1502824lft.0.-pod-prod-02-eu;
 Mon, 11 Sep 2023 00:43:51 -0700 (PDT)
X-Received: by 2002:a05:6512:789:b0:500:882b:e55a with SMTP id x9-20020a056512078900b00500882be55amr6539875lfr.45.1694418231816;
        Mon, 11 Sep 2023 00:43:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694418231; cv=none;
        d=google.com; s=arc-20160816;
        b=j1TEkf1DA6QisCB8TbzPkfHL/bB61HPh+ybRuKBA9DiKY5QcfLZ5M6IJJILO1RkOws
         luK9yMv2seMU60aZrweDCAr+bJF1lsQveOOJWpxTcZqc2tB3BjTefz/lpNlctoYXF3Br
         enKFFpNyFnsA4oM8d+v4+K2SksU4OFmUPgKMtu1HL0wMh4PQEKdpZu5bi7ILAipBOTTW
         zE5zn7FQ0Wy2Oi3NOcM0xrwNSGOWGRHtRgvRuumFcU7XbaP6TmgpFj7QrfDq0gJ5LbPC
         95PT5IqT8vz9s4m93euNk5QIzn8GM2Lf8kfxZLEO/9nqccPM4+L3MVMDo1/vn+Bm2lHG
         Hnew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=thread-index:thread-topic:content-transfer-encoding:mime-version
         :subject:references:in-reply-to:message-id:cc:to:from:date;
        bh=sJC9GADLZrNWjdcQFUBdOdKDTwFdTraerNcmf1gdqvU=;
        fh=6f+STlsjv072Nmmh+G7gpJ+wtI9hO4tmPSx56v+9T/I=;
        b=jwYHLeP8wreDAyi4J+79C/IEaZV5gNFm4KbQ2kB9MsZ8/oXN2k5UhahoxmcFsMfdLG
         8SoLD8pyzp8tmAhLeMh+rI3LuyMCL2PYaUSNYaB7Jqz+2qRR2TWMst2yJCygnMSIimoM
         v4IB+YGypmocX0mjqdtK9LpXIG0BLbryp9VwzifPdVyZ8/VZmArGZH5QryNDrtz6lpkd
         nGl/etKhClqwcrnPklVfRRoZE17Is/aXUOWPf70x6MDGMlfztciOS5LXerq1/vNgD1p4
         sCc6XOnFK580WrNSjhEJI1EeZpJYZDbotLszKzWt7xE3yFl/b2sjPcPfYHMhTQvw73PP
         U35A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
Received: from lithops.sigma-star.at (lithops.sigma-star.at. [195.201.40.130])
        by gmr-mx.google.com with ESMTPS id o15-20020ac24e8f000000b004ffa23b6e2asi485421lfr.5.2023.09.11.00.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Sep 2023 00:43:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) client-ip=195.201.40.130;
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 62534635DB5B;
	Mon, 11 Sep 2023 09:43:48 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10032)
	with ESMTP id Zt4T-9st26DK; Mon, 11 Sep 2023 09:43:48 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 08DD16234896;
	Mon, 11 Sep 2023 09:43:48 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id Bc_dpGCLszHV; Mon, 11 Sep 2023 09:43:47 +0200 (CEST)
Received: from lithops.sigma-star.at (lithops.sigma-star.at [195.201.40.130])
	by lithops.sigma-star.at (Postfix) with ESMTP id D05ED635DB5B;
	Mon, 11 Sep 2023 09:43:47 +0200 (CEST)
Date: Mon, 11 Sep 2023 09:43:47 +0200 (CEST)
From: Richard Weinberger <richard@nod.at>
To: Vincent Whitchurch <Vincent.Whitchurch@axis.com>
Cc: davidgow <davidgow@google.com>, x86 <x86@kernel.org>, 
	dave hansen <dave.hansen@linux.intel.com>, kernel <kernel@axis.com>, 
	rafael j wysocki <rafael.j.wysocki@intel.com>, 
	linux-kernel <linux-kernel@vger.kernel.org>, 
	Johannes Berg <johannes@sipsolutions.net>, mingo <mingo@redhat.com>, 
	linux-um <linux-um@lists.infradead.org>, tglx <tglx@linutronix.de>, 
	andreyknvl@gmail.com, anton ivanov <anton.ivanov@cambridgegreys.com>, 
	Dmitry Vyukov <dvyukov@google.com>, hpa <hpa@zytor.com>, 
	Peter Zijlstra <peterz@infradead.org>, 
	ryabinin a a <ryabinin.a.a@gmail.com>, frederic@kernel.org, 
	bp <bp@alien8.de>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Message-ID: <1681710160.12996.1694418227692.JavaMail.zimbra@nod.at>
In-Reply-To: <f11475f922994b88f5adb14d23240716e16d5303.camel@axis.com>
References: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com> <CABVgOS=X1=NC9ad+WV4spFFh4MBHLodhcyQ=Ks=6-FpXrbRTdA@mail.gmail.com> <f11475f922994b88f5adb14d23240716e16d5303.camel@axis.com>
Subject: Re: [PATCH] x86: Fix build of UML with KASAN
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [195.201.40.130]
X-Mailer: Zimbra 8.8.12_GA_3807 (ZimbraWebClient - FF97 (Linux)/8.8.12_GA_3809)
Thread-Topic: x86: Fix build of UML with KASAN
Thread-Index: AQHZmsQx3HM02RYVik+aPUiiZcEw2q+Dtz2AgJIVpwAaWaDaFg==
X-Original-Sender: richard@nod.at
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted
 sender) smtp.mailfrom=richard@nod.at
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

----- Urspr=C3=BCngliche Mail -----
> Von: "Vincent Whitchurch" <Vincent.Whitchurch@axis.com>
>> Thanks: I stumbled into this the other day and ran out of time to debug =
it.
>>=20
>> I've tested that it works here.
>>=20
>> Tested-by: David Gow <davidgow@google.com>
>=20
> Thanks.  Perhaps someone could pick this up?  It's been a few months,
> and the build problem is still present on v6.6-rc1.

I'll happily carry it though the UML tree if we get an ACK from x86 maintai=
ners.

Thanks,
//richard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1681710160.12996.1694418227692.JavaMail.zimbra%40nod.at.
