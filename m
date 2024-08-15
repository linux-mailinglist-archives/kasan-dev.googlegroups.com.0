Return-Path: <kasan-dev+bncBDO456PHTELBBWN3662QMGQEEBSPRFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id A96B3952CE6
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 12:52:11 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2700203caa2sf524791fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 03:52:11 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723719130; x=1724323930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3yWrEmblAYagbaSOzh9ZOrV7XjfSvBUHkcAXyn9nNGA=;
        b=dxKjwY3pdvzpHpsx8+FjvsKZHfDHfhMbOOcYaaVSRQ9ZK4oGaqYMHp7EZeYlqpRXYa
         vk4LtY5eRQUxpBSK0nqo3Ix9Zv1m87k6DoPlcxtUIAsIIt7F2meBE/8YXsLMH66pBLCo
         7qM0DWXiUhWi8Tnp4K3cKGRopFpC/bIdKvj2Up6qs3PwCOz9SQ1BNEpbiuTRL5r9EF/o
         E81S0dphxyuNCNxiiaP8rYyn4RY3c8ycEljmys99Jw9jllA2cw1aCDQ24Fxll+C/rLGe
         XyUEA1h2w2xsSJIS3xCrvmjp/mZEaZ4nZwASRboQpvm/gGsMrn9yZ51VdiHrC9AgGWSM
         TVXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723719130; x=1724323930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3yWrEmblAYagbaSOzh9ZOrV7XjfSvBUHkcAXyn9nNGA=;
        b=LUlYNgBxh+JXYS/mYT/dpNFPtNPkKYCmyqEbb5kmHV33dk5T9eVWGJQeuRuNCJIWeI
         jbDHF5HPFEdbG5hRIRUyV9uUuqUIcmFbIwF9y+UJYoAm4xZ2dPVDMtTkvdkmR87R/T1H
         qT2iQA2WBESF791OTS8xR+iJeZnb3b80xfK1nXPnNM+2gYF1ha/A/UWxau141dgHz7VO
         aAhbsyseXP6YVxgK4B3G8vsEn81sPhE/+akpPafnvAXhTyuMcdXNwzbgYyNOGU7l8adk
         GwifdN3HjN5gEruMq0TyVz9XA4tacri4bG53jYKke3BHDUE20Vg+bP4szbimIJC+6xEi
         3Nxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723719130; x=1724323930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3yWrEmblAYagbaSOzh9ZOrV7XjfSvBUHkcAXyn9nNGA=;
        b=mGaxzngDXklJEX1a5pBRUwacbUkz6rwLnkepfs8Ln8VYwLcR/PdYEcv2aL32vJxDSP
         EKcr/FZHoZKfxxlIrjxgdlRiGpiQhrU6ngOKLf+ctUjEpnNuTtgUAiguDqoVhnu2W0Hr
         +orOr5Mjwafp8O1ZGsOuME4toKBLW4D6FEEcZwhVQrsMtEoYwBkyg9YDSm3bioOWRulv
         TXOPsIiQsVy4LLQ8ESPTZt9/iSKAuwlW5wQySJFuRd4uc8K4YzsNzfrS/lknlfJY2ovR
         WwCNSfv7fsGsdwlMeBWWRozg1qnI2omi+WhiSyI4nrN0pax7XoGG/RP0YoQ52CxeVyzO
         YOJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWjEbUoTZZRn1Ij1sZ3ZBBYHZpBNSiqxoX8koL2wHfgzl8EQ7hZwOMez+KBNPcZ4I6mrK2cvmox+G3xZ2zRxy48ixD2D3wcTw==
X-Gm-Message-State: AOJu0YwefiGozK4lGM5Ek/GHlglF6oO9wI/y0GDWA2kpobdM8dfauLJ+
	4Who5Nin4jKeStQ0oEWDLa9es1PWE5ecvy4ykeSg2b/vCs4xkohi
X-Google-Smtp-Source: AGHT+IGLl05TzXUyOcl2ljZgVNpOpy5TbVbJehZhHJpaiRX+BSeR/Kr5cfPTxMYBBv3F0NM9+iucBA==
X-Received: by 2002:a05:6870:63a6:b0:261:52d:1aef with SMTP id 586e51a60fabf-26fe5c74115mr7133428fac.49.1723719130136;
        Thu, 15 Aug 2024 03:52:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7d8b:b0:254:7203:f69f with SMTP id
 586e51a60fabf-26fff5004e1ls997736fac.2.-pod-prod-05-us; Thu, 15 Aug 2024
 03:52:09 -0700 (PDT)
X-Received: by 2002:a05:6870:440b:b0:261:a04:2ab2 with SMTP id 586e51a60fabf-26fe59aab2emr321131fac.1.1723719129069;
        Thu, 15 Aug 2024 03:52:09 -0700 (PDT)
Date: Thu, 15 Aug 2024 03:52:08 -0700 (PDT)
From: hana soodi <hanasoodi668@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <55ad2cbb-8ed8-4513-90a9-ec0cc87007a9n@googlegroups.com>
In-Reply-To: <b74a7f29-31cd-4fc6-bae7-50e52a8ff83bn@googlegroups.com>
References: <b74a7f29-31cd-4fc6-bae7-50e52a8ff83bn@googlegroups.com>
Subject: =?UTF-8?B?UmU6INin2LnZhNin2YZ8INis2YjYs9iq2YrZhiDYqNix2LPYqiDYs9in?=
 =?UTF-8?B?2YrYqtmI2KrZitmDINmE2YTZgtix2K0=?=
 =?UTF-8?B?2Kkg2YjYp9mE2KfYrNmH2KfYtiDYp9mE?=
 =?UTF-8?B?2YXZhtiy2YTZiiAwMDk3MTU1MzAzMTg0NiDYp9mE2YXZhQ==?=
 =?UTF-8?B?2YTZg9ipINin2YTYs9i52YjYr9mK2Kkg?=
 =?UTF-8?B?2KfZhNix2YrYp9i2IC0tINis2K/YqQ==?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_33234_1704034604.1723719128409"
X-Original-Sender: hanasoodi668@gmail.com
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

------=_Part_33234_1704034604.1723719128409
Content-Type: multipart/alternative; 
	boundary="----=_Part_33235_1921853077.1723719128409"

------=_Part_33235_1921853077.1723719128409
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://linktr.ee/cytotic_d_nur =D9=89

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/55ad2cbb-8ed8-4513-90a9-ec0cc87007a9n%40googlegroups.com.

------=_Part_33235_1921853077.1723719128409
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

https://linktr.ee/cytotic_d_nur =D9=89<br /><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/55ad2cbb-8ed8-4513-90a9-ec0cc87007a9n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/55ad2cbb-8ed8-4513-90a9-ec0cc87007a9n%40googlegroups.com</a>.<b=
r />

------=_Part_33235_1921853077.1723719128409--

------=_Part_33234_1704034604.1723719128409--
