Return-Path: <kasan-dev+bncBDPIR7NTZMERBYNOVCSAMGQEZOLKHVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 10DD273087A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 21:39:15 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3f41a04a297sf5665105e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 12:39:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686771554; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xibvxuv4Up2TURiKwJTqDSq2USZ04QpB/2HAnteFTHNM//9+ZqUypF+ZGPRgpdgWbz
         REazhHTMBNjsMfZcyJL2uecwR1Em/UC2WhtbiknK2IF6JwioDB14TOodsJCoNxGBm+Kx
         h1lpt+/KSzwPYqHWRq+8MrbLf6qeL84nPlzVqVXOa/RHd1ZpyABWKiykQiSSVS3TEcV8
         YXiZUGwaByLkY/KmIWwCZx+S6mg+yCAJ369j/Img97bIAmRe9COe+k2XyJH4tZdwHYaH
         cav5K5/9uKUj47L1bZyUywQk5miS3VG9VEvTjdvKm5y8u+Q/h6z8AT/oDCXIjDYglUmj
         Vu0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=NZWQsNeU+KY7p1CiADJxobG/BHtRucBaAHpQ+hUw8oU=;
        b=yRJ0gFwm2cgXp5RDD+S31t+UZ94944kjfCGE9l2ZaI/3HMrw446KmKUtJHK2MYATbX
         aObjl9MLmfMMB1d0aORfMW7KuyVgj3VlP0YW7GO3M2TQVQNZ3dIQ2VqLSjEIrAdb1/M6
         OKopmZ3l77O+IfbzupjA04G2wAfETqDXDXAa6EwUpzKgB4wJQ3FRXZNfnQdzJtqYByY3
         20jxc+yg/WztZWs7lCWC+zAZu042LsS+IIbdkljCc7nD8+udqweGWmvFtwJM+YJWf1vR
         V/tyvBo4aNjsSz/Z+0MHlDxwhV2vXqY/D2fW0YJ552pBfj7ZY9en+t/mufkQeVotyOAa
         V67A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Akyo6Cm3;
       spf=pass (google.com: domain of albertoffice6@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=albertoffice6@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686771554; x=1689363554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NZWQsNeU+KY7p1CiADJxobG/BHtRucBaAHpQ+hUw8oU=;
        b=G34DCr6TmlOU7DyRPoDd8gGsWyQPcZy0FZq/yneA2rCY5UtqaedvT61WQc8h6jc7rj
         zAYYEXSFwBYRbRiTSmcDn51C6mUBWJd+xJdLxnYJRMkmvj2rGzzqmvIzdikM7MWEjFT9
         qkDsjXJt6XuU4ZjUcmL4poX8Bu8gj58Q9yZnkNiTsdj4KZmqYZnNAYfda6ry6M6tTw7C
         2q/G9U7ST1keEaMeTsG3g+69WI6TzdkDHjaLa81p9auJeQiuIHbjzqmSx0C2fr6Fram3
         Trny5Yo9ec87mxRP8hjaMcBCEVWoJQtufASUd6rvmK/YdO8OhcSlfoM0tsi41Z7j8cNN
         gt6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1686771554; x=1689363554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=NZWQsNeU+KY7p1CiADJxobG/BHtRucBaAHpQ+hUw8oU=;
        b=QlshDs35AN/1UyS7G8/uY2Lbo+H9GHC/wit4wB3PQoIAJwuJe0HiKpqiei6tjkxiOV
         sLqB3PC8DD6lv0SbI1F3Dbr8j8mwUZTXBO+c8KEisG2l3ERjup9RV1mvT+6v7kFHdZkn
         EnWnKm0hMmniMcMQn1t1YE+i23JBg5lB3nxx6SKkGUngxqgQ8Q8Y+fuACyQhpFlBWC90
         GXk3ApTFXNTjgVUy8vd24AWAb2KRkGG8YNJvmT0CFDgSDbOimck6cNuOeT1D21O5wOBO
         CpdwphcJVhFmmMSRQN834t0pQOL3muAp3++MZjgOlBpaa2QJY3PngtRf4IEmg5myLQ+q
         iPoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686771554; x=1689363554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NZWQsNeU+KY7p1CiADJxobG/BHtRucBaAHpQ+hUw8oU=;
        b=RP2SEjlxY2cMaLn7XyPQ4ZH6fR2TsIiEH7XtID/Kd8QR270BZ7f0AXmBIvTZq02U9a
         8qPmoWqvx85MkfGNUmldb7HPCiMtG7ZE5PpAj3KeA3NO01w/3pXHKXfDAHSR0kMMoRFq
         1FeleKc0/Wa2XM3guxeKonNBzOFRj2mUESFrQRF8uFuRKyjvN+DxVsywWu1L7s19bo+M
         7bQHcvChJcpA4eoArsFHfggFe+paLUsvSsUeCwPGROV8ii7GDgRwf4lKl1GtXtMzMxpc
         lUcRt3mu3MXjxMfe3wG1H01/LDjCmAYkxrFeLKEDAPhkTjpIK3JT5As++9eV4WxOrnRW
         w54A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwKBzsX5iFMTKzorhutRLD5JN30GdqpnsIyts7vaASSF1MSJhBS
	7kHYZNjhfY2RvgZM+wkTsis=
X-Google-Smtp-Source: ACHHUZ5t3q8mQHZhj5vl4xrKNPlXQSZOE4M5glNQzrpcLEjm2C27dMhA9yazMzldv/a+mrqcgEQ9Mw==
X-Received: by 2002:a05:600c:2212:b0:3f4:23b9:eed2 with SMTP id z18-20020a05600c221200b003f423b9eed2mr12642442wml.38.1686771554185;
        Wed, 14 Jun 2023 12:39:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ac6:b0:3f7:ecbb:40f9 with SMTP id
 d6-20020a05600c3ac600b003f7ecbb40f9ls237807wms.0.-pod-prod-03-eu; Wed, 14 Jun
 2023 12:39:12 -0700 (PDT)
X-Received: by 2002:adf:f8cf:0:b0:30f:ca87:8e09 with SMTP id f15-20020adff8cf000000b0030fca878e09mr4752660wrq.30.1686771552243;
        Wed, 14 Jun 2023 12:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686771552; cv=none;
        d=google.com; s=arc-20160816;
        b=YUsWIeTs2Z6RJROavdtXt/j8x3pGV6CvbO8Je5x5lzQrAbFQ5ZQIRzcTzBhducwnXS
         OsqPyETqxQrhOJKaMtjsYm3WWbMMUoe9F215Pu2jf+pxXOpqZ1uu9fDSALZsveommJ4t
         bk2k2OFAD8yCAIWAV5W8Fw8//sX5AKMUf2dYcANBk1UaGxR4Fk379gw7LxLs/bGAtfwo
         ZEtITtnymyeIrhX3Q2BOJb5QrcaKf+ItlWruGETf7i+nvhurpykwtXqGeXNinsGx5IN7
         Uc6uRDZn6vlmOS0KY7fEYgdEkRuFsqKD/KjWxB3EzLq/FvoFBuO8giI3mCHXW3AJbcMp
         /BaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=Gue3uzYAyV0cc5wDJm1ECI10d6nKS8znNsrG0tfj1JU=;
        b=SJHCPEzW3937Vp1ppZOCYYm5ZvXE2KiEOkdxNJ3LJyGS1WThq+hRem7nbzx4CxYEKu
         MQzyMeE0L98MiMLoKqNY0oG5kMFYWxDYAIvwqB5vn0GSbsBjh+oB8BuMS5gL/UPGQ20q
         Yd+Qeoaee5tQoRRWHpqwBrCD2wNmn7iQvg68hHSgphIic98ejQR9InhyVmdaLsTPnBB5
         9Vvraaww5OsRZNxrc8Y+pM1/8//rCfGzXW+w1xbIy8z9mkXh+o1EaFvd2yWmbivs2dr9
         xqP8qRm3oh1Lw5JiteWxTuCt5g4rlBgKc9fnnf61OELzD1l+Rm7mkdd3B1xeXs/yAJj0
         4tVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Akyo6Cm3;
       spf=pass (google.com: domain of albertoffice6@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=albertoffice6@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id n13-20020a056000170d00b0030fbd4303a5si567041wrc.7.2023.06.14.12.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jun 2023 12:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of albertoffice6@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-3f8d0d684f3so10147205e9.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Jun 2023 12:39:12 -0700 (PDT)
X-Received: by 2002:a7b:ce19:0:b0:3f4:a09f:1877 with SMTP id
 m25-20020a7bce19000000b003f4a09f1877mr11033493wmc.23.1686771551649; Wed, 14
 Jun 2023 12:39:11 -0700 (PDT)
MIME-Version: 1.0
Reply-To: mrjamessalifou@gmail.com
From: "Mr. James Salifou" <mrjamessalifou@gmail.com>
Date: Wed, 14 Jun 2023 21:39:00 +0200
Message-ID: <CALPx2PTBZ=7nmdSEEaeMajJQxc0ga1XRK-4u3pGbZZ9g7dp79Q@mail.gmail.com>
Subject: Your ATM Card
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000002745f505fe1c1b09"
X-Original-Sender: mrjamessalifou@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=Akyo6Cm3;       spf=pass
 (google.com: domain of albertoffice6@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=albertoffice6@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000002745f505fe1c1b09
Content-Type: text/plain; charset="UTF-8"

Your ATM Card

I am the new director for operations in charge now.I came across an
envelope containing an ATM card which was kept here for your
collection.

I hope you are aware of this fund ATM card which was donated to you. I
Will need your urgent attention and cooperation for the fast delivery
of your ATM card (mrjamessalifou@gmail.com)

Mr. James Salifou

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALPx2PTBZ%3D7nmdSEEaeMajJQxc0ga1XRK-4u3pGbZZ9g7dp79Q%40mail.gmail.com.

--0000000000002745f505fe1c1b09
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Your ATM Card<br></div><div dir=3D"ltr" class=3D"gmai=
l_signature" data-smartmail=3D"gmail_signature"><br>I am the new director f=
or operations in charge now.I came across an<br>envelope containing an ATM =
card which was kept here for your<br>collection.<br><br>I hope you are awar=
e of this fund ATM card which was donated to you. I<br>Will need your urgen=
t attention and cooperation for the fast delivery<br>of your ATM card (<a h=
ref=3D"mailto:mrjamessalifou@gmail.com" target=3D"_blank">mrjamessalifou@gm=
ail.com</a>)<br><br>Mr. James Salifou<br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CALPx2PTBZ%3D7nmdSEEaeMajJQxc0ga1XRK-4u3pGbZZ9g7dp79Q%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CALPx2PTBZ%3D7nmdSEEaeMajJQxc0ga1XRK-4u3pGbZZ9g7d=
p79Q%40mail.gmail.com</a>.<br />

--0000000000002745f505fe1c1b09--
