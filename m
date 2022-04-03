Return-Path: <kasan-dev+bncBCQ3JSGYUIMRBFESU6JAMGQEFBHWIGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C41994F0B35
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Apr 2022 18:19:34 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id q13-20020a638c4d000000b003821725ad66sf4430730pgn.23
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Apr 2022 09:19:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649002773; cv=pass;
        d=google.com; s=arc-20160816;
        b=FgHdJPq3a8BRb53VoQc8WgSuGYACOuBRlnPJEJTFYFsFkMwdpR8zIy8ePo7VKBE5wR
         0meA1KCcWNoYoNpHNhqGFQnDRGeFisISqVWapgi5khe0guhWyywJGa6tYO7wei6G2G7v
         b512CIye5Bqsqbj4LgGTGYwse30Dxgpb/SskCCbA41J/X6KuktAjiD5QSX1ZbeLiNyck
         IvXtY4isUOoGur9+3IFPw9C2ABgA2j3ZTZt66LIcpV/snheo5gx9qVbEXdafg2MMX/DK
         5F7e7j0Pb0YyxaKQMObsFELH/Bhbu46CSc1vpBMC2BdX4qz96zNbD9M64VrF3HqiONAP
         NShw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=S/kbCCl4hgEAOcMtSjy6UCBpsNYy7taZNhK6rbvYGuI=;
        b=iilw7Old7B0LsKbjc29OD9OVgVUEvM8EVhbPtIOF5bSqmu5FsMY8IV6Ki+EGZw+wgx
         uMNgJIZWj0GbzA51KTUVLGTjhVVlw0Tqpq5eqwzuAz9wgp5LSOZ/Xcxsmxlx09RqZqA+
         pAkFOcNYhoIHJmPX063Kocc2++Kc+2wCwPHQC22z3AN9tURV+1nlDJVl+KYVHxf/sbP/
         vehFFtkQOYZAFK57/d6NPXzXtp+xpsXfiD24V3sIU10HwxDrk50oiZdptsQM/l7eNCeF
         +QxFReg9ZvlM0GopkSkqwvGh/Pf3g947vyT9caKS9LwBjtxy+HD6Tl5noWPxoc2Ss0SE
         rU7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HxYI6fQX;
       spf=pass (google.com: domain of chanchigozie@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=chanchigozie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S/kbCCl4hgEAOcMtSjy6UCBpsNYy7taZNhK6rbvYGuI=;
        b=fMwHUC/f65tQaucvgD+JwaubMgB1AC7VH0DQhl14H5HwuHCTOsi7lXQm5DdI06qouz
         2fxIAzziCCC8fKGCOzbg9KMK/jrKkGbTUNEXRQfdeHLGdRkrgTt/xwd8f11kglvE4nY7
         MqTM6SoFsrgC3jQ1GXjm5emylW6g2F+QBOVFxhJ9QQqiNJKU8Ppq5zUr8S4TFwJ6JLPF
         xy9OlxUDNsORJtbNBqYaWYwV0gsgMoc+1tVf0qacbPopc9iJ4h8OcADz4h5nWu5CJmiv
         YXwNU4irqbt2EJxbp6qCY7yHsQT+G+7BpT2mm/Qd6mp5QourfR8jnvC7OYRa1T6xwpbY
         zWog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S/kbCCl4hgEAOcMtSjy6UCBpsNYy7taZNhK6rbvYGuI=;
        b=Xh6cZntJYGOKjRE3IPPIXYAp9z8WH6KLzrg5Z+Gb027BHu07d5EwpnQfEfi6puuvjz
         9Cn3IlHjDM7AmcuxysIkRBntVtNb+wRqUajuuOaFO1/UpkViDSc6Jy05li9XtEsD1KpU
         lMCl2HYxcwrfNtwK+YGPMdTHfLLSrt4/iSBu04YA/Hj4ZXDBqGaBVGk3FWCfc6cTkM6h
         I24Kp0ByTJzn+FLehyJV4QFMgNa7pOq835ebZhR6z947Pw2hbPsx7EjUcI0D3i5AF0E9
         3ZUcDd8dLYVtMWK/qOn3FmnX04Rp2cIPsFv6kX93ttuuqEEPyI3aKEv4Wdj0bIiCC0BH
         ps/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S/kbCCl4hgEAOcMtSjy6UCBpsNYy7taZNhK6rbvYGuI=;
        b=Z6XnDWwGmZ4tkdRxEJPyxh0h6vsjvANVL1Z2ci1SGIUIAyHNm6MDyML8HKTypCU5aF
         /Ji4uFUHirX5dJDyzFiEk6fXRVDznn/AM52xl/jwCkOpwDNTd0WzKgG0lbyZutZVWs1D
         SmxHxkXJUD5jC7CchZAynM0UMzPP0Fdn0KH6iA9KC3Ii1iNIQ0QozkuPak/NWtdr6ym8
         v4zjhS296ilPAwqKcwvuAs+XrhOfCd+RnED9txtI5NlKd9zUh6xcbEzbbJyG4EqUQsBB
         YX7ZpPUfX/pCsiCD18Lkjc2So+rayWBbz1vxXCR4k0Kr7rdYidWhCUhP3vDvUs8H5yBZ
         v86A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315k5c/piGG8pbIWSNcDyPjneREYZtV7mzY9UZNuFUmbwxeKlyg
	kOEoLZVsaID3qQ6jiTcqmR4=
X-Google-Smtp-Source: ABdhPJx2hKuirT0fY1gcJiqChDD1xdrzpqz5zYHHAd+nhY1heVel5qyZkBD8rVWfdKRiappS6yCQmQ==
X-Received: by 2002:a05:6a00:140b:b0:4e1:2cbd:30ba with SMTP id l11-20020a056a00140b00b004e12cbd30bamr20246818pfu.46.1649002773107;
        Sun, 03 Apr 2022 09:19:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c4f:b0:1c6:8749:f769 with SMTP id
 u15-20020a17090a0c4f00b001c68749f769ls6405220pje.3.gmail; Sun, 03 Apr 2022
 09:19:32 -0700 (PDT)
X-Received: by 2002:a17:902:b582:b0:14c:a63d:3df6 with SMTP id a2-20020a170902b58200b0014ca63d3df6mr19814218pls.51.1649002772234;
        Sun, 03 Apr 2022 09:19:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649002772; cv=none;
        d=google.com; s=arc-20160816;
        b=F+lwHdu3gOBcnupktE8Yjj7uL59vjcu0RN6FppiGWFK5g0onuxCx07gQQ58b9j6caH
         YLC+c1AzaNKvClZbkavABPux36URsTl7DkX0BvKoSkZdZ8LyVh5L2oZ6+OjjLWVZLuXH
         USUVU/xm0wASdm8ILegw8jTjfZNL56jTP+zkIUANyGnGZnMBWE1r2m7A8aoBgMDxrn3o
         NSKUVOmzzh0TWSe5stz0i3rbSwN+CKFuNsPWdp0xRu+FNT+kYjvlBCc9B+AuAULDEWqp
         m6OriJD02n0g5PuzhAXjzYpCTTVZyohpQXmWNYD/I2EQJbIIeqf069Bm2btFSwCEggbX
         CGrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=AGGku2n7Te/e5UQsqcdae5hFW7OCzCsFek3sfx4fM5U=;
        b=S18jyXUjGKWJMSgGw7Xpu7eAtv6e/0GSt9fjCFY0r7KL2xgv7eETBWaV1GhAelzW+Q
         2vogvEk58vzZSYHCBh/gmMs4JdhsJ1SF8C+O33oDpOxQxXghGoAM+gFziRs0NtoHBw84
         K5hesTFLAx0j6ofEmCs+WjKk2M9uG5vjZbvRq7uyWV6zQ/aF/DpkFFA9xMBrN4m+rJz9
         P58Wt9FFp98MY23/P6j1hKkUiU6XbiyWMYXii7FGK5Q7wNpi5IRqFgtYOFmppcKeG+3l
         KOMnZmdoIgeb9BZutnneyJ+FGPWDR13m71BUx7JGdzsNsDFMkG8CU9Wi/sHjxaja4KDH
         V1hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HxYI6fQX;
       spf=pass (google.com: domain of chanchigozie@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=chanchigozie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id g6-20020a17090a714600b001c9af9201d7si1077457pjs.1.2022.04.03.09.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Apr 2022 09:19:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of chanchigozie@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-2eafabbc80aso76241477b3.11
        for <kasan-dev@googlegroups.com>; Sun, 03 Apr 2022 09:19:32 -0700 (PDT)
X-Received: by 2002:a81:3686:0:b0:2eb:2146:8c13 with SMTP id
 d128-20020a813686000000b002eb21468c13mr11663990ywa.507.1649002771311; Sun, 03
 Apr 2022 09:19:31 -0700 (PDT)
MIME-Version: 1.0
From: Mrs Aisha Al-Qaddafi <mrsaishaalqaddafi967@gmail.com>
Date: Sun, 3 Apr 2022 09:18:05 -0700
Message-ID: <CALTLBYU9iP4-sZeJwiJo4WA8ZmHdVW72OO+1_HCCRkbX9FSyLA@mail.gmail.com>
Subject: please Dear i need your urgent reply
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000006af22405dbc2601b"
X-Original-Sender: mrsaishaalqaddafi967@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=HxYI6fQX;       spf=pass
 (google.com: domain of chanchigozie@gmail.com designates 2607:f8b0:4864:20::1131
 as permitted sender) smtp.mailfrom=chanchigozie@gmail.com;       dmarc=pass
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

--0000000000006af22405dbc2601b
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

please Dear i need your urgent reply

Please bear with me. I am writing this letter to you with tears and sorrow
from my heart.

I am Aisha Muammar Gaddafi, the only daughter of the embattled president of
Libya, Hon. Muammar Gaddafi. I know my mail might come

to you as a surprise because you don=E2=80=99t know me, but due to the unso=
licited
nature of my situation here in Refugee camp Ouagadougou

Burkina Faso i decided to contact you for help. I have passed through pains
and sorrowful moments since the death of my father. At the

same time, my family is the target of Western nations led by Nato who want
to destroy my father at all costs. Our investments and bank

accounts in several countries are their targets to freeze.

My Father of blessed memory deposited the sum of $27.5M (Twenty Seven
Million Five Hundred Thousand Dollars) in a Bank at Burkina

Faso which he used my name as the next of kin. I have been commissioned by
the (BOA) bank to present an interested foreign

investor/partner who can stand as my trustee and receive the fund in his
account for a possible investment in his country due to my

refugee status here in Burkina Faso.

I am in search of an honest and reliable person who will help me and stand
as my trustee so that I will present him to the Bank for the

transfer of the fund to his bank account overseas. I have chosen to contact
you after my prayers and I believe that you will not betray my

trust but rather take me as your own sister or daughter. If this
transaction interests you, you don't have to disclose it to anybody because

of what is going on with my entire family, if the United nation happens to
know this account, they will freeze it as they freeze others, so

please keep this transaction only to yourself until we finalize it.

Sorry for my pictures. I will enclose it in my next mail and more about me
when I hear from you okay.

Yours Sincerely
Best Regard,
Aisha Gaddafi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CALTLBYU9iP4-sZeJwiJo4WA8ZmHdVW72OO%2B1_HCCRkbX9FSyLA%40mail.gmai=
l.com.

--0000000000006af22405dbc2601b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">please Dear i need your urgent reply<br><br>Please bear wi=
th me. I am writing this letter to you with tears and sorrow from my heart.=
<br><br>I am Aisha Muammar Gaddafi, the only daughter of the embattled pres=
ident of Libya, Hon. Muammar Gaddafi. I know my mail might come <br><br>to =
you as a surprise because you don=E2=80=99t know me, but due to the unsolic=
ited nature of my situation here in Refugee camp Ouagadougou <br><br>Burkin=
a Faso i decided to contact you for help. I have passed through pains and s=
orrowful moments since the death of my father. At the <br><br>same time, my=
 family is the target of Western nations led by Nato who want to destroy my=
 father at all costs. Our investments and bank <br><br>accounts in several =
countries are their targets to freeze.<br><br>My Father of blessed memory d=
eposited the sum of $27.5M (Twenty Seven Million Five Hundred Thousand Doll=
ars) in a Bank at Burkina <br><br>Faso which he used my name as the next of=
 kin. I have been commissioned by the (BOA) bank to present an interested f=
oreign <br><br>investor/partner who can stand as my trustee and receive the=
 fund in his account for a possible investment in his country due to my <br=
><br>refugee status here in Burkina Faso.<br><br>I am in search of an hones=
t and reliable person who will help me and stand as my trustee so that I wi=
ll present him to the Bank for the <br><br>transfer of the fund to his bank=
 account overseas. I have chosen to contact you after my prayers and I beli=
eve that you will not betray my <br><br>trust but rather take me as your ow=
n sister or daughter. If this transaction interests you, you don&#39;t have=
 to disclose it to anybody because <br><br>of what is going on with my enti=
re family, if the United nation happens to know this account, they will fre=
eze it as they freeze others, so <br><br>please keep this transaction only =
to yourself until we finalize it.<br><br>Sorry for my pictures. I will encl=
ose it in my next mail and more about me when I hear from you okay.<br><br>=
Yours Sincerely<br>Best Regard,<br>Aisha Gaddafi</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CALTLBYU9iP4-sZeJwiJo4WA8ZmHdVW72OO%2B1_HCCRkbX9FSyLA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CALTLBYU9iP4-sZeJwiJo4WA8ZmHdVW72OO%2B1_HCCRkbX9F=
SyLA%40mail.gmail.com</a>.<br />

--0000000000006af22405dbc2601b--
