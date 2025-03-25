Return-Path: <kasan-dev+bncBC5YVHMF2MHRBUUJRC7QMGQEWG5MJJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 79EBEA6E7EA
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 02:20:20 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-476a8aff693sf108833561cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 18:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742865619; cv=pass;
        d=google.com; s=arc-20240605;
        b=kokpdkP8Dvszb3c/vHkKUpSIPgW/A+OZcDjlEXvvWXTOsAdNZE1wr2rKTe+z0Y8v1L
         BGfv9nWQBrmmkM23qWYaMXzEFAHAAUjhj0Nr8PMPboPQ3ae9NumxURRutO1v+zplo6X/
         NmuIX3ErtbrMJtex+V31ir82hdiJpc9imQ46Qtee2YrpnwKjGd+q9eHsNHKYV/WqbJK+
         4pnIYLPFt/8BDi5nVyITO99yFVlVLUVx+MiiSkC465tJOHYMXgpbYDeYDtDFOwuxG1vC
         dXE6r+2B1hCqxRkhsJL1iVx+BF/jaIx10N+hhXOVFFdlgZgZrh/YGf5Am1iQZhQFqTMt
         V8Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=f55T7Tiw36/u0OyPV31kWx6bvSmegD7xskLsHLFQuwk=;
        fh=hC7qbHSbvHarT4ed5msPjZa5K+zzSEWfAOZm8222/CU=;
        b=bL0IkY/vFY+MJuDQgEQALNlP4SvlS0RKWODWScIn/ECvp1boJBuKOOrQWtF92i3ylm
         6SiAGDgFmloR8KLoJEjbhJg9RPlI0ai9qhgMvgKNnjZgPM/IKS5GpiBTt7zrVJKIiVL2
         nNilVG++JTBnvSgwsRGnA5cfxvJM7C2JOaRINNuRAYJ+HpAt6H7ZIxfcNZmgOw+PfSUT
         yZD1if9vh2kJNsdGojWAvoUb1i0Uvib3Atc7U6ZwTmK6wwzKxcH7BoTlci3MD2o/GYRq
         ekFwXgzdQ83EklhaebXk7jMNZCYODCmp7wT350h+2etSkLhJJq8+cuhARpWVwRaaUF2a
         gQUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OqEbfgB8;
       spf=pass (google.com: domain of infooffice3445@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=infooffice3445@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742865619; x=1743470419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f55T7Tiw36/u0OyPV31kWx6bvSmegD7xskLsHLFQuwk=;
        b=UzMqiXVqGeZk8ph/a6LN0X/NxD7K/omHNDkthz49MPpZrnRNEzJix+SXFQx0IE8s5M
         FGHSHt9IIKGXoDXs/pDSA5Y/aQmYQojbSBRBKHMTe45i6w4g3unj/Asxbx43JiXZQQMX
         qEEEKe3cmAZg5toY4KKZO9eKHgB4SKbuapsYNk3C094FBZH6ckvVCM8OUgJxkgEnwKot
         NNG1KN93ICkJNMy1XsYCZIA0Hp9oWkQtvnXBuJ314OfDZpDBe2X7BkMmZxihlUG8Ttw+
         W2oUERto9nnZBq0iqFJy7bcGqRYmOgmTod8xjn3+43JTQg82I6r3iKTh0uIRoO28n29u
         sydg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742865619; x=1743470419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=f55T7Tiw36/u0OyPV31kWx6bvSmegD7xskLsHLFQuwk=;
        b=WKWOgS1p1s5RaBemtxbQRyc0Q+mJwkKIV1iXUQzLvRjUuEAJvgfh2xWFnNI7+C4z3+
         lQoM2e2ejUgFOJUgRD/5B5mbJKHNSAO3PAUXTFO5H2JFlTbdQI7BWZ7kdJbfbG6GqULZ
         geBLgoM3hZ78DY5hYTGqKm0AIW5nCqxqo8ZRrfXgqrAnZbwRKSqZ07qwIfqcKEvE32mA
         eQWdulrc06koJJZwWsNjPDNjnKeCtjsGU8EBFLKHL/5j8fUPIrqM+bBEqmn0qzPDxXnd
         H4nDx84JjNFrDAEnyuNG8hSFl+TKDFsrU9sLbZBDhIx957j/10H6Og0Ll3du6+F4BkWb
         JuEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742865619; x=1743470419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f55T7Tiw36/u0OyPV31kWx6bvSmegD7xskLsHLFQuwk=;
        b=Z2ZVLh6H1DyXIXOkN/JxAm7l34h/lv/ERfPQDuzX44XSLl21lQELD/NeWJ42xmOCNR
         d4cG5sM8YINRmwgD2+nXOQJvs8gGBXYRY3V9VYPkuNNJ+vTYZlwtmAqUlmIfAWYsqFSd
         M4UKyYKYA+RgTZoMm/tZeUuUfUDij5Z6UrzCFZqH/rKKIgwsSSEITQF18kL8kaKRfKXe
         G5cqh+jEW910XTBElJpGjNe5yATOHFfmSf32+GH9r7GJGQ8nLCXO7obv2V92NxwaHu3/
         3RjRWzm/obCR52GyGnRE4ZnV1jjLJkcKlouEECEcF6l1hb/sYjeqt3cdXyM52EGLJhO0
         VVLg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUddVPDV64azmK99dHd+bise5Y+cErHr7W0o0nLGtCnEEu4EnRV33l09UZqZnsZvelz6My+sg==@lfdr.de
X-Gm-Message-State: AOJu0YwlP7rZUQjty25SZ7opooADTM+vDez7sJsnMjQ/B2gK2f1qEqLk
	/xH4AqrHR7fs51Ygde44Lc5yEObQ3ZZi9akWL5I08SjrC2iBw3Zn
X-Google-Smtp-Source: AGHT+IEGgrBwfutZgX1AxMHqprGJgVA7aYIPNh7tN69aCJAmcc8XleOaWQHB2mxcuzuiUduKEBswWg==
X-Received: by 2002:a05:622a:17c8:b0:476:8412:9275 with SMTP id d75a77b69052e-4771ddeda62mr215967471cf.35.1742865619025;
        Mon, 24 Mar 2025 18:20:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK+Hyefl3U5FARTRjXu4wqlPcHZr0sFAC0YQNerG9DPAg==
Received: by 2002:a05:622a:8026:b0:476:69c5:ff0b with SMTP id
 d75a77b69052e-4771c3e376dls45669901cf.1.-pod-prod-09-us; Mon, 24 Mar 2025
 18:20:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHLSPpMfaPlhRVj/GiX5+9D45VFYKv2eFIym2Ww+EqwtJg4s80lQDTov6xUPZ6zP/RlK7oJ094HFk=@googlegroups.com
X-Received: by 2002:a05:622a:2b0b:b0:476:84c0:4864 with SMTP id d75a77b69052e-4771dd94df1mr279880631cf.31.1742865618092;
        Mon, 24 Mar 2025 18:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742865618; cv=none;
        d=google.com; s=arc-20240605;
        b=jKIvFiquvXduljirn3iQSIePpGFKFa5MUbw7EHbq7+RGLi7KDRoJqZMnAc7ZUMNX/w
         DTzamuzlIrSOD+NdDqwUTJ15BhtRf3MrXe1Vvlb+NhyVJj7Ms5mAV397Zy3gMZ4wjUyl
         g0pBzpVMgBD8nx1x3up/57kUrcAbi1VjAdmN2UJAfZbWwzgG7wOGYXLXRjPigVWmIKVq
         1F81wZD8V6isC0OrG4dgxktSnGoL8e4Qt6iJavEKgSiyhvp8aSM1Wb1XgaQChcvw85sa
         6KwUsW6okFt1WjXZjQts/wDBMftKqK5FwJxL4T5Yv9mT3h7t4y17j2ebpLe9xuRNX6Rf
         U6xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=UG+z3GvaUA5+ZHFra3+2KicHEkDx2CQhGDQ4bvUXZBM=;
        fh=TF1l3HR/SKPvFRZuriOvafwhkByPHt2gm3+HriiBJ/g=;
        b=bODC94pI9DMPr4QgO8eZp6xLUnEEo59FCLVbamxtHd/gY2WoPHzdyjmqLeCUOt0A4L
         rFuRWErhkJjrrZ7bbTgl0FUbQyrIh8v96MMraCL2Hf5VqmvbeV+VLKC00SF9r34PuChw
         XupAn7L6GTJK0/iSeF1hmPdcHcUdrNtxkJlcft7tpJQqr3gxI9csFSFzOM4Z+nW8NXmU
         a9Tw3Vq5DIMtbhmx6JhTSDRET8OA0m78sx3I1KRGCipMQJ/sDf6asYNNajcXE1jxh3my
         HOOCmQ+9akInJSmbX9iYt0YzisvvSCwbhOqkzcxGGg6OvgfFUc6Nm/+JFVfPUH5r1Z4t
         T7QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OqEbfgB8;
       spf=pass (google.com: domain of infooffice3445@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=infooffice3445@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4771d10a3fbsi3844571cf.2.2025.03.24.18.20.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Mar 2025 18:20:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of infooffice3445@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id 3f1490d57ef6-e46ebe19489so3793893276.2
        for <kasan-dev@googlegroups.com>; Mon, 24 Mar 2025 18:20:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnT+eQrLzDpI4793j+SYtTlOgKKir/S/bk4ULpO0XvSum+N4JkAtQv5yGQq7rd/JOP8XZgXbGmjGk=@googlegroups.com
X-Gm-Gg: ASbGncvWf6/vtXN2G7iPOidn0FKvwNzuJnVcLHjgpwIZhTkCV76qjml7xlVWPqcTUwm
	zIZfSWjYVxdOBxBaSkU90XulANL5+Vd8hZyxH7ilNdsfWAFOgksBM1l6YjKiZWOAY/s9zDlaxnU
	A0DthnSDYgw1qJBXQrhcWxX6klXgM=
X-Received: by 2002:a05:6902:2709:b0:e63:6f6a:ab03 with SMTP id
 3f1490d57ef6-e66a4dbd62cmr19039723276.22.1742865617449; Mon, 24 Mar 2025
 18:20:17 -0700 (PDT)
MIME-Version: 1.0
From: Robert Mosa <infooffice3445@gmail.com>
Date: Mon, 24 Mar 2025 18:20:07 -0700
X-Gm-Features: AQ5f1JqVpJVjj_s1REXj-dtc9UxqpsIxdcuLemX7W-kyjitPapcRlgUchMOtvj8
Message-ID: <CAJNr-U1wQ=BDwbxPvNYawjo+RoQyuo+ntzq7oT5pN0K63h_7rA@mail.gmail.com>
Subject: Greetings dear reply as soon as possible
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000004fb5b0631208690"
X-Original-Sender: infooffice3445@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OqEbfgB8;       spf=pass
 (google.com: domain of infooffice3445@gmail.com designates
 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=infooffice3445@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--00000000000004fb5b0631208690
Content-Type: text/plain; charset="UTF-8"

Greetings dear reply as soon as possible

I am Sgt, Daniella Powell,



Hundreds of millions in cash and  gold were found in Hezbollah bunkers in
Lebanon by our military rescue mission and moved to a safe courier service
shipping company through the help of the United Nations coordinator  .





Please keep this information for yourself only, I will like to use your
detailed information to move the trunk box of  gold and cash money out from
the courier service shipping company to your own home / office address in
your country for investment.



I am mapping out 30% of the total money  and gold for your help, another 5%
for any expense  may  incur in transferring the trunk box to your country.







Thanks,

Sgt, Daniella Powell.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAJNr-U1wQ%3DBDwbxPvNYawjo%2BRoQyuo%2Bntzq7oT5pN0K63h_7rA%40mail.gmail.com.

--00000000000004fb5b0631208690
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">
<div id=3D"gmail-:1ah" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":3mf" aria-expanded=3D"false">
<div id=3D"gmail-:19h" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":3hs" aria-expanded=3D"false">
<div id=3D"gmail-:1ao" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":3dh" aria-expanded=3D"false">
<div id=3D"gmail-:1a7" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":38h" aria-expanded=3D"false">
<div id=3D"gmail-:1as" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":33u" aria-expanded=3D"false">
<div id=3D"gmail-:1a6" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":2z5" aria-expanded=3D"false">
<div id=3D"gmail-:1at" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":2ui" aria-expanded=3D"false">
<div id=3D"gmail-:1a5" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":2pv" aria-expanded=3D"false">
<div id=3D"gmail-:2jb" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":2ll" aria-expanded=3D"false">
<div id=3D"gmail-:19u" class=3D"gmail-Am gmail-aiL gmail-Al editable gmail-=
LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Message Body" role=3D"textbox=
" aria-multiline=3D"true" style=3D"direction:ltr;min-height:280px" tabindex=
=3D"1" aria-controls=3D":2jx" aria-expanded=3D"false">
<div><p class=3D"MsoNormal">Greetings dear reply as soon as possible<u></u>=
<u></u></p>
</div>
<div>
<p class=3D"MsoNormal">I am Sgt, Daniella Powell,=C2=A0<u></u><u></u></p>
</div>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<div>
<p class=3D"MsoNormal">Hundreds of millions in cash and=C2=A0 gold were fou=
nd=20
in Hezbollah bunkers in Lebanon by our military rescue mission and moved
 to a safe courier service shipping company through the help of the=20
United Nations coordinator=C2=A0 .<u></u><u></u></p>
</div>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<div>
<p class=3D"MsoNormal">Please keep this information for yourself only, I=20
will like to use your detailed information to move the trunk box of=C2=A0=
=20
gold and cash money out from the courier service shipping company to=20
your own home / office address in your country for
 investment.<u></u><u></u></p>
</div>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<div>
<p class=3D"MsoNormal">I am mapping out 30% of the total money=C2=A0 and go=
ld=20
for your help, another 5% for any expense=C2=A0 may=C2=A0 incur in transfer=
ring=20
the trunk box to your country.<u></u><u></u></p>
</div>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
<div>
<p class=3D"MsoNormal"><u></u>=C2=A0<u></u></p>
</div>
<div>
<p class=3D"MsoNormal">Thanks,<u></u><u></u></p>
</div>
<div>
<p class=3D"MsoNormal">Sgt, Daniella Powell.</p></div>

</div>

</div>

</div>

</div>

</div>

</div>

</div>

</div>

</div>

</div>

</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAJNr-U1wQ%3DBDwbxPvNYawjo%2BRoQyuo%2Bntzq7oT5pN0K63h_7rA%40mail.=
gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com=
/d/msgid/kasan-dev/CAJNr-U1wQ%3DBDwbxPvNYawjo%2BRoQyuo%2Bntzq7oT5pN0K63h_7r=
A%40mail.gmail.com</a>.<br />

--00000000000004fb5b0631208690--
