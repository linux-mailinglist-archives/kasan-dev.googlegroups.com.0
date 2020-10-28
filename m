Return-Path: <kasan-dev+bncBDD5NCEDWIIBBUPL4T6AKGQEH6ZDGCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E09029CF22
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 10:11:46 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id l17sf2811123iol.17
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 02:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603876305; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kurvz13UMVICq9jpRsjqKhaozo0kCMLKbq0cNbluKq8h0CtNHqqB+OFcrcoH3Ncej6
         FysMV6rtwMUgxWR6ndc3yiOxVfVDtOUbfTuasjtK35YDIYMNZl/TzEo0WXi1O3bsopi7
         DXBW//NV4O5QOuGUBs1Pl/Tv9zxHGNJTeL87Rbp4XIMjNiKhHk5uy3eSBPZIM9RClO80
         sK3QgvQqM1SQKWfpaqiQe0cb4bxyitv2f8gfe8SJDFfQXpMi38TYMdaV08Kpkh8p1AZ+
         xOypbGLjNT0Fc+h43BFWSLp1WGStI9467wUXGLLLmxd7Id+uCi0DJo1XAI22c6N4i7HV
         ZWiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=gc0FhbC5FQ1sz4hxeUGsfAu4gjKuRIAqj7nY+kbPMyA=;
        b=rekiwBvULspVTPhwrrPYPL8+Qn6d/piBFKbk15eIQN5T1aiX5dSBmWsyTl2plzHMkR
         603rqrqbRoZsuuQuUdZ73ZUCbORtHWz5UZpMpLmvOjEvX/valYNf6+C+7H5QyCMhz3cO
         AM2iIFRgsxMAteUo2SbWLbRgt0UVuBpvNQk9yNZZHSstE2InqikPeHYnAKiv9Ihj5626
         ecdpLaquqRg2o8CRlhZNdiPYBCwwn6n5ns4ZfW6tk1/ltp4B31o6LTJs5V0UmSL/uAz0
         Cv7YzzhQ0emFznZnh6yehiQBCC8+Y9072h+IyNse+IYFBjXTSCccoTj/HavwxYY0qeyg
         GKTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Ty/1kASH";
       spf=pass (google.com: domain of marilyncity2@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=marilyncity2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gc0FhbC5FQ1sz4hxeUGsfAu4gjKuRIAqj7nY+kbPMyA=;
        b=GRTZHRL4LHJKXcfhipEb1jApCyFKR2OiZS+zeMPw6ISrmASpa5ZbKjJPLU4Pef2ROe
         grezwvpHq7P9m5T/BFUx/Ky6br9JIA8VHNNnwaXmmV7WldhNhq3epDl59Rnai8H7EzJm
         jI3TRraurLkjU0UVnNixFClJtOW1wSLhkerCgvWl3DCjlDoaJy789vwh80ESeAy7CCFU
         eNaIZLg/gj+Cz818GuTCXXWVGhQ4gSm76M0djQ+h9U0nC+PbYBI4dp7fg6MgfSmOf1kW
         0Y6SCjV8dLg1wZgigBb0gi9l1m0PLKz1+DV/jLui+YJiHtj7dJ7j0XCoakE9WfCBwNVx
         1UhQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gc0FhbC5FQ1sz4hxeUGsfAu4gjKuRIAqj7nY+kbPMyA=;
        b=Vk/D+LSGCbkup7+JrJwmGyHcgt+sqjIisc+tvQUxXIMfslmrGClpO2NtH3C/i1qDCh
         CGrHLlHRdIxJVQCwu0LmTLedVVThXUkyMixBsX0/dsqV6dIrZifeLbMwQjRHCJ6U2wNG
         eCDZsD/lVmqlHFMh8cIq3KbcVmjJGV+9d1sQ0vuo2yjciqCTR5TSV1ArQLoSrzW2S8UL
         u5tQY4D0uBT87i+prq+Xyshw/We0wfHZGvHviL5gsjFSvQz5YnGcU/wBE9J2GDuyrnxc
         C9SioliL/rsEqjtEv+kc+C5cHOQ3pGzcEvwOwgPOmfU+Ks7mzucl2C9FgEcjCXf0cpcL
         DNRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gc0FhbC5FQ1sz4hxeUGsfAu4gjKuRIAqj7nY+kbPMyA=;
        b=bTfHOAue/nB48MeVXDHRTLaIQmkq3sAqqzUQ6K7eNGDY6CsqjwkMm3npqn85WVIRQB
         OWV5WcdDH93J93FjW7Oy+MSPmWv5bZwTqkEQ6dFwqW2vQIG0+S9LIdWJyby1PZOL6jei
         QM9xgR70VGEd7L45JvSqsLf3dsw/AOPt+4P8XAoWScNxgIVX+g54ffEZXp0MhnC37AZu
         /8HRpC4eAzntxklfE8sN8rtPAj7ud9DQElYIl3YdvpesPDNFw3bZWXM17eWdZm41WsPk
         sJNpZZ/RpoNQVftCjlgu62iTKVY7F8UjBkk1oHfIioUgFGmScyz6e/IQ4EpVdhznfuwu
         mIdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SfpAsPowL6mMdJfkchMio5pNBqKe1hTR1pzG9kMJm85/S2YFc
	7U5zNr7sp6ExLxPRoamW5A0=
X-Google-Smtp-Source: ABdhPJxuSiXuv+udOFoIABlvTsdIAdK2GlG6h1XmIk8YiqZn6SZR3v1O5OjM0GFbhY0YDg/jZjXrmA==
X-Received: by 2002:a92:de50:: with SMTP id e16mr4905368ilr.144.1603876305226;
        Wed, 28 Oct 2020 02:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1308:: with SMTP id r8ls519754jad.7.gmail; Wed, 28
 Oct 2020 02:11:44 -0700 (PDT)
X-Received: by 2002:a02:76c5:: with SMTP id z188mr6036110jab.74.1603876304841;
        Wed, 28 Oct 2020 02:11:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603876304; cv=none;
        d=google.com; s=arc-20160816;
        b=swd7lwvAP6hoOfO2vfCmzsKYS7eButjV1mq2+SBqKeYTUBTomxQ/dW5N1nQQzxrge/
         vxIvsOkri12Pvr9jrwdpjeoOsTU1igsigQCUfVQH2jTjWfkkH6sj+y4c5C3swMl6L2NQ
         6zvEeertemRoWE7vaBEc7Id/IT4rk7ht75ey8CodlSRpGFks5lJWhExiSucHunWnisXd
         OoVdtKxk8zT554YwQiWKomSGNB433ec+7MZFkcqU5rqAJX5sI+UC9/K9h/4g3/oggWMG
         9rM75+gsMf+E2JccqDc9Uy6LNRweNyNhIHRdb/Pm8IzsPIlQfqWGfv9XvGuU12iiT21h
         ljlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=Ww6tMX9R2xDZ2w5dCKjhSc6XtgfBGV5hdRgcsHOS4ps=;
        b=Q6UImfkxmKtb7SenFF5BnMCzsmqdBRJY1h/dT3DufKOpQopol/9OG24o/GdHCCCtFy
         hHPmvqZhss/Yed/ybwMDpcgJr7CluDuK6iSDZU+XaZ3YyU+m7bRo9/CkfOl3wthdl588
         OgYfkZCKCshWJD8JAp39uuocgMslsdBNXfF8dGujf72O41N4fh291rZIOpDEaYwKB2RD
         0VR608XlOdwDppoAG9/18TbI2w5+KTY4z0P8A5UfIPBMF/alNvCfVPTdvWQU2mcEw+4v
         W+vVR6qlo+5K1Fi12Hyzue1ih0TKBHvpTgfKpz4EfZDKgnL3P3A2co5FAsDpL0v3GBcL
         0MlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Ty/1kASH";
       spf=pass (google.com: domain of marilyncity2@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=marilyncity2@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id b21si179778iow.3.2020.10.28.02.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 02:11:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of marilyncity2@gmail.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id w191so4279241oif.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 02:11:44 -0700 (PDT)
X-Received: by 2002:aca:2111:: with SMTP id 17mr4364849oiz.139.1603876304459;
 Wed, 28 Oct 2020 02:11:44 -0700 (PDT)
MIME-Version: 1.0
Reply-To: peggycoldern@gmail.com
From: from Peggy <marilyncity2@gmail.com>
Date: Wed, 28 Oct 2020 02:11:35 -0700
Message-ID: <CAOAk-oPa4KGZ8qmF5r+Q+G7-54Efz8D8gjGKO+Qswbu0NF1+yA@mail.gmail.com>
Subject: COVID-19
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000641f8805b2b78d16"
X-Original-Sender: marilyncity2@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="Ty/1kASH";       spf=pass
 (google.com: domain of marilyncity2@gmail.com designates 2607:f8b0:4864:20::242
 as permitted sender) smtp.mailfrom=marilyncity2@gmail.com;       dmarc=pass
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

--000000000000641f8805b2b78d16
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

--=20
Dear Beneficiary

RE: UNDP -COVID-19 approved Funds for the year 2020.

The corona virus has impacted on us all. However, to help address
challenges facing the business community, the UNDP launched a special
covid-19 Response Fund of ($8,5,000,000.00) for each business
entrepreneur(s) only.

We are glad to announce to you today that this August body in
conjunction with World Bank have collectively approved and
signed the Release of ($8.55,000,000.00) to you, as palliative/Stimulus
fund as an entrepreneur.

Application Process:
(a) Application form will be given you to fill and return.
(b)Your direct telephone and fax numbers with whatsapp number
(c) Your means of Identification or passport id card
(d)Application form must be submitted within (3) business days
(e)Applicants must register genuine details to receive the said fund
through our accredited on-line banking services or by Atm card deliver.
(i)Payment of $8.5,000,000.00 to successful Applicants/entrepreneurs is
made by UNDP through our accredited bank(s) in America =E2=80=93 England su=
ch
as Co-operative JP Morgan Chase Bank USA.
(ii)This procedure is confidential and only for the applicant/beneficiary.

We await your compliance as soon as possible.

Yours truly,
John M Flint
Financial Resolution Department

Whatsapp number +1(571)444-6846
E-mail: inf_orev1@live.co.uk

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOAk-oPa4KGZ8qmF5r%2BQ%2BG7-54Efz8D8gjGKO%2BQswbu0NF1%2ByA%40mai=
l.gmail.com.

--000000000000641f8805b2b78d16
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr" c=
lass=3D"gmail_signature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr=
"><div><div><div>Dear Beneficiary</div><div><br></div><div>RE: UNDP -COVID-=
19 approved Funds for the year 2020.</div><div><br></div><div>The corona vi=
rus has impacted on us all. However, to help address</div><div>challenges f=
acing the business community, the UNDP launched a special</div><div>covid-1=
9 Response Fund of ($8,5,000,000.00) for each business entrepreneur(s) only=
.</div><div><br></div><div>We are glad to announce to you today that this A=
ugust body in</div><div>conjunction with World Bank have collectively appro=
ved and</div><div>signed the Release of ($8.55,000,000.00) to you, as palli=
ative/Stimulus fund as an entrepreneur.</div><div><br></div><div>Applicatio=
n Process:</div><div>(a) Application form will be given you to fill and ret=
urn.</div><div>(b)Your direct telephone and fax numbers with whatsapp numbe=
r=C2=A0</div><div>(c) Your means of Identification or passport id card=C2=
=A0</div><div>(d)Application form must be submitted within (3) business day=
s</div><div>(e)Applicants must register genuine details to receive the said=
 fund</div><div>through our accredited on-line banking services or by Atm c=
ard deliver.</div><div>(i)Payment of $8.5,000,000.00 to successful Applican=
ts/entrepreneurs is</div><div>made by UNDP through our accredited bank(s) i=
n America =E2=80=93 England such</div><div>as Co-operative JP Morgan Chase =
Bank USA.</div><div>(ii)This procedure is confidential and only for the app=
licant/beneficiary.</div><div><br></div><div>We await your compliance as so=
on as possible.</div><div><br></div><div>Yours truly,</div><div>John M Flin=
t=C2=A0</div><div>Financial Resolution Department</div><div><br></div><div>=
Whatsapp number +1(571)444-6846</div><div>E-mail: <a href=3D"mailto:inf_ore=
v1@live.co.uk" target=3D"_blank">inf_orev1@live.co.uk</a>=C2=A0=C2=A0</div>=
</div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOAk-oPa4KGZ8qmF5r%2BQ%2BG7-54Efz8D8gjGKO%2BQswbu0NF1=
%2ByA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CAOAk-oPa4KGZ8qmF5r%2BQ%2BG7-54Efz8D8gjGKO%=
2BQswbu0NF1%2ByA%40mail.gmail.com</a>.<br />

--000000000000641f8805b2b78d16--
