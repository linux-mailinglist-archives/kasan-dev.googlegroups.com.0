Return-Path: <kasan-dev+bncBCI4B6EH6IPBBQHPWWQQMGQETDGTAEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 173F36D7DB9
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Apr 2023 15:29:38 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id p27-20020a05610223fb00b00425b0a40455sf12619557vsc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Apr 2023 06:29:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680701377; cv=pass;
        d=google.com; s=arc-20160816;
        b=BCT1z0ygumleT9G/cTh6V0XwojBat/jhWzsVaUWHt/ixLwtlp9ARiwImQXxzHnbYh8
         7n3oKWK8cOLy/0UYoN0P+9Fdrz+9yZG0EYePRKd2MikDP7GR8If/yizp11k15KeNcPdm
         qRD3D3U8iI7Kmuqk8t9tJq7Y6XrQs8dlIEr+HEMmKxWC7R+rpFVG9l2k7xpPXPj/8lUN
         dfVpNxusiYLMCdo/Gbm1Tphj8O2t4oC0DIUJDLLkiWlZKVZwNC+xQEIygF5b6TLHdzDY
         o/rOxUUqw1cvplgjbfhOnbrNIu+3OQo86vOJpbZkzqxXQhd5YOEN018V+unutiic+VLm
         /drQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=JMruhImXYeXp3/dTd448S04NFOb1KWVYxWcAh/eT2kI=;
        b=A2cYIR/NYJM6qZjtP3us/XekJHpHpEdB2NvUt/wk9iUSWfiKZ1Pc0XZF6Fcn+MhQ73
         lDp02CnLVUpX+2ebCuM8VIoxf/bEjHpbM5spHTyNGZ/9Z8mUYotjeyAgu6k4lEYokaIE
         8M5re6eYU4Pe2nM0rfzWL+nHmBzM6n9xxnryB8FY2M+EWkXFd4tIl8Xp4ZBqOyC2LHJd
         WPecAKGITQy1PpO5aKaBZum3+OGL8h2zRQPV8pOiQxSWFCeL7XjYTYGK4Nj5c0pRKhFU
         FVQriTVPzo76dj/z2ShcRkophmDTTyuyuV5S64ApZQq51TKJ51DyDgNUTaAC355gvWwf
         kBqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Ifkwb9v+;
       spf=pass (google.com: domain of samanthakipkalya24@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=samanthakipkalya24@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680701377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JMruhImXYeXp3/dTd448S04NFOb1KWVYxWcAh/eT2kI=;
        b=Z6GheLvOhrQ+ASsx4GQe7Sje0HUdms7xWRrRvNqEsvcmlqK/IRXWmtpTrsH4h0RROx
         0QaOe9NhPBAb2fAijtNEstN6TKEnZ4NonspPm3FH7ATnse156SACxYNLK0CBCtYBBn1Q
         fjkQTS6kzGubAJfcJT51W4wqEiu1e6nAz9tf0P4DFLKc/E6IoLiz0seYUe/n8DBtLo2m
         VeCNUDL+gdbX/hvUh60NFX7Nbfn1DnsfN3ZGdrm628IBLB20Dzs2mE70HarZhnCDML0t
         k0XmgfsBuUgrFz/jnFs0Xz2DNlMlR30qhe/gd+GZ5ZeU3oDC6jQKEtMGFVdiADXvKolC
         f4mw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680701377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=JMruhImXYeXp3/dTd448S04NFOb1KWVYxWcAh/eT2kI=;
        b=lZNUfeGh+kwIYalK/6zGQBBi0bn5oM05E+wIw4ZEmHCGjefuozKARZV6O+aMzRhlPp
         tHDclubUDpIZpC42VxxlcKKHH9HSzK/fFV1s1Gl4C5SexsSLZhVnb1/dqRnGBqJtvL7U
         yTE18Ln6SfhfMRLdL31tLjAGX5y4GtmPfBt3MmfEkv315U/RaoK0ZeAPjlnhs5w62+pO
         L6KHM+ROPLVO7l28ca2QHge/cFUcyVi3tvAiKnzd4oJPtlRqEX3FB7qottx3sjEKCt/P
         wEhSSGEncLGhiCqy43sfRiZEXBIGw0cTdCneJb2c6ufmL4BHMIwbQNQ1fqO299Ovsrw2
         3CVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680701377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JMruhImXYeXp3/dTd448S04NFOb1KWVYxWcAh/eT2kI=;
        b=yNy0Z3d3KIp1/oGBKoUafw9UcF15XSkGaho3IAcdb3lqHKXhfbPv5mploraOlAmImI
         zaDaKpjvc4jNelYZUz4Yhrmc5zArU6l/UnqcPKy+BlzfOj2khO3E0bYDsw+b7sBZUSDv
         Poa+JOqJORBgTpOyTzCSEKvM7HDzSvKRKIHIeKkuo6dq06R//fLdFBtL68wQqfyNfASP
         Y63RR2tQHs9xVOV9ZvnHbhbo+08a8CNYkvLDrgug7N6VHmpF8KQUnDOKsD8iEaZe+jqi
         sZMHtkPEIVIalfyWS9IQnEEuXpQ30D8tEmQFEFNV8d7atImFYsHVGFjh5yDV9xyds+Sw
         axng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fP7AC/8Muk8uM5C7ZL/LFBzaKOO2VAL08SpQORBojzO88yG3KR
	oKvAPN3s2/TAlRQXdu1gz9o=
X-Google-Smtp-Source: AKy350bYuA6p7cwtE8YiAcCSwYEyPUxNluT3GDDbGRZcZCob5/O13VPmuI8L8b6bDvybbPCwktn02Q==
X-Received: by 2002:a9f:3110:0:b0:68b:94c5:7683 with SMTP id m16-20020a9f3110000000b0068b94c57683mr4273974uab.0.1680701376710;
        Wed, 05 Apr 2023 06:29:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:104a:b0:43b:f241:ea10 with SMTP id
 z10-20020a056122104a00b0043bf241ea10ls2263586vkn.6.-pod-prod-gmail; Wed, 05
 Apr 2023 06:29:36 -0700 (PDT)
X-Received: by 2002:a05:6122:188d:b0:43c:5af2:4340 with SMTP id bi13-20020a056122188d00b0043c5af24340mr2683398vkb.2.1680701376001;
        Wed, 05 Apr 2023 06:29:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680701375; cv=none;
        d=google.com; s=arc-20160816;
        b=Jx7jVAdIF+HNcAfs8RJ6HntyeOCCHyJkcyWVf2dPyCVrcH0juiNsn8JxZOxQZm9yK/
         n+vg1LIW2ll5WPfHLHKIlzTbLKQxFMOWBPmaXoqPbek1sungzNDCVLXPwXS/qI1/ULq1
         lmiRVfxUl8EACS7Hf7/xQxcPKVLWy0UoHs/yDMgp0rd5bONetlqRKfAYTFw+T4XF4Obx
         +0LcjuLI0c+lFqsDTkhkTTJk0fWGyDoFCpXlOl1LzmspCt7GCxPA4epjitH5yoaZcfNt
         nrPpWm9dKBGtyTQLlHoUED/A0NmG8WKlADO/Zv84y0hkz4sh/5x1ewCHliQbyVpyQtEK
         gDag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=nWU7AO+a4H1149XuPSwXKN7DBadWmQfkHAREL40tPAw=;
        b=rYoP2cbIEJ5fj0hrT+HMuaJGB0U8EhHmUABZWqzPR0Q27zj1yfhq3gHSjySeg4CrJk
         sOO42iKmLRRqL8xRB69B1cmf1UIwg7Mu8JbkoS/UCVSXye21G/v72BhoUb6DsocjWizd
         kSWScsDQX3A26yJnQkPwlbzus+lLuMyuZ9GIj7qo823EI/69YH7Sl+aiUza+pvvZ2FCc
         P9ygEbZCzMGWfeJ08e0Hz4RbjexhKriQul0EJyCT0Kqg5r0a7306BR9spM6cbPCDBAGu
         qrhOwmldpAo9NzP/IrDJMc9VTyXoTRSdAxb5v7Lv25/wHQN/HXdGN9RDgiY6vOsXlP1s
         u/pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Ifkwb9v+;
       spf=pass (google.com: domain of samanthakipkalya24@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=samanthakipkalya24@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id bn10-20020a0561220f0a00b00400dba9ad27si747445vkb.0.2023.04.05.06.29.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Apr 2023 06:29:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of samanthakipkalya24@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id m16so22171584ybk.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Apr 2023 06:29:35 -0700 (PDT)
X-Received: by 2002:a25:d20f:0:b0:b78:8bd8:6e88 with SMTP id
 j15-20020a25d20f000000b00b788bd86e88mr4217292ybg.6.1680701375557; Wed, 05 Apr
 2023 06:29:35 -0700 (PDT)
MIME-Version: 1.0
From: Samantha Kipkalya <samanthakipkalya091@gmail.com>
Date: Wed, 5 Apr 2023 06:36:38 -0700
Message-ID: <CAL9mhjORuNNSPsDe1gj=Z+HhDckJQfG3ZxuyFf3D8jxMGSXSYw@mail.gmail.com>
Subject: PLEASE MY DEAREST HELP ME OUT.
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000076bb8105f896c814"
X-Original-Sender: samanthakipkalya091@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Ifkwb9v+;       spf=pass
 (google.com: domain of samanthakipkalya24@gmail.com designates
 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=samanthakipkalya24@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000076bb8105f896c814
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

PLEASE MY DEAREST HELP ME OUT.

Please my dearest help me!

MY cry for you
Greetings my dearest one,


I am writing this mail to you with tears and sorrow from my heart. With due
respect, trust and humanity, i appeal to you to exercise a little patience
and read through my letter, i wish to contact you personally for a long
term business relationship and investment assistance in your Country so i
feel quite safe dealing with you in this important business having gone
through your remarkable profile, honestly i am writing this email to you
with pains, tears and sorrow from my heart, i will really like to have a
good relationship with you and i have a special reason why i decided to
contact you, i decided to contact you due to the urgency of my situation,
My name's are princess Samantha Kipkalya Kones, 24yrs old female and I held
from Kenya in East Africa.


My father was the former Kenyan road Minister. He and Assistant Minister of
Home Affairs Lorna Laboso had been on board the Cessna 210, which was
headed to Kericho and crashed in a remote area called Kajong=E2=80=99a, in
western Kenya. The plane crashed on the Tuesday 10th, June, 2008.

You can read more about the crash through the below site:



http://edition.cnn.com/2008/WORLD/africa/06/10/kenya.crash/index.html





After the burial of my father, my stepmother and uncle conspired and sold
my father=E2=80=99s property to an Italian Expert rate which the shared the=
 money
among themselves and live nothing for me. I am constrained to contact you
because of the abuse I am receiving from my wicked stepmother and uncle.
They planned to take away all my late father=E2=80=99s treasury and propert=
ies from
me since the unexpected death of my beloved Father. Meanwhile i wanted to
escape to the USA but they hide away my international passport and other
valuable travelling documents. Luckily they did not discover where i kept
my fathers File which contains important documents.




So I decided to run to the refugee camp where i am presently seeking asylum
under the United Nations High Commission for the Refugee here in
Ouagadougou, Republic of Burkina Faso.


One faithful morning, I opened my father=E2=80=99s briefcase and found out =
the
documents which he has deposited huge amount of money in bank in Burkina
Faso with my name as the next of kin. I travelled to Burkina Faso to
withdraw the money for a better life so that I can take care of myself and
start a new life, on my arrival, the Bank Director whom I met in person
told me that my father=E2=80=99s instruction/will to the bank is that the m=
oney
would only be release to me when I am married or present a trustee who will
help me and invest the money overseas.



I am in search of an honest and reliable person who will help me and stand
as my trustee so that I will present him to the Bank for transfer of the
money to his bank account overseas. i have chosen to contact you after my
prayers and I believe that you will not betray my trust. But rather take me
as your own sister.



Although, you may wonder why I am so soon revealing myself to you without
knowing you, well I will say that my mind convinced me that you may be the
true person to help me. More so, my father of blessed memory deposited the
sum of (US$9.5) Dollars in Bank with my name as the next of kin. However, I
shall forward you with the necessary documents on confirmation of your
acceptance to assist me for the transfer and statement of the fund in your
country.



As you will help me in an investment, and i will like to complete my
studies, as i was in my 1year in the university when my beloved father
died. It is my intention to compensate you with 40% of the total money for
your services and the balance shall be my capital in your establishment.


As soon as I receive your positive response showing your interest I will
put things into action immediately. In the light of the above. I shall
appreciate an urgent message indicating your ability and willingness to
handle
this transaction sincerely.






AWAITING YOUR URGENT AND POSITIVE RESPONSE, Please do keep this only to
yourself for now untill the bank will transfer the fund.


I beg you not to disclose it till i come over because I am afraid of my
wicked stepmother who has threatened to kill me and have the money alone ,I
thank God Today that am out from my country (KENYA) but now In (Burkina
Faso) where my father deposited these money with my name as the next of
Kin. I have the documents for the claims. i feel you are only one who can
help me out of this

Yours Sincerely
 Princess Samantha Kipkalya Kones
God bless you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAL9mhjORuNNSPsDe1gj%3DZ%2BHhDckJQfG3ZxuyFf3D8jxMGSXSYw%40mail.gm=
ail.com.

--00000000000076bb8105f896c814
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">PLEASE MY DEAREST HELP ME OUT. <br><br>Please my dearest h=
elp me!<br><br>MY cry for you <br>Greetings my dearest one,<br><br><br>I am=
 writing this mail to you with tears and sorrow from my heart. With due res=
pect, trust and humanity, i appeal to you to exercise a little patience and=
 read through my letter, i wish to contact you personally for a long term b=
usiness relationship and investment assistance in your Country so i feel qu=
ite safe dealing with you in this important business having gone through yo=
ur remarkable profile, honestly i am writing this email to you with pains, =
tears and sorrow from my heart, i will really like to have a good relations=
hip with you and i have a special reason why i decided to contact you, i de=
cided to contact you due to the urgency of my situation, My name&#39;s are =
princess Samantha Kipkalya Kones, 24yrs old female and I held from Kenya in=
 East Africa. <br><br><br>My father was the former Kenyan road Minister. He=
 and Assistant Minister of Home Affairs Lorna Laboso had been on board the =
Cessna 210, which was headed to Kericho and crashed in a remote area called=
 Kajong=E2=80=99a, in <br>western Kenya. The plane crashed on the Tuesday 1=
0th, June, 2008.<br><br>You can read more about the crash through the below=
 site:<br><br><br><br><a href=3D"http://edition.cnn.com/2008/WORLD/africa/0=
6/10/kenya.crash/index.html">http://edition.cnn.com/2008/WORLD/africa/06/10=
/kenya.crash/index.html</a><br><br><br><br><br><br>After the burial of my f=
ather, my stepmother and uncle conspired and sold my father=E2=80=99s prope=
rty to an Italian Expert rate which the shared the money among themselves a=
nd live nothing for me. I am constrained to contact you because of the abus=
e I am receiving from my wicked stepmother and uncle. They planned to take =
away all my late father=E2=80=99s treasury and properties from me since the=
 unexpected death of my beloved Father. Meanwhile i wanted to escape to the=
 USA but they hide away my international passport and other valuable travel=
ling documents. Luckily they did not discover where i kept my fathers File =
which contains important documents. <br><br><br><br><br>So I decided to run=
 to the refugee camp where i am presently seeking asylum under the United N=
ations High Commission for the Refugee here in Ouagadougou, Republic of Bur=
kina Faso.<br><br><br>One faithful morning, I opened my father=E2=80=99s br=
iefcase and found out the documents which he has deposited huge amount of m=
oney in bank in Burkina Faso with my name as the next of kin. I travelled t=
o Burkina Faso to withdraw the money for a better life so that I can take c=
are of myself and start a new life, on my arrival, the Bank Director whom I=
 met in person told me that my father=E2=80=99s instruction/will to the ban=
k is that the money would only be release to me when I am married or presen=
t a trustee who will help me and invest the money overseas. <br><br><br><br=
>I am in search of an honest and reliable person who will help me and stand=
 as my trustee so that I will present him to the Bank for transfer of the m=
oney to his bank account overseas. i have chosen to contact you after my pr=
ayers and I believe that you will not betray my trust. But rather take me a=
s your own sister.<br><br><br><br>Although, you may wonder why I am so soon=
 revealing myself to you without knowing you, well I will say that my mind =
convinced me that you may be the true person to help me. More so, my father=
 of blessed memory deposited the sum of (US$9.5) Dollars in Bank with my na=
me as the next of kin. However, I shall forward you with the necessary docu=
ments on confirmation of your acceptance to assist me for the transfer and =
statement of the fund in your country. <br><br><br><br>As you will help me =
in an investment, and i will like to complete my studies, as i was in my 1y=
ear in the university when my beloved father died. It is my intention to co=
mpensate you with 40% of the total money for your services and the balance =
shall be my capital in your establishment. <br><br><br>As soon as I receive=
 your positive response showing your interest I will put things into action=
 immediately. In the light of the above. I shall appreciate an urgent messa=
ge indicating your ability and willingness to handle<br>this transaction si=
ncerely.<br><br><br><br><br><br><br>AWAITING YOUR URGENT AND POSITIVE RESPO=
NSE, Please do keep this only to yourself for now untill the bank will tran=
sfer the fund. <br><br><br>I beg you not to disclose it till i come over be=
cause I am afraid of my wicked stepmother who has threatened to kill me and=
 have the money alone ,I thank God Today that am out from my country (KENYA=
) but now In (Burkina Faso) where my father deposited these money with my n=
ame as the next of Kin. I have the documents for the claims. i feel you are=
 only one who can help me out of this<br><br>Yours Sincerely<br>=C2=A0Princ=
ess Samantha Kipkalya Kones <br>God bless you.<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAL9mhjORuNNSPsDe1gj%3DZ%2BHhDckJQfG3ZxuyFf3D8jxMGSXSY=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAL9mhjORuNNSPsDe1gj%3DZ%2BHhDckJQfG3ZxuyFf3D8j=
xMGSXSYw%40mail.gmail.com</a>.<br />

--00000000000076bb8105f896c814--
