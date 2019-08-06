Return-Path: <kasan-dev+bncBCOZZYH3S4DRBDHKUXVAKGQE6BTVSRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CB1383188
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Aug 2019 14:39:41 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id d204sf34684015oib.9
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 05:39:41 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FW9fvSN6PbJkGH+hIEBIVTNiPF488Wj6+MGmVydqGtQ=;
        b=kfIc2JFAI28VznstH0+gVf3l4pE1WnZJeyXq7fSGcJIqJcaV93sBfCYwLKzBOtlw8p
         C9HVj/cag0ZDO2MD80WcrGmH6W3E68om67rffU5gojAiN5KDuGIRKOBaJ35rlz7SFtg9
         Iv3IbdBCffgem5vNUT/MdwY/Z80JHT3aWSrehidlNlHJtY52/rquTi/jl3yeerqhHUsM
         cTyOM2KofpnfFQP5+uRtV4RbqRqtI0hGQfX7ZeddL4s4aRry8LDXK923U+lvIP/ucigG
         6dLamkPMD8IpngZUS/xaAkwvfORy5H1OIqNKJ02n/x6khusv+IHVX1w5Idr/EoTiP+Yw
         lcUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FW9fvSN6PbJkGH+hIEBIVTNiPF488Wj6+MGmVydqGtQ=;
        b=gZrQnBOJhdaxryB8n3pLHcIFkgUcn6r0fqfNNCMYHG5N2attUCn1UqJFIJpulY0hDY
         sJFEoIdyAI1ioBTWYN1EbokvFzifP+y9eIwzxU2gPhi/XGaCKHhnsASU6qYCzfcT2Sro
         IYHW5cTlRIBL7omvfM/f/QDZe0AX/61sNUuu6TzzvvG8s4TtWRHccMbNixbXfONTqV3Q
         AG1JsLA5G4oNz0Bw/bsp2ZkJxogYrmNE61uVbjg/gBaA3ahYzmSfVbA6s6FvHWgh5sVO
         nmB6ccfrXgdw9YjSOuyxwtpa38GwBFa5gdIXY/Y76Bj5bwJZow3u+yydIp7weQomCkOS
         qJTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FW9fvSN6PbJkGH+hIEBIVTNiPF488Wj6+MGmVydqGtQ=;
        b=MyNfmlqoBGZlq52edBBy+ZvH123A61QOPH6jtphKd0vIc1Zs6e/FyGaQ8XCCjuQLdi
         Z8JSpg+F4AihP42zQuRt6g6lIhBhE7+3uvk05PtDx0Ode24q5EAvY9QGauJ/xdeiFzPK
         llZJXCdzIFmhLXLIJi2hlnNpOtfua6M+1FyBk7zN+fgKWQhmDiUyfB3eTU7o5nzTzL2O
         3wCT17tfOq0tF9k4A9bs0sDquMFTL6vwytZVWQnf4mEmkaYumCn+LSkOIxzGTUtOwKLJ
         GknfNu34uQSOGNsbMICsdsOA0OheD0u/byhY3zPiAZYhfWRuJ0aJ2le5rOx+93GLT+it
         3A3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXaM7fWhShF01T3jsPB7bcrjclRET2Gw/W6ZAG0nm3hHAxMLzVj
	kqMbpz1ClvakpXOZX6LV0VY=
X-Google-Smtp-Source: APXvYqzfcZ1DrFIrASZVSzhwJfh3z9Q5lVRe2JHeicchT9sSGNoLI3liIZTXf8gWCR2IJqTPxtfMMw==
X-Received: by 2002:a05:6830:1206:: with SMTP id r6mr3140213otp.37.1565095180167;
        Tue, 06 Aug 2019 05:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c78e:: with SMTP id x136ls770068oif.5.gmail; Tue, 06 Aug
 2019 05:39:39 -0700 (PDT)
X-Received: by 2002:aca:4e84:: with SMTP id c126mr2166257oib.153.1565095179686;
        Tue, 06 Aug 2019 05:39:39 -0700 (PDT)
Date: Tue, 6 Aug 2019 05:39:39 -0700 (PDT)
From: "Hvanyou 42@gmail.con" <hvanhvan10@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <ce375d66-143b-41a0-9e86-6144d0249993@googlegroups.com>
In-Reply-To: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
References: <CAOE+jABoFq5K=s7JvuJSkC4PgocZSytUPcsniYT6gYUcgOVjdA@mail.gmail.com>
Subject: Re: I have already sent you Money Gram payment of $5000.00 today,
 MTCN 10288059
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_2071_1282188162.1565095179120"
X-Original-Sender: hvanhvan10@gmail.com
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

------=_Part_2071_1282188162.1565095179120
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=E0=B9=80=E0=B8=A1=E0=B8=B7=E0=B9=88=E0=B8=AD =E0=B8=A7=E0=B8=B1=E0=B8=99=
=E0=B8=A8=E0=B8=B8=E0=B8=81=E0=B8=A3=E0=B9=8C=E0=B8=97=E0=B8=B5=E0=B9=88 2 =
=E0=B8=AA=E0=B8=B4=E0=B8=87=E0=B8=AB=E0=B8=B2=E0=B8=84=E0=B8=A1 =E0=B8=84.=
=E0=B8=A8. 2019 21 =E0=B8=99=E0=B8=B2=E0=B8=AC=E0=B8=B4=E0=B8=81=E0=B8=B2 3=
2 =E0=B8=99=E0=B8=B2=E0=B8=97=E0=B8=B5 55 =E0=B8=A7=E0=B8=B4=E0=B8=99=E0=B8=
=B2=E0=B8=97=E0=B8=B5 UTC+7, MR. Goodluck Jonathan Former President of Nige=
ria, =E0=B9=80=E0=B8=82=E0=B8=B5=E0=B8=A2=E0=B8=99=E0=B8=A7=E0=B9=88=E0=B8=
=B2:
> Attn Beneficiary,
>=20
> GoodNews
> I have already sent you Money Gram payment of $5000.00 today, MTCN 102880=
59
> because we have finally concluded to effect your transfer
> funds of $4.8,000.000usd
> through MONEY GRAM International Fund transfer Service
> Each payment will be sending to you by $5000.00 daily until the
> ($4.8,000.000usd) is completely transferred
> we have this morning sent=C2=A0 MONEY GRAM payment of $5,000.00=20
> ready to pick up by you, Money Gram payment of $5000.00 sent today, MTCN =
10288059
> So contact the MONEY GRAM Agent to pick up this first payment of $5000 no=
w
>=20
> Contact person Dr. Don James
> Direector MONEY GRAM Service,Benin
> Phone number: +229 98856728
> E-mail: moneyg...@outlook.fr
>=20
> Ask him to give you the complete, sender name, question and
> answer to enable you pick up the $5.000.00 sent today, Also you are instr=
ucted to re-confirm to him your information's as listed below to avoid wron=
g transactions
>=20
> (1) Receiver Name--------------
> (2) Contact address--------------
> (3) Country---------------------
> (4) Telephone numbers-------------
>=20
> Contact Dr. Don James for your MONEY GRAM payment of $4.8,000.000usd
> Note: I have paid the deposit and insurrance fees for you but the only mo=
ney you are required to send to them is just $19.00 dollars only for transf=
er fee
> You must make sure that you send this required transfer to office before =
you can be avle to pick up your first $5000.00 at your addrss today.
> We need your urgent reply
>=20
> Best Regards
> Mrs,Mary J. Anold



=E0=B9=80=E0=B8=A1=E0=B8=B7=E0=B9=88=E0=B8=AD =E0=B8=A7=E0=B8=B1=E0=B8=99=
=E0=B8=A8=E0=B8=B8=E0=B8=81=E0=B8=A3=E0=B9=8C=E0=B8=97=E0=B8=B5=E0=B9=88 2 =
=E0=B8=AA=E0=B8=B4=E0=B8=87=E0=B8=AB=E0=B8=B2=E0=B8=84=E0=B8=A1 =E0=B8=84.=
=E0=B8=A8. 2019 21 =E0=B8=99=E0=B8=B2=E0=B8=AC=E0=B8=B4=E0=B8=81=E0=B8=B2 3=
2 =E0=B8=99=E0=B8=B2=E0=B8=97=E0=B8=B5 55 =E0=B8=A7=E0=B8=B4=E0=B8=99=E0=B8=
=B2=E0=B8=97=E0=B8=B5 UTC+7, MR. Goodluck Jonathan Former President of Nige=
ria, =E0=B9=80=E0=B8=82=E0=B8=B5=E0=B8=A2=E0=B8=99=E0=B8=A7=E0=B9=88=E0=B8=
=B2:
> Attn Beneficiary,
>=20
> GoodNews
> I have already sent you Money Gram payment of $5000.00 today, MTCN 102880=
59
> because we have finally concluded to effect your transfer
> funds of $4.8,000.000usd
> through MONEY GRAM International Fund transfer Service
> Each payment will be sending to you by $5000.00 daily until the
> ($4.8,000.000usd) is completely transferred
> we have this morning sent=C2=A0 MONEY GRAM payment of $5,000.00=20
> ready to pick up by you, Money Gram payment of $5000.00 sent today, MTCN =
10288059
> So contact the MONEY GRAM Agent to pick up this first payment of $5000 no=
w
>=20
> Contact person Dr. Don James
> Direector MONEY GRAM Service,Benin
> Phone number: +229 98856728
> E-mail: moneyg...@outlook.fr
>=20
> Ask him to give you the complete, sender name, question and
> answer to enable you pick up the $5.000.00 sent today, Also you are instr=
ucted to re-confirm to him your information's as listed below to avoid wron=
g transactions
>=20
> (1) Receiver Name--------------
> (2) Contact address--------------
> (3) Country---------------------
> (4) Telephone numbers-------------
>=20
> Contact Dr. Don James for your MONEY GRAM payment of $4.8,000.000usd
> Note: I have paid the deposit and insurrance fees for you but the only mo=
ney you are required to send to them is just $19.00 dollars only for transf=
er fee
> You must make sure that you send this required transfer to office before =
you can be avle to pick up your first $5000.00 at your addrss today.
> We need your urgent reply
>=20
> Best Regards
> Mrs,Mary J. Anold

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ce375d66-143b-41a0-9e86-6144d0249993%40googlegroups.com.

------=_Part_2071_1282188162.1565095179120--
