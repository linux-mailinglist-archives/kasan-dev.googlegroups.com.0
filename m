Return-Path: <kasan-dev+bncBCC5R5HGSAKBBOHT2G3QMGQER5YRHVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A0D089867E6
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 22:59:37 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-42cb830ea86sf1092635e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 13:59:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727297977; cv=pass;
        d=google.com; s=arc-20240605;
        b=J2puJUxG6Ym0DEV5T+eB/Zf8Wuv7ibJslrw6BlFz9Tei+GQaFJ7IFbwk4LY+cRRE86
         lRHdNHiwmMUhRXC/E/ivxzvgofqm+DU34qKRQ025zU/pOhN8Athz4vV/FlpKQ/kn0NBk
         cAc2PVSuNApnI4yRTQQ/2urOQLNVTweDM0Is7LC2iYRyLMxMbwtpBgG42WYhoGRgepA7
         pN1DvX0/aFHKR2xCKQYryJcxSH6ReREppY8S19NbcdOZas1Wx+xnrKgMHCWg7/tJA2Oy
         Q9wBFazFPl2XuSDJ8cl7zhdc0xd4D/rrEK0ElTQe83Y8QxOIDlg+hKj5mKkr2i8GtOl4
         26Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=OWSoFOkgsaJ9UzmDZLalkYXOv8Nzxe744NamPoOYlv4=;
        fh=iEGHrkJg8MHFPQSYMIVD+ZUZOG2WATSh3k29+ABBjRg=;
        b=FG6BvWyzNt/oZ8VIQ5X0whb/S37AbNC/IXIfpyVcn1mVdnhkZoeekjWNvFWZ+UXWNV
         JkJVtDpU1hL0xG62YZpf9t/SGRQEDfMDKEp57uwPcGK2aax7yMY1jEWNSy6l6SF2Cb4K
         ZCM6iDxkNmSDkONXLP2+NEnO7BYP4k4fw+O8LA9Igz/pg3Y59jHgDI/rBuTb/zeqF9Dw
         rFKx/IPVKaiqvpoGabNSNtZda9qASOKZzVEbqmCI8E6n9qePviNOkD8ySAqn92TqHMlL
         KbpbaD1nf+9WN+HK9kpbsbuMJbeBSm1RaexsEFn0Tg8ypgPVQLqIMC2kLZnIkwGXCjur
         zAGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BqvZUGL7;
       spf=pass (google.com: domain of qosimzubair@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=qosimzubair@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727297977; x=1727902777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OWSoFOkgsaJ9UzmDZLalkYXOv8Nzxe744NamPoOYlv4=;
        b=bE7uhI6xSZR76NX0Bv08Bm8sYGL3sIJc5D+I8AbYYvlydkHE623Ki56zBOBZggn30/
         Sk5vzJgWUHveB3vqnhBcFa0+MpWRohjyd5TK3ES8u3+QvsecJPzaXhcSIJaIgFrkdqab
         98skboeASSQ6NK5N8vbTHOwKqSS0fwSXOiuTvaqRzVrthu5YQUczMXmq/BBSvHXSU4rL
         mSdNZwAXfFyhvviD+3/mCOsIjU3faFbsuaIgft6HHJDjF0DUXnnLlDKw0Bo9QjDcGHE+
         jSaSWV48NOlvOZxZQwkmXDAD9gVslBC9O7AQ1YLZD6u1C6VXJm6VKsYXtRJzj/vuxE2A
         T4tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727297977; x=1727902777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=OWSoFOkgsaJ9UzmDZLalkYXOv8Nzxe744NamPoOYlv4=;
        b=M3stjty+cjex2/lneUT2MCwiVxIKAF5lfeVZ3H00fNsJa266WgwNIh4gBllB+Cn5ip
         6s8tuAr/6vk3uCbsiGzeBiL7SUBkgd4jjbTiTNuzpwzkI0PyLJxXjNXN1+pY63FscMUN
         7c4MN8UPO05G69qw1wsunzFZHqH0cG5hkG9wVggsfMeLt5uvyASkr4FiLgQq860E5Epk
         xgqU2EWgDO8yZYpTvYfJDQ6QDWtr/AELaES/NRqaz+FaO4BKW7OOH5LCTPXiq0kZQWT9
         Ya6WWOHRS3fw2THGsobFxpWBlEp2C3p7Skks1iC85+YxUu0jj19cZH5lSjd8Z8pv4Maq
         AduA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727297977; x=1727902777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OWSoFOkgsaJ9UzmDZLalkYXOv8Nzxe744NamPoOYlv4=;
        b=AlfQt5A0XjGLgLdVolC1tYuJQmKG/O8Z61360+1J9CbnlDy1fyQu6zMU6CnesonsqC
         sNdWhtC/oiaIEl8acRsiHeZFiz0vLeST5+pbvrFQczjrke4ODbt+xwoAtuyioH/4Ngmj
         e2G0zEhZcShZ6hBgOj1NoCJlDzs4itCS9XTkFXdYaBnsxzQd+mTS8VOc5tuAH2SdzuBb
         Z1Ps216HR0adwGq9+xbhZDKUG+yX1j8ZAyI2BAs79yXxtH7YIky3zfVPWAfrERATULqN
         QSwfHrqI4j1o3F6AK6FxF1TIVKfirAoXq6v8SaMRB0YV32r305Ia3n+xBzpj+kM2iL7s
         psnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH4VWER7N6aOqASpzUxdgwuGJN/xLJuthFlPl843AvUdpkn60sOc2T4AJBFejRimF0L76dMQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw5Glv9ITC3VeTta5wmoBO9NOgCrZQ4sj9YaIQU3NgpYBNsFHmo
	A+VvbicNAb55Yk51Bj1kUS/HVopRFl5B+jO3wg0nT8DLnLtV2t/F
X-Google-Smtp-Source: AGHT+IEdoPDo27vfPokIpP6FUtKiugAIi2TR+Ay+o5tic1+lpUuXtS8avpvXbZXrE0zSYhGyBjO4bw==
X-Received: by 2002:a05:600c:5127:b0:42b:a9b4:3f59 with SMTP id 5b1f17b1804b1-42e9610de2emr30350235e9.14.1727297976472;
        Wed, 25 Sep 2024 13:59:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8f:b0:42c:bb08:9fa6 with SMTP id
 5b1f17b1804b1-42f521611afls904235e9.0.-pod-prod-03-eu; Wed, 25 Sep 2024
 13:59:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUomtUiqUPr1u1dojphGkppBjKvgG+wmFJouH6jiQvOKS0SROvgTsKiUb2rFZRf+QGgW3Pl4Tfuftk=@googlegroups.com
X-Received: by 2002:a05:600c:5006:b0:42c:b995:20ca with SMTP id 5b1f17b1804b1-42e9614554bmr29220525e9.24.1727297974416;
        Wed, 25 Sep 2024 13:59:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727297974; cv=none;
        d=google.com; s=arc-20240605;
        b=Y04hOQuDbLw1vxVEv4AYvKrK3SZ5TBKp39+kvXTt3Mq5+iWIFg3L695R+3dv6UNGNm
         qfeT7UfRgDbQGnNqYsKgCojWQ80tP/oBevS9qbWuN7ldXAaNnzR6xRlj+g28rADSMBhS
         B0f6kluJnbw+xEbBf8LqfvZZ9sKMm5duLku2iwipY4uo13hTJkPqZvgBBu23NNzhbVSZ
         zybxOA4rudJqPSdJpc8fxFlVeImC7RWXBHdf2aF3Qk358HsvnnOPjpNuI0GWrjeAbu8H
         4tOIBksD5lNW/VNorX2CXtXllgyjWEsGA4Ndkiyki5gJbKa0gu/PnGez1MROJfjmfHAT
         DnBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=PBzrkPJyzdTohO5PayJQWOUCAxnc42ytwp9o1W9CWrs=;
        fh=ZIHnItCur7RT5vvHboIvieGO3bUzhnJIuXKEELDohsg=;
        b=XGEzSyEXTAB9Pr5jcxxib4DTrGIB3oMwykJzWagfENgVb1GwvslAE5VUOH8AEmGCjG
         R3f89iVTMSRMyVhcY5xuWEXvD1ICAFc5DxGHYzx8lUDi2538LDjtD9XbB8ImMrr/z/SF
         nFbHvWLc3YKsnOWfq238jC62moERLC9MUASiT5hJNMnSOVWLlGCdwEWA9X3yQ7w2sXLz
         eYGzQJ0qAs6rfEitiSsQoLX7tUXBLMRo157ihV0khr7feLpqgQ0uz/wiMimMAXcA9ybP
         3Ybw8bA8bJo0NFJraIEVFXF1P6cnNztCZW/rNSYYLoDUQNjtITy8aexGOXtcrxBxK1Xz
         rZKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BqvZUGL7;
       spf=pass (google.com: domain of qosimzubair@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=qosimzubair@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e96a3c27asi528365e9.2.2024.09.25.13.59.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 13:59:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of qosimzubair@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-536748c7e9aso379010e87.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 13:59:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXr7mBM67twx0XGPLros+nKa8Vyb3cmZLJHUfLXNItWY2Aoxj/G1AWkeYIo/NhzQ5DflWTFOj+lveU=@googlegroups.com
X-Received: by 2002:a05:6512:e94:b0:533:d3e:16e6 with SMTP id
 2adb3069b0e04-5387754d312mr2714396e87.25.1727297973381; Wed, 25 Sep 2024
 13:59:33 -0700 (PDT)
MIME-Version: 1.0
Reply-To: mariaelizabethschaeffler44@gmail.com
From: maria elizabeth schaeffle <qosimzubair@gmail.com>
Date: Wed, 25 Sep 2024 13:59:19 -0700
Message-ID: <CAOnMvBU-WYAVU42qzGNJAo9UxFakAqXucowbhiamFz_=9tdiAA@mail.gmail.com>
Subject: donate 1,500,000.00 euros for you
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001ff2590622f7e6a1"
X-Original-Sender: qosimzubair@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BqvZUGL7;       spf=pass
 (google.com: domain of qosimzubair@gmail.com designates 2a00:1450:4864:20::12f
 as permitted sender) smtp.mailfrom=qosimzubair@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--0000000000001ff2590622f7e6a1
Content-Type: text/plain; charset="UTF-8"

-- 
Hello

I am Ms. Maria Elisabeth Schaeffler, a German entrepreneur and investor
and philanthropist. I am the Chairman of Wipro Limited. 25 percent of it
My personal fortune is spent on charity. And I also promised to give
The remaining 25% will go to private individuals in 2024. I have decided to
do this
donate 1,500,000.00 euros for you. If you are interested in mine
Donation, contact me for more information.

You can also read more about me using the link below

https://en.wikipedia.org/wiki/Maria-Elisabeth_Schaeffler

Greetings

Managing Director Wipro Limited
Maria Elizabeth Schaeffler.
Email: mariaelizabethschaeffler44@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnMvBU-WYAVU42qzGNJAo9UxFakAqXucowbhiamFz_%3D9tdiAA%40mail.gmail.com.

--0000000000001ff2590622f7e6a1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><br></div><span class=3D"gmail_sign=
ature_prefix">-- </span><br><div dir=3D"ltr" class=3D"gmail_signature" data=
-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div>Hello</div><div><br></=
div><div>I am Ms. Maria Elisabeth Schaeffler, a German entrepreneur and inv=
estor</div><div>and philanthropist. I am the Chairman of Wipro Limited. 25 =
percent of it</div><div>My personal fortune is spent on charity. And I also=
 promised to give</div><div>The remaining 25% will go to private individual=
s in 2024. I have decided to do this</div><div>donate 1,500,000.00 euros fo=
r you. If you are interested in mine</div><div>Donation, contact me for mor=
e information.</div><div><br></div><div>You can also read more about me usi=
ng the link below</div><div><br></div><div><a href=3D"https://en.wikipedia.=
org/wiki/Maria-Elisabeth_Schaeffler" target=3D"_blank">https://en.wikipedia=
.org/wiki/Maria-Elisabeth_Schaeffler</a></div><div><br></div><div>Greetings=
</div><div><br></div><div>Managing Director Wipro Limited</div><div>Maria E=
lizabeth Schaeffler.</div><div>Email: <a href=3D"mailto:mariaelizabethschae=
ffler44@gmail.com" target=3D"_blank">mariaelizabethschaeffler44@gmail.com</=
a></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOnMvBU-WYAVU42qzGNJAo9UxFakAqXucowbhiamFz_%3D9tdiAA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAOnMvBU-WYAVU42qzGNJAo9UxFakAqXucowbhiamFz_%3D9t=
diAA%40mail.gmail.com</a>.<br />

--0000000000001ff2590622f7e6a1--
