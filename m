Return-Path: <kasan-dev+bncBDP27Y72SUJRBCEUWTXAKGQEIQ4UDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC9DAFC110
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 09:02:18 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id f7sf3344171plj.12
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 00:02:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573718537; cv=pass;
        d=google.com; s=arc-20160816;
        b=OGUpOrBOowrBftDaucXfgPsJo09wL3IyAfDqSUs7/062kBi9R9eHB6EvUprnuXKkgs
         okiCCxMPmGJF6qSLv6Nq2vyTElEpjddnABQBDK/D4rpZ7DyWJQ7VyfxsjYWzAEx6Jnif
         181i93nLrVF1ZE+QYQFQsy0WCuZs79Nmj1tfDTzXLhx7BTi0tdVz90F+TqX6mpi+3+kk
         G3Klt27ZJtNRjWmYq+5NhSf8eIhwkQtR4GUgzTyvESGlQBvuE8HFpwTieiaekyZCyklf
         GvIPvpbeGrPxLgoATbg16ObSl5hhg9F2MkbM7sp9q6eiZrq6gbjvfrW3W6+Q0Ej7qeT2
         JREQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:date:message-id
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=MhhR94+XDi6Gmy6q+rDfr3BlI0jZqCoqYDFGfAZhkxI=;
        b=JYiHgIN/1WBatEgxNpXOGO2yiImHkcVlY2RMh1C1HoaYA1tidYl4l+XDYBZILIaFGT
         ayltoIiBnemyPxBwVQFEQztcojN6JSPt6QJLer0S2JAMWy3X6SfiF1diF52SzjL8AFw0
         uSf2eyXdkBjhjmH6+m2kIqALKmNe7kKP8vlQM5a+NsaVBgMlPWR1+IQQ1Z2ct0hxL1RK
         Ni7o+nkHdkVqZsec/VZ83YLWZIrxFZXr4jWL1lo53jQAKbgHjbE9LGR5mkZ9ejwPWyxW
         jl0/yMcigZiJrgtHteSEJQbUYlIyML/3Zpb6rU5Qk4ZYXIaHgnHT80u8320WAfNtb+WF
         KyxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mQ14IHoY;
       spf=pass (google.com: domain of 3bwrnxqsjcuqottgz6a69ebmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com designates 2607:f8b0:4864:20::d47 as permitted sender) smtp.mailfrom=3BwrNXQsJCUQottgz6A69EBmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MhhR94+XDi6Gmy6q+rDfr3BlI0jZqCoqYDFGfAZhkxI=;
        b=YPd0fyg7Wtc5hkfi8Kncd8Ni+d8DEWNp/p+z5K2cMKt1VBLSmTjxLMN2xL9gtjkrj5
         6d0T4BOzHG4yg5t67fU+I05Kw1VWFlCy78JkBoF2SO/xvtntdW7QP+YGBem2R9kDCgOX
         1+/OPz9sKDHgol8Ou6TJgu7H14ANW3MqaioZYwg0hHkJ8CnQvMhc36JE2BCx+KJAuREg
         mxjpvMNvpD/+p95Vz7lOP0jOy9TGyxNm8ZhsvbddRO8yiLZ7XmU3f0ZyW4uLKZuFA8HQ
         0gLOdSd4cKNj/5Vmx5XbHx46sr3vewGKI8cuJ34ln3JBQPWvuDs7HEZ3OHhOTuPTL1ax
         s5nQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MhhR94+XDi6Gmy6q+rDfr3BlI0jZqCoqYDFGfAZhkxI=;
        b=CjCStjUmuYjLcCQrm5HZmGyo5wTPapR1i91LnAFH7OTixAfQt2rDOdkg0xJ9hLpsCw
         ifNFjNIiHJLEjsxLATrc44ACaO1tjCBKcsVcCMRgQTPuovc2oUSJzbIis//qsDtJwde9
         9jP4pMLVDsXFsuOXQGOe144aOyuOksTys5y4olp+IRocmYdpawtileYyGJpifsmhIp8D
         QyzGRdNAVhx3k38qfXevSM8Pg4ZENTKitwkJW4VALxkVcnGzfcHLrbmTcDxh/KqOQX+g
         ITVDyhUMlpnGWfwDu3ttwnzHWKrBckjNO4vu7APN1taNwi8l1WkxR8S6bMVG5a3A8r9E
         CW+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:message-id:date
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MhhR94+XDi6Gmy6q+rDfr3BlI0jZqCoqYDFGfAZhkxI=;
        b=dmbC/kAbkb6Z7vcWz2zFObZXXDH1iyeln7kr5SNZQTyfdnaDhJOBJfRWtzuB8WJsI+
         BCXO+4U5qntB8nCNVPbb2U2ERIgA4HN4lgjRoL799zzwgg+2EwrfLVMirypdnzsS8Qnd
         1Z/3ak/Zi7xREVb58CZlXsL42QZlpqY2r+nneUADh9LFvTC1cT+uYtZcJ8+V3VCwBgMU
         3SoRKVCMQxYHLWX7KxwpvfzWZqqy/kNSyVAQAdcO0vLKEie+AMjZ9Vf9nTzghecXevPI
         ZffDzQH53Ya5VARSkMc+1Blj4hQeeAHsdZlJIlEzw3xye7KUzlOpqHbeg2HMTvutTwoy
         5HhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW8FCFkU14mx0lDPsapWJeyCnnPPA4w/BaUXkrI2bchk/ZdV/mj
	Wf/cSvRiqkk0o0xCg2dEY6k=
X-Google-Smtp-Source: APXvYqwLhngYvs0ZxLs31Ypj9WhZ/mcZSzLBhnQ0v666SwmlZcW8yrFaUFfYfl0/CiMuuKIdchvR4Q==
X-Received: by 2002:a17:902:7d8c:: with SMTP id a12mr8152260plm.221.1573718536578;
        Thu, 14 Nov 2019 00:02:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2cc3:: with SMTP id s186ls487024pgs.13.gmail; Thu, 14
 Nov 2019 00:02:16 -0800 (PST)
X-Received: by 2002:a63:d0f:: with SMTP id c15mr8721350pgl.313.1573718536074;
        Thu, 14 Nov 2019 00:02:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573718536; cv=none;
        d=google.com; s=arc-20160816;
        b=Agqjb6Z/cPDi2nWog9VAGENOwEBODZ72CzYzFPTnoIeJRguCf5grzQJLZ9y5yMZXih
         A//dcQjBwiA8psCCi48+5OUSlWIl0ByF2cTBpB+CDKwRESsE7+UnAL4aqQw10krDu4LQ
         HxqEkt2U3AUPNsUIHglfErUCmnS5a5XZ9eJiFK6dckHQg2OueDpXZcsg/2j97LqHguxb
         xHuEVrOtruJKNMBG190gQ4MFatlcydQZL+woaq/GEaCwi4oINnKm0ICbDZYlPfsunkGt
         9n+hgJjS8eBrkXVWIMb+/HQ9A9LiJHEXZnckFzN+eGHkjER2PlAcWGjz0Keivs28Hbez
         QvSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:date:message-id:reply-to:mime-version
         :dkim-signature;
        bh=pYbVkrEfsFQraJawLxuF+3h0YpXyZpLHv3BjKbB2pxY=;
        b=hXP8laG1/3oUb/OjFH6FQiXz1uArOH4ObDxzj08ksAJQtfqRW49fuqvjjVKxwMePsF
         53vHqtZsjRiUWa4pT/phBBDveKq5JEkfJHNID/ZsQtXpuCraJz2JiM3ggQ6Y0bghzJ3/
         AKryeHB7uGAnsmhyazhhcr9Pxg/HoalRikJjKNh6B1Z8OhguAYpSpi8R/G8G34q5Nckb
         7KGH/4ijFIvWogJKaR34tD8WejP8cVDC335MIBa8JozdOy802KfwrWSQ3cttPltZ6dnr
         fHDic14XzZyooKXhb1yyRALH6jnSPvasu4nygorkps8WTVOgNmqnsRnMMfipxSjMqjZI
         YpsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mQ14IHoY;
       spf=pass (google.com: domain of 3bwrnxqsjcuqottgz6a69ebmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com designates 2607:f8b0:4864:20::d47 as permitted sender) smtp.mailfrom=3BwrNXQsJCUQottgz6A69EBmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd47.google.com (mail-io1-xd47.google.com. [2607:f8b0:4864:20::d47])
        by gmr-mx.google.com with ESMTPS id w63si193113pgd.2.2019.11.14.00.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 00:02:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bwrnxqsjcuqottgz6a69ebmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com designates 2607:f8b0:4864:20::d47 as permitted sender) client-ip=2607:f8b0:4864:20::d47;
Received: by mail-io1-xd47.google.com with SMTP id z1so3425999ioh.11
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 00:02:16 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a5e:a70e:: with SMTP id b14mt7278655iod.166.1573718535549;
 Thu, 14 Nov 2019 00:02:15 -0800 (PST)
Reply-To: innat040385@gmail.com
X-No-Auto-Attachment: 1
Message-ID: <00000000000049bb78059749e631@google.com>
Date: Thu, 14 Nov 2019 08:02:15 +0000
Subject: =?UTF-8?B?ODAl55qE5r2c5Zyo5a6i5oi3IOmcgOimgeS9oOS4u+WKqOiBlOezuw==?=
From: innat040385@gmail.com
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="0000000000004a2d3a059749e6d7"
X-Original-Sender: innat040385@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=mQ14IHoY;       spf=pass
 (google.com: domain of 3bwrnxqsjcuqottgz6a69ebmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com
 designates 2607:f8b0:4864:20::d47 as permitted sender) smtp.mailfrom=3BwrNXQsJCUQottgz6A69EBmsgor.iusqgygt-jk1muumrkmxu0vy.ius@trix.bounces.google.com;
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

--0000000000004a2d3a059749e6d7
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
Content-Transfer-Encoding: quoted-printable

I've invited you to fill out the following form:
80%=E7=9A=84=E6=BD=9C=E5=9C=A8=E5=AE=A2=E6=88=B7 =E9=9C=80=E8=A6=81=E4=BD=
=A0=E4=B8=BB=E5=8A=A8=E8=81=94=E7=B3=BB

To fill it out, visit:
https://docs.google.com/forms/d/e/1FAIpQLSd2aCiskQhBWacX9izlNtjnWEKv83nRs61=
8c5r7lV5YrfLurw/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;usp=3Dmail_form_lin=
k

80%=E7=9A=84=E6=BD=9C=E5=9C=A8=E5=AE=A2=E6=88=B7 =E9=9C=80=E8=A6=81=E4=BD=
=A0=E4=B8=BB=E5=8A=A8=E8=81=94=E7=B3=BB

Google Forms: Create and analyze surveys.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/00000000000049bb78059749e631%40google.com.

--0000000000004a2d3a059749e6d7
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body style=3D"font-family: Roboto,Helvetica,Arial,sans-serif; margin=
: 0; padding: 0; height: 100%; width: 100%;"><table border=3D"0" cellpaddin=
g=3D"0" cellspacing=3D"0" style=3D"background-color:rgb(103,58,183);" width=
=3D"100%" role=3D"presentation"><tbody><tr height=3D"64px"><td style=3D"pad=
ding-left: 24px"><img alt=3D"Google Forms" height=3D"26px" style=3D"display=
: inline-block; margin: 0; vertical-align: middle;" width=3D"143px" src=3D"=
https://www.gstatic.com/docs/forms/google_forms_logo_lockup_white_2x.png"><=
/td></tr></tbody></table><div style=3D"padding: 24px; background-color:rgb(=
237,231,246)"><div align=3D"center" style=3D"background-color: #fff; border=
-bottom: 1px solid #e0e0e0; margin: 0 auto; max-width: 624px; min-width: 15=
4px; padding: 0 24px;"><table align=3D"center" cellpadding=3D"0" cellspacin=
g=3D"0" style=3D"background-color: #fff;" width=3D"100%" role=3D"presentati=
on"><tbody><tr height=3D"24px"><td></td></tr><tr><td><span style=3D"display=
: table-cell; vertical-align: top; font-size: 13px; line-height: 18px; colo=
r: #424242;" dir=3D"auto">80%=E7=9A=84=E6=BD=9C=E5=9C=A8=E5=AE=A2=E6=88=B7 =
=E9=9C=80=E8=A6=81=E4=BD=A0=E4=B8=BB=E5=8A=A8=E8=81=94=E7=B3=BB</span></td>=
</tr><tr height=3D"20px"><td></tr><tr style=3D"font-size: 20px; line-height=
: 24px;"><td dir=3D"auto"><a href=3D"https://docs.google.com/forms/d/e/1FAI=
pQLSd2aCiskQhBWacX9izlNtjnWEKv83nRs618c5r7lV5YrfLurw/viewform?vc=3D0&amp;c=
=3D0&amp;w=3D1&amp;usp=3Dmail_form_link" style=3D"color: rgb(103,58,183); t=
ext-decoration: none; vertical-align: middle; font-weight: 500">80%=E7=9A=
=84=E6=BD=9C=E5=9C=A8=E5=AE=A2=E6=88=B7 =E9=9C=80=E8=A6=81=E4=BD=A0=E4=B8=
=BB=E5=8A=A8=E8=81=94=E7=B3=BB</a><div itemprop=3D"action" itemscope itemty=
pe=3D"http://schema.org/ViewAction"><meta itemprop=3D"url" content=3D"https=
://docs.google.com/forms/d/e/1FAIpQLSd2aCiskQhBWacX9izlNtjnWEKv83nRs618c5r7=
lV5YrfLurw/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;usp=3Dmail_goto_form"><m=
eta itemprop=3D"name" content=3D"Fill out form"></div></td></tr><tr height=
=3D"16px"></tr><tr><td style=3D"display: table-cell; vertical-align: top; f=
ont-size: 13px; line-height: 18px; color: #424242;" dir=3D"auto">=E5=BD=93=
=E5=9B=BD=E5=A4=96=E5=AE=A2=E6=88=B7=E9=9C=80=E8=A6=81=E9=87=87=E8=B4=AD=E4=
=BA=A7=E5=93=81=E6=97=B6=EF=BC=8C=E6=9C=8980%=E7=9A=84=E9=87=87=E8=B4=AD=E5=
=95=86=E4=BC=9A=E7=9B=B4=E6=8E=A5=E4=BB=8E=E8=87=AA=E5=B7=B1=E7=9A=84=E4=BE=
=9B=E5=BA=94=E5=95=86=E5=90=8D=E5=BD=95=E9=87=8C=E9=9D=A2=E9=80=89=E6=8B=A9=
=E4=BE=9B=E5=BA=94=E5=95=86=E8=BF=9B=E8=A1=8C=E5=90=88=E4=BD=9C=E3=80=82<br=
><br>=E5=8F=AA=E6=9C=8920%=E9=9D=9E=E5=B8=B8=E7=86=9F=E6=82=89=E4=B8=AD=E5=
=9B=BD=E7=9A=84=E9=87=87=E8=B4=AD=E5=95=86=E6=89=8D=E4=BC=9A=E9=80=9A=E8=BF=
=87B2B=E5=B9=B3=E5=8F=B0=E3=80=81=E5=8F=82=E5=8A=A0=E5=B1=95=E4=BC=9A=E7=AD=
=89=E6=96=B9=E5=BC=8F=E9=80=89=E6=8B=A9=E4=BE=9B=E5=BA=94=E5=95=86=E3=80=82=
<br><br>=E5=9B=A0=E6=AD=A4=E9=80=A0=E6=88=90=E4=BA=86=E8=AF=A2=E7=9B=98=E5=
=8F=91=E7=BB=99=E6=88=90=E7=99=BE=E4=B8=8A=E5=8D=83=E5=AE=B6=E4=BE=9B=E5=BA=
=94=E5=95=86=EF=BC=8C=E9=80=A0=E6=88=90=E6=AF=94=E4=BB=B7=E5=8E=8B=E4=BB=B7=
=E7=9A=84=E5=9B=B0=E5=A2=83=EF=BC=81<br><br>=E6=82=A8=E6=98=AF=E9=80=89=E6=
=8B=A9=E8=8B=A6=E8=8B=A6=E7=AD=89=E5=BE=85=E8=A2=AB=E9=80=89=E6=8B=A9=EF=BC=
=8C=E8=BF=98=E6=98=AF=E4=B8=BB=E5=8A=A8=E5=87=BA=E5=87=BB=E5=91=A2=EF=BC=9F=
<br><br>=E6=88=91=E5=8F=B8=E5=A4=96=E8=B4=B8SAAS=E7=B3=BB=E7=BB=9F=E3=80=82=
=E5=B8=AE=E6=82=A8=E4=B8=BB=E5=8A=A8=E8=81=94=E7=B3=BB=E5=85=A8=E7=90=83=E5=
=AE=A2=E6=88=B7=EF=BC=8C=E6=89=BE=E5=88=B0=E5=AE=A2=E6=88=B7=E5=86=B3=E7=AD=
=96=E4=BA=BA=E7=B2=BE=E5=87=86=E6=89=93=E5=87=BB=E3=80=82<br><br> --2513303=
521--<br>(=E5=8A=9F=E8=83=BD=E5=9C=A8=E7=BA=BF=E6=BC=94=E7=A4=BA.q.q)</td><=
/tr><tr height=3D"24px"></tr><tr><td><table border=3D"0" cellpadding=3D"0" =
cellspacing=3D"0" width=3D"100%"><tbody><tr><td><a href=3D"https://docs.goo=
gle.com/forms/d/e/1FAIpQLSd2aCiskQhBWacX9izlNtjnWEKv83nRs618c5r7lV5YrfLurw/=
viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;usp=3Dmail_form_link" style=3D"bord=
er-radius: 3px; box-sizing: border-box; display: inline-block; font-size: 1=
3px; font-weight: 700; height: 40px; line-height: 40px; padding: 0 24px; te=
xt-align: center; text-decoration: none; text-transform: uppercase; vertica=
l-align: middle; color: #fff; background-color: rgb(103,58,183);" target=3D=
"_blank" rel=3D"noopener">Fill out form</a></td></tr></tbody></table></td><=
/tr><tr height=3D"24px"></tr></tbody></table></div><table align=3D"center" =
cellpadding=3D"0" cellspacing=3D"0" style=3D"max-width: 672px; min-width: 1=
54px;" width=3D"100%" role=3D"presentation"><tbody><tr height=3D"24px"><td>=
</td></tr><tr><td><a href=3D"https://docs.google.com/forms?usp=3Dmail_form_=
link" style=3D"color: #424242; font-size: 13px;">Create your own Google For=
m</a></td></tr></tbody></table></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/00000000000049bb78059749e631%40google.com?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/0=
0000000000049bb78059749e631%40google.com</a>.<br />

--0000000000004a2d3a059749e6d7--
