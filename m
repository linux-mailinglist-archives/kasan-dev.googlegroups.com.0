Return-Path: <kasan-dev+bncBCXNRKX44UEBBH6USCQQMGQESXK45EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45C536CD91E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 14:08:01 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-54629ed836asf12968117b3.10
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 05:08:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680091680; cv=pass;
        d=google.com; s=arc-20160816;
        b=sJ6bhU8cTaN6dPwb/xxU7y7yAIDiihLbBKUAxzPtxQfM/V6ooP2iHB7C8sEz+gOyu3
         D1jSGX/69LazRaChw3cKkmgVNZi+d9auhARkv/vBUrmqV46uLFy7qYBjPQbwE+ROLzIl
         92QAxOfBEHWfTNhl9/s2IEFWSQAuYNT4KXIIBAKG/0DYrTKgawIMx9JfVYa2N3pfHW+D
         3ZcSL3fdzMRKL2GEve3nfZBWYYSegy5k7M/zJH4JlZm78N7W/Lbqat1S1ycU7rWFJWTb
         ulreWAjx7hJNaMrELBK2XVE3l5dqPglG213YfhH7hQFeUObVojiMiPdUKP+NNBOEBcuA
         /Wew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=jUdjSDY5AvczWmcXg0wTz+QxUL7Sb/H390CAuTiAXz0=;
        b=vkhaOqZtw/acfI38OaU0kquXsInv/zAGoDGzw+oQQyk4uxezaP/guPqwbjsdRxWNAI
         pWwL29xB26c5H0uoM8VayayLIgDKLY95aauh9gYaBhWmHlMhcdtK1LT6FrMCpoykQb28
         FRqHpn5YmUoSDJcVnBf861FdmOJWmPuYwOApwlzGz0WrBxYtygVgGr+huS6URM4dK2Ns
         aZPbBg0ESWJI9YGJxt4wAy0A71iJh6s/KQxG/02iJbhkWupNmnT3DXlIym+skIoaR7L/
         b2uk1TRqNV9EFV80I7vFIVfXOiDWS1CA8WzqGWKXxLQj6JIj8FYYbrQdz8ggocMTzuaS
         fYHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YvOEIfGQ;
       spf=pass (google.com: domain of dodjimensah29@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dodjimensah29@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680091680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jUdjSDY5AvczWmcXg0wTz+QxUL7Sb/H390CAuTiAXz0=;
        b=dMIMbbr9PGizNDgZ9fETLfRSCLb4GIBq8zyYj2OFRD9HGl5SAdZvxOjPrV4orGRh+O
         L/gawunfroKU4O0exdGhRdP7sZVJPJdhMmdF60aEVO9EkibR9iqgc3msH9JxtywnZd4l
         PjgtIpXCFV2RzAA7BY+UMVcQY5py8yyMgphMJoAwY3YqqcwBhimFQP8PbQQH9H2jdaSd
         DDBwn1MRD6JJKYrUC23zGCLz/EDkxfSVc1/s3HcIB/bI5y3RyHBn4EMGB1T57+ioh1y9
         /y2k3qodB4tajHvwhNv9UpCR33WgpiCnqjr9Agf+W7KXVRRGPaPdwqxmjQnRJQgP4M1n
         29ww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680091680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=jUdjSDY5AvczWmcXg0wTz+QxUL7Sb/H390CAuTiAXz0=;
        b=ObUbXXX1jOVXrQmN+KckWC/oFvNL+d/12DhLJOxlMw7f0yRYjIMPuQ2VSd8s47u7Aw
         uIPLLZYlDPIlUtlx6dUm1tyUsFIf2X0h5Q7eVc4ZdkwgJPo9BeoQzcV6APHE+NB776MJ
         iUgmgN6AoQ1g4VkLBvW1pI8lDGGsaL0f/hFafethgj1BQF/KRgwHqUBre2rOozeGQxWG
         ECDXSQjkT5mwTRFd/3m5BjpCSDOqf5E3znkTamJwljx4WHewyOOPVlUcqLTS+Nyxurp8
         eWy6ElgjdtviKIzXeAj4oHM6ZuW/N0y9ZlVAR96HnRuyojwn6aD/gmtdeb4fUV1Vu4kP
         DF9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680091680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jUdjSDY5AvczWmcXg0wTz+QxUL7Sb/H390CAuTiAXz0=;
        b=3e2TT+x/z41WZBcRVWolIn6Ix71RbI5Q5qklSML0u9hxO99rd1nqsKCWjZGl1ZaNs0
         uo2i8hLuIhw3kt9RqVFXlAiUBFyJhaJXUT3aZ906T6OBxJK+xzS7XXZRRkv2Bx9QB4uB
         C8iFu+OBePmrWgfxst0J3Yv8pnUF9JCcBl5FveFIW7mR+X8VJNdqCLt9silAB0OXUqxN
         /sdztW6KOT6dw3oM8IFpzOqtaFDUn6lXFcbSIl5u3hI+PcFF4ydfv+RCSYzXth9kIlk2
         5cJFrJJ0FLug1WAcBN8b/2FM6AwTBT0Z33x5Cl/6Ln4/k9JTbz9PA+STyDYAxLMMe8qy
         ANzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eNsKYRaJZV9tSYF+h41yo0gTYIACisx/vhnKgYPWI85hOMpVT4
	4b1aK07V32ke/cZ//s7SZZ0=
X-Google-Smtp-Source: AKy350bh+UG5phZBWMZmg4KYz6fZS2eYpkme4VMK73jVcFTzWT4LYRcMr09w9pThQP3pNhWli/YwsA==
X-Received: by 2002:a81:b388:0:b0:545:8202:bbcf with SMTP id r130-20020a81b388000000b005458202bbcfmr8759215ywh.9.1680091679672;
        Wed, 29 Mar 2023 05:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a202:0:b0:b7a:4d20:a84f with SMTP id b2-20020a25a202000000b00b7a4d20a84fls6564839ybi.3.-pod-prod-gmail;
 Wed, 29 Mar 2023 05:07:59 -0700 (PDT)
X-Received: by 2002:a25:5188:0:b0:b68:3e9:385c with SMTP id f130-20020a255188000000b00b6803e9385cmr15263107ybb.27.1680091679084;
        Wed, 29 Mar 2023 05:07:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680091679; cv=none;
        d=google.com; s=arc-20160816;
        b=fLKyujT3ue3KtVU0mB08ZKvlrom6sdl3FZCFTL2cp3VbnHMLenpEktYfaOPleKlIjE
         JjXLYnOeE9z50ZsLp120P7+1u3N59arGSTIsHoS7SK8T163vV0Djyjvs/vO5XbXX6fEF
         BBqGtY2Nm/ci/CTboeBhS9TwHigY0oI/DQKkauSD+N3D6017z8Qmp1jhsJZOjGbNCMYW
         l+7aHqly1BFWDBrpmcoM2uGxBxJnEhTGaMRhWqWatWgh6xwb/zCJKR1ectBxBgOf6Eeu
         MC9U6oBClceXdoNh+1jfIRe+Mt/yzMMGmFk4tL9Pn1WbBDewCUnc6x9IrEGI5PExThRU
         Ruxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ZbzaHAVZeMShqiYn99yjSUsQ/zI4NPCuBWPChDOTNF8=;
        b=E8eqQQ/BvT9DvRRrwxwQpQOL2uAK7pX/oKm9milWpgpsgaqdl2ZCneU6Aj/S8HU53Y
         uNQNNl/3x9ubCX7+EvoxA6qt5PIFHyVE1NMo9Sgt83A5be4vy9NbwRSuvpuAFjz5tAb4
         ABu8VPWYw+mjegzLlGa33tOTWn53EOegmQ4s6wLwfwnJpiFAkHqg8pTuBk7k6zMMTYFS
         +TzkbFBNDFZYx7+pyvYmXxQBJElPfQlpWE29NY9RgxcJKmRvOtsQiLGZZhCllTHTqizd
         ejWalZWmYRGPar7bHOXKj0ekVlbSFyFVwWU2PP2CWcuresCO5yok6pYSpPGve1kU2BQ/
         F0xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YvOEIfGQ;
       spf=pass (google.com: domain of dodjimensah29@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dodjimensah29@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id q17-20020a25bfd1000000b00b244fd21bc6si1998706ybm.3.2023.03.29.05.07.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Mar 2023 05:07:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dodjimensah29@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id f6-20020a17090ac28600b0023b9bf9eb63so15911430pjt.5
        for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 05:07:59 -0700 (PDT)
X-Received: by 2002:a17:90a:600c:b0:240:9d66:cd54 with SMTP id
 y12-20020a17090a600c00b002409d66cd54mr1888126pji.8.1680091678295; Wed, 29 Mar
 2023 05:07:58 -0700 (PDT)
MIME-Version: 1.0
From: Dodji Mensah <dodjimensah29@gmail.com>
Date: Wed, 29 Mar 2023 12:07:32 +0000
Message-ID: <CAL2UYuSD319UcvsKX563qXUEtsOvT7DMG-cWbdd1A2xza9gORg@mail.gmail.com>
Subject: Private Contact
To: Dodji Mensah <dodjimensah29@gmail.com>
Content-Type: multipart/alternative; boundary="000000000000accc3805f808d331"
X-Original-Sender: dodjimensah29@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YvOEIfGQ;       spf=pass
 (google.com: domain of dodjimensah29@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=dodjimensah29@gmail.com;       dmarc=pass
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

--000000000000accc3805f808d331
Content-Type: text/plain; charset="UTF-8"

Attn: sir/madam,

I contact you for an important issue that will be a mutual gain to us both.
I am the son of the late Edoh Mensah, the famous Gold merchant in the
republic of Ghana who died mysteriously few years ago.

I am willing to expatriate the proceeds of my father's account overseas,
for security reasons. A total amount of USD $ 3.6 Million, in one of the
banks in Togo by my late father. I need a foreign partner, honest and
trustworthy who can collaborate with me to get these funds transferred out
of this country. You will be entitled to 30% of the total funds as
compensation for your assistance.

With due respect, all I need is your trust and total commitment, to ensure
a safe transaction.

Sincerely,

Dodji Mensah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAL2UYuSD319UcvsKX563qXUEtsOvT7DMG-cWbdd1A2xza9gORg%40mail.gmail.com.

--000000000000accc3805f808d331
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">


















<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">Attn: sir/madam,<s=
pan></span></span></p>

<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">I contact you for =
an
important issue that will be a mutual gain to us both. I am the son of the =
late
Edoh Mensah, the famous Gold merchant in the republic of Ghana who died
mysteriously few years ago.<span></span></span></p>

<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">I am willing to
expatriate the proceeds of my father&#39;s account overseas, for security r=
easons.
A total amount of USD $ 3.6 Million, in one of the banks in Togo by my late
father. I need a foreign partner, honest and trustworthy who can collaborat=
e
with me to get these funds transferred out of this country. You will be
entitled to 30% of the total funds as compensation for your assistance. <sp=
an></span></span></p>

<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">With due respect, =
all I
need is your trust and total commitment, to ensure a safe transaction.<span=
></span></span></p>

<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">Sincerely,<span></=
span></span></p>

<p class=3D"MsoNormal" style=3D"text-align:justify;margin:0cm 0cm 10pt;line=
-height:115%;font-size:11pt;font-family:&quot;Calibri&quot;,&quot;sans-seri=
f&quot;"><span style=3D"font-size:12pt;line-height:115%;font-family:&quot;B=
ookman Old Style&quot;,&quot;serif&quot;" lang=3D"EN-US">Dodji Mensah<span>=
</span></span></p>





</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAL2UYuSD319UcvsKX563qXUEtsOvT7DMG-cWbdd1A2xza9gORg%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAL2UYuSD319UcvsKX563qXUEtsOvT7DMG-cWbdd1A2xza9gORg=
%40mail.gmail.com</a>.<br />

--000000000000accc3805f808d331--
