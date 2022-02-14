Return-Path: <kasan-dev+bncBCFMFUMV7UORBIXNVCIAMGQEJENMQEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 693374B4CC5
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 12:01:55 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id j17-20020a25ec11000000b0061dabf74012sf33099402ybh.15
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 03:01:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644836514; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ycc9klYaRdBr9bhyciin5Hx/YWlT1IZ5/w1tOuXYb5f/EfBy03DuWI3gL0NKK4H+i9
         UlCQZiiIBNqtjQvlyI36j+EIydjFYSCdBAAVLksGw76pKwfN/iB0dISNDRseZGbiE9N3
         AWGxTY9m1wycV6js7OR16eObGe8YjQJGKXLetbakmL2HD3IbdWrKsoOwHXusvwqyb5UJ
         HtR2W6Sk6v3eh6ecCruZOBU4AAwR+zF1Bn12Rg3kQyAOB/bxg8JzWGBgkykG0wUyvQLI
         1CBF8Yk4NZPOdWNH+N+EM4LHLLNxwSCaZRokxgMdvV8Q/ftW9TYbw4n8egWcbcy/G+ah
         Hgww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=u3I/bE1f+C52MmGPiiPoKEsjhMt04Eivk2ONFtOK6/Y=;
        b=IMnb+7+fchDZZz4p1zhlCDUkXWmyBneDieQpeGYQHCG4IJrVZ+KK8WpudJQG+AR3Sk
         Jz92UXu3QxTaPFZVnjMjlv4CupIuITWEhDfXXmBdnm3y65FIth7ZuxZ31ndRUE/XOsEa
         g+c+e20j3xX47VYabwiVSRFTLtR99RkVz+ryUx25ysHtNjxa+uJKmyxI/6nod6iMY58m
         rLT3T/8MNzlbRfFylaLJw3H9NDjEBmB0m+S/lghq7n+4DA3mcEPMfvaOX8QZIMlnK1mE
         QYmaRXFuBgtkcSbYUwJeYe4k8JxjgHElK+RJnZYd8ek6TjArHJWtKvUKSiEy6SxTGkyK
         jf9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=p4N+qMPg;
       spf=pass (google.com: domain of koffakoffi3@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=koffakoffi3@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u3I/bE1f+C52MmGPiiPoKEsjhMt04Eivk2ONFtOK6/Y=;
        b=btOlBY8505fpohEEt+4BmbvObt7DUw+TsErrhM3HcjrVbpaGJjOXWXFUTYj52lALMZ
         Tz4MIUXHFAyesjJIdMnNMn6sjCg2iNfwXcEnrKFYkEje5rjiLQarbtLpkEcY4ngj1/KU
         OFf9+kpxYdlUWLC7aCYgAHhVcET4qcoxOEqpAM4tecTMwVuqVzYJs6JLBeNWjkKd38rM
         7LJq8/8NVnKKrHSm+SmdlYcg1mzBo5xkxDNJRNZy6SdXS+ZZVjeIONpoTmDYkJWr92pT
         cR+1Pzm20ocRhPwcLpoap8APB8mIjOIWZF0OmGrohhS47JqkpPJBXhaZmEr0qiT4ajfN
         CFnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u3I/bE1f+C52MmGPiiPoKEsjhMt04Eivk2ONFtOK6/Y=;
        b=qvmq8+zu23T9weWLy/05lAwbmczNB1uHcez2U9UYFL7vKM+1B0sib+kyr6Txy9104a
         8c3+bKUlekeiKpngV1i2l98dE1RTJnB4zAOvowFPi6OfH5TdOAqW5MYyfQqv9Fd41nCw
         R5KuU45aA4PLyh+Kk99pT39niUeKZwDb5LpFKvb+yJ1AsuJ+OoIdoPmB//k4GhVJhUip
         38D/TTsjxMh52qgyTF2qpOr1VvCWDFx25nlRBQlk9DrWxzN/di86t9m54FGBDe0Gui+P
         GC6iKKHz/ofoxpGOgNf4C1G+l+DJrh2bYhU/K6lhQoHhp3jUqjibnoewQboNek2kHIod
         qF4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u3I/bE1f+C52MmGPiiPoKEsjhMt04Eivk2ONFtOK6/Y=;
        b=qGUCngXqtbCUhcT8rgP+V97LHR6BFc5gtJXs7eZDe9RmNw1vx5qwR3TVrMdyxkycYK
         Fup29AxtsMLYWWLHlBret6+4O0tFsI0jLC+FrSXCM6mk8YEhygBWvHr3vBTAo4ndpXxX
         OsAKHx/oqQr+II+/rz5j0V/XfLuoz0bQqBMZQ6Xzsz+N02O21BooVrnF+4By5RuEvjIs
         yKR01FnJy2HM6cldwzO+KSKGN07FNbd3HdTWK+OuEUwXyRHltbOrriJCyJf9QxqYUBUy
         CQ8/hYctHY+ZOG8pXXEaxrHVVtiGaHcAXOvvjIKH2UDd5N65Fp9+tV5pn3XbkgBeDZQw
         Zv6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FWFpyUISqOfUf7lLxPEPhB7V7GR4ylA1mmf1di1iuFgeKmAjT
	bjrtuncKHm6SAAgDlHWMlXs=
X-Google-Smtp-Source: ABdhPJwG/4Rtya9MBQbncezmSDUVk0Xb611Z4qvwaXJ4hQXMNRFi9cVWk0gYTVzPZpNbLO3MgD48+w==
X-Received: by 2002:a81:e544:: with SMTP id c4mr13574892ywm.439.1644836514281;
        Mon, 14 Feb 2022 03:01:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:84c5:: with SMTP id x5ls3152604ybm.4.gmail; Mon, 14 Feb
 2022 03:01:53 -0800 (PST)
X-Received: by 2002:a25:2cf:: with SMTP id 198mr11328262ybc.349.1644836513816;
        Mon, 14 Feb 2022 03:01:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644836513; cv=none;
        d=google.com; s=arc-20160816;
        b=Qfk2qKwgKp9a4ms0P1BsXsONA1EAP8KAKes3h9PuYJFOZqOXlYK8vt9z2U+zXlwpI7
         dsphjoFLf5Rfu1tr3vTHCZa6P7G+ZEs7grPK3u3iX4z3+NYHX3KPWAQAxZYU8VoEQafO
         GKrh8kvXsz8a32YABdf3aJhUpcafpNBq+rdySYKXpgWRGm5GV7YiiJEJfzK65sMPSUel
         0KcovolddCygY/6nPf5WfOPYEFHdQrWQbJYbCVmuO7dR9ubf7KgZ7JF9pHl6COj15rG3
         GGDHHmAKB+fUV1BoAjcNTeu5XRgw4/0NptAeHgt+s+RU0gdhw0GdXDaxcuu2/4+VB9JI
         46Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Zzq1az6V6eRD5hU3LMHQW9s2baLIgsbDgfhUY9nSOIw=;
        b=QCdpN5BvRF7ycHvW18vcS/MNfbHi/lE2ZDP8N8sgorhR+n+CcbTkPLeeGIR8nVJmRM
         BjWeIjiMJfnvBXOxlT8DGm1SeJ7nllO/QQdo7OFZ+om6tSF/iwLJG4WGISZtASiyVdT/
         PWJVxjH9yRpgDm9xM4rvsb7hSpOc5w2+cD3yyRftpmcZQqhX/NBLQ+uTQkG90HQLqAnA
         ethfic1yBsKQhz+IRQ2ggt/ZHGa1lCzk47yPRRdF/aXTcI3FVwxPfRehSlQH1TodcF64
         sVgaxSFpAQ6vroVEVydeuo2J7xH17T9F/FxYo04gvLtymAYWIZzD5X8yZDhYL7sriAxz
         M6mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=p4N+qMPg;
       spf=pass (google.com: domain of koffakoffi3@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=koffakoffi3@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id n63si1058167ybg.5.2022.02.14.03.01.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Feb 2022 03:01:53 -0800 (PST)
Received-SPF: pass (google.com: domain of koffakoffi3@gmail.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id l125so11712924ybl.4
        for <kasan-dev@googlegroups.com>; Mon, 14 Feb 2022 03:01:53 -0800 (PST)
X-Received: by 2002:a81:ce03:: with SMTP id t3mr13123280ywi.413.1644836513663;
 Mon, 14 Feb 2022 03:01:53 -0800 (PST)
MIME-Version: 1.0
From: Katie Higgins <higginsn769@gmail.com>
Date: Mon, 14 Feb 2022 03:01:42 -0800
Message-ID: <CAHfRN=7tBSpwyyE4DyWmyAzGaMaFgmHvzoUYn=seDVXDzUizaw@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000001c500205d7f8587d"
X-Original-Sender: higginsn769@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=p4N+qMPg;       spf=pass
 (google.com: domain of koffakoffi3@gmail.com designates 2607:f8b0:4864:20::b35
 as permitted sender) smtp.mailfrom=koffakoffi3@gmail.com;       dmarc=pass
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

--0000000000001c500205d7f8587d
Content-Type: text/plain; charset="UTF-8"

mijn naam is Katie, kunnen we alsjeblieft praten?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHfRN%3D7tBSpwyyE4DyWmyAzGaMaFgmHvzoUYn%3DseDVXDzUizaw%40mail.gmail.com.

--0000000000001c500205d7f8587d
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">mijn naam is Katie, kunnen we alsjeblieft praten?</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHfRN%3D7tBSpwyyE4DyWmyAzGaMaFgmHvzoUYn%3DseDVXDzUiza=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAHfRN%3D7tBSpwyyE4DyWmyAzGaMaFgmHvzoUYn%3DseDV=
XDzUizaw%40mail.gmail.com</a>.<br />

--0000000000001c500205d7f8587d--
