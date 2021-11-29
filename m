Return-Path: <kasan-dev+bncBDHZBAGJ5EHBB4HXXWGQMGQEKVWS7SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 565E246BF2C
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Dec 2021 16:21:21 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id h20-20020ac85e14000000b002b2e9555bb1sf17840382qtx.3
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Dec 2021 07:21:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638890480; cv=pass;
        d=google.com; s=arc-20160816;
        b=U0S9w8qJDmGHF8LZ5esV7XwZ57qWOfnE1kMZhozvfwpjo7RhAL76OOnYAp4maMpt27
         4sqaO2Stj4ZHHlyWJ2YfrvNe4vx54x+/obTftcssg6E6s2gdrcVfkK0D+xvAvmbybxcg
         pxmlETACfw81zYG2a5NGeCVWqpXlWCKyBoqtkY2RHtDkIpy5EWuIiuJYFeJ3SoQTq6pD
         mI8+WyEtN8DtYlJoBYxLFUGOgA/B6CtK2T50ZprZHuhZLEBNBJU2gAW4dJk+r14PFdvy
         /Sn0wt1QLIE2ZN8GB9FwWc0vKjvdHDecWQgMnbmMKBG6hulHz8dvOjL23/5S9YcWBEmP
         vbNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:to:from:date
         :sender:dkim-signature;
        bh=HGYO1F5kiQkdt1aYc2x+IEMv2gsAHqE2vTPFaXOi0+0=;
        b=ASQiyyqlqiFu32QbSLywqUIXeD/wuj7nbXFn2r8w/lwPK3vGTOFsOnVv5s+nfqr6fH
         fBlXupiRVil4eeBvZQfljBvYwI93F+33ODKZOxjYRfo0RdtSi60HhECJK4Yf9rQdokU0
         B0lg88cUii+6FPX9pv9ankTLwVoXkDM8/z6vloxQsqLf9C3GgmZNm8DGVVwbps0a9n3L
         ApqZ0gq2cFX30rEcSG4sxV0aSBlf0InOEDJMq+TKNMHD+w/WaGOj+ByBYL6jVy/D5fVq
         UYiTs4XDaaRWcDcBWivzq9yzYLLpu+dtVsLaiFbkBiglwCBK3V7Swfz7DSBjOFETiWcG
         2ePA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kilobyte@angband.pl designates 51.83.246.204 as permitted sender) smtp.mailfrom=kilobyte@angband.pl
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:subject:message-id:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HGYO1F5kiQkdt1aYc2x+IEMv2gsAHqE2vTPFaXOi0+0=;
        b=IW/2EKRIzzx01HeCTWpI1jhvv3ko8wxHLVUnsfzQXqseY82acTNLsB1Q4MjFb1GP+s
         ZcTcnF5Mu1pJ6F5ijB8Af7PVmhtchG6UFvzWZZEPMsO95dKj8enPaU89XS0pa9/0D1rU
         fKPvDIJfUZ5PWppL3wH8FvY+oOReBUU1uR8/0lW/wPKSlgozTpObBPWbWNqgxIHIXbEx
         OltWxDTdD0GPotyHwqVDVjOoP4Y7A6AF29qh5WQS4p2eXR1gdV5FTdhcXUI1fR+klvTA
         KtDq53AgoF41hdOOUX7Q4VDJfEMvOUJRFoOvXu89wWaES855QKDrVQcVO093IlhnmEzg
         0GnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:subject:message-id
         :mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGYO1F5kiQkdt1aYc2x+IEMv2gsAHqE2vTPFaXOi0+0=;
        b=FEs2Ro6qU67ElKzJ0zDL7ZTKjmqRrYwl9XLrr0oXqaqSyF1Iw1g/h3PmTn4AG/b3+3
         i8kQ+xpjdAKjdHdC9ZyA29/zGXndkqIAVgiYNUJYBW1/4sua5vUOtuZr7nFbgplkCZKh
         OQGV9v5FLH0o/2X5zarbSbag5O0x4+N66YLXXVxg3RTwaQR7T67y6iXONn8KiwXk64Q+
         9OO6vE5dwq4tQ52273Mh05AXwnhf9lheCdimlz5FN6WMo06nH1ZOUJ+QLjtLDuOSdf5S
         W+ZR+cRPqEUPWQQaHHzIgJJhuMNNb2+xYrb8vq1764+prWbbMSXOuVg6o8LzeWfugb7R
         2e+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lAxeUwKm/KR81MjoWhNmC7/WqTaXe1IGY3tEa7OHQw2A7b3G8
	YhHD9tabYdynzjEHb8FsVIE=
X-Google-Smtp-Source: ABdhPJzvGXJIpmOE1ZSopYZqcRHHYkGgX4NsFA5j8gIf0o+cR0jcFGhD3t8M+h83hFlYLUoiHXmk7A==
X-Received: by 2002:ac8:59c7:: with SMTP id f7mr49403296qtf.605.1638890480281;
        Tue, 07 Dec 2021 07:21:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e34c:: with SMTP id a12ls10609161qvm.2.gmail; Tue, 07
 Dec 2021 07:21:19 -0800 (PST)
X-Received: by 2002:a05:6214:29c4:: with SMTP id gh4mr46196303qvb.118.1638890479922;
        Tue, 07 Dec 2021 07:21:19 -0800 (PST)
Received: by 2002:a05:620a:2908:b0:462:9457:3743 with SMTP id af79cd13be357-46a8a38e831ms85a;
        Mon, 29 Nov 2021 09:37:24 -0800 (PST)
X-Received: by 2002:a2e:b545:: with SMTP id a5mr49374988ljn.31.1638207443719;
        Mon, 29 Nov 2021 09:37:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638207443; cv=none;
        d=google.com; s=arc-20160816;
        b=DMu3QrR3vzvdUMPMejtZ3OtudvYJSKwuS+rvU5ayOYMdFIWplpcSXkm02LgEHa5fam
         HORQvPAwDmGaU5jcw5ZLf8oJh8eSS7lf1tOmQcu1/OaaHcIZnRwevqZ2oqehu9+m0XBe
         7j+tTz256BaWIMxolIFZIYbnb1X585iKanymKjVZrlF3S7XWI9J0v42VhjlX1dYUlKmx
         Nm2F2Vt4JO4JZzPPHsu+tkSlL0KUeIZMmwCL0oipkpWMzwtX+VZ0l2VNfyr2vRIlSlYi
         zwC90ant2eKhzJA43qZePStUDhK4UVvny3tICnAOdcJhaATVGquesqUnRYdaLmW0ASmI
         RAiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:to:from:date;
        bh=4JozKR3IUJWlPzYrQcWfDJDoi4qFCXruzgpqv3ge9fI=;
        b=hwQHq9VM99aj5UiixAYujvOGOaxRDuQoKmOwIWIpCfnRBIG7NOwN6Rh4TAoMikPNor
         OWHyXW4D0beBZF/bPG6B3+K7Xm2yFZMGUBi8xpHGT4fVXKufWj3WVLlSV4AFdLHKpkpH
         N0CLyifymxYpL7I7L1+yvp2tMKCxZ1xJT9a1Zrd/ti8hhJLeR0fRuS1eR7yUGVRs0nxI
         N6fscXsTBwMXHPcyHKSuWPfSV4uMGmLPN3VyyyS7WpGjIYQVBabh6NWFDNa8ifJXGYCI
         XsT1Th6TVvdN8kdLdi/H90LvlNXF3MI7pfnZcPyTkyoZrAi7qaNBKYIIcX0Ln/yf/hqv
         IbgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kilobyte@angband.pl designates 51.83.246.204 as permitted sender) smtp.mailfrom=kilobyte@angband.pl
Received: from tartarus.angband.pl (tartarus.angband.pl. [51.83.246.204])
        by gmr-mx.google.com with ESMTPS id j13si1246994lfu.5.2021.11.29.09.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Nov 2021 09:37:23 -0800 (PST)
Received-SPF: pass (google.com: domain of kilobyte@angband.pl designates 51.83.246.204 as permitted sender) client-ip=51.83.246.204;
Received: from kilobyte by tartarus.angband.pl with local (Exim 4.94.2)
	(envelope-from <kilobyte@angband.pl>)
	id 1mrkYa-00EPT2-QN; Mon, 29 Nov 2021 18:35:12 +0100
Date: Mon, 29 Nov 2021 18:35:12 +0100
From: Adam Borowski <kilobyte@angband.pl>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: build failure in kcsan_test: atomic_thread_fence -fsanitize=thread
Message-ID: <YaUPUNMISPzGbX0C@angband.pl>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Junkbait: aaron@angband.pl, zzyx@angband.pl
X-SA-Exim-Connect-IP: <locally generated>
X-SA-Exim-Mail-From: kilobyte@angband.pl
X-SA-Exim-Scanned: No (on tartarus.angband.pl); SAEximRunCond expanded to false
X-Original-Sender: kilobyte@angband.pl
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kilobyte@angband.pl designates 51.83.246.204 as
 permitted sender) smtp.mailfrom=kilobyte@angband.pl
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi!
I get the following build failure:

kernel/kcsan/kcsan_test.c: In function =E2=80=98test_atomic_builtins=E2=80=
=99:
kernel/kcsan/kcsan_test.c:975:17: error: =E2=80=98atomic_thread_fence=E2=80=
=99 is not supported with =E2=80=98-fsanitize=3Dthread=E2=80=99 [-Werror=3D=
tsan]
  975 |                 __atomic_thread_fence(__ATOMIC_SEQ_CST);
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

So I wonder: what's the purpose of this check if it warns/werrors?


Meow!
--=20
=E2=A2=80=E2=A3=B4=E2=A0=BE=E2=A0=BB=E2=A2=B6=E2=A3=A6=E2=A0=80
=E2=A3=BE=E2=A0=81=E2=A2=A0=E2=A0=92=E2=A0=80=E2=A3=BF=E2=A1=81
=E2=A2=BF=E2=A1=84=E2=A0=98=E2=A0=B7=E2=A0=9A=E2=A0=8B=E2=A0=80 At least sp=
ammers get it right: "Hello beautiful!".
=E2=A0=88=E2=A0=B3=E2=A3=84=E2=A0=80=E2=A0=80=E2=A0=80=E2=A0=80

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YaUPUNMISPzGbX0C%40angband.pl.
