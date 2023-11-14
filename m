Return-Path: <kasan-dev+bncBCT4XGV33UIBBJX5Z6VAMGQELSBJQYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id C452D7EBA1E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 00:11:35 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1ef393787e8sf608197fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 15:11:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700003494; cv=pass;
        d=google.com; s=arc-20160816;
        b=E4o4mqpIKE/FbCY7GQW1ORS1305XvMIcgHmvXiSuQXQMgOt23VdAzeKCHpmvMLVAkC
         wLWoE4IIBGvm8Nl0tpH6YiLCQc0XN0fdv3PQzAjP6pzry87Vy1Oiay4I5/SaVNGZ+XVI
         xAtnOP6b1qlOZhMCQRm/BHi7d9bOdUMf6fSYq+QnuS7uZe3erSinCtY17UMiUYUem53q
         b7nri4ec6ZI7Magu6NLRITMx5jioSH3DsZ2DYW161Ncu6KXC7z91d3Pl+t18V5TefDpf
         3TSAgcbfUXaCeE36VnmAIR4UoAyCJP3ec4rZsarDDHSMoDdkcHJS3WI9yhec6OyYDymB
         O9dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kYrKZgQzUQvNFq9r8iW3ZWzJW7HUBQxYh2B3jgnJN+M=;
        fh=y3qq6DpdB3PSI0H4IbJvKn5O5PXg1IMiCcdxaQaPqIg=;
        b=nXUW/ulJbq05Udty82Vmw1r9byLtAQs790EGHGPD1piHfJyYk7DQBsr5YdSg09Yz71
         4XdXVD+t5Yn+MUq0fsKAd4vIa+Y3YrUAXsfxqzkB2BlzjBAOfbDjCLZuJL8UmsEFSPYS
         8nGTc0gtGIpo2ei9s+lF5uT4QQ1id2DWFKoHWUOsCSr7WckaoN+OvtI5vGO9W1eBZ1g4
         Iaj5M0FrRFhOtBa9hzBzRrnX8TGMqeAK/Pabg06jTF0WtH+y0Ag3cEuadl1mU9lHWBGa
         ZiWFe+GKj33Ohm38XwPbUMptDnoayaXOP6u8zy1uRQrIL1Bw68UDAOtgd4yDFOoBrpoD
         AZwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LyzijmPh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700003494; x=1700608294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kYrKZgQzUQvNFq9r8iW3ZWzJW7HUBQxYh2B3jgnJN+M=;
        b=pz2bKkspzJdEK57zJudoiR1bSwfWo89loIUtkQff5Cz7r82zsBG48CTMvNez0k3Ecl
         lZGWw2M4xinntIytvGZ0opeeNVMYJxAa8sTEo+0xwYhgJx71jIPxVB73HOaIVjIERa5r
         prGGX79VdSAsf5b5E21YB/0rVKguc7TboJqwPV8/CwOGBhu2ALN4BrtJklvsPlsbER+9
         m5gCj0qdmHOo8X8yaBN4x4/2CBSy9lT4ufLpo2diIlVcU6svUA7cyAaiH1SZpYl0nMI3
         C11t2ct8eJ1/wNgKbRrzZNvBUjlyS1taUx2+lbhXH/4pIlmWIhDzonVLfV4jTCRPOyKk
         6snA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700003494; x=1700608294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kYrKZgQzUQvNFq9r8iW3ZWzJW7HUBQxYh2B3jgnJN+M=;
        b=aaXesb+TAAQsPEJbetaopg2sVWi13llEUEVO54bIja1SWb5/JGecEJkcKUb13D2w4z
         pzbHsFkh50ihWKobWXEp1a590BkEgJzBcKLpplVdTs3MtaHwEzsD5i921OtZFhNcSuEi
         hgTb3bzem+v9+xL719Q2YImYykpont2MnhnCZDszMhXWdWjeD79EoVwjuo3RAXcRjalp
         E4TpNiVYZJzrTzRqhtlfnVMYkcMQrBL+sPte4kxJhmqWlsAu5Lq1SC2JGR1hSqCbSFum
         tPzxx6lVHoZjcqWBLXXvoWdhlmRHl0lF8sDKNsjvXBTUq+S4DNWCT690nXuykaMG7ovS
         Mrvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyXy5lDpVye6wM1ic9RgnFMvqHw/Hgds8lPrkrQgt0OUyElzyoh
	hikAJBHtHLS93Dsqmnz/jhY=
X-Google-Smtp-Source: AGHT+IEVJ+ikzuKzZ78ua8Vy2TtkKZq6e/vMo2bWDCjbgmUJL8XUM70w3KRDDdJoVn3pc9rPwiOG9g==
X-Received: by 2002:a05:6870:1d0e:b0:1e9:8a7e:5893 with SMTP id pa14-20020a0568701d0e00b001e98a7e5893mr4431649oab.5.1700003494277;
        Tue, 14 Nov 2023 15:11:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f299:b0:1f0:4ef9:f2b2 with SMTP id
 u25-20020a056870f29900b001f04ef9f2b2ls2261021oap.0.-pod-prod-06-us; Tue, 14
 Nov 2023 15:11:33 -0800 (PST)
X-Received: by 2002:a05:6358:7e56:b0:169:57f3:7551 with SMTP id p22-20020a0563587e5600b0016957f37551mr3223827rwm.23.1700003493485;
        Tue, 14 Nov 2023 15:11:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700003493; cv=none;
        d=google.com; s=arc-20160816;
        b=twYJuzc7jPyNsIjK0Ewpz9JEBu0RVtC1/k99S7GK4oKlMgcZAwp5bmH4vTp10GyxzY
         PE8vE4F8nyBY1NeqYJEz7O4H1ZsJYKmRXwAq+ak1NXYLPGpwUhdqxaXIpUcggmJzFrkq
         /aw+qQau3WDjcmtJxYj1oc2AENt+8KzrnCyiT8X3ZumcGqPI1jV9T2VZWuL47y95FR5x
         VcBecIEpy0kqORl1kpccR0Bv7fZNo3EHT8QhY6vBoex4iHllwuoKoM/ZOuzgQf85cHmi
         SnZUCGnljkSGExv9tUCGI7CAv6+cFHYWFt+a9v9FMLYtXuBjJDEVCLphDJlazt1l028s
         xeDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9rk4Bb1F8kvlytED/CE4XkyISAHUHz/Ojr48noqKtLg=;
        fh=y3qq6DpdB3PSI0H4IbJvKn5O5PXg1IMiCcdxaQaPqIg=;
        b=h9NjiHStTTyuGAFO8nJBcLN9TiAweFRWB37PLMfk01JYWeqvQjxtvtJRkuGXZ60cjf
         stHGlF5Za+pNDAHVeTpNjSfEI+p+e71og+MHOfx8G7xn4k1fUJ3kjlH7NLZIx60TBiUP
         8RPGvAzyyWgAsKEow8YJO1/+MOtFOxJCEBq6ZkSWaZnnihaCkiUe2uii9RgzslOpwF3u
         vHaDP1W1FdJBKNZTpXHxozruSVZHj0LWLfvs726hwcX5VnJSm0BFJteDHbooahMtXY8Q
         vvj1u7C1FbkQpLybAEgcTwj7WtnuRQrFjDtu0CcwNIzC2NCFmXqeh0WbdErmvkX+BqKm
         3FjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LyzijmPh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id ay29-20020a05622a229d00b0041ce9eb6295si1286987qtb.1.2023.11.14.15.11.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 15:11:33 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B12D9CE1ADF;
	Tue, 14 Nov 2023 23:11:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A13A0C433C7;
	Tue, 14 Nov 2023 23:11:29 +0000 (UTC)
Date: Tue, 14 Nov 2023 15:11:28 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Paul =?ISO-8859-1?Q?Heidekr?=
 =?ISO-8859-1?Q?=FCger?= <paul.heidekrueger@tum.de>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, Joe Perches
 <joe@perches.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
Message-Id: <20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
In-Reply-To: <CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
	<CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
	<CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LyzijmPh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 14 Nov 2023 12:00:49 +0100 Marco Elver <elver@google.com> wrote:

> +Cc Andrew (get_maintainers.pl doesn't add Andrew automatically for
> KASAN sources in lib/)

Did I do this right?


From: Andrew Morton <akpm@linux-foundation.org>
Subject: MAINTAINERS: add Andrew Morton for lib/*
Date: Tue Nov 14 03:02:04 PM PST 2023

Add myself as the fallthough maintainer for material under lib/

Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 MAINTAINERS |    7 +++++++
 1 file changed, 7 insertions(+)

--- a/MAINTAINERS~a
+++ a/MAINTAINERS
@@ -12209,6 +12209,13 @@ F:	include/linux/nd.h
 F:	include/uapi/linux/ndctl.h
 F:	tools/testing/nvdimm/
 
+LIBRARY CODE
+M:	Andrew Morton <akpm@linux-foundation.org>
+L:	linux-kernel@vger.kernel.org
+S:	Supported
+T:	git git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
+F:	lib/*
+
 LICENSES and SPDX stuff
 M:	Thomas Gleixner <tglx@linutronix.de>
 M:	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231114151128.929a688ad48cd06781beb6e5%40linux-foundation.org.
