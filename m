Return-Path: <kasan-dev+bncBDIK727MYIIBBLFRWGPAMGQEAFQ5V2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 51674676992
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 22:27:09 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id t26-20020adfa2da000000b002be9cd25e90sf701245wra.11
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 13:27:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674336429; cv=pass;
        d=google.com; s=arc-20160816;
        b=cK1pS/4QFmF9MDh93/XcVHxl3rJhXUamAFPencq7E2GCvqs5u3r7vENGBFvsC4jupI
         QDGtFGidzScDsipo+lflEMLMa7CMpopyzXrlsRY7PqVsceogujpe+qIX7HVg/xQ9N6ao
         JSTATAo/BSIzLhm9RBWKdPGcvxZb672j5YHO605ZCAufN1nCAMVmUtJBfbUvQjoXjl2l
         mQyITinm3evSAUtEEBub9LczPtXELv/mX3lhMLAFBmnR0GezlODIBRCspIF8e5/GZ7wG
         Ds7JpFjQXd2a4zLWptN0tYU+UrXKnn+WOCmOD7SHOnUvNkCHS393vAENtgDVa21SgOjR
         Jsjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=hm/Jl2eoJVafIrOzwJEV0CHHy8DvM22DeiQFwoVI+CA=;
        b=GPAQWKwk3T79BTSqCO/lCGJoc3hrDoKXE0Sz9el5AONiJmLDfz/MtmFgUiK5ezTJDA
         uouFz/DgNEq0Kgzg1PgIXz2b8WJAiq4WaMRV+ClpWfmGH9+4R61MHRjL4CSM0C7e6fVb
         RC33l5XxWaUOuEOQ5mrdLbfK+Mmp6yS0WYmkeZU+Ae9oVSXWrWZx3BaJewc6QrTYmHPB
         hefUrUV3xKlZTxYvUTzC301DumacT5cnOQrpvqPDz/ZHG/dOf/Pr6Jc1UpkX2d5vOWuN
         M1c7wKWK4mi/1XciLdmGjNxhhhv6BXmxOnQkYvrgOHn7MLNkuu9i9N6cjfUaMngaY0iM
         JUgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hm/Jl2eoJVafIrOzwJEV0CHHy8DvM22DeiQFwoVI+CA=;
        b=tgfmxUNPrcNYhKsoQdyEeM+apbGxrKFFhW/1N0bREtVS0R1qqi/V9cdlsLDhuTSRiU
         qShN73KZ8uFl/jpdOISN8GJnqdQcfBKDn1VehuLUYeyeD0x+UVry0qoeafQU7XCKZcXm
         8YUIKofrA9oVMJGjQRG+ikM8DuWLsROecOztORT3rvqGSPe3W5GC96JQ+d9oCanUJJF3
         gq0z+ffHTL7BGR6jM4KRx5T0JrSgqvpRSuhUF4Nc3+LU4Ta4kiq1o987738OIlJrTEx3
         Dn/XHS4gqm2eGLlWhScD41/red7lrxRrj1vFpDDa95xjez2idZdKs8aEMjzA/BLHV9Wo
         R9YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hm/Jl2eoJVafIrOzwJEV0CHHy8DvM22DeiQFwoVI+CA=;
        b=oVPrJ8Awukz/tqliHeWtxQLohA8A/aex3BqqM3IJWavyE95GSIjm3Up7x/xUARS6bq
         U68Xbff3fe5NN6/u1T4fg1X07H/yzEPtjoeHI+pHxuU4gc0RvZZRxq32ZBxqdaoP81FU
         wcOwVa7GIQg7YcfLNhXfPEJkZi9E2QdHQM5nWFBV3zuU5H1oZnGfPk/m17C7PRbzQ9Lp
         zKuMxWKQKYHmq3AQ8N11/4kJELN/fnxIhWukYAwvkGjPmbKNaNZ463WZUwggUps0su9A
         xoyCRS9hBjl9fuM9VDVu/UKWnLe1Edugx3ZMXW5s2K6Hua4U7bLN/mnhfU/OTPn473WC
         n42g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqIDK3lyjf0IP9KBXnMyFohP1+fgaXzOHBFqVEL9iYzp1EDGm7z
	0wScBn8QfaYQqKKDgv48d0U=
X-Google-Smtp-Source: AMrXdXvo8Xp0W8znmir3qPv9nPBn53Fhm1EYi9zUFR/IlsWbVoaBBP61jGJR3f8hCjWobS1NooAYEw==
X-Received: by 2002:a05:600c:a52:b0:3db:99c:bca9 with SMTP id c18-20020a05600c0a5200b003db099cbca9mr1769540wmq.113.1674336428775;
        Sat, 21 Jan 2023 13:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:25a:b0:269:604b:a0dd with SMTP id
 m26-20020a056000025a00b00269604ba0ddls5724066wrz.0.-pod-prod-gmail; Sat, 21
 Jan 2023 13:27:07 -0800 (PST)
X-Received: by 2002:adf:d1c7:0:b0:2be:544c:fe2c with SMTP id b7-20020adfd1c7000000b002be544cfe2cmr7595334wrd.25.1674336427757;
        Sat, 21 Jan 2023 13:27:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674336427; cv=none;
        d=google.com; s=arc-20160816;
        b=KTkB7p65cw5MonC/L3IaZqxllR16XZtn8na10vrsVXtLwHpm5GGoMtWc5KAYGGpn/I
         hrrUXx8FGepCX8sB6DaoC6ETHIPzjnKpNryv80qc/qu1+HILV29R5obRhu1HosmWc9c/
         cejrBMmC4k8hYCFOzX0Y2d9x1EyDnOBluFcasiZACFW1jJv3z+kHSti+cS6W216kqm5I
         9vV6niTDDSqzTJFTwjqTx/VfB/Z4CdhvVoRLj0OLrecPMYiHtHmySaV5JCO/s1LjluEx
         9v1RomInWrbMxcn57pBur2EUxk2ynTRV1z/IlLnvMPPGmnm+YqzTAzsh6VBFXsSvWXQH
         ue+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=yhmwtE13OOMQNJIh4iCnBh8C5pkGPy9ns1M5J9HbuAU=;
        b=LK8wK8DmGkVNIlsYNd/MjYBd0KXzp7cGijvWHN8Er3M6BjiJGOMwGubYvxpJPuQfUC
         aWbxrmDKKmwuyQROs6uuHUiPwgUJh7WDAYbKwo8c1BUukzrK8g/j1gC/7V3gFJoGiiPB
         IGx9oqCVdeFPiXxCYSXkSo2pHpTE3jdQSmA2TMI9JXw4tJ+qb2ttjnsHwFxmJZEnxGoL
         /RIb4sEqTGVPxbeyrOgQmQ392fVSk40umWpcX9bf6e+AVX76S0zA4N1W2MRbreU+ldFK
         UBkFcz1RfKCoU/ghC8hkeAh74FhCg/3egkeiSU2sIHsbceG5fHTUCaaFRFrmxmXo3xyD
         rqeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id c1-20020adfed81000000b002be29f05cdfsi608314wro.0.2023.01.21.13.27.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Jan 2023 13:27:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pJLNr-001fc4-Li; Sat, 21 Jan 2023 22:26:43 +0100
Received: from dynamic-089-012-154-190.89.12.pool.telefonica.de ([89.12.154.190] helo=[192.168.1.11])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pJLNr-001xPR-F4; Sat, 21 Jan 2023 22:26:43 +0100
Message-ID: <7c6b114a-38f8-1a0b-8623-d492f9cc2fb9@physik.fu-berlin.de>
Date: Sat, 21 Jan 2023 22:26:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Content-Language: en-US
To: Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
 Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-wireless@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org, Arnd Bergmann <arnd@arndb.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
 <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
 <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com>
 <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de>
 <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de>
 <c1d233b9-bc85-dce9-ffa0-eb3170602c6c@physik.fu-berlin.de>
 <def16c9b-7bb1-a454-0896-b063a9e85964@fu-berlin.de>
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <def16c9b-7bb1-a454-0896-b063a9e85964@fu-berlin.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: 89.12.154.190
X-Original-Sender: glaubitz@physik.fu-berlin.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as
 permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
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

Hi!

On 1/20/23 20:29, Michael Karcher wrote:
> Hello Adrian,
>> Could you post a kernel patch for that? I would be happy to test it on m=
y
>> SH-7785CLR board. Also, I'm going to file a bug report against GCC.
>=20
> I filed the bug already. It's https://gcc.gnu.org/bugzilla/show_bug.cgi?i=
d=3D108483.
>=20
> The diff is attached. It's published as CC0 in case anyone considers this=
 trivial change copyrightable. This patch prevents this one specific warnin=
g from being upgraded to "error" even if you configure the kernel to use "-=
Werror". It still keeps it active as warning, though.

I used the following variant and it fixes the issue for me:

diff --git a/arch/sh/Makefile b/arch/sh/Makefile
index 5c8776482530..11b22f7167d2 100644
--- a/arch/sh/Makefile
+++ b/arch/sh/Makefile
@@ -167,7 +167,7 @@ drivers-y                   +=3D arch/sh/drivers/
  cflags-y       +=3D $(foreach d, $(cpuincdir-y), -I $(srctree)/arch/sh/in=
clude/$(d)) \
                    $(foreach d, $(machdir-y), -I $(srctree)/arch/sh/includ=
e/$(d))
 =20
-KBUILD_CFLAGS          +=3D -pipe $(cflags-y)
+KBUILD_CFLAGS          +=3D -pipe -Wno-error=3Dsizeof-pointer-div $(cflags=
-y)
  KBUILD_CPPFLAGS                +=3D $(cflags-y)
  KBUILD_AFLAGS          +=3D $(cflags-y)

If you agree, can you post a patch to LKML so we can unbreak the SH build f=
or CONFIG_WERROR?

Thanks,
Adrian

--=20
  .''`.  John Paul Adrian Glaubitz
: :' :  Debian Developer
`. `'   Physicist
   `-    GPG: 62FF 8A75 84E0 2956 9546  0006 7426 3B37 F5B5 F913

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7c6b114a-38f8-1a0b-8623-d492f9cc2fb9%40physik.fu-berlin.de.
