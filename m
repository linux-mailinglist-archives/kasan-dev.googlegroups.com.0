Return-Path: <kasan-dev+bncBDIK727MYIIBB6PT4COQMGQEQNQNBSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EF766602C9
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 16:10:51 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id h18-20020a05640250d200b004758e655ebesf1405485edb.11
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 07:10:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673017849; cv=pass;
        d=google.com; s=arc-20160816;
        b=qGwdm5AFdEHSvBZw1nVK5IBy1fwzdbqvVyC9drFnXhDtvRhJ39xTpmxp735au9WCfd
         JM4QxDwapvZHrP7XLvEgM47I+rBIIIxYfvAZIZ3P8Oqy2Ai59iL4zVIsRo1C5IFbmXHE
         fi2HXXkzzqG7tEkzQ1RuRaRQH11KlqMgZ+WiuG0dw22q377KxxnK401n1R7QZN0fN8IX
         r6CXLB9cQ/zpDls7BUHElM7mDNyaAY7s4WtVdYt3xqwI8hsL1Ej5SDNygf0zBYFHWQEn
         F0ivHQ8/X5LFK/eUljlH6MTwz5PUPP9snUOPFnXQ3xQRZ1Ns6jAOGxhb1Xbf0Mr63pFJ
         JGsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=AfYTPXiJEHnkhvgwtPD7OIghKKrXc5Ymjp2zDGGtid8=;
        b=Kdy78ytxTwkrojQzy/q5SgIzE4pVlUQ6SXtcqtPRCBW6yfOFCxMbsmGATW8N4vwUmQ
         4RBYG0lq1gUSkoVjl2aEV2SVxcZx/ey6l4yiB+uDhtdhTNwc2mb5W9LIOczs509wnpZr
         3usl2i5bqIPZyzOSyd0eLpLcfWPmYLAcyoOp0V4hZRU4RjhhkOPROoFr1i4JpXeD8Rg0
         e3gt4WEL2n90CI/WJTKcviJCg2CUcf1lu2+Hj566h6felg828R8Qx88Eg9bqg9s7XgB3
         anDntdeiuZGXsAprBHDbSJXv2BXufiri5I2FgcQV+cL4xjCEwY56WtLiA6UUsjnO67A9
         wuuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AfYTPXiJEHnkhvgwtPD7OIghKKrXc5Ymjp2zDGGtid8=;
        b=PjT3ekUCmQ4Ly+mfuufwT/W+0kFyvwQnDUx9ZQiL2xDO+jKelMG+QAtZcTi4ea9Wzi
         4x/9/nzj4aetRoFumKq/V1t0Ai8UA0mQ4N0PC/gwiJo3G6NLrDqcrdwtImzHIALIFuP1
         Wtsy7Rk/WKa1pLERi8iZSkDs2+EkVmDbIJ3lEYYDqQwGuQuunEz5+SZEbS7AvMnY0lVY
         RUYcgx4g9hQDo8z2OJrvhbcXN19PR6/ZZGxvBisySGDS1dBhkn0HhuMmlfb1i+iCY6bf
         0aTtSgFnoFpVC0mYkJoEZTulj6qopNcOqX0P4wxC7vZ5YV74HrgUbT4ZPSCQcLMFZkUF
         BTHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AfYTPXiJEHnkhvgwtPD7OIghKKrXc5Ymjp2zDGGtid8=;
        b=Id/SvNBlaVKdHMkgsnj1pMe22GLk+nGhDt5EQlh0Y0mmPMu2TdBja4FZ9qV5K0o3yW
         TmHFRW16gyc6ULAi15RYj48BEEViLz2UhjvoWfq0MtEv66mDcegyTQ7pphfuaKHJqPzT
         xod7iKsMhAcD0pC6PehQbZpEfhQTG8h0IkCsct+F0OSNS3vnmsCPMD4sPGpgARm+OfCp
         poOyQYmPEJOVLg47YE8ocGtforXyhXFxz72ekdfsRb9+pdWOar1rFJ9JU0dGvJFT6g8p
         GYYZLfCb+Gtm+j4GiGF/KvlBawdcfjymM3VNslxA4qF7GDxFj7zGGabBEor0a6YuVemB
         VtYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koF7hQtiliaLrQqeu4jn58nvRFb4FzRhSnV7LAsq9XIATnGfZpQ
	lNIYQJSiID5Q95ZSkaMfRio=
X-Google-Smtp-Source: AMrXdXuIKgOM3C4IbMIVMQ3RkevperDAziNtQIXStCOqoWOc6onmwy/4+nrrP4ubYQSg9plzF75eJA==
X-Received: by 2002:a17:907:80c7:b0:7ff:7364:913a with SMTP id io7-20020a17090780c700b007ff7364913amr4690277ejc.490.1673017849463;
        Fri, 06 Jan 2023 07:10:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4413:b0:43d:b3c4:cd21 with SMTP id
 y19-20020a056402441300b0043db3c4cd21ls4612951eda.2.-pod-prod-gmail; Fri, 06
 Jan 2023 07:10:48 -0800 (PST)
X-Received: by 2002:a05:6402:1297:b0:494:fae3:c0e4 with SMTP id w23-20020a056402129700b00494fae3c0e4mr4417836edv.10.1673017848424;
        Fri, 06 Jan 2023 07:10:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673017848; cv=none;
        d=google.com; s=arc-20160816;
        b=iK+k8EvF2FZIgjZehO7wQc/Oxz77uFxG6MTDLjlzjj52VckZuwkr7vuKH7DLrFFjB/
         ILD97VQ5UnM/4+lpi1rnVM6a7apr1T2NBvCjmK0wmnWgF95hYOEqrO8VYnS/ZMFVywFQ
         yc9rp8bplnU50lM+S9m1HXaQ2JhPyOckMdjQorTm/L6WQFQLpIUoxTGP+Ywrc9QVEcul
         LcB+L1/PiVodn9MfCotpdSR+DH2EDcDWGiwOzzdQjwGV8pVl5WwQSghylLf+smQmC71D
         bmXQGbFLuBBGGfgXsJRwQzSyAeGkdDBKeVo99GOGK5EVAnSgzleStpSqPPZwpS1n1ns1
         deUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=+EwS5gPWRuBK0knCKE80c3CmYTQUABv6Yjee2O85s/Q=;
        b=GUNZIkUWEO2poCleVlOE534Q+bEcOH/evTDCAzZ5cWLXhVUUHaphCWBCgQCHRacJou
         7glsSOtyozIAluYkYOJ0jT27YpZUfGCb6cdQbDJyOdZak4GNz++u0OlQKR2Pw8uxNAxP
         N0HTQLEFN0hGo545kYnlxPczsgCGx0Y1huUujMJi6C26nJ/KhrGimgioMl12iy/NQ4OW
         avuO2zUmEeRvxNMlSwcjvTIVURRk3DnFlcVMtg40kkdpSSvZ5k8AkkjWCgt2GbkIjF6G
         Hthjv1fkF4b2/f1ov7dqBOQw6kAXoWLVcmrkp17V5v/GkGtaP9NZxXpuarf62feyty3I
         FL6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id l25-20020aa7c319000000b0048ecd372fccsi72171edq.5.2023.01.06.07.10.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Jan 2023 07:10:48 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pDoMP-002xQU-QR; Fri, 06 Jan 2023 16:10:21 +0100
Received: from p57bd9807.dip0.t-ipconnect.de ([87.189.152.7] helo=[192.168.178.81])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pDoMP-000ZKo-K4; Fri, 06 Jan 2023 16:10:21 +0100
Message-ID: <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
Date: Fri, 6 Jan 2023 16:10:20 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Build regressions/improvements in v6.2-rc1
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>, linux-kernel@vger.kernel.org
Cc: amd-gfx@lists.freedesktop.org, linux-arm-kernel@lists.infradead.org,
 linux-media@vger.kernel.org, linux-wireless@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-sh@vger.kernel.org,
 linux-f2fs-devel@lists.sourceforge.net, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, linux-xtensa@linux-xtensa.org
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: 87.189.152.7
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

Hi Geert!

On 12/27/22 09:35, Geert Uytterhoeven wrote:
>    + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_262' declared with attribute error: Unsupported access size fo=
r {READ,WRITE}_ONCE().:  =3D> 358:45
>    + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_263' declared with attribute error: Unsupported access size fo=
r {READ,WRITE}_ONCE().:  =3D> 358:45
>=20
> In function 'follow_pmd_mask',
>      inlined from 'follow_pud_mask' at /kisskb/src/mm/gup.c:735:9,
>      inlined from 'follow_p4d_mask' at /kisskb/src/mm/gup.c:752:9,
>      inlined from 'follow_page_mask' at /kisskb/src/mm/gup.c:809:9:
>=20
> sh4-gcc11/sh-defconfig (G=C3=BCnter wondered if pmd_t should use union)

I'm seeing this, too. Also for sh7785lcr_defconfig.

> sh4-gcc11/sh-allmodconfig (ICE =3D internal compiler error)

I'm not seeing this one, but I am getting this one instead:

In file included from ./arch/sh/include/asm/hw_irq.h:6,
                  from ./include/linux/irq.h:596,
                  from ./include/asm-generic/hardirq.h:17,
                  from ./arch/sh/include/asm/hardirq.h:9,
                  from ./include/linux/hardirq.h:11,
                  from ./include/linux/interrupt.h:11,
                  from ./include/linux/serial_core.h:13,
                  from ./include/linux/serial_sci.h:6,
                  from arch/sh/kernel/cpu/sh2/setup-sh7619.c:11:
./include/linux/sh_intc.h:100:63: error: division 'sizeof (void *) / sizeof=
 (void)' does not compute the number of array elements [-Werror=3Dsizeof-po=
inter-div]
   100 | #define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/siz=
eof(*a)
       |                                                               ^
./include/linux/sh_intc.h:105:31: note: in expansion of macro '_INTC_ARRAY'
   105 |         _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
       |                               ^~~~~~~~~~~

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
kasan-dev/c05bee5d-0d69-289b-fe4b-98f4cd31a4f5%40physik.fu-berlin.de.
