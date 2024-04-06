Return-Path: <kasan-dev+bncBDH43ZGQR4ARBIFXYOYAMGQEM2FLMOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29A0389A8FE
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 07:20:34 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5a486a8e1fdsf2980057eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Apr 2024 22:20:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712380832; cv=pass;
        d=google.com; s=arc-20160816;
        b=e6kdAGDPDogQH+p8jp1HJzY27qCOSIBM3nPBHYjM2QA53iB24QAAH9/SlPMgpwLEbu
         zxbggmX4/FS8RmTbp47TPULocx3m5IP+nX2FoUJraJ+KXXCyCEG0yPVW7AXxIq7Fq4ou
         t3qVUSnB2Ig2eiwkOKAaTwpKBZ10uRkugZqmQqzGjObWjQ+LzY/3ZZx6msuEWYijgyFV
         F6+ZteUTEnchNKlQayWRwrNSQvLdV2dveCI/Z6lXmFI4V5mBP1NZp517Eibf56B52drl
         UV0IjwnkgBkUlak3Kf/RGxyFWxYRwEzWSqd1hmbAfcK2D13qve+e9tr4W/qTf/td5+fG
         XIGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=B6CY1v1zFN1ER0xNlZaLDILJ6FwDv1flLLbqT2KX608=;
        fh=N2Adqf7YZ7EyQJv/xqtqoC9ZINNsXLGkc3cvxNQMcro=;
        b=EhQuMm7gdkqFrfjCkhVLXmYMHdYfJDP9xPCSBV1FjHDBBdI8aPLJgl5FbNPWjArlrf
         MFY4xbHiAejVWpFgSvcYjZOwF2SsFl2tVD/RsSYLA3E8+/mY8+9qeEXnMfpEGaUV8Ey1
         hQchEV8ysMKEbnJZDbiEGKdRZSjD46M2khVEzl8IPfg7Aqiilf2eA3vuDGOo6ws5wFdJ
         1dTh6sL4tsAq6UDx4+79jEe5HHyCpJd6memYpIcC3VaZwE1LF0EXJPOmVRX1g463s7ep
         VJ2anNU8/PNStSf0Ty2HBNtiG0wwm6jR7J+tIjHCdPqMUFy6VexeMGrgMdiMBGAusZ7a
         u7Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HYazYNyp;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712380832; x=1712985632; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B6CY1v1zFN1ER0xNlZaLDILJ6FwDv1flLLbqT2KX608=;
        b=IJLX2YTjtr2vH5z0h4OxOk5Lw8EmjduL6dhtLKlWG2PW9waAqa/NDjXDecC95bmhyn
         Vi95Exq0LuPk8dd9wazWvZ8F/yOEUCz4ikG3AbKSS6/VvSsAqURl5/K95kzsgZ7ayMHP
         6d0PUnXcBJm4Ne1QHhwyRVksPLZ52tI6V1+pjbDWn1ZWY1sEA0TgIfC4/hUjxCrsKplP
         xL0neCcafz8hCoFPQtqHtJ9+NLVw2QBNcJQdNV783mh0cXrMNDlMPNh8CJl/ETmY3Cmd
         AuyCj9p+3OiD1euPPK3FXzzMBMbhNvV2sBTHvMaKn2Z9JRj/JzrphDoH/nhMURjyonxh
         I1WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712380832; x=1712985632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B6CY1v1zFN1ER0xNlZaLDILJ6FwDv1flLLbqT2KX608=;
        b=tkD4+u8Rc9jW8PpWlABfAId8PKzbXI86WSQIUdoFZR7chKfM2H4tac7VsR7msSNe4g
         WRmvZewUus0XdXCWsUIOgWp1lpw/nNBbPH4HI5KM6mSFmR0WyzdR+Nl/zms2TzdjiHxT
         sZJQJD9gjeiBsyS7fSpIMFXfxHApDKPG/mwRa/B3xRhVaQJqkZ55sjWdmM7paC3n2ZYO
         JXfKBKWwdacL5jMpGHzHEm9L7q1qunm90BZ+Gn2rQSJtudc/2VL8DlR60qojilR4L68t
         vMHR1LUv76uCdNc5+wuzDKFlQ0dIPdPgujUa/dY0ahqlezckw5i9frLcUiGdfMHe27YT
         egGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIYXo4OGtnVSkXOz7Y+gsZwTxhKACzbYeVZWMKeN70YzeA1ADupBQtZuQytLi+prB5bSE2VhRtIINp3kNrvYt7WbaSGRSpAg==
X-Gm-Message-State: AOJu0YzIyAXwtCaa0fDvXHyfuTCPtaz1DgSFM8Ss80XcRRqs/VLGoBVN
	jdfoaNvqb7B3QYFrznKSkFfK5NQJLFKEj9FgTrqwgJ86LF8pifBa
X-Google-Smtp-Source: AGHT+IHwbsFjXAkjNH5cLT8k0xq6FZxMUot2L/98Cg1Sr6e+4/sQUjvf2R7G637Fe26C7iAzNq0sIA==
X-Received: by 2002:a05:6820:308b:b0:5a5:16e1:beb3 with SMTP id eu11-20020a056820308b00b005a516e1beb3mr3640671oob.0.1712380832675;
        Fri, 05 Apr 2024 22:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1acc:b0:5a4:905d:743f with SMTP id
 bu12-20020a0568201acc00b005a4905d743fls1813195oob.1.-pod-prod-05-us; Fri, 05
 Apr 2024 22:20:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyFnSPJOiobg0d4kJeeM7sXHOiolRqt10rYtdA5h9z0MtTmrgyczjT5444IjtcAgSvbUBVGekyHgNPnv5+IO1EJsZcmdjVBUd9YA==
X-Received: by 2002:a05:6830:1012:b0:6ea:18d:a03b with SMTP id a18-20020a056830101200b006ea018da03bmr1339657otp.9.1712380831788;
        Fri, 05 Apr 2024 22:20:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712380831; cv=none;
        d=google.com; s=arc-20160816;
        b=Fa+34nrJISlm8umx4RnQ/b96H8IM+zC0I7Ao16YpNCYAYJ6PbQSITJ5e7tnfFMid3z
         PSST6aD7NKkL5dFAQyNnUtM+axmlPYShlfEy4IjMgW8fLpQ3i3RxYjOspBXDFU3aFyWO
         CICrjXl0UF12eHgu2tvniBWIlXHGDPzZhHNGFDDoev/AQBkD69m6a5qk68jhS3n8VDNZ
         nT29XgK2N/10eB7LHgHP7HYdqSShfnpBwj2+5MegJsGEe9ynwXJ9pYOuLu3d6zEETSv5
         FxV1QANYncQhyMIuHsOxfslfGClrQuPO56JIqlffxHRruK9II6YvqbmpMAweK5VVkX3B
         WXDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=nE2uRvTv/U2m0+ghgElBUjbItaNExt97aA+SSiNR/Ik=;
        fh=EZvtioogHPoh0X0UC9/NtTLppamOUPzEVoU4LopwfHM=;
        b=PrqCCrhJy9q1mB3JIBCRGMY+16zDU3vL/36r17hd5TGDBxi1vPPHeRMiLV+jakEGwt
         oc8S/FtDHBl3IjFMxXFR7cWyO7xT08X7FT20Nnxa9MgK41+7/H5j8IpPtBCxuiCoAOPb
         qB3ATPRDLQ7VdZNqJG+t1swFTRCVeZRQpLlMgU4JfZRoQ5bp8Q4gwexRWsFRoYfImwYd
         l/ekwhb0pEkbK1JB7Ri1nt1YtqXtJfpjrw915DvD5izx/R2WOXePuKxjctPLJs37p184
         PAjz2IOJWp4cfiTvkbDCFVSGUipawRaWD3nI/SIdco4eVTXuUxJKEnKYr7sh68q4ANME
         tCrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HYazYNyp;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 80-20020a630153000000b005dc851134acsi224614pgb.1.2024.04.05.22.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Apr 2024 22:20:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 5995DCE2776;
	Sat,  6 Apr 2024 05:20:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 33A2AC43390;
	Sat,  6 Apr 2024 05:20:28 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 19C9BD84BAC;
	Sat,  6 Apr 2024 05:20:28 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 00/34] address all -Wunused-const warnings
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <171238082809.31617.17365732495689756509.git-patchwork-notify@kernel.org>
Date: Sat, 06 Apr 2024 05:20:28 +0000
References: <20240403080702.3509288-1-arnd@kernel.org>
In-Reply-To: <20240403080702.3509288-1-arnd@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-kernel@vger.kernel.org, arnd@arndb.de, mpe@ellerman.id.au,
 christophe.leroy@csgroup.eu, dlemoal@kernel.org, jikos@kernel.org,
 gregkh@linuxfoundation.org, minyard@acm.org, peterhuewe@gmx.de,
 jarkko@kernel.org, kristo@kernel.org, sboyd@kernel.org, abbotti@mev.co.uk,
 hsweeten@visionengravers.com, srinivas.pandruvada@linux.intel.com,
 lenb@kernel.org, rafael@kernel.org, john.allen@amd.com,
 herbert@gondor.apana.org.au, vkoul@kernel.org, ardb@kernel.org,
 andersson@kernel.org, mdf@kernel.org, liviu.dudau@arm.com,
 benjamin.tissoires@redhat.com, andi.shyti@kernel.org,
 michael.hennerich@analog.com, peda@axentia.se, lars@metafoo.de,
 jic23@kernel.org, dmitry.torokhov@gmail.com, markuss.broks@gmail.com,
 alexandre.torgue@foss.st.com, lee@kernel.org, kuba@kernel.org,
 Shyam-sundar.S-k@amd.com, iyappan@os.amperecomputing.com,
 yisen.zhuang@huawei.com, stf_xl@wp.pl, kvalo@kernel.org, sre@kernel.org,
 tony@atomide.com, broonie@kernel.org, alexandre.belloni@bootlin.com,
 chenxiang66@hisilicon.com, martin.petersen@oracle.com,
 neil.armstrong@linaro.org, heiko@sntech.de, krzysztof.kozlowski@linaro.org,
 hvaibhav.linux@gmail.com, elder@kernel.org, jirislaby@kernel.org,
 ychuang3@nuvoton.com, deller@gmx.de, hch@lst.de, robin.murphy@arm.com,
 rostedt@goodmis.org, mhiramat@kernel.org, akpm@linux-foundation.org,
 keescook@chromium.org, trond.myklebust@hammerspace.com, anna@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, tiwai@suse.com,
 linuxppc-dev@lists.ozlabs.org, linux-ide@vger.kernel.org,
 openipmi-developer@lists.sourceforge.net, linux-integrity@vger.kernel.org,
 linux-omap@vger.kernel.org, linux-clk@vger.kernel.org,
 linux-pm@vger.kernel.org, linux-crypto@vger.kernel.org,
 dmaengine@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-arm-msm@vger.kernel.org, linux-fpga@vger.kernel.org,
 dri-devel@lists.freedesktop.org, linux-input@vger.kernel.org,
 linux-i2c@vger.kernel.org, linux-iio@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com,
 linux-arm-kernel@lists.infradead.org, netdev@vger.kernel.org,
 linux-leds@vger.kernel.org, linux-wireless@vger.kernel.org,
 linux-rtc@vger.kernel.org, linux-scsi@vger.kernel.org,
 linux-spi@vger.kernel.org, linux-amlogic@lists.infradead.org,
 linux-rockchip@lists.infradead.org, linux-samsung-soc@vger.kernel.org,
 greybus-dev@lists.linaro.org, linux-staging@lists.linux.dev,
 linux-serial@vger.kernel.org, linux-usb@vger.kernel.org,
 linux-fbdev@vger.kernel.org, iommu@lists.linux.dev,
 linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org, linux-nfs@vger.kernel.org,
 linux-kbuild@vger.kernel.org, alsa-devel@alsa-project.org,
 linux-sound@vger.kernel.org
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HYazYNyp;       spf=pass
 (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello:

This series was applied to netdev/net-next.git (main)
by Jakub Kicinski <kuba@kernel.org>:

On Wed,  3 Apr 2024 10:06:18 +0200 you wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Compilers traditionally warn for unused 'static' variables, but not
> if they are constant. The reason here is a custom for C++ programmers
> to define named constants as 'static const' variables in header files
> instead of using macros or enums.
> 
> [...]

Here is the summary with links:
  - [05/34] 3c515: remove unused 'mtu' variable
    https://git.kernel.org/netdev/net-next/c/17b35355c2c6
  - [19/34] sunrpc: suppress warnings for unused procfs functions
    (no matching commit)
  - [26/34] isdn: kcapi: don't build unused procfs code
    https://git.kernel.org/netdev/net-next/c/91188544af06
  - [28/34] net: xgbe: remove extraneous #ifdef checks
    https://git.kernel.org/netdev/net-next/c/0ef416e045ad
  - [33/34] drivers: remove incorrect of_match_ptr/ACPI_PTR annotations
    (no matching commit)

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171238082809.31617.17365732495689756509.git-patchwork-notify%40kernel.org.
