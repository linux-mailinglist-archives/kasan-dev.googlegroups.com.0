Return-Path: <kasan-dev+bncBDE6RCFOWIARBL7OR24AMGQE2LEYRVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id BAE18992926
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2024 12:25:53 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2faccaed382sf26636001fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 03:25:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728296752; cv=pass;
        d=google.com; s=arc-20240605;
        b=R6sw1SXIOBpDdQD8njXAT5Qx53KbicAtbWUNkgWXmMJ4w+zOK/4CyxaY2YnLcXBoPG
         wf+gQokkvX3gbcMnMWfK6UvFUvCg8ptzyclQn7gNVTEAjlnJtTp1Xbfs9+odEY3P9PO/
         EFV+aBKHUS3SXGq3plK9lCkaos+/AsZIrb5019zm5l4aK3uvrBkDq69RPVkuATdUtbUn
         QWmijQw7TR0LjkscXujXPoQzvi7Aw0gq2luGHtD7hUHj9FrQXOY0A+1gW0KTFVKnxAty
         jwx5Q60DvkT4bP2nebkigipynIAPDKz0rIK2dQAkgQ/0kNqkUc4D77IpYlddKNv6/H+k
         AZHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=N1bxIz7JUPlLORnsc+P/3cBO5Ik6kveSSXJJt+oinoM=;
        fh=k01Royd1GdYOaZEWOgd3awR2dkh6BcOQE7ydEPHci1g=;
        b=ginIcMr1KkYKdbMX2K/AA1H+lEPvDcmZw+isuyEi/tvejOIhvPbUH97PlMm99uMu9i
         qGQ65Mobuih+Rqk3kMC+E1WvkCFA/2fwTw0y7QeA8EyaMe6t0uMnTTJ7jJDBmdrvHZDz
         G5KyP2G3ro7yQlJ63ZmkTx2mp6mxRtJBSqgZT426avRaNAuMf8a2pbFUH/IPLOZLD6K1
         3E5h/M8uzgEanX5iuCOhEyLPheNPzxR6z/W4tOrOx/WIFVTvoC7zQZLOOiZMG23cvpT4
         G14ldTe/VAq33IY/ZT1lmdHskxgv2rLQctvnbK90vqjeKU+X/fDMPoQhOqctwJPH7gk0
         7RwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XVMykQBy;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728296752; x=1728901552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N1bxIz7JUPlLORnsc+P/3cBO5Ik6kveSSXJJt+oinoM=;
        b=XCBHSo5hncFIEDOppRPQtKMhmbGfMtTR/98LvY1VRQ4XcRAc/oNE0pe6/y9rHOOVUQ
         7wWjO5bOcMJz+txie5JN0ee8MTrrrPCG8s9ugunC8nUZIsM0U6kNURmDJwH7yw8w0+t8
         WN+rKK4WnZvPUICYhkQZHd9CCwdACO6F5Ovr/e+p5+mNSIgkr6dAg4sib0BACztAr1HW
         EgW3jlAcTbtt0TPvwcpZTMZtjyNrWGilEOHtGpg0CAgy5svGIpOUNiTh6717RXnONnGg
         N8lNgj216xL94ilwj1HjBagv5FtI7HVXEOdS/uukqnq7IcZi/DVGJ+f+7RIqsXXAtcZT
         uuEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728296752; x=1728901552;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N1bxIz7JUPlLORnsc+P/3cBO5Ik6kveSSXJJt+oinoM=;
        b=wepA45+8eEpCh/iFyoSS3NBU1daJFvQRdiioCK2uW+jFX8JBLXK0Ig4SBpXJmrD0nc
         +7dnrezE/2ZcCNMh1S4GZ6OMFOzJ0H2RKLzdmQcde9CBIIKyc6P4jQjOs2aGjayMgK7l
         WD2PbSCx2VAd5hAjO8XmkdH4BpzToXqZ6NaN17Nt7VDWumNCFH6Y/tZuHe8+RhrelEK/
         uAZRhlT0L1C3bTxLD9xrmQwTFoz3/BF0W6zemCvjKHh2FI5Y8gANkzT502WYiNqFcmVa
         ODRXSDUqrd+p3lGYVFHdm6hdi2Wd9fnNk9Glvl/WRpi7CRrMlrOqMErs99+D4hMbGAFz
         hwPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBbi55Y1s7MKPKTDNPzKvrSl7/ufHnI2TvtsgXIiFOoowQrxDB0CtiQd9K9UEom1ma0zrkcg==@lfdr.de
X-Gm-Message-State: AOJu0YyLQHO1TreZzETeZxmhjO86j9GugmksB6suDjyZ0KhaXtDrAu0Y
	Cq+OivVBPJFEjn7tCkdClSTnZ+i98R4xWviTPYiHyJvMXZYw7EoA
X-Google-Smtp-Source: AGHT+IG3xgQYBPViRH+M30ySFmpBGxVYfYcKAgUzl9sILpA8Ej4bbzFneaFvw8uZFGdS6ViO/HHxFQ==
X-Received: by 2002:a05:6512:3d22:b0:536:545c:bbf6 with SMTP id 2adb3069b0e04-539ab859f01mr4871791e87.1.1728296751548;
        Mon, 07 Oct 2024 03:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:31ca:b0:535:6cbe:dfe3 with SMTP id
 2adb3069b0e04-539a638ae28ls847198e87.2.-pod-prod-02-eu; Mon, 07 Oct 2024
 03:25:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUq3GmRWbUpHQakZawl6vCeFuvwbm28GwaH+RNkQv0cWs2zXlg7rQP/dx2dpbC1ijxg3C0pvmTHBLY=@googlegroups.com
X-Received: by 2002:a05:6512:e91:b0:533:4676:c21c with SMTP id 2adb3069b0e04-539ab9dd1a7mr5206787e87.44.1728296749455;
        Mon, 07 Oct 2024 03:25:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728296749; cv=none;
        d=google.com; s=arc-20240605;
        b=a9bsnX1HcmGSAr4K/8/Sm0bSHkInqqCBombUsn6r2ftGpTSACJFLjh+99Q9MWEpkao
         LPqMZdT6+Ea5ii5wvzE4Op51e7M4Eb0IUq8uBXFoZ/H7UCObCkoMojOAzN6AKiqvgdGC
         Kj6My2fYWK2MKcikFNOobz5TiJANIc43yo3pW9E3Rv9lDs4Dn2pa8m4/m3mFG3sWtwOr
         VxvfUmFOOsMRPhGjFTalEUbD08naq2M7w0k6tXH5U0+JSQBQvjLj1CP4KMG1L1ZtVih+
         dtD0BAAArq/VG4svDts7cQH8xRTjWA+N8g3OkECWAfn+YqQIAPIKe2IPXXD4pE/SCS3m
         7ZsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Tq4Mh1/pERBmTxuuNnLyUAvp7YHaFtdyt/qPZp7mNMc=;
        fh=z5KWD29UKGboHkUZfws7F9grnvcetLBr06Np1nOCEu4=;
        b=g3CnhTwrjLuAZuogYoDSjEDMC1UJS7OAkMw2xNyrUSFAOrPrXhmZTTqkolQM8MXNMu
         OWOcGbgpW04lgLu81Z98+mZBa1vG09MVL4kQnE3RdMMBfC3CwF/Vr+9EzvMmPBH62800
         bY2hR8XziPC6zu6TdruW50cReK+9L5eiBlDLtxuEcYOrFsdvBJ63nsij94miuHwBvoTP
         vjaCiufN/5ByArSmL0EOCM2DMTUwELZwKnpU846Qn+AAAj97wndwIE01Rdc5W6ICeoW+
         MihAD8EoVyXHDJqyiy3WmtdStKwW+OcRw0DQC++vNY56Xhz2M5l9DJSpMpJG0PZXySB9
         Hb9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XVMykQBy;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539afe2fd1fsi98295e87.0.2024.10.07.03.25.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2024 03:25:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-2f75c56f16aso41480821fa.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2024 03:25:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVz9uPPmxHaxiKvwD311DCnp38kY854DqCMr1GUTyB6zQ9HroP0iRXr+Skmp9f9KzcGUGwgruPp2uA=@googlegroups.com
X-Received: by 2002:a05:651c:1548:b0:2fa:cf40:7335 with SMTP id
 38308e7fff4ca-2faf3c28d38mr49821001fa.19.1728296748894; Mon, 07 Oct 2024
 03:25:48 -0700 (PDT)
MIME-Version: 1.0
References: <ZwNwXF2MqPpHvzqW@liu>
In-Reply-To: <ZwNwXF2MqPpHvzqW@liu>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 7 Oct 2024 12:25:38 +0200
Message-ID: <CACRpkdZwmjerZSL+Qxc1_M3ywGPRJAYJCFX7_dfEknDiKtuP8w@mail.gmail.com>
Subject: Re: [PATCH] ARM/mm: Fix stack recursion caused by KASAN
To: Melon Liu <melon1335@163.com>
Cc: linux@armlinux.org.uk, lecopzer.chen@mediatek.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=XVMykQBy;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 7, 2024 at 7:25=E2=80=AFAM Melon Liu <melon1335@163.com> wrote:

> When accessing the KASAN shadow area corresponding to the task stack
> which is in vmalloc space, the stack recursion would occur if the area`s
> page tables are unpopulated.
>
> Calltrace:
>  ...
>  __dabt_svc+0x4c/0x80
>  __asan_load4+0x30/0x88
>  do_translation_fault+0x2c/0x110
>  do_DataAbort+0x4c/0xec
>  __dabt_svc+0x4c/0x80
>  __asan_load4+0x30/0x88
>  do_translation_fault+0x2c/0x110
>  do_DataAbort+0x4c/0xec
>  __dabt_svc+0x4c/0x80
>  sched_setscheduler_nocheck+0x60/0x158
>  kthread+0xec/0x198
>  ret_from_fork+0x14/0x28
>
> Fixes: 565cbaad83d ("ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC")
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Melon Liu <melon1335@163.org>

Patch looks correct to me:
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>

Can you put the patch into Russell's patch tracker after some
time for review, if no issues are found, please?

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACRpkdZwmjerZSL%2BQxc1_M3ywGPRJAYJCFX7_dfEknDiKtuP8w%40mail.gmai=
l.com.
