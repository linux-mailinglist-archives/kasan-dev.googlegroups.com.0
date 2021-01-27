Return-Path: <kasan-dev+bncBCMIZB7QWENRB5HKY2AAMGQE5PG5G6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6242330638F
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 19:48:22 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id y187sf1841392pfc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 10:48:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611773301; cv=pass;
        d=google.com; s=arc-20160816;
        b=KRNSzizCsTj5tddaZTyMEhxTYjrPdFGB1N9WpBM/Mo3fsJN1LUxOu85sw73ZGVY+HC
         ym14hwVJ4eRVq49dH691jbHwohyv0nFpLy4sq2WDfvydmxbxnyUAHV1VvTbUN979vqFA
         5eaoTKvfLj7d4CtUseskTx6/GwuFlDMVeFmi1ZdyMM6UgzHR/n3uTTwxlC6QSpBZ/Kma
         bDKAgCzvARJbAmiK9M37umgmilAfUUlpglY7E001nKseJAZBnA0myDDBs6IjyGMMcyRH
         Z6PIpp7+azJ0ZCvuhRJfGvTrixUmdIQXweTTSYWdwnCPwkOUOuFBLGHk8MJdn90+mxRp
         AEug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t27pqcdahe+Xml1AucBwvjAvaqmCnmdHQ7OzXbVKifg=;
        b=JKgIQzfLObr+3uO0jOCBB18o2DrxlU2IXpRgl5dh2sk0K4pvKABO2iS5SoKtQt5Q/t
         7dm1m/ThPbjMQRqCf/DS9hzbqxGWSvU2409ednUYUM4U3RZHs5zPZpczry8Yd+exy0Xx
         BMI9rivyhiYHQHobf30mvwMWdvICDlXFCSYEw1xjaYBgjcOtLvDRcPMiEqjTfqCFPCUu
         VIaLPuTm+KZTLzcOCAScbKWgeR8ovGfdaKcEfWg+ClVlZ89Tl+/9SJZwjAYRpNWVXAgr
         8FRXqgToad/h8ecCHC85at6zeRubAdmvLke+lip0Vtb5n4jBEItkNrw4C+CBbbYodpD7
         AG4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uzIRLSc0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t27pqcdahe+Xml1AucBwvjAvaqmCnmdHQ7OzXbVKifg=;
        b=rWDSaYkcSfltACX49xCM+Yn/lGChir95aZD3zjSEzeumI11m69gDX4Cr6lD3fw1XZI
         7gVTjE0qySxzlZ88bcACbi+bsdXrQ+W0STatHC6RADYYIUXU5ziMV9UiLFinTfLp98a2
         /gUM0e471kyW1ut7ct7NjkMkwXmwBn13k72kWQhcyUUWRrxtwET1YFXl2Z1R90XB7gul
         n/yl82cVsJgDXU+7dvmg1XVBwenaozpRHUQgC/gDsNliURgFXPPy3p/kNXThmNCOIMLL
         gm0joxF0FnrpipdLAW5r6tsS9ReeGTV6ymIAi/JZ035p8rcdVhGwU1t+AbPvrhOofyQF
         Rlfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t27pqcdahe+Xml1AucBwvjAvaqmCnmdHQ7OzXbVKifg=;
        b=l2IL//IAKzFrUWVymVVUybNnBZse3pK0t4bC3dzeB425vTJYCZa7pURROw1jhxsTQB
         5+nY5vfBl/De7y9f2bhDKAJdw3VS/L9oO/NTd0UbQJqngudAoMPscGtPPVv1FUdo8nA7
         JRtFRHwn4rERMutXLRYuigk6/vR/dybKrG5SlDi2Qk2Jq2wreuPSaaUDYG70N6ku9uvv
         8qe3rASS5bQH5aTjX7LjVH4sqGAJbFzVbRM8CHTloDFG7msUvPfUdcfWLavaIPXlHgsx
         ye1wny2Dhud3cmuaasyCYQhd3t2kJ/AyfZxjHP1BW3XNBTuc0D0DB3Zx9Ura/PnFVS9c
         rXbA==
X-Gm-Message-State: AOAM533ZvI95frK966MU/Hz7iYa70TtOHUa6C75d9gJp5PbgKNl57pBo
	RwK8UN9Z3RWK5MSoOlA2UXw=
X-Google-Smtp-Source: ABdhPJx9M2ksbhwFUbapB9wq/g9FIFtNoXX/pZGySrbtzizvUKqjpVm3C1lEsqGvdH/vb7w+/1WM5w==
X-Received: by 2002:aa7:9834:0:b029:1bc:8866:e270 with SMTP id q20-20020aa798340000b02901bc8866e270mr12035912pfl.17.1611773300959;
        Wed, 27 Jan 2021 10:48:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:550b:: with SMTP id b11ls1537323pji.0.gmail; Wed, 27
 Jan 2021 10:48:20 -0800 (PST)
X-Received: by 2002:a17:90a:df46:: with SMTP id gy6mr7003155pjb.163.1611773300367;
        Wed, 27 Jan 2021 10:48:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611773300; cv=none;
        d=google.com; s=arc-20160816;
        b=sa9I26O4ZsO0BFPBuUZJ4Ofz+E4WmaBU00ENbK29peLszk+Ont92Z2clC+aroGvqiy
         u+0WwbVJu1yQoaN9S/HwPmLPdkD7lqNYr2F4tSmZfrgFvKKFvFAvGKokJhtqK+KadUj0
         mpF7qOA+hILIypJs4SiaeL+wnttoL15G7sdXLaN5N/CsfpTuXuHrT5Dc+SLJ6f4qbSsd
         wcLMDRqtTjBOUDL/GJZb0xbRqtckuWcghi559xhdaQ4U0Q2kpioubzMaE5JImFj4SqQg
         nanfaCn5aXeIjGfRNgleeH4fd1GzidlCE44jtJdSDD2S6Xg/YFZq+l2lgT5Izin6BNX8
         tAHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EUEoIQ9qWT1kGbtvZ5eDvB5BPzX/7KNE3wZ/wAEqoFw=;
        b=MYU5JRgercqpExej6jClrBi+EdX33/SivdJWj7jkU042EVxLdzBFr2zMb54yUTzv8U
         sOgJxySG0a+Rxg+fblyUUb9uVYUtjjPK4ts9bphibrzuEYhBRcfsfQDsAl9m6Na9Hvr9
         +mUvwweFuPP3qj40EQUwc3hiRMnkmHi3XcSwsbc/SU18MFpLxV2l+ux0w/hS2yEXeJNN
         3c4LE6bW+5NwO2sN9zOgNy9VIWKye1ojUK74Bt0CcGcwywP7Zp9+MgM95P5AuqTeMTC+
         cd1Pv5/Dou4QosNDkn+iN3jEz0wyU6gDoz9JOJjF2tC7y1OyG+pEJv/PKpXAM0CBdbKE
         sfCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uzIRLSc0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id t9si342906pjv.2.2021.01.27.10.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 10:48:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id a19so2793654qka.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 10:48:20 -0800 (PST)
X-Received: by 2002:a05:620a:711:: with SMTP id 17mr10862573qkc.501.1611773299798;
 Wed, 27 Jan 2021 10:48:19 -0800 (PST)
MIME-Version: 1.0
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com> <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
In-Reply-To: <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 19:48:08 +0100
Message-ID: <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in ibft_init()
To: Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
Cc: George Kennedy <george.kennedy@oracle.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com, 
	konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uzIRLSc0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
<konrad.wilk@oracle.com> wrote:
>
> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
> > During boot of kernel with CONFIG_KASAN the following KASAN false
> > positive failure will occur when ibft_init() reads the
> > ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
> >
> > The ACPI iBFT table is not allocated, and the iscsi driver uses
> > a pointer to it to calculate checksum, etc. KASAN complains
> > about this pointer with use-after-free, which this is not.
> >
>
> Andrey, Alexander, Dmitry,
>
> I think this is the right way for this, but was wondering if you have
> other suggestions?
>
> Thanks!

Hi George, Konrad,

Please provide a sample KASAN report and kernel version to match line numbers.

Why does KASAN think the address is freed? For that to happen that
memory should have been freed. I don't remember any similar false
positives from KASAN, so this looks a bit suspicious.


> > Signed-off-by: George Kennedy <george.kennedy@oracle.com>
> > ---
> >  drivers/firmware/Makefile | 3 +++
> >  1 file changed, 3 insertions(+)
> >
> > diff --git a/drivers/firmware/Makefile b/drivers/firmware/Makefile
> > index 5e013b6..30ddab5 100644
> > --- a/drivers/firmware/Makefile
> > +++ b/drivers/firmware/Makefile
> > @@ -14,6 +14,9 @@ obj-$(CONFIG_INTEL_STRATIX10_SERVICE) += stratix10-svc.o
> >  obj-$(CONFIG_INTEL_STRATIX10_RSU)     += stratix10-rsu.o
> >  obj-$(CONFIG_ISCSI_IBFT_FIND)        += iscsi_ibft_find.o
> >  obj-$(CONFIG_ISCSI_IBFT)     += iscsi_ibft.o
> > +KASAN_SANITIZE_iscsi_ibft.o := n
> > +KCOV_INSTRUMENT_iscsi_ibft.o := n
> > +
> >  obj-$(CONFIG_FIRMWARE_MEMMAP)        += memmap.o
> >  obj-$(CONFIG_RASPBERRYPI_FIRMWARE) += raspberrypi.o
> >  obj-$(CONFIG_FW_CFG_SYSFS)   += qemu_fw_cfg.o
> > --
> > 1.8.3.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg%40mail.gmail.com.
