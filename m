Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPEDU76AKGQE4HZNWFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D555D2908DB
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 17:52:29 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id e1sf922146otb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 08:52:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602863548; cv=pass;
        d=google.com; s=arc-20160816;
        b=lDNc90cGSg8mYNM72xf+f3kH5vmpRDA+VP63qc/NP6gtqNRx6iLFii9DcyNMpIDcwz
         huhJsbl/6trnViboGhdlnCcDrbYZUlf5NdqDGoZfBl53u/c48lZegTg7RPFjkcjFo0fe
         JWbPhEuxVeflYqXYE2f89RKZe3VyaYlrKP3ur6UTc3dcq45Ek6jh5hTT2JoO1T59mArQ
         uZXWQVcGEL3tgfTnMh2GCjeLPy71vBJEfdzEPrHuqWYcs4PBU64mgNCBj9+37mG/GqnW
         wcLDWdmw94iFJR4RRuPSQNoQdlc6sHzts2wcUdYHUtmXpgL2UscEwQEXwrO81ra44cE7
         2K+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U8iGxeqZNwJuqAjV7+VCuYzSycJlM9qKn3608I/WXZs=;
        b=iiyRGF1busesGcmJhdd0h1iM4k7Ts4miixaP4Sw7Sux4BQcM3rzQuj/KBD5OPRq8WD
         UAd+SSx8EwZIEI/74SrD8PR1LqUvgjKErs2ekTct+0SgN6JI+1LRXFRUlmKEnXhzFGGy
         fbTqIgtgdVxmsRN+559LpcqLZ/0WLgov0qfyhaewxX7ShgT6tDGTilqfsLDeU9x1HvZM
         qSlQukLX5XFMTJB2AZhbjIZT1YHnyN1iIH2irrkM8GTf9AZ9f/9v9TWgkdoG7ap7f44b
         vNIzhbCdsf8NfE4qzvaxsWQIOyrwn5XHMbQp+ClFysNaszUut3w1YjVqXqgYRDO5Se3F
         qxEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iyAo2KZU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8iGxeqZNwJuqAjV7+VCuYzSycJlM9qKn3608I/WXZs=;
        b=g3iVcmhQisMCrHQTe10vLIKitw/bKBL+T2LtjwvgXz/wRIn/BC6nkTvTmkpdq33rpL
         lC2bk+/AYpsFP9Dwxfqickqvj9wzmCyPqCVY5ab+VRdE/L+ORvORN/tvfH08yC8B8ICJ
         5Z8guvF0XrWTSi/zeAR64QXDmOnPTT+sCrOx/a0QbplkJVAR/l7vQhzLACK4YSLRjR4V
         ddyfBXxrvb1EZiGxi6dzfxru2UUOq5DuoGzfE+0wPkAWihXHY28KhdRiiF6SR+EnX/4m
         AgRsioFdZa7+LPsxwTiR8WzwEONkY7hzFoB2Zu2vSCx8jnEzZAPUPbZsW/FgUyWnbwhE
         sBxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8iGxeqZNwJuqAjV7+VCuYzSycJlM9qKn3608I/WXZs=;
        b=ul7dIOVg9u86QxWjPOkX9UWLNePV38Z/w1dRAr83A96DahcU6a0/ranwmjh6Q4TfVM
         8UpliUCm7wGyzQSw09JNzIK1Pk8eMlfyVt83LqRBQ7nw/sjTRTXIiZC25A7nBHbFzBLt
         tTvdnrj7n+a4UXOUvyUTNTpXeQuA/t6ipwWDZ3bkSKdHI+AerLgoohTeAQDTA2R2HUOd
         YjXEorjPtBVfcvv8SgaLJSENeIVEqsyLLhCFHTbuaeLbaguwita0neMnxWTicaFiLhHu
         yW456ch+qxcxqmhmJCIpint4DpMorQeVE6Q2Ur6/tbbil+mL2C63T59s3ObMO1L8IwWy
         O4dw==
X-Gm-Message-State: AOAM532ApK8h2mDrg+mdVKyeFIzywcXDq6tp1GMn1ookaMxOQbH+5XXJ
	DVk57SVoxyaCEEmDS8v3zkA=
X-Google-Smtp-Source: ABdhPJxVXNNBa3CE+ua1isYiz6Jxta8nGZkcAC3HHXetm0gCZERK+6+njEa0M8MDpMNBY9z6aX3fIA==
X-Received: by 2002:a9d:68d9:: with SMTP id i25mr3123134oto.11.1602863548731;
        Fri, 16 Oct 2020 08:52:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls722753otk.3.gmail; Fri, 16 Oct
 2020 08:52:28 -0700 (PDT)
X-Received: by 2002:a05:6830:4033:: with SMTP id i19mr3249944ots.127.1602863548407;
        Fri, 16 Oct 2020 08:52:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602863548; cv=none;
        d=google.com; s=arc-20160816;
        b=jzSroE+nr5dNGBemJLyvuHD6t1S+fq8VphV/lsA7eqdg8fiECoH7Ecx6UDM1C0F20O
         wDsJlv24DQhMLLkpc9SWWE0a/AHZ7upy18Odg8FekfrUTAe27P3+1Mz8MWaezmk4ARnF
         7XsFyAcvZJg8boCt8LrOCoa7zmJ94wvko6t/gA67WqThjsVZ/EuJ7myrz3hQFGEECmIp
         XUcVsyQ3lwX5AHKiD6awrAMuEADsX41lDj60lYnbcvPdtScmNpelyMFoX/UxfQRXBQAW
         hu08noJXEHNXcqIKkzYfAAH2GK0EjyA0Kb9AzUe4cyi8oQex4UCb8IymI2/kmNrwflQI
         /cfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=571s3sQDBAJDkliF7o6LeQ1FWJNszmME0SBRVCm2JiM=;
        b=Mir7PQE4X7pr9ZZSNvHDEocSVE2KKMTtR4COhSSZRD2rdw3461p7Ialdkidewjo5r2
         9O4g7UCLwF4XQF/J42vOgV3a7CaPC3x8ntDjblbRZd9yzikDQleZx5xECWKKmVNjLYd2
         3mBLUNz+bL0IV98JndT5sPRJF5FbvM3OhxbmXsLfllGGTPJxgITlQOgrYUhjQ20rO5Vr
         m44I1IrMy2+BysCw4FeNWzKT2lr3ccbTXX92kD24lrQ/xEoZFzzx4eowlKkrjN9Ok3wZ
         fpzU6lytYu4xhc3GwRMmnBYRgpwVZ2KGWvd4kAvsXy2ZrxmVqEKMSZagaEvXmbC8qaWe
         nSUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iyAo2KZU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id o22si283552otk.2.2020.10.16.08.52.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 08:52:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id p3so1269911pjd.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 08:52:28 -0700 (PDT)
X-Received: by 2002:a17:902:d888:b029:d0:cb2d:f274 with SMTP id
 b8-20020a170902d888b02900d0cb2df274mr4625974plz.13.1602863547567; Fri, 16 Oct
 2020 08:52:27 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
In-Reply-To: <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 17:52:16 +0200
Message-ID: <CAAeHK+wo2UE5JqHfui5o08pUPCFZPQTXKeicE+dTjxwj_2euww@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Kostya Serebryany <kcc@google.com>, Serban Constantinescu <serbanc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iyAo2KZU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Oct 15, 2020 at 4:41 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
> > This patchset is not complete (see particular TODOs in the last patch),
> > and I haven't performed any benchmarking yet, but I would like to start the
> > discussion now and hear people's opinions regarding the questions mentioned
> > below.
> >
> > === Overview
> >
> > This patchset adopts the existing hardware tag-based KASAN mode [1] for
> > use in production as a memory corruption mitigation. Hardware tag-based
> > KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
> > and pointer tagging. Please see [3] and [4] for detailed analysis of how
> > MTE helps to fight memory safety problems.
> >
> > The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
> > boot time switch, that allows to choose between a debugging mode, that
> > includes all KASAN features as they are, and a production mode, that only
> > includes the essentials like tag checking.
> >
> > It is essential that switching between these modes doesn't require
> > rebuilding the kernel with different configs, as this is required by the
> > Android GKI initiative [5].
> >
> > The last patch of this series adds a new boot time parameter called
> > kasan_mode, which can have the following values:
> >
> > - "kasan_mode=on" - only production features
> > - "kasan_mode=debug" - all debug features
> > - "kasan_mode=off" - no checks at all (not implemented yet)
> >
> > Currently outlined differences between "on" and "debug":
> >
> > - "on" doesn't keep track of alloc/free stacks, and therefore doesn't
> >   require the additional memory to store those
> > - "on" uses asyncronous tag checking (not implemented yet)
> >
> > === Questions
> >
> > The intention with this kind of a high level switch is to hide the
> > implementation details. Arguably, we could add multiple switches that allow
> > to separately control each KASAN or MTE feature, but I'm not sure there's
> > much value in that.
> >
> > Does this make sense? Any preference regarding the name of the parameter
> > and its values?
>
> KASAN itself used to be a debugging tool only. So introducing an "on"
> mode which no longer follows this convention may be confusing.
> Instead, maybe the following might be less confusing:
>
> "full" - current "debug", normal KASAN, all debugging help available.
> "opt" - current "on", optimized mode for production.
> "on" - automatic selection => chooses "full" if CONFIG_DEBUG_KERNEL,
> "opt" otherwise.
> "off" - as before.
>
> Also, if there is no other kernel boot parameter named "kasan" yet,
> maybe it could just be "kasan=..." ?
>
> > What should be the default when the parameter is not specified? I would
> > argue that it should be "debug" (for hardware that supports MTE, otherwise
> > "off"), as it's the implied default for all other KASAN modes.
>
> Perhaps we could make this dependent on CONFIG_DEBUG_KERNEL as above.
> I do not think that having the full/debug KASAN enabled on production
> kernels adds any value because for it to be useful requires somebody
> to actually look at the stacktraces; I think that choice should be
> made explicitly if it's a production kernel. My guess is that we'll
> save explaining performance differences and resulting headaches for
> ourselves and others that way.
>
> > Should we somehow control whether to panic the kernel on a tag fault?
> > Another boot time parameter perhaps?
>
> It already respects panic_on_warn, correct?
>
> > Any ideas as to how properly estimate the slowdown? As there's no
> > MTE-enabled hardware yet, the only way to test these patches is use an
> > emulator (like QEMU). The delay that is added by the emulator (for setting
> > and checking the tags) is different from the hardware delay, and this skews
> > the results.
> >
> > A question to KASAN maintainers: what would be the best way to support the
> > "off" mode? I see two potential approaches: add a check into each kasan
> > callback (easier to implement, but we still call kasan callbacks, even
> > though they immediately return), or add inline header wrappers that do the
> > same.
> [...]

CC Kostya and Serban.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwo2UE5JqHfui5o08pUPCFZPQTXKeicE%2BdTjxwj_2euww%40mail.gmail.com.
