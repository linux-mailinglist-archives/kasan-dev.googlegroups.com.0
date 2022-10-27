Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPWD46NAMGQEWQUUKKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F17F60ED87
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 03:41:20 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id o10-20020a056e02102a00b003006328df7bsf258032ilj.17
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 18:41:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666834879; cv=pass;
        d=google.com; s=arc-20160816;
        b=YftJhZPVgQsNngQVydloUbiqfrzegWeBgM6eqFgouGmAPqrYDyh0EW75y0Gd5lMsh1
         jicadJhkzuueRIhjlINMZyeNsO0HN+CYxgSv+tAcrEhvUpqY5Yf0vA86bFnoISu44JA1
         fIACtv+tq0OIh3lY9Huvayzf1zOAmP+pOUbhLscPHVx+fOaJlgPwzzx7/N9awpy4AjmK
         5lFRew2Jsu6DRjsOPbJ/YjsvRjJmcKdVITRgkOitzDwtFPFYErTlSs8K54aWwmWFofJE
         JAx0Vf5Llt9/KCnZM0MfnIU5k8XSSrilx3jt0p0Nqd3QP5JoAePpIyTxxXff+mPWd+XV
         Ks6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IRtaKy4LSPqXGPaLV8uV2kXJ5UiCcwRcQpXq8NdruZo=;
        b=xSM9xktgmJ0MukwD+lC4WBaSSgHlRERmTz5F2YtWZStwzBiIuFPoi0BVSywii35hXe
         p5xnkf/wluZ7DgznazvfHte7zZOM/aeKo/2I/wpKBnqYi9ylWQs0M2tyJu3FhwdWn++W
         OPVWZy+TxtG4BbAsGl4KN5bcUdTQLOGaicj06xWo89WKF0Pe/t56h8tX2sffSTSvLav7
         QYPnB3poq2X9MAQF9TCtuGlt8WZ11z47sRwMDXJAPxw5ARdiCorvj5JW59MQMeHD2UNN
         bA+TY74ZAuK7l16zou9VsrSV+f5skOTOPVYNEt/pGQEezgbzaqUi7ATCTNueJUbOaWQG
         KZzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TS9VMOtL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IRtaKy4LSPqXGPaLV8uV2kXJ5UiCcwRcQpXq8NdruZo=;
        b=WZvXkxCUR9KZV87R+I2U0+opsxztO7osq7f8oHSYSJGZ8h1aIvD/RlOWG1O2rvsoI5
         c1JDICMx6ZqNDNjnZG2gg2zzo1eyf/5WVSFtAxiyajuM2C4whBcFcJVSz4/b1VZ4WUuE
         Vo0TQwsxMn79ENGkHpwtEKbjyHwKOIH6Li1S85ju/jyWf0RSq6GgKo/1rUE3uMq1Wg+r
         aAXaRT1H8WQUTQsLViCFKcbe7vW3Ok4Gjg/RNVlzEqoSYSi9r8BfzMtaW2S9hxdRO13J
         wgC/u7ayzR3OAZ0x+2rdp90VDIAHph2nbtHw4OogdxJ2CRIZ3MCv9ZA1ZfFQSeJ/3hg8
         Yp7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=IRtaKy4LSPqXGPaLV8uV2kXJ5UiCcwRcQpXq8NdruZo=;
        b=Wy92JKs+cS41YjextRJWkeo98jxHnInpealKrES5Qt2g7+R1LxSb2wZPHHwHuvKxJ2
         mzWRUBHgv3C70NznYLaezTjUhtCdB/VNK0OZS+krP/HURmWK+mUMfAnLN8rMCWjO6MHI
         uOcUYOJy9qMx1WtgsDsuYXZ2W6edXmS72jQfDSWB4aXWuTdt4nZnXki87iyDG6zo6hwF
         jns1iPk5G6auhbxmFlPsOTrbi4BfMHT/whgLWi/6use6DyjE3NLck6sz35Pto19F2vz9
         bqp4a/tJZFw/5+rSmKV/TQrx2eMZFB8DytwnQpH01A29bqw4A39EIZGNVMr/OjgPeJKF
         PXEA==
X-Gm-Message-State: ACrzQf1dEe7xpAd1yo54OKNw8GtlMB8HKCURX1jGzCOAIuwR9l39OCo7
	vqlvddDyNK8JpzHr89EVijE=
X-Google-Smtp-Source: AMsMyM6EbIQ6A+tERIqqgJdjo+aCXEAw1hfyIXCT+qs3zoS/V5fmioHFi5Mu8W9KUyxBOcGQMeVdiQ==
X-Received: by 2002:a05:6602:125d:b0:6bc:61ec:29c0 with SMTP id o29-20020a056602125d00b006bc61ec29c0mr27900128iou.81.1666834879004;
        Wed, 26 Oct 2022 18:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d03:b0:2ff:7d6b:f9a with SMTP id
 g3-20020a056e020d0300b002ff7d6b0f9als3484163ilj.5.-pod-prod-gmail; Wed, 26
 Oct 2022 18:41:18 -0700 (PDT)
X-Received: by 2002:a05:6e02:152b:b0:2fc:43a:1d10 with SMTP id i11-20020a056e02152b00b002fc043a1d10mr30039922ilu.237.1666834878376;
        Wed, 26 Oct 2022 18:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666834878; cv=none;
        d=google.com; s=arc-20160816;
        b=vRF8WL+bvQi1Gs7RmGaamXdtQKJJnKJpt46UWSBuTe29fbJGnjOheGVx5eN69JbO1p
         iHH7wjAl10V9RHrga8lVyHvePbK+xyULJKllmbh/0/2t0UudbPmwMkh/XNqR4FqeigmX
         uoNm8Shjvq58bW6LqOiOloEsRhuovMTVloOpGpbTLFp4QgBvH5cL2hSsa33j1np4A14Q
         6zHdi6f3uUIMCZtuHLNJBj0iMUbiAzeHrY03fJHlontaWXrfR6pvWKupPwAaXJaNJNof
         9VrqxszwvPJJDYG6mEIm+2JZ8hdofxeKdkW5iwsshqZZPFps/K1LBgoPgI0lAdS5SdUS
         Mdfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZN1sjqfDbSU4YpXqJaq2AYTuLBvoYcLhcoaOncV+3Pg=;
        b=NVrVTiXSwfxHOMO7XNxDCItA9u7Jzos+jYVrwRNRU67yHLr1gJnD5QPLscjgb/MKEw
         KGb7NA5uPYu7OyE2UYWpHru3oNDbhak/6iMhwlOCSC2W5NnIfzganI1jdVdA6L/OMVbM
         BZ1W59/nAvr6wyyYFzvdfgh+IuN7Gbhe22WTOkNSXDzrwkGTYPu68VP6eiB2Hc38/Jpy
         hWWUuKZGN5HxdIFFOp9ybt033RElP5GtOPhs5ApFimrZTlbI3r39gjssNUgyKzur5kUp
         OAOxmN81UzWfrp46LakATsf8nRGkKw9dWrhOFh87aTvqCJ2KjaffREi6gqCjsYje3B86
         lyKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TS9VMOtL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id w22-20020a056638025600b00371d335d40bsi3870jaq.3.2022.10.26.18.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Oct 2022 18:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 187so84709ybe.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Oct 2022 18:41:18 -0700 (PDT)
X-Received: by 2002:a25:7b42:0:b0:6ca:1d03:2254 with SMTP id
 w63-20020a257b42000000b006ca1d032254mr33497724ybc.584.1666834877962; Wed, 26
 Oct 2022 18:41:17 -0700 (PDT)
MIME-Version: 1.0
References: <20221026204031.1699061-1-Jason@zx2c4.com> <CANpmjNMmHa04Fqf5Ub5-vz6HuqT_Gg8GmEfKD6rv8JeMfBZ32w@mail.gmail.com>
 <Y1nQJ9ZFizv0bzgI@zx2c4.com>
In-Reply-To: <Y1nQJ9ZFizv0bzgI@zx2c4.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Oct 2022 18:40:41 -0700
Message-ID: <CANpmjNNWaRCOC1=3FE75VWQ8B49RBS6208+Cr9s7v2wBkW6pMQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: buffer random bools in bitmask
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: kasan-dev@googlegroups.com, patches@lists.linux.dev, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TS9VMOtL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 26 Oct 2022 at 17:26, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> Hi Marco,
>
> On Wed, Oct 26, 2022 at 05:04:27PM -0700, Marco Elver wrote:
> > Is it to avoid depleting the entropy pool?
>
> The entropy pool never depletes, so no.
>
> > kfence_guarded_alloc() is supposed to be a slow-path. And if it were a
>
> Ahh, my huge misunderstanding, then. For some reason, I was under the
> general assumption that this got called for every allocation. Given that
> this apparently isn't the case, let's indeed just forget I posted this.

No worries. Allocations via sl[au]b are "sampled", i.e. a fixed sample
interval decides if an allocation is redirected through KFENCE (the
lowest sample interval is 1ms, but that's generally not recommended
anyway - default is 100ms - so if the system is busy doing
allocations, every 100ms there's a call into kfence_guarded_alloc()).

> This then means, by the way, that there are in fact no fast-path
> users of random booleans, which means get_random_bool() is totally
> unnecessary. Before I thought this was the one case, hence open coding
> it, but luckily that even isn't necessary.
>
> Anyway, sorry for the noise.

Thanks for clarifying - and good we sorted it out. ;-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNWaRCOC1%3D3FE75VWQ8B49RBS6208%2BCr9s7v2wBkW6pMQ%40mail.gmail.com.
