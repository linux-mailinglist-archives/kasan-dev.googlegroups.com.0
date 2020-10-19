Return-Path: <kasan-dev+bncBDE6RCFOWIARBBFAWX6AKGQE44LHGPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FEFF2923BB
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:36:20 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id v14sf4289380wmj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:36:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603096580; cv=pass;
        d=google.com; s=arc-20160816;
        b=c4P3bli8CSmJ6AtESFMKqeBiMQOh7Oer+tMOQlp4RmZh5o8ogp4H87EvCXMynBxOsb
         6RWyXtNgpZXjhB++w2hEqSsJnpAfsJgSTWfch35XGe60MtY4cCH6znGfJ5XtdaV4uO8O
         cbT/RQT6mNEO3viEZ9ownYDEcSyMmlqqlNzM1sM797YiyYv9AyvqaOpDTmbNIr/wslly
         UoTrV17VDpmWArw62ytb52c/8ZyM7CpJ5I5cV3fVsfC7tIRUQ30MyvXcB30D+PyIjVKt
         buSDxWui9HexuxpapEnbYhV1eBpShlZATdDSuxmD89K04XJEJP/4whn7RiIlo6cwF2N/
         9h/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=G3uoOxdqn+oDVg3iUgP7ntuMFgPAenmjtctCSOYnZU0=;
        b=FHQd8i5DRbwzkHxPPJN61eZDU+AtrOgJ62UJmF26ygWMYJ9jA5gfBTweqkSfJoEV57
         yon5kbm9QRyQ4I3rYP9afdsAp2GnV+3OIh4A63wleTRev/8uI/QhYnKekIGJB/cbor4X
         dJLFbAyawLWS+ldpwXKZzfGLKN98s37hLE3l8ZjRbAP1g/aGOjnmO7Ecrkm8UELX+yEt
         TIVPLdJYmKykxoPtR98GziiytEF+dVHDnyu8gG5cFsAS0vikZoVVeDAC2aZme4qEu8Yu
         iej5aKw4aoJZ1U74qE2sW83uO+YvZ+7TKMoNl0+SHYUxlvNgQ5VGdRfBmDxMgR/0Og4Q
         uqlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SBPN0dV7;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3uoOxdqn+oDVg3iUgP7ntuMFgPAenmjtctCSOYnZU0=;
        b=sQlHRpNLxg0Tdmh3SB14uKcbSsf1rVNgLZBDgvOL5qc+8cz1xdjqpMWFX02YtA7aDY
         9y8tduj/gBbbe7AHhSlq3ZNEVKbuZiUGMHj1MJKjFR3xoECwGHos99ruVjDbWE49QH1V
         jhW4zECO1KYFiUkVYDs5/sD7BDNbo8cAPZAe3LF5D+AE2teE6bRoofbIuECkE3im12Js
         9lyxYLHxze60pUrj1ApPEpiaQpYFZ0EL0EaHc4DjDSfqL6uTUkf0llGURlBMxKvpNE4r
         kjvLQ8DJXywUPSSlA+3O8nBmHm+P5QPPkzpeHC+YohEoLoLHa492lFAy4oKFNsPSXvKH
         1Ydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3uoOxdqn+oDVg3iUgP7ntuMFgPAenmjtctCSOYnZU0=;
        b=p3lVIC3+d1ulT4VDkwLwjIGoxSb6L5SRNBbDnHTfycFXe99rNtC4Q9pWBDIRnzualG
         ntddpOIsq62RoYeJzeiqOazq1XwdITsrrx0KFgBVUIO53nmt5UAeJ03D1JcCWSdPNYxT
         mvzDCimRjXaRHezY5sV6aTmJ03V6c7MVKIuLiWGJ/OM+MknWqhVxvsHhtM0tolVJN1Re
         Q7Jv1+UWhkeoJ+55+yFFIvdWbzqBTzWQP3/c9YlU+I4oWinOspzUEQUNvIt0X3pnNDid
         ayjspytPqUWQaYhtfdLso4Cc75aIX9w6ptBZWyGDOL0Ppys6yrKaAlcq7bg0h8MdsOkR
         Rs/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338wlrxjT8wnvMIvzNRUWb6o1lV12TZeQMj/stv+NrdNUWBr9ha
	j049o450OWzegv5GV/Np4Yg=
X-Google-Smtp-Source: ABdhPJznMIiZ+rDDadrwVbjFcfm6idw6sN4ShBXCc1jhMkgJi+CAJq/r7VrzcNc4QYmfiLqLArbkUA==
X-Received: by 2002:a1c:62c4:: with SMTP id w187mr16663667wmb.149.1603096580236;
        Mon, 19 Oct 2020 01:36:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls9306007wrj.0.gmail; Mon, 19 Oct
 2020 01:36:19 -0700 (PDT)
X-Received: by 2002:a5d:4311:: with SMTP id h17mr18974094wrq.398.1603096579419;
        Mon, 19 Oct 2020 01:36:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603096579; cv=none;
        d=google.com; s=arc-20160816;
        b=b8qco27hsCPPmiYY52fLYcrRVe5oJWBY7AA8oS5HoDghUvFFuOvATIf8F+ue2YzKvv
         YVfg15oHGoo/ec2OiuLXZEh+sxlRYgyvTg5G1wgyh+tYcgUQmIZ3Ly/NoMpFKOyO82LF
         hTgpWZO/c5K0W7vUvkTLtgdRCDLg2Q3QV5rV0+zX3MBkYMw8uEOy0C2ql9FINAe1wqxX
         iVQRS5zx2dlQN7Mt9gjhmREVBR1YEdrsfRsvps8Gq7f11/RwKQgO8DyA8UQ1+V5zZ08/
         RMJdMIDkhD1TqUgeZiuGZGhiG6hGS470dtsspUktKOk7RuSuoBDU1Gc/6HWkfnhE8z9g
         gtAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SPqHC2ZFzy03MruidpFtClPPaAnAKHtdRheoWl9M8t0=;
        b=0TUbeLrfB2MVKDIwXjP1WSb6SQua86moOPaeq43r063zFARHfelMGHn/ihdgy8ocXI
         LO0AUcHexUF268O61llveEchqxFcWR4q9HkRrQGXeGz+My5KjMD/cODRftRYHzLKfqf0
         T5u406LPAF4GrNXgPVeo+JfiX44Pcd5jj6iZKvyde3CNhuSX2CGPEdyeG9W02wr3+gTG
         Y3V/+IiyAKeXi2ZuQ0mjW1FuVkzXW2kafBBkHEC2XJ2X0MyFFMSxRamgCiwJPLdSx3hR
         grJXUuQA4iJNBHdTKpmFRVtQcRjG9x/TdlMQhYx5AlDoubCDPxIxVB9q02ZJfBPtH8ur
         O1eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SBPN0dV7;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id o4si143219wrx.4.2020.10.19.01.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:36:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id h20so10987855lji.9
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:36:19 -0700 (PDT)
X-Received: by 2002:a2e:8905:: with SMTP id d5mr2895767lji.144.1603096578862;
 Mon, 19 Oct 2020 01:36:18 -0700 (PDT)
MIME-Version: 1.0
References: <20201012215701.123389-3-linus.walleij@linaro.org> <20201014105958.21027-1-a.fatoum@pengutronix.de>
In-Reply-To: <20201014105958.21027-1-a.fatoum@pengutronix.de>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 19 Oct 2020 10:36:08 +0200
Message-ID: <CACRpkdYQ4LpQiAFZLkUBr37U7iQJ+_tJx8SmWVGK+n6gWv0w+Q@mail.gmail.com>
Subject: Re: [PATCH] fixup! ARM: Replace string mem* functions for KASan
To: Ahmad Fatoum <a.fatoum@pengutronix.de>
Cc: Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florian Fainelli <f.fainelli@gmail.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Russell King <linux@armlinux.org.uk>, 
	Abbott Liu <liuwenliang@huawei.com>, Mike Rapoport <rppt@linux.ibm.com>, 
	Sascha Hauer <kernel@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=SBPN0dV7;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, Oct 14, 2020 at 1:00 PM Ahmad Fatoum <a.fatoum@pengutronix.de> wrote:

> CONFIG_FORTIFY_SOURCE doesn't play nicely for files that are compiled
> with CONFIG_KASAN=y, but have sanitization disabled.
>
> This happens despite 47227d27e2fc ("string.h: fix incompatibility between
> FORTIFY_SOURCE and KASAN"). For now, do what ARM64 is already doing and
> disable FORTIFY_SOURCE for such files.
>
> Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
> ---
> CONFIG_FORTIFY_SOURCE kernel on i.MX6Q hangs indefinitely in a
> memcpy inside the very first printk without this patch.
>
> With this patch squashed:
> Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de>

Thanks so much Ahmad! I folded in your fix into this patch and
added your Signed-off-by then added your Tested-by on all
patches and will resend as v16 before putting this into Russell's
patch tracker.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYQ4LpQiAFZLkUBr37U7iQJ%2B_tJx8SmWVGK%2Bn6gWv0w%2BQ%40mail.gmail.com.
