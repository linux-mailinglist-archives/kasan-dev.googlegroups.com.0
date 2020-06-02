Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYWG3L3AKGQEY4V2ZDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F8871EC256
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:07:15 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id k21sf8567843pgn.14
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:07:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591124834; cv=pass;
        d=google.com; s=arc-20160816;
        b=KXewvLAKcV/Z/3LxxXkqswbpk1EguiuC6zep3kiX5VpcWatVveU96IHRURb96WOLDj
         fVQWWUU1bYBzw2shXUmrTdmbcnZxyMexvPuh9GaZDtn3yPNOVwy/vxxO/Ko/aa7GkbK8
         3OWva8joz2V4Tt3vCTkMztenwEjFGvVSFFLzghslEp9G9xKG6E4apEgqV9VfSrfqJhmk
         FyQCjwAQR+zALX2Nvol79IB3ybYYy2sWm0/3Gv8ePnTACHbzbrBNva5+Ta2JKf9Y2fva
         xBz5pZ344a9HleOpBw71KJP3fb6EAblBqOUN3xTjJB5dRoc0/EUa9hoOgK25pnerM3vP
         Qg7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8IthswPLdBhu0uCp2Ekpn5iH1r/h2eENmHMNMK6xwAU=;
        b=OX50X2X036QxZ2YeouJAR5RV1s23O0+1VZsh150KapWUB9KbI9ap8Lauf1J0wrcvbN
         JAbcHxSAlphZw3eN6IPMJ6esKlLhH8veghnkA7XwA4aa7ezfN+cDgh8tHupipLV03Hj8
         eXr++U2JRZ/tHe1FcOPVTOoKEkVao17H/lC9h1tn6Ul6qIStJ33yO+YP2aPH+B5PC+PQ
         ZGzCzIThUL6gjAC36ufyHkUSP4RmdpN6pHztLJ5uUc1RU0VCsS+1b19SH1RRepSZniKY
         vQylQYIaDBxqvfSuLcEtcxEs2/9ci0e8QV5vT76x1anmkQYyRv9WPhyNjBbvkKMk+/5/
         9gSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VyfN57zV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8IthswPLdBhu0uCp2Ekpn5iH1r/h2eENmHMNMK6xwAU=;
        b=d/IjFpF/efF/Qa637dLomrLRNznMsOiiBSwy2le8AJI0ukFm+ABV25AOznkGVcpT4a
         FHSepPqN3AtmSnzUZT4tOlg5qhkY7j5i8rm45TKiIIm7w3eeiE+Tbhh+r7TOt/+6TUJA
         rxEvJ/GjOEAbYIhkGQF06hRaRex1N4/vEKq0tgf56NNFVeEbM9jr1ide95X6ms8TImmB
         Ww0gflRaZwDDIRjpKJJOn+8XTJzXnZ47Yo6WnEldnx5rffobsLKSAdaxJ+Yc2oTxKZu2
         Hch53UVTF7r3L92qC3BTKtJNn5nsT6ImKuzONI/1KKU9fSu3fIODCoMNv9g/SCYJHOXI
         Hv4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8IthswPLdBhu0uCp2Ekpn5iH1r/h2eENmHMNMK6xwAU=;
        b=HPIa1Lt5VCwpYrqjQ5zQCx00upShQAfG+PaXNyYc1wDC30Er6Eg3PZkwey/ABvxzE4
         IS291p0cWumYHgDWvsXUpIC4QguWb+u2qEVohuAjQInprihuXFYrCjXeWWZOp6ohQLXG
         7ydlMfQgrXH/XFg/ZYrXAmoWeTN2O2d+nMrWS0gHQhbLh2XjfF3Jhyz4AidfXhdrHynl
         0Zlftz4u8zXOr+VSsCzu3EoR/wCznJaFEsRViGY+z40PtexJ/8Y0qGHJLiSBaV6hvTxb
         C2PjEA/Fooze3U900kRboUixgwdGEeGM7wL2tqB5WUNXe/mvPWKvHdj16m0Rlch9IxV2
         M3MA==
X-Gm-Message-State: AOAM530E61qOcdM/fBb5Qx8xP40nypOa5rW2o2r8h/aedgQQADpHnNR6
	emXlXpRafAQGcmB+HQyoCAo=
X-Google-Smtp-Source: ABdhPJzU69cBDe0MBGLyFACAvhCYNpbgVqsapog4kE5Y6fbA5aYKl9l+/02ADq8cLUL3J8JvgAzX1g==
X-Received: by 2002:a17:90a:5d09:: with SMTP id s9mr644269pji.113.1591124834364;
        Tue, 02 Jun 2020 12:07:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c910:: with SMTP id o16ls5454774pgg.4.gmail; Tue, 02 Jun
 2020 12:07:13 -0700 (PDT)
X-Received: by 2002:a63:5f41:: with SMTP id t62mr25958696pgb.252.1591124833862;
        Tue, 02 Jun 2020 12:07:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591124833; cv=none;
        d=google.com; s=arc-20160816;
        b=eRCn2xAoGMSqDrx22ibXS4w5BH/SsiZu/Atwnoih3upHTAf5JpxV8hggYUjFGcunRE
         oVUm5MzRVUBpSUpX8M/5YjnqsVGUor22qDRJTtPYiocA/O/FVhZYUGBtIlDFCY8bScxW
         u0MsONbSYrZxQRQsDcV5aOwizUUxljMvrhBCfOHqGrY/jfqTzd5e+lH8iZCaM+Rvb6yj
         PWoKwLvjbaM3bQ6BQGS33QYU0k9MUF7RehqzbeLkLwjUlh2tFbiD61lVtmEG1DkzFj8Q
         n+SqW8e+E4JZ1WjaaB0T+YkMBTwAIg+Z2Zvs3VQMWE2P18OKsCq22pW//VN3YNYXS924
         4SBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RSAfpRmu4NBGjmiVQ1lcYcxOmmXpwec5mF9PhUPKqU0=;
        b=CAZ9s5PUwoE9wiYxo2sY6+EcewtX43ncGTtO1km73ZOFJZwId3rhL0rMGhmnOv3ixL
         bK/oW9CbQTcAnP9gdthO6zloZ0Jd8dpGdt6u4Wy7AvZgBzkmUGhoID+UXNSqtb9suPdJ
         1oA/VWKRdUwDzyRYOM9l9egjjU9x+JCoIPg8Nf8OvgmDkSNxwRc7EFPxmVMSp2fRGM7N
         pmDYyw8qtufj1YK0M6JLAqXrLOp9gjhn0knVJk2QrLfdhEf1aX/nUnjU8raxyDxU8OZb
         ekQ5nSJweRma4Oxnu2n4F/liKUD2swJiDn6Vd63tIFUeVngDUg/E8za20yL3vXUFw/qS
         xGeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VyfN57zV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id a22si372711pjv.3.2020.06.02.12.07.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 12:07:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id o7so7349737oti.9
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 12:07:13 -0700 (PDT)
X-Received: by 2002:a9d:7dc4:: with SMTP id k4mr477503otn.251.1591124833330;
 Tue, 02 Jun 2020 12:07:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAAeHK+wh-T4aGDeQM5Z9tTgZM+Y4xkOavjT7QuR+FHQkY-CHuw@mail.gmail.com>
In-Reply-To: <CAAeHK+wh-T4aGDeQM5Z9tTgZM+Y4xkOavjT7QuR+FHQkY-CHuw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 21:07:01 +0200
Message-ID: <CANpmjNPi2AD5jECNf6NBUuFk0+j+0-RA6ceFCOPPvw5PtoQu2g@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VyfN57zV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Tue, 2 Jun 2020 at 20:53, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
> >
> > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > have a compiler that does not fail builds due to no_sanitize functions.
> > This does not yet mean they work as intended, but for automated
> > build-tests, this is the minimum requirement.
> >
> > For example, we require that __always_inline functions used from
> > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > fails to build entirely, therefore we make the minimum version GCC 8.
>
> Could you also update KASAN docs to mention this requirement? As a
> separate patch or in v2, up to you.

I can do a v2 tomorrow. But all this is once again tangled up with
KCSAN, so I was hoping to keep changes minimal. ;-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPi2AD5jECNf6NBUuFk0%2Bj%2B0-RA6ceFCOPPvw5PtoQu2g%40mail.gmail.com.
