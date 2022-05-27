Return-Path: <kasan-dev+bncBCMIZB7QWENRBK43YOKAMGQEWPB5MSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A8DE536333
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:10:03 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id i7-20020a170906850700b006fec53a78c3sf2428977ejx.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653657003; cv=pass;
        d=google.com; s=arc-20160816;
        b=OnqHbyslmKAGbWItAEZJRIX1a/5uvOUR2h59T3Cf1eVFNIQO57qSovPJw3JbhH8faW
         SX9jQ6p0gTrHVMjM5x1cxVsRY9cq69Qdm19WiJFDC2yTcxuEPyUc+q+eb+4SlV+C6E6O
         Zu1CiMLfHX2YdLhopyvvP+36QOJtxcfDNazJSBZQH9SNbcp9cxeZmc905DpQxPNJPY+v
         mgTV8TdpY+hKdhqIQ0uWhh5ANRfBcg6ycXFMImgp+i2mZJHM7pPfhUJXkvehudk3r5wU
         LuSUMGPI4ect1dVRVN+Pfkz9ytAaS9W33PI+oYJ1j9emDuTte2MwhBnCgs81kO5I30KX
         9Law==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gAv0CbUvB+NQTlw3ynIzhQ1SmXGF3VBZ0+6BnKTqZOk=;
        b=xVKwiuYdCPuUbvi8JAxsg+WMPodDLX1laxgVXebzOy7ArV7NWZEng5kFtWZpBSL/Si
         KT3o2k4x9gaWhaQ5fGUjWzY+w22IBF7xbQwzQzaNQ+bhyQdU0XAtWi2knsWenYX/N/yD
         vuqwRC3UAEKnlpq6KGAS08irfAq+TzdXYBArOPRGtrCsu/6sH8jBdzo+/RAARc4bflnE
         LZSiwXSRbjAt5gj5IFDwzyN0dhg96LxnotLo3vEpNluO7zJXWJ1x0fHyj5slemE8T+B/
         fOEBWeR573tv/l61DOmj9U6ECstOxYohXPvuFA0nkf6pYjSRNEF0nr5Zh9YQ8p6Vv/h0
         5Wmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EgU6cO2M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gAv0CbUvB+NQTlw3ynIzhQ1SmXGF3VBZ0+6BnKTqZOk=;
        b=KAyQZPdt5zmKb/8h69wE+gOBhrwNYgN9CJisejwdRz6GLheGM1YQOJOiEwii5gscGl
         XBYbxxLpZ8G9I9Jpm/i2jnZGLI8BA78SAwdr9/SSQ3Xh4L0Ichl2DpRSScLOyHyIg/6w
         G9y5so7KgFVEXdWdMUGWUm9UQ3Gn1vdwYiyrNlzKkDSBgIYkdgo8VC1eqV9lsuYFvq78
         3JFpExmU1jxnNi+o0lJX+4LoCcmrFZCWHZpHaCUmg3KfbR/Vf7CzH5trdyE68rF8gtaM
         Y2sfIA7gKCKQ8AX8WUbZftS+Hu7rZ4uUInFPzvKfM9nBFdm84Pkr2edgTtKEPjwcGdum
         A0rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gAv0CbUvB+NQTlw3ynIzhQ1SmXGF3VBZ0+6BnKTqZOk=;
        b=Dr8UxrrMPwbgx0e3VG07/c8WLh1onLoxaT1ZF9pc3J+zkian+JeM5uxOF2tMeYyXkz
         8MYptngi9u2CTikeWcbQCjbR8pIiffdubwQrzB3ItAYCXl/2oBrGBxjuRuTGmMsrrQH1
         /S2QR9pA7s6FNUTOPyt6dVZBYoEGhLb1v0LMF6IEfvF/NRHvuzdY/n5vMeqTMgHCJHZt
         CaC9aAfQp3xmQU9zLhRUWyzSyZ3uV7pHc57T4O3tl4Q0zft1GZ1taQa33hEREYDorutB
         sBlkOeLRQTGpSiBMOOIl9sXsibJj7rv3xz87U63YiMljay54Kvxknuds/xfJjNNr9hX2
         tXbQ==
X-Gm-Message-State: AOAM531vSGoY22hIxSEJxQp6AlhdWv2gdJObWDOnIAf8nbbdS+iv8c1B
	d/j00FdOvRNwdKunGC+cUwQ=
X-Google-Smtp-Source: ABdhPJymukkG1bP3nfEuDdsdzCcgy8+A6bwdhAERreMTYID49WZ9sNnkR2rG2L1HSe8fFqvmU+tqIg==
X-Received: by 2002:a05:6402:4306:b0:42b:694a:b84b with SMTP id m6-20020a056402430600b0042b694ab84bmr26737861edc.67.1653657003255;
        Fri, 27 May 2022 06:10:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3fc5:b0:6fe:fc5b:a579 with SMTP id
 k5-20020a1709063fc500b006fefc5ba579ls4634426ejj.10.gmail; Fri, 27 May 2022
 06:10:02 -0700 (PDT)
X-Received: by 2002:a17:907:9717:b0:6fe:b4cd:e0a with SMTP id jg23-20020a170907971700b006feb4cd0e0amr31497876ejc.152.1653657002255;
        Fri, 27 May 2022 06:10:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653657002; cv=none;
        d=google.com; s=arc-20160816;
        b=BGsFy9HT0Iwa7c9eXN8E3sHQt+yn8dwhmi9zN1HKQaQcq4wEgmg4rxFcuwlC3KIbYV
         4krtW2OPG3CmyAwhYRCUt6jaDvKRpoaYJKhAkW+LOCfsV6HoD2mUdyfj/XTJC8Qoh8Xs
         t1umQyvGmJunCcN6IZM3woxIeUAloQ99MXLjUPmwyWwNlcgtuB3w89iTvwGVss4QI2jF
         Ex+UGsmFtJoUPs1E0pTf2HyPdukrIRGN/jRDPD/LOhO9aWz6A9amxdty4tS3IF7eSPOt
         J32azKLE/IaIf6+yGHT3kWn+9CuzH49mnM5+cnTPBgG3czZAZwrzZahj8+kjDLyKVHKI
         lBjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SPCeKo76snNBaZflfILsWsg+w+6SDoLhW+Bf3h1esco=;
        b=wIufuiJQ85n8iuWjgkZ8wi4LQN9rn05OVSlHc10iqGPJ1U/CFEpxeSYGBrxWwqwzbr
         Du5KGkADBjH0Vrvi9b+P+Ss+VRZs4rWmL7o8f501NnkZ0h30pgkf5Ob5oBurrO72pWZF
         JnSCeM48/pZiz5jCXtHChOZr+q7Bu3tqaAk/ebcYwmiFRa7ZGy/zkCEt11tdNRGg5Bpe
         rHaAY0k+DqHFfvYFiJ92TfrLMa2W6mTclYXm65++5ET+uBv9Eiv6f3CGIteuB0Bojf5V
         GELJCI/us9tcvNGnCpJ6O1M7Y1+O/1ErGnhkpaM20LOVQ++tolZ5UTDMri7Vm7mo+uAd
         CbrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EgU6cO2M;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id gt17-20020a1709072d9100b006feb6644b51si165322ejc.2.2022.05.27.06.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 06:10:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id r3so4892341ljd.7
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 06:10:02 -0700 (PDT)
X-Received: by 2002:a2e:9696:0:b0:253:edca:d93c with SMTP id
 q22-20020a2e9696000000b00253edcad93cmr14234693lji.92.1653657001495; Fri, 27
 May 2022 06:10:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220525111756.GA15955@axis.com> <20220526010111.755166-1-davidgow@google.com>
 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
In-Reply-To: <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 15:09:50 +0200
Message-ID: <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch <vincent.whitchurch@axis.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EgU6cO2M;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Fri, 27 May 2022 at 15:05, Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Wed, 2022-05-25 at 18:01 -0700, David Gow wrote:
> > From: Patricia Alfonso <trishalfonso@google.com>
> >
> > Make KASAN run on User Mode Linux on x86_64.
>
> FWIW, I just added this to my virtual lab which I use as CI tests, and
> it immediately found a use-after-free bug in mac80211!
>
> I did note (this is more for kasan-dev@) that the "freed by" is fairly
> much useless when using kfree_rcu(), it might be worthwhile to annotate
> that somehow, so the stack trace is recorded by kfree_rcu() already,
> rather than just showing the RCU callback used for that.

KASAN is doing it for several years now, see e.g.:
https://groups.google.com/g/syzkaller-bugs/c/eTW9zom4O2o/m/_v7cOo2RFwAJ

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZVrx9VudKV5enB0%3DiMCBCEVzhCAu_pmxBcygBZP_yxfg%40mail.gmail.com.
