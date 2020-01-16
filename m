Return-Path: <kasan-dev+bncBCMIZB7QWENRBQF3QDYQKGQE4INKJTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 677DA13D5E6
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:24:34 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id f15sf11875060pgk.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:24:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579163073; cv=pass;
        d=google.com; s=arc-20160816;
        b=YMOgTeD3lN7A4W6rl94akxK3skO804yu1vqGoCD3bruZwvwM3C/qiFaO71Hip77JCL
         5d4vZ2njgvs+QoY+pJsMhBxzfLSqvEaNborO2IWEm3lZMgGbozNGimk51a+SXOJRP/cu
         a/kKaXY/kXcDRtz8oFSc+pcskKwfPnMK6Qzs1Dk+e2mZgy/mjVkDptRPa2Kmao94jmZm
         yRsXdWfrM2euA/D8uG0JNjX1eYNezYL/9fwsJ1A1B4cWeHWnj4VT080eGwROiEV29iSK
         YLlKNxyHoD7UDNnLfxr4eJ4sfP2lKXWYuo4Hliz4CxXIL3bJLd+UAPLDMTtGsujJV8qU
         jmuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tLvVyxKQF15UsA09pDjabxRogw+BIoeayjyOnJlS8t4=;
        b=i3vvuuplLtcwvQ+dYnABYyQRnVH9zFZtGz1ntHArq0HV5eb7593kE9fR/Ihfhn7xAX
         tZtqkLTmoCdxINOCv3erAZ06RHh/Z7+2X5S/c4T8lPIllGHEqLHRVi+heSkrmQuXQrf/
         8gFTMFQIznDo7Z+oHnL1cCD5lMoQvLr0CbEdVjg3lZG9u0Wn2jbi8ZMRK8FSCxELGcC7
         ZfHgjFpr/1ggX/79pb2yWx0WUdAlbatEX8Vi7hICNw0oSR3ziecRtDsu21GlzKRJHQzo
         vJUNtDthh2Zxo2UQH4M7SRP17hE7X77+yi1+z6VcosPTcmielGmUGbxGHoUNp97kR8Uz
         QGpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ln5la+m0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLvVyxKQF15UsA09pDjabxRogw+BIoeayjyOnJlS8t4=;
        b=NwxZceZ5VXHpIlLf/fIfzYT32aReCdWReh/aTxXjubQkpHhJ5X3AbfMSVffedOgKr7
         BygbfQ2Zem+0rKoiRPiDxiq1YhmnPYZaSCcDpIVCQVsIr7IKXABtk82NNs9ifMeQa3TE
         OnSp0zIFaJ89n3pNV7iERiBGgSm7l7dMruZS/kxxnc899hUvcvz/5bBg9fJ0e4XSaF99
         xW/HKUhSRD6I4nSe8OflHK84dgXLeGbw1cFznpsoOydY0tpj1Y5sxMa3c5hBTJqwvyom
         L3QFXsO8XHO6Xu2qPxMNxTBq03BI4n37WI9Sds6eBqwneWlgYVRkLWym6rzl/W8CKvoD
         /eqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tLvVyxKQF15UsA09pDjabxRogw+BIoeayjyOnJlS8t4=;
        b=J6hv2Enrlje2kEJ/dy+aKfQvshhHeppmdaoedZ0a58xYTGsk94dnLN4PfVMelGW8af
         el9O4R6iUw2Krfgi9oMR4zUsHTYbhVGQuDVSwb/Prn0Ne1r/u4s3UjS12oAV64z4inhK
         mCPHVQTpqiWI0h56vkbWBgij+XYBLFcrdnrRFYJMAi4Ppo5Od1ClnU/itLYYBeVpgr0W
         JLQCT8gmQcbL2xL3zl0LBwGnoL4CXy7y72n0KcbnqGE24UxPOFTPS98/dA3Q3ZfxsXhM
         Ox3vODecH/k/YHkZinmifz/FDoGWFx0CQiv8Wp9bfCN2UhoBUxwPBtesco3GdZGGumEG
         HeVw==
X-Gm-Message-State: APjAAAXkpkkRSrqWSALzJBQYvOIQIUP26JPT4bb4HfodUwzoai7WOEZT
	yx7j5PLvWScXLRgrI06TDsg=
X-Google-Smtp-Source: APXvYqwWWFeyaHoVllUSqs80a7U0OeuUflBYdagVu5rfQrY1Tg1yOiD34KHML84hxAY6S7JKwzxIQA==
X-Received: by 2002:a17:90b:941:: with SMTP id dw1mr5360546pjb.21.1579163072804;
        Thu, 16 Jan 2020 00:24:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3ae2:: with SMTP id b89ls678262pjc.2.canary-gmail;
 Thu, 16 Jan 2020 00:24:32 -0800 (PST)
X-Received: by 2002:a17:902:6902:: with SMTP id j2mr729288plk.16.1579163072313;
        Thu, 16 Jan 2020 00:24:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579163072; cv=none;
        d=google.com; s=arc-20160816;
        b=rmProvziZZJS707d73xGi5geXbcfunREH/NiPnYzQNsmAxJMMgkPgmpQz1Nhyjc0Tw
         GDn/uBh/D/+B6evtFOzTAYE9/xEgd4rpAyUv75SPJ0Sggxu5RH8R8K6HcJfrxW/7I8vN
         dT6oa4gCHHqpslNeC54RoXOoY4uEXwMHdj6b2JwDsImnMCPk7eA1hWvRFXBIDZVbwfBw
         Vz73knTgWuOiJDPRk0/Ujad3UyR49VzPlD5CqprpM01B5xfuuvfSYeXwP9cGt97m1sO9
         WEIfZlAVWEZexqanejcZRfTXb3cBpzc9m7NcAhH7PXHl4SFa+3lGS3WW97ToQBst1clH
         dVXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tlgKvEyVkOCk+r5Hpx71WwyKD+4RnBChT7TjkISGEd8=;
        b=cKTdCiYdqwLKpL328JwUYyotAWxtsuQXshDmHd9kM4VUG6QKvL4lLema+K77JdqyKC
         TLqKSwvk18vdNk50NAEpr8lbFoE/A+0YMPm0op5iPERjSKVSQOrwil7XResAWOaNeJlD
         CWlpJAOP3Uvk7HZjbqnTWXrbJrUY1p4TdajYH5wgRwmCa+mhOX/zbFLUFjBqw0n4gh9y
         WwUkl6z2Ov4zaq0lwQsOW4sTOX1SPn2CFWxaElsrvgW3LUSGH9HZBxS3UvjiDri3JZSm
         tgwE52vjDZOOwiRrgUMDL9RjLGNXrBXOZJv5CFLSNEDjpUx1AbWl16HH8pZ0dc4fmXja
         We+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ln5la+m0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id d12si387389pjv.0.2020.01.16.00.24.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:24:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id v25so18212095qto.7
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:24:32 -0800 (PST)
X-Received: by 2002:aed:3b6e:: with SMTP id q43mr1220224qte.57.1579163071242;
 Thu, 16 Jan 2020 00:24:31 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net> <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
In-Reply-To: <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:24:20 +0100
Message-ID: <CACT4Y+ZDRtFrm5jfD+a9X=frGM=WKpoeJJZ6MRhZsATbG8aDTA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ln5la+m0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Wed, Jan 15, 2020 at 11:56 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> > > +++ b/kernel/Makefile
> > > @@ -32,6 +32,12 @@ KCOV_INSTRUMENT_kcov.o := n
> > >  KASAN_SANITIZE_kcov.o := n
> > >  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > >
> > > +ifdef CONFIG_UML
> > > +# Do not istrument kasan on panic because it can be called before KASAN
> >
> > typo there - 'instrument'
> >
>
> Thanks for catching that!

Hi Patricia,

Very cool indeed! And will be a kunit killer feature!

I can't parse this sentence (even with fixed), what is "kasan on panic"?
Did you want to say "Do not instrument panic because it can be called
before KASAN is initialized"?
Or  "Do not KASAN-instrument panic because it can be called before
KASAN is initialized"? Though, "KASAN-instrument" looks somewhat
redundant in this context.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZDRtFrm5jfD%2Ba9X%3DfrGM%3DWKpoeJJZ6MRhZsATbG8aDTA%40mail.gmail.com.
