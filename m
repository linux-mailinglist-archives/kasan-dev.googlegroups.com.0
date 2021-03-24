Return-Path: <kasan-dev+bncBCT4XGV33UIBBYEK56BAMGQE5JO3PPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A75A0348502
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 00:04:01 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id m14sf2419168pgr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 16:04:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616627040; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIRF3a5Bmadw33jsxroKwdd1QXLSWfYflNd4j9B4th+bWCUaL9GfJsXBGxRMBwqUyz
         Dbmk1nlfbYn+q+BKoSviFR3mdQh7x0jCYXb8qp1AQQWUMqdXqTnb5LSlAm3VKkWgPEfm
         +bNv5hTaeH/6xGhNw53dBNih4PmgEGC5LTj7T/Xz1UbYSg8pGUKyPZwAKfDVlwo13u9D
         1LJ6fSf5li9PrOtrtLWgaPzkfbRxomNwKSsXOuVZLpWxJh/77avcGZ1HxxC3K1qO903D
         /CFa49cP35h0Tu+GEmG0jRWC43Zin54HHbGxETranbjd/ISxIIjtpjt2jiamQOhuAjFG
         6BlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FWSupM9XkD41he6KFcqs9qhPw+29Uw5kvYRLfX8Uat4=;
        b=HZkFwrRoEyUIOktWqp4G65nvMbF8GMPV6gYb4LsihkLY35WMU2NUXZqMOTSJu00Fp/
         F3lQX8qtEYbXHu6WcWDm5RiwG0Ok7yf9pgLiw8rhLY1tg8NUT0NYej+6UGmbmGUAAs7a
         b6oIQx+K7QjBnpSUjX2aiL5f5ZpyHaK7jAROX8GItk1q8dUH28RApnH7OXQT1UHy9413
         2iFrRxJXk8dPSMAv2htCnc1X8Xkot4rViwIjRo/46Ga00o9T/lFQI9vGa9ZZ4RiNEqOZ
         JiqkeUF0i8yMvoVdrSNUbZr7li/xIQgM6NjXCp+YztpfFLexAiiBSbLGes2Aro+ZtZ7y
         sghQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="bB/Eyu/6";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWSupM9XkD41he6KFcqs9qhPw+29Uw5kvYRLfX8Uat4=;
        b=Bgb+MZJ3K+Uqrbb6sSrmvIn1+sPT4euJRPQcl6xvPNavMGNrafUhdKS0V1db0ERwbj
         G6HOu3NAXHnlmsBhI4OHav7SZJGdyVA8sSajHOC2qnd5ufvm3APN8FK8fgeSKVYz7Yej
         WDqQ6ffeh+F3pN91ZuziCiuEUd9VYE7vATz1eAzWA7lWq8KvJKUhNRYI47Ll41yMI1Re
         4UCFC5G+exxkzohKU+8qKBRArcHhLD+GXYVqaZO7Y+MjpR3fG2OBEZ4ZrfvsK6jNa1KY
         2mtjTB6OBI/zZuSlPSJga47KB9i+yh/lsX6HdsRBjquvrmthw351rqJv5kH9TSARPsF6
         pstg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWSupM9XkD41he6KFcqs9qhPw+29Uw5kvYRLfX8Uat4=;
        b=lxQ6i8BqFEkEUnuCUMjQbE3jw7xyvIV6dQ06SmteY6jikludq9q3ulVrOIBZE6ajyU
         ONZvzpLtdVKbP/VyBf6CSB3BAe/rtPs5/xGesjjssH3giB7zk12KQ7QJspkT0YaKjjfj
         3ajcowv0yaYz6EJRoOi5E41UGi9ZPdYuJ0FS4BDfAc2A65uOdu+DSEPzak21QPBzhsQh
         EUwO5/KJiW0GDc/TQIGiv6bcDSf336lm5lYWW5j3l8Co9aD2IVx+xsLc17jYZBg2GIo3
         MzHrt1/6XScAl7+bw7R1IBg9vaX76n49MotJVhHpAqZ9seSLPzfcx7pruYkKgbFgn5kD
         ziow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326N6rX9fw8Dahqi7ExFmPEFGoQRiouItWcD+2xLLnj+kb5xXp5
	ETMciNb+Ind6x99H8umlbrE=
X-Google-Smtp-Source: ABdhPJwF3doRJGAA45YLHvv6tHGXNbPOkvUrchUqMCVZ8HDOuoDQ3gy96TXThtkCx1CX+jRHDkmXiA==
X-Received: by 2002:a17:902:fe09:b029:e4:951e:2d2e with SMTP id g9-20020a170902fe09b02900e4951e2d2emr6103400plj.22.1616627040374;
        Wed, 24 Mar 2021 16:04:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2a8e:: with SMTP id j14ls1915113pjd.3.canary-gmail;
 Wed, 24 Mar 2021 16:03:59 -0700 (PDT)
X-Received: by 2002:a17:90b:4c0a:: with SMTP id na10mr5979329pjb.227.1616627039740;
        Wed, 24 Mar 2021 16:03:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616627039; cv=none;
        d=google.com; s=arc-20160816;
        b=evV8a98hYSA3yTFXYbEpI0ig/R3YE/qmsWUX0Fsaw42pwca7oap2G1K5EOa4HVW3N8
         A0tXPcpjeuF1AUqvI6O2t3rF1AaMObyGaZj6zGfAm6tsoU8/fZYY8W7k2IJ8/PnkAjOW
         6cAXNcxHiys13D1vGXOT9q5ytuIbm7iIxXahKHRv5io498FV9FZp8opCn40yesUpad7b
         RqYrTAVer90srs6JDTaw1+DPgUGR+ik/CYSHilQiOe6wKpbX9vX494qpVW1qGlaqM2rs
         LtWxjxb6ZYAMOtWFvl/lsW4ztF/Nm6no+jYGSDKIX5tDux6DMDoOqB2+2FuLzzmZYmSg
         lNog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wjIiiWjGwk3YrbZd+rp0bN+2bjjrsOZIz/NsPYbXOMk=;
        b=MYTBfguYVDA5Y74ZS3VzGiYcHfYGceQOYR9NCxWqjYHG6mU1U+whgC9gnleTVC+nU7
         EogECn9A4UH117JLvczpl5WnDmkV+C8oMJ01PSTZsZU2SQ8DZZdPGvy0TqgNr2FKjuZT
         UXlI9qyIULLzNsCd8wcpQ+atT2LTKSqMt7NoQ3FOQSiF0e+OI7sejdPPQmXmjGJcYRb+
         lrn5sf34429GMLwUppFBaFqxPfnnfS/BitOU4hy78CWkIWjeNLyumEcRhcw2cGKg1Fdl
         4MqQUSpFWV4ItMFmd8ai32VjQ1b7UBkp8YtUbq2FmLS/5IyE2yUVimAtHzJcjfJvYtk2
         5BWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="bB/Eyu/6";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e200si122258pfh.3.2021.03.24.16.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Mar 2021 16:03:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 32EB2619E5;
	Wed, 24 Mar 2021 23:03:59 +0000 (UTC)
Date: Wed, 24 Mar 2021 16:03:58 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: tl455047 <tl445047925@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, LKML
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>
Subject: Re: [PATCH] kernel: kcov: fix a typo in comment
Message-Id: <20210324160358.0f36aa1f8ea7098f66fe64bd@linux-foundation.org>
In-Reply-To: <CANpmjNMFfQs6bV4wrigfcWMwCvA_oMwBxy9gkaD4g+A1sZJ6-Q@mail.gmail.com>
References: <20210323062303.19541-1-tl445047925@gmail.com>
	<CACT4Y+atQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA+nkTS4eoHg@mail.gmail.com>
	<CANpmjNMFfQs6bV4wrigfcWMwCvA_oMwBxy9gkaD4g+A1sZJ6-Q@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="bB/Eyu/6";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 23 Mar 2021 23:32:57 +0100 Marco Elver <elver@google.com> wrote:

> On Tue, 23 Mar 2021 at 07:45, 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > On Tue, Mar 23, 2021 at 7:24 AM tl455047 <tl445047925@gmail.com> wrote:
> > >
> > > Fixed a typo in comment.
> > >
> > > Signed-off-by: tl455047 <tl445047925@gmail.com>
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> >
> > +Andrew, linux-mm as KCOV patches are generally merged into mm.
> >
> > Thanks for the fix
> 
> FYI, I believe this code may not be accepted due to this:
> 
> "[...] It is imperative that all code contributed to the kernel be legitimately
> free software.  For that reason, code from anonymous (or pseudonymous)
> contributors will not be accepted."
> 
> See Documentation/process/1.Intro.rst

Correct.  I let this one pass because the patch is so minor.  But yes,
a real name would be preferred, please.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324160358.0f36aa1f8ea7098f66fe64bd%40linux-foundation.org.
