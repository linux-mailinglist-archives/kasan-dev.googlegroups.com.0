Return-Path: <kasan-dev+bncBCA2BG6MWAHBBB6ASCIAMGQEH4MYCZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 69AC64AFE08
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Feb 2022 21:11:54 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id x6-20020a923006000000b002bea39c3974sf222802ile.12
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Feb 2022 12:11:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644437513; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cufyqz7X0V8MzTyejr2iuWX3eWcZdeVuXu+m34pBvwDdDxoZ22CIJ/x7i4qgHMXRTI
         FphFu4RrrCPCa9soBD0/X1OcCkrfVdXrAdQPr1KnA28vK1ZXNG1UsYQZX2RVOEfYLx0v
         iRufImKr/4ulY08xXm8EbInWP/AXApP+2dkTXP6GOhtKbH+ROZQYG92nWL0ZSk3hwtqj
         Mt7cWmPPuqTMvApw3zO+Fv508SFjvC6Z8qRu8VCf8vtBozACM5lO4KJ3sir8Ew25xmft
         ZPrwVwyuXB5+GtUUqw4qqFGmsQ2PEfCup+SE/aiERmTboQYZT/MycEUV95yo/vfGriUb
         JypA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xVwDukDRIrwjmssmwWeL2c4xL6mPGUBJ705UirAXuOs=;
        b=U73jMdfoeeCB2LubRFWZMncwIKPzyCrDG9D1/AxNr6T3jYBN3R1sV7YvhdSM7Vtx9V
         /cDOgEnxTS5M887wPz/utg/50BAc42gx8myF+444v4eusGx594myhBXWhlzdbMUskeG9
         iFixdLg2KpNmQFuxNPu6uRaf/hCpnBltD00WBmAKEw0nBCDlKG6B7bR+nLP8M/fAXFZW
         BdQDPE6SY0Qmy46EXkx1ewHMML2JdrTm46myYOSguUSX1VYlmgKrFlZd+mXfP+i5wJle
         ZGazabN0gKbKx3HkvW+vP5j5qk5dp7mOIOM2B5Tfc2nVMgo4FxLxuOOSuNBDtW/OuDWi
         vakA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y8GV0Csm;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xVwDukDRIrwjmssmwWeL2c4xL6mPGUBJ705UirAXuOs=;
        b=DpcJM0BeStntKQgxO3KVA/iWEZ8wlggvFesrTqirSpJpFipHGHct9//A3Yi8dr0S0j
         fUSP0WBI/M0Q5YrGJcVTJknRkWlEOnmOsD9Txx+oyiQepcf1riP8ftEdbnJveXvQdNU6
         rUoFUTUP47lwoWMpKa3lcjtxxR9SK9R48c3tqCewvbc7o5T8qmmb0fuYUSWs09TiX/KK
         3cfPzE6R221JznsuipJTXIshXRnbTJgfPlIV+Ox7u+aFnScO9gWJYl1yQtkEtLsizucy
         +6bPWn88vGpvCBjfHpbAXm3dPYF1Zi0AXPPlMv1nF+DJ/iyScJH9ijZL2yEcXbXqb351
         +q8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xVwDukDRIrwjmssmwWeL2c4xL6mPGUBJ705UirAXuOs=;
        b=r1T6gHeh0UftsoyEq4dsjLmBe34fGNI1wL91DgUnY7ZTiQONaZNqtGL+L4d69+xAvX
         AWZwRnQBa1q3Lag9BCy5U7TJgDUW5gv82dZ67whbGYXbTLV7lyNBiAebm6fbYXXki2Aq
         wilitbaIwgnI9eXb7k7mj3wBUjG585ibvMuXnqJNS5IlA0ilFGHDpkbdjWRdol2FbBZP
         t58XmacHoiR8mDo7ErteWYSv0VUfQcLm3GgsQX5jir8esY236cL/iG12PI/o3TwG+2CJ
         e8EimpnVEd+KSrat5gVmaXrSt1zzFYv3I3ZvfshhDMqqvtdA6OSO10cjItHEpKKptA/E
         ExCg==
X-Gm-Message-State: AOAM532i4gmI8d8EnzqN0vOBsIFXj+1bD3z0S8DHhqcVHhBEmW5DkZFR
	CGKRR8Gg6RWe/2QsqPMwQqg=
X-Google-Smtp-Source: ABdhPJza8ImHvLi5+ewzWVgKQLjzuvF0ZgGwCqLGBQFi8ktlPAhFC6MpbbNkuDSACrlkiMBlaWgqTQ==
X-Received: by 2002:a02:1d89:: with SMTP id 131mr2025753jaj.215.1644437511984;
        Wed, 09 Feb 2022 12:11:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:160d:: with SMTP id x13ls386259iow.0.gmail; Wed, 09
 Feb 2022 12:11:51 -0800 (PST)
X-Received: by 2002:a05:6602:2e90:: with SMTP id m16mr1988730iow.74.1644437511622;
        Wed, 09 Feb 2022 12:11:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644437511; cv=none;
        d=google.com; s=arc-20160816;
        b=uKRtKMeIAEAG3j6wcDRfqv5sHE48Z0vSsI0Z0rnX7FwW43+um79f0raW5O62pJikol
         5IbJZvN8Crkq29sWLWvlCB/80Io5Egxyg9hPZ6UVelUnXoWcJRh3UisUGjj/tC0og4pG
         oh/sJ32oXbF3S4885Tz1wEdCoxg4vi9FvMaZAgFfUGgzPDzDGvYLjKw0P0xKSsvVJdx7
         onoHuCcKL0iKg+Wqn4kAFnub3iTUDRK3pwp2V5HzhgDwVw8+dxlzWuA5bOCCtfFm6g7R
         x48q9F2au4aVm1IivMonjam0QYHYe+IkTQKZhFp4/I3COpvg6nScuolFwQhri6PmmNJF
         ybFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hRMRE2i2WixSoGBLfdLeC38WF4SFKOpi+pn6Nl89CtE=;
        b=pwblPjdxZVj4JWr4uUpFVQB6nC2cId2NPWu1MtSBa/tws+WlB9stUuHDqAokDKZj6g
         GNGl53qFO5EuXQeyP57Zt0r5C+tBXgFPuHUdrKp41NSPWRfirvF0NgiGnPCbKKxCT+xK
         /jBs+/VHSdLyHVIS4Mkd6R1hTXr5c7nlmgbakD9IYZUXPGjpEIJoVl0KN/1rYOhWCCw4
         PnvzPQKk1Frw5VdU6v5kX88CIQNfB0FSMkQ8doSvvN6QTQkuSfcVc/CgailImYxAQquN
         Jem4eKU0iFST739Vdb20Jvu1knl4+e9yT90uvk5aC8TBAsHfhSxhtg8XligBiju+VDGg
         yGsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y8GV0Csm;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id z9si167225ilu.5.2022.02.09.12.11.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Feb 2022 12:11:51 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id t4-20020a17090a510400b001b8c4a6cd5dso3317170pjh.5
        for <kasan-dev@googlegroups.com>; Wed, 09 Feb 2022 12:11:51 -0800 (PST)
X-Received: by 2002:a17:902:e950:: with SMTP id b16mr4068072pll.12.1644437510700;
 Wed, 09 Feb 2022 12:11:50 -0800 (PST)
MIME-Version: 1.0
References: <20220208114541.2046909-1-ribalda@chromium.org>
In-Reply-To: <20220208114541.2046909-1-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Feb 2022 15:11:39 -0500
Message-ID: <CAFd5g46mAWZmO2QMv=weanWJ9JNEOWrTHSRc80aHkePG2auWkg@mail.gmail.com>
Subject: Re: [PATCH v4 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y8GV0Csm;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Tue, Feb 8, 2022 at 6:45 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Today, when we want to check if a pointer is NULL and not ERR we have
> two options:
>
> KUNIT_EXPECT_TRUE(test, ptr == NULL);
>
> or
>
> KUNIT_EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);
>
> Create a new set of macros that take care of NULL checks.
>
> Reviewed-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46mAWZmO2QMv%3DweanWJ9JNEOWrTHSRc80aHkePG2auWkg%40mail.gmail.com.
