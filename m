Return-Path: <kasan-dev+bncBCMIZB7QWENRBNVRTDUAKGQEFB2SVGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F6F4743A
	for <lists+kasan-dev@lfdr.de>; Sun, 16 Jun 2019 12:23:52 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id a17sf3315423otd.19
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Jun 2019 03:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560680630; cv=pass;
        d=google.com; s=arc-20160816;
        b=nYXnegz7ZeaCc7JaCbv2wae2EskVxRktu2+t7c8ZQ9BMsAdbeeFat+DYJnWEIJKkw1
         lY+1YXHDbP8ehsd5cyPwpiWT6495ZahXOIKnnZfH9CzKRwuDBwfDx5LNkGEDpc2a+fZt
         o2OsNOVil6UWt6/UePSepNqx+hfuKjCLBFKR5QkUjDll3KEh8m+rW3mIEz2COfyvZcvn
         Gey3+8id2KwUI1kiZc50/vWSjsRnukomoeQEjlB158/8DYFqX4kLwoUzIAEEzVn9i9f6
         /KGRonZEVsrAKQMyltmxAk9Q8mffO6WPe/G+meTXgOm0r02SSDFvNy5AZfLDmCfr7zK9
         Z/lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:mime-version:dkim-signature;
        bh=d5/N/OqCwMiQLeXMfDA9YUOLt1bvdWfRoeCKiXjddK0=;
        b=NXpiywfrQVKHScUNSGTiX+Fsg/1txaVVSwqD6XGsevNX/AAAW04Ow+xAOubPDPhiCC
         z5vGcfPiOnyZpgMubO62klgsoEIT3nUwMZnnoWrKMcPxJswcSwAjlaO5cHNjONPXR5Lc
         2q8OizU9e0ycOKTQ6f49EEebqVqbtnmk/FLWe9rqTCS0DwkmSer+bmCgF2KsAFopqP+n
         ys1y6ezD6ibSAIZOfOEko4Q0O1IUYd/41Skbhjv+dZYs7prAV8l/4k7sfBRxHQvVRyEN
         jPGU0rpq+f7FmahtTGTrpPDxjt1xZUfzHXma+j0YyGM7mW+QU1o2eex6WCtf7tJNv9ue
         xsNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=poa9HFE2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=d5/N/OqCwMiQLeXMfDA9YUOLt1bvdWfRoeCKiXjddK0=;
        b=dgnWm1hUW54SP2X1WAeT09rE7Gl9lfprvO2haCXOQVut1e88/GGl5Y3dKsiLw7loCa
         dLe7nRN2joF+xhTjncIjH3/YXCcK0taKK2qcJDt2MPxBxRFP4o17yv7lmATO8i5Yh+PF
         lAUduH+xBzG5F9e6VPQ/6HSMWcuAzKpZoQPu4EETgtIar9DeqAvxj9JNg1hGsHuPfVQk
         dNCURutHsoYhYva5gVmzC1oylhq3sflZ8Bt2wYfVbklVi/sQn54JMxSCcjxY+S4g2l5U
         B37Rhy7r6v+caX1z7lhIPN2ZvoEA5cINEHkliabvQuaBMZrf9FOWpcCrCLX6s+slPT/r
         6QmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d5/N/OqCwMiQLeXMfDA9YUOLt1bvdWfRoeCKiXjddK0=;
        b=DlN2ShF92dnJpIk4W9xqR8+FleOmoN8FdtE2lUhHMkkhoyaSb+eZ22rfsaDLUtj9dF
         xYGor3drwBYbWFLgXMr/FQqbNMc/zn9rFUarNVvihDXOEySDSkXay0GpC8jmSvvgOlwJ
         fgZU4XeehY6bu9Tg7Z0zpHtP+zWSn2XEb0y9PpGBfJ5OB/YF96bQOeeg5Jb3/CYDNHhF
         6SxkoNlAb2+LdFxDqYP+5shq5/UqouXUeiSJivOScLAD1NFwEP7IOdcC13vwL7b6fX5p
         uZJDq0AQ0Q+uHW5QGq36y8CH9JvVmtezoWXuc26jvlPE1OTmWvezw6RyFHrirP6TDnHH
         N9aQ==
X-Gm-Message-State: APjAAAUJ4oDO8tMHKVRf579OdLSTGcG81LgqS5iRAg9ZF6dFNdZk4z6P
	97c58I9zPs8Lfvc/upDCa/E=
X-Google-Smtp-Source: APXvYqyzQzsosg0WQ1txXTCwx2aChD+d5GT0bbHfBk/kKxe4XX8AK03cBAUk4c+um86uZ5iaNVsYFw==
X-Received: by 2002:aca:c382:: with SMTP id t124mr7387793oif.9.1560680630503;
        Sun, 16 Jun 2019 03:23:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3fc3:: with SMTP id m186ls1930360oia.15.gmail; Sun, 16
 Jun 2019 03:23:50 -0700 (PDT)
X-Received: by 2002:aca:4d8:: with SMTP id 207mr7383232oie.88.1560680630161;
        Sun, 16 Jun 2019 03:23:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560680630; cv=none;
        d=google.com; s=arc-20160816;
        b=pe3QKbK4hZro0Yem2Mr1dSHGBuzgMiJR3eMaN/el3YFbPPKAzoV6n4Zl9m9eIcpUxt
         knFw9HdkyB+CQ2GEO8+dN4AX/eGacDjC4J7c/DzsCa9MsZUbsAmQ6Lf60WXcC5248z0g
         FTXyKnDUrhkza0XvM7VqeO3rIIxvy4iAkrGEi7bh0RNsN7Ba7SJUiex0U+yqDJcuZCJe
         MNjynn55D+WDa+FffUxFb+ihABjjAIc5kHv+T1pceCHD5TnWF2JZv0u62Lxsdi4ndEUa
         NJEgcbL/AEOZwPu2FKYyGbzkZ4jWZSj6OJcZITeJZROtewpu8omv9QR7SXhc0xTmZGpm
         s66Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=s3k6GliP+JsBPn4B1PVzd3Sxp1rH0zTWIZuFXfA1ABk=;
        b=zpPhtBkfXKiYqRltBmmVHXI8gqCmPkB4AUiU9yckajDpjQ90NvPQGeDbrbvZdPx2eg
         wwUWW9Zaf6EGr9ePiUT5069SsRbhdmrv3VAEgV4lez2kgUJ8stC+5gupQeoiJ+upJ42Z
         U+IgTXGpVW3tx5tKLpglpufQ1+gZohwXN5IQ+80nGKaix6jPKDfTGpHeMiAFDTXYyjl4
         wGs7f4mW2lLn5ZiR2Pm6jEtQAZN9yLTPwySUihrgWbir91WPtI4l/aSTchHtP7mWreNS
         B+RKhztkEDsP2QE944sqpo9PtA7ip0wF0WG2SEE70vAMpJGkKwmJtSAUNbrbH4eJKRoJ
         8HHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=poa9HFE2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id 110si343479otj.4.2019.06.16.03.23.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 Jun 2019 03:23:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id d12so7146713iod.5
        for <kasan-dev@googlegroups.com>; Sun, 16 Jun 2019 03:23:50 -0700 (PDT)
X-Received: by 2002:a6b:4101:: with SMTP id n1mr6494638ioa.138.1560680629345;
 Sun, 16 Jun 2019 03:23:49 -0700 (PDT)
MIME-Version: 1.0
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 16 Jun 2019 12:23:38 +0200
Message-ID: <CACT4Y+bgr4aC-DZuLCyhxpcES39mbEgLV_UWakmkOYEBPrOkwg@mail.gmail.com>
Subject: Re: [PATCH 0/2] bcache: two emergent fixes for Linux v5.2-rc5 (use-after-scope)
To: kasan-dev <kasan-dev@googlegroups.com>, linux-block <linux-block@vger.kernel.org>, 
	Coly Li <colyli@suse.de>, Rolf Fokkens <rolf@rolffokkens.nl>, 
	Pierre JUHEN <pierre.juhen@orange.fr>, Shenghui Wang <shhuiw@foxmail.com>, 
	Kent Overstreet <kent.overstreet@gmail.com>, Nix <nix@esperi.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will.deacon@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=poa9HFE2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d42
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

Hi,

This is regarding the subj patch:
https://bugzilla.kernel.org/show_bug.cgi?id=203573
https://www.spinics.net/lists/linux-bcache/msg07474.html
(don't see a way to reply to the patch)

This looks like a serious bug that would have been caught by
use-after-scope mode in KASAN given any coverage of the involved code
(i.e. any tests that executes the function once) if I am reading this
correctly.
But use-after-scope detection was removed in:
7771bdbbfd3d kasan: remove use after scope bugs detection.
because it does not catch enough bugs.
Hard to say if this bug is enough rationale to bring use-after-scope
back, but it is a data point. FWIW this bug would have been detected
during patch testing with no debugging required.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbgr4aC-DZuLCyhxpcES39mbEgLV_UWakmkOYEBPrOkwg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
