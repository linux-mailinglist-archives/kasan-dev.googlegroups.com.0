Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFMYSCFQMGQEAJA2MAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id BE672428A77
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 12:04:06 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id v7-20020a1709029a0700b0013daaeaa33esf7724301plp.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 03:04:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633946645; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkDT6YdBiZU08g5ATITSHyTNJZUslYuA9HfYKieQ9LhZcmjUJJv4R0qE/A03QY2MTG
         s20d5vpr6tJQGehFZzCN8SbObbUts/ItQ3KyfI5slW4Kms9HcOKh02tue0BabAq38IDp
         eF8k3D4wBVGcL6JkG9ryNMhcZLo69eIyMn3s6tGVA6LH/b9fdPGzKy/XhHXEjLNvo+7v
         XBfsqFUQ/nXyUp61p7a+ix1qIpPm0uvSVoOpsGTslvcSNl5AUIH3LJneSBR0hHCKXDDN
         ogmvrDlD5K6T1phnEMZsehZpEASt0IhjmVcq6qj3XNiplpADd/SBzRXeoUfHeWQs5gyq
         fN4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0IMOQQyLW/VWAO9ifL7Rc6l1cbGNemt8Gv2OO14k4M4=;
        b=mUsPZd2J9q2Qo+6BHq72Ax/TdEj1/P3G3wuC7hmNgbDMhaX7siBJXi/gbaI6IAwX0k
         0kquHneQ0oUx0L0/USFyaYNoxzZXbBo+dL0YBqKNk2viChJh/Mt/M3AlPmWyG5LwyxSr
         33wi+vITECRVfYtZJRO1EE+ujsDjFFu+FuqXOzsJu05dWrr+mnMCnmqbhEHFNbT9fJ2Y
         MRtRpTbbnFBO/OpqcOaGlmBj1ifSVWTzje+QH042yk7bUaXe9UhUdtXdnz03ajKMOl/f
         pyu0DV6EhdwFYkZsYEf8LdVeaK5CklNnW/l9A8dQ65+9mx47k9N5q3QJ8DOEpPSUhxLX
         UWzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gNogjTGQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0IMOQQyLW/VWAO9ifL7Rc6l1cbGNemt8Gv2OO14k4M4=;
        b=bU3WgfSu1gbEZ2YWh5vl71E/agvxyB/vtVIpo/Aws5WpA934bmqjY7tp6wqP6r43U7
         tktGT68gsyLU3jurUlMrgC1Dj/NTDjxjTbEmH1TUCtT0vmyDIXBnzTUpVmu0S39c/27Y
         Js/VWne3MJa+x/qPwQ4CGsRG9qBpPPFZPjIIp6F3BnontKf0OW1z5lwIyPywRkLPNMhq
         VhQQ7w3kujYmuVLE2J4CCoxIxOcY9qt/NE2seNJWMRqpMMbyEIh3HtkIN1qxKAErpFpH
         UToiR/X0ziiAbn6zRBcHpxncaUAHgu2Ss+mJej16qhGYgW9/HGW7EsTXAMVcul4NjtQr
         8hww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0IMOQQyLW/VWAO9ifL7Rc6l1cbGNemt8Gv2OO14k4M4=;
        b=kPyP1wF65eR+bsgMfuT8OmqeakPLJeZ9TWXabqC8ayaufsSjSksMZWBCvpvwS7Psqn
         PXhmsjghmnDZBRBGhuAZL+jPeTnunolgvYXnWtAXomjSg39mZ6aGezvnj7sZ5t/Towba
         lHFy9g5ykHG3a/WGtvYcvrxG+9boK+MxqQGhmkV43JrbJDrOUoWzv1Hwi9Oeh2zZ59nu
         T5XW8DwI9SyDCyJPm+03ifwdFbqeMe8FevsPWxYRGHjNp/kDw9du72UDuQwWmhvB+aBZ
         qFI3iTk0TbaWFzl6udDH2yWerHOO0Lz9QMxAv4izLGVCZ05aDIkCaw8XwRJSM0hv4j5n
         /W1w==
X-Gm-Message-State: AOAM532yCtA6TGHn+4nLfoWoTT8lGpym5CKN9wfjFFvjcuuBsz6LUc/G
	XWUr+hV4IXzp4ePnBf04B7c=
X-Google-Smtp-Source: ABdhPJzSvbzqCm9rRljPV26yz8BNOqARZByI9s7xVOtCUVWZenM447cvDBUNGnixctA/3Vc1hwrM9g==
X-Received: by 2002:aa7:80d1:0:b029:399:ce3a:d617 with SMTP id a17-20020aa780d10000b0290399ce3ad617mr24826730pfn.16.1633946645383;
        Mon, 11 Oct 2021 03:04:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a8b:: with SMTP id v133ls4064529pfc.2.gmail; Mon, 11
 Oct 2021 03:04:04 -0700 (PDT)
X-Received: by 2002:a62:2982:0:b0:44c:f2a3:ec62 with SMTP id p124-20020a622982000000b0044cf2a3ec62mr12500518pfp.23.1633946644757;
        Mon, 11 Oct 2021 03:04:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633946644; cv=none;
        d=google.com; s=arc-20160816;
        b=zp5Ko+IHAO4WqSCwFE47stxj+X8b59csyo1H+KLzCxJCWZTOZB/HrLjUGzdGcSgSrh
         Jmo+7G4+2tbDNLZyuk9S42dPjz2oUGnj8wkH2TP7hL0W/FgMOvmLwvgpKoz8EKWrOTDy
         6jVM7p4CWLi9nsDORNQk50yY/lNsVLXq+ULLv12rQpQEFSfANIFj8+B+Xi1qhQp2Lfh4
         S4F1U/QAiL+o4wPfyhFD1fi4Pka42vc7cArsm6HEITOG3NdF/mlzXPNcyJZHKqWxFAO5
         zw5cYeJEiePVuNSFy0PlbJeLL7Duu3jf6Zb5H1l6Y/dE944SMprk5d4c+o4iHk82qJqB
         3nKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BTfrofmPQUPweaAMFrrpDCsxkes27wM1OdN6B7aOuF4=;
        b=WSzLiFba8czCnxkzC/ndAzpr2nR7nbnN4kz9N8PznWL6UhFQkBO47T2e0+rNd/6PU4
         EAuyrO3X1hTE6/LzxYloZ9zUFGQBeCOIqEYhOhA3vEem2AEc/iH6Xm3R9y2q0h0WoTWa
         2l9VWl7tqmG/GXsJ5rcpxC8ZkkqJR+zd2xsGHYOucmpmVxeUJinMAsuvYM7mY8LCvD6A
         9JnAtMGkT6aqDYKwfgPkYNXHA0hg5GMRMQzQK8NrxY5ycr94v/QLl39Ya/XXTn4gMAv5
         SFCCCsINDU/L4i5Ccmu5BivqRnbbv6KiHBM8dD+YINzLNSZYEwnzictf60oJsX2u/nQ/
         5F6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gNogjTGQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id g24si401089pgm.0.2021.10.11.03.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 03:04:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id d21-20020a9d4f15000000b0054e677e0ac5so7066735otl.11
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 03:04:04 -0700 (PDT)
X-Received: by 2002:a9d:6f04:: with SMTP id n4mr20153119otq.157.1633946643977;
 Mon, 11 Oct 2021 03:04:03 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop> <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop> <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop> <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop> <YWQJe1ccZ72FZkLB@arighi-desktop>
In-Reply-To: <YWQJe1ccZ72FZkLB@arighi-desktop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 12:03:52 +0200
Message-ID: <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gNogjTGQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> ...
> > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > secs timeout for TCG emulation to avoid false positive warnings:
> > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > There are a number of other timeouts raised as well, some as high as
> > > 420 seconds.
> >
> > I see, I'll try with these settings and see if I can still hit the soft
> > lockup messages.
>
> Still getting soft lockup messages even with the new timeout settings:
>
> [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]

The lockups are expected if you're hitting the TCG bug I linked. Try
to pass '-enable-kvm' to the inner qemu instance (my bad if you
already have), assuming that's somehow easy to do.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtCf%2Bq21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B%2BfKA%40mail.gmail.com.
