Return-Path: <kasan-dev+bncBCM33EFK7EJRBOEOSH5QKGQENTXBGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D5CE26F566
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:35:53 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id x81sf1620323wmg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 22:35:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600407353; cv=pass;
        d=google.com; s=arc-20160816;
        b=QotO/mUnzV60w5W4nqadJNZiFhgi2VcPyYlaqDDQ5HZyopmM1lj5UZ6jNqebW89pqW
         ayFTlFFX9z+3iGLMh5/6EseH35Yvbj/xbeOLjUy52wtY8p3mfKvaXzu63V2ep3MK/u6R
         D81hAM3PQKOdpynzR3Gqr91YnaGXPLSDOMd/396KIip+/QDFSfNerKDehs6f7ZuwfXT1
         oefy4N9ka66mF03bOc+i3VDtU75HagJste/JUoLW0WBO0DO7U79i1x1GcufgPaQcxG3s
         XEhmNJcT+ageG2RRZ9GjNog0uyMD5oGcu+05e+H9d8/77XzhuwTbhyYe5tucH4x65mJG
         6rDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4XpLaGXWA8MS4YEFor2qPC0KOdTWWQaZ7pBHoqpndV8=;
        b=tEriadKImo/PKCPlXRXB3xR88wz0aY82qcu36qz4Hyc+oJGWl13AWNfgXWUVrUiAld
         njpthzbp0HbPanqEXzua4Z0oRFsUHlqX/FHqzUqSenSPuWY6gsttWpAz7CmUQoEwxb0A
         wuCPZDf61cQ/DjMtAB7d6m8+FQobYtziIhbPjLFyIVA4bM/MUbz7CvRJKTjIPKozy51C
         AqrzIJYnSIAuwh9KXpldESA1PLR76KAvV+dm+yKL5Yeq1GP9BorcUTRCvSUns1iqrc7e
         x3toQ1re48RZc0ykEj4mIlDutC86m8XIJSGpFqm7aF0s8j5bP/+VMeIYaFqYml2eL0ep
         v+mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="uis/nomw";
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4XpLaGXWA8MS4YEFor2qPC0KOdTWWQaZ7pBHoqpndV8=;
        b=Bt0oejTEnIZVoCLHuy4nLzD+rgVCogKbYUVrgl5p4A3gfqzkwuz8dO4GNNUPzzszU6
         kzuy/UVVNnuSUfxJLiQJtpGlYqPe50++5tNIrIPb4rvrYchFLUo+9cJw/B26sGILcTzv
         H+QGib6IbKuikynMVtjbFQQtjRDo55+sTuta32RdAG54zWfLJu34DeKgZSKYofgfcpRP
         6TPY1B8At+FJ0RPhataEfrDf/BSYErXxPccw5WJ0fsWIF8zxwIYLwbwS2kjq4tbqi5HW
         DMCLQEFCBSuGwLAkTBbnPZbSCpiKPVZnOzZDrqWHFcYXo7Z+YzNKvi+WhyFU89X84e2T
         mnKQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4XpLaGXWA8MS4YEFor2qPC0KOdTWWQaZ7pBHoqpndV8=;
        b=eEWikRdjQ4lC1G+Xyu/sc6ldHA24iYMO/QOinf0cIuLkCM4cYbtZzqKC4a7QJNWRyP
         qeP0UGBPpylKT3bfybzB+TXgY91CuZtk/I7fas4C8ZLi9eMmgItBFq3jyVx6ihTU8elv
         jfBVmvDIn4D10xR3INiXwpqr3GuqWAXrpdWrUbvKwfTkbkApbb/LTetrTgFbPEjrxWdN
         yo46+l5ZiK4AXlgIEsIM3cZyzxEcqNCEBtJQflqERVPxm3fqPiRGKvva9gSo/ggIsQWV
         AQDlDP/b6VoZY4Jx2BMpKFeaXk9+UIMq2pCNALvG/e8JT+dF+ujQxigFqubjfSz9E6B7
         vpIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4XpLaGXWA8MS4YEFor2qPC0KOdTWWQaZ7pBHoqpndV8=;
        b=PDPeyZ5XEkGnUymT1h5gULCXPNpxIgltupM727E4qk9dJdIXAg2jtjGWm5Yd5i1pXL
         U3KzOV5JcUc76cJSDWdxW7DWyuGbe8Qcf7oJ7TVqWuZ43j/xbqHys9lmjVUAXoIYYJzv
         ySSM8oIlTgQ8BJqo6UOw8jpErSuaPcRZaLQVLQVFZRkjUv66vfMbZ0bjo5L/sbB5f/kX
         AjgsTyB7AsCn2UUXTWAatLw0ULU8YLz3X05M0y5Xe4+3UhlZ3h5py6l48xRPwwIYT6vW
         OqGulkhzoILodH9/dywFFQ6Czg2yosECp6jGC8ig4fhkGLdNxJGxgu28xhhs80psDY4N
         bOCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532opD0bIu6QKAvz85XyK0wtM3mXFrUWWgm/SHKgv1f+vMX4eUxU
	noSkk4WAo5q7+RvXFu2poTw=
X-Google-Smtp-Source: ABdhPJzPsKUhADaEYFYUjc+gLjIXObq+6GOsjs5ft+EFkMsV0G1rNcNyup6f9dEwUbaYUo+C0U7bgg==
X-Received: by 2002:a1c:ed01:: with SMTP id l1mr12341251wmh.152.1600407352940;
        Thu, 17 Sep 2020 22:35:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls3473093wrm.1.gmail; Thu, 17 Sep
 2020 22:35:51 -0700 (PDT)
X-Received: by 2002:adf:cd0e:: with SMTP id w14mr38659238wrm.0.1600407351891;
        Thu, 17 Sep 2020 22:35:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600407351; cv=none;
        d=google.com; s=arc-20160816;
        b=rJT3kqqHqZl/ydca1HbzL9bxAO124hlIGkLz16g/G0bK95BxHv8SNOpwWCe/5NF9np
         9WhSsPWlOLLxSkT/wQj3bKF3H2QnKQRDnwQ7dG3WTsxHlkMaUXyOwZO+EOgS+duFjzHe
         jspJSl9Y21UmFEO8P/zUjxcYRhnGSe/zBR5SqEY5yd/cS5dMDW8qGVxnlhEWYdogfZtB
         aLBfc7NyhxnTQqi14qMbRSisfF2mTgO8K5jiAELDg6OdufHdrlJR/5osScJW4Wg7cNLJ
         pOQ9+igFePPRfbpiKziRrHTmFUDNuO5xMevZXU+fxQOlQO7IYPBDIb0injV/ApkaxpE4
         yxgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/bymMNxBgwleuFgLBFDrHQ+0acGZRuWjBwHuK7Z5b7Q=;
        b=Q3KFBlZaIHp0t/hRUxPAxW6cqMvV/oBsJQMIHCM742Fe8TtmWCm0TeMv+PGGj6wIpd
         bLTv3v/1taq4DzoO+sUHG09ZvjHVtLvhlN7jOa92EXSlod7Oep7hvWnnLVfdEuHAWxEP
         xzrRpT9KwRRHfRyn3AKkfwYreBIC8EF6KuKnKIRzenqlPqbrFEq94FQ1oO8NNCqSujwC
         L3OJDItg5HaaG0nn2l2FIO8I9cRDreM40blGMKg+GANWT2K8OOvX7AU0rKaUTqsLTpGl
         SCPn1hvBzznWyl3xW1cKGUdSsF358LX5xsLJYRTL9uS2iPtG4DnXmcI+6GDraTOSvwny
         f3oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="uis/nomw";
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id s192si170713wme.1.2020.09.17.22.35.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 22:35:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id b22so4726741lfs.13;
        Thu, 17 Sep 2020 22:35:51 -0700 (PDT)
X-Received: by 2002:ac2:5193:: with SMTP id u19mr11584170lfi.518.1600407351407;
 Thu, 17 Sep 2020 22:35:51 -0700 (PDT)
MIME-Version: 1.0
References: <20200917084905.1647262-1-ilie.halip@gmail.com> <20200917221620.n4vavakienaqvqvi@treble>
In-Reply-To: <20200917221620.n4vavakienaqvqvi@treble>
From: Ilie Halip <ilie.halip@gmail.com>
Date: Fri, 18 Sep 2020 08:35:40 +0300
Message-ID: <CAHFW8PTFsmc7ykbrbdOYM6s-y1fpiV=7ee49BXaHjOkCMhBzhQ@mail.gmail.com>
Subject: Re: [PATCH] objtool: ignore unreachable trap after call to noreturn functions
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Rong Chen <rong.a.chen@intel.com>, 
	Marco Elver <elver@google.com>, Philip Li <philip.li@intel.com>, Borislav Petkov <bp@alien8.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>, clang-built-linux <clang-built-linux@googlegroups.com>, 
	Peter Zijlstra <peterz@infradead.org>, Nathan Chancellor <natechancellor@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ilie.halip@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="uis/nomw";       spf=pass
 (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::141
 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> The patch looks good to me.  Which versions of Clang do the trap after
> noreturn call?  It would be good to have that in the commit message.

I omitted this because it happens with all versions of clang that are
supported for building the kernel. clang-9 is the oldest version that
could build the mainline x86_64 kernel right now, and it has the same
behavior.

Should I send a v2 with this info?

I.H.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHFW8PTFsmc7ykbrbdOYM6s-y1fpiV%3D7ee49BXaHjOkCMhBzhQ%40mail.gmail.com.
