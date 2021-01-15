Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWVYQ2AAMGQED5FE6GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59F992F7CF8
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:44:59 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id c69sf4057944vke.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:44:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610718298; cv=pass;
        d=google.com; s=arc-20160816;
        b=otfmqx98D9fzVN202pgj8m9QZHUA/pY3AvAghc50lF/jaGlBA4Jbnt8E2rTFAtlyCG
         U/FhRrZRysbb459CBcfdaupzaSlkSp9BYP9HmZXfrcK9Cut/YknnqQ1eFe1CVJst8lA3
         1SO2E45jHq8nE1rrxU4RZHNgWxEkF4avL8WjkdGxVIHcn5HNESYZ/bzycj/z5N/VTbUl
         mnHS/zsO7q1VogauS+oJp4ThXWxCkGf8Sd5qEDdtZMCaFehG0TLrs3J0MvQ/DMvdjISC
         tOt633ehkxIswxWz0mJZbQjx4ykKVJPKizRBp3sQ8bHLFdACKHR3oXUPbezxd6kMAoBi
         lmUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zn6faj8c80knZCwZ1FYtUjOalTnShFVzxaM3Fn5Xpd8=;
        b=xBaBnER4sS3puvSKGO5m0+HqoDP/Bh0xww4eZHxLOXYM9BTRbiuvGh3dF9yctPX5zO
         OkoFxe/WNUsHhmjNu9h9J9940fbDBOr8KIOuel39um9ubKWEN4DcvC7JGUJTtLRFhFK1
         zHYuqZSl1JESsUJ2Oklp6J+7FH5GUGXqWf1fcBdh5080lil7LSb+qyrH1+IlFlRnvLut
         VQJTepnddJJwG8UZ2zR2byMugqoEUmGS2q6ztyLyoF9imA6/MyLdNxfWa4h8gzY746FO
         axrVrXRGB0XxzptsBEmbHf86g1tsMSr4uqLy+y8iwjKX/GLehz/WZcrekeTvsbgXggxt
         KZBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U3zx+BVA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zn6faj8c80knZCwZ1FYtUjOalTnShFVzxaM3Fn5Xpd8=;
        b=H+LEDZg7v6dMzx5dE1qaDy7PI6+GyGy947tdE+QIp/glRrs5uHFHGpU/jnkIqOuV8p
         8Su67/dnDB9rDPStz8D4Y7GAZs0bMfsYpEKj7S7kljM5KGdHQbu89eNY/gdx4NQ5ajdA
         HhQeonmxkzuiaU2yIaAQJD7CaQ7ATxG0Hm0Z8qtZcVR+KSy4j9CCiCpHfNdGBsSKKANZ
         TEoUzMWQvgkKrHUfQwgkduL9F3JRqB2VychtW1casl+TmRv/6UzOPFSTfIYZSON1P+ec
         Fi7/oSXJAQv1ERrcokT4oHt0DQ3ZaS1rFJB2dn1HIdz77exmWnzWw8Gq8cn4gjbe6hGQ
         ao/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zn6faj8c80knZCwZ1FYtUjOalTnShFVzxaM3Fn5Xpd8=;
        b=oFiKfTSTKRmbAcbJpwcUIXaq7g5yUutTPr656n1huNbuj0ovEMv4esgypFjJmmCXof
         I5cT7yxUdoFQ7ZQmjIdRKxxn37ZvrPB7jLBc4tEp0cetPb5jcwyXHCy/+QnfJVXslZIm
         7cFlWaFU3y9jp3mK39KzoR6WYT7fknu66MxIBptMJ9c1X6OG2JjBSyBh00SDb4rCqSAT
         MHz1Dz5rsGn4jSqBD7QEGTYN3GN6NjipPAfg5XgEXCUkzBt5VmTQWiGOFyIxSBf55d5S
         4r8s+INVXSFUoFN6VnssgutQ2muInByQS1W/Qhi3QfWxV/HZ8tyQ2MpvWKEu11hsgSl9
         YEww==
X-Gm-Message-State: AOAM532/eIXM76+6zXGdznOtrf/Mqt6BsTwnK2qlPwMUBZpOXMy3VlCK
	jHXyeVvtb6r2cBXC4czDPtU=
X-Google-Smtp-Source: ABdhPJz/j2rvo+hPQ4p7p9PVsosaIYC7tKig5zg+meDJ5jx6H6bqu7Z/IGy55hFpaMkWjsO45b45aQ==
X-Received: by 2002:a67:b445:: with SMTP id c5mr394318vsm.19.1610718298424;
        Fri, 15 Jan 2021 05:44:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f457:: with SMTP id r23ls1190270vsn.4.gmail; Fri, 15 Jan
 2021 05:44:57 -0800 (PST)
X-Received: by 2002:a05:6102:732:: with SMTP id u18mr10457094vsg.5.1610718297950;
        Fri, 15 Jan 2021 05:44:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610718297; cv=none;
        d=google.com; s=arc-20160816;
        b=KM7UEqdIEqYTMSxaDehHRdJyHPUtTm2vY9852AmZ9vHudEn12fQh7GpjjYOtcU8eMs
         niAJVr6juB8CrVDIypMtkL1QwpBTJ1jUeTXJ8EK2TwLhY3Ccmcr/1xJv6vieu050DR/F
         QSquHDjA5sFqpCLYUTuOJ+kVRnppO205Q5Vi1vrmhJDGaz9QOpjcVNd9fk+o6s12EGEy
         08386oR+7E9dq4eeolG5W/pypa8e9N28TROiTSM6kCYSIh0u6rq1WbfUTcXusp+HWz1p
         YI8wV430Gi19pGFPETpojvwaAYArtOC4t4JFECRfKUUArChDfYgEayq/UQUsXfPpTyFR
         xoag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hoLRfGrE41S4rKfeCJicect+XhE5pSOE3WmEeBCuXuk=;
        b=EJjJTNQ1gM4W7KaaRbRIWwYsO+5EGY36YsexD8JgzFiog3H6ceZjXL3WWNzxEQ0UOx
         98/koa8rLbyGIrbElU0kUju1pFkZ5qIjI5T/lxXM9R7NI23MoYQ759qDOy+bOwLokdgk
         y3uYmNX+pDQQcvTC++hYXJHwnn/HTVXr4EpXOG3cIDm3IzAevZ66hHCsFkOzgarbEGTc
         IT+2nsOEB2DeJK9pbYlWYwu3Qw2EhlIfjbfZ2zqLJMI1fakJU/ZAQVlKVLhB9inWHaoC
         /bgHOFCGqXyApHJhSFCBOtsgP9xAotZrs0ayzSKCFg1O7D1eUXqnG7seWVnNZd7gIdcd
         R0HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U3zx+BVA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id q22si539238vsn.2.2021.01.15.05.44.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:44:57 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id c14so5997822qtn.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:44:57 -0800 (PST)
X-Received: by 2002:ac8:7111:: with SMTP id z17mr11856619qto.369.1610718297471;
 Fri, 15 Jan 2021 05:44:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <da60f1848b42dd04a4977e156715c8d0382a1ecd.1610652890.git.andreyknvl@google.com>
 <YAGVCxWTBlv4ZITG@elver.google.com>
In-Reply-To: <YAGVCxWTBlv4ZITG@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:44:46 +0100
Message-ID: <CAG_fn=Wgagm2JXrTXanRe2ue=So2_MAXJWFmjzb2ZvU3GF2VWA@mail.gmail.com>
Subject: Re: [PATCH v3 15/15] kasan: don't run tests when KASAN is not enabled
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U3zx+BVA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jan 15, 2021 at 2:13 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> > Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
> > corrupting kernel memory.
> >
> > Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWgagm2JXrTXanRe2ue%3DSo2_MAXJWFmjzb2ZvU3GF2VWA%40mail.gmail.com.
