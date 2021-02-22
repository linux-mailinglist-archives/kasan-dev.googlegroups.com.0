Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF7GZ2AQMGQEXEN62NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FC053218F1
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 14:35:21 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id x190sf1052462vkd.12
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 05:35:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614000920; cv=pass;
        d=google.com; s=arc-20160816;
        b=aaSxwmI/20OjPcSnz7oPYRbLXlLij4CWAEV98hjkfmUoJ7h1I81RHLsrx9ToMFHk4J
         +sFCgxTYvr2D19HD4wRCmPKPJRsb/RDLYQ+c6+6XryvDEb4kpbFJ46FcN2SaKeEwAMU9
         IEpzd+zU5W+e5hXY6viTKOOhhXX3vUsyx9xwwnMh0AZ6/uycD4HgDq1kghuGtrvhv6lj
         SYR1TCfitWr+Hfma+KoBCGWIBuDXMA6L9nBDR+A7HAxkdKP5lbMqWQSNnGEt6oO4UNle
         aMFtmasiSyX2zCHgBjwnl0DHM1zPBFSmF0DhmCA/5wwjylQ+AV/vrln/+qfVNCL+QHT7
         TfsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KYvKufDXwuhzbALRhn/zxIaIVpgGdfwIO6ofV7kktYM=;
        b=U9aldCUB1eepH8GWEv0EHvllhdfNhUr++WUzJrcTAm13dTiLp8KcfhICaFj6GAGeZ7
         mWSGanjP3dM+hvO26UNnwZZ7onL6p4mfJ0txH+zGbsCPTvsxd0O8/1TyxqLOvJeJI6an
         ZqjTyTZylF9Dx9QyBhEOgd9jHrSybrqOO0OjyDmg5bbRflKbyA2hLkr/KOjU3lWboADD
         Z1L/eTKpYsE17rdw3Ctf5pQZ3vOyIWJdJGOJy6DP/b/VgQhufisQ6esEajynKQkRFY/j
         6/6U4a+oTJc/siWgXBQPoDB6ygM1LrT9tJTYmIQc76TeyMGauCyILrbtT5evAdo7dpPA
         wWqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mUdHcv1E;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KYvKufDXwuhzbALRhn/zxIaIVpgGdfwIO6ofV7kktYM=;
        b=rLC7B+jd0VVtT+QBBg2TngeuB4gCrjhVMsm5GSoi7YUlXN9RpyKZrrwcfrGu55+k4p
         amSo3Bjxp1Hoy3cI4nWaFV3/8YjlNEkEpOuOe8I9fik+QHlDTHJPASby38GRRWYkXuay
         kxG1D88gL8DQHAAPMt9dy+azL6CWYj3ZRBuKC/f0aAJpUjMkA1uESB4NaUrXoAO9eeYL
         ohwRBu8tcD0owNUr24orbDcFZ93ipxiyNx5f12HhHgafg7E/wf4ZufVoV5HrEH6803DL
         rdMgYl4gf5jeSk520okRjdraZGQf/GIG1Hy1mgxXenzemLSUCCKhFZN7gyllKh52YIKq
         DDXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KYvKufDXwuhzbALRhn/zxIaIVpgGdfwIO6ofV7kktYM=;
        b=mJSpLikI/dNhmLK41HB+rj1E9V39jfdmQmE0J6dWktPcts0sB+NXDOLm47ZXNYkP2C
         P/cztBT32eB7pHiOQ6d7d84xbaHTbP7s7sVCO3Ava0EcNASvHXmFsEdKt1XlfuPbNqtV
         4AhQkpJsHMNrBdsECPTXjBsaSdAWGASyvvwZoeT4+n1YJW2jBCRPfXiAmAWNGX+hhDM0
         1tSeBUZGZ/xYVqcARS3votXzA5bLKswqMhWkLmw9ixmgmjIo1WBT49ACme2bJSIeBY7N
         OWfdGFax2j3y96n2Or8917SILoHP/fA7m7mJhP9qJssByw5gUaRCRGNZNHVcbIq7a6lj
         V+GQ==
X-Gm-Message-State: AOAM530Elub15evUWTaXgS1bxjcnfH/wU4hi7/pyYh6E7ztrvMB6TgJV
	+5j+X3iRE88D2EmH14HHIM8=
X-Google-Smtp-Source: ABdhPJzre9RG8vBFC1LoeVz50/uBVcBemm3OgMn0htbM2OLCfaLxzmAh+WkZILC9V39TH6EYBVRxEA==
X-Received: by 2002:a67:ee13:: with SMTP id f19mr12690160vsp.24.1614000920029;
        Mon, 22 Feb 2021 05:35:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:604b:: with SMTP id u72ls806879vkb.0.gmail; Mon, 22 Feb
 2021 05:35:19 -0800 (PST)
X-Received: by 2002:a1f:8d54:: with SMTP id p81mr13535614vkd.10.1614000919564;
        Mon, 22 Feb 2021 05:35:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614000919; cv=none;
        d=google.com; s=arc-20160816;
        b=FhOQ3mKN0BVWAAArlYJH3ummXGju4STrED4362THUAMatdXPYLbV8ZDMYD19UEdLv8
         ZVJSyFQ1JtLjtDSrvFvwHzneurCJtDL9XnsR+iqyvbjCHLmeDz3ni5QpUJk/YY4zLYvE
         MexExILT/6BPLx/BJFIuDLVhyXijtfouVBxtfviN7KgHtf+tBFpVKW1HJxA6XXpGPVsB
         x4JZa3PQLxqROl+GgRgN27dVEyGXoQ2aT0iIJOrJ9MJCBfOnkyeljbkxoc1zXuUylMRz
         jUPdhXLnV6QnjGUhZbuuD53pbVMx0nsWzAVXjKO8Y/2TbDahtI+BmVtn2/EewbCUXlNN
         PpMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bctf/dzCv2h8tPgb+fc7WxfPbgnBZqLLxVvk8KfYrRI=;
        b=Y6yd6q+yJ5Ihj8849JbCbCMT62sBU5v30CFU3ZpNvnyOCcj//ubSyCw9ZqHMQMlaYm
         H2Smw5pO9kW5umq0XHnFHh7JY5/OoXkxx3mKFZ9ThLWWPbjCHJ2hLWL6SA+fSun0rlul
         JpzfmNnsnI2X9IKOnAerGQKOv/Z2DY/8aZzSfPK7do1xdkp3BccALcQeimzoELkHmbP2
         4AEfIn1K7FrrBb06hGq5+bbMwD1u2zGJdUDi8Bl7zYN+o8y4uJ+Q6NOeQquXo8L913qN
         pW0ZhPQjyy+bq+NoHtIiBWc1AAgZAWyn3VLx0DTmS/KPSnERsEFUlw/6PxfOOWStD2ZS
         Jm8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mUdHcv1E;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id h7si502835vkk.1.2021.02.22.05.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Feb 2021 05:35:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id 17so4441785pli.10
        for <kasan-dev@googlegroups.com>; Mon, 22 Feb 2021 05:35:19 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr23471873pjb.166.1614000918571;
 Mon, 22 Feb 2021 05:35:18 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-8-vincenzo.frascino@arm.com> <20210212172224.GF7718@arm.com>
 <CAAeHK+zg5aoFfi1Q36NyoaJqorES+1cvn+mRRcZ64uW8s7kAmQ@mail.gmail.com> <fbc215de-82f0-cc6f-c6f3-9ea639af65d2@arm.com>
In-Reply-To: <fbc215de-82f0-cc6f-c6f3-9ea639af65d2@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Feb 2021 14:35:07 +0100
Message-ID: <CAAeHK+zUCY8J3gHPAU6fJSQ-fK8R9JHER7PxqWkvbmbdtiLbEQ@mail.gmail.com>
Subject: Re: [PATCH v13 7/7] kasan: don't run tests in async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mUdHcv1E;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Feb 22, 2021 at 12:13 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> On 2/12/21 9:44 PM, Andrey Konovalov wrote:
> >> I think we have time to fix this properly ;), so I'd rather not add this
> >> patch at all.
> > Yeah, this patch can be dropped.
> >
> > I have a prototype of async support for tests working. I'll apply it
> > on top of the next version Vincenzo posts and share the patch.
> >
> > Vincenzo, when you post the next version, please make sure you rebase
> > on top of the mm tree version that includes "kasan: export HW_TAGS
> > symbols for KUnit tests" (linux-next/akpm doesn't yet have it).
>
> Fine by me, I will drop this patch when I will repost in -rc1.
>
> @Andrey: If you want me to test the series all together, you can send me your
> tree before I repost and then I can send the patches as single series. What do
> you think?

I'll need a rebased version of your patches first, otherwise conflicts
will be a pain.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzUCY8J3gHPAU6fJSQ-fK8R9JHER7PxqWkvbmbdtiLbEQ%40mail.gmail.com.
