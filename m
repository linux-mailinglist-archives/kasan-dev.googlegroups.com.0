Return-Path: <kasan-dev+bncBDE6RCFOWIARBDOQUX6QKGQEAWEUESY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EF3292AC064
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 17:02:21 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id x16sf4486264wrg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 08:02:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604937741; cv=pass;
        d=google.com; s=arc-20160816;
        b=IAI8MwPVWX3Aq7AfIpD/eUzDsfhCmgA/hBWk/CnOV9DmSi3B3Gm+tNfesVrqKfhdvc
         eDOYFa7QTzvQuL44yrZQi8U8l8jGaHLPLKSK32OoBR+sB2bobJcOb8Pui+ZVu5TyGSx2
         ipGv6U6QJFA9nIP2C1e3ihjnRcHl27KDtUsjxU36D+ej0QATTJObzmvf5WhuvkzC8iV0
         /aXdqznF5rIieDopjtDtCAlsr0rid1gU/AO/ZJnkLk69+usOHYXYijiFSVvWd4eNRRyg
         +i4qjxoC72Rba62CP8f6QrPh8N+usR6jUKmFgqOI6/mMUKiCe0B8nsw27+hQx/5PfyrE
         b1qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=jc4LdCVPfV86kUiDSYxsvtWeqFe/VsosRTtlW9tkQr0=;
        b=whTEIvLV66IDG3V0gv0jaezfS8tgVA8eR4f4iwJ26VSavLdewTudE6327/O0+B/b9T
         G9edhJm8+PBxqreouTh+9crOkNsvQUoAl0bqEGJlpFhYcpS06Um0BZJFUVrRldtAFdA6
         odr0u73iN8RtPgXole1VAHALbprrOWAgpWzXCBpavSH2ATIvV/BwGPgEudRwfwuW3/5T
         zyAKdchirkV5TAk42LYkf6wWdxV1pgfKD6x4HHAqOVDVmlQsl+uIiYFwhBIQ0iCTzQav
         sOYxtw55cGs+axRtZ65bfs/hWEnKLj3u/s6SFjDPR8aeGLewrnJde3m7cU7CyMimXvV/
         +cKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pFVPI1xk;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jc4LdCVPfV86kUiDSYxsvtWeqFe/VsosRTtlW9tkQr0=;
        b=r5yoeG51uU71pNwXz75omTPYr8JlkYVLTO7OxKPvrWrWALYYtsZ7JzE1pH5Bo1Dv8O
         UZ9vEseF6F9dj6wdXAJKu4qvdcjky8nHqoQVhMuKWqbjBRzUsNdcq6LzmiA73npHxaam
         hJQ3hqQJG6ix2+7PZvJHokHVMHrqO2lBVh72lBbokkm9J+fNiad0gIm6ZQSdPHO4O37p
         f24XpmGBkVhKYWhXfQu6GjGu9C0Uqo0svFCphSLol6P+LB+Fzcnv/rFKspHAy8SVG5l/
         zab7y/3sf4HiCcrOKpGgGZDt9iL9PaOn3eCwlC7WhBbhElQMDYZyzT8nBr46bUxpBSzl
         yLEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jc4LdCVPfV86kUiDSYxsvtWeqFe/VsosRTtlW9tkQr0=;
        b=duCKpj2z/mQUhiM68uJFx7XlwO03kDWo73u1ixOYuBukbJDSk7J4VyALTxaxqYuUSd
         gnkPSxt+O7eQoq+cUgzEX4hkV+laHd3cwR1nHU5Scic3V6DKcGgByg8ZPFX9uOOKxHV6
         x3Iz5aD7w7NWsrAOqAKKpLs3kcxS9qhQZhPrNd3CYuBrp9o7bDSJIAmLk8wtoGk4crC4
         jyS6AFZjAUIO9EwNnEfj5R/Gv+3GKu3PIQLGVrICqHWQqzf528hwTszi2HG4h/xfI/AB
         +gSdEzjvI3ni9MczXUAr3RAx9WtOFEcbtOBg646DOsF08Kb9/PVb69H2CvaObaxhR5Hc
         dgqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533f5VnPgcnWUQ9n6XkOcQSudNxA1/KfUwgflaZnyw075Qxaf4oB
	TQBEIMAlKpWvUB5Vp7/hbQs=
X-Google-Smtp-Source: ABdhPJwBN2zBtbRULT4rGXiVL10Tu1X2upcgpxsAqnBd8eFfdk9l7GSNnk92aD8rxXtYEAGQLk1HFQ==
X-Received: by 2002:a7b:c954:: with SMTP id i20mr45810wml.56.1604937741656;
        Mon, 09 Nov 2020 08:02:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls4796666wmb.2.canary-gmail; Mon,
 09 Nov 2020 08:02:20 -0800 (PST)
X-Received: by 2002:a05:600c:21d5:: with SMTP id x21mr16123917wmj.133.1604937740751;
        Mon, 09 Nov 2020 08:02:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604937740; cv=none;
        d=google.com; s=arc-20160816;
        b=mNhBXi3hniFoVGy0F+saulCuZUf5MgFr7LBdEWnv38CEqotICXRXUrTAiT9+00teeR
         +ERMZVIE48nR9cZG49PyFEJC7Ij55EDvdw8+nyB8QKn/kkni6U4CNPZIL7GdqWDhbMYu
         2Bhy6keSeAAUZnCdZ/vMVxkJB+Zin4eNhH+TgjXgZToal4hra7WSTNvwzNijs3trPZPC
         LXnGeUK96eq8qQsRkNsh88A1Fi+CfOKFwforrsWDk3DIZkTvlYGuH2VHM5NXeAmmKm2M
         2E+mF3ZA7vaufqZvhcETkUuPgyjSgByPzhVpgPJpZ+QJBoGwrhAmvWGRP+SH8AdlvISV
         uZgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LYXkVfDx+sIP3XjpaTJvSwehzbCXVjxjdcBKl6KL1A0=;
        b=uXGAjrjp3stx2r5H3uk3+gosjKJPOJrdqhSSU+zpORi0LVepwTy7w2VxUGapgb5KoI
         KVhhbcwQZG830LKShnziNYzgwO37wT2YID0e3F8pXQvcgzP2D2wfekDpCVOpvKzNKw25
         pKz/ChxxShLbq1Z0aKcp2aCJo1BRCtCJznCT/LnSTFPhaqQ26O2IfqveXS7URrL8hD9Q
         fX2TL8wleGS5ykvDHWz+dz30JvKuwsYvLoRBPQT1/9xYmYHHThtHfhvx5EqEQQefzhOp
         +liQmEge9j0R/TTiPwE3guBJ/QHUSvS8NeT+UpPMpl/plQ+oPYKPVoeXKHr1+0gYJy4F
         r7zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pFVPI1xk;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id v10si145802wrr.3.2020.11.09.08.02.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Nov 2020 08:02:20 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id h23so6500846ljg.13
        for <kasan-dev@googlegroups.com>; Mon, 09 Nov 2020 08:02:20 -0800 (PST)
X-Received: by 2002:a2e:80d2:: with SMTP id r18mr6952555ljg.286.1604937740121;
 Mon, 09 Nov 2020 08:02:20 -0800 (PST)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org> <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
 <20201106094434.GA3268933@ubuntu-m3-large-x86> <CACRpkdaBnLsQB-b8fYaXGV=_i2y7pyEaVX=8pCAdjPEVHtqV4Q@mail.gmail.com>
 <20201106151554.GU1551@shell.armlinux.org.uk>
In-Reply-To: <20201106151554.GU1551@shell.armlinux.org.uk>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 9 Nov 2020 17:02:09 +0100
Message-ID: <CACRpkdaaDMCmYsEptrcQdngqFW6E+Y0gWEZHfKQdUqgw7hiX1Q@mail.gmail.com>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Nathan Chancellor <natechancellor@gmail.com>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Florian Fainelli <f.fainelli@gmail.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>, 
	Arnd Bergmann <arnd@arndb.de>, Abbott Liu <liuwenliang@huawei.com>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Linux-Next Mailing List <linux-next@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=pFVPI1xk;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, Nov 6, 2020 at 4:16 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
> On Fri, Nov 06, 2020 at 02:37:21PM +0100, Linus Walleij wrote:

> > Aha. So shall we submit this to Russell? I figure that his git will not
> > build *without* the changes from mmotm?
> >
> > That tree isn't using git either is it?
> >
> > Is this one of those cases where we should ask Stephen R
> > to carry this patch on top of -next until the merge window?
>
> Another solution would be to drop 9017/2 ("Enable KASan for ARM")
> until the following merge window, and queue up the non-conflicing
> ARM KASan fixes in my "misc" branch along with the rest of KASan,
> and the conflicting patches along with 9017/2 in the following
> merge window.
>
> That means delaying KASan enablement another three months or so,
> but should result in less headaches about how to avoid build
> breakage with different bits going through different trees.
>
> Comments?

I suppose I would survive deferring it. Or we could merge the
smaller enablement patch towards the end of the merge
window once the MM changes are in.

If it is just *one* patch in the MM tree I suppose we could also
just apply that one patch also to the ARM tree, and then this
fixup on top. It does look a bit convoluted in the git history with
two hashes and the same patch twice, but it's what I've done
at times when there was no other choice that doing that or
deferring development. It works as long as the patches are
textually identical: git will cope.
If there is a risk that the patch in MM changes this latter
approach is a no-go.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdaaDMCmYsEptrcQdngqFW6E%2BY0gWEZHfKQdUqgw7hiX1Q%40mail.gmail.com.
