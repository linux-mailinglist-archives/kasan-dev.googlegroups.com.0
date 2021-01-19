Return-Path: <kasan-dev+bncBDE6RCFOWIARBXPITKAAMGQEDMSX6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D2D632FB55A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:28:45 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id d2sf1966971wmc.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:28:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611052125; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wxqu+cJ+ap/mNvN0Ge0TodUcrikqqn687GYvo4gkoppGb7h2dfYctKgoqLWiNs2Pgk
         9hiVSv9B60jont7WGcbVkGeJMEcrTmpGxVoLC7PWLHD+Vj8PUbjj1WDRwi7/0mVsmAmJ
         zPuabmkIR0QYkf08/NdjHjfeq7BaJP+fRqVyavdU3hMyHa7gx7XHpIwxNQL+arrnIt8B
         +8qN+SukepTsGJSEwy/z+4V9SU1sjztrLjiJRoQosSJe3KkJgqIA/dwV20ySnR/xjKw/
         vo4x2Bl/XbTfkulxOkm82H0KfJ9c8+7O2T4MNxFDHBy6yX9ALka1q8CH0UMNO0AT3W1F
         GuuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=nvZ3JCOCV2pMDjYVyAzcKP+/JjVt9ZMdXiFUYWtZC9c=;
        b=uMpAaq4/VLe3RVJPc1qzf34UGhpnVzfb3oGSeKxzTbW+qYjA4LnBot8EpgEA7aFTC4
         +PN0tNunkMrKjXNwyxNkRPA/oEbFZHlBnqDEAwM7QOYXIj2X4SlhV9bhvFpQDBuUgInf
         pGYofRKpn6RaP8tq86NFrn5Cpv3oQpxddauN3THT0OJsRibclhbxc/RZ9RJTj9fP0gBx
         Ux2cTC8dLrsfaf+ZpkkO6Cb4716ml2IWHvkcu0p+oLlsKtFhUSiMOUUF5gT2979yNZRD
         2mvmRiw2ZRb8V0UDxUIV1bMg6HTe36swYBT8oMLSih5YIuehWZGWHvKzlZ0S3PDrEdYY
         /m6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="D/t8BDP1";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvZ3JCOCV2pMDjYVyAzcKP+/JjVt9ZMdXiFUYWtZC9c=;
        b=P/rIZvU+N5Bf4RRyMuMsM0rWrPfXBUczYNKepQERncc56AbbYa+a7/Bj2Vu9jH/DY/
         gb2I55LXRgejPWZ1PsohFq0pFFBEBEdPfJmVP0ugFr/ylnpROQnKfh9RgVxG6C9KIqLQ
         2cb4+PSpoK6bXulhI3gc8sbw+YCYXGFdX7p+ZzpvkpHDnmyg79gA8j+zVXYUrvs8BJMS
         kse5clEU/wGXwXCK4v6k+Quso3EBhQFUlOyaZ8N1eUiAsq+ksG6yhus4ieyl6mzclL+m
         63CuiQK7Ekem1lUK+L+EoOc2i2uYRU7lyK2qpav7NuMN6C2kSYV/BzS9ZvSyBl/FmF2l
         Rp8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvZ3JCOCV2pMDjYVyAzcKP+/JjVt9ZMdXiFUYWtZC9c=;
        b=pW4H5DbOo2CUVYWZJUFIUMo3sgkRc9te1ExT0+prXaKA9VwLVvjVgPBQp/PeDqBlDz
         EM6DH8rV3NLZJCHu6/HzsAD6pG8e/PTnpZGqg0iIkGqw++1iBeRRNoSl1NjWzRY5PDhm
         jWBjw0GhajWyxnTidTidi5pyCy5G908TZRvxL8S1/mp3zcDPcuJ4neKlJdx2Ksk9C+ms
         uKq1qSMwlQ9sEP/W71hRlgwsD3V0UfH0paiUqHI1jVMx9Aea0R2H1LZ1QOoecjtKAVVq
         2AICKfF2foTdcw/bR+xz4U8M2t1rgWGryj/JYknO617QDjKAb9JedS7MVO/hKU+wi+OL
         hD5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SUxIeKf+lea9z5yxE8efezYqiy1aGEZO9Q6Mntsh6vvwtDo4f
	Y2jprdE8bFe8G+2rifAL3Lw=
X-Google-Smtp-Source: ABdhPJzaiYMHb/1q/IYmNwhfpouA6dVYCDikvB23trskPPnNGKu0BxfmaI0xY+tFSLxpD+2q0j/yxQ==
X-Received: by 2002:adf:f401:: with SMTP id g1mr3663207wro.258.1611052125644;
        Tue, 19 Jan 2021 02:28:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls5682537wmb.2.gmail; Tue, 19
 Jan 2021 02:28:44 -0800 (PST)
X-Received: by 2002:a05:600c:2295:: with SMTP id 21mr3443082wmf.133.1611052124859;
        Tue, 19 Jan 2021 02:28:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611052124; cv=none;
        d=google.com; s=arc-20160816;
        b=q6Y8wVj0o3vNjpIdjY/vMyOz+0jNIZOay8fxbSAHbl9SHTL3XSWU06FgMTFJkJFC/f
         hXMSosLx6aiQEPD5EhgGozQNDcToW54YESrqVIzGKSM8RQp9n52NekgdCRhWqPQHFyHp
         +rySOAMbAXOLG1vv8ivoKXovQmh2DZt/fjxP3bkVFIKCGdzEA/RGO8tplSqV8kDuXiph
         OJuDHHVVfHPBzR878HcoASHTnBjNfDIyTY9Bx/+W6DjtqOEZHu0ZJTgyHBaeTBpDCi1C
         mVWPsWfznqi3T2zxYzbjZgtB6NfbOfFamdewdrZqIoreN9SKqJvRWa1XSBNNm7SnuogG
         4RPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+/3NXmPgV+dIzf360Hy689mFEDN7hh8RZvr5EOEBKk8=;
        b=Q9vPHtJO3/bhkDPRHl+r76dRv5WXhPu7kND5PdAUXWYP4LoxtVc2P3eJ8tNFZ6NIQv
         EDR2/y3EnwEhDhhuKAVQkMkDSuzR+uvM9JKy/6g2nAjMuacFA7lyP6Ht1cMMeE/IZKAs
         i60xupObc3bxqegil3vSRMCdwP+dYzAsHDsMs6cw6iQjqdwMxBMbn93XWElKpX0eRfcL
         /D1tM2whXB1F0KRlQ8HxzTGwFfjCxc6irWacX6Mc3D4lSqP4X0cx5ti5mTVxd9uLQlFN
         Cgex/wuaEPFIQ3xJoGZzsEUXeLy6GL0sK5X0Dv8hfWq6SOZOiVFSKsxvuvY1kE9blAQO
         7ZxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="D/t8BDP1";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id z188si151576wmc.1.2021.01.19.02.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:28:44 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id o17so28357603lfg.4
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:28:44 -0800 (PST)
X-Received: by 2002:ac2:5597:: with SMTP id v23mr1513022lfg.649.1611052124589;
 Tue, 19 Jan 2021 02:28:44 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com> <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
In-Reply-To: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 11:28:33 +0100
Message-ID: <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Krzysztof Kozlowski <krzk@kernel.org>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="D/t8BDP1";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Tue, Jan 19, 2021 at 11:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, Jan 19, 2021 at 11:17 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> > > > You could also try other QEMU machine (I don't know many of them, some
> > > > time ago I was using exynos defconfig on smdkc210, but without KASAN).
> > >
> > > vexpress-a15 seems to be the most widely used and more maintained. It
> > > works without KASAN. Is there a reason to switch to something else?
> >
> > Vexpress A15 is as good as any.
> >
> > It can however be compiled in two different ways depending on whether
> > you use LPAE or not, and the defconfig does not use LPAE.
> > By setting CONFIG_ARM_LPAE you more or less activate a totally
> > different MMU on the same machine, and those are the two
> > MMUs used by ARM32 systems, so I would test these two.
> >
> > The other interesting Qemu target that is and was used a lot is
> > Versatile, versatile_defconfig. This is an older ARMv5 (ARM926EJ-S)
> > CPU core with less memory, but the MMU should be behaving the same
> > as vanilla Vexpress.
>
> That's interesting. If we have more than 1 instance in future we could
> vary different aspects between them to get more combined coverage.
> E.g. one could use ARM_LPAE=y while another ARM_LPAE=n.
>
> But let's start with 1 instance running first :)

Hm I noticed that I was running in LPAE mode by default on Vexpress
so I try non-LPAE now. Let's see what happens...

Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYwT271D5o_jpubH5BXwTsgt8bH%3Dv36rGP9HQn3sfDwMw%40mail.gmail.com.
