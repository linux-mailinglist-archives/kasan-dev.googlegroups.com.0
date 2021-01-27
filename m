Return-Path: <kasan-dev+bncBCMIZB7QWENRBCHZYSAAMGQE6ZGUVJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CB6C3057EA
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 11:12:25 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id r18sf764042qta.19
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 02:12:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611742344; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZaYNQg0qZywAs1D5n7xGXZzwYfOoCc+haVbri5dlhyueG9QkrYOIxLj+VqZvNK/5/
         0+VlBUYhJjiiaeDZ2damu92XYkLe8rMmAx8khjh9kZ8LNAhlKy/rpkiS7Th9LDbSIdCG
         EZ16EVhtOJQYMwSnXOfdbgfMOyXCn2P8pND25i76wc+7r/aVCi+hLN7DSus28Ysu73SY
         TBcF3AKqpyVgk6ClNM+xLsIuBDq/FgHYUN/xemxEk11IU0fjp/5vv6tviR/IQyHyi3gx
         vjCwiX/VOfwQ53CseJbYimcrJRcVPjydxho9Eo3SC0E3TXA8HjG3g+L7j5f8rHJtuk5m
         yVVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RY8t2Es21bp/IIv8yw3jLwEQiHJJmt7Bh45jp6b7Gbk=;
        b=PIqbUMIiMHndnMP41EqAlqLHN2khKAOfbmvau0ZcDJ1q1eLrE3mqc2zpgd55oJ5aml
         EsxICQ2nN2ZAs8gNbxvaSKKaZTPjRvApx9aNdzsvMIfJHT37YfCwJ1eVSfG6jzQolQSg
         HSGiRFTO2ZTWuOYcqeg/tMzoZ5I3x+spwqKgp7iFvMOmdeEK9u+ETVJ2rrLSSrQPq08t
         WJrpNAXBwQFJnJF/qEDA5IR/XO147VzQy7BOHKj8bZErnHaGPLJaj05ALKXx1JtySr07
         9r6o2fU3UJrliQ1HPNQzVpmv5s3Kfe0r5JCxlppbB0wCRKicTurfTWyjRIokZ80Zl7fm
         Niog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NdlPaeby;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RY8t2Es21bp/IIv8yw3jLwEQiHJJmt7Bh45jp6b7Gbk=;
        b=inKUOCWxYufZP0ugWvMvs2I72Dn5O19a3tfkZSkLi+QddZBq51UP3pdGDJOBPc6aU+
         KPhporyEMhiuhHEbjqbMuS+fFmuo3d3PTIYf3tiIv6Ajg+3vpn2ncOvzA3MlO5DKWwZt
         KO03zD4qqFPzPOhLjPUn+8QKEVEvDeDH51xNtSqqbcIHLoaxG9vOvzkPwRGQPPMzlNBJ
         bUSpaSoNTMvyi0H9ui/L/C8lqHUNMIZp3mDwJB7nHJwbSn+0rTjW1OkLj4m2kl7UVPIK
         zQsJ47KZ5PERKFQiEeceyqxMgJC6riM2pKjef2WSNJ3QLswYD3lhaiuBSzY5bFZWxgbg
         2iDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RY8t2Es21bp/IIv8yw3jLwEQiHJJmt7Bh45jp6b7Gbk=;
        b=j+PqTmEg0vzy33QGdazDx13hiJsE7hzJqo6PFlKOgDYAoHp3V7Sm0NrpqUbMMw33Uz
         ltEuPgPD5YTXxS/IvJn3WVulidDS4qGrbYabx9R5fnzFHBJU24B+lgRv6NYBX4/pFs+q
         M/jIdVuFI38GxfE+voDPTrZVdgEDX3jn3XN4T5TH3xHPdDXpx18YND1Iu0C1D7VpsYbP
         G01jldU/apAX8ZmD9gvLPd03BsAn/BfPnQVw65p/I4ffrEKbPHT3JK8udaCXtJ7LVKPn
         +dR9HaeJZT5KWiwzXU2rWzIkI8VGlC+XRnz86RuvaH8go3M29AxPYYuUefPb8645x918
         uHbQ==
X-Gm-Message-State: AOAM53333r9iqwEaxfEgYDAwEZ+A7AXqPRwZO3rJ4V1YNwzVy2sQXq5D
	wdeZjbJBG7UlkXy8Eo3T0Z4=
X-Google-Smtp-Source: ABdhPJydOTQyVTiGSkqUol82uZZiof6+zpJNgWJnfH1oGh960I504KNWa+aV74MxH9nJLwMdlCD7jQ==
X-Received: by 2002:a37:7003:: with SMTP id l3mr9949498qkc.467.1611742344655;
        Wed, 27 Jan 2021 02:12:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:a19:: with SMTP id i25ls72463qka.2.gmail; Wed, 27
 Jan 2021 02:12:24 -0800 (PST)
X-Received: by 2002:a37:5903:: with SMTP id n3mr9938212qkb.203.1611742344347;
        Wed, 27 Jan 2021 02:12:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611742344; cv=none;
        d=google.com; s=arc-20160816;
        b=i4YHw28aAOBeKui9oS6Btll97iPmdFXIaTT8E4BQu80UfQANIv3uXuGD4kEMB+TBcy
         M73ApHa9chMgv6QBk2G2hBixpZCqUILGBhGygOsoUlfI+7JQ7ayOajJbOBP+bsICNSbi
         eCQ7Ex7/U2TgAasS33HQ7PYsj/LDcCcWHF+UAXGmQJtFFSLIHZhKKna72i/IJtCA4CQB
         AtQMHlQXO4jfPGGlQDc/dsPPK9iH1GeiLNaDDKdIJHGne8IfUh2QLuP2FZ+IXwtac1Yi
         V4Pvnh0wK7oBCv6l3+uOKZwj14ornwF9T85Xtt6UNqLw+kYtAnNdCFH2P/a/bC2X91vA
         LX/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C3Ju8o6gsvT5Vb/cFN7DKyPEfkRkPBuMLdHR5PZLWA0=;
        b=RrG4/kCOkKgKvqZNV4CmVacY0iq8lO6VAS46KlFRzFVdoEeXS/pt5CDVOm3hUvjUn2
         7EKZALCOe6Thsu1C04FEdu3TYCePt15IIjyX1Zl1hbOrE7eMyWQ0xQtrrSsMOSMC7zEE
         OIN3xQsMazQzJWYFc6bcUaD9zpd8vuV0XtWjEAHR3RE2k7pVfDYp56T44aB0USpMsRBN
         Pht7fOQAsKGkqx3KQ76p0JiR8y0hEJQcSiLCIzl6SgvZWcxR3xU1/MkhW8+03afPAW37
         PX3ye8TU/J+d+5tI7lhK8qeq5MDyh7ZDqoLgMYf0D1gQG6R29DGt7S9mdXZ+897xRrsx
         z4bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NdlPaeby;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id c3si81316qkc.2.2021.01.27.02.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 02:12:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id 19so1178737qkh.3
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 02:12:24 -0800 (PST)
X-Received: by 2002:a37:8cc1:: with SMTP id o184mr2957823qkd.424.1611742343747;
 Wed, 27 Jan 2021 02:12:23 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <CACT4Y+Za1P7-g8ukSJOcy-TWurz4HXxW4wau0VsEDEgoUvuZLQ@mail.gmail.com> <CACRpkdbQeYuy2DoG4uWi1nqP+KCU1LTcVPjsV_j61N2LL4ugjw@mail.gmail.com>
In-Reply-To: <CACRpkdbQeYuy2DoG4uWi1nqP+KCU1LTcVPjsV_j61N2LL4ugjw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 11:12:11 +0100
Message-ID: <CACT4Y+Zi=oqvOZFVakbOGzBMsE_wZHGe9nB=V=mYy_urJxFf+A@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NdlPaeby;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
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

On Wed, Jan 27, 2021 at 10:57 AM Linus Walleij <linus.walleij@linaro.org> wrote:
>
> On Wed, Jan 27, 2021 at 10:39 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > It's qemu-system-arm running on x86_64.
> > But I don't think that bug is related, it seems to affect arm32 in general.
>
> Yep. I am trying to reproduce with your defconfig.
> It seems you are not using vexpress_defconfig:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm/configs/vexpress_defconfig
> ?
>
> Instead this looks like a modified multi_v7 config, right?
> Then a bunch of debugging options have been turned on as it
> seems.
>
> multi_v7 "should work" too but I haven't used that.

The config is based on vexpress_defconfig:
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/arm.yml#L5

With a bunch of debug configs on top (among other things):
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/debug.yml

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZi%3DoqvOZFVakbOGzBMsE_wZHGe9nB%3DV%3DmYy_urJxFf%2BA%40mail.gmail.com.
