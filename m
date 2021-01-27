Return-Path: <kasan-dev+bncBCMIZB7QWENRBZPJYSAAMGQEYX3CVGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FF6430571B
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 10:39:50 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id n12sf999246ili.15
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 01:39:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611740389; cv=pass;
        d=google.com; s=arc-20160816;
        b=nlzG8Ixb4TB0ZCNHEI2oUn6Tx/HAy+UFi2kdEBUVAf5yuFzeP6u7yF50pj/3wxtfJz
         6eZ/U2lSb8AF7EM9oWKmtIhnJ9GgUNilSHGIxa6hsxbIFwYk25/KD+TymC41xPvlWTQy
         hlp+G8d4zmS1qqs/3EGVxuyUh1kAI8jjfbY9W3QcwvElZr61h3OIlH1iUiEaNDTdIoOQ
         rLFUQusUCVtiLUmi7ZJcOPog121zouvW/ApiCV4luildXKSH/n3BPX+4OsRnrdM8oKec
         IIs3jubaEpXIDxV/e2RcfRS/eV3JbG0IdKrM2zNfbMYYB+1b8DmK0HatJ/yxQGoVu7lj
         NQ8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/srpnacSVdaqzz8ltm61ydBt2uwB1ULRHp9fiYILwlM=;
        b=b5tjpiqe5rRSyesjQJzgLCtpNnRnNf26qdMKGycd8Oj7ii5LPCjT2yODKDYgi0ZRpY
         UMvYw6d9ClaWsswBdjsUm3UoKi0iuxEql8s0KQuVERB2lThyWnRf1M8v7xo+RH/mUR4n
         yK6yO3XF8UvV8YanchFBvKuTMq8L1VaiKAD6VqmvTPELzcDeSdO2jajDrR+GzYIJSKaw
         a0FmiBE+xx8DKRFLYKt+pG1FVWE80Bmc945d0CcRrg4vLox3Wy74vEGM5VUTxQG1mSdk
         mlbjwEJEOsYK/CnOWNGRVFV3ihxjbIQToP9atAeL87187kOdGKrtM3KihgIpThIo2hc9
         zOFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=izgwRzB1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/srpnacSVdaqzz8ltm61ydBt2uwB1ULRHp9fiYILwlM=;
        b=kuWm7260rBlxLYD8kiJMCCgUtcbYisJtZpyn7rKgFQGUM5w+8C17mOaHwrsLTfYGAj
         jDDjv3K7MHF1ePTtCERV6kWb9eaER3kyXjl8TUNB0pXVLzYhJqjsQj/cZ+WX8r+BFvwd
         xnp5UFcEwdJ5cZa7HX0nCaHmAOp4lDuJxZWviIJshtih9tRIYqNR/1+N8KR0HDHZ/2NJ
         EITjmsNxYruvJQk9furYI8itG7sJqutFnQ1X0gvMNZ5leEZUvh3Yu0mu62rVZgt6Ik2t
         JvMexQD6iVEOvSe63q2Dl5GnC1nVwUjR7Fnm3Uzl0N/AfX+o07LwbfVJWuLVCIZR8y8r
         fRHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/srpnacSVdaqzz8ltm61ydBt2uwB1ULRHp9fiYILwlM=;
        b=CJ08U4f/UBxJJeQp4+c1g9HkzXVsioOhKsCVqn3VPVvyYgLLbzo6vnivI6nCv0k9KG
         hBkEGLyppnteJmiEURX00euJynvfghZ/pBztCbngv4i53EY6qV58U6WszBpCh5solFci
         EeSDv4kgSXUnUAMqwBveJodVPgXeNC4N26Tr2AcyuCDj7kvasb4gZuxTpYF8BZs1O2O8
         k+C8TORdJQcU4jAzI2waiNjxa4qotrS948MF9HGYwcckhB6pyqTWTMH6gJ5q/9gLSeaC
         pkzORgBwHuVqZFrkLRvrjCQv2CHYLgerun+UFv/MEdrzJhO9U6ATxHqSD3+gz47EUIHN
         Z1Ew==
X-Gm-Message-State: AOAM530H4pK3MH5tMIeL6ZNDVtLUIEUhhl3fQJLc3WGno0yZtNivUHd6
	UyIKq/XN9mlvf3f1Ib0wOrk=
X-Google-Smtp-Source: ABdhPJwWxd1kyfAXjICP4vsT6LWWzsJaTbKNH/E7y1utpAJLnyz2P7ndatUkSQwrwvMBj81YWUmxfg==
X-Received: by 2002:a6b:6511:: with SMTP id z17mr6883597iob.183.1611740389176;
        Wed, 27 Jan 2021 01:39:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:3297:: with SMTP id d23ls188558ioz.10.gmail; Wed,
 27 Jan 2021 01:39:48 -0800 (PST)
X-Received: by 2002:a05:6602:8f:: with SMTP id h15mr6865542iob.29.1611740388663;
        Wed, 27 Jan 2021 01:39:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611740388; cv=none;
        d=google.com; s=arc-20160816;
        b=Gg+QR96HKKgPr1+lzbAmQJC/wvIBLRkDFwsKQi6kfyEHXvLdJz0n2K4LYIjkSq8j+7
         PNlcXN0NT5YrsJyr1pDGINXKKdjIDp4fnWhzA5KGYfsAnXx3vxbweOXDWz/l7J94J6lH
         +AlSSPTHVh7uoU8jnnfC0EuCWNJb/+VFp3+iPq9hH5EIrLROw/5nd0sOETzO+NGAJ6qK
         asb+6lpDAo1rA2rkgG6CQ8cZiljpcgI0OGtLYbibujc/RpbNL2X0UhUuSA1/QLUbcgX9
         wClnGAYwQ3uv4hiN4ly14JULs4NyJ6QW8dMc7XKOuSzpiNchMWljKFg4Abvi6q/8mQPI
         EKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i5mFaE/s7QJg9ehYF5aI/DlK4rIagyN6xEPpFaUWeMw=;
        b=B+/yDInYpl6dwfVKqVdt81NFoEj+zd9z4a8o0Ba0DeoAdEtJIzjyeEF0drbitDk1j6
         8IQirczha7A2LPRM7vOJW09ihfg5Xvy8DSeLoPIRSZYGKARQEvsCd5RKrTFtjR7FbFzv
         f5ZzY63Q5c0izUWVoqnPx73EhCfJZFqwKteFhleDVcR3wpqUtkL/z1vHKfQ2xMYDaQj9
         fAxH0eUomWEShrv+RMTRLmQMXxN+2a6qxsDGDkvqCdRZij8dmbXW1cXOEybeOakW+1D6
         DTDngaWMazhUCvDckMdMCAQRDJKNJouCyLbUVXK4A8KwEK1IWM4zEgJUbthS1RjbWhq7
         4f/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=izgwRzB1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id c2si90051ilj.3.2021.01.27.01.39.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 01:39:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id l14so762721qvp.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 01:39:48 -0800 (PST)
X-Received: by 2002:a0c:9122:: with SMTP id q31mr9447413qvq.23.1611740387963;
 Wed, 27 Jan 2021 01:39:47 -0800 (PST)
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
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com> <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
In-Reply-To: <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 10:39:36 +0100
Message-ID: <CACT4Y+Za1P7-g8ukSJOcy-TWurz4HXxW4wau0VsEDEgoUvuZLQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=izgwRzB1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2a
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

On Wed, Jan 27, 2021 at 9:24 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> > I've set up an arm32 instance (w/o KASAN for now), but kernel fails during boot:
> > https://groups.google.com/g/syzkaller-bugs/c/omh0Em-CPq0
> > So far arm32 testing does not progress beyond attempts to boot.
>
> It is booting all right it seems.

It depends on the definition of "all right". If you are looking for
bugs, and you have bugs during boot, then that's it  :)

> Today it looks like Hillf Danton found the problem:

Yes, it seems so.

> if I understand correctly
> the code is executing arm32-on-arm64 (virtualized QEMU for ARM32
> on ARM64?) and that was not working with the vexpress QEMU model
> because not properly tested.

It's qemu-system-arm running on x86_64.
But I don't think that bug is related, it seems to affect arm32 in general.



> I don't know if I understand the problem right though :/
>
> Yours,
> Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZa1P7-g8ukSJOcy-TWurz4HXxW4wau0VsEDEgoUvuZLQ%40mail.gmail.com.
