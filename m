Return-Path: <kasan-dev+bncBDE6RCFOWIARB56CVCBAMGQEZUIJCXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FA9A3374C1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 14:56:08 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id a24sf8536297ljp.16
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 05:56:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615470968; cv=pass;
        d=google.com; s=arc-20160816;
        b=BzzqFmjsBym2f1OAnu9Oe8nmf5JtlphrSQib+WpIyCAc1hZ+vIfM5Qu76ZuOZAkP+T
         KTu287wDB3hZ+OxbSy6/1jhwnunun6br0eC2NuFstRGbkJ58ZzBJPuoW0vYEoaW+w7kC
         jGumDpWwD7JuVRF3WZvIGVjHae7GN3MrNeUBFh5TyDrYb+bSnkbyDz/OT8c4+pwvUrgP
         AcrVZsXbCfKdGF7AlXKE03wfI9CcQ3dSOvKFMK2KR5luDDZFFqek+GFbjc38odoSRGnF
         O4siieQknFxhV2SO8d9v0/6EYSlSynId0GhKXzBVt1GcCfzy2dyzoCUtLsf+A4dRvVMo
         Hang==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=B4xEDekBSI83nCtzTNbT0n/mz7htYYnJ8QcOr+ne++Q=;
        b=n6FBtlND7hbxdsPdYUlbiQH5mN5/EE0CxEUvEmYn5sCDA+Qyi0YNjxfCCYcNLfsVmN
         wJmjvQxouFRXXtyeqdiXLZUADcxEMYFxCD8Jwgqgr0WI2vW46D+1WooDAH9CygUaLzJS
         7wKYQrW9BeDwMUw1e2Gh+OBqUZHoqNhAr5CW6HIlHIgQ1S088c3fzaL/q3J48Z+T/CLi
         EkEFlaCyRoZHLOL5j0hKnLKJe9pX4WhItlCAQLiMDDylnRSKM/HLK4V2ZQEu0CLtsyQW
         rSAcXQsBcXceXa6hHkBEk0QugjFbnulIvgKbx9TGbDSNN4R+RLac+OEFu1xEjlpg8q/P
         b0iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sdbRih7q;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B4xEDekBSI83nCtzTNbT0n/mz7htYYnJ8QcOr+ne++Q=;
        b=p0qBc2vDCw+XqcD7zlMOC0GXk7Gg4OjpQGH+/jgQN55iSkUbZbi1Egx0ukoPvY1BGk
         Luq8llvRUTeG+y34yTSqqTqYkI5ixx9OhD5DRGQ4JXzPAjxfiHor0p3cAmAVBkBpgVqh
         LI/ju0G1cCkoPfVnEFvaBJk9+VxgQFX65K00BzwgFemJQqKS9m3srLZpcG/D6Y3HK6w7
         KM0L4brfThlwsLTnjjTcAdAPcavz8fM+Q3KJncLmvZ2tvBlBPIfnhUCDnppzmOfZxxtd
         pxu4lis4eVKYZHT5ff2/pv21JqlSUUE3fbNlKLelhggjgHNtK1PRLaFi/QCS2LWuTxcR
         UFAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B4xEDekBSI83nCtzTNbT0n/mz7htYYnJ8QcOr+ne++Q=;
        b=QHyAx/InLhN86HTYTVG4z6wT5f5sNx8EIHj6TYYwWhvF/VOFbmtxDqT4TczAi20nJ0
         SzcgKbvCc2BudbgLgtHZsGduj7Ov+tnNOtl++AvYctSOlc++imB/2uLdzuyC8wyV0R7a
         wFgjp1sphiVvn9qTm8Z8VPIRu5SV22ahnVA5ncGVRnWJuoL3gZqKuV2woowLoTfuArMW
         FiPoEXQLOmDU7D+ixP5hKJE22VrNUKlRhTy3r+vGdTkGmdkG+YITw1tu1YJH3/ZarNCl
         6PbFv6S+fIWUZV8DMsxe/qr1sBoEFCbKDWGPmBRocZZUEhsG0XvZfKpNou0292BKV6cC
         hlWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W7oUdqoxrdXzKJAMLs5baL8vXctebiz9+dp0gJwXmPwyo+D81
	feti0I43PiGBbcRjHZl+sKs=
X-Google-Smtp-Source: ABdhPJxjATbuHvCCDlJtj3x7suSw9LTyAOGt6ruwuHM6JNu+c2FnMHU62+9dwmADYx9/hSnFRrV+yQ==
X-Received: by 2002:a2e:7007:: with SMTP id l7mr5004653ljc.436.1615470968083;
        Thu, 11 Mar 2021 05:56:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls833322lfu.3.gmail; Thu, 11
 Mar 2021 05:56:07 -0800 (PST)
X-Received: by 2002:a19:488e:: with SMTP id v136mr2358665lfa.611.1615470967069;
        Thu, 11 Mar 2021 05:56:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615470967; cv=none;
        d=google.com; s=arc-20160816;
        b=ipbKXcjXvDSzphSG1bVpON6eZzqdJjC0VwnlYe98ebUbcFPRrPTifBh6pLHbp3v/oq
         Uh4VR1xuSSZ4Qfz7i9/ta9Nbdc6kHy/kxjUkj0vOGuBv941vv99AH/T5EbCg278dWCDf
         I86V3GtkDqxWI00MU6kEcQsw0k7mSiuh01sB4Ut2qpSk0/eBZxVlusbyLGCAB6q65yIf
         mvb8SZMWcvnnYA5I9riggzBydTn/FvKXcuGCjidZ4GOLxJ9QRuVi6PvIz/yVyTq6pOzx
         nLftShTY56jtMoxNdaexIhJelBHdQMKmzRtvaynOFjW6DUq2vivhXXBjFrYyquxCtZ+X
         RAgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o0Ga7zryx4Wb+AhNId72fmbo4aigUPJGOnBhr5Syhu8=;
        b=gwGr7fdI80ofJttziwiMFzyy0ZCS2+34EMAA6ZzRlNLsb9sumJHvP3kFk3VXKyRXya
         WY79zdRZYNf31gRTJQLG2FYLs3yjRvq+S7SL2MJ68zWsdoEY0kvcpRcBUjdsZCgzYYFP
         f46IbMzS4VTw55WENXP0MJxZHO5sALHJOKIlhFC820JvYPi1TTWkvbLXYIWRG434yOS5
         iXXZ2cRVBW7U4B8EUKv++a/RzXJhIahqG6GJd22HUm9i2CJ0Sby5cg6Ahnlab29QNFrM
         mMCbqVh9fSQZ67fjmyIpkmOIPNtR53OwhnSBKBqmoz+HjV3uYB0Gd+zGbAPvH6a3I2Gy
         qdhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sdbRih7q;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id f21si121391ljg.6.2021.03.11.05.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 05:56:06 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id r3so31715415lfc.13
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 05:56:06 -0800 (PST)
X-Received: by 2002:a19:4c08:: with SMTP id z8mr2301640lfa.157.1615470965813;
 Thu, 11 Mar 2021 05:56:05 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
In-Reply-To: <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 11 Mar 2021 14:55:54 +0100
Message-ID: <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=sdbRih7q;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Thu, Mar 11, 2021 at 11:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/

I am still puzzled by this, but I still have the open question about how much
memory the Go runtime really use. I am suspecting quite a lot, and the
ARM32 instance isn't on par with any contemporary server or desktop
when it comes to memory, it has ~2GB for a userspace program, after
that bad things will happen: the machine will start thrashing.

Do you have some idea about how much memory these Go binaries
use up at runtime on x86 or Aarch64?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q%40mail.gmail.com.
