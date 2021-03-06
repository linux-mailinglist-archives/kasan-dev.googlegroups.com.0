Return-Path: <kasan-dev+bncBDDL3KWR4EBRBGG6RWBAMGQEVSDTARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D741732FA63
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 13:01:30 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id o11sf2832716pgv.6
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Mar 2021 04:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615032089; cv=pass;
        d=google.com; s=arc-20160816;
        b=dIkkgP7pHODNE4jDI4tbtVoL+xA6wlCRv0sNX6MEIUKeIxjgoAfNo1+wCaLtav6hj7
         ty+sHgSFjO2DvzDbUgMxuL58ZWbE/bFFeZ7hfBGwZgtMhTw8ODR/4D1rLvXB835K50rh
         DMmLQWng8KLBccwTcd0cf9X1obN4BQV7BqUrPd97p7EEYDVcj6+hnfquy7RNzwCLPy5v
         vh+e/XnRORKTWBCEbaJOLb9nTglbzxaYbFHSW+7SlReIs7lNXS/EPvajGWTyPfirPFYW
         /64TRauzJzVM7K/zuKwLiA3tbk+BKORp2bU8HtkwvCOZdt2WVs1nbkkX/c9zE0d27pq9
         hgxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=o5mPOidX5Fs/jGEmEYm7xK7tjH42cp7WwifFF02BI9Q=;
        b=cQzXtJ90fVfuDo21gakA1V1SQA2AWsVe9Q8je47J70HmLzl312i+HSXyKv44r3qlL/
         bmgo8asPzMnpxcnLdiRK/K3sunI5HSneVyKAiZqDnM/YM2KKdfXumJP9dWhB8ftfIk6L
         MaMzjw+/zFY/TH/5ucb78vhHfQhIGWDcVGN33xjXyoG14BqpTQPBhH6FMgMp3eW9CQwg
         zjfK9rNEAgI2U88bmCWA75VyatErozDngBSTLWnkrEfMdrXUhODaXYYN8A4mzMjLxKnJ
         Shk1sHyHnoO1vCyri/afq44x0kEg75PTBpLa2g6ZRJfpKOlN/Yncj5WNT0xqompeASIP
         EvYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o5mPOidX5Fs/jGEmEYm7xK7tjH42cp7WwifFF02BI9Q=;
        b=PPN4/RLRj2KWFiPaOlAs3SCjBzHoHG/MUlHoaLJuxtVxcBGW2336957tyoq+F5ue3g
         lWWjXBdujwjDc/oNdiiER35yL6MaSiLH6UrurK9gfUgUhHhOVizoXHWZ0EJAtaiG8+hY
         qwHwjA+0el4ZjgXmqy+eiPx/n1VZ8F9IqFb9OeoPTebD4YTt9e7WCZNxkSAnqFw06p+M
         nwuctkLv6CtqL0TM6MkV/uASBZN0Uq8RsSRAolrB1YIY+WbESfqEZL2rtJmBhp66IO5S
         qAhsYmuE7G9C56BZK7wKhLmDoef0mbkXg6gstQ+dowS9dbuVL880dRZjSqy1IoL/BJ1Y
         tItw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o5mPOidX5Fs/jGEmEYm7xK7tjH42cp7WwifFF02BI9Q=;
        b=ZtJcnB1ihU2KKPNTfYdMeZZn95YuPLeZ27bs+NPwET1xIfKOc2AZrCG1MvUkLsmzV8
         QL+LsDVbviWxqwM2OLCYEaBRIj8QHrdVy44doQViKmZvCksV/bxJFCTQbNm1WOJ+b6rM
         rbvVOUuqBbI+7lqjwk1WN3rZTiU3vxeQiOo/YpgOa45niCrHzxZNk/AbeUjJ0dCnrW9q
         wYdIMm7bKGdcaGcmjuSLfZ5rFSRWtEvbGTcC3jOIxl8LB6nWrnQEjJoMB7N7Brqmt2FK
         L0L6NsmvTHyij3atqCP611dxr276Ji6V8d2q+xUt65npyDUduPpEXko+ShrO7+pTtXzM
         scYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530aDENNVVo8opemuG8ya8pfCWrmIvoEafTCuxp4MFKlVH5TnIRJ
	x5vGqXrAkfW70jZhREGPbiw=
X-Google-Smtp-Source: ABdhPJyuS0cSyEGKQ9jb/sdPZj5iWZwKrGSLQ6WSde3wRFL7l3oIL9v9X7bpmHLBSVq78PxJJrLGjw==
X-Received: by 2002:a17:90a:6282:: with SMTP id d2mr2508737pjj.168.1615032088152;
        Sat, 06 Mar 2021 04:01:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:9549:: with SMTP id t9ls516534pgn.3.gmail; Sat, 06 Mar
 2021 04:01:27 -0800 (PST)
X-Received: by 2002:aa7:910c:0:b029:1ed:ef1:81b with SMTP id 12-20020aa7910c0000b02901ed0ef1081bmr13728002pfh.49.1615032087530;
        Sat, 06 Mar 2021 04:01:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615032087; cv=none;
        d=google.com; s=arc-20160816;
        b=gTLopqdfMtiDzSC2OjwjpyyRLTclzmxfDHYt+PLPW0PyK2HJk/vO0zuRSSodQA3bfP
         Q2ptxcsVM45F9GNvIdwPIa5cf59Fad3c66kjxagCx83r8rm3e5CEd4LXBoiy5V0AHq1t
         rbO+yOXSoyfnfMKx+EYyNj+/GkYqEYrUZ5pJgXPXKhzYqYO+kD8wxZuMioPtkBeAcJ47
         sx+sjbTv6bIBsDJ2YZxSRJKuXWAVMhwehkaBYLRycXOBYroBntLhoWTiTz+nZxD1M6xk
         ige44IVf4ZcGrQr7brcrxu5yIsquLHmA6Ep3DMIzI38DjGC+6O9sCJXd/JhuL3aM7MlS
         zE7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=m8hLKWmwdhJWLUrxM9fHeGg9XzOnp0ej6e5OJ+IFRgw=;
        b=pSIE9iOtYpt9SpQL7JvvAilMtHXinutVQZUv6QYjnwvxzGPDmswVd93PnohxzWdgjN
         zWXo2jRC9tq64EXXtxlDFCBnsrNQTvChOT89t2Ujqx536MFx83JvGTnSQB9AZSmMTFkz
         c6KiUpTbwKJHxXaEn7TPdbU3v8Hzkrhfb/WqbJLhAq6ZX4Ito6CLKfJODPA2xE9HAid3
         OZafhjOcnObHCvMKoY/YLgh7WzjzCgioqppGwKxzpxJi+qAa9mnUV5k/zO+avk9u79/7
         uG0rMRnzy5kwpMH/YlterHT4KIpMLMMQalzeudsk2pOX8tMo40nlqhrzskkXSPyb/2+b
         vpHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h7si329249plr.3.2021.03.06.04.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 06 Mar 2021 04:01:27 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 489906501B;
	Sat,  6 Mar 2021 12:01:26 +0000 (UTC)
Date: Sat, 6 Mar 2021 12:01:23 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>
Subject: Re: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
Message-ID: <20210306120121.GA2932@arm.com>
References: <20210305171108.GD23855@arm.com>
 <CAAeHK+yuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg@mail.gmail.com>
 <20210305175124.GG23855@arm.com>
 <20210305175243.GH23855@arm.com>
 <CAAeHK+ykdwBXETF5WkrWnbzzS6RAJdmqZ3DrFdM_7FoXZR3Wqg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+ykdwBXETF5WkrWnbzzS6RAJdmqZ3DrFdM_7FoXZR3Wqg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Mar 05, 2021 at 07:36:22PM +0100, Andrey Konovalov wrote:
> On Fri, Mar 5, 2021 at 6:52 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > This is weird. kasan_unpoison_task_stack() is only defined when
> > > > CONFIG_KASAN_STACK is enabled, which shouldn't be enablable for
> > > > HW_TAGS.
> > >
> > > CONFIG_KASAN=y
> > > # CONFIG_KASAN_GENERIC is not set
> > > CONFIG_KASAN_HW_TAGS=y
> > > CONFIG_KASAN_STACK=1
> >
> > From Kconfig:
> >
> > config KASAN_STACK
> >         int
> >         default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> >         default 0
> >
> > and I use gcc.
> 
> Ah, that explains it.
> 
> Could you try applying this patch and see if it fixes the issue?
> 
> https://patchwork.kernel.org/project/linux-mm/patch/20210226012531.29231-1-walter-zh.wu@mediatek.com/

Walter's patches already in -next fix this issue.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210306120121.GA2932%40arm.com.
