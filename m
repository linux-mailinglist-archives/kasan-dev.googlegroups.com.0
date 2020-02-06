Return-Path: <kasan-dev+bncBDK3TPOVRULBBU5S6HYQKGQESHQUOYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id DAEAF154AFA
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 19:22:11 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id n12sf4971254edq.13
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 10:22:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581013331; cv=pass;
        d=google.com; s=arc-20160816;
        b=QSwLxzDvXKWLJveYADvmK1CfqzrWvCxQnQV2HqVnAZ9ZeIH5zLQVDNZqE62zUPrCX7
         7coCvuv6Rkarj+VU+mMbSCCz9erzIzenUQFri1mV4giQZ0zPgkKcDfdk44IZGA0c/1LG
         F1VfLKSgY436ZjH4I1kHTPZfdFZkPWlmSBGZTsCcmcG+u0xb+lMcoeIG0bWfnZDS4BWA
         hZxCgLHTTZzwIx/6LIin16YxgoDPnU2sSbPuPRXMH8DvChG1fMomHGH1UzECzQsJo0FE
         OvdftXWYsbTexUDaKZgX7Fvt27CVfVNADZyIFoNrwcQAqDkXIV8wSwLFUndmUdSp47Lh
         vZbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aIMDEg5TJBGhKB4pOzwk5GC4kFMk9a4m3n6soZN6wtU=;
        b=DhqRjESzpSPzVh3DLI4JRGHSzXPWsA7Fff7F8zqXpPxQFXtdCEZB3ZzzVL7KqCzv57
         jo9JIOTtwvqdME9SyJCBQBLqL49ZlHUmRHFFpqlO0o2P2wqJ0q2e220hXjTCnj+x6s22
         8VciRNC3e71oTRZxd0yR+0XKvQi37qHfDM3qh3ec85svcP6dfHp9ZW59FB7FH8AfklH0
         Lr0ulSOIvqe33gvxnE5cSdfhjLW/XQA4zH7not8/toNddnFNH+vROk2rRXYQkW2g8s0S
         cUfVnfxDsDsTy0GaBiHyryLBNbb3hu66Q9EjiegcVusbO+D6QsHryKYfivQ3L47O5wjL
         uAgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=of3NEExB;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aIMDEg5TJBGhKB4pOzwk5GC4kFMk9a4m3n6soZN6wtU=;
        b=NQ4/XtZcInVCfUsbGiIPBFoDg1gxVE42cGQJ71IaA+Bk/8MVey5CBTWPNBErEzNOe0
         FPbnYSHEJpOgpyE0LjuFyJqymYLBH3aIuVvvpmsvGgjghWB0Wi1w2H15R/Xd+mRnsMOW
         nUmreSmZBXC+A6VexpFgQjEILPmV/vggncrczi0R7TU9/FXIwLyBOqVEMC6oVKsl69YQ
         rAjSOlde6UrtauJje1QRAcP+8w/XTzVv1RVQzpffO+GqLIxDhED05m8514uAtp9p2n6k
         X2IlrDX/doPqou0IBX7wTTVpbRL0xoELZ/yPSbNnyu5QY575azbWmQOFmVw4MFcADw/w
         fs/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aIMDEg5TJBGhKB4pOzwk5GC4kFMk9a4m3n6soZN6wtU=;
        b=Zc1NXHfaj1fJZ12Fz1umU9/kf+P5+0wTjuLueoRGW6xM1JURuQhA1MHXkYHF5IzkHn
         fCxx4hWKUhKtqUSyGFf96h7jFateNtqZ9XsBD4JH7cU9ABnPNuwGN1I+R03I+ThANQx9
         joGZ0rWb/sbnyuVzuk9Fogagjs+kgYigLOTr3Wq4ZFefcpP776JK6VPg+nkTKqHk5wsS
         XBN14ZelAT0jelEV+TQ3fiUS6uzpvRZPnlf5nAODsSgNwPkIhgnowQbv8vVS4kspAdRL
         BFY9CThk3m6XKbQGKqAVpeLdo3JL0YGkLUPYp+p/LvJOqXvavzre7EkT3GvVXlBBlX8E
         6tAw==
X-Gm-Message-State: APjAAAVytXbu1iqvw/P+hCkxhb0smIK3nTCR90cBBCkHkbakTzUY2R3S
	R5fqU1xrrgYpQnWRJzIEBkc=
X-Google-Smtp-Source: APXvYqyHZpjumiy3POLb+MHCK3bUOyuwk//oT2pS+oQXc6rETN/eUPKfJCpQ65eneM3BwAyrs1xX5g==
X-Received: by 2002:a05:6402:cb7:: with SMTP id cn23mr4277436edb.72.1581013331644;
        Thu, 06 Feb 2020 10:22:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7f99:: with SMTP id f25ls3669319ejr.5.gmail; Thu, 06
 Feb 2020 10:22:11 -0800 (PST)
X-Received: by 2002:a17:906:4bd1:: with SMTP id x17mr4520168ejv.181.1581013331088;
        Thu, 06 Feb 2020 10:22:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581013331; cv=none;
        d=google.com; s=arc-20160816;
        b=o8nZX7N4anzMGjmBWs5a8Hoxc3M/by6IrU60gitY4etPyhJsPaqNAFhcpXIBt1V6Mj
         dE2BeSycclIi4EMIuZY1PMzkwELgntevphDaTqZk1a5uBjSLGcs3BkL1trQyivLy1QVj
         lKY84kPhdgzeP87a+KPeYdjCA1EXtrbT7L8nPKS5Zv9iDUPDzXPLQIfTUhk6SQHbxUJs
         DkNshRezC39Rt5r0J/Qie9XxwXBb0SDLUGZAlR8vVFxXW1aOtu4rpV4yJcP5pQz+9pDV
         ycn4eeMvgsW8ufKGUM7VDuLK9LiPLk9n/UO7o/suVTagFnUZHJgmOBcMSmjhNcuMug31
         2m2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d9qzkt0YHl1j1zQLYfgUtStKm8RvBNZBr/cpsyPQQSI=;
        b=PRpRdt+hITbLs7oPXdsnFAwH6TlA9iGdMjDh09lk3/eGOdG+ikPvQZRIUf5WZHPxFQ
         V9Cep8Z4T4cLAmvkqu9xxwzPqvawdbPZinYyOQN1sypIiJRKASd8DqNR9rj7inMfec53
         KQPvmB/77HPFkS65gKJiKetKhqiQIrv3t9mW8x1nc6sMPxW+21dm+aTQmQ39YXfU6ZzE
         woqYpTi4Nip3U23KccAaHRnQQhC0XYSrs1jaR14CNYr1d4YHIxvfLCbaH42YBFvu8Rw/
         a/wEPgBziFUsOLcmGTLiryhcx5UqqJTM7iBMrfQgZSN608zCFduzejtDm2XYUOEwcxO8
         d4pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=of3NEExB;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id n1si22618edw.4.2020.02.06.10.22.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 10:22:11 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id b17so1201714wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 10:22:11 -0800 (PST)
X-Received: by 2002:a7b:c119:: with SMTP id w25mr6125664wmi.112.1581013330505;
 Thu, 06 Feb 2020 10:22:10 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net> <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
In-Reply-To: <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2020 10:21:59 -0800
Message-ID: <CAKFsvUJu7NZpM0ER45zhSzte3ovkAvXBKx3Tppxci7O=0TwJMg@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: richard@nod.at, jdike@addtoit.com, 
	Brendan Higgins <brendanhiggins@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org, 
	David Gow <davidgow@google.com>, aryabinin@virtuozzo.com, 
	Dmitry Vyukov <dvyukov@google.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=of3NEExB;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Thu, Jan 16, 2020 at 12:03 AM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> On Thu, 2020-01-16 at 08:57 +0100, Johannes Berg wrote:
> >
> > And if I remember from looking at KASAN, some of the constructors there
> > depended on initializing after the KASAN data structures were set up (or
> > at least allocated)? It may be that you solved that by allocating the
> > shadow so very early though.
>
> Actually, no ... it's still after main(), and the constructors run
> before.
>
> So I _think_ with the CONFIG_CONSTRUCTORS revert, this will no longer
> work (but happy to be proven wrong!), if so then I guess we do have to
> find a way to initialize the KASAN things from another (somehow
> earlier?) constructor ...
>
> Or find a way to fix CONFIG_CONSTRUCTORS and not revert, but I looked at
> it quite a bit and didn't.
>
> johannes


I've looked at this quite extensively over the past week or so. I was
able to initialize KASAN as one of the first things that gets executed
in main(), but constructors are, in fact, needed before main(). I
think it might be best to reintroduce constructors in a limited way to
allow KASAN to work in UML. I have done as much testing as I can on my
machine and this limited version seems to work, except when
STATIC_LINK is set. I will send some patches of what I have done so
far and we can talk more about it there. I would like to add your
name, Johannes, as a co-developed-by on that patch. If there is a
better way to give you credit for this, please let me know.


-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUJu7NZpM0ER45zhSzte3ovkAvXBKx3Tppxci7O%3D0TwJMg%40mail.gmail.com.
