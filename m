Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS53SSJQMGQEAT2W3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 621CF50D0ED
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 11:52:12 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id x9-20020ab05789000000b002fa60bdf012sf5221549uaa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 02:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650793931; cv=pass;
        d=google.com; s=arc-20160816;
        b=qm94GnqoW9w/sDcHMR6vBwRLt6XUKUTpdx6+0vODag1W268xTmou4vk7g3p+NcKhN8
         R23mJB6Q67SvwECaevpr67HSb9HsXYs44HWwmhpttpfY5RRlTduoP1jZ7DIgVM7c670f
         K5OlRJTsIvUmxfK2hG1EkIGm7Xh1nfFrT75mnz2Rdp7e4GLft0U0FurpsrkEF1QBoz5B
         5zsbQHdXDRQ39VKf8Xp6hK1ILB3K3uePr5lLgF3565ZZCsEBujfy6s53SEaE/xUJ1JJr
         B4uUax9qL5Q+EtmtYsZ0OfHwTCwhLbVFgJJiz7Me7TikYy2cWTN32IdzAyIFMoIFNpZp
         xCJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1FvXxknhQoOFFDDtmXutyysrWB1sWBTn58b6a3QJDd4=;
        b=YTeGpem18w7VmfNFAK1lzjRnnMh8NOiXt5pYYT5+NUB/rtXjXIFdTl5kS5jSBum/C2
         bX9IMh5+LasKHkoCMMg4HxN6lNZ2OxPORdQu/KlkdIFI35ZdEXIXRxCIcmTHBZpJykUr
         VRx9ri460FKEN6wzKkJORYU5zx69u9BVZnOH6msvGNkzvVazRcYv6T6zEYbmc9cFBZZ6
         juyHC79eLSxRkleFosrDkwdwcjBecs5BJJcOkTnVZjzXct00hrZpvhwo0T0HdK1BykqW
         AO4bm6DC+8C5mtGtViSsR3/cAeqmR+sU3/zwFPk9s6XY/41i6rLmVD7RyJmP97MwPj1l
         V8Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k+ussjTH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1FvXxknhQoOFFDDtmXutyysrWB1sWBTn58b6a3QJDd4=;
        b=kb4nGCwedygN7xTEUaX09FpKxaTWucx7FFShxuYcRZ7WsrNarCipaiKpbo4DzP98Yy
         eYkJoOfqbWc6kW2cU+dBR4yr4Bp6dJJkBXoq/Wpw7xtIyRkDx/1roxzT9yfgt41bFOb0
         XwOQN5kY9OMojg/8ihDIIMXoESug/xlybHNA4iuRDaVJgY4tLB+BiNwW9MY1AqPbXvTE
         GSoIOuF4yWIv0bVkZh03ktl1f7ie9oBZcwO6g5hRvvsCztERZC44Wn/845itrdMxJX2I
         oXGrvG2boc64cq4GxX0fXBUIF6W6FmI4MdkFmR2Hwyc9HKZ8Hvwwl/ZZmBBVcxVaND1f
         Ro8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1FvXxknhQoOFFDDtmXutyysrWB1sWBTn58b6a3QJDd4=;
        b=WoV6N4YC3IWsFGazPox/lKkCXPkyufUMlNf0UAofq5Sn7sD3+fLZ+OYZaAOC+oC+/w
         Dw99MYxGA+GzplXkMCpHqJAUCPZ4aWsmQx/8TMaqTad+FynEjD4/sflxqmO/hP2JoTp2
         0Qd22Pz0piwcwPL9zBYsCTfer4vxjoUdJdUm2tEDHuKyK5MvnWHE0cGlHuB4ZGgnbZva
         B5xAF2bS7PO3ODwgeai3KlL3514Zm2pYvSQwSdlkp1hCzohlpDN/+JlSlHRRseXbdS+Z
         Y2vxmku7JdOGY0cG1Rp709sCZKeknLoRN2tpDyIuFkEhivK9C8jP6qJU/YKSQYwgsbVG
         XP6A==
X-Gm-Message-State: AOAM530UminjwYbkKFv3biKE+Hxz1j1tiMsqsfyNeqLVfId6092AYZIc
	T308IsPDW9WAizqDpd22B4A=
X-Google-Smtp-Source: ABdhPJzxk/Vs5WxTyKcNf4umqPnJNHfd4wCVyGCfPhtceWf5WSTPuOOy7JYsM3+ZpoARlx06yDwY/g==
X-Received: by 2002:a1f:9e45:0:b0:345:a7eb:e774 with SMTP id h66-20020a1f9e45000000b00345a7ebe774mr3797194vke.5.1650793931224;
        Sun, 24 Apr 2022 02:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df9a:0:b0:32c:27bd:37dd with SMTP id x26-20020a67df9a000000b0032c27bd37ddls1654796vsk.10.gmail;
 Sun, 24 Apr 2022 02:52:10 -0700 (PDT)
X-Received: by 2002:a05:6102:1492:b0:32a:5efa:1f75 with SMTP id d18-20020a056102149200b0032a5efa1f75mr3604939vsv.64.1650793930629;
        Sun, 24 Apr 2022 02:52:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650793930; cv=none;
        d=google.com; s=arc-20160816;
        b=iHAcy9n4nYl0YJf7DEfVcMVOFT7pNv91hXAYxN9kwacMYm82d8V1/X/0HRHzha09iY
         i30R7/iO0IrYXT539VY++Md8oBgMoTprqbvrJqIZhi1f8/ZagmAR7SHx8pKlFHKlD5up
         N9h5EvvwgVmmw12xoaxf5rIf+uNX05iOhPBo1TblxOYevCZcbyQ96YqlkHF1fSApKze9
         /NYYnE/5zcJ4DMwnsm/23tpwQ/oSeNOlr5Z7WQ2IVx2TpMMKqyuwKD7ulCFKnjcwxzIm
         fZvkWUZmwykecgk6okGKhZaNe3fgGxqmLY0A71fSUeVJB0Fn4YNlJqOiUTBUEfcQJEy5
         Ag7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rmy4idXC2eBClz5DkYm2e4LN35DXVZgPlYi+CftqWGY=;
        b=O0J2BiXLs3m6Itg8HsmhEh2PeUcozoupPKkaVMeDoxQj80rn10wNuvykReT9KqGREk
         QSyQIH7Uqw2k/fay/T7BwlpoKbf7DYIAj9RKp22RddJSFScgp8S0xEXNHuWOaB+m+yRk
         CXoUKmv3nL8ubKKb9QczXNLOJBGWeYiIZegWPjp7yOJFvlWf/LpePCoIEeP9ZZMY1kRD
         MwaO9nt6NiAM0r6daiGedp9SsMaX8B+4YmzeF9hfFw5R8XAptLvRjbRwLprMgFmematg
         CeVq9LrZYQdwkEIsZttJB4+c/MQtRb9co+OcI6IA7uFil41Mnj9Jb7AQx+mSlyVc1s1R
         92cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k+ussjTH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id a16-20020ab03c90000000b0035fc4b18c67si2334116uax.2.2022.04.24.02.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Apr 2022 02:52:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-2ef5380669cso122742057b3.9
        for <kasan-dev@googlegroups.com>; Sun, 24 Apr 2022 02:52:10 -0700 (PDT)
X-Received: by 2002:a81:1087:0:b0:2f7:da07:6d89 with SMTP id
 129-20020a811087000000b002f7da076d89mr1567199ywq.412.1650793930117; Sun, 24
 Apr 2022 02:52:10 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNM0qeKraYviOXFO4znVE3hUdG8-0VbFbzXzWH8twtQM9w@mail.gmail.com>
 <20220424081049.57928-1-huangshaobo6@huawei.com>
In-Reply-To: <20220424081049.57928-1-huangshaobo6@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 24 Apr 2022 11:51:34 +0200
Message-ID: <CANpmjNOOE8z_YYbJXsv=hxBhvCHyWhYapA8VKgnk2bHAtL6=8Q@mail.gmail.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: akpm@linux-foundation.org, chenzefeng2@huawei.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, nixiaoming@huawei.com, wangbing6@huawei.com, 
	wangfangpeng1@huawei.com, young.liuyang@huawei.com, zengweilin@huawei.com, 
	zhongjubin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=k+ussjTH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 24 Apr 2022 at 10:10, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>
> On Thu, 21 Apr 2022 15:28:45 +0200, Marco Elver <elver@google.com> wrote:
> > On Thu, 21 Apr 2022 at 15:06, Alexander Potapenko <glider@google.com> wrote:
> > [...]
> > > This report will denote that in a system that could have been running for days a particular skbuff was corrupted by some unknown task at some unknown point in time.
> > > How do we figure out what exactly caused this corruption?
> > >
> > > When we deploy KFENCE at scale, it is rarely possible for the kernel developer to get access to the host that reported the bug and try to reproduce it.
> > > With that in mind, the report (plus the kernel source) must contain all the necessary information to address the bug, otherwise reporting it will result in wasting the developer's time.
> > > Moreover, if we report such bugs too often, our tool loses the credit, which is hard to regain.
> >
> > I second this - in particular we'll want this off in fuzzers etc.,
> > because it'll just generate reports that nobody can use to debug an
> > issue. I do see the value in this in potentially narrowing the cause
> > of a panic, but that information is likely not enough to fully
> > diagnose the root cause of the panic - it might however prompt to
> > re-run with KASAN, or check if memory DIMMs are faulty etc.
> >
> > We can still have this feature, but I suggest to make it
> > off-by-default, and only enable via a boot param. I'd call it
> > 'kfence.check_on_panic'. For your setup, you can then use it to enable
> > where you see fit.
>
> Can I implement your suggestion into the second patch and add the "Suggested-by: Marco Elver <elver@google.com>" tag to it?

I don't think it's necessary, after all the overall patch is still
your idea - you're just using our review feedback to improve it. In
the change-log (after ---) you can of course mention that, but it'll
be stripped upon applying.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOOE8z_YYbJXsv%3DhxBhvCHyWhYapA8VKgnk2bHAtL6%3D8Q%40mail.gmail.com.
