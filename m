Return-Path: <kasan-dev+bncBDE6RCFOWIARBSGRXWBAMGQELYWNKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 554C533B793
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 15:01:45 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id a63sf2874298wmd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 07:01:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615816905; cv=pass;
        d=google.com; s=arc-20160816;
        b=vkTJHwspshrQWhTMUoNO2ThiZifkh4Z6DeFOaLC/B1tWx1fvrxANGufa9twULe80Bb
         N6w/38oZD1qhV2TnWDMK2XojiDKrDTYJQcYWBlKIuB4xKQP1d2KF0k+PFAqsbkAYi3oH
         F2fDcgSkDumiQSCIYWvfvUYqbLXHsvAobc5A2xdq+VPw/HWFQ13V2DMxWNQbEN2HsC4n
         b0jh+H4HiORyS6rILEGn0BMheGNzwNHiKy/3VWIsnqc0la8Au/+TMTSo6PuYFHc9fUNZ
         Aoeo5yH52XxBww5bsveuDkc/ryztx0BZ9IKXHLT0zz4VdKwFFQr603jaCAhEVVFhhL2s
         CQyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=gMek2UPH829Vz3B9COpz9wuygUNPa9wmSLuwqK70wAw=;
        b=aYYvUtNTQNaCL8Tbt67B/DNtiiJ3fnmGcpX7gKnodEwFeCWS58j/DwTgfLdUwPbpaQ
         PdsjtWREtH5lhMXdbT99j4VZGNkY4I1vvA+7G+AUyd5aCQSOSzFjSBrXcymrsHkgwSgy
         jg9vIVK6lUMtD+jfrkmWe1jHvGtHiWrdZ6Y9/hmZBaokSbGlq9A5m1zjbtk0LW2QNLEa
         oIbQ7loYYcBR8SwxqZzRnx3FsxJi0aO9WT0ziDnY4LcEoWuP8A4SFYC4h0uuCJe/IpY3
         XhgB/WUWx1hkdRkrvw33EJ6NQW08qcFdIQXzjp+IelCAWR1SmAg9MZFIMuP8pGzToI5N
         eZ/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="w/vPza7y";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gMek2UPH829Vz3B9COpz9wuygUNPa9wmSLuwqK70wAw=;
        b=mm8PWqTc/luZklFIo3VTjjU9lUkN5mNEpXj8WU5ejcDSUVaPP62vAcmd942Jpv5yRt
         fsLL0eVrOrH4NCeZLDUs4uRcAyEooj9SrppTx1XPTkOHao6BHdmtQ+TVnIJMk8kQ1+vn
         NtjcvUSRqQ/VbACszoUvFwdmdxZP99qaC9U6Dd98cuh5tTRQLkoqbFQkEiyYCIJt5Cl+
         Dc40Y+UlEJHAWP+o95zj9jPKC8kdf2zgu69OWLixv5UGbeVuyRaJpPU59Dlz2/cY0ayh
         OLd1Zh4w/zrApuYrL6HnWzs+6vxocsbhQLuC0fXXG2d7iwb43pTmkkJOUI4GmBqQhsEC
         ojvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gMek2UPH829Vz3B9COpz9wuygUNPa9wmSLuwqK70wAw=;
        b=GocR3v6ZzC7rI2XAVwgM9Xe0EKmCpFRrvB1xAyn6ZXjzxlHnJLn65NJl7u2rAY69t0
         bzuayFuRU3+zzwN3ceGDkEZAb/ZkYVhpbn/fPxiKygbOEUfcUc/7I4S+Kl6L+hx8hyxk
         39cJ4c7uobGcZRf5K2AFGChS5k7j8LXh7MPrlHpAmheidBAxiHxof7M2i/lcGOB6wTPM
         kFdMvSg/rt5JJn8HH0HZa0lvt0rMVLiz7PBnb5QgpKVUl4JJK6NWMwy8Z3/ltYlMVsC/
         uwYojGxzBIzGDWikek+auU44qb/VhRO/eSY9v53drwq239gb2WdeU/Ojvmm2WM/kEOXp
         x2zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r7upZazHUPo0ZwB0aYH6WyTM2ExDBW+nVjP2E12OGp4tIIh3b
	/iKdpfKf5ajhrjpMEqWFKWg=
X-Google-Smtp-Source: ABdhPJx1USconqPopWgwBsOsCfUTfl84djiXeqqX3j9fYSOtTSsHxm19i0rH7qzO5EJ/1z63jBfxHA==
X-Received: by 2002:a1c:a985:: with SMTP id s127mr25592741wme.158.1615816904942;
        Mon, 15 Mar 2021 07:01:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e6:: with SMTP id g6ls492363wrd.3.gmail; Mon, 15 Mar
 2021 07:01:44 -0700 (PDT)
X-Received: by 2002:a5d:4523:: with SMTP id j3mr28484864wra.288.1615816904160;
        Mon, 15 Mar 2021 07:01:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615816904; cv=none;
        d=google.com; s=arc-20160816;
        b=qXEbPO9wduJ/wCiu+aVmO6hW9wpKSdB0L6zxVJw/Bg/XqoygJ/MdsI75ceg2kFXfS7
         Uhh4H96RL3DPT1fl2RNtLYwFsxyThB/kQ1Xp5n/I+mJuwRXhHOcvFpO20v4OnDD7jY1r
         ocOlv1y02pZ1MGk1nAUfKv1i+LD2sncpxht4huSMsLqn4TjTx0Qq2Hy/zv2AhixxkTw4
         egjH6CL+xwv+kqZo1gnkV65WGw8Up9NJ97PoPMyqEOl2WlRqQNLFQRwvZn2MZuJMF1VA
         AZ1LFHbfdu151vbHsFzK61T4FvDiKUEv54U7p+qWdkm4fGbMRHh2OQuEn3BLWeXRV9vz
         dvTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s/Ki9/xaCWqRsxv1my3hW6i2nGL/EjMHLbJSOx5wTjQ=;
        b=bGQCtq+sHJj2M/zczPXvARIfsG1L1Mt10L8ETuXWmMm5n8Z+VsbFQSjdOHjNFBpCFH
         YfLikvUgxcI0rsRAHAuBJTBkyZbPdG2cscZ/Fh3/ZkHoypjwOBrfSZ2TKAJ+tbRelR7j
         ydE6h82E5JQoQA96KXOQ6iuSS1+56IgO8/gzvS1Pjo7Pa+rAdA3jYYfswihXhQngEn8B
         wmqGzvDzLoJqus9M+UAw8GZoDsNcTaV9HjXYWDnl8svnAisn9Qk31FiD+oVa5UU4tkOi
         qG4jKmMlW88Th03YrHrQ+6265XT/LtcNluFj7oV+hBcfvZA3LZyeaAk7ziZvD9CB3Vsi
         6PTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="w/vPza7y";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id t124si701834wmb.3.2021.03.15.07.01.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 07:01:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id a1so16337277ljp.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 07:01:44 -0700 (PDT)
X-Received: by 2002:a2e:9cb:: with SMTP id 194mr10631515ljj.438.1615816903407;
 Mon, 15 Mar 2021 07:01:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
 <20210311140904.GJ1463@shell.armlinux.org.uk> <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
In-Reply-To: <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 15 Mar 2021 15:01:32 +0100
Message-ID: <CACRpkdatfcNp_5UnkxEuEYCmHYAbV+TV1LJT512y7pDao=JjQg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Arnd Bergmann <arnd@arndb.de>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Dmitry Vyukov <dvyukov@google.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="w/vPza7y";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Thu, Mar 11, 2021 at 3:55 PM Arnd Bergmann <arnd@arndb.de> wrote:

> If KASAN limits the address space available to user space, there might be
> a related issue, even when there is still physical memory available.

So in this case with the 2/2 split userspace TASK_SIZE
will be (include/asm/memory.h) KASAN_SHADOW_START
which in this case is 0x6ee00000.
Details in
commit c12366ba441da2f6f2b915410aca2b5b39c1651,

I'm just puzzled that OOM is not kicking in if the binary
runs out of virtual memory (hits 0x6ee00000).
It sure occurse when we run out of physical memory,
that has happened to me on 16MB systems.

What happens if we just use PAGE_OFFSET 0xC0000000
like most platforms? This free:s up a whole bunch of virtual
memory for userspace (will be 0xb6e00000).

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdatfcNp_5UnkxEuEYCmHYAbV%2BTV1LJT512y7pDao%3DJjQg%40mail.gmail.com.
