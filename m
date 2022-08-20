Return-Path: <kasan-dev+bncBC5JXFXXVEGRBIPDQOMAMGQECB7OLXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B48659AEB2
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Aug 2022 16:37:22 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id f18-20020a05600c4e9200b003a5f81299casf3883484wmq.7
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Aug 2022 07:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661006241; cv=pass;
        d=google.com; s=arc-20160816;
        b=jJaT+yV3j7EWPlA0vbJg6eHiH6o7fehpVwCcedm/dUgZwvfIUVQfCUe/CVBIn9Eeyc
         5oKDyjfQ13R/ZOOYNhAQ6JB0Kzy8CziJtzREHET6X5LuesgrB8//u2mDvTFx13aZw2nP
         ZoTKPwJPExMMFGJAnzVmAWKLrk7XKNbY4V+4Q2mC+g5H3Yru9WEF4d6q68nFh+iV2WlW
         6FmNHVzfH0rnt/JpYpVPHLmEpzahLWgA0b12cOpSA/gsLzmfqp8aByoHNgrH4mcVs3IM
         WOpDA8zKOS2rLuxW2floERJOQHKrXMmXijCh4xneJP633PRHxdumR+purwlyFa9DyScn
         YL2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N8jOgzGFtkoABujNpyDGmn41d47Qe0QU5iAzzDlAU7Y=;
        b=y1BR4bCHAlLUxCHbgRyuw40dYd1fvriCY/xlOqzv5Sc53P6wS7NTkmjTI8lsxHCi1h
         yXxB9rx4Eab4dvW6dZm9FEOQ3fr9+u74NxhtSzbhWqNXD3G8tD1JDRbLNIFNxfuZ0Fbb
         unxawtDKda5K3ymFWP+th4flsSYrXNeJxnuRsjQgUkigdlXbxKsiM69snMFrcMktJP+s
         ns6lRHJAKFtglPDQJtOjmd2EmmlzSCr5U/VgiLQoy4FAVthFbYbBErEbjF5/0QtUN+Y4
         YzXwYGhSD0PkbvW4BrR8CaDMS9k7hM6IwI87oumH75wTQjXgC71Q6/nyPAs7ywXqI89w
         LnpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c0/5SZHW";
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=N8jOgzGFtkoABujNpyDGmn41d47Qe0QU5iAzzDlAU7Y=;
        b=Idy4cPyTTwJam3xiKl7sZ/eBikkCUPH+v8tnjSynonPRgn5gPWlJJEIW8gFaLffAj+
         vlza6mMWlT7dMo+bVL7zCohbeXrQZTrkksmrk5Uhn8MFR3xsI21xL2vBGK+tE3A6fK7+
         LzQVPGQKUkSbx4+JTxxtcoG4AxqL7UZN2QMwlDKWgmY7xEUxxFkeDZL6kQplkRL2vsqB
         zX6psUnWaZIqcTIIC5kOymPUd7vqBqc8+VIT/WbBFPvW/H6quN0XT3LX+9DHNZ8hIwJi
         Lw2xGTWrwbzuzBZ9zLBonkbpraSw1CvXfcFj26dUbT/dceUoZHevHnfj6j6tTjXnH0rj
         7a4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=N8jOgzGFtkoABujNpyDGmn41d47Qe0QU5iAzzDlAU7Y=;
        b=xHsOoNQj8Vb9i8YPxGcFHWZyOoub3x5j4pqPWdI6kS1McAbChYTIVTJR6502LAszU6
         arZyn/99VnlVorVURWKgoSFR/G2sYFD0EJ5fhIZ2Y274MsxPCUxgKpQQY/smXKEIi8T0
         Gkg9S5FvEo3rlz4Zr5AlUpSCHc8rGgwCoq8l7ORRX/nGZGWqrmWi0G5NlgWcWC3mtBhI
         TdXENHHjC45v6zRii3Z8Tm6aSEAXmjyC/2h1NVOFQ9v5bpZIt+FP0UnHXiA3Ksn15KtQ
         z0j6wWuxDMH+daLFkLFpJeCHCAXZbulG0qwm2nngTAOut8LWfPbAcbY+iIyaknrRb6xj
         JqdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2YexyCuIasIKMpEF6x6dI6eV6Boh8xWzbPqs9Zv25VPBBxTzJW
	CrFLgIDgh9+Sg8k+4YNOzLc=
X-Google-Smtp-Source: AA6agR7MkQokbj/OTyAw8LAraGFNUosqu81kHjBqOSA4dQnPf4kdjMy0SG1cTju2ymH+rcVdxbxnVw==
X-Received: by 2002:a1c:7418:0:b0:3a6:5e8:148b with SMTP id p24-20020a1c7418000000b003a605e8148bmr7467209wmc.128.1661006241723;
        Sat, 20 Aug 2022 07:37:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20d:0:b0:225:26dd:8b59 with SMTP id j13-20020adfd20d000000b0022526dd8b59ls10160349wrh.3.-pod-prod-gmail;
 Sat, 20 Aug 2022 07:37:20 -0700 (PDT)
X-Received: by 2002:adf:dc90:0:b0:225:3a6a:18ca with SMTP id r16-20020adfdc90000000b002253a6a18camr3980842wrj.415.1661006240326;
        Sat, 20 Aug 2022 07:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661006240; cv=none;
        d=google.com; s=arc-20160816;
        b=udCQnId331iv5/EqioEekMvNqMvHWImGuLdb5lOhwM8PVFWaeNA7uWm/Jtnr/MrFGO
         fcu7psqzY+ZAqhyOE8cpyyghVWJEQ+Z62VFvl4+8uo+FRScxouyxZ4vrmnors/Tq7nuB
         SFSg6yzRTbuiE8UB75f4IUIYgnwHhYk2O62Nix5c1cfLJ1wKy1RsQ2efbN1UBFJ2bFFu
         V75LAU/A7WIxVhfyTYEydORjqiSEuiUbmcoYK9mQPcLK3V9hh292qO5q4jXLHEYAHxGa
         Bh171fc++E6uCdxTX8HubO6U014Y/5I3RxXL4POF6AYK5V5tgZLR5Me1RmH57ZuNLlK6
         vQvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EKqV7mRrWjx8l3qzmdIRlsvLj/j8Chh+EErQLyiuAVU=;
        b=mFGtxwX9Y32O9OyJGQlDZtuJger+fF2R278tvERVtPDaxnoVvvl+9GZDVcowRzukcZ
         OM/LHbxO0DqNUOCjvCV/Qza+sS8x5E6OxXniDlngVrWiwCYz1fmGMwY0UkCAyCJ0ge5i
         sl4yspw6lkPCXw+aAoxu9LfEG+UNbjfsWMhA0OTexwc4FdKJtkkf/mWIy6RVveD+Fi6B
         MNvhXoWZ+4tuoWULUXJlO0Fhpg76QZAgqlJIs2a24ht0yuEPvZZ3tzbmWOfn2esQdv2+
         54gPxla4P9MK8d+y5q3UerPsiDeDMElqPfVgEXjmlTpGLZYIh95bMiaNjyN1CURdGiY9
         Jadw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c0/5SZHW";
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id 26-20020a05600c231a00b003a5ce2af2c7si317520wmo.1.2022.08.20.07.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 20 Aug 2022 07:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id F1B57B80CAD;
	Sat, 20 Aug 2022 14:37:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 99438C433D6;
	Sat, 20 Aug 2022 14:37:18 +0000 (UTC)
Date: Sat, 20 Aug 2022 10:37:17 -0400
From: Sasha Levin <sashal@kernel.org>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: linux-kernel@vger.kernel.org, stable@vger.kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Russell King <rmk+kernel@armlinux.org.uk>, linux@armlinux.org.uk,
	ryabinin.a.a@gmail.com, matthias.bgg@gmail.com, arnd@arndb.de,
	rostedt@goodmis.org, nick.hawkins@hpe.com, john@phrozen.org,
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH AUTOSEL 5.19 54/64] ARM: 9202/1: kasan: support
 CONFIG_KASAN_VMALLOC
Message-ID: <YwDxnRGKNbk5Chay@sashalap>
References: <20220814152437.2374207-1-sashal@kernel.org>
 <20220814152437.2374207-54-sashal@kernel.org>
 <CAMj1kXEzSwOtMGUi1VMg9xj60sHJ=9GHdjK2LXBXahSPmm56jw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <CAMj1kXEzSwOtMGUi1VMg9xj60sHJ=9GHdjK2LXBXahSPmm56jw@mail.gmail.com>
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="c0/5SZHW";       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Aug 16, 2022 at 04:45:14PM +0200, Ard Biesheuvel wrote:
>On Sun, 14 Aug 2022 at 17:30, Sasha Levin <sashal@kernel.org> wrote:
>>
>> From: Lecopzer Chen <lecopzer.chen@mediatek.com>
>>
>> [ Upstream commit 565cbaad83d83e288927b96565211109bc984007 ]
>>
>> Simply make shadow of vmalloc area mapped on demand.
>>
>> Since the virtual address of vmalloc for Arm is also between
>> MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
>> address has already included between KASAN_SHADOW_START and
>> KASAN_SHADOW_END.
>> Thus we need to change nothing for memory map of Arm.
>>
>> This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
>> and support CONFIG_VMAP_STACK with KASan.
>>
>> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
>> Tested-by: Linus Walleij <linus.walleij@linaro.org>
>> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
>> Signed-off-by: Russell King (Oracle) <rmk+kernel@armlinux.org.uk>
>> Signed-off-by: Sasha Levin <sashal@kernel.org>
>
>This patch does not belong in -stable. It has no fixes: or cc:stable
>tags, and the contents are completely inappropriate for backporting
>anywhere. In general, I think that no patch that touches arch/arm
>(with the exception of DTS updates, perhaps) should ever be backported
>unless proposed or acked by the maintainer.

I'll drop it.

>I know I shouldn't ask, but how were these patches build/boot tested?
>KAsan is very tricky to get right, especially on 32-bit ARM ...

They were only build tested at this stage. They go through
boot/functional test only after they are actually queued up for the
various trees.

-- 
Thanks,
Sasha

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YwDxnRGKNbk5Chay%40sashalap.
