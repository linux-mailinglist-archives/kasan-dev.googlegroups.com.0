Return-Path: <kasan-dev+bncBDIK727MYIIBBCVLTOPAMGQEJST67VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 4750366E465
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 18:06:19 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id j30-20020adfb31e000000b002be008be32csf1657620wrd.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 09:06:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673975178; cv=pass;
        d=google.com; s=arc-20160816;
        b=hflduiiHOSoHsAoIoi3yoi4cUedFLvIB/QMnMWZkRL4zjHX40Ok9HqMdM9aVaj6KAo
         /kc3zjUtFM6t7hnPuKPcVbdz/o33jLHrurVO5uMw2o805VPvqoNn54gi5Q+DNV7nrc3M
         wFIisgAKEICqiCaW27fIEt7iDfcj1DqhUl7+myVm5vupbFQ7aGZfTZfGay0VZ2Gkhf6X
         MYphqRrq/Nc0Lv73yN9fSckX4JFP8g2mci1z1ExyHXEFZ4B+vMycnqmHtCiqRmhT+nKD
         7aivQrK8WbKH3vMcshUveyUlkEYszL0DD+OM4Z08khRvO9bACGL/D+3GFQc5dMUK7f8i
         ze2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=MNDJrygIlUpN/kfmvwDz6D9OxfOJxC6gjJ+BroWnrRI=;
        b=aHADF3KVTpiJx0RR5hDa+/kWZuitjIQN2R2RUD1FEeZviq4VHxj2DIVCUZPOGoL/as
         U5hdi02FiriOgPfbbTluUUTnSGsR6yveey2VjZfyZf/9XVNEfjfU2Gjo4c4TGKURkN0s
         SP8hEbDzFh9DqoILMaVHpdSs6h0Pdo9AyvSKRMkKWBCH/1YTqOwXcfp1jDWzCg7F6IHl
         GhqJFPnN6hLexip53CPZhMsux8vGomtTmr/1UGIF4YDBoIljpO0ac2NSmC11DIykBA+R
         Yrg4+6j4eF5CpR4uTGUEYtQfDGvlnlIkdYrVK/1YmpSr3QxgnXfCNRK9BtX9W1F0w7/Y
         fTew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MNDJrygIlUpN/kfmvwDz6D9OxfOJxC6gjJ+BroWnrRI=;
        b=kFThOp/U5uHY7jvqI2VjIxDx+m+NGg97NXpi1DPOkZRt7hQ2FYFshcH+oSc6JG/3AP
         N0YdNHkVjOXMdsYIm+EcwPdXi+EG5eizvC9kvrb+zjH6RLmoxwqLRXPQ7gENSRf7HlvL
         ug8k9OZs5kzNVruP1CIBdV2WQoC44FRtfiT1AXsqjzbNHjMpSsv88EKjcJn6CDbWe7kR
         ENHdGszXYmwhTIFjTLN5ZU3s5qI1biYlokf107TukiGkuLAsZQayj600wc3MicKpVRJp
         NLTC9Mnq197Am6vFR4RkbjydIDN2YlJWmw5XGHcAfU4VJE1MjFwyC7q5kXqUXPr/7mqa
         /2Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MNDJrygIlUpN/kfmvwDz6D9OxfOJxC6gjJ+BroWnrRI=;
        b=uSPT2ibYcrsqNuSRkpswJKDYyrwsg3o2N3i3d/GOBNPfV1GhtPxYwkRt9iPRkXOkhz
         fzCmDPFoaoSgmUMN1dmeuYfeGTqBRXq4bnnJmGpEooprj0hZPUVscGDt562ZCSqTX5iX
         MNbaOq83U5oy0S0rYWH8JBmQMU2zAB0OuO2hH6QQj0JL0T3vl/pZEOg7etXTGmmgy9HC
         obcjfHBwzEoAudgdtD1/qLY29UK4dwgVmlZEfEf2if2DkPcLQxKXH616Xvfs47hI1nkZ
         hmnhwHAzkx+dJvQfVZY/NvnTBvzcV5Oq9Ml98cDVvs3s0IFAs/xVCBAJ6KBPIj843NDA
         giLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq5txgdP/xNqkwR1OdtKDfQifk+I3W2YVwxUGE5GGjYkiRSGYNH
	wovlSxvdgGZvyXP23crKSds=
X-Google-Smtp-Source: AMrXdXt1MFSlD9ecwAZq7W3rF69R+zqlhqzQ14jKgpwIroWlXk6FYMaq46YQjMuFmTU+iA3aEubLMw==
X-Received: by 2002:a5d:440a:0:b0:2be:f2a:a455 with SMTP id z10-20020a5d440a000000b002be0f2aa455mr126055wrq.559.1673975178887;
        Tue, 17 Jan 2023 09:06:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:17d8:b0:3c6:c1ff:1fd with SMTP id
 y24-20020a05600c17d800b003c6c1ff01fdls9605104wmo.2.-pod-canary-gmail; Tue, 17
 Jan 2023 09:06:18 -0800 (PST)
X-Received: by 2002:a05:600c:4d08:b0:3da:fef0:226b with SMTP id u8-20020a05600c4d0800b003dafef0226bmr3831466wmp.32.1673975177971;
        Tue, 17 Jan 2023 09:06:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673975177; cv=none;
        d=google.com; s=arc-20160816;
        b=uCYbHZO+Nsm2/d3ZsD1sk6O5fnwZv62LTbtQ476QOE3BDP+EBNeSiQ2Hdir8DQMJmB
         bQoNUEZYfcM1erDLK5X/zsB6lFqL1C9p4DXFMwSViJzdaLL0z99zJ3cNZO/WQvut/QbO
         DL1b6cH21mG6nEy1M9oUcrgkEpR8yaeUfeCtVhmOVvkVLBJ/NMhmcmi5OY5BJm7wNzTB
         V/+0C12dsm+YQ7dB7OzVvxC8niGzdZM3WSakej3NO8bbKSTUGU059khDI4nyYpgYlA54
         RFMhlocNDaBCrtDdqpyuRm6q2A94fs/yvgmh9dg3wYdD9FHoS5/lOW45IT8IN2kbLohS
         iQAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=0kLX03Az6cKSTZEXY/z4ABJEUAyylqMMgPZyMU9LWOQ=;
        b=n+8ZLhMpr6nMpXegSRIAIraORJu+VJF47N6OVye8SFvYBpIzv61eGOrOV8LXr29Gsv
         J6/lWL4HYkwFdCpaxZeGAw1hRuoULxAEwG20P/XNd99qh986Q/FSRtUOnGILahGaK2H1
         aQ7LraGiXoSJPtYp3xXw6Ew1+fJI3/WT5YEa4fxC+Ke3CbUA4F641AZDEXPBSvjtERRe
         9djSXVmWTjs1RO/u1cV31AGqaHYZM6vwOK80P9prZRG2rMyP+s5ZnJ2Y/kM8OQZp8xN/
         /i3AURQ9RkRlrLlt1ZvpbqT3eD7gScg6sJJ+rwpX2C/8pME92usjgHHkxoXZSSDb8YL+
         B9NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id e4-20020a05600c448400b003d9c774d43fsi731390wmo.2.2023.01.17.09.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 09:06:17 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pHpPU-001nMn-Ss; Tue, 17 Jan 2023 18:06:08 +0100
Received: from p57bd9464.dip0.t-ipconnect.de ([87.189.148.100] helo=[192.168.178.81])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pHpPT-002tRa-PS; Tue, 17 Jan 2023 18:06:08 +0100
Message-ID: <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de>
Date: Tue, 17 Jan 2023 18:06:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Calculating array sizes in C - was: Re: Build
 regressions/improvements in v6.2-rc1
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org,
 linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org,
 linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 linux-xtensa@linux-xtensa.org,
 Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de>
 <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
 <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
 <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: 87.189.148.100
X-Original-Sender: glaubitz@physik.fu-berlin.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as
 permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
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

Hi!

On 1/17/23 18:01, Geert Uytterhoeven wrote:
> The issue is that some of the parameters are not arrays, but
> NULL. E.g.:
> 
> arch/sh/kernel/cpu/sh2/setup-sh7619.c:static
> DECLARE_INTC_DESC(intc_desc, "sh7619", vectors, NULL,
> arch/sh/kernel/cpu/sh2/setup-sh7619.c-                   NULL,
> prio_registers, NULL);

Isn't this supposed to be caught by this check:

	a, __same_type(a, NULL)

?

Adrian

-- 
  .''`.  John Paul Adrian Glaubitz
: :' :  Debian Developer
`. `'   Physicist
   `-    GPG: 62FF 8A75 84E0 2956 9546  0006 7426 3B37 F5B5 F913

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/429140e0-72fe-c91c-53bc-124d33ab5ffa%40physik.fu-berlin.de.
