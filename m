Return-Path: <kasan-dev+bncBDIK727MYIIBBGVATOPAMGQEJZXJ5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CE3B966E3DA
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 17:43:06 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id j30-20020adfb31e000000b002be008be32csf1633897wrd.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 08:43:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673973786; cv=pass;
        d=google.com; s=arc-20160816;
        b=wL9G0UZK3JmkJO1W6WFoqHM0kMKKmqV1BL37k6PvqydbW/TRG0d0Yy9woYsa9QYw4z
         QRiBDo/p/qD1Oy+tEqrmVGp10VEGliQi5ijEXQNN0ejzXRQgRkkyLBw33LAw8XXRM+k5
         6bB63LzKjzyHDesJrwdMdJpG8f4sF4OMgTH/32wFGAWX6YpMH37PZl8oiPjNZBvWTWUt
         DXZkRMdBbpKCoGufyisgaH1GUnuTGJCwrPEIUIL5cFcdvrYiiQOsWLSYWcegvmf3yzZM
         zzbHcY181xdb1ZVWGBQetrF4XFK8dwsDjbpGli6UdtXpFojdwp18kte810CtQRQ41lk1
         lkfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=3+5D+eCV3b9bFCfJ0BZF9pK0oZjzZ1FWiHJ9jL6F40s=;
        b=btPopXyANp+leikxnrkPj4DrsA34qyzYaURlnkJaqoj0iKYrdAj/+D2K7jaVzMvnbV
         CR6ebh6c39tFdEd2MOVFLrOA1uGYT8BOL0DtvsRoRyXk/CiCREcwxeacnD2fKGqfv0g6
         up54W9dlyOTxh7GL6vE8Ao/z+Zcp10C7Qnen16TNOq42Tb0wYjEcmf+VMvXVXV2qRH3B
         CkdI3S/ccMA8h0zBWw0bPgspt4ZpjsMm9FHkGTWLQvIHCVMvnuL/NY2ot7VdxQ2pbB8L
         /38E1IhxKK0jhR3YH1JjcsLNvb5QO04a0V/FWyJJv6x0HlXzr+zjtH61crsowmzeIeKm
         LEvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3+5D+eCV3b9bFCfJ0BZF9pK0oZjzZ1FWiHJ9jL6F40s=;
        b=WbUlr0eMOJmwVDzEmth+O6o4QuIHW2RBDdIgDnHLDEPfCbWhmPAyVgXENr8rSnbL5Q
         u4c+6YAeSQnnB5gTuLFiPF9mQoYm/ia8Y2UttUXG5WENMgcjbl4u1Sww/8gK3DVYKcHr
         8VC+NULO+kxEditel4a8iZm3isKAoIE4LHXnjdX/T8BNEZ/+VhnoAuxfanKPuErjRGOU
         7IUQ32wUN2Q/sjdf4SwpNiUMcb0hFe7Hf7gh6pcCamYnWdYxKMN56x7EiopxFbE7xiax
         PdGbZlQU25WaNTc+EKjumuQD6sZ6AEBeZF2EbgO0WujTKDkeELht5ug4G2wdCoY8sAkU
         mdkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3+5D+eCV3b9bFCfJ0BZF9pK0oZjzZ1FWiHJ9jL6F40s=;
        b=i1iJgYbPkjyXUQxGv0TBxrkbdwH3YmAHKRiq3Lov1f7mpy3YMXR11jW2t7q038ZLsI
         n6+7/vambN6Ehp0Ieq2NXhbysbN35kiCdOOqsrXIs8VdOhlUpCaKebx72RAx/kOas7tX
         6H7+lpHrrnv6C9Y9NDPgrGT8edfqD4ZEoyA2rYMnLS+1w5uzHJIwEG7TgQ0ibpozEJw3
         U6Cvf13zTjh0cr6kZTQiALOY70udpOTMVcJdliCZPKCcj14lBJa/7KFYFpKZloTX2tHW
         ThGbryRnjGO6466dg4SiyIjpZhkFm8/i1vZfndLBHsk9TnjiFGtdJOX8PEnpam5FSKe/
         zNXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kobgWSIyVPyQ6OXLglkpLgbRnJYTqwIrU7d7flhRLCm3u8iiTVS
	mQLHa/ITKpsVBJ2ScCnL+gY=
X-Google-Smtp-Source: AMrXdXtwDiZOP/imLq31Pm29X8Yl0y/Z16eTdCwCgE/yIekNddApwvz6ggCtc1G5fPiC4GVvcta/ow==
X-Received: by 2002:adf:f6c9:0:b0:2bb:673e:c486 with SMTP id y9-20020adff6c9000000b002bb673ec486mr199209wrp.200.1673973786381;
        Tue, 17 Jan 2023 08:43:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a1d:0:b0:2b6:8e51:dcb with SMTP id bq29-20020a5d5a1d000000b002b68e510dcbls819815wrb.3.-pod-prod-gmail;
 Tue, 17 Jan 2023 08:43:05 -0800 (PST)
X-Received: by 2002:a5d:6681:0:b0:298:4baf:ac8a with SMTP id l1-20020a5d6681000000b002984bafac8amr3351461wru.44.1673973785453;
        Tue, 17 Jan 2023 08:43:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673973785; cv=none;
        d=google.com; s=arc-20160816;
        b=hR7djyBq+2FVAmm25MD+XegKLvBFziZaK+ujkAH5W17yo+X1snNS71/XVkvo+rYD2o
         4DEK2YPiP3C0bG4IRIpngh1axsgrUXEsxJZFhETqGqI+Oryj2JKNn6rKkBlTawJSk3Ym
         asTvISl5FW0/xubKk85XjapMSyy4oyDZ2ElZOzg7MND+YbGl3BdmzJcvQ7BCMlW9Glo4
         dKSz8zOFW7M5a4qwMQ3lWmDjLXrIEGHS+FE7224X8cUGAJ5LQZsbH8jXfH9XJ6M5SHpC
         FiRxD/MzQH4NYdBmdVCEHE9x6waVA9U0MjIIdexyKPmDCfGJRT8ia/7QQzNYDkieY5pN
         0AqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=jBMiC23PuaYE856mBxP4m1QXC3Ppdq8BFbM+KH+7+Eo=;
        b=Y+pXLMOMieFHsfzM2R6FRtpY33c4IDaI3hZKyaTcPjjs3zAyPZButX2Xspi2K1fdWS
         I+oWxJGX5AcsUGXo5yZzTJVVgEj2csUIERax+XCXBSdwn6vlHlJEovRfrnySmCI77PJI
         y+UX9RoKb9R79rE7SUJm926nUKPnh7ON0M3R824Aw0bitQDmB6BqwMUdJ2uZ/O6De/nb
         6UY9rPaY2PRiOkcUjuYZbr06NmtFpMWk+GunapWpmPNv4oMngZD7wD6qHqHxtdN2VOmf
         xUdne2XooDCgmJlvkHeK72XcERSZTvdLkF5U80iWhJcR+1zkl0AEp00jKge7nL612P1+
         spEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) smtp.mailfrom=glaubitz@zedat.fu-berlin.de
Received: from outpost1.zedat.fu-berlin.de (outpost1.zedat.fu-berlin.de. [130.133.4.66])
        by gmr-mx.google.com with ESMTPS id bp11-20020a5d5a8b000000b002be1052742esi221895wrb.4.2023.01.17.08.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Jan 2023 08:43:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glaubitz@zedat.fu-berlin.de designates 130.133.4.66 as permitted sender) client-ip=130.133.4.66;
Received: from inpost2.zedat.fu-berlin.de ([130.133.4.69])
          by outpost.zedat.fu-berlin.de (Exim 4.95)
          with esmtps (TLS1.3)
          tls TLS_AES_256_GCM_SHA384
          (envelope-from <glaubitz@zedat.fu-berlin.de>)
          id 1pHp2k-001f9B-4y; Tue, 17 Jan 2023 17:42:38 +0100
Received: from p57bd9464.dip0.t-ipconnect.de ([87.189.148.100] helo=[192.168.178.81])
          by inpost2.zedat.fu-berlin.de (Exim 4.95)
          with esmtpsa (TLS1.3)
          tls TLS_AES_128_GCM_SHA256
          (envelope-from <glaubitz@physik.fu-berlin.de>)
          id 1pHp2j-002q0C-UX; Tue, 17 Jan 2023 17:42:38 +0100
Message-ID: <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de>
Date: Tue, 17 Jan 2023 17:42:37 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Calculating array sizes in C - was: Re: Build
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
From: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
In-Reply-To: <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
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

Hi Geert!

On 1/6/23 16:17, Geert Uytterhoeven wrote:
>> I'm not seeing this one, but I am getting this one instead:
>>
>> In file included from ./arch/sh/include/asm/hw_irq.h:6,
>>                    from ./include/linux/irq.h:596,
>>                    from ./include/asm-generic/hardirq.h:17,
>>                    from ./arch/sh/include/asm/hardirq.h:9,
>>                    from ./include/linux/hardirq.h:11,
>>                    from ./include/linux/interrupt.h:11,
>>                    from ./include/linux/serial_core.h:13,
>>                    from ./include/linux/serial_sci.h:6,
>>                    from arch/sh/kernel/cpu/sh2/setup-sh7619.c:11:
>> ./include/linux/sh_intc.h:100:63: error: division 'sizeof (void *) / sizeof (void)' does not compute the number of array elements [-Werror=sizeof-pointer-div]
>>     100 | #define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/sizeof(*a)
>>         |                                                               ^
>> ./include/linux/sh_intc.h:105:31: note: in expansion of macro '_INTC_ARRAY'
>>     105 |         _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
>>         |                               ^~~~~~~~~~~
> 
> The easiest fix for the latter is to disable CONFIG_WERROR.
> Unfortunately I don't know a simple solution to get rid of the warning.

I did some research and it seems that what the macro _INT_ARRAY() does with "sizeof(a)/sizeof(*a)"
is a commonly used way to calculate array sizes and the kernel has even its own macro for that
called ARRAY_SIZE() which Linus asks people to use here [1].

So, I replaced _INTC_ARRAY() with ARRAY_SIZE() (see below), however the kernel's own ARRAY_SIZE()
macro triggers the same compiler warning. I'm CC'ing Michael Karcher who has more knowledge on
writing proper C code than me and maybe an idea how to fix this warning.

Thanks,
Adrian

> [1] https://lkml.org/lkml/2015/9/3/428

diff --git a/include/linux/sh_intc.h b/include/linux/sh_intc.h
index c255273b0281..07a187686a84 100644
--- a/include/linux/sh_intc.h
+++ b/include/linux/sh_intc.h
@@ -97,14 +97,12 @@ struct intc_hw_desc {
         unsigned int nr_subgroups;
  };
  
-#define _INTC_ARRAY(a) a, __same_type(a, NULL) ? 0 : sizeof(a)/sizeof(*a)
-
  #define INTC_HW_DESC(vectors, groups, mask_regs,       \
                      prio_regs, sense_regs, ack_regs)   \
  {                                                      \
-       _INTC_ARRAY(vectors), _INTC_ARRAY(groups),      \
-       _INTC_ARRAY(mask_regs), _INTC_ARRAY(prio_regs), \
-       _INTC_ARRAY(sense_regs), _INTC_ARRAY(ack_regs), \
+       ARRAY_SIZE(vectors), ARRAY_SIZE(groups),        \
+       ARRAY_SIZE(mask_regs), ARRAY_SIZE(prio_regs),   \
+       ARRAY_SIZE(sense_regs), ARRAY_SIZE(ack_regs),   \
  }
  
  struct intc_desc {

-- 
  .''`.  John Paul Adrian Glaubitz
: :' :  Debian Developer
`. `'   Physicist
   `-    GPG: 62FF 8A75 84E0 2956 9546  0006 7426 3B37 F5B5 F913

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3800eaa8-a4da-b2f0-da31-6627176cb92e%40physik.fu-berlin.de.
