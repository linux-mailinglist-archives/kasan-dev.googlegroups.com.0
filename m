Return-Path: <kasan-dev+bncBD7I3CGX5IPRBHUNYWTAMGQE67HNKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D2607772EB5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 21:31:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fbdf341934sf31791525e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 12:31:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691436703; cv=pass;
        d=google.com; s=arc-20160816;
        b=LK/euIDQhE3LNVlE9/UKtxd9JNaoBecjwopmWLeQ54SkRY4WWVIvyVconC1DE+9pUm
         wOjkCFzZxPk5k5NEySLrzppLnsplJcWQHp2J5mO6gkOeMM3X1LOxhrbdAYHT+bEHJOwo
         pytpxYVi59j3Y0UE4mLuVAUgDB7wfZVqT5sxd40v4n0KDXN2XSJyxQ2PhPUEwwN/gxTZ
         ScBvDnr3ZXyU5XNmEKK9y4fie8sOTBqbCC/pvonu0ZkfqYQOf0MegUkItTFrq1OswbJ8
         wXJcpplg7YhEIUPpzxew/jSn+AQ0ob7OCjizjHfD71WsBpQOP9Sm1s3CP4L2M/8pz2R0
         gaQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=RKKeEHN4YPq9ix9lb9jrmpgwFgbi5VLzK2rNTgQjXms=;
        fh=6WNc4MQKJ2PVuR+1NcvDj2LMJXZ4guPhuNqgpbYrfHA=;
        b=j4/fKbVLIqDXHYFEE93AJKNo7U60fPIkqnX4JWBY4HJYNvIfH/z3iyjOvpPp80xjOS
         //nCQtUsRn1Wzcwm6ZQtjSL3Gcnd7dcU99JWNPQN7bruXR9OMpaAafY9dhg4+IC+fAT5
         FSZsknJEiCAYXU8Yh84myg/4piMV5pgTHB1OIyD/hE907ggCYH/a8Uxq9k/tZBOWDTeR
         p59p+l6LdpZwgKvtvJ9HeulVDZVK8jb0VmNNwZFbHnFUblmwBcoHYlWnxMDALAqoQOM/
         hUQBdN6fXco1DQhrX3w5EI5/vDJhNGedPn+md3mgoKbB3rmgcFpX8eTvxUoKb6n+EAqU
         z7ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=XWXEoDjw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691436703; x=1692041503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RKKeEHN4YPq9ix9lb9jrmpgwFgbi5VLzK2rNTgQjXms=;
        b=HteHkJcu2xKrY5wMiHleXCoaEhq4jkXFwTW5AX2derT52jydte6qDhUPC6lr7Z1lJG
         a43El3/Oo+myCHut3oI6yTck3U3nrCrNI0U9NRSVDGWw8Rr1A0CS/wPhl7E1bHsWjADE
         NsnC9vJ2f9fwsB+qFGOTwgyDPVx7k22HMjEEmKCgE0fRZ2VXmOJ1xeA6X976436HjGDI
         pbJe9u16Dx+ppzI8bTwjnLs3beDEvAnhNtDjfyeiKKifaYpMViv9oXwvEcd2itQnkEFU
         IqFvae1rY8yIUDZUG6c0ilOiEG2FIVBvo4UWxHQuTGrQsqTH2k+smgV00Hf/MVjqEyt8
         uhSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691436703; x=1692041503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RKKeEHN4YPq9ix9lb9jrmpgwFgbi5VLzK2rNTgQjXms=;
        b=HqWuBri7BZ0egrsFvdORzcBpw5i1+o+k3Sf1AJ5kkjBj2SGQyAhQFiAEu0JDOadfjC
         0eW2lolcmgH336Pr8yhivY+1dVkNGFrzm0NWoM/MTrQ68L/eF7Y1c8+QchrMXCfSEHrm
         unOkGN0VeVpA1MRRkSHqkUmhRaR4osrDDKP5n6vPMYc9L/nveljuyiffvPDDqVMXYoGJ
         atvw+3wbtAqy4OlxTdHSuUk1mE5NOTOGmtZrSE2gWKNBsQvSLT/jbh9mqAqXa7HuOeNs
         Mvg6STGN0kIgA7+jmLiDZsIS31YAIRVo0Frp9+0Rz5pxuE+Q/ui/K5IZadjDc6CERiWi
         ReXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwaX179NX9eevMUfQRnc+Ki5IHpoi+/mQvljXgwXo10yJ58KbCT
	MpHyDnuOsnDOqU42Hx9hyg8=
X-Google-Smtp-Source: AGHT+IFlPIMnWATlfE4QoGym1/Fna5YzwXmnEbtNAwlO1G6Tz+6vt5dr88k66HIHnN60j1iXEUds3w==
X-Received: by 2002:a1c:6a16:0:b0:3fe:2606:84a4 with SMTP id f22-20020a1c6a16000000b003fe260684a4mr8392461wmc.34.1691436702900;
        Mon, 07 Aug 2023 12:31:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b1a:b0:3fe:481a:10f9 with SMTP id
 m26-20020a05600c3b1a00b003fe481a10f9ls1373910wms.1.-pod-prod-09-eu; Mon, 07
 Aug 2023 12:31:41 -0700 (PDT)
X-Received: by 2002:adf:fa84:0:b0:317:e08b:7b1d with SMTP id h4-20020adffa84000000b00317e08b7b1dmr4534793wrr.11.1691436701202;
        Mon, 07 Aug 2023 12:31:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691436701; cv=none;
        d=google.com; s=arc-20160816;
        b=RRFWcWfVRa8kSmJUhAn9mUHTs7eE1VgDOffB5rSyV9CN5wLIZs5S8dxn7ocDN9yo/Z
         ZwJJ6uI/KsX2qYMN392br2JAnhd+MqBgG9+ldZLhjrDyGwYAJN8WUIqkbKsTCoWpgiot
         k0rp5cYDntvxDr96pNRa0UY6jAgAvnefKJx3EhHq6X3Z2IaxD9CmGZMyazkjhsjsNmGS
         DXBFfjSEJwlh+fFiq6sK2czRXJiT8muKn8qc71v9LTmtTtv4esDN2R5XFsg3O80+X6wn
         KfM/PxyMMAvQp8ewQv/4VOdQ5P+7k076mLX4oxAc/MO19yLDxX0f2xdir1zxTbji+iXH
         LEZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=uLrESuDnsmXF0LnLVgvvKKzxJ74Ji/f7/0NisgyaeNY=;
        fh=6WNc4MQKJ2PVuR+1NcvDj2LMJXZ4guPhuNqgpbYrfHA=;
        b=EJRx1jCScYZ5f0xcu9sGmxKrr04aUk+Cy9XB29MnmfVOkiqxcBr/lF48KZREDXSOiJ
         sR7Kx/mOeDfDiPFH1ZAe01wLRZJ42ePFxBK4weqcSxBJzppga1ZY2J/jJrP0GQHO9Dh2
         pQptfvGQ7YoEIlwM6SfEnYR4vLeFRN0vGSOdjDbMZugN0C85Ptxo+MQU3jjBEEysmjD7
         HwUzHn8UwzdgFfq37nNivLfTb4R5czMpYAD2nCRxF2gCTNSqD4EtFyLRysCk+jrYE/Pl
         kJe0dTUkdZR3Bo31+id+ZTLjNGf6UunAEfVRsJxXgd3FOiwEpHXfCUw+6E3XfQQ5ZOex
         P2+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=XWXEoDjw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id ay2-20020a05600c1e0200b003fe0df12dfcsi701642wmb.2.2023.08.07.12.31.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 12:31:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-4fe389d6f19so7721837e87.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 12:31:41 -0700 (PDT)
X-Received: by 2002:a05:6512:3696:b0:4fe:61f:3025 with SMTP id d22-20020a056512369600b004fe061f3025mr5912246lfs.61.1691436700291;
        Mon, 07 Aug 2023 12:31:40 -0700 (PDT)
Received: from [192.168.1.128] (77.33.185.10.dhcp.fibianet.dk. [77.33.185.10])
        by smtp.gmail.com with ESMTPSA id c18-20020aa7c752000000b0052228721f84sm5609359eds.77.2023.08.07.12.31.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 12:31:39 -0700 (PDT)
Message-ID: <fdd7eb5d-2b76-d326-f059-5cdf652b5848@rasmusvillemoes.dk>
Date: Mon, 7 Aug 2023 21:31:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Content-Language: en-US, da
To: Petr Mladek <pmladek@suse.com>,
 Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <ZNEHt564a8RCLWon@alley>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=XWXEoDjw;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 07/08/2023 17.03, Petr Mladek wrote:

> I agree that kernel.h is not the right place. But are there any
> numbers how much separate sprintf.h might safe?
> 
> Maybe, we should not reinvent the wheel and get inspired by
> userspace.
> 
> sprintf() and friends are basic functions which most people know
> from userspace. And it is pretty handy that the kernel variants
> are are mostly compatible as well.
> 
> IMHO, it might be handful when they are also included similar way
> as in userspace. From my POV printk.h is like stdio.h. And we already
> have include/linux/stdarg.h where the v*print*() function might
> fit nicely.
> 
> How does this sound, please?

No, please. Let's have a separate header for the functions defined in
vsprintf.c. We really need to trim our headers down to something more
manageable, and stop including everything from everywhere just because
$this little macro needs $that little inline function.

I did https://wildmoose.dk/header-bloat/ many moons ago, I'm sure it
looks even worse today. I also did some sparse-hackery to let it tell me
which macros/functions/types were declared/defined in a given .h file,
and then if some .c file included that .h file but didn't use any of
those, the #include could go away.

Sure, individually, moving the sprintf family out of kernel.h won't save
much (and, of course, nothing at all initially when we're forced to add
an include of that new header from kernel.h). But this technical debt
has crept in over many years, it's not going away in one or two
releases. And use of the sprintf family is very easy to grep for, so
it's a good low-hanging fruit where we should be able to make everybody
who needs one of them include the proper header, and then drop the
include from kernel.h.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fdd7eb5d-2b76-d326-f059-5cdf652b5848%40rasmusvillemoes.dk.
