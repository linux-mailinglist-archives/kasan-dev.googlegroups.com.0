Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT5IUDVAKGQEBK4UBBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 74F618183B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2019 13:34:40 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id h3sf21027982vsr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 04:34:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565004879; cv=pass;
        d=google.com; s=arc-20160816;
        b=aGeg/nPTSKx7H0zpzxT2GtHVMVUBAJ8gIhYtdBG3cMpxx212132gG9VvlIk4r5qOKw
         813ujDXK6a+j24rIsgnAyY5742zzFVzwwNJ+zTyrViMgg/VA33JJSLvhth21trvWyo21
         4ZmRFO47DDv/ZY7/dsxIgP337zWm4/cSpy6geYkxn1Ugtd3JMPyAUxwHuP82g4lGsoB6
         r4EwWNZZ35bvDm9jMKiXVkr2MDl3bnFvgJcDfzco1LMFgZHLIvwlod+8lCYqDIWl8pOV
         vx1UeU41a8dyjSRCLvQ2CTdQoyh0RrZxVxLq3FSC5UpPIohA/1eTY20lc8kucDq13mh/
         rz8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KMgsVj/Cn+eBVIUQto0CI5hg3oNjb5uhNf23BylsVnM=;
        b=JHY3luTvZtLf6j7XSfJF/cIlgpVMAHZ1tE4DTVgta3X0dTZlU0PzS6yDEajtqyMAZT
         q6FzdmZeXEeMitBmM0ekoOCxbm7iofPOi5uA6i0rI7q6IU+yXK/XgsuqaCGIUzeTggkh
         ISId+vuAPYPoivvUysObN+eKnYVBIWOMJnFHpTa1oc++Hkm7eZwdPlwW+x+1CqVVqfmG
         s/vYgi3bd5yyEXmAOGaNh2cTdj3GgroMeGNkyprF6KtBP94r88uSA/qfvv8sFkEVlXBh
         FP3C31qwffJoP2GXKqyZUy3UwoFTs+OYMlLIuEI5Eb5owVEf4cQ7uIEII/Hiwv4SW90G
         JpKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mlUCjSuV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KMgsVj/Cn+eBVIUQto0CI5hg3oNjb5uhNf23BylsVnM=;
        b=C6Vea8ek+4TpAYGIyY7eV1lp+U8ihboNw9q0X9yA6QQ1ZvTUEeVmfZDQqacy7jLzzf
         l3SPpn5bAIRXW7f6zYHud0Z9Q4O098VOHL7ArS0cfmXqSUzbEajks6MFfGw6IQmeD6Tp
         yEkgDQ9DySZbrBeYgT4eSy40XQqJSq0/oDb1u4Z6D1V61bw1Qdk7sMCHG083D/4fQx5x
         z6uHl5mN+L+VrpYZTzbKCMX7ID2p5BFtTjQzHje/Jr+YB0Yd1LE3J6FF6j9G/qMDXpNv
         gqwYVBgBh67MORrA/+C62gTgj0lM1ONdMLP89JkEgIGSuP8uvlD7EbYAWtmKCi49OtgG
         NG0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KMgsVj/Cn+eBVIUQto0CI5hg3oNjb5uhNf23BylsVnM=;
        b=qoEgBpuDLlsk0idO8v5pO7dr7rg6/516dMW1M78FIn/FDzQnW3DIgMx7X/H+IuTxEv
         JLliDqH0Bt/6LukuFRGyTn6pBKqm/ufGduMtyN26RCjbSuPUxeV7CrMFUiMFVfmYEYFB
         n+1RjnRFY8X3NJzzxyHYc7NmFmFrLkMaIm4+4QDLNtzXcRkBibOB3du7Q4oNoEcZb4ff
         2rmdHAOURrrX1O89Eq+iso97zQjSZeTvZPWDAxVJcu5AXqAbEtjWq20uE//U7ORuxl/E
         G4pnjoD4S9eXfYdmQMVqI9PiyYzYRpLAaGWktb/o2Jd/kfERAze8nxMZvGSdB6P2F+Ef
         h3bA==
X-Gm-Message-State: APjAAAXevFuiTJtEURjqo6cOAH1fgxT49wWRy3ZuxTzc9WtgdLy16tEI
	n4lk+DfQt1NC93YcIDz32Hs=
X-Google-Smtp-Source: APXvYqwSIl3B9aOa1o0jdeBPVgENjKoV8O97DOMvP1Ki7Z+HP+Vy9LL2PYgTyIIEPk9WuFqzJHos0g==
X-Received: by 2002:a1f:2b07:: with SMTP id r7mr58377664vkr.65.1565004879409;
        Mon, 05 Aug 2019 04:34:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8bc3:: with SMTP id n186ls10642192vsd.12.gmail; Mon, 05
 Aug 2019 04:34:39 -0700 (PDT)
X-Received: by 2002:a67:efd6:: with SMTP id s22mr8751069vsp.47.1565004879188;
        Mon, 05 Aug 2019 04:34:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565004879; cv=none;
        d=google.com; s=arc-20160816;
        b=VEFFVpr/x3fS56X6mDtjLVW4kzdpZPBJKpDoL+ovirMH0pk5Qr2Ex6aFwBclV5bR5v
         ViTIVt7YlfNq8NjtreqmgQ8sKUYdMkR1VyR6Rs107Sh2VJnHmad4O8Dg2wXmn7xOr3Go
         PHbzBK62HWTl3wrc8MILDM21gmcyU/AQmvjCZ3qAWQQdYzog0f7kaJ2XV6UUvQ619Lwf
         bsnjMvLWsIN3Y7WTiU7LkaY0QnZfeNLNZXTkhD9oTFu3yqHUV+qj7xlHmQ/AVgDGT8VX
         ocDo2kzmONbEVofNPuVUWDKA74Szgf8mDtfeMZzmNC7tgTkA8xGgIejxSarX2qKF0Mdu
         9hYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3adL5un0ZnSXAz928cw8ee4aXCsqnVigMSoC0+DwpJM=;
        b=T/XXtYoJph5QBXbsUbhkie4FAQuLU4+hyFt8cuxBi+ElmQB4ni6n2Rm+UwxG91XkcL
         WrlLh3QDpMRl97+9q/n8LRCEz8aMH2yUGnV15P/C/Ue99+i4+Bge/WQJwX6yWcyGYKce
         aqJjb2llm1VcvhefDu50shMvCRu1kH7A04I6nZ9Q6E0eimC1gl0jGh7bIRU1STL95b9D
         PY8LfmpO9ueVdLLJbjI0/CyxVl7cVpF+dcGSgDj5Ep/J7Fyd3Qgjwmum1oXRvN9iUckk
         5n6DPteruMVDD5wXTttDWkVTtJ14rfSjeswapIiDYyKjPlxS2jX5arxSNYIsXy88Qbgc
         UhvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mlUCjSuV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id k125si4431323vkh.4.2019.08.05.04.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Aug 2019 04:34:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id r1so39491874pfq.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2019 04:34:39 -0700 (PDT)
X-Received: by 2002:aa7:86c6:: with SMTP id h6mr73693055pfo.51.1565004877884;
 Mon, 05 Aug 2019 04:34:37 -0700 (PDT)
MIME-Version: 1.0
References: <96b2546a-3540-4c08-9817-0468c3146fab@googlegroups.com>
In-Reply-To: <96b2546a-3540-4c08-9817-0468c3146fab@googlegroups.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2019 13:34:26 +0200
Message-ID: <CAAeHK+wp7BduMoNQEOLgwB28pYLoKrp=cHiAzRW1ysu27UBn2A@mail.gmail.com>
Subject: Re: I'm trying to build kasan for pixel 2 xl ( PQ3A.190705.001 ), But
 touch is not working.
To: manikantavstk@gmail.com
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mlUCjSuV;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Most likely the issue is caused by a mismatching touchscreen driver
module. You need to flash/copy a KASAN-built one to the device as
well. I don't know any details on how to do it though.

On Mon, Aug 5, 2019 at 1:22 PM <manikantavstk@gmail.com> wrote:
>
> Without kasan same build works fine. But after enabling kasan, compilation is successful but after flashing the images device touchscreen is not working.
>
> Applied this patch:
>
> +CONFIG_INPUT_TOUCHSCREEN=y
> +CONFIG_LGE_TOUCH_CORE=y
> +CONFIG_LGE_TOUCH_LGSIC_SW49408=m
> +CONFIG_TOUCHSCREEN_FTM4=y
> +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=y
> +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=y
> +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=y
> +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=y
>
> Still no luck and touch isn't working.
> Can you provide any patch/ any inputs to resolve this touch problem?
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwp7BduMoNQEOLgwB28pYLoKrp%3DcHiAzRW1ysu27UBn2A%40mail.gmail.com.
