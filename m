Return-Path: <kasan-dev+bncBDE6RCFOWIARB3WDZH2AKGQEW4A5ODY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 450451A5BA7
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Apr 2020 02:33:51 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id o10sf4137325wrj.7
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Apr 2020 17:33:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586651631; cv=pass;
        d=google.com; s=arc-20160816;
        b=RGEme9wNO42qNm5N0U/xhZH15RdNg9RZXG6qJnwGViqh7PvbERWox7/S4JUEe1LeLT
         6A2bDgGRielMR7Cv8DKSJI67JgAn2byotQxlVVlpHhT20J43WFn/vXNGXsPTwKqSKz8b
         3desv/Dgqxj7L0A8XEpda1lL3sHaGxvWzK9/SzC/SzFKQcmYiqwJhgrVvANaeO0OrkMs
         OCTWg59b9bYA5LOUUFEJCdy5llCcjKi37IMu4I0CtweR7fehLFam6bJ+PsVE5JdPH+QQ
         OpaNIvr6DNZzMY49xFilnevfvgiLL34+7P0Tr4dbCURxqOn9XZPP+t3gh+AzU9KdbX+S
         0aew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+6Ij5ffPiSgTn19JmTcUxyjVezctDojWaObs/PC6jGg=;
        b=dSLn//wR/fuVKkL3llpImqVjuqMq13HByyoqiYwT0y6OMvJF2pEw0/zZvQ1jfeew6h
         HuUVSiubGXrFb1lKfM5ucw9fjw7kpnqGblw470ULpsHX21i8+xnW9ldOxl3aENGMPmkG
         +7vRePzx2IbeNRbOHT/+ZFlSzfa15QlFl59U0xZ/vnVp2twGkvYonnsjO/PBxesYhxpC
         BTv6ZXr74gGi+vAuuyDfWaxlGEiAL6q6mdLOoYLHfa2NCNAqm/he+3do2dis+xWb7S3L
         nIFV/YBq7L86Hx72pnAjMHH0UxSwhDqgsYvpOh3KxaDexDAAh0eQT6HD4eywepAT9XJ+
         e40g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="kV/LeCGT";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6Ij5ffPiSgTn19JmTcUxyjVezctDojWaObs/PC6jGg=;
        b=fZ/OpphZ5+q/xhFbEfwfg9h72ZMFpmc2nwl/Jf6Vg5JJopPOZxShH1RZZbXWwGPpnU
         ANvgV7DLNY3hWtkx6b76S7N9k2BtuXL99jvkUtpjeelfS9WQEzTnIKE7UAdFS6vitwLu
         QqAB8Fu9hAUXmOR1qJ72o9W4QqrymBSBbajif/WxNZS6N9s79WiN+7biwfRtHHklJGoB
         19FtSxH5Dn8CnrcoT5GE8BDLWX0augF0rIUq6/QwvPVLX6+IIGVCtp3KWk7c2XpuMAGc
         NuQWShKPr9oa7c/Xa8rHMlMmG9SwIuJHMCpO2g8IL3TGu5EpY/SCPZICXQx56ND1xPCh
         YtMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6Ij5ffPiSgTn19JmTcUxyjVezctDojWaObs/PC6jGg=;
        b=r7OxrCZ8KA25qDF8EJuyghJ6ajiOvZbSnmdWUNHrp1d++gOKX4fEMt3J7c2Wf93Iv8
         g6891QF+NieaIYWo8Or8bzpX/OAAq0BFfeZkORLxLllV59KR8GbCZnJamhzrS6w2rMAt
         /oMA2TGrGa1D93nGpAEgk0yLeQLQrLUTZIz6zDhJE2eNfMMuen5oMeG5F9gav9/ibLzK
         4jXzlD7/6XDorAL6C9QBVSlUufglUnU03kbbulcRavsMby3xOjHCUhueRTlAjfqbJ6DI
         rLNr20XVpdTiKJr2Tgf/JESutGvkQaIMxHK/hWh7PfrvDguMx8TVX8YWGWYrMESeghOI
         08FA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYBGOjwdTUXr5Rvr11A4PJbs+UxuXmDGzypuwJqIXjVgV5BfuHX
	EzCBsJkx4eXMh6dV/p7FOgA=
X-Google-Smtp-Source: APiQypKWtjzF6Ws5p+LDg67ZW/1tHXrepHxj2pI4HYvFbmUfG5GoiYZzweI/DzMwaidTRKddaB712w==
X-Received: by 2002:adf:fad0:: with SMTP id a16mr13003059wrs.149.1586651630953;
        Sat, 11 Apr 2020 17:33:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a9c4:: with SMTP id s187ls11483608wme.0.canary-gmail;
 Sat, 11 Apr 2020 17:33:50 -0700 (PDT)
X-Received: by 2002:a1c:4085:: with SMTP id n127mr12632601wma.163.1586651630166;
        Sat, 11 Apr 2020 17:33:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586651630; cv=none;
        d=google.com; s=arc-20160816;
        b=dMKdS/agi2Na2bcKGvp2RM9Mrl8mTYZUD71lQzUkc58IN/9gVdlDwBjg08zaggLzVu
         RftExnv9N1fxt/sN3PoHn0SnXfe7sjNvvPK7BNIQrj9YRJOF9BapN34/B3YMK1un8QV1
         Ovns4ishu9q/oimPlAmZ+PVmV6QBNtYPKWtYrNo3xNyTVINXEeKwyybfLcyetSCMvN81
         +AHZCIfrZwhARimCZUVd1x+duKiBvuxxd3bvabb+pYAHzkDnt3Z1DamIGJlInR2Vzfr6
         G80ZsScpXRx4CgO3qRRC/wWxcvpXSO0bvZDJ9uGlWh5H6gPyWMddiYdup4SrwpbRS+g8
         HXug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zsyaQJSTyWtQU6SNb3d/B5KGEXk22uVClxXXTgsbd6E=;
        b=P8T8AET/4M/lh6o4hHCzNW2Wx39RSIPwNkma0JOnxNesm9BR7dP18NQZwUYUiepSDh
         Is3habEkLHZhRcSEBIOIOggn+s/U3RMidyFdTgfhLYwTuZnNdy13yuWNwNG9Z3+rFfF5
         2vtxv42zMwZUhV1avoz4ClJo80H4X93xUhw9d5cRzRbfgAIQ4sDdD+aArnPNjTl/lO4n
         syrilpYdXQzWQSH7wMv6piqjhK9xYJTDy90h3xF5SHTTD1JsFmcCWKxqwDfEDRF0D7Fs
         rOQiJ0HUXYs39KVzXXFFxsGuMc6eWm7o6zDgwOUzRVLOUB//YuLwf0cidAP5GwV6KNEt
         W9fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="kV/LeCGT";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id s22si200661wme.0.2020.04.11.17.33.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Apr 2020 17:33:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id m19so3912428lfq.13
        for <kasan-dev@googlegroups.com>; Sat, 11 Apr 2020 17:33:50 -0700 (PDT)
X-Received: by 2002:a19:48c3:: with SMTP id v186mr6282470lfa.194.1586651629741;
 Sat, 11 Apr 2020 17:33:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200117224839.23531-1-f.fainelli@gmail.com> <20200117224839.23531-8-f.fainelli@gmail.com>
 <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
In-Reply-To: <CAKv+Gu_6wWhi418=GpMjfMpE2E+XHbL-DYKT8MJ1jE3+VybrAg@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Sun, 12 Apr 2020 02:33:38 +0200
Message-ID: <CACRpkdbR2VG422X0-nhOeWtS3Mhm7M1+RKMozBZbg0Jv5c_TTQ@mail.gmail.com>
Subject: Re: [PATCH v7 7/7] ARM: Enable KASan for ARM
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <ryabinin@virtuozzo.com>, Abbott Liu <liuwenliang@huawei.com>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Russell King <linux@armlinux.org.uk>, Christoffer Dall <christoffer.dall@arm.com>, 
	Marc Zyngier <marc.zyngier@arm.com>, Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Jinbum Park <jinb.park7@gmail.com>, Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Rob Landley <rob@landley.net>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Masahiro Yamada <yamada.masahiro@socionext.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Thomas Garnier <thgarnie@google.com>, 
	David Howells <dhowells@redhat.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Andre Przywara <andre.przywara@arm.com>, Julien Thierry <julien.thierry@arm.com>, 
	Andrew Jones <drjones@redhat.com>, Philip Derrin <philip@cog.systems>, Michal Hocko <mhocko@suse.com>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kvmarm <kvmarm@lists.cs.columbia.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="kV/LeCGT";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Fri, Apr 10, 2020 at 12:45 PM Ard Biesheuvel <ardb@kernel.org> wrote:

> > +CFLAGS_KERNEL          += -D__SANITIZE_ADDRESS__
(...)
> > -                                  $(call cc-option,-mno-single-pic-base)
> > +                                  $(call cc-option,-mno-single-pic-base) \
> > +                                  -D__SANITIZE_ADDRESS__
>
> I am not too crazy about this need to unconditionally 'enable' KASAN
> on the command line like this, in order to be able to disable it again
> when CONFIG_KASAN=y.
>
> Could we instead add something like this at the top of
> arch/arm/boot/compressed/string.c?
>
> #ifdef CONFIG_KASAN
> #undef memcpy
> #undef memmove
> #undef memset
> void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> void *__memmove(void *__dest, __const void *__src, size_t count)
> __alias(memmove);
> void *__memset(void *s, int c, size_t count) __alias(memset);
> #endif

I obviously missed this before I sent out my new version of the series.
It bothers me too.

I will try this approach when I prepare the next iteration.

Thanks a lot!

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbR2VG422X0-nhOeWtS3Mhm7M1%2BRKMozBZbg0Jv5c_TTQ%40mail.gmail.com.
