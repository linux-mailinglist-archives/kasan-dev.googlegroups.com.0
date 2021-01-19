Return-Path: <kasan-dev+bncBCSPV64IYUKBB4FETOAAMGQEB4GDMAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f62.google.com (mail-lf1-f62.google.com [209.85.167.62])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B4522FB61C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 13:37:05 +0100 (CET)
Received: by mail-lf1-f62.google.com with SMTP id j70sf7940827lfj.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 04:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611059824; cv=pass;
        d=google.com; s=arc-20160816;
        b=VIIv3Z0Xb4AD8OOEhwYZmBL97X5oEw0HOwSSC9E/wfJ0CwwlktkfEbzeZ6EDiDPI47
         BmI0pKs3I/gYDDpIDpLv5qNFPH8/o9Mw92WQZHcq+tYDTK6uiuzW+GcizZWdfESpKpyL
         AVznX2DaP1uoNyC3xCvpRKUE8rgtAQGA+oCltkxHkAl694WWn5DXW2G7MijFI1iuWWLx
         aV4kayEP58wz8Ehr24yrTerOr711T7/8YWvlmhHITjloHd2m28guPCVyqwNM7pGuMMZh
         wl/C1I7Wm+QEweqMzXOM2QAMy310BH6OEnXygRlzbXYfSzOWiGp0d3SzCftp3mmmYIUW
         FyXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=i/F1ax0F7DKzAE7YLE5hMUQRM35cLb/cLUUWIv3KVik=;
        b=kl0ClZ7G75aO4k8EmuAa6Bb0/k6A2krDSZNY0JdiQ9I1mOLA+xhTIkryOBe5CUeoLY
         4RHQ6ojdE2S7Pu7hrx5CPt9b4kXeCRpqrvKASMYjK9kv9bnBF1bTk6Wf2MPbegXtbewd
         ZG2yIGcL0yaIkJfLVAQQcy2OJWQ5KbpLrqblPWeJxqVRtARWBUl+Gx3VSNT3yIYxvNFA
         hmMSHFBj3OP4idCxrxKg2E1MbBmwmffRPQHIgXJ4/cc+s7rMSZLgi0t5cqWheDIEFJhL
         /bhNlwK/kuVzpz3GGz8OW83GxTp7yDbLRhZQ37ed5N2rdKyTtgFD/3pOwqhg8TOPmiWl
         WTJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=x8MxxHQU;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=i/F1ax0F7DKzAE7YLE5hMUQRM35cLb/cLUUWIv3KVik=;
        b=UIqwfuK9Zj6ZVn17vhZ0UlW96VYnNS5+KezmkZW+tKSZY0wqu/FOTyH3bhJys4cHir
         kWjpSiODYu4oVGafUYApZY1B4KUdaJIP765TfCyq7e8q+h0kYWEODI+TYWa/oQPJSO3c
         Amlnh7JQ8yxoNrCk7yW3LycYYLgfMXYulsaMo4A4olYM44JgvnJO4rSlo7ZF0DPzMMJ4
         jDZBxa+m0E+Oxud1UFngugA0d0xTFkqLme/PHfhbVpI2dz9juDCec0Q61A9fidyXIcgI
         6hjW0+XgUc03h3U3lb0ZNILXNbQPdvLX/IkfEJz5JJi+rNj34zcBLI0LmY6J6fhB66oC
         81BQ==
X-Gm-Message-State: AOAM530TjgcoefGNYl+XuPsdvl1M5llAJW70Wj+8JmBV3zXjw/w8YfuI
	xdAZK2Q35G2bj3j5H8fIWgc=
X-Google-Smtp-Source: ABdhPJwwxTJm9NQmLScN8QFAtYpPTQCaZqNK6/wfpdZFqgzTxTW1U3sSZPlTOCLQEKtACXJJy/bwhA==
X-Received: by 2002:a05:6512:208b:: with SMTP id t11mr1721766lfr.647.1611059824654;
        Tue, 19 Jan 2021 04:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b549:: with SMTP id a9ls3302646ljn.1.gmail; Tue, 19 Jan
 2021 04:37:03 -0800 (PST)
X-Received: by 2002:a2e:4c11:: with SMTP id z17mr1849638lja.364.1611059823643;
        Tue, 19 Jan 2021 04:37:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611059823; cv=none;
        d=google.com; s=arc-20160816;
        b=Kv7xX7DoiNcxvhMa1I27xG8r7XXRzNjfcAdMLAVj8keUmtwPpwCuZAZ3iyG/80mLdh
         AZ92Rsr+en4XDWLUcQ/IsNaBRQEVxYnDgqrksC7yJMP4jO9pr3cddHircrewvsYThHFl
         s7p5HPL/K6slWh2OYO7M/YTgX459ArQgT94MMYVAmARyh8WfBuzgEvP+LKE6oDNrSF3w
         caCFipCs1CYmf2NuUEzjPCImi8niqPoy9q57MrqEkLtO2WF7ENPs1LT/bCO79tBY8XW9
         nCiXjQ2CKZkPfXFU4vh1LUpFkTzTqWqGl7HzPU5QbEdQNcfbTW8emh1MZasptR3jHR6k
         nG6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=3091HDIDJPbXMzpbOgmafqc9I4heyAG2HJIcUBxxHpY=;
        b=ZC48Ejp6eapSXfyL53WjtPg5hC1K2OCVgJmkuLfkdiqXGJaUJSM3J1JO/2a5SNgK+H
         t84XQ39rAMjpuBDPlT1RATK0DtVELlqvQxBBj7CqQP757zXSmN01TUxHzQn7IZ7Gf3Gn
         bf6DKs+SaJ7b/Ue34yYcspUWiZtEoLlQWT0h+7NgqQka9PPJHxzn5PARxYU81pvIWEBm
         XqRbTLxvFVahwGVPwGjeDSINHVh2jxGuOKawgpxLGswWmDVAKOmJSI9Af/4QAmMSFYsf
         CxFS65S0FuDV+MSXyJ2hGJYyRscE+Po2BNbn2xXvFTNDoTk/zdvGKYW9yxwW6oFDvr2o
         yUVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=x8MxxHQU;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id r26si977680lfe.8.2021.01.19.04.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Jan 2021 04:37:03 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:49964)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l1qFo-0007Mt-8K; Tue, 19 Jan 2021 12:37:00 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l1qFn-00050y-6C; Tue, 19 Jan 2021 12:36:59 +0000
Date: Tue, 19 Jan 2021 12:36:59 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119123659.GJ1551@shell.armlinux.org.uk>
References: <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk>
 <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk>
 <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=x8MxxHQU;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Tue, Jan 19, 2021 at 01:05:11PM +0100, Dmitry Vyukov wrote:
> Yes, I used the qemu -dtb flag.
> 
> I tried to use CONFIG_ARM_APPENDED_DTB because it looks like a very
> nice option. However, I couldn't make it work.
> I enabled:
> CONFIG_ARM_APPENDED_DTB=y
> CONFIG_ARM_ATAG_DTB_COMPAT=y
> # CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_FROM_BOOTLOADER is not set
> CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_EXTEND=y
> and removed qemu -dtb flag and I see:
> 
> Error: invalid dtb and unrecognized/unsupported machine ID
>   r1=0x000008e0, r2=0x80000100
>   r2[]=05 00 00 00 01 00 41 54 01 00 00 00 00 10 00 00

Right, r2 now doesn't point at valid DT, but points to an ATAG list.

The decompressor should notice that, and fix up the appended DTB.

I assume you concatenated the zImage and the appropriate DTB and
passed _that_ as the kernel to qemu?

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119123659.GJ1551%40shell.armlinux.org.uk.
