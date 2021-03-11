Return-Path: <kasan-dev+bncBCSPV64IYUKBBA6JVCBAMGQEEMT76AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f58.google.com (mail-wm1-f58.google.com [209.85.128.58])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F51133751C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 15:09:08 +0100 (CET)
Received: by mail-wm1-f58.google.com with SMTP id z26sf4106382wml.4
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 06:09:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615471748; cv=pass;
        d=google.com; s=arc-20160816;
        b=lGd945li+8k8NHSB9ttm7O7AhETtYuDHuPAEG31cPkE/FQ3aBborigLJnRbL+YW1C5
         Lhl9s1grY+/5Oh9ypvCq3kyFMqHepiLxo4lFCWnICKKcvlRt/lAfHdkwy7RNJ4z/30DG
         FjvIiL87K4zStHXWgQLKIOPNuGAB4bwHOH5DoEz/MSLnYjE5d0vrxTbSfXV6Od8/RUET
         k9ko6pyELQ5T4bsihHZTZgGcg3u67uApMXaDONe+YkNhZmzGCQa6CwY5jHhJ8d9Eg+ef
         Pf4qj7Z3DilT2uPq/j6i68xYL07ioV9GOyvApKLg7Jn93EO4LyP3/Az0H4iP4t78x535
         CTpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=ErbXkpB36RVKAAGnNx/7def47UusMFf6/XLd2KukQgQ=;
        b=TNMYmCuFnyyr4SVCkzJqhJipBNXq0xQ3De5Tp+uWLCTTr4wtHKXnAcjT+O4YTTEG13
         oBZeVaKFk8RKqvVpbCKkzZKwpBS5wjUnX9S4aIl6eiHEUabx7tDQP1Asm9uVyzES42xk
         nQe5pfN8N7JV2+yGA03ko7yxjQtD+sNYMOFK5kxMttUJ6V1RZv4MTW67oPvVyGuFQ0jo
         K3M/c1Wx57E60lOsVbyIsVGODf/9j9yq7bNTuLRs9UvzObNC2HalkA0AyElKzjkM9PUO
         CYWhD8Su0bRSWX1cpvDcGPN92rOhkTp9mTJTLVO1wfPHmIux3bFLHpmRu3pN7p2QYvqQ
         FI1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=sM7WD1z0;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ErbXkpB36RVKAAGnNx/7def47UusMFf6/XLd2KukQgQ=;
        b=kC4D/Eqcg1XI4oMP9ccDHj8dO1JTGjDaNIQGCZqDIBtgOu5D51M6vDwZJsROO+fm45
         5mVkZbCanfEf9DpaOIt03JLK0Bd4ZaOjxC28sAsk/q0pQbXK3NSACvWcgTpsEv71bVrt
         a6tQFW3AOdgCftkBIvFFbETgxRdfulp1bvc9ikLvA2+Ysz5+kArpOFCkzKdP4XhO39hM
         uRo6T+DCU6hosaTTuTL32YSaFty+9HyyCdFOK+x7+EE+NwO7BKTiuPMzdjYBCfdUPGXE
         vXNpztovqlV6b6V1JHnNMPQSgleoJ0vUDW6bAdBwOzpb+HTj/Q8tcA7s+D/wk7rR+Qzx
         2HcQ==
X-Gm-Message-State: AOAM5324YyUTVUM9Zwv61KhWhesam6gHB2AIMN7qIH1ZWFc0nsoq8OCS
	+pUKs0uC2zqCvyMHRT+U4Ew=
X-Google-Smtp-Source: ABdhPJxdK/VIQkK0iJXo2YbS1TmRWA9gvV9oY8bFFZ4Wfbij8A5g62YT3yTxW5SsDz8LfD2NJJNqNA==
X-Received: by 2002:a1c:bb89:: with SMTP id l131mr8693864wmf.47.1615471748131;
        Thu, 11 Mar 2021 06:09:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls5885202wrd.0.gmail; Thu, 11 Mar
 2021 06:09:07 -0800 (PST)
X-Received: by 2002:a5d:6381:: with SMTP id p1mr9160421wru.266.1615471747328;
        Thu, 11 Mar 2021 06:09:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615471747; cv=none;
        d=google.com; s=arc-20160816;
        b=NcUyK81FPXLIxSYAwyJ/opghwdtv8Nl3icnL8btReJt0Jfum919/DukKYtolEvg7xf
         bs86lPD8JWtxgObJFjAlcTVqmXiy+YIE2otnGWtrUfQapNCyPNYjERLe0SRoVSASLJUi
         p4ENYESRx19Le25CM1mc+AF0S4CVaV/ZVdZ2qpcNs9tUy/yWBIcJSSwinaDI+tAvmkFG
         w4AProg0hxbM9hyeOt6IaKx4ffJLRSqAne9X8fQ012TkU95HHb4YBZLvDOn76C+YbtTT
         XJXwYiMe4m58e3qq/aC5Ut3WLoHogSc24G18xqaLVqOEFq+arr8FAzgRKsoQZkk0CpS9
         +VZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7G9RE8ibk8Cjh1PDLSZgsGX/C//JGwxH+7KvhCZ1rR4=;
        b=bW7ySYzzDgRI9DpJ4ViuX+hA921qB3cVmmcEBww7uFT6ex+3/9bFsJA2nfIjVfGf+W
         exrQ/K3ai0+XXlCEGEdDUD9+jmvHhe3k5wIMXFhPBT9RybMRLm/cfAYtZApz3oqaxgAm
         6dxlZQldeX06mPWrm9L6VBoy70tnKDm2FSba9ROVMyGAa3L9jPkLM0RDr7pjhVk7+s/9
         TDwVAc9EtDUNPR/8AJMmVIwuu5HdCAOKSuttI5oPreLYLCoFLGGU4MRdWB2qdZIHFDX0
         83te4iTqEF4FDSqNXylJFjV7VreN+PRj6zpbMP3WKhzOwWyLcSdOdWfIDKDnyVNcsVcF
         BQ/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=sM7WD1z0;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id r11si108470wrm.1.2021.03.11.06.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Mar 2021 06:09:07 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:50770)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1lKLzt-0005cy-LZ; Thu, 11 Mar 2021 14:09:05 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1lKLzs-0001hZ-Kf; Thu, 11 Mar 2021 14:09:04 +0000
Date: Thu, 11 Mar 2021 14:09:04 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210311140904.GJ1463@shell.armlinux.org.uk>
References: <20210119123659.GJ1551@shell.armlinux.org.uk>
 <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=sM7WD1z0;
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

On Thu, Mar 11, 2021 at 02:55:54PM +0100, Linus Walleij wrote:
> On Thu, Mar 11, 2021 at 11:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> > https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/
> 
> I am still puzzled by this, but I still have the open question about how much
> memory the Go runtime really use. I am suspecting quite a lot, and the
> ARM32 instance isn't on par with any contemporary server or desktop
> when it comes to memory, it has ~2GB for a userspace program, after
> that bad things will happen: the machine will start thrashing.

I believe grafana is a Go binary - I run this in a VM with only 1G
of memory and no swap along with apache. It's happy enough.

USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
grafana   1122  0.0  5.9 920344 60484 ?        Ssl  Feb18  28:31 /usr/sbin/grafana-server --config=/etc/grafana/grafana.ini ...

So, I suspect it's basically KASAN upsetting Go somehow that then
causes the memory usage to spiral out of control.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210311140904.GJ1463%40shell.armlinux.org.uk.
