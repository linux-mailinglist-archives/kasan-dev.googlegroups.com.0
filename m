Return-Path: <kasan-dev+bncBCMIZB7QWENRBKOJWCZAMGQEAEAS3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DE168CA769
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 06:35:54 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-522297fc4d7sf9352416e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2024 21:35:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716266153; cv=pass;
        d=google.com; s=arc-20160816;
        b=CIPs9Y2N++Agw2mZoZEQBJporuXsyVuVtYhKjfGY5ucKRVZMveO2wMlr5NRJ+v6Gi0
         lpQd5lwqmckH9EyplRzn+GwWLMV3RriyXjdqVwYrauO7GB6O+uP/+oKBB9qA7aoOXVK7
         4joHnfE/ZzXvUvKfr8BGGFJ5S+DpT7KJ9VG6z0kAhAlNAQC+CIuwQMNfNMG/eoswSFaM
         7nGQ2YkPARFNBfp8p5WLLtMgBiNU7SAUjgsBoLtzwqsqsIvJ+z/X2BFXK7rUBZcrhDnk
         lG5qZ6svlCoK7vBdxaJMrScLmAZ11559S51gelfw8abcM2iX4c/IPeZytkBg2PAhz/ZF
         kNlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oJpXAaccC6TYdIhZPPQOVEk+cRxKln2UaSb3DNjIi8U=;
        fh=OUucjm7bixLXqoCjuKVLqPueRcy0DGll57F6e/A42Ek=;
        b=ZKCzG4qC2mZCK9s73fDnMfOIoyYaduj74qQMq/1UZ1i7JuHRXBNEIgh1/F9FuQqPQM
         IqiiC1r6PRvnv0kaNgnS0vSxBPA3a2YojctMHrAMelLbfGBzc92oig06FxQBYwVaQJWU
         3HmNr7zdIAjqolT70EXVWTngUu2OK+ep8KBWzaFEj1zBGPGm8OnOKowDwMPZZ1bw+0wl
         j7NAlDiEusPFKjIZn4uem5kg2gBiOPzX9PNlVIoMeVUtXUvanHVHg7A8C2ZvKeQ0Bz/C
         l0tWXzI0+jJUNywR0HLdVeZ8/nzQJWaWXjos7njg/t0Cl4DxO8YhDHzL4XstBgjXk34c
         mpzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BjfbV9kN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716266153; x=1716870953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oJpXAaccC6TYdIhZPPQOVEk+cRxKln2UaSb3DNjIi8U=;
        b=tNbD8nMvRpOC+e4YDEN+I58We2X4ZlLPEU/nraia+oNKnb/9tnrPrYdCOsJlBtKwiH
         YqF4Xobx0uLd233qMGNmmqmA7Bhpg6Hl2SZs0q8oSQvTfDV76wHH/YqN8xSbjxGw2BIG
         0CYQcqOCfEnK6UUHcUfn5SWFhiQ7ZBdkveVUVywZr8m/DnqaEVABgk1LJ/LfDoC0IV2M
         hoptYY1o2cDHeYFj/ym7c7LfOhap76FZhJQMZEZii/jRXuC/mROzoUDdTkRS234btiAt
         yMPRjQSnUxlddpDyM4hvrTaJWQS0ILCAw1CpjB6dO8bndi2AS6G/FZdSD8qGJ9h8XUPO
         kUeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716266153; x=1716870953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oJpXAaccC6TYdIhZPPQOVEk+cRxKln2UaSb3DNjIi8U=;
        b=imbNaKxqzeuOuEYhD9s3jW93SDAWCd9BT96g17G5oYeWLktCm7ZuCtWg5GovRQJaV6
         eTYnWbwjD+7syb9eiflZI11yl0gmMIT+ZcUUzgcgK2VcUby25pdsQtuHRGMIs3x7uYrC
         JTX6gDddGQI/liRD2YH4Jd0KH6SI9KrVIFGSBIijoWirgcXAvhUxWl0c1guxfs+WxUlB
         F4jK2KRtLH6EryBSjLby755Z3e5GLFfwJdHTzh6ir1SiF2iA1qVD8HAalLwFBZT3Xgv0
         cmTzZbvUcSX1oFcfRI2gbqIFzgEhW5bHhUSxc5oYOsxWfl6KLsAVc1Xjlc0eGVRP+dzp
         NqIA==
X-Forwarded-Encrypted: i=2; AJvYcCVzkJaYTC32WuEn4ANlbLuu2bL5kUpU4EcqgT8DngFWKhj9VJ+wLQkn1+OyGgeJF+LVVZEKhoIOyqG8MAw8AUfZfx3hb1JZEA==
X-Gm-Message-State: AOJu0YzKuyRChXFuwfm/JuMypMxJAyNdf0sTr6w/PbgqCmrcKzMUBuFe
	uKGpKAyiJKZN5W1ljQvzDqSnq+Pwdcx7SurvSQ0ypX01p2cCh7tC
X-Google-Smtp-Source: AGHT+IH9krA4V/TowkmP0Lg5WPWyv4yKTDCk9SOOHTECzHlyVqqvnIYeRNQyCGzhFvDmDHusJYLNeA==
X-Received: by 2002:a19:4358:0:b0:521:b42f:2674 with SMTP id 2adb3069b0e04-52210277c35mr23685660e87.63.1716266153330;
        Mon, 20 May 2024 21:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b06:b0:51f:4af2:4680 with SMTP id
 2adb3069b0e04-521e4433dd8ls1183350e87.1.-pod-prod-08-eu; Mon, 20 May 2024
 21:35:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUs1uw+WveInxLVsO6fkAG4TGi+eq7rn21gSWt9Hw0dqgv9idah/HKbXkSgRVqhuDUXwjfU1kIVjpzENzeJp+yNifFukeINTSjhtQ==
X-Received: by 2002:a2e:751:0:b0:2e6:8b17:ca10 with SMTP id 38308e7fff4ca-2e68b17cd3bmr201790191fa.13.1716266151057;
        Mon, 20 May 2024 21:35:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716266151; cv=none;
        d=google.com; s=arc-20160816;
        b=T39YDCNX/rMFNW+IsCLaNCFGS6V6C1n7ncGO24FtnTGoL3Ck9g01WD4CrFXNM5+JOZ
         OwET0ikLaPygxOh5uRnbyURca04MGd+7g0OY/q0XRk4DakVor+DaZAYFd8gfCs1WJYst
         fZmzAZjizCc1sQLBervh+tzmP33iiVA1ePGwO8USiEaZ31O2aFtGA8XTNFnmQmA6v/AU
         gmU9beLKN+ciyajElvtZWPS3zA3U6uiWn04Kj1IZNnTWSGn8qBpR6l566xML7CT/uLh+
         2GAI0LJPsIqCt21SnNEfHB4Oi7mJDDDvhkJXGwZ/rIp8ojbg/xIaj3LRWoqHsH43kx8k
         fSMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bu1zy9E7az32y56EOjWw+O7OSWd3qh6SwlhX3MCkEJU=;
        fh=gYGfd3JCa9fTM8MP1eQ2zFbvF0bNfbGEBJPrE8xlIDc=;
        b=BY2MkE2Akp2F/2ym10ZIhII4uPx7z0yW+amrSTBbKoaLC5BrZiWQ5FMQ4NbIO3Vy1p
         obfOf8X9dUvps0xgNKFx3Ixxs9CYKkPX+D0fwpc5gUQEz/nMY1aYAjnGLOO0D9ORoBpg
         NVpbTuDhQMBfPmL8jwVmJMXimPPOAmpjLmPwOkGDY8fulylVe0mYYEDNF3ZOsF5Vsrq/
         d4MMZx02jmVOhKllYjJ+lSce3fo5vQR8P5ZE8EzFcy9HquKNnvs6t3ZZHQ9rTQozJ6JH
         zCH7LQEhpuFPWCcn52HoiJW62JpRSAb6F+0x2ODLc0jiu6cG74fHuGzkWdZ38h7cMj4f
         Dggw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BjfbV9kN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-41fcc411c0bsi8282385e9.0.2024.05.20.21.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 May 2024 21:35:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-51ab3715d46so6455e87.1
        for <kasan-dev@googlegroups.com>; Mon, 20 May 2024 21:35:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXeSzeT73RR+rPwlKCPVrYg5hGnO+oqBDSCIPLiWP0zAgcZ6KSLHw4Bj6iZMSQV4jF0Z7hJ2b2EBktr6cs0tQ1k2LCK3bkNXJq0pw==
X-Received: by 2002:a05:6512:3a9:b0:523:69f8:ead with SMTP id
 2adb3069b0e04-5240a1004e9mr297353e87.1.1716266150078; Mon, 20 May 2024
 21:35:50 -0700 (PDT)
MIME-Version: 1.0
References: <20240520205856.162910-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240520205856.162910-1-andrey.konovalov@linux.dev>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 May 2024 06:35:37 +0200
Message-ID: <CACT4Y+bO03Efd48XW7V6F2D9FMUoWytV8L9BL8OK2DR8scJgmQ@mail.gmail.com>
Subject: Re: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
To: andrey.konovalov@linux.dev
Cc: Alan Stern <stern@rowland.harvard.edu>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Tejun Heo <tj@kernel.org>, 
	linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BjfbV9kN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 20 May 2024 at 22:59, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH
> workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
> interrupts enabled.
>
> Thus, the remote coverage collection section in usb_giveback_urb_bh()->
> __usb_hcd_giveback_urb() might be interrupted, and the interrupt handler
> might invoke __usb_hcd_giveback_urb() again.
>
> This breaks KCOV, as it does not support nested remote coverage collection
> sections within the same context (neither in task nor in softirq).
>
> Update kcov_remote_start/stop_usb_softirq() to disable interrupts for the
> duration of the coverage collection section to avoid nested sections in
> the softirq context (in addition to such in the task context, which are
> already handled).

Besides the issue pointed by the test robot:

Acked-by: Dmitry Vyukov <dvyukov@google.com>

Thanks for fixing this.

This section of code does not rely on reentrancy, right? E.g. one
callback won't wait for completion of another callback?

At some point we started seeing lots of "remote cover enable write
trace failed (errno 17)" errors while running syzkaller. Can these
errors be caused by this issue?


> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Closes: https://lore.kernel.org/linux-usb/0f4d1964-7397-485b-bc48-11c01e2fcbca@I-love.SAKURA.ne.jp/
> Closes: https://syzkaller.appspot.com/bug?extid=0438378d6f157baae1a2
> Suggested-by: Alan Stern <stern@rowland.harvard.edu>
> Fixes: 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH workqueue")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  drivers/usb/core/hcd.c | 12 +++++++-----
>  include/linux/kcov.h   | 44 +++++++++++++++++++++++++++++++++---------
>  2 files changed, 42 insertions(+), 14 deletions(-)
>
> diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
> index c0e005670d67..fb1aa0d4fc28 100644
> --- a/drivers/usb/core/hcd.c
> +++ b/drivers/usb/core/hcd.c
> @@ -1623,6 +1623,7 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
>         struct usb_hcd *hcd = bus_to_hcd(urb->dev->bus);
>         struct usb_anchor *anchor = urb->anchor;
>         int status = urb->unlinked;
> +       unsigned long flags;
>
>         urb->hcpriv = NULL;
>         if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
> @@ -1640,13 +1641,14 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
>         /* pass ownership to the completion handler */
>         urb->status = status;
>         /*
> -        * This function can be called in task context inside another remote
> -        * coverage collection section, but kcov doesn't support that kind of
> -        * recursion yet. Only collect coverage in softirq context for now.
> +        * Only collect coverage in the softirq context and disable interrupts
> +        * to avoid scenarios with nested remote coverage collection sections
> +        * that KCOV does not support.
> +        * See the comment next to kcov_remote_start_usb_softirq() for details.
>          */
> -       kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
> +       flags = kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
>         urb->complete(urb);
> -       kcov_remote_stop_softirq();
> +       kcov_remote_stop_softirq(flags);
>
>         usb_anchor_resume_wakeups(anchor);
>         atomic_dec(&urb->use_count);
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index b851ba415e03..ebcfc271aee3 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -55,21 +55,47 @@ static inline void kcov_remote_start_usb(u64 id)
>
>  /*
>   * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
> - * work around for kcov's lack of nested remote coverage sections support in
> - * task context. Adding support for nested sections is tracked in:
> - * https://bugzilla.kernel.org/show_bug.cgi?id=210337
> + * workaround for KCOV's lack of nested remote coverage sections support.
> + *
> + * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi?id=210337.
> + *
> + * kcov_remote_start_usb_softirq():
> + *
> + * 1. Only collects coverage when called in the softirq context. This allows
> + *    avoiding nested remote coverage collection sections in the task context.
> + *    For example, USB/IP calls usb_hcd_giveback_urb() in the task context
> + *    within an existing remote coverage collection section. Thus, KCOV should
> + *    not attempt to start collecting coverage within the coverage collection
> + *    section in __usb_hcd_giveback_urb() in this case.
> + *
> + * 2. Disables interrupts for the duration of the coverage collection section.
> + *    This allows avoiding nested remote coverage collection sections in the
> + *    softirq context (a softirq might occur during the execution of a work in
> + *    the BH workqueue, which runs with in_serving_softirq() > 0).
> + *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
> + *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
> + *    the middle of its remote coverage collection section, and the interrupt
> + *    handler might invoke __usb_hcd_giveback_urb() again.
>   */
>
> -static inline void kcov_remote_start_usb_softirq(u64 id)
> +static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
>  {
> -       if (in_serving_softirq())
> +       unsigned long flags = 0;
> +
> +       if (in_serving_softirq()) {
> +               local_irq_save(flags);
>                 kcov_remote_start_usb(id);
> +       }
> +
> +       return flags;
>  }
>
> -static inline void kcov_remote_stop_softirq(void)
> +static inline void kcov_remote_stop_softirq(unsigned long flags)
>  {
> -       if (in_serving_softirq())
> +       if (in_serving_softirq()) {
>                 kcov_remote_stop();
> +               local_irq_restore(flags);
> +       }
>  }
>
>  #ifdef CONFIG_64BIT
> @@ -103,8 +129,8 @@ static inline u64 kcov_common_handle(void)
>  }
>  static inline void kcov_remote_start_common(u64 id) {}
>  static inline void kcov_remote_start_usb(u64 id) {}
> -static inline void kcov_remote_start_usb_softirq(u64 id) {}
> -static inline void kcov_remote_stop_softirq(void) {}
> +static inline unsigned long kcov_remote_start_usb_softirq(u64 id) {}
> +static inline void kcov_remote_stop_softirq(unsigned long flags) {}
>
>  #endif /* CONFIG_KCOV */
>  #endif /* _LINUX_KCOV_H */
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbO03Efd48XW7V6F2D9FMUoWytV8L9BL8OK2DR8scJgmQ%40mail.gmail.com.
