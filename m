Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNJTTEQMGQEXGXLOJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D76E8C8A787
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 15:55:07 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-7be3d08f863sf11387235b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 06:55:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764168906; cv=pass;
        d=google.com; s=arc-20240605;
        b=NhKQ96icR8WxJbBGfIzG9+6B+2FU1t6p54+RAgtagdaYVNlbsxT8tqGNm/WGrThUKX
         n9plSrZyLlPcskWrNs+eLdI9xUrPnHKS/hRiyJadnYi0qmOeeY/Uk0FL4qbSYEd9j2W0
         Nik361mrOamuOTLMMDT1hMpD4dasBWor9XgjcQEpBR78hOLZUjh5RDakKfGMTefFWTv5
         opWAyoSynv6t3jfnevP+3WuM96D4Nzkuno8Lkvg4N9uZhnLpeiu8Pcszf4mmnFM0pacf
         cnjEUR8ypspUF/ALJLdfrsnNJKMwtYHeqn1GnGgXJKyAHqCiSsf4aynD6GOheKQShTlV
         ogyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SB6r4cSHKdSitBIWvIPUiPNJ98UZZepIv3mU3FfI+Fg=;
        fh=RWb9/YBdt/PU7Wgp28rD5C/edUk2Q86bxrZLlvnyYvU=;
        b=Yyj/JBJ54WXr+8GGcZV+xk8rYcvPnUuHTmHnZpo8k84p9BaaSbQkIcBk95fHvPC93J
         oZO5ARgXV3HtmfadxbBMZ0DMrCzRFyMtYm9T++dai5CkfQYRFWXsoPqq3/iFTNs5yxxe
         7bsBjcafXitnE25Hoz04pJUjTYw7rEdEuSlwdLxL+sNdOxu8ZwR5HiC7cEbjw9jVTd4s
         c8UnLdn/oWGz2JL2FOHGten+8bje5ND+0DCnKqpmxRAiWMdhtu9nCNNSvum3XqmF8EWn
         S5O2O079HUJyD9gTHs54zCWH6xmerEdnNJ497RN687R0vkPWZdXcBEIWva4dL2qKH+qa
         wrbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2QcychmC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764168906; x=1764773706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SB6r4cSHKdSitBIWvIPUiPNJ98UZZepIv3mU3FfI+Fg=;
        b=JTW/2mpe7CF9RwKakxphgG/ADbOh9EjrKkCJ3d6dOq2YwowL2oHMxekhmui7yz6Nvp
         //Sb53BkoJN13355mZ4WOCw7vQdOMHk+eKW4tSmiZf5VZz1xkfpSlpklEhZsoQZxBDct
         RPdseovVzKz3nhOsnyIyMRVNzux41pTqRq4h8ZRmBAAEATjwRuxUNbI/RKYl1bp9TL9d
         dTZm5ZTROxrbLfA2ABoHbqZOdOJWbefB4ueHG3SanAToW76Nu1B3Irh5RK7fvfIwh+hT
         terBDqm7NHlurcWGcEHqbrAWVSgtMxWPFWMSwNKN8tHiibURReGWQTFj2nSb8Ha+rgPU
         U+Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764168906; x=1764773706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SB6r4cSHKdSitBIWvIPUiPNJ98UZZepIv3mU3FfI+Fg=;
        b=MvgBM1n6qWYUPonR9P+EPkzZaxA/L1y1vFVSYwI/l2SNyBChbf2aXbN1dTvG2yNfGd
         XFNBHF1AQNhGs1Po6W7rD8zkS5RS4TxWOKmGCedmwSMduQLmg1Mf9g0rKH0ey/aqXVTv
         s0BvXVWyL1r1cZywZsiVnY3QN+fl0xm4+ffAGPOLbLUeAphmgEDForFVn6l4DgpOU8GD
         dNBnF5WJhJameNoCBPzsoAZhszobxNvCfSbpcs/LyuoTx1dxPVg3QHweQH1b67pvi5+b
         KsjyYq+eMIzT0wTSgfjd46HzWwI/WMYfT+o1RGLMZHeYyNq4vdIT88gqZkEzHcnBEkBw
         dpfg==
X-Forwarded-Encrypted: i=2; AJvYcCV3QDXOgyF+z6LXAsvlc99cVPR6cwa8yoe1Sucwi2BW0d1oOGSbDldXBetv1Hra4QgrwQ2GEQ==@lfdr.de
X-Gm-Message-State: AOJu0YzeMJ6QTxWvgLqGYvV2hzXWG/xbVFTt1w8dZHht1NVZkI9IWV2t
	Im0opy4660vVqGYPcHpeY3PZwCwos9qCgSA5bFFPqENoPKVCOkqF7JP2
X-Google-Smtp-Source: AGHT+IG9l99fmpDqjol45/hJjF/yEydh+UV13B1O7hcYw2mbr5dVc02ej0aiwUxcP94WHpxH7xAdfA==
X-Received: by 2002:a05:7022:b9e:b0:11b:9386:a3cb with SMTP id a92af1059eb24-11c9d872a83mr14357306c88.44.1764168905531;
        Wed, 26 Nov 2025 06:55:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bhSKNK9p5+i4yCv5wo1Tjxdf1ScI8zrP7nmcOmMA3DZA=="
Received: by 2002:a05:7022:628a:b0:11b:e4d5:d8c with SMTP id
 a92af1059eb24-11c93bc538cls5588767c88.0.-pod-prod-01-us; Wed, 26 Nov 2025
 06:55:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUpKPM2Xigutdy33EAqtWcii+nIfuu6pcgNDswHqxdWatcEe5RgGrnVbl7mb+A9UK3rDjeVuMwTwBw=@googlegroups.com
X-Received: by 2002:a05:7300:c8c2:b0:2a4:3593:968c with SMTP id 5a478bee46e88-2a7190a5c1bmr10558598eec.9.1764168903765;
        Wed, 26 Nov 2025 06:55:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764168903; cv=none;
        d=google.com; s=arc-20240605;
        b=NJ9h6dIZBiNvzXKg8S86BRRH5r7xPPreTBMzvHcspJz6LGjyAOkm0nRJNkKss3xutH
         X6nC+GM2SDiEbWpqeUOS5b2ZsoFVs1ITuSPt1qswWy061OVCB0iCZyQrOjXgrb9ArFjE
         JTdnQQh6dq/G+BKVYjL9Hb2x+8RNxKUtP3h2uIKi2/w0zZ1dBONYs/XuVzdNL2k4BTaK
         ff4davvG+OWSA19pWQDo5xEVyWvkJxD1kcA6RgjLuQdiB4eX6oux3bHZuDCM2WaGYW7e
         m0pS0pGz4pb/eigb4IyRxl0MLX9YB+zrOWwIDtRPMrGeMyZagPAgJCQ788o4BWKfTFTC
         SK0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gMAlKyQZ4W1o56NI0K8gYAmxYW1legwujSD4ppPGA7A=;
        fh=vv+kcaoj5inGin6FuN2JPoVUhSPHhk9sGizkyPb1WLU=;
        b=MYjWsz45HzWaDxi+IoFdHWzUgVM+1KCiudlnF5fnz4LCsPIMTd9n+CxP1XzVF0xXZB
         Gy4DQ9zdaS5qHTu4gQeKnx4+B7W0Q1w2NguA+LjlkZhyPUP/eBsYDQXGmTS621gXzcdH
         biUswAjoyMJWa/3x0Ev3x4x/kqwFhJ9pREPk7O5WZGwjaFsRSRBDdn/9E3vFoxJIERhB
         pgO6Qg94/zvlClflSJOCzEiMnCaBOcFsdX8vEjsT2FoyETN+wJDl5HnLo6Xq6td3P0co
         VT26oJuqNkKeZGhBQbvEPymkmyteozaIyZZFoObE4zqs1B5U/Q1YfdirpakCw1aLC5jI
         CIXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2QcychmC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2a734924e18si133659eec.1.2025.11.26.06.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Nov 2025 06:55:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7a435a3fc57so7121893b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Nov 2025 06:55:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW7psZ4vf4nIWDkCCAwqiaiHbiqjGDpQbDB3j+cDfLaiuNkvT6vzipkBMaxtWgLOYIaWa7cJlkwGLU=@googlegroups.com
X-Gm-Gg: ASbGncuBTT7S2Nw5bio9q9coTkOGN9vv1GkNzZFqyivTgaQCfLmpzez+M/BjqzGk91K
	K2eheO3flmxzKg+/jCqmQn+DmMyw3W+ZV+2kijrmAgp9tbmRAdcaxS0c9UF6rCekn3wlNaDTJjp
	ZlzNg5WRBkhnjupcSGgJqMYW3CohdHdgB0TPpurGwRLA83nUuw7X7HsOcSJDSM4n8V5WSKbktVb
	/nvSylGIJU/7otVtFKMSsYSdg3/ZBQIGBweAXNaHuYxbh+I6giBGTJo+ZVpGmH7+otVPonvbEIv
	QvKqUS0cKsVRI/6uHsydYfPiX3c=
X-Received: by 2002:a05:7022:690:b0:119:e569:fbb5 with SMTP id
 a92af1059eb24-11c9d864eebmr14056160c88.36.1764168902698; Wed, 26 Nov 2025
 06:55:02 -0800 (PST)
MIME-Version: 1.0
References: <sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu> <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
In-Reply-To: <k4awh5dgzdd3dp3wmyl3z3a7w6nhoo6pszgeflbnbtdyxz47yd@ir5cgbvypdct>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Nov 2025 15:54:26 +0100
X-Gm-Features: AWmQ_bkdcQGpEywajea9M9MaObnxb3B6H0v13jPKgL3UpjH7060tA1EcV-cDw3g
Message-ID: <CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM=7QNJ02GMFG7BMeOGA@mail.gmail.com>
Subject: Re: CSD lockup during kexec due to unbounded busy-wait in
 pl011_console_write_atomic (arm64)
To: Breno Leitao <leitao@debian.org>
Cc: glider@google.com, dvyukov@google.com, usamaarif642@gmail.com, 
	leo.yan@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com, rmikey@meta.com, 
	john.ogness@linutronix.de, pmladek@suse.com, linux@armlinux.org.uk, 
	paulmck@kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2QcychmC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 26 Nov 2025 at 15:13, Breno Leitao <leitao@debian.org> wrote:
>
> On Tue, Nov 25, 2025 at 08:02:16AM -0800, Breno Leitao wrote:
> > 6. Meanwhile, kfence's toggle_allocation_gate() on another CPU attempts to
> > perform a synchronous operation across all CPUs, which correctly triggers a CSD
> > lock timeout because CPU#0 is stuck in the busy loop with IRQs disabled.
>
> I've hacked a patch to disable kfence IPIs during machine shutdown, and
> with it loaded, I don't reproduce the problem described in this thread.
>
>         Author: Breno Leitao <leitao@debian.org>
>         Date:   Tue Nov 25 07:21:55 2025 -0800
>
>         mm/kfence: add reboot notifier to disable KFENCE on shutdown
>
>         Register a reboot notifier to disable KFENCE and cancel any pending
>         timer work during system shutdown. This prevents potential IPI
>         synchronization issues that can occur when KFENCE is active during
>         the reboot process.
>
>         The notifier runs with high priority (INT_MAX) to ensure KFENCE is
>         disabled early in the shutdown sequence.
>
>         Signed-off-by: Breno Leitao <leitao@debian.org>
>
>         diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>         index 727c20c94ac5..5810afaaf6b4 100644
>         --- a/mm/kfence/core.c
>         +++ b/mm/kfence/core.c
>         @@ -26,6 +26,7 @@
>         #include <linux/panic_notifier.h>
>         #include <linux/random.h>
>         #include <linux/rcupdate.h>
>         +#include <linux/reboot.h>
>         #include <linux/sched/clock.h>
>         #include <linux/seq_file.h>
>         #include <linux/slab.h>
>         @@ -819,6 +820,21 @@ static struct notifier_block kfence_check_canary_notifier = {
>
>         static struct delayed_work kfence_timer;
>
>         +static int kfence_reboot_callback(struct notifier_block *nb,
>         +                                 unsigned long action, void *data)
>         +{
>         +       /* Disable KFENCE to avoid IPI synchronization during shutdown */
>         +       WRITE_ONCE(kfence_enabled, false);
>         +       /* Cancel any pending timer work */
>         +       cancel_delayed_work_sync(&kfence_timer);
>         +       return NOTIFY_OK;
>         +}
>         +
>         +static struct notifier_block kfence_reboot_notifier = {
>         +       .notifier_call = kfence_reboot_callback,
>         +       .priority = INT_MAX, /* Run early to stop timers ASAP */
>         +};

Just place it under the #ifdef CONFIG_KFENCE_STATIS_KEYS below, I do
not think this is required if CONFIG_KFENCE_STATIC_KEYS is unset.

>         #ifdef CONFIG_KFENCE_STATIC_KEYS
>         /* Wait queue to wake up allocation-gate timer task. */
>         static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
>         @@ -901,6 +917,8 @@ static void kfence_init_enable(void)
>                 if (kfence_check_on_panic)
>                         atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
>
>         +       register_reboot_notifier(&kfence_reboot_notifier);
>         +
>                 WRITE_ONCE(kfence_enabled, true);
>                 queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
>
>
> Alexander, Marco and Kasan maintainers:
>
> What is the potential impact of disabling KFENCE during reboot
> procedures?

But only if CONFIG_KFENCE_STATIC_KEYS is enabled?
That would be reasonable, given our recommendation has been to disable
CONFIG_KFENCE_STATIC_KEYS since
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4f612ed3f748962cbef1316ff3d323e2b9055b6e
in most cases.

I believe some low-CPU count systems are still benefiting from it, but
in general, I'd advise against it.

> The primary motivation is to avoid triggering IPIs during the machine
> teardown process, mainly when the nbconsole is not running in threaded
> mode.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOsSmKUxrLxTWYMD3RKnzSw5dfM%3D7QNJ02GMFG7BMeOGA%40mail.gmail.com.
