Return-Path: <kasan-dev+bncBCKLNNXAXYFBB3OU43CAMGQE65YB4MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C8CDB201DE
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:31:43 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-55b861d06d4sf1595200e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:31:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754901102; cv=pass;
        d=google.com; s=arc-20240605;
        b=iQsjBKt2D1p6+wxv5HlCMvWF3JmHXWPIPb2jye4MNu4fva30ZXmha+I9HPfI/z47Lg
         Y5UQPPTzNnHYWMbUwIc8U4+mbOfHWi6tFsETojsvuzSRGx5MaL+FakLxbGaDybnyXS+B
         ek/Ny4WxynSoPHh6Hx3gi8cJ7qykja5CUgcwAUkyXlDx2i9wuCTA3GpER2wR1dpFuWih
         bKFuHO/SyF78cmT9pgw165ObziTqf7OdzjFOEMp+c5kaF1/5fAIXGnh5gSZa3FBsa5VA
         1qXagWF04ooO2s9A6o8VDjDt/tV1WosMOLRY/IE6qWaF4GmKm1H5f37XkZmcxHKG9mlx
         TUlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ukeCVe0dmN85B0aghao0F840ppOGtkRzfLR5uzOzuD0=;
        fh=VnP03dFKT+ol6C7OUxnQ7K3/dDgf/yR8P4bjU2vxTKE=;
        b=YBfhrNPln6Bf/27/9ks/FNZPpjK7CxP1APOTmHjvyuI3S2Z6OqyVQNe/qXEhfRvKt/
         EZrdbq9Vz9k8hmtpKnQJCUk3z7IrvTVmsQneE2bz9PyHS1HXj79yonpq4ElMgPlQ6aiz
         V4rLz/595aKyWglxNuFfLE7UYVQ/W2mjFEYxB+6n1CMmMhg0SbIpK/yf9UE2sGVyE4oF
         uGcLcH+XQMznSd5xvCB5y9Wu7xjQ+88JpdS6yDLzN27o/Zo3eh5/Ld68FGD6e+uFsMpd
         ryGZwv0Dz8GK8E+WNzsgqfB/Os7BpTempUD7QDAEjNA7PPmv4pIS3F63b4Y9DdSX7ED+
         ucWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cZNO6N2q;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754901102; x=1755505902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ukeCVe0dmN85B0aghao0F840ppOGtkRzfLR5uzOzuD0=;
        b=ouMfU0YgccvqXtS3rMIz5NtFJRQsHSGlw8ZIUADmEBCU45rWE7GBuS3exdV5dWOH0/
         Z69ARv4SOqn8K4Aso+yoP0NLLjALsHrpVxCOYUfSPbZnydix+OHgiuyeOj8PsWraz0rL
         fmzoOtFV9+aQA4QozTaktk+yu0YSueGgACrL2KR7v6sXKHkCj5Rsn2hjWlUmcy2TMSie
         iEVW+BAFqp7hGoOqLKkQsup1q/RgmhvMtKRnI80yNCu+kvCg7Wn/Jyl0Q2fZ9xRAHbsT
         uB6OdifuA9jxO7PSnbaMIINDo/2aLpJFdEvCpnUZDz6vJMmeOesY3TIgJ7U9hrIS9ngT
         R2cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754901102; x=1755505902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ukeCVe0dmN85B0aghao0F840ppOGtkRzfLR5uzOzuD0=;
        b=qNpAXRVYKDtgXB6fSvn2HvTt7skQDTvpuhXiPh05tZIq/jfrWlLPC07hD7c5LPDQk6
         946hMIKccKnFDnSxtRco8f5hDJb3heVZD793mW3Q6XKX5MAvJkBABBB6LnURU7eXvH7P
         uuVVuT/eNI53qHTWd50f1w0ZegELKdCkmrDeLN+s1z6L+pZhNiBTNc6hiknCK9D+XZKw
         a2LK86ixRRBoJPJKt+LcRzgGe55o6F9k+TGCLs42/Uv3QDkPbmAuKyG4l5bXKEmZ+zvY
         iJmUbm4ZOaskLO4P3VOQs0BVf411x2ZMDJOtrfA+kWFJDgQWX756A3p2ezk8qUWCEcqW
         wogQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3f4NwV9H2dGWPwAOg0QfSVxpVcuSfBt7KfyJuQPxFSXfpkUzFYpvlEx+Py0129crwH+5qMQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxdi5+YidY+PrDBLLHei+AGT9gCuBVKjPYNMki7HduJH8WTrbqg
	+01GZX1kPYJEmIuFzPM3KRmZs6y3+YBKjcNDdqSvtF7JuMuxM4KmpRwH
X-Google-Smtp-Source: AGHT+IGt4TsSQf91lxPEHCY9Ok6ecCawbs3SUOW2TmClt4zfzhm3xYLpY56/sp0wyNCvHMatP8HYsw==
X-Received: by 2002:a05:6512:61d0:10b0:55c:c937:1100 with SMTP id 2adb3069b0e04-55cc937152emr1272435e87.10.1754901101909;
        Mon, 11 Aug 2025 01:31:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsbFo5igYWD7zWytZOyRnNRDzICvKquYCHddCHIs6lRg==
Received: by 2002:a05:6512:31c8:b0:551:ee0c:ec5 with SMTP id
 2adb3069b0e04-55cb626cefcls848543e87.2.-pod-prod-00-eu; Mon, 11 Aug 2025
 01:31:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9YjIFyK0EOuKIdVisU5y5jmLwFDRHiFP2c3fLi2DwaIwiqY4IJbABTXSr/CuO/xHlOrmb+5aMBjs=@googlegroups.com
X-Received: by 2002:a05:6512:1289:b0:55a:51e9:cecc with SMTP id 2adb3069b0e04-55cb60c6973mr4359800e87.17.1754901098210;
        Mon, 11 Aug 2025 01:31:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754901098; cv=none;
        d=google.com; s=arc-20240605;
        b=Y/XMNECH67FPP3x7GS+JiJoNI6pIhbsuWN4oMjKtAbJjZPGSRBwFOC3vBvO1lKLs4+
         U1WKxe602I2+/obhbJG2EICJzi+4c8PRn2CwqEKyNWr/YwVF4tcr2dOLINPeg8TNhaDn
         DeGlJMFV8OmxNTf59ndvs81hdHCKY/k6XzJ6EWglA8UxUcIehjonwb3xmHhFOO7Ej3wz
         IhGLKg1y3cgjBIRosCLOqpL/ya4vdJgdAk6eShOnwbyIREsieQv3NWQrbeYu1wmui/kQ
         zBicYtzBlpTEzhDvgQAUacuElJWLsa3H/jelllAXS0FdtqNNym65aEMZOk1eWKuLVG4+
         wUFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=JeEYEDHr31+P2zVZyryZ2NEbaRwQuOh+nfUwKPEWE1U=;
        fh=DiywWmPV2ee2na/P7pao6StAFdqF8/4vgmQELu4Z2cc=;
        b=N721Xk53RtDJEJCMY5PB7FGz/JPzj/qHM/T69qGlRuw/h40stQWUx0yL1bTc9OD7e8
         UhQJhumNlu8Zqfq0aLnjRG9qAeDajXdKSRkbiglu4iNBBKWt/VGbp8ZnYQGcmBYr5w3S
         bFgcOtU0dZQqk1qNtz48lLPeHwBtVjVXhglIgfInNTOCKCmWJwVNq5D+ytIqyWzbARAf
         KL5ePWVpkV5fmfe2xwAuzIbIa7vIp6jQIJ48NiHXDA8DHWL0/REer4JGOXfq/4HSctxp
         X69+sOcGb/rTzZXxXt+9Y0AyYUgKPXG2uJrzw6LHiOMBP3V5pxeZRXVGq2Rs1LqhBVRi
         fhdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cZNO6N2q;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8895b6cbsi655405e87.7.2025.08.11.01.31.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:31:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 11 Aug 2025 10:31:35 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Thomas Gleixner <tglx@linutronix.de>, stable@vger.kernel.org,
	kasan-dev@googlegroups.com, syzkaller@googlegroups.com,
	linux-usb@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	Austin Kim <austindh.kim@gmail.com>
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
Message-ID: <20250811083135.xtl2wSQz@linutronix.de>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <20250808163345.PPfA_T3F@linutronix.de>
 <ee26e7b2-80dd-49b1-bca2-61e460f73c2d@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ee26e7b2-80dd-49b1-bca2-61e460f73c2d@kzalloc.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=cZNO6N2q;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-08-09 02:35:48 [+0900], Yunseong Kim wrote:
> Hi Sebastian,
Hi Yunseong,

> > Could someone maybe test this?
> 
> As you requested, I have tested your patch on my setup.
> 
> I can check that your patch resolves the issue. I have been running
> the syzkaller for several hours, and the "sleeping function called
> from invalid context" bug is no longer triggered.

Thank you. I just sent this as a proper patch assuming kcov still does
what it should. I just don't understand why this triggers after moving
to workqueues and did not with the tasklet setup. Other that than
workqueue code has a bit more overhead, it is the same thing.

> I really impressed your "How to Not Break PREEMPT_RT" talk at LPC 22.

Thank you.

> 
> Tested-by: Yunseong Kim <ysk@kzalloc.com>
> 
> 
> Thanks,
> 
> Yunseong Kim

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811083135.xtl2wSQz%40linutronix.de.
