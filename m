Return-Path: <kasan-dev+bncBCO3PDUQQMDRBFPNTDBQMGQE54JXZXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D3ED7AF6C08
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 09:51:54 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-553b94b73d6sf2965029e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 00:51:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751529112; cv=pass;
        d=google.com; s=arc-20240605;
        b=XXa0htc6GoP+m0YTbcb5dpWrlbju/VetjDjSc5FCoQW11A03QsOIUUZMKlI5XHZHlw
         ZTh1Hyg5bzul7QGaz6rla+c+nEYOBE8IKHsodFGdt3tAYNOYJNp0ZPyg8CsZJ0cXLSIi
         KsBwtJzUDU211omk1AOmPWC9A0Nz17rZrRK6sP2lE/C84jd8dvOaC+AN3bAHyjEiQXMg
         4mxAW1zj6nkNKMWqadGYSPs9DyueIdSRyeV4ARKLEJ0yuaqP7JrVddcC41wr+dQl7aYr
         cAWkZnYXDGNnhH8bWmHRxeygUbEffV4jg8xK0HTffbotfY6SaDOs7EHb/Dlv4XOT1y0s
         kroA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=pUvFKtJvaaFASZp8BkgA5m1GcxSwf3lZ+/LRFg6m3lw=;
        fh=lqWuRon1nAkH/uR8Z/MYghsawvHirxamAe54QXbrPQQ=;
        b=XwiuGl85x3G5b98pypGG/4PwH5DqSAyDkr9DQmBltmjdPRCb88oC/JaPAKi67MjYUX
         C8u9IJNYeX347zkH2VaKrFR4XMMWUDAg5P1rVewaV0uV3x4yz/uSV3Xg4izb1nkIoUSv
         J5wshXlhOQ8BhA+h7eTzxtxEXY19w/262UCvSG0aaipuFsk4IY3d1sVVxQcklSLVdtZO
         XaTPDpIb3guO75Vq6ngWQ4Ujp8cnzeE/Oy8MhqOxKjVlicNeB9Lh72t+vLf/j0SvzWbG
         vagqBgK5z3tmBnYBDx39Azi+rZsbJ/wUijjD3fBcwTTClQj7LjeiTILLe4hx1eypRMGn
         EP+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CLgpQZAy;
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751529112; x=1752133912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pUvFKtJvaaFASZp8BkgA5m1GcxSwf3lZ+/LRFg6m3lw=;
        b=EugeLRbaAANkarKnXJ3ciMVqmsc3wOa17clTZpP1pj3c/urlP8KY/83qeBfsaUp7bY
         /rFrj7Dvb/Q7bF/sKlCQtuI22BtLsK8SEsPqaujeKTp3XimPU2RMYihw/b/Qa9Q0LowP
         2ME9fiRd25nPs1WEfl4PiKO8/vkz/b7GsnFsHB7BzXDNuBsNYfvdwcUh8yAaTZ9oLXW7
         Vtz44pDq9BWIdmUBX4tZ9d38eX7kuQVj+O5+3FFLYa9kU1ojuJl4CCyn9EPaBRHJDl0/
         1MlRkedwlkK5WbcyGlgogvBjTsjV9QXvN2GxQ27ELIMJI4J0dLROp98jTVs39jedkaKP
         0/lg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751529112; x=1752133912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pUvFKtJvaaFASZp8BkgA5m1GcxSwf3lZ+/LRFg6m3lw=;
        b=Dh2S83IK+LLhovOfAjjKZY3c89vVCGpwgaPjnz8Kpg6kLD90iJQlYOiO5ZJQLS/nNu
         vKdbxgwJB+3dNS8EfKyNzXm/Rc5aj5gcqUTwg44ciFEXnI++f7/jz2zR5yGYrNiKho+t
         vFWT+3nsocFQWSSTV18H+uNcqb/u7oYDv7BISmOW50aLhXVX4IZJfjQSls3rRuLZpczH
         Vcca3x4R+MYJSPa/5VgKhbB7VEhPLXFlZfjzpdbg2/xlpdgASemg4z8CXAVzRDAsfbaC
         ZulKbu0gz/UxjulNKo2AnEVgOrdbkpE0qTaG850+TksFJvd+YXTUjcNCY80uacqgoUDJ
         6xaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751529112; x=1752133912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pUvFKtJvaaFASZp8BkgA5m1GcxSwf3lZ+/LRFg6m3lw=;
        b=nxyWmOH8Mh/NdDLObZa9qraRgBKKeOSdjOMH7l3e2JN0ypXsRwkdA7sd5ygHC75/zi
         MjjEseKTe3KqdTob/57gLwMKo+R4l6k7xQVsY+27TpyBgLeRgKruURIBmm6t2CB64Krl
         oaAn+fcpbco//ua69LcPl4fZKlteenqutrF/E2ieyYY3GD5Jb7OaJYi+GQ7wINzEfcRl
         LEC82b8pCdVRYkJ3gYHScUMlgRMIHhdepsneG8m85RY6fgaw8yiXI70z8V1Iwz8HvZLT
         radoRDt+G2JQM4z8LNSdry2qA26xla6UXIw1AHA+rt9qt8pNYeCv2crJdYbwpIAzSkgE
         qcbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6sQFUwdUuvEYmbmI9x8xy78Vyqapl7GOgiI9qvaX1iMsxlICFUMdorGe8nsxRtiErwsAVcQ==@lfdr.de
X-Gm-Message-State: AOJu0YyHLpiAw0hT9aCAu5tp9AVYeNih088bpQVYI8Fuz+tUT7LVl1bG
	1ILsr0K0L06QRfZezz7ZU5gMZwxGWdTiHCOjnWg1N7AB/2C1Nv6p0sGr
X-Google-Smtp-Source: AGHT+IHjYfZdF3ypWwxu+aUKDzYWQONrnU5Z0L0YSt3SHwD94tkZmKEls1WbphDUEjoWdciwjtxSDw==
X-Received: by 2002:a05:6512:3b13:b0:553:cc61:1724 with SMTP id 2adb3069b0e04-5562eedfa12mr729995e87.24.1751529111191;
        Thu, 03 Jul 2025 00:51:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2a+ltfHP5NYg7DczNAIwnb+u4tXdSfAKKNvONs18Pmw==
Received: by 2002:a05:6512:1402:b0:550:e048:74ff with SMTP id
 2adb3069b0e04-5562784fd21ls474709e87.0.-pod-prod-06-eu; Thu, 03 Jul 2025
 00:51:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUk8By/CNaYg7Ee6H4ma6hr4KdpGixDVjLX6rNfrKjYJepi7O8chCvOLiF/j/Hj9pVd50f5y7ZtXT0=@googlegroups.com
X-Received: by 2002:a05:6512:4025:b0:553:297b:3d4e with SMTP id 2adb3069b0e04-5562efc934fmr794302e87.52.1751529107214;
        Thu, 03 Jul 2025 00:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751529107; cv=none;
        d=google.com; s=arc-20240605;
        b=WkQfyyZYwEEUPd5RtxPClYuqqWDxcyKHXAP2dPDj0FCT8gMEKSyJPR0c9v1gL6VIAs
         edlepdCsZFeI303rJnOXXSI92beTJE1wZC38PY0viB/9b96MNVwNsLxokq0+X11kV5Xj
         NivpaE2nVg+gXXkVAXkFeNff+lseuMsM7kOU7zP6eZdnWegACdqFokqdEZjgR4Ms8lx3
         G3rGTCYpKNsZnlS9ty9/Dciu6IpD4U32b+P0bYQ10VHPPSU02w+3UA/WbdsDxQ76we6O
         S4HRuP2EjVxV5SoWSceS7TRg935uPEAiznylUrsx4hBzcX8TntL0a7Nov/tgd7BapYKw
         4TtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HCOocaiZE3RHaNr4ijYeQaRjphYIZIyLbI3fYSnEAzM=;
        fh=jG+86OnaJq5KGMA2zt10DBj5UsZTsrhM0D5MP5rYe8w=;
        b=iF11qiknSF5S1AqAEu2WktUhTX4ajMA3AQkNSxWnZPRN9EIVIdab8jUXYxY69tHZ6S
         1lYGowPJMGczyd30yWNKi6jJGRa922EuQkWR+77oK8ZW8dXXrFf4rjeG9d0Z531m3okl
         dq8EeTCgbkKyBrAhPK6w9EnPVRY5qVrHUriqydg0OtOVcgOVnwbAKu0iRGAriYZ6WF2y
         FdEgwWp4OjdwTIinjmUt9VpQ0c6GREJ5XPMpBclg5Mf9JZcVeV6UseHZJO9KjM9FGZWp
         Wg2zzKVTivVLnX4mCT1Qg8QFLcjw/H/ViTbOov7jcWDTwwvMzC7LpjGSqzU6aw1R/HJ0
         WK5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CLgpQZAy;
       spf=pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b2458d1si648560e87.4.2025.07.03.00.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jul 2025 00:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight.linux@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-453398e90e9so43024895e9.1
        for <kasan-dev@googlegroups.com>; Thu, 03 Jul 2025 00:51:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5hF6BCVdYyxFpz44v0HjIt/gTpt8bIIQmggxtICQdXcTQeoXR1SyuFHCelSeqMrGBGwaxhYMM5ew=@googlegroups.com
X-Gm-Gg: ASbGncvD6S1VkZgxBjeJD+e42Cm8YmCT9lC4xSr7maE5b9UUTMDIE6L6IaoRF/8ZHwU
	HUrlP5QVusvwEzClJZ/s8wNQxEyvvn807NqmlxyjOZYRITgvb30cltLUwRyw9AN5HO++hYVebij
	ZCTw8olSUOutiLxucukpSj9Oiw+8Fhj38AO8xUFGAkm1W/xjthks2YyXmzqz9xJ0rZV5ptn/ina
	UzF+8fD8Z7FUGzqcLKmNjCrf/72Hzx/kz6xRepQut91Kyf4fIWkLi06EGqfhLcP+/qYLXsAba+b
	fTkZfjhVTZ4WCi6HkeqjJYrLAOFkSFt/XJ7oTVvW6qvDyv9n2ysoffnemYvZqNXao/nJUUutlE7
	ivC7liiUZJ3r9f7Cn6A==
X-Received: by 2002:a05:600c:3593:b0:441:b3eb:570a with SMTP id 5b1f17b1804b1-454a9c620e9mr26826685e9.2.1751529106099;
        Thu, 03 Jul 2025 00:51:46 -0700 (PDT)
Received: from pumpkin (host-92-21-58-28.as13285.net. [92.21.58.28])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-454a9989fcesm18768755e9.16.2025.07.03.00.51.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Jul 2025 00:51:45 -0700 (PDT)
Date: Thu, 3 Jul 2025 08:51:43 +0100
From: David Laight <david.laight.linux@gmail.com>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, Dave
 Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco
 Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Thomas
 Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
Message-ID: <20250703085144.4afe788f@pumpkin>
In-Reply-To: <20250626134158.3385080-3-glider@google.com>
References: <20250626134158.3385080-1-glider@google.com>
	<20250626134158.3385080-3-glider@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.38; arm-unknown-linux-gnueabihf)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight.linux@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CLgpQZAy;       spf=pass
 (google.com: domain of david.laight.linux@gmail.com designates
 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=david.laight.linux@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, 26 Jun 2025 15:41:49 +0200
Alexander Potapenko <glider@google.com> wrote:

> kcov used to obey clang-format style, but somehow diverged over time.
> This patch applies clang-format to kernel/kcov.c and
> include/linux/kcov.h, no functional change.
> 
... 
> -#define kcov_prepare_switch(t)			\
> -do {						\
> -	(t)->kcov_mode |= KCOV_IN_CTXSW;	\
> -} while (0)
> +#define kcov_prepare_switch(t)                   \
> +	do {                                     \
> +		(t)->kcov_mode |= KCOV_IN_CTXSW; \
> +	} while (0)
>  

Too many level of indent.

(and too much churn I just deleted)

	David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250703085144.4afe788f%40pumpkin.
