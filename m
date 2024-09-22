Return-Path: <kasan-dev+bncBDW2JDUY5AORBW4PYC3QMGQEKRLICQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C15CC97E16F
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 14:04:45 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-53659c3c9bdsf2200173e87.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 05:04:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727006685; cv=pass;
        d=google.com; s=arc-20240605;
        b=QOl6rBq33pT03aJPXp5oJ2y/JXjpfWtbYHdIdgSwMq1HU977F531bSPd2t1MVIzDEl
         UR1ZBd9eU2+JtOgv/XmkfhHEhccuRkUqumlUgKfl6AzxNHlHw54gdUjsZfRoVkEHTZgE
         DAA/Iq88cFFwsucWPAVQLiciku0+vLpCrB7saG3tWl7zXHubXoi/G02fIjLV/FgCqDV0
         zgeNW/8vdXIc4NIWIFO/KOzaA1kkbXd82KGg3NQXeUaHnQwnmsigY6nRTMhXdobu+fIU
         8nJTvKrvwTjp5zs0anCpZb22wXmnaZ6cxX/XefUE/CZufPWQIwAQOo0oKCcX8Sq1evTO
         cu1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=rsx4YQPNyChgOBvaZZNesE06rVkGp0tnUefLqW2f/Ks=;
        fh=eVxt29EOOeUo7bZEe9iGI+sc+OdeWJcjCEbXeKR7p6U=;
        b=JttswcVvNU9XwEXksLQNJwNL0hEwfExLmbp1ORdXgkOjFkFyTTeZu5tN+3S67uRd64
         aZsE4HWZGn/WlpeRTMdeLiuTuwRSq63A2YCBuy223W0zd8jTe+zMnQw/TYS5VnBvSopC
         /Nl4pIfJHYjHHhgteFM9xERw0MK5qSTBMyFU1qD0UYIeGXsK/lU7TbDyVjGGNtQUHeWA
         fRPEREPkAPAx6B9g9xwVytXpfXvfYHWeZApOEcuS87jcvkmZ3xHzlwQJ6vhdrehnw1GT
         25XKZiXYqp0SWE1xMWMOXTz/PE9+hPaSKtLWwV0XqAl6rhaHrFCtpLvlZEKStK1Do8Vt
         9JJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ThhwAGmM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727006685; x=1727611485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rsx4YQPNyChgOBvaZZNesE06rVkGp0tnUefLqW2f/Ks=;
        b=CnXgraKxB+4TbnyAWGeBPlpR/gDZBH/rCrJwykd/lr0hm6o4HpgbdD5kcjkMZhzbJ7
         7czHqAnGJsly/zNyzp9lYvb32amHasKWEAoabwmuQ5AIvMHuwHwgw2keKnBWlN/yJAY6
         WaOQv9lu+qghlWGa6PX6JISJ73JlNO6xuQ13Hw2Itbz0ssvx1Sp9dobsH/PJaXiEvn7S
         EjRXhVtFqmEEcoszAbLzA4TZVuv4cUtWAeXvyVx0bT1MU0Jo2OFDKyh6oxfGU4VRiRxz
         Sy0G8Fgr+YBdS1Rk/Yb7Mq630C+qURKZnnsCtenduj9DAuNNQ70xUZklesIkFKn1poLl
         2gPA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727006685; x=1727611485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rsx4YQPNyChgOBvaZZNesE06rVkGp0tnUefLqW2f/Ks=;
        b=ePUG89U+uCLgOXMLfG4WdM5rTuWfY+DlyD7EAmCBKwqa3OH34pfhuTTHRd48PLciV1
         Jj21V19At6fGGGvcMijWBk2T2Rm3c8ZZBn/BmOUPsiuOAtQ0VxbmhZCSH+Jqn6N4/iFu
         Am2XZYonQ4uP8u8ITiylf5ZvPWHQNspPLsH1RaorPM6kcCaVd8+cGg4piJFBsrqWFeIE
         BgZRYhNSeR4ziLoUi350UIDDOF6HSFvcRGLNbBkg1SNuVtZMObkNaJAna/z+37oX1GGV
         i7U4Ty2Z0VUbYlvlUCWBp7YZiiHiXy/Kq++YEZ2Faf1cMWR7C9eX7e9qVjK2d8NDMlNr
         KSug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727006685; x=1727611485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rsx4YQPNyChgOBvaZZNesE06rVkGp0tnUefLqW2f/Ks=;
        b=ERHCgmrBaXiz/XaPf/MWEGNqlh9huQBJhishSB0VkOn4M0BX21VjpI/mInPTx0I3xu
         EZ0BvtJdkXNcuni0Qw6mMlpwWLlVLgoBgEvxxz1MSdE/nwFwlR6GITS+yXRIEkzt+CKB
         luzWBfl4BiC4v9aMX/0RA80bNWG3Eo6wAIsqpnnRv0KRGRQr6t8oqmSl8O9YJ2WZJxoE
         7Yr3UtW2iPiLPs9qnDV6khEoI6tKUOGqpfzvSZbLj4dyQXJrnGaN+Hnjyul+/NUyNu9a
         auDU3DgarEgzlGtLLjJ6gaLHxKQasHGS/8YE51Cqccm6De/bKWRJA4FoGtYJ/7R7ttvk
         oulg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxLS0C3dned9zrkjGGpjOJJpmPQJZg74vv7k8V4LQP8YTzQ7biUI8zOGEzesqJcG4nH/eoqw==@lfdr.de
X-Gm-Message-State: AOJu0YyTwZy1tYUzzWCaEk9aoroZOGt3KVUGsLIiQeBtu/3QE67/NU3t
	78RX2YbClNdSOxOxFtCUOhkl42SeTTOrYDELH9yJdNwgXwxQwZ0/
X-Google-Smtp-Source: AGHT+IE+0RrKCynqGBXB8ZX4Ymx70RT0v/zrBQYXlyCcThG9cS1ZWnXnbZq3ZNhlLZoo0UJjU9EE8g==
X-Received: by 2002:a05:6512:1095:b0:52c:dac3:392b with SMTP id 2adb3069b0e04-536ac2f5b17mr4127250e87.33.1727006683704;
        Sun, 22 Sep 2024 05:04:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a82:0:b0:2f3:f66b:fe2e with SMTP id 38308e7fff4ca-2f7c3f49e4els4958911fa.2.-pod-prod-03-eu;
 Sun, 22 Sep 2024 05:04:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcsLDtXKN9gZTCOlnbDtsPlaa0oJ/lwnq7rKBgRbB2aYF8ztvFs3i0h08+ngQBaKcoAygwLFG0xBM=@googlegroups.com
X-Received: by 2002:a2e:b88e:0:b0:2f3:e2fd:7dcd with SMTP id 38308e7fff4ca-2f7cb301378mr43622941fa.6.1727006681612;
        Sun, 22 Sep 2024 05:04:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727006681; cv=none;
        d=google.com; s=arc-20240605;
        b=e7KFBJE4LErHdm3QTH2wlFmR7MCUWqm4v9bsifkuRBNtjjck1rEk6U2JZqZq5QBULe
         EQl7zong36XDqIBoVcgDwzeNEllX3Tmb+VpnMc8kCdYYknHDqOzKle6cBsQ6TdeLhwFi
         ysjJM+/hpxXoOtKuSYAAvkgEiKtSbA13XS3s9hvzuuyL4kqICYQ169kCEolJbFRomeD3
         E8NXhyJzFoXQe0lp54uox7MKuGzoukpoHZ6FQL5H4yFal7KTdWGc9R40IS+V6wnLLq0W
         LZ/zEi0inm+jgFI8zZ6p9ao3uBIk0FuWc0tflurx2SlJFz8GCul4+XbZtKelUEYCWMUs
         TDxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RBEPlNYF+wUU1oRD6OHrayxuYaCQspJdH4WFCZ/gD0I=;
        fh=58jZtwXtjDEZbeA8rAEVjhAPYT3Es/qXGyMsSS4hmk8=;
        b=HbnsSYz9aqrysZZu6svAbNR1gS4tlO3kujxfBOX5FIy/yW/8RAcqj30vZlxeSbllBL
         PN1yB76EjuJEWdlcWafXlGiwhbYY3kS3WV1NZik1tPD1bysW2SZxC1lYXw82HCxrJVKU
         JEMyq2qI4VQS2te2NkboF1ZJCSiw6aPzpOOuQnTciedRbF6cCZdF0G7EV9OD50rax2d8
         hZ5LuuTz/G76VtlSX8HUMNK+S5V9lhabOpISFn4nR7QgU5DR6OpBmD6kG49LbmjBn5i1
         UMCmt6XtPMQbcahO8bldvMVtCCE/Dc/Gzn1STeyNl2pWJeeYj/h9Fw3pdRK15cE/00xX
         VxVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ThhwAGmM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f79d37cf84si3870141fa.5.2024.09.22.05.04.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 05:04:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-42cb806623eso28333665e9.2
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 05:04:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnwCwJDQ44U6Asib3YSFdAdppe9tbj5lPsxtxTCcHQwuXTW0eRToN/6kyArT2hOMTHQTt/+MZUwhQ=@googlegroups.com
X-Received: by 2002:a05:600c:15d4:b0:42c:b22e:fc23 with SMTP id
 5b1f17b1804b1-42e7e7aa2ccmr43532325e9.15.1727006680647; Sun, 22 Sep 2024
 05:04:40 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
 <20240921071005.909660-1-snovitoll@gmail.com> <CA+fCnZfQT3j=GpomTZU3pa-OiQXMOGX1tOpGdmdpMWy4a7XVEw@mail.gmail.com>
 <CACzwLxjZ33r2aCKromHP++2sLjWAQ9evF5kZQCx2poty=+N_3Q@mail.gmail.com>
In-Reply-To: <CACzwLxjZ33r2aCKromHP++2sLjWAQ9evF5kZQCx2poty=+N_3Q@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 Sep 2024 14:04:29 +0200
Message-ID: <CA+fCnZfaZGowWPE8kMeTY60n7BCFT2q4+Z2EJ92YB_+7+OUo7Q@mail.gmail.com>
Subject: Re: [PATCH v4] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ThhwAGmM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Sep 22, 2024 at 11:26=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> On Sun, Sep 22, 2024 at 1:49=E2=80=AFAM Andrey Konovalov <andreyknvl@gmai=
l.com> wrote:
> >
> > I tried running the tests with this patch applied, but unfortunately
> > the added test fails on arm64, most likely due to missing annotations
> > in arm64 asm code.
>
> Thanks for testing it on arm64. I've checked other arch and found out
> that only s390, x86 are using <linux/instrumented.h> header with
> KASAN and friends in annotations. <linux/kasan-checks.h> is in arm64 and =
x86.
>
> While the current [PATCH v4] has x86 only instrumentations for
> __get/put_kernel_nofault, I think, we can take as an example copy_from_us=
er
> solution here:
>
> https://elixir.bootlin.com/linux/v6.11-rc7/source/include/linux/uaccess.h=
#L162-L164
>
> , which should be a generic instrumentation of __get/put_kernel_nofault
> for all arch. I can try to make a separate PATCH with this solution.

_inline_copy_from_user appears to only be called for non-kernel
variants of copy_from_user, so you would need something different.

> > We need to either mark the added test as x86-only via
> > KASAN_TEST_NEEDS_CONFIG_ON or add annotations for arm64.
> >
> > With annotations for arm64, the test might still fail for other
> > architectures, but I think that's fine: hopefully relevant people will
> > add annotations in time. But I consider both x86 and arm64 important,
> > so we should keep the tests working there.
> >
> > If you decide to add annotations for arm64, please also test both
> > KASAN_SW_TAGS and KASAN_HW_TAGS modes.
>
> Please suggest if the solution above to make a generic instrumentation of
> __get/put_kernel_nofault is suitable.

I think the approach you have taken with adding instrument_read/write
into arch code is fine, we just need to do this for all arches.

An alternative would be common wrapper macros that calls
__get/put_kernel_nofault + instrument_read/write.

> Otherwise, for this patch as you've suggested, we can add
> KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_X86);
> to make sure that kunit test is for x86 only and I can add arm64 kasan-ch=
ecks
> with SW, HW tags in separate "mm, arm64" PATCH.

Sounds good too.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfaZGowWPE8kMeTY60n7BCFT2q4%2BZ2EJ92YB_%2B7%2BOUo7Q%40mai=
l.gmail.com.
