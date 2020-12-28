Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB4PBU77QKGQEXPOIGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A2232E4039
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 15:51:30 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id g17sf18812140ybh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 06:51:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609167089; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhOiJ7otXGaR3xcZJeIoc6rvP72ZruUTkXiCch/rw6YBW5D14AeQUh2W1HgjOCp/B/
         KdmbQ5RPtdHyILVk33AM9M9fgtc9mpq5iKfk1c+c7Owb5XgDbvs9WtZrzT8zQaobEztl
         hP9DRsjFcfzE13nd6v1evEBCXxHP3HJf2BicQ9tBZAh4NfY2GBSA3SUv0q9515lrcHSV
         o4x4AABQlngVuL3y6HByseVPQtKxIFjiaX5GoQ7wsIWeWxFxCaYNMP88TKjJU49cEQoe
         lplVpgB6ZiLTyWJYfyriBohfvxnouUNGj5Cipa5vVaNIkmvpQ5NGHTnn1HCxAFkf9Omt
         D5/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e+Lv8we1Xk0Sm72Ebn/z8Z0M86OjmIZhzaQRakUggWM=;
        b=jvf68pXRSP42Nfm3X0y5SnUyjhJCadLIf7bMOsLjriNS4hFSLY0Rn5QoKEEIy2tt/M
         9uADEFznT8xuCpVR7YwmkIEieC1BRmDJn15Z+I57KW/GKw6xsLfDrPC+PzU1Qj7W77/o
         kSw1Nr80N7/wn2qAK1rVwcq65sE+FzVancmz5q9iRw7QrcsqncAF3/lXqjgBS4UQDvtS
         cgE2AIZ2RvBt9sfmYhXpcLQHMVJlNDymNjO8Z3JWiYrVzuyjXr0Xv/EWhLlsjlUm1Rif
         Uhy+kHjYma54zg5IjLO4hCUk1atXIg8azgoLGSba+MucWT/qj7I245pB37E06ipoxjmS
         2Awg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=AUMwak0p;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e+Lv8we1Xk0Sm72Ebn/z8Z0M86OjmIZhzaQRakUggWM=;
        b=GlIh1PnW/PKmipzdpb54asxndUnLBOqGpsNX6lwVb2c1Y2hlgH9giDIwSiBlM+mHui
         qPk7u9f8kEEqjMKrCf3vxWaDm5dFrF46ILyES5pCfQ7Y6tch0yYMAuqc5L1tvGpmY4d4
         b0/Zkdm9fYuutvieYxNnsTAZHlMqnT93VupSUz81HSt1Xbxpk0PwE8vPKDGdLpioESCt
         +ZcyYHXdhKguQxbMOrkB57bVKPVXJMqSjYUFplC20NvZQPFQ4L0Doyo0tx4Lr1xEBO+o
         utdyX2BqebISr0J/wcfIR60dl7fmiTd0GxmE6YymhauNjObKzfiR3iS4XGFIXVz5t041
         1pbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e+Lv8we1Xk0Sm72Ebn/z8Z0M86OjmIZhzaQRakUggWM=;
        b=Lm9U6d4+cOuUnzyY3iQR+pwvk4dkePAp9GqYbi9YodXrdPGgMgNIorfUbcPUlAKRm9
         eSH4sNP4CjalkFTWCywrB0YdJbAwQdnTYEfJLFrjmgzFDM4esQLLoAX2dpv2B7eX+soE
         /2B9Kv5RmdEAM48KVoG+SRGZEW8ueucoXn07A23vkqMJGjsvZdcw8mP3nvv50wNF4En3
         EqwxCW6Pzm10lW8xt4sCIz9OQG7pVZ3okV+nKa6hdEDyudQDWKxirx0OzYu/mz7LHYTE
         +Ggt+7oSTU8dd+/PVOpmVFvcySD+SrxiFzpF+w/vJW7Ot9d36YxbNiOtSrELebBjC8D/
         6/kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HTQiJV1hR74A/9WLkXFlGFEREe7VKr6hy1C0mPrxBgU2DFEXr
	uYqPIL3Yx3EDb8Evt6M9a8c=
X-Google-Smtp-Source: ABdhPJwDYjIRmTaPzpol3hI1n3HNtRu8XMWGgQF0zrCiEHqTC8mi/mjQJLrBzCuN6Vqb3DXivyfd7Q==
X-Received: by 2002:a25:9b81:: with SMTP id v1mr57687762ybo.168.1609167089679;
        Mon, 28 Dec 2020 06:51:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77cc:: with SMTP id s195ls28396944ybc.2.gmail; Mon, 28
 Dec 2020 06:51:29 -0800 (PST)
X-Received: by 2002:a25:3d7:: with SMTP id 206mr67763854ybd.31.1609167089297;
        Mon, 28 Dec 2020 06:51:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609167089; cv=none;
        d=google.com; s=arc-20160816;
        b=WynzfNescdur5vw4Npu7uZBTrnFUd4yOtHI4E8yWyS2Jt5aFqy38dNwSWhetu0OOjO
         fCBLFoIVDbdGB26ghtfpaLI7LwNv/yRQTUHWNa5C/cjPjzOoE6iHeqoXQJsFkhg3cUCt
         cc33IX75vEnOz/i7k4i2rl/tGJXtBCs7ZEus5tj/a7mhueKcX2+luCyKb8Lk8Ke7lU1J
         rxF/mIg3dLre2azDxX0ep+d8DtukD1pBXhl9LmedavftMUHtsA6PunH1MwJZ7rf/+vaI
         AeFQ1bhQtJCRcJRxWCgG4ado8bkwfVmjcsJiK0AfBwpYd/0yD1nmVqQ6w9rXnQv/f5Hv
         jIcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LB6uN59veMk5B3hXDCpU0vfNuHyBgurllHRfzz0zR/M=;
        b=W1eAw/bdUjFLIQpSkQKY3efIFCwXQI27MEHq2glS47CE0N60OXytt+KMj61JSNH30W
         Y0eH/RnmOskfsa0vAPHwRyWAt+oNgHchsRvG+kbN/rI6zVEQOo5MGj1qT3f/ol75kEyc
         rCNwfOonVM7aWoZsgXJkZSV1B7eHLhX69JlEmP0z52HHbptYGa55pm4lotgZquCCjJZT
         P0yVkB1UY+OGbXaxsGkhpDkWkyNtO/EwkwltGG26Lk+s1yxvqsR624HPTtx4VErjLSpD
         TkAgZdNrWsE2TbtOzSaR/qilmGIC0PSS0H6kwB3P6UL3KDRN98wzvuHDIhAbjUHGXGZr
         KeTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=AUMwak0p;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i70si2285028ybg.1.2020.12.28.06.51.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Dec 2020 06:51:29 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B4B2A2084D;
	Mon, 28 Dec 2020 14:51:27 +0000 (UTC)
Date: Mon, 28 Dec 2020 15:52:50 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Shuah Khan <shuah@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Nazime Hande Harputluoglu <handeharput@gmail.com>
Subject: Re: [PATCH v5] kcov, usb: only collect coverage from
 __usb_hcd_giveback_urb in softirq
Message-ID: <X+nxQo7q2n4dGzoy@kroah.com>
References: <d7035335fdfe7493067fbf7d677db57807a42d5d.1606175031.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d7035335fdfe7493067fbf7d677db57807a42d5d.1606175031.git.andreyknvl@google.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=AUMwak0p;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Nov 24, 2020 at 12:47:25AM +0100, Andrey Konovalov wrote:
> Currently there's a kcov remote coverage collection section in
> __usb_hcd_giveback_urb(). Initially that section was added based on the
> assumption that usb_hcd_giveback_urb() can only be called in interrupt
> context as indicated by a comment before it. This is what happens when
> syzkaller is fuzzing the USB stack via the dummy_hcd driver.
> 
> As it turns out, it's actually valid to call usb_hcd_giveback_urb() in task
> context, provided that the caller turned off the interrupts; USB/IP does
> exactly that. This can lead to a nested KCOV remote coverage collection
> sections both trying to collect coverage in task context. This isn't
> supported by kcov, and leads to a WARNING.
> 
> Change __usb_hcd_giveback_urb() to only call kcov_remote_*() callbacks
> when it's being executed in a softirq. To avoid calling
> in_serving_softirq() directly in the driver code, add a couple of new kcov
> wrappers.
> 
> As the result of this change, the coverage from USB/IP related
> usb_hcd_giveback_urb() calls won't be collected, but the WARNING is fixed.
> 
> A potential future improvement would be to support nested remote coverage
> collection sections, but this patch doesn't address that.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Acked-by: Marco Elver <elver@google.com>
> ---
> 
> Changes in v5:
> - Don't call in_serving_softirq() in USB driver code directly, do that
>   via kcov wrappers.

Does not apply to 5.11-rc1 :(

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X%2BnxQo7q2n4dGzoy%40kroah.com.
