Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBF7D3T7QKGQEAE7RUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 665272ED3EB
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 17:06:50 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id f190sf5136669oib.10
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 08:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610035609; cv=pass;
        d=google.com; s=arc-20160816;
        b=rbZKxxSD2BsxhjH3XOeXQyFporJCI6mIW8Nw3UDcGu10gs5utP6Y0/kLwKWTmKQGFY
         UkemcE+wU3l5MK4dZrOVyqj+D0YKMizrorYGtplpDlpEqQ4vvKDklAtGmz4Dk62Y+PQ7
         Un56boPSq0S2aa+1/Etw+iSTHs//CMPux5mPV6AeQ4DbaRuCR86fmkjYSGOUNtbtmyG0
         vYLHcWrEsTyWJtueOQRIwYFKn71s1fjzP/5iVdd+g50PIF17SG5p2uf8116/65/RD+1P
         wEtu2bMcBhr7CMP5Q2q6cgLV+eWXXCwYHvBF8hSrwZsP1xCY0G/nh25EnMYBSw/wYMg4
         fPow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RQD4EsUdCJTfO7ZF9g/AVrUueO7fLHYhS+18416/3Yg=;
        b=bQ2WitTqXe4JXDXBGTN47LntPhvZC+QXhBAVaunSCaxizc3XLzWMP5hbbCSsnjLq7S
         Zp9BG7qM5Yleu8IFz5KhB/PC3C7KrKiPEEuLYr2jtSzynD2MPu0djOcfVUXuqRxNpOVG
         KWlvUEW2YoYpoK/au+VohJ9ntBlF+LklYd3zvF0j6daevONKG3y1MPvHbqzEMaBdRhLO
         RwZJOG9LXk3Me6zRJ2xz9L+Gf13A2P/FDDueuIK6P4kLy3ZVuH9ovcOVfpH1+yU+1Db9
         YX8uHyv90Q658aTzQutOLYA6lkyXNZlMRAYJZCUQ4C0RTkR1/xU4r1b1fmhcc+fTyIig
         8VMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=TbGgU040;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RQD4EsUdCJTfO7ZF9g/AVrUueO7fLHYhS+18416/3Yg=;
        b=V8ZZGyxxL6CgKYj2yMOn39xAKLDpN20el188NeChGtRTjOT21LekDLJb9JnxfPqAgZ
         aefIMrhz8qu87SBzoGDg0j4hzQnuugC1oTvuxrfRAPKyyzjeZwBt8A2AmhMos3az0OTj
         TA7eyEpSxP3pE3U9PQMCs0RO7RxEObzpf4wJhanfpXwMFoFRd9LYtI3HqplXsDns0beO
         ArpkOtQFjnOMq4j/7A4eEqzTO+RvRI5rPiG+D5Nf5ID5cnjXnUPUCQWKlHu3efPudmo9
         vGLau2K1TAyywBv1QXA0MY7lAwSUYnF0dhNHXiyRYQKblTIJZgsx21s6XYyY/0p+fMJg
         V/rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RQD4EsUdCJTfO7ZF9g/AVrUueO7fLHYhS+18416/3Yg=;
        b=Ic/dkgjfXe3gIH8RXTpE1HLecLK5VOqUmVhqZilI3JvAH6ahagfrhR2gkcKbA2iBgr
         9Xa4de9yi+2KKKP+eaHytwhob8QEwktWNCypL4uLKyjGz4M/nOXnelBoGLbJ7+8+R/0d
         S4gTx3M7/w79ak00vVv+oM2kW8pp+exI6TRbPjlBT43QIcmTFGQo9ji7mAh8hEDGwdiv
         CY3sIX9ZT/uFCToJ/BxLNmcA3PbQmLdRRvlIFDeVymZ1qourF/ubHbtsSlbznJYsMrKz
         78bFJ6nQe8pIrQXw8pSDgsn3KvaJscfaQ1Kk/dL3D9UlAYTL/7ggJrNPQD+OKwvrRYtE
         HZDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JqlhGTL6P28w24kdHa12ztw//K/GdkKFRC1voevugVJgyqeGM
	0bxVz2HJuwHps7KMIqagDsw=
X-Google-Smtp-Source: ABdhPJyrbOiNOFZOKSJfyXmknuuRwCCz9Qv0SfUCxhDEK6jZpfi30H3VaV3sYiIUsM11ZisvwsTidA==
X-Received: by 2002:a05:6830:2015:: with SMTP id e21mr6747842otp.367.1610035607599;
        Thu, 07 Jan 2021 08:06:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b1c5:: with SMTP id j5ls483703ooo.11.gmail; Thu, 07 Jan
 2021 08:06:47 -0800 (PST)
X-Received: by 2002:a4a:a289:: with SMTP id h9mr1577060ool.86.1610035607119;
        Thu, 07 Jan 2021 08:06:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610035607; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRKoCe3nwbpcrPhJDDSJrKYwyKo6CScOfUD/ndRBERoGFa+laH6M8ghxEcLfPeHCaB
         cW3qZ3eT5HkCRkH6MKR1BmTYUu2Zu4ZpyFreEnO9YBMJr9Bir5RIstfwHrkSLC1CbXSx
         Es/qAwhjj1OuM4QfIBzhrDv9AinmNeQM3hvQYA0ShEcWHMEkRFCnNwkBoS1BoRoGA58G
         ueYmfjQiAHi1u7Ac05ZU7sqnh9TwMAA83Z68hZw8H3bBn2L+jBpWFwkNDYq4KS5t0Gmk
         wD3TXIftgfOsx9I26rsV+YyqpBFjTyBEqVYBpG0eKDN2QdVPDtGQSzozKr5egbQ3Ujys
         bfhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZHGRoJrbDHewzcicvx9RbP2nSRjj4P6GJKS+dXVVPLg=;
        b=AMVhG69drQ5wLr4tsG4K443HapHE6cZr/5cEatHU7qFBqxk0R7mrhRxDNdNEwUfFzI
         +D79A7GESZHXEmolr5QUF8RUFUcto+ZJtUM3uiDDdx/gxrf1Jbcp9QGto5GrzPGzKmKc
         DaiHxnerqGKr5Tik0x75Rwop5UoyJBoV7t4wnqN76jNqJqjV7y/YVBSQTogIhc8bsZU/
         8m6YevbY4548T7GyQzZ4TUdJ3k3iAbA5bNVPSnWpFz0uPP5IgSgXM0GkIwdLhBAvgrNR
         i4lRMzLhjqngcElnQ5m5q1DKyUdB2+FSm8PAuq9jfBygBRug/o0hCqYZr2csARbJU979
         xc0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=TbGgU040;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r8si602346otp.4.2021.01.07.08.06.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Jan 2021 08:06:47 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DA32320857;
	Thu,  7 Jan 2021 16:06:45 +0000 (UTC)
Date: Thu, 7 Jan 2021 17:08:06 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>
Subject: Re: [PATCH v2] kcov, usb: hide in_serving_softirq checks in
 __usb_hcd_giveback_urb
Message-ID: <X/cx5tjAODS6PFTO@kroah.com>
References: <04978189d40307e979be61c458f4944b61134198.1610035117.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <04978189d40307e979be61c458f4944b61134198.1610035117.git.andreyknvl@google.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=TbGgU040;       spf=pass
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

On Thu, Jan 07, 2021 at 05:01:44PM +0100, Andrey Konovalov wrote:
> Done opencode in_serving_softirq() checks in __usb_hcd_giveback_urb() to
> avoid cluttering the code, hide them in kcov helpers instead.
> 
> Fixes: aee9ddb1d371 ("kcov, usb: only collect coverage from __usb_hcd_giveback_urb in softirq")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> 
> Changes v1->v2:
> - Fix a typo in the commit description and in a comment in the patch.

I can't drop the previous one, so can you just make a follow-on patch
please?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/cx5tjAODS6PFTO%40kroah.com.
