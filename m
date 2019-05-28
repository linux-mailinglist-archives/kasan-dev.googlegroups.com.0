Return-Path: <kasan-dev+bncBDV37XP3XYDRB36NWXTQKGQEZVZNL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B2AF2CCA5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 18:50:55 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id z5sf33981114edz.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559062255; cv=pass;
        d=google.com; s=arc-20160816;
        b=oDZtfVkBbTW2GAIf2krDCyhcsMmkwgZsvWrVN+qtp5hCkDED0PUGVmbacEmiI3WhDX
         7zzcG5bAVFKDopSf7qO4uHKWFsiiB/fcK0knlK+oI+fpVEUq+Zi1hvpcleQrky9ZV5yu
         eE2MEkRozu0CsKr0VDRCwCTHmIZycul4Iq3lQuNCLHpdf2JG+tqoyfLba2xLSvlBwnq6
         swHfhai3OxyC3mqpFh1nArUy4RtosVY5oOSeNmGAYEb+A3gHCp6KdrQ03jswf9bPBB7m
         5/2qEdIkocDJmYciwqvPbXo0Y72pqC+Nr8+1l6uz6ex+XD4/+BdtX+zLB0jRlN64TVTk
         T4SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=w7opcFkTJhWyYP4gOQAgSs09HnwDIGBQeSXANegsR14=;
        b=bS7NNIyft0L20NEW2AcVrkE37fFhcRi0oYQnTR1sA8pLGBCvNsQnN0Z1HNqlCAFiEE
         +exZSuezlckeBUu0iwkxn4miELQj13q4dN0put5Ql6in5mKYoMKKD0CwWA3GE8ArPjEk
         gosshydhl05SXdOHVKHKdJ1JA2Qr4XdJVa+U+5oM6HSC9Aro3LaU/3uqN5RoK8C0qQqx
         WWV4zwS3pLJJXLhjpyZAQj7427zgvu5Wzyb0Xte/EzCKghzY/V/xkTjc04ETB+nP1mau
         cRPwy/xyk3V46c2g72GCz9z8hQuFl/w7DtDgIQJFBvjx8pEqDNxb/Q6vVbbPyVFFHzzj
         BHRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w7opcFkTJhWyYP4gOQAgSs09HnwDIGBQeSXANegsR14=;
        b=Nic2pAN9dVqyaxtwhldnuy7zspjPUag/YG4Ypob4iR7gmzDeX8cZjAp+aSq9bKtZrf
         iwjYJUG8b5jOw0sc3taceo5V39qV9LxQoB7LprcIi97uQQ5H5i4hRIGnJgOU6wOxpuIh
         WEnpMUZHJHRp2I9tkuYfclbWT/qvuXc2H6tUxeVb5S2tlqrknaB1mmAPmj1U4K1YdvVf
         flN02j064q8jtOpcRZVyRC5Ie3gqfY1mw97NM8H6FM6qjC72HOo2LRpMJLAgtJBA7tj+
         YqHT0WyiY0uLC1olB8ZanBY+7ZiMMUUi1iuCZw/KaLTPV25IMG8ReVFFTtVQ61/Pibxw
         /EAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w7opcFkTJhWyYP4gOQAgSs09HnwDIGBQeSXANegsR14=;
        b=nko3FXXUahVD+KQH0huILYp6xrTrZOLiVoLKLwxmZuR3emQ5Bf2h/0qEDt2lpt1Z2q
         W5gaBnQ/2QOaMclDiZljzvpd1sF/yJMr3iUZi0wXiSJ8kXGJo0KHB0XU75Z3eX3u3/pO
         R9R92FOOyc4I/hXH3mrL6VLVai4YLkVdE78RJyXZDKz70H52pL5ogJhUljgSech+5W0+
         Bct4hrk0recvxXPPSAj5hRhog3LYy0yN1nAEUvWxilMDW5SiEmQRwW6t1wLvabB2QYoZ
         x9nxn3QRWMO36FQwOvfhT61FMGsrYFy1MdPFkHmRrpgW3+S0X6VNZm4C9QYo/oplM9u8
         2QoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWwfCwUIRdkxd1iVhhLw6GnCiKCl/DJXWK1XwC4BXifickK9MiH
	rz8DbRMXYhzXVIO0PS7NFWw=
X-Google-Smtp-Source: APXvYqwG0PyOe1/KvkFA1dnLsNCg4hL3Eu8qhmx3ExwTBsubDoQnpPjv28c6KaG95EOpExg1Fu/sWg==
X-Received: by 2002:a17:906:61c3:: with SMTP id t3mr85386903ejl.273.1559062255175;
        Tue, 28 May 2019 09:50:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7807:: with SMTP id u7ls4770365ejm.13.gmail; Tue, 28
 May 2019 09:50:54 -0700 (PDT)
X-Received: by 2002:a17:906:ca5b:: with SMTP id jx27mr92279419ejb.233.1559062254679;
        Tue, 28 May 2019 09:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559062254; cv=none;
        d=google.com; s=arc-20160816;
        b=x5gFcoclVx9Gf9whLb0Z8GYdRhSixYD+0kIYm/nm5BchTjFV71a3EJmS2SOtlILelN
         HYCbV3Eq0R7TU8l124ZDZ+0GWVcetO9La/qiaxSVOpp7XdDDLcMtHLWtCdBStah0NSYa
         V2jJPtMC/efp6AteTeWFl4V6OwBTTst9HgUFJEvgofBuzATt4rQBTpvaVtofd+gbb8EP
         M8lqTLfPP/+aA0tY1bGlIUbufLFNXo3Ro+scuIUO+FquGSkudX7FncHMOrGLoc4HC8pz
         1KduWybA2YIw8GoPX32OB/nCL27uElmI7MoeM5c6HmRqtrLNC9vc4VziPBGcy0h1a5BF
         ZJlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=CSrPAdXVG2PPSgKELxFOFFehvoXAPD5g1uoAw4jiONo=;
        b=1J5E3YXwnvqRq6AI1AlP3zf551iqmWMxl9/xmlSejYKFNXGNJeH+Ghp2d5nsIVXDJV
         EQ/aSGCG/DKJOzxp3xXRZEZJrsAQayLlacSq7zc04tfFLF4g76HAGgLYcOw5YdG7259I
         MGKX1MyI3oNt205KZFoJBXlC3fGMSxkRa1nY9dJg8MUFvnL8O/UHUZKHlZJRSM/TFImF
         dlrRadhD/FFWxb5ERaJhL89IiNDW+Jzj9vgDoqZyFfg8u534hddoh646gcNIeclEI76e
         cmpfUe50NvQaQkf8DQJqi94u//fRRDrROjgW9ik0lgKlEDKfL2c7Oq/Z+DKhiz9qs+t6
         Yx5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id w5si901482edw.1.2019.05.28.09.50.54
        for <kasan-dev@googlegroups.com>;
        Tue, 28 May 2019 09:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CB43CA78;
	Tue, 28 May 2019 09:50:53 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D794C3F59C;
	Tue, 28 May 2019 09:50:50 -0700 (PDT)
Date: Tue, 28 May 2019 17:50:48 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com, corbet@lwn.net,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, hpa@zytor.com,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] lib/test_kasan: Add bitops tests
Message-ID: <20190528165048.GD28492@lakrids.cambridge.arm.com>
References: <20190528163258.260144-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190528163258.260144-1-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi,

On Tue, May 28, 2019 at 06:32:56PM +0200, Marco Elver wrote:
> +static noinline void __init kasan_bitops(void)
> +{
> +	long bits = 0;
> +	const long bit = sizeof(bits) * 8;

You can use BITS_PER_LONG here.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528165048.GD28492%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
