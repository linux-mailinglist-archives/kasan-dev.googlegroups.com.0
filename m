Return-Path: <kasan-dev+bncBDDL3KWR4EBRBE4HW75QKGQEIJUHXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id C3EF92784DA
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 12:16:52 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id t10sf643832uap.4
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 03:16:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601029012; cv=pass;
        d=google.com; s=arc-20160816;
        b=uocDwMbAKSCiKezT64pkLn+dduzTj/HrcdldLEdB2pHd1X5wVKh8K3JDhRLBLUZSwQ
         2FFUA5RS2LpSCjHVFdvguSzCz3HEpHtF29aBl/vI/gVNvAPtKcg/+hccUyna0I0kHMxS
         92gUaK71p/MglYauWThJ0yym6zf2ZaZdug7+Z1U4Z7yDUKIfV6+9vUmM8o+y8xaGTU6v
         k5E8qIBZljkFYEnl1VsNDitOhw43hsZn0cT9d1yjOe4Tj3yft6TVlMCkjFluPb7iKTMq
         4zI6UCHXcjcUWXQ8cwD0sb/xw6Z/Yglr6oVfktnJI2tFAM3wPhKGYOzWUvNb8Qr+p5zx
         v9rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=RWFW4GIvCClRxT1ZINIYVPmA2MQNB4LrkZ3gV0dK/9I=;
        b=jxvg+Yud570WL33Q4vFHCAfzzmeqwf42+KMwmi+l4b5tbUV1G6P8Govtd19d+QRsp2
         4rXxVSfVbNcB7ot0/NFXuMxtE8T4LvUMiu+S4DjYKVn5nmTT1k2/XjlGKyLqAkc3xX7g
         eAydTkHg/QdShSB+eSGJbDM+Db6u2LYzA6uiKTawPXt6NtDyNk43gsZUowBaQACKOp/4
         j4EaWoPS/Q46qDJWpEl/N2i44qsyavhLvBJzPRoPIizS2xnCD58V7S0ivA7w4EE3RGzL
         ahn2CI2Z3C3ooEqI5YjloNK+STCzTE90Ie2iFKc/6nBnMPXmFaYkM8j2RTRfhwKqXl6J
         +k0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RWFW4GIvCClRxT1ZINIYVPmA2MQNB4LrkZ3gV0dK/9I=;
        b=NZDPJW1c/Qoz63LSU50bdm48m6q1992AvPpn90smgg9NapYZHF8F6OIDNlYPSAEwxS
         2WQ39Ade1HwL2Ms9tVfQR72Zvrq+6bUuOVAebow2ecEYsdT42GnUTt2OCm2GE802EjFv
         ykB65ArjMvSQZZAVpX0aezC26m7o1uftcNFfJtofVn8tNPA36svbYZafamdydCPYIJia
         Z/EKBPU6dMoQMnQoN60M8pqeIBtwxnczG40zExvh1iTewo7hg8YCcZNmwb++GQv42Ot9
         uva7tVu4z5IS5RjkNy6QUIpAHCyjk0NuSpXLEunh3pEnGDgL40Iqc5Th0mrkkTJwG2NG
         3i3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RWFW4GIvCClRxT1ZINIYVPmA2MQNB4LrkZ3gV0dK/9I=;
        b=DTRdPBWQlhObfTHUMzDcV0gFVeT/cs67PFXcxitDmchxGYFdyjCe7SUb2xO2oIYTzw
         HCTAXSObjD+fR2JmscKI6Is/boYunC0Aa0Iux/8JEHJIzsyvC5q4lprX7+KvCI9WCixf
         m9icgxZt0sWc4xekhnRDq1m1wzLVfG/GiXKhbLQJVMkT7irkTK4GFZHVc7WMxtUyioMt
         I3MD2HkZxULOXdd4be2ed9EzOUQJfScXwCRVhCN9RkgrVp9CuO9B//P8BVZe94HVGF+Z
         FZCBmKkh/d3FiUI9rG0aX6Y7rF/302RVaPKabG0pfT04B060Xg47EUF3N4XE8Oggp9Pd
         UtRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530AwCZZzX0I0oA4XfAdhDI/lpwBjPyoeQYMMs9iIHt+oeX+vp84
	2+K/Lo2Lf2za64YkyIP+I74=
X-Google-Smtp-Source: ABdhPJw/uycrRjJRohotkamd49IIdjvYhMjSTmS5gHw7EjMn8qlI5XQcAj+leoJ1ge6nu/8TwO54Xg==
X-Received: by 2002:a67:8bc2:: with SMTP id n185mr2299933vsd.49.1601029011766;
        Fri, 25 Sep 2020 03:16:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls305153vsd.9.gmail; Fri, 25 Sep
 2020 03:16:51 -0700 (PDT)
X-Received: by 2002:a67:6187:: with SMTP id v129mr2222233vsb.53.1601029011258;
        Fri, 25 Sep 2020 03:16:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601029011; cv=none;
        d=google.com; s=arc-20160816;
        b=GMnpZIGNqIuIxBJcpsx2QXIk8TDXaf8I4qX3ZqsYO6RZ/KOOQBBfdz3criWcB2avcB
         aE3mAuic9BO8/9CEu8vEkPaKRTjvI9DbxUbJgqpqvWCqzPl3Yc2REpW+nLCaALq8zjO7
         yJVLQTWWpg2nB8wdxP7Zphh2DDih93fpl8vrmDjvYDnxtD99GcqX4+TGEhyiEAIH0682
         RLRcxrjU25zqW5O3dVSWz6rqFL1JeZe4qWNCyDKrSOXQWiE2FUILHq3SeetD0E3lAs9R
         sdNlIQSdXWcK6um1pDiqoStyAj/wOLvNbIxm5b3UvdmZBRzv+CXHJzWdWesrOLlWxDKE
         ivFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=c52LAAzDhcK5vcNgqL8obNDF3NsUaZr2isIGsHME3Ho=;
        b=CQx6zDVq5DNYVPRhSCLi8r+Ylc00+ZWhM7Ihbmllrhy0F2wDhKW6jRrHONpw1Aa5hM
         n+WPiQwVoXn17ZcJlqVbIAdjh2lMUhrQwS9zbJb8FYFz4bUK5l3vfGTK+PP1PqCrBfZi
         bv6oMgfUVyT2COanN5RucxgUPE/7M3nPaoZqUDGMWnjW9/HDu0i8c5ZKquFkOH26mk1l
         MXZyAbQFWFQ5Lq+Br3ClF3UN/zsWTW+nJ+ouQOdTuKqDEupvrYyS7EakywQFjLluTS8A
         VMnTQ8kc1YAhfEI9CdIbG1+BPba2j2iqBDgmDyQBdwmZfqSZpZvlgYtd7lK8hH7PFHag
         kmoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si60275uas.1.2020.09.25.03.16.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 03:16:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6613620717;
	Fri, 25 Sep 2020 10:16:47 +0000 (UTC)
Date: Fri, 25 Sep 2020 11:16:44 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 23/39] arm64: Enable armv8.5-a asm-arch option
Message-ID: <20200925101644.GC4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <878fb755aed45104a44f2737d4244c14fdd1b9cd.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <878fb755aed45104a44f2737d4244c14fdd1b9cd.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:50:30AM +0200, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) which
> is an armv8.5-a architecture extension.
> 
> Enable the correct asm option when the compiler supports it in order to
> allow the usage of ALTERNATIVE()s with MTE instructions.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925101644.GC4846%40gaia.
