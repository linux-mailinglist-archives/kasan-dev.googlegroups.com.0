Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIFJZ2GQMGQEEAAVZJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id DADB74707E6
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 18:55:45 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id bn28-20020a05651c179c00b002222b4cc6d8sf2553425ljb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 09:55:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639158945; cv=pass;
        d=google.com; s=arc-20160816;
        b=KioFkk7/ImohjI5H3yE98lTGYUAGnzZe1M6HvNCMW6/d3083JQ75u3bW+1YSI26MJp
         uvy4eWwfk5uvKo0Cx6gg/OVuUyYxarZWfJi41kxnC6rlLTmb0Z+BkKGtp14xo1gIVc3K
         JNRqw8Ypm0DsqZpPdgfuyjKqbhFcfd0n3/g6kiSZe7uzY75fJo8VDrfp6x5juRfuAopf
         zhVUiUk779SjfCjHmzwdjjIOUbh5nLw2C1GObhS0gUWfXImi4fG0Ght+8wPxO3qozyJD
         zvsSI+885kX/eN+JMI/Qk+4idgVlns3GmsdEwFDNrO17Tn47Sv692e1LpJ2KKTriTglF
         GYsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SnLR1Gn+eQGPQf3qoRWFx7ri2DptJjayJnVTdR/ttz8=;
        b=gM0dYaifJSMWrbPxXk6yvwXPsUwNHR1+OR522nL4vaMSjkbDf6mODefdn2hNls/TXk
         pXZxyzPSsscs2xRXskSsVlA7jqvj0APQw9xJ2M/6iSv7VgDWL7mGMk0pfwZT866im3Q2
         4rlKKnkLUTP4HCWVbg/UFXd0FIV2fr8wByE1mkhOryJ9v3qrWL60a0XsW88bJP6oyw9r
         5yGvz0PNody6YEIKFosoDGBbqwnUquvcSc3m1D7AZc5N9teWxH8dpizR2hrMTQwqOYME
         sjKNs0mkztwkY683ogPKvE7tUkNSBQxRzPZJnHHPiVw/sbktZWd8mRhUOavZiy/IdBKf
         uRYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SnLR1Gn+eQGPQf3qoRWFx7ri2DptJjayJnVTdR/ttz8=;
        b=AEut/X/USFg40JbCJh4ZqM/q+l3Axcl0pyKj0t1cjUsTkuIMqJcgR9uiZIKLNZqVQP
         /cVabLS39owb3bISuptOXUJTfe9im19r2nWcQu0beCx4k0saTxw31tp5SK4khEaqgIlZ
         xxE2GAkpnwBZRP28iKvPE5ilvDmltGRQyWELtQLgG6UoQTJW4nkSotdlQk0TFY/JMEaS
         EptWs6US7x3ehgYb7ahfGt+HMqJHqz914RyrzisHb1jBnhhHZDhWHiMovwLegxEIwl8m
         bW4kiejXw+NAygyuCXli7E8CEzyDceuLl/sccizfTwojjtvueI2ZV/lc772oQu0Mhxzc
         GJbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SnLR1Gn+eQGPQf3qoRWFx7ri2DptJjayJnVTdR/ttz8=;
        b=mB2gJZ5GWwUK86vxJ6xUxwmAHwZON3iNhpDHzM1ZW+NWEieyFONZbcRF6PesARIE2x
         inrOo6dz+YPHRA7YBnomKrpQvd07BCzDgerNhi4v0K2SegJXCts5wv0mWvUAS+wUInlN
         xbMnrXpM8SJEz3b/zE4mJNvxxSwtcogu7jucWP0KQIXhoRrrClQ6jUq6b5BvYlZ2x63l
         5d0SO2hiFCI2pSgo5VfpsxYuA1ZKqpl+5AEADilQiQ7u/QNdk/67vY/glwAvfrZHjc2j
         H3hUWEM6laL8c3oUXD+Hunc/dviTgTfg/X+1Aqb1I+v+y+xJRHCXY1DQNUC+XCD8fIVz
         dzJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x3Rod7MljJPaaqSNPW2vdqwBaZQw9ek7385JZ5PGowC4qGx3M
	M9767qrZet7IsyGpQ5Sj8m8=
X-Google-Smtp-Source: ABdhPJywziRFa3JGvP5chVS9yviGqzDa/QLYonJ2R32EG0neXVzl1jRs92TwmWZm7pku428qjHwdgA==
X-Received: by 2002:a19:c308:: with SMTP id t8mr13788052lff.621.1639158945155;
        Fri, 10 Dec 2021 09:55:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls431210lfv.1.gmail; Fri, 10
 Dec 2021 09:55:44 -0800 (PST)
X-Received: by 2002:ac2:4f03:: with SMTP id k3mr14047505lfr.72.1639158944059;
        Fri, 10 Dec 2021 09:55:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639158944; cv=none;
        d=google.com; s=arc-20160816;
        b=cVHWitBXHidfQ9E59rrkOWs1kl+5y2877CLalcIC6RFxjcYmyXNKTEXaty/WcWfURN
         QGmZYtnwZaEIqsQpN2xTCxTnIpvJTpoCnJv64ygutGjsSofZ1Tl6rgGOeaPx5tQNuA2C
         k0bzerJ7JStx6g+ypk3NhPCQqG/m1jU2ZU9ciqklvW4Q0pLp/3Yn4cSycfpmqyxufJlW
         EBl68vMxbxPjfqNHEElcA5QJcLxOCkES/AQEgo+XAGcTUvLXVPNg7RgPVkNH1MD64IrS
         D91a6MK5Nj5ZQYKIW5CRWuckixO5Bdy/+yuzJHjiztLhkr1sCjnxSt699yILOqgE+aSw
         LI+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=krU9gLFRuP2g5yf1CvtY/56s4oeoOZwmbpTn1tQis5Y=;
        b=y70S7Gabs4nS343yxXO3/m8o/WvFVyagnMascjVKChvAgJnxf9j18XDyFiLicegjzo
         43dVpX/AWGbKOuHjmZTrd6CUwjnIOe2ifpcX+qvT/VEdzvFKN3NVzUWuJV8ynnO9NxLF
         RcLqJRw1ZycKjjtklZ2qJ0wwmIiIdLqhXx/ja81wAfam0w74PbEjPH1Z06BDv3aosw09
         DipKmArWW24TibUXzjeIfV7ILncFqfIfxs0aPE0A5uXQ+bAPwc9zJxOeASJHu9/J1rsD
         jWhS/txToeRR7bvA4rpJMzEmz27LHlWA4OxyMtiSW4APhLWXiurM6JJ0odKPzp9y1rRM
         t+oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id f11si215452lfv.6.2021.12.10.09.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Dec 2021 09:55:44 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 49109B8291C;
	Fri, 10 Dec 2021 17:55:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 37AE2C00446;
	Fri, 10 Dec 2021 17:55:39 +0000 (UTC)
Date: Fri, 10 Dec 2021 17:55:36 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 17/34] kasan, x86, arm64, s390: rename functions for
 modules shadow
Message-ID: <YbOUmEBU2TwVAu4t@arm.com>
References: <cover.1638825394.git.andreyknvl@google.com>
 <11f5a6419f8830fdedc84dca5f847543ef7960f4.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <11f5a6419f8830fdedc84dca5f847543ef7960f4.1638825394.git.andreyknvl@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Dec 06, 2021 at 10:43:54PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Rename kasan_free_shadow to kasan_free_module_shadow and
> kasan_module_alloc to kasan_alloc_module_shadow.
> 
> These functions are used to allocate/free shadow memory for kernel
> modules when KASAN_VMALLOC is not enabled. The new names better
> reflect their purpose.
> 
> Also reword the comment next to their declaration to improve clarity.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

For arm64:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbOUmEBU2TwVAu4t%40arm.com.
