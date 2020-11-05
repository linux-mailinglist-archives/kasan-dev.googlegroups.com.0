Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3OIR76QKGQEZRCSSPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 68E802A7D45
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 12:39:26 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id k200sf536742oih.23
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 03:39:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604576365; cv=pass;
        d=google.com; s=arc-20160816;
        b=GEKcjLHGtJzwsKzNCwGnzRTDmH4l8r+7lFg10LrthuSB6AXCNV5m0at+gzcdKdJ0X+
         fRrz4h2jPF5k3k5pdb6yQntLvXadGj+AO48TMaTcrYynQsxpKjws0Sh9zc44b4rh3sCQ
         GbbbZX/oGm/vSkHkO/YsA6ZYidhac+OWZlzrTPEsqrBbZ0hVtVrjVhf6mujjH3my+znZ
         CzpNN5YbDodnEjvsZTRkQs1BA+hZwJZaGdziM/zeL8wt7XSmaU4f7+LfitvS178pXGxB
         JoHCXTfax93NWpu8Sgh8xpxZ9vgGG2WufjfOhya/RQ5DQylFDOHpqh5+gcQy1V70ljsm
         hGcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=uwiN/Y9lhR/pIk2klU3upadLZLy3RF8NoVxBfvOwpHg=;
        b=rb0oDVYU/yNOUa2S9GdsIXh0LcyIH8/vzzM9hWrK6dOEkCiAAX+W7O5Ar48WZwrh/G
         eWbwZHFXPDT50BuRNJ1jhE09mtwa5jKGCEdtwQAoYDqcCRnFsNxnu0fzc7bpLh/GtPk6
         WmdtIRjFlZsnUAcwrqBYrhX3zHWf+cSek40JNtFCgOC0PRJvzlIOkJ5RDq2f8GEHOitJ
         yr7GyJ5TE/+F7rZdbxuOcSSYQuMCOhH9xVnwHzYsQXqLpwN50a3IffPDn/rVdIaIV8vx
         s0Um4YdH3pd9oZrydgTzmjiPwh6gx+y3dcUq8v54jPQcNymUHmHnW30u7ojtftB5RWmJ
         7hpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uwiN/Y9lhR/pIk2klU3upadLZLy3RF8NoVxBfvOwpHg=;
        b=AJNVCF83orJl9FcwuVphES7+heuA6GZwRkD2ogRjgSJiy5QNGT21b8NZjOLyNNDzmP
         LzfEiV36qfN2gDYxfjT+LNofGvMDNuiToEsJ3G6ffjFCnhtzQX8QUpcR+/sEDQlC1jR1
         QeN3VprwJt3dV+lYDpPJZL1HvS9iiralCoQQo12p4ywvejF+MJ/UVQl322T5gGqH7TGg
         pr+zYLJX3FjpbkMAnNN51cBFNMCosP1I6oBdhwJv2GJ6OuD0fqBrZvJP2UNoW7oQG4aA
         HAd4xf733CLcC7wVPCefCnYbRwEsPdc7iapNItpHk5gm2UKWdEC1emOO+Q7O2AmjNO1h
         uHxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uwiN/Y9lhR/pIk2klU3upadLZLy3RF8NoVxBfvOwpHg=;
        b=UYYHuYQSeKi3/HF6dA9y+xEZhpBqLf+HIyEhmQRpewDAmY5zLWimjPfSTC0yR5jcba
         y0aIZRBb38itYzvJD92Rxo+0wMAj8ZLMOXcod+9MQRM4kOBFmUO0ICqgbdt7fB5hecig
         Y8BL64ggzQ68T6B98Bc4cZTqFql6Dz0Ft2rh8L3UyBL8DTQk1uUBP8xugkRgSrX2xPbV
         h7ocXTy/QUWlTiyW2EV38qPqmgZHOe6Vbn3lpTR7/EqbHMBAjN0B2KKRiHKW4SfmYuQV
         sNaFk8Kt1fKeaUfo03GQcvWaOmr43fGX+VzUALGyWgN/db+/DD3Lx3bacdGL4E5JTquY
         /GtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XvtvGWLp5w94Hcwi/NVaJYmYUunyPxcCm/U6ohHoUMnvqhAY0
	Z2AR++xpS4j9h/mvvVj/W4o=
X-Google-Smtp-Source: ABdhPJyZiYHck2JCkxra2yJzxeBQhn3LqPpQEEqx4vtQUiR/KtRDYuN70T23ySntI/qPyG9m13s0fw==
X-Received: by 2002:aca:4b8a:: with SMTP id y132mr1224414oia.29.1604576365295;
        Thu, 05 Nov 2020 03:39:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:14a:: with SMTP id h10ls325743oie.11.gmail; Thu, 05
 Nov 2020 03:39:25 -0800 (PST)
X-Received: by 2002:aca:6184:: with SMTP id v126mr1308018oib.157.1604576364972;
        Thu, 05 Nov 2020 03:39:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604576364; cv=none;
        d=google.com; s=arc-20160816;
        b=ywlUH51dHLZcd5xi5U73vFGXUuqiXINF6AzNhp48vS4CRePrA8ooOKJ7Lrkzx7ZVHh
         rrWLn04v76EXkhpKwMIBmec3+JAWh8e3gCy9qRuYdiNFK8KPgpQOJGbkIc7PdVKgTczU
         8J1htR19/I2Lay3x2qL8nf5YdI6iFtwXTCIFsl/H9Rc1kzn18VswC9pfxKrk1em8h0wB
         mQqWw9YTW2iTF+Y9COvKTIC2/DCQvcWL1mnKPKQ1veIiwGVmhDFAG9o39xpPpu6CxVEi
         D2ToYwTi3ogcnrnS6oP7Jo9EgauDQNjjI0BnFF6CxCZoS7oiWEqKvNHxlUCrIx/vZxLa
         CDbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PnMP+rZvhyZ3d2XlBwYSKL5dvdElfcJJtXk6Q3pbfLM=;
        b=r/nCfr3G5lCfjjefYBAVg105toBSLjsdtEYj+RpstbpzFg8JTMbPisRDqxrhrHljn2
         IK/zS1hzB1S8nlCBceLee7nigqTRsn5nZyH872mJmw/nZG/fr6GpGiIAbGlqaYTTCHAs
         yFwPojxNJ5Jsla+jFUl8ovzkyBErDQCrad8/QbiPFIB0cS+2sCWC+JgcryCUI3cBlx+B
         AnLyXCAy9REYn6ntJdeQtfuyhgChwZADTUWVi60mHeFzHd+9/9TWusHAuzRbebROnUS9
         HikztbPNNDvph0ilUQsp8XTMpHmvfrWv6izVHqzPNxrpw9XaBp5IXub7oqCVhKCS6Lfc
         ZAcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w26si71529oih.1.2020.11.05.03.39.24
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Nov 2020 03:39:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BAEBB142F;
	Thu,  5 Nov 2020 03:39:24 -0800 (PST)
Received: from [10.37.12.41] (unknown [10.37.12.41])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5AD083F719;
	Thu,  5 Nov 2020 03:39:22 -0800 (PST)
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <58aae616-f1be-d626-de16-af48cc2512b0@arm.com>
 <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1ef3f645-8b91-cfcf-811e-85123fea90fa@arm.com>
Date: Thu, 5 Nov 2020 11:42:23 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 11/5/20 11:35 AM, Andrey Konovalov wrote:
> This will work. Any preference on the name of this function?
>

I called it in my current iteration mte_enable(), and calling it from
cpu_enable_mte().

> Alternatively we can rename mte_init_tags() to something else and let
> it handle both RRND and sync/async.

This is an option but then you need to change the name of kasan_init_tags and
the init_tags indirection name as well. I would go for the simpler and just
splitting the function as per above.

What do you think?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ef3f645-8b91-cfcf-811e-85123fea90fa%40arm.com.
