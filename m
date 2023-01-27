Return-Path: <kasan-dev+bncBCR5PSMFZYORBBVQZWPAMGQES32JPMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EE0867DCF8
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 05:50:16 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id d130-20020a1f9b88000000b003b87d0db0d9sf1512956vke.15
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 20:50:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674795015; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQT5jMOnN5f6IDc/OlqKBWIL5fgZ96DfQ7NjBXm/OxIkbtws4L1cD1M3ZoQmORGLci
         l9xYMEPCts7Ev/N/4sNZu3g8reAdKUpyL91UIRHKtPCYwGjPX1L4pClnQJaCNLp9Gllf
         x3IjyFJPc1OvMJhkhsffdj9/kkEvxPUIFlMvBqjGKb0SDEtP8l/wfb4ouBvK4xWd06qO
         qiD+3xpYDeoLDPmWezcaNQ9+oPjEYm2o1RALOJhrai99VOUcgjaJ9AAX/mbHUEaMfQ6t
         8zSTtAijgafTjsgCyobJB+cj2UsFThtQhvPblGH1o4RagGwdcJ4IzLUbEFMYtkdZzcie
         negg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=v/7foTv4iaOckD5luVPcP/nX4SE68hnkUGdwZO0CVhM=;
        b=ZjNoWYgnqPjPFzyoYOWkPfcy3mhYtKyDpUeNT0qNoyu5e0O4mKiziujrrX4YysioMW
         GobROoB9hrhgE+vgvc3EcrRaaxiaKeBhLE40QDVLttC9lSdTqo5NBPk63nLJX5MIgr6v
         EKYqpuFBbjRcDxv2VBvLsxZmXqm6EdGmm0CnSYeB6FVxLrN30bn07Q1Z3tK9kve8Od+V
         Tb1EGpHj6+CmRdmsY3cegzi2XjUGU+PGtPwOb4AIi40N0HzNkK0pQQpQHSgryxmRff46
         UcLW72hzOhcww4uLaogo4jI2gcVhDvtNhcyJUDQOwd8d1tKidtMMRb2Tkk7+c2m/8z9x
         CSvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="oSu9/Iai";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v/7foTv4iaOckD5luVPcP/nX4SE68hnkUGdwZO0CVhM=;
        b=G8cglLDfhmOmcK62ye53DAEZH32I4OB5GFVFvwq7nzFhYbhqeQWdtytv67TsezRD7/
         AnyFU6d4k8Y2kbCkgErNrNdfd6Yzzn1nREDAS7Lyn/U/3z+tMJoB8uoTcQy6nwZu0Ojz
         beYP/RAyhXcjz/RrNNFmW+RH2caknHPsIF9g2Hok2kBDzj1B4eBoYx8yMN2PyWf+6MTw
         KbftvWTak8B2hxALjpJfovevQMpJjuGC2AJ/EruZwIed5PFhHk3oWgky2Y8fo4R3KkRx
         1FMHix8fc9r/2VwakcLWtoA3KOr/iRFwru3nDCKuPcPTpruBl6QfcwTz0omc1exbp3cG
         f8uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v/7foTv4iaOckD5luVPcP/nX4SE68hnkUGdwZO0CVhM=;
        b=KkK5L426cmwEZzb8ppq9QgzKZKEPLFQg4WKZsmplL4FBy2HS4zTMhT/oQ2W4/3nmcs
         YAS0aA/jprwVYY6UynjVGRW78IO3GQqzNXpTReoSgsyCOZ7Pr3aYtDjpJkMUExhH2/9r
         0TpoyqtKLk19X4lJ64UHuUllrdNDWqq3XcFRiyIH7PSPp34M7YQTDXi6n0A0JgVEQPWv
         k2nxoMOsClaOOidhKLRXcl1CHs3xnBqNQF5G7ApyGfh9JEOsLLyFFgNAvTA4iIPCdRJE
         jx78F9Ymo9/418dOzzyixm3rvduSZrjLCf8fCISb6SwMZAozweyvEPOuqanw+GK4vRhM
         9vxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXShOFDFfZ8Q7eJ78UVYzeF8HrF3K6hMFKTqT9vMLkA5Yoytnqc
	98QIHoQU2aGmhX1ONiwRnT4=
X-Google-Smtp-Source: AK7set/FPVYGnTYYWEdRPF95DYhJcdlkW6OafBrJZZg7GBXy9NdJo1VwasSH5MIhEnKAOvqKO9n5mw==
X-Received: by 2002:ab0:15b0:0:b0:657:6ebc:a2be with SMTP id i45-20020ab015b0000000b006576ebca2bemr1103024uae.64.1674795015207;
        Thu, 26 Jan 2023 20:50:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f413:0:b0:3b1:1703:92cb with SMTP id p19-20020a67f413000000b003b1170392cbls1350433vsn.1.-pod-prod-gmail;
 Thu, 26 Jan 2023 20:50:14 -0800 (PST)
X-Received: by 2002:a05:6102:d93:b0:3e8:456f:3750 with SMTP id d19-20020a0561020d9300b003e8456f3750mr7164206vst.31.1674795014154;
        Thu, 26 Jan 2023 20:50:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674795014; cv=none;
        d=google.com; s=arc-20160816;
        b=Fi2ERD9uFG5RSKrjfuwlnHkLNHLnWIOyEyFP12SVn9ZzWY7ScbOEkPbqVucaoHVBI6
         gC03S8JJPHTjEE0ate63+PGlaSPwmGYlkIU/MdVjxBfSbBMsXL1y0+SxzM6Z0HFdzht2
         PWt6Hv8MQUzJyuZZs4cY7a6Jo21Ox4P6AtIB6kVlRt4czdywhnFmo4EPcr5bNr287NMl
         +RC8Px/wSm8VxKn8i+0J98T7/UsTqZDj2AO0Tc8nWQZr70FKK5waYs7d0xZYGoqttDmC
         lWIJaUv7QCazOYiIucBhDmIgXq+p5zXUl7CT2n4VxZg6khsejapNaSXUbTklgmP/ypNQ
         sFQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=xrXkmoW88qRFi3cS/J8wdbXij99nXqiP/sRzTWWDpHM=;
        b=rVGP4KDzZbMipOyRKkA1f4TNFKsvGFRfyOBCRYNa+o8uugWmZeg5E7ocvjdCSKY9vc
         22aLKaKctr5AcU+rn4/HEz/Bey+A0R+WC86VLBLpjrN8vGEbuLEPo2olfNeDGd/QwSDj
         icNC4XnKfVsJJ3cVRT1UxUi9kgiHDSYLQXHsbScLkURl6lFf7XDvOKhO8KMenutU3OKV
         +8kKNL2bMpmR1K5p9OeAX2Q8Hp/TN6QzmQ0bkefziS5ZsqaDsH0ccNANmZGPFsX1S2kW
         tF/zerVtkZ7h8+ZyEBLxgyrGp9Ru9qeO6Zz33zk5dUPvEiSqiNPEirKl2dbPGS96IA4U
         AorQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="oSu9/Iai";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (mail.ozlabs.org. [2404:9400:2221:ea00::3])
        by gmr-mx.google.com with ESMTPS id f1-20020a056102150100b003d3da321f9fsi325231vsv.1.2023.01.26.20.50.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jan 2023 20:50:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) client-ip=2404:9400:2221:ea00::3;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4P34rJ02zQz4xGM;
	Fri, 27 Jan 2023 15:50:07 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Andrew Morton <akpm@linux-foundation.org>, Christophe Leroy
 <christophe.leroy@csgroup.eu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, Nathan Lynch <nathanl@linux.ibm.com>
Subject: Re: [PATCH] kasan: Fix Oops due to missing calls to
 kasan_arch_is_ready()
In-Reply-To: <20230126152024.bfdd25de2ff5107fa7c02986@linux-foundation.org>
References: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
 <20230126152024.bfdd25de2ff5107fa7c02986@linux-foundation.org>
Date: Fri, 27 Jan 2023 15:50:01 +1100
Message-ID: <874jsctwcm.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="oSu9/Iai";       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3
 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Andrew Morton <akpm@linux-foundation.org> writes:
> On Thu, 26 Jan 2023 08:04:47 +0100 Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>
>> On powerpc64, you can build a kernel with KASAN as soon as you build it
>> with RADIX MMU support. However if the CPU doesn't have RADIX MMU,
>> KASAN isn't enabled at init and the following Oops is encountered.
>
> Should we backport to -stable?  If so, can we identify a suitable Fixes: target?

It would be nice if it went to stable, but I'd defer to the Kasan maintainers.

The kasan_arch_is_ready() checks went in a while back, but there wasn't
a meaningful user until the powerpc support went in, so I'd target that:

Fixes: 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only KASAN support")
Cc: stable@vger.kernel.org # v5.19+

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/874jsctwcm.fsf%40mpe.ellerman.id.au.
