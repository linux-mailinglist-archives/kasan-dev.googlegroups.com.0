Return-Path: <kasan-dev+bncBDDL3KWR4EBRBB55TGAQMGQEIPN7CLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 700C4319CDF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 11:55:05 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id c19sf269559pjo.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 02:55:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613127304; cv=pass;
        d=google.com; s=arc-20160816;
        b=e9b2XAutfAUYu1FfQcXMwI244gTSK5UKjuK6lNXorqkEL60e8iGL0FTtWUKMdebB+I
         Itk6KSS+X6iXkcRK7MieZNwNlOsxnGtPlJf8sA7lteUMN7UjFpmnqj/EG++G9eSEHoBk
         M3NjHfE6HEGnUBVWPc9vWO5KxufiLjUGPrbr2zJkD5jnWCrjyIn8Hm2xwTJ7lEbHQMEV
         w28m0R9gPmhOrrwi4PZt37+w7vnQ0elvtm0gQmxIc0YYL+XKVxb73i8J0xGnsB7+nUxc
         13mIjpMZiB/9IVezE4hwePor94YVbyfXEc0PRFuV1+dfWFjyhOno8DkIsEf2gLK4xykK
         ZvMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=PYG877GbEagLbO8OIZ8JenvDBUfG6nsuaouQruMG8QU=;
        b=lYzNsPR26irh6GpOxOUueBaZn8bB0ttwvhZCoCwBd6ZBFVrn8Rd0MRjS+vWN4LNqn5
         xx4aQ6piY6Sh7rX8ZKj/Ab6k2DkUnGohSKhJaAXRWuDVwQZl30TK2651rM/YvRkKO2XW
         BxNDZleRvvTFYCVqkwawolMO0qLw3bpik+bVT+107aN5KpDj1TPu0Mnm76Hrt2O5eQrD
         NVEnklzPglM/V1RdAXF6CSdEPt2Z0p/FREY+o4DASSLTB0Kt66qNQK17/GsgHZSM9u7Z
         lOLOF52TpFrDB2mWL71p+W5u4LP1P4qDayL1x+m7FTTrmG+O6yrZfJ5tv4B8J+15HbAl
         Wo1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PYG877GbEagLbO8OIZ8JenvDBUfG6nsuaouQruMG8QU=;
        b=fS+QSGebTbGdnxfgZIWzdupuHC8fuqV6qDPd+uvKZHg4f93t1EN+1dya5omJvkwun2
         6hmbwrcHZ9eKpmtlqmSrOuLxNhMlpfGiNTY0KaYkt+B9QKjIfOEjE4qcyBkrS0+kVEmi
         syZoMJ4gvqkZdlwaLD9ond4uWXJ5ISp2AYqfaXzx61qKvVcxhOQamhx1WnL58K1ZTK4+
         LsHvE1MuS/MbbJ63XIiHshyRdIcHdNOoVsPV492kgmBnDBmPOT68uwMd+CmwNa75NLdN
         hmKJPn12AahXse7DroQA6p7GySbMtdHVWmCNa5LNQ3e2fnRK3Wrahb1HItuuIkdquIC6
         YXfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PYG877GbEagLbO8OIZ8JenvDBUfG6nsuaouQruMG8QU=;
        b=s2pTkF2snBPAJt51ZMEjiLb8f5QbrUHTdH77Jb/S7047By/EGFewEVaQnIY7beIQvj
         Bpf73scmLZpiu2d6vFP/ve6BG54+THJmGDQETBnYIyEKGqDEMKPC9MmC5fsmi5WB3pIp
         k12pX4M6wy0SXsNil5MmTop7kcBd18FmT4q5e8J9QC92zzqBde3zYRZ14ZVfpMOFSCSR
         JbrebShBW5GUGnZRUea4dUoUtpgGhWoGnIUp9YA7ozCKc6USAqe99EabhfGjO2oX09R6
         aymP3X+WzmQHFJs0tv5Lq9ZY6e4b9V9OqYE7EHoGnFEBrjDdWUECpOrn6rkYrziIjpw4
         0gXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PLbRTBqcb74dr2sezUNp56vXwaXROSxwj2MI8onlXkpLybSjv
	6ayPibKWkojjcYL1PKSn02c=
X-Google-Smtp-Source: ABdhPJwl5XTq8uUq3isMunLQKQ/tdkjx8ebaWT1ApyzK3r+VdNjC3XO8Fwgn0WhX9qMkPhhW7Gw+fw==
X-Received: by 2002:a17:902:7c18:b029:e2:de98:59c9 with SMTP id x24-20020a1709027c18b02900e2de9859c9mr2521050pll.4.1613127303913;
        Fri, 12 Feb 2021 02:55:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2311:: with SMTP id d17ls3816181plh.6.gmail; Fri, 12
 Feb 2021 02:55:03 -0800 (PST)
X-Received: by 2002:a17:902:7c83:b029:e2:b157:e25c with SMTP id y3-20020a1709027c83b02900e2b157e25cmr2422389pll.32.1613127303231;
        Fri, 12 Feb 2021 02:55:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613127303; cv=none;
        d=google.com; s=arc-20160816;
        b=diGvv9R9S0q+SiIilekxYJ/vnj6nzQe1VOXRdtddfUBaECbzvLXU1c5t4ZutykTjTC
         Ha0KEsg2MzdLgAL2KHTVHa2f+ffnAnzLz26yWIwmTaODbtN8j6TsXzPyJfGwlC6qHEli
         rk7BsvdCjQ4tZl+l7AZob22cYoWfdXEX9PwnnJN2+w4mVorj+vyq+kph/wRJ0ogV2Hzg
         W3IjpwulUlflYgLfzvaa5ZrYuFqZkOGYhAxqe4mkA0ZOIKvsRUKkEqFV5IDTqW2n8tml
         abUH0rTaiyhcsxlupF5Y12HVVvpVxzR8bkB+6CbTOo88HW2hFm9IwDSSJzGtlaIz+q/z
         Vjbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=l4+xqjXDNO4IQ2OBBvyfruyq0A5tN3dTcV8EaZrzMhE=;
        b=BTCsJ1PIcDmVlLDxiCBPhOFD0TA8FzQgfGsQ+Vs8sI7l9nZMGV8r/0R4DoozkI8xZJ
         lFa1GFjZXYFmtsU5dmFk7HMCfI6NenDdUpBMaYN6HxRYysYn26u3DIqhNNFHlw5jUcf1
         qG/DW6A4GrLJszuHYT0K8uG2SiH2Q/1J2PsPsJ4f6iSY6k6jyI/MrE69bE2rr8NjU8mo
         b+NboqcQzJo1RQnti1UgzHS1x3IJHaaZ28yD5r1szk83EQMNVgwfy6yUgXKkS0YPA7WT
         AzuA1sf1pU3fJfTQZS6LeiPYVPWaCAJ/S+85U0DGd/+GLjxnIpuQXxmygJlnzMClm+Pt
         dThA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f11si402328plo.4.2021.02.12.02.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 02:55:03 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AA47D64E35;
	Fri, 12 Feb 2021 10:55:01 +0000 (UTC)
Date: Fri, 12 Feb 2021 10:54:59 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2] arm64: Fix warning in mte_get_random_tag()
Message-ID: <20210212105458.GA7718@arm.com>
References: <20210211152208.23811-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210211152208.23811-1-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Thu, Feb 11, 2021 at 03:22:08PM +0000, Vincenzo Frascino wrote:
> The simplification of mte_get_random_tag() caused the introduction of the
> warning below:
>=20
> In file included from arch/arm64/include/asm/kasan.h:9,
>                  from include/linux/kasan.h:16,
>                  from mm/kasan/common.c:14:
> mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
> arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99 =
is used
>                                          uninitialized [-Wuninitialized]
>    45 |         asm(__MTE_PREAMBLE "irg %0, %0"
>       |
>=20
> Fix the warning using "=3Dr" for the address in the asm inline.
>=20
> Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210212105458.GA7718%40arm.com.
