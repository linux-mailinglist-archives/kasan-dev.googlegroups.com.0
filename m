Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHGMVOAAMGQEIEUOTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60FDD3005FA
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:50:05 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id p15sf2312565oth.20
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:50:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611327004; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HUOZE3GYrm8qsTHRaTLeIGognIU3kAgihto0AlLF7bgBRdY7D+YK5WYsa/l8ymw6i
         hY7Z6JTUBXI3o6gsjLBJfe1DmY9dFzSdMLOMgrGY3LtVVNvl5IFpTl9j70ciBpQz1802
         WglnGqPDmu0+m0k85VCotVvG8ZFCFjhFWFQ7yvEBk/WR1fyxNDMNyv2INrf5NaTaCHZq
         0+YWDQz1pLURf8fK/sx63hYbWkWrbBempBFITbQCQ2lclc9OhJSfgD/nlASLaEUgKXCc
         RTFwzQqfw8NVDiptIp75ZgRbFWnJyxYPn6k+Sc9qHRWOT7lxNaRIA8XK3bT3jCZYz/g1
         FPBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=mUtzK9dBqvcSMBMM36DfrIqW66FfFurE7bZ+h7w3tbo=;
        b=E3kJ6ccj/gNQur/hfiHg0ZOPodKxQK88E83eRi1aKY5nUBncdmHhPT/GiojzC8CCeC
         +H4jXinn36qIFv6Q+yKQiOVQmy10WKeSSXE7wbx1X667MkQf7dFN4RioujRfLJwemUUj
         dI+FrXcGqwl+/qSn3GaQsCx7QIK44pQMgjFu2xs4bduedO0ktVvJXyZTqwhXE/FOigGf
         CaxwfyiIErcO1pw4RiR4UsHLJI8W6+Si3bL7GySy3QLYI6AYdthJe5T7kToq04ejhDYx
         XmlWtROwxYexwGgtxk6CO1W4HueWYlGswmSauZZa37ZqlPNDc3vPFdxF0+aj2VwYQ1Vh
         LzOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mUtzK9dBqvcSMBMM36DfrIqW66FfFurE7bZ+h7w3tbo=;
        b=FabXoBv74zoozpTc7LzmIVcFcsR1Xt6XPkmcJI23zz5VrObUjDmfb4LrpTozqWpSLJ
         4QKEap+vytrHxB8/K9jfhmot4Wbu38brAsWO3tB//q9DbLPFq/Km3w6uBj4SdSmJ75xe
         PyPGEM03vv19UMXlsSTG28oknVxQnQyDiv6afNLY0Z1fi3C24WusgxfZLCYFm5Nnumqm
         CZfhsDMMm0++mM1gQVokVzp3PBMSIW4K08JD1s4TOg9nmFy3maEPFD+JTz3Id71WLcJe
         9tpTQewAnQcxoZ1/HJ2icOEYEtzlrJQhhwMAgnW6zJHiPRQ6ThAkzcGKK8pGkIPos3FT
         z15A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mUtzK9dBqvcSMBMM36DfrIqW66FfFurE7bZ+h7w3tbo=;
        b=HhPkF5ERcLg0gkCMjNry8zH5/wf/qS9Guac7XMMe2zRh1OCrnzxdqo9EwByAi4Y52s
         4Rod1faJFYFumH1kjdlQDyzplHO0QzrqKlCOKu8SkIcBzLrwRQw+rkvdMVR0MUizuwFN
         MiJI45NMSpWKdZ+3PIRmviDTppGfkYaVnBmp5VO2f8T0bwpWRVjyw/V1Gah3tW6GAhPe
         d78q7MmFexbVdvRLjYL9jakrh4oQEQdSQJLEDyVBT5aF1m78LoN+LKdxkf7PFi1G4Ddy
         qW2p1MKHBFVGrazrlRbjxNrgRvAX91RQg15yZNpMXa2mbbjLfINhK0Jmsx4Vd9mvUoY+
         78SA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319+z6lI+3OwVvPoxXRUE1IeqJLq7t6ii6tHuWRQ51oYU1j4JRU
	4BkAB9WOIWoiT31oxVDpjmM=
X-Google-Smtp-Source: ABdhPJzhAUCd3bSeufVMqMuan+TWeKqZ9DCQHTT70SH9MoPCbQrlDxUwx/d1diG8VG1uaBL/Q7erww==
X-Received: by 2002:a9d:784a:: with SMTP id c10mr3704663otm.132.1611327004257;
        Fri, 22 Jan 2021 06:50:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:504c:: with SMTP id e73ls1536721oib.9.gmail; Fri, 22 Jan
 2021 06:50:03 -0800 (PST)
X-Received: by 2002:aca:b409:: with SMTP id d9mr3637743oif.120.1611327003925;
        Fri, 22 Jan 2021 06:50:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611327003; cv=none;
        d=google.com; s=arc-20160816;
        b=IdoGhRo12lWqjtQfVidAijoo//C/1glN8ykcNUm6MzCAZSsd2zmzPu4uxk9jpIgkol
         CxEMdI6wnHHmwe+MFitkJPe2CllgabTw12Sfoht4lOMR0UVJ5u6NNz95Puz74n9An63I
         CVIlFNiO1SP7/cSWDgzw5G0nayXFvMGERKONtJr86+ZjenIM+yx19K2jTMRaN/dWSSVg
         k3NUBqH9bURts/a2rQsl5vDeauDvwWq3OdU+eEaj6g5lUetWjdyVx01anch2Hd+gZAq5
         mzeYYtTlzlQIx48PN+fJWjfN3yX3WFORZXeBKIvDH8y60Skk7gFpMbtptXBd/oo0Gkjf
         U0NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=bGgXOcyU+5BhT96EzH4EgjliOKAUrq5nKaRGE12UdNg=;
        b=hGOp62jTzTYey07gjTGXRffYiD0givNPf2Y/NwRdD0iPct6DLIdf08DAYvzmJXy+OH
         8Vc5I5QVkcYmC1Yx8BH7CfTgzPRib0eN/Y5+GmNfhLIbLDdr6YCMzdHw9oO8zliYdwuU
         uKv9iU8d7ZENVVCHddE3ffU6qf92SFzVi9BfA40Srgzmv5TMBTESBifljyP3WCRzdM/d
         VKTYFg6mKZrrnhL13ajnT3/+urR7pEgFtg8N8tN0IzVdHz/i2mu/dA/ziiEcuGsorD/K
         hvOKzc3BMmj0LO9H+sFAlsyySEd+6U3WUFXmQRIChGjvLEn19SCo2kJHVA+bGL1EvUl1
         jQmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i2si840067otk.1.2021.01.22.06.50.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jan 2021 06:50:03 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 05765239EE;
	Fri, 22 Jan 2021 14:50:00 +0000 (UTC)
Date: Fri, 22 Jan 2021 14:49:58 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [PATCH v3 1/2] arm64: Improve kernel address detection of
 __is_lm_address()
Message-ID: <20210122144958.GF8567@gaia>
References: <20210122143748.50089-1-vincenzo.frascino@arm.com>
 <20210122143748.50089-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210122143748.50089-2-vincenzo.frascino@arm.com>
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

On Fri, Jan 22, 2021 at 02:37:47PM +0000, Vincenzo Frascino wrote:
> Currently, the __is_lm_address() check just masks out the top 12 bits
> of the address, but if they are 0, it still yields a true result.
> This has as a side effect that virt_addr_valid() returns true even for
> invalid virtual addresses (e.g. 0x0).
> 
> Improve the detection checking that it's actually a kernel address
> starting at PAGE_OFFSET.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

The question is whether we leave this for 5.12 or we merge it earlier.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122144958.GF8567%40gaia.
