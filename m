Return-Path: <kasan-dev+bncBCY5VBNX2EDRBGMJ2DXQKGQE2GQWFVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E3B9311ECFB
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 22:37:29 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id l20sf99253wrc.13
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 13:37:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576273049; cv=pass;
        d=google.com; s=arc-20160816;
        b=nsJhshsgAXOHsEPZBjH9PCSc+E6XyRnbtCNCWbxc8lzZfwawNHh7jii/18GYoi1BHk
         nRLuJKIl7ca1XT/CC+a2Tm/8ZVZj0pVdW7S1Y29O10OebYaPkuetCulQ/N+BHG9+kQE8
         OHOAKN+BNFFsMAcxBVSbkhD3YfyeT/+UDlJTGSkSqkPmz+CkK2VBTGhnlUXgLI3TJZEG
         Cd5LBsztyY1h6yw2bK3WcclYWBOv0xeXDVEo1uSefawvGwx7cRM9/02OmOfVroclDPEz
         GBLEnRbIfi7TR2tkpb44FcYahngKl70oTvaPC3SpMkX09yt7khq2rqDK4aEW4fPpzW4Y
         10Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature:dkim-signature;
        bh=vE++K8xEkDcAMGJfB+MLM9JYRUdlAVlBhpNybpCvDVs=;
        b=av07ANd5pl8osSlQlo2Qbmm4sQgDmQYkbpMYBYsGQXPlnrS+dZpcF/Cs5wDMsyctjw
         GQPVy/NmoJMqliPE8yXZ0tmm6ANeIr5QYKdf1cFHUjCXk2MMuk1HK9SLFp45sbqe6oGw
         bVUvB/2cjCnmC3qVO3ohjMLc8nbX3baEFEaZf2NR0xcc5KwKcD3mw2KAfrmVaNACgHhO
         h8qftBUBDU6/zKNN/Tq4jXBft7296vbCFzm2vBhitB9v9J+9fCyZSkUf3Vm+/9mpMK03
         eIbXjdaxuovZYuwNUFrNhBEtyMqhYkzqh/1WRJ1Hm6xxDXQ4yznuuF+CJbFdDUWHB4qI
         zZwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BkJUDoxm;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vE++K8xEkDcAMGJfB+MLM9JYRUdlAVlBhpNybpCvDVs=;
        b=J+hR1hTwjq8BLQQCEdW1K9DSlf3JMC9wX+II5NzkG44FzdEQYcUjMdv9R0ulbVXS8M
         yhAmb5A38TAU0IMAbpdK8VihZd0Lk8YjOX27LdWK5sPZx10SN5R3IMMlfwt6beqsmffC
         JUYIo0AnvsO5E+RSWCD5AlEI4e4pG/NCykwZL15MQmwXNKUG+cPwO5vzdDdEkqnjJW70
         gwEL3oUEH0eRrdXPNNeK8ybG/kcWj7mNZ9ZGHw2eEhFrT8lrOvTKyvBPIJFgRwjwzmZG
         2vckVjoFbYyQVzS0mL1XhA12i96bHenNpN2K5c9ZmAAZkZz2mMGolIj32k7W7Twu3I7G
         mntQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vE++K8xEkDcAMGJfB+MLM9JYRUdlAVlBhpNybpCvDVs=;
        b=m7RwM4hvyv3GUw0pwLHi//piFTnRO3dJpWaFzvADRiWsn0JZMXBYngiG2K8dU8L/3M
         1V7U3rFRLGWJArSWqTpfe+/kFwR+bh7m1ya0EOk/ucgghmc66HAGeLeps13so9oB8a8r
         /rmr3QuSbTEle74Xkwb2Npzuz+JjvlF8aiKV5VG+GltYngI4ti7pwqbuyAW/kdKtBTmz
         0k3i+ah+6coxPZAzolR7BlPr76Ul+rEQY7Yu5y/UvjuOnerLkHOdD1D9nMTwzspXJo4s
         R2Dw4fSifoGyaDBPgE8fxk+iamdKqOdYaX9cKIpb3qCYzpuoDXEbHBCavOIMRpnU2DkI
         uJ0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vE++K8xEkDcAMGJfB+MLM9JYRUdlAVlBhpNybpCvDVs=;
        b=ILcZEHe9U8Eo4Vsl2xplL1/FxMe0/qoiroBySIUzHB7mdmUkpXehNYntCCO13fFYK9
         SFkdpJHoZ1SRlgYWi9MMvqMDBATp9DABfCYFjyJSWfy2JdvR/LCSJWnhvIV3z8mjA08L
         6wJxxgiHWHVwPBK49g9vT0Hquk3psa7rFOcpoPGyde2sZ9gK8VkqXZ4U7t5iL8qwKonc
         kND7RiFKit8rtSWHnimJx8NXYnlQpFeiK19mW6n+bw932J5RylD+wWQblO1p6Z4yatG8
         onfeHhbQ2PaSoN8CsaeHtTJo4YrjpZQDRbG8m9V6XnEN7IX4Do2bLvdaDYaoOWs2V/9O
         49cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUEkRJEo5PGn7FJDJ1BIIiHhM0iI/Vn0laVl2g5rnjDCjn7iaYI
	wXGBwP4bPRamSD6cK0zMP0g=
X-Google-Smtp-Source: APXvYqzF5pJkILYrdPvNl7OxlEX6VCuNKleCAtQ8UWekCLxCcasQBQzB9S15UBVoNmOlZmEteU7rgw==
X-Received: by 2002:a05:600c:228f:: with SMTP id 15mr16244782wmf.56.1576273049602;
        Fri, 13 Dec 2019 13:37:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls5451435wmb.2.gmail; Fri, 13
 Dec 2019 13:37:29 -0800 (PST)
X-Received: by 2002:a05:600c:2144:: with SMTP id v4mr16508578wml.31.1576273049106;
        Fri, 13 Dec 2019 13:37:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576273049; cv=none;
        d=google.com; s=arc-20160816;
        b=Dn1JeS/1nYlVzmpGc4/v7wM2/Cv2O4nSRLbvJm3otMqaHzjotLE2d9oppGlCeYjo29
         RFmT2wjlN21hYbujVnBjYJJ96ALQILp1pRxXQ+vEMeu3KWajG33nZrboy6XbgzFqJLYn
         3jImDWWQyeT0qtbt7YuLYRyHT9gSQX8QGUrF8w9yfSXWDBY99YaTYuaA4iIW/ctidufb
         g90yJ6sZjweFMeoE1hr1B7ZSe31zAvxSg4InvdT7xdmMPz4d3QwkOMYHoKfUlRhCexGa
         6oDDX6mEIE54TB6eJbWHGpp8P0YxRwMS+4Di06G6Rc5DaQGLrH01hzJrUfFs40X0ePtT
         EVzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=6Cel1cpD0Jtu0AycJ47huuRD/DgMmGpodkanI6OR1bo=;
        b=Ga6+JsJQKhbOPHhQS5KyMY7dwux6OQ9nWvGvMMUk3OTfzd6OkpzULD5IG/frzldWu6
         Q6btkwL5WrVRcsyUtegasdUgv378CiA7fpR/bj0kP4pE7+aS3HHTLWLvEwgAl1k9s7Bx
         kP44xM94+2xZHcxy+DxYsMIzWBJvw1QRaYPnc7cMACshMKElCJQTkN5ElFSxmXCuWgtb
         NgHUHEdo2qwwd/5FMY9HvdI7Vx0mv5O6M+poOOSDpgiLfSq3efKpNbZ9TZ83nWLBQ245
         6T9Z1lD3G1hksNOCQ0b3eAKiTKW9lGBJ/Y51sb6D7z1AeiR3JspArlVd+ruQEwMUQStQ
         A24w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BkJUDoxm;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id j65si429360wmj.2.2019.12.13.13.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Dec 2019 13:37:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id a13so207754ljm.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Dec 2019 13:37:29 -0800 (PST)
X-Received: by 2002:a2e:165c:: with SMTP id 28mr10631069ljw.247.1576273048447;
        Fri, 13 Dec 2019 13:37:28 -0800 (PST)
Received: from [192.168.68.108] (115-64-122-209.tpgi.com.au. [115.64.122.209])
        by smtp.gmail.com with ESMTPSA id z7sm5774631lfa.81.2019.12.13.13.37.24
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Dec 2019 13:37:27 -0800 (PST)
Subject: Re: [PATCH v3 1/3] kasan: define and use MAX_PTRS_PER_* for early
 shadow tables
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com
References: <20191212151656.26151-1-dja@axtens.net>
 <20191212151656.26151-2-dja@axtens.net>
From: Balbir Singh <bsingharora@gmail.com>
Message-ID: <37872cba-5cdf-2e28-df45-70df4e8ef5af@gmail.com>
Date: Sat, 14 Dec 2019 08:37:20 +1100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191212151656.26151-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=BkJUDoxm;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::243
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 13/12/19 2:16 am, Daniel Axtens wrote:
> powerpc has a variable number of PTRS_PER_*, set at runtime based
> on the MMU that the kernel is booted under.
> 
> This means the PTRS_PER_* are no longer constants, and therefore
> breaks the build.
> 
> Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
> As KASAN is the only user at the moment, just define them in the kasan
> header, and have them default to PTRS_PER_* unless overridden in arch
> code.
> 
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Suggested-by: Balbir Singh <bsingharora@gmail.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
Reviewed-by: Balbir Singh <bsingharora@gmail.com>

Balbir

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37872cba-5cdf-2e28-df45-70df4e8ef5af%40gmail.com.
