Return-Path: <kasan-dev+bncBCSL7B6LWYHBBCX6VDFQMGQEPXIABSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ECF4D31EF4
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:37:15 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-599cdb859c9sf2914068e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:37:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570635; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vcl4A+JXou1CjC5zC3upI+V0DJdBomAu6LV8mZo7baRrFRMzRqt84HMS7jaZJ6Sg5h
         U/2gXL9XGHDQjKyDLC1jNo9RRAHpKsSsFCusyxIc5NaRQPsr9x1ufSCIvApVhkYb1cNM
         a31+J4SIUl2CkD4iFtKctyPEEDDLFR3dvl4kSEbqqcOcvNDrzCFtWK/pIp/b4ctbqYgh
         0i1s25verQyviDNKi1+KFLOQwfJv4I3StMZS1F6F3HdClHKWiPYb6mCvksi/RXP3IKr7
         KJYY51CboLMQ7p5vdcoZncI+xbDCwA9YZdQc2XlCmG277W3XppD0wgqvCAzPq+Ion3sR
         Q9Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=NhLB3FAyP8aCH3xR4cvZmB/8hzhgI4TFLEyOiAvrvjs=;
        fh=8vozlOAVYYakOXSCjV67UR1OUv26LD2uLYpK8584F2E=;
        b=jRypXkZBCZbZJn8D7gIIX6otLpr8l1dPhdDc1sPkcI6MeAX+qWYv/Jy8Uv4e+2YDFD
         X6PRx4Q6LudgPmXCpgzjqBuCe1IydxKX/JK3YaLmhl6UuJ/fG/3eSDeSWt4ef4x6CQAH
         kX77lRS3scNj+wk/IpuBsC5CqyS+VcXS7vjZYafZ0LR+6yKBRu/MkJWuO0bq2PJ8YknG
         ywU79WTd5Sm0pUDnlCN+W8INWgpiLYdgOPDlOn8Txhy+Txg0VM2CNeFE54luivXNhbBK
         8NQ2ShvWzmCHrOGdOeqJcn1UXMuPnKPt2YwQoOzRC05/nz1BJGeSbZ6tXqv4XHyCmdSa
         iSYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CAsoPXuF;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570635; x=1769175435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NhLB3FAyP8aCH3xR4cvZmB/8hzhgI4TFLEyOiAvrvjs=;
        b=bn3uEsyXjpJ91Z65oV/J/G9CbM5jXC9FTp3y9h2+JIsji/PDBNZq06Xdz+1t8OzQYr
         4QLHVfibQiEtyUyVr3XmMIpaihl+r0a418kEe+qkFYTf4zi0tOcmgG8X0F1+KQkknV1s
         lcnHmw9OT9mPG9JCS4STyaL289qSYwYJGd2eOiPdRJK3idYwtkRsT7lzLFul7J3UwGPI
         TktA67Jy3pDkvGOUlRpDRWQl7awZSHU9tAP7TNrjnfuqLSkoHSixtCiNYvndhQREBSP5
         ChIqQcHXAXuTCxsz0HDhlDskz4jq+6VWTh2qrsGQ32+ipE1m0WkNfRlIbyfCyNQj/Dyn
         KndQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570635; x=1769175435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NhLB3FAyP8aCH3xR4cvZmB/8hzhgI4TFLEyOiAvrvjs=;
        b=T4AAS3fHOJc1NGzfvyJYR5LVDsag4FIkGvUaOCvtXi2mgbvJgVfvsYcOLBrF01cv92
         77BynU5lNIhyNleHjyiRHr/HXel88qR+0+QS41spbBVWFk5r0uirkOhRb1orEpNp0KP2
         P1Gnb9Tik2WM/XddKfMYeANdo88eoHUPcBGMATcoLEbZfdOAnus/kCE0LR6Xwasqi4/V
         dPiwEFzQn/YJiQSZ54KZ99HDT7Jt964Vm+gjS1jzW1UVHUCaxX5XC+aD0RESi7QbKvYp
         OyQuhTPkT0qXoAeI73gpUg3Bh7aEe7WRapekDYhGbyTPyQuqNQyOe3wbv7jXOr/qfHoJ
         m8OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570635; x=1769175435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NhLB3FAyP8aCH3xR4cvZmB/8hzhgI4TFLEyOiAvrvjs=;
        b=BvaJU4R5cTTgVsJWOuG9XJ1UAMFlOOQ03PZYPXmfltXTgoicrWV2/Q71NQhGnArbMB
         e9CcwZyZsedrpv2fj0IR3qo1NkpUq8ltcay4dS0VmoTVjIOcU2VeTB7DVp4aU4iTYzhZ
         LChQKr4mT7Dv7a+kxjdTD47mPILRuM7f6ciXZvUeJ8+Ydo2qTURHnTsmPUWzbI+i5etw
         eiuj42VN1xyd92LmzL9/MePhIc4KYSnHImK/XZl8HhgyuAuAg0TXWNJy5F4WpFy+WZKS
         ExernsliSbN6+LNw8qeaWWeu+aXAN0TSA2ZtgaPT0kgWmplhJ+ML+7LMoXvno3rwGZgp
         tirw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyE9pSUTafNudRTyV2rM4kM9wS1LpieidGzm2d9Gr4HRh/0YuXM70FG4RZzLfeVI//yLfyXg==@lfdr.de
X-Gm-Message-State: AOJu0Yy1Tk2uHhNPzAlUuEqmN9HhL8MCLfQ9VsqVux2+l8oMXpZewit/
	ZJYOqs98UTaMVOCZro13YLDNtJTCzancgL0rwoWSZCNe5V31HWGe7xRj
X-Received: by 2002:a05:6512:1243:b0:59b:7291:9cd9 with SMTP id 2adb3069b0e04-59baeefe3a3mr1137388e87.48.1768570634583;
        Fri, 16 Jan 2026 05:37:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EBigLz2MxnJzpvtpJK6daJuhMHamNj2PdQ9fy4i4/Kxw=="
Received: by 2002:a05:6512:3d9e:b0:59b:751b:8a44 with SMTP id
 2adb3069b0e04-59ba6e4c96als674659e87.0.-pod-prod-08-eu; Fri, 16 Jan 2026
 05:37:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1AeLE9otCKU+RXnefU+ee6QYjbRV5eLCRRFSmN+4P9FmrOch0ybpQo68ZkKtqsPdZbCct9CgfzKY=@googlegroups.com
X-Received: by 2002:a05:6512:2204:b0:59b:9b46:c8f4 with SMTP id 2adb3069b0e04-59baeebacf9mr988699e87.18.1768570631618;
        Fri, 16 Jan 2026 05:37:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570631; cv=none;
        d=google.com; s=arc-20240605;
        b=X6RVGjxzWGnLP1Cm5Enelfg17uzBSk3dTZ5d9tCxugHbl338Q9vdjeSsSmamt4Y4be
         hk1kmeWx0VS+NlVDZn9vz0JdSpl2LRX4qdcSOCO0SvGJEUocWsEK57OlubitAHdZ4sl8
         oU0HKnkefTZamu71lx1pWV2Nz8euLR5kXIFpnyYT7dnjk+/5lbu79GmPsIm5cGcHtN9W
         v3VHYcx3G0EZK8AlzUptteWhKgCmF9KJYnPAESpC0T5CArNkTiHZozB8VvqyunJMNimM
         S1OSWP69D+7znafg/gMbVndR/uzv3L8OGDDRZd64f0i2XHSQHebLlO88IH3p8AwKrcTN
         YteA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=DngFN/gqjOQfQFekRPoAxNCTly3dG4yhCs5BgGxEbUI=;
        fh=ZJqbs9tequAPaWoZPuqYAZ/k24lkNOoRmsVhpbUaEgE=;
        b=FeOE0fyjv44YxSTgu3RPZoi8z4IHOHUdkLWgMDwX2azXRFRd4kDj/xzmxfkn/BdOZf
         uAOedeKB0ZlQjUEgDXadvZu8VKAVWzQKFYVDxFCksHjQDLvS46IZCQJUvFNM6vvnupcV
         EIP93HkiBOUIriLQCMY4T3/seJ5IcWAsgsMzmh6COznciJkUSORJqVst9Oy16fdCxvj+
         ZOitDZVIkwmb1L/8sBTyvYVvjbJ4kPtuac5AAT9MRUPZpdeF/a21xI3gJ0FqBgvCwY8Y
         MAALyXPWIg9XGjy8pF/mh/j4uyZ3XwAUa1cAt+OvsDjBMitah1ZSgwrW9ctACAN1FYO4
         NUKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CAsoPXuF;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf341ef5si55270e87.1.2026.01.16.05.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:37:11 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-59b72c87109so135836e87.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:37:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWqjzTODfVxw5fL2AHUD7IEpoITXnppf91s1G8SEBED7PXo8Ro1b4HLjbbziTEqr+IVMonIabSZ8mI=@googlegroups.com
X-Gm-Gg: AY/fxX7yQCK+EkF9GXqqIX//sMnl/vzmKliHuEyJf1zgcfh5cvs+j8fS3YBuvKdlsAK
	H5fW1i1FjzDGaMaBXe29EVQJyVcaXbtd6t+0aTPg9q/HSvpoiJH2PpGXYLDcHC3ZpFATlJlL6Mp
	6UWVhGv+6+kaokjyoSCYO6GVJSBT9Bx+35dUrdGsT4591RlrVFeUlcARuMPJ40DUj9lPVe9FPDD
	CXPbv/XWuRGWWoeQzwHZ3CLiwfo/5VJ+pglKknSGdhD46avl82PDxPPGC221x+RSXohz4rBuytc
	03COftMK2SFHxuHoUJ1norGDYZajQN/8GVPxc3/0rVrcfaPy97cJUmgeZQdFKpiQ1N30MnGzufO
	KlojpZKksTnhbOjh42DDGcd6Im+v/9M4pObMI7BlsmWoWrI4zn86JqlTMdsQoaVZr6NBi52HZnj
	C2yoyaJ1yBdoVclTCV4A==
X-Received: by 2002:a05:6512:2c85:b0:59b:b597:f6ff with SMTP id 2adb3069b0e04-59bb597f75amr19913e87.2.1768570630863;
        Fri, 16 Jan 2026 05:37:10 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf397ae4sm781058e87.59.2026.01.16.05.37.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:37:10 -0800 (PST)
Message-ID: <2077c91e-0789-4ecc-9560-550d9b1a56d5@gmail.com>
Date: Fri, 16 Jan 2026 14:36:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 08/14] x86/kasan: KASAN raw shadow memory PTE init
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <9968297ee3c83a73e1fb05c6415b024d1d2d6a04.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <9968297ee3c83a73e1fb05c6415b024d1d2d6a04.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CAsoPXuF;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 1/12/26 6:28 PM, Maciej Wieczor-Retman wrote:
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> 
> In KASAN's generic mode the default value in shadow memory is zero.
> During initialization of shadow memory pages they are allocated and
> zeroed.
> 
> In KASAN's tag-based mode the default tag for the arm64 architecture is
> 0xFE which corresponds to any memory that should not be accessed. On x86
> (where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
> during the initializations all the bytes in shadow memory pages should
> be filled with it.
> 
> Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
> avoid zeroing out the memory so it can be set with the KASAN invalid
> tag.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> ---

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2077c91e-0789-4ecc-9560-550d9b1a56d5%40gmail.com.
