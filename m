Return-Path: <kasan-dev+bncBCSL7B6LWYHBBCHS7PEAMGQECQTZNEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D236C73AA6
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 12:18:34 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-47788165c97sf4973175e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 03:18:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763637514; cv=pass;
        d=google.com; s=arc-20240605;
        b=OxNiBXVLOAfkU7/tASmncZwy+brgUnCDFTOb+aq8sjvgI79PyUGzn0GsrECS7kgtw/
         O/6GWAs9VRKmYarVc5WIHhJprsqAZnK+9n5CgJeJbktJEJ9n7lxC7kgyXWraPRV9ltWc
         Reocmf2lUdjhxjrm97on0FdnRF+GIxxewTuruSpw+zi6I2lrmRvKHsL/0H9thDKpFK3S
         pvG88D2do00YZ8pfJkJJrNnwxDmlicIH4S6S2K6DsuM9m6ZLFOh5+rrB3LLOzhkbFfYS
         98WR29kKOjHu433DPRf9D1+3OWFg7FPWn0BpM0s23EwQfqH8HQGbzYGTZ3lFau0xL57V
         1Lrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=kFEyfOdbsQQgI07jk1Z4qZ9riBtsNPu+Ik04SpKM+WA=;
        fh=kBsDm1Ci/WetL90kV6mGM4ssm6+jUzFWWGgZMK5wiOg=;
        b=jUyHREM8y8GvffgatEnQJLKTdgMWcVlFSRZ4gDIXu1WWMOAZAB165SIniKI89JedCJ
         DK69Zvj7td8AzceQSnNtm5o07VqOS/9epgo4OFuvDq0TUObCLc35qpG2EN76kX0aLCRa
         XtF3bcokdjruh3XmGM1mi+k1J4u4J9v0+MSBc4bxeWPjxzripbef8K0rbZHKgGRU4264
         58FeS/I53xveTexCl2eq+r2YKp58yp9WCulOH+3kU9nIlKXZv09njccfOESrb4iZM2S2
         FbL6cYUbSbHTwWbiPuW79G0vCwz3VEh2T55hLlIEK5/4+Ww3dCtGEY8pjPmw+XGWVll3
         mMdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c5kr6yim;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763637514; x=1764242314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kFEyfOdbsQQgI07jk1Z4qZ9riBtsNPu+Ik04SpKM+WA=;
        b=Kp1fgxkr1Q30XRQCvzRS/+OvRx4cGj/qcZKbMZEGkn2tWRn72DIlbQVPEdh79bIWgk
         ia0uruDCCqpF99MBynHpisUyDRWT/gnyMwTZLTb4UVAShKj9h+0C94PPuA4hQ2fdkLup
         Z5bzw5Ul/ImsNN2qaBOqbc8NU/XL8rVrhAN51K/SSpYh7n+vnH+2sb/7jLP+WeHT+l+v
         rHWKZcIiyQg4Gqp4RtNuSZ4s14+EMbq/PuTulGbX+4JrM3gbkoLIf80R804ZAY6tkKJW
         we6L8/p21433wAOdwn9JGfu+kdIYftjb4MzYI7CsSC20dPGkeG+K0668yoPsCdm59nEI
         LAOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1763637514; x=1764242314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kFEyfOdbsQQgI07jk1Z4qZ9riBtsNPu+Ik04SpKM+WA=;
        b=CtCopcpNe696UpPSrAKXOoWFN/V3rWizwXg/A5amYUbNxTlc1r1OQD5eV9uSFUKf+B
         5qxZcJGE8oS/Mv2HDMyoJkJS1/i7rkgFF2jK8AJvBo26HbPO+t/i/ViY7+q7qM6UtoeW
         ixkWHf69oqkjqCncjqtDbYsFbbLfxcTWqF05gOGSvF/Tr9oEdKzBVmQmQDBDVayHxXsp
         Evvjiwath1MFfMd8sHuLlxO+2qC6deaw0hq9XLk/sWQNiaKiHEkNxNcG8RF0J5FeXOz5
         taZLVEnhC2BLmfia2XAVToeIo3zVnYpPOfu1BJwptpeGltzgh57lqFNvHJuO5r3DeH/v
         JPtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763637514; x=1764242314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kFEyfOdbsQQgI07jk1Z4qZ9riBtsNPu+Ik04SpKM+WA=;
        b=R3Gb3U1t/8HFJFL8moZEeXlmUytayrZBjPi0u0cLbKh9Xp2ISXV7XWmMbSAwpy1ahs
         LbTh/kN+/9z9nB3LW3szkY0xorWbW5pqJVySiJcQo26/MUgNYTk63xoxoB8HDZ0UiuIT
         LAsViUbW1klzUGdXLX6LLG0z1PTHBKW71Aludocm6r7Bf9F9iPh/muCe+nFPxc0j3yVk
         6kDsjBl0sFy6mfqkRsGk4zFnYKTu9VT7F2KhxqAOFf/sljDRZBIXHcZ+q0Sh3Q3siq4X
         OWwsN5bIJM2bN6fIeQtyVADyFxLevDi/hLDDMak1D6xPVo9yEz0t/okxUCNraBh7RqzF
         i1lA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5p++nwzaqLSOrkx9/lHyyeOAlOxq9WJJHb67G8ItZ32AGN6PMPv2fdQ/kKmJAYQwrywDW+g==@lfdr.de
X-Gm-Message-State: AOJu0YwQpaRaiLHuq0sFEMMGC3AvUxNn/f4jGeqyZhUo7F42Qm7a0Qet
	VI3+ioBcRLUzpUdsH11ucvDieO6eh7dFxJnkv4LMeNPZvO/9KDx828G6
X-Google-Smtp-Source: AGHT+IF1rv2Nk2JHnf1cYP5/JYjdCY5OMzcfVh1mH3jdEKn3DxDkuPPnUb5nDOGlNQVtZ2rQ6gcN7Q==
X-Received: by 2002:a05:600c:1907:b0:477:89d5:fdb2 with SMTP id 5b1f17b1804b1-477babdc713mr16501605e9.14.1763637513561;
        Thu, 20 Nov 2025 03:18:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bi+w6FGln+o6k9jIbzYRmHAu/2X1eKmmOSkbw4L0LYjg=="
Received: by 2002:a05:600c:3490:b0:477:59d9:8ccf with SMTP id
 5b1f17b1804b1-477b8e1c9d0ls3807295e9.1.-pod-prod-01-eu; Thu, 20 Nov 2025
 03:18:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+8YK6bC88Ynokki51Fr502WPxTYaO8b2X9c7+kXTZWxuD/jTnq4wlP7eQwlhxenPsB12eK9H02I4=@googlegroups.com
X-Received: by 2002:a05:600c:1382:b0:477:a02d:397a with SMTP id 5b1f17b1804b1-477babc1fe6mr19526735e9.2.1763637510566;
        Thu, 20 Nov 2025 03:18:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763637510; cv=none;
        d=google.com; s=arc-20240605;
        b=XZmSxvWmWsx6qFuZXPJ4LM82XVxHILi76Bbl2EVTrnCY1kn3ok8NDYi0FUW1WEd5Hq
         lGTeF+4iWzGvdoVjuxKClqOpNXivgpgN2iCIEdHcDLX50hjxB5cRyvuN9nHGg6QPicyl
         60Iu+fC970oVQLbcCZJEFaVu53n+BJItdRqUhjkiGRu0YG/TtKGlyixPa5BeYDzupJGv
         eLdlgjNgBnY3Soc0zW+SCs43SOpdC79Ljhd11MI5sRV7Ut0dK3t7LnE/81Km8W9MrOYZ
         0N5JzN9r743flojJEd5+I07BD7PppnxTiArbqPxawxDw0ArUHWeCb8o41O9YnjEgEfek
         catg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=dF/pjzfYykuLtKaPyJMWY8rSAkFJWU7DY4gOk+0f57c=;
        fh=CydNqfIYURI/xQ+7EQ6YbWA33H1yEbEZsKYXc8e0/1U=;
        b=KB+g3HW/IcpwFhnrnN/Tq5yfi5U4knd7M69xuH66UCMgbrzux69PSVXeeVYWK+xEtM
         Xkxn4FAVMl1wFUBOaRZVr4BmJNBynsyK/FxA9eQRi6A95tuUPBL1nEh3B4IOZYKxJJZa
         GGN7j5i5AzlMQ0Z92GbQFhkv+Qh5jkDSnJGvdfkROK3GGkmRsrTw+vWoLHaPmvrJoClV
         L7uRSGrQXShPpfKoXY+xQcpid+N0df96p6vM384TYJzrvcEWk0uEX0WNBGk7iy6OiAAc
         bawf/envjs4h689S4N5KBwZm/LlkG9fF5kXC5oFtsWJox1QAbWiptXd45GMd293kojPr
         SRRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c5kr6yim;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477b82e6a85si197535e9.2.2025.11.20.03.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 03:18:30 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id 2adb3069b0e04-5957a623c7fso164919e87.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 03:18:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWtsQlGaAAQQfh5I9PjkVN3jRO6dk88E/EIiWR7jyWHzVN+E1JL5076TMBv2Qap8eYB34VO7sUS1OE=@googlegroups.com
X-Gm-Gg: ASbGncssj2IuDhCLLYPpakaN2RZT6p3yIbbnQSJQKb9BP9ZEggHiSteYjh5sUzEp41L
	gvAJmyf5q0krBRK/U+Ki8lvMgTZohnEbVVk6nGXSG1/zcXs1GKM/6ZHYRiPm+dSoWSC/O0XIZSD
	N+jqWBSyyyOR+Q6kQI2gHELbeeVzAPEMSjpezGC/sinyjVs05fXF6UFprFAaPeRR+dM5/d54Umt
	3srpteK2IrgWRdMaqJ8hE8DFJ/TEwhPX566DSSDm2MJSGO9OVSjCY/XwagIoxHRl/OcXIsriqSq
	vbxKAiQeUYvN7TWUn6vuz1GP1/fM/GgjGt86bcUdvn8krHnenCa+/5fcD/BFrG5OPnyGNoa12/H
	SSDJAdtfWHlAHC8oT6kx3O/58De6HQqLATb67v6hbdGdisBLTSoZo49kjrIiwsC3n5FdT5w6o0g
	r62OqQpiF5bDCxGlhsKb1979vEjOi8
X-Received: by 2002:a05:6512:3d25:b0:592:f3c8:39d8 with SMTP id 2adb3069b0e04-5969e316a89mr487099e87.5.1763637509408;
        Thu, 20 Nov 2025 03:18:29 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5969db75632sm601938e87.9.2025.11.20.03.18.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 03:18:28 -0800 (PST)
Message-ID: <9e066a2f-28fd-4da7-bca8-c10f7b58f811@gmail.com>
Date: Thu, 20 Nov 2025 12:17:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [linux-next:master] [mempool] 022e94e2c3:
 BUG:KASAN:double-free_in_mempool_free
To: Christoph Hellwig <hch@lst.de>, kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, Vlastimil Babka <vbabka@suse.cz>,
 linux-mm@kvack.org, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
References: <202511201309.55538605-lkp@intel.com>
 <20251120072726.GA31171@lst.de>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20251120072726.GA31171@lst.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=c5kr6yim;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12b
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



On 11/20/25 8:27 AM, Christoph Hellwig wrote:
> Maybe I'm misunderstanding the trace, but AFAICS this comes from
> the KASAN kunit test that injects a double free, and the trace
> shows that KASAN indeed detected the double free and everything is
> fine.  Or did I misunderstand the report?
> 

Right, the report comes from the test, so it's expected behavior.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9e066a2f-28fd-4da7-bca8-c10f7b58f811%40gmail.com.
