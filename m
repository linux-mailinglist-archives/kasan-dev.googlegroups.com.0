Return-Path: <kasan-dev+bncBCSL7B6LWYHBB7MXZGNQMGQE24PPMEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B72B9628204
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 15:09:02 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id x20-20020ac25dd4000000b004a2c484368asf3271749lfq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 06:09:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668434942; cv=pass;
        d=google.com; s=arc-20160816;
        b=IkJ5guePCxQab+Cuw+gtsANyd14/AAtgJ6jGlIX8i7YbyLM2UkMhMda2OdUcYxBec2
         ukz2YgZSVEtW/I3JUqgs3cOsSHZNINwKSG+r54m1qsVoHCDNzdRK/Rzgh9Qiyq326j3N
         TnOYD7he49UWsXK4i2C9jCNU+mm6W6PEGLobJlNG1GYYoOw6+YJKzEAXB4rRNfhgeKXV
         ffzNEPQNNGtIhx/QFGHEwngls89U9EWJywsNftz8Siq98c6PLC4vQDjuYtAUVOYRXfAC
         NGbuCdJJtpIUihU9tG/l0m6tTJYEFue89z4jggwNH7oIYT/Mtd6qPlD4SfPPYYDw6/kb
         o97w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=gJX11a5YYelS7AxdWbIsj2oeGO0+rQ69aefly4ZR1LM=;
        b=I1uo3OL+/HLKZ1YVaKUfeoXApOGdRTc+hgI8NrTZiRr22oOFXabc7TdFGGOkF9qg9d
         0KjzpqE0oKl7A9xohN6t3Vp35AsWZFfsqteZGt5ud5M1QbX1qejvScEfaZTsESkJHWEv
         hDW+1iPDkR7NpIKldZA6E7Gelj10RnG3qtMEHrxH+62o+yRHVTT+7HjnhQUe6WH46dUl
         4Y0cwoDSkzyAcuCz9h5dHxgJcU09npN3BWJtFMNb9q7fZgKfpKQGbwrTahtcGs8zGG/E
         ajEtKTey2N0Zaxj+cnJnu+SUMf2+/VvwEksS2zAfVnu9qRQF1Tou/iU2clI5He9XU0IV
         jssg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lkGMB6zU;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gJX11a5YYelS7AxdWbIsj2oeGO0+rQ69aefly4ZR1LM=;
        b=V8j3FmTCKhhWU+EsaKKalGLO9aHsjLZ18KDT8fWMXa97hrNPTklbGANnK5VVdk5a7r
         5M2x2SaDjJh2LZeHpqAwyKK08bYmedl7+QXMjP1cpvJ0hfy+eoQMzYKUXpKo+iGm/tI9
         LCswqIzay/89xsDh4FWQnvgpG5iUqETo3VFxbm72YyMrISxRUPOgmXycCe4AwFrLsm1/
         GR+FQsTf0uX1Ydr59Cdpp3ARivjrSsVSIZK0TvylbQ2iXjSMKcjnbtw7AiWcM7brKqdj
         f85kr3wFhvp0rgF2uAU+Ig41uzWeX1aBIeELX/7Ub4XI/KoylMaRvo0hU5ELrBvsVmkn
         ihsw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gJX11a5YYelS7AxdWbIsj2oeGO0+rQ69aefly4ZR1LM=;
        b=mGTQRO/m3gGnqLY86Z4+ULfqT1fe45asyrxVZs07d2zCxUsuYkZ7zUqNTUETzHfz+a
         PUI286xXGEAw59cFuZY/uuHWptsKNyS1CxmUAiNyDd1V6i3nDhsx3OqZOR/hmp9xdpIK
         8vwikwiTid0PBpOsIlinGFOAIGqeUKdrlX96Sgyf+GV0XVUHXvslJp0Z7IzIEeDgB27Y
         UMGVYmb7H3JFKRU7qKnm/WRp7r8k+vAiYue0IzMrYJ/S44tH4q0MVA5vo60psW7eOh/3
         b61oiGnERxbQSVcvDRF7RIoi7fJ0pOv/Vdtv/Q8rJD/M/g96Uf/jUHR+BG2qI+4JBuyn
         YrzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gJX11a5YYelS7AxdWbIsj2oeGO0+rQ69aefly4ZR1LM=;
        b=neJfFnV/TR/0JN6d8sGbiUhBskshQLVW+CvgTUOanjY4zYNc9kHoHkFNqOqgJn3jsO
         eCfZYmN8Cl7oioLXmn/F6Q6LAg3wLwmXmviHrD+70DjyeQd2WN6Vn0Y2pstcL/T84VjK
         dVp8/MAUNNqnTLZ9IMacidEjHgO0QLV9Qi8potxxC5BpNwsmDSHxGK+JtoU4oneAXKzb
         kKCiWsfm7HWBS1Hxg0NvZw+QYivmcBI5IA8JKy6J1P18NDIPVzpL4LODp1zlcGjsmr9X
         EEAouBeR3OZM+k7gp8/VhV0A7HLWv77K+ggYTBvs0JQ9TenKZ7eyQ8VWH0MZTDVcW619
         1/nQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmXMHA5xGBGCQ5Q9mL7g/fY5kGbXBtx1qUOWw/Peb/TOLOmyAHu
	h28QjldtaQdIdYDBqOZhljA=
X-Google-Smtp-Source: AA0mqf5lx3nTLMw8XnebGU196R5CgYYha83kge+m4xPso+nlw3MaFcXHGf3vji44uRS4qhZxfWW+Tg==
X-Received: by 2002:a2e:9982:0:b0:277:2b10:bf69 with SMTP id w2-20020a2e9982000000b002772b10bf69mr4623320lji.392.1668434941827;
        Mon, 14 Nov 2022 06:09:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ef:0:b0:494:6c7d:cf65 with SMTP id v15-20020ac258ef000000b004946c7dcf65ls796863lfo.2.-pod-prod-gmail;
 Mon, 14 Nov 2022 06:09:00 -0800 (PST)
X-Received: by 2002:a05:6512:2347:b0:4b4:a14a:c958 with SMTP id p7-20020a056512234700b004b4a14ac958mr361689lfu.579.1668434940392;
        Mon, 14 Nov 2022 06:09:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668434940; cv=none;
        d=google.com; s=arc-20160816;
        b=jN7TB0ctKQKxnKjwREsP/W+nuvPWIIrQo4wkznicijhqQJi/KdNAqiu71QnKlB2lh+
         ZqbkjyPpOATvp9W+bsLPWLF8l10qi88uQncX3aiWto1YMU5Vt2AQOPw6F769dv0drGvh
         dpyNlWHpmoktlSgg9jaq64PYTuGAeo/nokkchiTkiUJiVFPoSQY4Yc89jKeQe0UuB0ux
         n+ZWEBZwCHTa4BIfPnbuVHg7vqwOVl8ZvFbBmsUxfePXopg1VP9xHCktIRspAntjeKiL
         3iyJt9FtClojFE4byZtRmOOnwOD98HcNc7pfTtO9vCLkK3Ufv1nhySCHE9fQePIwkJGp
         T1+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7bxYVgpnsGzW86VQq7hMIoZbZDot9yO7odIkSzWAAKs=;
        b=iKFwm3usWh5CHnUc1Fi3I6rp+Wy9o+7hQgIcIobeZuM2ZM0jEIi7UT9aQaWEEMoVR3
         6lu4XFHIuurtdwbnWcKBwUH7rdHBQkGtrxzt62RVbvNBKGn7vV9u7pZrwQNrXVz8y1vX
         UWc3Q3sq/0Xjn9gCGPqaBVj3pPbdz9+oPWUvTum9b/FL0IIDbXQ1xucarHVf8DpdUew1
         ljS2hPxgobpHhPdlYuXvQq0Fj8oOlKXRIJdrN/DsHZD1PMbnD9xqaND7xVKimQHJCQpf
         +FTT67JUrVg0ANNefUq0SWTy37JT4OzJu7LSnGXPyKZt7sSnGcdGsc6DQTyxOwYYx96n
         xXhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lkGMB6zU;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id m9-20020a056512358900b0049c8ac119casi328127lfr.5.2022.11.14.06.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:09:00 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id s8so2325123lfc.8
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 06:09:00 -0800 (PST)
X-Received: by 2002:a19:2d53:0:b0:499:cce2:12d9 with SMTP id t19-20020a192d53000000b00499cce212d9mr4578763lft.4.1668434940040;
        Mon, 14 Nov 2022 06:09:00 -0800 (PST)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id x3-20020a056512078300b004a44ffb1050sm1847952lfr.171.2022.11.14.06.08.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:08:59 -0800 (PST)
Message-ID: <fda48075-783d-1833-5f1c-c10ca2880a56@gmail.com>
Date: Mon, 14 Nov 2022 17:09:00 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2 1/5] x86/mm: Recompute physical address for every page
 of per-CPU CEA mapping
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-2-seanjc@google.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221110203504.1985010-2-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lkGMB6zU;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 11/10/22 23:35, Sean Christopherson wrote:
> Recompute the physical address for each per-CPU page in the CPU entry
> area, a recent commit inadvertantly modified cea_map_percpu_pages() such
> that every PTE is mapped to the physical address of the first page.
> 
> Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Signed-off-by: Sean Christopherson <seanjc@google.com>

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fda48075-783d-1833-5f1c-c10ca2880a56%40gmail.com.
