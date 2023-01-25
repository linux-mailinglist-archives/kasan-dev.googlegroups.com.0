Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBYPWYOPAMGQEHENJSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65D8767AEBE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:50:27 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id j84-20020a1fa057000000b003e1a9db9f88sf7215094vke.13
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:50:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674640226; cv=pass;
        d=google.com; s=arc-20160816;
        b=B8lLdkHHiWf5zIhElFKoFMjvthb8GFt3/PWYcpnV89tdosPAbM4VNLAZGv5KmAlSm0
         ZmqSlbsj8NafvhVg4+Ybe8hbnH1BO/buKd+diirWahH5JHy7Azhm0f7pAmaPKcGrDOAY
         1t3AGkqA5c1oBtPsDN0WwpRluxAnUtx//Z6Pv1gefJ/LdZLMJByRspImCc0X91Cbt970
         Hrv9CsGYkMsIJRlrV3acEXrZyB1ke8+ocp5p2IitlB/32V7M9L4t4JYrOPRFrUHhek0X
         dO4y+LoDxwmV0iwoIPTM5cwDTvHFM5Mz32czEOqhl5m18zg2kMNU94wi1U/BEEMNCT7p
         Ieiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U10p3quDEeaBOnug+uqydTIVt8AzGpIEOmUA3uMqQ1M=;
        b=yr2S1aBGaDFsH2KE9GIYKA4ON/kkXFFXbEWF8P40xmBSuj4e7qXGsEY2Rx1UWtZHd+
         U+07cmVTlNjKBGSKDx6J6KuHUEgKHRKSky7c2cWMD0L3rtT56DtIxmYml8ZtPARnQ5mM
         wIV7nFuAj6/faidxOGAh1W5qLm1aaVLIUB9owfV4ajt0ihNZqyliezsdEEMMbFag0hw2
         hnd3Y/yFrJJnpBVgEpMdL3pjFXMQpjt4mY0LLuMwsKAThHak7ncKwGwHmerJZWYuexz0
         fKfQTIb99LGc8YcEMttsU9ZWOmk/dfRfhlviCAF7vaEqr4yWZyM6C3epE8+v5zHZzYuA
         oplw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JSgpiqWm;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U10p3quDEeaBOnug+uqydTIVt8AzGpIEOmUA3uMqQ1M=;
        b=LQ9v/jHmNUs4zJyuQG/vr8lH7aPBZ/b9owPONK8iB2swF5wS9RG6oJJdj6XQjWXEBI
         DVsZwnDy6XLfk3k4kABWtr9L9U+V4V4Upyku/Uj1mxhyoqOd1TuYsUaFsChaKxOCOFDx
         JMx75mvER/rOWKckeoN8GU1XJCuUDACA7a2BfTD4/uEvJJEg7LoZejoY7n8Pq+1d1xEK
         DC5LZ2gK20mbSNtYh39WrN/UteQUqS3tTBM5EfHu0r8ELngAnQPtUKEeXNTmRdu22+X9
         YejwWfzM5gpBkdQMZwI+jlOG17dTQP62JyGBLzzznA7nl6kPZUoC9C5gnC8GPDLNIAT3
         nXbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=U10p3quDEeaBOnug+uqydTIVt8AzGpIEOmUA3uMqQ1M=;
        b=ApqFgsfUJrmgbU9BxowMGTCvjTxhG8J7HoALKrKnv9Q/CJd++JXCDLx6MOtAR5G4Jc
         al2Xxvm3sv4oYm4Fyv1y1/L85TYqe5ap+tHISuoYNBezmqvgeU+/E8+4Q0D/nsxjlCqw
         yvT3m4TSWM5PjSetymq9bi7++Fh1ebuPvgSWxnEIuRXCetezxDH+esSq44N+7b/Reh0W
         iNKHu9Gk9sQus8pa1KGE5qunQYyU1lhX3fbU1roa+YVK1ykEVlxyb0PfrPUm/2ykiMo8
         073BOtBIF/1z5YD4i76PY3QRy0b4Q7dZDp4yRzHMyvgP82jK9ip/y58479smEQfM9ylz
         MPGg==
X-Gm-Message-State: AFqh2komhD8h4iYpR29KwO6UlPK3G01lENzf3AI2IQsWl2Ol2TRPZ+Ab
	xv1RP+hqkTXdhUqEkgOfScs=
X-Google-Smtp-Source: AMrXdXv/dqtVeiQHTxrh1Lmmi9UkmmykzZisC/SVus2g0xmuyW9tKJYcsrtaFUxRShF16tjBhNmQcQ==
X-Received: by 2002:a1f:3055:0:b0:380:5dbd:1076 with SMTP id w82-20020a1f3055000000b003805dbd1076mr4123418vkw.22.1674640226063;
        Wed, 25 Jan 2023 01:50:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ca1b:0:b0:3aa:190a:9431 with SMTP id z27-20020a67ca1b000000b003aa190a9431ls6283233vsk.4.-pod-prod-gmail;
 Wed, 25 Jan 2023 01:50:25 -0800 (PST)
X-Received: by 2002:a05:6102:5c2:b0:3ce:d96e:d462 with SMTP id v2-20020a05610205c200b003ced96ed462mr18751848vsf.34.1674640225507;
        Wed, 25 Jan 2023 01:50:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674640225; cv=none;
        d=google.com; s=arc-20160816;
        b=sFIYEOP92SpLLUQHYRWx5t0mIn6V2Y5eWvjCY6NGPMlTbMgpEF6DhN5TPDsmkoM7/P
         QI8HRV6DvN3/qU9tq2fNOPhTwA5/HaNUx1jTxuix9PByGmy5fAZt0C24uAgNozCNwx8u
         LnfduC7dHJWLJOeendetxwwocVWdxxCov3vpjhAgR6WXu+hxBF7/LwKdlfTuLWnptNXG
         AGIFyZgYNZ8nfyCRrNY/kHbc40aaS2y7zILlq++k43Xfyu1gMiz3mTV5mxsMDUjcxWsF
         tMzQA5WblLpVmKEE2tTBG1McZZmRqytEB22vS3q5mGZCF20thXG7vlSFfUICP3q2iaQJ
         psEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3dGewbCBEk8znJB/rL0pY57fT4B6zUWIZHf+6ieq5k4=;
        b=tD6YhnvRE7SDfZjAC4FtmgOr1RSaFzARam4/DexMMtgdptTwGiQC3bLKzMyqLl68FP
         YDi8XOD7amiLfFY4VE8+DIAAIO299O9+z1UNjpp6n21n1McdtXDuzEQjSQR5eoHtl4lo
         HB+mIeU8YKeig8AIl8cLqAfWXlqc+lzFz55rtkUckXy1AcU8XgwHsME8XK7QThSUskgb
         PyHWtmpD8D57ReZwMsgeuZsRMSzJUDe7Y2nwbbLB2DVPv38c0cL+Iw7Ue+ea3spO376Y
         Pqgb4F9eOo++R8vOIhBOG9nOARCufi5jxgUCNacxs6m8qde3d1Bsa1+PFAEa3pZ7D7E6
         oVEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JSgpiqWm;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id s32-20020a056130022000b005e51a1a1ef1si516102uac.2.2023.01.25.01.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 01:50:25 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id c66so2827328iof.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 01:50:25 -0800 (PST)
X-Received: by 2002:a02:cc24:0:b0:389:af9:4860 with SMTP id
 o4-20020a02cc24000000b003890af94860mr3582826jap.164.1674640224797; Wed, 25
 Jan 2023 01:50:24 -0800 (PST)
MIME-Version: 1.0
References: <20230117163543.1049025-1-jannh@google.com>
In-Reply-To: <20230117163543.1049025-1-jannh@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 10:49:48 +0100
Message-ID: <CAG48ez246oQD-rdnemBokm+345Uo+OejvVQk1mR4=9fXzbX0gQ@mail.gmail.com>
Subject: Re: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
To: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org
Cc: Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, 
	Andy Lutomirski <luto@kernel.org>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JSgpiqWm;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d31 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Jan 17, 2023 at 5:35 PM Jann Horn <jannh@google.com> wrote:
> KASAN (except in HW_TAGS mode) tracks memory state based on virtual
> addresses. The mappings of kernel stack pages in the linear mapping are
> currently marked as fully accessible.
> Since stack corruption issues can cause some very gnarly errors, let's be
> extra careful and tell KASAN to forbid accesses to stack memory through the
> linear mapping.
>
> Signed-off-by: Jann Horn <jannh@google.com>

@akpm please remove this one from your tree for now, it's unlikely to
work at least for now because there's code like cifs_sg_set_buf()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez246oQD-rdnemBokm%2B345Uo%2BOejvVQk1mR4%3D9fXzbX0gQ%40mail.gmail.com.
