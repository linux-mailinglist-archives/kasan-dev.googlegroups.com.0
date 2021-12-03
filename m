Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKVBVCGQMGQEEYOAJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C01E9467796
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 13:42:18 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id k7-20020aa7c387000000b003e7ed87fb31sf2507060edq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 04:42:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638535338; cv=pass;
        d=google.com; s=arc-20160816;
        b=tWnm5uHIutN90SF+Ctu2KumhpLubmOAX51MaO0crGOvQK072OYo39KQQCqe6jnkZ+s
         5HzhU9rTB1TD7LPnlzRx5wilYhfOJOPZEQddU/9O7lmi2pX61FlIz1SbrP9gqwR7Simp
         OukY764pRgoSWMc6NTztWzp6pSsIuwA8/BB6ItpdkfF0JwYdkekIlGU60LRYqEq8MxRE
         dAQiKNuU9Wx3j9rEo4JJO0bmTagne8ulePddUwIDlzGNZSQuvRN7uzJ8zxIiE3zY/Xob
         8n2dlVzH4u1IUaKHE0oBrSr9CsqMvl4VqiPmAdz4QtEZbUoIBbKnOPESiGqhAK029Jju
         a1Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qjb0leBAr0b8AGubPxia42DNDt2xWNZvteknmSGlFbc=;
        b=WrNnIaa30P7Rzn9AfczscGVBgg5J/ai+dMic29NMlyE73loTIWZrK/6nouxqKMGWFJ
         VCZlVM6N8sVScoqcxcuAnEvLDtBsv5Qv/jyaozxtiKl71bRIY9VryFID+LIDN/B3N/+8
         dVdw0XLr2j3sg8JhcVZ3Qct1O419k1k6vtI589PJ39kWA5ocePZF4u9kuRtnTCJjGkRB
         n+fEL04BcUs5bkyrsziVHiyUeLIXFtfVe5Moc2BZfHji4AY7j5DT5hiWmN66bHGmFWVj
         O6fVYxz5ztmRmByOtCCTUqQpfgyYybyI9wLUBvyOTdkC0LopAR+bl0NRWVeSZWfCHhPn
         gCUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rL72f8vz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qjb0leBAr0b8AGubPxia42DNDt2xWNZvteknmSGlFbc=;
        b=RRewDSJLFiG1HMEvgYcwGCXIu4qZ3yzwqAsi/kwDXBunC26P9c/bRRFlZgzoFcYh/p
         DQgc+XA8yAZjKZXtlpn0HC9FY4ra3xctlNEY6Mg7+XA9idSen62sCr1iwlittaFlTxYk
         18I4yBNCDXUhOgpAidgbHwVO0HpnokoP6ibtO6bbP3jl/FFCbW1vpcfg1PNwjZFlIJgO
         fpsaobDuPNzGY0+AwymRLwo6DAwDf7sJZ3+pICb2cEMiNKfFW4iI5sxYvYVhaLCvxG9E
         hpcq85BZA7mm4asDmG6gC8DR7J65jFynzv28Mt6RlPiidWNPqRtpzIQOWG7lfY2t7f/P
         4voA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qjb0leBAr0b8AGubPxia42DNDt2xWNZvteknmSGlFbc=;
        b=zjPPhCUaw+5rR6LWeuJCoXPEMezSmaQA8pAkiYxoSefrd5+PpODtMq39YkBGk1DLAG
         6wD1ZLDF3wHjTrHh3GVeQyacMasu/R5dS7Z7+vUzDfz045naIeFFfNbfBd+aQqDVK7c+
         Qdm0y0NR/Uw1keBfhsNHLwQLBe7eElzKseCejNcSP/q8kU9To1B+e9UL5RtMqFXBEsFZ
         0UC1nL3m9ARFcdpOu0pJWGbmINybw3P5FKNQ74oWOfqR91AcDXt4GBP7szaMbRomtE+k
         ZVeJ6fUsor7T6glRcuhLtM4Baewut1Qte8DplOg4QXJi+DebnwTESIhklRTCcUvtHQBK
         /C4w==
X-Gm-Message-State: AOAM532MqRW0HSo22xIvsCXZVYijB6zJT+1qzc+AGROKAs2DC+iI4WID
	qtLPNDJkxyrjsXlr46MA+PM=
X-Google-Smtp-Source: ABdhPJzfwI1rxESxdviY9owpbijHykFhT8d346C6Zi26vaz70tDopcFQZt1LkZ1U2FxHMXQtgaxP6g==
X-Received: by 2002:aa7:ca46:: with SMTP id j6mr26580028edt.234.1638535338512;
        Fri, 03 Dec 2021 04:42:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6da0:: with SMTP id sb32ls3728512ejc.8.gmail; Fri,
 03 Dec 2021 04:42:17 -0800 (PST)
X-Received: by 2002:a17:906:1613:: with SMTP id m19mr24138715ejd.136.1638535337572;
        Fri, 03 Dec 2021 04:42:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638535337; cv=none;
        d=google.com; s=arc-20160816;
        b=ZalCEF7s45xFx3cY3CJRZW8GVQ+gEaDeCgOz9N3hM8HtzTHzVQENRg4Mawt6qAzTU8
         p6bUOKS3gE3j2YI7IL+EmNFbUpZoWtvcaALQqDvd47ywAqASybrM2lih8d27wGXUJkPQ
         LZT5oyX99ZpmmaznQ7jC+AIfg0jao9fb1ca9fQygUaTpMhxQ+Ze5iA2qM3G5t69LgVhE
         diABLud/0oxf4VSaozK3r3XEgSGdmZKJXuyYcXufHGR6JLkMIGBmjm24qlQryjinPTzj
         TFdC0NT5K5+zb/IwnCMzBDZ+2USaxa9/0QX3j3wzmnHFyfvDqBJDqNY85hfrOFlcCCkI
         Pw5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=K6qjVToyPcEHlycO2HNFxJnoTYZ6aOQ5rp3ZUXudbCA=;
        b=EdTagoeDfYAR8VNM6c/3mAcCgF3mzs+8wL7kQTkTSXdvN6Kk7sZURKFRm3xxT2u2O0
         vtsMoxD9Mhv6FdgcqIOFYWPNwme9/zxkwsZON0sd79qmbMYChUmJlDJQuNhCTld6Vdq5
         tHRt7YTnrRE9ULD1HqE8X2RIcFsxEmhy3fRkWx3CKOWCmmevTzRrGqg+McMQpa1iCFSB
         Gm/3OR1Gjt1l+Qk8QL5+MPaSYSg35b5vws5D+HiTjTtEh5LrLMbevMtSpuutPfPGiYju
         GS5gLh1P31XAV51RQBQeufqjmxwZlGxD7TNVDTHzgCf+leaP161i+yYilsf83nH/E+g0
         IjCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rL72f8vz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id w5si144099ede.3.2021.12.03.04.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 04:42:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id n33-20020a05600c502100b0032fb900951eso4755194wmr.4
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 04:42:17 -0800 (PST)
X-Received: by 2002:a05:600c:299:: with SMTP id 25mr14594606wmk.77.1638535337117;
        Fri, 03 Dec 2021 04:42:17 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:cb5f:d3e:205e:c7c4])
        by smtp.gmail.com with ESMTPSA id a22sm2474329wme.19.2021.12.03.04.42.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 04:42:16 -0800 (PST)
Date: Fri, 3 Dec 2021 13:42:10 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 24/31] kasan, vmalloc, arm64: mark vmalloc mappings as
 pgprot_tagged
Message-ID: <YaoQos9Fevz32h6+@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <8557e32739e38d3cdf409789c2b3e1b405c743f4.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8557e32739e38d3cdf409789c2b3e1b405c743f4.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rL72f8vz;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
> a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
> memory tags via MTE-specific instructions.
> 
> This change adds proper protection bits to vmalloc() allocations.
> These allocations are always backed by page_alloc pages, so the tags
> will actually be getting set on the corresponding physical memory.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

This is also missing Signed-off-by from Vincenzo.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaoQos9Fevz32h6%2B%40elver.google.com.
