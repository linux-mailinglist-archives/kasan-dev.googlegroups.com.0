Return-Path: <kasan-dev+bncBCCZL45QXABBBLO46LEQMGQECTLKIHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id AE6DFCBA175
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Dec 2025 01:07:10 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4ed6855557asf34521191cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 16:07:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765584429; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fze7iZq79wnQguiTHzSAu3N7rUlSyMjxV7TLgDZCpQY5usQKOpreKb2E8ygqJlXQap
         1iV7sLH+aIemC9YQTmegygAuyvcWyvU0fapftHrFANi7ih3paMXwwWdS1MH8tou5mRMr
         no4aCOazBOyqlwblRxiPKnW4G4e4Hc5Hd1RVWPLBCdCTAXOliJ4c14L3qW7wagqP8LQE
         BqN2Rxbo6cb5iTuujpvNQUmEjDEWQFgh3ejAwZWqEkuD0P4Gn6g4MR/bchE1Y1yomv52
         97V0oDtIByGZaPED4aEmU0fQ3HHevrQD/G8y8PTxRrpbpGUb7sWd19I7r32XpiTa6Jvm
         +XuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xoln5He7jhZBKIXWAe4mDWhwWhMaG0HMq+rygQJkTtg=;
        fh=0jkHAJ/Gvb6fJOXXo/2EqDxXBifkCHYFDxV/y4YnGWE=;
        b=IoSnkpMLA1GMLxI1fIIHMyo55v0UYyEMpZIzo5K8TSbu/2v+4ZFfQS8nex5n3FCVaB
         jZ9YBcntdeXL9XZUx9TXVXPAsjghIM4b6q/k/K2anSVd6Fqdetu8JQDwazfsG7VB8e8O
         eiqGfwrMNSaR619eWrpNNFVObjNf76h+E/h3peMLdroqPfBJhD/ntwc9f00bL84AD6qP
         /0E3RbyKWKaZfiqlZ8V9ztyfOwMmYax4YKtQNAGbyhYPrZx0eLRW+3ciUrN8VbH7jkOJ
         612exYdZ7dIm+4NIkGfQVECAzE8i8cvKDV/GU65SkuVBbx2Q2vI9Z5oVzV81doESrzjs
         O4NQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=cpi+57Q7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765584429; x=1766189229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xoln5He7jhZBKIXWAe4mDWhwWhMaG0HMq+rygQJkTtg=;
        b=aWlHpuS5R/kr4kh4/gNxOWNJYASXDxoL7DY5JzcAvUzqGWoMabu+/lBiLBbN1OK6cl
         tSg3jWrbQFDEyWFs2Gj4SkS50CS5u/t4OtfTwtDOtGJ82YRs69xACzT4h4w427U81RYr
         nQNpYtt6O2hr3kScxMD/BGhhRgxZZMyOFkvnhaE+0JpCVQ2FLVD88qv3ZsJ6bFoVGAX3
         cQXAj/Fkf4rDaBvyOOTQrGajgl1Dw36vq94orQlkZRKDqcaGfMRN0v/44uaAo34/Bo9Y
         sQ8x6ZgQlQCdbdy85Kr56ByJU1Ab0LHc9tYiCEKO4lVcdHAtzYqdW72GA3+1mDVAKZ3u
         7GmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765584429; x=1766189229;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xoln5He7jhZBKIXWAe4mDWhwWhMaG0HMq+rygQJkTtg=;
        b=qJPW3Hv2wOvVNssdOtF6gZcgpdq+FlnWHLrumLg5z76NhiMD6ZScJ2jQgEQpofSolk
         DRvnZdyrySQP9fBKoK+0kKKa3kxD2thDY+/SzYJWDbADjW7uhfF4WZ087xI+KvT3UnR5
         zBm+AscjfE5YOME+JWDYUZRZJIcsYMc6U8LhFf1ateXF3SApirXykDt60Dm5coG+0jPP
         APsJqS7oPdC+zXwE2ZMPG2pFhYnP0HHqqemP9SFOeA3yHEk90QfAWykBzP93HPWr+ZPS
         lXDlAWpQj/yv7e1Skzs+AKI20MTVQ0oWP4Rence4oh6zPgTkYtV+UsKi8Ja90QaTT/UQ
         PTwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQmx0wyMorjt7lefee6lPGtZFtoWYDnshIrbdZBzgzoY6SxwHvx+CMKhfwJxyZTR49NHH0SQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjuzRt/LrEiwu9LbGPO0nRedsJ5BozfGpZ5kYPh/zwIZgg4a8V
	Y7TSLVgASsVwtH/OIHxSjckvr2JcCXMsSvPcDVMFQy9qwcCZ4Xj29g7N
X-Google-Smtp-Source: AGHT+IEEFoeMX9zFvMOV/4EZcad3i3NS+9ErcDXxPg/7W3VE1zTJxDP9VdooWjpCcul4JaM3Ekv3Gw==
X-Received: by 2002:a05:622a:148c:b0:4f1:8bfe:e446 with SMTP id d75a77b69052e-4f1cf62768dmr57623091cf.41.1765584429171;
        Fri, 12 Dec 2025 16:07:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYvOaSO6bbAjxkLnIndVxdlBjaGaBowu4Eotfo//Vkp9Q=="
Received: by 2002:a05:622a:1920:b0:4ee:234a:302a with SMTP id
 d75a77b69052e-4f1ceeedc35ls14416381cf.2.-pod-prod-00-us; Fri, 12 Dec 2025
 16:07:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWkwEtM6sLxGMNR4T4rdKk4DhwlkXrHDsBGgAIk3zz6heqCfXFmdwXMy0rYY033nqpM5f1YQ29w3SI=@googlegroups.com
X-Received: by 2002:a05:622a:3d4:b0:4ee:230b:ed07 with SMTP id d75a77b69052e-4f1bfbd1960mr105939621cf.15.1765584428503;
        Fri, 12 Dec 2025 16:07:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765584428; cv=none;
        d=google.com; s=arc-20240605;
        b=FQZhkIRD1YqO+1Hz2uWE+oMIAE2yzqYp9iB7ylXwWg/oCbMWuJglLUaRAJ6G6Nomuu
         DFMx/7rgNruatcczD8TXQxKN68IsuFbZOdTbET9p83xYtEiyKuzZLi3dDYVtiAXalT6I
         FuWzaNUF8ME3XYiIxlrx+8jNasd+5lXviJvrx1jZetu7y9N1g63m88JhP/AIpMT33Afq
         A+VM5Du5nSzfK5aH/z4bBxO3Hyy2WItR99VvHeUWxiNW93iXZbrlTtsa+a+onmnQKS59
         0A/Dzzf8eP6vSjT4bqlv7co74neu2hreM9C5zqshA434IdIIo/CsvNNCaRJ7SVcVvmPj
         KeKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=c459pZsavFBd2omsdsKSsvXiCamORAaW3VGkhGRV9lw=;
        fh=SdE3InwhPzBYnpc7Azp39twRr1smpVooC0sauRVFExM=;
        b=LGawTvTrcQJZbGsgGLte8zVREPJoOQXKkwOcmb3Q5/IGi8cNmMl9tBmO19he6wKvD2
         205H6XuIlXgFCOM82q22qNAMoEIdT6ELPDUQoWYLZ91WiPxgRS9y6qA3LyQi7V+nD78J
         xdTo7rE9nDxG/cJYj6NlLEJG08TE1BWZlRynZ/74SvgZKrGAtInh3uzpmbQetk+4VDtv
         s2XXB9ej6IuygGgxYRoMch8b0mm22P3yyxgnkMi16K0qfCFLIbJFhLUJC1FJx2CTcUdY
         XFGRByNq87HNKkClhO6zr3oygM0AjMCBz0mb/gJ3KhCN+jFTlH9CcHwTRn/h2yCnx7bY
         5xaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=cpi+57Q7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88993b303d5si157276d6.1.2025.12.12.16.07.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 16:07:08 -0800 (PST)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-297ec50477aso7518465ad.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Dec 2025 16:07:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWAAj2vZv3cUOzflBp/UqPQ9UQu28hV2EM9rlJo+ywyH4hpLzELMG/FBRTz9x7KSL/2wrdI7BjJcv8=@googlegroups.com
X-Gm-Gg: AY/fxX6FrPYL5EkKua2PGUwPX8pnJm0BRXB6TXK0z5pWABjFvO2c7aVrk0OlVdf8IJG
	JnmwGjAKOZTB8Fhb1cXAlDmUOozq2OwIFkJ28JrEvQJulKXsZwacMxXSq5lsPC1pnXnNLEPacoT
	5nbAzfo71CV4R6nqz6HbvC8hvVDKSlno/krZSXSottnqmrniG26ol7TvokQHJmbo3mg4AX928eY
	Rj0pRDo7BZb3JoyESxdZP+8xGIiu8cZsNkCoS85e/m9nWA5IBJzFXkL3n2qJ0svHJlKeGzT4zYJ
	rL3IigebelklmMi+4Zra8kLzeSEP71fg8SVDsdm/xetRYxOIdfa1gjcEGKhUKoODKZYBoSr6XyW
	WB2N6a12pKaaxpOFbQutyQK3AsJ1x+mOfJkKrIukYUMp58BhcltRhw1ij0Oq9187zugw0njOOoq
	yfnobU6zlWvuKfBs653wXMakyZ/HNdXrh+Owhu0h6laox3kFcnD7K2dhvE4ePgmUNV
X-Received: by 2002:a17:902:c94d:b0:295:6117:c597 with SMTP id d9443c01a7336-29eee9f1eb6mr75179915ad.5.1765584427334;
        Fri, 12 Dec 2025 16:07:07 -0800 (PST)
Received: from ?IPV6:2001:f70:700:2400:3248:8d01:1cd9:d123? ([2001:f70:700:2400:3248:8d01:1cd9:d123])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29f2ebc340csm25064615ad.28.2025.12.12.16.07.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Dec 2025 16:07:06 -0800 (PST)
Message-ID: <cbc99cb2-4415-4757-8808-67bf7926fed4@linuxfoundation.org>
Date: Fri, 12 Dec 2025 17:06:59 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
To: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com
Cc: andreyknvl@gmail.com, andy@kernel.org, andy.shevchenko@gmail.com,
 brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net,
 davidgow@google.com, dhowells@redhat.com, dvyukov@google.com,
 elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com,
 jack@suse.cz, jannh@google.com, johannes@sipsolutions.net,
 kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com,
 linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org,
 sj@kernel.org, tarasmadan@google.com, Shuah Khan <skhan@linuxfoundation.org>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
Content-Language: en-US
From: Shuah Khan <skhan@linuxfoundation.org>
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=cpi+57Q7;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On 12/4/25 07:12, Ethan Graham wrote:
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
> 
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out. Using a simple macro-based API, developers
> can add a new fuzz target with minimal boilerplate code.
> 
> The core design consists of three main parts:
> 1. The `FUZZ_TEST(name, struct_type)` and `FUZZ_TEST_SIMPLE(name)`
>     macros that allow developers to easily define a fuzz test.
> 2. A binary input format that allows a userspace fuzzer to serialize
>     complex, pointer-rich C structures into a single buffer.
> 3. Metadata for test targets, constraints, and annotations, which is
>     emitted into dedicated ELF sections to allow for discovery and
>     inspection by userspace tools. These are found in
>     ".kfuzztest_{targets, constraints, annotations}".
> 
> As of September 2025, syzkaller supports KFuzzTest targets out of the
> box, and without requiring any hand-written descriptions - the fuzz
> target and its constraints + annotations are the sole source of truth.
> 
> To validate the framework's end-to-end effectiveness, we performed an
> experiment by manually introducing an off-by-one buffer over-read into
> pkcs7_parse_message, like so:
> 
> - ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
> + ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);
> 
> A syzkaller instance fuzzing the new test_pkcs7_parse_message target
> introduced in patch 7 successfully triggered the bug inside of
> asn1_ber_decoder in under 30 seconds from a cold start. Similar
> experiments on the other new fuzz targets (patches 8-9) also
> successfully identified injected bugs, proving that KFuzzTest is
> effective when paired with a coverage-guided fuzzing engine.
> 

As discussed at LPC, the tight tie between one single external user-space
tool isn't something I am in favor of. The reason being, if the userspace
app disappears all this kernel code stays with no way to trigger.

Ethan and I discussed at LPC and I asked Ethan to come up with a generic way
to trigger the fuzz code that doesn't solely depend on a single users-space
application.

Until such time, we can hold off on merging this code as is.
  
thanks,
-- Shuah

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cbc99cb2-4415-4757-8808-67bf7926fed4%40linuxfoundation.org.
