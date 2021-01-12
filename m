Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7WM637QKGQED7HAKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 460572F31DA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:39:11 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id x22sf446111ejb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610458751; cv=pass;
        d=google.com; s=arc-20160816;
        b=mY3eGO9LJJudqZk8XHSpHv324ClKbHD0crgd4eipqnuVNKUJbiP3dUR9ysiQH4Zq3Z
         mDm0CGo17wBo23WuiocGOpZz7vPUfXWd0hDdtIoZ+qT1/04tdtdJA1ijhIOK+0RSSZpf
         IDbVmxM2IAMEYCiCFs63eYE9Q7Zk9EPEkbQosSOOxhSa9q3F06ui5vONrGEGSPWGwLjO
         SJ6ae43IU57g42v6Q0/kAvsO1ZZVMF5UKf/dRaOdMmPysIrLzr0FMCwVmoUTJSmJXdzV
         xhOu62n3GJq60UdniU3qmRDX77qAmDQwsYWXXjQNyRyN3VmrBsCkw8RCEbUlco/CgPwV
         MtMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Ftc4U6o7wfQToIrkQAps7FUsNcYgRQ9qI9W8DhsYwHc=;
        b=DpYziXeE2DXRJqnoexFqu0rqc8Bh1NHAihCsNMddIpuxyu8ryC9lAvE0be/+FmmK22
         H+tidT/e631fOyC76kNQfKbIydAC9lOFcMw7gyQ2X11+454lM7XQV7GV6a6JYCuNv7hL
         FJ0UJWN5zFmV5rXo5ZxNI1ujlUQsn77mgEvnsuxq7NrCDGow1dif7rIrgtIeCD0rYwgi
         GoAlq44lH2ezn0WS/9VkKZt9/J+/grUDoWUEY0NLWG4Z+XWIb7L1szbw7Avft78HIH53
         Vr3R00m91vcq4HAqoBMzzVugvM4+1xYFsUOIF+AY8rkyT2tz+/wv98HI1ZEN5XIzDNbc
         J6gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OgC9q6Gb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ftc4U6o7wfQToIrkQAps7FUsNcYgRQ9qI9W8DhsYwHc=;
        b=PJmQS9bqjZgjPFWMUsfDbCQF4AYBMbXVop1ErxshUC4ZlWJZ6Y6SfZNNh/zmqOpVn2
         EdcYI138GB0Q86zepH6v8uMrcY03CNQaffRvzGAzpDbVGM/bur3g6i/aUH3xeQXSIrvv
         xAlbtCxJ1TqYJ6oe3lx13nJuoHscd2jp6uSg5tXfLo2FwjtTXSKSMfVL0NYN1fgNEln7
         yKzqOaQFHSd5qOKBH5ZVFyoHlZe8lf2JKFH5uu8wpvV/9dt/RmvWcMEOSqcHJhDv16sk
         GHMadllYDSgz9EaRVQSRybZUYmyHqlmgjeh7XI9zDVELtVoK/POAzeuZ+Ft59KtEXLjw
         Kt8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ftc4U6o7wfQToIrkQAps7FUsNcYgRQ9qI9W8DhsYwHc=;
        b=tkTke+kYv+M6SjYRuM6mzAmzoxDg31qiZIGH9HBGawzZQ9XGvKiBIIzYWEf2zbkvlT
         2MVNLYaMaKmRR5oLP5JifpAIGAUf5bDX9B8pXWYjHEL3sxl+yJUEl6Pnt3kM4BO1y9uZ
         q0yvnKM9oI+Ir+AVALWugyeRF7DuaTXWulDDnA/pY9gJpxviabACE32Qpq4Ri6vGKrl4
         DJ+K+AI41DdFy+jxf2XC1/7A2b4yj20tya3GGRO1qyr5tdXaoEiZk/jZfDo+2FBUSpqG
         mmsbALWgaHiUKIHq1CR9REnrmtdrMXUpwbBdrKBJIYE5ROBMQlTF3Qastp25i4MsgGA4
         JOVQ==
X-Gm-Message-State: AOAM530ta8YwmuEydlf0JdfNX98Q1v8CHdTAAn9+77NbMw4r9SypWks2
	Z6wk/hL9fcii6ng+pWe7bOs=
X-Google-Smtp-Source: ABdhPJxouyvDXDHeMtcIQ63EH7UxE9yEiK/AAUbiyGNZfJJ8yWvguDhbd+JAz1CQC0X+T0d4saEeQA==
X-Received: by 2002:a17:906:5043:: with SMTP id e3mr3343827ejk.260.1610458751068;
        Tue, 12 Jan 2021 05:39:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:82d1:: with SMTP id a17ls1532674ejy.1.gmail; Tue, 12
 Jan 2021 05:39:10 -0800 (PST)
X-Received: by 2002:a17:907:60a:: with SMTP id wp10mr3369772ejb.205.1610458750004;
        Tue, 12 Jan 2021 05:39:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610458750; cv=none;
        d=google.com; s=arc-20160816;
        b=LRTrBRBQfpagLXkIg2KvIkbXOtpN+lDXlPiqoMQhgP977o+MkuOHV2aHkcrm6BoSSg
         M5waB6/X1BXMJcWhmmBWfNL3Nk7EAlFxXEOPPbXjwuKDUgVFdyBMJQyDqVbkWaAkj/mL
         sjm0Xxf8zgBNJu/MUub7o/cLIHl8l7bGuzcV6TQL7RueAztrjOg3JGOB24eGXh+RJe/D
         rsmb2RgPp8wPyMGWDVgfkq7iYExNxEHXA3LqBBA6HH2ZI5BjkgwQ0DlQhp5+AOstgjGn
         hl0aaqpseFe5SZO6Ee/Y7c5rm0u8/JmKna3B5Cuh7Xzj3NkP0rwCO113sjbk0HJOA/rP
         pNFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/gH3LsuYOCe5YajoCQBV3RVdjva6zoqEdCztkktjq5s=;
        b=fBuSLClZ14GEwgvmdAbDa/pyz25G49gYtMe4FPjvlZaTUNSHSD7eLY3KNmzQLSfgHE
         D9oqLHZzviWZDj8rBu1vs1LP5lP8noqPB+F/cQZAdJZ7bCbqU4lDsKazWyIej1gLBDaV
         nsaOlUyda6OJyXJZ7cqRNM27xfakJgJ8YmVwAMJ6K3WK9vlCFRA9XNwOrGChZoLEvErA
         OSOi972xcPjVjgtNvDh3sHQ0NorCGMwU2Zzv2iLLLKNnt/0M+/Xu9azF7Y12virDja4U
         60i18SHQlmGoVRX73ZIyxoCjUws/+ommkmB47bvP73/E74K0oyRJqRRd3+KslW/GSTLh
         vgdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OgC9q6Gb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id d2si159887edo.5.2021.01.12.05.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:39:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id g10so411424wmh.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:39:09 -0800 (PST)
X-Received: by 2002:a1c:c204:: with SMTP id s4mr3615203wmf.73.1610458749636;
        Tue, 12 Jan 2021 05:39:09 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id l20sm5038940wrh.82.2021.01.12.05.39.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:39:08 -0800 (PST)
Date: Tue, 12 Jan 2021 14:39:03 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 08/11] kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
Message-ID: <X/2md4h0Nki8RNW0@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OgC9q6Gb;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> In the kmalloc_uaf2() test, the pointers to the two allocated memory
> blocks might be the same, and the test will fail. With the software
> tag-based mode, the probability of the that happening is 1/254, so it's
> hard to observe the failure. For the hardware tag-based mode though,
> the probablity is 1/14, which is quite noticable.
> 
> Allow up to 4 attempts at generating different tags for the tag-based
> modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
> ---
>  lib/test_kasan.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b5077a47b95a..b67da7f6e17f 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -375,7 +375,9 @@ static void kmalloc_uaf2(struct kunit *test)
>  {
>  	char *ptr1, *ptr2;
>  	size_t size = 43;
> +	int counter = 0;
>  
> +again:
>  	ptr1 = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>  
> @@ -384,6 +386,13 @@ static void kmalloc_uaf2(struct kunit *test)
>  	ptr2 = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>  
> +	/*
> +	 * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
> +	 * Allow up to 4 attempts at generating different tags.
> +	 */
> +	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 4)
> +		goto again;
> +

Why do we even need a limit? Why not retry until ptr1 != ptr2?

>  	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
>  	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>  
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2md4h0Nki8RNW0%40elver.google.com.
