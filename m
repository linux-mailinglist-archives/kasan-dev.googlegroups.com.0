Return-Path: <kasan-dev+bncBCT4XGV33UIBBVUTYKMQMGQET4Z76VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A3B0B5E9496
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 19:03:19 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id g21-20020ac25395000000b004988628ac86sf1537083lfh.21
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 10:03:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664125399; cv=pass;
        d=google.com; s=arc-20160816;
        b=tk94rSozUGrK0eFQG8zTCq+NQ2kyUtddnnbwlv5Vnkt85asgs+yxEASJQwY4L0j8qh
         zPwdTFbvzZV73r4TSGr3alWdFEeFSCLuB80I9Ub+8fhid+ZOd5D1ymPmZXuwrEM5q/v8
         oHJTNNBCo6ZND7M+vFx6EGKmoymmNny3WmpGOBXessKvy0MLg2fT2PuaKj6l8VtzbqDm
         tvpUl1L6LlqIUt/XErYXsiPMzZ/Qr5isDrG19XsVbcMcWg9irWeYUsekEaExnSb+ct+Q
         sS/OCySGv5GQ6PHWNzBA6O++N5Nm3IiLC3IrtOppzBmHJWWMg44W6J54UiLohNO2Wkkd
         VwdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=p/fv5KIFgd8NBuYxllcDOWya93McOkSgpLvhCxdz/8g=;
        b=C13u0wXIRfnLyubVWffDe/siKabD+OXE+fYwQV0i8cgAlpCDMjI5jHvEGEZv53wC/q
         Vk/sunRzoHnnOTIVEyVwVHn8lMVrgJnVBCNW4Ckz9xp/kOqVrnVZBzpNZzfaBi/BGJ87
         UK7W8cz6PsI8v0Y7RJfAh+svQU9mV3drbuwQFbCD6miRTo5ZDYqNBR3tTZeOq12euRof
         MMKXFBmSk5d8r44l6Bthk+GkgO2MXV8GtA9sRQCFxjlTXaX5AoVtQ1RCFUcDmFoWgLGA
         fSb/L7+mz40DXmfhNG3MzLJ/mtjb9le3VJAppuE9zY1hRQyo4WT1upYN/2UOiXpFXy9s
         Usqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=hbIdH3Y6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=p/fv5KIFgd8NBuYxllcDOWya93McOkSgpLvhCxdz/8g=;
        b=dnxTbr+wVn+mhmh98x5QzxYXzXGQEpKL+bKfG0XY8+2MWFmcaA/mbxqHtUl+GLjVu2
         hv/p0gc0doI6YjhPql70sVEmt9se8tsFZCGko+NHULVPRIY63K8JkxaeL9qoZORjpooe
         0ZKx9UlkqmD9b9495cEZb6q1pCvyjgoKd0QqgDhIDV8jJCcxE7Ik1X1yVhJoiMg9PSnl
         OIPy/ggPHgQDYt464232eu1PY2+kTRFIyNt9OT7L2m9HrL7HirCLBW7U79SX2k89y/o5
         fGqy1er4LV/S5RX1KV/xqizanJ3IuB+/NEvCCDk0TVr25WVHTjMv4DdFjwERMvPKIY9Z
         TPsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=p/fv5KIFgd8NBuYxllcDOWya93McOkSgpLvhCxdz/8g=;
        b=aj9QXHUWUkDtpuHzesfMVeQh5YyGMWjZcHmvXj/Nko2J8NB/1xobvgWcrtRRD5fGZw
         YoBbH8P3fiv5xpwgPjCRIuu9DNbnNF3cPXf8iS1bP5mPn1pOPkExK7LHlKw5MKhtkMqj
         aFbwykPfprhd56JaXiu0Llb/S3LSYCUnRZP1KDOVoLxL9kMNiZ2BWr87Io53PnaYCCat
         x0QwlMZo6EF+qF7+W44QolL2AcTvl1PC5QTARk9HCvOnxxEJ5oLUqSSs3XewNx9686cK
         LEND3+7TvHn+dTkvkNkRa85NGnuXZTQCZYxNYNSOEz/iOaGZyLw+2s50iMgL6LW5umps
         P0FA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3oy7BUDpOYmbbdZoq6kdI2cAT2lGhMVArtiS7uG74Lh+scZUwt
	X7KfRbJK5QR93Ukuo6Ur5gs=
X-Google-Smtp-Source: AMsMyM6P5HDUjJO2D/x3dSDAkfE3BGkkWDoRjyeCZWMpX+gJkAvKp+tLbApsF/ztVmF6K+stQgAHyg==
X-Received: by 2002:a2e:9f4a:0:b0:26d:53fd:120a with SMTP id v10-20020a2e9f4a000000b0026d53fd120amr2725152ljk.475.1664125398819;
        Sun, 25 Sep 2022 10:03:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls454582lfc.1.-pod-prod-gmail;
 Sun, 25 Sep 2022 10:03:17 -0700 (PDT)
X-Received: by 2002:a05:6512:b17:b0:4a0:13c:9b3f with SMTP id w23-20020a0565120b1700b004a0013c9b3fmr6978391lfu.91.1664125397229;
        Sun, 25 Sep 2022 10:03:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664125397; cv=none;
        d=google.com; s=arc-20160816;
        b=Y4h8EH7p4mRWe5ELXVkw0kJORe6eqRexxRk4U48fWOoZLbfPuCCcW0TqUr9mZKV7Bg
         9c9hTgx8RGNtbbAYhqidG0Mlts/WFY//umWm6RCMK05mr9jQfePy9Rs6L3j3TWC4sZ5L
         1iEgvSygyK7clrYd1ZT0IBLzIE9LCFQjFV2t4/J8v3zJ42gxGSsIDfGo2z1fC1BY53Ja
         NivT5rw24PBuj0xfES5QTqLEDfoa/CCiYfk/z3CdGDcD3XA8WSE5k3/s0gjTsc3U2Knf
         ffdG8Xl7gLLSjMw+tW7yihShlPGAPVUtY5c3tgWhA/zBMWcAskZSPGMr81cZI6byeIVF
         GEug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ET9jid1fFz41r3oSHHroP+XNjGjrtmMKMEMT1FtwlQg=;
        b=btBnVI14tGrx5Usxb6QKy6sdQPmJ572hMpScrauYthg86ujHDESamWm3fAkxkRKKrY
         a7iwa2+VzzfgCPycK1l+oA3Y4itrbgvcsZ2nmq3BmrWNJdwxAs6J/qtp+L/FCPRNjtPN
         2PHDICkHT9xBPE2IXSYSDtotJFYdF2/uhm/HB2KPoCpEKbDZFcZfT5cuvhdJDdtxeeI8
         tIAo4ZEngJfO+TD1bpbh9bWw75r7Ani72fqn7DhT0exQX2Jgz5TQwHNmjmGu38YxHzW9
         HEJn9W8dFBysThhe7oR3Ag1B6IxiKDaeI0WqMKEh9wS9vke6eCXOwuZ7D+RJqLjdwyz3
         51Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=hbIdH3Y6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id x9-20020a056512078900b00499b6fc70ecsi524196lfr.1.2022.09.25.10.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Sep 2022 10:03:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5F8E4B80BEC;
	Sun, 25 Sep 2022 17:03:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9F534C433D6;
	Sun, 25 Sep 2022 17:03:13 +0000 (UTC)
Date: Sun, 25 Sep 2022 10:03:12 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, Kees Cook
 <keescook@chromium.org>, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>, kernel test robot <lkp@intel.com>
Subject: Re: [PATCH mm v2] kasan: fix array-bounds warnings in tests
Message-Id: <20220925100312.6bfecb122b314862ad7b2dd4@linux-foundation.org>
In-Reply-To: <9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl@google.com>
References: <9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=hbIdH3Y6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 24 Sep 2022 22:23:21 +0200 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> GCC's -Warray-bounds option detects out-of-bounds accesses to
> statically-sized allocations in krealloc out-of-bounds tests.
> 
> Use OPTIMIZER_HIDE_VAR to suppress the warning.
> 
> Also change kmalloc_memmove_invalid_size to use OPTIMIZER_HIDE_VAR
> instead of a volatile variable.
> 
> ...
>
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -333,6 +333,8 @@ static void krealloc_more_oob_helper(struct kunit *test,
>  	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>  
> +	OPTIMIZER_HIDE_VAR(ptr2);
> +
>  	/* All offsets up to size2 must be accessible. */
>  	ptr2[size1 - 1] = 'x';
>  	ptr2[size1] = 'x';
> @@ -365,6 +367,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
>  	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>  
> +	OPTIMIZER_HIDE_VAR(ptr2);

What chance does a reader have of working out why this is here?  If
"little" then a code comment would be a nice way of saving that poor
person for having to dive into the git history.


>  	/* Must be accessible for all modes. */
>  	ptr2[size2 - 1] = 'x';
>  
> @@ -578,13 +582,14 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
>  {
>  	char *ptr;
>  	size_t size = 64;
> -	volatile size_t invalid_size = size;
> +	size_t invalid_size = size;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
>  	memset((char *)ptr, 0, 64);
>  	OPTIMIZER_HIDE_VAR(ptr);
> +	OPTIMIZER_HIDE_VAR(invalid_size);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
>  	kfree(ptr);
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220925100312.6bfecb122b314862ad7b2dd4%40linux-foundation.org.
