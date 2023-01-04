Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAH52SOQMGQEE5KCT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BBF665CECC
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 09:53:21 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 3-20020a05621420e300b00531b6f7e4bdsf5897358qvk.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 00:53:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672822400; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPy/LOBDb+lTcXYYXlWN3Cpky+pEYlCpdVnRPycFzXvgyi8F/C3kfl0Y1t8cnSygst
         NhkUl+qEveGK1PEzW0MpNHk6NrC2LHSXaG9r+zo4YPchcDyZqNJFzP/TDTsxNZpagEut
         usaXADCqCuWPWh0d7b15Giw/142OLMtnpLqzHSs3r6gw7U8J+1iQV41W1Ei9aMfFljIq
         w+mDQCTwcOK1Z0isuihPyd8Oja/lPyijdhKL2W0p0OjVVp1ZSzN9Dhzl9OVszafPUdgx
         5D+YHCXuJcab6BwxethX1L+heWD3RfB8NlDDB69yhwV0VQml/4jG0WMzhJsXtHALvkzc
         pZ0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UH1b+WksFnVbmKDfFQvN6//r2RgtRUpG7FnFIdA9uV0=;
        b=U82AhVH5A65HYLhc48V1ahE4VzRTixeZzJqpIrj/UrGqZjZKtR7SvYzY4mgpkrhlKB
         MMByO2bR+BvQe8D26Jhdva7BaDLeFilzFohOl1B4KbGKSO/cdc39Xp7YBNvorM+vezJN
         PKrU9Lq3UDBa5Ex3mD9d1ccu0cMGj7pLODEdzggoS0WFkUpxtbDqM8ugrZx4cUXRlJ0D
         fAdTwPKOAijt2hNL/KikLaJDZC6Mtgly4I3l++pbRx3xkHS+wYg3sgmusa9UY1SEb8ji
         51tGHvueFTLFb/ghPaC0RbKN1W+xYye2I8J8YnnRDcWsBroxaRdHq/cnnSinb/PjDjHf
         jGEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U71+aMIK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UH1b+WksFnVbmKDfFQvN6//r2RgtRUpG7FnFIdA9uV0=;
        b=bvtoYVFn2MAxsotTBGMCi0qPAKt31rlSnB5+XUOaJ64O07U8k1sSxqYG00fWwxZ0EQ
         eYIIL3L2OE/jZsG5n91TLfXQt7DHI4ZQ/Ve2dHn3bkmzMyNkkrpfnZPMWK6FjqyN6G6j
         nJ0gYCtmhUJNLH6Q4yh/atSjuWS/OZL8qvI/TyPbdrpSvDNMNkJQvwIMNll00Djj7QLC
         y5HkdIOofkPxef0xZb9G2oIHPA1D5nOfmHTaV77B7BvoSphHeLXeC7WLnSoC1MYVYy1y
         sB3USfBaLTyhJkML53z0dwHRAA0JSlqhSrOKubUykN3fexCGqyW+T+ac/GlD99yXXOe2
         UB1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UH1b+WksFnVbmKDfFQvN6//r2RgtRUpG7FnFIdA9uV0=;
        b=6keNOS5r/3S7ZM6DHpdSAH9LUmeJxxuC/wE6lQh4SKBMxSJXNqdAT6o4otDD2I3xsB
         rsDLPav6yuBqgeMQrGXSKIkui16B+uIynDOLb693NhjZvKGSIAK2OlnR0orhECNYZDsT
         vM2jc+/2mTsJfvuejl2fgEqY47OSvosDMAnZrWih1RajsQofh8WKr1kXRaTBet0YVa/E
         Nc2QaUqgkpWItRaPME2gw/SBGYEKx6RFEn1ke/emKlgNd0R8ru1jcFDBiVv7xxqCx61K
         mAfLhNl8TBBK7YP25PIpnRJ0gASr+yYJyzwN1L1Aw+ocHudJMhTp4WCGF7obLWQ3TbrD
         uFRg==
X-Gm-Message-State: AFqh2krCTkSs5FmlU2+nqaPfdLnmJCV3w3lATYgmHOTM+KPCIeryv7qU
	0cY5R/59+MmNgwd1a/7odYM=
X-Google-Smtp-Source: AMrXdXsMGX75YkUYxJLZKId/hD7QQLGrJkix7r/7zRnx9UHnrIUGSrezktid/DtDvFJYknroo/JzZQ==
X-Received: by 2002:a05:620a:2b41:b0:6fe:f590:61e6 with SMTP id dp1-20020a05620a2b4100b006fef59061e6mr2919201qkb.384.1672822400309;
        Wed, 04 Jan 2023 00:53:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a9ce:0:b0:4c6:a598:758c with SMTP id c14-20020a0ca9ce000000b004c6a598758cls12796950qvb.0.-pod-prod-gmail;
 Wed, 04 Jan 2023 00:53:19 -0800 (PST)
X-Received: by 2002:ad4:4f32:0:b0:4c7:8ab2:2fe1 with SMTP id fc18-20020ad44f32000000b004c78ab22fe1mr64096652qvb.19.1672822399697;
        Wed, 04 Jan 2023 00:53:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672822399; cv=none;
        d=google.com; s=arc-20160816;
        b=JYS1ntUj9ScRX0BS7ZlXytPMNuFbVNm1gJ6QjH92Nt2RqlnMaBPe6IYMyhtmFjgyua
         vwO32Bk4ELmngvEeFEtnaziy4X8XEgyNXrIQ5vNAPBPBl0wwmIZNYDhi9TF3fLFgS8wp
         E2dM7GT6pLPFe5SHvFVXUqQZWvVr74FcLG1nZ65Cr7yzrt/qBz7R1BTh6AqmVL+PRIM3
         W0Xly46ED/Y8yYUOhEdouibcdV8n+fvrXQN3Mwbj2G+/XM0TuHN17k3JJC6blDrzeYpG
         +e9a19ZKAqn8T+IxBcnV42iPtpvbmPZn0VAJEjLaHfW2KTJ2xy1ibDbKir5dOc7HEqiq
         MxEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TC8yBB36dJOtwIcLP7PUotL5XoF8yexyBz9lxLUGOuw=;
        b=pH3rNjnupc/kcFDz3mfwqfENEzrX0H/MfMbAssTU/rMvmTP/7Vl1QbK6lVf+wNo538
         DNpygk7A+5Imd07m+lGKfvjbcBy1hGIYBfgs1ADNLxCiTHUVHh29G36WhEdUXt7E7QH1
         b7SKSMu5YGGHew0hnEXFzqqmzOh+qH2Qg763N3W2LuMNqSMxfR42K9hzEh+xovktngUa
         IzRVis0cHasLB7v72E9K2nn9yV3UdPntFVDxWojJNdiTielc9CQCz6K9XieXaI4SPEbN
         fZFf3UQi2PQSi5h8sjxctGzs0PRCOHVu7FSxVHFWLKMXMTsCBsh3XkuRUaRCNl3g6nF3
         YyVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U71+aMIK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id 19-20020a05620a06d300b006fa04da5987si2095635qky.5.2023.01.04.00.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Jan 2023 00:53:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-4a2f8ad29d5so127542717b3.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Jan 2023 00:53:19 -0800 (PST)
X-Received: by 2002:a0d:f083:0:b0:3b2:ce3b:eae1 with SMTP id
 z125-20020a0df083000000b003b2ce3beae1mr5973532ywe.4.1672822399245; Wed, 04
 Jan 2023 00:53:19 -0800 (PST)
MIME-Version: 1.0
References: <f64778a4683b16a73bba72576f73bf4a2b45a82f.1672794398.git.andreyknvl@google.com>
In-Reply-To: <f64778a4683b16a73bba72576f73bf4a2b45a82f.1672794398.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Jan 2023 09:52:42 +0100
Message-ID: <CANpmjNMBHQxYd4R+s3gsyKrp+OpZLiyVCsKK2TBLzMHGv4urBw@mail.gmail.com>
Subject: Re: [PATCH] kasan: mark kasan_kunit_executing as static
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U71+aMIK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
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

On Wed, 4 Jan 2023 at 02:09, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Mark kasan_kunit_executing as static, as it is only used within
> mm/kasan/report.c.
>
> Fixes: c8c7016f50c8 ("kasan: fail non-kasan KUnit tests on KASAN reports")
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 1d02757e90a3..22598b20c7b7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -119,7 +119,7 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
>   * Whether the KASAN KUnit test suite is currently being executed.
>   * Updated in kasan_test.c.
>   */
> -bool kasan_kunit_executing;
> +static bool kasan_kunit_executing;
>
>  void kasan_kunit_test_suite_start(void)
>  {
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMBHQxYd4R%2Bs3gsyKrp%2BOpZLiyVCsKK2TBLzMHGv4urBw%40mail.gmail.com.
