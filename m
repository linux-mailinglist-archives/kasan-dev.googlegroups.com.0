Return-Path: <kasan-dev+bncBCAP7WGUVIKBBIFD3OOQMGQE7ZKCVBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id EC2F265ED1C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 14:33:21 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id b4-20020a253404000000b006fad1bb09f4sf36460825yba.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 05:33:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672925600; cv=pass;
        d=google.com; s=arc-20160816;
        b=eTVL7/BQsOoUiMv5Z0iExtkqeSH9Gi94+RGv+frj8wBYZ9cHmXO1KiHqgEToUYxGfX
         0855wd4FqV708AZJNcPGY7G+THJmLAW6PzrHh6Bv3GNVnqHlbu9XvL6QCqxH5jiOlqTL
         JhQtzXCs781QLzfZKlloC8R2aBBKRgg8VnCUYUCyKP+1Esuuax3KeA6HG6Ukcdlx7HMA
         pQpfEzPnhYsL1r2pnmsDuhnLYT/KQN7zvWbKk3Jw+mzaD7a5w21ejlOGhgUhvxNs1PpE
         JGHGm7e7PxrKAWADtuOZOgKdm/YGcD0ZbzRz36OmvNyzCqF3Lbyqq+xuqm7diUe+D5jD
         2Cxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=hiq1xMm+ShgLibpUfF/FYf7WOfFCU5xJKGzfrMaoJnU=;
        b=FCjjRDhB0PlpvfcCiNtcvoGyE9ODD9ca2TKMnxRpNTnZaXAnmmhY5uKaly9cHqiKQE
         xNIqV8rdtwPODhhLf8G785Z1SWSkNsne0nCBrfzGwMI+1ZIYVgGkHBS/NDpGa0OI8NYY
         T2iHf/bqF5i3lQ/nP0/hqFE8o4K09WCaYM1rW/jVMESrAw2onUUzKbPn12Te+sOQytFd
         s700X4+y3ibx3c/c2Y5KcMnYMkdtYW7u9/0zNwP7ffiF4jTenEIa20i5vUxl7Q2hKT3T
         GRsZTapvekH69XaLfVbabyj0hb6xqa50i8YNJJIPWatnROz6Q9omVA5nGM0PX/b9rnKc
         X+Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hiq1xMm+ShgLibpUfF/FYf7WOfFCU5xJKGzfrMaoJnU=;
        b=Ws3Va2EwWY/9/uqh2xoToEcT7yOdJNpdR//MhABscAIJPzH8n3hIFjaOHLveX5BesY
         xn6ejgIHRKS2uxVOqKDJzUsE6rdzm9ORMiE5UNUT6ebnfJhIv13GK4aFawqo2cvsUIWP
         20lI1AWixxyaOuuFwkrcDOFkg+puCBWGXntApj2gMxj1PARj0oInlAXICkB+z8bkIo5v
         mIWKQllnP2iv6CavEEAUiEB1rDETp7wmNuknNWu9v1TPimUmeWbCPTkR8xeyLsSSleMN
         ytaqW0q9q1OUne07HocvX8vj7jAm+nbOV0jTAyqBHoofxJ9roFjYA60aJXxrWgxh5Wo1
         RQ+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:to:content-language:subject:user-agent:mime-version
         :date:message-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hiq1xMm+ShgLibpUfF/FYf7WOfFCU5xJKGzfrMaoJnU=;
        b=uO0+pKl4J3sB6Wox3UqRGkLFwJo67yknurCtodfM63kHnKdmgkKBgskO0KRQknxPnx
         W7xBiRcG9F/gU1Ghyl9GbnYcZLqCU+2pulpO5FYlDM+SNXGAaW0XTGkEM8+VwXeEAnYM
         HKl9JY7NRD7pEBk9wcT0szlFdYSB2e7306RsRWr/GeV+V6Vj19jtASSEHgG9AzkFErlR
         oWEA96ZVuWcVaObN6eyovwh1dCYLB4G1RfTTPdhv9Q+vY8IjgVI+VYsn9YpSwn4o3K72
         a5a3ycmAvOYmcC/ujit0zw5km9jNxtO1KZdolao6P1mt7wSR+driwYU1WpvCYosUSuJ3
         L5pQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koVfnxsqtG3dsOL5i2qcwitT42b+1MXjdRbacv8bXKHQo4XB9BL
	OKXNC6bpFvlTORorINEyVCY=
X-Google-Smtp-Source: AMrXdXtegWjM9Pgeb3zeaTu+jaKFymWy4l+v/YxLqJ17Me9U8AA1kRRvil5tl1O3rZBadPt7Rtn9+w==
X-Received: by 2002:a0d:dc86:0:b0:3d5:ecbb:2923 with SMTP id f128-20020a0ddc86000000b003d5ecbb2923mr6644055ywe.485.1672925600588;
        Thu, 05 Jan 2023 05:33:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2bc6:0:b0:798:2357:36e with SMTP id r189-20020a252bc6000000b007982357036els7131852ybr.8.-pod-prod-gmail;
 Thu, 05 Jan 2023 05:33:19 -0800 (PST)
X-Received: by 2002:a25:7cc1:0:b0:72b:cd76:ac4b with SMTP id x184-20020a257cc1000000b0072bcd76ac4bmr43562226ybc.40.1672925599771;
        Thu, 05 Jan 2023 05:33:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672925599; cv=none;
        d=google.com; s=arc-20160816;
        b=fDaaGTDaI3YNj7uhM2Oc2ulZn9uDAgwspuuE8FNqJo1R3JhRVbOPNWY/Uq4jdjayW5
         NdL0VzOn9+GgA7+2eXK8++XyC0pS2YyT6KNh190SpEIZ7GL8aMQATMpmi5Nf88HxFx5B
         yVFcJQvcYY/gsVmNRw0TfThJlG0OZY73gIxuN1vWeeLtEPMit1tFvey2+kwa43pUhKp3
         vdCj9bl6TgyL327zsIbBPTv3FbU15TVzOJhMbnNWm7r67qjOTP2OxmhZNqUUkRGnh+nJ
         UOxAdPKeHqP9oM4mLOcEOCawMW9eU76iePVZSkoQcsQpbnW91TnvfdSwSDM4l8YdRKqy
         8e+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=ybg7AvyWptczXoF2atnm4QssNqVUB8NQ6aAa+jHrnLI=;
        b=mrmDtO0XmZ9nFxTBaDtq/jemygSA6JZc3+epH5brVhd9oiYNrxBs6dc+7uu977bt3k
         j2u2DvPOtS6/u9tY5qtTC68Tfl0tvPycsSh8qNYQxdYCONOr8HKwbx5BdNZSj4KTGWJq
         CnSm5IT6j3Tck8qa7DPAQBRXThBpirRdkZ7gNJ0qv/EKH705dr48hfAAA5b5wi+4cOww
         UprRTrwOsYcTFPDxVLpvqFJdUBT9FZGZGPl28TXPd4jRRtQiu2+jnVBZCUG21QuevmdE
         DTlECMpxExNUlGuZgqNScPiJvpzGT3AkfyRPv71xh0r7jGCRMs/KJPWSyzkBoPJ/XdLe
         ooeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id v22-20020ae9e316000000b00704abc4c5bdsi2207557qkf.3.2023.01.05.05.33.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Jan 2023 05:33:19 -0800 (PST)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav313.sakura.ne.jp (fsav313.sakura.ne.jp [153.120.85.144])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 305DX8wW057642;
	Thu, 5 Jan 2023 22:33:08 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav313.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp);
 Thu, 05 Jan 2023 22:33:07 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp)
Received: from [192.168.1.20] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 305DX784057638
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Thu, 5 Jan 2023 22:33:07 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <3e818daa-448c-9e36-7059-df26f6ce0075@I-love.SAKURA.ne.jp>
Date: Thu, 5 Jan 2023 22:33:08 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>, Helge Deller <deller@gmx.de>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Kees Cook <keescook@chromium.org>
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
 <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
 <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
 <Y7a6XkCNTkxxGMNC@phenom.ffwll.local>
 <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
 <Y7bPJzyVpqTK+DMd@phenom.ffwll.local>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <Y7bPJzyVpqTK+DMd@phenom.ffwll.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2023/01/05 22:22, Daniel Vetter wrote:
> Oh I was more asking about the fbdev patch. This here sounds a lot more
> something that needs to be discussed with kmsan people, that's definitely
> not my area.
> -Daniel

Commit a6a00d7e8ffd ("fbcon: Use kzalloc() in fbcon_prepare_logo()") was
redundant but not reverting that commit is harmless. You don't need to
worry about this problem. This is a problem for KMSAN people.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3e818daa-448c-9e36-7059-df26f6ce0075%40I-love.SAKURA.ne.jp.
