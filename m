Return-Path: <kasan-dev+bncBCT6537ZTEKRBVPWX2PQMGQEWIO3SGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BB67169B1E3
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 18:37:26 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id z9-20020a0568301da900b0068dc4cd084asf641257oti.18
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 09:37:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676655445; cv=pass;
        d=google.com; s=arc-20160816;
        b=YFKlvQFJpDSyE8OaaC8f5u/b/vX0uWoutKwQ/YpNT1hC6nhRzclx7abqYsL5g+SW0V
         2/scJR+3a3wg40Ax2MrLIkxRbkMulys0PwSHzODyOhbhvj6D7FisT8r8NJbC1WZdyify
         T/Fk0GHbGOw+XPZCEyNf98DTb14ukdhZteI5AYbR0WwJk4ghrJQ96BWaRNjw2eqGO6Rk
         aUcjZf8cW17ibbs8k1nQuuHFBOAdnzy3YalPpS9s3JJgSOXN536Rvlb1cabdy0dWGD6r
         j8DUszsdmHO6FY4PiFGlpSHklAoSmpFA2Z4v0PpQB+DIpQmTCn+SUcp4VdoqWga3/QHx
         mRyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2sdnroRnHEGs7saO+OSolbKpEbTKWaeFlthxyPn2YLc=;
        b=UmM1mXnXWwwwzcjyTL45ehe8dg9FJFcx0YHRh+suCSn5iNYqBl8PNflpJq8WyROlHe
         xVvRWZB2FLzwo85lqv0fNcrnn0Tp8+g+L3zsBQw4+wJNe7/J2WBJ+BactXifnvsv0xw3
         vbcy5CZn0+VBxPE7cCIBQo0zszsKF2Z311PjkM+XsvhHBXIhOj+sU1UzBWQSUcjt5iUQ
         LBnwQGetQ10m5QWqdPUAxUBU5Mq4KbWQhcWbfBX/B2ItSUCMnpPheyox7kP7/WNQtkjl
         NwsSH2JBjgx4tjfKnJIgK5HpNqL5xDmA8vEK++IQzgn2j1qHWqdWmxToFDT54iwXbAnv
         2ynA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=migPS26i;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2sdnroRnHEGs7saO+OSolbKpEbTKWaeFlthxyPn2YLc=;
        b=GCXYtzbMp0XnyXESjqBCAJPktxkMWaRfJ36OJRFEr8XNEzQaqx0LXbxfHs8tiS0fVI
         iGEiuV6iFeOKzuV1nJ3M5FP54WoL/v3VE/+OfZbeSdJmhj45Q3FgjfTlNv/6QDClCNnk
         cZ7oWKJdMLpAPKwAklfPxt+ErlHXHKV0WVwsQQDoj9dmtwVERdrvI8GDAvDIKz+st70l
         1O5SlhoOXXbFFRMKY6HLBIDOi6ColNhLOyH7rdvEeDemPxL1Bci2Hd46/Yz/ZqQWR7jt
         jsO05T0Ju1hSFLSi51T02iEdYI6Eb0hb9FGQ+vdYU2c97Q49oZczax+rhRVPw1p2WsCq
         aKuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2sdnroRnHEGs7saO+OSolbKpEbTKWaeFlthxyPn2YLc=;
        b=yPn60vVVaB3T37IDw8tyD6IIQ7K3wZjs6htkjAaNzsnd/Fr3Qlw9tWkkxQLA0Ke4wg
         wVYZUfGaHP8kh5zGlcxVxWOZEDCycgFpTBiRN10yhPE2Dj0VdCmRxqi+ULA8UcjVD8U+
         3+GTp96ydnQaFCtM53V0HPvTw8Wy4wm0mmI8+di2rJAjzSwMIZ8IxqssK40dgi9g7Hgf
         n3MSwYDrGscRjCSul1GQxpcJZdjUGN2lBOXQB8MNd+NkWeF7kQwTZLXCyYuhpMBGwGCA
         6zFj6RZyu6bBa5Hyd78c4+KiwD8pW6Jt4PzohmKQnKLVpemDGBl2rm0ubl38AcZ5YfTE
         MVMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXxT4rgx5o839/zESpAPa0PVQEx+mzpofyVXBUwgs7++iy9blrX
	UNYb8vlNThNa9AYKfWj/ahQ=
X-Google-Smtp-Source: AK7set/tq+XEodkn/jgvOaHHfA9A6BqQqlfEgs/zetMHnXz3HI4eoJQx9bzT27Vd8jP01Td/jJCZxg==
X-Received: by 2002:a05:6808:1786:b0:37d:93d3:e4ba with SMTP id bg6-20020a056808178600b0037d93d3e4bamr529206oib.113.1676655445219;
        Fri, 17 Feb 2023 09:37:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7984:0:b0:66c:e766:8d07 with SMTP id h4-20020a9d7984000000b0066ce7668d07ls216371otm.10.-pod-prod-gmail;
 Fri, 17 Feb 2023 09:37:24 -0800 (PST)
X-Received: by 2002:a9d:720a:0:b0:68b:bd49:36e9 with SMTP id u10-20020a9d720a000000b0068bbd4936e9mr208089otj.30.1676655444652;
        Fri, 17 Feb 2023 09:37:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676655444; cv=none;
        d=google.com; s=arc-20160816;
        b=znA1sF18JcTcG9vvvLfodMiB+YbQRkLtNoQf/oiWUsAXQhoG0zXPPXpaHdDOUKC5hi
         vaNzyTxIZtL8Vd+PCv3bMxBce36ab8QCH0t9X0himtTiY03YJobdHgQM51yyetD3/Jx1
         P69KECkqsc7A7gGQ1F5NFiW6dUkUi19CIG5apR9WEOWc/XXNig1WLGR5q6SOPzGdzpmv
         ySj/d6TsAth5d6TDn/L4q2R1x0TvHuH2+9gLfUZP/bxF3OL6zpSL9sk57Qk+6+UBDcZ5
         YijcfoC7Xp9gBwl9Vj6/IYPQTI5SiBQVibl8P67FrM1CzD3bX2zuZeZwRojUMSEAPxnl
         sprQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0mlKR2SiEJ9tOPTNmRsqma/dHgH/w4UzqWx3jVVxzeg=;
        b=nnjLTTm6C2alNpfIz4zHf6BAlcbpTnxhZuPJsI9cyi50bWowOjFu0s/3BRlnr8Bn9c
         lndITEk86NFBMS4ezErDNFlVIAUFhfoqIkrvnbk9lU1Qh3Y1Kx7ceSIzawYnJARJIbwG
         /dWE7eI3Zka8Ih2lRWfXXsmFHQQM++RbHU9CkWqhUwhrqBnTFG8uKIwrKpQWqPRSE+zD
         YBogkYQ6xcYMhM7iOndQvRZZEjiGVn2z0P+5RL6ii1mXeo2AqzNSEEUJoSikxum7ZmfH
         VtTttqXvTEXJJPDrvl4CkWoa9oKytMxWvUpVeVJyrO6dUiETX3b/vi4UHgqUR7gDi84G
         vhTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=migPS26i;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id by2-20020a056830608200b00690bb9c5f18si509940otb.5.2023.02.17.09.37.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 09:37:24 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id p33so1008471pfh.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 09:37:24 -0800 (PST)
X-Received: by 2002:a62:140f:0:b0:5a8:5424:d13b with SMTP id 15-20020a62140f000000b005a85424d13bmr1712775pfu.21.1676655443710;
        Fri, 17 Feb 2023 09:37:23 -0800 (PST)
Received: from localhost.localdomain ([124.123.168.102])
        by smtp.gmail.com with ESMTPSA id m4-20020aa79004000000b0056be1581126sm3393702pfo.143.2023.02.17.09.37.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Feb 2023 09:37:22 -0800 (PST)
From: Naresh Kamboju <naresh.kamboju@linaro.org>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	glider@google.com,
	jakub@redhat.com,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-toolchains@vger.kernel.org,
	mingo@kernel.org,
	nathan@kernel.org,
	ndesaulniers@google.com,
	peterz@infradead.org,
	ryabinin.a.a@gmail.com,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH -tip v4 1/3] kasan: Emit different calls for instrumentable memintrinsics
Date: Fri, 17 Feb 2023 23:07:13 +0530
Message-Id: <20230217173713.90899-1-naresh.kamboju@linaro.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230216234522.3757369-1-elver@google.com>
References: <20230216234522.3757369-1-elver@google.com>
MIME-Version: 1.0
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=migPS26i;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Content-Type: text/plain; charset="UTF-8"
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

> Clang 15 provides an option to prefix memcpy/memset/memmove calls with
> __asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724

> GCC will add support in future:
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777

> Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> architectures that require noinstr to be really free from instrumented
> mem*() functions (all GENERIC_ENTRY architectures).

> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>


Tested Kunit tests with clang-15, clang-16 and gcc-12 the reported
issues got fixed.

ref:
https://lkft.validation.linaro.org/scheduler/job/6172341#L618
https://lkft.validation.linaro.org/scheduler/job/6172351#L618
https://lkft.validation.linaro.org/scheduler/job/6172338#L618

https://lore.kernel.org/all/CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com/

--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230217173713.90899-1-naresh.kamboju%40linaro.org.
