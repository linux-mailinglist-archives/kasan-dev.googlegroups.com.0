Return-Path: <kasan-dev+bncBCT4XGV33UIBBTXN2G3QMGQEA7YUNPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 762A09867C1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 22:47:13 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7179469744dsf360821b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 13:47:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727297230; cv=pass;
        d=google.com; s=arc-20240605;
        b=HvOMoP9WLEpVK4h11DcWsOfxOvobTTzSw6rCZQAv9dAOdEFPJV7InmMFbQv7RLH4hz
         icOBhMrLNchEwYDrnfSCbQkVmzltUWabwxx8pXGhlddBes5F6BkT6cbJbPOVrPKraKjj
         3nZh9/PhaVmYdXdht1NpZPD7JXVybMkZwb3hRjFSDPtxmiUAefnxDxlneHe3DzCcbXzk
         S1ESuXV8biDfYTW2FjEmQgzz8AydCRHegSm5SoeI5cV5ot1+LYPjHVaB5pxvcIOzmREn
         yNxODuwfNfpGJA5znpuM4YLd//uVp3lElNiG36JQg0uknbGEAqCRKVwZN0qrSgtEhdXf
         a1Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=L/+nl8GzNliheBSHu4gR5vkft1rpPm0BdOH7nK6GqzU=;
        fh=fo6EviFxyaPLPJwf+ySoXIWOrWDdfVDPE/ogfycLWiM=;
        b=iZh+71Fx7eP8wBn92A16p0AlzXgyOMjB/xCzkE0Y7nKYjfwk1p65RHovsWFTjzIZpY
         k+aDnt+7MLln4zH+h8f2KbU5p62Q4kXU0g/tE1j+iWXDHuH7+OCamzzNfHH1rZ8OjeoA
         SXlxaMlZEDKPUl9ZrT9oemh3v85fgQoZuPK0INC9C2DDAbkSU8FIATopnb++/z8SrUJR
         Beg4bvxb+jetYYTa+5z/+IttpiglrT+vUarS/8LqKV/Wvraj7QgmjVWshloyPi4tR7xO
         gclS2h3Us7B0vz3rMYHvwIJNhDewWGVkM07lPLXW33/8ESnUs4bErs0JQYcPBfvy+HMx
         ldlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=F845A0rO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727297230; x=1727902030; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L/+nl8GzNliheBSHu4gR5vkft1rpPm0BdOH7nK6GqzU=;
        b=CQ8+0i3arX3eQBSGc+DjH0Eo/ks9OCmT/rU/6tLQcki93QHPEzaH/5y5TZkdDf0nU7
         eM0MR1NsW2Rz8StXB2ndk739jKJvDxGyS6BqQaaZecANwdcOFfztWLfhC3k4Gk0bIdWk
         jWEbJBQ346tYB0lcYnuXZWADFUdppZfjW1oNfdjt1oAeoFhuKbCa/uhusL1JgoD3dL0a
         q9FP65+XdNCSA9UmxoF9NZcobCCsqUI2gJvKoV0I37Z9XmG9clj9H412zyel7CfgCBH6
         Bn6lP9CXXjfmBFUuF3UOjnKD5ukyacbFNH5jx2NgsjOyOQa+WNW7rpV1xA9q5FGySAfl
         4LPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727297230; x=1727902030;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L/+nl8GzNliheBSHu4gR5vkft1rpPm0BdOH7nK6GqzU=;
        b=DHske5y3NJr3yDYD9Rv1h5cYKPU3yqiuB0CvWdHi9UzD12eX/UW1z6cL0VXyKK9c8H
         4CAHBxw2A+cqvvyrcAmCmJ8mnV9RgW13dDyhI33yU/7NnUcsQvw1ZhYLwwdg6sO64os+
         HYyXn15QT1/9YxTyK/5vFdTnjM6XF5dUtPhIrWHcI/+7ZxEHIbU3rA7d1wfSy9jlmIOu
         44spEtd7RcysWqcxTjP9Qb63Z9uQiic+kJ17xR8G/IeHmuHRJKQedInbERnT1kWsNwVl
         YGQ+M3mv40owmYCAmKdtind0lsKG27LrWbwHi2DqVE5gPTUgvr3lT0J5xH5Q52qo4fcG
         3haQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkCw7uGG9Nx1E3RivClBycgPjzu0GC43OQcz3ZDVFu2ZGYb3OwuzZ2Y+EOj3X8rEUcfoEuJg==@lfdr.de
X-Gm-Message-State: AOJu0Yzem38WNgeaQahCZH3NI3dnnDteCQ/3rKgonk+Hpy9yaBaZTTzV
	xNfqipw9lE44yvNQS6dk6Q1HDZLThYSrY8lnFHyZtPS9XjTbgdLs
X-Google-Smtp-Source: AGHT+IF+RfFcFmQgbPDYcDOwvmj7dd3BxVmiNs0iIw2vyWjml0IWpIrumjQfjC73TrBTlRzCHPlO5A==
X-Received: by 2002:a05:6a00:21cb:b0:714:1f6d:11e5 with SMTP id d2e1a72fcca58-71b0aaafb3emr5109737b3a.12.1727297230201;
        Wed, 25 Sep 2024 13:47:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9299:b0:717:84e8:f50f with SMTP id
 d2e1a72fcca58-71b18c1ce70ls252066b3a.0.-pod-prod-03-us; Wed, 25 Sep 2024
 13:47:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVB+VH53ZdHIZqDD35L3AHNNOGZsEGcoSNFDRcZ+rJn4N5AmeqmEs7y5yuQYI9mGg6F5q2afdch01c=@googlegroups.com
X-Received: by 2002:a17:90a:8c14:b0:2dd:5137:a9df with SMTP id 98e67ed59e1d1-2e06ae5f847mr4367340a91.12.1727297228783;
        Wed, 25 Sep 2024 13:47:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727297228; cv=none;
        d=google.com; s=arc-20240605;
        b=McJsEqTNvRE8VMW2HQKUJ/jybZn0ctJ9TCLFogQLal2x6eUwJSaN5wRwMIkjkrX86c
         neILVquUEvfMVCPiuJGcyHXAKarSvAuP+kQl9Fh+i2V7yfKpFA8J0JBRBIG/gl4L2Mjq
         trld4AxS85KxJtYs7WaBjLRodmI+V3ZqiKunBuZVu8R90ZkpRT0upmJ+j8YPsE5FA6yu
         RPvqut+kGTRtR7lhABFcrA8UN8NIMhJK1ldZu3hFeKNiLQ5T6orQ+NNYhJI9wqpqyS1m
         3y9K8673UsCurUv16ie59UF9TnpGPL1dG3HfrpjomI3o8BO+dgk7R2P1hI950LQdh7fZ
         qcNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8vwZsLsJqnGGsWmw9eRd6+825SvNtUPHR6+TnWRg3t8=;
        fh=J01G5hgtGyltc4MXlGqe9rGnuKOP+Un2uRYEwgeKTrg=;
        b=PzJ6Gm7QN8MNHoqhfSu+mBi8P1fhSJ3gvwd+yweFx/wPftoLRTJ7qd/9CrgRrNOdUm
         LScOZk5g64ysraHmJuQO6OGLb5HP4w5ya1UtmRM9sXTjbw9r/kLtJ6ktZd5Y75mw8JxT
         hj1VOQp2I4K+tb3xPrsb2VY4KQEP92NQqi/qny3AqGGzTBl5cN/0rLnE9r1/RjZqsIWO
         lXVNofXMVL9FH99TskaqqE2s9Nwo4GUuerstXBpKX7KlsBK9WD+h0Nd7TY4+oaYJPGBs
         76YD80u92FYI/RI7/5CkKTaxDDKUF6QMwPYf1eUqyD9zGyBc/r4Ap/qB3k1q52+UvIvN
         7vqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=F845A0rO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e06ca9e74csi181217a91.0.2024.09.25.13.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Sep 2024 13:47:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8289FA44823;
	Wed, 25 Sep 2024 20:46:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CD996C4CEC3;
	Wed, 25 Sep 2024 20:47:06 +0000 (UTC)
Date: Wed, 25 Sep 2024 13:47:06 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Adrian Huang <adrianhuang0701@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Uladzislau Rezki <urezki@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Adrian Huang
 <ahuang12@lenovo.com>
Subject: Re: [PATCH 1/1] kasan, vmalloc: avoid lock contention when
 depopulating vmalloc
Message-Id: <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
In-Reply-To: <20240925134732.24431-1-ahuang12@lenovo.com>
References: <20240925134732.24431-1-ahuang12@lenovo.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=F845A0rO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 25 Sep 2024 21:47:32 +0800 Adrian Huang <adrianhuang0701@gmail.com> wrote:

>
> ...
>
> From: Adrian Huang <ahuang12@lenovo.com>
> After re-visiting code path about setting the kasan ptep (pte pointer),
> it's unlikely that a kasan ptep is set and cleared simultaneously by
> different CPUs. So, use ptep_get_and_clear() to get rid of the spinlock
> operation.

"unlikely" isn't particularly comforting.  We'd prefer to never corrupt
pte's!

I'm suspecting we need a more thorough solution here.

btw, for a lame fix, did you try moving the spin_lock() into
kasan_release_vmalloc(), around the apply_to_existing_page_range()
call?  That would at least reduce locking frequency a lot.  Some
mitigation might be needed to avoid excessive hold times.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240925134706.2a0c2717a41a338d938581ff%40linux-foundation.org.
