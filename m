Return-Path: <kasan-dev+bncBDV37XP3XYDRB3GORL6QKGQEQJS3CTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D62D72A64D9
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 14:06:53 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id m8sf9541388plt.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 05:06:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604495212; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sq++SF5HwMW0TnaGOnK7tMinDrr5utn7rgcNXEq6Jq1OmyKI+/0kTZnre4iAZugW2x
         woGpXzaiZM6XLW3qJKJxzKRGyt6WVK+/cEInW5bQemJolGc4nMSXJyREB+/ib0CMvvPy
         pO5t8zTMXPU1XpTDGzq5cmSeZMz6+URMx/7ANszh1mEpbvVHhygttkGPTOAJuC0vsNAp
         Qk2nPSBSyuHOd3qj7taGIapcrIadFytjQuocmN2iZIUNyz0ELwZKo7Qz3v1B8lS7GVdS
         zKISCQeCWnMh50wQ9DTArZH+1rTbaNjUOjjSANmnSCF/cimHxCKTLzORcmcOoyhqX5fF
         otng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=l+jnYhA9aP7FwL1EyYxr6GJl5RzPnxa9m/sZZXqzzo0=;
        b=XlYVh0VhRU7B/MlCfN2p8cvgu894JqqAKbmJ8swf79EtN3ZUKqCbjLQfpjYm63Gp2e
         8NICPGe33oDFPk2qe86S+OE1tqBR43t06LyXqzyP16b29FbtFTQGbEt8kQTydcMupkPa
         k8eZ5kYycDcdDajHb2BtTWJYvOvhyOkbmrslVP8NAs8JJoS6cq6+VuABBC+y1lBe++o2
         CFRTQIIQyQLYNnjyvatt8bIKphDCJobVpxj6FFyjMtzXpEuXQ8ILk2NeMX7INveCJlNn
         81FkLCwPkUIzlaBi7qq75hoysg2ZTACuNWW/C3dyJv3X5XhTEpXh/+J+dIeZ5RAiu0xf
         co8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l+jnYhA9aP7FwL1EyYxr6GJl5RzPnxa9m/sZZXqzzo0=;
        b=JFPGotmq3NehxtnZ4yKT9XseJ2IBLyg8Ln66TfzG1XbwTbgYwnBEDMWx0zzXjn9JKP
         DEqsqoOVJRs8+Sa64SvLeFeOPkl5N98Pz5JkoWCqsSN3ggta42bMCYIeNIHKlfiXBMAB
         pjjrS1TGN7O1/sV50Yxbg/e0gJKYx4X1ntg5U/4PMu+A7N/0GpALr1iX92esviGXG6tl
         huwCkkU9+7zPrGTZUK44mxh5jsXktgu9eWa3zc3SXk8SDmu0J3aVaqkr0Xs2fsnGbpv1
         YWlIizfpzOUm4KQhkq8xWJkGbxkknT4qV7RnAYMs1hEZDMiiJtvEqHabr6JwtM3p/0pn
         EuUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l+jnYhA9aP7FwL1EyYxr6GJl5RzPnxa9m/sZZXqzzo0=;
        b=kKuGskzggnKyCMtKMV00Va8KwGe5vrnePa2Qbk2tqhyjLp+0MwSI7rNVfCMovziQuM
         1UrlciMSBCLY60DsqMP8qVW7K+H+HWDv99P/cqg35w6VyN0aHLLhidLIhxhyhn2N5A0i
         IIpMarhFdAHqrYOxzKIvYUw7MPRjHfLL/bRsQV24b3sD9tYFK1tyY08EeQPN5LD5Suca
         S1LRiOUXG+gsGna2dPu0FwFH5i7YdzOABE57MzO4VS8gZX9cJyWXtC0gJoyEZQ8ys+D4
         djKK6lBWnPWcCLT5nAT77ooE+kvFJuYNo1NgPUs1h8qhPgG4pEfzeD8lycUztYBxZV1d
         /q1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531m4jTZIV8HBa/FGyIzVbFF/h+PoBQtZ69aHmdr1rYdhGbTxmd9
	5BNV0Jowhhcc7KxwFYM3YCs=
X-Google-Smtp-Source: ABdhPJxrtsOHtxmrZYEb+Whs0AIc+8wFROfkjfpQS5PQPyipkF04syrbSu64YXrUFhNnmgsB9EgPaw==
X-Received: by 2002:a63:eb09:: with SMTP id t9mr21149296pgh.279.1604495212356;
        Wed, 04 Nov 2020 05:06:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:843:: with SMTP id q3ls872579pfk.10.gmail; Wed, 04
 Nov 2020 05:06:51 -0800 (PST)
X-Received: by 2002:a65:6158:: with SMTP id o24mr22319998pgv.120.1604495211729;
        Wed, 04 Nov 2020 05:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604495211; cv=none;
        d=google.com; s=arc-20160816;
        b=cmKrR6Ik/DsdfVvRSpHSRPxvA33jCMEya78YbliIrQZFnDG0w8jRsptz0GMQrBUqB0
         gq/IesQmPbrzX48wGNgfv/FeJB9UbDu4oYNaOs3Tt57udDCC0FV9PamgN8/rSKrqFD1r
         nQhHrd4S4k+fnVUiLK7rRGsijyoAM3dem/tCTz83zH+uoq2BZZ1DcWyIkrdueItR++Oi
         CHns6+2lIG01+LFgMhqFQhtvkcTRLy0wxrJfcVTYWqsR72QcAdDqaaC/HcR4ZOUEKUuU
         lph+xzifMeKnBgT+I8qZXDgpfdRpkbGsTusgxFF7Uc3A6X8Y0srh83tqoWscr5Trbf0I
         Jiow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=0x486GN3XGbl9tzPuRm5HyRGnSu1RYkhpCwVe6aq+Wo=;
        b=pypmjuMGwQc8SinoKU0fwdbHSwieoYJvLxdGV7xyCSdz0S+S01nTq4MFf+eOaa2r5o
         qNR7e8DxDiun744XFm9X9ZAYpUG72/DWvstrV5NCCwYAwvpCcuxlURJI7FRxHlnw4dqw
         DKC3ZgENPfP0IXU7beUOk6HU72RqeWP9mIXIaxJ9QE6qQpG4zt3ANpCaIJ6cZTrseCBB
         L3W0TnNBn1X8Qc8TVpWMVAx32eKCGWleEYP/El1N9ModfKYf7vyCg1GffRa0E5zGreCe
         56w6BGUARyW2/ju+2T5zlZsN+zr2r/bCxb1V8C1X8sPww08bMDU8exXuizARqZ5SXAev
         JxEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p4si108559pjo.1.2020.11.04.05.06.51
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Nov 2020 05:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F721139F;
	Wed,  4 Nov 2020 05:06:51 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.57.109])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 29D1D3F719;
	Wed,  4 Nov 2020 05:06:46 -0800 (PST)
Date: Wed, 4 Nov 2020 13:06:37 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com,
	cl@linux.com, dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	joern@purestorage.com, keescook@chromium.org, penberg@kernel.org,
	peterz@infradead.org, sjpark@amazon.com, tglx@linutronix.de,
	vbabka@suse.cz, will@kernel.org, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v7 3/9] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201104130111.GA7577@C02TD0UTHF1T.local>
References: <20201103175841.3495947-1-elver@google.com>
 <20201103175841.3495947-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201103175841.3495947-4-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Nov 03, 2020 at 06:58:35PM +0100, Marco Elver wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
> 
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the entire linear map to be mapped
> at page granularity. Doing so may result in extra memory allocated for
> page tables in case rodata=full is not set; however, currently
> CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> is therefore not affected by this change.
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks for dilligently handling all the review feedback. This looks good
to me now, so FWIW:

Reviewed-by: Mark Rutland <mark.rutland@arm.com>

There is one thing that I thing we should improve as a subsequent
cleanup, but I don't think that should block this as-is.

> +#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"

IIUC, the core kfence code is using this to figure out where to trace
from when there's a fault taken on an access to a protected page.

It would be better if the arch code passed the exception's pt_regs into
the kfence fault handler, and the kfence began the trace began from
there. That would also allow for dumping the exception registers which
can help with debugging (e.g. figuring out how the address was derived
when it's calculated from multiple source registers). That would also be
a bit more robust to changes in an architectures' exception handling
code.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201104130111.GA7577%40C02TD0UTHF1T.local.
