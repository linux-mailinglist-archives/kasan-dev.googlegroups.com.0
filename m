Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NPUOGQMGQETIOERBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 385C4466540
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 15:28:06 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id p17-20020adff211000000b0017b902a7701sf5083008wro.19
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 06:28:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638455286; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q4QkcsR+R+XbIkMoQorlI60a3lo+eKXb7nFLV5nDEKJ1U0pSYWktWloINSJu8MVVZR
         zfARtLMFAO3Wv3WBReL6qQ6n/DuL5gNWRGnhZdLMfM88RZ0/CkK1dC/J1Ig+C7RQs7U5
         NAG+gidARWfvY8D2blW/MK89XKl6M851WqAQZPfeD6KcHvaxEeWiLzaU8TGnQf+eGk+p
         7pWnJBs30uMcIwouSiaYq8yorQxdCNgytAfMcrxi4xLyM2CxOQpf88kayKHrnal8GDe4
         dSMfsUPypqrvFqM0LzvKRx6Qc/msPpiK60+PxngFpRkz8q5df2mKLoBQwuECGkVKHJeW
         vsYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=iFtBuBfBUy2KjNHeZ+AOau2/b+yCkCqrvXOVqltIXKQ=;
        b=i1aOYkvjpy3L3KeYqNjIIkwAYsfsw110DLeaETRBQJXvGB56weMG+BYNSu9A+AMlcN
         2qJsFH2x9F6GqOAQR6/0UKEBOZ/1ZnMBRgAlAq2LulA97b4iyGvH2SR8AeX5F7TQO11b
         bXIqFMucU8CNjaFA1LnRi5ladZPms0qN+yDyXX1XxlJzm/6kHjL0UrAG6iaZ1TZDeK78
         o+UGQiUn7GsI4aUsTUAePzk+tfwm/Mu8GMnE/PveFWXkrC84O9g+y3eQBr2wOXTowauz
         A+Tk2eSxH3ylSTE2z9sUU7OQzkGhaWT3PsZV3cvOTKme4rs4gV/JMbmjjFQ+yS137h7y
         rbDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TPi+XE3O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iFtBuBfBUy2KjNHeZ+AOau2/b+yCkCqrvXOVqltIXKQ=;
        b=cGw7L75h6PXToaqEly83z3ecvTvzuRsxEdFLJFKRbhv2aIcfKCXeQF0Ve3/hE/a4k0
         c7j6yESsgJMlJipENfYCypDxzOgtByen/olWyQ6QU2v8+RDZB/QtmvyHHcGLyLb8XZgY
         IcYKsbrXCBYSzIOX7mfjmXqsiaxA60uBiFrYz2wf0cY+Owj/sFIjS8frXVSFnCEGSdWP
         ARDPF85lrniwRVOAZrzVwy1E5XWq6mFgRSQJOjCSIi5Aj+7Kgk2sNsh+6wEeaUqSgEoT
         wnmrOPCE5BZlMnpbaLRLbj2RJSG3nok5qDNtVf2pPCSpDLd1Ei+sRKj8ad3Ka5rxiqE+
         QkYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iFtBuBfBUy2KjNHeZ+AOau2/b+yCkCqrvXOVqltIXKQ=;
        b=Ci+TR1WHugh3dpahHoB1R/Q3DVz9ajXGb7dsoUkdGTx4KEX76564C2sXo3DUNyABDK
         DiCGe4VUNSN8BwBO9VxcToLbkQPceTIOuHD+rUr8LxNP+ZMHlSt+JS9TmBfQAEad27nV
         K9JNtB1de1h5l5TRpFaorrd+bPsHVnRpeWOvDkrCQ08a8FdDcQ/6hQjJ26MOVEsKWle4
         Xtd9EPtpIeasod47dMnUlAhk7fhKfwOwLPE62kCW3EzGenA3F0m2MbOYCi+oTf+TdfOW
         fiQ1J50iWzkJhLyK1kBzd7UKPiTiv4LxDohuROtwvhnOg0vvme9pnQwKYNKwZ9VuZoAS
         cUFA==
X-Gm-Message-State: AOAM533ILH1XHZ5ktZhggbmqtgwMPbq7limSQ3R4NUoQBf2PbWq3Q4KR
	UjSEXMonWOKLgAormkRJI88=
X-Google-Smtp-Source: ABdhPJxgTAMra8M/qo4EIMw56OaMx1T8yBhm6TzwVVkHRocjhfpHhFXnBTBC4UaJ/BQubFF5oa3UgQ==
X-Received: by 2002:a05:600c:1d0e:: with SMTP id l14mr6637256wms.64.1638455285929;
        Thu, 02 Dec 2021 06:28:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls5073428wmr.1.canary-gmail;
 Thu, 02 Dec 2021 06:28:05 -0800 (PST)
X-Received: by 2002:a7b:cf18:: with SMTP id l24mr6914907wmg.145.1638455284910;
        Thu, 02 Dec 2021 06:28:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638455284; cv=none;
        d=google.com; s=arc-20160816;
        b=u8reG6Yxpz/vGnQz+J6e3bidfPHz5eld4rxsZntrgWbxaiVVctFWRuos6ml62/jgcz
         QUz/PqVnFsol2KqSx/Lw8mFFJ4G/eOfCncoHEwtzQa7gN05Ih5CBRuHbvybSJbrbzoq7
         xkKmn/+RFolvMtua2CF8RUADSswY9Bq+BvbU3OOooicPgAzcK+VS6U10Enzakp8akaaZ
         UTmBNYmyEOQ0cA/BMsD+tJzDiwgzubl3WD+YeKNP7k6HSaH/LEXHa4lUfOYSzxDNdAA+
         nfPS0nxMmxG9PgJhG664M3so7Zttz4sYHh7gQPUzS54s2jytng2aTSblL38jD5Pg5BYn
         JEqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0bMo5owWEWMIAHQEq+ayNoaDPR5E2HoxKytk6h0JhPY=;
        b=kchyxfU30JPA9RBlQ61xyNhxnHTfD7xYGqMxVSbCwPplZncrNSMtjw1eLTa2U9UF0W
         K5SCznDn7Q9m338WYdfrnOK+e0lglvucKvqunC7FRVtyeOlBEPJj+Jg7+N3itkPHpHYs
         lcJkN7JSw4drHO0ZKz2gfSjhxlawPSE/fKvosDlyZji7gCSuYNyf3xInQgO0XzMSwoua
         YGodYqccmVnQFjllqxNcyM7EfsX09vOfTNbbCjA0lXhDvIKj5nsqAH1USQdXwQ0Uhvpd
         CZtnfnjz3DUpQcFkL0FpL/5vDZW0PaPNvt/zkXE5hA8SPOIFxsvPAbLBJsBsT31ijcsx
         ZlNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TPi+XE3O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id c10si149877wmq.4.2021.12.02.06.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 06:28:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id t9so43045799wrx.7
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 06:28:04 -0800 (PST)
X-Received: by 2002:adf:f0c5:: with SMTP id x5mr14116782wro.484.1638455284429;
        Thu, 02 Dec 2021 06:28:04 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ddd6:f3c9:b2f0:82f3])
        by smtp.gmail.com with ESMTPSA id k37sm2403749wms.21.2021.12.02.06.28.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 06:28:03 -0800 (PST)
Date: Thu, 2 Dec 2021 15:27:58 +0100
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
Subject: Re: [PATCH 21/31] kasan, fork: don't tag stacks allocated with
 vmalloc
Message-ID: <YajX7pyIK27Gd+IE@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <4fbc6668845e699bf708aee5c11ad9fd012d4dcd.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4fbc6668845e699bf708aee5c11ad9fd012d4dcd.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TPi+XE3O;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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
> Once tag-based KASAN modes start tagging vmalloc() allocations,
> kernel stacks will start getting tagged if CONFIG_VMAP_STACK is enabled.
> 
> Reset the tag of kernel stack pointers after allocation.
> 
> For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
> instrumentation can't handle the sp register being tagged.
> 
> For HW_TAGS KASAN, there's no instrumentation-related issues. However,
> the impact of having a tagged SP pointer needs to be properly evaluated,
> so keep it non-tagged for now.

Don't VMAP_STACK stacks have guards? So some out-of-bounds would already
be caught.

What would be the hypothetical benefit of using a tagged stack pointer?
Perhaps wildly out-of-bounds accesses derived from stack pointers?

I agree that unless we understand the impact of using a tagged stack
pointers, it should remain non-tagged for now.

> Note, that the memory for the stack allocation still gets tagged to
> catch vmalloc-into-stack out-of-bounds accesses.

Will the fact it's tagged cause issues for other code? I think kmemleak
already untags all addresses it scans for pointers. Anything else?

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  kernel/fork.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 3244cc56b697..062d1484ef42 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -253,6 +253,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  	 * so cache the vm_struct.
>  	 */
>  	if (stack) {
> +		stack = kasan_reset_tag(stack);
>  		tsk->stack_vm_area = find_vm_area(stack);
>  		tsk->stack = stack;
>  	}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YajX7pyIK27Gd%2BIE%40elver.google.com.
