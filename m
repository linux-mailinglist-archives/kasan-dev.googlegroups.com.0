Return-Path: <kasan-dev+bncBDV37XP3XYDRBFHR6D6AKGQEVK3JMII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA8C32A0A8E
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 17:00:21 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id k6sf4798387pls.22
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 09:00:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604073620; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJAosQ5GMoY+yt2+SgSMFPoNj4FtyeATwCmlpUvpOUrI49m2JNbkWUPTjecC21jxYY
         0+RkEmLpoMJ51JkiRSAyjcpr3OcbdGrF9ATQ6OBtWKjQ1sQaKkQFQSI5/G1V3WeT4rGx
         TGZr8EHAicBEaRZMNocerSB8ePBOju1LCm4NMr6SoIu+ssr9RmOQId5mJmdXmdmLLc43
         J8ZtMlx/hhRoinlXVgfN+YjywcanrIAqY1+r9PZ80gQwUKjABNYXIq7272b3s/LzDTHy
         TLHP+Dsq0GqHHgRTNAE71FcbN/ENjzNNdarX4MUcReRrbrKqFcJ+BEnmUE16U0fVdXPy
         eSdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xY7F8bFVs2ZIL+DaTcgsRz7+L/56O28qL0K4JrVhYzY=;
        b=AFdwwVXVy+Z3+q2jtB5D7MSW2T7vNcOhWmQglAJ2+r7oNTp7KX3aDbQx9mQkyzgQlB
         hOD81PU0OGzjfob1MvFB456zPcmX8pcBbT9+/21XwkMKjbaqpSWglAetV4XycTTdGAr7
         JzbQfQfeNqC41KM3+akA8/WEynLGUBDbOSSYkUxZZpgx8STAijzt7ZKJMYKmvqqdvBIu
         1RklylFdUkqzwGKVgwQdCfKVzTgztknGzmfpF5DmIdElawWsUT8w67+MMGdrGWXb8u50
         8mR+05DzLWlwkPKjfOyt0JfDpBaMS9Vxl20TKKyW3u7o8bZYZRezMTyVyGbUgd2NK7+K
         5UUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xY7F8bFVs2ZIL+DaTcgsRz7+L/56O28qL0K4JrVhYzY=;
        b=KJcfBH9Vo+pQAKwGEo+oolEymrf2Id2R8nuAF+AxUYxT1HroRU3R/pvkSbGc45Vi0P
         89mtHx8RNoPGee4ptYGv2yVLhMFSA36R1eV1PW6jy3gFPnLxuLxC9wbBfNAy0i6Kdcj8
         3ugac+M1nqTVh8gFqBpj67odHoXveSAEpmxCgo7CzlB9+SspDMB3FpWQuFuTv2tQ1rKM
         4ZCGSv4RGCsNgWHNMVNx1BGjB1cUqHmZd4Z1hsZxFtyKCixtzclY/DPVRNn0BFpxGpOW
         Y/aM93fxzGiZLwzVsCQuQJYQUGfmMKnmsuS7oAnp42J6PxA8erWqmC6o3ggxOuYsC7mM
         +TRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xY7F8bFVs2ZIL+DaTcgsRz7+L/56O28qL0K4JrVhYzY=;
        b=Xc+1hpHE6/DsJDDhBh3/ry6z7D3D2dZNoA/h8pGXK1tRTMmXRSqwd0O9G0Wb+xmGWm
         JEl6kwuroWTkRSNWBEPCBMkmwIgkG3VytyKJGk6YJwebiZ6GV323db6+iDQ3wi7m066I
         8wORMl2FVFfq7JTIQB/DoiXJTtTPUPuzNORuAlN0Ydy4Tdy38kDuz57/KBJWBaUuUXqU
         AhFFtDAtHVifDn+AAqhQSLR+WKgs2zJHjNhCPDfkjWkLqTCeVAFDrOtTkRKeWlD584/z
         hy3UNzesi4KkEqH5d8eGmTLYhptlyEEKD2v8v8D4fKpd+Zg19XpfjdBsrcxIPMMiyfHa
         ugCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Hy0GlxqHevJ5AJZ7A0Awz1F3vo1fXEMP+3MnuvYHB0PNu6JMV
	5u9/9QOOqk/7V9kdrcbgAzM=
X-Google-Smtp-Source: ABdhPJzyyATFg3Wrnx+fO3dlRrrlXzT8NREUk6sFtS6g9FzFhPBKtzGuPbpfsLlUFNc9mO5lMSc5uQ==
X-Received: by 2002:a63:4414:: with SMTP id r20mr2790858pga.141.1604073620358;
        Fri, 30 Oct 2020 09:00:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8686:: with SMTP id x128ls2463260pfd.5.gmail; Fri, 30
 Oct 2020 09:00:19 -0700 (PDT)
X-Received: by 2002:a63:354c:: with SMTP id c73mr2866699pga.315.1604073619715;
        Fri, 30 Oct 2020 09:00:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604073619; cv=none;
        d=google.com; s=arc-20160816;
        b=fwL+yhfIX3AOsbMIzjdJNxoQMzD7IaWW+KMtf4uIKIV4qbBkRUeULwINW3jFWJPDsk
         0BL7FOXKtuTy8X6Hxvp+OAIdFrk3e7+pCPILN5ULJUmUQnq0enYgP5mXXRDBFDEQbPnf
         62TPMUQArLG9BUw5eXM09is0ggkn5dhlSZmg6+C2qEf/Nq4Uttj+CNzzG4k8eMvvDiUX
         miLjiCiHZTRcsrnyaoyKwyJShXzqjwoGy7N0mGbi5TSFJQI2/tM4m13E9YPTXPkzkjbR
         2poWv8VP2pdFM5xSLCM3CKi1B9HQGf8GNOInscqfY79jY1JR9DSV6A2vBhmnBsbtPMOd
         +fTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=FJhhKaIyk8d5QiGzRwV9qWluUhRo2iWvHmvdM4cgvQo=;
        b=NFG/owXolAH7E8d2qF8qxj+TxytB92NaE2ZP+LBbVpQRZKh7ljxupiBoerQXiUCvDf
         tv9AJIZ5jERcqbSegjWcUr/q//gMy0+d1Sc3oi7sds0Sj6VcfUikSuiZr1VX0drDnWxT
         TAenTmrlKDT9NRIZDBaUbavc713c197LAEtX0aeaVCBgUwRZQFTsES2R1MbxNZGrEhVE
         Ks1czm3kseoxTVC6v/BlU5h/7ZtQist/YJaIJuRBEqm0JtsrXdqTgknsEdfigzT5c6yM
         pQ4j7C7W9PZSNpfyzsb4cb6sPE4TOjqMqz2mMO+DDENdrP5i+0qUPU465+s9/VHAlwH+
         yePg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v8si486204pgj.1.2020.10.30.09.00.19
        for <kasan-dev@googlegroups.com>;
        Fri, 30 Oct 2020 09:00:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C38911435;
	Fri, 30 Oct 2020 09:00:13 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E2B453F719;
	Fri, 30 Oct 2020 09:00:06 -0700 (PDT)
Date: Fri, 30 Oct 2020 16:00:04 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Jann Horn <jannh@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H . Peter Anvin" <hpa@zytor.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	kernel list <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>
Subject: Re: [PATCH v6 3/9] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201030160004.GE50718@C02TD0UTHF1T.local>
References: <20201029131649.182037-1-elver@google.com>
 <20201029131649.182037-4-elver@google.com>
 <CAG48ez11T4gXHkhgnM7eWc1EJQ5u7NQup4ADy75c1uUVPeWGSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez11T4gXHkhgnM7eWc1EJQ5u7NQup4ADy75c1uUVPeWGSg@mail.gmail.com>
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

On Fri, Oct 30, 2020 at 03:49:26AM +0100, Jann Horn wrote:
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > @@ -312,6 +313,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
> >             "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
> >                 return;
> >
> > +       if (kfence_handle_page_fault(addr))
> > +               return;
> 
> As in the X86 case, we may want to ensure that this doesn't run for
> permission faults, only for non-present pages. Maybe move this down
> into the third branch of the "if" block below (neither permission
> fault nor NULL deref)?

I think that'd make sense. Those cases *should* be mutually exclusive,
but it'd be more robust to do the KFENCE checks in that last block so
that if something goes wrong wrong within KFENCE we can't get stuck in a
loop failing to service an instruction abort or similar.

Either that, or factor out an is_el1_translation_fault() and only do the
KFENCE check and is_spurious_el1_translation_fault() check under that.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201030160004.GE50718%40C02TD0UTHF1T.local.
