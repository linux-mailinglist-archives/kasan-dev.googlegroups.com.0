Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB4X65X6AKGQEQISC4MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D110629FBB7
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:26 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id t17sf2080541wrm.13
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026226; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y7EcC9/1fx5y/oCEM01a6+kbW6akwHqkLrThw6RiiowqHHrf4x1DPLo20bdF4rF/Eu
         PlwK3+u0C3qcVbUdZs8PkNlQg1miBMmgaDbpo4efM2vDf7Vo/itcVCJdg4m2BDC9v/yz
         eGLGmoiRMhTFlGZBAR9HZQ6GUl/aIp45muSbAaK3NiSeZo0xwG2Ad/TFTpQ3ojmm5bpX
         fpIzMz66LMiMF/szXflAlFaKAQy+PsEbbi+r98gNqfoCqcUFTdXCiIGDm9bzPAxLS+EF
         /sV+W+OGvpM3SpBMS9TQRBMbcY7HYmBFdnICZ9/udPi5IknIkiwEraKzsmuCToP4PwjK
         1lpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wVaQkkIrsIha/op8HgYxYI0WKV8LAuQ9zKYqR5eq3zM=;
        b=vh/EEwOh1ykPh+9HaN8s9v5FGii0VEzcMhbGHnFHlOgsGiLHK5eFtR8rwh1ZTIpTNL
         gHKFx27XC3e1wdfLUqmyq2a4kq7A4llAmv7HpwPbtDfsmUhHtlyLYR6wNFZtYI9q1mG+
         s24rRSe7EwWFDkL3CO9VEx06Ao03E8a9Q+HID0N7PsjPHIYla2Tixpn5v8Y31VSU85tw
         GZrfgSrR+XHtCLfEVxPoBE38ZRTy3+CGlk88X4P86cgbKksZRolU0UkrJGKVAy2WzqEo
         fuLGdkfOF9lshJeDSjFNqV5M/aqZ16jFJiSHlldeGRmKV4nEsOP0oLGi+oV9BPPQUjNk
         2eoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BFe+B8BC;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wVaQkkIrsIha/op8HgYxYI0WKV8LAuQ9zKYqR5eq3zM=;
        b=MnK3sC0hK7Yq0MQnOx6/IAbQ9eDZmfZwnivSNUf2GU1UQ1y0hxLXQLC2jAU6q5r4k+
         h1FvXQMue0jC31o9Ad3xIHyIhlp9zOlZeMx7NdzSnve3BWor24hEgvfPwPZmdqOXRg2+
         hsjNTZP2mGDB8W1C4WxyYbMQQhhF3cuTSUiQRM3s0vJ1jQzLmDj+ps1Y2wU2yQMa8eGh
         M/l6ewqHFiQaJu29sjSQ8B8SWgaxH6lwj/71rtCcfbpbRNO8e8LMo5O4hvVrLk2gna8G
         CVHhBE791LpBKgnHYsyybWESMrlJPO7TAoNNUfZPe1hUjj2aaIuseSKjDJ0iUlKjzfbB
         kQHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wVaQkkIrsIha/op8HgYxYI0WKV8LAuQ9zKYqR5eq3zM=;
        b=UEa2Jpq3BlUBtYFqWaVddxAhVKJc1G0HwuyxkrXZhG1wJIgry2qBybUQnhKjK9L8nI
         tNj/27VnwdWPz4PhrJnnu0tFQ2VKlnH/GbwIKv5qpzu7fGB5nMCKL3QFHBliFnUqtbNR
         Pfqi3y+vPYgHAJRED23Y3FZgZobpey5qLgqzJ9823nX2hVIhU8xBZEBp0oU2RX3trmu3
         R9k6fjB+Wkm6+vTBJrALOYiSTrpf5kVrGL1fIU/7pxdR883HQ0F0cydgZlIT1XL2uusW
         BLX99m6oATbnt0vmXeeyMqGjK1hLbsq+6VG9qcQyh90dwVDI6RmSsgki8eIohe3lyihH
         IR3A==
X-Gm-Message-State: AOAM531p8zZBMQYsgiEXHkv12hOgki6wQGO0YErAK1eaVIlKhpJ0RNhc
	FzRVT735t/zgrizq/P1214o=
X-Google-Smtp-Source: ABdhPJwmxa0woF9z2Ji+bhsIQBGZemTtbKn4/dJ9FmjqahCCh6F/Maazl0+KBXrFr/ANqkEGt33+rA==
X-Received: by 2002:a1c:307:: with SMTP id 7mr44614wmd.165.1604026226557;
        Thu, 29 Oct 2020 19:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2c84:: with SMTP id s126ls880711wms.1.canary-gmail; Thu,
 29 Oct 2020 19:50:25 -0700 (PDT)
X-Received: by 2002:a1c:398a:: with SMTP id g132mr65374wma.51.1604026225655;
        Thu, 29 Oct 2020 19:50:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026225; cv=none;
        d=google.com; s=arc-20160816;
        b=T2d6E3L7a8fO70Spa0aIvS/UnWLWjs5te6yp1BmGwsBHFOB5VZMXWLcT6LSNS0161q
         oVzriM+Xl9qnrMJU6/0uL55awVktJrqGM5FEA+YGp0Nh2ZkxqsFnbvHIeVeoiC+brGaQ
         zaCJIIhrHpjZ6tD70SxOa3jBI0ALBCK2AeQgHKWDKASuqyzZbMJ6lqz1Fl9hjolKkg38
         CsXSUwN81gtCxLehMz2hECb+pBZ9WkG6oLlYec8/j4Pj7u0iJ5N4KYvbVruUoPPWyfDQ
         ZDLh1Khdv+6+NMQO+t4tiq3dr+4bdBoTC1Fc16SYjeJ3jwwPzWVbbeM3w+wRUMiTdwcU
         E8fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QNSPCer1UJ6z9F+/9uXH8Oi4/yk+Ks5V2RaOCBC84Eg=;
        b=qqSgMgIFXqdHpecFDe/Dxx1QU5jPPLDdg3MHX5vK8WLeaAgP0CkmaKGZaRyHRET0yX
         7HbwL/cehQ5zHMKAQ7RtenXw1OcxC72PcPZl67wJOGKaKuT3GyVaVcHwADMLi5kklJno
         RUSpu5e3s1ow/8WUEMsH7I2/xOTjswNxRt7UkuCr3ZvAYatFfLrF4I3zevFxlxVPx5/R
         t6mFe+2O4cn/lgsL5p2XQYwr6bbSS32MV9uk9sJ8GJsj7nwXv7c+VgSpvsFmYMeQfZW8
         kzhnN5laJdY0AUfykfcANE2xe4Tle9qfzNt0MSl0iMkfvUHzMuBJcb/gnAOyxeglA0Lf
         NPIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BFe+B8BC;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id e5si158973wrj.3.2020.10.29.19.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:50:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id 126so5962625lfi.8
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:50:25 -0700 (PDT)
X-Received: by 2002:a19:e308:: with SMTP id a8mr12857lfh.573.1604026224931;
 Thu, 29 Oct 2020 19:50:24 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-9-elver@google.com>
In-Reply-To: <20201029131649.182037-9-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:58 +0100
Message-ID: <CAG48ez071wf5kvBwpmRk9QiSDzDDN7zh17zEcZjPDWKUjbqosA@mail.gmail.com>
Subject: Re: [PATCH v6 8/9] kfence: add test suite
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BFe+B8BC;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> Add KFENCE test suite, testing various error detection scenarios. Makes
> use of KUnit for test organization. Since KFENCE's interface to obtain
> error reports is via the console, the test verifies that KFENCE outputs
> expected reports to the console.
[...]
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
[...]
> +static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocation_policy policy)
> +{
> +       void *alloc;
> +       unsigned long timeout, resched_after;
[...]
> +       /*
> +        * 100x the sample interval should be more than enough to ensure we get
> +        * a KFENCE allocation eventually.
> +        */
> +       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       /*
> +        * Especially for non-preemption kernels, ensure the allocation-gate
> +        * timer has time to catch up.
> +        */
> +       resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       do {
[...]
> +               if (time_after(jiffies, resched_after))
> +                       cond_resched();

You probably meant to recalculate resched_after after the call to
cond_resched()?

> +       } while (time_before(jiffies, timeout));
> +
> +       KUNIT_ASSERT_TRUE_MSG(test, false, "failed to allocate from KFENCE");
> +       return NULL; /* Unreachable. */
> +}
[...]
> +/*
> + * KFENCE is unable to detect an OOB if the allocation's alignment requirements
> + * leave a gap between the object and the guard page. Specifically, an
> + * allocation of e.g. 73 bytes is aligned on 8 and 128 bytes for SLUB or SLAB
> + * respectively. Therefore it is impossible for the allocated object to adhere
> + * to either of the page boundaries.

Should this be "to the left page boundary" instead of "to either of
the page boundaries"?

> + * However, we test that an access to memory beyond the gap result in KFENCE

*results



> + * detecting an OOB access.
> + */
> +static void test_kmalloc_aligned_oob_read(struct kunit *test)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez071wf5kvBwpmRk9QiSDzDDN7zh17zEcZjPDWKUjbqosA%40mail.gmail.com.
