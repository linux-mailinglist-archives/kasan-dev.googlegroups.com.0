Return-Path: <kasan-dev+bncBCMIZB7QWENRB244XKHQMGQEC5ZHKCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF34B497E0E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 12:33:00 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id u35-20020a056808152300b002cd7df67524sf1771168oiw.19
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:33:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643023980; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETHe5lIzLB9N5rEtmZPGoMdVNTtOLlwZ7gDgykJ5G0kGns0t6hDEsXI6NJ16ISrjNg
         +gPNTSXpgrd/xhflTBsTD2uGyPoWIxjlNnu4TjiHf7frzbSBZawEEpKc1N8/C6/hv1Nl
         XRV6gq9fGOPjVXYq6kwfv03ieXYhkXNf0dlH4pxVbuZsOzaL6iO2OVaWoa+E3QScszyy
         Mh3LPQJ2k67p68ER5wHOF1wIvAh/8DkZfPJUaJVXP7yX6EEmyxDMNDAYX1o5vgI6buln
         Ddj5cwIdhbKScdbbgmtWe+8BaQdWaM4UMxA3iNF/3pNTYyqdbliw8LcNC5/+OUoAh7vA
         Gi+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NIbzhq3HtHATp36lmksW79qx3pRYaWOvBnY4jht9t9Y=;
        b=Y6S09tf+7k/hzvmyAmTrYpL0UG3WyUfWB3eyL+8klyD5lTQ/+q62xK4y3srjM4g1c8
         ndahmMyEzIchGk0A6bfPPviy2mF8PxKZXZipKBltmL5a7o9VsyhERx3hPOxbodbUPezo
         iwEIOvwkFODT+5znisNkM33WBt5Pp2ZwskoCK81yoMbLhzE/7VxzeGsxFMmzazQIe8S7
         hCTBByZKeQTiEKGXu7R9yX8KHVcjeRZBKxEtFFwxrOd+wGvKT7syM2JguGRhx5400qFK
         65W9HFZgtVzyv9mwGHpl1Zeo/Wfr/5okCRvbis5HREvflg/gmGLIyVwb7xllCCtIRW/6
         xvTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o+RNdaWx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NIbzhq3HtHATp36lmksW79qx3pRYaWOvBnY4jht9t9Y=;
        b=o6D7NcGWM/2q2YeJSiRKKozj2QYpH8CLWDdvHEmLcDJivFqD+++HozfVxtnHDfItEl
         RcNUGAgA7IgQLjFzUuOFrIcPLHIeEgt98gXREmbbMOfy+rGzpAYvEsburXTHNGE3C5QV
         y9jpfX8E/kmKgbJMLXkb9cAAuiFMT47MJCj6qnf9ViuCdioXnTBHoFvCFivR1vKga3tJ
         1e27kHNj0dwPdh98A4Ab2Jn61GS5wEIs+bNajjyz2W48vbIwQxKClY0bUtgG+Xv08Tzg
         LhcEjDm3SEYHe9P/5r2uw6uSVPoBwOFMjejdWFRd2gzjMpdH2OODBr+LgrYTJl23GMlP
         M8BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NIbzhq3HtHATp36lmksW79qx3pRYaWOvBnY4jht9t9Y=;
        b=40DXvmkmnpsLP7nTFwjjTcGF0FkD/nxkYQgukfSb98wctL4I8PDZUd65JbXgDAJ97t
         s6qos1BdhvWbhadnQx4qoviyhAAFmLzQs0lzjLhbVrMIk5ReAoZHtMx61yi5lVJV2DQH
         /YWSXFF8WJsRMpXUsmL4IGblZEIOgkM1R3XWqQKNCMg7SWqVYjiIACQgorslkiNM6/xR
         ft8/ZMkpUCAarxY+O9M2Vjs2WzR0JixrnsSNg5yOYF8YepGnoNVurbU2S0S/RDZHHV5r
         gd7oxvtEXWWm3ub/BAcHhMvG+UO39zrCer6JJNfpufHRTXLJZTIG/5n9K/krWehfcQUT
         PWcw==
X-Gm-Message-State: AOAM530Fn4Tac2mD0SnAfkmXPDGB8OrAtXy6s6q2BTd4OG8cHvQI+dn8
	JeqfUvtwTSuZ2CBPLGHC41g=
X-Google-Smtp-Source: ABdhPJymsymtHEP5a35krh5fwRlb6lD/1RckDWmNAD4fsik0EabByDLeODY6qY8SaXGBtlROtuDfdQ==
X-Received: by 2002:a9d:1707:: with SMTP id i7mr8169361ota.105.1643023979809;
        Mon, 24 Jan 2022 03:32:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1412:: with SMTP id w18ls5176179oiv.4.gmail; Mon,
 24 Jan 2022 03:32:59 -0800 (PST)
X-Received: by 2002:a05:6808:6ce:: with SMTP id m14mr985663oih.150.1643023979476;
        Mon, 24 Jan 2022 03:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643023979; cv=none;
        d=google.com; s=arc-20160816;
        b=K414XQ+Vvu60cySVvcLuFwowKRqRMjUjm0GNVW6s8hJ7V135Zrt9ukfEGTUc09mUeA
         nE/tyiAFGnWeOC7g0imde/lLUr2MKX7F12LMtCN3zI+0UO5kQe2SHlI1CAbo+EB9XtVQ
         iyNGj1D8sn69JZlCRW8hpakQG0b5D1uivrvLzGXgrJqpGqDv0HUGNSqr+xA4YpsjIJ+u
         Vm97AWOC/rAKULyEUOFrkxh9JqzONcV3amm9tgWaeAJtlqHSrRVF0pYdaQZlzKYgOgfp
         Olmn/roHUZ9a5Qx1wiQtorngnZTeP/J7rIcijHax7gEbKMYVWZPSDuwMQIeCLMar9VMM
         YuzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UFyEedV/4W7XdVLa8Lx8qnPyLjbWcIdiBACIonQnaII=;
        b=RSqCLKjr1MohNx4fRJoVc5atPDxPcsLg+iHe4arr0pmJ57vQBSdt/XZfn72CZFvxAE
         MX6MNnZ3d3oNUl9Z5pjrSvqzaqVXlLH4Jc1aUprIvWeB/qo5DG3CLSgCPHW9FVWvvlTu
         /+do1DKVHDHoHNRGKKgcbPqZYeS5oV3YUApadrzp7pe/PZFsaVq3qk9i90VAmLwYo5VN
         YbPBlQKNRRXuCqOhYQq4J6Oi87mBRlMMRr1+lMF1pW+SY4zQ4TngXKsd6Zu3sUDGl+SI
         ZhtqSBPsEvd+Xc/8CSbI1eYnj3C2glOUTqlXt2dVqxrkEFblC2/ijdX+UBwqzzzbYw4S
         vr8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o+RNdaWx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id bg7si456174oib.4.2022.01.24.03.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 03:32:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id bf5so25012917oib.4
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 03:32:59 -0800 (PST)
X-Received: by 2002:a05:6808:120a:: with SMTP id a10mr980600oil.160.1643023977513;
 Mon, 24 Jan 2022 03:32:57 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com> <Ye5hKItk3j7arjaI@elver.google.com>
 <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
In-Reply-To: <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 12:32:45 +0100
Message-ID: <CACT4Y+a86X+gH5aJ-o5ituc-+hysFOYBJ7ZvuC234xJnwANWvA@mail.gmail.com>
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence objects
To: "liupeng (DM)" <liupeng256@huawei.com>
Cc: Marco Elver <elver@google.com>, glider@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=o+RNdaWx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 24 Jan 2022 at 12:24, liupeng (DM) <liupeng256@huawei.com> wrote:
>
>
> On 2022/1/24 16:19, Marco Elver wrote:
>
> On Mon, Jan 24, 2022 at 02:52AM +0000, Peng Liu wrote:
>
> KFENCE is designed to be enabled in production kernels, but it can
> be also useful in some debug situations. For machines with limited
> memory and CPU resources, KASAN is really hard to run. Fortunately,
>
> If these are arm64 based machines, see if CONFIG_KASAN_SW_TAGS works for
> you. In future, we believe that CONFIG_KASAN_HW_TAGS will be suitable
> for a variety of scenarios, including debugging scenarios of resource
> constrained environments.
>
> Thank you for your good suggestion, we will try it.
>
> KFENCE can be a suitable candidate. For KFENCE running on a single
> machine, the possibility of discovering existed bugs will increase
> as the increasing of KFENCE objects, but this will cost more memory.
> In order to balance the possibility of discovering existed bugs and
> memory cost, KFENCE objects need to be adjusted according to memory
> resources for a compiled kernel Image. Add a module parameter to
> adjust KFENCE objects will make kfence to use in different machines
> with the same kernel Image.
>
> In short, the following reasons motivate us to add this parameter.
> 1) In some debug situations, this will make kfence flexible.
> 2) For some production machines with different memory and CPU size,
> this will reduce the kernel-Image-version burden.
>
> [...]
>
> This patch (of 3):
>
> [ Note for future: No need to add "This patch (of X)" usually -- this is
>   added by maintainers if deemed appropriate, and usually includes the
>   cover letter. ]
>
> The most important motivation of this patch series is to make
> KFENCE easy-to-use in business situations.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> ---
>  Documentation/dev-tools/kfence.rst |  14 ++--
>  include/linux/kfence.h             |   3 +-
>  mm/kfence/core.c                   | 108 ++++++++++++++++++++++++-----
>  mm/kfence/kfence.h                 |   2 +-
>  mm/kfence/kfence_test.c            |   2 +-
>  5 files changed, 103 insertions(+), 26 deletions(-)
>
> [...]
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 4b5e3679a72c..aec4f6b247b5 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -17,12 +17,13 @@
>  #include <linux/atomic.h>
>  #include <linux/static_key.h>
>
> +extern unsigned long kfence_num_objects;
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
>   * address to metadata indices; effectively, the very first page serves as an
>   * extended guard page, but otherwise has no special purpose.
>   */
> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> +#define KFENCE_POOL_SIZE ((kfence_num_objects + 1) * 2 * PAGE_SIZE)
>  extern char *__kfence_pool;
>
> I appreciate the effort, but you could have gotten a quicker answer if
> you had first sent us an email to ask why adjustable number of objects
> hasn't been done before. Because if it was trivial, we would have
> already done it.
>
> What you've done is turned KFENCE_POOL_SIZE into a function instead of a
> constant (it still being ALL_CAPS is now also misleading).
>
> This is important here:
>
> /**
> * is_kfence_address() - check if an address belongs to KFENCE pool
> * @addr: address to check
> *
> * Return: true or false depending on whether the address is within the KFENCE
> * object range.
> *
> * KFENCE objects live in a separate page range and are not to be intermixed
> * with regular heap objects (e.g. KFENCE objects must never be added to the
> * allocator freelists). Failing to do so may and will result in heap
> * corruptions, therefore is_kfence_address() must be used to check whether
> * an object requires specific handling.
> *
> * Note: This function may be used in fast-paths, and is performance critical.
> * Future changes should take this into account; for instance, we want to avoid
> * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
> * constant (until immediate patching support is added to the kernel).
> */
> static __always_inline bool is_kfence_address(const void *addr)
> {
> /*
> * The __kfence_pool != NULL check is required to deal with the case
> * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
> * the slow-path after the range-check!
> */
> return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
> }
>
> Unfortunately I think you missed the "Note".
>
> Which means that ultimately your patch adds another LOAD to the fast
> path, which is not an acceptable trade-off.
>
> This would mean your change would require benchmarking, but it'd also
> mean we and everyone else would have to re-benchmark _all_ systems where
> we've deployed KFENCE.
>
> I think the only reasonable way forward is if you add immediate patching
> support to the kernel as the "Note" suggests.
>
> May you give us more details about "immediate patching"?


Another option may be as follows:
Have a config for _max_ pool size. Always reserve max amount of
virtual address space, and do the range check for the max amount. But
actually allocate pages potentially for a smaller number of objects
(configured with a runtime parameter).


> In the meantime, while not a single kernel imagine, we've found that
> debug scenarios usually are best served with a custom debug kernel, as
> there are other debug features that are only Kconfig configurable. Thus,
> having a special debug kernel just configure KFENCE differently
> shouldn't be an issue in the majority of cases.
>
> Should this answer not be satisfying for you, the recently added feature
> skipping already covered allocations (configurable via
> kfence.skip_covered_thresh) alleviates some of the issue of a smaller
> pool with a very low sample interval (viz. high sample rate).
>
> The main thing to watch out for is KFENCE's actual sample rate vs
> intended sample rate (per kfence.sample_interval). If you monitor
> /sys/kernel/debug/kfence/stats, you can compute the actual sample rate.
> If the actual sample rate becomes significantly lower than the intended
> rate, only then does it make sense to increase the pool size. My
> suggestion for you is therefore to run some experiments, while adjusting
> kfence.sample_interval and kfence.skip_covered_thresh until you reach a
> sample rate that is close to intended.
>
> Thanks,
> -- Marco
> .
>
> Thank you for your patient suggestions, it's actually helpful and inspired.
> We have integrated your latest work "skipping already covered allocations",
> and will do more experiments about KFENCE. Finally, we really hope you can
> give us more introductions about "immediate patching".
>
> Thanks,
> -- Peng Liu
> .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba86X%2BgH5aJ-o5ituc-%2BhysFOYBJ7ZvuC234xJnwANWvA%40mail.gmail.com.
