Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3P65X6AKGQE2XZQLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47CD429FBB5
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:22 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id c24sf1032699ljk.13
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:50:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026221; cv=pass;
        d=google.com; s=arc-20160816;
        b=FRujuTForzXuOH5wyx6lzW+FfGydpqutJdfFOfL61R5BSaI+lh60z9HIcTC7kRZa49
         YJ+J1Jel+BNWV3beZBOHLCz+m0l90KPc/uerbP8KmOxUHdFRBjO7nj6WI+m38QUa1ZZU
         F5y/Zc7dlzpAV59/7cdBEULWFO8KUeUk37coUMBSefNELvWtdZNLI92iQ4zDJHlnwMRR
         UaHA6ltDzTFaNWT7Af/V344+//2JakY53xfAIkcjbNWhNlgY9+/ChFnFlBnj8G7UEJsx
         ud3zmRCWvYq3hOoLpdv4nJJJ0Iq8MuKL577WASw9cyIE3ybBoACQaEkZ3aYyaTOy0qZH
         +Eqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yLxxz6DrJidW7nf3H70uj1W45a8mG51PvhXS36B8FGY=;
        b=GF/n2yMGWuxLa3W1UAcNGjf80/erTQcbnr6glp7TRWiV+rMSgSFR8iNhmLF0jLdDgE
         YdYEyd2Tpp4juss23jbgdY3kKyHV75SgHhNtHbATj+0H9wjGG72N92MLXYzjf89OjRLj
         Vk6NlY/r4Wj/oc0YhTWyQVCTTethlFvfYzS2A4cpaYktXgg2xuHeyFFrytGlbSimxwYT
         9hF+E+Na85pVw46fPxpITy9+7LSX/Qk3p8TWqah1FwV64bqOsFLiQAqffk7S/keWxp8p
         VIF1qnfBloQawmJ2LG84Y7c4Cg5vuDynWDAPXXL4IaYn5NY1FxOPpRxCBKtfv/RO4Qge
         P6Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iW5ihpg+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yLxxz6DrJidW7nf3H70uj1W45a8mG51PvhXS36B8FGY=;
        b=Znu+zqcgqtIH0y1TFxVW63OQQGJXB6Rot/A68Wp8JfBYTnZ/5Q7O53GCa4PqEVyCpX
         P8nGfYQAonGO+pPGA9IJHp6ts9pG51mkkaGB1Cvxy8avKpik+NeDca3d1K3y+iRLtcmz
         Xn0kGpxEcBiXbYx30WkvGAfD+nHUh4vbWMp1wUsZbi9HMBduNSGNA5sSUJ+jbVeOySvi
         +uMF3xevBO+49Pow3MJvgQbtegutAxdcnXyeV9ytdzUvA4Uo6JHAY7+naxcHxaHMu8vS
         kNDeJN9LTgkQA4phSja1B2SF/6AzkhL6XgtwUBMMKt/pT/4V/yfsx4EaDyMVmeKHiRSe
         u1Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yLxxz6DrJidW7nf3H70uj1W45a8mG51PvhXS36B8FGY=;
        b=VqVe1g8d4WwyLlAUFqhMyIFva4hW8Lp/gl/Ea4dmpXXCTnH8/hNIq8M5f5PUpYUBr5
         9W23+bQY0MiC430ZD6wcE1QcrAvZ3/TwTYY31EUwbYQJXj+XzjrCe588laEDQIW22Caj
         bOefW+kBIotJMoTOQlbIzVUVMfWExWdloSHGEYS0mZe1g7dKg8HVh9G5VWhYztcXIJRk
         f03IXbTWhteD1grlpE+byKEzKeH7eG3EdJKdyOtPD+dY8fAML0311p7UMgFmoWm+hi4K
         PiFrSmfvjzsiNxQ8Y62v8WLkPaBiMwROUuPjtu7Ph3tt+SJpiwMw1pYjX2tkg3V0WA3C
         DrAg==
X-Gm-Message-State: AOAM533ytU1MZqBAh+bL8ytRHpbD0gA2sQCCKvQRELxjNw0HhkiRiyl4
	FAAYGQQiZvGpFrCEq0IYJpw=
X-Google-Smtp-Source: ABdhPJxavXBANv5rOU2XoKmClQxUfIjYOXq/shfSqW7ShJN0dDPDTfl01iNlIEpjV+snfFwVtiEWuA==
X-Received: by 2002:ac2:5938:: with SMTP id v24mr26094lfi.228.1604026221827;
        Thu, 29 Oct 2020 19:50:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c15:: with SMTP id x21ls198502ljc.8.gmail; Thu, 29 Oct
 2020 19:50:20 -0700 (PDT)
X-Received: by 2002:a2e:b88f:: with SMTP id r15mr91917ljp.453.1604026220828;
        Thu, 29 Oct 2020 19:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026220; cv=none;
        d=google.com; s=arc-20160816;
        b=on8jam9jNhds4tpQA4I2vohW/XdBm59Mq3IwIVp1oRzITnlaCVXeS1FWTtROS92qoD
         THydutbZcJs5EqRGvay7gjpUh84R9r0/N03TLdU7Mq5wsLO1+h6yCGC1yCTVsHKdJviZ
         Pr/7xBLo//rxQRtVAzzXkMQ60IqmsQWhxjKICqNIwPEMwy6qprSMUS3/PmTjOZcLB4Vk
         sWdILNqahzBgl6RAXBJ9I6WZhjA6KKJ3IHUWyRqN/yZV6K22tSK0cpGPyfkFfZ7UOhP4
         2d4mYxmS6bpZr9Bpzriuhb4DLEcYfwf6fOSV/qflCxlhGsj1iqa54vhEqt6Euhofk3jC
         HcwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eoeNB3Dm2STEtOexs69p6fZG9+pIZ5Rd4jeKPI0aVt4=;
        b=ahAU4tM008D+jPPfvSLnDkuV3ETMsDLjpQQuZ4hsIYoivjvidixM+d0K5nykRVUI5+
         F2e4EBfBqiPReMKgMay+rNmhJDKMI3Mb4nZ50/ULnkb1w5ZZxI7IbaW5UcJKUTCGQF9z
         7UpTFSIfjN80d6eq7giC51jYjpP4BpJ9vY86G9yiUWi7lRGlfepkeJXo+Q6fK2BZ8P0K
         qCj3HoXckIBuzCAaDUG57ihbEhRUgn7miGN7mKPC/ubl6xiD1U51Tn3D6o4TPqcGVG5L
         di6qIxkZfNJcDLTW0fEQON2IPyOK+EsvpHRcDLQBTWv1yeVcB/1NdgZsyvIFF48mCyNV
         oy2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iW5ihpg+;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k63si118436lfd.0.2020.10.29.19.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id i2so5361182ljg.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:50:20 -0700 (PDT)
X-Received: by 2002:a2e:b888:: with SMTP id r8mr99590ljp.138.1604026220407;
 Thu, 29 Oct 2020 19:50:20 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-8-elver@google.com>
In-Reply-To: <20201029131649.182037-8-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:53 +0100
Message-ID: <CAG48ez2ak7mWSSJJ3Zxd+cK1c5uZVqeF2zZ9HLtmXEoiG5=m-Q@mail.gmail.com>
Subject: Re: [PATCH v6 7/9] kfence, Documentation: add KFENCE documentation
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
 header.i=@google.com header.s=20161025 header.b=iW5ihpg+;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as
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
> Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
[...]
> +The KFENCE memory pool is of fixed size, and if the pool is exhausted, no
> +further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (default
> +255), the number of available guarded objects can be controlled. Each object
> +requires 2 pages, one for the object itself and the other one used as a guard
> +page; object pages are interleaved with guard pages, and every object page is
> +therefore surrounded by two guard pages.
> +
> +The total memory dedicated to the KFENCE memory pool can be computed as::
> +
> +    ( #objects + 1 ) * 2 * PAGE_SIZE

Plus memory overhead from shattered hugepages. With the default object
count, on x86, we allocate 2MiB of memory pool, but if we have to
shatter a 2MiB hugepage for that, we may cause the allocation of one
extra page table, or 4KiB. Of course that's pretty much negligible.
But on arm64 it's worse, because there we have to disable hugepages in
the linear map completely. So on a device with 4GiB memory, we might
end up with something on the order of 4GiB/2MiB * 0x1000 bytes = 8MiB
of extra L1 page tables that wouldn't have been needed otherwise -
significantly more than the default memory pool size.

If the memory overhead is documented, this detail should probably be
documented, too.

> +Using the default config, and assuming a page size of 4 KiB, results in
> +dedicating 2 MiB to the KFENCE memory pool.
[...]
> +For such errors, the address where the corruption as well as the invalidly

nit: "the address where the corruption occurred" or "the address of
the corruption"

> +written bytes (offset from the address) are shown; in this representation, '.'
> +denote untouched bytes. In the example above ``0xac`` is the value written to
> +the invalid address at offset 0, and the remaining '.' denote that no following
> +bytes have been touched. Note that, real values are only shown for
> +``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information disclosure for non-debug
> +builds, '!' is used instead to denote invalidly written bytes.
[...]
> +KFENCE objects each reside on a dedicated page, at either the left or right
> +page boundaries selected at random. The pages to the left and right of the
> +object page are "guard pages", whose attributes are changed to a protected
> +state, and cause page faults on any attempted access. Such page faults are then
> +intercepted by KFENCE, which handles the fault gracefully by reporting an
> +out-of-bounds access.

... and marking the page as accessible so that the faulting code can
continue (wrongly) executing.


[...]
> +Interface
> +---------
> +
> +The following describes the functions which are used by allocators as well page

nit: "as well as"?



> +handling code to set up and deal with KFENCE allocations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez2ak7mWSSJJ3Zxd%2BcK1c5uZVqeF2zZ9HLtmXEoiG5%3Dm-Q%40mail.gmail.com.
