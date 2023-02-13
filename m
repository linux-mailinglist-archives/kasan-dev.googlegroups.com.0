Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7F4VCPQMGQEZCIE5AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A2BFD694460
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:26:54 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id l1-20020a17090270c100b00198be135a14sf7151432plt.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:26:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676287613; cv=pass;
        d=google.com; s=arc-20160816;
        b=OYlFmL4wcfUh+hA/21oI+O5vRK9Uf64Bsh5FgkPpJxAfPO6JusRE1KekEFWj9CmP0p
         U2VBHSCQ6KhnL4w/yrL8qUqksRVMliv5oU9YgAqHQ6lYhfoCATGH3mogGJDjPbKjutt7
         T7sYqIHO+4vEARYz7r2zXUPK/VwaMc2L5rEpeMarocAIArdnzSO4GF1ZUoR4bCZ7V2j8
         IW5yodZr0s2dWaUdVgn9LDi4gvQC7ULLsRYl0i/BcA9IAgtc3oDUuhItjjlFIslCtGAa
         WqyCOEK+ia8l5As0QAuoq5ddxb22nnqnQyaRp99+qiXbvhrmI99Ud1mOZcZSqK7DYGVU
         8ASA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rjuy/LpQ0J5Nqivkq7KXlq3l1LWjasg6NscyIsYVjzM=;
        b=y/JEhfzk0kBqZYKczvniIX2bdWmFa0MKh2RjnEK1dA5fY74G/7DVow21Cjc3p5G5yN
         H6nqK1hiawmB+2iT3ZhZYQpucsrrpMfQIcN60XmvMgTGk5ddlLrLzH0SkS9rKGZGmSRI
         HKK6Fd1eArASMQr80pHpsQul8PBnS69E5rwHqKX2zTDtDpsa/xUWgVBsPagsXH31Ebh9
         m4p8h1cj5Clv9MWFuBP7bzc9g00oF5+aOaHL3kGofWnVjuH8EWlM9eibTSqaKRZTMzS9
         TmHZmfU047ag+aZu+mgpMLBo3H6DUjCamed8ydZTx+e3s9nZkfYsKywfN6HO0gOfhdnw
         zJlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VptsRcKp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rjuy/LpQ0J5Nqivkq7KXlq3l1LWjasg6NscyIsYVjzM=;
        b=jrw2kHGZUlT2/7Am6lOL4fvt25qe80KxdBjZYnfMvEFDuJ7B67Pz8PFZbehvwmWnlD
         8prWmKr1hzLy0PhHsJdgCUYU2wUbLplWj8tvsk3/B5D4jaPdQfILPmxQxlj/61Mh+Zh9
         NPDlWRvzFGUNE29gXOs0Vog5ZC7BPpj3Msju2yJu41ORcsqhgDvgRREPruN2ueP6JYye
         neYHweTv2UGDpin0zPfN3gyPolKI/O+euRyb63Blu4/vVuWuzyYzbEVB+3r7tNlf6h4B
         QK2kG3YGgNUEkJug6rclV6ApaE7kYulesvZq84aEspgKk8xYnnCYRIwSx7REzOpCp/9I
         LntQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rjuy/LpQ0J5Nqivkq7KXlq3l1LWjasg6NscyIsYVjzM=;
        b=yTMxQgvEEcNYEfDTbcRGgvGgUt7ZpUFlF202TIDoepEe0c6WVUGLJkADjh64/NeKx4
         B4v1Lrxx4X+uJua+DkVGBbDANriXLJ40q4CYPwnhqMXurLkqIyoPgoAec5lm5DczeU3h
         HV1Pdm7MzbNZFQdjtBS6hXr7WYg7c2TNvuhxTAoz9ns8pPOcNMUIT9LBM0dwcQhKotQ6
         dcVcc2+EqwG4/uKPY2SbKvrEg1QX5B+kME3HUznMIB6C9BqXlnuBV1SpLUz2JzDqKycR
         O1jr11xJB4lIUV3pE5XBa7gs2GdWjYhJnXWLuvbN+qYVg/kQuupmK1E58zSUSKEzcZ1c
         OpsA==
X-Gm-Message-State: AO0yUKXMFTKxtLtQnlkSfoF3Id4NP/HEe99zBVCgmWTwN2lES8EpFZdO
	ivXK7N368UnFjmVdoMEt3F0=
X-Google-Smtp-Source: AK7set+GKG/TgpPtH+k43QZ9QYyWO8cYL08Ha6/IX/8ka7fBHW/HZ1MnmMtpHe+IT3aoTKE8w2/1ng==
X-Received: by 2002:a63:7116:0:b0:4fb:465c:3c6b with SMTP id m22-20020a637116000000b004fb465c3c6bmr2596210pgc.90.1676287613078;
        Mon, 13 Feb 2023 03:26:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ec4d:0:b0:49d:3383:2383 with SMTP id r13-20020a63ec4d000000b0049d33832383ls2495371pgj.4.-pod-prod-gmail;
 Mon, 13 Feb 2023 03:26:52 -0800 (PST)
X-Received: by 2002:aa7:9438:0:b0:593:ed9c:9f07 with SMTP id y24-20020aa79438000000b00593ed9c9f07mr17412832pfo.27.1676287612327;
        Mon, 13 Feb 2023 03:26:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676287612; cv=none;
        d=google.com; s=arc-20160816;
        b=SnknZ06fjVmkifjOYRU6FAfWdn5qOKbiNrgdKZV4PRWL2xg+7z58UcuP0JdT1IHDTq
         cEtmseQbXhQhkQW4qEKIr/SNN0JvD1XGldAAT+p/VxtzjUjnS6YuE9pGT1oFGQ3nujAo
         gCtW6cJlI32I+70q3ZslIX5U7aL+0IyAOdxIUg0w4hi+I7CG40WVp+ke2gCjUMc++KC7
         erPzct6gXNvcBmUNKRSuSXE3ltyWkAkt18AARPALpCkxEv6jGNPcwW/IqMf/e2kI2AwX
         Q2ArvME1qmXmLAdfBq+dsLzGgQWdm3U9eoP3GNW2rDCVwQB/X7bRKSmcbGCIcu4HBYBa
         tZxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AMZ+dV1nC8MEbsqkMnbGLqJoVdn1vA5Cn4dTYfSbU0w=;
        b=g0+OjAa6aGE11BV6r4K46a4BWnhJohoHXnWkZMLrk7PW1V05rhGuGXDKe+fv56exoL
         epn2lrCfXy1V/0pWGr5s+J8915nZPTCxRwlEexR0mw7Hrp/VCtfo8uTLV9MSGLf6n0Es
         MfwkJw/pnIdhVplWANzeLr8YacKijBLmjA17X61JYlXngD5UnPIup1BsN/Ue4XAZOz1Q
         Ejrfpyeh83xIHFwkogrzmzWI4SCteEvmwsR4gvn2fTNaksEzoxHZCkm9WJ7csQfUTAgM
         0JWYOYWcpaklY46vJDYhvReowUCqeeyo3SXw03Xfk/YbCt4l6S+gat0j4c9SYIQKrVFb
         uqQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VptsRcKp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id p13-20020a056a000a0d00b0058e08791ba4si749295pfh.4.2023.02.13.03.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:26:52 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id z5so1634513iow.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 03:26:52 -0800 (PST)
X-Received: by 2002:a05:6602:3155:b0:732:9e46:de04 with SMTP id
 m21-20020a056602315500b007329e46de04mr11828525ioy.65.1676287611687; Mon, 13
 Feb 2023 03:26:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <484fd2695dff7a9bdc437a32f8a6ee228535aa02.1676063693.git.andreyknvl@google.com>
In-Reply-To: <484fd2695dff7a9bdc437a32f8a6ee228535aa02.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 12:26:11 +0100
Message-ID: <CAG_fn=VzvKnvqqPChYFi3mzbe4u2dfYz5mT=nJ-TSkKiLqB17g@mail.gmail.com>
Subject: Re: [PATCH v2 14/18] lib/stackdepot: rename next_pool_inited to next_pool_required
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VptsRcKp;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Stack depot uses next_pool_inited to mark that either the next pool is
> initialized or the limit on the number of pools is reached. However,
> the flag name only reflects the former part of its purpose, which is
> confusing.
>
> Rename next_pool_inited to next_pool_required and invert its value.
>
> Also annotate usages of next_pool_required with comments.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVzvKnvqqPChYFi3mzbe4u2dfYz5mT%3DnJ-TSkKiLqB17g%40mail.gmail.com.
