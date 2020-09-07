Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6OD3H5AKGQELVO5ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id EA6EF25FFBF
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 18:38:18 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id m16sf6126865pgl.16
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 09:38:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599496697; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPbwF8GUEJBXx8qT1vZ6lZlTidC6GqgTK25zOUTQ37sdg8q4aUqtlWSWjpXjJi3kvP
         qiiLnQEm6UmF91M3DJw2C40+ZsY1l3cYTXgxa8W00L4EO9uwjsLRfLlOO/ZuNWDjtrQA
         p5JalAmbh1CEgOBxXOkmWXXu1UF8eY3s4vkuaG9UVcD1Js402eB2CLHicWE4T7xo1EKO
         1KXm3C9Qmv4Ofgsh2TTAwxePFfMLob/W2CzcLFHcVAMqg9BrgEdrNlfjPy+Pv6DVLSuQ
         QAxuqkmhW5gOS5/VOo23VvoUQsbczQbv/Xz0srU9bMoW+Kv8Ss9iHEKTAlZFZ4SAh1/p
         560Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/ecupfsrU2xgEO0D3mjX1/2bBCS5aUwzHBksShVGqcU=;
        b=Yv7s5cqZyaTxlAUHCEyNSRqWO14vMhvTaPHv6P7o+OWRhvtgdwvpC4S6Sx7Yu2k/h+
         K9tQqQKEu6Kg+1qubEUSA5Wh8rMcegPUpFUfdDBvhN1llW5vuwrx0OwDs1zwLC2nhNV4
         IuahqijmH8bDGXKRaNn8zAlVSYyAMQ+e2TKJ/r2+KMFWPEzC0kGDHCNxA2SB5ALJmb1r
         FEen4kM5dY3jbX/E0uyfmng0P99NjJDiDouPbUD54tBUUF2EsSvxLyKZfZqXxqB4DJIn
         1g4oBsbXrTVsfgVsFN8pQmtJnXyL9miNLsm2hfEE4SnKNG32gXHFpB3xM3Ae7dmlBM1W
         z6Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bitllW57;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ecupfsrU2xgEO0D3mjX1/2bBCS5aUwzHBksShVGqcU=;
        b=apSyhZkWc3YhEFMKNL5tNZ5K1oaO15Xv6P7BBl7NUT9Fbz8lTObBnpc/wfZqwEUY+V
         pdLOlxMecDSA6L22GufZ9RTa10+9ZtRrXWr0INvL2mSOidrjqIjULX+MiGpgREU+8WaZ
         96Mnd2WXydpS7dxtUIJs495zvV+QjWvO+P+N5NckDTxSzY8mHd4E1nJ4WFrfeoDKDaHh
         OsaTf4DaQz2uSidQQYcjEKJLmru7xr7roDJgAaM0c3TwK0sgNlO6rmGLUoG9s8Nb3Cal
         N7nmd6JZufwW2abG5cW9T6Vu44jdMDyM0hYuzUkXXnSsqWZtsDVY7PTGh4ppOVp9ewuR
         MsGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ecupfsrU2xgEO0D3mjX1/2bBCS5aUwzHBksShVGqcU=;
        b=BauQ4B4zHNqbF5Hpu2LF4pa3AwKIbUNFat6w5XEtuW5ExE8oxz+CeN1pn+pfaHGb1k
         tubh82Vqvqor+GQKOw1u2IgFNedabUqES219Bga4BBzFiNCA78Bztyspt/PKlUtbL+5O
         wNxLKGsx8BjbUR/zfKKqjk+zgysNygOwnE9WYmVOIgkUqk5x1zUnZLZ6p6eqLoyoarRO
         /PVr9/NflYZ46PKF3gBjtE4uyIsg18qlNvaJZ1CTH1KqOcpInWDC2PCf1MtiA19J9rvj
         7Gj2v7kcvsQHupDa8gxqH39U3pyOKpXqhMeoyNPFo0OAA5/nzi5HZudYQ/6htM/JyKtM
         rvdg==
X-Gm-Message-State: AOAM532RXFjUYZLanot7dX91dOMeQPTXmZkEKmSZjY2T1b3ga+bsaAbL
	h0O+2KNa6iVbUjCX3HF4dSg=
X-Google-Smtp-Source: ABdhPJyFk/b4Q/to4qThCsvqff0PY7jJKEgQbmv1GA44+xv0/GUqSO569sNmkLpogiTYtNb5i7Xm7Q==
X-Received: by 2002:a65:6897:: with SMTP id e23mr17548070pgt.103.1599496697412;
        Mon, 07 Sep 2020 09:38:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3590:: with SMTP id mm16ls17926pjb.3.canary-gmail;
 Mon, 07 Sep 2020 09:38:16 -0700 (PDT)
X-Received: by 2002:a17:90a:af82:: with SMTP id w2mr122334pjq.185.1599496696767;
        Mon, 07 Sep 2020 09:38:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599496696; cv=none;
        d=google.com; s=arc-20160816;
        b=IQ/VRi2Xl56P/WHt7OJSnsnnJS2/HgZjvJfcPR7YWXc2uahub9w1rMvtsgwy4u2PIa
         MHagc5zR/kK/twY8XjIHNQP5OaUfN4otFtsN65NDtEEMP0RDAbg/II2Cvva30RPfgRpL
         ETmENUNYbM8P9Ow6aXLQp1vTUTTU27TS9e61tL+V8E5hfC/Rb9wv/GvZdZU1MgwPRCBm
         +70OFeFt67FHjM/Ln+gcstzowUf02qZ58aJJ2e1QyVzATJy0MY4YzFm+KzToCYlJTCLv
         cvSiLuB/HeTXoQMfkAXeb85t4NIJF2+kXaQjP+k30BXVG+4NTaZvGfQWRZv1jklhCUqg
         YTyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=22rG+o0x5E8fn3lCo9EgmgeQWY6DcyVeCCT/ulJfvbo=;
        b=IEFkTOeql1N6XhvJ+XSiJFO0gyfpafCA0SgNR+H9rJtQfSrwnzBHZS+UD2w6ieMgtc
         w6dx/Tw7N44wM7cl6tnYDJwtEhgq7skCf8UUKb6x9l/9qHWpxJ2qZMRssTIzVTeDA5tN
         o5Xal2xWp7vwN/m7Q4mTUAIC79K7BphiVfe1TudLc4MSdBxNlhN41vE43LBtVAJ1mlAj
         OaC+W7+lqaQYmZNQWbtPaQ1VQMZr8S7azQrv2++Omeua7z6xlA28vWkI7LmKd65/t7X4
         Npm/MZQMfn3JdJzQX0eri5ds67ycEJHqsaQXb3PhbqbW13cOcSNwKs9XOMOIYrhlrn0w
         q94A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bitllW57;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id l2si765004pfd.0.2020.09.07.09.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 09:38:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id u25so12689931otq.6
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 09:38:16 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr15600016otc.233.1599496695929;
 Mon, 07 Sep 2020 09:38:15 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <20200907164148.00007899@Huawei.com>
In-Reply-To: <20200907164148.00007899@Huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Sep 2020 18:38:04 +0200
Message-ID: <CANpmjNNL_hqmKfZAGF5mF-HwVx78tp+j0JNKhK=xPwJLvdWnZg@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Jonathan Cameron <Jonathan.Cameron@huawei.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Kees Cook <keescook@chromium.org>, Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bitllW57;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Mon, 7 Sep 2020 at 17:43, Jonathan Cameron
<Jonathan.Cameron@huawei.com> wrote:
...
> Interesting bit of work. A few trivial things inline I spotted whilst having
> a first read through.
>
> Thanks,
>
> Jonathan

Thank you for having a look! We'll address these for v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNL_hqmKfZAGF5mF-HwVx78tp%2Bj0JNKhK%3DxPwJLvdWnZg%40mail.gmail.com.
