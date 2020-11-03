Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBA5OQ76QKGQEB47DN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 10BCE2A59DE
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 23:17:40 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id j13sf8426045wrn.4
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 14:17:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604441859; cv=pass;
        d=google.com; s=arc-20160816;
        b=iVjaM/0Zwzi4PmpWEKh4ynb1j2D4h0Abhv6bxD75fPz7IEsHvRHpXH+Rz5+lOQ5/Z6
         yDv/4EQnkLS/FAe/bXgvC0gNHnMQOWjslv8Ub1dW3+z4oGANhjkLoS6fvkV0lgnBOI6y
         1b5OtPJi/qow850Z4n8JMFki72QnfZqFLw6osH4JlqF6GiJKPHs47WDFt3G+9Hi45DB1
         HdQMoJEAgUvId+SfoMflIO08CDfsBknqKTBYlpL36MTYPdM63i7bEvX3xv3WNqmB3qNE
         FjKRMHUEZUmagMM+iRFaEFgmYfxgyHyGeogusFs9NC6GrfUwpfwBTLJzBbhZddCdH9yI
         8mHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nuZ6AfLalPiegIubN0I1z3twnwppGsId6u+5yM/cLxM=;
        b=a63AT0dlHm4HrTwPDReTx1pDHFylnyBpsKkDaVSFGTvk7K+16YLKAGj36x27bY7hP6
         LR50DzQutdDlpKKhydcO+cfM+KXY4G2AZnhq+7NBtRnRCzfucJjiMv1J3CMFpymBPyR+
         tGI36WAN6e/wzGTW5gR76BNobxjOCn0NcpkWlc83uCDXz+8/hdVQ8xmVg0++GPxOSKeD
         UsC7bc4/c70/d1X7SjtkiwHKS7N8Zd0jtV5h5bOxLFVRYtFzOxS13DxbcgMqA22TKrcq
         C2eq6ypUGbDxSESXjafFe6c99RAcomaXlTSda4R94Hk0ooszk/9NkawyK/TRjzmsm8XF
         yBiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oDO+8A43;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nuZ6AfLalPiegIubN0I1z3twnwppGsId6u+5yM/cLxM=;
        b=Dyp/5fJ8TqIxAnt2w3lcxXsSouLfI8od9/28Ycy0TKBycHQlhyJ7vBLnvMCclHeBVH
         S6g/3LXERxv6rGdibOScVTW7awInDxI0L/ewJKhk9KSf9JqAY8jtTL+IrfaUoywWnFQy
         lysaY0mnJIx5wuzD8yORozPs4mZriF03F0R7/LaUL2K7qwYhj+fSlZo5xNlKfrWRPTXO
         F1jEs9qJ5JIGx5JMPR6ty5L9ZTuwNwlj869h6tQD0jPyA8UHqv0VjpTBdDuvpPGLJeBX
         SLUVt6x5pGcft0zLBQc82xny9CKc+zq0b287Bx5yVy9rokWyAK9YVF1n53ZUNbErmgD0
         EZuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nuZ6AfLalPiegIubN0I1z3twnwppGsId6u+5yM/cLxM=;
        b=TF0bDbNefocAXzkyBMOgemA4r2aW0WB3klwfy3mqUt2Ku1v5+VGcaW2QYOH66YFpEa
         b4wmrca6FPw332tF1BHvkMhtUCfNUX3Yl1/WZ4ykSxN+gJI3HzTCfMaqg7ZSlEe/0eiz
         PN7MJtKVIQkECsNm2Gg+ykYlzmwWmHh9SKDf85vZG3U72j9GymTw/eHwBzAiyFbmeBzH
         zfEssCZ0u28zZf87nu+JSSH2zkHx1gQYZ2F/NRyWy8gDGr6j6GeRPRu6X+HaRU9Dr76y
         CEMjZNxn6yX5yKtwtZkczmCv4+Ets48/MZ+0M9zQvdok8u9/fDFsCCjVyI2ql/Q2V9Vc
         RqnA==
X-Gm-Message-State: AOAM532T4+Hgj8t8smCmQc3OI8ckRHvdSxvglL8yBXkhKVrJgzqYX+mp
	0Gr1yKek84blKsrv6v45e4U=
X-Google-Smtp-Source: ABdhPJxoD2YKraHS52klw0Fopd2gOMIvzUPa4Q+0Hs03Bp6MW/KVQ2Icje0EwYmjb2fnDq3u2iF1SQ==
X-Received: by 2002:a5d:69d1:: with SMTP id s17mr28667087wrw.77.1604441859780;
        Tue, 03 Nov 2020 14:17:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls193767wro.2.gmail; Tue, 03 Nov
 2020 14:17:39 -0800 (PST)
X-Received: by 2002:a5d:6143:: with SMTP id y3mr30056118wrt.277.1604441858901;
        Tue, 03 Nov 2020 14:17:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604441858; cv=none;
        d=google.com; s=arc-20160816;
        b=p7rSPUVtYpOcu/rXCsBki6AxgDSeH/yGm/CpSNosD3a2NSDa+wjnIvZHhzWqSnV9V9
         HZfzZk9PQ4hsomx3ZcaExKG4Q5RhmlWJ2KblFP+8rWEPXFo+ocy5MQNpe5/EAr5FBgF7
         QCivGw0qigTpdIypaphxjhTYlmHVj/hU2j6v75d5iFN8dwSpuN64muTgXuSYTMivpEm9
         ncwPVYB7FC9CZziO9PAGzSVhYuIzsSk0LC7C2GipjL0hILBxO0w8vTCsRYbmhbKVSGbp
         ZbCa4xbn0Yr1wFf+2UTpoFy2cju9T3USJ+ThtLrocdvH3z6FEHZJFWZyNlTJTB+fwhOg
         QQiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1oYKXAN5GCNK52qKASABkZS4MsOww72x3szPS4VEUtM=;
        b=eVNJWYEdVozMAI46qUgdPlQrJBupWr6qU0tQJGZN7XOs4m43/OJZGWSmA7pq5J7oin
         LfKLN3h+E/eR3+oIjaXuhZ+JsCsOqyMNeomLNfugiqIko706ZZxUSLnHcRSV8CWYJXo3
         cQcGJHfXVVNoFEm0nEhrRB2EMPwJvnv6rYVbD6w8bDV2ov+XV/hkEUiZugCCJQEI27Tg
         Q+4Kx4ttVdqyMtLxveTgjZLZS7M6VFa4VlyffSXJ7xL7fCnx/D3HQEkHOekPaGHAaEXU
         BGDRppGWj/zU4yWQfY6Fx28A8IwQqbXHEDnz9MjG3MIBv3atuv2WcaaD2dmxzcCRO25x
         fJ5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oDO+8A43;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id z83si180758wmc.3.2020.11.03.14.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 14:17:38 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id k25so20776005lji.9
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 14:17:38 -0800 (PST)
X-Received: by 2002:a2e:9a17:: with SMTP id o23mr10126372lji.242.1604441858170;
 Tue, 03 Nov 2020 14:17:38 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-2-elver@google.com>
In-Reply-To: <20201103175841.3495947-2-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 23:17:11 +0100
Message-ID: <CAG48ez3rNvqRuU7o1f_Jd3sNZVD+nLSry4rbwMR_VHEXmj6pvA@mail.gmail.com>
Subject: Re: [PATCH v7 1/9] mm: add Kernel Electric-Fence infrastructure
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
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oDO+8A43;       spf=pass
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

On Tue, Nov 3, 2020 at 6:58 PM Marco Elver <elver@google.com> wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.

Reviewed-by: Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3rNvqRuU7o1f_Jd3sNZVD%2BnLSry4rbwMR_VHEXmj6pvA%40mail.gmail.com.
