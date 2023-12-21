Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVWSKWAMGQE7ATLSXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 53F1881BF6C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:08:00 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-203014900a9sf1388054fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:08:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189279; cv=pass;
        d=google.com; s=arc-20160816;
        b=WlP09RCzu/C6BeDKsQNpPbD7+1GxmeVcfcFEkJWN5JoryaUb6tOUgQYLiPse1jWm1y
         9O06+6A+XSkdx2rH3egl7ZnvBh4hJaa6dGaE+LpLbQmRpl523+/Esb7OlumA0IAVQhHG
         8CHkH9rlis5wEeUkXjOXGcb7/uB8rpqHXIoxTsk51eQcg8uECmFvX3UefXyLlfTEs5DU
         UecCyQ/9FnqOqpj/a/oE6UD3pVq1diOsqYWkbhd0YtXEoIFs21vtB/kEkjYkw/xlvwve
         cpxXu9J2WFyPgq1CXXRHUx4fps82d5bvL+NpqMvuL2H1q7Em2MSFyd7vXFIMZXuhccbi
         QoPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JeoPsNz1hsa2YhEibjw+wp+42a17FThNYqxeGvqSTsU=;
        fh=e5eZVnhbMlEPt4JP0wU6P3zVPlTs314xtHxa2009KGw=;
        b=uq9lQZn9gpRoEknWtBj/D7lAHdAIk8wnfIkVtrqyXUlIzuL5KsdgSoRcfx37NYUS4q
         mmBgC2nDssPJSU4cCPtHK750x5NtNoMzuEW/mtM7gjcpCZ4SYX9v0TI6Dx5svRKY8kkx
         1wPH7Bxs0IupYB2uMMt4JnQmpzB/4fhg+3DVs327LSLX5uQpZMuZat7FjC07Tv2OnI/q
         n+W1OOoqT8Y+vu3pSPR4mfasNwrfjDuPdTzvcmjiGoAhBIw5q05XpWtH+JtSjazMvSCE
         JpZWClKZv3Q1h8AJGW4Ty+pHR4akWeMk2bNcTnXkz3hMnW2eDbam+SoU9FkwCMHG927f
         a2tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D7RJgx5a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189279; x=1703794079; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JeoPsNz1hsa2YhEibjw+wp+42a17FThNYqxeGvqSTsU=;
        b=h9oIOCJAFP7bd0/YghqE+MqOcQeZTsfSkahfCKx5bWQi6WdRPm6oPaU5YX3wSgGO30
         ZuFMjlXeyy3RL/8kI4hT1QlGbx0jpvoltSOm/5xurEE15fchUr+ej2KcFGh6a1BkvsHq
         7AtCkjiGjsRCOvGCZd6fMnKl+3c/HUSOYKoenIyyvggw6YbNBJrmCWu3I0q6ObdjYDb7
         A4S1V3V2MBt6QpUTYEDh46PAsU+qFxebGJMnD4Ee/+E5IwB5I8pciKOfn0MA4G49o4c0
         /Nbp1xnVgKydXxXbKT9JsNpXrZZ14kvW3COZL78j1ycEHbRb3FHY5z0rErlu6r+G3hwg
         jQeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189279; x=1703794079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JeoPsNz1hsa2YhEibjw+wp+42a17FThNYqxeGvqSTsU=;
        b=b37omfVkTeu+J4eOgYTWRsKqzkHbLuRZY7ESPxI9sLsDSi2PIRBnlg7b4hEGhLmM4u
         QrYj+yl+ejYO3F5orMMTrNEb62SJ0r4alYQS3lrbyS4nV8wBNLC4ykmbuCUoUEQsHV9M
         e3bv3qReqBX/Cl/XKzsJUMdQBA8PsAlD11EX1MP26w49ogRzhIPsTyhdDXECIraUCKwD
         quYO6tDIJsvSvOEJOn+jNSGPHfoQQ9QbltL1IXdVOPuZofyETj70gOlcwFQOkJBCW+15
         SNH4qyebgJCZKqI04OZcY/ah8wSp3ahSqdizWtjt6A2fe0PaEzHzCX2P1f/K+9msWOXx
         htfQ==
X-Gm-Message-State: AOJu0YyVG16g2r6WW4D0ybJ3zJQYBERXfQwKlLzvZLKtO0zt27GVRsDW
	LeWfEqF4ItiSIkdBWcMcM4w=
X-Google-Smtp-Source: AGHT+IGU2jqiVxrBeweFLo6GZ7WAdrWVdK7WY109cmPxtf5KVY7cznUumJpYfItxCTXJlpMKgczNmw==
X-Received: by 2002:a05:6871:4084:b0:203:afb:ceeb with SMTP id kz4-20020a056871408400b002030afbceebmr384344oab.40.1703189278794;
        Thu, 21 Dec 2023 12:07:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b154:b0:204:3470:1cb with SMTP id
 a20-20020a056870b15400b00204347001cbls868906oal.2.-pod-prod-02-us; Thu, 21
 Dec 2023 12:07:57 -0800 (PST)
X-Received: by 2002:a05:6871:60e:b0:204:3c51:b09e with SMTP id w14-20020a056871060e00b002043c51b09emr358923oan.118.1703189277432;
        Thu, 21 Dec 2023 12:07:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189277; cv=none;
        d=google.com; s=arc-20160816;
        b=LQut0s6bXXMSbE2Kcp9KVr46MbXlrGjIzjXb9+o+aLDo83eRmDx/tPdj+2QpG8UKI+
         mKNpmo/FwQyhXDCtzbQEcf8Eezk+bI/9/usfD3PnlzGym5HrHBCNMrkVz+rks0R3wsMF
         OPNB79BaR5/JuhRN9qNtyxlXXhcUdTzSp/SWs50/7VpcQcK99lKy27rE/j6Hya3VeBl1
         F9h2UZclkjSQBBVXIztU3wkd2DX2NMvxnfEwl5n27dphjeuPKvsVrl0AuOfman6usU0O
         n2AGlAxSebDZdlbjTa2aHgU+kYgw3jou6Gprz+334ZMFLRXLonZsFWqnXWmTZmPviPxP
         dQpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=utqNK2Z5ebr5Ah9is9CZfM+/3gvjCU4Z0H/FEO7/fZM=;
        fh=e5eZVnhbMlEPt4JP0wU6P3zVPlTs314xtHxa2009KGw=;
        b=w8O2D87WZXFavY8DYqAphd73yty31VIotwJCKbZmrQvFRJlQn8xT3eAHP52VIh3LXH
         r3IDYZHoACio3cnfgRQuEZJ4XJiyqlVg4WRldwZoBt7VdnaBebkjSdy9QCHmzwJE9N6K
         40WkDP7Tc5jra8YABjLeIpBGcJaLlj4Lj1NjFPLyb2mUHRLB5NwqMLAeZ1yFlUIN8Xls
         LEP4Jj35xT9inP2ZB0VAzRjWmMVCyoKPGweQSlK/OUVOEP9JwYMOdpSCxBa5a2aJuVfl
         qhEduzsI7ub+hJnKPtFLIczXbvxsqAKjxl3yz2kYF9cdi5QjuhyrhsMqCkaoB/O62DEX
         ++gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D7RJgx5a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id lv23-20020a056871439700b002043bb5e02asi83706oab.1.2023.12.21.12.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:07:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id 46e09a7af769-6dba3438499so803685a34.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:07:57 -0800 (PST)
X-Received: by 2002:a05:6870:a192:b0:203:7cb2:35 with SMTP id
 a18-20020a056870a19200b002037cb20035mr406025oaf.60.1703189276982; Thu, 21 Dec
 2023 12:07:56 -0800 (PST)
MIME-Version: 1.0
References: <20231221180042.104694-1-andrey.konovalov@linux.dev>
In-Reply-To: <20231221180042.104694-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:07:20 +0100
Message-ID: <CANpmjNPkZQEp-jCVvbmcPBh2x=Q9jvBNtr0fPMoR+--_Oo4MCA@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: Mark unpoison_slab_object() as static
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D7RJgx5a;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Thu, 21 Dec 2023 at 19:00, <andrey.konovalov@linux.dev> wrote:
>
> From: Nathan Chancellor <nathan@kernel.org>
>
> With -Wmissing-prototypes enabled, there is a warning that
> unpoison_slab_object() has no prototype, breaking the build with
> CONFIG_WERROR=y:
>
>   mm/kasan/common.c:271:6: error: no previous prototype for 'unpoison_slab_object' [-Werror=missing-prototypes]
>     271 | void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
>         |      ^~~~~~~~~~~~~~~~~~~~
>   cc1: all warnings being treated as errors
>
> Mark the function as static, as it is not used outside of this
> translation unit, clearing up the warning.
>
> Fixes: 3f38c3c5bc40 ("kasan: save alloc stack traces for mempool")
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Changes v1->v2:
> - Mark as "static inline" instead of just "static".
> ---
>  mm/kasan/common.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ebb1b23d6480..f4255e807b74 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -277,8 +277,8 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>         /* The object will be poisoned by kasan_poison_pages(). */
>  }
>
> -void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
> -                         bool init)
> +static inline void unpoison_slab_object(struct kmem_cache *cache, void *object,
> +                                       gfp_t flags, bool init)
>  {
>         /*
>          * Unpoison the whole object. For kmalloc() allocations,
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPkZQEp-jCVvbmcPBh2x%3DQ9jvBNtr0fPMoR%2B--_Oo4MCA%40mail.gmail.com.
