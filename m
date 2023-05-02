Return-Path: <kasan-dev+bncBCLL3W4IUEDRBFMIYSRAMGQE2F7ZCJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CFE96F43F2
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 14:37:42 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-2f5382db4d1sf1048901f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 05:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683031062; cv=pass;
        d=google.com; s=arc-20160816;
        b=p5o1JAVSi8yi2rUwgaY/P7DsRKS7iyE7PD9WQFp33xZs7ZusF+BD8Q/0g5wikQ2p1P
         GWWWA0PbmAtB8PABCGWSRS79utyYUHkvz/KgWHZb3+BI0rjAHHOYKxugRNO4t5+abzFV
         NefZDXlRF7dOMqUhcpYH/cO1QEDZ0veFJYf/qxjyFSdUREyiVgcZW8wm2AUJZYcDf4OY
         vAjuGa7oqJVlCQ+VFqLIuRu3sXHHkwmDTJeCWMlGYRO0C/scFGH7SyKN0a5I4qG6+VoZ
         GRTU4CSkC62Pw6MgTgQEocJRPRzOkOyEmtdyEcMqcpxQ8SOzr0X0fSx4OfN3YsjFwq0X
         uARA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=woJf8KOpOsI/t2y/pgS8nB4GxF9JOV07TGxrlCHohmw=;
        b=1FO3lHGZTSSBAQBvRBmadvwmLVOX6qng57sdBHLl/Bqx0YWSPn8IFyI6bluFaRAqJn
         cJd3IP3yIJYrhZmm/CTGGR56FEjxHYxdowF5IypS8BHXWCabYr9K2o9W6xEsyfpLI2Lh
         9n6MjkFy6FmGd3spGakeOVY8Ceeqe2jz9VWTTSA2V9rxEj5XLcs33fW9O7zE2kzttoiI
         vaXnwsvs/eIBtqIGmO/2FANjPEAy/VNyOUx4Ear0AZjWvdmM0+52r20Nein4l3AZ8rtT
         2OVMfebzpNyB51AIS1eohnaab5alOKXEV20LN11G+MPZRtPeJOQwl8IbUXDpVKVHtueF
         l2oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=IfEosdQD;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683031062; x=1685623062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=woJf8KOpOsI/t2y/pgS8nB4GxF9JOV07TGxrlCHohmw=;
        b=qQFs8BWftXTZf0e66vZGcj0iaffQiqCC8ikwdc924egoMENXPBR37PudzdBkXhevLJ
         bRDKOVVFhI3+fud0tX2MupyFAeFC5nkbkK5SV0+n05upBZvNa0e41ymKfQETImT6ooOm
         xRFFhouDWXC97so/cM20+7FDhtZJjpZqKHBLle1hOlI1QF15Iv3X849uAEUBmfdbAeNt
         5QKVIbymKK2nDo6FSTLLDhv4HaqyUng4IWxRgq4zn9QpGBa7JBzZjrICp1Zp1Jqpkma7
         gz5rRsR7PoiHuAuOREX+Jv7O/wQ9DSzoR4W4U6ZUiD3dwbMbZ2HBZuG5FmFoX3MBU88r
         79tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683031062; x=1685623062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=woJf8KOpOsI/t2y/pgS8nB4GxF9JOV07TGxrlCHohmw=;
        b=g8dmeBytDX7BujMP02Tk3mMWQDwx1hi2KU1W4Xq6liVla1DeBRgbfs5j+uOHPNRPx8
         5HF4ZS76Z0jPYmq4RNespmKeWDw4+Fd6Jg05iOgWYm/zolazP37wIGZYUkhZgWB3Sp+n
         bohFT4BQ8sDrj3EIauWJ1bR0rjmPzTrYEsulfgdg6Q9rAYHLq6rJ+axZrY98iusN1iK1
         Ee6QWKxY3irK9a+yX/a22mUJXNvOkdAEpWwHpUtRuJiK7Ak2jWYdQDwL86pCAl+raLk9
         QXvQuI5EQRF5c8eEfaJHU6pGrKdL84eJyw68I+AvpIAbhq1JmeFbclUtHhrCVbCuawMR
         Ukxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyhVNAZ5NGVZrfk0TQqPw5OsnhTrxllhnXVCKIuhxMsvkqsRFik
	YJ6OVHX/Rp3qHpPGNVW5Pq4=
X-Google-Smtp-Source: ACHHUZ7lkWpamB7O0vQ/PePIdB82dkDW5O3Z6KbZZZh2/xEG7RY/yGRKwMdPQ1z0Nv0l/1Cl2y3xUg==
X-Received: by 2002:a05:6000:12ca:b0:2ef:baa3:deaf with SMTP id l10-20020a05600012ca00b002efbaa3deafmr2058023wrx.8.1683031061857;
        Tue, 02 May 2023 05:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c0b:b0:306:28af:9a26 with SMTP id
 ba11-20020a0560001c0b00b0030628af9a26ls159225wrb.0.-pod-prod-gmail; Tue, 02
 May 2023 05:37:40 -0700 (PDT)
X-Received: by 2002:adf:eecf:0:b0:306:3731:f73b with SMTP id a15-20020adfeecf000000b003063731f73bmr1811152wrp.43.1683031060455;
        Tue, 02 May 2023 05:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683031060; cv=none;
        d=google.com; s=arc-20160816;
        b=Iag7ey0qxsmor6abh0fphwsKTBZxoU35S4mAmIZlr+tdaWK+Q7e1GjT5FVIy7FN82I
         ktsN8ORAsA5BzLoPxZIcIRi/7Y576oT96IVHGjS+pK36h/Q+HfIgeBDRI5bJzBxTduJN
         fvvKHrotuAiyrdknv9XhFLdHoaScs6wcNq5UOVLYe8249Z7g9xhTjIKRWTiPMSx4fVzf
         /tvcehTuM6sVpp9uAdEyVLPfp3+ybQ/t1/27z3li5ji6h9KeSvmiBbMNZAT7r3AMX7se
         z3qyNG5M0Q3UV2E0m1i8OkAX2Mf19fBhCJX3zRDReQheQNOJ/iAr+PjoEXzgv5YukyiI
         mOqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WiSBVa425oCXo8PlOI7ShaplOLZx93ZjOuloCKsozms=;
        b=iiSRMI2EhVo+LI2qNnWQpvFjJkyVPiy0h+oCu5ZfgHwUVhMkNZFu9/wELKcFpHLAgz
         fFjC84repTxApHit2jQnfvF8XXr1t1x4xTK9rKChM3HwhCf3fmP4NSSMneidi5Br9ClQ
         3z75uAWtLFZFO49DOdid21suZmpnPQ7HHs100P55xgCdgTTI/zj4LLTXTlVzbtau0U1+
         +eQdCT6V6hPrW7Fl5XIJyLe9MUlTc1+9x++nEOFopsoPIEiJMWmKR/Ga9bVm0IwCiRab
         BX50xwRpKal9RZRY/gr6k87rmsLIuyLfgMYM8gPAkBZU/Qhizr7EERfBepxYuj7CrcMC
         ydxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=IfEosdQD;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id m14-20020a5d64ae000000b002f4a32010f7si1563691wrp.5.2023.05.02.05.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 05:37:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 2CF8014D08D;
	Tue,  2 May 2023 14:37:38 +0200 (CEST)
Date: Tue, 2 May 2023 14:37:37 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 06/40] lib/string.c: strsep_no_empty()
Message-ID: <20230502143737.1e11f1ac@meshulam.tesarici.cz>
In-Reply-To: <20230501165450.15352-7-surenb@google.com>
References: <20230501165450.15352-1-surenb@google.com>
	<20230501165450.15352-7-surenb@google.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=IfEosdQD;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Mon,  1 May 2023 09:54:16 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This adds a new helper which is like strsep, except that it skips empty
> tokens.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/string.h |  1 +
>  lib/string.c           | 19 +++++++++++++++++++
>  2 files changed, 20 insertions(+)
> 
> diff --git a/include/linux/string.h b/include/linux/string.h
> index c062c581a98b..6cd5451c262c 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -96,6 +96,7 @@ extern char * strpbrk(const char *,const char *);
>  #ifndef __HAVE_ARCH_STRSEP
>  extern char * strsep(char **,const char *);
>  #endif
> +extern char *strsep_no_empty(char **, const char *);
>  #ifndef __HAVE_ARCH_STRSPN
>  extern __kernel_size_t strspn(const char *,const char *);
>  #endif
> diff --git a/lib/string.c b/lib/string.c
> index 3d55ef890106..dd4914baf45a 100644
> --- a/lib/string.c
> +++ b/lib/string.c
> @@ -520,6 +520,25 @@ char *strsep(char **s, const char *ct)
>  EXPORT_SYMBOL(strsep);
>  #endif
>  
> +/**
> + * strsep_no_empt - Split a string into tokens, but don't return empty tokens
                ^^^^
Typo: strsep_no_empty

Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230502143737.1e11f1ac%40meshulam.tesarici.cz.
