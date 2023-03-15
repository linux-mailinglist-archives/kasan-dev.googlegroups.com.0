Return-Path: <kasan-dev+bncBC7OBJGL2MHBB57ZYWQAMGQEDVN7OEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 884076BAA6E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 09:08:24 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id oo15-20020a056214450f00b005a228adfcefsf7291622qvb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 01:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678867703; cv=pass;
        d=google.com; s=arc-20160816;
        b=MgSczLwWtAlW8A/cTYcS98wjoneqNWvUcLT6truRRlxZmIuPZnW8rUn4c1YjVtSzMV
         u5geVsnecgTGkU0QWay9OTix0QGeFsQxkYDP6UVwwzTO+SuhYH55ureNPNQI87lSDR+E
         BYGMvQ7rtPju5rpNAt58TRGqyIMxmzIoIeV3WPUOQqyRXWiwelZ1QtgFB7DtBy/2zBkk
         ck21QwjHom7hMCVZfLmpPl0J7dXLE3Fve7urgjlJBPaXPUhj9+gAPk+fr4xQAJh/WHw0
         BPNRjZBlQSDewhGC1mbf/ekQLc0ELjU4MvDWTW7r9NPEG9hXiEekdUbktWAfVQ87JLGK
         g8Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zWA4lvMGgLthEAcUFU6kg29cKIt+G97X0plvxoDrIjg=;
        b=hs+c+f0uNESH7TgrkCLX7/VMJ6QdB37gOlrV701Jzdx2GjpFijd1zAcM4bOXrLvKFI
         2/9UtFlUPZS/nQOZMPFwpU3H7gB/8XO7nmuyk07cvHPfcOg5x+9Mp+xY56UBxouJUV+c
         zRdIEjMKDuSIY4OKUT96XE2nNMi2Fbsn8a4W++BUimLBaASE8Qar7KtLdClMBQK8gFT1
         M19KgTiiJudt86YHP28UJB+9ewHaYXN813gS9DEKVffc5EKNvsBQMgzwq1JluwEgTsJ5
         sdWBhdB63Qr4Pt0yrCWjEd9Z4S5+ECcdYY6W2Ky62LVkHi37RlPS6aJvA7nssZIiFfiA
         SbMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K0QKzfSs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678867703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zWA4lvMGgLthEAcUFU6kg29cKIt+G97X0plvxoDrIjg=;
        b=I2jcsXnhMhgj0McXTE+8EJQqa2/eumymi9qMAKidiE0ZMw+3PS1b0hWpbRtkBnk7Xj
         2sjer1wd6SB6yV1tJWfOtsYlWYcD8GKEdPdegIUodlW3DsWEx9wkQPx5s/dc0JT9fRUp
         IAexlY3+IrpHCp2SjIJSQG+twEJI0MFsm+69Q5Vu5NSDBlQgEYjgeGalU86Ko2kfWv+T
         whA+ig2RGhDgHOcHk5PhFnimNQ5hslFttDUVe4WaLsyLwnDIheIBFURhHFPfJALvSW7b
         VgeXa2GpnzrtyjCPulvHvT2iHNRHecU2IlhI6d+H1OLRjluHQwveper8dER5hJC3G8MM
         bzag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678867703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zWA4lvMGgLthEAcUFU6kg29cKIt+G97X0plvxoDrIjg=;
        b=SGKo+OqAjYTM8+HMo86zmyiRmMKVc3Q7r8N3gSQVIQlyjIpiKqUEY8xTV4TR+0I8DZ
         ilwGGlpO7qKl89oXpgA9p1BlpM8M36FnRKOA3gb4vD5DP4q41G0WmVY4cZmWuLMHERAZ
         m8vXbZkCNhhRYszjgHAdccedKqm04FsUYYH51U4qpY8LpmnnAl8Iyx22zyEkxy3l4YBb
         8dqUBc+7BY3DYFMGR3fevTY86uRhWfKfeW8tvf8gZYIAbkcO/Pi9dn9Pj4WYRf4pg0zh
         4tc0TpM3Raq14a/+HLgqAqAMg2PoYq/RoMA3nMC9XftehCGx/80zrBPThciiujieniNn
         I/tA==
X-Gm-Message-State: AO0yUKUjRc+R1DKLeo5VXllyxmBu7S6HemvMB2scPSkXLRU7tU372v8c
	lrOip1gjyYzNFQOuB3HaBL4=
X-Google-Smtp-Source: AK7set+FqUMibbr/6ZyRLTDg8bTgY7mMRaFf3fOI20guIAI/l3pqhZ1c55WBWWhELlpxAjAJ9IX3OQ==
X-Received: by 2002:a37:44d7:0:b0:742:93f5:3e4a with SMTP id r206-20020a3744d7000000b0074293f53e4amr5049968qka.1.1678867703227;
        Wed, 15 Mar 2023 01:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4752:0:b0:3b0:98a4:96b8 with SMTP id k18-20020ac84752000000b003b098a496b8ls19351485qtp.8.-pod-prod-gmail;
 Wed, 15 Mar 2023 01:08:22 -0700 (PDT)
X-Received: by 2002:a05:622a:1a95:b0:3bf:db29:b793 with SMTP id s21-20020a05622a1a9500b003bfdb29b793mr69113809qtc.20.1678867702459;
        Wed, 15 Mar 2023 01:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678867702; cv=none;
        d=google.com; s=arc-20160816;
        b=zMPntv9Ij4w8xGqYfrFYGpOG5XVuRfw0E5vyn2/I8xcpnGrxuwYEtXWaONK1nwjFXp
         cbwa+kXk2RJc+sg+ieEUuJS0CvdZAQkXKJ/lPuyhupYX8f/GbiivzSfHOKJuFuRqU6tb
         XoJlp/hvSyUTHWjPQN6pAVk10TaR2mX+KLjkTvsCg/zAro+hakqleYGCyh4GY59sUc+Q
         IsaiESgXbWVMVYq7v2w1cZ8+x6WuDzDbBbLOUZB9cYJz4a57Xjn9bcARGGMpHOYJS8CR
         LwjgvRaLTgYzyrN8U8VdJ9fyPo9rbBOdmTbs4ON+SiJu0Et3LEShSCAGMe1csnbBOk04
         yB0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LT6Ia3vKrU2zpUQTyPaL1FAau/PMFoHjbq3HdkvqDrE=;
        b=fienRSCqFBRFwTEao7jW0M2DN5fbTtMQCvnqCi1B9uWgs3qZwa4FJCpaMR0kdqmp2Y
         g3/DCm7MvVJ+SR7UIyD7fuiOk+nCEWyQSFgGWFm8kVqnx7fryznfaKij1SRuumzy8g6z
         Oj8Sm3+R8zrKh2yIhf6nmu7cfN6Ehn3JuG/LMu5kDyxHPybZ9me+3ALdPn5TampvW7cv
         w5UNfWT7Bt+c7L5L7m6orh/hKHRqbl/KAhX8NHAV4WQIt/rnlJc5ej63mtElt8WYny2b
         Zct6eiwXls5sE8txKRloUFqjZab+D/XNqAS512ilA6/KXCITpJ+E9uH/G4TAOYuNFQAn
         WeqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K0QKzfSs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id dz13-20020a05620a2b8d00b007427cf877eesi221373qkb.2.2023.03.15.01.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Mar 2023 01:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id v10so7476686iox.8
        for <kasan-dev@googlegroups.com>; Wed, 15 Mar 2023 01:08:22 -0700 (PDT)
X-Received: by 2002:a6b:fc05:0:b0:744:d7fc:7a4f with SMTP id
 r5-20020a6bfc05000000b00744d7fc7a4fmr18528284ioh.1.1678867701817; Wed, 15 Mar
 2023 01:08:21 -0700 (PDT)
MIME-Version: 1.0
References: <20230315034441.44321-1-songmuchun@bytedance.com>
In-Reply-To: <20230315034441.44321-1-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Mar 2023 09:07:40 +0100
Message-ID: <CANpmjNMxDT+AHBZra9ryhm6aw+WqBsdJ_SKdcdZr6CBsh97LyQ@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: fix using kfence_metadata without
 initialization in show_object()
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, muchun.song@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K0QKzfSs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as
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

On Wed, 15 Mar 2023 at 04:45, Muchun Song <songmuchun@bytedance.com> wrote:
>
> The variable kfence_metadata is initialized in kfence_init_pool(), then, it is
> not initialized if kfence is disabled after booting. In this case, kfence_metadata
> will be used (e.g. ->lock and ->state fields) without initialization when reading
> /sys/kernel/debug/kfence/objects. There will be a warning if you enable
> CONFIG_DEBUG_SPINLOCK. Fix it by creating debugfs files when necessary.
>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Tested-by: Marco Elver <elver@google.com>
Reviewed-by: Marco Elver <elver@google.com>

Good catch!

> ---
>  mm/kfence/core.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5349c37a5dac..79c94ee55f97 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -726,10 +726,14 @@ static const struct seq_operations objects_sops = {
>  };
>  DEFINE_SEQ_ATTRIBUTE(objects);
>
> -static int __init kfence_debugfs_init(void)
> +static int kfence_debugfs_init(void)
>  {
> -       struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
> +       struct dentry *kfence_dir;
>
> +       if (!READ_ONCE(kfence_enabled))
> +               return 0;
> +
> +       kfence_dir = debugfs_create_dir("kfence", NULL);
>         debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
>         debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
>         return 0;
> @@ -883,6 +887,8 @@ static int kfence_init_late(void)
>         }
>
>         kfence_init_enable();
> +       kfence_debugfs_init();
> +
>         return 0;
>  }
>
> --
> 2.11.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMxDT%2BAHBZra9ryhm6aw%2BWqBsdJ_SKdcdZr6CBsh97LyQ%40mail.gmail.com.
