Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOO34KVQMGQE54GOHUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 87DF580F5EC
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 20:00:12 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d0c7235971sf42322555ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 11:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702407611; cv=pass;
        d=google.com; s=arc-20160816;
        b=OYo8zlg1BZSBLx5/jLOdA30KVMj5LxqX4TmRHqm9FO6P5pkoZXfaBKqzb4fdw53zuq
         RHiyric6vJP9t2bf43QvMtwDiBfiXyf7tsmbFO09wq/5B9wRrBUPgb9nZ9fsti9oUziR
         8brFbtK6WvkFPDyhZIziQkNrmZ5dD+AuJnADEF9jD/8//a6B5faf5M7OmHGTxzP2wElQ
         vNXocacuGYke/YfNyPdyZovmO7FFHMix8ZpxieRJGsyJ3ET3Lq6suzSIxldYQLby/0/z
         54U1sF8fCocBXfRnG5xGzsQH9x5t+gGJWlk8+GKMuXiM8RKdi7UKmbB/QVWVWT6F6Oy6
         AhBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VHci1Cjonl8CEToAsMA4utvUWJfrssofnmWDkcrFvms=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=SduJipU7KFypkLB7gQYktzOygFPUTIbDPDoZyEuwiwNBlFjdPqziv90iP2M08rH7Ri
         ABYmczNYiUooM0ib15YEheKwBW+FrQiQMbHQMjGei0zjwI7PYUns1YwXM3kOb8T0F76k
         XskULTpeYNyCTjscEAvzSNM/CSm4KXpzlsj3VNCqpvf5/2Ka+ItIkhjxec9TkOBQnVK4
         We703i9wBWhUn1xc4vZbhmQze0NSBOnDdTc/cUmnFH1KVnVNfgQ3vD3gBDKeReTbf7xs
         89UNWTK6DVJYvkv6u1KK7pkOjkk0dwroSPx00CDXp8HF4koqE8pv6g/nPEufN6XyFXC7
         hgbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FUb07hdQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702407611; x=1703012411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VHci1Cjonl8CEToAsMA4utvUWJfrssofnmWDkcrFvms=;
        b=okCiP9x7jzQWSrFJ4aizPhQyRxf74aX5B1ZrK2Z4PhjAyK+VBRHY4y3pBAvgjcTd30
         2Y+8iVI7KkPK2dEIXK7/v6eFgnuDtMgnsjFn97r+uDEzElSA6oJGcbW6wkCdDOKO4x1q
         h0Va42N2WMqOp12tBIOxFDWcWPPCoei6WInGQgEKoOTp56TWnR3Pqwop9JGKlbNC59F8
         g3pnMqx7NSSSTJsDmY2rnrfs9SE3uYdMnMUp/BBAxnk6WUBz/CE8EelGm1e+TBQRn957
         uRe+vJL2xh6aTLhBsf4eCMhdzpnHzr+DANQRc4FxDoPiT6ND/9RB8yJSx6C6Fxv5FWGA
         DYAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702407611; x=1703012411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VHci1Cjonl8CEToAsMA4utvUWJfrssofnmWDkcrFvms=;
        b=b5Yk1rfWNPtUk0PpQjLhQfdUAGq8o8TZSKcEeLS/IVuWXXHoIhrDJokug7sCoahz2w
         eyYwWAYHjL5BPLxDGsBTDT4wUJK8ZNj8MPG6PvopKc797POr/1GmnYj+KellF857oc+3
         0RbnZiPoFTit2/So6xrcdNZjf6G1t5+e1i6fLAy1H/3kCtOdLmd9Sl+6HxgQh4tn9P02
         hsGcjTjNAqo92UymBrkjAme7YvHou8qZrSCEUTzRby1S+tVBarbzSA0cmzuOOi+DebL9
         /WrKGcKIgZaPhNMLA/MBhl8FtplgRG9MC0ZCh46tEHC6zAaODjSugtnD1MIy7E2CpAHs
         BfZw==
X-Gm-Message-State: AOJu0Yy2s01IgNL14gRZ8/XUgNUHhWXEExYlUMa9KsmGbGxmp6X57/Fn
	XnI25LvCQru8RV5/ItWfpNI=
X-Google-Smtp-Source: AGHT+IGrSs4uMQ6qqDF6t/OP39QW/U7sB4WkBs/jPw4L4Nao2KLL5//du1ZaG8kKr9atTK6RXfzjFw==
X-Received: by 2002:a17:902:ec90:b0:1d0:ad0e:bef4 with SMTP id x16-20020a170902ec9000b001d0ad0ebef4mr9342140plg.63.1702407609909;
        Tue, 12 Dec 2023 11:00:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2652:b0:1cf:cf40:3ce5 with SMTP id
 je18-20020a170903265200b001cfcf403ce5ls3136520plb.0.-pod-prod-00-us; Tue, 12
 Dec 2023 11:00:08 -0800 (PST)
X-Received: by 2002:a17:902:dace:b0:1d3:4af3:2e90 with SMTP id q14-20020a170902dace00b001d34af32e90mr11561plx.6.1702407608190;
        Tue, 12 Dec 2023 11:00:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702407608; cv=none;
        d=google.com; s=arc-20160816;
        b=i3/iYqdrQNd+FcPYEe10kLZl3S2MXCIk2TYW94PCxGRB19xhq+r6AXN5OznGJPKwf7
         biJIJx4t0Dp2CK7/Z8FjyLa2AfD6uGbstuyrn6cMiMCsl9NeVXKuczyHNyW00Uma/K3B
         V8JW3fRmmYLhGNSfwyPFLIU7B0NlXiYTcESQuS3NgM8RCiPbzsntkEiidRPOwzCuMSul
         uFTZ4PPp+CWV8eoMRBaY+qeiIxoeDfYd2ukJcAhB4UePx5/A/WX9cR1z9piSeLpdSl6D
         R8wJ/nttGuIdy7gQSQIxGy5m43dS2cyuzpKpDZ1S420jRVFpdV8m8rFaDPwLL0H5vKW5
         DLVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PUFl67MNvz50LEEW65eGueVacBRt36aAKgnhCxXMoqo=;
        fh=U+LkbmzWWCZxhGJEzEnoma1O4OhNrWGKYws0tLC4nok=;
        b=GB8O3BzoQhsIxkwdemFRGNeriuLbOARE4Xbc6c3FDI56q4hu2zq+wt9qkHcwmx1FZo
         7kmSYMGkKnuOaSWRxyaE/mR51WLvxqisYpZESWxNE9wLRa5KzXopnBj8H2HNflyNEKRw
         ZmX/OjGv4XHsBfUsg8f+dcRn7CbEv7cz88Os896BYehqFP/Hm4HYtxN7id3FeyY1Zjq0
         jw76G5syIMqZQjAla0ONqItWnYFOVNn16nKVfvsxGCnueMa6F64GmT3Xwgzkl78GDqkW
         wUN93O2SAiVGlC9dQ+c0bEPjr7wQVqgu0cjRo2OcR9/7kCNc2P55ISDk3gaiyYw89kd2
         KR2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FUb07hdQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id s11-20020a170903200b00b001d346fac8ddsi54998pla.0.2023.12.12.11.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 11:00:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id 71dfb90a1353d-4b2ceee07e5so3407096e0c.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 11:00:08 -0800 (PST)
X-Received: by 2002:a05:6122:4b:b0:48d:5be:2868 with SMTP id
 q11-20020a056122004b00b0048d05be2868mr5216760vkn.0.1702407607079; Tue, 12 Dec
 2023 11:00:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl@google.com>
In-Reply-To: <6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Dec 2023 19:59:29 +0100
Message-ID: <CANpmjNNXiRxwTk4wGHL3pXmXo5YUY=VNLCf+g+kB6inXJnC2YA@mail.gmail.com>
Subject: Re: [PATCH mm 1/4] lib/stackdepot: add printk_deferred_enter/exit guards
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FUb07hdQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as
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

On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Stack depot functions can be called from various contexts that do
> allocations, including with console locks taken. At the same time, stack
> depot functions might print WARNING's or refcount-related failures.
>
> This can cause a deadlock on console locks.
>
> Add printk_deferred_enter/exit guards to stack depot to avoid this.
>
> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@google.com/
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Doesn't need Fixes, because the series is not yet in mainline, right?

> ---
>  lib/stackdepot.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 870cce2f4cbd..a0be5d05c7f0 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -506,12 +506,14 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>         bucket = &stack_table[hash & stack_hash_mask];
>
>         read_lock_irqsave(&pool_rwlock, flags);
> +       printk_deferred_enter();
>
>         /* Fast path: look the stack trace up without full locking. */
>         found = find_stack(bucket, entries, nr_entries, hash);
>         if (found) {
>                 if (depot_flags & STACK_DEPOT_FLAG_GET)
>                         refcount_inc(&found->count);
> +               printk_deferred_exit();
>                 read_unlock_irqrestore(&pool_rwlock, flags);
>                 goto exit;
>         }
> @@ -520,6 +522,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>         if (new_pool_required)
>                 need_alloc = true;
>
> +       printk_deferred_exit();
>         read_unlock_irqrestore(&pool_rwlock, flags);
>
>         /*
> @@ -541,6 +544,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>         }
>
>         write_lock_irqsave(&pool_rwlock, flags);
> +       printk_deferred_enter();
>
>         found = find_stack(bucket, entries, nr_entries, hash);
>         if (!found) {
> @@ -562,6 +566,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
>                         depot_keep_new_pool(&prealloc);
>         }
>
> +       printk_deferred_exit();
>         write_unlock_irqrestore(&pool_rwlock, flags);
>  exit:
>         if (prealloc) {
> @@ -600,9 +605,11 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>                 return 0;
>
>         read_lock_irqsave(&pool_rwlock, flags);
> +       printk_deferred_enter();
>
>         stack = depot_fetch_stack(handle);
>
> +       printk_deferred_exit();
>         read_unlock_irqrestore(&pool_rwlock, flags);
>
>         *entries = stack->entries;
> @@ -619,6 +626,7 @@ void stack_depot_put(depot_stack_handle_t handle)
>                 return;
>
>         write_lock_irqsave(&pool_rwlock, flags);
> +       printk_deferred_enter();
>
>         stack = depot_fetch_stack(handle);
>         if (WARN_ON(!stack))
> @@ -633,6 +641,7 @@ void stack_depot_put(depot_stack_handle_t handle)
>         }
>
>  out:
> +       printk_deferred_exit();
>         write_unlock_irqrestore(&pool_rwlock, flags);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_put);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXiRxwTk4wGHL3pXmXo5YUY%3DVNLCf%2Bg%2BkB6inXJnC2YA%40mail.gmail.com.
