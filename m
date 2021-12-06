Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR5AXCGQMGQEY7JRUIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E1964469701
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 14:29:44 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id g20-20020a4a7554000000b002caefc8179csf7981619oof.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 05:29:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638797384; cv=pass;
        d=google.com; s=arc-20160816;
        b=A7KXNN1Y+Iav/EKKZqmGwPavHcvmOFpDeuBXPBR2BXvMNT/Ds2x6Oh3oR/8IEeQiU9
         YSkHVxRKMslhdslK6Gqf5JryKmAF29TrheoxBzV2zzFHGXp3wBQRnDDWe8ncUKG6t0FM
         3vKoo98aOrJZBwBngQkb1Wsqncqtx8elkPoMqr1I2GXJNbVelsaG/m/wN56QAHrZ7tFL
         +BvbJ0H8c/glrHNGTUHU6QIbX0ImuZTS9fYx+8YEBq3mKRblSO76Oa9V8ZuV1H/eq7Zs
         7zJcPdwZuOLnuH/4FxqMMfbi82GGQhOWdvSc9t/JBg6KgYib8VNVED4sjfzgDc7r3Z5I
         mRNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VSKm5P3ff3XvWvQuXLrggg2RyBVFlu543RGBS6R9KkM=;
        b=Cfp3yxq6ILyz9LWC6gLCaGSCplnc/UJtDcdxUEN0Xy9Mh+TzImNvDFtdwP3U9hC6JK
         4Xm3P6tCanxvlbJBNJgYL43NBkNDwx4dS2QpODg5qiPU1vrar/kGQ/KDOLpUuPiKD9ip
         FdNBoA9Iq/6V4QxgoD89YJX2Sfi4rvxqugh8tudGm7HboOImtRJ5vPRAixdnwyrrF/S6
         1y0fiDKahImA2P0hlIyx0JNqtqjtWNrHQNd/DxvmNlBBpGo6xJ9XhrXy5diaaIw8/p8p
         iiN+gsyUhefBLSohuMqTINI5M1ovUQ1LNrFe1VNhlqtu++GvXbeRrlI8fnYZyiAClVvg
         gk8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IE5me+LH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VSKm5P3ff3XvWvQuXLrggg2RyBVFlu543RGBS6R9KkM=;
        b=DZdXP+1AAg/lCrQrk7yb8iG2ok2bN7gVinZ61T+/eJ21oqKdU4KL15JSvbS3OJfSnL
         XIagBD3s69WzHuLxpTxsvqEs2R5U2+ta/8wwIh//unxekFswa+A+wX5qAAkHnpj/aCNY
         ENTQf+6jK3ywhVK2++lM2icAIkrwxmDE7Lg2tVWFbPqKzRSmrJsEsJ20kHTBXjf3E567
         018yMs2gHSiPP4dVMzCqlo2vjL26d74fe8KN4uO4Rb+kPDgN9i8Ia5J60g2+YsnofbhY
         rdOhnQ0nmnuwZ3Wv7OFWfJPWH0GoKGWkvozik812DrVqfl2OyZO/U0uVd3Feo8YuAFnY
         GQ/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VSKm5P3ff3XvWvQuXLrggg2RyBVFlu543RGBS6R9KkM=;
        b=X3wfHzUdekQXEpAu8SBYD6Sz9BmPJzxaTJeQA9mjv45rZqNu5GxMZ0YaWtVKTTte08
         G79V3wNYxeEYchgMISDSQySK5qWiM/S1xfj/+tqzbiKCPksWS8aUso6MgEuncH5aKwqV
         RU+LJbNxossdtTvK+Xehh4r1RtpRjvq8Gzg5Tt+AhIxG/GJxpsQxFZ3mj26jyeS3aNZC
         UkftgHjCqfakG0OHS5HwCV62Rw94pY/CpuGaPZ3WodCmncrpSIbelra/BsUcBc/Xw2eG
         WkTR2bF4vqpGAsyR9plCp8P/rJXL+0igtHtsS3TVZmjN9pF0w1jaP5lhr4tPtS4H3xjW
         WgJA==
X-Gm-Message-State: AOAM531QVBHGm38p0rqIh7rqM4SE+JaQECV0f3W0aMBKu/rWwscPI54A
	vj1HVcf917uBefwwkpkwqAA=
X-Google-Smtp-Source: ABdhPJz+elPIvBRmiWG/vtYA6coOcgrjja8ltzD90znX5h8jxwGqvFwTpLF/QLjBMfw7J2dmYZmvgQ==
X-Received: by 2002:a05:6808:1814:: with SMTP id bh20mr22971594oib.31.1638797383758;
        Mon, 06 Dec 2021 05:29:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3116:: with SMTP id b22ls5634969ots.3.gmail; Mon,
 06 Dec 2021 05:29:43 -0800 (PST)
X-Received: by 2002:a05:6830:4103:: with SMTP id w3mr28792871ott.207.1638797383309;
        Mon, 06 Dec 2021 05:29:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638797383; cv=none;
        d=google.com; s=arc-20160816;
        b=s/gdTbEt7OdsURnHaoakfUrkh/MYM1scm3RGFOSAD5MMRWD6aHHfCB/0BGeMUB2vMM
         75Wdkou2DBPgYnXALYhgKeG+bDzdVSPAP+4ryLIgGCxMvVbhZwOrbGz8PfAt6V6F5veS
         8ljDIT0UM/r2+TSS0Sv9aBkTdJU7/UTGI7PB+EWqZqa7d1W6ITP4Gsdwr2zyPEw8GtIB
         LWInWpPouv0XHfGywaCFHPPGAgNZMh1JhJw1zV6Bd1/l6VuoGxIK1oFMq1wBhmG3XTi7
         Ld02SJmniTDltw27QwjNrMWiJbQrYfPBSV4GHsnDLMykI34HNwEuJh8cIJGpBc6ZfMCW
         RRhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hwAXMiVFRnMKI3jWqdRm+kJXMsdijWyrT1caWs3PQTk=;
        b=rjskuNVtq95tBlhabZEUNJrFQcIwJoxSQJxXtKJnqqCPOacnW9jiq2Atj5Yb+CTDej
         mJ+XFqX5z+fG+JRcI8uzBpeGjLzZ9syxz/qDX/iNTTSEgag7KhiU+oChvro73DZoYF+u
         9mAyi2qhUVLJ/6elm6igAwQ5mF1IXcVLI14SbzJZYOYFT9fgk8GvN5+oMOSG+RzsM+0+
         PtcDz62MtC4Dr9913g3wnUNZEWKpJtuXlL4HMjswkMOPMeryi21506O5TnJ9DsRVoDp4
         o1eJ/EWL+BWi/DADqyV7CxnOklJbvz2UiodMgW7HwOoGzVVi8dmnAnftl/YYJslT3hQ5
         o0hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IE5me+LH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id u27si1225466ots.2.2021.12.06.05.29.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 05:29:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id s139so21352502oie.13
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 05:29:43 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr23741704oil.65.1638797382907;
 Mon, 06 Dec 2021 05:29:42 -0800 (PST)
MIME-Version: 1.0
References: <20211206133628.2822545-1-libaokun1@huawei.com>
In-Reply-To: <20211206133628.2822545-1-libaokun1@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Dec 2021 14:29:31 +0100
Message-ID: <CANpmjNOrtcu16zKEjiZbBZJPDKWa6-PM_hw1yNZhXvpZupYgng@mail.gmail.com>
Subject: Re: [PATCH -next] kfence: fix memory leak when cat kfence objects
To: Baokun Li <libaokun1@huawei.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	viro@zeniv.linux.org.uk, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, yukuai3@huawei.com, 
	Hulk Robot <hulkci@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IE5me+LH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Mon, 6 Dec 2021 at 14:24, Baokun Li <libaokun1@huawei.com> wrote:
>
> Hulk robot reported a kmemleak problem:
> -----------------------------------------------------------------------
> unreferenced object 0xffff93d1d8cc02e8 (size 248):
>   comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
>   hex dump (first 32 bytes):
>     00 40 85 19 d4 93 ff ff 00 10 00 00 00 00 00 00  .@..............
>     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
>   backtrace:
>     [<00000000db5610b3>] seq_open+0x2a/0x80
>     [<00000000d66ac99d>] full_proxy_open+0x167/0x1e0
>     [<00000000d58ef917>] do_dentry_open+0x1e1/0x3a0
>     [<0000000016c91867>] path_openat+0x961/0xa20
>     [<00000000909c9564>] do_filp_open+0xae/0x120
>     [<0000000059c761e6>] do_sys_openat2+0x216/0x2f0
>     [<00000000b7a7b239>] do_sys_open+0x57/0x80
>     [<00000000e559d671>] do_syscall_64+0x33/0x40
>     [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
> unreferenced object 0xffff93d419854000 (size 4096):
>   comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
>   hex dump (first 32 bytes):
>     6b 66 65 6e 63 65 2d 23 32 35 30 3a 20 30 78 30  kfence-#250: 0x0
>     30 30 30 30 30 30 30 37 35 34 62 64 61 31 32 2d  0000000754bda12-
>   backtrace:
>     [<000000008162c6f2>] seq_read_iter+0x313/0x440
>     [<0000000020b1b3e3>] seq_read+0x14b/0x1a0
>     [<00000000af248fbc>] full_proxy_read+0x56/0x80
>     [<00000000f97679d1>] vfs_read+0xa5/0x1b0
>     [<000000000ed8a36f>] ksys_read+0xa0/0xf0
>     [<00000000e559d671>] do_syscall_64+0x33/0x40
>     [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
> -----------------------------------------------------------------------
>
> I find that we can easily reproduce this problem with the following
> commands:
>         `cat /sys/kernel/debug/kfence/objects`
>         `echo scan > /sys/kernel/debug/kmemleak`
>         `cat /sys/kernel/debug/kmemleak`
>
> The leaked memory is allocated in the stack below:
> ----------------------------------
> do_syscall_64
>   do_sys_open
>     do_dentry_open
>       full_proxy_open
>         seq_open            ---> alloc seq_file
>   vfs_read
>     full_proxy_read
>       seq_read
>         seq_read_iter
>           traverse          ---> alloc seq_buf
> ----------------------------------
>
> And it should have been released in the following process:
> ----------------------------------
> do_syscall_64
>   syscall_exit_to_user_mode
>     exit_to_user_mode_prepare
>       task_work_run
>         ____fput
>           __fput
>             full_proxy_release  ---> free here
> ----------------------------------
>
> However, the release function corresponding to file_operations is not
> implemented in kfence. As a result, a memory leak occurs. Therefore,
> the solution to this problem is to implement the corresponding
> release function.
>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Reported-by: Hulk Robot <hulkci@huawei.com>
> Signed-off-by: Baokun Li <libaokun1@huawei.com>

Good catch!

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 46103a7628a6..186838f062b2 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -684,6 +684,7 @@ static const struct file_operations objects_fops = {
>         .open = open_objects,
>         .read = seq_read,
>         .llseek = seq_lseek,
> +       .release = seq_release,
>  };
>
>  static int __init kfence_debugfs_init(void)
> --
> 2.31.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOrtcu16zKEjiZbBZJPDKWa6-PM_hw1yNZhXvpZupYgng%40mail.gmail.com.
