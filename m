Return-Path: <kasan-dev+bncBCT4XGV33UIBBOVZUKZQMGQET47MHSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B31D904409
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 20:51:40 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c3213b3878sf1651336a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 11:51:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718131898; cv=pass;
        d=google.com; s=arc-20160816;
        b=DcHC1Cr6YK79s9+/5PCKLCr3gCvxJFRQDFganH1YzuWAHUbx+r7w1D3He3pVTxrCtE
         f5pitzKVFT+BMmw5mxbc9hZjC0tZVcHNzg10gvAgaIUM9l7PCOmF501OvkTp6NCVEtFh
         ti1cHV+q0XEOu8POXr1I6YN3nfYvAF1duTExVSxjFrnjKHhEU+J8xVs6HY4Nkp9OoSS6
         DLKFVBBPufH1gK5Do7zXGBsitokfI6buAav81pp0bkxRLkp7+jKufyKlyyyyaqBnNGFC
         fE/dO/ARB/eYP8hGxYP+CM0kZyh3h8DOKlKdxUbUfcLv3AqF8Sx4Brxc39u/qJN921cO
         HwDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=33wMVJ/I8fErFoG2TP2F2wyT7kSvPUdvmJlyWrH6Y6g=;
        fh=kK1H1uUfHYaBMe0+OJy8blPeiCLvlBIrK+5aRuTIUqI=;
        b=G8iFc3tucf39cAZm9TwGkWYwaac2N0FOuN9kNW8KFctxidYyFPc0OqpxuZ0d9U7jrV
         ObJSlA+JHoZCIvl1/3vsOXVAiOo1Gtlqni79DIq2WdzW013xzFhvbtHT6jz08YbBBGhQ
         MnLCiaOV4rgk87hqfPMzAu2t6dDgVNyJBhFitxTC8lTEU8Zm8d28/ulF7qsGolhv7ArF
         8Xglzfn8+D7dWDbt+W28Ac7yptqMibgmruDpFVh7C3C8s/mzVgEUlJtT3J5Pt3q66/zU
         7LzWZQDGhZyy66fVmI2J4Mq2x6HojSXH2vWCQLIzZZsTYhBHstWiAIF7IMp3bMdFOg4f
         fynw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=No3kRxxr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718131898; x=1718736698; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=33wMVJ/I8fErFoG2TP2F2wyT7kSvPUdvmJlyWrH6Y6g=;
        b=o2Sgh8/HnHa2vV8RfuA8ZDC7I+iKWpUQzM756ojpqAytkWg7H1QOaqX4UK8jZvYQy2
         xJNgA6fjMcUtdPISIEXTmbRP4Cuvcn3bSmUeMyPi6J4Vg09fAXfFTq8+vlyChXR5Fh5j
         iHkqmOLGRvhy26qTpLRGhxekkUP4fHNMAD4jJG8KzXAGAF0ete3JJivt/SfyC2DryE0A
         T0asSj3yQMdgk9IoT/SALNwjMVKOdht7EsH0NKo3mqH+hGPAoRhRWJ3PU6i8S5LsmiZY
         95MvcZdJNcl9gAf27aaBzVg0V7d7lqahfOLDWxAXpQeWboPpTCbuECQv8TZxuDpoyTSU
         0lAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718131898; x=1718736698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=33wMVJ/I8fErFoG2TP2F2wyT7kSvPUdvmJlyWrH6Y6g=;
        b=iiYueTtv8cGgwHsTWtI56chdYxFMJ9V5XmaGidGNqDPnBxSBET+pJ+PmHuuTuMQumW
         FcZivzvbWUw3Dnp2KunhmZE0qCLg6uJ8CRWz0go6Yaj4WjVlcn8/xiSfUTUC/SFRMl6A
         pUM0rtaXmL1/PNhLSJIjAleWkXKlAz6RhDn1SBZ1vChprZS5M93cl5BmVs0mlJa+s3+3
         wy+tsDWL0ByukpJ9SkA5hAA8oTABzZUQC1lT5dRukym4kkc9CgSGxU5WiVGDm28FO3J7
         51/vBmbvejRwWu5147JnKdSvtTab+cYvFAGHLG9ZMPHrJkRFNmgnQGnRS37zOrMV2+OF
         lMhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzNuHZjSVBrDdHOWZ1mNd38wixroQ+AiTNUKKbqQL98UbN2n2V5VFGnqV0i16J56elXawYzoV/FVU40kRdQoN9iCXqbxMAcw==
X-Gm-Message-State: AOJu0Yybms87/ve+5QCIP+szIvolkSR1q97FNobnvW9Fl3RHAOhf+/Dg
	hrc+jD1ZbZycW0ln+6UeKjY7+iIufNZV4BUqRt0W53yu1h1L/7w6
X-Google-Smtp-Source: AGHT+IE9qjHqerE1VTgIJOd/9C62vD9U65xLrJIzjd+ZeiuscoXmqkAXfaL+6Cu7HSuqWhLj2aTMqw==
X-Received: by 2002:a17:90a:b013:b0:2bd:f1d5:8e3e with SMTP id 98e67ed59e1d1-2c2bcc6d03emr12267469a91.35.1718131898434;
        Tue, 11 Jun 2024 11:51:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b85:b0:2bd:e914:8fe1 with SMTP id
 98e67ed59e1d1-2c2b4782bc9ls3178458a91.0.-pod-prod-04-us; Tue, 11 Jun 2024
 11:51:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJNzE64zHexktU7P+ReNL60MVzQWgqnuU1aRVxGAMNtQrMfkqy40wPMtshglIj6pb8tcikY/Gi8GmsrQwpSAy13tBe2JHsuGcLBg==
X-Received: by 2002:a17:90a:3487:b0:2c4:9fa5:56be with SMTP id 98e67ed59e1d1-2c49fa5574emr543679a91.14.1718131897003;
        Tue, 11 Jun 2024 11:51:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718131896; cv=none;
        d=google.com; s=arc-20160816;
        b=oHHHbUL7mm82FO0AMa8dfv/Fe/k8DdtLTCUvGtxrq3Y/YRyrz8MZJmI8IX9kd/LF8R
         Qe2UmQTVErv36mT3XDiiwl9NMof+OHkX31xLwr6P+0SIqMCNNpHw6TRVm3ErRLPcswR9
         XksxoIm//lHZo9ekZvXdsSeLpaCQXd3AWD6yX3pS2tOqPJOqevtCZIax8PzmqJ4JZbZA
         nE4jzQT6ZZRAWtOqCnOGcHutTq7+q2tq8xK8gaknOv9Ls/gsA7nV5ccTCEwMnjajJnOX
         XYZNfVPzN3S/p9AaomqZ8VVg6iNf17YgLwgCUmav5Yiz5ir4mhA/i4meIkcsNPjiZqyb
         n70w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ch6Ef/9+oouFYtrlPPGYQzl5zrYIyJBzWuJGDffk8Aw=;
        fh=fRHmbX4kiZkr1X+/3i7RbgVD14JT5XkZDhblGZlruTk=;
        b=xKb4vswdICgLz2uoHhomr3435PJ+r3327Tox+FjEn7/c6fxqm138k92nm29cxN2xF/
         jxFrSGTuLsl8KJL/dTAuYDS8DSOjtJCSgTVLDoJq/VrFVbbgs7oC2eizKSTrNhJiFvAj
         wObU3GaFBfqoRzzF7fT1Ii4fav6fiiBsME38i7mU46d3KyMSZptU3qWiRQYX3qcj9Y4k
         9Hesnmp1BvKg7K7HKHOfgTX/Ccq13M2sk4H9d+mfEV88Bl/ZORlLzr4zxko8nqVb8M+1
         kMYw6MXq2XmD4Chpm9fA49n8+S0oIrly0xYdvmMMPTd21SVkJITve0O6qzUy9WFlk1w3
         cEIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=No3kRxxr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c33b3fdc28si142115a91.1.2024.06.11.11.51.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 11:51:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id DF210CE14EB;
	Tue, 11 Jun 2024 18:51:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0B23C2BD10;
	Tue, 11 Jun 2024 18:51:33 +0000 (UTC)
Date: Tue, 11 Jun 2024 11:51:33 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Aleksandr Nogikh <nogikh@google.com>
Cc: dvyukov@google.com, andreyknvl@gmail.com, arnd@arndb.de,
 elver@google.com, glider@google.com, syzkaller@googlegroups.com,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcov: don't lose track of remote references during
 softirqs
Message-Id: <20240611115133.fa80466e924ad34ed4ad73cb@linux-foundation.org>
In-Reply-To: <20240611133229.527822-1-nogikh@google.com>
References: <20240611133229.527822-1-nogikh@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=No3kRxxr;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 11 Jun 2024 15:32:29 +0200 Aleksandr Nogikh <nogikh@google.com> wrote:

> In kcov_remote_start()/kcov_remote_stop(), we swap the previous KCOV
> metadata of the current task into a per-CPU variable. However, the
> kcov_mode_enabled(mode) check is not sufficient in the case of remote
> KCOV coverage: current->kcov_mode always remains KCOV_MODE_DISABLED
> for remote KCOV objects.
> 
> If the original task that has invoked the KCOV_REMOTE_ENABLE ioctl
> happens to get interrupted and kcov_remote_start() is called, it
> ultimately leads to kcov_remote_stop() NOT restoring the original
> KCOV reference. So when the task exits, all registered remote KCOV
> handles remain active forever.
> 
> Fix it by introducing a special kcov_mode that is assigned to the
> task that owns a KCOV remote object. It makes kcov_mode_enabled()
> return true and yet does not trigger coverage collection in
> __sanitizer_cov_trace_pc() and write_comp_data().

What are the userspace visible effects of this bug?  I *think* it's
just an efficiency thing, but how significant?  In other words, should
we backport this fix?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240611115133.fa80466e924ad34ed4ad73cb%40linux-foundation.org.
